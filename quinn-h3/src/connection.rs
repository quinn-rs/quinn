#![allow(dead_code)]

use bytes::{Buf, BytesMut};

use super::frame::{HeadersFrame, HttpFrame, SettingsFrame};
use super::{ErrorCode, StreamType};
use crate::qpack::{self, DecoderError, DynamicTable, EncoderError, HeaderField};
use quinn_proto::StreamId;

#[derive(Debug, PartialEq)]
pub enum ConnectionError {
    SettingsFrameUnexpected,
    SettingsFrameMissing,
    ControlStreamAlreadyOpen,
    EncoderStreamAlreadyOpen,
    DecoderStreamAlreadyOpen,
    UnimplementedStream(StreamType),
    DecoderStreamError { reason: EncoderError },
    EncoderStreamError { reason: DecoderError },
    EncodeError { reason: EncoderError },
    DecodeError { reason: DecoderError },
}

pub enum State {
    Open,
    Closing(ErrorCode),
    Closed(),
}

pub struct Connection {
    state: State,
    remote_control_stream: bool,
    encoder_stream: bool,
    decoder_stream: bool,
    local_settings: SettingsFrame,
    remote_settings: Option<SettingsFrame>,
    decoder_table: DynamicTable,
    encoder_table: DynamicTable,
    pending_control: BytesMut,
    pending_decoder: BytesMut,
    pending_encoder: BytesMut,
}

impl Connection {
    pub fn new() -> Self {
        let local_settings = SettingsFrame::default();
        let mut pending_control = BytesMut::new();

        local_settings.encode(&mut pending_control);

        Self {
            state: State::Open,
            remote_control_stream: false,
            encoder_stream: false,
            decoder_stream: false,
            local_settings,
            remote_settings: None,
            decoder_table: DynamicTable::new(),
            encoder_table: DynamicTable::new(),
            pending_control,
            pending_decoder: BytesMut::new(),
            pending_encoder: BytesMut::new(),
        }
    }

    pub fn on_recv_control(&mut self, frame: &HttpFrame) {
        match (&self.remote_settings, frame) {
            (None, HttpFrame::Settings(s)) => {
                println!("recieved settings : {:?}", s);
                self.remote_settings = Some(s.to_owned()); // TODO check validity?
            }
            (None, _) => self.state = State::Closing(ErrorCode::MissingSettings),
            (Some(_), HttpFrame::Settings(_)) => {
                self.state = State::Closing(ErrorCode::UnexpectedFrame)
            }
            (Some(_), f) => match f {
                HttpFrame::Priority(_)
                | HttpFrame::CancelPush(_)
                | HttpFrame::Goaway(_)
                | HttpFrame::MaxPushId(_) => {
                    unimplemented!("TODO: unimplemented frame on control stream: {:?}", f)
                }
                _ => self.state = State::Closing(ErrorCode::UnexpectedFrame),
            },
        }
    }

    pub fn on_recv_decoder<T: Buf>(&mut self, buf: &mut T) -> Result<(), ConnectionError> {
        match qpack::on_decoder_recv(&mut self.encoder_table, buf) {
            Err(err) => {
                self.state = State::Closing(ErrorCode::QpackDecoderStreamError);
                Err(ConnectionError::DecoderStreamError { reason: err })
            }
            Ok(_) => Ok(()),
        }
    }

    pub fn on_recv_encoder<R: Buf>(&mut self, encoder: &mut R) -> Result<(), ConnectionError> {
        let ret = qpack::on_encoder_recv(
            &mut self.decoder_table.inserter(),
            encoder,
            &mut self.pending_decoder,
        );
        match ret {
            Err(err) => {
                self.state = State::Closing(ErrorCode::QpackEncoderStreamError);
                Err(ConnectionError::EncoderStreamError { reason: err })
            }
            Ok(_) => Ok(()),
        }
    }

    pub fn on_recv_stream(&mut self, ty: StreamType) -> Result<(), ConnectionError> {
        match ty {
            StreamType::CONTROL => {
                if self.remote_control_stream {
                    self.state = State::Closing(ErrorCode::WrongStreamCount);
                    Err(ConnectionError::ControlStreamAlreadyOpen)
                } else {
                    self.remote_control_stream = true;
                    Ok(())
                }
            }
            StreamType::ENCODER => {
                if self.encoder_stream {
                    self.state = State::Closing(ErrorCode::WrongStreamCount);
                    Err(ConnectionError::EncoderStreamAlreadyOpen)
                } else {
                    self.encoder_stream = true;
                    Ok(())
                }
            }
            StreamType::DECODER => {
                if self.decoder_stream {
                    self.state = State::Closing(ErrorCode::WrongStreamCount);
                    Err(ConnectionError::DecoderStreamAlreadyOpen)
                } else {
                    self.decoder_stream = true;
                    Ok(())
                }
            }
            _ => {
                self.state = State::Closing(ErrorCode::UnknownStreamType);
                Err(ConnectionError::UnimplementedStream(ty))
            }
        }
    }

    pub fn encode_header<'a, T: Iterator<Item = (&'a str, &'a str)>>(
        &mut self,
        stream_id: &StreamId,
        headers: T,
    ) -> Result<HeadersFrame, ConnectionError> {
        let headers = headers
            .map(|f| HeaderField::new(f.0, f.1))
            .collect::<Vec<_>>(); // TODO pass an iterator
        let mut block = BytesMut::with_capacity(512);
        qpack::encode(
            &mut self.encoder_table.encoder(stream_id.0),
            &mut block,
            &mut self.pending_encoder,
            &headers,
        )?;
        Ok(HeadersFrame {
            encoded: block.into(),
        })
    }

    pub fn decode_header(
        &mut self,
        stream_id: &StreamId,
        header: &HeadersFrame,
    ) -> Result<Option<Vec<(String, String)>>, ConnectionError> {
        match qpack::decode_header(
            &mut self.decoder_table,
            &mut std::io::Cursor::new(&header.encoded),
        ) {
            Err(DecoderError::MissingRefs) => Ok(None),
            Err(e) => Err(ConnectionError::DecodeError{ reason: e }),
            Ok(decoded) => {
                qpack::ack_header(stream_id.0, &mut self.pending_decoder);
                return Ok(Some(
                    decoded
                        .into_iter()
                        .map(|f| f.into_inner())
                        .collect(),
                ));
            }
        }
    }
}

impl From<EncoderError> for ConnectionError {
    fn from(err: EncoderError) -> ConnectionError {
        ConnectionError::EncodeError { reason: err }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_recv_stream_unique(ty: StreamType, err: ConnectionError) {
        let mut conn = Connection::new();
        assert_eq!(conn.on_recv_stream(ty), Ok(()));
        assert_eq!(conn.on_recv_stream(ty), Err(err));
    }

    #[test]
    fn recv_stream() {
        check_recv_stream_unique(
            StreamType::CONTROL,
            ConnectionError::ControlStreamAlreadyOpen,
        );
        check_recv_stream_unique(
            StreamType::ENCODER,
            ConnectionError::EncoderStreamAlreadyOpen,
        );
        check_recv_stream_unique(
            StreamType::DECODER,
            ConnectionError::DecoderStreamAlreadyOpen,
        );
    }

    #[test]
    fn handle_settings_frame() {
        let mut conn = Connection::new();

        let settings = SettingsFrame::default();
        conn.on_recv_control(&HttpFrame::Settings(settings.clone()));
        assert_eq!(Some(settings), conn.remote_settings);
    }
}
