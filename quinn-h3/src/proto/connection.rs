use std::collections::VecDeque;

use bytes::{Buf, Bytes, BytesMut};
use quinn_proto::StreamId;
use std::convert::TryFrom;

use crate::{
    proto::{
        frame::{HeadersFrame, HttpFrame},
        headers::{self, Header},
    },
    qpack::{self, DecoderError, DynamicTable, EncoderError, HeaderField},
    Settings,
};

#[derive(Clone, Copy)]
pub enum PendingStreamType {
    Control = 0,
    Encoder = 1,
    Decoder = 2,
}

#[derive(Debug)]
pub enum DecodeResult {
    Decoded(Header),
    MissingRefs(usize),
}

impl PendingStreamType {
    pub fn iter() -> impl Iterator<Item = Self> {
        [
            PendingStreamType::Control,
            PendingStreamType::Encoder,
            PendingStreamType::Decoder,
        ]
        .iter()
        .cloned()
    }
}

pub struct Connection {
    #[allow(dead_code)]
    local_settings: Settings,
    remote_settings: Option<Settings>,
    decoder_table: DynamicTable,
    encoder_table: DynamicTable,
    pending_streams: [BytesMut; 3],
    requests_in_flight: VecDeque<StreamId>,
    go_away: bool,
}

impl Connection {
    pub fn with_settings(settings: Settings) -> Result<Self> {
        let mut decoder_table = DynamicTable::new();
        decoder_table.set_max_blocked(settings.qpack_blocked_streams as usize)?;
        decoder_table.set_max_size(settings.qpack_max_table_capacity as usize)?;

        let mut pending_control = BytesMut::with_capacity(128);
        settings.encode(&mut pending_control);
        let pending_streams = [
            pending_control,
            BytesMut::with_capacity(2048),
            BytesMut::with_capacity(2048),
        ];

        Ok(Self {
            decoder_table,
            pending_streams,
            local_settings: settings,
            remote_settings: None,
            encoder_table: DynamicTable::new(),
            requests_in_flight: VecDeque::with_capacity(32),
            go_away: false,
        })
    }

    pub fn encode_header(&mut self, stream_id: StreamId, headers: Header) -> Result<HeadersFrame> {
        if let Some(ref s) = self.remote_settings {
            if headers.len() as u64 > s.max_header_list_size {
                return Err(Error::HeaderListTooLarge);
            }
        }

        let mut block = BytesMut::with_capacity(512);
        qpack::encode(
            &mut self.encoder_table.encoder(stream_id.0),
            &mut block,
            &mut self.pending_streams[PendingStreamType::Encoder as usize],
            headers.into_iter().map(HeaderField::from),
        )?;

        Ok(HeadersFrame {
            encoded: block.into(),
        })
    }

    pub fn decode_header(
        &mut self,
        stream_id: StreamId,
        header: &HeadersFrame,
    ) -> Result<DecodeResult> {
        match qpack::decode_header(
            &self.decoder_table,
            &mut std::io::Cursor::new(&header.encoded),
        ) {
            Err(DecoderError::MissingRefs(r)) => Ok(DecodeResult::MissingRefs(r)),
            Err(e) => Err(Error::DecodeError { reason: e }),
            Ok(decoded) => {
                qpack::ack_header(
                    stream_id.0,
                    &mut self.pending_streams[PendingStreamType::Decoder as usize],
                );
                Ok(DecodeResult::Decoded(Header::try_from(decoded)?))
            }
        }
    }

    pub fn on_recv_encoder<R: Buf>(&mut self, read: &mut R) -> Result<usize> {
        Ok(qpack::on_encoder_recv(
            &mut self.decoder_table.inserter(),
            read,
            &mut self.pending_streams[PendingStreamType::Decoder as usize],
        )?)
    }

    pub fn remote_settings(&self) -> &Option<Settings> {
        &self.remote_settings
    }

    pub fn set_remote_settings(&mut self, settings: Settings) -> Result<()> {
        self.encoder_table
            .set_max_blocked(settings.qpack_blocked_streams as usize)?;
        self.encoder_table
            .set_max_size(settings.qpack_max_table_capacity as usize)?;
        self.remote_settings = Some(settings);
        Ok(())
    }

    pub fn pending_stream_take(&mut self, ty: PendingStreamType) -> Option<Bytes> {
        if self.pending_streams[ty as usize].is_empty() {
            return None;
        }
        Some(self.pending_streams[ty as usize].take().freeze())
    }

    pub fn pending_stream_release(&mut self, ty: PendingStreamType) {
        let capacity = self.pending_streams[ty as usize].capacity();
        self.pending_streams[ty as usize].reserve(capacity);
    }

    pub fn request_initiated(&mut self, id: StreamId) {
        if !self.go_away {
            self.requests_in_flight.push_back(id);
        }
    }

    pub fn request_finished(&mut self, id: StreamId) {
        if !self.go_away {
            self.requests_in_flight.push_back(id);
        }
    }

    pub fn requests_in_flight(&self) -> usize {
        self.requests_in_flight.len()
    }

    pub fn go_away(&mut self) {
        if !self.go_away {
            self.go_away = true;
            let id = self.requests_in_flight.back().map(|i| i.0).unwrap_or(0) + 1;
            HttpFrame::Goaway(id)
                .encode(&mut self.pending_streams[PendingStreamType::Control as usize]);
        }
    }

    pub fn leave(&mut self, id: StreamId) {
        self.go_away = true;
        self.requests_in_flight.retain(|i| i.0 <= id.0);
    }

    pub fn is_closing(&self) -> bool {
        self.go_away
    }
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, PartialEq)]
pub enum Error {
    HeaderListTooLarge,
    InvalidHeaderName(String),
    InvalidHeaderValue(String),
    InvalidRequest(String),
    InvalidResponse(String),
    Settings { reason: String },
    EncodeError { reason: EncoderError },
    DecodeError { reason: DecoderError },
}

impl From<EncoderError> for Error {
    fn from(err: EncoderError) -> Error {
        Error::EncodeError { reason: err }
    }
}

impl From<DecoderError> for Error {
    fn from(err: DecoderError) -> Error {
        Error::DecodeError { reason: err }
    }
}

impl From<qpack::DynamicTableError> for Error {
    fn from(err: qpack::DynamicTableError) -> Error {
        Error::Settings {
            reason: format!("dynamic table error: {}", err),
        }
    }
}

impl From<headers::Error> for Error {
    fn from(err: headers::Error) -> Self {
        match err {
            headers::Error::InvalidHeaderName(s) => Error::InvalidHeaderName(s),
            headers::Error::InvalidHeaderValue(s) => Error::InvalidHeaderValue(s),
            headers::Error::InvalidRequest(e) => Error::InvalidRequest(format!("{:?}", e)),
            headers::Error::MissingMethod => Error::InvalidRequest("missing method".into()),
            headers::Error::MissingStatus => Error::InvalidResponse("missing status".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{
        header::{HeaderMap, HeaderValue},
        uri::Uri,
        Method,
    };

    impl Default for Connection {
        fn default() -> Self {
            Self {
                local_settings: Settings::default(),
                remote_settings: None,
                decoder_table: DynamicTable::new(),
                encoder_table: DynamicTable::new(),
                pending_streams: [
                    BytesMut::with_capacity(2048),
                    BytesMut::with_capacity(2048),
                    BytesMut::with_capacity(2048),
                ],
                requests_in_flight: VecDeque::with_capacity(32),
                go_away: false,
            }
        }
    }

    #[test]
    fn encode_no_dynamic() {
        let mut header_map = HeaderMap::new();
        header_map.append("hello", HeaderValue::from_static("text/html"));
        let header = Header::request(Method::GET, Uri::default(), header_map);

        let mut conn = Connection::default();
        assert_matches!(conn.encode_header(StreamId(1), header), Ok(_));
        assert!(conn.pending_streams[PendingStreamType::Encoder as usize].is_empty());
    }

    #[test]
    fn encode_with_dynamic() {
        let mut header_map = HeaderMap::new();
        header_map.append("hello", HeaderValue::from_static("text/html"));
        let header = Header::request(Method::GET, Uri::default(), header_map);

        let mut conn = Connection::default();
        conn.encoder_table
            .set_max_size(2048)
            .expect("set table size");
        conn.encoder_table
            .set_max_blocked(12usize)
            .expect("set max blocked");
        assert_matches!(conn.encode_header(StreamId(1), header), Ok(_));
        assert!(!conn.pending_streams[PendingStreamType::Encoder as usize].is_empty());
    }

    #[test]
    fn encode_too_many_fields() {
        let mut header_map = HeaderMap::new();
        for _ in 0..5 {
            header_map.append("hello", HeaderValue::from_static("text/html"));
        }
        let header = Header::request(Method::GET, Uri::default(), header_map);

        let mut conn = Connection::default();
        conn.remote_settings = Some(Settings {
            max_header_list_size: 4,
            ..Settings::default()
        });
        assert_eq!(
            conn.encode_header(StreamId(1), header),
            Err(Error::HeaderListTooLarge)
        );
    }

    #[test]
    fn decode_header() {
        let mut header_map = HeaderMap::new();
        header_map.append("hello", HeaderValue::from_static("text/html"));
        let header = Header::request(Method::GET, Uri::default(), header_map);

        let mut client = Connection::default();
        let encoded = client
            .encode_header(StreamId(1), header)
            .expect("encoding failed");

        let mut server = Connection::default();
        assert_matches!(
            server.decode_header(StreamId(1), &encoded),
            Ok(DecodeResult::Decoded(_header))
        );
        assert!(!server.pending_streams[PendingStreamType::Decoder as usize].is_empty());
    }

    #[test]
    fn decode_blocked() {
        let mut header_map = HeaderMap::new();
        header_map.append("hello", HeaderValue::from_static("text/html"));
        let header = Header::request(Method::GET, Uri::default(), header_map);

        let mut client = Connection::default();
        client
            .encoder_table
            .set_max_size(2048)
            .expect("set table size");
        client
            .encoder_table
            .set_max_blocked(12usize)
            .expect("set max");

        let encoded = client
            .encode_header(StreamId(1), header)
            .expect("encoding failed");
        assert!(!client.pending_streams[PendingStreamType::Encoder as usize].is_empty());

        let mut server = Connection::with_settings(Settings {
            qpack_max_table_capacity: 2048,
            qpack_blocked_streams: 42,
            ..Settings::default()
        })
        .expect("create server");

        assert_matches!(
            server.decode_header(StreamId(1), &encoded),
            Ok(DecodeResult::MissingRefs(1))
        );
        assert!(server.pending_streams[PendingStreamType::Decoder as usize].is_empty());
    }
}
