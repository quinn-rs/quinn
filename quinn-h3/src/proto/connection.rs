use bytes::BytesMut;
use http::{
    header::{HeaderName, HeaderValue, InvalidHeaderName, InvalidHeaderValue},
    HeaderMap,
};
use quinn_proto::StreamId;

use crate::proto::frame::HeadersFrame;
use crate::qpack::{self, DecoderError, DynamicTable, EncoderError, HeaderField};
use crate::Settings;

pub struct Connection {
    #[allow(dead_code)]
    local_settings: Settings,
    remote_settings: Option<Settings>,
    decoder_table: DynamicTable,
    encoder_table: DynamicTable,
    pending_encoder: BytesMut,
    pending_decoder: BytesMut,
}

impl Connection {
    pub fn with_settings(settings: Settings) -> Result<Self> {
        let mut decoder_table = DynamicTable::new();
        decoder_table.set_max_blocked(settings.qpack_blocked_streams as usize)?;
        decoder_table
            .inserter()
            .set_max_mem_size(settings.qpack_max_table_capacity as usize)?;

        Ok(Self {
            local_settings: settings,
            remote_settings: None,
            decoder_table,
            encoder_table: DynamicTable::new(),
            pending_encoder: BytesMut::with_capacity(2048),
            pending_decoder: BytesMut::with_capacity(2048),
        })
    }

    pub fn encode_header(
        &mut self,
        stream_id: &StreamId,
        headers: &HeaderMap,
    ) -> Result<HeadersFrame> {
        if let Some(ref s) = self.remote_settings {
            if headers.len() as u64 > s.max_header_list_size {
                return Err(Error::HeaderListTooLarge);
            }
        }

        let headers = headers.into_iter().map(HeaderField::from);

        let mut block = BytesMut::with_capacity(512);
        qpack::encode(
            &mut self.encoder_table.encoder(stream_id.0),
            &mut block,
            &mut self.pending_encoder,
            headers,
        )?;

        Ok(HeadersFrame {
            encoded: block.into(),
        })
    }

    pub fn decode_header(
        &mut self,
        stream_id: &StreamId,
        header: &HeadersFrame,
    ) -> Result<Option<HeaderMap>> {
        match qpack::decode_header(
            &mut self.decoder_table,
            &mut std::io::Cursor::new(&header.encoded),
        ) {
            Err(DecoderError::MissingRefs) => Ok(None),
            Err(e) => Err(Error::DecodeError { reason: e }),
            Ok(decoded) => {
                qpack::ack_header(stream_id.0, &mut self.pending_decoder);

                let mut header_map = HeaderMap::with_capacity(decoded.len());
                for field in decoded.into_iter() {
                    let (name, value) = field.into_inner();
                    header_map.append(
                        HeaderName::from_bytes(&name)?,
                        HeaderValue::from_bytes(&value)?,
                    );
                }
                return Ok(Some(header_map));
            }
        }
    }
}

impl Default for Connection {
    fn default() -> Self {
        Self {
            local_settings: Settings::default(),
            remote_settings: None,
            decoder_table: DynamicTable::new(),
            encoder_table: DynamicTable::new(),
            pending_encoder: BytesMut::with_capacity(2048),
            pending_decoder: BytesMut::with_capacity(2048),
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, PartialEq)]
pub enum Error {
    HeaderListTooLarge,
    InvalidHeader { reason: String },
    Settings { reason: String },
    EncodeError { reason: EncoderError },
    DecodeError { reason: DecoderError },
}

impl From<EncoderError> for Error {
    fn from(err: EncoderError) -> Error {
        Error::EncodeError { reason: err }
    }
}

impl From<InvalidHeaderValue> for Error {
    fn from(err: InvalidHeaderValue) -> Error {
        Error::InvalidHeader {
            reason: format!("InvalidHeaderValue: {:?}", err),
        }
    }
}

impl From<InvalidHeaderName> for Error {
    fn from(err: InvalidHeaderName) -> Error {
        Error::InvalidHeader {
            reason: format!("InvalidHeaderName: {:?}", err),
        }
    }
}

impl From<qpack::DynamicTableError> for Error {
    fn from(err: qpack::DynamicTableError) -> Error {
        Error::Settings {
            reason: format!("dynamic table error: {}", err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::{HeaderMap, HeaderValue};

    #[test]
    fn encode_no_dynamic() {
        let mut header = HeaderMap::new();
        header.append("hello", HeaderValue::from_static("text/html"));

        let mut conn = Connection::default();
        assert_matches!(conn.encode_header(&StreamId(1), &header), Ok(_));
        assert!(conn.pending_encoder.is_empty());
    }

    #[test]
    fn encode_with_dynamic() {
        let mut header = HeaderMap::new();
        header.append("hello", HeaderValue::from_static("text/html"));

        let mut conn = Connection::default();
        conn.encoder_table
            .inserter()
            .set_max_mem_size(2048)
            .expect("set table size");
        conn.encoder_table
            .set_max_blocked(12usize)
            .expect("set max blocked");
        assert_matches!(conn.encode_header(&StreamId(1), &header), Ok(_));
        assert!(!conn.pending_encoder.is_empty());
    }

    #[test]
    fn encode_too_many_fields() {
        let mut header = HeaderMap::new();
        for _ in 0..5 {
            header.append("hello", HeaderValue::from_static("text/html"));
        }

        let mut conn = Connection::default();
        conn.remote_settings = Some(Settings {
            max_header_list_size: 4,
            ..Settings::default()
        });
        assert_eq!(
            conn.encode_header(&StreamId(1), &header),
            Err(Error::HeaderListTooLarge)
        );
    }

    #[test]
    fn decode_header() {
        let mut header = HeaderMap::new();
        header.append("hello", HeaderValue::from_static("text/html"));

        let mut client = Connection::default();
        let encoded = client
            .encode_header(&StreamId(1), &header)
            .expect("encoding failed");

        let mut server = Connection::default();
        assert_eq!(
            server.decode_header(&StreamId(1), &encoded),
            Ok(Some(header))
        );
        assert!(!server.pending_decoder.is_empty());
    }

    #[test]
    fn decode_blocked() {
        let mut header = HeaderMap::new();
        header.append("hello", HeaderValue::from_static("text/html"));

        let mut client = Connection::default();
        client
            .encoder_table
            .inserter()
            .set_max_mem_size(2048)
            .expect("set table size");
        client
            .encoder_table
            .set_max_blocked(12usize)
            .expect("set max");

        let encoded = client
            .encode_header(&StreamId(1), &header)
            .expect("encoding failed");
        assert!(!client.pending_encoder.is_empty());

        let mut server = Connection::with_settings(Settings {
            qpack_max_table_capacity: 2048,
            qpack_blocked_streams: 42,
            ..Settings::default()
        })
        .expect("create server");

        assert_eq!(server.decode_header(&StreamId(1), &encoded), Ok(None));
        assert!(server.pending_decoder.is_empty());
    }
}
