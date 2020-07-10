use std::collections::HashSet;

use bytes::{Buf, Bytes, BytesMut};
use quinn_proto::{Dir, Side, StreamId};
use std::convert::TryFrom;
use tracing::{debug, trace, warn};

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
#[allow(clippy::large_enum_variant)]
pub enum DecodeResult {
    Decoded(Header, bool),
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
    side: Side,
    remote_settings: Option<Settings>,
    decoder_table: DynamicTable,
    encoder_table: DynamicTable,
    pending_streams: [BytesMut; 3],
    requests_in_flight: HashSet<StreamId>,
    max_id_in_flight: StreamId,
    go_away: Option<StreamId>,

    #[cfg(feature = "interop-test-accessors")]
    pub had_refs: bool,
}

impl Connection {
    pub fn new(side: Side, settings: Settings) -> Self {
        let mut decoder_table = DynamicTable::new();
        decoder_table
            .set_max_blocked(settings.qpack_max_blocked_streams() as usize)
            .expect("set max blocked streams");
        decoder_table
            .set_max_size(settings.qpack_max_table_capacity() as usize)
            .expect("set max table size");

        let mut pending_control = BytesMut::with_capacity(128);
        settings.to_frame().encode(&mut pending_control);
        let pending_streams = [
            pending_control,
            BytesMut::with_capacity(2048),
            BytesMut::with_capacity(2048),
        ];

        let dir = match side {
            Side::Server => Dir::Bi,
            Side::Client => Dir::Uni,
        };

        Self {
            side,
            decoder_table,
            pending_streams,
            remote_settings: None,
            encoder_table: DynamicTable::new(),
            requests_in_flight: HashSet::with_capacity(32),
            max_id_in_flight: StreamId::new(side, dir, 0),
            go_away: None,

            #[cfg(feature = "interop-test-accessors")]
            had_refs: false,
        }
    }

    pub fn encode_header(&mut self, stream_id: StreamId, headers: Header) -> Result<HeadersFrame> {
        if let Some(ref s) = self.remote_settings {
            if headers.len() as u64 > s.max_header_list_size() {
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
            encoded: block.freeze(),
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
            Err(DecoderError::MissingRefs(r)) => {
                trace!("header blocked on {}", r);
                Ok(DecodeResult::MissingRefs(r))
            }
            Err(e) => Err(Error::DecodeError { reason: e }),
            Ok((decoded, had_refs)) => {
                if had_refs {
                    #[cfg(feature = "interop-test-accessors")]
                    {
                        self.had_refs = had_refs;
                    }
                    qpack::ack_header(
                        stream_id.0,
                        &mut self.pending_streams[PendingStreamType::Decoder as usize],
                    );
                }
                trace!(
                    "decoded {} fields, required ref {}",
                    decoded.len(),
                    had_refs
                );
                Ok(DecodeResult::Decoded(Header::try_from(decoded)?, had_refs))
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

    pub fn on_recv_decoder<R: Buf>(&mut self, read: &mut R) -> Result<()> {
        Ok(qpack::on_decoder_recv(&mut self.encoder_table, read)?)
    }

    pub fn remote_settings(&self) -> &Option<Settings> {
        &self.remote_settings
    }

    pub fn set_remote_settings(&mut self, settings: Settings) -> Result<()> {
        self.encoder_table
            .set_max_blocked(settings.qpack_max_blocked_streams() as usize)?;
        self.encoder_table
            .set_max_size(settings.qpack_max_table_capacity() as usize)?;

        if settings.qpack_max_table_capacity() > 0 {
            qpack::set_dynamic_table_size(
                &mut self.encoder_table,
                &mut self.pending_streams[PendingStreamType::Encoder as usize],
                settings.qpack_max_table_capacity() as usize,
            )?;
        };

        self.remote_settings = Some(settings);

        Ok(())
    }

    pub fn pending_stream_take(&mut self, ty: PendingStreamType) -> Option<Bytes> {
        if self.pending_streams[ty as usize].is_empty() {
            return None;
        }
        Some(self.pending_streams[ty as usize].split().freeze())
    }

    pub fn pending_stream_release(&mut self, ty: PendingStreamType) {
        let capacity = self.pending_streams[ty as usize].capacity();
        self.pending_streams[ty as usize].reserve(capacity);
    }

    // The remote peer initiated a stream: a request from client or a push from server
    pub fn remote_stream_initiated(&mut self, id: StreamId) -> Result<()> {
        if let Some(max_id) = self.go_away {
            if id.index() > max_id.index() {
                warn!(id=%id, "rejecting");
                return Err(Error::Aborted);
            }
        }
        debug!(id=%id, "accepting");
        self.requests_in_flight.insert(id);
        if id.index() > self.max_id_in_flight.index() {
            self.max_id_in_flight = id
        };
        Ok(())
    }

    // A stream initiated by the remote peer has finished
    pub fn remote_stream_finished(&mut self, id: StreamId) {
        trace!(id=%id, "finished");
        self.requests_in_flight.remove(&id);
    }

    // A graceful shutdown initiated locally, let `allow_streams` potentially in-flight
    // incoming streams be processed.
    pub fn go_away(&mut self, allow_streams: u64) {
        let dir = match self.side {
            Side::Server => Dir::Bi,
            Side::Client => Dir::Uni,
        };
        let max_id = StreamId::new(
            !self.side,
            dir,
            self.max_id_in_flight.index() + allow_streams,
        );
        debug!(last_stream=%max_id, "shutting down");
        self.go_away = Some(max_id);
        HttpFrame::Goaway(self.max_id_in_flight.0)
            .encode(&mut self.pending_streams[PendingStreamType::Control as usize]);
    }

    // Remote peer initiated a graceful shutdown, any stream greater than `max_id`
    // will be rejected.
    pub fn leave(&mut self, max_id: StreamId) {
        self.go_away = Some(max_id);
        self.requests_in_flight.retain(|i| i.0 <= max_id.0);
    }

    pub fn stream_cancel(&mut self, stream_id: StreamId) {
        qpack::stream_canceled(
            stream_id.0,
            &mut self.pending_streams[PendingStreamType::Decoder as usize],
        );
    }

    pub fn shutdown_complete(&self) -> bool {
        self.go_away.is_some() && self.requests_in_flight.is_empty()
    }

    pub fn is_closing(&self) -> bool {
        self.go_away.is_some()
    }
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, PartialEq)]
pub enum Error {
    Aborted,
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
            headers::Error::MissingAuthority => Error::InvalidRequest("missing authority".into()),
            headers::Error::ContradictedAuthority => {
                Error::InvalidRequest(":authority and Host are different".into())
            }
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

    #[test]
    fn encode_no_dynamic() {
        let mut header_map = HeaderMap::new();
        header_map.append("hello", HeaderValue::from_static("text/html"));
        let header = Header::request(Method::GET, Uri::default(), header_map);

        let mut conn = Connection::new(Side::Client, Settings::new());
        assert_matches!(conn.encode_header(StreamId(1), header), Ok(_));
        assert!(conn.pending_streams[PendingStreamType::Encoder as usize].is_empty());
    }

    #[test]
    fn encode_with_dynamic() {
        let mut header_map = HeaderMap::new();
        header_map.append("hello", HeaderValue::from_static("text/html"));
        let header = Header::request(Method::GET, Uri::default(), header_map);

        let mut conn = Connection::new(Side::Client, Settings::new());
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

        let mut conn = Connection::new(Side::Client, Settings::new());
        let mut settings = Settings::new();
        settings.set_max_header_list_size(4).unwrap();
        conn.remote_settings = Some(settings);
        assert_eq!(
            conn.encode_header(StreamId(1), header),
            Err(Error::HeaderListTooLarge)
        );
    }

    #[test]
    fn decode_header() {
        let mut header_map = HeaderMap::new();
        header_map.append("hello", HeaderValue::from_static("text/html"));
        let header = Header::request(
            Method::GET,
            // NOTE: H3 adds a trailing `/`, so the one in following the url is important
            //       only to make the `Header` comparison succeed at the end of this test.
            "https://example.com/".parse().expect("uri"),
            header_map,
        );

        let mut client = Connection::new(Side::Client, Settings::new());
        let encoded = client
            .encode_header(StreamId(1), header.clone())
            .expect("encoding failed");

        let mut server = Connection::new(Side::Client, Settings::new());
        assert_matches!(
            server.decode_header(StreamId(1), &encoded),
            Ok(DecodeResult::Decoded(decoded, false)) => {
                assert_eq!(decoded, header);
            }
        );
        assert!(server.pending_streams[PendingStreamType::Decoder as usize].is_empty());
    }

    #[test]
    fn decode_blocked() {
        let mut header_map = HeaderMap::new();
        header_map.append("hello", HeaderValue::from_static("text/html"));
        let header = Header::request(Method::GET, Uri::default(), header_map);

        let mut client = Connection::new(Side::Client, Settings::new());
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

        let mut settings = Settings::new();
        settings.set_qpack_max_blocked_streams(42).unwrap();
        settings.set_qpack_max_table_capacity(2048).unwrap();
        let mut server = Connection::new(Side::Server, settings);

        assert_matches!(
            server.decode_header(StreamId(1), &encoded),
            Ok(DecodeResult::MissingRefs(1))
        );
        assert!(server.pending_streams[PendingStreamType::Decoder as usize].is_empty());
    }
}
