use bytes::{Buf, BufMut};
use quinn_proto::{
    coding::{BufExt, BufMutExt, Codec, UnexpectedEnd},
    VarInt,
};

use super::frame::{FrameHeader, Type as FrameType};

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub struct SettingId(pub u64);

macro_rules! setting_identifiers {
    {$($name:ident = $val:expr,)*} => {
        impl SettingId {
            $(pub const $name: SettingId = SettingId($val);)*
        }
    }
}

impl SettingId {
    const NONE: SettingId = SettingId(0);

    fn is_supported(self) -> bool {
        match self {
            SettingId::MAX_HEADER_LIST_SIZE
            | SettingId::QPACK_MAX_TABLE_CAPACITY
            | SettingId::QPACK_MAX_BLOCKED_STREAMS => true,
            _ => false,
        }
    }
}

setting_identifiers! {
    QPACK_MAX_TABLE_CAPACITY = 0x1,
    QPACK_MAX_BLOCKED_STREAMS = 0x7,
    MAX_HEADER_LIST_SIZE = 0x6,
}

impl Codec for SettingId {
    fn decode<B: Buf>(buf: &mut B) -> Result<Self, UnexpectedEnd> {
        Ok(SettingId(buf.get_var()?))
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.write_var(self.0);
    }
}

/// Settings for a HTTP/3 connection
///
/// The HTTP/3 protocol offers a few settings to configure limits and header encoding
/// parameters of a connection.
///
/// See the [QPACK] specification for more details.
///
/// [QPACK]: https://quicwg.org/base-drafts/draft-ietf-quic-qpack.html
#[derive(Clone, Debug)]
pub struct Settings {
    max_header_list_size: u64,
    qpack_max_table_capacity: u64,
    qpack_max_blocked_streams: u64,
}

impl Default for Settings {
    /// Create settings with H3 default values
    fn default() -> Self {
        Self {
            max_header_list_size: DEFAULT_MAX_HEADER_LIST_SIZE,
            qpack_max_table_capacity: DEFAULT_QPACK_MAX_TABLE_CAPACITY,
            qpack_max_blocked_streams: DEFAULT_QPACK_MAX_BLOCKED_STREAMS,
        }
    }
}

impl Settings {
    /// Create settings with quinn-h3's recomended values
    ///
    /// Enables `QPACK`.
    pub fn new() -> Self {
        Self {
            max_header_list_size: 0,
            qpack_max_table_capacity: 4096,
            qpack_max_blocked_streams: 128,
        }
    }

    /// The maximum number of entries in headers and trailers
    ///
    /// `0` means infinity.
    pub fn max_header_list_size(&self) -> u64 {
        if self.max_header_list_size == 0 {
            return std::u64::MAX;
        }
        self.max_header_list_size
    }

    /// The maximum size for `QPACK` encoding dynamic table
    ///
    /// `0` means `QPACK` is disabled.
    pub fn qpack_max_table_capacity(&self) -> u64 {
        self.qpack_max_table_capacity
    }

    /// The maximum number of request waiting to be decoded with arriving encoder data
    ///
    /// If `0`, the peer won't send any dynamically encoded headers.
    pub fn qpack_max_blocked_streams(&self) -> u64 {
        self.qpack_max_blocked_streams
    }

    /// Set the maximum number of entries in headers and trailers
    ///
    /// `0` means infinity.
    pub fn set_max_header_list_size(&mut self, value: u64) -> Result<&mut Self, InvalidValue> {
        if value > VarInt::MAX.into_inner() as u64 {
            return Err(InvalidValue(SettingId::QPACK_MAX_TABLE_CAPACITY, value));
        }
        self.max_header_list_size = value;
        Ok(self)
    }

    /// Set the maximum size for `QPACK` encoding dynamic table
    ///
    /// If `0`, the peer won't send any dynamically encoded headers.
    pub fn set_qpack_max_blocked_streams(&mut self, value: u64) -> Result<&mut Self, InvalidValue> {
        if value > MAX_BLOCKED_STREAMS_MAX {
            return Err(InvalidValue(SettingId::QPACK_MAX_BLOCKED_STREAMS, value));
        }
        self.qpack_max_blocked_streams = value;
        Ok(self)
    }

    /// Set the maximum number of request waiting to be decoded with arriving encoder data
    ///
    /// Set this to `0` to disable `QPACK`.
    pub fn set_qpack_max_table_capacity(&mut self, value: u64) -> Result<&mut Self, InvalidValue> {
        if value > MAX_TABLE_CAPACITY_MAX {
            return Err(InvalidValue(SettingId::QPACK_MAX_TABLE_CAPACITY, value));
        }
        self.qpack_max_table_capacity = value;
        Ok(self)
    }

    pub(crate) fn from_frame(settings: SettingsFrame) -> Result<Settings, Error> {
        let mut this = Self::default();
        for (id, val) in settings.entries[..settings.len].iter() {
            match *id {
                SettingId::MAX_HEADER_LIST_SIZE => this.set_max_header_list_size(*val)?,
                SettingId::QPACK_MAX_TABLE_CAPACITY => this.set_qpack_max_table_capacity(*val)?,
                SettingId::QPACK_MAX_BLOCKED_STREAMS => this.set_qpack_max_blocked_streams(*val)?,
                x => return Err(Error::InvalidSettingId(x.0)),
            };
        }
        Ok(this)
    }

    pub(super) fn to_frame(&self) -> SettingsFrame {
        let mut frame = SettingsFrame::default();
        if self.max_header_list_size != DEFAULT_MAX_HEADER_LIST_SIZE {
            frame
                .insert(SettingId::MAX_HEADER_LIST_SIZE, self.max_header_list_size)
                .expect("max header list");
        }
        if self.qpack_max_table_capacity != DEFAULT_QPACK_MAX_TABLE_CAPACITY {
            frame
                .insert(
                    SettingId::QPACK_MAX_TABLE_CAPACITY,
                    self.qpack_max_table_capacity,
                )
                .expect("qpack max table");
        }
        if self.qpack_max_blocked_streams != DEFAULT_QPACK_MAX_BLOCKED_STREAMS {
            frame
                .insert(
                    SettingId::QPACK_MAX_BLOCKED_STREAMS,
                    self.qpack_max_blocked_streams,
                )
                .expect("qpack max blocked");
        }
        frame
    }
}

#[derive(Debug, PartialEq)]
pub struct SettingsFrame {
    entries: [(SettingId, u64); 3],
    len: usize,
}

impl Default for SettingsFrame {
    fn default() -> Self {
        Self {
            entries: [(SettingId::NONE, 0); 3],
            len: 0,
        }
    }
}

impl SettingsFrame {
    fn insert(&mut self, id: SettingId, value: u64) -> Result<(), Error> {
        if self.len >= self.entries.len() {
            return Err(Error::Exceeded);
        }

        if !id.is_supported() {
            return Ok(());
        }

        if self.entries[..self.len].iter().any(|(i, _)| *i == id) {
            return Err(Error::Repeated(id));
        }

        self.entries[self.len] = (id, value);
        self.len += 1;
        Ok(())
    }

    pub(super) fn encode<T: BufMut>(&self, buf: &mut T) {
        self.encode_header(buf);
        for (id, val) in self.entries[..self.len].iter() {
            id.encode(buf);
            buf.write_var(*val);
        }
    }

    pub(super) fn decode<T: Buf>(buf: &mut T) -> Result<SettingsFrame, Error> {
        let mut settings = SettingsFrame::default();
        while buf.has_remaining() {
            if buf.remaining() < 2 {
                // remains less than 2 * minimum-size varint
                return Err(Error::Malformed);
            }

            let identifier = SettingId::decode(buf).map_err(|_| Error::Malformed)?;
            let value = buf.get_var().map_err(|_| Error::Malformed)?;

            if identifier.is_supported() {
                settings.insert(identifier, value)?;
            }
        }
        Ok(settings)
    }
}

impl FrameHeader for SettingsFrame {
    const TYPE: FrameType = FrameType::SETTINGS;
    fn len(&self) -> usize {
        self.entries[..self.len].iter().fold(0, |len, (id, val)| {
            len + VarInt::from_u64(id.0).unwrap().size() + VarInt::from_u64(*val).unwrap().size()
        })
    }
}

const MAX_TABLE_CAPACITY_MAX: u64 = 1_073_741_823; // 2^30 -1
const MAX_BLOCKED_STREAMS_MAX: u64 = 65_535; // 2^16 - 1

const DEFAULT_MAX_HEADER_LIST_SIZE: u64 = 0; // Infinity
const DEFAULT_QPACK_MAX_TABLE_CAPACITY: u64 = 0;
const DEFAULT_QPACK_MAX_BLOCKED_STREAMS: u64 = 0;

#[derive(Debug)]
pub(crate) enum Error {
    Exceeded,
    Malformed,
    Repeated(SettingId),
    InvalidSettingId(u64),
    InvalidSettingValue(SettingId, u64),
}

#[derive(Debug)]
pub struct InvalidValue(SettingId, u64);

impl From<InvalidValue> for Error {
    fn from(e: InvalidValue) -> Error {
        Error::InvalidSettingValue(e.0, e.1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn settings_from_frame() {
        let mut frame = SettingsFrame::default();
        frame
            .insert(SettingId::QPACK_MAX_TABLE_CAPACITY, 40)
            .unwrap();
        frame
            .insert(SettingId::QPACK_MAX_BLOCKED_STREAMS, 41)
            .unwrap();
        frame.insert(SettingId::MAX_HEADER_LIST_SIZE, 42).unwrap();
        let settings = Settings::from_frame(frame).unwrap();
        assert_eq!(settings.qpack_max_table_capacity(), 40);
        assert_eq!(settings.qpack_max_blocked_streams(), 41);
        assert_eq!(settings.max_header_list_size(), 42);
    }

    #[test]
    fn frame_insert_twice() {
        let mut frame = SettingsFrame::default();
        frame
            .insert(SettingId::QPACK_MAX_TABLE_CAPACITY, 0)
            .unwrap();
        assert_matches!(
            frame.insert(SettingId::QPACK_MAX_TABLE_CAPACITY, 0),
            Err(Error::Repeated(SettingId::QPACK_MAX_TABLE_CAPACITY))
        );
    }

    #[test]
    fn settings_frame_unknown_ignored() {
        let mut frame = SettingsFrame::default();
        frame.insert(SettingId(0x1aa), 0).unwrap();
        frame.insert(SettingId(0x13a), 1).unwrap();
        frame.insert(SettingId(0x12a), 2).unwrap();
        frame.insert(SettingId(0x19a), 3).unwrap();
        frame
            .insert(SettingId::QPACK_MAX_TABLE_CAPACITY, 42)
            .unwrap();
        assert_eq!(
            Settings::from_frame(frame)
                .unwrap()
                .qpack_max_table_capacity(),
            42
        );
    }

    #[test]
    fn settings_frame_any_number_of_uknown() {
        let mut buf = Cursor::new(&[26, 1, 6, 1, 27, 0, 1, 2, 28, 0, 7, 3, 29, 0]);
        let settings = Settings::from_frame(SettingsFrame::decode(&mut buf).unwrap()).unwrap();
        assert_eq!(settings.max_header_list_size(), 0x1);
        assert_eq!(settings.qpack_max_table_capacity(), 0x2);
        assert_eq!(settings.qpack_max_blocked_streams(), 0x3);
    }

    #[test]
    fn settings_default_values_not_encoded() {
        let mut settings = Settings::default();
        settings.set_qpack_max_table_capacity(42).unwrap();
        let frame = settings.to_frame();
        assert_eq!(frame.len, 1);
        assert_eq!(frame.entries[0], (SettingId::QPACK_MAX_TABLE_CAPACITY, 42));
    }

    #[test]
    fn settings_all_defaults() {
        assert_eq!(Settings::default().to_frame().len, 0);
    }

    #[test]
    fn settings_all_values() {
        let mut settings = Settings::new();
        // all other values from new() are non-h3-default
        settings.set_max_header_list_size(43).unwrap();
        let frame = settings.to_frame();
        assert_eq!(frame.len, 3);
        assert_eq!(frame.entries[0], (SettingId::MAX_HEADER_LIST_SIZE, 43));
        assert_matches!(frame.entries[1], (SettingId::QPACK_MAX_TABLE_CAPACITY, _));
        assert_matches!(frame.entries[2], (SettingId::QPACK_MAX_BLOCKED_STREAMS, _));
    }
}
