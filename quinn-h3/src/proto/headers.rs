use std::borrow::Cow;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::iter::{IntoIterator, Iterator};

use bytes::Bytes;
use http::{
    header::{self, HeaderName, HeaderValue},
    uri, HeaderMap, Method, StatusCode, Uri,
};
use string::String;

use crate::qpack::HeaderField;

#[derive(Debug)]
pub struct Header {
    pseudo: Pseudo,
    fields: HeaderMap,
}

impl Header {
    pub fn request(method: Method, uri: Uri, headers: HeaderMap) -> Self {
        let pseudo = Pseudo::request(method, uri);

        Header {
            pseudo: pseudo,
            fields: headers,
        }
    }

    pub fn len(&self) -> usize {
        self.pseudo.len() + self.fields.len()
    }
}

impl IntoIterator for Header {
    type Item = HeaderField;
    type IntoIter = HeaderIter;
    fn into_iter(self) -> Self::IntoIter {
        HeaderIter {
            pseudo: Some(self.pseudo),
            fields: self.fields.into_iter(),
        }
    }
}

pub struct HeaderIter {
    pseudo: Option<Pseudo>,
    fields: header::IntoIter<HeaderValue>,
}

impl Iterator for HeaderIter {
    type Item = HeaderField;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(ref mut pseudo) = self.pseudo {
            if let Some(method) = pseudo.method.take() {
                return Some((":method", method.as_str()).into());
            }

            if let Some(scheme) = pseudo.scheme.take() {
                return Some((":scheme", scheme.as_bytes()).into());
            }

            if let Some(authority) = pseudo.authority.take() {
                return Some((":authority", authority.as_bytes()).into());
            }

            if let Some(path) = pseudo.path.take() {
                return Some((":path", path.as_bytes()).into());
            }

            if let Some(status) = pseudo.status.take() {
                return Some((":status", status.as_str()).into());
            }
        }

        self.pseudo = None;

        while let Some(f) = self.fields.next() {
            if let (Some(n), v) = f {
                return Some((n.as_str(), v.as_bytes()).into());
            }
        }

        None
    }
}

impl TryFrom<Vec<HeaderField>> for Header {
    type Error = Error;
    fn try_from(headers: Vec<HeaderField>) -> Result<Self, Self::Error> {
        let mut fields = HeaderMap::with_capacity(headers.len());
        let mut pseudo = Pseudo::default();

        for field in headers.into_iter() {
            let (name, value) = field.into_inner();
            match Field::parse(name, value)? {
                Field::Method(m) => pseudo.method = Some(m),
                Field::Scheme(s) => pseudo.scheme = Some(s),
                Field::Authority(a) => pseudo.authority = Some(a),
                Field::Path(p) => pseudo.path = Some(p),
                Field::Status(s) => pseudo.status = Some(s),
                Field::Header((n, v)) => {
                    fields.append(n, v);
                }
            }
        }

        Ok(Header { pseudo, fields })
    }
}

enum Field {
    Method(Method),
    Scheme(String<Bytes>),
    Authority(String<Bytes>),
    Path(String<Bytes>),
    Status(StatusCode),
    Header((HeaderName, HeaderValue)),
}

impl Field {
    pub fn parse<N, V>(name: N, value: V) -> Result<Self, Error>
    where
        N: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        let name = name.as_ref();
        if name.len() < 1 {
            return Err(Error::InvalidHeaderName(format!("{:?}", name)));
        }

        if name[0] == b':' {
            let pseudo = match PSEUDO_MAP.get(name) {
                Some(pseudo) => pseudo,
                None => return Err(Error::invalid_name(name)),
            };
            return Ok(match pseudo {
                PseudoType::SCHEME => Field::Scheme(try_value(name, value)?),
                PseudoType::AUTHORITY => Field::Authority(try_value(name, value)?),
                PseudoType::PATH => Field::Path(try_value(name, value)?),
                PseudoType::METHOD => Field::Method(
                    Method::from_bytes(value.as_ref())
                        .or(Err(Error::invalid_value(name, value)))?,
                ),
                PseudoType::STATUS => Field::Status(
                    StatusCode::from_bytes(value.as_ref().into())
                        .or(Err(Error::invalid_value(name, value)))?,
                ),
            });
        }

        Ok(Field::Header((
            HeaderName::from_bytes(name.as_ref().into()).or(Err(Error::invalid_name(name)))?,
            HeaderValue::from_bytes(value.as_ref().into())
                .or(Err(Error::invalid_value(name, value)))?,
        )))
    }
}

fn try_value<N, V>(name: N, value: V) -> Result<String<Bytes>, Error>
where
    N: AsRef<[u8]>,
    V: AsRef<[u8]>,
{
    string::TryFrom::<Bytes>::try_from(Bytes::from(value.as_ref()))
        .or(Err(Error::invalid_value(name, value)))
}

macro_rules! pseudo_type {
    (
        $(
            ($name:ident, $val:expr),
        )+
    ) => {
        #[derive(Clone)]
        enum PseudoType { $($name,)* }

        lazy_static! {
            static ref PSEUDO_MAP: HashMap<Cow<'static, [u8]>, PseudoType> = [
                $((Cow::Borrowed(&$val[..]), PseudoType::$name),)+
            ].into_iter().map(|(n, v)| (n.clone(), v.clone())).collect();
        }
    }
}

pseudo_type![
    (METHOD, b":method"),
    (SCHEME, b":scheme"),
    (AUTHORITY, b":authority"),
    (PATH, b":path"),
    (STATUS, b":status"),
];

#[derive(Debug, Default, Eq, PartialEq)]
pub struct Pseudo {
    // Request
    method: Option<Method>,
    scheme: Option<String<Bytes>>,
    authority: Option<String<Bytes>>,
    path: Option<String<Bytes>>,

    // Response
    status: Option<StatusCode>,

    len: usize,
}

impl Pseudo {
    pub fn request(method: Method, uri: Uri) -> Self {
        let parts = uri::Parts::from(uri);

        let mut path = parts
            .path_and_query
            .map(|v| v.into())
            .unwrap_or_else(|| Bytes::new());

        if path.is_empty() && method != Method::OPTIONS {
            path = Bytes::from_static(b"/");
        }

        let mut pseudo = Pseudo {
            method: Some(method),
            scheme: None,
            authority: None,
            path: Some(to_string(path)),
            status: None,
            len: 2,
        };

        if let Some(scheme) = parts.scheme {
            pseudo.set_scheme(scheme);
        }

        if let Some(authority) = parts.authority {
            pseudo.set_authority(to_string(authority.into()));
        }

        pseudo
    }

    pub fn response(status: StatusCode) -> Self {
        Pseudo {
            method: None,
            scheme: None,
            authority: None,
            path: None,
            status: Some(status),
            len: 1,
        }
    }

    pub fn set_scheme(&mut self, scheme: uri::Scheme) {
        self.scheme = Some(to_string(scheme.into()));
        self.len += 1;
    }

    pub fn set_authority(&mut self, authority: String<Bytes>) {
        self.authority = Some(authority);
        self.len += 1;
    }

    pub fn len(&self) -> usize {
        self.len
    }
}

fn to_string(src: Bytes) -> String<Bytes> {
    unsafe { String::from_utf8_unchecked(src) }
}

pub enum Error {
    InvalidHeaderName(std::string::String),
    InvalidHeaderValue(std::string::String),
}

impl Error {
    fn invalid_name<N>(name: N) -> Self
    where
        N: AsRef<[u8]>,
    {
        Error::InvalidHeaderName(format!("{:?}", name.as_ref()))
    }

    fn invalid_value<N, V>(name: N, value: V) -> Self
    where
        N: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        Error::InvalidHeaderValue(format!(
            "{:?} {:?}",
            to_string(name.as_ref().into()),
            value.as_ref()
        ))
    }
}
