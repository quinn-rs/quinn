use std::{
    borrow::Cow,
    collections::HashMap,
    convert::TryFrom,
    iter::{IntoIterator, Iterator},
};

use bytes::Bytes;
use http::{
    header::{self, HeaderName, HeaderValue},
    uri, HeaderMap, Method, StatusCode, Uri,
};
use string::String;

use crate::qpack::HeaderField;

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Clone))]
pub struct Header {
    pseudo: Pseudo,
    fields: HeaderMap,
}

#[allow(clippy::len_without_is_empty)]
impl Header {
    pub fn request(method: Method, uri: Uri, fields: HeaderMap) -> Self {
        Self {
            pseudo: Pseudo::request(method, uri),
            fields,
        }
    }

    pub fn response(status: StatusCode, fields: HeaderMap) -> Self {
        Self {
            pseudo: Pseudo::response(status),
            fields,
        }
    }

    pub fn trailer(fields: HeaderMap) -> Self {
        Self {
            pseudo: Pseudo::default(),
            fields,
        }
    }

    pub fn into_request_parts(self) -> Result<(Method, Uri, HeaderMap), Error> {
        let mut uri = Uri::builder();

        if let Some(path) = self.pseudo.path {
            uri.path_and_query(path.as_bytes());
        }

        if let Some(scheme) = self.pseudo.scheme {
            uri.scheme(scheme.as_bytes());
        }

        if let Some(authority) = self.pseudo.authority {
            uri.authority(authority.as_bytes());
        }

        Ok((
            self.pseudo.method.ok_or(Error::MissingMethod)?,
            uri.build().map_err(Error::InvalidRequest)?,
            self.fields,
        ))
    }

    pub fn into_response_parts(self) -> Result<(StatusCode, HeaderMap), Error> {
        Ok((self.pseudo.status.ok_or(Error::MissingStatus)?, self.fields))
    }

    pub fn into_fields(self) -> HeaderMap {
        self.fields
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
                Field::Method(m) => {
                    pseudo.method = Some(m);
                    pseudo.len += 1;
                }
                Field::Scheme(s) => {
                    pseudo.scheme = Some(s);
                    pseudo.len += 1;
                }
                Field::Authority(a) => {
                    pseudo.authority = Some(a);
                    pseudo.len += 1;
                }
                Field::Path(p) => {
                    pseudo.path = Some(p);
                    pseudo.len += 1;
                }
                Field::Status(s) => {
                    pseudo.status = Some(s);
                    pseudo.len += 1;
                }
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
        if name.is_empty() {
            return Err(Error::InvalidHeaderName("name is empty".into()));
        }

        if name[0] != b':' {
            return Ok(Field::Header((
                HeaderName::from_bytes(name).or_else(|_| Err(Error::invalid_name(name)))?,
                HeaderValue::from_bytes(value.as_ref())
                    .or_else(|_| Err(Error::invalid_value(name, value)))?,
            )));
        }

        let pseudo = match PSEUDO_MAP.get(name) {
            Some(pseudo) => pseudo,
            None => return Err(Error::invalid_name(name)),
        };

        Ok(match pseudo {
            PseudoType::SCHEME => Field::Scheme(try_value(name, value)?),
            PseudoType::AUTHORITY => Field::Authority(try_value(name, value)?),
            PseudoType::PATH => Field::Path(try_value(name, value)?),
            PseudoType::METHOD => Field::Method(
                Method::from_bytes(value.as_ref())
                    .or_else(|_| Err(Error::invalid_value(name, value)))?,
            ),
            PseudoType::STATUS => Field::Status(
                StatusCode::from_bytes(value.as_ref())
                    .or_else(|_| Err(Error::invalid_value(name, value)))?,
            ),
        })
    }
}

fn try_value<N, V>(name: N, value: V) -> Result<String<Bytes>, Error>
where
    N: AsRef<[u8]>,
    V: AsRef<[u8]>,
{
    string::TryFrom::<Bytes>::try_from(Bytes::from(value.as_ref()))
        .or_else(|_| Err(Error::invalid_value(name, value)))
}

/// Pseudo-header fields have the same purpose as data from the first line of HTTP/1.X,
/// but are conveyed along with other headers. For example ':method' and ':path' in a
/// request, and ':status' in a response. They must be placed before all other fields,
/// start with ':', and be lowercase.
/// See RFC7540 section 8.1.2.1. for more details.
#[derive(Debug, Default)]
#[cfg_attr(test, derive(PartialEq, Clone))]
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

#[allow(clippy::len_without_is_empty)]
impl Pseudo {
    pub fn request(method: Method, uri: Uri) -> Self {
        let parts = uri::Parts::from(uri);

        let mut path = parts
            .path_and_query
            .map(|v| v.into())
            .unwrap_or_else(Bytes::new);

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
            ].iter().map(|(n, v)| (n.clone(), v.clone())).collect();
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

#[derive(Debug)]
pub enum Error {
    InvalidHeaderName(std::string::String),
    InvalidHeaderValue(std::string::String),
    InvalidRequest(http::Error),
    MissingMethod,
    MissingStatus,
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
