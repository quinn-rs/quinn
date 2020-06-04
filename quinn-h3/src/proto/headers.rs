use std::{
    borrow::Cow,
    collections::HashMap,
    convert::TryFrom,
    iter::{IntoIterator, Iterator},
    str::FromStr,
};

use http::{
    header::{self, HeaderName, HeaderValue},
    uri::{self, Authority, Parts, PathAndQuery, Scheme, Uri},
    HeaderMap, Method, StatusCode,
};

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
            uri = uri.path_and_query(path.as_str().as_bytes());
        }

        if let Some(scheme) = self.pseudo.scheme {
            uri = uri.scheme(scheme.as_str().as_bytes());
        }

        match (self.pseudo.authority, self.fields.get("host")) {
            (None, None) => return Err(Error::MissingAuthority),
            (Some(a), None) => uri = uri.authority(a.as_str().as_bytes()),
            (None, Some(h)) => uri = uri.authority(h.as_bytes()),
            (Some(a), Some(h)) if a.as_str() != h => return Err(Error::ContradictedAuthority),
            (Some(_), Some(h)) => uri = uri.authority(h.as_bytes()),
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

    #[cfg(test)]
    pub(crate) fn authory_mut(&mut self) -> &mut Option<Authority> {
        &mut self.pseudo.authority
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
                return Some((":scheme", scheme.as_str().as_bytes()).into());
            }

            if let Some(authority) = pseudo.authority.take() {
                return Some((":authority", authority.as_str().as_bytes()).into());
            }

            if let Some(path) = pseudo.path.take() {
                return Some((":path", path.as_str().as_bytes()).into());
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
    Scheme(Scheme),
    Authority(Authority),
    Path(PathAndQuery),
    Status(StatusCode),
    Header((HeaderName, HeaderValue)),
}

impl Field {
    fn parse<N, V>(name: N, value: V) -> Result<Self, Error>
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

fn try_value<N, V, R>(name: N, value: V) -> Result<R, Error>
where
    N: AsRef<[u8]>,
    V: AsRef<[u8]>,
    R: FromStr,
{
    let (name, value) = (name.as_ref(), value.as_ref());
    let s = std::str::from_utf8(value).map_err(|_| Error::invalid_value(name, value))?;
    R::from_str(s).map_err(|_| Error::invalid_value(name, value))
}

/// Pseudo-header fields have the same purpose as data from the first line of HTTP/1.X,
/// but are conveyed along with other headers. For example ':method' and ':path' in a
/// request, and ':status' in a response. They must be placed before all other fields,
/// start with ':', and be lowercase.
/// See RFC7540 section 8.1.2.1. for more details.
#[derive(Debug, Default)]
#[cfg_attr(test, derive(PartialEq, Clone))]
struct Pseudo {
    // Request
    method: Option<Method>,
    scheme: Option<Scheme>,
    authority: Option<Authority>,
    path: Option<PathAndQuery>,

    // Response
    status: Option<StatusCode>,

    len: usize,
}

#[allow(clippy::len_without_is_empty)]
impl Pseudo {
    fn request(method: Method, uri: Uri) -> Self {
        let Parts {
            scheme,
            authority,
            path_and_query,
            ..
        } = uri::Parts::from(uri);

        let path = path_and_query.map_or_else(
            || PathAndQuery::from_static("/"),
            |path| {
                if path.path().is_empty() && method != Method::OPTIONS {
                    PathAndQuery::from_static("/")
                } else {
                    path
                }
            },
        );

        let len = 3 + if authority.is_some() { 1 } else { 0 };

        Self {
            method: Some(method),
            scheme: scheme.or(Some(Scheme::HTTPS)),
            authority,
            path: Some(path),
            status: None,
            len,
        }
    }

    fn response(status: StatusCode) -> Self {
        Pseudo {
            method: None,
            scheme: None,
            authority: None,
            path: None,
            status: Some(status),
            len: 1,
        }
    }

    fn len(&self) -> usize {
        self.len
    }
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
    InvalidHeaderName(String),
    InvalidHeaderValue(String),
    InvalidRequest(http::Error),
    MissingMethod,
    MissingStatus,
    MissingAuthority,
    ContradictedAuthority,
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
            String::from_utf8_lossy(name.as_ref()),
            value.as_ref()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_has_no_authority_nor_host() {
        let headers = Header::try_from(vec![(b":method", Method::GET.as_str()).into()]).unwrap();
        assert!(headers.pseudo.authority.is_none());
        assert_matches!(headers.into_request_parts(), Err(Error::MissingAuthority));
    }

    #[test]
    fn request_has_authority() {
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b":authority", b"test.com").into(),
        ])
        .unwrap();
        assert_matches!(headers.into_request_parts(), Ok(_));
    }

    #[test]
    fn request_has_host() {
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b"host", b"test.com").into(),
        ])
        .unwrap();
        assert!(headers.pseudo.authority.is_none());
        assert_matches!(headers.into_request_parts(), Ok(_));
    }

    #[test]
    fn request_has_same_host_and_authority() {
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b":authority", b"test.com").into(),
            (b"host", b"test.com").into(),
        ])
        .unwrap();
        assert_matches!(headers.into_request_parts(), Ok(_));
    }
    #[test]
    fn request_has_different_host_and_authority() {
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b":authority", b"authority.com").into(),
            (b"host", b"host.com").into(),
        ])
        .unwrap();
        assert_matches!(
            headers.into_request_parts(),
            Err(Error::ContradictedAuthority)
        );
    }
}
