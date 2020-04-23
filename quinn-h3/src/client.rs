//! Client implementation for the HTTP/3 protocol.
//!
//! # Overview
//!
//! Start by constructing a [`Client`] endpoint with a [`Builder`], then [`connect()`] to a server.
//! Before being able to issue requests, a handshake phase will need to be completed, waiting for
//! [`Connecting`] to resolve. You can also choose to try to issue your first request even before
//! the handshake succeeds, using the [`0-RTT`] feature.
//!
//! Once a [`Connection`] is up and running, you can start sending [`Request`]s via
//! [`Connection::send_request()`]. After this, a [`RecvResponse`] and a [`BodyWriter`] future are
//! made available for, respectively, receiving the response, and sending the request's body, if any.
//!
//! [`RecvResponse`] represents the response's header reception and decoding. It will yield
//! headers values as a [`Response`] struct. Along with a [`BodyReader`], enabling to stream
//! the response body via its [`AsyncRead`] implementation, then possibly receive the trailers.
//!
//! # Example
//!
//! ```
//! use std::{fs, net::SocketAddr};
//! use futures::AsyncReadExt;
//! use http::{Request};
//! use quinn_h3::client::Client;
//!
//! #[tokio::main]
//! async fn main() {
//! # return;
//!     // Create an endpoint
//!     let client = Client::default();
//!
//!     // Connect to a server
//!     let socket = "example.com:443".parse().unwrap();
//!     let connecting = client.connect(&socket, "example.com").unwrap();
//!     // Wait for the handshake to succeed
//!     let connection = connecting.await.unwrap();
//!
//!     // Send a request
//!     let request = Request::get("https://example.com").body(()).unwrap();
//!     let (recv_response, _body_writer) = connection.send_request(request).await.unwrap();
//!
//!     // Receive the response
//!     let (response, body_reader) = recv_response.await.unwrap();
//!
//!     // Stream the response body into a string
//!     let mut body = String::new();
//!     body_reader.read_to_string(&mut body).await.unwrap();
//!
//!     println!("response: {:?}, body: \n'{}'", response, body);
//! }
//! ```
//!
//! [`Builder`]: struct.Builder.html
//! [`Client`]: struct.Client.html
//! [`connect()`]: struct.Client.html#metod.connect
//! [`Connecting`]: struct.Connecting.html
//! [`0-RTT`]: struct.Connecting.html#method.into_0rtt
//! [`Connection`]: struct.Connection.html
//! [`Request`]: https://docs.rs/http/*/http/request/index.html
//! [`Connection::send_request()`]: struct.Connection.html#method.send_request
//! [`BodyWriter`]: ../struct.BodyWriter.html
//! [`BodyReader`]: ../struct.BodyReader.html
//! [`SendRequest`]: struct.SendRequest.html
//! [`RecvResponse`]: struct.RecvResponse.html
//! [`Response`]: https://docs.rs/http/*/http/request/index.html
//! [`AsyncRead`]: https://docs.rs/futures/*/futures/io/trait.AsyncRead.html

#![allow(clippy::needless_doctest_main)]

use std::{
    future::Future,
    mem,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{ready, Stream};
use http::{request, Request, Response};
use quinn::{Certificate, Endpoint};
use quinn_proto::{Side, StreamId};
use tracing::trace;

use crate::{
    body::{Body, BodyReader, BodyWriter},
    connection::{ConnectionDriver, ConnectionRef},
    frame::{FrameDecoder, FrameStream, WriteFrame},
    headers::{DecodeHeaders, SendHeaders},
    proto::{
        frame::{DataFrame, HttpFrame},
        headers::Header,
        settings::Settings,
        ErrorCode,
    },
    streams::Reset,
    Error, ZeroRttAccepted,
};

/// Configure and build a new HTTP/3 client
///
/// Creates a [`Client`] with a custom configuration. If you don't need anything specific,
/// you can use the shorter [`Client::new()`] method instead.
///
/// ```
/// # use anyhow::Result;
/// # async fn example() -> Result<()> {
/// use std::fs;
/// use quinn_h3::{client, Settings};
///
/// let cert = quinn::Certificate::from_der(&fs::read("cert.der")?)?;
///
/// let mut settings = Settings::default();
/// settings.set_max_header_list_size(4096).unwrap();
///
/// let mut builder = client::Builder::default();
/// builder.settings(settings);
/// builder.add_certificate_authority(cert);
///
/// let client = builder.build()?;
/// # Ok(())
/// # }
/// ```
///
/// [`Client`]: struct.Client.html
/// [`Client::new()`]: struct.Client.html#method.new
#[derive(Clone)]
pub struct Builder {
    settings: Settings,
    client_config: quinn::ClientConfigBuilder,
}

impl Default for Builder {
    fn default() -> Self {
        let mut client_config = quinn::ClientConfigBuilder::default();
        client_config.protocols(&[crate::ALPN]);

        Self {
            client_config,
            settings: Settings::new(),
        }
    }
}

impl Builder {
    /// Set the HTTP/3 settings
    pub fn settings(&mut self, settings: Settings) -> &mut Self {
        self.settings = settings;
        self
    }

    /// Create a new client
    ///
    /// This method spawns a task for the QUIC endpoint's IO management, therefore it must
    /// be called from tokio runtime context.
    pub fn build(self) -> Result<Client, quinn::EndpointError> {
        let mut endpoint_builder = quinn::Endpoint::builder();
        endpoint_builder.default_client_config(self.client_config.build());
        let (endpoint, _) = endpoint_builder.bind(&"[::]:0".parse().unwrap())?;

        Ok(Client {
            endpoint,
            settings: self.settings,
        })
    }

    /// Add a trusted certificate authotity
    ///
    /// Quinn uses the system's certificate authorities by default. Use this method to add
    /// a custom one.
    pub fn add_certificate_authority(
        &mut self,
        cert: Certificate,
    ) -> Result<&mut Self, webpki::Error> {
        self.client_config.add_certificate_authority(cert)?;
        Ok(self)
    }

    /// Configure the client from an existing QUIC config
    ///
    /// If you need to configure QUIC settings, for example control flow or crypto, use this
    /// function to create your builder.
    pub fn with_quic_config(mut client_config: quinn::ClientConfigBuilder) -> Self {
        client_config.protocols(&[crate::ALPN]);
        Self {
            client_config,
            settings: Settings::new(),
        }
    }

    /// Create a new client bound to an existing QUIC endpoint
    ///
    /// This is usefull if you want to manage several clients, possibly using different protocols,
    /// with the same QUIC client endpoint.
    pub fn endpoint(self, endpoint: Endpoint) -> Client {
        Client {
            endpoint,
            settings: self.settings,
        }
    }
}

/// Client endpoint for the HTTP/3 protocol
///
/// This lets you connect to HTTP/3 servers with given settings.
///
/// It also contains saved crypto sessions, so a new connection can accept [`0-RTT`] exchanges when
/// a prior connection to the same server as already suceeded.
///
/// ```
/// use std::net::SocketAddr;
/// use quinn_h3::client::Client;
///
/// # async fn example() {
/// let client = Client::default();
/// let connection = client.connect(&"example.com".parse().unwrap(), "example.com");
/// # }
/// ```
/// [`0-RTT`]: struct.Connecting.html#method.into_0rtt
pub struct Client {
    endpoint: Endpoint,
    settings: Settings,
}
impl Default for Client {
    /// Create a new HTTP/3 client endpoint with crate's recomended settings
    fn default() -> Self {
        Builder::default().build().expect("build default client")
    }
}

impl Client {
    /// Connect to a remote server endpoint
    ///
    /// Initiates a hanshake with an endpoint. The `server_name` argument is  used to
    /// authenticate the server, it must be covered by its certificate.
    ///
    /// This method spawns a driver task for endpoint's IOs management at the QUIC level.
    /// Therefore, it must be called in tokio runtime context.
    ///
    /// On success, this method returns a [`Connecting`] future, representing the handhake
    /// completion.
    ///
    /// [`Connecting`]: struct.Connecting.html
    pub fn connect(
        &self,
        addr: &SocketAddr,
        server_name: &str,
    ) -> Result<Connecting, quinn::ConnectError> {
        Ok(Connecting {
            settings: self.settings.clone(),
            connecting: self.endpoint.connect(addr, server_name)?,
        })
    }

    /// Connect to a remote server endpoint with a specific QUIC config
    ///
    /// This is useful when you want to tune QUIC settings for one connection. Note that
    /// [`Builder::with_quic_config()`] enalbes such a configuration for all connections.
    ///
    /// [`Builder::with_quic_config()`]: struct.Builder.html#method.with_quic_config
    pub fn connect_with(
        &self,
        client_config: quinn::ClientConfig,
        addr: &SocketAddr,
        server_name: &str,
    ) -> Result<Connecting, quinn::ConnectError> {
        Ok(Connecting {
            settings: self.settings.clone(),
            connecting: self
                .endpoint
                .connect_with(client_config, addr, server_name)?,
        })
    }

    /// Wait for all connections on the endpoint to be cleanly shut down
    ///
    /// Waiting for this condition before exiting ensures that a good-faith effort is made to notify
    /// peers of recent connection closes, whereas exiting immediately could force them to wait out
    /// the idle timeout period.
    ///
    /// Does not proactively close existing connections. Consider calling [`Connection::close()`] if
    /// that is desired.
    ///
    /// [`Connection::close`]: struct.Connection.html#method.close
    pub async fn wait_idle(&mut self) {
        self.endpoint.wait_idle().await;
    }
}

/// HTTP/3 handshake future
///
/// Represents an ongoing HTTP/3 handshake. Upon success, this future will resolve into an
/// established [`Connection`].
///
/// [`Connection`]: struct.Connection.html
pub struct Connecting {
    connecting: quinn::Connecting,
    settings: Settings,
}

impl Connecting {
    /// Try to convert an ongoing handshake into a 0-RTT enabled exchange
    ///
    /// # About 0-RTT
    ///
    /// 0 Round Trip Time is a QUIC feature enabling application data exchange before the
    /// peers have finished the TLS handshake. It's based on prior crypto exchange, reused
    /// for a new connection. So this function will fail if it's the first contact with
    /// the server.
    ///
    /// # Security concerns
    ///
    /// This functionality is vulnerable to replay attacks. Therefore any request with a
    /// non-idempotent method sent before [`ZeroRttAccepted`] resolves will fail.
    ///
    /// # Usage
    ///
    /// Upon success, this method returns a [`Connection`], and a `Future`
    /// that will resolve when the handshake completes: [`ZeroRttAccepted`]. If this peer
    /// is not associated with any known prior connection, the [`Connecting`] handshake
    /// completion future will be handed back.
    ///
    /// ## Task spawing
    ///
    /// This method spawns two driver tasks for connection management at QUIC and HTTP/3
    /// levels. Therefore, it must be called in tokio runtime context.
    ///
    /// ## Example
    /// ```
    /// # use anyhow::Result;
    /// use http::Request;
    /// use quinn_h3::client::{Connecting, RecvResponse};
    ///
    /// async fn send_0rtt_request(connecting: Connecting) -> Result<RecvResponse> {
    ///     let request = Request::get("https://example.com").body(()).unwrap();
    ///
    ///     let mut connection = match connecting.into_0rtt() {
    ///         Ok((connection, _)) => connection,
    ///         Err(connecting) => connecting.await?,
    ///     };
    ///
    ///     let (recv_response, _) = connection.send_request(request).await.unwrap();
    ///
    ///     Ok(recv_response)
    /// }
    /// ```
    ///
    /// [`Connection`]: struct.Connection.html
    /// [`ZeroRttAccepted`]: type.ZeroRttAccepted.html
    /// [`Connecting`]: struct.Connecting.html
    pub fn into_0rtt(self) -> Result<(Connection, ZeroRttAccepted), Self> {
        let Self {
            connecting,
            settings,
        } = self;
        match connecting.into_0rtt() {
            Err(connecting) => Err(Self {
                connecting,
                settings,
            }),
            Ok((new_conn, zero_rtt)) => {
                let quinn::NewConnection {
                    connection,
                    uni_streams,
                    bi_streams,
                    ..
                } = new_conn;
                let conn_ref =
                    ConnectionRef::new(connection, Side::Client, uni_streams, bi_streams, settings);
                tokio::spawn(ConnectionDriver(conn_ref.clone()));
                Ok((Connection(conn_ref), zero_rtt))
            }
        }
    }
}

impl Future for Connecting {
    type Output = Result<Connection, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let quinn::NewConnection {
            connection,
            uni_streams,
            bi_streams,
            ..
        } = ready!(Pin::new(&mut self.connecting).poll(cx))?;
        let conn_ref = ConnectionRef::new(
            connection,
            Side::Client,
            uni_streams,
            bi_streams,
            self.settings.clone(),
        );
        tokio::spawn(ConnectionDriver(conn_ref.clone()));
        Poll::Ready(Ok(Connection(conn_ref)))
    }
}

/// Established HTTP/3 connection
///
/// This enables you to send requests to the server with [`send_request()`] and [`close()`]
/// the connection.
///
/// Note that the connection will also be closed when this object is dropped.
///
/// ```
/// # use anyhow::Result;
/// use futures::AsyncWriteExt;
/// use http::Request;
/// use quinn_h3::client::{Connection};
///
/// async fn post_things(connection: &mut Connection, body: &[u8]) -> Result<()> {
///     let request = Request::post("https://example.com").body(())?;
///
///     // Send the request
///     let (recv_response, mut body_writer) = connection.send_request(request).await?;
///     body_writer.write_all(body).await?;
///
///     let (response, _) = recv_response.await?;
///     Ok(())
/// }
///
/// ```
/// [`send_request()`]: #method.send_request
/// [`close()`]: #method.close
pub struct Connection(ConnectionRef);

impl Connection {
    /// Send a HTTP/3 request
    ///
    /// This accepts a [`http::Request<B>`] and emits a [`RecvRequest`] future along with a
    /// [`BodyWriter`]. The former will resolve when the response headers are received. You can
    /// optionally stream the request body with the latter through its [`AsyncWrite`] implementation.
    /// Note that you can also use the parameter type of [`http::Request<B>`], if the body is small
    /// enough and implements [`Into<Body>`].
    ///
    /// # Example: GET request
    /// ```
    /// # use anyhow::Result;
    /// use futures::AsyncReadExt;
    /// use http::Request;
    /// use quinn_h3::client::Connection;
    ///
    /// async fn get_things(connection: &mut Connection) -> Result<()> {
    ///     let request = Request::get("https://example.com/things").body(())?;
    ///
    ///     // Send the request
    ///     let (recv_response, _) = connection.send_request(request).await?;
    ///
    ///     // Receive the response
    ///     let (response, mut body_reader) = recv_response.await?;
    ///     let mut body = String::new();
    ///     body_reader.read_to_string(&mut body).await?;
    ///    
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Example: upload a file with POST
    /// ```
    /// # use anyhow::Result;
    /// use futures::AsyncReadExt;
    /// use http::Request;
    /// use quinn_h3::client::Connection;
    ///
    /// async fn post_thing(connection: &mut Connection, path: &str) -> Result<()> {
    ///     let request = Request::post("https://example.com/new_thing").body(())?;
    ///     let mut file = tokio::fs::File::open(path).await?;
    ///
    ///     // Send the request's headers
    ///     let (recv_response, mut body_writer) = connection.send_request(request).await?;
    ///     // Stream the request's body from a file to the server
    ///     tokio::io::copy(&mut file, &mut body_writer).await?;
    ///
    ///     // Stream the response into body a string
    ///     let (response, mut body_reader) = recv_response.await?;
    ///     let mut body = String::new();
    ///     body_reader.read_to_string(&mut body).await?;
    ///
    ///     Ok(())
    /// }
    /// ```
    /// [`http::Request<B>`]: https://docs.rs/http/*/http/request/index.html
    /// [`RecvRequest`]: struct.RecvRequest.html
    /// [`BodyWriter`]: ../struct.BodyWriter.html
    /// [`AsyncWrite`]: https://docs.rs/futures/*/futures/io/trait.AsyncWrite.html
    /// [`Into<Body>`]: ../struct.Body.html
    pub async fn send_request<T: Into<Body>>(
        &self,
        request: Request<T>,
    ) -> Result<(RecvResponse, BodyWriter), Error> {
        let (request, body) = request.into_parts();
        let request::Parts {
            method,
            uri,
            headers,
            ..
        } = request;
        let (send, recv) = self.0.quic.open_bi().await?;

        if recv.is_0rtt() && !method.is_idempotent() {
            return Err(Error::internal("non-idempotent method tried on 0RTT"));
        }

        let stream_id = send.id();
        let send = SendHeaders::new(
            Header::request(method, uri, headers),
            &self.0,
            send,
            stream_id,
        )?
        .await?;

        let recv = RecvResponse::new(FrameDecoder::stream(recv), self.0.clone(), stream_id);
        match body.into() {
            Body::Buf(payload) => {
                let send: WriteFrame<DataFrame<_>> = WriteFrame::new(send, DataFrame { payload });
                Ok((
                    recv,
                    BodyWriter::new(send.await?, self.0.clone(), stream_id, false),
                ))
            }
            Body::None => Ok((
                recv,
                BodyWriter::new(send, self.0.clone(), stream_id, false),
            )),
        }
    }

    /// Close the connection immediately
    ///
    /// All ongoing requests will fail. Peer will receive a connection error with `NO_ERROR` code.
    pub fn close(self) {
        trace!("connection closed by user");
        self.0
            .quic
            .close(ErrorCode::NO_ERROR.into(), b"Connection closed");
    }

    // Update traffic keys spontaneously for testing purposes.
    #[doc(hidden)]
    pub fn force_key_update(&self) {
        self.0.quic.force_key_update();
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.0
            .quic
            .close(ErrorCode::NO_ERROR.into(), b"Connection closed");
    }
}

/// Receive an HTTP/3 response
///
/// This future is emitted by [`Connection::send_request()`] and will resolve once the response
/// headers are received and decoded.
///
/// Upon success, it will yield a [`Response`] struct containing the headers, and a
/// [`BodyWriter`] enabling to stream the response body via its [`AsyncRead`] implementation.
///
/// # Example: download into a file
/// ```
/// # use anyhow::Result;
/// use http::{Request, StatusCode};
/// use quinn_h3::client::Connection;
///
/// async fn download_file(connection: &mut Connection, path: &str) -> Result<()> {
///     let request = Request::post("https://example.com/new_thing").body(())?;
///     let (recv_response, mut body_writer) = connection.send_request(request).await?;
///
///     // Receive the response's headers
///     let (response, mut body_reader) = recv_response.await?;
///
///     // Check the headers
///     if response.status() == StatusCode::OK {
///         // Stream the response's body into a file
///         let mut file = tokio::fs::File::open(path).await?;
///         tokio::io::copy(&mut body_reader, &mut file).await?;
///     }
///
///     Ok(())
/// }
/// ```
/// [`Connection::send_request()`]: struct.Connection.htm#method.send_request
/// [`Response`]: https://docs.rs/http/*/http/response/index.html
/// [`BodyWriter`]: ../struct.BodyWriter.html
/// [`AsyncRead`]: https://docs.rs/futures/*/futures/io/trait.AsyncRead.html
pub struct RecvResponse {
    state: RecvResponseState,
    conn: ConnectionRef,
    stream_id: StreamId,
    recv: Option<FrameStream>,
}

enum RecvResponseState {
    Receiving(FrameStream),
    Decoding(DecodeHeaders),
    Finished,
}

impl RecvResponse {
    pub(crate) fn new(recv: FrameStream, conn: ConnectionRef, stream_id: StreamId) -> Self {
        Self {
            conn,
            stream_id,
            recv: None,
            state: RecvResponseState::Receiving(recv),
        }
    }

    /// Cancel a HTTP/3 response reception
    ///
    /// Server will receive a request error with `REQUEST_CANCELLED` code. Any call on any
    /// object related with this request will fail.
    pub fn cancel(mut self) {
        let recv = match mem::replace(&mut self.state, RecvResponseState::Finished) {
            RecvResponseState::Receiving(recv) => recv,
            RecvResponseState::Decoding(_) => self.recv.take().expect("cancel recv"),
            _ => return,
        };
        self.conn.h3.lock().unwrap().cancel_request(self.stream_id);
        recv.reset(ErrorCode::REQUEST_CANCELLED);
    }
}

impl Future for RecvResponse {
    type Output = Result<(Response<()>, BodyReader), crate::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        loop {
            match self.state {
                RecvResponseState::Finished => {
                    return Poll::Ready(Err(crate::Error::internal(
                        "recv response polled after finish",
                    )))
                }
                RecvResponseState::Receiving(ref mut recv) => {
                    let frame = ready!(Pin::new(recv).poll_next(cx));

                    trace!("client got {:?}", frame);
                    match frame {
                        None => return Poll::Ready(Err(Error::peer("received an empty response"))),
                        Some(Err(e)) => return Poll::Ready(Err(e.into())),
                        Some(Ok(f)) => match f {
                            HttpFrame::Reserved => (),
                            HttpFrame::Headers(h) => {
                                let decode =
                                    DecodeHeaders::new(h, self.conn.clone(), self.stream_id);
                                match mem::replace(
                                    &mut self.state,
                                    RecvResponseState::Decoding(decode),
                                ) {
                                    RecvResponseState::Receiving(r) => self.recv = Some(r),
                                    _ => unreachable!(),
                                };
                            }
                            _ => {
                                match mem::replace(&mut self.state, RecvResponseState::Finished) {
                                    RecvResponseState::Receiving(recv) => {
                                        recv.reset(ErrorCode::FRAME_UNEXPECTED);
                                    }
                                    _ => unreachable!(),
                                }
                                return Poll::Ready(Err(Error::peer("first frame is not headers")));
                            }
                        },
                    }
                }
                RecvResponseState::Decoding(ref mut decode) => {
                    let headers = ready!(Pin::new(decode).poll(cx))?;
                    let response = build_response(headers);
                    match response {
                        Err(e) => return Poll::Ready(Err(e)),
                        Ok(r) => {
                            self.state = RecvResponseState::Finished;
                            return Poll::Ready(Ok((
                                r,
                                BodyReader::new(
                                    self.recv.take().unwrap(),
                                    self.conn.clone(),
                                    self.stream_id,
                                    true,
                                ),
                            )));
                        }
                    }
                }
            }
        }
    }
}

fn build_response(header: Header) -> Result<Response<()>, Error> {
    let (status, headers) = header.into_response_parts()?;
    let mut response = Response::builder()
        .status(status)
        .version(http::version::Version::HTTP_3)
        .body(())
        .unwrap();
    *response.headers_mut() = headers;
    Ok(response)
}

#[cfg(test)]
impl Connection {
    pub(crate) fn inner(&self) -> &ConnectionRef {
        &self.0
    }
}

#[cfg(feature = "interop-test-accessors")]
impl Connection {
    /// Return true if one header has been decoded with the help of a dynamic QPACK entry.
    pub fn had_refs(&self) -> bool {
        let conn = self.0.h3.lock().unwrap();
        conn.inner.had_refs
    }
}
