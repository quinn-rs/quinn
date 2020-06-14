//! Client implementation for the HTTP/3 protocol
//!
//! # Overview
//!
//! Start by constructing a [`Client`] endpoint with a [`Builder`], then [`connect()`] to a server.
//! Before being able to issue requests, a handshake phase will need to be completed, waiting for
//! [`Connecting`] to resolve. You can also choose to try to issue your first request even before
//! the handshake succeeds, using the [`0-RTT`] feature.
//!
//! Once a [`Connection`] is up and running, you can start sending [`Request`]s via
//! [`Connection::send_request()`]. Which will return [`SendRequest`] and [`RecvResponse`] futures.
//! Both of them resolve when the respective headers have been recieved and decoded.
//!
//! Body and trailers are handled through the wrapped [`http_body::Body`] implementation in [`Request<B>`]
//! and [`Response<RecvBody>`]. You can access them using their respective [`body_mut()`] method.
//!
//! # Example
//!
//! ```
//! use std::{fs, net::SocketAddr};
//! use http::Request;
//! use quinn_h3::{client::Client, Body, RecvBody};
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
//!     let request = Request::get("https://example.com")
//!         .body(Body::from(()))
//!         .unwrap();
//!     let (send_request, recv_response) = connection.send_request(request);
//!     send_request.await.unwrap();
//!
//!     // Receive the response
//!     let mut response = recv_response.await.unwrap();
//!
//!     // Stream the response body into a string
//!     let mut body = response.body_mut().read_to_end().await.unwrap();
//!
//!     println!("response: {:?}, body: \n'{:?}'", response, body);
//! }
//! ```
//!
//! [`Builder`]: struct.Builder.html
//! [`Client`]: struct.Client.html
//! [`connect()`]: struct.Client.html#metod.connect
//! [`Connecting`]: struct.Connecting.html
//! [`0-RTT`]: struct.Connecting.html#method.into_0rtt
//! [`Connection`]: struct.Connection.html
//! [`Request<B>`]: https://docs.rs/http/*/http/request/index.html
//! [`Request`]: https://docs.rs/http/*/http/request/index.html
//! [`Connection::send_request()`]: struct.Connection.html#method.send_request
//! [`SendRequest`]: struct.SendRequest.html
//! [`RecvResponse`]: struct.RecvResponse.html
//! [`Response<RecvBody>`]: https://docs.rs/http/*/http/request/index.html
//! [`http_body::Body`]: https://docs.rs/http_body/*/http_body/trait.Body.html
//! [`body_mut()`]: https://docs.rs/http/*/http/request/struct.Request.html

#![allow(clippy::needless_doctest_main)]

use std::{
    error::Error as StdError,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{channel::oneshot, ready, FutureExt};
use http::{request, HeaderMap, Method, Request, Response, Uri};
use http_body::Body as HttpBody;
use pin_project::pin_project;
use quinn::{Certificate, Endpoint, OpenBi, RecvStream};
use quinn_proto::{Side, StreamId};
use tracing::trace;

use crate::{
    body::RecvBody,
    connection::{ConnectionDriver, ConnectionRef},
    data::RecvData,
    frame::FrameDecoder,
    proto::{headers::Header, settings::Settings, ErrorCode},
    Error, SendData, ZeroRttAccepted,
};
use futures_util::future;

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
    /// use quinn_h3::{
    ///     client::{Connecting, RecvResponse},
    ///     Body,
    /// };
    ///
    /// async fn send_0rtt_request(connecting: Connecting) -> Result<RecvResponse> {
    ///     let request = Request::get("https://example.com")
    ///         .body(Body::from(()))
    ///         .unwrap();
    ///
    ///     let mut connection = match connecting.into_0rtt() {
    ///         Ok((connection, _)) => connection,
    ///         Err(connecting) => connecting.await?,
    ///     };
    ///
    ///     let (send_response, recv_response) = connection.send_request(request);
    ///     send_response.await.unwrap();
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
/// use http::Request;
/// use quinn_h3::{client::Connection, Body};
///
/// async fn post_things(connection: &mut Connection, body: &[u8]) -> Result<()> {
///     let request = Request::post("https://example.com")
///         .body(Body::from(()))?;
///
///     // Send the request
///     let (send_request, recv_response) = connection.send_request(request);
///     send_request.await?;
///
///     let response = recv_response.await?;
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
    /// This accepts a [`http::Request<B>`] and emits [`SendRequest<B, B::Data>`], that will resolve
    /// when transmission is complete, and [`RecvResponse`], that will resolve when response headers
    /// have been received and decoded.
    ///
    /// Note that both of those futures can be polled concurrently, but the reception will hang
    /// indefinitely if transmission is not polled.
    ///
    /// # Example: GET request
    /// ```
    /// # use anyhow::Result;
    /// use http::Request;
    /// use quinn_h3::{client::Connection, Body};
    ///
    /// async fn get_things(connection: &mut Connection) -> Result<()> {
    ///     let request = Request::get("https://example.com/things")
    ///         .body(Body::from(()))?;
    ///
    ///     // Send the request
    ///     let (send_request, recv_response) = connection.send_request(request);
    ///     send_request.await?;
    ///
    ///     // Receive the response
    ///     let mut response = recv_response.await?;
    ///     let body = response.body_mut().read_to_end().await?;
    ///
    ///     Ok(())
    /// }
    /// ```
    ///
    /// [`http::Request<B>`]: https://docs.rs/http/*/http/request/index.html
    /// [`SendRequest<B, B::Data>`]: struct.SendRequest.html
    /// [`RecvResponse`]: struct.RecvResponse.html
    pub fn send_request<B>(&self, request: Request<B>) -> (SendRequest<B, B::Data>, RecvResponse)
    where
        B: HttpBody + 'static,
        B::Error: Into<Box<dyn StdError + Send + Sync>> + Send + Sync,
    {
        let (open_send, open_recv) = oneshot::channel();
        let recv = RecvResponse::new(open_recv, self.0.clone());
        let send = SendRequest::new(open_send, self.0.clone(), request);

        (send, recv)
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

/// Send a request
#[pin_project(project = SendRequestProj)]
pub struct SendRequest<B, D> {
    conn: ConnectionRef,
    request: Option<Request<B>>,
    #[pin]
    state: SendRequestState<B, D>,
    open: OpenBi,
    chan: Option<oneshot::Sender<(RecvStream, StreamId)>>,
}

impl<B> SendRequest<B, B::Data>
where
    B: HttpBody + 'static,
    B::Error: Into<Box<dyn StdError + Send + Sync>> + Send + Sync,
{
    pub(crate) fn new(
        open_send: oneshot::Sender<(RecvStream, StreamId)>,
        conn: ConnectionRef,
        request: Request<B>,
    ) -> Self {
        let open = conn.quic.open_bi();
        Self {
            conn,
            open,
            chan: Some(open_send),
            request: Some(request),
            state: SendRequestState::Opening,
        }
    }

    /// Cancel the request
    ///
    /// The peer will receive a request error with `REQUEST_CANCELLED` code.
    pub fn cancel(&mut self) {
        if let SendRequestState::Sending(send) = &mut self.state {
            send.cancel();
        }
    }
}

impl<B> SendRequestProj<'_, B, B::Data>
where
    B: HttpBody + 'static,
    B::Error: Into<Box<dyn StdError + Send + Sync>> + Send + Sync,
{
    fn take(&mut self) -> Result<(Method, Uri, HeaderMap, B), Error> {
        let (parts, body) = self.request.take().expect("no request").into_parts();
        let request::Parts {
            method,
            uri,
            headers,
            ..
        } = parts;

        match (uri.authority(), headers.get("host")) {
            (None, None) => Err(Error::Header("Missing authority")),
            (Some(a), Some(h)) if a.as_str() != h => {
                Err(Error::Header("Host and :authority are in contradiction"))
            }
            _ => Ok((method, uri, headers, body)),
        }
    }
}

impl<B> Future for SendRequest<B, B::Data>
where
    B: HttpBody + 'static,
    B::Error: Into<Box<dyn StdError + Send + Sync>> + Send + Sync,
{
    type Output = Result<(), Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut me = self.project();
        loop {
            match &mut me.state.as_mut().project() {
                SendRequestStateProj::Opening => {
                    match ready!(me.open.poll_unpin(cx)) {
                        Err(e) => {
                            me.chan.take().unwrap(); // drop it so RecvResponse fails
                            return Poll::Ready(Err(e.into()));
                        }
                        Ok((send, recv)) => {
                            let (method, uri, headers, body) = me.take()?;

                            if recv.is_0rtt() && !method.is_idempotent() {
                                let err = Error::internal("non-idempotent method tried on 0RTT");
                                me.chan.take().unwrap(); // drop it so RecvResponse fails
                                return Poll::Ready(Err(err));
                            }

                            me.chan
                                .take()
                                .unwrap()
                                .send((recv, send.id()))
                                .map_err(|_| Error::internal("SendRequest chan cancelled"))?;

                            let header = Header::request(method, uri, headers);
                            let send = SendData::new(send, me.conn.clone(), header, body, false);
                            me.state.set(SendRequestState::Sending(send));
                        }
                    }
                }
                SendRequestStateProj::Sending(send) => {
                    ready!(Pin::new(send).poll(cx))?;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

#[pin_project(project = SendRequestStateProj)]
enum SendRequestState<B, D> {
    Opening,
    Sending(#[pin] SendData<B, D>),
}

/// Receive an HTTP/3 response
///
/// This future is emitted by [`Connection::send_request()`] and will resolve once the response
/// headers are received and decoded.
///
/// Upon success, it will yield a [`Response`], containing an instance of [`RecvBody`] enabling
/// to stream data in.
///
/// # Example
/// ```
/// # use anyhow::Result;
/// use http::{Request, StatusCode};
/// use quinn_h3::{client::Connection, Body};
///
/// async fn download_file(connection: &mut Connection, path: &str) -> Result<()> {
///     let request = Request::post("https://example.com/new_thing")
///         .body(Body::from(()))?;
///     let (send_request, recv_response) = connection.send_request(request);
///
///     // Transmit request
///     send_request.await?;
///
///     // Receive the response's headers
///     let mut response = recv_response.await?;
///
///     // Check the headers
///     if response.status() == StatusCode::OK {
///        // Get the body as well
///        let body = response.body_mut().read_to_end().await?;
///     }
///
///     Ok(())
/// }
/// ```
/// [`Connection::send_request()`]: struct.Connection.htm#method.send_request
/// [`Response`]: https://docs.rs/http/*/http/response/index.html
/// [`RecvBody`]: ../struct.RecvBody.html
pub struct RecvResponse {
    state: RecvResponseState,
    conn: ConnectionRef,
    stream_id: Option<StreamId>,
    recv: Option<RecvData>,
}

enum RecvResponseState {
    Opening(oneshot::Receiver<(RecvStream, StreamId)>),
    Receiving,
    Finished,
}

impl RecvResponse {
    pub(crate) fn new(
        recv: oneshot::Receiver<(RecvStream, StreamId)>,
        conn: ConnectionRef,
    ) -> Self {
        Self {
            conn,
            recv: None,
            state: RecvResponseState::Opening(recv),
            stream_id: None,
        }
    }

    /// Cancel an HTTP/3 response reception
    ///
    /// Server will receive a request error with `REQUEST_CANCELLED` code. Any call on any
    /// object related with this request will fail.
    pub async fn cancel(&mut self) {
        let stream_id = match self.state {
            RecvResponseState::Finished => None,
            RecvResponseState::Opening(ref mut o) => {
                future::poll_fn(|cx| {
                    Poll::Ready(match o.poll_unpin(cx) {
                        Poll::Ready(Ok((mut r, i))) => {
                            let _ = r.stop(ErrorCode::REQUEST_CANCELLED.into());
                            Some(i)
                        }
                        _ => None,
                    })
                })
                .await
            }
            RecvResponseState::Receiving => {
                self.recv
                    .take()
                    .unwrap()
                    .reset(ErrorCode::REQUEST_CANCELLED);
                self.stream_id.take()
            }
        };

        if let Some(id) = stream_id {
            self.conn.h3.lock().unwrap().cancel_request(id);
        }

        self.state = RecvResponseState::Finished;
    }
}

impl Future for RecvResponse {
    type Output = Result<Response<RecvBody>, crate::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        loop {
            match self.state {
                RecvResponseState::Finished => {
                    return Poll::Ready(Err(crate::Error::internal(
                        "recv response polled after finish",
                    )))
                }
                RecvResponseState::Opening(ref mut open) => {
                    let (recv, id) = ready!(open.poll_unpin(cx))
                        .map_err(|_| Error::internal("RecvResponse channel cancelled"))?;
                    self.stream_id = Some(id);
                    self.recv = Some(RecvData::new(
                        FrameDecoder::stream(recv),
                        self.conn.clone(),
                        self.stream_id.unwrap(),
                    ));
                    self.state = RecvResponseState::Receiving;
                }
                RecvResponseState::Receiving => {
                    let (headers, body) = ready!(self.recv.as_mut().unwrap().poll_unpin(cx))?;

                    let (status, headers) = headers.into_response_parts()?;
                    let mut response = Response::builder()
                        .status(status)
                        .version(http::version::Version::HTTP_3)
                        .body(body)
                        .unwrap();
                    *response.headers_mut() = headers;

                    self.state = RecvResponseState::Finished;
                    return Poll::Ready(Ok(response));
                }
            }
        }
    }
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
