//! Server implementation for the HTTP/3 protocol
//!
//! # Overview
//!
//! Simply build a new server endpoint with [`Builder::default()`], the only required configuration
//! is the [`certificate`]. Calling [`Builder::build()`] will bind a `UDP` socket listening on
//! `0.0.0.0:443` and return a [`Stream`] of [`IncomingConnection`]s.
//!
//! Each of which will need to complete handshaking, waiting for [`Connecting`] to resolve. At this time,
//! you can also try to execute requests arrived before the handshake completion, by using the
//! [`Connecting::into_0rtt()`] method; review the security implications in that method's documentation.
//!
//! A connection is essentially a [`Stream`] of [`IncomingRequest`]s. Polling it will yield futures
//! representing the header reception: [`RecvRequest`] will resolve into the request's header values,
//! along with a [`Sender`] to manage the response.
//!
//! # Example: simple server
//!
//! ```
//! use std::fs;
//! use futures::StreamExt;
//! use http::{Response, StatusCode};
//! use quinn::{Certificate, CertificateChain, PrivateKey};
//! use quinn_h3::{server, Body};
//!
//! #[tokio::main]
//! async fn main() {
//! # return;
//!     // The server always needs a certificate, as QUIC is secure by default.
//!     let key_data = fs::read("key.der").unwrap();
//!     let cert_data = fs::read("cert.der").unwrap();
//!     let key = PrivateKey::from_der(&key_data).unwrap();
//!     let cert = Certificate::from_der(&cert_data).unwrap();
//!     let cert_chain = CertificateChain::from_certs(vec![cert]);
//!
//!     let mut incoming_connection = server::Builder::default()
//!         .certificate(cert_chain, key)
//!         .unwrap()
//!         .build()
//!         .unwrap();
//!
//!     while let Some(connecting) = incoming_connection.next().await {
//!         // Handle each incoming connection in a new task.
//!         tokio::spawn(async move {
//!             // Complete QUIC handshake
//!             let mut incoming_request = connecting.await.unwrap();
//!
//!             while let Some(recv_request) = incoming_request.next().await {
//!                 // Each request also gets its own task
//!                 tokio::spawn(async move {
//!                     // Receive request
//!                     let (request, mut sender) = recv_request.await.unwrap();
//!                     println!("received request: {:?}", request);
//!
//!                     let response = Response::builder()
//!                         .status(StatusCode::OK)
//!                         .body(Body::from("Greetings over datagram ways"))
//!                         .unwrap();
//!
//!                     // Send the response
//!                     sender.send_response(response).await.unwrap();
//!                 });
//!             }
//!         });
//!     }
//! }
//! ```
//!
//! # Generate a certificate
//!
//! The `h3_server` example generates certificates for you:
//!
//! ```bash
//! ❯ cargo run --example h3_server
//!     Finished dev [unoptimized + debuginfo] target(s) in 0.09s
//!      Running `target/debug/examples/h3_server`
//! server listening
//! ^C
//! ❯ ls ~/.local/share/quinn-examples
//! cert.der    key.der
//! ```
//!
//! [`Builder::default()`]: struct.Builder.html#method.default
//! [`Builder::build()`]: struct.Builder.html#method.build
//! [`certificate`]: struct.Builder.html#method.certificate
//! [`Stream`]: https://docs.rs/futures/*/futures/stream/trait.Stream.html
//! [`IncomingConnection`]: struct.IncomingConnection.html
//! [`Connecting`]: struct.Connecting.html
//! [`Connecting::into_0rtt()`]: struct.Connecting.html#method.into_0rtt
//! [`IncomingRequest`]: struct.IncomingRequest.html
//! [`RecvRequest`]: struct.RecvRequest.html
//! [`BodyReader`]: ../struct.BodyReader.html
//! [`BodyWriter`]: ../struct.BodyWriter.html
//! [`Sender`]: struct.Sender.html
//! [`Sender::send_response()`]: struct.Sender.html#method.send_response
//! [`AsyncWrite`]: https://docs.rs/futures/*/futures/io/trait.AsyncWrite.html
//! [`http::Response<B>`]: https://docs.rs/http/*/http/response/index.html
//! [`types`]: ../enum.Body.html

#![allow(clippy::needless_doctest_main)]

use std::{
    error::Error as StdError,
    future::Future,
    net::{Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket},
    pin::Pin,
    task::{Context, Poll},
};

use futures::{ready, FutureExt, Stream};
use http::{response, Request, Response};
use http_body::Body as HttpBody;
use quinn::{
    CertificateChain, EndpointBuilder, PrivateKey, RecvStream, SendStream, ZeroRttAccepted,
};
use quinn_proto::Side;
use rustls::TLSError;
use tracing::trace;

use crate::{
    body::RecvBody,
    connection::{ConnectionDriver, ConnectionRef},
    data::{RecvData, SendData},
    frame::FrameDecoder,
    proto::{headers::Header, ErrorCode},
    streams::Reset,
    Error, Settings,
};

/// Configure and build a HTTP/3.0 server
#[derive(Clone)]
pub struct Builder {
    config: quinn::ServerConfigBuilder,
    listen: SocketAddr,
    settings: Settings,
}

impl Default for Builder {
    fn default() -> Self {
        Self::with_quic_config(quinn::ServerConfigBuilder::default())
    }
}

impl Builder {
    /// Set the certificate chain that will be presented to clients
    pub fn certificate(
        &mut self,
        cert_chain: CertificateChain,
        key: PrivateKey,
    ) -> Result<&mut Self, TLSError> {
        self.config.certificate(cert_chain, key)?;
        Ok(self)
    }

    /// Create a new server with current configuration
    ///
    /// This method spawns two driver tasks, for the `QUIC` and `HTTP/3` connections, therefore
    /// it must be called from within a tokio runtime context.
    pub fn build(self) -> Result<IncomingConnection, quinn::EndpointError> {
        let mut endpoint_builder = quinn::Endpoint::builder();
        endpoint_builder.listen(self.config.build());

        let (_, incoming) = endpoint_builder.bind(&self.listen)?;

        Ok(IncomingConnection {
            incoming,
            settings: self.settings,
        })
    }

    /// Set the address the server will be bound to
    ///
    /// ```
    /// # use std::net::{SocketAddrV6, Ipv6Addr};
    /// # use quinn_h3::server;
    /// let mut builder = server::Builder::default();
    /// builder.listen(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 443, 0, 0).into());
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn listen(&mut self, addr: SocketAddr) -> &mut Self {
        self.listen = addr;
        self
    }

    /// Set H3 settings.
    pub fn settings(&mut self, settings: Settings) -> &mut Self {
        self.settings = settings;
        self
    }

    /// Specify a base QUIC configuration
    ///
    /// Useful for fine-tuning QUIC settings like flow control, cryptography... See
    /// [`ServerConfigBuilder`] for the list of configurable settings.
    ///
    /// The ALPN protocol will be overwritten with [`quinn-h3's protocol`](../constant.ALPN.html).
    /// If you want to set your own, use [`Builder::endpoint()`] with an explicitly configured endpoint.
    ///
    /// [`ServerConfigBuilder`]: ../../quinn/generic/struct.ServerConfigBuilder.html
    /// [`ServerConfig`]: /quinn/struct.ServerConfig.html
    /// [`quinn-h3's ALPN`]: ../constant.ALPN.html
    /// [`Builder::endpoint()`]: #method.endpoint
    pub fn with_quic_config(mut config: quinn::ServerConfigBuilder) -> Self {
        config.protocols(&[crate::ALPN]);
        Self {
            config,
            listen: SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 443, 0, 0).into(),
            settings: Settings::new(),
        }
    }

    /// Create a new server from an existing QUIC endpoint configuration
    ///
    /// Take full control over the underlying QUIC configuration. This is
    /// useful for supporting multiple protocols, or setting a custom crypto
    /// configuration.
    ///
    /// If [listen()](struct.Builder.html#method.listen) has never been called,
    /// the binding address defaults to `[::]:443`.
    ///
    /// This method spawns two driver tasks, for the `QUIC` and `HTTP/3` connections,
    /// therefore it must be called from within a tokio runtime context.
    pub fn endpoint(
        self,
        endpoint: EndpointBuilder,
    ) -> Result<IncomingConnection, quinn::EndpointError> {
        let (_, incoming) = endpoint.bind(&self.listen)?;

        Ok(IncomingConnection {
            incoming,
            settings: self.settings,
        })
    }

    /// Create a new server attaching it to a bound socket
    pub fn with_socket(
        self,
        socket: UdpSocket,
    ) -> Result<IncomingConnection, quinn::EndpointError> {
        let mut endpoint_builder = quinn::Endpoint::builder();
        endpoint_builder.listen(self.config.build());
        let (_, incoming) = endpoint_builder.with_socket(socket)?;
        Ok(IncomingConnection {
            incoming,
            settings: self.settings,
        })
    }
}

/// Stream of incoming connection for one server endpoint
///
/// Yields a new HTTP/3 connection as soon as the handshake starts. The returned [`Connecting`]
/// object can then be used either to await the handshake completion or be converted
/// into a [`0-RTT`], enabling a potential request sent in the first packet to be processed.
///
/// ```
/// use futures::StreamExt;
/// use quinn_h3::server;
///
/// # use anyhow::Result;
/// # async fn handle_connection(conn: quinn_h3::server::Connecting) -> Result<()>
/// # { unimplemented!() }
/// # #[tokio::main]
/// # async fn main() -> Result<()> {
/// # return Ok(());
/// let mut incoming_connection = server::Builder::default().build()?;
///
/// println!("server listening");
/// while let Some(connecting) = incoming_connection.next().await {
///     println!("server received connection");
///     handle_connection(connecting);
/// }
/// # Ok(())
/// # }
/// ```
///
/// [`Connecting`]: struct.Connecting.html
/// [`0-RTT`]: struct.Connecting.html#method.into_0rtt
pub struct IncomingConnection {
    incoming: quinn::Incoming,
    settings: Settings,
}

impl Stream for IncomingConnection {
    type Item = Connecting;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        Poll::Ready(
            ready!(Pin::new(&mut self.incoming).poll_next(cx)).map(|c| Connecting {
                connecting: c,
                settings: self.settings.clone(),
            }),
        )
    }
}

/// HTTP/3 handshake future.
///
/// Represents an ongoing HTTP/3 handshake. Upon success, this future will resolve to a
/// [`Stream`] of [`IncomingRequest`]s.
///
/// [`Stream`]: https://docs.rs/futures/*/futures/stream/trait.Stream.html
/// [`IncomingRequest`]: struct.IncomingRequest.html
pub struct Connecting {
    connecting: quinn::Connecting,
    settings: Settings,
}

impl Connecting {
    /// Try to convert an ongoing handshake into a 0-RTT enabled exchange.
    ///
    /// # About 0-RTT
    ///
    /// 0 Round Trip Time is a QUIC feature enabling application data exchange before the
    /// peers have finished the TLS handshake. It's based on prior crypto exchange, reused
    /// for a new connection. So this function will fail if it's the first contact with
    /// the client.
    ///
    /// # Security concerns
    ///
    /// This functionality is vulnerable to replay attacks. Therefore any request with a
    /// non-idempotent method will cause the connection to be rejected immediately.
    /// Applications should also be careful about the load generated
    /// by 0-RTT triggered request processing, as this feature creates Denial of Service
    /// attack opportunities.
    ///
    /// # Usage
    ///
    /// Upon success, this method returns a `Stream` of [`IncomingRequest`]s, and a `Future`
    /// that will resolve when the handshake completes: [`ZeroRttAccepted`]. If this peer
    /// is not associated with any known prior connection, the [`Connecting`] handshake
    /// completion future will be handed back.
    ///
    /// ```
    /// use futures::StreamExt;
    /// use quinn_h3::server::{self, IncomingRequest};
    ///
    /// # use anyhow::Result;
    /// # async fn handle_request(_: IncomingRequest) {unimplemented!()}
    /// # #[tokio::main]
    /// # async fn main() -> Result<()> {
    /// # return Ok(());
    /// let mut incoming_connection = server::Builder::default().build()?;
    ///
    /// while let Some(connecting) = incoming_connection.next().await {
    ///     match connecting.into_0rtt() {
    ///         Ok((incoming_request, _zerortt_accepted)) => {
    ///             handle_request(incoming_request).await;
    ///         }
    ///         Err(connecting) => {
    ///             let incoming_request = connecting.await?;
    ///             handle_request(incoming_request).await;
    ///         }
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [`IncomingRequest`]: struct.IncomingRequest.html
    /// [`ZeroRttAccepted`]: type.ZeroRttAccepted.html
    /// [`Connecting`]: struct.Connecting.html
    pub fn into_0rtt(self) -> Result<(IncomingRequest, ZeroRttAccepted), Self> {
        let Self {
            connecting,
            settings,
        } = self;
        let (new_connection, zerortt_accepted) =
            connecting.into_0rtt().map_err(|connecting| Self {
                connecting,
                settings: settings.clone(),
            })?;
        let quinn::NewConnection {
            connection,
            bi_streams,
            uni_streams,
            ..
        } = new_connection;

        let conn_ref =
            ConnectionRef::new(connection, Side::Server, uni_streams, bi_streams, settings);
        tokio::spawn(ConnectionDriver(conn_ref.clone()));
        Ok((IncomingRequest(conn_ref), zerortt_accepted))
    }

    /// Construct a HTTP/3 handshake `Future` from an ongoing QUIC handshake
    ///
    /// Makes supporting several protocols over one endpoint possible, by accepting
    /// incoming connections initialization at the QUIC level. The client's ALPN protocol can
    /// then be used to route this new connection to the requested protocol. Say if
    /// the ALPN matches [`quinn_h3::ALPN`], you can safely use [`Connecting::from_quic()`],
    /// to handle this connection.
    ///
    /// Note that [`From<quinn::Connecting>`] is also available if default settings suit
    /// your needs.
    ///
    /// # Example: support multiple protocols over quic
    /// ```no_run
    /// # use quinn;
    /// # async fn serve_h3(conn: quinn_h3::server::Connecting) { unimplemented!() }
    /// # async fn serve_tea(conn: quinn::Connecting) { unimplemented!() }
    /// # fn main() {
    /// # use quinn_h3::{server, Settings};
    /// # tokio::runtime::Runtime::new().unwrap().block_on(async {
    /// use std::net::ToSocketAddrs;
    /// use futures::StreamExt;
    ///
    /// use quinn;
    /// use quinn_h3::server;
    ///
    /// let mut server_config = quinn::ServerConfigBuilder::default();
    /// // server_config.certificate(cert_chain, key)
    /// server_config.protocols(&[quinn_h3::ALPN, b"teapotmq"]);
    ///
    /// let mut quic_builder = quinn::Endpoint::builder();
    /// quic_builder.listen(server_config.build());
    ///
    /// let (_, mut incoming) =
    ///     quic_builder.bind(&"[::]:443".parse().unwrap()).unwrap();
    ///
    /// while let Some(mut connecting) = incoming.next().await {
    ///     let data = match connecting.handshake_data().await {
    ///         Err(_) => continue,
    ///         Ok(x) => x,
    ///     };
    ///     match &data.protocol.unwrap()[..] {
    ///         b"teapotmq" => serve_tea(connecting).await,
    ///         quinn_h3::ALPN => {
    ///             let connecting =
    ///                 quinn_h3::server::Connecting::from_quic(connecting, Settings::default());
    ///             serve_h3(connecting).await;
    ///         }
    ///         _ => (),
    ///     }
    /// }
    /// # });
    /// # }
    /// ```
    ///
    /// [`quinn_h3::ALPN`]: ../constant.ALPN.html
    /// [`Connecting::from_quic()`]: #method.from_quic
    /// [`From<quinn::Connecting>`]: #method.from
    pub fn from_quic(connecting: quinn::Connecting, settings: Settings) -> Self {
        Self {
            connecting,
            settings,
        }
    }
}

impl Future for Connecting {
    type Output = Result<IncomingRequest, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let quinn::NewConnection {
            connection,
            bi_streams,
            uni_streams,
            ..
        } = ready!(Pin::new(&mut self.connecting).poll(cx))?;
        let conn_ref = ConnectionRef::new(
            connection,
            Side::Server,
            uni_streams,
            bi_streams,
            self.settings.clone(),
        );
        tokio::spawn(ConnectionDriver(conn_ref.clone()));
        Poll::Ready(Ok(IncomingRequest(conn_ref)))
    }
}

impl From<quinn::Connecting> for Connecting {
    fn from(connecting: quinn::Connecting) -> Self {
        Self {
            connecting,
            settings: Settings::new(),
        }
    }
}

/// Stream of incoming requests for a connection.
///
/// This yields [`RecvRequest`] futures as soon as its underlying QUIC stream is open.
///
/// ```
/// use futures::StreamExt;
/// use quinn_h3::{
///     server::{Connecting, IncomingRequest},
///     Error,
/// };
///
/// async fn handle_connection(connecting: Connecting) -> Result<(), Error> {
///     let mut incoming_request = connecting.await?;
///
///     while let Some(recv_request) = incoming_request.next().await {
///         let (request, _) = recv_request.await?;
///         println!("Received request: {:?}", request);
///     }
///
///     Ok(())
/// }
/// ```
///
/// [`RecvRequest`]: struct.RecvRequest.html
pub struct IncomingRequest(ConnectionRef);

impl IncomingRequest {
    /// Gracefully close the connection.
    ///
    /// All currently running requests will be honored, as well as `allow_requests` requests
    /// sent before the client received the GoAway frame.
    pub fn go_away(&mut self, allow_requests: u64) {
        self.0.h3.lock().unwrap().inner.go_away(allow_requests);
    }
}

impl Stream for IncomingRequest {
    type Item = RecvRequest;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        match self.0.h3.lock().unwrap().next_request(cx) {
            Ok(Some((s, r))) => Poll::Ready(Some(RecvRequest::new(r, s, self.0.clone()))),
            Ok(None) => Poll::Pending,
            Err(_) => Poll::Ready(None),
        }
    }
}

/// Receive request's headers future.
///
/// Will resolve once headers have been received and decoded, returning a tuple with the
/// actual [`Request`], and a [`Sender`] that enables sending back a response. The request
/// object contains an [`http_body::Body`] implementation, [`RecvBody`], that can be used
/// to stream the incoming body.
///
/// Using the elements of this tuple, you can send a response, stream the request's body while
/// starting to send a response and its body concurrently, or [`reject`] the request.
///
/// ```
/// use anyhow::Result;
/// use http::{Method, Request, Response, StatusCode};
///
/// use quinn_h3::{server::RecvRequest, Body};
///
/// async fn handle_request(recv_request: RecvRequest) -> Result<()> {
///     let (mut request, mut sender) = recv_request.await?;
///     println!("received request: {:?}", request);
///
///     if request.method() == Method::POST {
///         let body = request.body_mut().read_to_end().await?;
///         println!("received body: {:?}", body);
///     }
///
///     let response = Response::builder().status(StatusCode::OK).body(Body::from(()))?;
///     sender.send_response(response).await?;
///
///     Ok(())
/// }
/// ```
///
/// [`Request`]: https://docs.rs/http/*/http/request/struct.Request.html
/// [`Sender`]: ../struct.Sender.html
/// [`http_body::Body`]: https://docs.rs/http-body/*/http_body/trait.Body.html
/// [`RecvBody`]: ../struct.RecvBody.html
/// [`reject`]: #method.reject
pub struct RecvRequest {
    conn: ConnectionRef,
    recv: Option<RecvData>,
    send: Option<SendStream>,
    is_0rtt: bool,
}

impl RecvRequest {
    /// Reject this request with `REQUEST_REJECTED` code.
    pub fn reject(mut self) {
        if let Some(mut recv) = self.recv.take() {
            recv.reset(ErrorCode::REQUEST_REJECTED);
        }
        if let Some(mut send) = self.send.take() {
            let _ = send.reset(ErrorCode::REQUEST_REJECTED.into());
        }
    }

    fn new(recv: RecvStream, send: SendStream, conn: ConnectionRef) -> Self {
        let is_0rtt = recv.is_0rtt();
        let recv = Some(RecvData::new(
            FrameDecoder::stream(recv),
            conn.clone(),
            send.id(),
        ));
        Self {
            conn,
            recv,
            is_0rtt,
            send: Some(send),
        }
    }

    fn build_request(
        &mut self,
        headers: Header,
        body: RecvBody,
    ) -> Result<Request<RecvBody>, Error> {
        let (method, uri, headers) = match headers.into_request_parts() {
            Ok(x) => x,
            Err(e) => {
                body.into_inner().reset(ErrorCode::REQUEST_REJECTED);
                let _ = self
                    .send
                    .take()
                    .unwrap()
                    .reset(ErrorCode::REQUEST_REJECTED.into());
                return Err(e.into());
            }
        };

        if self.is_0rtt && !method.is_idempotent() {
            if let Some(r) = &mut self.recv {
                r.reset(ErrorCode::REQUEST_REJECTED);
            }
            if let Some(s) = &mut self.send {
                let _ = s.reset(ErrorCode::REQUEST_REJECTED.into());
            }
            return Err(Error::peer(format!(
                "Tried an non indempotent method in 0-RTT: {}",
                method,
            )));
        }

        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .version(http::version::Version::HTTP_3)
            .body(body)
            .unwrap();

        *request.headers_mut() = headers;
        Ok(request)
    }
}

impl Future for RecvRequest {
    type Output = Result<(Request<RecvBody>, Sender), Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let (header, body) = ready!(self.recv.as_mut().unwrap().poll_unpin(cx))?;
        let request = self.build_request(header, body)?;
        trace!("Got {:?}", request);
        let sender = Sender {
            send: self.send.take(),
            conn: Some(self.conn.clone()),
        };
        Poll::Ready(Ok((request, sender)))
    }
}

/// Send a response back to the client.
///
/// This struct is made available once request headers are received, when [`RecvRequest`] resolves.
/// The application can then send the resulting [`http::Response`] with [`send_response()`]. It can
/// be used independently with [`BodyReader`], so you can choose whether the application needs to
/// receive the body prior to issuing a response or if a response can be issued right away.
///
/// The request can also be cancelled with [`cancel()`], after which the client will receive a request
/// error with `REQUEST_CANCELLED` cause.
///
/// [`RecvRequest`]: struct.RecvRequest.html
/// [`http::Response`]: https://docs.rs/http/*/http/response/struct.Response.html
/// [`send_response()`]: #method.send_response
/// [`BodyReader`]: ../body/struct.BodyReader.html
/// [`cancel()`]: #method.cancel
pub struct Sender {
    send: Option<SendStream>,
    conn: Option<ConnectionRef>,
}

impl Sender {
    /// Start sending a response.
    ///
    /// Use this with an [`http::Response<B>`], where B is an implementation of
    /// [`http_body::Body`].
    ///
    /// The returned [`SendData`] future will resolve on transmission completion.
    ///
    /// This crate provides [`SimpleBody`] and [`IntoBody`] as conveninece implemetation
    /// for simple data. If you want to go further, you'll have to implement your own
    /// [`http_body::Body`].
    ///
    /// # Example: simple body
    ///
    /// ```
    /// use anyhow::Result;
    /// use http::{Response, StatusCode};
    /// use quinn_h3::{server::Sender, Body};
    ///
    /// async fn simple_response(mut sender: Sender) -> Result<()> {
    ///    let response = Response::builder()
    ///        .status(StatusCode::OK)
    ///        .body(Body::from("the response body"))?;
    ///
    ///    sender.send_response(response).await?;
    ///
    ///    Ok(())
    /// }
    /// ```
    ///
    /// [`http::Response<B>`]: https://docs.rs/http/*/http/response/struct.Response.html
    /// [`http_body::Body`]: https://docs.rs/http-body/*/http_body/trait.Body.html
    /// [`SendData`]: ../struct.SendData.html
    /// [`SimpleBody`]: ../struct.SimpleBody.html
    /// [`IntoBody`]: ../trait.IntoBody.html
    pub fn send_response<B>(&mut self, response: Response<B>) -> SendData<B, B::Data>
    where
        B: HttpBody + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn StdError + Send + Sync>> + Send + Sync,
    {
        let (response, body) = response.into_parts();

        let response::Parts {
            status, headers, ..
        } = response;
        let header = Header::response(status, headers);

        let (send, conn) = (self.send.take().unwrap(), self.conn.take().unwrap());
        SendData::new(send, conn, header, body, true)
    }

    /// Cancel request processing
    ///
    /// Sends a request error with `REQUEST_CANCELLED` HTTP/3 error code. Once called, all other
    /// calls on any object related to this request will fail.
    ///
    /// Cancelling a request means that some request data have been processed by the application, which
    /// decided to abandon the response.
    pub fn cancel(&mut self) {
        let _ = self
            .send
            .as_mut()
            .unwrap()
            .reset(ErrorCode::REQUEST_CANCELLED.into());
    }
}
