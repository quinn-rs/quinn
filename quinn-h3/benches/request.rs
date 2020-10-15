use bencher::{benchmark_group, benchmark_main, Bencher};
use futures::{channel::oneshot, Future, StreamExt};
use http::{Request, Response, StatusCode};
use tokio::select;
use tracing::error_span;
use tracing_futures::Instrument as _;

use quinn_h3::{self, client, server::IncomingConnection, Body, Settings};

mod helpers;
use helpers::Bench;

benchmark_group!(
    benches_request,
    bench_empty,
    bench_empty_body,
    bench_google,
    bench_google_qpack,
    bench_google_qpack_small_table,
    bench_google_body,
);
benchmark_main!(benches_request);

// Benches

pub fn bench_empty(bench: &mut Bencher) {
    request(bench, empty_request, empty_server, Settings::new())
}

pub fn bench_empty_body(bench: &mut Bencher) {
    request(bench, empty_request, empty_server_body, Settings::new())
}

fn bench_google_qpack(bench: &mut Bencher) {
    request(bench, google_request, google_server, Settings::new())
}

fn bench_google_qpack_small_table(bench: &mut Bencher) {
    let mut settings = Settings::default();
    settings.set_qpack_max_blocked_streams(128).unwrap();
    settings.set_qpack_max_table_capacity(1024).unwrap();
    request(bench, google_request, google_server, settings)
}

fn bench_google(bench: &mut Bencher) {
    let mut settings = Settings::default();
    settings.set_qpack_max_table_capacity(0).unwrap();
    request(bench, google_request, google_server, settings)
}

fn bench_google_body(bench: &mut Bencher) {
    request(bench, google_request, google_server_body, Settings::new())
}

// Empty header values

pub fn empty_request() -> Request<Body> {
    Request::get("https://localhost").body(().into()).unwrap()
}

pub fn empty_response() -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .body(().into())
        .unwrap()
}

pub async fn empty_server(incoming: IncomingConnection, stop: oneshot::Receiver<()>) {
    request_server(incoming, stop, empty_response).await;
}

pub fn empty_response_body() -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .body(Body::from("a".repeat(64 * 1024).as_str()))
        .unwrap()
}

pub async fn empty_server_body(incoming: IncomingConnection, stop: oneshot::Receiver<()>) {
    request_server(incoming, stop, empty_response_body).await;
}

// Google header values

pub fn google_request() -> Request<Body> {
    Request::get("https://www.google.com/search?client=ubuntu&channel=fs&q=sfqfd&ie=utf-8&oe=utf-8")
        .header("Host", "www.google.com")
        .header(
            "User-Agent",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:75.0) Gecko/20100101 Firefox/75.0",
        )
        .header(
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        )
        .header("Accept-Language", "en-US,en;q=0.5")
        .header("Accept-Encoding", "gzip, deflate, br")
        .header("Connection", "keep-alive")
        .header("Cookie", "e".repeat(1356))
        .header("Upgrade-Insecure-Requests", "1")
        .header("Cache-Control", "max-age=0")
        .header("TE", "Trailers")
        .body(().into())
        .unwrap()
}

pub fn google_response() -> Response<Body> {
    Response::builder().status(StatusCode::OK)
            .header("content-type", "text/html; charset=UTF-8")
            .header("date", "Sun, 19 Apr 2020 09:11:37 GMT")
            .header("expires", "-1")
            .header("cache-control", "private, max-age=0")
            .header("trailer", "X-Google-GFE-Current-Request-Cost-From-GWS")
            .header("strict-transport-security", "max-age=31536000")
            .header("content-encoding", "br")
            .header("server", "gws")
            .header("x-xss-protection", "0")
            .header("x-frame-options", "SAMEORIGIN")
            .header("set-cookie", "1P_JAR=2020-04-19-09; expires=Tue, 19-May-2020 09:11:37 GMT; path=/; domain=.google.com; Secure; SameSite=none")
            .header("set-cookie", "SIDCC=1111111111111111111111111111111111111111111111111111111111111111111111111111; expires=Mon, 19-Apr-2021 09:11:37 GMT; path=/; domain=.google.com; priority=high")
            .header("alt-svc", "quic=\":443\"; ma=2592000; v=\"46,43\",h3-Q050=\":443\"; ma=2592000,h3-Q049=\":443\"; ma=2592000,h3-Q048=\":443\"; ma=2592000,h3-Q046=\":443\"; ma=2592000,h3-Q043=\":443\"; ma=2592000,h3-T050=\":443\"; ma=2592000")
            .header("X-Firefox-Spdy", "h2")
            .body(Body::from(())).unwrap()
}

pub async fn google_server(incoming: IncomingConnection, stop: oneshot::Receiver<()>) {
    request_server(incoming, stop, google_response).await;
}

pub fn google_response_body() -> Response<Body> {
    Response::builder().status(StatusCode::OK)
            .header("content-type", "text/html; charset=UTF-8")
            .header("date", "Sun, 19 Apr 2020 09:11:37 GMT")
            .header("expires", "-1")
            .header("cache-control", "private, max-age=0")
            .header("trailer", "X-Google-GFE-Current-Request-Cost-From-GWS")
            .header("strict-transport-security", "max-age=31536000")
            .header("content-encoding", "br")
            .header("server", "gws")
            .header("x-xss-protection", "0")
            .header("x-frame-options", "SAMEORIGIN")
            .header("set-cookie", "1P_JAR=2020-04-19-09; expires=Tue, 19-May-2020 09:11:37 GMT; path=/; domain=.google.com; Secure; SameSite=none")
            .header("set-cookie", "SIDCC=1111111111111111111111111111111111111111111111111111111111111111111111111111; expires=Mon, 19-Apr-2021 09:11:37 GMT; path=/; domain=.google.com; priority=high")
            .header("alt-svc", "quic=\":443\"; ma=2592000; v=\"46,43\",h3-Q050=\":443\"; ma=2592000,h3-Q049=\":443\"; ma=2592000,h3-Q048=\":443\"; ma=2592000,h3-Q046=\":443\"; ma=2592000,h3-Q043=\":443\"; ma=2592000,h3-T050=\":443\"; ma=2592000")
            .header("X-Firefox-Spdy", "h2")
            .body(Body::from("a".repeat(64 * 1024).as_str())).unwrap()
}

pub async fn google_server_body(incoming: IncomingConnection, stop: oneshot::Receiver<()>) {
    request_server(incoming, stop, google_response_body).await;
}

// Runner

fn request<Fut>(
    bench: &mut Bencher,
    make_request: fn() -> Request<Body>,
    service: fn(incoming_conn: IncomingConnection, stop_recv: oneshot::Receiver<()>) -> Fut,
    settings: Settings,
) where
    Fut: Future<Output = ()> + 'static,
{
    let _ = tracing_subscriber::fmt::try_init();

    let mut ctx = Bench::with_settings(settings);

    let (addr, server) = ctx.spawn_server(service);
    let (client, runtime) = ctx.make_client(addr);

    bench.iter(|| {
        runtime.block_on(async {
            request_client(&client, make_request())
                .instrument(error_span!("client"))
                .await
        });
    });
    client.close();
    ctx.stop_server();
    server.join().expect("server");
}

async fn request_client(client: &client::Connection, request: Request<Body>) {
    let (req, recv_resp) = client.send_request(request);
    req.await.expect("request");
    let mut resp = recv_resp.await.expect("recv_resp");
    resp.body_mut().read_to_end().await.expect("read body");
}

async fn request_server(
    mut incoming_conn: IncomingConnection,
    mut stop_recv: oneshot::Receiver<()>,
    make_response: fn() -> Response<Body>,
) {
    let mut incoming_req = incoming_conn
        .next()
        .await
        .expect("accept")
        .await
        .expect("connect");
    loop {
        select! {
            _ = &mut stop_recv => break,
            Some(recv_req) = incoming_req.next() => {
                let (_, mut sender) = recv_req.await.expect("recv_req");
                sender.send_response(make_response())
                    .await
                    .expect("send_response");
            },
        }
    }
}
