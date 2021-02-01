use bencher::{benchmark_group, benchmark_main, Bencher};
use futures::{channel::oneshot, StreamExt};
use http::{Request, Response, StatusCode};
use tokio::select;
use tracing::error_span;
use tracing_futures::Instrument as _;

use quinn_h3::{self, client, server::IncomingConnection, Body};

mod helpers;
use helpers::{Bench, BenchBody};

benchmark_group!(
    benches_download,
    download_1k,
    download_32k,
    download_64k,
    download_128k,
    download_1m
);

benchmark_group!(benches_upload, upload_32k, upload_1m);

benchmark_main!(benches_download, benches_upload);

pub fn download_1k(bench: &mut Bencher) {
    download(bench, 1024)
}

pub fn download_32k(bench: &mut Bencher) {
    download(bench, 32 * 1024)
}

pub fn download_64k(bench: &mut Bencher) {
    download(bench, 64 * 1024)
}

pub fn download_128k(bench: &mut Bencher) {
    download(bench, 128 * 1024)
}

pub fn download_1m(bench: &mut Bencher) {
    download(bench, 1024 * 1024)
}

fn download(bench: &mut Bencher, frame_size: usize) {
    let _ = tracing_subscriber::fmt::try_init();

    let mut ctx = Bench::default();

    let (addr, server) = ctx.spawn_server(download_server);
    let (client, runtime) = ctx.make_client(addr);
    let total_size = 10 * 1024 * 1024;

    bench.bytes = total_size as u64;

    bench.iter(|| {
        runtime.block_on(async {
            download_client(&client, frame_size, total_size)
                .instrument(error_span!("client"))
                .await
        });
    });
    client.close();
    ctx.stop_server();
    server.join().expect("server");
}

async fn download_client(client: &client::Connection, frame_size: usize, total_size: usize) {
    let (req, recv_resp) = client.send_request(
        Request::get("https://localhost/")
            .header("frame_size", format!("{}", frame_size))
            .header("total_size", format!("{}", total_size))
            .body(Body::from(()))
            .unwrap(),
    );
    req.await.expect("request");
    let mut resp = recv_resp.await.expect("recv_resp");
    while let Some(Ok(_)) = resp.body_mut().data().await {}
}

async fn download_server(
    mut incoming_conn: IncomingConnection,
    mut stop_recv: oneshot::Receiver<()>,
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
                let (request, mut sender) = recv_req.await.expect("recv_req");
                let frame_size = request
                    .headers()
                    .get("frame_size")
                    .map(|x| x.to_str().unwrap().parse().expect("parse frame size"))
                    .expect("no frame size");
                let total_size = request
                    .headers()
                    .get("total_size")
                    .map(|x| x.to_str().unwrap().parse().expect("parse total size"))
                    .expect("no total size");

                sender
                    .send_response(
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(BenchBody::new(frame_size, total_size))
                            .unwrap(),
                    )
                    .await
                    .expect("send_response");
            },
        }
    }
}

pub fn upload_32k(bench: &mut Bencher) {
    upload(bench, 32 * 1024)
}

pub fn upload_1m(bench: &mut Bencher) {
    upload(bench, 1024 * 1024)
}

fn upload(bench: &mut Bencher, frame_size: usize) {
    let _ = tracing_subscriber::fmt::try_init();

    let mut ctx = Bench::default();

    let (addr, server) = ctx.spawn_server(upload_server);
    let (client, runtime) = ctx.make_client(addr);
    let total_size = 10 * 1024 * 1024;

    bench.bytes = total_size as u64;

    bench.iter(|| {
        runtime.block_on(async {
            upload_client(&client, frame_size, total_size)
                .instrument(error_span!("client"))
                .await
        });
    });
    client.close();
    ctx.stop_server();
    server.join().expect("server");
}

async fn upload_client(client: &client::Connection, frame_size: usize, total_size: usize) {
    let (req, recv_resp) = client.send_request(
        Request::get("https://localhost/")
            .body(BenchBody::new(frame_size, total_size))
            .unwrap(),
    );
    req.await.expect("request");
    let mut resp = recv_resp.await.expect("recv_resp");
    while let Some(Ok(_)) = resp.body_mut().data().await {}
}

async fn upload_server(
    mut incoming_conn: IncomingConnection,
    mut stop_recv: oneshot::Receiver<()>,
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
                let (mut req, mut sender) = recv_req.await.expect("recv_req");
                while let Some(Ok(_)) = req.body_mut().data().await {}
                let response = Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from(()))
                    .unwrap();
                sender
                    .send_response(response)
                    .await
                    .expect("send_response");
            }
        }
    }
}
