use bytes::Bytes;
use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
use http::{Request, Response, StatusCode};

use crate::server::IncomingConnection;
use crate::Error;

#[macro_use]
mod helpers;
use helpers::{timeout_join, Helper};

async fn serve_one(mut incoming: IncomingConnection) -> Result<(), crate::Error> {
    let mut incoming_req = incoming.next().await.expect("no accept").await?;
    while let Some(recv_req) = incoming_req.next().await {
        let (_, _, sender) = recv_req.await?;
        let body_writer = sender
            .send_response(Response::builder().status(StatusCode::OK).body(()).unwrap())
            .await
            .expect("send_response");
        match body_writer.close().await {
            Ok(()) => {}
            // Only accept application close errors
            Err(Error::Write(quinn::WriteError::ConnectionClosed(
                quinn::ConnectionError::ApplicationClosed(_),
            ))) => {}
            Err(e) => panic!("response stream close: {}", e),
        }
    }
    Ok(())
}

#[tokio::test(threaded_scheduler)]
async fn incoming_request_stream_ends_on_client_closure() {
    let helper = Helper::new();
    let (_, incoming) = helper.make_server();
    let server_handle = tokio::spawn(async move { serve_one(incoming).await });

    let conn = helper.make_connection().await;
    conn.close();
    // After connection closure, IncomingRequest::next() polling should
    // resolve to None, so server_handle will resolve as well.
    timeout_join(server_handle).await.unwrap();
}

#[tokio::test(threaded_scheduler)]
async fn incoming_request_stream_closed_on_client_drop() {
    let helper = Helper::new();
    let (_, incoming) = helper.make_server();
    let server_handle = tokio::spawn(async move { serve_one(incoming).await });

    let conn = helper.make_connection().await;
    drop(conn);

    timeout_join(server_handle).await.unwrap();
}

async fn serve_one_request_client_body(mut incoming: IncomingConnection) -> String {
    let mut incoming_req = incoming
        .next()
        .await
        .expect("connecting")
        .await
        .expect("accept");
    let recv_req = incoming_req.next().await.expect("wait request");
    let (_, mut body_reader, sender) = recv_req.await.expect("recv_req");

    let mut body = String::new();
    body_reader
        .read_to_string(&mut body)
        .await
        .expect("server read body");
    sender
        .send_response(Response::builder().status(StatusCode::OK).body(()).unwrap())
        .await
        .expect("send_response");
    body
}

#[tokio::test(threaded_scheduler)]
async fn client_send_body() {
    let helper = Helper::new();

    let (_, incoming) = helper.make_server();
    let server_handle = tokio::spawn(async move { serve_one_request_client_body(incoming).await });

    let conn = helper.make_connection().await;
    let (resp, _) = conn.send_request(post!("the body")).await.expect("request");
    resp.await.expect("recv response");
    drop(conn);

    assert_eq!(timeout_join(server_handle).await, "the body");
}

#[tokio::test(threaded_scheduler)]
async fn client_send_stream_body() {
    let helper = Helper::new();

    let (_, incoming) = helper.make_server();
    let server_handle = tokio::spawn(async move { serve_one_request_client_body(incoming).await });

    let conn = helper.make_connection().await;
    let (resp, mut body_writer) = conn.send_request(post!()).await.expect("request");
    body_writer
        .write_all(&b"the body"[..])
        .await
        .expect("write body");
    body_writer.close().await.expect("body close");
    let _ = resp.await.unwrap();
    drop(conn);

    assert_eq!(timeout_join(server_handle).await, "the body");
}
