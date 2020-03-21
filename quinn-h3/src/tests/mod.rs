use bytes::Bytes;
use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
use http::{Response, StatusCode};
use tokio::time::{delay_for, Duration};

use crate::{proto::frame::DataFrame, server::IncomingConnection, Error, HttpError};

mod helpers;
use helpers::{get, post, timeout_join, Helper};

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
    let incoming = helper.make_server();
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
    let incoming = helper.make_server();
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

    let incoming = helper.make_server();
    let server_handle = tokio::spawn(async move { serve_one_request_client_body(incoming).await });

    let conn = helper.make_connection().await;
    let (resp, _) = conn
        .send_request(post("/", "the body"))
        .await
        .expect("request");
    resp.await.expect("recv response");
    drop(conn);

    assert_eq!(timeout_join(server_handle).await, "the body");
}

#[tokio::test(threaded_scheduler)]
async fn client_send_stream_body() {
    let helper = Helper::new();

    let incoming = helper.make_server();
    let server_handle = tokio::spawn(async move { serve_one_request_client_body(incoming).await });

    let conn = helper.make_connection().await;
    let (resp, mut body_writer) = conn.send_request(post("/", ())).await.expect("request");
    body_writer
        .write_all(&b"the body"[..])
        .await
        .expect("write body");
    body_writer.close().await.expect("body close");
    let _ = resp.await.unwrap();
    drop(conn);

    assert_eq!(timeout_join(server_handle).await, "the body");
}

#[tokio::test]
async fn client_cancel_response() {
    let helper = Helper::new();

    let mut incoming = helper.make_server();
    let server_handle = tokio::spawn(async move {
        let mut incoming_req = incoming
            .next()
            .await
            .expect("connecting")
            .await
            .expect("accept");
        let recv_req = incoming_req.next().await.expect("wait request");
        delay_for(Duration::from_millis(25)).await;
        let (_, _, sender) = recv_req.await.expect("recv_req");
        sender
            .send_response(Response::builder().status(StatusCode::OK).body(()).unwrap())
            .await
            .map(|_| ())
    });

    let conn = helper.make_connection().await;
    delay_for(Duration::from_millis(50)).await;
    let (resp, _) = conn.send_request(get("/")).await.unwrap();
    resp.cancel();

    assert_matches!(
        timeout_join(server_handle).await,
        Err(Error::Http(HttpError::RequestCancelled, None))
    );
}

#[tokio::test]
async fn go_away() {
    let helper = Helper::new();

    let mut incoming = helper.make_server();
    let server_handle = tokio::spawn(async move {
        let mut incoming_req = incoming
            .next()
            .await
            .expect("connecting")
            .await
            .expect("accept");
        let recv_req = incoming_req.next().await.expect("wait request");
        incoming_req.go_away();
        let (_, _, sender) = recv_req.await.expect("recv_req");
        sender
            .send_response(Response::builder().status(StatusCode::OK).body(()).unwrap())
            .await
            .map(|_| ())
    });

    let conn = helper.make_connection().await;
    let (resp, _) = conn.send_request(get("/")).await.unwrap();
    assert!(resp.await.is_ok());

    delay_for(Duration::from_millis(50)).await;
    let (resp, _) = conn.send_request(get("/")).await.unwrap();
    assert_matches!(
        resp.await.map(|_| ()),
        Err(Error::Http(HttpError::RequestRejected, None))
    );

    assert!(timeout_join(server_handle).await.is_ok());
}

async fn serve_n_0rtt(mut incoming: IncomingConnection, n: usize) -> Result<(), crate::Error> {
    for _ in 0..n {
        let (mut incoming_req, _) = incoming
            .next()
            .await
            .expect("accept failed")
            .into_0rtt()
            .map_err(|_| ())
            .expect("0rtt failed");
        while let Some(recv_req) = incoming_req.next().await {
            let (_, _, sender) = recv_req.await?;
            let body_writer = sender
                .send_response(Response::builder().status(StatusCode::OK).body(()).unwrap())
                .await?;
            match body_writer.close().await {
                Ok(()) => {}
                Err(Error::Write(quinn::WriteError::ConnectionClosed(
                    quinn::ConnectionError::ApplicationClosed(_),
                ))) => {}
                Err(e) => return Err(e),
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn zero_rtt_success() {
    let mut helper = Helper::new();
    let incoming = helper.make_server();
    let server_handle = tokio::spawn(async move { serve_n_0rtt(incoming, 2).await });

    let (conn, zerortt_accepted) = helper.make_0rtt().await;
    let resp = conn.send_request(get("/")).await.expect("request").0.await;
    assert!(resp.is_ok());
    assert!(zerortt_accepted.await);
    conn.close();

    assert!(timeout_join(server_handle).await.is_ok());
}

#[tokio::test]
async fn zero_rtt_success_after_handshake() {
    let mut helper = Helper::new();
    let incoming = helper.make_server();
    let server_handle = tokio::spawn(async move { serve_n_0rtt(incoming, 2).await });

    let (conn, zerortt_accepted) = helper.make_0rtt().await;
    assert!(zerortt_accepted.await);
    let resp = conn.send_request(get("/")).await.expect("request").0.await;
    assert!(resp.is_ok());
    conn.close();

    assert!(timeout_join(server_handle).await.is_ok());
}

#[tokio::test]
async fn zero_rtt_fails_request_success() {
    let helper = Helper::new();
    let incoming = helper.make_server();
    let server_handle = tokio::spawn(async move { serve_one(incoming).await });

    let zero_rtt = helper
        .make_client()
        .connect(&helper.socket_addr(), "localhost")
        .expect("connect")
        .into_0rtt();
    let conn = match zero_rtt {
        Err(c) => c.await.expect("connecting"),
        Ok(_) => panic!("0-RTT shall fail"),
    };
    let resp = conn
        .send_request(post("/", ()))
        .await
        .expect("request")
        .0
        .await;
    assert!(resp.is_ok());
    conn.close();

    assert!(timeout_join(server_handle).await.is_ok());
}

#[tokio::test]
async fn zero_rtt_client_forbids_non_idempotent() {
    let mut helper = Helper::new();
    let incoming = helper.make_server();
    tokio::spawn(async move { serve_n_0rtt(incoming, 2).await });

    let (conn, _) = helper.make_0rtt().await;
    assert!(conn.send_request(post("/", ())).await.is_err());
}

#[tokio::test]
async fn zero_rtt_client_accepts_non_idempotent_after_handshake() {
    let mut helper = Helper::new();
    let incoming = helper.make_server();
    tokio::spawn(async move { serve_n_0rtt(incoming, 2).await });

    let (conn, zero_rtt_accepted) = helper.make_0rtt().await;
    assert!(zero_rtt_accepted.await);
    assert!(conn.send_request(post("/", ())).await.is_ok());
}

#[tokio::test]
async fn zero_rtt_server_forbids_non_idempotent() {
    let mut helper = Helper::new();
    let incoming = helper.make_server();
    let server_handle = tokio::spawn(async move { serve_n_0rtt(incoming, 2).await });

    let (mut conn, _) = helper.make_fake_0rtt().await;
    let mut req = conn.post().await;
    assert_matches!(req.read().await, Some(Err(_)));
    assert!(req
        .write(|mut b| DataFrame {
            payload: Bytes::from("hey")
        }
        .encode(&mut b))
        .await
        .is_err());
    assert!(timeout_join(server_handle).await.is_err());
}

#[tokio::test]
async fn zero_rtt_server_accepts_non_idempotent_after_handshake() {
    let mut helper = Helper::new();
    let incoming = helper.make_server();
    let server_handle = tokio::spawn(async move { serve_n_0rtt(incoming, 2).await });

    let (mut conn, zero_rtt_accepted) = helper.make_fake_0rtt().await;
    assert!(zero_rtt_accepted.await);

    let mut req = conn.post().await;
    assert!(req
        .write(|mut b| DataFrame {
            payload: Bytes::from("hey")
        }
        .encode(&mut b))
        .await
        .is_ok());
    assert_matches!(req.read().await, Some(Ok(_)));

    conn.0.close();
    assert!(timeout_join(server_handle).await.is_ok());
}
