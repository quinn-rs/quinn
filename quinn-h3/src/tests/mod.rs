use bytes::{BufMut, Bytes};
use futures::{future, StreamExt};
use http::{request, Request, Response, StatusCode, Uri};
use tokio::time::{sleep, Duration};

use crate::{
    proto::{frame::DataFrame, headers::Header},
    server::IncomingConnection,
    Body, Error, HttpError, SendData,
};

mod helpers;
use helpers::{get, post, timeout_join, Helper};

async fn serve_one(mut incoming: IncomingConnection) -> Result<(), crate::Error> {
    let mut incoming_req = incoming.next().await.expect("no accept").await?;
    while let Some(recv_req) = incoming_req.next().await {
        let (_, mut sender) = recv_req.await?;
        sender
            .send_response(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from(()))
                    .unwrap(),
            )
            .await
            .expect("send_response");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
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

#[tokio::test(flavor = "multi_thread")]
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
    let (mut req, mut sender) = recv_req.await.expect("recv_req");
    let body = req.body_mut().read_to_end().await.expect("read body");

    sender
        .send_response(
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(()))
                .unwrap(),
        )
        .await
        .expect("send_response");

    String::from_utf8_lossy(&body).to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn client_send_body() {
    let helper = Helper::new();

    let incoming = helper.make_server();
    let server_handle = tokio::spawn(async move { serve_one_request_client_body(incoming).await });

    let conn = helper.make_connection().await;
    let (req, resp) = conn.send_request(post("/", "the body"));
    req.await.expect("request");
    resp.await.expect("recv response");
    drop(conn);

    assert_eq!(timeout_join(server_handle).await, "the body");
}

#[tokio::test(flavor = "multi_thread")]
async fn client_send_stream_body() {
    let helper = Helper::new();

    let incoming = helper.make_server();
    let server_handle = tokio::spawn(async move { serve_one_request_client_body(incoming).await });

    let conn = helper.make_connection().await;
    let (req, resp) = conn.send_request(post("/", "the body"));
    req.await.expect("request");
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
        let (_, mut sender) = recv_req.await.expect("recv_req");
        sender
            .send_response(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from("a".repeat(1024 * 1024 * 100).as_ref()))
                    .unwrap(),
            )
            .await
            .map(|_| ())
    });

    let conn = helper.make_connection().await;
    let (req, mut resp) = conn.send_request(get("/"));
    req.await.unwrap();
    resp.cancel().await;

    assert_matches!(
        timeout_join(server_handle).await,
        Err(Error::Http(HttpError::RequestCancelled, None))
    );
}

#[tokio::test]
async fn server_cancel_response() {
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
        let (_, mut sender) = recv_req.await.expect("recv_req");
        let mut send_data = sender.send_response(
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from("a".repeat(1024 * 1024 * 100).as_ref()))
                .unwrap(),
        );
        send_data.cancel();
    });

    let conn = helper.make_connection().await;
    let (req, resp) = conn.send_request(get("/"));
    req.await.unwrap();
    assert_matches!(
        resp.await,
        Err(Error::Http(HttpError::RequestCancelled, None))
    );
    timeout_join(server_handle).await;
}

#[tokio::test]
async fn poll_stopped() {
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
        let (_, mut sender) = recv_req.await.expect("recv_req");
        let mut send_data = sender.send_response(
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from("a".repeat(1024 * 1024 * 100).as_ref()))
                .unwrap(),
        );
        future::poll_fn(|cx| send_data.poll_stopped(cx)).await
    });

    let conn = helper.make_connection().await;
    let (req, mut resp) = conn.send_request(get("/"));
    req.await.unwrap();
    resp.cancel().await;

    assert_matches!(
        timeout_join(server_handle).await,
        Ok(HttpError::RequestCancelled)
    );
}

#[tokio::test]
async fn go_away() {
    let helper = Helper::new();

    let mut incoming = helper.make_server();
    let server_handle = tokio::spawn(async move {
        let response = || {
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(()))
                .unwrap()
        };
        let mut incoming_req = incoming
            .next()
            .await
            .expect("connecting")
            .await
            .expect("accept");
        // Accept a first request before shutting down
        let recv_req = incoming_req.next().await.expect("wait request");
        let (_, mut sender) = recv_req.await.expect("recv_req");
        sender.send_response(response()).await.map(|_| ()).unwrap();
        // Wait for the 2 other request to be issued
        sleep(Duration::from_millis(25)).await;
        incoming_req.go_away(1);
        let recv_req = incoming_req.next().await.expect("wait request");
        let (_, mut sender) = recv_req.await.expect("recv_req");
        sender.send_response(response()).await.map(|_| ()).unwrap();
        incoming_req.next().await
    });

    let conn = helper.make_connection().await;
    let (req, resp) = conn.send_request(get("/"));
    req.await.unwrap();

    // This request will be counted in the grace interval of 1
    let (req_graced, resp_graced) = conn.send_request(get("/"));
    // This request will go beyond the grace interval and will be rejected
    let (req_rejected, resp_rejected) = conn.send_request(get("/"));
    // Wait for the GoAway frame to arrive
    sleep(Duration::from_millis(50)).await;
    // Simulate the "in-flight" nature of these two
    assert_matches!(tokio::join!(req_graced, req_rejected), (Ok(_), Ok(_)));

    assert_matches!(resp.await, Ok(_));
    assert_matches!(resp_graced.await, Ok(_));
    assert_matches!(
        resp_rejected.await,
        Err(Error::Http(HttpError::RequestRejected, _))
    );

    // GoAway has been received by the client: New requests are rejected locally because connetion
    // is shutting down.
    let (req_locally_aborted, _) = conn.send_request(get("/"));
    assert_matches!(req_locally_aborted.await.map(|_| ()), Err(Error::Aborted));

    // The server shutdown is complete, so incoming_request.next() returns None
    assert_eq!(timeout_join(server_handle).await.map(|_| ()), None);
}

#[tokio::test]
async fn go_away_from_client() {
    let helper = Helper::new();

    let incoming = helper.make_server();
    let server_handle = tokio::spawn(async move { serve_one(incoming).await });
    let mut conn = helper.make_connection().await;

    // start the first request
    let (req1, resp1) = conn.send_request(get("/"));
    req1.await.unwrap();
    // create a second request but do not start it
    let (req2, resp2) = conn.send_request(get("/"));
    // The goaway is issued as first request is in flight but not the second
    conn.go_away(0);
    // First request succeed
    assert_matches!(tokio::join!(resp1, req2), (Ok(_), Ok(_)));

    // second request is rejected as it was issued after go_away frame
    assert_matches!(
        resp2.await.map(|_| ()),
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
            let (_, mut sender) = recv_req.await?;
            sender
                .send_response(
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(Body::from(()))
                        .unwrap(),
                )
                .await?;
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
    let (req, resp) = conn.send_request(get("/"));
    req.await.expect("request");
    assert!(resp.await.is_ok());
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
    let (req, resp) = conn.send_request(get("/"));
    req.await.expect("request");
    assert!(resp.await.is_ok());
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
    let (req, resp) = conn.send_request(post("/", ()));
    req.await.expect("request");
    assert!(resp.await.is_ok());
    conn.close();

    assert!(timeout_join(server_handle).await.is_ok());
}

#[tokio::test]
async fn zero_rtt_client_forbids_non_idempotent() {
    let mut helper = Helper::new();
    let incoming = helper.make_server();
    tokio::spawn(async move { serve_n_0rtt(incoming, 2).await });

    let (conn, _) = helper.make_0rtt().await;
    assert!(conn.send_request(post("/", ())).0.await.is_err());
}

#[tokio::test]
async fn zero_rtt_client_accepts_non_idempotent_after_handshake() {
    let mut helper = Helper::new();
    let incoming = helper.make_server();
    tokio::spawn(async move { serve_n_0rtt(incoming, 2).await });

    let (conn, zero_rtt_accepted) = helper.make_0rtt().await;
    assert!(zero_rtt_accepted.await);
    assert!(conn.send_request(post("/", ())).0.await.is_ok());
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

#[tokio::test]
async fn unknown_frame_ignored() {
    let mut helper = Helper::new();
    let incoming = helper.make_server();
    let server_handle = tokio::spawn(async move { serve_one(incoming).await });

    let mut conn = helper.make_fake().await;
    let mut req = conn.blank().await;
    assert!(req
        .write(|b| b.put(&[0x2f, 4, 0, 255, 128, 0][..]))
        .await
        .is_ok());
    assert!(req.send_get().await.is_ok());
    assert_matches!(req.read().await, Some(Ok(_)));
    assert_matches!(req.read().await, None);
    conn.0.close();
    assert!(timeout_join(server_handle).await.is_ok());
}

#[tokio::test]
async fn server_rejects_missing_authority() {
    let mut helper = Helper::new();
    let incoming = helper.make_server();
    let server_handle = tokio::spawn(async move { serve_one(incoming).await });

    let mut conn = helper.make_fake().await;
    let mut req = conn.blank().await;
    let (request, body) = get("/").into_parts();
    let request::Parts {
        method,
        uri,
        headers,
        ..
    } = request;

    let mut headers = Header::request(method, uri, headers);
    *headers.authory_mut() = None;
    SendData::new(
        req.send.take().expect("send stream"),
        req.conn.clone(),
        headers,
        body,
        false,
    )
    .await
    .expect("send headers");

    assert_matches!(
        req.into_recv_data().await,
        Err(Error::Http(HttpError::RequestRejected, None))
    );
    assert_matches!(
        timeout_join(server_handle).await,
        Err(Error::Peer(reason)) if reason == "invalid headers: MissingAuthority"
    );
}

#[tokio::test]
async fn server_accepts_host_as_authority() {
    let mut helper = Helper::new();
    let incoming = helper.make_server();
    let server_handle = tokio::spawn(async move { serve_one(incoming).await });

    let mut conn = helper.make_fake().await;
    let mut req = conn.blank().await;
    let (request, body) = Request::get("https://localhost")
        .header("Host", "localhost")
        .body(Body::from(()))
        .unwrap()
        .into_parts();
    let request::Parts {
        method,
        uri,
        headers,
        ..
    } = request;

    let mut headers = Header::request(method, uri, headers);
    *headers.authory_mut() = None;
    dbg!(&headers);
    SendData::new(
        req.send.take().expect("send stream"),
        req.conn.clone(),
        headers,
        body,
        false,
    )
    .await
    .expect("send headers");

    assert_matches!(req.into_recv_data().await, Ok(_));
    drop(conn);
    assert_matches!(timeout_join(server_handle).await, Ok(()));
}

#[tokio::test]
async fn client_needs_authority() {
    let helper = Helper::new();
    let incoming = helper.make_server();
    let server_handle = tokio::spawn(async move { serve_one(incoming).await });
    let conn = helper.make_connection().await;

    let request = Request::get(Uri::builder().path_and_query("/").build().unwrap())
        .body(Body::from(()))
        .unwrap();

    let (send_req, _) = conn.send_request(request);
    assert_matches!(send_req.await, Err(Error::Header("Missing authority")));
    drop(conn);
    assert_matches!(timeout_join(server_handle).await, Ok(()));
}

#[tokio::test]
async fn client_accepts_host_as_authority() {
    // Mostly usefull for proxying from HTTP/1
    let helper = Helper::new();
    let incoming = helper.make_server();
    let server_handle = tokio::spawn(async move { serve_one(incoming).await });
    let conn = helper.make_connection().await;

    let request = Request::get(Uri::builder().path_and_query("/").build().unwrap())
        .header("host", "test.com")
        .body(Body::from(()))
        .unwrap();

    let (send_req, recv_resp) = conn.send_request(request);
    send_req.await.unwrap();
    assert_matches!(recv_resp.await, Ok(_));
    drop(conn);
    let _ = timeout_join(server_handle).await;
}

#[tokio::test]
async fn client_rejects_contradicted_authority() {
    // Mostly usefull for proxying from HTTP/1
    let helper = Helper::new();
    let incoming = helper.make_server();
    let server_handle = tokio::spawn(async move { serve_one(incoming).await });
    let conn = helper.make_connection().await;

    let request = Request::get(
        Uri::builder()
            .scheme("http")
            .path_and_query("/")
            .authority("authority.com")
            .build()
            .unwrap(),
    )
    .header("host", "host.com")
    .body(Body::from(()))
    .unwrap();

    let (send_req, _) = conn.send_request(request);
    assert_matches!(
        send_req.await,
        Err(Error::Header("Host and :authority are in contradiction"))
    );
    drop(conn);
    assert_matches!(timeout_join(server_handle).await, Ok(()));
}
