use std::time::Duration;

use futures::StreamExt;
use http::{Request, Response, StatusCode};
use tokio::time::timeout;

use crate::server::IncomingConnection;

mod helpers;
use helpers::Helper;

async fn serve_one(mut incoming: IncomingConnection) {
    let mut incoming_req = incoming
        .next()
        .await
        .expect("connecting")
        .await
        .expect("accept");
    while let Some(recv_req) = incoming_req.next().await {
        let (_, _, sender) = recv_req.await.expect("recv_req");
        let body_writer = sender
            .send_response(Response::builder().status(StatusCode::OK).body(()).unwrap())
            .await
            .expect("send_response");
        body_writer.close().await.expect("response stream close");
    }
}

#[tokio::test(threaded_scheduler)]
async fn incoming_request_stream_ends_on_client_closure() {
    let helper = Helper::new();
    let (_, incoming) = helper.make_server();
    let server_handle = tokio::spawn(async move { serve_one(incoming).await });

    let conn = helper.make_connection().await;
    let (resp, _) = conn
        .send_request(
            Request::get("https://localhost/")
                .body(())
                .expect("request"),
        )
        .await
        .expect("request");
    let _ = resp.await;

    conn.close();
    // After connection closure, IncomingRequest::next() polling should
    // resolve to None, so server_handle will resolve as well.
    timeout(Duration::from_millis(500), server_handle)
        .await
        .map_err(|_| panic!("IncomingRequest did not resolve"))
        .expect("server panic")
        .unwrap();
}

#[tokio::test(threaded_scheduler)]
async fn incoming_request_stream_closed_on_client_drop() {
    let helper = Helper::new();
    let (_, incoming) = helper.make_server();
    let server_handle = tokio::spawn(async move { serve_one(incoming).await });

    let conn = helper.make_connection().await;
    let (resp, _) = conn
        .send_request(
            Request::get("https://localhost/")
                .body(())
                .expect("request"),
        )
        .await
        .expect("request");
    let _ = resp.await;
    drop(conn);

    timeout(Duration::from_millis(500), server_handle)
        .await
        .map_err(|_| panic!("IncomingRequest did not resolve"))
        .expect("server panic")
        .unwrap();
}
