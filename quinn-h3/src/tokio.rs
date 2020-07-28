use {
    futures_util::{
        io::{AsyncRead, AsyncWrite},
        stream::Stream,
    },
    pin_project::pin_project,
};

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

/// Adapter for `tokio::io::AsyncRead` and `tokio::io::AsyncWrite` to provide
/// the variants from the `futures` crate and the other way around.
///
/// Taken from
/// https://github.com/sdroege/async-tungstenite/blob/dfe62345be984600ba5b3c8785793651a9b5149d/src/tokio.rs#L591
#[pin_project]
#[derive(Debug, Clone)]
pub struct Adapter<T>(#[pin] pub T);

impl<T: tokio::io::AsyncRead> AsyncRead for Adapter<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.project().0.poll_read(cx, buf)
    }
}

impl<T: tokio::io::AsyncWrite> AsyncWrite for Adapter<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.project().0.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().0.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().0.poll_shutdown(cx)
    }
}

impl<T: AsyncRead> tokio::io::AsyncRead for Adapter<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.project().0.poll_read(cx, buf)
    }
}

impl<T: AsyncWrite> tokio::io::AsyncWrite for Adapter<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.project().0.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().0.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().0.poll_close(cx)
    }
}

impl<T> Stream for Adapter<T>
where
    T: Stream,
{
    type Item = T::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().0.poll_next(cx)
    }
}
