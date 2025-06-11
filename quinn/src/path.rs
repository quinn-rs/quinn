use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use proto::{ConnectionError, OpenPathError, PathId, PathStatus, VarInt};
use tokio::sync::oneshot;

use crate::connection::ConnectionRef;

/// Future produced by [`crate::Connection::open_path`]
pub struct OpenPath(OpenPathInner);

enum OpenPathInner {
    /// Opening a path in underway.
    ///
    /// This migth fail later on.
    Ongoing {
        opened: oneshot::Receiver<Result<(), OpenPathError>>,
        path_id: PathId,
        conn: ConnectionRef,
    },
    /// Opening a path failed immediately.
    Rejected {
        /// The error that occurred.
        err: OpenPathError,
    },
}

impl OpenPath {
    pub(crate) fn new(
        path_id: PathId,
        opened: oneshot::Receiver<Result<(), OpenPathError>>,
        conn: ConnectionRef,
    ) -> Self {
        Self(OpenPathInner::Ongoing {
            opened,
            path_id,
            conn,
        })
    }

    pub(crate) fn rejected(err: OpenPathError) -> Self {
        Self(OpenPathInner::Rejected { err })
    }
}

impl Future for OpenPath {
    type Output = Result<Path, OpenPathError>;
    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.get_mut().0 {
            OpenPathInner::Ongoing {
                ref mut opened,
                path_id,
                ref mut conn,
            } => Pin::new(opened).poll(ctx).map(|_| {
                Ok(Path {
                    id: path_id,
                    conn: conn.clone(),
                })
            }),
            OpenPathInner::Rejected { err } => Poll::Ready(Err(err)),
        }
    }
}

/// An open (Multi)Path
pub struct Path {
    id: PathId,
    conn: ConnectionRef,
}

impl Path {
    /// The [`PathId`] of this path.
    pub fn id(&self) -> PathId {
        self.id
    }

    /// The current [`PathStatus`] of this path.
    pub fn status(&self) -> PathStatus {
        self.conn
            .state
            .lock("path status")
            .inner
            .path_status(self.id)
    }

    /// Closes this path
    ///
    /// The passed in `error_code` is sent to the remote.
    /// The future will resolve to the `error_code` received from the remote.
    pub fn close(&self, error_code: VarInt) -> ClosePath {
        let (on_path_close_send, on_path_close_recv) = oneshot::channel();
        {
            let mut state = self.conn.state.lock("close_path");
            state.inner.close_path(self.id, error_code);
            state.close_path.insert(self.id, on_path_close_send);
        }

        ClosePath {
            closed: on_path_close_recv,
        }
    }
}

/// Future produced by [`Path::close`]
pub struct ClosePath {
    closed: oneshot::Receiver<VarInt>,
}

impl Future for ClosePath {
    type Output = Result<VarInt, ConnectionError>;
    fn poll(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        // TODO: thread through errors
        let res = ready!(Pin::new(&mut self.closed).poll(ctx));
        match res {
            Ok(code) => Poll::Ready(Ok(code)),
            Err(_err) => todo!(), // TODO: appropriate error
        }
    }
}
