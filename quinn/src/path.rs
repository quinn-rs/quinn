use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use proto::{ClosePathError, ClosedPath, ConnectionError, PathError, PathId, PathStatus, VarInt};
use tokio::sync::oneshot;

use crate::connection::ConnectionRef;

/// Future produced by [`crate::Connection::open_path`]
pub struct OpenPath(OpenPathInner);

enum OpenPathInner {
    /// Opening a path in underway.
    ///
    /// This migth fail later on.
    Ongoing {
        opened: oneshot::Receiver<Result<(), PathError>>,
        path_id: PathId,
        conn: ConnectionRef,
    },
    /// Opening a path failed immediately.
    Rejected {
        /// The error that occurred.
        err: PathError,
    },
}

impl OpenPath {
    pub(crate) fn new(
        path_id: PathId,
        opened: oneshot::Receiver<Result<(), PathError>>,
        conn: ConnectionRef,
    ) -> Self {
        Self(OpenPathInner::Ongoing {
            opened,
            path_id,
            conn,
        })
    }

    pub(crate) fn rejected(err: PathError) -> Self {
        Self(OpenPathInner::Rejected { err })
    }
}

impl Future for OpenPath {
    type Output = Result<Path, PathError>;
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
    pub fn status(&self) -> Result<PathStatus, ClosedPath> {
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
    pub fn close(&self, error_code: VarInt) -> Result<ClosePath, ClosePathError> {
        let (on_path_close_send, on_path_close_recv) = oneshot::channel();
        {
            let mut state = self.conn.state.lock("close_path");
            state.inner.close_path(self.id, error_code)?;
            state.close_path.insert(self.id, on_path_close_send);
        }

        Ok(ClosePath {
            closed: on_path_close_recv,
        })
    }

    /// Sets the keep_alive_interval for a specific path
    ///
    /// See [`TransportConfig::default_path_keep_alive_interval`] for details.
    ///
    /// Returns the previous value of the setting.
    ///
    /// [`TransportConfig::default_path_keep_alive_interval`]: crate::TransportConfig::default_path_keep_alive_interval
    pub fn set_max_idle_timeout(
        &self,
        timeout: Option<Duration>,
    ) -> Result<Option<Duration>, ClosedPath> {
        let mut state = self.conn.state.lock("path_set_max_idle_timeout");
        state.inner.set_path_max_idle_timeout(self.id, timeout)
    }

    /// Sets the keep_alive_interval for a specific path
    ///
    /// See [`TransportConfig::default_path_keep_alive_interval`] for details.
    ///
    /// Returns the previous value of the setting.
    ///
    /// [`TransportConfig::default_path_keep_alive_interval`]: crate::TransportConfig::default_path_keep_alive_interval
    pub fn set_keep_alive_interval(
        &self,
        interval: Option<Duration>,
    ) -> Result<Option<Duration>, ClosedPath> {
        let mut state = self.conn.state.lock("path_set_keep_alive_interval");
        state.inner.set_path_keep_alive_interval(self.id, interval)
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
