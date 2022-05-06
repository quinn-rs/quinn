#[cfg(feature = "runtime-tokio")]
mod tokio_runtime;
#[cfg(feature = "runtime-tokio")]
pub use tokio_runtime::*;

#[cfg(feature = "runtime-async-std")]
mod async_std_runtime;
#[cfg(feature = "runtime-async-std")]
pub use async_std_runtime::*;

use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

pub trait AsyncTimer: Send + Debug {
    fn reset(self: Pin<&mut Self>, i: Instant);
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<()>;
}

pub trait Runtime: udp::runtime::Runtime {
    fn new_timer(&self, i: Instant) -> Pin<Box<dyn AsyncTimer>>;
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>);
}

pub fn make_runtime() -> Box<dyn Runtime> {
    #[cfg(feature = "runtime-tokio")]
    {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Box::new(crate::TokioRuntime);
        }
    }

    #[cfg(feature = "runtime-async-std")]
    {
        return Box::new(crate::AsyncStdRuntime);
    }

    #[cfg(not(feature = "runtime-async-std"))]
    panic!("No usable runtime found");
}
