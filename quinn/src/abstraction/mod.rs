pub(super) mod io;
pub(super) mod mpsc;
pub(super) mod oneshot;
pub(super) mod sync;

#[cfg(not(any(feature = "runtime-tokio", feature = "runtime-smol")))]
compile_error!("Must enable either `runtime-tokio` or `runtime-smol` feature");
