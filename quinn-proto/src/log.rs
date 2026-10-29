#[cfg(feature = "tracing")]
pub(crate) use tracing::{debug, error, span::EnteredSpan, trace, trace_span, warn};

#[cfg(not(feature = "tracing"))]
pub(crate) use no_op::*;

#[cfg(not(feature = "tracing"))]
mod no_op {
    macro_rules! event {
        ($($tt:tt)*) => {
            ()
        };
    }

    macro_rules! trace_span {
        ($($tt:tt)*) => {
            $crate::log::EnteredSpan
        };
    }

    pub(crate) use {event as debug, event as error, event as trace, event as warn, trace_span};

    pub(crate) struct EnteredSpan;

    impl EnteredSpan {
        pub(crate) fn enter(&self) -> Self {
            Self
        }

        pub(crate) fn entered(self) -> Self {
            self
        }
    }
}
