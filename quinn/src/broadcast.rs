use std::task::{Context, Waker};

/// Helper for waking unpredictable numbers of tasks simultaneously
///
/// # Rationale
///
/// Sometimes we want to let an arbitrary number of tasks wait for the same transient condition. If
/// a task is polled and finds that the condition of interest is not in effect, it must register a
/// `Waker` to arrange to be polled when that may have changed. The number of such tasks is
/// indefinite, so we collect multiple `Waker`s in a `Vec` to be triggered en masse when the
/// condition arises.
///
/// Complication arises from the spurious polling expected by futures. If each interested task
/// blindly registered a new `Waker` on finding the condition not in effect, the `Vec` would grow
/// with proportion to the (unbounded) number of spurious wakeups that interested tasks undergo. To
/// resolve this, we increment a generation counter every time we drain the `Vec`, and associate
/// with each interested task the generation at which it last registered. If a spurious wakeup
/// occurs, the task's generation is current, and we can avoid growing the `Vec`. If, however, the
/// wakeup is genuine but the condition of interest has already passed, then the task's generation
/// no longer matches the counter, and we infer that the task's `Waker` is no longer stored and a
/// new one must be recorded.
pub struct Broadcast {
    wakers: Vec<Waker>,
    generation: u64,
}

impl Broadcast {
    pub fn new() -> Self {
        Self {
            wakers: Vec::new(),
            generation: 0,
        }
    }

    /// Ensure the next `wake` call will wake the calling task
    ///
    /// Checks the task-associated generation counter stored in `state`. If it's present and
    /// current, we already have this task's `Waker` and no action is necessary. Otherwise, record a
    /// `Waker` and store the current generation in `state`.
    pub fn register(&mut self, cx: &mut Context, state: &mut State) {
        if state.0 == Some(self.generation) {
            return;
        }
        state.0 = Some(self.generation);
        self.wakers.push(cx.waker().clone());
    }

    /// Wake all known `Waker`s
    pub fn wake(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        for waker in self.wakers.drain(..) {
            waker.wake();
        }
    }
}

/// State maintained by each interested task
///
/// Stores the generation at which the task previously registered a `Waker`, if any.
#[derive(Default)]
pub struct State(Option<u64>);
