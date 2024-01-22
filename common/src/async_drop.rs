use futures_util::{future::BoxFuture, Future};
use log::trace;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender, WeakUnboundedSender};

enum AsyncDropperMsg {
    Future(BoxFuture<'static, ()>),
    Termination,
}

/// Assists with executing code in a future when the future is cancelled.
pub struct AsyncDropper {
    tx: UnboundedSender<AsyncDropperMsg>,
}
impl AsyncDropper {
    /// Creates a new `AsyncDropper`
    /// Returns a tuple containing the AsyncDropper struct and a future that will perform tasks when a future is dropped.
    #[track_caller]
    pub fn new() -> (AsyncDropper, impl Future<Output = ()> + 'static) {
        let orig = format!("{}", std::panic::Location::caller());
        trace!("new dropper '{orig}'");

        let (tx, mut rx) = unbounded_channel();
        let fut = async move {
            while let Some(msg) = rx.recv().await {
                match msg {
                    AsyncDropperMsg::Future(fut) => {
                        fut.await;
                    },
                    AsyncDropperMsg::Termination => {
                        trace!("term received for '{orig}'...");
                        break;
                    },
                }
            }
            trace!("dropper '{orig}' exited.");
        };

        (Self { tx }, fut)
    }

    /// Defers execution of a future to when the returned `AsyncDropGuard` is dropped
    pub fn defer<F: Future<Output = ()> + Send + 'static>(&self, fut: F) -> AsyncDropGuard {
        let tx = self.tx.downgrade();
        AsyncDropGuard { tx, run: Some(Box::pin(fut)) }
    }
}
impl Drop for AsyncDropper {
    fn drop(&mut self) {
        if let Err(err) = self.tx.send(AsyncDropperMsg::Termination) {
            // If this ever panics, we're not cleaning up resources properly.
            panic!("failed to send termination: {}", err);
        }
    }
}

/// A Guard struct. When dropped executes the defered future.
pub struct AsyncDropGuard {
    tx: WeakUnboundedSender<AsyncDropperMsg>,
    run: Option<BoxFuture<'static, ()>>,
}

impl AsyncDropGuard {
    /// This consumes the guard, causing the internal future not to execute.
    pub fn consume(mut self) {
        self.run.take();
    }
}

impl Drop for AsyncDropGuard {
    fn drop(&mut self) {
        if let Some(fun) = self.run.take() {
            if let Some(tx) = self.tx.upgrade() {
                let _ = tx.send(AsyncDropperMsg::Future(fun));
            }
        }
    }
}
