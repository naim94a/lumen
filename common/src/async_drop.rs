use futures_util::{future::BoxFuture, Future};
use tokio::{sync::mpsc::{UnboundedSender, unbounded_channel, WeakUnboundedSender}};

enum AsyncDropperMsg {
    Future(BoxFuture<'static, ()>),
    Termination,
}

pub struct AsyncDropper {
    tx: UnboundedSender<AsyncDropperMsg>,
}
impl AsyncDropper {
    pub fn new() -> (AsyncDropper, impl Future<Output = ()> + 'static) {
        let (tx, mut rx) = unbounded_channel();
        let fut = async move {
            while let Some(msg) = rx.recv().await {
                match msg {
                    AsyncDropperMsg::Future(fut) => {
                        fut.await;
                    },
                    AsyncDropperMsg::Termination => {
                        break;
                    }
                }
            }
            log::info!("term received...");
        };

        (Self { tx }, fut)
    }

    pub fn defer<F: Future<Output = ()> + Send + 'static>(&self, fut: F) -> AsyncDropGuard {
        let tx = self.tx.downgrade();
        AsyncDropGuard {
            tx,
            run: Some(Box::pin(fut))
        }
    }
}
impl Drop for AsyncDropper {
    fn drop(&mut self) {
        let _ = self.tx.send(AsyncDropperMsg::Termination);
    }
}

pub struct AsyncDropGuard {
    tx: WeakUnboundedSender<AsyncDropperMsg>,
    run: Option<BoxFuture<'static, ()>>,
}

impl AsyncDropGuard {
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
