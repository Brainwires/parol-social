//! A dedicated writer thread that owns the [`Database`].
//!
//! Why a thread and not `tokio::task::spawn_blocking`: the connection is single-threaded and
//! the writes must land in the order they were made (a ratchet state must never be replaced
//! by an older one). One thread draining one channel gives that order for free, needs no
//! runtime, and lets several pending batches share a commit (one fsync) when the disk is
//! slower than the caller.

use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use crate::StoreError;
use crate::db::{Database, apply_ops};
use crate::model::Op;

type Call = Box<dyn FnOnce(&mut Database) + Send>;

enum Job {
    Ops(Vec<Op>),
    Call(Call),
}

/// The handle to the writer thread. [`Writer::submit`] never waits for the disk;
/// [`Writer::call`] and [`Writer::flush`] do. Dropping it drains the pending writes and
/// closes the database.
pub struct Writer {
    tx: Option<Sender<Job>>,
    thread: Option<JoinHandle<Database>>,
    failed: Arc<Mutex<Option<String>>>,
}

impl std::fmt::Debug for Writer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Writer")
    }
}

impl Writer {
    /// Move the database to its own thread.
    pub fn spawn(db: Database) -> Result<Writer, StoreError> {
        let (tx, rx) = mpsc::channel();
        let failed = Arc::new(Mutex::new(None));
        let thread = std::thread::Builder::new()
            .name("parolnet-store".into())
            .spawn({
                let failed = failed.clone();
                move || run(db, rx, failed)
            })?;
        Ok(Writer {
            tx: Some(tx),
            thread: Some(thread),
            failed,
        })
    }

    fn send(&self, job: Job) -> Result<(), StoreError> {
        self.tx
            .as_ref()
            .ok_or(StoreError::Stopped)?
            .send(job)
            .map_err(|_| StoreError::Stopped)
    }

    fn take_failure(&self) -> Result<(), StoreError> {
        match self.failed.lock().unwrap_or_else(|e| e.into_inner()).take() {
            Some(why) => Err(StoreError::WriteFailed(why)),
            None => Ok(()),
        }
    }

    /// Queue a batch; it is applied in one transaction, in submission order. Returns at
    /// once. An `Err` reports that an *earlier* batch failed to commit (the new batch is
    /// queued all the same).
    pub fn submit(&self, ops: Vec<Op>) -> Result<(), StoreError> {
        if !ops.is_empty() {
            self.send(Job::Ops(ops))?;
        }
        self.take_failure()
    }

    /// Run `f` on the writer thread after every batch submitted so far, and wait for it.
    pub fn call<R: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Database) -> R + Send + 'static,
    ) -> Result<R, StoreError> {
        let (reply_tx, reply_rx) = mpsc::channel();
        self.send(Job::Call(Box::new(move |db| {
            let _ = reply_tx.send(f(db));
        })))?;
        reply_rx.recv().map_err(|_| StoreError::Stopped)
    }

    /// Wait until everything submitted so far is committed.
    pub fn flush(&self) -> Result<(), StoreError> {
        self.call(|_| ())?;
        self.take_failure()
    }

    /// Commit what is pending, stop the thread and give the database back.
    pub fn close(mut self) -> Result<Database, StoreError> {
        self.stop().ok_or(StoreError::Stopped)
    }

    fn stop(&mut self) -> Option<Database> {
        self.tx = None;
        self.thread.take()?.join().ok()
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn run(mut db: Database, rx: Receiver<Job>, failed: Arc<Mutex<Option<String>>>) -> Database {
    let mut pending: Option<Job> = None;
    loop {
        let job = match pending.take() {
            Some(job) => job,
            None => match rx.recv() {
                Ok(job) => job,
                // Every sender is gone and the channel is drained.
                Err(_) => return db,
            },
        };
        match job {
            Job::Call(f) => f(&mut db),
            Job::Ops(first) => {
                // Take the batches that queued up meanwhile into the same commit.
                let mut batches = vec![first];
                loop {
                    match rx.try_recv() {
                        Ok(Job::Ops(ops)) => batches.push(ops),
                        Ok(call @ Job::Call(_)) => {
                            pending = Some(call);
                            break;
                        }
                        Err(_) => break,
                    }
                }
                if let Err(e) = commit(&mut db, &batches) {
                    tracing::error!(error = %e, "store write failed");
                    failed
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .get_or_insert_with(|| e.to_string());
                }
            }
        }
    }
}

fn commit(db: &mut Database, batches: &[Vec<Op>]) -> Result<(), StoreError> {
    let tx = db.conn_mut().transaction()?;
    for ops in batches {
        apply_ops(&tx, ops)?;
    }
    tx.commit()?;
    Ok(())
}
