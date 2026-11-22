//! The I/O driver of a relay node: links, timers and the exit.
//!
//! [`RelayService`] owns the connections of a [`StandardRelayNode`]. For each link it
//! runs a reader (cells in) and a writer (the node's per-link queue out), it dials the
//! next hop when the node extends a circuit (PNP-004-MUST-006), and it runs the node's
//! clock: the 90-second dead-circuit rule and the padding of §5.9.

use crate::relay_node::StandardRelayNode;
use crate::stream::DataCommand;
use crate::{CELL_SIZE, LinkId, RelayAction, RelayCell, RelayError};
use async_trait::async_trait;
use parolnet_transport::Connection;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// Opens the connection to the next hop of a circuit.
#[async_trait]
pub trait LinkDialer: Send + Sync {
    async fn dial(&self, addr: SocketAddr) -> Result<Arc<dyn Connection>, RelayError>;
}

/// The circuit an exit delivers for, as the handle to answer on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ExitCircuit {
    pub link: LinkId,
    pub circuit_id: u32,
}

/// What a relay does with the stream data of circuits it is the exit of.
#[async_trait]
pub trait ExitHandler: Send + Sync {
    async fn on_data(
        &self,
        service: &Arc<RelayService>,
        circuit: ExitCircuit,
        stream_id: u32,
        command: DataCommand,
        data: Vec<u8>,
    );
}

struct LinkIo {
    notify: Arc<Notify>,
    tasks: Vec<JoinHandle<()>>,
}

type Delivery = (ExitCircuit, u32, DataCommand, Vec<u8>);

/// A relay node with its connections.
pub struct RelayService {
    node: Arc<StandardRelayNode>,
    dialer: Arc<dyn LinkDialer>,
    links: Mutex<HashMap<LinkId, LinkIo>>,
    exit_tx: Option<mpsc::UnboundedSender<Delivery>>,
    timer: Mutex<Option<JoinHandle<()>>>,
    /// Wakes the timer when the node's next deadline moved closer.
    reschedule: Arc<Notify>,
}

/// Longest the timer sleeps when no circuit asks for less.
const MAX_TICK: Duration = Duration::from_secs(1);
/// Shortest the timer sleeps.
const MIN_TICK: Duration = Duration::from_millis(1);

impl RelayService {
    /// Start a relay service. Its timers run until the service is dropped or
    /// [`Self::shutdown`] is called.
    pub fn new(
        node: Arc<StandardRelayNode>,
        dialer: Arc<dyn LinkDialer>,
        exit: Option<Arc<dyn ExitHandler>>,
    ) -> Arc<Self> {
        let (exit_tx, exit_rx) = match exit {
            Some(_) => {
                let (tx, rx) = mpsc::unbounded_channel();
                (Some(tx), Some(rx))
            }
            None => (None, None),
        };
        let service = Arc::new(Self {
            node,
            dialer,
            links: Mutex::new(HashMap::new()),
            exit_tx,
            timer: Mutex::new(None),
            reschedule: Arc::new(Notify::new()),
        });

        // Deliveries are handed to the exit one at a time, in arrival order.
        if let (Some(handler), Some(mut rx)) = (exit, exit_rx) {
            let weak = Arc::downgrade(&service);
            tokio::spawn(async move {
                while let Some((circuit, stream_id, command, data)) = rx.recv().await {
                    let Some(service) = weak.upgrade() else { break };
                    handler
                        .on_data(&service, circuit, stream_id, command, data)
                        .await;
                }
            });
        }

        let weak: Weak<Self> = Arc::downgrade(&service);
        let reschedule = service.reschedule.clone();
        let timer = tokio::spawn(async move {
            loop {
                let wait = {
                    let Some(service) = weak.upgrade() else { break };
                    let now = Instant::now();
                    service
                        .node
                        .next_deadline()
                        .map(|at| at.saturating_duration_since(now))
                        .unwrap_or(MAX_TICK)
                        .clamp(MIN_TICK, MAX_TICK)
                };
                tokio::select! {
                    _ = tokio::time::sleep(wait) => {}
                    _ = reschedule.notified() => {}
                }
                let Some(service) = weak.upgrade() else { break };
                let actions = service.node.on_tick(Instant::now());
                service.dispatch(actions);
            }
        });
        *service.timer.lock().unwrap_or_else(|e| e.into_inner()) = Some(timer);
        service
    }

    /// The node this service drives.
    pub fn node(&self) -> &Arc<StandardRelayNode> {
        &self.node
    }

    /// Take a connection a neighbour opened to us.
    pub fn accept(self: &Arc<Self>, conn: Arc<dyn Connection>) -> LinkId {
        let link = self.node.new_link();
        self.ensure_link(link);
        self.attach(link, conn);
        link
    }

    fn ensure_link(&self, link: LinkId) -> Arc<Notify> {
        let mut links = self.links.lock().unwrap_or_else(|e| e.into_inner());
        links
            .entry(link)
            .or_insert_with(|| LinkIo {
                notify: Arc::new(Notify::new()),
                tasks: Vec::new(),
            })
            .notify
            .clone()
    }

    /// Run the reader and the writer of a link.
    fn attach(self: &Arc<Self>, link: LinkId, conn: Arc<dyn Connection>) {
        let notify = self.ensure_link(link);

        let writer = {
            let service = Arc::downgrade(self);
            let conn = conn.clone();
            tokio::spawn(async move {
                loop {
                    loop {
                        let Some(service) = service.upgrade() else {
                            return;
                        };
                        let Some(cell) = service.node.pop_outgoing(link) else {
                            break;
                        };
                        if conn.send(&cell.to_bytes()).await.is_err() {
                            service.link_down(link);
                            return;
                        }
                    }
                    notify.notified().await;
                }
            })
        };

        let reader = {
            let service = Arc::downgrade(self);
            tokio::spawn(async move {
                loop {
                    let received = conn.recv().await;
                    let Some(service) = service.upgrade() else {
                        return;
                    };
                    match received {
                        Ok(raw) => {
                            // Anything that is not one whole cell is not a cell.
                            let Ok(buf) = <[u8; CELL_SIZE]>::try_from(raw.as_slice()) else {
                                continue;
                            };
                            let Ok(cell) = RelayCell::from_bytes(&buf) else {
                                continue;
                            };
                            let actions = service.node.process(link, cell, Instant::now());
                            service.dispatch(actions);
                        }
                        Err(_) => {
                            service.link_down(link);
                            return;
                        }
                    }
                }
            })
        };

        let mut links = self.links.lock().unwrap_or_else(|e| e.into_inner());
        match links.get_mut(&link) {
            Some(io) => {
                io.tasks.push(writer);
                io.tasks.push(reader);
            }
            None => {
                writer.abort();
                reader.abort();
            }
        }
    }

    fn link_down(self: &Arc<Self>, link: LinkId) {
        let io = self
            .links
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&link);
        let actions = self.node.link_closed(link);
        self.dispatch(actions);
        if let Some(io) = io {
            for task in io.tasks {
                task.abort();
            }
        }
    }

    /// Carry out what the node asked for.
    fn dispatch(self: &Arc<Self>, actions: Vec<RelayAction>) {
        for action in actions {
            match action {
                RelayAction::Flush(link) => {
                    let notify = self
                        .links
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .get(&link)
                        .map(|io| io.notify.clone());
                    if let Some(notify) = notify {
                        notify.notify_one();
                    }
                }
                RelayAction::Reschedule => self.reschedule.notify_one(),
                RelayAction::Open { link, addr } => {
                    self.ensure_link(link);
                    let service = self.clone();
                    tokio::spawn(async move {
                        match service.dialer.dial(addr).await {
                            Ok(conn) => service.attach(link, conn),
                            Err(e) => {
                                tracing::debug!(error = %e, "next hop unreachable");
                                service.link_down(link);
                            }
                        }
                    });
                }
                RelayAction::Deliver {
                    link,
                    circuit_id,
                    stream_id,
                    command,
                    data,
                } => {
                    if let Some(tx) = &self.exit_tx {
                        let _ =
                            tx.send((ExitCircuit { link, circuit_id }, stream_id, command, data));
                    }
                }
            }
        }
    }

    /// As the exit of `circuit`, send stream data back to the originator.
    pub fn exit_send(
        self: &Arc<Self>,
        circuit: ExitCircuit,
        stream_id: u32,
        command: DataCommand,
        data: &[u8],
    ) -> Result<(), RelayError> {
        let actions = self.node.exit_send(
            circuit.link,
            circuit.circuit_id,
            stream_id,
            command,
            data,
            Instant::now(),
        )?;
        self.dispatch(actions);
        Ok(())
    }

    /// Stop the timers and every link task.
    pub fn shutdown(&self) {
        if let Some(timer) = self.timer.lock().unwrap_or_else(|e| e.into_inner()).take() {
            timer.abort();
        }
        let links: Vec<LinkIo> = self
            .links
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain()
            .map(|(_, io)| io)
            .collect();
        for io in links {
            for task in io.tasks {
                task.abort();
            }
        }
    }
}

impl Drop for RelayService {
    fn drop(&mut self) {
        self.shutdown();
    }
}
