//! Connection behaviour (PNP-006 §4.5): which connections a node keeps, for how long, and
//! when it may open or close one.
//!
//! - One connection per peer: every circuit and gossip stream to a peer shares it
//!   (PNP-006-MUST-025; the streams are [`crate::tls_stream::TlsConnection::open_stream`]).
//! - Connections are long-lived (PNP-006-MUST-022): a connection is not torn down
//!   voluntarily before [`MIN_CONNECTION_LIFETIME`] (PNP-006-MUST-023), and each gets a
//!   lifetime drawn at random from [`LIFETIME_MIN`] to [`LIFETIME_MAX`] after which
//!   [`ConnectionManager::rotate_expired`] closes it (PNP-006-SHOULD-001).
//! - After a connection to a peer ended, no new one is opened to that peer for
//!   [`RECONNECT_WAIT`] (PNP-006-MUST-024).
//! - A node keeps [`MIN_CONNECTIONS`] to [`MAX_CONNECTIONS`] connections
//!   (PNP-006-SHOULD-002).
//! - A voluntary close is a proper one (`Connection::close`: TLS `close_notify`,
//!   PNP-006-MUST-026); only an unresponsive peer is dropped without it.

use crate::{Connection, Transport, TransportError};
use rand::Rng;
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::Instant;

/// A connection is not closed voluntarily before it is this old (PNP-006-MUST-023).
pub const MIN_CONNECTION_LIFETIME: Duration = Duration::from_secs(10 * 60);
/// The shortest lifetime a connection is given (PNP-006-SHOULD-001).
pub const LIFETIME_MIN: Duration = Duration::from_secs(60 * 60);
/// The longest lifetime a connection is given (PNP-006-SHOULD-001).
pub const LIFETIME_MAX: Duration = Duration::from_secs(4 * 60 * 60);
/// The wait between a connection to a peer ending and the next one to it
/// (PNP-006-MUST-024).
pub const RECONNECT_WAIT: Duration = Duration::from_secs(30);
/// The fewest connections a node should keep (PNP-006-SHOULD-002).
pub const MIN_CONNECTIONS: usize = 2;
/// The most connections a node should keep (PNP-006-SHOULD-002).
pub const MAX_CONNECTIONS: usize = 8;

/// Why the manager refused.
#[derive(Debug, thiserror::Error)]
pub enum ManagerError {
    #[error("the last connection to this peer ended {0:?} ago; the next may open in {1:?}")]
    ReconnectTooSoon(Duration, Duration),
    #[error("already at the limit of {MAX_CONNECTIONS} connections")]
    TooManyConnections,
    #[error("the connection is {0:?} old; it may be closed voluntarily in {1:?}")]
    TooYoung(Duration, Duration),
    #[error("no connection to that peer")]
    NotConnected,
    #[error(transparent)]
    Transport(#[from] TransportError),
}

struct Entry<C> {
    conn: Arc<C>,
    opened: Instant,
    lifetime: Duration,
}

struct Inner<C> {
    open: HashMap<SocketAddr, Entry<C>>,
    /// When the last connection to a peer ended.
    ended: HashMap<SocketAddr, Instant>,
}

/// Keeps a node's connections as PNP-006 §4.5 describes.
pub struct ConnectionManager<T: Transport> {
    transport: T,
    inner: Mutex<Inner<T::Conn>>,
}

impl<T: Transport> ConnectionManager<T> {
    pub fn new(transport: T) -> Self {
        ConnectionManager {
            transport,
            inner: Mutex::new(Inner {
                open: HashMap::new(),
                ended: HashMap::new(),
            }),
        }
    }

    /// The connection to `addr`: the one that exists, or a new one. A second circuit or a
    /// gossip session to a peer therefore rides the first one's connection.
    pub async fn connect(&self, addr: SocketAddr) -> Result<Arc<T::Conn>, ManagerError> {
        let mut inner = self.inner.lock().await;
        if let Some(entry) = inner.open.get(&addr) {
            return Ok(entry.conn.clone());
        }
        if let Some(ended) = inner.ended.get(&addr) {
            let ago = ended.elapsed();
            if ago < RECONNECT_WAIT {
                return Err(ManagerError::ReconnectTooSoon(ago, RECONNECT_WAIT - ago));
            }
        }
        if inner.open.len() >= MAX_CONNECTIONS {
            return Err(ManagerError::TooManyConnections);
        }
        let conn = Arc::new(self.transport.connect(addr).await?);
        // A random lifetime, so connections do not all turn over on the hour.
        let span = (LIFETIME_MAX - LIFETIME_MIN).as_millis() as u64;
        let lifetime = LIFETIME_MIN + Duration::from_millis(OsRng.gen_range(0..=span));
        inner.ended.remove(&addr);
        inner.open.insert(
            addr,
            Entry {
                conn: conn.clone(),
                opened: Instant::now(),
                lifetime,
            },
        );
        Ok(conn)
    }

    /// Close the connection to `addr` because we choose to. Refused while the connection
    /// is younger than [`MIN_CONNECTION_LIFETIME`]. The close is a proper one.
    pub async fn close(&self, addr: SocketAddr) -> Result<(), ManagerError> {
        let entry = {
            let mut inner = self.inner.lock().await;
            let entry = inner.open.get(&addr).ok_or(ManagerError::NotConnected)?;
            let age = entry.opened.elapsed();
            if age < MIN_CONNECTION_LIFETIME {
                return Err(ManagerError::TooYoung(age, MIN_CONNECTION_LIFETIME - age));
            }
            inner.ended.insert(addr, Instant::now());
            inner.open.remove(&addr).expect("checked above")
        };
        entry.conn.close().await?;
        Ok(())
    }

    /// The peer at `addr` stopped answering, or its connection failed: forget the
    /// connection at once, whatever its age. Nothing is owed to a peer that is not there.
    pub async fn drop_unresponsive(&self, addr: SocketAddr) -> bool {
        let mut inner = self.inner.lock().await;
        let dropped = inner.open.remove(&addr).is_some();
        if dropped {
            inner.ended.insert(addr, Instant::now());
        }
        dropped
    }

    /// Close every connection whose lifetime is over (properly) and return their peers.
    /// Call it now and then (a minute's granularity is plenty).
    pub async fn rotate_expired(&self) -> Vec<SocketAddr> {
        let expired: Vec<(SocketAddr, Entry<T::Conn>)> = {
            let mut inner = self.inner.lock().await;
            let due: Vec<SocketAddr> = inner
                .open
                .iter()
                .filter(|(_, e)| e.opened.elapsed() >= e.lifetime)
                .map(|(addr, _)| *addr)
                .collect();
            let now = Instant::now();
            due.into_iter()
                .filter_map(|addr| {
                    inner.ended.insert(addr, now);
                    inner.open.remove(&addr).map(|e| (addr, e))
                })
                .collect()
        };
        let mut peers = Vec::with_capacity(expired.len());
        for (addr, entry) in expired {
            let _ = entry.conn.close().await;
            peers.push(addr);
        }
        peers
    }

    /// Open connections to `candidates`, in order, until [`MIN_CONNECTIONS`] are open.
    /// Returns how many are open afterwards.
    pub async fn maintain(&self, candidates: &[SocketAddr]) -> usize {
        for addr in candidates {
            if self.connection_count().await >= MIN_CONNECTIONS {
                break;
            }
            if let Err(e) = self.connect(*addr).await {
                tracing::debug!(%addr, %e, "connection not opened");
            }
        }
        self.connection_count().await
    }

    pub async fn connection_count(&self) -> usize {
        self.inner.lock().await.open.len()
    }

    /// The lifetime the connection to `addr` was given.
    pub async fn lifetime_of(&self, addr: SocketAddr) -> Option<Duration> {
        self.inner.lock().await.open.get(&addr).map(|e| e.lifetime)
    }
}
