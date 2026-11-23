//! # parolnet-simnet
//!
//! A deterministic in-memory network for `parolnet-rtc`, and the call scenarios M1 checks on
//! it. Test-only: nothing ships from this crate.
//!
//! [`SimNet`] is a flat internet of [`SimHost`]s. A host has addresses (which the test may
//! change mid-run, as when a laptop moves from one network to another) and an uplink with a
//! [`LinkProfile`]: random loss, a fixed delay, jitter (with or without reordering) and a rate
//! cap with a drop-tail queue. A host is a [`parolnet_rtc::Network`], so the driver binds
//! its sockets on it exactly as it does on the operating system.
//!
//! Time is tokio's. On a paused runtime (`#[tokio::test(start_paused = true)]`) the whole
//! simulation runs in virtual time: a ten-second call takes as long as its packets take to
//! compute, and nothing depends on the machine's load. The network itself is deterministic:
//! loss and jitter come from a seeded generator and deliveries are ordered by (time, sequence
//! number). What the engine randomizes (ICE credentials, certificates, SSRCs) still differs
//! from run to run, so byte counts vary by a few bytes and a rate-capped run is reproducible
//! in its shape, not bit for bit.
//!
//! [`call`] builds two drivers on such a network with the synthetic media of
//! `parolnet-media` (a tone through Opus into the desktop's playout buffer; a rate-following
//! video source) and measures what the M1 exit bar is stated in: frame gaps, audio that is
//! still the tone, the estimator's trajectory.
//!
//! Not modelled: NAT (every address reaches every other of its family), ICMP, path MTU.

pub mod call;

use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use parolnet_rtc::net::{DatagramSocket, LocalAddress, Network};
use tokio::sync::Notify;

/// How one host's uplink treats what the host sends.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LinkProfile {
    /// The share of datagrams lost at random (0.0 to 1.0).
    pub loss: f64,
    /// One-way delay every datagram takes.
    pub delay: Duration,
    /// Extra delay, uniform between zero and this, per datagram.
    pub jitter: Duration,
    /// Whether jitter may reorder datagrams. Off: a datagram never overtakes an earlier one
    /// (the delay variation of a queue); on: each is delayed on its own (several paths).
    pub reorder: bool,
    /// The link's capacity in bits per second (`None`: unlimited).
    pub rate_bps: Option<u64>,
    /// How much may wait for a capped link before the tail is dropped, as time at the
    /// link's rate.
    pub queue: Duration,
}

impl Default for LinkProfile {
    /// A good link: 10 ms each way, nothing lost, no cap.
    fn default() -> Self {
        LinkProfile {
            loss: 0.0,
            delay: Duration::from_millis(10),
            jitter: Duration::ZERO,
            reorder: false,
            rate_bps: None,
            queue: Duration::from_millis(300),
        }
    }
}

impl LinkProfile {
    /// The M1 profile "2% loss".
    pub fn lossy() -> Self {
        LinkProfile {
            loss: 0.02,
            delay: Duration::from_millis(30),
            ..Default::default()
        }
    }

    /// The M1 profile "300 kbps cap".
    pub fn capped_300k() -> Self {
        LinkProfile {
            delay: Duration::from_millis(30),
            rate_bps: Some(300_000),
            ..Default::default()
        }
    }

    /// The M1 profile "100 ms jitter" (with reordering).
    pub fn jittery() -> Self {
        LinkProfile {
            delay: Duration::from_millis(30),
            jitter: Duration::from_millis(100),
            reorder: true,
            ..Default::default()
        }
    }
}

/// What a host's uplink did so far.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LinkStats {
    /// Datagrams the host sent.
    pub sent: u64,
    pub sent_bytes: u64,
    /// Of those, datagrams whose first byte is in RFC 7983's RTP / RTCP range (128 to 191):
    /// (S)RTP or (S)RTCP, which a data-only connection sends none of.
    pub sent_rtp_or_rtcp: u64,
    /// Lost at random.
    pub lost: u64,
    /// Dropped by the capped link's full queue.
    pub queue_drops: u64,
    /// Sent from an address the host no longer has, or to one nobody is bound to.
    pub unroutable: u64,
    /// Handed to the destination socket.
    pub delivered: u64,
    pub delivered_bytes: u64,
}

struct Host {
    addresses: Vec<LocalAddress>,
    profile: LinkProfile,
    /// When the capped link is free again.
    busy_until: Option<Instant>,
    /// The latest delivery time given out (to keep order when reordering is off).
    last_delivery: Option<Instant>,
    stats: LinkStats,
    next_port: u16,
}

struct SocketState {
    host: usize,
    queue: VecDeque<(Vec<u8>, SocketAddr)>,
    waker: Option<Waker>,
}

struct Delivery {
    at: Instant,
    seq: u64,
    from_host: usize,
    from: SocketAddr,
    to: SocketAddr,
    data: Vec<u8>,
}

impl PartialEq for Delivery {
    fn eq(&self, other: &Self) -> bool {
        (self.at, self.seq) == (other.at, other.seq)
    }
}
impl Eq for Delivery {}
impl PartialOrd for Delivery {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Delivery {
    /// Earliest first out of a max-heap; ties in the order they were sent.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (other.at, other.seq).cmp(&(self.at, self.seq))
    }
}

struct World {
    hosts: Vec<Host>,
    sockets: HashMap<SocketAddr, SocketState>,
    wire: BinaryHeap<Delivery>,
    seq: u64,
    rng: u64,
}

impl World {
    /// splitmix64: small, seedable, and the same on every platform.
    fn next_random(&mut self) -> u64 {
        self.rng = self.rng.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform in [0, 1).
    fn unit(&mut self) -> f64 {
        (self.next_random() >> 11) as f64 / (1u64 << 53) as f64
    }
}

struct Shared {
    world: Mutex<World>,
    /// Wakes the wire task when an earlier delivery was scheduled, and when the network is
    /// dropped.
    scheduled: Arc<Notify>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, World> {
        self.world.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Drop for Shared {
    fn drop(&mut self) {
        // The wire task holds no strong reference: tell it the network is gone.
        self.scheduled.notify_one();
    }
}

fn now() -> Instant {
    parolnet_rtc::now()
}

/// The simulated internet.
#[derive(Clone)]
pub struct SimNet {
    shared: Arc<Shared>,
}

impl SimNet {
    /// A network whose losses and jitter follow `seed`. Must be called inside a tokio
    /// runtime: the task that delivers datagrams starts here and ends with the last handle.
    pub fn new(seed: u64) -> SimNet {
        let shared = Arc::new(Shared {
            world: Mutex::new(World {
                hosts: Vec::new(),
                sockets: HashMap::new(),
                wire: BinaryHeap::new(),
                seq: 0,
                rng: seed,
            }),
            scheduled: Arc::new(Notify::new()),
        });
        tokio::spawn(deliver(Arc::downgrade(&shared), shared.scheduled.clone()));
        SimNet { shared }
    }

    /// Add a machine with these addresses (the first of each family is the one its default
    /// route uses) on interface `sim0`.
    pub fn host(&self, addresses: &[&str]) -> SimHost {
        let mut world = self.shared.lock();
        world.hosts.push(Host {
            addresses: parse_addresses(addresses),
            profile: LinkProfile::default(),
            busy_until: None,
            last_delivery: None,
            stats: LinkStats::default(),
            next_port: 49_152,
        });
        SimHost {
            shared: self.shared.clone(),
            id: world.hosts.len() - 1,
        }
    }
}

fn parse_addresses(addresses: &[&str]) -> Vec<LocalAddress> {
    addresses
        .iter()
        .map(|a| {
            let ip: IpAddr = a.parse().expect("an IP address");
            LocalAddress {
                interface: "sim0".into(),
                prefix_len: if ip.is_ipv4() { 24 } else { 64 },
                ip,
            }
        })
        .collect()
}

/// The task that hands datagrams to their destination when their time has come. It holds
/// the network weakly and ends with the network's last handle.
async fn deliver(shared: Weak<Shared>, scheduled: Arc<Notify>) {
    loop {
        let next = {
            let Some(shared) = shared.upgrade() else {
                return;
            };
            let mut world = shared.lock();
            let now = now();
            let mut wake = Vec::new();
            while world.wire.peek().is_some_and(|d| d.at <= now) {
                let Some(d) = world.wire.pop() else { break };
                let size = d.data.len() as u64;
                match world.sockets.get_mut(&d.to) {
                    Some(socket) => {
                        socket.queue.push_back((d.data, d.from));
                        if let Some(waker) = socket.waker.take() {
                            wake.push(waker);
                        }
                        let stats = &mut world.hosts[d.from_host].stats;
                        stats.delivered += 1;
                        stats.delivered_bytes += size;
                    }
                    None => world.hosts[d.from_host].stats.unroutable += 1,
                }
            }
            let next = world.wire.peek().map(|d| d.at);
            drop(world);
            for waker in wake {
                waker.wake();
            }
            next
        };
        match next {
            Some(at) => {
                tokio::select! {
                    _ = tokio::time::sleep_until(at.into()) => {}
                    _ = scheduled.notified() => {}
                }
            }
            None => scheduled.notified().await,
        }
    }
}

/// One machine on the network. Cloning gives another handle to the same machine.
#[derive(Clone)]
pub struct SimHost {
    shared: Arc<Shared>,
    id: usize,
}

impl std::fmt::Debug for SimHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimHost").field("id", &self.id).finish()
    }
}

impl SimHost {
    /// How this host's uplink treats what it sends from now on.
    pub fn set_profile(&self, profile: LinkProfile) {
        let mut world = self.shared.lock();
        let host = &mut world.hosts[self.id];
        host.profile = profile;
        host.busy_until = None;
    }

    pub fn profile(&self) -> LinkProfile {
        self.shared.lock().hosts[self.id].profile
    }

    /// The machine moved: it has these addresses now. Sockets bound to an address it no
    /// longer has stay open but neither send nor receive, like a socket on an interface that
    /// went away.
    pub fn set_addresses(&self, addresses: &[&str]) {
        self.shared.lock().hosts[self.id].addresses = parse_addresses(addresses);
    }

    pub fn stats(&self) -> LinkStats {
        self.shared.lock().hosts[self.id].stats
    }

    /// This host as the driver's network.
    pub fn network(&self) -> Arc<dyn Network> {
        Arc::new(self.clone())
    }

    fn has_address(world: &World, id: usize, ip: IpAddr) -> bool {
        world.hosts[id].addresses.iter().any(|a| a.ip == ip)
    }

    fn send(&self, from: SocketAddr, to: SocketAddr, data: &[u8]) {
        let mut world = self.shared.lock();
        let now = now();
        let size = data.len() as u64;
        {
            let stats = &mut world.hosts[self.id].stats;
            stats.sent += 1;
            stats.sent_bytes += size;
            if data.first().is_some_and(|b| (128..=191).contains(b)) {
                stats.sent_rtp_or_rtcp += 1;
            }
        }
        // An address the machine lost, a destination of the other family, or one that is not
        // a host's address any more: nowhere to go.
        let routable = Self::has_address(&world, self.id, from.ip())
            && from.is_ipv4() == to.is_ipv4()
            && world
                .hosts
                .iter()
                .any(|h| h.addresses.iter().any(|a| a.ip == to.ip()));
        if !routable {
            world.hosts[self.id].stats.unroutable += 1;
            return;
        }
        let profile = world.hosts[self.id].profile;
        if profile.loss > 0.0 && world.unit() < profile.loss {
            world.hosts[self.id].stats.lost += 1;
            return;
        }
        // The capped link: one datagram at a time at its rate, a bounded wait before it.
        let mut leaves = now;
        if let Some(rate) = profile.rate_bps.filter(|r| *r > 0) {
            let host = &mut world.hosts[self.id];
            let start = host.busy_until.map_or(now, |t| t.max(now));
            if start.saturating_duration_since(now) > profile.queue {
                host.stats.queue_drops += 1;
                return;
            }
            let on_wire = Duration::from_secs_f64(size as f64 * 8.0 / rate as f64);
            leaves = start + on_wire;
            host.busy_until = Some(leaves);
        }
        let jitter = if profile.jitter.is_zero() {
            Duration::ZERO
        } else {
            profile.jitter.mul_f64(world.unit())
        };
        let mut at = leaves + profile.delay + jitter;
        let host = &mut world.hosts[self.id];
        if !profile.reorder {
            at = host.last_delivery.map_or(at, |last| at.max(last));
        }
        host.last_delivery = Some(host.last_delivery.map_or(at, |last| last.max(at)));
        world.seq += 1;
        let seq = world.seq;
        let earlier = world.wire.peek().is_none_or(|next| at < next.at);
        world.wire.push(Delivery {
            at,
            seq,
            from_host: self.id,
            from,
            to,
            data: data.to_vec(),
        });
        drop(world);
        if earlier {
            self.shared.scheduled.notify_one();
        }
    }
}

impl Network for SimHost {
    fn addresses(&self) -> Vec<LocalAddress> {
        self.shared.lock().hosts[self.id].addresses.clone()
    }

    fn preferred_source(&self, v6: bool) -> Option<IpAddr> {
        self.shared.lock().hosts[self.id]
            .addresses
            .iter()
            .map(|a| a.ip)
            .find(|ip| ip.is_ipv6() == v6)
    }

    fn bind(&self, addr: SocketAddr) -> io::Result<Box<dyn DatagramSocket>> {
        let mut world = self.shared.lock();
        if !Self::has_address(&world, self.id, addr.ip()) {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("{} is not an address of this host", addr.ip()),
            ));
        }
        let local = if addr.port() == 0 {
            loop {
                let host = &mut world.hosts[self.id];
                let port = host.next_port;
                host.next_port = if port == u16::MAX { 49_152 } else { port + 1 };
                let candidate = SocketAddr::new(addr.ip(), port);
                if !world.sockets.contains_key(&candidate) {
                    break candidate;
                }
            }
        } else if world.sockets.contains_key(&addr) {
            return Err(io::Error::new(io::ErrorKind::AddrInUse, "address in use"));
        } else {
            addr
        };
        world.sockets.insert(
            local,
            SocketState {
                host: self.id,
                queue: VecDeque::new(),
                waker: None,
            },
        );
        Ok(Box::new(SimSocket {
            host: self.clone(),
            local,
        }))
    }
}

/// A datagram socket on the simulated network.
pub struct SimSocket {
    host: SimHost,
    local: SocketAddr,
}

impl Drop for SimSocket {
    fn drop(&mut self) {
        self.host.shared.lock().sockets.remove(&self.local);
    }
}

impl DatagramSocket for SimSocket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let mut world = self.host.shared.lock();
        let reachable = SimHost::has_address(&world, self.host.id, self.local.ip());
        let Some(socket) = world.sockets.get_mut(&self.local) else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "socket closed",
            )));
        };
        debug_assert_eq!(socket.host, self.host.id);
        if !reachable {
            // The interface is gone: what was on its way is lost, and nothing arrives.
            socket.queue.clear();
        }
        match socket.queue.pop_front() {
            Some((data, from)) => {
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                Poll::Ready(Ok((n, from)))
            }
            None => {
                socket.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    fn poll_send_to(
        &self,
        _cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        self.host.send(self.local, target, buf);
        Poll::Ready(Ok(buf.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parolnet_rtc::net::{recv_from, send_to};

    async fn socket(host: &SimHost, addr: &str) -> Box<dyn DatagramSocket> {
        host.bind(addr.parse().unwrap()).unwrap()
    }

    /// Send `count` datagrams of `size` bytes, one every `every`; returns each one's
    /// (sequence number, arrival time after the first send) in arrival order.
    async fn run(
        profile: LinkProfile,
        seed: u64,
        count: u32,
        size: usize,
        every: Duration,
    ) -> (Vec<(u32, Duration)>, LinkStats) {
        let net = SimNet::new(seed);
        let (a, b) = (net.host(&["10.0.0.1"]), net.host(&["10.0.0.2"]));
        a.set_profile(profile);
        let tx = socket(&a, "10.0.0.1:0").await;
        let rx = socket(&b, "10.0.0.2:5000").await;
        let start = tokio::time::Instant::now();
        let receiver = tokio::spawn(async move {
            let mut got = Vec::new();
            let mut buf = vec![0u8; 2048];
            while let Ok(Ok((n, _))) =
                tokio::time::timeout(Duration::from_secs(5), recv_from(rx.as_ref(), &mut buf)).await
            {
                assert_eq!(n, size);
                let seq = u32::from_be_bytes(buf[..4].try_into().unwrap());
                got.push((seq, start.elapsed()));
            }
            got
        });
        for seq in 0..count {
            let mut data = vec![0u8; size];
            data[..4].copy_from_slice(&seq.to_be_bytes());
            send_to(tx.as_ref(), &data, "10.0.0.2:5000".parse().unwrap())
                .await
                .unwrap();
            tokio::time::sleep(every).await;
        }
        (receiver.await.unwrap(), a.stats())
    }

    #[tokio::test(start_paused = true)]
    async fn a_clean_link_delivers_everything_in_order_after_its_delay() {
        let real = std::time::Instant::now();
        let (got, stats) = run(
            LinkProfile::default(),
            1,
            500,
            200,
            Duration::from_millis(20),
        )
        .await;
        assert_eq!(got.len(), 500);
        assert!(got.iter().map(|g| g.0).eq(0..500));
        for (seq, at) in &got {
            assert_eq!(
                *at,
                Duration::from_millis(20) * *seq + Duration::from_millis(10)
            );
        }
        assert_eq!((stats.sent, stats.delivered, stats.lost), (500, 500, 0));
        // Ten virtual seconds (and the receiver's five of waiting) took no real time.
        assert!(real.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn loss_follows_the_seed_and_the_rate() {
        let profile = LinkProfile {
            loss: 0.02,
            ..Default::default()
        };
        let every = Duration::from_millis(1);
        let (first, stats) = run(profile, 7, 20_000, 100, every).await;
        let lost = 20_000 - first.len();
        assert_eq!(stats.lost as usize, lost);
        assert!(
            (300..=500).contains(&lost),
            "2% of 20000 is 400, got {lost}"
        );
        // The same seed loses the same datagrams; another seed loses others.
        let (again, _) = run(profile, 7, 20_000, 100, every).await;
        assert_eq!(first, again);
        let (other, _) = run(profile, 8, 20_000, 100, every).await;
        assert_ne!(
            first.iter().map(|g| g.0).collect::<Vec<_>>(),
            other.iter().map(|g| g.0).collect::<Vec<_>>()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn jitter_spreads_arrivals_and_reorders_only_when_asked() {
        let jitter = Duration::from_millis(100);
        let mut profile = LinkProfile {
            jitter,
            reorder: true,
            ..Default::default()
        };
        let every = Duration::from_millis(20);
        let (got, _) = run(profile, 3, 1000, 100, every).await;
        assert_eq!(got.len(), 1000);
        let delays: Vec<Duration> = got.iter().map(|(seq, at)| *at - every * *seq).collect();
        let (min, max) = (delays.iter().min().unwrap(), delays.iter().max().unwrap());
        assert!(*min >= Duration::from_millis(10) && *min < Duration::from_millis(20));
        assert!(*max > Duration::from_millis(100) && *max <= Duration::from_millis(110));
        let out_of_order = got.windows(2).filter(|w| w[1].0 < w[0].0).count();
        assert!(out_of_order > 100, "{out_of_order} reordered");

        profile.reorder = false;
        let (got, _) = run(profile, 3, 1000, 100, every).await;
        assert!(got.iter().map(|g| g.0).eq(0..1000), "in order");
        let delays: Vec<Duration> = got.iter().map(|(seq, at)| *at - every * *seq).collect();
        assert!(delays.iter().max().unwrap() > &Duration::from_millis(90));
    }

    #[tokio::test(start_paused = true)]
    async fn a_rate_cap_paces_and_its_queue_drops_the_excess() {
        // 1000-byte datagrams every 10 ms are 800 kbit/s into a 300 kbit/s link.
        let profile = LinkProfile {
            rate_bps: Some(300_000),
            queue: Duration::from_millis(200),
            delay: Duration::ZERO,
            ..Default::default()
        };
        let (got, stats) = run(profile, 5, 1000, 1000, Duration::from_millis(10)).await;
        assert_eq!(stats.sent, 1000);
        assert_eq!(stats.delivered + stats.queue_drops, 1000);
        // Ten seconds at 300 kbit/s carry 375 datagrams of 1000 bytes (plus what the queue
        // still held at the end).
        assert!((370..=385).contains(&got.len()), "{}", got.len());
        let span = got.last().unwrap().1 - got[0].1;
        let rate = (got.len() - 1) as f64 * 8000.0 / span.as_secs_f64();
        assert!((295_000.0..=305_000.0).contains(&rate), "{rate}");
        // Nothing waited longer than the queue allows (plus its own time on the wire).
        for (seq, at) in &got {
            let waited = *at - Duration::from_millis(10) * *seq;
            assert!(waited <= Duration::from_millis(230), "{waited:?}");
        }
        // Under the cap nothing is dropped or delayed beyond its own transmission.
        let (got, stats) = run(profile, 5, 200, 300, Duration::from_millis(10)).await;
        assert_eq!((got.len(), stats.queue_drops), (200, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn an_address_that_left_neither_sends_nor_receives() {
        let net = SimNet::new(1);
        let (a, b) = (net.host(&["10.0.0.1", "fd00::1"]), net.host(&["10.0.0.2"]));
        assert_eq!(a.preferred_source(false), Some("10.0.0.1".parse().unwrap()));
        assert_eq!(a.preferred_source(true), Some("fd00::1".parse().unwrap()));
        assert!(a.bind("10.9.9.9:0".parse().unwrap()).is_err());
        let old = socket(&a, "10.0.0.1:4000").await;
        assert!(a.bind("10.0.0.1:4000".parse().unwrap()).is_err(), "in use");
        let peer = socket(&b, "10.0.0.2:5000").await;
        let to_b: SocketAddr = "10.0.0.2:5000".parse().unwrap();
        let mut buf = [0u8; 64];
        send_to(old.as_ref(), b"one", to_b).await.unwrap();
        let (n, from) = recv_from(peer.as_ref(), &mut buf).await.unwrap();
        assert_eq!(
            (&buf[..n], from),
            (&b"one"[..], "10.0.0.1:4000".parse().unwrap())
        );
        // No route between families.
        let v6 = socket(&a, "[fd00::1]:0").await;
        send_to(v6.as_ref(), b"x", to_b).await.unwrap();

        a.set_addresses(&["10.0.1.1"]);
        send_to(old.as_ref(), b"two", to_b).await.unwrap();
        send_to(peer.as_ref(), b"reply", from).await.unwrap();
        let new = socket(&a, "10.0.1.1:0").await;
        send_to(new.as_ref(), b"three", to_b).await.unwrap();
        let (n, from) = recv_from(peer.as_ref(), &mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"three");
        assert_eq!(from.ip(), "10.0.1.1".parse::<IpAddr>().unwrap());
        let nothing =
            tokio::time::timeout(Duration::from_secs(1), recv_from(old.as_ref(), &mut buf)).await;
        assert!(nothing.is_err(), "the old address receives nothing");
        assert_eq!(a.stats().unroutable, 2);
        assert_eq!(b.stats().unroutable, 1);
    }
}
