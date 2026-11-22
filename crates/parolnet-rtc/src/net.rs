//! Where a connection's datagrams go: the socket and interface seam of the driver.
//!
//! The driver never names `tokio::net::UdpSocket` or the operating system's interface list
//! directly. It asks a [`Network`] for the machine's addresses and for sockets, and moves
//! datagrams through [`DatagramSocket`]s. [`SystemNetwork`] is the real thing;
//! `parolnet-simnet` supplies an in-memory network with loss, delay and a rate cap that runs
//! the same driver loop on tokio's virtual clock.
//!
//! This module also holds the two decisions made from the interface list:
//!
//! - [`select_addresses`]: which local addresses get a socket and a host candidate, and in
//!   which order of preference;
//! - [`NetworkMonitor`]: when the set of usable addresses changed (an ICE restart is due).

use std::collections::BTreeSet;
use std::fmt;
use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// An unconnected datagram socket bound to one local address.
pub trait DatagramSocket: Send + Sync + 'static {
    /// The address the socket is bound to.
    fn local_addr(&self) -> io::Result<SocketAddr>;

    /// Receive one datagram into `buf`: its length and sender.
    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>>;

    /// Send one datagram to `target`.
    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>>;
}

impl DatagramSocket for UdpSocket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        UdpSocket::local_addr(self)
    }

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let mut read = tokio::io::ReadBuf::new(buf);
        match UdpSocket::poll_recv_from(self, cx, &mut read) {
            Poll::Ready(Ok(from)) => Poll::Ready(Ok((read.filled().len(), from))),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        UdpSocket::poll_send_to(self, cx, buf, target)
    }
}

/// `socket.recv_from(buf)` for a [`DatagramSocket`].
pub async fn recv_from(
    socket: &dyn DatagramSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr)> {
    poll_fn(|cx| socket.poll_recv_from(cx, buf)).await
}

/// `socket.send_to(buf, target)` for a [`DatagramSocket`].
pub async fn send_to(
    socket: &dyn DatagramSocket,
    buf: &[u8],
    target: SocketAddr,
) -> io::Result<usize> {
    poll_fn(|cx| socket.poll_send_to(cx, buf, target)).await
}

/// One address of one interface.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LocalAddress {
    /// The interface's name (`en0`, `wlan0`, an adapter name on Windows).
    pub interface: String,
    pub ip: IpAddr,
    /// Length of the network prefix (IPv6 addresses of one interface in one /64 are the same
    /// network: only one of them is announced).
    pub prefix_len: u8,
}

/// The machine's network as the driver sees it.
pub trait Network: fmt::Debug + Send + Sync + 'static {
    /// Every address of every interface that is up, unfiltered.
    fn addresses(&self) -> Vec<LocalAddress>;

    /// The source address the system would use towards the internet, per family (`None`
    /// without a route). With IPv6 privacy extensions this is the temporary address.
    fn preferred_source(&self, v6: bool) -> Option<IpAddr>;

    /// Bind a datagram socket. Must be called inside a tokio runtime.
    fn bind(&self, addr: SocketAddr) -> io::Result<Box<dyn DatagramSocket>>;
}

/// The operating system's interfaces and UDP sockets.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemNetwork;

impl Network for SystemNetwork {
    fn addresses(&self) -> Vec<LocalAddress> {
        let interfaces = match if_addrs::get_if_addrs() {
            Ok(list) => list,
            Err(err) => {
                tracing::debug!(%err, "cannot list the network interfaces");
                return Vec::new();
            }
        };
        interfaces
            .into_iter()
            // `Unknown` is what several systems report for interfaces that work (loopback,
            // tunnels); only a definite "down" is left out.
            .filter(|i| {
                !matches!(
                    i.oper_status,
                    if_addrs::IfOperStatus::Down
                        | if_addrs::IfOperStatus::NotPresent
                        | if_addrs::IfOperStatus::Dormant
                )
            })
            .map(|i| {
                let prefix_len = match &i.addr {
                    if_addrs::IfAddr::V4(a) => a.prefixlen,
                    if_addrs::IfAddr::V6(a) => a.prefixlen,
                };
                LocalAddress {
                    ip: i.ip(),
                    interface: i.name,
                    prefix_len,
                }
            })
            .collect()
    }

    fn preferred_source(&self, v6: bool) -> Option<IpAddr> {
        crate::default_local_ip(v6)
    }

    fn bind(&self, addr: SocketAddr) -> io::Result<Box<dyn DatagramSocket>> {
        let socket = std::net::UdpSocket::bind(addr)?;
        socket.set_nonblocking(true)?;
        Ok(Box::new(UdpSocket::from_std(socket)?))
    }
}

/// At most this many local addresses get a socket: every one adds a host candidate (and a
/// server-reflexive one) to a description that has to fit a 16 KiB signaling frame, and
/// candidate pairs grow with the product of both sides' lists.
pub const MAX_LOCAL_ADDRESSES: usize = 6;

fn is_v4_link_local(ip: Ipv4Addr) -> bool {
    ip.octets()[0] == 169 && ip.octets()[1] == 254
}

fn is_v6_link_local(ip: Ipv6Addr) -> bool {
    ip.segments()[0] & 0xffc0 == 0xfe80
}

/// Deprecated site-local (`fec0::/10`) and other prefixes that are never reachable peers:
/// IPv4-mapped and IPv4-compatible forms, the discard prefix, documentation.
fn is_v6_unusable(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    s[0] & 0xffc0 == 0xfec0
        || ip.to_ipv4_mapped().is_some()
        || (s[..6] == [0, 0, 0, 0, 0, 0] && !ip.is_loopback())
        || (s[0] == 0x0100 && s[1..4] == [0, 0, 0])
        || (s[0] == 0x2001 && s[1] == 0x0db8)
}

/// An interface identifier derived from the hardware address (modified EUI-64, RFC 4291
/// appendix A): it carries the device's MAC address wherever the device goes.
fn is_eui64(ip: Ipv6Addr) -> bool {
    let o = ip.octets();
    o[11] == 0xff && o[12] == 0xfe
}

fn usable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_multicast()
                || v4.is_broadcast()
                || is_v4_link_local(v4))
        }
        IpAddr::V6(v6) => {
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || is_v6_link_local(v6)
                || is_v6_unusable(v6))
        }
    }
}

/// The local addresses a connection binds and announces as host candidates, most preferred
/// first.
///
/// - **Left out**: loopback, link-local (IPv4 `169.254/16`, IPv6 `fe80::/10`: reachable only
///   with a zone, which a candidate cannot carry), unspecified, multicast, deprecated
///   site-local, mapped and documentation addresses.
/// - **One IPv6 address per interface and /64.** An interface with privacy extensions
///   (RFC 8981) holds a temporary address and a stable one in the same prefix. Only one is
///   announced: the one the system itself uses as its source address (`preferred`, the
///   temporary one), else the first that is not derived from the hardware address, else what
///   there is. The stable address is never announced next to a temporary one: it would
///   identify the device across networks to every contact.
/// - **Order** (it becomes the candidates' local preference, RFC 8445 section 5.1.2.1): the
///   default route's addresses first, IPv6 before IPv4 (RFC 8421), then the other interfaces
///   in the system's order, families interleaved.
/// - **At most [`MAX_LOCAL_ADDRESSES`]**, keeping at least one address of each family that
///   has any.
/// - **Loopback only when there is nothing else** (a machine with no network: two clients on
///   it still reach each other).
pub fn select_addresses(all: &[LocalAddress], preferred: [Option<IpAddr>; 2]) -> Vec<IpAddr> {
    let preferred: Vec<IpAddr> = preferred.into_iter().flatten().collect();
    // One per (interface, family, network) for IPv6; IPv4 addresses are all kept.
    let mut chosen: Vec<&LocalAddress> = Vec::new();
    for addr in all.iter().filter(|a| usable(a.ip)) {
        let IpAddr::V6(v6) = addr.ip else {
            if !chosen.iter().any(|c| c.ip == addr.ip) {
                chosen.push(addr);
            }
            continue;
        };
        let network = |ip: Ipv6Addr| u128::from(ip) >> 64;
        let rank = |a: &LocalAddress| match a.ip {
            ip if preferred.contains(&ip) => 0,
            IpAddr::V6(ip) if !is_eui64(ip) => 1,
            _ => 2,
        };
        let same = chosen.iter().position(|c| {
            c.interface == addr.interface
                && matches!(c.ip, IpAddr::V6(other) if network(other) == network(v6))
        });
        match same {
            Some(i) if rank(addr) < rank(chosen[i]) => chosen[i] = addr,
            Some(_) => {}
            None => chosen.push(addr),
        }
    }

    if chosen.is_empty() {
        // No network at all: loopback, so that two clients on one machine connect.
        let mut loopback: Vec<IpAddr> = all
            .iter()
            .map(|a| a.ip)
            .filter(IpAddr::is_loopback)
            .collect();
        loopback.sort_by_key(IpAddr::is_ipv4);
        loopback.dedup();
        return loopback;
    }

    let default_interfaces: Vec<&str> = chosen
        .iter()
        .filter(|c| preferred.contains(&c.ip))
        .map(|c| c.interface.as_str())
        .collect();
    let mut ordered: Vec<IpAddr> = Vec::with_capacity(chosen.len());
    let mut push = |ip: IpAddr| {
        if !ordered.contains(&ip) {
            ordered.push(ip);
        }
    };
    // The addresses the system routes from, IPv6 first.
    for want_v6 in [true, false] {
        for c in &chosen {
            if preferred.contains(&c.ip) && c.ip.is_ipv6() == want_v6 {
                push(c.ip);
            }
        }
    }
    // The default interfaces' other addresses, then every other interface in order; within
    // an interface IPv6 first.
    let mut interfaces: Vec<&str> = default_interfaces.clone();
    for c in &chosen {
        if !interfaces.contains(&c.interface.as_str()) {
            interfaces.push(&c.interface);
        }
    }
    for name in interfaces {
        for want_v6 in [true, false] {
            for c in chosen.iter().filter(|c| c.interface == name) {
                if c.ip.is_ipv6() == want_v6 {
                    push(c.ip);
                }
            }
        }
    }

    if ordered.len() > MAX_LOCAL_ADDRESSES {
        // Keep the best of the family that the cut would remove altogether.
        let kept = &ordered[..MAX_LOCAL_ADDRESSES];
        let missing = [true, false].into_iter().find(|v6| {
            !kept.iter().any(|ip| ip.is_ipv6() == *v6)
                && ordered.iter().any(|ip| ip.is_ipv6() == *v6)
        });
        let rescue = missing.and_then(|v6| ordered.iter().copied().find(|ip| ip.is_ipv6() == v6));
        ordered.truncate(MAX_LOCAL_ADDRESSES);
        if let Some(ip) = rescue {
            ordered[MAX_LOCAL_ADDRESSES - 1] = ip;
        }
    }
    ordered
}

/// The addresses [`select_addresses`] picks on `network` right now.
pub fn local_addresses(network: &dyn Network) -> Vec<IpAddr> {
    select_addresses(
        &network.addresses(),
        [
            network.preferred_source(true),
            network.preferred_source(false),
        ],
    )
}

/// The local preference (RFC 8445 section 5.1.2.1) of the `index`-th local address: unique
/// per address, highest for the first.
pub fn local_preference(index: usize) -> u16 {
    u16::MAX - (index.min(1023) as u16) * 64
}

/// An ICE candidate priority (RFC 8445 section 5.1.2.1) for component 1.
pub fn candidate_priority(type_preference: u8, local_preference: u16) -> u32 {
    (u32::from(type_preference) << 24) | (u32::from(local_preference) << 8) | 255
}

/// How often [`NetworkMonitor`] looks at the interface list.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Reports when the set of usable local addresses changed.
///
/// It polls: every `interval` it lists the interfaces and compares the addresses
/// [`select_addresses`] would pick with the last set. A push notification would be earlier by
/// up to one interval, but there is no portable one: the route socket (macOS, BSD), netlink
/// (Linux) and `NotifyIpInterfaceChange` (Windows) are three implementations to keep correct,
/// and the crate that wraps two of them has none for Apple systems. Listing the interfaces is
/// one system call, and the monitor only runs while its receiver is alive.
///
/// A change is reported once it has been seen on two consecutive polls with the same result
/// (an interface that is coming up gets its addresses one at a time), so the notification
/// trails the change by one to two intervals.
pub struct NetworkMonitor {
    changes: mpsc::UnboundedReceiver<Vec<IpAddr>>,
}

impl NetworkMonitor {
    /// Start watching `network`. Must be called inside a tokio runtime.
    pub fn start(network: Arc<dyn Network>, interval: Duration) -> NetworkMonitor {
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut detector = ChangeDetector::new(local_addresses(network.as_ref()));
            let mut tick = tokio::time::interval(interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await;
            loop {
                tokio::select! {
                    _ = tick.tick() => {}
                    _ = tx.closed() => return,
                }
                let seen = local_addresses(network.as_ref());
                if let Some(changed) = detector.observe(seen)
                    && tx.send(changed).is_err()
                {
                    return;
                }
            }
        });
        NetworkMonitor { changes: rx }
    }

    /// The next change: the usable addresses after it. `None` when the monitor stopped.
    pub async fn changed(&mut self) -> Option<Vec<IpAddr>> {
        self.changes.recv().await
    }
}

/// The debounce behind [`NetworkMonitor`]: a new address set counts once two consecutive
/// observations agree on it.
#[derive(Debug)]
pub struct ChangeDetector {
    current: BTreeSet<IpAddr>,
    candidate: Option<BTreeSet<IpAddr>>,
}

impl ChangeDetector {
    pub fn new(initial: Vec<IpAddr>) -> Self {
        ChangeDetector {
            current: initial.into_iter().collect(),
            candidate: None,
        }
    }

    /// Feed one observation; returns the new address set when a change has settled.
    pub fn observe(&mut self, seen: Vec<IpAddr>) -> Option<Vec<IpAddr>> {
        let ordered = seen.clone();
        let seen: BTreeSet<IpAddr> = seen.into_iter().collect();
        if seen == self.current {
            self.candidate = None;
            return None;
        }
        if self.candidate.as_ref() == Some(&seen) {
            self.current = seen;
            self.candidate = None;
            return Some(ordered);
        }
        self.candidate = Some(seen);
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(interface: &str, ip: &str, prefix_len: u8) -> LocalAddress {
        LocalAddress {
            interface: interface.to_owned(),
            ip: ip.parse().unwrap(),
            prefix_len,
        }
    }

    fn ips(list: &[&str]) -> Vec<IpAddr> {
        list.iter().map(|s| s.parse().unwrap()).collect()
    }

    fn pick(all: &[LocalAddress], v6: Option<&str>, v4: Option<&str>) -> Vec<IpAddr> {
        select_addresses(
            all,
            [
                v6.map(|s| s.parse().unwrap()),
                v4.map(|s| s.parse().unwrap()),
            ],
        )
    }

    #[test]
    fn loopback_and_link_local_are_left_out() {
        let all = [
            addr("lo0", "127.0.0.1", 8),
            addr("lo0", "::1", 128),
            addr("lo0", "fe80::1", 64),
            addr("en0", "fe80::1c2d:3e4f:5a6b:7c8d", 64),
            addr("en0", "192.168.1.20", 24),
            addr("en1", "169.254.10.3", 16),
            addr("en2", "0.0.0.0", 0),
            addr("en2", "ff02::1", 8),
            addr("en2", "fec0::1", 64),
            addr("en2", "::ffff:10.0.0.1", 96),
            addr("en2", "2001:db8::1", 64),
        ];
        assert_eq!(
            pick(&all, None, Some("192.168.1.20")),
            ips(&["192.168.1.20"])
        );
    }

    #[test]
    fn both_families_and_every_interface_are_gathered_default_route_first() {
        let all = [
            addr("utun3", "10.8.0.2", 32),
            addr("en0", "192.168.1.20", 24),
            addr("en0", "2a01:db9:1:2:a1b2:c3d4:e5f6:1789", 64),
            addr("en5", "10.0.0.7", 24),
            addr("en5", "fd00:1::7", 64),
        ];
        assert_eq!(
            pick(
                &all,
                Some("2a01:db9:1:2:a1b2:c3d4:e5f6:1789"),
                Some("192.168.1.20")
            ),
            ips(&[
                "2a01:db9:1:2:a1b2:c3d4:e5f6:1789",
                "192.168.1.20",
                "10.8.0.2",
                "fd00:1::7",
                "10.0.0.7",
            ])
        );
    }

    #[test]
    fn one_ipv6_address_per_network_and_the_temporary_one_wins() {
        // en0 holds a stable (hardware-derived) and a temporary address in one /64, a
        // deprecated temporary one too, and a ULA in another prefix.
        let stable = "2a01:db9:1:2:021e:c2ff:fe9a:4d5e";
        let temporary = "2a01:db9:1:2:b0c1:4a5e:91d3:7f02";
        let old_temporary = "2a01:db9:1:2:5d11:8e0a:c477:3b6c";
        let all = [
            addr("en0", stable, 64),
            addr("en0", old_temporary, 64),
            addr("en0", temporary, 64),
            addr("en0", "fd12:3456:789a:1:021e:c2ff:fe9a:4d5e", 64),
            addr("en0", "192.168.1.20", 24),
        ];
        // The system's own source address is the temporary one.
        let got = pick(&all, Some(temporary), Some("192.168.1.20"));
        assert_eq!(
            got,
            ips(&[
                temporary,
                "192.168.1.20",
                "fd12:3456:789a:1:021e:c2ff:fe9a:4d5e"
            ])
        );
        assert!(!got.contains(&stable.parse().unwrap()));
        // Without a routed source the hardware-derived address still loses to any other.
        let got = pick(&all, None, None);
        assert!(got.contains(&old_temporary.parse().unwrap()), "{got:?}");
        assert!(!got.contains(&stable.parse().unwrap()), "{got:?}");
        // It is announced only when the interface has nothing else in that network.
        let only = [addr("en0", stable, 64)];
        assert_eq!(pick(&only, None, None), ips(&[stable]));
        // The same prefix on another interface is another network.
        let two = [addr("en0", temporary, 64), addr("en1", old_temporary, 64)];
        assert_eq!(pick(&two, None, None).len(), 2);
    }

    #[test]
    fn loopback_is_the_fallback_of_a_machine_without_a_network() {
        let all = [
            addr("lo0", "127.0.0.1", 8),
            addr("lo0", "::1", 128),
            addr("lo0", "fe80::1", 64),
        ];
        assert_eq!(pick(&all, None, None), ips(&["::1", "127.0.0.1"]));
        assert!(pick(&[], None, None).is_empty());
    }

    #[test]
    fn the_list_is_capped_and_keeps_both_families() {
        let mut all: Vec<LocalAddress> = (0..10)
            .map(|i| addr(&format!("en{i}"), &format!("10.0.{i}.2"), 24))
            .collect();
        all.push(addr("en9", "2a01:db9:9::2", 64));
        let got = pick(&all, None, Some("10.0.0.2"));
        assert_eq!(got.len(), MAX_LOCAL_ADDRESSES);
        assert_eq!(got[0], "10.0.0.2".parse::<IpAddr>().unwrap());
        assert!(got.iter().any(IpAddr::is_ipv6), "{got:?}");
        assert!(got.iter().filter(|ip| ip.is_ipv4()).count() == MAX_LOCAL_ADDRESSES - 1);
    }

    #[test]
    fn priorities_are_unique_and_follow_the_order() {
        let host: Vec<u32> = (0..MAX_LOCAL_ADDRESSES)
            .map(|i| candidate_priority(126, local_preference(i)))
            .collect();
        assert!(host.windows(2).all(|w| w[0] > w[1]), "{host:?}");
        // Every host candidate outranks every server-reflexive one, and those every relay.
        let srflx = candidate_priority(100, local_preference(0));
        let relay = candidate_priority(0, local_preference(0));
        assert!(host.iter().all(|p| *p > srflx) && srflx > relay);
        // RFC 8445's formula for the single-address case.
        assert_eq!(candidate_priority(126, 65535), 2_130_706_431);
    }

    #[test]
    fn a_change_is_reported_once_it_has_settled() {
        let mut d = ChangeDetector::new(ips(&["192.168.1.20"]));
        assert_eq!(d.observe(ips(&["192.168.1.20"])), None);
        // Wi-Fi goes away: seen once, not reported yet.
        assert_eq!(d.observe(ips(&[])), None);
        // The new network's addresses arrive one at a time.
        assert_eq!(d.observe(ips(&["10.20.0.5"])), None);
        assert_eq!(d.observe(ips(&["2a01:db9::5", "10.20.0.5"])), None);
        assert_eq!(
            d.observe(ips(&["2a01:db9::5", "10.20.0.5"])),
            Some(ips(&["2a01:db9::5", "10.20.0.5"]))
        );
        assert_eq!(d.observe(ips(&["10.20.0.5", "2a01:db9::5"])), None);
        // A blip that reverts is never reported.
        assert_eq!(d.observe(ips(&["10.20.0.5"])), None);
        assert_eq!(d.observe(ips(&["2a01:db9::5", "10.20.0.5"])), None);
        assert_eq!(d.observe(ips(&["2a01:db9::5", "10.20.0.5"])), None);
    }
}
