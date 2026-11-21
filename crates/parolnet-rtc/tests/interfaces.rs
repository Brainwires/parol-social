//! Several sockets per connection, on real loopback sockets: with `Gather::Interfaces` a
//! connection binds every address the network lists, IPv4 and IPv6, asks the STUN servers of
//! each family, and an ICE restart moves it to the addresses the machine has then.
//!
//! The machine's interface list is a test double (loopback only, changed by the test); the
//! sockets are the operating system's. Hosts without IPv6 loopback skip the dual-stack parts.

mod support;

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use parolnet_rtc::net::{DatagramSocket, LocalAddress, Network, SystemNetwork};
use parolnet_rtc::rtc::stun::message::{BINDING_SUCCESS, Message, TransactionId};
use parolnet_rtc::rtc::stun::xoraddr::XorMappedAddress;
use parolnet_rtc::{Gather, RtcConfig};
use support::{Pair, host_addresses, ufrag};
use tokio::net::UdpSocket;

/// A machine whose interface list the test controls; its sockets are real.
#[derive(Debug)]
struct Loopbacks(Mutex<Vec<IpAddr>>);

impl Loopbacks {
    fn new(addrs: &[&str]) -> Arc<Loopbacks> {
        let list = Loopbacks(Mutex::new(Vec::new()));
        list.set(addrs);
        Arc::new(list)
    }

    fn set(&self, addrs: &[&str]) {
        *self.0.lock().unwrap() = addrs.iter().map(|a| a.parse().unwrap()).collect();
    }
}

impl Network for Loopbacks {
    fn addresses(&self) -> Vec<LocalAddress> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .map(|ip| LocalAddress {
                interface: "lo0".into(),
                ip: *ip,
                prefix_len: if ip.is_ipv4() { 8 } else { 128 },
            })
            .collect()
    }

    fn preferred_source(&self, _v6: bool) -> Option<IpAddr> {
        None
    }

    fn bind(&self, addr: SocketAddr) -> io::Result<Box<dyn DatagramSocket>> {
        SystemNetwork.bind(addr)
    }
}

fn ipv6_loopback() -> bool {
    std::net::UdpSocket::bind("[::1]:0").is_ok()
}

fn config(network: &Arc<Loopbacks>, offerer: bool) -> RtcConfig {
    RtcConfig {
        gather: Gather::Interfaces,
        bind: "0.0.0.0:0".parse().unwrap(),
        network: network.clone(),
        data_channel: offerer.then(|| "pn-test".to_owned()),
        polite: !offerer,
        ..Default::default()
    }
}

async fn ping_pong(pair: &mut Pair, what: &str) {
    let (a_channel, b_channel) = (pair.a.seen.channel.unwrap(), pair.b.seen.channel.unwrap());
    let (a_before, b_before) = (pair.a.seen.messages.len(), pair.b.seen.messages.len());
    pair.a.handle.send_data(a_channel, what.as_bytes()).unwrap();
    pair.b.handle.send_data(b_channel, what.as_bytes()).unwrap();
    pair.until(what, 10, |p| {
        p.a.seen.messages.len() > a_before && p.b.seen.messages.len() > b_before
    })
    .await;
}

/// Answers binding requests with the sender's own address moved to another port, so the
/// mapped address differs from the socket's (as behind a NAT).
async fn stun_server(bind: &str) -> SocketAddr {
    let socket = UdpSocket::bind(bind).await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        loop {
            let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let mut req = Message::new();
            req.raw = buf[..n].to_vec();
            if req.decode().is_err() {
                continue;
            }
            let mut resp = Message::new();
            resp.build(&[
                Box::new(TransactionId(req.transaction_id.0)),
                Box::new(BINDING_SUCCESS),
                Box::new(XorMappedAddress {
                    ip: from.ip(),
                    port: 40_000,
                }),
            ])
            .unwrap();
            let _ = socket.send_to(&resp.raw, from).await;
        }
    });
    addr
}

#[tokio::test]
async fn host_candidates_of_both_families_and_dual_stack_stun() {
    if !ipv6_loopback() {
        eprintln!("skipped: no IPv6 loopback on this host");
        return;
    }
    let (net_a, net_b) = (
        Loopbacks::new(&["127.0.0.1", "::1"]),
        Loopbacks::new(&["127.0.0.1", "::1"]),
    );
    let (stun4, stun6) = (
        stun_server("127.0.0.1:0").await,
        stun_server("[::1]:0").await,
    );
    let mut a = config(&net_a, true);
    a.stun_servers = vec![
        format!("stun:{stun4}"),
        format!("stun:[::1]:{}", stun6.port()),
    ];
    let mut pair = Pair::new(a, config(&net_b, false)).await;
    let locals = pair.a.handle.local_addrs().await.unwrap();
    assert_eq!(locals.len(), 2, "{locals:?}");
    assert!(
        locals[0].is_ipv6() && locals[1].is_ipv4(),
        "IPv6 first: {locals:?}"
    );
    assert_eq!(pair.a.handle.local_addr(), locals[0]);

    pair.connect().await;
    let offer = &pair.a.seen.descriptions[0].sdp;
    assert_eq!(host_addresses(offer), ["127.0.0.1", "::1"], "{offer}");
    assert_eq!(
        host_addresses(&pair.b.seen.descriptions[0].sdp),
        ["127.0.0.1", "::1"]
    );
    // Each socket asked the server of its own family, and each answer became a candidate
    // related to that socket.
    let srflx: Vec<&str> = offer.lines().filter(|l| l.contains("typ srflx")).collect();
    assert!(
        srflx
            .iter()
            .any(|l| l.contains(" 127.0.0.1 40000 ") && l.contains("raddr 127.0.0.1")),
        "{srflx:?}"
    );
    assert!(
        srflx
            .iter()
            .any(|l| l.contains(" ::1 40000 ") && l.contains("raddr ::1")),
        "{srflx:?}"
    );
    // The IPv6 host candidate outranks the IPv4 one, and every host one every srflx one.
    let priority = |needle: &str| -> u32 {
        offer
            .lines()
            .find(|l| l.contains("candidate:") && l.contains(needle))
            .and_then(|l| l.split_ascii_whitespace().nth(3))
            .and_then(|p| p.parse().ok())
            .unwrap_or_else(|| panic!("no candidate with {needle} in {offer}"))
    };
    let (v6, v4) = (priority(" ::1 "), priority(" 127.0.0.1 "));
    assert!(v6 > v4, "{v6} {v4}");
    let best_srflx = srflx
        .iter()
        .filter_map(|l| l.split_ascii_whitespace().nth(3)?.parse::<u32>().ok())
        .max()
        .unwrap();
    assert!(v4 > best_srflx);

    pair.until("the data channel", 10, |p| {
        p.a.seen.channel.is_some() && p.b.seen.channel.is_some()
    })
    .await;
    ping_pong(&mut pair, "over one of the pairs").await;
    pair.close().await;
}

/// A socket that gets no STUN answer (its interface has no route to the servers) does not
/// cost the connection the whole STUN timeout once another socket was answered.
#[tokio::test]
async fn gathering_does_not_wait_out_the_timeout_for_a_socket_without_an_answer() {
    if !ipv6_loopback() {
        eprintln!("skipped: no IPv6 loopback on this host");
        return;
    }
    let net = Loopbacks::new(&["127.0.0.1", "::1"]);
    let stun4 = stun_server("127.0.0.1:0").await;
    // An IPv6 "server" that never answers.
    let silent = UdpSocket::bind("[::1]:0").await.unwrap();
    let mut config = config(&net, true);
    config.stun_servers = vec![
        format!("stun:{stun4}"),
        format!("stun:[::1]:{}", silent.local_addr().unwrap().port()),
    ];
    config.stun_timeout = std::time::Duration::from_secs(5);
    let started = std::time::Instant::now();
    let mut pair = Pair::new(config, self::config(&net, false)).await;
    let took = started.elapsed();
    assert!(
        took < std::time::Duration::from_secs(2),
        "gathering took {took:?}"
    );
    pair.a.handle.create_offer().unwrap();
    pair.until("the offer", 10, |p| !p.a.seen.descriptions.is_empty())
        .await;
    let offer = &pair.a.seen.descriptions[0].sdp;
    assert!(
        offer
            .lines()
            .any(|l| l.contains("typ srflx") && l.contains(" 127.0.0.1 40000 ")),
        "{offer}"
    );
    pair.close().await;
}

#[tokio::test]
async fn an_ice_restart_moves_to_the_addresses_the_machine_has_now() {
    if !ipv6_loopback() {
        eprintln!("skipped: no IPv6 loopback on this host");
        return;
    }
    // Both machines start on an IPv4-only network.
    let (net_a, net_b) = (
        Loopbacks::new(&["127.0.0.1"]),
        Loopbacks::new(&["127.0.0.1"]),
    );
    let mut pair = Pair::new(config(&net_a, true), config(&net_b, false)).await;
    pair.connect().await;
    pair.until("the data channel", 10, |p| {
        p.a.seen.channel.is_some() && p.b.seen.channel.is_some()
    })
    .await;
    assert_eq!(
        host_addresses(&pair.a.seen.descriptions[0].sdp),
        ["127.0.0.1"]
    );
    ping_pong(&mut pair, "on the first network").await;
    let before = pair.a.handle.local_addrs().await.unwrap();

    // Both move to a network that has IPv6 only. `a` notices and restarts; `b` learns of it
    // from the offer and gathers on what it has now.
    net_a.set(&["::1"]);
    net_b.set(&["::1"]);
    pair.a.handle.restart_ice().unwrap();
    pair.until("the restart", 10, |p| {
        p.a.seen.offers() == 2 && p.b.seen.answers() == 2
    })
    .await;
    let offer = pair.a.seen.descriptions.last().unwrap();
    let answer = pair.b.seen.descriptions.last().unwrap();
    assert_ne!(ufrag(offer), ufrag(&pair.a.seen.descriptions[0]));
    assert_eq!(host_addresses(&offer.sdp), ["::1"], "{}", offer.sdp);
    assert_eq!(host_addresses(&answer.sdp), ["::1"], "{}", answer.sdp);
    let after = pair.a.handle.local_addrs().await.unwrap();
    assert!(after.iter().all(SocketAddr::is_ipv6), "{after:?}");
    assert!(!after.contains(&before[0]), "the old socket is closed");

    pair.until("connected on the new network", 15, |p| {
        p.a.seen.connected() && p.b.seen.connected()
    })
    .await;
    ping_pong(&mut pair, "on the second network").await;
    // The same SCTP association and channel throughout.
    let quality = pair.a.handle.quality().await.unwrap();
    assert!(quality.local_candidate.is_some());
    pair.settle(100).await;
    pair.close().await;
}

#[tokio::test]
async fn a_machine_without_any_address_does_not_start() {
    let nothing = Loopbacks::new(&[]);
    let err = parolnet_rtc::spawn(config(&nothing, true)).await.err();
    assert!(
        matches!(err, Some(parolnet_rtc::RtcError::NoInterface)),
        "{err:?}"
    );
    // One whose only listed address cannot be bound reports the socket error.
    let unbindable = Loopbacks::new(&["127.0.0.1"]);
    let mut cfg = config(&unbindable, true);
    cfg.bind = "0.0.0.0:1".parse().unwrap(); // a privileged port
    if let Err(err) = parolnet_rtc::spawn(cfg).await {
        assert!(matches!(err, parolnet_rtc::RtcError::Io(_)), "{err:?}");
    }
}
