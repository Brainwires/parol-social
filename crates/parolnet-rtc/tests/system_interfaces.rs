//! Two connections on this machine's real interfaces (whatever they are): every usable
//! address is bound and announced, and the two connect over one of the pairs.
//!
//! Skipped (with a line on stderr) on a machine that does not deliver UDP between its own
//! sockets on those addresses: see `support::delivers_to_itself`.

mod support;

use parolnet_rtc::net::{SystemNetwork, local_addresses};
use parolnet_rtc::{Gather, RtcConfig};
use support::{Pair, delivers_to_itself, host_addresses};

fn config(offerer: bool) -> RtcConfig {
    RtcConfig {
        gather: Gather::Interfaces,
        bind: "0.0.0.0:0".parse().unwrap(),
        data_channel: offerer.then(|| "pn-test".to_owned()),
        polite: !offerer,
        mdns: false,
        ..Default::default()
    }
}

#[tokio::test]
async fn two_connections_on_the_machines_own_interfaces() {
    let addresses = local_addresses(&SystemNetwork);
    eprintln!("usable addresses: {addresses:?}");
    assert!(!addresses.is_empty(), "at least loopback");
    if !addresses.iter().any(|ip| delivers_to_itself(*ip)) {
        eprintln!("skipped: this machine does not deliver UDP between its own addresses");
        return;
    }
    let mut pair = Pair::new(config(true), config(false)).await;
    let bound = pair.a.handle.local_addrs().await.unwrap();
    eprintln!("bound: {bound:?}");
    assert!(!bound.is_empty());
    pair.a.handle.create_offer().unwrap();
    pair.until("the offer", 10, |p| !p.a.seen.descriptions.is_empty())
        .await;
    let offer = pair.a.seen.descriptions[0].sdp.clone();
    eprintln!(
        "{}",
        offer
            .lines()
            .filter(|l| l.contains("candidate"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    // Every bound address is a host candidate.
    let hosts = host_addresses(&offer);
    for addr in &bound {
        assert!(
            hosts.contains(&addr.ip().to_string()),
            "{addr} in {hosts:?}"
        );
    }
    pair.until("connected", 20, |p| {
        p.a.seen.connected() && p.b.seen.connected()
    })
    .await;
    pair.until("the channel", 10, |p| {
        p.a.seen.channel.is_some() && p.b.seen.channel.is_some()
    })
    .await;
    let quality = pair.a.handle.quality().await.unwrap();
    eprintln!(
        "selected: {:?} / {:?}",
        quality.local_candidate, quality.remote_candidate
    );
    pair.close().await;
}
