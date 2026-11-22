# PNP-011: ParolNet 1:1 Calls

### Status: CANDIDATE
### Version: 0.1
### Date: 2026-11-21

---

## Changelog

**v0.1 (2026-11-21) — Initial version**

- 1:1 voice and video calls as the native clients, the web app and the PWA run them: call signals inside the end-to-end session, a WebRTC connection of the call's own with DTLS-SRTP, Opus and VP8, the ICE policy, ringing, busy, reject and timeouts.
- New in this version over what the PWA does: renegotiation of a call that is under way (`reoffer` / `reanswer`: video added, a camera turned off or on, an ICE restart), ICE restart of the data connection after a network change, send-side congestion control with the encoder following its estimate, and connection-quality reporting. All of it is negotiated by feature names; a peer that lists none keeps working exactly as before.
- Supersedes PNP-007 sections 4 (call signaling), 5 (audio framing), 6 (video framing) and the call part of section 8 (MediaCall shaping). PNP-007's file transfer sections are superseded separately by PNP-010.
- Clauses: PNP-011-MUST-001 through PNP-011-MUST-034, PNP-011-SHOULD-001 through PNP-011-SHOULD-008, PNP-011-MAY-001.

---

## 1. Overview

A ParolNet call is a WebRTC session between two paired peers. Its media (Opus audio, optionally VP8 video) travels peer to peer as SRTP keyed by DTLS; no relay or server carries or can read it. What makes the session end-to-end authenticated is where its session descriptions travel: inside the Double Ratchet session of the two peers (PNP-002), as CALL_SIGNAL messages (PNP-001 section 3.4) on the verified data channel between them (PNP-001 section 10.5.1). The DTLS certificate fingerprints in those descriptions are therefore authenticated by the peers' identity keys, and DTLS-SRTP is end to end without a separate binding step.

A call uses a WebRTC connection of its own, next to the data connection that carries its signals. The two have separate ICE sessions, certificates and lifetimes: a call ends without touching the data connection, and the data connection can be rebuilt during a call.

This specification describes calls as implemented by `parolnet-app` and `parolnet-rtc` (native clients), `web/src/engine/calls.ts` (web app) and `pwa/src/call.js` (PWA). Sections 4 to 6 are common to all of them. Sections 7 to 10 are implemented by the native clients; the web app and the PWA do not list the features that enable them and interoperate through sections 4 to 6 alone.

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT" and "MAY" in this document are to be interpreted as described in RFC 2119.

## 2. Terminology

- **Caller**, **callee**: the peer that sent the call's `offer`, and the peer that received it.
- **Data connection**: the WebRTC connection between two paired peers that carries the `parolnet` data channel (PNP-001 section 10.5). A data connection is *verified* once the peer's CHANNEL_BINDING has been checked (PNP-001 section 10.5.1).
- **Call connection**: the WebRTC connection that carries one call's media.
- **Description**: an SDP session description (RFC 8866) as used by JSEP (RFC 9429): an offer or an answer.
- **Set up**: a call is set up on a peer once that peer has applied both the call's `offer` and its `answer`.
- **Renegotiation**: an offer / answer exchange on a call connection that is set up.
- **ICE restart**: a renegotiation that replaces the ICE credentials and candidates of a connection (RFC 8445 section 9) and keeps everything else, the DTLS session included.
- **Designated initiator**: of two peers, the one whose PeerId is lower; the peer that offers the data connection (PNP-001 section 10.5).

## 3. Call Signals

### 3.1 Carriage

A call signal is the plaintext of a CALL_SIGNAL envelope (message type 0x0B, PNP-001 section 3.4), encrypted and padded like every other envelope of the session and sent on the peers' verified data channel. Signals are not queued for a peer that is not connected and are not sent through a relay (PNP-007 section 7.8, PNP-001 section 10.5.1): a call can be started only with a peer whose data connection is verified.

The body of a call signal is a UTF-8 JSON object with a string member `action`, which names the signal, and a string member `callId`, which names the call. A receiver MUST ignore a CALL_SIGNAL whose body is not such an object, or whose `callId` is empty or longer than 64 characters. **PNP-011-MUST-001**

The caller chooses the `callId` of a new call: 16 bytes from a cryptographically secure random source, written as 32 lowercase hexadecimal digits. An implementation MUST generate call identifiers this way. **PNP-011-MUST-002**

### 3.2 Signals

| `action` | Members beside `callId` | Sent by | Meaning |
|---|---|---|---|
| `offer` | `sdp`, `withVideo`, `features` | caller | Start a call; `sdp` is the call connection's offer. |
| `answer` | `sdp`, `withVideo`, `features` | callee | Accept; `sdp` is the answer. |
| `ice` | `candidate` | either | One more ICE candidate (an `RTCIceCandidateInit` object: `candidate`, `sdpMid`, `sdpMLineIndex`, `usernameFragment`). |
| `reject` | none | callee | Decline, or busy. |
| `hangup` | none | either | End the call. |
| `reoffer` | `sdp` | either | Renegotiate a call that is set up; `sdp` is an offer (section 7). |
| `reanswer` | `sdp` | the receiver of a `reoffer` | `sdp` is the answer to it. |

`sdp` is a string holding the description. `withVideo` is a boolean saying whether the call was started as a video call; an absent `withVideo` means false. An `offer` or `answer` without a string `sdp` MUST be ignored. **PNP-011-MUST-003**

A receiver MUST ignore a signal whose `action` it does not know, and MUST ignore members it does not know in a signal it does. **PNP-011-MUST-004** This is what lets signals and members be added: the PWA and the web app ignore `reoffer`, `reanswer` and `features`.

### 3.3 Features

`features` is an array of strings naming what the sender implements beyond the signals `offer`, `answer`, `ice`, `reject` and `hangup`. This version defines one name:

| Name | Meaning |
|---|---|
| `renegotiate` | The sender accepts `reoffer` and answers it with `reanswer` (section 7). |

A receiver MUST treat a `features` member that is not an array as an empty list, MUST skip entries that are not strings, and MUST keep names it does not know out of its decisions without failing the signal. **PNP-011-MUST-005**

An implementation that accepts `reoffer` MUST list `renegotiate` in every `offer` and `answer` it sends. An implementation that does not MUST NOT list it; with nothing to list it omits `features`, and its signals are then exactly those of the PWA. **PNP-011-MUST-006**

A `reoffer` or `reanswer` without a string `sdp` MUST be ignored. **PNP-011-MUST-007**

## 4. Call Setup

### 4.1 States

```
caller:  Outgoing ──answer──▶ Connecting ──media connected──▶ Active ──▶ Ended
callee:  Incoming ──accept──▶ Connecting ──media connected──▶ Active ──▶ Ended
```

The caller creates the call connection, makes its offer and sends `offer`. The callee rings. On accepting it creates its call connection, applies the offer, and sends `answer`; on declining it sends `reject`. The caller applies the answer. Each side is Active once its call connection reports connected. Either side ends the call with `hangup`, which the other side does not answer.

A signal that names a call held with another peer than its sender is ignored: a call belongs to the pair of peers that set it up.

### 4.2 Incoming Offers

An `offer` whose `callId` names a call the receiver already holds MUST be ignored. **PNP-011-MUST-008**

A peer that holds a call that has not ended (ringing, connecting or active, in either direction) is busy. A busy peer MUST answer the `offer` of another call with `reject` and MUST NOT ring for it. **PNP-011-MUST-009** Two peers that call each other at the same moment therefore reject each other's call, and both calls end.

### 4.3 Timeouts

A call that is not answered within 60 seconds MUST end: the caller sends `hangup` and reports that nobody answered, the callee stops ringing and reports a missed call. **PNP-011-MUST-010**

After the answer (sent or applied), the call connection MUST connect within 30 seconds; a peer whose connection has not connected by then sends `hangup` and reports the call as failed. **PNP-011-MUST-011**

### 4.4 Early Candidates

Descriptions carry their candidates (section 5.5); `ice` signals carry candidates found later. One may arrive before the receiver has applied the description it belongs to (a callee that has not accepted yet). A receiver SHOULD keep up to 64 such candidates per call and add them once the description is applied, and drop those beyond. **PNP-011-SHOULD-001** An `ice` signal whose `candidate.candidate` is the empty string marks the end of candidates and adds nothing.

## 5. The Media Session

### 5.1 One Connection per Call

A call's media MUST use a peer connection of its own: one that carries no data channel and is not the data connection. **PNP-011-MUST-012**

### 5.2 Keying

The call connection is keyed by DTLS-SRTP (RFC 5763, RFC 5764). Every description of a call MUST carry the DTLS certificate fingerprint of its sender as `a=fingerprint:sha-256`, MUST describe its media sections with the `UDP/TLS/RTP/SAVPF` profile, and MUST NOT carry SDES keys (`a=crypto`). **PNP-011-MUST-013**

Each side verifies the certificate the other presents in the DTLS handshake against the fingerprint in the description it received. Because that description arrived inside the end-to-end session, a party between the peers that cannot forge envelopes of the session cannot substitute a certificate: there is no CHANNEL_BINDING step for a call connection.

Media is not padded (PNP-006 covers envelopes; the security invariant "messages are padded" excludes call media): an observer of the path sees packet sizes and timing of an SRTP stream.

### 5.3 Transport

All media sections of a call MUST be bundled on one transport (`a=group:BUNDLE`), and RTCP MUST be multiplexed with RTP (`a=rtcp-mux`). **PNP-011-MUST-014**

### 5.4 Codecs

The first media section of a call is audio. It MUST offer Opus (RFC 7587) as `opus/48000/2`. **PNP-011-MUST-015** Senders encode mono voice in 20 ms frames; receivers accept any Opus frame length.

A video call has one video section after the audio section, and it MUST offer VP8 (RFC 7741) as `VP8/90000`; a call started without video has no video section until one is added by renegotiation (section 7). **PNP-011-MUST-016**

The video section SHOULD also offer retransmission (RFC 4588) as `rtx/90000` with `apt` naming the VP8 payload type. **PNP-011-SHOULD-002** Lost video packets are then repaired on a stream of their own. Without it a repair is the original packet sent again, which an SRTP sender may only do when the bytes are identical to the first transmission.

Both sections SHOULD negotiate transport-wide congestion control feedback: the `transport-cc` RTCP feedback and the `http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01` header extension. **PNP-011-SHOULD-003** It is what section 9 estimates the path from; a peer that does not negotiate it is sent media at the starting rate.

The video section offers the RTCP feedback `nack`, `nack pli`, `ccm fir` and `goog-remb`. A receiver that cannot decode (it has no keyframe, or lost its reference) asks for a keyframe with PLI, at most once a second.

### 5.5 Candidates

A description is sent once candidate gathering for it has finished, and MUST contain the candidates gathered. **PNP-011-MUST-017** (`ice` signals remain valid for candidates that turn up later, and browsers send them.)

Which candidates a peer may have at all is fixed by PNP-001 section 10.5: STUN servers come from the peer's own relay and from nowhere else, a TURN server only from the user's own settings, and with "relay only" selected nothing but relay candidates is signalled or used. This section adds which local addresses become host candidates.

A peer MUST NOT signal a host candidate for a loopback, link-local (IPv4 `169.254.0.0/16`, IPv6 `fe80::/10`), unspecified or multicast address, with one exception: a machine with no other address signals its loopback addresses, so that two clients on it can connect. **PNP-011-MUST-018**

An interface with IPv6 privacy extensions (RFC 8981) holds a temporary and a stable address in the same prefix. For each interface and each /64 a peer MUST signal at most one IPv6 address: the one the system uses as its source address towards the internet when it is in that prefix, otherwise one that is not derived from the hardware address (modified EUI-64), and a hardware-derived address only when the interface has no other in that prefix. **PNP-011-MUST-019** A stable address signalled next to a temporary one would identify the device to every contact across networks.

A peer SHOULD order its host candidates so that the addresses of the default route come first, IPv6 before IPv4 (RFC 8421), give each address its own local preference in that order, and prioritise every host candidate over every server-reflexive one and those over relay candidates (RFC 8445 section 5.1.2). **PNP-011-SHOULD-004**

Peers resolve the mDNS names (`<uuid>.local`) that browsers signal in place of private addresses.

## 6. Ending a Call

`hangup` ends a call in any state; `reject` ends one that the callee has not accepted. A peer that receives either closes its call connection and reports the end; neither is answered. A call whose connection fails (ICE fails, or the connection closes) ends as failed, and the peer that noticed sends `hangup`.

## 7. Renegotiation

### 7.1 When

A call that is set up can be changed by a second offer / answer exchange on its connection, carried by `reoffer` and `reanswer`. Three changes are defined: starting to send video (in a call without a video section the section is added; the peer's side of it receives until the peer starts its own video the same way), stopping or resuming the video one sends (the direction of the video section), and an ICE restart (section 8).

`reoffer` MUST NOT be sent to a peer that did not list `renegotiate` in the `offer` or `answer` of that call, nor by a peer that did not list it itself. **PNP-011-MUST-020**

A receiver MUST ignore a `reoffer` for a call that is not set up, has ended, or that it does not hold, and one it receives although it did not list `renegotiate`. **PNP-011-MUST-021**

### 7.2 Crossing Offers

Both peers can send a `reoffer` before either has seen the other's. The caller's stands: a caller that receives a `reoffer` while its own is unanswered MUST ignore it, and a callee in the same position MUST take its own back (a JSEP rollback), apply the caller's and answer it. **PNP-011-MUST-022** The callee offers what it had wanted again once that exchange is done.

### 7.3 What a Renegotiation Keeps

A `reoffer` and its `reanswer` MUST carry the DTLS fingerprint of the description they replace: the DTLS session, and the SRTP keys derived from it, continue. **PNP-011-MUST-023**

A `reoffer` that only changes media (a section added, a direction changed) MUST keep the ICE username fragment and password of the description it replaces. **PNP-011-MUST-024** An offer with other ICE credentials is an ICE restart.

Whether a peer sends video is what the video section of its latest description says: it sends when the section is not rejected (its port is not 0) and its direction is `sendrecv` or `sendonly`, where a section without a direction attribute is `sendrecv`. A receiver MUST derive it from the description and not from `withVideo`, which describes how the call started. **PNP-011-MUST-025**

### 7.4 Unanswered Offers

A `reoffer` that is not answered within 10 seconds MUST be taken back (a rollback), and the call continues as it was before it; what the offer asked for is not pending afterwards. **PNP-011-MUST-026**

### 7.5 Peers That Do Not Renegotiate

With a peer that did not list `renegotiate` the call stays as it was set up. An implementation MUST NOT try to add video to an audio call with such a peer, and when its user turns the camera off in a video call it MUST keep the video stream as negotiated. **PNP-011-MUST-027** What is sent on a stream whose camera is off is then black frames (one a second is enough), which is what a browser sends for a disabled track.

## 8. ICE Restart

### 8.1 On a Call Connection

A peer restarts ICE on a call connection when its usable local addresses changed (section 8.4), or when the connection reports that it lost its path. The restart is a `reoffer`.

The offer of an ICE restart MUST carry a new ICE username fragment and password and the candidates gathered for it on the addresses the peer has at that time, and so MUST its answer. **PNP-011-MUST-028** The answerer gathers again too: its own network may be the one that changed.

Until the restart has selected a candidate pair, both peers MUST go on sending and accepting the session's packets (DTLS, SRTP) on the pair the session had (RFC 8445 section 9): an ICE restart does not interrupt a path that still works. **PNP-011-MUST-029**

A call whose peer does not list `renegotiate` cannot be restarted; it continues while its path does and ends as failed when ICE fails.

### 8.2 On the Data Connection

The descriptions of a data connection cross the signaling relay (`rtc_offer`, `rtc_answer`, PNP-001 section 10.5), and so do those of its ICE restart. Whether a peer applies a second `rtc_offer` to the connection it has, instead of replacing the connection, is announced on the data channel: the `identity` frame each side sends when the channel opens has a `features` array of strings, in which `ice-restart` says so.

A peer that applies ICE restarts to its data connection MUST list `ice-restart` in its `identity` frame; a peer MUST NOT send an ICE restart offer for a data connection whose other side did not list it, or when it did not list it itself. **PNP-011-MUST-030** A peer that does not list it (the PWA, the web app) treats every `rtc_offer` as an offer for a new connection, as before.

An `rtc_offer` from a peer to which the receiver holds a connection MUST be applied to that connection only if the connection is verified and the offer carries exactly the DTLS fingerprints that the connection's CHANNEL_BINDING covers; any other `rtc_offer` is an offer for a new connection. Likewise the `rtc_answer` to a restart MUST carry those fingerprints, and a peer that receives another answer MUST give the connection up and build a new one. **PNP-011-MUST-031**

The relay can read and write these descriptions. What it gains by forging a restart is what it has at connection setup already: it can make the peers send their ICE checks, and then their encrypted packets, to addresses of its choosing, or nowhere. It cannot read or alter the channel's content, because the DTLS session, whose certificates the binding covers, does not change.

When restart offers cross, the designated initiator's stands: a designated initiator that receives a restart offer while its own is unanswered MUST ignore it; the other peer MUST drop its own and apply and answer the one it received. **PNP-011-MUST-032**

### 8.3 When a Restart Does Not Complete

A restart of the data connection has 15 seconds to be answered and to connect. At that point a peer whose connection has no working path MUST give the connection up and build a new one, exactly as it does for a connection that failed; a peer whose connection works but whose offer was never answered MUST take the offer back and keep the connection. **PNP-011-MUST-033**

While a data connection has no working path a client shows it as connecting, not as direct, whatever is being done about it.

### 8.4 Noticing a Network Change

A client SHOULD watch the set of local addresses it would use for host candidates (section 5.5) and restart ICE on its data connections and its call when the set changes, after two consecutive observations agree on the new set (an interface that comes up receives its addresses one at a time). **PNP-011-SHOULD-005** The reference client observes every 2 seconds. It also asks its relay at once whether the relay's socket is still alive, since the restart of the data connection needs the relay.

## 9. Adapting to the Path

### 9.1 The Estimate

A sender SHOULD run send-side congestion control on a call connection: an estimate of the bitrate the path carries, from the peer's transport-wide feedback (section 5.4), that starts at 300 kbit/s and is kept between 100 kbit/s and 2.5 Mbit/s. **PNP-011-SHOULD-006** The reference client uses the Google congestion control algorithm (draft-ietf-rmcat-gcc-02): a delay-gradient trend filter with additive-increase / multiplicative-decrease, lowered further when more than a tenth of the packets are lost.

### 9.2 The Encoder

The estimate is for everything a peer sends. The video encoder's target bitrate MUST NOT exceed nine tenths of what the estimate leaves after 80 kbit/s for audio, except that it is not required to go below 30 kbit/s. **PNP-011-MUST-034**

```
video_bitrate = max(30 000, (estimate - 80 000) * 9 / 10)        bit/s
```

The held-back tenth pays for retransmissions and the encoder's overshoot. A sender changes the encoder's rate when the estimate changes, without a keyframe.

### 9.3 Received Audio

A receiver SHOULD de-jitter audio before decoding it: deliver the packets in sequence order at the pace of their RTP timestamps, held as long as packets have recently arrived late, and give up a packet that arrives after its successors were played. **PNP-011-SHOULD-007** Video is not held back this way: frames are reassembled from whatever order their packets arrive in, and a retransmission may arrive long after its neighbours.

## 10. Connection Quality

A client SHOULD report the quality of an active call's connection to its user interface about once a second, and count the connection as weak when more than 5% of the packets are lost in either direction, when the round trip takes more than 400 ms, or when the estimate of section 9.1 is under 200 kbit/s. **PNP-011-SHOULD-008**

A user interface MAY show nothing while the connection is not weak, and one line of words naming the reasons while it is. **PNP-011-MAY-001**

The measurements come from the peer's RTCP receiver reports (loss of what was sent, round trip time), from the receiver's own counters (loss of what was expected) and from ICE consent checks (round trip time of the selected pair). Whether the selected pair goes through a TURN server is part of the report.

## 11. Security Considerations

- **Authentication of the media session.** The fingerprints that DTLS verifies arrive in CALL_SIGNAL envelopes, which are authenticated and encrypted by the session of the two peers. Compromise of a relay does not let it join or observe a call. Compromise of a peer's session keys does, as it does for messages.
- **What the path sees.** The two peers see each other's candidate addresses; a call is only possible with a paired contact whose data connection exists, so no address is shown that the data connection did not show already. With "relay only" selected, peers and the path see the user's TURN server instead (PNP-001 section 10.5). An observer of the path sees an SRTP flow: its endpoints, timing and sizes, and so that a call takes place and roughly what kind.
- **Renegotiation.** `reoffer` and `reanswer` are authenticated like every call signal. A renegotiation cannot replace the DTLS session (section 7.3), so it cannot be used to move a call to keys the peers did not set up.
- **Restart of the data connection.** Its signaling is not authenticated; section 8.2 states what that allows and why it is no more than connection setup allows. A peer applies it only under the fingerprints its channel binding verified.
- **Feature names.** `features` is information from the peer about itself. A peer that lists a feature it does not implement only harms its own call: the other side's `reoffer` goes unanswered and is taken back after 10 seconds (section 7.4).
- **Resource bounds.** A call identifier is at most 64 characters, pending candidates are bounded (section 4.4), a peer holds one call, and a description is bounded by the envelope size (PNP-001 section 3.6).

## 12. Relation to Other Specifications

| Specification | Relation |
|---|---|
| PNP-001 section 3.4 | Allocates CALL_SIGNAL (0x0B). |
| PNP-001 section 10.5 | The signaling-only relay profile; the client's ICE policy (STUN from the own relay, TURN from the user). |
| PNP-001 section 10.5.1 | The channel binding that verifies the data connection call signals travel on, and whose fingerprints gate its ICE restart (section 8.2). |
| PNP-002 | The session that encrypts and authenticates call signals. |
| PNP-007 sections 4, 5, 6 and 8 | Superseded for 1:1 calls by this document. Their clauses stay registered (identifiers are never reused) and describe the earlier design: media carried in relay cells with application-level SRTP keys. |
| PNP-009 | Group calls are out of scope here. |
