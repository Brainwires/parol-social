// 1:1 calls: signalling on the verified channel, non-trickle SDP, callId matching, busy,
// reject / hangup teardown on both sides, ring and connect timeouts, mute and camera.
import { assert, assertEquals, assertRejects } from "@std/assert";
import { CALL_CONNECT_TIMEOUT_MS, CALL_RING_TIMEOUT_MS } from "../../src/engine/calls.ts";
import { type CallInfo, EngineError } from "../../src/engine/types.ts";
import { type CallSignal, callSignalJson, chatFrame } from "../../src/engine/wire.ts";
import { FakeStream, FakeTrack } from "./harness/fakes.ts";
import { type Device, withWorld, type World } from "./harness/world.ts";

async function pairWithMedia(w: World): Promise<[Device, Device]> {
  const a = await w.device("a", { media: true });
  const b = await w.device("b", { media: true });
  await w.pair(a, b);
  return [a, b];
}

function callStates(d: Device): string[] {
  return d.eventsOf("Call").map((e) =>
    e.call.state.kind === "Ended" ? `Ended(${e.call.state.end.kind})` : e.call.state.kind
  );
}

function call(d: Device): CallInfo {
  const c = d.engine.snapshot().call;
  if (!c) throw new Error("no call");
  return c;
}

/** The call connections of a device (those with tracks). */
function callPcs(d: Device) {
  return d.pcs.filter((p) => p.senders.length > 0);
}

/** Send a raw call signal from `from` on its data channel to the other side. */
function inject(from: Device, to: Device, sig: CallSignal): void {
  const env = from.wasm.envelope_encode(
    to.id,
    0x0b,
    new TextEncoder().encode(callSignalJson(sig)),
    0n,
    null,
  );
  from.pcs.find((p) => p.senders.length === 0 && p.connectionState === "connected")!.channels[0]
    .inject(chatFrame(env));
}

Deno.test(
  "call: video call from offer to active to hangup, torn down on both sides",
  withWorld(async (w) => {
    const [a, b] = await pairWithMedia(w);
    const signalsBefore = w.relay.signals.length;
    const started = await a.engine.startCall(b.id, true);
    assertEquals(started.state.kind, "Outgoing");
    assertEquals(started.callId.length, 32);
    await w.settle();
    const ringing = call(b);
    assertEquals(ringing, {
      ...started,
      peerId: a.id,
      incoming: true,
      state: { kind: "Incoming" },
    });
    // The callee builds nothing and captures nothing until the user accepts.
    assertEquals(callPcs(b).length, 0);
    assertEquals(b.streams.length, 0);

    await b.engine.acceptCall(ringing.callId);
    await w.settle();
    assertEquals(callStates(a), ["Outgoing", "Connecting", "Active"]);
    assertEquals(callStates(b), ["Incoming", "Connecting", "Active"]);
    // A connection of its own, with the user's ICE configuration, and nothing via the relay.
    assertEquals(callPcs(a).length, 1);
    assertEquals(callPcs(b).length, 1);
    assertEquals(w.relay.signals.length, signalsBefore);
    // Non-trickle: the offer carried its candidates.
    assert(callPcs(a)[0].localDescription!.sdp.includes("a=candidate:"));
    const media = a.engine.callMedia(started.callId)!;
    assertEquals(media.local, a.streams[0]);
    assertEquals(media.remote, b.streams[0]);
    assertEquals(a.streams[0].getVideoTracks().length, 1);
    assert(a.eventsOf("CallMedia").length >= 2);

    await a.engine.hangup(started.callId);
    await w.settle();
    assertEquals(callStates(a).at(-1), "Ended(HungUp)");
    assertEquals(callStates(b).at(-1), "Ended(RemoteHungUp)");
    for (const d of [a, b]) {
      assertEquals(d.engine.snapshot().call, null);
      assertEquals(callPcs(d)[0].connectionState, "closed");
      assert(d.streams[0].tracks.every((t) => t.stopped), "capture stopped");
      assertEquals(d.engine.callMedia(started.callId), null);
    }
    // The data channel is untouched.
    assertEquals(a.path(b), "Direct");
  }),
);

Deno.test(
  "call: reject tears the caller down at once",
  withWorld(async (w) => {
    const [a, b] = await pairWithMedia(w);
    const started = await a.engine.startCall(b.id, false);
    await w.settle();
    await b.engine.rejectCall(started.callId);
    await w.settle();
    assertEquals(callStates(b), ["Incoming", "Ended(Declined)"]);
    assertEquals(callStates(a), ["Outgoing", "Ended(Rejected)"]);
    assertEquals(callPcs(a)[0].connectionState, "closed");
    assert(a.streams[0].tracks.every((t) => t.stopped));
    assertEquals(a.streams[0].getVideoTracks().length, 0);
    // Nothing fires later.
    await w.advance(CALL_RING_TIMEOUT_MS + 1_000);
    assertEquals(callStates(a), ["Outgoing", "Ended(Rejected)"]);
  }),
);

Deno.test(
  "call: a second call while busy is answered with reject and changes nothing",
  withWorld(async (w) => {
    const a = await w.device("a", { media: true });
    const b = await w.device("b", { media: true });
    const c = await w.device("c", { media: true });
    await w.pair(a, b);
    await w.pair(a, c);
    const first = await b.engine.startCall(a.id, false);
    await w.settle();
    const second = await c.engine.startCall(a.id, false);
    await w.settle();
    assertEquals(callStates(c), ["Outgoing", "Ended(Rejected)"]);
    assertEquals(call(a).callId, first.callId);
    assertEquals(call(a).peerId, b.id);
    assert(second.callId !== first.callId);
    // And we cannot start one ourselves.
    assertEquals(
      (await assertRejects(() => a.engine.startCall(c.id, false), EngineError)).code,
      "Busy",
    );
  }),
);

Deno.test(
  "call: signals are matched by callId and by peer",
  withWorld(async (w) => {
    const a = await w.device("a", { media: true });
    const b = await w.device("b", { media: true });
    const c = await w.device("c", { media: true });
    await w.pair(a, b);
    await w.pair(a, c);
    const started = await a.engine.startCall(b.id, false);
    await w.settle();
    // A hangup for another call id, and one for the right id from the wrong contact.
    inject(b, a, { action: "hangup", callId: "ff".repeat(16) });
    inject(c, a, { action: "hangup", callId: started.callId });
    inject(c, a, { action: "answer", callId: started.callId, video: false, sdp: "v=0\r\n" });
    // A duplicate offer does not ring twice.
    inject(a, b, { action: "offer", callId: started.callId, video: false, sdp: "v=0\r\n" });
    await w.settle();
    assertEquals(callStates(a), ["Outgoing"]);
    assertEquals(callStates(b), ["Incoming"]);
    assert(a.logs.some((l) => l.includes("for someone else's call")));
    inject(b, a, { action: "hangup", callId: started.callId });
    await w.settle();
    assertEquals(callStates(a), ["Outgoing", "Ended(RemoteHungUp)"]);
  }),
);

Deno.test(
  "call: ice that arrives before the user accepts is kept and applied",
  withWorld(async (w) => {
    const [a, b] = await pairWithMedia(w);
    const started = await a.engine.startCall(b.id, false);
    await w.settle();
    const candidate = {
      candidate: "candidate:9 1 udp 1 192.0.2.9 9 typ host",
      sdpMid: "0",
      sdpMLineIndex: 0,
    };
    inject(a, b, { action: "ice", callId: started.callId, candidate });
    await w.settle();
    await b.engine.acceptCall(started.callId);
    await w.settle();
    assertEquals(callPcs(b)[0].remoteCandidates.map((c) => c.candidate), [candidate.candidate]);
    assertEquals(call(b).state.kind, "Active");
  }),
);

Deno.test(
  "call: nobody answers for 60 s: the caller hangs up and the callee's ringing stops",
  withWorld(async (w) => {
    const [a, b] = await pairWithMedia(w);
    await a.engine.startCall(b.id, false);
    await w.advance(CALL_RING_TIMEOUT_MS - 1_000);
    assertEquals(callStates(a), ["Outgoing"]);
    await w.advance(1_100);
    assertEquals(callStates(a), ["Outgoing", "Ended(NoAnswer)"]);
    assertEquals(callStates(b), ["Incoming", "Ended(RemoteHungUp)"]);
    assert(a.streams[0].tracks.every((t) => t.stopped));
  }),
);

Deno.test(
  "call: media that never connects fails the call on both sides after 30 s",
  withWorld(async (w) => {
    const [a, b] = await pairWithMedia(w);
    const started = await a.engine.startCall(b.id, false);
    await w.settle();
    w.rtc.blockConnect = true;
    await b.engine.acceptCall(started.callId);
    await w.advance(CALL_CONNECT_TIMEOUT_MS + 1_000);
    assertEquals(callStates(b).at(-1), "Ended(Failed)");
    assert(callStates(a).at(-1)!.startsWith("Ended("));
    assertEquals(a.engine.snapshot().call, null);
    assertEquals(w.rtc.open.filter((p) => p.senders.length > 0).length, 0);
  }),
);

Deno.test(
  "call: needs a contact, media and a verified channel",
  withWorld(async (w) => {
    const [a, b] = await pairWithMedia(w);
    const nomedia = await w.device("n");
    await w.pair(nomedia, a);
    const code = async (fn: () => Promise<unknown>) => (await assertRejects(fn, EngineError)).code;
    assertEquals(await code(() => a.engine.startCall("0c".repeat(32), false)), "UnknownContact");
    assertEquals(await code(() => nomedia.engine.startCall(a.id, false)), "Media");
    assertEquals(await code(() => a.engine.acceptCall("ab".repeat(16))), "UnknownCall");
    a.cut();
    await w.settle();
    assertEquals(await code(() => a.engine.startCall(b.id, false)), "NotConnected");
    // Asking for a call asks for the path too.
    await w.advance(1_000);
    assertEquals(a.path(b), "Direct");
  }),
);

Deno.test(
  "call: mute and camera toggle the local tracks without signalling",
  withWorld(async (w) => {
    const [a, b] = await pairWithMedia(w);
    const started = await a.engine.startCall(b.id, true);
    await w.settle();
    await b.engine.acceptCall(started.callId);
    await w.settle();
    const sentBefore = a.pcs[0].channels[0].sent.length;
    a.engine.setMuted(started.callId, true);
    a.engine.setCameraOff(started.callId, true);
    const [audio] = a.streams[0].getAudioTracks() as FakeTrack[];
    const [video] = a.streams[0].getVideoTracks() as FakeTrack[];
    assertEquals([audio.enabled, video.enabled], [false, false]);
    assertEquals([call(a).muted, call(a).cameraOff], [true, true]);
    a.engine.setMuted(started.callId, false);
    assertEquals([audio.enabled, video.enabled], [true, false]);
    assert(!video.stopped, "camera off keeps the track");
    assertEquals(a.pcs[0].channels[0].sent.length, sentBefore);
    // The other side's toggles are its own.
    assertEquals(call(b).muted, false);
  }),
);

Deno.test(
  "call: the data channel dropping does not end a call; shutdown hangs up",
  withWorld(async (w) => {
    const [a, b] = await pairWithMedia(w);
    const started = await a.engine.startCall(b.id, false);
    await w.settle();
    await b.engine.acceptCall(started.callId);
    await w.settle();
    await a.engine.shutdown();
    w.devices = w.devices.filter((d) => d !== a);
    await w.settle();
    assertEquals(callStates(a).at(-1), "Ended(HungUp)");
    assert(a.streams[0].tracks.every((t) => t.stopped));
    assert(callStates(b).at(-1)!.startsWith("Ended("));
  }),
);

Deno.test(
  "call: the camera can be replaced without renegotiation; the engine owns the new capture",
  withWorld(async (w) => {
    const [a, b] = await pairWithMedia(w);
    const started = await a.engine.startCall(b.id, true);
    await w.settle();
    await b.engine.acceptCall(call(b).callId);
    await w.settle();
    assertEquals(call(a).state.kind, "Active");
    const pc = callPcs(a)[0];
    const before = pc.senders.find((s) => s.track.kind === "video")!.track as FakeTrack;
    const signals = w.relay.signals.length;
    const mediaEvents = a.eventsOf("CallMedia").length;

    const back = new FakeStream([new FakeTrack("video")]);
    await a.engine.replaceCamera(started.callId, back);
    await w.settle();
    assert(before.stopped, "the first camera is released");
    assertEquals(pc.senders.find((s) => s.track.kind === "video")!.track, back.tracks[0]);
    const local = a.engine.callMedia(started.callId)!.local!;
    assertEquals(local.getVideoTracks(), [back.tracks[0]]);
    assertEquals(local.getAudioTracks().length, 1, "the microphone stays");
    assertEquals(a.eventsOf("CallMedia").length, mediaEvents + 1);
    assertEquals(w.relay.signals.length, signals, "no signalling");

    // A camera that is off stays off on the new track.
    a.engine.setCameraOff(started.callId, true);
    const third = new FakeStream([new FakeTrack("video")]);
    await a.engine.replaceCamera(started.callId, third);
    await w.settle();
    assertEquals(third.tracks[0].enabled, false);

    await a.engine.hangup(started.callId);
    await w.settle();
    assert(third.tracks[0].stopped, "released when the call ends");

    // After the call: refused, and the offered capture is stopped.
    const late = new FakeStream([new FakeTrack("video")]);
    const err = await assertRejects(
      () => a.engine.replaceCamera(started.callId, late),
      EngineError,
    );
    assertEquals(err.code, "UnknownCall");
    assert(late.tracks[0].stopped);
  }),
);
