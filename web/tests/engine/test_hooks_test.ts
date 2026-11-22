// The optional `__parolnetTest` contract (docs/web-port/interop.md §11.4).
import { assert, assertEquals } from "@std/assert";
import * as mod from "../../src/engine/mod.ts";
import { installTestHooks } from "../../src/engine/test-hooks.ts";
import { withWorld } from "./harness/world.ts";

Deno.test("test hooks: not part of the engine's public module, not installed by default", () => {
  assert(!("installTestHooks" in mod));
  assert(!("__parolnetTest" in globalThis));
});

Deno.test(
  "test hooks: the §11.4 contract drives pairing, chat and calls",
  withWorld(async (w) => {
    const a = await w.device("a", { media: true });
    const b = await w.device("b", { media: true });
    const windowA = new EventTarget() as EventTarget & { CustomEvent: typeof CustomEvent };
    windowA.CustomEvent = CustomEvent;
    const seen: unknown[] = [];
    windowA.addEventListener("parolnet:test", (e) => seen.push((e as CustomEvent).detail));
    const ha = installTestHooks(a.engine, windowA);
    const targetB: Record<string, unknown> = {};
    const hb = installTestHooks(b.engine, targetB);
    assertEquals(targetB.__parolnetTest, hb);

    assertEquals(ha.version, 1);
    assertEquals(await ha.ready(), { peerId: a.id });
    assert(ha.relayRegistered());
    assertEquals(ha.iceServers(), []);
    assertEquals(ha.pathState(b.id), "offline");

    const code = await ha.showPairingCode();
    // The text form of the code: base45 with an underscore for every blank.
    assert(/^[0-9A-Z_$%*+\-./:]{100,}$/.test(code), code);
    assertEquals(ha.sas(), null);
    await hb.pairWithCode(code);
    await w.settle();
    // Both show the same verification code; each says it matches.
    assertEquals(ha.sas()?.digits, hb.sas()?.digits);
    assertEquals([ha.sas()?.peerId, hb.sas()?.peerId], [b.id, a.id]);
    assertEquals(hb.pathState(a.id), "connecting");
    await ha.confirmSas();
    assertEquals(ha.sas()?.confirmed, true);
    await hb.confirmSas();
    await w.settle();
    assertEquals([ha.sas(), hb.sas()], [null, null]);
    assertEquals(await ha.contacts(), [b.id]);
    assertEquals(hb.pathState(a.id), "direct");
    assertEquals(ha.rawPathState(b.id), "Direct");

    assertEquals(await hb.sendText(a.id, "hello"), { state: "Sent" });
    await w.settle();
    assertEquals(await ha.messages(b.id), [{
      direction: "received",
      text: "hello",
      state: "Received",
    }]);
    assertEquals(await hb.messages(a.id), [{ direction: "sent", text: "hello", state: "Sent" }]);

    assertEquals(ha.callState(), "idle");
    await hb.startCall(a.id, true);
    await w.settle();
    assertEquals(ha.incomingCall()?.peerId, b.id);
    assertEquals(ha.incomingCall()?.video, true);
    assertEquals([ha.callState(), hb.callState()], ["incoming", "outgoing"]);
    await ha.acceptCall();
    await w.settle();
    assertEquals([ha.callState(), hb.callState()], ["active", "active"]);
    assertEquals(ha.incomingCall(), null);
    await ha.hangup();
    await w.settle();
    assertEquals([ha.callState(), hb.callState()], ["idle", "idle"]);

    const kinds = new Set(seen.map((d) => (d as { kind: string }).kind));
    assert(kinds.has("path") && kinds.has("message") && kinds.has("call"));
    assert(kinds.has("sas"));
    assert(
      seen.some((d) =>
        JSON.stringify(d) === JSON.stringify({ kind: "paired", peerId: b.id, sasVerified: true })
      ),
    );
    assert(
      seen.some((d) =>
        JSON.stringify(d) === JSON.stringify({ kind: "path", peerId: b.id, state: "direct" })
      ),
    );
    // Nothing secret is reachable through the hooks.
    assert(!JSON.stringify(Object.keys(ha)).match(/secret|session|key|turn/i));
    ha.uninstall();
    hb.uninstall();
    assert(!("__parolnetTest" in targetB));
  }),
);
