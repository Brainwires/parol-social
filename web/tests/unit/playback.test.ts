// The registry of the elements that play a call (src/platform/playback.ts): everything is
// detached in one turn, paused first, and a stream the call no longer has is not played.
import { assertEquals } from "@std/assert";
import { detach, keepOnly, play } from "../../src/platform/playback.ts";

/** As much of a media element as the registry touches, with a log of what was done to it. */
function element(name: string, log: string[]) {
  let stream: unknown = null;
  return {
    get srcObject() {
      return stream;
    },
    set srcObject(next: unknown) {
      log.push(`${name}.srcObject = ${next === null ? "null" : (next as { id: string }).id}`);
      stream = next;
    },
    play() {
      log.push(`${name}.play()`);
      return Promise.resolve();
    },
    pause() {
      log.push(`${name}.pause()`);
    },
  } as unknown as HTMLMediaElement;
}

const stream = (id: string) => ({ id }) as unknown as MediaStream;

Deno.test("playback: when the call ends every element is paused and detached in that turn", () => {
  const log: string[] = [];
  const [remote, self] = [element("remote", log), element("self", log)];
  const [theirs, ours] = [stream("theirs"), stream("ours")];
  keepOnly([ours, theirs]);
  play(remote, theirs);
  play(self, ours);
  assertEquals(log, [
    "remote.srcObject = theirs",
    "remote.play()",
    "self.srcObject = ours",
    "self.play()",
  ]);

  log.length = 0;
  keepOnly([]);
  assertEquals(log, [
    "remote.pause()",
    "remote.srcObject = null",
    "self.pause()",
    "self.srcObject = null",
  ]);

  // Nothing is left to do when the screen lets go of them afterwards, or at the next call's end.
  log.length = 0;
  detach(remote);
  detach(self);
  keepOnly([]);
  assertEquals(log, []);
});

Deno.test("playback: a stream the call no longer has is not played, and stops playing", () => {
  const log: string[] = [];
  const [remote, self] = [element("remote", log), element("self", log)];
  const [theirs, front, back] = [stream("theirs"), stream("front"), stream("back")];
  keepOnly([front, theirs]);
  play(remote, theirs);
  play(self, front);

  // The camera was switched: the old capture stops playing, their video goes on.
  log.length = 0;
  keepOnly([back, theirs]);
  assertEquals(log, ["self.pause()", "self.srcObject = null"]);
  log.length = 0;
  play(self, back);
  assertEquals(log, ["self.srcObject = back", "self.play()"]);

  // The call ended; an effect of an earlier render still asks for the old stream.
  keepOnly([]);
  log.length = 0;
  play(remote, theirs);
  assertEquals(log, []);
  assertEquals(remote.srcObject, null);
});

Deno.test("playback: an element whose teardown throws does not keep the others playing", () => {
  const log: string[] = [];
  const [broken, fine] = [element("broken", log), element("fine", log)];
  const theirs = stream("theirs");
  keepOnly([theirs]);
  play(broken, theirs);
  play(fine, theirs);
  broken.pause = () => {
    throw new Error("pause failed");
  };
  log.length = 0;
  keepOnly([]);
  assertEquals(log, ["fine.pause()", "fine.srcObject = null"]);
});
