// Sends a VP8 test stream from headless Chromium to the spike's WHIP-style endpoint.
//
//   node apps/desktop/spike/send.mjs [endpoint] [seconds]
//
// endpoint defaults to http://127.0.0.1:8189/whip, seconds to 30. CHROME_PATH picks the
// browser (else puppeteer's own Chrome for Testing). The picture is a canvas: colour bars, a
// moving box and a frame counter, so a receiver can tell decoded video from a flat fill. The
// audio is a 1000 Hz sine (Opus, Chromium's libopus), for the opus-rs interop check.
// Test scaffolding only: in ParolNet the offer and answer travel inside the E2EE session.

import puppeteer from "puppeteer";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const endpoint = process.argv[2] ?? "http://127.0.0.1:8189/whip";
const seconds = Number(process.argv[3] ?? 30);
const profile = mkdtempSync(join(tmpdir(), "parolnet-spike-chrome-"));

const browser = await puppeteer.launch({
  headless: true,
  executablePath: process.env.CHROME_PATH || undefined,
  userDataDir: profile,
  args: [
    "--allow-loopback-in-peer-connection",
    "--disable-features=WebRtcHideLocalIpsWithMdns",
    "--no-first-run",
    "--no-default-browser-check",
    "--autoplay-policy=no-user-gesture-required",
  ],
});

try {
  const page = await browser.newPage();
  page.on("console", (msg) => console.log(`[page] ${msg.text()}`));
  await page.goto("about:blank");

  const offer = await page.evaluate(async () => {
    const canvas = document.createElement("canvas");
    canvas.width = 640;
    canvas.height = 360;
    document.body.appendChild(canvas);
    const ctx = canvas.getContext("2d");
    const bars = ["#c0c0c0", "#c0c000", "#00c0c0", "#00c000", "#c000c0", "#c00000", "#0000c0"];
    let n = 0;
    setInterval(() => {
      bars.forEach((c, i) => {
        ctx.fillStyle = c;
        ctx.fillRect((i * canvas.width) / bars.length, 0, canvas.width / bars.length + 1, canvas.height);
      });
      ctx.fillStyle = "#101010";
      ctx.fillRect(((n * 4) % (canvas.width + 80)) - 80, 220, 80, 80);
      ctx.fillStyle = "#ffffff";
      ctx.fillRect(20, 20, 260, 60);
      ctx.fillStyle = "#000000";
      ctx.font = "bold 40px monospace";
      ctx.fillText(`#${String(n).padStart(6, "0")}`, 30, 65);
      n++;
    }, 33);

    const track = canvas.captureStream(30).getVideoTracks()[0];
    const audioContext = new AudioContext({ sampleRate: 48000 });
    await audioContext.resume();
    const oscillator = audioContext.createOscillator();
    oscillator.frequency.value = 1000;
    const gain = audioContext.createGain();
    gain.gain.value = 0.3;
    const destination = audioContext.createMediaStreamDestination();
    oscillator.connect(gain).connect(destination);
    oscillator.start();
    window.audioContext = audioContext;

    const pc = new RTCPeerConnection();
    window.pc = pc;
    pc.addTransceiver(destination.stream.getAudioTracks()[0], { direction: "sendonly" });
    const transceiver = pc.addTransceiver(track, { direction: "sendonly" });
    const vp8 = RTCRtpSender.getCapabilities("video").codecs.filter(
      (c) => c.mimeType.toLowerCase() === "video/vp8",
    );
    transceiver.setCodecPreferences(vp8);
    await pc.setLocalDescription(await pc.createOffer());
    await new Promise((resolve) => {
      if (pc.iceGatheringState === "complete") return resolve();
      pc.addEventListener("icegatheringstatechange", () => {
        if (pc.iceGatheringState === "complete") resolve();
      });
      setTimeout(resolve, 3000);
    });
    return pc.localDescription.sdp;
  });

  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "content-type": "application/sdp" },
    body: offer,
  });
  if (response.status !== 201) {
    throw new Error(`endpoint answered ${response.status}`);
  }
  const answer = await response.text();
  await page.evaluate((sdp) => window.pc.setRemoteDescription({ type: "answer", sdp }), answer);
  await page.waitForFunction(() => window.pc.connectionState === "connected", { timeout: 20000 });
  console.log("sender connected");

  await new Promise((resolve) => setTimeout(resolve, seconds * 1000));
  const stats = await page.evaluate(async () => {
    const out = {};
    (await window.pc.getStats()).forEach((s) => {
      if (s.type === "outbound-rtp" && s.kind === "audio") {
        out.audioPacketsSent = s.packetsSent;
      }
      if (s.type === "outbound-rtp" && s.kind === "video") {
        Object.assign(out, {
          framesEncoded: s.framesEncoded,
          keyFramesEncoded: s.keyFramesEncoded,
          pliCount: s.pliCount,
          nackCount: s.nackCount,
          encoder: s.encoderImplementation,
          size: `${s.frameWidth}x${s.frameHeight}`,
        });
      }
    });
    return out;
  });
  console.log(`sender stats ${JSON.stringify(stats)}`);
} finally {
  await browser.close();
  rmSync(profile, { recursive: true, force: true });
}
