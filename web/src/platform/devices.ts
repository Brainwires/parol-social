// Camera, microphone and speaker: which ones the person chose (remembered on this device),
// and the capture the engine asks for when a call starts. Browser media globals are read at
// call time, never at module load.
import { type ReadonlySignal, signal } from "denext/signals";
import type { MediaConstraints, MediaDevices as EngineMedia } from "../engine/platform.ts";
import { readPref, writePref } from "./prefs.ts";

export interface DeviceChoice {
  /** Device ids; an empty string is the browser's default. */
  microphone: string;
  camera: string;
  speaker: string;
}

function read(): DeviceChoice {
  try {
    const saved = JSON.parse(readPref("devices") ?? "{}") as Partial<DeviceChoice>;
    return {
      microphone: typeof saved.microphone === "string" ? saved.microphone : "",
      camera: typeof saved.camera === "string" ? saved.camera : "",
      speaker: typeof saved.speaker === "string" ? saved.speaker : "",
    };
  } catch {
    return { microphone: "", camera: "", speaker: "" };
  }
}

const choice = signal<DeviceChoice>(
  typeof localStorage === "undefined" ? { microphone: "", camera: "", speaker: "" } : read(),
);

export const deviceChoice: ReadonlySignal<DeviceChoice> = choice;

export function chooseDevice(kind: keyof DeviceChoice, deviceId: string): void {
  choice.value = { ...choice.value, [kind]: deviceId };
  writePref("devices", JSON.stringify(choice.value));
}

export interface DeviceList {
  microphones: MediaDeviceInfo[];
  cameras: MediaDeviceInfo[];
  speakers: MediaDeviceInfo[];
}

/** The devices the browser lists. Labels are empty until the person has allowed capture. */
export async function listDevices(): Promise<DeviceList> {
  const list: DeviceList = { microphones: [], cameras: [], speakers: [] };
  try {
    for (const device of await navigator.mediaDevices.enumerateDevices()) {
      if (device.kind === "audioinput") list.microphones.push(device);
      else if (device.kind === "videoinput") list.cameras.push(device);
      else if (device.kind === "audiooutput") list.speakers.push(device);
    }
  } catch {
    // No media devices here: three empty lists.
  }
  return list;
}

/** This browser can send a call's sound to a chosen speaker. */
export function canChooseSpeaker(): boolean {
  return typeof HTMLMediaElement !== "undefined" && "setSinkId" in HTMLMediaElement.prototype;
}

const VIDEO = { width: { ideal: 640 }, height: { ideal: 480 } };

function device(id: string): { deviceId?: { exact: string } } {
  return id ? { deviceId: { exact: id } } : {};
}

/**
 * Capture for a call, from the chosen devices. A chosen device that is gone (unplugged since)
 * falls back to the browser's default instead of failing the call.
 */
export const callMedia: EngineMedia = {
  async getUserMedia(constraints: MediaConstraints) {
    const chosen = choice.value;
    const wanted = (useChoice: boolean): MediaStreamConstraints => ({
      audio: constraints.audio ? (useChoice ? device(chosen.microphone) : true) : false,
      video: constraints.video ? { ...VIDEO, ...(useChoice ? device(chosen.camera) : {}) } : false,
    });
    try {
      return await navigator.mediaDevices.getUserMedia(wanted(true));
    } catch (error) {
      const name = (error as { name?: string })?.name;
      if (name !== "OverconstrainedError" && name !== "NotFoundError") throw error;
      return await navigator.mediaDevices.getUserMedia(wanted(false));
    }
  },
};

/** Video only, from one camera: for switching cameras during a call. */
export function captureCamera(deviceId: string): Promise<MediaStream> {
  return navigator.mediaDevices.getUserMedia({ video: { ...VIDEO, ...device(deviceId) } });
}
