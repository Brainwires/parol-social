// Calls. An incoming call is a full screen on a phone and a banner at wide widths, with
// Accept and Decline. Once under way the call takes the whole window: their video fills it,
// this device's camera floats in a corner, the controls sit along the bottom. When it is
// over, the same screen says how it ended, in plain words.
import { useEffect, useRef, useState } from "denext";
import { Button, IconButton } from "../components/Button.tsx";
import { Avatar } from "../components/ConversationRow.tsx";
import { Icon } from "../components/Icon.tsx";
import { CALL_FAILED_MEDIA } from "../engine/calls.ts";
import { type MessageKey, t } from "../i18n/index.ts";
import {
  canChooseSpeaker,
  captureCamera,
  chooseDevice,
  deviceChoice,
  listDevices,
} from "../platform/devices.ts";
import { detach, play } from "../platform/playback.ts";
import { startRinging, stopRinging } from "../platform/ring.ts";
import { useStore } from "../state/context.ts";
import { type CallEndWords, callEndWords, type CallInfo } from "../state/model.ts";
import { nameOf } from "../state/store.ts";

const ENDED: Record<CallEndWords, MessageKey> = {
  youEnded: "call.ended.youEnded",
  theyEnded: "call.ended.theyEnded",
  // A call this device declined is not shown at all (the store drops it).
  youDeclined: "call.ended.youEnded",
  theyDeclined: "call.ended.theyDeclined",
  noAnswer: "call.ended.noAnswer",
  missed: "call.ended.missed",
  failed: "call.ended.failed",
};

/** "3:07", "1:02:45". */
export function formatDuration(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  const pad = (n: number) => String(n).padStart(2, "0");
  const hours = Math.floor(s / 3600);
  const minutes = Math.floor((s % 3600) / 60);
  return hours > 0 ? `${hours}:${pad(minutes)}:${pad(s % 60)}` : `${minutes}:${pad(s % 60)}`;
}

function endedText(call: CallInfo, name: string): string {
  if (call.state.kind !== "Ended") return "";
  const end = call.state.end;
  if (end.kind === "Failed" && end.reason === CALL_FAILED_MEDIA) return t("call.error.media");
  return t(ENDED[callEndWords(end, call.incoming)], { name });
}

/** Plays a stream. `srcObject` is set through the element: there is no attribute for it. */
function Media({ stream, muted, className, label, sinkId, testId }: {
  stream: MediaStream | null;
  muted: boolean;
  className: string;
  label: string;
  sinkId?: string;
  testId: string;
}) {
  const element = useRef<HTMLVideoElement>(null);
  useEffect(() => {
    const video = element.current;
    if (!video) return;
    // Through the registry, so the store can detach it the moment the call ends.
    play(video, stream);
    return () => detach(video);
  }, [stream]);
  useEffect(() => {
    const video = element.current as
      | (HTMLVideoElement & {
        setSinkId?(id: string): Promise<void>;
      })
      | null;
    if (sinkId === undefined || !video?.setSinkId) return;
    // A speaker that is gone: the browser's default keeps playing.
    void video.setSinkId(sinkId).catch(() => {});
  }, [sinkId, stream]);
  return (
    <video
      ref={element}
      className={className}
      muted={muted}
      autoPlay
      playsInline
      aria-label={label}
      data-testid={testId}
    />
  );
}

function IncomingCall({ call, name }: { call: CallInfo; name: string }) {
  const store = useStore();
  const dialog = useRef<HTMLDialogElement>(null);
  const words = useRef<HTMLParagraphElement>(null);

  // A modal dialog, so it is on top of any open sheet. Focus goes to the words, not to a
  // button: a key pressed for something else must not answer or decline a call. Tab reaches
  // Accept next.
  useEffect(() => {
    const element = dialog.current;
    if (element && !element.open && typeof element.showModal === "function") element.showModal();
    words.current?.focus();
    startRinging("incoming");
    return () => {
      stopRinging();
      if (element?.open) element.close();
    };
  }, []);

  const text = t(call.video ? "call.incomingVideo" : "call.incoming", { name });
  return (
    <dialog
      ref={dialog}
      className="incoming"
      role="alertdialog"
      aria-label={text}
      data-testid="incoming-call"
      onCancel={(event: { preventDefault(): void }) => event.preventDefault()}
    >
      <Avatar name={name} />
      <p className="incoming__words" tabIndex={-1} ref={words} data-testid="incoming-call-words">
        {text}
      </p>
      <div className="incoming__actions">
        <Button
          variant="primary"
          testId="call-accept"
          icon={call.video ? "video" : "phone"}
          onClick={() => void store.acceptCall().catch(() => {})}
        >
          {t("call.accept")}
        </Button>
        <Button
          variant="danger"
          testId="call-decline"
          onClick={() => void store.declineCall().catch(() => {})}
        >
          {t("call.decline")}
        </Button>
      </div>
    </dialog>
  );
}

function CallScreen({ call, name }: { call: CallInfo; name: string }) {
  const store = useStore();
  const dialog = useRef<HTMLDialogElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const media = store.callMedia.value;
  const [cameras, setCameras] = useState<MediaDeviceInfo[]>([]);
  const [speakers, setSpeakers] = useState<MediaDeviceInfo[]>([]);
  const [camera, setCamera] = useState(0);
  const [choosingOutput, setChoosingOutput] = useState(false);
  const [startedAt, setStartedAt] = useState<number | null>(null);
  const [elapsed, setElapsed] = useState(0);
  const kind = call.state.kind;
  const active = kind === "Active";
  const ended = kind === "Ended";

  // A modal dialog: the rest of the app is inert while a call has the window.
  useEffect(() => {
    const element = dialog.current;
    if (!element || element.open || typeof element.showModal !== "function") return;
    element.showModal();
    heading.current?.focus();
    return () => {
      if (element.open) element.close();
    };
  }, []);

  useEffect(() => {
    if (kind !== "Outgoing") return;
    startRinging("outgoing");
    return stopRinging;
  }, [kind]);

  // The timer runs from the moment the call is connected.
  useEffect(() => {
    if (!active) return;
    const start = Date.now();
    setStartedAt(start);
    const timer = setInterval(() => setElapsed((Date.now() - start) / 1000), 1000);
    return () => clearInterval(timer);
  }, [active]);

  // Which cameras and speakers there are; known by name once capture is allowed.
  useEffect(() => {
    if (!media.local) return;
    void listDevices().then((devices) => {
      setCameras(devices.cameras);
      setSpeakers(devices.speakers);
    });
  }, [media.local]);

  const flip = async () => {
    if (cameras.length < 2) return;
    const next = (camera + 1) % cameras.length;
    try {
      await store.replaceCamera(await captureCamera(cameras[next].deviceId));
      setCamera(next);
    } catch {
      // The other camera could not be used: the call goes on with this one.
    }
  };

  const status = kind === "Outgoing"
    ? t("call.outgoing", { name })
    : kind === "Connecting" || kind === "Incoming"
    ? t("call.connecting", { name })
    : active
    ? t("line.open")
    : endedText(call, name);

  return (
    <dialog
      ref={dialog}
      className="call"
      aria-label={t("call.with", { name })}
      data-testid="call-screen"
      data-state={kind}
      data-video={call.video ? "true" : "false"}
      onCancel={(event: { preventDefault(): void }) => {
        // Escape does not end a call; when it is over, it closes the screen.
        event.preventDefault();
        if (ended) store.dismissCall();
      }}
    >
      <div className="call__stage">
        {!ended && (
          <Media
            stream={media.remote}
            muted={false}
            className="call__remote"
            label={t("call.with", { name })}
            sinkId={canChooseSpeaker() ? deviceChoice.value.speaker : undefined}
            testId="call-remote"
          />
        )}
        {(!call.video || !media.remote || ended) && (
          <div className="call__avatar">
            <Avatar name={name} />
          </div>
        )}
        {!ended && call.video && media.local && (
          call.cameraOff
            ? <p className="call__self call__self--off">{t("call.cameraIsOff")}</p>
            : (
              <Media
                stream={media.local}
                muted
                className="call__self"
                label={t("call.selfView")}
                testId="call-self"
              />
            )
        )}
      </div>

      <header className="call__header">
        <h1 className="call__name" tabIndex={-1} ref={heading}>
          <bdi>{name}</bdi>
        </h1>
        <p className="call__status" role="status" data-testid="call-status">{status}</p>
        {active && startedAt !== null && (
          <p className="call__timer" role="timer" aria-live="off" data-testid="call-timer">
            {formatDuration(elapsed)}
          </p>
        )}
      </header>

      {ended
        ? (
          <div className="call__controls">
            <Button variant="primary" testId="call-close" onClick={store.dismissCall}>
              {t("call.close")}
            </Button>
          </div>
        )
        : (
          <div className="call__controls" role="group" aria-label={t("call.with", { name })}>
            <IconButton
              icon={call.muted ? "mic-off" : "mic"}
              label={t(call.muted ? "call.unmute" : "call.mute")}
              testId="call-mute"
              className="call__control"
              pressed={call.muted}
              onClick={() => store.setMuted(!call.muted)}
            />
            {call.video && (
              <IconButton
                icon={call.cameraOff ? "video-off" : "video"}
                label={t(call.cameraOff ? "call.cameraOn" : "call.cameraOff")}
                testId="call-camera"
                className="call__control"
                pressed={call.cameraOff}
                onClick={() => store.setCameraOff(!call.cameraOff)}
              />
            )}
            {call.video && cameras.length > 1 && (
              <IconButton
                icon="flip"
                label={t("call.flip")}
                testId="call-flip"
                className="call__control"
                onClick={() => void flip()}
              />
            )}
            {canChooseSpeaker() && speakers.length > 0 && (
              <div className="call__output">
                <button
                  type="button"
                  className="icon-btn call__control"
                  aria-label={t("call.output")}
                  aria-haspopup="menu"
                  aria-expanded={choosingOutput ? "true" : "false"}
                  data-testid="call-output"
                  onClick={() => setChoosingOutput(!choosingOutput)}
                >
                  <Icon name="speaker" />
                </button>
                {choosingOutput && (
                  <div
                    className="menu call__output-menu"
                    role="menu"
                    data-testid="call-output-menu"
                    onKeyDown={(event: { key: string }) => {
                      if (event.key === "Escape") setChoosingOutput(false);
                    }}
                  >
                    {[
                      { deviceId: "", label: t("call.outputDefault") },
                      ...speakers.filter((s) => s.deviceId !== "" && s.deviceId !== "default"),
                    ].map((speaker, index) => (
                      <button
                        key={speaker.deviceId}
                        type="button"
                        role="menuitemradio"
                        className="menu__item"
                        aria-checked={deviceChoice.value.speaker === speaker.deviceId
                          ? "true"
                          : "false"}
                        onClick={() => {
                          chooseDevice("speaker", speaker.deviceId);
                          setChoosingOutput(false);
                        }}
                      >
                        {speaker.label || t("settings.devices.unnamed", { n: index })}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            )}
            <IconButton
              icon="hangup"
              label={t("call.end")}
              testId="call-hangup"
              className="call__control call__control--end"
              onClick={() => void store.hangup().catch(() => {})}
            />
          </div>
        )}
    </dialog>
  );
}

/** Rendered once at the root: whatever call there is, on top of whatever screen is shown. */
export function CallLayer() {
  const store = useStore();
  const call = store.call.value;
  if (!call) return null;
  const name = nameOf(store, call.peerId);
  if (call.state.kind === "Incoming") return <IncomingCall call={call} name={name} />;
  return <CallScreen key={call.callId} call={call} name={name} />;
}
