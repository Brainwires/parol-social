// What went wrong, in plain words with what to do. The engine rejects with an `EngineError`
// whose `code` says why; its English `message` is for logs, never for the screen.
import { EngineError } from "../engine/types.ts";
import { type MessageKey, t } from "../i18n/index.ts";

const WORDS: Partial<Record<EngineError["code"], MessageKey>> = {
  InvalidCode: "pair.invalid",
  CodeExpired: "pair.expired",
  OwnCode: "pair.own",
  TooLong: "error.tooLong",
  NotQueued: "error.notQueued",
  Storage: "error.storage",
  Media: "call.error.media",
  NotConnected: "call.error.notConnected",
  Busy: "call.error.busy",
  Transfer: "error.transfer",
  NoSession: "error.noSession",
  UnknownContact: "error.unknownContact",
  UnknownTransfer: "error.unknownTransfer",
};

/** `fallback` is used for anything without words of its own. */
export function errorText(
  error: unknown,
  params: { name?: string } = {},
  fallback: MessageKey = "error.generic",
): string {
  const key = error instanceof EngineError ? WORDS[error.code] : undefined;
  return t(key ?? fallback, { name: params.name ?? "" });
}
