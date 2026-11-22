import { type ReactNode, useEffect } from "denext";
import { Announcer } from "./components/Announcer.tsx";
import { ToastHost } from "./components/Toast.tsx";
import { route } from "./router.ts";
import { AddContact } from "./screens/AddContact.tsx";
import { CallLayer } from "./screens/Call.tsx";
import { Conversation, ConversationPlaceholder } from "./screens/Conversation.tsx";
import { ConversationList } from "./screens/ConversationList.tsx";
import { SasScreen } from "./screens/SasCheck.tsx";
import { Settings } from "./screens/Settings.tsx";
import { FirstRun, Loading, Locked, OtherTab, StartFailed } from "./screens/Start.tsx";
import { StoreProvider, useStore } from "./state/context.ts";
import type { AppStore } from "./state/store.ts";

function Frame() {
  const store = useStore();
  const current = route.value;
  // A verification code that waits to be compared takes the main column wherever the person
  // is (the add-a-contact screen shows it itself): the contact's device is waiting too.
  const sas = current.name === "add" ? null : store.sas.value;
  // A phone shows one column: the list, or whatever was opened from it.
  const view = !sas && (current.name === "list" || current.name === "lab") ? "list" : "main";

  // Back on the list with focus left on something that is gone (the conversation that was
  // closed, the contact that was removed): put it on the list's title.
  useEffect(() => {
    if (view !== "list" || document.activeElement !== document.body) return;
    document.querySelector<HTMLElement>('[data-testid="list-title"]')?.focus();
  }, [view]);

  return (
    <div className="app" data-view={view} data-route={current.name} data-testid="app">
      <div className="app__list">
        <ConversationList current={current} />
      </div>
      <main className="app__main">
        {sas
          ? <SasScreen sas={sas} />
          : current.name === "conversation"
          ? <Conversation key={current.peerId} peerId={current.peerId} />
          : current.name === "add"
          ? <AddContact />
          : current.name === "settings"
          ? <Settings />
          : <ConversationPlaceholder />}
      </main>
    </div>
  );
}

function Phases({ store }: { store: AppStore }) {
  const phase = store.phase.value;
  switch (phase.kind) {
    case "loading":
      return <Loading />;
    case "locked":
      return <Locked retryAtMs={phase.retryAtMs} />;
    case "first-run":
      return <FirstRun />;
    case "other-tab":
      return <OtherTab moved={phase.moved} />;
    case "failed":
      return <StartFailed reason={phase.reason} />;
    case "ready":
      return <Frame />;
  }
}

/** `lab` is the state lab's page, in development and test builds; production has none. */
export function App({ store, lab }: { store: AppStore; lab?: ReactNode }) {
  return (
    <StoreProvider value={store}>
      {lab !== undefined && route.value.name === "lab" ? <>{lab}</> : <Phases store={store} />}
      <CallLayer />
      <ToastHost />
      <Announcer />
    </StoreProvider>
  );
}
