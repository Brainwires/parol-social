import { ToastHost } from "./components/Toast.tsx";
import { route } from "./router.ts";
import { Conversation, ConversationPlaceholder } from "./screens/Conversation.tsx";
import { ConversationList } from "./screens/ConversationList.tsx";
import { Lab } from "./screens/Lab.tsx";
import { StoreProvider } from "./state/context.ts";
import type { AppStore, FakeControls } from "./state/store.ts";

export function App({ store }: { store: AppStore & FakeControls }) {
  const current = route.value;
  return (
    <StoreProvider value={store}>
      {current.name === "lab"
        ? <Lab controls={store} />
        : (
          <div className="app" data-view={current.name} data-testid="app">
            <div className="app__list">
              <ConversationList current={current} />
            </div>
            <main className="app__main">
              {current.name === "conversation"
                ? <Conversation key={current.peerId} peerId={current.peerId} />
                : <ConversationPlaceholder />}
            </main>
          </div>
        )}
      <ToastHost />
    </StoreProvider>
  );
}
