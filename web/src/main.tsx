// The entry Denext bundles (mode: "spa"). Stylesheets are imported here, once; each declares
// the same @layer order first, so the cascade does not depend on the order they are bundled in.
import { createRoot } from "denext/client";
import "./design/tokens.css";
import "./design/base.css";
import "./components/components.css";
import "./screens/screens.css";
import "./screens/lab.css";
import { App } from "./app.tsx";
import { registerServiceWorker } from "./platform/service-worker.ts";
import { loadWasm } from "./platform/wasm.ts";
import { startRouter } from "./router.ts";
import { createFakeStore } from "./state/fake.ts";

// Phase 1: the screens run on fake state. The real services replace this store later.
const store = createFakeStore();

startRouter();
const root = document.getElementById("root");
if (root) createRoot(root).render(<App store={store} />);

// After the first render: neither blocks the screen.
void loadWasm().catch(() => {
  // wasmStatus carries the failure; the device status line shows it.
});
void registerServiceWorker();
