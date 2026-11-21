// The entry of development and test builds (PAROLNET_BUILD=test, see denext.config.ts): the app, plus the state
// lab under #/lab and the `window.__parolnetTest` hooks the interop driver reads
// (docs/web-port/interop.md §11.4). The production entry is src/main.tsx.
import "./screens/lab.css";
import { installTestHooks, type ParolnetTestHooks } from "./engine/test-hooks.ts";
import { Lab } from "./screens/Lab.tsx";
import { startApp } from "./start.tsx";
import { createFakeStore } from "./state/fake.ts";

const fake = createFakeStore();
let hooks: ParolnetTestHooks | null = null;

void startApp({
  lab: { store: fake, page: <Lab controls={fake} /> },
  onEngine(engine) {
    hooks?.uninstall();
    hooks = engine ? installTestHooks(engine) : null;
  },
});
