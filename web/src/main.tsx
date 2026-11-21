// The production entry Denext bundles (mode: "spa"): the app on the engine, nothing else.
// The state lab and the test hooks are in src/main.dev.tsx, which this build never imports.
import { startApp } from "./start.tsx";

void startApp();
