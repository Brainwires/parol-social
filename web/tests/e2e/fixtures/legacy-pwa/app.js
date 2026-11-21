// Stands in for the previous PWA's page (pwa/src/boot.js): registers sw.js at the same scope
// and, like it, tells a waiting worker to take over.
navigator.serviceWorker.register("sw.js").then((reg) => {
  window.__legacyRegistration = reg;
  if (reg.waiting) reg.waiting.postMessage("skipWaiting");
});
