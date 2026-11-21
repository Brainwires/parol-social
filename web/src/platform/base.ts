/**
 * Resolves a file of the export against the page's own URL. The app is hosted under a sub-path
 * (https://parol.social/pwa/) and routes in the URL hash, so the document URL is always the
 * directory the files sit in. Never write a root-absolute "/x" URL in the app.
 */
export function assetUrl(path: string): string {
  return new URL(path, document.baseURI).href;
}
