// A tiny static server that hosts an export the way production does: under /pwa/, with the
// Content-Security-Policy as an HTTP header, an index fallback and the cache headers of
// web/nginx.example.conf. The browser tests start it in-process (and stop it, to go offline);
// `node static-server.mjs [dir] [port]` serves web/out by hand.
import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { createServer } from "node:http";
import { extname, join, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

export const BASE_PATH = "/pwa/";

/** The policy the app must run under. Keep in step with web/nginx.example.conf. */
export const CSP = [
  "default-src 'self'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "style-src 'self'",
  "connect-src 'self' wss: ws:",
  "img-src 'self' data: blob:",
  "media-src 'self' blob:",
  "worker-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join("; ");

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".webmanifest": "application/manifest+json; charset=utf-8",
  ".wasm": "application/wasm",
  ".woff2": "font/woff2",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".txt": "text/plain; charset=utf-8",
};

/** Content-hashed or versioned names: cache forever. Everything else: revalidate. */
function cacheControl(path) {
  return /^(assets\/.+-[A-Z0-9]{8}\.[a-z0-9]+|wasm\/.+-[0-9a-f]{8}\.(js|wasm)|fonts\/.+\.woff2)$/
      .test(path)
    ? "public, max-age=31536000, immutable"
    : "no-cache";
}

async function isFile(path) {
  try {
    return (await stat(path)).isFile();
  } catch {
    return false;
  }
}

/**
 * Starts the server. `root` can be swapped while it runs (`setRoot`) to stand in for a deploy.
 * Returns { origin, url, setRoot, close }.
 */
export async function startServer({ root, port = 0 }) {
  let current = resolve(root);
  const server = createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://localhost");
    if (url.pathname === BASE_PATH.slice(0, -1)) {
      response.writeHead(308, { location: BASE_PATH }).end();
      return;
    }
    if (!url.pathname.startsWith(BASE_PATH)) {
      response.writeHead(404, { "content-type": "text/plain" }).end("not found");
      return;
    }
    let relative = normalize(decodeURIComponent(url.pathname.slice(BASE_PATH.length)));
    if (relative === "." || relative === "") relative = "index.html";
    let file = join(current, relative);
    if (!file.startsWith(current + sep)) {
      response.writeHead(403).end();
      return;
    }
    if (!(await isFile(file))) {
      // Index fallback for navigations; a missing file with an extension is a real 404.
      if (extname(relative) !== "") {
        response.writeHead(404, { "content-type": "text/plain" }).end("not found");
        return;
      }
      relative = "index.html";
      file = join(current, relative);
    }
    response.writeHead(200, {
      "content-type": TYPES[extname(file)] ?? "application/octet-stream",
      "cache-control": cacheControl(relative.split(sep).join("/")),
      "content-security-policy": CSP,
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
      ...(relative === "sw.js" ? { "service-worker-allowed": BASE_PATH } : {}),
    });
    if (request.method === "HEAD") response.end();
    else createReadStream(file).pipe(response);
  });
  await new Promise((done) => server.listen(port, "127.0.0.1", done));
  const origin = `http://127.0.0.1:${server.address().port}`;
  return {
    origin,
    url: origin + BASE_PATH,
    setRoot(next) {
      current = resolve(next);
    },
    close() {
      server.closeAllConnections();
      return new Promise((done) => server.close(done));
    },
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const root = process.argv[2] ?? fileURLToPath(new URL("../../out", import.meta.url));
  const server = await startServer({ root, port: Number(process.argv[3] ?? 8787) });
  console.log(`serving ${root} at ${server.url}`);
}
