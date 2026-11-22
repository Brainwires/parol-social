# ParolNet Distribution Server

Static HTML landing pages for the ParolNet web app (`web/`, served at `/pwa/`): what ParolNet is, how to add it to a device, and what to know before relying on it.

## Files

- **`index.html`** (+ `index.css`, `index.js`) — The front page: one line on what ParolNet is, the "Open ParolNet" button, install steps per platform (`index.js` puts the steps for the visitor's device first; without it all of them show), the facts to know before relying on it, and the licence and source link.
- **`install.html`** (+ `install.css`, and `index.css`) — Kept so old links keep working: says the install steps are on the front page and links to `/` and `/pwa/`.
- **`nginx.conf`** — Nginx configuration (signaling-only profile): the web app under `/pwa/` with its cache rules, WASM and manifest MIME types, the service worker, gzip, and the relay endpoints.
- **`nginx.relay.conf`** — The same for the relay profile (`SIGNALING_ONLY=0`); the entrypoint installs it in place of `nginx.conf`.
- **`nginx-security-headers.conf`** — The security headers (the Content-Security-Policy among them), included by both configs in the server block and in every location that sets headers of its own.
- **`entrypoint.sh`** — Starts the relay and nginx.

## Hosting with Docker (Recommended)

A `Dockerfile` and `docker-compose.yml` are provided at the project root.

### Using Docker Compose

```bash
# Build and run
docker compose up -d

# View at http://localhost:1411
# Stop
docker compose down
```

The compose file is the parol.social deployment: it sets `RELAY_PUBLIC_NAMES=parol.social`, the name clients dial the relay under. A client signs its registration for the name it dialed and the relay refuses any other (PNP-001 §10.7), so to use the app on a local run of the compose file start it with `RELAY_PUBLIC_NAMES=localhost:1411 docker compose up -d`. On your own host set it to your host name. (`docker run` below sets no name, and a relay without one accepts loopback clients, so `http://localhost:1411` works there as it is.)

### Using Docker directly

```bash
docker build -t parolnet .
docker run -d -p 1411:80 parolnet
```

The image builds the relay and the web app from source (multi-stage `Dockerfile`: no host-side build step) and runs them on `nginx:alpine`: the distribution landing page at `/`, the web app's static export (`web/out`) at `/pwa/`, the relay behind nginx at the same origin (`/ws`, `/turn-credentials`, ...). Deploy or update with `git pull && docker compose up -d --build`; check a running container with `scripts/image-smoke.sh http://127.0.0.1:1411`.

The legacy PWA in `pwa/` is no longer part of the image. The new app's service worker at `/pwa/sw.js` takes over from the old one at the same scope and deletes its caches.

## Alternative Hosting Options

These are plain static HTML files with zero dependencies. Any static file server works.

- **Nginx / Apache / Caddy** — Drop the files in your document root. Make sure WASM files are served with the `application/wasm` MIME type (the provided `nginx.conf` handles this). For the web app itself see `web/nginx.example.conf`.
- **CDN** — Cloudflare Pages, Netlify, GitHub Pages, Vercel. Push and deploy.
- **S3 / R2** — Upload as a static website.
- **IPFS** — Pin the directory for censorship-resistant hosting.
- **Tor Hidden Service** — Host as a `.onion` site for anonymous access.

## Important Notes

- **WASM MIME type** — WASM files must be served with `Content-Type: application/wasm`. The included `nginx.conf` handles this. If using a different server, configure it accordingly.
- **Service Worker requires HTTPS** — The Service Worker will only register over HTTPS or on `localhost`. For production deployments, use HTTPS. For local development, `http://localhost:1411` works fine.

## Directory Structure

The Docker setup serves files at these paths:

```
/                  → server/index.html  (distribution landing page)
/install.html      → server/install.html (points to / and /pwa/)
/pwa/              → web/out/           (the web app, built in the image)
/pwa/index.html    → web/out/index.html (app shell; no-cache)
/pwa/sw.js         → web/out/sw.js      (service worker; no-cache)
/pwa/assets/       → web/out/assets/    (content-hashed bundle; cached for a year)
/pwa/wasm/         → web/out/wasm/      (content-hashed wasm core + manifest.json)
```

## Design Decisions

- **No JavaScript frameworks** — Pure static HTML with a stylesheet and (for `index.html`) a small script beside it. No inline script or style: the pages run under the same Content-Security-Policy as the web app.
- **No external dependencies** — Static assets can be opened from many environments. Full PWA behavior, including Service Worker install and offline caching, requires HTTPS or `localhost`; `file://` is limited-use only.
- **The app's design** — The palette and type of the web app (`web/src/design/tokens.json`, `docs/ux/web-app.md`): ink on cool paper, light and dark from the system, plain words, sentence case. The font is the app's own Atkinson Hyperlegible Next under `/pwa/fonts/` (versioned file names), with a system fallback.
- **Mobile-first** — Responsive down to 360px, a reading width of 680px on wider screens.
