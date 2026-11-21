# ParolNet Distribution Server

Static HTML landing pages that serve as the distribution point for the ParolNet web app (`web/`, served at `/pwa/`). The pages are intentionally disguised as a calculator app listing to appear innocuous.

## Files

- **`index.html`** (+ `index.css`, `index.js`) — Full app-store-style landing page with app info, install button, instructions, and privacy note.
- **`install.html`** (+ `install.css`) — Minimal version with just icon, name, and install button. Use this for direct distribution links.
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
/install.html      → server/install.html (minimal install page)
/pwa/              → web/out/           (the web app, built in the image)
/pwa/index.html    → web/out/index.html (app shell; no-cache)
/pwa/sw.js         → web/out/sw.js      (service worker; no-cache)
/pwa/assets/       → web/out/assets/    (content-hashed bundle; cached for a year)
/pwa/wasm/         → web/out/wasm/      (content-hashed wasm core + manifest.json)
```

## Customization

To update the version or release date, edit the static values in `index.html`:

- **Version** — Search for `1.0.0`
- **Release date** — Search for `Apr 2026`
- **App size** — Search for `~2 MB`

## Design Decisions

- **No JavaScript frameworks** — Pure static HTML with a stylesheet and (for `index.html`) a small script beside it. No inline script or style: the pages run under the same Content-Security-Policy as the web app.
- **No external dependencies** — Static assets can be opened from many environments. Full PWA behavior, including Service Worker install and offline caching, requires HTTPS or `localhost`; `file://` is limited-use only.
- **Innocuous appearance** — The page presents as a calculator utility download. No references to encryption, messaging, security, or ParolNet.
- **Mobile-first** — Responsive layout, max-width 480px, looks good on phones.
