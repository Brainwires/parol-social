# ParolNet Distribution Server

Static HTML landing pages that serve as the distribution point for the ParolNet PWA. The pages are intentionally disguised as a calculator app listing to appear innocuous.

## Files

- **`index.html`** — Full app-store-style landing page with app info, install button, instructions, and privacy note.
- **`install.html`** — Minimal version with just icon, name, and install button. Use this for direct distribution links.

## Hosting

These are plain static HTML files with zero dependencies. Host them anywhere:

- **Quick local test:** `python3 -m http.server 8080`
- **Nginx / Apache** — Drop the files in your document root.
- **Cloudflare Pages / GitHub Pages / Netlify** — Push and deploy.
- **S3 / R2** — Upload as static website.
- **IPFS** — Pin the directory.

## Directory Structure

The pages expect the PWA to be accessible at `../pwa/` relative to the server directory:

```
your-site/
├── server/
│   ├── index.html
│   ├── install.html
│   └── README.md
└── pwa/
    ├── index.html
    ├── manifest-calculator.json
    ├── icons/
    │   └── calc-*.svg
    └── ...
```

If your deployment structure is different, update the `href` in the install button(s) to point to the correct PWA path.

## Customization

To update the version or release date, edit the static values in `index.html`:

- **Version** — Search for `1.0.0`
- **Release date** — Search for `Apr 2026`
- **App size** — Search for `~2 MB`

## Design Decisions

- **No JavaScript frameworks** — Pure static HTML with inline CSS.
- **No external dependencies** — Works offline, works from `file://`, works anywhere.
- **Innocuous appearance** — The page presents as a calculator utility download. No references to encryption, messaging, security, or ParolNet.
- **Mobile-first** — Responsive layout, max-width 480px, looks good on phones.
