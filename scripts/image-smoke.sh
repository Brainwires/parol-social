#!/usr/bin/env bash
# Smoke checks against a running relay image (the CI `image` job runs them; so can an operator
# after a deploy). Checks the landing page, the web app's shell, cache rules, security headers,
# MIME types, and that nginx reaches the relay.
#
# Usage: scripts/image-smoke.sh [BASE_URL]      (default http://127.0.0.1:8080)
set -euo pipefail

BASE="${1:-http://127.0.0.1:8080}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FAILED=0

CSP="default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self' wss: ws:; img-src 'self' data: blob:; media-src 'self' blob:; worker-src 'self'; object-src 'none'; base-uri 'self'; form-action 'none'; frame-ancestors 'none'"

fail() { echo "FAIL $*"; FAILED=1; }

# fetch PATH: headers to $TMP/h, body to $TMP/b, prints the status.
fetch() {
  curl -sS -o "$TMP/b" -D "$TMP/h" -w '%{http_code}' "$BASE$1"
}
header() { grep -i "^$1:" "$TMP/h" | head -n1 | cut -d: -f2- | sed 's/^ *//; s/\r$//'; }

expect_status() { # PATH STATUS...
  local path="$1"; shift
  local got; got="$(fetch "$path")"
  for want in "$@"; do [ "$got" = "$want" ] && { echo "ok   $path -> $got"; return 0; }; done
  fail "$path -> $got (want $*)"; return 1
}
expect_header() { # NAME VALUE (exact) for the last fetch
  local got; got="$(header "$1")"
  [ "$got" = "$2" ] || fail "$1: '$got' (want '$2')"
}
expect_security_headers() {
  expect_header Content-Security-Policy "$CSP"
  expect_header X-Content-Type-Options nosniff
  expect_header X-Frame-Options DENY
  expect_header Referrer-Policy no-referrer
}

# The landing page.
expect_status / 200 && expect_security_headers

# The web app's shell: CSP, revalidated on every use.
expect_status /pwa/ 200 && {
  expect_security_headers
  expect_header Cache-Control no-cache
  grep -q '<title>ParolNet</title>' "$TMP/b" || fail "/pwa/ is not the web app's shell"
}
cp "$TMP/b" "$TMP/index.html"
expect_status /pwa 308

# A content-hashed asset named by the shell: cached for a year, security headers kept.
asset="$(grep -oE '\./assets/index-[A-Z0-9]{8}\.js' "$TMP/index.html" | head -n1 | cut -c3-)"
if [ -z "$asset" ]; then
  fail "no hashed entry script in /pwa/index.html"
else
  expect_status "/pwa/$asset" 200 && {
    expect_security_headers
    expect_header Cache-Control "public, max-age=31536000, immutable"
  }
fi

# The service worker: never cached by HTTP.
expect_status /pwa/sw.js 200 && {
  expect_security_headers
  expect_header Cache-Control no-cache
  expect_header Service-Worker-Allowed /pwa/
}

# The manifest, unhashed: no-cache, its own MIME type.
expect_status /pwa/manifest.webmanifest 200 && {
  expect_header Cache-Control no-cache
  expect_header Content-Type application/manifest+json
}

# The wasm core: its manifest names the module, served as application/wasm, immutable.
expect_status /pwa/wasm/manifest.json 200 && expect_header Cache-Control no-cache
wasm="$(grep -oE 'parolnet_wasm_bg-[0-9a-f]{8}\.wasm' "$TMP/b" | head -n1)"
if [ -z "$wasm" ]; then
  fail "no module named in /pwa/wasm/manifest.json"
else
  expect_status "/pwa/wasm/$wasm" 200 && {
    expect_header Content-Type application/wasm
    expect_header Cache-Control "public, max-age=31536000, immutable"
  }
  # Compressed on the fly for a client that accepts gzip.
  enc="$(curl -sS -o /dev/null -D - -H 'Accept-Encoding: gzip' "$BASE/pwa/wasm/$wasm" \
    | grep -i '^content-encoding:' | tr -d '\r' | cut -d' ' -f2)"
  [ "$enc" = gzip ] || fail "/pwa/wasm/$wasm not gzip-encoded (got '$enc')"
fi

# A missing file under /pwa/ is a 404, not the shell.
expect_status /pwa/no-such-file.js 404

# The relay behind nginx: ICE servers as JSON, the WebSocket endpoint, health.
expect_status /turn-credentials 200 && {
  case "$(header Content-Type)" in application/json*) ;; *) fail "/turn-credentials is not JSON";; esac
  echo "     $(head -c 200 "$TMP/b")"
}
expect_status /health 200
# A plain GET (no upgrade) reaches the relay, which refuses it.
expect_status /ws 400 426

if [ "$FAILED" -ne 0 ]; then
  echo "smoke checks FAILED"
  exit 1
fi
echo "smoke checks passed"
