# syntax=docker/dockerfile:1
#
# ParolNet relay image: the relay binary behind nginx, which also serves the landing page (/)
# and the web app (/pwa/). Everything is built from source here; nothing has to be prebuilt on
# the host. `docker compose up -d --build` is the whole deployment.
#
# Stages:
#   relay-builder  the relay binary (musl, static)
#   web-tools      Rust (from rust-toolchain.toml) + the wasm32 target, wasm-pack and Denext
#   web            the wasm core (web/scripts/build-wasm.ts) and the static export (web/out)
#   (final)        nginx:alpine with the relay, the nginx configs, the landing pages, web/out
#
# The Rust stages copy only the Rust workspace, so a change under web/ does not rebuild Rust,
# and the web app's dependencies are fetched in a layer of their own before its sources.

# ── Stage 1: the relay binary ────────────────────────────────────────────────────────────────
FROM rust:1.92-alpine AS relay-builder
RUN apk add --no-cache musl-dev pkgconfig
WORKDIR /build
COPY rust-toolchain.toml Cargo.toml Cargo.lock ./
COPY .cargo .cargo
COPY crates crates
COPY xtask xtask
# Cache mounts keep the registry and the incremental target dir between local builds; the
# binary is copied out of the cached target dir in the same step.
RUN --mount=type=cache,id=pn-relay-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=pn-relay-cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=pn-relay-target,target=/build/target \
    cargo build --release --locked -p parolnet-relay-server --features analytics \
    && cp target/release/parolnet-relay /parolnet-relay

# ── Stage 2: the web toolchain ───────────────────────────────────────────────────────────────
# Debian (glibc), not Alpine: Denext ships prebuilt binaries for *-unknown-linux-gnu only
# (its install script has no musl target).
FROM rust:1.92-bookworm AS web-tools
ARG TARGETARCH
# Versions: wasm-pack is the release CI installs (rustwasm's installer pins v0.13.1); Denext is
# the version web/deno.lock resolves (jsr:@denext/denext 4.21.0), and `denext runtime install`
# installs the runtime release that Denext version bundles.
ARG WASM_PACK_VERSION=0.13.1
ARG DENEXT_VERSION=v4.21.0
ENV DENEXT_INSTALL=/opt/denext \
    DENO_DIR=/opt/deno-cache \
    PATH=/opt/denext/bin:$PATH
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) arch=x86_64 ;; \
      arm64) arch=aarch64 ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    name="wasm-pack-v${WASM_PACK_VERSION}-${arch}-unknown-linux-musl"; \
    curl -fsSL "https://github.com/rustwasm/wasm-pack/releases/download/v${WASM_PACK_VERSION}/${name}.tar.gz" \
      | tar xz -C /tmp; \
    install -m 0755 "/tmp/${name}/wasm-pack" /usr/local/bin/wasm-pack; \
    rm -rf "/tmp/${name}"; \
    wasm-pack --version
RUN set -eu; \
    curl -fsSL https://denext.dev/install.sh \
      | DENEXT_VERSION="$DENEXT_VERSION" DENEXT_NO_RUNTIME=1 DENEXT_MODIFY_PATH=0 sh; \
    denext runtime install; \
    denext --version
WORKDIR /src
# The toolchain rust-toolchain.toml names, with its wasm32 target.
COPY rust-toolchain.toml ./
RUN rustup toolchain install && rustup target list --installed

# ── Stage 3: the web app ─────────────────────────────────────────────────────────────────────
FROM web-tools AS web
# The web app's dependencies (JSR), in their own layer: only deno.json / deno.lock invalidate it.
COPY web/deno.json web/deno.lock web/
RUN cd web && denext deno install --frozen

# The wasm core. Its inputs are the Rust workspace and the build script, not the app's sources.
# AUTHORITY_PUBKEYS (comma-separated 64-char hex Ed25519 keys) and AUTHORITY_THRESHOLD reach
# crates/parolnet-wasm/build.rs through the environment; empty keys mean the dev placeholder
# keys.
COPY Cargo.toml Cargo.lock ./
COPY .cargo .cargo
COPY crates crates
COPY xtask xtask
COPY web/scripts/build-wasm.ts web/scripts/build-wasm.ts
ARG AUTHORITY_PUBKEYS=""
ARG AUTHORITY_THRESHOLD=2
RUN --mount=type=cache,id=pn-web-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=pn-web-cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=pn-web-target,target=/src/target \
    --mount=type=cache,id=pn-web-wasm-pack,target=/root/.cache/.wasm-pack \
    cd web \
    && AUTHORITY_PUBKEYS="$AUTHORITY_PUBKEYS" AUTHORITY_THRESHOLD="$AUTHORITY_THRESHOLD" \
       denext task build-wasm

# The app itself: the production export (tokens, `denext export`, scripts/postexport.ts).
COPY web/ web/
RUN cd web && denext task build

# ── Stage 4: runtime (nginx + relay) ─────────────────────────────────────────────────────────
# No TURN server: the default relay profile is signaling-only (PNP-001 §10.5) and carries no
# user traffic. Relay-profile operators who want TURN run their own TURN server and set
# SIGNALING_ONLY=0, TURN_SECRET and TURN_URIS (see ops/turn.md).
FROM nginx:alpine

# Nginx config (signaling-only profile). The relay-profile config is kept beside it; the
# entrypoint installs it when SIGNALING_ONLY=0. Both include the shared security headers.
COPY server/nginx.conf /etc/nginx/conf.d/default.conf
COPY server/nginx.relay.conf /etc/nginx/parolnet-relay.conf
COPY server/nginx-security-headers.conf /etc/nginx/snippets/parolnet-security-headers.conf
# Abuse log directory and the (possibly empty) fail2ban ban list directory
# that the nginx configs include; see ops/fail2ban.md.
RUN mkdir -p /var/log/nginx/parolnet /etc/nginx/banned

# Static files: the landing pages, and the web app's export (web/out only).
COPY server/index.html server/index.css server/index.js server/install.html server/install.css \
     /usr/share/nginx/html/
COPY --from=web /src/web/out/ /usr/share/nginx/html/pwa/

# Build metadata, baked into the image's environment and printed by the entrypoint at startup.
# (The web app's About screen shows the wasm core's crate version; it reads no build metadata.)
ARG BUILD_DATE=""
ARG BUILD_COMMIT=""
ARG BUILD_VERSION=""
ARG DEV_MODE=false
ENV PAROLNET_BUILD_DATE="$BUILD_DATE" \
    PAROLNET_BUILD_COMMIT="$BUILD_COMMIT" \
    PAROLNET_BUILD_VERSION="$BUILD_VERSION" \
    PAROLNET_DEV_MODE="$DEV_MODE"

# Relay binary
COPY --from=relay-builder /parolnet-relay /usr/local/bin/parolnet-relay

# Entrypoint script
COPY server/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80

# RELAY_PUBLIC_NAMES (comma-separated host or host:port, no port = 443) is the name clients dial
# this relay under. A client signs its registration for the name it dialed and the relay refuses
# any other (PNP-001 §10.7). It has no default here on purpose: without it the relay registers
# only clients that dialed a loopback address (a local `docker run -p 1411:80`), and a public
# deployment has to say what it is called: `-e RELAY_PUBLIC_NAMES=relay.example.org`, or the
# `environment:` entry in docker-compose.yml.

# Persistent relay identity — mount this as a volume to keep the Ed25519
# signing key stable across container restarts. On first boot the relay
# generates /data/relay.key (mode 0600); subsequent boots load it.
# RELAY_KEY_FILE may override the path; RELAY_SECRET_KEY (hex) wins over both
# and never touches disk (useful for CI / one-shot runs).
VOLUME /data

CMD ["/entrypoint.sh"]
