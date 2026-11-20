# Stage 1: Build relay server binary
FROM rust:1.92-alpine AS builder
RUN apk add --no-cache musl-dev pkgconfig
WORKDIR /build
COPY . .
RUN cargo build --release -p parolnet-relay-server --features analytics

# Stage 2: Runtime with nginx + relay. No TURN server: the default relay
# profile is signaling-only (PNP-001 §10.5) and carries no user traffic.
# Relay-profile operators who want TURN run their own TURN server and set
# SIGNALING_ONLY=0, TURN_SECRET and TURN_URIS (see ops/turn.md).
FROM nginx:alpine

# Nginx config (signaling-only profile). The relay-profile config is kept
# beside it; the entrypoint installs it when SIGNALING_ONLY=0.
COPY server/nginx.conf /etc/nginx/conf.d/default.conf
COPY server/nginx.relay.conf /etc/nginx/parolnet-relay.conf
# Abuse log directory and the (possibly empty) fail2ban ban list directory
# that the nginx configs include; see ops/fail2ban.md.
RUN mkdir -p /var/log/nginx/parolnet /etc/nginx/banned

# Static files
COPY server/index.html /usr/share/nginx/html/index.html
COPY server/install.html /usr/share/nginx/html/install.html
COPY pwa/ /usr/share/nginx/html/pwa/

# Bake build metadata into image ENV so entrypoint can write build-info.js at startup.
# DEV_MODE defaults to false; override with --build-arg DEV_MODE=true or env var at runtime.
ARG BUILD_DATE=""
ARG BUILD_COMMIT=""
ARG BUILD_VERSION=""
ARG DEV_MODE=false
ENV PAROLNET_BUILD_DATE="$BUILD_DATE" \
    PAROLNET_BUILD_COMMIT="$BUILD_COMMIT" \
    PAROLNET_BUILD_VERSION="$BUILD_VERSION" \
    PAROLNET_DEV_MODE="$DEV_MODE"

# Relay binary
COPY --from=builder /build/target/release/parolnet-relay /usr/local/bin/parolnet-relay

# Entrypoint script
COPY server/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80

# Persistent relay identity — mount this as a volume to keep the Ed25519
# signing key stable across container restarts. On first boot the relay
# generates /data/relay.key (mode 0600); subsequent boots load it.
# RELAY_KEY_FILE may override the path; RELAY_SECRET_KEY (hex) wins over both
# and never touches disk (useful for CI / one-shot runs).
VOLUME /data

CMD ["/entrypoint.sh"]
