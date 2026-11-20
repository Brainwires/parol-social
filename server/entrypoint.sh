#!/bin/sh
# Write build-info.js at startup so DEV_MODE env var takes effect without a rebuild.
# DEV_MODE env var wins over the baked-in PAROLNET_DEV_MODE build arg.
_dev="${DEV_MODE:-${PAROLNET_DEV_MODE:-false}}"
echo "window.BUILD_INFO={date:'v${PAROLNET_BUILD_VERSION} ${PAROLNET_BUILD_COMMIT} ${PAROLNET_BUILD_DATE}',dev:${_dev}};" \
    > /usr/share/nginx/html/pwa/build-info.js
echo "Build: v${PAROLNET_BUILD_VERSION} ${PAROLNET_BUILD_COMMIT} | dev=${_dev}"

# The image runs no TURN server. The relay defaults to the signaling-only
# profile (SIGNALING_ONLY unset or 1): it serves STUN URIs from STUN_URIS and
# never relays or stores user content. SIGNALING_ONLY=0 selects the relay
# profile (mailbox, tokens, TURN credentials for an external TURN server).
_profile=$(printf '%s' "${SIGNALING_ONLY:-1}" | tr '[:upper:]' '[:lower:]' | tr -d ' ')
case "$_profile" in
    0|false|off|no)
        echo "Relay profile: relay (SIGNALING_ONLY=${SIGNALING_ONLY})"
        # Proxy the relay-profile endpoints too, unless the operator mounted
        # their own nginx config (read-only mount: the copy fails, theirs stays).
        cp /etc/nginx/parolnet-relay.conf /etc/nginx/conf.d/default.conf 2>/dev/null || true
        ;;
    *) echo "Relay profile: signaling-only" ;;
esac

# Start relay server in background
echo "Starting ParolNet relay on port 9000..."
/usr/local/bin/parolnet-relay &

# Start nginx in foreground
echo "Starting nginx..."
exec nginx -g 'daemon off;'
