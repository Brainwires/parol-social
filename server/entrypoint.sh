#!/bin/sh
# Start relay server in background
echo "Starting ParolNet relay on port 9000..."
/usr/local/bin/parolnet-relay &

# Start nginx in foreground
echo "Starting nginx..."
exec nginx -g 'daemon off;'
