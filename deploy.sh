#!/bin/bash
# ParolNet Deploy Script
# Builds WASM, rebuilds Docker container, restarts service
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== ParolNet Deploy ==="
echo ""

# Step 1: Build WASM
echo "[1/2] Building WASM module..."
if ! command -v wasm-pack &> /dev/null; then
    echo "ERROR: wasm-pack not found. Install: curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh"
    exit 1
fi

wasm-pack build crates/parolnet-wasm \
    --target web \
    --out-dir "$SCRIPT_DIR/pwa/pkg" \
    --release

# Clean wasm-pack extras
rm -f pwa/pkg/.gitignore pwa/pkg/package.json pwa/pkg/README.md

echo "WASM built: $(du -sh pwa/pkg/parolnet_wasm_bg.wasm | cut -f1)"
echo ""

# Step 2: Rebuild Docker image (multi-stage: compiles relay server + bundles with nginx)
echo "[2/2] Rebuilding Docker image and restarting..."
docker compose build --no-cache

# Restart container
docker compose down
docker compose up -d

# Cleanup dangling images and build cache
echo "Cleaning up old Docker artifacts..."
docker image prune -f
docker builder prune -f

echo ""
echo "=== Deploy complete ==="
echo "Site: http://localhost:1411"
echo ""
