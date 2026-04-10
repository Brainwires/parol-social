#!/bin/bash
# Build ParolNet PWA
#
# This script:
# 1. Builds the WASM module with wasm-pack
# 2. Copies the output to pwa/pkg/
# 3. The result is a fully self-contained PWA that can be:
#    - Served from any static file host
#    - Distributed as a ZIP file
#    - Hosted on IPFS
#    - Served from a Tor hidden service
#    - Placed on a USB drive
#
# After first load, the PWA works entirely offline.
# If the source site disappears, installed copies keep working.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "Building ParolNet WASM module..."
cd "$PROJECT_ROOT"

# Check if wasm-pack is installed
if ! command -v wasm-pack &> /dev/null; then
    echo "wasm-pack not found. Install it with:"
    echo "  curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh"
    exit 1
fi

# Build WASM with wasm-pack (web target for ES modules)
wasm-pack build crates/parolnet-wasm \
    --target web \
    --out-dir "$SCRIPT_DIR/pkg" \
    --release

# Remove unnecessary files from pkg
rm -f "$SCRIPT_DIR/pkg/.gitignore"
rm -f "$SCRIPT_DIR/pkg/package.json"
rm -f "$SCRIPT_DIR/pkg/README.md"

echo ""
echo "PWA built successfully!"
echo ""
echo "Files in $SCRIPT_DIR/:"
ls -la "$SCRIPT_DIR/"
echo ""
echo "To serve locally:"
echo "  cd $SCRIPT_DIR && python3 -m http.server 8080"
echo ""
echo "To distribute:"
echo "  1. Upload the entire pwa/ directory to any static host"
echo "  2. Or zip it: cd $SCRIPT_DIR && zip -r parolnet-pwa.zip ."
echo "  3. Or IPFS: ipfs add -r $SCRIPT_DIR"
echo ""
echo "After first visit, the app works entirely offline."
echo "If the host disappears, installed copies keep working."
