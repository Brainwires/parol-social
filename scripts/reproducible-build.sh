#!/usr/bin/env bash
set -euo pipefail

# Reproducible Build Script for ParolNet
# Builds artifacts in Docker and verifies reproducibility.
#
# Usage:
#   ./scripts/reproducible-build.sh          # Build once, output checksums
#   ./scripts/reproducible-build.sh --verify  # Build twice, compare checksums

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$PROJECT_DIR/dist"
IMAGE_NAME="parolnet-reproducible-build"

echo "=== ParolNet Reproducible Build ==="
echo "Project: $PROJECT_DIR"
echo ""

# Clean dist directory
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

# Build Docker image
echo "Building Docker image..."
docker build \
    -f "$PROJECT_DIR/Dockerfile.release" \
    -t "$IMAGE_NAME" \
    --no-cache \
    "$PROJECT_DIR"

# Extract artifacts
echo "Extracting artifacts..."
docker run --rm -v "$DIST_DIR:/out" "$IMAGE_NAME"

echo ""
echo "=== Build Checksums ==="
cat "$DIST_DIR/SHA256SUMS"
echo ""

if [ "${1:-}" = "--verify" ]; then
    echo "=== Verification Build ==="
    echo "Building again to verify reproducibility..."

    VERIFY_DIR="$PROJECT_DIR/dist-verify"
    rm -rf "$VERIFY_DIR"
    mkdir -p "$VERIFY_DIR"

    # Rebuild
    docker build \
        -f "$PROJECT_DIR/Dockerfile.release" \
        -t "${IMAGE_NAME}-verify" \
        --no-cache \
        "$PROJECT_DIR"

    docker run --rm -v "$VERIFY_DIR:/out" "${IMAGE_NAME}-verify"

    echo ""
    echo "=== Comparing Checksums ==="
    if diff "$DIST_DIR/SHA256SUMS" "$VERIFY_DIR/SHA256SUMS" > /dev/null 2>&1; then
        echo "PASS: Both builds produced identical checksums."
        echo ""
        cat "$DIST_DIR/SHA256SUMS"
    else
        echo "FAIL: Checksums differ between builds!"
        echo ""
        echo "Build 1:"
        cat "$DIST_DIR/SHA256SUMS"
        echo ""
        echo "Build 2:"
        cat "$VERIFY_DIR/SHA256SUMS"
        exit 1
    fi

    # Clean up verification artifacts
    rm -rf "$VERIFY_DIR"
    docker rmi "${IMAGE_NAME}-verify" 2>/dev/null || true
fi

echo ""
echo "Artifacts in: $DIST_DIR/"
echo "Done."
