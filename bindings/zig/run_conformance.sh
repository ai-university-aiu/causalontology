#!/usr/bin/env bash
# Run the causalontology-zig conformance suite (all 107 frozen vectors).
#
# Usable locally and in CI from any working directory:
#   bash bindings/zig/run_conformance.sh
#
# If no zig is on PATH, the pinned Zig 0.13.0 release tarball is downloaded
# to a temp-dir cache (no root required) and used directly.
set -euo pipefail

# The repository root is two levels above this script.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

ZIG_VERSION="0.13.0"
ZIG_DIST="zig-linux-x86_64-${ZIG_VERSION}"

if command -v zig >/dev/null 2>&1; then
    ZIG="zig"
else
    CACHE="${TMPDIR:-/tmp}/causalontology-zig-toolchain"
    ZIG="${CACHE}/${ZIG_DIST}/zig"
    if [ ! -x "$ZIG" ]; then
        echo "zig not on PATH; fetching pinned ${ZIG_DIST} ..."
        mkdir -p "$CACHE"
        curl -sL "https://ziglang.org/download/${ZIG_VERSION}/${ZIG_DIST}.tar.xz" \
            -o "${CACHE}/${ZIG_DIST}.tar.xz"
        tar -xJf "${CACHE}/${ZIG_DIST}.tar.xz" -C "$CACHE"
    fi
fi

# The runner locates conformance/vectors and spec/schema by walking up from
# the working directory, so run it from the repository root.
cd "$ROOT"
exec "$ZIG" run bindings/zig/conformance.zig
