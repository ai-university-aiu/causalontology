#!/usr/bin/env bash
# Run the causalontology-zig conformance suite (all 137 checks; 38 of them are
# driven by the frozen shared vector files, the other 99 are written here).
#
# Usable locally and in CI from any working directory:
#   bash bindings/zig/run_conformance.sh
#
# It behaves identically inside a package fetched with `zig fetch`: that tree
# carries the 137 vectors and the specification, and the schemas are compiled
# into the library, so a run there proves the bytes the consumer received and
# never reaches for a checkout.
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

# The runner locates conformance/vectors by walking up from the working
# directory, so run it from the root of this tree. The schemas are not read
# from this tree at all - they are compiled into the library - but the runner
# does compare the compiled-in copies against ROOT/spec/schema when that
# directory exists, and fails on any drift.
cd "$ROOT"
exec "$ZIG" run bindings/zig/conformance.zig
