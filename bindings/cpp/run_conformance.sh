#!/usr/bin/env bash
# run_conformance.sh - compile and run the causalontology-cpp conformance
# suite. Zero dependencies: g++ (C++17) and a POSIX shell are all it needs.
set -euo pipefail

# The directory this script lives in (bindings/cpp) and the repository root.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

# Build into a throwaway temp directory; clean it up on exit.
BUILD="$(mktemp -d "${TMPDIR:-/tmp}/causalontology-cpp.XXXXXX")"
trap 'rm -rf "$BUILD"' EXIT

g++ -std=c++17 -O2 -Wall -Wextra \
    -o "$BUILD/conformance" \
    "$HERE"/src/*.cpp "$HERE"/conformance.cpp

CAUSALONTOLOGY_ROOT="$ROOT" "$BUILD/conformance"
