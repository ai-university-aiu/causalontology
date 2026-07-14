#!/usr/bin/env bash
# Compile and run the causalontology-kotlin conformance suite with Kotlin/Native.
#
# Uses kotlinc-native from PATH when available; otherwise downloads the pinned
# 2.0.20 prebuilt compiler to a temporary directory. The compiler is a JVM
# application, so a JDK must be present (JAVA_HOME or java on PATH); the first
# compile also downloads the Kotlin/Native LLVM dependencies (~1-2 GB).
#
# The binary reads conformance/vectors/ and spec/schema/ relative to the
# repository root, so it is executed from there (CAUSALONTOLOGY_ROOT overrides).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

KN_VERSION="2.0.20"
KN_NAME="kotlin-native-prebuilt-linux-x86_64-${KN_VERSION}"
KN_URL="https://github.com/JetBrains/kotlin/releases/download/v${KN_VERSION}/${KN_NAME}.tar.gz"

if command -v kotlinc-native >/dev/null 2>&1; then
    KOTLINC="kotlinc-native"
else
    TMPBASE="${TMPDIR:-/tmp}"
    KN_DIR="${TMPBASE}/${KN_NAME}"
    if [ ! -x "${KN_DIR}/bin/kotlinc-native" ]; then
        echo "kotlinc-native not on PATH; downloading the pinned ${KN_VERSION} prebuilt ..."
        curl -sL -o "${TMPBASE}/${KN_NAME}.tar.gz" "${KN_URL}"
        tar xzf "${TMPBASE}/${KN_NAME}.tar.gz" -C "${TMPBASE}"
    fi
    KOTLINC="${KN_DIR}/bin/kotlinc-native"
fi

"${KOTLINC}" "${HERE}"/src/*.kt -e org.causalontology.main -o /tmp/co_conformance

# kotlinc-native names the produced executable with a .kexe suffix.
BIN="/tmp/co_conformance"
[ -x "${BIN}" ] || BIN="/tmp/co_conformance.kexe"

cd "${ROOT}"
exec "${BIN}"
