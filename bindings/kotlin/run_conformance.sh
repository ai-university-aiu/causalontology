#!/usr/bin/env bash
# Compile and run the causalontology-kotlin conformance suite on Kotlin/JVM.
#
# Requires kotlinc (JVM) and a JDK on PATH (kotlinc-jvm 2.0.21, JDK 21 at the
# 2.0.0 conformance freeze). The compiled jar reads conformance/vectors/ and
# spec/schema/ relative to the repository root, so it is executed from there
# (CAUSALONTOLOGY_ROOT overrides).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

OUT="${TMPDIR:-/tmp}/co_conformance_kotlin.jar"

echo "compiling causalontology-kotlin (kotlinc-jvm) ..."
kotlinc "${HERE}"/src/*.kt -include-runtime -d "${OUT}"

cd "${ROOT}"
exec java -cp "${OUT}" org.causalontology.ConformanceKt
