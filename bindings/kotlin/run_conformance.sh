#!/usr/bin/env bash
# Compile and run the causalontology-kotlin conformance suite on Kotlin/JVM.
#
# Requires kotlinc (JVM) and a JDK on PATH (kotlinc-jvm 2.0.21, JDK 21 at the
# 2.0.0 conformance freeze).
#
# Two modes:
#
#   repository mode (default)
#       Compiles the sources under src/ and runs from the repository root, so
#       conformance/vectors/ and spec/schema/ resolve relatively
#       (CAUSALONTOLOGY_ROOT overrides). This is the historical behaviour and
#       is unchanged.
#
#   installed mode (CAUSALONTOLOGY_TEST_INSTALLED set)
#       Compiles ONLY the conformance runner and puts an already built and
#       installed artifact on the classpath, the way a real consumer resolves
#       the library. Nothing under src/ except the runner itself is compiled,
#       so repository code cannot silently stand in for the published package.
#       Build the artifact first with tools/build_jar.sh; override its location
#       with CAUSALONTOLOGY_KOTLIN_JAR. The runner prints
#       "binding under test: <path>" and refuses to run if that path is inside
#       the repository tree.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
VERSION="4.0.0"

if [ -n "${CAUSALONTOLOGY_TEST_INSTALLED:-}" ]; then
    DEFAULT_JAR="${HOME}/.m2/repository/io/github/ai-university-aiu/causalontology-kotlin/${VERSION}/causalontology-kotlin-${VERSION}.jar"
    JAR="${CAUSALONTOLOGY_KOTLIN_JAR:-$DEFAULT_JAR}"
    if [ ! -f "${JAR}" ]; then
        echo "CAUSALONTOLOGY_TEST_INSTALLED is set but no installed artifact was found at:" >&2
        echo "  ${JAR}" >&2
        echo "build and install one with: ${HERE}/tools/build_jar.sh" >&2
        exit 1
    fi
    JAR="$(cd "$(dirname "${JAR}")" && pwd)/$(basename "${JAR}")"
    case "${JAR}" in
        "${ROOT}"|"${ROOT}"/*)
            echo "the artifact under test is inside the repository tree: ${JAR}" >&2
            echo "installed mode must exercise a copy outside the repository." >&2
            exit 1
            ;;
    esac

    RUNNER="${TMPDIR:-/tmp}/co_conformance_kotlin_runner.jar"
    echo "compiling the conformance runner against the installed artifact ..."
    kotlinc "${HERE}/src/Conformance.kt" -cp "${JAR}" -include-runtime -d "${RUNNER}"

    export CAUSALONTOLOGY_REPO="${ROOT}"
    export CAUSALONTOLOGY_ROOT="${CAUSALONTOLOGY_ROOT:-${ROOT}}"
    exec java -cp "${JAR}:${RUNNER}" org.causalontology.ConformanceKt
fi

OUT="${TMPDIR:-/tmp}/co_conformance_kotlin.jar"

echo "compiling causalontology-kotlin (kotlinc-jvm) ..."
kotlinc "${HERE}"/src/*.kt -include-runtime -d "${OUT}"

cd "${ROOT}"
exec java -cp "${OUT}" org.causalontology.ConformanceKt
