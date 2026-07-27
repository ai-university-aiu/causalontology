#!/usr/bin/env bash
# Build the causalontology-kotlin library from src/ into a single jar and drop
# it into a Maven-local repository layout, OUTSIDE the repository tree, so the
# conformance runner can be pointed at a real installed artifact.
#
# What this jar is, precisely. The registry artifact for this binding is the
# Kotlin/Native klib that build.gradle.kts produces and publishes as
# io.github.ai-university-aiu:causalontology-kotlin-linuxx64:4.0.0. A klib
# cannot be executed by the JVM conformance runner, so this script builds the
# same library sources - byte for byte the same src/*.kt, including the
# generated src/SpecSchemas.kt - with kotlinc-jvm instead. It is a faithful
# stand-in for installed-mode testing, not itself a published artifact; do not
# read a pass here as a statement about a jar on Maven Central.
#
# The conformance runner (src/Conformance.kt) is deliberately NOT compiled in:
# the jar carries the library only. The twenty-one JSON Schemas travel inside
# it as the compiled-in string constants of src/SpecSchemas.kt, so it validates
# objects with no repository checkout and no CAUSALONTOLOGY_SPEC on the
# environment - the same property the klib has, and the whole point of the
# vendoring.
#
# To check the klib itself carries the schemas:
#   gradle build   # writes build/classes/kotlin/linuxX64/main/klib/*.klib
#   then confirm each spec/schema/*.schema.json appears verbatim in the klib's
#   default/ir/strings.knt string table, or link a Kotlin/Native consumer
#   against the klib with kotlinc-native -l and call Schema.validateSchema with
#   CAUSALONTOLOGY_SPEC unset from outside the checkout.
#
# Usage:  tools/build_jar.sh [install-directory]
# Default install directory:
#   ~/.m2/repository/io/github/ai-university-aiu/causalontology-kotlin/4.0.0
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
KOTLIN="$(cd "${HERE}/.." && pwd)"
VERSION="4.0.0"
DEST="${1:-${HOME}/.m2/repository/io/github/ai-university-aiu/causalontology-kotlin/${VERSION}}"

SRCS=()
for f in "${KOTLIN}"/src/*.kt; do
    case "$(basename "${f}")" in
        Conformance.kt) continue ;;
    esac
    SRCS+=("${f}")
done

if [ ! -f "${KOTLIN}/src/SpecSchemas.kt" ]; then
    echo "src/SpecSchemas.kt is missing - generate it with:" >&2
    echo "  python3 ${HERE}/gen_spec_schemas.py" >&2
    exit 1
fi

mkdir -p "${DEST}"
JAR="${DEST}/causalontology-kotlin-${VERSION}.jar"
echo "compiling causalontology-kotlin ${VERSION} (kotlinc-jvm) ..."
kotlinc "${SRCS[@]}" -d "${JAR}"
echo "installed: ${JAR}"
