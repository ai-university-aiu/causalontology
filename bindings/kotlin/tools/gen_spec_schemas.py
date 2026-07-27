#!/usr/bin/env python3
"""Regenerate bindings/kotlin/src/SpecSchemas.kt from spec/schema/*.schema.json.

Kotlin/Native klibs cannot carry loose resource files, so the twenty-one
Causalontology JSON Schemas are vendored into the published package the same
way the Rust binding vendors them with include_str!: as string constants in a
generated Kotlin source file that is compiled into the artifact.

The generated text is byte-for-byte identical to the files in spec/schema.
Run this after any change to spec/schema; the Gradle `verifyBundledSchemas`
task and the conformance runner's drift guard both fail loudly if you forget.

Usage:  python3 bindings/kotlin/tools/gen_spec_schemas.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
KOTLIN = os.path.dirname(HERE)
ROOT = os.path.dirname(os.path.dirname(KOTLIN))
SPEC = os.path.join(ROOT, "spec", "schema")
OUT = os.path.join(KOTLIN, "src", "SpecSchemas.kt")

HEADER = '''\
// GENERATED FILE - DO NOT EDIT BY HAND.
// Regenerate with: python3 bindings/kotlin/tools/gen_spec_schemas.py
//
// The twenty-one Causalontology JSON Schemas, vendored into the published
// package as string constants. A Kotlin/Native klib cannot carry loose
// resource files, so the schemas are embedded at compile time - the same
// approach the Rust binding takes with include_str!. This is what lets an
// installed copy of the binding validate objects standalone, with no
// repository checkout and no CAUSALONTOLOGY_SPEC on the environment.
//
// Each value is byte-for-byte identical to spec/schema/<name>; the
// conformance runner compares them and hard-fails on any drift.
package org.causalontology

object SpecSchemas {

    // schema filename -> the schema file's exact text
    val FILES: Map<String, String> = mapOf(
'''

FOOTER = '''\
    )
}
'''


def esc(s):
    """Escape a string for a Kotlin double-quoted literal, exactly."""
    out = []
    for ch in s:
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "$":
            out.append("\\$")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif 0x20 <= o <= 0x7E:
            out.append(ch)
        else:
            out.append("\\u%04x" % o)
    return "".join(out)


def main():
    if not os.path.isdir(SPEC):
        sys.exit("spec/schema not found at %s" % SPEC)
    names = sorted(n for n in os.listdir(SPEC) if n.endswith(".schema.json"))
    if len(names) != 21:
        sys.exit("expected 21 schema files in %s, found %d" % (SPEC, len(names)))
    parts = [HEADER]
    for i, name in enumerate(names):
        with open(os.path.join(SPEC, name), "r", encoding="utf-8") as f:
            text = f.read()
        comma = "" if i == len(names) - 1 else ","
        parts.append('        "%s" to "%s"%s\n' % (name, esc(text), comma))
    parts.append(FOOTER)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write("".join(parts))
    print("wrote %s (%d schemas)" % (OUT, len(names)))


if __name__ == "__main__":
    main()
