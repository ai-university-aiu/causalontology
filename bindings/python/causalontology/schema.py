"""Schema validation against spec/schema/*.schema.json.

A deliberately small interpreter for exactly the JSON Schema keywords the
eighteen Causalontology schemas use: type, const, enum, pattern, required,
properties, additionalProperties, items, minItems, minLength, minimum,
maximum, oneOf, local $ref (#/$defs/...), and cross-file $ref to a sibling
schema (https://causalontology.org/schema/<file>.schema.json#/...). "format"
is treated as an annotation, as the 2020-12 draft does by default.
"""

import json
import os
import re
from pathlib import Path

# kind -> schema file. Three token kinds keep their original 1.0.0-reserved
# file names (individual/token/state); the id scheme is the whole word.
SCHEMA_FILES = {
    "occurrent": "occurrent.schema.json",
    "causal_relation_object": "causal_relation_object.schema.json",
    "continuant": "continuant.schema.json",
    "realizable": "realizable.schema.json",
    "stratum": "stratum.schema.json",
    "bridge": "bridge.schema.json",
    "cross_stratal_seam": "cross_stratal_seam.schema.json",
    "port": "port.schema.json",
    "conduit": "conduit.schema.json",
    "quality": "quality.schema.json",
    "token_individual": "individual.schema.json",
    "token_occurrence": "token.schema.json",
    "state_assertion": "state.schema.json",
    "token_causal_claim": "token_causal_claim.schema.json",
    "assertion": "assertion.schema.json",
    "enrichment": "enrichment.schema.json",
    "retraction": "retraction.schema.json",
    "succession": "succession.schema.json",
}

_cache = {}
_BASE = "https://causalontology.org/schema/"


def _schema_dir():
    env = os.environ.get("CAUSALONTOLOGY_SPEC")
    if env:
        return Path(env) / "schema"
    return Path(__file__).resolve().parents[3] / "spec" / "schema"


def _load_file(filename):
    if filename not in _cache:
        with open(_schema_dir() / filename) as f:
            _cache[filename] = json.load(f)
    return _cache[filename]


def load_schema(kind):
    if kind not in SCHEMA_FILES:
        raise ValueError("unknown kind: %r" % (kind,))
    return _load_file(SCHEMA_FILES[kind])


def _navigate(doc, pointer):
    node = doc
    for part in pointer.split("/"):
        if part == "":
            continue
        node = node[part]
    return node


def _resolve(schema, root):
    """Resolve local and cross-file $refs to a concrete schema node + its root."""
    while isinstance(schema, dict) and "$ref" in schema:
        ref = schema["$ref"]
        if ref.startswith("#/"):
            schema = _navigate(root, ref[2:])
        elif ref.startswith(_BASE):
            rest = ref[len(_BASE):]
            filename, _, pointer = rest.partition("#/")
            root = _load_file(filename)
            schema = _navigate(root, pointer) if pointer else root
        else:
            raise ValueError("unsupported $ref: %r" % ref)
    return schema, root


_TYPES = {
    "object": dict, "array": list, "string": str,
    "number": (int, float), "boolean": bool, "integer": int,
}


def _check(value, schema, root, path, errors):
    schema, root = _resolve(schema, root)

    if "oneOf" in schema:
        passing = 0
        for sub in schema["oneOf"]:
            suberrs = []
            _check(value, sub, root, path, suberrs)
            if not suberrs:
                passing += 1
        if passing != 1:
            errors.append("%s: matches %d of the oneOf branches (need exactly 1)"
                          % (path, passing))
        return

    t = schema.get("type")
    if t is not None:
        pytype = _TYPES[t]
        ok = isinstance(value, pytype)
        if t in ("number", "integer") and isinstance(value, bool):
            ok = False
        if not ok:
            errors.append("%s: expected %s" % (path, t))
            return

    if "const" in schema and value != schema["const"]:
        errors.append("%s: must equal %r" % (path, schema["const"]))
    if "enum" in schema and value not in schema["enum"]:
        errors.append("%s: %r not in enumeration" % (path, value))
    if "pattern" in schema and isinstance(value, str):
        if not re.search(schema["pattern"], value):
            errors.append("%s: %r does not match %s"
                          % (path, value, schema["pattern"]))
    if "minLength" in schema and isinstance(value, str):
        if len(value) < schema["minLength"]:
            errors.append("%s: shorter than minLength" % path)
    if "minimum" in schema and isinstance(value, (int, float)) \
            and not isinstance(value, bool):
        if value < schema["minimum"]:
            errors.append("%s: below minimum %s" % (path, schema["minimum"]))
    if "maximum" in schema and isinstance(value, (int, float)) \
            and not isinstance(value, bool):
        if value > schema["maximum"]:
            errors.append("%s: above maximum %s" % (path, schema["maximum"]))

    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append("%s: fewer than %d items" % (path, schema["minItems"]))
        if "items" in schema:
            for i, item in enumerate(value):
                _check(item, schema["items"], root, "%s[%d]" % (path, i), errors)

    if isinstance(value, dict):
        props = schema.get("properties", {})
        for req in schema.get("required", []):
            if req not in value:
                errors.append("%s: required property '%s' missing" % (path, req))
        if schema.get("additionalProperties") is False:
            for key in value:
                if key not in props:
                    errors.append("%s: additional property '%s'" % (path, key))
        for key, sub in props.items():
            if key in value:
                _check(value[key], sub, root, "%s.%s" % (path, key), errors)


def validate_schema(obj, kind=None):
    """(ok, reasons) — structural validity against the kind's JSON Schema."""
    from .canonical import infer_kind
    kind = kind or infer_kind(obj)
    root = load_schema(kind)
    errors = []
    _check(obj, root, root, "$", errors)
    return (not errors), errors
