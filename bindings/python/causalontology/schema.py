"""Schema validation against spec/schema/*.schema.json.

A deliberately small interpreter for exactly the JSON Schema keywords the
eight Causalontology schemas use: type, const, enum, pattern, required,
properties, additionalProperties, items, minItems, minLength, minimum,
maximum, oneOf, and local $ref (#/$defs/...). "format" is treated as an
annotation, as the 2020-12 draft does by default.
"""

import json
import os
import re
from pathlib import Path

SCHEMA_FILES = {
    "cro": "cro.schema.json",
    "occurrent": "occurrent.schema.json",
    "continuant": "continuant.schema.json",
    "realizable": "realizable.schema.json",
    "assertion": "assertion.schema.json",
    "enrichment": "enrichment.schema.json",
    "retraction": "retraction.schema.json",
    "succession": "succession.schema.json",
}

_cache = {}


def _schema_dir():
    env = os.environ.get("CAUSALONTOLOGY_SPEC")
    if env:
        return Path(env) / "schema"
    return Path(__file__).resolve().parents[3] / "spec" / "schema"


def load_schema(kind):
    if kind not in SCHEMA_FILES:
        raise ValueError("unknown kind: %r" % (kind,))
    if kind not in _cache:
        with open(_schema_dir() / SCHEMA_FILES[kind]) as f:
            _cache[kind] = json.load(f)
    return _cache[kind]


def _resolve(schema, root):
    while "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/"):
            raise ValueError("only local $ref supported: %r" % ref)
        node = root
        for part in ref[2:].split("/"):
            node = node[part]
        schema = node
    return schema


_TYPES = {
    "object": dict, "array": list, "string": str,
    "number": (int, float), "boolean": bool,
}


def _check(value, schema, root, path, errors):
    schema = _resolve(schema, root)

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
        if t == "number" and isinstance(value, bool):
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
