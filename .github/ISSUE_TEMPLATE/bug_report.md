---
name: Bug report
about: A conformance or correctness problem in the spec, a binding, or the store
title: ""
labels: bug
---

**Which part?**
Specification section, binding (e.g. `causalontology-rust`), or the reference store.

**Conformance-style reproduction (preferred)**
The input record(s) and the exact output you got versus the output the standard
requires. If it is an identity or signature mismatch, include the content-addressed
id(s) from each side.

```json
// input
```

**Expected vs actual**

**Version**
Specification version (current is 4.0.0) and binding version / commit.

**Installed, or from a checkout?**
Please say which, and give the exact install command. The two behave
differently and the difference has been the source of real bugs: a package
installed from a registry must validate with no repository anywhere on the
machine and no `CAUSALONTOLOGY_SPEC` set.

**Environment**
OS, language toolchain version.
