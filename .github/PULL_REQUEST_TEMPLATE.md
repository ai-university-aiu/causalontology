## What and why

Briefly, what does this change and why.

## Checklist

- [ ] The 107 conformance vectors pass for any binding I touched (`conformance/vectors/`).
- [ ] New/changed identifiers follow the whole-word conventions in [NAMING.md](../NAMING.md).
- [ ] For a new binding: it ships the vectors as its test suite and is wired into `.github/workflows/conformance.yml`.
- [ ] For a specification change: it follows [GOVERNANCE.md](../GOVERNANCE.md) (change order, SemVer rules, vectors re-frozen) and updates [CHANGELOG.md](../CHANGELOG.md).
- [ ] Docs updated where relevant (README, PUBLISHING.md, bindings/README.md).
