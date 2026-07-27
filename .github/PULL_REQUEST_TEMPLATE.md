## What and why

Briefly, what does this change and why.

## Checklist

- [ ] The 137 conformance **checks** pass for any binding I touched — 38 of them driven by the frozen shared files in `conformance/vectors/`, the other 99 written in that binding's own runner.
- [ ] They pass in **installed mode** too, not only against the source tree: the built artifact, installed outside the checkout, run from a working directory outside the checkout, with `CAUSALONTOLOGY_SPEC` unset. A repo-mode pass on its own is exactly what shipped three broken releases.
- [ ] If I touched the vendored schemas, they are still byte-identical to `spec/schema` (the `schemas` job checks that, and checks that the binding is on its list).
- [ ] New/changed identifiers follow the whole-word conventions in [NAMING.md](../NAMING.md).
- [ ] For a new binding: it ships the vectors as its test suite and is wired into `.github/workflows/conformance.yml` with **both** a repo-mode and an installed-mode job, and is added to the installed-mode coverage table in that file's header.
- [ ] For a specification change: it follows [GOVERNANCE.md](../GOVERNANCE.md) (change order, SemVer rules, vectors re-frozen) and updates [CHANGELOG.md](../CHANGELOG.md).
- [ ] Docs updated where relevant (README, PUBLISHING.md, bindings/README.md).
