## Summary

Describe the change and reference any related issue.

## Checklist

- [ ] Licensed under [`GPL-3.0-or-later`](https://github.com/TulparLemon/Malaz/blob/main/LICENSE) with no incompatible or unvetted third-party dependencies.
- [ ] Preserves **offline-by-default** behavior (see [`docs/SECURITY_MODEL.md`](https://github.com/TulparLemon/Malaz/blob/main/docs/SECURITY_MODEL.md)).
- [ ] Preserves the **completeness invariant** (*"Unchecked is never clean"*): errors, limits, timeouts, and missing engines never degrade silently to `GREEN`.
- [ ] Follows the 7-layer architecture in [`docs/ARCHITECTURE.md`](https://github.com/TulparLemon/Malaz/blob/main/docs/ARCHITECTURE.md) (`scripts/arch_gate.py` passes).
- [ ] Local quality gates pass (`repo_hygiene_gate.py`, `arch_gate.py`, `license_gate.py`, `check_doc_claims.py`, `check_duplicate_logic.py`, `ruff`, `mypy`, `pytest`).
- [ ] Contributing guidelines reviewed ([`CONTRIBUTING.md`](https://github.com/TulparLemon/Malaz/blob/main/.github/CONTRIBUTING.md)).
