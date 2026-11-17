# Code Signing Policy

> Free code signing provided by [SignPath.io](https://signpath.io/), certificate by [SignPath Foundation](https://signpath.org/).

## 1. Signing Status & Publisher Identity

- **Certificate Authority & Publisher:** Once SignPath Foundation onboarding is active, Windows Authenticode signatures on official `Malaz.exe` binaries identify **SignPath Foundation** as the *Verified Publisher*.
- **Current Release Status (`v1.0.0`):** Release `v1.0.0` is authenticated via detached OpenPGP signatures (`SHA256SUMS-1.0.0.txt.asc`) while SignPath Foundation onboarding is in progress. See [docs/VERIFYING_RELEASES.md](docs/VERIFYING_RELEASES.md) for current verification instructions and live Authenticode status.

---

## 2. Team Roles & Access Control

Malaz enforces protected-branch governance and mandatory multi-factor authentication (2FA/MFA) on all GitHub and SignPath.io accounts with project access:

- **Committers:** [`@TulparLemon`](https://github.com/TulparLemon) — authorized to author and commit changes on typed working branches.
- **Reviewers:** [`@TulparLemon`](https://github.com/TulparLemon) — reviews all external pull requests and verifies automated hygiene, architecture, license, and test gates before any merge into the protected `main` branch.
- **Approvers:** [`@TulparLemon`](https://github.com/TulparLemon) — verifies and approves every release signing request in SignPath.io against the corresponding annotated Git tag and GitHub Actions build run.

---

## 3. Build Provenance & Signed Artifact Scope

- **Reproducible CI Provenance:** Official Windows release archives are built exclusively on GitHub-hosted runners (`windows-latest`) via [`.github/workflows/release.yml`](.github/workflows/release.yml) from annotated `v*` Git tags using [`scripts/build_nuitka.bat`](scripts/build_nuitka.bat), [`src/malaz/__init__.py`](src/malaz/__init__.py), locked build dependencies in [`requirements.lock`](requirements.lock), and tag-parity checks in [`scripts/make_release.py`](scripts/make_release.py).
- **Signed Binary Scope (`Malaz.exe` Only):** Only the project's own compiled executable (`Malaz.exe`) is submitted for signing under the SignPath Foundation certificate. Bundled CPython and third-party runtime libraries (`.dll` and `.pyd` files listed in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)) are never signed or re-signed under the project certificate; any existing upstream signatures remain unmodified.

---

## 4. Privacy & Network Policy

This program will not transfer any information to other networked systems unless specifically requested by the user or the person installing or operating it.

By default, Malaz operates strictly **offline**: it opens zero network sockets during startup, file scanning, YARA rule evaluation, or report export, requires no account, collects zero telemetry, and never uploads scanned files or crash reports to external services. Every optional network feature (such as manual ClamAV database updates, public blocklist refreshes, and opt-in DNS sender authentication checks) is disabled by default and documented in full in [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md).
