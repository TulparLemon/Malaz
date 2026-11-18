# Releasing Malaz (Maintainer Guide)

Every official Malaz release is built from a single **annotated Git tag** inside GitHub Actions (`.github/workflows/release.yml`) using locked dependencies (`requirements.lock`), verified automatically by `scripts/make_release.py` and `scripts/check_release.py`, uploaded as an **unpublished Draft Release**, and then signed offline by the maintainer with the project OpenPGP key.

---

## 1. Create & Push an Annotated Tag

Ensure `main` is clean, green in CI, and `src/malaz/__init__.py` (`__version__`) plus [../CHANGELOG.md](../CHANGELOG.md) match the target version (for example `1.0.0`):

```powershell
git checkout main
git pull --ff-only origin main
python scripts/check_release.py --tree-ref main

git tag -a v1.0.0 -m "Malaz 1.0.0"
git push origin v1.0.0
```

Pushing `v1.0.0` triggers `.github/workflows/release.yml`, which:
1. Runs the full quality gate (`scripts/ci_gate.py`) inside a locked Python 3.12 `.venv`.
2. Builds the portable standalone Windows archive via `scripts/build_nuitka.bat` (including `make_sbom.py`, `smoke_build.py`, and `check_release.py`).
3. Runs `scripts/make_release.py` to generate `Malaz-1.0.0-source.zip` and `Malaz-1.0.0-licenses.zip` directly from `refs/tags/v1.0.0`, verify 1:1 file parity with the tag tree, check PE version metadata (`1.0.0.0`), extract `sbom.json`, and write `SHA256SUMS-1.0.0.txt`.
4. Uploads all 5 files to a **Draft** GitHub Release.

---

## 2. Download, Verify, Sign & Publish

Once the `Release` workflow succeeds, download the draft assets on the signing machine, verify integrity, create the detached OpenPGP signature, re-verify, and publish:

```powershell
gh release download v1.0.0 -D dist\draft-v1.0.0

# Pre-sign check: verifies all 4 asset hashes & sizes; exits 3 (UNSIGNED) before signing
python scripts/verify_release_set.py dist\draft-v1.0.0

# Create detached signature (never rewrite SHA256SUMS after this step!)
python scripts/sign_sums.py --sums dist\draft-v1.0.0\SHA256SUMS-1.0.0.txt --key AD927E805BE3B440BD676872F350D77C8D498335 --require-signature

# Post-sign check: must exit 0 (hashes + VALIDSIG fingerprint verified)
python scripts/verify_release_set.py dist\draft-v1.0.0

# Upload signature & public key, then publish the draft
gh release upload v1.0.0 dist\draft-v1.0.0\SHA256SUMS-1.0.0.txt.asc docs\RELEASE-SIGNING-KEY.asc
gh release edit v1.0.0 --draft=false
```

End-user verification instructions are documented in [VERIFYING_RELEASES.md](VERIFYING_RELEASES.md).
