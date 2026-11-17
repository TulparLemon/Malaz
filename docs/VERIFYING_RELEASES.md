# Verifying Releases

Every official Malaz release provides **OpenPGP-signed SHA-256 checksum manifests** and a machine-readable **CycloneDX 1.5 Software Bill of Materials (`sbom.json`)** so you can verify archive integrity and provenance before running `Malaz.exe`.

---

## 1. Release Signing Key

```text
Fingerprint: 11F5 1D1B EE30 EAA3 C88A  E01B 36F1 852E 0ADE 4A08
UID:         Malaz Release Signing <release@malaz.local>
```

Public key file in this repository: [RELEASE-SIGNING-KEY.asc](RELEASE-SIGNING-KEY.asc) (also documented in [../SECURITY.md](../SECURITY.md)).

---

## 2. Release Assets & Verification Files

Download the detached signature and checksum manifest alongside the release archive:

| File | Purpose |
| :--- | :--- |
| `Malaz-1.0.0.zip` | Portable standalone Windows application archive (`Malaz.exe` + bundled runtime) |
| `Malaz-1.0.0-source.zip` | Exact source tree exported from the annotated Git release tag |
| `Malaz-1.0.0-licenses.zip` | Project `LICENSE`, `THIRD_PARTY_NOTICES.md`, and bundled wheel license texts |
| `sbom.json` | CycloneDX 1.5 runtime Software Bill of Materials (also included inside `Malaz-1.0.0.zip`) |
| `SHA256SUMS-1.0.0.txt` | SHA-256 checksums and byte lengths of all four release assets above |
| `SHA256SUMS-1.0.0.txt.asc` | Detached OpenPGP signature over `SHA256SUMS-1.0.0.txt` |
| `RELEASE-SIGNING-KEY.asc` | Project public OpenPGP signing key |

---

## 3. Step-by-Step Verification (Windows PowerShell + GnuPG)

### Step 1 - Import the Public Key & Verify the Signature

```powershell
gpg --import RELEASE-SIGNING-KEY.asc
gpg --verify SHA256SUMS-1.0.0.txt.asc SHA256SUMS-1.0.0.txt
```

Expected output must show `Good signature from "Malaz Release Signing <release@malaz.local>"` **and** match the exact primary key fingerprint:

```text
11F5 1D1B EE30 EAA3 C88A  E01B 36F1 852E 0ADE 4A08
```

### Step 2 - Verify the Archive SHA-256 Checksum

```powershell
Get-FileHash Malaz-1.0.0.zip -Algorithm SHA256
Get-Content SHA256SUMS-1.0.0.txt
```

Confirm that the computed `SHA256` digest matches the entry in `SHA256SUMS-1.0.0.txt` character for character.

> **If verification fails:** Do **not** extract or execute the archive. Delete the file and report the discrepancy via [../SECURITY.md](../SECURITY.md).

---

## 4. Inspecting the Included SBOM (`sbom.json`)

Both at the top level of the extracted `Malaz-1.0.0.zip` archive and as a standalone release asset, `sbom.json` lists all 47 direct and transitive runtime Python packages with exact versions, licenses, and `pkg:pypi/...` PURLs (matching [../THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)). When running from source, you can validate any `sbom.json` file with:

```bat
python scripts/make_sbom.py --output sbom.json --check
```

---

## 5. Authenticode, Windows SmartScreen & SignPath Status

| Protection Mechanism | Provided by OpenPGP Signature? | Current `v1.0.0` Status |
| :--- | :---: | :--- |
| **Download Integrity** (detects tampering in transit) | **Yes** | Active |
| **Publisher Provenance** (cryptographically tied to project key) | **Yes** | Active |
| **Windows SmartScreen Suppression** | No (requires Windows Authenticode certificate + download reputation) | Unsigned in `v1.0.0` (SmartScreen prompt appears on first run) |
| **Windows 11 Smart App Control (SAC)** | No (SAC blocks unsigned binaries) | Unsigned binaries cannot start when SAC is in enforcement mode |

Now that the source repository (`https://github.com/TulparLemon/Malaz`), locked CI pipeline ([../.github/workflows/ci.yml](../.github/workflows/ci.yml)), and automated tag-to-draft release build ([../.github/workflows/release.yml](../.github/workflows/release.yml), see [RELEASING.md](RELEASING.md)) are public under `GPL-3.0-or-later`, open-source Windows Authenticode signing via **SignPath Foundation** is planned for an upcoming release.
