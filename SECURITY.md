# Security Policy

## Supported Versions

| Version | Supported | Notes |
| :--- | :--- | :--- |
| `main` / `1.0.x` | Yes | Active public release line (`GPL-3.0-or-later`) |
| `< 1.0` (pre-release milestones) | No | Please upgrade to `1.0.0` or newer |

## Reporting a Vulnerability

Because Malaz parses untrusted, potentially hostile files, we treat parser bugs, archive traversal, resource exhaustion, report injection, and silent detection bypasses as security issues. Please **do not** report security vulnerabilities in public GitHub issues.

1. **Preferred Channel:** Submit a confidential report via **GitHub Private Vulnerability Reporting**:
   <https://github.com/TulparLemon/Malaz/security/advisories/new>
2. **What to Include:** Affected module/file, reproduction steps, security impact (e.g., Zip-Slip, memory/time cap bypass, command/argument injection, HTML/CSV injection, or an unchecked stage silently returning `GREEN`), and — if possible — a minimal, benign proof-of-concept fixture. **Never upload live malware.**
3. **Response Timeline:** We aim to acknowledge reports within **7 days**, coordinate remediation privately, and credit reporters in the release advisory if desired.

## Release Signing Key

Official release checksum manifests (`SHA256SUMS-*.txt.asc`) are signed with the following OpenPGP key (public key tracked at [docs/RELEASE-SIGNING-KEY.asc](docs/RELEASE-SIGNING-KEY.asc); verification steps in [docs/VERIFYING_RELEASES.md](docs/VERIFYING_RELEASES.md)):

```text
Fingerprint: AD92 7E80 5BE3 B440 BD67  6872 F350 D77C 8D49 8335
UID:         Malaz Release Signing <release@malaz.local>
```

## Security Architecture Summary

Full details are documented in [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md):

- **100% Offline by Default:** Standard GUI and CLI scans open zero network sockets and emit zero telemetry.
- **Explicit Opt-In Network Paths Only:** Signature/rule updates (`freshclam`, ReversingLabs YARA, Neo23x0 `signature-base`, public hash/domain/CIDR blocklists), `--clamav-update-check`, and optional mail checks (DNS SPF/DMARC lookups and SHA-256-only URL reputation against a user-configured `https://` endpoint) are disabled by default and require explicit user action.
- **Hardened Untrusted-Input Handling:** Strict byte, entry-count, recursion-depth, and wall-clock caps across all archive and document parsers (`src/malaz/config.py`); Zip-Slip and NTFS junction containment; `shell=False` argument lists for all external tools; JavaScript-free HTML5/PDF reports with strict HTML/CSV/Bidi escaping; privacy-preserving diagnostic logs under `%LOCALAPPDATA%\Malaz\logs\malaz.log`.

## Scope Disclaimer

Malaz is a local static triage tool provided under `GPL-3.0-or-later` without warranty. A `GREEN` verdict indicates that no static heuristics, local blocklists, or configured local AV engines flagged the file — it is **not** a guarantee that an unknown file is safe to execute.
