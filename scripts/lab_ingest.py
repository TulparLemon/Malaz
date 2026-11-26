#!/usr/bin/env python3
"""Host-side zero-unpack streaming ingest for the isolated Malaz Malware Lab.

Implements Spec 017 §3.1:
* Streams password-protected malicious ZIP archives (AES-256 & ZipCrypto via
  ``pyzipper.AESZipFile``) in 64-KiB chunks without writing decrypted samples
  to disk and without materialising whole files in RAM.
* Enforces All-or-Nothing atomicity per ZIP (with full rollback of
  ``total_unpacked_bytes`` and ``seen_hashes`` on any rejected member).
* Streams benign files recursively under the same size and symlink limits.
* Two-phase commit: validates all files and checks for malicious/benign
  ``label_conflict`` before staging a single file into ``<staging-dir>/input_ro/``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import stat
import sys
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
for _p in (ROOT / "src", ROOT / "scripts"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import pyzipper  # noqa: E402

from malaz import config  # noqa: E402
from malaz.core import magic  # noqa: E402
from malaz.lab.manifest import ManifestError, load_manifest, sha256_file  # noqa: E402
from malaz.security.safe_extract import unsafe_name_reason  # noqa: E402

_CHUNK_BYTES = 64 * 1024
_EXT_RE = re.compile(r"^\.[a-z0-9]{1,10}$")
_FAMILY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_TYPE_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,31}$")
_WIN_REPARSE_ATTR = 0x0400

_REJECT_KEYS = (
    "oversize",
    "member_limit",
    "zipslip",
    "corrupt",
    "wrong_password",
    "unencrypted",
    "host_av",
    "unreadable_benign",
    "label_conflict",
)


@dataclass(frozen=True)
class _StagedEntry:
    sha256: str
    name: str
    file_type: str
    family: str
    label: str
    source: str
    split: str
    first_seen: str
    src_path: Path  # original benign file or ZIP path


def _is_reparse_or_symlink(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        st = os.lstat(path)
        file_attrs = getattr(st, "st_file_attributes", 0)
        if file_attrs & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            return True
    except OSError:
        return True
    return False


def _is_inside_repo(path: Path) -> bool:
    real_root = Path(os.path.realpath(ROOT))
    real_path = Path(os.path.realpath(path))
    try:
        return real_path.is_relative_to(real_root)
    except AttributeError:
        return str(real_path).lower().startswith(str(real_root).lower())


def _is_host_av_error(exc: OSError) -> bool:
    if isinstance(exc, PermissionError):
        return True
    winerr = getattr(exc, "winerror", None)
    return winerr in (5, 225, 226)


def _sanitize_ext(raw_name: str) -> str:
    ext = Path(raw_name).suffix.lower()
    return ext if _EXT_RE.fullmatch(ext) else ".bin"


def _sanitize_family(raw: str | None) -> str:
    if raw and isinstance(raw, str):
        cleaned = raw.strip()
        if _FAMILY_RE.fullmatch(cleaned):
            return cleaned
    return "unknown"


def _detect_member_type(prefix: bytes, raw_name: str) -> str:
    ft = magic.detect(prefix)
    ft = magic.refine_text_type(ft, Path(raw_name).suffix.lower())
    detected = (ft.type or "unknown").lower()
    return detected if _TYPE_RE.fullmatch(detected) else "unknown"


def _choose_split(
    sha256: str, test_ratio: float, prev_splits: dict[str, str]
) -> str:
    if sha256 in prev_splits:
        return prev_splits[sha256]
    bucket = int(sha256[:8], 16) / float(1 << 32)
    return "test" if bucket < test_ratio else "dev"


def _load_previous_splits(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    manifest = load_manifest(path)
    return {entry.sha256: entry.split for entry in manifest.entries}


def _load_family_map(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("family-map muss ein JSON-Objekt sein")
    return {str(k).lower(): str(v) for k, v in data.items()}


def _is_wrong_password_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    return (
        "bad password" in msg
        or "password required" in msg
        or "wrong password" in msg
        or "authentication" in msg
    )


def _inspect_zip_atomic(
    zip_path: Path,
    *,
    password_bytes: bytes,
    max_members: int,
    max_member_bytes: int,
    remaining_total_bytes: int,
    seen_mal_hashes: set[str],
    family_map: dict[str, str],
    source: str,
    test_ratio: float,
    prev_splits: dict[str, str],
    today: str,
) -> tuple[list[_StagedEntry], int, int, str | None]:
    """Stream and validate one encrypted ZIP atomically.

    Returns ``(new_entries, zip_unpacked_bytes, dedup_count, reject_reason)``.
    If ``reject_reason`` is not ``None``, caller discards the entire ZIP.
    """
    if _is_reparse_or_symlink(zip_path):
        return [], 0, 0, "zipslip"

    try:
        zf_ctx = pyzipper.AESZipFile(zip_path, "r")
    except OSError as exc:
        return [], 0, 0, ("host_av" if _is_host_av_error(exc) else "corrupt")
    except (zipfile.BadZipFile, RuntimeError, ValueError):
        return [], 0, 0, "corrupt"

    local_entries: list[_StagedEntry] = []
    local_hashes: set[str] = set()
    zip_bytes = 0
    dedup_count = 0
    regular_members = 0
    zip_stem = zip_path.stem.lower()

    try:
        with zf_ctx as zf:
            infos = zf.infolist()
            for info in infos:
                if info.is_dir():
                    continue
                regular_members += 1
                if regular_members > max_members:
                    return [], 0, 0, "member_limit"
                if (info.flag_bits & 0x1) == 0:
                    return [], 0, 0, "unencrypted"
                if unsafe_name_reason(info.filename):
                    return [], 0, 0, "zipslip"
                unix_mode = info.external_attr >> 16
                if stat.S_ISLNK(unix_mode) or (info.external_attr & _WIN_REPARSE_ATTR):
                    return [], 0, 0, "zipslip"

                if (
                    info.file_size > max_member_bytes
                    or (zip_bytes + info.file_size) > remaining_total_bytes
                ):
                    return [], 0, 0, "oversize"

                hasher = hashlib.sha256()
                prefix = bytearray()
                member_bytes = 0
                try:
                    with zf.open(info, "r", pwd=password_bytes) as stream:
                        # pyzipper's ZipExtFile truncates read() at the untrusted ZIP
                        # header info.file_size. Lift _left so header-spoofed streams
                        # cannot hide extra uncompressed bytes behind a small header;
                        # our chunk loop enforces the real byte cap, and post-EOF checks
                        # catch any mismatch between declared and actual sizes.
                        if hasattr(stream, "_left"):
                            stream._left = 1 << 62
                        while True:
                            chunk = stream.read(_CHUNK_BYTES)
                            if not chunk:
                                break
                            member_bytes += len(chunk)
                            if (
                                member_bytes > max_member_bytes
                                or (zip_bytes + member_bytes) > remaining_total_bytes
                            ):
                                return [], 0, 0, "oversize"
                            hasher.update(chunk)
                            if len(prefix) < _CHUNK_BYTES:
                                need = _CHUNK_BYTES - len(prefix)
                                prefix.extend(chunk[:need])
                        if (
                            member_bytes != info.file_size
                            or getattr(stream, "_compress_left", 0) > 0
                        ):
                            return [], 0, 0, "corrupt"
                except OSError as exc:
                    return [], 0, 0, ("host_av" if _is_host_av_error(exc) else "corrupt")
                except RuntimeError as exc:
                    if _is_wrong_password_error(exc):
                        return [], 0, 0, "wrong_password"
                    return [], 0, 0, "corrupt"
                except (zipfile.BadZipFile, ValueError, EOFError):
                    return [], 0, 0, "corrupt"

                digest = hasher.hexdigest()
                if digest in seen_mal_hashes or digest in local_hashes:
                    dedup_count += 1
                    continue

                zip_bytes += member_bytes
                local_hashes.add(digest)
                ext = _sanitize_ext(info.filename)
                ftype = _detect_member_type(bytes(prefix), info.filename)
                fam = _sanitize_family(
                    family_map.get(digest) or family_map.get(zip_stem)
                )
                split = _choose_split(digest, test_ratio, prev_splits)
                local_entries.append(
                    _StagedEntry(
                        sha256=digest,
                        name=f"{digest}{ext}",
                        file_type=ftype,
                        family=fam,
                        label="malicious",
                        source=source,
                        split=split,
                        first_seen=today,
                        src_path=zip_path,
                    )
                )
    except OSError as exc:
        return [], 0, 0, ("host_av" if _is_host_av_error(exc) else "corrupt")
    except RuntimeError as exc:
        if _is_wrong_password_error(exc):
            return [], 0, 0, "wrong_password"
        return [], 0, 0, "corrupt"
    except (zipfile.BadZipFile, ValueError):
        return [], 0, 0, "corrupt"

    if regular_members == 0:
        return [], 0, 0, "corrupt"

    return local_entries, zip_bytes, dedup_count, None


def _stream_benign_file(
    path: Path,
    *,
    max_member_bytes: int,
    remaining_total_bytes: int,
) -> tuple[str | None, bytes, int, str | None]:
    """Stream one benign file in 64-KiB chunks.

    Returns ``(sha256, prefix_64k, n_bytes, reject_reason)``.
    """
    if _is_reparse_or_symlink(path):
        return None, b"", 0, "unreadable_benign"

    hasher = hashlib.sha256()
    prefix = bytearray()
    total = 0
    try:
        with path.open("rb") as fh:
            while True:
                chunk = fh.read(_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_member_bytes or total > remaining_total_bytes:
                    return None, b"", 0, "oversize"
                hasher.update(chunk)
                if len(prefix) < _CHUNK_BYTES:
                    need = _CHUNK_BYTES - len(prefix)
                    prefix.extend(chunk[:need])
    except OSError:
        return None, b"", 0, "unreadable_benign"

    return hasher.hexdigest(), bytes(prefix), total, None


def _write_sha256_file(target_file: Path, sha_file: Path) -> str:
    digest = sha256_file(target_file)
    sha_file.write_text(f"{digest}  {target_file.name}\n", encoding="utf-8")
    return digest


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Zero-unpack host ingest for Malaz Lab.")
    ap.add_argument("--bad-zips", type=Path, required=True)
    ap.add_argument("--benign-dir", type=Path, required=True)
    ap.add_argument("--staging-dir", type=Path, required=True)
    ap.add_argument("--corpus-id", type=str, required=True)
    ap.add_argument("--source", type=str, default="local_lab")
    ap.add_argument("--test-ratio", type=float, default=0.3)
    ap.add_argument("--previous-manifest", type=Path, default=None)
    ap.add_argument("--family-map", type=Path, default=None)
    ap.add_argument("--password-file", type=Path, default=None)
    ap.add_argument("--max-members-per-zip", type=int, default=64)
    ap.add_argument("--max-total-mb", type=int, default=1024)
    return ap.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    # Validate CLI parameters fail-closed (Exit 2)
    if not math.isfinite(args.test_ratio) or not (0.0 <= args.test_ratio <= 1.0):
        print("FEHLER: --test-ratio muss endlich in [0.0, 1.0] liegen.", file=sys.stderr)
        return 2
    if args.max_members_per_zip <= 0 or args.max_total_mb <= 0:
        print("FEHLER: Limits müssen positiv sein.", file=sys.stderr)
        return 2
    if not args.corpus_id.strip():
        print("FEHLER: --corpus-id darf nicht leer sein.", file=sys.stderr)
        return 2
    if not args.bad_zips.is_dir() or not args.benign_dir.is_dir():
        print("FEHLER: --bad-zips und --benign-dir müssen existierende Ordner sein.", file=sys.stderr)
        return 2

    # Password handling (never log!)
    if args.password_file is not None:
        try:
            pw_text = args.password_file.read_text(encoding="utf-8").strip("\r\n")
        except OSError as exc:
            print(f"FEHLER: --password-file nicht lesbar: {exc}", file=sys.stderr)
            return 2
        if not pw_text:
            print("FEHLER: Passwort aus --password-file ist leer.", file=sys.stderr)
            return 2
    else:
        pw_text = "infected"
    password_bytes = pw_text.encode("utf-8")

    # Staging path safety: must not be symlink/reparse point and must be outside ROOT
    staging: Path = args.staging_dir
    if staging.exists() and _is_reparse_or_symlink(staging):
        print("FEHLER: --staging-dir darf kein Symlink/Reparse-Point sein.", file=sys.stderr)
        return 2
    for parent in staging.parents:
        if parent.exists() and _is_reparse_or_symlink(parent):
            print("FEHLER: Elternpfad von --staging-dir ist ein Symlink/Reparse-Point.", file=sys.stderr)
            return 2
    if _is_inside_repo(staging):
        print("FEHLER: --staging-dir darf nicht innerhalb des Repositories liegen.", file=sys.stderr)
        return 2

    input_ro = staging / "input_ro"
    if input_ro.exists():
        if _is_reparse_or_symlink(input_ro) or not input_ro.is_dir():
            print("FEHLER: input_ro ist ungültig.", file=sys.stderr)
            return 2
        if any(input_ro.iterdir()):
            print("FEHLER: input_ro existiert bereits und ist nicht leer.", file=sys.stderr)
            return 2

    try:
        prev_splits = _load_previous_splits(args.previous_manifest)
        family_map = _load_family_map(args.family_map)
    except (OSError, ValueError, ManifestError) as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        return 2

    max_member_bytes = int(config.MAX_READ_SIZE)
    max_total_bytes = int(args.max_total_mb) * 1024 * 1024
    today = datetime.now(UTC).strftime("%Y-%m-%d")

    rejected: dict[str, int] = {k: 0 for k in _REJECT_KEYS}
    total_unpacked_bytes = 0
    deduplicated = 0

    # ----------------------------------------------------------------------- #
    # Phase 1: In-memory streaming validation & conflict check (NO writes yet!)
    # ----------------------------------------------------------------------- #
    seen_mal_hashes: set[str] = set()
    staged_zips: list[tuple[Path, list[_StagedEntry], int]] = []

    zip_files = sorted(
        (p for p in args.bad_zips.iterdir() if p.suffix.lower() == ".zip"),
        key=lambda p: p.name.lower(),
    )
    for zp in zip_files:
        remaining = max_total_bytes - total_unpacked_bytes
        entries, zbytes, zdedup, rej = _inspect_zip_atomic(
            zp,
            password_bytes=password_bytes,
            max_members=args.max_members_per_zip,
            max_member_bytes=max_member_bytes,
            remaining_total_bytes=remaining,
            seen_mal_hashes=seen_mal_hashes,
            family_map=family_map,
            source=args.source,
            test_ratio=args.test_ratio,
            prev_splits=prev_splits,
            today=today,
        )
        if rej is not None:
            rejected[rej] += 1
            continue
        deduplicated += zdedup
        if not entries:
            # ZIP contained only duplicates -> do not copy into input_ro/bad_zips/
            continue
        for ent in entries:
            seen_mal_hashes.add(ent.sha256)
        total_unpacked_bytes += zbytes
        staged_zips.append((zp, entries, zbytes))

    seen_ben_hashes: set[str] = set()
    staged_benign: list[_StagedEntry] = []
    label_conflicts = 0

    for bp in sorted(args.benign_dir.rglob("*"), key=lambda p: str(p).lower()):
        if bp.is_dir():
            continue
        if _is_reparse_or_symlink(bp):
            rejected["unreadable_benign"] += 1
            continue
        remaining = max_total_bytes - total_unpacked_bytes
        digest, prefix, bbytes, rej = _stream_benign_file(
            bp,
            max_member_bytes=max_member_bytes,
            remaining_total_bytes=remaining,
        )
        if rej is not None or digest is None:
            rejected[rej or "unreadable_benign"] += 1
            continue
        if digest in seen_mal_hashes:
            label_conflicts += 1
            rejected["label_conflict"] += 1
            continue
        if digest in seen_ben_hashes:
            deduplicated += 1
            continue
        seen_ben_hashes.add(digest)
        total_unpacked_bytes += bbytes
        ext = _sanitize_ext(bp.name)
        ftype = _detect_member_type(prefix, bp.name)
        split = _choose_split(digest, args.test_ratio, prev_splits)
        staged_benign.append(
            _StagedEntry(
                sha256=digest,
                name=f"{digest}{ext}",
                file_type=ftype,
                family="benign",
                label="benign",
                source=args.source,
                split=split,
                first_seen=today,
                src_path=bp,
            )
        )

    if label_conflicts > 0:
        print(
            f"FEHLER: {label_conflicts} Label-Konflikt(e) (SHA-256 in malicious UND benign) — "
            "Staging abgebrochen (input_ro bleibt unberührt).",
            file=sys.stderr,
        )
        return 1

    # ----------------------------------------------------------------------- #
    # Phase 2: Atomic staging copies + manifest & checksum artefacts
    # ----------------------------------------------------------------------- #
    bad_zips_dir = input_ro / "bad_zips"
    benign_out_dir = input_ro / "benign"
    bad_zips_dir.mkdir(parents=True, exist_ok=True)
    benign_out_dir.mkdir(parents=True, exist_ok=True)

    final_malicious: list[_StagedEntry] = []
    bad_zips_sha256: dict[str, str] = {}

    for idx, (zp, entries, zbytes) in enumerate(staged_zips, 1):
        try:
            zsha = sha256_file(zp)
            dest_name = f"{idx:04d}_{zsha[:12]}.zip"
            dest_path = bad_zips_dir / dest_name
            shutil.copy2(zp, dest_path)
            actual_dest_sha = sha256_file(dest_path)
            if actual_dest_sha != zsha:
                dest_path.unlink(missing_ok=True)
                raise PermissionError("ZIP copy hash mismatch")
        except OSError as exc:
            # Roll back this ZIP cleanly
            if "dest_path" in locals():
                dest_path.unlink(missing_ok=True)
            total_unpacked_bytes = max(0, total_unpacked_bytes - zbytes)
            for ent in entries:
                seen_mal_hashes.discard(ent.sha256)
            rejected["host_av" if _is_host_av_error(exc) else "corrupt"] += 1
            continue
        bad_zips_sha256[dest_name] = zsha
        final_malicious.extend(entries)

    final_benign: list[_StagedEntry] = []
    for bent in staged_benign:
        dest = benign_out_dir / bent.name
        try:
            shutil.copy2(bent.src_path, dest)
        except OSError:
            dest.unlink(missing_ok=True)
            rejected["unreadable_benign"] += 1
            continue
        final_benign.append(bent)

    all_entries = [*final_malicious, *final_benign]
    if not all_entries:
        print("FEHLER: Keine gültigen Dateien nach Ingest übrig.", file=sys.stderr)
        return 1

    manifest_doc: dict[str, Any] = {
        "schema_version": 1,
        "corpus": {
            "id": args.corpus_id.strip(),
            "created": today,
            "source": args.source.strip() or "local_lab",
            "notes": "",
        },
        "files": [
            {
                "sha256": ent.sha256,
                "name": ent.name,
                "type": ent.file_type,
                "family": ent.family,
                "label": ent.label,
                "source": ent.source,
                "first_seen": ent.first_seen,
                "split": ent.split,
                "notes": "",
            }
            for ent in all_entries
        ],
    }

    manifest_path = input_ro / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest_doc, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    # Self-validate against strict manifest schema
    load_manifest(manifest_path)

    manifest_sha = _write_sha256_file(manifest_path, input_ro / "manifest.sha256")
    (input_ro / "bad_zips_sha256.json").write_text(
        json.dumps(bad_zips_sha256, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    summary_doc = {
        "schema_version": 1,
        "manifest_sha256": manifest_sha,
        "accepted_malicious": len(final_malicious),
        "accepted_benign": len(final_benign),
        "total_unpacked_bytes": total_unpacked_bytes,
        "deduplicated": deduplicated,
        "rejected": rejected,
        "rejected_total": sum(rejected.values()),
    }
    summary_path = input_ro / "ingest_summary.json"
    summary_path.write_text(
        json.dumps(summary_doc, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    _write_sha256_file(summary_path, input_ro / "ingest_summary.sha256")

    print(
        f"Ingest OK: malicious={len(final_malicious)}, benign={len(final_benign)}, "
        f"deduplicated={deduplicated}, rejected={summary_doc['rejected_total']}, "
        f"manifest_sha256={manifest_sha[:12]}..."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
