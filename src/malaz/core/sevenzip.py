"""7-Zip backed extraction for RAR/7z/CAB/ISO/deb/rpm archives.

Python's standard library cannot read these containers. When a 7-Zip
command line binary (``7z``/``7zz``) is installed, this module drives it to
extract those archives into a throw-away directory so the dispatcher can scan
each member the same way it scans ZIP members. When the binary is missing the
stage is skipped gracefully — those containers then only get the surface checks
(entropy/YARA) from the generic pipeline.

The 7-Zip binary is the user's own (LGPL) install and is *not* bundled with
the application. Calling it as an external process keeps the distribution
clean: the user's own installation carries its own licence, and Malaz never
redistributes it.

Security notes (see docs/SECURITY_MODEL.md):
* subprocess with an argument list and ``shell=False``; the archive path is a
  single literal argv element (no injection).
* the binary is resolved from fixed install locations and absolute ``PATH``
  entries only — never from the working directory (SEC-010).
* a hard timeout bounds the extraction.
* per-member size, cumulative-volume and entry-count limits mirror the ZIP
  bomb protection in :mod:`core.archive`.
* members are read back by walking the extraction directory, so only files
  that really landed inside it are processed.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from pathlib import Path

from .. import config
from ..procio import (
    decode_tool_output,
    run_tool,
    safe_temp_suffix,
    tool_output_truncated,
)
from ..security.safe_extract import is_safe_member_name
from .archive import BUDGET_STOP_PREFIX, ZIPSLIP_PREFIX, split_unsafe_names
from .toolpath import which_absolute


def find_7z_binary() -> Path | None:
    """Locate an installed 7-Zip CLI binary, or return ``None``.

    Fixed install locations first, then the PATH — but never the current
    working directory (see :func:`_which_absolute`).
    """
    for candidate in config.SEVENZIP_CANDIDATES:
        path = Path(candidate)
        # A relative candidate would resolve against the CWD, which is exactly
        # what this function promises never to use: a "7z.exe" dropped next to
        # whatever directory the scan was started from would be executed.
        if not path.is_absolute() or not path.is_file():
            continue
        return path
    for name in ("7z", "7zz", "7za"):
        found = which_absolute(name)
        if found is not None:
            return found
    return None


#: Return code of :func:`_list_members` when the tool output hit
#: ``MAX_TOOL_OUTPUT_BYTES`` (SEC-023). A real 7-Zip exit code is 0..255, so
#: this can never be forged by the tool itself.
_LIST_TRUNCATED_RC = -2


def _extract(
    binary: Path,
    archive_path: Path,
    out_dir: Path,
    password: str | None,
    timeout: int,
) -> tuple[int, str]:
    """Run ``7z x`` once. Returns ``(returncode, combined_output)``.

    The password travels via stdin (``-p`` with no value makes 7-Zip read it
    from the prompt) instead of the command line, so it is not visible to
    other local processes inspecting argv (WMI Win32_Process, Process Explorer).
    """
    args = [
        str(binary),
        "x",           # extract with full paths
        "-y",          # assume yes on prompts
        "-bd",         # no progress percentage noise
        f"-o{out_dir}",  # output directory (no space, 7z syntax)
    ]
    if password is not None:
        # Empty -p: 7-Zip asks for the password on stdin; feed it one line.
        args.append("-p")
    args.append(str(archive_path))
    try:
        # run_tool: no console window, stdin password feed, hard kill on
        # app shutdown. One prompt line per encrypted archive; extra
        # trailing newlines are harmless (bytes avoid encoding of secrets).
        rc, raw_out, raw_err = run_tool(
            args,
            timeout=timeout,
            input=((password + "\n") if password is not None else "").encode("utf-8"),
        )
    except subprocess.TimeoutExpired:
        return -1, f"7-Zip-Entpacken abgebrochen (Timeout > {timeout}s)"
    except FileNotFoundError:
        return -1, "7-Zip-Binary nicht gefunden"
    except Exception as exc:  # defensive
        return -1, f"{type(exc).__name__}: {exc}"

    out = decode_tool_output(raw_out)
    err = decode_tool_output(raw_err)
    return rc, (out + "\n" + err).strip()


def _sanitize_7z_output(raw: str, work: Path | None = None) -> str:
    """Redact local temp directory paths and strip noisy 7-Zip banner lines.

    Keeps the actionable error line(s) concise for GUI/HTML/JSON reports while
    never exposing the local Windows username via ``tempfile.mkdtemp`` paths.
    """
    text = raw or ""
    if work is not None:
        w_str = str(work)
        text = text.replace(w_str, "<temp>").replace(w_str.replace("\\", "/"), "<temp>")
    lines: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or set(line) <= {"-", "="}:
            continue
        low = line.lower()
        if (
            (low.startswith("7-zip") and "copyright" in low)
            or low.startswith(("scanning the drive", "listing archive:", "extracting archive:"))
            or (low.startswith("1 file,") and "bytes" in low)
        ):
            continue
        lines.append(line)
    summary = " | ".join(lines) if lines else text.strip()
    return summary[: config.MAX_STRING_CAPTURE]


def _looks_like_wrong_password(rc: int, output: str) -> bool:
    low = output.lower()
    return rc == 2 and (
        "wrong password" in low
        or ("password" in low and "cannot open encrypted" in low)
        or "can not open encrypted" in low
    )


def _list_members(
    binary: Path, archive_path: Path, timeout: int, password: str | None = None
) -> tuple[int, list[tuple[str, int]] | None, str]:
    """List archive members with their declared sizes (``7z l -slt``).

    Returns ``(returncode, [(name, size), ...], output)``. The declared sizes
    come from the container headers and bound the disk footprint BEFORE any
    extraction happens, so zip-bomb-style archives are rejected up front
    instead of being written to the temp directory.

    When the tool output hit ``MAX_TOOL_OUTPUT_BYTES`` the list is a PREFIX:
    the function returns :data:`_LIST_TRUNCATED_RC` and ``members=None`` so
    no bomb/entry pre-check is ever derived from an incomplete list.

    ``password`` (via stdin, like :func:`_extract`) covers archives with
    encrypted headers, whose listing fails without it.

    ``-slt`` also prints a header block describing the ARCHIVE itself (its own
    ``Path = <absolute archive path>``), which is not a member. Measured
    against 7-Zip 26.03, the block appears before the ``----------`` separator
    that opens the member list; parsing it used to add a phantom entry with an
    absolute path and an inflated count, skewing the bomb pre-check. The
    ``Folder = +`` entries are real (empty ``Size = 0``) and are kept so the
    entry-count limit matches what ZIP counting sees.
    """
    args = [str(binary), "l", "-slt"]
    if password is not None:
        args.append("-p")
    args.append(str(archive_path))
    try:
        proc = run_tool(
            args,
            timeout=timeout,
            input=((password + "\n") if password is not None else "").encode("utf-8"),
        )
    except (subprocess.TimeoutExpired, OSError):
        return -1, None, "7-Zip-Listing fehlgeschlagen"
    except UnicodeEncodeError:
        # A password read from a file can carry lone surrogates (surrogateescape
        # on Windows file names). _extract catches every exception; this path
        # only caught TimeoutExpired/OSError, so the encode failure escaped and
        # replaced the whole scan. Measured: a two-character password of
        # surrogates raised out of _list_members.
        return -1, None, "Passwort nicht darstellbar (ungültige Zeichenkodierung)"
    rc, raw_out, raw_err = proc
    out = decode_tool_output(raw_out)
    err = decode_tool_output(raw_err)
    output = (out + "\n" + err).strip()
    if tool_output_truncated(proc):
        # SEC-023: the listing is a PREFIX. Its declared sizes and entry count
        # are exactly what the bomb pre-check is built on — run it on an
        # incomplete list and a crafted archive with millions of entries could
        # pass the limits (the missing rows are never counted). No listing ->
        # no pre-check -> no extraction. The sentinel is not a valid 7-Zip
        # exit code (0..255), so the caller can skip the password retries: a
        # capped listing will not become complete by trying another password.
        return _LIST_TRUNCATED_RC, None, (
            "7-Zip-Listing wurde an der Ausgabe-Obergrenze abgeschnitten — "
            "Eintragsliste unvollständig, Bomben-Pre-Check nicht möglich: "
            f"{_sanitize_7z_output(output, archive_path.parent)}"
        )
    if rc != 0:
        return rc, None, output

    members: list[tuple[str, int]] = []
    path = ""
    size = 0
    # False until the member list opens (see docstring); everything before the
    # separator describes the archive itself, not its content. 7-Zip prints
    # TWO dashed lines: "--" before the archive property block and a longer
    # "----------" before the members. Matching on "any dashed line" would
    # treat the archive's own absolute path as a member (measured), so the
    # length must be part of the test.
    in_members = False
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Path = "):
            if path:
                members.append((path, size))
            candidate = line[len("Path = "):]
            # The archive's own header entry carries the path we passed in. It
            # is identified by POSITION (before the separator), not by name:
            # a member name may legitimately equal that absolute path — ZIP
            # allows any bytes in a name, backslashes included — and dropping
            # it by name silently removed its declared size from the bomb
            # pre-check. Measured: an archive whose member was named after the
            # archive's own path listed only the innocent member.
            path = candidate if in_members else ""
            size = 0
        elif line.startswith("Size = "):
            try:
                size = int(line[len("Size = "):])
            except ValueError:
                size = 0
        elif len(line) > 2 and set(line) == {"-"}:
            in_members = True
    if path:
        members.append((path, size))
    if not in_members:
        # rc=0 but no member block: an empty archive, or a listing whose format
        # this parser does not understand (another 7-Zip version or locale).
        # Returning an empty list made the caller believe the listing was fine
        # and run its bomb pre-check over zero entries — extraction without any
        # volume measurement. ``members is None`` is already the caller's
        # "listing failed, do not extract" signal.
        return 0, None, output
    return 0, members, output


def iter_7z_members(
    data: bytes,
    suffix: str,
    passwords: list[str] | None = None,
) -> Iterator[tuple[str, bytes, str | None]]:
    """Yield ``(member_name, member_bytes, error)`` for a 7-Zip container.

    Mirrors :func:`core.archive.iter_zip_members`. ``suffix`` carries the
    original file extension so 7-Zip can pick the right parser. Extraction is
    aborted early once the cumulative extracted volume or entry count exceeds
    the configured bomb-protection limits.
    """
    binary = find_7z_binary()
    if binary is None:
        return
    if passwords is None:
        passwords = []
    candidate_passwords = [None] + list(passwords) + [
        pw for pw in config.load_zip_passwords() if pw not in passwords
    ]

    # 7z needs a file on disk; keep it in a private temp dir we remove after.
    work = Path(tempfile.mkdtemp(prefix="malaz_7z_"))
    # The suffix selects 7-Zip's parser, but it can originate from an archive
    # member name — sanitize it with the shared primitive, which caps the
    # LENGTH as well as the character set. The hand-rolled filter here used to
    # take only the characters: a 200-char suffix pushed the temp path over
    # MAX_PATH, ``write_bytes`` raised, and the exception replaced the whole
    # scan result with CORE_ERROR. Same sink as the four other materialisation
    # sites (clamav, windows_av, office_pipeline, pe_pipeline).
    safe_suffix = safe_temp_suffix(suffix, ".tmp")
    archive_path = work / f"archive{safe_suffix}"
    out_dir = work / "out"
    out_dir.mkdir()
    try:
        archive_path.write_bytes(data)

        # Pre-flight listing: reject bomb-sized archives by their declared
        # header sizes before 7-Zip writes anything to the temp directory.
        # Encrypted-header archives fail to list without a password, so the
        # password candidates are tried here as well.
        rc_list, members, list_output = _list_members(
            binary, archive_path, config.SEVENZIP_TIMEOUT_SECONDS
        )
        # A timeout or an OS error is NOT a password problem: retrying the
        # listing with the other candidates cannot succeed, and each try costs
        # SEVENZIP_TIMEOUT_SECONDS (120 s). Measured: a crafted archive kept a
        # worker busy for 7 x 120 s = 14 minutes for a listing that had already
        # failed. -1 (timeout/OSError) therefore aborts instead of retrying.
        retry_candidates = () if rc_list == -1 else candidate_passwords[1:]
        if rc_list != 0 and rc_list != _LIST_TRUNCATED_RC:
            for pw in retry_candidates:
                rc_list, members, list_output = _list_members(
                    binary, archive_path, config.SEVENZIP_TIMEOUT_SECONDS, pw
                )
                if rc_list == 0 or rc_list == _LIST_TRUNCATED_RC:
                    break
                if rc_list == -1:
                    # A timeout or OS error mid-loop is not a wrong password.
                    # Without this break a crafted archive that fails fast
                    # without a password but hangs WITH one held a worker for
                    # len(candidate_passwords) x SEVENZIP_TIMEOUT_SECONDS —
                    # measured 8 candidates x 120 s = 16 minutes.
                    break
        if rc_list != 0 or members is None:
            # No listing -> no bomb pre-check -> no extraction. A malformed
            # archive that crashes the listing but would extract must not be
            # able to fill the disk unchecked.
            yield (
                "",
                b"",
                (
                    "7-Zip-Listing fehlgeschlagen — Archiv aus Sicherheitsgründen "
                    "nicht entpackt (Bomben-Pre-Check nicht möglich): "
                    f"{_sanitize_7z_output(list_output, work)}"
                ),
            )
            return

        # Path-traversal (zip-slip) detection on the DECLARED names. This is
        # the only place it can happen for RAR/7z: 7-Zip sanitises such names
        # silently while extracting (measured with 26.03 — "../../x",
        # "..\\..\\x" and an absolute path all land INSIDE the output
        # directory), so the extraction reports success, the walk sees only
        # safe names, and the attempt would otherwise leave no trace at all.
        # The ZIP path flags this as ARCH_ZIPSLIP (CRITICAL); RAR/7z must not
        # be the quiet way around it.
        unsafe = [
            name for name, _size in members if not is_safe_member_name(name)
        ]
        if unsafe:
            # Wie beim TAR: nur der echte Escape bekommt den Anker, der
            # ungewoehnliche Name eine eigene, mildere Meldung.
            from .archive import unsafe_name_note

            angriff, mild = split_unsafe_names(unsafe)
            if angriff:
                examples = ", ".join(angriff[:5])
                yield (
                    "",
                    b"",
                    (
                        f"{ZIPSLIP_PREFIX} {len(angriff)} Eintragsname(n) würden beim "
                        f"Entpacken aus dem Zielverzeichnis schreiben (Path Traversal). "
                        f"Beispiele: {examples}"
                    ),
                )
            if mild:
                milder_text = unsafe_name_note(mild)
                if milder_text:
                    yield ("", b"", milder_text)

        declared_total = sum(size for _, size in members)
        if declared_total > config.MAX_UNCOMPRESSED_SIZE:
            yield (
                "",
                b"",
                (f"7-Zip-Archiv abgelehnt: deklariertes Gesamtvolumen "
                 f"{declared_total} Bytes > Limit {config.MAX_UNCOMPRESSED_SIZE} "
                 f"Bytes (Zip-Bomben-Schutz)"),
            )
            return
        if len(members) > config.MAX_ARCHIVE_ENTRIES:
            yield (
                "",
                b"",
                (f"7-Zip-Archiv abgelehnt: {len(members)} Einträge > "
                 f"Limit {config.MAX_ARCHIVE_ENTRIES} (Zip-Bomben-Schutz)"),
            )
            return

        rc = 2
        output = ""
        for pw in candidate_passwords:
            rc, output = _extract(
                binary, archive_path, out_dir, pw, config.SEVENZIP_TIMEOUT_SECONDS
            )
            if rc == 0:
                break
            if rc == -1:  # hard failure (timeout / missing binary)
                yield ("", b"", output)
                return
            if not _looks_like_wrong_password(rc, output):
                break  # some other error; stop trying passwords

        if rc != 0:
            excerpt = _sanitize_7z_output(output, work)
            yield (
                "",
                b"",
                f"7-Zip konnte das Archiv nicht entpacken (Returncode {rc}): {excerpt}",
            )
            return

        # Disk-footprint guard: the pre-flight check above trusts the DECLARED
        # header sizes, but a crafted archive can lie about them. Measure what
        # was ACTUALLY written and abort if it exceeds the bomb limit — the
        # temp directory is wiped in the finally block either way.
        # NOTE (inherent CLI limitation): this runs AFTER the extraction
        # subprocess, so a lying archive can still fill the disk up to the
        # 7-Zip process finishing; the guard bounds the RESULT, not the
        # write itself. (Symlinks excluded — same rule as the member walk
        # below: their stat() would count the TARGET's size.)
        actual_total = sum(
            p.stat().st_size
            for p in out_dir.rglob("*")
            if not p.is_symlink() and p.is_file()
        )
        if actual_total > config.MAX_UNCOMPRESSED_SIZE:
            yield (
                "",
                b"",
                (f"7-Zip-Archiv abgelehnt: tatsächlich entpacktes Volumen "
                 f"{actual_total} Bytes > Limit {config.MAX_UNCOMPRESSED_SIZE} "
                 f"Bytes (Zip-Bomben-Schutz) — deklarierte Header-Größen waren "
                 "offensichtlich gefälscht."),
            )
            return

        # Cross-check the listing against what actually landed on disk. 7-Zip
        # silently turns a member whose name ends in "/" into a DIRECTORY and
        # DROPS its payload: measured with 26.05, a ZIP member "evil.exe/"
        # carrying 88 bytes of PowerShell cradle listed as a file and extracted
        # as an empty folder — the walk saw only the other member, so the
        # payload was never scanned and the archive scored clean. The listing
        # is the only place the loss is visible.
        # COUNTS, not membership: an archive can carry both "evil.exe/" (whose
        # payload 7-Zip drops) and a harmless "evil.exe" (which lands on disk).
        # A set lookup then finds the normalised name and reports nothing —
        # measured bypass. Comparing how many entries claim a name against how
        # many files carry it keeps the dropped one visible.
        from collections import Counter

        on_disk = Counter(
            p.relative_to(out_dir).as_posix().rstrip("/")
            for p in out_dir.rglob("*")
            if not p.is_symlink() and p.is_file()
        )
        listed = Counter(
            name.replace("\\", "/").rstrip("/")
            for name, size in members
            if size > 0
        )
        lost: list[str] = []
        for name, size in members:
            if size <= 0:
                continue
            key = name.replace("\\", "/").rstrip("/")
            if listed[key] > on_disk[key]:
                lost.append(name)
                # One report per missing copy, not one per claim.
                listed[key] -= 1
        if lost:
            examples = ", ".join(lost[:5])
            yield (
                "",
                b"",
                (f"7-Zip hat {len(lost)} Mitglied(er) mit Inhalt NICHT entpackt "
                 f"(z. B. {examples}) — sie wurden nicht analysiert. Ursache ist "
                 "in der Regel ein Name, der auf \"/\" endet: 7-Zip legt dann "
                 "einen Ordner an und verwirft die Nutzlast."),
            )

        extracted_total = 0
        processed = 0
        # Sorted walk gives deterministic member order. Symlinks are excluded:
        # 7-Zip can materialise them (TAR/WIM) and is_file()/read_bytes() would
        # follow the link outside the extraction directory.
        files = sorted(
            p for p in out_dir.rglob("*") if not p.is_symlink() and p.is_file()
        )
        for file_path in files:
            if processed >= config.MAX_ARCHIVE_ENTRIES:
                yield (
                    "",
                    b"",
                    (f"{BUDGET_STOP_PREFIX} Eintrags-Limit {config.MAX_ARCHIVE_ENTRIES} "
                     "erreicht — weitere extrahierte Dateien wurden nicht gelesen."),
                )
                return
            processed += 1

            rel = file_path.relative_to(out_dir).as_posix()
            try:
                size = file_path.stat().st_size
            except OSError as exc:
                yield (rel, b"", f"Eintrag nicht lesbar: {exc}")
                continue

            if size > config.MAX_EXTRACTED_FILE_SIZE:
                yield (
                    rel,
                    b"",
                    f"Eintrag zu groß ({size} Bytes > {config.MAX_EXTRACTED_FILE_SIZE})",
                )
                continue
            if extracted_total + size > config.MAX_UNCOMPRESSED_SIZE:
                yield (
                    "",
                    b"",
                    (f"{BUDGET_STOP_PREFIX} Entpacktes Gesamtvolumen würde Limit "
                     f"{config.MAX_UNCOMPRESSED_SIZE} Bytes überschreiten "
                     "(Zip-Bomben-Schutz) — weitere Mitglieder wurden übersprungen."),
                )
                return

            try:
                member_bytes = file_path.read_bytes()
            except OSError as exc:
                yield (rel, b"", f"Eintrag nicht lesbar: {exc}")
                continue
            extracted_total += len(member_bytes)
            yield (rel, member_bytes, None)
    finally:
        shutil.rmtree(work, ignore_errors=True)
