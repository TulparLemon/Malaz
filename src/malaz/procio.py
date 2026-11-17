"""Decoding of external-tool subprocess output and console suppression.

Windows console tools (MpCmdRun, 7z, clamscan) write to pipes using the OEM
code page (e.g. cp850 on German systems), not UTF-8. Decoding such output as
UTF-8 with ``errors="replace"`` turns every umlaut into U+FFFD, which silently
breaks the German phrase matching in the AV engines ("quarantäne" never
matches). UTF-8 is tried first — pure-ASCII output decodes identically either
way — and anything that is not valid UTF-8 falls back to the OEM code page
on Windows.

The same module owns the ``creationflags`` that keep these tools invisible:
a GUI process (pythonw.exe) has no console, so every console application it
spawns would otherwise flash its own black window.
"""

import os
import re
import subprocess
import threading
import time
from contextlib import suppress
from pathlib import Path, PureWindowsPath

_VERDICT_WORDS = frozenset(
    {
        # English verdict vocabulary (mirrors windows_av._THREAT/_CLEAN/
        # _REMEDIATION_PHRASES and external-scanner marker conventions).
        "action",
        "cleaned",
        "cleaning",
        "deleted",
        "detected",
        "finished",
        "found",
        "malware",
        "no",
        "quarantined",
        "remediated",
        "removed",
        "started",
        "successfully",
        "taken",
        "threat",
        "threats",
        "virus",
        # German equivalents (MpCmdRun is localised).
        "bedrohung",
        "bedrohungen",
        "bereinigt",
        "durchgeführt",
        "entfernt",
        "erkannt",
        "gefunden",
        "gelöscht",
        "keine",
        "maßnahme",
        "quarantine",
        "quarantäne",
        "schadsoftware",
        "trojaner",
        "unter",
        "viren",
    }
)

# Zeilen, in denen ein Scanner den Zielpfad echoet. Nur hier ist ein blanker
# Dateiname beweisbar der Pfad-Echo und darf entfernt werden. Steht der Name
# dagegen allein in einer Ergebniszeile, ist er Dateninhalt/Urteil und bleibt
# stehen — sonst loescht eine Datei namens "found 1 threats" genau die
# Urteilsphrase, die der Scanner daneben geschrieben hat (SEC-018).
_ECHO_LINE_RE = re.compile(
    r"^\s*(?:scanning\b|scan\b|file\s*:|datei\s*:)",
    re.IGNORECASE,
)


def strip_scan_target(output: str, target: str) -> str:
    """Remove the scanned path (and bare file name) from tool output.

    Scanner CLIs echo the scanned path in lines like ``Scanning <path> found
    no threats.``. Because that path is user/attacker controlled, verdict
    phrases must never be matched against it — a folder named ``quarantine``
    or a file called ``threat detected.pdf`` would otherwise flip the verdict.

    The bare file name is removed ONLY on echo lines (``Scanning …``,
    ``file: …``). A standalone token elsewhere is the tool's own output and is
    left untouched, even when it is byte-identical to the file name.
    """
    if not target:
        return output
    stripped = output
    try:
        win_name = PureWindowsPath(target).name
        if (
            ("/" in target or "\\" in target)
            and target != Path(target).name
            and target != win_name
        ):
            # Full path: contains separators, plain removal is safe. Match
            # BOTH separator spellings — a tool may echo backslashes while
            # the target was normalised to forward slashes (or vice versa);
            # a style mismatch would leave the directory token in the text.
            stripped = re.sub(re.escape(target), "", stripped, flags=re.IGNORECASE)
            flipped = (
                target.replace("\\", "/")
                if "\\" in target
                else target.replace("/", "\\")
            )
            if flipped != target:
                stripped = re.sub(
                    re.escape(flipped), "", stripped, flags=re.IGNORECASE
                )
        # Bare file name: ONLY inside an explicit scan-echo line ("Scanning
        # …", "file: …"). A bare token elsewhere is tool output — possibly the
        # verdict itself. Global removal deleted every occurrence, including
        # Defender's own "found 1 threats" result next to the echo, so a real
        # detection of a file with that name was read as clean (SEC-018).
        #
        # Word boundaries only — plain substring removal would also mangle
        # verdict phrases ("found 1 threats" with a file named "threat" became
        # "found 1 s").
        #
        # If the name IS itself a verdict word ("threat", "virus", …), keep
        # it even in the echo line: stripping it would delete the verdict word
        # from a genuine finding line and turn it into a False Negative. The
        # full-path strip (above) already removed the attacker-controlled path
        # echo, so only the bare token remains.
        name = Path(target).name
        if (
            name
            and re.sub(r"\.\w+$", "", name).lower() not in _VERDICT_WORDS
            and name.lower().rstrip(". ") not in _VERDICT_WORDS
        ):
            # BEIDE FORMEN entfernen. Der Echo kommt in der OEM-Codepage
            # zurueck: Zeichen, die sie nicht kennt, werden zu "?". Eine Datei
            # "threat detected ✓.pdf" erscheint dann als
            # "threat detected ?.pdf" — und ein byte-genauer Vergleich trifft
            # sie NICHT, der Name bleibt im Text stehen.
            #
            # GEMESSEN, in beide Richtungen:
            #   Datei "threat detected ✓.pdf", Scan SAUBER  -> "threat"
            #   Datei "found no threats ✓.pdf", Scan TREFFER -> "clean"
            # Ein Dateiname darf ein Urteil nicht kippen — in KEINE Richtung.
            # Beide Namen sind Verdict-Phrasen, also greift die Ausnahme oben
            # nicht, und der Echo blieb stehen.
            #
            # Deshalb zusaetzlich die verstuemmelte Form: jedes Zeichen
            # ausserhalb von ASCII wird zu "?", genau wie die OEM-Codepage es
            # tut. Damit faellt der Echo weg, BEVOR der Text zum Urteil kommt —
            # an der Wurzel statt mit einer Heuristik auf den Phrasen.
            # ZWEI FORMEN, und nur die eine Richtung ist noetig.
            #
            # Der Zielpfad kommt aus windows_av.py:390 so, wie er AUF DER
            # PLATTE steht ("threat detected ✓.pdf"); der Echo zurueck
            # kommt in der OEM-Codepage, in der ✓ zu "?" wird. Die
            # byte-genaue Entfernung trifft ihn deshalb nicht, er bleibt im
            # Text stehen — und kippt das Urteil, weil "threat detected"
            # zufaellig eine Trefferphrase ist.
            #
            # Die UMGEKEHRTE Richtung (Ziel verstuemmelt, Echo echt) ist
            # bewusst NICHT abgedeckt — nicht weil sie unmoeglich waere (mit
            # "?" als Platzhalter liesse sie sich treffen), sondern weil sie
            # hier nicht BEGEHBAR ist: der Aufrufer uebergibt den Pfad so, wie
            # er auf der Platte steht. Ein Platzhalter waere Mehraufwand fuer
            # einen Fall, den kein Aufrufer herstellt.
            #
            # Wird spaeter ein Aufrufer mit verstuemmeltem Ziel ergaenzt, ist
            # dieser Zweig die Stelle, die nachzuziehen ist.
            varianten = (name, "".join(ch if ch.isascii() else "?" for ch in name))
            zeilen = []
            for zeile in stripped.splitlines(keepends=True):
                # Nur Echo-Zeilen: der Zeilenanfang beweist, dass der Name
                # hinter "Scanning"/"file:" der Pfad-Echo ist. Eine Zeile wie
                # das blanke "found 1 threats" des Scanners bleibt unberuehrt,
                # auch wenn die Datei genauso heisst.
                #
                # clamscan echoet stattdessen "<pfad oder name>: OK" — auch
                # dieser Zeilenanfang ist ein Echo. Ein Urteil wie
                # "found 1 threats" hat keinen Doppelpunkt hinter dem Namen
                # und bleibt damit geschuetzt.
                ist_echo = bool(_ECHO_LINE_RE.match(zeile))
                if not ist_echo:
                    anfang = zeile.lstrip().lower()
                    for variante in varianten:
                        if (
                            variante
                            and anfang.startswith(variante.lower())
                            and anfang[len(variante) :].lstrip().startswith(":")
                        ):
                            ist_echo = True
                            break
                if ist_echo:
                    for variante in varianten:
                        if variante:
                            zeile = re.sub(
                                rf"\b{re.escape(variante)}\b",
                                "",
                                zeile,
                                flags=re.IGNORECASE,
                            )
                zeilen.append(zeile)
            stripped = "".join(zeilen)
    except re.error:  # defensive: pathological names must not break parsing
        return output
    return stripped


def no_window_flags() -> int:
    """``creationflags`` value for subprocess calls that must stay invisible.

    ``CREATE_NO_WINDOW`` prevents console applications (MpCmdRun, clamscan,
    7z, PowerShell, …) from opening their own console window when the parent
    is a console-less GUI process. Returns 0 on non-Windows platforms, where
    ``creationflags`` must be zero.
    """
    if os.name == "nt":
        return subprocess.CREATE_NO_WINDOW
    return 0


def safe_temp_suffix(suffix: str | None, default: str = ".bin", max_len: int = 16) -> str:
    """Sanitize a file suffix before it is used for a temp file name.

    Suffixes regularly originate from archive member names (attacker
    controlled): separators/absolute parts must never reach ``mkstemp``, the
    length is capped so a 250-char "suffix" cannot overflow the Windows path
    limit, and only ASCII alphanumerics plus ``.-_`` survive (Unicode
    look-alikes have no business in a temp name).
    """
    cleaned = "".join(
        ch if (ch.isascii() and (ch.isalnum() or ch in ".-_")) else "_"
        for ch in (suffix or "")
    )
    core = cleaned[:max_len].lstrip(".")
    if not core:
        return default
    return "." + core


def decode_tool_output(raw: bytes | None) -> str:
    """Decode subprocess output: UTF-8 first, OEM code page as fallback."""
    if not raw:
        return ""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    if os.name == "nt":
        with suppress(LookupError, ValueError):
            return raw.decode("oem", errors="replace")
    return raw.decode("utf-8", errors="replace")


class HardShutdown(RuntimeError):
    """Raised by :func:`run_tool` when the app is shutting down and the
    subprocess was killed for it."""


# Set when the application is closing: every engine subprocess still running
# is killed instead of blocking the exit for up to its full timeout
# (90 s AV / 120 s 7-Zip per process — the "window closed, zombie process"
# case). Cooperative cancel (Abbrechen-Button) deliberately does NOT set
# this: there the current file is allowed to finish.
_HARD_SHUTDOWN = threading.Event()


def request_hard_shutdown() -> None:
    _HARD_SHUTDOWN.set()


def clear_hard_shutdown() -> None:
    _HARD_SHUTDOWN.clear()


def hard_shutdown_requested() -> bool:
    return _HARD_SHUTDOWN.is_set()


# Bounded tool-output buffer (SEC-023). Normal engine output is a few KiB per
# scan; a prepared 7z/RAR whose listing names millions of entries pushed
# ``pipe.read()`` past 64 MiB and into the OOM path. Each pipe keeps at most
# this prefix and DISCARDS the rest — while still draining to EOF: stopping
# the read would fill the 64 KiB pipe buffer and block the child in write()
# until the timeout killed it (a tool with legitimately long output would then
# look like a failure). 8 MiB is far above Defender/clamscan/7z normal output.
# Hitting the cap is reported via ToolResult.truncated: the kept bytes are only
# a prefix, and no caller may parse them as a complete result (a cut-off threat
# line or half a JSON document would otherwise read as clean/success).
MAX_TOOL_OUTPUT_BYTES = 8 * 1024 * 1024
_PUMP_CHUNK = 64 * 1024


class ToolResult(tuple):
    """``(rc, stdout, stderr)`` plus an explicit truncation flag (SEC-023).

    Subclassing ``tuple`` keeps every ``rc, out, err = run_tool(...)`` caller
    working unchanged. ``truncated`` is True when at least one stream reached
    :data:`MAX_TOOL_OUTPUT_BYTES` and the rest was discarded: the returned
    bytes are then only a PREFIX of what the tool wrote. A parser MUST treat
    that as "not checked" — reading the visible part as a complete document
    would silently turn a cut-off verdict (a threat line beyond the cap, half
    a JSON object) into a clean/success result.
    """

    truncated: bool

    def __new__(
        cls,
        rc: int,
        stdout: bytes,
        stderr: bytes,
        truncated: bool = False,
    ) -> "ToolResult":
        result = super().__new__(cls, (rc, stdout, stderr))
        result.truncated = bool(truncated)
        return result


def tool_output_truncated(result: tuple) -> bool:
    """True when ``run_tool`` had to cut the output (SEC-023).

    Accepts plain ``(rc, stdout, stderr)`` tuples too (test fakes and older
    call sites return those): without the flag the output counts as complete —
    exactly the behaviour before the flag existed.
    """
    return bool(getattr(result, "truncated", False))


def run_tool(
    args: list[str],
    timeout: float | None = 90.0,
    input: bytes | None = None,
    env: dict[str, str] | None = None,
) -> ToolResult:
    """Run an external tool and return ``(rc, stdout, stderr)``.

    The returned :class:`ToolResult` unpacks like the plain tuple it replaces;
    its ``truncated`` flag says whether ``MAX_TOOL_OUTPUT_BYTES`` cut the
    captured output (callers must treat that as "not checked").

    Drop-in for ``subprocess.run(..., capture_output=True)`` with the Malaz
    invariants built in: no console window (GUI), bounded waiting, and an
    immediate ``kill()`` when the application is shutting down
    (:class:`HardShutdown`) or the timeout expires
    (``subprocess.TimeoutExpired`` — both re-raised after cleanup, callers
    already translate them into skip reasons).
    """
    proc = subprocess.Popen(
        args,
        stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        env=env,
        creationflags=no_window_flags(),
    )

    def _pump(pipe, buffer: list) -> None:
        chunks: list[bytes] = []
        kept = 0
        cut = False
        with suppress(Exception):
            while True:
                chunk = pipe.read(_PUMP_CHUNK)
                if not chunk:
                    break
                room = MAX_TOOL_OUTPUT_BYTES - kept
                if room <= 0:
                    cut = True
                    continue  # drain without keeping (bounds memory only)
                if len(chunk) > room:
                    chunk = chunk[:room]
                    cut = True
                chunks.append(chunk)
                kept += len(chunk)
        with suppress(Exception):
            pipe.close()
        buffer.append((b"".join(chunks), cut))

    out_buf: list[tuple[bytes, bool]] = []
    err_buf: list[tuple[bytes, bool]] = []
    readers = [
        threading.Thread(target=_pump, args=(proc.stdout, out_buf), daemon=True),
        threading.Thread(target=_pump, args=(proc.stderr, err_buf), daemon=True),
    ]
    for reader in readers:
        reader.start()
    if input is not None:
        stdin = proc.stdin

        def _feed() -> None:
            with suppress(Exception):
                if stdin is not None:
                    stdin.write(input)
            with suppress(Exception):
                if stdin is not None:
                    stdin.close()

        threading.Thread(target=_feed, daemon=True).start()

    deadline = None if timeout is None else time.monotonic() + timeout
    killed_reason: Exception | None = None
    while True:
        try:
            proc.wait(timeout=0.25)
            break
        except subprocess.TimeoutExpired:
            pass
        if hard_shutdown_requested():
            killed_reason = HardShutdown(
                f"abgebrochen (Programm wird beendet): {args[0]}"
            )
            break
        if deadline is not None and time.monotonic() >= deadline:
            killed_reason = subprocess.TimeoutExpired(
                cmd=args, timeout=timeout if timeout is not None else 0.0
            )
            break

    if killed_reason is not None:
        with suppress(Exception):
            proc.kill()
        with suppress(Exception):
            proc.wait(timeout=5)
        # Close the pipes ourselves: a grandchild process that inherited the
        # write end keeps it open, and the reader threads would block in
        # read() forever (leaked threads, silently empty output). Closing
        # makes read() raise and the threads terminate.
        for pipe in (proc.stdout, proc.stderr):
            with suppress(Exception):
                if pipe is not None:
                    pipe.close()

    for reader in readers:
        reader.join(timeout=5)
    stdout, stdout_cut = out_buf[0] if out_buf else (b"", False)
    stderr, stderr_cut = err_buf[0] if err_buf else (b"", False)
    if killed_reason is not None:
        raise killed_reason
    return ToolResult(
        proc.returncode, stdout, stderr, truncated=stdout_cut or stderr_cut
    )
