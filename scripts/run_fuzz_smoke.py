"""Deterministischer Fuzz-Smoke ohne Atheris — der Windows-Weg.

Warum dieses Skript existiert
=============================

Atheris baut auf libFuzzer/Clang und ist unter Windows nicht installierbar
(``requirements-fuzz.txt`` gilt nur für Linux/WSL). Die Harnesses in ``fuzz/``
sind aber plattformneutral: sie importieren ausschließlich Parser-Module.
Dieser Treiber fährt dieselben ``fuzz_one``-Funktionen mit einem
deterministischen, geseedeten Mutationslauf über den synthetischen Korpus.
Damit ist die Fuzzing-Härtung auch auf dem Entwicklungsrechner und in CI
nachweisbar, ohne eine einzige echte Probe und ohne Netz.

Was der Lauf NICHT ist
======================

Kein coverage-gesteuerter Fuzzer. Er findet Abstürze nur, wenn die Mutation
zufällig eine problematische Stelle trifft. Die tiefe Suche bleibt Atheris
auf Linux/WSL; dieser Lauf ist die Regressionsbremse für Windows.

Sicherheitsgrenzen: kein Subprozess, kein Netz, keine Datei wird gelesen —
die Analyse-Kontexte zeigen auf nicht existente Pfade (``<fuzz-input>…``).
Eingaben werden nach ``--max-input-bytes`` gekappt; der Prozess-RSS wird
während des Laufs geprüft und der Lauf bricht ab, bevor die Maschine swappt.

Aufruf
======

    .venv\\Scripts\\python.exe scripts\\run_fuzz_smoke.py --runs 10000
    .venv\\Scripts\\python.exe scripts\\run_fuzz_smoke.py --targets pdf,zip
    .venv\\Scripts\\python.exe scripts\\run_fuzz_smoke.py --replay FILE --targets pdf

Exit-Codes: 0 = alle Ziele ohne Crash, 1 = Crash (Eingabe gespeichert),
2 = ungültige Argumente, 3 = Zeitbudget/RSS-Limit, 4 = einzelne Eingabe
überschritt ``--iteration-timeout`` (gespeichert).
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import os
import random
import sys
import time
import traceback
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for _path in (ROOT / "src", ROOT / "scripts", ROOT / "fuzz"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

# Harness-Modul je Ziel. Reihenfolge ist stabil, damit Seed und Ausgabe
# reproduzierbar bleiben.
HARNESSES: tuple[tuple[str, str], ...] = (
    ("pdf", "fuzz_pdf"),
    ("ooxml", "fuzz_ooxml"),
    ("zip", "fuzz_zip"),
    ("eml", "fuzz_eml"),
    ("rtf", "fuzz_rtf"),
    ("swf", "fuzz_swf"),
    ("lnk", "fuzz_lnk"),
    ("pe", "fuzz_pe"),
    ("images", "fuzz_images"),
)

# Welche Korpus-Dateien als Startpunkte dienen (Endungen, kleingeschrieben).
EXTENSIONS: dict[str, tuple[str, ...]] = {
    "pdf": (".pdf",),
    "ooxml": (".doc", ".docm", ".docx", ".xls", ".xlsm", ".xlsx", ".ppt", ".pptm"),
    "zip": (".zip", ".rar", ".tar", ".iso", ".cab", ".7z", ".gz"),
    "eml": (".eml", ".msg"),
    "rtf": (".rtf",),
    "swf": (".swf",),
    "lnk": (".lnk", ".url"),
    "pe": (".exe", ".dll", ".sys"),
    "images": (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".ico",
               ".webp", ".heic", ".avif"),
}

# Minimale OLE-Datei als MSG-Startpunkt: der Korpus enthält keine .msg, und
# ohne einen OLE-Kopf würde der MSG-Zweig nie erreicht.
EXTRA_SEEDS: dict[str, tuple[bytes, ...]] = {
    "eml": (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 504,),
}

# Format-Marker, die eine reine Bit-Mutation praktisch nie erzeugt.
DICTIONARIES: dict[str, tuple[bytes, ...]] = {
    "pdf": (b"%PDF-1.7", b" obj", b"endobj", b"stream\n", b"endstream",
            b"%%EOF", b"xref", b"trailer", b"/JavaScript", b"/OpenAction",
            b"/Launch", b"/ObjStm", b"/Length", b"/Filter", b"/FlateDecode"),
    "ooxml": (b"PK\x03\x04", b"[Content_Types].xml", b"word/document.xml",
              b"xl/workbook.xml", b"docProps/core.xml", b"_rels/.rels",
              b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", b"<?xml version="),
    "zip": (b"PK\x03\x04", b"PK\x05\x06", b"PK\x01\x02", b"../../", b"..\\..\\",
            b"\\..\\", b"C:\\", b"//server/share/", b"file.txt:stream"),
    "eml": (b"From: ", b"To: ", b"Subject: ", b"Content-Type: multipart/mixed; boundary=\"x\"",
            b"--x", b"\r\n\r\n", b"Content-Transfer-Encoding: base64",
            b"attachment; filename=", b"Received: "),
    "rtf": (b"{\\rtf1", b"\\objdata ", b"\\objupdate", b"\\objclass", b"}", b"\\bin"),
    "swf": (b"CWS", b"ZWS", b"FWS", b"\x0f", b"\xff\xff\xff\xff"),
    "lnk": (b"L\x00\x00\x00", b"\x01\x14\x02\x00", b"[InternetShortcut]",
            b"URL=file:///C:/", b"URL=javascript:", b"HotKey="),
    "pe": (b"MZ", b"PE\x00\x00", b"\x0b\x01", b"\x0b\x02", b".text", b".rsrc"),
    "images": (b"\x89PNG\r\n\x1a\n", b"IEND", b"\xff\xd8\xff", b"\xff\xd9",
               b"ftyp", b"heic", b"avif", b"Exif\x00\x00", b"GIF89a",
               b"RIFF", b"WEBP"),
}
_GENERIC_TOKENS = (b"\x00", b"\xff", b"..", b"/", b"\\", b"%s", b"<", b">", b"\r\n")

ENTRY_LIMIT = 64 * 1024


def _rss_mb() -> float:
    """Arbeitsspeicher des Prozesses in MiB (best effort, plattformneutral)."""
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        class _Counters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = _Counters()
        counters.cb = ctypes.sizeof(_Counters)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        # Ohne restype liefert GetCurrentProcess ein abgeschnittenes int statt
        # des Pseudo-Handles; GetProcessMemoryInfo scheitert dann still.
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        handle = kernel32.GetCurrentProcess()
        ok = psapi.GetProcessMemoryInfo(
            ctypes.c_void_p(handle), ctypes.byref(counters), counters.cb
        )
        return counters.WorkingSetSize / (1024 * 1024) if ok else 0.0
    try:
        with open("/proc/self/statm", encoding="ascii") as handle:
            pages = int(handle.read().split()[1])
        return pages * os.sysconf("SC_PAGE_SIZE") / (1024 * 1024)
    except (OSError, ValueError, IndexError):
        return 0.0


def _load_seeds() -> dict[str, list[bytes]]:
    """Synthetische Startpunkte aus dem v2-Korpus, nach Ziel gruppiert."""
    import make_corpus_v2

    fixtures = make_corpus_v2.build_fixtures()
    seeds: dict[str, list[bytes]] = {name: [] for name, _ in HARNESSES}
    for fixture in fixtures:
        suffix = Path(fixture.name).suffix.lower()
        for target, extensions in EXTENSIONS.items():
            if suffix in extensions:
                seeds[target].append(fixture.data)
    for target, extra in EXTRA_SEEDS.items():
        seeds.setdefault(target, []).extend(extra)
    return seeds


def _mutate(
    rng: random.Random,
    seeds: list[bytes],
    tokens: tuple[bytes, ...],
    max_bytes: int,
) -> bytes:
    """Eine deterministische Mutation eines Korpus-Startpunkts."""
    base = seeds[rng.randrange(len(seeds))]
    data = bytearray(base[:max_bytes])
    for _ in range(rng.randint(1, 4)):
        op = rng.randrange(9)
        if not data:
            data = bytearray(rng.choice(tokens or _GENERIC_TOKENS))
            continue
        if op == 0:  # Bit kippen
            pos = rng.randrange(len(data))
            data[pos] ^= 1 << rng.randrange(8)
        elif op == 1:  # Bytes ersetzen
            pos = rng.randrange(len(data))
            end = min(len(data), pos + rng.randint(1, 16))
            data[pos:end] = bytes(rng.randrange(256) for _ in range(end - pos))
        elif op == 2:  # Token einfügen
            pos = rng.randrange(len(data) + 1)
            data[pos:pos] = rng.choice(tokens or _GENERIC_TOKENS)
        elif op == 3:  # Bereich löschen
            start = rng.randrange(len(data))
            end = min(len(data), start + rng.randint(1, 64))
            del data[start:end]
        elif op == 4:  # abschneiden
            del data[rng.randrange(len(data)):]
        elif op == 5:  # Bereich duplizieren
            start = rng.randrange(len(data))
            end = min(len(data), start + rng.randint(1, 32))
            data[start:start] = data[start:end]
        elif op == 6:  # mit einem anderen Seed mischen
            other = seeds[rng.randrange(len(seeds))]
            cut = rng.randrange(len(data) + 1)
            data[cut:cut] = other[: rng.randint(0, min(len(other), 64))]
        elif op == 7:  # Format-Marker an den Anfang
            marker = rng.choice(tokens or _GENERIC_TOKENS)
            data[0:0] = marker
        else:  # NUL-/0xFF-Lauf
            data.extend(bytes([rng.choice((0, 255))]) * rng.randint(1, 32))
        if len(data) > max_bytes:
            del data[max_bytes:]
    return bytes(data)


def _save_crash(crash_dir: Path, target: str, data: bytes) -> Path:
    crash_dir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(data).hexdigest()[:16]
    path = crash_dir / f"{target}-{digest}.bin"
    path.write_bytes(data)
    return path


def _report(input_path: Path, target: str, data: bytes) -> None:
    print(f"\n  Eingabe gespeichert: {input_path}", file=sys.stderr)
    print(
        f"  Reproduktion: .venv\\Scripts\\python.exe scripts\\run_fuzz_smoke.py "
        f"--replay \"{input_path}\" --targets {target}",
        file=sys.stderr,
    )
    print(
        "  Regression: die Datei bleibt in tests/data/fuzz_regressions/ liegen;\n"
        "  der Replay oben ist der Nachweis. Siehe .github/CONTRIBUTING.md.",
        file=sys.stderr,
    )
    print(f"  (Eingabe {len(data)} Bytes)", file=sys.stderr)


def _run_target(
    target: str,
    module_name: str,
    seeds: list[bytes],
    args: argparse.Namespace,
) -> int:
    module = importlib.import_module(module_name)
    one_input = module.fuzz_one
    rng = random.Random(args.seed ^ zlib.crc32(target.encode()))
    tokens = DICTIONARIES.get(target, ())
    crash_dir = Path(args.crash_dir)

    started_all = time.monotonic()
    slowest = 0.0
    rss_peak = 0.0
    for index in range(args.runs):
        if args.timeout and time.monotonic() - started_all > args.timeout:
            print(f"  !! {target}: Zeitbudget {args.timeout}s überschritten "
                  f"nach {index} Läufen", file=sys.stderr)
            return 3
        # Die ersten Läufe sind unveränderte Korpus-Dateien: ein Harness, der
        # schon an einem gültigen Fixture scheitert, ist kein Fuzz-Fund.
        if index < len(seeds):
            data = seeds[index][: args.max_input_bytes]
        else:
            data = _mutate(rng, seeds, tokens, args.max_input_bytes)

        started = time.perf_counter()
        try:
            one_input(data)
        except Exception:
            print(f"\n!! {target}: Crash in Lauf {index + 1}", file=sys.stderr)
            traceback.print_exc()
            _report(_save_crash(crash_dir, target, data), target, data)
            return 1
        elapsed = time.perf_counter() - started
        slowest = max(slowest, elapsed)

        if args.iteration_timeout and elapsed > args.iteration_timeout:
            print(f"\n!! {target}: Eingabe brauchte {elapsed:.1f}s "
                  f"(> {args.iteration_timeout}s) in Lauf {index + 1}",
                  file=sys.stderr)
            _report(_save_crash(crash_dir, target, data), target, data)
            return 4

        if index % 25 == 0:
            rss = _rss_mb()
            rss_peak = max(rss_peak, rss)
            if args.max_rss_mb and rss > args.max_rss_mb:
                print(f"\n!! {target}: RSS {rss:.0f} MiB > Limit "
                      f"{args.max_rss_mb} MiB in Lauf {index + 1}", file=sys.stderr)
                _report(_save_crash(crash_dir, target, data), target, data)
                return 3

    duration = time.monotonic() - started_all
    print(
        f"  {target:6s}: {args.runs:6d} Läufe, {len(seeds):3d} Seeds, "
        f"langsamste Eingabe {slowest * 1000:7.1f} ms, "
        f"RSS max {rss_peak:5.0f} MiB, {duration:6.1f}s — OK"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runs", type=int, default=1000,
                        help="Läufe je Ziel (Standard 1000; Abnahme: 10000)")
    parser.add_argument("--targets", default=",".join(name for name, _ in HARNESSES),
                        help="Kommagetrennte Ziele (Standard: alle)")
    parser.add_argument("--seed", type=int, default=1337, help="Basis-Seed")
    parser.add_argument("--max-input-bytes", type=int, default=ENTRY_LIMIT,
                        help="Eingaben werden auf diese Größe gekappt")
    parser.add_argument("--max-rss-mb", type=int, default=2048,
                        help="Abbruch oberhalb dieses Prozess-RSS (0 = aus)")
    parser.add_argument("--iteration-timeout", type=float, default=10.0,
                        help="Abbruch, wenn EINE Eingabe länger braucht (0 = aus)")
    parser.add_argument("--timeout", type=float, default=0.0,
                        help="Zeitbudget je Ziel in Sekunden (0 = aus)")
    parser.add_argument("--crash-dir", type=Path,
                        default=ROOT / "tests" / "data" / "fuzz_regressions",
                        help="Ablage für Crash-Repros (als Regressionstests)")
    parser.add_argument("--replay", type=Path, default=None,
                        help="Eine gespeicherte Eingabe gegen genau ein Ziel fahren")
    args = parser.parse_args(argv)

    names = [name.strip() for name in args.targets.split(",") if name.strip()]
    known = dict(HARNESSES)
    unknown = [name for name in names if name not in known]
    if unknown:
        parser.error(f"unbekannte Ziele: {', '.join(unknown)}")
    if args.runs < 1:
        # 0 Läufe wären ein grüner Haken ohne Prüfung — genau die Klasse
        # "Test, der nicht beißt", die dieses Projekt abschafft.
        parser.error("--runs muss mindestens 1 sein")

    if args.replay is not None:
        if len(names) != 1:
            parser.error("--replay braucht genau ein Ziel in --targets")
        if not args.replay.is_file():
            parser.error(f"Eingabe fehlt: {args.replay}")
        target = names[0]
        module = importlib.import_module(known[target])
        data = args.replay.read_bytes()
        try:
            module.fuzz_one(data)
        except Exception:
            traceback.print_exc()
            print(f"!! {target}: Replay stürzt weiterhin ab", file=sys.stderr)
            return 1
        print(f"  Replay {args.replay} ({len(data)} Bytes) gegen {target}: OK")
        return 0

    seeds = _load_seeds()
    empty = [name for name in names if not seeds.get(name)]
    if empty:
        parser.error(f"keine Startpunkte für: {', '.join(empty)}")

    print(f"Fuzz-Smoke: {args.runs} Läufe je Ziel, Seed {args.seed}, "
          f"max. Eingabe {args.max_input_bytes} B")
    status = 0
    for name in names:
        status |= _run_target(name, known[name], seeds[name], args)
        if status:
            break
    return status


if __name__ == "__main__":
    raise SystemExit(main())
