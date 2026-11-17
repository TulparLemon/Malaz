"""Import SHA-256 hashes from local threat feeds into the Malaz blocklist.

Usage (from the project root, venv active):

    python scripts/import_blocklist.py FEED.txt [WEITERER.txt ...] [--dry-run]

A "feed" is any local text file containing SHA-256 hashes — one per line,
as CSV/TSV columns, or embedded in JSON. Well-formed 64-char hex tokens are
extracted; duplicates and invalid tokens are skipped. The blocklist itself
stays offline: importing a file you already have never touches the network.

Hashes are written to the per-user file (``config.USER_HASH_BLOCKLIST_FILE``,
``%LocalAppData%\\Malaz\\hashes\\blocklist.sha256``), NOT to the curated
``rules/hashes/blocklist.sha256``: that one is tracked by git, so imported
third-party hashes would end up inside releases. Loading merges both files.
Pass ``--target`` to write somewhere else (tests do this).

Public feeds you can download once and import manually (mind each feed's
license): e.g. abuse.ch (malwarebazaar / threatfox hashes), VirusShare lists
or your organisation's internal IOC export.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Make `malaz` importable when the package is not installed (source layout).
_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from malaz import config  # noqa: E402
from malaz.core.hashlist import extract_sha256_hashes, load_blocklist, merge_blocklist  # noqa: E402
from malaz.core.url_reputation import url_hash  # noqa: E402


def _is_url_line(line: str) -> bool:
    """True for a feed line that carries an http(s) URL.

    ``#`` starts a comment, empty lines are skipped. Only http/https count —
    the lookup hashes exactly these, and a stray word must not become a
    "blocklist entry" whose hash can never match a real link.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return False
    lowered = stripped.lower()
    return lowered.startswith(("http://", "https://"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="import_blocklist",
        description="SHA-256-Hashes aus lokalen Feed-Dateien in die Malaz-Blocklist übernehmen.",
    )
    parser.add_argument("feeds", nargs="+", metavar="DATEI", help="lokale Feed-Datei(en)")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="nur anzeigen, was übernommen würde (nichts schreiben)",
    )
    parser.add_argument(
        "--target",
        metavar="DATEI",
        default=None,
        help=(
            "Zieldatei für die Importe "
            f"(Standard: {config.USER_HASH_BLOCKLIST_FILE})"
        ),
    )
    parser.add_argument(
        "--urls",
        action="store_true",
        help=(
            "Feed enthält URLs (eine pro Zeile, z. B. URLhaus) — es werden die "
            "SHA-256-Hashes der URLs gespeichert, nicht die URLs selbst"
        ),
    )
    args = parser.parse_args(argv)
    target = Path(args.target) if args.target else None

    hashes: list[str] = []
    for feed in args.feeds:
        path = Path(feed)
        if not path.is_file():
            print(f"!! Nicht gefunden: {path}", file=sys.stderr)
            return 1
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            print(f"!! Nicht lesbar: {path} ({exc})", file=sys.stderr)
            return 1
        if args.urls:
            urls = [ln.strip() for ln in text.splitlines() if _is_url_line(ln)]
            found = [url_hash(u) for u in urls]
            print(f"[+] {path.name}: {len(urls)} URLs gefunden -> {len(found)} Hashes")
        else:
            found = extract_sha256_hashes(text)
            print(f"[+] {path.name}: {len(found)} SHA-256-Hashes gefunden")
        hashes.extend(found)

    if not hashes:
        print("Keine Hashes gefunden — nichts zu tun.")
        return 0

    unique = sorted(set(hashes))
    dest = target if target is not None else Path(
        config.URL_BLOCKLIST_FILE if args.urls else config.USER_HASH_BLOCKLIST_FILE
    )
    # `merge_blocklist` dedupliziert gegen die UNION aus kuratierter und
    # Nutzerliste nur, wenn kein `path` uebergeben wird. Genau das ist fuer den
    # Standardimport gewollt; ein expliziter `path` schaltet die kuratierte
    # Liste aus und liesse Duplikate zu (BUG-090).
    merge_curated = dest == Path(config.USER_HASH_BLOCKLIST_FILE)
    existing = len(load_blocklist() if merge_curated else load_blocklist(dest))
    print(f"[*] {len(unique)} eindeutige Hashes, Blocklist hat aktuell {existing} Einträge.")

    if args.dry_run:
        print(f"[Dry-Run] Ziel wäre {dest} — es wurde nichts geschrieben.")
        return 0

    label = ",".join(Path(f).name for f in args.feeds)[:80]
    # Standardziel NICHT explizit uebergeben: `path=None` laesst
    # `merge_blocklist` gegen die Union aus kuratierter und Nutzerliste
    # deduplizieren. `--target` liegt ausserhalb dieser beiden Listen und
    # wird deshalb weiterhin explizit gesetzt.
    if merge_curated:
        added = merge_blocklist(unique, source_label=label)
    else:
        added = merge_blocklist(unique, source_label=label, path=dest)
    # Nur verwaltete Ziele bekommen ein Manifest; --target (Tests, Sonderfälle)
    # liegt außerhalb der vier Blocklisten und wird nicht signiert.
    managed = {
        Path(config.USER_HASH_BLOCKLIST_FILE),
        Path(config.URL_BLOCKLIST_FILE),
        Path(config.DOMAIN_BLOCKLIST_FILE),
        Path(config.IP_BLOCKLIST_FILE),
    }
    if dest in managed:
        try:
            from malaz.core.feed_manifest import write_manifest

            write_manifest()
        except Exception as exc:
            print(f"!! Feed-Manifest nicht geschrieben: {exc}", file=sys.stderr)
    print(f"[OK] {added} neue Hashes in {dest} übernommen.")
    if added == 0:
        print("    (alle Hashes waren bereits gelistet)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
