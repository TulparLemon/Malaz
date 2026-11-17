"""verify_feeds.py — Alter und Integrität der Offline-Datenbanken prüfen.

Reines Lesen des Dateisystems, kein Netz. Prüft:

* Alter der ClamAV-Signaturdatenbank,
* Alter der extern nachgeladenen YARA-Regeln,
* Alter der vier importierten Blocklisten,
* das HMAC-signierte Feed-Manifest (``feed-manifest.json``) gegen die Dateien,
  die der Scanner tatsächlich liest.

Exit-Codes: 0 = alles prüfbar/ok (fehlende oder unsignierte Datenbanken sind
ein Hinweis, kein Fehler), 1 = Manifest verändert oder Inhalt weicht ab
(``tampered``/``changed``/``error``).

    python scripts/verify_feeds.py
    python scripts/verify_feeds.py --json status.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))

from malaz import config  # noqa: E402
from malaz.core.feed_manifest import (  # noqa: E402
    summary,
    update_ages,
    verify_manifest,
)
from malaz.core.feeds import list_states  # noqa: E402


def collect() -> dict:
    ages = update_ages()
    lists = list_states()
    status = verify_manifest()
    return {
        "schema": "malaz.feed-status/1",
        "ages": [
            {"name": entry.name, "age_days": entry.age_days,
             "state": entry.state, "detail": entry.detail}
            for entry in ages
        ],
        "blocklists": [
            {
                "name": state.name,
                "age_days": state.age_days,
                "size_bytes": state.size_bytes,
                "fresh": state.is_fresh(config.FEEDS_AUTO_UPDATE_MIN_AGE_DAYS),
            }
            for state in lists
        ],
        "manifest": {
            "state": status.state,
            "checked_files": status.checked_files,
            "problems": list(status.problems),
            "summary": summary(status),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Alter/Integrität der Offline-Datenbanken")
    parser.add_argument("--json", type=Path, default=None, help="Status als JSON schreiben")
    args = parser.parse_args(argv)

    document = collect()
    print("Aktualität:")
    for entry in document["ages"]:
        print(f"  • {entry['name']}: {entry['detail']} [{entry['state']}]")
    print("Blocklisten:")
    for state in document["blocklists"]:
        if state["age_days"] is None:
            print(f"  • {state['name']}: fehlt")
        else:
            print(
                f"  • {state['name']}: {state['age_days']} Tag(e) alt, "
                f"{state['size_bytes'] / 1024 / 1024:.1f} MB"
                f"{'' if state['fresh'] else ' — veraltet'}"
            )
    print(f"Manifest: {document['manifest']['summary']}")
    for problem in document["manifest"]["problems"]:
        print(f"  !! {problem}", file=sys.stderr)

    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(
            json.dumps(document, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"JSON: {args.json}")
    return 0 if document["manifest"]["state"] not in {
        "tampered", "changed", "error",
    } else 1


if __name__ == "__main__":
    raise SystemExit(main())
