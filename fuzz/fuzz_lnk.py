"""Atheris-Harness: Windows-Shell-Link (``.lnk``) und ``.url``-Parser.

``parse_lnk`` liest die ShellLink-Header, ID-Listen, LinkInfo und
String-Daten. Der ``.url``-Pfad (INI mit ``URL=``) lebt in der
Generic-Pipeline; hier werden genau dessen Parser und Ziel-Bewertung
gefahren, nicht die gesamte Pipeline.
"""

from _support import load, run

(parse_lnk,) = load("malaz.core.lnk", "parse_lnk")
(defang_url,) = load("malaz.core.url_view", "defang_url")
(_parse_shortcut_values, _shortcut_reasons) = load(
    "malaz.pipelines.generic_pipeline",
    "_parse_shortcut_values",
    "_shortcut_reasons",
)

TARGET = "lnk"


def fuzz_one(data: bytes) -> None:
    parse_lnk(data)
    values = _parse_shortcut_values(data)
    target = values.get("url", "").strip()
    if target:
        defang_url(target[:512])
        _shortcut_reasons(target)


if __name__ == "__main__":
    run(fuzz_one)
