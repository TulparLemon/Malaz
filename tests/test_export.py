"""CSV- und JSON-Export: Inhalt, Verschachtelung, Maskierung."""

from __future__ import annotations

import csv
import json

from malaz.models import Indicator, RiskLevel, ScanResult, Severity
from malaz.reporting.export import CSV_COLUMNS, write_csv, write_json


def _ergebnis(name: str, score: int, level: RiskLevel, regel: str) -> ScanResult:
    r = ScanResult(
        path=name,
        detected_type="pdf",
        risk_level=level,
        score=score,
        sha256="a" * 64,
        md5="b" * 32,
        duration_ms=12,
    )
    r.indicators.append(
        Indicator(
            rule_id=regel,
            title="Etwas gefunden",
            detail="Details",
            severity=Severity.HIGH,
            category="script",
        )
    )
    return r


def test_csv_has_a_row_per_file_with_stable_rule_ids(tmp_path):
    """Die Regel-IDs sind der Grund fuer den Export: stabil und maschinenlesbar."""
    ziel = write_csv(
        [_ergebnis("boese.pdf", 90, RiskLevel.RED, "PDF_JS")], tmp_path / "e.csv"
    )
    # utf-8-sig, damit Excel die Umlaute richtig zeigt.
    with ziel.open(encoding="utf-8-sig", newline="") as handle:
        zeilen = list(csv.DictReader(handle, delimiter=";"))

    assert len(zeilen) == 1
    assert list(zeilen[0]) == list(CSV_COLUMNS)
    assert zeilen[0]["Name"] == "boese.pdf"
    assert zeilen[0]["Ergebnis"] == "Gefährlich"
    assert zeilen[0]["Score"] == "90"
    assert zeilen[0]["Regeln"] == "PDF_JS"


def test_csv_includes_nested_children_with_their_container_path(tmp_path):
    """Ein Anhang muss als eigene Zeile auftauchen — sonst fehlt die Datei,
    wegen der die Mail ueberhaupt verdaechtig war."""
    kind = _ergebnis("anhang.exe", 95, RiskLevel.RED, "PE_PACKED")
    kind.depth = 1
    eltern = _ergebnis("mail.eml", 80, RiskLevel.RED, "MAIL_AUTH_FAIL")
    eltern.detected_type = "eml"
    eltern.children.append(kind)

    ziel = write_csv([eltern], tmp_path / "e.csv")
    with ziel.open(encoding="utf-8-sig", newline="") as handle:
        zeilen = list(csv.DictReader(handle, delimiter=";"))

    assert len(zeilen) == 2
    assert zeilen[0]["Tiefe"] == "0"
    assert zeilen[1]["Tiefe"] == "1"
    assert zeilen[1]["Name"] == "anhang.exe"
    assert "mail.eml" in zeilen[1]["Pfad"], zeilen[1]["Pfad"]
    assert "Anhang" in zeilen[1]["Pfad"], "die Art des Kindes fehlt"


def test_csv_labelled_msg_attachments_as_attachments(tmp_path):
    """BUG-042: eine .msg erkennt der Scanner als ``ole``, nicht als ``msg``.

    Der CSV-Containerpfad nannte ihre Anhaenge deshalb "Eintrag", als waeren
    sie Archivmitglieder.
    """
    kind = _ergebnis("anhang.exe", 95, RiskLevel.RED, "PE_PACKED")
    eltern = _ergebnis("mail.msg", 80, RiskLevel.RED, "MAIL_AUTH_FAIL")
    eltern.detected_type = "ole"  # so meldet es der Scanner fuer eine .msg
    eltern.mail_security = {
        "spf": "unknown",
        "dkim": "unknown",
        "dmarc": "unknown",
        "sender": "ok",
        "has_from": "1",
    }
    eltern.children.append(kind)

    ziel = write_csv([eltern], tmp_path / "e.csv")
    with ziel.open(encoding="utf-8-sig", newline="") as handle:
        zeilen = list(csv.DictReader(handle, delimiter=";"))

    assert "Anhang" in zeilen[1]["Pfad"], zeilen[1]["Pfad"]
    assert "Eintrag" not in zeilen[1]["Pfad"], zeilen[1]["Pfad"]


def test_json_is_nested_and_complete(tmp_path):
    """JSON bildet den Baum ab, wie gescannt wurde."""
    kind = _ergebnis("anhang.exe", 95, RiskLevel.RED, "PE_PACKED")
    eltern = _ergebnis("mail.eml", 80, RiskLevel.RED, "MAIL_AUTH_FAIL")
    eltern.detected_type = "eml"
    eltern.children.append(kind)

    ziel = write_json([eltern], tmp_path / "e.json")
    daten = json.loads(ziel.read_text(encoding="utf-8"))

    assert daten["tool"] == "Malaz"
    assert daten["count"] == 1
    datei = daten["files"][0]
    assert datei["name"] == "mail.eml"
    assert datei["findings"][0]["rule"] == "MAIL_AUTH_FAIL"
    # Das Urteil steht als deutsches Wort UND als Stufe drin: das Wort fuer den
    # Menschen, die Stufe fuer ein Skript, das filtern will.
    assert datei["findings"][0]["severity"] == "Hoch"
    assert datei["risk"] == "Gefährlich"
    assert datei["score"] == 80
    assert len(datei["children"]) == 1
    assert datei["children"][0]["name"] == "anhang.exe"


def test_export_masks_invisible_characters(tmp_path):
    """Ein Steuerzeichen im Namen ist in CSV/JSON unsichtbar, aber vorhanden.

    Wer die Tabelle in Excel oeffnet, liest sonst eine andere Datei als die,
    die dasteht — dieselbe Regel wie in der Oberflaeche und im Bericht.
    """
    getarnt = "rechnung\u202egpj.exe"
    r = _ergebnis(getarnt, 90, RiskLevel.RED, "PE_PACKED")

    csv_ziel = write_csv([r], tmp_path / "e.csv")
    roh = csv_ziel.read_text(encoding="utf-8-sig")
    assert "\u202e" not in roh, "U+202E steht unmaskiert in der CSV"
    assert "u202e" in roh, "der Hinweis auf das Zeichen fehlt ganz"

    json_ziel = write_json([r], tmp_path / "e.json")
    daten = json.loads(json_ziel.read_text(encoding="utf-8"))
    name = daten["files"][0]["name"]
    assert "\u202e" not in name
    assert "u202e" in name


def test_export_handles_an_empty_result_list(tmp_path):
    """Keine Ergebnisse ist kein Fehler — die Datei entsteht mit Kopfzeile."""
    ziel = write_csv([], tmp_path / "leer.csv")
    with ziel.open(encoding="utf-8-sig", newline="") as handle:
        zeilen = list(csv.DictReader(handle, delimiter=";"))
    assert zeilen == []

    json_ziel = write_json([], tmp_path / "leer.json")
    daten = json.loads(json_ziel.read_text(encoding="utf-8"))
    assert daten["count"] == 0 and daten["files"] == []


def test_csv_neutralises_formula_prefixes(tmp_path):
    """Ein Dateiname darf in Excel keine Formel werden.

    Name und Pfad sind angreiferkontrolliert, und die CSV ist ausdruecklich
    fuer Excel gedacht. Eine Datei namens
    ``=HYPERLINK("http://boese.tld","Rechnung")`` landet sonst als AKTIVE
    Formel in der Tabelle — der Schaden trifft den Nutzer, der die Datei
    oeffnet. Gemessen vor dem Fix: die Pfad-Zelle begann mit "=".
    """
    faelle = [
        '=HYPERLINK("http://boese.tld","Rechnung")',
        "+1+1",
        "-2+3",
        "@SUM(A1)",
        "\tcmd",
        "\rcmd",
    ]
    for name in faelle:
        r = ScanResult(
            path=name, detected_type="pdf", risk_level=RiskLevel.RED, score=90
        )
        ziel = write_csv([r], tmp_path / "e.csv")
        with ziel.open(encoding="utf-8-sig", newline="") as handle:
            zeilen = list(csv.DictReader(handle, delimiter=";"))
        for spalte in ("Name", "Pfad"):
            zelle = zeilen[0][spalte]
            assert zelle[:1] not in ("=", "+", "-", "@", "\t", "\r"), (
                f"{spalte} beginnt mit {zelle[:1]!r} — in Excel eine Formel: {zelle!r}"
            )
        # Entschaerft heisst sichtbar gemacht, nicht verfaelscht: der volle Wert
        # steht weiterhin da (im Pfad, den die Anzeige nicht kuerzt).
        assert name in zeilen[0]["Pfad"], zeilen[0]["Pfad"]
        assert zeilen[0]["Name"], "die Namensspalte ist leer"


def test_json_keeps_the_plain_value(tmp_path):
    """JSON ist fuer Programme — ein fuehrendes Hochkomma waere Datenverlust.

    Die CSV ist die Tabellen-Ausgabe und wird entschaerft; JSON ist die
    Datenschnittstelle. Wer JSON in eine Tabelle kippt, muss das dort tun.
    """
    name = "=HYPERLINK(\"http://boese.tld\",\"Rechnung\")"
    r = ScanResult(path=name, detected_type="pdf", risk_level=RiskLevel.RED, score=90)
    ziel = write_json([r], tmp_path / "e.json")
    daten = json.loads(ziel.read_text(encoding="utf-8"))
    assert daten["files"][0]["path"] == name, "der Wert wurde verfaelscht"
