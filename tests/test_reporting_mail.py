"""Das Absender-Urteil im BERICHT — und die Breite seiner Beschriftungen.

WARUM DIESE DATEI EXISTIERT
===========================
Die Anzeige des Absender-Urteils gab es in der Liste, im Detailfeld und in der
CLI, aber nicht im Bericht. Wer eine Mail scannte und den Bericht speicherte,
sah dort nur den Rohbefund ``MAIL_AUTH_FAIL`` — nicht die Aussage
"SPF FEHLGESCHLAGEN | DKIM nicht verwendet | DMARC FEHLGESCHLAGEN" und nicht,
ob der angezeigte Name zur Absenderadresse passt. Der Bericht ist das, was
weitergereicht wird.

Die zweite Pruefung hier ist die wichtigere: die PDF-Spalte fuer die
Beschriftung ist 88 pt breit. "Absender-Authentifizierung" misst 144 pt und
LIEF IN DIE WERTSPALTE HINEIN — im erzeugten PDF ueberlappten Beschriftung und
Wert ("Absender-Authe nicht beurteilbar ... ntifizierung"). Das war im
HTML-Bericht nicht zu sehen, weil dort der Browser umbricht. Eine
Beschriftung, die nicht passt, faellt ohne diese Messung niemandem auf.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from malaz.analysis.clamav import ClamAVScanner
from malaz.analysis.windows_av import WindowsDefenderScanner
from malaz.core.dispatcher import Dispatcher
from malaz.models import RiskLevel, ScanResult
from malaz.reporting.html_report import generate_report
from malaz.reporting.mail_section import mail_lines

# Breite der Beschriftungsspalte in reporting/pdf_report._kv_line.
_PDF_LABEL_WIDTH = 88.0


def _qt_fonts_available() -> bool:
    """Hat Qt überhaupt eine Schrift-Datenbank?

    Im venv/offscreen findet Qt kein Font-Verzeichnis
    (``QFontDatabase: Cannot find font directory``). Dann sind
    ``QFontMetrics`` und die PDF-Textextraktion nicht aussagekräftig, und eine
    Messung/Assertion darauf wäre ein Umgebungsfehler, kein Befund.
    """
    try:
        from PySide6.QtGui import QFontDatabase
    except Exception:
        return False
    return bool(QFontDatabase.families())


def _dispatcher() -> Dispatcher:
    return Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )


def _mail(tmp_path: Path, name: str, header: bytes, auth: bytes = b"") -> Path:
    path = tmp_path / name
    path.write_bytes(
        b"Received: from mx.firma.de (mx.firma.de [203.0.113.9]) by p "
        b"with ESMTPS; Tue, 1 Jan 2030 10:00:00 +0000\r\n"
        + header
        + b"To: opfer@firma.de\r\nSubject: Rechnung\r\nMessage-ID: <x@firma.de>\r\n"
        + auth
        + b"\r\nBitte zahlen.\r\n"
    )
    return path


def test_report_shows_the_sender_verdict(tmp_path):
    """Der Bericht muss die Aussage tragen, nicht nur den Rohbefund."""
    echt = _mail(
        tmp_path,
        "echt.eml",
        b"From: Firma <service@firma.de>\r\n",
        b"Authentication-Results: mx.firma.de; spf=pass; dkim=pass; dmarc=pass\r\n",
    )
    gefaelscht = _mail(
        tmp_path,
        "faelschung.eml",
        b'From: "post@serioese-bank.tld" <boese@evil.tld>\r\n',
        b"Authentication-Results: mx.microsoft.com; spf=pass; dkim=pass; dmarc=pass\r\n",
    )
    notiz = tmp_path / "notiz.txt"
    notiz.write_bytes(b"Nur Text.\n")

    disp = _dispatcher()
    html = generate_report(
        [
            disp.scan_path(echt),
            disp.scan_path(gefaelscht),
            disp.scan_path(notiz),
        ],
        "Test",
    )

    # Die Verfahren mit Urteil, nicht als Rohbefund.
    assert "SPF bestanden | DKIM bestanden | DMARC bestanden" in html
    # Der gefaelschte Anzeigename steht als Satz im Bericht.
    assert "weicht von der Absenderadresse ab" in html
    # Und die Herkunft — ohne diesen Hinweis liest sich die Kopfzeile wie ein
    # Urteil, obwohl sie aus der Datei stammt.
    assert "NICHT nachgeprueft" in html
    # Eine ungedeckte Behauptung darf nicht als "bestanden" erscheinen.
    assert "Behauptung ohne Deckung" in html
    # Fuer Nicht-Mails gibt es keine Absenderzeilen.
    assert html.count("Absender-Auth") == 2, "nur die zwei Mails"


def test_report_says_not_judgeable_when_the_claim_is_unbacked(tmp_path):
    """Eine nicht gedeckte Behauptung ist kein Freispruch.

    Die Kopfzeile behauptet bestandene Authentifizierung; der Server, der sie
    ausgestellt haben will, fehlt in der Kette. Wuerde der Bericht hier
    "SPF bestanden" schreiben, waere das eine Falschaussage — genau die
    Verwechslung von Behauptung und Urteil.
    """
    result = _dispatcher().scan_path(
        _mail(
            tmp_path,
            "ungedeckt.eml",
            b"From: Firma <service@firma.de>\r\n",
            b"Authentication-Results: mx.microsoft.com; spf=pass; dkim=pass; dmarc=pass\r\n",
        )
    )
    summary = dict(mail_lines(result))["Absender-Auth"]
    assert "nicht beurteilbar" in summary
    assert "bestanden" not in summary


def _report_label_literals() -> set[str]:
    """Alle Beschriftungen, die ``mail_lines`` setzen kann — aus dem AST.

    Die fruehere Regex erfasste nur Labels direkt vor ``auth_summary`` /
    ``sender_line`` / ``HINWEIS``. "Quelle", "Bewertung", "Link N" und
    "Links" fehlten damit, d.h. eine zu breite neue Zeile konnte unbemerkt
    zurueckkehren (Audit TEST-021). Gelesen werden alle 2-Tupel, die
    ``lines.append`` bekommt oder in der ``lines``-Liste stehen; f-Strings
    werden mit einer Beispielnummer aufgeloest.
    """
    import ast

    def literal(node: ast.AST) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr):
            return "".join(
                part.value if isinstance(part, ast.Constant) else "1"
                for part in node.values
            )
        return None

    def collect_tuple(node: ast.AST) -> None:
        if isinstance(node, ast.Tuple) and len(node.elts) == 2:
            value = literal(node.elts[0])
            if value:
                labels.add(value)

    labels: set[str] = set()
    quelle = Path("src/malaz/reporting/mail_section.py").read_text(encoding="utf-8")
    for node in ast.walk(ast.parse(quelle)):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "append"
        ):
            for arg in node.args:
                collect_tuple(arg)
        elif (
            isinstance(node, (ast.Assign, ast.AnnAssign))
            and isinstance(node.value, ast.List)
        ):
            for elt in node.value.elts:
                collect_tuple(elt)
    return labels


def test_report_labels_fit_the_pdf_column(qapp):
    """Die wichtigere Pruefung: eine Beschriftung darf die Spalte nicht sprengen.

    Die PDF-Spalte ist 88 pt breit. "Absender-Authentifizierung" misst 144 pt —
    im erzeugten PDF ueberlappten Beschriftung und Wert, sichtbar als
    "Absender-Authe nicht beurteilbar ... ntifizierung". Im HTML-Bericht war
    davon nichts zu sehen, weil der Browser umbricht. Ohne diese Messung faellt
    eine zu lange Beschriftung niemandem auf.

    ``qapp`` statt eines selbst gebauten ``QGuiApplication``: ein QGuiApplication
    ohne QApplication vergiftet die Session, und ein kombinierter Lauf mit
    ``test_mail_viewer`` endete mit Exit 9 ohne Summary (Audit TEST-020).
    """
    QFontMetrics = pytest.importorskip("PySide6.QtGui").QFontMetrics
    from PySide6.QtGui import QGuiApplication

    from malaz.reporting.pdf_report import _font

    assert QGuiApplication.instance() is not None, "qapp hat keine Anwendung erzeugt"

    labels = _report_label_literals()
    assert labels, "keine Beschriftungen gefunden — AST-Anker veraltet?"
    # Die frueher uebersehenen Labels muessen dabei sein, sonst ist der Anker
    # erneut zu schmal und der Test wertlos.
    assert {"Quelle", "Bewertung", "Link 1", "Links"} <= labels, sorted(labels)

    if not _qt_fonts_available():
        pytest.skip(
            "Qt findet keine Schriftarten (offscreen/venv) — die PDF-Spaltenbreite "
            "ist in dieser Umgebung nicht messbar; die Label-Vollständigkeit "
            "oben ist trotzdem geprueft."
        )

    metrics = QFontMetrics(_font(8))
    zu_breit = {
        label: metrics.horizontalAdvance(label)
        for label in labels
        if metrics.horizontalAdvance(label) > _PDF_LABEL_WIDTH
    }
    assert not zu_breit, (
        f"Beschriftungen breiter als die PDF-Spalte ({_PDF_LABEL_WIDTH} pt): "
        + ", ".join(f"{k} = {v:.0f}pt" for k, v in zu_breit.items())
    )


def test_report_carries_the_link_scores_and_sender_score(tmp_path):
    """Die Einzelbewertung der Links gehoert in den Bericht.

    Der Bericht zeigt bisher nur die Sammelbefunde ("irgendwo ist ein
    Kurzlink"). Die Einzelbewertung sagt, WELCHER Link wie riskant ist und
    warum — das ist die Aussage, die der Nutzer pruefen kann.
    """
    from malaz.core.eml_analysis import LinkFacts
    from malaz.models import RiskLevel, ScanResult
    from malaz.reporting.mail_section import mail_lines

    r = ScanResult(
        path="mail.eml",
        detected_type="eml",
        risk_level=RiskLevel.RED,
        score=80,
        mail_security={
            "spf": "fail", "dkim": "fail", "dmarc": "fail", "sender": "mismatch",
        },
        mail_links=[
            LinkFacts(
                url="http://evil.tld/x", host="evil.tld", scheme="http",
                display_text="https://bank.de", mismatch=True,
            ),
            LinkFacts(url="https://shop.de/x", host="shop.de", scheme="https"),
        ],
    )
    zeilen = dict(mail_lines(r))
    assert "Bewertung" in zeilen, zeilen.keys()
    assert "/100" in zeilen["Bewertung"], zeilen["Bewertung"]

    # Der riskante Link steht drin, der harmlose nicht — sonst waere die Liste
    # bei einer Werbe-Mail seitenlang.
    alle = "\n".join(zeilen.values())
    assert "evil.tld" in alle, "der riskante Link fehlt"
    assert "shop.de" not in alle, "der harmlose Link macht die Liste voll"
    assert "nicht anklicken" in alle or "Vorsicht" in alle


def test_child_findings_do_not_change_the_parent_sender_verdict():
    """BUG-043: nur die Befunde DIESER Mail zaehlen fuer den Absender.

    ``MAIL_AUTH_CLAIM_UNBACKED`` im Anhang sagt nichts ueber den Absender der
    Elternmail. Vorher las ``auth_summary``/``sender_score`` den Marker aus
    ``all_indicators()`` (inkl. Kinder): die Elternmail stand als "nicht
    beurteilbar" da und ihre Bewertung war auf 20 gedeckelt.
    """
    from malaz.models import Indicator, ScanResult, Severity
    from malaz.reporting.mail_section import mail_lines

    kind = ScanResult(path="anhang.pdf", detected_type="pdf")
    kind.indicators = [
        Indicator(
            rule_id="MAIL_AUTH_CLAIM_UNBACKED",
            title="Behauptung ohne Deckung",
            severity=Severity.MEDIUM,
        )
    ]
    eltern = ScanResult(path="mail.eml", detected_type="eml")
    eltern.mail_security = {
        "spf": "pass",
        "dkim": "pass",
        "dmarc": "pass",
        "sender": "ok",
        "has_from": "1",
    }
    eltern.children = [kind]

    zeilen = dict(mail_lines(eltern))
    assert zeilen["Absender-Auth"] == "SPF bestanden | DKIM bestanden | DMARC bestanden"
    assert zeilen["Bewertung"].startswith("100/100"), zeilen["Bewertung"]


def test_remaining_link_count_uses_all_scored_links():
    """BUG-047: die Restzahl darf nicht aus der gekappten Liste kommen.

    30 Shortener -> 8 werden gezeigt, also fehlen 22. Vorher wurde auf 25
    begrenzt und ``len(auffaellig) - 8`` gerechnet: "17 weitere".
    """
    from malaz.core.eml_analysis import LinkFacts
    from malaz.models import ScanResult
    from malaz.reporting.mail_section import mail_lines

    result = ScanResult(path="mail.eml", detected_type="eml")
    result.mail_security = {
        "spf": "pass",
        "dkim": "pass",
        "dmarc": "pass",
        "sender": "ok",
        "has_from": "1",
    }
    result.mail_links = [
        LinkFacts(
            url=f"https://kurz{i}.tld/x",
            host=f"kurz{i}.tld",
            scheme="https",
            is_shortener=True,
        )
        for i in range(30)
    ]

    zeilen = dict(mail_lines(result))
    assert [label for label in zeilen if label.startswith("Link ")] == [
        f"Link {i}" for i in range(1, 9)
    ]
    assert zeilen["Links"] == "… und 22 weitere auffaellige", zeilen["Links"]


def test_msg_attachments_are_labelled_as_attachments():
    """BUG-042: eine .msg ist ``ole``, ihre Kinder sind trotzdem Anhaenge."""
    from malaz.models import ScanResult
    from malaz.reporting.html_report import generate_report

    eltern = ScanResult(path="mail.msg", detected_type="ole")
    eltern.mail_security = {
        "spf": "unknown",
        "dkim": "unknown",
        "dmarc": "unknown",
        "sender": "ok",
        "has_from": "1",
    }
    eltern.children = [ScanResult(path="anhang.pdf", detected_type="pdf")]

    html = generate_report([eltern], "Test")
    assert "Anhänge (1):" in html
    assert "Archiveinträge" not in html


def test_pdf_value_lines_mask_attacker_controlled_text(monkeypatch):
    """Auch die WERTZEILEN des PDF muessen maskiert werden.

    ``_kv_line`` zeichnete ``str(value)`` roh, waehrend der Fliesstext daneben
    ueber ``_paragraph`` maskiert wird. Damit ging jeder angreiferkontrollierte
    Wert unmaskiert ins PDF: der Pfad, der Anzeigename und die neue
    Link-Zeile mit dem Host. Qt wendet den Bidi-Algorithmus an — aus
    "rechnung<U+202E>gpj.exe" wird beim Zeichnen "rechnungexe.jpg".
    """
    from malaz.reporting import pdf_report

    gesehen: list[str] = []

    class _FakeRenderer:
        def __init__(self) -> None:
            self.x = self.y = 0.0

        def wrap_lines(self, text, width, font):
            gesehen.append(text)
            return []

        def lines_height(self, lines, font):
            return 0

        def ensure(self, height):
            return None

        def draw_lines_at(self, *args, **kwargs):
            return None

    klass = pdf_report._PdfRenderer
    monkeypatch.setattr(pdf_report, "_PdfRenderer", _FakeRenderer)
    fake = _FakeRenderer()
    pdf_report._kv_line(fake, "Host", "boese.tld/rechnung\u202egpj.exe", 400.0)
    assert gesehen, "der Renderer wurde nicht aufgerufen"
    assert not any("\u202e" in text for text in gesehen), (
        f"U+202E geht unmaskiert ins PDF: {gesehen}"
    )
    assert any("u202e" in text for text in gesehen), "das Zeichen wurde entfernt statt maskiert"
    del klass


def test_real_pdf_contains_no_raw_bidi_character(qtbot, tmp_path):
    """Der staerkste Test: im ERZEUGTEN PDF steht kein U+202E mehr.

    Am gerenderten Dokument gemessen, nicht am Zwischenschritt. ``pypdf``
    extrahiert den Text, den Qt gezeichnet hat — steht das Steuerzeichen dort
    noch, sieht der Leser eine andere Adresse als die echte.
    """
    pypdf = pytest.importorskip("pypdf")
    from PySide6.QtGui import QGuiApplication

    from malaz.reporting.pdf_report import save_pdf_report

    assert QGuiApplication.instance() is not None, "qapp/qtbot hat keine Anwendung erzeugt"

    getarnt = "rechnung\u202egpj.exe"
    r = ScanResult(
        path=f"C:/proben/{getarnt}",
        detected_type="pe",
        risk_level=RiskLevel.RED,
        score=90,
    )
    ziel = save_pdf_report([r], tmp_path / "b.pdf", "Test")
    text = "\n".join(page.extract_text() for page in pypdf.PdfReader(str(ziel)).pages)

    if not text.strip():
        # Ohne Schrift-Datenbank zeichnet Qt nichts und pypdf extrahiert
        # nichts — dann ist die Maskierung nicht messbar. Ein LEERES PDF bei
        # vorhandenen Fonts bleibt dagegen ein Fehlschlag.
        if not _qt_fonts_available():
            pytest.skip(
                "Qt findet keine Schriftarten (offscreen/venv) — der PDF-Text "
                "ist leer und die Bidi-Maskierung nicht messbar."
            )
        pytest.fail("das erzeugte PDF enthält keinen extrahierbaren Text")

    assert "\u202e" not in text, "U+202E steht ungeschuetzt im PDF"
    assert "u202e" in text, "das Zeichen wurde entfernt statt maskiert"


def test_wrap_lines_is_the_masking_sink(qtbot, tmp_path):
    """Die PDF-Senke ist ``wrap_lines`` — die ECHTE Funktion, nicht ein Fake.

    Der erste Anlauf dieses Tests setzte einen Fake-Renderer ein, der
    ``wrap_lines`` ersetzte. Der Fake maskierte nicht, der Test wurde rot, und
    das sah nach einem Befund aus — die echte Funktion maskiert aber laengst
    (siehe ihr Docstring, und die Zeile ``mask_invisible(text)`` im Rumpf).
    Gemessen wurde also der Fake, nicht der Code. Genau die Fehlerklasse, die
    der Audit-Skill "Beweis, der nicht traegt" nennt.

    Hier wird die echte Methode geprueft: sie ist der eine Trichter, durch den
    jeder gezeichnete und jeder gemessene Text laeuft.
    """
    from PySide6.QtGui import QFont, QPdfWriter

    from malaz.reporting.pdf_report import _PdfRenderer

    writer = QPdfWriter(str(tmp_path / "x.pdf"))
    writer.setResolution(72)
    renderer = _PdfRenderer(writer)
    try:
        getarnt = "rechnung\u202egpj.exe"
        zeilen = renderer.wrap_lines(
            f"Die Datei {getarnt} ist auffaellig", 400.0, QFont()
        )
        zusammen = " ".join(zeilen)
        assert "\u202e" not in zusammen, f"unmaskiert: {zusammen!r}"
        assert "u202e" in zusammen, "das Zeichen wurde entfernt statt maskiert"
    finally:
        # Der Renderer haelt einen offenen QPainter auf dem Writer. Ohne
        # ``end()`` bricht der Prozess beim Aufraeumen ab — nicht mit einer
        # Ausnahme, sondern mit einem Absturz.
        renderer.painter.end()


