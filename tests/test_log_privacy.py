"""Die Logdatei darf die Dateinamen des Nutzers nicht enthalten.

Sie ist die Datei, die bei einem Problem weitergereicht wird — an den Support,
an die IT, in ein Forum. Darin standen die vollstaendigen Pfade jeder
gepruefte Datei, also der Inhalt eines fremden Rechners.
"""

from __future__ import annotations

import logging

from malaz.core.log_privacy import AnonymizeFilter, anonymize, anonymize_name


def test_windows_and_posix_paths_are_anonymised():
    faelle = [
        r"C:\Users\Alex\Steuer\Scheidung 2026.pdf",
        r"C:\Users\Alex\Rechnungen\gehalt_2026.docx",
        "/home/alex/privat/arztbrief.pdf",
        r"\\server\freigabe\geheim.docx",
    ]
    for pfad in faelle:
        text = anonymize(f"scanning {pfad}")
        assert pfad.rsplit("\\" if "\\" in pfad else "/", 1)[-1] not in text, text
        assert "<datei:" in text, f"kein Platzhalter fuer {pfad!r}"
        # Die ENDUNG bleibt: sie entscheidet ueber den Analysepfad und ist
        # fuer die Diagnose nuetzlich.
        endung = pfad.rsplit(".", 1)[-1]
        assert endung in text, f"die Endung fehlt: {text!r}"


def test_the_token_is_stable_and_not_reversible():
    """Dieselbe Datei -> derselbe Name, aber nicht zurueckrechenbar."""
    a = anonymize(r"C:\a\geheim.pdf")
    b = anonymize(r"C:\a\geheim.pdf")
    c = anonymize(r"C:\a\anderes.pdf")
    assert a == b, "derselbe Pfad ergibt verschiedene Namen — Ablauf unlesbar"
    assert a != c, "verschiedene Pfade ergeben denselben Namen"
    assert "geheim" not in a, a


def test_text_without_a_path_is_unchanged():
    for text in ("", "kein Pfad hier", "Scan abgeschlossen: 3 Dateien"):
        assert anonymize(text) == text


def test_extension_cannot_forge_a_log_line():
    """SEC-004: ``evil.pdf\\nINFO SCAN CLEAN`` must stay one token/one line."""
    token = anonymize_name("evil.pdf\nINFO SCAN CLEAN")
    assert "\n" not in token, repr(token)
    assert "INFO" not in token and "SCAN" not in token, token
    assert token.endswith(".pdf>"), token


def test_escape_sequences_and_cr_are_neutralised():
    """SEC-040: control characters outside a path survived into malaz.log."""
    out = anonymize("vorher \x1b[31mrot\x1b[0m\rnach")
    assert "\x1b" not in out
    assert "\r" not in out
    assert "\\x1b" in out


def test_bare_filename_is_redacted():
    """SEC-040: ``secret.pdf`` without a path separator leaked the name."""
    out = anonymize("Datei secret.pdf konnte nicht gelesen werden")
    assert "secret" not in out, out
    assert "<datei:" in out
    assert "secret.pdf" not in out


def test_filter_covers_message_arguments():
    """``log.info("scan %s", pfad)`` legt den Pfad in record.args.

    Nur ``record.msg`` zu maskieren liesse genau die Schreibweise unmaskiert,
    die dieses Projekt am haeufigsten benutzt.
    """
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="scanning %s and %s",
        args=(r"C:\Users\Alex\geheim.pdf", r"C:\Users\Alex\auch-geheim.docx"),
        exc_info=None,
    )
    AnonymizeFilter().filter(record)
    assert "geheim" not in record.getMessage(), record.getMessage()
    assert "<datei:" in record.getMessage()


def test_explicit_display_name_is_hashed_even_without_a_path():
    token = anonymize_name("README.md")
    assert token.startswith("<datei:")
    assert token.endswith(".md>")
    assert "README" not in token


def test_dispatcher_stage_log_does_not_write_bare_filename(caplog):
    import logging

    from malaz.core.dispatcher import Dispatcher
    from malaz.models import CAT_AV, Indicator, ScanResult, Severity

    result = ScanResult(path="README.md")
    result.indicators = [
        Indicator(
            rule_id="AV_SKIPPED",
            title="Defender übersprungen",
            category=CAT_AV,
            severity=Severity.INFO,
            weight=0,
        )
    ]
    with caplog.at_level(logging.INFO, logger="malaz.core.dispatcher"):
        Dispatcher.__new__(Dispatcher)._log_stages(result)
    assert "README.md" not in caplog.text
    assert "<datei:" in caplog.text


def test_formatter_redacts_traceback_paths_and_email_identities():
    import logging

    from malaz.core.log_privacy import AnonymizeFormatter

    try:
        raise OSError(r"C:\Users\Alex\secret\mail.eml")
    except OSError:
        import sys

        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname=__file__,
            lineno=1,
            msg="failure for alice@example.com",
            args=(),
            exc_info=sys.exc_info(),
        )
    text = AnonymizeFormatter("%(message)s").format(record)
    assert "Alex" not in text
    assert "alice@example.com" not in text
    assert "<datei:" in text
    assert "<email:" in text


def test_filter_never_raises_on_strange_arguments():
    """Ein Filter darf den Scan nie anhalten."""
    record = logging.LogRecord(
        name="test", level=logging.INFO, pathname=__file__, lineno=1,
        msg="x %s", args=(object(),), exc_info=None,
    )
    assert AnonymizeFilter().filter(record) is True


def test_filter_keeps_non_string_arguments(tmp_path):
    """Zahlen duerfen nicht zu Text werden — sonst bricht %d.

    Der Filter hat vorher JEDES Argument mit ``str()`` belegt. ``log.info(
    "%d Dateien", 3)`` scheiterte danach mit "TypeError: %d format: a real
    number is required, not str" — und zwar im Log-Pfad, also genau dann, wenn
    etwas schiefgeht. Gemessen: vier Tests in tests/test_import_blocklist.py
    wurden dadurch rot.
    """
    record = logging.LogRecord(
        name="test", level=logging.INFO, pathname=__file__, lineno=1,
        msg="%d Dateien, %s gescannt", args=(3, r"C:\a\geheim.pdf"),
        exc_info=None,
    )
    AnonymizeFilter().filter(record)
    # Wuerde die Zahl zu "3" werden, wirft getMessage hier einen TypeError.
    text = record.getMessage()
    assert text.startswith("3 Dateien"), text
    assert "geheim" not in text
