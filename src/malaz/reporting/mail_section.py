"""Das Absender-Urteil als Berichtstext — fuer HTML und PDF dieselbe Quelle.

WARUM DIESE DATEI EXISTIERT
===========================
Die Anzeige des Absender-Urteils gab es in der Liste, im Detailfeld und in der
CLI — aber NICHT im Bericht. Wer eine Mail scannte und den Bericht speicherte,
sah dort nur den Rohbefund ``MAIL_AUTH_FAIL`` und nicht die Aussage
"SPF FEHLGESCHLAGEN | DKIM nicht verwendet | DMARC FEHLGESCHLAGEN" und auch
nicht, ob der angezeigte Name zur Absenderadresse passt. Der Bericht ist das,
was weitergereicht wird.

Zwei Renderer (HTML, PDF) brauchen denselben Inhalt. Getrennt formuliert
laufen sie auseinander — dieselbe Fehlerklasse wie beim Adressmuster, das in
zwei Modulen stand. Deshalb liefert diese Datei nur DATEN (Zeilen aus
Beschriftung und Wert); die Renderer entscheiden ueber die Darstellung.
"""

from __future__ import annotations

# Wortwahl aus core/mail_view importiert, NICHT kopiert: derselbe Sachverhalt
# darf im Bericht nicht anders heissen als im Detailfeld. Die Kopie stand hier
# wortgleich und war fuer scripts/check_duplicate_logic.py unsichtbar, weil der
# Pruefer nur Skalare verglich (ein dict-Literal ist ein ast.Dict, kein
# ast.Constant) — er meldete "Keine unbegruendeten Dopplungen" zu zwei
# identischen Tabellen. Der Pruefer vergleicht jetzt auch Sammlungen.
from ..core.mail_view import AUTH_LABELS
from ..models import ScanResult

# Die Regel, die eine ungedeckte Behauptung meldet. Steht sie an, sind die
# Verfahren NICHT beurteilbar — ein Haken waere eine Falschaussage.
_UNBACKED = "MAIL_AUTH_CLAIM_UNBACKED"

# Ein einzelnes Literal: als Tupelelement wollte ruff mal die implizite, mal
# die explizite Verkettung — beides ist hier unnoetig.
HINWEIS_ANZEIGENAME = (
    "Ein abweichender Anzeigename ist die haeufigste Taeuschung: der Name "
    "sieht vertraut aus, die Adresse ist es nicht"
)


def is_mail_result(result: ScanResult) -> bool:
    """Ist dieses Ergebnis eine Mail, deren Kinder ANHAENGE sind?

    ``detected_type`` allein genuegt nicht: eine Outlook-``.msg`` wird als
    ``ole`` erkannt (der Container), nicht als ``msg``. ``mail_security``
    setzt der Dispatcher nur fuer echte Mails — deshalb ist es das zweite,
    verlaessliche Signal. Ohne es hiessen die Anhaenge einer ``.msg`` im
    Bericht "Archiveintraege".
    """
    return result.detected_type in ("eml", "msg") or bool(result.mail_security)


def _claim_unbacked(result: ScanResult) -> bool:
    """Nur die Befunde DIESER Mail zaehlen — nicht die ihrer Kinder.

    ``all_indicators()`` zieht Anhaenge/Archivmitglieder mit herein. Ein
    Befund im Anhang sagt aber nichts ueber den Absender der Elternmail;
    vorher erbte die Elternmail das Kind-Urteil ("nicht beurteilbar",
    Bewertung gedeckelt auf 20).
    """
    return any(ind.rule_id == _UNBACKED for ind in result.indicators)


def auth_summary(result: ScanResult) -> str:
    """``SPF bestanden | DKIM nicht verwendet | DMARC FEHLGESCHLAGEN``."""
    security = result.mail_security
    if not security:
        return ""
    if _claim_unbacked(result):
        # Die Behauptung ist nicht gedeckt: was in der Kopfzeile steht, ist
        # damit keine Aussage ueber den Absender.
        return "nicht beurteilbar (Behauptung ohne Deckung in der Server-Kette)"
    parts = [
        f"{name} {AUTH_LABELS.get(security.get(key, ''), 'unbekannt')}"
        for name, key in (("SPF", "spf"), ("DKIM", "dkim"), ("DMARC", "dmarc"))
    ]
    return " | ".join(parts)


def sender_line(result: ScanResult) -> str:
    """Aussage zum Anzeigenamen — oder leer, wenn es keine gibt."""
    security = result.mail_security
    if not security:
        return ""
    if security.get("sender") == "mismatch":
        return (
            "Der Anzeigename weicht von der Absenderadresse ab — der Name ist "
            "frei waehlbar, massgeblich ist die Adresse"
        )
    if security.get("sender") == "ok":
        return "Der Anzeigename passt zur Absenderadresse"
    return ""


def mail_lines(result: ScanResult) -> list[tuple[str, str]]:
    """Beschriftung/Wert-Zeilen fuer den Bericht; leer bei Nicht-Mails.

    Der Hinweis auf die fehlende Nachpruefbarkeit ist keine Verzierung: in
    einer zugestellten Mail schreibt der empfangende Server die Kopfzeile, in
    einer Datei, die der Nutzer analysiert, sind es Bytes, die der Angreifer
    kontrolliert.
    """
    if not result.mail_security:
        return []
    # Die Beschriftungen sind KURZ, weil die PDF-Spalte 88 pt breit ist:
    # "Absender-Authentifizierung" misst 144 pt und lief in die Wertspalte
    # hinein (im erzeugten PDF ueberlappten Beschriftung und Wert). Die Grenze
    # haelt tests/test_reporting_mail.py fest.
    lines: list[tuple[str, str]] = [
        ("Absender-Auth", auth_summary(result)),
        ("Quelle", "Kopfzeilen der Datei — NICHT nachgeprueft"),
    ]
    sender = sender_line(result)
    if sender:
        lines.append(("Anzeigename", sender))

    # Die Bewertung als Zahl — dieselbe, die das E-Mail-Panel in der
    # Oberflaeche zeigt. Ohne sie stuende im Bericht nur "Absender-Angaben
    # widerspruechlich", ohne wie schwer das wiegt.
    from ..core.mail_score import sender_score

    # "has_from" fuehrt die Tatsache aus dem Parser. Fehlt der Marker (aeltere
    # Ergebnisse, Parse-Fehler), gilt wie bisher "Absender vorhanden"; bool()
    # des Dicts ist KEIN Nachweis, weil die Auth-Keys immer gesetzt sind.
    marker = result.mail_security.get("has_from")
    hat_absender = marker is None or str(marker).strip().lower() not in (
        "",
        "0",
        "false",
    )
    bewertung = sender_score(
        result.mail_security,
        result.mail_security.get("sender", "unknown"),
        claim_unbacked=_claim_unbacked(result),
        has_from=hat_absender,
    )
    lines.append(
        ("Bewertung", f"{bewertung.score}/100 — {bewertung.label}")
    )

    # Die einzelnen Links mit ihrer Bewertung. Nur die auffaelligen: eine
    # Werbe-Mail traegt hundert Links, und der Bericht soll die gefaehrlichen
    # zeigen, nicht die Menge.
    from ..core.mail_score import link_scores

    # Alle Links bewerten, DANN filtern: vorher begrenzte ``link_scores`` auf
    # 25, und die Restzahl wurde aus dieser gekappten Liste berechnet. Bei 30
    # Shortenern stand "17 weitere", obwohl 22 fehlten.
    links = getattr(result, "mail_links", None) or []
    auffaellig = [e for e in link_scores(links, limit=len(links)) if e.score > 0]
    if auffaellig:
        # Eine Zeile je Link, damit die Tabelle im PDF nicht auseinanderfaellt.
        for nummer, eintrag in enumerate(auffaellig[:8], start=1):
            grund = eintrag.reasons[0] if eintrag.reasons else ""
            lines.append(
                (
                    f"Link {nummer}",
                    f"{eintrag.host} — {eintrag.label} ({eintrag.score}/100). {grund}",
                )
            )
        if len(auffaellig) > 8:
            lines.append(
                ("Links", f"… und {len(auffaellig) - 8} weitere auffaellige")
            )
    if result.mail_security.get("sender") == "mismatch":
        lines.append(
            (
                "Hinweis",
                HINWEIS_ANZEIGENAME,
            )
        )
    return lines
