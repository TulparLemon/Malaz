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
from ..i18n import get_language, language_context, resolve_language
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


_AUTH_LABELS_EN: dict[str, str] = {
    "pass": "pass",
    "fail": "FAILED",
    "softfail": "softfail",
    "neutral": "neutral",
    "none": "not used",
    "unknown": "unverifiable",
}

_AUTH_LABELS_TR: dict[str, str] = {
    "pass": "başarılı",
    "fail": "BAŞARISIZ",
    "softfail": "kısmi",
    "neutral": "nötr",
    "none": "kullanılmıyor",
    "unknown": "doğrulanamadı",
}


def _tr_mail_score_label(label: str) -> str:
    low = (label or "").lower()
    if "gefährlich" in low or "gefaehrlich" in low or "hoch" in low or "betrug" in low:
        return "Şüpheli"
    if "verdächtig" in low or "verdaechtig" in low or "widerspr" in low or "prüf" in low:
        return "İnceleme gerekli"
    if "nicht beurteilbar" in low or "unbekannt" in low:
        return "Doğrulanamadı"
    if "unauffällig" in low or "unauffaellig" in low or "ok" in low:
        return "Normal"
    return label


def _en_mail_score_label(label: str) -> str:
    low = (label or "").lower()
    if "gefährlich" in low or "gefaehrlich" in low or "hoch" in low or "betrug" in low:
        return "Suspicious"
    if "verdächtig" in low or "verdaechtig" in low or "widerspr" in low or "prüf" in low:
        return "Needs review"
    if "nicht beurteilbar" in low or "unbekannt" in low:
        return "Unverifiable"
    if "unauffällig" in low or "unauffaellig" in low or "ok" in low:
        return "Unremarkable"
    return label


def auth_summary(result: ScanResult, *, lang: str | None = None) -> str:
    """``SPF bestanden | DKIM nicht verwendet | DMARC FEHLGESCHLAGEN``."""
    eff = resolve_language(lang) if lang is not None else get_language()
    security = result.mail_security
    if not security:
        return ""
    if _claim_unbacked(result):
        if eff == "tr":
            return "doğrulanamadı (başlık beyanı sunucu teslimat zinciriyle desteklenmiyor)"
        if eff == "en":
            return "unverifiable (header claim unsupported by server delivery chain)"
        return "nicht beurteilbar (Behauptung ohne Deckung in der Server-Kette)"
    labels = _AUTH_LABELS_TR if eff == "tr" else (_AUTH_LABELS_EN if eff == "en" else AUTH_LABELS)
    fallback = "bilinmiyor" if eff == "tr" else ("unknown" if eff == "en" else "unbekannt")
    parts = [
        f"{name} {labels.get(security.get(key, ''), fallback)}"
        for name, key in (("SPF", "spf"), ("DKIM", "dkim"), ("DMARC", "dmarc"))
    ]
    return " | ".join(parts)


def sender_line(result: ScanResult, *, lang: str | None = None) -> str:
    """Aussage zum Anzeigenamen — oder leer, wenn es keine gibt."""
    eff = resolve_language(lang) if lang is not None else get_language()
    security = result.mail_security
    if not security:
        return ""
    if security.get("sender") == "mismatch":
        if eff == "tr":
            return (
                "Görünen ad gerçek gönderen adresiyle uyuşmuyor — görünen ad "
                "serbestçe yazılabilir, önemli olan gerçek adrestir"
            )
        if eff == "en":
            return (
                "Display name differs from sender address — display names are "
                "freely editable; the actual address matters"
            )
        return (
            "Der Anzeigename weicht von der Absenderadresse ab — der Name ist "
            "frei waehlbar, massgeblich ist die Adresse"
        )
    if security.get("sender") == "ok":
        if eff == "tr":
            return "Görünen ad gönderen adresiyle uyumlu"
        if eff == "en":
            return "Display name matches sender address"
        return "Der Anzeigename passt zur Absenderadresse"
    return ""


def mail_lines(
    result: ScanResult, *, lang: str | None = None
) -> list[tuple[str, str]]:
    """Beschriftung/Wert-Zeilen fuer den Bericht; leer bei Nicht-Mails."""
    if not result.mail_security:
        return []
    eff = resolve_language(lang) if lang is not None else get_language()
    is_en = eff == "en"
    is_tr = eff == "tr"
    with language_context(eff):
        summary = auth_summary(result, lang=eff)
        if is_tr:
            lines: list[tuple[str, str]] = [
                ("Kimlik Doğr.", summary),
                ("Kaynak", "Dosya başlıkları — canlı DNS ile DOĞRULANMADI"),
            ]
        elif is_en:
            lines = [
                ("Sender Auth", summary),
                ("Source", "File headers — NOT verified against live DNS"),
            ]
        else:
            lines = [
                ("Absender-Auth", summary),
                ("Quelle", "Kopfzeilen der Datei — NICHT nachgeprueft"),
            ]
        sender = sender_line(result, lang=eff)
        if sender:
            if is_tr:
                lines.append(("Görünen Ad", sender))
            elif is_en:
                lines.append(("Display Name", sender))
            else:
                lines.append(("Anzeigename", sender))

        from ..core.mail_score import link_scores, sender_score

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
        score_lbl = (
            _tr_mail_score_label(bewertung.label)
            if is_tr
            else (_en_mail_score_label(bewertung.label) if is_en else bewertung.label)
        )
        if is_tr:
            lines.append(("Gönderici", f"{bewertung.score}/100 — {score_lbl}"))
        elif is_en:
            lines.append(("Sender Score", f"{bewertung.score}/100 — {score_lbl}"))
        else:
            lines.append(("Bewertung", f"{bewertung.score}/100 — {score_lbl}"))

        links = getattr(result, "mail_links", None) or []
        auffaellig = [e for e in link_scores(links, limit=len(links)) if e.score > 0]
        if auffaellig:
            for nummer, eintrag in enumerate(auffaellig[:8], start=1):
                grund = eintrag.reasons[0] if eintrag.reasons else ""
                elbl = (
                    _tr_mail_score_label(eintrag.label)
                    if is_tr
                    else (_en_mail_score_label(eintrag.label) if is_en else eintrag.label)
                )
                val = (
                    f"{eintrag.host} — {elbl} ({eintrag.score}/100)"
                    if (is_en or is_tr)
                    else f"{eintrag.host} — {elbl} ({eintrag.score}/100). {grund}"
                )
                lines.append((f"Link {nummer}", val))
            if len(auffaellig) > 8:
                extra = len(auffaellig) - 8
                more_val = (
                    f"… ve {extra} şüpheli bağlantı daha"
                    if is_tr
                    else (
                        f"… and {extra} more suspicious links"
                        if is_en
                        else f"… und {extra} weitere auffaellige"
                    )
                )
                lines.append(("Links", more_val))
        if result.mail_security.get("sender") == "mismatch":
            if is_tr:
                lines.append(
                    (
                        "Not",
                        (
                            "Uyumsuz görünen ad en yaygın oltalama yöntemidir: "
                            "isim tanıdık görünür ama gerçek adres farklıdır"
                        ),
                    )
                )
            elif is_en:
                lines.append(
                    (
                        "Note",
                        (
                            "A mismatched display name is the most common phishing trick: "
                            "the name looks familiar while the actual address is not"
                        ),
                    )
                )
            else:
                lines.append(("Hinweis", HINWEIS_ANZEIGENAME))
        return lines


render_mail_section = mail_lines
