"""Pure text/formatting helpers preserved from main_window for reports & tests."""

from __future__ import annotations

from ..core.mail_view import AUTH_LABELS, MAX_DISPLAY_CHARS, _clip
from ..models import (
    CAT_ARCHIVE,
    CAT_AV,
    CAT_CONTENT,
    CAT_ENTROPY,
    CAT_FORMAT,
    CAT_HASHLIST,
    CAT_IOC,
    CAT_MACRO,
    CAT_MAIL,
    CAT_METADATA,
    CAT_RESOURCE,
    CAT_SCRIPT,
    CAT_SIGNATURE,
    CAT_STEGO,
    CAT_STRUCTURE,
    CATEGORY_EXPLANATIONS,
    ScanResult,
    type_description,
)
from ..security.escaping import mask_invisible

_AUTH_MARK = {"pass": "\u2713", "fail": "\u2717", "none": "\u2013", "unknown": "?"}




def _verdict_cell(result: ScanResult) -> str:
    """Die Ampelszelle — mit sichtbarer Unvollstaendigkeit.

    Der Grundsatz: *was wir nicht geprüft haben, darf nicht wie geprüft
    aussehen.* Ein Grün auf einer Datei, deren Makro-Stufe mangels Bibliothek
    nie lief, ist kein Freispruch. Ohne diesen Zusatz sieht die Zeile aus wie
    eine geprüfte saubere Datei — die Stufenmeldungen tragen Gewicht 0 und
    ändern den Score nicht.

    Ausgeschrieben statt als Symbol: ein Warnzeichen muss man kennen, den
    Satz versteht jeder. Die Spalte ist breit genug.
    """
    kurz = result.risk_level.short
    if result.is_incomplete:
        return f"{kurz} (unvollständig)"
    return kurz


def _mail_security_summary(result) -> str:
    """Kurzfassung fuer die Listenzeile: ``SPF \u2717 \u00b7 DKIM \u2717 \u00b7 DMARC \u2717``.

    Leer fuer alles, was keine Mail ist \u2014 eine Spalte voller Striche waere
    Rauschen. Die Zeichen: \u2713 bestanden, \u2717 nicht verwendet oder
    fehlgeschlagen, ? nicht beurteilbar.
    """
    sec = getattr(result, "mail_security", None)
    if not sec:
        return ""
    # KURZ halten: die Zelle wird umgebrochen, und ein Umbruch schneidet den
    # Rest ab (im Screenshot fehlte genau die Absender-Warnung). Deshalb steht
    # die wichtigste Aussage VORNE und die Trennzeichen sind knapp.
    rules = {ind.rule_id for ind in result.all_indicators()}
    unbacked = "MAIL_AUTH_CLAIM_UNBACKED" in rules
    # Ist die Behauptung nicht gedeckt, sind die Verfahren NICHT beurteilbar —
    # ein Haekchen waere hier eine Falschaussage. Vorher stand neben einer
    # gefaelschten Mail "SPF\u2713 DKIM\u2713 DMARC\u2713", weil die Anzeige die
    # Behauptung wie ein Urteil las.
    parts = [
        f"{name}{'?' if unbacked else _AUTH_MARK.get(sec.get(key, ''), '?')}"
        for name, key in (("SPF", "spf"), ("DKIM", "dkim"), ("DMARC", "dmarc"))
    ]
    text = " ".join(parts)
    warnungen = []
    if unbacked:
        warnungen.append("\u26a0 Auth nicht gedeckt")
    if sec.get("sender") == "mismatch":
        warnungen.append("\u26a0 Name \u2260 Adresse")
    if warnungen:
        return " | ".join([*warnungen, text])
    return text


def _mail_security_tooltip(result) -> str:
    """Die Langfassung als Tooltip \u2014 die Spalte selbst bleibt schmal."""
    sec = getattr(result, "mail_security", None)
    if not sec:
        return ""
    rules = {ind.rule_id for ind in result.all_indicators()}
    lines = ["Absender-Sicherheit (aus den Kopfzeilen der Mail, NICHT verifiziert):"]
    if "MAIL_AUTH_CLAIM_UNBACKED" in rules:
        lines.append(
            "  ! Die Kopfzeile behauptet bestandene Authentifizierung durch einen "
            "Server, der in der Received-Kette nicht vorkommt — die Angaben unten "
            "sind damit NICHT beurteilbar."
        )
    for name, key in (("SPF", "spf"), ("DKIM", "dkim"), ("DMARC", "dmarc")):
        lines.append(f"  {name}: {AUTH_LABELS.get(sec.get(key, ''), 'unbekannt')}")
    sender = sec.get("sender")
    if sender == "mismatch":
        lines.append(
            "  Anzeigename: weicht von der Absenderadresse ab \u2014 der Name kann "
            "frei gewaehlt sein, massgeblich ist die Adresse."
        )
    elif sender == "ok":
        lines.append("  Anzeigename: passt zur Absenderadresse.")
    else:
        lines.append("  Anzeigename: nicht beurteilbar.")
    return "\n".join(lines)

# Short display names for the indicator categories (layman wording).
_CATEGORY_NAMES = {
    CAT_STRUCTURE: "Dateiaufbau",
    CAT_SCRIPT: "Skripte",
    CAT_MACRO: "Makros",
    CAT_STEGO: "Verborgene Daten",
    CAT_ARCHIVE: "Archiv-Inhalt",
    CAT_ENTROPY: "Verschlüsselung/Kompression",
    CAT_SIGNATURE: "Signatur-Treffer",
    CAT_FORMAT: "Dateiformat",
    CAT_METADATA: "Metadaten",
    CAT_RESOURCE: "Eingebettete Objekte",
    CAT_AV: "Virenscanner",
    CAT_HASHLIST: "Bekannte Schad-Datei",
    CAT_IOC: "Verdächtige Adressen",
    CAT_CONTENT: "Inhalt",
    CAT_MAIL: "E-Mail-Auffälligkeiten",
}



def _group_by_category(result: ScanResult) -> list[tuple[str, str, list]]:
    """Group indicators by category, worst category first.

    Returns (category_name, explanation, indicators) triples.
    """
    groups: dict[str, list] = {}
    for ind in result.indicators:
        groups.setdefault(ind.category, []).append(ind)

    def worst(group: list) -> int:
        return max(ind.severity for ind in group)

    ordered = sorted(groups.items(), key=lambda kv: worst(kv[1]), reverse=True)
    out = []
    for category, inds in ordered:
        name = _CATEGORY_NAMES.get(category, category)
        explanation = CATEGORY_EXPLANATIONS.get(category, "Weitere Auffälligkeiten.")
        out.append((name, explanation, sorted(inds, key=lambda i: i.severity, reverse=True)))
    return out


def _format_detail(result: ScanResult, indent: int = 0) -> str:
    """Render a result as plain text with a layman-friendly structure.

    Layout: verdict → recommendation → what was found (grouped, explained) →
    technical details → mail content → nested archive members.

    The invisible/bidi masking sits on the whole rendered text, at the one
    place every field leaves this module (mirrors ``escape_html`` on the HTML
    side). Masking per call site covered the fields someone remembered —
    indicator title/detail and the path — and missed ``result.error``, which
    carries the Zip-Slip note with the raw entry name; a U+202E in it reached
    the panel unmodified (Qt applies the bidi algorithm to plain text, so it
    displayed as a different name). Masking a second time is a no-op.
    """
    pad = "  " * indent
    lines: list[str] = []
    if result.error:
        lines.append(f"{pad}Hinweis: {result.error}")
        lines.append("")

    # GANZ OBEN, vor dem Urteil. Der Nutzer liest die erste Zeile und
    # entscheidet danach; eine Fussnote am Ende erreicht ihn nicht mehr. Eine
    # Datei, deren Makro-Stufe mangels Bibliothek nie lief, ist nicht
    # freigesprochen — sie ist UNGEPRUEFT.
    if result.is_incomplete:
        lines.append(f"{pad}⚠ {result.incompleteness_note()}")
        lines.append("")

    groups = _group_by_category(result)
    lines.append(f"{pad}Was wurde gefunden?")
    if not groups:
        lines.append(f"{pad}  Keine Auffälligkeiten.")
    for name, explanation, inds in groups:
        lines.append(f"{pad}  ■ {name}")
        lines.append(f"{pad}    {explanation}")
        for ind in inds:
            lines.append(f"{pad}    – [{ind.severity.label}] {ind.title}")
            if ind.detail:
                for dl in ind.detail.splitlines() or [ind.detail]:
                    lines.append(f"{pad}        {dl}")
    lines.append("")

    if result.mail_preview:
        # THE MAIL ITSELF, not just the rule names: headers, decoded TEXT body,
        # annotated links, attachment names — plain text on purpose, since the
        # HTML body is attacker-controlled and the project never renders
        # untrusted markup (see core.mail_view).
        #
        # Rendered HERE, at every depth, and not appended to the top-level row:
        # a mail inside a ZIP or attached to another mail is exactly the case an
        # analyst must be able to read, and those are nested results.
        lines.append("")
        for preview_line in result.mail_preview.rstrip("\n").splitlines():
            lines.append(f"{pad}{preview_line}" if preview_line else "")

    if result.children:
        # A mail carries attachments, an archive carries members — calling both
        # "archive contents" made a scanned .eml read like a ZIP.
        noun = "Anhänge" if result.detected_type == "eml" else "Einträge"
        lines.append("")
        lines.append(f"{pad}Enthaltene {noun} ({len(result.children)}):")
        for child in result.children:
            lines.append("")
            lines.append(_format_detail(child, indent + 1))
    return mask_invisible("\n".join(lines))


def _format_technical(result: ScanResult, indent: int = 0) -> str:
    """Ebene 3: die Rohdaten — Hashes, Typ, Dauer, Ankerregel.

    Getrennt vom Befundtext, weil es eine andere Leserschaft hat: der Laie
    braucht es nicht, wer die Datei an einen Dienstleister weitergibt schon.
    Beides in einem Feld zu mischen war der Grund, warum der erste Satz des
    Detailfelds eine Zahl war statt einer Handlung.

    Die Maskierung liegt wie bei _format_detail auf dem fertigen Text: der Pfad
    kann aus einem Archivmitglied stammen und ist damit angreiferkontrolliert.
    """
    pad = "  " * indent
    type_text = type_description(result.detected_type, result.mime_hint)
    # Gekuerzt wie in core/mail_view: der Pfad eines Archivmitglieds ist
    # angreiferkontrolliert und darf bis 65 535 Zeichen lang sein. Gemessen
    # erzeugte ein 60 000-Zeichen-Name eine Einzelzeile von 60 013 Zeichen.
    # _clip setzt einen sichtbaren Hinweis — ein stiller Schnitt wuerde genau
    # den Trick verbergen, den die Analyse meldet.
    lines = [
        f"{pad}Datei: {_clip(result.path, MAX_DISPLAY_CHARS)}",
        f"{pad}Typ: {type_text}",
        f"{pad}Groesse: {result.size} Bytes",
        f"{pad}SHA-256: {result.sha256 or '—'}",
        f"{pad}MD5: {result.md5 or '—'}",
        f"{pad}Dauer: {result.duration_ms} ms",
        f"{pad}Score: {result.score}/100 ({result.risk_level.short})",
    ]
    if result.av_discount:
        lines.append(
            f"{pad}AV-Nachlass: -{result.av_discount} Punkte durch "
            f"AV-ohne-Fund (der Virenscanner hat nichts gefunden)"
        )
    if result.anchored:
        lines.append(
            f"{pad}Anker-Regel: aktiv — ein kritischer Befund erzwingt "
            f"mindestens diese Stufe"
        )
    for child in result.children:
        lines.append("")
        lines.append(
            f"{pad}--- {_clip(child.display_name, MAX_DISPLAY_CHARS)} ---"
        )
        lines.append(_format_technical(child, indent + 1))
    return mask_invisible("\n".join(lines))
