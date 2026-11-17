"""Plain-text rendering of a parsed mail for the GUI detail panel.

The mail analysis in :mod:`core.eml_analysis` already extracts everything an
analyst wants to see — headers, decoded text body, annotated links, attachment
names. Until now those facts were used for the findings and then **discarded**;
the user saw rule names ("MAIL_LINK_IP_LITERAL") but never the mail itself.

Design constraints, all deliberate:

* **Plain text, never HTML.** ``MailFacts.html_body`` is attacker-controlled.
  Rendering it would add a parser surface for no analytical gain — the body's
  *signals* are already extracted as indicators. The whole project uses
  ``setPlainText`` and never ``setHtml`` (verified), and no ``QTextBrowser``
  exists. This module keeps that invariant.
* **No clickable links.** The only ``QDesktopServices.openUrl`` in the project
  opens a *local* file ("nothing leaves the machine"). A clickable phishing
  link would break that: opening it tells the attacker the address is live.
  Links are therefore printed as selectable text, with their annotations
  (mismatch, IP literal, punycode) inlined — which is more informative than a
  click anyway.
* **No second parse.** The dispatcher hands the rendered text to the result, so
  opening a row costs nothing — and the link list is ``facts.links``, filled
  once by ``parse_mail``/``parse_msg``. Re-extracting it here ran the anchor
  scan twice per mail.
* **Both mail containers.** ``.eml`` reaches this module as parsed
  ``MailFacts`` (via :mod:`core.eml_analysis`); an Outlook ``.msg`` is an
  OLE/CFB container that MIME parsing never sees, so :func:`parse_msg` reads
  the flat ``__substg1.0_*`` property streams into the *same* ``MailFacts``
  shape. One renderer, one set of masking rules — the container the mail
  arrived in must not change what the analyst gets to see.

The renderer is pure (no Qt), so it is unit-testable and shared by the GUI
detail panel. Untrusted strings pass through ``security.escaping.mask_invisible``
(first line of defence for invisible/bidi controls — see that module for the
measurement). If this text is ever wired into the HTML report, it must
additionally go through ``escape_html`` / ``_esc_newlines`` like every other
untrusted string there.
"""

from __future__ import annotations

import io
import re
from contextlib import suppress
from pathlib import Path

from .. import config
from ..security.escaping import mask_invisible
from .email_extract import _ATTACH_NAME_STREAMS
from .eml_analysis import ADDRESS_IN_DISPLAY_RE, DOMAIN_IN_ADDRESS_RE, MailFacts, extract_links
from .ole_depth import directory_frames, walk_headroom

# Cap so a pathological mail cannot flood the panel; the analysis limits are
# separate and stay in effect.
_MAX_BODY_CHARS = 20_000
# Header fields are attacker-controlled too, and they reach the GUI panel AND
# the CLI summary. Measured before this cap: a mail with a 200 000-character
# Subject produced a 600 KB preview with ONE 200 027-character line — the body
# was capped at 20 000 and the headers were not. Real header values are far
# below this; a hit here is a finding in itself, so the cut is announced.
_MAX_HEADER_CHARS = 500


# Grenze fuer angezeigte Werte in allen Ausgabewegen (GUI-Tabelle, Panels,
# Bericht, Mail-Anzeige). Ein Archivmitglied darf bis 65 535 Zeichen heissen;
# ohne Grenze wurde der HTML-Bericht fuer EINE Datei 125 173 Zeichen lang und
# ein Panel-Label 300 040 Zeichen breit.
#
# EINE Konstante, nicht vier: sie stand zwischenzeitlich mit demselben Wert in
# gui/main_window, gui/mail_panel und beiden Reportmodulen — gefunden von
# scripts/check_duplicate_logic.py, das genau dafuer existiert.
MAX_DISPLAY_CHARS = 300


def _clip(value: str, limit: int) -> str:
    """Cut a value to ``limit`` and say so — a silent cut hides the trick."""
    if len(value) <= limit:
        return value
    return f"{value[:limit]} … (gekürzt, {len(value)} Zeichen)"


def _header_line(label: str, value: str, *, indent: str = "") -> str:
    """One ``Label: value`` line, or an em dash when the field is missing."""
    return f"{indent}{label}: {_clip(mask_invisible(value).strip(), _MAX_HEADER_CHARS) or '—'}"


def _flag_names(link) -> list[str]:
    """Human-readable annotations of one link, worst first."""
    flags: list[str] = []
    if link.mismatch:
        flags.append("Linktext nennt anderen Host")
    if link.is_ip_literal:
        flags.append("IP-Adresse statt Name")
    if link.is_punycode:
        flags.append("Punycode (Zeichen-Tarnung)")
    if link.is_shortener:
        flags.append("Kurz-Link (Ziel verdeckt)")
    if link.has_credentials:
        flags.append("Zugangsdaten in der URL")
    if link.risky_tld:
        flags.append("auffällige Top-Level-Domain")
    if link.reputation:
        flags.append(f"Reputation: {mask_invisible(link.reputation)}")
    return flags


AUTH_LABELS = {
    "pass": "bestanden",
    "fail": "FEHLGESCHLAGEN",
    "none": "nicht verwendet",
    "unknown": "nicht beurteilbar",
}


def _auth_summary(verdicts: dict[str, str]) -> str:
    """One compact line: which mechanism the sender uses and which not.

    ``not used`` and ``cannot be judged`` are different statements and stay
    different here: the first means the sender published no policy, the second
    means the mail carries no evidence either way (no Authentication-Results,
    typically a mail that never passed a server).
    """
    if not verdicts:
        return "nicht beurteilbar (keine Angaben)"
    parts = [
        f"{mech.upper()} {AUTH_LABELS.get(v, v)}" for mech, v in verdicts.items()
    ]
    return " | ".join(parts)


def _sender_consistency(display: str, addr: str) -> str:
    """Does the shown name name the same sender the mail actually came from?

    Only the plain cases are reported here — a foreign address inside the
    display name, and a display name that is nothing but a different address.
    The brand and lookalike checks live in the pipeline, where the brand list
    is; this line is the quick "what you see vs what it is" for the viewer.
    """
    mismatch, shown = sender_mismatch(display, addr)
    if not mismatch:
        return ""
    return (
        f"Der Anzeigename nennt '{shown}', tatsaechlich gesendet wurde "
        f"von '{addr}'"
    )


def render_mail(facts: MailFacts) -> str:
    """Render one parsed mail as plain text for the detail panel.

    ``facts`` comes from :func:`core.eml_analysis.parse_mail` or
    :func:`parse_msg`, which both fill ``facts.links``; this renderer prints
    those findings and never extracts anything itself.

    Sections appear only when they carry data, so a short mail does not produce
    empty headings. Returns an empty string for a mail with nothing to show.
    """
    if facts.parse_error and not any(
        (facts.subject, facts.from_addr, facts.text_body, facts.attachment_names)
    ):
        return ""

    lines: list[str] = ["E-Mail-Inhalt", "=" * 60, ""]

    # -- headers ---------------------------------------------------------- #
    lines.append("Kopfzeilen")
    lines.append(_header_line("Betreff", facts.subject, indent="  "))
    if facts.from_display and facts.from_addr:
        lines.append(
            _header_line(
                "Von", f"{facts.from_display} <{facts.from_addr}>", indent="  "
            )
        )
    else:
        lines.append(
            _header_line("Von", facts.from_display or facts.from_addr, indent="  ")
        )
    lines.append(_header_line("An", facts.to_addr, indent="  "))
    # Reply-To/Return-Path only when they are set: their absence is already
    # reported as a finding, and an empty row here adds no information.
    if facts.reply_to:
        lines.append(_header_line("Antwort an", facts.reply_to, indent="  "))
    if facts.return_path:
        lines.append(_header_line("Rückläufer", facts.return_path, indent="  "))
    if facts.received_count:
        lines.append(f"  Empfangsstationen (Received): {facts.received_count}")
    # A verdict per mechanism, not the raw header. The raw text is what the
    # receiving server wrote; what the analyst needs is "did this sender
    # authenticate at all", and silence about a mechanism read like approval.
    # The header itself is kept below, because it carries the evidence.
    # "(laut Datei, nicht verifiziert)" is not decoration: the header is
    # written by the receiving server in a delivered mail, but in a file the
    # user is analysing it is bytes the attacker controls. Without the label
    # the line reads as a finding of fact.
    lines.append(
        f"  Authentifizierung (laut Datei, nicht verifiziert): "
        f"{_auth_summary(facts.auth_verdicts)}"
    )
    if facts.from_addr and facts.from_display:
        mismatch = _sender_consistency(facts.from_display, facts.from_addr)
        if mismatch:
            lines.append(f"  Absenderpruefung: {mismatch}")
    if facts.auth_results:
        lines.append(_header_line("Auth-Ergebnis (Rohtext)", facts.auth_results, indent="  "))
    # Welcher Server die Authentifizierung bescheinigt haben will — und ob er
    # ueberhaupt in der Kette steht. Ohne diese Zeile liest sich eine
    # mitgeschriebene Authentication-Results wie ein Urteil.
    if facts.auth_claimed_by:
        lines.append(f"  Bescheinigt von: {mask_invisible(facts.auth_claimed_by)}")
    if facts.dkim_domain:
        selector = f", Selektor {facts.dkim_selector}" if facts.dkim_selector else ""
        lines.append(
            f"  DKIM-Auszeichnung: {mask_invisible(facts.dkim_domain)}{selector} "
            f"(Signatur nicht geprueft — der Schluessel liegt im DNS)"
        )
    lines.append("")

    # -- Kette und fremde Behauptungen ------------------------------------ #
    #
    # Die Kette ist die einzige Angabe, die ein Faelscher mitschreiben muss,
    # wenn die Mail echt aussehen soll. Sie zu zeigen heisst: der Leser kann
    # die Behauptungen oben selbst gegen sie halten.
    if facts.received_hops:
        lines.append(f"Empfangsweg ({len(facts.received_hops)} Stationen, neueste zuerst)")
        for hop in facts.received_hops[:8]:
            parts = []
            if hop.from_host:
                parts.append(f"von {mask_invisible(hop.from_host)}")
            if hop.ip:
                parts.append(f"[{mask_invisible(hop.ip)}]")
            if hop.by_host:
                parts.append(f"an {mask_invisible(hop.by_host)}")
            if hop.protocol:
                parts.append(f"({hop.protocol})")
            if hop.tls:
                parts.append(f"TLS: {hop.tls}")
            if hop.stamp:
                parts.append(f"— {mask_invisible(hop.stamp)}")
            lines.append("  " + " ".join(parts))
        if len(facts.received_hops) > 8:
            lines.append(f"  … {len(facts.received_hops) - 8} weitere")
        lines.append("")

    if facts.filter_claims:
        lines.append(
            f"Behauptungen fremder Filter ({len(facts.filter_claims)}) — "
            f"stammen aus der Datei, nicht nachpruefbar"
        )
        for header, value in list(facts.filter_claims.items())[:6]:
            lines.append(f"  {header}: {mask_invisible(_clip(value, 120))}")
        lines.append("")

    # -- body ------------------------------------------------------------- #
    # The TEXT body, never the HTML part: html_body is attacker-controlled and
    # rendering it would create parser surface without adding a signal.
    body = (facts.text_body or "").strip()
    if body:
        if len(body) > _MAX_BODY_CHARS:
            body = (
                body[:_MAX_BODY_CHARS]
                + f"\n\n[… gekürzt, {len(facts.text_body)} Zeichen insgesamt]"
            )
        lines.append("Textinhalt")
        lines.append("  " + mask_invisible(body).replace("\n", "\n  "))
        lines.append("")

    # -- links ------------------------------------------------------------ #
    # The list the ANALYSER already produced (facts.links, filled by
    # parse_mail/parse_msg), not a fresh extraction: re-running the anchor scan
    # here doubled the cost of every mail, and on a body of unclosed anchors it
    # doubled a quadratic scan (measured: 33 KiB mail 6.2 s over both calls).
    links = facts.links
    if links:
        lines.append(f"Enthaltene Links ({len(links)})")
        for link in links:
            # display_text was capped at 120 and the URL was not — the same
            # gap, in the same block.
            lines.append(f"  – {_clip(mask_invisible(link.url), _MAX_HEADER_CHARS)}")
            if link.display_text and link.display_text.strip() != link.url:
                shown = mask_invisible(link.display_text.strip())[:120]
                lines.append(f"      Linktext: {shown}")
            for flag in _flag_names(link):
                lines.append(f"      ! {flag}")
        lines.append("")

    # -- attachments ------------------------------------------------------ #
    if facts.attachment_names:
        lines.append(f"Anhänge ({len(facts.attachment_names)})")
        for name in facts.attachment_names:
            # BUG-054: names are attacker-controlled and may be 65 535 chars.
            # Masking alone kept the whole name; the display cap applies here
            # exactly as it does to links and headers.
            lines.append(f"  – {_clip(mask_invisible(name), MAX_DISPLAY_CHARS)}")
        lines.append("")

    if facts.parse_error:
        lines.append(f"Hinweis: {mask_invisible(facts.parse_error)}")

    return "\n".join(lines).rstrip() + "\n"


# --------------------------------------------------------------------------- #
# Outlook .msg (OLE/CFB container)
# --------------------------------------------------------------------------- #

# Property streams of a .msg: inside ``__substg1.0_<id><type>`` the first hex
# group is the PidTag id and the trailing group the property type
# (001F = PT_UNICODE, 001E = PT_STRING8, 0102 = PT_BINARY). Candidates are
# ordered: the Unicode variant first, then the ANSI one, then the legacy alias
# Outlook used before the "SentRepresenting" properties existed.
_MSG_SUBJECT = ("__substg1.0_0037001F", "__substg1.0_0037001E")
_MSG_SENDER_NAME = (
    "__substg1.0_0C1A001F",  # PidTagSenderName
    "__substg1.0_0C1A001E",
    "__substg1.0_0042001F",  # PidTagSentRepresentingName
    "__substg1.0_0042001E",
)
_MSG_SENDER_ADDR = (
    "__substg1.0_5D01001F",  # PidTagSenderSmtpAddress
    "__substg1.0_5D02001F",  # PidTagSentRepresentingSmtpAddress
    "__substg1.0_0C1F001F",  # PidTagSenderEmailAddress
    "__substg1.0_0C1F001E",
    "__substg1.0_0065001F",  # PidTagSentRepresentingEmailAddress
)
_MSG_DISPLAY_TO = ("__substg1.0_0E04001F", "__substg1.0_0E04001E")  # PidTagDisplayTo
_MSG_BODY = ("__substg1.0_1000001F", "__substg1.0_1000001E")  # PidTagBody
# PidTagHtml. Read for the link extraction only, never printed — the HTML body
# is attacker-controlled (see the module docstring).
_MSG_HTML = (
    "__substg1.0_10130102",  # PT_BINARY, what Outlook writes
    "__substg1.0_1013001F",  # PT_UNICODE, also seen in real files
    "__substg1.0_1013001E",
)

# The property table every real message carries. Its absence is what separates
# a message from any other compound file (a .doc renamed to .msg) — without
# this check such a file would produce an empty "mail" that reads as clean.
_MSG_PROPERTY_TABLE = "__properties_version1.0"
_MSG_HEADER_CAP = 8 * 1024  # a header field longer than this is not a header
_MSG_BODY_CAP = 512 * 1024  # mirrors eml_analysis._MAX_BODY_BYTES


def _decode_msg_value(stream_name: str, raw: bytes) -> str:
    """Decode one property stream according to its PidTag type suffix.

    Never raises: a truncated or mis-encoded stream becomes replacement
    characters, not a failed scan. The type comes from the stream NAME, which
    is the only place a .msg states it.

    PT_STRING8 uses latin-1 — the same rule ``email_extract`` applies to the
    attachment name streams. Decoding the same byte twice with two different
    codecs would let the panel and the result row disagree about one file name.
    """
    if stream_name.endswith("001F"):  # PT_UNICODE
        return raw.decode("utf-16-le", errors="replace")
    if stream_name.endswith("0102"):  # PT_BINARY (PidTagHtml) — the HTML text
        return raw.decode("utf-8", errors="replace")
    return raw.decode("latin-1", errors="replace")  # PT_STRING8 (ANSI)


def _msg_field(ole, candidates: tuple[str, ...], cap: int) -> str:
    """Read the first non-empty property stream of ``candidates``.

    Read is capped at the stream level (``read(cap)``), so a crafted multi-GB
    property cannot be pulled into memory just to be truncated afterwards.
    Only the C-string terminator is dropped; anything embedded — including
    invisible controls — stays in the value and is handled by
    ``mask_invisible`` at render time.
    """
    for stream_name in candidates:
        try:
            if not ole.exists(stream_name):
                continue
            raw = ole.openstream(stream_name).read(cap)
        except Exception:
            continue
        text = _decode_msg_value(stream_name, raw).rstrip("\x00").strip()
        if text:
            return text
    return ""


def _msg_attachment_names(ole) -> list[str]:
    """Display names of every ``__attach_*`` storage — names only.

    The payloads are extracted by :mod:`core.email_extract`; reading them here
    as well would pull every attachment into memory a second time just to
    print its name.
    """
    names: list[str] = []
    try:
        storages = list(ole.listdir(streams=False, storages=True))
    except Exception:
        return names

    for entry in storages[: config.MAX_ARCHIVE_ENTRIES]:
        if not entry or not entry[0].lower().startswith("__attach_"):
            continue
        for name_stream in _ATTACH_NAME_STREAMS:
            path = [*entry, name_stream]
            try:
                if not ole.exists(path):
                    continue
                raw = ole.openstream(path).read(_MSG_HEADER_CAP)
            except Exception:
                continue
            name = _decode_msg_value(name_stream, raw).rstrip("\x00").strip()
            if name:
                # Only ever a display name — never a path we would open.
                names.append(Path(name).name)
                break
    return names


def parse_msg(data: bytes) -> MailFacts:
    """Parse an Outlook ``.msg`` (OLE/CFB container) into :class:`MailFacts`.

    A ``.msg`` is not a MIME mail, so :func:`eml_analysis.parse_mail` never
    sees it: Outlook stores every field as a named stream inside a compound
    file. Only the flat textual properties are read — subject, sender,
    recipient, plain-text body, the HTML body (for link extraction only) and
    the attachment display names. Bounded and never raising, exactly like
    ``parse_mail``, so a hostile container degrades into a parse note instead
    of an exception in the scan path.
    """
    facts = MailFacts()
    if not data:
        facts.parse_error = "Leere Datei"
        return facts
    try:
        import olefile
    except Exception as exc:  # pragma: no cover - olefile ships with oletools
        facts.parse_error = f"olefile nicht verfügbar: {exc}"
        return facts

    try:
        # Same headroom as the Office stages: the two are siblings driving the
        # same recursive walk, and giving it to only one of them made the very
        # same container readable in one path and "unreadable" in the other.
        with walk_headroom(directory_frames(data)):
            ole = olefile.OleFileIO(io.BytesIO(data))
    except Exception as exc:  # not a compound file at all
        facts.parse_error = f".msg nicht lesbar: {type(exc).__name__}: {exc}"
        return facts

    try:
        if not ole.exists(_MSG_PROPERTY_TABLE):
            facts.parse_error = "Keine Outlook-Nachricht (Property-Tabelle fehlt)"
            return facts
        facts.subject = _msg_field(ole, _MSG_SUBJECT, _MSG_HEADER_CAP)
        facts.from_display = _msg_field(ole, _MSG_SENDER_NAME, _MSG_HEADER_CAP)
        facts.from_addr = _msg_field(ole, _MSG_SENDER_ADDR, _MSG_HEADER_CAP)
        facts.to_addr = _msg_field(ole, _MSG_DISPLAY_TO, _MSG_HEADER_CAP)
        facts.text_body = _msg_field(ole, _MSG_BODY, _MSG_BODY_CAP)
        facts.html_body = _msg_field(ole, _MSG_HTML, _MSG_BODY_CAP)
        facts.attachment_names = _msg_attachment_names(ole)
        # Extracted HERE, once, like parse_mail does for an .eml: the renderer
        # renders facts.links and never re-derives them.
        facts.links = extract_links(facts.text_body, facts.html_body)
    finally:
        with suppress(Exception):
            ole.close()
    return facts


def probe_outlook_msg(data: bytes) -> tuple[bool, str]:
    """``(is_mail, problem)`` for a container the caller detected as OLE.

    Content-based, NOT extension-based: the extension is attacker-controlled
    and a renamed ``.msg`` (or a ``.oft`` template, same container) would
    otherwise slip past every mail path — no preview AND, worse, no recursion
    into ``__attach_*``, so an executable inside it would never be scanned.
    Measured: a real ``.msg`` renamed to ``.dat`` produced zero child scans.

    The marker is the property table every real message carries. The outcomes
    are deliberately distinct, because collapsing them was a silent detection
    loss:

    * ``(False, "")`` — opened fine, no property table: a ``.doc`` renamed to
      ``.msg``. Genuinely not a message.
    * ``(True, "")`` — a readable message.
    * ``(False, "<text>")`` — the container could not be *read* at all. We
      therefore cannot confirm a message, but we must not report "not a
      message" either: that was the silent path. The caller reports the
      problem so the incompleteness is visible.

    Why not ``True`` for the unreadable case: taking the mail path would not
    recover the attachments. ``parse_msg`` and the attachment walk use the
    same olefile directory traversal, so they fail identically — the only
    thing the mail path adds is ``EMAIL_PARSE_ERROR`` noise, and on a
    non-message OLE object (measured: an embedded object with a broken DIFAT
    inside an RTF) that noise is simply false.
    """
    if not data:
        return False, ""
    try:
        import olefile
    except Exception:  # pragma: no cover - olefile ships with oletools
        return False, ""
    try:
        # ``walk_headroom`` before the library call, exactly as in the Office
        # stages. Without it the two siblings disagreed on the same bytes:
        # measured, a container with 496 nested storages was walked by the
        # Office stages while this probe raised RecursionError and reported the
        # container as unreadable — a false "could not read" that costs the
        # scan its mail path.
        with walk_headroom(directory_frames(data)), olefile.OleFileIO(io.BytesIO(data)) as ole:
            if not ole.exists(_MSG_PROPERTY_TABLE):
                return False, ""
            return True, ""
    except RecursionError:
        # olefile.append_kids walks the directory's red-black tree recursively
        # (its own docstring: "recursive method"), so a container whose tree is
        # a chain — which the attacker controls, since it is just bytes — can
        # overflow the stack.
        return False, "Verzeichnisbaum zu tief (olefile-Rekursion)"
    except Exception as exc:
        # "Definitely not a compound file" is a rejection, not a problem: the
        # caller normally only asks about magic-detected OLE, but the function
        # must not claim arbitrary bytes are a message.
        if type(exc).__name__ == "NotOleFileError":
            return False, ""
        # A container that IS OLE but cannot be read: unproven either way.
        return False, f"{type(exc).__name__}: {exc}"


def sender_mismatch(display: str, addr: str) -> tuple[bool, str]:
    """``(passt_nicht, genannt)`` — nennt der Anzeigename eine fremde Domain?

    Die EINE Umsetzung dieser Frage. Vorher gab es zwei: diese Funktion und
    ``_sender_consistency``, die dieselben zwei Ausdruecke noch einmal
    hinschrieb — und beim ReDoS-Fix wurde nur eine der beiden Stellen
    repariert. ``sender_verdict`` (fuer die Liste) und ``_sender_consistency``
    (fuer den Vorschautext) leiten jetzt beide hierher ab, koennen also nicht
    mehr auseinanderlaufen.
    """
    shown = re.findall(ADDRESS_IN_DISPLAY_RE, display or "", re.IGNORECASE)
    actual = re.search(DOMAIN_IN_ADDRESS_RE, addr or "", re.IGNORECASE)
    if not shown or not actual:
        return False, ""
    if any(dom.lower() != actual.group(1).lower() for dom in shown):
        return True, shown[0]
    return False, ""


def sender_verdict(facts) -> str:
    """``ok`` | ``mismatch`` | ``unknown`` — passt der Anzeigename zum Absender?

    Nur der schlichte Vergleich: nennt der Anzeigename eine Adresse, deren
    Domain von der echten From-Domain abweicht. Die Marken- und
    Lookalike-Pruefungen liegen in der Analyse, wo die Markenliste steht.

    Die Quantoren sind BEGRENZT (RFC 5321: 64 / 255) — unbeschraenkt ist diese
    Form quadratisch auf angreiferkontrolliertem Text; siehe
    tests/test_regex_safety.py, das genau das prueft.
    """
    display = facts.from_display or ""
    addr = facts.from_addr or ""
    if not display or not addr:
        return "unknown"
    mismatch, _ = sender_mismatch(display, addr)
    return "mismatch" if mismatch else "ok"


def render_msg(data: bytes) -> str:
    """Render an Outlook ``.msg`` container as a plain-text mail preview.

    Returns an empty string when the container is not a readable message:
    an empty panel is honest, a scaffold that looks like a mail is not.
    """
    return render_mail(parse_msg(data))
