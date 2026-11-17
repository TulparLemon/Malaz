"""Email attachment extraction for .eml and Outlook .msg files.

Emails are the primary malware delivery vector; until now they were only
scanned as text (IOCs), so the attached PDF/Office/PE payload was never
analysed. This module extracts every attachment in memory so the dispatcher
can feed it back into the normal analysis loop.

* ``.eml``: parsed with the stdlib ``email`` module (RFC 5322/2045). All
  non-multipart parts with a filename or an attachment/inline disposition are
  yielded.
* ``.msg`` (Outlook): a compound-file (OLE) container; parsed with ``olefile``
  (MIT, shipped with oletools). Attachments live in ``__attach_*`` storages;
  the binary payload is the ``__substg1.0_37010102`` stream
  (PidTagAttachDataBinary), the display name is read from the
  ``__substg1.0_3704000A/1E/1F`` streams (PidTagAttachLongFilename/Filename).
  Any structural problem degrades to an error entry — never a crash.

Security notes:
* attachment names are attacker-controlled and used ONLY as display names /
  suffix hints (they are never written to disk, so no path traversal surface).
* per-attachment and cumulative volume guards mirror the archive limits.
* the stdlib parser itself is the one unbounded stage: its cost is quadratic
  in the multipart nesting depth and linear in the number of parts, and the
  interpreter limit that used to cap the depth is gone since round 5 (see
  ``_MAX_MIME_LAYERS`` and ``_MAX_MIME_PARTS``). Both .eml entry points — this
  module and ``core.eml_analysis.parse_mail`` — therefore ask
  :func:`mime_depth_note` first and refuse a mail past either budget unparsed,
  but weighted, instead of parsing it.
"""

from __future__ import annotations

import base64
import binascii
import io
import quopri
import re
from collections.abc import Iterator
from contextlib import suppress
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import unquote_to_bytes

from .. import config
from .archive import BUDGET_STOP_PREFIX
from .ole_depth import directory_frames, directory_too_deep, walk_headroom

# MIME nesting limit. Deliberately HIGHER than MAX_ARCHIVE_DEPTH: every
# forwarding level of a mail adds ~2 multipart/rfc822 layers, so a limit of
# 5 would silently skip attachments of 3+ times forwarded mails — a prime
# phishing vector.
_MAX_MIME_DEPTH = 16

# Budget for the stdlib parser, checked BEFORE it runs.
#
# ``BytesParser.parsebytes`` costs quadratic time in the multipart nesting
# depth. Measured here (CPython 3.12, venv) on nested multipart/mixed, same
# generator that builds the depth fixture in tests/test_email_rtf.py:
# 128 layers 0.078 s, 256 0.172 s, 512 0.422 s, 1024 1.234 s, 2048 3.735 s,
# 4000 12.219 s, 8000 49.875 s — and hardly anything else: the same 512
# layers around a 4 MiB leaf body still parse in 0.532 s, nested
# message/rfc822 is cheap (4000 encapsulations 0.469 s). Depth is the
# quadratic lever; the linear one is the WIDTH, see ``_MAX_MIME_PARTS``.
#
# Until round 5 the interpreter limit (1000) was the only bound on that depth:
# the parser died after ~0.95 s with a RecursionError, which this module
# turned into a weighted note. ``ole_depth.ensure_walk_limit`` now installs
# HARD_MAX_FRAMES (8192) process-wide — deliberately, for olefile — and 8192
# Python frames is exactly what lets the parser walk ~8200 layers. End to end
# that is 94.7 s for one 565 KB mail (2.25 s of it here, the rest in
# ``eml_analysis.parse_mail``, which parses the same bytes a second time), and
# 604 s for a 491 KB ZIP of eight such members — far below MAX_FILE_SIZE
# (200 MB), with no per-file time budget and MAX_SCAN_WORKERS=3 running three
# of them at once.
#
# So the .eml path gets its own bound. 256 layers = 0.17 s: 16x this module's
# own _MAX_MIME_DEPTH, and enormously above real mail — the deepest .eml of
# both corpora nests 1 layer, a mail forwarded ten times nests 22 (12
# estimated), which is 20x below the budget at a forwarding depth no real
# thread reaches.
_MAX_MIME_LAYERS = 256

# Budget for the parser's WIDTH — the number of MIME parts, checked BEFORE it
# runs, next to the depth budget above.
#
# The parser is linear in the part count but the constant is not small: every
# part costs a header parse and a payload object. Measured in the venv on a
# flat multipart/mixed mail with one shared boundary, in-process via
# ``Dispatcher.scan_path`` (both .eml stages — extraction and
# ``eml_analysis.parse_mail`` — parse the same bytes, so the end-to-end number
# is what the user waits for): 1000 parts 64 KB 0.672 s, 5000 parts 320 KB
# 2.844 s, 20 000 parts 1.28 MB 10.453 s, 60 000 parts 3.84 MB 29.594 s —
# 0.49 ms per part, flat. Nothing bounds the part count except MAX_READ_SIZE
# (100 MB), which is ~1.8 million parts ≈ 13 minutes for ONE file, and the
# extraction's own MAX_ARCHIVE_ENTRIES cap does not help: it breaks the
# traversal after 10 000 parts, but ``BytesParser.parsebytes`` has already
# walked all of them.
#
# The amplifier is the archive path, exactly as it was for the depth finding:
# a 3.8 MB wide mail deflates to ~4 KB, so a 4 KB ZIP member costs 10 s and a
# 32 KB ZIP of eight of them 78.7 s — 2.5 s of scanner time per attacker
# kilobyte, against 0.19 s/KB for the ZIP bomb that MAX_UNCOMPRESSED_SIZE
# deliberately allows (500 MB of members, measured 94 s).
#
# 4096 is chosen against real mail, not against the attack: the widest .eml of
# both corpora has 5 parts, a newsletter/digest with 500 parts costs 0.33 s
# (8x below the budget), and a mail forwarded ten times nests 22 layers. At
# the budget the refusal-free worst case is 4096 x 0.49 ms ≈ 2.0 s of parser
# time (measured end to end: 3.0 s for a 4096-part mail whose parts are all
# attachments, 250 of which the dispatcher also child-scans — a mail past
# MAX_RECURSIVE_MEMBERS is already YELLOW today), i.e. at most what the
# scanner already spends on a 100 MB text file (3.3 s). A mail past the budget
# is refused with a weighted note instead of parsed.
_MAX_MIME_PARTS = config.MAIL_MAX_MIME_PARTS

# Longest boundary token the estimate compares (RFC 2046 caps a boundary at
# 70 characters). The declaration capture and the delimiter token are cut to
# the same length, so a boundary LONGER than the cap cannot hide its parts
# from the estimate: the stdlib parser uses the full token and splits on it,
# so an over-long boundary would otherwise make every delimiter unmatched —
# measured, a 2000-part mail with a 71-character boundary is 0.45 s of parser
# work while the estimate sees depth 0.
_MIME_BOUNDARY_MAX = 70

# ``boundary=`` parameter of a Content-Type header. All spellings the stdlib
# parser honours are covered, because a spelling the estimate cannot read
# makes BOTH budgets blind (measured: with ``boundary*=BND`` the parser splits
# the mail, the estimate sees nothing): the RFC 2231 extended form
# ``boundary*=`` (optionally ``charset'language'`` prefixed and
# percent-encoded), the continuation form ``boundary*0=``/``boundary*1=``
# (audit SEC-032: 300 layers declared 0 while the parser split them), quoted
# values — a quoted value may contain ';' — and unquoted ones, which end there.
_MIME_BOUNDARY_DECL = re.compile(
    rb'boundary(?:\*(?P<index>\d{1,3}))?(?P<extended>\*)?\s*=\s*'
    rb'(?:"(?P<quoted>[^"\r\n]{1,%d})"|(?P<plain>[^";\r\n]{1,%d}))'
    % (_MIME_BOUNDARY_MAX, _MIME_BOUNDARY_MAX),
    re.IGNORECASE,
)
# A delimiter line, i.e. a line that opens or closes a part. The stdlib
# feedparser splits lines at ``\r\n|\r|\n``, so a CR-only document is nested
# for the parser while ``^`` (which only fires after ``\n``) sees no delimiter
# at all — the second alternative covers it without matching a line twice.
_MIME_DELIMITER = re.compile(rb"^--[^\r\n]*|(?<=\r)--[^\r\n]*", re.MULTILINE)
# More distinct boundaries than this is not a mail. The declaration set is
# capped so the scan cannot be turned into a memory hog by a hostile file;
# past the cap every delimiter counts, so the cap can only refuse more.
_MAX_MIME_BOUNDARIES = 1024


def _boundary_value(raw: bytes, extended: bool) -> bytes:
    """One ``boundary`` value as the stdlib parser reads it.

    RFC 2231 extended values carry ``charset'language'`` in front of the token
    and percent-encode it; ``get_param`` decodes both, so the estimate has to
    as well — measured, ``boundary*=us-ascii'en'B%4ED`` splits a mail on the
    delimiter ``--BND``. Continuation segments (``boundary*0*=``/``*1=``) are
    decoded segment-wise and joined by :func:`_declared_boundaries`.
    """
    # ``get_param`` decodes the ``charset'language'`` prefix whether or not the
    # parameter carries the ``*`` marker (measured: ``boundary=us-ascii'en'B000``
    # and ``boundary*=us-ascii'en'B000`` both split on ``--B000``). Percent
    # decoding applies to the RFC 2231 extended forms.
    if raw.count(b"'") >= 2:
        raw = unquote_to_bytes(raw.split(b"'", 2)[2])
    elif extended:
        raw = unquote_to_bytes(raw)
    return raw.strip()[:_MIME_BOUNDARY_MAX]


def _declared_boundaries(line: bytes) -> list[bytes]:
    """Boundary tokens declared on ONE Content-Type line.

    RFC 2231 continuation values are one token split over ``*0``, ``*1``, …:
    the stdlib parser concatenates the segments of the same header line
    (measured: ``boundary*0=BN; boundary*1=D0`` splits on ``--BND0``). The
    estimate must join them the same way, or ``boundary*0``/``*1`` becomes a
    free way past both MIME budgets (audit SEC-032).
    """
    tokens: list[bytes] = []
    segments: dict[int, bytes] = {}
    for match in _MIME_BOUNDARY_DECL.finditer(line):
        value = match.group("quoted")
        if value is None:
            value = match.group("plain")
        if value is None:
            continue
        decoded = _boundary_value(value, bool(match.group("extended")))
        index = match.group("index")
        if index is None:
            tokens.append(decoded)
        else:
            segments[int(index)] = decoded
    if segments:
        joined = b""
        for index in range(len(segments)):
            segment = segments.get(index)
            if segment is None:
                break
            joined += segment
            if len(joined) >= _MIME_BOUNDARY_MAX:
                break
        if joined:
            tokens.append(joined[:_MIME_BOUNDARY_MAX])
    return tokens


def _mime_declared(data: bytes) -> set[bytes]:
    """The boundary tokens this mail DECLARES — from ``Content-Type:`` lines.

    Where a declaration may live is decided by the grammar, not by position: a
    ``boundary`` parameter belongs to a Content-Type header, at the top of the
    mail or in a part. Scanning the whole blob instead was the overshoot this
    helper closes — measured, 1100 ``boundary=b0000`` lines in a body filled
    the declaration set to its cap, the counting then switched to "every
    delimiter counts", and the mail's own 1100 ``--b0000`` text lines were read
    as nesting: estimated depth 257 at a real depth of 1, so both entry points
    refused a harmless mail.

    Restricting to *header regions* was the first attempt and it failed twice:
    a signature separator (``-- ``, RFC 3676) flipped the scan back into header
    mode, and parts appear INNERMOST FIRST in the stream, so "only tokens
    declared so far" dropped every nested boundary. Tying the search to the
    header NAME needs neither a state machine nor an order: folded
    continuations belong to the line they follow.
    """
    declared: set[bytes] = set()
    continued = False
    # ``io.BytesIO(data)`` iterates the lines LAZILY; ``data.splitlines()``
    # materializes every line as a list object before any budget applies.
    # Measured: 2.9 MB of short lines peak at 8.1 MiB with splitlines — ~2.8x
    # the input, and at MAX_READ_SIZE (100 MB) that is the same amplification
    # class this function exists to bound. Iterating lazily and splitting each
    # chunk on the remaining CR keeps the legacy ``\r``-only form working at no
    # memory cost (``splitlines`` handled it, the plain iterator would not).
    for chunk in io.BytesIO(data):
        for line in chunk.replace(b"\r\n", b"\n").split(b"\r"):
            stripped = line.strip()
            folded = continued and line[:1] in (b" ", b"\t")
            continued = folded or stripped.lower().startswith(b"content-type:")
            if not (folded or stripped.lower().startswith(b"content-type:")):
                continue
            for token in _declared_boundaries(line):
                if not token:
                    continue
                declared.add(token)
                if len(declared) >= _MAX_MIME_BOUNDARIES:
                    return declared
    return declared


def _mime_shape(data: bytes) -> tuple[int, int]:
    """``(estimated nesting depth, part delimiters)`` — no parse, linear.

    The shape is visible in the delimiter lines alone: ``--token`` opens (or
    repeats) the level that ``token`` delimits, ``--token--`` closes it, and a
    delimiter of an outer level closes everything nested below it — the same
    rule the parser applies. A delimiter only counts when the mail actually
    declared ``token`` as a boundary, so body text that merely looks like
    structure (a diff, a list of ``--flags``, ASCII art) cannot push either
    number up; that is also why a mail without any ``boundary=`` parameter is
    answered without touching its lines at all.

    The delimiter count is the parser's part count: a flat mail with N parts
    has N+1 delimiter lines for its one boundary, and every further level adds
    its own. Tokens are cut to ``_MIME_BOUNDARY_MAX`` on both sides of the
    comparison, so an over-long boundary cannot drop out of the match.

    Exact below the budgets, a lower bound above them: counting stops at the
    first layer past ``_MAX_MIME_LAYERS`` or the first delimiter past
    ``_MAX_MIME_PARTS``, which is all the caller needs to know.
    """
    declared = _mime_declared(data)
    if not declared:
        return 0, 0
    # Past the declaration cap the set is incomplete, so every delimiter has
    # to count — refusing more, never less. Reaching the cap now means the mail
    # really carries that many DECLARATIONS (see _mime_declared): body text can
    # no longer fill the set, which is what used to invert the counting and
    # turn quoted text into structure.
    loose = len(declared) >= _MAX_MIME_BOUNDARIES

    stack: list[bytes] = []
    position: dict[bytes, int] = {}
    deepest = 0
    delimiters = 0
    for match in _MIME_DELIMITER.finditer(data):
        raw = match.group()[2:].strip()
        # A boundary value may itself END in '--' (the parser takes the
        # parameter as written, and the delimiter line then carries four
        # dashes). Try the FULL token first and only fall back to the closing
        # form: reading `--d000--` as the closing delimiter of `d000` — a token
        # that was never declared — dropped every delimiter of such a mail.
        # Measured: 300 layers estimated as 1, so the depth budget never fired.
        closing = False
        token = raw[:_MIME_BOUNDARY_MAX]
        if (loose or token not in declared) and raw.endswith(b"--"):
            candidate = raw[:-2].strip()[:_MIME_BOUNDARY_MAX]
            if candidate and (loose or candidate in declared):
                token = candidate
                closing = True
        if not token or (not loose and token not in declared):
            continue
        delimiters += 1
        if delimiters > _MAX_MIME_PARTS:
            return deepest, delimiters  # decided; the parser must not run
        if loose and token not in declared:
            # Past the declaration cap only the PART COUNT may count an
            # undeclared delimiter, never the DEPTH. Counting it for depth was
            # the overshoot that survived two fixes: a forwarded mail quotes the
            # original's headers as TEXT, so 1100 `Content-Type: ... boundary=qNNNN`
            # lines refilled the set to its cap, "every delimiter counts" took
            # over, and the mail's own 1100 `--qNNNN` quoted lines were read as
            # nesting — estimated depth 257 at a real depth of 1, refused.
            #
            # Depth cannot be bought that way: a genuinely nested mail declares
            # one boundary per level, so the first 1024 declarations already
            # exceed the 256-layer budget on their own. The width stays counted,
            # so a wide mail is still refused by _MAX_MIME_PARTS.
            continue
        at = position.get(token)
        if at is None:
            stack.append(token)
            position[token] = len(stack) - 1
            deepest = max(deepest, len(stack))
            if deepest > _MAX_MIME_LAYERS:
                return deepest, delimiters  # decided; the parser must not run
        else:
            # A delimiter of an outer level closes everything below it.
            while len(stack) > at + 1:
                del position[stack.pop()]
        if closing and stack and stack[-1] == token:
            del position[stack.pop()]
    return deepest, delimiters


def mime_depth_note(data: bytes) -> str | None:
    """The refusal note when a mail is too deep or too wide, else None.

    THE predicate for both .eml entry points: which mail is refused, for which
    reason, and with which wording is decided here and nowhere else. A mail
    beyond either budget is never handed to ``BytesParser``, and the note it
    gets instead is a weighted one on the dispatcher's side
    (EMAIL_PARSE_ERROR, weight 25) — "not parsed" must never read like
    "clean".

    Two stages parse the very same bytes (this module's extraction and
    ``core.eml_analysis.parse_mail``, which the eml pipeline runs). Bounding
    only one of them halves the cost instead of removing it: measured, a
    1500-layer mail is 2.25 s in the extraction and 2.2 s again in
    ``parse_mail``, and the same doubling applies to a wide mail. Both ask
    here.
    """
    layers, parts = _mime_shape(data)
    if layers > _MAX_MIME_LAYERS:
        # The count stops at the first layer above the budget, so it is a
        # lower bound — "at least", not "estimated".
        return (
            f"E-Mail nicht geparst: MIME-Verschachtelung von mindestens "
            f"{layers} Schichten über dem Budget von {_MAX_MIME_LAYERS} — der "
            "Inhalt wurde NICHT analysiert und ist nicht als 'sauber' zu "
            "werten."
        )
    if parts > _MAX_MIME_PARTS:
        return (
            f"E-Mail nicht geparst: mindestens {parts} MIME-Teile über dem "
            f"Budget von {_MAX_MIME_PARTS} — der Inhalt wurde NICHT analysiert "
            "und ist nicht als 'sauber' zu werten."
        )
    return None


# Stream names inside an __attach_* storage (PidTag constants).
_ATTACH_DATA_STREAM = "__substg1.0_37010102"
# Name candidates: AttachLongFilename (Unicode/ANSI) then AttachFilename.
_ATTACH_NAME_STREAMS = (
    "__substg1.0_3704001F",  # PidTagAttachLongFilename, PT_UNICODE
    "__substg1.0_3704001E",  # PidTagAttachLongFilename, PT_STRING8
    "__substg1.0_3704000A",  # PidTagAttachFilename
)


def _per_attachment_limit() -> int:
    return config.MAX_EXTRACTED_FILE_SIZE


def _total_limit() -> int:
    return config.MAX_UNCOMPRESSED_SIZE



def _decode_attachment_bounded(part, limit: int) -> tuple[bytes | None, str | None]:
    """Decode a MIME part without materializing an oversized decoded blob."""
    raw = part.get_payload(decode=False)
    if isinstance(raw, list):
        return None, "MIME-Teil enthält unerwartete Unterteile"
    if raw is None:
        return None, None
    if isinstance(raw, str):
        try:
            encoded = raw.encode(part.get_content_charset() or "utf-8", "surrogateescape")
        except (LookupError, UnicodeEncodeError, ValueError, TypeError):
            # Same trap as ``eml_analysis._decode_part``: a charset header with
            # an embedded NUL makes codecs.lookup raise ValueError, not
            # LookupError. The header is attacker-controlled.
            encoded = raw.encode("utf-8", "replace")
    else:
        encoded = bytes(raw)

    transfer = (part.get("Content-Transfer-Encoding") or "").strip().lower()
    if transfer == "base64":
        # The encoded representation is already part of the parsed input. Do
        # not call get_payload(decode=True) for an oversized candidate: that
        # creates the full decoded object before the size check can reject it.
        compact = b"".join(encoded.split())
        if len(compact) > ((limit + 2) // 3 + 1) * 4:
            return None, "Base64-Anhang zu groß (Dekodierung würde das Limit überschreiten)"
        try:
            decoded = base64.b64decode(compact, validate=False)
        except (binascii.Error, ValueError) as exc:
            return None, f"Base64-Anhang nicht lesbar: {type(exc).__name__}"
    elif transfer == "quoted-printable":
        if len(encoded) > max(1, limit // 2):
            return None, "Quoted-Printable-Anhang zu groß"
        decoded = quopri.decodestring(encoded)
    elif transfer in ("", "7bit", "8bit", "binary"):
        decoded = encoded
    else:
        # Unknown encodings are rare; keep the stdlib fallback bounded by a
        # conservative preflight instead of risking an unbounded decode.
        if len(encoded) > max(1, limit // 2):
            return None, f"Unbekannter MIME-Transfer-Encoding zu groß: {transfer}"
        try:
            value = part.get_payload(decode=True)
        except Exception as exc:
            return None, f"Anhang nicht dekodierbar: {type(exc).__name__}"
        decoded = value if isinstance(value, bytes) else b""
    if len(decoded) > limit:
        return None, f"Anhang zu groß ({len(decoded)} Bytes > {limit})"
    return decoded, None

def iter_email_attachments(
    data: bytes, kind: str
) -> Iterator[tuple[str, bytes, str | None]]:
    """Yield ``(name, payload, error)`` for every attachment of an email.

    ``kind`` is ``"eml"`` or ``"msg"`` (magic-detected). Yields at most
    ``MAX_ARCHIVE_ENTRIES`` attachments and stops once the cumulative decoded
    volume exceeds the bomb-protection limit.
    """
    if not data:
        return
    if kind == "msg":
        yield from _iter_msg(data)
    else:
        yield from _iter_eml(data)


# -- .eml ------------------------------------------------------------------ #


def _iter_eml(data: bytes) -> Iterator[tuple[str, bytes, str | None]]:
    # The parser is the expensive stage (quadratic in the nesting depth, see
    # _MAX_MIME_LAYERS) and it runs before any depth check of our own. Ask the
    # shared predicate first: a mail beyond the budget is reported unparsed,
    # never handed to BytesParser.
    too_deep = mime_depth_note(data)
    if too_deep:
        yield ("", b"", too_deep)
        return
    try:
        message = BytesParser(policy=policy.default).parsebytes(data)
    except Exception as exc:  # defensive: malformed mail must not crash
        yield ("", b"", f"E-Mail nicht parsebar: {type(exc).__name__}: {exc}")
        return

    extracted_total = 0
    processed = 0
    # Iterative traversal instead of message.walk(): walk() recurses over
    # subparts, so a ~45 KB .eml with ~1200 nested multipart layers raised
    # RecursionError and turned the WHOLE mail into CORE_ERROR. The stack
    # variant survives any depth; parts beyond _MAX_MIME_DEPTH are skipped
    # with a note.
    from email.message import Message as _Message

    stack: list[tuple[_Message, int]] = [(message, 0)]
    depth_skipped = False
    while stack:
        part, depth = stack.pop()
        if depth > _MAX_MIME_DEPTH:
            depth_skipped = True
            continue
        if processed >= config.MAX_ARCHIVE_ENTRIES:
            break
        processed += 1
        if part.is_multipart():
            ctype = (part.get_content_type() or "").lower()
            # Eine MITGESENDETE MAIL ist ein Anhang, kein Teil DIESER Mail.
            # GEMESSEN: sie wurde als multipart weiter gereicht, und ihr
            # Inhalt landete danach nirgends — weder als eigener Eintrag
            # (der Name wurde nie gelesen) noch als Text (die inneren Teile
            # haben weder Dateinamen noch Attachment-Disposition). Die
            # angehaengte Mail war damit fuer den Scanner unsichtbar: keine
            # Link-Extraktion, kein Blocklisten-Abgleich, kein eigenes Urteil.
            # Wer seinen Inhalt in eine .eml legt, umging die Pruefung.
            if ctype == "message/rfc822":
                anhang_name = None
                try:
                    anhang_name = part.get_filename()
                except Exception:
                    anhang_name = None
                if anhang_name:
                    roh = b""
                    try:
                        inhalt = part.get_payload()
                        if isinstance(inhalt, list) and inhalt:
                            # get_payload() liefert bei message/rfc822 eine
                            # Liste mit EINEM Message-Objekt; as_bytes() gibt
                            # dessen Rohbytes zurueck.
                            erstes = inhalt[0]
                            roh = erstes.as_bytes() if hasattr(erstes, "as_bytes") else b""
                    except Exception as exc:
                        yield (
                            Path(anhang_name).name,
                            b"",
                            f"Angehängte E-Mail nicht lesbar: {type(exc).__name__}",
                        )
                        continue
                    if roh:
                        yield (Path(anhang_name).name, roh, "")
                    continue
            try:
                subparts = list(part.get_payload())
            except Exception:
                subparts = []
            for sub in reversed(subparts):
                stack.append((sub, depth + 1))
            continue
        disposition = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()
        if not filename and disposition not in ("attachment", "inline"):
            continue
        if not filename:
            filename = f"anhang_{processed}.bin"
        # Only the basename is used (display name, never a filesystem path).
        filename = Path(filename).name or f"anhang_{processed}.bin"
        # NO ``Content-Length`` preflight: that header is not a MIME header and
        # has no meaning for a body part. A forged ``Content-Length: 1e12``
        # made the attachment look "too large" and the payload was never
        # decoded or scanned (audit BUG-066). The decode below is bounded by
        # ``_per_attachment_limit`` on the ACTUAL bytes and the total budget is
        # checked against the decoded length — the real limits stay.
        per_attachment = _per_attachment_limit()
        payload, decode_error = _decode_attachment_bounded(part, per_attachment)
        if decode_error:
            yield (filename, b"", decode_error)
            continue
        if payload is None:
            continue
        if extracted_total + len(payload) > _total_limit():
            # A silently dropped attachment is invisible: the report then says
            # "scope clean" although this member was never scanned (TEST-025 /
            # audit). Yield the shared budget-stop note (the dispatcher maps
            # BUDGET_STOP_PREFIX to the bomb-protection finding) instead of
            # returning silently.
            yield (
                "",
                b"",
                (
                    f"{BUDGET_STOP_PREFIX} MIME-Gesamtlimit für Anhänge "
                    "überschritten — weitere Anhänge wurden NICHT dekodiert "
                    "und NICHT analysiert."
                ),
            )
            return
        extracted_total += len(payload)
        yield (filename, payload, None)
    if depth_skipped:
        yield (
            "",
            b"",
            (
                f"MIME-Verschachtelung tiefer als {_MAX_MIME_DEPTH} — "
                "tiefere Teile wurden übersprungen."
            ),
        )


# -- .msg (Outlook) --------------------------------------------------------- #


def _iter_msg(data: bytes) -> Iterator[tuple[str, bytes, str | None]]:
    try:
        import olefile
    except Exception as exc:
        yield ("", b"", f"olefile nicht verfügbar: {exc}")
        return

    # olefile builds the whole storage tree in the constructor
    # (``build_storage_tree`` -> recursive ``append_kids``), and the tree's
    # depth is file content: one 128-byte directory entry per level. Measured
    # over ``Dispatcher.scan_path``: the same ``.msg`` with an attached ZIP
    # scanned RED 50 with the child scan at nesting 0, but from 496 nested
    # storages on it degraded to "nicht lesbar" (YELLOW 25, no child scan at
    # all) — although the probe reported those bytes as a readable message
    # and the preview rendered subject and attachment names. This was the
    # third olefile caller; the other two (Office stages, mail_view) already
    # measure the depth and request the headroom, so the same control is
    # applied here rather than a fourth path being left open.
    frames = directory_frames(data)
    if directory_too_deep(frames):
        yield (
            "",
            b"",
            (
                f"Verzeichnisbaum des Containers zu tief ({frames} "
                "Rekursions-Frames) — die Anhänge wurden NICHT geprüft und "
                "das Ergebnis ist nicht als 'sauber' zu werten."
            ),
        )
        return
    try:
        with walk_headroom(frames):
            ole = olefile.OleFileIO(io.BytesIO(data))
    except Exception as exc:  # not a valid compound file
        yield ("", b"", f".msg nicht lesbar: {type(exc).__name__}: {exc}")
        return

    extracted_total = 0
    processed = 0
    try:
        for storage in _attachment_storages(ole):
            if processed >= config.MAX_ARCHIVE_ENTRIES:
                return
            processed += 1
            name, payload, error = _read_attachment(ole, storage)
            if error:
                yield (name or "(Anhang)", b"", error)
                continue
            if payload is None:
                continue
            per_attachment = _per_attachment_limit()
            if len(payload) > per_attachment:
                yield (
                    name or "(Anhang)",
                    b"",
                    f"Anhang zu groß ({len(payload)} Bytes > {per_attachment})",
                )
                continue
            if extracted_total + len(payload) > _total_limit():
                return
            extracted_total += len(payload)
            yield (name or f"anhang_{processed}.bin", payload, None)
    finally:
        with suppress(Exception):
            ole.close()


def _attachment_storages(ole) -> list[tuple[str, ...]]:
    """Return the storage paths of every ``__attach_*`` entry."""
    out: list[tuple[str, ...]] = []
    for entry in ole.listdir(streams=False, storages=True):
        if entry and entry[0].lower().startswith("__attach_"):
            out.append(tuple(entry))
    return out


def _read_attachment(ole, storage: tuple[str, ...]) -> tuple[str, bytes | None, str | None]:
    """Read one attachment storage; returns ``(name, payload, error)``."""
    name = ""
    for name_stream in _ATTACH_NAME_STREAMS:
        stream = [*list(storage), name_stream]
        if not ole.exists(stream):
            continue
        try:
            raw = ole.openstream(stream).read(1024)
        except Exception:
            continue
        if name_stream.endswith("1F"):  # UTF-16LE
            name = raw.decode("utf-16-le", errors="replace").strip("\x00")
        else:  # ANSI
            name = raw.decode("latin-1", errors="replace").strip("\x00")
        if name:
            break
    if name:
        name = Path(name).name  # display name only

    data_stream = [*list(storage), _ATTACH_DATA_STREAM]
    if not ole.exists(data_stream):
        # Some writers store the payload under a differently-named 3701 stream.
        for entry in ole.listdir(streams=True, storages=False):
            if entry[:-1] == list(storage) and entry[-1].lower().startswith(
                "__substg1.0_3701"
            ):
                data_stream = list(entry)
                break
        else:
            return name, None, "Kein Anhang-Daten-Stream gefunden"
    try:
        payload = ole.openstream(data_stream).read()
    except Exception as exc:
        return name, None, f"Anhang-Daten nicht lesbar: {exc}"
    return name, payload, None
