"""Tests for the 7-Zip backed RAR/7z extraction (core.sevenzip).

The real 7-Zip binary is not required: the extraction subprocess is replaced by
a fake that writes files into the output directory, so the member-reading,
size-limit and bomb-budget logic is tested deterministically on any machine.
"""

from pathlib import Path

from malaz import config
from malaz.core import sevenzip

# -- binary discovery -------------------------------------------------------- #

def test_find_binary_returns_none_when_absent(monkeypatch):
    monkeypatch.setattr(config, "SEVENZIP_CANDIDATES", ())
    monkeypatch.setattr(sevenzip.shutil, "which", lambda name, path=None: None)
    assert sevenzip.find_7z_binary() is None


def test_find_binary_prefers_installed_path(monkeypatch, tmp_path):
    fake = tmp_path / "7z.exe"
    fake.write_bytes(b"MZ")
    monkeypatch.setattr(config, "SEVENZIP_CANDIDATES", (str(fake),))
    assert sevenzip.find_7z_binary() == fake


def test_find_binary_falls_back_to_path(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "SEVENZIP_CANDIDATES", ())
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setattr(
        sevenzip.shutil, "which", lambda name, path=None: str(tmp_path / name)
    )
    assert sevenzip.find_7z_binary() == tmp_path / "7z"


def test_find_binary_never_searches_the_working_directory(monkeypatch):
    """SEC-010: ``.``/empty PATH entries must not reach ``shutil.which``.

    With ``PATH=.;tools`` the stdlib resolved a planted ``7z.exe`` from the
    scanned directory as ``.\\7z.EXE``. Only absolute entries may be passed on.
    """
    import os

    monkeypatch.setattr(config, "SEVENZIP_CANDIDATES", ())
    monkeypatch.setenv("PATH", os.pathsep.join([".", "", "tools"]))
    aufgerufen = []

    def fake_which(name, path=None):
        aufgerufen.append(path)
        return "7z.EXE"

    monkeypatch.setattr(sevenzip.shutil, "which", fake_which)
    assert sevenzip.find_7z_binary() is None
    assert not aufgerufen, f"which() wurde mit relativen Eintraegen aufgerufen: {aufgerufen}"


def test_find_binary_passes_only_absolute_path_entries(monkeypatch, tmp_path):
    import os

    monkeypatch.setattr(config, "SEVENZIP_CANDIDATES", ())
    monkeypatch.setenv("PATH", os.pathsep.join([".", "", str(tmp_path)]))
    gesehen = []

    def fake_which(name, path=None):
        gesehen.append(path)
        return str(tmp_path / name)

    monkeypatch.setattr(sevenzip.shutil, "which", fake_which)
    assert sevenzip.find_7z_binary() == tmp_path / "7z"
    assert gesehen == [str(tmp_path)]


def test_find_binary_rejects_a_relative_hit(monkeypatch, tmp_path):
    """Even a relative result from ``which`` must not be executed."""
    monkeypatch.setattr(config, "SEVENZIP_CANDIDATES", ())
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setattr(
        sevenzip.shutil, "which", lambda name, path=None: ".\\7z.EXE"
    )
    assert sevenzip.find_7z_binary() is None


def test_iter_members_empty_when_no_binary(monkeypatch):
    monkeypatch.setattr(sevenzip, "find_7z_binary", lambda: None)
    assert list(sevenzip.iter_7z_members(b"dummy", ".rar")) == []


# -- wrong-password detection ------------------------------------------------ #

def test_wrong_password_detected():
    assert sevenzip._looks_like_wrong_password(2, "ERROR: Wrong password")
    assert sevenzip._looks_like_wrong_password(
        2, "Cannot open encrypted file. Wrong password?"
    )
    assert not sevenzip._looks_like_wrong_password(0, "Everything is Ok")
    assert not sevenzip._looks_like_wrong_password(2, "CRC failed")


# -- extraction flow with a fake 7z ----------------------------------------- #


def _fake_listing(members):
    """Stand-in for sevenzip._list_members returning a successful listing."""

    def fake(binary, archive_path, timeout, password=None):
        return 0, list(members), ""

    return fake


def _make_fake_extract(files: dict[str, bytes], rc: int = 0):
    """Return a stand-in for sevenzip._extract that materialises ``files``."""

    def fake(binary, archive_path, out_dir, password, timeout):
        if rc != 0:
            return rc, "ERROR: simulated failure"
        for rel, content in files.items():
            target = Path(out_dir) / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        return 0, "Everything is Ok"

    return fake


def test_iter_members_reads_extracted_files(monkeypatch):
    monkeypatch.setattr(sevenzip, "find_7z_binary", lambda: Path("/fake/7z"))
    monkeypatch.setattr(
        sevenzip,
        "_list_members",
        _fake_listing([("a.txt", 5), ("sub/b.bin", 2)]),
    )
    monkeypatch.setattr(
        sevenzip, "_extract", _make_fake_extract({"a.txt": b"hello", "sub/b.bin": b"\x00\x01"})
    )
    members = list(sevenzip.iter_7z_members(b"archivebytes", ".rar"))
    names = {name: data for name, data, err in members if err is None}
    assert names["a.txt"] == b"hello"
    assert names["sub/b.bin"] == b"\x00\x01"
    assert all(err is None for _, _, err in members)


def test_iter_members_flags_oversized_member(monkeypatch):
    monkeypatch.setattr(sevenzip, "find_7z_binary", lambda: Path("/fake/7z"))
    monkeypatch.setattr(
        sevenzip, "_list_members", _fake_listing([("big.bin", 16)])
    )
    monkeypatch.setattr(
        sevenzip, "_extract", _make_fake_extract({"big.bin": b"x" * 16})
    )
    monkeypatch.setattr(config, "MAX_EXTRACTED_FILE_SIZE", 8)
    members = list(sevenzip.iter_7z_members(b"archivebytes", ".7z"))
    assert len(members) == 1
    name, data, err = members[0]
    assert name == "big.bin"
    assert data == b""
    assert err is not None and "zu groß" in err


def test_iter_members_rejects_lying_headers(monkeypatch):
    # Lying headers: the listing declares a total within the budget, but the
    # actually extracted volume exceeds it. The disk-footprint guard rejects
    # the WHOLE archive — a lying header means the archive is malicious, so
    # no member is analysed at all (stronger than the old per-member stop).
    monkeypatch.setattr(sevenzip, "find_7z_binary", lambda: Path("/fake/7z"))
    monkeypatch.setattr(
        sevenzip,
        "_list_members",
        _fake_listing([("a.bin", 10), ("b.bin", 1)]),
    )
    monkeypatch.setattr(
        sevenzip,
        "_extract",
        _make_fake_extract({"a.bin": b"x" * 10, "b.bin": b"y" * 10}),
    )
    monkeypatch.setattr(config, "MAX_UNCOMPRESSED_SIZE", 12)
    members = list(sevenzip.iter_7z_members(b"archivebytes", ".rar"))
    assert len(members) == 1
    name, data, err = members[0]
    assert name == "" and data == b""
    assert err is not None and "tatsächlich entpacktes Volumen" in err


def test_iter_members_reports_extraction_failure(monkeypatch):
    monkeypatch.setattr(sevenzip, "find_7z_binary", lambda: Path("/fake/7z"))
    monkeypatch.setattr(sevenzip, "_list_members", _fake_listing([]))
    monkeypatch.setattr(sevenzip, "_extract", _make_fake_extract({}, rc=2))
    members = list(sevenzip.iter_7z_members(b"archivebytes", ".rar"))
    assert len(members) == 1
    name, _data, err = members[0]
    assert name == ""
    assert err is not None and "Returncode 2" in err


# -- pre-flight listing (bomb protection before extraction) ---------------- #

def test_preflight_rejects_bomb_before_extraction(monkeypatch):
    # A bomb-sized archive must be rejected by its declared header sizes BEFORE
    # 7-Zip writes anything to the temp directory.
    monkeypatch.setattr(sevenzip, "find_7z_binary", lambda: Path("/fake/7z"))
    extracted: list[bool] = []

    def fake_extract(binary, archive_path, out_dir, password, timeout):
        extracted.append(True)
        return 0, "Everything is Ok"

    monkeypatch.setattr(sevenzip, "_extract", fake_extract)
    monkeypatch.setattr(
        sevenzip,
        "_list_members",
        lambda binary, archive_path, timeout: (0, [("a.bin", 10), ("b.bin", 10)], ""),
    )
    monkeypatch.setattr(config, "MAX_UNCOMPRESSED_SIZE", 12)
    members = list(sevenzip.iter_7z_members(b"archivebytes", ".rar"))
    assert extracted == []  # extraction must never have run
    assert len(members) == 1
    name, _, err = members[0]
    assert name == ""
    assert err is not None and "abgelehnt" in err


def test_preflight_rejects_too_many_entries(monkeypatch):
    monkeypatch.setattr(sevenzip, "find_7z_binary", lambda: Path("/fake/7z"))
    extracted: list[bool] = []

    def fake_extract(binary, archive_path, out_dir, password, timeout):
        extracted.append(True)
        return 0, "Everything is Ok"

    monkeypatch.setattr(sevenzip, "_extract", fake_extract)
    monkeypatch.setattr(
        sevenzip,
        "_list_members",
        lambda binary, archive_path, timeout: (0, [("a", 1), ("b", 1), ("c", 1)], ""),
    )
    monkeypatch.setattr(config, "MAX_ARCHIVE_ENTRIES", 2)
    members = list(sevenzip.iter_7z_members(b"archivebytes", ".7z"))
    assert extracted == []
    assert any("Einträge" in err for _, _, err in members)


def test_list_members_parses_slt_output(monkeypatch):
    from unittest import mock

    slt = (
        "----------\n"
        "Path = a.txt\n"
        "Folder = -\n"
        "Size = 3\n"
        "Packed Size = 3\n"
        "----------\n"
        "Path = sub/b.bin\n"
        "Size = 5\n"
        "Packed Size = 2\n"
    )
    with mock.patch(
        "malaz.core.sevenzip.run_tool",
        return_value=(0, slt.encode(), b""),
    ) as run:
        rc, members, _ = sevenzip._list_members(Path("/fake/7z"), Path("x.rar"), 5)
    assert rc == 0
    assert members == [("a.txt", 3), ("sub/b.bin", 5)]
    args = run.call_args[0][0]
    assert "l" in args and "-slt" in args


def test_list_members_failure_refuses_extraction(monkeypatch):
    # Security contract: when the pre-flight listing cannot run, the archive
    # must NOT be extracted without the bomb pre-check — a crafted archive
    # that crashes `7z l` but extracts must not be able to fill the disk.
    monkeypatch.setattr(sevenzip, "find_7z_binary", lambda: Path("/fake/7z"))
    extracted: list[bool] = []

    def fake_extract(binary, archive_path, out_dir, password, timeout):
        extracted.append(True)
        return 0, "Everything is Ok"

    monkeypatch.setattr(sevenzip, "_extract", fake_extract)

    def failing_listing(binary, archive_path, timeout, password=None):
        return 2, None, "corrupt listing"

    monkeypatch.setattr(sevenzip, "_list_members", failing_listing)
    members = list(sevenzip.iter_7z_members(b"archivebytes", ".rar"))
    assert extracted == []  # extraction must never have run
    assert len(members) == 1
    name, _data, err = members[0]
    assert name == ""
    assert err is not None and "nicht entpackt" in err


def test_list_members_flags_truncated_output(monkeypatch):
    """SEC-023: a capped listing is incomplete and must say so.

    The visible prefix even parses as a member; the missing rows are exactly
    what the bomb pre-check would have counted. So: no member list at all and
    a sentinel that is not a real 7-Zip exit code.
    """
    from unittest import mock

    from malaz.procio import ToolResult

    slt = "----------\nPath = a.txt\nSize = 3\n"
    with mock.patch(
        "malaz.core.sevenzip.run_tool",
        return_value=ToolResult(0, slt.encode(), b"", truncated=True),
    ):
        rc, members, output = sevenzip._list_members(Path("/fake/7z"), Path("x.7z"), 5)

    assert rc == sevenzip._LIST_TRUNCATED_RC
    assert members is None
    assert "abgeschnitten" in output


def test_truncated_listing_never_extracts_and_never_retries(monkeypatch):
    """A truncated listing must not reach the bomb pre-check or extraction.

    It also must not be retried per password candidate: the cap is a property
    of the output, not of the password, and each retry would re-run the huge
    listing.
    """
    monkeypatch.setattr(sevenzip, "find_7z_binary", lambda: Path("/fake/7z"))
    extracted: list[bool] = []
    calls: list[object] = []

    def fake_extract(binary, archive_path, out_dir, password, timeout):
        extracted.append(True)
        return 0, "Everything is Ok"

    def truncated_listing(binary, archive_path, timeout, password=None):
        calls.append(password)
        return (
            sevenzip._LIST_TRUNCATED_RC,
            None,
            "7-Zip-Listing wurde an der Ausgabe-Obergrenze abgeschnitten",
        )

    monkeypatch.setattr(sevenzip, "_extract", fake_extract)
    monkeypatch.setattr(sevenzip, "_list_members", truncated_listing)
    members = list(
        sevenzip.iter_7z_members(b"archivebytes", ".7z", passwords=["a", "b"])
    )

    assert extracted == []
    assert calls == [None], f"Listing wurde {len(calls)}x gestartet"
    assert len(members) == 1
    name, _data, err = members[0]
    assert name == ""
    assert err is not None
    assert "nicht entpackt" in err and "Bomben-Pre-Check" in err


def test_list_members_retries_with_passwords(monkeypatch):
    # Encrypted-header archives only list with a password; the candidates
    # from the password list must be tried before giving up.
    monkeypatch.setattr(sevenzip, "find_7z_binary", lambda: Path("/fake/7z"))
    seen_passwords: list[object] = []

    def listing(binary, archive_path, timeout, password=None):
        seen_passwords.append(password)
        if password == "infected":
            return 0, [("a.txt", 5)], ""
        return 2, None, "cannot open encrypted archive"

    monkeypatch.setattr(sevenzip, "_list_members", listing)
    monkeypatch.setattr(
        sevenzip, "_extract", _make_fake_extract({"a.txt": b"hello"})
    )
    members = list(sevenzip.iter_7z_members(b"archivebytes", ".rar"))
    assert any(m[0] == "a.txt" and m[2] is None for m in members)
    assert "infected" in seen_passwords


# -- Zip-Slip im 7z-Pfad (Befund des Security-Audits) ------------------------ #

def test_list_members_ignores_archive_header_block(monkeypatch):
    """Der Archiv-Kopf darf nicht als Member gelten.

    '7z l -slt' druckt vor der Member-Liste einen Block ueber das ARCHIV
    selbst (eigener 'Path = <absoluter Archivpfad>'). Wurde der mitgeparst,
    zaehlte das Archiv als eigener Eintrag: die Bomben-Vorpruefung rechnete
    mit einer Nummer zu viel, und der absolute Pfad tauchte als Member auf.
    Gegen 7-Zip 26.03 gemessen: zwei Trennlinien, '--' und '----------'.
    """
    from unittest import mock

    slt = (
        "7-Zip (a) 26.03 : Copyright (c)\n"
        "\n"
        "Listing archive: C:\\temp\\archive.7z\n"
        "\n"
        "--\n"
        "Path = C:\\temp\\archive.7z\n"
        "Type = 7z\n"
        "Physical Size = 313\n"
        "\n"
        "----------\n"
        "Path = sub\\good.txt\n"
        "Size = 2\n"
    )
    with mock.patch("malaz.core.sevenzip.run_tool", return_value=(0, slt.encode(), b"")):
        rc, members, _ = sevenzip._list_members(Path("/fake/7z"), Path("x.7z"), 5)
    assert rc == 0
    assert members == [("sub\\good.txt", 2)], members


def test_iter_members_reports_zipslip_before_extracting(monkeypatch):
    """Ein Traversal-Name muss gemeldet werden — VOR dem Entpacken.

    7-Zip saeubert solche Namen beim Entpacken still (mit 26.03 gemessen:
    '../../x', '..\\..\\x' und ein absoluter Pfad landen alle INNERHALB des
    Zielverzeichnisses). Die Extraktion meldet also Erfolg, der Walk sieht nur
    sichere Namen — ohne diese Pruefung bliebe der Versuch spurlos. Der
    ZIP-Pfad meldet dasselbe als ARCH_ZIPSLIP (CRITICAL).
    """
    monkeypatch.setattr(sevenzip, "find_7z_binary", lambda: Path("/fake/7z"))
    monkeypatch.setattr(
        sevenzip,
        "_list_members",
        _fake_listing([("..\\..\\evil.txt", 5), ("good.txt", 3)]),
    )
    monkeypatch.setattr(
        sevenzip, "_extract", _make_fake_extract({"good.txt": b"abc"})
    )
    members = list(sevenzip.iter_7z_members(b"bytes", ".7z"))
    errors = [err for _, _, err in members if err]
    assert any(err.startswith("Zip-Slip:") for err in errors), errors
    # Und der Inhalt wird trotzdem gescannt: der Angriff verhindert die
    # Analyse der uebrigen Mitglieder nicht.
    assert any(name == "good.txt" and err is None for name, _d, err in members)


def test_iter_members_no_zipslip_on_benign_names(monkeypatch):
    """Gegenprobe: harmlose Namen duerfen keinen Zip-Slip melden."""
    monkeypatch.setattr(sevenzip, "find_7z_binary", lambda: Path("/fake/7z"))
    monkeypatch.setattr(
        sevenzip,
        "_list_members",
        _fake_listing([("sub\\good.txt", 5), ("a.txt", 3)]),
    )
    monkeypatch.setattr(
        sevenzip, "_extract", _make_fake_extract({"good.txt": b"abc", "a.txt": b"de"})
    )
    members = list(sevenzip.iter_7z_members(b"bytes", ".7z"))
    assert not any(err and "Zip-Slip" in err for _, _, err in members), members


def test_zipslip_becomes_critical_indicator():
    """Der Befund muss als ARCH_ZIPSLIP mit CRITICAL im Ergebnis landen.

    Sonst waere der RAR/7z-Weg der leise Umweg um die ZIP-Erkennung.
    """
    from malaz.core.dispatcher import Dispatcher
    from malaz.models import Severity

    note = Dispatcher()._container_note(
        "Zip-Slip: 1 Eintragsname(n) wuerden aus dem Ziel schreiben",
        "(RAR/7z-Inhalt)",
        0,
        "ARCH_7Z_ERROR",
        "Archiv konnte nicht entpackt werden",
    )
    zipslip = [i for i in note.indicators if i.rule_id == "ARCH_ZIPSLIP"]
    assert len(zipslip) == 1, [i.rule_id for i in note.indicators]
    assert zipslip[0].severity is Severity.CRITICAL
    assert zipslip[0].weight == 50


# -- Temp-Name: Zeichenvorrat UND Laengenkappe (Befund des Security-Audits) --- #

def test_iter_members_survives_a_200_char_suffix(monkeypatch, tmp_path):
    """Eine lange Endung darf den Scan nicht sprengen (MAX_PATH).

    Die Endung stammt aus dem Namen des gescannten Archivs. Der handgeschriebene
    Sanitizer in ``iter_7z_members`` filterte nur Zeichen, kappte aber nicht:
    eine 200-Zeichen-Endung schob den Temp-Pfad ueber MAX_PATH, ``write_bytes``
    warf FileNotFoundError, und die Ausnahme entkam dem Generator bis in den
    Dispatcher, wo sie das GESAMTE Scanergebnis durch CORE_ERROR ersetzte
    (gemessen: ZIP mit Zip-Slip ohne Decoy RED/50, mit langem Member-Namen
    GRUEN/5). ``procio.safe_temp_suffix`` ist genau dafuer die Senke — die vier
    anderen Materialisierungsstellen nutzen sie bereits.

    Die Laenge der Temp-Basis wird hier auf 180 Zeichen festgenagelt, damit die
    Pfadgrenze nicht von der Laenge des System-Temp abhaengt: 180 + 'archive' +
    gekappter Endung passt (<= 260), 180 + 'archive' + 201 Zeichen nicht.
    """
    pad = 180 - len(str(tmp_path)) - 1
    assert pad > 0, f"tmp_path zu lang fuer den Test: {tmp_path}"
    base = tmp_path / ("w" * pad)
    base.mkdir()
    assert len(str(base)) == 180
    monkeypatch.setattr(sevenzip.tempfile, "mkdtemp", lambda *a, **kw: str(base))
    monkeypatch.setattr(sevenzip, "find_7z_binary", lambda: Path("/fake/7z"))
    monkeypatch.setattr(sevenzip, "_list_members", _fake_listing([("a.txt", 5)]))
    monkeypatch.setattr(
        sevenzip, "_extract", _make_fake_extract({"a.txt": b"hello"})
    )

    members = list(sevenzip.iter_7z_members(b"archivebytes", "." + "a" * 200))

    # Kein Ausnahmefluss: das Mitglied wird gelesen und bleibt auswertbar.
    assert [(name, data) for name, data, err in members if err is None] == [
        ("a.txt", b"hello")
    ]
    assert not [err for _, _, err in members if err], members


def test_iter_members_keeps_extension_for_normal_suffixes(monkeypatch):
    """Gegenprobe: gewoehnliche Endungen kommen unveraendert beim Temp-Name an.

    Der Sanitizer darf nur kappen/filtern — 7-Zip waehlt seinen Parser nach der
    Endung.
    """
    seen: list[str] = []
    monkeypatch.setattr(sevenzip, "find_7z_binary", lambda: Path("/fake/7z"))
    monkeypatch.setattr(sevenzip, "_list_members", _fake_listing([]))

    def fake_extract(binary, archive_path, out_dir, password, timeout):
        seen.append(archive_path.name)
        return 0, "Everything is Ok"

    monkeypatch.setattr(sevenzip, "_extract", fake_extract)
    list(sevenzip.iter_7z_members(b"archivebytes", ".7z"))
    list(sevenzip.iter_7z_members(b"archivebytes", ".RAR"))
    assert seen == ["archive.7z", "archive.RAR"], seen


def test_ungewoehnlicher_name_kommt_mild_an():
    """Derselbe milde Marker muss auch beim RAR/7z-Weg mild ankommen.

    Die vier Meldewege (ZIP-Pipeline, TAR-Walk, RAR/7z, Container-Notiz im
    Dispatcher) muessen GLEICH urteilen — sonst waere ein "CON.txt"-Mitglied
    im ZIP mild und im RAR weiterhin CRITICAL, also genau die Asymmetrie, die
    ``test_container_traversal_symmetry`` verhindern soll.

    Ein 7z-Binary ist zum Testzeitpunkt nicht garantiert vorhanden (auf diesem
    Rechner: nicht installiert), deshalb wird hier der Vertrag geprueft, auf
    den sich der 7z-Weg verlaesst: der Marker kommt an. Der Pruefer selbst und
    die Trennung sind in test_safe_extract.py und test_archive.py abgedeckt.
    """
    from malaz.core.dispatcher import Dispatcher
    from malaz.models import Severity

    note = Dispatcher()._container_note(
        "Ungewoehnlicher Name: 1 Eintragsname(n) sind ungewoehnlich "
        "(reservierte Windows-Geraetenamen). Beispiele: CON.txt",
        "(RAR/7z-Inhalt)",
        0,
        "ARCH_7Z_ERROR",
        "Archiv konnte nicht entpackt werden",
    )
    regeln = {i.rule_id: i for i in note.indicators}
    assert "ARCH_ZIPSLIP" not in regeln, "kein Traversal — kein Anker"
    assert "ARCH_UNSAFE_NAME" in regeln, sorted(regeln)
    assert regeln["ARCH_UNSAFE_NAME"].severity is Severity.LOW
    assert regeln["ARCH_UNSAFE_NAME"].weight == 5
