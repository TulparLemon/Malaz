import hashlib
import io
import os
import tempfile
import zipfile

import pytest

from malaz.analysis.clamav import ClamAVScanner
from malaz.analysis.windows_av import WindowsDefenderScanner
from malaz.core.dispatcher import Dispatcher
from malaz.models import CAT_AV, Indicator, RiskLevel, Severity


@pytest.fixture()
def dispatcher():
    # Disable BOTH AV engines in unit tests for speed/determinism (archive
    # members would otherwise go through the real engines, too).
    return Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )


def _scan(dispatcher, data: bytes, suffix: str):
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.write(fd, data)
    os.close(fd)
    try:
        return dispatcher.scan_path(path)
    finally:
        os.unlink(path)


def test_malicious_pdf_is_red(dispatcher):
    r = _scan(dispatcher, b"%PDF-1.7\n/Launch /JavaScript\n%%EOF", ".pdf")
    assert r.detected_type == "pdf"
    assert r.risk_level == RiskLevel.RED
    assert r.anchored


def test_benign_text_is_green(dispatcher):
    r = _scan(dispatcher, b"hello world, just a normal text file", ".txt")
    assert r.risk_level == RiskLevel.GREEN


def test_zip_recursion(dispatcher):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("inner.txt", b"inner content")
    r = _scan(dispatcher, buf.getvalue(), ".zip")
    assert r.detected_type == "zip"
    assert len(r.children) == 1
    assert r.children[0].display_name == "inner.txt"


def test_zip_with_malicious_member_anchors_parent(dispatcher):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("evil.pdf", b"%PDF-1.7\n/Launch\n%%EOF")
    r = _scan(dispatcher, buf.getvalue(), ".zip")
    # Parent aggregates child indicators -> red via anchor.
    assert r.risk_level == RiskLevel.RED


@pytest.mark.parametrize(
    "compression", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED]
)
def test_prefixed_zip_scans_its_members(dispatcher, compression):
    """SEC-001: ein Präfixbyte vor dem ZIP schaltete die Rekursion ab.

    ``magic.detect`` prüft ZIP nur an Offset 0; ``b"X" + zip`` war "unknown"
    (bzw. "pe" bei MZ-Präfix), der Archivzweig lief nie und der Inhalt galt
    als GRÜN. Gemessen: dasselbe PDF im Archiv ergab als reines ZIP ROT 100,
    präfixiert nur GRÜN 5.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as zf:
        zf.writestr("evil.pdf", b"%PDF-1.7\n/Launch /JavaScript\n%%EOF")
    archive = buf.getvalue()

    plain = _scan(dispatcher, archive, ".zip")
    prefixed = _scan(dispatcher, b"X" + archive, ".zip")
    # MZ-Präfix: magic.detect liefert „pe“ — trotzdem ein Archiv.
    mz_prefixed = _scan(dispatcher, b"MZ" + b"\x00" * 62 + archive, ".bin")

    # (2) Das normale ZIP bleibt unverändert.
    assert plain.detected_type == "zip"
    assert [c.display_name for c in plain.children] == ["evil.pdf"]
    assert plain.risk_level == RiskLevel.RED

    for result in (prefixed, mz_prefixed):
        assert result.detected_type == "zip"
        assert [c.display_name for c in result.children] == ["evil.pdf"]
        assert result.risk_level == RiskLevel.RED, result.score


def test_stray_eocd_without_central_directory_is_not_an_archive(dispatcher):
    """Ein zufälliges ``PK\\x05\\x06`` darf kein Archiv erfinden.

    Die Bestätigung läuft über ``zipfile``: Bytes ohne lesbares
    Zentralverzeichnis bleiben ihr erkannter Typ, statt als (leeres) Archiv
    zu gelten — sonst trüge jedes Binärformat mit diesen vier Bytes einen
    Archivzweig.
    """
    data = bytes(range(256)) * 30 + b"PK\x05\x06" + b"\xff" * 18
    with pytest.raises(zipfile.BadZipFile):
        zipfile.ZipFile(io.BytesIO(data))

    r = _scan(dispatcher, data, ".bin")
    assert r.detected_type != "zip"
    assert r.children == []


def test_prefixed_zip_beyond_the_read_cap_keeps_the_truncation_note(
    dispatcher, monkeypatch, tmp_path
):
    """Der große Präfix-Fall: EOCD liegt außerhalb des Puffers.

    Oberhalb ``MAX_LARGE_FILE_SIZE`` steht nur ein Präfix in ``data``; die
    Prüfung muss über den Pfad laufen (dort liegt das EOCD), die Mitglieder
    kommen aus der vollständigen Datei. Die Kappung bleibt als
    CORE_READ_TRUNCATED sichtbar — ohne doppelte Container-Fehlermeldung.
    """
    monkeypatch.setattr("malaz.config.MAX_LARGE_FILE_SIZE", 512)
    monkeypatch.setattr("malaz.config.MAX_LARGE_PREFIX_SIZE", 128)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("evil.pdf", b"%PDF-1.7\n/Launch /JavaScript\n%%EOF")
        zf.writestr("padding.bin", b"\x00" * 4096)
    target = tmp_path / "gross.zip"
    target.write_bytes(b"X" + buf.getvalue())

    r = dispatcher.scan_path(target)

    ids = {i.rule_id for i in r.indicators}
    assert "CORE_READ_TRUNCATED" in ids, sorted(ids)
    assert "ARCH_ZIP_ERROR" not in ids, "die volle Datei ist lesbar"
    assert r.detected_type == "zip"
    assert "evil.pdf" in [c.display_name for c in r.children]
    assert r.risk_level == RiskLevel.RED, r.score


def test_broken_large_zip_keeps_real_container_error_weight(
    dispatcher, tmp_path, monkeypatch
):
    """SEC-006: the full file is readable by path; a real ARCH_ZIP_ERROR counts.

    The ZIP branch passes ``source_path`` (the complete file), yet the cap flag
    from the in-memory prefix zeroed the container note: 25 -> 0 and the text
    blamed a "Lesekappung" that did not apply.
    """
    monkeypatch.setattr("malaz.config.MAX_LARGE_FILE_SIZE", 1024)
    monkeypatch.setattr("malaz.config.MAX_LARGE_PREFIX_SIZE", 256)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", b"x" * 64)
    blob = bytearray(buf.getvalue())
    eocd = blob.rfind(b"PK\x05\x06")
    assert eocd >= 0
    blob[eocd:eocd + 4] = b"\x00" * 4
    target = tmp_path / "kaputt.zip"
    target.write_bytes(bytes(blob) + b"\x00" * 4096)

    r = dispatcher.scan_path(target)

    archive_notes = [
        i for i in r.all_indicators() if i.rule_id == "ARCH_ZIP_ERROR"
    ]
    assert archive_notes, sorted(i.rule_id for i in r.all_indicators())
    assert archive_notes[0].weight == 25, archive_notes[0].detail
    assert "Lesekappung" not in archive_notes[0].detail


def test_zipslip_is_red(dispatcher):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../evil.txt", b"x")
    r = _scan(dispatcher, buf.getvalue(), ".zip")
    assert r.risk_level == RiskLevel.RED
    assert any(i.rule_id == "ARCH_ZIPSLIP" for i in r.indicators)


def test_high_entropy_blob(dispatcher):
    r = _scan(dispatcher, os.urandom(60_000), ".bin")
    assert any(i.rule_id == "GEN_ENTROPY" for i in r.indicators)


def test_oversized_file_rejected(dispatcher, monkeypatch):
    from malaz import config

    monkeypatch.setattr(config, "MAX_FILE_SIZE", 10)
    r = _scan(dispatcher, b"x" * 100, ".bin")
    assert r.error is not None
    assert any(i.rule_id == "CORE_LIMIT" for i in r.indicators)


def test_hashes_computed(dispatcher):
    r = _scan(dispatcher, b"abc", ".bin")
    assert len(r.sha256) == 64
    assert len(r.md5) == 32


def test_hash_covers_full_file_beyond_read_cap(dispatcher, monkeypatch):
    # Regression: files larger than the read cap were reported with the hash of
    # their truncated prefix, so integrity checks and the hash blocklist could
    # never match them.
    from malaz import config

    monkeypatch.setattr(config, "MAX_READ_SIZE", 64)
    data = os.urandom(200)  # data is truncated to 64 bytes for analysis
    r = _scan(dispatcher, data, ".bin")
    assert r.sha256 == hashlib.sha256(data).hexdigest()
    assert r.md5 == hashlib.md5(data, usedforsecurity=False).hexdigest()
    assert r.sha256 != hashlib.sha256(data[:64]).hexdigest()


def test_blocklist_matches_full_file_hash(dispatcher, monkeypatch, tmp_path):
    # The blocklist check must use the full-file hash, not the truncated data.
    from malaz import config

    monkeypatch.setattr(config, "MAX_READ_SIZE", 32)
    monkeypatch.setattr(config, "HASH_BLOCKLIST_FILE", tmp_path / "blocklist.sha256")
    data = os.urandom(100)
    (tmp_path / "blocklist.sha256").write_text(
        hashlib.sha256(data).hexdigest() + "\n"
    )
    r = _scan(dispatcher, data, ".bin")
    assert any(i.rule_id == "GEN_HASH_BLOCKLIST" for i in r.indicators)


def _make_tar_gz(entries: dict[str, bytes]) -> bytes:
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_tar_gz_recursion(dispatcher):
    data = _make_tar_gz({"inner.txt": b"innocent text"})
    r = _scan(dispatcher, data, ".tar.gz")
    assert r.detected_type == "gzip"
    assert len(r.children) == 1
    assert r.children[0].display_name == "inner.txt"


def test_tar_gz_malicious_member_anchors_parent(dispatcher):
    data = _make_tar_gz({"evil.pdf": b"%PDF-1.7\n/Launch\n%%EOF"})
    r = _scan(dispatcher, data, ".tar.gz")
    assert r.risk_level == RiskLevel.RED
    assert any(
        c.detected_type == "pdf" and c.risk_level == RiskLevel.RED
        for c in r.children
    )


def _skipped_indicator() -> Indicator:
    """'Engine meldete nichts' — seit dem run_tool-Umbau liefern die
    Scan-Wrapper immer einen Indicator (SKIPPED statt None)."""
    return Indicator(
        rule_id="AV_SKIPPED", title="Scan übersprungen",
        severity=Severity.INFO, category=CAT_AV, weight=0,
    )


def test_throwing_external_scanner_keeps_existing_indicators(dispatcher):
    """BUG-006: a scanner exception replaced a RED result with CORE_ERROR.

    The call sat outside every isolation layer; ``scan_path``'s broad catch
    discarded the PDF findings already collected (RED 80 -> YELLOW 25).
    """

    class _Throwing:
        name = "Boom"
        available = True

        def scan_path(self, _path):
            raise RuntimeError("simulierter Scanner-Ausfall")

    dispatcher.external_scanners = [_Throwing()]
    r = _scan(dispatcher, b"%PDF-1.7\n/Launch /JavaScript\n%%EOF", ".pdf")

    ids = {i.rule_id for i in r.indicators}
    assert r.risk_level == RiskLevel.RED, r.score
    assert "EXT_BOOM_ERROR" in ids, sorted(ids)
    assert "CORE_ERROR" not in ids, "der Scanner-Ausfall hat den Scan ersetzt"
    assert any(rule.startswith("PDF_") for rule in ids), sorted(ids)


def test_av_revision_change_is_reported(tmp_path, monkeypatch):
    """SEC-005: the engines open ``real_path`` after the read-side stat.

    A file swapped during the AV stage was judged in a revision that was never
    analysed, with no finding — and a clean vote even discounted the score.
    """
    d = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    target = tmp_path / "harmlos.txt"
    target.write_bytes(b"original content")

    def swapping_av(real_path):
        real_path.write_bytes(b"clean replacement with other length")
        return Indicator(
            rule_id="AV_CLEAN", title="keine Bedrohung",
            severity=Severity.INFO, category=CAT_AV, weight=0,
        )

    monkeypatch.setattr(d, "_av_scan", swapping_av)
    r = d.scan_path(target)

    ids = {i.rule_id for i in r.indicators}
    assert "CORE_FILE_CHANGED" in ids, sorted(ids)
    assert r.risk_level != RiskLevel.GREEN, r.score


def test_av_intervention_anomaly_flagged(tmp_path, monkeypatch):
    # Datei verschwindet während des Scans, ohne AV-Treffer -> Warnung (HIGH),
    # NICHT still als "sauber" anzeigen (Regression: VM-Korpus-Befund).
    d = Dispatcher(av_scanner=WindowsDefenderScanner(enabled=False))
    f = tmp_path / "x.bin"
    f.write_bytes(b"harmlos")

    def fake_av(real_path):
        real_path.unlink()  # AV "entfernt" die Datei, meldet aber nichts
        return _skipped_indicator()

    monkeypatch.setattr(d, "_av_scan", fake_av)
    monkeypatch.setattr(d, "_clam_scan", lambda p: _skipped_indicator())
    r = d.scan_path(f)
    eingriff = [i for i in r.all_indicators() if i.rule_id == "AV_EINGRIFF"]
    assert len(eingriff) == 1
    assert eingriff[0].severity == Severity.HIGH
    assert eingriff[0].weight == 30


def test_av_intervention_with_threat_is_info(tmp_path, monkeypatch):
    # Datei verschwindet UND ein AV-Treffer wurde gemeldet -> ergänzende Info
    # ohne Gewicht; der Treffer selbst trägt die Bewertung.
    d = Dispatcher(av_scanner=WindowsDefenderScanner(enabled=False))
    f = tmp_path / "x.bin"
    f.write_bytes(b"harmlos")

    def fake_av(real_path):
        real_path.unlink()
        return Indicator(
            rule_id="AV_THREAT", title="Bedrohung erkannt",
            severity=Severity.CRITICAL, category=CAT_AV, weight=50,
        )

    monkeypatch.setattr(d, "_av_scan", fake_av)
    monkeypatch.setattr(d, "_clam_scan", lambda p: _skipped_indicator())
    r = d.scan_path(f)
    eingriff = [i for i in r.all_indicators() if i.rule_id == "AV_EINGRIFF"]
    assert len(eingriff) == 1
    assert eingriff[0].severity == Severity.INFO
    assert r.risk_level == RiskLevel.RED  # via AV_THREAT


def test_plain_gzip_payload_scanned(dispatcher):
    import gzip

    data = gzip.compress(b"%PDF-1.7\n/Launch /JavaScript\n%%EOF")
    r = _scan(dispatcher, data, ".gz")
    # Single-stream fallback: the decompressed PDF inside gets scanned.
    assert len(r.children) == 1
    assert r.children[0].detected_type == "pdf"
    assert r.risk_level == RiskLevel.RED


# --- Befund #2/#3/#4/#7: nicht analysierte Bereiche dürfen nicht grün wirken --


def _tar_with_traversal(n_padding: int) -> bytes:
    """TAR mit genau einer Traversal-Datei, dann ``n_padding`` harmlose."""
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        ti = tarfile.TarInfo("../evil.txt")
        ti.size = 1
        tf.addfile(ti, io.BytesIO(b"x"))
        for i in range(n_padding):
            t = tarfile.TarInfo(f"f{i}.txt")
            t.size = 1
            tf.addfile(t, io.BytesIO(b"y"))
    return buf.getvalue()


def test_tar_entry_limit_and_member_limit_charge_once(dispatcher, monkeypatch):
    """BUG-001: TAR-Eintragslimit + Mitgliederlimit ergaben 50 = ROT.

    ``iter_compressed_members`` liefert die Eintragslimit-Notiz aus dem
    Metadaten-Vorlauf VOR dem Walk (ZIP/7z liefern sie am Ende). Die
    Dedup-Suche begann aber erst HINTER der Skip-Notiz
    (``children[note_start:]``) und fand die Eintragslimit-Notiz deshalb nie:
    beide Stopps wurden mit 25 gewertet, 25 + 25 = 50 = ANCHOR_CRITICAL_SCORE.
    Gemessen vor dem Fix: dasselbe harmlose TAR ROT 50, das ZIP-Äquivalent
    GELB 25.
    """
    from malaz import config

    monkeypatch.setattr(config, "MAX_ARCHIVE_ENTRIES", 5)
    monkeypatch.setattr(config, "MAX_RECURSIVE_MEMBERS", 3)

    r = _scan(dispatcher, _tar_with_fat_members(20, 16, traversal_at=-1), ".tar")

    assert r.risk_level == RiskLevel.YELLOW, f"score={r.score} {_weights(r)}"
    stop = [i for i in r.all_indicators() if i.rule_id == "ARCH_MEMBER_STOP"]
    skip = [i for i in r.all_indicators() if i.rule_id == "ARCH_MEMBER_SKIP"]
    assert stop and stop[0].weight == 25, "die Eintragslimit-Notiz traegt die Ursache"
    # Sichtbar bleiben, aber nicht ein zweites Mal wiegen.
    assert skip, "die Responsiveness-Notiz darf nicht verschwinden"
    assert skip[0].weight == 0, "dieselbe Ursache darf nicht doppelt zaehlen"


def test_unconfirmed_clamav_threat_is_not_green(dispatcher):
    """SEC-002: ein unbestätigter ClamAV-Fund wog 15 und blieb GRÜN.

    ``clamscan`` liefert rc=1 ohne parsebare FOUND-Zeile (z. B.
    Kodierungsschaden). Der Dispatcher stufte das zu Recht als MEDIUM ein —
    aber MEDIUMs Basisgewicht ist 15, und SCORE_GREEN_MAX ist 19: eine
    infizierte Datei wurde mit GRÜN 15 als Freispruch angezeigt. 25 hebt sie
    über die GRÜN-Schwelle, ohne den CRITICAL-Anker zu erfinden, den die
    fehlende FOUND-Zeile nicht belegt.
    """
    from types import SimpleNamespace

    from malaz.core.scoring import compute_score

    def clam(name: str, detail: str = "") -> SimpleNamespace:
        return SimpleNamespace(
            limit_exceeded=False,
            threat_found=True,
            threat_name=name,
            detail=detail or name,
            clean=False,
            skipped_reason="",
        )

    unconfirmed = dispatcher._clam_indicator(
        clam("unbestätigt (keine FOUND-Zeile in der Ausgabe)")
    )
    breakdown = compute_score([unconfirmed])
    assert unconfirmed.weight >= 25, unconfirmed.weight
    assert breakdown.risk_level != RiskLevel.GREEN, (
        f"score={breakdown.score} fuer einen gemeldeten ClamAV-Fund"
    )
    assert breakdown.risk_level != RiskLevel.RED, "kein Anker ohne FOUND-Zeile"

    # Gegenprobe: die bestaetigte FOUND-Zeile behaelt den Anker.
    confirmed = dispatcher._clam_indicator(clam("Eicar-Test-Signature"))
    assert compute_score([confirmed]).risk_level == RiskLevel.RED


def test_zipslip_note_survives_the_member_limit(dispatcher, monkeypatch):
    """Befund #2: ``break`` verschluckte die Zip-Slip-Meldung.

    Die Zusammenfassungen der Container-Iteratoren kommen als LETZTES yield,
    nach dem Durchlauf. Das Limit beendet den Generator per ``break`` — die
    Meldung kam nie an. Gemessen: 250 Mitglieder -> ROT 50, 251 -> GRÜN 0,
    der Angriff verschwand spurlos, allein durch ein Mitglied mehr.
    """
    monkeypatch.setattr("malaz.config.MAX_RECURSIVE_MEMBERS", 20)

    below = _scan(dispatcher, _tar_with_traversal(10), ".tar")
    above = _scan(dispatcher, _tar_with_traversal(40), ".tar")

    assert "ARCH_ZIPSLIP" in {i.rule_id for i in below.all_indicators()}
    assert "ARCH_ZIPSLIP" in {i.rule_id for i in above.all_indicators()}, (
        "die Traversal-Meldung darf nicht am Mitgliederlimit verfallen"
    )
    assert above.risk_level == RiskLevel.RED


def test_skipped_members_are_not_green(dispatcher, monkeypatch):
    """Befund #7: ein hinter das Limit gelegtes Mitglied wirkte entlastend.

    Gewicht 0 hieß: den ganzen Inhalts-Schritt abschalten kostet nichts.
    Gemessen: dieselbe Archivdatei ROT 90 mit der Nutzlast vorn und GELB 30
    mit der Nutzlast hinter genug harmlosen Einträgen.
    """
    monkeypatch.setattr("malaz.config.MAX_RECURSIVE_MEMBERS", 10)

    payload = b"powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"

    def archive(payload_first: bool) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            if payload_first:
                zf.writestr("boese.ps1", payload)
            for i in range(50):
                zf.writestr(f"h{i}.txt", b"x")
            if not payload_first:
                zf.writestr("boese.ps1", payload)
        return buf.getvalue()

    first = _scan(dispatcher, archive(True), ".zip")
    last = _scan(dispatcher, archive(False), ".zip")

    assert first.risk_level == RiskLevel.RED
    assert last.risk_level != RiskLevel.GREEN, (
        "ein nicht gescanntes Mitglied darf nie grün ergeben"
    )
    skip = [
        i for i in last.all_indicators() if i.rule_id == "ARCH_MEMBER_SKIP"
    ]
    assert skip, "der übersprungene Bereich muss gemeldet werden"
    assert skip[0].weight > 0
    assert "ungeprüft" in skip[0].title.lower() or "nicht" in skip[0].title.lower()


def test_failing_member_keeps_the_parent_findings(dispatcher, monkeypatch):
    """Befund #3: eine Ausnahme beim Mitglied ersetzte das GANZE Ergebnis.

    ``result = self._scan(...)`` in ``_scan_children`` wurde nie zugewiesen,
    also trug das frische ScanResult keinen einzigen Indikator — nur
    CORE_ERROR blieb übrig. Gemessen: ein Archiv mit Zip-Slip-Eintrag ROT 50,
    und GRÜN 5, sobald ein einziges Mitglied beim Scannen warf.
    """
    real_scan = dispatcher._scan

    def boom(data, path, depth, **kwargs):
        if depth > 0:  # nur Mitglieder, nicht die oberste Datei
            raise OSError("simulierter Ausfall beim Mitglied")
        return real_scan(data, path, depth, **kwargs)

    baseline = _scan(dispatcher, _tar_with_traversal(2), ".tar")
    assert baseline.risk_level == RiskLevel.RED
    assert "ARCH_ZIPSLIP" in {i.rule_id for i in baseline.all_indicators()}

    monkeypatch.setattr(dispatcher, "_scan", boom)
    broken = _scan(dispatcher, _tar_with_traversal(2), ".tar")

    ids = {i.rule_id for i in broken.all_indicators()}
    assert "ARCH_ZIPSLIP" in ids, "der Befund darf nicht mit der Ausnahme verfallen"
    assert broken.error is None, "die Ausnahme darf nicht das ganze Ergebnis ersetzen"
    assert broken.risk_level == RiskLevel.RED
    # Runde 4: das werfende Mitglied hat eine eigene ID ("dieses Mitglied
    # wurde nicht analysiert"), ARCH_MEMBER_STOP gehört allein dem
    # Bombenschutz-Stopp.
    assert "ARCH_MEMBER_ERROR" in ids, "der Ausfall selbst muss sichtbar sein"


def test_failing_container_recursion_is_reported(dispatcher, monkeypatch):
    """Fällt die ganze Container-Rekursion aus, bleibt der Rest erhalten."""

    def boom(*_a, **_k):
        raise OSError("simulierter Ausfall beim Entpacken")

    monkeypatch.setattr(dispatcher, "_scan_compressed_members", boom)
    broken = _scan(dispatcher, _tar_with_traversal(2), ".tar")

    ids = {i.rule_id for i in broken.all_indicators()}
    # Runde 4: die geworfene Container-Rekursion hat eine eigene ID; sie teilte
    # sich ARCH_MEMBER_STOP mit dem Bombenschutz-Stopp, wodurch "Container-
    # Ausnahme" und "bewusst nur teilentpackt" ununterscheidbar wurden.
    assert "ARCH_CONTAINER_ERROR" in ids, "der Ausfall selbst muss sichtbar sein"
    assert "ARCH_MEMBER_STOP" not in ids, (
        "ARCH_MEMBER_STOP gehört allein dem Bombenschutz-Stopp"
    )
    assert broken.risk_level != RiskLevel.GREEN


def test_unscanned_file_is_never_green(dispatcher, monkeypatch):
    """Befund #3b: CORE_ERROR wog 5, die GRÜN-Schwelle liegt bei 19.

    Eine Datei, die NIE geprüft wurde, wurde damit als grün ausgewiesen —
    genau die Entlastung, die der eigene Kommentar des Indikators verbietet.
    """

    def boom(*_a, **_k):
        raise OSError("gesperrt")

    monkeypatch.setattr(dispatcher, "_scan", boom)
    fd, path = tempfile.mkstemp(suffix=".bin")
    os.write(fd, b"harmlos")
    os.close(fd)
    try:
        r = dispatcher.scan_path(path)
    finally:
        os.unlink(path)

    assert "CORE_ERROR" in {i.rule_id for i in r.indicators}
    assert r.risk_level != RiskLevel.GREEN


def test_read_cap_is_reported(dispatcher, monkeypatch, tmp_path):
    """Befund #4: zwischen Lese- und Dateigrenze war die Kappung unsichtbar.

    Analysiert werden nur MAX_READ_SIZE Bytes; bis MAX_FILE_SIZE feuert kein
    Limit-Indikator. Gemessen: identische Bytes ROT 80 unter der Grenze und
    GRÜN 0 darüber. Die fünf Geschwisterstufen melden eine Kappung, diese nicht.
    """
    monkeypatch.setattr("malaz.config.MAX_READ_SIZE", 4096)
    monkeypatch.setattr("malaz.config.MAX_FILE_SIZE", 8192)

    small = tmp_path / "klein.bin"
    small.write_bytes(b"\x00" * 2048 + b"harmlos")
    big = tmp_path / "gross.bin"
    big.write_bytes(b"\x00" * 4096 + b"hinter der Lesegrenze" + b"\x00" * 2048)

    r_small = dispatcher.scan_path(small)
    r_big = dispatcher.scan_path(big)

    assert "CORE_READ_TRUNCATED" not in {i.rule_id for i in r_small.indicators}
    ids = {i.rule_id for i in r_big.indicators}
    assert "CORE_READ_TRUNCATED" in ids, "die Kappung muss sichtbar sein"
    assert r_big.risk_level != RiskLevel.GREEN


def test_short_read_between_stat_and_read_is_reported(dispatcher, tmp_path, monkeypatch):
    """Befund #2: ein kurzer Lesevorgang blieb ohne jede Markierung.

    ``scan_path`` nahm die Größe aus dem ``stat`` VOR dem Lesen und behandelte
    den Puffer als vollständige Revision. Gemessen mit absichtlich veraltetem
    stat: angekündigt 1048576 Bytes, tatsächlich gelesen 4096, gemeldeter
    sha256 = Hash genau dieser 4096 Byte, 0 Indikatoren, GRÜN — während
    derselbe Fall im Nachbarzweig (Lesekappung) CORE_READ_TRUNCATED 20 = GELB
    ergibt und ein natürlicher Race 154 von 200 Scans mit einem Hash aus zwei
    Revisionen lieferte, ohne CORE_ERROR.
    """
    from pathlib import Path

    target = tmp_path / "schrumpft.bin"
    target.write_bytes(b"A" * 4096)

    # Das Renn-Fenster deterministisch nachgestellt: der erste stat für genau
    # diese Datei sagt 1 MiB an, auf der Platte liegen 4096 Byte — die Datei
    # wurde zwischen Größenabfrage und Lesen verkleinert. Jeder weitere stat
    # (auch der zweite Blick nach dem Lesen) ist echt.
    real_stat = Path.stat
    stale = os.stat_result(
        (*tuple(real_stat(target))[:6], 1024 * 1024, *tuple(real_stat(target))[7:])
    )
    state = {"stale_used": False}

    def fake_stat(self, *args, **kwargs):
        if self == target and not state["stale_used"]:
            state["stale_used"] = True
            return stale
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", fake_stat)
    r = dispatcher.scan_path(target)

    ids = {i.rule_id for i in r.indicators}
    assert "CORE_READ_SHORT" in ids, (
        f"der kurze Lesevorgang muss gemeldet werden: {sorted(ids)}"
    )
    assert r.size == 4096, "die analysierte Größe stammt aus den gelesenen Bytes"
    assert r.risk_level != RiskLevel.GREEN, f"score={r.score}"


def test_grown_file_between_stat_and_read_is_reported(dispatcher, tmp_path, monkeypatch):
    """Nachbarfall: die Datei ist nach dem Lesen größer als angekündigt.

    Kein kurzer Lesevorgang (es kamen genau ``read_size`` Bytes), aber der
    zweite Blick nach dem Lesen zeigt eine andere (size, mtime_ns): alles, was
    nach der Größenabfrage angehängt wurde, wurde NIE analysiert — vorher ohne
    jede Spur (0 Indikatoren, GRÜN).
    """
    from pathlib import Path

    target = tmp_path / "waechst.bin"
    target.write_bytes(b"harmlos" + b"X" * 900_000)

    real_stat = Path.stat
    state = {"stale_used": False}

    def fake_stat(self, *args, **kwargs):
        if self == target and not state["stale_used"]:
            state["stale_used"] = True
            return os.stat_result(
                (*tuple(real_stat(target))[:6], 4096, *tuple(real_stat(target))[7:])
            )
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", fake_stat)
    r = dispatcher.scan_path(target)

    ids = {i.rule_id for i in r.indicators}
    assert "CORE_FILE_CHANGED" in ids, (
        f"die Änderung während des Scans muss gemeldet werden: {sorted(ids)}"
    )
    assert "CORE_READ_TRUNCATED" not in ids, (
        "keine Lesekappung im Spiel — der Fall ist eine Dateiänderung"
    )
    assert r.risk_level != RiskLevel.GREEN, f"score={r.score}"


def test_drain_bounds_the_materialized_payload(dispatcher):
    """Der Nachlauf darf den Iterator nicht unbegrenzt leermachen.

    Die Abschlussnotizen der Container-Iteratoren kommen als LETZTES yield,
    also muss der Nachlauf bis ans Ende ziehen — und jedes ``next()``
    materialisiert ein Mitglied. Ohne Grenze holt er bei einem Archiv mit
    10 000 fetten Mitgliedern den ganzen Inhalt in den Speicher, genau das,
    wogegen das Mitgliederlimit existiert.
    """

    def counting(n: int, size: int):
        state = {"pulled": 0, "bytes": 0}

        def gen():
            for i in range(n):
                state["pulled"] += 1
                state["bytes"] += size
                yield (f"f{i}.txt", b"x" * size, None)
            state["pulled"] += 1
            yield ("", None, "Zip-Slip-Versuch (1 Eintraege)")

        return gen(), state

    # Fette Mitglieder: der Nachlauf bricht an der Volumengrenze ab.
    it, state = counting(10_000, 200_000)  # 2 GB virtuell
    children: list = []
    dispatcher._drain_container_notes(
        it, children, "(T)", 1, "ARCH_TEST_ERROR", "T"
    )
    # The default budget is 8 MiB. A payload is materialised BEFORE its size
    # can be charged, and the ``for`` pulls the next member before the budget
    # guard sees the negative balance: at most TWO members may cross the line.
    # The old assertion allowed the whole doubled budget (TEST-010).
    max_members = 8 * 1024 * 1024 // 200_000 + 2
    assert state["bytes"] <= max_members * 200_000, (
        f"Nachlauf hat {state['bytes']} Bytes materialisiert"
    )
    assert state["pulled"] <= max_members, "der Nachlauf zieht das Archiv leer"

    # Billige Mitglieder: die Notiz am Ende kommt trotzdem an.
    it2, _ = counting(5_000, 1)
    children2: list = []
    dispatcher._drain_container_notes(
        it2, children2, "(T)", 1, "ARCH_TEST_ERROR", "T"
    )
    assert children2, "die Abschlussnotiz darf nicht verloren gehen"


def _tar_with_fat_members(n: int, size: int, *, traversal_at: int = -1) -> bytes:
    """TAR mit ``n`` fetten Mitgliedern und einem Traversal-Namen an ``traversal_at``.

    Dieselbe Traversal-Name-Lage wie ``_tar_with_traversal``, nur mit
    Mitgliedern, deren Nutzlast das 8-MiB-Budget des Nachlaufs sprengt. Die
    Position ist ein Parameter, weil davon abhängt, ob der Eintrag noch im
    gelaufenen Teil des Walks liegt — genau daran hing der Runde-4-Restbefund.
    ``-1`` heißt: gar kein Traversal-Eintrag (die Gegenprobe).
    """
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        blob = b"x" * size
        for i in range(n):
            if i == traversal_at:
                ti = tarfile.TarInfo("../evil0.txt")
                ti.size = 4
                tf.addfile(ti, io.BytesIO(b"evil"))
                continue
            t = tarfile.TarInfo(f"f{i}.txt")
            t.size = size
            tf.addfile(t, io.BytesIO(blob))
    return buf.getvalue()


def test_zipslip_reaches_the_verdict_with_fat_members(dispatcher, monkeypatch):
    """Befund #1: die Zip-Slip-Meldung darf nicht an der Mitgliedsgröße hängen.

    Gemessen: 300 Mitglieder a 100 KB (29,5 MiB) ROT 75 mit ARCH_ZIPSLIP gegen
    260 Mitglieder a 1 MiB (260,1 MiB) GELB 25 nur mit ARCH_MEMBER_SKIP —
    identische Traversal-Namen, nur die Mitgliedsgröße geändert. Ursache war
    die Notiz am Generator-Ende (``iter_compressed_members``) hinter dem
    Byte-Budget des Nachlaufs. Der Iterator meldet sie seit FixArchive4 sofort
    beim ersten unsicheren Namen (``core/sevenzip.py:253-267`` als Vorbild);
    dieser Test ist der Ende-zu-Ende-Beleg dafür und läuft erst nach dieser
    Änderung grün.
    """
    monkeypatch.setattr("malaz.config.MAX_RECURSIVE_MEMBERS", 20)
    # 130 Mitglieder a 100 KB = 13 MiB; die Restnutzlast hinter dem Limit
    # (~11 MiB) ist größer als das 8-MiB-Budget des Nachlaufs.
    r = _scan(
        dispatcher,
        _tar_with_fat_members(130, 100_000, traversal_at=0),
        ".tar",
    )

    ids = {i.rule_id for i in r.all_indicators()}
    assert "ARCH_ZIPSLIP" in ids, f"die Traversal-Meldung fehlt: {sorted(ids)}"
    assert r.risk_level == RiskLevel.RED, f"score={r.score} {_weights(r)}"


def test_fat_members_do_not_turn_a_benign_tar_red(dispatcher, monkeypatch):
    """Die Gegenprobe zum Nachlauf: nur EINE gewichtete Aussage je Ursache.

    Der Nachlauf meldet den Verlust der Abschlussnotiz jetzt ausdrücklich —
    darf aber nicht zusätzlich gewichtet werden: die Ursache (Mitgliederlimit)
    trägt bereits ARCH_MEMBER_SKIP mit 25. 25 + 25 = 50 = ROT für ein Archiv
    ohne jedes Inhaltssignal wäre genau die Doppelzählung, die in Runde 3
    einen 101-MiB-TAR aus Nullbytes ROT 55 ergeben hat.
    """
    monkeypatch.setattr("malaz.config.MAX_RECURSIVE_MEMBERS", 20)
    r = _scan(
        dispatcher,
        _tar_with_fat_members(130, 100_000, traversal_at=-1),
        ".tar",
    )

    weights = _weights(r)
    assert weights.get("ARCH_MEMBER_SKIP") == 25, weights
    assert r.risk_level == RiskLevel.YELLOW, f"score={r.score} {weights}"


def test_drain_reports_unread_summary_instead_of_silence(dispatcher):
    """Befund #1, Nachlauf-Seite: der Verlust der Notiz muss sichtbar sein.

    Hinter fetten Mitgliedern ist die Abschlussnotiz für den Nachlauf
    unerreichbar: sie zu holen hieße, jedes Restmitglied zu materialisieren
    (genau das verbietet die 8-MiB-Grenze und der Test
    ``test_drain_bounds_the_materialized_payload``). Dann darf der Verlust
    nicht stillschweigend passieren — eine Stufe, die Inhalt nicht auswertet,
    muss scorewirksam werden ODER ausdrücklich als ungeprüft erscheinen.
    """
    def fat_then_note(n: int, size: int):
        for i in range(n):
            yield (f"f{i}.txt", b"x" * size, None)
        yield ("", b"", "Zip-Slip-Versuch (1 Eintraege)")

    children: list = []
    dispatcher._drain_container_notes(
        fat_then_note(200, 100_000), children, "(T)", 1,
        "ARCH_TEST_ERROR", "T",
    )

    indicators = [i for c in children for i in c.indicators]
    ids = {i.rule_id for i in indicators}
    assert "ARCH_ZIPSLIP" not in ids, "das Budget darf den Iterator nicht leerziehen"
    unread = [i for i in indicators if i.rule_id == "ARCH_NOTE_UNREAD"]
    assert unread, (
        f"eine unerreichbare Abschlussnotiz darf nicht stillschweigend "
        f"verfallen: {sorted(ids)}"
    )
    # Gewicht 0: die Ursache wird an der Aufrufstelle als ARCH_MEMBER_SKIP
    # gewichtet, ein zweites Gewicht wäre eine Doppelzählung derselben Ursache.
    assert unread[0].weight == 0, unread[0].weight


def test_container_and_member_failures_use_distinct_rule_ids(dispatcher, monkeypatch):
    """Befund #4: eine ID, eine Bedeutung.

    ``ARCH_MEMBER_STOP`` wurde an drei Stellen mit zwei Bedeutungen benutzt:
    geworfene Container-Rekursion, geworfenes Mitglied und Bombenschutz-Stopp.
    Jede regel-ID-basierte Auswertung (Bericht, Korpusvergleich, Golden
    Snapshot) machte daraus eine ununterscheidbare Menge. Jetzt: Container ->
    ARCH_CONTAINER_ERROR, Mitglied -> ARCH_MEMBER_ERROR, und ARCH_MEMBER_STOP
    bleibt allein dem Bombenschutz-Stopp.
    """
    from malaz import config

    # (a) die Container-Rekursion selbst wirft.
    def boom(*_a, **_k):
        raise OSError("simulierter Ausfall beim Entpacken")

    monkeypatch.setattr(dispatcher, "_scan_compressed_members", boom)
    container = _scan(dispatcher, _tar_with_fat_members(2, 16, traversal_at=-1), ".tar")
    container_ids = {i.rule_id for i in container.all_indicators()}
    assert "ARCH_CONTAINER_ERROR" in container_ids, sorted(container_ids)
    assert "ARCH_MEMBER_STOP" not in container_ids, sorted(container_ids)

    monkeypatch.undo()
    # (b) ein Mitglied selbst wirft.
    real_scan = dispatcher._scan

    def faulty(data, path, depth, **kwargs):
        if depth > 0:
            raise OSError("simulierter Ausfall beim Mitglied")
        return real_scan(data, path, depth, **kwargs)

    monkeypatch.setattr(dispatcher, "_scan", faulty)
    member = _scan(dispatcher, _tar_with_fat_members(2, 16, traversal_at=-1), ".tar")
    member_ids = {i.rule_id for i in member.all_indicators()}
    assert "ARCH_MEMBER_ERROR" in member_ids, sorted(member_ids)
    assert "ARCH_MEMBER_STOP" not in member_ids, sorted(member_ids)

    monkeypatch.undo()
    # (c) der Bombenschutz-Stopp (Eintrags-Limit) behält ARCH_MEMBER_STOP.
    monkeypatch.setattr(config, "MAX_ARCHIVE_ENTRIES", 5)
    bomb = _scan(dispatcher, _tar_with_fat_members(20, 16, traversal_at=-1), ".tar")
    bomb_ids = {i.rule_id for i in bomb.all_indicators()}
    assert "ARCH_MEMBER_STOP" in bomb_ids, sorted(bomb_ids)
    assert not {"ARCH_CONTAINER_ERROR", "ARCH_MEMBER_ERROR"} & bomb_ids, sorted(bomb_ids)


# --- Fixrunde 3: jede Stufe, die Inhalt nicht auswertet, muss scorewirksam sein


def _weights(result) -> dict[str, int]:
    out: dict[str, int] = {}
    for ind in result.all_indicators():
        out[ind.rule_id] = max(out.get(ind.rule_id, 0), ind.weight or 0)
    return out


def _patch_zip_field(
    data: bytearray, sig: bytes, name: bytes, *, len_off: int, name_off: int,
    field_off: int, value: int | None = None, set_bit: int | None = None,
) -> None:
    """Set one 16-bit field of the ZIP entries called ``name``.

    ``len_off``/``name_off`` locate the name inside the record (they differ
    between Local File Header and Central Directory), ``field_off`` the field
    that is written.
    """
    import struct

    idx = data.find(sig)
    while idx != -1:
        nlen = struct.unpack_from("<H", data, idx + len_off)[0]
        if bytes(data[idx + name_off : idx + name_off + nlen]) == name:
            if value is not None:
                struct.pack_into("<H", data, idx + field_off, value)
            else:
                assert set_bit is not None
                old = struct.unpack_from("<H", data, idx + field_off)[0]
                struct.pack_into("<H", data, idx + field_off, old | set_bit)
        idx = data.find(sig, idx + 4)


def _zip_with_unreadable_member(*, method: int | None = None) -> bytes:
    """ZIP, dessen Nutzlast-Mitglied der Entpacker nicht liefern kann.

    ``method=98`` (unbekanntes Verfahren, im Central Directory gesetzt) lässt
    ``zipfile.read`` scheitern; ohne ``method`` wird dasselbe über das
    Encrypted-Bit erreicht. Beide Male liefert ``iter_zip_members``
    ``(name, b"", error)`` — der Inhalt des Mitglieds wird nie analysiert.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("payload.ps1", b"$c = New-Object Net.WebClient\n")
        zf.writestr("readme.txt", b"harmlos")
    data = bytearray(buf.getvalue())
    if method is not None:
        _patch_zip_field(
            data, b"PK\x01\x02", b"payload.ps1",
            len_off=28, name_off=46, field_off=10, value=method,
        )
    else:
        # Encrypted-Bit (General Purpose Flags) in beiden Kopien des Eintrags.
        _patch_zip_field(
            data, b"PK\x03\x04", b"payload.ps1",
            len_off=26, name_off=30, field_off=6, set_bit=0x1,
        )
        _patch_zip_field(
            data, b"PK\x01\x02", b"payload.ps1",
            len_off=28, name_off=46, field_off=8, set_bit=0x1,
        )
    return bytes(data)


def _nested_zip(levels: int, payload: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("inner.txt", payload)
    data = buf.getvalue()
    for _ in range(levels - 1):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("layer.zip", data)
        data = buf.getvalue()
    return data


def _tar_with_one_member(size: int) -> bytes:
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo("blob.bin")
        info.size = size
        tf.addfile(info, io.BytesIO(b"\x00" * size))
    return buf.getvalue()


@pytest.mark.parametrize("method", [None, 98])
def test_unreadable_member_is_not_green(dispatcher, monkeypatch, method):
    """Fixrunde 3: ein nicht entpackbares Mitglied kostete nur 5 Punkte.

    ``_scan_children`` hat drei Zweige für dieselbe Aussage „dieses Mitglied
    wurde nicht ausgewertet"; zwei davon (ARCH_MEMBER_SKIP/ARCH_MEMBER_STOP)
    tragen seit Runde 2 Gewicht 25, der dritte (``if error:``) behielt 5 — unter
    SCORE_GREEN_MAX (19). Gemessen: dasselbe ZIP GRÜN 5 (Verfahren 98) bzw.
    GRÜN 10 (verschlüsselt markiert), während die Nutzlast unangetastet in der
    Datei steht.
    """
    from pathlib import Path

    from malaz import config

    # Keine Passwortliste des Nutzers: das Mitglied ist in beiden Varianten
    # unlesbar, unabhängig davon, was lokal konfiguriert ist.
    monkeypatch.setattr(
        config,
        "PASSWORD_FILE",
        Path(tempfile.gettempdir()) / "malaz_fixrunde3_no_passwords.txt",
    )
    r = _scan(dispatcher, _zip_with_unreadable_member(method=method), ".zip")

    assert r.risk_level != RiskLevel.GREEN, f"score={r.score}"
    assert _weights(r).get("ARCH_MEMBER_ERROR", 0) >= 20


def test_depth_limit_is_not_green(dispatcher):
    """Fixrunde 3: das Tiefenlimit kostete 5 Punkte — unter der GRÜN-Schwelle.

    Unterhalb von MAX_ARCHIVE_DEPTH wird nichts mehr entpackt, also nichts mehr
    analysiert. Gemessen: sechsfach verschachteltes ZIP mit PowerShell-Nutzlast
    GRÜN 5, zweifach verschachtelt (Kontrolle) ROT 50.
    """
    r = _scan(dispatcher, _nested_zip(6, b"$c = New-Object Net.WebClient\n"), ".zip")

    assert r.risk_level != RiskLevel.GREEN, f"score={r.score}"
    assert _weights(r).get("ARCH_DEPTH_LIMIT", 0) >= 20


def test_disabled_sevenzip_stage_is_not_green(dispatcher, monkeypatch):
    """Fixrunde 3: abgeschaltete 7z-Stufe meldete GRÜN 0 mit Freigabe-Empfehlung.

    ARCH_7Z_DISABLED trug INFO/0, während der Geschwisterzweig ARCH_7Z_MISSING
    für dieselbe Aussage („Inhalt nicht analysiert") MEDIUM/20 trägt. Ein
    RAR/7z-Container darf im Bericht nicht als unauffällig erscheinen.
    """
    from malaz import config

    monkeypatch.setattr(config, "SEVENZIP_ENABLED", False)
    r = _scan(dispatcher, b"7z\xbc\xaf\x27\x1c" + b"\xff" * 32, ".7z")

    assert r.risk_level != RiskLevel.GREEN, f"score={r.score}"
    assert _weights(r).get("ARCH_7Z_DISABLED", 0) >= 20


def test_failing_pipeline_stage_is_not_green(dispatcher, monkeypatch):
    """Fixrunde 3: ein ausgefallener Pipeline-Lauf kostete 0 Punkte.

    Derselbe Fall wie CORE_ERROR (Runde 2, 5 -> 25): die Stufe hat nichts
    analysiert, ihr Ergebnis ist unbekannt. Gemessen: ROT 60 -> GRÜN 0, sobald
    die PDF-Stufe warf.
    """

    class Boom:
        name = "generic"

        def analyze(self, ctx):
            raise RuntimeError("simulierter Pipeline-Ausfall")

    monkeypatch.setattr(dispatcher, "generic", Boom())
    r = _scan(dispatcher, b"harmloser text ohne signale", ".txt")

    assert r.risk_level != RiskLevel.GREEN, f"score={r.score}"
    assert _weights(r).get("GENERIC_ERROR", 0) >= 20


def test_read_cap_consequence_is_not_counted_twice(dispatcher, monkeypatch):
    """Fixrunde 3: CORE_READ_TRUNCATED zählte die Kappung ein zweites Mal.

    Die Kappung (Gewicht 25) und die Container-Folgenotiz derselben Ursache
    (ARCH_TAR_ERROR/ARCH_ZIP_ERROR/MAIL_CONTAINER_WARN, je 25) addierten sich zu
    50 = ANCHOR_CRITICAL_SCORE: eine Datei ohne jedes Inhaltssignal wurde ROT,
    allein weil ihre Struktur am Dateiende liegt (gemessen: 101-MiB-TAR aus
    Nullbytes ROT 55; dieselben Bytes mit angehobener Lesegrenze GRÜN 5).
    Die Kappung muss sichtbar bleiben, aber sie darf nur EINMAL zählen.
    """
    from malaz import config

    monkeypatch.setattr(config, "MAX_READ_SIZE", 4096)
    monkeypatch.setattr(config, "MAX_FILE_SIZE", 65536)
    # TAR-Header + 6000 Byte Mitglied: der abgeschnittene Präfix endet mitten
    # im Mitglied, die Container-Stufe scheitert an genau dieser Kappung.
    r = _scan(dispatcher, _tar_with_one_member(6000), ".tar")

    assert "CORE_READ_TRUNCATED" in {i.rule_id for i in r.indicators}
    assert r.risk_level == RiskLevel.YELLOW, f"score={r.score} {_weights(r)}"
    # Die Folge bleibt sichtbar (der Nutzer erfährt, warum nichts kam) ...
    assert "ARCH_TAR_ERROR" in _weights(r)
    # ... trägt die Bewertung aber nicht ein zweites Mal.
    notes = [
        i
        for res in r.children
        for i in res.indicators
        if i.rule_id == "ARCH_TAR_ERROR"
    ]
    assert notes and notes[0].weight == 0, [i.weight for i in notes]


def test_traversal_beyond_every_limit_is_still_reported(dispatcher, monkeypatch):
    """Der Traversal-Eintrag darf nicht von Position oder Mitgliedsgröße abhängen.

    Runde 4 hatte die Meldung an den ersten unsicheren Namen *im Walk* gelegt.
    Das verschob die Grenze nur: der Dispatcher kappt bei
    `MAX_RECURSIVE_MEMBERS` und lässt den Generator fallen, der Nachlauf zieht
    auf einem 8-MiB-Budget und fette Mitglieder erschöpfen es, lange bevor der
    Eintrag erreicht ist. Gemessen damals (Cap 20, 300 Mitglieder à 200 KB):
    Traversal an Position 10 -> ROT 75 MIT `ARCH_ZIPSLIP`, an Position 120 und
    295 -> GELB 25 OHNE — zahlenidentisch mit demselben Archiv GANZ OHNE
    Traversal-Eintrag. Der Angriffsversuch verschwand also vollständig.

    Seit dem Metadaten-Vorlauf in `iter_compressed_members` stammt die Meldung
    aus den **deklarierten Namen** und hängt an keinem Limit mehr.
    """
    monkeypatch.setattr("malaz.config.MAX_RECURSIVE_MEMBERS", 20)

    def archive(traversal_at: int) -> bytes:
        return _tar_with_fat_members(300, 200_000, traversal_at=traversal_at)

    last = _scan(dispatcher, archive(295), ".tar")
    last_ids = {i.rule_id for i in last.all_indicators()}
    assert "ARCH_ZIPSLIP" in last_ids, (
        f"Traversal hinter Cap und Nachlauf-Budget verschwand: {sorted(last_ids)}"
    )
    assert last.risk_level == RiskLevel.RED, f"score={last.score}"

    # Die Gegenprobe, die den Befund ausgemacht hat: dieselben Bytes OHNE
    # Traversal-Eintrag müssen sich UNTERSCHEIDEN lassen. Waren beide Zahlen
    # gleich, war der Eintrag wirkungslos.
    without = _scan(dispatcher, archive(-1), ".tar")
    assert without.score != last.score, (
        "mit und ohne Traversal-Eintrag ergeben denselben Score "
        f"({last.score}) — der Eintrag ist wirkungslos"
    )


def test_detected_container_type_survives_an_appended_zip():
    """SEC-001-Nachbeben: eine CFB/OLE mit ZIP-Anhang wurde ``zip``.

    Der SEC-001-Fix (``_prefixed_zip_type``) hob JEDE Datei mit lesbarem ZIP
    auf "zip" — auch eine Outlook-.msg. ``zipfile`` akzeptiert beliebige
    Praefixe und oeffnete die CFB, also galt die Datei als Archiv: ``is_msg``
    lief nie, ``mail_preview``/``mail_security`` blieben leer und der
    ZIP-Anhang wurde nicht als Kind gescannt (gemessen: detected_type "zip",
    children [], obwohl ``magic.detect`` "ole" sagte). Ein erkannter
    Container mit eigenem Analyse-Zweig behaelt seinen Typ; die
    SEC-001-Praefixfaelle bleiben scharf.
    """
    import io
    import zipfile

    from malaz.core import magic
    from malaz.core.dispatcher import _prefixed_zip_type

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("anhang.txt", b"x")
    archive = buf.getvalue()

    cfb = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 504
    data = cfb + archive
    assert magic.detect(data).type == "ole"
    assert _prefixed_zip_type(magic.detect(data), data, None).type == "ole"

    for prefix in (b"X", b"MZ" + b"\x00" * 62):
        prefixed = prefix + archive
        assert magic.detect(prefixed).type in ("unknown", "pe")
        assert _prefixed_zip_type(magic.detect(prefixed), prefixed, None).type == "zip"
