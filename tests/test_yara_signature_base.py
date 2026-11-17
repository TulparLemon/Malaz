"""signature-base als zweite YARA-Regelquelle: Feed-Laden + Beschaffung.

Die Quelle liegt bewusst in ``rules/yara/signature_base`` und nicht in
``rules/yara/external`` — letzteres raeumt ``core.yara_update`` bei jedem
ReversingLabs-Update leer (``rglob`` auf ``*.yar``/``*.yara``/``*.yarc``).
Der Test ``test_feed_updates_never_touch_each_other`` haelt das fest.
"""

import io
import os
import subprocess
import zipfile
from pathlib import Path
from unittest import mock

import pytest

from malaz import config
from malaz.core import yara_signature_base
from malaz.core.yara_engine import YaraEngine

pytest.importorskip("yara")

_RULE_SB = b"""
rule SignatureBase_Test_Rule {
    meta:
        author = "Test Autor (DOES-NOT-EXIST)"
        description = "signature-base probe"
    strings: $a = "SIGBASEMARKERAAA" ascii
    condition: $a
}
"""
_RULE_SB_B = b"""
rule SignatureBase_Test_Rule_B {
    strings: $a = "SIGBASEMARKERBBB" ascii
    condition: $a
}
"""
_RULE_EXT = b"""
rule External_Test_Rule_A {
    strings: $a = "EXTTESTAAAAMARKER" ascii
    condition: $a
}
"""
# Regel mit externen Variablen: Malaz setzt keine -> darf nie installiert werden.
_RULE_EXT_VAR = b"""
rule SignatureBase_ExternVar_Probe {
    strings: $a = "SIGBASEEXTVAR" ascii
    condition: $a and filepath contains "x"
}
"""

# Bundles sind identifizierbar: eine neue Version muss die alte ersetzen.
_MARKER_NAMESPACE = "probe.yar"


def _fake_zip_bytes(
    members: dict[str, bytes], compression: int = zipfile.ZIP_STORED
) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as bundle:
        for name, content in members.items():
            bundle.writestr(name, content)
        bundle.writestr("signature-base-master/LICENSE", b"DRL 1.1 text\n")
    return buf.getvalue()


def _feed_zip(rules: dict[str, bytes]) -> bytes:
    """Archive in the real layout: ``<repo-branch>/yara/<name>``."""
    members = {f"signature-base-master/yara/{name}": content
               for name, content in rules.items()}
    members["signature-base-master/yara/external-variable-rules.txt"] = (
        b"# rules needing external variables\n"
        b"gen_externvar.yar\n"
    )
    members["signature-base-master/iocs/ignore-me.txt"] = b"kein Regelwerk"
    members["signature-base-master/vendor/yara/fremd.yar"] = _RULE_SB_B
    return _fake_zip_bytes(members)


def _make_junction(link: Path, target: Path) -> bool:
    """Create a directory junction (Windows) — False if unsupported."""
    if os.name != "nt":
        return False
    target.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)],
        capture_output=True,
        check=False,
    )
    return result.returncode == 0 and link.is_dir()


def _patch_download(monkeypatch, payload: bytes, module=yara_signature_base):
    captured = {}

    class _Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def geturl(self):
            return config.YARA_SIGNATURE_BASE_URL

    def fake_urlopen(request, timeout=0):
        captured["url"] = request.full_url
        return _Resp(payload)

    monkeypatch.setattr(module, "urlopen", fake_urlopen)
    return captured


@pytest.fixture()
def rules_dirs(tmp_path, monkeypatch):
    main = tmp_path / "yara"
    (main / "external").mkdir(parents=True)
    (main / "signature_base").mkdir(parents=True)
    monkeypatch.setattr(config, "YARA_RULES_DIR", main)
    monkeypatch.setattr(config, "YARA_EXTERNAL_DIR", main / "external")
    monkeypatch.setattr(config, "YARA_SIGNATURE_BASE_DIR", main / "signature_base")
    monkeypatch.setattr(config, "YARA_EXTERNAL_DISABLED", main / "external_disabled.txt")
    return main


# -- Engine: zweite Quelle ---------------------------------------------------- #

def test_config_feed_names_match_feed_dirs():
    """YARA_FEED_DIRS ist die eine Quelle der Lade-Reihenfolge."""
    assert config.YARA_EXTERNAL_DIR.name in config.YARA_FEED_DIRS
    assert config.YARA_SIGNATURE_BASE_DIR.name in config.YARA_FEED_DIRS
    assert len(set(config.YARA_FEED_DIRS)) == len(config.YARA_FEED_DIRS)


def test_engine_loads_signature_base_sources(rules_dirs):
    (rules_dirs / "signature_base" / "probe.yar").write_bytes(_RULE_SB)
    engine = YaraEngine(rules_dir=rules_dirs)
    assert engine.available and engine.load_error is None
    assert [m.rule for m in engine.scan(b"xx SIGBASEMARKERAAA yy")] == [
        "SignatureBase_Test_Rule"
    ]


def test_engine_loads_signature_base_bundle(rules_dirs):
    import yara

    yara.compile(
        sources={_MARKER_NAMESPACE: _RULE_SB.decode()}
    ).save(str(rules_dirs / "signature_base" / "bundle.yarc"))
    engine = YaraEngine(rules_dir=rules_dirs)
    assert engine.load_error is None
    assert [m.rule for m in engine.scan(b"SIGBASEMARKERAAA")] == [
        "SignatureBase_Test_Rule"
    ]


def test_bundle_shadows_stray_sources(rules_dirs):
    """Bundle + Quell-Datei duerfen nicht doppelt matchen."""
    import yara

    yara.compile(sources={"probe.yar": _RULE_SB.decode()}).save(
        str(rules_dirs / "signature_base" / "bundle.yarc")
    )
    (rules_dirs / "signature_base" / "stray.yar").write_bytes(_RULE_SB)
    hits = YaraEngine(rules_dir=rules_dirs).scan(b"SIGBASEMARKERAAA")
    assert [m.rule for m in hits] == ["SignatureBase_Test_Rule"]


def test_both_feeds_load_into_one_engine(rules_dirs):
    (rules_dirs / "external" / "feed.yar").write_bytes(_RULE_EXT)
    (rules_dirs / "signature_base" / "probe.yar").write_bytes(_RULE_SB)
    engine = YaraEngine(rules_dir=rules_dirs)
    assert engine.load_error is None
    hits = {m.rule for m in engine.scan(b"EXTTESTAAAAMARKER SIGBASEMARKERAAA")}
    assert hits == {"External_Test_Rule_A", "SignatureBase_Test_Rule"}


def test_disabled_list_suppresses_signature_base_rule(rules_dirs):
    (rules_dirs / "signature_base" / "probe.yar").write_bytes(_RULE_SB)
    (rules_dirs / "external_disabled.txt").write_text(
        "SignatureBase_Test_Rule\n", encoding="utf-8"
    )
    engine = YaraEngine(rules_dir=rules_dirs)
    assert engine.scan(b"SIGBASEMARKERAAA") == []


def test_missing_feed_directory_is_not_an_error(rules_dirs):
    import shutil

    shutil.rmtree(rules_dirs / "signature_base")
    engine = YaraEngine(rules_dir=rules_dirs)
    assert engine.load_error is None
    assert engine.scan(b"SIGBASEMARKERAAA") == []


# -- Update-Modul ------------------------------------------------------------- #

def test_update_builds_bundle_attribution_and_licence(rules_dirs, monkeypatch):
    payload = _feed_zip({"probe.yar": _RULE_SB, "gen_externvar.yar": _RULE_EXT_VAR})
    captured = _patch_download(monkeypatch, payload)

    lines = []
    result = yara_signature_base.update_signature_base_rules(line_callback=lines.append)

    assert result.ok
    assert result.installed == 1  # gen_externvar.yar wurde gefiltert
    assert result.excluded == 1
    assert result.skipped == 0
    assert result.rules >= 1
    assert captured["url"] == config.YARA_SIGNATURE_BASE_URL
    feed = rules_dirs / "signature_base"
    assert (feed / "bundle.yarc").is_file()
    assert list(feed.rglob("*.yar")) == []  # nichts bleibt als Quelle liegen
    assert (feed / "LICENSE-DRL-1.1.txt").read_text(encoding="utf-8").startswith("DRL")
    note = (feed / "README-signature-base.txt").read_text(encoding="utf-8")
    assert "Neo23x0/signature-base" in note and "DRL 1.1" in note
    engine = YaraEngine(rules_dir=rules_dirs)
    assert engine.load_error is None
    assert [m.rule for m in engine.scan(b"SIGBASEMARKERAAA")] == [
        "SignatureBase_Test_Rule"
    ]
    # Externe Variablen: die Regel darf nirgends im Feed landen.
    assert engine.scan(b"SIGBASEEXTVAR") == []


def test_update_ignores_vendor_and_non_yara_members(rules_dirs, monkeypatch):
    """Nur yara/<datei>.yar zaehlt — vendor/, iocs/, .exe kommen nie an."""
    members = {
        "signature-base-master/yara/probe.yar": _RULE_SB,
        "signature-base-master/vendor/yara/fremd.yar": _RULE_SB_B,
        "signature-base-master/iocs/iocs.csv": b"1,2,3",
        "signature-base-master/yara/../evil.exe": b"MZ...",
        "../evil.exe": b"MZ...",
        "signature-base-master/yara/tool.ps1": b"powershell",
    }
    _patch_download(monkeypatch, _fake_zip_bytes(members))

    result = yara_signature_base.update_signature_base_rules()

    assert result.ok and result.installed == 1
    feed = rules_dirs / "signature_base"
    assert list(feed.rglob("*.exe")) == []
    assert list(feed.rglob("*.ps1")) == []
    assert list(feed.rglob("*.csv")) == []
    assert not (rules_dirs.parent / "evil.exe").exists()
    engine = YaraEngine(rules_dir=rules_dirs)
    assert [m.rule for m in engine.scan(b"SIGBASEMARKERBBB")] == []  # vendor-Regel


def test_update_without_yara_python_writes_sources(rules_dirs, monkeypatch):
    """Ohne yara-python liegen die .yar-Quellen da; die Engine kompiliert sie."""
    monkeypatch.setattr(yara_signature_base, "_HAVE_YARA", False)
    _patch_download(
        monkeypatch,
        _feed_zip({"probe.yar": _RULE_SB, "gen_externvar.yar": _RULE_EXT_VAR}),
    )

    result = yara_signature_base.update_signature_base_rules()

    assert result.ok and result.installed == 1 and result.rules == 0
    feed = rules_dirs / "signature_base"
    assert (feed / "probe.yar").is_file()
    assert not (feed / "gen_externvar.yar").exists()  # externe Variablen gefiltert
    assert (feed / "README-signature-base.txt").is_file()
    engine = YaraEngine(rules_dir=rules_dirs)
    assert engine.load_error is None
    assert [m.rule for m in engine.scan(b"SIGBASEMARKERAAA")] == [
        "SignatureBase_Test_Rule"
    ]


def test_update_skips_broken_rules_but_keeps_the_rest(rules_dirs, monkeypatch):
    _patch_download(
        monkeypatch,
        _feed_zip({"gut.yar": _RULE_SB, "kaputt.yar": b"rule { invalid syntax"}),
    )

    result = yara_signature_base.update_signature_base_rules()

    assert result.ok and result.installed == 1 and result.skipped == 1
    engine = YaraEngine(rules_dir=rules_dirs)
    assert [m.rule for m in engine.scan(b"SIGBASEMARKERAAA")] == [
        "SignatureBase_Test_Rule"
    ]


def test_update_replaces_old_feed(rules_dirs, monkeypatch):
    (rules_dirs / "signature_base" / "alt.yar").write_bytes(_RULE_SB_B)
    _patch_download(monkeypatch, _feed_zip({"neu.yar": _RULE_SB}))

    result = yara_signature_base.update_signature_base_rules()

    assert result.ok
    assert not (rules_dirs / "signature_base" / "alt.yar").exists()
    assert (rules_dirs / "signature_base" / "bundle.yarc").is_file()


def test_update_never_deletes_behind_a_junction(rules_dirs, tmp_path, monkeypatch):
    """SEC-036: der Cleanup darf einer Junction nicht in einen Fremdordner folgen."""
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "userdocument.yar"
    victim.write_bytes(_RULE_SB_B)
    feed = rules_dirs / "signature_base"
    if not _make_junction(feed / "j", outside):
        pytest.skip("Verzeichnis-Junction auf diesem System nicht moeglich")
    (feed / "alt.yar").write_bytes(_RULE_SB)
    _patch_download(monkeypatch, _feed_zip({"neu.yar": _RULE_SB}))

    result = yara_signature_base.update_signature_base_rules()

    assert result.ok
    assert victim.read_bytes() == _RULE_SB_B
    assert not (feed / "alt.yar").exists()
    assert (feed / "bundle.yarc").is_file()


def test_update_aborts_on_empty_archive_without_wiping(rules_dirs, monkeypatch):
    before = rules_dirs / "signature_base" / "alt.yar"
    before.write_bytes(_RULE_SB)
    _patch_download(
        monkeypatch, _fake_zip_bytes({"signature-base-master/README.md": b"nix"})
    )

    result = yara_signature_base.update_signature_base_rules()

    assert not result.ok
    assert "keine Regel-Dateien" in result.error
    assert before.is_file()


def test_update_rejects_redirect_to_other_host(rules_dirs, monkeypatch):
    class _Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def geturl(self):
            return "https://evil.example/rules.zip"

    monkeypatch.setattr(
        yara_signature_base, "urlopen", lambda req, timeout=0: _Resp(b"x")
    )
    result = yara_signature_base.update_signature_base_rules()
    assert not result.ok
    assert "umgeleitet" in result.error


def test_update_rejects_oversized_download(rules_dirs, monkeypatch):
    big = b"z" * (config.YARA_SIGNATURE_BASE_MAX_ZIP_BYTES + 1)

    class _Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def geturl(self):
            return config.YARA_SIGNATURE_BASE_URL

        def read(self, n=-1):
            return big[:n] if n > 0 else big

    monkeypatch.setattr(yara_signature_base, "urlopen", lambda req, timeout=0: _Resp())
    result = yara_signature_base.update_signature_base_rules()
    assert not result.ok
    assert "Limit" in result.error


def test_update_url_is_allowlisted():
    from malaz.core.yara_signature_base import _validated_url

    assert _validated_url() == config.YARA_SIGNATURE_BASE_URL
    bad = "http://evil.example/x.zip"
    with mock.patch.object(config, "YARA_SIGNATURE_BASE_URL", bad), pytest.raises(
        ValueError
    ):
        _validated_url()


# -- Groessenlimit + Bestandsschutz (Befunde des Security-Audits) ------------ #

def test_oversized_exclusion_list_is_skipped_like_an_oversized_rule(
    rules_dirs, monkeypatch
):
    """Das Groessenlimit gilt fuer JEDES gelesene Mitglied.

    Der ``info.file_size``-Check stand nur im Regel-Zweig: eine uebergrosse
    Regeldatei wurde korrekt verworfen, eine gleich grosse Ausschlussliste
    dagegen vollstaendig gelesen und ausgewertet (gemessen: 4 MiB aus einem
    8 KiB-Archiv). Der Download-Cap begrenzt nur die KOMPRIMIERTE Uebertragung;
    fuer das Dekompressionsvolumen ist diese Pruefung die einzige Schranke —
    ``core.yara_update`` prueft sie deshalb fuer jeden Member.

    Das gemessene Volumen wird am Lesepfad selbst abgegriffen: kein Mitglied
    darf ueber das Limit hinaus entpackt werden.
    """
    limit = config.YARA_SIGNATURE_BASE_MAX_FILE_BYTES
    # Stark komprimierbar: das Archiv bleibt winzig, das Mitglied ist zu gross.
    big = b"gen_externvar.yar\n" * (limit // 18 + 1)
    assert len(big) > limit
    payload = _fake_zip_bytes(
        {
            "signature-base-master/yara/probe.yar": _RULE_SB,
            "signature-base-master/yara/gross.yar": big,
            "signature-base-master/yara/external-variable-rules.txt": big,
        },
        zipfile.ZIP_DEFLATED,
    )
    assert len(payload) < 64 * 1024, len(payload)
    _patch_download(monkeypatch, payload)

    read_sizes: list[int] = []
    real_read = zipfile.ZipExtFile.read

    def spy(self, n=-1):
        data = real_read(self, n)
        read_sizes.append(len(data))
        return data

    monkeypatch.setattr(zipfile.ZipExtFile, "read", spy)

    result = yara_signature_base.update_signature_base_rules()

    # Insgesamt wurden nur die kleinen Mitglieder entpackt — die zwei
    # uebergrossen (gleiche Bytes, gleicher Name-Typ) gar nicht.
    assert sum(read_sizes) < limit, read_sizes
    assert result.ok
    assert result.installed == 1  # nur probe.yar: gross.yar ist zu gross
    assert result.skipped == 0
    # Die uebergrosse Ausschlussliste wurde nicht gelesen: sie darf keine
    # Regelnamen beisteuern (vorher: 1 Name aus dem 2-MiB-Mitglied).
    assert result.excluded == 0
    engine = YaraEngine(rules_dir=rules_dirs)
    assert engine.load_error is None
    assert [m.rule for m in engine.scan(b"SIGBASEMARKERAAA")] == [
        "SignatureBase_Test_Rule"
    ]


def test_failed_swap_keeps_the_previous_feed(rules_dirs, monkeypatch):
    """Scheitert der Rename, muss der vorherige Feed unangetastet bleiben.

    Die unlink-Schleife lief VOR ``os.replace``: ``bundle.yarc`` war bereits
    geloescht, das neue Bundle blieb als ``.bundle.yarc.tmp`` liegen (die Engine
    globt ``*.yarc``/``*.yar``/``*.yara`` — die Datei passt auf keines davon)
    und der Feed war verloren. Ein von einem anderen Prozess gehaltenes
    ``bundle.yarc`` (AV-Scanner) genuegt als Ausloeser.
    """
    feed = rules_dirs / "signature_base"
    (feed / "alt.yar").write_bytes(_RULE_SB_B)
    previous = b"vorheriger-bestand"
    (feed / "bundle.yarc").write_bytes(previous)
    _patch_download(monkeypatch, _feed_zip({"probe.yar": _RULE_SB}))

    def refuse_replace(src, dst):
        raise PermissionError(13, "Datei wird von einem anderen Prozess verwendet")

    monkeypatch.setattr(yara_signature_base.os, "replace", refuse_replace)

    result = yara_signature_base.update_signature_base_rules()

    assert not result.ok
    assert "PermissionError" in result.error
    # Vorheriger Zustand vollstaendig erhalten — nichts geloescht.
    assert (feed / "bundle.yarc").read_bytes() == previous
    assert (feed / "alt.yar").read_bytes() == _RULE_SB_B


# -- Die beiden Feeds duerfen sich nicht gegenseitig loeschen ----------------- #

def test_feed_updates_never_touch_each_other(rules_dirs, monkeypatch):
    """Regression: signature_base lag frueher unter external/ und wurde von
    jedem ReversingLabs-Update (rglob *.yar/*.yara/*.yarc) still geloescht."""
    from malaz.core import yara_update as ext_module

    _patch_download(monkeypatch, _feed_zip({"probe.yar": _RULE_SB}))
    assert yara_signature_base.update_signature_base_rules().ok
    sb_bundle = rules_dirs / "signature_base" / "bundle.yarc"
    assert sb_bundle.is_file()

    # ReversingLabs-Update laeuft direkt danach: darf signature_base nicht anfassen.
    ext_payload = _fake_zip_bytes({"repo-develop/yara/trojan/a.yara": _RULE_EXT})
    _patch_download(monkeypatch, ext_payload, module=ext_module)
    assert ext_module.update_external_rules().ok

    assert sb_bundle.is_file()
    assert (rules_dirs / "signature_base" / "README-signature-base.txt").is_file()
    engine = YaraEngine(rules_dir=rules_dirs)
    assert engine.load_error is None
    hits = {m.rule for m in engine.scan(b"SIGBASEMARKERAAA EXTTESTAAAAMARKER")}
    assert hits == {"SignatureBase_Test_Rule", "External_Test_Rule_A"}

    # ... und umgekehrt: ein zweites signature-base-Update laesst external/ in Ruhe.
    ext_bundle = rules_dirs / "external" / "bundle.yarc"
    _patch_download(monkeypatch, _feed_zip({"probe.yar": _RULE_SB}))
    assert yara_signature_base.update_signature_base_rules().ok
    assert ext_bundle.is_file()


def test_status_reports_installed_feed(rules_dirs, monkeypatch):
    _patch_download(monkeypatch, _feed_zip({"probe.yar": _RULE_SB}))
    assert yara_signature_base.update_signature_base_rules().ok

    text = "\n".join(yara_signature_base.describe_install())

    assert "bundle.yarc" in text
    assert "Regeln:" in text
    assert "README-signature-base.txt" in text

    for name in ("README-signature-base.txt", "LICENSE-DRL-1.1.txt"):
        (rules_dirs / "signature_base" / name).unlink()
    assert "Attribution: fehlt." in "\n".join(
        yara_signature_base.describe_install()
    )


def test_status_without_install(rules_dirs):
    import shutil

    shutil.rmtree(rules_dirs / "signature_base")
    text = "\n".join(yara_signature_base.describe_install())
    assert "nicht installiert" in text


def _spoof_zip_file_sizes_to_zero(raw_zip: bytes, match_substr: bytes = b"") -> bytes:
    """Set GP flag bit 3 (Data Descriptor, _left=None in stdlib) and file_size=0 (SEC-008)."""
    data = bytearray(raw_zip)
    idx = 0
    while True:
        pos = data.find(b"PK\x03\x04", idx)
        if pos == -1:
            break
        fn_len = int.from_bytes(data[pos + 26 : pos + 28], "little")
        ex_len = int.from_bytes(data[pos + 28 : pos + 30], "little")
        fname = bytes(data[pos + 30 : pos + 30 + fn_len])
        if not match_substr or match_substr in fname:
            flags = int.from_bytes(data[pos + 6 : pos + 8], "little") | 0x0008
            data[pos + 6 : pos + 8] = flags.to_bytes(2, "little")
            data[pos + 22 : pos + 26] = b"\x00\x00\x00\x00"
        idx = pos + 30 + fn_len + ex_len
    idx = 0
    while True:
        pos = data.find(b"PK\x01\x02", idx)
        if pos == -1:
            break
        fn_len = int.from_bytes(data[pos + 28 : pos + 30], "little")
        ex_len = int.from_bytes(data[pos + 30 : pos + 32], "little")
        cm_len = int.from_bytes(data[pos + 32 : pos + 34], "little")
        fname = bytes(data[pos + 46 : pos + 46 + fn_len])
        if not match_substr or match_substr in fname:
            flags = int.from_bytes(data[pos + 8 : pos + 10], "little") | 0x0008
            data[pos + 8 : pos + 10] = flags.to_bytes(2, "little")
            data[pos + 24 : pos + 28] = b"\x00\x00\x00\x00"
        idx = pos + 46 + fn_len + ex_len + cm_len
    return bytes(data)

def test_signature_base_cumulative_budget_and_spoofed_header(rules_dirs, monkeypatch):
    """SEC-039 + SEC-008: cumulative decompression cap holds even with file_size == 0."""
    monkeypatch.setattr(config, "YARA_SIGNATURE_BASE_MAX_FILE_BYTES", 1024)
    monkeypatch.setattr(config, "YARA_SIGNATURE_BASE_MAX_TOTAL_BYTES", 2500)

    # 1. Normal cumulative budget overflow -> ValueError
    many = _fake_zip_bytes(
        {f"signature-base-master/yara/r{i}.yar": b"x" * 900 for i in range(4)},
        zipfile.ZIP_DEFLATED,
    )
    with pytest.raises(ValueError, match="Gesamtlimit"):
        yara_signature_base._flat_members(many)

    # 2. Single spoofed file_size==0 member > max_file is bounded-read & skipped,
    #    while valid probe.yar still installs!
    single_spoof = _spoof_zip_file_sizes_to_zero(
        _fake_zip_bytes(
            {
                "signature-base-master/yara/probe.yar": _RULE_SB,
                "signature-base-master/yara/bomb.yar": b"A" * 2000,
            },
            zipfile.ZIP_DEFLATED,
        ),
        b"bomb.yar",
    )
    members = yara_signature_base._flat_members(single_spoof)
    assert list(members) == ["probe.yar"]

    # 3. Repeated spoofed file_size==0 members (> max_file each) CANNOT bypass budget via skips!
    multi_spoof = _spoof_zip_file_sizes_to_zero(
        _fake_zip_bytes(
            {f"signature-base-master/yara/b{i}.yar": b"A" * 1500 for i in range(3)},
            zipfile.ZIP_DEFLATED,
        )
    )
    with pytest.raises(ValueError, match="Gesamtlimit"):
        yara_signature_base._flat_members(multi_spoof)


def test_signature_base_oversized_license_aborts_and_preserves_existing_bundle(
    rules_dirs, monkeypatch
):
    feed = rules_dirs / "signature_base"
    existing_bundle = feed / "bundle.yarc"
    existing_bundle.write_bytes(b"existing-valid-bundle")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("signature-base-master/yara/probe.yar", _RULE_SB)
        zf.writestr(
            "signature-base-master/LICENSE",
            b"L" * (yara_signature_base._MAX_LICENSE_BYTES + 2048),
        )
    spoofed = _spoof_zip_file_sizes_to_zero(buf.getvalue(), b"LICENSE")
    _patch_download(monkeypatch, spoofed)

    result = yara_signature_base.update_signature_base_rules()
    assert not result.ok
    assert "ValueError: LICENSE im Archiv" in result.error
    assert existing_bundle.read_bytes() == b"existing-valid-bundle"
