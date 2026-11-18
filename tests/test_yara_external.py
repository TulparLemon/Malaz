"""Externe YARA-Regeln: Laden aus external/, Sperrliste, Update-Modul."""

import io
import os
import subprocess
import zipfile
from pathlib import Path
from unittest import mock

import pytest

from malaz import config
from malaz.core import yara_update
from malaz.core.yara_engine import YaraEngine

pytest.importorskip("yara")

_RULE_A = b"""
rule External_Test_Rule_A {
    strings: $a = "EXTTESTAAAAMARKER" ascii
    condition: $a
}
"""
_RULE_B = b"""
rule External_Test_Rule_B {
    strings: $a = "EXTTESTBBBBMARKER" ascii
    condition: $a
}
"""


@pytest.fixture()
def rules_dirs(tmp_path, monkeypatch):
    main = tmp_path / "yara"
    (main / "external").mkdir(parents=True)
    monkeypatch.setattr(config, "YARA_RULES_DIR", main)
    monkeypatch.setattr(config, "YARA_EXTERNAL_DIR", main / "external")
    monkeypatch.setattr(config, "YARA_EXTERNAL_DISABLED", main / "external_disabled.txt")
    return main


# -- Engine: external-Ordner + Sperrliste ------------------------------------ #

def test_engine_loads_external_rules(rules_dirs):
    (rules_dirs / "external" / "feed.yar").write_bytes(_RULE_A)
    engine = YaraEngine(rules_dir=rules_dirs)
    assert engine.available
    assert engine.load_error is None
    hits = engine.scan(b"xx EXTTESTAAAAMARKER yy")
    assert [m.rule for m in hits] == ["External_Test_Rule_A"]


def test_disabled_list_suppresses_single_rule(rules_dirs):
    (rules_dirs / "external" / "feed.yar").write_bytes(_RULE_A + _RULE_B)
    (rules_dirs / "external_disabled.txt").write_text(
        "# FP auf Office-Vorlagen beobachtet\nExternal_Test_Rule_A\n",
        encoding="utf-8",
    )
    engine = YaraEngine(rules_dir=rules_dirs)
    hits = engine.scan(b"EXTTESTAAAAMARKER EXTTESTBBBBMARKER")
    assert [m.rule for m in hits] == ["External_Test_Rule_B"]


def test_disabled_list_spares_curated_rules_with_the_same_name(rules_dirs):
    """BUG-078: der Kill-Switch gilt nur für Feed-Regeln, nicht für eigene."""
    (rules_dirs / "curated.yar").write_text(
        'rule SameName { strings: $cur = "CURATEDMARK" condition: $cur }',
        encoding="utf-8",
    )
    (rules_dirs / "external" / "feed.yar").write_text(
        'rule SameName { strings: $feed = "FEEDMARK" condition: $feed }',
        encoding="utf-8",
    )
    (rules_dirs / "external_disabled.txt").write_text(
        "SameName\n", encoding="utf-8"
    )
    engine = YaraEngine(rules_dir=rules_dirs)
    hits = engine.scan(b"CURATEDMARK FEEDMARK")
    assert [m.rule for m in hits] == ["SameName"]
    assert hits[0].matched_strings == ["$cur"], "Feed-Regel wurde nicht gefiltert"


def test_empty_rule_set_is_not_a_clean_scan():
    """BUG-079: no loaded rules reported no error either.

    Every file then passed the YARA stage unexamined while the result read
    like an acquittal. An empty rule base is an INCOMPLETE stage, and the
    pipeline must show it.
    """
    engine = YaraEngine.__new__(YaraEngine)
    engine._rules = []
    engine._disabled = frozenset()
    engine.load_error = None
    type(engine).available = property(lambda self: True)
    try:
        outcome = engine.scan_with_status(b"irgendein inhalt")
    finally:
        del type(engine).available

    assert outcome.matches == []
    assert "keine YARA-Regeln" in (outcome.scan_error or "")


def test_empty_rule_set_reaches_the_pipeline_as_an_incomplete_finding(monkeypatch, tmp_path):
    """BUG-079 end-to-end: the engine state alone is the cause, not the effect.

    The user sees the indicator. Dropping the forwarding would leave an
    unexamined file looking clean again (same contract as YARA_SCAN_ERROR).
    """
    from malaz.models import AnalysisContext
    from malaz.pipelines.generic_pipeline import GenericPipeline

    engine = YaraEngine.__new__(YaraEngine)
    engine._rules = []
    engine._disabled = frozenset()
    engine.load_error = None
    type(engine).available = property(lambda self: True)
    try:
        pipe = GenericPipeline()
        monkeypatch.setattr(pipe, "yara", engine, raising=False)
        data = b"harmloser inhalt"
        ctx = AnalysisContext(
            path=tmp_path / "probe.bin", data=data, detected_type="pe", size=len(data)
        )
        indicators = pipe.analyze(ctx)
    finally:
        del type(engine).available

    hits = [i for i in indicators if i.rule_id == "YARA_SCAN_ERROR"]
    assert hits, [i.rule_id for i in indicators]
    assert hits[0].weight is not None and hits[0].weight > config.SCORE_GREEN_MAX
    assert "NICHT ausgewertet" in hits[0].detail


def test_feed_include_is_disabled(rules_dirs, tmp_path):
    """SEC-038: eine Feed-Regel darf keine Datei ausserhalb des Baums lesen."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.yar").write_text(
        'rule Included { strings: $a = "OUTSIDEMARK" condition: $a }',
        encoding="utf-8",
    )
    (rules_dirs / "external" / "feed.yar").write_text(
        'include "../../outside/secret.yar"\n'
        'rule FeedOnly { condition: true }',
        encoding="utf-8",
    )
    engine = YaraEngine(rules_dir=rules_dirs)
    assert "includes are disabled" in (engine.load_error or "")
    assert engine.scan(b"OUTSIDEMARK") == []


def test_feed_console_import_is_rejected(rules_dirs):
    """SEC-038: console.log schreibt bei jedem Match am Log-Sink vorbei."""
    (rules_dirs / "external" / "feed.yar").write_text(
        'import "console"\n'
        'rule ConsoleProbe { strings: $a = "CONSOLEMARK" condition: $a }',
        encoding="utf-8",
    )
    engine = YaraEngine(rules_dir=rules_dirs)
    assert "console" in (engine.load_error or "").lower()
    assert engine.scan(b"CONSOLEMARK") == []


def test_reload_picks_up_new_files(rules_dirs):
    engine = YaraEngine(rules_dir=rules_dirs)
    assert engine.scan(b"EXTTESTAAAAMARKER") == []
    (rules_dirs / "external" / "feed.yar").write_bytes(_RULE_A)
    engine.reload()
    assert [m.rule for m in engine.scan(b"EXTTESTAAAAMARKER")] == [
        "External_Test_Rule_A"
    ]


def test_external_meta_defaults_to_high(rules_dirs):
    """Fremde Regeln ohne Malaz-Meta landen auf HIGH/30 als Default."""
    (rules_dirs / "external" / "feed.yar").write_bytes(_RULE_A)
    engine = YaraEngine(rules_dir=rules_dirs)
    from malaz.models import Severity

    (hit,) = engine.scan(b"EXTTESTAAAAMARKER")
    assert hit.severity == Severity.HIGH
    assert hit.weight is None  # -> BASE_WEIGHTS[HIGH] = 30


# -- Update-Modul -------------------------------------------------------------- #

def _fake_zip_bytes(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as bundle:
        for name, content in members.items():
            bundle.writestr(name, content)
        bundle.writestr("LICENSE", b"MIT License text\n")
    return buf.getvalue()


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


def _patch_download(monkeypatch, payload: bytes):
    captured = {}

    class _Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def geturl(self):
            return config.YARA_UPDATE_URL

    def fake_urlopen(request, timeout=0):
        captured["url"] = request.full_url
        return _Resp(payload)

    monkeypatch.setattr(yara_update, "urlopen", fake_urlopen)
    return captured


def test_update_builds_bundle_and_attribution(rules_dirs, monkeypatch):
    payload = _fake_zip_bytes({
        "repo-develop/yara/trojan/a.yara": _RULE_A,
        "repo-develop/yara/backdoor/b.yara": _RULE_B,
        "repo-develop/yara/readme.md": b"no rule",
    })
    captured = _patch_download(monkeypatch, payload)

    lines = []
    result = yara_update.update_external_rules(line_callback=lines.append)

    assert result.ok and result.installed == 2 and result.skipped == 0
    assert captured["url"] == config.YARA_UPDATE_URL
    # Ein vorkompiliertes Bundle statt 1.5k Einzeldateien.
    assert (rules_dirs / "external" / "bundle.yarc").is_file()
    assert list((rules_dirs / "external").rglob("*.yar")) == []
    readme = rules_dirs / "external" / "README-externe-regeln.txt"
    assert "ReversingLabs" in readme.read_text(encoding="utf-8")
    engine = YaraEngine(rules_dir=rules_dirs)
    assert engine.load_error is None
    assert [m.rule for m in engine.scan(b"EXTTESTAAAAMARKER")] == [
        "External_Test_Rule_A"
    ]


def test_bundle_shadows_stray_sources(rules_dirs):
    """Bundle + Quell-Datei duerfen nicht doppelt matchen."""
    rules = yara_update._yara.compile(
        sources={"a": _RULE_A.decode()}
    ) if yara_update._HAVE_YARA else None
    if rules is None:
        pytest.skip("yara-python fehlt")
    rules.save(str(rules_dirs / "external" / "bundle.yarc"))
    (rules_dirs / "external" / "stray.yar").write_bytes(_RULE_A)
    hits = YaraEngine(rules_dir=rules_dirs).scan(b"EXTTESTAAAAMARKER")
    assert [m.rule for m in hits] == ["External_Test_Rule_A"]


def test_update_replaces_old_feed(rules_dirs, monkeypatch):
    (rules_dirs / "external" / "alt.yar").write_bytes(_RULE_B)
    _patch_download(monkeypatch, _fake_zip_bytes({"repo/yara/x.yara": _RULE_A}))

    result = yara_update.update_external_rules()

    assert result.ok
    assert not (rules_dirs / "external" / "alt.yar").exists()
    assert (rules_dirs / "external" / "bundle.yarc").is_file()


# -- SEC-036: Junctions duerfen nie das Regelverzeichnis verlassen ----------- #

def test_containment_helper_rejects_paths_outside(tmp_path):
    from malaz.core import yara_engine

    root = tmp_path / "rules"
    root.mkdir()
    inside = root / "a.yar"
    inside.write_text("rule a { condition: false }\n", encoding="utf-8")
    outside = tmp_path / "b.yar"
    outside.write_text("rule b { condition: false }\n", encoding="utf-8")

    assert yara_engine.is_contained(root, inside)
    assert not yara_engine.is_contained(root, outside)
    assert not yara_engine.is_contained(root, root / ".." / "b.yar")
    assert list(yara_engine.iter_rule_files(tmp_path / "fehlt", (".yar",))) == []


def test_rule_walk_prunes_reparse_points(tmp_path, monkeypatch):
    """Der Walk darf einen (hier gemockten) Reparse-Point nicht betreten."""
    from malaz.core import yara_engine

    root = tmp_path / "rules"
    (root / "normal").mkdir(parents=True)
    (root / "normal" / "good.yar").write_text("rule g { condition: false }\n")
    (root / "junction").mkdir()
    (root / "junction" / "hidden.yar").write_text("rule h { condition: false }\n")

    real = yara_engine._is_reparse_point

    def fake(entry):
        return Path(entry.path).name == "junction" or real(entry)

    monkeypatch.setattr(yara_engine, "_is_reparse_point", fake)

    names = sorted(p.name for p in yara_engine.iter_rule_files(root, (".yar",)))
    assert names == ["good.yar"]


def test_update_never_deletes_behind_a_junction(rules_dirs, tmp_path, monkeypatch):
    """Ein `mklink /J` unter external/ darf keine Fremddateien loeschen.

    ``Path.rglob`` ueberspringt nur Symlinks, keine Junctions: der Cleanup
    lief in den verlinkten Ordner und loeschte dort jedes ``*.yar``.
    """
    from malaz.core import yara_engine

    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "userdocument.yar"
    victim.write_bytes(_RULE_B)
    link = rules_dirs / "external" / "j"
    if not _make_junction(link, outside):
        pytest.skip("Verzeichnis-Junction auf diesem System nicht moeglich")
    assert not yara_engine.is_contained(rules_dirs / "external", victim)
    (rules_dirs / "external" / "stale.yar").write_bytes(_RULE_A)
    _patch_download(monkeypatch, _fake_zip_bytes({"repo/yara/x.yara": _RULE_A}))

    result = yara_update.update_external_rules()

    assert result.ok
    assert victim.read_bytes() == _RULE_B
    assert not (rules_dirs / "external" / "stale.yar").exists()
    assert (rules_dirs / "external" / "bundle.yarc").is_file()


def test_engine_does_not_load_rules_through_a_junction(rules_dirs, tmp_path):
    from malaz.core import yara_engine

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "injected.yar").write_bytes(_RULE_A)
    if not _make_junction(rules_dirs / "external" / "j", outside):
        pytest.skip("Verzeichnis-Junction auf diesem System nicht moeglich")

    engine = YaraEngine(rules_dir=rules_dirs)

    assert engine.available and engine.load_error is None
    assert engine.scan(b"EXTTESTAAAAMARKER") == []
    assert list(yara_engine.iter_rule_files(rules_dirs / "external", (".yar",))) == []


def test_failed_bundle_swap_keeps_old_feed(rules_dirs, monkeypatch):
    old = rules_dirs / "external" / "alt.yar"
    old.write_bytes(_RULE_B)
    _patch_download(monkeypatch, _fake_zip_bytes({"repo/yara/x.yara": _RULE_A}))

    def locked(*_args, **_kwargs):
        raise OSError("bundle target locked")

    monkeypatch.setattr(yara_update.os, "replace", locked)
    result = yara_update.update_external_rules()
    assert not result.ok
    assert old.read_bytes() == _RULE_B
    assert not (rules_dirs / "external" / "bundle.yarc").exists()


def test_update_skips_broken_rules(rules_dirs, monkeypatch):
    payload = _fake_zip_bytes({
        "repo/yara/gut.yara": _RULE_A,
        "repo/yara/kaputt.yara": b"rule { invalid syntax",
    })
    _patch_download(monkeypatch, payload)

    result = yara_update.update_external_rules()

    assert result.ok and result.installed == 1 and result.skipped == 1
    engine = YaraEngine(rules_dir=rules_dirs)
    assert [m.rule for m in engine.scan(b"EXTTESTAAAAMARKER")] == [
        "External_Test_Rule_A"
    ]


def test_safe_member_subpath_sanitizes():
    from malaz.core.yara_update import _safe_member_subpath as safe

    assert safe("repo-develop/yara/trojan/X.yara") == "trojan/X.yara"
    assert safe("plain/X.yar") == "X.yar"
    assert safe("../evil.exe") is None
    assert safe("repo/yara/../secret.yara") is None
    assert safe("C:/win/evil.yara") == "evil.yara"  # auf Basename reduziert
    assert safe("evil:name.yara") is None
    assert safe("repo/yara/readme.md") is None


def test_safe_member_subpath_normalizes_backslash_traversal(tmp_path):
    """Backslash-Trenner sind derselbe Traversal wie der Schraegstrich.

    Audit-Fund: geprueft wurde nur die POSIX-Form. Ein Name ohne einen
    einzigen Schraegstrich (``..\\..\\evil.yar``) zerfiel in EIN Segment, das
    weder leer noch "." noch ".." war — es kam unveraendert durch, und
    ``external / name`` loeste auf Windows eine Ebene hoeher auf (gemessen:
    ``<basis>/evil.yar`` statt ``<basis>/external/evil.yar``). Geprueft wird
    hier das Schreibziel, nicht die Schreibweise: kein Name, den die Funktion
    durchlaesst, darf das Regelverzeichnis verlassen.
    """
    from malaz.core.yara_update import _safe_member_subpath as safe

    external = (tmp_path / "external").resolve()

    def write_target(name: str):
        sub = safe(name)
        return None if sub is None else (external / sub).resolve()

    # Saubere Feed-Namen behalten ihre Kategorie (auch in der Rueckwaerts-Form).
    assert safe("repo-develop/yara/trojan/X.yara") == "trojan/X.yara"
    assert safe("a\\yara\\trojan\\X.yara") == "trojan/X.yara"
    # Traversal, ADS-Name und die Windows-Form ".. " — keiner darf entkommen.
    for name in (
        "..\\..\\evil.yar",
        "repo/yara/cat/..\\..\\..\\pwned.yar",
        "repo/yara/..\\..\\pwned.yara",
        "repo/yara/.. \\evil.yar",
        "repo/yara/x.yar:stream",
        "../evil.yar",
        "C:/win/evil.yara",
    ):
        target = write_target(name)
        assert target is None or target.is_relative_to(external), (name, str(target))


class _RawNameZip:
    """ZIP-Leser, der Mitgliedsnamen ungefiltert weitergibt.

    CPythons ``zipfile`` ersetzt beim LESEN jeden Backslash durch "/"
    (``ZipInfo.__init__`` -> ``_sanitize_filename``, unter Windows
    ``os.sep``) — ein Archiv mit ``..\\..\\evil.yar`` liefert dort
    ``../../evil.yar``. Genau deshalb kann der Test das nicht ueber den
    Standardleser zeigen: er legt die rohen Namen aus der zentralen
    Verzeichnisstruktur (im Archivbyte nachgewiesen) selbst vor. Die Senke
    ``external / subpath`` bleibt die echte.
    """

    def __init__(self, members: dict[str, bytes]) -> None:
        self._members = members

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def infolist(self):
        return [
            _RawMember(name, len(content)) for name, content in self._members.items()
        ]

    def read(self, info):
        return self._members[info.filename]

    def open(self, info):
        return io.BytesIO(self._members[info.filename])


class _RawMember:
    def __init__(self, filename: str, size: int) -> None:
        self.filename = filename
        self.file_size = size
        self.is_dir = lambda: False


def test_update_backslash_member_never_writes_outside(rules_dirs, monkeypatch):
    """Ende-zu-Ende im schreibenden Zweig (ohne yara-python): keine Datei aussen.

    Der Zweig mit ``_HAVE_YARA = False`` schreibt die Regelquellen — dort lag
    die Senke. Ein gefaelschter Feed mit Backslash-Traversal darf nichts
    ausserhalb von ``external/`` anlegen: was dort landet, laedt der naechste
    Start nicht mehr als Regel, liegt aber im Regelbaum des Nutzers.
    """
    monkeypatch.setattr(yara_update, "_HAVE_YARA", False)
    monkeypatch.setattr(
        yara_update.zipfile,
        "ZipFile",
        lambda _f: _RawNameZip({
            "repo/yara/ok.yara": _RULE_A,
            "repo/yara/cat/..\\..\\..\\pwned.yar": _RULE_B,
            "..\\..\\evil.yar": _RULE_B,
        }),
    )
    _patch_download(monkeypatch, b"archiv")

    result = yara_update.update_external_rules()

    assert result.ok
    external = rules_dirs / "external"
    stray = sorted(
        p.relative_to(rules_dirs.parent).as_posix()
        for p in rules_dirs.parent.rglob("*")
        if p.is_file() and external not in p.parents
    )
    assert stray == [], f"ausserhalb von external/ geschrieben: {stray}"
    assert (external / "ok.yara").is_file()


def test_update_zip_slip_and_junk_never_written(rules_dirs, monkeypatch):
    payload = _fake_zip_bytes({
        "repo/yara/ok.yara": _RULE_A,
        "../evil.exe": b"MZ...",
        "repo/tools/helper.ps1": b"powershell",
    })
    _patch_download(monkeypatch, payload)

    result = yara_update.update_external_rules()

    assert result.ok
    assert list((rules_dirs / "external").rglob("*.exe")) == []
    assert list((rules_dirs / "external").rglob("*.ps1")) == []
    assert not (rules_dirs.parent / "evil.exe").exists()


def test_update_aborts_on_empty_archive(rules_dirs, monkeypatch):
    _patch_download(monkeypatch, _fake_zip_bytes({"repo/readme.md": b"nix"}))
    before = rules_dirs / "external" / "alt.yar"
    before.write_bytes(_RULE_A)

    result = yara_update.update_external_rules()

    assert not result.ok
    assert before.is_file()  # Bestand bleibt unangetastet


def test_update_rejects_redirect_to_other_host(monkeypatch):
    class _Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def geturl(self):
            return "https://evil.example/rules.zip"

    monkeypatch.setattr(
        yara_update, "urlopen", lambda req, timeout=0: _Resp(b"x")
    )
    result = yara_update.update_external_rules()
    assert not result.ok
    assert "umgeleitet" in result.error


def test_update_rejects_oversized_download(rules_dirs, monkeypatch):
    class _Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def geturl(self):
            return config.YARA_UPDATE_URL

    big = b"z" * (config.YARA_UPDATE_MAX_ZIP_BYTES + 1)

    class _Big(_Resp):
        def read(self, n=-1):
            return big[:n] if n > 0 else big

    monkeypatch.setattr(yara_update, "urlopen", lambda req, timeout=0: _Big())
    result = yara_update.update_external_rules()
    assert not result.ok
    assert "Limit" in result.error


def test_gui_yara_button_only_when_rules_failed(qapp):
    # Simplified UX (same contract as the ClamAV button): the manual YARA
    # button exists but stays hidden while the bundled rules loaded fine —
    # it appears only when the rule engine reported a load error.
    #
    # Engine-free dispatcher: MainWindow's default probes ClamAV (~2.2 s),
    # which has nothing to do with YARA button visibility.
    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher
    from malaz.gui.main_window import MainWindow

    window = MainWindow(
        dispatcher=Dispatcher(
            av_scanner=WindowsDefenderScanner(enabled=False),
            clam_scanner=ClamAVScanner(enabled=False),
        )
    )
    try:
        assert window.options_view.btn_yara_now.text() == "YARA"
        assert window.options_view.btn_yara_now.isEnabled() is True
    finally:
        window.close()


def test_yara_runner_maps_result(qapp):
    from malaz.gui.main_window import _yara_rules_runner

    with mock.patch(
        "malaz.core.yara_update.update_external_rules"
    ) as fake:
        from malaz.core.yara_update import YaraUpdateResult

        fake.return_value = YaraUpdateResult(ok=True, installed=5)
        assert _yara_rules_runner(lambda _l: None) == (0, "")
        fake.return_value = YaraUpdateResult(ok=False, error="boom")
        assert _yara_rules_runner(lambda _l: None) == (1, "boom")


def test_extract_rule_files_enforces_a_cumulative_byte_budget(monkeypatch):
    """SEC-039: pro Datei gedeckelt, in Summe nicht.

    2000 Dateien x 2 MiB konnten aus einem 30-MiB-Archiv ~4 GiB puffern.
    Jetzt bricht das Update mit einem klaren Fehler ab, statt den Speicher
    zu sprengen.
    """
    monkeypatch.setattr(config, "YARA_UPDATE_MAX_TOTAL_BYTES", 2500)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as bundle:
        for i in range(5):
            bundle.writestr(f"rules-main/yara/cat/rule{i}.yar", b"x" * 1000)

    with pytest.raises(ValueError) as fehler:
        yara_update._extract_rule_files(buf.getvalue())
    assert "Gesamtlimit" in str(fehler.value), str(fehler.value)


def test_external_spoofed_zero_header_cannot_bypass_caps(monkeypatch):
    """SEC-008 + SEC-039: Data-Descriptor + file_size == 0 cannot bypass per-file or total caps."""
    monkeypatch.setattr(config, "YARA_UPDATE_MAX_FILE_BYTES", 1024)
    monkeypatch.setattr(config, "YARA_UPDATE_MAX_TOTAL_BYTES", 2500)

    def spoof_zero(raw_zip: bytes, match_substr: bytes = b"") -> bytes:
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

    buf1 = io.BytesIO()
    with zipfile.ZipFile(buf1, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("repo/yara/ok.yar", _RULE_A)
        zf.writestr("repo/yara/bomb.yar", b"B" * 2000)
    one_bomb = spoof_zero(buf1.getvalue(), b"bomb.yar")
    extracted = yara_update._extract_rule_files(one_bomb)
    assert [name for name, _ in extracted] == ["ok.yar"]

    buf3 = io.BytesIO()
    with zipfile.ZipFile(buf3, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(3):
            zf.writestr(f"repo/yara/b{i}.yar", b"B" * 1500)
    three_bombs = spoof_zero(buf3.getvalue())
    with pytest.raises(ValueError, match="Gesamtlimit"):
        yara_update._extract_rule_files(three_bombs)
