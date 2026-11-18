"""Tests für die capa-Integration (analysis/capa.py + PE-Pipeline-Stufe).

KEIN Test ruft capa wirklich auf: ``run_tool`` wird ersetzt (Muster wie in
tests/test_clamav.py). Die Suite läuft ohne Netz und ohne externe Werkzeuge —
ein Test, der die echte Binary bräuchte, würde auf jedem Rechner ohne capa
grün sein, ohne etwas zu prüfen.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from malaz import config
from malaz.analysis import capa as capa_module
from malaz.analysis.capa import (
    CapaResult,
    CapaRule,
    CapaScanner,
    _parse_capa_output,
    capa_label,
)
from malaz.models import AnalysisContext, Severity

# -- Hilfen ----------------------------------------------------------------- #

def _scanner(tmp_path: Path, monkeypatch, *, rules_dir: Path | None = None) -> CapaScanner:
    """Scanner mit gefälschter Binary, ohne Suche im Dateisystem."""
    fake = tmp_path / "capa.exe"
    fake.write_bytes(b"MZ")
    monkeypatch.setattr(capa_module, "which_absolute", lambda name: None)
    scanner = CapaScanner.__new__(CapaScanner)
    scanner.enabled = True
    scanner.timeout = 5
    scanner.binary = fake
    scanner.rules_dir = rules_dir
    return scanner


def _run_with(monkeypatch, rc: int, stdout: bytes, stderr: bytes = b"") -> list[list[str]]:
    """``run_tool`` ersetzen und die Argumentlisten mitschreiben."""
    calls: list[list[str]] = []

    def fake(args, timeout=None, **kwargs):
        calls.append(list(args))
        return rc, stdout, stderr

    monkeypatch.setattr(capa_module, "run_tool", fake)
    return calls


def _json_rules(rules: dict[str, str]) -> bytes:
    """capa-JSON im Format des Ergebnisdokuments (Name -> Namensraum)."""
    return json.dumps(
        {
            "meta": {"version": "9.0.0"},
            "rules": {
                name: {"meta": {"name": name, "namespace": ns}, "matches": []}
                for name, ns in rules.items()
            },
        }
    ).encode()


def _pe_ctx(data: bytes = b"MZ" + b"\x00" * 62) -> AnalysisContext:
    return AnalysisContext(
        path=Path("sample.exe"), data=data, detected_type="pe", size=len(data), depth=0
    )


# -- (a) fehlende Binary: nicht verfügbar, kein Aufruf ---------------------- #

def test_missing_binary_is_unavailable_and_never_invoked(tmp_path, monkeypatch):
    """Beissprobe: ohne Binary darf capa NICHT gestartet werden.

    Der Ersatz wirft, wenn er doch gerufen wird — eine Zusicherung auf
    ``available is False`` allein würde nicht merken, dass trotzdem ein Prozess
    gestartet wird.
    """
    monkeypatch.setattr(
        config, "CAPA_CANDIDATES", (str(tmp_path / "gibtsnicht" / "capa.exe"),)
    )
    monkeypatch.setattr(capa_module, "which_absolute", lambda name: None)
    monkeypatch.setattr(
        capa_module,
        "run_tool",
        lambda *a, **k: pytest.fail(f"capa wurde ohne Binary gestartet: {a}"),
    )
    target = tmp_path / "sample.exe"
    target.write_bytes(b"MZ")

    # enabled=True: CAPA_ENABLED ist per Default aus, und mit dem Default
    # waere available schon deshalb False — die Beissprobe auf die
    # PFADSUCHE liefe ins Leere (gemessen: die Mutation blieb gruen).
    scanner = CapaScanner(enabled=True)
    assert scanner.binary is None
    assert scanner.available is False

    result = scanner.scan_path(target)
    assert result.scanned is False
    assert result.skipped_reason


def test_disabled_scanner_is_not_available():
    scanner = CapaScanner(enabled=False)
    assert scanner.available is False
    assert scanner.binary is None
    assert scanner.scan_path(Path("x.exe")).skipped_reason


def test_binary_is_found_via_path_fallback(tmp_path, monkeypatch):
    """Ohne festen Installationsort zählt der PATH (wie bei DIE)."""
    monkeypatch.setattr(config, "CAPA_CANDIDATES", (str(tmp_path / "gibtsnicht"),))
    found = tmp_path / "capa.exe"
    found.write_bytes(b"MZ")
    monkeypatch.setattr(capa_module, "which_absolute", lambda name: str(found))
    # CAPA_ENABLED ist per Default aus (gemessen zu langsam) — dieser Test
    # prueft die PFADSUCHE, also einschalten.
    scanner = CapaScanner(enabled=True)
    assert scanner.available is True
    assert scanner.binary == found


# -- (b) kaputte Ausgabe: skipped_reason statt Ausnahme --------------------- #

def test_broken_json_becomes_a_skip_reason(tmp_path, monkeypatch):
    """Beissprobe: Müll auf stdout ist kein Grund für eine Ausnahme.

    Zwei Formen, die im Betrieb vorkommen: Text, der gar kein JSON ist, und
    ein abgeschnittenes Dokument (Prozess abgebrochen, Ausgabe gekappt).
    """
    scanner = _scanner(tmp_path, monkeypatch)
    target = tmp_path / "sample.exe"
    target.write_bytes(b"MZ")

    _run_with(monkeypatch, 0, b"<html>not json at all</html>")
    assert scanner.scan_path(target).skipped_reason == (
        "capa-Ausgabe nicht lesbar (kein gültiges JSON)"
    )

    _run_with(monkeypatch, 0, b'{"meta": {"version": "9.0.0"}, "rules": {"create pro')
    assert scanner.scan_path(target).skipped_reason == (
        "capa-Ausgabe nicht lesbar (kein gültiges JSON)"
    )


def test_empty_output_says_so_and_keeps_the_returncode(tmp_path, monkeypatch):
    """Gepacktes Sample: capa schreibt den Grund nach stderr, sonst nichts."""
    scanner = _scanner(tmp_path, monkeypatch)
    target = tmp_path / "packed.exe"
    target.write_bytes(b"MZ")
    _run_with(monkeypatch, 3, b"", b"unsupported format: cannot find a suitable approach")

    result = scanner.scan_path(target)
    assert result.scanned is False
    assert "Returncode 3" in (result.skipped_reason or "")
    assert "unsupported format" in result.detail


def test_json_without_rules_is_a_normal_empty_result(tmp_path, monkeypatch):
    """Leeres ``rules``-Objekt ist der Normalfall — kein Fehler, keine Ausnahme."""
    scanner = _scanner(tmp_path, monkeypatch)
    target = tmp_path / "sample.exe"
    target.write_bytes(b"MZ")
    _run_with(monkeypatch, 0, json.dumps({"meta": {}, "rules": {}}).encode())

    result = scanner.scan_path(target)
    assert result.scanned is False
    assert result.capabilities == []
    assert "keine Fähigkeiten" in (result.skipped_reason or "")


def test_timeout_becomes_a_skip_reason(tmp_path, monkeypatch):
    """Beissprobe: der Timeout darf nicht als Ausnahme nach oben laufen."""
    scanner = _scanner(tmp_path, monkeypatch)
    target = tmp_path / "sample.exe"
    target.write_bytes(b"MZ")

    def boom(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="capa", timeout=5)

    monkeypatch.setattr(capa_module, "run_tool", boom)
    result = scanner.scan_path(target)
    assert result.scanned is False
    assert "Timeout" in (result.skipped_reason or "")


def test_capa_failure_never_raises(tmp_path, monkeypatch):
    """Auch ein unerwarteter Fehler bleibt ein skipped_reason."""
    scanner = _scanner(tmp_path, monkeypatch)
    target = tmp_path / "sample.exe"
    target.write_bytes(b"MZ")

    def boom(*args, **kwargs):
        raise OSError("Zugriff verweigert")

    monkeypatch.setattr(capa_module, "run_tool", boom)
    result = scanner.scan_path(target)
    assert result.scanned is False
    assert "OSError" in (result.skipped_reason or "")


def test_missing_file_is_not_called(tmp_path, monkeypatch):
    scanner = _scanner(tmp_path, monkeypatch)
    monkeypatch.setattr(
        capa_module, "run_tool", lambda *a, **k: pytest.fail("kein Aufruf ohne Datei")
    )
    result = scanner.scan_path(tmp_path / "weg.exe")
    assert result.scanned is False
    assert "existiert nicht" in (result.skipped_reason or "")


# -- Regelbasis (rc 10 = E_MISSING_RULES) ----------------------------------- #

def test_missing_rules_hint_names_the_rules_path(tmp_path, monkeypatch):
    """capa ohne Regelbasis (pip-Installation) → Hinweis mit konkretem Pfad.

    Der Pfad wird im Test gesetzt, nicht aus der echten Konfiguration gelesen:
    die Meldung muss den Pfad nennen, den die Suche BENUTZT hat — stünde er
    fest im Modul (Import-Zeitpunkt), fiele das hier auf.
    """
    expected = tmp_path / "capa-rules-ablage"
    monkeypatch.setattr(config, "CAPA_RULES_CANDIDATES", (str(expected),))
    scanner = _scanner(tmp_path, monkeypatch)
    target = tmp_path / "sample.exe"
    target.write_bytes(b"MZ")
    _run_with(
        monkeypatch,
        10,
        b"",
        b"default embedded rules not found! (maybe you installed capa as a library?)\n"
        b"provide your own rule set via the `-r` option.",
    )

    result = scanner.scan_path(target)
    assert result.scanned is False
    reason = result.skipped_reason or ""
    assert "-r" in reason, reason
    assert str(expected) in reason, reason


def test_rules_directory_is_handed_over_only_when_it_contains_rules(
    tmp_path, monkeypatch
):
    """Ein leerer Ordner darf ein funktionierendes capa nicht kaputtmachen."""
    empty = tmp_path / "leer"
    empty.mkdir()
    full = tmp_path / "capa-rules"
    full.mkdir()
    (full / "create-process.yml").write_text("rule:\n", encoding="utf-8")
    monkeypatch.setattr(
        config, "CAPA_RULES_CANDIDATES", (str(tmp_path / "gibtsnicht"), str(empty))
    )
    assert CapaScanner.__new__(CapaScanner)._locate_rules() is None
    monkeypatch.setattr(
        config, "CAPA_RULES_CANDIDATES", (str(empty), str(full))
    )
    assert CapaScanner.__new__(CapaScanner)._locate_rules() == full

    scanner = _scanner(tmp_path, monkeypatch, rules_dir=full)
    target = tmp_path / "sample.exe"
    target.write_bytes(b"MZ")
    calls = _run_with(monkeypatch, 0, _json_rules({"create process": "host-interaction"}))
    scanner.scan_path(target)
    # Argumentliste, kein Shell-String: Binary, Ruhe-Modus, JSON, Regeln, Datei.
    assert calls == [[str(scanner.binary), "-q", "-j", "-r", str(full), str(target.resolve())]]


# -- (c) Deckel auf die Regelzahl ------------------------------------------- #

def test_rule_cap_is_applied(tmp_path, monkeypatch):
    """Beissprobe: mehr Regeln als CAPA_MAX_RULES werden gekappt und gemeldet."""
    scanner = _scanner(tmp_path, monkeypatch)
    target = tmp_path / "sample.exe"
    target.write_bytes(b"MZ")
    many = {f"capability {i}": "host-interaction" for i in range(config.CAPA_MAX_RULES + 50)}
    _run_with(monkeypatch, 0, _json_rules(many))

    result = scanner.scan_path(target)
    assert result.scanned is True
    assert len(result.capabilities) == config.CAPA_MAX_RULES
    assert result.truncated is True


def test_oversized_output_is_not_parsed(tmp_path, monkeypatch):
    """Beissprobe: oberhalb des Deckels wird gar nicht erst geparst.

    Geprüft wird die Grenze selbst — genau auf dem Deckel läuft der Lauf noch
    durch, ein Zeichen darüber nicht.
    """
    scanner = _scanner(tmp_path, monkeypatch)
    target = tmp_path / "sample.exe"
    target.write_bytes(b"MZ")
    payload = _json_rules({"create process": "host-interaction"})
    _run_with(monkeypatch, 0, payload)

    monkeypatch.setattr(config, "CAPA_MAX_OUTPUT_CHARS", len(payload))
    assert scanner.scan_path(target).scanned is True

    monkeypatch.setattr(config, "CAPA_MAX_OUTPUT_CHARS", len(payload) - 1)
    result = scanner.scan_path(target)
    assert result.capabilities == []
    assert "unplausibel" in (result.skipped_reason or "")


def test_truncated_output_is_not_parsed_as_a_verdict(tmp_path, monkeypatch):
    """SEC-023: a capped capa output is a PREFIX, never a result document.

    The visible part here is even valid JSON with a capability — but bytes
    beyond the cap may contain any other rule. Parsing the prefix would let a
    crafted sample decide what Malaz sees; the stage must report "not checked".
    """
    from malaz.procio import ToolResult

    scanner = _scanner(tmp_path, monkeypatch)
    target = tmp_path / "sample.exe"
    target.write_bytes(b"MZ")
    payload = _json_rules({"create process": "host-interaction"})
    monkeypatch.setattr(
        capa_module,
        "run_tool",
        lambda *a, **k: ToolResult(0, payload, b"", truncated=True),
    )

    result = scanner.scan_path(target)

    assert result.scanned is False
    assert result.understood is False
    assert result.capabilities == []
    assert "abgeschnitten" in (result.skipped_reason or "")


def test_hostile_json_fields_are_capped_and_nested_data_ignored():
    """Die Ausgabe beschreibt eine angreiferkontrollierte Datei.

    Nur Name und Namensraum werden gelesen, jeder Text wird gekappt, und ein
    riesiger ``matches``-Baum wird nicht angefasst.
    """
    payload = {
        "meta": {},
        "rules": {
            "x" * 5_000: {
                "meta": {"name": "y" * 5_000, "namespace": "z" * 5_000},
                "matches": [[0x1000, ["c" * 50] * 100] for _ in range(200)],
            },
            "kein-dict": "nicht verwendbar",
            "ohne-meta": {"matches": []},
        },
    }
    parsed = _parse_capa_output(json.dumps(payload))
    assert parsed.understood is True
    assert parsed.truncated is False
    rules = parsed.rules
    assert len(rules) == 2, [r.name for r in rules]  # "kein-dict" fällt weg
    assert all(len(r.name) <= config.CAPA_MAX_STRING for r in rules)
    assert all(len(r.namespace) <= config.CAPA_MAX_STRING for r in rules)
    # Der 5000-Zeichen-Name ist gekappt; "ohne-meta" hat keinen meta-Namen und
    # trägt deshalb den Schlüssel.
    assert [r.name for r in rules] == ["y" * config.CAPA_MAX_STRING, "ohne-meta"]


def test_malformed_shapes_never_raise():
    """Formen, die capa so nie liefert, dürfen trotzdem nichts auslösen."""
    for raw in (
        "",
        "   ",
        "kein json",
        '"nur ein string"',
        "[1, 2, 3]",
        '{"rules": "kein objekt"}',
        '{"rules": {}}',
        '{"meta": {}, "rules": [{"meta": {"name": "create process"}}]}',
        '{"rules": {"a": null}}',
        "{" * 400,
    ):
        parsed = _parse_capa_output(raw)
        assert isinstance(parsed.rules, list), raw
        assert parsed.truncated is False, raw


# -- (d) Übersetzungstabelle ------------------------------------------------ #

def test_translation_table_is_applied():
    """Beissprobe: der Namensraum wird übersetzt, ohne die Regeln zu verlieren.

    Gemessen an den vier Namensräumen, die im Regelwerk am häufigsten feuern.
    """
    assert capa_label(
        "persist via Run key", "persistence/registry/run"
    ).startswith("Einrichten einer dauerhaften Autostart-Funktion: ")
    assert capa_label("send data", "communication").startswith("Kontakt zu einem Server: ")
    assert capa_label("check for debugger", "anti-analysis").startswith(
        "Verstecken vor Analyse: "
    )
    assert capa_label("create process", "host-interaction").startswith(
        "Zugriff auf das System: "
    )
    # Der Regelname bleibt unverändert — er benennt die capa-Regel.
    assert capa_label("send data", "communication") == "Kontakt zu einem Server: send data"


def test_specific_namespace_wins_over_the_general_one():
    """Ein Eintrag für den Zweig schlägt den Eintrag für die Wurzel."""
    assert capa_label("create process", "host-interaction/process/create") == (
        "Starten von Programmen: create process"
    )
    assert capa_label("encrypt data", "data-manipulation/encryption/aes") == (
        "Verschlüsseln von Daten: encrypt data"
    )


def test_unknown_namespace_keeps_the_rule_name():
    """Ohne Eintrag wird nichts weggelassen und nichts erfunden."""
    assert capa_label("do something", "voellig/neuer/namensraum") == "do something"
    assert capa_label("do something", "") == "do something"


def test_parsed_capabilities_carry_the_german_label():
    rules = _parse_capa_output(
        _json_rules({"persist via Run key": "persistence/registry"}).decode()
    ).rules
    assert rules[0].display == (
        "Einrichten einer dauerhaften Autostart-Funktion: persist via Run key"
    )
    assert rules[0].name == "persist via Run key"
    assert rules[0].namespace == "persistence/registry"


# -- Pipeline-Anbindung ----------------------------------------------------- #

def _fake_scanner(monkeypatch, module, result: CapaResult, available: bool = True):
    """Ersetzt ``CapaScanner`` in der Pipeline durch einen festen Antwortgeber."""

    class FakeCapa:
        def __init__(self, *args, **kwargs):
            pass

        def scan_path(self, path):
            assert Path(path).exists(), "Temp-Datei muss angelegt worden sein"
            return result

    monkeypatch.setattr(FakeCapa, "available", available, raising=False)
    monkeypatch.setattr(module, "CapaScanner", FakeCapa)
    # Die Stufe ist per Default AUS (gemessen zu langsam, siehe config.py).
    # Diese Tests pruefen die STUFE, nicht die Voreinstellung — also
    # einschalten. Den Aus-Zustand prueft test_capa_is_opt_in_because_it_is_slow.
    monkeypatch.setattr(module.config, "CAPA_ENABLED", True)
    return FakeCapa


def test_capability_indicator_is_one_per_file_with_german_names(monkeypatch, tmp_path):
    """Ein Befund je Datei, Detail mit deutschen Namen, gekappt bei 8."""
    import malaz.pipelines.pe_pipeline as module

    rules = [
        CapaRule(name=f"cap {i}", namespace="persistence", display=f"Autostart: cap {i}")
        for i in range(12)
    ]
    _fake_scanner(
        monkeypatch, module, CapaResult(scanned=True, capabilities=rules)
    )
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")
    inds = module.PePipeline()._capa(_pe_ctx())

    assert len(inds) == 1, "je Fähigkeit ein Befund würde den Score fluten"
    hit = inds[0]
    assert hit.rule_id == "CAPA_CAPABILITY"
    # LOW/5 — siehe _CAPA_LEVELS: die Regelbasis meldet auf fast jedem
    # Programm Faehigkeiten, ein solches Signal darf keine 15 wert sein.
    assert hit.severity == Severity.LOW
    assert hit.weight == 5
    assert "Autostart: cap 0" in hit.detail
    assert "Autostart: cap 7" in hit.detail
    assert "Autostart: cap 8" not in hit.detail, "Deckel auf 8 Namen"
    assert "… und 4 weitere" in hit.detail
    assert "12 Fähigkeiten" in hit.detail


def test_capability_detail_keeps_the_real_count_when_truncated(monkeypatch, tmp_path):
    """Der Deckel aus capa.py darf im Detail nicht als kleinere Zahl erscheinen."""
    import malaz.pipelines.pe_pipeline as module

    rules = [
        CapaRule(name=f"cap {i}", namespace="communication", display=f"Kontakt: cap {i}")
        for i in range(config.CAPA_MAX_RULES)
    ]
    _fake_scanner(
        monkeypatch, module, CapaResult(scanned=True, capabilities=rules, truncated=True)
    )
    inds = module.PePipeline()._capa(_pe_ctx())
    assert "gekappt" in inds[0].detail
    assert f"{config.CAPA_MAX_RULES} Fähigkeiten" in inds[0].detail


def test_unavailable_engine_is_pure_diagnosis(monkeypatch, tmp_path):
    """capa fehlt → INFO/0 mit Titel; kein Erkennungsverlust, kein Score."""
    import malaz.pipelines.pe_pipeline as module

    _fake_scanner(monkeypatch, module, CapaResult(), available=False)
    inds = module.PePipeline()._capa(_pe_ctx())

    assert [i.rule_id for i in inds] == ["CAPA_UNAVAILABLE"]
    assert inds[0].severity == Severity.INFO
    assert inds[0].weight == 0
    assert inds[0].title == module._CAPA_TITLES["CAPA_UNAVAILABLE"]


def test_no_capabilities_yield_no_indicator(monkeypatch, tmp_path):
    """Gepacktes Sample: die Stufe schweigt, statt einen Leerbefund zu melden.

    Das Fixture stand hier auf ``scanned=False`` — und das heisst NICHT "keine
    Faehigkeiten", sondern "die Stufe konnte nicht laufen". Ein Test, dessen
    Fixture nicht erzeugt, was sein Docstring behauptet: er pruefte den
    Rueckgabewert eines Abbruchs, nicht den eines echten Laufs ohne Treffer.
    Ein echter Lauf ohne Treffer ist ``scanned=True`` mit leerer Liste.
    """
    import malaz.pipelines.pe_pipeline as module

    # Der ECHTE Zustand aus analysis/capa.py: ein Lauf ohne Treffer endet im
    # "Nothing usable"-Zweig mit scanned=False und understood=True. Ein
    # Fixture mit scanned=True waere ein Zustand, den der Scanner nie
    # erzeugt — der Test waere gruen und hielte nichts.
    _fake_scanner(
        monkeypatch,
        module,
        CapaResult(scanned=False, understood=True, capabilities=[]),
    )
    assert module.PePipeline()._capa(_pe_ctx()) == []


def test_materialize_failure_is_reported(monkeypatch):
    """Der Fehlerpfad bleibt sichtbar (INFO/0) statt die Stufe lautlos zu killen."""
    import malaz.pipelines.pe_pipeline as module

    _fake_scanner(monkeypatch, module, CapaResult(scanned=True))
    monkeypatch.setattr(
        module.PePipeline,
        "_materialize",
        lambda self, ctx, prefix="malaz_die_": _boom(),
    )
    inds = module.PePipeline()._capa(_pe_ctx())
    assert [i.rule_id for i in inds] == ["CAPA_ERROR"]
    assert inds[0].weight == 0 and inds[0].severity == Severity.INFO


def _boom():
    raise OSError("kein Temp-Platz")


def test_capa_rule_ids_are_in_both_tables():
    """Jede capa-Regel-ID braucht Titel UND Severity in der Tabelle."""
    from malaz.pipelines import pe_pipeline as module

    for rule_id in ("CAPA_CAPABILITY", "CAPA_UNAVAILABLE", "CAPA_ERROR"):
        assert rule_id in module._CAPA_LEVELS, rule_id
        assert rule_id in module._CAPA_TITLES, rule_id
        assert module._CAPA_TITLES[rule_id].strip()
    # LOW/5, nicht MEDIUM/15: die Regelbasis meldet auf fast jedem Programm
    # Faehigkeiten wie "Prozess starten". Ein Signal, das fuer praktisch jede
    # EXE gilt, darf sie nicht ueber die Schwelle heben — dieselbe Regel wie
    # bei MAIL_AUTH_ABSENT und beim Zaehlpixel.
    assert module._CAPA_LEVELS["CAPA_CAPABILITY"] == (Severity.LOW, 5)
    assert module._CAPA_LEVELS["CAPA_UNAVAILABLE"] == (Severity.INFO, 0)
    assert module._CAPA_LEVELS["CAPA_ERROR"] == (Severity.INFO, 0)


def test_capa_stage_only_runs_for_pe_files(monkeypatch):
    """Nur PE: capa kann mehr Formate, aber Malaz ruft es dort auf, wo es trägt."""
    import malaz.pipelines.pe_pipeline as module

    monkeypatch.setattr(
        module,
        "CapaScanner",
        lambda *a, **k: pytest.fail("capa darf für Nicht-PE nicht laufen"),
    )
    ctx = AnalysisContext(
        path=Path("doc.pdf"), data=b"%PDF-1.7", detected_type="pdf", size=8, depth=0
    )
    assert module.PePipeline().analyze(ctx) == []


def test_capa_stage_runs_when_the_binary_is_there(monkeypatch, tmp_path):
    """Ende-zu-Ende über analyze(): die Stufe hängt wirklich im Ablauf."""
    import malaz.pipelines.pe_pipeline as module

    real_pipeline = module.PePipeline
    calls: list[Path] = []

    class FakeCapa:
        def __init__(self, *args, **kwargs):
            pass

        available = True

        def scan_path(self, path):
            calls.append(Path(path))
            return CapaResult(
                scanned=True,
                capabilities=[
                    CapaRule(
                        name="persist via Run key",
                        namespace="persistence/registry",
                        display="Einrichten einer dauerhaften Autostart-Funktion: "
                        "persist via Run key",
                    )
                ],
            )

    monkeypatch.setattr(module, "CapaScanner", FakeCapa)
    monkeypatch.setattr(config, "CAPA_ENABLED", True)
    # Die übrigen externen Stufen ruhigstellen (kein PowerShell, kein DIE).
    monkeypatch.setattr(module, "which_absolute", lambda name: None)
    monkeypatch.setattr(module, "run_tool", lambda *a, **k: (1, b"", b""))

    data = b"MZ" + b"\x00" * 200
    ctx = AnalysisContext(
        path=Path("packed.exe"), data=data, detected_type="pe", size=len(data), depth=0
    )
    inds = real_pipeline().analyze(ctx)
    ids = {i.rule_id for i in inds}
    assert "CAPA_CAPABILITY" in ids, sorted(ids)
    assert calls, "capa wurde nicht aufgerufen"
    hit = next(i for i in inds if i.rule_id == "CAPA_CAPABILITY")
    assert "Autostart-Funktion" in hit.detail


def test_capability_panel_groups_and_explains(qtbot):
    """Der Faehigkeiten-Reiter gruppiert und sagt, dass es kein Urteil ist.

    Ohne den Hinweissatz liest ein Laie eine Liste von Faehigkeiten als Beweis
    fuer Schadsoftware — dabei trifft "liest Dateien" oder "legt einen Dienst
    an" auf voellig normale Programme zu.
    """
    from PySide6.QtWidgets import QLabel

    from malaz.gui.capability_panel import CapabilityPanel
    from malaz.models import RiskLevel, ScanResult

    r = ScanResult(
        path="setup.exe",
        detected_type="pe",
        risk_level=RiskLevel.GREEN,
        score=10,
        capa_capabilities=[
            {"name": "Einrichten einer dauerhaften Autostart-Funktion", "namespace": "persistence"},
            {"name": "Kontakt zu einem Server", "namespace": "communication"},
            {"name": "Schutz vor Debuggern", "namespace": "anti-analysis/anti-debugging"},
            {"name": "Voellig unbekannte Regel", "namespace": "voellig-neu"},
        ],
    )
    panel = CapabilityPanel()
    qtbot.addWidget(panel)
    panel.show_result(r)
    text = "\n".join(w.text() for w in panel.findChildren(QLabel) if w.text())

    assert "Einordnung, kein Urteil" in text, "der Hinweis fehlt"
    assert "Autostart" in text
    # Gruppiert, nicht als eine Zeile. Der Name kommt aus _GROUP_DE (kurze
    # Ueberschrift), NICHT aus _NAMESPACE_DE — dort steht der Verbsatz, der
    # den Namen EINES Befunds bildet.
    assert "Analyse-Abwehr" in text, text[:300]
    # Der Eintrag steht mit dem KURZEN Namen unter der Gruppe: den Namensraum
    # als Praefix an jedem Eintrag zu wiederholen waere redundant, weil er
    # schon in der Ueberschrift steht. Der Befundtext (CAPA_CAPABILITY) traegt
    # weiterhin die ausfuehrliche Form.
    assert "Schutz vor Debuggern" in text, text[:300]
    assert "Verstecken vor Analyse: Schutz vor Debuggern" not in text, (
        "der Namensraum steht doppelt — einmal als Ueberschrift, einmal am Eintrag"
    )
    # Eine unbekannte Regel wird NICHT verschwiegen.
    assert "Voellig unbekannte Regel" in text


def test_capability_panel_says_so_when_there_is_nothing(qtbot):
    """Ohne Faehigkeiten sagt der Reiter das — und behauptet keine Harmlosigkeit."""
    from PySide6.QtWidgets import QLabel

    from malaz.gui.capability_panel import CapabilityPanel
    from malaz.models import RiskLevel, ScanResult

    panel = CapabilityPanel()
    qtbot.addWidget(panel)
    panel.show_result(ScanResult(path="x.exe", detected_type="pe", risk_level=RiskLevel.RED, score=80))
    text = "\n".join(w.text() for w in panel.findChildren(QLabel) if w.text())
    assert "keine Fähigkeiten" in text
    assert "nicht, dass sie harmlos ist" in text, "die Aussage verleitet zur Entwarnung"


def test_capability_tab_only_for_files_with_capabilities(qtbot):
    """Der Reiter erscheint nur, wenn es etwas zu zeigen gibt."""
    from malaz.gui.main_window import MainWindow
    from malaz.models import RiskLevel, ScanResult

    window = MainWindow()
    qtbot.addWidget(window)

    ohne = ScanResult(path="a.pdf", detected_type="pdf", risk_level=RiskLevel.GREEN, score=0)
    window._on_result(ohne)
    window.table.setCurrentItem(window.table.topLevelItem(0))
    assert window.detail_view._btn_tab_capa.isHidden()

    mit = ScanResult(
        path="b.exe", detected_type="pe", risk_level=RiskLevel.YELLOW, score=30,
        capa_capabilities=[{"name": "Kontakt zu einem Server", "namespace": "communication"}],
    )
    window._on_result(mit)
    window.table.setCurrentItem(window.table.topLevelItem(1))
    assert not window.detail_view._btn_tab_capa.isHidden()
    assert window.detail_view._btn_tab_capa.text() == "Fähigkeiten (1)"

    # Und wieder weg bei einer Datei ohne Faehigkeiten.
    window.table.setCurrentItem(window.table.topLevelItem(0))
    assert window.detail_view._btn_tab_capa.isHidden()


def test_missing_rule_base_is_reported_not_swallowed(monkeypatch):
    """Eine fehlende Regelbasis darf die Stufe nicht lautlos verschwinden lassen.

    ``pip install flare-capa`` bringt keinen ``rules/``-Ordner mit. capa bricht
    dann mit Returncode 10 ab, ``_missing_rules_hint()`` baut eine hilfreiche
    Meldung — und die wurde weggeworfen: die Stufe endete mit
    ``if not result.scanned or not result.capabilities: return []``, und
    ``scanned=False`` ist genau der Zustand fuer "Regelbasis fehlt", Timeout,
    Uebergroesse und Lauf-Fehler. Der Nutzer sah keine capa-Zeile und las das
    als "capa lief, nichts gefunden".

    Die 27 Tests rufen capa nie wirklich auf — dieser Pfad war damit
    ungetestet. Hier wird der Scanner-Aufruf ersetzt.
    """
    monkeypatch.setattr(config, "CAPA_ENABLED", True)

    from malaz.analysis.capa import CapaResult
    from malaz.pipelines.pe_pipeline import _CAPA_LEVELS, _CAPA_TITLES, PePipeline

    class _FakeScanner:
        available = True

        def scan_path(self, path):
            return CapaResult(
                scanned=False,
                returncode=10,
                skipped_reason="capa: Regelbasis fehlt (erwartet unter 'rules')",
                detail="provide your own rule set via the `-r` option",
            )

    import malaz.pipelines.pe_pipeline as modul

    monkey = modul.CapaScanner
    modul.CapaScanner = _FakeScanner  # type: ignore[misc]
    try:
        pipeline = PePipeline()
        ctx = _pe_ctx()
        indicatoren = pipeline._capa(ctx)
    finally:
        modul.CapaScanner = monkey  # type: ignore[misc]

    ids = [i.rule_id for i in indicatoren]
    assert ids, "die Stufe verschwand lautlos"
    assert "CAPA_SKIPPED" in ids, ids
    detail = next(i.detail for i in indicatoren if i.rule_id == "CAPA_SKIPPED")
    assert "Regelbasis" in detail, "die Begruendung fehlt"
    assert "CAPA_SKIPPED" in _CAPA_LEVELS and "CAPA_SKIPPED" in _CAPA_TITLES


def test_ran_but_found_nothing_is_not_reported_as_a_failure(monkeypatch):
    """Ein gepacktes PE darf NICHT "capa konnte nicht laufen" bekommen.

    ``scanned=False`` allein unterscheidet die Faelle nicht: ein echter Lauf
    ohne Treffer und ein Ausfall (Regelbasis fehlt, Timeout) landen beide
    dort. Getrennt werden sie durch ``un
derstood`` — ein Lauf, dessen Ausgabe
    lesbar war. Ohne diese Unterscheidung stuende auf JEDEM gepackten PE die
    Falschaussage, die Stufe sei nicht gelaufen.
    """
    import malaz.pipelines.pe_pipeline as module

    _fake_scanner(
        monkeypatch,
        module,
        CapaResult(scanned=False, understood=True, capabilities=[]),
    )
    assert module.PePipeline()._capa(_pe_ctx()) == []


def test_unreadable_output_is_reported(monkeypatch):
    """Eine unlesbare Ausgabe ist ein Ausfall und wird gemeldet."""
    import malaz.pipelines.pe_pipeline as module

    _fake_scanner(
        monkeypatch,
        module,
        CapaResult(
            scanned=False,
            understood=False,
            skipped_reason="capa-Ausgabe nicht lesbar (kein gültiges JSON)",
        ),
    )
    inds = module.PePipeline()._capa(_pe_ctx())
    assert [i.rule_id for i in inds] == ["CAPA_SKIPPED"], inds


def test_capability_group_headings_are_short(qtbot):
    """Gruppenueberschriften sind Substantive, keine Saetze.

    Gemessen im Screenshot: die Ueberschrift lautete "Einrichten einer
    dauerhaften Autostart-Funktion (2)". Die Tabelle _NAMESPACE_DE liefert
    Verbsaetze — richtig als Name EINES Befunds ("Verstecken vor Analyse:
    detect debugger"), falsch als Ueberschrift ueber einer Liste.

    Zwei Register, zwei Tabellen: _NAMESPACE_DE fuer den Befundnamen,
    _GROUP_DE fuer die Ueberschrift.
    """
    from PySide6.QtWidgets import QLabel

    from malaz.analysis.capa import _GROUP_DE, _NAMESPACE_DE
    from malaz.gui.capability_panel import CapabilityPanel
    from malaz.models import RiskLevel, ScanResult

    # Jede Ueberschrift ist kurz — eine Zeile, kein Satz.
    for gruppe, name in _GROUP_DE.items():
        assert len(name) <= 24, f"{gruppe}: {name!r} ist zu lang fuer eine Ueberschrift"

    r = ScanResult(
        path="x.exe", detected_type="pe", risk_level=RiskLevel.YELLOW, score=30,
        capa_capabilities=[
            {"name": "Einen Dienst anlegen", "namespace": "persistence/service"},
            {"name": "Kontakt zu einem Server", "namespace": "communication/http"},
        ],
    )
    panel = CapabilityPanel()
    qtbot.addWidget(panel)
    panel.show_result(r)
    text = "\n".join(w.text() for w in panel.findChildren(QLabel) if w.text())

    assert "Persistenz" in text or "Autostart" in text, text[:300]
    # Der Verbsatz aus _NAMESPACE_DE taucht als UEBERSCHRIFT nicht mehr auf.
    assert "Einrichten einer dauerhaften Autostart-Funktion (" not in text
    # Als Befundname bleibt er erhalten.
    assert _NAMESPACE_DE["persistence"].startswith("Einrichten")


def test_capability_panel_handles_hostile_entries(qtbot):
    """Randfaelle in den capa-Daten duerfen das Panel nicht aus dem Tritt bringen.

    Die capa-Ausgabe beschreibt eine angreiferkontrollierte Datei und kommt
    als JSON von einem externen Werkzeug: fehlende Felder, leere Namen, ein
    Namensraum ohne Schraegstrich, tausend Eintraege.
    """
    from PySide6.QtWidgets import QLabel

    from malaz.gui.capability_panel import CapabilityPanel
    from malaz.models import RiskLevel, ScanResult

    faelle = [
        [],  # leer (kein Reiter, aber auch kein Absturz)
        [{}],  # Eintrag ohne jedes Feld
        [{"name": ""}],  # leerer Name
        [{"namespace": "ohne-schraegstrich"}],  # Namensraum ohne Unterebene
        [{"name": "x", "namespace": ""}],  # leerer Namensraum
        [{"name": "a" * 5000, "namespace": "runtime"}],  # absurd langer Name
        [{"name": f"cap {i}", "namespace": "runtime"} for i in range(1000)],  # Masse
    ]
    for nummer, eintraege in enumerate(faelle):
        r = ScanResult(
            path=f"x{nummer}.exe", detected_type="pe", risk_level=RiskLevel.YELLOW,
            score=30, capa_capabilities=list(eintraege),
        )
        panel = CapabilityPanel()
        qtbot.addWidget(panel)
        panel.show_result(r)  # darf nie werfen
        laengen = [len(w.text()) for w in panel.findChildren(QLabel)]
        assert laengen, f"Fall {nummer} rendert gar nichts"
        assert max(laengen) < 3000, f"Fall {nummer}: {max(laengen)} Zeichen in einem Label"


def test_capability_tab_absent_when_capa_reports_nothing(qtbot):
    """Ohne Faehigkeiten kein Reiter — auch wenn capa gelaufen ist."""
    from malaz.gui.main_window import MainWindow
    from malaz.models import RiskLevel, ScanResult

    window = MainWindow()
    qtbot.addWidget(window)
    # Ein Zustand, den die Pipeline NIE erzeugt: gelaufen, keine Liste.
    r = ScanResult(path="a.exe", detected_type="pe", risk_level=RiskLevel.GREEN, score=0)
    window._on_result(r)
    window.table.setCurrentItem(window.table.topLevelItem(0))
    assert window.detail_view._btn_tab_capa.isHidden()


def test_capability_tab_sits_before_the_technical_tab(qtbot):
    """Die Faehigkeiten sind das Lesbare und gehoeren VOR das Technische.

    Der Reiter wurde per addTab angehaengt und landete damit HINTER
    "Technische Details" — waehrend der E-Mail-Reiter mit insertTab(1, ...)
    bewusst davor steht ("das Fachliche steht hinten, das Lesbare vorn").
    Dieselbe Begruendung gilt hier: "was kann dieses Programm" ist die Frage,
    die ein Laie stellt.
    """
    from malaz.gui.main_window import MainWindow
    from malaz.models import RiskLevel, ScanResult

    window = MainWindow()
    qtbot.addWidget(window)
    r = ScanResult(
        path="a.exe", detected_type="pe", risk_level=RiskLevel.YELLOW, score=30,
        capa_capabilities=[{"name": "create process", "namespace": "host-interaction"}],
    )
    window._on_result(r)
    window.table.setCurrentItem(window.table.topLevelItem(0))
    assert not window.detail_view._btn_tab_capa.isHidden()
    assert window.detail_view._btn_tab_capa.text() == "Fähigkeiten (1)"


def test_missing_signatures_are_recognised(tmp_path, monkeypatch):
    """Das pip-capa scheitert an fehlenden SIGNATUREN, nicht an Regeln.

    Gemessen mit installiertem flare-capa 9.4.0 ohne Signaturordner:

        ERROR    capa: Using default signature path, but it doesn't exist.
                 Please install the signatures first
        Unexpected exception raised: <class 'OSError'>

    Also KEIN Returncode 10 und KEIN Regel-Wortlaut — die vorhandenen Marker
    griffen nicht, und der Nutzer bekam statt des hilfreichen Hinweises ein
    "capa-Ausgabe nicht lesbar". Genau der wahrscheinlichste
    Installationsweg (pip) traf das.
    """
    from malaz.analysis.capa import _missing_rules, _missing_rules_hint

    meldung = (
        "ERROR    capa: Using default signature path, but it doesn't exist.\n"
        "         Please install the signatures first:"
    )
    assert _missing_rules(meldung), "die Signatur-Meldung wird nicht erkannt"
    assert "signatur" in _missing_rules_hint().lower(), (
        "der Hinweis nennt die Signaturen nicht"
    )


def test_capa_is_opt_in_because_it_is_slow(qtbot, tmp_path):
    """capa laeuft NICHT von selbst — gemessen ist es zu langsam dafuer.

    ECHTE Messung mit dem Standalone-capa 9.4.0 auf harmlosen, alltaeglichen
    Bibliotheken:

        libffi-8.dll     5 Faehigkeiten    23 s
        msvcp140.dll    18 Faehigkeiten   139 s
        libssl-3.dll     8 Faehigkeiten   302 s
        libcrypto-3.dll  -                Timeout nach 600 s

    Mit CAPA_ENABLED = True und einem Zeitlimit von 120 s kostet JEDE
    gepruefte .exe/.dll bis zu zwei Minuten — ein Ordner mit 50 Programmen
    waere ueber eine Stunde. Fuer ein Werkzeug, das der Nutzer nebenbei
    laufen laesst, ist das unbrauchbar.

    Dazu passt die Zahl der Treffer: 5 bis 18 Faehigkeiten auf voellig
    harmlosen Bibliotheken. Beides zusammen heisst: einschalten ja, aber
    bewusst.
    """
    from malaz import config

    assert config.CAPA_ENABLED is False, (
        "capa laeuft von selbst — gemessen 23 bis 600+ Sekunden je Datei"
    )
    # Und der Hinweis muss sagen, wie man es einschaltet.
    from malaz.analysis.capa import _capa_disabled_hint

    hinweis = _capa_disabled_hint().lower()
    assert "capa_enabled" in hinweis, hinweis
    assert "langsam" in hinweis or "sekunden" in hinweis, hinweis


def test_the_gui_checkbox_reaches_the_stage(qtbot):
    """Der Haken muss die Stufe WIRKLICH erreichen — sonst ist sie tot.

    CAPA_ENABLED ist per Default aus (gemessen zu langsam). Ohne einen Haken
    in der Oberflaeche waere der ganze Faehigkeiten-Reiter im ausgelieferten
    Programm unerreichbar: der Nutzer muesste config.py von Hand editieren.
    """
    from malaz import config
    from malaz.gui.main_window import MainWindow
    from malaz.gui.settings import app_settings

    # Ueber die Naht, nicht direkt: sonst schreibt der Test in die Registry
    # des Entwicklers, waehrend die App daneben gekapselt ist.
    app_settings().setValue("capa_enabled", False)
    window = MainWindow()
    qtbot.addWidget(window)

    assert window.chk_capa.isChecked() is False
    assert config.CAPA_ENABLED is False, "die gespeicherte Einstellung greift nicht"

    window.chk_capa.setChecked(True)
    assert config.CAPA_ENABLED is True, "der Haken erreicht die Stufe nicht"
    assert app_settings().value("capa_enabled", False, bool) is True

    window.chk_capa.setChecked(False)
    assert config.CAPA_ENABLED is False
