"""Tests für DIE- und PE-Pipeline-Bereiche, die bisher ungetestet waren."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from malaz.analysis.die import _finding_label as finding_label
from malaz.analysis.die import finding_risk
from malaz.models import AnalysisContext


def _find_pyd() -> Path | None:
    # Portabel: DLLs-Verzeichnis des Basis-Interpreters (auch aus dem venv),
    # sonst irgendein _*.pyd im venv-site-packages.
    base = Path(getattr(sys, "base_exec_prefix", sys.exec_prefix))
    candidates = sorted((base / "DLLs").glob("_*.pyd"))
    if candidates:
        return candidates[0]
    sp = Path(sys.executable).resolve().parent.parent / "Lib" / "site-packages"
    found = sorted(sp.glob("*.pyd"))
    return found[0] if found else None


PYD = _find_pyd() or Path(r"C:/Program Files/Python312/DLLs/_bz2.pyd")


def _pe_ctx() -> AnalysisContext:
    data = PYD.read_bytes()
    return AnalysisContext(path=PYD.name, data=data, detected_type="pe",
                           size=len(data), depth=0)


# -- die.py ------------------------------------------------------------------ #

def test_finding_label_formats_type_name_version():
    assert finding_label({"type": "packer", "name": "UPX"}) == "packer: UPX"
    assert (
        finding_label({"type": "compiler", "name": "MSVC", "version": "v19"})
        == "compiler: MSVC: v19"
    )


def test_finding_risk_weights():
    assert finding_risk({"type": "packer"}) == 30
    assert finding_risk({"type": "protector"}) == 30
    assert finding_risk({"type": "cryptor"}) == 30
    assert finding_risk({"type": "obfuscator"}) == 30
    assert finding_risk({"type": "installer"}) == 10  # haeufig gutartig
    assert finding_risk({"type": "linker"}) == 0      # reiner Fingerabdruck
    assert finding_risk({}) == 0


# -- pe_pipeline: echte PE-Analyse über ein mitgeliefertes .pyd --------------- #

@pytest.mark.skipif(not PYD.exists(), reason="keine _bz2.pyd im venv")
class TestRealPe:
    def _inds(self):
        from malaz.pipelines.pe_pipeline import PePipeline

        return PePipeline().analyze(_pe_ctx())

    def test_header_indicator_present(self):
        ids = {i.rule_id for i in self._inds()}
        assert "PE_HEADER" in ids

    def test_mitigations_reported(self):
        # Deterministisch: DllCharacteristics selbst parsen und mit dem
        # Indikator abgleichen (statt einer Tautologie).
        import pefile

        pe = pefile.PE(data=PYD.read_bytes(), fast_load=True)
        chars = pe.OPTIONAL_HEADER.DllCharacteristics
        pe.close()
        # Kalibrierte Regel: nur ASLR/DEP zählen als Schwäche (CFG fehlt bei
        # 28% legitimer Software und ist daher nur ein Hinweis).
        dynamic, nx = 0x0040, 0x0100
        expect_weak = not (chars & dynamic and chars & nx)
        ids = {i.rule_id for i in self._inds()}
        assert ("PE_WEAK_MITIGATIONS" in ids) == expect_weak
        assert "PE_HEADER" in ids

    def test_imports_scanned(self):
        ids = {i.rule_id for i in self._inds()}
        assert "PE_IMPHASH" in ids or "PE_NO_IMPORTS" in ids


# -- pe_pipeline: Authenticode ------------------------------------------------ #

def _authenticode(monkeypatch, status, available=True):
    import malaz.pipelines.pe_pipeline as module

    monkeypatch.setattr(module, "which_absolute",
                        lambda name: "pwsh" if available else None)
    monkeypatch.setattr(
        module, "run_tool",
        lambda *a, **k: (0, f'{{"Status": "{status}", "Message": "m"}}'.encode(), b""),
    )
    return module


def test_authenticode_valid_signature(monkeypatch, tmp_path):
    module = _authenticode(monkeypatch, "Valid")
    sample = tmp_path / "x.exe"
    sample.write_bytes(b"MZ" * 4)
    ctx = AnalysisContext(path=sample, data=sample.read_bytes(),
                          detected_type="pe", size=8, depth=0)
    inds = module.PePipeline()._authenticode(ctx)
    assert any(i.rule_id == "PE_SIGNED" for i in inds)


def test_authenticode_missing_powershell_skips(monkeypatch, tmp_path):
    module = _authenticode(monkeypatch, "Valid", available=False)
    sample = tmp_path / "x.exe"
    sample.write_bytes(b"MZ" * 4)
    ctx = AnalysisContext(path=sample, data=b"MZ" * 4, detected_type="pe",
                          size=8, depth=0)
    assert module.PePipeline()._authenticode(ctx) == []


# -- pe_pipeline: DIE-Stage ---------------------------------------------------- #

def test_die_findings_integrated(monkeypatch, tmp_path):
    import malaz.pipelines.pe_pipeline as module

    sample = tmp_path / "packed.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 60)
    ctx = AnalysisContext(path=sample, data=sample.read_bytes(),
                          detected_type="pe", size=64, depth=0)

    class FakeDie:
        available = True

        def scan_path(self, path):
            from malaz.analysis.die import DieResult

            return DieResult(
                scanned=True,
                findings=[{"type": "packer", "name": "UPX"}],
                detail="packer: UPX",
            )

    monkeypatch.setattr(module, "DieScanner", FakeDie)
    inds = module.PePipeline()._die(ctx)
    assert any("packer: UPX" in (i.title + i.detail) for i in inds)
    hit = next(i for i in inds if "UPX" in i.title + i.detail)
    assert hit.severity.name == "HIGH" and hit.weight == 30


# -- Suffix-Härtung von _materialize (PE/DIE) --------------------------------- #

def test_materialize_sanitizes_hostile_suffix():
    """Ein untreuer Member-Name darf mkstemp nicht sprengen.

    Der Suffix stammt bei Archiv-Membern aus dem Member-Namen. Ungekürzt
    schiebt er den Temp-Pfad über das Windows-Limit von 260 Zeichen; mkstemp
    wirft dann OSError und die DIE-Stufe fällt still aus (der Fehlerpfad
    erzeugt DIE_ERROR mit Gewicht 0). Gemessen kostete das ein gepacktes
    Sample 30 Punkte: Score 50/RED -> 20/YELLOW.
    """
    from malaz.pipelines.pe_pipeline import PePipeline

    pipe = PePipeline()
    long_name = "sample." + "a" * 260
    ctx = AnalysisContext(
        path=Path(long_name), data=b"MZ" + b"\x00" * 64,
        detected_type="pe", size=68,
    )
    with pipe._materialize(ctx) as tmp:
        assert len(Path(tmp).suffix) <= 17, "Suffix muss gekürzt sein"
        assert Path(tmp).exists()


def test_materialize_rejects_separators_in_suffix():
    from malaz.pipelines.pe_pipeline import PePipeline

    pipe = PePipeline()
    ctx = AnalysisContext(
        path=Path('bo"es<>.d<oc|x'), data=b"MZ", detected_type="pe", size=2,
    )
    with pipe._materialize(ctx) as tmp:
        name = Path(tmp).name
        assert all(ch not in name for ch in '<>|"')


def test_long_member_name_keeps_full_pe_verdict(monkeypatch):
    """Ende-zu-Ende: der lange Name darf die Erkennung nicht verkürzen.

    Zuvor verschwand die DIE-Stufe komplett, weil mkstemp scheiterte — ein
    gepacktes PE verlor dadurch 30 Punkte. Jetzt muss der DIE-Indikator auch
    bei einem 260-Zeichen-Member-Namen ankommen.
    """
    from malaz.analysis.die import DieResult
    from malaz.pipelines import pe_pipeline

    class _FakeDie:
        available = True

        def scan_path(self, path):
            assert Path(path).exists(), "Temp-Datei muss angelegt worden sein"
            return DieResult(
                scanned=True,
                findings=[{"type": "packer", "name": "UPX", "version": "4.2"}],
            )

    monkeypatch.setattr(pe_pipeline, "DieScanner", _FakeDie)

    from malaz.pipelines.pe_pipeline import PePipeline

    data = PYD.read_bytes()
    ctx = AnalysisContext(
        path=Path("sample." + "a" * 260), data=data,
        detected_type="pe", size=len(data),
    )
    ids = {i.rule_id: i.weight for i in PePipeline().analyze(ctx)}
    assert "DIE_PACKER" in ids, f"DIE-Stufe fiel aus: {sorted(ids)}"
    assert ids["DIE_PACKER"] == 30
