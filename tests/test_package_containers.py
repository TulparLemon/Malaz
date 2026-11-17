"""Regressions­tests für Linux-Paketcontainer (Feld-Report 25.08.2026).

Live-Befunde auf einem Analysten-Rechner:
1. Legitime .deb/.rpm (sysdig, Cynet) wurden als "unknown" mit Entropie ~8
   als GEFAEHRLICH (ROT 50-70) eingestuft — Paketarchive sind aber IMMER
   komprimiert, das ist Struktur, kein Verdacht.
2. Komprimierte Daten matchten die Domain-Regex mit Muell wie "q.RU" oder
   "p0g9.Pw" (GEN_IOC-False-Positives aus Zufallsbytes).
"""

import os

from malaz.analysis.clamav import ClamAVScanner
from malaz.analysis.windows_av import WindowsDefenderScanner
from malaz.core.dispatcher import Dispatcher
from malaz.core.magic import detect


def _dispatcher():
    return Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )


def _ids(result):
    return {i.rule_id for i in result.all_indicators()}


_RPM_MAGIC = b"\xed\xab\xee\xdb"
_DEB_MAGIC = b"!<arch>\ndebian-binary"


def test_magic_detects_package_containers():
    assert detect(_RPM_MAGIC + b"\x00" * 64).type == "rpm"
    assert detect(_DEB_MAGIC + b"\x00" * 64).type == "deb"


def test_package_entropy_is_not_suspicious(tmp_path):
    # Komprimierter Inhalt: reale Zufallsdaten (Entropie ~8). Frueher:
    # GEN_ENTROPY High -> ROT. Jetzt: Paketcontainer, keine Entropie-Anzeige.
    target = tmp_path / "sysdig.rpm"
    target.write_bytes(_RPM_MAGIC + os.urandom(400_000))
    result = _dispatcher().scan_path(target)
    assert "GEN_ENTROPY" not in _ids(result)


def test_packages_route_to_sevenzip_extraction(tmp_path, monkeypatch):
    # Ohne 7-Zip-Binary muss der ehrliche ARCH_7Z_MISSING-Hinweis (GELB)
    # entstehen — das beweist zugleich, dass deb/rpm in die 7z-Extraktion
    # geroutet werden statt als Blob durchzulaufen.
    from malaz.core import sevenzip as sevenzip_module

    monkeypatch.setattr(sevenzip_module, "find_7z_binary", lambda: None)
    target = tmp_path / "cyneteps.deb"
    target.write_bytes(_DEB_MAGIC + os.urandom(10_000))
    result = _dispatcher().scan_path(target)
    ids = _ids(result)
    assert "ARCH_7Z_MISSING" in ids
    from malaz.models import RiskLevel

    assert result.risk_level >= RiskLevel.YELLOW  # Inhalt ungeprüft != sauber


def test_ioc_extraction_skips_compressed_noise(tmp_path):
    # Hochentropischer Blob mit Zufalls-"Domain"-Fragmenten: keine IOCs.
    target = tmp_path / "blob.bin"
    target.write_bytes(os.urandom(300_000) + b" q.RU p0g9.Pw V.cn ")
    result = _dispatcher().scan_path(target)
    assert "GEN_IOC" not in _ids(result)


def test_ioc_extraction_keeps_textual_findings(tmp_path):
    # Textdatei mit echter IP bleibt ein Low-Fund (kein Rückschritt).
    target = tmp_path / "status.csv"
    target.write_bytes(b"geraet,ip\nswitch-a,10.0.0.21\n" * 50)
    result = _dispatcher().scan_path(target)
    assert "GEN_IOC" in _ids(result)
