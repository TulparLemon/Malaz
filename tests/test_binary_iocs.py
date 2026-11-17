"""Adressen in den ROHBYTES: core/binary_iocs.py und seine Einbindung.

Die Lücke, die diese Tests absichern: die IOC-Prüfung der Generic-Pipeline lief
nur für Texttypen. Ein PE, ein PDF, ein OLE-Container, ein Bild oder ein Archiv
wurde gar nicht auf Serveradressen geprüft — dabei steht die C2-Adresse genau
dort (Datensektion, XMP-Metadaten, Makro-Stream, angehängte Nutzlast).

Beissprobe ist ``test_namespace_urls_are_not_reported``: die Sperrliste wird im
Test geleert, und genau dann MUSS die Namespace-URL gemeldet werden. Wird der
Filter aus dem Modul entfernt, ist der Test rot.

Alle Tests, die "kein Blocklist-Treffer" behaupten, zeigen die drei Listen
zuerst auf nicht existierende Dateien (``_no_blocklists``) — sonst hinge das
Ergebnis vom Import-Stand des Rechners ab.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from malaz import config
from malaz.core import binary_iocs
from malaz.core.binary_iocs import extract_binary_iocs, split_blocked_iocs
from malaz.core.url_reputation import url_hash
from malaz.models import AnalysisContext, Severity
from malaz.pipelines.generic_pipeline import GenericPipeline

# Eine echte C2-Adresse sieht in einem PE so aus: Zeichenkette in einer
# Datensektion, nicht ausgeführt.
_C2_URL = b"http://c2-host.top/gate.php"


def _pe_like(payload: bytes = b"") -> bytes:
    """Minimaler, strukturell gültiger PE-artiger Bytestrom plus Nutzlast.

    ``_pe_at`` verlangt MZ, einen e_lfanew-Zeiger auf die PE-Signatur und
    mindestens 0x40 Bytes Kopf — deshalb wird der Kopf hier exakt so gebaut.
    """
    head = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x80) + b"\x00" * 0x40
    return head + b"PE\x00\x00" + b"\x00" * 0x200 + payload


def _ctx(data: bytes, name: str = "probe.bin", ftype: str = "pe") -> AnalysisContext:
    return AnalysisContext(path=Path(name), data=data, detected_type=ftype, size=len(data))


def _ids(indicators) -> list[str]:
    return [i.rule_id for i in indicators]


def _no_blocklists(tmp_path: Path, monkeypatch) -> None:
    """Alle drei lokalen Listen auf fehlende Dateien zeigen."""
    for name in ("DOMAIN_BLOCKLIST_FILE", "IP_BLOCKLIST_FILE", "URL_BLOCKLIST_FILE"):
        monkeypatch.setattr(config, name, tmp_path / f"fehlt-{name}.txt")


def _write_blocklists(
    tmp_path: Path,
    monkeypatch,
    *,
    domains: tuple[str, ...] = (),
    nets: tuple[str, ...] = (),
    urls: tuple[str, ...] = (),
) -> None:
    """Die drei lokalen Listen als echte Dateien anlegen und einklinken."""
    domain_file = tmp_path / "domains.txt"
    domain_file.write_text("\n".join(domains), encoding="utf-8")
    net_file = tmp_path / "netze.txt"
    net_file.write_text("\n".join(nets), encoding="utf-8")
    url_file = tmp_path / "urls.sha256"
    url_file.write_text("\n".join(url_hash(u) for u in urls), encoding="utf-8")
    monkeypatch.setattr(config, "DOMAIN_BLOCKLIST_FILE", domain_file)
    monkeypatch.setattr(config, "IP_BLOCKLIST_FILE", net_file)
    monkeypatch.setattr(config, "URL_BLOCKLIST_FILE", url_file)


# -- Extraktion aus Rohbytes ------------------------------------------------- #


def test_extracts_every_address_kind_from_raw_bytes():
    payload = (
        _C2_URL
        + b"\x00" * 4
        + b"203.0.113.9"
        + b"\x00" * 4
        + b"beacon.evil-c2.xyz"
        + b"\x00" * 4
        + b"2001:db8::1"
    )
    hits = extract_binary_iocs(_pe_like(payload))
    assert ("url", "http://c2-host.top/gate.php") in hits
    assert ("ipv4", "203.0.113.9") in hits
    assert ("domain", "beacon.evil-c2.xyz") in hits
    assert ("ipv6", "2001:db8::1") in hits


def test_namespace_urls_are_not_reported(monkeypatch):
    """Namespace-URLs sind keine C2-Adressen — Beissprobe.

    Mit geleerter Sperrliste MUSS dieselbe URL gemeldet werden: das belegt,
    dass wirklich der Filter sie unterdrückt und nicht etwa das Muster sie
    verfehlt.
    """
    namespaces = (
        b"http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        b"http://schemas.openxmlformats.org/wordprocessingml/2006/main"
        b"http://www.w3.org/1999/02/22-rdf-syntax-ns#"
        b"http://ns.adobe.com/xap/1.0/"
        b"http://purl.org/dc/elements/1.1/"
    )
    data = _pe_like(namespaces)
    assert extract_binary_iocs(data) == []

    monkeypatch.setattr(binary_iocs, "NAMESPACE_HOSTS", ())
    kinds = {kind for kind, _value in extract_binary_iocs(data)}
    assert "url" in kinds


def test_ipv4_needs_valid_octets():
    # "1.2.3.4.5" (Versionsnummer) und "999.1.1.1" sind keine Adressen; ohne die
    # Oktett-Grenze träfe das Muster mitten in der ersten Angabe.
    assert extract_binary_iocs(b"version 1.2.3.4.5 released") == []
    assert extract_binary_iocs(b"999.1.1.1") == []
    assert extract_binary_iocs(b"host 10.0.0.7 here") == [("ipv4", "10.0.0.7")]


def test_ipv6_candidates_are_validated():
    # Eine Uhrzeit und die nichtssagende Adresse sind keine IOCs; die
    # Kompressionsform muss aber durchkommen.
    assert extract_binary_iocs(b"time 12:34:56 ok") == []
    assert extract_binary_iocs(b"bind ::") == []
    assert extract_binary_iocs(b"peer 2001:db8::1 up") == [("ipv6", "2001:db8::1")]


def test_url_host_is_not_reported_again_as_domain():
    hits = extract_binary_iocs(b"GET " + _C2_URL + b" HTTP/1.1")
    assert hits == [("url", "http://c2-host.top/gate.php")]


def test_url_keeps_its_own_scheme_and_drops_list_punctuation():
    # Das Komma stammt aus der Aufzählung, nicht aus der Adresse — sonst
    # stünde es im Befund und der Hash-Vergleich mit der URL-Liste schlüge fehl.
    hits = extract_binary_iocs(b"see http://a-host.top/x.php, then http://b-host.top/y")
    assert hits == [
        ("url", "http://a-host.top/x.php"),
        ("url", "http://b-host.top/y"),
    ]


def test_hit_cap_is_enforced(monkeypatch):
    monkeypatch.setattr(config, "BINARY_IOC_MAX_HITS", 5)
    data = b" ".join(b"http://host-%d.top/x" % n for n in range(20))
    hits = extract_binary_iocs(data)
    assert sum(1 for kind, _value in hits if kind == "url") == 5
    assert (binary_iocs.IOC_CAP, "url") in hits
    assert binary_iocs.capped_ioc_kinds(hits) == ("url",)


def test_url_cap_does_not_hide_ip_and_domain_checks(monkeypatch):
    """BUG-029/SEC-021: 200 decoy URLs must not disable the C2 domain check."""
    monkeypatch.setattr(config, "BINARY_IOC_MAX_HITS", 3)
    decoys = b" ".join(b"http://host-%d.top/x" % n for n in range(20))
    hits = extract_binary_iocs(decoys + b" evil-c2-host.top 203.0.113.9")
    assert sum(1 for kind, _value in hits if kind == "url") == 3
    assert ("domain", "evil-c2-host.top") in hits
    assert ("ipv4", "203.0.113.9") in hits
    assert binary_iocs.capped_ioc_kinds(hits) == ("url",)

    blocked, plain, unavailable = split_blocked_iocs(hits)
    assert unavailable == []
    assert not any(kind == binary_iocs.IOC_CAP for kind, _ in blocked + plain)


def test_url_cap_still_reaches_the_blocklist(tmp_path, monkeypatch):
    """SEC-021: die C2-Domain muss trotz vollem URL-Deckel geprüft werden."""
    _write_blocklists(tmp_path, monkeypatch, domains=("evil-c2-host.top",))
    monkeypatch.setattr(config, "BINARY_IOC_MAX_HITS", 3)
    decoys = b" ".join(b"http://host-%d.top/x" % n for n in range(20))
    hits = extract_binary_iocs(decoys + b" evil-c2-host.top")
    blocked, _plain, unavailable = split_blocked_iocs(hits)
    assert ("domain", "evil-c2-host.top") in blocked
    assert unavailable == []


def test_stream_scans_the_final_tail(monkeypatch):
    """BUG-028: overlap was cut off by the in-memory scan cap, losing EOF IOCs."""
    monkeypatch.setattr(config, "BINARY_IOC_SCAN_SIZE", 4096)
    url = b"http://tail-host.top/x"
    data = b"\x00" * (2 * 4096 - len(url)) + url

    class _Source:
        def iter_chunks(self, size, deadline=None):
            for start in range(0, len(data), size):
                yield data[start:start + size]

    hits = binary_iocs.extract_binary_iocs_stream(_Source(), overlap=512)
    assert ("url", url.decode()) in hits

    # overlap=0 must not carry the whole previous chunk forward.
    hits = binary_iocs.extract_binary_iocs_stream(
        _Source(), chunk_size=1024, overlap=0
    )
    assert ("url", url.decode()) in hits


def test_stream_cap_marker_is_returned(monkeypatch):
    """A capped stream reports it instead of silently truncating."""
    monkeypatch.setattr(config, "BINARY_IOC_SCAN_SIZE", 4096)
    monkeypatch.setattr(config, "BINARY_IOC_MAX_HITS", 2)
    urls = b" ".join(b"http://host-%d.top/x" % n for n in range(10))
    data = urls + b" evil-c2-host.top"

    class _Source:
        def iter_chunks(self, size, deadline=None):
            yield data

    hits = binary_iocs.extract_binary_iocs_stream(_Source(), overlap=0)
    assert binary_iocs.capped_ioc_kinds(hits) == ("url",)
    assert ("domain", "evil-c2-host.top") in hits


def test_scan_size_cap_is_enforced(monkeypatch):
    monkeypatch.setattr(config, "BINARY_IOC_SCAN_SIZE", 64)
    assert extract_binary_iocs(b"x" * 8 + _C2_URL) == [
        ("url", "http://c2-host.top/gate.php")
    ]
    assert extract_binary_iocs(b"x" * 64 + _C2_URL) == []


def test_empty_input_is_not_an_error():
    assert extract_binary_iocs(b"") == []


# -- Einordnung gegen die lokalen Listen ------------------------------------- #


def test_split_uses_domain_ip_and_url_lists(tmp_path, monkeypatch):
    _write_blocklists(
        tmp_path,
        monkeypatch,
        domains=("blocked-host.top",),
        nets=("203.0.113.0/24",),
        urls=("http://listed-url.top/payload",),
    )
    hits = [
        ("url", "http://listed-url.top/payload"),
        ("url", "http://blocked-host.top/gate.php"),  # Host auf der Domain-Liste
        ("url", "http://clean-host.top/x"),
        ("ipv4", "203.0.113.9"),
        ("ipv4", "198.51.100.4"),
        ("ipv6", "2001:db8::1"),
        ("domain", "mail.blocked-host.top"),  # Unterdomain
        ("domain", "clean-host.top"),
    ]
    blocked, plain, unavailable = split_blocked_iocs(hits)
    assert blocked == [
        ("url", "http://listed-url.top/payload"),
        ("url", "http://blocked-host.top/gate.php"),
        ("ipv4", "203.0.113.9"),
        ("domain", "mail.blocked-host.top"),
    ]
    assert plain == [
        ("url", "http://clean-host.top/x"),
        ("ipv4", "198.51.100.4"),
        ("ipv6", "2001:db8::1"),
        ("domain", "clean-host.top"),
    ]
    assert unavailable == []


def test_split_without_any_list_reports_nothing_as_blocked(tmp_path, monkeypatch):
    """Fehlende Listen sind der Normalfall nach einer Neuinstallation."""
    _no_blocklists(tmp_path, monkeypatch)
    blocked, plain, unavailable = split_blocked_iocs([("domain", "c2-host.top")])
    assert blocked == []
    assert plain == [("domain", "c2-host.top")]
    assert unavailable == []


# -- Einbindung in die Generic-Pipeline -------------------------------------- #


@pytest.mark.parametrize("ftype", ["pe", "elf", "macho", "pdf", "ole", "png", "zip"])
def test_binary_formats_get_the_address_check(tmp_path, monkeypatch, ftype):
    _no_blocklists(tmp_path, monkeypatch)
    inds = GenericPipeline().analyze(
        _ctx(_pe_like(_C2_URL), name="probe.bin", ftype=ftype)
    )
    hit = [i for i in inds if i.rule_id == "BINARY_IOC"]
    assert hit, f"{ftype}: keine Adressprüfung"
    assert hit[0].severity == Severity.INFO
    assert hit[0].weight == 0, "eine unbekannte Adresse darf die Note nicht treiben"
    assert "c2-host.top" in hit[0].detail
    assert "GEN_IOC" not in _ids(inds), "der Textpfad darf hier nicht mitlaufen"


def test_text_formats_keep_the_text_path_only(tmp_path, monkeypatch):
    """Kein Doppellauf: GEN_IOC für Text, BINARY_IOC für alles andere."""
    _no_blocklists(tmp_path, monkeypatch)
    inds = GenericPipeline().analyze(
        _ctx(b"see " + _C2_URL + b" now", name="probe.txt", ftype="text")
    )
    assert "GEN_IOC" in _ids(inds)
    assert "BINARY_IOC" not in _ids(inds)


def test_lnk_is_left_to_the_lnk_stage(tmp_path, monkeypatch):
    """Der LNK-Zweig wertet seine Strings selbst aus — kein zweiter Befund."""
    _no_blocklists(tmp_path, monkeypatch)
    inds = GenericPipeline().analyze(_ctx(_pe_like(_C2_URL), name="x.lnk", ftype="lnk"))
    assert "BINARY_IOC" not in _ids(inds)


def test_blocklisted_address_in_a_binary_is_a_high_finding(tmp_path, monkeypatch):
    _write_blocklists(tmp_path, monkeypatch, domains=("c2-host.top",))
    inds = GenericPipeline().analyze(_ctx(_pe_like(_C2_URL), name="probe.bin", ftype="pe"))
    blocked = [i for i in inds if i.rule_id == "BINARY_IOC_BLOCKED"]
    assert blocked
    assert blocked[0].severity == Severity.HIGH
    assert blocked[0].weight == 30
    assert "c2-host.top" in blocked[0].detail
    assert "BINARY_IOC" not in _ids(inds), "derselbe Treffer nicht zweimal melden"


def test_cap_marker_reaches_the_report(tmp_path, monkeypatch):
    """The cap is visible in the result, not just in the extractor."""
    _no_blocklists(tmp_path, monkeypatch)
    monkeypatch.setattr(config, "BINARY_IOC_MAX_HITS", 1)
    data = _pe_like(
        b"http://a-host.top/x http://b-host.top/y evil-c2-host.top"
    )
    inds = GenericPipeline().analyze(_ctx(data, name="probe.bin", ftype="pe"))
    capped = [i for i in inds if i.rule_id == "BINARY_IOC_CAPPED"]
    assert capped, "der Deckel muss im Befund sichtbar sein"
    assert capped[0].weight == 0
    assert "URLs" in capped[0].detail
    assert "NICHT" in capped[0].detail


def test_rule_ids_have_title_and_severity():
    """Jede neue Regel braucht Titel UND Severity in den Tabellen.

    Ohne Eintrag fiele der Befund still auf einen Vorgabewert zurück — dieselbe
    Falle, die die Mail-Pipeline mit einem eigenen Test absichert.
    """
    from malaz.pipelines import generic_pipeline as gp

    for rule_id in ("BINARY_IOC", "BINARY_IOC_BLOCKED", "BINARY_IOC_CAPPED"):
        assert rule_id in gp._BINARY_IOC_LEVELS, rule_id
        assert rule_id in gp._BINARY_IOC_TITLES, rule_id
        assert gp._BINARY_IOC_TITLES[rule_id].strip()
    assert gp._BINARY_IOC_LEVELS["BINARY_IOC"] == (Severity.INFO, 0)
    assert gp._BINARY_IOC_LEVELS["BINARY_IOC_BLOCKED"] == (Severity.HIGH, 30)
    assert gp._BINARY_IOC_LEVELS["BINARY_IOC_CAPPED"] == (Severity.INFO, 0)


def test_namespace_filter_is_at_least_as_strict_as_the_text_path():
    """Die Sperrliste deckt alles ab, was der Textpfad als harmlos führt.

    Beide Wege müssen dieselbe Adresse gleich beurteilen: was in einem Text als
    harmlos gilt, darf in einem PE nicht plötzlich als Serveradresse auftauchen.
    """
    from malaz.pipelines.generic_pipeline import _BENIGN_HOSTS

    fehlend = [host for host in _BENIGN_HOSTS if host not in binary_iocs.NAMESPACE_HOSTS]
    assert not fehlend, f"nur im Textpfad als harmlos geführt: {fehlend}"


def test_yara_ausfall_wird_in_der_pipeline_sichtbar(monkeypatch, tmp_path):
    """BEISSPROBE fuer YARA_SCAN_ERROR — am Engine-Objekt allein genuegt nicht.

    ``test_yara`` prueft ``e.scan_error``. Das ist die Ursache, nicht die
    Wirkung: der Nutzer sieht den BEFUND. Faellt die Weitergabe an die
    Pipeline weg, bleibt ein nicht geprueftes Ergebnis wie ein sauberes.
    """
    _no_blocklists(tmp_path, monkeypatch)
    from malaz.core.yara_engine import YaraEngine

    class _Werfend:
        def match(self, **_k):
            raise RuntimeError("timeout nach 30 Sekunden")

    engine = YaraEngine.__new__(YaraEngine)
    engine._rules = [_Werfend()]
    engine._disabled = set()
    engine.load_error = None
    type(engine).available = property(lambda self: True)
    try:
        pipe = GenericPipeline()
        monkeypatch.setattr(pipe, "yara", engine, raising=False)
        inds = pipe.analyze(_ctx(b"irgendein inhalt", name="probe.bin", ftype="pe"))
    finally:
        del type(engine).available

    treffer = [i for i in inds if i.rule_id == "YARA_SCAN_ERROR"]
    assert treffer, "der YARA-Ausfall erreichte den Befund nicht"
    assert treffer[0].weight == 25
    assert "NICHT ausgewertet" in treffer[0].detail
