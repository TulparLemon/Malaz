"""Tests for structural PDF /URI link analysis and honest GREEN advice (Spec 006 / PDF-001)."""

from __future__ import annotations

import io
from pathlib import Path

import pikepdf
import pytest

from malaz import config
from malaz.analysis.clamav import ClamAVScanner
from malaz.analysis.windows_av import WindowsDefenderScanner
from malaz.core.dispatcher import Dispatcher
from malaz.core.url_reputation import url_hash
from malaz.models import AnalysisContext, RiskLevel
from malaz.pipelines.pdf_pipeline import PdfPipeline, _decode_pdf_uri
from malaz.reporting.html_report import generate_report


def _make_uri_pdf(
    uris: list[bytes | str],
    *,
    object_stream: bool = False,
) -> bytes:
    """Create a real valid PDF with /Annots -> /A -> /URI entries."""
    pdf = pikepdf.new()
    annots = []
    for raw in uris:
        uri_obj = pikepdf.String(raw) if isinstance(raw, (bytes, str)) else raw
        annot = pdf.make_indirect(
            pikepdf.Dictionary(
                Type=pikepdf.Name.Annot,
                Subtype=pikepdf.Name.Link,
                Rect=[0, 0, 100, 20],
                A=pikepdf.Dictionary(
                    Type=pikepdf.Name.Action,
                    S=pikepdf.Name.URI,
                    URI=uri_obj,
                ),
            )
        )
        annots.append(annot)
    pdf.pages.append(
        pikepdf.Page(
            pikepdf.Dictionary(
                Type=pikepdf.Name.Page,
                MediaBox=[0, 0, 612, 792],
                Annots=pikepdf.Array(annots),
            )
        )
    )
    buf = io.BytesIO()
    if object_stream:
        pdf.save(
            buf,
            object_stream_mode=pikepdf.ObjectStreamMode.generate,
            compress_streams=True,
            deterministic_id=True,
        )
    else:
        pdf.save(
            buf,
            object_stream_mode=pikepdf.ObjectStreamMode.disable,
            compress_streams=False,
            deterministic_id=True,
        )
    return buf.getvalue()


def _scan_bytes(tmp_path: Path, data: bytes, name: str = "sample.pdf"):
    path = tmp_path / name
    path.write_bytes(data)
    dispatcher = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    return dispatcher.scan_path(path)


@pytest.fixture
def isolated_blocklists(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Isolate all local blocklists into tmp_path so host feeds never interfere."""
    bl_dir = tmp_path / "blocklists"
    bl_dir.mkdir()
    monkeypatch.setattr(config, "DOMAIN_BLOCKLIST_FILE", bl_dir / "domains.txt")
    monkeypatch.setattr(config, "IP_BLOCKLIST_FILE", bl_dir / "netze.txt")
    monkeypatch.setattr(config, "URL_BLOCKLIST_FILE", bl_dir / "urls.sha256")
    monkeypatch.setattr(config, "USER_HASH_BLOCKLIST_FILE", bl_dir / "hashes.sha256")
    monkeypatch.setattr(config, "DIE_ENABLED", False)
    return bl_dir


def test_uri_link_is_reported(tmp_path: Path, isolated_blocklists: Path):
    data = _make_uri_pdf(["https://example.org/invoice"])
    res = _scan_bytes(tmp_path, data)
    by_id = {ind.rule_id: ind for ind in res.indicators}
    assert "PDF_LINK" in by_id
    assert by_id["PDF_LINK"].weight == 0
    assert by_id["PDF_LINK"].severity.name == "INFO"
    assert "hxxps://example.org/invoice" in by_id["PDF_LINK"].detail
    assert res.risk_level == RiskLevel.GREEN
    assert res.score == 0


def test_utf16_without_bom_is_decoded(tmp_path: Path, isolated_blocklists: Path):
    """The measured bypass: UTF-16BE without BOM in /URI must be decoded and matched."""
    (isolated_blocklists / "domains.txt").write_text("phish-example.invalid\n", encoding="utf-8")
    raw_utf16be = "http://phish-example.invalid/login".encode("utf-16-be")
    assert not raw_utf16be.startswith(b"\xfe\xff")
    data = _make_uri_pdf([raw_utf16be], object_stream=False)
    res = _scan_bytes(tmp_path, data)
    rule_ids = {ind.rule_id for ind in res.indicators}
    assert "BINARY_IOC_BLOCKED" in rule_ids
    assert res.risk_level >= RiskLevel.YELLOW
    assert res.score >= 30


def test_uri_in_object_stream_is_found(tmp_path: Path, isolated_blocklists: Path):
    raw_utf16be = "https://hidden-in-objstm.example/doc".encode("utf-16-be")
    data = _make_uri_pdf([raw_utf16be], object_stream=True)
    assert b"hidden-in-objstm" not in data  # compressed inside /ObjStm
    res = _scan_bytes(tmp_path, data)
    by_id = {ind.rule_id: ind for ind in res.indicators}
    assert "PDF_LINK" in by_id
    assert "hxxps://hidden-in-objstm.example/doc" in by_id["PDF_LINK"].detail


def test_blocked_url_is_high(tmp_path: Path, isolated_blocklists: Path):
    target = "https://bad-invoice.invalid/pay?id=7"
    (isolated_blocklists / "urls.sha256").write_text(url_hash(target) + "\n", encoding="utf-8")
    data = _make_uri_pdf([target], object_stream=True)
    res = _scan_bytes(tmp_path, data)
    blocked = [i for i in res.indicators if i.rule_id == "BINARY_IOC_BLOCKED"]
    assert blocked
    assert blocked[0].severity.name == "HIGH"
    assert blocked[0].weight == 30
    assert "/Annots -> /A -> /URI" in blocked[0].detail
    assert res.risk_level == RiskLevel.YELLOW


def test_blocked_domain_is_high(tmp_path: Path, isolated_blocklists: Path):
    (isolated_blocklists / "domains.txt").write_text("evil-portal.invalid\n", encoding="utf-8")
    data = _make_uri_pdf(["https://sub.evil-portal.invalid/auth"], object_stream=True)
    res = _scan_bytes(tmp_path, data)
    assert any(
        i.rule_id == "BINARY_IOC_BLOCKED" and i.severity.name == "HIGH" and i.weight == 30
        for i in res.indicators
    )
    assert res.risk_level == RiskLevel.YELLOW


def test_blocked_ip_literal_is_high(tmp_path: Path, isolated_blocklists: Path):
    (isolated_blocklists / "netze.txt").write_text("1.10.16.0/24\n", encoding="utf-8")
    data = _make_uri_pdf(["http://1.10.16.0/x"], object_stream=True)
    res = _scan_bytes(tmp_path, data)
    assert any(
        i.rule_id == "BINARY_IOC_BLOCKED" and i.severity.name == "HIGH" and i.weight == 30
        for i in res.indicators
    )
    assert res.risk_level == RiskLevel.YELLOW


def test_compressed_and_uncompressed_score_identically(tmp_path: Path, isolated_blocklists: Path):
    (isolated_blocklists / "domains.txt").write_text("same-score.invalid\n", encoding="utf-8")
    plain_pdf = _make_uri_pdf(["http://same-score.invalid/a"], object_stream=False)
    comp_pdf = _make_uri_pdf(["http://same-score.invalid/a"], object_stream=True)
    r_plain = _scan_bytes(tmp_path, plain_pdf, "plain.pdf")
    r_comp = _scan_bytes(tmp_path, comp_pdf, "comp.pdf")
    assert r_plain.score == r_comp.score == 30
    assert r_plain.risk_level == r_comp.risk_level == RiskLevel.YELLOW


def test_legitimate_link_stays_green(tmp_path: Path, isolated_blocklists: Path):
    data = _make_uri_pdf(["https://www.bundesfinanzministerium.de"])
    res = _scan_bytes(tmp_path, data)
    assert res.risk_level == RiskLevel.GREEN
    assert res.score == 0
    assert any(i.rule_id == "PDF_LINK" for i in res.indicators)


def test_namespace_urls_are_ignored(tmp_path: Path, isolated_blocklists: Path):
    data = _make_uri_pdf(
        [
            "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
            "http://ns.adobe.com/xap/1.0/",
            "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
        ],
        object_stream=True,
    )
    res = _scan_bytes(tmp_path, data)
    assert not any(i.rule_id == "PDF_LINK" for i in res.indicators)
    assert res.risk_level == RiskLevel.GREEN


def test_control_chars_are_stripped(tmp_path: Path, isolated_blocklists: Path):
    decoded = _decode_pdf_uri("http://ctrl.example/a\nb\x00c\rd")
    assert decoded == "http://ctrl.example/abcd"
    data = _make_uri_pdf([b"http://ctrl.example/a\nb\x00c"], object_stream=True)
    res = _scan_bytes(tmp_path, data)
    link = next(i for i in res.indicators if i.rule_id == "PDF_LINK")
    assert "\n" not in link.detail
    assert "\x00" not in link.detail
    assert "hxxp://ctrl.example/abc" in link.detail


def test_unreadable_blocklist_marks_incomplete(
    tmp_path: Path, isolated_blocklists: Path, monkeypatch: pytest.MonkeyPatch
):
    bad_dir = isolated_blocklists / "domains_as_dir"
    bad_dir.mkdir()
    monkeypatch.setattr(config, "DOMAIN_BLOCKLIST_FILE", bad_dir)
    orig_is_file = Path.is_file

    def _fake_is_file(self: Path) -> bool:
        if self == bad_dir:
            return True
        return orig_is_file(self)

    monkeypatch.setattr(Path, "is_file", _fake_is_file)
    data = _make_uri_pdf(["https://check-me.example/a"], object_stream=True)
    res = _scan_bytes(tmp_path, data)
    rule_ids = {i.rule_id for i in res.indicators}
    assert "DOMAIN_BLOCKLIST_UNAVAILABLE" in rule_ids
    assert "DOMAIN_BLOCKLIST_UNAVAILABLE" in {i.rule_id for i in res.incomplete_stages}
    assert res.is_incomplete is True


def test_missing_blocklists_are_not_an_error(tmp_path: Path, isolated_blocklists: Path):
    data = _make_uri_pdf(["https://normal.example/doc"], object_stream=True)
    res = _scan_bytes(tmp_path, data)
    rule_ids = {i.rule_id for i in res.indicators}
    assert not any(r.endswith("_BLOCKLIST_UNAVAILABLE") for r in rule_ids)
    pdf_incomplete = [i.rule_id for i in res.incomplete_stages if not i.rule_id.endswith("_SKIPPED")]
    assert pdf_incomplete == []
    assert res.risk_level == RiskLevel.GREEN


def test_cap_is_visible(
    tmp_path: Path, isolated_blocklists: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(config, "BINARY_IOC_MAX_HITS", 5)
    uris = [f"https://cap-{i}.example/p" for i in range(8)]
    data = _make_uri_pdf(uris, object_stream=True)
    res = _scan_bytes(tmp_path, data)
    rule_ids = {i.rule_id for i in res.indicators}
    assert "PDF_LINK_CAPPED" in rule_ids
    assert "PDF_LINK_CAPPED" in {i.rule_id for i in res.incomplete_stages}
    assert res.is_incomplete is True


def test_graph_incomplete_when_pages_and_root_unreadable():
    """Mutation guard: if neither pages nor Root can be walked, walk.incomplete is True."""

    class _BrokenPdf:
        @property
        def pages(self):
            raise RuntimeError("corrupt pages")

        @property
        def Root(self):
            raise RuntimeError("corrupt root")

    pipe = PdfPipeline()
    walk = pipe._walk_action_graph(_BrokenPdf(), collect_js=False, collect_uris=True)
    assert walk.incomplete is True
    assert walk.visited == set()


def test_green_advice_does_not_promise_safety():
    advice = RiskLevel.GREEN.advice
    assert "bedenkenlos" not in advice.lower()
    assert "absender" in advice.lower()


def test_green_advice_reaches_html_report(tmp_path: Path, isolated_blocklists: Path):
    data = _make_uri_pdf(["https://www.bundesfinanzministerium.de"])
    res = _scan_bytes(tmp_path, data)
    html = generate_report([res])
    assert RiskLevel.GREEN.advice in html
    assert "bedenkenlos" not in html.lower()


def test_integer_and_array_uri_do_not_oom_and_warn(tmp_path: Path, isolated_blocklists: Path):
    """F1: /URI 500000000 must NEVER allocate 500 MB via bytes(int); reports PDF_PARSE_WARN."""
    assert _decode_pdf_uri(500_000_000) is None
    assert _decode_pdf_uri(True) is None
    assert _decode_pdf_uri([104, 116, 116, 112]) is None

    pdf = pikepdf.new()
    annot = pdf.make_indirect(
        pikepdf.Dictionary(
            Type=pikepdf.Name.Annot,
            Subtype=pikepdf.Name.Link,
            Rect=[0, 0, 100, 20],
            A=pikepdf.Dictionary(
                Type=pikepdf.Name.Action,
                S=pikepdf.Name.URI,
                URI=500_000_000,
            ),
        )
    )
    pdf.pages.append(
        pikepdf.Page(
            pikepdf.Dictionary(
                Type=pikepdf.Name.Page,
                MediaBox=[0, 0, 612, 792],
                Annots=pikepdf.Array([annot]),
            )
        )
    )
    buf = io.BytesIO()
    pdf.save(buf, deterministic_id=True)
    res = _scan_bytes(tmp_path, buf.getvalue(), "int_uri.pdf")
    assert any(i.rule_id == "PDF_PARSE_WARN" for i in res.indicators)
    assert res.risk_level >= RiskLevel.YELLOW


def test_oversized_uri_is_capped_before_decode():
    """F1/N3: oversized /URI strings are capped to MAX_STRING_CAPTURE cleanly."""
    huge = ("https://example.org/" + "a" * (config.MAX_STRING_CAPTURE * 6)).encode("ascii")
    decoded = _decode_pdf_uri(huge)
    assert decoded is not None
    assert len(decoded) == config.MAX_STRING_CAPTURE


def test_utf16_with_bom_and_le_decoded():
    """N3: UTF-16BE with BOM and UTF-16LE without BOM decode cleanly."""
    with_bom = b"\xfe\xff" + "https://bom.example/a".encode("utf-16-be")
    assert _decode_pdf_uri(with_bom) == "https://bom.example/a"
    le_no_bom = "https://le.example/b".encode("utf-16-le")
    assert _decode_pdf_uri(le_no_bom) == "https://le.example/b"


def test_catalog_uri_base_dictionary_stays_green(tmp_path: Path, isolated_blocklists: Path):
    """F2: ISO 32000-1 Catalog /URI << /Base (...) >> must NOT trigger PDF_PARSE_WARN."""
    pdf = pikepdf.new()
    pdf.Root[pikepdf.Name.URI] = pikepdf.Dictionary(
        Base=pikepdf.String("https://www.bundesfinanzministerium.de/")
    )
    pdf.pages.append(
        pikepdf.Page(pikepdf.Dictionary(Type=pikepdf.Name.Page, MediaBox=[0, 0, 612, 792]))
    )
    buf = io.BytesIO()
    pdf.save(buf, deterministic_id=True)
    res = _scan_bytes(tmp_path, buf.getvalue(), "catalog_uri.pdf")
    assert not any(i.rule_id == "PDF_PARSE_WARN" for i in res.indicators)
    assert any(i.rule_id == "PDF_LINK" for i in res.indicators)
    assert res.risk_level == RiskLevel.GREEN
    assert res.score == 0


def test_userinfo_and_trailing_dot_cannot_bypass_blocklist(
    tmp_path: Path, isolated_blocklists: Path
):
    """F3: https://w3.org:1@evil-phish.invalid/login and trailing dot must hit blocklist."""
    (isolated_blocklists / "domains.txt").write_text("evil-phish.invalid\n", encoding="utf-8")
    for uri in (
        "https://w3.org:1@evil-phish.invalid/login",
        "https://user@evil-phish.invalid/login",
        "https://evil-phish.invalid./login",
    ):
        data = _make_uri_pdf([uri], object_stream=True)
        res = _scan_bytes(tmp_path, data, "bypass.pdf")
        assert any(i.rule_id == "BINARY_IOC_BLOCKED" for i in res.indicators), uri
        assert res.risk_level == RiskLevel.YELLOW, uri


def test_structure_scan_emits_parse_warn_on_walk_incomplete():
    """N3: end-to-end check that walk.incomplete produces PDF_PARSE_WARN in _structure_scan."""

    class _EmptyPdf:
        def __init__(self) -> None:
            self.objects: list = []
            self.attachments: dict = {}

        @property
        def pages(self):
            raise RuntimeError("corrupt pages")

        @property
        def Root(self):
            raise RuntimeError("corrupt root")

    pipe = PdfPipeline()
    ctx = AnalysisContext(path=Path("broken.pdf"), data=b"%PDF-1.7\n%%EOF", size=15, detected_type="pdf")
    indicators = pipe._structure_scan(ctx, _EmptyPdf())
    assert any(
        i.rule_id == "PDF_PARSE_WARN" and i.weight == 20 and "Seitenbaum/Root" in i.title
        for i in indicators
    )


def test_uri_get_exception_emits_parse_warn():
    """F4: exception on obj.get(/URI) appends None sentinel -> PDF_PARSE_WARN (never silent)."""
    pipe = PdfPipeline()
    indicators = pipe._link_indicators([None])
    assert any(i.rule_id == "PDF_PARSE_WARN" and i.weight == 20 for i in indicators)
