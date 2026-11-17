import io
import re

import pytest

pikepdf = pytest.importorskip("pikepdf")

from pathlib import Path
from typing import ClassVar

from malaz import config
from malaz.core.scoring import compute_score
from malaz.models import AnalysisContext, RiskLevel
from malaz.pipelines.pdf_pipeline import PdfPipeline


def _ctx(data: bytes) -> AnalysisContext:
    return AnalysisContext(path=Path("t.pdf"), data=data, detected_type="pdf", size=len(data))


def _ids(indicators) -> list[str]:
    return [i.rule_id for i in indicators]


def _make_pdf(encrypt_pw: str | None = None, owner_only: bool = False) -> bytes:
    """Build a one-page PDF with pikepdf; optionally encrypt it."""
    pdf = pikepdf.new()
    pdf.pages.append(
        pikepdf.Page(
            pikepdf.Dictionary(
                Type=pikepdf.Name.Page,
                MediaBox=[0, 0, 612, 792],
                Contents=pikepdf.Stream(pdf, b"BT /F1 12 Tf 72 72 Td (hello world) Tj ET"),
            )
        )
    )
    buf = io.BytesIO()
    if encrypt_pw is None:
        pdf.save(buf)
    elif owner_only:
        pdf.save(
            buf, encryption=pikepdf.Encryption(owner=encrypt_pw, user="", R=4)
        )
    else:
        pdf.save(
            buf, encryption=pikepdf.Encryption(owner=encrypt_pw, user=encrypt_pw, R=4)
        )
    return buf.getvalue()


def test_unencrypted_has_no_encryption_indicator():
    data = _make_pdf()
    inds = PdfPipeline().analyze(_ctx(data))
    assert not any(r.startswith("PDF_ENCRYPTED") for r in _ids(inds))


def test_encrypted_switch_off_is_medium_and_no_crash(monkeypatch):
    monkeypatch.setattr(config, "PDF_TRY_DEFAULT_PASSWORDS", False)
    data = _make_pdf("geheim")
    inds = PdfPipeline().analyze(_ctx(data))
    locked = [i for i in inds if i.rule_id == "PDF_ENCRYPTED"]
    assert locked
    assert locked[0].severity.name == "MEDIUM"
    # Keyword triage still ran on the raw bytes (no crash, no decryption).
    assert "PDF_ENCRYPTED_OPENED" not in _ids(inds)


def test_encrypted_switch_on_with_matching_password(monkeypatch):
    monkeypatch.setattr(config, "PDF_TRY_DEFAULT_PASSWORDS", True)
    monkeypatch.setattr(config, "PDF_PASSWORDS", ["geheim"])
    data = _make_pdf("geheim")
    inds = PdfPipeline().analyze(_ctx(data))
    assert "PDF_ENCRYPTED_OPENED" in _ids(inds)
    assert "PDF_ENCRYPTED" not in _ids(inds)


def test_encrypted_switch_on_with_wrong_password(monkeypatch):
    monkeypatch.setattr(config, "PDF_TRY_DEFAULT_PASSWORDS", True)
    monkeypatch.setattr(config, "PDF_PASSWORDS", ["wrong"])
    data = _make_pdf("geheim")
    inds = PdfPipeline().analyze(_ctx(data))
    locked = [i for i in inds if i.rule_id == "PDF_ENCRYPTED"]
    assert locked
    assert locked[0].severity.name == "MEDIUM"


def test_encrypted_owner_only_opens_without_user_password(monkeypatch):
    # Owner-password-only PDFs open with the implicit empty user password and
    # must NOT end up in the locked state.
    monkeypatch.setattr(config, "PDF_TRY_DEFAULT_PASSWORDS", True)
    monkeypatch.setattr(config, "PDF_PASSWORDS", [""])
    data = _make_pdf("boss", owner_only=True)
    inds = PdfPipeline().analyze(_ctx(data))
    assert "PDF_ENCRYPTED" not in _ids(inds)
    assert "PDF_ENCRYPTED_OPENED" in _ids(inds)


# -- JavaScript extraction / analysis -------------------------------------- #


def test_analyze_js_text_suspicious_and_obfuscated():
    p = PdfPipeline()
    js = "ev" + "al(String.fromCharCode(97,108,101,114,116));"
    inds = p._analyze_js_text(js, auto_exec=False)
    ids = _ids(inds)
    assert "PDF_JS_EXTRACTED" in ids
    assert "PDF_JS_SUSPICIOUS" in ids  # eval(
    assert "PDF_JS_OBFUSCATED" in ids  # String.fromCharCode
    susp = next(i for i in inds if i.rule_id == "PDF_JS_SUSPICIOUS")
    assert susp.severity.name == "HIGH"


def test_analyze_js_text_boesartiges_primitiv_eskaliert():
    """POSITIVKONTROLLE: nur ein boesartiges Primitiv bildet den Anker.

    Die vorige Fassung dieses Tests nahm ``submitForm`` — eine API, die in
    JEDEM Formular mit Absende-Knopf steht. Damit war der Anker an einer
    Alltagsfunktion festgenagelt; gemessen wurde daraus ein IRS-Formular mit
    ROT 95. Jetzt steht hier ein Aufruf, der in einem harmlosen Dokument
    keinen Alltagsfall hat.
    """
    p = PdfPipeline()
    inds = p._analyze_js_text("this.exportDataObject({cName:'x'});", auto_exec=True)
    susp = next(i for i in inds if i.rule_id == "PDF_JS_SUSPICIOUS")
    assert susp.severity.name == "CRITICAL"
    assert susp.weight == 50


def test_action_graph_truncation_weight_is_20(monkeypatch):
    # GEMESSEN am VA-Formular 21-526ez: der reale Graph lief in die Grenze,
    # /JS + launchURL + inkrementelle Saves ergaben zusammen ROT. Die
    # Unvollständig-Notiz bleibt mit 20 allein GELB (SCORE_GREEN_MAX = 19).
    monkeypatch.setattr(PdfPipeline, "_GRAPH_MAX_DEPTH", 0)
    inds = PdfPipeline().analyze(_ctx(_make_pdf()))
    warn = next(i for i in inds if i.rule_id == "PDF_PARSE_WARN")
    assert warn.weight == 20


def test_analyze_js_text_dokumentuebliche_api_ist_kein_anker():
    """Dieselbe Form, ein harmloser Aufruf — darf NICHT als boesartig gelten.

    GEMESSEN: auf 13 echten Behoerdenformularen (IRS, VA, GSA, CMS) feuerte
    von der alten Liste ausschliesslich ``launchurl``; mit Auto-Start ergab
    das CRITICAL/50. Ein Formular, das auf seine Anleitung verlinkt, ist
    kein Angriff.
    """
    p = PdfPipeline()
    for aufruf in ("this.submitForm('http://x');", "app.launchURL('http://x');"):
        inds = p._analyze_js_text(aufruf, auto_exec=True)
        assert not any(i.rule_id == "PDF_JS_SUSPICIOUS" for i in inds), aufruf
        mild = next(i for i in inds if i.rule_id == "PDF_JS_DOC_API")
        assert mild.weight == 0, "sichtbar, aber kein Score"


def test_analyze_js_text_benign_only_extracted():
    p = PdfPipeline()
    inds = p._analyze_js_text("var x = 1 + 2; console.println(x);", auto_exec=False)
    assert _ids(inds) == ["PDF_JS_EXTRACTED"]


def _make_js_pdf(js_code: str, open_action: bool = True) -> bytes:
    """Build a minimal valid PDF carrying an inline ``/JavaScript`` action."""
    def esc(s: str) -> str:
        return s.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")

    objs = {
        1: "<< /Type /Catalog /Pages 2 0 R"
           + (" /OpenAction 4 0 R" if open_action else "") + " >>",
        2: "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>",
        4: "<< /Type /Action /S /JavaScript /JS (" + esc(js_code) + ") >>",
    }
    out = b"%PDF-1.7\n"
    offsets: dict[int, int] = {}
    for num in sorted(objs):
        offsets[num] = len(out)
        out += f"{num} 0 obj\n{objs[num]}\nendobj\n".encode("latin-1")
    xref_pos = len(out)
    size = max(objs) + 1
    out += b"xref\n" + f"0 {size}\n".encode("latin-1")
    out += b"0000000000 65535 f \n"
    for num in range(1, size):
        out += f"{offsets[num]:010d} 00000 n \n".encode("latin-1")
    out += b"trailer\n" + f"<< /Size {size} /Root 1 0 R >>\n".encode("latin-1")
    out += b"startxref\n" + f"{xref_pos}\n".encode("latin-1") + b"%%EOF\n"
    return out


def test_pdf_with_embedded_js_openaction_is_critical():
    data = _make_js_pdf("ev" + "al(String.fromCharCode(97,108,101,114,116));", open_action=True)
    inds = PdfPipeline().analyze(_ctx(data))
    ids = _ids(inds)
    assert "PDF_JS_EXTRACTED" in ids
    assert "PDF_JS_SUSPICIOUS" in ids
    assert "PDF_JS_OBFUSCATED" in ids
    # Wired to /OpenAction -> auto-exec -> critical anchor.
    susp = next(i for i in inds if i.rule_id == "PDF_JS_SUSPICIOUS")
    assert susp.severity.name == "CRITICAL"


def test_pdf_with_embedded_js_without_openaction_is_high():
    data = _make_js_pdf("ev" + "al(String.fromCharCode(97));", open_action=False)
    inds = PdfPipeline().analyze(_ctx(data))
    susp = next(i for i in inds if i.rule_id == "PDF_JS_SUSPICIOUS")
    assert susp.severity.name == "HIGH"


def test_pdf_with_js_stream_indirect_reference():
    """The /JS value may be an indirect, compressed stream object."""
    pdf = pikepdf.new()
    pdf.pages.append(
        pikepdf.Page(
            pikepdf.Dictionary(
                Type=pikepdf.Name.Page, MediaBox=[0, 0, 612, 792]
            )
        )
    )
    # Eine echte Nutzlast, kein Alltagsaufruf: der Test prueft den
    # EXTRAKTIONSWEG (indirekter, komprimierter /JS-Strom). Mit
    # app.launchURL hiess die Zusicherung "launchurl ist boesartig" — die
    # Messung an 13 echten Behoerdenformularen hat das widerlegt.
    stream = pikepdf.Stream(pdf, b"this.exportDataObject({cName:'x'});")
    action = pikepdf.Dictionary(S=pikepdf.Name.JavaScript, JS=pdf.make_indirect(stream))
    pdf.Root.OpenAction = pdf.make_indirect(action)
    buf = io.BytesIO()
    pdf.save(buf)
    inds = PdfPipeline().analyze(_ctx(buf.getvalue()))
    ids = _ids(inds)
    assert "PDF_JS_EXTRACTED" in ids
    assert "PDF_JS_SUSPICIOUS" in ids  # exportDataObject, aus dem Strom


# -- obfuscation-aware keyword triage (pdfid-style) ------------------------- #


def test_obfuscated_keywords_detected():
    # /J#61vaScript is /JavaScript with the 'a' hex-escaped; the plain byte
    # counter must not be the only line of defence.
    data = b"%PDF-1.7\n/Type /Catalog\n/J#61vaScript (x)\n/Open#41ction 1\n%%EOF"
    inds = PdfPipeline().analyze(_ctx(data))
    ids = _ids(inds)
    assert "PDF_KW_JavaScript_OBF" in ids
    assert "PDF_KW_OpenAction_OBF" in ids
    # The plain counter must NOT have seen the obfuscated names.
    assert "PDF_KW_JavaScript" not in ids
    assert "PDF_KW_OpenAction" not in ids


def test_obfuscation_scan_skipped_without_hash():
    data = b"%PDF-1.7\n/JavaScript 1\n%%EOF"
    inds = PdfPipeline().analyze(_ctx(data))
    ids = _ids(inds)
    assert "PDF_KW_JavaScript" in ids
    assert "PDF_KW_JavaScript_OBF" not in ids


def test_encrypt_and_page_keywords():
    data = b"%PDF-1.7\n/Encrypt /Standard\n/Page /Page\n%%EOF"
    inds = PdfPipeline().analyze(_ctx(data))
    ids = _ids(inds)
    assert "PDF_KW_Encrypt" in ids
    assert "PDF_KW_Page" in ids


def test_hex_escapes_count_only_when_they_decode_to_the_keyword_byte():
    """BUG-021: any ``#xx`` pair counted as any keyword character.

    ``/J#00vaScript`` decoded to NUL + "vaScript", not ``/JavaScript``, but
    the old pattern accepted every hex pair at every keyword position. Only
    the escape that decodes to the CHARACTER may match — with hex digits
    still case-insensitive, as PDF requires.
    """
    from malaz.pipelines.pdf_pipeline import _count_obfuscated_names

    keyword = b"/JavaScript"
    assert _count_obfuscated_names(b"/J#61vaScript", keyword) == 1
    # Case-insensitive hex digits: 'J' = 0x4A.
    assert _count_obfuscated_names(b"/#4AavaScript", keyword) == 1
    # Valid hex, wrong character: NUL is not 'a'.
    assert _count_obfuscated_names(b"/J#00vaScript", keyword) == 0
    # Invalid hex is not an escape either.
    assert _count_obfuscated_names(b"/J#zzvaScript", keyword) == 0


def test_black_fill_resets_the_white_text_state():
    """BUG-022: ``0 0 0 rg`` / ``0 g`` / ``k`` never reset the colour state.

    The old table only matched components starting with ``1``, so a stream
    that painted white and then RESET to black still looked like hidden white
    text (false positive) — and a black-only stream could inherit the flag.
    """
    from malaz.pipelines.pdf_pipeline import _hat_weissen_text

    # Baseline: white text on white is still detected.
    assert _hat_weissen_text(b"1 1 1 rg BT /F1 12 Tf (geheim) Tj ET")
    # A black RGB fill after the white one is a real reset.
    assert not _hat_weissen_text(
        b"1 1 1 rg 0 0 0 rg BT /F1 12 Tf (sichtbar) Tj ET"
    )
    assert not _hat_weissen_text(b"1 g 0 g BT (sichtbar) Tj ET")
    # CMYK: 0/0/0/0 is paper white, 0/0/0/1 is black.
    assert not _hat_weissen_text(
        b"1 1 1 rg 0 0 0 1 k BT (schwarz) Tj ET"
    )
    assert _hat_weissen_text(b"0 0 0 0 k BT (weiss) Tj ET")


def test_colour_reset_inside_a_string_is_not_an_operator():
    """The reset detection must not create an evasion vector.

    ``(0 0 0 rg)`` is text the user sees; treating it as a colour operator
    would let an attacker hide white text by writing the reset sequence into
    the very string that is drawn.
    """
    from malaz.pipelines.pdf_pipeline import _hat_weissen_text

    assert _hat_weissen_text(b"1 1 1 rg BT (0 0 0 rg) Tj ET")
    assert _hat_weissen_text(b"1 1 1 rg % 0 0 0 rg\nBT (geheim) Tj ET")


def _pdf_with_attachment(name: str, payload: bytes = b"MZ fake payload") -> bytes:
    pdf = pikepdf.new()
    pdf.pages.append(
        pikepdf.Page(
            pikepdf.Dictionary(
                Type=pikepdf.Name.Page,
                MediaBox=[0, 0, 612, 792],
                Contents=pikepdf.Stream(pdf, b"BT /F1 12 Tf (hi) Tj ET"),
            )
        )
    )
    pdf.attachments[name] = pikepdf.AttachedFileSpec(pdf, payload)
    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


@pytest.mark.parametrize(
    "name",
    ["payload.exe ", "payload.exe.", "payload.exe::$DATA"],
    ids=["trailing-space", "trailing-dot", "ntfs-ads"],
)
def test_embedded_executable_suffix_is_not_bypassable_by_windows_names(name):
    """BUG-018: the suffix check asked the RAW attachment name.

    GEMESSEN: ``payload.exe`` was CRITICAL/50, while ``payload.exe `` /
    ``payload.exe.`` / ``payload.exe::$DATA`` only produced the harmless
    "embedded files" note (20, YELLOW). Windows strips trailing dots/spaces
    and cuts everything from ``:`` (ADS) when it writes the member to disk —
    exactly the rules ``safe_extract`` applies — so all three land as
    ``payload.exe`` and must keep the dropper anchor.
    """
    inds = PdfPipeline().analyze(_ctx(_pdf_with_attachment(name)))
    exe = [i for i in inds if i.rule_id == "PDF_EMBEDDED_EXECUTABLE"]
    assert exe, [i.rule_id for i in inds]
    assert exe[0].severity.name == "CRITICAL"
    assert exe[0].weight == 50
    assert "PDF_EMBEDDED_FILES" not in _ids(inds)


def test_embedded_document_with_trailing_space_stays_a_note():
    """Gegenrichtung: die Normalisierung darf harmlose Namen nicht hochziehen."""
    inds = PdfPipeline().analyze(_ctx(_pdf_with_attachment("anhang.txt ")))
    assert "PDF_EMBEDDED_EXECUTABLE" not in _ids(inds)
    assert "PDF_EMBEDDED_FILES" in _ids(inds)


def test_hex_obfuscated_js_never_weighs_below_the_plain_baseline():
    """BUG-020: the obfuscation branch gated on SEVERITY, not on the weight.

    ``/JS`` is LOW/20, so ``/J#53`` / ``/J#61vaScript`` scored 5 each —
    stage score 10 instead of the 40 the readable keywords cost. Hiding the
    keyword must never make the file cheaper.
    """
    plain = PdfPipeline()._keyword_triage(_ctx(b"%PDF-1.7\n/JavaScript /JS\n%%EOF"))
    hidden = PdfPipeline()._keyword_triage(_ctx(b"%PDF-1.7\n/J#61vaScript /J#53\n%%EOF"))
    baseline = {i.rule_id: i for i in plain}
    obfuscated = {i.rule_id: i for i in hidden}
    for plain_id, obf_id in (
        ("PDF_KW_JS", "PDF_KW_JS_OBF"),
        ("PDF_KW_JavaScript", "PDF_KW_JavaScript_OBF"),
    ):
        assert baseline[plain_id].weight == 20
        assert obfuscated[obf_id].weight >= baseline[plain_id].weight
    assert compute_score(hidden).score >= compute_score(plain).score


def test_aa_key_regex_excludes_aapl_names():

    from malaz.pipelines.pdf_pipeline import _AA_KEY_RE

    assert _AA_KEY_RE.search(b"/AA <<") is not None
    assert _AA_KEY_RE.search(b"/OpenAction /AA 0 R") is not None
    assert _AA_KEY_RE.search(b"/AAPL:AA.Ignore") is None
    assert _AA_KEY_RE.search(b"/AAPL:pdf") is None


def test_keyword_triage_does_not_count_aapl_as_aa():
    data = b"%PDF-1.5\n/AAPL:AAIgnore\n%%EOF"
    ctx = AnalysisContext(path=Path("a.pdf"), data=data, detected_type="pdf", size=len(data))
    inds = PdfPipeline()._keyword_triage(ctx)
    assert not any(i.rule_id == "PDF_KW_AA" for i in inds)


def test_js_flate_bomb_is_refused_not_oomed(tmp_path, monkeypatch):
    # Regression (kritisch): read_bytes() materialisierte den KOMPLETT
    # dekomprimierten Stream — eine Flate-Bombe (kleine Datei, riesige
    # Ausgabe) hätte OOM/freeze verursacht. Der bounded Reader muss den
    # Stream verweigern und einen Warn-Indicator liefern.
    import io
    import zlib

    import pikepdf

    import malaz.pipelines.pdf_pipeline as module

    monkeypatch.setattr(module, "_MAX_STREAM_BYTES", 64 * 1024)

    bomb_payload = zlib.compress(b"eval(String.fromCharCode(1));" + b"A" * (1024 * 1024))
    pdf = pikepdf.new()
    # Stream, dessen RAW-Inhalt der komprimierte Blob ist und der per
    # /FlateDecode beim Lesen auf >1 MB expandiert — Root trägt ihn als /JS.
    js_stream = pdf.make_stream(bomb_payload)
    js_stream.Filter = pikepdf.Name.FlateDecode
    pdf.Root.JS = pdf.make_indirect(js_stream)

    buf = io.BytesIO()
    pdf.save(buf)
    data = buf.getvalue()

    from malaz.models import AnalysisContext as Ctx

    ctx = Ctx(path=Path("bomb.pdf"), data=data, detected_type="pdf", size=len(data))
    opened = module.PdfPipeline()._open_pdf(ctx)
    pdf2 = opened[0]
    assert pdf2 is not None
    chunks, warnings = module.PdfPipeline()._extract_js(pdf2)
    assert warnings, "Bombe muss als Warnung gemeldet werden"
    assert not chunks


def test_unfiltered_js_stream_is_read_directly():
    # Regression (Hunt 3): ungefilterte Streams liefen durch den zlib-Pfad
    # und wurden pauschal als 'beschädigt' verworfen — False Negative PLUS
    # falscher Bomben-Verdacht auf völlig legitimen PDFs.
    import io

    import pikepdf

    import malaz.pipelines.pdf_pipeline as module

    pdf = pikepdf.new()
    js_bytes = b"this.exportDataObject({cName:'x'});"
    js_stream = pdf.make_stream(js_bytes)  # KEIN Filter
    pdf.Root.JS = pdf.make_indirect(js_stream)
    buf = io.BytesIO()
    pdf.save(buf)

    from malaz.models import AnalysisContext as Ctx

    ctx = Ctx(path=Path("plain.pdf"), data=buf.getvalue(), detected_type="pdf",
              size=buf.tell())
    pdf2 = module.PdfPipeline()._open_pdf(ctx)[0]
    assert pdf2 is not None
    chunks, warnings = module.PdfPipeline()._extract_js(pdf2)
    assert warnings == []
    assert chunks and b"exportDataObject" in chunks[0].encode("latin-1", "ignore")


def test_flate_bomb_warning_is_medium_not_info(monkeypatch):
    # Regression (Hunt 4): die Bomben-Klassifikation matchte die eigenen
    # Meldungsstrings nicht — eine echte Bombe wurde als INFO/0 'nicht
    # lesbar' präsentiert. Sie muss MEDIUM mit Bomben-Titel sein.
    # Runde 4: 15 lag unter SCORE_GREEN_MAX (19) — ein PDF, dessen einziger
    # JS-Stream eine Dekompressionsbombe ist, kam damit noch GRUEN durch.
    # Der Bombe und dem beschaedigten Stream ist gemeinsam, dass der Inhalt
    # NICHT gelesen wurde; beide tragen deshalb 25 (siehe
    # test_bomb_warning_is_not_lighter_than_the_partial_read_warning).
    import io
    import zlib

    import pikepdf

    import malaz.pipelines.pdf_pipeline as module

    monkeypatch.setattr(module, "_MAX_STREAM_BYTES", 64 * 1024)

    bomb_payload = zlib.compress(b"x" * (1024 * 1024))
    pdf = pikepdf.new()
    js_stream = pdf.make_stream(bomb_payload)
    js_stream.Filter = pikepdf.Name.FlateDecode
    pdf.Root.JS = pdf.make_indirect(js_stream)
    buf = io.BytesIO()
    pdf.save(buf)

    from malaz.models import AnalysisContext as Ctx

    ctx = Ctx(path=Path("b.pdf"), data=buf.getvalue(), detected_type="pdf",
              size=buf.tell())
    pdf2 = module.PdfPipeline()._open_pdf(ctx)[0]
    inds = module.PdfPipeline()._javascript_scan(ctx, pdf2)
    warn = next(i for i in inds if i.rule_id == "PDF_JS_STREAM_WARN")
    assert warn.severity.name == "MEDIUM"
    assert warn.weight == 25
    assert "Bomben-Verdacht" in warn.title
    assert "nicht als 'sauber'" in warn.detail


def test_warn_is_bomb_survives_layout_prefix():
    # Regression (Hunt 5): die Layout-Forensik praefigiert die Gruende mit
    # 'S. <n>: ' — startswith-Matches fielen dort weg und der suffix-lose
    # exotische Hartlimit-Fall wurde als INFO-Lesefehler präsentiert.
    from malaz.pipelines.pdf_pipeline import _warn_is_bomb

    # Alle Bomben-Refusals, unpraefigiert UND praefigiert:
    for reason in (
        "Stream > 8388608 Bytes (Dekompressionsbombe-Verdacht)",
        "entpackter Stream > 8388608 Bytes (Dekompressionsbombe-Verdacht)",
        "entpackter Stream > 8388608 Bytes",  # exotisch, hartes Limit
        "Stream-Filterkette überschreitet Größenlimit (geschätzt)",
        "S. 1: entpackter Stream > 8388608 Bytes",  # Layout-Praefix
        "S. 12: Stream > 8388608 Bytes (Dekompressionsbombe-Verdacht)",
    ):
        assert _warn_is_bomb(reason), reason
    # Keine Bombe: gewoehnliche Lese-/Strukturfehler
    for reason in (
        "Flate-Stream beschädigt",
        "Stream nicht lesbar (AttributeError)",
        "S. 3: Flate-Stream beschädigt",
    ):
        assert not _warn_is_bomb(reason), reason


def test_chain_expansion_factors():
    from malaz.pipelines.pdf_pipeline import _chain_expansion

    assert _chain_expansion(["/FlateDecode"]) == 1032
    # Klassischer Alt-Acrobat-Kombo: schrumpft leicht, dann Flate
    assert _chain_expansion(["/ASCII85Decode", "/FlateDecode"]) == 0.8 * 1032
    # ASCIIHex schrumpft um die Haelfte pro Stufe
    assert _chain_expansion(["/ASCIIHexDecode"]) == 0.5
    assert _chain_expansion(["/ASCIIHexDecode", "/ASCIIHexDecode"]) == 0.25
    # Die gefaehrliche Doppel-Flate: ~1e6:1
    assert _chain_expansion(["/FlateDecode", "/FlateDecode"]) == 1032 * 1032
    # Unbekannte Filter bekommen den Flate-Worst-Case
    assert _chain_expansion(["/DCTDecode"]) == 1032


def test_double_flate_bomb_refused_before_materialising(monkeypatch):
    # Regression: die pauschale 1200:1-Schaetzung liess eine ~50-Byte-Doppel-
    # Flate-Kette durch; read_bytes() haette erst GB-weise materialisiert
    # (OOM), bevor der harte Nach-Check griff. Die Faktoren-Mathematik
    # verweigert die Kette VOR der Dekompression.
    import zlib

    import pikepdf

    import malaz.pipelines.pdf_pipeline as module

    monkeypatch.setattr(module, "_MAX_STREAM_BYTES", 64 * 1024)

    payload = b"B" * (1024 * 1024)  # 1 MB Ziel-Ausdehnung
    flate1 = zlib.compress(payload)
    flate2 = zlib.compress(flate1)  # Rohdaten: winzig
    assert len(flate2) * 1032 * 1032 > 64 * 1024  # Schätzung muss ansprechen

    # Direkt am In-Memory-Objekt: pikepdfs save() kollabiert doppelte
    # Filter-Arrays zu einer Stufe — ein gespeichertes Test-PDF könnte die
    # Kette also gar nicht transportieren. Der Angriffsfall lebt im
    # geöffneten Objektgraphen, genau den wir hier prüfen.
    pdf = pikepdf.new()
    js_stream = pdf.make_stream(flate2)
    js_stream.Filter = pikepdf.Array([pikepdf.Name.FlateDecode,
                                      pikepdf.Name.FlateDecode])
    pdf.Root.JS = pdf.make_indirect(js_stream)

    chunks, warnings = module.PdfPipeline()._extract_js(pdf)
    assert warnings and "Größenlimit" in warnings[0]
    assert chunks == []
    assert module._warn_is_bomb(warnings[0])  # als Bombe klassifiziert, nicht INFO


def test_legit_ascii85_flate_chain_still_readable():
    # Alt-Acrobat-PDFs nutzen [/ASCII85Decode /FlateDecode] routinemaessig:
    # kleine legitime Streams muessen weiter lesbar bleiben (0.8*1032 = 826:1
    # erlaubt ~10 KB Rohdaten gegen das 8-MB-Limit).
    import base64
    import io
    import zlib

    import pikepdf

    import malaz.pipelines.pdf_pipeline as module

    payload = b"app.alert('hallo');" * 100
    raw = base64.a85encode(zlib.compress(payload))

    pdf = pikepdf.new()
    js_stream = pdf.make_stream(raw)
    js_stream.Filter = pikepdf.Array([pikepdf.Name.ASCII85Decode,
                                      pikepdf.Name.FlateDecode])
    pdf.Root.JS = pdf.make_indirect(js_stream)
    buf = io.BytesIO()
    pdf.save(buf)

    from malaz.models import AnalysisContext as Ctx

    ctx = Ctx(path=Path("a85.pdf"), data=buf.getvalue(), detected_type="pdf",
              size=buf.tell())
    pdf2 = module.PdfPipeline()._open_pdf(ctx)[0]
    chunks, warnings = module.PdfPipeline()._extract_js(pdf2)
    assert warnings == []
    assert chunks and "app.alert" in chunks[0]


def test_encrypted_structural_error_yields_parse_warn_not_crash(monkeypatch):
    # Regression (Audit M2): ein Strukturfehler WAEHREND des Passwort-Loops
    # muss als PDF_PARSE_WARN quittiert werden — das alte `raise` im
    # except-Block umging den eigenen Handler und verlor alle Tiefen-
    # Ergebnisse. Simuliert via pikepdf.open-Mock beim zweiten Versuch.
    import pikepdf as _pk

    monkeypatch.setattr(config, "PDF_TRY_DEFAULT_PASSWORDS", True)
    monkeypatch.setattr(config, "PDF_PASSWORDS", ["", "geheim"])
    data = _make_pdf("geheim")
    real_open = _pk.open
    calls = {"n": 0}

    def flaky_open(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 2:  # erster Versuch: PasswordError; zweiter: Strukturfehler
            raise ValueError("kaputte xref während Entschlüsselung")
        return real_open(*args, **kwargs)

    monkeypatch.setattr(_pk, "open", flaky_open)
    inds = PdfPipeline().analyze(_ctx(data))
    assert "PDF_PARSE_WARN" in _ids(inds)
    assert "kaputte xref" in next(
        i for i in inds if i.rule_id == "PDF_PARSE_WARN"
    ).detail


def test_js_budget_exhaustion_is_visible_not_silent(monkeypatch):
    # Regression (Hunt 3.1, Evasions-Vektor): Ein Angreifer fuellt das
    # 8-MiB-JS-Budget mit harmlosem Padding-Stream; der boese zweite /JS
    # wurde STILL verworfen. Beides muss jetzt sichtbar gemeldet werden.
    import pikepdf

    import malaz.pipelines.pdf_pipeline as module

    monkeypatch.setattr(module, "_MAX_STREAM_BYTES", 64 * 1024)

    pdf = pikepdf.new()
    # Objekt 1 (Root-/JS): harmloses Padding, fuellt fast das ganze Budget
    pad = pdf.make_stream(b"A" * (60 * 1024))
    pad.Type = pikepdf.Name.Action
    pdf.Root.JS = pdf.make_indirect(pad)
    # Objekt 2 (spaetere Objektnummer): boese Payload — wuerde ohne Fix
    # still auf 0 Zeichen trunciert.
    container = pikepdf.Dictionary(
        JS=pikepdf.String("X" * (10 * 1024)),
        S=pikepdf.Name.JavaScript,
    )
    pdf.Root.Evil = pdf.make_indirect(container)

    _chunks, warnings = module.PdfPipeline()._extract_js(pdf)
    assert any("Gesamtbudget" in w for w in warnings), warnings


def test_js_budget_truncation_of_stream_warns(monkeypatch):
    import pikepdf

    import malaz.pipelines.pdf_pipeline as module

    monkeypatch.setattr(module, "_MAX_STREAM_BYTES", 4096)

    pdf = pikepdf.new()
    # Objekt 1: JS-STRING belegt 3000 Zeichen Budget (Strings haben keinen
    # Per-Stream-Cap).
    pdf.Root.JS = pikepdf.String("S" * 3000)
    # Objekt 2: 4096-Byte-Stream besteht den Per-Stream-Check (<= Limit),
    # wird aber am REST-Budget (1096) gekuerzt -> Warnung noetig.
    big = pdf.make_stream(b"B" * 4096)
    big.Type = pikepdf.Name.Action
    container = pikepdf.Dictionary(JS=pdf.make_indirect(big))
    pdf.Root.Evil = pdf.make_indirect(container)

    chunks, warnings = module.PdfPipeline()._extract_js(pdf)
    assert chunks and len(chunks[-1]) == 1096  # Praefix bleibt analysierbar
    assert any("gekürzt" in w for w in warnings), warnings


def test_empty_flate_stream_is_not_flagged_incomplete():
    # Regression (Hunt 3.2): Generatoren schreiben leere Content-Streams
    # MIT Filter — das ist keine Abschneidung, keine Warnung noetig.
    import pikepdf

    from malaz.pipelines.pdf_pipeline import _read_stream_bounded

    pdf = pikepdf.new()
    stream = pdf.make_stream(b"")
    stream.Filter = pikepdf.Name.FlateDecode
    payload, warn = _read_stream_bounded(stream, pikepdf)
    assert payload == b""
    assert warn is None


# -- stage outages must never present as "clean" (Audit Runde 3) ------------ #
#
# Every one of these tests failed before the fix: the deep stages carried
# weight 0 (or, in the layout case, emitted no indicator at all), so a PDF
# whose content was never inspected came back GREEN. The rule (docs/
# CHANGELOG.md): a stage that does not evaluate content must either cost
# points or say "unchecked" — weight 0 for "not analysed" is a finding.
# SCORE_GREEN_MAX is 19, so the lower bound is 25 (same as CORE_ERROR).


@pytest.fixture(scope="module")
def verdict_dispatcher():
    """AV engines off: this contract is about the static PDF stages."""
    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher

    config.YARA_FEED_DIRS = ()
    try:
        yield Dispatcher(
            av_scanner=WindowsDefenderScanner(enabled=False),
            clam_scanner=ClamAVScanner(enabled=False),
        )
    finally:
        config.YARA_FEED_DIRS = config.YARA_FEED_DIRS_DEFAULT


def _objstm_payload_pdf() -> bytes:
    """A PDF whose payload only the deep stages can see.

    The JavaScript sits in a compressed ``/ObjStm`` and is wired up as
    ``/OpenAction``: the raw-byte triage cannot find a single marker, so the
    file's verdict rests entirely on pikepdf/qpdf opening it.
    """
    pdf = pikepdf.new()
    pdf.pages.append(
        pikepdf.Page(
            pikepdf.Dictionary(
                Type=pikepdf.Name.Page,
                MediaBox=[0, 0, 612, 792],
                Contents=pikepdf.Stream(pdf, b"BT /F1 12 Tf 72 72 Td (hello) Tj ET"),
            )
        )
    )
    action = pikepdf.Dictionary(
        S=pikepdf.Name.JavaScript,
        JS=pikepdf.String(
            "app.launchURL('http://evil.example/x'); ev" + "al(a+b); "
            "this.exportDataObject({cName:'x'});"
        ),
    )
    pdf.Root.OpenAction = pdf.make_indirect(action)
    buf = io.BytesIO()
    pdf.save(buf, object_stream_mode=pikepdf.ObjectStreamMode.generate)
    return buf.getvalue()


def _bump_xref_size(data: bytes) -> bytes:
    """One byte in the xref stream: ``/Size n`` -> ``/Size n+1``.

    qpdf refuses such a file (the entry count no longer matches), while a
    tolerant reader opens it and still sees the untouched payload.
    """
    match = re.search(rb"/Size (\d+)", data)
    assert match is not None, "Fixture hat keinen /Size-Eintrag"
    bumped = str(int(match.group(1)) + 1).encode()
    assert len(bumped) == len(match.group(1)), "Fixture muss gleich lang bleiben"
    return data[: match.start(1)] + bumped + data[match.end(1):]


def test_pdf_stage_outage_never_reports_green(tmp_path, verdict_dispatcher):
    # Measured before the fix: RED 60 became GREEN 5 after changing ONE byte
    # of the xref stream, while pypdf 6.16.2 still read the live
    # /OpenAction JavaScript out of the same bytes.
    data = _objstm_payload_pdf()
    for marker in (b"/JavaScript", b"/JS", b"/OpenAction", b"launchURL"):
        assert marker not in data  # only the deep stages can see the payload

    baseline = tmp_path / "baseline.pdf"
    baseline.write_bytes(data)
    assert verdict_dispatcher.scan_path(baseline).risk_level == RiskLevel.RED

    mutated = tmp_path / "mutated.pdf"
    mutated.write_bytes(_bump_xref_size(data))
    result = verdict_dispatcher.scan_path(mutated)
    assert "PDF_PARSE_WARN" in _ids(result.indicators)
    # A stage that did not run is YELLOW, never green.
    assert result.risk_level != RiskLevel.GREEN
    assert result.score > config.SCORE_GREEN_MAX


def test_js_extraction_outage_is_never_green(tmp_path, verdict_dispatcher, monkeypatch):
    # The JS stage is the only thing that can see an /ObjStm payload; if its
    # extraction fails, the file must not come back clean.
    data = _objstm_payload_pdf()
    path = tmp_path / "js.pdf"
    path.write_bytes(data)

    def boom(self, pdf):
        raise ValueError("Objekte unlesbar")

    monkeypatch.setattr(PdfPipeline, "_extract_js", boom)
    result = verdict_dispatcher.scan_path(path)
    assert "PDF_JS_PARSE_WARN" in _ids(result.indicators)
    assert result.risk_level != RiskLevel.GREEN
    assert result.score > config.SCORE_GREEN_MAX


def test_missing_pikepdf_is_never_green(tmp_path, verdict_dispatcher, monkeypatch):
    # Without pikepdf the stages 2-4 never run in that installation; a
    # completely uninspected PDF must not be reported as clean.
    monkeypatch.setattr(config, "has_capability", lambda name: False)
    path = tmp_path / "harmlos.pdf"
    path.write_bytes(_make_pdf())
    result = verdict_dispatcher.scan_path(path)
    assert "PDF_LIB_MISSING" in _ids(result.indicators)
    assert result.risk_level != RiskLevel.GREEN
    assert result.score > config.SCORE_GREEN_MAX


def test_layout_stage_outage_is_reported_not_swallowed():
    # The page-tree failure used to be swallowed by a bare `pass`: no
    # indicator at all, so invisible-text / color-on-color detection could
    # silently never run and the file still scored GREEN.
    class _UnreadablePageTree:
        @property
        def pages(self):
            raise RuntimeError("Seitenbaum unlesbar")

    inds = PdfPipeline()._layout_forensics(_ctx(b"%PDF-1.7\n%%EOF"), _UnreadablePageTree())
    warn = next(i for i in inds if i.rule_id == "PDF_PARSE_WARN")
    assert warn.severity.name == "MEDIUM"
    assert warn.weight > config.SCORE_GREEN_MAX
    assert "nicht als 'sauber'" in warn.detail


def test_locked_pdf_warns_from_the_stage_alone(tmp_path, verdict_dispatcher, monkeypatch):
    # A password-protected PDF whose content we could not read must not be
    # GREEN — and not merely by accident of the /Encrypt keyword (a different
    # stage's signal): the stage warning itself has to cross the threshold.
    monkeypatch.setattr(config, "PDF_TRY_DEFAULT_PASSWORDS", False)
    path = tmp_path / "locked.pdf"
    path.write_bytes(_make_pdf("geheim"))
    result = verdict_dispatcher.scan_path(path)
    locked = [i for i in result.indicators if i.rule_id == "PDF_ENCRYPTED"]
    assert locked
    assert result.risk_level != RiskLevel.GREEN
    assert locked[0].weight > config.SCORE_GREEN_MAX


# -- unreadable streams/pages are "not checked", not "clean" (Runde 4) ------- #


def _corrupt_flate_stream(pdf, payload: bytes):
    """A stream that CLAIMS /FlateDecode but holds bytes that are not zlib."""
    stream = pdf.make_stream(payload)
    stream.Filter = pikepdf.Name.FlateDecode
    return stream


def test_damaged_js_stream_warning_crosses_the_green_threshold():
    """Regression (Runde 4): der Nicht-Bomben-Zweig trug Gewicht 0.

    Gemessen vor dem Fix: ein /JS-Stream, dessen zlib-Daten beschaedigt sind,
    liefert `PDF_JS_STREAM_WARN` mit Gewicht 0 — der JavaScript-Code darin
    wurde nie analysiert, das PDF blieb GRUEN. Die Bombe daneben kostete 15.
    Ein nicht gelesener Stream ist "nicht geprueft", nicht "sauber": beide
    Zweige tragen jetzt dieselbe Gewichtsklasse (25) — keine Aussage ist
    schwerer als die andere, nur der Titel unterscheidet sie.
    """
    from malaz.core.scoring import compute_score

    pdf = pikepdf.new()
    pdf.Root.JS = pdf.make_indirect(_corrupt_flate_stream(pdf, b"kein zlib"))
    buf = io.BytesIO()
    pdf.save(buf)
    ctx = _ctx(buf.getvalue())

    pipe = PdfPipeline()
    inds = pipe._javascript_scan(ctx, pipe._open_pdf(ctx)[0])
    warn = next(i for i in inds if i.rule_id == "PDF_JS_STREAM_WARN")
    assert "Bomben-Verdacht" not in warn.title, warn.title
    assert warn.weight is not None and warn.weight > config.SCORE_GREEN_MAX
    assert compute_score(inds).risk_level != RiskLevel.GREEN


def test_damaged_layout_stream_warning_crosses_the_green_threshold():
    """Dieselbe Regel fuer den Inhalts-Stream der Layout-Forensik."""
    from malaz.core.scoring import compute_score

    pdf = pikepdf.new()
    pdf.pages.append(
        pikepdf.Page(
            pikepdf.Dictionary(
                Type=pikepdf.Name.Page,
                MediaBox=[0, 0, 612, 792],
                Contents=_corrupt_flate_stream(pdf, b"kein zlib"),
            )
        )
    )
    buf = io.BytesIO()
    pdf.save(buf)
    ctx = _ctx(buf.getvalue())

    pipe = PdfPipeline()
    inds = pipe._layout_forensics(ctx, pipe._open_pdf(ctx)[0])
    warn = next(i for i in inds if i.rule_id == "PDF_STREAM_WARN")
    assert "Bomben-Verdacht" not in warn.title, warn.title
    assert warn.weight is not None and warn.weight > config.SCORE_GREEN_MAX
    assert compute_score(inds).risk_level != RiskLevel.GREEN


def test_bomb_warning_is_not_lighter_than_the_partial_read_warning(monkeypatch):
    """Gegenrichtung: die Bombe darf nicht SCHWAECHER wiegen als der Rest.

    Der Nicht-Bomben-Zweig von 0 auf 25 zu heben, ohne den Bomben-Zweig
    mitzunehmen, haette die Reihenfolge umgedreht: ein absichtlich
    aufgeblasener Stream (Umgehungsversuch) haette weniger gekostet als ein
    zufaellig beschaedigter. Beide Zweige tragen deshalb 25.
    """
    import zlib

    import malaz.pipelines.pdf_pipeline as module

    monkeypatch.setattr(module, "_MAX_STREAM_BYTES", 64 * 1024)
    pdf = pikepdf.new()
    pdf.Root.JS = pdf.make_indirect(
        _corrupt_flate_stream(pdf, zlib.compress(b"x" * (1024 * 1024)))
    )
    buf = io.BytesIO()
    pdf.save(buf)
    ctx = _ctx(buf.getvalue())
    pipe = PdfPipeline()
    bomb = next(
        i
        for i in pipe._javascript_scan(ctx, pipe._open_pdf(ctx)[0])
        if i.rule_id == "PDF_JS_STREAM_WARN"
    )
    assert "Bomben-Verdacht" in bomb.title, bomb.title

    assert bomb.weight == 25
    assert bomb.severity.name == "MEDIUM"


def test_deeply_nested_js_is_reported_not_silently_dropped():
    """BUG-023: ``_js_value_text`` returned at depth > 4 without a note.

    A /JS array nested five levels deep was not analysed and nothing said so:
    the file came back without a JavaScript finding, i.e. like a clean scan.
    The depth bound stays (it is defensive), but it must announce itself.
    """
    pdf = pikepdf.new()
    pdf.pages.append(
        pikepdf.Page(
            pikepdf.Dictionary(Type=pikepdf.Name.Page, MediaBox=[0, 0, 612, 792])
        )
    )
    value = pikepdf.String("app.alert(1)")
    for _ in range(6):
        value = pikepdf.Array([value])
    pdf.Root.JS = value
    buf = io.BytesIO()
    pdf.save(buf)
    ctx = _ctx(buf.getvalue())

    pipe = PdfPipeline()
    inds = pipe._javascript_scan(ctx, pipe._open_pdf(ctx)[0])
    warn = next(i for i in inds if i.rule_id == "PDF_JS_STREAM_WARN")
    assert "nicht vollständig analysiert" in warn.title, warn.title
    assert "Analysetiefe" in warn.detail, warn.detail
    assert "nicht als 'sauber'" in warn.detail
    assert warn.weight is not None and warn.weight > config.SCORE_GREEN_MAX


def test_layout_forensics_reports_skipped_pages_once():
    """Regression (Runde 4): `except: continue` uebersprang Seiten spurlos.

    Gemessen vor dem Fix: eine Seite, deren Inhaltsstrom nicht lesbar ist,
    verschwand ohne jeden Indikator — die Layout-Forensik (unsichtbarer Text,
    Color-on-Color) lief fuer sie nicht, und nichts sagte das. Sind ALLE
    Seiten so gebaut, kam die Stufe mit 0 Punkten durch und die Datei war
    GRUEN. Die uebersprungenen Seiten werden gesammelt EINMAL gemeldet.
    """
    from malaz.core.scoring import compute_score

    class _UnreadablePage:
        def get(self, name):
            raise RuntimeError("Inhaltsstrom unlesbar")

    class _Pdf:
        pages: ClassVar[list] = [_UnreadablePage(), _UnreadablePage()]

    inds = PdfPipeline()._layout_forensics(_ctx(b"%PDF-1.7\n%%EOF"), _Pdf())
    hits = [i for i in inds if i.rule_id == "PDF_PAGE_SKIP_WARN"]
    assert len(hits) == 1, f"kein oder mehrfacher Befund: {[i.rule_id for i in inds]}"
    hit = hits[0]
    assert hit.severity.name == "MEDIUM"
    assert hit.weight is not None and hit.weight > config.SCORE_GREEN_MAX
    assert "1" in hit.title and "2" in hit.title, hit.title
    assert "nicht als 'sauber'" in hit.detail
    assert compute_score(inds).risk_level != RiskLevel.GREEN


def test_layout_forensics_still_analyses_the_readable_pages():
    """Gegenrichtung: eine defekte Seite darf die uebrigen nicht abschalten."""
    pdf = pikepdf.new()
    hidden = pikepdf.Stream(pdf, b"BT 3 Tr (geheim) Tj ET")

    class _UnreadablePage:
        def get(self, name):
            raise RuntimeError("kaputt")

    class _GoodPage:
        def get(self, name):
            return hidden

    class _Pdf:
        pages: ClassVar[list] = [_GoodPage(), _UnreadablePage()]

    inds = PdfPipeline()._layout_forensics(_ctx(b"%PDF-1.7\n%%EOF"), _Pdf())
    assert "PDF_INVISIBLE_TEXT" in _ids(inds)
    assert "PDF_PAGE_SKIP_WARN" in _ids(inds)


def test_layout_forensics_stops_at_the_shared_decompression_budget(monkeypatch):
    """PERF-002: 40 Seiten mit grossen Inhalts-Streams sprengten den Speicher.

    Der Per-Stream-Deckel (_MAX_STREAM_BYTES) begrenzt EINEN Stream, nicht die
    Summe ueber die Seiten: gemessen 68/132/260 MiB Peak bei 8/16/32
    Referenzen auf denselben 4-MiB-Stream (Datei 12,7 KiB). Jetzt gibt es EIN
    Budget fuer alle Streams/Seiten; wer es ueberschreitet, bekommt einen
    sichtbaren PDF_PARSE_WARN, und die Stufe stoppt — "nicht geprueft" ist
    nicht "sauber".
    """
    import malaz.pipelines.pdf_pipeline as module
    from malaz.core.scoring import compute_score

    stream_size = 256 * 1024
    # 1 MiB Budget = genau vier Seiten dieses Formats.
    monkeypatch.setattr(module, "_MAX_LAYOUT_BYTES", 4 * stream_size)

    pdf = pikepdf.new()
    hidden = pikepdf.Stream(pdf, b"BT 3 Tr (geheim) Tj ET")
    padding = pikepdf.Stream(pdf, b" " * stream_size)
    # S. 1 ist unsichtbarer Text, S. 2..39 sind teure Füllseiten, S. 40
    # versteckt wieder Text — hinter dem Budget und damit ungeprüft.
    pdf.pages.append(
        pikepdf.Page(
            pikepdf.Dictionary(
                Type=pikepdf.Name.Page,
                MediaBox=[0, 0, 612, 792],
                Contents=pdf.make_indirect(hidden),
            )
        )
    )
    for _ in range(38):
        pdf.pages.append(
            pikepdf.Page(
                pikepdf.Dictionary(
                    Type=pikepdf.Name.Page,
                    MediaBox=[0, 0, 612, 792],
                    Contents=pdf.make_indirect(padding),
                )
            )
        )
    pdf.pages.append(
        pikepdf.Page(
            pikepdf.Dictionary(
                Type=pikepdf.Name.Page,
                MediaBox=[0, 0, 612, 792],
                Contents=pdf.make_indirect(hidden),
            )
        )
    )
    buf = io.BytesIO()
    pdf.save(buf)
    ctx = _ctx(buf.getvalue())

    reads: list[int] = []
    real_read = module._read_stream_bounded

    def counting_read(stream, pikepdf_module):
        reads.append(1)
        return real_read(stream, pikepdf_module)

    monkeypatch.setattr(module, "_read_stream_bounded", counting_read)
    inds = module.PdfPipeline()._layout_forensics(ctx, module.PdfPipeline()._open_pdf(ctx)[0])

    # 40 Seiten, aber nur das Budget an Streams wird gelesen.
    assert len(reads) <= 5, f"{len(reads)} Streams gelesen"
    warn = next(i for i in inds if i.rule_id == "PDF_PARSE_WARN")
    assert "Dekompressionsbudget" in warn.title, warn.title
    assert "ab S. 6" in warn.title, warn.title
    assert warn.severity.name == "MEDIUM"
    assert warn.weight is not None and warn.weight > config.SCORE_GREEN_MAX
    assert "nicht als 'sauber'" in warn.detail
    assert compute_score(inds).risk_level != RiskLevel.GREEN
    # S. 1 wurde geprueft, S. 40 liegt hinter dem Budget und taucht nicht auf.
    invisible = next(i for i in inds if i.rule_id == "PDF_INVISIBLE_TEXT")
    assert "S. [1]" in invisible.title, invisible.title
    assert "40" not in invisible.title, invisible.title


# -- Echte PDFs: die Falschpositive, gemessen an 38 Dokumenten -------------- #
#
# Grundgesamtheit, gegen die hier gearbeitet wurde (nichts davon im Repo):
#   25 echte arXiv-Preprints (digital geboren, viele LaTeX-Varianten)
#   13 echte Behoerdenformulare (IRS, VA, GSA, CMS — gemeinfrei)
# VORHER: 12 von 13 Formularen ROT (90-100 Punkte), 1 arXiv-PDF ROT.
# NACHHER: 0 ROT in beiden Gruppen.
#
# Die Ursachen waren KEINE vier einzelnen Fehler, sondern ein Muster: dasselbe
# Artefakt wurde durch drei Brillen bewertet (Schluesselwort, Struktur,
# Inhalt), und formatuebliche Merkmale trugen Gewicht. Wie pdfid.py es haelt:
# formatuebliche Schluesselwoerter werden GEZAEHLT, nicht gewertet.


def _pdf(inhalt: bytes) -> bytes:
    """Ein minimales, aber echtes PDF um einen Inhalt herum."""
    return (
        b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/Contents 4 0 R>>endobj\n"
        b"4 0 obj<</Length " + str(len(inhalt)).encode() + b">>stream\n"
        + inhalt + b"\nendstream\nendobj\n"
        b"trailer<</Root 1 0 R>>\n%%EOF\n"
    )


def test_formatuebliche_schluesselwoerter_tragen_kein_gewicht():
    """/ObjStm, /AcroForm und die /EmbeddedFile-Typbezeichnung.

    Gemessen: ein modernes Formular startete allein damit ~20 Punkte tiefer —
    bevor irgendetwas analysiert war. Objekt-Streams sind seit PDF 1.5 (2003)
    der Standard; ein Formular ist ein Formular; und /EmbeddedFile ist der
    Name eines OBJEKTTYPS (die IRS-Formulare tragen ihn 8-11x, ohne dass die
    strukturelle Pruefung einen einzigen Anhang findet).
    """
    roh = _pdf(b"1 1 1 rg /ObjStm /AcroForm /EmbeddedFile (x) Tj")
    inds = PdfPipeline().analyze(_ctx(roh))
    regeln = {i.rule_id: i for i in inds}
    for regel in ("PDF_KW_ObjStm", "PDF_KW_AcroForm", "PDF_KW_EmbeddedFile"):
        # TEST-016: a missing indicator previously left this branch unentered
        # and the test green — the assertion must be that it EXISTS.
        assert regel in regeln, f"Indikator fehlt: {sorted(regeln)}"
        assert regeln[regel].weight == 0, f"{regel} darf kein Urteil tragen"
        assert regeln[regel].detail, "der Befund bleibt trotzdem sichtbar"


def test_javascript_praesenz_ist_gelb_nicht_gruen():
    """Mit Gewicht 0 wurde ein JS-PDF KOMPLETT GRUEN — das war zu weit.

    Ein PDF, das JavaScript enthaelt, ist ein "schau hin", kein Freibrief.
    Gemessen am Fixture js_no_autostart.pdf: YELLOW 30 -> GRUEN 0 mit
    Gewicht 0, mit 10 wieder YELLOW.
    """
    roh = _pdf(b"<</S/JavaScript/JS(app.alert\\(1\\);)>>")
    inds = PdfPipeline().analyze(_ctx(roh))
    js = [i for i in inds if i.rule_id in ("PDF_KW_JS", "PDF_KW_JavaScript")]
    assert js, "die JS-Praesenz muss als Befund erscheinen"
    # TEST-014: `any(i.weight ...)` was green for weight 1 (and for any other
    # weighted indicator in the list). The assertion has to be the VERDICT —
    # JavaScript presence alone must land in YELLOW, not GREEN.
    breakdown = compute_score(inds)
    assert breakdown.risk_level is RiskLevel.YELLOW
    assert breakdown.score > config.SCORE_GREEN_MAX


def test_dokumentuebliche_apis_sind_kein_anker():
    """app.launchURL ist das, was ein Formular mit Anleitung tut.

    GEMESSEN: auf 13 echten Behoerdenformularen feuerte von der alten
    Liste AUSSCHLIESSLICH "launchurl" — und mit Auto-Start gekoppelt ergab
    das CRITICAL/50, also ROT fuer ein IRS-Formular.
    """
    from malaz.pipelines.pdf_pipeline import _PDF_JS_COMMON, _PDF_JS_MALICIOUS

    assert "launchurl" in _PDF_JS_COMMON
    assert "submitform" in _PDF_JS_COMMON
    assert "launchurl" not in _PDF_JS_MALICIOUS
    # Die wirklich boesartigen Primitive bleiben.
    for primitiv in ("exportdataobject", "collab.geticon"):
        assert primitiv in _PDF_JS_MALICIOUS, primitiv


def test_js_fromcharcode_hidden_malicious_primitive_is_deobfuscated():
    code = "this.exportDataObject({cName:'x'});"
    js = "String.fromCharCode(" + ",".join(str(ord(c)) for c in code) + ");"
    inds = PdfPipeline()._analyze_js_text(js, auto_exec=False)
    ids = _ids(inds)
    assert "PDF_JS_DEOBFUSCATED" in ids
    assert "PDF_JS_SUSPICIOUS" not in ids, "das Primitiv war im Original nicht sichtbar"
    treffer = next(i for i in inds if i.rule_id == "PDF_JS_DEOBFUSCATED")
    # BUG-017: a primitive hidden by obfuscation rates like the plain one
    # (HIGH/30 without auto-start, CRITICAL/50 with); MEDIUM/15 used to fall
    # below SCORE_GREEN_MAX and turned the verdict GREEN.
    assert treffer.weight == 30
    assert treffer.severity.name == "HIGH"
    assert "exportdataobject" in treffer.detail.lower()


def test_js_fromcharcode_benign_greeting_is_not_deobfuscated():
    js = "String.fromCharCode(72,101,108,108,111);"
    inds = PdfPipeline()._analyze_js_text(js, auto_exec=False)
    ids = _ids(inds)
    assert "PDF_JS_OBFUSCATED" in ids
    assert "PDF_JS_DEOBFUSCATED" not in ids


def test_pdf_with_hidden_malicious_js_is_deobfuscated():
    code = "this.exportDataObject({cName:'x'});"
    js = "String.fromCharCode(" + ",".join(str(ord(c)) for c in code) + ");"
    data = _make_js_pdf(js, open_action=True)
    inds = PdfPipeline().analyze(_ctx(data))
    assert "PDF_JS_DEOBFUSCATED" in _ids(inds)


# -- SEC-013 / BUG-016: direct action dictionaries and object streams ------- #
#
# The raw keyword triage cannot see a Flate-compressed /ObjStm, and
# ``pdf.objects`` only yields objects whose TOP-LEVEL key is /JS: a direct
# ``/OpenAction << ... >>``, an annotation ``/A << ... >>`` or a field ``/AA``
# dictionary is part of its parent object. These fixtures are saved with
# object streams, so only the structural walk can find the payload.


def _objstm_pdf() -> "pikepdf.Pdf":
    pdf = pikepdf.new()
    pdf.pages.append(
        pikepdf.Page(
            pikepdf.Dictionary(
                Type=pikepdf.Name.Page,
                MediaBox=[0, 0, 612, 792],
                Contents=pikepdf.Stream(
                    pdf, b"BT /F1 12 Tf 72 72 Td (hello) Tj ET"
                ),
            )
        )
    )
    return pdf


def _save_objstm(pdf) -> bytes:
    buf = io.BytesIO()
    pdf.save(buf, object_stream_mode=pikepdf.ObjectStreamMode.generate)
    return buf.getvalue()


def test_direct_openaction_js_in_objstm_reaches_red():
    pdf = _objstm_pdf()
    pdf.Root.OpenAction = pikepdf.Dictionary(
        S=pikepdf.Name.JavaScript,
        JS=pikepdf.String("this.exportDataObject({cName:'x'}); ev" + "al(a+b);"),
    )
    data = _save_objstm(pdf)
    for marker in (b"/OpenAction", b"/JavaScript", b"exportDataObject"):
        assert marker not in data, marker

    inds = PdfPipeline().analyze(_ctx(data))
    susp = next(i for i in inds if i.rule_id == "PDF_JS_SUSPICIOUS")
    assert susp.severity.name == "CRITICAL"
    assert susp.weight == 50
    assert compute_score(inds).risk_level == RiskLevel.RED


def test_annotation_direct_action_js_reaches_red():
    payload = "this.exportDataObject({cName:'x'});"
    encoded = "String.fromCharCode(" + ",".join(str(ord(c)) for c in payload) + ");"
    pdf = _objstm_pdf()
    pdf.pages[0].Annots = pikepdf.Array(
        [
            pikepdf.Dictionary(
                Type=pikepdf.Name("/Annot"),
                Subtype=pikepdf.Name("/Text"),
                Rect=[0, 0, 100, 20],
                A=pikepdf.Dictionary(
                    S=pikepdf.Name.JavaScript, JS=pikepdf.String(encoded)
                ),
            )
        ]
    )
    data = _save_objstm(pdf)
    assert b"/JavaScript" not in data

    inds = PdfPipeline().analyze(_ctx(data))
    deobf = next(i for i in inds if i.rule_id == "PDF_JS_DEOBFUSCATED")
    # A click is not an auto-start -> HIGH/30; together with the obfuscation
    # signal (30) the file is RED. Before the fix the direct /A dictionary
    # was never extracted at all (GREEN 0).
    assert deobf.severity.name == "HIGH"
    assert deobf.weight == 30
    assert compute_score(inds).risk_level == RiskLevel.RED


@pytest.mark.parametrize("indirect", [False, True], ids=["direct", "indirect"])
def test_launch_action_in_objstm_is_critical(indirect):
    pdf = _objstm_pdf()
    action = pikepdf.Dictionary(
        S=pikepdf.Name.Launch, F=pikepdf.String("cmd.exe")
    )
    pdf.Root.OpenAction = pdf.make_indirect(action) if indirect else action
    data = _save_objstm(pdf)
    assert b"/Launch" not in data

    inds = PdfPipeline().analyze(_ctx(data))
    treffer = next(i for i in inds if i.rule_id == "PDF_KW_Launch")
    assert treffer.severity.name == "CRITICAL"
    assert treffer.weight == 50
    assert compute_score(inds).risk_level == RiskLevel.RED


def test_concatenated_eval_with_autostart_reaches_red():
    pdf = _objstm_pdf()
    pdf.Root.OpenAction = pikepdf.Dictionary(
        S=pikepdf.Name.JavaScript,
        JS=pikepdf.String('"ev"+"al(app.alert(1));"'),
    )
    data = _save_objstm(pdf)
    assert b"eval(" not in data

    inds = PdfPipeline().analyze(_ctx(data))
    deobf = next(i for i in inds if i.rule_id == "PDF_JS_DEOBFUSCATED")
    # BUG-017: the hidden primitive must rate like the plain one, never 15.
    assert deobf.severity.name == "CRITICAL"
    assert deobf.weight == 50
    assert compute_score(inds).risk_level == RiskLevel.RED


def test_benign_form_js_stays_below_red_and_has_no_launch_false_positive():
    pdf = _objstm_pdf()
    field = pdf.make_indirect(
        pikepdf.Dictionary(
            Type=pikepdf.Name("/Annot"),
            Subtype=pikepdf.Name("/Widget"),
            T=pikepdf.String("betrag"),
            FT=pikepdf.Name("/Tx"),
            Rect=[0, 0, 100, 20],
            AA=pikepdf.Dictionary(
                K=pikepdf.Dictionary(
                    S=pikepdf.Name.JavaScript,
                    # Ordinary form formatting. "/Launch" here is JavaScript
                    # STRING content, not a PDF action — it must not count.
                    JS=pikepdf.String(
                        "AFNumber_Format(2, 0, 0, 0, '', this); // /Launch"
                    ),
                )
            ),
        )
    )
    pdf.pages[0].Annots = pikepdf.Array([field])
    pdf.Root.AcroForm = pikepdf.Dictionary(Fields=pikepdf.Array([field]))
    data = _save_objstm(pdf)
    assert b"/Launch" not in data

    inds = PdfPipeline().analyze(_ctx(data))
    ids = _ids(inds)
    assert "PDF_JS_EXTRACTED" in ids  # the walk reached the direct /AA dict
    assert "PDF_KW_Launch" not in ids
    assert compute_score(inds).risk_level != RiskLevel.RED
