"""Property-based tests (Hypothesis) for parser robustness.

These complement the hand-written edge cases: for *arbitrary* inputs the
functions must never crash, raise, or violate their fundamental invariants.
"""

from hypothesis import given, settings
from hypothesis import strategies as st

from malaz.core.entropy import shannon_entropy
from malaz.core.filename_iocs import _build_rules
from malaz.core.magic import FileType, detect
from malaz.core.rtf_extract import iter_rtf_objects
from malaz.core.swf_extract import iter_swf_payloads
from malaz.security.escaping import escape_html
from malaz.security.safe_extract import is_safe_member_name

# Keep property runs fast; invariants, not fuzzing depth, are the point.
settings.register_profile("ci", max_examples=200, deadline=None)
settings.load_profile("ci")


@given(st.binary(max_size=4096))
def test_magic_detect_never_crashes(data):
    result = detect(data)
    assert isinstance(result, FileType)
    assert result.type
    assert result.mime


@given(st.binary(max_size=4096))
def test_entropy_in_range(data):
    entropy = shannon_entropy(data)
    assert 0.0 <= entropy <= 8.0
    if not data:
        assert entropy == 0.0


@given(st.text(max_size=512))
def test_escape_html_no_raw_markup(text):
    escaped = escape_html(text)
    # TEST-018: the old assertion (`"<" not in escaped or "&lt;" in escaped`)
    # passed for '<a><b>' -> '&lt;a><b>' — only the FIRST '<' escaped. Every
    # markup delimiter must be gone, not just one example of it.
    assert "<" not in escaped, escaped
    assert ">" not in escaped, escaped
    assert '"' not in escaped, escaped
    assert "'" not in escaped, escaped
    assert ">script" not in escaped


@given(st.text(max_size=512))
def test_safe_member_name_never_crashes(name):
    result = is_safe_member_name(name)
    assert isinstance(result, bool)


@given(st.text(min_size=3, max_size=64))
def test_traversal_names_rejected(name):
    # Any name containing a ".." path component is unsafe.
    if any(part == ".." for part in name.replace("\\", "/").split("/")):
        assert is_safe_member_name(name) is False


@given(st.binary(max_size=2048))
def test_rtf_extract_never_crashes(data):
    list(iter_rtf_objects(data))


@given(st.binary(max_size=2048))
def test_swf_extract_never_crashes(data):
    list(iter_swf_payloads(data))


@given(st.lists(st.text(max_size=80), min_size=0, max_size=10))
def test_ioc_rule_lines_never_crash(rules):
    # _build_rules compiles every line; invalid regexes become errors, never
    # exceptions.
    lines = [r + ";50;Beschreibung" for r in rules]
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "r.txt").write_text("\n".join(lines), encoding="utf-8")
        # _build_rules reads config.FILENAME_IOC_RULES_DIR — test the parser
        # through a monkeypatched path by calling the internal line loader.
        from malaz.core import filename_iocs as module

        original = module._iter_rule_lines

        def fake_lines():
            return [(str(Path(tmp) / "r.txt"), line) for line in lines]

        module._iter_rule_lines = fake_lines
        try:
            rules_out, errors = _build_rules()
            assert isinstance(rules_out, list)
            assert isinstance(errors, list)
        finally:
            module._iter_rule_lines = original


# -- AP3: Pfade, Alternate Data Streams, Zip-Slip, Limits --------------------
#
# Die Byte-Parser oben waren bereits abgedeckt. Was fehlte, war die
# *Namens*-Ebene: kein Pfad, der aus einem Archiv stammt, darf das
# Zielverzeichnis verlassen, ein NTFS-Stream werden oder einen Gerätenamen
# auflösen. Die Eigenschaft wird gegen ``posixpath.normpath`` geprüft, nicht
# gegen die Implementierung — sonst prüfte der Test sich selbst.

import posixpath  # noqa: E402

import pytest  # noqa: E402

from malaz import config  # noqa: E402
from malaz.core.archive import iter_zip_members  # noqa: E402
from malaz.core.eml_analysis import parse_mail  # noqa: E402
from malaz.core.lnk import parse_lnk  # noqa: E402
from malaz.core.ole_depth import directory_frames  # noqa: E402
from malaz.core.ooxml_rels import external_relationships  # noqa: E402
from malaz.pipelines.image_pipeline import ImagePipeline  # noqa: E402
from malaz.pipelines.pdf_pipeline import PdfPipeline  # noqa: E402
from malaz.pipelines.pe_pipeline import PePipeline  # noqa: E402
from malaz.security.escaping import mask_invisible  # noqa: E402
from malaz.security.limits import LimitExceeded, guard_file_size, guard_read_size  # noqa: E402
from malaz.security.safe_extract import (  # noqa: E402
    REASON_ADS,
    REASON_TRAVERSAL,
    unsafe_name_reason,
)

_NAME_PARTS = st.sampled_from(["a", "..", ".", "...", "CON", "nul.txt", "x ", "d:y", "file.txt:stream"])


@given(st.lists(_NAME_PARTS, min_size=1, max_size=6), st.sampled_from(["/", "\\"]))
def test_archive_names_never_resolve_outside_the_target(parts, separator):
    name = separator.join(parts)
    reason = unsafe_name_reason(name)
    if any(part.replace(" ", "") == ".." for part in parts):
        assert reason == REASON_TRAVERSAL
    if reason is None:
        collapsed = posixpath.normpath(name.replace("\\", "/"))
        assert collapsed != ".."
        assert not collapsed.startswith(("../", "/"))


@given(st.sampled_from([
    "/etc/passwd",
    "C:\\Windows\\System32\\evil.dll",
    "c:/windows/evil.dll",
    "\\\\server\\share\\evil.exe",
    "//server/share/evil.exe",
]))
def test_absolute_or_drive_paths_are_traversal(name):
    assert unsafe_name_reason(name) == REASON_TRAVERSAL


@given(st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789._ ", min_size=1, max_size=20))
def test_colon_names_are_ads(stem):
    # "file" davor: ein einzelner Buchstabe vor dem Doppelpunkt wäre nach
    # Windows-Regeln ein Laufwerksbuchstabe — richtigerweise Traversal.
    name = "file" + stem.strip(". ") + ":stream"
    assert unsafe_name_reason(name) == REASON_ADS


@given(st.text(alphabet="אבגדהוזחטיכלמנסעפצקרשתابجد", min_size=1, max_size=16))
def test_genuine_rtl_names_are_not_rejected(letters):
    # Echte hebräische/arabische Buchstaben sind Text, kein Bidi-Trick.
    assert unsafe_name_reason(letters + ".txt") is None


_BIDI_AND_INVISIBLE = (
    [chr(0)] + [chr(code) for code in range(0x202A, 0x202F)]
    + [chr(code) for code in range(0x2066, 0x206A)]
)


@given(st.text(max_size=64), st.lists(st.sampled_from(_BIDI_AND_INVISIBLE), max_size=8))
def test_mask_invisible_removes_every_bidi_control(text, controls):
    injected = text + "".join(controls) + "rechnung.pdf"
    masked = mask_invisible(injected)
    assert not any(char in _BIDI_AND_INVISIBLE for char in masked)


@given(st.integers(min_value=0, max_value=10**7))
def test_guard_read_size_never_exceeds_the_cap(size):
    read = guard_read_size(size)
    assert 0 <= read <= config.MAX_READ_SIZE
    assert read == min(size, config.MAX_READ_SIZE)


@given(st.integers(min_value=0, max_value=10**7))
def test_guard_file_size_accepts_everything_below_the_limit(size):
    guard_file_size(min(size, config.MAX_FILE_SIZE))


@given(st.integers(min_value=1, max_value=1_000_000))
def test_guard_file_size_rejects_everything_above_the_limit(extra):
    with pytest.raises(LimitExceeded):
        guard_file_size(config.MAX_FILE_SIZE + extra)


# -- AP3: Parser-Randfälle --------------------------------------------------
#
# Dieselben Eingabefunktionen wie die Atheris-Harnesses in ``fuzz/``. Sie
# laufen hier unter Windows/Hypothesis, weil Atheris dort nicht verfügbar ist
# (.github/CONTRIBUTING.md).


@settings(max_examples=60, deadline=None)
@given(st.binary(max_size=2048))
def test_pdf_pipeline_never_crashes(data):
    from pathlib import Path

    from malaz.models import AnalysisContext

    PdfPipeline().analyze(AnalysisContext(
        path=Path("<property>.pdf"), data=data, detected_type="pdf", size=len(data)
    ))


@settings(max_examples=60, deadline=None)
@given(
    st.binary(max_size=1024),
    st.sampled_from(["png", "jpeg", "gif", "tiff", "ico", "webp", "heic", "avif"]),
)
def test_image_pipeline_never_crashes(data, detected_type):
    from pathlib import Path

    from malaz.models import AnalysisContext

    ImagePipeline().analyze(AnalysisContext(
        path=Path(f"<property>.{detected_type}"),
        data=data,
        detected_type=detected_type,
        size=len(data),
    ))


@settings(max_examples=60, deadline=None)
@given(st.binary(max_size=2048))
def test_pe_structure_never_crashes(data):
    from pathlib import Path

    from malaz.models import AnalysisContext

    # Die drei externen Stufen starten Subprozesse (PowerShell/DIE/capa) und
    # parsen keine Bytes dieses Puffers — hier laufen nur die Parser.
    pipeline = PePipeline()
    pipeline._authenticode = lambda _ctx: []
    pipeline._die = lambda _ctx: []
    pipeline._capa = lambda _ctx: []
    pipeline.analyze(AnalysisContext(
        path=Path("<property>.exe"), data=data, detected_type="pe", size=len(data)
    ))


@given(st.binary(max_size=512))
def test_lnk_and_mail_parsers_never_crash(data):
    parse_lnk(data)
    parse_mail(data)


@given(st.binary(max_size=2048))
def test_office_containers_never_crash(data):
    directory_frames(data)
    external_relationships(data)


@given(st.binary(max_size=4096))
def test_zip_walk_stays_bounded_and_closes(data):
    engine = iter_zip_members(data)
    count = 0
    try:
        for _ in engine:
            count += 1
            assert count <= config.MAX_ARCHIVE_ENTRIES
    finally:
        engine.close()
