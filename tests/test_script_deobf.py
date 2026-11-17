"""Tests for static script deobfuscation and the VBA deep-analysis heuristics."""

from malaz.core.script_deobf import extract_vba_strings
from malaz.pipelines.office_pipeline import OfficePipeline

# -- extract_vba_strings --------------------------------------------------- #


def test_literal_concatenation():
    assert extract_vba_strings('x = "pow" & "ershell"') == ["powershell"]


def test_chr_concatenation():
    # Chr(112)=p, Chr(111)=o, Chr(119)=w
    assert extract_vba_strings("x = Chr(112) & Chr(111) & Chr(119)") == ["pow"]


def test_mixed_literal_and_chr():
    # "cmd" & Chr(46)="." & "exe"
    assert extract_vba_strings('x = "cmd" & Chr(46) & "exe"') == ["cmd.exe"]


def test_single_plain_literal_is_skipped():
    # Not obfuscated -> the raw scan already sees it.
    assert extract_vba_strings('x = "hello world"') == []


def test_single_chr_is_returned():
    assert extract_vba_strings("x = Chr(65)") == ["A"]


def test_line_continuation_is_joined():
    code = '"pow" _\n& "ershell"'
    assert extract_vba_strings(code) == ["powershell"]


def test_plus_is_not_concatenation():
    # '+' is not the VBA string connector we reconstruct.
    assert extract_vba_strings('x = "a" + "b"') == []


def test_escaped_quotes():
    # "say ""hi""" -> say "hi"
    assert extract_vba_strings('x = "say ""hi""" & "!"') == ['say "hi"!']


def test_multiple_separate_runs():
    code = 'a = "foo" & "bar"\nb = "x" & "y"'
    assert extract_vba_strings(code) == ["foobar", "xy"]


# -- _vba_deep_indicators -------------------------------------------------- #


def _rule_ids(indicators):
    return {i.rule_id for i in indicators}


def test_obfuscated_keyword_reconstructed():
    p = OfficePipeline()
    # "powershell" is hidden (only appears once reassembled), not in raw code.
    out = p._vba_deep_indicators("x = 1", ["powershell -enc abc"], has_autoexec=False)
    assert "OFFICE_VBA_OBFUSCATED" in _rule_ids(out)


def test_obfuscated_keyword_anchors_with_autoexec():
    p = OfficePipeline()
    out = p._vba_deep_indicators("auto_open", ["net.webclient"], has_autoexec=True)
    ind = next(i for i in out if i.rule_id == "OFFICE_VBA_OBFUSCATED")
    assert ind.severity.name == "CRITICAL"


def test_not_obfuscated_when_visible_raw():
    p = OfficePipeline()
    # "powershell" already in raw code -> no obfuscation indicator.
    out = p._vba_deep_indicators("run powershell now", ["powershell"], has_autoexec=False)
    assert "OFFICE_VBA_OBFUSCATED" not in _rule_ids(out)


def test_download_execute_chain_detected():
    p = OfficePipeline()
    code = 'URLDownloadToFile 0, url, path, 0\nShell "cmd.exe"'
    out = p._vba_deep_indicators(code.lower(), [], has_autoexec=False)
    assert "OFFICE_VBA_DL_EXEC" in _rule_ids(out)


def test_download_alone_is_not_a_chain():
    p = OfficePipeline()
    out = p._vba_deep_indicators("urldownloadtofile 0, url, path", [], has_autoexec=False)
    assert "OFFICE_VBA_DL_EXEC" not in _rule_ids(out)


def test_encoded_powershell_detected():
    p = OfficePipeline()
    out = p._vba_deep_indicators('shell "powershell -encodedcommand jqbe"', [], False)
    assert "OFFICE_VBA_ENC_PS" in _rule_ids(out)


def test_lolbin_detected():
    p = OfficePipeline()
    out = p._vba_deep_indicators('shell "regsvr32 /s /u foo.dll"', [], False)
    assert "OFFICE_VBA_LOLBIN" in _rule_ids(out)


def test_benign_macro_has_no_deep_indicators():
    p = OfficePipeline()
    out = p._vba_deep_indicators("msgbox \"hello world\"\nrange(\"a1\").value = 1", [], False)
    assert out == []
