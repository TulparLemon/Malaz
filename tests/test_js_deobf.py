"""AP13: bounded static JavaScript deobfuscation."""

from __future__ import annotations

import json
import time

import pytest

from malaz.core.js_deobf import MAX_FROMCHARCODE_ARGS, MAX_INPUT, deobfuscate_js


def test_hex_and_unicode_escapes():
    assert "eval(" in deobfuscate_js(r"\x65val(")
    assert "eval(" in deobfuscate_js(r"\u0065val(")


def test_unescape_and_fromcharcode():
    assert "eval(" in deobfuscate_js("unescape('%65val(')")
    codes = ",".join(str(ord(char)) for char in "exportDataObject")
    assert "exportDataObject" in deobfuscate_js(f"String.fromCharCode({codes})")


def test_unescape_call_syntax_is_unchanged():
    # Whitespace between name/argument and the closing paren was accepted by
    # the old regex and still is; the payload keeps its own quotes intact.
    assert deobfuscate_js("unescape ( '%65val(' )") == "eval("
    assert deobfuscate_js("unescape('a')unescape('b')") == "ab"
    assert deobfuscate_js("x unescape('a') y unescape(\"b\") z") == "x a y b z"
    # No closing paren -> not a call, the text stays as it is.
    assert deobfuscate_js("unescape('a'") == "unescape('a'"


def test_literal_concatenation_is_joined():
    assert "eval(" in deobfuscate_js("'ev' + 'al('")


def test_escaped_backslash_is_not_decoded():
    # A literal backslash before the escape belongs to the source, not to a
    # string escape; decoding it would invent text.
    assert r"\x65" in deobfuscate_js(r"\\x65")


def test_fromcharcode_argument_cap():
    codes = ",".join("65" for _ in range(MAX_FROMCHARCODE_ARGS + 100))
    decoded = deobfuscate_js(f"String.fromCharCode({codes})")
    assert len(decoded) == MAX_FROMCHARCODE_ARGS


def test_input_cap():
    decoded = deobfuscate_js("A" * (MAX_INPUT + 1000))
    assert len(decoded) == MAX_INPUT


def test_lone_surrogates_never_escape_the_decoder():
    """BUG-019: decoded surrogates killed the UTF-8 report export.

    ``String.fromCharCode(55296)`` / ``unescape('%uD800')`` produced a lone
    UTF-16 surrogate; ``reporting.export.write_json`` then raised
    ``UnicodeEncodeError: surrogates not allowed`` and lost the whole report.
    """
    lone = deobfuscate_js("String.fromCharCode(55296,222)")
    assert not any(0xD800 <= ord(char) <= 0xDFFF for char in lone), repr(lone)
    assert "\ufffd" in lone
    lone.encode("utf-8")  # the export sink that used to raise
    json.dumps({"detail": lone}, ensure_ascii=False).encode("utf-8")

    assert "\ufffd" in deobfuscate_js("unescape('%uD800')")
    assert "\ufffd" in deobfuscate_js(r"\uD800")

    # A real surrogate PAIR is the character it encodes — not two replacement
    # characters and not two surrogates.
    grin = deobfuscate_js("String.fromCharCode(55357,56832)")
    assert "\U0001F600" in grin
    assert not any(0xD800 <= ord(char) <= 0xDFFF for char in grin)


@pytest.mark.parametrize(
    "unit", ["unescape('", "unescape("], ids=["many-quotes", "no-quotes"]
)
def test_unescape_scan_is_linear_on_200k_hostile_input(unit):
    """PERF-001: the backreference regex rescanned the rest per start position.

    GEMESSEN vor dem Fix: 0,5 s bei 25 k, 8 s bei 100 k und 32 s bei 200 k
    Zeichen (quadratisch). Der Vorwärtsscan darf dafuer nie zuruecklaufen;
    die Schranke ist grosszuegig, damit nur echte Quadratik anschlaegt.
    """
    payload = unit * (MAX_INPUT // len(unit))
    assert len(payload) <= MAX_INPUT
    assert len(payload) > MAX_INPUT - len(unit)

    started = time.perf_counter()
    decoded = deobfuscate_js(payload)
    elapsed = time.perf_counter() - started

    assert decoded == payload, "unvollstaendige Aufrufe duerfen Text nicht verlieren"
    assert elapsed < 10.0, f"{elapsed:.1f}s fuer {len(payload)} Zeichen"
