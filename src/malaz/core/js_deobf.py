"""Bounded static JavaScript deobfuscation for scripts, PDF JS, and HTML/SVG.

Decodes common string-hiding primitives WITHOUT executing anything:
``\\xNN`` / ``\\uNNNN`` / ES6 ``\\u{NNNN}`` escapes, ``unescape('%XX')``,
``String.fromCharCode``, array joins (incl. ``.reverse().join(...)``),
single-level string lookup tables, literal concatenation, and static
``atob('...')`` / ``window.atob('...')``.

All scanners are linear O(N) with hard input, expansion, table, and pass
budgets (Spec 016 / DET-003).
"""

from __future__ import annotations

import json
import re

from .script_deobf import (
    MAX_B64_DECODED_BYTES,
    MAX_CHAR_ITEMS,
    MAX_DEOBF_PASSES,
    MAX_JS_ARRAY_ITEMS,
    MAX_JS_ITEM_CHARS,
    MAX_JS_TABLES,
    MAX_TOTAL_DECODED_CHARS,
    REASON_B64_LIMIT,
    REASON_INPUT_LIMIT,
    REASON_OUTPUT_LIMIT,
    REASON_PASS_LIMIT,
    REASON_PS_LIMIT,
    REASON_TABLE_LIMIT,
    DeobfBudget,
    ScriptDeobfResult,
    decode_b64_bounded,
    decode_text_bytes,
)

# Backwards-compatible legacy constants (kept for existing callers/tests)
MAX_INPUT = 512 * 1024
MAX_PASSES = MAX_DEOBF_PASSES
MAX_FROMCHARCODE_ARGS = MAX_CHAR_ITEMS

_HEX_ESCAPE = re.compile(r"(?<!\\)\\x([0-9a-fA-F]{2})")
_UNICODE_ESCAPE = re.compile(r"(?<!\\)\\u([0-9a-fA-F]{4})")
_UNICODE_ES6_ESCAPE = re.compile(r"(?<!\\)\\u\{([0-9a-fA-F]{1,6})\}")
_FROM_CHAR_CODE = re.compile(
    r"String\s*\.\s*fromCharCode\s*\(([^()]*)\)", re.IGNORECASE
)
_CONCAT = re.compile(
    r"(['\"])([^'\"\\]*)\1\s*\+\s*(['\"])([^'\"\\]*)\3"
)
_PERCENT_U = re.compile(r"%u([0-9a-fA-F]{4})")
_PERCENT = re.compile(r"%([0-9a-fA-F]{2})")
# UTF-16 surrogate pairs as produced by fromCharCode/%uXXXX, and lone surrogates.
_SURROGATE_PAIR = re.compile("[\ud800-\udbff][\udc00-\udfff]")
_LONE_SURROGATE = re.compile("[\ud800-\udfff]")

_JS_TABLE_DECL_RE = re.compile(
    r"\b(?:var|let|const)[ \t]+([A-Za-z_$][A-Za-z0-9_$]{0,63})[ \t]*=[ \t]*\["
)
_JS_TABLE_INDEX_RE = re.compile(
    r"\b([A-Za-z_$][A-Za-z0-9_$]{0,63})[ \t]*\[[ \t]*(0x[0-9a-fA-F]{1,6}|\d{1,6})[ \t]*\]"
)

# Execution / DOM sinks that qualify static atob() as high-confidence (Spec 016 §3.2)
_JS_ATOB_SINKS = (
    "eval(",
    "new function",
    "<script",
    "activexobject",
    "wscript",
    "document.write",
    "document.createelement",
    "location.href",
    "powershell",
    "cmd.exe",
)


def _percent_decode(value: str) -> str:
    value = _PERCENT_U.sub(lambda match: chr(int(match.group(1), 16)), value)
    return _PERCENT.sub(lambda match: chr(int(match.group(1), 16)), value)


def _skip_space(text: str, pos: int) -> int:
    while pos < len(text) and text[pos].isspace():
        pos += 1
    return pos


def _decode_unescape_calls(text: str) -> str:
    """Decode ``unescape('...')`` in ONE linear forward pass."""
    if "unescape" not in text:
        return text
    out: list[str] = []
    pos = 0
    end = len(text)
    exhausted: dict[str, int] = {}
    while pos < end:
        start = text.find("unescape", pos)
        if start < 0:
            out.append(text[pos:])
            break
        open_paren = _skip_space(text, start + len("unescape"))
        if open_paren >= end or text[open_paren] != "(":
            out.append(text[pos:open_paren])
            pos = open_paren
            continue
        quote_at = _skip_space(text, open_paren + 1)
        if quote_at >= end or text[quote_at] not in "'\"":
            out.append(text[pos:quote_at])
            pos = quote_at
            continue
        quote = text[quote_at]
        search = quote_at + 1
        if search >= exhausted.get(quote, end + 1):
            out.append(text[pos:search])
            pos = search
            continue
        close = text.find(quote, search)
        if close < 0:
            exhausted[quote] = search
            out.append(text[pos:search])
            pos = search
            continue
        after = _skip_space(text, close + 1)
        if after < end and text[after] == ")":
            out.append(text[pos:start])
            out.append(_percent_decode(text[search:close]))
            pos = after + 1
            continue
        out.append(text[pos : quote_at + 1])
        pos = quote_at + 1
    return "".join(out)


def _normalise_surrogates(text: str) -> str:
    """Combine UTF-16 surrogate pairs and replace lone surrogates with U+FFFD."""

    def _combine(match: re.Match) -> str:
        high, low = match.group(0)
        return chr(0x10000 + ((ord(high) - 0xD800) << 10) + (ord(low) - 0xDC00))

    return _LONE_SURROGATE.sub("\ufffd", _SURROGATE_PAIR.sub(_combine, text))


def _decode_es6_unicode(text: str) -> tuple[str, bool]:
    if "\\u{" not in text:
        return text, False
    changed = False

    def _repl(match: re.Match) -> str:
        nonlocal changed
        cp = int(match.group(1), 16)
        if 0 <= cp <= 0x10FFFF:
            changed = True
            return chr(cp)
        return match.group(0)

    out = _UNICODE_ES6_ESCAPE.sub(_repl, text)
    return out, changed


def _decode_from_char_code(text: str) -> tuple[str, bool, bool]:
    """Decode ``String.fromCharCode(...)`` with ``MAX_CHAR_ITEMS`` cap."""
    if "fromcharcode" not in text.lower():
        return text, False, False
    changed = False
    limit_hit = False

    def _repl(match: re.Match) -> str:
        nonlocal changed, limit_hit
        raw_parts = match.group(1).split(",")
        if len(raw_parts) > MAX_CHAR_ITEMS:
            limit_hit = True
            return match.group(0)
        chars: list[str] = []
        for part in raw_parts:
            tok = part.strip()
            if not tok:
                continue
            try:
                code = int(tok, 0)
            except ValueError:
                continue
            if 0 <= code <= 0x10FFFF:
                chars.append(chr(code))
        if not chars:
            return match.group(0)
        changed = True
        return "".join(chars)

    out = _FROM_CHAR_CODE.sub(_repl, text)
    return out, changed, limit_hit


def _read_js_quoted_literal(text: str, start: int) -> tuple[str, int] | None:
    """Read one single- or double-quoted JS string literal linearly."""
    n = len(text)
    if start >= n or text[start] not in ("'", '"'):
        return None
    q = text[start]
    i = start + 1
    buf: list[str] = []
    while i < n:
        c = text[i]
        if c == "\\" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "n":
                buf.append("\n")
            elif nxt == "r":
                buf.append("\r")
            elif nxt == "t":
                buf.append("\t")
            else:
                buf.append(nxt)
            i += 2
            continue
        if c == q:
            return "".join(buf), i + 1
        if c in ("\r", "\n"):
            return None
        buf.append(c)
        i += 1
    return None


def _parse_js_string_array_inner(
    inner: str, *, max_items: int, max_item_chars: int = MAX_JS_ITEM_CHARS
) -> tuple[list[str] | None, bool]:
    """Parse comma-separated JS string literals linearly.

    Returns ``(items_or_none, limit_hit)``.
    """
    items: list[str] = []
    i = 0
    n = len(inner)
    expect_item = True
    while i < n:
        while i < n and inner[i] in " \t\r\n":
            i += 1
        if i >= n:
            break
        if not expect_item:
            if inner[i] == ",":
                expect_item = True
                i += 1
                continue
            return None, False
        lit = _read_js_quoted_literal(inner, i)
        if lit is None:
            return None, False
        val, end = lit
        if len(val) > max_item_chars:
            return None, True
        items.append(val)
        if len(items) > max_items:
            return None, True
        i = end
        expect_item = False
    if not items:
        return None, False
    return items, False


def merge_js_array_joins(
    text: str,
    *,
    max_items: int = MAX_JS_ARRAY_ITEMS,
    max_output: int = MAX_TOTAL_DECODED_CHARS,
) -> tuple[str, bool, bool]:
    """Linear O(N) resolver for JS ``['a','b'].join('')`` & ``.reverse().join('')``.

    Returns ``(merged_text, changed, limit_hit)`` (Spec 016 §3.2).
    """
    marker = ".join("
    if marker not in text:
        return text, False, False

    out: list[str] = []
    out_len = 0
    pos = 0
    n = len(text)
    changed = False
    limit_hit = False

    while pos < n:
        idx = text.find(marker, pos)
        if idx == -1:
            tail = text[pos:]
            if out_len + len(tail) > max_output:
                limit_hit = True
                out.append(tail[: max(0, max_output - out_len)])
            else:
                out.append(tail)
            break

        # Parse separator inside .join(...)
        j = idx + len(marker)
        while j < n and text[j] in " \t":
            j += 1
        sep_str: str | None = None
        after_sep = j
        if j < n and text[j] in ("'", '"'):
            lit = _read_js_quoted_literal(text, j)
            if lit is not None and len(lit[0]) <= 8:
                sep_str, after_sep = lit
        elif j < n and text[j] == ")":
            sep_str = ","
            after_sep = j

        if sep_str is not None:
            k = after_sep
            while k < n and text[k] in " \t":
                k += 1
            if k < n and text[k] == ")":
                # Check optional .reverse() immediately before .join(
                rb = idx - 1
                while rb >= pos and text[rb] in " \t\r\n":
                    rb -= 1
                reversed_arr = False
                if rb >= pos and text[rb] == ")":
                    rev_open = rb - 1
                    while rev_open >= pos and text[rev_open] in " \t":
                        rev_open -= 1
                    if rev_open >= pos and text[rev_open] == "(":
                        rev_start = rev_open - len(".reverse")
                        if rev_start >= pos and text[rev_start:rev_open] == ".reverse":
                            reversed_arr = True
                            rb = rev_start - 1
                            while rb >= pos and text[rb] in " \t\r\n":
                                rb -= 1

                if rb >= pos and text[rb] == "]":
                    search_start = max(pos, rb - 131_072)
                    lb = text.rfind("[", search_start, rb)
                    if lb != -1:
                        items, arr_lim = _parse_js_string_array_inner(
                            text[lb + 1 : rb], max_items=max_items
                        )
                        if arr_lim:
                            limit_hit = True
                        elif items is not None and (len(items) >= 2 or reversed_arr):
                            if reversed_arr:
                                items = list(reversed(items))
                            merged = json.dumps(sep_str.join(items))
                            prefix = text[pos:lb]
                            if out_len + len(prefix) + len(merged) > max_output:
                                limit_hit = True
                                out.append(text[pos : pos + max(0, max_output - out_len)])
                                pos = n
                                break
                            out.append(prefix)
                            out.append(merged)
                            out_len += len(prefix) + len(merged)
                            changed = True
                            pos = k + 1
                            continue

        seg = text[pos : idx + len(marker)]
        if out_len + len(seg) > max_output:
            limit_hit = True
            out.append(seg[: max(0, max_output - out_len)])
            pos = n
            break
        out.append(seg)
        out_len += len(seg)
        pos = idx + len(marker)

    if not changed and not limit_hit:
        return text, False, False
    return "".join(out), True, limit_hit


def _resolve_js_string_tables(
    text: str, *, max_output: int
) -> tuple[str, bool, bool, str]:
    """Single-level ``var/let/const _arr = ['a', 'b']; _arr[0x0]`` lookup resolver.

    Returns ``(new_text, changed, limit_hit, limit_reason)``.
    """
    if "[" not in text or ("var" not in text and "let" not in text and "const" not in text):
        return text, False, False, ""

    tables: dict[str, list[str]] = {}
    limit_hit = False
    limit_reason = ""
    n = len(text)

    next_rb = -1
    next_lb = -1
    for m in _JS_TABLE_DECL_RE.finditer(text):
        ident = m.group(1)
        if ident not in tables and len(tables) >= MAX_JS_TABLES:
            limit_hit = True
            limit_reason = REASON_TABLE_LIMIT
            break
        m_end = m.end()
        if m_end > next_rb:
            next_rb = text.find("]", m_end)
            if next_rb == -1:
                break
        if m_end > next_lb:
            next_lb = text.find("[", m_end)
        # Skip in O(1) when another '[' precedes the matching ']' (not a flat string array)
        if next_lb != -1 and next_lb < next_rb:
            continue
        rb = next_rb
        items, arr_lim = _parse_js_string_array_inner(
            text[m_end:rb],
            max_items=MAX_JS_ARRAY_ITEMS,
            max_item_chars=MAX_JS_ITEM_CHARS,
        )
        if arr_lim:
            limit_hit = True
            limit_reason = REASON_TABLE_LIMIT
            continue
        if items is not None:
            tables[ident] = items

    if not tables:
        return text, False, limit_hit, limit_reason

    out: list[str] = []
    out_len = 0
    pos = 0
    changed = False

    for m in _JS_TABLE_INDEX_RE.finditer(text):
        ident = m.group(1)
        arr = tables.get(ident)
        if arr is None:
            continue
        try:
            idx = int(m.group(2), 0)
        except ValueError:
            continue
        if not (0 <= idx < len(arr)):
            continue
        prefix = text[pos : m.start()]
        repl = json.dumps(arr[idx])
        if out_len + len(prefix) + len(repl) > max_output:
            limit_hit = True
            limit_reason = REASON_OUTPUT_LIMIT
            out.append(prefix[: max(0, max_output - out_len)])
            pos = n
            break
        out.append(prefix)
        out.append(repl)
        out_len += len(prefix) + len(repl)
        pos = m.end()
        changed = True

    if pos < n:
        tail = text[pos:]
        if out_len + len(tail) > max_output:
            limit_hit = True
            limit_reason = REASON_OUTPUT_LIMIT
            out.append(tail[: max(0, max_output - out_len)])
        else:
            out.append(tail)

    if not changed:
        return text, False, limit_hit, limit_reason
    return "".join(out), True, limit_hit, limit_reason


def _decode_js_atob_calls(
    text: str,
    *,
    budget: DeobfBudget,
    max_output: int,
    dry_run: bool = False,
) -> tuple[str, bool, bool, bool, str]:
    """Linear O(N) resolver for static ``atob('...')`` / ``window.atob('...')``.

    Replaces valid printable text payloads inline as JSON-quoted JS string literals
    so follow-up passes can concatenate ``atob(...)+atob(...)``.
    Returns ``(new_text, changed, high_confidence, limit_hit, limit_reason)``.
    """
    if "atob" not in text:
        return text, False, False, False, ""

    out: list[str] = []
    out_len = 0
    pos = 0
    n = len(text)
    changed = False
    high_conf = False
    limit_hit = False
    limit_reason = ""

    while pos < n:
        idx = text.find("atob", pos)
        if idx == -1:
            tail = text[pos:]
            if out_len + len(tail) > max_output:
                limit_hit = True
                limit_reason = REASON_OUTPUT_LIMIT
                out.append(tail[: max(0, max_output - out_len)])
            else:
                out.append(tail)
            break

        # Ensure word boundary or window./self./globalThis. prefix before 'atob'
        call_start = idx
        valid_prefix = True
        if idx > 0:
            prev_ch = text[idx - 1]
            if prev_ch.isalnum() or prev_ch in ("_", "$"):
                valid_prefix = False
            elif prev_ch == ".":
                for pfx in ("window.", "self.", "globalThis."):
                    ps = idx - len(pfx)
                    if ps >= pos and text[ps:idx] == pfx:
                        if ps > pos and (text[ps - 1].isalnum() or text[ps - 1] in ("_", "$")):
                            valid_prefix = False
                        else:
                            call_start = ps
                        break
                else:
                    valid_prefix = False

        if valid_prefix:
            open_p = _skip_space(text, idx + 4)
            if open_p < n and text[open_p] == "(":
                q_at = _skip_space(text, open_p + 1)
                lit = _read_js_quoted_literal(text, q_at)
                if lit is not None:
                    b64_str, after_lit = lit
                    close_p = _skip_space(text, after_lit)
                    if close_p < n and text[close_p] == ")":
                        if not dry_run:
                            if budget.used_b64_blobs >= budget.max_b64_blobs:
                                limit_hit = True
                                limit_reason = REASON_B64_LIMIT
                                seg = text[pos:]
                                out.append(seg[: max(0, max_output - out_len)])
                                break
                            budget.used_b64_blobs += 1
                        raw, b64_lim = decode_b64_bounded(
                            b64_str, max_bytes=MAX_B64_DECODED_BYTES
                        )
                        if b64_lim:
                            limit_hit = True
                            limit_reason = REASON_B64_LIMIT
                        elif raw is not None:
                            decoded = decode_text_bytes(raw)
                            if decoded is not None:
                                if dry_run:
                                    return text, True, False, False, ""
                                repl = json.dumps(decoded)
                                prefix = text[pos:call_start]
                                if out_len + len(prefix) + len(repl) > max_output:
                                    limit_hit = True
                                    limit_reason = REASON_OUTPUT_LIMIT
                                    out.append(prefix[: max(0, max_output - out_len)])
                                    break
                                out.append(prefix)
                                out.append(repl)
                                out_len += len(prefix) + len(repl)
                                changed = True
                                low_dec = decoded.lower()
                                if any(sink in low_dec for sink in _JS_ATOB_SINKS):
                                    high_conf = True
                                pos = close_p + 1
                                continue

        seg = text[pos : idx + 4]
        if out_len + len(seg) > max_output:
            limit_hit = True
            limit_reason = REASON_OUTPUT_LIMIT
            out.append(seg[: max(0, max_output - out_len)])
            break
        out.append(seg)
        out_len += len(seg)
        pos = idx + 4

    if not changed:
        return text, False, False, limit_hit, limit_reason
    return "".join(out), True, high_conf, limit_hit, limit_reason


def _run_js_single_pass(
    current: str,
    *,
    max_out: int,
    budget: DeobfBudget,
    result: ScriptDeobfResult,
    dry_run: bool = False,
) -> tuple[str, bool]:
    """One JS deobfuscation pass (Spec 016 §3.3.4 order)."""
    before = current
    step_changed = False

    # 1. Escapes (\xNN, \uNNNN, \u{NNNN}, unescape, fromCharCode)
    cand = _HEX_ESCAPE.sub(lambda match: chr(int(match.group(1), 16)), current)
    cand = _UNICODE_ESCAPE.sub(lambda match: chr(int(match.group(1), 16)), cand)
    if cand != current:
        step_changed = True
        if dry_run:
            return current, True
        current = cand

    es6_text, es6_chg = _decode_es6_unicode(current)
    if es6_chg:
        step_changed = True
        if dry_run:
            return current, True
        current = es6_text
        result.add_technique("js_unicode_es6", high_confidence=False)

    un_text = _decode_unescape_calls(current)
    if un_text != current:
        step_changed = True
        if dry_run:
            return current, True
        current = un_text

    fcc_text, fcc_chg, fcc_lim = _decode_from_char_code(current)
    if fcc_lim and not dry_run:
        result.set_limit(REASON_PS_LIMIT)
    if fcc_chg:
        step_changed = True
        if dry_run:
            return current, True
        current = fcc_text

    # 2. Array joins (['a','b'].join(''), .reverse().join(''))
    aj_text, aj_chg, aj_lim = merge_js_array_joins(current, max_output=max_out)
    if aj_lim and not dry_run:
        result.set_limit(REASON_TABLE_LIMIT)
    if aj_chg:
        step_changed = True
        if dry_run:
            return current, True
        current = aj_text
        result.add_technique("js_array_join", high_confidence=False)

    # 3. Single-level string lookup tables
    tb_text, tb_chg, tb_lim, tb_reason = _resolve_js_string_tables(
        current, max_output=max_out
    )
    if tb_lim and not dry_run:
        result.set_limit(tb_reason or REASON_TABLE_LIMIT)
    if tb_chg:
        step_changed = True
        if dry_run:
            return current, True
        current = tb_text
        result.add_technique("js_string_table", high_confidence=False)

    # 4. JS string concatenation ('a' + 'b')
    cc_text = _CONCAT.sub(
        lambda match: json.dumps(match.group(2) + match.group(4)), current
    )
    if cc_text != current:
        if len(cc_text) > max_out:
            if not dry_run:
                result.set_limit(REASON_OUTPUT_LIMIT)
        else:
            step_changed = True
            if dry_run:
                return current, True
            current = cc_text

    # 5. Static atob('...') / window.atob('...')
    at_text, at_chg, at_hi, at_lim, at_reason = _decode_js_atob_calls(
        current, budget=budget, max_output=max_out, dry_run=dry_run
    )
    if at_lim and not dry_run:
        result.set_limit(at_reason or REASON_B64_LIMIT)
    if at_chg:
        step_changed = True
        if dry_run:
            return current, True
        current = at_text
        result.add_technique("js_atob", high_confidence=at_hi)

    return current, (step_changed or current != before)


def deobfuscate_js_detailed(
    text: str,
    *,
    explicit_script: bool = False,
    budget: DeobfBudget | None = None,
    charge_input: bool = True,
) -> ScriptDeobfResult:
    """Statically deobfuscate JavaScript under strict DoS & budget limits."""
    b = budget if budget is not None else DeobfBudget()

    if b.used_extra_chars >= b.max_total_chars:
        res = ScriptDeobfResult(text=_normalise_surrogates(text))
        res.set_limit(REASON_OUTPUT_LIMIT)
        return res

    input_truncated = False
    if charge_input:
        if b.used_input_chars >= b.max_input_chars:
            res = ScriptDeobfResult(text=_normalise_surrogates(text))
            if explicit_script:
                res.set_limit(REASON_INPUT_LIMIT)
            return res
        allowed, fits = b.charge_chunk_input(len(text))
        if not fits:
            input_truncated = True
            work = text[:allowed]
        else:
            work = text
    else:
        if len(text) > MAX_TOTAL_DECODED_CHARS:
            input_truncated = True
        work = text[:MAX_TOTAL_DECODED_CHARS]

    chunk_input_len = len(work)
    res = ScriptDeobfResult(text=work)
    current = work
    made_change_on_last = False

    for _pass in range(MAX_DEOBF_PASSES):
        max_out = min(
            MAX_TOTAL_DECODED_CHARS,
            chunk_input_len + b.remaining_extra(),
        )
        current, chg = _run_js_single_pass(
            current, max_out=max_out, budget=b, result=res
        )
        made_change_on_last = chg
        if chg:
            res.changed = True
        if not chg or res.limit_hit:
            break

    if made_change_on_last and not res.limit_hit:
        max_out = min(
            MAX_TOTAL_DECODED_CHARS,
            chunk_input_len + b.remaining_extra(),
        )
        _, would_chg = _run_js_single_pass(
            current, max_out=max_out, budget=b, result=res, dry_run=True
        )
        if would_chg:
            res.set_limit(REASON_PASS_LIMIT)

    res.text = _normalise_surrogates(current)
    b.used_extra_chars += max(0, len(res.text) - chunk_input_len)

    if input_truncated and (explicit_script or res.changed or res.decoded_blobs):
        res.set_limit(REASON_INPUT_LIMIT)

    return res


def deobfuscate_js(text: str) -> str:
    """Backwards-compatible wrapper returning only the decoded JS string."""
    return deobfuscate_js_detailed(text).text
