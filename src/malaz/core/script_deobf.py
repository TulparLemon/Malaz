"""Purely static, bounded script deobfuscation (PowerShell, Batch, VBA).

100% Python standard library, strictly offline, zero code execution (never
``eval``, ``exec``, ``str.format`` on attacker input, or subprocesses).
Every parser and scanner is linear O(N) with hard input, expansion, pass,
and decompression budgets (Spec 016 / DET-003).
"""

from __future__ import annotations

import base64
import binascii
import re
import zlib
from dataclasses import dataclass, field

from . import magic

# --------------------------------------------------------------------------- #
# Hard safety & completeness limits (Spec 016 §3.4)
# --------------------------------------------------------------------------- #

MAX_DEOBF_INPUT = 512 * 1024
MAX_TOTAL_DECODED_CHARS = 512 * 1024
MAX_DEOBF_PASSES = 3
MAX_PS_FORMAT_ARGS = 64
MAX_CHAR_ITEMS = 8_192
MAX_B64_BLOBS = 32
MAX_B64_DECODED_BYTES = 256 * 1024
MAX_DECOMPRESSED_BYTES = 512 * 1024
MAX_BATCH_VARS = 256
MAX_BATCH_VAR_VALUE = 2_048
MAX_JS_TABLES = 64
MAX_JS_ARRAY_ITEMS = 512
MAX_JS_ITEM_CHARS = 2_048

# Canonical limit reasons (Spec 016 §4.2)
REASON_INPUT_LIMIT = "Eingabe über 512-KiB-Limit"
REASON_OUTPUT_LIMIT = "Ausgabe-Budget (512 KiB) erreicht"
REASON_DECOMP_LIMIT = "GZip/Deflate-Dekompressionslimit (512 KiB) erreicht"
REASON_B64_LIMIT = "Base64-Blob-Budget überschritten"
REASON_PASS_LIMIT = "Maximale Deobfuskations-Tiefe erreicht"
REASON_TABLE_LIMIT = "Batch-Variablen- oder JS-Tabellen-Limit erreicht"
REASON_PS_LIMIT = "PowerShell-Format- oder Char-Array-Limit erreicht"

# --------------------------------------------------------------------------- #
# Shared dataclasses & budget accounting (Spec 016 §3.2)
# --------------------------------------------------------------------------- #


@dataclass
class DeobfBudget:
    """Cascade- and multi-chunk-safe document budget."""

    max_input_chars: int = MAX_DEOBF_INPUT
    max_total_chars: int = MAX_TOTAL_DECODED_CHARS
    max_b64_blobs: int = MAX_B64_BLOBS
    used_input_chars: int = 0
    used_extra_chars: int = 0
    used_b64_blobs: int = 0

    def charge_chunk_input(self, n_chars: int) -> tuple[int, bool]:
        """Charge one standalone chunk's input size once.

        Returns ``(allowed_chars, fits_completely)``.
        """
        remaining = max(0, self.max_input_chars - self.used_input_chars)
        if n_chars <= remaining:
            self.used_input_chars += n_chars
            return n_chars, True
        self.used_input_chars = self.max_input_chars
        return remaining, False

    def remaining_extra(self) -> int:
        return max(0, self.max_total_chars - self.used_extra_chars)


@dataclass
class ScriptDeobfResult:
    """Structured result of one static deobfuscation pass/pipeline."""

    text: str
    techniques: list[str] = field(default_factory=list)
    high_confidence_techniques: list[str] = field(default_factory=list)
    decoded_blobs: list[str] = field(default_factory=list)
    changed: bool = False
    limit_hit: bool = False
    limit_reason: str = ""

    def add_technique(self, tech: str, *, high_confidence: bool = False) -> None:
        if tech not in self.techniques:
            self.techniques.append(tech)
        if high_confidence and tech not in self.high_confidence_techniques:
            self.high_confidence_techniques.append(tech)

    def set_limit(self, reason: str) -> None:
        self.limit_hit = True
        if not self.limit_reason:
            self.limit_reason = reason


# --------------------------------------------------------------------------- #
# Existing VBA string / Chr() reconstruction (unchanged contract)
# --------------------------------------------------------------------------- #

_VBA_TOKEN = re.compile(
    r'(?:"(?:[^"]|"")*"|\bChr[W$]?\s*\(\s*\d{1,5}\s*\))', re.IGNORECASE
)
_VBA_CHR_FULL = re.compile(r"Chr[W$]?\s*\(\s*(\d{1,5})\s*\)", re.IGNORECASE)
_VBA_CONNECTOR = re.compile(
    r"\A\s*(?:_[ \t]*\r?\n\s*)?&\s*(?:_[ \t]*\r?\n\s*)?\Z"
)


def _token_value(token: str) -> str:
    """Return the runtime string value of one constant VBA token."""
    token = token.strip()
    m = _VBA_CHR_FULL.fullmatch(token)
    if m:
        code = int(m.group(1))
        return chr(code)
    if len(token) >= 2 and token.startswith('"') and token.endswith('"'):
        return token[1:-1].replace('""', '"')
    return ""


def extract_vba_strings(code: str) -> list[str]:
    """Reconstruct strings assembled via VBA literal/``Chr`` concatenation."""
    results: list[str] = []
    tokens = list(_VBA_TOKEN.finditer(code))
    i = 0
    n = len(tokens)
    while i < n:
        run = [tokens[i]]
        j = i
        while j + 1 < n:
            between = code[tokens[j].end() : tokens[j + 1].start()]
            if _VBA_CONNECTOR.fullmatch(between):
                run.append(tokens[j + 1])
                j += 1
            else:
                break
        involves_chr = any(_VBA_CHR_FULL.fullmatch(t.group(0).strip()) for t in run)
        if len(run) >= 2 or involves_chr:
            value = "".join(_token_value(t.group(0)) for t in run)
            if value.strip():
                results.append(value)
        i = j + 1
    return results


# --------------------------------------------------------------------------- #
# Bounded Base64, GZip/Deflate, and text decoding helpers
# --------------------------------------------------------------------------- #

_B64_WS_TRANS = str.maketrans("", "", " \t\r\n")
_PS_ENCODED_RE = re.compile(
    r"(?:-(?:encodedcommand|enc|ec)\b)[ \t]+([A-Za-z0-9+/]{16,65536}={0,2})",
    re.IGNORECASE,
)


def decode_b64_bounded(
    raw_b64: str, *, max_bytes: int = MAX_B64_DECODED_BYTES
) -> tuple[bytes | None, bool]:
    """Decode Base64 strictly bounded before allocation.

    Returns ``(decoded_bytes, limit_hit)``.
    """
    clean = raw_b64.translate(_B64_WS_TRANS)
    if len(clean) < 8:
        return None, False
    est_bytes = (len(clean) * 3) // 4
    if est_bytes > max_bytes:
        return None, True
    rem = len(clean) % 4
    if rem == 1:
        return None, False
    padded = clean if rem == 0 else clean + ("=" * (4 - rem))
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None, False
    if len(raw) > max_bytes:
        return None, True
    return raw, False


def decompress_bounded(
    data: bytes, *, wbits: int, max_bytes: int = MAX_DECOMPRESSED_BYTES
) -> tuple[bytes | None, bool]:
    """Bounded GZip/Deflate decompression without calling ``flush()``.

    Returns ``(decompressed_bytes, limit_hit)``.
    """
    if wbits >= 16 and (len(data) < 10 or data[:2] != b"\x1f\x8b"):
        return None, False
    try:
        dobj = zlib.decompressobj(wbits)
        out = dobj.decompress(data, max_bytes + 1)
    except zlib.error:
        return None, False
    if len(out) > max_bytes or dobj.unconsumed_tail:
        return None, True
    if wbits < 0:
        # Raw deflate has no magic header/checksum: truncated or trailing random
        # bytes are non-deflate noise, never a false-positive limit_hit.
        if not dobj.eof or dobj.unused_data:
            return None, False
        return out, False
    if not dobj.eof or dobj.unused_data:
        return None, True
    return out, False


def _is_plausible_text(decoded: str, *, min_ratio: float = 0.80) -> bool:
    if len(decoded.strip()) < 4:
        return False
    printable = sum(
        1 for c in decoded if c != "\ufffd" and (c.isprintable() or c in "\t\r\n")
    )
    return printable >= len(decoded) * min_ratio


def decode_text_bytes(raw: bytes, *, min_ratio: float = 0.80) -> str | None:
    """Decode bytes to plausible text, prioritising UTF-16LE over UTF-8."""
    if len(raw) < 4:
        return None
    utf16 = magic.decode_utf16_if_detected(raw)
    if utf16 is not None and _is_plausible_text(utf16, min_ratio=min_ratio):
        return utf16
    # BOM-less UTF-16LE (standard PowerShell Unicode bytes without BOM).
    if len(raw) >= 8 and len(raw) % 2 == 0:
        sample = raw[:256]
        half = max(1, len(sample) // 2)
        odd_nuls = sample[1::2].count(0)
        even_nuls = sample[0::2].count(0)
        if odd_nuls >= half * 0.45 and even_nuls <= half * 0.1:
            u16le = raw.decode("utf-16-le", errors="replace").lstrip("\ufeff")
            if _is_plausible_text(u16le, min_ratio=min_ratio):
                return u16le
    decoded = raw.decode("utf-8", errors="replace").lstrip("\ufeff")
    if _is_plausible_text(decoded, min_ratio=min_ratio):
        return decoded
    return None


def decode_powershell_encoded(text: str) -> list[str]:
    """Decode PowerShell ``-EncodedCommand`` base64 (UTF-16LE) payloads.

    Returns deduplicated decoded command strings in order of appearance.
    """
    out: list[str] = []
    seen: set[str] = set()
    for m in _PS_ENCODED_RE.finditer(text):
        if len(out) >= 64:
            break
        blob = m.group(1)
        blob += "=" * (-len(blob) % 4)
        try:
            raw = base64.b64decode(blob, validate=False)
        except (binascii.Error, ValueError):
            continue
        for encoding in ("utf-16-le", "utf-8"):
            try:
                decoded = raw.decode(encoding)
            except (UnicodeError, ValueError):
                continue
            if not decoded.strip():
                continue
            printable = sum(c.isprintable() or c.isspace() for c in decoded)
            if printable >= len(decoded) * 0.85:
                if decoded not in seen:
                    seen.add(decoded)
                    out.append(decoded)
                break
    return out


# --------------------------------------------------------------------------- #
# PowerShell static deobfuscation (Spec 016 §3.3.1-§3.3.2)
# --------------------------------------------------------------------------- #

_PS_DQ_ESCAPES = frozenset('nrt0abfv"$`eu')
_PS_IDENT_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
)
_PS_COMMENT_PRECEDERS = frozenset(" \t\r\n;({)}|&],")
_PS_TOKEN_BREAKERS = frozenset(" \t\r\n:|&;({[")


def _strip_ps_backticks(
    text: str, *, line_reset_single_quotes: bool = False
) -> tuple[str, bool, bool]:
    """7-state linear O(N) PowerShell backtick deobfuscator (Spec 016 §3.3.1).

    Returns ``(stripped_text, changed, high_confidence)``.
    """
    if "`" not in text:
        return text, False, False

    out: list[str] = []
    n = len(text)
    i = 0
    state = "UNQUOTED"
    comment_allowed = True
    token_ticks = 0
    max_token_ticks = 0
    changed = False

    def _finish_token() -> None:
        nonlocal token_ticks, max_token_ticks
        if token_ticks > max_token_ticks:
            max_token_ticks = token_ticks
        token_ticks = 0

    while i < n:
        ch = text[i]

        if state == "LINE_COMMENT":
            out.append(ch)
            if ch == "\n":
                state = "UNQUOTED"
                comment_allowed = True
            i += 1
            continue

        if state == "BLOCK_COMMENT":
            if ch == "#" and i + 1 < n and text[i + 1] == ">":
                out.append("#>")
                i += 2
                state = "UNQUOTED"
                comment_allowed = True
            else:
                out.append(ch)
                i += 1
            continue

        if state == "HERE_SINGLE_QUOTE":
            if (
                ch == "'"
                and i + 1 < n
                and text[i + 1] == "@"
                and (i == 0 or text[i - 1] == "\n")
            ):
                out.append("'@")
                i += 2
                state = "UNQUOTED"
                comment_allowed = True
            else:
                out.append(ch)
                i += 1
            continue

        if state == "HERE_DOUBLE_QUOTE":
            if (
                ch == '"'
                and i + 1 < n
                and text[i + 1] == "@"
                and (i == 0 or text[i - 1] == "\n")
            ):
                out.append('"@')
                i += 2
                state = "UNQUOTED"
                comment_allowed = True
                _finish_token()
                continue
            if ch == "`" and i + 1 < n:
                nxt = text[i + 1]
                if nxt == "\r" and i + 2 < n and text[i + 2] == "\n":
                    i += 3
                    continue
                if nxt in ("\r", "\n"):
                    i += 2
                    continue
                if nxt in _PS_DQ_ESCAPES:
                    out.append(ch)
                    out.append(nxt)
                    i += 2
                    continue
                if 0x20 <= ord(nxt) <= 0x7E:
                    out.append(nxt)
                    changed = True
                    token_ticks += 1
                    i += 2
                    continue
            if ch in _PS_TOKEN_BREAKERS:
                _finish_token()
            out.append(ch)
            i += 1
            continue

        if state == "SINGLE_QUOTE":
            if ch == "'":
                if i + 1 < n and text[i + 1] == "'":
                    out.append("''")
                    i += 2
                    continue
                out.append("'")
                i += 1
                state = "UNQUOTED"
                comment_allowed = True
                continue
            if line_reset_single_quotes and ch == "\n":
                out.append(ch)
                i += 1
                state = "UNQUOTED"
                comment_allowed = True
                continue
            out.append(ch)
            i += 1
            continue

        if state == "DOUBLE_QUOTE":
            if ch == "`" and i + 1 < n:
                nxt = text[i + 1]
                if nxt == "\r" and i + 2 < n and text[i + 2] == "\n":
                    i += 3
                    continue
                if nxt in ("\r", "\n"):
                    i += 2
                    continue
                if nxt in _PS_DQ_ESCAPES:
                    out.append(ch)
                    out.append(nxt)
                    i += 2
                    continue
                if 0x20 <= ord(nxt) <= 0x7E:
                    out.append(nxt)
                    changed = True
                    token_ticks += 1
                    i += 2
                    continue
            if ch == '"':
                if i + 1 < n and text[i + 1] == '"':
                    out.append('""')
                    i += 2
                    continue
                out.append('"')
                i += 1
                state = "UNQUOTED"
                comment_allowed = True
                _finish_token()
                continue
            if ch in _PS_TOKEN_BREAKERS:
                _finish_token()
            out.append(ch)
            i += 1
            continue

        # state == "UNQUOTED"
        # Check here-string openings @' / @" followed by optional [ \t]* + newline
        if ch == "@" and i + 1 < n and text[i + 1] in ("'", '"'):
            q = text[i + 1]
            j = i + 2
            while j < n and text[j] in " \t":
                j += 1
            if j < n and text[j] in ("\r", "\n"):
                end_nl = j + 2 if (text[j] == "\r" and j + 1 < n and text[j + 1] == "\n") else j + 1
                _finish_token()
                out.append(text[i:end_nl])
                i = end_nl
                state = "HERE_SINGLE_QUOTE" if q == "'" else "HERE_DOUBLE_QUOTE"
                comment_allowed = False
                continue

        if comment_allowed and ch == "<" and i + 1 < n and text[i + 1] == "#":
            _finish_token()
            out.append("<#")
            i += 2
            state = "BLOCK_COMMENT"
            continue

        if comment_allowed and ch == "#":
            _finish_token()
            out.append("#")
            i += 1
            state = "LINE_COMMENT"
            continue

        if ch == "'":
            _finish_token()
            out.append("'")
            i += 1
            state = "SINGLE_QUOTE"
            comment_allowed = False
            continue

        if ch == '"':
            _finish_token()
            out.append('"')
            i += 1
            state = "DOUBLE_QUOTE"
            comment_allowed = False
            continue

        if ch == "`" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "\r" and i + 2 < n and text[i + 2] == "\n":
                i += 3
                continue
            if nxt in ("\r", "\n"):
                i += 2
                continue
            prev_ch = out[-1] if out else ""
            if nxt in _PS_IDENT_CHARS and (
                prev_ch in _PS_IDENT_CHARS or nxt not in _PS_DQ_ESCAPES
            ):
                out.append(nxt)
                changed = True
                token_ticks += 1
                comment_allowed = False
                i += 2
                continue
            # Preserve escaped punctuation/quote/comment/backtick verbatim & advance 2!
            out.append(ch)
            out.append(nxt)
            comment_allowed = False
            i += 2
            continue

        if ch in _PS_TOKEN_BREAKERS:
            _finish_token()
        out.append(ch)
        comment_allowed = ch in _PS_COMMENT_PRECEDERS
        i += 1

    _finish_token()
    if not changed:
        return text, False, False
    return "".join(out), True, (max_token_ticks >= 3)


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


_PS_SINGLE_CHAR_RE = re.compile(
    r"\[char\]\s*(?:\(\s*)?(0x[0-9a-fA-F]{1,4}|\d{1,5})(?:\s*\))?",
    re.IGNORECASE,
)
_PS_CHAR_ARRAY_HEAD_RE = re.compile(
    r"(?:(?:-join[ \t]+)?\[char\[\]\]\s*@?\(|\[int\[\]\]\s*@?\()",
    re.IGNORECASE,
)
_PS_INT_CTX_BEFORE_RE = re.compile(r"(?:-join|\[char\])[ \t]*$", re.IGNORECASE)
_PS_INT_CTX_AFTER_RE = re.compile(
    r"^[ \t]*(?:-join|\|[ \t]*(?:%|foreach(?:-object)?)[ \t]*\{[ \t]*\[char\])",
    re.IGNORECASE,
)
_PS_JOIN_TAIL_RE = re.compile(r"""^[ \t]*-join[ \t]*(?:''|"")""", re.IGNORECASE)


def _decode_ps_char_arrays(
    text: str, max_out: int
) -> tuple[str, bool, bool, bool]:
    """Decode PowerShell ``[char[]]@(...)``, ``-join [char[]](...)`` and ``[char]N``.

    Strictly linear O(N): caches next ``)`` and ``(`` indices so nested or
    unclosed ``[char[]](`` runs never re-scan or copy overlapping spans.
    Returns ``(new_text, changed, high_confidence, limit_hit)``.
    """
    low = text.lower()
    if "[char" not in low and "[int[]" not in low:
        return text, False, False, False

    changed = False
    high_conf = False
    limit_hit = False

    # 1. Array forms: [char[]]@(...) / -join [char[]](...) / contextual [int[]]@(...)
    out: list[str] = []
    out_len = 0
    pos = 0
    n = len(text)
    next_close = -1
    next_open = -1

    for m in _PS_CHAR_ARRAY_HEAD_RE.finditer(text):
        start = m.start()
        if start < pos:
            continue
        m_end = m.end()
        if m_end > next_close:
            next_close = text.find(")", m_end)
            if next_close == -1:
                break
        if m_end > next_open:
            next_open = text.find("(", m_end)
        # Skip in O(1) if another '(' sits before the matching ')' (cannot be flat int list)
        if next_open != -1 and next_open < next_close:
            continue

        close = next_close
        is_int_arr = m.group(0).lower().startswith("[int[]]")
        if is_int_arr:
            before_ok = bool(_PS_INT_CTX_BEFORE_RE.search(text[max(0, start - 32) : start]))
            after_ok = bool(_PS_INT_CTX_AFTER_RE.search(text[close + 1 : close + 64]))
            if not (before_ok or after_ok):
                continue

        body = text[m_end:close]
        raw_parts = body.split(",")
        if len(raw_parts) > MAX_CHAR_ITEMS:
            limit_hit = True
            continue
        chars: list[str] = []
        valid_array = True
        printable_ascii = 0
        for part in raw_parts:
            tok = part.strip()
            if not tok:
                continue
            try:
                cp = int(tok, 0)
            except ValueError:
                valid_array = False
                break
            if not (0 <= cp <= 0x10FFFF):
                valid_array = False
                break
            if 0x20 <= cp <= 0x7E or cp in (9, 10, 13):
                printable_ascii += 1
            chars.append(chr(cp))
        if not valid_array or not chars:
            continue

        end_pos = close + 1
        jm = _PS_JOIN_TAIL_RE.match(text[end_pos : end_pos + 32])
        if jm:
            end_pos += jm.end()

        prefix = text[pos:start]
        repl = _ps_quote("".join(chars))
        if out_len + len(prefix) + len(repl) > max_out:
            limit_hit = True
            break
        out.append(prefix)
        out.append(repl)
        out_len += len(prefix) + len(repl)
        pos = end_pos
        changed = True
        if printable_ascii >= 8:
            high_conf = True

    if pos < n:
        tail = text[pos:]
        if out_len + len(tail) > max_out:
            limit_hit = True
            out.append(tail[: max(0, max_out - out_len)])
        else:
            out.append(tail)
    work = "".join(out)

    # 2. Single [char]NN casts
    if "[char]" in work.lower():
        single_count = 0
        single_changed = False

        def _repl_char(match: re.Match) -> str:
            nonlocal single_changed, single_count
            try:
                cp = int(match.group(1), 0)
            except ValueError:
                return match.group(0)
            if not (0 <= cp <= 0x10FFFF):
                return match.group(0)
            single_changed = True
            if 0x20 <= cp <= 0x7E or cp in (9, 10, 13):
                single_count += 1
            return _ps_quote(chr(cp))

        candidate = _PS_SINGLE_CHAR_RE.sub(_repl_char, work)
        if len(candidate) <= max_out:
            work = candidate
            if single_changed:
                changed = True
            if single_count >= 8:
                high_conf = True
        else:
            limit_hit = True

    return work, changed, high_conf, limit_hit


def _read_ps_string_literal(text: str, start: int) -> tuple[str | None, int, bool]:
    """Read one PowerShell single- or double-quoted literal linearly.

    Returns ``(value_or_none, end_pos, closed)``:
    - ``closed=False`` means EOF was reached without a closing quote (``end_pos == len(text)``);
      callers mark that quote type exhausted so no later quote re-scans to EOF (strict O(N)).
    - ``closed=True, value=None`` means a double-quoted string contained ``$`` interpolation;
      callers skip verbatim to ``end_pos`` without re-scanning interior quotes.
    """
    n = len(text)
    if start >= n or text[start] not in ("'", '"'):
        return None, start, False
    q = text[start]
    i = start + 1
    buf: list[str] = []
    if q == "'":
        while i < n:
            if text[i] == "'":
                if i + 1 < n and text[i + 1] == "'":
                    buf.append("'")
                    i += 2
                    continue
                return "".join(buf), i + 1, True
            buf.append(text[i])
            i += 1
        return None, n, False

    has_dollar = False
    while i < n:
        c = text[i]
        if c == "`" and i + 1 < n:
            nxt = text[i + 1]
            if not has_dollar:
                if nxt in ('"', "`", "$"):
                    buf.append(nxt)
                elif nxt == "n":
                    buf.append("\n")
                elif nxt == "r":
                    buf.append("\r")
                elif nxt == "t":
                    buf.append("\t")
                else:
                    buf.append(nxt)
            i += 2
            continue
        if c == '"':
            if i + 1 < n and text[i + 1] == '"':
                if not has_dollar:
                    buf.append('"')
                i += 2
                continue
            return (None if has_dollar else "".join(buf)), i + 1, True
        if c == "$":
            has_dollar = True
        elif not has_dollar:
            buf.append(c)
        i += 1
    return None, n, False


def _merge_ps_concat(text: str, max_out: int) -> tuple[str, bool, bool]:
    """Strictly linear O(N) merger for PowerShell ``'a' + 'b'`` string concatenations."""
    if "+" not in text or ("'" not in text and '"' not in text):
        return text, False, False

    out: list[str] = []
    out_len = 0
    n = len(text)
    i = 0
    changed = False
    limit_hit = False
    exhausted: set[str] = set()

    def _emit(seg: str) -> bool:
        nonlocal out_len, limit_hit
        if out_len + len(seg) > max_out:
            limit_hit = True
            rem = max(0, max_out - out_len)
            if rem:
                out.append(seg[:rem])
                out_len += rem
            return False
        out.append(seg)
        out_len += len(seg)
        return True

    while i < n:
        ch = text[i]
        if ch in ("'", '"') and ch not in exhausted:
            val, end, closed = _read_ps_string_literal(text, i)
            if not closed:
                exhausted.add(ch)
                if not _emit(ch):
                    break
                i += 1
                continue
            if val is None:
                if not _emit(text[i:end]):
                    break
                i = end
                continue
            parts = [val]
            while True:
                j = end
                while j < n and text[j] in " \t\r\n":
                    j += 1
                if j < n and text[j] == "+":
                    j += 1
                    while j < n and text[j] in " \t\r\n":
                        j += 1
                    if j < n and text[j] in ("'", '"') and text[j] not in exhausted:
                        nval, nend, nclosed = _read_ps_string_literal(text, j)
                        if not nclosed:
                            exhausted.add(text[j])
                            break
                        if nval is not None:
                            parts.append(nval)
                            end = nend
                            continue
                break
            if len(parts) >= 2:
                merged = _ps_quote("".join(parts))
                if not _emit(merged):
                    break
                changed = True
                i = end
                continue
            if not _emit(text[i:end]):
                break
            i = end
            continue
        if not _emit(ch):
            break
        i += 1

    if not changed and not limit_hit:
        return text, False, False
    return "".join(out), changed, limit_hit


def _eval_ps_format_f(
    text: str, max_out: int
) -> tuple[str, bool, bool, bool]:
    """Safe linear O(N) PowerShell ``-f`` format-operator evaluator (never ``str.format``).

    Returns ``(new_text, changed, high_confidence, limit_hit)``.
    """
    low = text.lower()
    if "-f" not in low:
        return text, False, False, False

    out: list[str] = []
    out_len = 0
    n = len(text)
    i = 0
    changed = False
    high_conf = False
    limit_hit = False
    exhausted: set[str] = set()

    def _emit(seg: str) -> bool:
        nonlocal out_len, limit_hit
        if out_len + len(seg) > max_out:
            limit_hit = True
            rem = max(0, max_out - out_len)
            if rem:
                out.append(seg[:rem])
                out_len += rem
            return False
        out.append(seg)
        out_len += len(seg)
        return True

    while i < n:
        paren_wrapped = False
        lit_start = i
        if text[i] == "(":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in ("'", '"') and text[j] not in exhausted:
                paren_wrapped = True
                lit_start = j

        if text[lit_start] in ("'", '"') and text[lit_start] not in exhausted:
            tmpl, after_tmpl, closed = _read_ps_string_literal(text, lit_start)
            if not closed:
                exhausted.add(text[lit_start])
                if not _emit(text[i]):
                    break
                i += 1
                continue
            if tmpl is None:
                if not _emit(text[i:after_tmpl]):
                    break
                i = after_tmpl
                continue

            j = after_tmpl
            while j < n and text[j] in " \t\r\n":
                j += 1
            if (
                j + 2 <= n
                and text[j] == "-"
                and text[j + 1] in ("f", "F")
                and (j + 2 == n or text[j + 2] in " \t\r\n'\"(")
            ):
                k = j + 2
                args: list[str] = []
                args_ok = True
                while True:
                    while k < n and text[k] in " \t\r\n":
                        k += 1
                    if k >= n or text[k] not in ("'", '"') or text[k] in exhausted:
                        args_ok = False
                        break
                    aval, aend, aclosed = _read_ps_string_literal(text, k)
                    if not aclosed:
                        exhausted.add(text[k])
                        args_ok = False
                        break
                    if aval is None:
                        args_ok = False
                        break
                    args.append(aval)
                    k = aend
                    if len(args) > MAX_PS_FORMAT_ARGS:
                        limit_hit = True
                        args_ok = False
                        break
                    m_pos = k
                    while m_pos < n and text[m_pos] in " \t\r\n":
                        m_pos += 1
                    if m_pos < n and text[m_pos] == ",":
                        k = m_pos + 1
                        continue
                    break

                end_expr = k
                open_prefix = ""
                if paren_wrapped and args_ok:
                    m_pos = k
                    while m_pos < n and text[m_pos] in " \t\r\n":
                        m_pos += 1
                    if m_pos < n and text[m_pos] == ")":
                        end_expr = m_pos + 1
                    else:
                        open_prefix = text[i:lit_start]

                if args_ok and args:
                    res_parts: list[str] = []
                    res_len = 0
                    indices: list[int] = []
                    adj_run = 0
                    max_adj_run = 0
                    t_idx = 0
                    t_len = len(tmpl)
                    tmpl_ok = True
                    placeholder_count = 0
                    while t_idx < t_len:
                        c = tmpl[t_idx]
                        if c == "{":
                            if t_idx + 1 < t_len and tmpl[t_idx + 1] == "{":
                                res_parts.append("{")
                                res_len += 1
                                adj_run = 0
                                t_idx += 2
                                continue
                            close_b = tmpl.find("}", t_idx + 1)
                            if close_b == -1:
                                tmpl_ok = False
                                break
                            inside = tmpl[t_idx + 1 : close_b]
                            if not (inside.isascii() and inside.isdigit()):
                                tmpl_ok = False
                                break
                            placeholder_count += 1
                            if placeholder_count > MAX_PS_FORMAT_ARGS:
                                limit_hit = True
                                tmpl_ok = False
                                break
                            idx_num = int(inside)
                            if idx_num >= len(args):
                                tmpl_ok = False
                                break
                            val = args[idx_num]
                            if out_len + len(open_prefix) + res_len + len(val) + 2 > max_out:
                                limit_hit = True
                                tmpl_ok = False
                                break
                            res_parts.append(val)
                            res_len += len(val)
                            indices.append(idx_num)
                            adj_run += 1
                            if adj_run > max_adj_run:
                                max_adj_run = adj_run
                            t_idx = close_b + 1
                            continue
                        if c == "}" and t_idx + 1 < t_len and tmpl[t_idx + 1] == "}":
                            res_parts.append("}")
                            res_len += 1
                            adj_run = 0
                            t_idx += 2
                            continue
                        res_parts.append(c)
                        res_len += 1
                        adj_run = 0
                        t_idx += 1

                    if tmpl_ok and indices:
                        quoted = _ps_quote("".join(res_parts))
                        if not _emit(open_prefix + quoted):
                            break
                        changed = True
                        non_mono = any(
                            indices[p] > indices[p + 1]
                            for p in range(len(indices) - 1)
                        )
                        if non_mono or max_adj_run >= 3:
                            high_conf = True
                        i = end_expr
                        continue

            if not _emit(text[i:after_tmpl]):
                break
            i = after_tmpl
            continue

        if not _emit(text[i]):
            break
        i += 1

    if not changed and not limit_hit:
        return text, False, False, False
    return "".join(out), changed, high_conf, limit_hit


_PS_FROM_B64_RE = re.compile(
    r"FromBase64String\s*\(\s*(['\"])([A-Za-z0-9+/=\s]{8,})\1\s*\)",
    re.IGNORECASE,
)


def _decode_ps_b64_blobs(
    text: str,
    budget: DeobfBudget,
    chunk_input_len: int,
    current_text_len: int,
    seen_blobs: set[str],
    result: ScriptDeobfResult,
) -> bool:
    """Decode ``FromBase64String('...')`` + optional GZip/Deflate within budget."""
    low = text.lower()
    if "frombase64string" not in low:
        return False
    has_deflate_ctx = "deflatestream" in low or "compressionmode" in low
    added_any = False

    for m in _PS_FROM_B64_RE.finditer(text):
        if budget.used_b64_blobs >= budget.max_b64_blobs:
            result.set_limit(REASON_B64_LIMIT)
            break
        budget.used_b64_blobs += 1
        raw_b64 = m.group(2)
        raw, b64_lim = decode_b64_bounded(raw_b64, max_bytes=MAX_B64_DECODED_BYTES)
        if b64_lim:
            result.set_limit(REASON_B64_LIMIT)
            continue
        if raw is None:
            continue

        decoded: str | None = None
        tech: str | None = None
        hi = False

        if len(raw) >= 10 and raw[:2] == b"\x1f\x8b":
            inflated, dec_lim = decompress_bounded(
                raw, wbits=16 + zlib.MAX_WBITS, max_bytes=MAX_DECOMPRESSED_BYTES
            )
            if dec_lim:
                result.set_limit(REASON_DECOMP_LIMIT)
                continue
            if inflated is not None:
                decoded = decode_text_bytes(inflated)
                if decoded is not None:
                    tech = "ps_gzip_b64"
                    hi = True
        elif has_deflate_ctx:
            inflated, dec_lim = decompress_bounded(
                raw, wbits=-15, max_bytes=MAX_DECOMPRESSED_BYTES
            )
            if dec_lim:
                result.set_limit(REASON_DECOMP_LIMIT)
                continue
            if inflated is not None:
                decoded = decode_text_bytes(inflated)
                if decoded is not None:
                    tech = "ps_deflate_b64"
                    hi = True

        if decoded is None:
            plain = decode_text_bytes(raw)
            if plain is not None:
                decoded = plain
                tech = "ps_b64"
                hi = False

        if decoded is None or tech is None or decoded in seen_blobs:
            continue

        extra_now = max(0, current_text_len - chunk_input_len)
        if budget.used_extra_chars + extra_now + len(decoded) > budget.max_total_chars:
            result.set_limit(REASON_OUTPUT_LIMIT)
            break

        seen_blobs.add(decoded)
        budget.used_extra_chars += len(decoded)
        result.decoded_blobs.append(decoded)
        result.add_technique(tech, high_confidence=hi)
        added_any = True

    return added_any


def _run_ps_single_pass(
    current: str,
    *,
    max_out: int,
    line_reset_single_quotes: bool,
    budget: DeobfBudget,
    chunk_input_len: int,
    seen_blobs: set[str],
    seen_enc: set[str],
    baseline_enc: set[str],
    result: ScriptDeobfResult,
    dry_run: bool = False,
) -> tuple[str, bool]:
    """Execute one PowerShell deobfuscation pass (exact Spec 016 §3.3.2 order)."""
    before = current
    step_changed = False

    # 1. Backticks
    bt_text, bt_chg, bt_hi = _strip_ps_backticks(
        current, line_reset_single_quotes=line_reset_single_quotes
    )
    if bt_chg:
        step_changed = True
        if not dry_run:
            current = bt_text
            result.add_technique("ps_backtick", high_confidence=bt_hi)
        else:
            return current, True

    # 2. [char[]] / [char] / contextual [int[]]
    ca_text, ca_chg, ca_hi, ca_lim = _decode_ps_char_arrays(current, max_out)
    if ca_lim and not dry_run:
        result.set_limit(REASON_PS_LIMIT)
    if ca_chg:
        step_changed = True
        if not dry_run:
            current = ca_text
            result.add_technique("ps_char_array", high_confidence=ca_hi)
        else:
            return current, True

    # 3. String concat
    cc_text, cc_chg, cc_lim = _merge_ps_concat(current, max_out)
    if cc_lim and not dry_run:
        result.set_limit(REASON_OUTPUT_LIMIT)
    if cc_chg:
        step_changed = True
        if not dry_run:
            current = cc_text
            result.add_technique("ps_concat", high_confidence=False)
        else:
            return current, True

    # 4. Format operator -f
    ff_text, ff_chg, ff_hi, ff_lim = _eval_ps_format_f(current, max_out)
    if ff_lim and not dry_run:
        result.set_limit(REASON_PS_LIMIT)
    if ff_chg:
        step_changed = True
        if not dry_run:
            current = ff_text
            result.add_technique("ps_format_f", high_confidence=ff_hi)
        else:
            return current, True

    if dry_run:
        return current, (step_changed or current != before)

    # 5. FromBase64String + GZip / Deflate
    if _decode_ps_b64_blobs(
        current, budget, chunk_input_len, len(current), seen_blobs, result
    ):
        step_changed = True

    # 6. Newly surfaced -EncodedCommand payloads (excluding baseline)
    for enc_payload in decode_powershell_encoded(current):
        if enc_payload in baseline_enc or enc_payload in seen_enc:
            continue
        extra_now = max(0, len(current) - chunk_input_len)
        if budget.used_extra_chars + extra_now + len(enc_payload) > budget.max_total_chars:
            result.set_limit(REASON_OUTPUT_LIMIT)
            break
        seen_enc.add(enc_payload)
        budget.used_extra_chars += len(enc_payload)
        result.decoded_blobs.append(enc_payload)
        result.add_technique("ps_encoded_cmd", high_confidence=False)
        step_changed = True

    return current, (step_changed or current != before)


def deobfuscate_powershell(
    text: str,
    *,
    explicit_script: bool = False,
    budget: DeobfBudget | None = None,
    charge_input: bool = True,
    line_reset_single_quotes: bool = False,
) -> ScriptDeobfResult:
    """Statically deobfuscate PowerShell text under strict DoS & budget limits."""
    b = budget if budget is not None else DeobfBudget()

    if b.used_extra_chars >= b.max_total_chars:
        res = ScriptDeobfResult(text=text)
        res.set_limit(REASON_OUTPUT_LIMIT)
        return res

    input_truncated = False
    if charge_input:
        if b.used_input_chars >= b.max_input_chars:
            res = ScriptDeobfResult(text=text)
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
    baseline_enc = set(decode_powershell_encoded(work))
    res = ScriptDeobfResult(text=work)
    seen_blobs: set[str] = set()
    seen_enc: set[str] = set()
    current = work

    made_change_on_last = False
    for _pass in range(MAX_DEOBF_PASSES):
        max_out = min(
            MAX_TOTAL_DECODED_CHARS,
            chunk_input_len + b.remaining_extra(),
        )
        current, chg = _run_ps_single_pass(
            current,
            max_out=max_out,
            line_reset_single_quotes=line_reset_single_quotes,
            budget=b,
            chunk_input_len=chunk_input_len,
            seen_blobs=seen_blobs,
            seen_enc=seen_enc,
            baseline_enc=baseline_enc,
            result=res,
        )
        made_change_on_last = chg
        if chg:
            res.changed = True
        if not chg or res.limit_hit:
            break

    # 4th convergence check: > MAX_DEOBF_PASSES active obfuscation layers
    if made_change_on_last and not res.limit_hit:
        max_out = min(
            MAX_TOTAL_DECODED_CHARS,
            chunk_input_len + b.remaining_extra(),
        )
        _, would_change = _run_ps_single_pass(
            current,
            max_out=max_out,
            line_reset_single_quotes=line_reset_single_quotes,
            budget=b,
            chunk_input_len=chunk_input_len,
            seen_blobs=seen_blobs,
            seen_enc=seen_enc,
            baseline_enc=baseline_enc,
            result=res,
            dry_run=True,
        )
        if would_change:
            res.set_limit(REASON_PASS_LIMIT)

    res.text = current
    b.used_extra_chars += max(0, len(current) - chunk_input_len)

    if input_truncated and (explicit_script or res.changed or res.decoded_blobs):
        res.set_limit(REASON_INPUT_LIMIT)

    return res


# --------------------------------------------------------------------------- #
# Windows Batch (.bat / .cmd) static deobfuscation (Spec 016 §3.3.3)
# --------------------------------------------------------------------------- #

_BATCH_CARET_PUNCT = frozenset("._:/\\=-")
_BATCH_STD_ENV: dict[str, str] = {
    "comspec": r"C:\Windows\system32\cmd.exe",
    "systemroot": r"C:\Windows",
    "windir": r"C:\Windows",
    "public": r"C:\Users\Public",
    "temp": r"C:\Windows\Temp",
    "tmp": r"C:\Windows\Temp",
}


def _strip_batch_carets(text: str) -> tuple[str, bool, bool]:
    """Pass-1-only linear O(N) Batch caret deobfuscator (Spec 016 §3.3.3).

    Returns ``(stripped_text, changed, high_confidence)``.
    """
    if "^" not in text:
        return text, False, False

    out: list[str] = []
    n = len(text)
    i = 0
    in_dq = False
    seg_carets = 0
    max_seg_carets = 0
    changed = False

    def _finish_seg() -> None:
        nonlocal seg_carets, max_seg_carets
        if seg_carets > max_seg_carets:
            max_seg_carets = seg_carets
        seg_carets = 0

    while i < n:
        ch = text[i]
        if ch == "\n":
            in_dq = False
            _finish_seg()
            out.append(ch)
            i += 1
            continue
        if in_dq:
            if ch == '"':
                in_dq = False
            out.append(ch)
            i += 1
            continue

        # Outside double quotes
        if ch == '"':
            in_dq = True
            out.append(ch)
            i += 1
            continue
        if ch in ("&", "|"):
            _finish_seg()
            out.append(ch)
            i += 1
            continue
        if ch == "^" and i + 1 < n:
            nxt = text[i + 1]
            # Line continuation ^\r?\n
            if nxt == "\r" and i + 2 < n and text[i + 2] == "\n":
                i += 3
                continue
            if nxt in ("\r", "\n"):
                i += 2
                continue
            # Escaped quote ^" -> literal " without toggling in_dq
            if nxt == '"':
                out.append('"')
                changed = True
                i += 2
                continue
            # Double caret ^^ -> single literal ^ (not counted; not re-collapsed!)
            if nxt == "^":
                out.append("^")
                i += 2
                continue
            if nxt.isascii() and nxt.isalnum():
                out.append(nxt)
                changed = True
                seg_carets += 1
                i += 2
                continue
            if nxt in _BATCH_CARET_PUNCT:
                out.append(nxt)
                changed = True
                i += 2
                continue
            # Preserve escaped operators (&|<>()^%!) verbatim (zero FP on echo ^<tag^>)
            out.append(ch)
            out.append(nxt)
            i += 2
            continue

        out.append(ch)
        i += 1

    _finish_seg()
    if not changed:
        return text, False, False
    return "".join(out), True, (max_seg_carets >= 4)


def _split_batch_segments(line: str) -> list[tuple[str, str]]:
    """Split one Batch line on unquoted ``&&`` / ``&`` / ``|`` into ``(seg, sep)``."""
    parts: list[tuple[str, str]] = []
    start = 0
    in_dq = False
    i = 0
    n = len(line)
    while i < n:
        c = line[i]
        if c == '"':
            in_dq = not in_dq
            i += 1
            continue
        if not in_dq:
            if c == "&":
                sep = "&&" if (i + 1 < n and line[i + 1] == "&") else "&"
                parts.append((line[start:i], sep))
                i += len(sep)
                start = i
                continue
            if c == "|":
                sep = "||" if (i + 1 < n and line[i + 1] == "|") else "|"
                parts.append((line[start:i], sep))
                i += len(sep)
                start = i
                continue
        i += 1
    parts.append((line[start:], ""))
    return parts


def _batch_slice(val: str, spec: str) -> str | None:
    """Exact ``cmd.exe`` substring slicing ``~start[,len]``."""
    parts = spec.split(",", 1)
    try:
        start = int(parts[0].strip())
        length = int(parts[1].strip()) if len(parts) == 2 and parts[1].strip() else None
    except ValueError:
        return None
    lv = len(val)
    s = max(0, min(lv, lv + start if start < 0 else start))
    if length is None:
        return val[s:]
    if length < 0:
        return val[s : max(s, lv + length)]
    return val[s : min(lv, s + length)]


def _batch_replace(val: str, spec: str) -> str | None:
    """Case-insensitive ``cmd.exe`` ``old=new`` replacement (rejects empty ``old``)."""
    eq = spec.find("=")
    if eq <= 0:
        return None
    old = spec[:eq]
    new = spec[eq + 1 :]
    if not old:
        return None
    low_val = val.lower()
    low_old = old.lower()
    out: list[str] = []
    pos = 0
    step = len(old)
    while True:
        idx = low_val.find(low_old, pos)
        if idx == -1:
            out.append(val[pos:])
            break
        out.append(val[pos:idx])
        out.append(new)
        pos = idx + step
    return "".join(out)


def _expand_batch_segment(
    seg: str,
    vars_map: dict[str, str],
    *,
    allow_std_bare: bool,
    max_remaining: int,
) -> tuple[str, bool, set[str], set[str], bool]:
    """Expand ``%var%``, ``!var!``, slicing, and replacement in one segment."""
    if "%" not in seg and "!" not in seg:
        if len(seg) > max_remaining:
            return seg[: max(0, max_remaining)], False, set(), set(), True
        return seg, False, set(), set(), False

    out: list[str] = []
    out_len = 0
    n = len(seg)
    i = 0
    changed = False
    techs: set[str] = set()
    hi_techs: set[str] = set()
    limit_hit = False
    adj_short_slices = 0
    max_adj_short_slices = 0

    while i < n:
        ch = seg[i]
        if ch in ("%", "!"):
            close = seg.find(ch, i + 1)
            if close != -1 and close > i + 1 and (close - i) <= 256:
                expr = seg[i + 1 : close]
                colon = expr.find(":")
                if colon == -1:
                    vname = expr.lower()
                    val = vars_map.get(vname)
                    if val is None and allow_std_bare:
                        val = _BATCH_STD_ENV.get(vname)
                    if val is not None:
                        if out_len + len(val) > max_remaining:
                            limit_hit = True
                            break
                        out.append(val)
                        out_len += len(val)
                        changed = True
                        techs.add("bat_set_expand")
                        adj_short_slices = 0
                        i = close + 1
                        continue
                else:
                    vname = expr[:colon].lower()
                    op = expr[colon + 1 :]
                    val = vars_map.get(vname)
                    if val is None:
                        val = _BATCH_STD_ENV.get(vname)
                    if val is not None and op:
                        if op.startswith("~"):
                            sliced = _batch_slice(val, op[1:])
                            if sliced is not None:
                                if out_len + len(sliced) > max_remaining:
                                    limit_hit = True
                                    break
                                out.append(sliced)
                                out_len += len(sliced)
                                changed = True
                                techs.add("bat_substring_slice")
                                if vname not in ("date", "time") and 1 <= len(sliced) <= 2:
                                    adj_short_slices += 1
                                    if adj_short_slices > max_adj_short_slices:
                                        max_adj_short_slices = adj_short_slices
                                else:
                                    adj_short_slices = 0
                                i = close + 1
                                continue
                        else:
                            replaced = _batch_replace(val, op)
                            if replaced is not None:
                                if out_len + len(replaced) > max_remaining:
                                    limit_hit = True
                                    break
                                out.append(replaced)
                                out_len += len(replaced)
                                changed = True
                                techs.add("bat_replace")
                                adj_short_slices = 0
                                i = close + 1
                                continue
        if out_len >= max_remaining:
            limit_hit = True
            break
        out.append(ch)
        out_len += 1
        adj_short_slices = 0
        i += 1

    if max_adj_short_slices >= 3:
        hi_techs.add("bat_substring_slice")
    if limit_hit:
        return "".join(out), changed, techs, hi_techs, True
    if not changed:
        return seg, False, techs, hi_techs, False
    return "".join(out), True, techs, hi_techs, False


_BATCH_SET_PREFIX_RE = re.compile(r"^[ \t]*@?set[ \t]+", re.IGNORECASE)
_BATCH_COMMENT_RE = re.compile(r"^[ \t]*(?:@?rem(?:\s|$)|::)", re.IGNORECASE)


def _expand_batch_vars_pass(
    text: str, max_out: int
) -> tuple[str, bool, set[str], set[str], bool, str]:
    """One linear pass of Batch ``set`` symbol-table collection and expansion."""
    vars_map: dict[str, str] = {}
    out_lines: list[str] = []
    out_len = 0
    changed = False
    techs: set[str] = set()
    hi_techs: set[str] = set()
    limit_hit = False
    limit_reason = ""

    def _append_chunk(buf: list[str], chunk: str) -> bool:
        nonlocal out_len, limit_hit, limit_reason
        if out_len + len(chunk) > max_out:
            limit_hit = True
            if not limit_reason:
                limit_reason = REASON_OUTPUT_LIMIT
            rem = max(0, max_out - out_len)
            if rem:
                buf.append(chunk[:rem])
                out_len += rem
            return False
        buf.append(chunk)
        out_len += len(chunk)
        return True

    for line in text.splitlines(keepends=True):
        if _BATCH_COMMENT_RE.match(line):
            if not _append_chunk(out_lines, line):
                break
            continue

        nl = ""
        body = line
        if body.endswith("\r\n"):
            nl = "\r\n"
            body = body[:-2]
        elif body.endswith("\n"):
            nl = "\n"
            body = body[:-1]

        rebuilt_parts: list[str] = []
        for seg, sep in _split_batch_segments(body):
            m_set = _BATCH_SET_PREFIX_RE.match(seg)
            if m_set:
                rest = seg[m_set.end() :]
                low_rest = rest.lstrip().lower()
                if low_rest.startswith(("/a", "/p")):
                    if not _append_chunk(rebuilt_parts, seg + sep):
                        break
                    continue

                quoted_assign = rest.startswith('"')
                if quoted_assign:
                    end_q = rest.rfind('"')
                    assign_str = rest[1:end_q] if end_q > 0 else rest[1:]
                else:
                    assign_str = rest

                eq = assign_str.find("=")
                if eq > 0:
                    vname = assign_str[:eq].strip().lower()
                    rhs_raw = assign_str[eq + 1 :]
                    if vname:
                        rem = max(0, max_out - out_len)
                        rhs_exp, r_chg, r_t, r_hi, r_lim = _expand_batch_segment(
                            rhs_raw, vars_map, allow_std_bare=True, max_remaining=rem
                        )
                        if r_lim:
                            limit_hit = True
                            limit_reason = REASON_OUTPUT_LIMIT
                            break
                        if r_chg:
                            changed = True
                            techs.update(r_t)
                            hi_techs.update(r_hi)
                        low_rhs = rhs_exp.lower()
                        if f"%{vname}%" in low_rhs or f"!{vname}!" in low_rhs:
                            vars_map.pop(vname, None)
                        else:
                            if len(rhs_exp) > MAX_BATCH_VAR_VALUE:
                                limit_hit = True
                                limit_reason = REASON_TABLE_LIMIT
                                break
                            if vname not in vars_map and len(vars_map) >= MAX_BATCH_VARS:
                                limit_hit = True
                                limit_reason = REASON_TABLE_LIMIT
                                break
                            vars_map[vname] = rhs_exp
                        rebuilt_seg = (
                            seg[: m_set.end()]
                            + (f'"{vname}={rhs_exp}"' if quoted_assign else f"{vname}={rhs_exp}")
                            if r_chg
                            else seg
                        )
                        if not _append_chunk(rebuilt_parts, rebuilt_seg + sep):
                            break
                        continue

            rem = max(0, max_out - out_len)
            exp_seg, s_chg, s_t, s_hi, s_lim = _expand_batch_segment(
                seg, vars_map, allow_std_bare=False, max_remaining=rem
            )
            if s_chg:
                changed = True
                techs.update(s_t)
                hi_techs.update(s_hi)
            if s_lim:
                limit_hit = True
                limit_reason = REASON_OUTPUT_LIMIT
                if exp_seg:
                    _append_chunk(rebuilt_parts, exp_seg)
                break
            if not _append_chunk(rebuilt_parts, exp_seg + sep):
                break

        if not limit_hit and nl:
            _append_chunk(rebuilt_parts, nl)
        out_lines.append("".join(rebuilt_parts))
        if limit_hit:
            break

    return "".join(out_lines), changed, techs, hi_techs, limit_hit, limit_reason


def deobfuscate_batch(
    text: str,
    *,
    explicit_script: bool = False,
    budget: DeobfBudget | None = None,
    charge_input: bool = True,
) -> ScriptDeobfResult:
    """Statically deobfuscate Windows Batch scripts under strict DoS & budget limits."""
    b = budget if budget is not None else DeobfBudget()

    if b.used_extra_chars >= b.max_total_chars:
        res = ScriptDeobfResult(text=text)
        res.set_limit(REASON_OUTPUT_LIMIT)
        return res

    input_truncated = False
    if charge_input:
        if b.used_input_chars >= b.max_input_chars:
            res = ScriptDeobfResult(text=text)
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

    # Pass 1 ONLY: caret stripping (never re-run on subsequent passes!)
    c_text, c_chg, c_hi = _strip_batch_carets(current)
    if c_chg:
        current = c_text
        res.changed = True
        res.add_technique("bat_caret", high_confidence=c_hi)

    # Passes 2..3 (up to MAX_DEOBF_PASSES - 1 var-expansion passes) + 4th convergence check
    made_var_change_on_last = False
    for _pass in range(MAX_DEOBF_PASSES - 1):
        max_out = min(
            MAX_TOTAL_DECODED_CHARS,
            chunk_input_len + b.remaining_extra(),
        )
        v_text, v_chg, v_techs, v_hi, v_lim, v_reason = _expand_batch_vars_pass(
            current, max_out
        )
        if v_lim:
            res.set_limit(v_reason or REASON_OUTPUT_LIMIT)
            if v_chg:
                current = v_text
                res.changed = True
                for t in v_techs:
                    res.add_technique(t, high_confidence=(t in v_hi))
            break
        made_var_change_on_last = v_chg
        if not v_chg:
            break
        current = v_text
        res.changed = True
        for t in v_techs:
            res.add_technique(t, high_confidence=(t in v_hi))

    if made_var_change_on_last and not res.limit_hit:
        max_out = min(
            MAX_TOTAL_DECODED_CHARS,
            chunk_input_len + b.remaining_extra(),
        )
        _, would_chg, _, _, would_lim, would_reason = _expand_batch_vars_pass(
            current, max_out
        )
        if would_lim:
            res.set_limit(would_reason or REASON_OUTPUT_LIMIT)
        elif would_chg:
            res.set_limit(REASON_PASS_LIMIT)

    res.text = current
    b.used_extra_chars += max(0, len(current) - chunk_input_len)

    if input_truncated and (explicit_script or res.changed or res.decoded_blobs):
        res.set_limit(REASON_INPUT_LIMIT)

    return res
