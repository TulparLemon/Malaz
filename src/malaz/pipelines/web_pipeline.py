"""Web content analysis pipeline (HTML smuggling, CHM ActiveX & SVG active content).

Implements Spec 014 (Block 3B): dedicated, strictly linear O(N) analysis for
standalone HTML/HTA/SVG files and extracted container attachments (EML, ZIP,
CHM, OneNote).

Design principles:
* Zero ReDoS risk: structural tag/attribute inspection uses Python's single-pass
  ``html.parser.HTMLParser`` with a hard tag cap (100 000 tags, fail-closed
  ``WEB_PARSE_LIMIT`` on overflow) and linear ``str.find`` helpers.
* Zero magic duplication: Base64 payload decoding reuses ``core.magic.detect``
  plus strict PE header validation (``e_lfanew`` -> ``PE\0\0``).
* Zero false positives on legitimate HTML manuals, benign CSV/JSON Blob exports,
  static SVG logos, and draw.io / Mermaid ``<foreignObject>`` diagrams.
"""

from __future__ import annotations

import base64
import contextlib
import html
import re
from html.parser import HTMLParser

from ..core import magic
from ..core.risky_types import RISKY_SUFFIXES
from ..models import (
    CAT_CONTENT,
    CAT_IOC,
    CAT_SCRIPT,
    AnalysisContext,
    Indicator,
    Severity,
)
from .base import Pipeline

_MAX_TAGS = 100_000
_MAX_B64_CANDIDATES = 512
_MAX_STAGE2_CHECKS = 32
_STAGE1_B64_CHARS = 64  # 48 decoded bytes
_STAGE2_DECODE_CAP = 65_536  # 64 KiB (covers ISO 9660 CD001 at 0x8001)
_STAGE2_B64_CHARS = ((_STAGE2_DECODE_CAP + 2) // 3) * 4

_WEB_HTML_SUFFIXES = frozenset(
    {".html", ".htm", ".shtml", ".xhtml", ".xht", ".hta", ".mht", ".mhtml"}
)

_SMUGGLING_DOWNLOAD_SUFFIXES: tuple[str, ...] = tuple(
    sorted(
        set(RISKY_SUFFIXES)
        | {".zip", ".rar", ".7z", ".iso", ".img", ".cab", ".gz", ".tgz", ".dmg"}
    )
)

_BENIGN_DOWNLOAD_SUFFIXES = frozenset(
    {
        ".csv", ".txt", ".json", ".png", ".jpg", ".jpeg", ".gif", ".webp",
        ".svg", ".pdf", ".ics", ".vcf", ".xml", ".md",
    }
)

_BINARY_SMUGGLE_MIMES = (
    "application/octet-stream",
    "application/x-msdownload",
    "application/x-msdos-program",
    "application/zip",
    "application/x-iso9660-image",
    "binary/",
)

_SMUGGLED_DANGEROUS_TYPES = frozenset(
    {
        "pe", "zip", "rar", "7z", "cab", "iso", "chm", "vhdx",
        "onenote", "lnk", "elf", "macho", "ole", "gzip",
    }
)

_BENIGN_IMAGE_TYPES = frozenset({"png", "jpeg", "gif", "webp", "bmp", "ico"})

_HHCTRL_CLSIDS = (
    "adb880a6-d8ff-11cf-9377-00aa003b7a11",
    "52a2aaae-085d-4187-97ea-8c30db990436",
)

_FOREIGN_ACTIVE_TAGS = frozenset(
    {"form", "input", "iframe", "script", "object", "embed", "meta", "a"}
)

# Strictly linear O(N) regular expressions (no nested quantifiers, no DOTALL .*).
_CONCAT_RE = re.compile(r"'\s*\+\s*'|\"\s*\+\s*\"")
_SMUGGLE_A_RE = re.compile(
    r"\b(?:atob|Uint8Array|ArrayBuffer|TextDecoder)\b|String\s*\.\s*fromCharCode\s*\(",
    re.IGNORECASE,
)
_SMUGGLE_B_RE = re.compile(
    r"\bnew\s+(?:Blob|File)\s*\(|\bcreateObjectURL\s*\(|"
    r"data:(?:application/[a-z0-9.+_-]{1,40}|binary/[a-z0-9.+_-]{1,40}|text/html|)"
    r"(?:;[a-z0-9._=-]{1,40}){0,4};base64,",
    re.IGNORECASE,
)
_SMUGGLE_MS_SAVE_RE = re.compile(r"\bmsSave(?:OrOpen)?Blob\s*\(", re.IGNORECASE)
_SMUGGLE_CREATE_A_RE = re.compile(
    r"\bcreateElement\s*\(\s*['\"`]a['\"`]\s*\)", re.IGNORECASE
)
_SMUGGLE_CLICK_RE = re.compile(r"\.\s*click\s*\(\s*\)", re.IGNORECASE)
_JS_DOWNLOAD_RE = re.compile(
    r"""(?:\.\s*download\s*=|\.\s*setAttribute\s*\(\s*['"]download['"]\s*,)\s*['"`]([^'"`\r\n]{1,260})['"`]""",
    re.IGNORECASE,
)
_DATA_URI_B64_RE = re.compile(
    r"data:([a-z0-9.+/-]{0,64})(?:;[a-z0-9._=-]{1,40}){0,4};base64,([A-Za-z0-9+/=\r\n\t ]{24,})",
    re.IGNORECASE,
)
_SCRIPT_CLOSE_RE = re.compile(
    r"</(?:[a-zA-Z_][\w.-]{0,64}:)?script[\s/>]", re.IGNORECASE
)
_HTML_RAWTEXT_TAGS = (
    "style", "title", "textarea", "xmp", "iframe", "noembed", "noframes",
)
_RAWTEXT_CLOSE_RES: dict[str, re.Pattern[str]] = {
    _tag: re.compile(
        rf"</(?:[a-zA-Z_][\w.-]{{0,64}}:)?{_tag}[\s/>]", re.IGNORECASE
    )
    for _tag in _HTML_RAWTEXT_TAGS
}
_OVERSIZED_EVENT_RE = re.compile(r"""[\s/"']on[a-z]{3,24}\s*=""", re.IGNORECASE)
_BENIGN_GEOMETRY_TAGS = frozenset({"path", "polygon", "polyline"})
_MAX_SINGLE_TAG_LEN = 65_536
_ATOB_B64_RE = re.compile(
    r"\batob\s*\(\s*['\"`]([A-Za-z0-9+/=\r\n\t ]{24,})",
    re.IGNORECASE,
)
_GENERIC_B64_RE = re.compile(r"[A-Za-z0-9+/][A-Za-z0-9+/=\r\n]{127,}")
_JS_EXFIL_RE = re.compile(
    r"""(?:\bfetch|\bsendBeacon)\s*\(\s*['"`](?:https?:)?//|"""
    r"""\.\s*open\s*\(\s*['"`][A-Za-z]{3,10}['"`]\s*,\s*['"`](?:https?:)?//""",
    re.IGNORECASE,
)
_SVG_JS_REDIRECT_RE = re.compile(
    r"(?:\b(?:window|document|top|self|parent)\s*\.\s*location\b|"
    r"\blocation\s*\.\s*(?:href|replace|assign)\b|"
    r"\blocation\s*=|\bwindow\s*\.\s*open\s*\()",
    re.IGNORECASE,
)
_HHCLICK_RE = re.compile(r"\.\s*hhclick\s*\(", re.IGNORECASE)
_ON_ATTR_RE = re.compile(r"^on[a-z]{3,24}$")
_META_URL_RE = re.compile(r"\burl\s*=\s*([^\r\n;]{1,512})", re.IGNORECASE)
_CTRL_SPACE_RE = re.compile(r"[\x00-\x20]+")


def _clean_uri_scheme(value: str) -> str:
    """Unescape HTML entities and strip ASCII control/space chars for scheme checks."""
    unescaped = html.unescape(value)
    return _CTRL_SPACE_RE.sub("", unescaped).lower()


def _decode_web_text(data: bytes) -> str:
    """Crash-safe decode (UTF-16 BOM/BOM-less shared with magic.py, else UTF-8)."""
    utf16 = magic.decode_utf16_if_detected(data)
    if utf16 is not None:
        return utf16
    return data.decode("utf-8", errors="replace").lstrip("\ufeff")


def _merge_array_joins(text: str) -> str:
    """Linear O(N) resolver for simple ``['a','b'].join('')`` string arrays."""
    marker = ".join("
    if marker not in text:
        return text
    out: list[str] = []
    pos = 0
    n = len(text)
    while pos < n:
        idx = text.find(marker, pos)
        if idx == -1:
            out.append(text[pos:])
            break
        j = idx + len(marker)
        while j < n and text[j] in " \t":
            j += 1
        if j + 2 <= n and text[j : j + 2] in ("''", '""'):
            k = j + 2
            while k < n and text[k] in " \t":
                k += 1
            if k < n and text[k] == ")":
                rb = idx - 1
                while rb >= pos and text[rb] in " \t\r\n":
                    rb -= 1
                if rb >= pos and text[rb] == "]":
                    search_start = max(pos, rb - 65_536)
                    lb = text.rfind("[", search_start, rb)
                    if lb != -1:
                        merged = _parse_string_array(text[lb + 1 : rb])
                        if merged is not None:
                            out.append(text[pos:lb])
                            out.append('"' + merged + '"')
                            pos = k + 1
                            continue
        out.append(text[pos : idx + len(marker)])
        pos = idx + len(marker)
    return "".join(out)


def _parse_string_array(inner: str) -> str | None:
    """Parse comma-separated single/double-quoted literals without nesting."""
    parts: list[str] = []
    i = 0
    n = len(inner)
    while i < n:
        while i < n and inner[i] in " \t\r\n,":
            i += 1
        if i >= n:
            break
        quote = inner[i]
        if quote not in ("'", '"'):
            return None
        end = inner.find(quote, i + 1)
        if end == -1:
            return None
        parts.append(inner[i + 1 : end])
        i = end + 1
        if len(parts) > 512:
            return None
    if len(parts) < 2:
        return None
    return "".join(parts)


def _preprocess_js(text: str) -> str:
    """Merge simple JS string concatenations and array joins linearly."""
    work = _CONCAT_RE.sub("", text)
    if ".join(" in work:
        work = _merge_array_joins(work)
    return work


def _b64_decode_prefix(raw_b64: str, max_b64_chars: int) -> bytes | None:
    """Strip ASCII whitespace and decode up to ``max_b64_chars`` of Base64."""
    cleaned = _CTRL_SPACE_RE.sub("", raw_b64)
    if len(cleaned) < 24:
        return None
    chunk = cleaned[:max_b64_chars]
    rem = len(chunk) % 4
    if rem == 1:
        chunk = chunk[:-1]
    elif rem:
        chunk = chunk + ("=" * (4 - rem))
    try:
        return base64.b64decode(chunk, validate=False)
    except Exception:
        return None


def _is_valid_pe(decoded: bytes) -> bool:
    """Strict PE check (MZ + valid e_lfanew -> PE\\0\\0) to prevent MZ false hits."""
    if len(decoded) < 64 or decoded[:2] != b"MZ":
        return False
    e_lfanew = int.from_bytes(decoded[60:64], "little")
    return 64 <= e_lfanew <= len(decoded) - 4 and decoded[e_lfanew : e_lfanew + 4] == b"PE\x00\x00"


class _WebTagCollector(HTMLParser):
    """Single-pass O(N) HTML/SVG tag collector with hard tag cap."""

    # _feed_bounded_tags extracts <script> bodies itself; disabling HTMLParser's
    # internal CDATA mode guarantees <script>/<style> never swallow later tags.
    def set_cdata_mode(self, elem: str, *, escapable: bool = False) -> None:
        return

    def __init__(self, *, xml_mode: bool = False) -> None:
        super().__init__(convert_charrefs=True)
        self.xml_mode = xml_mode
        self.tag_count = 0
        self.tag_limit_exceeded = False

        self.script_depth = 0
        self.rawtext_tag: str | None = None
        self.foreign_depth = 0
        self.foreign_ns_depth = 0
        self.object_hhctrl_depth = 0

        self.has_script_tag = False
        self.script_texts: list[str] = []
        self.event_handlers: list[str] = []
        self.event_values: list[str] = []
        self.js_uris: list[str] = []
        self.svg_data_html_uris: list[str] = []

        self.foreign_active_hits: list[str] = []

        self.has_password_input = False
        self.has_foreign_password_input = False
        self.external_form_actions: list[str] = []
        self.foreign_external_form_actions: list[str] = []

        self.meta_refresh_targets: list[str] = []
        self.download_names: list[str] = []

        self.has_hhctrl_object = False
        self.has_hhctrl_shortcut_param = False

        self.data_uri_attrs: list[tuple[str, str]] = []

    def _local_name(self, tag: str) -> str:
        return tag.rsplit(":", 1)[-1].lower()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.tag_limit_exceeded:
            return
        self.tag_count += 1
        if self.tag_count > _MAX_TAGS:
            self.tag_limit_exceeded = True
            return

        local = self._local_name(tag)
        attr_map: dict[str, str] = {}
        for raw_k, raw_v in attrs:
            if not raw_k:
                continue
            k = raw_k.lower()
            v = raw_v or ""
            attr_map[k] = v

            if _ON_ATTR_RE.match(k):
                if len(self.event_handlers) < 16:
                    self.event_handlers.append(k)
                if len(self.event_values) < 64 and v:
                    self.event_values.append(v[:1024])
                if self.foreign_depth > 0 and len(self.foreign_active_hits) < 8:
                    self.foreign_active_hits.append(f"@{k}")

            local_attr = k.rsplit(":", 1)[-1]
            if local_attr in ("href", "src", "action", "data", "values", "to", "from"):
                uri_parts = v.split(";") if local_attr == "values" else (v,)
                for raw_part in uri_parts[:256]:
                    cleaned = _clean_uri_scheme(raw_part)
                    if cleaned.startswith(("javascript:", "vbscript:")):
                        if len(self.js_uris) < 16:
                            self.js_uris.append(cleaned[:256])
                        if self.foreign_depth > 0 and len(self.foreign_active_hits) < 8:
                            self.foreign_active_hits.append(cleaned[:32])
                    elif cleaned.startswith("data:text/html"):
                        if len(self.svg_data_html_uris) < 16:
                            self.svg_data_html_uris.append(cleaned[:128])
                        if self.foreign_depth > 0 and len(self.foreign_active_hits) < 8:
                            self.foreign_active_hits.append("data:text/html")

                if "base64," in v.lower():
                    m = _DATA_URI_B64_RE.search(v)
                    if m and len(self.data_uri_attrs) < _MAX_B64_CANDIDATES:
                        self.data_uri_attrs.append((m.group(1).lower(), m.group(2)))

        if local in ("svg", "math"):
            self.foreign_ns_depth += 1

        in_html_ns = not self.xml_mode and (
            self.foreign_ns_depth == 0 or self.foreign_depth > 0
        )
        if local == "script":
            self.has_script_tag = True
            self.script_depth += 1
        elif local == "style" or (in_html_ns and local in _RAWTEXT_CLOSE_RES):
            self.rawtext_tag = local

        if local == "foreignobject":
            self.foreign_depth += 1
        elif (
            self.foreign_depth > 0
            and local in _FOREIGN_ACTIVE_TAGS
            and len(self.foreign_active_hits) < 8
        ):
            self.foreign_active_hits.append(f"<{local}>")

        if local == "input" and attr_map.get("type", "").strip().lower() == "password":
            self.has_password_input = True
            if self.foreign_depth > 0:
                self.has_foreign_password_input = True

        if local == "form":
            action = attr_map.get("action", "").strip()
            low_action = _clean_uri_scheme(action)
            if low_action.startswith(("http://", "https://", "//")):
                if len(self.external_form_actions) < 8:
                    self.external_form_actions.append(action[:160])
                if self.foreign_depth > 0 and len(self.foreign_external_form_actions) < 8:
                    self.foreign_external_form_actions.append(action[:160])

        if local == "meta":
            http_equiv = attr_map.get("http-equiv", "").strip().lower()
            content = attr_map.get("content", "")
            if http_equiv == "refresh" and content:
                m = _META_URL_RE.search(content)
                if m:
                    raw_url = m.group(1).strip().strip("'\"")
                    if len(self.meta_refresh_targets) < 8:
                        self.meta_refresh_targets.append(raw_url)

        if local in ("a", "area") and "download" in attr_map:
            dl = attr_map.get("download", "").strip()
            if dl and len(self.download_names) < 16:
                self.download_names.append(dl)

        if local == "object":
            classid = attr_map.get("classid", "").lower()
            if any(cid in classid for cid in _HHCTRL_CLSIDS):
                self.has_hhctrl_object = True
                self.object_hhctrl_depth += 1

        if local == "param" and self.object_hhctrl_depth > 0:
            pname = attr_map.get("name", "").strip().lower()
            pval = attr_map.get("value", "").strip().lower()
            if pname == "command" and pval in ("shortcut", "tcard", "winhelp"):
                self.has_hhctrl_shortcut_param = True

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        # In WHATWG HTML5, trailing '/' closes elements ONLY in XML mode or
        # inside foreign content (<svg>/<math> §13.2.6.5), never HTML non-voids.
        if not (self.xml_mode or self.foreign_ns_depth > 0):
            return
        local = self._local_name(tag)
        if local == "script" and self.script_depth > 0:
            self.script_depth -= 1
        elif local == self.rawtext_tag:
            self.rawtext_tag = None
        elif local == "foreignobject" and self.foreign_depth > 0:
            self.foreign_depth -= 1
        elif local == "object" and self.object_hhctrl_depth > 0:
            self.object_hhctrl_depth -= 1
        if local in ("svg", "math") and self.foreign_ns_depth > 0:
            self.foreign_ns_depth -= 1

    def handle_endtag(self, tag: str) -> None:
        if self.tag_limit_exceeded:
            return
        local = self._local_name(tag)
        if local == "script" and self.script_depth > 0:
            self.script_depth -= 1
        elif local == self.rawtext_tag:
            self.rawtext_tag = None
        elif local == "foreignobject" and self.foreign_depth > 0:
            self.foreign_depth -= 1
        elif local == "object" and self.object_hhctrl_depth > 0:
            self.object_hhctrl_depth -= 1
        if local in ("svg", "math") and self.foreign_ns_depth > 0:
            self.foreign_ns_depth -= 1

    def handle_data(self, data: str) -> None:
        if self.tag_limit_exceeded:
            return
        if self.script_depth > 0 and data and len(self.script_texts) < 128:
            self.script_texts.append(data)

    def unknown_decl(self, data: str) -> None:
        """Capture ``<![CDATA[...]]>`` inside ``<svg:script>`` blocks."""
        if self.tag_limit_exceeded:
            return
        if self.script_depth > 0 and data.startswith("CDATA[") and len(self.script_texts) < 128:
            self.script_texts.append(data[6:])


def _find_tag_end_linear(
    text: str, lt: int, exhausted_quotes: set[str]
) -> tuple[int, int]:
    """Strictly O(N) WHATWG HTML5 6-state tag-attribute scanner starting at ``lt``.

    Follows WHATWG HTML5 §13.2.5.32-38 so leading ``=`` (``<a =">``, ``<a/=">``)
    starts an attribute name, duplicate ``=`` (``<a x==">``) starts an unquoted
    value, and ``'``/``"`` opens a quoted value ONLY in ``BEFORE_ATTR_VAL``.
    Each index is visited at most once; unclosed quotes are memoized in
    ``exhausted_quotes`` so later tags are never swallowed.
    """
    n = len(text)
    i = lt + 1
    # States: 0=TAG_NAME, 1=BEFORE_ATTR_NAME, 2=ATTR_NAME,
    #         3=AFTER_ATTR_NAME, 4=BEFORE_ATTR_VAL, 5=UNQUOTED_VAL
    state = 0
    while i < n:
        ch = text[i]
        if ch == ">":
            return i, i + 1
        if ch == "<":
            return -1, i

        is_ws = ch in " \t\r\n\f"
        if state == 0:  # TAG_NAME
            if is_ws or ch == "/":
                state = 1
        elif state == 1:  # BEFORE_ATTR_NAME
            if not is_ws and ch != "/":
                state = 2  # including '=' per WHATWG §13.2.5.33
        elif state == 2:  # ATTR_NAME
            if ch == "=":
                state = 4
            elif is_ws:
                state = 3
            elif ch == "/":
                state = 1
        elif state == 3:  # AFTER_ATTR_NAME
            if ch == "=":
                state = 4
            elif ch == "/":
                state = 1
            elif not is_ws:
                state = 2
        elif state == 4:  # BEFORE_ATTR_VAL
            if is_ws:
                pass
            elif ch in ('"', "'"):
                if ch not in exhausted_quotes:
                    q_end = text.find(ch, i + 1)
                    if q_end == -1:
                        exhausted_quotes.add(ch)
                        state = 5
                    else:
                        i = q_end + 1
                        state = 1
                        continue
                else:
                    state = 5
            else:
                state = 5  # including '=' per WHATWG §13.2.5.38
        else:  # 5 = UNQUOTED_VAL
            if is_ws:
                state = 1
        i += 1
    return -1, n

def _extract_tag_local_name(text: str, lt: int, gt: int) -> str:
    i = lt + 1
    while i < gt and text[i] in " /!?\t\r\n":
        i += 1
    start = i
    while i < gt and (text[i].isalnum() or text[i] in "_.-:"):
        i += 1
    return text[start:i].rsplit(":", 1)[-1].lower()


def _feed_bounded_tags(
    collector: _WebTagCollector, text: str, *, xml_mode: bool = False
) -> None:
    """Feed bounded ``<...>`` tokens to ``_WebTagCollector`` in strictly O(N) time."""
    n = len(text)
    pos = 0
    exhausted_quotes: set[str] = set()
    no_std_comment = False
    no_bang_comment = False
    next_std_comment = -1
    next_bang_comment = -1
    no_pi_close = False
    while pos < n and not collector.tag_limit_exceeded:
        if collector.script_depth > 0:
            m_close = _SCRIPT_CLOSE_RE.search(text, pos)
            body = text[pos:] if m_close is None else text[pos : m_close.start()]
            if body:
                if "<![CDATA[" in body:
                    body = body.replace("<![CDATA[", "").replace("]]>", "")
                collector.handle_data(body)
            if m_close is None:
                break
            end_gt = text.find(">", m_close.end() - 1)
            if end_gt == -1:
                break
            collector.handle_endtag("script")
            pos = end_gt + 1
            continue

        if collector.rawtext_tag is not None:
            rt_tag = collector.rawtext_tag
            m_close = _RAWTEXT_CLOSE_RES[rt_tag].search(text, pos)
            if m_close is None:
                break
            end_gt = text.find(">", m_close.end() - 1)
            if end_gt == -1:
                break
            collector.handle_endtag(rt_tag)
            pos = end_gt + 1
            continue

        lt = text.find("<", pos)
        if lt == -1 or lt + 1 >= n:
            break

        # HTML5: '<' only starts a tag/declaration if followed by [A-Za-z/!?].
        # Literal '<' in text (e.g. 'If x < 5 and it's fine') is skipped cleanly.
        nxt = text[lt + 1]
        if not (nxt.isalpha() or nxt in "/!?"):
            pos = lt + 1
            continue

        # HTML5 comments: handle abrupt '<!-->' / '<!--->' and both '-->' / '--!>'.
        if text.startswith("<!--", lt):
            if text.startswith("<!-->", lt):
                pos = lt + 5
                continue
            if text.startswith("<!--->", lt):
                pos = lt + 6
                continue
            if not no_std_comment and next_std_comment < lt + 4:
                next_std_comment = text.find("-->", lt + 4)
                if next_std_comment == -1:
                    no_std_comment = True
            if not no_bang_comment and next_bang_comment < lt + 4:
                next_bang_comment = text.find("--!>", lt + 4)
                if next_bang_comment == -1:
                    no_bang_comment = True
            if no_std_comment and no_bang_comment:
                break
            pos = (
                next_std_comment + 3
                if not no_std_comment
                and (no_bang_comment or next_std_comment < next_bang_comment)
                else next_bang_comment + 4
            )
            continue

        # CDATA only exists in XML/SVG; in HTML5 '<![CDATA[...>' is a bogus comment
        # terminated at the very first '>'.
        if text.startswith("<![CDATA[", lt):
            if xml_mode:
                end_cd = text.find("]]>", lt + 9)
                if end_cd == -1:
                    break
                pos = end_cd + 3
            else:
                gt_cd = text.find(">", lt + 9)
                if gt_cd == -1:
                    break
                pos = gt_cd + 1
            continue

        # HTML5 bogus comments / XML PIs & declarations: never run through
        # attribute-quote scanning (prevents '<!x a=">' / '<?x a=">' from
        # swallowing the following tag).
        if nxt == "?":
            if xml_mode and not no_pi_close:
                end_pi = text.find("?>", lt + 2)
                if end_pi != -1:
                    pos = end_pi + 2
                    continue
                no_pi_close = True
            gt_pi = text.find(">", lt + 2)
            if gt_pi == -1:
                break
            pos = gt_pi + 1
            continue

        if nxt == "!":
            gt_decl = text.find(">", lt + 2)
            if gt_decl == -1:
                break
            if xml_mode:
                lb = text.find("[", lt + 2, gt_decl)
                if lb != -1:
                    rb = text.find("]>", lb + 1)
                    if rb == -1:
                        break
                    pos = rb + 2
                    continue
            pos = gt_decl + 1
            continue

        gt, next_pos = _find_tag_end_linear(text, lt, exhausted_quotes)
        if gt == -1:
            pos = next_pos
            continue

        tag_len = gt - lt + 1
        if tag_len > _MAX_SINGLE_TAG_LEN:
            local = _extract_tag_local_name(text, lt, gt)
            tag_slice = text[lt : gt + 1]
            low_slice = tag_slice.lower()
            if "base64," in low_slice:
                for m in _DATA_URI_B64_RE.finditer(tag_slice):
                    if len(collector.data_uri_attrs) >= _MAX_B64_CANDIDATES:
                        break
                    collector.data_uri_attrs.append((m.group(1).lower(), m.group(2)))
            is_benign_geom = (
                local in _BENIGN_GEOMETRY_TAGS
                and _OVERSIZED_EVENT_RE.search(tag_slice) is None
                and not any(
                    tok in low_slice
                    for tok in ("javascript:", "vbscript:", "data:text/html", "<script", "&#")
                )
            )
            if not is_benign_geom:
                collector.tag_limit_exceeded = True
                break
            pos = next_pos
            continue

        collector.rawdata = ""
        collector.clear_cdata_mode()
        with contextlib.suppress(Exception):
            collector.feed(text[lt : gt + 1])
        pos = next_pos

class WebContentPipeline(Pipeline):
    name = "web"

    def analyze(self, ctx: AnalysisContext) -> list[Indicator]:
        if not ctx.data:
            return []
        text = _decode_web_text(ctx.data)
        suffix = ctx.path.suffix.lower() if ctx.path.suffix else ""
        is_svg = magic.is_svg_root(text)
        is_html = ctx.detected_type == "html" or suffix in _WEB_HTML_SUFFIXES

        # Plain XML (e.g. rechnung.xml, OOXML members) without <svg> or HTML suffix.
        if not is_svg and not is_html:
            return []

        return self._analyze_text(text, is_svg=is_svg, is_html=is_html, depth=0)

    def _analyze_text(
        self,
        text: str,
        *,
        is_svg: bool,
        is_html: bool,
        depth: int,
    ) -> list[Indicator]:
        xml_mode = is_svg and not is_html
        collector = _WebTagCollector(xml_mode=xml_mode)
        with contextlib.suppress(Exception):
            _feed_bounded_tags(collector, text, xml_mode=xml_mode)

        found: dict[str, Indicator] = {}

        def _add(ind: Indicator) -> None:
            if ind.rule_id not in found:
                found[ind.rule_id] = ind

        if collector.tag_limit_exceeded:
            _add(
                self._indicator(
                    "WEB_PARSE_LIMIT",
                    "HTML/SVG-Tag-Limit überschritten",
                    detail=(
                        f"Die Strukturprüfung wurde nach {_MAX_TAGS} Tags gestoppt. "
                        "Der Rest des Dokuments wurde strukturell NICHT geprüft — "
                        "das Ergebnis ist unvollständig und nicht als 'sauber' zu werten."
                    ),
                    severity=Severity.MEDIUM,
                    category=CAT_CONTENT,
                    weight=20,
                )
            )

        work = _preprocess_js(text)

        download_names = list(collector.download_names)
        for m in _JS_DOWNLOAD_RE.finditer(work):
            if len(download_names) >= 32:
                break
            download_names.append(m.group(1).strip())

        smuggle_ind = self._check_html_smuggling(work, download_names)
        if smuggle_ind is not None:
            _add(smuggle_ind)

        payload_ind, decoded_snippets = self._check_base64_payloads(work, collector)
        if payload_ind is not None:
            _add(payload_ind)

        cred_ind = self._check_credential_form(
            work,
            collector,
            is_html=is_html,
            is_svg=is_svg,
        )
        if cred_ind is not None:
            _add(cred_ind)

        if is_html:
            meta_ind = self._check_meta_refresh(collector)
            if meta_ind is not None:
                _add(meta_ind)
            chm_ind = self._check_chm_activex(work, collector)
            if chm_ind is not None:
                _add(chm_ind)

        if is_svg:
            for ind in self._check_svg(collector):
                _add(ind)

        if depth == 0 and decoded_snippets:
            for snippet_text, snippet_is_svg, snippet_is_html in decoded_snippets:
                sub_inds = self._analyze_text(
                    snippet_text,
                    is_svg=snippet_is_svg,
                    is_html=snippet_is_html,
                    depth=1,
                )
                for ind in sub_inds:
                    _add(ind)

        return list(found.values())

    def _check_html_smuggling(
        self, work: str, download_names: list[str]
    ) -> Indicator | None:
        low_work = work.lower()
        has_binary_mime = any(mime in low_work for mime in _BINARY_SMUGGLE_MIMES)

        normalized_dls = [d.lower().strip() for d in download_names if d.strip()]
        has_risky_dl = any(
            d.endswith(_SMUGGLING_DOWNLOAD_SUFFIXES) for d in normalized_dls
        )
        all_benign_dl = (
            bool(normalized_dls)
            and all(
                any(d.endswith(ext) for ext in _BENIGN_DOWNLOAD_SUFFIXES)
                for d in normalized_dls
            )
            and not has_binary_mime
        )

        classes: list[str] = []
        if _SMUGGLE_A_RE.search(work):
            classes.append("Payload-Synthese (atob/Uint8Array/ArrayBuffer)")
        if _SMUGGLE_B_RE.search(work):
            classes.append("Blob/ObjectURL/Binary-Data-URI")

        has_ms_save = bool(_SMUGGLE_MS_SAVE_RE.search(work))
        has_c = bool(
            has_ms_save
            or has_risky_dl
            or (
                not all_benign_dl
                and _SMUGGLE_CLICK_RE.search(work)
                and _SMUGGLE_CREATE_A_RE.search(work)
                and ("createobjecturl(" in low_work or "data:" in low_work)
            )
        )

        if has_c:
            classes.append("Erzwungener Download/Drop")

        if len(classes) < 2:
            return None
        if all_benign_dl and not has_risky_dl and not has_ms_save:
            return None

        return self._indicator(
            "HTML_SMUGGLING",
            "HTML-Smuggling-Muster erkannt",
            detail=(
                "Kombination typischer HTML-Smuggling-Primitive: "
                + ", ".join(classes)
                + "."
            ),
            severity=Severity.HIGH,
            category=CAT_SCRIPT,
            weight=35,
        )

    def _check_base64_payloads(
        self,
        work: str,
        collector: _WebTagCollector,
    ) -> tuple[Indicator | None, list[tuple[str, bool, bool]]]:
        # Independent caps per source so many benign data:image/png icons can
        # never starve atob(...) or generic Base64 payload extraction.
        candidates: list[tuple[str, str, str]] = []

        data_candidates: list[tuple[str, str, str]] = [
            ("data", mime, b64) for mime, b64 in collector.data_uri_attrs[:_MAX_B64_CANDIDATES]
        ]
        for m in _DATA_URI_B64_RE.finditer(work):
            if len(data_candidates) >= _MAX_B64_CANDIDATES * 2:
                break
            data_candidates.append(("data", m.group(1).lower(), m.group(2)))
        candidates.extend(data_candidates)

        for atob_count, m in enumerate(_ATOB_B64_RE.finditer(work)):
            if atob_count >= _MAX_B64_CANDIDATES:
                break
            candidates.append(("atob", "", m.group(1)))

        generic_matches: list[str] = []
        for m in _GENERIC_B64_RE.finditer(work):
            generic_matches.append(m.group(0))
            if len(generic_matches) >= _MAX_B64_CANDIDATES * 4:
                break
        if len(generic_matches) > _MAX_B64_CANDIDATES:
            generic_matches.sort(key=len, reverse=True)
            generic_matches = generic_matches[:_MAX_B64_CANDIDATES]
        for raw in generic_matches:
            candidates.append(("generic", "", raw))

        detected_types: list[str] = []
        stage2_queue: list[tuple[int, str, str, str]] = []
        seen_prefix: set[str] = set()

        for kind, mime, raw in candidates:
            key = f"{kind}:{mime}:{len(raw)}:{raw[:64]}:{raw[-32:]}"
            if key in seen_prefix:
                continue
            seen_prefix.add(key)

            head = _b64_decode_prefix(raw, _STAGE1_B64_CHARS)
            if not head or len(head) < 4:
                continue
            ftype = magic.detect(head).type

            if ftype in _BENIGN_IMAGE_TYPES:
                continue

            if ftype in _SMUGGLED_DANGEROUS_TYPES and ftype != "pe":
                if ftype not in detected_types:
                    detected_types.append(ftype)
                continue

            needs_stage2 = (
                head[:2] == b"MZ"
                or head[:16] == b"\x00" * 16
                or (kind == "data" and mime in ("text/html", "image/svg+xml"))
                or kind == "atob"
            )
            if needs_stage2:
                stage2_queue.append((len(raw), kind, mime, raw))

        stage2_queue.sort(key=lambda item: item[0], reverse=True)
        decoded_snippets: list[tuple[str, bool, bool]] = []

        for _, kind, mime, raw in stage2_queue[:_MAX_STAGE2_CHECKS]:
            decoded = _b64_decode_prefix(raw, _STAGE2_B64_CHARS)
            if not decoded:
                continue
            if decoded[:2] == b"MZ" and _is_valid_pe(decoded):
                if "pe" not in detected_types:
                    detected_types.append("pe")
                continue
            ftype = magic.detect(decoded).type
            if ftype in _SMUGGLED_DANGEROUS_TYPES and ftype != "pe":
                if ftype not in detected_types:
                    detected_types.append(ftype)
                continue
            if (
                len(decoded_snippets) < 8
                and (
                    (kind == "data" and mime in ("text/html", "image/svg+xml"))
                    or kind == "atob"
                )
                and b"\x00" not in decoded[:256]
            ):
                snippet = decoded.decode("utf-8", errors="replace")
                s_svg = mime == "image/svg+xml" or magic.is_svg_root(snippet)
                low_s = snippet.lower()
                s_html = (
                    mime == "text/html"
                    or "<form" in low_s
                    or "<script" in low_s
                    or "<meta" in low_s
                    or "<object" in low_s
                    or "<html" in low_s
                    or (
                        kind == "atob"
                        and (
                            "blob(" in low_s
                            or "createobjecturl(" in low_s
                            or "mssave" in low_s
                            or "download" in low_s
                        )
                    )
                )
                if s_svg or s_html:
                    decoded_snippets.append((snippet, s_svg, s_html))

        payload_ind: Indicator | None = None
        if detected_types:
            types_str = ", ".join(t.upper() for t in detected_types[:4])
            payload_ind = self._indicator(
                "HTML_SMUGGLED_PAYLOAD",
                f"Eingebetteter Base64-Payload erkannt ({types_str})",
                detail=(
                    f"Ein eingebetteter Base64-Block dekodiert zu einem gefährlichen "
                    f"Binärformat ({types_str}) — starker Hinweis auf HTML-/SVG-Smuggling."
                ),
                severity=Severity.CRITICAL,
                category=CAT_SCRIPT,
                weight=50,
            )
        return payload_ind, decoded_snippets

    def _check_credential_form(
        self,
        work: str,
        collector: _WebTagCollector,
        *,
        is_html: bool,
        is_svg: bool,
    ) -> Indicator | None:
        if is_html:
            has_pw = collector.has_password_input
            actions = collector.external_form_actions
        elif is_svg:
            has_pw = collector.has_foreign_password_input
            actions = collector.foreign_external_form_actions
        else:
            return None

        if not has_pw:
            return None

        exfil_sources: list[str] = []
        if actions:
            exfil_sources.append(f"form[action]={actions[0]}")
        else:
            js_scope = "\n".join(collector.script_texts + collector.event_values)
            if not js_scope and is_html:
                js_scope = work
            if _JS_EXFIL_RE.search(_preprocess_js(js_scope)):
                exfil_sources.append("JS-Abfluss (fetch/XHR/sendBeacon)")

        if not exfil_sources:
            return None

        return self._indicator(
            "HTML_CREDENTIAL_FORM",
            "Passwort-Formular mit externem Abfluss",
            detail=(
                "Lokales HTML/SVG enthält ein Passwortfeld (<input type='password'>) "
                f"mit externem Ziel ({', '.join(exfil_sources)}) — typisches Offline-Phishing."
            ),
            severity=Severity.MEDIUM,
            category=CAT_CONTENT,
            weight=25,
        )

    def _check_meta_refresh(self, collector: _WebTagCollector) -> Indicator | None:
        bad_targets: list[str] = []
        for raw_target in collector.meta_refresh_targets:
            cleaned = _clean_uri_scheme(raw_target)
            if cleaned.startswith(("javascript:", "vbscript:", "data:", "file:", "\\\\")):
                bad_targets.append(cleaned[:64])
        if not bad_targets:
            return None
        return self._indicator(
            "HTML_META_REFRESH_SUSPICIOUS",
            "Verdächtige Meta-Refresh-Weiterleitung",
            detail=(
                "Meta-Refresh verweist auf ein aktives oder lokales Schema: "
                + ", ".join(bad_targets[:4])
                + "."
            ),
            severity=Severity.MEDIUM,
            category=CAT_SCRIPT,
            weight=20,
        )

    def _check_chm_activex(
        self, work: str, collector: _WebTagCollector
    ) -> Indicator | None:
        if not collector.has_hhctrl_object:
            return None
        if not (collector.has_hhctrl_shortcut_param or _HHCLICK_RE.search(work)):
            return None
        return self._indicator(
            "HTML_CHM_ACTIVEX",
            "CHM-ActiveX-Befehlsausführung (hhctrl ShortCut)",
            detail=(
                "HTML-Seite bindet das HTML-Help-ActiveX-Steuerelement (hhctrl) "
                "mit ShortCut-/Befehlsausführung ein — typischer CHM-Malware-Vektor."
            ),
            severity=Severity.CRITICAL,
            category=CAT_SCRIPT,
            weight=50,
        )

    def _check_svg(self, collector: _WebTagCollector) -> list[Indicator]:
        out: list[Indicator] = []

        script_reasons: list[str] = []
        if collector.has_script_tag:
            script_reasons.append("<script>-Tag")
        if collector.event_handlers:
            script_reasons.append(
                "Event-Handler (" + ", ".join(collector.event_handlers[:4]) + ")"
            )
        if collector.js_uris:
            script_reasons.append("javascript:/vbscript:-URI")
        if script_reasons:
            out.append(
                self._indicator(
                    "SVG_SCRIPT",
                    "Aktiver Skript-Inhalt in SVG-Grafik",
                    detail=(
                        "SVG enthält ausführbaren Inhalt: "
                        + ", ".join(script_reasons)
                        + "."
                    ),
                    severity=Severity.HIGH,
                    category=CAT_SCRIPT,
                    weight=35,
                )
            )

        if collector.foreign_active_hits:
            out.append(
                self._indicator(
                    "SVG_FOREIGN_OBJECT",
                    "Interaktiver HTML-Inhalt in SVG (<foreignObject>)",
                    detail=(
                        "SVG bettet aktiven HTML-Inhalt über <foreignObject> ein: "
                        + ", ".join(collector.foreign_active_hits[:4])
                        + "."
                    ),
                    severity=Severity.MEDIUM,
                    category=CAT_SCRIPT,
                    weight=20,
                )
            )

        redir_reasons: list[str] = []
        js_context = "\n".join(
            collector.script_texts + collector.event_values + collector.js_uris
        )
        if js_context and _SVG_JS_REDIRECT_RE.search(_preprocess_js(js_context)):
            redir_reasons.append("JS-Weiterleitung (location/window.open)")
        if collector.meta_refresh_targets:
            redir_reasons.append("<meta http-equiv='refresh'>")
        if collector.svg_data_html_uris:
            redir_reasons.append("data:text/html-URI")
        if redir_reasons:
            out.append(
                self._indicator(
                    "SVG_EXTERNAL_REDIRECT",
                    "Aktive Weiterleitung in SVG-Grafik",
                    detail=(
                        "SVG löst eine aktive Weiterleitung oder HTML-Einbettung aus: "
                        + ", ".join(redir_reasons)
                        + "."
                    ),
                    severity=Severity.MEDIUM,
                    category=CAT_IOC,
                    weight=20,
                )
            )

        return out
