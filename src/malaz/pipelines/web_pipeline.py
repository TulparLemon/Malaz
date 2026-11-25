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

from ..core import magic, qr_scan
from ..core.js_deobf import deobfuscate_js_detailed, merge_js_array_joins
from ..core.risky_types import RISKY_SUFFIXES
from ..core.script_deobf import DeobfBudget
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
    r"</(?:[a-zA-Z_][\w.-]{0,64}:)?script[ \t\r\n/>]", re.IGNORECASE
)
_HTML_RAWTEXT_TAGS = (
    "style", "title", "textarea", "xmp", "iframe", "noembed", "noframes", "noscript",
)
# WHATWG HTML5 §13.2.6.5 start tags that break out of foreign content (<svg>/<math>)
_FOREIGN_BREAKOUT_TAGS = frozenset(
    {
        "b", "big", "blockquote", "body", "br", "center", "code", "dd", "div",
        "dl", "dt", "em", "embed", "h1", "h2", "h3", "h4", "h5", "h6", "head",
        "hr", "i", "img", "li", "listing", "menu", "meta", "nobr", "ol", "p",
        "pre", "ruby", "s", "small", "span", "strong", "strike", "sub", "sup",
        "table", "tt", "u", "ul", "var",
    }
)
_SVG_HTML_INTEGRATION_TAGS = frozenset({"foreignobject", "desc", "title"})
_MATH_TEXT_INTEGRATION_TAGS = frozenset({"mi", "mo", "mn", "ms", "mtext"})
_HTML_VOID_TAGS = frozenset(
    {
        "area", "base", "br", "col", "embed", "hr", "img", "input",
        "link", "meta", "param", "source", "track", "wbr",
    }
)
_HTML_SCRIPT_TOKEN_RE = re.compile(
    r"<!--+>|<!--|-->|</?script(?=[ \t\r\n\f/>])", re.IGNORECASE
)
_RAWTEXT_CLOSE_RES: dict[str, re.Pattern[str]] = {
    _tag: re.compile(rf"</{_tag}[ \t\r\n\f/>]", re.IGNORECASE)
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
_META_URL_RE = re.compile(r"\burl\s*=\s*([^;]+)", re.IGNORECASE)
_META_CTRL_TABLE = str.maketrans("", "", "".join(chr(c) for c in range(0x20)))
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


def _preprocess_js(text: str) -> tuple[str, bool]:
    """Merge simple JS string concatenations and array joins linearly."""
    work = _CONCAT_RE.sub("", text)
    limit_hit = False
    if ".join(" in work:
        work, _changed, limit_hit = merge_js_array_joins(
            work, max_output=max(512 * 1024, len(work) + 65_536)
        )
    return work, limit_hit


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


def _is_confirmed_benign_image_b64(raw_b64: str) -> bool:
    """Return True if the first 48 decoded bytes match a benign raster image magic."""
    head = _b64_decode_prefix(raw_b64, _STAGE1_B64_CHARS)
    return bool(head and len(head) >= 4 and magic.detect(head).type in _BENIGN_IMAGE_TYPES)


class _WebTagCollector(HTMLParser):
    """Single-pass O(N) HTML/SVG tag collector with hard tag cap."""

    # _feed_bounded_tags extracts <script> bodies itself; disabling HTMLParser's
    # internal CDATA mode guarantees <script>/<style> never swallow later tags.
    def set_cdata_mode(self, elem: str, *, escapable: bool = False) -> None:
        return

    def __init__(
        self,
        *,
        xml_mode: bool = False,
        js_budget: DeobfBudget | None = None,
    ) -> None:
        super().__init__(convert_charrefs=True)
        self.xml_mode = xml_mode
        self._js_budget = js_budget if js_budget is not None else DeobfBudget()
        self.deobf_js_chunks: list[str] = []
        self.tag_count = 0
        self.tag_limit_exceeded = False
        self.parse_limit_reason = ""

        self.script_depth = 0
        self.foreign_script_depth = 0
        self.rawtext_tag: str | None = None
        self.foreign_depth = 0
        # Explicit WHATWG HTML5 namespace stack (HTML mode only): (local_tag, ns)
        # where ns in {"svg", "math", "svg_ip", "math_ip", "html"}.
        # _ns_scope_counts mirrors HTML5 scope boundaries (svg_ip/math_ip) in O(1).
        self._ns_stack: list[tuple[str, str]] = []
        self._ns_scope_counts: list[dict[str, int]] = [{}]
        self._last_prev_in_foreign = False
        self._last_pushed_ns = False
        self.object_hhctrl_depth = 0
        self._object_hhctrl_stack: list[bool] = []

        self.has_script_tag = False
        self.event_handlers: list[str] = []
        self.js_uris: list[str] = []
        self.svg_data_html_uris: list[str] = []
        self.has_js_exfil = False
        self.has_svg_js_redirect = False

        self.foreign_active_hits: list[str] = []

        self.has_password_input = False
        self.has_foreign_password_input = False
        self.external_form_actions: list[str] = []
        self.foreign_external_form_actions: list[str] = []

        self.has_meta_refresh = False
        self.suspicious_meta_refresh_targets: list[str] = []
        self.has_any_dl = False
        self.has_risky_dl = False
        self.has_non_benign_dl = False

        self.has_hhctrl_object = False
        self.has_hhctrl_shortcut_param = False

        self.data_uri_attrs: list[tuple[str, str]] = []

    def _local_name(self, tag: str) -> str:
        return tag.rsplit(":", 1)[-1].lower() if self.xml_mode else tag.lower()

    @property
    def current_ns(self) -> str:
        return self._ns_stack[-1][1] if self._ns_stack else "html"

    @property
    def in_foreign_content(self) -> bool:
        return self.current_ns in ("svg", "math")

    @property
    def cdata_allowed(self) -> bool:
        # WHATWG §13.2.5.42: CDATA is allowed whenever the adjusted current node
        # is NOT in the HTML namespace (includes SVG/MathML integration points
        # themselves until an HTML child element is pushed on top).
        return self.current_ns in ("svg", "math", "svg_ip", "math_ip", "html_ip")

    def _push_ns(self, local: str, ns: str) -> None:
        self._ns_stack.append((local, ns))
        if ns in ("svg_ip", "math_ip", "html_ip"):
            # WHATWG §13.2.4.2: SVG/MathML integration points are scope boundaries;
            # outer HTML end tags cannot pop past them.
            self._ns_scope_counts.append({local: 1})
        else:
            scope = self._ns_scope_counts[-1]
            scope[local] = scope.get(local, 0) + 1
        if local == "foreignobject" and ns == "svg_ip":
            self.foreign_depth += 1

    def _pop_ns_top(self) -> tuple[str, str]:
        tag, ns = self._ns_stack.pop()
        scope = self._ns_scope_counts[-1]
        cnt = scope.get(tag, 1) - 1
        if cnt <= 0:
            scope.pop(tag, None)
        else:
            scope[tag] = cnt
        if ns in ("svg_ip", "math_ip", "html_ip") and len(self._ns_scope_counts) > 1:
            self._ns_scope_counts.pop()
        if tag == "foreignobject" and ns == "svg_ip" and self.foreign_depth > 0:
            self.foreign_depth -= 1
        return tag, ns

    def _breakout_foreign(self) -> None:
        while self._ns_stack and self._ns_stack[-1][1] in ("svg", "math"):
            self._pop_ns_top()
        self.foreign_script_depth = 0

    def _inspect_js_chunk(self, chunk: str) -> None:
        if not chunk:
            return
        if (
            self._js_budget.used_input_chars >= self._js_budget.max_input_chars
            or self._js_budget.used_extra_chars >= self._js_budget.max_total_chars
        ):
            self.tag_limit_exceeded = True
            if not self.parse_limit_reason:
                self.parse_limit_reason = "JS-Deobfuskations-Limit erreicht"
            return
        res = deobfuscate_js_detailed(
            chunk, explicit_script=True, budget=self._js_budget
        )
        if res.limit_hit:
            self.tag_limit_exceeded = True
            if not self.parse_limit_reason:
                self.parse_limit_reason = (
                    res.limit_reason or "JS-Deobfuskations-Limit erreicht"
                )
        pre = _CONCAT_RE.sub("", res.text)
        if res.changed:
            self.deobf_js_chunks.append(pre)
        if not self.has_js_exfil and _JS_EXFIL_RE.search(pre):
            self.has_js_exfil = True
        if not self.has_svg_js_redirect and _SVG_JS_REDIRECT_RE.search(pre):
            self.has_svg_js_redirect = True

    def _record_download_name(self, name: str) -> None:
        low = name.strip().lower()
        if not low:
            return
        self.has_any_dl = True
        if low.endswith(_SMUGGLING_DOWNLOAD_SUFFIXES):
            self.has_risky_dl = True
            self.has_non_benign_dl = True
        elif not any(low.endswith(ext) for ext in _BENIGN_DOWNLOAD_SUFFIXES):
            self.has_non_benign_dl = True

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.tag_limit_exceeded:
            return
        self.tag_count += 1
        if self.tag_count > _MAX_TAGS:
            self.tag_limit_exceeded = True
            self.parse_limit_reason = f"mehr als {_MAX_TAGS} Tags"
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
                if v:
                    self._inspect_js_chunk(v)
                if self.foreign_depth > 0 and len(self.foreign_active_hits) < 8:
                    self.foreign_active_hits.append(f"@{k}")

            local_attr = k.rsplit(":", 1)[-1]
            if local_attr in ("href", "src", "action", "data", "values", "to", "from"):
                uri_parts = v.split(";") if local_attr == "values" else (v,)
                for raw_part in uri_parts:
                    if len(raw_part) < 10:
                        continue
                    cleaned = _clean_uri_scheme(raw_part)
                    if cleaned.startswith(("javascript:", "vbscript:")):
                        if len(self.js_uris) < 16:
                            self.js_uris.append(cleaned[:256])
                        self._inspect_js_chunk(cleaned)
                        if self.foreign_depth > 0 and len(self.foreign_active_hits) < 8:
                            self.foreign_active_hits.append(cleaned[:32])
                    elif cleaned.startswith("data:text/html"):
                        if len(self.svg_data_html_uris) < 16:
                            self.svg_data_html_uris.append(cleaned[:128])
                        if self.foreign_depth > 0 and len(self.foreign_active_hits) < 8:
                            self.foreign_active_hits.append("data:text/html")

                if "base64," in v.lower():
                    m = _DATA_URI_B64_RE.search(v)
                    if (
                        m
                        and len(self.data_uri_attrs) < _MAX_B64_CANDIDATES
                        and not _is_confirmed_benign_image_b64(m.group(2))
                    ):
                        self.data_uri_attrs.append((m.group(1).lower(), m.group(2)))

        if not self.xml_mode and self.in_foreign_content and (
            local in _FOREIGN_BREAKOUT_TAGS
            or (
                local == "font"
                and any(a in attr_map for a in ("color", "face", "size"))
            )
        ):
            self._breakout_foreign()

        prev_ns = self.current_ns
        prev_in_foreign = prev_ns in ("svg", "math")
        self._last_prev_in_foreign = prev_in_foreign
        self._last_pushed_ns = False

        if self.xml_mode:
            if local == "foreignobject":
                self.foreign_depth += 1
            elif (
                self.foreign_depth > 0
                and local in _FOREIGN_ACTIVE_TAGS
                and len(self.foreign_active_hits) < 8
            ):
                self.foreign_active_hits.append(f"<{local}>")
        else:
            if local in ("svg", "math"):
                self._push_ns(local, local)
                self._last_pushed_ns = True
            elif prev_ns == "svg" and local in _SVG_HTML_INTEGRATION_TAGS:
                self._push_ns(local, "svg_ip")
                self._last_pushed_ns = True
            elif prev_ns == "math" and local in _MATH_TEXT_INTEGRATION_TAGS:
                self._push_ns(local, "math_ip")
                self._last_pushed_ns = True
            elif (
                prev_ns == "math"
                and local == "annotation-xml"
                and attr_map.get("encoding", "").strip().lower()
                in ("text/html", "application/xhtml+xml")
            ):
                self._push_ns(local, "html_ip")
                self._last_pushed_ns = True
            elif prev_ns == "math_ip" and local in ("mglyph", "malignmark"):
                self._push_ns(local, "math")
                self._last_pushed_ns = True
            else:
                if (
                    prev_ns in ("svg_ip", "math_ip", "html_ip", "html")
                    and local not in _HTML_VOID_TAGS
                ):
                    self._push_ns(local, "html")
                    self._last_pushed_ns = True
                if (
                    self.foreign_depth > 0
                    and local in _FOREIGN_ACTIVE_TAGS
                    and len(self.foreign_active_hits) < 8
                ):
                    self.foreign_active_hits.append(f"<{local}>")
        in_html_ns = (not self.xml_mode) and (not prev_in_foreign)
        if local == "script":
            self.has_script_tag = True
            if self.xml_mode or in_html_ns:
                self.script_depth += 1
            else:
                # HTML5 foreign <svg><script> stays in Data State (breakout tags
                # still exit <svg>); track separately without raw-skipping.
                self.foreign_script_depth += 1
        elif in_html_ns and local in _RAWTEXT_CLOSE_RES:
            self.rawtext_tag = local

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
                m = _META_URL_RE.search(content.translate(_META_CTRL_TABLE))
                if m:
                    self.has_meta_refresh = True
                    raw_url = m.group(1).strip().strip("'\"")
                    cleaned_url = _clean_uri_scheme(raw_url)
                    if cleaned_url.startswith(
                        ("javascript:", "vbscript:", "data:", "file:", "\\\\")
                    ) and len(self.suspicious_meta_refresh_targets) < 8:
                        self.suspicious_meta_refresh_targets.append(cleaned_url[:64])

        if local in ("a", "area") and "download" in attr_map:
            self._record_download_name(attr_map.get("download", ""))

        if local == "object":
            classid = attr_map.get("classid", "").lower()
            is_hhctrl = any(cid in classid for cid in _HHCTRL_CLSIDS)
            self._object_hhctrl_stack.append(is_hhctrl)
            if is_hhctrl:
                self.has_hhctrl_object = True
                self.object_hhctrl_depth += 1

        if local == "param" and self.object_hhctrl_depth > 0:
            pname = attr_map.get("name", "").strip().lower()
            pval = attr_map.get("value", "").strip().lower()
            if pname == "command" and pval in ("shortcut", "tcard", "winhelp"):
                self.has_hhctrl_shortcut_param = True

    def _pop_object(self) -> None:
        if self._object_hhctrl_stack and self._object_hhctrl_stack.pop() and self.object_hhctrl_depth > 0:
            self.object_hhctrl_depth -= 1

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if self.tag_limit_exceeded:
            return
        local = self._local_name(tag)
        closes_self = self.xml_mode or self._last_prev_in_foreign or local in ("svg", "math")
        if not closes_self:
            return
        if local == "script":
            if self.xml_mode and self.script_depth > 0:
                self.script_depth -= 1
            elif self.foreign_script_depth > 0:
                self.foreign_script_depth -= 1
        elif local == self.rawtext_tag:
            self.rawtext_tag = None
        elif local == "object":
            self._pop_object()
        if self._last_pushed_ns and self._ns_stack:
            self._pop_ns_top()
        elif self.xml_mode and local == "foreignobject" and self.foreign_depth > 0:
            self.foreign_depth -= 1

    def handle_endtag(self, tag: str) -> None:
        if self.tag_limit_exceeded:
            return
        self.tag_count += 1
        if self.tag_count > _MAX_TAGS:
            self.tag_limit_exceeded = True
            self.parse_limit_reason = f"mehr als {_MAX_TAGS} Tags"
            return
        local = self._local_name(tag)
        if local == "script":
            if self.script_depth > 0:
                self.script_depth -= 1
            elif self.foreign_script_depth > 0:
                self.foreign_script_depth -= 1
        elif local == self.rawtext_tag:
            self.rawtext_tag = None
        elif local == "object":
            self._pop_object()
        if self.xml_mode:
            if local == "foreignobject" and self.foreign_depth > 0:
                self.foreign_depth -= 1
            return
        if self.in_foreign_content and local in ("br", "p"):
            self._breakout_foreign()
            return
        # Amortized O(1): only pop when local is in the current HTML5 scope.
        if self._ns_scope_counts[-1].get(local, 0) > 0:
            while self._ns_stack:
                popped_tag, _ = self._pop_ns_top()
                if popped_tag == local:
                    break
            if not self.in_foreign_content:
                self.foreign_script_depth = 0

    def handle_data(self, data: str) -> None:
        if self.tag_limit_exceeded:
            return
        if self.script_depth > 0 and data:
            self._inspect_js_chunk(data)

    def unknown_decl(self, data: str) -> None:
        """Capture ``<![CDATA[...]]>`` inside ``<svg:script>`` blocks."""
        if self.tag_limit_exceeded:
            return
        if self.script_depth > 0 and data.startswith("CDATA["):
            self._inspect_js_chunk(data[6:])


def _find_tag_end_linear(
    text: str, start_pos: int, exhausted_quotes: set[str]
) -> tuple[int, int]:
    """Strictly O(N) WHATWG HTML5 6-state tag-attribute scanner starting at ``lt``.

    Follows WHATWG HTML5 §13.2.5.32-38 so leading ``=`` (``<a =">``, ``<a/=">``)
    starts an attribute name, duplicate ``=`` (``<a x==">``) starts an unquoted
    value, and ``'``/``"`` opens a quoted value ONLY in ``BEFORE_ATTR_VAL``.
    Each index is visited at most once; unclosed quotes are memoized in
    ``exhausted_quotes`` so later tags are never swallowed.
    """
    n = len(text)
    i = start_pos
    # States: 0=TAG_NAME, 1=BEFORE_ATTR_NAME, 2=ATTR_NAME,
    #         3=AFTER_ATTR_NAME, 4=BEFORE_ATTR_VAL, 5=UNQUOTED_VAL
    # Per WHATWG HTML5 §13.2.5.8/32/33/36/38, '<' inside an open tag never
    # starts a nested tag or comment; the first unquoted '>' closes the tag.
    state = 0
    while i < n:
        ch = text[i]
        if ch == ">":
            return i, i + 1

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

def _extract_tag_local_name(
    text: str, lt: int, gt: int, *, xml_mode: bool = False
) -> str:
    i = lt + 1
    while i < gt and text[i] in " /!?\t\r\n\f":
        i += 1
    start = i
    while i < gt and (text[i].isalnum() or text[i] in "_.-:"):
        i += 1
    raw = text[start:i]
    return raw.rsplit(":", 1)[-1].lower() if xml_mode else raw.lower()


def _find_html_script_end(
    text: str, pos: int, exhausted_quotes: set[str]
) -> tuple[int, int] | None:
    """Linear O(N) WHATWG §13.2.5.17-31 HTML5 script-end scanner (handles double-escaped)."""
    state = 0  # 0=NORMAL, 1=ESCAPED (after <!--), 2=DOUBLE_ESCAPED (after <!--<script)
    for m in _HTML_SCRIPT_TOKEN_RE.finditer(text, pos):
        tok = m.group(0).lower()
        if tok.startswith("<!--") and tok.endswith(">"):
            # WHATWG §13.2.5.18-22: <!--> / <!---> returns immediately to NORMAL.
            state = 0
        elif tok == "<!--":
            if state == 0:
                state = 1
        elif tok == "-->":
            if state in (1, 2):
                state = 0
        elif tok == "<script":
            if state == 1:
                state = 2
        elif tok == "</script":
            if state == 2:
                state = 1
            else:
                end_gt, end_next = _find_tag_end_linear(
                    text, m.start() + 2, exhausted_quotes
                )
                if end_gt == -1:
                    return None
                return m.start(), end_next
    return None


def _find_xml_script_end(
    text: str, pos: int, collector: _WebTagCollector
) -> int | None:
    """Strictly linear O(N) XML/SVG <script> scanner honoring CDATA and comments."""
    cur = pos
    n = len(text)
    next_close_m: re.Match[str] | None = _SCRIPT_CLOSE_RE.search(text, cur)
    no_close = next_close_m is None
    next_cd = text.find("<![CDATA[", cur)
    next_cmt = text.find("<!--", cur)
    while cur < n:
        if not no_close and next_close_m is not None and next_close_m.start() < cur:
            next_close_m = _SCRIPT_CLOSE_RE.search(text, cur)
            if next_close_m is None:
                no_close = True
        if next_cd != -1 and next_cd < cur:
            next_cd = text.find("<![CDATA[", cur)
        if next_cmt != -1 and next_cmt < cur:
            next_cmt = text.find("<!--", cur)

        close_pos = n if (no_close or next_close_m is None) else next_close_m.start()
        cd_pos = n if next_cd == -1 else next_cd
        cmt_pos = n if next_cmt == -1 else next_cmt
        earliest = min(close_pos, cd_pos, cmt_pos)

        if earliest == n:
            if cur < n:
                collector.handle_data(text[cur:])
            return None
        if earliest == cd_pos:
            if cd_pos > cur:
                collector.handle_data(text[cur:cd_pos])
            end_cd = text.find("]]>", cd_pos + 9)
            if end_cd == -1:
                collector.handle_data(text[cd_pos + 9 :])
                return None
            collector.handle_data(text[cd_pos + 9 : end_cd])
            cur = end_cd + 3
            continue
        if earliest == cmt_pos:
            if cmt_pos > cur:
                collector.handle_data(text[cur:cmt_pos])
            end_cmt = text.find("-->", cmt_pos + 4)
            if end_cmt == -1:
                return None
            cur = end_cmt + 3
            continue
        if close_pos > cur:
            collector.handle_data(text[cur:close_pos])
        assert next_close_m is not None
        end_gt = text.find(">", next_close_m.end() - 1)
        return None if end_gt == -1 else end_gt + 1
    return None


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
            if xml_mode:
                next_pos = _find_xml_script_end(text, pos, collector)
                if next_pos is None:
                    break
                collector.handle_endtag("script")
                pos = next_pos
                continue
            script_end = _find_html_script_end(text, pos, exhausted_quotes)
            body = text[pos:] if script_end is None else text[pos : script_end[0]]
            if body:
                if "<![CDATA[" in body:
                    body = body.replace("<![CDATA[", "").replace("]]>", "")
                collector.handle_data(body)
            if script_end is None:
                break
            collector.handle_endtag("script")
            pos = script_end[1]
            continue

        if collector.rawtext_tag is not None:
            rt_tag = collector.rawtext_tag
            m_close = _RAWTEXT_CLOSE_RES[rt_tag].search(text, pos)
            if m_close is None:
                break
            end_gt, end_next = _find_tag_end_linear(
                text, m_close.start() + 2, exhausted_quotes
            )
            if end_gt == -1:
                break
            collector.handle_endtag(rt_tag)
            pos = end_next
            continue

        lt = text.find("<", pos)
        if collector.foreign_script_depth > 0:
            chunk = text[pos:] if lt == -1 else text[pos:lt]
            if chunk:
                collector._inspect_js_chunk(chunk)
        if lt == -1 or lt + 1 >= n:
            break

        # HTML5 §13.2.5.6: '<' only starts a tag/declaration if followed by ASCII [A-Za-z/!?].
        nxt = text[lt + 1]
        if not ((nxt.isascii() and nxt.isalpha()) or nxt in "/!?"):
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

        # CDATA exists in XML/SVG and HTML5 foreign content (<svg>/<math> outside
        # <foreignObject>, WHATWG §13.2.5.42); elsewhere '<![CDATA[...>' ends at '>'.
        if text.startswith("<![CDATA[", lt):
            in_foreign = xml_mode or collector.cdata_allowed
            if in_foreign:
                end_cd = text.find("]]>", lt + 9)
                if end_cd == -1:
                    if collector.foreign_script_depth > 0:
                        collector._inspect_js_chunk(text[lt + 9 :])
                    break
                if collector.foreign_script_depth > 0:
                    collector._inspect_js_chunk(text[lt + 9 : end_cd])
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
            if xml_mode:
                end_dt = magic.skip_xml_doctype_end(text, lt)
                if end_dt == -1:
                    collector.tag_limit_exceeded = True
                    collector.parse_limit_reason = "Unvollständige XML-Deklaration"
                    break
                pos = end_dt
                continue
            gt_decl = text.find(">", lt + 2)
            if gt_decl == -1:
                break
            pos = gt_decl + 1
            continue

        # WHATWG §13.2.5.7 End tag open state: '</' + non-ASCII-alpha is a bogus
        # comment ending at the first '>'; otherwise scan end-tag name from lt + 2.
        if nxt == "/":
            if lt + 2 >= n:
                break
            c2 = text[lt + 2]
            if not (c2.isascii() and c2.isalpha()):
                gt_bc = text.find(">", lt + 2)
                if gt_bc == -1:
                    break
                pos = gt_bc + 1
                continue
            scan_start = lt + 2
        else:
            scan_start = lt + 1

        gt, next_pos = _find_tag_end_linear(text, scan_start, exhausted_quotes)
        if gt == -1:
            pos = next_pos
            continue

        tag_len = gt - lt + 1
        if tag_len > _MAX_SINGLE_TAG_LEN:
            local = _extract_tag_local_name(text, lt, gt, xml_mode=xml_mode)
            tag_slice = text[lt : gt + 1]
            low_slice = tag_slice.lower()
            if "base64," in low_slice:
                for m in _DATA_URI_B64_RE.finditer(tag_slice):
                    if len(collector.data_uri_attrs) >= _MAX_B64_CANDIDATES:
                        break
                    if not _is_confirmed_benign_image_b64(m.group(2)):
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
                collector.parse_limit_reason = (
                    f"Einzel-Tag über {_MAX_SINGLE_TAG_LEN} Zeichen"
                )
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
        is_html = suffix in _WEB_HTML_SUFFIXES or (
            ctx.detected_type == "html" and not is_svg
        )

        # Plain XML (e.g. rechnung.xml, OOXML members) without <svg> or HTML suffix.
        if not is_svg and not is_html:
            return []

        qr_budget = qr_scan.DataUriBudget()
        qr_outcome = qr_scan.QrScanOutcome()
        js_budget = DeobfBudget()
        input_truncated = ctx.size > len(ctx.data)
        indicators = self._analyze_text(
            text,
            is_svg=is_svg,
            is_html=is_html,
            depth=0,
            qr_budget=qr_budget,
            qr_outcome=qr_outcome,
            js_budget=js_budget,
            input_truncated=input_truncated,
        )
        indicators.extend(qr_scan.build_qr_indicators(self.name, qr_outcome))
        return indicators

    def _analyze_text(
        self,
        text: str,
        *,
        is_svg: bool,
        is_html: bool,
        depth: int,
        qr_budget: qr_scan.DataUriBudget | None = None,
        qr_outcome: qr_scan.QrScanOutcome | None = None,
        js_budget: DeobfBudget | None = None,
        input_truncated: bool = False,
    ) -> list[Indicator]:
        xml_mode = is_svg and not is_html
        active_js_budget = js_budget if js_budget is not None else DeobfBudget()
        collector = _WebTagCollector(xml_mode=xml_mode, js_budget=active_js_budget)
        try:
            _feed_bounded_tags(collector, text, xml_mode=xml_mode)
        except Exception:
            collector.tag_limit_exceeded = True
            collector.parse_limit_reason = "Struktur-Parser-Ausnahme"

        found: dict[str, Indicator] = {}

        def _add(ind: Indicator) -> None:
            if ind.rule_id not in found:
                found[ind.rule_id] = ind

        if collector.tag_limit_exceeded:
            limit_reason = (
                collector.parse_limit_reason or f"mehr als {_MAX_TAGS} Tags"
            )
            _add(
                self._indicator(
                    "WEB_PARSE_LIMIT",
                    "HTML/SVG-Tag-Limit überschritten",
                    detail=(
                        f"Die Strukturprüfung wurde am Limit gestoppt ({limit_reason}). "
                        "Der Rest des Dokuments wurde strukturell NICHT geprüft — "
                        "das Ergebnis ist unvollständig und nicht als 'sauber' zu werten."
                    ),
                    severity=Severity.MEDIUM,
                    category=CAT_CONTENT,
                    weight=20,
                )
            )

        work, pre_limit = _preprocess_js(text)
        if pre_limit and "WEB_PARSE_LIMIT" not in found:
            _add(
                self._indicator(
                    "WEB_PARSE_LIMIT",
                    "HTML/SVG-Tag-Limit überschritten",
                    detail=(
                        "Die statische JS-Vorverarbeitung wurde am Sicherheitslimit gestoppt. "
                        "Der Rest des Dokuments wurde strukturell NICHT geprüft — "
                        "das Ergebnis ist unvollständig und nicht als 'sauber' zu werten."
                    ),
                    severity=Severity.MEDIUM,
                    category=CAT_CONTENT,
                    weight=20,
                )
            )
        if collector.deobf_js_chunks:
            work = work + "\n" + "\n".join(collector.deobf_js_chunks)

        for m in _JS_DOWNLOAD_RE.finditer(work):
            collector._record_download_name(m.group(1))

        smuggle_ind = self._check_html_smuggling(work, collector)
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

        if qr_outcome is not None:
            qr_sub = qr_scan.scan_data_uri_images(
                text,
                budget=qr_budget,
                input_truncated=input_truncated,
            )
            qr_outcome.merge(qr_sub)

        if depth == 0 and decoded_snippets:
            for snippet_text, snippet_is_svg, snippet_is_html in decoded_snippets:
                sub_inds = self._analyze_text(
                    snippet_text,
                    is_svg=snippet_is_svg,
                    is_html=snippet_is_html,
                    depth=1,
                    qr_budget=qr_budget,
                    qr_outcome=qr_outcome,
                    js_budget=active_js_budget,
                    input_truncated=(len(snippet_text) >= _STAGE2_DECODE_CAP),
                )
                for ind in sub_inds:
                    _add(ind)

        return list(found.values())

    def _check_html_smuggling(
        self, work: str, collector: _WebTagCollector
    ) -> Indicator | None:
        low_work = work.lower()
        has_binary_mime = any(mime in low_work for mime in _BINARY_SMUGGLE_MIMES)

        has_risky_dl = collector.has_risky_dl
        all_benign_dl = (
            collector.has_any_dl
            and not collector.has_non_benign_dl
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

        data_seen: set[str] = set()
        data_candidates: list[tuple[str, str, str]] = []
        for mime, b64 in collector.data_uri_attrs:
            dkey = f"{mime}:{len(b64)}:{b64[:64]}:{b64[-32:]}"
            if dkey in data_seen or _is_confirmed_benign_image_b64(b64):
                continue
            data_seen.add(dkey)
            data_candidates.append(("data", mime, b64))
            if len(data_candidates) >= _MAX_B64_CANDIDATES:
                break
        for m in _DATA_URI_B64_RE.finditer(work):
            if len(data_candidates) >= _MAX_B64_CANDIDATES:
                break
            mime = m.group(1).lower()
            b64 = m.group(2)
            dkey = f"{mime}:{len(b64)}:{b64[:64]}:{b64[-32:]}"
            if dkey in data_seen or _is_confirmed_benign_image_b64(b64):
                continue
            data_seen.add(dkey)
            data_candidates.append(("data", mime, b64))
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
        elif collector.has_js_exfil or (
            is_html and not collector.has_script_tag and _JS_EXFIL_RE.search(work)
        ):
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
        bad_targets = collector.suspicious_meta_refresh_targets
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
        if collector.has_svg_js_redirect:
            redir_reasons.append("JS-Weiterleitung (location/window.open)")
        if collector.has_meta_refresh:
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
