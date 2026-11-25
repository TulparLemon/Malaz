"""Structural PDF action-graph traversal and URI link analysis.

Extracted from :mod:`malaz.pipelines.pdf_pipeline` (Spec 012, Etappe 2).
"""

from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass, field
from typing import Any

from .. import config
from ..core.binary_iocs import (
    BINARY_IOC_BLOCKED_TITLE,
    BLOCKLIST_UNAVAILABLE_TITLE,
    IOC_URL,
    host_of_url,
    is_namespace_host,
    split_blocked_iocs,
)
from ..core.url_view import defang_url
from ..models import CAT_IOC, CAT_STRUCTURE, Indicator, Severity
from .pdf_streams import make_pdf_indicator

# Graph walk bounds (preserve exact main values from Spec 012 Zero-Behavior-Change).
GRAPH_MAX_DEPTH = 16
GRAPH_MAX_NODES = 200_000


@dataclass
class _GraphWalk:
    """Structured result of :meth:`PdfPipeline._walk_action_graph`."""

    js_values: list = field(default_factory=list)
    uri_values: list = field(default_factory=list)
    launch_hits: int = 0
    truncated: bool = False
    visited: set[tuple[int, int]] = field(default_factory=set)
    incomplete: bool = False


# C-speed translation table stripping C0 controls (0x00..0x1F) and DEL (0x7F).
_C0_STRIP_TABLE = str.maketrans("", "", "".join(chr(c) for c in range(0x20)) + "\x7f")


def decode_pdf_uri(raw: Any) -> str | None:
    """Decode a PDF ``/URI`` string safely (UTF-16BE/LE with or without BOM).

    Only accepts ``str``, ``bytes``, ``bytearray``, or ``pikepdf.String`` —
    never coerces PDF integers (``bytes(500_000_000)`` OOM DoS) or arrays.
    Caps raw input BEFORE decoding/scanning to bound memory and CPU.
    """
    max_chars = config.MAX_STRING_CAPTURE
    max_raw_bytes = max_chars * 4  # generous bound for UTF-16 + BOM + stripped C0s

    if isinstance(raw, str):
        decoded = raw[:max_raw_bytes]
    elif isinstance(raw, (bytes, bytearray)):
        raw_bytes = bytes(raw[:max_raw_bytes])
        decoded = ""
    else:
        try:
            import pikepdf

            if not isinstance(raw, pikepdf.String):
                return None
            raw_bytes = bytes(raw)[:max_raw_bytes]
            decoded = ""
        except Exception:
            return None

    if not isinstance(raw, str):
        if not raw_bytes:
            return None
        if raw_bytes.startswith(b"\xfe\xff"):
            body = raw_bytes[2:]
            if len(body) % 2:
                body = body[:-1]
            decoded = body.decode("utf-16-be", errors="replace")
        elif raw_bytes.startswith(b"\xff\xfe"):
            body = raw_bytes[2:]
            if len(body) % 2:
                body = body[:-1]
            decoded = body.decode("utf-16-le", errors="replace")
        elif len(raw_bytes) >= 4:
            even_len = len(raw_bytes) - (len(raw_bytes) % 2)
            sample = raw_bytes[:even_len]
            half = even_len // 2
            even_nul = sample[0::2].count(0) / half
            odd_nul = sample[1::2].count(0) / half
            if even_nul > 0.40 and odd_nul < 0.05:
                decoded = sample.decode("utf-16-be", errors="replace")
            elif odd_nul > 0.40 and even_nul < 0.05:
                decoded = sample.decode("utf-16-le", errors="replace")
            else:
                decoded = raw_bytes.decode("latin-1")
        else:
            decoded = raw_bytes.decode("latin-1")

    cleaned = decoded.translate(_C0_STRIP_TABLE).strip()
    if not cleaned:
        return None
    if len(cleaned) > max_chars:
        cleaned = cleaned[:max_chars]
    return cleaned


def walk_action_graph(
    pdf,
    *,
    collect_js: bool,
    collect_uris: bool = False,
    max_depth: int = GRAPH_MAX_DEPTH,
    max_nodes: int = GRAPH_MAX_NODES,
) -> _GraphWalk:
    """Walk dictionaries/arrays reachable from the document action anchors.

    Returns a :class:`_GraphWalk` dataclass:

    * ``js_values``: value of every ``/JS``/``/JavaScript`` key found
      (direct or indirect; stream-/string-/array-shaped);
    * ``uri_values``: ``/URI`` targets (plus Catalog ``/URI << /Base ... >>``
      base strings when present; ``None`` sentinel on read error);
    * ``launch_hits``: number of Launch actions (``/S /Launch`` or a
      ``/Launch`` key) in the graph;
    * ``truncated``: the depth/node bound was hit, i.e. the graph was NOT
      fully inspected;
    * ``visited``: object ids already walked, so an indirect payload that
      is reachable twice is only collected/analysed once;
    * ``incomplete``: ``True`` when URIs were requested and neither the
      page tree nor the document root could be walked.

    Starting points are the page tree and the document root; the root
    walk reaches /OpenAction, /AA, /Names (JavaScript name tree) and
    /AcroForm, the page walk reaches /Annots. Streams are NOT traversed:
    their bytes are payload, not an object graph (a ``/JS`` stream value
    is still collected and read by :meth:`_js_value_text`).
    """
    import pikepdf

    js_values: list = []
    uri_values: list = []
    seen_uri_objgens: set[tuple[int, int]] = set()
    visited: set[tuple[int, int]] = set()
    state = {"nodes": 0, "launch": 0, "truncated": False}

    def _record_uri(val: object) -> None:
        uid = _identity(val)
        if uid is not None:
            if uid in seen_uri_objgens:
                return
            seen_uri_objgens.add(uid)
        uri_values.append(val)

    def _identity(obj):
        try:
            if obj.is_indirect:
                return obj.objgen
        except Exception:
            pass
        return None

    def _walk(obj, depth: int) -> None:
        if state["truncated"]:
            return
        state["nodes"] += 1
        if depth > max_depth or state["nodes"] > max_nodes:
            state["truncated"] = True
            return
        if isinstance(obj, pikepdf.Stream):
            # The stream CONTENT is payload, never an object graph; only
            # the /JS value itself is decoded later.
            return
        ident = _identity(obj)
        if ident is not None:
            if ident in visited:
                return
            visited.add(ident)
        if isinstance(obj, pikepdf.Array):
            try:
                items = list(obj)
            except Exception:
                return
            for item in items:
                _walk(item, depth + 1)
            return
        # pikepdf.Page is an ObjectHelper, NOT a Dictionary subclass; its
        # underlying page dictionary is ``page.obj``.
        if not isinstance(obj, pikepdf.Dictionary):
            return
        try:
            keys = list(obj.keys())
        except Exception:
            return
        key_names = {str(key) for key in keys}
        is_launch = "/Launch" in key_names
        if not is_launch:
            try:
                is_launch = (
                    obj.get(pikepdf.Name("/S")) == pikepdf.Name("/Launch")
                )
            except Exception:
                is_launch = False
        if is_launch:
            state["launch"] += 1
        # Collect THIS dictionary's JS carriers before descending into
        # its other values: the old whole-object pass checked /JS and
        # /JavaScript first, so a shallow payload keeps being analysed
        # before a deeply nested one (budget order stays predictable).
        if collect_js:
            for js_key in (pikepdf.Name.JS, pikepdf.Name.JavaScript):
                if js_key in keys:
                    with suppress(Exception):
                        js_values.append(obj.get(js_key))
        if collect_uris and pikepdf.Name.URI in keys:
            try:
                uri_obj = obj.get(pikepdf.Name.URI)
            except Exception:
                # Broken indirect /URI reference must never vanish silently:
                # append None sentinel so _link_indicators emits PDF_PARSE_WARN.
                uri_values.append(None)
            else:
                if isinstance(uri_obj, pikepdf.Dictionary):
                    # ISO 32000-1 §12.6.4.7: Document Catalog /URI << /Base (...) >>
                    # is a standard dictionary, not a malformed URI string.
                    if pikepdf.Name.Base in uri_obj:
                        try:
                            base_val = uri_obj.get(pikepdf.Name.Base)
                        except Exception:
                            uri_values.append(None)
                        else:
                            _record_uri(base_val)
                else:
                    _record_uri(uri_obj)
        for key in keys:
            try:
                value = obj.get(key)
            except Exception:
                continue
            # The /JS value was collected above; walking it still reaches
            # actions below a /JavaScript NAME TREE (the key also names a
            # container). _js_value_text ignores container shapes.
            _walk(value, depth + 1)

    # Page tree first: a page dict also carries /Annots (and its /A
    # actions). The root walk then reaches the rest and skips every
    # indirect page it already saw.
    try:
        for page in pdf.pages:
            try:
                page_dict = page.obj
            except Exception:
                page_dict = page
            _walk(page_dict, 0)
            if state["truncated"]:
                break
    except Exception:
        pass
    if not state["truncated"]:
        try:
            root = pdf.Root
        except Exception:
            root = None
        if root is not None:
            _walk(root, 0)
    graph_incomplete = bool(collect_uris and not visited and not state["truncated"])
    return _GraphWalk(
        js_values=js_values,
        uri_values=uri_values,
        launch_hits=state["launch"],
        truncated=bool(state["truncated"]),
        visited=visited,
        incomplete=graph_incomplete,
    )


def build_link_indicators(uri_values: list, *, source: str = "pdf") -> list[Indicator]:
    """Decode structural PDF ``/URI`` values and check them against local blocklists."""
    cap = config.BINARY_IOC_MAX_HITS
    urls: list[str] = []
    seen: set[str] = set()
    capped = False
    raw_capped = False
    unreadable = 0

    # Hard ceiling on raw /URI decodings even when all entries are direct
    # duplicates, namespaces, or unreadable objects (prevents CPU amplification).
    max_raw_entries = max(cap * 20, 4_000)
    for idx, raw in enumerate(uri_values):
        if idx >= max_raw_entries:
            raw_capped = True
            break
        url = decode_pdf_uri(raw)
        if url is None:
            unreadable += 1
            continue
        if is_namespace_host(url):
            continue
        key = url.lower()
        if key in seen:
            continue
        if cap > 0 and len(urls) >= cap:
            capped = True
            break
        seen.add(key)
        urls.append(url)

    out: list[Indicator] = []
    if unreadable:
        out.append(
            make_pdf_indicator(source,
                "PDF_PARSE_WARN",
                f"Nicht lesbare PDF-Links (/URI) ({unreadable})",
                detail=(
                    f"{unreadable} /URI-Eintrag/-Einträge im PDF ließen sich "
                    "nicht dekodieren und wurden daher NICHT geprüft."
                ),
                severity=Severity.MEDIUM,
                category=CAT_STRUCTURE,
                weight=20,
            )
        )
    if capped or raw_capped:
        cap_reason = (
            f"Das PDF enthält mehr als {max_raw_entries} rohe /URI-Einträge."
            if raw_capped and not capped
            else f"Das PDF enthält mehr als {cap} eindeutige Links (/URI)."
        )
        out.append(
            make_pdf_indicator(source,
                "PDF_LINK_CAPPED",
                "PDF-Link-Prüfung durch Trefferdeckel begrenzt",
                detail=(
                    f"{cap_reason} Weitere Links wurden nicht geprüft — "
                    "das Ergebnis ist daher nicht vollständig."
                ),
                severity=Severity.INFO,
                category=CAT_IOC,
                weight=0,
            )
        )
    if not urls:
        return out

    hits = [(IOC_URL, url) for url in urls]
    blocked, plain, unavailable = split_blocked_iocs(hits)

    for rule_id, detail in unavailable:
        out.append(
            make_pdf_indicator(source,
                rule_id,
                BLOCKLIST_UNAVAILABLE_TITLE,
                detail=detail + " Das Ergebnis ist an dieser Stelle unvollständig.",
                severity=Severity.INFO,
                category=CAT_IOC,
                weight=0,
            )
        )

    if blocked:
        shown = ", ".join(
            f"{defang_url(url)} ({host_of_url(url) or 'Host unbekannt'})"
            for _kind, url in blocked[:10]
        )
        extra = f" (+{len(blocked) - 10} weitere)" if len(blocked) > 10 else ""
        out.append(
            make_pdf_indicator(source,
                "BINARY_IOC_BLOCKED",
                f"{BINARY_IOC_BLOCKED_TITLE} ({len(blocked)})",
                detail=(
                    "Link in der PDF-Struktur (/Annots -> /A -> /URI) steht "
                    f"auf der lokalen Blocklist: {shown}{extra}"
                ),
                severity=Severity.HIGH,
                category=CAT_IOC,
                weight=30,
            )
        )

    if plain:
        shown = ", ".join(defang_url(url) for _kind, url in plain[:10])
        extra = f" (+{len(plain) - 10} weitere)" if len(plain) > 10 else ""
        qualifier = (
            "Ein Teil der lokalen Blocklisten war nicht lesbar; dieser "
            "Hinweis ist daher nicht vollständig."
            if unavailable
            else "Kein Eintrag auf einer lokalen Blocklist — Hinweis ohne Einfluss auf die Bewertung."
        )
        out.append(
            make_pdf_indicator(source,
                "PDF_LINK",
                f"Links im PDF ({len(plain)})",
                detail=(
                    f"Strukturelle Links in der PDF-Struktur (/URI): {shown}{extra}. "
                    f"{qualifier}"
                ),
                severity=Severity.INFO,
                category=CAT_IOC,
                weight=0,
            )
        )
    return out

