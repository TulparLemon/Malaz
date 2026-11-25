"""PDF JavaScript extraction and static abuse/obfuscation analysis.

Extracted from :mod:`malaz.pipelines.pdf_pipeline` (Spec 012, Etappe 2).
Uses :func:`malaz.pipelines.pdf_links.walk_action_graph` so the PDF action
graph is traversed via one shared bounded walker.
"""

from __future__ import annotations

from collections.abc import Callable

from ..core.js_deobf import deobfuscate_js_detailed
from ..core.script_deobf import DeobfBudget
from ..models import CAT_SCRIPT, AnalysisContext, Indicator, Severity
from .pdf_links import GRAPH_MAX_DEPTH, GRAPH_MAX_NODES, walk_action_graph
from .pdf_streams import (
    _AA_KEY_RE,
    MAX_STREAM_BYTES,
    make_pdf_indicator,
    read_pdf_text_value,
    warn_is_bomb,
)

_PDF_JS_MALICIOUS = (
    "ev" + "al(",           # eval — Code aus Daten
    "app.ev" + "al",        # app.eval
    "exportdataobject",     # eingebettete Datei auf die Platte schreiben
    "collab.geticon",       # bekanntes Exploit-Primitiv
    "mail" + "msg(",        # Mail versenden
    "execdialog",           # Menuebefehl ausfuehren
)

# In Dokumenten ueblich. Bleibt als Befund sichtbar (Gewicht 10 statt 30),
# traegt aber KEINEN Anker.
_PDF_JS_COMMON = (
    "launchurl",            # Link oeffnen — jedes Formular mit Anleitung
    "submitform",           # Formular absenden
    "getannotation",        # Anmerkungen lesen
    "util.stringfromstream",
    "exportasstring",
)

# Obfuscation techniques used to hide a JS payload from keyword scanners.
_PDF_JS_OBFUSCATION = (
    "string.fromcharcode",
    "fromcharcode",
    "unescape(",
    "charcodeat",
    "\\u00",  # \u00xx unicode escape runs
    "\\x",    # \xXX hex escape runs
)


def root_has_auto_action(pdf) -> bool:
    """Structural auto-exec context (ObjStm-safe).

    Checks the document root (/OpenAction, /AA) AND every page dict's
    /AA — a page-open action runs JS on merely VIEWING the page, which
    the raw-byte fallback cannot see when pages live in object streams.
    """
    import pikepdf

    try:
        root = pdf.Root
    except Exception:
        return False
    try:
        if pikepdf.Name.OpenAction in root:
            return True
    except Exception:
        pass
    try:
        if root.get(pikepdf.Name.AA) is not None:
            return True
    except Exception:
        pass
    try:
        page_iter = iter(pdf.pages)
    except Exception:
        return False
    while True:
        # Pull ONE page at a time: a corrupt page tree raises here (caught
        # below), and no huge PDF materialises all page handles at once.
        try:
            page = next(page_iter)
        except StopIteration:
            break
        except Exception:
            return False
        # Per-page try: one corrupt page dict must not hide /AA on the
        # remaining pages (fail-tolerant, like _layout_forensics).
        try:
            if pikepdf.Name.AA in page:
                return True
        except Exception:
            continue
    return False


def extract_pdf_js(
    pdf,
    *,
    max_stream_bytes: int | None = None,
    max_depth: int = GRAPH_MAX_DEPTH,
    max_nodes: int = GRAPH_MAX_NODES,
) -> tuple[list[str], list[str]]:
    """Collect embedded JavaScript code from the PDF (decompressed).

    Returns ``(chunks, stream_warnings)``: streams whose decompressed
    size exceeds the bomb limit are refused with a warning instead of
    being materialised in full (OOM protection). Collection stops as
    soon as the accumulated text reaches the analysis budget — the
    per-stream cap alone would not bound the SUM over many streams,
    and the budget is shared THROUGH the recursion so a single /JS
    array of many strings cannot bypass it either.

    Direct action dictionaries (``/OpenAction << /S /JavaScript /JS … >>``,
    annotation ``/A``, the JavaScript name tree) are part of their parent
    object and were invisible to the old ``pdf.objects`` loop; the bounded
    graph walk reaches them (BUG-016). The old whole-object pass stays as
    a fallback for action objects that are NOT reachable from the root
    (e.g. a damaged page tree), skipping everything already walked.
    """
    import pikepdf

    limit = MAX_STREAM_BYTES if max_stream_bytes is None else max_stream_bytes

    chunks: list[str] = []
    warnings: list[str] = []
    total_ref = [0]
    walk = walk_action_graph(pdf, collect_js=True, max_depth=max_depth, max_nodes=max_nodes)
    js_values = walk.js_values
    visited = walk.visited
    for value in js_values:
        if total_ref[0] >= limit:
            break
        read_pdf_text_value(
            value, pikepdf, depth=0, chunks=chunks,
            warnings=warnings, total_ref=total_ref, max_stream_bytes=limit,
        )
    if total_ref[0] >= limit:
        # Budget exhaustion MUST be visible: an attacker can pad with
        # 8 MiB of harmless JS and hide a malicious /JS behind it —
        # silently dropping that is an evasion vector (hunt finding 3.1).
        warnings.append(
            f"JS-Gesamtbudget ({limit} Bytes) erschöpft "
            "— weitere /JS-Inhalte wurden nicht analysiert; das "
            "Ergebnis ist nicht als 'sauber' zu werten."
        )
        return chunks, warnings
    for obj in pdf.objects:
        if obj is None:
            continue
        try:
            if obj.is_indirect and obj.objgen in visited:
                continue
        except Exception:
            continue
        try:
            keys = list(obj.keys())
        except Exception:
            continue
        for key in (pikepdf.Name.JS, pikepdf.Name.JavaScript):
            if key not in keys:
                continue
            try:
                value = obj.get(key)
            except Exception:
                continue
            read_pdf_text_value(
                value, pikepdf, depth=0, chunks=chunks,
                warnings=warnings, total_ref=total_ref, max_stream_bytes=limit,
            )
            if total_ref[0] >= limit:
                # Budget exhaustion MUST be visible: an attacker can pad
                # with 8 MiB of harmless JS and hide a malicious /JS
                # behind it — silently dropping that is an evasion
                # vector (hunt finding 3.1).
                warnings.append(
                    f"JS-Gesamtbudget ({limit} Bytes) erschöpft "
                    "— weitere /JS-Inhalte wurden nicht analysiert; das "
                    "Ergebnis ist nicht als 'sauber' zu werten."
                )
                return chunks, warnings
    return chunks, warnings


def analyze_js_text(
    js_text: str,
    auto_exec: bool,
    *,
    source: str = "pdf",
    budget: DeobfBudget | None = None,
) -> list[Indicator]:
    """Static content analysis of extracted JavaScript (no execution)."""
    out: list[Indicator] = []
    lowered = js_text.lower()
    excerpt = js_text.strip()[:200]

    # Informational: JS was present and inspected (no score impact — the
    # keyword triage already signals mere presence; the value here is the
    # content analysis below).
    out.append(
        make_pdf_indicator(source,
            "PDF_JS_EXTRACTED",
            f"Eingebettetes JavaScript extrahiert ({len(js_text)} Zeichen)",
            detail="JavaScript-Code wurde aus dem PDF dekomprimiert und statisch "
                   "geprüft (nicht ausgeführt). Anfang: " + excerpt,
            severity=Severity.INFO,
            category=CAT_SCRIPT,
            weight=0,
        )
    )

    boese = sorted({api for api in _PDF_JS_MALICIOUS if api in lowered})
    if boese:
        out.append(
            make_pdf_indicator(source,
                "PDF_JS_SUSPICIOUS",
                "Bösartige JavaScript-APIs: " + ", ".join(boese),
                detail=(
                    "Das eingebettete JavaScript nutzt Ausführungs-/Exfiltrations- "
                    "oder bekannte Exploit-Primitive"
                    + (", gekoppelt an eine Auto-Start-Aktion (/OpenAction, /AA)."
                       if auto_exec else ".")
                ),
                severity=Severity.CRITICAL if auto_exec else Severity.HIGH,
                category=CAT_SCRIPT,
                weight=50 if auto_exec else 30,
            )
        )

    # Dokumentuebliche APIs: sichtbar, aber kein Anker. Ein Formular, das
    # einen Link oeffnet oder sich absendet, ist kein Angriff.
    ueblich = sorted({api for api in _PDF_JS_COMMON if api in lowered})
    if ueblich:
        out.append(
            make_pdf_indicator(source,
                "PDF_JS_DOC_API",
                "Dokumentübliche JavaScript-APIs: " + ", ".join(ueblich),
                detail=(
                    "Diese APIs sind in Formularen und verlinkten Dokumenten "
                    "alltäglich (Link öffnen, Formular absenden, Anmerkung "
                    "lesen). Sie allein sind kein Hinweis auf eine Schadwirkung."
                ),
                severity=Severity.INFO,
                category=CAT_SCRIPT,
                # 0: the detail text already says it — these APIs alone
                # are not a finding. On the VA form 21-526ez this added
                # 10 points to /JS and an incomplete graph walk and made
                # a benign form RED.
                weight=0,
            )
        )

    obf_hits = sorted({o for o in _PDF_JS_OBFUSCATION if o in lowered})
    if obf_hits:
        out.append(
            make_pdf_indicator(source,
                "PDF_JS_OBFUSCATED",
                "Verschleiertes JavaScript: " + ", ".join(obf_hits),
                detail="Der JavaScript-Code nutzt Verschleierung (z. B. "
                       "String.fromCharCode/unescape), um den Payload zu verbergen.",
                severity=Severity.HIGH,
                category=CAT_SCRIPT,
                weight=30,
            )
        )

    # AP13: decode the hiding primitives statically and re-check the
    # payload. Only a MALICIOUS primitive that was not visible in the
    # original text is a new statement; harmless form JS that uses
    # fromCharCode for a greeting stays without this finding.
    doc_budget = budget if budget is not None else DeobfBudget()
    deobf_res = deobfuscate_js_detailed(js_text, explicit_script=True, budget=doc_budget)
    if deobf_res.limit_hit:
        out.append(
            make_pdf_indicator(
                source,
                "PDF_JS_PARSE_WARN",
                "JavaScript-Extraktion fehlerhaft — JS-Analyse nicht gelaufen",
                detail=(
                    f"Statische JS-Deobfuskation am Sicherheitslimit gestoppt "
                    f"({deobf_res.limit_reason}) — verbleibender JS-Code wurde nicht "
                    "vollständig analysiert; das Ergebnis ist nicht als 'sauber' zu werten."
                ),
                severity=Severity.MEDIUM,
                category=CAT_SCRIPT,
                weight=25,
            )
        )
    decoded = deobf_res.text
    if decoded != js_text:
        decoded_lower = decoded.lower()
        revealed = sorted(
            {
                api
                for api in _PDF_JS_MALICIOUS
                if api in decoded_lower and api not in lowered
            }
        )
        if revealed:
            excerpt = decoded.strip()[:200]
            # BUG-017: obfuscation must never TURN a verdict around. The
            # same payload scored CRITICAL/50 when written as plain
            # ``eval(...)`` and only MEDIUM/15 when written as
            # ``"ev"+"al(...)"`` — 15 < SCORE_GREEN_MAX (19), so hiding
            # the primitive made the file GREEN. A primitive revealed
            # only after decoding is at least as suspicious as the one
            # that was readable all along: same rating as
            # PDF_JS_SUSPICIOUS.
            out.append(
                make_pdf_indicator(source,
                    "PDF_JS_DEOBFUSCATED",
                    "Verschleiertes JavaScript enthält bösartige API: "
                    + ", ".join(revealed),
                    detail=(
                        "Nach statischer Dekodierung (keine Ausführung) "
                        "wurden bislang verborgene Primitive sichtbar: "
                        + ", ".join(revealed)
                        + ". Dekodierter Anfang: " + excerpt
                    ),
                    severity=Severity.CRITICAL if auto_exec else Severity.HIGH,
                    category=CAT_SCRIPT,
                    weight=50 if auto_exec else 30,
                )
            )
    return out


def scan_pdf_javascript(
    ctx: AnalysisContext,
    pdf,
    *,
    source: str = "pdf",
    max_stream_bytes: int | None = None,
    extract_fn: Callable[..., tuple[list[str], list[str]]] | None = None,
) -> list[Indicator]:
    """Extract embedded JavaScript and analyse it for abuse / obfuscation.

    The keyword triage (stage 1) only counts ``/JavaScript``/``/JS`` markers
    on the raw bytes; here the actual script code is pulled out of the PDF
    object graph (including compressed streams and indirect references) and
    inspected statically. Nothing is executed.
    """
    limit = MAX_STREAM_BYTES if max_stream_bytes is None else max_stream_bytes
    try:
        if extract_fn is not None:
            chunks, stream_warnings = extract_fn(pdf)
        else:
            chunks, stream_warnings = extract_pdf_js(pdf, max_stream_bytes=limit)
    except Exception as exc:
        # A structural failure must not silently hide ALL JavaScript
        # findings — "could not analyse" is visibly different from "clean".
        return [
            make_pdf_indicator(source,
                "PDF_JS_PARSE_WARN",
                "JavaScript-Extraktion fehlerhaft — JS-Analyse nicht gelaufen",
                detail=(
                    f"{type(exc).__name__}: {exc} — die JS-Analyse ist "
                    "unvollständig; das Ergebnis ist nicht als 'sauber' zu werten."
                ),
                severity=Severity.MEDIUM,
                category=CAT_SCRIPT,
                # 25, not 0: the comment above was always right — the
                # weight was what made it a lie. SCORE_GREEN_MAX is 19, so
                # weight 0 scored a PDF whose JavaScript was NEVER
                # extracted as GREEN. The raw-byte triage cannot see JS
                # that lives in a compressed /ObjStm, which is exactly the
                # measured evasion.
                weight=25,
            )
        ]
    # Cap the analysed text: .lower() would otherwise double the memory
    # of an oversized (attack) payload once more.
    js_text = "\n".join(chunks)[:limit]
    out: list[Indicator] = []
    if stream_warnings:
        bomb_suspected = any(warn_is_bomb(w) for w in stream_warnings)
        # Runde 4: both branches are the same fact — the content of these
        # streams was NOT analysed. Measured before the fix: a merely
        # damaged /JS stream scored 0 (below SCORE_GREEN_MAX), the bomb 15.
        # So a PDF whose JavaScript sat in a stream the reader refused came
        # back GREEN, and the deliberate bomb weighed *more* than the
        # accident. One weight class (25) for "not read" — the title and the
        # severity distinguish the reason, no branch is the lighter one.
        out.append(
            make_pdf_indicator(source,
                "PDF_JS_STREAM_WARN",
                (
                    "JavaScript-Stream nur teilweise gelesen (Bomben-Verdacht)"
                    if bomb_suspected
                    else "JavaScript nicht vollständig analysiert"
                ),
                detail=(
                    "; ".join(stream_warnings[:3])
                    + " — der betroffene JavaScript-Code wurde nicht "
                    "analysiert; das Ergebnis ist nicht als 'sauber' zu werten."
                ),
                severity=Severity.MEDIUM,
                category=CAT_SCRIPT,
                weight=25,
            )
        )
    if not js_text.strip():
        return out
    # Auto-exec context: JS wired to /OpenAction or a genuine /AA key
    # runs on open. Raw-byte checks miss object streams and encrypted
    # PDFs, so the object graph is consulted as well. The regex excludes
    # /AAPL:… names that macOS writes into every Quartz PDF (they would
    # escalate innocent JS to CRITICAL).
    auto_exec = (
        b"/OpenAction" in ctx.data
        or bool(_AA_KEY_RE.search(ctx.data))
        or root_has_auto_action(pdf)
    )
    doc_budget = DeobfBudget()
    out.extend(analyze_js_text(js_text, auto_exec, source=source, budget=doc_budget))
    return out

