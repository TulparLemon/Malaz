"""Bounded container and child-member scanning extracted from :mod:`malaz.core.dispatcher`.

Implements Spec 012 Etappe 3 (zero-behavior-change): isolates archive, 7-Zip,
compressed-stream, email-attachment, RTF-object, and SWF-payload unpacking from
core scan orchestration. Uses :class:`ContainerScanContext` to invoke
``Dispatcher`` callbacks without creating a back-import cycle.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .. import config
from ..models import CAT_ARCHIVE, Indicator, ScanResult, Severity
from .archive import (
    BUDGET_STOP_PREFIX,
    UNSAFE_NAME_PREFIX,
    ZIPSLIP_PREFIX,
    iter_zip_members,
)
from .filesource import FileSource
from .log_privacy import anonymize_name

log = logging.getLogger(__name__)


_DRAIN_BYTES = 8 * 1024 * 1024  # drain budget, see _drain_container_notes


class _ScanBudget:
    """Global per-top-level-file budget across ALL nesting levels.

    The per-container limits (MAX_RECURSIVE_MEMBERS, AV_ARCHIVE_MEMBER_LIMIT)
    reset on every recursion level — a fractal/quine zip multiplies them up
    to billions of scan calls and AV engine runs. One budget object travels
    through the whole recursion tree of a single scan_path() call (hunt
    finding: global recursion DoS).
    """

    __slots__ = ("av_left", "members_left")

    def __init__(self) -> None:
        self.members_left = config.MAX_TOTAL_SCAN_MEMBERS
        self.av_left = config.MAX_TOTAL_AV_MEMBER_SCANS

    def take_member(self) -> bool:
        if self.members_left <= 0:
            return False
        self.members_left -= 1
        return True

    def take_av(self) -> bool:
        if self.av_left <= 0:
            return False
        self.av_left -= 1
        return True


class _ScanChildFn(Protocol):
    def __call__(
        self,
        data: bytes,
        path: Path,
        depth: int,
        display_path: str,
        real_path: Path | None,
        size: int,
        sha256: str | None = None,
        md5: str | None = None,
        budget: _ScanBudget | None = None,
        source: FileSource | None = None,
    ) -> ScanResult: ...


@dataclass(frozen=True)
class ContainerScanContext:
    """Explicit dependency bundle passed from :class:`Dispatcher` to container helpers."""

    scan_child: _ScanChildFn
    av_scan_member: Callable[[ScanResult, bytes], None]
    finalize_score: Callable[[ScanResult], None]
    passwords: list[str] | None


def drain_container_notes(
    ctx: ContainerScanContext,
    iterator,
    children: list[ScanResult],
    path_label: str,
    depth: int,
    container_rule: str,
    container_title: str,
    limit: int = 16,
    max_bytes: int = 8 * 1024 * 1024,
    truncated_prefix: bool = False,
) -> None:
    """Collect the trailing container-level notes after a member limit.

    ``break`` abandons the generator, and container iterators emit their
    summary notes at the END: the Zip-Slip report in
    ``iter_compressed_members`` is the last yield, after the walk. With a
    plain ``break`` that note never arrived — measured: a TAR with a
    traversal entry scored RED 50 with 250 members and GREEN 0 with 251,
    the attempt vanishing without a trace.

    Only name-less notes are taken (``name == ""`` with an error). A named
    entry here is a member we decided not to scan; it is already covered by
    the skip note above, and scanning it would defeat the limit.

    Reaching those trailing notes means pulling the iterator to its end,
    and every ``next()`` materializes one member — on a 10 500-entry
    archive that is 10 500 payloads, exactly what the ``break`` exists to
    avoid. ``max_bytes`` bounds the payload materialized for this; cheap
    members (the common case for a tripped cap) still let us reach the
    summary, an archive of fat members stops early and keeps the note it
    already has.

    Fat members therefore *can* end the drain before the summary arrives,
    and the note is then unreachable: reaching it would mean pulling every
    remaining member (measured: a 260 MiB TAR of 1 MiB members needs 260
    pulls, and the note sits behind the last one), which is exactly what
    ``max_bytes`` forbids. Two things follow from that, and both are
    needed:

    * The loss must not be silent — a stage that did not evaluate content
      has to be score-effective or explicitly "ungeprüft". The drain
      therefore appends an explicit ``ARCH_NOTE_UNREAD`` note when the
      byte budget ends it (see ``_unread_tail_note``).
    * An iterator that knows the summary before the walk ends should not
      depend on the drain at all — ``iter_compressed_members`` collects the
      Zip-Slip names in a metadata pre-pass over the TAR headers and yields
      the report BEFORE any member is read (see ``core/archive.py``), so the
      CRITICAL finding is independent of this budget and of the member cap.
      Measured with the cap at 20 and 300 members of 200 KB: without the
      pre-pass a traversal at position 120 or 295 scored YELLOW 25 with no
      ``ARCH_ZIPSLIP``, numerically identical to the same archive without
      any traversal entry at all.
    """
    remaining = limit
    budget = max_bytes
    reason = "Volumen-Budget erschöpft"
    tail_unread = False
    try:
        for name, payload, error in iterator:
            if remaining <= 0:
                break
            if budget <= 0:
                # The next member's payload is what the budget forbids;
                # the summary notes live behind it. Reported below instead
                # of dropped in silence.
                tail_unread = True
                break
            budget -= len(payload) if payload else 0
            if not error or name:
                continue
            children.append(
                container_note(ctx,
                    error, path_label, depth, container_rule, container_title,
                    truncated_prefix=truncated_prefix,
                )
            )
            remaining -= 1
    except Exception as exc:  # a broken iterator must not lose the result
        log.warning("Container-Nachlauf fehlgeschlagen: %s: %s", type(exc).__name__, exc)
        reason = f"Iterator-Abbruch {type(exc).__name__}"
        tail_unread = True
    if tail_unread:
        children.append(unread_tail_note(ctx, path_label, depth, reason))


def unread_tail_note(ctx: ContainerScanContext, path_label: str, depth: int, reason: str) -> ScanResult:
    """Report a container drain that ended before the trailing summary.

    ``_drain_container_notes`` walks the iterator past the member limit to
    collect the container's summary notes, which every iterator emits as its
    LAST yield (Zip-Slip list, bomb stop, entry-limit stop). That walk is
    bounded by ``max_bytes`` because each ``next()`` materializes one
    member; when the remaining members are fat the budget is spent before
    the summary, and when the iterator raises the rest is unknown as well.
    Either way the summary is *not read* — and an unread stage must be
    explicitly visible (audit rule: score-effective or "ungeprüft").

    Weight 0 on purpose: the cause that got us here — the member limit
    tripping — is already weighted once as ``ARCH_MEMBER_SKIP`` /
    ``ARCH_TOTAL_LIMIT`` (25) at the call site, and "one cause, one weighted
    statement" forbids charging it a second time. Weight 25 here would push
    a benign archive of fat members to 50 = RED without a single content
    signal (the same double count that made a 101 MiB zero-byte TAR score
    RED 55). The note documents *which* stage noticed, not the finding.
    """
    note = ScanResult(path=path_label, depth=depth + 1)
    note.error = f"Abschlussnotiz des Containers nicht gelesen ({reason})"
    note.indicators = [
        Indicator(
            rule_id="ARCH_NOTE_UNREAD",
            title="Abschlussnotiz des Containers NICHT gelesen (ungeprüft)",
            detail=(
                f"Der Nachlauf nach dem Mitgliederlimit endete vor der "
                f"abschließenden Meldung des Containers ({reason}). Ob der "
                "Container eine solche Meldung hatte (Zip-Slip-Liste, "
                "Bomben-Stopp, Eintrags-Limit), ist damit UNGEPRÜFT. Die "
                "Gewichtung derselben Ursache trägt ARCH_MEMBER_SKIP."
            ),
            severity=Severity.INFO,
            category=CAT_ARCHIVE,
            weight=0,
            source="dispatcher",
        )
    ]
    ctx.finalize_score(note)
    return note


def scan_children(
    ctx: ContainerScanContext,
    iterator,
    depth: int,
    *,
    path_label: str,
    container_rule: str,
    container_title: str,
    member_rule: str = "ARCH_MEMBER_ERROR",
    member_title: str = "Mitglied nicht entpackbar",
    budget: _ScanBudget | None = None,
    truncated_prefix: bool = False,
    member_budget=None,
) -> list[ScanResult]:
    """Shared driver for every container member recursion.

    Turns ``(name, payload, error)`` streams (ZIP, 7z/RAR, tar/gzip,
    e-mail attachments, RTF objects, SWF payloads) into child results:
    container-level errors and bomb-protection stops become visible
    notes, per-member errors become "not examined" findings (MEDIUM/25,
    like the skip/stop notes — the iterator delivers no payload for
    them), and healthy members are re-scanned recursively — bounded by
    ``MAX_RECURSIVE_MEMBERS`` with an explicit truncation note when the
    cap trips.
    """
    children: list[ScanResult] = []
    scanned = 0
    if budget is None:  # defensive
        budget = _ScanBudget()
    # Budget for AV member scans: at most N members per archive go
    # through the real engines (each run costs seconds); the GLOBAL
    # cap in the budget bounds the total across all nesting levels.
    av_budget = (
        config.AV_ARCHIVE_MEMBER_LIMIT if config.AV_SCAN_ARCHIVE_MEMBERS else 0
    )
    for name, payload, error in iterator:
        if not name and error:
            children.append(
                container_note(ctx,
                    error, path_label, depth, container_rule, container_title,
                    truncated_prefix=truncated_prefix,
                )
            )
            continue

        if not budget.take_member():
            note = ScanResult(path=path_label, depth=depth + 1)
            note.error = (
                "Globales Scan-Limit erreicht — weitere Mitglieder über "
                "alle Verschachtelungsebenen nicht gescannt"
            )
            note.indicators = [
                Indicator(
                    rule_id="ARCH_TOTAL_LIMIT",
                    title="Globales Scan-Limit erreicht",
                    detail=(
                        f"Limit von {config.MAX_TOTAL_SCAN_MEMBERS} rekursiv "
                        "gescannter Mitglieder (global, über alle "
                        "Verschachtelungsebenen) erreicht — z. B. bei "
                        "Fractal-/Quine-Archiven. Das Ergebnis ist "
                        "unvollständig."
                    ),
                    severity=Severity.MEDIUM,
                    category=CAT_ARCHIVE,
                    weight=25,
                    source="dispatcher",
                )
            ]
            ctx.finalize_score(note)
            children.append(note)
            if member_budget is not None:
                member_budget.left = _DRAIN_BYTES
            drain_container_notes(ctx,
                iterator, children, path_label, depth,
                container_rule, container_title,
                truncated_prefix=truncated_prefix,
            )
            break

        if scanned >= config.MAX_RECURSIVE_MEMBERS:
            note = ScanResult(path=path_label, depth=depth + 1)
            note.error = "Weitere Mitglieder nicht gescannt (Responsiveness-Limit)"
            note.indicators = [
                Indicator(
                    rule_id="ARCH_MEMBER_SKIP",
                    title="Mitglieder nicht gescannt — Inhalt ungeprüft",
                    detail=(
                        f"Limit {config.MAX_RECURSIVE_MEMBERS} rekursiv "
                        "gescannter Mitglieder erreicht; der Rest dieses "
                        "Containers wurde NICHT analysiert. Der Inhalt ist "
                        "unbekannt, nicht sauber — ein schädliches Mitglied "
                        "hinter dieser Grenze bleibt unentdeckt."
                    ),
                    # Weight, not 0: skipping members removes the whole
                    # content stage from the verdict. With weight 0 a
                    # payload placed behind enough harmless entries scored
                    # GREEN — measured: the same archive scored RED 90 with
                    # the payload first and YELLOW 30 with it last.
                    severity=Severity.MEDIUM,
                    category=CAT_ARCHIVE,
                    weight=25,
                    source="dispatcher",
                )
            ]
            ctx.finalize_score(note)
            children.append(note)
            if member_budget is not None:
                member_budget.left = _DRAIN_BYTES
            drain_container_notes(ctx,
                iterator, children, path_label, depth,
                container_rule, container_title,
                truncated_prefix=truncated_prefix,
            )
            if any(
                indicator.rule_id == "ARCH_MEMBER_STOP"
                and "Eintrags-Limit" in indicator.detail
                # ALLE Kinder, nicht nur der Nachlauf: die TAR-Notiz
                # (iter_compressed_members) kommt VOR dem Walk, weil sie
                # aus dem Metadaten-Vorlauf stammt; ZIP/7z liefern sie am
                # Ende. Der Nachlauf-Bereich begann hinter dieser Notiz,
                # also blieb sie unentdeckt und 25 + 25 = 50 = ROT fuer ein
                # blosses Quelltext-Tarball (>10.000 Dateien). Gemessen:
                # TAR 50 ROT, dasselbe ZIP 25 GELB.
                for tail in children
                for indicator in tail.indicators
            ):
                # The iterator's entry-limit note is the single weighted
                # statement for this cause. Keep the responsiveness note
                # visible, but do not charge the same limit twice.
                note.indicators[0].weight = 0
                note.indicators[0].severity = Severity.INFO
                ctx.finalize_score(note)
            break

        if error:
            child = ScanResult(path=name, depth=depth + 1, error=error)
            child.indicators = [
                Indicator(
                    rule_id=member_rule,
                    title=member_title,
                    detail=(
                        f"{error} — dieses Mitglied wurde NICHT "
                        "analysiert; sein Inhalt ist unbekannt, nicht "
                        "sauber."
                    ),
                    severity=Severity.MEDIUM,
                    category=CAT_ARCHIVE,
                    # 25 statt 5 — dieselbe Gewichtsklasse wie
                    # ARCH_MEMBER_SKIP und ARCH_MEMBER_ERROR. Dieser Zweig
                    # bekommt seinen Fehler aus dem Iterator, und jeder
                    # Produzent liefert dazu einen LEEREN Payload
                    # (archive.py: "Eintrag zu groß", "Verschlüsselt",
                    # "Entpacken fehlgeschlagen", "nicht lesbar";
                    # sevenzip.py: "Eintrag nicht lesbar"; email_extract.py:
                    # "Anhang nicht dekodierbar"). Es gibt hier also keinen
                    # reinen Metadaten-Fehler, bei dem der Inhalt noch
                    # vorliegt — jedes error-Feld heißt "kein Inhalt".
                    # Gewicht 5 lag unter SCORE_GREEN_MAX (19): ein ZIP,
                    # dessen einziges Problem ein nicht entpackbares
                    # Nutzlast-Mitglied war, meldete GRÜN (gemessen:
                    # Verfahrensfeld 8 -> 98 GRÜN 5 gegen ROT 80 intakt,
                    # verschlüsselt markiert GRÜN 10).
                    weight=25,
                    source="dispatcher",
                )
            ]
            ctx.finalize_score(child)
            children.append(child)
            continue

        try:
            child = ctx.scan_child(
                data=payload,
                path=Path(name),
                depth=depth + 1,
                display_path=name,
                real_path=None,
                size=len(payload),
                budget=budget,
            )
        except Exception as exc:
            # Isolate per member. An exception here used to escape to
            # scan_path and replace the WHOLE result (no indicators left,
            # only CORE_ERROR) — measured: one crafted member turned a RED
            # archive GREEN. Now it costs this member only.
            log.warning(
                "Mitglied %r fehlgeschlagen: %s: %s",
                anonymize_name(name), type(exc).__name__, exc,
            )
            child = ScanResult(path=name, depth=depth + 1)
            child.error = f"{type(exc).__name__}: {exc}"
            child.indicators = [
                # Same rule id as the ``if error:`` branch above — both say
                # "this member was not analysed, its content is unknown" —
                # and the two are told apart by the title suffix. It used to
                # be ARCH_MEMBER_STOP, which the bomb-protection stop also
                # used; keeping the id unchanged across the whole
                # "member was not inspected" class means one id, one
                # meaning, and no third reading of ARCH_MEMBER_STOP.
                # 25 = same weight class as the other "not inspected" notes:
                # an unexamined member must not read as clean.
                Indicator(
                    rule_id="ARCH_MEMBER_ERROR",
                    title=f"{member_title} (unerwarteter Fehler)",
                    detail=(
                        f"{type(exc).__name__}: {exc} — dieses Mitglied "
                        "wurde NICHT analysiert."
                    ),
                    severity=Severity.MEDIUM,
                    category=CAT_ARCHIVE,
                    weight=25,
                    source="dispatcher",
                )
            ]
            ctx.finalize_score(child)
            children.append(child)
            continue
        # Real AV verdict for archive members, too — bounded by the
        # per-archive budget AND the global cap so huge or fractal
        # archives cannot explode the engine-call count.
        if av_budget > 0 and payload and budget.take_av():
            av_budget -= 1
            ctx.av_scan_member(child, payload)
        children.append(child)
        scanned += 1
        if (
            member_budget is not None
            and scanned >= config.MAX_RECURSIVE_MEMBERS
        ):
            # Arm the payload budget BEFORE the next member is pulled: the
            # ``for`` statement materialises it before the cap check in the
            # loop body can fire, so arming later came too late — measured,
            # a 30 MB member was still decompressed although the drain was
            # about to drop it.
            member_budget.left = _DRAIN_BYTES
    return children


def depth_limit_indicator(what: str, verb: str = "entpackt") -> Indicator:
    """The container stage stopped at ``MAX_ARCHIVE_DEPTH``.

    Below this level nothing is expanded — and therefore nothing is
    analysed. Weight 25 (not 5): the established size for "stage did not
    run", above ``SCORE_GREEN_MAX`` (19) so the file can never come out
    GREEN, and far below ``ANCHOR_CRITICAL_SCORE`` (50) so a single stopped
    level stays YELLOW. Measured: a six-level ZIP with a PowerShell payload
    in the innermost layer scored GREEN 5, the same payload two levels deep
    scored RED 50.
    """
    return Indicator(
        rule_id="ARCH_DEPTH_LIMIT",
        title="Maximale Verschachtelungstiefe erreicht",
        detail=(
            f"{what} wird nicht tiefer {verb} (Limit "
            f"{config.MAX_ARCHIVE_DEPTH}). Der Inhalt unterhalb dieser "
            "Ebene wurde NICHT geprüft."
        ),
        severity=Severity.MEDIUM,
        category=CAT_ARCHIVE,
        weight=25,
        source="dispatcher",
    )


def guarded_members(ctx: ContainerScanContext, what: str, fn, indicators: list[Indicator]):
    """Run a container recursion; a failure costs the stage, not the verdict.

    An exception from a member iterator used to escape all the way up to
    ``scan_path``, where the catch-all replaced the WHOLE result: the
    assignment ``result = ctx.scan_child(...)`` had never completed, so the
    fresh ``ScanResult`` carried no indicator at all and only ``CORE_ERROR``
    remained. Measured: an archive with a Zip-Slip entry scored RED 50, and
    GREEN 5 once one crafted member raised — a single member turned a
    detection into a false all-clear.

    Returns ``[]`` for the affected container so the rest of the scan (and
    every indicator collected so far) survives.

    Own rule id ``ARCH_CONTAINER_ERROR``. It used to share
    ``ARCH_MEMBER_STOP`` with the bomb-protection stop
    (``_container_note``) and with the per-member catch below — three
    different conditions behind one id, so any rule-id-based evaluation
    (report columns, corpus comparison, golden snapshot) collapsed "the
    container recursion raised" and "the archive was deliberately only
    partly extracted" into one indistinguishable set. The id itself is now
    unambiguous; weight 25 and MEDIUM are unchanged.
    """
    try:
        return fn()
    except Exception as exc:
        log.warning(
            "Container %s fehlgeschlagen: %s: %s", what, type(exc).__name__, exc
        )
        indicators.append(
            Indicator(
                rule_id="ARCH_CONTAINER_ERROR",
                title=f"{what}: Inhalt nicht auswertbar",
                detail=(
                    f"{type(exc).__name__}: {exc} — dieser Teil des "
                    "Containers wurde NICHT geprüft. Das Ergebnis ist "
                    "unvollständig und nicht als 'sauber' zu werten."
                ),
                severity=Severity.MEDIUM,
                category=CAT_ARCHIVE,
                weight=25,
                source="dispatcher",
            )
        )
        return []


def scan_archive_members(
    ctx: ContainerScanContext, data: bytes, depth: int, budget: _ScanBudget | None = None,
    truncated_prefix: bool = False, source_path=None,
) -> list[ScanResult]:
    # SEC-006: a path-backed source means ``iter_zip_members`` reads the
    # FULL file (central directory included), so a container error there is
    # a real ARCH_ZIP_ERROR — not a consequence of the in-memory prefix
    # cap. Passing the cap flag on let ``_container_note`` zero its weight
    # (25 -> 0, "Folge der Lesekappung") for a genuinely broken ZIP >64 MB.
    effective_truncation = truncated_prefix and source_path is None
    from .archive import MemberBudget

    member_budget = MemberBudget()
    return scan_children(ctx,
        iter_zip_members(
            data, ctx.passwords, path=source_path, member_budget=member_budget
        ),
        depth,
        path_label="(ZIP-Inhalt)",
        container_rule="ARCH_ZIP_ERROR",
        container_title="Archiv konnte nicht gelesen werden",
        budget=budget,
        truncated_prefix=effective_truncation,
        member_budget=member_budget,
    )


def scan_sevenzip_members(
    ctx: ContainerScanContext, data: bytes, depth: int, suffix: str,
    budget: _ScanBudget | None = None,
    truncated_prefix: bool = False,
) -> list[ScanResult]:
    """Scan members of a RAR/7z/CAB/ISO archive via the 7-Zip binary."""
    from .sevenzip import find_7z_binary, iter_7z_members

    label = "CAB/ISO-Inhalt" if suffix in (".cab", ".iso") else "RAR/7z-Inhalt"

    if not config.SEVENZIP_ENABLED:
        # A disabled stage must be visible: container content silently not
        # being scanned is indistinguishable from "clean" otherwise.
        note = ScanResult(path=f"({label})", depth=depth + 1)
        note.error = f"{label}-Auswertung deaktiviert (config.SEVENZIP_ENABLED=False)"
        note.indicators = [
            Indicator(
                rule_id="ARCH_7Z_DISABLED",
                title=f"{label} nicht geprüft",
                detail=(
                    "Die 7-Zip-Integration ist in der Konfiguration "
                    "deaktiviert. Die Datei wurde nur oberflächlich "
                    "geprüft (Entropie/Signaturen); der "
                    f"{label} wurde NICHT analysiert und ist nicht als "
                    "'sauber' zu werten."
                ),
                severity=Severity.MEDIUM,
                category=CAT_ARCHIVE,
                # 20 wie der Geschwisterzweig ARCH_7Z_MISSING: beide
                # bedeuten "der Inhalt wurde nicht analysiert".
                # Gewicht 0 (INFO) ließ den Bericht stattdessen
                # "Grün (unauffällig) ... bedenkenlos verwendet werden"
                # für einen nie angesehenen Container ausgeben (gemessen:
                # bad.7z GRÜN 0 abgeschaltet gegen GELB 20 ohne 7-Zip).
                weight=20,
                source="dispatcher",
            )
        ]
        ctx.finalize_score(note)
        return [note]

    if find_7z_binary() is None:
        note = ScanResult(path=f"({label})", depth=depth + 1)
        note.error = "7-Zip nicht installiert — Inhalt nicht gescannt"
        note.indicators = [
            Indicator(
                rule_id="ARCH_7Z_MISSING",
                title=f"{label} nicht geprüft",
                detail=(
                    "Zum Entpacken von RAR/7z/CAB/ISO-Containern wird eine "
                    "installierte 7-Zip-CLI (7z/7zz) benötigt. Der "
                    f"{label} wurde NICHT analysiert — das Ergebnis ist "
                    "nicht als 'sauber' zu werten (7-Zip installieren und "
                    "erneut scannen)."
                ),
                severity=Severity.MEDIUM,
                category=CAT_ARCHIVE,
                weight=20,
                source="dispatcher",
            )
        ]
        ctx.finalize_score(note)
        return [note]

    return scan_children(ctx,
        iter_7z_members(data, suffix, ctx.passwords),
        depth,
        path_label=f"({label})",
        container_rule="ARCH_7Z_ERROR",
        container_title="Archiv konnte nicht entpackt werden",
        budget=budget,
        truncated_prefix=truncated_prefix,
    )


def scan_compressed_members(
    ctx: ContainerScanContext, data: bytes, depth: int, kind: str,
    budget: _ScanBudget | None = None,
    truncated_prefix: bool = False,
) -> list[ScanResult]:
    """Scan members of a tar/gzip/bzip2/xz container (in-memory)."""
    from .archive import MemberBudget, iter_compressed_members

    member_budget = MemberBudget()
    return scan_children(ctx,
        iter_compressed_members(data, kind, member_budget=member_budget),
        depth,
        path_label="(TAR/komprimierter Inhalt)",
        container_rule="ARCH_TAR_ERROR",
        container_title="Container konnte nicht entpackt werden",
        budget=budget,
        truncated_prefix=truncated_prefix,
        member_budget=member_budget,
    )


def scan_email_members(
    ctx: ContainerScanContext, data: bytes, depth: int, kind: str,
    budget: _ScanBudget | None = None,
    truncated_prefix: bool = False,
) -> list[ScanResult]:
    """Scan every attachment of an .eml/.msg mail (in-memory)."""
    from .email_extract import iter_email_attachments

    return scan_children(ctx,
        iter_email_attachments(data, kind),
        depth,
        path_label="(E-Mail)",
        container_rule="EMAIL_PARSE_ERROR",
        container_title="E-Mail konnte nicht entpackt werden",
        member_rule="EMAIL_ATTACH_ERROR",
        member_title="Anhang nicht entpackbar",
        budget=budget,
        truncated_prefix=truncated_prefix,
    )


def scan_rtf_objects(
    ctx: ContainerScanContext, data: bytes, depth: int, budget: _ScanBudget | None = None,
    truncated_prefix: bool = False,
) -> list[ScanResult]:
    """Scan OLE/embedded objects decoded from an RTF (in-memory)."""
    from .rtf_extract import iter_rtf_objects

    return scan_children(ctx,
        iter_rtf_objects(data),
        depth,
        path_label="(RTF)",
        container_rule="RTF_PARSE_ERROR",
        container_title="RTF-Objekte konnten nicht gelesen werden",
        member_rule="RTF_OBJ_ERROR",
        member_title="Eingebettetes Objekt nicht lesbar",
        budget=budget,
        truncated_prefix=truncated_prefix,
    )


def scan_swf_payload(
    ctx: ContainerScanContext, data: bytes, depth: int, budget: _ScanBudget | None = None,
    truncated_prefix: bool = False,
) -> list[ScanResult]:
    """Scan the decompressed content of a compressed SWF."""
    from .swf_extract import iter_swf_payloads

    return scan_children(ctx,
        iter_swf_payloads(data),
        depth,
        path_label="(SWF)",
        container_rule="SWF_PARSE_ERROR",
        container_title="SWF konnte nicht dekomprimiert werden",
        member_rule="SWF_PAYLOAD_ERROR",
        member_title="SWF-Inhalt nicht lesbar",
        budget=budget,
        truncated_prefix=truncated_prefix,
    )


def container_note(
    ctx: ContainerScanContext,
    error: str,
    path_label: str,
    depth: int,
    error_rule: str,
    error_title: str,
    *,
    truncated_prefix: bool = False,
) -> ScanResult:
    """Build a child note for a container-level error or budget stop.

    A bomb-protection stop (``BUDGET_STOP_PREFIX``) means the archive was
    NOT fully analysed — that is a visible finding of its own, not an
    extraction failure, and must never be silently dropped.

    A traversal attempt (``ZIPSLIP_PREFIX``) is an attack indicator, not a
    degradation: it carries the same CRITICAL weight the ZIP pipeline
    assigns to ``ARCH_ZIPSLIP``, so RAR/7z cannot be the quiet route.

    ``truncated_prefix`` says the container was handed a cut-off prefix of
    a larger file (see ``_scan``). Its "not readable" message is then the
    consequence of that cap, not a second finding: it stays visible but
    carries no weight of its own, because CORE_READ_TRUNCATED counts the
    cap once. Without this the two weights added up to 50 =
    ANCHOR_CRITICAL_SCORE — a 101 MiB zero-byte TAR scored RED 55.
    """
    note = ScanResult(path=path_label, depth=depth + 1, error=error)
    if error.startswith(ZIPSLIP_PREFIX):
        detail = error[len(ZIPSLIP_PREFIX):].strip()
        note.indicators = [
            Indicator(
                rule_id="ARCH_ZIPSLIP",
                title="Zip-Slip-Versuch",
                detail=detail,
                severity=Severity.CRITICAL,
                category=CAT_ARCHIVE,
                weight=50,
                source="dispatcher",
            )
        ]
    elif error.startswith(UNSAFE_NAME_PREFIX):
        # Der ZWEITE Marker aus core.archive: derselbe Pruefer, aber ein
        # anderer Grund. Ein reservierter Geraetename oder ein
        # Doppelpunkt im Namen ist kein Pfad-Escape — ihn mit dem Anker
        # zu belegen behauptete einen Angriff, den es nicht gibt.
        # LOW/5 wie ARCH_ENCRYPTED: sichtbar, aber kein Urteil.
        detail = error[len(UNSAFE_NAME_PREFIX):].strip()
        note.indicators = [
            Indicator(
                rule_id="ARCH_UNSAFE_NAME",
                title="Ungewöhnliche Eintragsnamen",
                detail=detail,
                severity=Severity.LOW,
                category=CAT_ARCHIVE,
                weight=5,
                source="dispatcher",
            )
        ]
    elif error.startswith(BUDGET_STOP_PREFIX):
        note.indicators = [
            Indicator(
                rule_id="ARCH_MEMBER_STOP",
                title="Archiv nicht vollständig ausgewertet",
                detail=error,
                # Bombenschutz-Stopp: das Archiv wurde bewusst nur
                # teilweise entpackt — alleiniges GELB, damit der Stopp
                # nie in einem grünen Gesamtergebnis verschwindet.
                #
                # Diese ID gehört ALLEIN diesem Stopp. Die beiden anderen
                # "Stufe nicht gelaufen"-Fälle des Dispatchers tragen
                # eigene IDs (ARCH_CONTAINER_ERROR für die geworfene
                # Container-Rekursion, ARCH_MEMBER_ERROR für das nicht
                # analysierte Mitglied), sonst kollabiert jede Auswertung
                # über die Regel-ID "bewusst nur teilentpackt" mit
                # "Container-Ausnahme".
                severity=Severity.MEDIUM,
                category=CAT_ARCHIVE,
                weight=25,
                source="dispatcher",
            )
        ]
    else:
        note.indicators = [
            Indicator(
                rule_id=error_rule,
                title=error_title,
                # "Konnte nicht geöffnet werden" heißt: Der Inhalt wurde
                # ÜBERHAUPT nicht analysiert (passwortgeschützter Header,
                # defektes Archiv, …). Nach dem Grundsatz "nicht
                # analysierbar ≠ sauber" muss so ein Fund allein schon
                # GELB geben — der Live-VM-Test hat genau hier eine
                # bösartige 7z als GRÜN durchrutschen sehen.
                #
                # Ausnahme: Der Container bekam nur einen abgeschnittenen
                # Präfix der Datei. Dann ist "nicht lesbar" die Folge der
                # Lesekappung, die CORE_READ_TRUNCATED bereits mit 20
                # bewertet — der Befund bleibt sichtbar (Gewicht 0), zählt
                # aber nicht ein zweites Mal (25 + 25 = 50 = ROT).
                detail=(
                    f"{error} — Folge der Lesekappung: der Rest der Datei "
                    "wurde nicht gelesen (siehe CORE_READ_TRUNCATED)."
                    if truncated_prefix
                    else error
                ),
                severity=(
                    Severity.INFO if truncated_prefix else Severity.MEDIUM
                ),
                category=CAT_ARCHIVE,
                weight=0 if truncated_prefix else 25,
                source="dispatcher",
            )
        ]
    ctx.finalize_score(note)
    return note
