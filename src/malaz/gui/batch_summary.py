"""Folder Overview (Ordner-Übersicht) dashboard for Malaz v11.

Displays 4 clickable KPI cards (Dangerous, Suspicious, Unchecked, Clean)
with circular status dots + a clickable Action Required list of all non-clean
top-level scanned files.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLayout,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from .. import config
from ..design_tokens import format_size, format_tag_code, state_label, visual_state
from ..i18n import get_language, localized_indicator_title, pick, t
from ..models import ScanResult
from .file_tree import is_spoofed_result
from .sanitize import (
    clip_text,
    escape_tooltip,
    indicator_weight,
    is_unc_or_device_path,
    masked_widget_text,
    result_is_incomplete,
)
from .score_ring import StatusDotWidget


class _KpiCard(QFrame):
    clicked = Signal(str)

    def __init__(
        self,
        state_key: str,
        title: str,
        subtitle: str,
        *,
        ring: bool = False,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._state_key = state_key
        self.setObjectName("kpiCard")
        self.setProperty("state", state_key if state_key != "unk" else "")
        self.setMinimumHeight(74)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(2)

        top = QHBoxLayout()
        top.setContentsMargins(0, 0, 0, 0)
        top.setSpacing(8)
        top.addWidget(
            StatusDotWidget(state_key, ring=ring, parent=self),
            0,
            Qt.AlignmentFlag.AlignVCenter,
        )

        self._count = QLabel("0", self)
        self._count.setObjectName("engineVal")
        self._count.setProperty("tone", "warn" if state_key == "unk" else state_key)
        self._count.setTextFormat(Qt.TextFormat.PlainText)
        top.addWidget(self._count, 1)
        lay.addLayout(top)

        self._title_lbl = QLabel(title, self)
        self._title_lbl.setObjectName("panelHeading")
        self._title_lbl.setTextFormat(Qt.TextFormat.PlainText)
        lay.addWidget(self._title_lbl)

        self._sub_lbl = QLabel(subtitle, self)
        self._sub_lbl.setObjectName("captionLabel")
        self._sub_lbl.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self._sub_lbl.setTextFormat(Qt.TextFormat.PlainText)
        lay.addWidget(self._sub_lbl)

    def set_labels(self, title: str, subtitle: str) -> None:
        self._title_lbl.setText(title)
        self._sub_lbl.setText(subtitle)

    def set_count(self, n: int) -> None:
        self._count.setText(str(n))

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self._state_key)
        super().mousePressEvent(event)


class _ActionRow(QFrame):
    clicked = Signal(object)

    def __init__(
        self,
        result: ScanResult,
        *,
        is_last: bool = False,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._result = result
        lang = get_language()
        state = visual_state(result.risk_level, result_is_incomplete(result))
        self.setObjectName("listRow")
        self.setProperty("clickable", "true")
        self.setProperty("last", "true" if is_last else "false")
        if state in ("bad", "warn"):
            self.setProperty("accent", state)
        self.setMinimumHeight(44)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        lay = QHBoxLayout(self)
        lay.setContentsMargins(13, 8, 16, 8)
        lay.setSpacing(14)

        left = QHBoxLayout()
        left.setContentsMargins(0, 0, 0, 0)
        left.setSpacing(8)
        tag_code, tag_kind = format_tag_code(
            result.detected_type,
            result.display_name,
            spoofed=is_spoofed_result(result),
        )
        tag_lbl = QLabel(tag_code, self)
        tag_lbl.setObjectName("fmtTag")
        tag_lbl.setProperty("kind", tag_kind)
        tag_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        tag_lbl.setTextFormat(Qt.TextFormat.PlainText)
        left.addWidget(tag_lbl)

        name_lbl = QLabel(clip_text(masked_widget_text(result.display_name), 38), self)
        name_lbl.setObjectName("panelHeading")
        name_lbl.setTextFormat(Qt.TextFormat.PlainText)
        name_lbl.setToolTip(escape_tooltip(result.display_name))
        left.addWidget(name_lbl, 1)

        left_box = QWidget(self)
        left_box.setLayout(left)
        left_box.setMinimumWidth(190)
        left_box.setMaximumWidth(250)
        lay.addWidget(left_box)

        top_ind = next(
            (
                i
                for i in sorted(
                    result.all_indicators(),
                    key=lambda x: (-indicator_weight(x), -int(x.severity)),
                )
                if indicator_weight(i) > 0
            ),
            None,
        )
        if state == "unk":
            desc_txt = (
                masked_widget_text(localized_indicator_title(result.incomplete_stages[0], lang=lang))
                if result.incomplete_stages
                else pick(
                    "Inhalt konnte nicht vollständig geprüft werden",
                    "Contents could not be fully inspected",
                    "İçerik tam olarak incelenemedi",
                    lang=lang,
                )
            )
        elif top_ind is not None:
            desc_txt = masked_widget_text(localized_indicator_title(top_ind, lang=lang))
        else:
            desc_txt = pick("Auffällige Datei", "Suspicious file", "Şüpheli dosya", lang=lang)

        desc_lbl = QLabel(clip_text(desc_txt, 90), self)
        desc_lbl.setObjectName("mutedLabel")
        desc_lbl.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        desc_lbl.setTextFormat(Qt.TextFormat.PlainText)
        lay.addWidget(desc_lbl, 1)

        badge_text = state_label(state, lang=lang)
        badge_tone = "warn" if state == "unk" else state
        badge = QLabel(badge_text, self)
        badge.setObjectName("badgeRight")
        badge.setProperty("tone", badge_tone)
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        badge.setTextFormat(Qt.TextFormat.PlainText)
        lay.addWidget(badge)

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self._result)
        super().mousePressEvent(event)


class BatchSummary(QWidget):
    """Folder Overview view (Ordner-Übersicht)."""

    filter_requested = Signal(str)
    result_selected = Signal(object)
    export_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("batchSummary")
        self._last_results: list[ScanResult] = []
        self._last_source_paths: list[str] | None = None
        self._last_truncated: bool = False

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(12)

        top_meta = QHBoxLayout()
        top_meta.setContentsMargins(0, 0, 0, 0)
        self._origin_lbl = QLabel("", self)
        self._origin_lbl.setObjectName("captionLabel")
        self._origin_lbl.setTextFormat(Qt.TextFormat.PlainText)
        top_meta.addWidget(self._origin_lbl, 1)

        self._size_lbl = QLabel("", self)
        self._size_lbl.setObjectName("captionLabel")
        self._size_lbl.setTextFormat(Qt.TextFormat.PlainText)
        top_meta.addWidget(self._size_lbl)
        root.addLayout(top_meta)

        hdr = QHBoxLayout()
        hdr.setContentsMargins(0, 0, 0, 0)
        self._title_lbl = QLabel("", self)
        self._title_lbl.setObjectName("fileTitle")
        self._title_lbl.setTextFormat(Qt.TextFormat.PlainText)
        hdr.addWidget(self._title_lbl, 1)
        self.headline = QLabel("", self)
        self.headline.setObjectName("mutedLabel")
        self.headline.setWordWrap(True)
        self.headline.setTextFormat(Qt.TextFormat.PlainText)
        self.detail = QLabel("", self)
        self.detail.setObjectName("captionLabel")
        self.detail.setWordWrap(True)
        self.detail.setTextFormat(Qt.TextFormat.PlainText)

        self._btn_export = QPushButton("", self)
        self._btn_export.clicked.connect(self.export_requested.emit)
        hdr.addWidget(self._btn_export)
        root.addLayout(hdr)

        kpis = QHBoxLayout()
        kpis.setContentsMargins(0, 0, 0, 0)
        kpis.setSpacing(12)
        self._kpi_bad = _KpiCard("bad", "", "", parent=self)
        self._kpi_warn = _KpiCard("warn", "", "", parent=self)
        self._kpi_unk = _KpiCard("unk", "", "", ring=True, parent=self)
        self._kpi_ok = _KpiCard("ok", "", "", parent=self)
        for card in (self._kpi_bad, self._kpi_warn, self._kpi_unk, self._kpi_ok):
            card.clicked.connect(self.filter_requested.emit)
            kpis.addWidget(card, 1)
        root.addLayout(kpis)

        self._trunc_banner = QFrame(self)
        self._trunc_banner.setObjectName("card")
        self._trunc_banner.setProperty("accent", "warn")
        tb_lay = QHBoxLayout(self._trunc_banner)
        tb_lay.setContentsMargins(14, 10, 14, 10)
        self._trunc_lbl = QLabel("", self._trunc_banner)
        self._trunc_lbl.setObjectName("panelHeading")
        self._trunc_lbl.setWordWrap(True)
        self._trunc_lbl.setTextFormat(Qt.TextFormat.PlainText)
        tb_lay.addWidget(self._trunc_lbl, 1)
        self._trunc_banner.hide()
        root.addWidget(self._trunc_banner)

        root.addWidget(self.headline)
        root.addWidget(self.detail)

        self._sec_lbl = QLabel("", self)
        self._sec_lbl.setObjectName("sectionTitle")
        self._sec_lbl.setTextFormat(Qt.TextFormat.PlainText)
        root.addWidget(self._sec_lbl)

        self._list_card = QFrame(self)
        self._list_card.setObjectName("card")
        self._list_card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        self._list_lay = QVBoxLayout(self._list_card)
        self._list_lay.setSizeConstraint(QLayout.SizeConstraint.SetMinimumSize)
        self._list_lay.setContentsMargins(0, 0, 0, 0)
        self._list_lay.setSpacing(0)
        root.addWidget(self._list_card)
        root.addStretch(1)

        self._common_dir: str | None = None
        self._apply_static_texts()

    def _apply_static_texts(self) -> None:
        lang = get_language()
        self._title_lbl.setText(pick("Ordner-Übersicht", "Folder Overview", "Klasör Özeti", lang=lang))
        self._btn_export.setText(t("btn.export"))
        if lang == "tr":
            self._kpi_bad.set_labels("Tehlikeli", "Hemen izole edin")
            self._kpi_warn.set_labels("Şüpheli", "İnceleme gerekli")
            self._kpi_unk.set_labels("Taranamadı", "Eksik / parola korumalı")
            self._kpi_ok.set_labels("Temiz", "Tehdit bulunmadı")
            self._sec_lbl.setText("DİKKAT GEREKTİRENLER")
        elif lang == "en":
            self._kpi_bad.set_labels("Dangerous", "Isolate immediately")
            self._kpi_warn.set_labels("Suspicious", "Review needed")
            self._kpi_unk.set_labels("Unchecked", "Incomplete / encrypted")
            self._kpi_ok.set_labels("Clean", "No threats")
            self._sec_lbl.setText("ACTION REQUIRED")
        else:
            self._kpi_bad.set_labels("Gefährlich", "Sofort isolieren")
            self._kpi_warn.set_labels("Verdächtig", "Prüfung nötig")
            self._kpi_unk.set_labels("Ungeprüft", "Unvollständig / Schutz")
            self._kpi_ok.set_labels("Unauffällig", "Sauber")
            self._sec_lbl.setText("HANDLUNGSBEDARF")

    def retranslate(self) -> None:
        self._apply_static_texts()
        if self._last_results or self._last_truncated:
            self.update_results(
                self._last_results,
                source_paths=self._last_source_paths,
                truncated=self._last_truncated,
            )

    @property
    def common_directory(self) -> str | None:
        return self._common_dir

    def update_results(
        self,
        results: list[ScanResult],
        *,
        source_paths: list[str] | None = None,
        truncated: bool = False,
    ) -> None:
        self._last_results = list(results)
        self._last_source_paths = list(source_paths) if source_paths is not None else None
        self._last_truncated = bool(truncated)
        self._apply_static_texts()

        lang = get_language()
        is_en = lang == "en"

        bad = [r for r in results if visual_state(r.risk_level, result_is_incomplete(r)) == "bad"]
        warn = [r for r in results if visual_state(r.risk_level, result_is_incomplete(r)) == "warn"]
        unk = [r for r in results if visual_state(r.risk_level, result_is_incomplete(r)) == "unk"]
        ok = [r for r in results if visual_state(r.risk_level, result_is_incomplete(r)) == "ok"]

        self._kpi_bad.set_count(len(bad))
        self._kpi_warn.set_count(len(warn))
        self._kpi_unk.set_count(len(unk))
        self._kpi_ok.set_count(len(ok))
        inc_total = sum(1 for r in results if result_is_incomplete(r))

        if lang == "tr":
            parts_h = [f"{len(results)} dosya tarandı"]
            if bad:
                parts_h.append(f"{len(bad)} tehlikeli")
            if warn:
                parts_h.append(f"{len(warn)} şüpheli")
            if ok:
                parts_h.append(f"{len(ok)} temiz")
            if inc_total:
                parts_h.append(f"{inc_total} taranamadı")
        elif is_en:
            parts_h = [
                f"{len(results)} file scanned" if len(results) == 1 else f"{len(results)} files scanned"
            ]
            if bad:
                parts_h.append(f"{len(bad)} dangerous")
            if warn:
                parts_h.append(f"{len(warn)} suspicious")
            if ok:
                parts_h.append(f"{len(ok)} clean")
            if inc_total:
                parts_h.append(f"{inc_total} unchecked")
        else:
            parts_h = [f"{len(results)} Dateien geprüft"]
            if bad:
                parts_h.append(f"{len(bad)} gefährlich")
            if warn:
                parts_h.append(f"{len(warn)} verdächtig")
            if ok:
                parts_h.append(f"{len(ok)} unauffällig")
            if inc_total:
                parts_h.append(f"{inc_total} unvollständig")
        self.headline.setText(" · ".join(parts_h))

        rule_counts: Counter[str] = Counter()
        for r in results:
            for ind in r.all_indicators():
                if indicator_weight(ind) > 0:
                    rule_counts[ind.rule_id] += 1
        top_rules = ", ".join(f"{rid} ({cnt})" for rid, cnt in rule_counts.most_common(5))
        prefix = pick("Top-Regeln: ", "Top rules: ", "Öne çıkan kurallar: ", lang=lang)
        self.detail.setText(f"{prefix}{top_rules}" if top_rules else "")
        self.detail.setVisible(bool(top_rules))

        total_bytes = sum(max(0, r.size) for r in results)
        files_word = (
            "dosya" if lang == "tr" else (("file" if len(results) == 1 else "files") if is_en else "Dateien")
        )
        self._size_lbl.setText(f"{len(results)} {files_word} · {format_size(total_bytes, lang=lang)}")

        if truncated:
            self._trunc_lbl.setText(
                pick(
                    f"Batch-Limit erreicht (max. {config.MAX_BATCH_FILES} Dateien) — "
                    "weitere Dateien wurden nicht aufgenommen und nicht geprüft.",
                    f"Batch limit reached (max {config.MAX_BATCH_FILES} files) — "
                    "additional files were not queued and remain unchecked.",
                    f"Toplu tarama sınırına ulaşıldı (en fazla {config.MAX_BATCH_FILES} dosya) — "
                    "kalan dosyalar kuyruğa alınmadı ve taranamadı.",
                    lang=lang,
                )
            )
            self._trunc_banner.show()
        else:
            self._trunc_banner.hide()

        raw_paths = [p for p in (source_paths or []) if p] or [r.path for r in results if r.path]
        parents: set[str] = set()
        for raw in raw_paths:
            if is_unc_or_device_path(raw):
                continue
            parent_str = str(Path(raw).parent)
            if parent_str and parent_str != ".":
                parents.add(parent_str)

        if len(parents) == 1:
            only = next(iter(parents))
            if is_unc_or_device_path(only):
                self._common_dir = None
            else:
                try:
                    self._common_dir = only if Path(only).is_dir() else None
                except (OSError, ValueError):
                    self._common_dir = None
            self._origin_lbl.setText(clip_text(masked_widget_text(only), 90))
        else:
            self._common_dir = None
            if parents:
                self._origin_lbl.setText(
                    pick(
                        f"{len(parents)} Ordner",
                        f"{len(parents)} folders",
                        f"{len(parents)} klasör",
                        lang=lang,
                    )
                )
            else:
                self._origin_lbl.setText("")

        while self._list_lay.count():
            child = self._list_lay.takeAt(0)
            if child.widget() is not None:
                w = child.widget()
                w.hide()
                w.setParent(None)
                w.deleteLater()

        flagged = [*bad, *warn, *unk]
        if not flagged:
            row = QFrame(self._list_card)
            row.setObjectName("listRow")
            row.setProperty("last", "true")
            rl = QHBoxLayout(row)
            rl.setContentsMargins(16, 12, 16, 12)
            lbl = QLabel(
                (
                    pick(
                        "Keine auffälligen oder ungeprüften Dateien gefunden.",
                        "No suspicious or unchecked files found.",
                        "Şüpheli veya taranamayan dosya bulunmadı.",
                        lang=lang,
                    )
                ),
                row,
            )
            lbl.setObjectName("mutedLabel")
            lbl.setTextFormat(Qt.TextFormat.PlainText)
            rl.addWidget(lbl)
            self._list_lay.addWidget(row)
        else:
            shown = flagged[:100]
            for idx, res in enumerate(shown):
                row = _ActionRow(res, is_last=(idx == len(shown) - 1), parent=self._list_card)
                row.clicked.connect(self.result_selected.emit)
                self._list_lay.addWidget(row)
            if len(flagged) > 100:
                more = QLabel(
                    (
                        pick(
                            f"+ {len(flagged) - 100} weitere Einträge in der Seitenleiste",
                            f"+ {len(flagged) - 100} more entries in the sidebar",
                            f"+ yan menüde {len(flagged) - 100} kayıt daha",
                            lang=lang,
                        )
                    ),
                    self._list_card,
                )
                more.setObjectName("captionLabel")
                more.setContentsMargins(16, 8, 16, 10)
                self._list_lay.addWidget(more)
        self._list_card.updateGeometry()
        self.updateGeometry()


BatchOverviewView = BatchSummary
