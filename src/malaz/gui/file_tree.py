"""Unified nested File & Container Tree for Malaz v11 ("Klare Fläche v2").

Displays both queued (pending) files and completed recursive ScanResult trees
(EML -> ZIP -> EXE, etc.) with:
- fixed 32x18 monospace format tags (red spoof tint on format-spoofed files),
- elided single-line BiDi-masked filenames (full masked name in tooltip),
- right-aligned circular status dots (solid bad/warn/ok, hollow ring unk/scanning/pending),
- ancestor-keep filtering (matching nested children keep their parent chain visible),
- drag & drop, Delete key removal, and context menu (locked while scanning).
"""

from __future__ import annotations

import os
from pathlib import Path

from PySide6.QtCore import QPoint, QRect, QRectF, QSize, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QFont, QFontMetrics, QPainter, QPen
from PySide6.QtWidgets import (
    QAbstractItemView,
    QMenu,
    QStyle,
    QStyledItemDelegate,
    QTreeWidget,
    QTreeWidgetItem,
    QWidget,
)

from ..design_tokens import format_tag_code, type_filter_bucket, visual_state
from ..models import ScanResult
from .sanitize import (
    clip_text,
    escape_tooltip,
    is_unc_or_device_path,
    masked_widget_text,
    result_is_incomplete,
)
from .theme import current_palette

RESULT_ROLE = int(Qt.ItemDataRole.UserRole) + 1
STATE_ROLE = int(Qt.ItemDataRole.UserRole) + 2
TAG_ROLE = int(Qt.ItemDataRole.UserRole) + 3
ROOT_PATH_ROLE = int(Qt.ItemDataRole.UserRole) + 4
PENDING_PATH_ROLE = int(Qt.ItemDataRole.UserRole) + 5
PARENT_CHAIN_ROLE = int(Qt.ItemDataRole.UserRole) + 6

_SPOOF_RULES = frozenset(
    {
        "GEN_DOUBLE_EXT",
        "GEN_EXT_MISMATCH",
        "GEN_BIDI_NAME",
        "ARCH_DOUBLE_EXT",
        "PE_DISGUISED_EXT",
    }
)


def is_spoofed_result(result: ScanResult) -> bool:
    """True when a file spoofs its extension/type (e.g. .pdf.exe)."""
    for ind in result.indicators:
        if ind.rule_id in _SPOOF_RULES or "MISMATCH" in ind.rule_id or "DOUBLE_EXT" in ind.rule_id:
            return True
    name = (result.display_name or "").lower()
    return (result.detected_type or "").lower() == "pe" and any(
        name.endswith((f".{ext}.exe", f".{ext}.scr"))
        for ext in ("pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt")
    )


class FileTreeDelegate(QStyledItemDelegate):
    """Paints v11 sidebar tree rows: [TAG] elided-filename ...... (dot)."""

    def sizeHint(self, option, index) -> QSize:
        return QSize(option.rect.width(), 34)

    def paint(self, painter: QPainter, option, index) -> None:
        p = current_palette()
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        rect: QRect = option.rect
        selected = bool(option.state & QStyle.StateFlag.State_Selected)
        hovered = bool(option.state & QStyle.StateFlag.State_MouseOver)

        row_rect = rect.adjusted(2, 1, -2, -1)
        if selected:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(p["row_active"]))
            painter.drawRoundedRect(QRectF(row_rect), 6.0, 6.0)
            painter.setBrush(QColor(p["row_active_line"]))
            painter.drawRect(QRectF(row_rect.left(), row_rect.top() + 3, 2.5, row_rect.height() - 6))
        elif hovered:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(p["row_hover"]))
            painter.drawRoundedRect(QRectF(row_rect), 6.0, 6.0)

        tag_info = index.data(TAG_ROLE)
        tag_code, tag_kind = tag_info if isinstance(tag_info, tuple) and len(tag_info) == 2 else ("DAT", "")
        tag_x = row_rect.left() + 8
        tag_y = row_rect.top() + (row_rect.height() - 18) // 2
        tag_rect = QRectF(tag_x, tag_y, 32.0, 18.0)

        if tag_kind == "spoof":
            tag_bg, tag_border, tag_fg = p["st_bad_badge"], p["st_bad_line"], p["st_bad"]
        elif tag_kind == "container":
            tag_bg, tag_border, tag_fg = p["st_info_badge"], p["st_info_line"], p["st_info"]
        else:
            tag_bg, tag_border, tag_fg = p["tag_bg"], p["border_subtle"], p["ink_2"]

        painter.setPen(QPen(QColor(tag_border), 1.0))
        painter.setBrush(QColor(tag_bg))
        painter.drawRoundedRect(tag_rect, 4.0, 4.0)

        f_tag = QFont("Cascadia Mono", 9)
        f_tag.setPixelSize(10)
        f_tag.setWeight(QFont.Weight.DemiBold)
        painter.setFont(f_tag)
        painter.setPen(QColor(tag_fg))
        painter.drawText(tag_rect, Qt.AlignmentFlag.AlignCenter, tag_code[:3])

        state = str(index.data(STATE_ROLE) or "pending")
        dot_d = 7.5
        dot_x = row_rect.right() - 16.0
        dot_y = row_rect.top() + (row_rect.height() - dot_d) / 2.0
        dot_rect = QRectF(dot_x, dot_y, dot_d, dot_d)

        if state in ("unk", "cancelled"):
            painter.setPen(QPen(QColor(p["st_warn"]), 1.7))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawEllipse(dot_rect)
        elif state == "scanning":
            painter.setPen(QPen(QColor(p["st_info"]), 1.7))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawEllipse(dot_rect)
        elif state == "pending":
            painter.setPen(QPen(QColor(p["ink_3"]), 1.5))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawEllipse(dot_rect)
        else:
            col = {"bad": p["st_bad"], "warn": p["st_warn"], "ok": p["st_ok"]}.get(state, p["ink_3"])
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(QColor(col)))
            painter.drawEllipse(dot_rect)

        text_left = int(tag_rect.right()) + 8
        text_right = int(dot_x) - 8
        text_w = max(20, text_right - text_left)
        name = str(index.data(Qt.ItemDataRole.DisplayRole) or "")

        f_name = QFont(option.font)
        f_name.setPixelSize(13)
        f_name.setWeight(QFont.Weight.DemiBold if selected else QFont.Weight.Normal)
        painter.setFont(f_name)
        painter.setPen(QColor(p["ink_1"] if selected or hovered else p["ink_2"]))
        elided = QFontMetrics(f_name).elidedText(name, Qt.TextElideMode.ElideRight, text_w)
        painter.drawText(
            QRect(text_left, row_rect.top(), text_w, row_rect.height()),
            Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
            elided,
        )
        painter.restore()


class FileTreeWidget(QTreeWidget):
    """Unified sidebar file & container tree with drag & drop and safe removal."""

    files_dropped = Signal(list)
    queue_changed = Signal()
    clear_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("fileTree")
        self.setHeaderHidden(True)
        self.setColumnCount(1)
        self.setIndentation(16)
        self.setUniformRowHeights(True)
        self.setAnimated(False)
        self.setRootIsDecorated(True)
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setItemDelegate(FileTreeDelegate(self))
        self.setAcceptDrops(True)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._show_context_menu)
        self._locked = False

    def set_locked(self, locked: bool) -> None:
        self._locked = bool(locked)

    def pending_paths(self) -> list[str]:
        paths: list[str] = []
        for i in range(self.topLevelItemCount()):
            item = self.topLevelItem(i)
            p = item.data(0, PENDING_PATH_ROLE)
            if p:
                paths.append(str(p))
        return paths

    def all_top_level_paths(self) -> list[str]:
        paths: list[str] = []
        for i in range(self.topLevelItemCount()):
            item = self.topLevelItem(i)
            p = item.data(0, PENDING_PATH_ROLE) or item.data(0, ROOT_PATH_ROLE)
            if p:
                paths.append(str(p))
        return paths

    def add_pending_path(self, raw_path: str) -> QTreeWidgetItem:
        name = Path(raw_path).name or raw_path
        masked = clip_text(masked_widget_text(name))
        tag = format_tag_code("", name)
        item = QTreeWidgetItem([masked])
        item.setData(0, RESULT_ROLE, None)
        item.setData(0, STATE_ROLE, "pending")
        item.setData(0, TAG_ROLE, tag)
        item.setData(0, ROOT_PATH_ROLE, raw_path)
        item.setData(0, PENDING_PATH_ROLE, raw_path)
        item.setData(0, PARENT_CHAIN_ROLE, [])
        item.setToolTip(0, escape_tooltip(raw_path))
        self.addTopLevelItem(item)
        return item

    def upsert_result(self, result: ScanResult) -> QTreeWidgetItem:
        def _norm(val: object) -> str:
            if not val:
                return ""
            raw = str(val)
            if is_unc_or_device_path(raw):
                return os.path.normcase(os.path.normpath(raw))
            try:
                return os.path.normcase(str(Path(raw).resolve()))
            except (OSError, ValueError):
                return os.path.normcase(os.path.normpath(raw))

        target_norm = _norm(result.path)
        res_name = os.path.normcase(Path(result.path).name or result.display_name)
        target_item: QTreeWidgetItem | None = None
        # Pass 1: exact / normalized full path match
        for i in range(self.topLevelItemCount()):
            cand = self.topLevelItem(i)
            pend = cand.data(0, PENDING_PATH_ROLE)
            if pend and (pend == result.path or _norm(pend) == target_norm):
                target_item = cand
                break
        # Pass 2: Dispatcher sets result.path = basename (OpSec); match first pending with same basename
        if target_item is None:
            for i in range(self.topLevelItemCount()):
                cand = self.topLevelItem(i)
                pend = cand.data(0, PENDING_PATH_ROLE)
                if pend and os.path.normcase(Path(str(pend)).name) == res_name:
                    target_item = cand
                    break

        full_disk_path = result.path
        if target_item is None:
            target_item = QTreeWidgetItem()
            self.addTopLevelItem(target_item)
        else:
            saved_root = target_item.data(0, ROOT_PATH_ROLE) or target_item.data(0, PENDING_PATH_ROLE)
            if saved_root:
                full_disk_path = str(saved_root)
            target_item.takeChildren()
        self._populate_item(target_item, result, root_path=full_disk_path, chain=[], depth=0)
        return target_item

    def _populate_item(
        self,
        item: QTreeWidgetItem,
        result: ScanResult,
        *,
        root_path: str,
        chain: list[tuple[str, QTreeWidgetItem]],
        depth: int,
    ) -> None:
        masked = clip_text(masked_widget_text(result.display_name))
        state = visual_state(result.risk_level, result_is_incomplete(result))
        tag = format_tag_code(result.detected_type, result.display_name, spoofed=is_spoofed_result(result))

        item.setText(0, masked)
        item.setData(0, RESULT_ROLE, result)
        item.setData(0, STATE_ROLE, state)
        item.setData(0, TAG_ROLE, tag)
        item.setData(0, ROOT_PATH_ROLE, root_path)
        item.setData(0, PENDING_PATH_ROLE, None)
        item.setData(0, PARENT_CHAIN_ROLE, list(chain))
        item.setToolTip(0, escape_tooltip(result.path or result.display_name, limit=70_000))

        next_chain = [*chain, (masked, item)]
        for child in result.children:
            child_item = QTreeWidgetItem()
            item.addChild(child_item)
            self._populate_item(child_item, child, root_path=root_path, chain=next_chain, depth=depth + 1)

        if result.children and state in ("bad", "warn", "unk") and depth < 4:
            item.setExpanded(True)

    def mark_pending_as_scanning(self) -> None:
        for i in range(self.topLevelItemCount()):
            item = self.topLevelItem(i)
            if item.data(0, RESULT_ROLE) is None:
                item.setData(0, STATE_ROLE, "scanning")
        self.viewport().update()

    def mark_unscanned_as_cancelled(self) -> None:
        for i in range(self.topLevelItemCount()):
            item = self.topLevelItem(i)
            if item.data(0, RESULT_ROLE) is None and item.data(0, STATE_ROLE) == "scanning":
                item.setData(0, STATE_ROLE, "cancelled")
                item.setToolTip(0, escape_tooltip("Prüfung abgebrochen — nicht geprüft"))
        self.viewport().update()

    def find_item_for_result(self, target: ScanResult) -> QTreeWidgetItem | None:
        def _walk(node: QTreeWidgetItem) -> QTreeWidgetItem | None:
            if node.data(0, RESULT_ROLE) is target:
                return node
            for idx in range(node.childCount()):
                found = _walk(node.child(idx))
                if found is not None:
                    return found
            return None

        for i in range(self.topLevelItemCount()):
            found = _walk(self.topLevelItem(i))
            if found is not None:
                return found
        return None

    def apply_filter(self, status_filter: str, type_filter: str, query: str) -> int:
        q = (query or "").strip().lower()
        filtering = status_filter != "all" or type_filter != "all" or bool(q)

        def _matches_self(item: QTreeWidgetItem) -> bool:
            state = str(item.data(0, STATE_ROLE) or "pending")
            if status_filter != "all":
                if status_filter == "unk":
                    if state not in ("unk", "cancelled"):
                        return False
                elif state != status_filter:
                    return False

            res: ScanResult | None = item.data(0, RESULT_ROLE)
            name = item.text(0)
            if type_filter != "all":
                dt = res.detected_type if res is not None else ""
                if type_filter_bucket(dt, name) != type_filter:
                    return False

            if q:
                hay = [name.lower()]
                if res is not None:
                    hay.append((res.detected_type or "").lower())
                    hay.append((res.sha256 or "").lower())
                    hay.extend(i.title.lower() for i in res.indicators)
                    hay.extend(i.rule_id.lower() for i in res.indicators)
                if not any(q in part for part in hay):
                    return False
            return True

        def _visit(item: QTreeWidgetItem) -> bool:
            child_vis = False
            for idx in range(item.childCount()):
                if _visit(item.child(idx)):
                    child_vis = True
            visible = _matches_self(item) or child_vis
            item.setHidden(not visible)
            if filtering and child_vis:
                item.setExpanded(True)
            return visible

        visible_top = 0
        for i in range(self.topLevelItemCount()):
            if _visit(self.topLevelItem(i)):
                visible_top += 1
        return visible_top

    def remove_selected_pending(self) -> int:
        if self._locked:
            return 0
        removed = 0
        for item in list(self.selectedItems()):
            if item.parent() is not None:
                continue
            if item.data(0, RESULT_ROLE) is None:
                idx = self.indexOfTopLevelItem(item)
                if idx >= 0:
                    self.takeTopLevelItem(idx)
                    removed += 1
        if removed:
            self.queue_changed.emit()
        return removed

    def keyPressEvent(self, event) -> None:
        if (
            event.key() in (Qt.Key.Key_Delete, Qt.Key.Key_Backspace)
            and not self._locked
            and self.remove_selected_pending()
        ):
            event.accept()
            return
        super().keyPressEvent(event)

    def _build_context_menu(self) -> QMenu:
        menu = QMenu(self)
        has_pending_sel = any(
            it.parent() is None and it.data(0, RESULT_ROLE) is None for it in self.selectedItems()
        )
        act_rm = menu.addAction("Aus Warteschlange entfernen")
        act_rm.setEnabled(has_pending_sel and not self._locked)
        act_rm.triggered.connect(self.remove_selected_pending)

        menu.addSeparator()
        act_clear = menu.addAction("Liste leeren")
        act_clear.setEnabled(self.topLevelItemCount() > 0 and not self._locked)
        act_clear.triggered.connect(self.clear_requested.emit)
        return menu

    def _show_context_menu(self, pos: QPoint) -> None:
        self._build_context_menu().exec(self.viewport().mapToGlobal(pos))

    def dragEnterEvent(self, event) -> None:
        if not self._locked and event.mimeData().hasUrls():
            event.acceptProposedAction()
            return
        event.ignore()

    def dragMoveEvent(self, event) -> None:
        if not self._locked and event.mimeData().hasUrls():
            event.acceptProposedAction()
            return
        event.ignore()

    def dropEvent(self, event) -> None:
        if self._locked or not event.mimeData().hasUrls():
            event.ignore()
            return
        paths = [u.toLocalFile() for u in event.mimeData().urls() if u.isLocalFile() and u.toLocalFile()]
        if paths:
            self.files_dropped.emit(paths)
            event.acceptProposedAction()
        else:
            event.ignore()
