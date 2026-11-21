"""Automatic display & High-DPI window/dialog sizing helpers.

Ensures Malaz never overflows off-screen or behind the Windows taskbar on
1080p laptops at 125%/150% DPI scaling (e.g. 1280x672 logical available area),
and re-clamps safely when moved across heterogeneous monitors.
"""

from __future__ import annotations

from PySide6.QtCore import QRect
from PySide6.QtGui import QGuiApplication, QScreen
from PySide6.QtWidgets import QDialog, QWidget

from .settings import app_settings

_FALLBACK_RECT = QRect(0, 0, 1280, 720)
_SETTINGS_RECT_KEY = "ui/window_rect"


def available_screen_rect(widget: QWidget | None = None) -> QRect:
    """Return usable screen geometry (excluding taskbar), with safe offscreen fallback."""
    screen: QScreen | None = None
    if widget is not None:
        handle = widget.windowHandle()
        if handle is not None:
            screen = handle.screen()
        if screen is None:
            screen = widget.screen()
    if screen is None:
        screen = QGuiApplication.primaryScreen()
    if screen is None:
        return QRect(_FALLBACK_RECT)
    avail = screen.availableGeometry()
    if avail.width() <= 0 or avail.height() <= 0:
        return QRect(_FALLBACK_RECT)
    return QRect(avail)


def compute_clamped_rect(
    avail: QRect,
    *,
    preferred_w: int = 1280,
    preferred_h: int = 760,
    saved: tuple[int, int, int, int] | None = None,
    margin_w: int = 32,
    margin_h: int = 40,
) -> QRect:
    """Pure geometry calculation: clamp preferred or saved rect strictly inside ``avail``."""
    max_w = max(320, avail.width())
    max_h = max(240, avail.height())

    if saved is not None:
        sx, sy, sw, sh = saved
        w = max(320, min(sw, max_w))
        h = max(240, min(sh, max_h))
        x = max(avail.left(), min(sx, avail.right() - w + 1))
        y = max(avail.top(), min(sy, avail.bottom() - h + 1))
        return QRect(x, y, w, h)

    target_w = min(preferred_w, max(320, max_w - margin_w)) if max_w > 960 else max_w
    target_h = min(preferred_h, max(240, max_h - margin_h)) if max_h > 600 else max_h
    w = min(target_w, max_w)
    h = min(target_h, max_h)
    x = avail.left() + max(0, (max_w - w) // 2)
    y = avail.top() + max(0, (max_h - h) // 2)
    return QRect(x, y, w, h)


def load_window_rect() -> tuple[int, int, int, int] | None:
    """Load persisted ``(x, y, w, h)`` from QSettings, or ``None`` if unset/invalid."""
    raw = app_settings().value(_SETTINGS_RECT_KEY)
    if not isinstance(raw, (list, tuple)) or len(raw) != 4:
        return None
    try:
        x, y, w, h = (int(v) for v in raw)
    except (TypeError, ValueError):
        return None
    if w < 320 or h < 240:
        return None
    return (x, y, w, h)


def save_window_rect(widget: QWidget) -> None:
    """Persist normal (non-maximized) window geometry as a plain 4-int rect."""
    if widget.isMaximized() or widget.isMinimized():
        return
    g = widget.geometry()
    if g.width() >= 320 and g.height() >= 240:
        app_settings().setValue(_SETTINGS_RECT_KEY, [g.x(), g.y(), g.width(), g.height()])


def clamp_window_to_screen(
    widget: QWidget,
    *,
    preferred_w: int = 1280,
    preferred_h: int = 760,
    min_w: int = 960,
    min_h: int = 560,
    use_saved: bool = True,
) -> QRect:
    """Set screen-safe minimum size and initial geometry on a top-level window."""
    avail = available_screen_rect(widget)
    widget.setMinimumSize(min(min_w, avail.width()), min(min_h, avail.height()))
    saved = load_window_rect() if use_saved else None
    rect = compute_clamped_rect(
        avail,
        preferred_w=preferred_w,
        preferred_h=preferred_h,
        saved=saved,
    )
    widget.setGeometry(rect)
    return rect


def reclamp_to_current_screen(widget: QWidget) -> None:
    """Re-clamp an already shown window if moved onto a smaller/higher-DPI monitor."""
    if widget.isMaximized():
        return
    avail = available_screen_rect(widget)
    g = widget.geometry()
    if g.width() <= avail.width() and g.height() <= avail.height() and avail.contains(g):
        return
    clamped = compute_clamped_rect(
        avail,
        saved=(g.x(), g.y(), g.width(), g.height()),
    )
    widget.setMinimumSize(min(960, avail.width()), min(560, avail.height()))
    widget.setGeometry(clamped)


def clamp_dialog_to_screen(
    dialog: QDialog,
    *,
    preferred_w: int,
    preferred_h: int,
    min_w: int = 440,
    min_h: int = 340,
) -> QRect:
    """Clamp a modal dialog to at most 88% of the current screen's available area."""
    avail = available_screen_rect(dialog.parentWidget() or dialog)
    max_w = max(320, int(avail.width() * 0.88))
    max_h = max(260, int(avail.height() * 0.88))
    w = min(preferred_w, max_w)
    h = min(preferred_h, max_h)
    dialog.setMinimumSize(min(min_w, w), min(min_h, h))
    dialog.resize(w, h)
    return QRect(0, 0, w, h)


def show_message_box(
    parent,
    title: str,
    text: str,
    *,
    icon=None,
) -> int:
    """Show a QMessageBox with explicitly localized button text (never OS-default DE in EN/TR).

    Respects test monkeypatches on ``QMessageBox.information`` / ``QMessageBox.critical``.
    """
    import types

    from PySide6.QtWidgets import QMessageBox

    from ..i18n import t

    is_crit = icon == QMessageBox.Icon.Critical
    static_fn = QMessageBox.critical if is_crit else QMessageBox.information
    if isinstance(static_fn, types.FunctionType):
        res = static_fn(parent, title, text)
        return int(res) if isinstance(res, int) else 0

    from PySide6.QtCore import Qt

    box = QMessageBox(parent)
    box.setTextFormat(Qt.TextFormat.PlainText)
    box.setWindowTitle(title)
    box.setText(text)
    box.setIcon(icon if icon is not None else QMessageBox.Icon.Information)
    box.addButton(t("btn.ok"), QMessageBox.ButtonRole.AcceptRole)
    return box.exec()
