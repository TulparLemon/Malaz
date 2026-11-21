"""QRunnable scan worker with a QObject signal bridge.

The GUI thread must never run analysis directly. ``ScanWorker`` executes on a
``QThreadPool`` and reports progress and results back to the GUI thread via Qt
queued signals, which is thread-safe.

Files are scanned in parallel by a small bounded thread pool
(``config.MAX_SCAN_WORKERS``) — the AV engines cost seconds per file, so
folder scans benefit visibly. Work runs concurrently, but results are
EMITTED in input order: the loop awaits each future sequentially, trading a
small delay (a slow file N holds emissions for N+1…) for deterministic,
easy-to-read output.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from PySide6.QtCore import QObject, QRunnable, Signal

from .. import config
from ..core.dispatcher import Dispatcher
from ..core.scoring import compute_score
from ..i18n import pick, t
from ..models import CAT_STRUCTURE, Indicator, ScanResult, Severity


class WorkerSignals(QObject):
    """Signals emitted by :class:`ScanWorker` (received on the GUI thread)."""

    # (current_index, total_count) — completed files, in input order
    progress = Signal(int, int)
    # human-readable status line
    status = Signal(str)
    # one finished ScanResult
    result = Signal(object)
    # a non-fatal error message
    error = Signal(str)
    # all files processed (True when the user cancelled mid-run)
    finished = Signal(bool)


class ScanWorker(QRunnable):
    """Scans a batch of file paths off the GUI thread."""

    def __init__(self, paths: list[str], dispatcher: Dispatcher | None = None):
        super().__init__()
        self.paths = [str(p) for p in paths]
        self.dispatcher = dispatcher or Dispatcher()
        self.signals = WorkerSignals()
        self._cancelled = threading.Event()
        # Keep the worker alive until the pool picks it up.
        self.setAutoDelete(True)

    def cancel(self) -> None:
        """Request cancellation (checked before each file starts)."""
        self._cancelled.set()

    def _scan_one(self, path: str) -> ScanResult | None:
        """Scan a single file on one of the worker threads."""
        if self._cancelled.is_set():
            return None  # queued but not started yet — skip quietly
        name = Path(path).name
        self.signals.status.emit(pick(f"Analysiere: {name}", f"Scanning: {name}", f"Taranıyor: {name}"))
        return self.dispatcher.scan_path(path)

    def run(self) -> None:  # executed on a pool thread
        total = len(self.paths)
        if total == 0:
            self.signals.finished.emit(False)
            return
        if self._cancelled.is_set():
            self.signals.status.emit(t("state.cancelled"))
            self.signals.finished.emit(True)
            return

        workers = max(1, min(config.MAX_SCAN_WORKERS, total))
        try:
            with ThreadPoolExecutor(
                max_workers=workers, thread_name_prefix="malaz-scan"
            ) as pool:
                futures = [pool.submit(self._scan_one, path) for path in self.paths]
                for index, future in enumerate(futures, start=1):
                    try:
                        result: ScanResult | None = future.result()
                    except Exception as exc:  # defensive — never crash the pool thread
                        failed = ScanResult(
                            path=self.paths[index - 1],
                            error=f"{type(exc).__name__}: Worker-Scanfehler",
                            indicators=[
                                Indicator(
                                    rule_id="CORE_ERROR",
                                    title="Scan-Worker konnte die Datei nicht prüfen",
                                    detail=(
                                        "Der Dispatcher-Scan ist unerwartet fehlgeschlagen; "
                                        "die Datei wurde nicht vollständig analysiert."
                                    ),
                                    severity=Severity.MEDIUM,
                                    category=CAT_STRUCTURE,
                                    weight=25,
                                    source="worker",
                                )
                            ],
                        )
                        # Same finalizer as Dispatcher._finalize_score: without
                        # it the failed result kept the dataclass defaults
                        # (score 0 / GREEN) even though its CORE_ERROR
                        # indicator weighs 25 — the GUI showed an unscanned
                        # file as clean (BUG-049).
                        breakdown = compute_score(failed.all_indicators())
                        failed.score = breakdown.score
                        failed.risk_level = breakdown.risk_level
                        failed.anchored = breakdown.anchored
                        failed.av_discount = breakdown.discount
                        self.signals.error.emit(
                            f"{Path(self.paths[index - 1]).name}: "
                            f"{type(exc).__name__}: Worker-Scanfehler"
                        )
                        self.signals.result.emit(failed)
                        # Progress counts PROCESSED files (success or error),
                        # so the bar always reaches 100 %.
                        self.signals.progress.emit(index, total)
                        continue
                    if result is None:
                        continue  # cancelled before this file started
                    # Progress counts COMPLETED files, emitted in input order.
                    self.signals.progress.emit(index, total)
                    self.signals.result.emit(result)
        finally:
            if self._cancelled.is_set():
                self.signals.status.emit(t("state.cancelled"))
            self.signals.finished.emit(self._cancelled.is_set())
