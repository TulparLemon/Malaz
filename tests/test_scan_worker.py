"""Tests for the Qt scan worker (workers/scan_worker.py).

The worker is executed synchronously in the test thread (QRunnable.run called
directly); with same-thread connections the Qt signals fire synchronously, so
no event loop or QApplication is required.
"""

import os
import tempfile
from pathlib import Path

from malaz.analysis.clamav import ClamAVScanner
from malaz.analysis.windows_av import WindowsDefenderScanner
from malaz.core.dispatcher import Dispatcher
from malaz.models import RiskLevel
from malaz.workers.scan_worker import ScanWorker


def _worker(paths: list[str]) -> ScanWorker:
    """A ScanWorker with the real AV engines OFF.

    These tests cover the WORKER's mechanics (progress, cancel, error
    reporting), not detection. ``ScanWorker`` defaults to ``Dispatcher()``,
    which probes Defender and ClamAV — measured 21 s for four tiny files, and
    machine-dependent: with a running clamd it is fast, without it every scan
    pays the full signature-database load. Same isolation as the corpus
    fixtures, for the same reason.
    """
    return ScanWorker(
        paths,
        dispatcher=Dispatcher(
            av_scanner=WindowsDefenderScanner(enabled=False),
            clam_scanner=ClamAVScanner(enabled=False),
        ),
    )


def _make_files(*names: str) -> list[str]:
    paths = []
    for name in names:
        fd, path = tempfile.mkstemp(suffix=name)
        with os.fdopen(fd, "wb") as fh:
            fh.write(b"hello world")
        paths.append(path)
    return paths


def _collect(worker: ScanWorker):
    results, errors, statuses, progress, finished = [], [], [], [], []

    def on_result(r):
        results.append(r)

    def on_error(m):
        errors.append(m)

    def on_status(m):
        statuses.append(m)

    def on_progress(cur, total):
        progress.append((cur, total))

    def on_finished():
        finished.append(True)

    worker.signals.result.connect(on_result)
    worker.signals.error.connect(on_error)
    worker.signals.status.connect(on_status)
    worker.signals.progress.connect(on_progress)
    worker.signals.finished.connect(on_finished)
    worker.run()  # synchronous in this thread
    return results, errors, statuses, progress, finished


def test_worker_scans_all_files():
    paths = _make_files("a.txt", "b.txt")
    try:
        worker = _worker(paths)
        results, errors, _, progress, finished = _collect(worker)
        assert len(results) == 2
        assert all(r.error is None for r in results)
        assert errors == []
        assert progress == [(1, 2), (2, 2)]
        assert finished == [True]
    finally:
        for p in paths:
            os.unlink(p)


def test_worker_reports_missing_file_as_error():
    # The dispatcher is defensive: a missing file becomes a ScanResult with
    # error set (no exception escapes to the worker).
    worker = _worker([str(Path(tempfile.gettempdir()) / "gibt_es_nicht.bin")])
    results, errors, _, _, finished = _collect(worker)
    assert len(results) == 1
    assert results[0].error is not None
    assert errors == []
    assert finished == [True]


def test_worker_cancel_stops_before_scan():
    paths = _make_files("a.txt", "b.txt", "c.txt")
    try:
        worker = _worker(paths)
        worker.cancel()
        results, errors, statuses, _, finished = _collect(worker)
        assert results == []
        assert errors == []
        assert any("Abgebrochen" in s for s in statuses)
        assert finished == [True]
    finally:
        for p in paths:
            os.unlink(p)


def test_worker_dispatcher_exception_is_scored_yellow(monkeypatch):
    # BUG-049: the failed result carried CORE_ERROR/25 but was emitted with
    # the ScanResult defaults score=0/risk=GREEN — an unanalysed file looked
    # clean in cell, counters, CSV and report.
    paths = _make_files("a.txt")

    def boom(self, _path):
        raise RuntimeError("simulierter Dispatcher-Crash")

    import malaz.workers.scan_worker as module

    monkeypatch.setattr(module.Dispatcher, "scan_path", boom)
    try:
        results, _, _, _, _ = _collect(_worker(paths))
        assert len(results) == 1
        assert results[0].score == 25
        assert results[0].risk_level == RiskLevel.YELLOW
        assert results[0].risk_level != RiskLevel.GREEN
    finally:
        os.unlink(paths[0])


def test_worker_dispatcher_exception_becomes_error(monkeypatch):
    paths = _make_files("a.txt")

    def boom(self, _path):
        raise RuntimeError("simulierter Dispatcher-Crash")

    import malaz.workers.scan_worker as module

    monkeypatch.setattr(module.Dispatcher, "scan_path", boom)
    try:
        worker = _worker(paths)
        results, errors, _, _, finished = _collect(worker)
        assert len(results) == 1
        assert results[0].error is not None
        assert "CORE_ERROR" in {i.rule_id for i in results[0].indicators}
        assert len(errors) == 1
        assert "simulierter Dispatcher-Crash" not in errors[0]
        assert finished == [True]
    finally:
        os.unlink(paths[0])
