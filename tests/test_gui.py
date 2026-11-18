"""GUI tests with pytest-qt (forced offscreen platform).

Runs the real MainWindow against a disabled-AV dispatcher; the scan worker
executes on the QThreadPool and the tests wait for the finished signal.
"""

import os
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Force the offscreen Qt platform BEFORE any PySide6 import so the tests run
# headless (CI, service sessions) and never open windows.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import tempfile

import pytest

pytest.importorskip("PySide6")

from malaz.analysis.clamav import ClamAVScanner
from malaz.analysis.windows_av import WindowsDefenderScanner
from malaz.core.dispatcher import Dispatcher
from malaz.gui.main_window import MainWindow
from malaz.models import Indicator, RiskLevel, ScanResult, Severity
from malaz.workers.scan_worker import ScanWorker


def _make_file(suffix: str, data: bytes = b"hello world") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return path


def test_window_starts_ready(window):
    assert window.table.pending_paths() == []
    assert window.table.topLevelItemCount() == 0
    assert not window.btn_report.isEnabled()


def test_add_paths_fills_queue(window, qtbot):
    path = _make_file(".txt")
    try:
        window.add_paths([path])
        assert window.table.topLevelItemCount() == 1
        assert window.table.pending_paths() == [path]
        assert window.table.topLevelItem(0).text(0) == os.path.basename(path)
    finally:
        os.unlink(path)


def test_add_paths_deduplicates(window):
    path = _make_file(".txt")
    try:
        window.add_paths([path, path])
        assert window.table.topLevelItemCount() == 1
        assert window.table.pending_paths() == [path]
    finally:
        os.unlink(path)


def test_add_paths_haelt_das_batch_limit_fuer_die_ganze_queue(window, monkeypatch):
    """BUG-052: Dialog und wiederholte Drops umgingen MAX_BATCH_FILES.

    ``expand_scan_paths`` deckelt nur EINE Auswahl. Der Dialog reichte seine
    Liste ungeprueft weiter, und ein zweiter Drop zaehlte wieder ab null —
    die Warteschlange wuchs ueber das Limit.
    """
    from malaz import config

    monkeypatch.setattr(config, "MAX_BATCH_FILES", 2)
    paths = [_make_file(".txt") for _ in range(3)]
    try:
        # Weg 1: wiederholtes Hinzufuegen (wie ein zweiter Drop).
        window.add_paths([paths[0]])
        from malaz.gui import main_window as mw

        # Weg 2: der Datei-Dialog reicht alle drei weiter.
        monkeypatch.setattr(
            mw.QFileDialog, "getOpenFileNames", lambda *a, **k: (paths, "")
        )
        window._on_add_files()
        assert window.table.topLevelItemCount() == 2, "das Limit gilt nicht fuer die Queue"
        assert window._batch_truncated, "der Abbruch wird nirgends gemeldet"

        # Auch ein weiterer Aufruf kann das Limit nicht ueberschreiten.
        window.add_paths([paths[2]])
        assert window.table.topLevelItemCount() == 2
    finally:
        for path in paths:
            os.unlink(path)


def test_scan_populates_table_and_enables_report(window, qtbot):
    path = _make_file(".txt")
    try:
        window.add_paths([path])
        window._on_scan()
        qtbot.waitUntil(lambda: window._worker is None, timeout=60_000)
        assert window.table.topLevelItemCount() == 1
        # File name in the first column.
        assert window.table.topLevelItem(0).text(0) == os.path.basename(path)
        assert window.btn_report.isEnabled()
        assert window._results[0].risk_level == RiskLevel.GREEN
    finally:
        os.unlink(path)


def test_scan_red_file_shows_risk(window, qtbot):
    path = _make_file(".pdf", b"%PDF-1.7\n/Launch\n%%EOF")
    try:
        window.add_paths([path])
        window._on_scan()
        qtbot.waitUntil(lambda: window._worker is None, timeout=60_000)
        row = 0
        # Der Zusatz "(unvollständig)" steht bewusst im Text: in dieser
        # Umgebung fehlt eine AV-Stufe, und ein nacktes "Gefährlich" ohne
        # Hinweis auf die Luecke waere die halbe Wahrheit. Geprueft wird
        # deshalb das URTEIL, nicht die ganze Zeile.
        from malaz.gui.file_tree import STATE_ROLE

        item = window.table.topLevelItem(row)
        assert item.data(0, STATE_ROLE) == "bad"
        window.table.setCurrentItem(item)
        assert window.verdict.headline.text().startswith("Gefährlich")
        assert window._results[0].risk_level == RiskLevel.RED
    finally:
        os.unlink(path)


def test_clear_resets_state(window):
    path = _make_file(".txt")
    try:
        window.add_paths([path])
        window._on_clear()
        assert window.table.pending_paths() == []
        assert window.table.topLevelItemCount() == 0
        assert not window.btn_report.isEnabled()
    finally:
        os.unlink(path)


def test_sender_column_hidden_until_a_mail_appears(window):
    """E-Mail-Tab bleibt fuer Nicht-Mails versteckt und erscheint erst bei Mails."""
    from malaz.models import RiskLevel, ScanResult

    assert window.detail_view._btn_tab_mail.isHidden(), "initial versteckt"

    mail = ScanResult(
        path="a.eml",
        detected_type="eml",
        mail_security={"spf": "pass", "dkim": "pass", "dmarc": "pass", "sender": "ok"},
    )
    mail.risk_level = RiskLevel.GREEN
    mail.score = 0
    window._on_result(mail)
    window.table.setCurrentItem(window.table.topLevelItem(0))
    assert not window.detail_view._btn_tab_mail.isHidden(), "bei Mail sichtbar"

    window._reset_result_view()
    assert window.detail_view._btn_tab_mail.isHidden(), "nach Reset wieder versteckt"


def test_install_all_runs_every_feed_without_a_dialog(monkeypatch):
    """'Alle installieren' muss alle Quellen abarbeiten, ohne zu blockieren.

    Der Sammellauf zeigte nach jedem Import einen modalen Dialog; im stillen
    Lauf wartet der auf einen Klick, den niemand gibt (gemessen: 600 s beim
    ersten Feed). still=True unterdrueckt ihn.
    """
    import malaz.gui.feeds_dialog as fdmod
    from malaz.core.feed_import import ImportResult
    from malaz.core.feeds import FeedError

    aufrufe = []

    def fake(feed, ziel_dir):
        aufrufe.append(feed.title)
        if len(aufrufe) == 2:
            raise FeedError("Netz weg")
        ziel = Path(ziel_dir) / f"{feed.key}.txt"
        ziel.parent.mkdir(parents=True, exist_ok=True)
        ziel.write_text("x", encoding="utf-8")
        return ziel, ImportResult("Test", 7, ziel)

    monkeypatch.setattr(fdmod, "refresh_feed", fake)
    dialog = fdmod.FeedsDialog()
    try:
        dialog._laden_alle()
        assert len(aufrufe) == len(dialog._rows), aufrufe
        assert dialog.btn_alle.isEnabled(), "Knopf muss wieder bedienbar sein"
        assert "1 fehlgeschlagen" in dialog.btn_alle.text()
    finally:
        dialog.deleteLater()


def test_scan_twice_rejected_while_running(window, qtbot, monkeypatch):
    path = _make_file(".txt")
    messages = []

    def fake_info(parent, title, text):
        messages.append(text)

    monkeypatch.setattr(
        "malaz.gui.main_window.QMessageBox.information", fake_info
    )
    try:
        window.add_paths([path])
        window._on_scan()
        # The second invocation is guarded while the worker runs; the queue
        # remains a single worker until the scan finishes.
        assert window._worker is not None
        window._on_scan()  # guarded -> info box (mocked), no second worker
        assert messages and "läuft bereits" in messages[0]
        qtbot.waitUntil(lambda: window._worker is None, timeout=60_000)
        assert window.table.topLevelItemCount() == 1
    finally:
        os.unlink(path)


def test_scan_without_files_shows_message(window, qtbot, monkeypatch):
    messages = []

    def fake_info(parent, title, text):
        messages.append((title, text))

    monkeypatch.setattr(
        "malaz.gui.main_window.QMessageBox.information", fake_info
    )
    window._on_scan()
    assert messages and "Keine Dateien" in messages[0][0]
    assert window._worker is None


def test_result_filter_hides_rows(window):
    from malaz.models import RiskLevel, ScanResult

    def _mk(name: str, level: RiskLevel) -> ScanResult:
        r = ScanResult(path=name, size=1, depth=0)
        r.risk_level = level
        r.detected_type = "text"
        r.duration_ms = 1
        return r

    for name, level in (
        ("a.txt", RiskLevel.GREEN),
        ("b.txt", RiskLevel.YELLOW),
        ("c.txt", RiskLevel.RED),
    ):
        result = _mk(name, level)
        window._on_result(result)

    assert window.table.topLevelItemCount() == 3
    assert not any(window.table.topLevelItem(i).isHidden() for i in range(3))

    # "Nur Verdächtige (Gelb)" -> nur Gelb bleibt.
    window._set_status_filter("warn")
    hidden = [window.table.topLevelItem(i).isHidden() for i in range(3)]
    assert hidden == [True, False, True]

    # "Nur Gefährliche (Rot)" -> nur Rot bleibt.
    window._set_status_filter("bad")
    hidden = [window.table.topLevelItem(i).isHidden() for i in range(3)]
    assert hidden == [True, True, False]

    # Zurück auf "Alle" -> alles sichtbar.
    window._set_status_filter("all")
    assert not any(window.table.topLevelItem(i).isHidden() for i in range(3))


def test_initial_paths_queue_and_autostart(qtbot, monkeypatch, tmp_path):
    # Context-menu scenario: "Malaz.exe DATEI" must open the GUI with the
    # file queued and the scan auto-started once the event loop is up.
    disabled = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    monkeypatch.setattr("malaz.gui.main_window.Dispatcher", lambda: disabled)
    sample = tmp_path / "brief.txt"
    sample.write_text("ganz normale Datei")

    win = MainWindow(initial_paths=[str(sample)])
    qtbot.addWidget(win)
    qtbot.waitUntil(lambda: len(win._results) >= 1 and win._worker is None, timeout=30_000)
    assert win.table.topLevelItemCount() == 1


def test_cancel_button_requests_cancellation(window, qtbot):
    paths = [_make_file(".txt"), _make_file(".txt")]
    try:
        window.add_paths(paths)
        window._on_scan()
        assert window._worker is not None
        assert window.btn_cancel.isEnabled()
        window._on_cancel()
        assert window._worker._cancelled.is_set()
        assert not window.btn_cancel.isEnabled()
        qtbot.waitUntil(lambda: window._worker is None, timeout=60_000)
    finally:
        for p in paths:
            os.unlink(p)


def test_close_event_cancels_running_worker(qtbot, monkeypatch):
    # Closing the window while a scan runs must request cancellation and
    # drain the pool — not hang or lose the request.
    from malaz import procio

    disabled = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    monkeypatch.setattr("malaz.gui.main_window.Dispatcher", lambda: disabled)
    win = MainWindow()
    qtbot.addWidget(win)
    worker = ScanWorker([_make_file(".txt")])  # nie gestartet: nur Zustand
    win._worker = worker
    try:
        win.close()
        assert worker._cancelled.is_set()
        assert procio.hard_shutdown_requested() is False  # aufgeräumt, kein Leak
    finally:
        procio.clear_hard_shutdown()


def test_export_report_writes_pdf_async(window, qtbot, monkeypatch, tmp_path):
    from malaz.models import RiskLevel, ScanResult

    result = ScanResult(path="a.txt", size=1, depth=0)
    result.risk_level = RiskLevel.GREEN
    result.detected_type = "text"
    result.duration_ms = 1
    window._on_result(result)

    out = tmp_path / "bericht.pdf"
    monkeypatch.setattr(
        "malaz.gui.main_window.QFileDialog.getSaveFileName",
        lambda *a, **k: (str(out), "PDF-Report (*.pdf)"),
    )
    window._on_export_report()

    # QPdfWriter creates the file at painter.begin() (0 bytes) and flushes the
    # content only at end(). Waiting for mere existence races the writer — wait
    # for the %PDF magic instead (implies fully written). While the writer is
    # still active the file is also LOCKED on Windows, so the probe must treat
    # a read error as "not ready yet" rather than letting it escape.
    def _written() -> bool:
        try:
            return out.exists() and out.read_bytes().startswith(b"%PDF-")
        except OSError:  # PermissionError while QPdfWriter holds the handle
            return False

    qtbot.waitUntil(_written, timeout=30_000)
    assert out.read_bytes().startswith(b"%PDF-")
    qtbot.waitUntil(lambda: window.btn_report.isEnabled(), timeout=10_000)


def test_export_report_failed_reenables_button(window, qtbot, monkeypatch, tmp_path):
    # Fehlgeschlagener Export: Button kehrt zurueck, Fehlermeldung kommt.
    from malaz.models import RiskLevel, ScanResult

    result = ScanResult(path="a.txt", size=1, depth=0)
    result.risk_level = RiskLevel.GREEN
    result.detected_type = "text"
    window._on_result(result)

    import malaz.gui.main_window as mw

    def failing_run(self):
        with suppress(RuntimeError):
            self.signals.failed.emit("OSError: Simulation")

    monkeypatch.setattr(
        "malaz.gui.main_window.QFileDialog.getSaveFileName",
        lambda *a, **k: (str(tmp_path / "x.pdf"), "PDF-Report (*.pdf)"),
    )
    monkeypatch.setattr(mw._ExportJob, "run", failing_run)
    # Der Fehlerpfad oeffnet einen modalen QMessageBox, der die Event-Loop
    # blockieren wuerde — im Test aufzeichnen statt anzeigen.
    boxes = []
    monkeypatch.setattr(
        "malaz.gui.main_window.QMessageBox.critical", lambda *a, **k: boxes.append(a)
    )
    window._on_export_report()
    qtbot.waitUntil(lambda: window.btn_report.isEnabled(), timeout=10_000)
    assert "fehlgeschlagen" in window.statusBar().currentMessage()
    assert boxes, "Fehlermeldung muss angezeigt werden"


def test_about_dialog_opens(window, qtbot, monkeypatch):
    boxes = []
    monkeypatch.setattr(
        "malaz.gui.main_window.QMessageBox.exec",
        lambda self: boxes.append(1) or 0,
    )
    window._on_about()
    assert boxes == [1]


def test_branding_header_logo_visible(window):
    """Das Logo muss auch IM Fenster sichtbar sein, nicht nur als Fenster-Icon."""
    assert not window.logo_label.pixmap().isNull()


def test_branding_app_icon_not_null(qapp):
    from malaz.branding import app_icon

    icon = app_icon()
    assert not icon.isNull()
    assert icon.availableSizes(), "ICO muss mehrere Groessen liefern"


def test_branding_frozen_path(tmp_path, monkeypatch):
    """Frozen: assets werden NEBEN der Exe gesucht (QIcon(exe) waere null)."""
    import sys as _sys

    from malaz import branding

    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "malaz.ico").write_bytes(
        (Path(__file__).resolve().parents[1] / "assets" / "malaz.ico").read_bytes()
    )
    monkeypatch.setattr(_sys, "frozen", True, raising=False)
    monkeypatch.setattr(_sys, "executable", str(tmp_path / "Malaz.exe"))
    assert branding.asset_dir() == tmp_path / "assets"
    assert not branding.app_icon().isNull()


def test_menu_actions_exist(window):
    menubar = window.menuBar()
    actions = [a.text() for a in menubar.actions()]
    assert any("Datei" in a for a in actions)
    assert any("Hilfe" in a for a in actions)


def test_drop_list_delete_key_removes_entry(window, qtbot):
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest

    path = _make_file(".txt")
    try:
        window.add_paths([path])
        assert window.table.topLevelItemCount() == 1
        window.table.setCurrentItem(window.table.topLevelItem(0))
        QTest.keyClick(window.table, Qt.Key.Key_Delete)
        assert window.table.topLevelItemCount() == 0
        assert window.table.pending_paths() == []
    finally:
        os.unlink(path)


def test_clear_resets_everything(window):
    path = _make_file(".txt")
    try:
        window.add_paths([path])
        window._on_clear()
        assert window.table.pending_paths() == []
        assert window.table.topLevelItemCount() == 0
        assert window._results == []
        assert window.progress.value() == 0
        assert not window.btn_report.isEnabled()
    finally:
        os.unlink(path)


def test_app_icon_loads(qapp):
    """assets/malaz.ico muss als Fenster-Icon ladbar sein (Tulpar-Logo).

    QIcon braucht eine laufende QApplication — ohne qapp-Fixture crasht
    das Laden auf Windows nativ und reisst die ganze Suite mit."""
    from PySide6.QtGui import QIcon

    from malaz.gui.main_window import _app_icon

    icon = _app_icon()
    assert isinstance(icon, QIcon)
    assert not icon.isNull(), "Icon-Datei fehlt oder ist leer"


# -- Warteschlange: Eintraege entfernen -------------------------------------- #

def test_queue_context_menu_offers_removal(window):
    """Rechtsklick muss 'entfernen' anbieten, wenn etwas markiert ist."""
    path = _make_file(".txt")
    try:
        window.add_paths([path])
        window.table.clearSelection()
        window.table.topLevelItem(0).setSelected(True)
        labels = [a.text() for a in window.table._build_context_menu().actions()]
        assert any("entfernen" in x.lower() for x in labels), labels
        assert any("leeren" in x.lower() for x in labels), labels
    finally:
        os.unlink(path)


def test_queue_context_menu_disabled_without_selection(window):
    """Ohne Auswahl darf 'entfernen' nichts anbieten (nicht ins Leere greifen)."""
    path = _make_file(".txt")
    try:
        window.add_paths([path])
        window.table.clearSelection()
        menu = window.table._build_context_menu()
        remove = next(a for a in menu.actions() if "entfernen" in a.text().lower())
        assert not remove.isEnabled()
        clear = next(a for a in menu.actions() if "leeren" in a.text().lower())
        assert clear.isEnabled()
    finally:
        os.unlink(path)


def test_queue_removes_only_selected_entries(window):
    """Nur die markierten Eintraege verschwinden - nicht die Nachbarn."""
    paths = [_make_file(".txt") for _ in range(4)]
    try:
        window.add_paths(paths)
        window.table.clearSelection()
        window.table.topLevelItem(0).setSelected(True)
        window.table.topLevelItem(2).setSelected(True)
        assert window.table.remove_selected_pending() == 2
        assert window.table.pending_paths() == [paths[1], paths[3]]
    finally:
        for p in paths:
            os.unlink(p)


def test_queue_removal_keeps_results_intact(window):
    """Entfernen eines wartenden Eintrags laesst bereits gescannte Ergebnisse unberuehrt."""
    path = _make_file(".txt")
    try:
        window.add_paths([path])
        window._results.append(object())
        window.table.clearSelection()
        window.table.topLevelItem(0).setSelected(True)
        window.table.remove_selected_pending()
        assert window._results, "Ergebnisse duerfen nicht mitgeloescht werden"
    finally:
        os.unlink(path)


def test_queue_remove_restores_hint_when_empty(window):
    """Nach dem letzten Eintrag ist die Warteschlange wieder leer."""
    path = _make_file(".txt")
    try:
        window.add_paths([path])
        window.table.clearSelection()
        window.table.topLevelItem(0).setSelected(True)
        window.table.remove_selected_pending()
        assert window.table.topLevelItemCount() == 0
        assert window.btn_scan.isHidden()
    finally:
        os.unlink(path)


def test_queue_remove_versteckt_den_mail_knopf(window):
    """Nach dem Entfernen einer Mail bleibt der Mail-Tab verborgen."""
    path = _make_file(".eml")
    try:
        window.add_paths([path])
        window.table.clearSelection()
        window.table.topLevelItem(0).setSelected(True)
        window.table.remove_selected_pending()
        assert window.table.topLevelItemCount() == 0
        assert window.detail_view._btn_tab_mail.isHidden()
    finally:
        os.unlink(path)


def test_queue_context_menu_clear_uses_window_reset(window):
    """'Liste leeren' im Kontextmenue muss den vollen Reset ausloesen."""
    path = _make_file(".txt")
    try:
        window.add_paths([path])
        window._results.append(object())
        menu = window.table._build_context_menu()
        clear = next(a for a in menu.actions() if "leeren" in a.text().lower())
        clear.trigger()
        assert window.table.topLevelItemCount() == 0
        assert window._results == []
    finally:
        os.unlink(path)


def test_queue_editing_locked_while_scanning(window):
    """Waehrend eines Scans darf die Warteschlange nicht veraendert werden."""
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest

    paths = [_make_file(".txt") for _ in range(2)]
    try:
        window.add_paths(paths)
        window.table.clearSelection()
        window.table.topLevelItem(0).setSelected(True)

        window._worker = object()
        try:
            window._set_scanning(True)
            assert window.btn_clear.isHidden()
            menu = window.table._build_context_menu()
            assert not any(a.isEnabled() for a in menu.actions() if a.text())

            QTest.keyClick(window.table, Qt.Key.Key_Delete)
            assert window.table.topLevelItemCount() == 2
        finally:
            window._worker = None
            window._set_scanning(False)

        menu = window.table._build_context_menu()
        assert any(a.isEnabled() and "entfernen" in a.text().lower() for a in menu.actions())
    finally:
        for p in paths:
            os.unlink(p)


def test_detail_panel_shows_mail_preview_of_nested_eml(window, qtbot, tmp_path):
    """Selecting the ZIP row must reveal the mail inside it.

    End-to-end through the real window: the mail preview used to be appended to
    the top-level row only, so a .eml in a container showed no content at all.
    """
    import zipfile

    mail = (
        b"From: a@b.invalid\nTo: c@d.invalid\nSubject: ZIP-Mail Betreff\n"
        b"MIME-Version: 1.0\nContent-Type: text/plain\n\nText im Archiv\n"
    )
    archive = tmp_path / "archiv.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("mail.eml", mail)

    window.add_paths([str(archive)])
    window._on_scan()
    qtbot.waitUntil(lambda: window._worker is None, timeout=60_000)

    from PySide6.QtWidgets import QLabel

    zip_item = window.table.topLevelItem(0)
    assert zip_item.childCount() == 1
    window.table.setCurrentItem(zip_item.child(0))
    assert not window.detail_view._btn_tab_mail.isHidden()
    labels = " ".join(lbl.text() for lbl in window.mail_panel.findChildren(QLabel))
    assert "Text im Archiv" in labels, labels


# ---- Bidi-Maskierung an den Qt-Senken (Audit Lauf 3) ------------------------ #

# Ein Dateiname mit U+202E wird von Qt (Bidi-Algorithmus) als "Rechnungexe.pdf"
# GEZEICHNET, obwohl "Rechnung\u202efdp.exe" gespeichert ist.
_BIDI_NAME = "Rechnung\u202efdp.exe"


def test_queue_entry_masks_bidi_name_and_still_scans_it(window, qtbot, tmp_path):
    """Regression (malaz/gui/main_window/table-and-queue-name-not-masked).

    Die Warteschlange war eine unmaskierte Anzeige-Senke: der rohe U+202E liess
    die Datei als "Rechnungexe.pdf" erscheinen. Geprueft wird der Text, den das
    Widget tatsaechlich zeichnet — UND dass der Scan weiterhin den echten Pfad
    bekommt (die Maskierung darf die Datei nicht umbenennen).
    """
    real = tmp_path / _BIDI_NAME
    real.write_bytes(b"hello world")

    window.add_paths([str(real), str(real)])  # zweimal: Dedup bleibt Pfadbasiert
    assert window.table.topLevelItemCount() == 1

    shown = window.table.topLevelItem(0).text(0)
    assert "\u202e" not in shown, "rohes Steuerzeichen in der Warteschlange"
    assert "\\u202e" in shown, "die Maskierung fehlt (Anzeige bleibt Taeuschung)"

    window._on_scan()
    qtbot.waitUntil(lambda: window._worker is None, timeout=60_000)
    assert window._results, "die maskierte Anzeige hat den Scan verhindert"
    # ScanResult.path traegt den Basisnamen; entscheidend ist, dass die Datei
    # unter ihrem ECHTEN Namen geoeffnet wurde: der rohe U+202E steckt im Pfad
    # (nicht das Anzeige-Escape) und die Bytes wurden gelesen. Ein maskierter
    # Pfad existiert nicht und endete mit Fehler.
    result = window._results[0]
    assert result.path == real.name
    assert "\u202e" in result.path, "gescannt wurde das Anzeige-Escape"
    assert result.error is None
    assert result.size == len(b"hello world")


def test_table_cell_masks_bidi_name(window):
    """Regression: die Ergebnis-Tabelle zeigte den rohen Namen in Spalte 0 —
    genau der Name, an dem der Nutzer das Urteil abliest."""
    from malaz.models import ScanResult

    result = ScanResult(path=f"C:/proben/{_BIDI_NAME}", size=1, score=0)
    window._on_result(result)

    shown = window.table.topLevelItem(0).text(0)
    assert "\u202e" not in shown, "rohes Steuerzeichen in der Tabelle"
    assert "\\u202e" in shown, "die Maskierung fehlt (Anzeige bleibt Taeuschung)"
    # Der harmlose Rest des Namens bleibt unveraendert lesbar.
    assert shown.startswith("Rechnung") and shown.endswith("fdp.exe")


def test_detail_panel_shows_av_discount_where_the_score_stands(window):
    """Ein Score unter der Summe seiner Befunde braucht seinen Grund im Panel."""
    from malaz.models import ScanResult

    result = ScanResult(path="C:/proben/rechnung.pdf", size=1, score=47, av_discount=8)
    window._on_result(result)
    window.table.setCurrentItem(window.table.topLevelItem(0))
    # Der Score steht auf der Karte, der Grund fuer die Herabsetzung in deren
    # Tooltip UND im Technik-Reiter. Beides muss ihn nennen — sonst sieht
    # "47/100" bei Befunden, die mehr hergeben, nach einem Fehler aus.
    from PySide6.QtWidgets import QLabel

    assert "47/100" in window.verdict.score.text()
    assert "AV-Entlastung" in window.verdict.score.toolTip()
    technik = " ".join(lbl.text() for lbl in window.detail_view.findChildren(QLabel))
    assert "47/100" in technik
    assert "8 Punkte" in technik and "AV-Entlastung" in technik, technik


def test_status_bar_masks_bidi_names(window):
    """Regression (Runde 4): die Statuszeile war eine unmaskierte Senke.

    ``ScanWorker`` sendet "Analysiere: <roher Name>", ``_on_status``/
    ``_on_error`` gaben den Text ungefiltert an ``statusBar().showMessage``
    weiter. Gemessen mit einem Namen aus U+202E: die Statuszeile zeigte das
    rohe Steuerzeichen und Qt zeichnete "Rechnungexe.pdf" — dieselbe Taeuschung,
    die Warteschlange, Tabelle und Detailpanel laengst maskieren. Die Maskierung
    sitzt jetzt im gemeinsamen Funnel (idempotent, also auch fuer bereits
    maskierte Texte unschaedlich).
    """
    window._on_status(f"Analysiere: {_BIDI_NAME}")
    shown = window.statusBar().currentMessage()
    assert "\u202e" not in shown, "rohes Steuerzeichen in der Statuszeile"
    assert "\\u202e" in shown, "die Maskierung fehlt (Anzeige bleibt Taeuschung)"
    assert shown.startswith("Analysiere: Rechnung") and shown.endswith("fdp.exe")

    window._on_error(f"{_BIDI_NAME}: kaputt")
    shown = window.statusBar().currentMessage()
    assert "\u202e" not in shown, "rohes Steuerzeichen im Fehlertext"
    assert "\\u202e" in shown, "die Maskierung fehlt (Anzeige bleibt Taeuschung)"
    assert shown.startswith("Fehler: Rechnung")

    # Gegenrichtung: harmlose Statuszeilen bleiben unveraendert.
    window._on_status("Scan läuft …")
    assert window.statusBar().currentMessage() == "Scan läuft …"


def test_window_accepts_injected_dispatcher(qtbot):
    """Der Dispatcher muss injizierbar sein — sonst baut jedes Fenster einen
    echten, der Defender und ClamAV per Subprozess abklopft.

    Gemessen: MainWindow() kostete 2,2 s pro Instanz, davon ~2,1 s in
    `ClamAVScanner._clamd_reachable()`. tests/test_gui.py zahlte das 26-mal
    und verwarf den Dispatcher danach. Ein injizierter, engine-freier
    Dispatcher muss unveraendert uebernommen werden (nicht ersetzt).
    """
    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher

    supplied = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    win = MainWindow(dispatcher=supplied)
    qtbot.addWidget(win)
    try:
        assert win.dispatcher is supplied, "injizierter Dispatcher wurde ersetzt"
        assert win.dispatcher.clam_scanner.available is False
    finally:
        win.close()


def test_verdict_card_shows_mark_word_and_score(qtbot):
    """Die Karte traegt Zeichen, Wort und Score — nie nur eine Farbe.

    Rund 8 % der Maenner sind farbenblind; die Einstufung muss auch in
    Graustufen erkennbar sein. Deshalb steht neben der Farbe immer ein Zeichen
    UND ein Wort.
    """
    from malaz.gui.verdict_card import RISK_MARK, VerdictCard
    from malaz.models import RiskLevel

    card = VerdictCard()
    qtbot.addWidget(card)

    for level in (RiskLevel.GREEN, RiskLevel.YELLOW, RiskLevel.RED):
        result = ScanResult(
            path="C:/proben/x.pdf", size=1, score=int(level) * 40, risk_level=level
        )
        card.show_result(result)
        assert card.headline.text().startswith(level.short), card.headline.text()
        assert card.mark.text() == RISK_MARK[level], "das Zeichen fehlt"
        assert card.advice.text(), "die Handlungszeile fehlt"
        assert f"{result.score}/100" in card.score.text()

    # Die drei Zeichen sind verschieden — sonst waere die Doppelkodierung
    # wertlos.
    assert len({RISK_MARK[lv] for lv in RiskLevel}) == 3


def test_verdict_card_clear_entfernt_den_score_tooltip(qtbot):
    """BUG-059: nach clear() erklaerte der Tooltip die VORIGE Datei.

    Der AV-Rabatt/Anker steht als Tooltip am Score. ``clear()`` leerte den
    Text, aber nicht den Tooltip — ueber dem leeren Feld stand weiter die
    Erklaerung der zuletzt gewaehlten Datei.
    """
    from malaz.gui.verdict_card import VerdictCard

    card = VerdictCard()
    qtbot.addWidget(card)
    card.show_result(
        ScanResult(
            path="C:/proben/rot.pdf",
            score=50,
            risk_level=RiskLevel.RED,
            av_discount=8,
            anchored=True,
        )
    )
    assert card.score.toolTip(), "Vorbedingung: der Tooltip ist gesetzt"

    card.clear()
    assert card.score.text() == ""
    assert card.score.toolTip() == "", "der Tooltip der alten Datei bleibt stehen"


def test_mail_tab_only_exists_for_mail(qtbot):
    """Der E-Mail-Reiter erscheint nur, wenn das Ergebnis eine Mail ist.

    Ein leerer Reiter bei einer PDF-Datei verspricht etwas, das die Datei
    nicht einloest — der Nutzer klickt ihn an und findet nichts.
    """
    window = MainWindow()
    qtbot.addWidget(window)

    pdf = ScanResult(path="C:/proben/x.pdf", size=1, detected_type="pdf")
    window._on_result(pdf)
    window.table.setCurrentItem(window.table.topLevelItem(0))
    assert window.detail_view._btn_tab_mail.isHidden(), "Mail-Tab ohne Mail sichtbar"

    mail = ScanResult(
        path="C:/proben/x.eml",
        size=1,
        detected_type="eml",
        mail_security={"spf": "pass", "dkim": "pass", "dmarc": "pass", "sender": "ok"},
    )
    window._on_result(mail)
    window.table.setCurrentItem(window.table.topLevelItem(1))
    assert not window.detail_view._btn_tab_mail.isHidden(), "Mail-Tab fehlt"

    window.table.setCurrentItem(window.table.topLevelItem(0))
    assert window.detail_view._btn_tab_mail.isHidden(), "Mail-Tab blieb stehen"


def test_mail_panel_masks_attacker_controlled_text(qtbot):
    """Das E-Mail-Panel darf getarnte Namen nicht unveraendert zeichnen.

    Ein Linkziel oder Anhangsname kann U+202E (RIGHT-TO-LEFT OVERRIDE)
    enthalten. Qt wendet den Bidi-Algorithmus auf QLabel-Text an: aus
    "rechnung<U+202E>gpj.exe" wird beim Zeichnen "rechnungexe.jpg" — der
    Nutzer liest eine harmlose Adresse fuer eine bosartige. Genau dagegen
    maskiert das Projekt an fuenf Stellen in main_window
    (_masked_widget_text, _format_detail, _format_technical, Statusleiste,
    Warteschlange); das Panel umging sie, weil es neu ist.
    """
    from PySide6.QtWidgets import QLabel

    from malaz.core.eml_analysis import LinkFacts
    from malaz.gui.mail_panel import MailPanel

    getarnt = "rechnung\u202egpj.exe"
    result = ScanResult(
        path="mail.eml",
        detected_type="eml",
        risk_level=RiskLevel.RED,
        score=80,
        mail_security={"spf": "fail", "dkim": "fail", "dmarc": "fail", "sender": "ok"},
        mail_links=[
            LinkFacts(
                url=f"http://boese.tld/{getarnt}",
                host=f"boese.tld/{getarnt}",
                scheme="http",
                mismatch=True,
            )
        ],
    )
    panel = MailPanel()
    qtbot.addWidget(panel)
    panel.show_result(result)

    texte = [w.text() for w in panel.findChildren(QLabel) if w.text()]
    offen = [t for t in texte if "\u202e" in t]
    assert not offen, (
        f"{len(offen)} Label(s) zeigen U+202E unmaskiert: {offen[:2]}"
    )
    # Die Gegenprobe: der Text ist noch DA, nur sichtbar gemacht. Entfernen
    # waere falsch — es wuerde genau den Trick verbergen, den die Analyse
    # meldet.
    assert any("u202e" in t or "\\u202e" in t for t in texte), (
        "der Steuerzeichen-Hinweis fehlt ganz"
    )


def test_mail_panel_clips_absurdly_long_values(qtbot):
    """Ein Linkziel kann beliebig lang sein — das Panel muss kuerzen.

    Gemessen: eine URL mit 300 000 Zeichen erzeugte ein Label mit 300 040
    Zeichen. Das Layout bricht, das Panel wird unbenutzbar. core/mail_view
    kuerzt aus genau diesem Grund seit jeher (_clip, mit dem Hinweis "ein
    stiller Schnitt verbirgt den Trick") — das neue Panel tat es nicht.
    """
    from PySide6.QtWidgets import QLabel

    from malaz.core.eml_analysis import LinkFacts
    from malaz.gui.mail_panel import MailPanel

    lang = "http://boese.tld/" + "a" * 300_000
    result = ScanResult(
        path="m.eml",
        detected_type="eml",
        risk_level=RiskLevel.RED,
        score=50,
        mail_security={"spf": "fail", "dkim": "fail", "dmarc": "fail", "sender": "ok"},
        mail_links=[LinkFacts(url=lang, host=lang, scheme="http", mismatch=True)],
    )
    panel = MailPanel()
    qtbot.addWidget(panel)
    panel.show_result(result)

    laengen = [len(w.text()) for w in panel.findChildren(QLabel)]
    assert laengen, "keine Labels"
    assert max(laengen) < 2000, (
        f"laengstes Label hat {max(laengen)} Zeichen — nicht gekuerzt"
    )
    # Gekuerzt heisst NICHT abgeschnitten: der Hinweis muss dastehen, sonst
    # verbirgt der Schnitt genau den Trick, den die Analyse meldet.
    assert any("gekuerzt" in w.text() or "…" in w.text() for w in panel.findChildren(QLabel))


def test_risk_mark_cannot_drift_between_panel_and_card(qtbot, monkeypatch):
    """Die Marken kommen aus theme.RISK_MARKS, nicht aus einem zweiten Literal."""
    from PySide6.QtWidgets import QLabel

    from malaz.gui import theme
    from malaz.gui.mail_panel import MailPanel

    monkeypatch.setitem(theme.RISK_MARKS, "red", "ZZ")
    result = ScanResult(
        path="m.eml",
        detected_type="eml",
        risk_level=RiskLevel.RED,
        score=50,
        mail_security={"spf": "fail", "dkim": "fail", "dmarc": "fail", "sender": "spoof"},
    )
    panel = MailPanel()
    qtbot.addWidget(panel)
    panel.show_result(result)
    texte = [w.text() for w in panel.findChildren(QLabel) if w.text()]
    assert any("ZZ" in text for text in texte), texte[:5]


def test_mail_panel_clips_long_attachment_names(qtbot):
    """Auch der Anhangsname braucht die Grenze — nicht nur Host und URL.

    Runde 2 des Audits: der Fix aus Runde 1 kuerzte Host und Linkziel, aber
    nicht den Anhangsnamen. Gemessen: ein 60 000-Zeichen-Name erzeugte ein
    Label mit 60 031 Zeichen. Dieselbe Fehlerklasse, an einer von drei Stellen
    behoben — genau das Muster, das der Skill als ergiebigste Heuristik nennt.
    """
    from PySide6.QtWidgets import QLabel

    from malaz.gui.mail_panel import MailPanel

    kind = ScanResult(
        path="x" * 60_000 + ".exe",
        detected_type="pe",
        depth=1,
        risk_level=RiskLevel.RED,
        score=90,
    )
    eltern = ScanResult(
        path="mail.eml",
        detected_type="eml",
        risk_level=RiskLevel.GREEN,
        score=0,
        mail_security={"spf": "pass", "dkim": "pass", "dmarc": "pass", "sender": "ok"},
    )
    eltern.children.append(kind)

    panel = MailPanel()
    qtbot.addWidget(panel)
    panel.show_result(eltern)

    laengen = [len(w.text()) for w in panel.findChildren(QLabel)]
    assert max(laengen) < 2000, f"laengstes Label hat {max(laengen)} Zeichen"
    assert any("gekürzt" in w.text() for w in panel.findChildren(QLabel)), (
        "der Hinweis fehlt — der Schnitt waere still"
    )


def test_mail_panel_inhalt_zeigt_nur_den_textteil(qtbot):
    """BUG-061: "Inhalt" wiederholte die Rohabschnitte Links und Anhänge.

    ``_body_only`` nahm alles ab "Textinhalt" bis zum Ende — und suchte
    ausserdem "Anhaenge" (ASCII), waehrend ``render_mail`` "Anhänge" schreibt.
    """
    from PySide6.QtWidgets import QLabel

    from malaz.gui.mail_panel import MailPanel

    preview = (
        "Kopfzeilen\n"
        "  Betreff: Test\n"
        "\n"
        "Textinhalt\n"
        "  Hallo\n"
        "  Welt\n"
        "\n"
        "Enthaltene Links (1)\n"
        "  – https://boese.tld/x\n"
        "\n"
        "Anhänge (1)\n"
        "  – anhang.exe\n"
    )
    result = ScanResult(
        path="C:/proben/mail.eml",
        detected_type="eml",
        mail_preview=preview,
        mail_security={
            "spf": "pass", "dkim": "pass", "dmarc": "pass",
            "sender": "ok", "has_from": "1",
        },
    )
    panel = MailPanel()
    qtbot.addWidget(panel)
    panel.show_result(result)

    werte = [
        label.text()
        for label in panel.findChildren(QLabel)
        if label.objectName() == "panelValue"
    ]
    koerper = [text for text in werte if "Hallo" in text]
    assert koerper, f"der Textteil fehlt: {werte}"
    assert "boese.tld" not in koerper[0], "der Link-Abschnitt steht doppelt im Inhalt"
    assert "anhang.exe" not in koerper[0], "der Anhangs-Abschnitt steht doppelt im Inhalt"


def test_mail_panel_ohne_textteil_zeigt_keine_leere_inhalt_ueberschrift(qtbot):
    """BUG-061: eine reine Anhangs-Mail erzeugte 'Inhalt' mit leerem Wert."""
    from PySide6.QtWidgets import QLabel

    from malaz.gui.mail_panel import MailPanel

    preview = (
        "Kopfzeilen\n"
        "  Betreff: Nur Anhang\n"
        "\n"
        "Anhänge (1)\n"
        "  – anhang.exe\n"
    )
    result = ScanResult(
        path="C:/proben/mail.eml",
        detected_type="eml",
        mail_preview=preview,
        mail_security={
            "spf": "pass", "dkim": "pass", "dmarc": "pass",
            "sender": "ok", "has_from": "1",
        },
        children=[
            ScanResult(path="anhang.exe", detected_type="pe", depth=1, score=90,
                       risk_level=RiskLevel.RED)
        ],
    )
    panel = MailPanel()
    qtbot.addWidget(panel)
    panel.show_result(result)

    ueberschriften = [
        label.text()
        for label in panel.findChildren(QLabel)
        if label.objectName() == "panelHeading"
    ]
    assert "Inhalt" not in ueberschriften, (
        "leere Ueberschrift ueber einer Mail ohne Textteil"
    )
    assert any("Anhaenge" in text for text in ueberschriften)


def test_mail_panel_zaehlt_alle_auffaelligen_links_und_nennt_den_rest(qtbot):
    """BUG-062: die Grenze schnitt VOR dem Filter und verschwieg den Rest.

    30 Shortener (je 10 Punkte) ergaben "Links (25 auffaellig)" — fuenf fehlten
    ohne Hinweis. Jetzt wird erst gefiltert, dann angezeigt, und die Zahl der
    ausgelassenen steht da.
    """
    from PySide6.QtWidgets import QLabel

    from malaz.core.eml_analysis import LinkFacts
    from malaz.gui.mail_panel import MailPanel

    links = [
        LinkFacts(
            url=f"https://kurz{nr}.tld/x",
            host=f"kurz{nr}.tld",
            scheme="https",
            is_shortener=True,
        )
        for nr in range(30)
    ]
    result = ScanResult(
        path="C:/proben/mail.eml",
        detected_type="eml",
        mail_links=links,
        mail_security={
            "spf": "pass", "dkim": "pass", "dmarc": "pass",
            "sender": "ok", "has_from": "1",
        },
    )
    panel = MailPanel()
    qtbot.addWidget(panel)
    panel.show_result(result)

    texte = [label.text() for label in panel.findChildren(QLabel)]
    assert any("Links (30 auffaellig)" in text for text in texte), texte
    assert any("und 5 weitere" in text for text in texte), texte

    gezeigt = [text for text in texte if "kurz" in text and "—" in text]
    assert len(gezeigt) == 25, f"{len(gezeigt)} Linkzeilen statt 25"


def test_result_table_clips_absurdly_long_names(qtbot):
    """Ein Member-Name bis 65 535 Zeichen darf die Tabelle nicht sprengen.

    Gemessen: die Spalte "Datei" trug 60 004 Zeichen. Mit der alten
    resizeRowToContents wurde die Zeile turmhoch, mit der neuen Hoehenmessung
    (die nur die Absender-Spalte betrachtet) wird der Name stattdessen still
    abgeschnitten. Beides ist falsch: kuerzen MIT Hinweis, und den vollen
    Namen im Tooltip — sonst sieht der Nutzer nicht, wie die Datei heisst.
    """
    window = MainWindow()
    qtbot.addWidget(window)

    lang = "x" * 60_000 + ".exe"
    window._on_result(
        ScanResult(
            path=lang, detected_type="pe", risk_level=RiskLevel.RED, score=90
        )
    )

    zelle = window.table.topLevelItem(0)
    assert len(zelle.text(0)) < 2000, (
        f"Zelle hat {len(zelle.text())} Zeichen — nicht gekuerzt"
    )
    assert "gekürzt" in zelle.text(0), "der Hinweis fehlt"
    # Der volle Name bleibt erreichbar.
    assert len(zelle.toolTip(0)) >= 60_000, "der volle Name fehlt im Tooltip"


def _drei_ergebnisse(window):
    """Drei Dateien mit unterschiedlichem Risiko und Score."""
    daten = [
        ("aaa_harmlos.pdf", 0, RiskLevel.GREEN, "Harmlos"),
        ("mmm_boese.exe", 90, RiskLevel.RED, "Sehr verdaechtig"),
        ("zzz_mittel.doc", 30, RiskLevel.YELLOW, "Etwas auffaellig"),
    ]
    for name, score, level, titel in daten:
        r = ScanResult(path=name, detected_type="pdf", risk_level=level, score=score)
        r.indicators.append(
            Indicator(
                rule_id="X", title=titel, detail="", severity=Severity.HIGH,
                category="script",
            )
        )
        window._on_result(r)
    window._on_finished(False)


def test_table_sorts_numerically_not_as_text(qtbot):
    """Ordner-Uebersicht zaehlt KPIs exakt pro Stufe."""
    window = MainWindow()
    qtbot.addWidget(window)
    _drei_ergebnisse(window)
    window._show_batch_overview()
    assert window.summary._kpi_bad._count.text() == "1"
    assert window.summary._kpi_warn._count.text() == "1"
    assert window.summary._kpi_ok._count.text() == "1"


def test_click_after_sorting_shows_the_right_file(qtbot):
    """Klick auf eine Zeile zeigt exakt das zugehoerige Ergebnis."""
    from PySide6.QtWidgets import QLabel

    window = MainWindow()
    qtbot.addWidget(window)
    _drei_ergebnisse(window)
    red_row = next(
        i
        for i in range(window.table.topLevelItemCount())
        if window._result_at(i).display_name == "mmm_boese.exe"
    )
    window.table.setCurrentItem(window.table.topLevelItem(red_row))
    assert window.verdict.headline.text().startswith("Gefährlich")
    texts = " ".join(lbl.text() for lbl in window.detail_view.findChildren(QLabel))
    assert "Sehr verdaechtig" in texts


def test_search_filters_by_name_type_and_finding(qtbot):
    """Das Suchfeld findet ueber Dateiname, Typ und Befundtitel.

    Bei 5000 Dateien (config.MAX_BATCH_FILES) findet ein Laie eine bestimmte
    Datei sonst nicht wieder — der Risikofilter beantwortet nur "zeig mir die
    gefaehrlichen", nicht "wo ist rechnung_2026.pdf".
    """
    window = MainWindow()
    qtbot.addWidget(window)
    _drei_ergebnisse(window)

    def sichtbar() -> list[str]:
        return [
            window._result_at(row).display_name
            for row in range(window.table.topLevelItemCount())
            if not window.table.topLevelItem(row).isHidden()
        ]

    assert len(sichtbar()) == 3

    window.search_box.setText("boese")
    assert sichtbar() == ["mmm_boese.exe"]

    # Gross-/Kleinschreibung egal.
    window.search_box.setText("BOESE")
    assert sichtbar() == ["mmm_boese.exe"]

    # Ueber den Befundtitel.
    window.search_box.setText("auffaellig")
    assert sichtbar() == ["zzz_mittel.doc"]

    # Nichts passt -> keine Zeile, aber kein Absturz.
    window.search_box.setText("gibtesnicht")
    assert sichtbar() == []

    # Leeren zeigt wieder alles.
    window.search_box.clear()
    assert len(sichtbar()) == 3


def test_search_and_risk_filter_combine(qtbot):
    """Suchtext UND Risikofilter muessen beide passen, nicht nur einer."""
    window = MainWindow()
    qtbot.addWidget(window)
    _drei_ergebnisse(window)

    def sichtbar() -> list[str]:
        return [
            window._result_at(row).display_name
            for row in range(window.table.topLevelItemCount())
            if not window.table.topLevelItem(row).isHidden()
        ]

    window._set_status_filter("bad")  # Nur Gefaehrliche (Rot)
    assert sichtbar() == ["mmm_boese.exe"]

    # Der Suchtext passt zu einer GRUENEN Datei — der Risikofilter muss sie
    # trotzdem ausschliessen.
    window.search_box.setText("harmlos")
    assert sichtbar() == [], "der Risikofilter wurde vom Suchtext ueberstimmt"


# -- Automatisches Nachladen der Datenbanken -------------------------------- #
#
# Der Haken ist die EINZIGE Erlaubnis fuer einen Netzlauf ohne Klick. Deshalb
# steht hier der Test, dass er wirklich schaltet — und dass er nicht schaltet,
# wenn er aus ist. Ein Netzzugriff darf dabei NIE entstehen: der Lauf wird
# abgefangen, bevor er in den Threadpool geht.


def _stilles_fenster(monkeypatch, qtbot):
    """Ein MainWindow ohne echte Engine-Arbeit — wie die window-Fixture.

    Zwei Dinge sind abzuschalten, nicht eines:

    * ``_EngineProbe`` startet einen PowerShell-Unterprozess im Threadpool,
      der waehrend der uebrigen Tests weiterlaeuft und jede CPU-Zeitmessung im
      Prozess verfaelscht.
    * Der DEFAULT-Dispatcher probt beim Bau ClamAV. Gemessen: 0,43 s gegen
      0,08 s mit einem stillen Dispatcher, also 0,35 s je Fenster. (Die
      window-Fixture nennt 2,2 s — der Wert ist aelter; mit laufendem
      clamd-Daemon ist die Probe deutlich schneller.)

    Beides zusammen ist genau das, was die ``window``-Fixture macht. Die
    ersten Fassungen dieser Tests bauten das Fenster direkt und zahlten beides.
    """
    monkeypatch.setattr("malaz.gui.main_window._EngineProbe.run", lambda self: None)
    dispatcher = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    win = MainWindow(dispatcher=dispatcher)
    qtbot.addWidget(win)
    return win


def _listen_fuers_fenster(tmp_path, monkeypatch, tage: int):
    """Vier Blocklisten mit vorgegebenem Alter anlegen."""
    from malaz import config

    # Die JETZIGE Zeit, nicht ein festes Datum.
    #
    # GEMESSEN: hier stand datetime(2026, 9, 22, 12, 0). Der Test war am 22.09.
    # gruen und am 23.09. rot — "tage=0" erzeugte dann eine Datei, die real
    # schon einen Tag alt war, und FEEDS_AUTO_UPDATE_MIN_AGE_DAYS=1 hielt sie
    # fuer veraltet. Ein Test, der mit dem Kalender kaputtgeht, meldet keinen
    # Fehler im Code, sondern einen im Test.
    jetzt = datetime.now(UTC)
    for konstante, name in (
        ("USER_HASH_BLOCKLIST_FILE", "blocklist.sha256"),
        ("URL_BLOCKLIST_FILE", "urls.sha256"),
        ("DOMAIN_BLOCKLIST_FILE", "domains.txt"),
        ("IP_BLOCKLIST_FILE", "netze.txt"),
    ):
        pfad = tmp_path / name
        pfad.write_text("a" * 64, encoding="utf-8")
        zeit = (jetzt - timedelta(days=tage)).timestamp()
        os.utime(pfad, (zeit, zeit))
        monkeypatch.setattr(config, konstante, pfad)
    return jetzt


def test_start_laedt_nur_mit_haken_nach(qtbot, tmp_path, monkeypatch):
    """Ohne Haken kein Lauf; mit Haken ein Lauf — und beide ohne Netz."""
    from malaz import config
    from malaz.gui.settings import app_settings

    _listen_fuers_fenster(tmp_path, monkeypatch, tage=9)
    monkeypatch.setattr(config, "FEEDS_AUTO_UPDATE_MIN_AGE_DAYS", 1)
    app_settings().setValue("feeds_auto_update", False)

    window = _stilles_fenster(monkeypatch, qtbot)
    gestartet: list[object] = []
    # Abfangen, BEVOR etwas in den Threadpool geht: sonst liefe ein echter
    # Download gegen fuenf fremde Server mitten in der Suite.
    monkeypatch.setattr(window.thread_pool, "start", gestartet.append)

    assert window.chk_feeds_auto.isChecked() is False

    window._maybe_auto_refresh_feeds()
    assert gestartet == [], "ohne Haken darf kein Lauf starten"

    # Mit Haken und veralteten Listen muss er starten.
    window.chk_feeds_auto.setChecked(True)
    assert app_settings().value("feeds_auto_update", False, bool) is True, (
        "der Haken wird nicht gemerkt"
    )
    window._maybe_auto_refresh_feeds()
    assert len(gestartet) == 1, "mit Haken und alten Listen muss er starten"


def test_frische_listen_starten_auch_mit_haken_nichts(qtbot, tmp_path, monkeypatch):
    """Der Deckel gegen Dauerlast: 65 MB bei jedem Start waeren unzumutbar."""
    from malaz import config

    _listen_fuers_fenster(tmp_path, monkeypatch, tage=0)
    monkeypatch.setattr(config, "FEEDS_AUTO_UPDATE_MIN_AGE_DAYS", 1)

    window = _stilles_fenster(monkeypatch, qtbot)
    gestartet: list[object] = []
    monkeypatch.setattr(window.thread_pool, "start", gestartet.append)
    window.chk_feeds_auto.setChecked(True)
    window._maybe_auto_refresh_feeds()
    assert gestartet == [], "frische Listen duerfen keinen Lauf ausloesen"


def test_die_standanzeige_steht_im_fenster(qtbot, tmp_path, monkeypatch):
    """Die Optionen-Ansicht zeigt den echten Stand der lokalen Listen."""
    _listen_fuers_fenster(tmp_path, monkeypatch, tage=0)

    window = _stilles_fenster(monkeypatch, qtbot)
    text = window.options_view._db_label.text()
    assert "Datei-Hashes" in text
    assert "4 von 4 Listen vorhanden" in window.options_view._db_label.toolTip()


def test_dialog_aktualisiert_die_standanzeige(qtbot, tmp_path, monkeypatch):
    """Nach dem Import im Dialog muss die Anzeige den NEUEN Stand zeigen."""
    _listen_fuers_fenster(tmp_path, monkeypatch, tage=9)
    window = _stilles_fenster(monkeypatch, qtbot)
    assert "veraltet" in window.options_view._db_label.toolTip()

    def nach_dem_dialog():
        assert "veraltet" in window.options_view._db_label.toolTip()
        _listen_fuers_fenster(tmp_path, monkeypatch, tage=0)

    monkeypatch.setattr(
        "malaz.gui.feeds_dialog.FeedsDialog", _DialogMitWirkung(nach_dem_dialog)
    )
    window._on_feeds()
    assert window.options_view._db_label.toolTip().count("veraltet") == 0, (
        "die Anzeige steht noch auf dem Stand VOR dem Import"
    )


class _DialogMitWirkung:
    """Ein Dialog-Ersatz, der beim exec() die Listen aendert."""

    def __init__(self, wirkung):
        self._wirkung = wirkung

    def __call__(self, _parent):
        return self

    def exec(self) -> None:
        self._wirkung()


def test_liste_leeren_raeumt_auch_die_urteilskarte(qtbot, monkeypatch):
    """Gemeldet vom Nutzer: nach "Liste leeren" stand weiter "unauffaellig".

    Die Karte haengt an der AUSWAHL, wurde beim Leeren aber nie zurueckgesetzt.
    Uebrig blieb das Urteil der zuletzt markierten Zeile — bei einer harmlosen
    Datei also ein gruener "unauffaellig"-Balken ueber einer leeren Tabelle.
    """
    window = _stilles_fenster(monkeypatch, qtbot)
    _drei_ergebnisse(window)

    # Die GRUENE Zeile markieren, nicht Zeile 0: die Tabelle ist nach Score
    # sortiert, Zeile 0 ist die bösartige. Der Nutzer beschrieb genau den
    # gruenen Fall ("unauffaellig" blieb stehen).
    gruen = next(
        r for r in range(window.table.topLevelItemCount())
        if window._result_at(r) is not None
        and window._result_at(r).risk_level == RiskLevel.GREEN
    )
    window.table.setCurrentItem(window.table.topLevelItem(gruen))
    assert window.verdict.headline.text().startswith("Unauffällig"), "Vorbedingung"

    window._on_clear()

    assert window.verdict.headline.text() == "", (
        "nach dem Leeren steht das Urteil der vorigen Auswahl noch da"
    )
    assert window.verdict.score.text() == ""
    assert window._pages.currentIndex() == 0


def test_neuer_scan_raeumt_die_urteilskarte_des_vorigen(qtbot, monkeypatch, tmp_path):
    """Dieselbe Luecke im Scan-Start: der alte Befund blieb bis zum ersten Treffer.

    Ohne das sieht der Nutzer waehrend eines neuen Laufs das Urteil der VORIGEN
    Datei — und haelt es fuer das Ergebnis der neuen.
    """
    window = _stilles_fenster(monkeypatch, qtbot)
    _drei_ergebnisse(window)
    gruen = next(
        r for r in range(window.table.topLevelItemCount())
        if window._result_at(r) is not None
        and window._result_at(r).risk_level == RiskLevel.GREEN
    )
    window.table.setCurrentItem(window.table.topLevelItem(gruen))
    assert window.verdict.headline.text().startswith("Unauffällig"), "Vorbedingung"

    datei = tmp_path / "probe.txt"
    datei.write_text("harmlos", encoding="utf-8")
    window.add_paths([str(datei)])
    window._on_scan()

    assert window.verdict.headline.text() == "", (
        "der Befund der vorigen Runde steht noch ueber dem neuen Lauf"
    )
    # Aufraeumen, falls der Worker noch laeuft.
    if window._worker is not None:
        window._worker.cancel()
        qtbot.waitUntil(lambda: window._worker is None, timeout=15000)


def test_abwaehlen_leert_die_ansicht(qtbot, monkeypatch):
    """Die eigentliche Ursache: der leere Auswahl-Zweig stieg einfach aus.

    Ohne Auswahl gibt es kein Ergebnis zu zeigen — die Panes behielten aber
    das der zuletzt markierten Zeile. Das trifft nicht nur "Liste leeren"
    (dort entzieht das Leeren der Tabelle die Auswahl), sondern auch den
    simplen Klick ins Leere.
    """
    window = _stilles_fenster(monkeypatch, qtbot)
    _drei_ergebnisse(window)
    gruen = next(
        r for r in range(window.table.topLevelItemCount())
        if window._result_at(r) is not None
        and window._result_at(r).risk_level == RiskLevel.GREEN
    )
    window.table.setCurrentItem(window.table.topLevelItem(gruen))
    assert window.verdict.headline.text().startswith("Unauffällig"), "Vorbedingung"

    window.table.clearSelection()
    window._on_selection_changed()

    assert window.verdict.headline.text() == ""
    assert len(window._results) == 3, "Abwaehlen darf die Ergebnisse NICHT loeschen"
    assert window.table.topLevelItemCount() == 3


def test_zeile_ohne_ergebnis_leert_die_ansicht(qtbot, monkeypatch):
    """Die zwei verbliebenen Ausstiege in _on_selection_changed.

    EHRLICHKEITSHINWEIS: der Zustand "Zeile ohne Ergebnis" ist durch die App
    NICHT erreichbar. ``_on_result`` haengt Ergebnis und Zeile im selben Zug
    an, und die einzige Leerung macht beides zusammen — es gilt immer
    ``rowCount() == len(self._results)``. Der Test stellt den Zustand von Hand
    her und prueft damit eine VERTEIDIGUNG, nicht einen erreichbaren Fehler.

    Berechtigt ist er trotzdem: die beiden Ausstiege liessen die Panes stehen,
    und ein kuenftiger Weg, der Zeilen und Ergebnisse getrennt anfasst (etwa
    ein Nachsortieren), wuerde die Luecke sofort echt machen. Der Test haelt
    fest, was dann gelten muss.
    """
    from PySide6.QtWidgets import QTreeWidgetItem

    window = _stilles_fenster(monkeypatch, qtbot)
    _drei_ergebnisse(window)
    gruen = next(
        r for r in range(window.table.topLevelItemCount())
        if window._result_at(r) is not None
        and window._result_at(r).risk_level == RiskLevel.GREEN
    )
    window.table.setCurrentItem(window.table.topLevelItem(gruen))
    assert window.verdict.headline.text().startswith("Unauffällig"), "Vorbedingung"

    leer = QTreeWidgetItem()
    leer.setText(0, "kommt_noch.exe")
    window.table.addTopLevelItem(leer)
    window.table.setCurrentItem(leer)
    window._on_selection_changed()

    assert window.verdict.headline.text() == "", (
        "die Ansicht der vorigen Zeile steht noch ueber einer Zeile ohne Ergebnis"
    )
    assert len(window._results) == 3, "die Ergebnisse selbst bleiben"


def test_ergebnisliste_ist_ein_baum_mit_aufklappbaren_kindern(window, qtbot, tmp_path):
    """Die drei Anzeige-Anforderungen des Nutzers an einem echten Fall.

    * **aufklappbar** — ein Archivmitglied steht UNTER seiner Zeile, nicht in
      einer eigenen, zusammenhanglosen Zeile. Ohne das sieht der Nutzer bei
      einem Archiv nicht, WELCHES Mitglied der Ausloeser war.
    * **farbcodiert** — die ganze Zeile traegt einen Hintergrundton nach
      Risikostufe, nicht nur die Ergebnisspalte. Bei 15 Zeilen musste man
      sonst die dritte Spalte von links nach rechts lesen.
    * **sortierbar** — die Spalten sind klickbar (Qt-Standard fuer
      QTreeWidget), und die Zahlenspalten tragen echte Zahlen, damit "90/100"
      nicht hinter "0/100" landet.
    """
    import zipfile

    from malaz.models import RiskLevel

    # Ein harmloses Archiv mit einem boesen Mitglied: genau der Fall, in dem
    # die Verschachtelung die Ursache zeigt.
    z = tmp_path / "paket.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("harmlos.txt", "nur text")
        zf.writestr("boese.pdf", b"%PDF-1.7\n/Launch\n%%EOF")

    window.add_paths([str(z)])
    window._on_scan()
    qtbot.waitUntil(lambda: window._worker is None, timeout=60_000)

    assert window.table.topLevelItemCount() == 1, "das Archiv fehlt"
    oben = window.table.topLevelItem(0)
    assert oben.text(0) == "paket.zip"

    from malaz.gui.file_tree import STATE_ROLE

    assert oben.childCount() == 2, "die Mitglieder fehlen unter der Zeile"
    namen = [oben.child(i).text(0) for i in range(oben.childCount())]
    assert "boese.pdf" in namen, namen
    assert oben.isExpanded() is True, "ein gefaehrlicher Container klappt auf"

    boese_item = oben.child(namen.index("boese.pdf"))
    harmlos_item = oben.child(namen.index("harmlos.txt"))
    assert boese_item.data(0, STATE_ROLE) == "bad"
    assert harmlos_item.data(0, STATE_ROLE) in ("ok", "unk")

    window.table.setCurrentItem(boese_item)
    assert window.verdict.headline.text().startswith("Gefährlich")
    _ = RiskLevel


def test_optionsdialog_liest_den_datenbankstand_bei_jedem_anzeigen_neu(qtbot, tmp_path, monkeypatch):
    """BUG-057: der Dialog zeigte den Stand vom Aufbau bis zum Neustart.

    ``_refresh_databases`` lief nur im Konstruktor. Der Dialog wird aber
    EINMAL gebaut und behalten — nach einem Feed-Import stand dort weiter
    "nicht vorhanden".
    """
    from malaz import config
    from malaz.gui.options_dialog import OptionsDialog

    db = tmp_path / "urls.sha256"
    monkeypatch.setattr(config, "URL_BLOCKLIST_FILE", db)
    dialog = OptionsDialog()
    qtbot.addWidget(dialog)
    assert "Schad-URLs: nicht vorhanden" in dialog._db_label.text()

    db.write_bytes(b"x" * 2048)
    dialog.show()
    assert "Schad-URLs: 2 KB" in dialog._db_label.text(), (
        "der Dialog hat beim Anzeigen nicht neu gelesen"
    )

    dialog.hide()
    db.write_bytes(b"x" * 4096)
    dialog.show()
    assert "Schad-URLs: 4 KB" in dialog._db_label.text()
    dialog.close()


def test_optionsdialog_zerstoert_die_schalter_nicht(window):
    """Der Dialog haengt die Kaestchen des Fensters ein — er darf sie nicht töten.

    GEMESSEN mit einem Wegwerf-Dialog (``OptionsDialog(self, ...).exec()``):
    Qt macht die einghaengten Kaestchen zu Kindern des Dialogs, und beim
    Schliessen raeumt er sie mit ab. Der naechste Scan liest
    ``chk_capa.isChecked()`` und stirbt:

        libshiboken: Internal C++ object (PySide6.QtWidgets.QCheckBox)
        already deleted

    Der Dialog wird deshalb EINMAL gebaut und behalten. Diese Zusicherung ist
    der Grund: sie faellt genau dann, wenn jemand wieder einen Wegwerf-Dialog
    daraus macht.

    Die Mutationsprobe dazu bleibt HAENGEN statt rot zu werden — ein
    Wegwerf-``exec()`` blockiert, wenn niemand ihn schliesst. Auch das ist
    ein Signal, nur kein sauberes; wer hier etwas aendert, soll es wissen.
    """
    from PySide6.QtWidgets import QApplication

    assert window.chk_capa is not None, "Vorbedingung: der Schalter existiert"
    vorher = window.chk_capa.isChecked()

    window._open_options()
    QApplication.processEvents()
    assert window._pages.currentIndex() == 3, "Optionen-Ansicht nicht geoeffnet"
    window._leave_options()
    QApplication.processEvents()

    assert window.chk_capa.isChecked() is vorher, "der Schalter hat seinen Wert verloren"
    window.chk_capa.setChecked(not vorher)
    assert window.chk_capa.isChecked() is not vorher, "der Schalter reagiert nicht mehr"
    window.chk_capa.setChecked(vorher)

    window._open_options()
    QApplication.processEvents()
    assert window._pages.currentIndex() == 3
    window._leave_options()
    assert window.chk_capa.isChecked() is vorher


def test_gespeicherte_opt_ins_gelten_auch_ohne_fenster(qtbot, monkeypatch, tmp_path):
    """Der Fehler, den erst der gebaute exe zeigte.

    Die Schalter wurden NUR durch das ``toggled``-Signal ihres Kästchens in
    ``config`` geschrieben. Im Fenster ging das gut (``setChecked`` löst das
    Signal aus), aber ``--cli`` baut kein Fenster: GEMESSEN blieb
    ``MAZ_DNS_AUTH`` aus, obwohl der Nutzer den Haken gesetzt hatte — die
    Prüfung lief still nicht, und der Bericht sagte nicht einmal, dass sie
    fehlte.

    ``apply_saved_opt_ins`` liest die Zuordnung jetzt beim Start, für beide
    Wege.
    """
    from PySide6.QtCore import QSettings

    from malaz import config
    from malaz.gui.settings import apply_saved_opt_ins

    ini = tmp_path / "einstellungen.ini"
    monkeypatch.setattr(
        "malaz.gui.settings.app_settings",
        lambda: QSettings(str(ini), QSettings.Format.IniFormat),
    )
    # Beide Opt-ins auf AN speichern, so wie es das Fenster tut.
    s = QSettings(str(ini), QSettings.Format.IniFormat)
    s.setValue("dns_auth_enabled", True)
    s.setValue("capa_enabled", True)
    s.sync()

    # Und die Config auf AUS stellen — der Zustand beim Programmstart.
    monkeypatch.setattr(config, "DNS_AUTH_ENABLED", False)
    monkeypatch.setattr(config, "CAPA_ENABLED", False)
    apply_saved_opt_ins()
    assert config.DNS_AUTH_ENABLED is True, "der DNS-Haken wirkte headless nicht"
    assert config.CAPA_ENABLED is True


def test_opt_ins_ohne_gespeicherten_wert_bleiben_aus(monkeypatch, tmp_path):
    """Die Gegenprobe: ohne gespeicherten Haken bleibt alles aus."""
    from PySide6.QtCore import QSettings

    from malaz import config
    from malaz.gui.settings import apply_saved_opt_ins

    ini = tmp_path / "leer.ini"
    monkeypatch.setattr(
        "malaz.gui.settings.app_settings",
        lambda: QSettings(str(ini), QSettings.Format.IniFormat),
    )
    monkeypatch.setattr(config, "DNS_AUTH_ENABLED", False)
    monkeypatch.setattr(config, "CAPA_ENABLED", False)
    apply_saved_opt_ins()
    assert config.DNS_AUTH_ENABLED is False
    assert config.CAPA_ENABLED is False


def test_detail_tabs_keyboard_and_accessible_names(window):
    """Tabs sind per Auswahl und Ctrl+1..4-Tastenkuerzel erreichbar."""
    from PySide6.QtGui import QAction

    actions = {
        act.shortcut().toString(): act
        for act in window.findChildren(QAction)
        if act.shortcut().toString()
    }
    assert "Ctrl+1" in actions and "Ctrl+2" in actions
    assert "Ctrl+3" in actions and "Ctrl+4" in actions

    actions["Ctrl+2"].trigger()
    assert window.detail_view._stack.currentIndex() == 1
    actions["Ctrl+1"].trigger()
    assert window.detail_view._stack.currentIndex() == 0
    actions["Ctrl+3"].trigger()
    assert window.detail_view._stack.currentIndex() == 0
    actions["Ctrl+4"].trigger()
    assert window.detail_view._stack.currentIndex() == 0

    assert window.search_box.accessibleName()
    assert window.btn_options.accessibleName()


# -- Phase B: Reiter-Identitaet, Filter-Auswahl, Qt-Textsenken ---------------- #


def test_capa_und_mail_reiter_zerstoeren_sich_nicht(qtbot, monkeypatch):
    """BUG-050: gecachte Tab-Indizes machten den Mail-Reiter unerreichbar.

    Reproduziert die Reihenfolge Capa-Datei -> Mail -> Capa-Datei -> Mail:
    ``insertTab(1, mail_panel)`` verschiebt den Faehigkeiten-Reiter, der
    gemerkte Index zeigte danach auf den falschen Reiter, und removeTab
    entfernte das E-Mail-Panel. Der Reiter wird jetzt ueber die
    WIDGET-Identitaet gesucht (``tabs.indexOf``).
    """
    window = _stilles_fenster(monkeypatch, qtbot)

    capa = ScanResult(path="C:/proben/tool.exe", detected_type="pe")
    capa.capa_capabilities = [{"name": "Prozess starten", "namespace": "host"}]
    mail = ScanResult(
        path="C:/proben/mail.eml",
        detected_type="eml",
        mail_security={
            "spf": "unknown",
            "dkim": "unknown",
            "dmarc": "unknown",
            "sender": "unknown",
            "has_from": "1",
        },
    )
    window._on_result(capa)
    window._on_result(mail)

    def auswaehlen(name: str):
        for row in range(window.table.topLevelItemCount()):
            item = window.table.topLevelItem(row)
            ergebnis = window._result_of(item)
            if ergebnis is not None and ergebnis.display_name == name:
                window.table.setCurrentItem(item)
                return
        raise AssertionError(f"Zeile fehlt: {name}")

    auswaehlen("tool.exe")
    assert not window.detail_view._btn_tab_capa.isHidden(), "Capa-Reiter fehlt"
    assert window.detail_view._btn_tab_mail.isHidden()

    auswaehlen("mail.eml")
    assert not window.detail_view._btn_tab_mail.isHidden(), "Mail-Reiter fehlt"
    assert window.detail_view._btn_tab_capa.isHidden(), "Capa-Reiter blieb fuer Mail stehen"

    auswaehlen("tool.exe")
    assert window.detail_view._btn_tab_mail.isHidden(), "Mail-Reiter blieb stehen"
    assert not window.detail_view._btn_tab_capa.isHidden(), "Capa-Reiter kam nicht zurueck"

    auswaehlen("mail.eml")
    assert not window.detail_view._btn_tab_mail.isHidden(), "Mail-Reiter fehlt beim zweiten Aufruf"
    assert window.detail_view._btn_tab_capa.isHidden()


def test_filter_versteckt_die_auswahl_und_raeumt_die_ansicht(qtbot, monkeypatch):
    """BUG-051: der Filter versteckte die Auswahl, die Panes blieben stehen.

    Qt entfernt eine gerade ausgewaehlte Zeile beim Verstecken aus
    ``selectedItems()``, ohne ``itemSelectionChanged`` zu senden. Danach stand
    das Urteil der unsichtbaren gruenen Datei ueber einer Liste, die nur noch
    die rote zeigte.
    """
    window = _stilles_fenster(monkeypatch, qtbot)
    _drei_ergebnisse(window)
    gruen = next(
        r
        for r in range(window.table.topLevelItemCount())
        if window._result_at(r) is not None
        and window._result_at(r).risk_level == RiskLevel.GREEN
    )
    window.table.setCurrentItem(window.table.topLevelItem(gruen))
    assert window.verdict.headline.text().startswith("Unauffällig"), "Vorbedingung"

    window._set_status_filter("bad")  # nur Gefaehrliche

    assert window.table.selectedItems() == [], "die versteckte Auswahl blieb"
    assert window.table.currentItem() is None, "die versteckte Zeile blieb current"
    assert window.verdict.headline.text() == "", (
        "das Urteil der versteckten Datei steht weiter im Panel"
    )
    assert window._pages.currentIndex() == 0
    assert len(window._results) == 3


def test_tooltip_escapet_html_aus_dem_dateinamen(qtbot, monkeypatch):
    """SEC-029: Qt rendert Tooltips als AutoText und lud file:-Bilder.

    Ein ZIP-Mitglied namens ``<img src=file:...>`` liess den Tooltip der
    Datei-Spalte ein lokales Bild laden. Der Tooltip wird jetzt HTML-escaped
    gesetzt; das Zeichen bleibt als Text sichtbar, ist aber kein Tag mehr.
    """
    window = _stilles_fenster(monkeypatch, qtbot)
    result = ScanResult(
        path="C:/proben/<img src=file:rot.png>.pdf", detected_type="pdf"
    )
    window._on_result(result)

    tip = window.table.topLevelItem(0).toolTip(0)
    assert "<img" not in tip, f"rohes HTML im Tooltip: {tip!r}"
    assert "&lt;img" in tip, f"das Tag wurde nicht escaped: {tip!r}"


def test_mail_panel_erzwingt_klartext_fuer_rumpf_und_anhaenge(qtbot):
    """SEC-030: QLabel-AutoText liess den Mail-Rumpf als HTML rendern.

    Ein Body oder Anhangsname mit ``<img src=file:...>`` lud die lokale Datei
    (gemessen 20 000 rote Pixel). Jedes Label des Panels traegt jetzt
    ausdruecklich ``Qt.TextFormat.PlainText``.
    """
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QLabel

    from malaz.gui.mail_panel import MailPanel

    panel = MailPanel()
    qtbot.addWidget(panel)
    preview = (
        "E-Mail-Inhalt\n"
        "============================================================\n"
        "\n"
        "Kopfzeilen\n"
        "  Betreff: Test\n"
        "\n"
        "Textinhalt\n"
        '<img src=file:rot.png>Hallo\n'
    )
    result = ScanResult(
        path="C:/proben/mail.eml",
        detected_type="eml",
        mail_preview=preview,
        mail_security={
            "spf": "unknown",
            "dkim": "unknown",
            "dmarc": "unknown",
            "sender": "unknown",
            "has_from": "1",
        },
        children=[
            ScanResult(
                path="C:/proben/<img src=file:rot.png>.pdf",
                detected_type="pdf",
                score=50,
                risk_level=RiskLevel.RED,
            )
        ],
    )
    panel.show_result(result)

    labels = panel.findChildren(QLabel)
    assert labels, "das Panel hat keine Labels aufgebaut"
    for label in labels:
        assert label.textFormat() == Qt.TextFormat.PlainText, (
            f"Label rendert AutoText/RichText: {label.text()!r}"
        )
    assert any("<img" in label.text() for label in labels), (
        "der Testfall enthaelt gar kein HTML im Anzeigetext"
    )


def test_mail_ohne_absender_zeigt_kein_absender_statt_teilweise_stimmig(qtbot):
    """BUG-053: ``has_from=bool(security)`` war bei jeder Mail True.

    Eine Mail ohne From-Kopf bekam 70/100 "nur teilweise stimmig" statt
    0/100 "Kein Absender angegeben" — das klassische Phishing-Merkmal wurde
    gelb statt rot dargestellt.
    """
    from PySide6.QtWidgets import QLabel

    from malaz.core.mail_score import sender_score
    from malaz.gui.mail_panel import MailPanel

    panel = MailPanel()
    qtbot.addWidget(panel)
    result = ScanResult(
        path="C:/proben/ohne_absender.eml",
        detected_type="eml",
        mail_preview="E-Mail-Inhalt\n====\n\nTextinhalt\nHallo\n",
        mail_security={
            "spf": "unknown",
            "dkim": "unknown",
            "dmarc": "unknown",
            "sender": "unknown",
            "has_from": "0",
        },
    )
    panel.show_result(result)

    texte = [label.text() for label in panel.findChildren(QLabel)]
    assert any("Kein Absender" in text for text in texte), texte
    assert not any("teilweise stimmig" in text for text in texte), texte

    # Gegenprobe: dieselben Angaben MIT Absender bleiben "teilweise stimmig" —
    # der Fix darf nicht jede unbekannte Authentifizierung rot faerben.
    mit_absender = sender_score(
        result.mail_security,
        "unknown",
        has_from=True,
    )
    assert mit_absender.score == 70, mit_absender
    ohne_absender = sender_score(result.mail_security, "unknown", has_from=False)
    assert ohne_absender.score == 0, ohne_absender


def test_eml_pipeline_meldet_den_echten_absender_status():
    """BUG-053 an der Quelle: der Marker kommt aus dem geparsten From-Kopf."""
    from pathlib import Path as _Path

    from malaz.models import AnalysisContext
    from malaz.pipelines.eml_pipeline import EmlPipeline

    ohne = b"To: opfer@firma.de\nSubject: ohne Absender\n\nHallo\n"
    ctx = AnalysisContext(
        path=_Path("ohne.eml"), data=ohne, detected_type="eml", size=len(ohne)
    )
    EmlPipeline().analyze(ctx)
    assert ctx.mail_security.get("has_from") == "0"

    mit = (
        b"From: Absender <a@firma.de>\n"
        b"To: opfer@firma.de\n"
        b"Subject: mit Absender\n"
        b"\n"
        b"Hallo\n"
    )
    ctx2 = AnalysisContext(
        path=_Path("mit.eml"), data=mit, detected_type="eml", size=len(mit)
    )
    EmlPipeline().analyze(ctx2)
    assert ctx2.mail_security.get("has_from") == "1"

    # Ein PARSE-FEHLER ist keine Aussage "kein Absender": der Marker fehlt,
    # das Panel faellt auf das bisherige Verhalten zurueck.
    ctx3 = AnalysisContext(
        path=_Path("kaputt.eml"), data=b"", detected_type="eml", size=0
    )
    EmlPipeline().analyze(ctx3)
    assert "has_from" not in ctx3.mail_security


def test_feed_timer_startet_nach_dem_schliessen_keinen_lauf(
    qtbot, tmp_path, monkeypatch
):
    """TEST-028: der 700-ms-Timer feuerte nach dem Testende weiter.

    ``QTimer.singleShot`` band den Slot an keinen Empfaenger. Ein geschlossenes
    Fenster startete danach trotzdem ``_FeedRefreshJob`` — ein echter
    Netzzugriff mitten in der naechsten Testdatei. Die Start-Timer gehoeren
    jetzt dem Fenster und werden in ``closeEvent`` gestoppt.
    """
    from PySide6.QtTest import QTest

    from malaz import config

    _listen_fuers_fenster(tmp_path, monkeypatch, tage=9)
    monkeypatch.setattr(config, "FEEDS_AUTO_UPDATE_MIN_AGE_DAYS", 1)

    gestartet: list[object] = []

    class _FakeFeedJob:
        def __init__(self, _signals):
            gestartet.append(self)

    # Kein Netz, kein Thread: der Job wird nur REGISTRIERT, wenn der Timer
    # ihn nach dem Schliessen noch startet.
    monkeypatch.setattr("malaz.gui.main_window._FeedRefreshJob", _FakeFeedJob)

    window = _stilles_fenster(monkeypatch, qtbot)
    window.chk_feeds_auto.setChecked(True)
    monkeypatch.setattr(window.thread_pool, "start", gestartet.append)

    assert window._startup_timers, "keine Start-Timer geplant"
    window.close()
    assert not any(timer.isActive() for timer in window._startup_timers), (
        "ein Start-Timer lief nach dem Schliessen weiter"
    )

    vorher = len(gestartet)
    QTest.qWait(800)  # laenger als der 700-ms-Feed-Haken
    assert len(gestartet) == vorher, (
        "nach dem Schliessen wurde ein Feed-Lauf gestartet"
    )


def test_main_wendet_gespeicherte_opt_ins_beim_start_an(monkeypatch):
    """TEST-030: der Aufruf in ``main()`` war durch keinen Test gedeckt.

    ``apply_saved_opt_ins`` wurde nur direkt getestet; ein Entfernen des
    Aufrufs aus ``__main__.main`` waere gruen geblieben. Der Test fuehrt den
    echten Einstiegspunkt aus (``--status``, ohne Engine/Netz) und prueft die
    Verdrahtung.
    """
    import malaz.__main__ as entry
    from malaz.gui import settings as settings_module

    aufrufe: list[bool] = []
    monkeypatch.setattr(entry, "_enable_utf8_console", lambda: None)
    monkeypatch.setattr(entry, "_setup_logging", lambda: None)
    monkeypatch.setattr(entry.config, "ensure_dirs", lambda: None)
    monkeypatch.setattr(settings_module, "apply_saved_opt_ins", lambda: aufrufe.append(True))

    class _StillerDispatcher:
        pass

    monkeypatch.setattr(entry, "Dispatcher", lambda: _StillerDispatcher())
    monkeypatch.setattr(entry, "_print_engines", lambda _dispatcher: None)

    assert entry.main(["--status"]) == 0
    assert aufrufe == [True], "main() wendet die gespeicherten Opt-ins nicht an"


# ---- BUG-058: Feed-Timeout muss bis zum Download durchkommen ------------- #


def test_feed_job_reicht_den_timeout_an_refresh_feed_durch(qapp, monkeypatch):
    """BUG-058: ``_FeedRefreshJob`` setzte self.timeout, rief aber ohne Argument.

    ``download_feed`` fiel damit auf seine 60 s zurueck, waehrend
    ``FEEDS_DOWNLOAD_TIMEOUT_SECONDS`` (120 s) dokumentiert war.
    """
    from pathlib import Path
    from types import SimpleNamespace

    from malaz.gui import main_window as mw

    gesehen: list[float | None] = []

    def fake_refresh(feed, ziel, timeout=None):
        gesehen.append(timeout)
        return Path("probe.feed"), SimpleNamespace(imported=1)

    monkeypatch.setattr("malaz.core.feed_import.refresh_feed", fake_refresh)

    class _Signal:
        def __init__(self):
            self.lines: list[tuple] = []

        def emit(self, *args):
            self.lines.append(args)

    signals = SimpleNamespace(ready=_Signal())
    mw._FeedRefreshJob(signals, timeout=7).run()

    assert gesehen, "kein Feed wurde verarbeitet"
    assert set(gesehen) == {7}, f"Timeout nicht durchgereicht: {set(gesehen)}"
    assert signals.ready.lines, "kein Ergebnis gemeldet"


def test_refresh_feed_reicht_den_timeout_bis_zum_download_durch(
    monkeypatch, tmp_path
):
    """BUG-058 an der Naht: ``refresh_feed`` muss ``download_feed`` den Wert geben."""
    from pathlib import Path
    from types import SimpleNamespace

    from malaz.core import feed_import
    from malaz.core.feed_import import ImportResult

    gesehen: list[float] = []

    def fake_download(feed, target_dir, timeout=60.0):
        gesehen.append(timeout)
        return tmp_path / "probe.feed"

    monkeypatch.setattr("malaz.core.feeds.download_feed", fake_download)
    monkeypatch.setattr(
        feed_import,
        "import_feed",
        lambda feed, pfad: ImportResult("Schad-Netze", 1, Path("ziel.txt")),
    )
    feed = SimpleNamespace(key="test", title="Test", kind="cidr")

    feed_import.refresh_feed(feed, tmp_path, timeout=7)

    assert gesehen == [7], f"download_feed bekam {gesehen} statt [7]"


def test_static_only_mode_is_session_only_and_enforces_incomplete(qtbot, monkeypatch, tmp_path):
    """Nur-Statik-Modus startet immer aus, wird nie persistiert und macht Scans unvollstaendig."""
    from malaz.gui.file_tree import STATE_ROLE

    win = _stilles_fenster(monkeypatch, qtbot)
    assert win.chk_static_only.isChecked() is False

    win.chk_static_only.setChecked(True)
    eff = win._effective_dispatcher()
    assert eff.av_scanner.available is False
    assert eff.clam_scanner.available is False

    win2 = _stilles_fenster(monkeypatch, qtbot)
    assert win2.chk_static_only.isChecked() is False

    probe = tmp_path / "harmlos.txt"
    probe.write_text("nur harmloser text", encoding="utf-8")
    res = eff.scan_path(probe)
    win._on_result(res)
    assert win.table.topLevelItem(0).data(0, STATE_ROLE) == "unk"


def test_theme_toggle_switches_between_dark_and_light(qapp, qtbot, monkeypatch):
    """Theme-Umschaltung wechselt Dark/Light live ohne Absturz."""
    from malaz.gui.theme import apply_theme, current_theme_mode

    win = _stilles_fenster(monkeypatch, qtbot)
    apply_theme(qapp, "dark", persist=True)
    assert current_theme_mode() == "dark"
    win._toggle_dark_light()
    assert current_theme_mode() == "light"
    win._toggle_dark_light()
    assert current_theme_mode() == "dark"


# -- Klare Flaeche v2: Completeness, Security & Lifecycle Contracts --------- #


def test_score_ring_dash_only_on_unk(qapp):
    """ScoreRingWidget zeigt '—' NUR bei visual_state=='unk', nie bei RED/YELLOW."""
    from malaz.gui.score_ring import ScoreRingWidget

    ring = ScoreRingWidget()
    try:
        ring.set_score(0, "unk")
        assert ring._state == "unk" and ring._score == 0
        ring.set_score(85, "bad")
        assert ring._state == "bad" and ring._score == 85
        ring.set_score(45, "warn")
        assert ring._state == "warn" and ring._score == 45
    finally:
        ring.deleteLater()


def test_detail_view_completeness_and_error_visibility(qapp):
    """B1: Detailansicht zeigt unvollstaendige Stufen auch bei gewichteten Befunden,
    nutzt kanonisches _INCOMPLETE_RULES und rendert result.error in beiden Tabs."""
    from PySide6.QtWidgets import QLabel

    from malaz.gui.detail_view import FileDetailView, _severity_badge
    from malaz.models import _INCOMPLETE_RULES, Indicator, RiskLevel, ScanResult, Severity

    # Every canonical _INCOMPLETE_RULES entry must NEVER render green ("ok")
    for rid in sorted(_INCOMPLETE_RULES):
        tone, badge = _severity_badge(
            Indicator(rule_id=rid, title=f"Luecke {rid}", severity=Severity.INFO, weight=0)
        )
        assert tone == "warn" and badge == "Ungeprüft", (rid, tone, badge)

    res = ScanResult(
        path="C:/proben/kaputt.exe",
        detected_type="pe",
        size=1024,
        sha256="a" * 64,
        risk_level=RiskLevel.YELLOW,
        score=35,
        error="Lesefehler: Zugriff verweigert",
        indicators=[
            Indicator(rule_id="PE_HIGH_ENTROPY", title="Hohe Entropie", severity=Severity.MEDIUM, weight=35),
            Indicator(rule_id="CORE_TIME_BUDGET", title="YARA Zeitlimit", severity=Severity.INFO, weight=0),
        ],
    )
    view = FileDetailView()
    try:
        view.show_result(res)
        ov_texts = [lbl.text() for lbl in view._page_overview.findChildren(QLabel)]
        assert any("Unvollständige Prüfung" in txt for txt in ov_texts), ov_texts
        assert any("Zugriff verweigert" in txt for txt in ov_texts), ov_texts

        det_texts = [lbl.text() for lbl in view._page_details.findChildren(QLabel)]
        assert any("Zugriff verweigert" in txt for txt in det_texts), det_texts
        assert any("Signatur" in txt for txt in det_texts), det_texts
        assert any("CORE_TIME_BUDGET" in txt for txt in det_texts), det_texts
    finally:
        view.deleteLater()


def test_copy_with_feedback_safe_on_delete_and_double_click(qapp):
    """M4: _copy_with_feedback darf weder bei Doppelklick Text ueberschreiben noch
    bei geloeschtem Button einen RuntimeError werfen."""
    from PySide6.QtWidgets import QPushButton

    from malaz.gui.detail_view import _copy_with_feedback

    btn = QPushButton("Kopieren")
    _copy_with_feedback(btn, "abc123")
    assert btn.text() == "Kopiert"
    _copy_with_feedback(btn, "abc123")  # double click
    assert btn.property("_orig_copy_text") == "Kopieren"

    # Trigger timer directly and confirm original text restores cleanly
    btn._copy_timer.timeout.emit()
    assert btn.text() == "Kopieren"

    # Delete button while timer is running -> child timer is destroyed with button
    _copy_with_feedback(btn, "xyz")
    btn.deleteLater()
    qapp.processEvents()


def test_mail_engine_strip_never_all_green_on_av_gap_or_header_issues(qapp):
    """B2: Mail-Karten duerfen bei AV-Skip/Fehler, MAIL_AUTH_CLAIM_UNBACKED,
    MAIL_REPLY_TO_MISMATCH oder unvollstaendiger Mail nicht alle 3 gruen sein."""
    from malaz.gui.engine_strip import _cards_for_archive, _cards_for_mail
    from malaz.models import EngineVerdict, Indicator, RiskLevel, ScanResult, Severity

    # 1. Direct AV error/skip on .eml with sender=="ok", no attachments, no links
    res_gap = ScanResult(
        path="mail.eml",
        detected_type="eml",
        mail_security={"sender": "ok"},
        engine_verdicts=[
            EngineVerdict(engine="defender", state="skipped", label="Ausgelassen", detail="Nur-Statik")
        ],
        indicators=[
            Indicator(rule_id="AV_SKIPPED", title="AV uebersprungen", severity=Severity.INFO, weight=0)
        ],
    )
    cards_gap = _cards_for_mail(res_gap)
    assert all(c[3] != "ok" for c in cards_gap), cards_gap

    # 2. MAIL_AUTH_CLAIM_UNBACKED
    res_unbacked = ScanResult(
        path="mail2.eml",
        detected_type="eml",
        mail_security={"sender": "ok"},
        indicators=[
            Indicator(
                rule_id="MAIL_AUTH_CLAIM_UNBACKED",
                title="Unbelegte Auth",
                severity=Severity.LOW,
                weight=10,
            )
        ],
    )
    assert _cards_for_mail(res_unbacked)[0][3] == "warn"
    assert _cards_for_mail(res_unbacked)[0][4] is True

    # 3. MAIL_REPLY_TO_MISMATCH
    res_rt = ScanResult(
        path="mail3.eml",
        detected_type="eml",
        mail_security={"sender": "ok"},
        indicators=[
            Indicator(
                rule_id="MAIL_REPLY_TO_MISMATCH",
                title="Reply-To abweichend",
                severity=Severity.MEDIUM,
                weight=20,
            )
        ],
    )
    assert _cards_for_mail(res_rt)[0][3] == "warn"

    # 4. N1: Archive card shows bad_kids[0].display_name and surfaces both bad_n and warn_n
    clean_kid = ScanResult(path="harmlos.txt", detected_type="text", risk_level=RiskLevel.GREEN, score=0)
    warn_kid = ScanResult(path="komisch.doc", detected_type="ole", risk_level=RiskLevel.YELLOW, score=35)
    bad_kid = ScanResult(path="trojaner.exe", detected_type="pe", risk_level=RiskLevel.RED, score=90)
    arch = ScanResult(
        path="paket.zip",
        detected_type="zip",
        risk_level=RiskLevel.RED,
        score=90,
        children=[clean_kid, warn_kid, bad_kid],
    )
    c1 = _cards_for_archive(arch)[0]
    assert "trojaner.exe" in c1[2], c1
    assert "1 auffällig" in c1[1], c1


def test_cancel_state_truncation_banner_settings_key_and_export_suffix(window, tmp_path, monkeypatch):
    """B3, B4, M2, M3, N3: Cancel-Zaehlung, sichtbares Truncation-Banner, QSettings-Key,
    _effective_dispatcher-Wiederverwendung, Export-Endung und closeEvent Hard-Shutdown."""
    from PySide6.QtWidgets import QFileDialog

    from malaz import config
    from malaz.gui.file_tree import STATE_ROLE
    from malaz.gui.settings import app_settings
    from malaz.models import RiskLevel, ScanResult

    # B4: QSettings key must be "clamav_auto_update"
    window.chk_clam_auto.setChecked(True)
    assert app_settings().value("clamav_auto_update", False, bool) is True

    # M2: _effective_dispatcher preserves yara & external_scanners
    sentinel_ext = [object()]
    window.dispatcher.external_scanners = sentinel_ext  # type: ignore[assignment]
    window.chk_static_only.setChecked(True)
    eff = window._effective_dispatcher()
    assert eff.yara is window.dispatcher.yara
    assert eff.external_scanners == sentinel_ext
    assert eff.av_scanner.enabled is False and eff.clam_scanner.enabled is False
    window.chk_static_only.setChecked(False)

    # B3: Visible truncation banner when MAX_BATCH_FILES reached
    monkeypatch.setattr(config, "MAX_BATCH_FILES", 2)
    files = []
    for i in range(3):
        f = tmp_path / f"f{i}.txt"
        f.write_text("hi", encoding="utf-8")
        files.append(str(f))
    window.add_paths(files)
    assert window._batch_truncated is True
    assert window._truncation_banner.isVisibleTo(window) is True

    # N3: Cancelled items never green and counted in unk chip
    window.table.mark_pending_as_scanning()
    window._on_finished(cancelled=True)
    assert window.table.topLevelItem(0).data(0, STATE_ROLE) == "cancelled"
    assert window._chip_unk._lbl.text() == "2"

    # M3 part 1: _on_export_report enforces filter suffix
    window._results = [
        ScanResult(path=str(files[0]), detected_type="text", risk_level=RiskLevel.GREEN, score=0)
    ]
    captured_jobs: list[object] = []
    monkeypatch.setattr(window.thread_pool, "start", lambda job: captured_jobs.append(job))

    for chosen_path, chosen_filter, expected_suffix, expected_pdf in [
        (str(tmp_path / "bericht"), "CSV-Tabelle (*.csv)", ".csv", False),
        (str(tmp_path / "malaz_bericht.html"), "PDF-Bericht (*.pdf)", ".pdf", True),
        (str(tmp_path / "out"), "JSON-Export (*.json)", ".json", False),
    ]:
        window._export_running = False
        monkeypatch.setattr(
            QFileDialog, "getSaveFileName", lambda *_a, p=chosen_path, f=chosen_filter: (p, f)
        )
        window._on_export_report()
        job = captured_jobs[-1]
        assert job.path.lower().endswith(expected_suffix), (job.path, expected_suffix)
        assert job.as_pdf is expected_pdf


def test_close_event_keeps_hard_shutdown_when_pool_times_out(qapp, monkeypatch):
    """M3 part 2: closeEvent ruft thread_pool.clear() und behaelt hard_shutdown aktiv,
    wenn waitForDone(5000) False liefert."""
    from malaz import procio
    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher
    from malaz.gui.main_window import MainWindow

    disp = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    w = MainWindow(dispatcher=disp)
    cleared = []

    class _DummyWorker:
        def cancel(self):
            pass

    w._worker = _DummyWorker()  # type: ignore[assignment]
    monkeypatch.setattr(w.thread_pool, "clear", lambda: cleared.append(True))
    monkeypatch.setattr(w.thread_pool, "waitForDone", lambda _ms: False)
    try:
        w.close()
        assert cleared == [True]
        assert procio.hard_shutdown_requested() is True
    finally:
        procio.clear_hard_shutdown()


def test_batch_summary_blocks_unc_before_filesystem_and_uses_source_paths(qapp, tmp_path, monkeypatch):
    """B4 part 3: BatchSummary darf bei UNC-Pfaden niemals Path.is_dir() rufen und
    nutzt source_paths trotz OpSec-Basename-Kuerzung."""
    from pathlib import Path as _Path

    from malaz.gui.batch_summary import BatchSummary
    from malaz.models import RiskLevel, ScanResult

    summary = BatchSummary()
    try:
        probed: list[str] = []
        orig_is_dir = _Path.is_dir

        def spy_is_dir(self):
            probed.append(str(self))
            return orig_is_dir(self)

        monkeypatch.setattr(_Path, "is_dir", spy_is_dir)
        unc_path = "\\\\evil-smb\\share\\doc.pdf"
        unc_res = ScanResult(path=unc_path, detected_type="pdf", risk_level=RiskLevel.GREEN)
        summary.update_results([unc_res], source_paths=[unc_path])
        assert probed == [], f"UNC-Pfad hat Dateisystem beruehrt: {probed}"
        assert summary.common_directory is None

        # Local source_paths resolve common_directory even when result.path is basename only
        local_file = tmp_path / "probe.pdf"
        local_file.write_bytes(b"%PDF-1.7")
        basenamed = ScanResult(path="probe.pdf", detected_type="pdf", risk_level=RiskLevel.GREEN)
        summary.update_results([basenamed], source_paths=[str(local_file)], truncated=True)
        assert summary.common_directory == str(tmp_path)
        assert summary._trunc_banner.isVisibleTo(summary) is True
    finally:
        summary.deleteLater()


def test_footer_summary_extract_iocs_and_options_view_contracts(qapp):
    """M5, M6, N4: build_footer_summary (5 Zustaende), _extract_iocs (Defang, Cap 100,
    kein ReDoS) und OptionsView-Badge + HTML-Escaping im Tooltip."""
    import time

    from malaz.gui.detail_view import _extract_iocs, build_footer_summary
    from malaz.gui.options_view import OptionsView
    from malaz.gui.score_ring import ToggleSwitch
    from malaz.models import CAT_IOC, Indicator, RiskLevel, ScanResult, Severity

    # build_footer_summary across 5 states
    ok_pe = ScanResult(path="a.exe", detected_type="pe", risk_level=RiskLevel.GREEN, score=0)
    assert "Typ: EXE" in build_footer_summary(ok_pe) and "Prüfung: Vollständig" in build_footer_summary(ok_pe)
    bad_pdf = ScanResult(path="b.pdf", detected_type="pdf", risk_level=RiskLevel.RED, score=80)
    assert "Prüfung: Vollständig" in build_footer_summary(bad_pdf)
    warn_inc = ScanResult(
        path="c.pdf",
        detected_type="pdf",
        risk_level=RiskLevel.YELLOW,
        score=30,
        indicators=[Indicator(rule_id="AV_SKIPPED", title="skip", severity=Severity.INFO, weight=0)],
    )
    assert "Prüfung: Teilweise" in build_footer_summary(warn_inc)
    unk_res = ScanResult(
        path="d.bin",
        detected_type="unknown",
        risk_level=RiskLevel.GREEN,
        score=0,
        indicators=[Indicator(rule_id="AV_SKIPPED", title="skip", severity=Severity.INFO, weight=0)],
    )
    assert "Prüfung: Unvollständig" in build_footer_summary(unk_res)
    enc_zip = ScanResult(
        path="e.zip",
        detected_type="zip",
        risk_level=RiskLevel.GREEN,
        score=0,
        indicators=[Indicator(rule_id="ARCH_ENCRYPTED", title="enc", severity=Severity.INFO, weight=0)],
    )
    assert "Prüfung: Gesperrt" in build_footer_summary(enc_zip)

    # _extract_iocs: defang + 100 cap + ReDoS immunity
    many = [
        Indicator(
            rule_id=f"URL_{i}",
            category=CAT_IOC,
            title="Link",
            detail=f"https://bad{i}.example.test/p",
            severity=Severity.MEDIUM,
            weight=10,
        )
        for i in range(120)
    ]
    many.append(
        Indicator(
            rule_id="MAIL_REPLY_TO_MISMATCH",
            category=CAT_IOC,
            title="Reply",
            detail="a" * 8000 + "@" + "." * 8000,
            severity=Severity.MEDIUM,
            weight=10,
        )
    )
    t0 = time.perf_counter()
    rows, overflow = _extract_iocs(ScanResult(path="x.eml", detected_type="eml", indicators=many))
    elapsed = time.perf_counter() - t0
    assert elapsed < 0.2, f"ReDoS-Verdacht: {elapsed:.3f}s"
    assert len(rows) == 100 and overflow == 20
    assert rows[0][3].startswith("hxxps://")

    # OptionsView header badge + tooltip HTML escaping
    keys = ("clam_auto", "feeds_auto", "dns_auth", "capa", "static_only", "auto_open")
    sw = {k: ToggleSwitch() for k in keys}
    ov = OptionsView(sw)
    try:
        assert "komplett offline" in ov._net_status_lbl.text().lower()
        sw["dns_auth"].setChecked(True)
        assert "opt-in aktiv" in ov._net_status_lbl.text().lower()
        ov.refresh(feed_tooltip="<img src=x onerror=alert(1)>")
        assert "&lt;img" in ov._db_label.toolTip()
    finally:
        ov.deleteLater()
