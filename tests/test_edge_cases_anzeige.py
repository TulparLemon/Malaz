"""Randfälle der neuen Anzeigen und der DNS-Stufe.

Die Hauptpfade sind in test_gui/test_dns_auth/test_incomplete_display belegt.
Hier stehen die Fälle, die man beim Schreiben nicht vor Augen hat und die
deshalb gern durchrutschen: leere Ergebnisse, ein Filter, der nur das KIND
trifft, Sortierung mit Kindern, sehr lange Notizen, ein Kind ohne eigene
Befunde.
"""

from __future__ import annotations

import logging
import zipfile

import pytest
from PySide6.QtWidgets import QApplication

from malaz.models import CAT_AV, Indicator, RiskLevel, ScanResult, Severity


def _ergebnis(rule_ids=(), level=RiskLevel.GREEN, score=0) -> ScanResult:
    r = ScanResult(path="probe.bin")
    r.score = score
    r.risk_level = level
    r.indicators = [
        Indicator(
            rule_id=rid,
            title=f"Stufe {rid}",
            detail="",
            severity=Severity.INFO,
            category=CAT_AV,
            weight=0,
        )
        for rid in rule_ids
    ]
    return r


# -- Modell ---------------------------------------------------------------- #


def test_ergebnis_ohne_befunde_ist_vollstaendig():
    """Ein leeres Ergebnis ist nicht 'unvollständig' — es ist leer."""
    r = _ergebnis()
    assert r.is_incomplete is False
    assert r.incompleteness_note() == ""


def test_sehr_viele_stufen_ergeben_eine_lesbare_notiz():
    """25 Ausfälle dürfen die Notiz nicht sprengen — sie geht in Panel,
    Bericht und Protokoll, und ein Roman ist dort unbrauchbar."""
    r = _ergebnis(["AV_SKIPPED"] + ["OFFICE_LIB_MISSING"] * 24)
    notiz = r.incompleteness_note()
    assert notiz
    assert len(notiz) < 2000, f"Notiz hat {len(notiz)} Zeichen"
    assert "UNVOLLSTÄNDIG" in notiz


def test_kind_ohne_befunde_erbt_nichts_vom_elternteil():
    """Das Elternteil ist unvollständig, das Kind nicht — jedes für sich."""
    aussen = _ergebnis(["YARA_SCAN_ERROR"])
    innen = _ergebnis()
    aussen.children = [innen]
    assert aussen.is_incomplete is True
    assert innen.is_incomplete is False


def test_tiefe_verschachtelung_im_protokoll_bleibt_eine_zeile(caplog):
    """200 Archivmitglieder dürfen das Protokoll nicht fluten.

    Eine Zeile je Datei, auch wenn alles lief: eine LÜCKE ist in einem
    Protokoll nur erkennbar, wenn die vollständigen Fälle danebenstehen.
    """
    from malaz.core.dispatcher import Dispatcher

    wurzel = _ergebnis()
    aktuell = wurzel
    for i in range(200):
        kind = _ergebnis(["DIE_SKIPPED"] if i == 150 else [])
        aktuell.children = [kind]
        aktuell = kind

    d = Dispatcher.__new__(Dispatcher)
    with caplog.at_level(logging.INFO, logger="malaz.core.dispatcher"):
        d._log_stages(wurzel)
    zeilen = [z for z in caplog.text.splitlines() if "Stufen" in z]
    assert len(zeilen) == 1, f"{len(zeilen)} Zeilen fuer 201 Ergebnisse"
    assert "UNVOLLSTÄNDIG" in zeilen[0]
    assert "1 Stufe" in zeilen[0], "die Zahl der Luecken stimmt nicht"


# -- Filter und Sortierung im Baum ----------------------------------------- #


@pytest.fixture
def archiv_fenster(window, qtbot, tmp_path):
    """Ein Archiv mit einem harmlosen und einem bösen Mitglied."""
    z = tmp_path / "paket.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("harmlos.txt", "nur text")
        zf.writestr("findmich_boese.pdf", b"%PDF-1.7\n/Launch\n%%EOF")
    window.add_paths([str(z)])
    window._on_scan()
    qtbot.waitUntil(lambda: window._worker is None, timeout=60_000)
    return window


def test_suche_nach_dem_kind_laesst_das_archiv_stehen(archiv_fenster):
    """Der Fall, den ein naiver Filter falsch macht.

    Wer nach einem Mitglied sucht, meint das MITGLIED. Verschwände dabei das
    Archiv, wäre die Trefferzeile aus der Liste — und mit ihr der einzige Weg
    dorthin.
    """
    w = archiv_fenster
    oben = w.table.topLevelItem(0)
    kinder = [oben.child(i).text(0) for i in range(oben.childCount())]

    w.search_box.setText("findmich")
    w._apply_filter()

    assert not oben.isHidden(), "das Archiv verschwand, obwohl sein Kind passt"
    assert oben.child(kinder.index("findmich_boese.pdf")).isHidden() is False
    assert oben.child(kinder.index("harmlos.txt")).isHidden() is True


def test_suche_nach_dem_archiv_versteckt_die_kinder(archiv_fenster):
    """Die Gegenrichtung: passt nur der Elternteil, sind die Kinder weg."""
    w = archiv_fenster
    oben = w.table.topLevelItem(0)

    w.search_box.setText("paket")
    w._apply_filter()

    assert not oben.isHidden()
    versteckt = [oben.child(i).isHidden() for i in range(oben.childCount())]
    assert all(versteckt), f"Kinder ohne Treffer blieben sichtbar: {versteckt}"


def test_sortierung_ordnet_nur_die_oberste_ebene(archiv_fenster):
    """Kinder behalten die SCAN-Reihenfolge.

    Eine Umsortierung der Mitglieder nach Spalte wäre irreführend: die
    Reihenfolge im Archiv ist die Reihenfolge, in der es aufgebaut wurde, und
    wer sie nach Score umsortiert, verliert genau diese Information.
    """
    from PySide6.QtCore import Qt

    w = archiv_fenster
    oben = w.table.topLevelItem(0)
    vorher = [oben.child(i).text(0) for i in range(oben.childCount())]

    w.table.sortItems(0, Qt.SortOrder.DescendingOrder)

    nachher = [oben.child(i).text(0) for i in range(oben.childCount())]
    assert nachher == vorher, "die Mitglieder wurden umsortiert"


def test_leeres_archiv_hat_keine_kinder(archiv_fenster, window, qtbot, tmp_path):
    """Ein Archiv ohne Mitglieder ist kein Fehler — es hat nur nichts."""
    z = tmp_path / "leer.zip"
    with zipfile.ZipFile(z, "w"):
        pass
    window.add_paths([str(z)])
    window._on_scan()
    qtbot.waitUntil(lambda: window._worker is None, timeout=60_000)

    neueste = window.table.topLevelItem(window.table.topLevelItemCount() - 1)
    assert neueste.childCount() == 0
    assert neueste.text(0) == "leer.zip"


# -- Layout: die Quick Wins aus der Design-Durchsicht ---------------------- #


def test_warteschlange_schrumpft_wenn_sie_leer_ist(window, tmp_path):
    """In Klare Flaeche v2 gibt es keinen 110 px hohen leeren Warteschlangen-Kasten mehr.

    Dateien landen direkt im linken Dateibaum; im Leerzustand zeigt die rechte
    Flaeche die Drop-Zone, und beim Leeren geht der Baum wieder sauber auf 0.
    """
    assert not hasattr(window, "file_list")
    assert window.table.topLevelItemCount() == 0
    assert window._pages.currentIndex() == 0

    p = tmp_path / "etwas.txt"
    p.write_text("text", encoding="utf-8")
    window.add_paths([str(p)])
    assert window.table.topLevelItemCount() == 1

    window._on_clear()
    assert window.table.topLevelItemCount() == 0
    assert window._pages.currentIndex() == 0


def test_fortschrittsbalken_ist_im_ruhezustand_weg(window):
    """Er stand dauerhaft in der Knopfreihe und draengte die Knoepfe zusammen.

    Jetzt hat er eine eigene Zeile und erscheint nur waehrend eines Laufs.
    """
    assert window.progress.isVisible() is False


def test_fortschrittsbalken_liegt_unter_der_knopfreihe(window):
    """Die Trennung von Aktionen und Fortschritt ist der ganze Punkt.

    Gemessen wird im SICHTBAREN Zustand in Fensterkoordinaten: der
    Fortschrittsbalken im Scan-Banner sitzt sauber unter der oberen Topbar.
    """
    from PySide6.QtCore import QPoint

    window.show()
    window.scan_banner.show()
    window.progress.show()
    window.progress.setValue(50)
    QApplication.processEvents()

    topbar_unten = window.btn_options.mapTo(window, QPoint(0, window.btn_options.height())).y()
    footer_oben = min(
        b.mapTo(window, QPoint(0, 0)).y()
        for b in (window.btn_add, window.btn_add_folder, window.btn_scan, window.btn_clear)
    )
    balken_oben = window.progress.mapTo(window, QPoint(0, 0)).y()
    balken_unten = window.progress.mapTo(window, QPoint(0, window.progress.height())).y()
    assert balken_oben >= topbar_unten, (
        f"der Fortschrittsbalken steht in der Topbar "
        f"(Balken oben {balken_oben}, Topbar unten {topbar_unten})"
    )
    assert balken_unten <= footer_oben, (
        f"der Fortschrittsbalken ueberlappt die Fusszeilen-Knoepfe "
        f"(Balken unten {balken_unten}, Fusszeile oben {footer_oben})"
    )


def test_laienansicht_zeigt_keine_rohe_werkzeugausgabe():
    """Der erste Block unter „Was gefunden wurde" war MpCmdRun-Text.

    GEMESSEN im gerenderten Fenster: "Scanning C:\\... found no threats",
    "----------- SCAN SUMMARY -----------", "Infected files: 0", Start/End
    Date. Für den Laien ist das Rauschen, und es begräbt die echten Befunde
    darunter. Die vollständige Ausgabe steht ohnehin wörtlich in malaz.log
    (analysis/windows_av: "logged verbatim so a wrong verdict can be
    diagnosed").
    """
    from malaz.core.dispatcher import Dispatcher
    from malaz.gui.main_window import _format_detail

    class _Av:
        clean = True
        threat_found = False
        remediated = False
        detail = (
            "Scanning C:\\temp\\x found no threats.\n"
            "--- SCAN SUMMARY ---\nInfected files: 0"
        )
        threat_name = ""

    r = ScanResult(path="probe.bin")
    r.score = 0
    d = Dispatcher.__new__(Dispatcher)
    ind = d._av_indicator(_Av())
    assert "SCAN SUMMARY" not in ind.detail, "die rohe Ausgabe steht wieder im Befund"

    r.indicators = [ind]
    text = _format_detail(r)
    for werkzeug_text in ("SCAN SUMMARY", "Infected files", "Scanning C:"):
        assert werkzeug_text not in text, f"Werkzeugausgabe in der Laienansicht: {werkzeug_text}"
    assert "nichts gefunden" in text, "die Aussage fehlt ganz"


def test_externe_engine_protokolliert_ihre_rohausgabe(caplog, monkeypatch, tmp_path):
    """Bevor das CLEAN-Detail gekürzt wird, muss die Ausgabe IRGENDWO stehen.

    GEMESSEN: ``analysis/external_scanner.py`` hatte einen Logger, der nirgends
    aufgerufen wurde — die Rohausgabe eines externen Scanners stand damit
    ausschliesslich im Befund-Detail. Wer das Detail kürzt (wie bei AV_CLEAN
    und CLAMAV_CLEAN geschehen), verliert sie dann VOLLSTÄNDIG statt nur aus
    der Laienansicht, und ein falsches Urteil ist nicht mehr nachvollziehbar.

    Geprüft wird das VERHALTEN: ein Scan, der etwas ausgibt, muss es ins
    Protokoll schreiben.
    """
    from malaz.analysis import external_scanner as mod

    class _R:
        returncode = 0

    rohausgabe = b"FremdScanner: SCAN SUMMARY Infected files: 0 (rc=0)"
    monkeypatch.setattr(mod, "run_tool", lambda *a, **k: (_R(), rohausgabe, b""))
    monkeypatch.setattr(mod, "which_absolute", lambda _n: "C:/fake/scanner.exe")

    ziel = tmp_path / "probe.bin"
    ziel.write_bytes(b"daten")
    scanner = mod.ExternalScanner(
        {"name": "FremdScanner", "binary": "scanner.exe", "clean_markers": ["infected files: 0"]}
    )

    with caplog.at_level(logging.INFO, logger="malaz.analysis.external_scanner"):
        ergebnis = scanner.scan_path(ziel)

    assert ergebnis.scanned, "der Scan lief nicht — Testaufbau prüfen"
    assert "SCAN SUMMARY" in caplog.text, (
        "die Rohausgabe steht nirgends im Protokoll; wird das Detail gekürzt, "
        "ist sie ganz verloren"
    )
    assert "FremdScanner" in caplog.text, "die Quelle fehlt in der Zeile"


# -- Die vier "noch offenen" Falschpositive, als Zusicherung ---------------- #


def test_spezifikationskomprimierte_formate_punkten_nicht(tmp_path):
    """Ein JPEG mit hoher Entropie ist der NORMALFALL, kein Befund.

    Die Regel sagt es selbst: "durch das JPEG-Format selbst erklärbar … sie
    allein ist kein Hinweis auf Schadcode". Wer das schreibt, darf dafür
    keine Punkte vergeben — sonst ergeben vier Bilder in einem Dokument 20
    Punkte und damit GELB.
    """
    import random

    from PySide6.QtGui import QColor, QImage

    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher

    random.seed(1)
    img = QImage(160, 160, QImage.Format.Format_RGB32)
    for y in range(160):
        for x in range(160):
            img.setPixelColor(
                x, y, QColor(random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
            )
    p = tmp_path / "foto.jpg"
    img.save(str(p), "JPEG", 95)

    d = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    r = d.scan_path(p)
    treffer = [i for i in r.all_indicators() if i.rule_id == "GEN_ENTROPY"]
    assert treffer, "die Regel feuerte gar nicht — Testaufbau prüfen"
    assert all(i.weight == 0 for i in treffer), (
        f"erklärbare Entropie vergibt {[i.weight for i in treffer]} Punkte"
    )


def test_wenige_bytes_hinter_dem_bildende_punkten_nicht(tmp_path):
    """3 Bytes hinter EOI sind kein Versteck.

    GEMESSEN: `_TRAILER_MIN_BYTES = 64`. Darunter ist es ein Hinweis ohne
    Gewicht — bei einem echten Word-Dokument waren es genau 3 Bytes.
    """
    from PySide6.QtGui import QColor, QImage

    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher

    img = QImage(60, 60, QImage.Format.Format_RGB32)
    for y in range(60):
        for x in range(60):
            img.setPixelColor(x, y, QColor(200, 30, 30))
    p = tmp_path / "bild.jpg"
    img.save(str(p), "JPEG", 90)
    p.write_bytes(p.read_bytes() + b"\x00\x01\x02")

    d = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    r = d.scan_path(p)
    treffer = [i for i in r.all_indicators() if i.rule_id == "JPEG_TRAILER"]
    assert treffer, "die Regel feuerte gar nicht — Testaufbau prüfen"
    assert all(i.weight == 0 for i in treffer)


def test_echte_listenmail_loest_die_drei_regeln_nicht_aus(tmp_path):
    """Eine Mailman-Mail darf nicht als Fälschung gelesen werden.

    Malaz verlangt ZWEI Hinweise (Listen-Kopfzeile UND Listen-Rückkehradresse),
    damit sich ein Angreifer nicht mit einer gefälschten `List-Id` freikauft.

    GEMESSEN mit einer echten Listenmail: `MAIL_RETURN_PATH_MISMATCH` und
    `MAIL_DMARC_ALIGNMENT_FAIL` fallen auf Gewicht 0, `MAIL_REPLY_TO_MISMATCH`
    von 30 auf 5.
    """
    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher

    mail = (
        b"From: Autor <autor@firma.de>\r\nTo: users@httpd.apache.org\r\n"
        b"Subject: Re: Frage\r\nDate: Mon, 1 Jan 2024 10:00:00 +0000\r\n"
        b"Message-ID: <b@firma.de>\r\n"
        b"List-Id: <users.httpd.apache.org>\r\n"
        b"List-Unsubscribe: <mailto:users-unsubscribe@httpd.apache.org>\r\n"
        b"Reply-To: users@httpd.apache.org\r\n"
        b"Received: from mx.apache.org (mx.apache.org [198.51.100.2]) by mx.example; "
        b"Mon, 1 Jan 2024 10:00:01 +0000\r\n"
        b"Return-Path: <users-return-123584-archive@httpd.apache.org>\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\nAntwort\r\n"
    )
    p = tmp_path / "liste.eml"
    p.write_bytes(mail)

    d = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    r = d.scan_path(p)
    gewichte = {i.rule_id: i.weight for i in r.all_indicators()}
    assert gewichte.get("MAIL_RETURN_PATH_MISMATCH", 0) == 0
    assert gewichte.get("MAIL_DMARC_ALIGNMENT_FAIL", 0) == 0
    assert gewichte.get("MAIL_REPLY_TO_MISMATCH", 0) <= 5, gewichte


def test_yahoo_groups_kopf_wird_als_liste_erkannt(tmp_path):
    """Ein Yahoo-Groups-Kopf ist eine Liste — auch ohne ``List-Id``.

    GEMESSEN vorher: Score **80/RED**. Die echte Rückkehradresse lautet
    ``sentto-12345-6789-absender=domain@returns.groups.yahoo.com`` — sie trägt
    kein ``-admin@``/``-bounces@``/``-return-``, das Muster griff dort also
    nicht, und ``Mailing-List:`` stand nicht in der Kopfzeilenliste. Beide
    Regeln feuerten voll.

    Jetzt dieselbe Entschärfung wie beim Mailman-Fall: 30 → 5 und 15 → 0.
    """
    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher

    mail = (
        b"From: kollege@firma.de\r\nTo: gruppe@yahoogroups.com\r\nSubject: Runde 3\r\n"
        b"Date: Mon, 1 Jan 2024 10:00:00 +0000\r\nMessage-ID: <a@firma.de>\r\n"
        b"Mailing-List: list gruppe@yahoogroups.com; contact gruppe-owner@yahoogroups.com\r\n"
        b"Reply-To: gruppe@yahoogroups.com\r\n"
        b"Received: from mx.firma.de (mx.firma.de [198.51.100.1]) by mx.example; "
        b"Mon, 1 Jan 2024 10:00:01 +0000\r\n"
        b"Return-Path: <sentto-12345-6789-kollege=firma.de@returns.groups.yahoo.com>\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\nHallo zusammen\r\n"
    )
    p = tmp_path / "yahoo.eml"
    p.write_bytes(mail)

    d = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    r = d.scan_path(p)
    gewichte = {i.rule_id: i.weight for i in r.all_indicators()}
    assert gewichte.get("MAIL_DMARC_ALIGNMENT_FAIL", 0) == 0, gewichte
    assert gewichte.get("MAIL_REPLY_TO_MISMATCH", 0) <= 5, gewichte


def test_gefaelschte_listen_kopfzeile_kauft_sich_nicht_frei(tmp_path):
    """Die Gegenprobe: EIN Hinweis genügt nicht.

    Ein Angreifer schreibt ``List-Id`` in eine Phishing-Mail. Wenn das allein
    schon als Liste durchginge, fielen ``MAIL_REPLY_TO_MISMATCH`` und
    ``MAIL_DMARC_ALIGNMENT_FAIL`` gratis weg — genau die BEC-Fälle, die diese
    Regeln fangen sollen. Deshalb braucht es ZWEI unabhängige Hinweise.
    """
    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher

    mail = (
        b"From: Chef <chef@firma.de>\r\nTo: buchhaltung@firma.de\r\n"
        b"Subject: Dringende Zahlung\r\nDate: Mon, 1 Jan 2024 10:00:00 +0000\r\n"
        b"Message-ID: <x@boese.example>\r\n"
        b"List-Id: <liste.example.org>\r\n"
        b"Reply-To: konto@boese.example\r\n"
        b"Received: from mx.boese.example (mx.boese.example [203.0.113.9]) by mx.example; "
        b"Mon, 1 Jan 2024 10:00:01 +0000\r\n"
        b"Return-Path: <chef@firma.de>\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\nZahlen Sie bitte\r\n"
    )
    p = tmp_path / "bec.eml"
    p.write_bytes(mail)

    d = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    r = d.scan_path(p)
    gewichte = {i.rule_id: i.weight for i in r.all_indicators()}
    assert gewichte.get("MAIL_REPLY_TO_MISMATCH", 0) == 30, (
        f"eine gefälschte List-Id entschärfte die BEC-Regel: {gewichte}"
    )


def test_zaehlpixel_wird_gemeldet(tmp_path):
    """``MAIL_HTML_TRACKING_PIXEL`` war die EINZIGE Regel ohne jede Abdeckung.

    GEMESSEN: 129 Regeln feuern über den Korpus, 20 weitere sind nur unter
    Bedingungen erreichbar, die er nicht fährt (capa aus, DNS aus) — 19 davon
    sind wenigstens unit-getestet. Diese eine war weder im Korpus noch in
    einem Test: sie konnte unbemerkt verschwinden.

    Ein 1x1-Bild im HTML-Teil meldet dem Absender, dass die Mail geöffnet
    wurde. Gewicht 0 — es ist ein Hinweis auf den Absender, kein Befund über
    die Gefährlichkeit.
    """
    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher

    html = (
        b"<html><body><p>Angebot ansehen</p>"
        b'<img src="http://zaehler.example/p.gif" width="1" height="1" alt="">'
        b"</body></html>"
    )
    mail = (
        b"From: werbung@firma.de\r\nTo: ich@example.org\r\nSubject: Angebot\r\n"
        b"Date: Mon, 1 Jan 2024 10:00:00 +0000\r\nMessage-ID: <t@firma.de>\r\n"
        b"Received: from mx.firma.de (mx.firma.de [198.51.100.1]) by mx.example; "
        b"Mon, 1 Jan 2024 10:00:01 +0000\r\n"
        b"Return-Path: <werbung@firma.de>\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/alternative; boundary="G"\r\n\r\n'
        b"--G\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nAngebot ansehen\r\n"
        b"--G\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" + html + b"\r\n--G--\r\n"
    )
    p = tmp_path / "werbung.eml"
    p.write_bytes(mail)

    d = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    r = d.scan_path(p)
    treffer = [i for i in r.indicators if i.rule_id == "MAIL_HTML_TRACKING_PIXEL"]
    assert treffer, "das Zählpixel wurde nicht gemeldet"
    assert treffer[0].weight == 0, "ein Zählpixel darf die Note nicht treiben"


def test_gewoehnliches_bild_ist_kein_zaehlpixel(tmp_path):
    """Die Gegenprobe: ein normales Bild im Newsletter darf nicht anschlagen.

    Sonst feuerte die Regel auf jeder Werbemail, und der Hinweis wäre
    Rauschen.
    """
    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher

    html = (
        b"<html><body><p>Angebot</p>"
        b'<img src="http://cdn.example/banner.png" width="600" height="200" alt="Angebot">'
        b"</body></html>"
    )
    mail = (
        b"From: werbung@firma.de\r\nTo: ich@example.org\r\nSubject: Angebot\r\n"
        b"Date: Mon, 1 Jan 2024 10:00:00 +0000\r\nMessage-ID: <t2@firma.de>\r\n"
        b"Received: from mx.firma.de (mx.firma.de [198.51.100.1]) by mx.example; "
        b"Mon, 1 Jan 2024 10:00:01 +0000\r\n"
        b"Return-Path: <werbung@firma.de>\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/alternative; boundary="G"\r\n\r\n'
        b"--G\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nAngebot\r\n"
        b"--G\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" + html + b"\r\n--G--\r\n"
    )
    p = tmp_path / "banner.eml"
    p.write_bytes(mail)

    d = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    r = d.scan_path(p)
    assert not [i for i in r.indicators if i.rule_id == "MAIL_HTML_TRACKING_PIXEL"]
