"""Die sichere Mail-Anzeige: Inhalt, Grenzen, Edge Cases.

Verlangt war: eine gedroppte .eml soll man ansehen koennen, OHNE sie zu
oeffnen. Dieses Fenster ist die Antwort — und die Tests hier halten fest, was
es NICHT tut: kein Mailprogramm, keine Ausfuehrung, kein Netz.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import QLabel

from malaz.gui.mail_viewer_dialog import (
    MAIL_SUFFIXES,
    MailViewerDialog,
    has_mail_suffix,
)

_KETTE = (
    b"Received: from mx.firma.de (mx.firma.de [203.0.113.9]) by p "
    b"with ESMTPS; Tue, 1 Jan 2030 10:00:00 +0000\r\n"
)


def _dialog_text(dialog: MailViewerDialog) -> str:
    return "\n".join(w.text() for w in dialog.findChildren(QLabel))


def test_has_mail_suffix_matches_only_mail_files():
    assert has_mail_suffix("a.eml")
    assert has_mail_suffix("A.EML")
    assert has_mail_suffix(Path("ordner/b.msg"))
    for nicht in ("c.txt", "d.pdf", "e.emlx", "eml", "f.eml.txt"):
        assert not has_mail_suffix(nicht), nicht
    assert set(MAIL_SUFFIXES) == {".eml", ".msg"}


def test_viewer_shows_the_mail_without_opening_it(qtbot, tmp_path):
    """Inhalt und Absender-Urteil stehen da, samt Hinweis was NICHT passiert."""
    pfad = tmp_path / "mail.eml"
    pfad.write_bytes(
        _KETTE
        + b'From: "post@serioese-bank.tld" <boese@evil.tld>\r\n'
        + b"To: opfer@firma.de\r\nSubject: Ihre Rechnung\r\n"
        + b"Message-ID: <x@evil.tld>\r\n\r\nBitte zahlen.\r\n"
    )
    dialog = MailViewerDialog(pfad)
    qtbot.addWidget(dialog)
    text = _dialog_text(dialog)

    # Der Hinweis auf das, was nicht passiert — ohne ihn liest sich die
    # Vorschau wie ein Freispruch.
    assert "NICHT in Ihrem Mailprogramm" in text
    assert "fuehrt nichts aus" in text
    # Der Inhalt.
    assert "Ihre Rechnung" in text
    assert "Bitte zahlen." in text
    # Das Absender-Urteil.
    assert "Absender" in text
    assert "weicht von der Absenderadresse ab" in text or "Name" in text


def test_viewer_says_so_when_the_file_is_not_a_mail(qtbot, tmp_path):
    """Eine .eml, die keine ist, darf nicht als leere Anzeige enden."""
    pfad = tmp_path / "keine.eml"
    pfad.write_bytes(b"\x00\x01\x02 kein MIME \xff\xfe")
    dialog = MailViewerDialog(pfad)
    qtbot.addWidget(dialog)
    text = _dialog_text(dialog)
    # Die Anzeige muss SAGEN, dass es keine Mail ist — und nicht etwa rohe
    # Bytes unter der Ueberschrift "Textinhalt" zeigen.
    assert "keine E-Mail" in text, text[:200]
    assert "Mail-Kopfzeilen" in text, "der Grund fehlt"
    assert "Textinhalt" not in text, "rohe Bytes werden als Mailrumpf gezeigt"
    assert "Scannen Sie sie" in text


def test_viewer_handles_a_missing_file(qtbot, tmp_path):
    """Eine geloeschte Datei darf keine Ausnahme werfen."""
    dialog = MailViewerDialog(tmp_path / "weg.eml")
    qtbot.addWidget(dialog)
    assert "nicht gelesen werden" in _dialog_text(dialog)


def test_viewer_handles_an_empty_file(qtbot, tmp_path):
    pfad = tmp_path / "leer.eml"
    pfad.write_bytes(b"")
    dialog = MailViewerDialog(pfad)
    qtbot.addWidget(dialog)
    text = _dialog_text(dialog)
    assert "keine E-Mail" in text, text[:200]


def test_viewer_does_not_render_html(qtbot, tmp_path):
    """Der HTML-Rumpf wird NIE gerendert — ein Bild darin waere ein Beacon.

    Der Absender erfaehrt damit, dass die Mail gelesen wurde. Deshalb gibt es
    hier kein setHtml und kein QTextBrowser; angezeigt wird Klartext.
    """
    pfad = tmp_path / "html.eml"
    pfad.write_bytes(
        _KETTE
        + b"From: a@firma.de\r\nMessage-ID: <x@firma.de>\r\n"
        + b"MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        + b"<p>Rechnung</p><img src='http://tracker.tld/p.gif' width='1' height='1'>\r\n"
    )
    dialog = MailViewerDialog(pfad)
    qtbot.addWidget(dialog)

    from PySide6.QtWidgets import QTextBrowser

    assert not dialog.findChildren(QTextBrowser), "es gibt einen HTML-Renderer"
    text = _dialog_text(dialog)
    # Die Adresse steht als TEXT da (der Leser soll sie sehen), aber es gibt
    # kein Bildelement, das sie laden koennte.
    assert "<img" not in text, "Markup wird angezeigt statt Klartext"


def test_viewer_masks_attacker_controlled_text(qtbot, tmp_path):
    """Derselbe Bidi-Schutz wie ueberall sonst."""
    pfad = tmp_path / "bidi.eml"
    pfad.write_bytes(
        _KETTE
        + b'From: "rechnung\xe2\x80\xaegpj.exe" <a@b.de>\r\n'
        + b"Subject: rechnung\xe2\x80\xaegpj.exe\r\n"
        + b"Message-ID: <x@b.de>\r\n\r\nText.\r\n"
    )
    dialog = MailViewerDialog(pfad)
    qtbot.addWidget(dialog)
    texte = [w.text() for w in dialog.findChildren(QLabel) if w.text()]
    assert not [t for t in texte if "\u202e" in t], "U+202E unmaskiert"


def test_viewer_titel_maskiert_und_kuerzt_den_dateinamen(qtbot, tmp_path):
    """BUG-063: der Fenstertitel trug den rohen, angreiferkontrollierten Namen.

    Mit ``Rechnung\\u202egpj.eml`` zeigte die Titelleiste U+202E — Qt wendet den
    Bidi-Algorithmus auch dort an, die Dateiendung wurde also optisch
    umgedreht. Andere Senken im Projekt maskieren und kuerzen.
    """
    pfad = tmp_path / "rechnung\u202egpj.eml"
    pfad.write_bytes(
        _KETTE + b"From: a@b.de\r\nSubject: x\r\nMessage-ID: <x@b.de>\r\n\r\nText.\r\n"
    )
    dialog = MailViewerDialog(pfad)
    qtbot.addWidget(dialog)
    titel = dialog.windowTitle()

    assert "\u202e" not in titel, repr(titel)
    assert "\\u202e" in titel, "der Bidi-Trick wurde entfernt statt sichtbar gemacht"
    assert "rechnung" in titel and "gpj.eml" in titel

    # Auch die Laenge: ein absurd langer Name darf die Titelleiste nicht
    # sprengen. Die Datei muss dafuer nicht existieren — der Titel entsteht
    # vor dem Lesen.
    lang = MailViewerDialog("x" * 60_000 + ".eml")
    qtbot.addWidget(lang)
    assert len(lang.windowTitle()) < 400, (
        f"Titel hat {len(lang.windowTitle())} Zeichen"
    )


def test_viewer_clips_absurdly_long_values(qtbot, tmp_path):
    """Ein 60 000-Zeichen-Betreff darf das Fenster nicht sprengen."""
    pfad = tmp_path / "lang.eml"
    pfad.write_bytes(
        _KETTE
        + b"From: a@b.de\r\nMessage-ID: <x@b.de>\r\nSubject: "
        + b"x" * 60_000
        + b"\r\n\r\nText.\r\n"
    )
    dialog = MailViewerDialog(pfad)
    qtbot.addWidget(dialog)
    laengen = [len(w.text()) for w in dialog.findChildren(QLabel)]
    assert max(laengen) < 5000, f"laengstes Label: {max(laengen)} Zeichen"


def test_viewer_handles_a_msg_container(qtbot, tmp_path):
    """Eine .msg, die kein lesbarer Container ist, sagt das — ohne Absturz."""
    pfad = tmp_path / "kaputt.msg"
    pfad.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 512)
    dialog = MailViewerDialog(pfad)
    qtbot.addWidget(dialog)
    text = _dialog_text(dialog)
    assert text.strip(), "leere Anzeige ohne Erklaerung"
    assert "kein lesbarer Outlook-Container" in text or "keine lesbaren" in text


def test_viewer_shows_unbacked_claims_as_claims(qtbot, tmp_path):
    """Bei ungedeckter Behauptung heisst es 'behauptet', nicht 'bestanden'."""
    pfad = tmp_path / "ungedeckt.eml"
    pfad.write_bytes(
        _KETTE
        + b"From: Firma <service@firma.de>\r\nMessage-ID: <x@firma.de>\r\n"
        + b"Authentication-Results: mx.microsoft.com; spf=pass; dkim=pass; dmarc=pass\r\n"
        + b"\r\nText.\r\n"
    )
    dialog = MailViewerDialog(pfad)
    qtbot.addWidget(dialog)
    text = _dialog_text(dialog)
    assert "SPF: bestanden" not in text, "eine Behauptung wird als Urteil gedruckt"
    assert "behauptet" in text or "nicht beurteilbar" in text


def test_viewer_does_not_read_the_whole_file_into_memory(qtbot, tmp_path):
    """Der Viewer darf eine riesige Datei nicht komplett in den Speicher holen.

    ``read_bytes()[:MAX_READ_SIZE]`` begrenzt nur, was GEPARST wird — gelesen
    war die Datei vorher vollstaendig. Der Knopf erscheint schon bei der Endung
    .eml/.msg (``has_mail_suffix`` sieht die Datei nicht an), also genuegte eine
    beliebig grosse Datei mit dieser Endung. Der Dispatcher liest aus demselben
    Grund begrenzt.

    Geprueft wird STRUKTURELL, nicht ueber die Anzeige: beide Fassungen zeigen
    dasselbe an, ein Unterschied ist am Ergebnis also nicht zu sehen. Genau
    diese Falle hat die Beissprobe aufgedeckt — ein Test, der nur "kein
    Absturz" prueft, blieb bei der Mutation gruen und hielt damit nichts fest.
    Dasselbe Vorgehen wie bei ``test_every_olefile_call_site_is_inside_the_headroom``.

    Dazu der Laufzeitbeleg: eine Datei ueber der Lesegrenze darf das Fenster
    nicht haengen lassen.
    """
    import ast
    from pathlib import Path as _Path

    def unbounded_reads(tree: ast.AST) -> list[ast.Call]:
        """``read_bytes()`` und ``read()``/``read_text()`` OHNE Groessengrenze.

        Der alte Test verbot nur ``.read_bytes``; ``handle.read()`` ohne
        Argument haette 64 MiB am Limit vorbei gelesen und blieb gruen (Audit
        TEST-022). ``read(size)`` bleibt erlaubt — genau die begrenzte Form,
        die der Viewer benutzt.
        """
        findet: list[ast.Call] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr == "read_bytes":
                findet.append(node)
            elif node.func.attr in ("read", "read_text"):
                bounded = bool(node.args) or any(
                    kw.arg in ("size", "n") for kw in node.keywords
                )
                if not bounded:
                    findet.append(node)
        return findet

    # Beissprobe zuerst: der Pruefer muss die Mutation erkennen, sonst ist der
    # strukturelle Test wieder blind.
    mutation = ast.parse(
        "def f(path):\n"
        "    with path.open('rb') as handle:\n"
        "        return handle.read()\n"
    )
    assert unbounded_reads(mutation), "der Pruefer erkennt handle.read() nicht"

    quelle = _Path("src/malaz/gui/mail_viewer_dialog.py").read_text(encoding="utf-8")
    unbegrenzt = unbounded_reads(ast.parse(quelle))
    assert not unbegrenzt, (
        "mail_viewer_dialog liest die Datei unbegrenzt "
        f"({len(unbegrenzt)} Aufruf(e) ohne Groessengrenze) — "
        "stattdessen handle.read(config.MAX_READ_SIZE) wie im Dispatcher"
    )

    # Laufzeitbeleg: eine grosse Datei darf nicht haengen.
    from malaz import config

    pfad = tmp_path / "riesig.eml"
    pfad.write_bytes(b"From: a@b.de\r\n\r\n" + b"x" * (config.MAX_READ_SIZE + 1024))
    dialog = MailViewerDialog(pfad)
    qtbot.addWidget(dialog)
    assert _dialog_text(dialog).strip()


def test_capability_tab_title_follows_the_selection(qtbot):
    """Der Reiter-Titel muss die Anzahl der AUSGEWAEHLTEN Datei zeigen.

    Er wurde nur beim ersten Anlegen gesetzt — danach blieb "Faehigkeiten (8)"
    ueber einem Panel mit 3 Eintraegen stehen. Da capa hier nicht installiert
    ist, sieht das kein Screenshot und kein anderer Test.
    """
    from malaz.gui.main_window import MainWindow
    from malaz.models import RiskLevel, ScanResult

    window = MainWindow()
    qtbot.addWidget(window)

    viel = ScanResult(
        path="a.exe", detected_type="pe", risk_level=RiskLevel.YELLOW, score=30,
        capa_capabilities=[
            {"name": f"Faehigkeit {i}", "namespace": "communication"} for i in range(8)
        ],
    )
    wenig = ScanResult(
        path="b.exe", detected_type="pe", risk_level=RiskLevel.YELLOW, score=30,
        capa_capabilities=[{"name": "Eine", "namespace": "communication"}],
    )
    window._on_result(viel)
    window._on_result(wenig)

    window.table.setCurrentItem(window.table.topLevelItem(0))
    labels = [window.tabs.tabText(i) for i in range(window.tabs.count())]
    assert "Fähigkeiten (8)" in labels, labels

    window.table.setCurrentItem(window.table.topLevelItem(1))
    labels = [window.tabs.tabText(i) for i in range(window.tabs.count())]
    assert "Fähigkeiten (1)" in labels, f"der Titel blieb stehen: {labels}"


# Eine Mail, die eine andere Mail MITSENDET (message/rfc822 mit Dateinamen).
# Der Angreifer legt seinen Text dorthin, wo der Leser den Mailtext erwartet.
_INNERE_MAIL = (
    b"From: innen@boese.example\r\nTo: a@firma.example\r\nSubject: Innen\r\n"
    b"Date: Mon, 1 Jan 2024 10:00:00 +0000\r\nMessage-ID: <in@boese.example>\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n\r\nInhalt der inneren Mail\r\n"
)
_MAIL_MIT_MAIL = (
    b"From: aussen@firma.example\r\nTo: b@firma.example\r\nSubject: Aussen\r\n"
    b"Date: Mon, 1 Jan 2024 10:00:00 +0000\r\nMessage-ID: <au@firma.example>\r\n"
    b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"G\"\r\n\r\n"
    b"--G\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nAussentext\r\n"
    b"--G\r\nContent-Type: message/rfc822\r\n"
    b"Content-Disposition: attachment; filename=\"weiter.eml\"\r\n\r\n"
    + _INNERE_MAIL
    + b"\r\n--G--\r\n"
)


def test_mitgesendete_mail_ist_ein_anhang():
    """GEMESSEN: eine angehaengte .eml fehlte in ``attachment_names`` ganz.

    ``message/rfc822`` ist selbst multipart. Der Sammelcode las den Dateinamen
    erst NACH dem Multipart-Zweig — der macht aber ``continue``. Die
    angehaengte Mail wurde deshalb weiter gereicht und bekam nie einen Namen.
    """
    from malaz.core.eml_analysis import parse_mail

    facts = parse_mail(_MAIL_MIT_MAIL)
    assert facts.attachment_names == ["weiter.eml"]


def test_mitgesendete_mail_bekommt_eigenes_scan_ergebnis():
    """Sie muss als EIGENE Datei gescannt werden, nicht nur angezeigt.

    Die Anzeige allein genuegt nicht: solange die angehaengte .eml kein
    eigenes Ergebnis bekam, wurden ihre Links nicht extrahiert, nicht gegen
    die Blocklisten gehalten und nicht bewertet. Wer seinen Inhalt in eine
    .eml legte, umging die Pruefung — bei sichtbarer Anzeige.
    """
    from malaz.core.email_extract import iter_email_attachments

    namen = [name for name, _payload, _fehler in iter_email_attachments(_MAIL_MIT_MAIL, "eml")]
    assert "weiter.eml" in namen, f"die angehaengte Mail fehlt: {namen}"

    # Und ihr Inhalt reist als Bytes mit, nicht als leerer Eintrag.
    for name, payload, fehler in iter_email_attachments(_MAIL_MIT_MAIL, "eml"):
        if name == "weiter.eml":
            assert not fehler, fehler
            assert b"Inhalt der inneren Mail" in payload


def test_mitgesendete_mail_hat_eigenes_urteil():
    """Ende zu Ende: das Kind traegt die Befunde, nicht der Elternteil.

    Ohne eigenes Ergebnis meldete der Elternteil die Links der angehaengten
    Mail als seine eigenen — der Nutzer saehe die URL, aber nicht, dass sie
    aus einer mitgesendeten Mail stammt.
    """
    import tempfile
    from pathlib import Path

    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher

    aussen = (
        b"From: aussen@firma.example\r\nTo: b@firma.example\r\nSubject: Aussen\r\n"
        b"Date: Mon, 1 Jan 2024 10:00:00 +0000\r\nMessage-ID: <au@firma.example>\r\n"
        b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"G\"\r\n\r\n"
        b"--G\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nAussentext\r\n"
        b"--G\r\nContent-Type: message/rfc822\r\n"
        b"Content-Disposition: attachment; filename=\"weiter.eml\"\r\n\r\n"
        + _INNERE_MAIL.replace(
            b"Inhalt der inneren Mail", b"Schauen: http://boese.example/m.exe"
        )
        + b"\r\n--G--\r\n"
    )
    with tempfile.TemporaryDirectory() as t:
        p = Path(t) / "aussen.eml"
        p.write_bytes(aussen)
        d = Dispatcher(
            av_scanner=WindowsDefenderScanner(enabled=False),
            clam_scanner=ClamAVScanner(enabled=False),
        )
        ergebnis = d.scan_path(p)

    assert len(ergebnis.children) == 1, "die angehaengte Mail wurde nicht gescannt"
    kind = ergebnis.children[0]
    assert kind.display_name == "weiter.eml"
    assert any("LINK" in i.rule_id for i in kind.indicators), (
        "das Kind hat keine Link-Befunde — sein Text wurde nicht geprueft"
    )


def test_gewoehnliche_anlage_bekommt_keine_kennzeichnung():
    """Die Gegenprobe: ein simpler Anhang darf die Markierung nicht erben.

    Sonst stuende der Hinweis an jedem PDF-Anhang, und die Kennzeichnung waere
    nach zwei Wochen Rauschen.
    """
    from malaz.core.eml_analysis import parse_mail

    roh = (
        b"From: a@firma.example\r\nTo: b@firma.example\r\nSubject: X\r\n"
        b"Date: Mon, 1 Jan 2024 10:00:00 +0000\r\nMessage-ID: <x@firma.example>\r\n"
        b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"G\"\r\n\r\n"
        b"--G\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nNur Text\r\n"
        b"--G\r\nContent-Type: application/pdf\r\n"
        b"Content-Disposition: attachment; filename=\"rechnung.pdf\"\r\n\r\n"
        b"PDFBYTES\r\n--G--\r\n"
    )
    facts = parse_mail(roh)
    assert facts.attachment_names == ["rechnung.pdf"]
    assert "Inhalt der angehängten E-Mail" not in facts.text_body


def test_unlesbare_url_liste_wird_nicht_als_geprueft_gemeldet(monkeypatch, tmp_path):
    """BEISSPROBE fuer MAIL_REPUTATION_WARN — die gefaehrlichste der vier.

    Eine vorhandene, aber unlesbare Blocklist wurde zu einer LEEREN Menge:
    ``_lookup_local`` fand nichts, und der Bericht meldete "geprueft, kein
    Treffer". Er behauptete damit eine Pruefung, die nicht stattgefunden
    hatte — schlimmer als gar keine Aussage, weil der Nutzer sich darauf
    verlaesst.
    """
    from pathlib import Path

    from malaz import config
    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core import hashlist, url_reputation
    from malaz.core.dispatcher import Dispatcher

    liste = tmp_path / "urls.sha256"
    liste.write_text("a" * 64 + "\n", encoding="utf-8")
    monkeypatch.setattr(config, "URL_BLOCKLIST_FILE", liste)
    monkeypatch.setattr(config, "DOMAIN_BLOCKLIST_FILE", tmp_path / "d.txt")
    monkeypatch.setattr(config, "IP_BLOCKLIST_FILE", tmp_path / "i.txt")
    monkeypatch.setattr(config, "USER_HASH_BLOCKLIST_FILE", tmp_path / "h.txt")
    monkeypatch.setattr(url_reputation, "local_blocklist_path", lambda: liste)
    monkeypatch.setattr(url_reputation, "enabled", lambda: False)
    hashlist._load_blocklist.cache_clear()

    # Lesbar: der Abgleich laeuft und meldet ehrlich "kein Treffer".
    mail = (
        b"From: a@firma.example\r\nTo: b@firma.example\r\nSubject: T\r\n"
        b"Date: Mon, 1 Jan 2024 10:00:00 +0000\r\nMessage-ID: <x@firma.example>\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Schauen: http://pruefung.example/pfad\r\n"
    )
    p = tmp_path / "m.eml"
    p.write_bytes(mail)
    d = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    lesbar = {i.rule_id for i in d.scan_path(p).indicators}
    assert "MAIL_REPUTATION_WARN" not in lesbar, "falscher Alarm bei lesbarer Liste"

    # Unlesbar: derselbe Ablauf, aber der Fehler muss nach oben.
    echt = Path.read_text

    def kaputt(self, *a, **k):
        if self == liste:
            raise PermissionError(13, "Zugriff verweigert")
        return echt(self, *a, **k)

    monkeypatch.setattr(Path, "read_text", kaputt)
    hashlist._load_blocklist.cache_clear()
    unlesbar = {i.rule_id for i in d.scan_path(p).indicators}

    assert "MAIL_REPUTATION_WARN" in unlesbar, (
        "die unlesbare Liste wurde als 'geprueft, kein Treffer' gemeldet"
    )


def test_mitgesendete_mail_ohne_namen_wird_trotzdem_gekennzeichnet():
    """Der Fall, den die Kennzeichnung vorher NICHT erreichte.

    ``herkunft`` wurde nie gesetzt (Startwert ``""``, unveraendert weiter
    gereicht) — die Kennzeichnung war toter Code. Eine mitgesendete Mail
    OHNE Dateinamen bekam kein eigenes Scan-Ergebnis (core/email_extract
    ueberspringt sie), ihr Text lief also unmarkiert in den Mailtext ein:
    fremder Inhalt las sich als Text der geoeffneten Mail.
    """
    from malaz.core.eml_analysis import parse_mail

    innen = (
        b"From: innen@boese.example\r\nTo: a@firma.example\r\nSubject: Innen\r\n"
        b"Date: Mon, 1 Jan 2024 10:00:00 +0000\r\nMessage-ID: <in@boese.example>\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\nFremder Inhalt\r\n"
    )
    # message/rfc822 OHNE Content-Disposition/filename.
    aussen = (
        b"From: aussen@firma.example\r\nTo: b@firma.example\r\nSubject: Aussen\r\n"
        b"Date: Mon, 1 Jan 2024 10:00:00 +0000\r\nMessage-ID: <au@firma.example>\r\n"
        b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"G\"\r\n\r\n"
        b"--G\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nAussentext\r\n"
        b"--G\r\nContent-Type: message/rfc822\r\n\r\n" + innen + b"\r\n--G--\r\n"
    )
    facts = parse_mail(aussen)
    assert facts.attachment_names == [], "ohne Namen ist sie kein Anhang"
    assert "Fremder Inhalt" in facts.text_body, "der Text ging verloren"
    assert "[Inhalt der angehängten E-Mail:" in facts.text_body, (
        "der fremde Text lief UNMARKIERT in den Mailtext ein"
    )
