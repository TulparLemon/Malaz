"""Tests für die statische .eml-Analyse (Header, Text, Links).

Alle Fixtures sind synthetisch und inert — nichts wird ausgeführt, gerendert
oder abgerufen. Der Reputations-Teil prüft ausdrücklich die
Datenschutz-Eigenschaften (nur Hash, nur opt-in, keine privaten Hosts).
"""

from __future__ import annotations

import os

import pytest

from malaz.core import eml_analysis, url_reputation
from malaz.core.eml_analysis import (
    analyze_body,
    analyze_structure,
    parse_mail,
    risky_attachment_names,
    summarize_links,
)
from malaz.core.scoring import compute_score
from malaz.models import AnalysisContext, RiskLevel
from malaz.pipelines.eml_pipeline import EmlPipeline


def _mail(**headers: str) -> bytes:
    lines = [f"{k.replace('_', '-')}: {v}" for k, v in headers.items()]
    return ("\n".join(lines) + "\n\nTextkörper mit Inhalt.\n").encode("utf-8")


def _ids(indicators) -> set[str]:
    return {i.rule_id for i in indicators}


# -- Parsing ----------------------------------------------------------------- #


def test_parse_extracts_headers_and_body():
    raw = (
        b'From: "Sparkasse Service" <service@sparkasse-sicherheit.tk>\n'
        b"Reply-To: <collect@evil-collector.xyz>\n"
        b"Return-Path: <bounce@spam-host.tk>\n"
        b"To: opfer@example.com\n"
        b"Message-ID: <x@y.tk>\n"
        b"Subject: Dringend\n"
        b"MIME-Version: 1.0\n"
        b'Content-Type: multipart/alternative; boundary="B"\n'
        b"\n"
        b"--B\nContent-Type: text/plain; charset=utf-8\n\nHallo Welt\n"
        b"--B\nContent-Type: text/html; charset=utf-8\n\n<b>Hallo</b>\n"
        b"--B--\n"
    )
    facts = parse_mail(raw)
    assert facts.parse_error == ""
    assert facts.subject == "Dringend"
    assert facts.from_display == "Sparkasse Service"
    assert facts.from_addr == "service@sparkasse-sicherheit.tk"
    assert facts.reply_to == "collect@evil-collector.xyz"
    assert "Hallo Welt" in facts.text_body
    assert "<b>Hallo</b>" in facts.html_body


def test_parse_handles_base64_body():
    import base64

    encoded = base64.b64encode(b"Geheimer Text mit Inhalt").decode()
    raw = (
        "From: a@b.de\nMessage-ID: <x@y>\n"
        "MIME-Version: 1.0\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "Content-Transfer-Encoding: base64\n\n" + encoded + "\n"
    ).encode("utf-8")
    facts = parse_mail(raw)
    # Der Body muss dekodiert vorliegen — sonst sieht jede codierte Mail
    # wie Rauschen aus und die Text-Heuristik greift nie.
    assert "Geheimer Text" in facts.text_body


def test_parse_empty_and_broken_input_never_raises():
    assert parse_mail(b"").parse_error
    assert parse_mail(b"\x00\x01not a mail at all").parse_error == ""


def test_deeply_nested_multipart_does_not_recurse():
    # 200 verschachtelte multipart-Ebenen: iterativer Walk statt Rekursion.
    raw = b"From: a@b.de\nMessage-ID: <x@y>\nMIME-Version: 1.0\n"
    for i in range(200):
        raw += f'Content-Type: multipart/mixed; boundary="B{i}"\n\n--B{i}\n'.encode()
    raw += b"Content-Type: text/plain\n\ntief verschachtelt\n"
    facts = parse_mail(raw)
    assert isinstance(facts.text_body, str)


def test_mime_part_budget_is_visible_not_silent(monkeypatch):
    """BUG-065: >Budget Teile dürfen nicht als sauber durchgehen."""
    raw = (
        b"From: a@b.de\nMessage-ID: <x@y>\nMIME-Version: 1.0\n"
        b'Content-Type: multipart/mixed; boundary="B"\n\n'
        b"--B\nContent-Type: text/plain\n\neins\n"
        b"--B\nContent-Type: text/plain\n\nzwei\n"
        b"--B\nContent-Type: text/plain\n\ndrei\n--B--\n"
    )
    monkeypatch.setattr(eml_analysis.config, "MAIL_MAX_MIME_PARTS", 2)
    facts = parse_mail(raw)
    assert facts.parts_truncated is True

    ctx = AnalysisContext(
        path=__import__("pathlib").Path("budget.eml"),
        data=raw,
        detected_type="eml",
        size=len(raw),
    )
    indicators = EmlPipeline().analyze(ctx)
    assert "MAIL_PARTS_TRUNCATED" in _ids(indicators)
    breakdown = compute_score(indicators)
    assert breakdown.score >= 25
    assert breakdown.risk_level is not RiskLevel.GREEN

    monkeypatch.setattr(eml_analysis.config, "MAIL_MAX_MIME_PARTS", 10)
    assert parse_mail(raw).parts_truncated is False


# -- Body: "ergibt der Text Sinn?" ------------------------------------------- #


def test_body_meaningful_text_is_flagged_readable():
    facts = parse_mail(_mail(From="a@b.de", Message_ID="<x@y>"))
    report = analyze_body(facts)
    assert report.readable is True
    assert report.looks_meaningful is True


def test_body_without_content_is_not_meaningful():
    facts = eml_analysis.MailFacts()
    report = analyze_body(facts)
    assert report.looks_meaningful is False
    assert "Kein Textkörper" in " ".join(report.notes)


def test_body_encoding_garbage_is_flagged_unreadable():
    facts = eml_analysis.MailFacts(text_body="\ufffd" * 60 + "abc")
    report = analyze_body(facts)
    assert report.readable is False


def test_body_detects_lure_and_credential_phrases():
    facts = eml_analysis.MailFacts(
        text_body=(
            "Ihr Konto wurde gesperrt. Bitte bestätigen Sie Ihre Zugangsdaten "
            "und Ihre TAN innerhalb von 24 Stunden."
        )
    )
    report = analyze_body(facts)
    assert "konto wurde gesperrt" in report.lure_hits
    assert "innerhalb von 24 stunden" in report.lure_hits
    assert "tan" in report.credential_hits


def test_body_detects_hidden_text_in_html():
    facts = eml_analysis.MailFacts(
        text_body="normaler Text mit Inhalt",
        html_body='<p style="color:#ffffff">unsichtbar</p>',
    )
    assert analyze_body(facts).hidden_text is True


# -- Struktur ---------------------------------------------------------------- #


def test_structure_detects_reply_to_mismatch():
    facts = eml_analysis.MailFacts(
        from_addr="chef@firma.de",
        reply_to="angreifer@fremd.tk",
        message_id="<x@y>",
        received_count=1,
    )
    kinds = {k for k, _ in analyze_structure(facts).findings}
    assert "MAIL_REPLY_TO_MISMATCH" in kinds


def test_structure_flags_brand_in_display_name_only():
    # Marke im Anzeigenamen, Domain gehört ihr nicht -> Betrugsversuch.
    spoof = eml_analysis.MailFacts(
        from_display="Sparkasse Service",
        from_addr="service@sparkasse-sicherheit.tk",
        message_id="<x@y>",
        received_count=1,
    )
    kinds = {k for k, _ in analyze_structure(spoof).findings}
    assert "MAIL_DISPLAY_NAME_SPOOF" in kinds

    # Echte Marken-Domain darf NICHT anschlagen (sonst False Positive).
    legit = eml_analysis.MailFacts(
        from_display="Sparkasse Service",
        from_addr="service@sparkasse.de",
        message_id="<x@y>",
        received_count=1,
    )
    kinds_legit = {k for k, _ in analyze_structure(legit).findings}
    assert "MAIL_DISPLAY_NAME_SPOOF" not in kinds_legit


def test_structure_reads_authentication_results():
    """Ein Befund fuer die Ursache, die gescheiterten Verfahren im Detail.

    Die Schleife meldete je Verfahren einen eigenen ``MAIL_AUTH_FAIL`` mit
    identischem Titel und Text. Eine Mail, bei der SPF, DKIM und DMARC alle
    scheitern, hat EINE Ursache — der Absender ist nicht, wer er behauptet —,
    zahlte dafuer aber 3 x 15 = 45 Punkte und riss damit jedes weitere
    Fuenf-Punkte-Signal ueber ANCHOR_CRITICAL_SCORE.
    """
    facts = eml_analysis.MailFacts(
        from_addr="a@b.de",
        message_id="<x@y>",
        received_count=1,
        auth_results="mx; spf=fail; dkim=none; dmarc=fail",
    )
    details = [d for k, d in analyze_structure(facts).findings if k == "MAIL_AUTH_FAIL"]
    assert len(details) == 1, details
    assert "SPF" in details[0] and "DMARC" in details[0], details[0]
    assert "DKIM" not in details[0], "nur die GESCHEITERTEN Verfahren nennen"


def test_structure_missing_received_and_message_id():
    facts = eml_analysis.MailFacts(from_addr="a@b.de")
    kinds = {k for k, _ in analyze_structure(facts).findings}
    assert "MAIL_NO_RECEIVED" in kinds
    assert "MAIL_NO_MESSAGE_ID" in kinds


# -- Links ------------------------------------------------------------------- #


def test_links_text_mismatch_is_detected():
    html = '<a href="http://bit.ly/x9f2">https://www.sparkasse.de/konto</a>'
    links = eml_analysis.extract_links("", html)
    by_url = {link.url: link for link in links}
    # Beide URLs werden erfasst: das Linkziel UND der sichtbare Text (der
    # selbst eine URL ist). Entscheidend ist die Zuordnung des Textes.
    assert "http://bit.ly/x9f2" in by_url
    href = by_url["http://bit.ly/x9f2"]
    assert href.is_shortener is True
    assert href.mismatch is True
    assert "sparkasse" in href.display_text


def test_links_classify_ip_punycode_and_risky_tld():
    text = (
        "http://192.168.44.9/login und "
        "http://xn--80ak6aa92e.com/x und "
        "http://angebot.shop.tk/y"
    )
    links = {link.url: link for link in eml_analysis.extract_links(text, "")}
    by_host = {link.host: link for link in links.values()}
    assert by_host["192.168.44.9"].is_ip_literal is True
    assert by_host["xn--80ak6aa92e.com"].is_punycode is True
    assert by_host["angebot.shop.tk"].risky_tld is True


def test_links_classify_bracketed_ipv6_and_reject_impossible_ipv4():
    """BUG-073: ``urlsplit`` strips the IPv6 brackets, so the old bracket
    branch was dead code; ``999.1.1.1`` counted as an IP literal.

    Both directions matter: an IPv6 literal must raise the IP finding, an
    impossible dotted quad must not be treated as an address.
    """
    links = {
        link.host: link
        for link in eml_analysis.extract_links(
            "http://[2001:db8::1]/x und http://999.1.1.1/y", ""
        )
    }
    assert links["2001:db8::1"].is_ip_literal is True
    assert links["999.1.1.1"].is_ip_literal is False
    # Direct forms keep working, including bracketed input.
    assert eml_analysis._is_ip_literal("[::1]") is True
    assert eml_analysis._is_ip_literal("192.168.0.1") is True
    assert eml_analysis._is_ip_literal("256.1.1.1") is False
    # Unicode "digits" are isdigit() but not int()-able; must not raise.
    assert eml_analysis._is_ip_literal("².1.1.1") is False


def test_risky_tld_matches_the_label_not_a_host_suffix():
    """BUG-074: the entry was ``"eat"`` without a dot.

    ``host.endswith("eat")`` flagged ``great``/``intranet-cheat`` while the
    intended ``x.eat`` never matched.
    """
    by_host = {
        link.host: link
        for link in eml_analysis.extract_links(
            "http://great/x http://intranet-cheat.example/y "
            "http://firma.eat/z http://angebot.shop.tk/w",
            "",
        )
    }
    assert by_host["great"].risky_tld is False
    assert by_host["intranet-cheat.example"].risky_tld is False
    assert by_host["firma.eat"].risky_tld is True
    assert by_host["angebot.shop.tk"].risky_tld is True
    # A trailing FQDN dot names the same host.
    assert eml_analysis._has_risky_tld("firma.tk.") is True


def test_links_credentials_in_url_are_flagged():
    links = eml_analysis.extract_links("http://user:pw@evil.example.com/x", "")
    assert links and links[0].has_credentials is True


def test_link_count_is_bounded():
    text = " ".join(f"http://host{i}.example.com/p" for i in range(200))
    assert len(eml_analysis.extract_links(text, "")) <= eml_analysis._MAX_LINKS


def test_summarize_links_returns_string_details():
    links = eml_analysis.extract_links("http://192.168.1.1/a", "")
    for kind, detail in summarize_links(links):
        assert isinstance(kind, str) and isinstance(detail, str)


# -- Anker-Formen: was ein Client als Link aufloest -------------------------- #

# Realistische Ankerformen (Audit-Fund): der Client loest jede der ersten neun
# zu einer Web-Anfrage auf — der Extraktor kannte nur die zwei Schemapraefixe
# und liess die uebrigen stillschweigend fallen. Die hinteren zwoelf sind die
# Gegenseite derselben Tabelle: relative Pfade, Fragmente und Fremdschemata
# benennen keinen fremden Host und duerfen keinen Link erzeugen, sonst schlaegt
# jeder harmlose Newsletter an.
_ANCHOR_FORMS: tuple[tuple[str, str | None], ...] = (
    ("http://evil.tld/login", "http://evil.tld/login"),
    ("https://evil.tld/login", "https://evil.tld/login"),
    ("//evil.tld/login", "http://evil.tld/login"),            # protokoll-relativ
    ("evil.tld/login", "http://evil.tld/login"),              # schema-los
    ("www.evil.tld/login", "http://www.evil.tld/login"),
    ("bit.ly/x9f2", "http://bit.ly/x9f2"),
    ("1.2.3.4/login", "http://1.2.3.4/login"),
    ("xn--80ak6aa92e.com/login", "http://xn--80ak6aa92e.com/login"),
    ("angebot.shop.tk/y", "http://angebot.shop.tk/y"),
    ("images/logo.png", None),
    ("assets/logo.png?v=2", None),
    ("download/rechnung.pdf", None),
    ("v1.2/app.js", None),
    ("./kontakt.html", None),
    ("../kontakt.html", None),
    ("/konto/login", None),
    ("rechnung.pdf", None),
    ("#top", None),
    ("mailto:info@example.de", None),
    ("tel:+4930123", None),
    ("//", None),
)


def test_anchor_form_table_only_resolvable_web_links_become_links():
    for href, expected in _ANCHOR_FORMS:
        links = eml_analysis.extract_links("", f'<a href="{href}">paypal.com</a>')
        urls = [link.url for link in links]
        assert urls == ([expected] if expected else []), (href, urls)
        if expected:
            # Klassifiziert heisst: der Anzeigetext wird gegen den echten Host
            # gehalten — genau das entfiel bei den untersuchten Formen.
            assert links[0].mismatch is True, href
            assert links[0].host == expected.split("//", 1)[1].split("/", 1)[0]


def test_anchor_form_table_keeps_dangerous_schemes_as_their_own_finding():
    # Die Gegenprobe darf nichts verschlucken: javascript:/data:/file: bleiben
    # sichtbar (eigener Befund), auch wenn sie kein Web-Link sind.
    for href in (
        "javascript:alert(1)",
        "data:text/html;base64,PHN2Zz4=",
        "file:///C:/Windows/calc.exe",
    ):
        kinds = {
            kind
            for kind, _ in summarize_links(
                eml_analysis.extract_links("", f'<a href="{href}">klick</a>')
            )
        }
        assert "MAIL_LINK_DANGEROUS_SCHEME" in kinds, href


def _link_mail(href: str) -> bytes:
    """Eine Phishing-Mail; nur der href unterscheidet die Varianten."""
    body = (
        "Ihr Konto wurde gesperrt. Bitte bestätigen Sie innerhalb von 24 Stunden "
        "Ihre Zahlungsdaten.\n"
    )
    html = (
        "<p>Ihr Konto wurde gesperrt. Bitte bestätigen Sie innerhalb von 24 "
        f'Stunden Ihre Zahlungsdaten.</p><a href="{href}">paypal.com</a>'
    )
    return (
        "From: service@evil.tld\n"
        "To: opfer@example.invalid\n"
        "Subject: Ihr Konto wurde gesperrt\n"
        "Message-ID: <x@evil.tld>\n"
        "MIME-Version: 1.0\n"
        'Content-Type: multipart/alternative; boundary="B"\n'
        "\n"
        "--B\nContent-Type: text/plain; charset=utf-8\n\n" + body +
        "\n--B\nContent-Type: text/html; charset=utf-8\n\n" + html +
        "\n--B--\n"
    ).encode("utf-8")


def test_scheme_relative_href_reaches_the_same_verdict_as_the_absolute_one():
    """Drei byte-identische Mails, nur der Schemateil des href unterscheidet sie.

    Gemessen vor dem Fix: A ROT (55), B/C GELB (25) — der weggefallene
    Anzeigetext-Abgleich (30) kippte das Urteil, obwohl Host, Linktext und
    Textkoerper gleich blieben. Nach dem Fix liegen die drei zusammen.
    """
    from pathlib import Path

    for href in ("http://evil.tld/login", "//evil.tld/login", "evil.tld/login"):
        raw = _link_mail(href)
        ctx = AnalysisContext(
            path=Path("x.eml"), data=raw, detected_type="eml", size=len(raw)
        )
        indicators = EmlPipeline().analyze(ctx)
        rule_ids = {i.rule_id for i in indicators}
        assert "MAIL_LINK_TEXT_MISMATCH" in rule_ids, (href, rule_ids)
        bundle = compute_score(indicators)
        assert bundle.risk_level is RiskLevel.RED, (href, bundle.score)
        assert bundle.score == 50, (href, bundle.score)


# -- Anker-Extraktion: Erkennung und Laufzeit -------------------------------- #

# Zwei Anker-Einheiten fuer die Laufzeit-Tests: identische Laenge je Anker, der
# eine mit, der andere ohne schliessendes '</a>'.
_ANCHOR_OPEN_UNIT = '<a href="http://a">t '
_ANCHOR_CLOSED_UNIT = '<a href="http://a">t</a> '


def _anchor_mail(unit: str, kib: int) -> bytes:
    """Eine echte Mail, deren HTML-Teil nur aus ``unit``-Wiederholungen besteht."""
    html = unit * ((kib * 1024) // len(unit))
    return (
        b"From: kunde@example.invalid\n"
        b"To: opfer@example.invalid\n"
        b"Subject: Rechnung\n"
        b"MIME-Version: 1.0\n"
        b'Content-Type: multipart/alternative; boundary="B"\n'
        b"\n"
        b"--B\nContent-Type: text/plain; charset=utf-8\n\nRechnung offen\n"
        b"--B\nContent-Type: text/html; charset=utf-8\n\n" + html.encode() + b"\n--B--\n"
    )


def test_anchor_links_are_found_in_every_real_tag_shape():
    """Die Erkennung darf durch die Laufzeit-Haertung nichts verlieren.

    Jede Zeile ist ein Tag, wie er in echten Mails vorkommt; erwartet wird der
    href und der (von Markup befreite) Linktext. Die Erwartungen sind die Werte
    des alten Ausdrucks — sie wurden gegen den Stand vor dem Fix gemessen und
    sind Zeichen fuer Zeichen gleich geblieben.
    """
    cases = [
        ('<a href="https://shop.example.de/x">Angebot</a>', "https://shop.example.de/x", "Angebot"),
        ("<a href='http://evil.example/x'>Klick</a>", "http://evil.example/x", "Klick"),
        ("<a href=http://evil.example/x>Klick</a>", "http://evil.example/x", "Klick"),
        ('<a href = "http://evil.example/x" >Klick</a>', "http://evil.example/x", "Klick"),
        # mehrzeiliges Tag
        (
            '<a\n  class="btn"\n  href="http://evil.example/x"\n>Klick</a>',
            "http://evil.example/x",
            "Klick",
        ),
        # Attribute vor href
        (
            '<a class="button primary" data-track="mail-1" href="http://1.2.3.4/x">Klick</a>',
            "http://1.2.3.4/x",
            "Klick",
        ),
        # Gross-/Kleinschreibung von Tag, Attribut und End-Tag
        ('<A HREF="http://evil.example/x">Klick</A>', "http://evil.example/x", "Klick"),
        ('<a HrEf="http://evil.example/x">Klick</a>', "http://evil.example/x", "Klick"),
        # Markup im Linktext ist Text, kein Abbruch
        (
            '<a href="http://evil.example/x">Klick <b>hier</b> bitte</a>',
            "http://evil.example/x",
            "Klick hier bitte",
        ),
        # leeres Linktext-Element
        ('<a href="http://evil.example/x"></a>', "http://evil.example/x", ""),
        # zwei Anker in einem Body
        (
            '<a href="http://erste.example/x">eins</a> und <a href="http://zweite.example/y">zwei</a>',
            "http://zweite.example/y",
            "zwei",
        ),
        # offener Anker VOR einem geschlossenen: der geschlossene liefert den Text
        (
            '<a href="http://offen.example/a">text <a href="http://zu.example/b">innen</a>',
            "http://offen.example/a",
            "text innen",
        ),
        # Entity-kodiertes Schema
        (
            '<a href="&#104;ttp://evil-collect.tk/x">hier klicken</a>',
            "http://evil-collect.tk/x",
            "hier klicken",
        ),
    ]
    for html, url, display in cases:
        links = eml_analysis.extract_links("", html)
        by_url = {link.url: link for link in links}
        assert url in by_url, f"Link nicht erkannt: {html!r} -> {sorted(by_url)}"
        assert by_url[url].display_text == display, html


def test_anchor_link_with_gt_in_attribute_is_still_found():
    """Ein '>' im Attributwert beendet das Tag — der href bleibt trotzdem sichtbar.

    Der alte Ausdruck konnte das Tag ebenfalls nicht ueberspannen (er lief nie
    ueber ein '>'), der Link kam schon immer ueber die URL-Suche im Body. Diese
    Zusage muss die gehaertete Extraktion halten.
    """
    html = '<a title="1 > 0" href="http://evil.example/x">Klick hier</a>'
    urls = {link.url for link in eml_analysis.extract_links("", html)}
    assert "http://evil.example/x" in urls, sorted(urls)


def test_anchor_tag_with_a_raw_lt_in_an_attribute_keeps_the_link():
    """Ein rohes '<' im Attribut ist ungueltiges HTML und beendet das Tag.

    Der Tag-Teil der gehaerteten Muster darf '<' NICHT ueberspannen: sonst wird
    der Scan ueber einen Body aus lauter '<a' wieder quadratisch — gemessen auf
    genau diesem Body (256 KiB, nur der Tag-Scan) 0,016 s ohne '<' gegen 0,8 s
    bei Schranke 512 und 6,2 s bei Schranke 4096. Die Schranke kann den
    unbegrenzten Blick nicht zurueckkaufen. Folge: ein Tag mit rohem '<' im
    Attributwert wird nicht mehr mit seinem '</a>' gepaart, der Anzeigetext
    entfaellt (der alte Ausdruck lieferte hier einen Anzeigetext).
    Der LINK selbst bleibt vollstaendig erkannt und klassifiziert — ueber die
    URL-Suche im Body, wie schon vorher fuer Tags mit '>' im Attributwert.
    """
    html = '<a x="<b" data-lang="de" href="http://1.2.3.4/login">Klick hier</a>'
    links = {link.url: link for link in eml_analysis.extract_links("", html)}

    assert "http://1.2.3.4/login" in links, sorted(links)
    assert links["http://1.2.3.4/login"].is_ip_literal is True
    assert links["http://1.2.3.4/login"].display_text == ""


def test_anchor_scan_costs_no_more_without_a_closing_tag():
    """Ein Body ohne '</a>' darf nicht teurer sein als einer mit.

    Der alte Ausdruck endete auf '(?P<text>.*?)</a>' mit re.DOTALL: fehlte das
    End-Tag, tastete JEDER Fehlversuch den Rest des Bodys ab (quadratisch).
    Gemessen am ungefixten Stand (echte Laeufe, parse_mail): 4 KiB 0,06 s,
    8 KiB 0,19 s, 16 KiB 0,75 s, **32 KiB 3,1 s** — x4 Bytes = x16 Zeit. Auf die
    Body-Grenze hochgerechnet sind das Minuten; bei 256 KiB wurden 188 s
    gemessen (und 33.008 B ueber scan_path 6,2 s). Die 32 KiB hier sind die
    groesste Groesse, bei der der Test vorher noch in ~3 s rot wird; der
    quadratische Anteil ist derselbe wie bei 256 KiB, nur kuerzer abgeschnitten.
    Nach dem Fix kostet dieselbe Datei 0,00 s.
    """
    import time

    t0 = time.monotonic()
    closed = parse_mail(_anchor_mail(_ANCHOR_CLOSED_UNIT, 32))
    t_closed = time.monotonic() - t0

    data = _anchor_mail(_ANCHOR_OPEN_UNIT, 32)
    t0 = time.monotonic()
    facts = parse_mail(data)
    t_open = time.monotonic() - t0

    assert t_open < 1.0, f"{t_open:.2f}s fuer {len(data)} B ohne End-Tag"
    # Und die FORM des Bodys darf den Preis nicht bestimmen: derselbe
    # Byte-Zaehler mit geschlossenen Ankern war vorher um Faktor ~195 billiger.
    assert t_open < 20 * max(t_closed, 1e-3), f"offen {t_open:.4f}s / zu {t_closed:.4f}s"
    # Das Ergebnis bleibt dasselbe: der href steckt (ueber die URL-Suche) drin.
    assert [link.url for link in facts.links] == ["http://a"]
    assert [link.url for link in closed.links] == ["http://a"]


def test_mail_without_closing_anchor_does_not_stall_the_scan(tmp_path):
    """Der echte Einstieg darf an einem offenen Anker nicht minutenlang haengen.

    Vorher ueber scan_path gemessen (ungefixt): 8.378 B 0,54 s, 32.954 B 5,93 s,
    65.722 B 24,11 s — die Analyse lief dabei zweimal (parse_mail und der
    Vorschau-Pfad). Nachher: 0,19 s fuer dieselbe Datei.
    """
    import time

    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher

    path = tmp_path / "gross.eml"
    path.write_bytes(_anchor_mail(_ANCHOR_OPEN_UNIT, 32))
    dispatcher = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    t0 = time.monotonic()
    result = dispatcher.scan_path(path)
    elapsed = time.monotonic() - t0

    assert elapsed < 2.0, f"{elapsed:.2f}s fuer {path.stat().st_size} B"
    assert "Enthaltene Links" in result.mail_preview


def test_mail_preview_renders_the_analysed_links():
    """Der Renderer zeigt facts.links — er extrahiert nicht erneut.

    Sonst laeuft die Anker-Suche je Mail zweimal. Am Verhalten belegt: eine
    Links-Liste, die der Body gar nicht hergibt, muss trotzdem erscheinen.
    """
    from malaz.core.eml_analysis import LinkFacts
    from malaz.core.mail_view import render_mail

    facts = parse_mail(_anchor_mail(_ANCHOR_CLOSED_UNIT, 1))
    facts.links = [LinkFacts(url="http://nur.aus.der.analyse.example/")]
    text = render_mail(facts)

    assert "http://nur.aus.der.analyse.example/" in text
    # Der Body-Link stammt aus der (hier ersetzten) Analyse, nicht aus dem Body.
    assert "http://a" not in text


# -- Anhangsnamen ------------------------------------------------------------ #


def test_attachment_names_flag_double_extension_and_executables():
    kinds = {
        k for k, _ in risky_attachment_names(
            ["rechnung.pdf.exe", "doku.docx", "script.ps1", "bild.jpg"]
        )
    }
    assert "MAIL_ATTACH_DOUBLE_EXT" in kinds
    assert "MAIL_ATTACH_RISKY_TYPE" in kinds
    # Harmlose Typen dürfen nicht gemeldet werden.
    assert len(kinds) == 2


def test_attachment_names_flag_binary_and_template_macro_formats():
    """BUG-027: .xlsb/.sldm/.xlam carry macros but were not RISKY_SUFFIXES."""
    kinds = [
        kind
        for kind, _name in risky_attachment_names(
            ["tabelle.xlsb", "vorlage.sldm", "addin.xlam", "doku.docx"]
        )
    ]
    assert kinds.count("MAIL_ATTACH_RISKY_TYPE") == 3, kinds
    assert len(kinds) == 3


# -- Pipeline ---------------------------------------------------------------- #


def test_pipeline_scores_phishing_mail_red():
    raw = (
        'From: "Sparkasse Service" <service@sparkasse-sicherheit.tk>\n'
        "Reply-To: <collect@evil-collector.xyz>\n"
        "To: opfer@example.com\n"
        "Message-ID: <x@y.tk>\n"
        "Subject: Dringend: Konto gesperrt\n"
        "Authentication-Results: mx; spf=fail\n"
        "MIME-Version: 1.0\n"
        'Content-Type: text/plain; charset="utf-8"\n'
        "\n"
        "Ihr Konto wurde gesperrt. Bitte bestätigen Sie innerhalb von 24 Stunden\n"
        "Ihre Zugangsdaten unter http://192.168.44.9/login\n"
    ).encode()
    ctx = AnalysisContext(
        path=__import__("pathlib").Path("phish.eml"),
        data=raw,
        detected_type="eml",
        size=len(raw),
    )
    ids = _ids(EmlPipeline().analyze(ctx))
    assert "MAIL_DISPLAY_NAME_SPOOF" in ids
    assert "MAIL_REPLY_TO_MISMATCH" in ids
    assert "MAIL_BODY_LURE_PHRASES" in ids
    assert "MAIL_LINK_IP_LITERAL" in ids


def test_pipeline_benign_mail_produces_no_high_findings():
    raw = (
        "From: kollege@firma.de\n"
        "To: ich@firma.de\n"
        "Message-ID: <normal@firma.de>\n"
        "Received: from mx.firma.de by mail.firma.de\n"
        "Subject: Mittagessen heute?\n"
        "MIME-Version: 1.0\n"
        'Content-Type: text/plain; charset="utf-8"\n'
        "\n"
        "Hallo, wollen wir heute zusammen Mittag essen gehen?\n"
        "Viele Grüße\n"
    ).encode()
    ctx = AnalysisContext(
        path=__import__("pathlib").Path("normal.eml"),
        data=raw,
        detected_type="eml",
        size=len(raw),
    )
    highs = [
        i for i in EmlPipeline().analyze(ctx) if i.severity.name in ("HIGH", "CRITICAL")
    ]
    assert highs == []


def test_pipeline_parse_error_is_visible():
    ctx = AnalysisContext(
        path=__import__("pathlib").Path("x.eml"),
        data=b"",
        detected_type="eml",
        size=0,
    )
    assert "MAIL_PARSE_WARN" in _ids(EmlPipeline().analyze(ctx))


# -- Datenschutz: Reputations-Lookup (opt-in, nur Hash) ---------------------- #


def test_reputation_disabled_by_default(monkeypatch):
    from malaz import config

    monkeypatch.setattr(config, "URL_REPUTATION_ENABLED", False)
    monkeypatch.setattr(config, "URL_REPUTATION_ENDPOINT", "https://example.invalid/x")
    assert url_reputation.enabled() is False
    result = url_reputation.lookup(["http://evil.example.com/a"])
    assert result.ran is False
    assert result.hits == {}


def test_reputation_enabled_lookup_sends_hashes_only(monkeypatch):
    from malaz import config

    monkeypatch.setattr(config, "URL_REPUTATION_ENABLED", True)
    monkeypatch.setattr(config, "URL_REPUTATION_ENDPOINT", "https://provider.invalid/v1")
    url = "https://evil.example.com/phish?token=SECRET"
    digest = url_reputation.url_hash(url)
    sent: dict = {}

    class _FakeResponse:
        def read(self, _n=None):
            return b'{"urls": {"' + digest.encode() + b'": {"threatType": "PHISHING"}}}'

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

    def fake_urlopen(request, timeout=None):
        # Der Kern der Datenschutz-Zusage: die URL selbst darf NIE im Body
        # stehen — nur ihr Hash.
        sent["body"] = request.data
        return _FakeResponse()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    result = url_reputation.lookup([url])
    assert result.ran is True
    assert result.hits == {digest: "phishing"}
    assert b"SECRET" not in sent["body"]
    assert b"evil.example.com" not in sent["body"]
    assert digest.encode() in sent["body"]


def test_reputation_skips_private_and_intranet_hosts(monkeypatch):
    from malaz import config

    monkeypatch.setattr(config, "URL_REPUTATION_ENABLED", True)
    monkeypatch.setattr(config, "URL_REPUTATION_ENDPOINT", "https://provider.invalid/v1")
    called = []
    monkeypatch.setattr(
        "urllib.request.urlopen", lambda *a, **k: called.append(1)
    )
    # Interne Ziele dürfen nie an einen Dritten gehen.
    result = url_reputation.lookup(
        ["http://192.168.1.1/x", "http://10.0.0.5/y", "http://intranet-host/z"]
    )
    assert result.ran is False
    assert called == []


def test_reputation_requires_https_endpoint(monkeypatch):
    from malaz import config

    monkeypatch.setattr(config, "URL_REPUTATION_ENABLED", True)
    monkeypatch.setattr(config, "URL_REPUTATION_ENDPOINT", "http://provider.invalid/v1")
    result = url_reputation.lookup(["http://evil.example.com/a"])
    assert result.ran is False
    assert "HTTPS" in result.skipped_reason


def test_reputation_failure_is_not_reported_as_clean(monkeypatch):
    from malaz import config

    monkeypatch.setattr(config, "URL_REPUTATION_ENABLED", True)
    monkeypatch.setattr(config, "URL_REPUTATION_ENDPOINT", "https://provider.invalid/v1")

    def boom(*_a, **_k):
        raise OSError("Netzwerk weg")

    monkeypatch.setattr("urllib.request.urlopen", boom)
    result = url_reputation.lookup(["http://evil.example.com/a"])
    assert result.ran is True
    assert result.error  # Fehler sichtbar
    assert result.hits == {}


def test_reputation_hash_ignores_fragment():
    # Der Fragment-Teil wird vom Browser interpretiert, nicht vom Server —
    # er darf den Hash nicht verändern.
    a = url_reputation.url_hash("https://example.com/x#section")
    b = url_reputation.url_hash("https://example.com/x")
    assert a == b


def test_status_to_finding_maps_known_statuses():
    verdict, _reason = url_reputation.status_to_finding("PHISHING")
    assert "Phishing" in verdict
    unknown, _ = url_reputation.status_to_finding("weird")
    assert "unbekannter Status" in unknown


# -- Erkennung: header-arme Mails erreichen die Pipeline --------------------- #


def test_header_poor_mail_is_detected_as_eml():
    # Regression: die Erkennung verlangte früher zwingend eine Message-ID —
    # damit liefen gerade handgebaute Phishing-Mails (ohne Message-ID) als
    # reiner Text durch und MAIL_NO_MESSAGE_ID konnte nie feuern.
    from malaz.core.magic import detect

    raw = (
        'From: "Sparkasse" <s@sparkasse-sicherheit.tk>\r\n'
        "To: opfer@example.com\r\n"
        "Subject: Konto gesperrt\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Bitte bestätigen Sie Ihr Konto.\r\n"
    ).encode()
    assert detect(raw).type == "eml"


def test_ordinary_text_with_from_keyword_stays_text():
    # Gegenprobe: eine Konfig-/Logdatei mit "from:" darf NICHT als Mail
    # eingestuft werden (sonst laufen normale Textdateien durch die
    # Mail-Heuristik).
    from malaz.core.magic import detect

    assert detect(b"from: a\nfrom: b\nto: c\n").type == "text"
    assert detect(b"Ein ganz normaler Satz ohne Header.").type == "text"


def test_pipeline_reports_missing_message_id_for_header_poor_mail():
    # Der eigentliche Zweck der erweiterten Erkennung: genau diese Mail muss
    # die Pipeline erreichen und dort als auffällig gemeldet werden.
    from pathlib import Path

    from malaz.core.magic import detect

    raw = (
        "From: service@sparkasse-sicherheit.tk\r\n"
        "To: opfer@example.com\r\n"
        "Subject: Ihr Konto wurde gesperrt\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Bitte bestätigen Sie innerhalb von 24 Stunden Ihre Zugangsdaten.\r\n"
    ).encode()
    assert detect(raw).type == "eml"
    ctx = AnalysisContext(
        path=Path("x.eml"), data=raw, detected_type="eml", size=len(raw)
    )
    ids = _ids(EmlPipeline().analyze(ctx))
    assert "MAIL_NO_MESSAGE_ID" in ids
    assert "MAIL_BODY_LURE_PHRASES" in ids


# -- Audit-Funde (Über-/Unterreaktion, Umgehungen) --------------------------- #


def test_link_with_path_in_display_text_is_not_a_mismatch():
    # ÜBERREAKTION (Audit-Fund): der Anzeigetext "www.shop.de/neu" zeigt auf
    # dieselbe Domain wie das Ziel — der Pfadanteil darf keinen Alarm
    # auslösen. Vorher verglich die Prüfung den ganzen String inkl. Pfad.
    html = '<a href="https://www.shop-beispiel.de/neu">www.shop-beispiel.de/neu</a>'
    links = eml_analysis.extract_links("", html)
    href = next(link for link in links if link.url.startswith("https://"))
    assert href.mismatch is False


def test_www_prefix_does_not_count_as_mismatch():
    html = '<a href="https://shop.de/x">www.shop.de</a>'
    links = eml_analysis.extract_links("", html)
    href = next(link for link in links if link.url.startswith("https://"))
    assert href.mismatch is False


def test_www_strip_does_not_eat_characters():
    # Echter Bug (Linter B005): "www.web.de".strip("www.") wurde zu "eb.de".
    assert eml_analysis._strip_www("www.web.de") == "web.de"
    assert eml_analysis._strip_www("web.de") == "web.de"


def test_html_entity_encoded_scheme_is_detected():
    # UMGEHUNG (Audit-Fund): href="&#104;ttp://…" verbarg den Link komplett.
    html = '<a href="&#104;ttp://evil-collect.tk/x">hier klicken</a>'
    links = eml_analysis.extract_links("", html)
    assert links, "Entity-kodierter Link muss erkannt werden"
    assert any(link.host == "evil-collect.tk" for link in links)


def test_named_entity_separators_are_resolved():
    assert eml_analysis._unescape_entities("h&#x74;tp&colon;//x") == "http://x"
    assert eml_analysis._unescape_entities("a&sol;b") == "a/b"


def test_display_name_with_lookalike_letters_is_flagged():
    # UMGEHUNG (Audit-Fund): kyrillisches A in "Paypal" umging jede
    # exakte Prüfung. Jetzt greift Mixed-Script + gefalteter Markenvergleich.
    facts = eml_analysis.MailFacts(
        from_display="P\u0430ypal Service",
        from_addr="a@fremd.tk",
        message_id="<x>",
        received_count=1,
    )
    kinds = {k for k, _ in analyze_structure(facts).findings}
    assert "MAIL_DISPLAY_NAME_MIXED_SCRIPT" in kinds
    assert "MAIL_DISPLAY_NAME_SPOOF" in kinds


def test_legitimate_mail_without_lookalikes_is_not_flagged():
    facts = eml_analysis.MailFacts(
        from_display="Paypal Service",
        from_addr="service@paypal.com",
        message_id="<x>",
        received_count=1,
    )
    kinds = {k for k, _ in analyze_structure(facts).findings}
    assert "MAIL_DISPLAY_NAME_MIXED_SCRIPT" not in kinds
    assert "MAIL_DISPLAY_NAME_SPOOF" not in kinds


def test_attachment_name_control_characters_are_flagged():
    # UMGEHUNG (Audit-Fund): NUL und RTL-Override verstecken den echten Typ
    # vor dem Nutzer ("rechnung.pdf" wird angezeigt, die Datei ist .exe).
    tricks = [
        "rechnung.pdf.exe\x00.txt",
        "rechnung.pdf\u202eexe",
        "rechnung.pdf\u2066exe",
    ]
    for name in tricks:
        kinds = {k for k, _ in risky_attachment_names([name])}
        assert "MAIL_ATTACH_NAME_TRICK" in kinds, name


def test_benign_attachment_names_stay_clean():
    for name in ("bericht.pdf", "bild.jpg", "doku.docx", "archiv.zip"):
        assert risky_attachment_names([name]) == (), name


def test_benign_business_mail_has_no_heavy_findings():
    # ÜBERREAKTIONS-Schutz: eine gewöhnliche Geschäftsmail darf keinen
    # schweren Befund erzeugen (sonst ist das Tool im Alltag unbrauchbar).
    from pathlib import Path

    raw = (
        "From: kollege@firma.de\r\nTo: ich@firma.de\r\n"
        "Message-ID: <a@firma.de>\r\nReceived: from mx.firma.de\r\n"
        "Subject: Rechnung Q3\r\nMIME-Version: 1.0\r\n"
        'Content-Type: text/plain; charset="utf-8"\r\n\r\n'
        "Hallo, anbei die Zahlen für Q3. Bitte kurz prüfen.\r\n"
    ).encode()
    ctx = AnalysisContext(
        path=Path("normal.eml"), data=raw, detected_type="eml", size=len(raw)
    )
    heavy = [
        i
        for i in EmlPipeline().analyze(ctx)
        if i.severity.name in ("HIGH", "CRITICAL")
    ]
    assert heavy == [], [i.rule_id for i in heavy]


# -- Weitere Audit-Funde: URI-Schemata, unsichtbare Zeichen ------------------ #


def test_dangerous_uri_schemes_are_flagged():
    # UMGEHUNG (Audit-Fund): javascript:, data:, vbscript: und file: wurden
    # komplett ignoriert — sie führen Code aus bzw. greifen auf lokale
    # Dateien zu und dürfen nie stillschweigend durchlaufen.
    for href in (
        "javascript:alert(1)",
        "vbscript:msgbox(1)",
        "data:text/html;base64,PHNjcmlwdD4=",
        "file:///C:/Windows/System32/calc.exe",
    ):
        html = f'<a href="{href}">Klick</a>'
        links = eml_analysis.extract_links("", html)
        kinds = {k for k, _ in summarize_links(links)}
        assert "MAIL_LINK_DANGEROUS_SCHEME" in kinds, href


def test_ordinary_http_links_are_not_flagged_as_dangerous():
    html = '<a href="https://www.firma.de/kontakt">Kontakt</a>'
    kinds = {k for k, _ in summarize_links(eml_analysis.extract_links("", html))}
    assert "MAIL_LINK_DANGEROUS_SCHEME" not in kinds


def test_invisible_characters_in_display_name_are_flagged():
    # UMGEHUNG (Audit-Fund): Zero-Width/Soft-Hyphen im Markennamen umging
    # jede exakte Prüfung, obwohl das Wort identisch aussieht.
    for zwsp in ("\u200b", "\u200c", "\u200d", "\ufeff", "\u00ad"):
        facts = eml_analysis.MailFacts(
            from_display=f"Pay{zwsp}pal",
            from_addr="a@fremd.tk",
            message_id="<x>",
            received_count=1,
        )
        kinds = {k for k, _ in analyze_structure(facts).findings}
        assert "MAIL_DISPLAY_NAME_MIXED_SCRIPT" in kinds, repr(zwsp)
        assert "MAIL_DISPLAY_NAME_SPOOF" in kinds, repr(zwsp)


def test_reply_to_on_same_registrable_domain_is_not_flagged():
    # FP-Kontrolle: beschreibt eine andere Subdomain derselben Organisation,
    # ist aber kein Angriff (sonst schlägt jeder legitime Versand an).
    facts = eml_analysis.MailFacts(
        from_addr="chef@firma.de",
        reply_to="noreply@mail.firma.de",
        message_id="<x>",
        received_count=1,
    )
    kinds = {k for k, _ in analyze_structure(facts).findings}
    assert "MAIL_REPLY_TO_MISMATCH" not in kinds


def test_newsletter_with_tracking_pixel_has_no_mismatch():
    # FP-Kontrolle: Tracking-Pixel und normale Links dürfen keinen Alarm
    # auslösen — sonst ist das Tool für Newsletter unbrauchbar.
    html = (
        '<img src="https://tracking.newsletter-cdn.de/open.gif?u=123">'
        '<a href="https://www.newsletter-cdn.de/artikel/1">Zum Artikel</a>'
        '<a href="https://www.newsletter-cdn.de/abmelden">Abmelden</a>'
    )
    links = eml_analysis.extract_links("", html)
    assert not [link for link in links if link.mismatch]


def test_dangerous_scheme_reaches_pipeline_with_own_title():
    # Der Befund muss durch die ECHTE Pipeline kommen (nicht nur aus dem
    # Modul) und einen spezifischen Titel tragen — nicht den generischen
    # Fallback "Auffälliger Link".
    from pathlib import Path

    body = (
        '<a href="javascript:alert(1)">a</a>'
        '<a href="data:text/html;base64,PHN2Zz4=">b</a>'
    )
    raw = (
        "From: a@b.de\r\nTo: c@d.de\r\nMessage-ID: <x@y>\r\nSubject: T\r\n"
        "Received: from mx\r\nMIME-Version: 1.0\r\n"
        'Content-Type: text/html; charset="utf-8"\r\n\r\n' + body
    ).encode("utf-8")
    ctx = AnalysisContext(
        path=Path("x.eml"), data=raw, detected_type="eml", size=len(raw)
    )
    hits = [
        i
        for i in EmlPipeline().analyze(ctx)
        if i.rule_id == "MAIL_LINK_DANGEROUS_SCHEME"
    ]
    assert hits, "Gefährliches Schema muss gemeldet werden"
    assert hits[0].severity.name == "HIGH"
    assert hits[0].weight == 30
    assert "Auffälliger Link" not in hits[0].title
    assert "javascript" in hits[0].detail and "data" in hits[0].detail


def test_every_mail_finding_kind_has_severity_and_title():
    # Struktur-Test: jeder Befund, den die Analyse erzeugen kann, braucht
    # Severity- UND Titel-Mapping. Ein fehlender Eintrag fällt sonst still
    # auf einen generischen Fallback zurück (Audit-Fund).
    from malaz.pipelines import eml_pipeline as ep

    kinds = {
        "MAIL_ATTACH_DOUBLE_EXT", "MAIL_ATTACH_NAME_TRICK", "MAIL_ATTACH_RISKY_TYPE",
        "MAIL_AUTH_FAIL", "MAIL_DISPLAY_NAME_MIXED_SCRIPT", "MAIL_DISPLAY_NAME_SPOOF",
        "MAIL_LINK_CREDENTIALS", "MAIL_LINK_DANGEROUS_SCHEME", "MAIL_LINK_IP_LITERAL",
        "MAIL_LINK_PUNYCODE", "MAIL_LINK_RISKY_TLD", "MAIL_LINK_SHORTENER",
        "MAIL_LINK_TEXT_MISMATCH", "MAIL_LOOKALIKE_DOMAIN", "MAIL_NO_MESSAGE_ID",
        "MAIL_NO_RECEIVED", "MAIL_REPLY_TO_MISMATCH", "MAIL_RETURN_PATH_MISMATCH",
    }
    mapped = (
        set(ep._STRUCTURE_SEVERITY) | set(ep._LINK_SEVERITY) | set(ep._ATTACH_SEVERITY)
    )
    assert kinds <= mapped, f"ohne Severity-Mapping: {kinds - mapped}"


def test_core_error_is_visible_not_silent():
    # Audit-Fund: ein Scan, der gar nicht laufen konnte (z. B. weil ein
    # Virenschutz die Datei beim Öffnen blockiert — genau der EICAR-Fall),
    # meldete Score 0 / GRÜN. Er muss sichtbar "nicht geprüft" heißen.
    import tempfile
    from pathlib import Path

    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher

    dispatcher = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    tmp = Path(tempfile.mkdtemp())
    missing = tmp / "gibtsnicht.bin"  # stat() schlägt fehl -> Exception-Pfad
    result = dispatcher.scan_path(missing)

    assert result.error, "Der Fehler muss im Ergebnis stehen"
    err = next(i for i in result.indicators if i.rule_id == "CORE_ERROR")
    assert err.weight > 0
    assert "NICHT als 'sauber'" in err.detail
    assert result.score > 0


# -- Audit Runde 3: Fehlalarme auf echten, signierten Systemdateien ---------- #


def test_cab_header_validation_accepts_real_cabs(monkeypatch):
    # Eine echte CAB-Datei muss als solche erkannt werden; der Filter darf
    # nur Zufallstreffer im Code verwerfen. Die Feldoffsets wurden an echten
    # CABs verifiziert (reserved1/2/3=0, versionMajor=1|3, Zähler > 0) —
    # eine frühere Version las die Offsets verschoben und verwarf damit
    # JEDES valide CAB (False Negative).
    import struct

    from malaz.pipelines.generic_pipeline import _cab_header_ok

    # Header-Bytes exakt nach MS-CAB-Layout (wie real gemessen).
    def make_cab(size=2048, cb_cabinet=1024, folders=1, files=1, major=1):
        head = struct.pack("<4sIIIIIBBHHHHH", b"MSCF", 0, cb_cabinet, 0, 44,
                           0, 3, major, folders, files, 0, 0, 0)
        return head.ljust(size, b"\x00")

    assert _cab_header_ok(make_cab(), 0) is True
    # versionMajor 3 ist ebenfalls gültig (Cabinet 1.3).
    assert _cab_header_ok(make_cab(major=3), 0) is True
    # Kein CAB: Zufallstreffer mitten in Code-Daten.
    noise = b"\x0f\x1fD\x00\x00\x85\xc0t\x19MSCFu\t\xc7G\x08\x02\x00\x00\x00"
    assert _cab_header_ok(noise, 11) is False
    # reserved3 muss 0 sein.
    bad = bytearray(make_cab())
    bad[20] = 1
    assert _cab_header_ok(bytes(bad), 0) is False


# -- Audit Runde 4: Fehlalarme auf echter Drittanbieter-Software ------------- #


def test_injection_rule_requires_all_three_phases():
    # Die Injektions-Erkennung darf NICHT bei einer einzelnen API anschlagen
    # (jede Prozess-verwaltende Software importiert VirtualAllocEx oder
    # CreateRemoteThread). Gemessen: 90 legitime Programme, clamscan.exe
    # löste die alte Einzelgruppen-Regel aus.
    from malaz.pipelines.pe_pipeline import match_import_patterns

    def fires(imports: set[str]) -> bool:
        return any(r == "PE_IMPORT_INJECTION" for r, _l, _m in match_import_patterns(imports))

    assert not fires({"virtualallocex"})
    assert not fires({"queueuserapc"})
    assert not fires({"virtualallocex", "writeprocessmemory"})  # Exec fehlt
    assert fires({"virtualallocex", "writeprocessmemory", "createremotethread"})
    assert fires({"virtualallocex", "writeprocessmemory", "queueuserapc"})


def test_normal_sections_are_not_reported_as_packed():
    # .bss/.tls/.ndata haben bauartbedingt keine Rohdaten — gemessen löste das
    # bei git-bash.exe und Uninstall ZCode.exe PE_PACKED/HIGH aus.
    from malaz.pipelines.pe_pipeline import _NORMAL_ZERO_RAW_SECTIONS

    for name in (b"bss", b"tls", b"debug", b"ndata", b"crt"):
        if name in _NORMAL_ZERO_RAW_SECTIONS:
            continue
        # .ndata ist nicht namentlich gelistet, wird aber über die
        # Schreib-/Ausführbar-Bedingung abgedeckt (Installer-Payload).
    assert b"bss" in _NORMAL_ZERO_RAW_SECTIONS
    assert b"tls" in _NORMAL_ZERO_RAW_SECTIONS


def test_authenticode_overlay_is_not_a_hidden_payload():
    # 65% der legitimen Programme tragen die Signatur als Overlay mit hoher
    # Entropie; das ist kein versteckter Inhalt.
    from malaz.pipelines.pe_pipeline import _looks_like_authenticode_blob

    blob = b"\x30\x82\x0f\xf0" + b"\x06\x09\x2a\x86\x48\x86\xf7\x0d" + b"\x00" * 40
    pkcs7 = (
        (len(blob) + 8).to_bytes(4, "little") + (0x0200).to_bytes(2, "little")
        + (0x0002).to_bytes(2, "little") + blob
    )
    assert _looks_like_authenticode_blob(pkcs7) is True
    # Ein angehängter ZIP-Payload bleibt verdächtig.
    assert _looks_like_authenticode_blob(b"PK\x03\x04" + b"\x00" * 100) is False


def test_embedded_signatures_are_counted_not_multiplied():
    # Dieselbe Signatur mehrfach gefunden darf nicht mehrfach zählen
    # (tailscale.exe erreichte mit 8 Einzeltreffern Score 100).
    from pathlib import Path

    from malaz.models import AnalysisContext
    from malaz.pipelines.generic_pipeline import GenericPipeline

    # Ein PE mit drei eingebetteten ZIP-Köpfen (stark genug für die Meldung).
    payload = b"MZ" + b"\x00" * 60 + b"PE\x00\x00" + b"\x00" * 400
    payload += b"PK\x03\x04" + b"A" * 20 + b"PK\x03\x04" + b"B" * 20 + b"PK\x03\x04"
    ctx = AnalysisContext(
        path=Path("x.exe"), data=payload, detected_type="pe", size=len(payload)
    )
    hits = [
        i for i in GenericPipeline().analyze(ctx) if i.rule_id == "GEN_EMBEDDED"
    ]
    # Höchstens ein Befund pro Signaturtyp, nicht pro Vorkommen.
    assert len(hits) <= 1, [i.title for i in hits]


def test_script_yara_rules_do_not_fire_on_binaries():
    # node.exe (JS-Runtime) und tailscale.exe lösten Skript-Regeln aus,
    # obwohl eine PE keine Makros/Skripte enthalten kann.

    from malaz.core.yara_engine import YaraEngine

    engine = YaraEngine()
    if not engine.available:
        import pytest

        pytest.skip("YARA nicht verfügbar")
    pe_header = b"MZ" + b"\x00" * 58 + b"PE\x00\x00"
    body = (
        b"CreateObject cmd.exe WScript.Shell URLDownloadToFile powershell "
        b"eval( unescape( fromCharCode -EncodedCommand Net.WebClient IEX"
    )
    matches = engine.scan(pe_header + body)
    script_rules = [
        m for m in matches
        if m.rule in ("Suspicious_VBA_Shell", "Suspicious_PowerShell_Encoded",
                      "JS_Obfuscation_Unescape")
    ]
    assert not script_rules, [m.rule for m in script_rules]

    # Gegenprobe: als SKRIPT (kein MZ) müssen dieselben Regeln greifen.
    matches2 = engine.scan(body)
    assert any(
        m.rule in ("Suspicious_VBA_Shell", "Suspicious_PowerShell_Encoded",
                   "JS_Obfuscation_Unescape")
        for m in matches2
    )


# -- Kalibrierung: ehrliche Gewichte statt Signatur-Dämpfung ------------------ #


def test_import_combinations_have_calibrated_weights():
    # Gemessen: Die vollständige Injektions-Trias wird auch von firefox.exe
    # importiert (Plugin-Isolation), SetWindowsHookEx von jeder Software mit
    # globalen Tastenkürzeln. Beide dürfen daher kein hohes Gewicht tragen —
    # die Signatur-Dämpfung, die das früher auffing, ist entfernt.
    from malaz.models import Severity
    from malaz.pipelines.pe_pipeline import _IMPORT_WEIGHTS

    inj_sev, inj_w = _IMPORT_WEIGHTS["PE_IMPORT_INJECTION"]
    key_sev, key_w = _IMPORT_WEIGHTS["PE_IMPORT_KEYLOG"]
    _dl_sev, dl_w = _IMPORT_WEIGHTS["PE_IMPORT_DOWNLOAD_EXEC"]
    assert inj_w <= 5 and inj_sev is Severity.LOW
    assert key_w <= 5 and key_sev is Severity.LOW
    # Download+Execute ist das spezifischste Muster und darf etwas höher sein,
    # aber kein Anker (der bleibt AV/YARA).
    assert 5 < dl_w <= 20


def test_signature_damping_is_removed():
    # Die Dämpfung war nach der Gewichts-Kalibrierung redundant: gemessen auf
    # 90 legitimen Programmen ergaben "mit" und "ohne" identische Urteile
    # (0% ROT, 9% GELB). Zwei übereinanderliegende Reduktionen schwächten
    # zudem die Erkennung signierter Malware.
    from malaz.pipelines import pe_pipeline as pp

    assert not hasattr(pp.PePipeline, "_dampen_for_signed")
    assert not hasattr(pp.PePipeline, "_DAMPENED_WHEN_SIGNED")
    # Ein signiertes Sample mit verdächtigen Merkmalen wird voll gewertet.
    from pathlib import Path

    from malaz.core.scoring import compute_score
    from malaz.models import AnalysisContext, Severity

    class _Sub(pp.PePipeline):
        def _structure(self, ctx):
            return [self._indicator("PE_TLS_CALLBACKS", "T", weight=30,
                                    severity=Severity.HIGH)]

        def _imports(self, ctx):
            return [self._indicator("PE_IMPORT_INJECTION", "I", weight=30,
                                    severity=Severity.HIGH)]

        def _mitigations(self, ctx):
            return []

        def _authenticode(self, ctx):
            return [self._indicator("PE_SIGNED", "Signiert", weight=0,
                                    severity=Severity.INFO)]

        def _die(self, ctx):
            return []

    b = compute_score(
        _Sub().analyze(
            AnalysisContext(path=Path("x.exe"), data=b"MZ", detected_type="pe", size=2)
        )
    )
    assert b.score >= 60, "signierte Heuristik-Treffer bleiben voll gewertet"


def test_pe_in_pe_is_detected_as_dropper():
    # Regression: `label == detected_type` übersprang PE-in-PE komplett — das
    # klassische Dropper-Muster blieb damit unerkannt.
    import struct
    from pathlib import Path

    from malaz.models import AnalysisContext
    from malaz.pipelines.generic_pipeline import GenericPipeline

    def pe_stub() -> bytes:
        return (
            b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x80)
            + b"\x00" * 0x40 + b"PE\x00\x00"
        )

    data = pe_stub() + b"\x00" * 0x200 + pe_stub() + b"\x00" * 0x100
    ctx = AnalysisContext(
        path=Path("dropper.exe"), data=data, detected_type="pe", size=len(data)
    )
    hits = [i for i in GenericPipeline().analyze(ctx) if i.rule_id == "GEN_EMBEDDED"]
    pe_hits = [i for i in hits if "pe" in i.title]
    assert pe_hits, "PE-in-PE muss erkannt werden"
    assert pe_hits[0].weight >= 15, "ein eingebettetes PE ist kein Rauschen"


def test_embedded_archive_in_pe_is_only_a_note():
    # Go/Rust-Binaries und Installer tragen Archive legitim (gemessen löste das
    # bei 17 von 90 legitimen Programmen GELB aus) — nur Archive werden
    # herabgestuft, Executables nicht.
    import struct
    from pathlib import Path

    from malaz.models import AnalysisContext
    from malaz.pipelines.generic_pipeline import GenericPipeline

    pe_stub = (
        b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x80)
        + b"\x00" * 0x40 + b"PE\x00\x00"
    )
    # Fünf ZIP-Kopf-Treffer (über der Wiederholungsschwelle).
    zip_head = b"PK\x03\x04\x14\x00\x00\x00\x08\x00\x00\x00\x00\x00" + b"A" * 30
    data = pe_stub + b"\x00" * 0x100 + zip_head * 5
    ctx = AnalysisContext(
        path=Path("go.exe"), data=data, detected_type="pe", size=len(data)
    )
    hits = [i for i in GenericPipeline().analyze(ctx) if i.rule_id == "GEN_EMBEDDED"]
    for hit in hits:
        if "zip" in hit.title:
            assert hit.weight == 0, "Archiv im PE ist ein Hinweis, kein Score"


def test_elf_magic_requires_valid_header():
    # \x7fELF ist 4 Byte und traf mitten in Microsoft-Binaries (SenseTVM.exe).
    from malaz.pipelines.generic_pipeline import _elf_at

    real = b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"\x02\x00>\x00"
    assert _elf_at(real, 0) is True
    # Code-Fragment, das zufällig mit dem Magic beginnt.
    assert _elf_at(b"\x7fELF" + b"\xff" * 20, 0) is False


def test_authenticode_blob_rejects_forged_short_length():
    # Ein gefälschter Kopf mit kleiner Längenangabe + großer Payload dahinter
    # darf NICHT als Signatur durchgehen (sonst wäre das Overlay getarnt).
    from malaz.pipelines.pe_pipeline import _looks_like_authenticode_blob

    blob = b"\x30\x82\x0f\xf0" + b"\x06\x09\x2a\x86\x48\x86\xf7\x0d" + b"\x00" * 40
    forged = (
        (16).to_bytes(4, "little") + (0x0200).to_bytes(2, "little")
        + (0x0002).to_bytes(2, "little") + blob + b"P" * 100_000
    )
    assert _looks_like_authenticode_blob(forged) is False
    # Korrekte Länge deckt den Blob ab.
    valid = (
        (len(blob) + 8).to_bytes(4, "little") + (0x0200).to_bytes(2, "little")
        + (0x0002).to_bytes(2, "little") + blob
    )
    assert _looks_like_authenticode_blob(valid) is True


def test_control_flow_guard_alone_is_not_a_finding():
    # CFG fehlt bei 28% legitimer Software — Härtungslücke, kein Schadhinweis.
    import struct
    from pathlib import Path

    import pefile  # noqa: F401  (nur zur Dokumentation der Abhängigkeit)

    from malaz.models import AnalysisContext
    from malaz.pipelines.pe_pipeline import PePipeline

    # Minimales PE: DllCharacteristics mit ASLR|DEP, ohne GUARD_CF.
    # Layout des PE32+-Optional-Headers: Magic(2) … DllCharacteristics bei
    # Offset 0x46..0x48 innerhalb des Optional-Headers.
    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0xF0, 0x0022)
    opt = struct.pack("<H", 0x20B) + b"\x00" * 0x44 + struct.pack(
        "<H", 0x0140  # DYNAMIC_BASE | NX_COMPAT, kein GUARD_CF
    ) + b"\x00" * 0xA8
    sec = b".text".ljust(8, b"\x00") + struct.pack(
        "<IIIIIIHHI", 0x1000, 0x1000, 0x400, 0x200, 0, 0, 0, 0, 0x60000020
    )
    data = dos + b"\x00" * (0x80 - len(dos)) + b"PE\x00\x00" + coff + opt + sec + b"\x00" * 0x400
    inds = PePipeline().analyze(
        AnalysisContext(path=Path("x.exe"), data=data, detected_type="pe", size=len(data))
    )
    ids = {i.rule_id: i.weight for i in inds}
    assert ids.get("PE_WEAK_MITIGATIONS") in (None, 0), ids
    assert "PE_MITIGATION_NOTE" in ids


def _tls_pe(mode: str) -> bytes:
    """Minimales PE32+ mit TLS-Verzeichnis (valid | zero | unmapped)."""
    import struct

    image_base = 0x140000000
    file_align, sec_align = 0x200, 0x1000
    rdata_rva, rdata_raw, tls_rva, cb_rva = 0x2000, 0x400, 0x2000, 0x2040
    opt_size = 0xF0
    size_of_headers = (
        0x80 + 4 + 20 + opt_size + file_align - 1
    ) // file_align * file_align
    cb_va = {
        "valid": image_base + cb_rva,
        "zero": 0,
        "unmapped": image_base + 0x900000,  # ausserhalb jedes Abschnitts
        "empty": image_base + cb_rva,  # Array vorhanden, erster Eintrag NULL
        "two": image_base + cb_rva,  # zwei Zeiger, dann NULL
        "overflow": image_base + cb_rva,  # kein Terminator -> Deckel greift
    }[mode]
    tls = struct.pack(
        "<QQQQII",
        image_base + rdata_rva,
        image_base + rdata_rva + 8,
        image_base + rdata_rva + 8,
        cb_va,
        0,
        0,
    )
    # Genug Platz fuer 100 Zeiger im Overflow-Fall, sonst 0x200.
    rdata_size = 0x400 if mode == "overflow" else 0x200
    rdata = bytearray(rdata_size)
    rdata[: len(tls)] = tls
    if mode == "valid":  # ein Zeiger, dann NULL-Terminator
        off = cb_rva - rdata_rva
        rdata[off : off + 16] = struct.pack("<QQ", image_base + 0x1000, 0)
    elif mode == "two":  # zwei Zeiger, dann NULL-Terminator
        off = cb_rva - rdata_rva
        rdata[off : off + 24] = struct.pack(
            "<QQQ", image_base + 0x1000, image_base + 0x1008, 0
        )
    elif mode == "overflow":
        # 100 Zeiger ohne Terminator: der Deckel bei 64 muss greifen, damit
        # ein praepariertes Array den Scan nicht ausbremst.
        off = cb_rva - rdata_rva
        for i in range(100):
            rdata[off + i * 8 : off + i * 8 + 8] = struct.pack(
                "<Q", image_base + 0x1000
            )

    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)
    coff = struct.pack("<HHIIIHH", 0x8664, 2, 0, 0, 0, opt_size, 0x0022)
    dirs = bytearray(16 * 8)
    dirs[9 * 8 : 9 * 8 + 8] = struct.pack("<II", tls_rva, 40)
    opt = (
        struct.pack("<H", 0x20B)
        + b"\x00" * (0x18 - 2)
        + struct.pack("<Q", image_base)
        + struct.pack("<II", sec_align, file_align)
        + b"\x00" * (0x46 - 0x28)
        + struct.pack("<H", 0x0140)
        + b"\x00" * (0x6C - 0x48)
        + struct.pack("<I", 16)
        + bytes(dirs)
    )
    sec_text = b".text".ljust(8, b"\x00") + struct.pack(
        "<IIIIIIHHI", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020
    )
    sec_rdata = b".rdata".ljust(8, b"\x00") + struct.pack(
        "<IIIIIIHHI",
        rdata_size,
        rdata_rva,
        rdata_size,
        rdata_raw,
        0,
        0,
        0,
        0,
        0x40000040,
    )
    body = (
        dos.ljust(0x80, b"\x00")
        + b"PE\x00\x00"
        + coff
        + opt
        + sec_text
        + sec_rdata
    )
    return body.ljust(size_of_headers, b"\x00") + b"\x90" * 0x200 + bytes(rdata)


def _tls_ids(mode: str) -> dict[str, int]:
    from pathlib import Path

    from malaz.models import AnalysisContext
    from malaz.pipelines.pe_pipeline import PePipeline

    data = _tls_pe(mode)
    ctx = AnalysisContext(
        path=Path("tls.exe"), data=data, detected_type="pe", size=len(data)
    )
    return {i.rule_id: i.weight for i in PePipeline().analyze(ctx)}


def _tls_titles(mode: str) -> dict[str, str]:
    from pathlib import Path

    from malaz.models import AnalysisContext
    from malaz.pipelines.pe_pipeline import PePipeline

    data = _tls_pe(mode)
    ctx = AnalysisContext(
        path=Path("tls.exe"), data=data, detected_type="pe", size=len(data)
    )
    return {i.rule_id: i.title for i in PePipeline().analyze(ctx)}


def test_tls_with_callbacks_reports_count_and_stays_low():
    # 75% der legitimen Programme haben TLS-Callbacks -> Anwesenheit allein
    # ist kein Signal, der Befund bleibt niedrig.
    ids = _tls_ids("valid")
    assert "PE_TLS_CALLBACKS" in ids
    assert ids["PE_TLS_CALLBACKS"] <= 5
    assert "PE_TLS_EMPTY" not in ids


def test_tls_empty_directory_is_a_note_without_weight():
    # VA=0 = echte Aussage der Datei (30% der Systemdateien) -> Hinweis.
    ids = _tls_ids("zero")
    assert ids.get("PE_TLS_EMPTY") == 0
    assert "PE_TLS_CALLBACKS" not in ids


def test_unresolvable_tls_array_yields_no_finding():
    # Kernpunkt: eine NICHT aufloesbare Callback-Adresse darf nicht als
    # "leeres Verzeichnis" durchgehen — sonst tarnt Malware eine kaputte
    # Struktur als Normalfall.
    ids = _tls_ids("unmapped")
    assert "PE_TLS_EMPTY" not in ids
    assert "PE_TLS_CALLBACKS" not in ids


def test_tls_callback_count_reflects_real_array():
    # Zaehlt exakt die Zeiger vor dem NULL-Terminator (echtes PE, kein Mock).
    # Der Zaehlwert steht im Titel, nicht nur das Gewicht — sonst wuerde der
    # Test einen falschen Zaehler (z.B. immer "1") nicht bemerken.
    assert "(1)" in _tls_titles("valid")["PE_TLS_CALLBACKS"]
    assert "(2)" in _tls_titles("two")["PE_TLS_CALLBACKS"]


def test_tls_array_without_terminator_is_capped():
    # 100 Zeiger ohne Terminator: der Deckel bei 64 muss greifen, damit ein
    # praepariertes Array den Scan nicht ausbremst. Belegt am exakten Wert.
    titles = _tls_titles("overflow")
    assert "(64)" in titles["PE_TLS_CALLBACKS"], titles


def _phish_links_mail() -> bytes:
    """A mail carrying every link anomaly the preview should annotate."""
    return (
        b"From: kunde@example.invalid\n"
        b"To: opfer@example.invalid\n"
        b"Received: from mx.example.invalid by mx2.example.invalid;\n"
        b"Subject: Rechnung offen\n"
        b"MIME-Version: 1.0\n"
        b'Content-Type: multipart/alternative; boundary="B"\n'
        b"\n"
        b"--B\nContent-Type: text/plain; charset=utf-8\n\n"
        b"Bitte begleichen Sie die offene Rechnung:\n"
        b"http://192.0.2.77/pay\n"
        b"https://bit.ly/3xYzAbc\n"
        b"https://xn--pypal-4ve.example.invalid/login\n"
        b"http://konto.info.tk/verify\n"
        b"--B\nContent-Type: text/html; charset=utf-8\n\n"
        b'<a href="http://example.invalid/ziel">https://www.paypal.com/anmeldung</a>\n'
        b"--B--\n"
    )


# -- Mail-Viewer (Klartext-Preview) ------------------------------------------ #

def test_mail_preview_has_headers_body_and_links():
    """The preview must show what the mail SAYS, not just which rules fired.

    Until now MailFacts was parsed, used for the findings and discarded — the
    user saw rule names but never the mail itself.
    """
    from malaz.core.eml_analysis import parse_mail
    from malaz.core.mail_view import render_mail

    data = _phish_links_mail()
    text = render_mail(parse_mail(data))
    assert "E-Mail-Inhalt" in text
    assert "Betreff:" in text and "Rechnung offen" in text
    assert "Von:" in text
    assert "Textinhalt" in text
    assert "Enthaltene Links" in text


def test_mail_preview_clips_attachment_names():
    """BUG-054: attachment names bypassed MAX_DISPLAY_CHARS.

    A 60 000-character name produced a 60 027-character label: masking kept
    the whole string. The cap that protects every other preview field must
    apply here too.
    """
    from malaz.core.eml_analysis import MailFacts
    from malaz.core.mail_view import MAX_DISPLAY_CHARS, render_mail

    langer_name = "A" * 60_000 + ".pdf"
    facts = MailFacts(subject="Test", attachment_names=[langer_name])
    text = render_mail(facts)
    assert "gekürzt" in text
    assert "60004 Zeichen" in text
    laengste = max(len(line) for line in text.splitlines())
    assert laengste <= MAX_DISPLAY_CHARS + 60, (
        f"Anhangszeile ist {laengste} Zeichen lang"
    )
    assert "A" * 60_000 not in text


def test_mail_preview_never_contains_raw_html():
    """The HTML body is attacker-controlled and must not be rendered.

    Printing it would add parser surface for no analytical gain — the body's
    signals are already extracted as indicators. The preview shows the TEXT
    body and the *extracted* URLs; what it must never carry is markup.
    """
    from malaz.core.eml_analysis import MailFacts, extract_links
    from malaz.core.mail_view import render_mail

    html = (
        '<html><body onload="alert(1)"><script>x=1</script>'
        '<img src="http://tracker.example.invalid/p.gif"></body></html>'
    )
    facts = MailFacts(
        subject="Test",
        text_body="harmloser Text",
        html_body=html,
        # Die Linkliste kommt aus der Analyse (parse_mail/parse_msg fuellt sie);
        # der Renderer zeigt facts.links und extrahiert nicht mehr selbst.
        links=extract_links("", html),
    )
    text = render_mail(facts)
    assert "harmloser Text" in text
    # Kein Markup aus dem HTML-Teil — das ist der Kern der Entscheidung.
    for marker in ("<script", "onload", "<img", "<html", "alert("):
        assert marker not in text, f"HTML-Rest im Preview: {marker}"
    # Der Tracker erscheint nur als *extrahierte URL* in der Linkliste, nicht
    # als Markup. Genau das ist gewollt: die Anomalie soll sichtbar sein.
    assert "http://tracker.example.invalid/p.gif" in text


def test_mail_preview_marks_link_anomalies():
    """The link list carries the annotations — that IS the value, not a click.

    No clickable links on purpose: the only openUrl in the project opens a
    local file ("nothing leaves the machine"), and clicking a phishing link
    would confirm liveness to the attacker.
    """
    from malaz.core.eml_analysis import parse_mail
    from malaz.core.mail_view import render_mail

    text = render_mail(parse_mail(_phish_links_mail()))
    assert "IP-Adresse statt Name" in text
    assert "Punycode" in text
    assert "Kurz-Link" in text


def test_mail_preview_empty_for_missing_mail():
    """A mail with nothing readable yields no preview (no empty scaffold)."""
    from malaz.core.eml_analysis import MailFacts
    from malaz.core.mail_view import render_mail

    assert render_mail(MailFacts(parse_error="kaputt")) == ""


def test_mail_preview_reaches_scan_result(tmp_path):
    """The dispatcher must hand the preview to the result.

    This is the load-bearing part: without it the GUI has nothing to show, and
    re-parsing on every click would cost a second parse per row.
    """
    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher

    path = tmp_path / "m.eml"
    path.write_bytes(_phish_links_mail())
    d = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    result = d.scan_path(path)
    assert result.detected_type == "eml"
    assert result.mail_preview, "Preview fehlt auf dem ScanResult"
    assert "Betreff: Rechnung offen" in result.mail_preview


def test_non_mail_has_no_preview(tmp_path):
    """Ordinary files must not grow a mail preview."""
    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher

    path = tmp_path / "note.txt"
    path.write_text("nur Text")
    d = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    assert d.scan_path(path).mail_preview == ""


def test_mail_preview_masks_bidi_trick():
    """A bidi-mangled attachment name must be MASKED, not rendered raw.

    Measured by screenshot with a NON-PALINDROMIC name: Qt applies the bidi
    algorithm to plain text. ``Rechnung\\u202efdp.exe`` is displayed as
    ``Rechnungexe.pdf`` — the deception reaches the user's eye exactly as the
    attacker intends. (A first probe used ``.exe``, a palindrome, so it looked
    the same with and without bidi and could not decide the question.)

    The preview therefore shows the STORED string with the control character
    spelled out. It must not drop it silently: ``MAIL_ATTACH_NAME_TRICK``
    reports the trick, and the view must not tidy away what the analysis flags.
    """
    from malaz.core.eml_analysis import MailFacts
    from malaz.core.mail_view import render_mail

    stored = "Rechnung\u202efdp.exe"
    text = render_mail(MailFacts(subject="Test", attachment_names=[stored]))
    # Die Escape-Darstellung steht da, das rohe Steuerzeichen nicht mehr.
    assert "Rechnung\\u202efdp.exe" in text
    assert "\u202e" not in text, "das Bidi-Zeichen wird roh ausgegeben"


def test_mail_preview_masks_bidi_in_headers_and_body():
    """The same masking applies to subject, body and parsed errors."""
    from malaz.core.eml_analysis import MailFacts
    from malaz.core.mail_view import render_mail

    text = render_mail(
        MailFacts(
            subject="Betreff\u202emit Trick",
            text_body="Body\u202emit Trick",
            parse_error="Fehler\u202emit Trick",
        )
    )
    assert "\u202e" not in text
    assert text.count("\\u202e") >= 3


def test_mail_preview_keeps_plain_names_untouched():
    """Ordinary text must not be altered by the masking."""
    from malaz.core.eml_analysis import MailFacts
    from malaz.core.mail_view import render_mail

    text = render_mail(
        MailFacts(
            subject="Rechnung 2026-0042",
            text_body="Guten Tag,\n\nanbei die Rechnung.",
            attachment_names=["rechnung.pdf", "foto.jpg"],
        )
    )
    assert "Rechnung 2026-0042" in text
    assert "rechnung.pdf" in text and "foto.jpg" in text
    assert "\\u" not in text


def test_detail_view_masks_bidi_in_path(tmp_path):
    """The detail panel must not show a bidi-mangled file name.

    Found by screenshot while verifying the mail preview: the panel renders
    ``result.path`` under "Technische Details", and for an attachment that path
    comes from the mail. Qt applies the bidi algorithm to plain text, so a file
    stored as ``Rechnung\\u202efdp.exe`` was displayed as ``Rechnungexe.pdf`` —
    an executable reading as a PDF, in the very panel that reports the trick.
    """
    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher
    from malaz.gui.main_window import _format_detail

    raw = (
        b"From: a@b.invalid\nTo: c@d.invalid\nSubject: Test\nMIME-Version: 1.0\n"
        b'Content-Type: multipart/mixed; boundary="B"\n\n'
        b"--B\nContent-Type: text/plain\n\nText\n"
        b"--B\nContent-Type: application/octet-stream\n"
        b'Content-Disposition: attachment; filename="Rechnung\xe2\x80\xaefdp.exe"\n\n'
        b"MZ\n--B--\n"
    )
    path = tmp_path / "m.eml"
    path.write_bytes(raw)
    d = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    result = d.scan_path(path)
    text = _format_detail(result)
    assert "\u202e" not in text, "der getarnte Name wird roh angezeigt"
    assert "\\u202e" in text, "die Maskierung fehlt"


def test_detail_view_shows_mail_preview_of_eml_inside_zip(tmp_path):
    """A mail in a CONTAINER must be readable, not just its indicators.

    The preview used to be appended to the top-level row only, while the nested
    results are rendered through the recursive branch of ``_format_detail``
    (which carried indicators and hashes). A .eml inside a ZIP therefore showed
    no content at all — the exact case a user drops in to see what was sent.
    """
    import zipfile

    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher
    from malaz.gui.main_window import _format_detail

    mail = (
        b"From: a@b.invalid\nTo: c@d.invalid\nSubject: ZIP-Mail Betreff\n"
        b"MIME-Version: 1.0\nContent-Type: text/plain\n\n"
        b"Text im Archivkoerper\n"
    )
    path = tmp_path / "archiv.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("mail.eml", mail)

    d = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    result = d.scan_path(path)
    assert result.detected_type == "zip"
    child = result.children[0]
    assert child.detected_type == "eml"
    assert "Betreff: ZIP-Mail Betreff" in child.mail_preview, "kein Preview am Kind"

    text = _format_detail(result)
    assert "Betreff: ZIP-Mail Betreff" in text, "der Preview fehlt in der Tiefe"
    assert "Text im Archivkoerper" in text



# -- Lokale URL-Blocklist: Link-Reputation ohne Netzwerk --------------------- #
#
# Der Offline-Teil der Link-Reputation: eine Datei mit SHA-256-Hashes von URLs
# (Muster wie die Datei-Hash-Blocklist). Kein Opt-in, kein Provider, kein
# Netzwerkpfad — deshalb unabhaengig von URL_REPUTATION_ENABLED.


def test_local_url_blocklist_hit_without_network(tmp_path, monkeypatch):
    from malaz import config

    bad = "http://evil.example.com/payload.bin"
    bl = tmp_path / "urls.sha256"
    bl.write_text(url_reputation.url_hash(bad) + "\n", encoding="utf-8")
    monkeypatch.setattr(config, "URL_BLOCKLIST_FILE", bl)
    monkeypatch.setattr(config, "URL_REPUTATION_ENABLED", False)
    monkeypatch.setattr(config, "URL_REPUTATION_ENDPOINT", "")

    def boom(*_a, **_k):
        raise AssertionError("lokaler Treffer darf kein Netzwerk ausloesen")

    monkeypatch.setattr("urllib.request.urlopen", boom)

    assert url_reputation.local_blocklist_enabled() is True
    assert url_reputation.enabled() is False
    result = url_reputation.lookup([bad])
    assert result.ran is True
    assert result.hits == {url_reputation.url_hash(bad): "local_malware"}


def test_local_url_blocklist_miss_is_not_a_hit(tmp_path, monkeypatch):
    from malaz import config

    bl = tmp_path / "urls.sha256"
    bl.write_text(url_reputation.url_hash("http://bad.example/x") + "\n", encoding="utf-8")
    monkeypatch.setattr(config, "URL_BLOCKLIST_FILE", bl)
    monkeypatch.setattr(config, "URL_REPUTATION_ENABLED", False)
    monkeypatch.setattr(config, "URL_REPUTATION_ENDPOINT", "")

    result = url_reputation.lookup(["https://harmlos.example/seite"])
    assert result.ran is True
    assert result.hits == {}


def test_local_url_blocklist_matches_despite_fragment(tmp_path, monkeypatch):
    """Der Hash ignoriert das Fragment — sonst umginge ein '#x' die Liste."""
    from malaz import config

    bl = tmp_path / "urls.sha256"
    bl.write_text(url_reputation.url_hash("http://evil.example/x") + "\n", encoding="utf-8")
    monkeypatch.setattr(config, "URL_BLOCKLIST_FILE", bl)
    monkeypatch.setattr(config, "URL_REPUTATION_ENABLED", False)
    monkeypatch.setattr(config, "URL_REPUTATION_ENDPOINT", "")

    result = url_reputation.lookup(["http://evil.example/x#abschnitt"])
    assert len(result.hits) == 1


def test_local_url_blocklist_absent_is_inactive(tmp_path, monkeypatch):
    from malaz import config

    monkeypatch.setattr(config, "URL_BLOCKLIST_FILE", tmp_path / "fehlt.sha256")
    monkeypatch.setattr(config, "URL_REPUTATION_ENABLED", False)
    monkeypatch.setattr(config, "URL_REPUTATION_ENDPOINT", "")
    assert url_reputation.local_blocklist_enabled() is False
    # Weder Liste noch Provider -> gar kein Lookup, klarer Grund.
    result = url_reputation.lookup(["http://evil.example/a"])
    assert result.ran is False


def test_local_hit_survives_provider_outage(tmp_path, monkeypatch):
    """Ein Provider-Ausfall darf einen lokalen Treffer nicht loeschen."""
    from malaz import config

    bad = "http://evil.example/payload"
    bl = tmp_path / "urls.sha256"
    bl.write_text(url_reputation.url_hash(bad) + "\n", encoding="utf-8")
    monkeypatch.setattr(config, "URL_BLOCKLIST_FILE", bl)
    monkeypatch.setattr(config, "URL_REPUTATION_ENABLED", True)
    monkeypatch.setattr(config, "URL_REPUTATION_ENDPOINT", "https://provider.invalid/v1")

    def boom(*_a, **_k):
        raise OSError("Netzwerk weg")

    monkeypatch.setattr("urllib.request.urlopen", boom)
    result = url_reputation.lookup([bad])
    assert result.error  # Ausfall sichtbar
    assert url_reputation.url_hash(bad) in result.hits


def test_pipeline_reports_local_url_hit(tmp_path, monkeypatch):
    """Die Pipeline meldet den lokalen Treffer als HIGH-Befund."""
    from malaz import config

    bad = "http://evil.example.com/payload.bin"
    bl = tmp_path / "urls.sha256"
    bl.write_text(url_reputation.url_hash(bad) + "\n", encoding="utf-8")
    monkeypatch.setattr(config, "URL_BLOCKLIST_FILE", bl)
    monkeypatch.setattr(config, "URL_REPUTATION_ENABLED", False)
    monkeypatch.setattr(config, "URL_REPUTATION_ENDPOINT", "")

    raw = (
        b"From: a@b.de\r\nTo: c@d.de\r\nSubject: Test\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Hier: " + bad.encode() + b"\r\n"
    )
    ctx = AnalysisContext(
        path=__import__("pathlib").Path("m.eml"),
        data=raw,
        detected_type="eml",
        size=len(raw),
    )
    hits = [i for i in EmlPipeline().analyze(ctx) if i.rule_id == "MAIL_LINK_REPUTATION"]
    assert hits, "lokaler URL-Treffer muss als Befund erscheinen"
    assert hits[0].severity.name == "HIGH"
    # Die Meldung darf keinen Provider behaupten.
    assert "Reputationsdienst" not in hits[0].detail


def test_local_check_covers_all_links_not_just_provider_payload(tmp_path, monkeypatch):
    """Die lokale Pruefung darf NICHT auf gefilterte/gekappte Links laufen.

    `_is_lookupable` und `URL_REPUTATION_MAX_LOOKUPS` begrenzen, was an einen
    DRITTEN gehen darf (Datenschutz). Die lokale Liste hat keinen Dritten zu
    schuetzen — wuerde sie dieselben Filter erben, verpasste sie stillschweigend
    jeden Link hinter dem Cap und jeden Link mit privatem Host.
    """
    from malaz import config

    # Ein Link mit privatem Host steht auf der Liste -> muss trotzdem treffen.
    internal = "http://intranet-host/malware.exe"
    bl = tmp_path / "urls.sha256"
    bl.write_text(url_reputation.url_hash(internal) + "\n", encoding="utf-8")
    monkeypatch.setattr(config, "URL_BLOCKLIST_FILE", bl)
    monkeypatch.setattr(config, "URL_REPUTATION_ENABLED", False)
    monkeypatch.setattr(config, "URL_REPUTATION_ENDPOINT", "")
    # Cap auf 1: der Treffer liegt bewusst HINTER dem Cap.
    monkeypatch.setattr(config, "URL_REPUTATION_MAX_LOOKUPS", 1)

    result = url_reputation.lookup(
        ["https://erster.example/a", "https://zweiter.example/b", internal]
    )
    assert url_reputation.url_hash(internal) in result.hits, (
        "lokale Pruefung lief auf der gekappten Provider-Liste"
    )


def test_no_clean_note_claims_provider_when_only_local_checked(tmp_path, monkeypatch):
    """Ohne Provider darf die Meldung keinen Reputationsdienst behaupten."""
    from malaz import config

    bl = tmp_path / "urls.sha256"
    bl.write_text(url_reputation.url_hash("http://evil.example/x") + "\n", encoding="utf-8")
    monkeypatch.setattr(config, "URL_BLOCKLIST_FILE", bl)
    monkeypatch.setattr(config, "URL_REPUTATION_ENABLED", False)
    monkeypatch.setattr(config, "URL_REPUTATION_ENDPOINT", "")

    raw = (
        b"From: a@b.de\r\nTo: c@d.de\r\nSubject: T\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"https://harmlos.example/seite\r\n"
    )
    ctx = AnalysisContext(
        path=__import__("pathlib").Path("m.eml"),
        data=raw,
        detected_type="eml",
        size=len(raw),
    )
    notes = [
        i for i in EmlPipeline().analyze(ctx) if i.rule_id == "MAIL_REPUTATION_CLEAN"
    ]
    assert notes, "ohne Treffer muss der Hinweis kommen"
    assert "Reputationsdienst" not in notes[0].detail
    assert "ohne Netzwerkzugriff" in notes[0].detail


# -- Absenderauthentifizierung sichtbar machen (SPF/DKIM/DMARC) ------------- #


def _auth_mail(auth_header: bytes, frm: bytes = b"Chef <chef@firma.de>") -> bytes:
    return (
        b"From: " + frm + b"\r\nTo: kunde@example.com\r\nSubject: Test\r\n"
        b"Message-ID: <x@firma.de>\r\nReceived: from mx.firma.de\r\n"
        + auth_header
        + b"\r\nText.\r\n"
    )


def test_auth_verdicts_distinguish_pass_fail_none_and_unknown():
    """Vier verschiedene Aussagen, die nicht zusammenfallen duerfen.

    ``pass`` und ``fail`` stehen im Header; ``none`` heisst, der Header
    erwaehnt das Verfahren nicht, ``unknown``, dass es gar keinen Header gibt.
    Vorher meldete Malaz nur den FEHLSCHLAG — fehlte die Authentifizierung
    ganz, sagte die Anzeige nichts, und Schweigen las sich wie Zustimmung.
    """
    from malaz.core.eml_analysis import auth_verdicts

    assert auth_verdicts("mx; spf=pass dkim=pass dmarc=pass") == {
        "spf": "pass", "dkim": "pass", "dmarc": "pass",
    }
    assert auth_verdicts("mx; spf=pass dkim=fail dmarc=pass")["dkim"] == "fail"
    assert auth_verdicts("mx; none") == {"spf": "none", "dkim": "none", "dmarc": "none"}
    assert auth_verdicts("") == {
        "spf": "unknown", "dkim": "unknown", "dmarc": "unknown",
    }


def test_missing_authentication_is_reported_not_silent():
    """Ein Absender ohne SPF/DKIM/DMARC muss sichtbar sein, nicht still."""
    from malaz.core.eml_analysis import analyze_structure, parse_mail

    def kinds(data: bytes) -> list[str]:
        return [k for k, _ in analyze_structure(parse_mail(data)).findings]

    # Alles bestanden: kein Befund.
    assert kinds(_auth_mail(b"Authentication-Results: mx; spf=pass dkim=pass dmarc=pass\r\n")) == []

    # Ein Fehlschlag ist NICHT dasselbe wie ein fehlendes Verfahren — sonst
    # meldet dasselbe Verfahren zweimal mit entgegengesetztem Wortlaut.
    failed = kinds(_auth_mail(b"Authentication-Results: mx; spf=pass dkim=fail dmarc=pass\r\n"))
    assert "MAIL_AUTH_FAIL" in failed
    assert "MAIL_AUTH_ABSENT" not in failed, failed

    # Kein Header und kein Verfahren: beide melden das Fehlen.
    assert "MAIL_AUTH_ABSENT" in kinds(_auth_mail(b""))
    assert "MAIL_AUTH_ABSENT" in kinds(
        _auth_mail(b"Authentication-Results: mx; none\r\n")
    )


def test_a_mail_without_a_server_does_not_double_count():
    """Ohne Received-Kette ist das Fehlen der Authentifizierung dieselbe Ursache.

    Eine generierte Datei hat nie einen Mailserver gesehen — dann gibt es
    nichts zu authentifizieren. Die gewichtete Aussage traegt MAIL_NO_RECEIVED;
    die Auth-Notiz bleibt Diagnose.
    """
    from malaz.core.eml_analysis import analyze_structure, parse_mail

    data = (
        b"From: Chef <chef@firma.de>\r\nTo: k@e.com\r\nSubject: T\r\n"
        b"Message-ID: <x@f.de>\r\n\r\nText.\r\n"  # kein Received
    )
    kinds = [k for k, _ in analyze_structure(parse_mail(data)).findings]
    assert "MAIL_NO_RECEIVED" in kinds
    assert "MAIL_AUTH_UNVERIFIABLE" in kinds
    assert "MAIL_AUTH_ABSENT" not in kinds, kinds


def test_foreign_address_in_the_display_name_is_reported():
    """Der Klassiker: 'support@paypal.com' als Name, gesendet von woanders.

    Die Markenliste deckt nur bekannte Marken ab; diese Pruefung erwischt die
    Technik selbst, unabhaengig davon, welchen Namen der Absender behauptet.
    """
    from malaz.core.eml_analysis import analyze_structure, parse_mail

    # Eine Adresse, die KEINE bekannte Marke nennt: nur so kommt der
    # Adress-Zweig zum Zug. Bei "support@paypal.com" gewinnt die Markenpruefung
    # — beide zusammen waren 30 + 30 fuer denselben Satz.
    data = _auth_mail(
        b"Authentication-Results: mx; spf=pass dkim=pass dmarc=pass\r\n",
        frm=b'"chef@anderefirma.de" <boese@evil.tld>',
    )
    findings = dict(analyze_structure(parse_mail(data)).findings)
    assert "MAIL_DISPLAY_ADDR_MISMATCH" in findings, sorted(findings)
    assert "anderefirma.de" in findings["MAIL_DISPLAY_ADDR_MISMATCH"]

    # Und der Markenfall meldet genau EINEN der beiden.
    brand = _auth_mail(
        b"Authentication-Results: mx; spf=pass dkim=pass dmarc=pass\r\n",
        frm=b'"support@paypal.com" <boese@evil.tld>',
    )
    brand_findings = dict(analyze_structure(parse_mail(brand)).findings)
    assert "MAIL_DISPLAY_NAME_SPOOF" in brand_findings, sorted(brand_findings)
    assert "MAIL_DISPLAY_ADDR_MISMATCH" not in brand_findings, (
        "dieselbe Ursache zweimal gemeldet: " + str(sorted(brand_findings))
    )

    # Gegenrichtung: derselbe Name, aber die Adresse passt — kein Befund.
    clean = _auth_mail(
        b"Authentication-Results: mx; spf=pass dkim=pass dmarc=pass\r\n",
        frm=b'"support@firma.de" <support@firma.de>',
    )
    assert "MAIL_DISPLAY_ADDR_MISMATCH" not in dict(
        analyze_structure(parse_mail(clean)).findings
    )


def test_the_viewer_names_each_mechanism_and_the_sender_check():
    """Die Anzeige nennt jedes Verfahren einzeln — nicht den Rohtext.

    Der Rohtext ist das, was der empfangende Server geschrieben hat; gebraucht
    wird die Aussage „nutzt dieser Absender das Verfahren ueberhaupt". Beides
    steht in der Ausgabe, das Urteil zuerst.
    """
    from malaz.core.eml_analysis import parse_mail
    from malaz.core.mail_view import render_mail

    text = render_mail(
        parse_mail(
            _auth_mail(b"Authentication-Results: mx; spf=pass dkim=fail dmarc=none\r\n")
        )
    )
    assert "SPF bestanden" in text
    assert "DKIM FEHLGESCHLAGEN" in text
    assert "DMARC nicht verwendet" in text

    # Ohne Header: „nicht beurteilbar", nicht Schweigen.
    bare = render_mail(parse_mail(_auth_mail(b"")))
    assert "nicht beurteilbar" in bare

    # Fremde Adresse im Anzeigenamen wird auch angezeigt.
    shown = render_mail(
        parse_mail(_auth_mail(b"", frm=b'"support@paypal.com" <boese@evil.tld>'))
    )
    assert "Absenderpruefung" in shown and "paypal.com" in shown


def test_a_claimed_pass_next_to_spoofing_is_reported():
    """Eine gefaelschte Auth-Kopfzeile ist das, was einen Spoof TARNT.

    ``Authentication-Results`` schreibt der empfangende Server — in einer Datei,
    die der Nutzer prueft, sind es aber Bytes, und die schreibt der Angreifer.
    Gemessen: ein gefaelschtes ``spf=pass dkim=pass dmarc=pass`` liess die
    Meldung „Absender authentifiziert nicht" vollstaendig verschwinden und
    wurde als „SPF bestanden" angezeigt. Behaupteter Pass NEBEN einem
    Spoofing-Signal ist keine zweite Tatsache, sondern EINE Taeuschung.
    """
    from malaz.core.eml_analysis import analyze_structure, parse_mail

    def findings(data: bytes) -> dict[str, str]:
        return dict(analyze_structure(parse_mail(data)).findings)

    claimed = b"Authentication-Results: mx; spf=pass dkim=pass dmarc=pass\r\n"

    # Gefaelschter Pass + fremde Adresse im Anzeigenamen.
    spoofed = _auth_mail(claimed, frm=b'"chef@anderefirma.de" <boese@evil.tld>')
    assert "MAIL_AUTH_CLAIMED_SPOOF" in findings(spoofed), sorted(findings(spoofed))

    # Gefaelschter Pass + fremde Antwortadresse.
    reply = _auth_mail(claimed).replace(
        b"To: kunde@example.com", b"To: kunde@example.com\r\nReply-To: x@anderefirma.de"
    )
    assert "MAIL_AUTH_CLAIMED_SPOOF" in findings(reply), sorted(findings(reply))

    # Gegenrichtung: echter Pass ohne Spoofing-Signal ergibt keinen Befund.
    clean = _auth_mail(claimed)
    assert findings(clean) == {}, sorted(findings(clean))


def test_the_auth_line_is_labelled_as_self_declared():
    """Die Anzeige darf den Header nicht als Feststellung praesentieren."""
    from malaz.core.eml_analysis import parse_mail
    from malaz.core.mail_view import render_mail

    text = render_mail(
        parse_mail(
            _auth_mail(b"Authentication-Results: mx; spf=pass dkim=pass dmarc=pass\r\n")
        )
    )
    assert "laut Datei, nicht verifiziert" in text, text


def test_the_cli_shows_the_mail_header_and_the_sender_checks(capsys, tmp_path):
    """Die Anzeige darf nicht nur im GUI-Detailpanel haengen.

    Der Kopfblock traegt genau das, was der Nutzer verlangt hat — ob der
    Absender SPF/DKIM/DMARC nutzt und ob die angezeigte Adresse die tatsaechliche
    ist. Wer ``--cli`` benutzt oder die Tabelle liest, sah bisher nur die
    Befunde, nicht das Urteil, das sie erklaert.
    """
    from malaz.__main__ import run_cli

    path = tmp_path / "spoof.eml"
    path.write_bytes(
        _auth_mail(
            b"Authentication-Results: mx; spf=fail dkim=none dmarc=fail\r\n",
            frm=b'"chef@anderefirma.de" <boese@evil.tld>',
        )
    )
    run_cli([str(path)], None)
    out = capsys.readouterr().out

    assert "Authentifizierung (laut Datei, nicht verifiziert)" in out
    assert "SPF FEHLGESCHLAGEN" in out
    assert "DKIM nicht verwendet" in out
    assert "Absenderpruefung" in out and "anderefirma.de" in out
    # Der Body gehoert nicht in eine Zusammenfassung.
    assert "Text." not in out


def test_no_corpus_mail_is_refused_by_the_depth_guard():
    """Kein Korpus-Fixture darf an der .eml-Tiefengrenze scheitern.

    Die Behauptung stand in Runde 7 als „an einer Korpus-Phishing-Mail fiel das
    Urteil von ROT 100 auf GELB 30" im Changelog und war FALSCH — kein
    Fixture der beiden Korpora ist betroffen, der Golden-Snapshot hat sich nie
    abwaerts bewegt. Der Satz ist korrigiert; diese Pruefung haelt die Aussage
    fest, damit sie beim naechsten Mal sofort auffliegt.

    Sie ist bewusst billig: nur die Schaetzung, kein Parse. Bei einer dreimal
    reparierten Heuristik, die jedes Mal ein neues Loch bekam, ist genau das die
    Pruefung, die eine Ueberkorrektur zuerst zeigen wuerde.
    """
    import sys
    from pathlib import Path

    from malaz.core.email_extract import mime_depth_note

    scripts = Path(__file__).resolve().parent.parent / "scripts"
    sys.path.insert(0, str(scripts))
    import make_benign_corpus as benign
    import make_test_corpus_extended as ext

    # Die Register heissen UNTERSCHIEDLICH und haben unterschiedliche
    # Eintragsformen: ``make_benign_corpus.BENIGN`` sind 2-Tupel (Name, Bauer),
    # ``make_test_corpus_extended.EXTENDED_CORPUS`` sind 3-Tupel (Name, Bauer,
    # erwartete Regeln). Die erste Fassung suchte nur nach ``CORPUS``/``
    # EXTENDED_CORPUS`` — fuer den harmlosen Korpus kam damit eine LEERE Liste
    # heraus, und die Sammel-Untergrenze ``checked >= 5`` fiel nicht auf, weil
    # ``ext`` sie allein erfuellte. Der Test deckte also die Haelfte ab und
    # behauptete beide: dieselbe Klasse wie die drei Doku-Saetze, nur im Test.
    registries = (
        ("make_benign_corpus.BENIGN", benign, "BENIGN", 1),
        ("make_test_corpus_extended.EXTENDED_CORPUS", ext, "EXTENDED_CORPUS", 5),
    )
    refused: list[str] = []
    for label, module, attr, minimum in registries:
        registry = getattr(module, attr, None)
        assert registry, f"{label} fehlt oder ist leer — Registry umbenannt?"
        eml = [(entry[0], entry[1]) for entry in registry if entry[0].endswith(".eml")]
        assert len(eml) >= minimum, (
            f"{label}: nur {len(eml)} .eml-Fixtures gefunden, erwartet >= {minimum} "
            "— die Pruefung wuerde weniger abdecken, als sie behauptet"
        )
        for filename, builder in eml:
            if mime_depth_note(builder()) is not None:
                refused.append(filename)

    assert not refused, (
        "Korpus-Fixtures werden von der Tiefengrenze abgelehnt: "
        + ", ".join(refused)
        + " — die Ablehnung ist GEWICHTET, das Urteil dieser Dateien faellt damit"
    )


def test_attacker_controlled_headers_cannot_flood_the_panel():
    """Kopfzeilen sind angreiferkontrolliert und brauchen dieselbe Grenze wie der Body.

    Der Body ist bei ``_MAX_BODY_CHARS`` gedeckelt („so a pathological mail
    cannot flood the panel"); Subject, Anzeigename, ``Authentication-Results``
    und Reply-To waren es nicht. Gemessen vorher: eine Mail mit einem
    200 000 Zeichen langen Betreff ergab einen 600 KB grossen Preview mit EINER
    200 027 Zeichen langen Zeile — und seit die CLI den Kopfblock druckt, landet
    das auch auf stdout. ``link.url`` hatte dieselbe Luecke: der Linktext war
    bei 120 gekappt, die URL nicht.

    Die Kuerzung wird ausgewiesen: ein stiller Schnitt wuerde genau den Trick
    verbergen, den die Anzeige zeigen soll.
    """
    from malaz.core.eml_analysis import parse_mail
    from malaz.core.mail_view import render_mail

    big = "A" * 20_000
    data = (
        b"From: " + big.encode() + b" <x@evil.tld>\r\nTo: k@e.com\r\n"
        b"Subject: " + big.encode() + b"\r\nMessage-ID: <x@f.de>\r\n"
        b"Received: from mx\r\nAuthentication-Results: " + big.encode()
        + b"\r\n\r\nText.\r\n"
    )
    out = render_mail(parse_mail(data))

    assert len(out) < 10_000, f"Preview {len(out)} Bytes fuer {len(data)} Bytes Eingabe"
    longest = max(len(line) for line in out.splitlines())
    assert longest < 1_000, f"laengste Zeile {longest} Zeichen"
    assert "gekürzt" in out, "die Kuerzung muss sichtbar sein, nicht still"

    # Gegenrichtung: normale Kopfzeilen bleiben unveraendert.
    plain = render_mail(parse_mail(_auth_mail(b"Authentication-Results: mx; spf=pass\r\n")))
    assert "… (gekürzt" not in plain
    assert "Betreff: Test" in plain


@pytest.fixture()
def _scan_dispatcher():
    """Dispatcher mit abgeschalteten AV-Engines: hier zaehlt die Wegewahl, nicht AV."""
    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher

    return Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )


def _tmp_eml(data: bytes):
    """Schreibt Mail-Bytes in eine Temp-Datei und gibt den Pfad zurueck."""
    import tempfile

    fd, path = tempfile.mkstemp(suffix=".eml", prefix="malaz_test_")
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return path


def test_padded_header_cannot_route_a_mail_into_the_text_path(_scan_dispatcher):
    """Ein langer Anzeigename darf die Mail-Erkennung nicht abschalten.

    Regression: ``_classify_text`` prüfte die ersten 4096 Bytes. Ein
    Anzeigename mit mehr Padding schob die ``Message-ID`` aus dem Fenster, die
    Datei wurde als ``text`` eingestuft — und damit fiel die GESAMTE MAIL_*-
    Schicht weg: Absenderauthentifizierung, Absendervergleich, Linkanalyse.
    Gemessen: Padding 0/1000/4000 -> ``eml`` mit ``MAIL_AUTH_FAIL``;
    5000/20000 -> ``text`` ohne einen einzigen MAIL_*-Befund.

    Die Erkennung folgt jetzt dem Kopfblock (bis zur ersten Leerzeile) statt
    einem festen Fenster.
    """
    def mail(pad: int) -> bytes:
        return (
            b"From: " + b"A" * pad + b" <boese@evil.tld>\r\nTo: k@e.com\r\n"
            b"Subject: Rechnung\r\nMessage-ID: <x@f.de>\r\nReceived: from mx\r\n"
            b"Authentication-Results: mx; spf=fail dkim=fail dmarc=fail\r\n\r\nText.\r\n"
        )

    for pad in (0, 4_000, 5_000, 20_000):
        path = _tmp_eml(mail(pad))
        result = _scan_dispatcher.scan_path(path)
        ids = {i.rule_id for i in result.all_indicators()}
        assert result.detected_type == "eml", (
            f"Padding {pad}: als '{result.detected_type}' eingestuft — die "
            "Mail-Pruefungen laufen damit gar nicht"
        )
        assert "MAIL_AUTH_FAIL" in ids, f"Padding {pad}: MAIL_* fehlen: {sorted(ids)}"


def test_a_mail_without_message_id_stays_a_mail(_scan_dispatcher):
    """Ohne Message-ID muss die Mail ERST RECHT als Mail erkannt werden.

    Regression aus dem eigenen Fix: die erste Fassung der Kopfblock-Grenze
    schnitt den Leerzeilen-Trenner MIT weg, aber ``_looks_like_mail`` verlangt
    ``has_body_separator``. Der zweite Pfad des Praedikats konnte damit nie
    greifen — genau der Fall, den sein Docstring als Grund nennt: handgebaute
    Phishing-Mails lassen die Message-ID weg, und in der Textstufe kann
    ``MAIL_NO_MESSAGE_ID`` nie feuern. Gemessen: mit Trenner ausgeschlossen
    ergab dieselbe Mail MIT Message-ID „eml" und OHNE „text".
    """
    base = (
        b"From: boese@evil.tld\r\nTo: k@e.com\r\nSubject: Rechnung\r\n"
        b"MIME-Version: 1.0\r\nReturn-Path: <boese@evil.tld>\r\n\r\nBitte pruefen.\r\n"
    )
    result = _scan_dispatcher.scan_path(_tmp_eml(base))
    ids = {i.rule_id for i in result.all_indicators()}
    assert result.detected_type == "eml", f"als '{result.detected_type}' eingestuft"
    assert "MAIL_NO_MESSAGE_ID" in ids, sorted(ids)


def test_long_display_name_does_not_stall_the_analysis():
    """Eine lange Kopfzeile darf die Analyse nicht quadratisch bremsen.

    Regression (eigener Fehler): die Pruefung „fremde Adresse im Anzeigenamen"
    benutzte ``[\\w.+-]+@`` OHNE Obergrenze. Auf angreiferkontrolliertem Text ist
    das quadratisch — ``[\\w.+-]+`` setzt an jeder Position an und laeuft dann
    bis ans Ende der Zeichenkette auf der Suche nach einem ``@``, das nie kommt.
    Gemessen: EIN ``findall``-Aufruf brauchte 10,98 s bei 40 000 Zeichen und
    276,9 s bei 200 000 — dieselbe Form wie ``_ANCHOR_RE`` in Runde 3, und
    erreichbar ueber ein ZIP-Mitglied fuer wenige Angreiferbytes (Deflate
    solcher Zeilen ist ~1000:1).

    Die Quantoren sind jetzt auf die RFC-5321-Grenzen begrenzt (64 / 255).
    Nachher: 0,048 s bei 40 000 und 0,233 s bei 200 000 Zeichen.
    """
    import time

    from malaz.core.eml_analysis import analyze_structure, parse_mail

    for size, budget in ((40_000, 2.0), (200_000, 5.0)):
        big = "A" * size
        data = (
            b"From: " + big.encode() + b" <x@evil.tld>\r\nTo: k@e.com\r\nSubject: "
            + big.encode() + b"\r\nMessage-ID: <x@f.de>\r\nReceived: from mx\r\n"
            b"Authentication-Results: " + big.encode() + b"\r\n\r\nText.\r\n"
        )
        facts = parse_mail(data)
        started = time.monotonic()
        analyze_structure(facts)
        elapsed = time.monotonic() - started
        assert elapsed < budget, (
            f"{size} Zeichen brauchten {elapsed:.1f}s (Grenze {budget}s) — "
            "die Adress-Regex ist wieder unbeschraenkt"
        )


# --------------------------------------------------------------------------- #
# Behauptungen gegen die Received-Kette
# --------------------------------------------------------------------------- #
#
# Alles in einer Mail ist angreiferkontrolliert. Eine Datei, die nie durch ein
# Gateway lief, kann "Authentication-Results: mx.microsoft.com; spf=pass"
# selbst hineinschreiben. Die Kette ist die einzige Angabe, die ein Faelscher
# mitschreiben muss, wenn die Mail echt aussehen soll — daran wird gemessen.


def _mail_with_chain(*headers: bytes, body: bytes = b"Text.\r\n") -> bytes:
    """Eine Mail mit zweistufiger Kette; ``headers`` wird davor gehaengt."""
    return (
        b"Received: from mx.firma.de (mx.firma.de [203.0.113.9]) by postfach.opfer.de "
        b"(using TLSv1.2 with cipher AES256) with ESMTPS; Tue, 1 Jan 2030 10:00:05 +0000\r\n"
        b"Received: from boese.evil.tld (boese.evil.tld [198.51.100.7]) by mx.firma.de "
        b"with ESMTP; Tue, 1 Jan 2030 09:59:58 +0000\r\n"
        b"From: Firma <service@firma.de>\r\n"
        b"To: opfer@opfer.de\r\n"
        b"Subject: Rechnung\r\n"
        b"Message-ID: <x@firma.de>\r\n"
        b"Date: Tue, 1 Jan 2030 10:00:00 +0000\r\n"
        + b"".join(headers)
        + b"\r\n"
        + body
    )


def _structure_ids(raw: bytes) -> set[str]:
    return {kind for kind, _ in analyze_structure(parse_mail(raw)).findings}


def test_received_chain_is_parsed_with_ips_and_timestamps():
    """Die Kette wird zerlegt, nicht nur gezaehlt.

    Ohne Stationen, IPs und Zeitstempel laesst sich keine der Behauptungen
    pruefen — die blosse Anzahl sagt nichts darueber, wer die Mail hatte.
    """
    facts = parse_mail(_mail_with_chain())
    assert len(facts.received_hops) == 2
    newest, oldest = facts.received_hops
    assert newest.by_host == "postfach.opfer.de"
    assert newest.ip == "203.0.113.9"
    assert newest.protocol == "ESMTPS"
    assert newest.tls == "TLSv1.2"
    assert "1 Jan 2030 10:00:05" in newest.stamp
    # Die LETZTE Station ist die, mit der sich der Absender verbunden hat.
    assert oldest.from_host == "boese.evil.tld"
    assert oldest.ip == "198.51.100.7"
    # Die Faltung gehoert zur selben Station: der Zeitstempel der ersten darf
    # nicht aus einer spaeteren Kopfzeile stammen (der erste Entwurf zog
    # "dmarc=pass" aus Authentication-Results als Zeitstempel ein).
    assert "dmarc" not in oldest.stamp


def test_forged_authentication_results_is_caught():
    """Der Kern: eine Behauptung ohne Deckung in der Kette.

    Die gedeckte Fassung darf NICHT anschlagen — sonst waere der Befund
    Rauschen und wuerde bei jeder echten Mail mit Gateway feuern.
    """
    gedeckt = _structure_ids(
        _mail_with_chain(b"Authentication-Results: mx.firma.de; spf=pass; dmarc=pass\r\n")
    )
    assert "MAIL_AUTH_CLAIM_UNBACKED" not in gedeckt

    gefaelscht = _structure_ids(
        _mail_with_chain(
            b"Authentication-Results: mx.microsoft.com; spf=pass; dkim=pass; dmarc=pass\r\n"
        )
    )
    assert "MAIL_AUTH_CLAIM_UNBACKED" in gefaelscht


def test_private_ip_as_sender_station_is_reported():
    """Eine Mail von aussen kann nicht von 10.x kommen."""
    raw = (
        b"Received: from intern (intern [10.0.0.5]) by mx.firma.de with ESMTP; "
        b"Tue, 1 Jan 2030 10:00:00 +0000\r\n"
        b"From: a@firma.de\r\nMessage-ID: <x@firma.de>\r\n\r\nT\r\n"
    )
    assert "MAIL_RECEIVED_PRIVATE_IP" in _structure_ids(raw)

    oeffentlich = _mail_with_chain()
    assert "MAIL_RECEIVED_PRIVATE_IP" not in _structure_ids(oeffentlich)


def test_dmarc_alignment_is_computed_not_read():
    """DMARC-Alignment selbst rechnen statt die Behauptung lesen.

    Ausgerichtet ist es, wenn die From-Domain mit der Envelope-Domain ODER der
    DKIM-Domain uebereinstimmt (relaxed: registrierbare Domain).
    """
    ausgerichtet = _structure_ids(
        _mail_with_chain(b"Return-Path: <bounce@firma.de>\r\n")
    )
    assert "MAIL_DMARC_ALIGNMENT_FAIL" not in ausgerichtet

    # Ueber DKIM gerettet: Envelope fremd, Signatur eigen.
    ueber_dkim = _structure_ids(
        _mail_with_chain(
            b"Return-Path: <b@fremd.tld>\r\n",
            b"DKIM-Signature: v=1; d=firma.de; s=s; bh=x\r\n",
        )
    )
    assert "MAIL_DMARC_ALIGNMENT_FAIL" not in ueber_dkim

    ohne = _structure_ids(
        _mail_with_chain(
            b"Return-Path: <b@fremd.tld>\r\n",
            b"DKIM-Signature: v=1; d=andere.tld; s=s; bh=x\r\n",
        )
    )
    assert "MAIL_DMARC_ALIGNMENT_FAIL" in ohne


def test_dkim_signing_domain_is_read_and_compared():
    """d=/s= auslesen; eine fremde Signaturdomain ist ein Befund."""
    facts = parse_mail(_mail_with_chain(b"DKIM-Signature: v=1; a=rsa-sha256; d=evil.tld; s=sel; bh=abc\r\n"))
    assert facts.dkim_domain == "evil.tld"
    assert facts.dkim_selector == "sel"
    assert "MAIL_DKIM_DOMAIN_MISMATCH" in _structure_ids(
        _mail_with_chain(b"DKIM-Signature: v=1; a=rsa-sha256; d=evil.tld; s=sel; bh=abc\r\n")
    )
    eigen = _structure_ids(
        _mail_with_chain(b"DKIM-Signature: v=1; a=rsa-sha256; d=firma.de; s=sel; bh=abc\r\n")
    )
    assert "MAIL_DKIM_DOMAIN_MISMATCH" not in eigen


def test_filter_claims_are_labelled_as_claims():
    """SCL und X-Spam-Status sind Behauptungen, nicht Messwerte."""
    facts = parse_mail(
        _mail_with_chain(
            b"X-Spam-Status: No, score=-2.1\r\n",
            b"X-Microsoft-Antispam: BCL:0;PCL:0;SCL:1\r\n",
        )
    )
    assert set(facts.filter_claims) == {"X-Spam-Status", "X-Microsoft-Antispam"}
    # Ob daraus ein BEFUND wird, haengt am Widerspruch zur Kette — das prueft
    # test_filter_claim_needs_a_contradiction. Hier steht nur, dass die
    # Kopfzeilen ueberhaupt eingesammelt werden (sie erscheinen in der
    # Vorschau, auch ohne Befund).
    assert "MAIL_FILTER_CLAIM" not in _structure_ids(_mail_with_chain())


def test_delivery_time_gap_is_reported():
    """Date-Kopf gegen die erste Zustellung — beide faelschbar, aber sie
    muessen zueinander passen."""
    nah = _mail_with_chain()
    assert "MAIL_RECEIVED_TIME_ANOMALY" not in _structure_ids(nah)

    weit = _mail_with_chain().replace(
        b"Tue, 1 Jan 2030 10:00:00 +0000", b"Sat, 5 Jan 2030 10:00:00 +0000"
    )
    assert "MAIL_RECEIVED_TIME_ANOMALY" in _structure_ids(weit)


def test_weak_tls_claim_is_reported_but_weightless():
    """Die TLS-Angabe stammt aus der Datei — berichten, nicht bewerten."""
    schwach = _mail_with_chain().replace(b"TLSv1.2", b"TLSv1.0")
    assert "MAIL_RECEIVED_WEAK_TLS" in _structure_ids(schwach)
    assert "MAIL_RECEIVED_WEAK_TLS" not in _structure_ids(_mail_with_chain())


def test_hidden_html_techniques_are_found_in_the_body_report():
    """Die EINE Stelle, die den HTML-Rumpf auf Verstecke prueft.

    `analyze_structure` hatte dieselben drei Techniken noch einmal
    (MAIL_HTML_HIDDEN_TEXT, MEDIUM/15). Eine Mail mit display:none bekam BEIDE
    Befunde — +20 Punkte mit fast gleichem Titel, gemessen an
    dist/Testdateien-EML/Phishing/phish_body.eml. Jetzt prueft nur noch
    analyze_body, und die Strukturanalyse sagt dazu nichts.
    """
    from malaz.core.eml_analysis import analyze_body

    def report(html: bytes):
        raw = (
            b"Received: from mx (mx [198.51.100.1]) by p; Tue, 1 Jan 2030 10:00:00 +0000\r\n"
            b"From: a@firma.de\r\nMessage-ID: <x@firma.de>\r\n"
            b"MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
            + html + b"\r\n"
        )
        return analyze_body(parse_mail(raw))

    assert not report(b"<p>Rechnung</p>").hidden_text
    for technik in (
        b"<p style='font-size:0px'>geheim</p>",
        b"<div style='display:none'>geheim</div>",
        b"<span style='visibility:hidden'>geheim</span>",
        b"<p style='opacity:0'>geheim</p>",
        b"<p style='color:#ffffff'>geheim</p>",
        b"<p style='color:white'>geheim</p>",
        b"<p style='max-height:0'>geheim</p>",
    ):
        assert report(technik).hidden_text, technik

    # Und die Strukturanalyse meldet dazu NICHTS mehr — sonst zaehlt dieselbe
    # Ursache zweimal.
    for technik in (b"<p style='font-size:0px'>g</p>", b"<div style='display:none'>g</div>"):
        raw = (
            b"Received: from mx (mx [198.51.100.1]) by p; Tue, 1 Jan 2030 10:00:00 +0000\r\n"
            b"From: a@firma.de\r\nMessage-ID: <x@firma.de>\r\n"
            b"MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
            + technik + b"\r\n"
        )
        ids = _structure_ids(raw)
        assert "MAIL_HTML_HIDDEN_TEXT" not in ids
        assert "MAIL_BODY_HIDDEN_TEXT" not in ids  # kommt aus der Pipeline


def test_tracking_pixel_is_reported_by_the_body_report():
    """Ein 1x1-Bild ist ein Zaehlpixel, kein versteckter Text.

    Zusammen in einem Befund mit 15 Punkten kippte jede gespeicherte legitime
    HTML-Werbe-Mail von GRUEN auf GELB. Getrennt: hidden_text bleibt aus,
    tracking_pixel an.
    """
    from malaz.core.eml_analysis import analyze_body

    def report(html: bytes):
        raw = (
            b"Received: from mx (mx [198.51.100.1]) by p; Tue, 1 Jan 2030 10:00:00 +0000\r\n"
            b"From: a@firma.de\r\nMessage-ID: <x@firma.de>\r\n"
            b"MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
            + html + b"\r\n"
        )
        return analyze_body(parse_mail(raw))

    pixel = b"<img src='http://x.tld/p.gif' width='1' height='1'>"
    versteckt = b"<p style='font-size:0px'>geheim</p>"

    nur_pixel = report(pixel)
    assert nur_pixel.tracking_pixel
    assert not nur_pixel.hidden_text

    nur_text = report(versteckt)
    assert nur_text.hidden_text
    assert not nur_text.tracking_pixel

    beides = report(versteckt + pixel)
    assert beides.hidden_text and beides.tracking_pixel


def test_message_id_domain_is_compared_with_the_sender():
    """Die Message-ID soll eine Domain tragen, die zum Absender passt."""
    fremd = _mail_with_chain().replace(b"<x@firma.de>", b"<x@fremd.tld>")
    assert "MAIL_MESSAGE_ID_DOMAIN" in _structure_ids(fremd)
    assert "MAIL_MESSAGE_ID_DOMAIN" not in _structure_ids(_mail_with_chain())

    ohne_domain = _mail_with_chain().replace(b"<x@firma.de>", b"<ohne-domain>")
    assert "MAIL_MESSAGE_ID_ODD" in _structure_ids(ohne_domain)


def test_mail_preview_shows_chain_and_claims():
    """Die Vorschau muss zeigen, wer was behauptet — sonst liest sich eine
    mitgeschriebene Authentication-Results wie ein Urteil."""
    from malaz.core.mail_view import render_mail

    raw = _mail_with_chain(
        b"Authentication-Results: mx.microsoft.com; spf=pass; dmarc=pass\r\n",
        b"DKIM-Signature: v=1; d=evil.tld; s=sel; bh=abc\r\n",
        b"X-Spam-Status: No, score=-2.1\r\n",
    )
    text = render_mail(parse_mail(raw))
    assert "Bescheinigt von: mx.microsoft.com" in text
    assert "DKIM-Auszeichnung: evil.tld" in text
    assert "Empfangsweg (2 Stationen" in text
    assert "198.51.100.7" in text, "die Absender-IP fehlt"
    assert "Behauptungen fremder Filter" in text
    assert "stammen aus der Datei" in text


def test_authserv_id_requires_a_server_name():
    """RFC 8601 verlangt einen authserv-id vor dem ersten Semikolon.

    Fehlt er, faengt der erste Token bereits ein "method=result" an. Ihn als
    Servernamen zu lesen meldete "behauptet bestandene Authentifizierung durch
    'spf'" — ein Satz, der nichts bedeutet. Ohne Namen gibt es niemanden, den
    man gegen die Kette halten koennte.
    """
    from malaz.core.eml_analysis import parse_mail

    def claimed(header: bytes) -> str:
        raw = b"From: a@b.de\r\nAuthentication-Results: " + header + b"\r\n\r\nT\r\n"
        return parse_mail(raw).auth_claimed_by

    assert claimed(b"mx.microsoft.com; spf=pass; dmarc=pass") == "mx.microsoft.com"
    assert claimed(b"spf=fail; dkim=none; dmarc=fail") == ""
    assert claimed(b"") == ""


def test_quoted_angle_brackets_do_not_hide_the_real_sender():
    """Die Umgehung, die der Parser vorher zuliess.

    RFC 5322 erlaubt `<` und `>` INNERHALB eines quoted-string. Wer den ersten
    `<` nimmt, liest bei
        From: "x <service@bank.tld>" <boese@evil.tld>
    die vom Angreifer behauptete Adresse als Absender und verwirft die echte —
    Anzeigename, Marken- und Domainpruefung laufen dann alle gegen die
    behauptete Domain und melden NICHTS. Gemessen vor dem Fix: keine Befunde.
    """
    raw = (
        b"Received: from mx (mx [198.51.100.1]) by p; Tue, 1 Jan 2030 10:00:00 +0000\r\n"
        b'From: "x <service@bank.tld>" <boese@evil.tld>\r\n'
        b"To: k@f.de\r\nMessage-ID: <x@f.de>\r\n\r\nT\r\n"
    )
    facts = parse_mail(raw)
    assert facts.from_addr == "boese@evil.tld", "der ECHTE Absender muss gewinnen"
    assert "<service@bank.tld>" in facts.from_display
    assert "MAIL_DISPLAY_ADDR_MISMATCH" in _structure_ids(raw)


def test_address_parsing_stays_correct_with_quotes():
    """Randfaelle des anfuehrungszeichen-bewussten Parsers."""
    from malaz.core.eml_analysis import _split_address

    assert _split_address('"Chef" <c@d.de>') == ("Chef", "c@d.de")
    assert _split_address('"a<b" <c@d>') == ("a<b", "c@d")
    assert _split_address('"quoted" <a@b>, "z" <c@d>') == ("quoted", "a@b")
    assert _split_address("<a>") == ("", "a")
    assert _split_address("a@b") == ("", "a@b")
    # Offenes Anfuehrungszeichen: nichts mehr ausserhalb, also kein Absender.
    assert _split_address('"no closing quote <a@b>') == ("", '"no closing quote <a@b>')


def test_address_list_yields_the_first_mailbox():
    """BUG-071: a mailbox-list was returned as ONE addr-spec.

    ``From: a@b.de, c@d.de`` produced ``from_addr='a@b.de, c@d.de'``; the
    domain then read ``d.de, c@d.de`` and fired reply-to/return-path/DMARC/
    message-id mismatches (60 -> RED) for otherwise consistent headers.
    """
    from malaz.core.eml_analysis import _split_address

    assert _split_address("a@b.de, c@d.de") == ("", "a@b.de")
    assert _split_address("Team: a@b.de;") == ("", "a@b.de")
    # The first mailbox wins, not the last one.
    assert _split_address("Erster <eins@a.de>, Zweiter <zwei@b.de>") == (
        "Erster",
        "eins@a.de",
    )
    # A plain single address is unchanged.
    assert _split_address(" a@b ") == ("", "a@b")


def test_mailbox_list_does_not_manufacture_mismatch_findings():
    """BUG-071 end-to-end: correct headers stay free of false mismatches."""
    raw = (
        b"From: a@firma.de, c@firma.de\r\n"
        b"Reply-To: a@firma.de\r\n"
        b"Return-Path: <bounce@firma.de>\r\n"
        b"To: kunde@firma.de\r\n"
        b"Message-ID: <x@firma.de>\r\n"
        b"\r\nT\r\n"
    )
    facts = parse_mail(raw)
    assert facts.from_addr == "a@firma.de"
    ids = _structure_ids(raw)
    for rule in (
        "MAIL_REPLY_TO_MISMATCH",
        "MAIL_RETURN_PATH_MISMATCH",
        "MAIL_DMARC_ALIGNMENT_FAIL",
    ):
        assert rule not in ids, (rule, sorted(ids))


def test_filter_claim_needs_a_contradiction():
    """Ein Befund nur, wenn die Behauptung nicht sein KANN.

    X-Spam-Status steht in praktisch jeder gefilterten Mail — "ist eine
    Behauptung" allein ist kein Befund, angezeigt wird sie in der Vorschau.
    """
    def mail(*hdr: bytes, chain: bool = True) -> bytes:
        kette = (
            b"Received: from mx.firma.de (mx.firma.de [203.0.113.9]) by p "
            b"with ESMTPS; Tue, 1 Jan 2030 10:00:00 +0000\r\n"
            if chain
            else b""
        )
        return (
            kette + b"From: a@firma.de\r\nMessage-ID: <x@firma.de>\r\n"
            + b"".join(hdr) + b"\r\nT\r\n"
        )

    def hat_claim(*hdr: bytes, chain: bool = True) -> bool:
        return "MAIL_FILTER_CLAIM" in _structure_ids(mail(*hdr, chain=chain))

    # Echte Mail mit Gateway: kein Befund.
    assert not hat_claim(b"X-Spam-Status: No, score=-2.1\r\n")
    assert not hat_claim(b"X-Virus-Scanned: by mx.firma.de at Tue\r\n")
    # Widerspruch: der genannte Server fehlt in der Kette.
    assert hat_claim(b"X-Virus-Scanned: by gateway.fremd.tld\r\n")
    # Keine Kette: eine Datei, die nie einen Server sah, kann kein Urteil tragen.
    assert hat_claim(b"X-Spam-Status: No\r\n", chain=False)


def test_quoted_address_parsing_is_linear():
    """Der Parser darf durch die Quote-Behandlung nicht quadratisch werden.

    Gemessen unterwegs: 200 000 '<' kosteten 5,25 s und 2 000 000 kosteten
    52,7 s (Zeichen-fuer-Zeichen in Python), danach 74,3 s (Anfuehrungszeichen-
    Suche bis zum Stringende statt bis zum Treffer). Jetzt linear.
    """
    import time

    from malaz.core.eml_analysis import _split_address

    def lauf(zeichen: str, n: int) -> float:
        text = zeichen * n
        # THREAD-Zeit, nicht Prozesszeit, und das Minimum aus mehreren
        # Laeufen. ``process_time`` zaehlt die CPU ALLER Threads des Prozesses:
        # Malaz hat einen QThreadPool, und ein Testlauf ist nie allein im
        # Prozess. Gemessen im randomisierten Suite-Lauf: der Faktor kippte
        # auf 3,0 (Grenze: < 3,0), obwohl der Parser unveraendert linear war.
        # Die Thread-Zeit misst genau die Arbeit, um die es hier geht.
        best = float("inf")
        for _ in range(3):
            start = time.thread_time()
            _split_address(text)
            best = min(best, time.thread_time() - start)
        return best

    klein = lauf("<", 200_000)
    gross = lauf("<", 400_000)
    # THREAD-Zeit und Minimum aus drei Laeufen reichen nicht: auf einem
    # beschaefigten Rechner (parallele Builds, Defender, andere Testjobs)
    # schwankt der Faktor trotzdem. GEMESSEN: 3,3 im Suite-Lauf, einzeln gruen
    # — die Grenze 3,0 war zu eng fuer eine Messung, die von aussen stoerbar
    # ist. 3,5 trennt linear (2,0) weiterhin klar von quadratisch (4,0).
    #
    # Die Untergrenze steigt mit: unter 50 ms ist der Nenner selbst Rauschen,
    # und ein Faktor aus zwei Rauschwerten sagt nichts.
    if klein > 0.05:  # unter der Rauschgrenze nicht auswerten
        assert gross / klein < 3.5, (
            f"{klein:.4f}s -> {gross:.4f}s (Faktor {gross / klein:.1f}, "
            f"linear waere 2,0, quadratisch ~4)"
        )


def test_every_mail_rule_has_a_title():
    """Jede Regel braucht einen Titel — sonst steht im Fenster der Sammeltext.

    Ohne Eintrag zeigt die GUI (und die CLI-Zeile) "Auffälliger Mail-Header".
    Der Detailtext ist dann spezifisch, der TITEL aber nicht — und der Titel ist
    das, was auf einen Blick gelesen wird. Zweimal passiert: erst beim
    Absender-Urteil, dann bei den Kopfzeilen-Regeln; beide Male fiel es erst
    beim Lesen einer Artefakt-Ausgabe auf. Diese Pruefung findet die Luecke
    vorher.

    Abgeleitet wird aus dem QUELLTEXT, nicht aus einer gepflegten Liste: eine
    Liste waere selbst wieder etwas, das man beim Anlegen einer Regel
    vergisst — also genau die Fehlerklasse, die hier abgesichert wird.
    """
    import re as _re
    from pathlib import Path as _Path

    from malaz.pipelines.eml_pipeline import (
        _ATTACH_TITLES,
        _LINK_TITLES,
        _STRUCTURE_TITLES,
    )

    quelle = _Path("src/malaz/core/eml_analysis.py").read_text(encoding="utf-8")
    regeln = sorted(set(_re.findall(r'"(MAIL_[A-Z_]+)"', quelle)))
    assert len(regeln) > 25, f"zu wenige Regeln gefunden: {len(regeln)}"

    fehlend: list[str] = []
    for regel in regeln:
        if regel.startswith("MAIL_LINK_"):
            tabelle = _LINK_TITLES
        elif regel.startswith("MAIL_ATTACH"):
            tabelle = _ATTACH_TITLES
        else:
            tabelle = _STRUCTURE_TITLES
        if regel not in tabelle:
            fehlend.append(regel)

    assert not fehlend, (
        "Regeln ohne Titel (erscheinen als 'Auffälliger Mail-Header'): "
        + ", ".join(fehlend)
    )


def test_sender_score_never_claims_the_sender_is_real():
    """Der Absender-Score darf keine Echtheit behaupten, die nie geprueft wurde.

    Malaz kann SPF/DKIM ohne Netz NICHT verifizieren. Ein Angreifer, der die
    Empfangskette UND die Authentication-Results-Kopfzeile selbst schreibt und
    beide auf seinen eigenen Server zeigen laesst, erzeugt eine in sich
    stimmige Datei — gemessen ergab das 100/100 mit dem Label "Absender wirkt
    echt". Das ist eine Falschaussage: geprueft wurde nichts, verglichen wurden
    nur Angaben, die alle aus derselben Datei stammen.
    """
    from malaz.core.mail_score import sender_score
    from malaz.core.mail_view import sender_verdict

    gefaelscht = (
        b"Received: from mx.evil.tld (mx.evil.tld [203.0.113.5]) by mx.evil.tld "
        b"with ESMTPS; Tue, 1 Jan 2030 10:00:00 +0000\r\n"
        b"From: Firma <service@evil.tld>\r\n"
        b"To: opfer@firma.de\r\n"
        b"Message-ID: <x@evil.tld>\r\n"
        b"Authentication-Results: mx.evil.tld; spf=pass; dkim=pass; dmarc=pass\r\n"
        b"\r\nBitte zahlen.\r\n"
    )
    facts = parse_mail(gefaelscht)
    score = sender_score(facts.auth_verdicts, sender_verdict(facts))

    # Die Zahl darf hoch sein — die Angaben sind ja stimmig.
    assert score.score >= 80
    # Aber das LABEL darf keine Echtheit behaupten.
    for behauptung in ("echt", "verifiziert", "geprueft", "sicher"):
        assert behauptung not in score.label.lower(), (
            f"Label behauptet mehr als belegt ist: {score.label!r}"
        )


def test_kurze_stichwoerter_treffen_nur_als_wort():
    """„tan" traf in "undersTANding" — vier von zwanzig sauberen Mails waren rot.

    GEMESSEN an 20 echten Ham-Mails (SpamAssassin-Korpus): die Phrase "tan"
    stand als blosser Teilstring in "understanding", "inheritance", "standing"
    und "instance". Jede dieser Mails galt damit als „Zugangsdaten-Ansprache"
    (MAIL_BODY_CREDENTIALS, 15 Punkte) und kippte von GRUEN nach ROT.

    Umgekehrt MUESSEN lange Phrasen Teilstring bleiben: das Deutsche bildet
    Komposita, und „Kreditkartennummer" enthaelt „kreditkarte" ohne es als
    eigenes Wort zu fuehren — eine Wortgrenze dort liesse die echte
    Kreditkarte durchfallen.
    """
    from malaz.core.eml_analysis import _phrase_trifft

    # Kurz: nur als eigenes Wort.
    assert _phrase_trifft("tan", "ihr tan lautet 1234") is True
    assert _phrase_trifft("tan", "understanding the egg") is False
    assert _phrase_trifft("tan", "inheritance of 250,000") is False
    assert _phrase_trifft("pin", "bitte pin eingeben") is True
    assert _phrase_trifft("pin", "spin the wheel") is False
    assert _phrase_trifft("pin", "pinguin foto") is False

    # Lang: auch im Kompositum.
    assert _phrase_trifft("kreditkarte", "ihre kreditkartennummer fehlt") is True
    assert _phrase_trifft("passwort", "passwortabfrage erschienen") is True
    assert _phrase_trifft("sozialversicherungsnummer", "...") is False


def test_mailingliste_wird_erkannt():
    """List-Id und Verwandte (RFC 2919) markieren eine Mailingliste.

    GEMESSEN an 20 echten Ham-Mails aus dem SpamAssassin-Korpus: 4 waren ROT,
    alle an Regeln, die fuer eine Mailingliste den NORMALZUSTAND beschreiben.
    """
    from malaz.core.eml_analysis import parse_mail

    roh = (
        b"From: Autor <autor@uni.example>\r\n"
        b"To: liste@lists.example\r\n"
        b"List-Id: <example.lists.example>\r\n"
        b"List-Unsubscribe: <mailto:liste-leave@lists.example>\r\n"
        b"Return-Path: <liste-admin@lists.example>\r\n"
        b"Subject: Test\r\n\r\nRumpf\r\n"
    )
    assert parse_mail(roh).is_mailing_list is True

    ohne = b"From: Autor <autor@uni.example>\r\nSubject: Test\r\n\r\nRumpf\r\n"
    assert parse_mail(ohne).is_mailing_list is False


def test_listenbefunde_tragen_kein_urteil():
    """Auf Listen sind drei Befunde der Normalfall — sie duerfen nicht zaehlen.

    * MAIL_RETURN_PATH_MISMATCH: die "-admin@"-Adresse GEHOERT der Liste.
    * MAIL_DMARC_ALIGNMENT_FAIL: Listen versenden neu, die Ausrichtung kann
      per Bauart nicht greifen.
    * MAIL_RECEIVED_PRIVATE_IP: der Listenserver relayt intern.

    Geprueft wird die GEWICHTUNG, nicht nur die Erkennung — ein Befund, den
    niemand abschaltet, haette weiter auf den Score gewirkt.
    """
    from malaz.core.eml_analysis import parse_mail
    from malaz.pipelines.eml_pipeline import _LISTEN_NORMAL, EmlPipeline

    assert "MAIL_RETURN_PATH_MISMATCH" in _LISTEN_NORMAL
    assert "MAIL_DMARC_ALIGNMENT_FAIL" in _LISTEN_NORMAL
    assert "MAIL_RECEIVED_PRIVATE_IP" in _LISTEN_NORMAL

    roh = (
        b"From: Autor <autor@uni.example>\r\n"
        b"List-Id: <example.lists.example>\r\n"
        b"List-Unsubscribe: <mailto:x@lists.example>\r\n"
        b"Return-Path: <liste-admin@lists.example>\r\n"
        b"Received: from intern (192.168.0.4) by lists.example; Mon, 1 Jan 2024 10:00:00 +0000\r\n"
        b"Subject: Test\r\n\r\nRumpf\r\n"
    )
    facts = parse_mail(roh)
    assert facts.is_mailing_list is True
    inds = EmlPipeline()._structure_indicators(facts)
    listen_befunde = [i for i in inds if i.rule_id in _LISTEN_NORMAL]
    assert listen_befunde, "die Befunde sollen sichtbar bleiben"
    # ALLE bleiben entschaerft, aber nur EINER traegt Punkte ("ein Artefakt,
    # eine Wertung"). Drei Befunde x 5 ergaben 15 und schoben jede echte
    # Listenmail ueber die GRUEN-Schwelle; mit einem bleiben 5.
    gewichte = [i.weight for i in listen_befunde]
    assert sum(gewichte) == 5, f"genau eine Restnotiz erwartet, war {gewichte}"
    assert all(w < 15 for w in gewichte), f"kein Befund darf voll zaehlen: {gewichte}"


def test_mailman_rueckkehradresse_wird_erkannt():
    """Der Grund, warum die Listen-Entschaerfung auf echten Archiven versagte.

    GEMESSEN an 20 AKTUELLEN Mails aus dem Apache-Archiv (httpd-users, 2025):
    19 davon waren ROT. Mailman schreibt die Rueckkehradresse als

        users-return-123584-archive-asf-public=cust-asf.ponee.io@httpd.apache.org

    Meine Bestaetigung kannte "-admin@"/"-bounces@"/"-owner@"/"-request@" —
    und verlangte die Marke DIREKT vor dem "@". Bei Mailman steht sie hinter
    einem Bindestrich mitten im Local-Part, das Muster traf dort also nie.

    Die 20 Ham-Mails von 2003 hatten diesen Fall nicht gezeigt: dort trugen 6
    von 8 Rueckkehradressen den Autorennamen. Genau deshalb braucht eine
    Falschpositiv-Pruefung AKTUELLE Daten.
    """
    from malaz.core.eml_analysis import parse_mail

    roh = (
        b"From: Autor <autor@firma.example>\r\n"
        b"Reply-To: users@liste.example\r\n"
        b"List-Id: <users.liste.example>\r\n"
        b"List-Unsubscribe: <mailto:users-unsubscribe@liste.example>\r\n"
        b"Return-Path: <users-return-123584-archiv@liste.example>\r\n"
        b"Subject: Test\r\n\r\nRumpf\r\n"
    )
    assert parse_mail(roh).is_mailing_list is True


def test_reply_to_der_liste_ist_kein_befund():
    """Reply-To auf die Liste ist der ZWECK einer Liste.

    Mit 30 Punkten war das der groesste Einzeltreiber: auf 19 von 20 echten
    Apache-Mails feuerte MAIL_REPLY_TO_MISMATCH, weil die Liste Reply-To auf
    sich selbst setzt, damit Antworten in die Liste gehen.
    """
    from malaz.pipelines.eml_pipeline import _LISTEN_NORMAL

    assert "MAIL_REPLY_TO_MISMATCH" in _LISTEN_NORMAL


def test_gefaelschte_liste_bleibt_sichtbar():
    """Audit-Befund 2 (medium): der Listen-Freibrief war faelschbar.

    GEMESSEN: `List-Id` UND `Return-Path` sind beides Kopfzeilen derselben vom
    Angreifer verfassten Datei. Wer beide setzt, senkte eine BEC-Mail von
    GELB 40 auf GRUEN 10 — genau die Regeln fielen aus, die diesen Fall fangen
    sollen. Bei einer statischen .eml ist ALLES angreifergeschrieben; eine
    Bestaetigung aus derselben Datei ist grundsaetzlich faelschbar.

    Deshalb tragen die Listenbefunde jetzt Restgewicht statt 0: sichtbar
    bleiben sie ohnehin, und eine gefaelschte Liste bekommt keinen Freibrief.
    """
    from malaz.core.eml_analysis import parse_mail
    from malaz.pipelines.eml_pipeline import _LISTEN_NORMAL, EmlPipeline

    roh = (
        b"From: Chef <chef@firma.example>\r\n"
        b"List-Id: <liste.example>\r\n"
        b"Return-Path: <liste-admin@liste.example>\r\n"
        b"Subject: Ueberweisung\r\n\r\nBitte ueberweisen Sie.\r\n"
    )
    facts = parse_mail(roh)
    assert facts.is_mailing_list is True
    inds = EmlPipeline()._structure_indicators(facts)
    listen = [i for i in inds if i.rule_id in _LISTEN_NORMAL]
    assert listen, "die Listenbefunde muessen sichtbar bleiben"
    # Kein Freibrief: irgendetwas muss zaehlen. Aber genau EINER — drei
    # Notizen x 5 schoben jede echte Listenmail ueber die GRUEN-Schwelle.
    assert sum(i.weight for i in listen) == 5, [i.weight for i in listen]


# -- Audit-Funde (Phase B, medium) ------------------------------------------ #


@pytest.mark.parametrize(
    "href",
    [
        " javascript:alert(1)",
        "\tjavascript:alert(1)",
        "&#9;javascript:alert(1)",
        "&#x09;javascript:alert(1)",
        "java&#9;script:alert(1)",
    ],
)
def test_dangerous_scheme_survives_leading_whitespace_and_entities(href):
    """BUG-067: `` javascript:`` und ``&#9;javascript:`` wurden nicht erkannt.

    ``_HREF_RE`` schloss Whitespace aus, ``_unescape_entities`` dekodierte
    Steuerzeichen nicht — der Link fehlte komplett und mit ihm
    MAIL_LINK_DANGEROUS_SCHEME.
    """
    links = eml_analysis.extract_links("", f'<a href="{href}">hier klicken</a>')
    assert any(link.scheme == "javascript" for link in links), links
    kinds = {kind for kind, _detail in summarize_links(links)}
    assert "MAIL_LINK_DANGEROUS_SCHEME" in kinds


def test_every_attachment_name_is_checked():
    """BUG-068: ``names[:20]`` versteckte einen bösartigen Anhang dahinter."""
    harmlos = [f"harmlos{i}.pdf" for i in range(20)] + ["rechnung.pdf.exe"]
    kinds = {kind for kind, _detail in risky_attachment_names(harmlos)}
    assert "MAIL_ATTACH_DOUBLE_EXT" in kinds


def test_ipv6_received_literal_is_read():
    """BUG-070: RFC-5321-Form ``[IPv6:fd00::1]`` wurde nicht als IP erkannt."""
    hop = eml_analysis._parse_received(
        "from mx.firma.example (mx.firma.example [IPv6:fd00::1]) by p "
        "with ESMTPS; Tue, 1 Jan 2030 10:00:00 +0000"
    )
    assert hop.ip == "fd00::1"

    raw = (
        b"Received: from mx.firma.example (mx.firma.example [IPv6:fd00::1]) "
        b"by p with ESMTPS; Tue, 1 Jan 2030 10:00:00 +0000\r\n"
        b"From: Firma <service@firma.example>\r\n"
        b"To: opfer@firma.example\r\n"
        b"Subject: Test\r\n"
        b"Message-ID: <x@firma.example>\r\n"
        b"\r\nText.\r\n"
    )
    facts = parse_mail(raw)
    assert facts.received_hops[-1].ip == "fd00::1"
    kinds = {kind for kind, _detail in analyze_structure(facts).findings}
    assert "MAIL_RECEIVED_PRIVATE_IP" in kinds


def test_backslash_in_authority_is_the_visited_host():
    """SEC-035: der Browser liest ``https://evil.com\\@good.com`` als evil.com."""
    html = (
        '<a href="https://evil.com\\@good.com/login">'
        "https://good.com/login</a>"
    )
    links = eml_analysis.extract_links("", html)
    link = next(link for link in links if "evil.com" in link.url)
    assert link.host == "evil.com"
    assert link.mismatch is True, "der Anzeigetext nennt eine andere Adresse"
    kinds = {kind for kind, _detail in summarize_links(links)}
    assert "MAIL_LINK_TEXT_MISMATCH" in kinds


def test_header_block_is_capped_and_truncation_is_visible():
    """SEC-034: ein Riesen-Kopfblock wurde ungebremst geparst.

    Geprueft wird beides: der Datenschnitt (nur ``_MAX_HEADER_BLOCK_BYTES``)
    UND die sichtbare Notiz. Der Rumpf bleibt vollständig.
    """
    cap = eml_analysis._MAX_HEADER_BLOCK_BYTES
    padding = b"A" * (cap + 4096)
    raw = (
        b"From: a@firma.example\r\nX-Pad: "
        + padding
        + b"\r\nSubject: gross\r\n"
        b"Message-ID: <x@firma.example>\r\n"
        b"\r\nRumpf bleibt erhalten.\r\n"
    )
    facts = parse_mail(raw)
    assert facts.header_truncated is True
    assert facts.parse_error == "", "der Rumpf ist lesbar — kein Parse-Fehler"
    assert facts.text_body.strip() == "Rumpf bleibt erhalten."
    kinds = {kind for kind, _detail in analyze_structure(facts).findings}
    assert "MAIL_HEADER_TRUNCATED" in kinds

    klein = b"From: a@firma.example\r\nSubject: klein\r\n\r\nRumpf.\r\n"
    assert parse_mail(klein).header_truncated is False


@pytest.mark.parametrize("scheme", ["ms-msdt", "search-ms", "jar", "ms-officecmd"])
def test_mail_score_knows_every_dangerous_scheme(scheme):
    """BUG-069: mail_score kannte nur eine Teilmenge der Schemes."""
    from malaz.core import mail_score
    from malaz.core.eml_analysis import LinkFacts

    score = mail_score.link_score(
        LinkFacts(url=f"{scheme}:...", host="", scheme=scheme)
    )
    assert score.score >= 60, f"{scheme} wurde nicht als gefährlich bewertet"
    assert score.reasons, "die Begründung fehlt"


def test_unreadable_local_blocklist_never_raises(monkeypatch):
    """BUG-075: ``is_file()`` kann PermissionError werfen (Windows)."""
    class _Unlesbar:
        def is_file(self):
            raise PermissionError("Zugriff verweigert")

    monkeypatch.setattr(url_reputation, "local_blocklist_path", lambda: _Unlesbar())
    assert url_reputation.local_blocklist_enabled() is False

    # Und der oeffentliche Weg darf ebenso wenig werfen.
    ergebnis = url_reputation.lookup(["http://evil.example/a"])
    assert ergebnis.ran is False
    assert ergebnis.hits == {}


def test_local_hits_survive_a_non_https_provider(monkeypatch, tmp_path):
    """BUG-076: non-HTTPS-Provider verwarf die lokalen Treffer."""
    from malaz import config

    url = "https://evil.example/phish"
    digest = url_reputation.url_hash(url)
    liste = tmp_path / "urls.sha256"
    liste.write_text(digest + "\n", encoding="utf-8")

    monkeypatch.setattr(config, "URL_BLOCKLIST_FILE", liste)
    monkeypatch.setattr(config, "URL_REPUTATION_ENABLED", True)
    monkeypatch.setattr(
        config, "URL_REPUTATION_ENDPOINT", "http://provider.invalid/v1"
    )

    ergebnis = url_reputation.lookup([url])
    assert ergebnis.ran is True, "der lokale Abgleich lief"
    assert ergebnis.hits == {digest: "local_malware"}
    assert "HTTPS" in ergebnis.skipped_reason


def test_part_1601_is_reached_after_the_old_limit():
    """BUG-065: the old 1600-node cap silently dropped the payload behind it."""
    head = (
        b"From: a@b.de\nMessage-ID: <x@y>\nMIME-Version: 1.0\n"
        b"Content-Type: multipart/mixed; boundary=\"B\"\n\n"
    )
    body = b"".join(
        b"--B\nContent-Type: text/plain\n\npadding\n" for _ in range(1600)
    )
    tail = b"--B\nContent-Type: text/plain\n\nPAYLOAD_1601\n--B--\n"
    facts = parse_mail(head + body + tail)
    assert facts.parts_truncated is False
    assert "PAYLOAD_1601" in facts.text_body
