"""SPF/DMARC über DNS — Opt-in, und die Grenzen der Aussage.

Der wichtigste Test hier ist NICHT, dass eine Abfrage funktioniert, sondern
dass die Stufe **kein Urteil erfindet**. Ein "NICHT erlaubt" bei einer
legitimen Mail ist schlimmer als "nicht beurteilbar": es beschuldigt einen
ehrlichen Absender, und der Nutzer handelt danach.
"""

from __future__ import annotations

import pytest

from malaz.core import dns_auth


def test_vorgabe_ist_aus():
    """Ohne Zustimmung des Nutzers fragt Malaz das Netz nicht."""
    from malaz import config

    assert config.DNS_AUTH_ENABLED is False
    assert dns_auth.enabled() is False


@pytest.mark.parametrize(
    ("ip", "netz", "soll"),
    [
        ("209.85.220.41", "209.85.128.0/17", True),  # echte Google-IP
        ("209.85.127.1", "209.85.128.0/17", False),  # eine Adresse daneben
        ("1.2.3.4", "1.2.3.4", True),
        ("1.2.3.5", "1.2.3.4", False),
        ("2001:4860:4864::1", "2001:4860:4864::/56", True),
        ("quatsch", "1.2.3.0/24", False),
    ],
)
def test_ip_gegen_bereich(ip, netz, soll):
    """CIDR-Vergleich — GEMESSEN der Fehler, der eine Falschanschuldigung baute.

    Eine erste Fassung verglich die IP als Zeichenkette. Bei gmail.com steht
    ``ip4:209.85.128.0/17``; die echte Google-IP liegt darin, der Vergleich
    sagte trotzdem "nicht erlaubt" — und die Pipeline haette HIGH/30 vergeben.
    """
    assert dns_auth._ip_in_cidr(ip, netz) is soll


def test_verweis_macht_die_ip_nicht_beurteilbar(monkeypatch):
    """Ein zweiter Verweis heisst: die Bereiche liegen woanders.

    Dann darf KEIN Urteil fallen — weder "erlaubt" noch "nicht erlaubt".
    """
    monkeypatch.setattr(
        dns_auth, "_txt_records", lambda name, **_k: ["v=spf1 include:_spf.google.com"]
    )
    ergebnis = dns_auth.check_spf("203.0.113.99", "beispiel.example")
    assert ergebnis.ip_allowed is None, "die Stufe hat ein Urteil erfunden"
    assert "nicht beurteilbar" in ergebnis.detail.lower()
    assert ergebnis.verdict == "nicht beurteilbar"


def test_a_mx_macht_die_ip_nicht_beurteilbar(monkeypatch):
    """``a``/``mx`` koennen die IP erlauben, ohne sie zu nennen."""
    monkeypatch.setattr(
        dns_auth, "_txt_records", lambda name, **_k: ["v=spf1 mx -all"]
    )
    ergebnis = dns_auth.check_spf("203.0.113.99", "beispiel.example")
    assert ergebnis.ip_allowed is None
    assert "nicht beurteilbar" in ergebnis.detail.lower()


def test_selbst_enthaltene_liste_gibt_ein_urteil(monkeypatch):
    """Die Gegenprobe: ohne Verweis darf (und soll) ein Urteil fallen."""
    monkeypatch.setattr(
        dns_auth,
        "_txt_records",
        lambda name, **_k: ["v=spf1 ip4:203.0.113.0/24 -all"],
    )
    drin = dns_auth.check_spf("203.0.113.7", "beispiel.example")
    assert drin.ip_allowed is True
    assert drin.verdict == "IP erlaubt"

    draussen = dns_auth.check_spf("198.51.100.7", "beispiel.example")
    assert draussen.ip_allowed is False
    assert draussen.verdict == "IP NICHT erlaubt"


def test_fehlschlag_ist_unbekannt_nicht_sauber(monkeypatch):
    """Der Grundsatz: was nicht geprüft wurde, darf nicht wie geprüft aussehen."""
    def kaputt(name, **_k):
        raise OSError("Zeitueberschreitung")

    monkeypatch.setattr(dns_auth, "_txt_records", kaputt)
    ergebnis = dns_auth.check_spf("203.0.113.7", "beispiel.example")
    assert ergebnis.ran is False
    assert ergebnis.error
    assert ergebnis.verdict == "unbekannt", "ein Ausfall wurde als Ergebnis gemeldet"
    assert ergebnis.ip_allowed is None


def test_kein_spf_eintrag_ist_eine_aussage(monkeypatch):
    """Eine Domain ohne SPF ist kein Fehler der Abfrage — sie sagt etwas."""
    monkeypatch.setattr(dns_auth, "_txt_records", lambda name, **_k: ["etwas anderes"])
    ergebnis = dns_auth.check_spf("203.0.113.7", "beispiel.example")
    assert ergebnis.ran is True
    assert ergebnis.verdict == "kein SPF-Eintrag"
    assert ergebnis.ip_allowed is None, "ohne Eintrag darf nichts erlaubt sein"


def test_dmarc_richtlinie_wird_gelesen(monkeypatch):
    monkeypatch.setattr(
        dns_auth,
        "_txt_records",
        lambda name, **_k: ["v=DMARC1; p=reject; rua=mailto:x@y.example"],
    )
    ergebnis = dns_auth.check_dmarc("mail.beispiel.example")
    assert ergebnis.policy == "reject"
    assert ergebnis.verdict == "Richtlinie reject"


@pytest.mark.parametrize(
    ("eintrag", "ip", "soll"),
    [
        # CIDR, nicht Zeichenkette: "203.0.113.0/24" == "203.0.113.5" ist als
        # Text falsch — eine erlaubte IP waere als "NICHT erlaubt" gemeldet
        # worden, mit HIGH/30.
        ("v=spf1 ip4:203.0.113.0/24 -all", "203.0.113.5", True),
        # Ein spaeteres "-all" darf einen frueheren ip4-Treffer NICHT
        # ueberschreiben. SPF ist first-match-wins.
        ("v=spf1 ip4:1.2.3.4 -all", "1.2.3.4", True),
        ("v=spf1 ip4:1.2.3.4 -all", "5.6.7.8", False),
        # Mehrere Mechanismen: der zweite Treffer zaehlt genauso.
        ("v=spf1 ip4:1.2.3.4 ip4:9.9.9.9 -all", "9.9.9.9", True),
        ("v=spf1 +all", "8.8.8.8", True),
        ("v=spf1 ip6:2001:db8::/32 -all", "2001:db8::1", True),
    ],
)
def test_spf_mechanismen_werden_richtig_ausgewertet(monkeypatch, eintrag, ip, soll):
    """Beide Fehler, die die Messung fand — als Zusicherung.

    GEMESSEN: mit Zeichenkettenvergleich meldete gmail.com die echte
    Google-IP als "NICHT erlaubt". Und ein spaeteres ``-all`` durfte den
    Treffer nicht loeschen — sonst gilt ``v=spf1 ip4:1.2.3.4 -all`` als
    "nicht erlaubt" fuer genau die IP, die es freigibt.
    """
    monkeypatch.setattr(dns_auth, "_txt_records", lambda name, **_k: [eintrag])
    ergebnis = dns_auth.check_spf(ip, "beispiel.example")
    assert ergebnis.ip_allowed is soll, f"{ip} in {eintrag!r}: {ergebnis.verdict}"


def test_spf_fragt_die_exakte_mail_domain(monkeypatch):
    """SPF liegt bei der Domain der Envelope-Adresse, nicht beim Registrable.

    Audit BUG-011/TEST-027: ``check_spf`` kuerzte ``mail.firma.example`` auf
    ``firma.example`` und fragte damit einen Eintrag ab, der fuer diese Mail
    gar nicht gilt.
    """
    gefragt: list[str] = []

    def merken(name, **_k):
        gefragt.append(name)
        return (
            ["v=spf1 ip4:203.0.113.7 -all"]
            if name == "mail.firma.example"
            else []
        )

    monkeypatch.setattr(dns_auth, "_txt_records", merken)
    ergebnis = dns_auth.check_spf("203.0.113.7", "bounce@mail.firma.example")
    assert gefragt == ["mail.firma.example"], gefragt
    assert ergebnis.ip_allowed is True


def test_spf_include_nutzt_mechanismen_beider_records(monkeypatch):
    """BUG-011: der include-Zweig ersetzte den ersten Record.

    ``ip4:203.0.113.9 include:… -all`` verlor damit die ip4-Angabe des
    AEUSSEREN Records; die dort erlaubte IP galt als "NICHT erlaubt".
    """
    records = {
        "mail.firma.example": [
            "v=spf1 ip4:203.0.113.9 include:_spf.firma.example -all"
        ],
        "_spf.firma.example": ["v=spf1 ip4:198.51.100.9 -all"],
    }

    def merken(name, **_k):
        return records.get(name, [])

    monkeypatch.setattr(dns_auth, "_txt_records", merken)
    aussen = dns_auth.check_spf("203.0.113.9", "mail.firma.example")
    innen = dns_auth.check_spf("198.51.100.9", "mail.firma.example")
    draussen = dns_auth.check_spf("192.0.2.1", "mail.firma.example")
    assert aussen.ip_allowed is True, aussen.detail
    assert innen.ip_allowed is True, innen.detail
    assert draussen.ip_allowed is False, draussen.detail


def test_spf_qualifier_wird_ausgewertet(monkeypatch):
    """``+ip4:`` war kein Mechanismus, ``-ip4:`` ebenso wenig (BUG-011)."""
    monkeypatch.setattr(
        dns_auth,
        "_txt_records",
        lambda name, **_k: ["v=spf1 +ip4:203.0.113.9 -all"],
    )
    assert dns_auth.check_spf("203.0.113.9", "firma.example").ip_allowed is True

    monkeypatch.setattr(
        dns_auth,
        "_txt_records",
        lambda name, **_k: ["v=spf1 -ip4:203.0.113.9 +all"],
    )
    assert dns_auth.check_spf("203.0.113.9", "firma.example").ip_allowed is False


def test_spf_ungueltige_ip_ist_unbekannt_nicht_nicht_erlaubt(monkeypatch):
    """Eine unbrauchbare IP ist "nicht beurteilbar", kein Schuldspruch."""
    monkeypatch.setattr(
        dns_auth,
        "_txt_records",
        lambda name, **_k: ["v=spf1 ip4:203.0.113.0/24 -all"],
    )
    ergebnis = dns_auth.check_spf("not-an-ip", "firma.example")
    assert ergebnis.ip_allowed is None
    assert ergebnis.verdict == "nicht beurteilbar"
    assert "keine gueltige IP" in ergebnis.detail


@pytest.mark.parametrize(
    ("eingabe", "erwartet"),
    [
        ("firma.de", "firma.de"),
        ("mail.firma.de", "firma.de"),
        ("a.b.c.firma.de", "firma.de"),
        ("firma.co.uk", "firma.co.uk"),  # Zwei-Teil-Suffix
        ("mail.firma.co.uk", "firma.co.uk"),
        ("FIRMA.DE", "firma.de"),  # Grossschreibung
        ("firma.de.", "firma.de"),  # Wurzelpunkt
        # Der Aufrufer uebergibt MAILADRESSEN, keine Domains. GEMESSEN: ohne
        # diesen Schritt wurde "_dmarc.a@firma.example" abgefragt, die
        # Namenspruefung lehnte ab, und die Stufe meldete fuer JEDE Mail
        # "unbekannt" — sie lief ins Leere, ohne dass es auffiel.
        ("a@firma.example", "firma.example"),
        ("<a@firma.de>", "firma.de"),  # Return-Path-Form
        ("A@Mail.Firma.DE", "firma.de"),
        ("a@", ""),
        ("<>", ""),
        ("", ""),
        ("...", ""),
        ("localhost", "localhost"),
    ],
)
def test_registrable_zerlegt_domains(eingabe, erwartet):
    """Die Domain, unter der SPF/DMARC stehen.

    Ohne die Zwei-Teil-Behandlung stuende bei "firma.co.uk" nur "co.uk" — und
    die Abfrage ginge an die falsche Domain.
    """
    assert dns_auth._registrable(eingabe) == erwartet


def test_dns_name_aus_der_mail_wird_verweigert(monkeypatch):
    """Der Name stammt aus einer Kopfzeile und ist angreiferkontrolliert.

    Ein Anführungszeichen darin beendete das PowerShell-Argument und führte
    fremden Code aus. Alles ausserhalb der DNS-Zeichen wird VERWEIGERT — nicht
    herausgefiltert: aus einem Angriffsversuch darf kein gültiger Name werden,
    den wir dann abfragen.
    """
    gerufen: list[str] = []

    class _Ergebnis:
        returncode = 0

    def fake_run(args, timeout=None):
        gerufen.append(args[-1])
        return _Ergebnis(), b'["v=spf1 -all"]', b""

    monkeypatch.setattr(dns_auth, "run_tool", fake_run)
    monkeypatch.setattr(dns_auth.shutil, "which", lambda _n: "powershell")

    with pytest.raises(ValueError):
        dns_auth._txt_records("beispiel.example'; Remove-Item C:\\ -Recurse; '")
    assert not gerufen, "der Name wurde ungefiltert übergeben"


def test_unicode_name_wird_abgelehnt_nicht_verstuemmelt(monkeypatch):
    """Ein IDN-Name wird VERWEIGERT, nicht zurechtgestutzt.

    GEMESSEN: eine erste Fassung filterte die Zeichen heraus, und
    "münchen.example" wurde zu "mnchen.example". Das ist kein sauberer Name,
    sondern ein ANDERER — hätte er einen SPF-Eintrag, wäre das Urteil eines
    über die falsche Domain. Ohne IDNA-Umrechnung gibt es hier nichts
    Seriöses zu antworten.
    """
    gerufen: list[str] = []

    class _R:
        returncode = 0

    def fake_run(args, timeout=None):
        gerufen.append(args[-1])
        return _R(), b'["v=spf1 -all"]', b""

    monkeypatch.setattr(dns_auth, "run_tool", fake_run)
    monkeypatch.setattr(dns_auth.shutil, "which", lambda _n: "powershell")

    with pytest.raises(ValueError):
        dns_auth._txt_records("münchen.example")
    assert not gerufen, "es wurde trotzdem gefragt"

    # Und der Aufrufer meldet das ehrlich als "unbekannt" — nicht als
    # "kein SPF-Eintrag", das wäre eine Aussage über die Domain.
    ergebnis = dns_auth.check_spf("203.0.113.5", "münchen.example")
    assert ergebnis.verdict == "unbekannt"
    assert ergebnis.ran is False


def test_leerer_name_bricht_ab_statt_zu_fragen(monkeypatch):
    """Ohne verwertbaren Namen darf gar nicht erst gefragt werden."""
    gerufen = []
    monkeypatch.setattr(dns_auth, "run_tool", lambda *a, **k: gerufen.append(1))
    with pytest.raises(ValueError):
        dns_auth._txt_records(";;;'")


def test_antwort_ohne_json_ist_ein_fehler_kein_ergebnis(monkeypatch):
    """Eine unlesbare Antwort darf nicht als "kein Eintrag" durchgehen.

    "kein SPF-Eintrag" ist eine Aussage ueber die DOMAIN; eine kaputte
    Werkzeugantwort ist eine ueber die ABFRAGE. Die beiden zu verwechseln
    hiesse, eine fehlgeschlagene Pruefung als Domain-Eigenschaft zu melden.
    """
    class _R:
        returncode = 0

    monkeypatch.setattr(dns_auth, "run_tool", lambda *a, **k: (_R(), b"kein json", b""))
    monkeypatch.setattr(dns_auth.shutil, "which", lambda _n: "powershell")

    ergebnis = dns_auth.check_spf("203.0.113.5", "firma.de")
    assert ergebnis.error, "die kaputte Antwort wurde verschluckt"
    assert ergebnis.ran is False
    assert ergebnis.verdict == "unbekannt"
    assert ergebnis.verdict != "kein SPF-Eintrag"


def test_beide_abfragen_scheitern_ergeben_einen_bericht(monkeypatch):
    """``check`` wirft nie — auch wenn beide Seiten scheitern."""

    def kaputt(*_a, **_k):
        raise OSError("kein Netz")

    monkeypatch.setattr(dns_auth, "_txt_records", kaputt)
    bericht = dns_auth.check("203.0.113.5", "firma.de", "firma.de")
    assert bericht.any_ran is False
    assert bericht.spf.error and bericht.dmarc.error
    assert bericht.spf.verdict == "unbekannt"
    assert bericht.dmarc.verdict == "unbekannt"


def test_fehlende_absenderdomain_ist_kein_netzfehler(monkeypatch):
    """Ohne Domain wird nicht gefragt — und das ist kein Ausfall."""
    gerufen = []
    monkeypatch.setattr(dns_auth, "_txt_records", lambda *a, **k: gerufen.append(1) or [])
    ergebnis = dns_auth.check_spf("203.0.113.5", "")
    assert not gerufen, "ohne Domain wurde trotzdem gefragt"
    assert ergebnis.ran is False
    assert "domain" in ergebnis.error.lower()


def test_fehlender_eintrag_ist_eine_antwort_kein_ausfall(monkeypatch):
    """NXDOMAIN heisst "diese Domain hat keinen Eintrag" — nicht "Netz kaputt".

    GEMESSEN: ``_dmarc.firma.example`` liefert den Win32-Code 9003, und die
    Stufe meldete daraufhin "DNS-Prüfung nicht möglich" (MAIL_AUTH_DNS_UNKNOWN)
    — als wäre die Abfrage gescheitert. Sie war erfolgreich; die Antwort ist
    nur leer. Wer das verwechselt, versteckt eine echte Domain-Aussage hinter
    einem Netzfehler und meldet im Bericht "unbekannt", wo er etwas weiss.
    """
    class _R:
        returncode = 0

    # Genau die Form, die das PowerShell-Skript jetzt liefert.
    antwort = b'{"ok":false,"code":9003}'
    monkeypatch.setattr(dns_auth, "run_tool", lambda *a, **k: (_R(), antwort, b""))
    monkeypatch.setattr(dns_auth.shutil, "which", lambda _n: "powershell")

    ergebnis = dns_auth.check_spf("203.0.113.5", "firma.example")
    assert ergebnis.error == "", f"NXDOMAIN wurde als Fehler gemeldet: {ergebnis.error}"
    assert ergebnis.ran is True
    assert ergebnis.verdict == "kein SPF-Eintrag"


def test_echter_dns_fehler_bleibt_unbekannt(monkeypatch):
    """Die Gegenprobe: ein ANDERER Fehlercode ist ein echter Ausfall.

    Sonst würde aus jedem Netzproblem ein "die Domain hat keinen SPF-Eintrag",
    und der Nutzer liest eine Aussage, die niemand geprüft hat.
    """
    class _R:
        returncode = 0

    antwort = b'{"ok":false,"code":12345}'
    monkeypatch.setattr(dns_auth, "run_tool", lambda *a, **k: (_R(), antwort, b""))
    monkeypatch.setattr(dns_auth.shutil, "which", lambda _n: "powershell")

    ergebnis = dns_auth.check_spf("203.0.113.5", "firma.example")
    assert ergebnis.error, "der echte Fehler wurde verschluckt"
    assert ergebnis.ran is False
    assert ergebnis.verdict == "unbekannt"
    assert ergebnis.verdict != "kein SPF-Eintrag"


def test_abgeschnittene_dns_antwort_ist_unbekannt(monkeypatch):
    """SEC-023: a cut-off JSON answer must not become "kein Eintrag".

    The prefix is complete JSON for "no records" plus the truncation flag —
    the missing part could name an SPF record. Unknown, not a domain claim.
    """
    from malaz.procio import ToolResult

    monkeypatch.setattr(
        dns_auth,
        "run_tool",
        lambda *a, **k: ToolResult(0, b'{"ok": true, "records": []}', b"", truncated=True),
    )
    monkeypatch.setattr(dns_auth.shutil, "which", lambda _n: "powershell")

    ergebnis = dns_auth.check_spf("203.0.113.5", "firma.example")

    assert ergebnis.error and "abgeschnitten" in ergebnis.error
    assert ergebnis.ran is False
    assert ergebnis.verdict == "unbekannt"
    assert ergebnis.verdict != "kein SPF-Eintrag"


def test_leere_antwort_ist_kein_eintrag(monkeypatch):
    """``ok=true`` ohne Eintraege: die Domain hat keinen — kein Fehler."""
    class _R:
        returncode = 0

    monkeypatch.setattr(
        dns_auth, "run_tool", lambda *a, **k: (_R(), b'{"ok":true,"records":[]}', b"")
    )
    monkeypatch.setattr(dns_auth.shutil, "which", lambda _n: "powershell")
    ergebnis = dns_auth.check_dmarc("firma.example")
    assert ergebnis.error == ""
    assert ergebnis.ran is True
    assert ergebnis.verdict == "kein DMARC-Eintrag"


def test_pipeline_uebergibt_adressen_und_sie_kommen_an(monkeypatch):
    """Der Fehler, der die ganze Stufe wirkungslos machte.

    ``_auth_dns`` reicht ``facts.from_addr`` und ``facts.return_path`` durch —
    das sind Mailadressen. GEMESSEN wurde daraus ``_dmarc.a@firma.example``,
    die Abfrage scheiterte an der Namensprüfung, und der Bericht sagte für
    jede Mail „DNS-Prüfung nicht möglich". Das sah nach einem Netzproblem aus
    und war ein Namensfehler.
    """
    gefragt: list[str] = []

    def merken(name, **_k):
        gefragt.append(name)
        return ["v=DMARC1; p=reject"]

    monkeypatch.setattr(dns_auth, "_txt_records", merken)
    dns_auth.check_dmarc("A@Mail.Firma.DE")
    assert gefragt, "es wurde gar nicht gefragt"
    # BUG-014: exact Mail domain first; the stub answers every name, so no
    # registrable fallback is needed.
    assert gefragt[0] == "_dmarc.mail.firma.de", f"falscher Name: {gefragt[0]}"
    assert "@" not in gefragt[0], "die Adresse wurde als Domain abgefragt"


def test_dmarc_faellt_auf_die_registrierbare_domain_zurueck(monkeypatch):
    """BUG-014: Subdomain-Eintrag unsichtbar -> jetzt exakt, dann Fallback."""
    gefragt: list[str] = []

    def merken(name, **_k):
        gefragt.append(name)
        return ["v=DMARC1; p=reject"] if name == "_dmarc.firma.example" else []

    monkeypatch.setattr(dns_auth, "_txt_records", merken)
    ergebnis = dns_auth.check_dmarc("mail.firma.example")
    assert gefragt == ["_dmarc.mail.firma.example", "_dmarc.firma.example"], gefragt
    assert ergebnis.policy == "reject"


def test_spf_faellt_auf_die_registrierbare_domain_zurueck(monkeypatch):
    """BUG-014: ein nur organisatorisch veroeffentlichter SPF-Eintrag zaehlt."""
    gefragt: list[str] = []

    def merken(name, **_k):
        gefragt.append(name)
        return ["v=spf1 ip4:203.0.113.7 -all"] if name == "firma.example" else []

    monkeypatch.setattr(dns_auth, "_txt_records", merken)
    ergebnis = dns_auth.check_spf("203.0.113.7", "mail.firma.example")
    assert gefragt == ["mail.firma.example", "firma.example"], gefragt
    assert ergebnis.ip_allowed is True
    assert "Eintrag von firma.example" in ergebnis.detail


# -- DKIM-Schluessel (nicht die Signatur) ----------------------------------- #


def test_dkim_abfrage_nutzt_den_richtigen_namen(monkeypatch):
    """``<selektor>._domainkey.<domain>`` — sonst findet die Abfrage nichts."""
    gefragt: list[str] = []

    def merken(name, **_k):
        gefragt.append(name)
        return ["v=DKIM1; k=rsa; p=MIIBIjANBgkq"]

    monkeypatch.setattr(dns_auth, "_txt_records", merken)
    ergebnis = dns_auth.check_dkim("20230601", "Mail.Firma.DE")
    assert gefragt == ["20230601._domainkey.firma.de"], gefragt
    assert ergebnis.verdict == "Schlüssel veröffentlicht"


def test_widerrufener_schluessel_ist_kein_gueltiger(monkeypatch):
    """Ein LEERES ``p=`` heisst widerrufen, nicht "Schluessel vorhanden".

    GEMESSEN an gmail.com: die Selektoren 20230601 und 20210112 liefern
    "v=DKIM1; k=rsa; p=" — Google hat sie zurueckgezogen (mit nslookup
    bestaetigt, also nicht der Resolver). Wer das als "veroeffentlicht"
    meldet, sagt bei einem widerrufenen Schluessel "alles in Ordnung".
    """
    monkeypatch.setattr(
        dns_auth, "_txt_records", lambda name, **_k: ["v=DKIM1; k=rsa; p="]
    )
    ergebnis = dns_auth.check_dkim("20230601", "gmail.com")
    assert ergebnis.ran is True
    assert ergebnis.revoked is True
    assert ergebnis.verdict == "Schlüssel widerrufen"


def test_lebender_schluessel_wird_als_solcher_gemeldet(monkeypatch):
    """Die Gegenprobe: ein gefuelltes ``p=`` ist ein veroeffentlichter Schluessel.

    GEMESSEN gegen das echte Netz: selector1@outlook.com liefert 251 Zeichen.
    """
    schluessel = "v=DKIM1; k=rsa; p=" + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A" * 6
    monkeypatch.setattr(dns_auth, "_txt_records", lambda name, **_k: [schluessel])
    ergebnis = dns_auth.check_dkim("selector1", "outlook.com")
    assert ergebnis.revoked is False
    assert ergebnis.verdict == "Schlüssel veröffentlicht"


def test_ohne_selektor_wird_nicht_gefragt(monkeypatch):
    """Eine Mail ohne DKIM-Signatur hat keinen Selektor — dann gibt es nichts
    abzufragen, und das ist kein Fehler."""
    gerufen: list[str] = []
    monkeypatch.setattr(dns_auth, "_txt_records", lambda *a, **k: gerufen.append(1) or [])
    ergebnis = dns_auth.check_dkim("", "firma.de")
    assert not gerufen, "ohne Selektor wurde trotzdem gefragt"
    assert ergebnis.error == ""
    assert ergebnis.verdict == "kein Selektor in der Signatur"


def test_check_fragt_alle_drei(monkeypatch):
    """SPF, DMARC und DKIM — der Auftrag lautete "SPF/DKIM/DMARC"."""
    gefragt: list[str] = []

    def merken(name, **_k):
        gefragt.append(name)
        return ["v=spf1 -all"] if "spf" not in name else ["v=DMARC1; p=reject"]

    monkeypatch.setattr(dns_auth, "_txt_records", merken)
    bericht = dns_auth.check(
        "203.0.113.5", "a@mail.firma.de", "b@firma.de", "sel1", "firma.de"
    )
    assert bericht.spf.ran and bericht.dmarc.ran and bericht.dkim.ran
    # TEST-027: der SPF-Name wurde nie geprueft — hier ist er die exakte
    # Envelope-Domain, nicht das Registrable.
    assert "mail.firma.de" in gefragt, gefragt
    assert "firma.de" not in gefragt, f"SPF fragte die falsche Domain: {gefragt}"
    assert any("_dmarc." in n for n in gefragt), gefragt
    assert any("_domainkey." in n for n in gefragt), gefragt


def test_dkim_record_ohne_v_dkim1_wird_erkannt(monkeypatch):
    """``v=DKIM1`` ist OPTIONAL — erkannt wird am ``p=``-Tag.

    GEMESSEN an s1._domainkey.github.com: der Eintrag lautet
    ``k=rsa; t=s; p=MIIBIjAN...`` — kein ``v=DKIM1`` am Anfang. Eine Prüfung
    auf den ANFANG verwarf ihn, und die Stufe meldete „kein Schlüssel
    veröffentlicht" für einen lebenden 406-Zeichen-Schlüssel.
    """
    monkeypatch.setattr(
        dns_auth,
        "_txt_records",
        lambda name, **_k: ["k=rsa; t=s; p=" + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A" * 8],
    )
    ergebnis = dns_auth.check_dkim("s1", "github.com")
    assert ergebnis.record, "der Eintrag wurde verworfen"
    assert ergebnis.revoked is False
    assert ergebnis.verdict == "Schlüssel veröffentlicht"


def test_zerlegter_txt_record_kommt_vollstaendig_an(monkeypatch):
    """Ein TXT-Record über 255 Byte wird in Teilstrings zerlegt.

    Die Verkettung passiert in PowerShell (``-join ''`` pro Record); hier
    geprüft wird, dass die Stufe mit der ZUSAMMENGESETZTEN Form umgeht — ein
    Bruchstück wäre je nach Trennstelle als „widerrufen" lesbar, weil das
    ``p=``-Tag im ersten Teil leer aussähe.

    GEMESSEN gegen das echte Netz: s1@github.com liefert 406 Zeichen in zwei
    Strings, selector1@outlook.com 437.
    """
    # So sieht das erste Bruchstück aus, wenn NICHT verkettet wird: p= leer.
    bruchstueck = "v=DKIM1; k=rsa; p="
    monkeypatch.setattr(dns_auth, "_txt_records", lambda name, **_k: [bruchstueck])
    assert dns_auth.check_dkim("s1", "github.com").verdict == "Schlüssel widerrufen"

    # Und so die zusammengesetzte Form.
    ganz = "v=DKIM1; k=rsa; p=" + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A" * 8
    monkeypatch.setattr(dns_auth, "_txt_records", lambda name, **_k: [ganz])
    ergebnis = dns_auth.check_dkim("s1", "github.com")
    assert ergebnis.revoked is False
    assert ergebnis.verdict == "Schlüssel veröffentlicht"


def test_mehrere_txt_records_bleiben_getrennt(monkeypatch):
    """Eine Domain kann mehrere TXT-Records haben — sie dürfen nicht verschmelzen.

    Deshalb wird PRO Record verkettet und nicht über alle hinweg: sonst
    entstünde aus einem Verifikations-TXT und einem DKIM-TXT ein dritter,
    den niemand veröffentlicht hat.
    """
    monkeypatch.setattr(
        dns_auth,
        "_txt_records",
        lambda name, **_k: ["etwas-anderes=1", "v=DKIM1; k=rsa; p=" + "A" * 300],
    )
    ergebnis = dns_auth.check_dkim("sel", "firma.de")
    assert ergebnis.record.startswith("v=DKIM1")
    assert "etwas-anderes" not in ergebnis.record


def test_zerlegter_record_wird_beim_lesen_verkettet(monkeypatch):
    """Die Verkettung passiert in PYTHON, nicht in PowerShell — deshalb ist
    genau dieser Fehler jetzt eine Zusicherung.

    GEMESSEN gegen das echte Netz: s1._domainkey.github.com liefert zwei
    Character-Strings mit zusammen 406 Zeichen. Wird nicht verkettet, sieht
    der Aufrufer nur das erste Bruchstück "v=DKIM1; k=rsa; p=" — also einen
    LEEREN Schlüssel — und meldet einen lebenden Schlüssel als "kein
    Schlüssel veröffentlicht".
    """
    class _R:
        returncode = 0

    # Die Form, die das PowerShell-Skript liefert: EIN Record, ZWEI Strings.
    antwort = (
        b'{"ok":true,"records":[["v=DKIM1; k=rsa; p=","'
        + b"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A" * 8
        + b'"]]}'
    )
    monkeypatch.setattr(dns_auth, "run_tool", lambda *a, **k: (_R(), antwort, b""))
    monkeypatch.setattr(dns_auth.shutil, "which", lambda _n: "powershell")

    eintraege = dns_auth._txt_records("s1._domainkey.github.com")
    assert len(eintraege) == 1, f"aus einem Record wurden {len(eintraege)}"
    # Das erste Bruchstück allein hat 18 Zeichen ("v=DKIM1; k=rsa; p=").
    # Alles deutlich darüber beweist, dass verkettet wurde.
    assert len(eintraege[0]) > 100, f"nur {len(eintraege[0])} Zeichen — Bruchstück"
    assert eintraege[0].startswith("v=DKIM1")


def test_zwei_records_bleiben_zwei(monkeypatch):
    """Die Gegenprobe: die Verkettung darf Records nicht verschmelzen.

    Eine Domain kann mehrere TXT-Records haben. Aus einem Verifikations- und
    einem DKIM-Eintrag darf kein dritter entstehen, den niemand
    veröffentlicht hat.
    """
    class _R:
        returncode = 0

    antwort = b'{"ok":true,"records":[["teil-a"],["teil-b"]]}'
    monkeypatch.setattr(dns_auth, "run_tool", lambda *a, **k: (_R(), antwort, b""))
    monkeypatch.setattr(dns_auth.shutil, "which", lambda _n: "powershell")

    eintraege = dns_auth._txt_records("firma.de")
    assert eintraege == ["teil-a", "teil-b"], eintraege


def test_unzerlegter_record_kommt_unveraendert_an(monkeypatch):
    """Die flache Form (ein String) bleibt gültig — sie ist der Normalfall."""
    class _R:
        returncode = 0

    antwort = b'{"ok":true,"records":["v=spf1 -all"]}'
    monkeypatch.setattr(dns_auth, "run_tool", lambda *a, **k: (_R(), antwort, b""))
    monkeypatch.setattr(dns_auth.shutil, "which", lambda _n: "powershell")

    assert dns_auth._txt_records("firma.de") == ["v=spf1 -all"]


# -- Das Gate in der Pipeline (TEST-026) ------------------------------------ #


def _pipeline_ctx():
    from pathlib import Path

    from malaz.models import AnalysisContext

    raw = (
        b"Received: from mx.firma.example (mx.firma.example [203.0.113.9]) "
        b"by p with ESMTPS; Tue, 1 Jan 2030 10:00:00 +0000\r\n"
        b"From: Firma <service@mail.firma.example>\r\n"
        b"To: opfer@firma.example\r\n"
        b"Subject: Rechnung\r\n"
        b"Message-ID: <x@mail.firma.example>\r\n"
        b"\r\n"
        b"Bitte zahlen.\r\n"
    )
    return AnalysisContext(
        path=Path("x.eml"), data=raw, detected_type="eml", size=len(raw)
    )


def test_pipeline_fragt_dns_nur_nach_opt_in(monkeypatch):
    """Das Gate ``if not dns_auth.enabled(): return []`` ist der Vertrag.

    Geprueft wird ueber ``EmlPipeline``, nicht nur ueber ``config``: das
    Entfernen des Gates waere sonst gruen geblieben (Audit TEST-026).
    """
    from malaz import config
    from malaz.pipelines.eml_pipeline import EmlPipeline

    gefragt: list[str] = []

    def merken(name, **_k):
        gefragt.append(name)
        if name == "mail.firma.example":
            return ["v=spf1 ip4:203.0.113.9 -all"]
        return []

    monkeypatch.setattr(dns_auth, "_txt_records", merken)
    ctx = _pipeline_ctx()

    monkeypatch.setattr(config, "DNS_AUTH_ENABLED", False)
    aus = EmlPipeline().analyze(ctx)
    assert gefragt == [], f"ohne Zustimmung wurde gefragt: {gefragt}"
    assert "MAIL_AUTH_DNS" not in {i.rule_id for i in aus}

    monkeypatch.setattr(config, "DNS_AUTH_ENABLED", True)
    an = EmlPipeline().analyze(ctx)
    assert "mail.firma.example" in gefragt, gefragt
    assert "MAIL_AUTH_DNS" in {i.rule_id for i in an}
