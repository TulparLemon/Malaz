"""Tests fuer die lokale IP-Blockliste (Spamhaus DROP)."""

import ipaddress

from malaz.core.ipblocklist import is_blocked_ip, load_ip_blocklist, parse_spamhaus_drop

# Zwei Eintraege, wie sie die DROP-Datei liefert: ein grosses Netz und ein
# spaeter beginnendes, das mitten darin liegt.
_DROP_TEXT = (
    "; Spamhaus DROP v4\n"
    '{"cidr":"10.0.0.0/8","sblid":"SBL1","rir":"ripencc"}\n'
    '{"cidr":"10.1.2.0/24","sblid":"SBL2","rir":"apnic"}\n'
    "\n"
    '{"cidr":"192.0.2.0/24","sblid":"SBL3","rir":"arin"}\n'
)


def _nets():
    return parse_spamhaus_drop(_DROP_TEXT)


def test_erste_und_letzte_adresse_sind_blockiert_nachbar_nicht():
    nets = _nets()
    assert is_blocked_ip("192.0.2.0", nets)  # erste Adresse des Netzes
    assert is_blocked_ip("192.0.2.255", nets)  # letzte Adresse des Netzes
    assert not is_blocked_ip("192.0.1.255", nets)  # direkt davor
    assert not is_blocked_ip("192.0.3.0", nets)  # direkt dahinter


def test_treffer_in_einem_frueher_beginnenden_netz_wird_gefunden():
    # 10.1.2.5 liegt in 10.1.2.0/24, aber auch in 10.0.0.0/8 — dessen
    # Startadresse liegt vor dem Bisektionspunkt. Ohne Rueckwaertslauf
    # bliebe 10.5.0.1 unerkannt.
    nets = _nets()
    assert is_blocked_ip("10.1.2.5", nets)
    assert is_blocked_ip("10.5.0.1", nets)
    assert not is_blocked_ip("11.0.0.1", nets)


def test_sortierung_der_liste_ist_nach_startadresse():
    starts = [int(net.network_address) for net in _nets()]
    assert starts == sorted(starts)


def test_kommentarzeilen_brechen_das_parsen_nicht():
    nets = parse_spamhaus_drop(
        "; Kopfzeile\n"
        "; noch ein Kommentar\n"
        ';{"cidr":"6.6.6.0/24"}\n'  # auskommentierter Eintrag darf nicht greifen
        '{"cidr":"203.0.113.0/24"}\n'
    )
    assert nets == [ipaddress.ip_network("203.0.113.0/24")]
    assert is_blocked_ip("203.0.113.7", nets)
    assert not is_blocked_ip("6.6.6.1", nets)


def test_kaputte_zeilen_werden_uebersprungen():
    nets = parse_spamhaus_drop(
        "kein json\n"
        '{"sblid":"ohne cidr"}\n'
        '{"cidr":"kein-netz"}\n'
        '["nicht","objekt"]\n'
        '{"cidr":"198.51.100.0/24"}\n'
    )
    assert nets == [ipaddress.ip_network("198.51.100.0/24")]


def test_doppelte_eintraege_werden_zusammengefasst():
    nets = parse_spamhaus_drop('{"cidr":"198.51.100.0/24"}\n{"cidr":"198.51.100.0/24"}\n')
    assert len(nets) == 1


def test_ungueltige_ip_gilt_als_nicht_blockiert():
    nets = _nets()
    for wert in ("", "   ", "nicht-ip", "999.999.999.999", "10.0.0.1/8", "10.0.0"):
        assert is_blocked_ip(wert, nets) is False


def test_ipv6_wirft_nicht():
    nets = _nets()
    assert is_blocked_ip("2001:db8::1", nets) is False
    assert is_blocked_ip("::1", nets) is False
    assert is_blocked_ip("::ffff:10.1.2.5", nets) is False


def test_ipv6_faellt_nicht_in_den_wertebereich_der_v4_netze():
    # ::1 hat den Zahlenwert 1 — ohne Trennung der Adressfamilien laege das
    # scheinbar in 0.0.0.0/8.
    nets = [ipaddress.ip_network("0.0.0.0/8")]
    assert is_blocked_ip("0.0.0.1", nets) is True
    assert is_blocked_ip("::1", nets) is False
    assert is_blocked_ip("::ffff:0.0.0.1", nets) is False
    assert is_blocked_ip("2001:db8::1", nets) is False


def test_leere_liste_blockiert_nichts():
    assert is_blocked_ip("10.0.0.1", []) is False


def test_fehlende_datei_ergibt_leere_liste(tmp_path):
    assert load_ip_blocklist(tmp_path / "gibts_nicht.json") == []


def test_datei_mit_kommentaren_wird_geladen(tmp_path):
    ziel = tmp_path / "drop.json"
    ziel.write_text(_DROP_TEXT, encoding="utf-8")
    nets = load_ip_blocklist(ziel)
    assert len(nets) == 3
    assert is_blocked_ip("10.5.0.1", nets)
    assert not is_blocked_ip("172.16.0.1", nets)


def test_utf8_bom_does_not_lose_the_first_entry(tmp_path):
    """BUG-080: ``\\ufeff`` on line 1 made the first entry unmatchable."""
    from malaz.core.domain_blocklist import load_domain_blocklist

    ip_file = tmp_path / "drop.json"
    ip_file.write_bytes(
        b"\xef\xbb\xbf" + b'{"cidr":"10.0.0.0/8"}\n{"cidr":"192.0.2.0/24"}\n'
    )
    nets = load_ip_blocklist(ip_file)
    assert is_blocked_ip("10.1.2.3", nets), "erster BOM-Eintrag fehlt"
    assert is_blocked_ip("192.0.2.7", nets)

    domain_file = tmp_path / "domains.txt"
    domain_file.write_bytes(b"\xef\xbb\xbf" + b"evil.example\ngood.example\n")
    domains = load_domain_blocklist(domain_file)
    assert "evil.example" in domains, "erste Domain mit BOM fehlt"
    assert "good.example" in domains


def test_unreadable_list_is_reported_not_swallowed(tmp_path, caplog):
    """Eine VORHANDENE, aber unlesbare Liste darf nicht still verschwinden.

    Fehlende Datei ist der Normalfall (noch nichts heruntergeladen) und darf
    still leer bleiben. Eine Datei, die da ist und nicht gelesen werden kann,
    ist etwas anderes: der Nutzer hat 1700 Netze importiert und bekommt ohne
    Warnung keine Pruefung mehr.

    core/hashlist macht das seit jeher richtig (log.warning im except); die
    neuen Listen taten es nicht — dieselbe Kontrolle an einer Stelle, an der
    Schwesterstelle vergessen.
    """
    import logging

    from malaz.core.domain_blocklist import load_domain_blocklist
    from malaz.core.ipblocklist import load_ip_blocklist

    # Ein Verzeichnis hat eine Groesse (stat gelingt), ist aber nicht lesbar.
    verzeichnis = tmp_path / "liste.txt"
    verzeichnis.mkdir()

    with caplog.at_level(logging.WARNING):
        assert load_ip_blocklist(verzeichnis) == []
        assert load_domain_blocklist(verzeichnis) == frozenset()

    assert caplog.records, "keine Warnung protokolliert — der Ausfall bleibt still"
    meldungen = [r.getMessage() for r in caplog.records]
    # Wortlaut, nicht Teilstring "lesen"/"read": der tmp_path-Name enthaelt
    # "unreadable" und lieferte den Treffer allein aus dem Pfad — der Test war
    # vakuum und blieb gruen, auch wenn beide Loader den Ausfall verschluckten
    # (TEST-034).
    assert any("Domain-Blockliste nicht lesbar" in m for m in meldungen), meldungen
    assert any("IP-Blockliste nicht lesbar" in m for m in meldungen), meldungen


def test_fehlende_domain_datei_ist_der_stille_normalfall(tmp_path):
    """ENOENT ist "noch nichts importiert" — keine Warnung, kein Status."""
    from malaz.core.domain_blocklist import load_domain_blocklist_or_error

    werte, fehler = load_domain_blocklist_or_error(tmp_path / "gibts_nicht.txt")
    assert werte == frozenset()
    assert fehler == ""


def test_domain_stat_fehler_gilt_nicht_als_fehlende_liste(tmp_path, monkeypatch):
    """BUG-077: nur ENOENT/ENOTDIR heisst "fehlt".

    Ein PermissionError beim stat ist eine VORHANDENE, unlesbare Liste. Vorher
    schluckte ``_stat_key`` jedes OSError und der Scan meldete "geprueft, kein
    Treffer", statt DOMAIN_BLOCKLIST_UNAVAILABLE zu setzen.
    """
    import pathlib

    from malaz.core.domain_blocklist import load_domain_blocklist_or_error

    ziel = tmp_path / "domains.txt"
    ziel.write_text("evil.example\n", encoding="utf-8")
    echt = pathlib.Path.stat

    def kaputt(self, *args, **kwargs):
        if str(self) == str(ziel):
            raise PermissionError(13, "Zugriff verweigert", str(self))
        return echt(self, *args, **kwargs)

    monkeypatch.setattr(pathlib.Path, "stat", kaputt)

    werte, fehler = load_domain_blocklist_or_error(ziel)
    assert werte == frozenset()
    assert fehler == "PermissionError", (
        "stat-Fehler wurde als 'Datei fehlt' verschluckt — "
        "DOMAIN_BLOCKLIST_UNAVAILABLE bleibt dann aus"
    )


def test_pathologische_domain_wird_vor_der_suffixschleife_abgelehnt():
    """SEC-037: der Suffix-Lauf ist quadratisch in der Label-Anzahl.

    Gemessen vorher: 40 000 Labels -> 9,57 s in einem Worker. Die Laengengrenze
    (253 Zeichen, DNS-Maximum) begrenzt den Lauf auf 127 Schritte.
    """
    import time as _time

    from malaz.core.domain_blocklist import is_blocked_domain

    listed = frozenset({"evil.example"})
    start = _time.perf_counter()
    assert is_blocked_domain(".".join(["a"] * 20_000), listed) is False
    dauer = _time.perf_counter() - start
    assert dauer < 0.5, f"{dauer:.2f}s für eine unmoegliche Domain"

    # Gegenprobe: normale Suffix-Treffer bleiben unveraendert.
    assert is_blocked_domain("mail.evil.example", listed) is True
    assert is_blocked_domain("evil.example", listed) is True
    assert is_blocked_domain("sauber.example", listed) is False


def test_stat_fehler_ist_nicht_fehlende_liste(tmp_path, monkeypatch):
    """BUG-077: nur ENOENT/ENOTDIR heisst 'Liste fehlt'."""
    from pathlib import Path

    from malaz.core.ipblocklist import load_ip_blocklist_or_error

    def _boom(self, *args, **kwargs):
        raise PermissionError(13, "denied")

    monkeypatch.setattr(Path, "stat", _boom)
    nets, error = load_ip_blocklist_or_error(tmp_path / "liste.txt")
    assert nets == []
    assert error == "PermissionError"
