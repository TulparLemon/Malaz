"""Tests fuer die Feed-Registry und den Downloader (core.feeds).

KEIN NETZ IN DER SUITE
======================
Ein Test, der eine echte Quelle abruft, waere aus drei Gruenden untauglich:
er haengt von der Verfuegbarkeit Dritter ab (rot ohne Codeaenderung), er
erzeugt Verkehr, wo das Projekt Offline-Betrieb verspricht, und er kann den
interessanten Fall — Abbruch mitten im Lesen — nicht herstellen.
``urllib.request.urlopen`` wird deshalb durch einen Doppelgaenger ersetzt.
Der Test prueft damit nicht "ob das Internet geht", sondern was Malaz mit den
Bytes und den Fehlern einer Antwort macht.
"""

from __future__ import annotations

import dataclasses
import os
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from malaz.core import feeds
from malaz.core.feeds import FEEDS, Feed, FeedError, download_feed

_INHALT = [b"1.2.3.0/24\n", b"5.6.7.0/24\n"]


class _Antwort:
    """Doppelgaenger einer urlopen-Antwort: Kontextmanager mit read().

    ``raw`` wird in ``chunks`` Stueck fuer Stueck ausgeliefert (leeres b""
    beendet), ``fehler`` wird nach dem angegebenen Stueck geworfen — so laesst
    sich ein Abbruch MITTEN im Download nachstellen, nicht nur ein Fehler vor
    dem ersten Byte.
    """

    def __init__(self, chunks: list[bytes], fehler: Exception | None = None) -> None:
        self._chunks = list(chunks)
        self._fehler = fehler

    def read(self, _size: int = -1) -> bytes:
        if self._fehler is not None and not self._chunks:
            raise self._fehler
        return self._chunks.pop(0) if self._chunks else b""

    def __enter__(self) -> _Antwort:
        return self

    def __exit__(self, *_exc: object) -> None:
        # None = Ausnahme nicht verschlucken (der Doppelgaenger verhaelt sich
        # wie eine echte Antwort).
        return None


@pytest.fixture
def feed() -> Feed:
    """Testfeed mit der Form eines echten Eintrags (keine Sonderfaelle)."""
    return Feed(
        key="testfeed",
        title="Testfeed",
        purpose="Nur fuer den Test.",
        url="https://example.invalid/feed.txt",
        size_hint="1 KB",
        license_note="Testdaten",
        kind="cidr",
    )


def _kein_urlopen(*_args: object, **_kwargs: object) -> None:
    raise AssertionError("Der Test darf keinen echten Netzwerkzugriff ausloesen")


def test_download_schreibt_datei_und_keine_part(tmp_path, monkeypatch, feed):
    """Erfolg: die fertige Datei liegt da, der Zwischenstand ist weg."""
    monkeypatch.setattr(urllib.request, "urlopen", lambda *_a, **_k: _Antwort(_INHALT))

    ziel = download_feed(feed, tmp_path)

    assert ziel == tmp_path / "testfeed.feed"
    assert ziel.read_bytes() == b"1.2.3.0/24\n5.6.7.0/24\n"
    # Die Beissprobe fuer den zweistufigen Download: ohne das Umbenennen
    # laege der Inhalt nur in der .part-Datei, und ziel.read_bytes() oben
    # schluege fehl.
    assert list(tmp_path.glob("*.part")) == []


def test_each_download_uses_its_own_part_name(tmp_path, monkeypatch, feed):
    """SEC-011: two parallel downloads shared ``<key>.feed.part``.

    Interleaved writes produced a published feed that matched neither payload
    (and was signed as valid). Each download must own its temporary file.
    """
    import types

    hexes = iter(["aaa", "bbb"])
    monkeypatch.setattr(
        feeds.uuid, "uuid4", lambda: types.SimpleNamespace(hex=next(hexes))
    )
    monkeypatch.setattr(urllib.request, "urlopen", lambda *_a, **_k: _Antwort(_INHALT))
    opened: list[str] = []
    original_open = Path.open

    def recording_open(self, mode="r", *args, **kwargs):
        if "w" in mode:
            opened.append(self.name)
        return original_open(self, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", recording_open)
    download_feed(feed, tmp_path)
    download_feed(feed, tmp_path)

    assert opened == ["testfeed.aaa.feed.part", "testfeed.bbb.feed.part"], opened


def test_lesefehler_laesst_keine_datei_zurueck(tmp_path, monkeypatch, feed):
    """Abbruch mitten im Lesen: keine halbe Datei, kein Rest, kein Feed."""
    def kaputt(*_args: object, **_kwargs: object) -> _Antwort:
        return _Antwort([_INHALT[0]], fehler=urllib.error.URLError("Netz weg"))

    monkeypatch.setattr(urllib.request, "urlopen", kaputt)

    with pytest.raises(FeedError):
        download_feed(feed, tmp_path)

    assert list(tmp_path.iterdir()) == []


def test_fehlversuch_zerstoert_den_vorhandenen_feed_nicht(tmp_path, monkeypatch, feed):
    """Ein misslungener Nachladeversuch darf die gute Datenbank nicht loeschen."""
    vorhanden = tmp_path / "testfeed.feed"
    vorhanden.write_bytes(b"alter stand\n")
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda *_a, **_k: _Antwort([b"teil\n"], fehler=TimeoutError("zu langsam")),
    )

    with pytest.raises(FeedError):
        download_feed(feed, tmp_path)

    assert vorhanden.read_bytes() == b"alter stand\n"
    assert list(tmp_path.glob("*.part")) == []


def test_zu_grosser_feed_bricht_ab(tmp_path, monkeypatch, feed):
    """Der Deckel greift waehrend des Lesens, nicht erst nach dem Speichern."""
    monkeypatch.setattr(feeds, "MAX_FEED_BYTES", 8)
    monkeypatch.setattr(
        urllib.request, "urlopen", lambda *_a, **_k: _Antwort([b"x" * 8, b"y" * 8, b"z" * 8])
    )

    with pytest.raises(FeedError, match="groesser als"):
        download_feed(feed, tmp_path)

    assert list(tmp_path.iterdir()) == []


def test_http_fehler_wird_zu_feedfehler(tmp_path, monkeypatch, feed):
    """HTTP 404 ist fuer die GUI derselbe Fehlerfall wie jeder andere."""
    def abgelehnt(*_args: object, **_kwargs: object) -> None:
        raise urllib.error.HTTPError(feed.url, 404, "Not Found", {}, None)  # type: ignore[arg-type]

    monkeypatch.setattr(urllib.request, "urlopen", abgelehnt)

    with pytest.raises(FeedError, match="404"):
        download_feed(feed, tmp_path)

    assert list(tmp_path.iterdir()) == []


def test_klartext_url_wird_abgelehnt(tmp_path, monkeypatch, feed):
    """Ein Feed ueber http:// ist austauschbar und wird gar nicht erst geholt."""
    monkeypatch.setattr(urllib.request, "urlopen", _kein_urlopen)
    unsicher = dataclasses.replace(feed, url="http://example.invalid/feed.txt")

    with pytest.raises(FeedError, match="https"):
        download_feed(unsicher, tmp_path)

    assert list(tmp_path.iterdir()) == []



def test_download_rejects_redirect_to_another_host(tmp_path, monkeypatch, feed):
    class _Redirected(_Antwort):
        def geturl(self):
            return "https://evil.invalid/feed.txt"

    monkeypatch.setattr(
        urllib.request, "urlopen", lambda *_a, **_k: _Redirected([b"data\n"])
    )
    with pytest.raises(FeedError, match="Weiterleitung"):
        download_feed(feed, tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_stream_rejects_redirect_to_another_host(monkeypatch, feed):
    class _Redirected(_Antwort):
        def geturl(self):
            return "http://evil.invalid/feed.txt"

    monkeypatch.setattr(
        feeds.urllib.request, "urlopen", lambda *_a, **_k: _Redirected([b"data\n"])
    )
    with pytest.raises(FeedError, match="Weiterleitung"):
        feeds.stream_feed(feed, lambda _line: None)

# -- Registry --------------------------------------------------------------


def test_registry_hat_keine_doppelten_keys():
    """Zwei Feeds mit demselben key wuerden sich gegenseitig ueberschreiben."""
    keys = [f.key for f in FEEDS]

    assert keys
    assert len(keys) == len(set(keys))


def test_registry_keys_sind_als_dateiname_brauchbar():
    """Der key wird zu ``<key>.feed`` — ein Pfad darin schriebe aus dem Ordner."""
    assert all(Path(f.key).name == f.key for f in FEEDS)


@pytest.mark.parametrize("eintrag", FEEDS, ids=lambda f: f.key)
def test_jede_feed_url_ist_https(eintrag):
    assert eintrag.url.startswith("https://"), f"{eintrag.key} laedt unverschluesselt"


def test_jeder_feed_hat_eine_bekannte_art():
    """Die Auswertung entscheidet ueber ``kind``; ein Tippfehler faellt sonst
    erst beim Import der heruntergeladenen Datei auf."""
    assert {f.kind for f in FEEDS} <= {"url", "domain", "sha256", "cidr"}


# -- Standsanzeige und Faelligkeit ------------------------------------------ #
#
# Der Stand wird aus den IMPORTIERTEN LISTEN gelesen, nicht aus den Rohdateien
# des Downloads. Die erste Fassung las die Rohdateien und meldete "nie
# geladen", obwohl 1,2 Millionen Eintraege aktiv waren — wer die Listen per
# import_blocklist.py gefuellt hat, hat gar keine Rohdateien. Diese Tests
# halten die richtige Grundlage fest.


def _listen(tmp_path, monkeypatch, *, alter: dict[str, int | None]):
    """Vier Listen anlegen, `alter` gibt je Name das Alter in Tagen vor."""
    from malaz import config

    pfade = {
        "Datei-Hashes": tmp_path / "blocklist.sha256",
        "URL-Hashes": tmp_path / "urls.sha256",
        "Domains": tmp_path / "domains.txt",
        "IP-Netze": tmp_path / "netze.txt",
    }
    monkeypatch.setattr(config, "USER_HASH_BLOCKLIST_FILE", pfade["Datei-Hashes"])
    monkeypatch.setattr(config, "URL_BLOCKLIST_FILE", pfade["URL-Hashes"])
    monkeypatch.setattr(config, "DOMAIN_BLOCKLIST_FILE", pfade["Domains"])
    monkeypatch.setattr(config, "IP_BLOCKLIST_FILE", pfade["IP-Netze"])

    jetzt = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)
    for name, pfad in pfade.items():
        tage = alter.get(name)
        if tage is None:
            continue  # Datei fehlt
        pfad.write_text("a" * 100, encoding="utf-8")
        zeit = (jetzt - timedelta(days=tage)).timestamp()
        os.utime(pfad, (zeit, zeit))
    return jetzt


def test_stand_liest_die_listen_nicht_die_rohdateien(tmp_path, monkeypatch):
    """Wer per Skript importiert hat, hat keine Rohdateien — und trotzdem Stand.

    Genau dieser Fall lag auf dem Rechner: die Rohablage existierte nicht,
    die Listen waren voll. Eine Anzeige, die den Transport misst, haette hier
    "nie geladen" behauptet.
    """
    jetzt = _listen(tmp_path, monkeypatch, alter={n: 0 for n in
                    ("Datei-Hashes", "URL-Hashes", "Domains", "IP-Netze")})
    from malaz.core.feeds import list_states, state_badge

    assert not feeds.feed_dir().exists(), "Vorbedingung: keine Rohablage"
    zustaende = list_states(jetzt)
    assert [z.name for z in zustaende] and all(z.exists for z in zustaende)

    name, zustand, tooltip = state_badge(min_age_days=1, now=jetzt)
    assert (name, zustand) == ("Datenbanken", "ok")
    assert "4 von 4 Listen vorhanden" in tooltip


def test_alter_liste_macht_gelb(tmp_path, monkeypatch):
    """Eine vergessene Liste neben drei frischen ist die Luecke."""
    jetzt = _listen(tmp_path, monkeypatch, alter={
        "Datei-Hashes": 0, "URL-Hashes": 5, "Domains": 0, "IP-Netze": 0})
    from malaz.core.feeds import state_badge

    assert state_badge(min_age_days=1, now=jetzt)[1] == "warn"


def test_fehlende_liste_macht_gelb_und_wird_genannt(tmp_path, monkeypatch):
    jetzt = _listen(tmp_path, monkeypatch, alter={
        "Datei-Hashes": 0, "URL-Hashes": 0, "Domains": 0, "IP-Netze": None})
    from malaz.core.feeds import state_badge

    _, zustand, tooltip = state_badge(min_age_days=1, now=jetzt)
    assert zustand == "warn"
    assert "IP-Netze: fehlt" in tooltip


def test_ohne_jede_liste_ist_der_stand_aus(tmp_path, monkeypatch):
    jetzt = _listen(tmp_path, monkeypatch, alter=dict.fromkeys(
        ("Datei-Hashes", "URL-Hashes", "Domains", "IP-Netze")))
    from malaz.core.feeds import state_badge

    assert state_badge(min_age_days=1, now=jetzt)[1] == "off"


def test_auffrischung_ist_aus_ohne_haken(tmp_path, monkeypatch):
    """Der Haken ist die einzige Erlaubnis — ohne ihn wird nichts geholt."""
    _listen(tmp_path, monkeypatch, alter={
        "Datei-Hashes": 99, "URL-Hashes": 99, "Domains": 99, "IP-Netze": 99})
    faellig, grund = feeds.refresh_due(enabled=False)
    assert faellig is False
    assert "aus" in grund


def test_auffrischung_ist_faellig_wenn_alles_veraltet(tmp_path, monkeypatch):
    """`now` MUSS mitgegeben werden.

    Ohne feste Uhrzeit haengt das Ergebnis an der Tageszeit des Testlaufs:
    eine Datei von "vor 5 Tagen 12:00" ist um 11:00 erst 4,98 Tage alt und
    damit 4 — der Test kippte je nach Stunde. Dieselbe Klasse Fehler, die
    den Korpus schon einmal zum Flackern brachte.
    """
    jetzt = _listen(tmp_path, monkeypatch, alter={
        "Datei-Hashes": 5, "URL-Hashes": 5, "Domains": 5, "IP-Netze": 5})
    faellig, grund = feeds.refresh_due(enabled=True, min_age_days=1, now=jetzt)
    assert faellig is True
    assert "5 Tage" in grund


def test_juengste_liste_nennt_das_kleinste_alter(tmp_path, monkeypatch):
    """BUG-015: 'juengste 5 Tage alt' bei Altern 1/2/5/4 war ``max``."""
    jetzt = _listen(tmp_path, monkeypatch, alter={
        "Datei-Hashes": 1, "URL-Hashes": 2, "Domains": 5, "IP-Netze": 4})
    faellig, grund = feeds.refresh_due(enabled=True, min_age_days=7, now=jetzt)
    assert faellig is False, grund
    assert "juengste 1 Tag" in grund, grund


def test_auffrischung_ist_faellig_wenn_nichts_da_ist(tmp_path, monkeypatch):
    """Ohne jede Liste ist die Einrichtung leer — das faellt sonst nie auf."""
    _listen(tmp_path, monkeypatch, alter=dict.fromkeys(
        ("Datei-Hashes", "URL-Hashes", "Domains", "IP-Netze")))
    faellig, grund = feeds.refresh_due(enabled=True, min_age_days=1)
    assert faellig is True
    assert "keine Liste" in grund


def test_frische_listen_loesen_keine_auffrischung_aus(tmp_path, monkeypatch):
    """Sonst holte jeder Start 65 MB — der Deckel gegen Dauerlast."""
    jetzt = _listen(tmp_path, monkeypatch, alter={n: 0 for n in
                    ("Datei-Hashes", "URL-Hashes", "Domains", "IP-Netze")})
    faellig, grund = feeds.refresh_due(enabled=True, min_age_days=1, now=jetzt)
    assert faellig is False
    assert "aktuell" in grund


class _StueckAntwort:
    """Minimale HTTP-Antwort fuer den Streaming-Test, ohne echtes Netz."""

    def __init__(self, daten: bytes, stueck: int = 64) -> None:
        self._daten = daten
        self._stueck = stueck
        self._pos = 0

    def __enter__(self) -> _Antwort:
        return self

    def __exit__(self, *_a) -> bool:
        return False

    def read(self, n: int = -1) -> bytes:
        n = self._stueck if n is None or n < 0 else min(n, self._stueck)
        teil = self._daten[self._pos : self._pos + n]
        self._pos += len(teil)
        return teil


def test_url_feed_wird_nicht_abgelegt(monkeypatch, tmp_path):
    """Der Fall, der den Anwender getroffen hat: EDR blockiert die Rohdatei.

    Eine Liste mit tausenden LEBENDEN Schad-URLs wurde als ``.feed.part``
    abgelegt; CyNet meldete "Malicious File Dumped on the Disk" und der Nutzer
    musste seine Schutz-Konfiguration anfassen, um Malaz zu benutzen.

    Der Streaming-Weg hasht im Vorbeilesen. Was nie auf der Platte liegt, kann
    nichts blockieren — und der Abgleich muss trotzdem funktionieren.
    """
    from malaz import config
    from malaz.core import feed_import, feeds, hashlist, url_reputation

    nutzlast = b"# Kommentar\nhttp://boese.example/malware.exe\n"
    nutzlast += b"".join(
        f"http://boese.example/pfad{i}\n".encode() for i in range(2000)
    )

    ziel = tmp_path / "urls.sha256"
    ziel.write_text("", encoding="utf-8")
    # TEST-011: the snapshot is written below ``feed_dir()/sources``, not into
    # the passed ``tmp_path``. Redirect it explicitly and assert on THAT tree —
    # the old test only looked at ``tmp_path`` and would have missed plaintext
    # URLs (or leftovers) in the real feed directory.
    feed_root = tmp_path / "feedroot"
    monkeypatch.setattr(feed_import, "feed_dir", lambda: feed_root)
    monkeypatch.setattr(feeds, "feed_dir", lambda: feed_root)
    monkeypatch.setattr(config, "URL_BLOCKLIST_FILE", ziel)
    monkeypatch.setattr(
        feeds.urllib.request,
        "urlopen",
        lambda *_a, **_k: _StueckAntwort(nutzlast),
    )
    hashlist._load_blocklist.cache_clear()

    feed = next(f for f in feeds.FEEDS if f.kind == "url")
    pfad, ergebnis = feed_import.refresh_feed(feed, tmp_path)

    assert ergebnis.imported == 2001, "die Zeilen kamen nicht alle an"
    assert pfad == ziel

    # Only the blocklist (and the signed snapshot below feed_root) may exist;
    # no raw download anywhere under tmp_path.
    uebrig = [
        p.name
        for p in tmp_path.rglob("*")
        if p.is_file() and p not in (ziel,) and feed_root not in p.parents
    ]
    assert uebrig == [], f"Rohdatei(en) auf der Platte: {uebrig}"

    snapshot = feed_root / "sources" / f"{feed.key}.url.txt"
    assert snapshot.is_file(), f"Snapshot fehlt: {sorted(feed_root.rglob('*'))}"
    snapshot_text = snapshot.read_text(encoding="utf-8")
    assert "boese.example" not in snapshot_text, (
        "Klartext-URL im Feed-Snapshot: " + snapshot_text[:200]
    )
    assert "http" not in snapshot_text.lower()
    # The snapshot holds hashes (one 64-hex token per line, comments allowed).
    for line in snapshot_text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            assert len(line) == 64 and all(c in "0123456789abcdef" for c in line), line

    # Und der Zweck bleibt erfuellt: der Link wird gefunden.
    monkeypatch.setattr(url_reputation, "local_blocklist_path", lambda: ziel)
    hashlist._load_blocklist.cache_clear()
    treffer = url_reputation._lookup_local(["http://boese.example/malware.exe"])
    assert len(treffer) == 1, "der gestreamte Eintrag wirkt nicht"


def test_streaming_bricht_bei_zu_grossem_feed_ab(monkeypatch):
    """Die Groessengrenze gilt auch ohne Datei — sonst waere sie umgehbar."""
    from malaz.core import feeds

    monkeypatch.setattr(feeds, "MAX_FEED_BYTES", 1024)
    feed = next(f for f in feeds.FEEDS if f.kind == "url")
    monkeypatch.setattr(
        feeds.urllib.request,
        "urlopen",
        lambda *_a, **_k: _StueckAntwort(b"x" * 4096, stueck=512),
    )
    try:
        feeds.stream_feed(feed, lambda _z: None)
    except feeds.FeedError as exc:
        assert "groesser" in str(exc)
    else:
        raise AssertionError("die Groessengrenze griff nicht")


class _AbbrechendeAntwort:
    """Eine Antwort, die mitten im Strom abbricht (Verbindung weg)."""

    def __init__(self, teile: list[bytes]) -> None:
        self._teile = list(teile)
        self._i = 0

    def __enter__(self):
        return self

    def __exit__(self, *_a) -> bool:
        return False

    def read(self, n: int = -1) -> bytes:
        if self._i >= len(self._teile):
            raise ConnectionResetError("Verbindung wurde zurückgesetzt")
        teil = self._teile[self._i]
        self._i += 1
        return teil


def test_abgebrochene_verbindung_mitten_im_strom(monkeypatch, tmp_path):
    """Ein Abbruch nach der Haelfte darf keinen halben Import hinterlassen.

    GEMESSEN ist der Fall beim Anwender: die Liste der lebenden Schad-URLs
    wurde abgelegt und vom EDR blockiert. Der Streaming-Weg legt nichts ab —
    aber was passiert, wenn die Verbindung MITTEN im Strom abreisst? Die
    bereits gehashten Zeilen duerfen nicht als vollstaendiger Feed gelten:
    eine halbe Liste, die sich als ganze ausgibt, meldet Links als "nicht
    gefunden", die in der fehlenden Haelfte stehen.
    """
    from malaz import config
    from malaz.core import feed_import, feeds, hashlist

    ziel = tmp_path / "urls.sha256"
    ziel.write_text("", encoding="utf-8")
    monkeypatch.setattr(config, "URL_BLOCKLIST_FILE", ziel)
    monkeypatch.setattr(
        feeds.urllib.request,
        "urlopen",
        lambda *_a, **_k: _AbbrechendeAntwort(
            [b"http://a.example/1\n" * 50, b"http://b.example/2\n" * 50]
        ),
    )
    hashlist._load_blocklist.cache_clear()

    feed = next(f for f in feeds.FEEDS if f.kind == "url")
    with pytest.raises((ConnectionResetError, OSError, feeds.FeedError)):
        feed_import.refresh_feed(feed, tmp_path)

    # Der Kern: NICHTS wurde uebernommen. Ein halber Import waere schlimmer
    # als gar keiner — er sieht vollstaendig aus.
    assert hashlist.load_blocklist(ziel) == frozenset(), (
        "ein abgebrochener Abruf hat Einträge hinterlassen"
    )
    uebrig = [p.name for p in tmp_path.rglob("*") if p.is_file() and p != ziel]
    assert uebrig == [], f"Rohdatei(en) trotz Abbruch: {uebrig}"


def test_streaming_haelt_zeilen_ueber_stueckgrenzen_zusammen(monkeypatch):
    """Ein Stueck endet mitten in einer Zeile — sie darf nicht zerreissen.

    Die Antwort kommt in 64-KB-Stuecken; eine URL, die genau auf die Grenze
    faellt, wuerde sonst in zwei Haelften zerlegt und zweimal gehasht. Beide
    Hashes passen dann zu keiner echten URL.
    """
    from malaz.core import feeds

    # Zwei Zeilen, und die Stueckgrenze liegt MITTEN in der ersten.
    ganz = b"http://erste.example/pfad\nhttp://zweite.example/x\n"
    stuecke = [ganz[:12], ganz[12:]]

    class _Antwort:
        def __init__(self):
            self._i = 0

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def read(self, n=-1):
            if self._i >= len(stuecke):
                return b""
            teil = stuecke[self._i]
            self._i += 1
            return teil

    monkeypatch.setattr(feeds.urllib.request, "urlopen", lambda *_a, **_k: _Antwort())
    feed = next(f for f in feeds.FEEDS if f.kind == "url")
    gesehen: list[str] = []
    feeds.stream_feed(feed, gesehen.append)

    assert gesehen == [
        "http://erste.example/pfad",
        "http://zweite.example/x",
    ], f"Zeilen zerrissen: {gesehen}"
