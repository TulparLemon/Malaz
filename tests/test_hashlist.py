
from pathlib import Path

from malaz.core.hashlist import is_listed, load_blocklist

VALID = "a" * 64
VALID_UPPER = "A" * 64


def _write(tmp_path, text):
    p = tmp_path / "bl.sha256"
    p.write_text(text, encoding="utf-8")
    return p


def test_loads_and_normalises_case(tmp_path):
    p = _write(tmp_path, f"# header\n\n{VALID_UPPER}  some note\n  {VALID}  \n")
    bl = load_blocklist(p)
    assert len(bl) == 1  # upper + same-as-lower dedupe to one
    assert VALID in bl


def test_ignores_invalid_lines(tmp_path):
    p = _write(tmp_path, "notahash\nzzzz\n" + VALID + "\n")
    bl = load_blocklist(p)
    assert len(bl) == 1


def test_is_listed(tmp_path):
    p = _write(tmp_path, VALID + "\n")
    assert is_listed(VALID, p)
    assert is_listed(VALID.upper(), p)  # case-insensitive lookup
    assert not is_listed("0" * 64, p)
    assert not is_listed("", p)


def test_missing_file_is_empty(tmp_path):
    p = tmp_path / "does_not_exist.sha256"
    assert load_blocklist(p) == frozenset()
    assert not is_listed(VALID, p)


def test_unlesbare_liste_vergiert_den_cache_nicht(tmp_path, monkeypatch):
    """Ein transienter Lesefehler darf die Liste nicht dauerhaft leeren.

    Der Fall ist gemessen, nicht erfunden: ``os.replace``
    (``core/atomicwrite``) hat auf Windows einen kurzen Moment, in dem ein
    gleichzeitiges Oeffnen der Zieldatei mit ``WinError 5`` scheitert. Laege
    das als leere Menge im ``lru_cache``, bliebe die importierte Liste fuer
    den REST DES PROZESSES leer — und ein fehlender Treffer sieht aus wie
    eine saubere Datei.
    """
    from malaz.core import hashlist

    ziel = tmp_path / "blocklist.sha256"
    ziel.write_text("a" * 64 + "\n", encoding="utf-8")

    # Erster Versuch scheitert (wie im Wettlauf), danach geht es wieder.
    echtes_read_text = Path.read_text
    aufrufe = {"n": 0}

    def wackelig(self, *args, **kwargs):
        if self == ziel and aufrufe["n"] == 0:
            aufrufe["n"] += 1
            raise PermissionError(13, "Zugriff verweigert (simuliert)")
        return echtes_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", wackelig)
    hashlist._load_blocklist.cache_clear()

    assert hashlist.load_blocklist(ziel) == frozenset(), "Vertrag: unlesbar = leer"
    # Und jetzt muss der NAECHSTE Aufruf die echte Liste sehen.
    gefunden = hashlist.load_blocklist(ziel)
    assert gefunden == frozenset({"a" * 64}), (
        "der Lesefehler wurde zwischengespeichert — die Liste bliebe leer"
    )


def test_is_listed_ueberlebt_eine_unlesbare_liste(tmp_path, monkeypatch):
    """``is_listed`` laeuft EINMAL JE GESCANTER DATEI — es darf nicht werfen.

    ``_load_blocklist`` wirft bei einer vorhandenen, aber unlesbaren Datei
    (``_UnreadableError``), damit der Fehlschlag nicht im ``lru_cache``
    landet. Genau deshalb duerfen ``is_listed`` und ``matched_source`` NICHT
    direkt darauf zugreifen: der transiente ``WinError 5`` aus dem atomaren
    Ersetzen wuerde sonst aus der Hash-Stufe herausfliegen und den Scan
    abbrechen, statt wie zugesagt "unlesbar = trifft nie" zu ergeben.

    Ein Test, der nur ``load_blocklist`` prueft, faengt das NICHT — der Pfad
    ist ein anderer.
    """
    from malaz.core import hashlist

    ziel = tmp_path / "blocklist.sha256"
    ziel.write_text(VALID + "\n", encoding="utf-8")
    hashlist._load_blocklist.cache_clear()

    # Wenn die Liste unlesbar wird, darf nichts fliegen.
    echtes_read_text = Path.read_text

    def kaputt(self, *args, **kwargs):
        if self == ziel:
            raise PermissionError(13, "Zugriff verweigert (simuliert)")
        return echtes_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", kaputt)
    assert hashlist.is_listed(VALID, ziel) is False, "Vertrag: unlesbar = trifft nie"
    assert hashlist.load_blocklist(ziel) == frozenset()

    # BEIDE Zweige, nicht nur den mit Pfad: der Scanner ruft `is_listed` OHNE
    # Pfad auf, und dort laeuft die Schleife ueber die konfigurierten Listen.
    # Ein Test nur auf dem Pfad-Zweig hat eine Mutation im anderen Zweig
    # durchgelassen — gemessen.
    from malaz import config

    monkeypatch.setattr(config, "HASH_BLOCKLIST_FILE", ziel)
    monkeypatch.setattr(config, "USER_HASH_BLOCKLIST_FILE", tmp_path / "gibtsnicht")
    hashlist._load_blocklist.cache_clear()
    assert hashlist.is_listed(VALID) is False, "unlesbar = trifft nie (ohne Pfad)"
    assert hashlist.matched_source(VALID) == ""

    # Und wieder lesbar: der Treffer muss zurueckkommen (nichts blieb haengen).
    monkeypatch.undo()
    hashlist._load_blocklist.cache_clear()
    assert hashlist.is_listed(VALID, ziel) is True


def test_status_reports_later_unreadable_list_after_a_hit(tmp_path, monkeypatch):
    from malaz import config
    from malaz.core import hashlist
    first = tmp_path / "first.sha256"
    first.write_text(VALID + "\n", encoding="utf-8")
    second = tmp_path / "second.sha256"
    second.mkdir()
    monkeypatch.setattr(config, "HASH_BLOCKLIST_FILE", first)
    monkeypatch.setattr(config, "USER_HASH_BLOCKLIST_FILE", second)
    hashlist._load_blocklist.cache_clear()

    found, errors = hashlist.is_listed_with_status(VALID)

    assert found is True
    assert errors, "ein Lesefehler nach dem Treffer darf nicht verschwinden"
