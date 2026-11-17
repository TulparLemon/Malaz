
from malaz.security.safe_extract import (
    ATTACK_REASONS,
    REASON_TRAVERSAL,
    is_safe_member_name,
    unsafe_name_reason,
)


def test_safe_names():
    assert is_safe_member_name("file.txt")
    assert is_safe_member_name("dir/file.txt")
    assert is_safe_member_name("a/b/c.bin")


def test_traversal_rejected():
    assert not is_safe_member_name("../evil.txt")
    assert not is_safe_member_name("..\\evil.txt")
    assert not is_safe_member_name("a/../../evil.txt")
    assert not is_safe_member_name("a\\..\\..\\evil.txt")


def test_absolute_and_drive_rejected():
    assert not is_safe_member_name("/etc/passwd")
    assert not is_safe_member_name("C:/Windows/evil.dll")
    assert not is_safe_member_name("\\\\server\\share")
    assert not is_safe_member_name("")




def test_console_device_aliases_rejected():
    # Regression (Hunt 1.1): CONIN$/CONOUT$ sind echte Windows-Device-Aliase
    # (Konsolen-Buffer) — Extract wuerde haengen statt eine Datei schreiben.
    assert not is_safe_member_name("CONIN$")
    assert not is_safe_member_name("conout$.txt")
    assert not is_safe_member_name("ordner/CONIN$")


# -- Der GRUND der Ablehnung ------------------------------------------------- #
#
# Der Pruefer lehnt zweierlei ab: echte Pfad-Escapes und Namen, die beim
# Entpacken unter Windows Aerger machen. Beides als "Zip-Slip-Versuch" zu
# melden ist falsch — gemessen ergab ein Zip mit NUR "CON.txt" ROT 50
# "Zip-Slip-Versuch (1 Eintraege)", obwohl darin kein Traversal steckt.

_ANGRIFFE = [
    "..\\..\\evil.dll",
    "..\\..\\..\\Windows\\System32\\evil.dll",
    "/etc/passwd",
    "C:/Windows/x.dll",
    "\\\\server\\share\\x.dll",
    "..",
    "ordner/..",
    "a/../../b.txt",
    # Verschleiert: Windows strippt abschliessende Leerzeichen, ".. " wird zu
    # ".." und ist dann der Aufwaerts-Verweis. Die erste Fassung meiner
    # Einordnung hielt das faelschlich fuer harmlos.
    "a/.. /evil.dll",
    ". .",
]

_MILDE = [
    "CON.txt",
    "aux.log",
    "NUL",
    "com1.dat",
    "normal:stream.txt",
    "...",
    "..foo.txt",
    "a/...",
]


def test_traversal_wird_als_angriff_erkannt():
    for name in _ANGRIFFE:
        assert unsafe_name_reason(name) == REASON_TRAVERSAL, name
        assert unsafe_name_reason(name) in ATTACK_REASONS, name


def test_ungewoehnliche_namen_sind_kein_angriff():
    """Genau der Fall des Nutzers: "uebertrieben".

    Ein reservierter Geraetename oder ein Doppelpunkt ist unter Unix ein
    gueltiger Dateiname — solche Archive entstehen auch ohne Absicht. Der
    Name bleibt abgelehnt (unveraendert), aber er darf keinen Angriff
    behaupten.
    """
    for name in _MILDE:
        grund = unsafe_name_reason(name)
        assert grund is not None, f"{name} muss weiter abgelehnt werden"
        assert grund not in ATTACK_REASONS, f"{name} ist kein Angriff"


def test_harmlose_namen_haben_keinen_grund():
    for name in ("harmlos.txt", "ordner/datei.txt", "meine datei.txt", "a/./b.txt"):
        assert unsafe_name_reason(name) is None, name
        assert is_safe_member_name(name) is True, name


def test_ablehnung_und_grund_widersprechen_sich_nie():
    """``is_safe_member_name`` muss genau ``reason is None`` sein.

    Die 34 Aufrufer im Baum kennen nur das Bool; wenn beide auseinanderliefen,
    wuerde mal das eine und mal das andere entschieden.
    """
    proben = _ANGRIFFE + _MILDE + ["harmlos.txt", "", "  ", "a/b.txt", "x"]
    for name in proben:
        assert is_safe_member_name(name) is (unsafe_name_reason(name) is None), name


def test_jeder_milde_grund_wird_korrekt_benannt():
    """Der Grund steht im Befund — er muss stimmen.

    Dieselbe Falle wie eine Ebene hoeher: erst hiess jeder milde Fall
    "Zip-Slip-Versuch", dann hiess jeder milde Fall "reservierter
    Geraetename" — auch "..." und "..foo.txt". Beides behauptet etwas, das
    nicht dasteht. Ein Pruefer, der bei "..." von einem Windows-Geraetenamen
    spricht, wird bei "CON" auch nicht mehr ernst genommen.
    """
    from malaz.security.safe_extract import (
        REASON_ADS,
        REASON_DEVICE,
        REASON_DOTNAME,
        REASON_EMPTY,
    )

    assert unsafe_name_reason("CON.txt") == REASON_DEVICE
    assert unsafe_name_reason("aux.log") == REASON_DEVICE
    assert unsafe_name_reason("NUL") == REASON_DEVICE
    assert unsafe_name_reason("normal:stream.txt") == REASON_ADS
    assert unsafe_name_reason("...") == REASON_DOTNAME
    assert unsafe_name_reason("..foo.txt") == REASON_DOTNAME
    assert unsafe_name_reason("a/...") == REASON_EMPTY


def test_die_meldung_nennt_nur_zutreffende_gruende():
    """Und der TEXT, den der Nutzer liest, darf nichts anderes behaupten."""
    from malaz.core.archive import unsafe_name_note

    text = unsafe_name_note(["...", "..foo.txt"]) or ""
    assert "zwei Punkten" in text, text
    assert "Geraetenamen" not in text, f"falsches Etikett: {text}"

    text = unsafe_name_note(["CON.txt"]) or ""
    assert "Geraetenamen" in text, text
    assert "zwei Punkten" not in text, text
