"""Log-Datei ohne Dateinamen: Anonymisierung an der Senke.

WARUM DIESE DATEI EXISTIERT
===========================
Malaz schreibt nach ``malaz.log``, und die Logdatei ist die Datei, die ein
Nutzer bei einem Problem weitergibt — an den Support, an die IT, in ein Forum.
Darin standen bisher die **vollstaendigen Pfade** jeder gepruefte Datei:

    INFO malaz.core.dispatcher: scanning C:\\Users\\Alex\\Steuer\\Scheidung 2026.pdf

Das ist der Inhalt eines fremden Rechners. Ein Log, das man weitergeben kann,
darf die Dateinamen des Nutzers nicht enthalten — sonst gibt er mit dem Log
auch preis, welche Dokumente er hat.

WAS STATTDESSEN IM LOG STEHT
============================
Ein stabiler Kurzname: ``<datei:3f2a1b9c.pdf>``. Die Endung bleibt (sie ist
fuer die Diagnose nuetzlich — "PDF" oder "EXE" entscheidet ueber den Pfad), der
Rest ist eine Pruefsumme. Zwei Eigenschaften, die zaehlen:

* **Stabil**: dieselbe Datei bekommt in jeder Zeile denselben Namen. Ohne das
  liesse sich ein Ablauf nicht mehr nachvollziehen.
* **Nicht umkehrbar**: aus der Pruefsumme laesst sich der Name nicht
  zurueckrechnen. Wer den Namen schon kennt, kann sie nachrechnen — das ist
  gewollt, es erlaubt die Zuordnung im konkreten Fall.

WARUM AN DER SENKE
==================
Als Filter am Datei-Handler, nicht an den Aufrufstellen. Das Projekt hat diese
Regel schon einmal gelernt: eine Maskierung pro Aufrufstelle deckte genau die
Felder ab, an die jemand gedacht hat, und verfehlte den Rest. Ein neuer Logger
waere sonst wieder eine neue Luecke.

Die KONSOLE bleibt unveraendert: sie ist der Bildschirm des Nutzers, und dort
ist der vollstaendige Pfad die hilfreiche Angabe.
"""

from __future__ import annotations

import hashlib
import logging
import re

# Windows-Pfade (``C:\...``, ``\\server\...``) und POSIX-Pfade (``/...``).
# Begrenzte Quantoren: die Zeichenkette kommt aus dem Programm, ist aber nicht
# die einzige Quelle — ein Dateiname kann in einer Fremdausgabe stecken.
# Ein Pfadsegment: alles ausser Trenner und den unter Windows verbotenen
# Zeichen. Das Anfuehrungszeichen ist ausgenommen, weil es in Log-Zeilen das
# Ende eines zitierten Pfades markiert.
_SEG = r"[^\\/:*?<>|\r\n\"]"

# ``C:\...`` (Laufwerk) oder ``\\server\freigabe\...`` (UNC). Der
# Quantor auf die Tiefe ist begrenzt: ein Log-Eintrag ist keine beliebig lange
# Kette, und eine unbeschraenkte Wiederholung waere auf Fremdausgabe quadratisch.
_WINDOWS_PATH = re.compile(
    rf"(?:[A-Za-z]:\\(?:{_SEG}{{1,255}}\\){{0,32}}{_SEG}{{1,255}}"
    rf"|\\\\{_SEG}{{1,255}}\\(?:{_SEG}{{1,255}}\\){{0,32}}{_SEG}{{1,255}})"
)
_POSIX_PATH = re.compile(r"/(?:[\w.\-]{1,255}/){1,32}[\w.\-]{1,255}")
_WINDOWS_SLASH_PATH = re.compile(
    rf"[A-Za-z]:/(?:{_SEG}{{1,255}}/){{0,32}}{_SEG}{{1,255}}"
)
_EMAIL = re.compile(
    r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"
)

# File extensions that identify a user file without any path separator. A
# curated set, not "anything with a dot": module names in tracebacks
# (``zipfile.BadZipFile``), version numbers and host names must stay readable —
# masking every dotted token destroyed exactly the diagnostic that the log
# exists for. The set covers the formats this project scans and the usual
# attachments/archives/scripts; anything else keeps its name (residual risk is
# documented in the audit report).
_FILE_EXTENSIONS = frozenset(
    {
        # Dokumente
        "pdf", "doc", "docx", "docm", "dot", "dotm", "xls", "xlsx", "xlsm",
        "xlsb", "xltm", "xlam", "sldm", "ppt", "pptx", "pptm", "potm", "ppsm",
        "hwp", "rtf", "odt", "ods", "odp", "msg", "eml", "mbox",
        # Text/Daten
        "txt", "csv", "tsv", "json", "xml", "yaml", "yml", "ini", "log",
        "html", "htm", "md", "sqlite", "db",
        # Archive/Images
        "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "cab", "iso", "img",
        "jar", "apk", "png", "jpg", "jpeg", "gif", "bmp", "svg", "heic",
        "avif", "webp", "swf",
        # Ausführbar/Skript
        "exe", "scr", "com", "pif", "msi", "dll", "cpl", "reg", "xll",
        "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf", "wsh", "ps1",
        "psm1", "hta", "lnk", "py", "sh",
    }
)
_BARE_FILE = re.compile(
    r"(?<![\w:/\\<>@])(?P<name>[\w.+-]{1,255}\.[A-Za-z][A-Za-z0-9]{0,11})(?![\w.])"
)

# C0 controls (except TAB and LF, which the formatter needs for tracebacks)
# plus DEL/C1. ESC is the vector for ANSI escape sequences; CR can overwrite a
# rendered line. Replaced by their visible ``\xNN`` spelling.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _visible_control(match: re.Match[str]) -> str:
    return f"\\x{ord(match.group(0)):02x}"


def _bare_file(match: re.Match[str]) -> str:
    name = match.group("name")
    extension = name.rsplit(".", 1)[-1].lower()
    if extension not in _FILE_EXTENSIONS:
        return name
    return _token(name)


def _token(path: str) -> str:
    """``<datei:3f2a1b9c.pdf>`` — stabil, nicht umkehrbar, mit Endung."""
    name = path.replace("\\", "/").rsplit("/", 1)[-1]
    endung = ""
    if "." in name[1:]:
        roh = name.rsplit(".", 1)[-1]
        # SEC-004: the extension comes from an attacker-controlled member
        # name. ``evil.pdf\nINFO SCAN CLEAN`` kept the newline and produced two
        # physical log lines. Only a plain alphanumeric prefix survives; the
        # rest of the token (newline/ANSI/…) is never emitted.
        prefix = re.match(r"[A-Za-z0-9]{1,12}", roh)
        if prefix is not None:
            endung = "." + prefix.group(0)
    kuerzel = hashlib.sha256(path.encode("utf-8", "replace")).hexdigest()[:8]
    return f"<datei:{kuerzel}{endung}>"


def _email_token(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:8]
    return f"<email:{digest}>"


def anonymize(text: str, *, multiline: bool = False) -> str:
    """Redact local paths, bare file names and email identities.

    ``multiline`` is for the formatter's final line only: a traceback is
    legitimately multi-line and keeps its newlines. Everywhere else (log
    arguments, messages) a newline would forge an additional physical line and
    is escaped. Control characters (ESC/ANSI, CR, NUL, …) are always made
    visible — SEC-040.
    """
    if not text:
        return text
    text = _WINDOWS_PATH.sub(lambda m: _token(m.group(0)), text)
    text = _WINDOWS_SLASH_PATH.sub(lambda m: _token(m.group(0)), text)
    text = _POSIX_PATH.sub(lambda m: _token(m.group(0)), text)
    text = _EMAIL.sub(lambda m: _email_token(m.group(0)), text)
    text = _BARE_FILE.sub(_bare_file, text)
    text = _CONTROL.sub(_visible_control, text)
    if not multiline:
        text = text.replace("\n", "\\n")
    return text


def anonymize_name(value: object) -> str:
    """Hash an explicit display/member name even when no path separator exists."""
    return _token(str(value))


def _anonymize_arg(value: object) -> object:
    """Ein Log-Argument anonymisieren — NUR wenn es Text ist.

    Vorher wurde jedes Argument mit ``str()`` belegt. Das bricht jede
    Formatierung mit einem Zahl-Platzhalter: ``log.info("%d Dateien", 3)``
    scheiterte danach mit "TypeError: %d format: a real number is required, not
    str" — und zwar im Log-Pfad, also genau dann, wenn etwas schiefgeht.
    Gemessen: vier Tests in tests/test_import_blocklist.py wurden dadurch rot.

    Zahlen, Wahrheitswerte und alles Nicht-Textliche bleiben deshalb
    unangetastet. Nur wo ein Pfad stehen kann — Text — wird ersetzt.
    """
    if isinstance(value, str):
        return anonymize(value)
    return value


class AnonymizeFormatter(logging.Formatter):
    """Anonymize the final formatted line, including traceback text."""

    def format(self, record: logging.LogRecord) -> str:
        # Tracebacks are legitimately multi-line; only argument/message line
        # breaks (already escaped by the filter) must not forge log lines.
        return anonymize(super().format(record), multiline=True)


class AnonymizeFilter(logging.Filter):
    """Setzt die Anonymisierung auf jeden Datensatz — auch auf Argumente.

    ``record.msg`` allein genuegt nicht: ``log.info("scan %s", path)`` legt den
    Pfad in ``record.args`` ab. Beide muessen durch, sonst bleibt genau die
    Schreibweise unmaskiert, die dieses Projekt am haeufigsten benutzt.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = anonymize(str(record.msg))
            if record.args:
                if isinstance(record.args, dict):
                    record.args = {
                        key: _anonymize_arg(value)
                        for key, value in record.args.items()
                    }
                else:
                    record.args = tuple(_anonymize_arg(value) for value in record.args)
        except Exception:
            # Ein Filter darf den Programmablauf nie anhalten. Im Zweifel
            # bleibt die Zeile unmaskiert — das ist besser als ein Absturz
            # mitten im Scan.
            return True
        return True
