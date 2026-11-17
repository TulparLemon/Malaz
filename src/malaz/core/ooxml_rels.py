"""Externe Beziehungen in OOXML-Containern finden (Remote Template Injection).

Warum das eine eigene Stufe braucht: eine ``.docx``/``.xlsx`` kann beim Öffnen
Inhalte von einem fremden Server nachladen — ganz **ohne Makro**. Word zieht
über ``word/_rels/settings.xml.rels`` eine ``attachedTemplate``-Beziehung mit
``TargetMode="External"``; Excel tut dasselbe über ``externalLink``-Beziehungen
in der Arbeitsmappe. Der Angriff heißt *Remote Template Injection*: Word lädt
die Vorlage vom Angreifer-Server und führt deren Makros aus, während die
gelieferte Datei selbst keinen einzigen Makro-Byte enthält. Jeder statische
Makro-Scanner sieht damit eine harmlose Datei.

Gelesen wird ausschließlich: es wird nichts entpackt, nichts ausgeführt und
keine Adresse kontaktiert (Malaz ist offline). Die Grenzen unten halten einen
präparierten Container davon ab, den Scan zu bremsen — die Zahl der
Beziehungen, die Länge eines Ziels und die Größe eines ``.rels``-Mitglieds
sind alle begrenzt. Geparst wird mit einem echten XML-Parser statt mit einem
Muster: ein handgeschriebener Attribut-Scanner übersieht gültiges XML
(einfache Anführungszeichen, Namensraum-Präfixe, Zeichenreferenzen) und macht
die Erkennung damit von der Schreibweise des Angreifers abhängig.
"""

from __future__ import annotations

import io
import re
import xml.etree.ElementTree as _stdlib_etree
import zipfile

try:  # defusedxml ist die gehärtete Variante (DTD/Entities verboten)
    from defusedxml import ElementTree as _etree
except Exception:  # pragma: no cover - optionale Härtung, Fallback unten
    _etree = _stdlib_etree
    _HARDENED_XML_PARSER = False
else:
    _HARDENED_XML_PARSER = True

# Harte Grenzen für angreiferkontrollierten Inhalt. 50 Beziehungen und 500
# Zeichen Ziel decken jeden realen Fall ab: ein Dokument mit mehr externen
# Verweisen ist kein Dokument mehr, sondern ein Angriffsversuch auf die
# Laufzeit des Scanners.
MAX_RELATIONSHIPS = 50
MAX_TARGET_CHARS = 500

# Ein ``.rels``-Mitglied ist in echten Dateien wenige Kilobyte groß. Die Grenze
# verhindert, dass ein als Beziehungsdatei getarntes Riesenmitglied den
# Speicher füllt (der Zip-Bomben-Schutz der Archivstufe greift hier nicht, weil
# diese Stufe direkt auf die Bytes schaut).
_MAX_REL_MEMBER_BYTES = 256 * 1024
# Obergrenze der gelesenen Beziehungsdateien: ein Dokument mit zehntausenden
# ``.rels``-Mitgliedern soll den Scan nicht in die Länge ziehen.
_MAX_REL_MEMBERS = 200

# Nur Ziele, die einen ANDEREN Rechner erreichen, gelten als externe
# Beziehung. UNC-Pfade (``\\host\share\x.dotm``) und ``file://host/...``
# werden von Office beim Öffnen per SMB/WebDAV geladen — der Rechner verlässt
# damit sehr wohl seinen eigenen Namensraum (NTLM-Leak, Remote Template). Die
# frühere reine ``https?://``-Prüfung meldete dafür nichts (Audit SEC-014).
# ``file:///C:/lokal`` (leerer Host) bleibt bewusst außen vor: das ist eine
# lokale Datei.
_EXTERNAL_TARGET = re.compile(
    r"^(?:https?://|file://[^/\\]|[/\\]{2}[^/\\])", re.IGNORECASE
)

# Beziehungsdateien, die eine Fernladung tragen können, werden VOR dem
# Mitglieder-Deckel gelesen (Audit SEC-015): 200 Dummy-``.rels`` vor
# ``word/_rels/settings.xml.rels`` versteckten die attachedTemplate-Beziehung.
# Rang 0: die dokumentweiten Tabellen; Rang 1: jede Tabelle eines Hauptteils
# direkt unter word/, xl/, ppt/; Rang 2: alles Verschachtelte. Innerhalb eines
# Rangs bleibt die Zip-Reihenfolge (stabiler Sort).
_RELEVANT_REL_MEMBERS = frozenset(
    {
        "_rels/.rels",
        "word/_rels/document.xml.rels",
        "word/_rels/settings.xml.rels",
        "xl/_rels/workbook.xml.rels",
        "ppt/_rels/presentation.xml.rels",
    }
)


def _rel_member_priority(name: str) -> int:
    """0 = dokumentweit, 1 = Hauptteil-Tabelle, 2 = verschachtelt."""
    lowered = name.lower().lstrip("/")
    if lowered in _RELEVANT_REL_MEMBERS:
        return 0
    parts = lowered.split("/")
    if len(parts) == 3 and parts[0] in ("word", "xl", "ppt") and parts[1] == "_rels":
        return 1
    return 2

# Der stdlib-Parser würde interne Entities expandieren (Billion Laughs); ein
# ``.rels`` mit DTD ist kein gültiges OPC-Paket. Nur der Fallback braucht die
# Vorprüfung — defusedxml lehnt DTD und Entities von sich aus ab.
_DOCTYPE_OR_ENTITY = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)


def _local_name(name: str) -> str:
    """``{namespace}Relationship`` -> ``Relationship`` (auch ohne Präfix)."""
    return name.rsplit("}", 1)[-1]


def _relationships_in(raw: bytes) -> list[tuple[str, str]]:
    """Alle externen ``(typ, ziel)``-Paare aus einer ``.rels``-Datei.

    ``typ`` ist der letzte Abschnitt der Beziehungs-URL
    (``…/relationships/attachedTemplate`` -> ``attachedTemplate``), weil genau
    dieser Name die Mechanik benennt. Nur Beziehungen mit
    ``TargetMode="External"`` **und** einem entfernten Ziel (``http(s)``,
    ``file://host``, UNC) zählen: eine interne Beziehung
    (``Target="media/image1.png"``) lädt nichts nach.

    Geparst wird echtes XML: einfache wie doppelte Anführungszeichen,
    Namensraum-Präfixe (``<r:Relationship>``), Zeichenreferenzen (``&#104;``)
    und beliebig lange Tags sind damit gültige Eingaben. Die Bytes (nicht der
    dekodierte Text) gehen an den Parser, damit eine XML-Deklaration mit
    anderer Kodierung respektiert wird; die Größe ist bereits durch
    ``_MAX_REL_MEMBER_BYTES`` begrenzt.
    """
    if not _HARDENED_XML_PARSER:
        # Die DTD-Prüfung muss die Kodierung sehen, die expat sieht: eine
        # UTF-16-Datei (BOM) sonst an der UTF-8-Dekodierung vorbei.
        if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            dtd_check = raw.decode("utf-16", errors="replace")
        else:
            dtd_check = raw.decode("utf-8", errors="replace")
        if _DOCTYPE_OR_ENTITY.search(dtd_check):
            return []
    try:
        root = _etree.fromstring(raw)
    except Exception:
        # Kein wohlgeformtes XML: nicht prüfbar. Die Container-Stufe meldet ein
        # defektes Paket, hier gibt es keinen Fund zu behaupten.
        return []
    found: list[tuple[str, str]] = []
    for element in root.iter():
        # Präfixe löst der Parser in einen Namensraum auf; verglichen wird der
        # lokale Name (case-insensitiv wie zuvor das Muster).
        if _local_name(element.tag).lower() != "relationship":
            continue
        attrs = {
            _local_name(key).lower(): value for key, value in element.attrib.items()
        }
        if attrs.get("targetmode", "").lower() != "external":
            continue
        target = attrs.get("target", "")
        if not _EXTERNAL_TARGET.match(target):
            continue
        typ = attrs.get("type", "").rstrip("/").rsplit("/", 1)[-1]
        found.append((typ or "external", target[:MAX_TARGET_CHARS]))
    return found


def external_relationships(
    data: bytes, notes: list[str] | None = None
) -> list[tuple[str, str]]:
    """Externe Beziehungen eines OOXML-Containers als ``(typ, ziel)``-Liste.

    Untersucht werden alle ``.rels``-Mitglieder des Zip-Containers — das sind
    die vom Format vorgesehenen Beziehungstabellen (``_rels/.rels``,
    ``word/_rels/document.xml.rels``, ``word/_rels/settings.xml.rels``,
    ``xl/_rels/workbook.xml.rels`` und die ``ppt/``-Gegenstücke). Statt eine
    feste Namensliste zu pflegen, die beim nächsten Formatzusatz veraltet, wird
    generisch nach der Endung gesucht.

    Reihenfolge bleibt erhalten, Doppelte werden entfernt, das Ergebnis ist auf
    :data:`MAX_RELATIONSHIPS` Einträge begrenzt. Ein Container, der kein
    lesbares Zip ist, liefert eine leere Liste — „nicht lesbar" meldet die
    Container-Stufe des Scans, nicht diese Funktion.

    ``notes`` (optional) sammelt sichtbare Hinweise für den Aufrufer. Wird der
    :data:`_MAX_REL_MEMBERS`-Deckel erreicht, steht dort, dass weitere
    Beziehungsdateien NICHT gelesen wurden — statt still abzuschneiden.
    """
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        return []

    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    try:
        with archive:
            # Wichtige Tabellen zuerst; der Deckel soll nie eine
            # attachedTemplate-Datei hinter lauter Attrappen verstecken.
            members = sorted(
                (
                    info
                    for info in archive.infolist()
                    if info.filename.lower().endswith(".rels")
                ),
                key=lambda info: _rel_member_priority(info.filename),
            )
            if len(members) > _MAX_REL_MEMBERS and notes is not None:
                notes.append(
                    f"Der Container enthält {len(members)} Beziehungsdateien "
                    f"(.rels); nur {_MAX_REL_MEMBERS} wurden gelesen (die "
                    "dokumentweiten zuerst). Weitere externe Verweise können "
                    "unentdeckt sein."
                )
            for info in members[:_MAX_REL_MEMBERS]:
                if info.file_size > _MAX_REL_MEMBER_BYTES:
                    continue
                try:
                    with archive.open(info) as handle:
                        raw = handle.read(_MAX_REL_MEMBER_BYTES)
                except Exception:
                    continue
                for pair in _relationships_in(raw):
                    if pair in seen:
                        continue
                    seen.add(pair)
                    out.append(pair)
                    if len(out) >= MAX_RELATIONSHIPS:
                        return out
    except Exception:
        # Ein defekter Zip-Zentralverzeichnis-Rest soll die Stufe nicht
        # sprengen; was bis hierher gefunden wurde, bleibt gültig.
        return out
    return out
