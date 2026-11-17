"""SPF und DMARC über DNS prüfen — **Opt-in**, Vorgabe aus.

Warum das hier steht und nicht in ``eml_analysis``
==================================================
Alles andere an der Mail-Analyse ist rein lokal. Diese Datei ist der EINZIGE
Weg, auf dem Malaz von sich aus eine Frage an das Netz stellt, und deshalb
steht sie getrennt, mit eigenem Schalter und eigener Begründung.

Was sie beantwortet
===================
Die Frage, die die Mail-Analyse bisher offenlassen musste: *ist die IP, mit
der sich der Absender verbunden hat, für diese Absenderdomain überhaupt
erlaubt?* Ohne DNS ist die Antwort „nicht beurteilbar" — und eine gefälschte
Mail sieht dann aus wie eine ehrliche mit fehlender Authentifizierung.

Der Preis — und er ist ein Urteilsrisiko, nicht nur Angriffsfläche
=================================================================
**Ein gefälschter DNS-Eintrag macht aus einer ehrlichen Lücke eine gelogene
Bestätigung.** Ohne DNS steht „nicht geprüft"; mit DNS steht dann „geprüft,
gültig" — und der Nutzer verlässt sich darauf. Dazu sieht der Resolver,
welche Domains analysiert werden.

Deshalb:
* **System-Resolver** (``Resolve-DnsName``), kein neuer Dritter. Die
  Firmen-DNS sieht diese Abfragen ohnehin, weil sie jede andere Auflösung
  auch sieht; ein fremder Resolver (1.1.1.1 & Co.) wäre ein NEUER Empfänger.
* **Opt-in**, Vorgabe aus (``config.DNS_AUTH_ENABLED``).
* **Ein fehlgeschlagener Abruf ist „unbekannt", nie „sauber".** Das ist
  derselbe Grundsatz wie bei den nicht gelaufenen Stufen: was wir nicht
  geprüft haben, darf nicht wie geprüft aussehen.
* **DNSSEC wird NICHT geprüft.** Es steht keine Bibliothek dafür zur
  Verfügung; die Aussage „DNSSEC gültig" wäre hier nicht gedeckt. Was
  gedeckt ist, steht im Bericht: ob ein Eintrag existiert und was er sagt.
  Validiert der Firmen-Resolver DNSSEC, fällt eine Fälschung bei ihm durch —
  das ist seine Zusage, nicht unsere.

Was NICHT geprüft wird
======================
**Die DKIM-Signatur wird nicht verifiziert.** Das verlangt Kanonisierung,
Header-Hashing und RSA/Ed25519 über den rohen Nachrichtenkörper — ohne
``dkimpy`` nicht seriös zu bauen, und eine halbe Prüfung wäre schlimmer als
keine.

Geprüft wird stattdessen die **Schlüsselveröffentlichung**: ``check_dkim``
fragt ``<selektor>._domainkey.<domain>`` ab. Drei Ausgänge, und der
Unterschied ist wichtig:

* Eintrag mit gefülltem ``p=`` — der Schlüssel ist veröffentlicht.
* Eintrag mit **leerem** ``p=`` — der Schlüssel ist **widerrufen**. Das ist
  ein Befund, kein "alles in Ordnung": GEMESSEN an gmail.com liefern die
  Selektoren 20230601 und 20210112 genau das (mit ``nslookup`` bestätigt,
  also nicht der Resolver).
* Kein Eintrag — der Selektor ist nicht veröffentlicht.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from ..procio import decode_tool_output, run_tool, tool_output_truncated

log = logging.getLogger(__name__)

# Die Abfrage läuft über den System-Resolver. Kein -Server-Schalter: was die
# Maschine ohnehin fragt, ist die einzige Adresse, die keinen NEUEN Empfänger
# einführt.
# Die Abfrage meldet IMMER ein JSON-Objekt: entweder die Eintraege oder den
# Win32-Fehlercode. Der Code ist noetig, weil die Fehlermeldung uebersetzt ist
# ("Der DNS-Name ist nicht vorhanden") und ein Textvergleich auf jeder anderen
# Windows-Sprache bricht.
#
# VERKETTEN, NICHT ABFLACHEN. Ein TXT-Record darf laenger als 255 Byte sein
# und wird dann in mehrere Character-Strings zerlegt, die zusammen EINEN
# Record ergeben. ``Select-Object -ExpandProperty Strings`` machte daraus
# mehrere Listeneintraege — der Aufrufer sah nur das erste Bruchstueck.
#
# GEMESSEN: s1._domainkey.github.com liefert 2 Strings mit zusammen 406
# Zeichen; ``check_dkim`` meldete daraus "kein Schluessel veroeffentlicht" fuer
# einen LEBENDEN Schluessel. Der einzige vorher gepruefte Fall
# (selector1@outlook.com, 251 Zeichen) lag knapp unter der Grenze und konnte
# den Fehler nicht zeigen.
#
# ``-join ''`` pro Record, nicht ueber alle: eine Domain kann MEHRERE
# TXT-Records haben (SPF, Verifikationen), und die duerfen nicht verschmelzen.
_PS_LOOKUP = (
    "$ErrorActionPreference='Stop';"
    "try {{"
    "  $r = Resolve-DnsName -Name '{name}' -Type TXT -DnsOnly -ErrorAction Stop;"
    # Die Strings bleiben PRO RECORD verschachtelt — verkettet wird in
    # Python. WARUM NICHT HIER: eine Verkettung in PowerShell ist nur ueber
    # einen echten Netzaufruf pruefbar, und genau dieser Fehler (ein
    # zerlegter TXT-Record kommt als Bruchstueck an) blieb damit unentdeckt.
    # In Python ist er eine Zusicherung.
    "  $t = @($r | Where-Object {{ $_.Strings }} | "
    "ForEach-Object {{ ,@($_.Strings) }});"
    "  @{{ ok = $true; records = $t }} | ConvertTo-Json -Compress"
    "}} catch {{"
    "  @{{ ok = $false; code = $_.Exception.NativeErrorCode }} | "
    "ConvertTo-Json -Compress"
    "}}"
)

# DNS_ERROR_RCODE_NAME_ERROR (NXDOMAIN). Der Name existiert nicht — das ist
# eine ANTWORT, kein Ausfall: "diese Domain hat keinen SPF-Eintrag" ist eine
# Aussage ueber die Domain und gehoert gemeldet, nicht als "Pruefung nicht
# moeglich" versteckt.
_DNS_NAME_ERROR = 9003

_TIMEOUT_SECONDS = 8


@dataclass
class SpfResult:
    """Was eine SPF-Abfrage ergeben hat."""

    ran: bool = False
    record: str = ""
    ip_allowed: bool | None = None  # None = nicht beurteilbar (include/redirect)
    detail: str = ""
    error: str = ""

    @property
    def verdict(self) -> str:
        if self.error:
            return "unbekannt"
        if not self.ran:
            return "nicht geprüft"
        if not self.record:
            return "kein SPF-Eintrag"
        if self.ip_allowed is None:
            return "nicht beurteilbar"
        return "IP erlaubt" if self.ip_allowed else "IP NICHT erlaubt"


@dataclass
class DmarcResult:
    """Was eine DMARC-Abfrage ergeben hat."""

    ran: bool = False
    record: str = ""
    policy: str = ""  # none | quarantine | reject
    error: str = ""

    @property
    def verdict(self) -> str:
        if self.error:
            return "unbekannt"
        if not self.ran:
            return "nicht geprüft"
        if not self.record:
            return "kein DMARC-Eintrag"
        return f"Richtlinie {self.policy or '?'}"


@dataclass
class DkimResult:
    """Was eine DKIM-Schluesselabfrage ergeben hat.

    Geprueft wird NUR, ob der Schluessel des Selektors veroeffentlicht ist —
    nicht die Signatur. Das ist bewusst: die Signatur zu pruefen verlangt
    Kanonisierung, Header-Hashing und RSA/Ed25519 ueber den rohen
    Nachrichtenkorper. Ohne ``dkimpy`` waere das eine halbe Pruefung, und die
    ist schlimmer als keine: sie sagt "geprueft" und meint es nicht.
    """

    ran: bool = False
    selector: str = ""
    record: str = ""
    revoked: bool = False
    error: str = ""

    @property
    def verdict(self) -> str:
        if not self.selector:
            return "kein Selektor in der Signatur"
        if self.error:
            return "unbekannt"
        if not self.ran:
            return "nicht geprüft"
        if not self.record:
            return "kein Schlüssel veröffentlicht"
        if self.revoked:
            return "Schlüssel widerrufen"
        return "Schlüssel veröffentlicht"


@dataclass
class AuthDnsReport:
    """Das Ergebnis beider Abfragen zu einer Mail."""

    spf: SpfResult = field(default_factory=SpfResult)
    dmarc: DmarcResult = field(default_factory=DmarcResult)
    dkim: DkimResult = field(default_factory=DkimResult)

    @property
    def any_ran(self) -> bool:
        return self.spf.ran or self.dmarc.ran or self.dkim.ran


def enabled() -> bool:
    """Ist die DNS-Prüfung eingeschaltet? Vorgabe: nein."""
    from .. import config

    return bool(getattr(config, "DNS_AUTH_ENABLED", False))


def _txt_records(name: str, timeout: float = _TIMEOUT_SECONDS) -> list[str]:
    """TXT-Einträge eines Namens holen. Wirft bei jedem Fehler.

    ``Resolve-DnsName`` und nicht ``nslookup``: dessen Ausgabe ist
    sprachabhängig („Nicht autorisierende Antwort" auf Deutsch), und ein
    Parser darauf bricht auf jeder anderen Windows-Sprache.
    """
    # SEC-010: never resolve through the CWD. Windows' shutil.which searches
    # "." before PATH; a planted powershell.exe in the scanned directory would
    # run with the user's rights. Prefer the fixed system path, then accept
    # only absolute PATH hits.
    fixed = (
        Path(os.environ.get("SYSTEMROOT", r"C:\Windows"))
        / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    )
    pwsh = str(fixed) if fixed.is_file() else ""
    if not pwsh:
        for name in ("powershell", "pwsh"):
            found = shutil.which(name)
            if found and Path(found).is_absolute():
                pwsh = found
                break
    if not pwsh:
        raise OSError("PowerShell nicht gefunden (powershell/pwsh)")
    # Der Name stammt aus einer Kopfzeile der Mail und ist damit
    # angreiferkontrolliert. Ein Anführungszeichen darin beendete sonst das
    # PowerShell-Argument und fuehrte fremden Code aus.
    #
    # ABGELEHNT, NICHT VERSTUEMMELT. Eine erste Fassung filterte die Zeichen
    # heraus — GEMESSEN: "münchen.example" wurde zu "mnchen.example". Das ist
    # kein sauberer Name, sondern ein ANDERER Name: haette er einen
    # SPF-Eintrag, waere das Urteil eines ueber die falsche Domain. Und
    # ``str.isalnum()`` ist unicode-weit, ein Umlaut passiert den Filter
    # ohnehin.
    #
    # IDN-Namen koennen ohne IDNA-Umrechnung nicht abgefragt werden; sie
    # werden deshalb abgelehnt. Der Aufrufer meldet dann "unbekannt" — was
    # stimmt, denn geprueft wurde nichts.
    erlaubt = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_")
    if not name or len(name) > 253 or not set(name) <= erlaubt:
        raise ValueError(f"kein abfragbarer DNS-Name: {name!r}")
    sicher = name
    args = [
        pwsh,
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        _PS_LOOKUP.format(name=sicher),
    ]
    proc = run_tool(args, timeout=timeout)
    if tool_output_truncated(proc):
        # SEC-023: a cut-off answer is not an empty/no-record answer — the
        # caller must report "unbekannt", not "kein Eintrag".
        raise OSError(
            "DNS-Antwort wurde an der Ausgabe-Obergrenze abgeschnitten "
            "— Ergebnis unbekannt"
        )
    _rc, raw_out, raw_err = proc
    roh = decode_tool_output(raw_out).strip()
    if not roh:
        fehler = decode_tool_output(raw_err).strip()
        raise OSError(fehler[:200] or "keine DNS-Antwort")
    try:
        daten = json.loads(roh)
    except json.JSONDecodeError as exc:
        raise OSError(f"DNS-Antwort nicht lesbar: {exc}") from exc
    if isinstance(daten, list):  # aeltere Form: nur die Eintraege
        return [str(x) for x in daten]
    if not isinstance(daten, dict):
        return []
    if daten.get("ok"):
        eintraege_roh: object = daten.get("records") or []
        if isinstance(eintraege_roh, str):
            return [eintraege_roh]
        if not isinstance(eintraege_roh, list):
            return []
        # Zwei Formen: eine Liste von Strings (ein Record, unzerlegt) oder
        # eine Liste von LISTEN (die Strings je Record). Beide werden zu
        # EINEM String pro Record verkettet.
        #
        # GEMESSEN: s1._domainkey.github.com liefert 2 Strings mit zusammen
        # 406 Zeichen. Ohne die Verkettung sah der Aufrufer nur "v=DKIM1;
        # k=rsa; p=" — also einen leeren Schluessel, und meldete einen
        # LEBENDEN Schluessel als "kein Schluessel veroeffentlicht".
        zusammen: list[str] = []
        for eintrag in eintraege_roh:
            if isinstance(eintrag, list):
                zusammen.append("".join(str(t) for t in eintrag))
            else:
                zusammen.append(str(eintrag))
        return zusammen
    if daten.get("code") == _DNS_NAME_ERROR:
        # NXDOMAIN: der Name hat KEINEN Eintrag. Kein Fehler — eine Antwort.
        # GEMESSEN: "_dmarc.firma.example" liefert 9003, und die Stufe meldete
        # daraufhin "DNS-Pruefung nicht moeglich", als waere das Netz kaputt.
        return []
    raise OSError(f"DNS-Abfrage fehlgeschlagen (Code {daten.get('code')})")


def _registrable(domain: str) -> str:
    """Die Domain, unter der SPF/DMARC stehen (ohne Subdomain).

    Für die Abfrage genügt das: SPF liegt beim Organisations-Domain, DMARC
    ebenfalls. ``mail.firma.de`` -> ``firma.de``.

    NIM MT AUCH ADRESSEN. Der Aufrufer uebergibt ``facts.from_addr`` und
    ``facts.return_path`` — das sind MAILADRESSEN ("a@firma.example"), keine
    Domains. GEMESSEN: ohne diesen Schritt wurde daraus der DNS-Name
    ``_dmarc.a@firma.example``, die Abfrage scheiterte an der Namenspruefung,
    und die Stufe meldete fuer JEDE Mail "unbekannt". Die Pruefung lief damit
    ins Leere, ohne dass es auffiel — die Meldung sah nach einem Netzproblem
    aus.
    """
    # Klammern zuerst: ``Return-Path`` steht in der Form "<a@firma.de>", und
    # ohne diesen Schritt bliebe "firma.de>" stehen — ein Name, den die
    # Abfrage ablehnt.
    roh = (domain or "").strip().strip("<>").strip()
    if "@" in roh:
        roh = roh.rsplit("@", 1)[1]
    teile = [t for t in roh.lower().strip(".").split(".") if t]
    if len(teile) <= 2:
        return ".".join(teile)
    # Zwei-Teil-Suffixe wie "co.uk" sind ohne Public-Suffix-Liste nicht
    # sicher zu erkennen; die üblichen Fälle (de, com, net, org) haben eins.
    if teile[-2] in ("co", "com", "net", "org", "gov", "edu") and len(teile[-1]) <= 2:
        return ".".join(teile[-3:])
    return ".".join(teile[-2:])


# SPF-Qualifier before a mechanism (RFC 7208, section 4.6.2). ``+`` is the
# default; the others soften/negate the mechanism's result.
_QUALIFIERS = frozenset({"+", "-", "~", "?"})


def _qualifier_and_mechanism(token: str) -> tuple[str, str]:
    """``+ip4:…`` -> ``("+", "ip4:…")``; a missing qualifier means ``+``."""
    if token[:1] in _QUALIFIERS:
        return token[0], token[1:]
    return "+", token


def _mechanismus_trifft(token: str, ip: str) -> bool:
    """Nennt dieser SPF-Mechanismus genau diese IP (bzw. diesen Bereich)?

    The qualifier must already be stripped by the caller: ``+ip4:…`` used to
    fall through both branches and an ALLOWED address was reported as NOT
    allowed (audit BUG-011).
    """
    if token.startswith("ip4:"):
        return _ip_in_cidr(ip, token[4:])
    if token.startswith("ip6:"):
        return _ip_in_cidr(ip, token[4:])
    return False


def _ip_in_cidr(ip: str, netz: str) -> bool:
    """Liegt ``ip`` in ``netz`` (``a.b.c.d`` oder ``a.b.c.d/len``)?

    WARUM DAS NICHT MIT == GEHT
    ===========================
    Eine erste Fassung verglich die IP als ZEICHENKETTE gegen den Eintrag.
    GEMESSEN an gmail.com: dort steht ``ip4:209.85.128.0/17``, und die echte
    Google-IP 209.85.220.41 liegt in diesem Bereich — der Vergleich sagte
    trotzdem "nicht erlaubt". Eine legitime Mail waere mit HIGH/30 markiert
    worden.
    """
    from ipaddress import ip_address, ip_network

    try:
        if "/" in netz:
            return ip_address(ip) in ip_network(netz, strict=False)
        return ip_address(ip) == ip_address(netz)
    except ValueError:
        return False


def _spf_domain(value: str) -> str:
    """Die EXAKTE Domain, unter der SPF veroeffentlicht wird.

    Anders als ``_registrable`` darf hier NICHT auf die Organisationsdomain
    gekuerzt werden: SPF liegt bei der Domain der Envelope-Adresse, und ein
    Eintrag von ``firma.de`` sagt nichts ueber ``mail.firma.de`` (RFC 7208,
    ``check_host()``). Die fruehere Abfrage von ``firma.de`` fuer jede
    Subdomain war ein falscher Abfragename (Audit BUG-011/TEST-027).
    Adressen (``a@mail.firma.de`` / ``<a@mail.firma.de>``) werden zerlegt.
    """
    roh = (value or "").strip().strip("<>").strip()
    if "@" in roh:
        roh = roh.rsplit("@", 1)[1]
    return roh.lower().strip().strip(".")


def check_spf(sender_ip: str, return_path_domain: str) -> SpfResult:
    """SPF-Eintrag holen und die Absender-IP dagegen halten.

    ``ip_allowed`` bleibt ``None``, sobald der Eintrag Mechanismen benutzt,
    die eine eigene Abfrage brauchen (``include:``, ``redirect=``, ``a``,
    ``mx``) oder die IP unbrauchbar ist. Ein ``None`` heißt „nicht
    beurteilbar" und wird auch so gemeldet — NICHT als erlaubt.
    """
    ergebnis = SpfResult()
    domain = _spf_domain(return_path_domain)
    if not domain:
        ergebnis.error = "keine Absenderdomain"
        return ergebnis
    try:
        eintraege = _txt_records(domain)
    except Exception as exc:
        ergebnis.error = f"{type(exc).__name__}: {exc}"
        return ergebnis
    ergebnis.ran = True
    spf = next((e for e in eintraege if e.lower().startswith("v=spf1")), "")
    ergebnis.record = spf
    if not spf:
        # BUG-014: the exact Mail-From domain is authoritative (RFC 7208), but
        # an operator that publishes only the organizational record is common.
        # Query the registrable domain as a FALLBACK instead of never seeing a
        # subdomain's record at all — and say so, so the result does not claim
        # a record directly below the sender domain.
        org = _registrable(domain)
        if org and org != domain:
            try:
                fallback = _txt_records(org)
            except Exception as exc:
                # The fallback failed; "kein SPF-Eintrag" would turn an outage
                # into a statement about the domain.
                ergebnis.error = f"{type(exc).__name__}: {exc}"
                return ergebnis
            spf = next((e for e in fallback if e.lower().startswith("v=spf1")), "")
            if spf:
                ergebnis.record = spf
                ergebnis.detail = (
                    f"kein SPF-Eintrag auf {domain}; Eintrag von {org} verwendet"
                )
    if not spf:
        return ergebnis

    if not sender_ip:
        ergebnis.detail = "keine Absender-IP aus der Received-Kette"
        return ergebnis
    ip = sender_ip.strip().strip("[]")
    from ipaddress import ip_address

    try:
        ip_address(ip)
    except ValueError:
        # "not-an-ip" matched no mechanism and was reported as "IP NICHT
        # erlaubt" (HIGH/30). An unusable input is "unknown", never a
        # negative verdict (audit BUG-011).
        ergebnis.detail = (
            f"Absender-IP '{ip}' ist keine gueltige IP-Adresse — "
            "nicht beurteilbar"
        )
        return ergebnis

    # EINE Ebene tief folgen. Praktisch jede echte Domain benutzt
    # "include:"/"redirect=" (gemessen: gmail.com -> "redirect=_spf.google.com");
    # ohne das Folgen waere die Antwort IMMER "nicht beurteilbar" und die
    # Stufe damit wertlos.
    #
    # Genau EINE Ebene, nicht die ganze Kette: die Ziel-Domain stammt aus dem
    # SPF-Eintrag und ist damit vom Absender mitbestimmt. Wer tiefer folgt,
    # laesst sich vom Angreifer beliebig viele DNS-Abfragen vorschreiben —
    # jede davon ein Lebenszeichen dieser Maschine bei einem fremden Server.
    tokens = spf.split()[1:]
    verweis = ""
    for token in tokens:
        _qualifier, mechanism = _qualifier_and_mechanism(token)
        lowered = mechanism.lower()
        if lowered.startswith("include:"):
            verweis = lowered.split(":", 1)[1]
            break
        if lowered.startswith("redirect="):
            verweis = lowered.split("=", 1)[1]
            break

    inner_tokens: list[str] = []
    if verweis:
        try:
            tiefer = _txt_records(verweis)
        except Exception as exc:
            ergebnis.detail = f"Verweis auf '{verweis}' nicht abrufbar: {exc}"
            return ergebnis
        zweiter = next((e for e in tiefer if e.lower().startswith("v=spf1")), "")
        if not zweiter:
            ergebnis.detail = f"Verweis auf '{verweis}' ohne SPF-Eintrag"
            return ergebnis
        ergebnis.record = f"{spf} -> {zweiter}"
        # MECHANISMEN BEIDER RECORDS (Audit BUG-011): die des ersten Records
        # wurden vorher ersetzt, ein dort genanntes ``ip4:`` verschwand und
        # die erlaubte IP galt als "NICHT erlaubt".
        inner_tokens = zweiter.split()[1:]
        ergebnis.detail = f"über '{verweis}' aufgelöst"

    def _outcome(qualifier: str) -> bool | None:
        """Was ein TREFFER mit diesem Qualifier bedeutet.

        ``-``/``~`` verweigern die Freigabe; ``?`` ist neutral und damit
        "nicht beurteilbar" — kein "nicht erlaubt".
        """
        return {"+": True, "-": False, "~": False, "?": None}[qualifier]

    # First match wins (RFC 7208). Only the outer ``all`` is a fallback: an
    # inner ``-all`` describes the include target, not this domain.
    matched = False
    outcome: bool | None = None
    for token in [*tokens, *inner_tokens]:
        qualifier, mechanism = _qualifier_and_mechanism(token)
        lowered = mechanism.lower()
        if lowered == "all":
            continue
        if _mechanismus_trifft(lowered, ip):
            matched = True
            outcome = _outcome(qualifier)
            break

    if matched:
        ergebnis.ip_allowed = outcome
        detail = (
            f"IP {ip} gegen {len(tokens) + len(inner_tokens)} Mechanismen geprüft"
        )
        if outcome is None:
            detail += " (neutraler Mechanismus — nicht beurteilbar)"
        ergebnis.detail = (ergebnis.detail + " | " if ergebnis.detail else "") + detail
        return ergebnis

    # ``+all`` im include-Ziel bedeutet: der include-Mechanismus trifft.
    if any(
        _qualifier_and_mechanism(token)[0] == "+"
        and _qualifier_and_mechanism(token)[1].lower() == "all"
        for token in inner_tokens
    ):
        ergebnis.ip_allowed = True
        ergebnis.detail = (ergebnis.detail + " | " if ergebnis.detail else "") + (
            f"IP {ip} ist über '{verweis}' freigegeben"
        )
        return ergebnis

    # GRENZE DER AUSSAGE — der wichtigste Teil dieser Funktion.
    #
    # "NICHT erlaubt" darf NUR fallen, wenn der Eintrag vollstaendig vor uns
    # liegt. Folgendes macht ihn unvollstaendig:
    #
    # * ein WEITERER Verweis (include/redirect IM ZIEL): dann liegen die
    #   ip4-Bereiche eine Ebene tiefer. GEMESSEN an gmail.com: die echte
    #   Google-IP 209.85.220.41 wurde als "NICHT erlaubt" gemeldet, weil
    #   _spf.google.com selbst wieder include: benutzt. Eine legitime Mail
    #   waere mit HIGH/30 markiert worden — eine FALSCHANSCHULDIGUNG, und
    #   die ist schlimmer als "nicht beurteilbar". Der bereits gefolgte
    #   Verweis zaehlt NICHT mehr als offen: seine Mechanismen stehen oben.
    # * a/mx/ptr/exists: koennen die IP erlauben, ohne sie zu nennen.
    unsicher = any(
        _qualifier_and_mechanism(token)[1].lower().startswith(
            ("a:", "mx:", "ptr:", "exists:")
        )
        or _qualifier_and_mechanism(token)[1].lower() in ("a", "mx", "ptr")
        for token in [*tokens, *inner_tokens]
    )
    unsicher = unsicher or any(
        _qualifier_and_mechanism(token)[1].lower().startswith(
            ("include:", "redirect=")
        )
        for token in inner_tokens
    )
    if unsicher:
        ergebnis.detail = (ergebnis.detail + " | " if ergebnis.detail else "") + (
            "Eintrag verweist weiter (include/redirect/a/mx/ptr) — die IP ist "
            "darueber NICHT beurteilbar"
        )
        return ergebnis

    # Der ``all``-Mechanismus des AEUSSEREN Records entscheidet, wenn kein
    # Mechanismus die IP genannt hat. ``-all``/``~all`` heisst: nur die
    # genannten Quellen — die IP ist NICHT erlaubt. Ohne ``all`` ist das
    # Ergebnis neutral (RFC 7208) und damit nicht beurteilbar.
    outer_all: str | None = None
    for token in tokens:
        qualifier, mechanism = _qualifier_and_mechanism(token)
        if mechanism.lower() == "all":
            outer_all = qualifier
            break
    ergebnis.ip_allowed = None if outer_all is None else _outcome(outer_all)
    detail = f"IP {ip} gegen {len(tokens) + len(inner_tokens)} Mechanismen geprüft"
    if outer_all is None:
        detail += " | Eintrag endet ohne all-Mechanismus — nicht beurteilbar"
    ergebnis.detail = (ergebnis.detail + " | " if ergebnis.detail else "") + detail
    return ergebnis


def check_dmarc(from_domain: str) -> DmarcResult:
    """DMARC-Eintrag holen und die Richtlinie nennen.

    Gefragt wird zuerst unter der EXAKTEN Absenderdomain (``_dmarc.mail…``);
    erst wenn dort kein Eintrag steht, unter der registrierbaren Domain
    (BUG-014). Die frühere Reihenfolge fragte ausschließlich registrierbar und
    machte einen auf der Subdomain veröffentlichten Eintrag unsichtbar.
    """
    ergebnis = DmarcResult()
    domain = _spf_domain(from_domain)
    if not domain:
        ergebnis.error = "keine Absenderdomain"
        return ergebnis
    try:
        eintraege = _txt_records(f"_dmarc.{domain}")
    except Exception as exc:
        ergebnis.error = f"{type(exc).__name__}: {exc}"
        return ergebnis
    ergebnis.ran = True
    dmarc = next((e for e in eintraege if e.lower().startswith("v=dmarc1")), "")
    if not dmarc:
        org = _registrable(domain)
        if org and org != domain:
            try:
                eintraege = _txt_records(f"_dmarc.{org}")
            except Exception as exc:
                ergebnis.error = f"{type(exc).__name__}: {exc}"
                return ergebnis
            dmarc = next((e for e in eintraege if e.lower().startswith("v=dmarc1")), "")
    ergebnis.record = dmarc
    if not dmarc:
        return ergebnis
    for teil in dmarc.split(";"):
        schluessel, _, wert = teil.partition("=")
        if schluessel.strip().lower() == "p":
            ergebnis.policy = wert.strip().lower()
            break
    return ergebnis


def check_dkim(selector: str, domain: str) -> DkimResult:
    """Ist der DKIM-Schluessel des Selektors veroeffentlicht?

    Die Abfrage lautet ``<selector>._domainkey.<domain>``. Beides stammt aus
    der ``DKIM-Signature``-Kopfzeile der Mail und ist damit vom Absender
    bestimmt — der Selektor wird deshalb wie ein DNS-Name geprueft, und ein
    unbrauchbarer Selektor ist ein Fehler, kein leerer Eintrag.
    """
    ergebnis = DkimResult(selector=(selector or "").strip())
    if not ergebnis.selector:
        return ergebnis
    ziel = _registrable(domain)
    if not ziel:
        ergebnis.error = "keine Signaturdomain"
        return ergebnis
    try:
        eintraege = _txt_records(f"{ergebnis.selector}._domainkey.{ziel}")
    except Exception as exc:
        ergebnis.error = f"{type(exc).__name__}: {exc}"
        return ergebnis
    ergebnis.ran = True
    # Der Schluessel steht als "v=DKIM1; k=rsa; p=..." im Eintrag. Ein leerer
    # p-Wert heisst "widerrufen" — das ist ein Befund, kein fehlender Eintrag.
    # Ein DKIM-Record erkennt man am TAG "p=", nicht am ANFANG.
    #
    # GEMESSEN an s1._domainkey.github.com: der Eintrag lautet
    # "k=rsa; t=s; p=MIIBIjAN..." — "v=DKIM1" ist laut RFC 6376 OPTIONAL und
    # fehlt hier. Eine Pruefung auf den Anfang (startswith "v=dkim1"/"p=")
    # verwarf den Eintrag, und die Stufe meldete "kein Schluessel
    # veroeffentlicht" fuer einen lebenden 406-Zeichen-Schluessel.
    ergebnis.record = next(
        (
            e
            for e in eintraege
            if any(
                teil.partition("=")[0].strip().lower() == "p"
                for teil in e.split(";")
            )
        ),
        "",
    )
    # Ein LEERES "p=" heisst widerrufen, nicht "Schluessel vorhanden".
    #
    # GEMESSEN an gmail.com: die Selektoren 20230601 und 20210112 liefern
    # beide "v=DKIM1; k=rsa; p=" — Google hat sie zurueckgezogen (bestaetigt
    # mit nslookup, also nicht der Resolver). Wer das als "veroeffentlicht"
    # meldet, sagt bei einem widerrufenen Schluessel "alles in Ordnung".
    schluessel = ""
    for teil in ergebnis.record.split(";"):
        name, _, wert = teil.partition("=")
        if name.strip().lower() == "p":
            schluessel = wert.strip()
            break
    ergebnis.revoked = bool(ergebnis.record) and not schluessel
    return ergebnis


def check(
    sender_ip: str,
    return_path_domain: str,
    from_domain: str,
    dkim_selector: str = "",
    dkim_domain: str = "",
) -> AuthDnsReport:
    """Alle drei Abfragen. Wirft nie — ein Fehler steht im Feld ``error``.

    DKIM bekommt Selektor und Domain aus der ``DKIM-Signature``-Kopfzeile
    (``facts.dkim_selector`` / ``facts.dkim_domain``). Fehlen sie, ist das
    kein Fehler der Abfrage: die Mail traegt dann keine Signatur, und das
    wird als solches gemeldet.
    """
    bericht = AuthDnsReport()
    try:
        bericht.spf = check_spf(sender_ip, return_path_domain or from_domain)
    except Exception as exc:  # pragma: no cover - check_spf faengt selbst ab
        bericht.spf = SpfResult(error=f"{type(exc).__name__}: {exc}")
    try:
        bericht.dmarc = check_dmarc(from_domain or return_path_domain)
    except Exception as exc:  # pragma: no cover
        bericht.dmarc = DmarcResult(error=f"{type(exc).__name__}: {exc}")
    try:
        bericht.dkim = check_dkim(dkim_selector, dkim_domain)
    except Exception as exc:  # pragma: no cover
        bericht.dkim = DkimResult(error=f"{type(exc).__name__}: {exc}")
    return bericht


__all__ = [
    "AuthDnsReport",
    "DkimResult",
    "DmarcResult",
    "SpfResult",
    "check",
    "check_dkim",
    "check_dmarc",
    "check_spf",
    "enabled",
]
