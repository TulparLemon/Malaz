"""Bewertungen fuer Mails: Absender-Vertrauen und einzelne Links.

WARUM DIESE DATEI EXISTIERT
===========================
Bis hierher gab es genau EINEN Score: den der Datei (``core/scoring.py``).
Der beantwortet "ist diese Datei gefaehrlich". Ein Laie, der eine Mail
anschaut, hat aber zwei weitere Fragen, und fuer die gab es keine Zahl:

* **Wem gehoert der Absender?** SPF/DKIM/DMARC und der Namensvergleich sagen
  etwas ueber den ABSENDER, nicht ueber den Anhang. Eine Werbe-Mail mit
  bestandener Authentifizierung und einem harmlosen PDF ist etwas anderes als
  eine Mail ohne jede Authentifizierung mit demselben PDF.
* **Wohin fuehrt dieser Link?** Die vorhandenen ``MAIL_LINK_*``-Befunde sagen
  "irgendwo in dieser Mail gibt es einen kurzen Link". Der Leser will wissen,
  WELCHER Link gemeint ist und wie riskant er ist.

Beide Scores sind ABLEITUNGEN, keine neuen Messungen: sie fassen zusammen, was
die Analyse schon festgestellt hat. Es wird nichts nachgeladen, nichts
geschickt, kein Netz beruehrt.

DIE TRENNLINIE ZU core/scoring.py
=================================
``scoring.py`` gewichtet Befunde zu EINER Datei-Note. Hier entstehen zwei
GETRENNTE Noten mit eigenem Wertebereich und eigener Aussage. Sie werden NICHT
in die Datei-Note eingerechnet — sonst haette dieselbe Feststellung
(Phishing-Link) zweimal Gewicht, genau die Doppelzaehlung, die in dieser
Sitzung mehrfach korrigiert werden musste.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# EINE Quelle fuer die gefaehrlichen URI-Schemes: diese Datei hatte eine
# Teilmenge ({file, javascript, data, vbscript}) und bewertete ms-msdt,
# search-ms, jar und ms-officecmd mit 0, waehrend summarize_links sie als
# MAIL_LINK_DANGEROUS_SCHEME meldete (Audit BUG-069).
from .eml_analysis import _DANGEROUS_URI_SCHEMES, LinkFacts
from .mail_view import AUTH_LABELS

# --------------------------------------------------------------------------- #
# Absender-Vertrauen
# --------------------------------------------------------------------------- #

# Punktabzug je Mechanismus. Ein NICHT verwendet ist kein Fehlschlag: viele
# kleine Absender haben kein SPF. Es ist ein Hinweis, kein Beweis.
_AUTH_PENALTY = {
    "fail": 30,  # ausdruecklich fehlgeschlagen
    "none": 10,  # nicht verwendet
    "unknown": 10,  # nicht beurteilbar (keine Kopfzeile)
    "pass": 0,
}

# Was ein abweichender Anzeigename kostet. Hoch, weil es die Taeuschung ist,
# die den Leser ueberhaupt erst in die Falle fuehrt: der Name sieht vertraut
# aus, die Adresse ist es nicht.
_SENDER_MISMATCH_PENALTY = 35
# Obergrenze bei gefaelschtem Anzeigenamen.
_MISMATCH_CAP = 45

# Eine Behauptung ohne Deckung in der Empfangskette ist schlimmer als keine
# Behauptung: hier wurde aktiv etwas vorgetaeuscht.
_UNBACKED_PENALTY = 45


@dataclass
class SenderScore:
    """Wie vertrauenswuerdig ist der Absender — 0 (schlecht) bis 100 (gut)."""

    score: int = 100
    label: str = ""
    reasons: list[str] = field(default_factory=list)

    @property
    def color(self) -> str:
        """``green`` | ``yellow`` | ``red`` — dieselben Stufen wie beim Risiko."""
        if self.score >= 80:
            return "green"
        if self.score >= 50:
            return "yellow"
        return "red"


def sender_score(
    auth_verdicts: dict[str, str],
    sender_verdict: str,
    *,
    claim_unbacked: bool = False,
    has_from: bool = True,
) -> SenderScore:
    """Absender-Vertrauen aus den bereits ermittelten Urteilen.

    ``auth_verdicts`` kommt aus ``eml_analysis.auth_verdicts``,
    ``sender_verdict`` aus ``mail_view.sender_verdict``. Es wird nichts neu
    geparst und nichts geprueft — nur gewichtet, was schon dasteht.
    """
    if not has_from:
        return SenderScore(
            score=0,
            label="Kein Absender angegeben",
            reasons=[
                "Die Mail nennt keinen Absender — das ist bei echter Mail unueblich"
            ],
        )

    score = 100
    reasons: list[str] = []

    for name, key in (("SPF", "spf"), ("DKIM", "dkim"), ("DMARC", "dmarc")):
        verdict = auth_verdicts.get(key, "unknown")
        penalty = _AUTH_PENALTY.get(verdict, 10)
        if penalty:
            score -= penalty
            grund = _AUTH_REASON.get(verdict, "unbekannt")
            reasons.append(f"{name}: {grund}")

    if sender_verdict == "mismatch":
        # Deckeln, nicht nur abziehen: die Authentifizierung sagt etwas ueber
        # die DOMAIN, der Anzeigename ist das, was der Leser sieht. Wer einen
        # fremden Namen traegt, wird gedeckelt, egal wie gut SPF steht.
        score = min(score - _SENDER_MISMATCH_PENALTY, _MISMATCH_CAP)
        reasons.append(
            "Der angezeigte Name passt nicht zur Absenderadresse — der Name ist frei waehlbar"
        )

    if claim_unbacked:
        # Deckelt zusaetzlich: eine gefaelschte Bescheinigung darf nie besser
        # aussehen als gar keine.
        score = min(score - _UNBACKED_PENALTY, 20)
        reasons.append(_UNBACKED_REASON)

    score = max(0, min(100, score))
    return SenderScore(score=score, label=_sender_label(score), reasons=reasons)


def mechanism_label(verdict: str, *, claimed: bool = False) -> str:
    """Beschriftung eines einzelnen Mechanismus fuer die Anzeige.

    ``claimed=True`` bei einer Behauptung OHNE Deckung in der Empfangskette.
    Dann darf dort nicht "bestanden" stehen: die Kopfzeile behauptet es, ein
    Urteil ist es nicht. Genau dieser Widerspruch stand im E-Mail-Panel —
    "Absender nicht belegt" direkt ueber "SPF bestanden".
    """
    text = AUTH_LABELS.get(verdict, "unbekannt")
    if claimed and verdict in ("pass", "fail"):
        return f"behauptet: {text}"
    return text


_AUTH_REASON = {
    "fail": "fehlgeschlagen",
    "none": "vom Absender nicht verwendet",
    "unknown": "nicht beurteilbar (keine Angabe in der Datei)",
    "pass": "bestanden",
}


def _sender_label(score: int) -> str:
    """Das Label beschreibt die ANGABEN, nicht den Absender.

    "Absender wirkt echt" war eine Falschaussage: Malaz kann SPF/DKIM ohne Netz
    nicht pruefen. Gemessen an einer Datei, die Kette UND
    Authentication-Results selbst schreibt und beide auf denselben eigenen
    Server zeigen laesst, ergab das 100/100 — mit dem Label "wirkt echt".
    Geprueft war nichts; verglichen wurden nur Angaben aus derselben Datei.
    """
    if score >= 80:
        return "Absender-Angaben stimmig"
    if score >= 50:
        return "Absender-Angaben nur teilweise stimmig"
    return "Absender-Angaben widerspruechlich oder fehlend"


# --------------------------------------------------------------------------- #
# Links
# --------------------------------------------------------------------------- #

_UNBACKED_REASON = (
    "Die Mail behauptet bestandene Authentifizierung durch einen Server, "
    "der in der Empfangskette fehlt"
)

_LINK_BLOCKLIST = (
    "Diese Adresse steht auf der Blockliste bekannter Schad-Adressen"
)

_LINK_MISMATCH = (
    "Der sichtbare Linktext nennt eine andere Adresse als das Ziel — das ist "
    "die haeufigste Phishing-Bauform"
)
_LINK_PUNYCODE = (
    "Der Name enthaelt Unicode-Zeichen und kann wie eine bekannte Marke "
    "aussehen, ohne es zu sein"
)
_LINK_SCHEME = (
    "Der Link fuehrt keinen Webbrowser aus, sondern startet ein Programm "
    "oder greift auf lokale Dateien zu"
)
_LINK_CREDENTIALS = (
    "In der Adresse stehen Zugangsdaten vor dem @ — damit laesst sich eine "
    "echte Domain vortaeuschen"
)

# Jedes Merkmal mit Punktzahl und Klartext. Die Reihenfolge der Liste ist die
# Reihenfolge der Gruende in der Anzeige: das schwerste zuerst.
_LINK_SIGNALS: tuple[tuple[str, int, str], ...] = (
    (
        "mismatch",
        60,
        _LINK_MISMATCH,
    ),
    (
        "is_punycode",
        45,
        _LINK_PUNYCODE,
    ),
    (
        "dangerous_scheme",
        60,
        _LINK_SCHEME,
    ),
    (
        "has_credentials",
        35,
        _LINK_CREDENTIALS,
    ),
    (
        "is_ip_literal",
        25,
        "Der Link nennt eine nackte IP-Adresse statt eines Namens",
    ),
    (
        "risky_tld",
        15,
        "Die Endung der Domain gilt als haeufig missbraucht",
    ),
    (
        "is_shortener",
        10,
        "Ein Kurzlink verbirgt das Ziel",
    ),
)

@dataclass
class LinkScore:
    """Wie riskant ist EIN Link — 0 (harmlos) bis 100 (gefaehrlich)."""

    link: LinkFacts
    score: int = 0
    reasons: list[str] = field(default_factory=list)
    # Der Name, den der Leser sieht: der Host, sonst die volle URL.
    host: str = ""

    @property
    def color(self) -> str:
        if self.score >= 60:
            return "red"
        if self.score >= 25:
            return "yellow"
        return "green"

    @property
    def label(self) -> str:
        if self.score >= 60:
            return "nicht anklicken"
        if self.score >= 25:
            return "Vorsicht"
        return "unauffaellig"


def link_score(link: LinkFacts) -> LinkScore:
    """Risiko eines einzelnen Links aus seinen bereits erhobenen Merkmalen."""
    flags = {
        "mismatch": link.mismatch,
        "is_punycode": link.is_punycode,
        "is_ip_literal": link.is_ip_literal,
        "risky_tld": link.risky_tld,
        "is_shortener": link.is_shortener,
        "has_credentials": link.has_credentials,
        "dangerous_scheme": link.scheme.lower() in _DANGEROUS_URI_SCHEMES,
    }
    score = 0
    reasons: list[str] = []
    for key, penalty, text in _LINK_SIGNALS:
        if flags.get(key):
            score += penalty
            reasons.append(text)

    # Ein Treffer in der lokalen URL-Blockliste ist kein Merkmal, sondern ein
    # Befund — er ueberstimmt alles andere.
    if (link.reputation or "").lower() in ("malicious", "blocked", "hit"):
        score = 100
        reasons.insert(0, _LINK_BLOCKLIST)

    return LinkScore(
        link=link,
        score=min(100, score),
        reasons=reasons,
        host=link.host or link.url,
    )


def link_scores(links: list[LinkFacts], limit: int = 10) -> list[LinkScore]:
    """Die riskantesten Links zuerst, hoechstens ``limit`` Stueck.

    Begrenzt, weil eine Werbe-Mail hundert Links traegt und der Leser die
    gefaehrlichsten sehen will, nicht alle. Die Zahl der ausgelassenen steht
    in der Anzeige (siehe gui).
    """
    scored = [link_score(link) for link in links]
    scored.sort(key=lambda s: s.score, reverse=True)
    return scored[:limit]
