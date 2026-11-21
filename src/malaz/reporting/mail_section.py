"""Das Absender-Urteil als Berichtstext — fuer HTML und PDF dieselbe Quelle.

WARUM DIESE DATEI EXISTIERT
===========================
Die Anzeige des Absender-Urteils gab es in der Liste, im Detailfeld und in der
CLI — aber NICHT im Bericht. Wer eine Mail scannte und den Bericht speicherte,
sah dort nur den Rohbefund ``MAIL_AUTH_FAIL`` und nicht die Aussage
"SPF FEHLGESCHLAGEN | DKIM nicht verwendet | DMARC FEHLGESCHLAGEN" und auch
nicht, ob der angezeigte Name zur Absenderadresse passt. Der Bericht ist das,
was weitergereicht wird.

Zwei Renderer (HTML, PDF) brauchen denselben Inhalt. Getrennt formuliert
laufen sie auseinander — dieselbe Fehlerklasse wie beim Adressmuster, das in
zwei Modulen stand. Deshalb liefert diese Datei nur DATEN (Zeilen aus
Beschriftung und Wert); die Renderer entscheiden ueber die Darstellung.
"""

from __future__ import annotations

# Wortwahl aus core/mail_view importiert, NICHT kopiert: derselbe Sachverhalt
# darf im Bericht nicht anders heissen als im Detailfeld. Die Kopie stand hier
# wortgleich und war fuer scripts/check_duplicate_logic.py unsichtbar, weil der
# Pruefer nur Skalare verglich (ein dict-Literal ist ein ast.Dict, kein
# ast.Constant) — er meldete "Keine unbegruendeten Dopplungen" zu zwei
# identischen Tabellen. Der Pruefer vergleicht jetzt auch Sammlungen.
from ..core.mail_view import AUTH_LABELS
from ..i18n import get_language, language_context, resolve_language
from ..models import ScanResult

# Die Regel, die eine ungedeckte Behauptung meldet. Steht sie an, sind die
# Verfahren NICHT beurteilbar — ein Haken waere eine Falschaussage.
_UNBACKED = "MAIL_AUTH_CLAIM_UNBACKED"

# Ein einzelnes Literal: als Tupelelement wollte ruff mal die implizite, mal
# die explizite Verkettung — beides ist hier unnoetig.
HINWEIS_ANZEIGENAME = (
    "Ein abweichender Anzeigename ist die haeufigste Taeuschung: der Name "
    "sieht vertraut aus, die Adresse ist es nicht"
)


def is_mail_result(result: ScanResult) -> bool:
    """Ist dieses Ergebnis eine Mail, deren Kinder ANHAENGE sind?

    ``detected_type`` allein genuegt nicht: eine Outlook-``.msg`` wird als
    ``ole`` erkannt (der Container), nicht als ``msg``. ``mail_security``
    setzt der Dispatcher nur fuer echte Mails — deshalb ist es das zweite,
    verlaessliche Signal. Ohne es hiessen die Anhaenge einer ``.msg`` im
    Bericht "Archiveintraege".
    """
    return result.detected_type in ("eml", "msg") or bool(result.mail_security)


def _claim_unbacked(result: ScanResult) -> bool:
    """Nur die Befunde DIESER Mail zaehlen — nicht die ihrer Kinder.

    ``all_indicators()`` zieht Anhaenge/Archivmitglieder mit herein. Ein
    Befund im Anhang sagt aber nichts ueber den Absender der Elternmail;
    vorher erbte die Elternmail das Kind-Urteil ("nicht beurteilbar",
    Bewertung gedeckelt auf 20).
    """
    return any(ind.rule_id == _UNBACKED for ind in result.indicators)


_AUTH_LABELS_EN: dict[str, str] = {
    "pass": "pass",
    "fail": "FAILED",
    "softfail": "softfail",
    "neutral": "neutral",
    "none": "not used",
    "unknown": "unverifiable",
}

_AUTH_LABELS_TR: dict[str, str] = {
    "pass": "başarılı",
    "fail": "BAŞARISIZ",
    "softfail": "kısmi",
    "neutral": "nötr",
    "none": "kullanılmıyor",
    "unknown": "doğrulanamadı",
}


_MAIL_REASON_MAP: dict[str, tuple[str, str]] = {
    "Der angezeigte Name passt nicht zur Absenderadresse — der Name ist frei waehlbar": (
        "Display name does not match sender address — display names are freely editable",
        "Görünen ad gönderici adresiyle eşleşmiyor — görünen ad serbestçe yazılabilir",
    ),
    "Die Mail behauptet bestandene Authentifizierung durch einen Server, der in der Empfangskette fehlt": (
        "Email claims passed authentication from a server missing from the delivery chain",
        "E-posta, teslimat zincirinde yer almayan bir sunucudan başarılı doğrulama iddia ediyor",
    ),
    "Diese Adresse steht auf der Blockliste bekannter Schad-Adressen": (
        "This address matches a local blocklist of known malicious destinations",
        "Bu adres bilinen zararlı hedeflerin yerel engelleme listesinde yer alıyor",
    ),
    "Der sichtbare Linktext nennt eine andere Adresse als das Ziel — das ist "
    "die haeufigste Phishing-Bauform": (
        "Visible link text displays a different destination than the actual target (phishing)",
        "Görünen bağlantı metni gerçek hedeften farklı bir adres gösteriyor (kimlik avı)",
    ),
    "Der Name enthaelt Unicode-Zeichen und kann wie eine bekannte Marke aussehen, ohne es zu sein": (
        "Domain uses Unicode/Punycode characters that can imitate a known brand",
        "Alan adı bilinen bir markayı taklit edebilen Unicode/Punycode karakterler içeriyor",
    ),
    "Der Link fuehrt keinen Webbrowser aus, sondern startet ein Programm oder greift auf lokale Dateien zu": (
        "Link invokes a local program or file URI instead of a web page",
        "Bağlantı bir web sayfası yerine yerel program veya dosya URI'si başlatıyor",
    ),
    "In der Adresse stehen Zugangsdaten vor dem @ — damit laesst sich eine echte Domain vortaeuschen": (
        "URL contains credentials before '@' to spoof a legitimate domain",
        "URL, gerçek bir alan adını taklit etmek için '@' öncesinde kimlik bilgisi içeriyor",
    ),
    "Der Link nennt eine nackte IP-Adresse statt eines Namens": (
        "Link points to a raw IP address instead of a domain name",
        "Bağlantı alan adı yerine doğrudan IP adresine yönlendiriyor",
    ),
    "Die Endung der Domain gilt als haeufig missbraucht": (
        "Domain uses a top-level domain frequently abused for phishing",
        "Alan adı kimlik avı için sıkça kötüye kullanılan bir uzantıya sahip",
    ),
    "Ein Kurzlink verbirgt das Ziel": (
        "URL shortener hides the final destination",
        "Kısaltılmış bağlantı gerçek hedef adresi gizliyor",
    ),
}


def localize_mail_score_label(label: str, *, lang: str | None = None) -> str:
    """Localize sender/link score labels from ``core/mail_score.py``."""
    eff = resolve_language(lang) if lang is not None else get_language()
    if eff == "de":
        return label
    low = (label or "").lower()
    is_tr = eff == "tr"
    if "teilweise stimmig" in low:
        return "Gönderen bilgileri kısmen tutarlı" if is_tr else "Sender details partially consistent"
    if "stimmig" in low:
        return "Gönderen bilgileri tutarlı" if is_tr else "Sender details consistent"
    if "widerspr" in low or "fehlend" in low:
        return (
            "Gönderen bilgileri çelişkili veya eksik" if is_tr else "Sender details conflicting or missing"
        )
    if "unauffällig" in low or "unauffaellig" in low:
        return "Normal" if is_tr else "Unremarkable"
    if (
        "nicht beurteilbar" in low
        or "nicht prüfbar" in low
        or "nicht pruefbar" in low
        or "unbekannt" in low
    ):
        return "Doğrulanamadı" if is_tr else "Unverifiable"
    if "gefährlich" in low or "gefaehrlich" in low or "hoch" in low or "betrug" in low:
        return "Şüpheli" if is_tr else "Suspicious"
    if (
        "verdächtig" in low
        or "verdaechtig" in low
        or "auffällig" in low
        or "auffaellig" in low
        or "prüf" in low
    ):
        return "İnceleme gerekli" if is_tr else "Needs review"
    if low == "ok":
        return "Normal" if is_tr else "Unremarkable"
    return label


def _tr_mail_score_label(label: str) -> str:
    return localize_mail_score_label(label, lang="tr")


def _en_mail_score_label(label: str) -> str:
    return localize_mail_score_label(label, lang="en")


def localize_mail_mechanism(verdict: str, *, claimed: bool = False, lang: str | None = None) -> str:
    """Localize a single SPF/DKIM/DMARC verdict (with unbacked-claim marker)."""
    eff = resolve_language(lang) if lang is not None else get_language()
    labels = _AUTH_LABELS_TR if eff == "tr" else (_AUTH_LABELS_EN if eff == "en" else AUTH_LABELS)
    fallback = "bilinmiyor" if eff == "tr" else ("unknown" if eff == "en" else "unbekannt")
    text = labels.get(verdict, fallback)
    if claimed and verdict in ("pass", "fail"):
        if eff == "tr":
            return f"iddia edilen: {text}"
        if eff == "en":
            return f"claimed: {text}"
        return f"behauptet: {text}"
    return text


def localize_mail_reason(reason: str, *, lang: str | None = None) -> str:
    """Localize a single sender or link reason string from ``core/mail_score.py``."""
    eff = resolve_language(lang) if lang is not None else get_language()
    if eff == "de" or not reason:
        return reason
    idx = 1 if eff == "tr" else 0
    exact = _MAIL_REASON_MAP.get(reason)
    if exact is not None:
        return exact[idx]
    for prefix in ("SPF: ", "DKIM: ", "DMARC: "):
        if reason.startswith(prefix):
            rest = reason[len(prefix) :]
            sub_map = {
                "fehlgeschlagen": ("failed", "başarısız"),
                "vom Absender nicht verwendet": ("not used by sender", "gönderici tarafından kullanılmıyor"),
                "nicht beurteilbar (keine Angabe in der Datei)": (
                    "unverifiable (no header record in file)",
                    "doğrulanamadı (dosya başlığında kayıt yok)",
                ),
                "bestanden": ("passed", "başarılı"),
            }
            if rest in sub_map:
                return f"{prefix}{sub_map[rest][idx]}"
    return reason


def auth_summary(result: ScanResult, *, lang: str | None = None) -> str:
    """``SPF bestanden | DKIM nicht verwendet | DMARC FEHLGESCHLAGEN``."""
    eff = resolve_language(lang) if lang is not None else get_language()
    security = result.mail_security
    if not security:
        return ""
    if _claim_unbacked(result):
        if eff == "tr":
            return "doğrulanamadı (başlık beyanı sunucu teslimat zinciriyle desteklenmiyor)"
        if eff == "en":
            return "unverifiable (header claim unsupported by server delivery chain)"
        return "nicht beurteilbar (Behauptung ohne Deckung in der Server-Kette)"
    labels = _AUTH_LABELS_TR if eff == "tr" else (_AUTH_LABELS_EN if eff == "en" else AUTH_LABELS)
    fallback = "bilinmiyor" if eff == "tr" else ("unknown" if eff == "en" else "unbekannt")
    parts = [
        f"{name} {labels.get(security.get(key, ''), fallback)}"
        for name, key in (("SPF", "spf"), ("DKIM", "dkim"), ("DMARC", "dmarc"))
    ]
    return " | ".join(parts)


def sender_line(result: ScanResult, *, lang: str | None = None) -> str:
    """Aussage zum Anzeigenamen — oder leer, wenn es keine gibt."""
    eff = resolve_language(lang) if lang is not None else get_language()
    security = result.mail_security
    if not security:
        return ""
    if security.get("sender") == "mismatch":
        if eff == "tr":
            return (
                "Görünen ad gerçek gönderen adresiyle uyuşmuyor — görünen ad "
                "serbestçe yazılabilir, önemli olan gerçek adrestir"
            )
        if eff == "en":
            return (
                "Display name differs from sender address — display names are "
                "freely editable; the actual address matters"
            )
        return (
            "Der Anzeigename weicht von der Absenderadresse ab — der Name ist "
            "frei waehlbar, massgeblich ist die Adresse"
        )
    if security.get("sender") == "ok":
        if eff == "tr":
            return "Görünen ad gönderen adresiyle uyumlu"
        if eff == "en":
            return "Display name matches sender address"
        return "Der Anzeigename passt zur Absenderadresse"
    return ""


def mail_lines(result: ScanResult, *, lang: str | None = None) -> list[tuple[str, str]]:
    """Beschriftung/Wert-Zeilen fuer den Bericht; leer bei Nicht-Mails."""
    if not result.mail_security:
        return []
    eff = resolve_language(lang) if lang is not None else get_language()
    is_en = eff == "en"
    is_tr = eff == "tr"
    with language_context(eff):
        summary = auth_summary(result, lang=eff)
        if is_tr:
            lines: list[tuple[str, str]] = [
                ("Kimlik Doğr.", summary),
                ("Kaynak", "Dosya başlıkları — canlı DNS ile DOĞRULANMADI"),
            ]
        elif is_en:
            lines = [
                ("Sender Auth", summary),
                ("Source", "File headers — NOT verified against live DNS"),
            ]
        else:
            lines = [
                ("Absender-Auth", summary),
                ("Quelle", "Kopfzeilen der Datei — NICHT nachgeprueft"),
            ]
        sender = sender_line(result, lang=eff)
        if sender:
            if is_tr:
                lines.append(("Görünen Ad", sender))
            elif is_en:
                lines.append(("Display Name", sender))
            else:
                lines.append(("Anzeigename", sender))

        from ..core.mail_score import link_scores, sender_score

        marker = result.mail_security.get("has_from")
        hat_absender = marker is None or str(marker).strip().lower() not in (
            "",
            "0",
            "false",
        )
        bewertung = sender_score(
            result.mail_security,
            result.mail_security.get("sender", "unknown"),
            claim_unbacked=_claim_unbacked(result),
            has_from=hat_absender,
        )
        score_lbl = (
            _tr_mail_score_label(bewertung.label)
            if is_tr
            else (_en_mail_score_label(bewertung.label) if is_en else bewertung.label)
        )
        if is_tr:
            lines.append(("Gönderen", f"{bewertung.score}/100 — {score_lbl}"))
        elif is_en:
            lines.append(("Sender Score", f"{bewertung.score}/100 — {score_lbl}"))
        else:
            lines.append(("Bewertung", f"{bewertung.score}/100 — {score_lbl}"))

        links = getattr(result, "mail_links", None) or []
        auffaellig = [e for e in link_scores(links, limit=len(links)) if e.score > 0]
        if auffaellig:
            for nummer, eintrag in enumerate(auffaellig[:8], start=1):
                grund = localize_mail_reason(eintrag.reasons[0] if eintrag.reasons else "", lang=eff)
                elbl = localize_mail_score_label(eintrag.label, lang=eff)
                val = (
                    f"{eintrag.host} — {elbl} ({eintrag.score}/100). {grund}"
                    if grund
                    else f"{eintrag.host} — {elbl} ({eintrag.score}/100)"
                )
                lines.append((f"Link {nummer}", val))
            if len(auffaellig) > 8:
                extra = len(auffaellig) - 8
                more_val = (
                    f"… ve {extra} şüpheli bağlantı daha"
                    if is_tr
                    else (
                        f"… and {extra} more suspicious links"
                        if is_en
                        else f"… und {extra} weitere auffaellige"
                    )
                )
                lines.append(("Links", more_val))
        if result.mail_security.get("sender") == "mismatch":
            if is_tr:
                lines.append(
                    (
                        "Not",
                        (
                            "Uyumsuz görünen ad en yaygın kimlik avı yöntemidir: "
                            "isim tanıdık görünür ama gerçek adres farklıdır"
                        ),
                    )
                )
            elif is_en:
                lines.append(
                    (
                        "Note",
                        (
                            "A mismatched display name is the most common phishing trick: "
                            "the name looks familiar while the actual address is not"
                        ),
                    )
                )
            else:
                lines.append(("Hinweis", HINWEIS_ANZEIGENAME))
        return lines


render_mail_section = mail_lines
