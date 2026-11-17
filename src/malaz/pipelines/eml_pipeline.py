"""Mail (.eml) pipeline: header structure, body text, and links.

Runs on top of ``core/email_extract.py`` (which recurses into attachments):
this pipeline answers the *content* questions — does the header layout hang
together, does the body text make sense, and where do the links really point.

Nothing here executes, renders, or fetches anything. Link reputation is a
separate, explicitly opt-in lookup (see ``core/url_reputation.py``) that sends
a URL **hash**, never the URL itself, and only when the user configured a
provider.
"""

from __future__ import annotations

from .. import config
from ..core import eml_analysis
from ..core.eml_analysis import (
    analyze_body,
    analyze_structure,
    parse_mail,
    risky_attachment_names,
    summarize_links,
)
from ..core.mail_view import render_mail, sender_verdict
from ..core.url_view import defang_url
from ..models import (
    CAT_CONTENT,
    CAT_IOC,
    CAT_MAIL,
    CAT_STRUCTURE,
    AnalysisContext,
    Indicator,
    Severity,
)
from .base import Pipeline

# Severity per structural finding kind. Impersonation and failed
# authentication are the ones a user must act on; the "unusual but possible"
# ones (missing Message-ID) stay informational.
# Befunde, die auf einer Mailingliste (RFC 2919, List-Id und Verwandte) den
# NORMALZUSTAND beschreiben:
#   MAIL_RETURN_PATH_MISMATCH  Die "-admin@"/"-bounces@"-Adresse gehoert der
#                              Liste; From nennt den Autor. Genau so ist eine
#                              Liste gebaut.
#   MAIL_DMARC_ALIGNMENT_FAIL  Listen versenden die Mail neu und setzen ihre
#                              eigene Envelope-Domain — die Ausrichtung kann
#                              deshalb nicht greifen. Viele Listen schreiben
#                              aus diesem Grund die From-Adresse um.
#   MAIL_RECEIVED_PRIVATE_IP   Der Listenserver relayt intern weiter, private
#                              Adressen in der Kette sind dort normal.
#
# GEMESSEN: 4 von 20 echten, sauberen Mails waren an genau diesen Regeln ROT.
_LISTEN_NORMAL = frozenset({
    # DIE GROESSTE fehlte: auf 19 von 20 AKTUELLEN Apache-Mails feuerte
    # MAIL_REPLY_TO_MISMATCH (30 Punkte) — "Antworten gehen an eine andere
    # Domain (users@httpd.apache.org) als der Absender". Genau das ist der
    # ZWECK einer Mailingliste: die Liste setzt Reply-To auf sich selbst,
    # damit Antworten in die Liste gehen. Ohne diesen Eintrag blieben trotz
    # erkannter Liste 19 von 20 Mails ROT.
    "MAIL_REPLY_TO_MISMATCH",
    "MAIL_RETURN_PATH_MISMATCH",
    "MAIL_DMARC_ALIGNMENT_FAIL",
    "MAIL_RECEIVED_PRIVATE_IP",
})

_STRUCTURE_SEVERITY = {
    "MAIL_DISPLAY_NAME_SPOOF": (Severity.HIGH, 30),
    # A foreign address INSIDE the display name — the technique, not a brand.
    "MAIL_DISPLAY_ADDR_MISMATCH": (Severity.HIGH, 30),
    # Claimed pass next to a spoofing signal: one deception, not two facts.
    # A forged Authentication-Results header is what makes a spoofed sender
    # look authenticated — that is the technique, and it was invisible.
    "MAIL_AUTH_CLAIMED_SPOOF": (Severity.HIGH, 30),
    "MAIL_DISPLAY_NAME_MIXED_SCRIPT": (Severity.HIGH, 30),
    "MAIL_LOOKALIKE_DOMAIN": (Severity.HIGH, 30),
    "MAIL_REPLY_TO_MISMATCH": (Severity.HIGH, 30),
    "MAIL_AUTH_FAIL": (Severity.MEDIUM, 15),
    # Hygiene signal, not evidence of an attack: weight 5, same class as
    # MAIL_NO_RECEIVED. The verdict itself belongs in the VIEWER (see
    # core/mail_view._auth_summary) — that is what the analyst reads, and the
    # detail is there per mechanism. Weighting it at 15 was an over-correction:
    # the note fires for every mail that is not fully authenticated, i.e. for
    # practically every saved .eml, and it pushed five corpus files over
    # ANCHOR_CRITICAL_SCORE (measured: 45 -> 60, 35 -> 50, 80 -> 95). A signal
    # that is true of almost every mail cannot be worth 15 points.
    "MAIL_AUTH_ABSENT": (Severity.LOW, 5),
    # Same cause as MAIL_NO_RECEIVED, which carries the weight: diagnosis only.
    "MAIL_AUTH_UNVERIFIABLE": (Severity.INFO, 0),
    # Ein gekuerzter Kopfzeilenblock ist eine Lese-Grenze, kein Befund ueber
    # die Mail: Diagnose ohne Punkte (SEC-034).
    "MAIL_HEADER_TRUNCATED": (Severity.INFO, 0),
    "MAIL_RETURN_PATH_MISMATCH": (Severity.MEDIUM, 15),
    "MAIL_NO_RECEIVED": (Severity.LOW, 5),
    "MAIL_NO_MESSAGE_ID": (Severity.INFO, 0),
    # Eine Kopfzeile, die bestandene Authentifizierung behauptet, waehrend der
    # behauptende Server in der Received-Kette fehlt: das ist die Taeter-
    # Handschrift, die eine gefaelschte Mail echt aussehen laesst. Gleiche
    # Klasse wie MAIL_AUTH_CLAIMED_SPOOF, dessen Sonderfall sie ist.
    "MAIL_AUTH_CLAIM_UNBACKED": (Severity.HIGH, 30),
    # Ein Treffer in der lokalen Blockliste ist kein Indiz, sondern ein
    # Befund: die Domain steht auf einer gepflegten Phishing-Liste, oder die
    # Absender-IP liegt in einem Netz bekannter Angriffsquellen. Hoeher als
    # jedes Verhaltensmerkmal, weil es eine Aussage ueber DIESEN Absender ist.
    "MAIL_SENDER_DOMAIN_BLOCKED": (Severity.CRITICAL, 50),
    "MAIL_SENDER_IP_BLOCKED": (Severity.HIGH, 30),
    "DOMAIN_BLOCKLIST_UNAVAILABLE": (Severity.INFO, 0),
    "IP_BLOCKLIST_UNAVAILABLE": (Severity.INFO, 0),
    "MAIL_DMARC_ALIGNMENT_FAIL": (Severity.MEDIUM, 15),
    # Derselbe Fall wie oben: gemessen trug die DKIM-Signatur
    # "UniversidaddeBurgos.onmicrosoft.com" — die TENANT-Domain des Hosters,
    # nicht die des Absenders. Auch hier wird Infrastruktur mit Absender
    # verglichen. Sichtbar, ohne Urteil.
    "MAIL_DKIM_DOMAIN_MISMATCH": (Severity.LOW, 0),
    "MAIL_RECEIVED_PRIVATE_IP": (Severity.MEDIUM, 15),
    # GEMESSEN an 20 AKTUELLEN Mails aus einem echten Apache-Archiv: diese
    # Regel feuerte auf 7 davon, weil die Message-ID die KENNUNG DES SERVERS
    # traegt statt der Absenderdomain — "AS4P191MB2109.EURP191.PROD.OUTLOOK.COM"
    # bei einem Absender auf ganz anderer Domain. Genau das ist bei
    # gehosteter Post der Normalfall: Exchange/M365 und Versanddienstleister
    # setzen den erzeugenden Host ein, nicht die Absenderdomain.
    #
    # Die Regel vergleicht damit eine INFRASTRUKTUR-Kennung mit der
    # Absenderdomain und misst die Zustellinfrastruktur, nicht den Absender.
    # Deshalb kein Gewicht: sichtbar bleibt der Befund (wer wissen will, wo
    # die Mail erzeugt wurde, liest ihn), aber er traegt kein Urteil.
    "MAIL_MESSAGE_ID_DOMAIN": (Severity.INFO, 0),
    "MAIL_MESSAGE_ID_ODD": (Severity.LOW, 5),
    "MAIL_RECEIVED_TIME_ANOMALY": (Severity.LOW, 5),
    # Beide sind Aussagen ueber die DATEI, nicht ueber den Transport: wir haben
    # die Verbindung nicht gesehen. Diagnose, kein Gewicht.
    "MAIL_RECEIVED_WEAK_TLS": (Severity.INFO, 0),
    "MAIL_FILTER_CLAIM": (Severity.INFO, 0),
}

_LINK_SEVERITY = {
    "MAIL_LINK_TEXT_MISMATCH": (Severity.HIGH, 30),
    "MAIL_LINK_IP_LITERAL": (Severity.MEDIUM, 15),
    "MAIL_LINK_CREDENTIALS": (Severity.MEDIUM, 15),
    "MAIL_LINK_SHORTENER": (Severity.LOW, 5),
    "MAIL_LINK_PUNYCODE": (Severity.MEDIUM, 15),
    "MAIL_LINK_RISKY_TLD": (Severity.LOW, 5),
    # Dangerous URI schemes run code or reach the local disk — the highest
    # weight in this group.
    "MAIL_LINK_DANGEROUS_SCHEME": (Severity.HIGH, 30),
}

_ATTACH_SEVERITY = {
    "MAIL_ATTACH_NAME_TRICK": (Severity.HIGH, 30),
    "MAIL_ATTACH_DOUBLE_EXT": (Severity.HIGH, 30),
    "MAIL_ATTACH_RISKY_TYPE": (Severity.MEDIUM, 15),
}

_LINK_REPUTATION_SEVERITY = (Severity.HIGH, 30)


class EmlPipeline(Pipeline):
    """Static analysis of the mail itself (attachments run as children)."""

    name = "eml"

    def analyze(self, ctx: AnalysisContext) -> list[Indicator]:
        facts = parse_mail(ctx.data)
        # Plain-text preview for the detail panel: headers, decoded TEXT body,
        # annotated links, attachment names. Never the HTML body (attacker-
        # controlled) — see core/mail_view. Set here so the dispatcher need not
        # parse the mail a second time.
        ctx.preview = render_mail(facts)
        # Structured form for the LIST view: the same verdicts the preview
        # prints, so a row can show them without reading the text.
        security = {**facts.auth_verdicts, "sender": sender_verdict(facts)}
        # Hat die Mail ueberhaupt einen From-Kopf? Ohne diesen Marker galt der
        # Absender als vorhanden, sobald das Dict gefuellt war — der Zweig
        # "Kein Absender" (0/ROT) war damit unerreichbar. Bei einem
        # PARSE-FEHLER bleibt der Marker weg: "nicht gelesen" ist keine
        # Aussage darueber, dass die Mail keinen Absender nennt.
        if not facts.parse_error:
            security["has_from"] = "1" if facts.from_addr else "0"
        ctx.mail_security = security
        # Die Linkliste fuer die Einzelbewertung im E-Mail-Panel. NICHT neu
        # extrahieren: parse_mail hat sie schon gefuellt, und ein zweiter
        # Durchlauf war in diesem Projekt bereits eine Ursache fuer doppelte
        # Arbeit (siehe core/mail_view).
        ctx.mail_links = list(facts.links)
        if facts.parse_error:
            return [
                self._indicator(
                    "MAIL_PARSE_WARN",
                    "E-Mail konnte nicht vollständig gelesen werden",
                    detail=facts.parse_error,
                    severity=Severity.INFO,
                    category=CAT_STRUCTURE,
                    weight=0,
                )
            ]

        out: list[Indicator] = []
        if facts.parts_truncated:
            out.append(
                self._indicator(
                    "MAIL_PARTS_TRUNCATED",
                    "E-Mail nur teilweise analysiert (MIME-Teile-Limit)",
                    detail=(
                        f"Die Mail enthält mehr als {config.MAIL_MAX_MIME_PARTS} "
                        "MIME-Teile. Nur dieser Teil wurde analysiert; weitere "
                        "Teile (Text, Links, Anhangsnamen) wurden NICHT geprüft. "
                        "Das Ergebnis ist unvollständig und nicht als 'sauber' "
                        "zu werten."
                    ),
                    severity=Severity.MEDIUM,
                    category=CAT_MAIL,
                    weight=25,
                )
            )
        out.extend(self._body_indicators(facts))
        out.extend(self._structure_indicators(facts))
        out.extend(self._link_indicators(facts))
        out.extend(self._attachment_indicators(facts))
        return out

    # -- body --------------------------------------------------------------- #

    def _body_indicators(self, facts) -> list[Indicator]:
        report = analyze_body(facts)
        out: list[Indicator] = []

        # "Does the text make sense?" — a broken/unreadable body must never be
        # reported as a clean result (same contract as the other pipelines).
        if not report.readable or not report.looks_meaningful:
            out.append(
                self._indicator(
                    "MAIL_BODY_UNREADABLE",
                    "Mailtext ist nicht sinnvoll lesbar",
                    detail=(
                        "; ".join(report.notes)
                        or "Der Textkörper ist unbrauchbar oder fehlt."
                    ),
                    severity=Severity.MEDIUM,
                    category=CAT_CONTENT,
                    weight=15,
                )
            )
        elif report.notes:
            out.append(
                self._indicator(
                    "MAIL_BODY_UNUSUAL",
                    "Mailtext ungewöhnlich aufgebaut",
                    detail="; ".join(report.notes),
                    severity=Severity.LOW,
                    category=CAT_CONTENT,
                    weight=5,
                )
            )

        subject_and_body = f"{facts.subject}\n{facts.text_body}".lower()
        lures = report.lure_hits or tuple(
            p for p in eml_analysis._LURE_PHRASES if p in subject_and_body
        )[:8]
        if lures:
            out.append(
                self._indicator(
                    "MAIL_BODY_LURE_PHRASES",
                    "Druck-/Zahlungsmuster im Text",
                    detail=(
                        "Formulierungen, die zu schnellem Handeln oder zur "
                        "Preisgabe von Daten drängen: " + ", ".join(lures)
                    ),
                    severity=Severity.MEDIUM,
                    category=CAT_CONTENT,
                    weight=15,
                )
            )

        if report.credential_hits:
            out.append(
                self._indicator(
                    "MAIL_BODY_CREDENTIALS",
                    "Abfrage sensibler Daten im Text",
                    detail=(
                        "Der Text spricht Zugangsdaten/Zahlungsmittel an: "
                        + ", ".join(report.credential_hits)
                    ),
                    severity=Severity.MEDIUM,
                    category=CAT_CONTENT,
                    weight=15,
                )
            )

        if report.hidden_text:
            out.append(
                self._indicator(
                    "MAIL_BODY_HIDDEN_TEXT",
                    "Versteckter Text im HTML-Teil",
                    detail=(
                        "Text ist unsichtbar formatiert (weiß, 0 px, "
                        "ausgeblendet oder transparent) — typisch für "
                        "Filter-Umgehung."
                    ),
                    severity=Severity.LOW,
                    category=CAT_CONTENT,
                    weight=5,
                )
            )
        if report.tracking_pixel:
            out.append(
                self._indicator(
                    "MAIL_HTML_TRACKING_PIXEL",
                    "Zählpixel (Öffnen wird gemeldet)",
                    detail=(
                        "Zählpixel im HTML-Teil (1x1) — das Öffnen der Mail "
                        "wird damit dem Absender gemeldet."
                    ),
                    severity=Severity.INFO,
                    category=CAT_CONTENT,
                    weight=0,
                )
            )
        return out

    # -- headers ------------------------------------------------------------ #

    def _structure_indicators(self, facts) -> list[Indicator]:
        out: list[Indicator] = []
        listen_notiz = False
        for kind, detail in analyze_structure(facts).findings:
            severity, weight = _STRUCTURE_SEVERITY.get(kind, (Severity.LOW, 5))
            # AUF EINER MAILINGLISTE sind drei dieser Befunde der NORMALZUSTAND
            # und duerfen kein Urteil tragen. GEMESSEN an 20 echten Ham-Mails
            # (SpamAssassin-Korpus): 4 waren ROT, allein an diesen Regeln.
            if facts.is_mailing_list and kind in _LISTEN_NORMAL:
                # EINMAL je Mail, nicht je Regel. Derselbe Grundsatz wie bei
                # GEN_ENTROPY, GEN_IOC und ARCH_MEMBER_ERROR: ein Artefakt,
                # eine Wertung. Drei Listenbefunde x 5 Punkte ergaben 15 und
                # schoben JEDE echte Listenmail ueber die GRUEN-Schwelle.
                #
                # ALLE bleiben entschaerft — nur der ERSTE traegt Punkte.
                # (Eine erste Fassung setzte die Bedingung "noch keine Notiz"
                # VOR die Entschaerfung; dann behielten die folgenden Befunde
                # ihr volles Gewicht 30/15/15 und echte Listenmails wurden
                # ROT. Gemessen, nicht ueberlegt.)
                severity = Severity.LOW
                weight = 5 if not listen_notiz else 0
                listen_notiz = True
                # NICHT auf 0 fuer ALLE — kein Freibrief.
                #
                # GEMESSEN (Audit-Befund 2): der Listen-Header UND die
                # Rueckkehradresse sind BEIDE Kopfzeilen derselben vom
                # Angreifer verfassten Datei. Wer beide setzt, senkte eine
                # BEC-Mail von GELB 40 auf GRUEN 10 — die Regel, die genau
                # diesen Fall fangen soll, fiel damit aus.
                #
                # Bei einer statischen .eml ist ALLES angreifergeschrieben;
                # eine Bestaetigung, die nur aus der Datei stammt, ist
                # grundsaetzlich faelschbar. Der erste Listenbefund traegt
                # deshalb 5 Punkte, die weiteren 0 — sichtbar bleiben alle,
                # und die Mail kommt auf ihren uebrigen Signalen ins Urteil.
            out.append(
                self._indicator(
                    kind,
                    _STRUCTURE_TITLES.get(kind, "Auffälliger Mail-Header"),
                    detail=detail,
                    severity=severity,
                    # Sender/envelope/Auth-Results are properties of the MAIL,
                    # not of any file content — grouping them under "Dateiaufbau"
                    # hid that the sender itself is the problem.
                    category=CAT_MAIL,
                    weight=weight,
                )
            )
        return out

    # -- links -------------------------------------------------------------- #

    def _auth_dns(self, facts) -> list[Indicator]:
        """SPF/DMARC über DNS prüfen — OPT-IN, Vorgabe aus.

        Die einzige Stelle, an der Malaz von sich aus das Netz fragt. Sie
        beantwortet, was die lokale Analyse offenlassen muss: ist die IP, mit
        der sich der Absender verbunden hat, für seine eigene Domain erlaubt?

        Drei Regeln, alle aus dem Grundsatz „nicht geprüft ist nicht sauber":

        * Aus, solange der Nutzer nicht zugestimmt hat.
        * Ein fehlgeschlagener Abruf ist **unbekannt**, nie „sauber" —
          ``MAIL_AUTH_DNS_UNKNOWN`` mit dem Grund.
        * „Nicht beurteilbar" (etwa ein ``include:``) wird als solches
          gemeldet und NICHT als erlaubt.
        """
        from ..core import dns_auth

        if not dns_auth.enabled():
            return []
        ip = facts.received_hops[-1].ip if facts.received_hops else ""
        bericht = dns_auth.check(
            ip,
            facts.return_path,
            facts.from_addr,
            dkim_selector=facts.dkim_selector,
            dkim_domain=facts.dkim_domain,
        )
        out: list[Indicator] = []

        if bericht.spf.error or bericht.dmarc.error or bericht.dkim.error:
            gruende = "; ".join(
                g
                for g in (
                    f"SPF: {bericht.spf.error}" if bericht.spf.error else "",
                    f"DMARC: {bericht.dmarc.error}" if bericht.dmarc.error else "",
                    f"DKIM: {bericht.dkim.error}" if bericht.dkim.error else "",
                )
                if g
            )
            out.append(
                self._indicator(
                    "MAIL_AUTH_DNS_UNKNOWN",
                    "DNS-Prüfung nicht möglich",
                    detail=(
                        f"{gruende} — die Absenderprüfung ist damit NICHT "
                        "gelaufen. Das heisst nicht, dass die Mail echt ist."
                    ),
                    severity=Severity.INFO,
                    category=CAT_IOC,
                    weight=0,
                )
            )

        if bericht.spf.ip_allowed is False:
            out.append(
                self._indicator(
                    "MAIL_SPF_IP_NOT_ALLOWED",
                    "Absender-IP nicht für die Domain freigegeben",
                    detail=(
                        f"Die IP {ip} steht nicht im SPF-Eintrag von "
                        f"'{dns_auth._registrable(facts.return_path or facts.from_addr)}'. "
                        "Ein Server, der für diese Domain senden darf, wäre dort "
                        "aufgeführt — die Mail stammt also nicht von einem "
                        "berechtigten Server dieser Domain."
                    ),
                    severity=Severity.HIGH,
                    category=CAT_IOC,
                    weight=30,
                )
            )

        teile = [
            f"SPF: {bericht.spf.verdict}",
            f"DMARC: {bericht.dmarc.verdict}",
            # DKIM: nur der SCHLUESSEL, nicht die Signatur. Ein widerrufener
            # Schluessel ist ein Befund — er heisst, dass die Signatur nicht
            # mehr gueltig sein kann.
            f"DKIM: {bericht.dkim.verdict}",
        ]
        if bericht.spf.detail:
            teile.append(bericht.spf.detail)
        if bericht.dmarc.policy in ("quarantine", "reject"):
            teile.append(
                "Die Domain verlangt, Mails ohne gültige Authentifizierung "
                f"zu behandeln ({bericht.dmarc.policy})."
            )
        out.append(
            self._indicator(
                "MAIL_AUTH_DNS",
                "Absenderprüfung über DNS",
                detail=(
                    " | ".join(teile)
                    + " — geprüft wurden die DNS-EINTRÄGE, nicht die "
                    "DKIM-Signatur selbst (dafür bräuchte es Kanonisierung und "
                    "Hashing) und nicht die DNSSEC-Kette."
                ),
                severity=Severity.INFO,
                category=CAT_IOC,
                weight=0,
            )
        )
        return out

    def _link_indicators(self, facts) -> list[Indicator]:
        out: list[Indicator] = []
        for kind, detail in summarize_links(facts.links):
            severity, weight = _LINK_SEVERITY.get(kind, (Severity.LOW, 5))
            out.append(
                self._indicator(
                    kind,
                    _LINK_TITLES.get(kind, "Auffälliger Link"),
                    detail=detail,
                    severity=severity,
                    category=CAT_IOC,
                    weight=weight,
                )
            )
        if facts.links:
            out.append(
                self._indicator(
                    "MAIL_LINKS_FOUND",
                    f"Links in der Mail: {len(facts.links)}",
                    detail=_defanged_link_list(facts.links),
                    severity=Severity.INFO,
                    category=CAT_IOC,
                    weight=0,
                )
            )
        out.extend(self._reputation_indicators(facts))
        out.extend(self._auth_dns(facts))
        return out

    # -- link reputation (opt-in, hash-only) -------------------------------- #

    def _reputation_indicators(self, facts) -> list[Indicator]:
        """Check the link hashes against the local list and/or a provider.

        Two independent sources: the local URL blocklist (offline, no opt-in
        needed) and the strictly opt-in online provider. Without either this
        does nothing at all. For the provider only SHA-256 hashes are
        transmitted; a failed lookup is reported as an INFO note — never as
        "clean".
        """
        if not facts.links:
            return []
        from ..core import url_reputation

        if not (
            url_reputation.local_blocklist_enabled() or url_reputation.enabled()
        ):
            return []
        result = url_reputation.lookup(facts.links)
        out: list[Indicator] = []
        if result.error:
            out.append(
                self._indicator(
                    "MAIL_REPUTATION_WARN",
                    "Reputations-Abgleich fehlgeschlagen",
                    detail=(
                        "Der Link-Abgleich konnte nicht durchgeführt werden — "
                        "die Link-Bewertung ist unvollständig. " + result.error
                    ),
                    severity=Severity.INFO,
                    category=CAT_IOC,
                    weight=0,
                )
            )
            # Fall through: local blocklist hits were established WITHOUT the
            # network and must survive a provider outage. Returning here would
            # erase findings the outage has nothing to do with.
            if not result.hits:
                return out
        if result.hits:
            by_hash = {
                url_reputation.url_hash(link.url): link for link in facts.links
            }
            for digest, status in result.hits.items():
                verdict, reason = url_reputation.status_to_finding(status)
                link = by_hash.get(digest)
                if link is not None:
                    link.reputation = verdict
                out.append(
                    self._indicator(
                        "MAIL_LINK_REPUTATION",
                        f"Link als {verdict} gemeldet",
                        detail=(
                            # "reason" liefert den Satz OHNE Punkt; die
                            # Endung setzt diese Zeile. Vorher stand hier ein
                            # zweiter Punkt ("Blocklist.. Betroffener Link").
                            f"{reason.rstrip('.')}. Betroffener Link: "
                            f"{defang_url(link.url) if link else digest}"
                        ),
                        severity=_LINK_REPUTATION_SEVERITY[0],
                        category=CAT_IOC,
                        weight=_LINK_REPUTATION_SEVERITY[1],
                    )
                )
        else:
            from ..core import url_reputation as _ur

            if _ur.enabled():
                source = "lokalem Abgleich und Reputationsdienst"
                how = "nur als Hash übermittelt"
            else:
                source = "lokaler URL-Blocklist"
                how = "ohne Netzwerkzugriff"
            out.append(
                self._indicator(
                    "MAIL_REPUTATION_CLEAN",
                    "Keine Link-Warnung",
                    detail=(
                        f"{len(facts.links)} Link(s) gegen {source} geprüft "
                        f"({how}) — kein Treffer."
                    ),
                    severity=Severity.INFO,
                    category=CAT_IOC,
                    weight=0,
                )
            )
        return out

    # -- attachments -------------------------------------------------------- #

    def _attachment_indicators(self, facts) -> list[Indicator]:
        """Flag dangerous attachment NAMES (contents are scanned as children)."""
        names = list(facts.attachment_names or [])
        out: list[Indicator] = []
        for kind, detail in risky_attachment_names(names):
            severity, weight = _ATTACH_SEVERITY.get(kind, (Severity.MEDIUM, 15))
            out.append(
                self._indicator(
                    kind,
                    _ATTACH_TITLES.get(kind, "Riskanter Anhang"),
                    detail=detail,
                    severity=severity,
                    # Attachment-name tricks belong to the mail, not to a file's
                    # content — "Anhang tarnt seinen Dateityp" under "Inhalt" was
                    # the wrong shelf.
                    category=CAT_MAIL,
                    weight=weight,
                )
            )
        if names:
            out.append(
                self._indicator(
                    "MAIL_ATTACHMENTS_FOUND",
                    f"Anhänge in der Mail: {len(names)}",
                    detail=", ".join(names[:10]),
                    severity=Severity.INFO,
                    category=CAT_MAIL,
                    weight=0,
                )
            )
        return out


_STRUCTURE_TITLES = {
    "MAIL_DISPLAY_NAME_SPOOF": "Absendername passt nicht zur Domain",
    "MAIL_DISPLAY_ADDR_MISMATCH": "Anzeigename nennt eine fremde Adresse",
    "MAIL_AUTH_CLAIMED_SPOOF": "Authentifizierung behauptet, Absender passt nicht",
    "MAIL_DISPLAY_NAME_MIXED_SCRIPT": "Absendername mischt Schriftsysteme",
    "MAIL_LOOKALIKE_DOMAIN": "Absenderdomain imitiert eine Marke",
    "MAIL_REPLY_TO_MISMATCH": "Antwortadresse weicht vom Absender ab",
    "MAIL_RETURN_PATH_MISMATCH": "Bounce-Adresse weicht vom Absender ab",
    "MAIL_AUTH_FAIL": "Mail-Authentifizierung fehlgeschlagen",
    "MAIL_AUTH_ABSENT": "Absenderauthentifizierung nicht nachgewiesen",
    "MAIL_AUTH_UNVERIFIABLE": "Authentifizierung nicht beurteilbar",
    "MAIL_HEADER_TRUNCATED": "Kopfzeilenblock gekürzt",
    "MAIL_NO_RECEIVED": "Keine Server-Kette (Received) vorhanden",
    "MAIL_NO_MESSAGE_ID": "Keine Message-ID vorhanden",
    # Ohne Eintrag steht im Fenster der Sammeltitel "Auffälliger Mail-Header" —
    # für eine fehlende DMARC-Ausrichtung ist das schlicht falsch. Der Titel
    # ist das, was der Nutzer liest.
    "MAIL_AUTH_CLAIM_UNBACKED": "Auth-Behauptung ohne Deckung in der Server-Kette",
    "MAIL_SENDER_DOMAIN_BLOCKED": "Absenderdomain steht auf der Phishing-Liste",
    "MAIL_SENDER_IP_BLOCKED": "Absender-IP aus bekanntem Angreifer-Netz",
    "DOMAIN_BLOCKLIST_UNAVAILABLE": "Lokale Domain-Blockliste nicht lesbar",
    "IP_BLOCKLIST_UNAVAILABLE": "Lokale IP-Blockliste nicht lesbar",
    "MAIL_DMARC_ALIGNMENT_FAIL": "DMARC-Ausrichtung fehlt",
    "MAIL_DKIM_DOMAIN_MISMATCH": "DKIM-Signatur deckt eine andere Domain",
    "MAIL_FILTER_CLAIM": "Filterurteil ohne Deckung in der Kette",
    "MAIL_RECEIVED_PRIVATE_IP": "Absenderstation mit privater IP",
    "MAIL_RECEIVED_TIME_ANOMALY": "Zeitstempel passt nicht zum Versand",
    "MAIL_RECEIVED_WEAK_TLS": "Veraltete Transportverschlüsselung (Angabe)",
    "MAIL_MESSAGE_ID_DOMAIN": "Message-ID stammt von fremder Domain",
    "MAIL_MESSAGE_ID_ODD": "Message-ID ohne Domain",
}

_LINK_TITLES = {
    "MAIL_LINK_DANGEROUS_SCHEME": "Link führt Code aus / greift lokal zu",
    "MAIL_LINK_TEXT_MISMATCH": "Linktext passt nicht zum Ziel",
    "MAIL_LINK_IP_LITERAL": "Link zeigt auf eine IP-Adresse",
    "MAIL_LINK_SHORTENER": "Link über einen Kurzdienst",
    "MAIL_LINK_PUNYCODE": "Link mit Punycode-Domain",
    "MAIL_LINK_RISKY_TLD": "Link auf riskanter Domain-Endung",
    "MAIL_LINK_CREDENTIALS": "Link mit eingebetteten Zugangsdaten",
}

_ATTACH_TITLES = {
    "MAIL_ATTACH_NAME_TRICK": "Anhangsname tarnt den Typ (Steuerzeichen)",
    "MAIL_ATTACH_DOUBLE_EXT": "Anhang tarnt seinen Dateityp",
    "MAIL_ATTACH_RISKY_TYPE": "Anhang ist direkt ausführbar",
}


def _defanged_link_list(links, limit: int = 10) -> str:
    """List links with the scheme broken so nothing is clickable in a report."""
    lines = []
    for link in links[:limit]:
        safe = defang_url(link.url)
        rep = f" [{link.reputation}]" if link.reputation else ""
        lines.append(f"{safe}{rep}")
    if len(links) > limit:
        lines.append(f"… und {len(links) - limit} weitere")
    return "\n".join(lines)
