"""Beißt die Testsuite noch? — Mutationen aus dem Audit als ausführbare Prüfung.

Warum es dieses Skript gibt
===========================

In elf Audit-Runden sind dieselben drei Fehlerklassen immer wieder aufgetreten,
und keine davon wurde von der Suite bemerkt — sie war in allen drei Fällen grün:

1. **Ein Test, der nichts prüft.** Die Tiefen-Fixtures der Runden 6-10
   verschachtelten gar nicht (sie deklarierten den Token, den sie auch
   delimitierten). Der stdlib-Parser sah darin Tiefe 2 statt 400, der Schätzer
   meldete 257 — und der Test lief grün, weil er die Schätzung gegen sich
   selbst prüfte.
2. **Eine Mutation, die die falsche Stelle trifft.** Ein ``replace(..., 1)``
   traf den ersten statt des gemeinten Vorkommens; der Test blieb grün und
   sah aus wie ein schwacher Test.
3. **Eine Messung im falschen Zustand.** Die quadratische Parse-Kurve ist nur
   oberhalb der Rekursionsgrenze sichtbar; eine Messung mit dem Standardlimit
   ließ den Guard kurzzeitig wie unnötig aussehen.

Alle drei haben eines gemeinsam: **die Suite war grün und die Aussage falsch.**
Ein grüner Lauf beweist nur, dass die Tests laufen — nicht, dass sie etwas
festhalten. Dieses Skript prüft das Gegenteil: es stellt je einen Fehler wieder
her, den das Projekt nachweislich schon einmal hatte, und verlangt, dass ein
bestimmter Test dabei **rot** wird.

Aufruf
======

    .venv/Scripts/python.exe scripts/check_tests_bite.py            # alle
    .venv/Scripts/python.exe scripts/check_tests_bite.py --list     # nur zeigen
    .venv/Scripts/python.exe scripts/check_tests_bite.py -k kappung

Exit-Code 0 = jede Mutation macht ihren Test rot. Exit-Code 1 = mindestens eine
nicht, und dann ist der Test wertlos, nicht die Mutation.

Mutiert wird eine **Temp-Kopie** des Repos, nie der Arbeitsbaum. Die erste
Fassung schrieb die Produktivdatei um und stellte sie im ``finally`` zurueck —
das deckt Ausnahmen, nicht einen harten Abbruch, und die Commit-Gewohnheit hier
ist ``git add -A && git commit``: eine liegengebliebene Mutation waere von genau
der Pruefung eingecheckt worden, die sie verhindern soll.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# The hosted CI has no ``.venv``: it installs into the runner's interpreter.
# The hard-coded venv path made every mutation fail with FileNotFoundError
# instead of running its test — a red that says nothing about the test.
PY = ROOT / ".venv" / "Scripts" / "python.exe"
if not PY.is_file():
    PY = Path(sys.executable)


@dataclass(frozen=True)
class Mutation:
    """Ein Fehler, den das Projekt schon hatte, und der Test, der ihn fängt."""

    name: str
    file: str
    old: str
    new: str
    test: str
    why: str


# Jede Mutation ist eine echte Regression aus einer Audit-Runde. Der Text muss
# WOERTLICH im Zielzustand vorkommen — das Skript prüft das und meldet sonst
# "Anker nicht gefunden", statt still nichts zu tun (genau der Fehler aus
# Klasse 2: eine Mutation, die nirgends ankommt, sieht wie ein grüner Test aus).
MUTATIONS: tuple[Mutation, ...] = (
    Mutation(
        name="kappung-doppelt-gezaehlt",
        file="src/malaz/core/archive.py",
        old="                if header_error:\n",
        new="                if False:\n",
        test="tests/test_archive.py::test_tar_truncation_is_counted_once",
        why=(
            "Runde 7: Container-Notiz (25) und Mitgliedsfehler (25) derselben "
            "Kappung ergaben 50 = ANCHOR_CRITICAL_SCORE — ein abgeschnittener "
            "Download galt als boesartig."
        ),
    ),
    Mutation(
        name="kappung-im-kopfblock-still",
        file="src/malaz/core/archive.py",
        old="            header_error = _tar_truncation_note(tf, data, kind)\n",
        new='            header_error = ""\n',
        test="tests/test_archive.py::test_tar_cut_inside_a_header_block_is_reported",
        why=(
            "Runde 7: tarfile schluckt TruncatedHeaderError bei offset != 0 und "
            "meldet ein sauberes Archivende — der Scan meldete GRUEN 0, "
            "waehrend ein Byte spaeter ROT 50 kam."
        ),
    ),
    Mutation(
        name="av-rabatt-hebt-auf-gruen",
        file="src/malaz/core/scoring.py",
        old="        score = max(score, config.SCORE_GREEN_MAX + 1)\n",
        new="        pass\n",
        test="tests/test_scoring.py::test_clean_av_votes_cannot_create_a_green_verdict",
        why=(
            "Runde 10: zwei saubere AV-Stimmen (Rabatt 8) drueckten eine "
            "'ungeprueft'-Notiz von 25 auf 17 = GRUEN — die Arbeit der Runden "
            "2-9 war damit entwertet, sobald die Engines liefen."
        ),
    ),
    Mutation(
        name="tiefenschaetzung-blind",
        file="src/malaz/core/email_extract.py",
        old="    declared = _mime_declared(data)\n",
        new="    declared = set()\n",
        test="tests/test_email_rtf.py::test_declaration_spellings_cannot_hide_the_nesting",
        why=(
            "Runde 7: die Deklarationssuche lief an den Schreibweisen des "
            "boundary vorbei (RFC2231, >70 Byte, quoted mit Semikolon, auf -- "
            "endend) — 2048 Schichten in 8,00 s statt 0,11 s."
        ),
    ),
    Mutation(
        name="cr-only-umgehung",
        file="src/malaz/core/email_extract.py",
        old='        for line in chunk.replace(b"\\r\\n", b"\\n").split(b"\\r"):\n',
        new='        for line in chunk.split(b"\\n"):\n',
        test="tests/test_email_rtf.py::test_cr_only_line_endings_reach_the_same_verdict",
        why=(
            "Runde 11: der Wechsel auf lazy Iteration trennt nur an \\n. Ohne "
            "die zusaetzliche CR-Aufteilung ist eine CR-only-Mail fuer die "
            "Suche EINE Zeile, declared bleibt leer, und der Parser laeuft mit "
            "der vollen quadratischen Kurve."
        ),
    ),
    Mutation(
        name="drain-materialisiert-unbegrenzt",
        file="src/malaz/core/dispatcher.py",
        old=(
            "                    tail_unread = True\n"
            "                    break\n"
            "                budget -= len(payload) if payload else 0\n"
        ),
        new="                    tail_unread = True\n                    break\n                pass\n",
        test="tests/test_dispatcher.py::test_drain_bounds_the_materialized_payload",
        why=(
            "Runde 3: der Nachlauf zog bis ans Iterator-Ende und holte jedes "
            "Mitglied in den Speicher — bei 200-KB-Mitgliedern 2 GB statt "
            "8,6 MB."
        ),
    ),
    Mutation(
        name="skip-ohne-gewicht",
        file="src/malaz/core/dispatcher.py",
        old=(
            '                        rule_id="ARCH_MEMBER_SKIP",\n'
            '                        title="Mitglieder nicht gescannt — Inhalt ungeprüft",\n'
            '                        detail=(\n'
            '                            f"Limit {config.MAX_RECURSIVE_MEMBERS} rekursiv "\n'
            '                            "gescannter Mitglieder erreicht; der Rest dieses "\n'
            '                            "Containers wurde NICHT analysiert. Der Inhalt ist "\n'
            '                            "unbekannt, nicht sauber — ein schädliches Mitglied "\n'
            '                            "hinter dieser Grenze bleibt unentdeckt."\n'
            '                        ),\n'
            '                        # Weight, not 0: skipping members removes the whole\n'
            '                        # content stage from the verdict. With weight 0 a\n'
            '                        # payload placed behind enough harmless entries scored\n'
            '                        # GREEN — measured: the same archive scored RED 90 with\n'
            '                        # the payload first and YELLOW 30 with it last.\n'
            '                        severity=Severity.MEDIUM,\n'
            '                        category=CAT_ARCHIVE,\n'
            '                        weight=25,'
        ),
        new=(
            '                        rule_id="ARCH_MEMBER_SKIP",\n'
            '                        title="Mitglieder nicht gescannt — Inhalt ungeprüft",\n'
            '                        detail=(\n'
            '                            f"Limit {config.MAX_RECURSIVE_MEMBERS} rekursiv "\n'
            '                            "gescannter Mitglieder erreicht; der Rest dieses "\n'
            '                            "Containers wurde NICHT analysiert. Der Inhalt ist "\n'
            '                            "unbekannt, nicht sauber — ein schädliches Mitglied "\n'
            '                            "hinter dieser Grenze bleibt unentdeckt."\n'
            '                        ),\n'
            '                        severity=Severity.MEDIUM,\n'
            '                        category=CAT_ARCHIVE,\n'
            '                        weight=0,'
        ),
        test="tests/test_dispatcher.py::test_skipped_members_are_not_green",
        why=(
            "Runde 2: ARCH_MEMBER_SKIP trug Gewicht 0 — eine Nutzlast hinter "
            "genug Attrappen blieb damit entlastend (GELB 30 gegen ROT 90)."
        ),
    ),
    Mutation(
        name="office-stomping-nicht-gemeldet",
        file="src/malaz/pipelines/office_pipeline.py",
        old="        if not stomped:\n            return []\n",
        new="        if True:\n            return []\n",
        test="tests/test_office_extra.py::test_vba_stomping_is_a_high_finding",
        why=(
            "Office fuehrt den P-Code aus, nicht den sichtbaren Quelltext: "
            "ohne die Meldung sieht ein gestompftes Dokument aus wie ein "
            "harmloses Makro — genau die Umgehung, die der Befund aufdeckt."
        ),
    ),
    Mutation(
        name="office-vba-dekodierung-aus",
        file="src/malaz/pipelines/office_pipeline.py",
        old="                if decoded:\n",
        new="                if False:\n",
        test="tests/test_office_extra.py::test_hidden_base64_string_becomes_visible",
        why=(
            "Ohne die Dekodierung bleibt die eingebettete Base64-Nutzlast "
            "unsichtbar: der Quelltext enthaelt nur den kodierten Block, "
            "jeder Suchbegriff laeuft daran vorbei."
        ),
    ),
    Mutation(
        name="office-remote-template-aus",
        file="src/malaz/pipelines/office_pipeline.py",
        old="        if templates:\n",
        new="        if False:\n",
        test="tests/test_office_extra.py::test_remote_template_is_a_high_finding",
        why=(
            "Remote Template Injection laeuft ohne Makro: faellt die "
            "attachedTemplate-Meldung weg, bleibt die Datei fuer den Nutzer "
            "unauffaellig, obwohl Office beim Oeffnen Code nachlaedt."
        ),
    ),
    Mutation(
        name="office-externe-beziehung-aus",
        file="src/malaz/pipelines/office_pipeline.py",
        old="        if others:\n",
        new="        if False:\n",
        test="tests/test_office_extra.py::test_external_relation_without_template_is_low",
        why=(
            "Ohne die allgemeine externe Beziehung verschwindet der Hinweis "
            "auf nachgeladene Inhalte (externalLink, oleObject, Bild)."
        ),
    ),
    Mutation(
        name="office-metadaten-aus",
        file="src/malaz/pipelines/office_pipeline.py",
        old="        if not parts:\n            return []\n",
        new="        if True:\n            return []\n",
        test="tests/test_office_extra.py::test_ooxml_metadata_is_listed_as_information",
        why=(
            "Die Verfasser-Angaben sind der einzige Hinweis, der einem Laien "
            "ohne Malaz verborgen bleibt (angebliche Bank, Autor Privatnutzer)."
        ),
    ),
    Mutation(
        name="rohbyte-namespace-filter-aus",
        file="src/malaz/core/binary_iocs.py",
        old=(
            "        if is_namespace_host(value):\n"
            "            continue\n"
            "        url_hosts.add(host_of_url(value))\n"
        ),
        new="        url_hosts.add(host_of_url(value))\n",
        test="tests/test_binary_iocs.py::test_namespace_urls_are_not_reported",
        why=(
            "Ohne den Namespace-Filter meldet jedes Office-Dokument und jede "
            "PDF mit XMP-Block seine Schema-URLs (w3.org, purl.org, "
            "ns.adobe.com) als Serveradresse — der eine echte C2-Treffer geht "
            "im Rauschen unter."
        ),
    ),
    Mutation(
        name="rohbyte-url-host-nicht-gegen-liste",
        file="src/malaz/core/binary_iocs.py",
        old="        return _host_is_blocked(host_of_url(value), domains, nets)\n",
        new="        return False\n",
        test="tests/test_binary_iocs.py::test_split_uses_domain_ip_and_url_lists",
        why=(
            "Eine C2-URL wird nur über ihren HOST erkannt (die Domain-Liste "
            "führt die Absender-/C2-Namen). Fällt der Host-Vergleich weg, ist "
            "die Adresse im Binärinhalt nur noch eine Information mit Gewicht "
            "0 statt eines Befunds."
        ),
    ),
    Mutation(
        name="rohbyte-stufe-nicht-verdrahtet",
        file="src/malaz/pipelines/generic_pipeline.py",
        # Der Anker muss EINDEUTIG sein. GEMESSEN: nachdem die Rohbyte-Stufe
        # einen zweiten Aufruf bekam (der Entropie-Zweig fuer Typ "unknown"),
        # passte "out.extend(self._binary_iocs(ctx))" zweimal — die Mutation
        # traf nichts mehr und meldete "Anker nicht eindeutig".
        #
        # Gezielt ist der Aufruf im elif-Zweig (lnk/url ausgeschlossen): DER
        # schliesst die dokumentierte Luecke. Der andere ist der Duplikat-
        # schutz im Textzweig — ihn zu mutieren wuerde eine andere Verdrahtung
        # pruefen und trotzdem gruen melden.
        #
        # GEMESSEN (AP8): der Anker endet jetzt auf der url-Begruendung, weil
        # der Zweig zusaetzlich .url ausnimmt; die alte lnk-Kommentarzeile
        # steht unveraendert, ist aber nicht mehr die letzte vor dem Aufruf.
        old=(
            "            # shows the target once, with its scheme/UNC/IP"
            " classification.\n"
            "            out.extend(self._binary_iocs(ctx))\n"
        ),
        new=(
            "            # shows the target once, with its scheme/UNC/IP"
            " classification.\n"
            "            pass\n"
        ),
        test="tests/test_binary_iocs.py::test_binary_formats_get_the_address_check",
        why=(
            "Genau die Luecke, die diese Stufe schliesst: PE/PDF/OLE/Bild/"
            "Archiv wurden gar nicht auf Adressen geprueft, obwohl die "
            "C2-Adresse dort steht."
        ),
    ),
    Mutation(
        name="capa-ohne-binary-gestartet",
        file="src/malaz/analysis/capa.py",
        old="            if path.is_file():\n",
        new="            if True:\n",
        test="tests/test_capa.py::test_missing_binary_is_unavailable_and_never_invoked",
        why=(
            "capa ist wie DIE/ClamAV/7-Zip ein Werkzeug, das der NUTZER "
            "installiert. Ohne die Existenzpruefung gilt der erste "
            "Standardpfad als vorhanden: Malaz startet bei jedem PE einen "
            "Prozess, der gar nicht existiert — statt sauber zu ueberspringen."
        ),
    ),
    Mutation(
        name="capa-kaputtes-json-ausnahme",
        file="src/malaz/analysis/capa.py",
        old="    except (ValueError, RecursionError):\n",
        new="    except RecursionError:\n",
        test="tests/test_capa.py::test_broken_json_becomes_a_skip_reason",
        why=(
            "capa schreibt bei gepackten/unbekannten Formaten Warnungen und "
            "leeres JSON. Faellt der Parse-Schutz weg, reisst eine solche "
            "Ausgabe die ganze PE-Pipeline mit — statt als Uebersprung "
            "gemeldet zu werden."
        ),
    ),
    Mutation(
        name="capa-regeldeckel-aus",
        file="src/malaz/analysis/capa.py",
        old="        if len(result.rules) >= config.CAPA_MAX_RULES:\n",
        new="        if False:\n",
        test="tests/test_capa.py::test_rule_cap_is_applied",
        why=(
            "Die JSON-Ausgabe beschreibt eine angreiferkontrollierte Datei. "
            "Ohne den Deckel bestimmt ein praepariertes Sample, wie viele "
            "Regeln die Anwendung in den Speicher holt und im Detail anzeigt."
        ),
    ),
    Mutation(
        name="capa-uebersetzung-aus",
        file="src/malaz/analysis/capa.py",
        old='        hit = _NAMESPACE_DE.get("/".join(parts[:depth]))\n',
        new="        hit = None\n",
        test="tests/test_capa.py::test_translation_table_is_applied",
        why=(
            "capa-Regelnamen sind englisch und technisch ('persist via Run "
            "key'). Ohne die Uebersetzung des Namensraums liest der Nutzer "
            "genau die Fachsprache, die Malaz uebersetzen soll."
        ),
    ),
    Mutation(
        name="capa-meldet-jeden-abbruch",
        file="src/malaz/pipelines/pe_pipeline.py",
        old="        if not result.scanned and not result.understood:\n",
        new="        if not result.scanned:\n",
        test="tests/test_capa.py::test_ran_but_found_nothing_is_not_reported_as_a_failure",
        why=(
            "scanned=False unterscheidet die Faelle NICHT: ein Lauf ohne "
            "Treffer landet im selben Zweig wie ein Ausfall. Ohne understood "
            "stuende auf JEDEM gepackten PE 'capa konnte nicht laufen'."
        ),
    ),
    Mutation(
        name="riskm_marken-wieder-als-literal",
        file="src/malaz/gui/mail_panel.py",
        old="        mark = RISK_MARKS[score.color]\n",
        new="        mark = {'green': '\\u2714', 'yellow': '\\u26a0', 'red': '\\u2716'}[score.color]\n",
        test="tests/test_gui.py::test_risk_mark_cannot_drift_between_panel_and_card",
        why=(
            "Die Zeichen-Abbildung stand wortgleich an vier Stellen. Beim "
            "naechsten Mal laeuft sie auseinander."
        ),
    ),
    Mutation(
        name="viewer-liest-unbegrenzt",
        file="src/malaz/gui/mail_viewer_dialog.py",
        old="                data = handle.read(config.MAX_READ_SIZE)\n",
        new="                data = self._path.read_bytes()[: config.MAX_READ_SIZE]\n",
        test="tests/test_mail_viewer.py::test_viewer_does_not_read_the_whole_file_into_memory",
        why=(
            "read_bytes() holt die Datei KOMPLETT in den Speicher und "
            "schneidet erst danach. Der Knopf erscheint schon bei der Endung."
        ),
    ),
    Mutation(
        name="faehigkeiten-titel-nur-einmal",
        file="src/malaz/gui/detail_view.py",
        old=(
            "            self._btn_tab_capa.setText(\n"
            "                pick(\n"
            '                    f"Fähigkeiten ({len(result.capa_capabilities)})",\n'
            '                    f"Capabilities ({len(result.capa_capabilities)})",\n'
            '                    f"Yetenekler ({len(result.capa_capabilities)})",\n'
            "                    lang=lang,\n"
            "                )\n"
            "            )\n"
        ),
        new="            pass\n",
        test="tests/test_mail_viewer.py::test_capability_tab_title_follows_the_selection",
        why=(
            "Der Titel wurde nur beim ersten Anlegen gesetzt. Danach stand "
            "'Faehigkeiten (8)' ueber einem Panel mit 3 Eintraegen."
        ),
    ),
    Mutation(
        name="clamav-dateilimit-aus",
        file="src/malaz/analysis/clamav.py",
        old="            if limit and target_size > limit:\n",
        new="            if False and limit and target_size > limit:\n",
        test="tests/test_clamav.py::test_clamd_size_limit_is_not_clean",
        why=(
            "clamd meldet eine uebersprungene Datei als OK; ohne die "
            "Vorpruefung wird daraus ein falsches CLAMAV_CLEAN."
        ),
    ),
    Mutation(
        name="clamd-uebergabe-aus",
        file="src/malaz/analysis/clamav.py",
        old=(
            "            if reachable:\n"
            "                self._clamd_conf_used = conf\n"
            "                self.binary = self._clamdscan\n"
        ),
        new=(
            "            if False and reachable:\n"
            "                self._clamd_conf_used = conf\n"
            "                self.binary = self._clamdscan\n"
        ),
        test="tests/test_clamav.py::test_refresh_state_upgrades_to_daemon",
        why=(
            "Die Instanz bleibt nach dem Daemon-Start auf clamscan; die GUI "
            "zahlt weiter 19 s statt 0,04 s pro Datei."
        ),
    ),
    Mutation(
        name="yara-fehler-als-sauber",
        file="src/malaz/core/engine_verdicts.py",
        old="    if generic_error is not None:\n",
        new="    if False and generic_error is not None:\n",
        test="tests/test_engine_verdicts.py::test_generic_pipeline_error_marks_yara_not_checked",
        why=(
            "Ein GENERIC_ERROR heisst, dass die YARA-Stufe nicht lief; "
            "'keine Treffer' waere ein Freispruch ohne Pruefung."
        ),
    ),
    Mutation(
        name="score-zerlegung-nur-eltern",
        file="src/malaz/gui/score_breakdown.py",
        old="        for indicator in result.all_indicators():\n",
        new="        for indicator in result.indicators:\n",
        test="tests/test_engine_ui.py::test_score_breakdown_includes_child_findings",
        why=(
            "Der Score kommt aus all_indicators(); die Zerlegung muss dieselbe "
            "Quelle lesen, sonst fehlt der Befund des Archivmitglieds."
        ),
    ),
    Mutation(
        name="batch-summary-nur-eltern",
        file="src/malaz/gui/batch_summary.py",
        old="            for ind in r.all_indicators():\n",
        new="            for ind in r.indicators:\n",
        test="tests/test_engine_ui.py::test_batch_summary_uses_child_rules",
        why=(
            "Die Top-Regel eines Archivs/Anhangs steht im Kind; ohne "
            "all_indicators() fehlt sie in der Batch-Zusammenfassung."
        ),
    ),
    Mutation(
        name="tooltip-html-nicht-escaped",
        file="src/malaz/gui/engine_strip.py",
        old='        self.setToolTip(escape_tooltip(tooltip or f"{name}: {value} — {subtitle}"))\n',
        new='        self.setToolTip(tooltip or f"{name}: {value} — {subtitle}")\n',
        test="tests/test_engine_ui.py::test_engine_chip_escapes_tooltip_html",
        why=(
            "Qt-Tooltips rendern AutoText; rohe Defender-/ClamAV-Ausgabe mit "
            "einem Dateinamen ist ein HTML-Sink."
        ),
    ),
    Mutation(
        name="zeitbudget-flag-aus",
        file="src/malaz/core/filesource.py",
        old=(
            "                and time.monotonic() >= deadline\n"
            "            ):\n"
            "                self.budget_exceeded = True\n"
        ),
        new=(
            "                and time.monotonic() >= deadline\n"
            "            ):\n"
            "                self.budget_exceeded = False\n"
        ),
        test="tests/test_large_files.py::test_time_budget_stops_streaming_and_is_visible",
        why=("Ohne das Flag sieht ein nach 120 s gestoppter Scan aus wie eine vollstaendige Analyse."),
    ),
    Mutation(
        name="pdf-link-gewicht-falsch",
        file="src/malaz/pipelines/pdf_pipeline.py",
        old=(
            "                    severity=Severity.INFO,\n"
            "                    category=CAT_IOC,\n"
            "                    weight=0,\n"
            "                )\n"
            "            )\n"
            "        return out"
        ),
        new=(
            "                    severity=Severity.INFO,\n"
            "                    category=CAT_IOC,\n"
            "                    weight=20,\n"
            "                )\n"
            "            )\n"
            "        return out"
        ),
        test="tests/test_pdf_links.py::test_legitimate_link_stays_green",
        why=(
            "Spec 006 (PDF-001): PDF_LINK mit Gewicht 20 wuerde jede normale "
            "Rechnung mit Website-Link auf GELB heben."
        ),
    ),
    Mutation(
        name="pdf-link-blocklist-aus",
        file="src/malaz/pipelines/pdf_pipeline.py",
        old="        blocked, plain, unavailable = split_blocked_iocs(hits)\n",
        new="        blocked, plain, unavailable = [], hits, []\n",
        test="tests/test_pdf_links.py::test_utf16_without_bom_is_decoded",
        why=(
            "Spec 006 (PDF-001): ohne split_blocked_iocs im PDF-Link-Pfad "
            "faellt ein UTF-16-Phishing-Link wieder still auf GRUEN 0."
        ),
    ),
    Mutation(
        name="pdf-walk-incomplete-aus",
        file="src/malaz/pipelines/pdf_pipeline.py",
        old='        graph_incomplete = bool(collect_uris and not visited and not state["truncated"])\n',
        new="        graph_incomplete = False\n",
        test="tests/test_pdf_links.py::test_graph_incomplete_when_pages_and_root_unreadable",
        why=(
            "Spec 006 (PDF-001): ohne graph_incomplete bleiben unlesbare "
            "Seitenbaum-/Root-Objekte beim Link-Scan still unbemerkt."
        ),
    ),
    Mutation(
        name="i18n-en-key-fehlt",
        file="src/malaz/i18n_catalog.py",
        old='    "menu.file": "&File",\n',
        new="",
        test="tests/test_i18n.py::test_catalog_key_and_placeholder_parity",
        why=(
            "Spec 011 (UI-006): ein fehlender Schluessel im englischen Katalog "
            "muss vom Paritaetstest sofort gefangen werden."
        ),
    ),
    Mutation(
        name="i18n-tr-key-fehlt",
        file="src/malaz/i18n_catalog_tr.py",
        old='    "options.language.tr": "Türkçe",\n',
        new="",
        test="tests/test_i18n.py::test_catalog_key_and_placeholder_parity",
        why=(
            "Spec 011 (UI-006): ein fehlender Schluessel im tuerkischen Katalog "
            "muss vom Paritaetstest sofort gefangen werden."
        ),
    ),
    Mutation(
        name="i18n-en-unchecked-zu-clean",
        file="src/malaz/i18n_catalog.py",
        old='    "state.unk": "Unchecked",\n',
        new='    "state.unk": "Clean",\n',
        test="tests/test_i18n.py::test_en_and_tr_completeness_invariant_gui_and_html",
        why=(
            "Spec 011 (UI-006): die Vollstaendigkeits-Invariante gilt in allen "
            "Sprachen — Unchecked darf niemals als Clean erscheinen."
        ),
    ),
)


def _apply(text: str, mutation: Mutation) -> str | None:
    """Ersetzt genau ein Vorkommen — oder meldet, dass der Anker fehlt."""
    if text.count(mutation.old) != 1:
        return None
    return text.replace(mutation.old, mutation.new, 1)


# Eine FAILED-Zeile der Kurzzusammenfassung nennt die Node-ID.
_FAILED_LINE = re.compile(r"^FAILED\s+(\S+)", re.MULTILINE)
_ONE_FAILED = re.compile(r"(?<!\d)1 failed\b")


def _caught(returncode: int, output: str, nodeid: str) -> tuple[bool, str]:
    """Hat pytest den ANGEFORDERTEN Test ausgefuehrt und ist er rot geworden?

    Ein Exit ungleich 0 ist kein Fang. pytest endet mit 2/3 bei Collection-,
    Import- und Syntaxfehlern, mit 4 bei einer unbekannten Node-ID und mit 5,
    wenn nichts lief. In allen vier Faellen hat kein Test etwas geprueft —
    die alte Pruefung (``returncode != 0``) meldete sie trotzdem als "rot wie
    erwartet": ein geloeschter/umbenannter Test oder ein Syntaxfehler in der
    mutierten Datei machte das Gate gruen (SEC-042).
    """
    if returncode == 0:
        return False, "Test blieb GRUEN — er haelt den Fehler nicht fest"
    if returncode != 1:
        return False, (
            f"pytest endete mit Exit {returncode} "
            "(Collection-/Import-/Auswahlfehler oder keine Tests) — "
            "der Test hat nichts geprueft"
        )
    failed_ids = {
        match.group(1).rstrip(":") for match in _FAILED_LINE.finditer(output)
    }
    if any(fid == nodeid or fid.startswith(nodeid + "[") for fid in failed_ids):
        return True, "rot wie erwartet"
    if _ONE_FAILED.search(output):
        return True, "rot wie erwartet"
    return False, "Exit 1, aber keine FAILED-Zeile fuer den angeforderten Test"


# Everything a test run needs. Copied once per run into a temp tree; the
# mutations are applied THERE, never in the working tree.
# ``.github`` is included here because tests/test_ci_config.py reads
# the workflow: without them every mutation run would fail on a missing file
# and look like "the test catches the bug".
_COPY = ("src", "tests", "scripts", "conftest.py", "pyproject.toml", ".github")


def make_copy() -> Path:
    """A throwaway copy of the repo to mutate.

    The first version mutated the working tree and restored in a ``finally``.
    That covers exceptions, not a hard kill — and the commit habit here is
    ``git add -A && git commit``, so a leftover mutation would have been
    committed by the very check built to prevent it. Mutating a copy removes
    the whole class: whatever happens to this process, the working tree is
    never the thing that changed.
    """
    tmp = Path(tempfile.mkdtemp(prefix="malaz_bite_"))
    for name in _COPY:
        source = ROOT / name
        target = tmp / name
        if source.is_dir():
            shutil.copytree(source, target, ignore=shutil.ignore_patterns("__pycache__"))
        else:
            shutil.copy2(source, target)
    return tmp


def run(mutation: Mutation, tree: Path) -> tuple[bool, str]:
    """True, wenn der Test bei dieser Mutation ROT wird.

    „Rot" heisst: pytest hat den angeforderten Test ausgefuehrt und mit
    ``FAILED`` beendet (Exit 1). Collection-/Import-Fehler und eine
    unbekannte Node-ID (Exit 2/3/4/5) sind kein Fang — siehe :func:`_caught`.
    """
    path = tree / mutation.file
    original = path.read_text(encoding="utf-8")
    mutated = _apply(original, mutation)
    if mutated is None:
        return False, f"Anker nicht eindeutig gefunden ({mutation.file})"
    def _evict_pyc(py_file: Path) -> None:
        with suppress(Exception):
            Path(importlib.util.cache_from_source(str(py_file))).unlink(missing_ok=True)
        shutil.rmtree(py_file.parent / "__pycache__", ignore_errors=True)

    try:
        path.write_text(mutated, encoding="utf-8")
        _evict_pyc(path)
        env = dict(os.environ)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        src_dir = str(tree / "src")
        existing_pp = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = f"{src_dir}{os.pathsep}{existing_pp}" if existing_pp else src_dir
        with tempfile.TemporaryDirectory(prefix="malaz_bite_run_") as basetemp:
            proc = subprocess.run(
                [
                    str(PY),
                    "-B",
                    "-m",
                    "pytest",
                    mutation.test,
                    "-q",
                    "-p",
                    "no:randomly",
                    "--basetemp",
                    basetemp,
                ],
                cwd=tree,
                env=env,
                capture_output=True,
                text=True,
                timeout=900,
            )
        if proc.returncode == 0:
            return False, "Test blieb GRUEN — er haelt den Fehler nicht fest"
        return _caught(proc.returncode, proc.stdout + proc.stderr, mutation.test)
    except subprocess.TimeoutExpired:
        return False, "Test lief in die Zeitgrenze"
    finally:
        path.write_text(original, encoding="utf-8")
        _evict_pyc(path)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--list", action="store_true", help="nur auflisten")
    ap.add_argument("-k", default="", help="nur Mutationen mit diesem Teilstring")
    args = ap.parse_args()

    selected = [m for m in MUTATIONS if args.k in m.name]
    if args.list:
        for m in selected:
            print(f"  {m.name:34s} {m.test}")
            print(f"      {m.why}")
        return 0

    if not selected:
        print(f"  keine Mutation passt auf -k {args.k!r}")
        return 1

    failures = 0
    print(f"  Bisspruefung: {len(selected)} Mutationen (auf einer Temp-Kopie)\n")
    tree = make_copy()
    for m in selected:
        ok, note = run(m, tree)
        mark = "OK " if ok else "!! "
        print(f"  {mark}{m.name:34s} {note}")
        if not ok:
            failures += 1
            print(f"      {m.why}")

    shutil.rmtree(tree, ignore_errors=True)
    print()
    if failures:
        print(
            f"  {failures} von {len(selected)} Mutationen werden NICHT gefangen. "
            "Der jeweilige Test haelt seinen Fehler nicht fest — die Mutation "
            "ist in Ordnung, der Test ist es nicht."
        )
        return 1
    print(f"  Alle {len(selected)} Mutationen machen ihren Test rot.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
