"""Golden snapshot: the full verdict of the whole corpus, change-detectable.

Why this exists: ``test_corpus*.py`` asserts that specific rules fire, which
catches "the rule stopped working". It does NOT catch the quieter regressions —
a weight nudged from 30 to 15, an extra note added to every file, a risk level
drifting from YELLOW to RED. Those are exactly the changes this project keeps
making (every calibration moved weights), so they need a tripwire.

What is snapshotted per file: the verdict (GREEN/YELLOW/RED), the score and the
sorted set of scoring rule IDs. Deliberately NOT the exact text of every title
or detail — pinning prose makes every wording improvement a test failure
without protecting anything a consumer observes.

Regenerating after an intended change:

    python scripts/make_golden_snapshot.py

The diff of the resulting JSON is the review artifact: it shows exactly which
files changed verdict and which rules moved.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from malaz import config
from malaz.analysis.clamav import ClamAVScanner
from malaz.analysis.windows_av import WindowsDefenderScanner
from malaz.core.dispatcher import Dispatcher
from malaz.core.scoring import BASE_WEIGHTS

# scripts/ auf den Pfad, BEVOR der Erzeuger importiert wird — der Import
# stand zuerst davor und scheiterte mit ModuleNotFoundError.
_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import corpus_determinism as det  # noqa: E402
import make_golden_snapshot as golden  # noqa: E402  (Pfad steht darueber)

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import make_benign_corpus as benign  # noqa: E402
import make_corpus_v2 as corpus_v2  # noqa: E402
import make_test_corpus_extended as ext  # noqa: E402

SNAPSHOT = Path(__file__).resolve().parent / "data" / "golden_snapshot.json"


@pytest.fixture(scope="module", autouse=True)
def _pin_no_7zip():
    """Same scan environment on machines with and without 7-Zip."""
    with det.pin_no_7zip():
        yield


@pytest.fixture(scope="module")
def dispatcher():
    """Scan the corpus with the SHIPPED rule set only.

    The optional third-party rule feeds (ReversingLabs under
    ``rules/yara/external``, Neo23x0/signature-base under
    ``rules/yara/signature_base``) are user-side downloads that may or may not
    be present. Snapshotting their effect would make this tripwire depend on
    what the developer happened to fetch — the same reason the AV engines run
    disabled. Measured drift when signature-base was installed: five files
    changed verdict or notes, all of them genuinely malicious (a lure.lnk went
    YELLOW -> RED), none benign. That is a real improvement, but it is not a
    property of the code under test.
    """

    config.YARA_FEED_DIRS = ()
    try:
        yield Dispatcher(
            av_scanner=WindowsDefenderScanner(enabled=False),
            clam_scanner=ClamAVScanner(enabled=False),
        )
    finally:
        config.YARA_FEED_DIRS = config.YARA_FEED_DIRS_DEFAULT


def _all_ids(result) -> set[str]:
    """rule_ids of a result and every nested child."""
    ids = {i.rule_id for i in result.indicators}
    for child in result.children:
        ids |= _all_ids(child)
    return ids


# EINE QUELLE fuer das Urteil: der Erzeuger (scripts/make_golden_snapshot.py)
# definiert es, der Test importiert es. Vorher stand die Funktion zweimal im
# Baum — mit demselben Fehler (i.weight statt effective_weight), und die
# Korrektur an einer Stelle liess die andere still veralten.
_verdict = golden._verdict


def build_snapshot(dispatcher, tmp: Path) -> dict[str, dict[str, object]]:
    """Scan both corpora and return ``{directory/file: verdict}``."""
    snap: dict[str, dict[str, object]] = {}
    with det.pin_no_7zip():
        for group, builder in (
            ("benign", benign.build_corpus),
            # Signatur-Fixtures (rar/rpm/cab/deb): sie sind YELLOW, weil ein
            # nicht parsebarer Container kein Freispruch ist. Sie gehoeren
            # trotzdem in den Snapshot — sonst faellt eine kaputte Erkennung fuer
            # diese Typen niemandem auf.
            ("benign", benign.build_type_coverage),
            ("malicious", ext.build_extended_corpus),
            ("v2", corpus_v2.write_corpus),
        ):
            target = tmp / group
            for path in builder(target):
                snap[f"{group}/{path.name}"] = _verdict(dispatcher.scan_path(path))
    return snap


def test_golden_snapshot_matches(dispatcher, tmp_path):
    """The current verdicts must equal the recorded snapshot.

    A mismatch is not automatically a bug — it is a change that must be
    *looked at*. If the change is intended, regenerate with
    ``python scripts/make_golden_snapshot.py`` and review the JSON diff.
    """
    if not SNAPSHOT.exists():
        pytest.skip("kein Snapshot vorhanden — scripts/make_golden_snapshot.py ausführen")

    expected = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    actual = build_snapshot(dispatcher, tmp_path)

    added = sorted(set(actual) - set(expected))
    removed = sorted(set(expected) - set(actual))
    assert not added, f"neue Fixtures nicht im Snapshot: {added}"
    assert not removed, f"Fixtures aus dem Snapshot fehlen: {removed}"

    drift: list[str] = []
    for key in sorted(expected):
        want, got = expected[key], actual[key]
        # "type" gehoert dazu: der Erzeuger schreibt es (make_golden_snapshot)
        # und eine Fehlklassifikation (z. B. .lnk -> "unknown") ist eine
        # Regression, die Score und Regeln unveraendert lassen kann — der
        # Test war fuer genau dieses Feld blind (TEST-029).
        for field in ("risk", "score", "rules", "notes", "type"):
            if want[field] != got[field]:
                drift.append(f"{key}.{field}: {want[field]!r} -> {got[field]!r}")
    assert not drift, "Urteile haben sich geändert:\n  " + "\n  ".join(drift)


def test_benign_corpus_stays_green(dispatcher, tmp_path):
    """Independent of the snapshot: ordinary files must never be flagged.

    The snapshot would catch a regression here too, but only as one line among
    many. This states the invariant directly, so the failure message says what
    broke without decoding a diff.
    """
    flagged = []
    # NUR build_corpus: dort liegen Dateien, die ein Nutzer gefahrlos oeffnen
    # kann. Die Signatur-Fixtures (build_type_coverage) sind absichtlich
    # unvollstaendige Container — sie sind YELLOW, weil "nicht geoeffnet"
    # kein Freispruch ist, und gehoeren nicht in diese Zusicherung.
    for path in benign.build_corpus(tmp_path / "b"):
        result = dispatcher.scan_path(path)
        if result.risk_level.name != "GREEN":
            flagged.append(
                f"{path.name}: {result.risk_level.name} ({result.score}) "
                # effective_weight, nicht i.weight: ein Befund mit
                # Severity-Gewicht hat weight=None und fiel hier aus der
                # Meldung — der Waechter sagte "markiert", aber nicht WOMIT.
                f"{sorted({i.rule_id for i in result.all_indicators() if i.effective_weight(BASE_WEIGHTS)})}"
            )
    assert not flagged, "harmlose Dateien wurden markiert:\n  " + "\n  ".join(flagged)


def test_malicious_corpus_is_not_green(dispatcher, tmp_path):
    """Detection fixtures must be flagged; informational ones need not.

    ``EXTENDED_CORPUS`` deliberately mixes two kinds of fixture:
      * *detection* fixtures exist to prove a rule fires — these must never be
        GREEN, because that would mean the detection silently regressed;
      * *informational* fixtures exercise a code path that is correctly weighted
        to zero: a colour-on-colour PDF is a weak heuristic, an object stream is
        a normal PDF 1.5 feature, EXIF is metadata, and the PE structure probes
        (TLS presence, a PDB path, an overlay note) report facts whose weight is
        intentionally 0 after calibration.

    The set below names them explicitly, so a new fixture forces a decision
    instead of silently landing in the exempt group.
    """
    informational = {
        # Needs an external blocklist entry to fire (own test below).
        "blocklisted.bin",
        # Truncation notes: LOW/15, below the YELLOW threshold by design.
        "cut_off.jpg", "cut_off.png",
        # PDF/Office containers with zero-weight or note-only findings.
        "color_on_color.pdf", "object_stream.pdf", "remote_formula.xlsx",
        "obfuscated.js", "persistence.ps1", "deep_nesting.zip",
        "encrypted_aes.zip", "corrupt.zip", "trailing_payload.jpg",
        "with_exif.png", "object.rtf", "traversal.tar",
        # PE structure probes: facts, not verdicts (all weight 0 by design).
        "plain.exe", "weak_mitigations.exe", "no_cfg.exe",
        "high_entropy_sections.exe", "overlay_payload.exe", "signed_overlay.exe",
        "with_pdb.exe", "tls_callbacks.exe", "tls_empty.exe",
        "broken_header.exe", "import_injection.exe", "import_keylog.exe",
    }
    quiet = []
    for path in ext.build_extended_corpus(tmp_path / "m"):
        result = dispatcher.scan_path(path)
        if result.risk_level.name == "GREEN" and path.name not in informational:
            quiet.append(path.name)
    assert not quiet, (
        "Erkennungs-Fixtures blieben unauffällig (oder sind neu und nicht "
        "eingeordnet): " + ", ".join(quiet)
    )


# -- platform-dependent signals ------------------------------------------------- #


def test_motw_ads_is_reported(dispatcher, tmp_path):
    """A downloaded file must be flagged from its Zone.Identifier stream.

    Mark-of-the-Web is the provenance signal that matters most in triage, and
    it lives on the filesystem entry (an NTFS alternate data stream), not in
    the file content — so it cannot be part of the byte corpus. Skipped where
    the platform cannot store ADS (FAT/exFAT, non-NTFS temp).
    """
    if sys.platform != "win32":
        pytest.skip("Zone.Identifier ist ein NTFS-ADS (nur Windows)")

    path = tmp_path / "downloaded.pdf"
    path.write_bytes(ext.motw_downloaded_pdf())
    if not ext.apply_motw(path, zone=3):
        pytest.skip("Dateisystem unterstützt keine Alternate Data Streams")

    result = dispatcher.scan_path(path)
    ids = _all_ids(result)
    assert "GEN_MOTW" in ids, sorted(ids)
    detail = next(
        i.detail for i in result.all_indicators() if i.rule_id == "GEN_MOTW"
    )
    assert "Internet" in detail


def test_blocklisted_hash_is_a_critical_anchor(dispatcher, tmp_path, monkeypatch):
    """A hash on the local blocklist must anchor the verdict at RED.

    Uses a throwaway blocklist so the fixture hash never enters the shipped
    list — the point is the wiring (hash -> anchor), not a real indicator.
    """
    import hashlib


    payload = ext.blocklisted_sample()
    digest = hashlib.sha256(payload).hexdigest()

    blocklist = tmp_path / "blocklist.sha256"
    blocklist.write_text(f"# test\n{digest}  corpus-sample\n", encoding="utf-8")
    monkeypatch.setattr(config, "HASH_BLOCKLIST_FILE", blocklist)

    path = tmp_path / "blocklisted.bin"
    path.write_bytes(payload)
    result = dispatcher.scan_path(path)

    assert result.score >= 50, f"Anker fehlt (Score {result.score})"
    assert result.risk_level.name == "RED"
    assert "GEN_HASH_BLOCKLIST" in _all_ids(result)


# -- reproducibility of the tripwire ------------------------------------------- #


def test_snapshot_script_ignores_imported_blocklists(tmp_path, monkeypatch):
    """Der Snapshot darf nicht vom Import-Stand des Rechners abhängen.

    ``scripts/make_golden_snapshot.py`` baute den Dispatcher mit der echten
    Konfiguration; eine importierte URL-Liste im Nutzerprofil schlug bis in
    das Urteil durch. Gemessen per A/B mit identischem Code, nur LocalAppData
    unterschiedlich: mit Importen 2 Abweichungen von 91 Dateien
    (phish_links.eml, phish_schemes.eml, jeweils zusätzlich
    MAIL_REPUTATION_CLEAN), mit leerem Profil 0. Damit zeigte das Beweismittel
    den Rechner statt den Code.

    Der Test stellt beide Seiten her: A) ungepinnt greift die nachgestellte
    Nutzerliste (sonst wäre der Test wertlos), B) über den Skript-Pfad
    gescannt nicht mehr. Korpus ist nur die betroffene Datei — der Pin ist
    eine Konfigurationsaussage, keine Aussage pro Datei.
    """
    from types import SimpleNamespace

    from malaz.core import url_reputation

    monkeypatch.setattr(config, "YARA_FEED_DIRS", ())

    poison = tmp_path / "urls.sha256"
    poison.write_text(
        url_reputation.url_hash("http://imported.example/x") + "\n", encoding="utf-8"
    )
    monkeypatch.setattr(config, "URL_BLOCKLIST_FILE", poison)

    fixture = tmp_path / "phish_links.eml"
    fixture.write_bytes(ext.eml_phishing_links())

    # A) So liefen die Skripte vorher: die Nutzerliste ist sichtbar.
    live = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    assert "MAIL_REPUTATION_CLEAN" in _all_ids(live.scan_path(fixture))

    # B) Derselbe Skript-Pfad, nur mit einer Datei als Korpus.
    monkeypatch.setattr(
        golden,
        "benign",
        SimpleNamespace(
            build_corpus=lambda target: [],
            build_type_coverage=lambda target: [],
        ),
    )
    monkeypatch.setattr(
        golden, "ext", SimpleNamespace(build_extended_corpus=lambda target: [fixture])
    )
    snap = golden.build(tmp_path / "corpus")
    assert "MAIL_REPUTATION_CLEAN" not in snap["malicious/phish_links.eml"]["notes"], snap


def test_run_corpus_output_ignores_imported_blocklists(tmp_path, monkeypatch, capsys):
    """Auch die Korpus-Uebersicht darf den Rechner nicht mitmessen.

    Derselbe A/B wie oben, nur ueber ``scripts/run_corpus.py``. Hier zaehlt
    eine GEWICHTETE Regel: die Uebersicht druckt nur Indikatoren mit Gewicht,
    ein Hinweis mit Gewicht 0 waere unsichtbar (erster Testversuch lief
    deshalb gruen durch, obwohl der Fix fehlte). Die nachgestellte
    Nutzerliste traegt den SHA-256 der Fixture-Datei, also einen echten
    Treffer: ungepinnt steht GEN_HASH_BLOCKLIST in der Ausgabe, gepinnt darf
    die Ausgabe Zeichen fuer Zeichen dieselbe sein wie ohne die Liste.
    """
    import hashlib

    import run_corpus  # scripts/ ist auf sys.path


    monkeypatch.setattr(config, "YARA_FEED_DIRS", ())

    fixture = tmp_path / "phish_links.eml"
    fixture.write_bytes(ext.eml_phishing_links())
    groups = {"malicious": lambda target: [fixture]}

    poison = tmp_path / "hashes.sha256"
    poison.write_text(hashlib.sha256(fixture.read_bytes()).hexdigest() + "\n", encoding="utf-8")
    monkeypatch.setattr(config, "USER_HASH_BLOCKLIST_FILE", poison)

    # Die Vergiftung greift: ungepinnt ist der Treffer sichtbar.
    live = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    assert "GEN_HASH_BLOCKLIST" in _all_ids(live.scan_path(fixture))

    run_corpus.run(groups)
    printed = capsys.readouterr().out
    assert "phish_links.eml" in printed, printed
    assert "GEN_HASH_BLOCKLIST" not in printed, printed


def test_jeder_signaturtyp_kommt_im_snapshot_vor():
    """Jeder Typ, den ``magic.detect()`` kennt, muss ein Fixture haben.

    GEMESSEN: neun Typen (bzip2 cab class deb iso rar rpm swf xz) hatten
    KEINE Abdeckung. Ein Typ, den die Erkennung kennt und kein Fixture
    berührt, kann unbemerkt kaputtgehen — der Snapshot hätte es nicht gemerkt.

    Diese Zusicherung ist der Grund, warum die Lücke nicht zurückkommt: eine
    neue Signatur in ``magic._SIGNATURES`` ohne Fixture macht sie rot, und
    die Meldung nennt den fehlenden Typ.
    """
    import json
    import re

    from malaz.core import magic

    quelle = Path(magic.__file__).read_text(encoding="utf-8")
    tabelle = quelle[quelle.index("_SIGNATURES") :][:8000]
    signiert = set(re.findall(r'Signature\("([a-z0-9]+)"', tabelle))
    assert signiert, "die Signaturtabelle wurde nicht gefunden — Testaufbau prüfen"

    # Typen, die NICHT in _SIGNATURES stehen, sondern einen eigenen Weg haben.
    # GEMESSEN: heic/avif kamen ueber _heif_type() herein — die
    # Signatur-Zusicherung haette fuer sie nie ein Fixture verlangt, also
    # genau die Luecke, die sie schliessen soll.
    sonderwege = {"heic", "avif", "url"}

    snapshot = json.loads(
        (Path(__file__).parent / "data" / "golden_snapshot.json").read_text(encoding="utf-8")
    )
    abgedeckt = {eintrag.get("type") for eintrag in snapshot.values()}

    fehlend = sorted((signiert | sonderwege) - abgedeckt)
    assert not fehlend, (
        f"diese Typen kennt magic.detect(), aber kein Fixture deckt sie ab: {fehlend}"
    )


def test_7zip_pin_is_effective(monkeypatch):
    """The pin must remove optional host CLI binaries (7z, DIE, capa) from measurements."""
    from malaz.analysis.capa import CapaScanner
    from malaz.analysis.die import DieScanner
    from malaz.core import sevenzip

    fake_7z = Path("C:/fake/7z.exe")
    fake_die = Path("C:/fake/diec.exe")
    fake_capa = Path("C:/fake/capa.exe")
    monkeypatch.setattr(sevenzip, "find_7z_binary", lambda: fake_7z)
    monkeypatch.setattr(DieScanner, "_locate", lambda self: fake_die)
    monkeypatch.setattr(CapaScanner, "_locate", lambda self: fake_capa)

    assert sevenzip.find_7z_binary() == fake_7z
    assert DieScanner().binary == fake_die
    assert CapaScanner(enabled=True).binary == fake_capa

    with det.pin_no_7zip():
        assert sevenzip.find_7z_binary() is None
        assert DieScanner().binary is None
        assert CapaScanner(enabled=True).binary is None

    assert sevenzip.find_7z_binary() == fake_7z
    assert DieScanner().binary == fake_die
    assert CapaScanner(enabled=True).binary == fake_capa


def test_run_corpus_lists_severity_weighted_rules():
    """BUG-082: ``if i.weight`` verschwieg Regeln ohne explizites Gewicht.

    ``GEN_FORMAT_MISMATCH`` wird mit ``severity=HIGH`` und ``weight=None``
    erzeugt; sein effektives Gewicht ist 30, es trug also den Score — stand
    aber in keiner Zeile und keiner CSV-Zelle der Uebersicht. Die Uebersicht
    muss dieselbe Rechnung wie ``compute_score`` zeigen
    (``effective_weight(BASE_WEIGHTS)``), sonst erklaert sie den Score nicht.
    """
    import run_corpus  # scripts/ ist auf sys.path

    from malaz.models import Indicator, ScanResult, Severity

    result = ScanResult(path="x.bin", detected_type="text")
    result.indicators = [
        Indicator("GEN_FORMAT_MISMATCH", "Format passt nicht", severity=Severity.HIGH),
        Indicator("GEN_ENTROPY", "Hohe Entropie", severity=Severity.LOW, weight=5),
    ]
    text = run_corpus._rules(result)
    assert "GEN_FORMAT_MISMATCH(30)" in text, text
    assert "GEN_ENTROPY(5)" in text, text
