"""Central configuration: paths, security limits, scoring thresholds, capabilities.

This module must stay import-light: it must not import any heavy third-party
library at module load time so that the application can always start and report
which optional capabilities are available.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from contextlib import suppress
from functools import cache
from pathlib import Path

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #

# src/malaz/config.py -> package / src / project root
PACKAGE_DIR = Path(__file__).resolve().parent
SRC_DIR = PACKAGE_DIR.parent
PROJECT_ROOT = SRC_DIR.parent


def _resolve_rules_dir() -> Path:
    """Locate the ``rules`` directory across dev and frozen (exe) layouts.

    In the source layout the rules live at the project root. In a Nuitka
    onefile/standalone build the package is unpacked to a temporary location and
    the derived project root no longer points at the bundled data, so we probe a
    few sensible locations and take the first one that exists: the dev root, the
    bundle root (package at the top of the unpacked tree), inside the package,
    and next to the running executable. This lets
    a user also drop a ``rules`` folder beside the exe to override the bundled
    one. When nothing exists we fall back to the dev-derived path so that
    :func:`ensure_dirs` can still create it.
    """
    candidates: list[Path] = [
        PROJECT_ROOT / "rules",          # source / dev layout
        PACKAGE_DIR.parent / "rules",    # frozen: package at bundle root
        PACKAGE_DIR / "rules",           # frozen: rules bundled inside package
    ]
    with suppress(Exception):
        candidates.append(Path(sys.executable).resolve().parent / "rules")
    # NOTE: no Path.cwd() candidate — starting the app from an untrusted
    # directory must not let a planted rules/ folder supply YARA rules,
    # ZIP password lists or the hash blocklist.
    for candidate in candidates:
        try:
            if candidate.is_dir():
                return candidate
        except OSError:
            continue
    return PROJECT_ROOT / "rules"


RULES_DIR = _resolve_rules_dir()
YARA_RULES_DIR = RULES_DIR / "yara"
PASSWORD_FILE = RULES_DIR / "passwords" / "zip_passwords.txt"
# Curated blocklist shipped with the project (EICAR sample entry + format
# docs). Imported third-party hashes MUST NOT land here: the file is tracked
# by git, so they would ship inside releases — abuse.ch's ToS, for instance,
# forbids redistribution outright. Imported feeds go to
# USER_HASH_BLOCKLIST_FILE instead (see below); both lists are read.
HASH_BLOCKLIST_FILE = RULES_DIR / "hashes" / "blocklist.sha256"

# Imported threat-intel hashes, kept OUTSIDE the tracked tree. Default is the
# per-user data directory so imports survive reinstalls; beside the executable
# the project already probes a writable ``rules`` folder for frozen layouts.
# See core.hashlist.load_blocklist(): tracked + user list are merged, so
# removing an import never needs a git operation.
USER_HASH_BLOCKLIST_FILE = Path(
    os.path.expandvars(r"%LocalAppData%\Malaz\hashes\blocklist.sha256")
)

# Parsed blocklists are cached here across processes. The file's mtime/size
# is part of the cache key; a stale or corrupt cache is ignored and the list
# is parsed again. Kept beside the imported lists (not in the tracked tree).
CACHE_DIR = Path(os.path.expandvars(r"%LocalAppData%\Malaz\cache"))
LIST_CACHE_VERSION = 1

# External YARA rules (MIT-licensed vendor feed, ReversingLabs) live in a
# subdirectory so an update never touches Malaz's own curated rule files.
YARA_EXTERNAL_DIR = YARA_RULES_DIR / "external"
# Explicit opt-in rule update (GUI button): fixed, allowlisted codeload URL
# of the pinned MIT-licensed ReversingLabs ruleset. Malaz itself stays
# offline at scan time — only this one user action goes online (same
# contract as the ClamAV/freshclam button).
YARA_UPDATE_URL = (
    "https://codeload.github.com/reversinglabs/"
    "reversinglabs-yara-rules/zip/refs/heads/develop"
)
YARA_UPDATE_HOST = "codeload.github.com"
# Bounds for the download and the extraction (zip-bomb / zip-slip guards).
# The feed currently ships ~1.5k small rule files (~6 MB).
YARA_UPDATE_MAX_ZIP_BYTES = 30 * 1024 * 1024
YARA_UPDATE_MAX_FILE_BYTES = 2 * 1024 * 1024
YARA_UPDATE_MAX_RULE_FILES = 2000
# Cumulative budget for the EXTRACTED rule content. The per-file cap alone
# bounded nothing overall: 2000 x 2 MiB could buffer ~4 GiB from a 30 MiB
# archive (SEC-039). The real feed is ~6 MiB, so 64 MiB leaves ample headroom
# and a compromised feed is refused with a clear error instead of an OOM.
YARA_UPDATE_MAX_TOTAL_BYTES = 64 * 1024 * 1024
# Per-rule kill switch for external rules that misfire on benign files:
# one rule name per line, '#' starts a comment. Applies to EVERY feed below
# (ReversingLabs and signature-base alike).
YARA_EXTERNAL_DISABLED = YARA_RULES_DIR / "external_disabled.txt"

# Second, independent third-party rule source: Neo23x0/signature-base
# ("Detection Rule License (DRL) 1.1"). Same contract as the ReversingLabs
# feed: Malaz ships NO third-party rules, the user fetches them consciously
# with scripts/update_signature_base.bat, and never at scan time.
# A separate directory is mandatory — core.yara_update deletes every
# *.yar/*.yara/*.yarc BELOW YARA_EXTERNAL_DIR on install, so signature-base
# rules parked there would be silently wiped by the next feed update.
YARA_SIGNATURE_BASE_DIR = YARA_RULES_DIR / "signature_base"
YARA_SIGNATURE_BASE_URL = (
    "https://codeload.github.com/Neo23x0/signature-base/zip/refs/heads/master"
)
YARA_SIGNATURE_BASE_HOST = "codeload.github.com"
# Bounds for the download and the extraction (zip-bomb / zip-slip guards).
# Measured 2026-09: 785 archive members, 751 rule files, 2.1 MB zip,
# 738 usable rules -> 5255 individual rules in the compiled bundle.
YARA_SIGNATURE_BASE_MAX_ZIP_BYTES = 32 * 1024 * 1024
YARA_SIGNATURE_BASE_MAX_FILE_BYTES = 2 * 1024 * 1024
YARA_SIGNATURE_BASE_MAX_RULE_FILES = 2000
YARA_SIGNATURE_BASE_MAX_TOTAL_BYTES = 64 * 1024 * 1024
# Feed directories below YARA_RULES_DIR, in engine load order. Each one is
# owned by exactly one acquisition module (core.yara_update,
# core.yara_signature_base) which only ever deletes inside its own directory.
# Kept as a named default so tests can neutralise the feeds for determinism
# (the golden snapshot must not depend on which feeds a developer fetched).
YARA_FEED_DIRS_DEFAULT = ("external", "signature_base")
YARA_FEED_DIRS = YARA_FEED_DIRS_DEFAULT

APP_NAME = "Malaz"


# --------------------------------------------------------------------------- #
# Security / resource limits  (see docs/SECURITY_MODEL.md)
# --------------------------------------------------------------------------- #

MB = 1024 * 1024

# Reject files larger than this outright. 2 GB is the new default: the
# streaming path (FileSource) keeps memory bounded for the deep pipelines and
# the AV engines scan the file from disk. The number is deliberately finite —
# scan time and engine timeouts still have to be bounded.
MAX_FILE_SIZE = 2 * 1024 * MB
# Maximum number of bytes read into memory for full-buffer analysis, PER
# worker. Three scan workers x 64 MB = 192 MB of file buffers on top of the
# ~278 MB base (GUI + blocklists), i.e. the documented ~470 MB target.
MAX_READ_SIZE = 64 * MB
# Files above this threshold are not read as one buffer; only a small prefix
# is loaded and the streaming stages (hash, entropy, YARA, IOC) read the file
# in chunks. Kept separate from MAX_READ_SIZE so tests and small files keep
# the historical "prefix up to MAX_READ_SIZE" behaviour.
MAX_LARGE_FILE_SIZE = 64 * MB
MAX_LARGE_PREFIX_SIZE = 8 * MB
# Chunk size for streaming reads (entropy/IOC/hash). Eight MB keeps the
# allocator and the regex passes bounded while still being sequential I/O.
MAX_STREAM_CHUNK = 8 * MB
# Wall-clock budget for the static analysis of one top-level file. A 2 GB
# file is still processed in bounded chunks; when the budget is reached the
# streaming stages stop and the result carries CORE_TIME_BUDGET (never GREEN).
MAX_FILE_SCAN_SECONDS = 120
# Zip-bomb protection: total uncompressed volume across an archive. Raised for
# the 2 GB file support; the per-entry and ratio limits remain the real guard.
MAX_UNCOMPRESSED_SIZE = 4 * 1024 * MB

# Wall-clock budget for unpacking ONE container member stream. The byte caps
# alone do not bound CPU: measured, an 8.3 MB .gz inflates to 8.6 GB and the
# scan spent 20 s on the capped 512 MB, an 3.9 MB .bz2 spent 11 s on 107 MB.
# A stream that cannot be unpacked in time is reported as not examined.
MAX_CONTAINER_SECONDS = 20

# Byte cap for a SINGLE decompressed stream that is not a TAR (plain .gz/.bz2/
# .xz payload). The generic 512 MB limit made one small file cost 20 s: an
# 8.3 MB .gz inflates to 8.6 GB and the scan spent the full time on the capped
# 512 MB. 64 MB is far above any real single-file triage target and keeps the
# worst case at a few seconds; the ratio rule already flags the bomb itself.
MAX_SINGLE_STREAM_BYTES = 64 * 1024 * 1024
# Zip-bomb protection: maximum number of entries in a single archive.
MAX_ARCHIVE_ENTRIES = 10_000
# Recursion depth for nested archives.
MAX_ARCHIVE_DEPTH = 5
# Maximum ratio of uncompressed / compressed size before we treat it as a bomb.
MAX_COMPRESSION_RATIO = 100
# Maximum size of a single extracted member we will process.
MAX_EXTRACTED_FILE_SIZE = 512 * MB
# Maximum number of archive members that are fully re-scanned (responsiveness,
# PER CONTAINER). DoS guard so a huge archive stays responsive.
MAX_RECURSIVE_MEMBERS = 250
# GLOBAL caps per top-level file, across ALL nesting levels: without them a
# fractal/quine zip (each member a copy of the archive) multiplies the
# per-container budgets — up to billions of scan calls and AV engine runs.
MAX_TOTAL_SCAN_MEMBERS = 2000
MAX_TOTAL_AV_MEMBER_SCANS = 150
YARA_SCAN_BUDGET_SECONDS = 30
# Maximum number of files a batch scan (CLI folder argument / dropped folder in
# the GUI) will process. DoS guard so pointing at a huge tree stays bounded; the
# walk stops early and the caller reports the truncation.
MAX_BATCH_FILES = 5000
# Parallel scan workers inside one batch. Three workers x 64 MB full buffer
# make the documented 192 MB buffered budget (the rest of the process is
# GUI + blocklists); larger files use the 8 MB streaming prefix instead.
MAX_SCAN_WORKERS = 3
# Cell budget for the xlsx formula scan. In read-only mode openpyxl honours the
# sheet's declared dimension, so a crafted <dimension ref="A1:XFD1048576"/> can
# pad the iteration to ~1.7e10 empty cells; this budget caps the loop.
MAX_FORMULA_CELLS = 250_000
# openpyxl materializes sharedStrings/sheet XML before the cell budget can
# help. This per-member cap is independent of the general 512 MB extracted
# limit: a 128 MB string pool is already a formula bomb for the loader.
MAX_FORMULA_MEMBER_SIZE = 64 * MB
# Raw-data excerpts captured into findings/reports are capped at this length.
MAX_STRING_CAPTURE = 4096
# MIME part budget shared by both .eml parsers (eml_analysis.parse_mail and
# email_extract). A mail wider than this is not silently half-read: the
# parser records the truncation and the pipeline reports it with weight 25.
MAIL_MAX_MIME_PARTS = 4096

# --------------------------------------------------------------------------- #
# String extraction from binaries  (see core/strings_extract.py)
# --------------------------------------------------------------------------- #
# AP9 foundation for PE/ELF/Mach-O: a bounded ASCII/UTF-16LE pass. The caps
# are hard limits, not hints — a hostile binary can otherwise turn the string
# scanner into a memory amplifier (millions of four-byte runs).
STRINGS_MIN_LEN = 4
STRINGS_MAX_STRING_LEN = 4096
STRINGS_MAX_SCAN_BYTES = 2 * MB
STRINGS_MAX_COUNT = 2000

# Chunk size used for streaming reads / hashing.
READ_CHUNK_SIZE = 1 * MB


# --------------------------------------------------------------------------- #
# Scoring  (see docs/ARCHITECTURE.md)
# --------------------------------------------------------------------------- #

# Risk-level boundaries (inclusive lower bound).
SCORE_GREEN_MAX = 19      # 0..19  -> GREEN
SCORE_YELLOW_MAX = 49     # 20..49 -> YELLOW
# 50..100 -> RED
SCORE_CAP = 100
ANCHOR_CRITICAL_SCORE = 50  # a CRITICAL indicator forces at least this score

# Entropy thresholds.
ENTROPY_HIGH = 7.5          # above this: likely encrypted/packed/hidden
ENTROPY_VERY_HIGH = 7.9
# Weight cap when high entropy is *explained* by the format itself (a PDF
# declaring /FlateDecode or /Encrypt legitimately consists of compressed
# streams — whole-file entropy ~7.5-8 is the norm, not an anomaly; the
# signal stays visible as LOW but must not drive the score).
#
# 0, nicht 5 — GEMESSEN an echten Dateien. Die Pruefung laeuft PRO MITGLIED,
# und der Deckel multipliziert sich damit ueber die Anzahl der Bilder: eine
# echte PowerPoint-Datei mit 11 PNG/JPEG-Streams kam auf 11 x 5 = 55 Punkte
# und damit ROT. Jeder einzelne Detailtext sagte dabei selbst, die Entropie
# sei "durch das PNG-Format selbst ... erklaerbar (Normalfall bei diesem
# Format); sie allein ist kein Hinweis auf Schadcode" — eine Warnung, die
# nicht auf den Score wirken darf, wenn sie das selbst behauptet.
#
# Sichtbar bleibt der Befund (Gewicht 0, nicht unterdrueckt): wer wissen
# will, warum die Datei auffiel, liest es im Detail. NICHT erklaerte
# Entropie behaelt ihr volles Gewicht — davon ist hier nichts betroffen.
ENTROPY_EXPLAINED_CAP = 0

# AV clean-vote discount: every engine that actually scanned a file and
# found nothing reduces the score slightly — two independent "no threat"
# verdicts are evidence, just weak evidence. Bounded so it can never mask
# a HIGH/CRITICAL signature hit (the CRITICAL anchor is applied AFTER the
# discount).
AV_CLEAN_DISCOUNT_PER_ENGINE = 4
AV_CLEAN_DISCOUNT_MAX = 8


# --------------------------------------------------------------------------- #
# Windows Defender / AV integration  (see analysis/windows_av.py)
# --------------------------------------------------------------------------- #

# Master switch; when False the AV stage is skipped entirely.
AV_ENABLED = True
# Also scan ARCHIVE MEMBERS (in-memory payloads staged to a private temp
# file) with the AV engines — without this, malware inside a zip/rar/7z is
# only judged by static heuristics, never by the real engines.
AV_SCAN_ARCHIVE_MEMBERS = True
# Per-archive budget: at most this many members go through the AV engines,
# so a 250-member archive cannot stall the scan for minutes.
AV_ARCHIVE_MEMBER_LIMIT = 25
# MpCmdRun custom-scan type (3 = custom scan of a specific file via -File).
AV_SCAN_TYPE = 3
# Hard timeout for the MpCmdRun subprocess so a hung scan cannot block a worker.
AV_TIMEOUT_SECONDS = 90
# Large files get a proportional budget instead of a fixed 90 s: the base
# timeout plus one second per 10 MB, capped here. The timeout is still a hard
# stop and is reported as "not checked", never as clean.
AV_TIMEOUT_MAX_SECONDS = 600
AV_TIMEOUT_PER_SIZE_STEP_SECONDS = 1
AV_TIMEOUT_SIZE_STEP_BYTES = 10 * MB


def av_timeout_for_size(size: int) -> int:
    """Timeout for one AV scan, scaled with the file size but bounded."""
    try:
        extra = max(0, int(size)) // AV_TIMEOUT_SIZE_STEP_BYTES
    except (TypeError, ValueError):
        extra = 0
    return min(
        AV_TIMEOUT_MAX_SECONDS,
        AV_TIMEOUT_SECONDS + extra * AV_TIMEOUT_PER_SIZE_STEP_SECONDS,
    )
# MpCmdRun process return codes.
AV_RC_CLEAN = 0
AV_RC_THREAT = 2
# Remediation policy. False (default) lets Defender act on a detected threat
# (clean/quarantine/remove) — the protective choice. Set True for pure analysis
# (e.g. when samples must be preserved), which passes -DisableRemediation.
AV_DISABLE_REMEDIATION = False
# Candidate install locations for MpCmdRun.exe. Environment variables are
# expanded at lookup time. These are fixed, internal paths (never payload data).
AV_MPCMDRUN_CANDIDATES = (
    r"%ProgramFiles%\Windows Defender\MpCmdRun.exe",
    r"%ProgramFiles(x86)%\Windows Defender\MpCmdRun.exe",
    r"%ProgramData%\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe",
)


# --------------------------------------------------------------------------- #
# IOC extraction is skipped at/above this entropy: compressed or packed
# data has no readable strings, every "domain" match is random noise
# (text ~4.5 bit/byte, base64 tops out ~6.5, compressed ~7.9).
IOC_MAX_ENTROPY = 7.0

# --------------------------------------------------------------------------- #
# ClamAV integration  (see analysis/clamav.py)
# --------------------------------------------------------------------------- #

# Master switch. ClamAV is a second, Defender-independent engine: it still
# works when Defender is disabled (e.g. a third-party EDR is the primary AV).
CLAMAV_ENABLED = True
CLAMAV_TIMEOUT_SECONDS = 90
# Large-file scans get the same proportional budget as Defender.
CLAMAV_TIMEOUT_MAX_SECONDS = 600
# clamd's built-in default when its config does not name MaxFileSize. Files
# above it are SKIPPED by clamd and still reported as "OK" — Malaz must not
# turn that into CLAMAV_CLEAN.
CLAMAV_DEFAULT_MAX_FILE_SIZE = 100 * MB
# Limits written into a Malaz-generated clamd config and passed to clamscan.
# They must be at least MAX_FILE_SIZE once the 2 GB limit is enabled.
CLAMAV_DAEMON_MAX_FILE_SIZE = 2 * 1024 * MB
CLAMAV_SCAN_MAX_SIZE = 4 * 1024 * MB


def clamav_timeout_for_size(size: int) -> int:
    """Timeout for one ClamAV scan, scaled with the file size but bounded."""
    try:
        extra = max(0, int(size)) // AV_TIMEOUT_SIZE_STEP_BYTES
    except (TypeError, ValueError):
        extra = 0
    return min(
        CLAMAV_TIMEOUT_MAX_SECONDS,
        CLAMAV_TIMEOUT_SECONDS + extra * AV_TIMEOUT_PER_SIZE_STEP_SECONDS,
    )
# Reachability probe for a running clamd daemon (clamdscan --ping=1). When
# the daemon answers, Malaz uses clamdscan for every scan: the daemon loads
# the signature database ONCE, so a scan costs milliseconds instead of the
# ~15+ s per fresh clamscan process (measured; the DB load dominates).
CLAMAV_PING_TIMEOUT_SECONDS = 5
# Candidate clamscan / clamdscan binaries. Common install paths on Windows
# (e.g. ClamWin / ClamAV port) plus a PATH fallback handled in the module.
CLAMAV_SCAN_CANDIDATES = (
    r"C:\Program Files\ClamAV\clamscan.exe",
    r"C:\Program Files\ClamAV\clamdscan.exe",
    r"C:\Program Files (x86)\ClamAV\clamscan.exe",
    r"C:\Program Files\ClamWin\bin\clamscan.exe",
    r"C:\clamav\clamscan.exe",
)
# Candidate signature-database directories. clamscan's compiled-in default is
# <install>\database; admin-less installs commonly keep signatures elsewhere
# (freshclam --datadir, e.g. %LocalAppData%\ClamAV\db). The first existing
# directory that actually contains signatures is passed to clamscan via
# --database; when none is found clamscan falls back to its own default and no
# flag is passed. Environment variables are expanded at lookup time.
CLAMAV_DB_CANDIDATES = (
    r"C:\Program Files\ClamAV\database",
    r"C:\Program Files (x86)\ClamAV\database",
    r"C:\clamav\database",
    r"%LocalAppData%\ClamAV\db",
    r"%ProgramData%\ClamAV\db",
)
# freshclam candidates for the explicit signature update (GUI button /
# scripts/update_clamav.bat). Malaz itself never goes online — only
# freshclam does, downloading from the official ClamAV mirrors.
CLAMAV_FRESHCLAM_CANDIDATES = (
    r"C:\Program Files\ClamAV\freshclam.exe",
    r"C:\Program Files (x86)\ClamAV\freshclam.exe",
    r"C:\clamav\freshclam.exe",
)
# Admin-less freshclam config (variant B, see docs/anleitung): when this
# file exists it is passed via --config-file so freshclam writes into the
# user-writable database directory instead of Program Files.
CLAMAV_FRESHCLAM_USER_CONF = r"%LocalAppData%\ClamAV\freshclam.conf"
# Admin-less clamd config. clamdscan reads it to learn HOW to reach the daemon
# (TCP host/port) — without it, clamdscan looks in the install directory, finds
# nothing and exits rc=2, so the ping fails and the scan silently falls back to
# the slow full-process clamscan (~16 s per file instead of milliseconds).
# Measured: `clamdscan --ping=1` → rc=2 without this file, rc=0 with it.
CLAMAV_CLAMD_USER_CONF = r"%LocalAppData%\ClamAV\clamd.conf"
# Bound the update run: freshclam downloads up to ~200 MB on a first run;
# a wedged download must not hang the dialog forever.
CLAMAV_UPDATE_TIMEOUT_SECONDS = 900

# -- Automatic signature update on startup (opt-in, age-gated) ------------- #
# Malaz is offline by design (docs/SECURITY_MODEL.md); this is the ONE
# additional network path and it stays OFF until the user ticks the box in
# the GUI (persisted via QSettings, see gui/main_window.py). Even when enabled
# it only fires when the local database is older than the threshold below, so
# a launch does not hit the network while the signatures are current.
CLAMAV_AUTO_UPDATE_ENABLED_DEFAULT = False
# Only update when the newest local CVD is at least this many days old.
CLAMAV_AUTO_UPDATE_MIN_AGE_DAYS = 1
# Startup update runs silently in the background with this bound (shorter
# than the manual dialog: a stuck download must not keep a worker alive).
CLAMAV_AUTO_UPDATE_TIMEOUT_SECONDS = 300


# -- URL reputation for mail links (OPT-IN, privacy-preserving) ------------- #
# OFF by default and without a provider the lookup is a no-op. When enabled,
# ONLY the SHA-256 hash of a link is sent (never the URL itself, never mail
# content) — see core/url_reputation.py for the enforced privacy rules.
URL_REPUTATION_ENABLED = False
# Leave empty unless the user configures a provider. Malaz ships no default
# endpoint and no embedded API key.
URL_REPUTATION_ENDPOINT = ""
URL_REPUTATION_TIMEOUT_SECONDS = 8
# Bound the requests per mail: more lookups would leak more and gain little.
URL_REPUTATION_MAX_LOOKUPS = 10

# -- Automatic feed refresh (OPT-IN) ---------------------------------------- #
# The feeds carry the user's threat intel (hashes, URLs, domains, nets), so a
# stale import means "detects less, silently". That is the same failure mode
# the ClamAV auto-update addresses, and it follows the same rules: OFF until
# the user ticks the box, and only fetched when the local copies are actually
# older than MIN_AGE_DAYS — a launch must not hammer five servers.
#
# Unlike ClamAV this needs NO external binary: the download is Malaz's own
# (core/feeds.py), so the checkbox works on a fresh install.
FEEDS_AUTO_UPDATE_ENABLED_DEFAULT = False
FEEDS_AUTO_UPDATE_MIN_AGE_DAYS = 1
# Per-feed download timeout. Generous because the biggest list is tens of MB.
FEEDS_DOWNLOAD_TIMEOUT_SECONDS = 120

# -- Local URL blocklist (the OFFLINE half of link reputation) -------------- #
# A SHA-256 hash list of known-bad URLs — same file format and same importer
# as the file-hash blocklist, so nothing new has to be learned:
#
#   python scripts/import_blocklist.py urls.txt --target "%URL_BLOCKLIST_FILE%"
#
# URLhaus ships exactly such a list (plain URLs, one per line). A hit raises
# the same MAIL_LINK_REPUTATION finding as a provider hit, but is established
# entirely offline. Independent of URL_REPUTATION_ENABLED: a user who wants
# zero network traffic gets the local check and nothing else.
#
# Lives beside the user's imported file-hashes: not tracked by git, so
# imported feeds never end up in a release.
URL_BLOCKLIST_FILE = Path(
    os.path.expandvars(r"%LocalAppData%\Malaz\hashes\urls.sha256")
)

# -- SPF/DMARC ueber DNS (OPT-IN, Vorgabe AUS) ------------------------------ #
# Der EINZIGE Weg, auf dem Malaz von sich aus eine Frage ans Netz stellt.
# Beantwortet: ist die IP, mit der sich der Absender verbunden hat, fuer diese
# Absenderdomain ueberhaupt erlaubt? Ohne DNS bleibt die Antwort "nicht
# beurteilbar", und eine gefaelschte Mail sieht aus wie eine ehrliche mit
# fehlender Authentifizierung.
#
# Der Preis ist ein URTEILSrisiko, nicht nur Angriffsflaeche: ein gefaelschter
# DNS-Eintrag macht aus einer ehrlichen Luecke eine gelogene Bestaetigung.
# Deshalb Vorgabe aus, System-Resolver (kein neuer Dritter), und ein
# fehlgeschlagener Abruf ist "unbekannt", nie "sauber".
#
# DNSSEC wird NICHT geprueft (keine Bibliothek dafuer) und die DKIM-Signatur
# NICHT verifiziert (Kanonisierung/Hashing ohne dkimpy nicht seriös). Was
# gemeldet wird, steht in core/dns_auth.py im Kopf.
DNS_AUTH_ENABLED = False

# -- Lokale Domain-Blockliste (Absender-Reputation, ebenfalls offline) ------ #
# Eine Domain pro Zeile. Der Abgleich laeuft ueber den Host aus dem From-Kopf
# und kuerzt von rechts (core/domain_blocklist.py), damit "mail.evil.tld"
# auch dann gefunden wird, wenn die Liste nur "evil.tld" fuehrt.
#
# Getrennt von der URL-Liste, weil es eine andere Frage ist: die URL-Liste
# erkennt EINEN bekannten Link, diese erkennt den ABSENDER.
DOMAIN_BLOCKLIST_FILE = Path(
    os.path.expandvars(r"%LocalAppData%\Malaz\hashes\domains.txt")
)

# -- Lokale IP-Blockliste (Absender-IPs, ebenfalls offline) ----------------- #
# CIDR-Netze, eine pro Zeile. Gefuellt aus Spamhaus DROP (Bulletproof-Hosting,
# Botnetze). Der Abgleich laeuft ueber die IP der ERSTEN Received-Station —
# also die Adresse, mit der sich der Absender verbunden hat.
IP_BLOCKLIST_FILE = Path(
    os.path.expandvars(r"%LocalAppData%\Malaz\hashes\netze.txt")
)


# --------------------------------------------------------------------------- #
# 7-Zip integration  (see core/sevenzip.py)
# --------------------------------------------------------------------------- #
#
# RAR- und 7z-Archive kann Python selbst nicht entpacken. Wenn eine 7-Zip-CLI
# (``7z``/``7zz``) installiert ist, werden auch diese Archive rekursiv gescannt.
# 7-Zip wird nur als externer Prozess aufgerufen (LGPL-Binary des Nutzers, wird
# NICHT mitgebündelt) — die Anwendung bleibt davon unberührt. Fehlt die Binary,
# werden RAR/7z nur oberflächlich (Entropie/YARA) geprüft und der Nutzer erhält
# einen Hinweis.
SEVENZIP_ENABLED = True
SEVENZIP_TIMEOUT_SECONDS = 120
SEVENZIP_CANDIDATES = (
    r"C:\Program Files\7-Zip\7z.exe",
    r"C:\Program Files (x86)\7-Zip\7z.exe",
)


# --------------------------------------------------------------------------- #
# Detect-It-Easy integration (see analysis/die.py)
# --------------------------------------------------------------------------- #
#
# Optional third-party engine (MIT license) for packer/compiler/protector
# identification of executables. Runs as an external process (like ClamAV/7-Zip);
# the binary is the user's own install and is NOT bundled. Only used for
# format/packer identification — never for malware-family verdicts, so the AV
# scope stays with Defender/ClamAV. Missing binary -> clean skip with a hint.
DIE_ENABLED = True
# A file with a valid Authenticode signature is not skipped from scanning, but
# the expensive DIE subprocess adds little to an already-trusted, signed
# binary. Skipping it there saves ~0.6 s per signed PE; unsigned and
# tampered files still go through DIE. Set False to always run DIE.
DIE_SKIP_SIGNED = True
DIE_TIMEOUT_SECONDS = 60
DIE_CANDIDATES = (
    r"C:\Program Files\Detect It Easy\diec.exe",
    r"C:\Program Files (x86)\Detect It Easy\diec.exe",
    r"C:\Program Files\DIE\diec.exe",
    r"C:\Tools\DIE\diec.exe",
)


# --------------------------------------------------------------------------- #
# capa integration (see analysis/capa.py)
# --------------------------------------------------------------------------- #
#
# Optional third-party engine (Apache-2.0) that names CAPABILITIES in whole
# sentences ("create process", "persist via Run key") — the layer DIE and YARA
# cannot give. Runs as an external process (like ClamAV/DIE/7-Zip); the binary
# is the user's own install and is NOT bundled. Missing binary -> clean skip
# with a hint, never a detection loss.
# AUS per Default — GEMESSEN, nicht geschaetzt.
#
# Mit dem Standalone-capa 9.4.0 auf harmlosen, alltaeglichen Bibliotheken:
#
#     libffi-8.dll      5 Faehigkeiten    23 s
#     msvcp140.dll     18 Faehigkeiten   139 s
#     libssl-3.dll      8 Faehigkeiten   302 s
#     libcrypto-3.dll   -                Timeout nach 600 s
#
# Mit CAPA_ENABLED = True kostet JEDE gepruefte .exe/.dll bis zu zwei Minuten.
# Ein Ordner mit 50 Programmen waere ueber eine Stunde — fuer ein Werkzeug,
# das man nebenbei laufen laesst, unbrauchbar. Wer die Faehigkeits-Analyse
# will, schaltet sie bewusst ein.
#
# Dazu kommt: capa meldet auf harmlosen Bibliotheken 5 bis 18 Faehigkeiten
# ("allocate or change RWX memory" auf libffi). Die Ausgabe ist eine
# Einordnung, kein Urteil — auch das spricht fuer bewusstes Einschalten.
CAPA_ENABLED = False
# Das Zeitlimit bleibt grosszuegig: wer einschaltet, will das Ergebnis. Es
# begrenzt nur den Ausreisser nach oben (libcrypto brauchte > 600 s).
CAPA_TIMEOUT_SECONDS = 120
CAPA_CANDIDATES = (
    r"C:\Program Files\capa\capa.exe",
    r"C:\Program Files (x86)\capa\capa.exe",
    r"C:\capa\capa.exe",
    r"C:\Tools\capa\capa.exe",
)
# Rule set for a capa that does NOT bring its own. The standalone release ships
# a ``rules\`` folder next to the binary and uses it automatically; a
# ``pip install flare-capa`` does not and exits with code 10 ("provide your own
# rule set via the `-r` option"). A directory found here is handed over as
# ``-r <dir>``. NOTHING is downloaded — Malaz stays offline; the user places the
# rules, and the skip message names this path.
CAPA_RULES_CANDIDATES = (
    r"C:\Program Files\capa\rules",
    r"C:\Program Files (x86)\capa\rules",
    r"C:\capa\rules",
    r"C:\Tools\capa\rules",
    r"C:\Tools\capa-rules",
)
# Cap on the capabilities taken from capa's JSON. The output describes an
# ATTACKER-CONTROLLED file, so its size is not ours to trust: a crafted sample
# could produce thousands of rule hits.
CAPA_MAX_RULES = 200
# Cap on the raw JSON text that is even parsed. The output grows with the number
# of matches (every matched rule carries its source text); for ordinary PE files
# it sits in the low hundreds of KB, so this ceiling is two orders of magnitude
# above normal and still bounds memory and parse time.
CAPA_MAX_OUTPUT_CHARS = 16 * 1024 * 1024
# Cap per individual string taken out of that JSON (rule name / namespace).
CAPA_MAX_STRING = 120
# Rule ids that describe the ENGINE configuration instead of the file (capa not
# installed). One source of truth for the golden snapshot
# (scripts/make_golden_snapshot.py AND tests/test_corpus_golden.py keep the same
# filter): such a note fires on every PE, so including it would turn any engine
# setting into a large diff and bury the real drift. The ``*_SKIPPED`` family
# (AV/ClamAV) is excluded by suffix for the same reason.
ENGINE_STATUS_RULE_IDS = frozenset(
    {
        "CAPA_UNAVAILABLE",
        # Die drei Listen-Marker sind derselbe Fall: sie sagen etwas ueber den
        # IMPORT-STAND dieser Maschine, nicht ueber die Datei. Im
        # Golden-Snapshot wuerden sie in JEDEM Eintrag stehen, sobald eine
        # Liste vorhanden-aber-unlesbar ist — und der Snapshot haenge dann am
        # Rechner des Entwicklers statt am Code.
        "DOMAIN_BLOCKLIST_UNAVAILABLE",
        "IP_BLOCKLIST_UNAVAILABLE",
        "URL_BLOCKLIST_UNAVAILABLE",
    }
)


# --------------------------------------------------------------------------- #
# Filename IOCs  (see core/filename_iocs.py)
# --------------------------------------------------------------------------- #
#
# Regex rules matched against the file path (Loki-style). Files live in
# ``rules/iocs/*.txt``; each line is ``regex[;score[;description]]``. A hit is
# reported with a weight derived from ``score`` (>= 50 anchors to RED). The
# directory is scanned for new/edited rule files on every load (cached briefly).
FILENAME_IOC_RULES_DIR = RULES_DIR / "iocs"
# Score thresholds: below this the hit is LOW, above HIGH, above this CRITICAL.
FILENAME_IOC_SCORE_HIGH = 30
FILENAME_IOC_SCORE_CRITICAL = 50


# --------------------------------------------------------------------------- #
# Embedded-signature scan  (see pipelines/generic_pipeline.py)
# --------------------------------------------------------------------------- #

# Master switch for the "known magic bytes elsewhere in the file" scan.
EMBEDDED_SIGNATURE_SCAN = True
# Maximum number of embedded signatures reported per file (responsiveness).
EMBEDDED_SIGNATURE_MAX = 8


# --------------------------------------------------------------------------- #
# Generic content checks  (see pipelines/generic_pipeline.py)
# --------------------------------------------------------------------------- #

# Master switch for the lightweight text/IOC/LNK heuristics in the generic
# pipeline. They only run on text-like / LNK content and are cheap.
GENERIC_CONTENT_CHECKS = True
# The content heuristics (decode, token search, IOC regexes) run on at most
# this many leading bytes. Without a cap, a large "unknown" binary would be
# decoded/lowered/scanned repeatedly in full (dozens of O(n) passes -> many
# seconds on 100 MB); a sample catches the overwhelming majority of real IOC
# placements and keeps scans responsive.
MAX_CONTENT_SCAN_SIZE = 4 * MB
# The IOC regexes additionally run over this many trailing bytes, so payloads
# appended to the end of a large file (the classic append trick) still get
# their URLs/IPs extracted.
MAX_CONTENT_TAIL_SIZE = 1 * MB


# --------------------------------------------------------------------------- #
# Address extraction from raw bytes  (see core/binary_iocs.py)
# --------------------------------------------------------------------------- #
#
# Formats that are NOT decoded as text (PE/ELF/Mach-O, PDF, OLE, images,
# archives) never went through the address check — although that is exactly
# where a C2 address sits. They are searched in their raw bytes now, capped
# here: the regexes run on attacker-controlled data, so both the input and the
# number of reported hits are bounded.
BINARY_IOC_SCAN_SIZE = 2 * MB
# Cap on reported addresses per file. A crafted file can contain millions of
# minimal matches; beyond this many the extraction stops.
BINARY_IOC_MAX_HITS = 200


# --------------------------------------------------------------------------- #
# External / EDR command-line scanners  (see analysis/external_scanner.py)
# --------------------------------------------------------------------------- #
#
# Hook for vendor CLIs we deliberately do NOT hard-code flags for (e.g. Cynet
# or any other EDR/AV that exposes an on-demand file scan). Your IT fills in the
# binary path and arguments taken from the vendor documentation. The literal
# token "{file}" in ``args`` is replaced by the scanned file path as a single
# argument (injection-safe, shell=False).
#
# Leave the list empty to disable. Example schema (uncomment & adapt):
#
# EXTERNAL_SCANNERS = [
#     {
#         "name": "Cynet",                          # label in the report
#         "binary": r"C:\Program Files\Cynet\...",  # path or name on PATH
#         "args": ["<scan-arg>", "{file}"],         # from vendor docs
#         "threat_rc": 1,                           # rc meaning "threat"
#         "clean_rc": 0,                            # rc meaning "clean"
#         "threat_markers": ["threat", "malware"],  # output substrings
#         "clean_markers": ["clean", "no threat"],
#         "timeout": 90,
#     },
# ]
EXTERNAL_SCANNERS: list[dict] = []


# --------------------------------------------------------------------------- #
# Encrypted-PDF handling  (see pipelines/pdf_pipeline.py)
# --------------------------------------------------------------------------- #
#
# Decrypting a PDF is static cryptography over the byte streams (AES/RC4); it
# executes no JavaScript / Launch / embedded payload, so it cannot "break out"
# the way opening the document in a viewer can. The only residual risk is a
# parser bug in the underlying C libraries, mitigated by running unprivileged
# and keeping the libraries current (see docs/SECURITY_MODEL.md). The PDF depth
# scan uses pikepdf (MPL-2.0, GPL-compatible) on top of qpdf, which is
# robust against malformed input, so no extra caps are needed.
# Try default passwords to look *inside* encrypted PDFs:
PDF_TRY_DEFAULT_PASSWORDS = True
# Passwords tried in order. The empty string covers owner-password-only PDFs.
PDF_PASSWORDS = ["", "owner", "password", "123456"]


# --------------------------------------------------------------------------- #
# Optional capability detection
# --------------------------------------------------------------------------- #

# Mapping of capability name -> top-level module that provides it.
_OPTIONAL_MODULES = {
    "numpy": "numpy",
    "yara": "yara",
    "pikepdf": "pikepdf",
    "oletools": "oletools",
    "xlm": "XLMMacroDeobfuscator",
    "openpyxl": "openpyxl",
    "pyside6": "PySide6",
}


@cache
def has_capability(name: str) -> bool:
    """Return True if the optional capability ``name`` is importable."""
    module = _OPTIONAL_MODULES.get(name)
    if module is None:
        return False
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def available_capabilities() -> dict[str, bool]:
    """Return the availability map for every optional capability."""
    return {name: has_capability(name) for name in _OPTIONAL_MODULES}


# --------------------------------------------------------------------------- #
# Default ZIP passwords used for password-protected archive triage.
# --------------------------------------------------------------------------- #

DEFAULT_ZIP_PASSWORDS = [
    "infected",
    "malware",
    "virus",
    "password",
    "123456",
    "1234",
]


@cache
def _load_zip_passwords_cached(mtime: float, size: int) -> tuple[str, ...]:
    """Read the password file; cache key invalidates on edit (see hashlist)."""
    passwords = list(DEFAULT_ZIP_PASSWORDS)
    try:
        if PASSWORD_FILE.exists():
            for line in PASSWORD_FILE.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    passwords.append(line)
    except OSError:
        pass
    return tuple(passwords)


def load_zip_passwords() -> list[str]:
    """Load the ZIP password list, falling back to the built-in defaults.

    Cached on the file's mtime/size — the extraction path reads it for
    EVERY archive (including nested ones), which made file I/O the hot
    path of recursive scans.
    """
    try:
        stat = PASSWORD_FILE.stat()
        mtime, size = stat.st_mtime, stat.st_size
    except OSError:
        mtime, size = -1.0, -1
    return list(_load_zip_passwords_cached(mtime, size))


def ensure_dirs() -> None:
    """Create the runtime directories the application relies on."""
    for path in (YARA_RULES_DIR, PASSWORD_FILE.parent, CACHE_DIR):
        path.mkdir(parents=True, exist_ok=True)
