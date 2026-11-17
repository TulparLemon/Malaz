"""Deterministic output helpers for the synthetic test corpora.

The three corpus generators (``make_test_corpus``, ``make_test_corpus_extended``,
``make_benign_corpus``) build fixtures with third-party writers that stamp the
CURRENT time or a random ID into their output:

* ``zipfile.writestr(str, …)`` sets each entry's ``date_time`` from the clock.
* ``openpyxl`` sets ``properties.modified`` inside ``save_workbook()`` — AFTER
  any pin the caller applied, so pinning ``wb.properties`` alone does not work.
* ``pikepdf`` writes a random ``/ID`` into the trailer unless told otherwise.

Two builds of the same fixture are therefore byte-identical only when they land
in the same second (ZIP: DOS resolution 2 s) or share the ID. That made
``test_extended_corpus_is_deterministic`` — which builds every fixture twice and
compares bytes — fail intermittently: measured across 133 builders, **19 were
clock-dependent**, and the failure showed up roughly once in six full runs.

Everything here pins the non-deterministic parts without changing the file's
*content*: the fixtures stay real, valid files of their format (which is what
makes them useful for false-positive work), only the timestamps and IDs become
constants. Fixed values are used instead of the current time so repeated runs
produce identical bytes, which the golden snapshot depends on.

The same reasoning applies to the *scan environment* of a corpus run: the
lists and rule feeds the user imported are per-machine state, not a property
of the code under test. :func:`pin_user_threat_intel` keeps them out.
"""

from __future__ import annotations

import gzip
import io
import tarfile
import tempfile
import zipfile
from contextlib import contextmanager
from pathlib import Path

#: Constant used for every embedded timestamp. Any fixed date works; this one
#: matches the pin already used by the ZIP helper in make_test_corpus_extended.
FIXED_TIME = (2026, 1, 1, 0, 0, 0)


def zip_write(zf, name: str, data: bytes, compress: bool = True) -> None:
    """Add one entry with a fixed timestamp to an open ZipFile.

    ``ZipFile.writestr(str, …)`` builds its ``ZipInfo`` internally and takes
    ``date_time`` from the current clock (DOS resolution: 2 s), so two builds
    differ when they straddle that boundary. Passing an explicit ``ZipInfo``
    is the only way to pin it. Use this instead of ``zf.writestr`` for every
    corpus fixture.

    Uses the ``ZipInfo`` class of the archive's own module: ``pyzipper``
    (AES-ZIP support) has its own class and rejects the stdlib one with
    "'ZipInfo' object has no attribute 'find'".
    """
    # The archive knows which ZipInfo class it expects (zipfile vs pyzipper).
    info_cls = getattr(zf, "zipinfo_cls", zipfile.ZipInfo)
    info = info_cls(name, date_time=FIXED_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED
    zf.writestr(info, data)


def pin_mime_boundary(msg, boundary: str = "MALAZ-DETERMINISTIC-BOUNDARY") -> None:
    """Replace every generated MIME boundary with a fixed one, in place.

    ``EmailMessage.set_content()``/``add_attachment()`` generate a random
    boundary (``===============<random>==``), so two builds of the same mail
    differ. Verified: setting the boundary makes the serialized bytes identical
    across builds.

    Must run BEFORE the first serialization: with the modern policy the
    boundary attribute starts out ``None`` and is only generated while writing,
    so a check on ``part.get_boundary()`` would skip every part and the boundary
    would stay random (caught by the corpus determinism audit — the first
    version of this helper did exactly that).
    """
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            part.set_boundary(boundary)


def save_workbook_deterministic(wb) -> bytes:
    """Serialize an openpyxl workbook with fully reproducible bytes.

    Pinning ``wb.properties`` alone is NOT enough — measured over a >2 s gap,
    two builds still differed in the ZIP *headers*:

      * ``Workbook.save()`` calls ``save_workbook()``, which assigns
        ``properties.modified = now()`` right before writing
        (``openpyxl/writer/excel.py:292``), overwriting any pin the caller set.
        That is why the pin in the neighbouring builder never worked.
      * ``ExcelWriter.write_data()`` writes every part via
        ``archive.writestr(<str name>, …)`` (``excel.py:60-90``), and ``zipfile``
        takes ``date_time`` from ``time.localtime()`` for string names — DOS
        resolution 2 s.

    So both layers are pinned here: the workbook is written by ``ExcelWriter``
    directly (skipping the ``modified`` assignment) and the resulting archive is
    re-packed with explicit ``ZipInfo`` timestamps.
    """
    from datetime import datetime

    from openpyxl.writer.excel import ExcelWriter

    wb.properties.created = datetime(*FIXED_TIME)  # noqa: DTZ001
    wb.properties.modified = datetime(*FIXED_TIME)  # noqa: DTZ001

    buf = io.BytesIO()
    archive = zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED)
    ExcelWriter(wb, archive).save()

    # Re-pack: zipfile stamped the entries with the current time.
    return repack_zip(buf.getvalue())


@contextmanager
def open_tar_gz(buf):
    """Context manager for a .tar.gz writer with fixed timestamps.

    Two layers default to the current time:
      * ``tarfile.open(mode="w:gz")`` stores the gzip header's ``mtime``, and
      * each ``TarInfo`` gets ``mtime = now()`` when only ``size`` is set.

    Measured over a >2 s gap, both made the bytes differ.

    Both layers must be handled here because ``tarfile.open()`` cannot be given
    a ``GzipFile`` with a pinned ``mtime``. The GzipFile is therefore closed
    EXPLICITLY, and that is not redundant:

    * ``TarFile.close()`` only closes the stream when ``_extfileobj`` is False
      (tarfile.py:409/473). ``taropen()`` sets ``_extfileobj = True`` whenever a
      ``fileobj`` was passed (tarfile.py:1705).
    * ``gzopen``/``bz2open``/``xzopen`` reset it to False right after opening
      (tarfile.py:1919 etc.) — precisely so ``close()`` finishes the
      compression. Building the GzipFile ourselves bypasses that, so the gzip
      trailer (CRC32 + ISIZE) would never be written: measured 10 bytes instead
      of 221, an unreadable archive.

    Verified at the finished artifact, not just by comparison: ``gzip.decompress``
    runs through and the trailer's ISIZE matches the decompressed length.
    Callers set member timestamps via :func:`tar_write`.
    """
    raw = gzip.GzipFile(fileobj=buf, mode="wb", mtime=0)
    # SIM115 wants a "with" here, which is exactly the bug described above: the
    # tar stream does NOT close the file object it was handed.
    tf = tarfile.open(fileobj=raw, mode="w")  # noqa: SIM115
    try:
        yield tf
    finally:
        tf.close()   # writes the tar end-of-archive blocks
        raw.close()  # writes the gzip trailer (CRC32 + ISIZE)


def tar_write(tf, name: str, data: bytes) -> None:
    """Add one member with a fixed mtime to an open tar writer."""
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mtime = 0
    tf.addfile(info, io.BytesIO(data))


def repack_zip(data: bytes) -> bytes:
    """Rewrite a ZIP with fixed entry timestamps, preserving member order.

    Member order is kept exactly as-is: an OOXML container is read by name, but
    re-ordering would still change the bytes and defeat the purpose.
    """
    src = zipfile.ZipFile(io.BytesIO(data))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dst:
        for item in src.infolist():
            info = zipfile.ZipInfo(item.filename, date_time=FIXED_TIME)
            info.compress_type = item.compress_type
            info.external_attr = item.external_attr
            info.internal_attr = item.internal_attr
            info.create_system = item.create_system
            dst.writestr(info, src.read(item.filename))
    return out.getvalue()


def save_pdf_deterministic(pdf, **save_options) -> bytes:
    """Serialize a pikepdf document without a random trailer ``/ID``.

    pikepdf writes a random ``/ID`` unless ``deterministic_id`` is set, which
    makes every rebuild differ. Content streams are unaffected. Extra
    ``save_options`` (e.g. ``object_stream_mode``) pass through unchanged.
    """
    buf = io.BytesIO()
    pdf.save(buf, deterministic_id=True, **save_options)
    return buf.getvalue()


@contextmanager
def pin_no_7zip():
    """Pin the scan to „no 7-Zip installed" for corpus/snapshot runs.

    Whether 7-Zip is installed is per-machine state, not a property of the
    code under test: with the CLI present, CAB/ISO members are extracted and
    scanned; without it, the same file yields ``ARCH_7Z_MISSING`` (20). The
    committed golden snapshot was recorded on a machine without 7-Zip, so a
    developer/VM with 7-Zip saw drift in files nobody changed (the handover
    documented this as an open environment dependency).

    This pins the branch WITHOUT disabling the stage: ``SEVENZIP_ENABLED``
    stays true, so the visible note remains ``ARCH_7Z_MISSING`` — the state
    the snapshot recorded. ``pin_no_7zip`` is for measurements; real scans in
    the GUI keep using an installed 7-Zip.
    """
    from malaz.core import sevenzip

    original = sevenzip.find_7z_binary
    sevenzip.find_7z_binary = lambda: None
    try:
        yield
    finally:
        sevenzip.find_7z_binary = original


@contextmanager
def pin_user_threat_intel():
    """Run a measurement against the project's own rule set.

    The bytes of a fixture are not the only non-reproducible input: the
    *scan environment* is one too. ``config.USER_HASH_BLOCKLIST_FILE``,
    ``config.URL_BLOCKLIST_FILE`` and the third-party ``YARA_FEED_DIRS`` are
    inputs the user imports on his machine (see scripts/import_blocklist.py,
    update_signature_base.bat). Whatever the developer happens to have
    imported must not reach a measurement, or the tripwire reports his
    import state instead of a code change — measured with
    ``make_golden_snapshot.py --check``: with the imported URL list two of 91
    files drifted (phish_links.eml, phish_schemes.eml, each plus
    MAIL_REPUTATION_CLEAN), with an empty profile none. ``conftest.py`` pins
    the same values for pytest; this is the script-side counterpart and the
    one place both consumers use (the corpus runners and the golden
    snapshot).
    """
    from malaz import config

    # ALLE Listen, die der Nutzer importiert. Die beiden letzten kamen mit der
    # Absender-Reputation dazu und fehlten hier: der Golden-Snapshot — ein
    # COMMITTETES Artefakt — hing damit davon ab, wer ihn zuletzt erzeugt hat.
    # Heute zufaellig unauffaellig (kein Treffer im Korpus), aber ungeschuetzt:
    # ein Fixture, dessen Absenderdomain in der importierten Liste steht,
    # bekaeme MAIL_SENDER_DOMAIN_BLOCKED (CRITICAL/50) und kippte GRUEN -> ROT.
    saved = (
        config.USER_HASH_BLOCKLIST_FILE,
        config.URL_BLOCKLIST_FILE,
        config.DOMAIN_BLOCKLIST_FILE,
        config.IP_BLOCKLIST_FILE,
        config.YARA_FEED_DIRS,
    )
    with tempfile.TemporaryDirectory(prefix="malaz_no_user_threat_intel_") as empty:
        # Never created: the loaders then see a fresh install ("missing").
        config.USER_HASH_BLOCKLIST_FILE = Path(empty) / "hashes.sha256"
        config.URL_BLOCKLIST_FILE = Path(empty) / "urls.sha256"
        config.DOMAIN_BLOCKLIST_FILE = Path(empty) / "domains.txt"
        config.IP_BLOCKLIST_FILE = Path(empty) / "netze.txt"
        config.YARA_FEED_DIRS = ()
        try:
            yield
        finally:
            (
                config.USER_HASH_BLOCKLIST_FILE,
                config.URL_BLOCKLIST_FILE,
                config.DOMAIN_BLOCKLIST_FILE,
                config.IP_BLOCKLIST_FILE,
                config.YARA_FEED_DIRS,
            ) = saved
