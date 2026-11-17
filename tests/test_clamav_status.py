"""Tests for the ClamAV status/version checker (analysis/clamav_status.py)."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

from malaz.analysis.clamav_status import (
    ClamAvStatus,
    _remote_verdict,
    collect_status,
    db_age_days,
    fetch_remote_dates,
    format_status,
    parse_cvd_date,
    read_binary_version,
    read_db_dates,
)


def _cvd_header(day: int, month: str = "Aug", year: int = 2026) -> bytes:
    return f"ClamAV-VDB:{day} {month} {year} 06-25 +00".encode()


def test_parse_cvd_date():
    dt = parse_cvd_date(_cvd_header(11))
    assert dt is not None
    assert dt.year == 2026 and dt.month == 8 and dt.day == 11
    assert dt.hour == 6 and dt.minute == 25
    assert dt.tzinfo is not None


def test_parse_cvd_date_garbage():
    assert parse_cvd_date(b"kein clamav kopf") is None
    assert parse_cvd_date(b"") is None
    assert parse_cvd_date(b"ClamAV-VDB:99 Unbek 2026 06-25 +00") is None


def test_read_db_dates(tmp_path):
    (tmp_path / "daily.cvd").write_bytes(_cvd_header(11))
    (tmp_path / "main.cvd").write_bytes(_cvd_header(1, "Jan", 2026))
    dates = read_db_dates(tmp_path)
    assert dates["daily"].day == 11
    assert dates["main"].month == 1
    assert "bytecode" not in dates  # file missing -> skipped


def test_read_db_dates_missing_dir(tmp_path):
    assert read_db_dates(tmp_path / "gibt_es_nicht") == {}


def test_db_age_days():
    now = datetime(2026, 8, 12, tzinfo=UTC)
    dates = {"daily": now - timedelta(days=3)}
    assert db_age_days(dates, now) == 3
    assert db_age_days({}, now) is None
    # Future-dated DB (clock skew) is clamped to 0.
    assert db_age_days({"daily": now + timedelta(days=1)}, now) == 0


def test_read_binary_version(monkeypatch):
    monkeypatch.setattr(
        "malaz.analysis.clamav_status.run_tool",
        lambda *a, **k: (0, b"ClamAV 1.5.3\nbla\n", b""),
    )
    assert read_binary_version(Path("C:/fake/clamscan.exe")) == "ClamAV 1.5.3"


def test_read_binary_version_truncated_is_empty(monkeypatch):
    """SEC-023: a cut-off version string is not a version."""
    from malaz.procio import ToolResult

    monkeypatch.setattr(
        "malaz.analysis.clamav_status.run_tool",
        lambda *a, **k: ToolResult(0, b"ClamAV 1.5.3\n", b"", truncated=True),
    )
    assert read_binary_version(Path("C:/fake/clamscan.exe")) == ""


def test_read_binary_version_failure(monkeypatch):
    def boom(*a, **k):
        raise OSError("kaputt")

    monkeypatch.setattr(
        "malaz.analysis.clamav_status.run_tool", boom
    )
    assert read_binary_version(Path("C:/fake/clamscan.exe")) == ""


def test_fetch_remote_dates(monkeypatch):
    class FakeResponse:
        def __init__(self, data):
            self._data = data

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n):
            return self._data

        def geturl(self):
            # Redirect-Nachpruefung im Produktionscode braucht die finale URL.
            return "https://database.clamav.net/daily.cvd"

    def fake_urlopen(request, timeout=8):
        # daily is newer than main; bytecode responds with garbage.
        if "daily" in request.full_url:
            return FakeResponse(_cvd_header(11))
        if "main" in request.full_url:
            return FakeResponse(_cvd_header(1, "Jan", 2026))
        return FakeResponse(b"kaputt")

    monkeypatch.setattr(
        "malaz.analysis.clamav_status.urlopen", fake_urlopen
    )
    dates = fetch_remote_dates()
    assert dates["daily"].day == 11
    assert dates["main"].month == 1
    assert "bytecode" not in dates


def test_fetch_remote_dates_failure(monkeypatch):
    def boom(*a, **k):
        raise OSError("kein Netz")

    monkeypatch.setattr(
        "malaz.analysis.clamav_status.urlopen", boom
    )
    try:
        fetch_remote_dates()
        raised = False
    except OSError:
        raised = True
    assert raised


def test_remote_verdict():
    now = datetime(2026, 8, 12, tzinfo=UTC)
    # local == remote -> aktuell
    status = ClamAvStatus(
        db_dates={"daily": now},
        remote_dates={"daily": now},
    )
    assert "aktuell" in _remote_verdict(status)
    # local older -> Update verfügbar
    status = ClamAvStatus(
        db_dates={"daily": now - timedelta(days=2)},
        remote_dates={"daily": now},
    )
    assert "Update verfügbar" in _remote_verdict(status)
    # missing daily -> unklar
    status = ClamAvStatus(db_dates={}, remote_dates={"daily": now})
    assert "unklar" in _remote_verdict(status)


def test_collect_status_offline(monkeypatch, tmp_path):
    from malaz.analysis import clamav_status as module

    (tmp_path / "daily.cvd").write_bytes(_cvd_header(11))
    monkeypatch.setattr(module, "_locate_db_dir", lambda: tmp_path)
    monkeypatch.setattr(module, "read_binary_version", lambda b=None: "ClamAV 1.5.3")
    status = collect_status(include_remote=False)
    assert status.binary_version == "ClamAV 1.5.3"
    assert status.db_dates["daily"].day == 11
    assert status.remote_dates == {}
    assert status.error == ""


def test_format_status_lines():
    now = datetime(2026, 8, 12, tzinfo=UTC)
    line = format_status(ClamAvStatus(
        binary_version="ClamAV 1.5.3",
        db_dates={"daily": now - timedelta(days=1)},
    ))
    assert "ClamAV 1.5.3" in line
    assert "11.08.2026" in line or "1 Tag" in line

    line = format_status(ClamAvStatus())
    assert "nicht gefunden" in line

    line = format_status(ClamAvStatus(
        binary_version="ClamAV 1.5.3",
        error="TimeoutExpired",
    ))
    assert "Update-Check nicht möglich" in line
