"""Tests for procio: subprocess wrapper, console suppression, temp suffixes."""

import subprocess
import sys
import time
from unittest import mock

import pytest

from malaz import procio
from malaz.procio import (
    decode_tool_output,
    no_window_flags,
    run_tool,
    safe_temp_suffix,
    strip_scan_target,
    tool_output_truncated,
)


def test_no_window_flags_platform_aware():
    flags = no_window_flags()
    if procio.os.name == "nt":
        assert flags == subprocess.CREATE_NO_WINDOW
    else:
        assert flags == 0


def test_run_tool_passes_create_no_window_to_popen():
    # Regression: without CREATE_NO_WINDOW every engine call flashed a black
    # console window per scanned file in the GUI (pythonw has no console).
    captured = {}

    class FakeProc:
        returncode = 0

        def __init__(self):
            self.stdout = _FakePipe(b"")
            self.stderr = _FakePipe(b"")
            self.stdin = None

        def wait(self, timeout=None):
            return 0

        def kill(self):  # pragma: no cover
            raise AssertionError("darf nicht aufgerufen werden")

    class _FakePipe:
        def __init__(self, data):
            self._data = data

        def read(self, size=-1):
            data, self._data = self._data, b""
            return data

        def close(self):
            pass

    def fake_popen(args, **kwargs):
        captured.update(kwargs)
        return FakeProc()

    with mock.patch.object(procio.subprocess, "Popen", side_effect=fake_popen):
        rc, out, err = run_tool(["echo", "hi"], timeout=5)
    assert (rc, out, err) == (0, b"", b"")
    if procio.os.name == "nt":
        assert captured["creationflags"] == subprocess.CREATE_NO_WINDOW


def test_run_tool_returns_output_and_rc():
    if procio.os.name != "nt":
        pytest.skip("Windows-cmd Test")
    rc, out, _err = run_tool(["cmd", "/c", "echo malaz-probe"], timeout=10)
    assert rc == 0
    assert b"malaz-probe" in out


def test_run_tool_timeout_kills_process():
    if procio.os.name != "nt":
        pytest.skip("Windows-ping Test")
    with pytest.raises(subprocess.TimeoutExpired):
        run_tool(["ping", "-n", "10", "127.0.0.1"], timeout=1.0)
    # Der Timeout muss den Prozess getoetet haben: ein erneuter schneller
    # Aufruf zeigt, dass nichts haengen bleibt.
    rc, _out, _err = run_tool(["cmd", "/c", "echo ok"], timeout=10)
    assert rc == 0


def test_run_tool_hard_shutdown_kills_process():
    if procio.os.name != "nt":
        pytest.skip("Windows-ping Test")
    procio.request_hard_shutdown()
    try:
        with pytest.raises(procio.HardShutdown):
            run_tool(["ping", "-n", "10", "127.0.0.1"], timeout=30)
    finally:
        procio.clear_hard_shutdown()
    # Nach dem Clear laufen Aufrufe wieder normal.
    start = time.monotonic()
    rc, _out, _err = run_tool(["cmd", "/c", "echo ok"], timeout=10)
    assert rc == 0 and time.monotonic() - start < 10


def test_decode_tool_output_utf8_first_oem_fallback():
    assert decode_tool_output(b"plain ascii") == "plain ascii"
    # cp850: 0x84 = ä, kein gueltiges UTF-8 -> OEM-Fallback auf Windows.
    if procio.os.name == "nt":
        assert "ä" in decode_tool_output(b"quarant\x84ne")


def test_strip_scan_target_keeps_a_verdict_line_named_like_the_file():
    # SEC-018: only the echo line may lose the file name. The scanner's own
    # result line is byte-identical to the name here and must survive.
    out = strip_scan_target(
        "Scanning C:\\tmp\\found 1 threats\nfound 1 threats",
        "C:\\tmp\\found 1 threats",
    )
    assert out.splitlines() == ["Scanning ", "found 1 threats"]


def test_strip_scan_target_never_removes_a_standalone_verdict_token():
    # A token outside an echo line is tool output/data, not a path echo — even
    # when it is exactly the scanned file's name.
    assert (
        strip_scan_target("found 1 threats", "C:/x/found 1 threats")
        == "found 1 threats"
    )
    assert (
        strip_scan_target("threat detected", "C:/x/threat detected.pdf")
        == "threat detected"
    )


def test_strip_scan_target_removes_the_name_inside_echo_lines():
    out = strip_scan_target(
        "file: threat detected.pdf found 1 threats.",
        "C:/scan/threat detected.pdf",
    )
    assert "threat detected.pdf" not in out
    # The genuine result token next to the echo stays.
    assert "found 1 threats" in out

    # clamscan echoes "<name>: OK" — the name still belongs to the echo, so
    # phrases inside it (here "connection refused") must not reach the
    # daemon-lost heuristic.
    clam = strip_scan_target("connection refused.pdf: OK", "connection refused.pdf")
    assert "connection refused" not in clam


def test_safe_temp_suffix_whitelist_and_cap():
    assert safe_temp_suffix(".pdf") == ".pdf"
    assert safe_temp_suffix("pdf") == ".pdf"
    assert safe_temp_suffix(".e<x|file") == ".e_x_file"
    assert safe_temp_suffix("") == ".bin"
    assert safe_temp_suffix(None) == ".bin"
    assert safe_temp_suffix("...") == ".bin"
    # Pfad-Trenner und Laengenbegrenzung
    assert "/" not in safe_temp_suffix("../evil")
    assert "\\" not in safe_temp_suffix("..\\evil")
    assert len(safe_temp_suffix("a" * 300)) <= 17


def test_run_tool_caps_the_output_buffer(monkeypatch):
    """SEC-023: a tool that floods stdout must not become process memory.

    Vorher las ``_pump`` bis EOF in einen ungeteilten ``bytes``; ein
    praepariertes 7z/RAR mit Millionen Eintraegen puffert die komplette
    Ausgabe. Jetzt bleibt ein Prefix stehen, der Rest wird verworfen — der
    Rohrinhalt wird weiter abgefuehrt, damit das Kind nicht blockiert.
    """

    class BigPipe:
        def __init__(self, data):
            self._rest = data

        def read(self, size=-1):
            if not self._rest:
                return b""
            take = len(self._rest) if size is None or size < 0 else size
            chunk, self._rest = self._rest[:take], self._rest[take:]
            return chunk

        def close(self):
            pass

    class FakeProc:
        returncode = 0

        def __init__(self):
            self.stdout = BigPipe(b"o" * 100_000)
            self.stderr = BigPipe(b"e")
            self.stdin = None

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(procio, "MAX_TOOL_OUTPUT_BYTES", 1024)
    with mock.patch.object(
        procio.subprocess, "Popen", side_effect=lambda *a, **k: FakeProc()
    ):
        result = run_tool(["fake-tool"], timeout=5)

    rc, out, err = result
    assert rc == 0
    assert len(out) == 1024, f"{len(out)} Bytes gepuffert statt 1024"
    assert err == b"e"
    assert result.truncated is True
    assert tool_output_truncated(result) is True


def _flooding_tool(extra_bytes: int) -> list[str]:
    """A real Python child that writes more than the output cap, in chunks."""
    code = (
        "import sys\n"
        "chunk = b'x' * 65536\n"
        f"left = {procio.MAX_TOOL_OUTPUT_BYTES + extra_bytes}\n"
        "out = sys.stdout.buffer\n"
        "while left > 0:\n"
        "    take = min(left, len(chunk))\n"
        "    out.write(chunk[:take])\n"
        "    out.flush()\n"
        "    left -= take\n"
    )
    return [sys.executable, "-c", code]


def test_run_tool_marks_a_flooding_tool_as_truncated():
    """SEC-023: >8 MiB output is a PREFIX — the flag must say so.

    The tool writes chunked, never a big file on disk: the point is the pipe
    cap, not the child's payload.
    """
    result = run_tool(_flooding_tool(4096), timeout=60)

    assert result.truncated is True
    # The tuple contract still works for every existing caller.
    rc, out, err = result
    assert rc == 0
    assert len(out) == procio.MAX_TOOL_OUTPUT_BYTES
    assert err == b""


def test_run_tool_marks_a_flooding_stderr_as_truncated():
    """The flag covers BOTH pipes — stderr can carry the decisive line too."""
    code = (
        "import sys\n"
        "chunk = b'e' * 65536\n"
        f"left = {procio.MAX_TOOL_OUTPUT_BYTES + 4096}\n"
        "err = sys.stderr.buffer\n"
        "while left > 0:\n"
        "    take = min(left, len(chunk))\n"
        "    err.write(chunk[:take])\n"
        "    err.flush()\n"
        "    left -= take\n"
    )
    result = run_tool([sys.executable, "-c", code], timeout=60)

    assert result.truncated is True
    assert len(result[2]) == procio.MAX_TOOL_OUTPUT_BYTES
    assert result[1] == b""


def test_run_tool_does_not_flag_output_below_the_cap():
    code = "import sys; sys.stdout.buffer.write(b'x' * 4096)"
    result = run_tool([sys.executable, "-c", code], timeout=60)

    assert result.truncated is False
    assert tool_output_truncated(result) is False
    rc, out, err = result
    assert (rc, out, err) == (0, b"x" * 4096, b"")
    # Plain tuples (test fakes, older call sites) count as complete — the
    # behaviour before the flag existed.
    assert tool_output_truncated((0, b"", b"")) is False
