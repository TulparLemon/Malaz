import struct

from malaz.core.lnk import parse_lnk

_MAGIC = b"\x4c\x00\x00\x00"
_CLSID = b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"


def _header(flags: int) -> bytes:
    return _MAGIC + _CLSID + struct.pack("<I", flags) + b"\x00" * (76 - 24)


def _ustr(s: str) -> bytes:
    enc = s.encode("utf-16-le")
    return struct.pack("<H", len(s)) + enc


def _astr(s: str) -> bytes:
    enc = s.encode("cp1252")
    return struct.pack("<H", len(enc)) + enc


def test_invalid_blob():
    info = parse_lnk(b"not a link")
    assert not info.valid


def test_parses_arguments_unicode():
    flags = (1 << 5) | (1 << 7)  # HasArguments + IsUnicode
    data = _header(flags) + _ustr("cmd.exe /c calc")
    info = parse_lnk(data)
    assert info.valid
    assert info.has_arguments
    assert info.arguments == "cmd.exe /c calc"
    assert "HasArguments" in info.flag_names


def test_parses_relative_and_working_dir_ansi():
    flags = (1 << 3) | (1 << 4)  # HasRelativePath + HasWorkingDir, no unicode
    data = _header(flags) + _astr("C\\malware.exe") + _astr("C:\\Temp")
    info = parse_lnk(data)
    assert info.valid
    assert info.relative_path == "C\\malware.exe"
    assert info.working_dir == "C:\\Temp"


def test_interesting_strings_only_nonempty():
    flags = (1 << 5) | (1 << 7)
    data = _header(flags) + _ustr("pwsh -enc X")
    info = parse_lnk(data)
    joined = " ".join(info.interesting_strings())
    assert "Argumente" in joined
    assert "Arbeitsverzeichnis" not in joined
