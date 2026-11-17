"""AP9: bounded, deterministic ASCII/UTF-16LE extraction."""

from __future__ import annotations

from malaz.core.strings_extract import SectionSpan, extract_strings


def test_ascii_and_utf16le_are_extracted_in_file_order():
    data = b"\x00\x00HelloAscii\x00" + "World".encode("utf-16-le") + b"\x00\x00\x00"
    result = extract_strings(data, min_len=4)
    values = [entry.value for entry in result.strings]
    assert "HelloAscii" in values
    assert "World" in values
    entries = {entry.value: entry for entry in result.strings}
    assert entries["HelloAscii"].offset == 2
    assert entries["HelloAscii"].encoding == "ascii"
    assert entries["World"].encoding == "utf-16le"
    assert entries["World"].offset > entries["HelloAscii"].offset


def test_min_length_is_honoured():
    result = extract_strings(b"ab\x00abcdef", min_len=4)
    assert [entry.value for entry in result.strings] == ["abcdef"]
    result = extract_strings(b"ab\x00abcdef", min_len=2)
    assert {entry.value for entry in result.strings} == {"ab", "abcdef"}


def test_duplicates_keep_the_first_occurrence():
    result = extract_strings(b"repeat\x00repeat\x00repeat")
    hits = [entry for entry in result.strings if entry.value == "repeat"]
    assert len(hits) == 1
    assert hits[0].offset == 0


def test_sections_attribute_offsets():
    sections = (
        SectionSpan(".text", 0, 8),
        SectionSpan(".data", 8, 16),
    )
    data = b"AAAA\x00\x00\x00\x00BBBBBBBBBBBBBBB"
    result = extract_strings(data, sections=sections)
    by_value = {entry.value: entry.section for entry in result.strings}
    assert by_value["AAAA"] == ".text"
    assert by_value["BBBBBBBBBBBBBBB"] == ".data"


def test_max_bytes_cap_is_reported():
    result = extract_strings(b"A" * 100, max_bytes=10, max_strings=10)
    assert result.scanned_bytes == 10
    assert "bytes" in result.caps
    assert result.strings[0].value == "A" * 10


def test_max_count_cap_is_reported():
    result = extract_strings(b"AAAA\x00BBBB\x00CCCC\x00DDDD", max_strings=2)
    assert len(result.strings) == 2
    assert "count" in result.caps
    assert result.capped


def test_max_string_length_cap_is_reported():
    result = extract_strings(b"A" * 100, max_string_length=10)
    assert result.strings[0].value == "A" * 10
    assert "length" in result.caps


def test_extraction_is_deterministic():
    data = b"alpha\x00beta\x00" + "gamma".encode("utf-16-le")
    assert extract_strings(data) == extract_strings(data)


def test_binary_garbage_does_not_raise():
    import random

    rng = random.Random(7)
    result = extract_strings(bytes(rng.randrange(256) for _ in range(4096)))
    assert result.scanned_bytes == 4096
    # Random bytes may contain short printable runs; no crash and no
    # unbounded growth is the contract.
    assert len(result.strings) <= 2000


def test_count_cap_is_not_claimed_when_nothing_is_skipped():
    result = extract_strings(b"AAAA\x00BBBB", max_strings=2)
    assert len(result.strings) == 2
    assert "count" not in result.caps
    result = extract_strings(b"AAAA\x00BBBB\x00CCCC", max_strings=2)
    assert "count" in result.caps
