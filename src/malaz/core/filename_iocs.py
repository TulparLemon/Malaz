"""Offline filename-IOC matching (Loki-style).

A line-based rule set of regular expressions matched (case-insensitively)
against the scanned file path. A hit is reported as an indicator whose weight
derives from an optional score; scores >= ``FILENAME_IOC_SCORE_CRITICAL`` make
the hit a CRITICAL anchor, exactly like the hash blocklist.

Rule file format (``rules/iocs/*.txt``):

    # comment
    regex
    regex;score
    regex;score;description

* the regex is a Python ``re`` pattern, matched with ``re.search`` against the
  full (lower-cased) path,
* ``score`` is 0..100 and maps to the indicator weight/severity,
* ``description`` is appended to the indicator detail.

The set is loaded on first use and cached briefly; new or edited rule files are
picked up on the next load (same pattern as the hash blocklist).
"""

from __future__ import annotations

import logging
import re
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from .. import config

log = logging.getLogger(__name__)

# Rule files are small; a short TTL keeps the IO negligible while edits to the
# rules directory still take effect quickly.
_CACHE_TTL_SECONDS = 10.0
_CACHE_DIR: str | None = None
_CACHE_AT = 0.0
_CACHE: tuple[list[_CompiledRule], list[str]] = ([], [])


@dataclass(frozen=True)
class _CompiledRule:
    pattern: re.Pattern
    score: int
    description: str


def _iter_rule_lines() -> list[tuple[str, str]]:
    """Yield ``(path, line)`` for every non-comment line in rules/iocs/*.txt."""
    out: list[tuple[str, str]] = []
    rules_dir = Path(config.FILENAME_IOC_RULES_DIR)
    try:
        if not rules_dir.is_dir():
            return out
        for rule_file in sorted(rules_dir.glob("*.txt")):
            try:
                raw = rule_file.read_text(encoding="utf-8", errors="ignore")
            except OSError as exc:
                log.warning("IOC-Datei %s nicht lesbar: %s", rule_file, exc)
                continue
            for line in raw.splitlines():
                stripped = line.strip().lstrip("\ufeff")
                if stripped and not stripped.startswith("#"):
                    out.append((str(rule_file), stripped))
    except OSError as exc:
        log.warning("IOC-Regelverzeichnis nicht lesbar: %s", exc)
    return out


def _build_rules() -> tuple[list[_CompiledRule], list[str]]:
    """Compile every rule line; return ``(rules, errors)``."""
    rules: list[_CompiledRule] = []
    errors: list[str] = []
    for source, line in _iter_rule_lines():
        # Format: regex[;score[;description]] — the DESCRIPTION may contain
        # semicolons (joined back together). A regex itself must NOT contain
        # a bare ';' — rewrite it (e.g. via character class) or the pattern
        # would be silently truncated at the first semicolon.
        parts = line.split(";")
        pattern_text = parts[0].strip()
        score = 0
        description = ""
        if len(parts) >= 2 and parts[1].strip():
            with suppress(ValueError):
                score = max(0, min(100, int(parts[1].strip())))
        if len(parts) >= 3:
            description = ";".join(parts[2:]).strip()
        if not pattern_text:
            continue
        try:
            compiled = re.compile(pattern_text, re.IGNORECASE)
        except re.error as exc:
            errors.append(f"{source}: ungültiger Regex {pattern_text!r}: {exc}")
            continue
        rules.append(_CompiledRule(compiled, score, description))
    return rules, errors


def _load_rules() -> tuple[list[_CompiledRule], list[str]]:
    """Load + compile the rule set with a short TTL cache.

    The cache is keyed on the configured rules directory so a runtime change of
    ``config.FILENAME_IOC_RULES_DIR`` (tests, deployments) takes effect.
    """
    global _CACHE_DIR, _CACHE_AT, _CACHE
    now = time.monotonic()
    dir_key = str(config.FILENAME_IOC_RULES_DIR)
    if dir_key == _CACHE_DIR and now - _CACHE_AT < _CACHE_TTL_SECONDS:
        return _CACHE
    rules, errors = _build_rules()
    _CACHE = (rules, errors)
    _CACHE_AT = now
    _CACHE_DIR = dir_key
    return _CACHE


def load_errors() -> list[str]:
    """Return the compile errors of the current rule set (for diagnostics)."""
    return _load_rules()[1]


@dataclass(frozen=True)
class FilenameIocMatch:
    pattern: str
    score: int
    description: str


def match_filename_iocs(path_text: str) -> list[FilenameIocMatch]:
    """Return all IOC rules matching ``path_text`` (case-insensitive)."""
    if not path_text:
        return []
    rules, _ = _load_rules()
    if not rules:
        return []
    lowered = path_text.lower()
    hits: list[FilenameIocMatch] = []
    for rule in rules:
        if rule.pattern.search(lowered):
            hits.append(
                FilenameIocMatch(rule.pattern.pattern, rule.score, rule.description)
            )
    return hits
