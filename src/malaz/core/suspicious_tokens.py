"""Canonical command/LOLBin vocabulary for text and binary string checks.

One source of truth: the generic text heuristics and the PE string stage must
agree on what a command-shaped string is. Keeping two tuples made a newly
added LOLBin reach only one of the two paths.
"""

from __future__ import annotations

# Kept to high-signal tokens to limit false positives. Ordered for stable
# report output; matching is case-insensitive at the call sites.
SUSPICIOUS_COMMAND_TOKENS = (
    "powershell",
    "cmd.exe",
    "cmd /c",
    "wscript",
    "cscript",
    "mshta",
    "regsvr32",
    "rundll32",
    "certutil",
    "bitsadmin",
    "wmic",
    "schtasks",
    "wevtutil",
    "net user",
    "net localgroup",
    "add-mppreference",
    "set-mppreference",
    "-executionpolicy bypass",
    "-windowstyle hidden",
    "-nop ",
    "-encodedcommand",
    "downloadstring",
    "downloadfile",
    "invoke-expression",
    "frombase64string",
    "iex(",
    "vssadmin delete",
    "bcdedit",
)
