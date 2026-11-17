"""PATH lookup that never resolves through the current directory.

``shutil.which`` honours every ``PATH`` entry — including empty entries (POSIX:
current directory) and relative ones such as ``.``. Measured on Windows: a
planted ``diec.exe`` in the scan directory was resolved as ``.\\diec.EXE``, and
the analysis run then executes a file that arrived with the sample. SEC-010
closed this for 7-Zip; the other tool lookups (DIE, ClamAV, capa, PowerShell,
external scanner) had the same hole.

Only ABSOLUTE ``PATH`` entries are passed through, and a non-absolute result is
rejected as well — on Windows the loader additionally resolves a bare name
against the current directory.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path


def which_absolute(name: str) -> Path | None:
    """Return the absolute path of ``name`` on ``PATH``, else ``None``.

    Never returns a relative path and never searches the current directory.
    """
    entries = []
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        # Windows PATH entries are sometimes stored quoted; strip that first
        # so a legitimate absolute directory is not discarded as "relative".
        entry = entry.strip().strip('"')
        # Some launchers leave %VAR% references unexpanded in PATH; without
        # this they look relative and the directory would be dropped.
        entry = os.path.expandvars(entry)
        if entry and Path(entry).is_absolute():
            entries.append(entry)
    if not entries:
        return None
    found = shutil.which(name, path=os.pathsep.join(entries))
    if not found:
        return None
    candidate = Path(found)
    return candidate if candidate.is_absolute() else None
