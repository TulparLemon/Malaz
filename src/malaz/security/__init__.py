"""Cross-cutting security hardening utilities.

These helpers protect the tool itself while it analyses potentially hostile
input: path-traversal (Zip-Slip) protection, output escaping (XSS) and
resource-exhaustion (DoS) guards.
"""

from .escaping import escape_html, safe_excerpt
from .limits import LimitExceeded, guard_file_size, guard_ratio, guard_read_size
from .safe_extract import is_safe_member_name

__all__ = [
    "LimitExceeded",
    "escape_html",
    "guard_file_size",
    "guard_ratio",
    "guard_read_size",
    "is_safe_member_name",
    "safe_excerpt",
]
