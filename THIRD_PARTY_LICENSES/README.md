# Third-Party Runtime License Texts

This directory contains the verbatim upstream license and notice files for the
47 Python wheel distributions included in the **Malaz** runtime environment
(matching the 48 runtime components documented in
[../THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md); `win_unicode_console`
ships without a separate license file in its wheel metadata).

- **Development-only packages** (`pytest`, `mypy`, `ruff`, `bandit`, `Nuitka`,
  etc.) are excluded from both binary builds and this directory.
- **Qt / PySide6 / shiboken6:** Conveyed under **GPL-3.0-or-later** ([../LICENSE](../LICENSE))
  pursuant to **LGPLv3 Section 3**; each `pyside6*` and `shiboken6` folder
  includes `licenses/LICENSE.GPLv3`, and commercial placeholder notices are
  excluded.
