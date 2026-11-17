External YARA Rules — Source: ReversingLabs (MIT License)
=========================================================
Archive URL: https://codeload.github.com/reversinglabs/reversinglabs-yara-rules/zip/refs/heads/develop
Upstream:    https://github.com/reversinglabs/reversinglabs-yara-rules
License:     MIT — full text in LICENSE-MIT-ReversingLabs.txt in this directory.

Malaz does NOT bundle these rules in the Git repository or binary releases.
When explicitly downloaded by the user ("YARA-Regeln nachladen" /
src/malaz/core/yara_update.py), the .yar sources are validated under bounded
decompression limits, compiled locally to bundle.yarc (preserving rule
namespaces and `author` metadata), and removed afterwards. Any redistribution
must retain the MIT copyright and permission notice.
