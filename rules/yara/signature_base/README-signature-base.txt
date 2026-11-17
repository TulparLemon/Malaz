External YARA Rules — Source: Neo23x0/signature-base
====================================================
Upstream:    https://github.com/Neo23x0/signature-base
Archive URL: https://codeload.github.com/Neo23x0/signature-base/zip/refs/heads/master
License:     Detection Rule License (DRL) 1.1 at the repository level — full
             text in LICENSE-DRL-1.1.txt. Individual rules carry distinct
             `license` metadata documented in LICENSES-EINZELREGELN.txt
             (including CC BY-NC 4.0, which is incompatible with GPL-3.0
             redistribution).

Malaz does NOT bundle these rules in the Git repository or binary releases.
Users may fetch and precompile them locally on an opt-in basis via
scripts/update_signature_base.bat (`bundle.yarc` preserves `author` metadata;
13 rules requiring external variables filepath/filename/extension are skipped).
When redistributing rules or publishing rule-match reports, comply with DRL 1.1
attribution requirements (author, source URI, license text).
