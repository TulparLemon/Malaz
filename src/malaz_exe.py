r"""Nuitka entry wrapper for the frozen one-file build.

Nuitka compiles the named entry as the top-level ``__main__`` module without a
parent package, which breaks the relative imports at the top of
``malaz/__main__.py`` ("attempted relative import with no known parent
package"). This thin wrapper imports the real entry point through its fully
qualified package name so those relative imports resolve, then delegates to
``main()``. In the source layout the package is started with ``python -m
malaz`` instead; this module is only used as the Nuitka entry point.

The wrapper also installs a crash log: any uncaught exception (including Qt
slot exceptions escaping the event loop) is appended to
``%TEMP%\Malaz_crash.log`` before it propagates, so failures on
end-user machines can be diagnosed from the log file.
"""
import os
import sys
import tempfile
import traceback

CRASH_LOG = os.path.join(tempfile.gettempdir(), "Malaz_crash.log")


def _write_crash_log(context: str) -> None:
    try:
        from malaz.core.log_privacy import anonymize

        text = anonymize(f"--- {context} ---\n{traceback.format_exc()}\n")
        with open(CRASH_LOG, "a", encoding="utf-8", errors="replace") as fh:
            fh.write(text)
    except Exception:
        pass  # never mask the original error with a logging failure


def _excepthook(exc_type, exc_value, exc_tb) -> None:
    try:
        from malaz.core.log_privacy import anonymize

        text = anonymize(
            "--- uncaught exception ---\n"
            + "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
            + "\n"
        )
        with open(CRASH_LOG, "a", encoding="utf-8", errors="replace") as fh:
            fh.write(text)
    except Exception:
        pass
    # Default behaviour (stderr/traceback) stays intact.
    sys.__excepthook__(exc_type, exc_value, exc_tb)


from malaz.__main__ import main

if __name__ == "__main__":
    sys.excepthook = _excepthook
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception:
        _write_crash_log("main() raised")
        raise
