"""Atheris-Harness: EML-/MSG-Parser und Mail-Pipeline.

``EmlPipeline`` arbeitet vollständig im Speicher (Header, MIME-Bäume,
Base64-/QP-Dekodierung, HTML-Anker, Anhangsnamen). Für MSG wird zusätzlich
``iter_email_attachments`` mit ``kind="msg"`` gefahren — der OLE-Pfad, den
die Pipeline als Kind-Analyse nutzt.
"""

from _support import context, drain, load, run

(EmlPipeline,) = load("malaz.pipelines.eml_pipeline", "EmlPipeline")
(parse_mail,) = load("malaz.core.eml_analysis", "parse_mail")
(iter_email_attachments,) = load("malaz.core.email_extract", "iter_email_attachments")

TARGET = "eml"

_PIPELINE = EmlPipeline()
_DRAIN = 16


def fuzz_one(data: bytes) -> None:
    parse_mail(data)
    _PIPELINE.analyze(context(data, "<fuzz-input>.eml", "eml"))
    drain(iter_email_attachments(data, "eml"), _DRAIN)
    drain(iter_email_attachments(data, "msg"), _DRAIN)


if __name__ == "__main__":
    run(fuzz_one)
