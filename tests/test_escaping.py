from malaz.security.escaping import escape_html, safe_excerpt


def test_escape_script_tag():
    assert escape_html("<script>alert(1)</script>") == "&lt;script&gt;alert(1)&lt;/script&gt;"


def test_escape_attribute_quotes():
    out = escape_html('" onmouseover="x')
    assert '"' not in out
    assert "&quot;" in out


def test_escape_none():
    assert escape_html(None) == ""


def test_escape_non_string():
    assert escape_html(123) == "123"


def test_excerpt_neutralises_markup():
    out = safe_excerpt(b"<script>alert(1)</script>")
    assert "<script>" not in out
    assert "&lt;script&gt;" in out


def test_excerpt_strips_control_chars():
    out = safe_excerpt(b"abc\x00\x01def")
    assert "\x00" not in out


def test_excerpt_truncates():
    out = safe_excerpt("x" * 10000, max_len=100)
    assert "gekürzt" in out


# -- Unsichtbare/bidi-Steuerzeichen ------------------------------------------ #

def test_mask_invisible_masks_bidi_controls():
    """A bidi override must not survive into any displayed text.

    Measured by screenshot with a NON-PALINDROMIC name: Qt applies the bidi
    algorithm to plain text, so ``Rechnung\\u202efdp.exe`` is displayed as
    ``Rechnungexe.pdf`` — an executable reading as a PDF. Browsers and
    ``QPainter`` (the PDF report) behave the same way. (A first probe used
    ``.exe``, a palindrome, which looks identical either way and could not
    decide the question.)
    """
    from malaz.security.escaping import mask_invisible

    stored = "Rechnung\u202efdp.exe"
    out = mask_invisible(stored)
    assert out == "Rechnung\\u202efdp.exe"
    assert "\u202e" not in out
    # Nicht entfernt: die Tarnung soll sichtbar bleiben, nicht verschwinden.
    assert "fdp" in out and "exe" in out


def test_mask_invisible_covers_all_control_codepoints():
    """Every bidi override/isolate and NUL is masked."""
    from malaz.security.escaping import mask_invisible

    for code in list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A)) + [0]:
        out = mask_invisible(f"a{chr(code)}b")
        assert f"\\u{code:04x}" in out, hex(code)
        assert chr(code) not in out, hex(code)


def test_mask_invisible_leaves_rtl_text_alone():
    """Genuine RTL letters are ordinary text — masking them would garble it.

    A Hebrew or Arabic subject line is not a deception; only the invisible
    control characters are.
    """
    from malaz.security.escaping import mask_invisible

    for legitimate in ("שלום עולם", "مرحبا بالعالم", "Rechnung שלום.pdf"):
        assert mask_invisible(legitimate) == legitimate


def test_mask_invisible_leaves_plain_text_alone():
    """Ordinary strings are returned unchanged (including None and ints)."""
    from malaz.security.escaping import mask_invisible

    assert mask_invisible("Rechnung 2026-0042.pdf") == "Rechnung 2026-0042.pdf"
    assert mask_invisible(None) == ""
    assert mask_invisible(123) == "123"


def test_escape_html_masks_bidi_too():
    """The HTML report path must mask as well — escaping alone does not help.

    HTML-escaping a bidi override leaves the character intact, so the browser
    would still re-order the text around it. This is why masking happens INSIDE
    escape_html rather than at each call site.
    """
    from malaz.security.escaping import escape_html

    out = escape_html("Rechnung\u202efdp.exe")
    assert "\u202e" not in out
    assert "\\u202e" in out
    assert "&lt;" in escape_html("<script>")  # Escaping bleibt erhalten
