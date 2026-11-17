import os

from malaz.core.entropy import entropy_indicator_weight, shannon_entropy


def test_empty_has_zero_entropy():
    assert shannon_entropy(b"") == 0.0


def test_constant_bytes_have_zero_entropy():
    assert shannon_entropy(b"\x00" * 4096) == 0.0


def test_random_bytes_have_high_entropy():
    assert shannon_entropy(os.urandom(100_000)) > 7.9


def test_low_entropy_text():
    assert shannon_entropy(b"aaaaaaaaaab") < 1.0


def test_weight_zero_below_threshold():
    assert entropy_indicator_weight(7.0) == 0


def test_weight_max_above_very_high():
    assert entropy_indicator_weight(7.95) == 30


def test_weight_ramps_between_thresholds():
    w = entropy_indicator_weight(7.7)
    assert 5 <= w <= 30


def test_entropy_indicator_weight_thresholds():
    from malaz.core.entropy import entropy_indicator_weight

    assert entropy_indicator_weight(0.0) == 0
    assert entropy_indicator_weight(7.0) == 0   # unter ENTROPY_HIGH: kein Befund
    assert entropy_indicator_weight(7.5) == 5   # exakt HIGH -> Rampenstart
    assert entropy_indicator_weight(7.7) > 5    # Rampe steigt
    assert entropy_indicator_weight(7.9) == 30  # exakt VERY_HIGH
    assert entropy_indicator_weight(8.0) == 30
