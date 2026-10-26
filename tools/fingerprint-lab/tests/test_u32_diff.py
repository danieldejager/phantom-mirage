"""derive._u32_diff follows the published ISN-difference rule (GCD section)."""

from derive import _seq_metrics, _u32_diff


def test_higher_isn_forward_difference_even_over_2_31():
    a, b = 0x10, 0x90000010  # forward diff 0x90000000 > 2**31
    assert _u32_diff(a, b) == 0x90000000
    # the old "always the smaller" form would have returned the wrapped value
    assert min((b - a) & 0xFFFFFFFF, (a - b) & 0xFFFFFFFF) == 0x70000000


def test_lower_isn_takes_smaller_of_subtract_and_wrap():
    assert _u32_diff(0x20000, 0x15000) == 0xB000  # page example 1: subtract
    assert _u32_diff(0xFFFFFF00, 0xC000) == 0xC100  # count up through zero
    assert _u32_diff(0x90000000, 0x10) == 0x70000010  # wrap smaller than subtract


def test_equal_isn_is_zero():
    assert _u32_diff(0x12345678, 0x12345678) == 0


def test_seq_metrics_uses_forward_difference():
    seqs = [0, 0x90000000]
    m = _seq_metrics(seqs[:2], [0.0, 0.1])
    assert m["diffs"] == [0x90000000]
