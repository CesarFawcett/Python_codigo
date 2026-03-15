from generator.entropy import calculate_entropy

def test_entropy_calculation():
    # Pool size 2 (binary) length 8 -> 8 bits
    assert calculate_entropy("01010101", 2) == 8.0
    # Pool size 10 length 4 -> 4 * log2(10) approx 13.29
    assert 13.28 < calculate_entropy("1234", 10) < 13.30

def test_zero_entropy():
    assert calculate_entropy("", 10) == 0
    assert calculate_entropy("abc", 0) == 0
