from generator.core import generate_password
from generator.character_sets import UPPERCASE, LOWERCASE, DIGITS, SYMBOLS

def test_password_length():
    pwd = generate_password(length=20)
    assert len(pwd) == 20

def test_character_inclusion():
    # Test that it includes characters from all categories when requested
    pwd = generate_password(length=100, use_upper=True, use_lower=True, use_digits=True, use_symbols=True)
    assert any(c in UPPERCASE for c in pwd)
    assert any(c in LOWERCASE for c in pwd)
    assert any(c in DIGITS for c in pwd)
    assert any(c in SYMBOLS for c in pwd)

def test_exclude_ambiguous():
    from generator.character_sets import AMBIGUOUS_CHARACTERS
    for _ in range(10):
        pwd = generate_password(length=50, exclude_ambiguous=True)
        for char in AMBIGUOUS_CHARACTERS:
            assert char not in pwd
