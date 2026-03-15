import secrets
from .character_sets import get_character_set, UPPERCASE, LOWERCASE, DIGITS, SYMBOLS

def generate_password(length=16, use_upper=True, use_lower=True, use_digits=True, use_symbols=True, exclude_ambiguous=False):
    """
    Generates a cryptographically secure random password.
    Ensures at least one character from each selected set is included.
    """
    if length < 1:
        raise ValueError("Password length must be at least 1")

    # Determine which pools to use
    pools = []
    if use_upper: pools.append(UPPERCASE)
    if use_lower: pools.append(LOWERCASE)
    if use_digits: pools.append(DIGITS)
    if use_symbols: pools.append(SYMBOLS)

    if not pools:
        raise ValueError("At least one character set must be selected")

    # Full set for random selection
    full_charset = get_character_set(use_upper, use_lower, use_digits, use_symbols, exclude_ambiguous)
    
    if not full_charset:
        raise ValueError("Character set is empty after exclusions")

    # Start with one random char from each selected pool to guarantee inclusion
    password = []
    for pool in pools:
        # Filter pool if exclude_ambiguous is on
        actual_pool = pool
        if exclude_ambiguous:
            from .character_sets import AMBIGUOUS_CHARACTERS
            for char in AMBIGUOUS_CHARACTERS:
                actual_pool = actual_pool.replace(char, "")
        
        if actual_pool:
            password.append(secrets.choice(actual_pool))

    # Fill the rest of the length
    while len(password) < length:
        password.append(secrets.choice(full_charset))

    # Shuffle to avoid predictable pattern (e.g. first char always upper)
    secrets.SystemRandom().shuffle(password)
    
    return "".join(password)

def generate_multiple(count=1, **kwargs):
    return [generate_password(**kwargs) for _ in range(count)]
