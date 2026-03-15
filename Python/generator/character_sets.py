import string

LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"

# Characters that are often confused with each other
AMBIGUOUS_CHARACTERS = "l1Io0O"

def get_character_set(use_upper=True, use_lower=True, use_digits=True, use_symbols=True, exclude_ambiguous=False):
    chars = ""
    if use_upper:
        chars += UPPERCASE
    if use_lower:
        chars += LOWERCASE
    if use_digits:
        chars += DIGITS
    if use_symbols:
        chars += SYMBOLS

    if exclude_ambiguous:
        for char in AMBIGUOUS_CHARACTERS:
            chars = chars.replace(char, "")
    
    return chars
