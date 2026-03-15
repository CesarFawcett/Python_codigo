import math

def calculate_entropy(password, charset_size):
    """
    Calculates Shannon entropy in bits.
    Formula: E = L * log2(R)
    L = length of password
    R = size of the pool of characters (character set)
    """
    if charset_size <= 0 or not password:
        return 0
    
    length = len(password)
    entropy = length * math.log2(charset_size)
    return round(entropy, 2)

def get_strength_label(entropy):
    if entropy < 28:
        return "Very Weak"
    elif entropy < 36:
        return "Weak"
    elif entropy < 60:
        return "Reasonable"
    elif entropy < 127:
        return "Strong"
    else:
        return "Very Strong"
