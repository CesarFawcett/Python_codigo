def validate_length(length):
    if not (8 <= length <= 128):
        return False, "Length must be between 8 and 128 characters."
    return True, ""

def validate_count(count):
    if count < 1 or count > 100:
        return False, "Count must be between 1 and 100."
    return True, ""
