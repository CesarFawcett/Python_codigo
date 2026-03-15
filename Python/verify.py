from generator.core import generate_password
from generator.entropy import calculate_entropy
from generator.character_sets import get_character_set

try:
    pwd = generate_password(length=16)
    charset = get_character_set()
    ent = calculate_entropy(pwd, len(charset))
    
    with open('verification_output.txt', 'w', encoding='utf-8') as f:
        f.write(f"Generated Password: {pwd}\n")
        f.write(f"Entropy: {ent} bits\n")
        f.write("Verification Success!\n")
except Exception as e:
    with open('verification_output.txt', 'w', encoding='utf-8') as f:
        f.write(f"Verification Failed: {str(e)}\n")
