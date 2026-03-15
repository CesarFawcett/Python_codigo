from generator.core import generate_password
from generator.entropy import calculate_entropy, get_strength_label
from generator.character_sets import get_character_set
from utils.validators import validate_length
from utils.clipboard import copy_to_clipboard

def run_interactive():
    print("\n🎮 MODO INTERACTIVO")
    print("====================\n")
    
    try:
        length_str = input("Longitud de la contraseña (default 16): ").strip()
        length = int(length_str) if length_str else 16
    except ValueError:
        print("❌ Error: Longitud inválida, usando 16.")
        length = 16
        
    v_len, msg_len = validate_length(length)
    if not v_len:
        print(f"❌ Error: {msg_len}")
        return

    use_upper = input("¿Incluir mayúsculas? (S/n): ").lower() != 'n'
    use_lower = input("¿Incluir minúsculas? (S/n): ").lower() != 'n'
    use_nums = input("¿Incluir números? (S/n): ").lower() != 'n'
    use_syms = input("¿Incluir símbolos? (S/n): ").lower() != 'n'
    no_amb = input("¿Excluir caracteres ambiguos? (s/N): ").lower() == 's'

    try:
        pwd = generate_password(
            length=length,
            use_upper=use_upper,
            use_lower=use_lower,
            use_digits=use_nums,
            use_symbols=use_syms,
            exclude_ambiguous=no_amb
        )
        
        charset = get_character_set(use_upper, use_lower, use_nums, use_syms, no_amb)
        ent = calculate_entropy(pwd, len(charset))
        strength = get_strength_label(ent)
        
        print("\n✨ Contraseña generada:")
        print(f"👉 {pwd}")
        print(f"📊 Fuerza: {strength} ({ent} bits de entropía)")
        
        copy = input("\n¿Copiar al portapapeles? (S/n): ").lower() != 'n'
        if copy:
            success, msg = copy_to_clipboard(pwd)
            print(f"{'✅' if success else '⚠️'} {msg}")
            
    except Exception as e:
        print(f"❌ Error al generar: {e}")
