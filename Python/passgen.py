from generator.core import generate_multiple
from generator.entropy import calculate_entropy, get_strength_label
from generator.character_sets import get_character_set
from cli.arguments import get_args
from utils.validators import validate_length, validate_count
from utils.clipboard import copy_to_clipboard
import sys

def print_header():
    print("\n🔐 GENERADOR DE CONTRASEÑAS SEGURAS")
    print("====================================\n")

def main():
    args = get_args()
    
    if args.interactive:
        from cli.interactive import run_interactive
        run_interactive()
        return

    # Validate inputs
    v_len, msg_len = validate_length(args.length)
    if not v_len:
        print(f"❌ Error: {msg_len}")
        sys.exit(1)
        
    v_count, msg_count = validate_count(args.count)
    if not v_count:
        print(f"❌ Error: {msg_count}")
        sys.exit(1)

    print_header()
    
    print("Configuración:")
    print(f"- Longitud: {args.length} caracteres")
    print(f"- Mayúsculas: {'✅ Sí' if args.upper else '❌ No'}")
    print(f"- Minúsculas: {'✅ Sí' if args.lower else '❌ No'}")
    print(f"- Números:    {'✅ Sí' if args.numbers else '❌ No'}")
    print(f"- Símbolos:   {'✅ Sí' if args.symbols else '❌ No'}")
    
    # Calculate entropy for the pool
    charset = get_character_set(args.upper, args.lower, args.numbers, args.symbols, args.no_ambiguous)
    charset_size = len(charset)
    
    passwords = generate_multiple(
        count=args.count,
        length=args.length,
        use_upper=args.upper,
        use_lower=args.lower,
        use_digits=args.numbers,
        use_symbols=args.symbols,
        exclude_ambiguous=args.no_ambiguous
    )
    
    # Use first password for entropy display
    ent = calculate_entropy(passwords[0], charset_size)
    strength = get_strength_label(ent)
    
    print(f"- Entropía:   {ent} bits ({strength})")
    print("\nContraseñas generadas:")
    print("──────────────────────")
    for i, pwd in enumerate(passwords, 1):
        print(f"{i}.  {pwd}")
    print("──────────────────────")

    if not args.no_copy and passwords:
        success, msg = copy_to_clipboard(passwords[0])
        if success:
            print(f"\n✅ Contraseña 1 copiada al portapapeles")
        else:
            print(f"\n⚠️ {msg}")

if __name__ == "__main__":
    main()
