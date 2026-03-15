import argparse

def get_args():
    parser = argparse.ArgumentParser(description="Secure Password Generator CLI")
    
    parser.add_argument("-l", "--length", type=int, default=16, help="Length of the password (8-128)")
    parser.add_argument("-c", "--count", type=int, default=1, help="Number of passwords to generate (1-100)")
    
    parser.add_argument("-u", "--upper", action="store_true", default=None, help="Include uppercase letters")
    parser.add_argument("-m", "--lower", action="store_true", default=None, help="Include lowercase letters")
    parser.add_argument("-n", "--numbers", action="store_true", default=None, help="Include numbers")
    parser.add_argument("-s", "--symbols", action="store_true", default=None, help="Include symbols")
    
    parser.add_argument("--no-ambiguous", action="store_true", help="Exclude ambiguous characters (l, 1, I, o, 0, O)")
    parser.add_argument("-i", "--interactive", action="store_true", help="Run in interactive mode")
    parser.add_argument("--no-copy", action="store_true", help="Do not copy the first password to clipboard")
    
    args = parser.parse_args()
    
    # Default to all True if none of the charset flags are specifically provided
    if args.upper is None and args.lower is None and args.numbers is None and args.symbols is None:
        args.upper = args.lower = args.numbers = args.symbols = True
    else:
        # If any are provided, the others default to False
        args.upper = args.upper or False
        args.lower = args.lower or False
        args.numbers = args.numbers or False
        args.symbols = args.symbols or False
        
    return args
