try:
    import pyperclip
    HAS_PYPERCLIP = True
except ImportError:
    HAS_PYPERCLIP = False

def copy_to_clipboard(text):
    if HAS_PYPERCLIP:
        try:
            pyperclip.copy(text)
            return True, "Copied to clipboard!"
        except Exception as e:
            return False, f"Failed to copy: {str(e)}"
    return False, "pyperclip not installed. Install it with 'pip install pyperclip'."
