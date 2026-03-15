# Secure Password Generator CLI

A robust Python CLI tool for generating high-entropy, customizable passwords.

## Features
- Cryptographically secure generation (using `secrets` module)
- Customizable length and character sets
- Entropy calculation
- CLI and Interactive modes
- Clipboard integration

## Installation
```bash
pip install -r requirements.txt
```

## Usage
```bash
python passgen.py -l 16 -s
```
```bash
python passgen.py -c 3 -l 20 -u -m -n -s
```