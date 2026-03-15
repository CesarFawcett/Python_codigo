# Professional Port Scanner

A powerful and educational port scanning tool implemented in Python.

## Features
- **TCP CONNECT Scan**: Reliable handshake-based scanning.
- **SYN Stealth Scan**: Half-open scanning (requires Admin/Root).
- **UDP Scanning**: Identify open/filtered UDP services.
- **Service Detection**: Banner grabbing to identify running services.
- **Reporting**: Export results to JSON, CSV, or HTML.
- **Concurrent**: Multi-threaded for high performance.

## Installation
1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd PortScanner
   ```
2. (Optional) Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage
### Basic Scan
```bash
python scanner.py -t 192.168.1.1
```

### Scan Specific Range
```bash
python scanner.py -t 192.168.1.1 -p 1-1024
```

### SYN Stealth Scan (Requires Admin)
```bash
# Windows
python scanner.py -t 192.168.1.1 -sS
```

### Exporting Results
```bash
python scanner.py -t 192.168.1.1 -o html -f report.html
```

## Architecture
- `core/`: Scanning mechanics and logic.
- `utils/`: Networking, validation, and progress utilities.
- `reports/`: Export formatting logic.
- `cli/`: User interface and argument parsing.

## Ethical Disclaimer
This tool is for educational and authorized security auditing purposes only. Unauthorized scanning of networks is illegal and unethical.
