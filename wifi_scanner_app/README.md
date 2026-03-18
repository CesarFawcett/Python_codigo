# Wi-Fi Network Scanner

A premium CLI tool to identify and visualize devices connected to your local Wi-Fi network using ARP scanning.

## Key Features
- **ARP Scanning**: Fast and reliable device discovery using Scapy.
- **Beautiful UI**: Professional tables and live progress bars powered by Rich.
- **Automatic Detection**: Smart detection of your local network range.
- **Hostname Resolution**: Identifies device names automatically.

## Requirements
- Python 3.8+
- Administrator/Root privileges (required for raw packet injection).

## Installation
1. Clone the repository or navigate to the project folder.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage
Run the scanner with default settings:
```bash
python main.py scan
```

Specify a custom range and interface:
```bash
python main.py scan --range 192.168.1.0/24 --interface "Wi-Fi"
```

---

