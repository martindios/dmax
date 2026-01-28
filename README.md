# dmax

A network discovery tool that combines ARP scanning with ICMP probing, hostname resolution, and MAC vendor lookup.

## Features

- **ARP Discovery**
- **ICMP Probing**: estimated OS based on TTL values
- **Hostname Resolution**: reverse DNS lookup for discovered hosts
- **MAC Vendor Lookup**: identify device manufacturers
- **Multiple Output Formats**: table, JSON, or CSV
- **Concurrent Scanning**: fast parallel probing with configurable workers

## Requirements

- Python 3
- Root/Administrator privileges (required for raw packet operations)
- Linux/Unix/macOS (I don't try it in Windows)

## Installation

```bash
# Clone the repository
git clone https://github.com/martindios/dmax
cd dmax

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # With fish: source .venv/bin/activate.fish

# Install dependencies
pip install -r requirements.txt
```

## Usage

Basic scan:
```bash
sudo .venv/bin/python3 dmax.py -i wlp0s29f7 -s 192.168.1.0/24
```

Fast ARP-only scan (skip ICMP and hostname resolution):
```bash
sudo .venv/bin/python3 dmax.py -i wlp0s29f7 -s 192.168.1.0/24 --no-icmp --no-resolve-hostnames
```

Export results to JSON:
```bash
sudo .venv/bin/python3 dmax.py -i wlp0s29f7 -s 192.168.1.0/24 --output json --out-file results.json
```

Verbose output with retries:
```bash
sudo .venv/bin/python3 dmax.py -i wlp0s29f7 -s 192.168.1.0/24 -v -r 2
```

## Options

| Flag | Description |
|------|-------------|
| `-i, --interface` | Network interface (required) |
| `-s, --subnet` | Target subnet in CIDR notation (required) |
| `--no-icmp` | Skip ICMP probing for faster scans |
| `--no-resolve-hostnames` | Skip reverse DNS lookups |
| `--no-vendor` | Skip MAC vendor lookups |
| `-t, --timeout` | Timeout for network operations (default: 2s) |
| `-w, --workers` | Number of parallel workers (default: 16) |
| `-r, --retry` | ICMP retry attempts (default: 1) |
| `--output` | Output format: table, json, csv (default: table) |
| `--out-file` | Write output to file instead of stdout |
| `-v, --verbose` | Increase verbosity (-v for INFO, -vv for DEBUG) |


## License

I share this project under the MIT license. You can have more information about this license on the LICENSE section of the repository.
