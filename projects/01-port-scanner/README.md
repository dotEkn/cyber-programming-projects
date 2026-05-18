# 01-Port-Scanner

A simple TCP Port scanner built with Python.

## Features

- Scan a single host
- Scan one port or a range of ports
- Use threads for faster scanning
- Configurable timeout

## Usage

I used the ``scanme.nmap.org``, which is meant to be scanned for educational use.

**Scan a port range**
```bash
python src/scanner.py <ipadress> -p 1-1024
```
**Scan a single port**
```bash
python src/scanner.py <ipadress> -p 80
```
## Example Output

```bash
Scanning 127.0.0.1 on ports 1-1024...
[OPEN] Port 22
[OPEN] Port 80

Scan Complete.
Open ports found: 2
```

## What I Learned

- Basic TCP Socket programming
- How port scanning works
- Using argparse for CLI tools
- Using threads with ThreadPoolExecutor

## Disclaimer
 *This project is intended for educational and authorized testing purposes only. Do not scan systems you do not own or have permissions to test.*
