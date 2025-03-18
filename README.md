# GusserNet

## Overview
GusserNet is a powerful and advanced network scanning tool designed for cybersecurity professionals and penetration testers. It provides extensive scanning capabilities, including port scanning, OS detection, service fingerprinting, and Shodan integration. The tool is optimized for performance with multi-threading and stealth scanning techniques.

## Features
- **Port Scanning**: Scan specific ports or a range of ports.
- **UDP Scanning**: Detect open UDP ports.
- **Stealth Scanning**: Perform SYN scans for stealthy network enumeration.
- **OS Detection**: Identify the target's operating system.
- **Service Fingerprinting**: Detect running services and their versions.
- **Banner Grabbing**: Extract banners for further analysis.
- **Shodan Integration**: Retrieve additional intelligence from Shodan.
- **Multi-threading**: Improve scanning speed with concurrent requests.
- **Custom Timeout**: Set timeout duration for responses.
- **Output to File**: Save scan results for later review.

## Installation
```sh
pip install -r requirements.txt
```

## Usage
```sh
python GusserNet.py target [options]
```

### Example Commands
1. **Basic Scan on Target**
   ```sh
   python GusserNet.py scanme.nmap.org -p 1-100 -v
   ```
2. **Stealth Scan with Fingerprinting**
   ```sh
   python GusserNet.py scanme.nmap.org -p 1-100 --stealth --fingerprint --udp -t 300 -v
   ```
3. **OS Detection**
   ```sh
   python GusserNet.py scanme.nmap.org -p 1-100 --os-detect -v
   ```
4. **Shodan Lookup**
   ```sh
   python GusserNet.py scanme.nmap.org --shodan -v
   ```
5. **Output Results to a File**
   ```sh
   python GusserNet.py scanme.nmap.org -p 1-100 -o results.txt
   ```

## Help Menu
```sh
python GusserNet.py --help
```

### Options
```
usage: GusserNet.py [-h] [-p PORTS] [-t THREADS] [-o OUTPUT] [-v] [--timeout TIMEOUT] [--top-ports TOP_PORTS] [--raw] [--udp] [--os-detect] [--stealth] [--banner] [--shodan] [--fingerprint] target

Gusser Net

positional arguments:
  target                Target IP or hostname

options:
  -h, --help            show this help message and exit
  -p, --ports PORTS     Port range (e.g., 1-1000)
  -t, --threads THREADS Number of threads
  -o, --output OUTPUT   Output results to file
  -v, --verbose         Verbose output
  --timeout TIMEOUT     Socket timeout in seconds
  --top-ports TOP_PORTS Scan top N common ports
  --raw                 Use raw socket scanning (root required)
  --udp                 Perform UDP scanning
  --os-detect           Perform advanced OS detection
  --stealth             Stealth SYN scan mode
  --banner              Grab service banners
  --shodan              Integrate Shodan lookup
  --fingerprint         Fingerprint services
```

## Notes
- Ensure you have the necessary permissions to perform network scans.
- Stealth mode and raw socket scanning may require root privileges.
- Use responsibly and in compliance with applicable laws and policies.

