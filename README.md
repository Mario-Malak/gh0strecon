# gh0strecon
gh0strecon is an automated reconnaissance tool that takes a domain name and maps its full attack surface. It discovers subdomains, resolves them to IPs, scans open ports, identifies running services, matches them against Metasploit exploit modules, and outputs everything as structured JSON files plus an interactive visual graph -all in one command.

## Features
1- Subdomain Enumeration — runs subfinder, assetfinder, and amass in sequence, merges and deduplicates all results\
2- Thread-Safe DNS Resolution — resolves every subdomain concurrently using dnspython, no race conditions, supports IPv4 and IPv6\
3- IP Deduplication — scans each IP exactly once regardless of how many subdomains point to it\
4- Port Scanning — nmap with retry logic, rate limiting, and three built-in scan modes\
5- Service Fingerprinting — extracts and normalizes service names and versions from nmap output\
6- Metasploit Intelligence — queries msfconsole for exploit and auxiliary modules matching each discovered service\
7- Structured Output — saves everything as JSON and plain text files\
8- Interactive Graph — self-contained HTML graph of the full attack surface, click any node to inspect it\

## Project Structure
```
gh0strecon/
├── main.py            — pipeline entrypoint
├── config.yaml        — all settings
├── requirements.txt   — Python dependencies
└── core/
    ├── models.py      — data models
    ├── enum.py        — subdomain enumeration
    ├── dns.py         — DNS resolution
    ├── dedupe.py      — deduplication
    ├── scanner.py     — nmap scanning
    ├── scheduler.py   — task scheduler with retry
    ├── parser.py      — service normalization
    ├── msf.py         — Metasploit intelligence
    ├── storage.py     — result persistence
    └── graph.py       — graph generation
```

## Installation
git clone https://github.com/Mario-Malak/gh0strecon.git \
cd gh0strecon\
pip install -r requirements.txt

## Usage
Fast scan — top 100 ports
> python3 main.py example.com

Normal scan — top 1000 ports with version detection
> python3 main.py example.com --mode normal


Full scan — all 65535 ports with scripts
> python3 main.py example.com --mode slow

Skip Metasploit lookups
> python3 main.py example.com --no-msf

Custom config
> python3 main.py example.com --config myconfig.yaml

## Output
All results saved to results/example.com/\
├── subdomains.txt   — all discovered subdomains\
├── dns.json         — resolved IPs per subdomain\
├── ips.json         — unique IP list\
├── ports.json       — open ports with service and version\
├── services.json    — normalized service records\
├── msf.json         — matched Metasploit modules\
└── graph.html       — interactive attack surface graph\


## This tool is intended for authorized penetration testing and security research only. Do not use against systems you do not own or have explicit permission to test.

