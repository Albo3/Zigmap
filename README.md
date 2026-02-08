# zigmap

`zigmap` is a slim, fast, Zig-based local network scanner inspired by Nmap.

## What it does

- Expands a user-provided IPv4 CIDR (example: `192.168.1.0/24`)
- Performs concurrent host discovery using TCP connect probes
- Scans TCP ports (default: all `1-65535`) on live hosts
- Uses combined port-map + banner signatures for stronger service detection
- Adds HTTP/TLS service metadata enrichment (status/server/title/TLS-record hints)
- Adds ARP/MAC OUI vendor lookup for stronger local LAN device confidence
- Bundles `data/nmap-mac-prefixes` for local OUI vendor resolution
- Adds device-type inference (printer/NAS/appliance/server/IoT) with confidence
- Provides weighted OS guesses with confidence and evidence reasoning
- Renders structured host reports with profile tags, confidence labels, and summaries

## Requirements

- Zig `0.15.2`

## Build

```bash
ZIG_GLOBAL_CACHE_DIR=/tmp/zig-cache ZIG_LOCAL_CACHE_DIR=.zig-cache zig build
```

## Run

```bash
ZIG_GLOBAL_CACHE_DIR=/tmp/zig-cache ZIG_LOCAL_CACHE_DIR=.zig-cache \
  zig build run -- --cidr 192.168.1.0/24
```

Positional CIDR is also supported:

```bash
ZIG_GLOBAL_CACHE_DIR=/tmp/zig-cache ZIG_LOCAL_CACHE_DIR=.zig-cache \
  zig build run -- 192.168.1.0/24
```

## Useful options

- `--ports 1-1024` or `--ports all`
- `--workers 256`
- `--timeout-ms 150`
- `--max-hosts 4096`
- `--discovery-ports 22,80,443,445`
- `--color` / `--no-color`

Example:

```bash
ZIG_GLOBAL_CACHE_DIR=/tmp/zig-cache ZIG_LOCAL_CACHE_DIR=.zig-cache \
  zig build run -- 10.0.0.0/24 --ports 1-1024 --workers 256 --timeout-ms 120
```

## Notes and limits

- This uses TCP connect scanning (no raw SYN scan).
- Host discovery can miss hosts behind strict firewalls.
- OS detection is heuristic, not full TCP/IP fingerprinting.
- Scan only networks you own or are explicitly authorized to test.
