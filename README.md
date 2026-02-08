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
zig build -Doptimize=ReleaseFast
```

## Run

```bash
./zig-out/bin/zigmap --ip 192.168.1.0/24
```

Nmap-style target alias is also supported:

```bash
./zig-out/bin/zigmap -ip 192.168.1.0/24
```

Positional CIDR still works:

```bash
./zig-out/bin/zigmap 192.168.1.0/24
```

Optional: install into your PATH prefix:

```bash
zig build -Doptimize=ReleaseFast --prefix ~/.local
~/.local/bin/zigmap --ip 192.168.1.0/24
```

## Useful flags

- `--ip`, `--cidr`, `-i`, `-ip`
- `--ports` / `-p` (example: `-p 1-1024` or `-p all`)
- `--workers` / `-w`
- `--timeout-ms` / `-t`
- `--max-hosts` / `-m`
- `--discovery-ports` / `-d`
- `--color` / `-c` and `--no-color` / `-C`

Example:

```bash
./zig-out/bin/zigmap -ip 10.0.0.0/24 -p 1-1024 -w 256 -t 120
```

## Notes and limits

- This uses TCP connect scanning (no raw SYN scan).
- Host discovery can miss hosts behind strict firewalls.
- OS detection is heuristic, not full TCP/IP fingerprinting.
- `zig build run -- ...` still works for development workflows.
- Scan only networks you own or are explicitly authorized to test.
