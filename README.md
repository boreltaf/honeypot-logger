# Honeypot Logger

A low-interaction honeypot with a live web dashboard that logs connection attempts
on configurable ports. Designed for security analytics education — demonstrates
attacker reconnaissance detection, threat intelligence gathering, and real-time
log visualization.

## Features

- **Multi-port TCP honeypot** — listens on SSH (22), HTTP (80), FTP (21), and more
- **Payload capture** — records the first ~4KB of each connection to see attacker intent
- **IP geolocation** — resolves source IPs to country/city (ipinfo.io or freegeoip)
- **Port scan detection** — alerts when one IP connects to multiple ports rapidly
- **Live web dashboard** — auto-updating stats, charts, and event table
- **SQLite backend** — zero configuration, all events persisted to disk
- **JSON API** — all data accessible via REST endpoints for external tooling

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Start the honeypot
python honeypot.py