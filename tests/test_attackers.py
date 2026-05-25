#!/usr/bin/env python3
"""
Test script to simulate attacker activity against the honeypot.
Run this from a separate terminal while honeypot.py is running.

Usage:
    python tests/test_attackers.py --target 127.0.0.1
    python tests/test_attackers.py --target 127.0.0.1 --ports 22,80,443 --count 20
"""

import socket
import time
import random
import argparse
import string


# Payloads that simulate real attacker behavior
HTTP_GET_PAYLOADS = [
    b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
    b"GET /wp-admin HTTP/1.1\r\nHost: localhost\r\n\r\n",
    b"GET /../../etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n",
    b"GET /?id=1 UNION SELECT * FROM users HTTP/1.1\r\nHost: localhost\r\n\r\n",
    b"GET /.env HTTP/1.1\r\nHost: localhost\r\n\r\n",
    b"GET /admin.php HTTP/1.1\r\nHost: localhost\r\n\r\n",
]

SSH_BANNERS = [
    b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3",
    b"SSH-2.0-OpenSSH_7.6p1 Ubuntu-4",
    b"SSH-2.0-dropbear_2022.82",
]

FTP_PAYLOADS = [
    b"USER admin\r\n",
    b"USER root\r\n",
    b"USER ftp\r\n",
    b"USER anonymous\r\n",
]

GENERIC_PAYLOADS = [
    b"\x00" * 100,  # Null scan
    b"GET / HTTP/1.0\r\n\r\n",
    b"HEAD / HTTP/1.0\r\n\r\n",
    b"dumb",
]


def get_payload_for_port(port):
    """Return a realistic payload based on the destination port."""
    if port == 80 or port == 8080:
        return random.choice(HTTP_GET_PAYLOADS)
    elif port == 22:
        return random.choice(SSH_BANNERS)
    elif port == 21:
        return random.choice(FTP_PAYLOADS)
    else:
        return random.choice(GENERIC_PAYLOADS)


def simulate_connection(target, port, delay=0):
    """Open a TCP connection to the honeypot and optionally send a payload."""
    if delay > 0:
        time.sleep(delay)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        sock.connect((target, port))

        payload = get_payload_for_port(port)
        sock.send(payload)

        # Wait briefly for any response (honeypot won't respond, but still)
        try:
            sock.recv(1024)
        except socket.timeout:
            pass

        sock.close()
        print(f"  [*] Sent to {target}:{port} -> {payload[:40].decode('utf-8', errors='replace')}...")
        return True
    except (ConnectionRefusedError, socket.timeout, OSError) as e:
        print(f"  [-] Failed {target}:{port} - {e}")
        return False


def simulate_port_scan(target, ports, delay=0.01):
    """Simulate a port scan by rapidly connecting to multiple ports."""
    print(f"\n  [!] Simulating port scan against {target}...")
    for port in ports:
        simulate_connection(target, port, delay=delay)


def simulate_brute_force(target, port, usernames, delay=0.5):
    """Simulate a brute-force login attempt."""
    print(f"\n  [!] Simulating brute-force on {target}:{port}...")
    for user in usernames:
        payload = f"USER {user}\r\n".encode()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            sock.connect((target, port))
            sock.send(payload)
            sock.close()
            print(f"  [*] Brute-force: {user}@{target}:{port}")
            time.sleep(delay)
        except (ConnectionRefusedError, socket.timeout, OSError) as e:
            print(f"  [-] Failed {target}:{port} - {e}")
            break


def main():
    parser = argparse.ArgumentParser(
        description="Test attacker simulator for honeypot-logger"
    )
    parser.add_argument(
        "--target", default="127.0.0.1",
        help="Honeypot target IP (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--ports", default="22,80,21,8080,3306,3389,4444",
        help="Comma-separated ports to test (default: 22,80,21,8080,3306,3389,4444)"
    )
    parser.add_argument(
        "--count", type=int, default=10,
        help="Number of random connections to make (default: 10)"
    )
    parser.add_argument(
        "--scan", action="store_true",
        help="Simulate a port scan (rapid sequential connections)"
    )
    parser.add_argument(
        "--brute", action="store_true",
        help="Simulate SSH/FTP brute-force"
    )
    args = parser.parse_args()

    ports = [int(p.strip()) for p in args.ports.split(",")]

    print("=" * 60)
    print("  Honeypot Attack Simulator")
    print("  Target:", args.target)
    print("  Ports:", ports)
    print("=" * 60)

    # 1. Random connections with realistic payloads
    print(f"\n[+] Sending {args.count} random connections...")
    for i in range(args.count):
        port = random.choice(ports)
        simulate_connection(args.target, port, delay=random.uniform(0.1, 0.5))

    # 2. Optional port scan simulation
    if args.scan:
        simulate_port_scan(args.target, ports, delay=0.01)

    # 3. Optional brute-force simulation
    if args.brute:
        usernames = ["admin", "root", "test", "user", "guest", "oracle"]
        simulate_brute_force(args.target, random.choice(ports), usernames)

    print("\n[+] Done. Check the honeypot dashboard at http://localhost:5000")


if __name__ == "__main__":
    main()