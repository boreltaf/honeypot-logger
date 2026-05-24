#!/usr/bin/env python3
"""
Honeypot Logger - Main Entry Point
"""

import sys
import threading
import time
from collections import defaultdict
from flask import Flask, render_template, jsonify, request
from config import (
    HONEYPOT_PORTS, DASHBOARD_PORT, DEBUG,
    PORTSCAN_THRESHOLD, PORTSCAN_WINDOW
)
from listener import HoneypotListener
from logger_db import HoneypotLogger
from geo import lookup_ip

# Here we initialize the logger (database)
logger = HoneypotLogger()

# The port scan detection state
_scan_tracker = defaultdict(list)      # ip as keys, ip -> [timestamp, ...].
_scan_lock = threading.Lock()
_scan_alerts = []                       # list of alert dicts

def check_portscan(ip, port):
    """
    Track connections per IP and raise alert if threshold exceeds.
    it is called by each listener after handling a connection.
    """
    now = time.time()
    with _scan_lock:
        _scan_tracker[ip].append(now)
        # Prune entries outside the window
        _scan_tracker[ip] = [
            t for t in _scan_tracker[ip]
            if now - t <= PORTSCAN_WINDOW
        ]
        count = len(_scan_tracker[ip])
        if count >= PORTSCAN_THRESHOLD:
            alert = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "source_ip": ip,
                "connections_in_window": count,
                "window_seconds": PORTSCAN_WINDOW,
                "port": port,
            }
            # Avoid duplicate alerts within the same window (check if last
            # alert for this IP is more than PORTSCAN_WINDOW seconds ago)
            last_alert_time = 0
            for a in _scan_alerts:
                if a["source_ip"] == ip:
                    alert_ts = time.mktime(
                        time.strptime(a["timestamp"].replace("Z", ""),
                                      "%Y-%m-%dT%H:%M:%S")
                    )
                    last_alert_time = max(last_alert_time, alert_ts)
            if time.time() - last_alert_time > PORTSCAN_WINDOW:
                _scan_alerts.insert(0, alert)
                print(f"  [!] PORT SCAN DETECTED: {ip} "
                      f"({count} connections in {PORTSCAN_WINDOW}s)")



# The web dashboard
app = Flask(__name__)


@app.route("/")
def dashboard():
    """Render the main dashboard page."""
    return render_template("dashboard.html")


@app.route("/api/events")
def api_events():
    """Return recent events as JSON."""
    limit = request.args.get("limit", 50, type=int)
    events = logger.get_recent_events(limit)
    return jsonify(events)


@app.route("/api/events/live")
def api_events_live():
    """Return events newer than the given ID (for live polling)."""
    since = request.args.get("since", 0, type=int)
    events = logger.get_events_since(since)
    latest_id = logger.get_latest_event_id()
    return jsonify({"events": events, "latest_id": latest_id})


@app.route("/api/stats")
def api_stats():
    """Return aggregated statistics as JSON."""
    stats = logger.get_stats()
    with _scan_lock:
        stats["portscan_alerts"] = list(_scan_alerts[:20])
    return jsonify(stats)


@app.route("/api/events/clear", methods=["POST"])
def api_clear():
    """Clear all events from the database."""
    logger.clear_events()
    with _scan_lock:
        _scan_alerts.clear()
        _scan_tracker.clear()
    return jsonify({"status": "ok"})


# The Main function
def main():
    print("=" * 60)
    print("  Honeypot Logger - Starting up")
    print("=" * 60)
    print(f"\n  listening on ports: {', '.join(str(p) for p in HONEYPOT_PORTS)}")
    print(f"  Dashboard: http://localhost:{DASHBOARD_PORT}")
    print(f"  you can use Ctrl+C to stop it\n")

    # Start listener threads for each configured port
    listeners = []
    for port, protocol in HONEYPOT_PORTS.items():
        listener = HoneypotListener(
            port=port,
            protocol=protocol,
            log_callback=logger.log_event,
            geo_callback=lookup_ip,
            portscan_callback=check_portscan,
        )
        listener.start()
        listeners.append(listener)

    # Run Flask dashboard in the main thread
    try:
        app.run(
            host="0.0.0.0",
            port=DASHBOARD_PORT,
            debug=DEBUG,
            use_reloader=False,  # Avoid duplicate listeners with reloader
        )
    except KeyboardInterrupt:
        print("\n[!] Shutting down...")
    finally:
        for l in listeners:
            l.stop()
        for l in listeners:
            l.join(timeout=2)
        print("[+] Honeypot stopped. Goodbye.")


if __name__ == "__main__":
    main()