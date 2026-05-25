"""
Individual honeypot port listener threads.
Each listener runs in its own thread, accepts connections, captures payload,
and logs the event.
"""

import socket
import threading
from config import BIND_IP, MAX_PAYLOAD_BYTES, BACKLOG


class HoneypotListener(threading.Thread):
    """
    A threaded TCP listener that accepts connections on a single port,
    grabs the initial payload, and passes the data to the logger callback.
    """

    def __init__(self, port, protocol, log_callback, geo_callback,
                 portscan_callback=None):
        super().__init__()
        self.port = port
        self.protocol = protocol
        self.log_callback = log_callback
        self.geo_callback = geo_callback
        self.portscan_callback = portscan_callback
        self.daemon = True
        self._stop_event = threading.Event()

    def stop(self):
        """Signal the listener to stop."""
        self._stop_event.set()

    def run(self):
        """Main listener loop."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Set a timeout so we can check stop_event periodically
        server_sock.settimeout(1.0)

        try:
            server_sock.bind((BIND_IP, self.port))
            server_sock.listen(BACKLOG)
            print(f"[+] Listener started on port {self.port} ({self.protocol})")
        except OSError as e:
            print(f"[-] Failed to bind port {self.port}: {e}")
            return

        while not self._stop_event.is_set():
            try:
                client_sock, (remote_ip, remote_port) = server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            # Handle connection in a new thread
            handler = threading.Thread(
                target=self._handle_connection,
                args=(client_sock, remote_ip, remote_port),
                daemon=True
            )
            handler.start()

        server_sock.close()
        print(f"[-] Listener stopped on port {self.port} ({self.protocol})")

    def _handle_connection(self, client_sock, remote_ip, remote_port):
        """Handle a single incoming connection."""
        payload = ""
        try:
            client_sock.settimeout(5.0)
            # Read up to MAX_PAYLOAD_BYTES
            raw = client_sock.recv(MAX_PAYLOAD_BYTES)
            if raw:
                # Decode safely, replace unprintable chars
                payload = raw.decode("utf-8", errors="replace")
                # Truncate at max length
                if len(payload) > MAX_PAYLOAD_BYTES:
                    payload = payload[:MAX_PAYLOAD_BYTES]
        except (socket.timeout, ConnectionResetError,
                OSError, UnicodeDecodeError):
            pass
        finally:
            try:
                client_sock.close()
            except OSError:
                pass

        # Geolocation lookup
        geo = self.geo_callback(remote_ip)

        # Log the event
        self.log_callback(
            source_ip=remote_ip,
            source_port=remote_port,
            dest_port=self.port,
            protocol=self.protocol,
            payload=payload,
            country=geo["country"],
            city=geo["city"],
            org=geo["org"],
        )

        # Port scan detection callback
        if self.portscan_callback:
            self.portscan_callback(remote_ip, self.port)

        # Print to console as well (useful for seeing activity in real-time)
        print(f"  [+] Connection: {remote_ip}:{remote_port} -> "
              f"port {self.port} ({self.protocol}) "
              f"[{geo['country']}/{geo['city']}]")