"""
My Honeypot configuration: You can modify this to have it configure to your liking. 
"""

# Ports the honeypot will listen on
# Format: {port: "protocol_name"}
HONEYPOT_PORTS = {
    22: "SSH",
    80: "HTTP",
    21: "FTP",
    8080: "HTTP-ALT",
    3306: "MySQL",
    3389: "RDP",
    4444: "CUSTOM",
}

# IP to bind to (0.0.0.0 = all interfaces). But you can configure it only binds to one interface
BIND_IP = "0.0.0.0"

# Dashboard web server port. You can change this to whatever port you want
DASHBOARD_PORT = 5000

# Max payload bytes to capture per connection
MAX_PAYLOAD_BYTES = 4096

# Connection backlog for my socket listener. You can adjust this according to you liking and your need
BACKLOG = 10

# Flask debug mode
DEBUG = False

# Geolocation: set to False if you want to run without internet / API
ENABLE_GEOIP = True

# Geolocation provider: "ipinfo" or "freegeoip"
GEOIP_PROVIDER = "ipinfo"

# SQLite database file path
DB_PATH = "honeypot.db"

# Port scan detection: alert if N connections from same IP within WINDOW seconds. Please note that this is only for scanning detection. 
# every connection to the honeypot will still be displayed on the dashboard. 
# you can adjust this to your liking
PORTSCAN_THRESHOLD = 5
PORTSCAN_WINDOW = 10  # seconds