# Python SIEM Firewall

A Python-based firewall and log dashboard with real-time packet filtering, logging, and analytics. This project uses Scapy for packet sniffing, iptables for blocking, SQLite for log storage, and Flask for a web dashboard.

## Features

- **Real-time packet capture** using Scapy
- **Selectable Scan Modes**: Choose to monitor traffic just for your PC or for your entire network (requires network hardware support).
- **Firewall rules** from `rules.json` (block IPs, ports, protocols)
- **Automatic blocking** via iptables
- **Logging** of all packet actions to SQLite (`logs.db`)
- **Web dashboard** (Flask) with:
  - Search and filter logs
  - Protocol, action, and top source IP charts (Chart.js)
  - Data table with sorting and pagination (DataTables)
  - Light/dark theme toggle

## Getting Started

### Prerequisites

- Python 3.7+
- `pip install -r requirements.txt`
- Linux (iptables required for blocking)
- For "Router" mode: A managed switch with port mirroring capabilities.

### Setup

1. Clone the repository.
2. Install dependencies:
    ```
    pip install -r requirements.txt
    ```
3. **Configure Network (for Router Mode)**: If you want to monitor all router traffic, configure port mirroring on your switch to send all traffic to the network interface of the machine running this script.
4. **Update Interface (for Router Mode)**: In `app.py`, change the `interface = 'eth1'` variable to the name of the network interface that is receiving the mirrored traffic.
5. Run the dashboard (requires root for packet sniffing and iptables):
    ```
    sudo python app.py
    ```
6. Visit [http://localhost:5000](http://localhost:5000) in your browser.

### File Structure

- `app.py` - Flask dashboard and packet sniffer control
- `analyzer.py` - Packet analysis and firewall logic
- `detector.py` - Suspicious activity detection
- `log_writer.py` - SQLite logging functions
- `rules.json` - Firewall rules and detection thresholds
- `logs.db` - Log database
- `templates/index.html` - Dashboard UI
- `static/style.css` - Custom styles
- `requirements.txt` - Python dependencies

## Customizing Rules

Edit `rules.json` to block specific IPs, ports, or protocols, and to set thresholds for suspicious activity detection.

```json
{
  "detection": {
    "frequent_ip_threshold": 5,
    "rare_protocol_percent": 10,
    "repeated_block_threshold": 5
  },
  "blocked_ips": ["1.2.3.4"],
  "blocked_ports": [23, 4444],
  "blocked_protocols": ["ICMP"]
}
