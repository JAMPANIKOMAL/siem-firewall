# Python SIEM Firewall

A Python-based firewall and log dashboard with real-time packet filtering, logging, and analytics. This project uses Scapy for packet sniffing, iptables for blocking, SQLite for log storage, and Flask for a web dashboard.

## Features

- **Real-time packet capture** using Scapy
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
- `pip install flask scapy`
- Linux (iptables required for blocking)

### Setup

1. Clone the repository.
2. Install dependencies:
    ```
    pip install flask scapy
    ```
3. Run the firewall (requires root for packet sniffing and iptables):
    ```
    sudo python firewall.py
    ```
4. Start the dashboard:
    ```
    python app.py
    ```
5. Visit [http://localhost:5000](http://localhost:5000) in your browser.

### File Structure

- `firewall.py` - Main firewall logic
- `app.py` - Flask dashboard
- `log_writer.py` - SQLite logging functions
- `rules.json` - Firewall rules
- `logs.db` - Log database
- `templates/index.html` - Dashboard UI
- `static/style.css` - Custom styles

## Customizing Rules

Edit `rules.json` to block specific IPs, ports, or protocols.

```json
{
  "blocked_ips": ["1.2.3.4"],
  "blocked_ports": [23, 4444],
  "blocked_protocols": ["ICMP"]
}