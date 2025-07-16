# firewall.py

import json
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP
import subprocess
from log_writer import log_packet, init_db

# ✅ Initialize database
init_db()

# 🔒 Block an IP with iptables if not already blocked
def block_ip(ip):
    try:
        subprocess.run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"], check=True)
    except subprocess.CalledProcessError:
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        print(f"🔒 Blocked IP: {ip}")

# 📜 Load firewall rules from rules.json
def load_rules():
    with open("rules.json", "r") as f:
        return json.load(f)

# 🔍 Check packet against rules
def packet_matches_rules(packet, rules):
    proto, port = None, None
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if TCP in packet:
        proto, port = "TCP", packet[TCP].dport
    elif UDP in packet:
        proto, port = "UDP", packet[UDP].dport
    elif ICMP in packet:
        proto = "ICMP"

    if src_ip in rules["blocked_ips"]:
        return True, f"Blocked IP {src_ip}"
    if port and port in rules["blocked_ports"]:
        return True, f"Blocked port {port}"
    if proto in rules["blocked_protocols"]:
        return True, f"Blocked protocol {proto}"

    return False, "Allowed"

# 🔄 Packet handler
def handle_packet(packet):
    if IP in packet:
        rules = load_rules()
        blocked, reason = packet_matches_rules(packet, rules)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src_ip, dst_ip = packet[IP].src, packet[IP].dst
        proto = "ICMP" if ICMP in packet else "TCP" if TCP in packet else "UDP"
        action = "BLOCKED" if blocked else "ALLOWED"

        if blocked:
            block_ip(src_ip)

        log_packet(timestamp, src_ip, dst_ip, proto, action, reason)
        print(f"[{action}] {timestamp} {src_ip} → {dst_ip} [{proto}] — {reason}")

# 🔥 Entry point (manual mode only)
if __name__ == "__main__":
    print("🔒 Starting Python Firewall (manual mode)... Ctrl+C to stop.")
    sniff(filter="ip", prn=handle_packet, store=0)
