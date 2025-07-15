import json
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP
import subprocess
from log_writer import log_packet, init_db

# ✅ Initialize the logs.db table
init_db()

# 🔒 Function to block IP using iptables
def block_ip(ip):
    try:
        # Check if rule already exists
        subprocess.run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"], check=True)
    except subprocess.CalledProcessError:
        # Rule doesn't exist, add it
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        print(f"🔒 IP {ip} has been blocked via iptables.")

# 📜 Load firewall rules from rules.json
def load_rules():
    with open("rules.json", "r") as f:
        return json.load(f)

# 🔍 Check if a packet matches any block rules
def packet_matches_rules(packet, rules):
    proto = None
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if TCP in packet:
        proto = "TCP"
        port = packet[TCP].dport
    elif UDP in packet:
        proto = "UDP"
        port = packet[UDP].dport
    elif ICMP in packet:
        proto = "ICMP"
        port = None
    else:
        return False, "UNKNOWN"

    if src_ip in rules["blocked_ips"]:
        return True, f"Blocked IP {src_ip}"
    if port and port in rules["blocked_ports"]:
        return True, f"Blocked port {port}"
    if proto in rules["blocked_protocols"]:
        return True, f"Blocked protocol {proto}"

    return False, "Allowed"

# 🔄 Process each packet captured by sniff()
def handle_packet(packet):
    if IP in packet:
        rules = load_rules()
        blocked, reason = packet_matches_rules(packet, rules)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = "ICMP"
        if TCP in packet: proto = "TCP"
        elif UDP in packet: proto = "UDP"

        action = "BLOCKED" if blocked else "ALLOWED"

        if blocked:
            block_ip(src_ip)  # 🔥 Real-time blocking via iptables

        log_packet(timestamp, src_ip, dst_ip, proto, action, reason)
        print(f"[{action}] {timestamp} {src_ip} → {dst_ip} [{proto}] — {reason}")

# 🚀 Start packet sniffing
print("🔒 Starting Python Firewall... Press Ctrl+C to stop.")
sniff(filter="ip", prn=handle_packet, store=0)
