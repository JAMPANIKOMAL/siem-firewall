import sqlite3
import json
import os
from collections import Counter

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "logs.db")
RULES_PATH = os.path.join(BASE_DIR, "rules.json")

def load_thresholds():
    try:
        with open(RULES_PATH, "r") as f:
            rules = json.load(f)
        return rules.get("detection", {})
    except Exception as e:
        print(f"Error loading detection config: {e}")
        return {}

def detect_suspicious_logs():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, src_ip, protocol, action FROM logs")
    rows = cursor.fetchall()
    conn.close()

    thresholds = load_thresholds()
    freq_thresh = thresholds.get("frequent_ip_threshold", 5)
    rare_thresh = thresholds.get("rare_protocol_percent", 10)
    block_thresh = thresholds.get("repeated_block_threshold", 5)

    total_logs = len(rows)
    ip_counter = Counter()
    block_counter = Counter()
    protocol_counter = Counter()

    log_map = {}
    for log_id, src_ip, protocol, action in rows:
        ip_counter[src_ip] += 1
        protocol_counter[protocol] += 1
        if action.upper() == "BLOCK":
            block_counter[src_ip] += 1

        log_map[log_id] = {
            "frequent_ip": False,
            "rare_protocol": False,
            "repeated_blocks": False
        }

    rare_protocols = {
        proto for proto, count in protocol_counter.items()
        if (count / total_logs * 100) < rare_thresh
    }

    for log_id, src_ip, protocol, action in rows:
        flags = log_map[log_id]
        if ip_counter[src_ip] >= freq_thresh:
            flags["frequent_ip"] = True
        if protocol in rare_protocols:
            flags["rare_protocol"] = True
        if block_counter[src_ip] >= block_thresh and action.upper() == "BLOCK":
            flags["repeated_blocks"] = True

    return log_map
