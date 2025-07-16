from flask import Flask, render_template, request
from log_writer import (
    fetch_filtered_logs,
    get_protocol_stats,
    get_action_stats,
    get_top_source_ips
)
from detector import detect_suspicious_logs
from threading import Thread
from scapy.all import sniff
from firewall import handle_packet

app = Flask(__name__)
logging_thread = None
logging_active = False

def start_sniffer():
    global logging_active
    sniff(filter="ip", prn=handle_packet, store=0, stop_filter=lambda x: not logging_active)

@app.route("/start-logging", methods=["POST"])
def start_logging():
    global logging_thread, logging_active
    if not logging_active:
        logging_active = True
        logging_thread = Thread(target=start_sniffer, daemon=True)
        logging_thread.start()
        return "Firewall logging started"
    return "Already running"

@app.route("/stop-logging", methods=["POST"])
def stop_logging():
    global logging_active
    logging_active = False
    return "Firewall logging stopped"

@app.route("/", methods=["GET"])
def index():
    query = request.args.get("query", "").strip()
    filter_action = request.args.get("action", "")
    logs = fetch_filtered_logs(query, filter_action)

    suspicious_flags = detect_suspicious_logs()
    enhanced_logs = []
    for log in logs:
        log_id = log[0]
        flags = suspicious_flags.get(log_id, {
            "frequent_ip": False,
            "rare_protocol": False,
            "repeated_blocks": False
        })
        enhanced_logs.append({
            "id": log[0],
            "timestamp": log[1],
            "src_ip": log[2],
            "dst_ip": log[3],
            "protocol": log[4],
            "action": log[5],
            "reason": log[6],
            "flags": flags
        })

    return render_template(
        "index.html",
        logs=enhanced_logs,
        query=query,
        filter_action=filter_action,
        protocols=get_protocol_stats(),
        actions=get_action_stats(),
        top_ips=get_top_source_ips()
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
