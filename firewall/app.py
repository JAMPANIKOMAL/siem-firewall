from flask import Flask, render_template, request
from log_writer import (
    fetch_filtered_logs,
    get_protocol_stats,
    get_action_stats,
    get_top_source_ips
)
from detector import detect_suspicious_logs

app = Flask(__name__)

@app.route("/", methods=["GET"])
def index():
    # 🔍 Search & Filter Parameters
    query = request.args.get("query", "").strip()
    filter_action = request.args.get("action", "")

    # 🧾 Fetch Logs
    logs = fetch_filtered_logs(query, filter_action)

    # 🧠 Smart Detection
    suspicious_flags = detect_suspicious_logs()

    # 🧩 Merge flags into logs
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

    # 📊 Chart Data
    protocols = get_protocol_stats()
    actions = get_action_stats()
    top_ips = get_top_source_ips()

    # 🎯 Render Template
    return render_template(
        "index.html",
        logs=enhanced_logs,
        query=query,
        filter_action=filter_action,
        protocols=protocols,
        actions=actions,
        top_ips=top_ips
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
