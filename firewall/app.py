from flask import Flask, render_template, request
from log_writer import (
    fetch_filtered_logs,
    get_protocol_stats,
    get_action_stats,
    get_top_source_ips
)

app = Flask(__name__)

@app.route("/", methods=["GET"])
def index():
    # Get query parameters
    query = request.args.get("query", "").strip()
    filter_action = request.args.get("action", "")

    # Fetch filtered logs based on query and action
    logs = fetch_filtered_logs(query, filter_action)

    # Dashboard stats
    protocols = get_protocol_stats()
    actions = get_action_stats()
    top_ips = get_top_source_ips()

    # Render HTML with all data
    return render_template(
        "index.html",
        logs=logs,
        query=query,
        filter_action=filter_action,
        protocols=protocols,
        actions=actions,
        top_ips=top_ips
    )

if __name__ == "__main__":
    # Run on all interfaces, port 5000
    app.run(host="0.0.0.0", port=5000, debug=True)
