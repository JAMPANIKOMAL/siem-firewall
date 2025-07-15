from flask import Flask, render_template, request
from log_writer import fetch_filtered_logs, fetch_all_logs

app = Flask(__name__)

@app.route("/", methods=["GET"])
def index():
    query = request.args.get("query", "").strip()
    filter_action = request.args.get("action", "")
    logs = fetch_filtered_logs(query, filter_action)
    return render_template("index.html", logs=logs, query=query, filter_action=filter_action)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
