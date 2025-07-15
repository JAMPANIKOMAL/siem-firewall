from flask import Flask, render_template, request
from log_writer import fetch_all_logs

app = Flask(__name__)

@app.route("/")
def index():
    logs = fetch_all_logs()
    return render_template("index.html", logs=logs)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
