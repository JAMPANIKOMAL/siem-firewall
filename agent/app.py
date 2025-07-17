from flask import Flask, render_template, Response
from flask_socketio import SocketIO
from threading import Thread, Event
from scapy.all import sniff
import json
import sqlite3
import os

# Import from the renamed analyzer.py file
from analyzer import handle_packet, load_rules
from log_writer import init_db, log_packet, get_protocol_stats, get_action_stats, get_top_source_ips, fetch_all_logs

# --- App and SocketIO Initialization ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-very-secret-key'
socketio = SocketIO(app, async_mode='threading')

# --- Global variables for controlling the sniffer thread ---
sniffer_thread = None
stop_sniffer_event = Event()

def reset_database():
    """Deletes the old database file and initializes a new, empty one."""
    db_file = "logs.db"
    if os.path.exists(db_file):
        try:
            os.remove(db_file)
            print(f"Removed old database: {db_file}")
        except OSError as e:
            print(f"Error removing database file {db_file}: {e}")
    init_db()

def packet_handler_with_emit(packet):
    """Processes a packet and emits the log data over WebSocket."""
    log_data = handle_packet(packet)
    if log_data:
        socketio.emit('new_log', log_data)
        if log_data['id'] % 10 == 0:
            stats = {
                'protocols': get_protocol_stats(),
                'actions': get_action_stats(),
                'top_ips': get_top_source_ips()
            }
            socketio.emit('stats_update', stats)

def run_sniffer(stop_event):
    """The target function for the sniffer thread."""
    print("Sniffer thread started.")
    sniff(filter="ip", prn=packet_handler_with_emit, stop_filter=lambda p: stop_event.is_set())
    print("Sniffer thread stopped.")

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('start_logging')
def handle_start_logging():
    global sniffer_thread
    if sniffer_thread is None or not sniffer_thread.is_alive():
        stop_sniffer_event.clear()
        sniffer_thread = Thread(target=run_sniffer, args=(stop_sniffer_event,))
        sniffer_thread.start()
        print("Logging started.")

@socketio.on('stop_logging')
def handle_stop_logging():
    stop_sniffer_event.set()
    global sniffer_thread
    sniffer_thread = None
    print("Logging stopped.")
    
@socketio.on('clear_logs')
def handle_clear_logs():
    global sniffer_thread
    if sniffer_thread and sniffer_thread.is_alive():
        stop_sniffer_event.set()
        sniffer_thread.join()
        sniffer_thread = None
        print("Logging stopped to clear database.")
        
    reset_database()
    print("Database has been cleared.")
    socketio.emit('logs_cleared')

@app.route('/save-logs')
def save_logs():
    logs = fetch_all_logs()
    headers = ["id", "timestamp", "src_ip", "dst_ip", "protocol", "action", "reason"]
    log_list = [dict(zip(headers, log)) for log in logs]
    
    return Response(
        json.dumps(log_list, indent=2),
        mimetype='application/json',
        headers={'Content-Disposition': 'attachment;filename=siem_logs.json'}
    )

if __name__ == '__main__':
    reset_database()
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)