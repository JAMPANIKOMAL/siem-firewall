from flask import Flask, render_template, Response, jsonify, request
from flask_socketio import SocketIO
from threading import Thread, Event, Lock
from scapy.all import sniff, get_if_list
import json
import sqlite3
import os

from analyzer import handle_packet
from log_writer import init_db, get_protocol_stats, get_action_stats, get_top_source_ips, get_events_by_time, fetch_all_logs

# --- App, SocketIO, and Lock Initialization ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-very-secret-key'
socketio = SocketIO(app, async_mode='threading')
rules_lock = Lock() # To prevent race conditions when reading/writing rules.json

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

def get_stats():
    """Helper function to gather all stats for the dashboard."""
    return {
        'protocols': get_protocol_stats(),
        'actions': get_action_stats(),
        'top_ips': get_top_source_ips(),
        'events_over_time': get_events_by_time()
    }

def packet_handler_with_emit(packet):
    """Processes a packet and emits the log data over WebSocket."""
    log_data = handle_packet(packet)
    if log_data:
        socketio.emit('new_log', log_data)
        if log_data['id'] % 5 == 0:
            socketio.emit('stats_update', get_stats())

def run_sniffer(stop_event, interface=None):
    """The target function for the sniffer thread."""
    print(f"Sniffer thread started on interface: {interface or 'default'}.")
    try:
        sniff(iface=interface, filter="ip", prn=packet_handler_with_emit, stop_filter=lambda p: stop_event.is_set())
    except Exception as e:
        print(f"Error starting sniffer: {e}")
        socketio.emit('sniffer_error', {'error': str(e)})
    finally:
        print("Sniffer thread stopped.")

# --- Flask Routes ---
@app.route('/')
def index():
    interfaces = get_if_list()
    return render_template('index.html', interfaces=interfaces)

@app.route('/get-rules')
def get_rules():
    """Reads and returns the current firewall rules."""
    with rules_lock:
        with open("rules.json", "r") as f:
            rules = json.load(f)
    return jsonify(rules)

@app.route('/update-rule', methods=['POST'])
def update_rule():
    """Adds or removes a rule from rules.json."""
    data = request.get_json()
    action = data.get('action')
    rule_type = data.get('type')
    value = data.get('value')

    if not all([action, rule_type, value]):
        return jsonify({'status': 'error', 'message': 'Missing data'}), 400

    with rules_lock:
        with open("rules.json", "r+") as f:
            rules = json.load(f)
            
            # Ensure the list exists
            if rule_type not in rules:
                rules[rule_type] = []

            target_list = rules[rule_type]

            if action == 'add':
                if value not in target_list:
                    target_list.append(value)
                else:
                    return jsonify({'status': 'error', 'message': 'Rule already exists'}), 409
            elif action == 'remove':
                if value in target_list:
                    target_list.remove(value)
                else:
                     return jsonify({'status': 'error', 'message': 'Rule not found'}), 404
            else:
                return jsonify({'status': 'error', 'message': 'Invalid action'}), 400

            f.seek(0)
            json.dump(rules, f, indent=2)
            f.truncate()
    
    return jsonify({'status': 'success', 'rules': rules})


# --- SocketIO Event Handlers ---
@socketio.on('connect')
def handle_connect():
    print('Client connected')
    socketio.emit('stats_update', get_stats())

@socketio.on('start_logging')
def handle_start_logging(data):
    global sniffer_thread
    selected_interface = data.get('interface')
    interface_to_use = None if selected_interface == 'default' else selected_interface

    if sniffer_thread is None or not sniffer_thread.is_alive():
        stop_sniffer_event.clear()
        sniffer_thread = Thread(target=run_sniffer, args=(stop_sniffer_event, interface_to_use))
        sniffer_thread.start()
        print(f"Logging started on interface: '{interface_to_use or 'default'}'.")

@socketio.on('stop_logging')
def handle_stop_logging():
    stop_sniffer_event.set()
    global sniffer_thread
    if sniffer_thread:
        sniffer_thread.join()
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
    return Response(json.dumps(log_list, indent=2), mimetype='application/json',
                    headers={'Content-Disposition': 'attachment;filename=siem_logs.json'})

if __name__ == '__main__':
    reset_database()
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
