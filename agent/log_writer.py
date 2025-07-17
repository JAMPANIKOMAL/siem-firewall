import sqlite3

DB_PATH = "logs.db"

def init_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            action TEXT,
            reason TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_packet(timestamp, src_ip, dst_ip, protocol, action, reason):
    # Added check_same_thread=False to support multi-threading
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO logs (timestamp, src_ip, dst_ip, protocol, action, reason)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (timestamp, src_ip, dst_ip, protocol, action, reason))
    new_id = cursor.lastrowid # Get the ID of the row we just inserted
    conn.commit()
    conn.close()
    return new_id # Return the new ID

def fetch_all_logs():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM logs ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows

def fetch_filtered_logs(query="", action=""):
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cursor = conn.cursor()
    query_like = f"%{query}%"
    
    sql = "SELECT * FROM logs WHERE 1=1"
    params = []

    if query:
        sql += " AND (src_ip LIKE ? OR dst_ip LIKE ? OR protocol LIKE ?)"
        params.extend([query_like, query_like, query_like])
    
    if action:
        sql += " AND action = ?"
        params.append(action)

    sql += " ORDER BY id DESC"
    
    cursor.execute(sql, params)
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_protocol_stats():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("SELECT protocol, COUNT(*) FROM logs GROUP BY protocol")
    data = cursor.fetchall()
    conn.close()
    return data

def get_action_stats():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("SELECT action, COUNT(*) FROM logs GROUP BY action")
    data = cursor.fetchall()
    conn.close()
    return data

def get_top_source_ips(limit=5):
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("SELECT src_ip, COUNT(*) FROM logs GROUP BY src_ip ORDER BY COUNT(*) DESC LIMIT ?", (limit,))
    data = cursor.fetchall()
    conn.close()
    return data

def get_events_by_time(limit=30):
    """Groups logs by minute to create time-series data."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cursor = conn.cursor()
    # This query groups logs by the minute they occurred in the last 30 minutes
    cursor.execute("""
        SELECT strftime('%H:%M', timestamp) as minute, COUNT(*)
        FROM logs
        WHERE timestamp >= strftime('%Y-%m-%d %H:%M:%S', 'now', '-30 minutes')
        GROUP BY minute
        ORDER BY minute ASC
        LIMIT ?
    """, (limit,))
    data = cursor.fetchall()
    conn.close()
    return data
