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
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO logs (timestamp, src_ip, dst_ip, protocol, action, reason)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (timestamp, src_ip, dst_ip, protocol, action, reason))
    new_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return new_id

def fetch_all_logs():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM logs ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_stats_by_column(column='protocol', limit=7):
    """Fetches statistics for a given column, to be used in charts."""
    # Allow-list to prevent SQL injection
    if column not in ['protocol', 'action']:
        return []
    
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cursor = conn.cursor()
    query = f"SELECT {column}, COUNT(*) as count FROM logs GROUP BY {column} ORDER BY count DESC LIMIT ?"
    cursor.execute(query, (limit,))
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

def get_events_by_time(granularity='minute', limit=60):
    """Groups logs by a given time granularity."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cursor = conn.cursor()

    if granularity == 'hour':
        time_format = '%Y-%m-%d %H:00:00'
        time_modifier = '-24 hours'
        label_format = '%H:00'
        limit = 24
    elif granularity == 'second':
        time_format = '%Y-%m-%d %H:%M:%S'
        time_modifier = '-60 seconds'
        label_format = '%H:%M:%S'
        limit = 60
    else:  # Default to minute
        time_format = '%Y-%m-%d %H:%M:00'
        time_modifier = '-60 minutes'
        label_format = '%H:%M'
        limit = 60

    query = f"""
        SELECT strftime('{label_format}', timestamp) as time_unit, COUNT(*)
        FROM logs
        WHERE timestamp >= strftime('%Y-%m-%d %H:%M:%S', 'now', '{time_modifier}')
        GROUP BY strftime('{time_format}', timestamp)
        ORDER BY time_unit ASC
        LIMIT ?
    """
    
    cursor.execute(query, (limit,))
    data = cursor.fetchall()
    conn.close()
    return data
