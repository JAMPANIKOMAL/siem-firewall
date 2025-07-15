import sqlite3

DB_PATH = "logs.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
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
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO logs (timestamp, src_ip, dst_ip, protocol, action, reason)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (timestamp, src_ip, dst_ip, protocol, action, reason))
    conn.commit()
    conn.close()


def fetch_all_logs():
    conn = sqlite3.connect("logs.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM logs ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows



def fetch_filtered_logs(query="", action=""):
    conn = sqlite3.connect("logs.db")
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
