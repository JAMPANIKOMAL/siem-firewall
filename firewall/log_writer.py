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
