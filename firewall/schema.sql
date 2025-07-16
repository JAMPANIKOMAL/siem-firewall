CREATE TABLE logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            action TEXT,
            reason TEXT
        );
CREATE TABLE sqlite_sequence(name,seq);
