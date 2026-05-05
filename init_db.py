import sqlite3

conn = sqlite3.connect('database.db')
cursor = conn.cursor()

# Table 1: Store each scan session
cursor.execute('''
CREATE TABLE IF NOT EXISTS scans (
    scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url TEXT NOT NULL,
    scan_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    total_issues INTEGER DEFAULT 0
)
''')

# Table 2: Store individual vulnerabilities found
cursor.execute('''
CREATE TABLE IF NOT EXISTS vulnerabilities (
    vuln_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    vuln_type TEXT,
    severity TEXT,
    description TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
)
''')

conn.commit()
conn.close()
print('Database created successfully!')
