from flask import Flask, render_template, request, redirect, url_for
from scanner import sqli, xss, headers
import sqlite3
from datetime import datetime

app = Flask(__name__)

# ── Route 1: Home Page ──────────────────────────────────────────
@app.route('/')
def home():
    return render_template('index.html')

# ── Route 2: Run Scan ───────────────────────────────────────────
@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get('url', '').strip()
    disclaimer = request.form.get('disclaimer')

    # Check disclaimer was accepted
    if not disclaimer:
        return render_template('index.html', error='You must accept the disclaimer.')

    # Validate URL format
    if not url.startswith('http://') and not url.startswith('https://'):
        return render_template('index.html', error='Invalid URL. Must start with http:// or https://')

    # Run all three scanner modules
    results = []
    results += sqli.detect_sqli(url)
    results += xss.detect_xss(url)
    results += headers.check_headers(url)

    # Save scan to database
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO scans (target_url, total_issues) VALUES (?, ?)',
                   (url, len(results)))
    scan_id = cursor.lastrowid

    for r in results:
        cursor.execute(
            'INSERT INTO vulnerabilities (scan_id, vuln_type, severity, description) VALUES (?, ?, ?, ?)',
            (scan_id, r['type'], r['severity'], r['description'])
        )

    conn.commit()
    conn.close()

    return render_template('results.html', url=url, results=results, count=len(results))

# ── Route 3: Scan History ────────────────────────────────────────
@app.route('/history')
def history():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM scans ORDER BY scan_date DESC')
    scans = cursor.fetchall()
    conn.close()
    return render_template('history.html', scans=scans)

# ── Run the App ──────────────────────────────────────────────────
if __name__ == '__main__':
    app.run(debug=True)