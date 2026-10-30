import sqlite3
import json
from pathlib import Path
from datetime import datetime


# Store the database in the project root directory
BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "scanner.db"


def get_connection():
    """Create a connection to the SQLite database."""
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    """Create the scan history table if it does not exist."""

    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                status_code INTEGER,
                response_time REAL,
                findings_count INTEGER DEFAULT 0,
                summary TEXT,
                findings TEXT,
                scan_date TEXT NOT NULL
            )
        """)


def save_scan(target_url, results):
    """Save scan results and return the new scan ID."""

    findings = results.get("findings", [])
    summary = results.get("summary", {})

    with get_connection() as connection:
        cursor = connection.execute("""
            INSERT INTO scans (
                target_url,
                status_code,
                response_time,
                findings_count,
                summary,
                findings,
                scan_date
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            target_url,
            results.get("status_code"),
            results.get("response_time"),
            len(findings),
            json.dumps(summary),
            json.dumps(findings),
            datetime.now().astimezone().isoformat(timespec="seconds")
        ))

        scan_id = cursor.lastrowid

    return scan_id


def get_scan_history():
    """Retrieve previous scans, newest first."""

    with get_connection() as connection:
        rows = connection.execute("""
            SELECT
                id,
                target_url,
                status_code,
                response_time,
                findings_count,
                summary,
                findings,
                scan_date
            FROM scans
            ORDER BY id DESC
        """).fetchall()

    history = []

    for row in rows:
        scan = dict(row)

        # Convert saved JSON strings back into Python objects
        try:
            scan["summary"] = json.loads(scan["summary"] or "{}")
        except (json.JSONDecodeError, TypeError):
            scan["summary"] = {}

        try:
            scan["findings"] = json.loads(scan["findings"] or "[]")
        except (json.JSONDecodeError, TypeError):
            scan["findings"] = []

        history.append(scan)

    return history


def get_scan_by_id(scan_id):
    """Retrieve one saved scan by its ID."""

    with get_connection() as connection:
        row = connection.execute("""
            SELECT *
            FROM scans
            WHERE id = ?
        """, (scan_id,)).fetchone()

    if row is None:
        return None

    scan = dict(row)

    try:
        scan["summary"] = json.loads(scan["summary"] or "{}")
    except (json.JSONDecodeError, TypeError):
        scan["summary"] = {}

    try:
        scan["findings"] = json.loads(scan["findings"] or "[]")
    except (json.JSONDecodeError, TypeError):
        scan["findings"] = []

    return scan