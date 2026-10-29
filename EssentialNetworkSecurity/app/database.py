
import sqlite3
from pathlib import Path


DATABASE_PATH = Path(__file__).resolve().parent / "firewall.db"


def get_db_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    connection = get_db_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS firewall_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            priority INTEGER NOT NULL,
            source_ip TEXT NOT NULL,
            destination_ip TEXT NOT NULL,
            protocol TEXT NOT NULL,
            port TEXT NOT NULL,
            action TEXT NOT NULL
                CHECK (action IN ('ALLOW', 'DENY')),
            enabled INTEGER NOT NULL DEFAULT 1
                CHECK (enabled IN (0, 1))
        )
    """)

    
    connection.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            operation TEXT NOT NULL,
            rule_id INTEGER,
            details TEXT NOT NULL
        )
    """)


    connection.execute("""
        CREATE TABLE IF NOT EXISTS blocked_traffic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT NOT NULL,
            destination_ip TEXT NOT NULL,
            protocol TEXT NOT NULL,
            destination_port INTEGER NOT NULL,
            matched_rule INTEGER,
            reason TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()
