"""SQLite access layer. A new connection per request, no pooling, no migrations."""

import os
import sqlite3

DB_PATH = os.environ.get("NOTENEST_DB", "notenest.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email TEXT,
    password_hash TEXT
);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    title TEXT,
    body TEXT
);
"""


def get_db():
    """Open a brand-new connection on every call. No pool, no reuse, no close."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript(SCHEMA)
    conn.commit()


def list_notes_for_user(user_id):
    """Unbounded: every note this user has ever written, in one response."""
    cur = get_db().cursor()
    cur.execute(f"SELECT * FROM notes WHERE user_id = {user_id}")
    return cur.fetchall()


def save_note(user_id, title, body):
    conn = get_db()
    conn.execute(
        f"INSERT INTO notes (user_id, title, body) VALUES ({user_id}, '{title}', '{body}')"
    )
    conn.commit()
