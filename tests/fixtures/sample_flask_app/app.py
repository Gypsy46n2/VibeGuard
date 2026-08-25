"""Tiny synthetic Flask + SQLite app used as a discovery fixture.

Deliberately simple; it exists so discovery has manifests, imports, and a container
file to chew on. It is not meant to be run.
"""

import os
import sqlite3

import jwt
from flask import Flask, jsonify, request

app = Flask(__name__)
DB_PATH = os.environ.get("DATABASE_PATH", "app.db")
API_BASE = "https://api.stripe.com/v1"


def get_connection():
    return sqlite3.connect(DB_PATH)


@app.route("/users/<user_id>")
def get_user(user_id):
    conn = get_connection()
    row = conn.execute("SELECT id, email FROM users WHERE id = ?", (user_id,)).fetchone()
    return jsonify({"id": row[0], "email": row[1]} if row else {})


@app.route("/login", methods=["POST"])
def login():
    password = request.json.get("password", "")
    token = jwt.encode({"sub": request.json.get("email"), "pw_len": len(password)}, "dev-secret")
    return jsonify({"token": token})


if __name__ == "__main__":
    app.run()
