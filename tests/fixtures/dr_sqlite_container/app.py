"""Tiny app whose only datastore is a SQLite file inside the image."""

import sqlite3

from flask import Flask

app = Flask(__name__)
conn = sqlite3.connect("data/app.db")


@app.get("/notes")
def notes():
    return list(conn.execute("SELECT id, body FROM notes"))
