"""Deliberately vulnerable Flask app used as a security-pack fixture.

Every defect here is intentional. The file is never executed; it exists so
discovery and end-to-end scans have realistic material to chew on.
"""

import os
import pickle
import sqlite3
import subprocess

import requests
from flask import Flask, make_response, redirect, request, send_file

app = Flask(__name__)
UPLOADS = "/srv/uploads"


def db():
    return sqlite3.connect("app.db")


@app.route("/user")
def user():
    uid = request.args.get("id")
    return str(db().execute(f"SELECT id, email FROM users WHERE id = {uid}").fetchall())


@app.route("/thumbnail")
def thumbnail():
    name = request.args.get("name")
    subprocess.run(f"convert {name} out.png", shell=True)
    return "ok"


@app.route("/download/<path:filename>")
def download(filename):
    return send_file(os.path.join(UPLOADS, filename))


@app.route("/preview")
def preview():
    return requests.get(request.args.get("url"), timeout=5).text


@app.route("/go")
def go():
    return redirect(request.args.get("next"))


@app.route("/restore", methods=["POST"])
def restore():
    return str(pickle.loads(request.data))


@app.route("/login", methods=["POST"])
def login():
    resp = make_response("ok")
    resp.set_cookie("session", "abc")
    return resp


if __name__ == "__main__":
    app.run(debug=True)
