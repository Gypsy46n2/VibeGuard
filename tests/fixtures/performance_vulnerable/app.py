"""Slow request paths, used as a discovery-level fixture."""

import time

from flask import Flask, jsonify, request
from PIL import Image

app = Flask(__name__)


class User:
    query = None

    def to_dict(self):
        return {}


@app.route("/users")
def list_users():
    return jsonify([r.to_dict() for r in User.query.all()])


@app.route("/wait")
def wait():
    time.sleep(5)
    return "ok"


@app.route("/upload", methods=["POST"])
def upload():
    img = Image.open(request.files["file"])
    img.thumbnail((2048, 2048))
    return "ok"
