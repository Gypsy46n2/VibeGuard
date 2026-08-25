"""Static assets and per-request connections, used as a discovery-level fixture."""

import requests
from flask import Flask, send_from_directory

app = Flask(__name__)


@app.route("/assets/<path:name>")
def assets(name):
    return send_from_directory("static", name)


def fan_out(urls):
    return [requests.get(url, timeout=5).json() for url in urls]
