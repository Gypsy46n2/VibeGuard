"""Tiny service used by the containers fixture."""

from flask import Flask

app = Flask(__name__)


@app.get("/")
def index() -> str:
    return "ok"
