"""Carts in a module global, uploads on local disk — the classic pair."""

from flask import Flask, request

app = Flask(__name__)

carts: dict[str, list[str]] = {}


@app.post("/cart")
def add_to_cart():
    carts.setdefault(request.form["user"], []).append(request.form["sku"])
    return "ok"


@app.post("/upload")
def upload():
    handle = request.files["file"]
    handle.save("uploads/" + handle.filename)
    return "ok"
