"""Deliberately unhardened API surface, used as a discovery-level fixture."""

import requests
from flask import Flask, request

app = Flask(__name__)


def handle(event):
    return event


def charge(amount):
    return {"charged": amount}


@app.route("/users")
def list_users():
    return {"users": []}


@app.route("/webhooks/stripe", methods=["POST"])
def stripe_webhook():
    handle(request.get_json())
    return "", 204


@app.route("/payments", methods=["POST"])
def create_payment():
    return charge(request.get_json()["amount"])


def upstream(url):
    attempts = 0
    while attempts < 3:
        attempts += 1
        resp = requests.get(url)
        if resp.ok:
            return resp.json()
    return None


if __name__ == "__main__":
    app.run(port=8000)
