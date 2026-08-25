"""Deliberately repairable service used by the M3 fixer tests.

Every defect here has a deterministic, provably safe repair, so the end-to-end fix
test can assert on real patches rather than on mocks.
"""

import requests
from flask import Flask

app = Flask(__name__)
UPSTREAM = "https://api.example.com"


@app.route("/users/<user_id>")
def get_user(user_id):
    response = requests.get(f"{UPSTREAM}/users/{user_id}")
    print(response.status_code)
    return response.json()


def publish(event):
    requests.post(f"{UPSTREAM}/events", json=event)
    return True
