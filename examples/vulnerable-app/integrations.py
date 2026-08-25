"""Outbound calls to the services NoteNest depends on."""

import requests

SEARCH_API = "https://search.example.com"
AVATAR_API = "https://avatars.example.com"


def index_note(note_id, body):
    """No timeout: a hung search cluster pins this worker forever."""
    return requests.post(
        f"{SEARCH_API}/index",
        json={"id": note_id, "body": body},
    )


def fetch_avatar(email):
    """A fresh connection and no timeout on every single avatar."""
    response = requests.get(f"{AVATAR_API}/{email}.png")
    return response.content


def notify_all(subscribers, note_id):
    """One synchronous HTTP call per subscriber, inside the request path."""
    for subscriber in subscribers:
        try:
            requests.post(subscriber["webhook"], json={"note": note_id})
        except Exception:
            pass
