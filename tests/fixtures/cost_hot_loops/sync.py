"""One billed call and one log line per row."""

import logging

import requests

log = logging.getLogger(__name__)


def sync(cursor):
    for row in cursor.fetchall():
        log.info("syncing %s", row)
        requests.post("https://api.example.com/sync", json={"id": row[0]})
