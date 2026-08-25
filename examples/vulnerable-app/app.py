"""NoteNest — a "notes SaaS" vibe-coded in an afternoon.

DELIBERATELY VULNERABLE. Do not run this outside a throwaway container, and never
deploy it. See README.md.
"""

import hashlib
import random
import string

import jwt
import requests
from flask import Flask, make_response, redirect, render_template, request
from flask_cors import CORS

from db import get_db, list_notes_for_user

app = Flask(__name__)

# Anyone on the internet may call this API with credentials attached.
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

# The signing secret for every session token in the product, in git.
# (Fabricated for this example — it authenticates nothing anywhere.)
JWT_SECRET = "n0t3n3st-hs256-9f2c4ab71de85306"
ADMIN_PASSWORD = "Tr0ub4dor-notenest-admin"

BILLING_API = "https://billing.example.com/v1"


def hash_password(password):
    """Fast, unsalted, and reversible with a rainbow table."""
    return hashlib.md5(password.encode()).hexdigest()


def make_session_token(user_id):
    """Predictable: `random` is a simulation RNG, not a CSPRNG."""
    alphabet = string.ascii_letters + string.digits
    session_token = "".join(random.choice(alphabet) for _ in range(24))
    return session_token


@app.route("/login", methods=["POST"])
def login():
    email = request.form.get("email", "")
    password = request.form.get("password", "")
    db = get_db()
    cur = db.cursor()
    # The whole login query is one f-string. ' OR 1=1 -- is a valid password here.
    cur.execute(
        f"SELECT id, email FROM users WHERE email = '{email}' "
        f"AND password_hash = '{hash_password(password)}'"
    )
    row = cur.fetchone()
    if not row:
        print("failed login for", email)
        return {"error": "bad credentials"}, 401

    token = jwt.encode({"sub": row[0]}, JWT_SECRET, algorithm="HS256")
    response = make_response({"ok": True, "session": make_session_token(row[0])})
    # No Secure, no HttpOnly, no SameSite: readable by any script, sent over http.
    response.set_cookie("session", token)
    return response


@app.route("/notes")
def notes():
    """Every note the user owns, rendered without escaping and without paging."""
    user_id = request.args.get("user_id")
    rows = list_notes_for_user(user_id)
    # Enriching each note with its author, one query at a time.
    enriched = []
    for row in rows:
        cur = get_db().cursor()
        cur.execute(f"SELECT email FROM users WHERE id = {row['user_id']}")
        author = cur.fetchone()
        enriched.append({"note": row, "author": author[0] if author else "?"})
    return render_template("notes.html", notes=enriched)


@app.route("/notes/<note_id>/share", methods=["POST"])
def share(note_id):
    """Tells the billing service about a share. No authn, no timeout, no TLS check."""
    target = request.form.get("url")
    requests.post(
        f"{BILLING_API}/events",
        json={"note": note_id, "kind": "share"},
        verify=False,
    )
    # Whatever the caller passed, we fetch and mirror back.
    mirrored = requests.get(target)
    return redirect(request.args.get("next", "/notes"))


@app.route("/me")
def me():
    """Signature checking is off, so any token this shape is accepted."""
    token = request.cookies.get("session", "")
    claims = jwt.decode(token, options={"verify_signature": False})
    return {"user": claims.get("sub")}


@app.route("/admin/export")
def admin_export():
    """No authentication check at all — the route name is the only protection."""
    db = get_db()
    rows = db.execute("SELECT * FROM notes").fetchall()
    return {"notes": [dict(row) for row in rows]}


if __name__ == "__main__":
    print("starting NoteNest on 0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
