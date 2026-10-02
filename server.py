#!/usr/bin/env python3
"""
Scenario Sketchbook sync server.

Serves index.html and a small JSON API that stores project documents in SQLite.
Every push is kept as a numbered revision, so the revision table is also the journal.

    pip install -r requirements.txt
    python server.py set-password
    python server.py run                 # http://127.0.0.1:8765

Settings (environment variables):
    SKETCHBOOK_DATA              folder for the database and secrets (default ./data)
    SKETCHBOOK_INSECURE_COOKIES  set to 1 to allow login over plain http (local testing only)
    SKETCHBOOK_TRUST_PROXY       set to 1 when behind a reverse proxy that sets X-Forwarded-* headers
"""
import argparse
import getpass
import json
import os
import re
import secrets
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, g, jsonify, request, send_from_directory, session
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

HERE = Path(__file__).resolve().parent
DATA = Path(os.environ.get("SKETCHBOOK_DATA", HERE / "data"))
DB_PATH = DATA / "sketchbook.db"
HASH_PATH = DATA / "password.hash"
SECRET_PATH = DATA / "secret.key"

ID_RE = re.compile(r"^[A-Za-z0-9_-]{3,64}$")
MAX_DOC_BYTES = 4 * 1024 * 1024

SCHEMA = """
CREATE TABLE IF NOT EXISTS revisions (
    project_id TEXT    NOT NULL,
    rev        INTEGER NOT NULL,
    name       TEXT    NOT NULL,
    doc        TEXT    NOT NULL,
    at         TEXT    NOT NULL,
    device     TEXT,
    note       TEXT,
    summary    TEXT,
    PRIMARY KEY (project_id, rev)
);
"""


# ---------- small helpers ----------

def ensure_data_dir():
    DATA.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(DATA, 0o700)
    except OSError:
        pass


def write_private(path, text):
    """Write a file readable only by the current user."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)


def load_secret():
    ensure_data_dir()
    if not SECRET_PATH.exists():
        write_private(SECRET_PATH, secrets.token_hex(32))
    return SECRET_PATH.read_text().strip()


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def clip(value, n):
    return str(value or "")[:n]


# ---------- app ----------

def create_app():
    app = Flask(__name__, static_folder=None)
    app.config.update(
        SECRET_KEY=load_secret(),
        MAX_CONTENT_LENGTH=MAX_DOC_BYTES + 64 * 1024,
        SESSION_COOKIE_NAME="sketchbook",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=not os.environ.get("SKETCHBOOK_INSECURE_COOKIES"),
        PERMANENT_SESSION_LIFETIME=timedelta(days=30),
    )
    if os.environ.get("SKETCHBOOK_TRUST_PROXY"):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    failures = {}  # ip -> [count, locked_until]

    # --- database ---
    def db():
        if "db" not in g:
            ensure_data_dir()
            c = sqlite3.connect(DB_PATH, isolation_level=None, timeout=10)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode=WAL")
            c.executescript(SCHEMA)
            g.db = c
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        c = g.pop("db", None)
        if c is not None:
            c.close()

    # --- guards and headers ---
    @app.before_request
    def csrf_guard():
        # Cookies are SameSite=Strict; this custom header is a second wall. A page on another
        # site cannot send it without a CORS preflight, and this server never allows CORS.
        if request.path.startswith("/api/") and request.method in ("POST", "PUT", "DELETE"):
            if request.headers.get("X-Sketchbook") != "1":
                return jsonify(error="Missing X-Sketchbook header"), 403

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
            "connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
        )
        if request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    def login_required(fn):
        from functools import wraps

        @wraps(fn)
        def wrapper(*a, **kw):
            if not session.get("u"):
                return jsonify(error="Not signed in"), 401
            return fn(*a, **kw)
        return wrapper

    # --- pages and auth ---
    @app.get("/")
    def index():
        resp = send_from_directory(HERE, "index.html")
        resp.headers["Cache-Control"] = "no-cache"
        return resp

    @app.get("/api/health")
    def health():
        return jsonify(ok=True)

    @app.get("/api/me")
    def me():
        if session.get("u"):
            return jsonify(user="you")
        return jsonify(error="Not signed in"), 401

    @app.post("/api/login")
    def login():
        ip = request.remote_addr or "?"
        count, locked_until = failures.get(ip, [0, 0])
        if time.time() < locked_until:
            return jsonify(error="Too many attempts. Wait a minute and try again."), 429
        if not HASH_PATH.exists():
            return jsonify(error="No password set. Run: python server.py set-password"), 503
        body = request.get_json(silent=True) or {}
        pw = body.get("password")
        if isinstance(pw, str) and check_password_hash(HASH_PATH.read_text().strip(), pw):
            failures.pop(ip, None)
            session.clear()
            session.permanent = True
            session["u"] = 1
            return jsonify(user="you")
        count += 1
        failures[ip] = [count, time.time() + 60 * min(2 ** max(count - 5, 0), 60) if count >= 5 else 0]
        return jsonify(error="Wrong password"), 401

    @app.post("/api/logout")
    def logout():
        session.clear()
        return jsonify(ok=True)

    # --- projects ---
    def head_rev(c, pid):
        row = c.execute("SELECT MAX(rev) AS m FROM revisions WHERE project_id=?", (pid,)).fetchone()
        return row["m"] or 0

    def check_id(pid):
        if not ID_RE.match(pid):
            return jsonify(error="Bad project id"), 400
        return None

    @app.get("/api/projects")
    @login_required
    def list_projects():
        rows = db().execute(
            """SELECT r.project_id AS id, r.name, r.rev, r.at, r.device
               FROM revisions r
               JOIN (SELECT project_id, MAX(rev) AS m FROM revisions GROUP BY project_id) h
                 ON h.project_id = r.project_id AND h.m = r.rev
               ORDER BY r.name COLLATE NOCASE"""
        ).fetchall()
        return jsonify([dict(r) for r in rows])

    @app.get("/api/projects/<pid>")
    @login_required
    def get_project(pid):
        bad = check_id(pid)
        if bad:
            return bad
        c = db()
        rev = request.args.get("rev", type=int) or head_rev(c, pid)
        row = c.execute("SELECT * FROM revisions WHERE project_id=? AND rev=?", (pid, rev)).fetchone()
        if not row:
            return jsonify(error="Not found"), 404
        return jsonify(id=pid, name=row["name"], rev=row["rev"], at=row["at"], device=row["device"],
                       note=row["note"], summary=row["summary"], doc=json.loads(row["doc"]))

    @app.get("/api/projects/<pid>/journal")
    @login_required
    def journal(pid):
        bad = check_id(pid)
        if bad:
            return bad
        rows = db().execute(
            "SELECT rev, at, device, note, summary FROM revisions WHERE project_id=? ORDER BY rev DESC LIMIT 200",
            (pid,),
        ).fetchall()
        return jsonify([dict(r) for r in rows])

    @app.post("/api/projects/<pid>")
    @login_required
    def push_project(pid):
        bad = check_id(pid)
        if bad:
            return bad
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(error="Expected a JSON object"), 400
        doc, base = body.get("doc"), body.get("baseRev")
        if (not isinstance(doc, dict) or doc.get("id") != pid
                or not all(isinstance(doc.get(k), list) for k in ("components", "groups", "scenarios"))):
            return jsonify(error="That doesn't look like a project document"), 400
        if not isinstance(base, int) or isinstance(base, bool) or base < 0:
            return jsonify(error="baseRev must be a whole number"), 400
        text = json.dumps(doc, separators=(",", ":"))
        if len(text.encode()) > MAX_DOC_BYTES:
            return jsonify(error="Document is too large"), 413

        c = db()
        c.execute("BEGIN IMMEDIATE")  # take the write lock, so check-and-insert is atomic
        try:
            head = head_rev(c, pid)
            if base != head:
                c.execute("ROLLBACK")
                return jsonify(error="conflict", rev=head), 409
            rev = head + 1
            c.execute(
                "INSERT INTO revisions (project_id, rev, name, doc, at, device, note, summary) VALUES (?,?,?,?,?,?,?,?)",
                (pid, rev, clip(doc.get("name"), 200) or "Untitled", text, now_iso(),
                 clip(body.get("device"), 80), clip(body.get("note"), 500), clip(body.get("summary"), 1000)),
            )
            c.execute("COMMIT")
        except Exception:
            if c.in_transaction:
                c.execute("ROLLBACK")
            raise
        return jsonify(rev=rev)

    @app.errorhandler(413)
    def too_big(_e):
        return jsonify(error="Request too large"), 413

    return app


# ---------- command line ----------

def set_password():
    ensure_data_dir()
    pw = getpass.getpass("New password (10+ characters): ")
    if len(pw) < 10:
        sys.exit("Too short. Use at least 10 characters.")
    if getpass.getpass("Again: ") != pw:
        sys.exit("Those didn't match.")
    write_private(HASH_PATH, generate_password_hash(pw))
    print(f"Saved. Existing sessions stay valid until they expire; delete {SECRET_PATH.name} to sign everyone out.")


def run(host, port):
    if not HASH_PATH.exists():
        sys.exit("No password yet. Run: python server.py set-password")
    app = create_app()
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("Warning: listening beyond this machine. Put HTTPS in front of it (see README).", file=sys.stderr)
    try:
        from waitress import serve
        print(f"Serving on http://{host}:{port}")
        serve(app, host=host, port=port, threads=4)
    except ImportError:
        print("waitress not installed; using Flask's development server.", file=sys.stderr)
        app.run(host=host, port=port)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("set-password", help="set or change the login password")
    r = sub.add_parser("run", help="start the server (default)")
    r.add_argument("--host", default="127.0.0.1")
    r.add_argument("--port", type=int, default=8765)
    args = p.parse_args()
    if args.cmd == "set-password":
        set_password()
    else:
        run(getattr(args, "host", "127.0.0.1"), getattr(args, "port", 8765))
