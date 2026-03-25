#!/usr/bin/env python3
"""
Todo App — Flask + SQLite backend
Run:  python server.py
Then open http://localhost:5000
"""

import sqlite3, hashlib, secrets, os
from flask import Flask, request, jsonify, g
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Allow requests from GitHub Pages (and anywhere else)
DB_PATH = os.environ.get("DB_PATH", "todo.db")  # On Render: set DB_PATH=/data/todo.db

# ── DB helpers ────────────────────────────────────────────────────────────────

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exc):
    db = getattr(g, "_database", None)
    if db: db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                salt     TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token   TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS todos (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL,
                text       TEXT NOT NULL,
                done       INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
        """)
        db.commit()

def hash_pw(password, salt):
    return hashlib.sha256((salt + password).encode()).hexdigest()

def auth_user(token):
    if not token: return None
    db = get_db()
    row = db.execute(
        "SELECT user_id FROM sessions WHERE token=?", (token,)
    ).fetchone()
    return row["user_id"] if row else None

# ── Auth routes ───────────────────────────────────────────────────────────────

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json()
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify(error="Username and password required"), 400
    salt = secrets.token_hex(16)
    pw_hash = hash_pw(password, salt)
    db = get_db()
    try:
        db.execute("INSERT INTO users(username,password,salt) VALUES(?,?,?)",
                   (username, pw_hash, salt))
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify(error="Username already taken"), 409
    return jsonify(ok=True), 201

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not row or hash_pw(password, row["salt"]) != row["password"]:
        return jsonify(error="Invalid credentials"), 401
    token = secrets.token_hex(32)
    db.execute("INSERT INTO sessions(token,user_id) VALUES(?,?)", (token, row["id"]))
    db.commit()
    return jsonify(token=token, username=username)

@app.route("/api/logout", methods=["POST"])
def logout():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    db = get_db()
    db.execute("DELETE FROM sessions WHERE token=?", (token,))
    db.commit()
    return jsonify(ok=True)

# ── Todo routes ───────────────────────────────────────────────────────────────

@app.route("/api/todos", methods=["GET"])
def get_todos():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    uid = auth_user(token)
    if not uid: return jsonify(error="Unauthorized"), 401
    db = get_db()
    rows = db.execute(
        "SELECT id,text,done,created_at FROM todos WHERE user_id=? ORDER BY created_at DESC",
        (uid,)
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/todos", methods=["POST"])
def add_todo():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    uid = auth_user(token)
    if not uid: return jsonify(error="Unauthorized"), 401
    text = (request.get_json().get("text") or "").strip()
    if not text: return jsonify(error="Text required"), 400
    db = get_db()
    cur = db.execute("INSERT INTO todos(user_id,text) VALUES(?,?)", (uid, text))
    db.commit()
    row = db.execute("SELECT id,text,done,created_at FROM todos WHERE id=?",
                     (cur.lastrowid,)).fetchone()
    return jsonify(dict(row)), 201

@app.route("/api/todos/<int:tid>", methods=["PATCH"])
def update_todo(tid):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    uid = auth_user(token)
    if not uid: return jsonify(error="Unauthorized"), 401
    data = request.get_json()
    db = get_db()
    row = db.execute("SELECT * FROM todos WHERE id=? AND user_id=?", (tid, uid)).fetchone()
    if not row: return jsonify(error="Not found"), 404
    done = data.get("done", row["done"])
    text = (data.get("text") or row["text"]).strip()
    db.execute("UPDATE todos SET done=?,text=? WHERE id=?", (int(done), text, tid))
    db.commit()
    updated = db.execute("SELECT id,text,done,created_at FROM todos WHERE id=?",
                         (tid,)).fetchone()
    return jsonify(dict(updated))

@app.route("/api/todos/<int:tid>", methods=["DELETE"])
def delete_todo(tid):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    uid = auth_user(token)
    if not uid: return jsonify(error="Unauthorized"), 401
    db = get_db()
    db.execute("DELETE FROM todos WHERE id=? AND user_id=?", (tid, uid))
    db.commit()
    return jsonify(ok=True)

if __name__ == "__main__":
    init_db()
    print("✓ Todo API running at http://localhost:5000")
    app.run(debug=False, port=5000)
