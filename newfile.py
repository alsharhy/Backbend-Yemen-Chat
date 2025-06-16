from flask import Flask, request, jsonify
import sqlite3
import hashlib
import os
from flask_cors import CORS
from datetime import datetime

app = Flask(__name__)
CORS(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "users.db")

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fullname TEXT NOT NULL,
            email TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            last_login TEXT,
            banned_until TEXT,
            permanently_banned INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()

@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            INSERT INTO users (fullname, email, username, password)
            VALUES (?, ?, ?, ?)""",
            (data["fullname"], data["email"], data["username"], hash_password(data["password"]))
        )
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "error": "اسم المستخدم مستخدم بالفعل"})

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.execute("""
        SELECT * FROM users WHERE username = ? AND password = ?""",
        (data["username"], hash_password(data["password"]))
    )
    result = cursor.fetchone()

    if result:
        if "permanently_banned" in result and result["permanently_banned"]:
            conn.close()
            return jsonify({"success": False, "error": "تم حظر الحساب بشكل دائم"})
        
        if "banned_until" in result and result["banned_until"]:
            try:
                banned_until = datetime.strptime(result["banned_until"], "%Y-%m-%d %H:%M:%S")
                if banned_until > datetime.now():
                    conn.close()
                    return jsonify({"success": False, "error": "الحساب محظور مؤقتًا حتى " + result["banned_until"]})
            except:
                pass
        
        conn.execute("""
            UPDATE users SET last_login = ? WHERE id = ?""",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), result["id"])
        )
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    else:
        conn.close()
        return jsonify({"success": False, "error": "بيانات الدخول غير صحيحة"})

@app.route("/users", methods=["GET"])
def get_users():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.execute("SELECT * FROM users")
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(users)

@app.route("/users/<int:user_id>", methods=["GET", "PUT"])
def update_user(user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    if request.method == "GET":
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        if row:
            user = dict(zip([column[0] for column in cursor.description], row))
            conn.close()
            return jsonify(user)
        else:
            conn.close()
            return jsonify({"error": "المستخدم غير موجود"}), 404

    elif request.method == "PUT":
        data = request.json
        cursor.execute("""
            UPDATE users
            SET fullname = ?, email = ?, username = ?, banned_until = ?, permanently_banned = ?
            WHERE id = ?
        """, (
            data.get("fullname"),
            data.get("email"),
            data.get("username"),
            data.get("banned_until"),
            data.get("permanently_banned", 0),
            user_id
        ))
        conn.commit()
        conn.close()
        return jsonify({"success": True})

# ✅ هذا هو مسار الحذف الذي طلبت إضافته
@app.route("/users/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)