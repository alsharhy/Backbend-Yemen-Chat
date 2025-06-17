from flask import Flask, request, jsonify
import psycopg2
from psycopg2.extras import RealDictCursor
import hashlib
import os
from flask_cors import CORS
from datetime import datetime

app = Flask(__name__)
CORS(app)

# الاتصال بقاعدة البيانات
DATABASE_URL = os.environ.get("DATABASE_URL")

def get_connection():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
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
        conn = get_connection()
        conn.execute("""
            INSERT INTO users (fullname, email, username, password)
            VALUES (%s, %s, %s, %s)
        """, (
            data["fullname"], data["email"], data["username"], hash_password(data["password"])
        ))
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    except psycopg2.IntegrityError:
        return jsonify({"success": False, "error": "اسم المستخدم مستخدم بالفعل"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM users WHERE username = %s AND password = %s
    """, (
        data["username"], hash_password(data["password"])
    ))
    result = cursor.fetchone()

    if result:
        if result["permanently_banned"]:
            conn.close()
            return jsonify({"success": False, "error": "تم حظر الحساب بشكل دائم"})

        if result["banned_until"]:
            try:
                banned_until = datetime.strptime(result["banned_until"], "%Y-%m-%d %H:%M:%S")
                if banned_until > datetime.now():
                    conn.close()
                    return jsonify({"success": False, "error": "الحساب محظور مؤقتًا حتى " + result["banned_until"]})
            except:
                pass

        cursor.execute("""
            UPDATE users SET last_login = %s WHERE id = %s
        """, (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"), result["id"]
        ))
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    else:
        conn.close()
        return jsonify({"success": False, "error": "بيانات الدخول غير صحيحة"})

@app.route("/users", methods=["GET"])
def get_users():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    conn.close()
    return jsonify(users)

@app.route("/users/<int:user_id>", methods=["GET", "PUT"])
def update_user(user_id):
    conn = get_connection()
    cursor = conn.cursor()

    if request.method == "GET":
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        conn.close()
        if user:
            return jsonify(user)
        else:
            return jsonify({"error": "المستخدم غير موجود"}), 404

    elif request.method == "PUT":
        data = request.json
        cursor.execute("""
            UPDATE users
            SET fullname = %s, email = %s, username = %s, banned_until = %s, permanently_banned = %s
            WHERE id = %s
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

@app.route("/users/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)