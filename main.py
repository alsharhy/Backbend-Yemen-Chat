from flask import Flask, request, jsonify
import psycopg2
from psycopg2.extras import RealDictCursor
from flask_cors import CORS
from datetime import datetime
import hashlib
import os

app = Flask(__name__)
CORS(app)

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
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS chats (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            title TEXT DEFAULT 'محادثة جديدة',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id SERIAL PRIMARY KEY,
            chat_id INTEGER REFERENCES chats(id) ON DELETE CASCADE,
            sender_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    cursor.close()
    conn.close()

# تشغيل تهيئة قاعدة البيانات عند بدء التطبيق
init_db()

@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (fullname, email, username, password)
            VALUES (%s, %s, %s, %s)
        """, (data["fullname"], data["email"], data["username"], hash_password(data["password"])))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"success": True})
    except psycopg2.IntegrityError:
        return jsonify({"success": False, "error": "اسم المستخدم مستخدم بالفعل"})

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM users WHERE username = %s AND password = %s
    """, (data["username"], hash_password(data["password"])))
    result = cursor.fetchone()

    if result:
        if result["permanently_banned"]:
            cursor.close()
            conn.close()
            return jsonify({"success": False, "error": "تم حظر الحساب بشكل دائم"})

        if result["banned_until"]:
            try:
                banned_until = datetime.strptime(result["banned_until"], "%Y-%m-%d %H:%M:%S")
                if banned_until > datetime.now():
                    cursor.close()
                    conn.close()
                    return jsonify({"success": False, "error": "الحساب محظور مؤقتًا حتى " + result["banned_until"]})
            except:
                pass

        cursor.execute("""
            UPDATE users SET last_login = %s WHERE id = %s
        """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), result["id"]))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"success": True, "user_id": result["id"]})
    else:
        cursor.close()
        conn.close()
        return jsonify({"success": False, "error": "بيانات الدخول غير صحيحة"})

@app.route("/users", methods=["GET"])
def get_users():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(users)

@app.route("/users/<int:user_id>", methods=["GET", "PUT", "DELETE"])
def user_operations(user_id):
    conn = get_connection()
    cursor = conn.cursor()

    if request.method == "GET":
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        if row:
            return jsonify(row)
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
        cursor.close()
        conn.close()
        return jsonify({"success": True})

    elif request.method == "DELETE":
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"success": True})

@app.route("/chats", methods=["GET"])
def get_chats():
    user_id = request.args.get("user_id")
    if not user_id:
        return jsonify({"error": "يرجى توفير user_id"}), 400

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM chats WHERE user_id = %s ORDER BY created_at DESC", (user_id,))
    chats = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(chats)

@app.route("/chats", methods=["POST"])
def create_chat():
    data = request.json
    user_id = data.get("user_id")
    title = data.get("title", "محادثة جديدة")

    if not user_id:
        return jsonify({"error": "user_id مطلوب"}), 400

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO chats (user_id, title) VALUES (%s, %s) RETURNING id", (user_id, title))
    chat_id = cursor.fetchone()["id"]
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({"success": True, "chat_id": chat_id})

@app.route("/chats/<int:chat_id>", methods=["PUT"])
def update_chat(chat_id):
    data = request.json
    title = data.get("title")

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE chats SET title = %s WHERE id = %s", (title, chat_id))
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({"success": True})

@app.route("/chats/<int:chat_id>", methods=["DELETE"])
def delete_chat(chat_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM chats WHERE id = %s", (chat_id,))
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({"success": True})

@app.route("/messages/<int:chat_id>", methods=["GET"])
def get_messages(chat_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT m.id, m.message, m.created_at, m.sender_id, u.username as sender_username
        FROM messages m
        LEFT JOIN users u ON m.sender_id = u.id
        WHERE m.chat_id = %s
        ORDER BY m.created_at ASC
    """, (chat_id,))
    messages = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(messages)

@app.route("/messages", methods=["POST"])
def send_message():
    data = request.json
    chat_id = data.get("chat_id")
    sender_id = data.get("sender_id")
    message = data.get("message")

    if not all([chat_id, sender_id, message]):
        return jsonify({"success": False, "error": "chat_id و sender_id و message مطلوبون"}), 400

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO messages (chat_id, sender_id, message) VALUES (%s, %s, %s) RETURNING id
    """, (chat_id, sender_id, message))
    message_id = cursor.fetchone()["id"]
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({"success": True, "message_id": message_id})

if __name__ == "__main__":
    app.run(debug=True)