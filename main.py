from flask import Flask, request, jsonify
import psycopg2
from psycopg2.extras import RealDictCursor
from flask_cors import CORS
from datetime import datetime
import hashlib
import os
import json

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
            id TEXT PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            title TEXT DEFAULT 'محادثة جديدة',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id SERIAL PRIMARY KEY,
            chat_id TEXT REFERENCES chats(id) ON DELETE CASCADE,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            timestamp TIMESTAMP
        )
    """)

    conn.commit()
    cursor.close()
    conn.close()

@app.route("/api/chats", methods=["GET"])
def get_chats():
    user_id = request.args.get("user_id")
    if not user_id:
        return jsonify({"error": "يرجى توفير user_id"}), 400

    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT c.*, 
                   json_agg(json_build_object(
                       'role', m.role, 
                       'content', m.content, 
                       'timestamp', m.timestamp
                   ) ORDER BY m.timestamp) AS messages
            FROM chats c
            LEFT JOIN messages m ON c.id = m.chat_id
            WHERE c.user_id = %s
            GROUP BY c.id
            ORDER BY c.created_at DESC
        """, (user_id,))
        chats = cursor.fetchall()
        
        # تحويل الرسائل من JSON إلى قائمة
        for chat in chats:
            if chat['messages'] and chat['messages'][0] is not None:
                chat['messages'] = chat['messages']
            else:
                chat['messages'] = []
                
        return jsonify(chats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/api/chats", methods=["POST"])
def save_chat():
    data = request.json
    chat_id = data.get("id")
    title = data.get("title")
    messages = data.get("messages", [])
    user_id = data.get("user_id")  # يجب إضافة هذا الحقل في الطلب

    if not user_id:
        return jsonify({"error": "user_id مطلوب"}), 400

    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        # التحقق مما إذا كانت المحادثة موجودة
        cursor.execute("SELECT id FROM chats WHERE id = %s", (chat_id,))
        chat_exists = cursor.fetchone()
        
        if chat_exists:
            # تحديث المحادثة
            cursor.execute("UPDATE chats SET title = %s WHERE id = %s", (title, chat_id))
            
            # حذف الرسائل القديمة
            cursor.execute("DELETE FROM messages WHERE chat_id = %s", (chat_id,))
        else:
            # إنشاء محادثة جديدة
            cursor.execute("""
                INSERT INTO chats (id, user_id, title) 
                VALUES (%s, %s, %s)
            """, (chat_id, user_id, title))
        
        # إضافة الرسائل الجديدة
        for msg in messages:
            cursor.execute("""
                INSERT INTO messages (chat_id, role, content, timestamp)
                VALUES (%s, %s, %s, %s)
            """, (chat_id, msg['role'], msg['content'], msg['timestamp']))
        
        conn.commit()
        return jsonify({"success": True, "chat_id": chat_id})
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/api/chats/<chat_id>", methods=["DELETE"])
def delete_chat(chat_id):
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("DELETE FROM chats WHERE id = %s", (chat_id,))
        conn.commit()
        return jsonify({"success": True})
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# بقية نقاط النهاية كما هي بدون تغيير...

if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)