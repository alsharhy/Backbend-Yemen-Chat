from flask import Flask, request, jsonify, make_response
import psycopg2
from psycopg2.extras import RealDictCursor
from flask_cors import CORS
from datetime import datetime, timedelta
import hashlib
import os
import uuid

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
            permanently_banned INTEGER DEFAULT 0,
            is_admin BOOLEAN DEFAULT FALSE
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS news (
            id SERIAL PRIMARY KEY,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            image_url TEXT,
            status TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS chats (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id SERIAL PRIMARY KEY,
            chat_id INTEGER REFERENCES chats(id) ON DELETE CASCADE,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS support_chats (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            status TEXT DEFAULT 'open',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS support_messages (
            id SERIAL PRIMARY KEY,
            chat_id INTEGER REFERENCES support_chats(id) ON DELETE CASCADE,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            message TEXT,
            image_url TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # تهيئة حساب المسؤول
    cursor.execute("""
        INSERT INTO users (fullname, email, username, password, is_admin)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (username) DO NOTHING
    """, ("Admin User", "admin@example.com", "admin", hash_password("1234"), True))
    
    conn.commit()
    cursor.close()
    conn.close()
    print("تمت تهيئة قاعدة البيانات")

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
    data = request.json or {}
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"success": False, "error": "يرجى إدخال اسم المستخدم وكلمة المرور"}), 400

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM users WHERE username = %s AND password = %s
    """, (username, hash_password(password)))
    result = cursor.fetchone()

    if not result:
        cursor.close()
        conn.close()
        return jsonify({"success": False, "error": "بيانات الدخول غير صحيحة"})

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
                return jsonify({"success": False, "error": f"الحساب محظور مؤقتًا حتى {result['banned_until']}"})
        except Exception as e:
            print(f"خطأ في معالجة تاريخ الحظر: {e}")

    cursor.execute("""
        UPDATE users SET last_login = %s WHERE id = %s
    """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), result["id"]))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({
        "success": True,
        "is_admin": result["is_admin"],
        "user_id": result["id"],
        "redirect_to": "admin_panel.html" if result["is_admin"] else "index.html"
    })

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

@app.route("/users/<int:user_id>/admin", methods=["POST"])
def toggle_admin(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT is_admin FROM users WHERE id = %s", (user_id,))
    current_status = cursor.fetchone()["is_admin"]
    
    new_status = not current_status
    
    cursor.execute("""
        UPDATE users
        SET is_admin = %s
        WHERE id = %s
    """, (new_status, user_id))
    
    conn.commit()
    cursor.close()
    conn.close()
    
    return jsonify({
        "success": True,
        "is_admin": new_status,
        "message": f"تم {'ترقية' if new_status else 'إزالة'} المستخدم إلى مشرف"
    })

@app.route("/news", methods=["GET", "POST"])
def news_operations():
    conn = get_connection()
    cursor = conn.cursor()
    
    if request.method == "GET":
        cursor.execute("SELECT * FROM news ORDER BY created_at DESC")
        news = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify(news)
    
    elif request.method == "POST":
        data = request.json
        try:
            cursor.execute("""
                INSERT INTO news (title, content, image_url, status)
                VALUES (%s, %s, %s, %s)
            """, (data["title"], data["content"], data.get("image_url", ""), data["status"]))
            conn.commit()
            cursor.close()
            conn.close()
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)})

@app.route("/news/<int:news_id>", methods=["DELETE", "PUT"])
def single_news_operations(news_id):
    conn = get_connection()
    cursor = conn.cursor()
    
    if request.method == "DELETE":
        cursor.execute("DELETE FROM news WHERE id = %s", (news_id,))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"success": True})
    
    elif request.method == "PUT":
        data = request.json
        cursor.execute("""
            UPDATE news
            SET title = %s, content = %s, image_url = %s, status = %s
            WHERE id = %s
        """, (data["title"], data["content"], data["image_url"], data["status"], news_id))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"success": True})

@app.route("/update-profile", methods=["POST"])
def update_profile():
    data = request.json
    user_id = data.get("user_id")
    
    if not user_id:
        return jsonify({"success": False, "error": "User ID missing"}), 400
    
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            UPDATE users
            SET fullname = %s, email = %s, username = %s
            WHERE id = %s
        """, (data["fullname"], data["email"], data["username"], user_id))
        
        conn.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})
    finally:
        cursor.close()
        conn.close()

@app.route("/chats", methods=["GET"])
def get_user_chats():
    user_id = request.args.get("user_id")
    if not user_id:
        return jsonify({"error": "User ID is required"}), 400
    
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM chats 
        WHERE user_id = %s 
        ORDER BY created_at DESC
    """, (user_id,))
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
        return jsonify({"success": False, "error": "User ID is required"}), 400
    
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO chats (user_id, title)
            VALUES (%s, %s)
            RETURNING id
        """, (user_id, title))
        chat_id = cursor.fetchone()["id"]
        conn.commit()
        return jsonify({"success": True, "chat_id": chat_id})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/chats/<int:chat_id>", methods=["DELETE"])
def delete_chat(chat_id):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM chats WHERE id = %s", (chat_id,))
        conn.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/chats/<int:chat_id>/messages", methods=["GET"])
def get_chat_messages(chat_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM messages 
        WHERE chat_id = %s 
        ORDER BY timestamp ASC
    """, (chat_id,))
    messages = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(messages)

@app.route("/chats/<int:chat_id>/messages", methods=["POST"])
def add_message(chat_id):
    data = request.json
    role = data.get("role")
    content = data.get("content")
    
    if not role or not content:
        return jsonify({"success": False, "error": "Role and content are required"}), 400
    
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO messages (chat_id, role, content)
            VALUES (%s, %s, %s)
        """, (chat_id, role, content))
        conn.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/support-chats", methods=["POST"])
def create_support_chat():
    data = request.json
    user_id = data.get("user_id")
    
    if not user_id:
        return jsonify({"success": False, "error": "User ID is required"}), 400
    
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO support_chats (user_id)
            VALUES (%s)
            RETURNING id
        """, (user_id,))
        chat_id = cursor.fetchone()["id"]
        conn.commit()
        return jsonify({"success": True, "chat_id": chat_id})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/support-chats", methods=["GET"])
def get_support_chats():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT sc.*, u.fullname, u.username 
        FROM support_chats sc
        JOIN users u ON sc.user_id = u.id
        ORDER BY created_at DESC
    """)
    chats = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(chats)

@app.route("/support-messages/<int:chat_id>", methods=["GET"])
def get_support_messages(chat_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT sm.*, u.fullname, u.profile_image
        FROM support_messages sm
        JOIN users u ON sm.user_id = u.id
        WHERE chat_id = %s
        ORDER BY timestamp ASC
    """, (chat_id,))
    messages = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(messages)

@app.route("/support-messages/<int:chat_id>", methods=["POST"])
def add_support_message(chat_id):
    data = request.json
    user_id = data.get("user_id")
    message = data.get("message")
    image_url = data.get("image_url")
    
    if not user_id or (not message and not image_url):
        return jsonify({"success": False, "error": "Invalid data"}), 400
    
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO support_messages (chat_id, user_id, message, image_url)
            VALUES (%s, %s, %s, %s)
        """, (chat_id, user_id, message, image_url))
        conn.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/statistics", methods=["GET"])
def get_statistics():
    conn = get_connection()
    cursor = conn.cursor()
    
    # عدد المستخدمين
    cursor.execute("SELECT COUNT(*) FROM users")
    users_count = cursor.fetchone()['count']
    
    # عدد الأخبار
    cursor.execute("SELECT COUNT(*) FROM news")
    news_count = cursor.fetchone()['count']
    
    # أنواع الأخبار المختلفة
    cursor.execute("SELECT COUNT(DISTINCT type) FROM news")
    news_types = cursor.fetchone()['count']
    
    # المحادثات اليومية
    today = datetime.now().strftime("%Y-%m-%d")
    cursor.execute("SELECT COUNT(*) FROM chats WHERE DATE(created_at) = %s", (today,))
    daily_chats = cursor.fetchone()['count']
    
    # توزيع أنواع الأخبار
    cursor.execute("SELECT type, COUNT(*) as count FROM news GROUP BY type")
    news_distribution = cursor.fetchall()
    news_labels = [item['type'] for item in news_distribution]
    news_values = [item['count'] for item in news_distribution]
    
    # نشاط المستخدمين (آخر 7 أيام)
    days = []
    active_users = []
    for i in range(7):
        date = (datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d")
        cursor.execute("SELECT COUNT(DISTINCT user_id) FROM chats WHERE DATE(created_at) = %s", (date,))
        count = cursor.fetchone()['count']
        days.insert(0, date)
        active_users.insert(0, count)
    
    cursor.close()
    conn.close()
    
    return jsonify({
        "users_count": users_count,
        "news_count": news_count,
        "news_types": news_types,
        "daily_chats": daily_chats,
        "news_distribution": {
            "labels": news_labels,
            "values": news_values
        },
        "user_activity": {
            "days": days,
            "values": active_users
        }
    })

if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)