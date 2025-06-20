from flask import Flask, request, jsonify, make_response
import psycopg2
from psycopg2.extras import RealDictCursor
from flask_cors import CORS
from datetime import datetime
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
            is_admin BOOLEAN DEFAULT FALSE,
            profile_image TEXT
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
    
    # تهيئة حساب المسؤول
    cursor.execute("""
        INSERT INTO users (fullname, email, username, password, is_admin, profile_image)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (username) DO NOTHING
    """, ("Admin User", "admin@example.com", "admin", hash_password("1234"), True, "https://ui-avatars.com/api/?name=Admin+User&background=3498db&color=fff"))
    
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
        
        # التحقق من عدم وجود نفس اسم المستخدم أو البريد الإلكتروني
        cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", 
                      (data["username"], data["email"]))
        existing_user = cursor.fetchone()
        
        if existing_user:
            if existing_user["username"] == data["username"]:
                return jsonify({"success": False, "error": "اسم المستخدم مستخدم بالفعل"})
            else:
                return jsonify({"success": False, "error": "البريد الإلكتروني مستخدم بالفعل"})
        
        cursor.execute("""
            INSERT INTO users (fullname, email, username, password, profile_image)
            VALUES (%s, %s, %s, %s, %s)
        """, (data["fullname"], data["email"], data["username"], 
              hash_password(data["password"]),
              f"https://ui-avatars.com/api/?name={data['fullname']}&background=3498db&color=fff"))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"success": True})
    except psycopg2.IntegrityError as e:
        return jsonify({"success": False, "error": "خطأ في إنشاء الحساب: " + str(e)})

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
        "fullname": result["fullname"],
        "username": result["username"],
        "email": result["email"],
        "profile_image": result["profile_image"],
        "redirect_to": "admin_dashboard" if result["is_admin"] else "user_dashboard"
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
        # التحقق من عدم وجود نفس اسم المستخدم أو البريد الإلكتروني
        cursor.execute("""
            SELECT * FROM users 
            WHERE (username = %s OR email = %s) 
            AND id != %s
        """, (data["username"], data["email"], user_id))
        
        existing_user = cursor.fetchone()
        
        if existing_user:
            if existing_user["username"] == data["username"]:
                return jsonify({"success": False, "error": "اسم المستخدم مستخدم بالفعل"})
            else:
                return jsonify({"success": False, "error": "البريد الإلكتروني مستخدم بالفعل"})
        
        # تحديث بيانات المستخدم
        cursor.execute("""
            UPDATE users
            SET fullname = %s, email = %s, username = %s, profile_image = %s
            WHERE id = %s
        """, (
            data["fullname"],
            data["email"],
            data["username"],
            data["profile_image"],
            user_id
        ))
        
        conn.commit()
        return jsonify({
            "success": True,
            "fullname": data["fullname"],
            "username": data["username"],
            "email": data["email"],
            "profile_image": data["profile_image"]
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})
    finally:
        cursor.close()
        conn.close()

@app.route("/user/<int:user_id>", methods=["GET"])
def get_user_profile(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT id, fullname, username, email, profile_image, is_admin
            FROM users 
            WHERE id = %s
        """, (user_id,))
        
        user = cursor.fetchone()
        if not user:
            return jsonify({"error": "المستخدم غير موجود"}), 404
        
        return jsonify(user)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)