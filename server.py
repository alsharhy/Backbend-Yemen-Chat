from flask import Flask, request, jsonify
import psycopg2
import hashlib
import os
from flask_cors import CORS
from datetime import datetime

app = Flask(__name__)
CORS(app)

# تحديث هذه القيم لتتناسب مع تفاصيل قاعدة البيانات على Render
DB_HOST = "dpg-d185sp0gjchc73dqaovg-a"  # استبدلها بعنوان الـ host الخاص بك
DB_NAME = "users_db_89cv"  # اسم قاعدة البيانات
DB_USER = "users_db_89cv_user"  # اسم المستخدم
DB_PASSWORD = "kJEaNIbeC9vWcMfGn17rSEDwwV84qKy9"  # كلمة المرور

# دالة لتشفير كلمة المرور
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# تهيئة قاعدة البيانات
def init_db():
    conn = psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        host=DB_HOST
    )
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
            permanently_banned BOOLEAN DEFAULT FALSE
        )
    """)
    conn.commit()
    conn.close()

# باقي التطبيق بدون تغييرات
@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    try:
        conn = psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST
        )
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (fullname, email, username, password)
            VALUES (%s, %s, %s, %s)
        """, (data["fullname"], data["email"], data["username"], hash_password(data["password"])))
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    except psycopg2.IntegrityError:
        return jsonify({"success": False, "error": "اسم المستخدم مستخدم بالفعل"})

# مسار تسجيل الدخول
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    conn = psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        host=DB_HOST
    )
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM users WHERE username = %s AND password = %s
    """, (data["username"], hash_password(data["password"])))
    result = cursor.fetchone()

    if result:
        if result[7]:  # فحص الحظر الدائم
            conn.close()
            return jsonify({"success": False, "error": "تم حظر الحساب بشكل دائم"})
        
        if result[6]:  # فحص الحظر المؤقت
            try:
                banned_until = datetime.strptime(result[6], "%Y-%m-%d %H:%M:%S")
                if banned_until > datetime.now():
                    conn.close()
                    return jsonify({"success": False, "error": "الحساب محظور مؤقتًا حتى " + result[6]})
            except:
                pass
        
        cursor.execute("""
            UPDATE users SET last_login = %s WHERE id = %s
        """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), result[0]))
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    else:
        conn.close()
        return jsonify({"success": False, "error": "بيانات الدخول غير صحيحة"})

# مسار عرض جميع المستخدمين
@app.route("/users", methods=["GET"])
def get_users():
    conn = psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        host=DB_HOST
    )
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    conn.close()
    
    # تحويل النتيجة إلى تنسيق JSON
    users_list = []
    for user in users:
        users_list.append({
            "id": user[0],
            "fullname": user[1],
            "email": user[2],
            "username": user[3],
            "last_login": user[4],
            "banned_until": user[5],
            "permanently_banned": user[6]
        })
    
    return jsonify(users_list)

# مسار تحديث المستخدم
@app.route("/users/<int:user_id>", methods=["GET", "PUT"])
def update_user(user_id):
    conn = psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        host=DB_HOST
    )
    cursor = conn.cursor()

    if request.method == "GET":
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        row = cursor.fetchone()
        if row:
            user = {
                "id": row[0],
                "fullname": row[1],
                "email": row[2],
                "username": row[3],
                "last_login": row[4],
                "banned_until": row[5],
                "permanently_banned": row[6]
            }
            conn.close()
            return jsonify(user)
        else:
            conn.close()
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
            data.get("permanently_banned", False),
            user_id
        ))
        conn.commit()
        conn.close()
        return jsonify({"success": True})

# مسار حذف المستخدم
@app.route("/users/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    conn = psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        host=DB_HOST
    )
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)