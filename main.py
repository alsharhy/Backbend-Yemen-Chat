from flask import Flask, request, jsonify, make_response
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
    
    # حذف جميع المستخدمين الموجودين
    cursor.execute("DROP TABLE IF EXISTS users CASCADE")
    
    # إعادة إنشاء الجدول
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
    
    # تهيئة حساب المسؤول
    cursor.execute("""
        INSERT INTO users (fullname, email, username, password, is_admin)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (username) DO NOTHING
    """, ("Admin User", "admin@example.com", "admin", hash_password("1234"), True))
    
    conn.commit()
    cursor.close()
    conn.close()
    print("تمت إعادة تهيئة قاعدة البيانات وحذف جميع المستخدمين")

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

    # البحث عن المستخدم
    cursor.execute("""
        SELECT * FROM users WHERE username = %s AND password = %s
    """, (username, hash_password(password)))
    result = cursor.fetchone()

    # إذا لم يتم العثور على المستخدم
    if not result:
        cursor.close()
        conn.close()
        return jsonify({"success": False, "error": "بيانات الدخول غير صحيحة"})

    # التحقق من الحظر الدائم
    if result["permanently_banned"]:
        cursor.close()
        conn.close()
        return jsonify({"success": False, "error": "تم حظر الحساب بشكل دائم"})

    # التحقق من الحظر المؤقت
    if result["banned_until"]:
        try:
            banned_until = datetime.strptime(result["banned_until"], "%Y-%m-%d %H:%M:%S")
            if banned_until > datetime.now():
                cursor.close()
                conn.close()
                return jsonify({"success": False, "error": f"الحساب محظور مؤقتًا حتى {result['banned_until']}"})
        except Exception as e:
            print(f"خطأ في معالجة تاريخ الحظر: {e}")

    # تحديث وقت آخر دخول
    cursor.execute("""
        UPDATE users SET last_login = %s WHERE id = %s
    """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), result["id"]))
    conn.commit()
    cursor.close()
    conn.close()

    # تحديد نوع الصفحة المستهدفة بناءً على صلاحية المستخدم
    redirect_to = "admin_dashboard" if result["is_admin"] else "user_dashboard"
    
    return jsonify({
        "success": True,
        "is_admin": result["is_admin"],
        "user_id": result["id"],
        "redirect_to": redirect_to
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

@app.route("/reset-db", methods=["POST"])
def reset_database():
    """إعادة تهيئة قاعدة البيانات وحذف جميع المستخدمين"""
    init_db()
    return jsonify({"success": True, "message": "تمت إعادة تهيئة قاعدة البيانات بنجاح"})

if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)