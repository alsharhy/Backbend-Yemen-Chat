from flask import Flask, request, jsonify, make_response
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime
import hashlib
import os
import logging

app = Flask(__name__)

# تهيئة نظام التسجيل
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
    conn.commit()
    cursor.close()
    conn.close()


@app.route("/signup", methods=["POST", "OPTIONS"])
def signup():
    if request.method == "OPTIONS":
        return jsonify({}), 200
    
    data = request.json
    logger.info(f"طلب تسجيل جديد: {data}")
    
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
    except psycopg2.IntegrityError as e:
        logger.error(f"خطأ في التسجيل: {str(e)}")
        return jsonify({"success": False, "error": "اسم المستخدم مستخدم بالفعل"}), 400
    except Exception as e:
        logger.error(f"خطأ غير متوقع في التسجيل: {str(e)}")
        return jsonify({"success": False, "error": "حدث خطأ في الخادم"}), 500

@app.route("/login", methods=["POST", "OPTIONS"])
def login():
    if request.method == "OPTIONS":
        return jsonify({}), 200
    
    data = request.json
    logger.info(f"طلب تسجيل دخول: {data['username']}")
    
    conn = get_connection()
    cursor = conn.cursor()
    
    # التحقق من حساب الإدمن الخاص
    if data["username"] == "admin" and data["password"] == "1234":
        # إذا كان هناك حساب admin موجود في قاعدة البيانات، نستخدمه. وإلا ننشئه
        cursor.execute("SELECT * FROM users WHERE username = 'admin'")
        admin_user = cursor.fetchone()
        if not admin_user:
            # إنشاء حساب admin إذا لم يكن موجودًا
            cursor.execute("""
                INSERT INTO users (fullname, email, username, password, is_admin)
                VALUES (%s, %s, %s, %s, %s)
            """, ("Admin User", "admin@example.com", "admin", hash_password("1234"), True))
            conn.commit()
            cursor.execute("SELECT * FROM users WHERE username = 'admin'")
            admin_user = cursor.fetchone()
        
        # إرجاع بيانات الإدمن
        response = jsonify({
            "success": True,
            "is_admin": True,
            "user_id": admin_user['id']
        })
        cursor.close()
        conn.close()
        return response
    
    cursor.execute("""
        SELECT * FROM users WHERE username = %s AND password = %s
    """, (data["username"], hash_password(data["password"])))
    result = cursor.fetchone()

    if result:
        if result["permanently_banned"]:
            cursor.close()
            conn.close()
            return jsonify({"success": False, "error": "تم حظر الحساب بشكل دائم"}), 403

        if result["banned_until"]:
            try:
                banned_until = datetime.strptime(result["banned_until"], "%Y-%m-%d %H:%M:%S")
                if banned_until > datetime.now():
                    cursor.close()
                    conn.close()
                    return jsonify({"success": False, "error": "الحساب محظور مؤقتًا حتى " + result["banned_until"]}), 403
            except Exception as e:
                logger.error(f"خطأ في معالجة وقت الحظر: {str(e)}")
                # تجاهل الخطأ ومتابعة العملية

        cursor.execute("""
            UPDATE users SET last_login = %s WHERE id = %s
        """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), result["id"]))
        conn.commit()
        
        response = jsonify({
            "success": True,
            "is_admin": result['is_admin'],
            "user_id": result["id"]
        })
        cursor.close()
        conn.close()
        return response
    else:
        cursor.close()
        conn.close()
        return jsonify({"success": False, "error": "بيانات الدخول غير صحيحة"}), 401

@app.route("/users", methods=["GET", "OPTIONS"])
def get_users():
    if request.method == "OPTIONS":
        return jsonify({}), 200
    
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(users)

@app.route("/users/<int:user_id>", methods=["GET", "PUT", "DELETE", "OPTIONS"])
def user_operations(user_id):
    if request.method == "OPTIONS":
        return jsonify({}), 200
    
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

@app.route("/users/<int:user_id>/admin", methods=["POST", "OPTIONS"])
def toggle_admin(user_id):
    if request.method == "OPTIONS":
        return jsonify({}), 200
    
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT is_admin FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    if not user:
        return jsonify({"success": False, "error": "المستخدم غير موجود"}), 404
        
    current_status = user["is_admin"]
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

if __name__ == "__main__":
    logger.info("جارٍ تهيئة قاعدة البيانات...")
    init_db()
    logger.info("بدء تشغيل الخادم...")
    app.run(debug=True, host="0.0.0.0", port=5000)