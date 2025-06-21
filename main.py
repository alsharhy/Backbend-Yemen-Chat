from flask import Flask, request, jsonify, make_response, send_from_directory
import psycopg2
from psycopg2.extras import RealDictCursor
from flask_cors import CORS
from datetime import datetime, timedelta
import hashlib
import os
import uuid
import jwt
from functools import wraps

app = Flask(__name__)
CORS(app)

# Load configuration from environment variables
DATABASE_URL = os.environ.get("DATABASE_URL")
SECRET_KEY = os.environ.get("SECRET_KEY", "your-secret-key-here")
API_KEY = os.environ.get("DEFAULT_API_KEY", "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")
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_connection():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    
    # Create users table
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
            profile_image TEXT,
            api_key TEXT
        )
    """)
    
    # Create news table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS news (
            id SERIAL PRIMARY KEY,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            image_url TEXT,
            status TEXT NOT NULL,
            type TEXT DEFAULT 'خبر',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Create site settings table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS site_settings (
            id SERIAL PRIMARY KEY,
            site_name TEXT NOT NULL,
            site_description TEXT NOT NULL,
            primary_color TEXT NOT NULL,
            site_status TEXT NOT NULL,
            api_key TEXT NOT NULL
        )
    """)
    
    # Create chat messages table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS chat_messages (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            response_time FLOAT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Create support chats table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS support_chats (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            status TEXT DEFAULT 'open',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Create support messages table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS support_messages (
            id SERIAL PRIMARY KEY,
            chat_id INTEGER REFERENCES support_chats(id),
            user_id INTEGER REFERENCES users(id),
            message TEXT,
            image_url TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Initialize admin user
    cursor.execute("""
        INSERT INTO users (fullname, email, username, password, is_admin, profile_image, api_key)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (username) DO NOTHING
    """, (
        "Admin User", 
        "admin@example.com", 
        "admin", 
        hash_password("1234"), 
        True, 
        "https://ui-avatars.com/api/?name=Admin+User&background=3498db&color=fff",
        API_KEY
    ))
    
    # Initialize site settings
    cursor.execute("""
        INSERT INTO site_settings (site_name, site_description, primary_color, site_status, api_key)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (id) DO NOTHING
    """, (
        "مساعد الذكاء الاصطناعي",
        "موقع متطور للذكاء الاصطناعي يساعدك في العديد من المهام اليومية والبرمجية",
        "#128c7e",
        "open",
        API_KEY
    ))
    
    conn.commit()
    cursor.close()
    conn.close()
    print("تمت تهيئة قاعدة البيانات")

# Authentication decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"error": "Token is missing"}), 401
            
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            if not data.get('is_admin'):
                return jsonify({"error": "Admin access required"}), 403
        except:
            return jsonify({"error": "Invalid token"}), 401
            
        return f(*args, **kwargs)
    return decorated_function

@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        # Check if username or email already exists
        cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", 
                      (data["username"], data["email"]))
        existing_user = cursor.fetchone()
        
        if existing_user:
            if existing_user["username"] == data["username"]:
                return jsonify({"success": False, "error": "اسم المستخدم مستخدم بالفعل"})
            else:
                return jsonify({"success": False, "error": "البريد الإلكتروني مستخدم بالفعل"})
        
        # Get default API key from site settings
        cursor.execute("SELECT api_key FROM site_settings LIMIT 1")
        site_settings = cursor.fetchone()
        default_api_key = site_settings["api_key"] if site_settings else API_KEY
        
        # Create new user
        cursor.execute("""
            INSERT INTO users (fullname, email, username, password, profile_image, api_key)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            data["fullname"],
            data["email"],
            data["username"],
            hash_password(data["password"]),
            f"https://ui-avatars.com/api/?name={data['fullname']}&background=3498db&color=fff",
            default_api_key
        ))
        
        conn.commit()
        return jsonify({
            "success": True,
            "message": "تم إنشاء الحساب بنجاح! يمكنك الآن تسجيل الدخول"
        })
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
    user = cursor.fetchone()

    if not user:
        cursor.close()
        conn.close()
        return jsonify({"success": False, "error": "بيانات الدخول غير صحيحة"})

    # Check if user is banned
    if user["permanently_banned"]:
        cursor.close()
        conn.close()
        return jsonify({"success": False, "error": "تم حظر الحساب بشكل دائم"})

    if user["banned_until"]:
        try:
            banned_until = datetime.strptime(user["banned_until"], "%Y-%m-%d %H:%M:%S")
            if banned_until > datetime.now():
                remaining = banned_until - datetime.now()
                hours = int(remaining.total_seconds() / 3600)
                cursor.close()
                conn.close()
                return jsonify({
                    "success": False, 
                    "error": f"الحساب محظور مؤقتًا لمدة {hours} ساعة"
                })
        except Exception as e:
            print(f"خطأ في معالجة تاريخ الحظر: {e}")

    # Update last login
    cursor.execute("""
        UPDATE users SET last_login = %s WHERE id = %s
    """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), user["id"]))
    conn.commit()
    
    # Generate JWT token
    token = jwt.encode({
        'user_id': user["id"],
        'username': user["username"],
        'is_admin': user["is_admin"],
        'exp': datetime.utcnow() + timedelta(days=7)
    }, SECRET_KEY, algorithm="HS256")

    return jsonify({
        "success": True,
        "token": token,
        "is_admin": user["is_admin"],
        "user_id": user["id"],
        "fullname": user["fullname"],
        "username": user["username"],
        "email": user["email"],
        "profile_image": user["profile_image"],
        "api_key": user["api_key"],
        "message": "مرحبًا بك! جاري تحميل لوحة التحكم..." if user["is_admin"] else "تم تسجيل الدخول بنجاح!"
    })

@app.route("/users", methods=["GET"])
@admin_required
def get_users():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, fullname, username, email, last_login, banned_until, permanently_banned, is_admin FROM users")
    users = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(users)

@app.route("/users/<int:user_id>", methods=["GET", "PUT", "DELETE"])
@admin_required
def user_operations(user_id):
    conn = get_connection()
    cursor = conn.cursor()

    if request.method == "GET":
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        cursor.close()
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
        cursor.close()
        conn.close()
        return jsonify({"success": True, "message": "تم تحديث بيانات المستخدم بنجاح"})

    elif request.method == "DELETE":
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"success": True, "message": "تم حذف المستخدم بنجاح"})

@app.route("/users/<int:user_id>/admin", methods=["POST"])
@admin_required
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
                INSERT INTO news (title, content, image_url, status, type)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                data["title"],
                data["content"],
                data.get("image_url", ""),
                data["status"],
                data.get("type", "خبر")
            ))
            conn.commit()
            cursor.close()
            conn.close()
            return jsonify({"success": True, "message": "تم إضافة الخبر بنجاح"})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)})

@app.route("/news/<int:news_id>", methods=["DELETE", "PUT"])
@admin_required
def single_news_operations(news_id):
    conn = get_connection()
    cursor = conn.cursor()
    
    if request.method == "DELETE":
        cursor.execute("DELETE FROM news WHERE id = %s", (news_id,))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"success": True, "message": "تم حذف الخبر بنجاح"})
    
    elif request.method == "PUT":
        data = request.json
        cursor.execute("""
            UPDATE news
            SET title = %s, content = %s, image_url = %s, status = %s, type = %s
            WHERE id = %s
        """, (
            data["title"],
            data["content"],
            data["image_url"],
            data["status"],
            data.get("type", "خبر"),
            news_id
        ))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"success": True, "message": "تم تحديث الخبر بنجاح"})

@app.route("/update-profile", methods=["POST"])
def update_profile():
    # Handle file upload
    if 'profile_image' in request.files:
        file = request.files['profile_image']
        if file.filename != '' and allowed_file(file.filename):
            filename = f"{uuid.uuid4().hex}.{file.filename.rsplit('.', 1)[1].lower()}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            profile_image = f"/uploads/{filename}"
        else:
            return jsonify({"success": False, "error": "صيغة الملف غير مسموح بها"})
    else:
        profile_image = request.form.get('profile_image') or None

    # Get form data
    user_id = request.form.get('user_id')
    fullname = request.form.get('fullname')
    email = request.form.get('email')
    username = request.form.get('username')
    api_key = request.form.get('api_key')
    
    if not user_id:
        return jsonify({"success": False, "error": "User ID missing"}), 400
    
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        # Check if username or email already exists
        cursor.execute("""
            SELECT * FROM users 
            WHERE (username = %s OR email = %s) 
            AND id != %s
        """, (username, email, user_id))
        
        existing_user = cursor.fetchone()
        
        if existing_user:
            if existing_user["username"] == username:
                return jsonify({"success": False, "error": "اسم المستخدم مستخدم بالفعل"})
            else:
                return jsonify({"success": False, "error": "البريد الإلكتروني مستخدم بالفعل"})
        
        # Update user profile
        update_query = """
            UPDATE users
            SET fullname = %s, email = %s, username = %s
        """
        params = [fullname, email, username]
        
        if profile_image:
            update_query += ", profile_image = %s"
            params.append(profile_image)
            
        if api_key:
            update_query += ", api_key = %s"
            params.append(api_key)
            
        update_query += " WHERE id = %s"
        params.append(user_id)
        
        cursor.execute(update_query, tuple(params))
        conn.commit()
        
        # Get updated user data
        cursor.execute("""
            SELECT fullname, username, email, profile_image, api_key
            FROM users 
            WHERE id = %s
        """, (user_id,))
        updated_user = cursor.fetchone()
        
        return jsonify({
            "success": True,
            "message": "تم تحديث الملف الشخصي بنجاح",
            "fullname": updated_user["fullname"],
            "username": updated_user["username"],
            "email": updated_user["email"],
            "profile_image": updated_user["profile_image"],
            "api_key": updated_user["api_key"]
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route("/user/<int:user_id>", methods=["GET"])
def get_user_profile(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT id, fullname, username, email, profile_image, is_admin, api_key
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

@app.route("/settings", methods=["GET", "POST"])
def site_settings():
    conn = get_connection()
    cursor = conn.cursor()
    
    if request.method == "GET":
        cursor.execute("SELECT * FROM site_settings LIMIT 1")
        settings = cursor.fetchone()
        
        if not settings:
            # Create default settings if not exists
            cursor.execute("""
                INSERT INTO site_settings 
                (site_name, site_description, primary_color, site_status, api_key)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING *
            """, (
                "مساعد الذكاء الاصطناعي",
                "موقع متطور للذكاء الاصطناعي يساعدك في العديد من المهام اليومية والبرمجية",
                "#128c7e",
                "open",
                API_KEY
            ))
            settings = cursor.fetchone()
            conn.commit()
        
        cursor.close()
        conn.close()
        return jsonify(settings)
    
    elif request.method == "POST":
        data = request.json
        cursor.execute("""
            UPDATE site_settings SET
            site_name = %s,
            site_description = %s,
            primary_color = %s,
            site_status = %s
            WHERE id = 1
            RETURNING *
        """, (
            data.get("site_name"),
            data.get("site_description"),
            data.get("primary_color"),
            data.get("site_status")
        ))
        
        updated_settings = cursor.fetchone()
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "message": "تم تحديث إعدادات الموقع بنجاح",
            "settings": updated_settings
        })

@app.route("/settings/api", methods=["POST"])
@admin_required
def update_api_key():
    data = request.json
    if not data.get("api_key"):
        return jsonify({"success": False, "error": "مطلوب مفتاح API"})
    
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        # Update site settings with new API key
        cursor.execute("""
            UPDATE site_settings SET
            api_key = %s
            WHERE id = 1
        """, (data["api_key"],))
        
        # Update API key for all users
        cursor.execute("""
            UPDATE users SET
            api_key = %s
        """, (data["api_key"],))
        
        conn.commit()
        return jsonify({
            "success": True,
            "message": "تم تحديث مفتاح API بنجاح لجميع المستخدمين"
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})
    finally:
        cursor.close()
        conn.close()

@app.route("/statistics", methods=["GET"])
@admin_required
def get_statistics():
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        # User statistics
        cursor.execute("SELECT COUNT(*) as users_count FROM users")
        users_count = cursor.fetchone()["users_count"]
        
        # Active users today
        cursor.execute("""
            SELECT COUNT(*) as active_users FROM users 
            WHERE last_login >= CURRENT_DATE
        """)
        active_users = cursor.fetchone()["active_users"]
        
        # Daily chats
        cursor.execute("""
            SELECT COUNT(*) as daily_chats FROM chat_messages
            WHERE created_at >= CURRENT_DATE
        """)
        daily_chats = cursor.fetchone()["daily_chats"]
        
        # Average response time
        cursor.execute("""
            SELECT AVG(response_time) as avg_response_time FROM chat_messages
            WHERE response_time IS NOT NULL
        """)
        avg_response = round(float(cursor.fetchone()["avg_response_time"] or 0), 2)
        
        # User activity last 7 days
        cursor.execute("""
            SELECT 
                TO_CHAR(date_series, 'YYYY-MM-DD') as day,
                COUNT(DISTINCT u.id) as active_users
            FROM 
                generate_series(CURRENT_DATE - 6, CURRENT_DATE, interval '1 day') as date_series
            LEFT JOIN users u ON DATE(u.last_login) = date_series
            GROUP BY date_series
            ORDER BY date_series
        """)
        activity_data = cursor.fetchall()
        
        # User distribution by activity level
        cursor.execute("""
            SELECT 
                CASE 
                    WHEN last_login >= CURRENT_DATE THEN 'نشط اليوم'
                    WHEN last_login >= CURRENT_DATE - 7 THEN 'نشط هذا الأسبوع'
                    WHEN last_login >= CURRENT_DATE - 30 THEN 'نشط هذا الشهر'
                    WHEN last_login IS NULL THEN 'لم يسجل دخول'
                    ELSE 'غير نشط'
                END as activity_level,
                COUNT(*) as users_count
            FROM users
            GROUP BY activity_level
        """)
        distribution_data = cursor.fetchall()
        
        # News statistics
        cursor.execute("SELECT COUNT(*) as news_count FROM news")
        news_count = cursor.fetchone()["news_count"]
        
        cursor.execute("SELECT COUNT(DISTINCT type) as news_types FROM news")
        news_types = cursor.fetchone()["news_types"]
        
        # Calculate trends (simplified for demo)
        cursor.execute("""
            SELECT 
                COUNT(*) as prev_month_users,
                (SELECT COUNT(*) FROM users WHERE last_login >= CURRENT_DATE - 30) as active_month_users
            FROM users
            WHERE created_at >= CURRENT_DATE - 60 AND created_at < CURRENT_DATE - 30
        """)
        trends = cursor.fetchone()
        users_trend = 12  # Simplified trend calculation
        
        return jsonify({
            "users_count": users_count,
            "active_users": active_users,
            "daily_chats": daily_chats,
            "avg_response_time": avg_response,
            "news_count": news_count,
            "news_types": news_types,
            "users_trend": users_trend,
            "active_trend": 8,
            "chats_trend": -5,
            "user_activity": {
                "days": [item["day"] for item in activity_data],
                "values": [item["active_users"] for item in activity_data]
            },
            "users_distribution": {
                "labels": [item["activity_level"] for item in distribution_data],
                "values": [item["users_count"] for item in distribution_data]
            }
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()
        
        
@app.route("/support-chats", methods=["GET"])
@admin_required
def get_support_chats():
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT sc.id, sc.status, sc.created_at, 
                   u.id as user_id, u.fullname, u.username, u.profile_image
            FROM support_chats sc
            JOIN users u ON sc.user_id = u.id
            ORDER BY sc.created_at DESC
        """)
        chats = cursor.fetchall()
        return jsonify(chats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/support-messages/<int:chat_id>", methods=["GET"])
def get_support_messages(chat_id):
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT sm.*, u.fullname, u.profile_image
            FROM support_messages sm
            JOIN users u ON sm.user_id = u.id
            WHERE sm.chat_id = %s
            ORDER BY sm.created_at ASC
        """, (chat_id,))
        messages = cursor.fetchall()
        return jsonify(messages)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/support-messages/<int:chat_id>", methods=["POST"])
def add_support_message(chat_id):
    data = request.json
    user_id = data.get("user_id")
    
    if not user_id:
        return jsonify({"success": False, "error": "User ID missing"}), 400
    
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            INSERT INTO support_messages (chat_id, user_id, message, image_url)
            VALUES (%s, %s, %s, %s)
            RETURNING *
        """, (
            chat_id,
            user_id,
            data.get("message", ""),
            data.get("image_url", "")
        ))
        
        message = cursor.fetchone()
        conn.commit()
        return jsonify({
            "success": True,
            "message": "تم إرسال الرسالة بنجاح",
            "data": message
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)