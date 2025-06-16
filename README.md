
# Flask User Management API

واجهة خلفية (Back-End) مبنية باستخدام Flask لإدارة المستخدمين. تشمل الميزات:

- تسجيل مستخدمين جدد
- تسجيل الدخول
- حظر مؤقت أو دائم للمستخدمين
- تعديل بيانات المستخدم
- حذف مستخدم
- عرض جميع المستخدمين
- تسجيل آخر وقت دخول

---

## 🔧 التقنيات المستخدمة

- **Flask** – إطار عمل بايثون خفيف
- **SQLite** – قاعدة بيانات مدمجة
- **Flask-CORS** – للسماح بالوصول من الواجهة الأمامية (Frontend)
- **Gunicorn** – خادم WSGI لتشغيل التطبيق على Render

---

## 📁 هيكلية الملفات

flask-backend/ │ ├── app.py               # الملف الرئيسي للسيرفر ├── requirements.txt     # حزم بايثون المطلوبة ├── Procfile             # ملف التشغيل لمنصة Render ├── runtime.txt          # (اختياري) لتحديد إصدار Python ├── .gitignore           # لتجاهل ملفات لا تُرفع مثل users.db └── README.md            # هذا الملف

---

## 🧪 نقاط نهاية الـ API

### ✅ `POST /signup`

تسجيل مستخدم جديد.

**Body:**
```json
{
  "fullname": "الاسم الكامل",
  "email": "example@mail.com",
  "username": "user1",
  "password": "secret"
}

Response:

{ "success": true }

أو في حالة الخطأ:

{ "success": false, "error": "اسم المستخدم مستخدم بالفعل" }


---

✅ POST /login

تسجيل الدخول، مع التحقق من:

صحة البيانات

حالة الحظر (مؤقت أو دائم)


Body:

{
  "username": "user1",
  "password": "secret"
}

Response الناجحة:

{ "success": true }

ردود أخرى حسب الحالة:

بيانات خاطئة

الحساب محظور مؤقتًا

الحساب محظور دائمًا



---

✅ GET /users

جلب جميع المستخدمين (للاستخدام الإداري).

Response:

[
  {
    "id": 1,
    "fullname": "Ahmed Ali",
    "email": "ahmed@example.com",
    "username": "ahmed",
    "last_login": "2025-06-15 14:22:11",
    "banned_until": null,
    "permanently_banned": 0
  },
  ...
]


---

✅ GET /users/<user_id>

جلب بيانات مستخدم معين.

Response:

{
  "id": 1,
  "fullname": "Ahmed Ali",
  ...
}


---

✅ PUT /users/<user_id>

تحديث بيانات مستخدم.

Body:

{
  "fullname": "اسم جديد",
  "email": "new@mail.com",
  "username": "newuser",
  "banned_until": "2025-07-01 12:00:00",   // اختياري
  "permanently_banned": 0                  // 0 أو 1
}

Response:

{ "success": true }


---

✅ DELETE /users/<user_id>

حذف مستخدم.

Response:

{ "success": true }


---

🛡️ ملاحظات أمنية

يتم تشفير كلمات المرور باستخدام SHA-256

يتم تسجيل آخر دخول ناجح في قاعدة البيانات

يتم منع المستخدم من تسجيل الدخول في حالة الحظر (مؤقت أو دائم)



---

🚀 خطوات التشغيل المحلي

pip install -r requirements.txt
python app.py


---

☁️ النشر على Render

الملفات المطلوبة:

requirements.txt

Procfile

runtime.txt (اختياري)

.gitignore (لمنع رفع users.db)


الخطوات:

1. ارفع المشروع إلى GitHub


2. أنشئ Web Service على https://render.com


3. استخدم الإعدادات التالية:



الإعداد	القيمة

Build Command	pip install -r requirements.txt
Start Command	gunicorn app:app
Environment	Python
Branch	main



---

🧠 ملاحظات إضافية

يتم إنشاء قاعدة البيانات تلقائيًا عند التشغيل لأول مرة (init_db()).

في حالة استخدام قاعدة بيانات دائمة على الإنترنت، يمكنك تعديل DB_PATH ليتصل بسيرفر خارجي.



---

📌 المبرمج

تم تطوير هذا المشروع كجزء من تطبيق إدارة مستخدمين باستخدام Python + Flask + SQLite.

---

هل تود أن أرسل لك المشروع كاملاً بصيغة ZIP مع هذا الملف مدمجًا بداخله؟

