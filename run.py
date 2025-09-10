from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient, errors
from dotenv import load_dotenv
import os, bcrypt, jwt, datetime, secrets
from bson.objectid import ObjectId

# ----------------- Load env -----------------
load_dotenv()
MONGO_URI = os.getenv("MONGO_URI")
SECRET_KEY = os.getenv("SECRET_KEY")
ADMIN_EMAILS = ["admin@iar.com", "head@iar.com"]  # Admin emails
ADMIN_PASSWORD = "admin123"  # default admin password

# ----------------- Flask app -----------------
app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
CORS(app, supports_credentials=True)

# ----------------- MongoDB connection -----------------
try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=10000)
    client.admin.command("ping")
    db = client.get_database()
    users_col = db["users"]
    timetable_col = db["timetable"]
    sessions_col = db["sessions"]
    attendance_col = db["attendance"]
    print("✅ MongoDB connected successfully")
except errors.ServerSelectionTimeoutError as e:
    print("❌ MongoDB connection error:", e)
    users_col = timetable_col = sessions_col = attendance_col = None

# ----------------- Auto-create admin -----------------
for admin_email in ADMIN_EMAILS:
    if not users_col.find_one({"email": admin_email}):
        hashed_pw = bcrypt.hashpw(ADMIN_PASSWORD.encode("utf-8"), bcrypt.gensalt())
        users_col.insert_one({
            "name": "Super Admin",
            "email": admin_email,
            "password": hashed_pw,
            "role": "admin"
        })
        print(f"✅ Admin created: {admin_email} / {ADMIN_PASSWORD}")

# ----------------- Predefined Faculty -----------------
faculty_email = "hod@iar.com"
if not users_col.find_one({"email": faculty_email}):
    hashed_pw = bcrypt.hashpw("hod123".encode("utf-8"), bcrypt.gensalt())
    users_col.insert_one({
        "name": "HOD",
        "email": faculty_email,
        "password": hashed_pw,
        "role": "faculty"
    })
print("✅ Faculty created:", faculty_email)

# ----------------- Predefined Students -----------------
for i in range(1, 11):
    email = f"student{i}@iar.com"
    password = f"student{i}"
    if not users_col.find_one({"email": email}):
        hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        users_col.insert_one({
            "name": f"Student {i}",
            "email": email,
            "password": hashed_pw,
            "role": "student",
            "extra_info": {"branch": "BTech(AI)", "semester": 5}
        })
print("✅ 10 Students created for BTech(AI)")

# ----------------- Predefined Lectures -----------------
lectures_data = [
    {
        "branchCode": "BBA",
        "semester": "2",
        "lectures": {"Monday": {"09:00-10:00": {"id": "lec1", "subject": "Management 101", "isLive": False}}}
    },
    {
        "branchCode": "BTech IT",
        "semester": "5",
        "lectures": {"Tuesday": {"10:00-11:00": {"id": "lec2", "subject": "Data Structures", "isLive": False}}}
    },
    {
        "branchCode": "BTech(AI)",
        "semester": "5",
        "lectures": {"Wednesday": {"11:00-12:00": {"id": "lec3", "subject": "AI Basics", "isLive": False}}}
    }
]
for lec in lectures_data:
    timetable_col.update_one(
        {"branchCode": lec["branchCode"], "semester": lec["semester"]},
        {"$set": {"lectures": lec["lectures"]}},
        upsert=True
    )
print("✅ 3 predefined lectures added")

# ----------------- Utility Functions -----------------
def _generate_token_and_expiry(ttl_seconds=45):
    token = secrets.token_urlsafe(16)
    expiry = datetime.datetime.utcnow() + datetime.timedelta(seconds=ttl_seconds)
    return token, expiry

# ----------------- Routes -----------------
@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Backend is running"}), 200

# ---------- Login ----------
@app.route("/api/login", methods=["POST"])
def login():
    try:
        data = request.json
        email = data.get("email")
        password = data.get("password")
        user = users_col.find_one({"email": email})
        if not user: return jsonify({"error": "User not found"}), 404
        if not bcrypt.checkpw(password.encode("utf-8"), user["password"]):
            return jsonify({"error": "Invalid password"}), 401
        token = jwt.encode(
            {"email": user["email"], "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
            app.config["SECRET_KEY"],
            algorithm="HS256"
        )
        if isinstance(token, bytes): token = token.decode("utf-8")
        user_data = {"name": user.get("name"), "email": user.get("email"), "role": user.get("role", "student")}
        return jsonify({"user": user_data, "token": token}), 200
    except Exception as e:
        print("❌ Login error:", e)
        return jsonify({"error": "Internal server error"}), 500

# ---------- Enroll User (Admin only) ----------
@app.route("/api/enroll", methods=["POST"])
def enroll_user():
    try:
        data = request.json
        admin_email = data.get("admin_email")
        if admin_email not in ADMIN_EMAILS: return jsonify({"error": "Unauthorized"}), 403
        name = data.get("name")
        email = data.get("email")
        password = data.get("password")
        role = data.get("role")
        extra_info = data.get("extra_info", {})
        if not name or not email or not password or not role: return jsonify({"error": "Missing required fields"}), 400
        if users_col.find_one({"email": email}): return jsonify({"error": "User already exists"}), 400
        hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        users_col.insert_one({"name": name, "email": email, "password": hashed_pw, "role": role, "extra_info": extra_info})
        return jsonify({"message": f"{role} created successfully"}), 201
    except Exception as e:
        print("❌ Enroll error:", e)
        return jsonify({"error": "Internal server error"}), 500

# ---------- Timetable routes ----------
@app.route("/api/timetables", methods=["GET"])
def get_all_timetables():
    try:
        timetables = list(timetable_col.find({}, {"_id": 0}))
        for t in timetables:
            lectures = t.get("lectures", {})
            for day, slots in lectures.items():
                for slot, lec in slots.items():
                    if "isLive" not in lec: lec["isLive"] = False
        return jsonify(timetables), 200
    except Exception as e:
        print("❌ Get all timetables error:", e)
        return jsonify({"error": "Internal server error"}), 500

@app.route("/api/timetable/<branch>/<semester>", methods=["GET"])
def get_timetable_by_branch_sem(branch, semester):
    try:
        timetable = timetable_col.find_one({"branchCode": {"$regex": f"^{branch}$", "$options": "i"}, "semester": str(semester)}, {"_id": 0})
        if not timetable: return jsonify({"error": "Timetable not found"}), 404
        return jsonify(timetable), 200
    except Exception as e:
        print("❌ Get timetable error:", e)
        return jsonify({"error": "Internal server error"}), 500

@app.route("/api/timetable/<branch>/<semester>/live", methods=["PATCH"])
def set_live_lecture(branch, semester):
    data = request.json
    lecture_id = data.get("lectureId")
    if not lecture_id: return jsonify({"error": "Missing lectureId"}), 400
    timetable = timetable_col.find_one({"branchCode": branch, "semester": semester})
    if not timetable: return jsonify({"error": "Timetable not found"}), 404
    lectures = timetable.get("lectures", {})
    for day, slots in lectures.items():
        for slot, lec in slots.items():
            lec["isLive"] = (lec.get("id") == lecture_id)
    timetable_col.update_one({"branchCode": branch, "semester": semester}, {"$set": {"lectures": lectures}})
    return jsonify({"message": "Lecture live status updated"}), 200

@app.route("/api/timetable", methods=["POST"])
def create_or_update_timetable():
    try:
        data = request.json
        user_email = request.headers.get("X-User-Email")
        user_role = request.headers.get("role")
        if not user_email or not user_role or user_role != "admin": return jsonify({"error": "Unauthorized"}), 403
        branch = data.get("branchCode", "").strip()
        semester = str(data.get("semester", "")).strip()
        lectures = data.get("lectures")
        if not branch or not semester or not lectures: return jsonify({"error": "Missing required fields"}), 400
        if not users_col.find_one({"email": user_email, "role": "admin"}): return jsonify({"error": "Unauthorized"}), 403
        timetable_col.update_one({"branchCode": branch, "semester": semester}, {"$set": {"lectures": lectures}}, upsert=True)
        return jsonify({"message": "Timetable saved successfully"}), 201
    except Exception as e:
        print("❌ Create/Update timetable error:", e)
        return jsonify({"error": "Internal server error"}), 500

# ---------- Users ----------
@app.route("/api/users", methods=["GET"])
def get_users():
    try:
        users = list(users_col.find({}, {"_id": 0, "password": 0}))
        return jsonify(users), 200
    except Exception as e:
        print("❌ Get users error:", e)
        return jsonify({"error": "Internal server error"}), 500

# ---------- Sessions ----------
@app.route("/api/session/create", methods=["POST"])
def create_session():
    try:
        data = request.json or {}
        faculty_email = data.get("faculty_email") or request.headers.get("X-User-Email")
        if not faculty_email: return jsonify({"error": "Missing faculty email"}), 400
        user = users_col.find_one({"email": faculty_email})
        if not user or user.get("role") not in ("faculty", "admin"): return jsonify({"error": "Unauthorized"}), 403
        session_id = data.get("sessionId") or secrets.token_urlsafe(8)
        token, expiry = _generate_token_and_expiry(45)
        sessions_col.insert_one({
            "sessionId": session_id,
            "faculty_email": faculty_email,
            "meta": data.get("meta", {}),
            "active": True,
            "current_token": token,
            "token_expiry": expiry,
            "created_at": datetime.datetime.utcnow()
        })
        return jsonify({"sessionId": session_id, "token": token, "token_expiry": expiry.isoformat()}), 201
    except Exception as e:
        print("❌ Create session error:", e)
        return jsonify({"error": "Internal server error"}), 500

@app.route("/api/session/<sessionId>/token", methods=["GET"])
def get_session_token(sessionId):
    try:
        caller = request.headers.get("X-User-Email")
        if not caller: return jsonify({"error": "Missing caller email header"}), 400
        session = sessions_col.find_one({"sessionId": sessionId})
        if not session: return jsonify({"error": "Session not found"}), 404
        if caller != session.get("faculty_email") and caller not in ADMIN_EMAILS: return jsonify({"error": "Unauthorized"}), 403
        now = datetime.datetime.utcnow()
        token = session.get("current_token")
        expiry = session.get("token_expiry")
        if not token or not expiry or expiry <= now:
            token, new_expiry = _generate_token_and_expiry(45)
            sessions_col.update_one({"sessionId": sessionId}, {"$set": {"current_token": token, "token_expiry": new_expiry}})
            expiry = new_expiry
        return jsonify({"sessionId": sessionId, "token": token, "token_expiry": expiry.isoformat()}), 200
    except Exception as e:
        print("❌ Get token error:", e)
        return jsonify({"error": "Internal server error"}), 500

# ---------- Attendance ----------
@app.route("/api/attendance/<student_email>", methods=["GET"])
def get_attendance(student_email):
    try:
        student = users_col.find_one({"email": student_email})
        if not student or student.get("role") != "student": return jsonify({"error": "Student not found"}), 404
        records = list(attendance_col.find({"student_email": student_email}, {"_id": 0}))
        return jsonify(records), 200
    except Exception as e:
        print("❌ Get attendance error:", e)
        return jsonify({"error": "Internal server error"}), 500

@app.route("/api/attendance/scan", methods=["POST"])
def attendance_scan():
    try:
        data = request.json or {}
        qr_value = data.get("qrValue")
        student_email = request.headers.get("X-User-Email") or data.get("student_email")
        if not qr_value or not student_email: return jsonify({"error": "Missing qrValue or student email"}), 400
        parts = qr_value.split("::")
        if len(parts) != 2: return jsonify({"error": "Invalid QR format"}), 400
        sessionId, token = parts[0], parts[1]
        session = sessions_col.find_one({"sessionId": sessionId, "active": True})
        if not session: return jsonify({"error": "Session not active or not found"}), 404
        now = datetime.datetime.utcnow()
        if not session.get("current_token") or session.get("token_expiry") <= now:
            return jsonify({"error": "Token expired"}), 400
        if token != session.get("current_token"): return jsonify({"error": "Invalid or outdated token"}), 400
        student = users_col.find_one({"email": student_email})
        if not student or student.get("role") != "student": return jsonify({"error": "Student not found or unauthorized"}), 403
        already = attendance_col.find_one({"sessionId": sessionId, "student_email": student_email})
        if already: return jsonify({"message": "Attendance already recorded"}), 200
        attendance_col.insert_one({"sessionId": sessionId, "student_email": student_email, "timestamp": now})
        return jsonify({"message": "Attendance marked"}), 201
    except Exception as e:
        print("❌ Attendance scan error:", e)
        return jsonify({"error": "Internal server error"}), 500

# ----------------- Run -----------------
if __name__ == "__main__":
    app.run(debug=True, port=5000)
