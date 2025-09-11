from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from dotenv import load_dotenv
import os, bcrypt, jwt, datetime, certifi
import secrets
from bson.objectid import ObjectId
import re

# ----------------- Load env -----------------
load_dotenv()
MONGO_URI = os.getenv("MONGO_URI")
SECRET_KEY = os.getenv("SECRET_KEY")
ADMIN_EMAILS = ["admin@iar.com", "head@iar.com"]  # Admin emails
ADMIN_PASSWORD = "admin123"  # default admin password

# ----------------- Flask app -----------------
app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
# This allows any frontend origin (quick fix)
CORS(app, supports_credentials=True)

# ----------------- MongoDB connection -----------------
try:
    client = MongoClient(
        MONGO_URI,
        serverSelectionTimeoutMS=10000,  # 10 second timeout
        tlsCAFile=certifi.where()
    )
    # Test the connection
    client.admin.command("ping")
    
    # Define collections
    db = client.get_database()  # Default DB from URI
    users_col = db["users"]
    timetable_col = db["timetable"]
    sessions_col = db["sessions"]
    attendance_col = db["attendance"]

    print("✅ MongoDB connected successfully")
except Exception as e:
    print("❌ MongoDB connection error:", e)
    # Define collections as None to prevent NameError
    users_col = timetable_col = sessions_col = attendance_col = None


# ----------------- Auto-create admin if not exists -----------------
for admin_email in ADMIN_EMAILS:
    if users_col and not users_col.find_one({"email": admin_email}):
        hashed_pw = bcrypt.hashpw(ADMIN_PASSWORD.encode("utf-8"), bcrypt.gensalt())
        users_col.insert_one({
            "name": "Super Admin",
            "email": admin_email,
            "password": hashed_pw,
            "role": "admin"
        })
        print(f"✅ Admin created: {admin_email} / {ADMIN_PASSWORD}")

# ----------------- Helper Functions -----------------
def normalize_string(text):
    """Normalize string for comparison"""
    if not text:
        return ""
    return str(text).strip().lower()

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
        if not user:
            return jsonify({"error": "User not found"}), 404

        if not bcrypt.checkpw(password.encode("utf-8"), user["password"]):
            return jsonify({"error": "Invalid password"}), 401

        token = jwt.encode(
            {"email": user["email"], "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
            app.config["SECRET_KEY"],
            algorithm="HS256"
        )
        if isinstance(token, bytes):
            token = token.decode("utf-8")

        user_data = {
            "name": user.get("name"),
            "email": user.get("email"),
            "role": user.get("role", "student"),
            "extra_info": user.get("extra_info", {})
        }

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
        if admin_email not in ADMIN_EMAILS:
            return jsonify({"error": "Unauthorized"}), 403

        name = data.get("name")
        email = data.get("email")
        password = data.get("password")
        role = data.get("role")  # student or faculty
        extra_info = data.get("extra_info", {})

        if not name or not email or not password or not role:
            return jsonify({"error": "Missing required fields"}), 400

        # ✅ check if email already exists
        if users_col.find_one({"email": email}):
            return jsonify({"error": "User already exists"}), 400

        hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

        user_data = {
            "name": name.strip(),
            "email": email.strip().lower(),
            "password": hashed_pw,
            "role": role,
            "created_at": datetime.datetime.utcnow()
        }

        if role == "student":
            branch = extra_info.get("branch")
            sem = extra_info.get("sem")
            mobile = extra_info.get("mobile")

            if not branch or not sem or not mobile:
                return jsonify({"error": "Missing student fields"}), 400

            # ✅ student ke liye branchCode bana rahe (e.g. BBA-2)
            branch_code = f"{branch}-{sem}"
            user_data["extra_info"] = {
                "branch": branch,
                "sem": sem,
                "branchCode": branch_code,
                "mobile": mobile
            }

        elif role == "faculty":
            subjects = extra_info.get("subjects", [])
            if not subjects:
                return jsonify({"error": "Faculty must have subjects"}), 400

            # ✅ faculty ke liye unique facultyCode bana rahe
            faculty_code = f"FAC-{secrets.token_hex(3)}"
            user_data["extra_info"] = {
                "subjects": subjects,
                "facultyCode": faculty_code
            }

        # Save in DB
        users_col.insert_one(user_data)

        return jsonify({
            "message": f"{role} created successfully",
            "user": {
                "name": user_data["name"],
                "email": user_data["email"],
                "role": user_data["role"],
                "extra_info": user_data["extra_info"]
            }
        }), 201

    except Exception as e:
        print("❌ Enroll error:", e)
        return jsonify({"error": "Internal server error"}), 500

# ---------- Timetable Routes ----------

# Get all timetables
@app.route("/api/timetables", methods=["GET"])
def get_all_timetables():
    try:
        timetables = list(timetable_col.find({}, {"_id": 0}))
        
        # Ensure isLive exists for each lecture and add IDs
        for t in timetables:
            lectures = t.get("lectures", {})
            for day, slots in lectures.items():
                for slot, lec in slots.items():
                    if lec:  # Only process if lecture exists
                        if "isLive" not in lec:
                            lec["isLive"] = False
                        # Add a unique ID for each lecture
                        if "id" not in lec:
                            lec["id"] = f"{t['branchCode']}-{t['semester']}-{day}-{slot}"
        
        return jsonify(timetables), 200
    except Exception as e:
        print("❌ Get all timetables error:", e)
        return jsonify({"error": "Internal server error"}), 500

# Get timetable by branch + semester
@app.route("/api/timetable/<branch>/<semester>", methods=["GET"])
def get_timetable_by_branch_sem(branch, semester):
    try:
        # Normalize input
        branch = branch.strip()
        semester = str(semester).strip()

        timetable = timetable_col.find_one(
            {
                "branchCode": {"$regex": f"^{branch}$", "$options": "i"},
                "semester": semester
            },
            {"_id": 0}
        )

        if not timetable:
            return jsonify({"error": "Timetable not found"}), 404
        
        # Ensure isLive exists for each lecture and add IDs
        lectures = timetable.get("lectures", {})
        for day, slots in lectures.items():
            for slot, lec in slots.items():
                if lec:  # Only process if lecture exists
                    if "isLive" not in lec:
                        lec["isLive"] = False
                    # Add a unique ID for each lecture
                    if "id" not in lec:
                        lec["id"] = f"{timetable['branchCode']}-{timetable['semester']}-{day}-{slot}"
        
        return jsonify(timetable), 200
    except Exception as e:
        print("❌ Get timetable error:", e)
        return jsonify({"error": "Internal server error"}), 500

# Create or update timetable
@app.route("/api/timetable", methods=["POST"])
def create_or_update_timetable():
    try:
        data = request.json
        user_email = request.headers.get("X-User-Email")
        user_role = request.headers.get("role")

        if not user_email or not user_role or user_role != "admin":
            return jsonify({"error": "Unauthorized"}), 403

        branch = data.get("branchCode", "").strip()
        semester = str(data.get("semester", "")).strip()
        lectures = data.get("lectures")

        if not branch or not semester or not lectures:
            return jsonify({"error": "Missing required fields"}), 400

        # Verify admin exists
        if not users_col.find_one({"email": user_email, "role": "admin"}):
            return jsonify({"error": "Unauthorized"}), 403

        # Upsert timetable
        timetable_col.update_one(
            {"branchCode": branch, "semester": semester},
            {"$set": {"lectures": lectures}},
            upsert=True
        )

        return jsonify({"message": "Timetable saved successfully"}), 201

    except Exception as e:
        print("❌ Create/Update timetable error:", e)
        return jsonify({"error": "Internal server error"}), 500

# Set a lecture as live
@app.route("/api/timetable/<branch>/<semester>/live", methods=["PATCH"])
def set_live_lecture(branch, semester):
    try:
        data = request.json
        lecture_id = data.get("lectureId")
        if not lecture_id:
            return jsonify({"error": "Missing lectureId"}), 400

        timetable = timetable_col.find_one({"branchCode": branch, "semester": semester})
        if not timetable:
            return jsonify({"error": "Timetable not found"}), 404

        lectures = timetable.get("lectures", {})
        lecture_found = False
        
        # First reset all lectures to not live
        for day, slots in lectures.items():
            for slot, lec in slots.items():
                if lec:  # Only process if lecture exists
                    lec["isLive"] = False
                    # Check if this is the lecture we want to set as live
                    if lec.get("id") == lecture_id:
                        lec["isLive"] = True
                        lecture_found = True

        if not lecture_found:
            return jsonify({"error": "Lecture not found in timetable"}), 404

        timetable_col.update_one(
            {"branchCode": branch, "semester": semester},
            {"$set": {"lectures": lectures}}
        )

        return jsonify({"message": "Lecture live status updated"}), 200
    except Exception as e:
        print("❌ Set live lecture error:", e)
        return jsonify({"error": "Internal server error"}), 500

# Get live lecture for a branch + semester
@app.route("/api/timetable/<branch>/<semester>/live", methods=["GET"])
def get_live_lecture(branch, semester):
    try:
        timetable = timetable_col.find_one(
            {"branchCode": branch, "semester": semester},
            {"_id": 0}
        )
        if not timetable:
            return jsonify({"error": "Timetable not found"}), 404

        lectures = timetable.get("lectures", {})
        live_lecture = None
        
        for day, slots in lectures.items():
            for slot, lec in slots.items():
                if lec and lec.get("isLive"):  # Only process if lecture exists and is live
                    live_lecture = lec.copy()  # Create a copy to avoid modifying original
                    live_lecture["day"] = day
                    live_lecture["slot"] = slot
                    break
            if live_lecture:
                break

        return jsonify(live_lecture or {}), 200
    except Exception as e:
        print("❌ Get live lecture error:", e)
        return jsonify({"error": "Internal server error"}), 500

# Reset all live lectures for a branch + semester
@app.route("/api/timetable/<branch>/<semester>/reset-live", methods=["PATCH"])
def reset_live(branch, semester):
    try:
        timetable = timetable_col.find_one({"branchCode": branch, "semester": semester})
        if not timetable:
            return jsonify({"error": "Timetable not found"}), 404

        lectures = timetable.get("lectures", {})
        for day, slots in lectures.items():
            for slot, lec in slots.items():
                if lec:  # Only process if lecture exists
                    lec["isLive"] = False

        timetable_col.update_one(
            {"branchCode": branch, "semester": semester},
            {"$set": {"lectures": lectures}}
        )
        return jsonify({"message": "All lectures reset"}), 200
    except Exception as e:
        print("❌ Reset live error:", e)
        return jsonify({"error": "Internal server error"}), 500

# ---------- Get All Users ----------
@app.route("/api/users", methods=["GET"])
def get_users():
    try:
        users = list(users_col.find({}, {"_id": 0, "password": 0}))  # hide passwords
        return jsonify(users), 200
    except Exception as e:
        print("❌ Get users error:", e)
        return jsonify({"error": "Internal server error"}), 500
    
# ---------- Session Management ----------
def _generate_token_and_expiry(ttl_seconds=45):
    token = secrets.token_urlsafe(16)
    expiry = datetime.datetime.utcnow() + datetime.timedelta(seconds=ttl_seconds)
    return token, expiry

# Create session (faculty starts a lecture)
@app.route("/api/session/create", methods=["POST"])
def create_session():
    try:
        data = request.json or {}
        faculty_email = data.get("faculty_email") or request.headers.get("X-User-Email")
        if not faculty_email:
            return jsonify({"error": "Missing faculty email"}), 400

        # Verify user is faculty/admin
        user = users_col.find_one({"email": faculty_email})
        if not user or user.get("role") not in ("faculty", "admin"):
            return jsonify({"error": "Unauthorized"}), 403

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

# Get current token for a session
@app.route("/api/session/<sessionId>/token", methods=["GET"])
def get_session_token(sessionId):
    try:
        # simple auth check
        caller = request.headers.get("X-User-Email")
        if not caller:
            return jsonify({"error": "Missing caller email header"}), 400

        # Verify caller is faculty/admin for this session
        session = sessions_col.find_one({"sessionId": sessionId})
        if not session:
            return jsonify({"error": "Session not found"}), 404

        # Only faculty who created session or admin can rotate/get token
        if caller != session.get("faculty_email") and caller not in ADMIN_EMAILS:
            return jsonify({"error": "Unauthorized to fetch token"}), 403

        now = datetime.datetime.utcnow()
        token = session.get("current_token")
        expiry = session.get("token_expiry")

        # If token is missing or expired, generate a new one and update DB
        if not token or not expiry or expiry <= now:
            token, new_expiry = _generate_token_and_expiry(45)
            sessions_col.update_one(
                {"sessionId": sessionId},
                {"$set": {"current_token": token, "token_expiry": new_expiry}}
            )
            expiry = new_expiry

        return jsonify({"sessionId": sessionId, "token": token, "token_expiry": expiry.isoformat()}), 200

    except Exception as e:
        print("❌ Get token error:", e)
        return jsonify({"error": "Internal server error"}), 500

# ---------- Student Management ----------
@app.route("/api/students/<branch>/<semester>", methods=["GET"])
def get_students_by_branch_sem(branch, semester):
    try:
        branch = branch.strip()
        semester = str(semester).strip()

        students = list(users_col.find(
            {"role": "student", "extra_info.branch": branch, "extra_info.sem": semester},
            {"_id": 0, "password": 0}
        ))

        return jsonify(students), 200
    except Exception as e:
        print("❌ Get students error:", e)
        return jsonify({"error": "Internal server error"}), 500

# ---------- Attendance Management ----------
@app.route("/api/attendance/<branch>/<semester>", methods=["GET"])
def get_attendance_by_branch_sem(branch, semester):
    try:
        branch = branch.strip()
        semester = str(semester).strip()

        # Find all students of this branch + semester
        students = list(users_col.find(
            {"role": "student", "extra_info.branch": branch, "extra_info.sem": semester},
            {"email": 1, "_id": 0}
        ))
        student_emails = [s["email"] for s in students]

        # Fetch attendance records for these students
        records = list(attendance_col.find(
            {"student_email": {"$in": student_emails}},
            {"_id": 0}
        ))

        return jsonify(records), 200
    except Exception as e:
        print("❌ Get attendance branch/sem error:", e)
        return jsonify({"error": "Internal server error"}), 500

# Get attendance for a specific student
@app.route("/api/attendance/<student_email>", methods=["GET"])
def get_attendance(student_email):
    try:
        # Verify student exists
        student = users_col.find_one({"email": student_email})
        if not student or student.get("role") != "student":
            return jsonify({"error": "Student not found"}), 404

        records = list(attendance_col.find({"student_email": student_email}, {"_id": 0}))
        return jsonify(records), 200
    except Exception as e:
        print("❌ Get attendance error:", e)
        return jsonify({"error": "Internal server error"}), 500

# Process QR code scan for attendance
@app.route("/api/attendance/scan", methods=["POST"])
def attendance_scan():
    try:
        data = request.json or {}
        qr_value = data.get("qrValue")
        student_email = request.headers.get("X-User-Email") or data.get("student_email")

        if not qr_value or not student_email:
            return jsonify({"error": "Missing qrValue or student email"}), 400

        # Parse QR value (format: sessionId::token)
        parts = qr_value.split("::")
        if len(parts) != 2:
            return jsonify({"error": "Invalid QR format"}), 400

        session_id, token = parts[0], parts[1]

        # Find active session
        session = sessions_col.find_one({"sessionId": session_id, "active": True})
        if not session:
            return jsonify({"error": "Session not active or not found"}), 404

        now = datetime.datetime.utcnow()
        stored_token = session.get("current_token")
        token_expiry = session.get("token_expiry")

        # Validate token
        if not stored_token or not token_expiry or token_expiry <= now:
            return jsonify({"error": "Token expired"}), 400

        if token != stored_token:
            return jsonify({"error": "Invalid or outdated token"}), 400

        # Verify student exists
        student = users_col.find_one({"email": student_email})
        if not student or student.get("role") != "student":
            return jsonify({"error": "Student not found or unauthorized"}), 403

        # Check if attendance already recorded for this session today
        today_start = datetime.datetime(now.year, now.month, now.day)
        today_end = today_start + datetime.timedelta(days=1)
        
        existing_attendance = attendance_col.find_one({
            "sessionId": session_id,
            "student_email": student_email,
            "timestamp": {"$gte": today_start, "$lt": today_end}
        })
        
        if existing_attendance:
            return jsonify({"message": "Attendance already recorded for today"}), 200

        # Record attendance
        attendance_col.insert_one({
            "sessionId": session_id,
            "student_email": student_email,
            "timestamp": now,
            "subject": session.get("meta", {}).get("subject", "Unknown")
        })

        return jsonify({"message": "Attendance marked successfully"}), 201

    except Exception as e:
        print("❌ Attendance scan error:", e)
        return jsonify({"error": "Internal server error"}), 500

# ----------------- Run -----------------
if __name__ == "__main__":
    app.run(debug=True, port=5000)