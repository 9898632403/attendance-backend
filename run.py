# run.py
from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from bson.objectid import ObjectId
from dotenv import load_dotenv
import os, bcrypt, certifi

load_dotenv()

app = Flask(__name__)
CORS(app)

MONGO_URI = os.getenv("MONGO_URI")
ADMIN_EMAILS = os.getenv("ADMIN_EMAILS", "admin@iar.com,head@iar.com").split(",")

client = MongoClient(MONGO_URI, tlsCAFile=certifi.where())
db = client['attendance_system']
users_col = db['users']
timetable_col = db['timetables']

# ---------------- Helper ----------------
def is_admin(email):
    return email in ADMIN_EMAILS

# ---------------- Enroll User ----------------
@app.route("/api/enroll", methods=["POST"])
def enroll_user():
    data = request.get_json()
    admin_email = data.get("admin_email")
    if not is_admin(admin_email):
        return jsonify({"error": "Unauthorized"}), 403

    name = data.get("name")
    email = data.get("email")
    password = data.get("password")
    role = data.get("role")
    extra_info = data.get("extra_info", {})

    if users_col.find_one({"email": email}):
        return jsonify({"error": "Email already exists"}), 400

    hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    user_doc = {
        "name": name,
        "email": email,
        "password": hashed_pw,
        "role": role,
        "extra_info": extra_info
    }
    res = users_col.insert_one(user_doc)
    user_doc["_id"] = str(res.inserted_id)
    user_doc.pop("password")
    return jsonify({"message": "User enrolled successfully", "user": user_doc})

# ---------------- Get all students ----------------
@app.route("/api/admin/students", methods=["GET"])
def get_students():
    admin_email = request.headers.get("X-User-Email")
    if not is_admin(admin_email):
        return jsonify({"error": "Unauthorized"}), 403

    students = list(users_col.find({"role": "student"}))
    for s in students:
        s["_id"] = str(s["_id"])
        s.pop("password", None)
    return jsonify(students)

# ---------------- Get all faculty ----------------
@app.route("/api/admin/faculty", methods=["GET"])
def get_faculty():
    admin_email = request.headers.get("X-User-Email")
    if not is_admin(admin_email):
        return jsonify({"error": "Unauthorized"}), 403

    faculty = list(users_col.find({"role": "faculty"}))
    for f in faculty:
        f["_id"] = str(f["_id"])
        f.pop("password", None)
    return jsonify(faculty)

# ---------------- Delete user ----------------
@app.route("/api/admin/user/<email>", methods=["DELETE"])
def delete_user(email):
    admin_email = request.headers.get("X-User-Email")
    if not is_admin(admin_email):
        return jsonify({"error": "Unauthorized"}), 403

    res = users_col.delete_one({"email": email})
    if res.deleted_count == 0:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"message": "User deleted successfully"})

# ---------------- Timetable routes ----------------
@app.route("/api/faculties", methods=["GET"])
def get_faculties():
    faculties = list(users_col.find({"role": "faculty"}))
    for f in faculties:
        f["_id"] = str(f["_id"])
    return jsonify(faculties)

@app.route("/api/timetables", methods=["GET"])
def get_timetables():
    timetables = list(timetable_col.find())
    for t in timetables:
        t["_id"] = str(t["_id"])
    return jsonify(timetables)

@app.route("/api/timetable/<branch>/<semester>", methods=["GET"])
def get_timetable(branch, semester):
    t = timetable_col.find_one({"branchCode": branch, "semester": int(semester)})
    if not t:
        return jsonify({"lectures": {}})
    t["_id"] = str(t["_id"])
    return jsonify(t)

@app.route("/api/timetable", methods=["POST"])
def create_update_timetable():
    data = request.get_json()
    admin_email = request.headers.get("X-User-Email")
    if not is_admin(admin_email):
        return jsonify({"error": "Unauthorized"}), 403

    branch = data.get("branchCode")
    semester = data.get("semester")
    lectures = data.get("lectures", {})

    existing = timetable_col.find_one({"branchCode": branch, "semester": int(semester)})
    if existing:
        timetable_col.update_one({"_id": existing["_id"]}, {"$set": {"lectures": lectures}})
        return jsonify({"message": "Timetable updated successfully"})
    else:
        timetable_col.insert_one({"branchCode": branch, "semester": int(semester), "lectures": lectures})
        return jsonify({"message": "Timetable created successfully"})

@app.route("/api/timetable/<branch>/<semester>", methods=["DELETE"])
def delete_timetable(branch, semester):
    admin_email = request.headers.get("X-User-Email")
    if not is_admin(admin_email):
        return jsonify({"error": "Unauthorized"}), 403

    res = timetable_col.delete_one({"branchCode": branch, "semester": int(semester)})
    if res.deleted_count == 0:
        return jsonify({"error": "Timetable not found"}), 404
    return jsonify({"message": "Timetable deleted successfully"})

if __name__ == "__main__":
    app.run(debug=True)
