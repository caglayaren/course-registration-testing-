"""Course Registration Service.

A small REST API (Flask) used as the system under test for the SOFT411
"Modern Testing Strategy & Prototype" assignment.

Business rules
--------------
* Students log in with ID + password and receive a bearer token.
* After 3 consecutive failed logins the account is locked.
* Anyone can search courses; only logged-in students can register.
* A student can register for a course only if
    - the course exists,
    - the student is not already registered for it,
    - the student has completed the prerequisite (if any),
    - the student has fewer than MAX_COURSES registered courses,
    - at least one seat is free.
"""
import hashlib
import hmac
import secrets
import threading

from flask import Flask, jsonify, request

MAX_COURSES = 3
MAX_FAILED_LOGINS = 3
MAX_QUERY_LENGTH = 50

DEFAULT_STUDENTS = {
    "s1001": {"name": "Ayse", "password": "Pass1001!", "completed": ["SOFT301", "MATH101"]},
    "s1002": {"name": "Mehmet", "password": "Pass1002!", "completed": []},
    "s1003": {"name": "Zeynep", "password": "Pass1003!", "completed": ["SOFT301"]},
}

DEFAULT_COURSES = {
    "SOFT301": {"title": "Software Engineering", "seats": 30, "prereq": None},
    "SOFT411": {"title": "Software Validation & Testing", "seats": 2, "prereq": "SOFT301"},
    "MATH101": {"title": "Calculus I", "seats": 40, "prereq": None},
    "MATH201": {"title": "Calculus II", "seats": 1, "prereq": "MATH101"},
    "CENG101": {"title": "Introduction to Programming", "seats": 0, "prereq": None},
    "PHYS101": {"title": "Physics I", "seats": 30, "prereq": None},
    "ENGL101": {"title": "Academic English", "seats": 30, "prereq": None},
}


def _hash_password(password, salt):
    # Low iteration count keeps the demo/tests fast; use >=600k in production.
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 1000).hex()


def create_app(students=None, courses=None):
    """Application factory: every call builds a fresh, isolated in-memory state."""
    app = Flask(__name__)
    lock = threading.Lock()

    students_src = students if students is not None else DEFAULT_STUDENTS
    courses_src = courses if courses is not None else DEFAULT_COURSES

    db_students = {}
    for sid, s in students_src.items():
        salt = secrets.token_bytes(8)
        db_students[sid] = {
            "name": s.get("name", sid),
            "salt": salt,
            "hash": _hash_password(s["password"], salt),
            "completed": set(s.get("completed", [])),
            "failed": 0,
            "locked": False,
            "courses": [],
        }
    db_courses = {
        code: {"title": c["title"], "seats": c["seats"], "prereq": c.get("prereq"), "enrolled": []}
        for code, c in courses_src.items()
    }
    tokens = {}

    def error(status, code, message):
        return jsonify({"error": code, "message": message}), status

    def current_student():
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return None
        return tokens.get(header[len("Bearer "):].strip())

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Content-Security-Policy"] = "default-src 'none'"
        return resp

    @app.errorhandler(404)
    def not_found(_):
        return error(404, "NOT_FOUND", "Resource not found.")

    @app.errorhandler(405)
    def not_allowed(_):
        return error(405, "METHOD_NOT_ALLOWED", "Method not allowed.")

    @app.post("/api/login")
    def login():
        data = request.get_json(silent=True) or {}
        sid, pw = data.get("student_id"), data.get("password")
        if not isinstance(sid, str) or not isinstance(pw, str) or not sid or not pw:
            return error(400, "MISSING_FIELDS", "student_id and password are required.")
        with lock:
            student = db_students.get(sid)
            if student is None:
                return error(401, "INVALID_CREDENTIALS", "Invalid ID or password.")
            if student["locked"]:
                return error(423, "ACCOUNT_LOCKED", "Account locked after too many failed attempts.")
            candidate = _hash_password(pw, student["salt"])
            if not hmac.compare_digest(candidate, student["hash"]):
                student["failed"] += 1
                if student["failed"] >= MAX_FAILED_LOGINS:
                    student["locked"] = True
                return error(401, "INVALID_CREDENTIALS", "Invalid ID or password.")
            student["failed"] = 0
            token = secrets.token_urlsafe(24)
            tokens[token] = sid
        return jsonify({"token": token, "name": student["name"]}), 200

    @app.get("/api/courses")
    def search_courses():
        q = request.args.get("q", "")
        if len(q) > MAX_QUERY_LENGTH:
            return error(400, "QUERY_TOO_LONG", f"Query must be at most {MAX_QUERY_LENGTH} characters.")
        needle = q.strip().lower()
        result = []
        with lock:
            for code in sorted(db_courses):
                c = db_courses[code]
                if needle in code.lower() or needle in c["title"].lower():
                    result.append({
                        "code": code,
                        "title": c["title"],
                        "seats_left": c["seats"] - len(c["enrolled"]),
                        "prerequisite": c["prereq"],
                    })
        return jsonify({"courses": result}), 200

    @app.post("/api/register")
    def register():
        sid = current_student()
        if sid is None:
            return error(401, "UNAUTHORIZED", "Valid bearer token required.")
        data = request.get_json(silent=True) or {}
        code = data.get("course_code")
        if not isinstance(code, str) or not code.strip():
            return error(400, "MISSING_FIELDS", "course_code is required.")
        code = code.strip().upper()
        with lock:
            course = db_courses.get(code)
            if course is None:
                return error(404, "COURSE_NOT_FOUND", f"Course {code} does not exist.")
            student = db_students[sid]
            if code in student["courses"]:
                return error(409, "ALREADY_REGISTERED", f"Already registered for {code}.")
            if course["prereq"] and course["prereq"] not in student["completed"]:
                return error(422, "PREREQUISITE_MISSING",
                             f"{code} requires {course['prereq']} to be completed first.")
            if len(student["courses"]) >= MAX_COURSES:
                return error(409, "MAX_COURSES_REACHED", f"At most {MAX_COURSES} courses allowed.")
            if course["seats"] - len(course["enrolled"]) <= 0:
                return error(409, "COURSE_FULL", f"{code} has no free seats.")
            course["enrolled"].append(sid)
            student["courses"].append(code)
            seats_left = course["seats"] - len(course["enrolled"])
        return jsonify({"message": f"Registered for {code}.", "course_code": code,
                        "seats_left": seats_left}), 201

    @app.get("/api/schedule")
    def schedule():
        sid = current_student()
        if sid is None:
            return error(401, "UNAUTHORIZED", "Valid bearer token required.")
        with lock:
            return jsonify({"student_id": sid, "courses": list(db_students[sid]["courses"])}), 200

    return app


if __name__ == "__main__":
    create_app().run(debug=False, port=5000)
