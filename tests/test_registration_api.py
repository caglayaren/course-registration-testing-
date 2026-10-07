"""Automated checks for the Course Registration Service (xUnit style, runs with
`python -m unittest` and also with `pytest`).

Test design techniques used (see report): equivalence partitioning (EP),
boundary-value analysis (BVA), decision table (DT), state-transition (ST).
"""
import statistics
import threading
import time
import unittest

from registration_service import create_app
from registration_service.app import MAX_COURSES, MAX_QUERY_LENGTH


def login(client, sid, password):
    return client.post("/api/login", json={"student_id": sid, "password": password})


def auth(client, sid="s1001", password=None):
    password = password or f"Pass{sid[1:]}!"
    resp = login(client, sid, password)
    assert resp.status_code == 200, resp.get_json()
    return {"Authorization": f"Bearer {resp.get_json()['token']}"}


class BaseApiTest(unittest.TestCase):
    def setUp(self):
        self.app = create_app()          # fresh state for every test
        self.client = self.app.test_client()


class LoginTests(BaseApiTest):
    def test_tc01_valid_login_returns_token(self):                 # EP (valid)
        resp = login(self.client, "s1001", "Pass1001!")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.get_json()["token"])

    def test_tc02_wrong_password_rejected(self):                   # EP (invalid)
        resp = login(self.client, "s1001", "wrong")
        self.assertEqual(resp.status_code, 401)
        self.assertNotIn("token", resp.get_json())
        self.assertEqual(resp.get_json()["error"], "INVALID_CREDENTIALS")

    def test_tc03_account_locks_after_three_failures(self):        # ST + BVA
        for _ in range(2):
            self.assertEqual(login(self.client, "s1002", "bad").status_code, 401)
        self.assertEqual(login(self.client, "s1002", "bad").status_code, 401)  # 3rd failure
        # Even the CORRECT password is now refused.
        resp = login(self.client, "s1002", "Pass1002!")
        self.assertEqual(resp.status_code, 423)
        self.assertEqual(resp.get_json()["error"], "ACCOUNT_LOCKED")


class SearchTests(BaseApiTest):
    def test_tc04_search_is_case_insensitive_and_partial(self):    # EP
        resp = self.client.get("/api/courses?q=soft")
        codes = [c["code"] for c in resp.get_json()["courses"]]
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(codes, ["SOFT301", "SOFT411"])

    def test_tc05_query_length_boundary(self):                     # BVA (50 / 51)
        ok = self.client.get("/api/courses?q=" + "a" * MAX_QUERY_LENGTH)
        too_long = self.client.get("/api/courses?q=" + "a" * (MAX_QUERY_LENGTH + 1))
        self.assertEqual(ok.status_code, 200)
        self.assertEqual(too_long.status_code, 400)
        self.assertEqual(too_long.get_json()["error"], "QUERY_TOO_LONG")


class RegistrationTests(BaseApiTest):
    def register(self, headers, code):
        return self.client.post("/api/register", json={"course_code": code}, headers=headers)

    def test_tc06_eligible_student_can_register(self):             # DT (all conditions true)
        h = auth(self.client, "s1003")
        resp = self.register(h, "SOFT411")
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(resp.get_json()["seats_left"], 1)          # 2 -> 1
        schedule = self.client.get("/api/schedule", headers=h).get_json()
        self.assertEqual(schedule["courses"], ["SOFT411"])

    def test_tc07_missing_prerequisite_rejected(self):             # DT (prereq = false)
        h = auth(self.client, "s1002")                              # completed nothing
        resp = self.register(h, "SOFT411")
        self.assertEqual(resp.status_code, 422)
        self.assertEqual(resp.get_json()["error"], "PREREQUISITE_MISSING")
        self.assertEqual(self.client.get("/api/schedule", headers=h).get_json()["courses"], [])

    def test_tc08_full_course_rejected(self):                      # DT (seat = false)
        h = auth(self.client, "s1001")
        resp = self.register(h, "CENG101")                          # 0 seats
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(resp.get_json()["error"], "COURSE_FULL")

    def test_tc09_duplicate_registration_rejected(self):           # DT (already registered)
        h = auth(self.client, "s1001")
        self.assertEqual(self.register(h, "MATH201").status_code, 201)
        resp = self.register(h, "MATH201")
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(resp.get_json()["error"], "ALREADY_REGISTERED")
        # seat count must not change on the rejected attempt
        seats = self.client.get("/api/courses?q=MATH201").get_json()["courses"][0]["seats_left"]
        self.assertEqual(seats, 0)

    def test_tc10_max_courses_boundary(self):                      # BVA (3 ok, 4 rejected)
        h = auth(self.client, "s1001")
        for code in ["SOFT301", "MATH101", "PHYS101"][:MAX_COURSES]:
            self.assertEqual(self.register(h, code).status_code, 201, code)
        resp = self.register(h, "ENGL101")                          # 4th course
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(resp.get_json()["error"], "MAX_COURSES_REACHED")


class SecurityTests(BaseApiTest):
    def test_tc11_protected_endpoints_require_valid_token(self):   # Security: authN
        for headers in ({}, {"Authorization": "Bearer not-a-real-token"},
                        {"Authorization": "Basic abc"}):
            r1 = self.client.post("/api/register", json={"course_code": "SOFT301"}, headers=headers)
            r2 = self.client.get("/api/schedule", headers=headers)
            self.assertEqual(r1.status_code, 401, headers)
            self.assertEqual(r2.status_code, 401, headers)

    def test_tc12_hostile_input_and_security_headers(self):        # Security: input + headers
        payloads = ["' OR '1'='1", "<script>alert(1)</script>", "../../etc/passwd", "%00"]
        for p in payloads:
            resp = self.client.get("/api/courses", query_string={"q": p})
            self.assertEqual(resp.status_code, 200, p)
            self.assertEqual(resp.get_json()["courses"], [], p)      # no data leaked
            self.assertEqual(resp.mimetype, "application/json")
        resp = self.client.get("/api/courses")
        self.assertEqual(resp.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(resp.headers["X-Frame-Options"], "DENY")
        self.assertIn("default-src 'none'", resp.headers["Content-Security-Policy"])
        self.assertEqual(resp.headers["Cache-Control"], "no-store")


class ReliabilityAndPerformanceTests(unittest.TestCase):
    def test_tc13_last_seat_is_given_to_exactly_one_student(self):  # Concurrency
        n = 8
        students = {f"c{i}": {"name": f"C{i}", "password": "pw"} for i in range(n)}
        courses = {"LAST101": {"title": "Last Seat", "seats": 1, "prereq": None}}
        app = create_app(students=students, courses=courses)
        headers = []
        for i in range(n):
            token = app.test_client().post(
                "/api/login", json={"student_id": f"c{i}", "password": "pw"}).get_json()["token"]
            headers.append({"Authorization": f"Bearer {token}"})

        statuses, barrier = [], threading.Barrier(n)

        def worker(h):
            client = app.test_client()
            barrier.wait()                                          # fire together
            statuses.append(client.post("/api/register", json={"course_code": "LAST101"},
                                        headers=h).status_code)

        threads = [threading.Thread(target=worker, args=(h,)) for h in headers]
        for t in threads: t.start()
        for t in threads: t.join()

        self.assertEqual(statuses.count(201), 1, statuses)
        self.assertEqual(statuses.count(409), n - 1, statuses)

    def test_tc14_search_performance_smoke(self):                  # Performance (smoke)
        client = create_app().test_client()
        timings = []
        for _ in range(200):
            start = time.perf_counter()
            resp = client.get("/api/courses?q=soft")
            timings.append(time.perf_counter() - start)
            self.assertEqual(resp.status_code, 200)
        p95 = statistics.quantiles(timings, n=20)[18]
        self.assertLess(p95, 0.100, f"p95 = {p95 * 1000:.1f} ms")   # criterion: p95 < 100 ms
        self.assertLess(sum(timings), 5.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
