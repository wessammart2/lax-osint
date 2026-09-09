"""Quick integration test — boots the server, runs API tests, shuts down."""
import sys, os, time, threading, subprocess

PORT = "8022"
os.environ["PYTHONPATH"] = os.path.dirname(__file__)

# boot uvicorn
proc = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "main:app", "--port", PORT],
    cwd=os.path.dirname(__file__),
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
)

import httpx

BASE = f"http://127.0.0.1:{PORT}"
for _ in range(20):
    try:
        r = httpx.get(f"{BASE}/api/health", timeout=2)
        if r.status_code == 200:
            break
    except Exception:
        time.sleep(1)
else:
    print("FAIL: server not up")
    proc.kill(); sys.exit(1)

OK = []
FAIL = []

def check(label, cond):
    if cond:
        OK.append(label); print(f"  OK  {label}")
    else:
        FAIL.append(label); print(f"FAIL  {label}")

print("=" * 50)
print("LAX OSINT — Integration Test")
print("=" * 50)

# 1) health
health = httpx.get(f"{BASE}/api/health", timeout=5).json()
check("health OK", health["status"] == "ok" and health["db"] == "local")

# 2) register
r = httpx.post(f"{BASE}/api/auth/register", json={"email": "int_test@lax.dev", "password": "Test1234!"}, timeout=10)
check("register 200", r.status_code == 200)
token_u = r.json().get("token")

# 3) login
r = httpx.post(f"{BASE}/api/auth/login", json={"email": "int_test@lax.dev", "password": "Test1234!"}, timeout=10)
check("login 200", r.status_code == 200)

# 4) me
r = httpx.get(f"{BASE}/api/auth/me", params={"token": token_u}, timeout=10)
check("me returns user", "user" in r.json() and r.json()["user"]["email"] == "int_test@lax.dev")
check("me not pro yet", r.json()["user"]["is_pro"] is False)

# 5) admin login
r = httpx.post(f"{BASE}/api/admin/login", json={"username": "kalilax", "password": "kalilax122313"}, timeout=10)
check("admin login 200", r.status_code == 200)
token_a = r.json().get("token")

# 6) admin stats
r = httpx.get(f"{BASE}/api/admin/stats", params={"token": token_a}, timeout=10)
check("admin stats 200", r.status_code == 200)

# 7) create codes
r = httpx.post(f"{BASE}/api/admin/codes", params={"token": token_a}, json={"count": 2, "days": 30}, timeout=10)
check("create codes 200", r.status_code == 200)
codes = r.json().get("codes", [])
check("2 codes created", len(codes) == 2)
code1 = codes[0]["code"]

# 8) pro activate
r = httpx.post(f"{BASE}/api/pro/activate", json={"token": token_u, "code": code1}, timeout=10)
check("pro activate 200", r.status_code == 200)
check("pro activated ok", r.json().get("ok") is True)

# 9) me after pro
r = httpx.get(f"{BASE}/api/auth/me", params={"token": token_u}, timeout=10)
check("me is_pro True", r.json()["user"]["is_pro"] is True)
check("me pro_until set", r.json()["user"]["pro_until"] is not None)

# 10) code reuse rejection
r = httpx.post(f"{BASE}/api/pro/activate", json={"token": token_u, "code": code1}, timeout=10)
check("code reuse 409", r.status_code == 409)

# 11) bad format rejection
r = httpx.post(f"{BASE}/api/pro/activate", json={"token": token_u, "code": "xxx"}, timeout=10)
check("bad format 400", r.status_code == 400)

# 12) nonexistent code
r = httpx.post(f"{BASE}/api/pro/activate", json={"token": token_u, "code": "AAAA-BBBB-CCCCC-DDD"}, timeout=10)
check("not found 404", r.status_code == 404)

# 13) disable user
r = httpx.post(f"{BASE}/api/admin/users/{r.json().get('detail', {}).get('id', 'x')}/disable",
               params={"token": token_a}, json={}, timeout=10)
# We don't know the id from activate test, so check via list
r = httpx.get(f"{BASE}/api/admin/users", params={"token": token_a}, timeout=10)
check("admin list users 200", r.status_code == 200)
users = r.json().get("users", [])
test_user = [u for u in users if u["email"] == "int_test@lax.dev"]
if test_user:
    uid = test_user[0]["id"]
    r = httpx.post(f"{BASE}/api/admin/users/{uid}/disable", params={"token": token_a}, json={}, timeout=10)
    check("disable user 200", r.status_code == 200)

# 14) admin logs
r = httpx.get(f"{BASE}/api/admin/logs", params={"token": token_a}, timeout=10)
check("admin logs 200", r.status_code == 200 and isinstance(r.json().get("logs"), list))

# 15) unauthed search blocked
r = httpx.get(f"{BASE}/api/search/email", params={"q": "test@test.com"}, timeout=5)
check("search no token 401", r.status_code == 401)

# 16) list codes
r = httpx.get(f"{BASE}/api/admin/codes", params={"token": token_a}, timeout=10)
check("list codes 200", r.status_code == 200)

# summary
print("=" * 50)
passed = len(OK); total = passed + len(FAIL)
print(f"Results: {passed}/{total} passed")
if FAIL:
    print(f"FAILED: {', '.join(FAIL)}")
    rc = 1
else:
    print("ALL TESTS PASSED")
    rc = 0

proc.kill()
sys.exit(rc)
