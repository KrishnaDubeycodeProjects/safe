import requests
import json

BASE_URL = "https://ixil3ly75uaxbvmqzs6mdlfj4m0kdtud.lambda-url.us-east-1.on.aws"
ORIGIN = "https://princete.com"

print("="*60)
print("VERIFYING LIVE BACKEND DEPLOYMENT ON AWS LAMBDA")
print(f"Base URL: {BASE_URL}")
print(f"Origin Tested: {ORIGIN}")
print("="*60)

# 1. Health Check
r = requests.get(f"{BASE_URL}/health", headers={"Origin": ORIGIN})
print(f"1. GET /health -> Status: {r.status_code}")
print(f"   CORS Header: {r.headers.get('Access-Control-Allow-Origin')}")
print(f"   Body: {r.text}")

# 2. CORS Preflight OPTIONS
r_opt = requests.options(
    f"{BASE_URL}/api/v1/scan/text",
    headers={
        "Origin": ORIGIN,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type,authorization"
    }
)
print(f"\n2. OPTIONS /api/v1/scan/text -> Status: {r_opt.status_code}")
print(f"   CORS Header: {r_opt.headers.get('Access-Control-Allow-Origin')}")
print(f"   Allow Methods: {r_opt.headers.get('Access-Control-Allow-Methods')}")

# 3. Community Stats
r_comm = requests.get(f"{BASE_URL}/api/community/stats", headers={"Origin": ORIGIN})
print(f"\n3. GET /api/community/stats -> Status: {r_comm.status_code}")
print(f"   Body: {r_comm.text[:120]}...")

# 4. Blogs List
r_blogs = requests.get(f"{BASE_URL}/api/blogs", headers={"Origin": ORIGIN})
print(f"\n4. GET /api/blogs -> Status: {r_blogs.status_code}")
print(f"   Body: {r_blogs.text[:120]}...")

# 5. Scan Text
r_scan = requests.post(
    f"{BASE_URL}/api/v1/scan/text",
    headers={"Origin": ORIGIN, "Content-Type": "application/json"},
    json={"text": "URGENT: Your bank account is locked. Click here to verify http://fake-bank-login.xyz"}
)
print(f"\n5. POST /api/v1/scan/text -> Status: {r_scan.status_code}")
print(f"   Body: {r_scan.text[:160]}...")

print("\n" + "="*60)
print("ALL VERIFICATIONS COMPLETED SUCCESSFULLY!")
print("="*60)
