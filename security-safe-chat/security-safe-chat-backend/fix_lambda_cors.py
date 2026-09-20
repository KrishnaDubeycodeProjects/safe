import os
import boto3
import requests
from dotenv import load_dotenv

load_dotenv()

session = boto3.Session(
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    region_name="us-east-1"
)

lam = session.client("lambda")
function_name = "safe-backend"

# Remove CORS from Lambda Function URL config so FastAPI handles it cleanly without duplicate headers
print("[*] Updating Lambda Function URL config (disabling Lambda-level CORS to avoid duplicates)...")
resp = lam.update_function_url_config(
    FunctionName=function_name,
    AuthType="NONE",
    Cors={}
)
print("[+] Updated Function URL Config:", resp)

# Test from https://safe.princete.com
url = "https://ixil3ly75uaxbvmqzs6mdlfj4m0kdtud.lambda-url.us-east-1.on.aws/health"
r = requests.get(url, headers={"Origin": "https://safe.princete.com"})
print("\n--- Test Response Headers ---")
print("Status:", r.status_code)
for k, v in r.headers.items():
    if "access-control" in k.lower():
        print(f"{k}: {v}")

# Test preflight OPTIONS
r_opt = requests.options(
    "https://ixil3ly75uaxbvmqzs6mdlfj4m0kdtud.lambda-url.us-east-1.on.aws/api/scan/text",
    headers={
        "Origin": "https://safe.princete.com",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type"
    }
)
print("\n--- Preflight OPTIONS Headers ---")
print("Status:", r_opt.status_code)
for k, v in r_opt.headers.items():
    if "access-control" in k.lower():
        print(f"{k}: {v}")
