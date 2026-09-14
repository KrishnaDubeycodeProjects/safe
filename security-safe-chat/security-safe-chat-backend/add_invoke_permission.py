import os
import time
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

try:
    lam.remove_permission(FunctionName=function_name, StatementId="AllowPublicInvokeFunction")
except Exception:
    pass

try:
    resp = lam.add_permission(
        FunctionName=function_name,
        StatementId="AllowPublicInvokeFunction",
        Action="lambda:InvokeFunction",
        Principal="*"
    )
    print("[+] Added lambda:InvokeFunction permission:", resp["Statement"])
except Exception as e:
    print("[!] Error adding InvokeFunction:", e)

# Test request
time.sleep(3)
url = "https://ixil3ly75uaxbvmqzs6mdlfj4m0kdtud.lambda-url.us-east-1.on.aws/health"
headers = {"Origin": "https://princete.com"}
r = requests.get(url, headers=headers)
print("Status:", r.status_code)
print("Response text:", r.text)
