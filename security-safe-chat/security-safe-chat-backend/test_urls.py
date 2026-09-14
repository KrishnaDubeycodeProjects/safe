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

# List current policy
try:
    pol = lam.get_policy(FunctionName=function_name)
    print("Current Policy:", pol["Policy"])
except Exception as e:
    print("No current policy:", e)

# Test function url
url = "https://ixil3ly75uaxbvmqzs6mdlfj4m0kdtud.lambda-url.us-east-1.on.aws/health"
headers = {"Origin": "https://princete.com"}
r = requests.get(url, headers=headers)
print("Response code:", r.status_code)
print("Response headers:", r.headers)
print("Response text:", r.text)
