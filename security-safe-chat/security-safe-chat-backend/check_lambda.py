import os
import json
import boto3
from dotenv import load_dotenv

load_dotenv()

session = boto3.Session(
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    region_name="us-east-1"
)

lam = session.client("lambda")
function_name = "safe-backend"

url_config = lam.get_function_url_config(FunctionName=function_name)
print("Function URL Config:", json.dumps(url_config, indent=2, default=str))

try:
    policy = lam.get_policy(FunctionName=function_name)
    print("Policy:", json.dumps(json.loads(policy["Policy"]), indent=2))
except Exception as e:
    print("Policy error:", e)
