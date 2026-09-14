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

try:
    lam.remove_permission(FunctionName=function_name, StatementId="FunctionURLAllowPublicAccess")
    print("[*] Removed old statement")
except Exception as e:
    print("[*] Old statement note:", e)

try:
    resp = lam.add_permission(
        FunctionName=function_name,
        StatementId="FunctionURLAllowPublicAccess",
        Action="lambda:InvokeFunctionUrl",
        Principal="*",
        FunctionUrlAuthType="NONE"
    )
    print("[+] Public access permission added successfully:", resp["Statement"])
except Exception as e:
    print("[!] Error adding permission:", e)
