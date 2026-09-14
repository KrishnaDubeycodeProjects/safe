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

# Remove all existing permissions
try:
    lam.remove_permission(FunctionName=function_name, StatementId="FunctionURLAllowPublicAccess")
except Exception as e:
    pass

try:
    lam.remove_permission(FunctionName=function_name, StatementId="FunctionURLAllowPublicAccessLatest", Qualifier="$LATEST")
except Exception as e:
    pass

# Add permission without qualifier
try:
    lam.add_permission(
        FunctionName=function_name,
        StatementId="FunctionURLAllowPublicAccess",
        Action="lambda:InvokeFunctionUrl",
        Principal="*",
        FunctionUrlAuthType="NONE"
    )
    print("[+] Added permission unqualified")
except Exception as e:
    print("[!] Error:", e)

# Test request
url = "https://ixil3ly75uaxbvmqzs6mdlfj4m0kdtud.lambda-url.us-east-1.on.aws/health"
r = requests.get(url)
print("Unqualified test status:", r.status_code, r.text)

if r.status_code == 403:
    # Try adding permission with Qualifier="$LATEST" or function URL ARN
    try:
        lam.add_permission(
            FunctionName=function_name,
            Qualifier="$LATEST",
            StatementId="FunctionURLAllowPublicAccessLatest",
            Action="lambda:InvokeFunctionUrl",
            Principal="*",
            FunctionUrlAuthType="NONE"
        )
        print("[+] Added permission with Qualifier=$LATEST")
    except Exception as e:
        print("[!] Error with qualifier:", e)
    
    r2 = requests.get(url)
    print("Qualified test status:", r2.status_code, r2.text)
