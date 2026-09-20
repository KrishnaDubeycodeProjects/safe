import os
import sys
import base64
import subprocess
import time
import json
import boto3
from dotenv import load_dotenv

load_dotenv()

AWS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET = os.getenv("AWS_SECRET_ACCESS_KEY")
REGION = os.getenv("AWS_REGION", "us-east-1")
REPO_NAME = "safe-backend"
FUNCTION_NAME = "safe-backend"

session = boto3.Session(
    aws_access_key_id=AWS_KEY,
    aws_secret_access_key=AWS_SECRET,
    region_name=REGION
)

sts = session.client("sts")
account_id = sts.get_caller_identity()["Account"]
print(f"[*] Authenticated to AWS Account: {account_id} ({REGION})")

ecr = session.client("ecr")

# 1. Ensure ECR Repo Exists
try:
    ecr.describe_repositories(repositoryNames=[REPO_NAME])
    print(f"[*] ECR Repository '{REPO_NAME}' exists.")
except ecr.exceptions.RepositoryNotFoundException:
    print(f"[*] Creating ECR Repository '{REPO_NAME}'...")
    ecr.create_repository(repositoryName=REPO_NAME)

ecr_uri = f"{account_id}.dkr.ecr.{REGION}.amazonaws.com/{REPO_NAME}:latest"

# 2. Authenticate Docker with ECR
print("[*] Authenticating Docker with Amazon ECR...")
auth_data = ecr.get_authorization_token()["authorizationData"][0]
token = base64.b64decode(auth_data["authorizationToken"]).decode("utf-8")
username, password = token.split(":")
registry = auth_data["proxyEndpoint"]

login_cmd = ["docker", "login", "-u", username, "--password-stdin", registry]
p = subprocess.run(login_cmd, input=password, capture_output=True, text=True)
if p.returncode != 0:
    print(f"[!] Docker login failed: {p.stderr}")
    sys.exit(1)
print("[+] Docker login succeeded.")

# 3. Build, Tag & Push Docker Image
print("[*] Building Docker image for Lambda...")
subprocess.run(["docker", "build", "-t", "safe-backend-lambda:latest", "."], check=True)

print(f"[*] Tagging image as {ecr_uri}...")
subprocess.run(["docker", "tag", "safe-backend-lambda:latest", ecr_uri], check=True)

print(f"[*] Pushing image to Amazon ECR...")
subprocess.run(["docker", "push", ecr_uri], check=True)
print("[+] Image successfully pushed to ECR!")

# 4. Ensure IAM Role for Lambda
iam = session.client("iam")
role_name = "safe-backend-lambda-role"
role_arn = None

trust_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }
    ]
}

try:
    role_resp = iam.get_role(RoleName=role_name)
    role_arn = role_resp["Role"]["Arn"]
    print(f"[*] Found IAM Role: {role_arn}")
except iam.exceptions.NoSuchEntityException:
    print(f"[*] Creating IAM Role '{role_name}'...")
    role_resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy)
    )
    role_arn = role_resp["Role"]["Arn"]
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    )
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/AmazonBedrockFullAccess"
    )
    print(f"[+] Created IAM Role: {role_arn}")
    time.sleep(10)

lambda_client = session.client("lambda")

env_vars = {
    "APP_ENV": "production",
    "CORS_ORIGINS": "https://safe.princete.com,https://princete.com,https://www.princete.com,https://safe-chat.vercel.app,http://localhost:4321",
    "BEDROCK_MODEL_ID": os.getenv("BEDROCK_MODEL_ID", "google.gemma-3-27b-it"),
    "BEDROCK_ANTHROPIC_VERSION": "bedrock-2023-05-31",
    "BEDROCK_MANTLE_API_KEY": os.getenv("BEDROCK_MANTLE_API_KEY", ""),
    "BEDROCK_API_KEY": os.getenv("BEDROCK_MANTLE_API_KEY", "") or os.getenv("BEDROCK_API_KEY", ""),
    "YOUTUBE_API_KEY": os.getenv("YOUTUBE_API_KEY", ""),
    "TAVILY_API_KEY": os.getenv("TAVILY_API_KEY", ""),
    "OCR_SPACE_API_KEY": os.getenv("OCR_SPACE_API_KEY", ""),
    "OCR_SPACE_API_URL": os.getenv("OCR_SPACE_API_URL", "https://api.ocr.space/parse/image"),
    "OCR_LANGUAGE": os.getenv("OCR_LANGUAGE", "eng"),
    "ADMIN_BLOG_KEY": os.getenv("ADMIN_BLOG_KEY", ""),
    "FEEDBACK_RECIPIENT_EMAIL": os.getenv("FEEDBACK_RECIPIENT_EMAIL", ""),
    "SMTP_USER": os.getenv("SMTP_USER", ""),
    "SMTP_PASSWORD": os.getenv("SMTP_PASSWORD", ""),
    "SMTP_HOST": os.getenv("SMTP_HOST", "smtp.gmail.com"),
    "SMTP_PORT": os.getenv("SMTP_PORT", "465"),
    "SUPABASE_URL": os.getenv("SUPABASE_URL", ""),
    "BLOG_STORAGE_PATH": "/tmp/blogs_store.json",
}

# 5. Create or Update Lambda Function
try:
    lambda_client.get_function(FunctionName=FUNCTION_NAME)
    print(f"[*] Updating existing Lambda Function code for '{FUNCTION_NAME}'...")
    lambda_client.update_function_code(
        FunctionName=FUNCTION_NAME,
        ImageUri=ecr_uri
    )
    print("[*] Waiting for Lambda code update to complete...")
    waiter = lambda_client.get_waiter("function_updated_v2")
    waiter.wait(FunctionName=FUNCTION_NAME)
    
    print(f"[*] Updating Lambda configuration...")
    lambda_client.update_function_configuration(
        FunctionName=FUNCTION_NAME,
        Timeout=30,
        MemorySize=1024,
        Environment={"Variables": env_vars}
    )
    print(f"[+] Lambda Function '{FUNCTION_NAME}' updated successfully!")
except lambda_client.exceptions.ResourceNotFoundException:
    print(f"[*] Creating new Lambda Function '{FUNCTION_NAME}'...")
    lambda_client.create_function(
        FunctionName=FUNCTION_NAME,
        PackageType="Image",
        Code={"ImageUri": ecr_uri},
        Role=role_arn,
        Timeout=30,
        MemorySize=1024,
        Environment={"Variables": env_vars}
    )
    print(f"[*] Waiting for Lambda creation to complete...")
    waiter = lambda_client.get_waiter("function_active_v2")
    waiter.wait(FunctionName=FUNCTION_NAME)
    print(f"[+] Lambda Function '{FUNCTION_NAME}' created successfully!")

# 6. Ensure Function URL with CORS
func_url = None
try:
    url_resp = lambda_client.get_function_url_config(FunctionName=FUNCTION_NAME)
    func_url = url_resp["FunctionUrl"]
    print(f"[*] Existing Function URL: {func_url}")
except lambda_client.exceptions.ResourceNotFoundException:
    print(f"[*] Creating Lambda Function URL...")
    url_resp = lambda_client.create_function_url_config(
        FunctionName=FUNCTION_NAME,
        AuthType="NONE",
        Cors={}
    )
    func_url = url_resp["FunctionUrl"]
    try:
        lambda_client.add_permission(
            FunctionName=FUNCTION_NAME,
            StatementId="AllowPublicInvokeFunction",
            Action="lambda:InvokeFunction",
            Principal="*"
        )
    except Exception:
        pass
    print(f"[+] Created Function URL: {func_url}")

print("\n" + "="*60)
print(f"SUCCESS! AWS Lambda Backend is Live:")
print(f"Function URL: {func_url}")
print(f"Health Check: {func_url}health")
print(f"CORS allowed for: https://princete.com, https://www.princete.com")
print("="*60)
