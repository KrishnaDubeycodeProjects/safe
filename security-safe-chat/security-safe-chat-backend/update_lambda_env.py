import os
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

print("[*] Updating Lambda Environment Variables...")
resp = lam.update_function_configuration(
    FunctionName=function_name,
    Timeout=30,
    MemorySize=1024,
    Environment={"Variables": env_vars}
)
print("[+] Lambda Environment Variables updated successfully!")
