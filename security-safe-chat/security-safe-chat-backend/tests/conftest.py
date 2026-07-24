"""
tests/conftest.py — shared pytest fixtures and environment setup.
"""
import os
import sys
from pathlib import Path

# Ensure project root is on the Python path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Provide minimal env vars so Settings() doesn't crash on import
os.environ.setdefault("AWS_ACCESS_KEY_ID", "test-key-id")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test-secret")
os.environ.setdefault("AWS_REGION", "us-east-1")
os.environ.setdefault("BEDROCK_MODEL_ID", "anthropic.claude-3-haiku-20240307-v1:0")
os.environ.setdefault("OCR_SPACE_API_KEY", "test-ocr-key")
os.environ.setdefault("API_SECRET_KEY", "")         # auth disabled for tests
os.environ.setdefault("SUPABASE_URL", "")           # supabase logging disabled
os.environ.setdefault("SUPABASE_SERVICE_KEY", "")
os.environ.setdefault("APP_ENV", "testing")
