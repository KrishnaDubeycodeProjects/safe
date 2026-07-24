# Security Safe Chat — Backend
## Production-Ready Python Backend

FastAPI + Amazon Bedrock (Claude 3 Haiku) + OCR.space

---

## Project Structure

```
security-safe-chat-backend/
├── app/
│   ├── __init__.py        # package marker
│   ├── config.py          # typed settings (pydantic-settings, reads .env)
│   ├── taxonomy.py        # full 100+ scam ID → label/verdict/red_flags map
│   ├── parser.py          # compact model output parser (all 5 cases)
│   ├── bedrock.py         # AWS Bedrock Claude 3 Haiku client
│   ├── ocr.py             # OCR.space async client (URL / base64 / bytes)
│   ├── schemas.py         # Pydantic request/response models
│   ├── routes.py          # FastAPI route handlers
│   ├── middleware.py      # optional X-API-Key auth middleware
│   └── main.py            # app factory + CORS + rate limiting + entry point
├── tests/
│   └── test_parser.py     # pytest unit tests for parser (all 5 cases)
├── .env.example           # environment variable template
├── requirements.txt       # pinned production dependencies
└── README.md
```

---

## Quick Start

### 1. Copy and fill the .env file

```bash
cp .env.example .env
# Fill in: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, OCR_SPACE_API_KEY
```

### 2. Install dependencies

```bash
python -m venv venv
venv\Scripts\activate          # Windows
pip install -r requirements.txt
```

### 3. Run the development server

```bash
uvicorn app.main:app --reload
```

Visit **http://localhost:8000/docs** for the interactive Swagger UI.

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Liveness probe |
| `POST` | `/analyze/text` | Classify plain-text message |
| `POST` | `/analyze/image` | Upload image → OCR → classify |
| `POST` | `/analyze/base64` | Base64 image → OCR → classify |

### POST /analyze/text

```json
// Request
{ "message": "Congratulations Rahul! You have won Rs. 1,00,00,000 in our lucky draw. Call now to claim!" }

// Response
{
  "case": 1,
  "is_scam": true,
  "score": 100,
  "matches": [{
    "id": "1.1.1",
    "label": "Cash Lottery Scam",
    "category": "Prize & Lottery Scams",
    "verdict": "Definitely a scam",
    "red_flags": ["Unsolicited win notification", "No record of entering", ...],
    "detection_message": "This message is a classic prize scam. It tells Rahul they've won 10000000 in a lottery they never entered.",
    "entities": { "name": "Rahul", "money": "10000000" }
  }],
  "entities": { "name": "Rahul", "money": "10000000" },
  "raw_model_output": "1.1.1|name=Rahul,money=10000000"
}
```

### POST /analyze/image

```
Content-Type: multipart/form-data
file: <image file>
language: eng  (optional)
```

Extracts text via OCR.space, then classifies. `extracted_text` is included in response.

### POST /analyze/base64

```json
{
  "image": "data:image/png;base64,iVBORw0KGgo...",
  "content_type": "image/png"
}
```

---

## Configuration (.env)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `AWS_ACCESS_KEY_ID` | ✅ | — | AWS IAM access key |
| `AWS_SECRET_ACCESS_KEY` | ✅ | — | AWS IAM secret |
| `AWS_REGION` | — | `us-east-1` | Bedrock region |
| `BEDROCK_MODEL_ID` | — | `anthropic.claude-3-haiku-20240307-v1:0` | Model to use |
| `OCR_SPACE_API_KEY` | ✅ | — | OCR.space API key |
| `OCR_LANGUAGE` | — | `eng` | OCR language code |
| `APP_ENV` | — | `development` | `development` or `production` |
| `APP_PORT` | — | `8000` | Server port |
| `CORS_ORIGINS` | — | `*` | Comma-separated allowed origins |
| `RATE_LIMIT_REQUESTS` | — | `30` | Requests per window |
| `RATE_LIMIT_WINDOW_SECONDS` | — | `60` | Rate limit window |
| `API_SECRET_KEY` | — | (empty) | Static API key for auth; leave blank to disable |

---

## AWS IAM Permissions Required

Attach this policy to your IAM user/role:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["bedrock:InvokeModel"],
    "Resource": "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0"
  }]
}
```

---

## Running Tests

```bash
pytest tests/ -v
```

---

## Production Deployment

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

For Docker / AWS ECS, set environment variables via your container environment — the `.env` file is optional.

---

## Parser Output Cases

| Case | Model Output | Meaning |
|------|-------------|---------|
| 1 | `X.X.X\|key=val,...` | Single matched scam type |
| 2 | `multi:X.X.X+X.X.X\|key=val,...` | Multiple scam types in one message |
| 3 | `gen\|key=val,...` | Generic scam, no taxonomy match |
| 4 | `unsure` | Ambiguous — could be legit or scam |
| 5 | `err` | Safe / legitimate message |
