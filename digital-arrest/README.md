# 📞 Digital Arrest Detector — AI Backend

FastAPI backend for the SAFE platform: community scam registry, one-line LLM
message verdicts, and link/URL analysis.

---

## 🚀 Features

- **Message scam verdict** — a message is sent to a local LLM (Ollama) with a
  single system prompt; the response is a one-line perspective plus a tag:
  `Safe` / `Likely Scam` / `Scam Confirmed`.
- **Link cascade** — whitelist/blocklist checks, typosquatting detection
  against 100+ Indian brands, domain heuristics, landing-page analysis, and
  optional LLM reasoning.
- **Community Scam Registry** — report/search/corroborate scam handles
  across platforms, with TF-IDF full-text search, fuzzy matching, and
  cross-platform identity linking. See `routes/community_routes.py`.
- **Related videos** — surfaces relevant YouTube coverage alongside
  community search results (`/api/community/videos`).

---

## 🛠 Tech Stack

- **Backend**: FastAPI + Uvicorn
- **LLM**: Ollama (local), via `utils/rag_utils.py`
- **Rate limiting**: slowapi
- **Storage**: flat JSON files (`data/`), optional Supabase for community reports

---

## 📂 Project Structure

```
digital-arrest/
│── app.py                # FastAPI app: health, /api/scan/text, /api/scan/link, /api/feedback
│── routes/                # /api/community/* endpoints
│── utils/                 # link_cascade, rag_utils, advanced_search_engine, community_*
│── data/                  # community reports / clusters / reputation overrides (JSON)
│── requirements.txt
```

---

## ⚙️ Installation

```bash
cd digital-arrest
python -m venv venv
venv\Scripts\activate          # Windows
pip install -r requirements.txt
cp .env.example .env           # fill in real values (YouTube API key, etc.)
uvicorn app:app --host 127.0.0.1 --port 8001 --reload
```

Or on Windows, just run `install_and_run.bat`.

Message verdicts require a local [Ollama](https://ollama.com) instance running
(`ollama serve`) with the model set in `utils/rag_utils.py` (`DEFAULT_MODEL`,
default `phi3:mini`) pulled. Without Ollama running, `/api/scan/text` returns
`503 Message analysis is temporarily unavailable`.

---

## 🖥 Usage

- **Text/message check** → `POST /api/scan/text {"text": "..."}` → `{"tag": "...", "message": "..."}`
- **Link check** → `POST /api/scan/link {"url": "..."}`
- **Community registry** → see `/docs` (Swagger UI) for the full `/api/community/*` surface.

---

## 📜 License

MIT License – free to use and modify with attribution.
