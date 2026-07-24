"""
routes.py — DEPRECATED

All routes have been consolidated into app/main.py as part of the
merge with Digital-arrest-detector (v2.0.0).

This file is kept for reference only and is NOT imported anywhere.
Delete it once the migration is confirmed stable.

Previous endpoints (now in main.py):
  POST /analyze/text
  POST /analyze/image
  POST /analyze/base64
  GET  /health
  GET  /

New endpoints added in main.py:
  POST /api/scan/text      ← cascade: keyword heuristics + Bedrock layer 2
  POST /api/scan/link      ← cascade: link analysis + typosquatting detection
  POST /api/scan/image     ← cascade: OCR.space + text/link + CV analysis
  POST /api/feedback       ← Gmail OAuth feedback archiver
"""
