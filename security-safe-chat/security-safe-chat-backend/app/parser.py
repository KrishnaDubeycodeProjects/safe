"""
parser.py — Compact output parser for the scam classification engine.

Converts the single-line model output into a structured Python dict
that the API response can serialize directly.

Supported formats
─────────────────
Case 1 (single match):   X.X.X|key=val,key=val,...
Case 2 (multi-match):    multi:X.X.X+X.X.X+...|key=val,...
Case 3 (generic scam):   gen|key=val,...
Case 4 (ambiguous):      unsure
Case 5 (safe / no scam): err
"""

from __future__ import annotations

import re
from typing import Any

from app.taxonomy import TAXONOMY, TaxonomyEntry

# ── Token regexes ─────────────────────────────────────────────────────────────
_RE_SINGLE = re.compile(r"^(\d+\.\d+\.\d+)\|(.*)$")
_RE_MULTI = re.compile(r"^multi:([\d.+]+)\|(.+)$")
_RE_GEN = re.compile(r"^gen\|(.+)$")
_RE_KV = re.compile(r"([a-z_]+)=([^,]+)")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_kv(raw: str) -> dict[str, str]:
    """Parse a 'key=value,key=value' string into a dict."""
    return {m.group(1): m.group(2).strip() for m in _RE_KV.finditer(raw)}


def _render_template(template: str, entities: dict[str, str]) -> str:
    """Fill {placeholder} tokens in a detection template with extracted values.

    Missing placeholders are left as-is so the message is still readable.
    """
    result = template
    for k, v in entities.items():
        result = result.replace(f"{{{k}}}", v)
    # Remove unfilled placeholders (e.g. {name} when name wasn't in message)
    result = re.sub(r"\{[a-z_]+\}", "[unknown]", result)
    return result


def _enrich(entry: TaxonomyEntry, entities: dict[str, str]) -> dict[str, Any]:
    """Build a rich result dict from a taxonomy entry + extracted entities."""
    return {
        "id": entry["id"],
        "label": entry["label"],
        "category": entry["category"],
        "subcategory": entry["subcategory"],
        "verdict": entry["verdict"],
        "score": entry["score"],
        "red_flags": entry["red_flags"],
        "detection_message": _render_template(entry["detection_template"], entities),
        "entities": entities,
    }


def _merged_entities(ids: list[str], entities: dict[str, str]) -> dict[str, str]:
    """Return entities, keeping only keys that are valid placeholders for ANY of the given ids."""
    allowed: set[str] = set()
    for tid in ids:
        entry = TAXONOMY.get(tid)
        if entry:
            allowed.update(entry["placeholders"])
    return {k: v for k, v in entities.items() if k in allowed}


# ── Public API ────────────────────────────────────────────────────────────────

def parse(raw_line: str) -> dict[str, Any]:
    """
    Parse one line of model output and return a structured result dict.

    Return schema
    ─────────────
    {
        "case":    int,          # 1–5
        "is_scam": bool,
        "matches": list[dict],   # enriched taxonomy entries (empty for gen/err/unsure)
        "entities": dict,        # flat extracted key=value pairs
        "raw":     str,          # original line from model
        # Case 3 only:
        "generic_scam": bool,
        # Case 4 only:
        "ambiguous": bool,
    }
    """
    line = raw_line.strip()

    # ── Case 5: safe ──────────────────────────────────────────────────────────
    if line == "err":
        return {
            "case": 5,
            "is_scam": False,
            "matches": [],
            "entities": {},
            "raw": line,
        }

    # ── Case 4: ambiguous ────────────────────────────────────────────────────
    if line == "unsure":
        return {
            "case": 4,
            "is_scam": False,
            "ambiguous": True,
            "matches": [],
            "entities": {},
            "raw": line,
        }

    # ── Case 3: generic scam ─────────────────────────────────────────────────
    m = _RE_GEN.match(line)
    if m:
        entities = _parse_kv(m.group(1))
        return {
            "case": 3,
            "is_scam": True,
            "generic_scam": True,
            "matches": [],
            "entities": entities,
            "raw": line,
            "detection_message": (
                "This message has strong scam indicators but does not match a specific known scam type. "
                "Exercise extreme caution and do not share personal or financial information."
            ),
        }

    # ── Case 2: multi-type ───────────────────────────────────────────────────
    m = _RE_MULTI.match(line)
    if m:
        ids = [i for i in m.group(1).split("+") if i]
        entities = _parse_kv(m.group(2))
        matches = []
        for tid in ids:
            entry = TAXONOMY.get(tid)
            if entry:
                # filter entities to only this entry's placeholders
                local_ent = {k: v for k, v in entities.items() if k in entry["placeholders"]}
                matches.append(_enrich(entry, local_ent))
            else:
                # Unknown ID — include minimal info
                matches.append({
                    "id": tid,
                    "label": f"Unknown type ({tid})",
                    "verdict": "Definitely a scam",
                    "score": 100,
                    "red_flags": [],
                    "detection_message": "Unknown scam type detected.",
                    "entities": entities,
                })
        highest_score = max((x["score"] for x in matches), default=100)
        return {
            "case": 2,
            "is_scam": True,
            "matches": matches,
            "entities": entities,
            "score": highest_score,
            "raw": line,
        }

    # ── Case 1: single type ──────────────────────────────────────────────────
    m = _RE_SINGLE.match(line)
    if m:
        tid = m.group(1)
        entities = _parse_kv(m.group(2))
        entry = TAXONOMY.get(tid)
        if entry:
            # Filter to allowed placeholders
            allowed_ent = {k: v for k, v in entities.items() if k in entry["placeholders"]}
            result = _enrich(entry, allowed_ent)
        else:
            result = {
                "id": tid,
                "label": f"Unknown type ({tid})",
                "verdict": "Definitely a scam",
                "score": 100,
                "red_flags": [],
                "detection_message": "A scam was detected but the type could not be looked up.",
                "entities": entities,
            }
        return {
            "case": 1,
            "is_scam": True,
            "matches": [result],
            "entities": result.get("entities", entities),
            "score": result.get("score", 100),
            "raw": line,
        }

    # ── Fallback: unparseable output ─────────────────────────────────────────
    return {
        "case": 4,
        "is_scam": False,
        "ambiguous": True,
        "matches": [],
        "entities": {},
        "raw": line,
        "parse_error": f"Model output did not match any expected format: {line!r}",
    }
