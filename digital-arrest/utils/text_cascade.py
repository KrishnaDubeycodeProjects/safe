# utils/text_cascade.py
import re
import unicodedata
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    np = None
    HAS_NUMPY = False
from typing import Dict, List, Tuple, Optional
import logging
from utils.rag_utils import is_ollama_available, query_ollama, rag_verify_text

logger = logging.getLogger("safe_backend.text_cascade")

KNOWN_SCAMS_DB = [
    "Dear customer, your SBI bank account is blocked due to KYC documents pending. Click here http://bit.ly/sbi-kyc-verify to update.",
    "Congratulations! You have won a cash prize of 25,00,000 rupees in KBC Lucky Draw. Contact our manager on WhatsApp +91-9988776655 to claim.",
    "Part-time job offer: Earn 5000 to 10000 rupees daily by liking YouTube videos. No experience required. Message us on Telegram now.",
    "Your electricity bill is unpaid. Power connection will be disconnected tonight. Call electricity department customer support immediately at 1800-xxx-xxxx.",
    "This is CBI officer calling. You are under digital arrest. Do not disconnect the video call. Transfer security deposit to bank account immediately.",
    "Your parcel from FedEx contains illegal drugs and has been seized by customs. Call Mumbai Police immediately to resolve this case.",
    "UPI payment of 5000 rupees has failed. Scan this QR code immediately to receive your refund in bank account.",
    "Urgent technical support: Your computer has been hacked. Call Windows Support helpline immediately to secure your files."
]

WHITELIST_PATTERNS = [
    r"^your OTP for.*transaction is \d{4,8}$"
]


class TextCascade:
    def __init__(self, text_model, vectorizer, sentiment_analyzer):
        self.text_model = text_model
        self.vectorizer = vectorizer
        self.sent_analyzer = sentiment_analyzer

        self.known_scams_tfidf = None
        if self.vectorizer:
            try:
                self.known_scams_tfidf = self.vectorizer.transform(KNOWN_SCAMS_DB)
            except Exception as e:
                logger.error(f"Failed to vectorize scam DB: {e}")

    def normalize_text(self, text: str) -> str:
        """Layer 0: Unicode normalization and cleanup."""
        normalized = unicodedata.normalize("NFKC", text)
        normalized = re.sub(r'[\u200b-\u200d\ufeff]', '', normalized)
        normalized = re.sub(r'\s+', ' ', normalized).strip()
        return normalized

    def match_rules(self, text: str) -> Tuple[float, Optional[str], List[str]]:
        """Layer 1: Rule-Based / Lexical filters."""
        text_lower = text.lower()

        for pattern in WHITELIST_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return 0.0, "Whitelisted message pattern", ["Message matches trusted whitelist pattern."]

        scam_keywords = {
            "otp": 3.0, "one-time password": 3.0, "cvv": 3.0, "upi pin": 3.0, "aadhaar": 2.5, "aadhar": 2.5,
            "blocked": 2.0, "suspended": 2.0, "kyc": 2.5, "lucky draw": 3.0, "lottery": 3.0, "won": 2.0,
            "digital arrest": 3.0, "cbi": 2.5, "customs": 2.0, "drugs": 1.5, "refund": 2.0, "click here": 1.5,
            "verify": 1.5, "urgent": 2.0, "immediate": 2.0, "seized": 2.0, "electricity bill": 2.5, "disconnect": 2.0
        }

        found_keywords = []
        score = 0.0
        for kw, weight in scam_keywords.items():
            if re.search(r'\b' + re.escape(kw) + r'\b', text_lower):
                found_keywords.append(kw)
                score += weight

        has_link = 1.0 if re.search(r'https?://|www\.', text_lower) else 0.0
        has_phone = 1.0 if re.search(r'\b\d{10}\b|\+\d{12}', text_lower) else 0.0

        heuristic_score = score + (has_link * 2.0) + (has_phone * 1.5)

        if heuristic_score >= 6.0:
            reasons = [f"Found high-risk terms: {', '.join(found_keywords)}."]
            if has_link:
                reasons.append("Contains a web link.")
            if has_phone:
                reasons.append("Contains a phone number.")
            return 0.95, "Layer 1 (Lexical Rule Match)", reasons

        return heuristic_score / 10.0, None, found_keywords

    def run_ml_model(self, text: str) -> float:
        """Layer 2: Statistical / Classical ML."""
        if not self.text_model or not self.vectorizer:
            return 0.0
        try:
            vec = self.vectorizer.transform([text])
            ml_prob = float(self.text_model.predict_proba(vec)[0][1])
            return ml_prob
        except Exception as e:
            logger.error(f"Error running Layer 2 ML Model: {e}")
            return 0.0

    def check_embeddings_similarity(self, text: str) -> float:
        """Layer 3: Embedding / Vector Space Cosine Similarity against known scams."""
        if not self.vectorizer or self.known_scams_tfidf is None:
            return 0.0
        try:
            vec = self.vectorizer.transform([text])
            sims = (self.known_scams_tfidf * vec.T).toarray().flatten()
            max_sim = float(np.max(sims))
            return max_sim
        except Exception as e:
            logger.error(f"Error in Layer 3 similarity lookup: {e}")
            return 0.0

    def query_llm_reasoning(self, text: str, ml_prob: float, keywords: List[str], sentiment: dict) -> dict:
        """Layer 4: LLM-based reasoning (last resort)."""
        try:
            if is_ollama_available():
                return rag_verify_text(text, ml_prob, keywords, sentiment)
        except Exception as e:
            logger.error(f"Error in Layer 4 Ollama reasoning: {e}")
        return {}

    def scan(self, raw_text: str) -> dict:
        """Execute the full tiered cascade pipeline."""
        steps_executed = []

        steps_executed.append("Layer 0: Preprocessing & Normalization")
        clean_text = self.normalize_text(raw_text)

        steps_executed.append("Layer 1: Rule-Based & Lexical Heuristics")
        rule_prob, rule_flag, rule_details = self.match_rules(clean_text)

        if rule_flag == "Whitelisted message pattern":
            logger.info("Text scan completed at Layer 1: Whitelist Match")
            return {
                "label": "✅ Likely Safe",
                "score": 1.0,
                "combined_prob": 0.05,
                "explanation": "Verified safe via automated sender whitelist check.",
                "actionSteps": ["This pattern matches regular system communications.", "Stay vigilant and verify caller identity."],
                "cascade_steps": steps_executed
            }

        if rule_prob >= 0.9:
            logger.info("Text scan completed at Layer 1: High Confidence Heuristics")
            return {
                "label": "🚨 Likely Scam",
                "score": 0.05,
                "combined_prob": rule_prob,
                "explanation": f"Automated heuristics flagged suspicious elements: {'; '.join(rule_details)}",
                "actionSteps": ["Do not share OTPs, card details, or click links.", "Block and report this number immediately."],
                "cascade_steps": steps_executed
            }

        steps_executed.append("Layer 2: Statistical ML Classification")
        ml_prob = self.run_ml_model(clean_text)

        if ml_prob > 0.85 or ml_prob < 0.15:
            logger.info(f"Text scan completed at Layer 2: ML Confidence {ml_prob}")
            label = "🚨 Likely Scam" if ml_prob > 0.85 else "✅ Likely Safe"
            verdict_score = max(0.1, min(0.9, 1.0 - ml_prob))
            return {
                "label": label,
                "score": verdict_score,
                "combined_prob": ml_prob,
                "explanation": f"Statistical model classified message with high confidence.",
                "actionSteps": ["Check for known scam patterns before reacting.", "Verify sender identity manually."] if ml_prob > 0.85 else ["Stay alert, as some new scams can evade classifiers."],
                "cascade_steps": steps_executed
            }

        steps_executed.append("Layer 3: TF-IDF Embedding Similarity Search")
        sim_score = self.check_embeddings_similarity(clean_text)
        if sim_score > 0.75:
            logger.info(f"Text scan completed at Layer 3: Similarity Score {sim_score}")
            return {
                "label": "🚨 Likely Scam",
                "score": 0.1,
                "combined_prob": max(ml_prob, sim_score),
                "explanation": "High similarity matching text signature found in the local scam pattern database.",
                "actionSteps": ["Do not follow instructions in this message.", "Report this scam text immediately."],
                "cascade_steps": steps_executed
            }

        steps_executed.append("Layer 4: LLM-based Agentic Reasoning")
        sentiment = self.sent_analyzer.polarity_scores(clean_text)
        keywords_list = rule_details if isinstance(rule_details, list) else []

        llm_response = self.query_llm_reasoning(clean_text, ml_prob, keywords_list, sentiment)

        if llm_response and llm_response.get("llm_prob") is not None:
            llm_prob = float(llm_response["llm_prob"])
            logger.info(f"Text scan completed at Layer 4: LLM Probability {llm_prob}")
            label = "🚨 Likely Scam" if llm_prob > 0.45 else "✅ Likely Safe"
            return {
                "label": label,
                "score": max(0.1, min(0.9, 1.0 - llm_prob)),
                "combined_prob": llm_prob,
                "explanation": llm_response.get("explanation") or "AI analyzed intent and potential risk factor.",
                "actionSteps": llm_response.get("advice") or ["Be careful with unsolicited communications."],
                "cascade_steps": steps_executed
            }

        logger.info("Text scan completed at Fallback Aggregator")
        combined_prob = (ml_prob * 0.6) + (rule_prob * 0.4)
        label = "🚨 Likely Scam" if combined_prob > 0.4 else "✅ Likely Safe"
        return {
            "label": label,
            "score": max(0.1, min(0.9, 1.0 - combined_prob)),
            "combined_prob": combined_prob,
            "explanation": "Combined statistical and pattern check completed. No advanced anomalies found.",
            "actionSteps": ["Always double check with official sources.", "Do not click links from unknown senders."],
            "cascade_steps": steps_executed
        }