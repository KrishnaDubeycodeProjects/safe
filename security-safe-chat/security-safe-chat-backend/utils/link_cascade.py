import re
import urllib.parse
import socket
import requests
import ssl
import json
from typing import Dict, List, Tuple, Optional
import logging
from datetime import datetime, timezone
# Ollama / RAG removed — LLM analysis handled by AWS Bedrock in text_cascade.py
def is_ollama_available() -> bool: return False
def query_ollama(*a, **kw) -> dict: return {}
def get_url_reputation_override(domain: str) -> float: return -1.0   # -1 = no override

logger = logging.getLogger("safe_backend.link_cascade")

TOP_BRANDS = [
    "sbi", "hdfc", "icici", "paytm", "phonepe", "gpay", "amazon", "flipkart",
    "google", "facebook", "whatsapp", "apple", "netflix", "paypal", "microsoft",
    "cibil", "cred", "axis", "kotak", "bob", "pnb", "canara", "union",
    "indianbank", "federal", "yesbank", "idbi", "boi", "centralbank"
]

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".info", ".loan", ".work", ".click", ".gq", ".tk", ".cf", ".ga", ".ml", ".bid",
    ".zip", ".mov", ".country", ".kim", ".cricket", ".science", ".party", ".webcam", ".date",
    ".review", ".accountant", ".faith", ".download", ".racing", ".win", ".stream"
}

URL_BLOCKLIST = [
    "secure-bank-login.com",
    "kbc-lottery-winner.in",
    "sbi-kyc-update.com",
    "earn-money-online.xyz",
    "whatsapp-chat-support.top"
]

URL_WHITELIST = [
    "google.com", "github.com", "microsoft.com", "apple.com", "amazon.in",
    "amazon.com", "flipkart.com", "paytm.com", "phonepe.com", "cybercrime.gov.in",
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com", "kotak.com",
    "onlinesbi.com", "netbanking", "rbi.org.in", "sebi.gov.in", "mca.gov.in",
    "uidai.gov.in", "income tax", "gst.gov.in", "epfindia.gov.in"
]


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def check_domain_age(domain: str) -> Tuple[Optional[int], Optional[str]]:
    """Check domain age using WHOIS lookup."""
    try:
        import whois
        w = whois.whois(domain)
        
        if w.creation_date:
            creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            
            if creation_date:
                if creation_date.tzinfo is None:
                    creation_date = creation_date.replace(tzinfo=timezone.utc)
                
                now = datetime.now(timezone.utc)
                age_days = (now - creation_date).days
                return age_days, None
        
        return None, "No creation date found in WHOIS"
    except Exception as e:
        logger.warning(f"WHOIS lookup failed for {domain}: {e}")
        return None, str(e)


def validate_ssl_certificate(domain: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """Validate SSL certificate for the domain."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                issuer = None
                for field in cert.get('issuer', []):
                    for key, value in field:
                        if key == 'organizationName':
                            issuer = value
                            break
                
                not_after = cert.get('notAfter')
                if not_after:
                    expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    if expiry_date < datetime.now():
                        return False, issuer, "Certificate expired"
                
                return True, issuer, None
    except ssl.SSLCertVerificationError as e:
        return False, None, f"SSL verification failed: {e}"
    except socket.timeout:
        return False, None, "Connection timeout"
    except Exception as e:
        return False, None, str(e)


class LinkCascade:
    def __init__(self, bedrock_client=None, parser=None):
        """
        Parameters
        ----------
        bedrock_client : module | None
            Pass the app.bedrock module — exposes classify_text(text) -> str.
        parser : module | None
            Pass the app.parser module — exposes parse(raw) -> dict.
        If either is None the cascade falls back to heuristic-only labels.
        """
        self.bedrock = bedrock_client
        self.parser = parser

    # ── LLM response helpers ──────────────────────────────────────────────────

    def _llm_label(self, parsed: dict, combined_prob: float) -> str:
        """Derive a label from the parser result."""
        if parsed.get("is_scam"):
            return "🚨 Likely Scam"
        if parsed.get("ambiguous"):
            return "⚠️ Uncertain"
        return "✅ Likely Safe" if combined_prob < 0.35 else "🚨 Likely Scam"

    def _llm_explanation(self, parsed: dict, heuristic_fallback: str) -> str:
        """Pull detection_message from parser result, fall back to heuristics."""
        matches = parsed.get("matches") or []
        if matches:
            msg = matches[0].get("detection_message", "")
            if msg:
                return msg
        return parsed.get("detection_message") or heuristic_fallback

    def _llm_action_steps(self, parsed: dict, fallback: list) -> list:
        """Pull red_flags from parser result as actionSteps, fall back to heuristics."""
        matches = parsed.get("matches") or []
        if matches:
            flags = matches[0].get("red_flags", [])
            if flags:
                return flags
        return fallback

    def parse_and_normalize(self, url: str) -> Dict:
        """Layer 0: URL parsing, punycode decoding, and redirect resolution."""
        if not re.match(r'^https?://', url, re.IGNORECASE):
            url_to_parse = "http://" + url
        else:
            url_to_parse = url

        parsed = urllib.parse.urlparse(url_to_parse)
        domain = parsed.netloc.split(':')[0]
        
        try:
            decoded_domain = domain.encode('utf-8').decode('idna')
        except Exception:
            decoded_domain = domain

        final_url = url
        redirected = False
        redirect_chain = []
        
        if any(shortener in domain.lower() for shortener in ["bit.ly", "tinyurl.com", "t.co", "rebrand.ly", "cutt.ly", "shorturl.at", "is.gd"]):
            try:
                resp = requests.head(url_to_parse, allow_redirects=True, timeout=3.0)
                final_url = resp.url
                redirected = True
                for r in resp.history:
                    redirect_chain.append(r.url)
            except Exception as e:
                logger.warning(f"Could not resolve redirect for {url}: {e}")

        return {
            "original_url": url_to_parse,
            "parsed_domain": domain,
            "decoded_domain": decoded_domain,
            "final_url": final_url,
            "redirected": redirected,
            "redirect_chain": redirect_chain,
            "path": parsed.path,
            "query": parsed.query,
            "is_https": url_to_parse.startswith("https://")
        }

    def check_blocklists_and_whitelist(self, domain: str) -> Tuple[Optional[float], Optional[str]]:
        """Layer 1: Lookup whitelists and blocklists."""
        domain_lower = domain.lower()

        override = get_url_reputation_override(domain_lower)
        if override == "scam":
            return 1.0, "blocked_list"
        if override == "safe":
            return 0.0, "whitelisted"

        for item in URL_WHITELIST:
            if domain_lower == item or domain_lower.endswith("." + item):
                return 0.0, "whitelisted"

        for item in URL_BLOCKLIST:
            if domain_lower == item or domain_lower.endswith("." + item):
                return 1.0, "blocked_list"

        return None, None

    def detect_typosquatting(self, domain: str) -> Tuple[bool, Optional[str]]:
        """Check if a domain is a brand typosquatting / lookalike attack."""
        domain_parts = domain.lower().split('.')
        if len(domain_parts) > 1:
            sld = domain_parts[-2]
            if sld in ["com", "co", "org", "net", "gov", "mil", "edu"] and len(domain_parts) > 2:
                sld = domain_parts[-3]
        else:
            sld = domain_parts[0]

        for brand in TOP_BRANDS:
            if brand in sld and sld != brand:
                return True, brand
            dist = levenshtein_distance(sld, brand)
            if dist == 1:
                return True, brand

        return False, None

    def check_domain_reputation(self, data: Dict) -> Tuple[float, List[str]]:
        """Layer 2: Domain reputation checks (age, SSL, etc.)."""
        domain = data["decoded_domain"]
        reasons = []
        score = 0.0

        age_days, age_error = check_domain_age(domain)
        if age_days is not None:
            if age_days < 30:
                score += 3.0
                reasons.append(f"Domain is very new ({age_days} days old). Newly registered domains are commonly used for scams.")
            elif age_days < 90:
                score += 1.5
                reasons.append(f"Domain is relatively new ({age_days} days old).")
            data["domain_age_days"] = age_days
        else:
            logger.warning(f"Could not determine domain age: {age_error}")

        if data["is_https"]:
            ssl_valid, ssl_issuer, ssl_error = validate_ssl_certificate(domain)
            if not ssl_valid:
                score += 2.0
                reasons.append(f"SSL certificate issue: {ssl_error}")
            elif ssl_issuer:
                suspicious_issuers = ["Let's Encrypt", "Free SSL", "Self-Signed"]
                if any(suspicious in ssl_issuer for suspicious in suspicious_issuers):
                    score += 0.5
                    reasons.append(f"SSL certificate issued by free/anonymous provider: {ssl_issuer}")
            data["ssl_valid"] = ssl_valid
            data["ssl_issuer"] = ssl_issuer

        return score, reasons

    def calculate_heuristics(self, data: Dict) -> Tuple[float, List[str]]:
        """Layer 3: Heuristics & Statistical features."""
        domain = data["decoded_domain"].lower()
        path = data["path"].lower()
        reasons = []
        score = 0.0

        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                score += 2.0
                reasons.append(f"Uses a suspicious top-level domain ({tld}) commonly associated with scams.")
                break

        dot_count = domain.count('.')
        if dot_count > 3:
            score += 1.5
            reasons.append("Contains a high number of subdomains, which is typical for phishing URL masks.")

        if '@' in data["original_url"]:
            score += 3.0
            reasons.append("Contains an '@' symbol, which can hide the real destination domain.")

        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, domain):
            score += 3.0
            reasons.append("Uses a raw IP address instead of a domain name to bypass host reputation checks.")

        is_typo, brand_matched = self.detect_typosquatting(domain)
        if is_typo:
            score += 4.0
            reasons.append(f"Lookalike domain closely matches the registered brand '{brand_matched}'.")

        suspicious_keywords = ["login", "verify", "secure", "update", "account", "kyc", "signin", "banking", "password", "otp"]
        matched_words = [word for word in suspicious_keywords if word in path]
        if matched_words:
            score += 1.0 * len(matched_words)
            reasons.append(f"URL path contains banking/credential harvest keywords: {', '.join(matched_words)}.")

        if domain.count('-') > 3:
            score += 1.0
            reasons.append("Domain contains excessive hyphens, common in phishing URLs.")
        
        if re.search(r'\d{3,}', domain):
            score += 0.5
            reasons.append("Domain contains long numeric sequences, often used to evade filters.")

        return score, reasons

    def analyze_landing_page(self, data: Dict) -> Tuple[float, List[str]]:
        """Layer 4: DOM / Content structure analysis with enhanced phishing detection."""
        url = data["final_url"]
        domain = data["decoded_domain"]
        reasons = []
        scam_prob = 0.0

        # Only skip if EXPLICITLY whitelisted
        w_prob, verdict = self.check_blocklists_and_whitelist(domain)
        if verdict == "whitelisted":
            return 0.0, []

        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1"
            }
            resp = requests.get(url, headers=headers, timeout=5.0, stream=True, allow_redirects=True)
            
            html_chunk = resp.raw.read(20480).decode('utf-8', errors='ignore')
            html_lower = html_chunk.lower()

            # Check for password fields
            if "type=\"password\"" in html_lower or "type='password'" in html_lower:
                scam_prob += 0.3
                reasons.append("Web page contains a password input field.")

            # Check for OTP/verification code fields
            if "otp" in html_lower or "one time password" in html_lower or "verification code" in html_lower:
                scam_prob += 0.25
                reasons.append("Web page requests verification code or OTP.")

            # Check for credit card fields
            if "credit card" in html_lower or "card number" in html_lower or "cvv" in html_lower:
                scam_prob += 0.3
                reasons.append("Web page requests credit card information.")

            # ✅ FIXED: Brand impersonation check INSIDE try block with correct logic
            for brand in TOP_BRANDS:
                brand_in_html = brand in html_lower
                is_official_domain = any(
                    domain.lower() == official or domain.lower().endswith("." + official)
                    for official in URL_WHITELIST 
                    if brand in official.lower()
                )
                
                if brand_in_html and not is_official_domain:
                    scam_prob += 0.3
                    reasons.append(
                        f"Web page references brand '{brand}' but is hosted on an unverified "
                        f"domain '{domain}' that is not in our trusted whitelist."
                    )

            # Check for suspicious forms
            if "<form" in html_lower:
                form_action_match = re.search(r'<form[^>]*action=["\']([^"\']+)["\']', html_lower)
                if form_action_match:
                    form_action = form_action_match.group(1)
                    if "http" in form_action and domain not in form_action:
                        scam_prob += 0.2
                        reasons.append("Form submits data to an external domain.")

            # Check for urgency language
            urgency_keywords = ["urgent", "immediately", "act now", "limited time", "expires", "suspended", "blocked"]
            urgency_count = sum(1 for kw in urgency_keywords if kw in html_lower)
            if urgency_count > 2:
                scam_prob += 0.2
                reasons.append("Page contains urgency/threat language designed to pressure users.")

            # Check for hidden iframes
            if "<iframe" in html_lower and "display:none" in html_lower:
                scam_prob += 0.15
                reasons.append("Page contains hidden iframes, often used for malicious redirects.")

            # Check for suspicious JavaScript
            if "eval(" in html_lower or "document.write" in html_lower:
                scam_prob += 0.1
                reasons.append("Page contains suspicious JavaScript that could execute malicious code.")

        except requests.exceptions.Timeout:
            reasons.append("Page took too long to load (timeout).")
        except requests.exceptions.ConnectionError:
            reasons.append("Could not connect to the page.")
        except Exception as e:
            logger.warning(f"Could not analyze landing page {url}: {e}")

        return scam_prob, reasons

    def ask_llm_reasoning(self, data: Dict, heuristics: List[str], dom_reasons: List[str]) -> Dict:
        """
        Layer 5: AWS Bedrock phishing-intent classification.

        Builds a natural-language context string from the URL data and all
        heuristic flags, then sends it to Bedrock via classify_text().
        The raw output is parsed by parser.parse() and the full structured
        result (detection_message, red_flags, is_scam, score) is returned
        so the caller can use real LLM data instead of hardcoded strings.
        """
        if not self.bedrock or not self.parser:
            return {}

        all_flags = heuristics + dom_reasons
        flags_text = "\n".join(f"- {f}" for f in all_flags) if all_flags else "None detected."

        # Build a synthetic message that describes the URL to the scam classifier
        context_message = (
            f"[URL Phishing Analysis]\n"
            f"Original URL: {data.get('original_url', 'unknown')}\n"
            f"Decoded domain: {data.get('decoded_domain', 'unknown')}\n"
            f"Final URL (after redirect): {data.get('final_url', 'unknown')}\n"
            f"SSL valid: {data.get('ssl_valid', 'unknown')}\n"
            f"Domain age: {data.get('domain_age_days', 'unknown')} days\n"
            f"Suspicious indicators found:\n{flags_text}"
        )

        try:
            import asyncio
            # Run the async classify_text in a thread-safe way
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    import concurrent.futures
                    with concurrent.futures.ThreadPoolExecutor() as pool:
                        raw = pool.submit(asyncio.run, self.bedrock.classify_text(context_message)).result(timeout=20)
                else:
                    raw = loop.run_until_complete(self.bedrock.classify_text(context_message))
            except RuntimeError:
                raw = asyncio.run(self.bedrock.classify_text(context_message))

            parsed = self.parser.parse(raw)
            logger.info("Bedrock link analysis: case=%s is_scam=%s", parsed.get('case'), parsed.get('is_scam'))
            return parsed   # full parser dict: case, is_scam, matches, detection_message, etc.
        except Exception as exc:
            logger.warning("Bedrock link reasoning failed: %s", exc)
            return {}

    def _build_return(self, label: str, combined_prob: float, explanation: str,
                      action_steps: list, steps: list, meta: dict = None,
                      llm_parsed: dict = None) -> dict:
        """
        Unified return builder.
        If llm_parsed (Bedrock parser result) is available, explanation and
        actionSteps are pulled from the real LLM response — not hardcoded strings.
        """
        if llm_parsed:
            explanation = self._llm_explanation(llm_parsed, explanation)
            action_steps = self._llm_action_steps(llm_parsed, action_steps)
            label = self._llm_label(llm_parsed, combined_prob)

        return {
            "label": label,
            "score": max(0.05, min(0.95, 1.0 - combined_prob)),
            "combined_prob": round(combined_prob, 4),
            "explanation": explanation,
            "actionSteps": action_steps,
            "cascade_steps": steps,
            "meta": meta or {},
            "llm_parsed": llm_parsed,   # expose full parser dict for consumers
        }

    def scan(self, url: str) -> dict:
        """Run URL cascade pipeline with enhanced security checks."""
        steps = []

        steps.append("Layer 0: Parsing & Punycode Normalization")
        data = self.parse_and_normalize(url)
        domain = data["decoded_domain"]

        steps.append("Layer 1: Blocklist & Reputation Lookups")
        meta = {
            "original_url": data.get("original_url"),
            "decoded_domain": domain,
            "final_url": data.get("final_url"),
            "ssl_valid": data.get("ssl_valid"),
            "domain_age_days": data.get("domain_age_days"),
        }
        list_prob, list_verdict = self.check_blocklists_and_whitelist(domain)
        if list_verdict == "whitelisted":
            return self._build_return(
                label="✅ Likely Safe", combined_prob=0.02,
                explanation=f"Domain '{domain}' is verified as an official trusted website.",
                action_steps=["This link is verified to belong to a legitimate service."],
                steps=steps, meta=meta,
            )
        elif list_verdict == "blocked_list":
            return self._build_return(
                label="🚨 Likely Scam", combined_prob=0.99,
                explanation="Link is on our global blocklist of active phishing/scam domains.",
                action_steps=["Do not click this link or provide any details.", "Close this tab immediately."],
                steps=steps, meta=meta,
            )

        steps.append("Layer 2: Domain Reputation (Age & SSL)")
        domain_rep_score, domain_rep_reasons = self.check_domain_reputation(data)

        steps.append("Layer 3: Lexical Heuristics & Typosquatting Check")
        h_score, h_reasons = self.calculate_heuristics(data)

        all_reasons = h_reasons + domain_rep_reasons

        if h_score >= 5.5:
            # High-confidence phishing — still ask LLM to get real messages
            steps.append("Layer 5: LLM Phishing Classification (Bedrock)")
            llm_parsed = self.ask_llm_reasoning(data, all_reasons, [])
            return self._build_return(
                label="🚨 Likely Scam", combined_prob=min(0.95, h_score / 6.0),
                explanation=f"Phishing indicators: {'; '.join(h_reasons)}",
                action_steps=["Do not enter passwords on this page.", "This domain is spoofing a trusted service."],
                steps=steps, meta=meta, llm_parsed=llm_parsed or None,
            )

        steps.append("Layer 4: HEAD Landing Page Form & Brand Validation")
        dom_prob, dom_reasons = self.analyze_landing_page(data)
        all_reasons += dom_reasons

        combined_heur_prob = (h_score / 10.0) + (domain_rep_score / 10.0) + dom_prob

        if combined_heur_prob >= 0.7:
            steps.append("Layer 5: LLM Phishing Classification (Bedrock)")
            llm_parsed = self.ask_llm_reasoning(data, all_reasons, dom_reasons)
            return self._build_return(
                label="🚨 Likely Scam", combined_prob=combined_heur_prob,
                explanation=f"Phishing concerns: {'; '.join(all_reasons)}",
                action_steps=["This link mimics official login structures.", "Verify via official app only."],
                steps=steps, meta=meta, llm_parsed=llm_parsed or None,
            )

        if combined_heur_prob < 0.15:
            return self._build_return(
                label="✅ Likely Safe", combined_prob=combined_heur_prob,
                explanation="No typosquatting, blocklist flags, or credential inputs detected.",
                action_steps=["The link appears safe.", "Still avoid downloading files from unknown domains."],
                steps=steps, meta=meta,
            )

        # Gray zone (0.15–0.70) — LLM decides
        steps.append("Layer 5: LLM Phishing Classification (Bedrock)")
        llm_parsed = self.ask_llm_reasoning(data, all_reasons, dom_reasons)

        if llm_parsed and llm_parsed.get("case"):
            # We have a real Bedrock parser result — use its data for everything
            is_scam = llm_parsed.get("is_scam", False)
            score_val = llm_parsed.get("score")
            llm_prob = (score_val / 100.0) if score_val else combined_heur_prob
            return self._build_return(
                label="🚨 Likely Scam" if is_scam else "✅ Likely Safe",
                combined_prob=llm_prob,
                explanation="AI classification completed.",
                action_steps=["Exercise care before entering credentials."],
                steps=steps, meta=meta, llm_parsed=llm_parsed,
            )

        # Bedrock unavailable — pure heuristic fallback
        combined_prob = max(0.1, min(0.9, combined_heur_prob))
        return self._build_return(
            label="🚨 Likely Scam" if combined_prob > 0.35 else "✅ Likely Safe",
            combined_prob=combined_prob,
            explanation="Heuristic evaluation completed. Bedrock unavailable.",
            action_steps=["Verify domain name spelling carefully.", "Never enter banking PINs or OTPs on links from SMS."],
            steps=steps, meta=meta,
        )