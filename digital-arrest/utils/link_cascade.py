import re
import urllib.parse
import socket
import requests
import ssl
import json
from typing import Dict, List, Tuple, Optional
import logging
from datetime import datetime, timezone
from utils.rag_utils import is_ollama_available, query_ollama
from utils.feedback_loop import get_url_reputation_override

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
    def __init__(self):
        pass

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
        """Layer 5: LLM-based phishing intent check."""
        if not is_ollama_available():
            return {}

        domain_age_info = ""
        if "domain_age_days" in data:
            domain_age_info = f"Domain age: {data['domain_age_days']} days"
        
        ssl_info = ""
        if "ssl_valid" in data:
            ssl_info = f"SSL valid: {data['ssl_valid']}, Issuer: {data.get('ssl_issuer', 'Unknown')}"

        prompt = f"""
You are SafeLink Assistant. Analyze the following URL domain and heuristics to decide if it is a phishing / scam landing page.

URL to scan: {data["original_url"]}
Destination domain: {data["decoded_domain"]}
Redirected URL: {data["final_url"]} if {data["redirected"]} else "None"
{domain_age_info}
{ssl_info}

Suspicious indicators detected:
{chr(10).join(f"- {h}" for h in (heuristics + dom_reasons))}

Task:
1) Classify the URL as "Likely Scam" or "Likely Safe".
2) Give a numeric estimate of risk as a percent (0-100).
3) Explain why in 1-2 sentences.
4) Suggest 2 short recommendations for the user.

Output JSON exactly with keys: verdict, risk_percent, explanation, advice (list of strings).
"""
        try:
            resp = query_ollama(prompt, max_tokens=256, temperature=0.0)
            text_out = resp.get("text", "")
            start = text_out.find("{")
            end = text_out.rfind("}")
            if start != -1 and end != -1:
                parsed = json.loads(text_out[start:end+1])
                return parsed
        except Exception as e:
            logger.error(f"Error querying LLM in LinkCascade: {e}")
        return {}

    def scan(self, url: str) -> dict:
        """Run URL cascade pipeline with enhanced security checks."""
        steps = []

        steps.append("Layer 0: Parsing & Punycode Normalization")
        data = self.parse_and_normalize(url)
        domain = data["decoded_domain"]

        steps.append("Layer 1: Blocklist & Reputation Lookups")
        list_prob, list_verdict = self.check_blocklists_and_whitelist(domain)
        if list_verdict == "whitelisted":
            return {
                "label": "✅ Likely Safe",
                "score": 1.0,
                "combined_prob": 0.02,
                "explanation": f"Domain '{domain}' is verified as an official trusted website on our whitelist.",
                "actionSteps": ["This link is verified to belong to a legitimate service.", "Always verify page contents directly."],
                "cascade_steps": steps
            }
        elif list_verdict == "blocked_list":
            return {
                "label": "🚨 Likely Scam",
                "score": 0.05,
                "combined_prob": 0.99,
                "explanation": f"Link is verified on our global blocklist of active phishing and scam domains.",
                "actionSteps": ["Do not click this link or provide details.", "Close this tab immediately."],
                "cascade_steps": steps
            }

        steps.append("Layer 2: Domain Reputation (Age & SSL)")
        domain_rep_score, domain_rep_reasons = self.check_domain_reputation(data)

        steps.append("Layer 3: Lexical Heuristics & Typosquatting Check")
        h_score, h_reasons = self.calculate_heuristics(data)

        if h_score >= 5.5:
            return {
                "label": "🚨 Likely Scam",
                "score": 0.1,
                "combined_prob": min(0.95, h_score / 6.0),
                "explanation": f"Phishing indicators detected: {'; '.join(h_reasons)}",
                "actionSteps": ["Do not click or enter passwords.", "This domain appears to be spoofing a trusted service."],
                "cascade_steps": steps
            }

        steps.append("Layer 4: HEAD Landing Page Form & Brand Validation")
        dom_prob, dom_reasons = self.analyze_landing_page(data)

        combined_heur_prob = (h_score / 10.0) + (domain_rep_score / 10.0) + dom_prob

        if combined_heur_prob >= 0.7:
            return {
                "label": " Likely Scam",
                "score": 0.15,
                "combined_prob": combined_heur_prob,
                "explanation": f"Web analysis revealed serious phishing concerns: {'; '.join(h_reasons + domain_rep_reasons + dom_reasons)}",
                "actionSteps": ["This link mimics official login structures.", "Verify bank services only using official customer applications."],
                "cascade_steps": steps
            }

        if combined_heur_prob < 0.15:
            return {
                "label": "✅ Likely Safe",
                "score": 0.9,
                "combined_prob": combined_heur_prob,
                "explanation": "No typosquatting, blocklist flags, or credential inputs detected.",
                "actionSteps": ["The link appears safe.", "Still avoid downloading files from unknown domains."],
                "cascade_steps": steps
            }

        steps.append("Layer 5: LLM-based Phishing Intent Reasoning")
        llm_res = self.ask_llm_reasoning(data, h_reasons + domain_rep_reasons, dom_reasons)
        if llm_res and "risk_percent" in llm_res:
            try:
                llm_prob = float(llm_res["risk_percent"]) / 100.0
                label = "🚨 Likely Scam" if llm_prob > 0.45 else "✅ Likely Safe"
                return {
                    "label": label,
                    "score": max(0.1, min(0.9, 1.0 - llm_prob)),
                    "combined_prob": llm_prob,
                    "explanation": llm_res.get("explanation") or "AI verification analyzed risk profile.",
                    "actionSteps": llm_res.get("advice") or ["Exercise care before inserting credentials."],
                    "cascade_steps": steps
                }
            except Exception:
                pass

        combined_prob = max(0.1, min(0.9, combined_heur_prob))
        label = "🚨 Likely Scam" if combined_prob > 0.35 else "✅ Likely Safe"
        return {
            "label": label,
            "score": max(0.1, min(0.9, 1.0 - combined_prob)),
            "combined_prob": combined_prob,
            "explanation": "Completed heuristic evaluations. Suspicious elements found, proceed with caution.",
            "actionSteps": ["Verify domain name spelling carefully.", "Never enter banking pins or OTPs on links from SMS."],
            "cascade_steps": steps
        }