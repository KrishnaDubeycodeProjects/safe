import re
import cv2
import numpy as np
import hashlib
from typing import Dict, List, Tuple, Optional
import logging
import os

try:
    import pytesseract
    HAS_PYTESSERACT = True
except ImportError:
    HAS_PYTESSERACT = False

logger = logging.getLogger("safe_backend.image_cascade")

from utils.feedback_loop import get_image_hash_reputation_override

KNOWN_SCAM_HASHES = {
    "8c8c0e0e0e0e8c8c": "Fake Paytm 5000 Rupees Payment Confirmation",
    "f0f00f0f3c3c0f0f": "Fake Google Pay Cashback Scratch Card",
    "a1a2b3b4c5c6d7d8": "Fake CBI Digital Arrest Warrant Template"
}

# Layer 1: exact-hash blocklist (sha256 -> label)
KNOWN_SCAM_SHA256 = {}


class ImageCascade:
    def __init__(self, text_cascade, link_cascade, deepfake_model=None):
        self.text_cascade = text_cascade
        self.link_cascade = link_cascade
        self.deepfake_model = deepfake_model

    def calculate_dhash(self, img: np.ndarray) -> str:
        """Calculate a 64-bit Difference Hash (dHash) for an image."""
        try:
            resized = cv2.resize(img, (9, 8), interpolation=cv2.INTER_AREA)
            if len(resized.shape) == 3:
                gray = cv2.cvtColor(resized, cv2.COLOR_BGR2GRAY)
            else:
                gray = resized

            diff = gray[:, 1:] > gray[:, :-1]

            decimal_val = 0
            for row in diff:
                for col in row:
                    decimal_val = (decimal_val << 1) | (1 if col else 0)

            hash_hex = f"{decimal_val:016x}"
            return hash_hex
        except Exception as e:
            logger.error(f"Error calculating dHash: {e}")
            return ""

    def calculate_sha256(self, file_path: str) -> str:
        """Calculate SHA256 of the image file for exact blocklist lookup."""
        h = hashlib.sha256()
        try:
            with open(file_path, "rb") as file:
                while chunk := file.read(8192):
                    h.update(chunk)
            return h.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating SHA256: {e}")
            return ""

    def extract_qr_code(self, img: np.ndarray) -> Optional[str]:
        """Detect and decode QR code in the image using OpenCV."""
        try:
            detector = cv2.QRCodeDetector()
            val, points, straight_qrcode = detector.detectAndDecode(img)
            if val:
                logger.info(f"Detected QR Code content: {val}")
                return val
        except Exception as e:
            logger.error(f"Error in OpenCV QR Code detection: {e}")
        return None

    def preprocess_image(self, img: np.ndarray) -> np.ndarray:
        """Advanced image preprocessing for better OCR accuracy."""
        try:
            # Convert to grayscale if color
            if len(img.shape) == 3:
                gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            else:
                gray = img

            # Denoise using Non-local Means Denoising
            denoised = cv2.fastNlMeansDenoising(gray, None, 10, 7, 21)

            # Apply adaptive thresholding for better text contrast
            thresh = cv2.adaptiveThreshold(
                denoised, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                cv2.THRESH_BINARY, 11, 2
            )

            # Morphological operations to clean up noise
            kernel = np.ones((2, 2), np.uint8)
            morph = cv2.morphologyEx(thresh, cv2.MORPH_CLOSE, kernel)

            return morph
        except Exception as e:
            logger.error(f"Error in image preprocessing: {e}")
            return img

    def rotate_image(self, img: np.ndarray, angle: float) -> np.ndarray:
        """Rotate image by given angle."""
        try:
            (h, w) = img.shape[:2]
            center = (w // 2, h // 2)
            M = cv2.getRotationMatrix2D(center, angle, 1.0)
            rotated = cv2.warpAffine(img, M, (w, h), flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_REPLICATE)
            return rotated
        except Exception as e:
            logger.error(f"Error rotating image: {e}")
            return img

    def run_ocr_multi_angle(self, file_path: str) -> str:
        """Run OCR on the image at multiple angles for better text extraction."""
        if not HAS_PYTESSERACT:
            logger.warning("pytesseract is not installed. OCR extraction skipped.")
            return ""
        
        try:
            # Set tesseract path
            tess_paths = [
                r"C:\Program Files\Tesseract-OCR\tesseract.exe",
                r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
                "/usr/bin/tesseract",
                "/usr/local/bin/tesseract",
            ]
            for path in tess_paths:
                if os.path.exists(path):
                    pytesseract.pytesseract.tesseract_cmd = path
                    break

            # Read image
            img = cv2.imread(file_path)
            if img is None:
                return ""

            # Preprocess image
            preprocessed = self.preprocess_image(img)

            # Try OCR at multiple angles (0, 90, 180, 270)
            angles = [0, 90, 180, 270]
            all_text = []
            
            for angle in angles:
                rotated = self.rotate_image(preprocessed, angle)
                
                # Save temporarily for pytesseract
                temp_path = f"temp_rotated_{angle}.png"
                cv2.imwrite(temp_path, rotated)
                
                try:
                    # Run OCR with multiple languages if available
                    text = pytesseract.image_to_string(temp_path, lang='eng+hin+guj')
                    if text.strip():
                        all_text.append(text.strip())
                except Exception as e:
                    logger.warning(f"OCR failed at {angle} degrees: {e}")
                    # Fallback to English only
                    try:
                        text = pytesseract.image_to_string(temp_path, lang='eng')
                        if text.strip():
                            all_text.append(text.strip())
                    except:
                        pass
                finally:
                    # Clean up temp file
                    if os.path.exists(temp_path):
                        try:
                            os.remove(temp_path)
                        except:
                            pass

            # Return the longest text (most complete extraction)
            if all_text:
                best_text = max(all_text, key=len)
                logger.info(f"OCR extracted {len(best_text)} characters from best angle")
                return best_text
            return ""
            
        except Exception as e:
            logger.error(f"Multi-angle OCR failed: {e}")
            return ""

    def extract_urls_from_text(self, text: str) -> List[str]:
        """Extract all URLs from text using regex."""
        if not text:
            return []
        
        # Comprehensive URL pattern
        url_pattern = r'(?:https?://|www\.)[\w\.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#\[\]@!\$&\'\(\)\*\+,;=.%]+'
        urls = re.findall(url_pattern, text, re.IGNORECASE)
        
        # Clean up URLs
        cleaned_urls = []
        for url in urls:
            # Remove trailing punctuation
            url = url.rstrip('.,;:!?)]\'\"')
            # Ensure proper format
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            cleaned_urls.append(url)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_urls = []
        for url in cleaned_urls:
            if url not in seen:
                seen.add(url)
                unique_urls.append(url)
        
        return unique_urls

    def extract_phone_numbers(self, text: str) -> List[str]:
        """Extract phone numbers from text."""
        if not text:
            return []
        
        # Indian phone number patterns
        patterns = [
            r'\+91[\s-]?[6-9]\d{9}',  # +91 format
            r'0[\s-]?[6-9]\d{9}',       # 0 prefix
            r'[6-9]\d{9}',               # 10 digit
            r'\(\d{3,4}\)[\s-]?\d{7,8}',  # With area code
        ]
        
        phones = []
        for pattern in patterns:
            matches = re.findall(pattern, text)
            phones.extend(matches)
        
        # Clean and deduplicate
        cleaned = []
        seen = set()
        for phone in phones:
            # Remove all non-digit characters except +
            clean = re.sub(r'[^\d+]', '', phone)
            if clean and clean not in seen and len(clean) >= 10:
                seen.add(clean)
                cleaned.append(clean)
        
        return cleaned

    def extract_emails(self, text: str) -> List[str]:
        """Extract email addresses from text."""
        if not text:
            return []
        
        email_pattern = r'[\w\.-]+@[\w\.-]+\.\w+'
        emails = re.findall(email_pattern, text, re.IGNORECASE)
        
        # Deduplicate
        return list(set(emails))

    def analyze_cv_manipulations(self, img: np.ndarray) -> Tuple[float, List[str]]:
        """Layer 2: Classical Computer Vision checks for editing/tampering."""
        reasons = []
        tamper_score = 0.0
        try:
            if len(img.shape) == 3:
                gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            else:
                gray = img

            edges = cv2.Canny(gray, 50, 150)
            contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            pasted_blocks = 0
            for c in contours:
                x, y, w, h = cv2.boundingRect(c)
                rect_ratio = w / float(h) if h > 0 else 0
                area = w * h
                if 20 < w < 200 and 10 < h < 100 and 0.8 < rect_ratio < 4.0 and area > 500:
                    pasted_blocks += 1

            if pasted_blocks > 15:
                tamper_score += 0.25
                reasons.append("Unnatural font blocks/boundaries detected (potential splicing editing).")

        except Exception as e:
            logger.error(f"Error checking CV features: {e}")

        return tamper_score, reasons

    def run_deepfake_inference(self, img: np.ndarray) -> float:
        """Layer 3: CNN/Keras model verification. Returns 0.0 if model not loaded (lazy/optional)."""
        if not self.deepfake_model:
            return 0.0
        try:
            img_rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
            img_resized = cv2.resize(img_rgb, (224, 224)) / 255.0
            tensor = np.expand_dims(img_resized, axis=0)

            prob = self.deepfake_model.predict(tensor, verbose=0)[0][0]
            return float(prob)
        except Exception as e:
            logger.error(f"Error running deepfake CNN model on image: {e}")
            return 0.0

    def scan(self, file_path: str) -> dict:
        """Run the full multi-layered Image Scan cascade with enhanced OCR and extraction."""
        steps = []

        img = cv2.imread(file_path)
        if img is None:
            return {
                "label": "❌ Unreadable Image",
                "score": 0.0,
                "combined_prob": 0.0,
                "explanation": "Uploaded file is not a valid image format or is corrupted.",
                "actionSteps": ["Check the file format.", "Upload a PNG or JPG file."],
                "cascade_steps": ["Layer 0: File Parsing Error"]
            }

        # --- Layer 0: Normalization, QR & Enhanced OCR Extraction ---
        steps.append("Layer 0: Preprocessing & Advanced Data Extraction")
        qr_content = self.extract_qr_code(img)
        ocr_text = self.run_ocr_multi_angle(file_path)

        # Extract URLs, phones, emails from OCR text
        extracted_urls = self.extract_urls_from_text(ocr_text)
        extracted_phones = self.extract_phone_numbers(ocr_text)
        extracted_emails = self.extract_emails(ocr_text)

        logger.info(f"Extracted {len(extracted_urls)} URLs, {len(extracted_phones)} phones, {len(extracted_emails)} emails from OCR")

        qr_result = None
        ocr_result = None
        url_results = []

        # Process QR code if found
        if qr_content:
            steps.append("Layer 0 Cross-Feed: UPI/Link check on QR code")
            if re.match(r'^https?://|www\.', qr_content, re.IGNORECASE) or qr_content.startswith("upi:"):
                qr_result = self.link_cascade.scan(qr_content)
            else:
                qr_result = self.text_cascade.scan(qr_content)

        # Process OCR text
        if ocr_text:
            steps.append(f"Layer 0 Cross-Feed: Scan OCR Text ({len(ocr_text)} chars)")
            ocr_result = self.text_cascade.scan(ocr_text)

        # Process each extracted URL through link cascade
        if extracted_urls:
            steps.append(f"Layer 0 Cross-Feed: Analyzing {len(extracted_urls)} extracted URLs")
            for url in extracted_urls[:5]:  # Limit to first 5 URLs to avoid timeout
                try:
                    url_result = self.link_cascade.scan(url)
                    url_results.append({
                        "url": url,
                        "result": url_result
                    })
                except Exception as e:
                    logger.error(f"Error analyzing URL {url}: {e}")

        # --- Layer 1: Hashing Blocklists ---
        steps.append("Layer 1: Exact Hash & Perceptual Hashing Blocklists")
        exact_sha = self.calculate_sha256(file_path)
        dhash = self.calculate_dhash(img)

        if exact_sha and exact_sha in KNOWN_SCAM_SHA256:
            return {
                "label": "🚨 Likely Scam",
                "score": 0.02,
                "combined_prob": 0.99,
                "explanation": f"Exact match found in known-scam image hash database: {KNOWN_SCAM_SHA256[exact_sha]}.",
                "actionSteps": ["This exact image has been reported as a scam before.", "Do not send funds or share transaction keys."],
                "cascade_steps": steps
            }

        community_match = get_image_hash_reputation_override(exact_sha) if exact_sha else None
        if community_match and community_match.get("verdict") == "scam":
            return {
                "label": "🚨 Likely Scam",
                "score": 0.03,
                "combined_prob": 0.97,
                "explanation": f"Image confirmed as scam by {community_match.get('votes', 0)} community reports (Layer 5 feedback cache).",
                "actionSteps": ["This image has been reported as a scam by other users.", "Do not send funds or share transaction keys."],
                "cascade_steps": steps
            }

        matched_scam = None
        if dhash:
            for known_hash, name in KNOWN_SCAM_HASHES.items():
                dist = sum(c1 != c2 for c1, c2 in zip(dhash, known_hash))
                if dist <= 4:
                    matched_scam = name
                    break

        if matched_scam:
            return {
                "label": "🚨 Likely Scam",
                "score": 0.05,
                "combined_prob": 0.98,
                "explanation": f"Perceptual template match: Detected similarity with '{matched_scam}'.",
                "actionSteps": ["This image matches known scam screenshots.", "Do not send funds or share transaction keys."],
                "cascade_steps": steps
            }

        # --- Layer 2: Tampering & Editing Indicators ---
        steps.append("Layer 2: Edit Detection & Font Artifacts")
        tamper_prob, tamper_reasons = self.analyze_cv_manipulations(img)

        # --- Layer 3: CNN / Deepfake Classifier (only runs if model preloaded) ---
        steps.append("Layer 3: Keras Deepfake Image Analysis")
        deepfake_prob = self.run_deepfake_inference(img)

        # --- Layer 4: Multimodal Aggregator (Aggregates OCR + QR + CV + URL results) ---
        steps.append("Layer 4: Cross-Pipeline Aggregator")

        reasons = list(tamper_reasons)
        max_prob = max(tamper_prob, deepfake_prob)
        action_steps = ["Verify details with bank customer services before sending funds."]

        if deepfake_prob > 0.65:
            reasons.append(f"Highly suspicious deepfake/synthetic face artifacts ({int(deepfake_prob*100)}%).")
            action_steps.append("Be alert of synthetic media impersonating customer support or government agents.")

        if qr_result:
            max_prob = max(max_prob, qr_result["combined_prob"])
            reasons.append(f"QR code contents flagged: {qr_result['explanation']}")
            action_steps.extend(qr_result["actionSteps"])

        if ocr_result:
            max_prob = max(max_prob, ocr_result["combined_prob"])
            reasons.append(f"OCR text content flagged: {ocr_result['explanation']}")
            action_steps.extend(ocr_result["actionSteps"])

        # Process URL results
        if url_results:
            for url_data in url_results:
                url = url_data["url"]
                result = url_data["result"]
                max_prob = max(max_prob, result["combined_prob"])
                reasons.append(f"URL '{url}' flagged: {result['explanation']}")
                action_steps.extend(result["actionSteps"])

        action_steps = list(dict.fromkeys(action_steps))[:4]

        label = "🚨 Likely Scam" if max_prob > 0.4 else "✅ Likely Safe"
        score = max(0.1, min(0.9, 1.0 - max_prob))

        return {
            "label": label,
            "score": score,
            "combined_prob": max_prob,
            "explanation": "Cascade image check complete. " + (" ".join(reasons) if reasons else "No anomalies detected."),
            "actionSteps": action_steps if label == "🚨 Likely Scam" else ["Image content appears safe and unmanipulated."],
            "cascade_steps": steps,
            "meta": {
                "sha256": exact_sha,
                "dhash": dhash,
                "ocr_text": ocr_text[:500] if ocr_text else "",
                "qr_content": qr_content or "",
                "extracted_urls": extracted_urls,
                "extracted_phones": extracted_phones,
                "extracted_emails": extracted_emails,
                "url_analysis_count": len(url_results)
            }
        }