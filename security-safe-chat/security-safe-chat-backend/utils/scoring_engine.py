import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger("safe_backend.scoring_engine")


class RiskLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    SAFE = "SAFE"


@dataclass
class ScoringWeights:
    """Configurable weights for different analysis components."""
    text_content_weight: float = 0.40      # 40% weight
    link_analysis_weight: float = 0.40     # 40% weight
    image_manipulation_weight: float = 0.20  # 20% weight


@dataclass
class AnalysisBreakdown:
    """Structured breakdown of analysis results."""
    text_score: float = 0.0
    text_flags: List[str] = None
    text_confidence: float = 0.0
    
    link_score: float = 0.0
    link_flags: List[str] = None
    link_confidence: float = 0.0
    urls_analyzed: int = 0
    
    image_score: float = 0.0
    image_flags: List[str] = None
    image_confidence: float = 0.0
    
    overall_score: float = 0.0
    max_score: float = 10.0
    risk_level: str = RiskLevel.SAFE.value
    
    def __post_init__(self):
        if self.text_flags is None:
            self.text_flags = []
        if self.link_flags is None:
            self.link_flags = []
        if self.image_flags is None:
            self.image_flags = []


class ScoringEngine:
    """
    Unified scoring engine that combines multiple analysis results
    into a single scam probability score (0-10).
    """
    
    def __init__(self, weights: ScoringWeights = None):
        self.weights = weights or ScoringWeights()
        logger.info("ScoringEngine initialized with weights: "
                   f"text={self.weights.text_content_weight}, "
                   f"link={self.weights.link_analysis_weight}, "
                   f"image={self.weights.image_manipulation_weight}")
    
    def _normalize_to_10_scale(self, probability: float) -> float:
        """Convert 0-1 probability to 0-10 scale."""
        return round(min(10.0, max(0.0, probability * 10.0)), 2)
    
    def _extract_text_flags(self, text_result: Dict) -> List[str]:
        """Extract flags/reasons from text cascade result."""
        flags = []
        
        if not text_result:
            return flags
        
        explanation = text_result.get("explanation", "")
        
        # Extract flags from explanation
        if "urgent" in explanation.lower():
            flags.append("Urgency language detected")
        if "financial" in explanation.lower() or "payment" in explanation.lower():
            flags.append("Financial threat keywords")
        if "authority" in explanation.lower() or "government" in explanation.lower():
            flags.append("Authority impersonation")
        if "phishing" in explanation.lower():
            flags.append("Phishing patterns detected")
        if "lottery" in explanation.lower() or "prize" in explanation.lower():
            flags.append("Reward/lottery scam indicators")
        if "bank" in explanation.lower() or "account" in explanation.lower():
            flags.append("Banking/financial context")
        if "otp" in explanation.lower() or "password" in explanation.lower():
            flags.append("Credential request detected")
        
        # Check cascade steps for additional context
        cascade_steps = text_result.get("cascade_steps", [])
        if any("Layer 1" in step and "Lexical" in step for step in cascade_steps):
            flags.append("Rule-based scam patterns matched")
        if any("ML" in step for step in cascade_steps):
            flags.append("Machine learning model flagged content")
        
        return flags if flags else ["Suspicious text content detected"]
    
    def _extract_link_flags(self, link_result: Dict) -> List[str]:
        """Extract flags/reasons from link cascade result."""
        flags = []
        
        if not link_result:
            return flags
        
        explanation = link_result.get("explanation", "")
        
        # Extract specific flags
        if "typosquatting" in explanation.lower() or "lookalike" in explanation.lower():
            flags.append("Typosquatting/brand impersonation detected")
        if "new domain" in explanation.lower() or "newly registered" in explanation.lower():
            flags.append("Newly registered domain")
        if "suspicious" in explanation.lower() and "tld" in explanation.lower():
            flags.append("Suspicious top-level domain")
        if "ssl" in explanation.lower():
            flags.append("SSL certificate issues")
        if "password" in explanation.lower() or "login" in explanation.lower():
            flags.append("Credential harvesting page detected")
        if "otp" in explanation.lower():
            flags.append("OTP collection page detected")
        if "brand" in explanation.lower() and "mismatch" in explanation.lower():
            flags.append("Brand impersonation on landing page")
        if "form" in explanation.lower() and "external" in explanation.lower():
            flags.append("Form submits to external domain")
        if "urgency" in explanation.lower() or "pressure" in explanation.lower():
            flags.append("Urgency/threat language on page")
        
        # Check for specific indicators
        meta = link_result.get("meta", {})
        if meta.get("domain_age_days") is not None:
            age = meta["domain_age_days"]
            if age < 30:
                flags.append(f"Domain very new ({age} days old)")
            elif age < 90:
                flags.append(f"Domain relatively new ({age} days old)")
        
        if not meta.get("ssl_valid", True):
            flags.append("Invalid SSL certificate")
        
        return flags if flags else ["Suspicious link detected"]
    
    def _extract_image_flags(self, image_result: Dict) -> List[str]:
        """Extract flags/reasons from image cascade result."""
        flags = []
        
        if not image_result:
            return flags
        
        explanation = image_result.get("explanation", "")
        
        # Check for specific image issues
        if "deepfake" in explanation.lower():
            flags.append("Deepfake/synthetic media detected")
        if "tamper" in explanation.lower() or "editing" in explanation.lower():
            flags.append("Image manipulation/tampering detected")
        if "scam" in explanation.lower() and "hash" in explanation.lower():
            flags.append("Known scam image (hash match)")
        if "perceptual" in explanation.lower() or "template" in explanation.lower():
            flags.append("Similar to known scam templates")
        if "qr code" in explanation.lower() and "flagged" in explanation.lower():
            flags.append("QR code contains suspicious content")
        
        # Check meta information
        meta = image_result.get("meta", {})
        if meta.get("extracted_urls"):
            flags.append(f"Contains {len(meta['extracted_urls'])} embedded URL(s)")
        if meta.get("extracted_phones"):
            flags.append(f"Contains {len(meta['extracted_phones'])} phone number(s)")
        if meta.get("url_analysis_count", 0) > 0:
            flags.append(f"Analyzed {meta['url_analysis_count']} extracted URLs")
        
        return flags if flags else ["Image analysis completed"]
    
    def _calculate_risk_level(self, score: float) -> str:
        """Determine risk level based on score (0-10)."""
        if score >= 8.0:
            return RiskLevel.CRITICAL.value
        elif score >= 6.5:
            return RiskLevel.HIGH.value
        elif score >= 4.0:
            return RiskLevel.MEDIUM.value
        elif score >= 2.0:
            return RiskLevel.LOW.value
        else:
            return RiskLevel.SAFE.value
    
    def calculate_score(
        self,
        ocr_text_result: Optional[Dict] = None,
        link_analysis_result: Optional[Dict] = None,
        image_manipulation_result: Optional[Dict] = None,
        extracted_urls_count: int = 0
    ) -> AnalysisBreakdown:
        """
        Calculate comprehensive scam score from multiple analysis results.
        
        Args:
            ocr_text_result: Result from text_cascade.scan() on OCR text
            link_analysis_result: Result from link_cascade.scan() on extracted URLs
            image_manipulation_result: Result from image cascade (for deepfake/tampering)
            extracted_urls_count: Number of URLs extracted from image
        
        Returns:
            AnalysisBreakdown with detailed scores and flags
        """
        breakdown = AnalysisBreakdown()
        
        # === 1. TEXT CONTENT ANALYSIS (40% weight) ===
        if ocr_text_result:
            text_prob = ocr_text_result.get("combined_prob", 0.0)
            breakdown.text_score = self._normalize_to_10_scale(text_prob)
            breakdown.text_confidence = text_prob
            breakdown.text_flags = self._extract_text_flags(ocr_text_result)
        else:
            breakdown.text_score = 0.0
            breakdown.text_flags = ["No text content to analyze"]
        
        # === 2. LINK ANALYSIS (40% weight) ===
        if link_analysis_result:
            link_prob = link_analysis_result.get("combined_prob", 0.0)
            breakdown.link_score = self._normalize_to_10_scale(link_prob)
            breakdown.link_confidence = link_prob
            breakdown.link_flags = self._extract_link_flags(link_analysis_result)
            breakdown.urls_analyzed = 1
        elif extracted_urls_count > 0:
            # If we have URLs but no analysis result
            breakdown.link_score = 5.0  # Neutral score
            breakdown.link_flags = [f"{extracted_urls_count} URL(s) extracted but not analyzed"]
        else:
            breakdown.link_score = 0.0
            breakdown.link_flags = ["No URLs found in content"]
        
        # === 3. IMAGE MANIPULATION ANALYSIS (20% weight) ===
        if image_manipulation_result:
            # Check for deepfake or tampering
            deepfake_prob = image_manipulation_result.get("combined_prob", 0.0)
            breakdown.image_score = self._normalize_to_10_scale(deepfake_prob)
            breakdown.image_confidence = deepfake_prob
            breakdown.image_flags = self._extract_image_flags(image_manipulation_result)
        else:
            breakdown.image_score = 0.0
            breakdown.image_flags = ["No image manipulation detected"]
        
        # === 4. COMBINE SCORES ===
        # Weighted combination
        weighted_score = (
            (breakdown.text_score * self.weights.text_content_weight) +
            (breakdown.link_score * self.weights.link_analysis_weight) +
            (breakdown.image_score * self.weights.image_manipulation_weight)
        )
        
        breakdown.overall_score = round(weighted_score, 2)
        breakdown.risk_level = self._calculate_risk_level(breakdown.overall_score)
        
        logger.info(f"Scoring complete: {breakdown.overall_score}/10 ({breakdown.risk_level}) - "
                   f"text={breakdown.text_score}, link={breakdown.link_score}, image={breakdown.image_score}")
        
        return breakdown
    
    def get_score_label(self, score: float) -> str:
        """Get emoji label for score."""
        if score >= 8.0:
            return "🚨 CRITICAL SCAM"
        elif score >= 6.5:
            return "🚨 HIGH RISK"
        elif score >= 4.0:
            return "⚠️ MEDIUM RISK"
        elif score >= 2.0:
            return "✅ LOW RISK"
        else:
            return "✅ SAFE"
    
    def format_detailed_report(self, breakdown: AnalysisBreakdown) -> Dict:
        """
        Format breakdown into a detailed report suitable for API response.
        """
        return {
            "scam_score": breakdown.overall_score,
            "max_score": breakdown.max_score,
            "risk_level": breakdown.risk_level,
            "label": self.get_score_label(breakdown.overall_score),
            "breakdown": {
                "text_analysis": {
                    "score": breakdown.text_score,
                    "confidence": breakdown.text_confidence,
                    "weight": self.weights.text_content_weight,
                    "flags": breakdown.text_flags
                },
                "link_analysis": {
                    "score": breakdown.link_score,
                    "confidence": breakdown.link_confidence,
                    "weight": self.weights.link_analysis_weight,
                    "flags": breakdown.link_flags,
                    "urls_analyzed": breakdown.urls_analyzed
                },
                "image_analysis": {
                    "score": breakdown.image_score,
                    "confidence": breakdown.image_confidence,
                    "weight": self.weights.image_manipulation_weight,
                    "flags": breakdown.image_flags
                }
            },
            "summary": {
                "total_flags": len(breakdown.text_flags) + len(breakdown.link_flags) + len(breakdown.image_flags),
                "highest_risk_component": max(
                    [("text", breakdown.text_score), 
                     ("link", breakdown.link_score), 
                     ("image", breakdown.image_score)],
                    key=lambda x: x[1]
                )[0]
            }
        }


# Convenience function for quick scoring
def quick_score(
    text_result: Optional[Dict] = None,
    link_result: Optional[Dict] = None,
    image_result: Optional[Dict] = None,
    urls_count: int = 0
) -> Dict:
    """
    Quick scoring function that returns formatted report.
    
    Usage:
        report = quick_score(
            text_result=ocr_result,
            link_result=link_result,
            image_result=image_result,
            urls_count=3
        )
    """
    engine = ScoringEngine()
    breakdown = engine.calculate_score(
        ocr_text_result=text_result,
        link_analysis_result=link_result,
        image_manipulation_result=image_result,
        extracted_urls_count=urls_count
    )
    return engine.format_detailed_report(breakdown)