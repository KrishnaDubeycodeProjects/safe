import logging
from typing import Dict, List, Optional

logger = logging.getLogger("safe_backend.suggestion_engine")


class SuggestionEngine:
    """
    Generates context-aware, prioritized suggestions based on 
    the detected scam flags and risk level.
    """
    
    def __init__(self):
        self.reporting_info = {
            "helpline": "1930",
            "website": "cybercrime.gov.in",
            "app": "National Cyber Crime Reporting Portal (1930 App)",
            "message": "Report the incident immediately. The first hour (Golden Hour) is critical for freezing funds."
        }

    def _get_immediate_actions(self, flags: List[str]) -> List[str]:
        """Generate urgent 'Stop' actions based on specific threats."""
        actions = []
        flags_lower = [f.lower() for f in flags]
        
        # Link/Phishing threats
        if any("credential" in f or "otp" in f or "password" in f for f in flags_lower):
            actions.append("🛑 STOP: Do not enter any passwords, PINs, CVV, or OTPs on this page.")
        if any("typosquatting" in f or "brand impersonation" in f or "lookalike" in f for f in flags_lower):
            actions.append("🛑 STOP: Do not click any links or download attachments from this source.")
            
        # Text/Urgency threats
        if any("urgency" in f or "threat" in f or "pressure" in f for f in flags_lower):
            actions.append("🛑 STOP: Scammers use panic to force mistakes. Take a deep breath and do not act immediately.")
        if any("financial" in f or "payment" in f or "transfer" in f for f in flags_lower):
            actions.append("🛑 STOP: Do not transfer any money or share your screen with the caller.")
            
        # Image/Deepfake threats
        if any("deepfake" in f or "synthetic" in f for f in flags_lower):
            actions.append("🛑 STOP: Hang up the video call immediately. It is a fake identity.")
        if any("qr code" in f for f in flags_lower):
            actions.append("🛑 STOP: Do not scan this QR code. You scan QR codes to PAY, not to receive money.")

        # Default action if no specific flags matched but risk is present
        if not actions:
            actions.append("️ CAUTION: Pause before taking any action requested by this message.")
            
        return actions

    def _get_verification_steps(self, flags: List[str]) -> List[str]:
        """Generate 'Check' actions to help the user verify the claim."""
        steps = []
        flags_lower = [f.lower() for f in flags]
        
        if any("new domain" in f or "newly registered" in f for f in flags_lower):
            steps.append("🔍 Verify: Check the domain age. Legitimate banks and companies use domains that are years old.")
        if any("ssl" in f for f in flags_lower):
            steps.append("🔍 Verify: Check for the padlock icon in the browser, but remember even scam sites can have basic SSL.")
        if any("bank" in f or "account" in f or "kyc" in f for f in flags_lower):
            steps.append("🔍 Verify: Call the official customer care number printed on the back of your bank card (not the number in the message).")
        if any("authority" in f or "government" in f or "police" in f for f in flags_lower):
            steps.append(" Verify: No government agency (CBI, Police, Income Tax) conducts arrests or investigations via video call or demands money online.")
        if any("reward" in f or "lottery" in f or "prize" in f for f in flags_lower):
            steps.append("🔍 Verify: If you didn't buy a ticket, you didn't win a lottery. Ignore unsolicited prize messages.")
            
        if not steps:
            steps.append("🔍 Verify: Search the phone number or message text on Google to see if others have reported it as a scam.")
            
        return steps

    def _get_educational_tip(self, risk_level: str, flags: List[str]) -> str:
        """Provide a short educational tip based on the scam type."""
        flags_lower = " ".join(flags).lower()
        
        if "deepfake" in flags_lower or "synthetic" in flags_lower:
            return "💡 Did you know? AI deepfakes can clone voices and faces in real-time. Always verify identity through a known, trusted channel."
        if "typosquatting" in flags_lower or "lookalike" in flags_lower:
            return "💡 Did you know? Scammers register domains like 'sbi-kyc-update.com' to look real. Always type the official bank URL manually."
        if "urgency" in flags_lower or "threat" in flags_lower:
            return "💡 Did you know? Urgency is a scammer's #1 tool. Legitimate organizations will never threaten you with immediate arrest or account blocking over a call."
        if "qr code" in flags_lower:
            return "💡 Did you know? A QR code is just a link. Scanning it can open a payment gateway that drains your account."
        if "otp" in flags_lower or "credential" in flags_lower:
            return "💡 Did you know? Your OTP is like your ATM PIN. Bank employees, police, or customer support will NEVER ask for it."
            
        return "💡 Tip: When in doubt, ignore, block, and report. Never share personal details with unsolicited contacts."

    def generate_suggestions(self, score_report: Dict) -> Dict:
        """
        Main method to compile a full suggestion report.
        
        Args:
            score_report: The dictionary output from ScoringEngine.format_detailed_report()
            
        Returns:
            Dict containing immediate_actions, verification_steps, reporting_info, and educational_tip.
        """
        risk_level = score_report.get("risk_level", "SAFE")
        breakdown = score_report.get("breakdown", {})
        
        # Aggregate all flags from text, link, and image
        all_flags = []
        all_flags.extend(breakdown.get("text_analysis", {}).get("flags", []))
        all_flags.extend(breakdown.get("link_analysis", {}).get("flags", []))
        all_flags.extend(breakdown.get("image_analysis", {}).get("flags", []))
        
        # If it's a safe/low risk, provide minimal, reassuring suggestions
        if risk_level in ["SAFE", "LOW"]:
            return {
                "immediate_actions": ["✅ The content appears safe. You may proceed with normal caution."],
                "verification_steps": ["Always ensure you are on the official website before entering sensitive data."],
                "reporting_info": None,
                "educational_tip": "💡 Tip: Keep your software updated and use strong, unique passwords for every account."
            }
        
        # Generate contextual suggestions for Medium, High, and Critical risks
        immediate_actions = self._get_immediate_actions(all_flags)
        verification_steps = self._get_verification_steps(all_flags)
        educational_tip = self._get_educational_tip(risk_level, all_flags)
        
        # Add reporting info only for High and Critical risks
        reporting_info = None
        if risk_level in ["HIGH", "CRITICAL"]:
            reporting_info = {
                "helpline": self.reporting_info["helpline"],
                "website": self.reporting_info["website"],
                "app": self.reporting_info["app"],
                "message": self.reporting_info["message"]
            }
            
        return {
            "immediate_actions": immediate_actions,
            "verification_steps": verification_steps,
            "reporting_info": reporting_info,
            "educational_tip": educational_tip
        }


# Convenience function for quick generation
def quick_suggestions(score_report: Dict) -> Dict:
    """
    Quick wrapper to generate suggestions from a score report.
    """
    engine = SuggestionEngine()
    return engine.generate_suggestions(score_report)