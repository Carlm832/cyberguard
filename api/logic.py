"""
CyberGuard — Expert System Logic
Rule base, inference engines, and ARIA chat engine.
"""

import os
import hashlib
import re
import math
import base64
from typing import List, Dict, Any
import requests

# ---------------------------------------------------------------------------
# PHISHING RULE BASE — First-class knowledge structure (not embedded in prompts)
# ---------------------------------------------------------------------------

PHISHING_RULES = [
    {
        "id": "R01", "name": "Credential harvesting attempt", "cf": 0.25,
        "indicator": "requests_credentials", "compound": False,
        "category": "high_risk",
        "explanation": "Legitimate services never ask for passwords via email. This is the strongest single phishing indicator.",
        "example": "Your account will be suspended. Verify your password here."
    },
    {
        "id": "R02", "name": "Suspicious or obfuscated link", "cf": 0.20,
        "indicator": "suspicious_link", "compound": False,
        "category": "high_risk",
        "explanation": "Phishing emails use links that disguise the real destination URL.",
        "example": "Click here to verify — real URL is paypa1-secure.ru/login"
    },
    {
        "id": "R03", "name": "Urgency or threat framing", "cf": 0.15,
        "indicator": "urgency", "compound": False,
        "category": "social_engineering",
        "explanation": "Creating time pressure prevents the recipient from thinking critically.",
        "example": "Your account will be deleted in 24 hours unless you act now."
    },
    {
        "id": "R04", "name": "Spoofed or irregular sender domain", "cf": 0.15,
        "indicator": "spoofed_domain", "compound": False,
        "category": "identity",
        "explanation": "Attackers register lookalike domains or spoof display names to impersonate trusted senders.",
        "example": "From: support@paypa1.com or Apple <noreply@apple-id-secure.net>"
    },
    {
        "id": "R05", "name": "Unknown sender", "cf": 0.10,
        "indicator": "unknown_sender", "compound": False,
        "category": "identity",
        "explanation": "Unsolicited contact from an unrecognised sender is a baseline phishing signal.",
        "example": "You receive an email from someone you have never interacted with."
    },
    {
        "id": "R06", "name": "Unexpected attachment", "cf": 0.08,
        "indicator": "unexpected_attachment", "compound": False,
        "category": "payload",
        "explanation": "Malicious attachments are a primary malware delivery vector.",
        "example": "Invoice_2024.pdf.exe or a Word document asking you to enable macros."
    },
    {
        "id": "R07", "name": "Generic impersonal greeting", "cf": 0.04,
        "indicator": "generic_greeting", "compound": False,
        "category": "social_engineering",
        "explanation": "Bulk phishing campaigns use generic salutations because they don't know your name.",
        "example": "Dear Customer, Dear User, Dear Account Holder."
    },
    {
        "id": "R08", "name": "Implausible prize or reward", "cf": 0.03,
        "indicator": "too_good_offer", "compound": False,
        "category": "social_engineering",
        "explanation": "Reward-based lures exploit greed and curiosity to override caution.",
        "example": "Congratulations! You have been selected to receive a £500 gift card."
    },
    {
        "id": "R09", "name": "Compound: urgency + unknown sender", "cf": 0.10,
        "indicator": None, "compound": True,
        "requires": ["urgency", "unknown_sender"],
        "category": "compound",
        "explanation": "Urgency framing from an unrecognised source is a textbook social engineering pattern. The combination is significantly more suspicious than either signal alone.",
        "example": "An unknown sender warning your account will be locked within the hour."
    },
    {
        "id": "R10", "name": "Compound: credential request + spoofed domain", "cf": 0.15,
        "indicator": None, "compound": True,
        "requires": ["requests_credentials", "spoofed_domain"],
        "category": "compound",
        "explanation": "Asking for credentials via a lookalike domain is the definitive phishing pattern.",
        "example": "A fake PayPal login page served from paypa1-secure.com."
    },
]

# ---------------------------------------------------------------------------
# PhishingExpert — deterministic inference engine
# ---------------------------------------------------------------------------

class PhishingExpert:
    """Runs every rule in PHISHING_RULES against the supplied signals object."""

    def __init__(self, indicators: Dict[str, bool]):
        self.indicators = indicators

    def evaluate(self) -> Dict[str, Any]:
        fired = []
        score = 0.0

        for rule in PHISHING_RULES:
            if rule.get("compound"):
                triggered = all(self.indicators.get(r, False) for r in rule["requires"])
            else:
                triggered = self.indicators.get(rule["indicator"], False)

            if triggered:
                fired.append({
                    "id": rule["id"],
                    "name": rule["name"],
                    "cf": rule["cf"],
                    "explanation": rule["explanation"],
                    "category": rule["category"],
                })
                score += rule["cf"]

        score = min(1.0, score)

        if score >= 0.7:
            level = "HIGH"
            recs = [
                "Do NOT click any links or open attachments.",
                "Report the email to your IT/security team immediately.",
                "Delete the email permanently from all folders.",
            ]
        elif score >= 0.4:
            level = "MEDIUM"
            recs = [
                "Verify the sender through an independent channel.",
                "Hover over links to check the real URL before clicking.",
                "If a login is required, navigate directly to the official site.",
            ]
        else:
            level = "LOW"
            recs = ["No strong phishing indicators detected. Stay vigilant."]

        return {
            "risk_score": round(score, 3),
            "risk_level": level,
            "fired_rules": fired,
            "triggered_indicators": [r["name"] for r in fired],
            "recommendations": recs,
        }


# ---------------------------------------------------------------------------
# PasswordExpert — rule-based password analyser
# ---------------------------------------------------------------------------

COMMON_PASSWORDS = {
    "password", "123456", "123456789", "12345678", "12345", "qwerty",
    "abc123", "monkey", "111111", "password1", "iloveyou", "admin",
    "welcome", "sunshine", "princess", "dragon", "letmein", "login",
    "solo", "master", "hello", "shadow", "654321", "superman", "football",
}

KEYBOARD_PATTERNS = [
    "qwerty", "qwertyuiop", "asdf", "asdfghjkl", "zxcv", "zxcvbnm",
    "12345", "123456", "1234567", "12345678", "09876", "987654", "qweasd",
]


class PasswordExpert:
    """Score a password against a local rule set. Password never sent to any API."""

    def __init__(self, password: str):
        self.password = password or ""

    def _entropy_bits(self) -> float:
        if not self.password:
            return 0.0
        pool = 0
        if re.search(r"[a-z]", self.password): pool += 26
        if re.search(r"[A-Z]", self.password): pool += 26
        if re.search(r"\d", self.password): pool += 10
        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", self.password): pool += 32
        if pool == 0:
            return 0.0
        return round(len(self.password) * math.log2(pool), 1)  # Fixed: was pool.bit_length()

    def _crack_time(self, entropy: float) -> str:
        if entropy <= 0: return "Instant"
        seconds = (2 ** entropy) / 1e10
        if seconds < 1:        return "< 1 second"
        if seconds < 60:       return f"~{int(seconds)} seconds"
        if seconds < 3600:     return f"~{int(seconds/60)} minutes"
        if seconds < 86400:    return f"~{int(seconds/3600)} hours"
        if seconds < 2.628e6:  return f"~{int(seconds/86400)} days"
        if seconds < 3.154e7:  return f"~{int(seconds/2.628e6)} months"
        if seconds < 3.154e9:  return f"~{int(seconds/3.154e7)} years"
        return "Centuries+"

    def evaluate(self) -> Dict[str, Any]:
        pwd = self.password
        checks = []
        score = 0

        def chk(rule_id, name, passed, points):
            nonlocal score
            checks.append({"id": rule_id, "name": name, "passed": passed, "points": points})
            if passed: score += points

        chk("P01", "Minimum length (8+ chars)",          len(pwd) >= 8,  10)
        chk("P02", "Good length (12+ chars)",             len(pwd) >= 12, 10)
        chk("P03", "Strong length (16+ chars)",           len(pwd) >= 16, 10)
        chk("P04", "Contains uppercase letters",          bool(re.search(r"[A-Z]", pwd)), 10)
        chk("P05", "Contains lowercase letters",          bool(re.search(r"[a-z]", pwd)), 10)
        chk("P06", "Contains digits",                     bool(re.search(r"\d", pwd)), 10)
        chk("P07", "Contains special characters",         bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", pwd)), 15)
        chk("P08", "Not a common password",               pwd.lower() not in COMMON_PASSWORDS, 10)
        chk("P09", "No keyboard patterns (qwerty…)",      not any(p in pwd.lower() for p in KEYBOARD_PATTERNS), 10)
        chk("P10", "No repeated characters (aaa, 111…)",  not bool(re.search(r"(.)\1{2,}", pwd)), 5)

        score = min(100, score)
        entropy = self._entropy_bits()

        if score >= 80:   label = "Very Strong"
        elif score >= 60: label = "Strong"
        elif score >= 40: label = "Fair"
        elif score >= 20: label = "Weak"
        else:             label = "Very Weak"

        feedback = [c["name"] for c in checks if not c["passed"]]
        if not feedback: feedback = ["Excellent password — no improvements needed."]

        return {
            "score": score,
            "strength_label": label,
            "entropy_bits": entropy,
            "crack_time": self._crack_time(entropy),
            "checks": checks,
            "feedback": feedback,
        }


# ---------------------------------------------------------------------------
# HIBPExpert — k-anonymity breach check
# ---------------------------------------------------------------------------

class HIBPExpert:
    API_URL = "https://api.pwnedpasswords.com/range/"

    def __init__(self, password: str):
        self.password = password or ""

    def check(self) -> Dict[str, Any]:
        if not self.password:
            return {"breached": False, "breach_count": 0}
        full_hash = hashlib.sha1(self.password.encode()).hexdigest().upper()
        prefix, suffix = full_hash[:5], full_hash[5:]
        try:
            resp = requests.get(self.API_URL + prefix, timeout=10, headers={"Add-Padding": "true"})
            resp.raise_for_status()
            for line in resp.text.splitlines():
                h, cnt = line.split(":")
                if h.upper() == suffix:
                    return {"breached": True, "breach_count": int(cnt)}
            return {"breached": False, "breach_count": 0}
        except Exception:
            return {"breached": False, "breach_count": 0, "error": True}


# ---------------------------------------------------------------------------
# FuzzyRiskEngine — overall security posture
# ---------------------------------------------------------------------------

class FuzzyRiskEngine:
    def __init__(self, phishing_score: float, password_score: float):
        self.phishing_score = phishing_score
        self.password_risk = 1.0 - (password_score / 100.0)

    def evaluate(self) -> Dict[str, Any]:
        overall = round(min(1.0, (self.phishing_score * 0.6) + (self.password_risk * 0.4)), 3)
        if overall >= 0.65:   status, colour = "Needs Attention", "red"
        elif overall >= 0.35: status, colour = "Moderate Risk",   "amber"
        else:                 status, colour = "Good Standing",   "teal"
        return {"overall_score": overall, "overall_status": status, "colour": colour}


# ---------------------------------------------------------------------------
# Gemini helper
# ---------------------------------------------------------------------------

def _gemini_chat(messages: List[Dict[str, str]], system_prompt: str = "", image: Dict[str, str] = None) -> Dict[str, Any]:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return {"error": True, "message": "Gemini API key not configured."}

    endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent?key={api_key}"
    contents = []
    for i, msg in enumerate(messages):
        parts = []
        if image and i == len(messages) - 1 and msg["role"] == "user":
            parts.append({"inline_data": {"mime_type": image["mime_type"], "data": image["data"]}})
        parts.append({"text": msg["content"]})
        contents.append({"role": msg["role"], "parts": parts})

    payload = {"contents": contents}
    if system_prompt:
        payload["system_instruction"] = {"parts": [{"text": system_prompt}]}

    try:
        resp = requests.post(endpoint, json=payload, timeout=20)
        if resp.status_code != 200:
            return {"error": True, "message": f"Gemini {resp.status_code}: {resp.text[:200]}"}
        data = resp.json()
        candidates = data.get("candidates", [])
        if not candidates:
            return {"error": True, "message": "No candidates returned."}
        text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "").strip()
        return {"error": False, "content": text}
    except Exception as e:
        return {"error": True, "message": str(e)}


# ---------------------------------------------------------------------------
# ARIAEngine — natural language layer over the expert system
# ---------------------------------------------------------------------------

class ARIAEngine:
    SYSTEM_PROMPT = (
        "You are ARIA (Awareness & Risk Intelligence Advisor), CyberGuard's cybersecurity expert. "
        "Your role is to explain the conclusions of a structured rule-based inference engine to non-technical users. "
        "You do NOT perform your own threat analysis — the inference engine has already calculated the verdict. "
        "When session analysis data is provided below, reference the specific rule IDs (e.g. R01, R04) in your explanation. "
        "Do NOT invent reasoning beyond what the fired rules say. "
        "Tone: calm, clear, non-condescending. Never say 'as an AI'. "
        "Keep responses to 3–5 sentences. End with an invitation to ask more. "
        "If confidence is below 0.3, say you cannot reach a firm conclusion and name what additional signals would change it."
    )

    def __init__(self, history: List[Dict[str, str]] = None):
        self.history = history or []

    def ask(self, user_message: str, session_context: dict = None, image: Dict[str, str] = None) -> Dict[str, Any]:
        context_block = ""
        if session_context:
            phishing = session_context.get("phishing_verdict")
            password = session_context.get("password_verdict")
            hibp     = session_context.get("hibp_result")
            posture  = session_context.get("posture")

            if phishing:
                rules_str = ", ".join(
                    f"{r['id']} ({r['name']}, CF={r['cf']})"
                    for r in phishing.get("fired_rules", [])
                ) or "none"
                context_block += (
                    f"\n\n--- SESSION ANALYSIS DATA (ground all responses in this) ---\n"
                    f"Phishing analysis: risk_score={phishing['risk_score']}, level={phishing['risk_level']}\n"
                    f"Rules fired: {rules_str}\n"
                    f"Recommendations issued: {'; '.join(phishing.get('recommendations', []))}\n"
                    f"Do NOT invent reasons beyond the fired rules above.\n"
                )
            if password:
                context_block += (
                    f"Password analysis: {password['strength_label']} ({password['score']}/100), "
                    f"entropy={password.get('entropy_bits')} bits, crack time={password.get('crack_time')}\n"
                    f"Issues: {', '.join(password.get('feedback', [])) or 'none'}\n"
                )
            if hibp and hibp.get("breached"):
                context_block += f"BREACH WARNING: password found in {hibp['breach_count']:,} known breaches.\n"
            if posture:
                context_block += f"Overall posture: {posture['overall_status']} ({posture['overall_score']}/1.0)\n"

        full_system = self.SYSTEM_PROMPT + context_block
        self.history.append({"role": "user", "content": user_message})
        messages = [{"role": "user" if h["role"] == "user" else "model", "content": h["content"]} for h in self.history]

        result = _gemini_chat(messages, system_prompt=full_system, image=image)
        reply = result["content"] if not result.get("error") else "I'm having trouble connecting. Please try again in a moment."
        self.history.append({"role": "assistant", "content": reply})

        return {"reply": reply, "history": self.history, "follow_ups": self._follow_ups(session_context)}

    def _follow_ups(self, ctx: dict = None) -> List[str]:
        if ctx and ctx.get("phishing_verdict"):
            return ["Why did these rules fire?", "What should I do right now?", "What if I already clicked a link?", "How confident is this verdict?"]
        if ctx and ctx.get("password_verdict"):
            return ["How do I make it stronger?", "What is a password manager?", "Should I enable two-factor authentication?", "What makes a password uncrackable?"]
        return ["How do I spot a phishing email?", "What makes a strong password?", "How do I check if I've been breached?", "What is two-factor authentication?"]
