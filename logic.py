import os
import hashlib
import json
import re
import secrets
import base64
from typing import List, Dict, Any
import requests
from urllib.parse import quote_plus

# Load API keys from environment (uses python-dotenv in app.py)
# Helper to call Gemini API (gemini-pro model) with a list of messages
def _gemini_chat(messages: List[Dict[str, str]], system_prompt: str = "") -> Dict[str, Any]:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return {"error": True, "message": "Gemini API key not set"}
    
    # Use v1beta for proper system_instruction support
    endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent?key={api_key}"
    
    payload = {
        "contents": [{"role": m["role"], "parts": [{"text": m["content"]}]} for m in messages]
    }
    
    if system_prompt:
        payload["system_instruction"] = {"parts": [{"text": system_prompt}]}

    try:
        resp = requests.post(endpoint, json=payload, timeout=15)
        if resp.status_code != 200:
            return {"error": True, "message": f"Gemini Error {resp.status_code}: {resp.text}"}
        
        data = resp.json()
        candidates = data.get("candidates", [])
        if not candidates:
            return {"error": True, "message": "No candidates returned from Gemini"}
        
        parts = candidates[0].get("content", {}).get("parts", [])
        if not parts:
            return {"error": True, "message": "No response parts found"}
            
        text = parts[0].get("text", "")
        # Robust JSON extraction: find first '{' and last '}'
        start = text.find('{')
        end = text.rfind('}')
        if start != -1 and end != -1:
            text = text[start:end+1]
        
        return {"error": False, "content": text.strip()}
    except Exception as e:
        return {"error": True, "message": str(e)}

# ---------- Expert engines ----------

class PhishingExpert:
    """Deterministic scoring of phishing indicators.

    Indicators dict keys:
        unknown_sender, urgency, suspicious_link, unexpected_attachment,
        spoofed_domain, requests_credentials, generic_greeting, too_good_offer
    """

    _weights = {
        "requests_credentials": 0.25,
        "suspicious_link": 0.20,
        "urgency": 0.15,
        "spoofed_domain": 0.15,
        "unknown_sender": 0.10,
        "unexpected_attachment": 0.08,
        "generic_greeting": 0.04,
        "too_good_offer": 0.03,
    }

    _labels = {
        "unknown_sender": "I don't know the sender",
        "urgency": "It feels urgent or threatening",
        "suspicious_link": "It contains a link to click",
        "requests_credentials": "It asks for my password or personal info",
        "unexpected_attachment": "It has an attachment",
        "spoofed_domain": "The email address looks odd",
        "generic_greeting": "It uses a generic greeting like 'Dear Customer'",
        "too_good_offer": "It offers a prize or reward that seems too good",
    }

    def __init__(self, indicators: Dict[str, bool]):
        self.indicators = indicators

    def evaluate(self) -> Dict[str, Any]:
        score = 0.0
        triggered = []
        for key, weight in self._weights.items():
            if self.indicators.get(key):
                score += weight
                triggered.append(self._labels.get(key, key.replace('_', ' ')))
        # Clamp to 0‑1 range
        score = min(1.0, score)
        # Determine level
        if score >= 0.7:
            level = "HIGH"
        elif score >= 0.4:
            level = "MEDIUM"
        else:
            level = "LOW"
        # Recommendations – simple static list based on level
        recs = []
        if level == "HIGH":
            recs = [
                "Do NOT click any links or open attachments.",
                "Report the email to your IT/security team.",
                "Delete the email permanently.",
            ]
        elif level == "MEDIUM":
            recs = [
                "Verify the sender through another channel.",
                "Hover over any links to see the real URL before clicking.",
                "If it asks for a login, go directly to the official site.",
            ]
        else:
            recs = ["The email looks normal, but stay vigilant."]
        return {
            "risk_score": round(score, 3),
            "risk_level": level,
            "triggered_indicators": triggered,
            "recommendations": recs,
        }

class PasswordExpert:
    """Score a password without storing it.
    Returns a numeric score (0‑100), a strength label and improvement tips.
    """

    def __init__(self, password: str):
        self.password = password or ""

    def _entropy_estimate(self) -> float:
        # Simple Shannon entropy based on character set size
        if not self.password:
            return 0.0
        pool = 0
        if re.search(r"[a-z]", self.password):
            pool += 26
        if re.search(r"[A-Z]", self.password):
            pool += 26
        if re.search(r"\d", self.password):
            pool += 10
        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", self.password):
            pool += 32
        entropy = len(self.password) * (pool.bit_length())
        # Normalise roughly to 0‑10 scale
        return min(10.0, entropy / 12.0)

    def evaluate(self) -> Dict[str, Any]:
        pwd = self.password
        score = 0
        length = len(pwd)
        # Length points
        if length >= 20:
            score += 40
        elif length >= 16:
            score += 30
        elif length >= 12:
            score += 20
        elif length >= 8:
            score += 10
        # Character variety
        if re.search(r"[A-Z]", pwd):
            score += 10
        if re.search(r"[a-z]", pwd):
            score += 10
        if re.search(r"\d", pwd):
            score += 15
        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", pwd):
            score += 15
        # Entropy bonus
        score += int(self._entropy_estimate() * 10)
        score = min(100, score)
        # Labels
        if score >= 80:
            label = "Very Strong"
        elif score >= 60:
            label = "Strong"
        elif score >= 40:
            label = "Fair"
        else:
            label = "Weak"
        # Feedback suggestions
        feedback = []
        if length < 12:
            feedback.append("Use at least 12 characters.")
        if not re.search(r"[A-Z]", pwd):
            feedback.append("Add uppercase letters.")
        if not re.search(r"[a-z]", pwd):
            feedback.append("Add lowercase letters.")
        if not re.search(r"\d", pwd):
            feedback.append("Add numbers.")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", pwd):
            feedback.append("Add special symbols.")
        if not feedback:
            feedback.append("Your password looks good!")
        return {
            "score": score,
            "strength_label": label,
            "feedback": feedback,
        }

class HIBPExpert:
    """Check password against Have I Been Pwned using k‑anonymity.
    The plain password is never transmitted.
    """

    API_URL = "https://api.pwnedpasswords.com/range/"

    def __init__(self, password: str):
        self.password = password or ""

    def _sha1_hash(self) -> str:
        return hashlib.sha1(self.password.encode("utf-8")).hexdigest().upper()

    def check(self) -> Dict[str, Any]:
        if not self.password:
            return {"breached": False, "breach_count": 0}
        full_hash = self._sha1_hash()
        prefix = full_hash[:5]
        suffix = full_hash[5:]
        try:
            resp = requests.get(self.API_URL + prefix, timeout=10)
            resp.raise_for_status()
            lines = resp.text.splitlines()
            for line in lines:
                h, cnt = line.split(":")
                if h.upper() == suffix:
                    return {"breached": True, "breach_count": int(cnt)}
            return {"breached": False, "breach_count": 0}
        except Exception:
            # In case of network error, treat as not breached but flag
            return {"breached": False, "breach_count": 0, "error": True}

class FuzzyRiskEngine:
    """Combine phishing and password scores into an overall status.
    Phishing score is 0‑1, password score is 0‑100 (converted to 0‑1).
    """

    def __init__(self, phishing_score: float, password_score: float):
        self.phishing_score = phishing_score
        self.password_score = password_score / 100.0

    def evaluate(self) -> Dict[str, Any]:
        overall = (self.phishing_score * 0.6) + (self.password_score * 0.4)
        if overall >= 0.65:
            status = "Needs Work"
        elif overall >= 0.35:
            status = "Fair"
        else:
            status = "Great"
        return {"overall_score": round(overall, 3), "overall_status": status}

# ---------- Gemini powered agents ----------



class ARIAEngine:
    """Chat engine that talks to Gemini using the ARIA system prompt.
    Maintains conversation history.
    """

    SYSTEM_PROMPT = (
        "You are ARIA (Awareness & Risk Intelligence Advisor), a friendly and knowledgeable "
        "cybersecurity expert specialising in phishing awareness and password security. "
        "Your audience is everyday employees and members of the general public — not technical experts. "
        "Your mission is to educate, reassure, and empower them. Tone: warm, clear, calm, approachable. "
        "Never use jargon without explanation. If a user is anxious, reassure first, then guide. "
        "If a request is out of scope, respond: 'I am not able to help with that. ARIA is here to protect people.' "
        "Keep answers to 3‑6 sentences or short numbered steps. End with an invitation for more questions."
    )

    def __init__(self, history: List[Dict[str, str]] = None):
        self.history = history or []

    def ask(self, user_message: str) -> Dict[str, Any]:
        # Append user message
        self.history.append({"role": "user", "content": user_message})
        # Build messages for Gemini
        messages = []
        for h in self.history:
            role = "user" if h["role"] == "user" else "model"
            messages.append({"role": role, "content": h["content"]})
        
        result = _gemini_chat(messages, system_prompt=self.SYSTEM_PROMPT)
        if result.get("error"):
            reply = "I'm having trouble connecting right now. Please try again in a moment."
        else:
            reply = result["content"]
        # Append assistant reply to history for future context
        self.history.append({"role": "assistant", "content": reply})
        return {"reply": reply, "history": self.history}

# End of module
