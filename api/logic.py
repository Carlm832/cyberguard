"""
CyberGuard — Expert System Logic
Rule base, inference engines, and ARIA chat engine.
"""

import os
import hashlib
import json
import re
import math
import base64
import time
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
# OpenRouter + NVD — Live Threat Intel Feed
# ---------------------------------------------------------------------------

_OPENROUTER_BASE = "https://openrouter.ai/api/v1/chat/completions"
_NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _fetch_nvd_cves(max_items: int = 5) -> List[Dict[str, Any]]:
    """
    Fetches recent CVEs from the NVD API and normalizes them into
    a minimal dict with: cve_id, description, severity, score.
    Returns an empty list on failure.
    """
    try:
        resp = requests.get(
            _NVD_CVE_URL,
            params={"resultsPerPage": max_items},
            timeout=10,
        )
        resp.raise_for_status()
        raw = resp.json()
        vulns = raw.get("vulnerabilities", [])
        result = []
        for v in vulns:
            cve = v.get("cve", {})
            cve_id = str(cve.get("id", "Unknown CVE"))

            # English description
            desc = ""
            for d in cve.get("descriptions", []):
                if isinstance(d, dict) and d.get("lang") == "en":
                    desc = str(d.get("value", ""))
                    break
            if not desc:
                descs = cve.get("descriptions", [])
                desc = str(descs[0].get("value", "")) if descs else ""

            # Severity + score
            severity = "medium"
            score = None
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(key)
                if isinstance(metric_list, list) and metric_list:
                    m = metric_list[0]
                    base_sev = str(m.get("baseSeverity") or "").lower()
                    if base_sev in {"critical", "high", "medium", "low"}:
                        severity = base_sev
                    cvss_data = m.get("cvssData") or m
                    score = cvss_data.get("baseScore")
                    break

            result.append({
                "cve_id": cve_id,
                "description": desc[:500],
                "severity": severity,
                "score": score,
            })
        return result
    except Exception:
        return []

_THREAT_INTEL_FALLBACK = [
    {"title": "Credential phishing campaigns target shared inbox users", "summary": "Attackers use urgency language and spoofed support domains to harvest credentials from shared email accounts.", "severity": "high", "source": "CyberGuard Local Feed"},
    {"title": "Macro-lure attachments resurface in invoice themes", "summary": "Unexpected attachments disguised as invoices are prompting users to enable macros, delivering RAT payloads.", "severity": "medium", "source": "CyberGuard Local Feed"},
    {"title": "MFA fatigue prompts observed in helpdesk impersonation", "summary": "Users receive repeated push authentication prompts followed by fake IT support calls to approve access.", "severity": "medium", "source": "CyberGuard Local Feed"},
    {"title": "Lookalike domains mimic enterprise SSO portals", "summary": "Homograph and typo-squatting domains are redirecting users to cloned single sign-on login pages.", "severity": "high", "source": "CyberGuard Local Feed"},
    {"title": "Ransomware operators exploit unpatched VPN gateways", "summary": "Several ransomware groups are actively scanning for and exploiting known CVEs in popular enterprise VPN products.", "severity": "critical", "source": "CyberGuard Local Feed"},
]


def fetch_openrouter_threat_intel() -> List[Dict[str, Any]]:
    """
    Two-stage pipeline:
      1. Pull the latest CVEs from NVD API.
      2. Send them to OpenRouter to generate plain-language, actionable threat
         intelligence items enriched with CVE context.
    Falls back to static items if either stage fails.
    """
    api_key = os.getenv("OPEN_ROUTER_API_KEY", "").strip()
    model = os.getenv("OPEN_ROUTER_THREAT_MODEL", "google/gemma-4-31b-it:free").strip()

    # --- Stage 1: Fetch real CVEs from NVD ---
    cves = _fetch_nvd_cves(max_items=5)
    if not cves:
        # NVD unavailable — still try OpenRouter with a generic prompt
        cve_context = "No live CVE data available right now. Generate 5 realistic current threats."
    else:
        cve_lines = []
        for c in cves:
            score_str = f" (CVSS {c['score']})" if c.get("score") else ""
            cve_lines.append(
                f"- {c['cve_id']} [{c['severity'].upper()}{score_str}]: {c['description'][:300]}"
            )
        cve_context = "Here are the latest real CVEs from the NVD database:\n" + "\n".join(cve_lines)

    # --- Stage 2: Enrich via OpenRouter ---
    if not api_key:
        # No OpenRouter key — format NVD data directly as fallback items
        if cves:
            return [
                {
                    "title": c["cve_id"],
                    "summary": c["description"][:200],
                    "severity": c["severity"],
                    "source": "NVD (local)",
                }
                for c in cves
            ]
        return _THREAT_INTEL_FALLBACK

    prompt = (
        f"{cve_context}\n\n"
        "Using the CVE data above as your source, produce exactly 5 threat intelligence items. "
        "For each CVE, write a short plain-English headline and a 1–2 sentence explanation "
        "that a non-technical user can understand — avoiding raw CVE jargon where possible. "
        "Respond ONLY with a valid JSON array, no markdown, no code fences, no extra text. "
        "Each object must have these exact keys: "
        "\"title\" (max 80 chars), "
        "\"summary\" (max 200 chars), "
        "\"severity\" (one of: critical, high, medium, low), "
        "\"source\" (use \"NVD via OpenRouter\"). "
        "Example: [{\"title\": \"...\", \"summary\": \"...\", \"severity\": \"high\", \"source\": \"NVD via OpenRouter\"}]"
    )

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://cyberguard.app",
        "X-Title": "CyberGuard Threat Feed",
    }
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 900,
        "temperature": 0.4,
    }

    try:
        resp = requests.post(_OPENROUTER_BASE, json=payload, headers=headers, timeout=25)
        resp.raise_for_status()
        data = resp.json()
        raw_text = (
            data.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
            .strip()
        )
        # Strip any accidental markdown fences
        if raw_text.startswith("```"):
            raw_text = re.sub(r"^```[a-z]*\n?", "", raw_text)
            raw_text = re.sub(r"\n?```$", "", raw_text)

        items = json.loads(raw_text)
        if not isinstance(items, list):
            raise ValueError("Response was not a JSON list")

        normalized = []
        valid_severities = {"critical", "high", "medium", "low"}
        for item in items[:5]:
            if not isinstance(item, dict):
                continue
            sev = str(item.get("severity", "medium")).lower()
            normalized.append({
                "title": str(item.get("title", "Untitled Threat"))[:100],
                "summary": str(item.get("summary", ""))[:250],
                "severity": sev if sev in valid_severities else "medium",
                "source": str(item.get("source", "NVD via OpenRouter")),
            })
        return normalized if normalized else _THREAT_INTEL_FALLBACK

    except Exception:
        # OpenRouter failed — return raw NVD data as plain items if we have them
        if cves:
            return [
                {
                    "title": c["cve_id"],
                    "summary": c["description"][:200],
                    "severity": c["severity"],
                    "source": "NVD",
                }
                for c in cves
            ]
        return _THREAT_INTEL_FALLBACK


# ---------------------------------------------------------------------------
# Gemini helper
# ---------------------------------------------------------------------------

# Stable pinned model — avoids surprises from the rolling "-latest" alias.
_GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
# How long (seconds) to wait per attempt before giving up.
_GEMINI_TIMEOUT = int(os.getenv("GEMINI_TIMEOUT", "40"))
# Total retry attempts (1 = no retries, 2 = one retry, etc.).
_GEMINI_RETRIES = int(os.getenv("GEMINI_RETRIES", "2"))


def _cloud_chat(messages: List[Dict[str, str]], system_prompt: str = "", image: Dict[str, str] = None) -> Dict[str, Any]:
    # 1. Try Gemini primary
    api_key = os.getenv("GEMINI_API_KEY")
    gemini_error = "Gemini API key not configured."
    
    if api_key:
        endpoint = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{_GEMINI_MODEL}:generateContent?key={api_key}"
        )
        max_messages = max(2, int(os.getenv("ARIA_MAX_CLOUD_MESSAGES", "8")))
        cloud_messages = messages[-max_messages:]

        contents = []
        for i, msg in enumerate(cloud_messages):
            parts = []
            if image and i == len(cloud_messages) - 1 and msg["role"] == "user":
                parts.append({"inline_data": {"mime_type": image["mime_type"], "data": image["data"]}})
            parts.append({"text": msg["content"]})
            contents.append({"role": msg["role"], "parts": parts})

        payload = {
            "contents": contents,
            "generationConfig": {
                "maxOutputTokens": int(os.getenv("ARIA_MAX_OUTPUT_TOKENS", "420")),
                "temperature": float(os.getenv("ARIA_TEMPERATURE", "0.35")),
            }
        }
        if system_prompt:
            payload["system_instruction"] = {"parts": [{"text": system_prompt}]}

        for attempt in range(1, _GEMINI_RETRIES + 1):
            try:
                resp = requests.post(endpoint, json=payload, timeout=_GEMINI_TIMEOUT)
                if resp.status_code == 200:
                    data = resp.json()
                    candidates = data.get("candidates", [])
                    if candidates:
                        text = (
                            candidates[0]
                            .get("content", {})
                            .get("parts", [{}])[0]
                            .get("text", "")
                            .strip()
                        )
                        return {"error": False, "content": text}
                    gemini_error = "No candidates returned."
                else:
                    gemini_error = f"Gemini {resp.status_code}: {resp.text[:200]}"
            except Exception as exc:
                gemini_error = str(exc)

            if attempt < _GEMINI_RETRIES:
                time.sleep(1)

    # 2. Fallback to OpenRouter
    openrouter_key = os.getenv("OPEN_ROUTER_API_KEY", "").strip()
    if not openrouter_key:
        return {"error": True, "message": f"Gemini failed ({gemini_error}) and no OpenRouter fallback key found."}

    or_messages = []
    if system_prompt:
        or_messages.append({"role": "system", "content": system_prompt})
        
    max_messages = max(2, int(os.getenv("ARIA_MAX_CLOUD_MESSAGES", "8")))
    cloud_messages = messages[-max_messages:]
    
    for i, msg in enumerate(cloud_messages):
        role = "assistant" if msg["role"] == "model" else msg["role"]
        if image and i == len(cloud_messages) - 1 and role == "user":
            data_uri = f"data:{image['mime_type']};base64,{image['data']}"
            or_messages.append({
                "role": role,
                "content": [
                    {"type": "text", "text": msg["content"]},
                    {"type": "image_url", "image_url": {"url": data_uri}}
                ]
            })
        else:
            or_messages.append({"role": role, "content": msg["content"]})
            
    or_model = os.getenv("OPEN_ROUTER_CHAT_MODEL", "google/gemma-4-31b-it:free").strip()
    
    headers = {
        "Authorization": f"Bearer {openrouter_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://cyberguard.app",
        "X-Title": "CyberGuard ARIA Chat",
    }
    
    payload = {
        "model": or_model,
        "messages": or_messages,
        "max_tokens": int(os.getenv("ARIA_MAX_OUTPUT_TOKENS", "420")),
        "temperature": float(os.getenv("ARIA_TEMPERATURE", "0.35")),
    }
    
    try:
        resp = requests.post(_OPENROUTER_BASE, json=payload, headers=headers, timeout=_GEMINI_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        text = (
            data.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
            .strip()
        )
        return {"error": False, "content": text}
    except Exception as exc:
        return {"error": True, "message": f"Gemini failed ({gemini_error}) and OpenRouter fallback failed: {str(exc)}"}


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
        # Submission-safe mode: local engine first, cloud optional.
        aria_mode = os.getenv("ARIA_MODE", "auto").strip().lower()
        if aria_mode in {"local", "offline", "local_only"}:
            reply = self._local_fallback_reply(user_message, session_context)
            self.history.append({"role": "user", "content": user_message})
            self.history.append({"role": "assistant", "content": reply})
            return {
                "reply": reply,
                "history": self.history,
                "follow_ups": self._follow_ups(session_context, user_message, self.history),
            }

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

        result = _cloud_chat(messages, system_prompt=full_system, image=image)
        reply = result["content"] if not result.get("error") else self._local_fallback_reply(user_message, session_context)
        self.history.append({"role": "assistant", "content": reply})

        return {
            "reply": reply,
            "history": self.history,
            "follow_ups": self._follow_ups(session_context, user_message, self.history),
        }

    def _local_fallback_reply(self, user_message: str, session_context: dict = None) -> str:
        """Provide deterministic local guidance when cloud LLM is unavailable."""
        msg = (user_message or "").strip()
        msg_l = msg.lower()
        match = re.search(r"\bR\d{2}\b", msg, flags=re.IGNORECASE)
        if match:
            rule_id = match.group(0).upper()
            rule = next((r for r in PHISHING_RULES if r["id"] == rule_id), None)
            if rule:
                return (
                    f"{rule['id']} is '{rule['name']}' with certainty factor {rule['cf']:.2f}. "
                    f"It belongs to the '{rule['category']}' category. "
                    f"Why it matters: {rule['explanation']} "
                    f"Example pattern: {rule['example']} "
                    f"If this signal appears with other indicators, the overall phishing risk increases quickly."
                )

        if "certainty factor" in msg_l or "cf" in msg_l:
            return (
                "Certainty factor (CF) is the weight each rule contributes to the phishing score when it fires. "
                "Your engine sums fired rule CFs and caps at 1.0. "
                "For example, if R01 (0.25) and R04 (0.15) fire, they contribute 0.40 total before any other rules. "
                "That score then maps to risk bands: LOW (<0.40), MEDIUM (0.40-0.69), HIGH (>=0.70)."
            )

        if "high threat" in msg_l or "high risk" in msg_l:
            return (
                "A HIGH threat verdict is triggered when total fired-rule confidence reaches 0.70 or more. "
                "This usually means multiple high-signal indicators fired together, such as credential requests, suspicious links, and spoofed domains. "
                "Compound rules like R10 (credential request + spoofed domain) increase score faster. "
                "At HIGH threat, the safe action is to avoid all links/attachments and report immediately."
            )

        if "spot a phishing" in msg_l or "how do i spot" in msg_l:
            return (
                "Use a quick rule check: credential request, suspicious link, urgency framing, spoofed sender domain, and unexpected attachment. "
                "If two or more high-signal indicators appear together, treat it as likely phishing. "
                "Never sign in from email links; open the official site manually instead. "
                "When unsure, verify the request through a separate trusted channel."
            )

        if "strong password" in msg_l or "password" in msg_l:
            return (
                "A strong password is long (12-16+ characters), unique per account, and mixes uppercase, lowercase, numbers, and symbols. "
                "Avoid common passwords, keyboard patterns, and repeated characters. "
                "Use a password manager to generate and store unique credentials. "
                "Enable two-factor authentication for critical accounts."
            )

        if "posture advice" in msg_l or "threat posture advice" in msg_l or "advice" in msg_l:
            if session_context and session_context.get("phishing_verdict"):
                verdict = session_context["phishing_verdict"]
                fired_rules = verdict.get("fired_rules", [])
                fired_ids = [r.get("id", "") for r in fired_rules]
                recs = verdict.get("recommendations", [])
                rec_text = " ".join(recs[:3]) if recs else "Verify sender identity through an independent channel."
                return (
                    f"Current posture is {verdict.get('risk_level', 'LOW')} with score {verdict.get('risk_score', 0)}. "
                    f"Key triggered rules: {', '.join(fired_ids) if fired_ids else 'none'}. "
                    f"Immediate actions: {rec_text} "
                    f"Priority next step: capture this message context (sender, URL, attachment hash) and submit it to your security process."
                )
            return (
                "Run a phishing assessment first so I can ground advice in fired rules and confidence score. "
                "In general: block risky clicks, enforce MFA, use unique passwords, and verify urgent requests out-of-band. "
                "Treat unknown senders plus urgency as a high-priority review case."
            )

        if session_context and session_context.get("phishing_verdict"):
            verdict = session_context["phishing_verdict"]
            fired = ", ".join(r["id"] for r in verdict.get("fired_rules", [])) or "none"
            return (
                f"I cannot reach cloud AI right now, but your local expert-system verdict is still available. "
                f"Risk level is {verdict.get('risk_level', 'LOW')} with score {verdict.get('risk_score', 0)} and fired rules: {fired}. "
                f"Use the recommendation list shown in the report as your immediate action plan."
            )

        return (
            "I cannot reach cloud AI at the moment, but the local expert system is running. "
            "You can still run phishing/password assessments and inspect the rule base (R01-R10). "
            "Ask for a specific rule ID like R01 and I will explain it from the local knowledge base."
        )

    def summarize_discussion(self, session_context: dict = None) -> str:
        user_msgs = [h.get("content", "") for h in self.history if h.get("role") == "user" and h.get("content")]
        if not user_msgs:
            return "No discussion to summarize yet. Ask ARIA a few questions first."

        topics = []
        joined = " ".join(user_msgs).lower()
        if "r0" in joined or "rule" in joined:
            topics.append("rule base interpretation")
        if "password" in joined or "entropy" in joined or "hibp" in joined:
            topics.append("password resilience")
        if "phish" in joined or "sender" in joined or "link" in joined:
            topics.append("phishing signal assessment")
        if "posture" in joined or "risk" in joined:
            topics.append("overall risk posture")

        topic_line = ", ".join(topics) if topics else "general cyber hygiene"

        if session_context and session_context.get("phishing_verdict"):
            verdict = session_context["phishing_verdict"]
            fired = ", ".join(r.get("id", "") for r in verdict.get("fired_rules", [])) or "none"
            return (
                "Discussion Summary:\n"
                f"- Primary topics covered: {topic_line}.\n"
                f"- Current phishing verdict: {verdict.get('risk_level', 'LOW')} ({verdict.get('risk_score', 0)}), fired rules: {fired}.\n"
                "- ARIA guidance emphasized verifying sender identity, avoiding direct login links, and escalating suspicious messages.\n"
                "- Recommended next step: run a fresh assessment when new indicators appear and track trend changes over time."
            )

        return (
            "Discussion Summary:\n"
            f"- Primary topics covered: {topic_line}.\n"
            "- ARIA guidance focused on interpreting rules, certainty factors, and practical hardening actions.\n"
            "- Recommended next step: run dashboard assessments so guidance can be tied to fired rules and confidence values."
        )

    def _follow_ups(self, ctx: dict = None, last_user_message: str = "", history: List[Dict[str, str]] = None) -> List[str]:
        msg = (last_user_message or "").lower()
        hlen = len(history or [])
        if hlen <= 2:
            return [
                "Explain the rules behind this result.",
                "Show me what raised my current risk score.",
                "Help me choose between phishing signals and password resilience.",
            ]
        if "r0" in msg or "rule" in msg:
            return ["Explain another rule next.", "Show me an example attack pattern for this rule.", "Map this rule to mitigation actions."]
        if "posture" in msg or "risk" in msg:
            return ["Give me a prioritized 3-step action plan.", "Re-check which indicators are driving my score most.", "Convert this into an incident note summary."]
        if "password" in msg or "entropy" in msg:
            return ["Give me a target password policy for my team.", "Explain which password checks failed and why.", "Show me 2FA rollout recommendations."]
        if ctx and ctx.get("phishing_verdict"):
            return ["Why did these rules fire?", "What should I do right now?", "What if I already clicked a link?", "How confident is this verdict?"]
        if ctx and ctx.get("password_verdict"):
            return ["How do I make it stronger?", "What is a password manager?", "Should I enable two-factor authentication?", "What makes a password uncrackable?"]
        return ["How do I spot a phishing email?", "What makes a strong password?", "How do I check if I've been breached?", "What is two-factor authentication?"]
