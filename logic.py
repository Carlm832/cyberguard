import re
import json
import os
from urllib import error, request


class EmailExpert:
    """Rule-based engine for assessing phishing threats."""

    def __init__(self):
        self.risk_factors = {
            "unknown_sender": 0.3,
            "malicious_links": 0.4,
            "urgency": 0.2,
            "sensitive_info_request": 0.4,
        }

    def evaluate(self, factors):
        """
        Evaluates email risk based on boolean factors.
        Returns a score from 0.0 to 1.0.
        """
        score = 0.0
        if factors.get("unknown_sender"):
            score += self.risk_factors["unknown_sender"]
        if factors.get("malicious_links"):
            score += self.risk_factors["malicious_links"]
        if factors.get("urgency"):
            score += self.risk_factors["urgency"]
        if factors.get("sensitive_info_request"):
            score += self.risk_factors["sensitive_info_request"]

        return min(1.0, score)


class PasswordExpert:
    """Rule-based engine for assessing password strength."""

    def evaluate(self, password):
        """
        Assesses password strength based on expert rules.
        Returns a strength score from 0.0 to 1.0 (1.0 is strongest).
        """
        if not password:
            return 0.0

        score = 0
        length = len(password)

        # Length rules
        if length >= 12:
            score += 4
        elif length >= 8:
            score += 2

        # Complexity rules
        if re.search(r"[A-Z]", password):
            score += 1
        if re.search(r"[a-z]", password):
            score += 1
        if re.search(r"\d", password):
            score += 2
        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            score += 2

        # Normalize to 0-1
        return min(1.0, score / 10.0)


class FuzzyRiskEngine:
    """Fuzzy Logic engine for combining risks."""

    def get_risk_label(self, score):
        if score < 0.35:
            return "LOW"
        if score < 0.7:
            return "MEDIUM"
        return "HIGH"

    def compute_total_risk(self, email_risk, password_strength=None):
        """
        Hybrid Fuzzy Inference:
        Combines email risk (0-1) and password weakness (1 - strength).
        """
        if password_strength is None:
            return round(email_risk, 2)

        pwd_weakness = 1.0 - password_strength

        # Weighted aggregate:
        # Email has higher weight because phishing is an active threat vector.
        total_score = (email_risk * 0.7) + (pwd_weakness * 0.3)

        return round(total_score, 2)

    def get_recommendations(self, email_factors, pwd_strength=None):
        recs = []
        if email_factors.get("malicious_links"):
            recs.append("Do not click links in suspicious emails.")
        if email_factors.get("sensitive_info_request"):
            recs.append("Never provide passwords or PII through email.")
        if pwd_strength is not None and pwd_strength < 0.6:
            recs.append("Improve password quality: use 12+ characters with symbols.")
        if not recs:
            recs.append("Continue following standard security procedures.")
        return recs


class SecurityChatExpert:
    """Rule-based Q&A assistant for phishing and password security."""

    def __init__(self):
        self.openrouter = OpenRouterClient()
        self.knowledge_base = [
            {
                "id": "PHISH_SENDER_01",
                "keywords": {"spoofed sender", "display name", "from address", "impersonation", "sender"},
                "answer": (
                    "Validate both the sender display name and full email domain. Impersonation often uses "
                    "small spelling changes or a different sender domain."
                ),
                "follow_up": "Do you want a checklist to verify whether this sender is legitimate?",
            },
            {
                "id": "PHISH_LINK_02",
                "keywords": {"link", "url", "hover", "domain", "typo", "misspelled domain"},
                "answer": (
                    "Hover before clicking and inspect the full URL. Watch for misspelled domains, extra subdomains, "
                    "or login pages hosted on unfamiliar domains."
                ),
                "follow_up": "Would you like a quick method to compare a suspicious URL with the real domain?",
            },
            {
                "id": "PHISH_URGENCY_03",
                "keywords": {"urgent", "immediately", "suspend", "action required", "deadline"},
                "answer": (
                    "Urgency is a major phishing signal. Pause and verify through a trusted channel before taking action."
                ),
                "follow_up": "Can I give you a short pause-and-verify routine for urgent messages?",
            },
            {
                "id": "PHISH_ATTACHMENT_04",
                "keywords": {"attachment", "invoice", "pdf", "zip", "macro", "docm"},
                "answer": (
                    "Treat unexpected attachments as high risk, especially macro-enabled files and archives. "
                    "Open only after independent verification."
                ),
                "follow_up": "Do you want safe steps for handling unknown attachments?",
            },
            {
                "id": "PHISH_QR_05",
                "keywords": {"qr", "quishing", "scan code", "qr code"},
                "answer": (
                    "QR phishing hides malicious links inside codes. Scan only from trusted sources and preview the URL first."
                ),
                "follow_up": "Would you like rules for safely handling QR codes in emails and posters?",
            },
            {
                "id": "PHISH_SMISH_06",
                "keywords": {"sms", "text message", "smishing", "mobile scam"},
                "answer": (
                    "Smishing messages often use fake delivery, bank, or account alerts. Do not tap links in unexpected texts."
                ),
                "follow_up": "Should I share a safe verification flow for suspicious SMS messages?",
            },
            {
                "id": "PHISH_VOICE_07",
                "keywords": {"vishing", "phone call", "caller", "support call", "helpdesk"},
                "answer": (
                    "Vishing attacks pressure you by phone. Hang up and call the organization using an official number."
                ),
                "follow_up": "Do you want a script you can use to end suspicious calls safely?",
            },
            {
                "id": "PHISH_BEC_08",
                "keywords": {"ceo fraud", "wire transfer", "gift card", "executive request", "bec"},
                "answer": (
                    "Business Email Compromise often requests urgent payments or gift cards. Require out-of-band approval."
                ),
                "follow_up": "Would a two-person approval rule for payment requests help your project demo?",
            },
            {
                "id": "PHISH_REPLYTO_09",
                "keywords": {"reply-to", "reply to", "different address", "redirect reply"},
                "answer": (
                    "If the Reply-To address differs from the sender domain, treat it as suspicious and verify manually."
                ),
                "follow_up": "Want a quick checklist of email header fields to inspect?",
            },
            {
                "id": "PHISH_LOGIN_10",
                "keywords": {"login page", "sign in", "credential page", "fake login"},
                "answer": (
                    "Never sign in through links in unexpected messages. Open the service directly from your bookmark."
                ),
                "follow_up": "Would you like a rule to detect fake login pages fast?",
            },
            {
                "id": "PHISH_RESET_11",
                "keywords": {"password reset email", "reset request", "did not request"},
                "answer": (
                    "Unrequested password reset emails can be phishing or account probing. Go directly to the service site."
                ),
                "follow_up": "Do you want incident steps for unrequested password reset notifications?",
            },
            {
                "id": "PHISH_SHORT_12",
                "keywords": {"short link", "bit.ly", "tinyurl", "shortened"},
                "answer": (
                    "Short links hide the destination. Use a preview/expander service before opening, or avoid entirely."
                ),
                "follow_up": "Would you like tools to safely expand shortened URLs?",
            },
            {
                "id": "PHISH_HTTPS_13",
                "keywords": {"https", "padlock", "secure site"},
                "answer": (
                    "HTTPS only means encrypted transport, not legitimacy. A phishing site can still have HTTPS."
                ),
                "follow_up": "Do you want criteria beyond HTTPS for judging site trustworthiness?",
            },
            {
                "id": "PWD_STRENGTH_14",
                "keywords": {"password", "strong password", "weak password", "strength"},
                "answer": (
                    "Use long, unique passwords. Length and uniqueness matter more than frequent forced changes."
                ),
                "follow_up": "Do you want examples of strong passphrase formats?",
            },
            {
                "id": "PWD_LENGTH_15",
                "keywords": {"length", "12 characters", "minimum length", "long password"},
                "answer": (
                    "Aim for at least 12 characters. Longer passphrases are usually more resilient and easier to remember."
                ),
                "follow_up": "Would you like a quick passphrase template for your users?",
            },
            {
                "id": "PWD_REUSE_16",
                "keywords": {"reuse", "same password", "multiple accounts"},
                "answer": (
                    "Password reuse is high risk. One breach can expose many accounts if passwords are reused."
                ),
                "follow_up": "Should I provide a migration plan to stop password reuse?",
            },
            {
                "id": "PWD_MANAGER_17",
                "keywords": {"password manager", "vault", "store passwords", "manager"},
                "answer": (
                    "A reputable password manager helps generate unique credentials and reduces reuse risk."
                ),
                "follow_up": "Do you want selection criteria for choosing a password manager?",
            },
            {
                "id": "PWD_MFA_18",
                "keywords": {"mfa", "2fa", "multi-factor", "authenticator"},
                "answer": (
                    "Enable MFA on critical accounts. Authenticator apps or hardware keys are generally stronger than SMS."
                ),
                "follow_up": "Would you like a prioritization list of accounts that should get MFA first?",
            },
            {
                "id": "PWD_BREACH_19",
                "keywords": {"breach", "leak", "compromised", "exposed password"},
                "answer": (
                    "After a breach, change affected passwords immediately, rotate reused credentials, and enable MFA."
                ),
                "follow_up": "Do you want a step-by-step breach response checklist?",
            },
            {
                "id": "PWD_ROTATION_20",
                "keywords": {"change password often", "rotation", "how often"},
                "answer": (
                    "Do not rotate strong passwords on a strict schedule unless policy requires it. "
                    "Rotate immediately when compromise is suspected."
                ),
                "follow_up": "Would you like policy language balancing usability and security?",
            },
            {
                "id": "PWD_SECURITY_Q_21",
                "keywords": {"security question", "mother's maiden name", "pet name"},
                "answer": (
                    "Security questions are weak if answers are guessable. Use random stored answers where possible."
                ),
                "follow_up": "Want examples of safer approaches when security questions are mandatory?",
            },
            {
                "id": "OTP_SHARE_22",
                "keywords": {"otp", "one-time code", "verification code", "share code"},
                "answer": (
                    "Never share one-time verification codes. Legitimate support teams will not ask for them."
                ),
                "follow_up": "Do you want a short warning message users can memorize for OTP scams?",
            },
            {
                "id": "SIM_SWAP_23",
                "keywords": {"sim swap", "port out", "phone takeover"},
                "answer": (
                    "SIM swap attacks can intercept SMS codes. Add carrier PIN protection and prefer app-based MFA."
                ),
                "follow_up": "Would you like safeguards for accounts still using SMS MFA?",
            },
            {
                "id": "MFA_FATIGUE_24",
                "keywords": {"mfa fatigue", "push bombing", "approval spam"},
                "answer": (
                    "Push-bombing attacks spam MFA prompts until a user accepts one. Deny unexpected prompts and report immediately."
                ),
                "follow_up": "Do you want user instructions for handling repeated MFA prompts?",
            },
            {
                "id": "RECOVERY_CODES_25",
                "keywords": {"backup codes", "recovery code", "account recovery"},
                "answer": (
                    "Store recovery codes offline in a secure location. They are critical if your second factor is lost."
                ),
                "follow_up": "Would you like a safe storage strategy for recovery codes?",
            },
            {
                "id": "PUBLIC_WIFI_26",
                "keywords": {"public wifi", "airport wifi", "coffee shop wifi"},
                "answer": (
                    "Avoid sensitive logins on public Wi-Fi without protection. Use trusted networks and MFA."
                ),
                "follow_up": "Do you want safe browsing rules for public networks?",
            },
            {
                "id": "BROWSER_SAVE_27",
                "keywords": {"save password in browser", "browser password", "autofill"},
                "answer": (
                    "Browser storage can be acceptable with device security controls, but a dedicated password manager is stronger."
                ),
                "follow_up": "Would you like a quick comparison: browser vault vs password manager?",
            },
            {
                "id": "ACCOUNT_LOCK_28",
                "keywords": {"account lockout", "failed login", "brute force"},
                "answer": (
                    "Use lockout and rate-limiting controls to slow brute-force attempts and alert on repeated failures."
                ),
                "follow_up": "Should I provide recommended lockout thresholds for a school project?",
            },
        ]
        self.default_result = {
            "answer": (
                "I am not fully certain about that topic yet. Safest next step: avoid clicking unknown links, "
                "do not share credentials or OTP codes, and verify through official channels."
            ),
            "rule_id": "FALLBACK_SAFE_00",
            "confidence": 0.2,
            "follow_up": "Would you like to rephrase your question as phishing, password, MFA, or breach related?",
            "matched_keywords": [],
        }
        self.llm_threshold = 0.55

    @staticmethod
    def _tokenize(text):
        return set(re.findall(r"[a-z0-9]+", text.lower()))

    def _score_rule(self, lowered, tokens, rule):
        score = 0
        matched = []
        for keyword in rule["keywords"]:
            if " " in keyword:
                if keyword in lowered:
                    score += 2
                    matched.append(keyword)
            elif keyword in tokens:
                score += 1
                matched.append(keyword)
        return score, matched

    def answer_question(self, question, prefer_nlp=True):
        """Return the best rule-based answer for a user question."""
        if not question or not question.strip():
            return {
                "answer": "Please type a question about phishing or password security.",
                "rule_id": "INPUT_EMPTY_00",
                "confidence": 1.0,
                "follow_up": "Try: 'How can I detect a phishing email?'",
                "matched_keywords": [],
            }

        lowered = question.lower()
        tokens = self._tokenize(question)

        best_rule = None
        best_score = 0
        best_matches = []
        second_score = 0

        for rule in self.knowledge_base:
            score, matched = self._score_rule(lowered, tokens, rule)
            if score > best_score:
                second_score = best_score
                best_score = score
                best_rule = rule
                best_matches = matched
            elif score > second_score:
                second_score = score

        if prefer_nlp:
            llm_result = self.openrouter.answer(question)
            if llm_result:
                return llm_result

        if best_rule and best_score > 0:
            separation_bonus = 1 if best_score > second_score else 0
            confidence = min(0.95, 0.35 + (best_score * 0.12) + (separation_bonus * 0.08))
            result = {
                "answer": best_rule["answer"],
                "rule_id": best_rule["id"],
                "confidence": round(confidence, 2),
                "follow_up": best_rule["follow_up"],
                "matched_keywords": sorted(best_matches),
            }
            if result["confidence"] >= self.llm_threshold or not prefer_nlp:
                return result
            llm_result = self.openrouter.answer(question)
            return llm_result or result

        llm_result = self.openrouter.answer(question)
        return llm_result or self.default_result


class OpenRouterClient:
    """Optional OpenRouter NLP fallback for broader security Q&A."""

    def __init__(self):
        self.api_key = os.getenv("OPENROUTER_API_KEY", "").strip()
        self.model = os.getenv("OPENROUTER_MODEL", "openai/gpt-4o-mini")
        self.url = "https://openrouter.ai/api/v1/chat/completions"
        self.timeout_sec = 12

    def _enabled(self):
        return bool(self.api_key)

    def capabilities(self):
        return {
            "enabled": self._enabled(),
            "model": self.model,
        }

    def answer(self, question):
        if not self._enabled():
            return None

        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a cybersecurity assistant. Provide concise, practical guidance focused on phishing, "
                        "password hygiene, MFA, account security, and breach response. Avoid legal/medical claims. "
                        "If unsure, say uncertainty and give safest next action."
                    ),
                },
                {"role": "user", "content": question},
            ],
            "temperature": 0.3,
            "max_tokens": 260,
        }

        req = request.Request(
            self.url,
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
                "HTTP-Referer": "http://localhost:8000",
                "X-Title": "CyberGuard",
            },
        )

        try:
            with request.urlopen(req, timeout=self.timeout_sec) as response:
                data = json.loads(response.read().decode("utf-8"))
        except (error.URLError, error.HTTPError, TimeoutError, json.JSONDecodeError):
            return None

        choices = data.get("choices") or []
        if not choices:
            return None

        message = (choices[0].get("message") or {}).get("content", "").strip()
        if not message:
            return None

        return {
            "answer": message,
            "rule_id": f"OPENROUTER_{self.model}",
            "confidence": 0.7,
            "follow_up": "Want me to turn this into a short step-by-step checklist?",
            "matched_keywords": [],
        }
