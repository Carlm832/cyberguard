"""
CyberGuard — FastAPI Entry Point (v3.1)
Uses SessionMiddleware for serverless-safe session storage.
"""

import os
import sys
from pathlib import Path
from typing import Any, List, Dict, Optional
import requests
import time

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel
import uvicorn
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from fastapi import BackgroundTasks

try:
    from .logic import ARIAEngine, FuzzyRiskEngine, HIBPExpert, PasswordExpert, PhishingExpert, PHISHING_RULES
except ImportError:
    from logic import ARIAEngine, FuzzyRiskEngine, HIBPExpert, PasswordExpert, PhishingExpert, PHISHING_RULES

def log_message(msg: str):
    try:
        if getattr(sys, "frozen", False):
            log_dir = Path(sys.executable).resolve().parent
        else:
            log_dir = BASE_DIR.parent
        log_file = log_dir / "cyberguard.log"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {msg}\n")
    except Exception as e:
        print(f"Logging failed: {e}")

def _load_env() -> None:
    """
    Load environment variables from likely runtime locations.
    Priority:
    1) executable directory (PyInstaller one-file runtime scenario)
    2) current working directory
    3) project root relative to source tree
    """
    candidate_paths = []
    if getattr(sys, "frozen", False):
        candidate_paths.append(Path(sys.executable).resolve().parent / ".env")
    candidate_paths.append(Path.cwd() / ".env")
    candidate_paths.append(BASE_DIR.parent / ".env")

    loaded = False
    for env_path in candidate_paths:
        if env_path.exists():
            load_dotenv(env_path, override=False)
            log_message(f"Loaded .env file from: {env_path}")
            loaded = True
            break
    if not loaded:
        log_message("Warning: No .env file found in candidate locations.")

_load_env()

app = FastAPI(title="CyberGuard", version="3.1.0")

_THREAT_CACHE: Dict[str, Any] = {"ts": 0.0, "items": []}

# Mount static folder
app.mount("/static", StaticFiles(directory=str(BASE_DIR.parent / "public" / "static")), name="static")

# SessionMiddleware uses secure cookies to store session data across serverless calls
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET_KEY", "cyberguard-expert-system-secret-18239"),
    max_age=3600
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", response_class=FileResponse)
async def serve_index():
    return FileResponse(str(BASE_DIR.parent / "templates" / "index.html"))

@app.get("/favicon.ico")
async def favicon():
    # Avoid noisy 404s when no favicon asset is bundled.
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class PhishingRequest(BaseModel):
    indicators: Dict[str, bool] = {}

class PasswordRequest(BaseModel):
    password: str = ""

class PostureRequest(BaseModel):
    phishing_score: float = 0.0
    password_score: float = 50.0

class ChatRequest(BaseModel):
    message: str
    history: List[Dict[str, str]] = []
    image: Optional[Dict[str, str]] = None

class ChatSummaryRequest(BaseModel):
    history: List[Dict[str, str]] = []

class EmailRequest(BaseModel):
    recipient_email: str
    report_type: str
    metrics: Dict[str, Any]
    fired_rules: List[Dict[str, Any]] = []
    aria_explanation: str = ""
    indicators: Dict[str, bool] = {}


# ---------------------------------------------------------------------------
# /api/rules — Knowledge Base
# ---------------------------------------------------------------------------

@app.get("/api/rules")
async def get_rules():
    return JSONResponse({"rules": PHISHING_RULES, "total": len(PHISHING_RULES)})


# ---------------------------------------------------------------------------
# /api/phishing — Phishing detector
# ---------------------------------------------------------------------------

@app.post("/api/phishing")
async def run_phishing(req: PhishingRequest, request: Request):
    expert = PhishingExpert(req.indicators)
    verdict = expert.evaluate()

    # Store in session
    request.session["phishing_verdict"] = verdict
    
    # Track statistics in session
    analyses = request.session.get("analyses_run", 0) + 1
    request.session["analyses_run"] = analyses
    
    fired_ids = [r["id"] for r in verdict["fired_rules"]]
    all_fired = request.session.get("all_fired_rules", [])
    for f_id in fired_ids:
        if f_id not in all_fired:
            all_fired.append(f_id)
    request.session["all_fired_rules"] = all_fired

    highest = request.session.get("highest_threat", "LOW")
    threat_ranks = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
    if threat_ranks.get(verdict["risk_level"], 1) > threat_ranks.get(highest, 1):
        request.session["highest_threat"] = verdict["risk_level"]

    # Re-evaluate posture if we have password verdict
    pwd_verdict = request.session.get("password_verdict")
    if pwd_verdict:
        posture_engine = FuzzyRiskEngine(verdict["risk_score"], pwd_verdict["score"])
        request.session["posture"] = posture_engine.evaluate()

    # Generate ARIA verdict
    aria = ARIAEngine()
    fired_str = ", ".join(f_id for f_id in fired_ids) or "none"
    if verdict["risk_score"] < 0.1:
        aria_prompt = (
            "The phishing analysis found no significant indicators. "
            "Tell the user in 2 sentences that no strong phishing signals were detected, "
            "and remind them to stay vigilant."
        )
    else:
        aria_prompt = (
            f"The inference engine fired rules {fired_str} with a total confidence of "
            f"{verdict['risk_score']} (risk level: {verdict['risk_level']}). "
            f"Explain this to a non-technical user in 3–4 sentences, citing the rule IDs. "
            f"Do not invent reasoning beyond these rules."
        )

    aria_result = aria.ask(aria_prompt, session_context=request.session)
    verdict["aria_explanation"] = aria_result["reply"]
    verdict["follow_ups"] = aria_result["follow_ups"]
    
    # Save back updated session info
    request.session["phishing_verdict"] = verdict
    return JSONResponse(verdict)


# ---------------------------------------------------------------------------
# /api/password — Password analyser
# ---------------------------------------------------------------------------

@app.post("/api/password")
async def run_password(req: PasswordRequest, request: Request):
    if not req.password:
        return JSONResponse({"error": "No password provided"}, status_code=400)

    pwd_expert = PasswordExpert(req.password)
    pwd_verdict = pwd_expert.evaluate()

    hibp_expert = HIBPExpert(req.password)
    hibp_result = hibp_expert.check()

    # Store in session
    request.session["password_verdict"] = pwd_verdict
    request.session["hibp_result"] = hibp_result

    analyses = request.session.get("analyses_run", 0) + 1
    request.session["analyses_run"] = analyses

    # Re-evaluate posture if we have phishing verdict
    phish_verdict = request.session.get("phishing_verdict")
    if phish_verdict:
        posture_engine = FuzzyRiskEngine(phish_verdict["risk_score"], pwd_verdict["score"])
        request.session["posture"] = posture_engine.evaluate()
    else:
        # Default fallback posture evaluation with 0 phishing risk
        posture_engine = FuzzyRiskEngine(0.0, pwd_verdict["score"])
        request.session["posture"] = posture_engine.evaluate()

    aria = ARIAEngine()
    aria_prompt = (
        f"Password analysis complete. Strength: {pwd_verdict['strength_label']} "
        f"({pwd_verdict['score']}/100), entropy: {pwd_verdict['entropy_bits']} bits, "
        f"estimated crack time: {pwd_verdict['crack_time']}. "
        + (f"BREACH: found in {hibp_result['breach_count']:,} known data breaches. " if hibp_result.get("breached") else "Not found in known breach databases. ")
        + f"Issues identified: {', '.join(pwd_verdict['feedback'])}. "
        f"Give 2–3 specific improvement recommendations referencing the check IDs where relevant."
    )
    aria_result = aria.ask(aria_prompt, session_context=request.session)

    return JSONResponse({
        "password": pwd_verdict,
        "hibp": hibp_result,
        "aria_explanation": aria_result["reply"],
        "follow_ups": aria_result["follow_ups"],
    })


# ---------------------------------------------------------------------------
# /api/posture — Fuzzy overall posture
# ---------------------------------------------------------------------------

@app.post("/api/posture")
async def run_posture(req: PostureRequest, request: Request):
    engine = FuzzyRiskEngine(req.phishing_score, req.password_score)
    result = engine.evaluate()
    request.session["posture"] = result
    return JSONResponse(result)


# ---------------------------------------------------------------------------
# /api/session-summary — Dashboard statistics
# ---------------------------------------------------------------------------

@app.get("/api/session-summary")
async def session_summary(request: Request):
    """Returns aggregated session statistics for the dashboard view."""
    return JSONResponse({
        "analyses_run": request.session.get("analyses_run", 0),
        "highest_threat": request.session.get("highest_threat", "LOW"),
        "all_fired_rules": request.session.get("all_fired_rules", []),
        "posture": request.session.get("posture", None)
    })

@app.get("/api/health/ai")
async def ai_health():
    """
    Quick ARIA connectivity diagnostics:
    - verifies Gemini key presence
    - performs a lightweight Gemini API probe
    """
    api_key = os.getenv("GEMINI_API_KEY")
    aria_mode = os.getenv("ARIA_MODE", "auto").strip().lower()
    if not api_key:
        return JSONResponse({
            "ok": False,
            "provider": "gemini",
            "aria_mode": aria_mode,
            "api_key_present": False,
            "error": "GEMINI_API_KEY is not configured"
        }, status_code=503)

    endpoint = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
    try:
        resp = requests.get(endpoint, timeout=8)
        body_preview = (resp.text or "")[:300]
        if resp.status_code == 200:
            return JSONResponse({
                "ok": True,
                "provider": "gemini",
                "aria_mode": aria_mode,
                "api_key_present": True,
                "status_code": resp.status_code
            })
        return JSONResponse({
            "ok": False,
            "provider": "gemini",
            "aria_mode": aria_mode,
            "api_key_present": True,
            "status_code": resp.status_code,
            "error": body_preview
        }, status_code=503)
    except Exception as e:
        return JSONResponse({
            "ok": False,
            "provider": "gemini",
            "aria_mode": aria_mode,
            "api_key_present": True,
            "error": str(e)
        }, status_code=503)

@app.get("/api/threat-intel")
async def threat_intel():
    """
    Returns normalized threat feed items.
    If THREAT_FEED_URL is configured, fetches remote data and caches it.
    Otherwise returns deterministic local fallback items.
    """
    now = time.time()
    cache_ttl = int(os.getenv("THREAT_FEED_CACHE_SECONDS", "3600"))
    if _THREAT_CACHE["items"] and (now - _THREAT_CACHE["ts"] < cache_ttl):
        return JSONResponse({"ok": True, "source": "cache", "items": _THREAT_CACHE["items"], "cached": True})

    fallback_items = [
        {"title": "Credential phishing campaigns target shared inbox users", "summary": "Attackers are using urgency language and spoofed support domains to harvest credentials.", "severity": "high", "source": "CyberGuard Local Feed", "published_at": "2026-05-20T08:00:00Z", "url": ""},
        {"title": "Macro-lure attachments resurface in invoice themes", "summary": "Unexpected attachments disguised as invoices are prompting macro enablement.", "severity": "medium", "source": "CyberGuard Local Feed", "published_at": "2026-05-19T14:30:00Z", "url": ""},
        {"title": "MFA fatigue prompts observed in helpdesk impersonation", "summary": "Users receive repeated authentication prompts followed by fake support calls.", "severity": "medium", "source": "CyberGuard Local Feed", "published_at": "2026-05-18T10:15:00Z", "url": ""},
        {"title": "Lookalike domains mimic enterprise SSO portals", "summary": "Homograph and typo domains are redirecting users to cloned sign-in pages.", "severity": "high", "source": "CyberGuard Local Feed", "published_at": "2026-05-17T16:45:00Z", "url": ""},
    ]

    feed_enabled = os.getenv("THREAT_FEED_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}
    feed_url = os.getenv("THREAT_FEED_URL", "").strip()
    feed_key = os.getenv("THREAT_FEED_API_KEY", "").strip()
    if not feed_enabled or not feed_url:
        _THREAT_CACHE["items"] = fallback_items
        _THREAT_CACHE["ts"] = now
        return JSONResponse({"ok": True, "source": "fallback", "items": fallback_items, "cached": False})

    headers = {}
    if feed_key:
        headers["Authorization"] = f"Bearer {feed_key}"

    try:
        resp = requests.get(feed_url, headers=headers, timeout=3)
        resp.raise_for_status()
        raw = resp.json()
        candidates = raw.get("items", raw if isinstance(raw, list) else [])
        # NVD API shape: {"vulnerabilities":[{"cve": {...}}]}
        if not candidates and isinstance(raw, dict) and isinstance(raw.get("vulnerabilities"), list):
            candidates = raw.get("vulnerabilities", [])
        normalized = []
        for item in candidates[:12]:
            if not isinstance(item, dict):
                continue
            # NVD item normalization
            if "cve" in item and isinstance(item.get("cve"), dict):
                cve = item["cve"]
                cve_id = str(cve.get("id") or "Unknown CVE")
                descriptions = cve.get("descriptions", [])
                summary = ""
                if isinstance(descriptions, list):
                    en_desc = next((d for d in descriptions if isinstance(d, dict) and d.get("lang") == "en"), None)
                    any_desc = descriptions[0] if descriptions and isinstance(descriptions[0], dict) else None
                    summary = str((en_desc or any_desc or {}).get("value") or "")

                severity = "medium"
                metrics = cve.get("metrics", {})
                if isinstance(metrics, dict):
                    v31 = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30")
                    v2 = metrics.get("cvssMetricV2")
                    metric_item = None
                    if isinstance(v31, list) and v31:
                        metric_item = v31[0]
                    elif isinstance(v2, list) and v2:
                        metric_item = v2[0]
                    if isinstance(metric_item, dict):
                        base_sev = str(metric_item.get("baseSeverity") or "").lower()
                        if base_sev in {"critical", "high", "medium", "low"}:
                            severity = base_sev
                        else:
                            score = None
                            cvss_data = metric_item.get("cvssData")
                            if isinstance(cvss_data, dict):
                                score = cvss_data.get("baseScore")
                            if isinstance(score, (int, float)):
                                if score >= 9.0:
                                    severity = "critical"
                                elif score >= 7.0:
                                    severity = "high"
                                elif score >= 4.0:
                                    severity = "medium"
                                else:
                                    severity = "low"

                refs = cve.get("references", [])
                first_url = ""
                if isinstance(refs, list):
                    first_ref = next((r for r in refs if isinstance(r, dict) and r.get("url")), None)
                    if first_ref:
                        first_url = str(first_ref.get("url"))

                normalized.append({
                    "title": cve_id,
                    "summary": summary,
                    "severity": severity,
                    "source": "NVD",
                    "published_at": str(cve.get("published") or ""),
                    "url": first_url,
                })
                continue

            normalized.append({
                "title": str(item.get("title") or item.get("name") or "Untitled threat item"),
                "summary": str(item.get("summary") or item.get("description") or ""),
                "severity": str(item.get("severity") or "medium").lower(),
                "source": str(item.get("source") or "External Threat Feed"),
                "published_at": str(item.get("published_at") or item.get("published") or ""),
                "url": str(item.get("url") or ""),
            })
        if not normalized:
            normalized = fallback_items
        _THREAT_CACHE["items"] = normalized
        _THREAT_CACHE["ts"] = now
        return JSONResponse({"ok": True, "source": "remote", "items": normalized, "cached": False})
    except Exception as e:
        _THREAT_CACHE["items"] = fallback_items
        _THREAT_CACHE["ts"] = now
        return JSONResponse({"ok": False, "source": "fallback", "items": fallback_items, "error": str(e), "cached": False})


# ---------------------------------------------------------------------------
# /api/chat — Full chat page
# ---------------------------------------------------------------------------

@app.post("/api/chat")
async def chat(req: ChatRequest, request: Request):
    aria = ARIAEngine(history=req.history)
    result = aria.ask(req.message, session_context=request.session, image=req.image)
    return JSONResponse(result)

@app.post("/api/chat-summary")
async def chat_summary(req: ChatSummaryRequest, request: Request):
    aria = ARIAEngine(history=req.history)
    summary = aria.summarize_discussion(session_context=request.session)
    return JSONResponse({"summary": summary})


# ---------------------------------------------------------------------------
# /api/breach-email — Seeded email breach lookup
# ---------------------------------------------------------------------------

BREACH_SEED = {
    "test@example.com": [
        {"service": "LinkedIn", "year": 2021, "data_types": ["Email", "Password (hashed)", "Username"], "severity": "HIGH", "records": 700000000},
        {"service": "Adobe", "year": 2013, "data_types": ["Email", "Password (encrypted)", "Username", "Credit card hint"], "severity": "MEDIUM", "records": 153000000},
        {"service": "Canva", "year": 2019, "data_types": ["Email", "Name", "Username", "Password (hashed)"], "severity": "MEDIUM", "records": 137272116},
    ],
    "demo@gmail.com": [
        {"service": "Dropbox", "year": 2012, "data_types": ["Email", "Password (hashed)"], "severity": "HIGH", "records": 68648009},
        {"service": "Wattpad", "year": 2020, "data_types": ["Email", "Username", "Password", "IP Address", "Date of birth"], "severity": "HIGH", "records": 270000000},
    ]
}

class BreachEmailRequest(BaseModel):
    email: str = ""

@app.post("/api/breach-email")
async def breach_email(req: BreachEmailRequest):
    email = req.email.strip().lower()
    breaches = BREACH_SEED.get(email, [])

    if not breaches:
        aria = ARIAEngine()
        aria_result = aria.ask(
            f"The email {email} was not found in any known breach databases. "
            f"Tell the user in 2 sentences that no breaches were found, and give one proactive tip."
        )
        return JSONResponse({"email": email, "breached": False, "breaches": [], "aria_explanation": aria_result["reply"]})

    aria = ARIAEngine()
    breach_summary = "; ".join(f"{b['service']} ({b['year']}, {', '.join(b['data_types'])})" for b in breaches)
    aria_result = aria.ask(
        f"Breach lookup for email {email} found {len(breaches)} breach(es): {breach_summary}. "
        f"Generate a prioritised action plan ordered by urgency — most recent credential breaches first. "
        f"Be specific about which service to address first and why."
    )

    return JSONResponse({
        "email": email,
        "breached": True,
        "breach_count": len(breaches),
        "breaches": sorted(breaches, key=lambda x: x["year"], reverse=True),
        "aria_explanation": aria_result["reply"],
    })


# ---------------------------------------------------------------------------
# /api/send-email — Transactional Email Sender (Mailjet / SMTP)
# ---------------------------------------------------------------------------

def _send_email_background(req: EmailRequest, generated_date: str):
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port_str = os.getenv("SMTP_PORT", "587")
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    smtp_from = os.getenv("SMTP_FROM")

    log_message(f"Starting background email dispatch for report type '{req.report_type}' to '{req.recipient_email}'")
    log_message(f"SMTP Configuration: HOST={smtp_host}, PORT={smtp_port_str}, USER={smtp_user}, FROM={smtp_from}")

    if not all([smtp_host, smtp_user, smtp_password, smtp_from]):
        log_message("Email not sent: Missing SMTP configuration in .env")
        return

    try:
        smtp_port = int(smtp_port_str)
    except ValueError as ve:
        log_message(f"Email not sent: Invalid SMTP_PORT '{smtp_port_str}': {ve}")
        return

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"CyberGuard {req.report_type} Analysis Report"
        msg["From"] = f"CyberGuard <{smtp_from}>"
        msg["To"] = req.recipient_email

        # Prepare dynamic variables
        risk_level = req.metrics.get("risk_level", "Unknown")
        confidence_score = req.metrics.get("confidence_score", 0)
        rules_fired = len(req.fired_rules)
        
        # Build rules HTML
        rules_html = ""
        for rule in req.fired_rules:
            rules_html += f"""
            <div style="background:#071a12; border:1px solid rgba(29,158,117,0.15); border-radius:10px; padding:16px; margin-bottom:8px;">
                <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
                <tr>
                    <td valign="middle">
                    <span style="background:#1D9E75; color:#060d0a; font-size:10px; font-weight:700; padding:3px 8px; border-radius:4px; font-family:monospace; letter-spacing:0.5px;">{rule.get('id', 'RULE')}</span>
                    &nbsp;
                    <span style="font-size:13px; font-weight:600; color:#e6f1ed;">{rule.get('name', 'Rule fired')}</span>
                    </td>
                    <td align="right" valign="middle" style="white-space:nowrap;">
                    <span style="font-size:12px; font-weight:700; color:#EF9F27; font-family:monospace;">+{rule.get('certainty_factor', 0)} CF</span>
                    </td>
                </tr>
                </table>
                <div style="font-size:12px; color:#597368; margin-top:8px; line-height:1.6;">{rule.get('description', '')}</div>
            </div>
            """

        if not req.fired_rules:
            rules_html = '<div style="font-size:12px; color:#597368;">No specific rules fired for this analysis.</div>'

        # Build indicators HTML
        indicators_html = ""
        if req.indicators:
            indicators_html += '<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%"><tr>'
            for key, val in req.indicators.items():
                name = str(key).replace('_', ' ').upper()
                if val:
                    indicators_html += f'<td style="padding:3px 6px 3px 0;"><span style="background:rgba(226,75,74,0.1); border:1px solid rgba(226,75,74,0.2); color:#fca5a5; font-size:11px; font-weight:600; padding:4px 10px; border-radius:5px; display:inline-block;">✕ {name}</span></td>'
                else:
                    indicators_html += f'<td style="padding:3px 6px 3px 0;"><span style="background:rgba(29,158,117,0.1); border:1px solid rgba(29,158,117,0.2); color:#6ee7b7; font-size:11px; font-weight:600; padding:4px 10px; border-radius:5px; display:inline-block;">✓ {name}</span></td>'
            indicators_html += '</tr></table>'

        # Build final HTML
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>CyberGuard Security Report</title>
</head>
<body style="margin:0; padding:0; background-color:#060d0a; font-family: Arial, Helvetica, sans-serif; -webkit-text-size-adjust:100%; -ms-text-size-adjust:100%;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#060d0a; min-height:100vh;">
    <tr>
      <td align="center" valign="top" style="padding: 40px 16px;">
        <table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="max-width:600px; width:100%; background-color:#0d1f1a; border:1px solid rgba(29,158,117,0.25); border-radius:16px; overflow:hidden; box-shadow: 0 20px 60px rgba(0,0,0,0.7);">
          <tr>
            <td style="background: linear-gradient(135deg, #0a2419 0%, #0d2e22 50%, #071a12 100%); padding: 36px 40px 28px 40px; border-bottom: 1px solid rgba(29,158,117,0.2);">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td valign="middle">
                    <table role="presentation" cellpadding="0" cellspacing="0" border="0">
                      <tr>
                        <td valign="middle" style="padding-right: 14px;">
                          <div style="width:46px; height:46px; background-color:#0d2e22; border:1.5px solid #1D9E75; border-radius:10px; display:inline-block; text-align:center; line-height:46px;">
                            <img src="https://img.icons8.com/ios/50/1D9E75/shield.png" width="24" height="24" alt="Shield" style="vertical-align:middle; margin-top:11px;" />
                          </div>
                        </td>
                        <td valign="middle">
                          <div style="font-size:22px; font-weight:800; color:#e6f1ed; letter-spacing:0.5px; line-height:1.1;">CyberGuard</div>
                          <div style="font-size:10px; color:#1D9E75; text-transform:uppercase; letter-spacing:1.5px; margin-top:3px;">Rule-Based Expert System</div>
                        </td>
                      </tr>
                    </table>
                  </td>
                  <td align="right" valign="middle">
                    <div style="background: rgba(29,158,117,0.12); border:1px solid rgba(29,158,117,0.3); border-radius:20px; padding:6px 14px; display:inline-block;">
                      <span style="font-size:11px; font-weight:700; color:#1D9E75; text-transform:uppercase; letter-spacing:1px;">Security Report</span>
                    </div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="background: rgba(29,158,117,0.06); padding: 20px 40px; border-bottom: 1px solid rgba(29,158,117,0.1);">
              <div style="font-size:18px; font-weight:700; color:#e6f1ed; margin-bottom:4px;">
                {req.report_type} Analysis
              </div>
              <div style="font-size:12px; color:#94aba1;">
                Generated on <span style="color:#1D9E75; font-weight:600;">{generated_date}</span>
                &nbsp;·&nbsp; Shared via CyberGuard Expert System
              </div>
            </td>
          </tr>
          <tr>
            <td style="padding: 32px 40px;">
              <p style="font-size:14px; color:#94aba1; margin:0 0 28px 0; line-height:1.7;">
                A CyberGuard security assessment has been shared with you. Below is the full expert system analysis.
              </p>
              <div style="margin-bottom:28px;">
                <div style="font-size:10px; font-weight:700; text-transform:uppercase; letter-spacing:1.5px; color:#597368; margin-bottom:12px;">Assessment Metrics</div>
                <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
                  <tr>
                    <td width="32%" style="padding-right:8px; vertical-align:top;">
                      <div style="background:#071a12; border:1px solid rgba(29,158,117,0.15); border-radius:10px; padding:16px;">
                        <div style="font-size:10px; color:#597368; text-transform:uppercase; letter-spacing:1px; margin-bottom:8px;">Verdict</div>
                        <div style="font-size:18px; font-weight:800; color:#e6f1ed;">{risk_level}</div>
                      </div>
                    </td>
                    <td width="32%" style="padding-right:8px; vertical-align:top;">
                      <div style="background:#071a12; border:1px solid rgba(29,158,117,0.15); border-radius:10px; padding:16px;">
                        <div style="font-size:10px; color:#597368; text-transform:uppercase; letter-spacing:1px; margin-bottom:8px;">Score</div>
                        <div style="font-size:18px; font-weight:800; color:#e6f1ed;">{confidence_score}</div>
                        <div style="background:#0d2e22; border-radius:3px; height:4px; margin-top:8px; overflow:hidden;">
                           <div style="background:#1D9E75; height:4px; width:{min(100, max(0, float(confidence_score) if isinstance(confidence_score, (int, float)) else 50))}%; border-radius:3px;"></div>
                        </div>
                      </div>
                    </td>
                    <td width="36%" style="vertical-align:top;">
                      <div style="background:#071a12; border:1px solid rgba(29,158,117,0.15); border-radius:10px; padding:16px;">
                        <div style="font-size:10px; color:#597368; text-transform:uppercase; letter-spacing:1px; margin-bottom:8px;">Details</div>
                        <div style="font-size:18px; font-weight:800; color:#e6f1ed;">{rules_fired} <span style="font-size:12px; color:#597368; font-weight:400;">items flagged</span></div>
                      </div>
                    </td>
                  </tr>
                </table>
              </div>
              <div style="margin-bottom:28px;">
                <div style="font-size:10px; font-weight:700; text-transform:uppercase; letter-spacing:1.5px; color:#597368; margin-bottom:12px;">Trace Details</div>
                {rules_html}
              </div>
              <div style="margin-bottom:28px; background: rgba(29,158,117,0.05); border:1px solid rgba(29,158,117,0.2); border-left: 4px solid #1D9E75; border-radius:4px 10px 10px 4px; padding:20px 24px;">
                <div style="font-size:10px; font-weight:700; text-transform:uppercase; letter-spacing:1.5px; color:#1D9E75; margin-bottom:12px;">
                  &#9656; ARIA Expert Security Evaluation
                </div>
                <p style="font-size:14px; color:#94aba1; margin:0; line-height:1.8;">
                  {req.aria_explanation or "No additional expert evaluation provided."}
                </p>
              </div>
              <div style="margin-bottom:32px;">
                <div style="font-size:10px; font-weight:700; text-transform:uppercase; letter-spacing:1.5px; color:#597368; margin-bottom:12px;">Inspected Indicators</div>
                {indicators_html}
              </div>
              <div style="background:#071a12; border-radius:8px; padding:14px 18px; border:1px solid rgba(29,158,117,0.1);">
                <p style="margin:0; font-size:12px; color:#597368; line-height:1.7;">
                  This report was automatically generated by the <strong style="color:#94aba1;">CyberGuard Expert System</strong>.
                </p>
              </div>
            </td>
          </tr>
          <tr>
            <td style="background:#071a12; padding:24px 40px; border-top:1px solid rgba(29,158,117,0.15);">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td valign="middle">
                    <div style="font-size:13px; font-weight:700; color:#1D9E75;">CyberGuard</div>
                    <div style="font-size:11px; color:#597368; margin-top:2px;">Rule-Based Expert Security System</div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""

        part = MIMEText(html_content, "html")
        msg.attach(part)

        log_message(f"Connecting to SMTP server at {smtp_host}:{smtp_port}...")
        server = smtplib.SMTP(smtp_host, smtp_port, timeout=15)
        log_message("Sending EHLO...")
        server.ehlo()
        log_message("Starting TLS secure channel...")
        server.starttls()
        log_message("Sending EHLO post-TLS...")
        server.ehlo()
        log_message(f"Logging in as user {smtp_user}...")
        server.login(smtp_user, smtp_password)
        log_message("Sending email message...")
        server.send_message(msg)
        log_message("Closing connection...")
        server.quit()
        log_message(f"Successfully sent report email to {req.recipient_email}")
    except Exception as e:
        log_message(f"Failed to send email to {req.recipient_email}: {e}")

@app.post("/api/send-email")
async def send_email(req: EmailRequest, background_tasks: BackgroundTasks):
    smtp_from = os.getenv("SMTP_FROM")
    if not smtp_from:
        log_message("API Send Email Request rejected: SMTP_FROM missing in environment variables.")
        return JSONResponse({"ok": False, "error": "Email is not configured (SMTP_FROM missing)"}, status_code=500)
    
    generated_date = datetime.now().strftime("%B %d, %Y at %I:%M %p")
    background_tasks.add_task(_send_email_background, req, generated_date)
    return JSONResponse({"ok": True, "message": "Email sending initiated in the background"})


# ---------------------------------------------------------------------------
# Legacy assess endpoint
# ---------------------------------------------------------------------------

@app.post("/api/assess")
async def assess(req: PhishingRequest, request: Request):
    return await run_phishing(req, request)


if __name__ == "__main__":
    uvicorn.run("index:app", host="0.0.0.0", port=8000, reload=True)
