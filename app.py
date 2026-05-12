"""
CyberGuard — FastAPI Application Entry Point
Updated to use Gemini and FastAPI with the new Hybrid Expert System logic.
"""

import os
from pathlib import Path
from typing import Any, List, Dict

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from logic import (
    ARIAEngine,
    FuzzyRiskEngine,
    HIBPExpert,
    PasswordExpert,
    PhishingExpert,
)

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

# ---------------------------------------------------------------------------
# App Initialization
# ---------------------------------------------------------------------------

app = FastAPI(title="CyberGuard", version="2.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8000", "http://127.0.0.1:8000", "*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
static_path = BASE_DIR / "static"
if not static_path.exists():
    static_path.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=static_path), name="static")

@app.get("/", response_class=FileResponse)
async def serve_index():
    return FileResponse(BASE_DIR / "templates" / "index.html")

# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class AssessRequest(BaseModel):
    indicators: Dict[str, bool] = {}
    password: str = ""

class ChatRequest(BaseModel):
    message: str
    history: List[Dict[str, str]] = []

class BreachRequest(BaseModel):
    password: str

# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------

@app.post("/api/assess")
async def assess(req: AssessRequest):
    phishing_expert = PhishingExpert(req.indicators)
    phishing_result = phishing_expert.evaluate()
    
    password_expert = PasswordExpert(req.password)
    password_result = password_expert.evaluate()
    
    hibp_expert = HIBPExpert(req.password)
    hibp_result = hibp_expert.check()
    
    fuzzy_engine = FuzzyRiskEngine(
        phishing_score=phishing_result["risk_score"],
        password_score=password_result["score"]
    )
    overall_result = fuzzy_engine.evaluate()
    
    return {
        "phishing": phishing_result,
        "password": password_result,
        "hibp": hibp_result,
        "overall": overall_result,
    }

@app.post("/api/chat")
async def chat(req: ChatRequest):
    # History comes in as [{"role": "user", "content": "..."}, {"role": "assistant", "content": "..."}]
    aria = ARIAEngine(history=req.history)
    result = aria.ask(req.message)
    return result



@app.post("/api/breach")
async def breach_check(req: BreachRequest):
    expert = HIBPExpert(req.password)
    result = expert.check()
    return result

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
