# CyberGuard

CyberGuard is a hybrid cybersecurity expert system for phishing risk assessment, password auditing, breach lookups, and ARIA-assisted remediation guidance. It combines deterministic expert rules with an AI advisory layer so users can inspect why a risk verdict was produced and what to do next.

## Features

- Rule-based phishing assessment with fired-rule traceability and certainty scoring.
- ARIA security assistant for contextual explanations, follow-up questions, and remediation plans.
- Password strength, entropy, and breach exposure analysis.
- Email breach lookup workflow with prioritized action guidance.
- Shareable security reports with PDF, HTML, and email delivery options.
- Multi-platform distribution: **Android Mobile (APK)**, **Windows Desktop (.exe)**, and **Web Platform**.
- Desktop build support through PyInstaller and pywebview.

## Tech Stack

- Python, FastAPI, Uvicorn
- HTML, CSS, vanilla JavaScript
- PyInstaller for Windows executable builds
- Google Gemini API for ARIA responses
- Have I Been Pwned API support for breach checks
- SMTP/Mailjet-compatible report sharing

## Getting Started

1. Create and activate a virtual environment.

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

2. Install dependencies.

   ```powershell
   python -m pip install -r requirements.txt
   ```

3. Copy `.env.example` to `.env` and fill in the values you need.

   ```powershell
   Copy-Item .env.example .env
   ```

4. Start the app.

   ```powershell
   python run_cyberguard.py
   ```

## Environment Variables

| Variable | Purpose |
| --- | --- |
| `GEMINI_API_KEY` | Enables ARIA AI responses. |
| `HIBP_API_KEY` | Optional Have I Been Pwned API key. |
| `SMTP_HOST` | SMTP server for report emails. |
| `SMTP_PORT` | SMTP port, usually `587`. |
| `SMTP_USER` | SMTP username or Mailjet API key. |
| `SMTP_PASSWORD` | SMTP password or Mailjet secret key. |
| `SMTP_FROM` | Verified sender address for report emails. |

## Build

Build the Windows desktop executable with:

```powershell
.\build_exe.ps1
```

The script installs build dependencies, runs PyInstaller, and writes the executable to `dist\CyberGuard.exe`. Python 3.11 or 3.12 is recommended for the desktop build.

## Project Structure

```text
api/                  FastAPI routes and expert-system logic
templates/            Main application template
public/static/        CSS and browser assets
assets/               App icons and packaged assets
run_cyberguard.py     Desktop/web launcher
build_exe.ps1         Windows executable build script
```

## Notes

- Keep `.env` local. It is ignored by git and should not be committed.
- Build outputs in `build/` and `dist/` are ignored by git.
- ARIA can run in fallback mode when the AI provider is unavailable, but full AI responses require `GEMINI_API_KEY`.
