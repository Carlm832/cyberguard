# CyberGuard — Cybersecurity Expert System & ARIA AI

<div align="center">

![CyberGuard Shield](https://img.icons8.com/ios-filled/100/1D9E75/shield.png)

### *Defend Your Digital Frontier with Explainable Rule Inference & Conversational AI Advisory*

[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12-blue?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Web%20(Desktop%20%26%20Mobile)-1D9E75)](https://carlm832.github.io/cyberguard/)
[![AI Advisory](https://img.shields.io/badge/AI%20Advisory-Gemini%202.5%20Flash%20%2B%20Llama%203.3-8A2BE2)](https://ai.google.dev/)
[![Privacy](https://img.shields.io/badge/Privacy-Zero%20Telemetry%20%7C%20k--Anonymity-success)](#privacy--security-guarantees)
[![License](https://img.shields.io/badge/License-MIT-gray.svg)](LICENSE)

[**🌐 Live Cloud Web Demo**](https://carlm832.github.io/cyberguard/) &nbsp;•&nbsp;
[**📥 Download Windows Client (.exe)**](https://github.com/Carlm832/cyberguard/releases/latest) &nbsp;•&nbsp;
[**📖 Architecture**](#-system-architecture) &nbsp;•&nbsp;
[**⚙️ Rules (R01–R10)**](#-deterministic-rule-base-r01r10) &nbsp;•&nbsp;
[**🚀 Quickstart**](#-installation--quickstart)

</div>

---

## 🛡️ Overview

**CyberGuard** is a hybrid cybersecurity expert system designed to identify digital threats, audit password resilience, detect compromised credentials, and deliver explainable remediation guidance. 

Unlike opaque black-box AI chatbots that risk hallucinations or traditional antivirus tools that offer generic alerts, CyberGuard bridges the gap by coupling **forward-chaining deterministic inference** (mathematical Certainty Factors) with an **ARIA AI Security Advisory Layer** (Google Gemini & Meta Llama 3.3).

Every risk assessment generates an exact, traceable audit chain displaying triggered Rule IDs, calculated Certainty Factors (CF), risk scores, and executive-ready exportable reports.

```
┌───────────────────────────┐     ┌───────────────────────────┐     ┌───────────────────────────┐
│   1. Signal Extraction    │ ──> │ 2. Deterministic Engine   │ ──> │   3. ARIA AI Advisory     │
│  - Obfuscated URLs        │     │  - Forward Chaining (R01) │     │  - Multimodal Vision      │
│  - Spoofed Domains        │     │  - Certainty Factors (CF) │     │  - Plain-Language Action  │
│  - Credential Traps       │     │  - Fuzzy Posture Scoring  │     │  - Executive Reports      │
└───────────────────────────┘     └───────────────────────────┘     └───────────────────────────┘
```

---

## ✨ Key Features & Capabilities

### 🔍 1. Deterministic Phishing Detector
* **Forward-Chaining Heuristics**: Evaluates email headers, sender authenticity, deceptive hyperlinks, urgent language, and unexpected attachments against rules **R01–R10**.
* **Certainty Factor (CF) Scoring**: Aggregates statistical weights and compound rules into an explainable composite threat rating:
  * **LOW RISK** (`< 0.40 CF`)
  * **MEDIUM RISK** (`0.40 – 0.69 CF`)
  * **HIGH THREAT** (`≥ 0.70 CF`)
* **Traceable Audit Log**: Displays explicit Rule IDs and rationale for every flagged indicator.

### 🔐 2. Password Thermodynamic Entropy & k-Anonymity Audit
* **Client-Side Thermodynamic Entropy**: Calculates exact entropy bits, keyspace complexity, character pool diversity, and estimated crack time against high-performance cracking rigs ($10^{10}$ hashes/sec).
* **Pattern & Dictionary Defense**: Real-time detection of common dictionary terms, spatial keyboard sequences (`qwerty`, `123456`), and repetitive structures.
* **k-Anonymity Breach Verification**: Queries the Have I Been Pwned database using SHA-1 hash prefixes (first 5 characters). Your full password never leaves local memory.

### 🤖 3. ARIA Multimodal Security Companion
* **AI Remediation Guidance**: Powered by Gemini 2.5 Flash, ARIA translates technical indicators into prioritized, non-technical action items.
* **Multimodal Screenshot Ingestion**: Drop suspicious email screenshots, phishing banners, or error dialogs directly into the chat for automated visual threat extraction.
* **Offline Fallback Engine**: If cloud AI APIs are unavailable or offline, ARIA automatically falls back to an internal deterministic advisory engine.

### 📡 4. NVD Real-Time Threat Intelligence
* **Live CVE Aggregator**: Ingests high-impact vulnerabilities directly from the National Vulnerability Database.
* **Plain-Language Synthesis**: Enriched via Meta Llama 3.3 to convert dense CVE descriptions into actionable defensive steps and patching priorities.

### 📄 5. Executive PDF & Verified SMTP Email Reporting
* **High-Resolution PDF Generation**: Client-side vector rendering via `html2pdf.js` with off-screen DOM canvas isolation and native print preview fallbacks.
* **Synchronous SMTP Dispatch**: Integrates with Mailjet/SMTP relays with real-time delivery validation and failure alerts.

---

## 🏛️ Deterministic Rule Base (R01–R10)

| Rule ID | Rule Classification | CF Weight | Trigger Condition |
| :--- | :--- | :---: | :--- |
| **R01** | Credential Harvesting | `+0.25` | Explicit prompts to submit credentials, passwords, or PINs. |
| **R02** | Deceptive Hyperlink | `+0.20` | Embedded link target hostname differs from anchor text. |
| **R03** | Coercive Urgency | `+0.15` | Threatens immediate account lockout or punitive action. |
| **R04** | Domain Impersonation | `+0.15` | Lookalike characters or mismatched domain suffixes. |
| **R05** | Unverified External Sender | `+0.10` | First-time interaction from an unverified external address. |
| **R06** | Suspicious Attachment | `+0.08` | Dangerous extensions (`.exe`, `.scr`, `.vbs`, `.iso`, `.zip`). |
| **R07** | Impersonal Salutation | `+0.05` | Generic greeting ("Dear Customer", "Dear User") on account alerts. |
| **R08** | Financial Coercion | `+0.18` | Unscheduled wire transfers or banking routing modifications. |
| **R09** | Compound: Urgent Unknown | `+0.10` | Simultaneous trigger of **R03** (Urgency) and **R05** (Unknown Sender). |
| **R10** | Compound: Targeted Harvesting | `+0.15` | Simultaneous trigger of **R01** (Credentials) and **R04** (Spoofed Domain). |

---

## 📦 Deployment Formats

CyberGuard supports two primary deployment form factors:

```
├── 🖥️ Windows Desktop Application (.exe)
│   ├── Native PyWebView standalone GUI (Windows 10/11)
│   ├── Encrypted local session & audit logging
│   └── 100% offline-capable
│
└── 🌐 Responsive Cloud Web Platform (/app)
    ├── Zero-install instant browser deployment
    ├── Responsive across Desktop, Tablet, and Mobile devices
    └── Static GitHub Pages compatibility (docs/app.html)
```

---

## 🚀 Installation & Quickstart

### Prerequisites
* **Python 3.11** or **3.12**
* **Git**
* Modern Web Browser (Chrome, Edge, Firefox, Safari)

### 1. Clone the Repository
```powershell
git clone https://github.com/Carlm832/cyberguard.git
cd cyberguard
```

### 2. Configure Virtual Environment
```powershell
# Create virtual environment
python -m venv .venv

# Activate on Windows (PowerShell)
.\.venv\Scripts\Activate.ps1

# Activate on Linux / macOS
source .venv/bin/activate
```

### 3. Install Dependencies
```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configure Environment Variables
Copy the example environment file and configure your API keys:
```powershell
Copy-Item .env.example .env
```

Edit `.env` with your settings:
```ini
# Gemini API Key (ARIA AI Advisor & Image Analysis)
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-2.5-flash

# OpenRouter (Live Threat Feed Enrichment via Llama 3.3)
OPEN_ROUTER_API_KEY=your_openrouter_api_key_here
OPEN_ROUTER_THREAT_MODEL=meta-llama/llama-3.3-8b-instruct:free

# Have I Been Pwned (Optional - for advanced breach lookups)
HIBP_API_KEY=your_hibp_key_here

# Mailjet / SMTP Server Settings (Report Email Dispatch)
SMTP_HOST=in-v3.mailjet.com
SMTP_PORT=587
SMTP_USER=your_mailjet_api_key
SMTP_PASSWORD=your_mailjet_secret_key
SMTP_FROM=your_verified_sender@example.com
```

### 5. Run the Application

#### Option A: Run Local Server (Web Browser)
```powershell
python -m uvicorn api.index:app --host 127.0.0.1 --port 8000 --reload
```
* **Landing Page**: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
* **Security Dashboard**: [http://127.0.0.1:8000/app](http://127.0.0.1:8000/app)

#### Option B: Run Standalone Desktop Launcher
```powershell
python run_cyberguard.py
```

---

## 🔨 Building the Windows Desktop Executable (`.exe`)

To compile a standalone, zero-dependency Windows desktop binary:

```powershell
# Run the automated build script
.\build_exe.ps1
```

The compiled binary will be generated at:
```
dist\CyberGuard.exe
```

---

## 🔒 Privacy & Security Guarantees

* **Zero Telemetry**: CyberGuard never transmits unhashed passwords, user scan inputs, or file metadata to third-party telemetry aggregators.
* **k-Anonymity Protocol**: For data breach checks, passwords are SHA-1 hashed locally. Only the first 5 hexadecimal characters are sent to verify breach counts against hundreds of returned candidates.
* **Memory Ephemerality**: User input variables are held strictly in temporary session memory and wiped on window disposal or session restart.

---

## 📁 Repository Structure

```text
cyberguard/
├── api/
│   ├── index.py              # FastAPI server, endpoints, expert logic, & email relay
│   └── expert_rules.py       # Knowledge base, forward-chaining rules, & fuzzy posture
├── public/
│   └── static/
│       ├── style.css         # Responsive Dark/Light security UI stylesheet
│       ├── html2pdf.bundle...# Bundled offline vector PDF generation engine
│       └── cyberguard_mock...# UI mockup asset
├── templates/
│   ├── index.html            # Main web application dashboard & ARIA chat UI
│   └── promo.html            # Promotional website landing page
├── docs/                     # GitHub Pages static site distribution
│   ├── index.html            # Public static landing page
│   ├── app.html              # Standalone static web application
│   └── static/               # Static CSS and JS assets for GitHub Pages
├── run_cyberguard.py         # Native PyWebView / browser launcher
├── build_exe.ps1             # PyInstaller Windows build script
├── requirements.txt          # Production dependencies
└── README.md                 # Project documentation
```

---

## 🤝 Contributing

Contributions, vulnerability rule suggestions, and pull requests are welcome!

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/NewInferenceRule`)
3. Commit your changes (`git commit -m 'feat: add DNS anomaly rule R11'`)
4. Push to the branch (`git push origin feature/NewInferenceRule`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

<div align="center">
  <sub>Built for security researchers, privacy advocates, and modern enterprises.</sub>
</div>
