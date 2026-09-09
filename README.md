# 🛡️ DeceptiScan & LLM Shield (HoneyPrompt)
### Unified Network Deception Identification & AI Prompt Vulnerability Platform
**Cybersecurity + AI Security (AI Red-Teaming) • B.Tech Final Year Capstone Project**

---

## 📌 1. Project Overview

**DeceptiScan & LLM Shield** is a cybersecurity and AI safety platform that unifies **Network Deception / Honeypot Identification** with **LLM Prompt Injection & Red-Teaming Auditing** under an interactive modern dashboard.

### Core Problems Solved:
1. **Infrastructure Deception**: Offensive and defensive security analysts need automated ways to detect whether a target server is an authentic production host or an instrumented **honeypot trap** (e.g. Cowrie, Dionaea, Conpot).
2. **AI Application Vulnerability**: LLMs integrated into business applications are vulnerable to **Prompt Injections (OWASP LLM01)**, **System Prompt Leakage (OWASP LLM07)**, and **Jailbreaks / Persona Hijacking**. This platform evaluates these vulnerabilities and generates automated defense hardening templates.

---

## 🏛️ 2. System Architecture

```text
                                [ User / Auditor ]
                                        │
                         [ Streamlit Cyber Dashboard ]
                                        │
           ┌────────────────────────────┴────────────────────────────┐
           ▼                                                         ▼
[ Module 1: Honeypot Scanner ]                           [ Module 2: LLM Prompt Shield ]
 ├── Port & Banner Extractor                              ├── OWASP Attack Payload DB
 ├── Signature Matcher (Cowrie, Dionaea)                  ├── Multi-Model Adapters (Gemini, GPT, Mock)
 ├── Random Forest Deception Classifier                   ├── Safety Refusal & Leakage Evaluator
 └── Latency & Anomaly Heuristics                         └── Prompt Hardening Engine (XML / Sandwich)
           │                                                         │
           └────────────────────────────┬────────────────────────────┘
                                        ▼
                       [ Unified Security Audit Report ]
                            ├── PDF Audit Exporter
                            └── JSON Telemetry Stream
```

---

## 🚀 3. Features Breakdown

### 🔍 Module 1: Honeypot Identification Engine
- **Multi-Port Banner Grabbing**: Non-blocking socket probing across common and deception ports (21, 22, 23, 80, 443, 502, 1433, 2222, 3306, etc.).
- **Signature Database**: Detects known honeypot frameworks (Cowrie SSH, Kippo, Dionaea Malware Sandbox, Conpot ICS/SCADA, Glastopf Web Trap).
- **Machine Learning Deception Classifier**: 20-feature `RandomForestClassifier` evaluating banner entropy, port combinations, and latency distributions.
- **Explainability Engine**: Lists exact reasons why a host is classified as a honeypot or production server.
- **Preset Simulations**: Includes 5 built-in target profiles for instant offline demonstration.

### 🤖 Module 2: LLM Prompt Vulnerability & Red-Teamer
- **OWASP-Aligned Attack Suites**:
  - *Direct Prompt Injections* (LLM01:2025): Delimiter escape, priority inversion, translation bypasses.
  - *System Prompt Leakage* (LLM07:2025): Verbatim extraction, Base64 exfiltration, canary token probing.
  - *Jailbreaks*: DAN (Do-Anything-Now) persona hijacking, hypothetical academic research bypasses.
- **Multi-Model Support**: Google Gemini API, OpenAI GPT-4o-mini, Custom HTTP Webhooks / Local Ollama, and an Offline High-Fidelity Mock Simulator.
- **Refusal & Leakage Judge**: Automated detection of model refusals, secret leakage, and compliance scores.

### ⚔️ Module 3: Side-by-Side Prompt Defense Studio
- Test custom attack payloads against **Unhardened Baseline System Prompt** vs. **Hardened System Prompt** side-by-side.
- Demonstrates live how attacks succeed on baseline prompts but get blocked by defense hardening.
- Generates production-ready copyable defense code:
  - **XML Delimiter Isolation** (`<user_input>`)
  - **Sandwich Defense** (Pre- and Post-anchoring)
  - **Strict Instruction Hierarchy**
  - **Canary Token Tripwires**

### 📊 Module 4: Unified PDF Security Report
- One-click compilation of an executive **Security Audit PDF Report** with scorecards, threat indices, and actionable remediation roadmaps.

---

## 💻 4. Installation & Quickstart

### 1. Prerequisites
- Python 3.10+ installed
- Git (optional)

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the Dashboard
```bash
python -m streamlit run app.py
```
*(Or `streamlit run app.py` if Python scripts are added to your PATH)*

*The web interface will open automatically in your browser at `http://localhost:8501`.*

---

## 🧪 5. Running Automated Unit Tests

```bash
python -m unittest discover tests
```
*Runs all 8 verification tests covering Network Scanner, ML Classifier, Prompt Evaluator, and PDF Report Exporter.*

---

## 📁 6. Project Directory Layout

```
├── app.py                          # Streamlit Cyber Dashboard Entrypoint
├── config.py                       # Global settings & configuration
├── requirements.txt                # Python dependencies
│
├── modules/
│   ├── honeypot_detector/          # MODULE 1: Honeypot Identification
│   │   ├── scanner.py              # Sockets & banner grabbing engine
│   │   ├── signatures.py           # Honeypot signature database & anomaly heuristics
│   │   ├── feature_extractor.py    # Extracts ML feature vector from scan data
│   │   ├── classifier.py           # Random Forest inference & risk scoring
│   │   ├── shodan_helper.py        # Shodan OSINT IP intelligence
│   │   └── models/
│   │       └── honeypot_model.joblib # Pre-trained ML model artifact
│   │
│   ├── prompt_shield/              # MODULE 2: LLM Prompt Security
│   │   ├── runner.py               # Test suite runner & orchestrator
│   │   ├── adapters.py             # Gemini, OpenAI, Custom API & Mock adapters
│   │   ├── evaluator.py            # Safety judge, refusal & leakage detection
│   │   ├── hardening.py            # Prompt defense strategies & templates
│   │   └── payloads/               # JSON Attack Test Suites
│   │       ├── injection_tests.json
│   │       ├── leakage_tests.json
│   │       └── jailbreak_tests.json
│   │
│   └── reporting/                  # UNIFIED REPORTING
│       ├── pdf_generator.py        # Generates executive PDF audit report
│       └── metrics.py              # Risk matrix calculation & JSON export
│
├── datasets/
│   ├── honeypot_dataset.csv        # Synthetic scan telemetry dataset
│   └── train_model.py              # Script to retrain Random Forest model
│
└── tests/                          # Test Suites
    ├── test_scanner.py             # Honeypot detection tests
    ├── test_evaluator.py           # LLM evaluator tests
    └── test_pdf.py                 # PDF generation tests
```

---

## 🎓 7. Project Presentation & Viva Highlights

1. **Dual Domain Innovation**: Combines traditional perimeter defense with cutting-edge LLM application safety.
2. **Defensive Focus**: Demonstrates not only how AI models break, but provides automated mitigation strategies (Sandwich Defense, XML Delimiters).
3. **Dual Detection Model**: Utilizes deterministic signature matching alongside probabilistic Machine Learning classification.
4. **Complete Security Deliverable**: Produces verifiable metrics, live side-by-side comparisons, and downloadable audit documentation.
