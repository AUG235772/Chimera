# 🦁 Chimera | AI-Powered Hybrid Vulnerability Scanner & Exploit Lab

![Security Grade](https://img.shields.io/badge/Security_Grade-A+-success?style=for-the-badge&logo=shield)
![AI Model](https://img.shields.io/badge/GenAI-Llama_3-blueviolet?style=for-the-badge&logo=openai)
![ML Model](https://img.shields.io/badge/ML-CodeBERT-orange?style=for-the-badge&logo=huggingface)
![Core](https://img.shields.io/badge/Core-OWASP_ZAP-blue?style=for-the-badge&logo=owasp)

**Chimera** is an advanced, automated security assessment and active exploitation framework designed to bridge the gap between Static Analysis (SAST) and Dynamic Analysis (DAST). 

Going beyond standard vulnerability detection, Chimera features an integrated **Exploit Replay Lab**, an **AI Kill Chain Analyzer**, and **Shadow API Discovery**, making it a unified DevSecOps pipeline tool that thinks like a Red Team Operator.

---

## 🚀 Key Capabilities

### 1. ⚔️ Active Web Scanning & Reconnaissance (DAST)
* **Shadow API Hunting:** Actively downloads and parses frontend JavaScript bundles using Regex/AST to extract hidden developer endpoints, GraphQL routes, and hardcoded AWS/API keys.
* **OWASP ZAP Orchestration:** Automates a headless ZAP instance to perform deep spidering, active scanning, and fuzzing for runtime vulnerabilities.
* **Smart Recon:** Enumerates subdomains via Certificate Transparency logs and scans for exposed critical ports and security headers.

### 2. 🔗 AI Kill Chain Analysis & Exploitation
* **Attack Path Mapping:** Instead of isolating vulnerabilities, Chimera’s AI analyzes all findings collectively to build realistic, multi-step kill chains (e.g., *WAF Bypass → Stored XSS → Session Hijacking*).
* **Weaponized PoC Generation:** Automatically generates executable `curl` scripts and payloads for identified vulnerabilities.
* **Interactive Exploit Lab:** A built-in "Burp Repeater" style dashboard allowing operators to safely fire AI-generated exploits at the target and analyze the raw server response in real-time.

### 3. 🛡️ Source Code Audit (SAST)
* **Neural Engine:** Uses a localized **CodeBERT** transformer model to analyze code logic and detect vulnerabilities (e.g., Logic Flaws, Insecure Crypto) that traditional regex scanners miss.
* **Dependency & Secret Audit:** Cross-references `package.json` and `requirements.txt` against the OSV Vulnerability Database and scans commit history for leaked credentials.

### 4. 🧠 Intelligent Forensic Reporting
* **Visual Evidence Collection:** Integrates Headless Selenium to automatically navigate to vulnerable endpoints and capture high-resolution Proof-of-Concept (PoC) screenshots.
* **GenAI Auto-Remediation:** Feeds vulnerability data into Groq's LPUs to generate human-readable impact analysis and exact code snippets to patch the flaws.
* **Forensic PDF:** Auto-generates a detailed, color-coded PDF report classified by risk severity, complete with exploit evidence and architectural fixes.

---

## 🛠️ Architecture & Tech Stack

Chimera follows a micro-modular architecture optimized for containerized deployment:

| Module | Technology | Purpose |
| :--- | :--- | :--- |
| **Backend** | Python, Flask, Socket.IO | Orchestration, API handling, and Real-time WebSocket telemetry. |
| **ML Engine** | PyTorch, Transformers | Running the local CodeBERT model for code analysis. |
| **AI Brain** | Groq API (Llama-3 70B) | Generating kill chains, contextual remediation, and weaponized PoCs. |
| **Scanner** | OWASP ZAP, Selenium | Dynamic web scanning and automated evidence capture. |
| **Frontend** | HTML5, CSS3, Tailwind | Responsive Hacker UI featuring the Exploit Replay Lab. |
| **Infrastructure** | Docker, Vercel | Containerized deployment with strict edge security headers. |

### 📂 Project Structure
```text
CHIMERA/
├── modules/
│   ├── ai_engine.py       # Llama-3 integration for Kill Chains & PoC generation
│   ├── zap_engine.py      # Controller for OWASP ZAP headless scanner
│   ├── ml_engine.py       # PyTorch loader for CodeBERT logic flaw detection
│   ├── github_recon.py    # Git cloning, secret scanning, and SCA checks
│   ├── recon.py           # Subdomain enumeration, JS parsing, and Shadow API hunting
│   ├── evidence.py        # Headless Selenium engine for PoC screenshot capture
│   └── report.py          # Forensic PDF generator with visual evidence rendering
├── templates/
│   └── index.html         # Interactive dashboard and Exploit Replay Lab UI
├── Dockerfile             # Multi-stage build (Python + Java + Chromium)
├── app.py                 # Core Flask application and SocketIO event loop
└── requirements.txt       # Python dependencies
```
---
## 💻 Installation & Usage
### Option 1: Run with Docker (Recommended)
Chimera requires Java (for ZAP) and Python. Docker handles this environment setup automatically.
```bash
# 1. Clone the repository
git clone [https://github.com/AUG235772/Chimera.git](https://github.com/AUG235772/Chimera.git)
cd Chimera

# 2. Build the Image
docker build -t chimera-scanner .

# 3. Run the Container
# Map port 7860 for the Web UI
docker run -p 7860:7860 --env-file .env chimera-scanner
```
### Option 2: Manual Local Setup
Prerequisites: Python 3.10+, Java 11+ (Required for ZAP), Chrome/Firefox (for Selenium).
```bash
# 1. Install Python Dependencies
pip install -r requirements.txt

# 2. Configure Environment Variables
# Create a .env file with your keys:
# GROQ_API_KEY=your_key_here
# ZAP_API_KEY=your_key_here

# 3. Launch the App
python app.py
```
Access the dashboard at http://localhost:7860.

---
## ⚠️ Disclaimer
**Chimera is intended for educational purposes and authorized security testing only.**<br>
The developer assumes no liability and is not responsible for any misuse or damage caused by this tool. Always obtain written permission from the owner before scanning any system.

---

### Developed by Aditya Gupta
