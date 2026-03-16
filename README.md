# 🦁 Chimera | AI-Powered Hybrid Vulnerability Scanner

![Security Grade](https://img.shields.io/badge/Security_Grade-A+-success?style=for-the-badge&logo=shield)
![AI Model](https://img.shields.io/badge/GenAI-Llama_3-blueviolet?style=for-the-badge&logo=openai)
![ML Model](https://img.shields.io/badge/ML-CodeBERT-orange?style=for-the-badge&logo=huggingface)
![Core](https://img.shields.io/badge/Core-OWASP_ZAP-blue?style=for-the-badge&logo=owasp)

**Chimera** is an automated security assessment framework designed to bridge the gap between Static Analysis (SAST) and Dynamic Analysis (DAST). It provides a unified interface to audit **GitHub Repositories** for insecure code patterns and scan **Live Web Applications** for runtime vulnerabilities.

Built with a modular architecture, Chimera leverages **Machine Learning (Microsoft CodeBERT)** to reduce false positives in code auditing and **Generative AI (Groq/Llama-3)** to provide human-readable impact analysis and remediation steps.

---

## 🚀 Key Capabilities

### 1. 🛡️ Source Code Audit (SAST)
* **Target:** GitHub Repositories (Public/Private).
* **Deep Learning Engine:** Uses a localized **CodeBERT** transformer model to analyze code logic and detect vulnerabilities (e.g., Logic Flaws, Insecure Crypto) that regex scanners miss.
* **Secrets Detection:** Scans commit history and file contents for hardcoded credentials (AWS Keys, API Tokens, Database URIs).
* **Dependency Analysis:** Cross-references `package.json` and `requirements.txt` against the **OSV Vulnerability Database** to detect insecure dependencies.

### 2. ⚔️ Web Application Scanning (DAST)
* **Target:** Live URLs / IP Addresses.
* **ZAP Integration:** Orchestrates a headless **OWASP ZAP** instance via API to perform spidering, active scanning, and fuzzing.
* **Real-time Recon:** Maps attack surface including hidden subdomains and exposed endpoints.
* **Security Header Analysis:** Checks for missing critical headers (CSP, HSTS, X-Frame-Options) to prevent Clickjacking and XSS.

### 3. 🧠 Intelligent Reporting
* **GenAI Enrichment:** Every finding is analyzed by **Llama-3 (via Groq)** to generate a "Black Box" exploit scenario and a specific code patch.
* **Smart Filtering:** Uses an internal confidence scoring system to filter out noise and false positives before reporting.
* **Forensic PDF:** Auto-generates a detailed PDF report classified by risk severity (Critical, High, Medium, Low).

---

## 🛠️ Architecture & Tech Stack

The project follows a micro-modular architecture for scalability:

| Module | Technology | Purpose |
| :--- | :--- | :--- |
| **Backend** | Python, Flask, Socket.IO | Orchestration, API handling, and Real-time WebSocket logs. |
| **ML Engine** | PyTorch, Transformers | Running the local CodeBERT model for code analysis. |
| **AI Engine** | Groq API (Llama-3) | Generating contextual remediation and exploit proofs. |
| **Scanner** | OWASP ZAP (Docker) | The core engine for dynamic web vulnerability scanning. |
| **Frontend** | HTML5, CSS3 (Hacker UI) | Responsive dashboard for initiating scans and viewing telemetry. |
| **Infrastructure** | Docker, Vercel | Containerized deployment and edge security headers. |

### 📂 Project Structure
```text
CHIMERA/
├── modules/
│   ├── ai_engine.py       # Interface for Llama-3 (Groq) remediation generation
│   ├── zap_engine.py      # Controller for OWASP ZAP headless scanner
│   ├── ml_engine.py       # PyTorch loader for CodeBERT vulnerability detection
│   ├── github_recon.py    # Git cloning, secret scanning, and dependency checks
│   ├── report.py          # PDF generation logic
│   └── recon.py           # Subdomain enumeration and spidering logic
├── templates/
│   └── index.html         # The main dashboard UI
├── Dockerfile             # Multi-stage build for Python + Java (ZAP requirement)
├── app.py                 # Main Flask application entry point
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
