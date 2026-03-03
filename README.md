# ATLAS (Advanced Testing Lab for Application Security)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)
![Status: Development](https://img.shields.io/badge/Status-Development-orange.svg)

> **"Bridging the gap between theory and practice in application security."**

ATLAS is a comprehensive security assessment framework designed for students, developers, and security enthusiasts. It combines automated reconnaissance, modular vulnerability checks, and interactive learning workflows into a unified, easy-to-use platform.



---



## Key Features

### Reconnaissance
*   **Automated Nmap Integration**: Effortlessly scan targets for open ports and services.
*   **Service Fingerprinting**: Identify running applications and versions.
*   **Tech Stack Detection**: Uncover backend technologies (e.g., PHP, Django, NodeJS).

### Vulnerability Assessment
*   **Modular Check Engine**: Run targeted checks for specific vulnerabilities.
*   **Supported Checks**:
    *   SQL Injection (SQLi)
    *   Cross-Site Scripting (XSS)
    *   Directory Traversal / LFI
    *   Weak Credentials (Brute-force)
    *   Misconfiguration Detection

### Interactive Learning
*   **Guided Mode**: Step-by-step wizard for setting up scans and understanding each phase.
*   **Demo Targets**: Practice safely with one-click presets for **VulnBank** (Web) and **IoTGoat** (IoT).
*   **Real-time Terminal**: Integrated web-based terminal for manual verification and advanced commands.

### Reporting & Dashboard
*   **Modern Web UI**: Dark-themed dashboard built with HTML5/CSS3/JS.
*   **Detailed Reports**: Generate HTML and JSON reports with remediation advice.
*   **Scan History**: View past assessments and track progress.

---

## Installation

### Prerequisites
*   **Python 3.10+**
*   **Nmap** (must be installed and in your system PATH)
    *   Linux: `sudo apt install nmap`
    *   macOS: `brew install nmap`
    *   Windows: [Download Installer](https://nmap.org/download.html)

### Setup Steps
1.  **Clone the Repository**:
    ```bash
    git clone https://github.com/your-username/atlas.git
    cd atlas
    ```

2.  **Create Virtual Environment** (Recommended):
    ```bash
    python -m venv venv
    source venv/bin/activate  # Windows: venv\Scripts\activate
    ```

3.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

---

## Usage

### Quick Start (Web UI)
Launch the API server and access the dashboard:
```bash
python -m uvicorn api.main:app --reload --port 8000
```
Open **http://localhost:8000** in your browser.
*   **Login**: Default credentials (if applicable) or register a new account.
*   **Dashboard**: Manage scans, view reports, and access the terminal.

### Command Line Interface (CLI)
Automate tasks directly from your terminal:

**Start a Scan:**
```bash
python -m cli.main scan http://localhost:3000 --profile full
```

**Launch Demo Target:**
```bash
python -m cli.main demo vulnbank
```

**List Available Checks:**
```bash
python -m cli.main checks list
```

---

## Project Structure

```
atlas/
├── api/          # FastAPI backend routes & application logic
├── atlas/        # Core engine
│   ├── checks/   # Vulnerability check modules (SQLi, XSS, etc.)
│   ├── core/     # State management & orchestration
│   └── recon/    # Nmap scanner integration
├── cli/          # Typer-based command line interface
├── web/          # Frontend assets (HTML, CSS, JS)
├── data/         # SQLite DB, logs, and report storage

```

---

## Contributing
Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) to get started.

1.  Fork the repository.
2.  Create a feature branch (`git checkout -b feature/amazing-feature`).
3.  Commit your changes (`git commit -m 'Add amazing feature'`).
4.  Push to the branch (`git push origin feature/amazing-feature`).
5.  Open a Pull Request.

---

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Disclaimer**: ATLAS is intended for educational and authorized testing purposes only. Using this tool against targets without prior mutual consent is illegal. The developers assume no liability and are not responsible for any misuse or damage caused by this program.
