# SENTINEL — OSINT Framework v2

> **Cybersecurity & IT Intelligence Platform**  
> Desktop application for structured OSINT investigations focused on data correlation.

---

## Features

- **Case Management** — Create, organize, and track investigation cases
- **OSINT Tools** — Integrated tools: Google Dorks, Wayback Machine, crt.sh, Censys, Subfinder, TheHarvester, and more
- **Correlation Engine** — Cross-source entity correlation for profiling and CTI
- **Reporting** — JSON/HTML export with entity extraction
- **Sentinel UI** — Premium dark cybersecurity dashboard interface

## Requirements

- Python 3.10+
- PySide6 + pyqtgraph (GUI) — installed via `requirements.txt`

## Setup

```bash
# 1. Clone the repo
git clone https://github.com/your-user/sentinel-osint.git
cd sentinel-osint

# 2. Create virtualenv
python3 -m venv env
source env/bin/activate

# 3. Install dependencies
pip install -r osint_app/requirements.txt

# 4. (Optional) Configure API keys for tools that need them (never committed)
echo "Hunter.io=your-hunter-key" >> ~/.osint_v2_keys
echo "CENSYS=your-censys-key"    >> ~/.osint_v2_keys
chmod 600 ~/.osint_v2_keys

# 5. Run
python3 -m osint_app.main
```

## Project Structure

```
sentinel-osint/
├── osint_app/          # All application code
│   ├── gui/            # Sentinel UI (theme, components, tabs)
│   ├── core/           # Data models
│   ├── tools/          # OSINT tool registry
│   ├── ai/             # AI engine adapters
│   ├── db/             # SQLite persistence
│   ├── reports/        # HTML report generator
│   ├── utils/          # Sanitizer, secret vault, tool checker
│   └── assets/         # Logo and static assets
├── docs/               # User and developer manuals
├── env/                # Virtual environment (not committed)
└── .gitignore
```

## CLI Tools

```bash
# Check which OSINT tools are installed:
python3 -m osint_app.main --check-tools

# Launch GUI (default):
python3 -m osint_app.main
```

## License

Private — Sentinel Cybersecurity & IT Intelligence. All rights reserved.
