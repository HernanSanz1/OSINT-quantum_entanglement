"""
Tool Checker & Dependency Installer
Checks Python libraries and binary tools; offers auto-install for Python deps.
"""
import importlib
import shutil
import subprocess
import sys
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class CheckResult:
    name: str
    kind: str          # "python" | "binary" | "optional_binary"
    available: bool
    version: str = ""
    install_cmd: str = ""
    note: str = ""


# ── Python dependencies ───────────────────────────────────────────────────────

_PYTHON_DEPS: List[Dict] = [
    {"import": "requests",      "pip": "requests",      "required": True},
    {"import": "bs4",           "pip": "beautifulsoup4","required": True},
    {"import": "psutil",        "pip": "psutil",        "required": True},
    {"import": "dns.resolver",  "pip": "dnspython",     "required": True},
    {"import": "ipwhois",       "pip": "ipwhois",       "required": True},
    {"import": "phonenumbers",  "pip": "phonenumbers",  "required": True},
    {"import": "openai",        "pip": "openai",        "required": False,
     "note": "Requerido para ChatGPT y Venice"},
    {"import": "pandas",        "pip": "pandas",        "required": False,
     "note": "Análisis de datos avanzado"},
    {"import": "networkx",      "pip": "networkx",      "required": False},
    {"import": "lxml",          "pip": "lxml",          "required": False},
]

# ── Binary tools ──────────────────────────────────────────────────────────────

_BINARY_TOOLS: List[Dict] = [
    # Required binary — core workflow
    {"bin": "ollama", "name": "Ollama (LLM local)", "required": False,
     "install": "brew install ollama  OR  curl https://ollama.ai/install.sh | sh"},
    # Optional binary tools
    {"bin": "subfinder",    "name": "Subfinder",      "required": False,
     "install": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
    {"bin": "amass",        "name": "OWASP AMASS",    "required": False,
     "install": "brew install amass"},
    {"bin": "theHarvester", "name": "TheHarvester",   "required": False,
     "install": "pip install theHarvester"},
    {"bin": "theharvester", "name": "TheHarvester (alt)", "required": False,
     "install": "pip install theHarvester"},
    {"bin": "sherlock",     "name": "Sherlock",        "required": False,
     "install": "pip install sherlock-project"},
    {"bin": "holehe",       "name": "Holehe",          "required": False,
     "install": "pip install holehe"},
    {"bin": "maigret",      "name": "Maigret",         "required": False,
     "install": "pip install maigret"},
    {"bin": "recon-ng",     "name": "Recon-ng",        "required": False,
     "install": "pip install recon-ng"},
    {"bin": "sn0int",       "name": "sn0int",          "required": False,
     "install": "cargo install sn0int"},
    {"bin": "spiderfoot",   "name": "SpiderFoot",      "required": False,
     "install": "pip install spiderfoot"},
    {"bin": "sf",           "name": "SpiderFoot (alt)","required": False, "install": ""},
]


class ToolChecker:
    """Check and install dependencies for OSINT App v2."""

    def check_all(self) -> Dict[str, List[CheckResult]]:
        return {
            "python":  self.check_python(),
            "binary":  self.check_binaries(),
        }

    # ── Python ─────────────────────────────────────────────────────────────────

    def check_python(self) -> List[CheckResult]:
        results = []
        seen: set = set()
        for dep in _PYTHON_DEPS:
            pkg = dep["import"]
            if pkg in seen:
                continue
            seen.add(pkg)
            try:
                mod = importlib.import_module(pkg.split(".")[0])
                ver = getattr(mod, "__version__", "unknown")
                results.append(CheckResult(
                    name=dep["pip"], kind="python",
                    available=True, version=ver,
                    install_cmd=f"pip install {dep['pip']}",
                    note=dep.get("note", ""),
                ))
            except ImportError:
                results.append(CheckResult(
                    name=dep["pip"], kind="python",
                    available=False,
                    install_cmd=f"pip install {dep['pip']}",
                    note=dep.get("note", ""),
                ))
        return results

    def check_binaries(self) -> List[CheckResult]:
        results = []
        seen: set = set()
        for tool in _BINARY_TOOLS:
            name = tool["name"]
            if name in seen:
                continue
            seen.add(name)
            path = shutil.which(tool["bin"])
            results.append(CheckResult(
                name=name, kind="binary",
                available=path is not None,
                version=path or "",
                install_cmd=tool.get("install", ""),
                note="",
            ))
        return results

    def auto_install_missing_python(
        self, results: Optional[List[CheckResult]] = None
    ) -> Dict[str, bool]:
        """
        Auto-install only missing Python packages.
        Returns {pkg_name: success}.
        SAFE: only runs `pip install <package>` — no shell=True, no user input in args.
        """
        if results is None:
            results = self.check_python()
        outcome: Dict[str, bool] = {}
        for r in results:
            if r.available or r.kind != "python":
                continue
            pkg = r.name
            logger.info(f"Auto-installing: {pkg}")
            try:
                proc = subprocess.run(
                    [sys.executable, "-m", "pip", "install", pkg, "--quiet"],
                    capture_output=True, text=True, timeout=120,
                )
                outcome[pkg] = proc.returncode == 0
            except subprocess.TimeoutExpired:
                outcome[pkg] = False
            except Exception as e:
                logger.error(f"Install {pkg} failed: {type(e).__name__}")
                outcome[pkg] = False
        return outcome

    def summary_text(self) -> str:
        """Human-readable status summary."""
        checks = self.check_all()
        lines = ["=" * 50, "  OSINT App v2 — Dependency Check", "=" * 50]
        for category, results in checks.items():
            lines.append(f"\n[{category.upper()}]")
            for r in results:
                icon = "✅" if r.available else "⬜"
                note = f"  ({r.note})" if r.note else ""
                ver = f" v{r.version}" if r.available and r.version not in ("unknown", "", r.version[:4]) else ""
                install = f"\n     → {r.install_cmd}" if not r.available and r.install_cmd else ""
                lines.append(f"  {icon} {r.name}{ver}{note}{install}")
        return "\n".join(lines)


# Global singleton
tool_checker = ToolChecker()
