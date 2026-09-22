"""Abstract base class for all OSINT tools — v2 with ToolRequirements."""
import shutil
import importlib
from abc import ABC, abstractmethod
from typing import List, Dict
from .models import QueryParameters, SearchResult, ToolRequirements


class OSINTTool(ABC):
    """Every tool must declare what it needs (requirements) and what it produces."""

    def __init__(self, name: str, description: str, requirements: ToolRequirements):
        self.name = name
        self.description = description
        self.requirements = requirements
        self.is_heavy: bool = False
        self.requires_api_key: bool = False
        self.api_key: str = ""
        # Runtime install check
        self.is_available: bool = True    # False = binary missing or server down

        # Override in subclasses with the binary name(s) and/or Python package(s)
        self._binary_names: List[str] = []   # e.g. ["sherlock"]
        self._python_pkgs: List[str]  = []   # e.g. ["requests", "bs4"]
        self._install_cmd: str = ""          # e.g. "pip install requests beautifulsoup4"
        # System-level deps: list of (binary_name, install_url)
        # e.g. [("go", "https://go.dev/dl/"), ("docker", "https://docs.docker.com/get-docker/")]
        self._system_deps: List[tuple] = []
        # Progress callback — set by framework before execute() — tools can call self._report_progress(msg)
        self._progress_cb = None
        # Cancellation flag
        self._is_cancelled = False

    @abstractmethod
    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        """Execute and return results. Pre-validated by DataCompatibilityEngine."""
        pass

    def check_available(self) -> bool:
        """Override in subprocess-based tools to verify binary is installed."""
        return True

    def _report_progress(self, msg: str) -> None:
        """Emit a progress message to the UI. Safe to call from execute()."""
        if callable(self._progress_cb):
            try:
                self._progress_cb(msg)
            except Exception:
                pass

    def stop(self) -> None:
        """Request the tool to stop execution."""
        self._is_cancelled = True

    def diagnose_status(self) -> Dict:
        """
        Returns a structured status dict for the Tools tab UI.
        Keys: status, icon, message, install_cmd

        status values:
          'ready'            — everything is in order
          'needs_key'        — binary/pkg ok but API key missing
          'not_installed'    — required binary not found in PATH
          'python_pkg_missing' — required Python package import fails
        """
        # 0. Check system-level dependencies (Go, Rust, Docker, etc.)
        for sys_bin, install_url in self._system_deps:
            if not shutil.which(sys_bin):
                return {
                    "status": "not_installed",
                    "icon": "🔧",
                    "message": (
                        f"Dependencia del sistema '{sys_bin}' no encontrada.\n"
                        f"Debes instalarlo en tu sistema primero antes de poder\n"
                        f"instalar o usar '{self.name}'."
                    ),
                    "install_cmd": (
                        f"# Instala '{sys_bin}' desde:\n"
                        f"{install_url}\n\n"
                        f"# Una vez instalado, vuelve a verificar esta herramienta."
                    ),
                }

        # 1. Check tool availability (relies on subclass' is_available flag which might check local folder paths)
        if hasattr(self, "is_available") and not self.is_available:
            return {
                "status": "not_installed",
                "icon": "❌",
                "message": (
                    f"Binario '{self._binary_names[0] if self._binary_names else self.name}' no encontrado o no instalado.\n"
                    f"Instálalo, compílalo o asegúrate de que esté en tu PATH."
                ),
                "install_cmd": self._install_cmd or f"# Busca instrucciones de instalación para {self.name}",
            }

        # 2. Check required Python packages
        for pkg in self._python_pkgs:
            try:
                importlib.import_module(pkg)
            except ImportError:
                pip_name = pkg.replace("_", "-")
                return {
                    "status": "python_pkg_missing",
                    "icon": "⚠️",
                    "message": f"Paquete Python '{pkg}' no instalado.",
                    "install_cmd": self._install_cmd or f"pip install {pip_name}",
                }

        # 3. Check API key if required
        if self.requires_api_key and not self.api_key:
            return {
                "status": "needs_key",
                "icon": "🔑",
                "message": (
                    f"API key no configurada para '{self.name}'.\n"
                    f"Agrégala en ~/.osint_v2_keys con el nombre '{self.name}'."
                ),
                "install_cmd": f'# En ~/.osint_v2_keys:\n# "{self.name}": "tu-api-key-aqui"',
            }

        # 4. All good
        return {
            "status": "ready",
            "icon": "✅",
            "message": f"{self.name} está listo para usar.",
            "install_cmd": "",
        }

    def set_api_key(self, api_key: str) -> None:
        self.api_key = api_key

