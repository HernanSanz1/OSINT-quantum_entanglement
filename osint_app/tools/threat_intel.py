"""
Threat Intelligence tools: IntelOwl, OpenCTI, MISP, Cortex, IntelMQ

ESTADO REAL (auditoría 2026-10-04): son PLANTILLAS. `BASE_URL` nunca se configura (siempre "") y no hay código
que consulte esos servidores: `execute` solo devuelve un aviso. Se mantienen para no perder la guía de instalación,
pero dicen la verdad y remiten a "IP Reputation", que sí da CTI real sin servidor. Programar cada cliente exige un
servidor de prueba para verificarlo en real.
"""
import logging
from typing import List
import requests

from ..core.models import ToolRequirements, QueryParameters, SearchResult
from ..core.base_tool import OSINTTool

logger = logging.getLogger(__name__)


class _ThreatBaseTool(OSINTTool):
    """Common base for threat intel tools that need a server URL."""
    BASE_URL: str = ""
    _DOCKER_REPO: str = ""          # GitHub repo URL for docker-compose
    _DOCKER_CMD: str = ""           # docker-compose command to start
    _DEFAULT_PORT: str = ""         # default local port

    def __init__(self, name, description, requirements):
        super().__init__(name, description, requirements)
        # Docker y docker-compose son dependencias del sistema para estas tools
        self._system_deps = [
            ("docker", "https://docs.docker.com/get-docker/"),
        ]

    def check_available(self) -> bool:
        if not self.BASE_URL:
            self.is_available = False
            return False
        try:
            r = requests.get(self.BASE_URL, timeout=5)
            self.is_available = r.ok
        except Exception:
            self.is_available = False
        return self.is_available

    def diagnose_status(self) -> dict:
        """
        Para tools Docker: verifica API key + conectividad al servidor.
        Explica exactamente cómo levantar el servicio si no está disponible.
        """
        # 1. ¿Tiene URL configurada?
        if not self.BASE_URL:
            return {
                "status": "not_installed",
                "icon": "🐳",
                "message": (
                    f"🚧 {self.name}: integración PENDIENTE — SENTINEL todavía no tiene programada la\n"
                    f"consulta a este servidor, así que levantarlo no basta. Para CTI real sin servidor usa\n"
                    f"'IP Reputation' (Shodan InternetDB, GreyNoise, Tor, Spamhaus, FireHOL, URLhaus)."
                ),
                "install_cmd": (
                    f"# 1. Clona el repositorio:\n"
                    f"git clone {self._DOCKER_REPO}\n\n"
                    f"# 2. Levanta los servicios:\n"
                    f"{self._DOCKER_CMD}\n\n"
                    f"# 3. Accede en: http://localhost:{self._DEFAULT_PORT}\n"
                    f"# 4. Guarda la API key (queda cifrada):\n"
                    f"#    python -m osint_app.main --set-key {self.name}\n"
                    f"# (cuando la integración esté programada)"
                ),
            }

        # 2. ¿El servidor responde?
        server_ok = self.check_available()
        if not server_ok:
            return {
                "status": "not_installed",
                "icon": "🐳",
                "message": (
                    f"{self.name}: servidor configurado en {self.BASE_URL}\n"
                    f"pero NO responde. ¿Está el Docker Compose levantado?"
                ),
                "install_cmd": (
                    f"# Levanta el servicio con:\n"
                    f"{self._DOCKER_CMD}\n\n"
                    f"# Verifica que esté corriendo:\n"
                    f"docker ps | grep {self.name.lower()}"
                ),
            }

        # 3. ¿Tiene API key?
        if self.requires_api_key and not self.api_key:
            return {
                "status": "needs_key",
                "icon": "🔑",
                "message": (
                    f"{self.name}: servidor ✅ responde en {self.BASE_URL}\n"
                    f"Pero falta la API key para autenticarse."
                ),
                "install_cmd": f"python -m osint_app.main --set-key {self.name}",
            }

        # 4. Todo listo
        return {
            "status": "not_installed",
            "icon": "🚧",
            "message": (f"{self.name}: el servidor responde en {self.BASE_URL}, pero la integración aún no está "
                        f"programada en SENTINEL. Usa 'IP Reputation' para CTI real."),
            "install_cmd": "",
        }


class IntelOwlTool(_ThreatBaseTool):
    _DOCKER_REPO = "https://github.com/intelowlproject/IntelOwl"
    _DOCKER_CMD  = "cd IntelOwl && docker-compose up -d"
    _DEFAULT_PORT = "80"

    def __init__(self):
        super().__init__(
            "IntelOwl", "Análisis de threat intelligence: IPs, dominios, hashes",
            ToolRequirements(
                mandatory=["observable"],
                optional=["domain", "ip", "hash_value", "target_name"],
                produces=["ip", "domain", "url", "hash"],
                hint="Acepta cualquier observable. Requiere IntelOwl local o SaaS.",
            )
        )
        self.requires_api_key = True
        self.is_heavy = True

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        return _server_error_result(self.name, "IntelOwl")


class OpenCTITool(_ThreatBaseTool):
    _DOCKER_REPO = "https://github.com/OpenCTI-Platform/docker"
    _DOCKER_CMD  = "cd opencti-docker && docker-compose up -d"
    _DEFAULT_PORT = "8080"

    def __init__(self):
        super().__init__(
            "OpenCTI", "Plataforma de amenazas cibernéticas — IOCs, TTPs",
            ToolRequirements(
                mandatory=["observable"],
                optional=["domain", "ip", "target_name"],
                produces=["ip", "domain", "url"],
                hint="Requiere servidor OpenCTI. Acepta cualquier observable.",
            )
        )
        self.requires_api_key = True
        self.is_heavy = True

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        return _server_error_result(self.name, "OpenCTI")


class MISPTool(_ThreatBaseTool):
    _DOCKER_REPO = "https://github.com/MISP/misp-docker"
    _DOCKER_CMD  = "cd misp-docker && docker-compose up -d"
    _DEFAULT_PORT = "443"

    def __init__(self):
        super().__init__(
            "MISP", "Plataforma de intercambio de información de amenazas",
            ToolRequirements(
                mandatory=["observable"],
                optional=["ip", "domain", "hash_value"],
                produces=["ip", "domain", "hash"],
                hint="Requiere servidor MISP. Acepta IP, dominio o hash.",
            )
        )
        self.requires_api_key = True
        self.is_heavy = True

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        return _server_error_result(self.name, "MISP")


class CortexTool(_ThreatBaseTool):
    _DOCKER_REPO = "https://github.com/TheHive-Project/Cortex"
    _DOCKER_CMD  = "cd Cortex && docker-compose up -d"
    _DEFAULT_PORT = "9001"

    def __init__(self):
        super().__init__(
            "Cortex", "Motor de análisis automático de observables",
            ToolRequirements(
                mandatory=["observable"],
                optional=["ip", "domain", "hash_value", "url"],
                produces=["ip", "domain", "hash", "url"],
                hint="Requiere servidor Cortex. Acepta cualquier observable.",
            )
        )
        self.requires_api_key = True
        self.is_heavy = True

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        return _server_error_result(self.name, "Cortex")


class IntelMQTool(_ThreatBaseTool):
    _DOCKER_REPO = "https://github.com/certtools/intelmq"
    _DOCKER_CMD  = "docker run -d -p 1337:1337 pbartusch/intelmq-api"
    _DEFAULT_PORT = "1337"

    def __init__(self):
        super().__init__(
            "IntelMQ", "Feeds de amenazas — IPs y dominios maliciosos",
            ToolRequirements(
                mandatory=["ip"],
                optional=["domain"],
                produces=["ip", "domain"],
                hint="Necesita IP. Obtenla con dnspython, CENSYS o Subfinder.",
            )
        )
        self.is_heavy = True

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        return _server_error_result(self.name, "IntelMQ")


def _server_error_result(tool_name: str, server: str) -> List[SearchResult]:
    """Aviso honesto: la integración con el servidor todavía no está programada."""
    return [SearchResult(
        title=f"{tool_name} — integración pendiente",
        url="",
        snippet=(f"SENTINEL todavía no tiene programada la consulta a {server}: configurar el servidor no basta. "
                 f"Para reputación de IPs y URLs usa la herramienta 'IP Reputation' "
                 f"(Shodan InternetDB, GreyNoise, Tor, Spamhaus, FireHOL y URLhaus, sin clave)."),
        source_tool=tool_name, category="Config Error",
        relevance_score=0,
    )]
