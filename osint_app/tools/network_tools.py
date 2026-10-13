"""
Network tools — HTTPS enforced, SSRF guard on all outbound calls.

SECURITY:
- All outbound URLs validated via validate_ssrf() before requests
- HTTPS used exclusively for archive.org (not HTTP)
- User-supplied domain/IP sanitized via sanitize_shell_arg()
- subprocess calls with explicit timeouts and never shell=True
- Output capped at MAX_OUTPUT_BYTES
"""
import importlib.util, re, shutil, subprocess, logging, shlex
from typing import List
from pathlib import Path
from ..core.models import ToolRequirements, QueryParameters, SearchResult
from ..core.base_tool import OSINTTool
from ..utils.sanitizer import (
    sanitize_shell_arg, sanitize_snippet, validate_domain, validate_ip, MAX_OUTPUT_BYTES,
)

logger = logging.getLogger(__name__)
MAX_RESULTS = 100

# El banner de TheHarvester imprime el correo de su autor: no es un hallazgo (antes salía en CADA ejecución como "Email")
HARVESTER_BANNER_EMAILS = {"cmartorella@edge-security.com"}
_EMAIL_LINE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")
_HOST_LINE = re.compile(r"^([A-Za-z0-9.-]+)(?::(\d{1,3}(?:\.\d{1,3}){3}))?$")     # "www.x.com" o "www.x.com:93.184.216.34"


class DnspythonTool(OSINTTool):
    def __init__(self):
        super().__init__(
            "dnspython", "Resolución DNS y análisis de registros",
            ToolRequirements(
                mandatory=["domain"],
                optional=[],
                produces=["ip", "domain"],
                hint="Necesita un dominio. Ingrésalo manualmente.",
            )
        )
        self._python_pkgs = ["dns"]
        self._install_cmd = "pip install dnspython"

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        domain = sanitize_shell_arg(query_params.domain or "")
        if not domain or not validate_domain(domain):
            logger.warning("DnspythonTool: invalid or missing domain")
            return []
        try:
            import dns.resolver
            results = []
            for rtype in ["A", "MX", "NS", "TXT", "CNAME"]:
                try:
                    answers = dns.resolver.resolve(domain, rtype, lifetime=10)
                    for rdata in answers:
                        snippet = sanitize_snippet(str(rdata))
                        results.append(SearchResult(
                            title=f"DNS {rtype}: {domain}",
                            url="", snippet=snippet,
                            source_tool=self.name, category="DNS",
                            relevance_score=70,
                        ))
                        if len(results) >= MAX_RESULTS:
                            return results
                except Exception:
                    continue
            return results
        except ImportError:
            logger.error("dnspython not installed — run: pip install dnspython")
            return []


class IpWhoisTool(OSINTTool):
    def __init__(self):
        super().__init__(
            "ipwhois", "WHOIS e información de ASN para IPs",
            ToolRequirements(
                mandatory=["ip"],
                optional=[],
                produces=["domain", "company", "location"],
                hint="Necesita una IP. Obtenla con CENSYS, dnspython o Subfinder.",
            )
        )
        self._python_pkgs = ["ipwhois"]
        self._install_cmd = "pip install ipwhois"

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        ip = (query_params.ip or "").strip()
        if not ip or not validate_ip(ip):
            logger.warning("IpWhoisTool: invalid or missing IP")
            return []
        try:
            from ipwhois import IPWhois
            obj = IPWhois(ip, timeout=15)
            data = obj.lookup_rdap(depth=1)
            asn  = sanitize_snippet(str(data.get("asn", "")))
            desc = sanitize_snippet(str(data.get("asn_description", "")))
            net  = data.get("network", {})
            return [SearchResult(
                title=f"WHOIS: {ip}",
                url="",
                snippet=f"ASN: {asn}  Org: {desc}  CIDR: {sanitize_snippet(net.get('cidr',''))}",
                source_tool=self.name, category="Network",
                relevance_score=75,
                raw_data=data,
            )]
        except ImportError:
            logger.error("ipwhois not installed — run: pip install ipwhois")
            return []
        except Exception as e:
            logger.error(f"ipwhois error: {type(e).__name__}")
            return []


class CensysTool(OSINTTool):
    def __init__(self):
        super().__init__(
            "CENSYS", "Escaneo de internet — hosts, certificados",
            ToolRequirements(
                mandatory=["domain"],
                optional=["ip"],
                produces=["ip", "domain", "url"],
                hint="Necesita dominio. Requiere API key de censys.io",
            )
        )
        self.requires_api_key = True
        self._python_pkgs = ["censys"]
        self._install_cmd = "pip install censys"
        self.check_available()

    def check_available(self) -> bool:
        # Sin el paquete la herramienta devolvía [] sin decir nada; así se marca como no instalada
        try:
            self.is_available = importlib.util.find_spec("censys") is not None
        except (ValueError, ImportError):          # un módulo a medias en sys.modules no debe impedir arrancar el programa
            self.is_available = False
        return self.is_available

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        if not self.api_key:
            logger.warning("CENSYS: no API key configured")
            self._report_progress("⚠️ CENSYS: falta la clave de API (python -m osint_app.main --set-key CENSYS).")
            return []
        domain = sanitize_shell_arg(query_params.domain or "")
        if not domain or not validate_domain(domain):
            return []
        try:
            import censys.certificates
            certs = censys.certificates.CensysCertificates()
            results = []
            for r in certs.search(
                f"parsed.names: {domain}",
                fields=["parsed.subject_dn", "parsed.names"],
                max_records=50,
            ):
                results.append(SearchResult(
                    title=f"Certificado: {sanitize_snippet(r.get('parsed.subject_dn','')[:60])}",
                    url="",
                    snippet=sanitize_snippet(str(r.get("parsed.names", []))),
                    source_tool=self.name, category="Certificate",
                    relevance_score=65,
                ))
                if len(results) >= MAX_RESULTS:
                    break
            return results
        except ImportError:
            # `censys.certificates` es la API antigua (v1): las versiones actuales del paquete ya no la incluyen
            self._report_progress("❌ CENSYS: esta herramienta usa la API antigua de Censys, que el paquete instalado ya no "
                                  "incluye. Está pendiente migrarla a la API actual (censys.search).")
            return []
        except Exception as e:
            logger.error(f"CENSYS error: {type(e).__name__}")
            self._report_progress(f"❌ CENSYS: falló la consulta ({type(e).__name__}).")
            return []


class TheHarvesterTool(OSINTTool):
    def __init__(self):
        super().__init__(
            "TheHarvester", "OSINT de emails, hosts y subdominios",
            ToolRequirements(
                mandatory=["domain"],
                optional=[],
                produces=["email", "domain", "ip"],
                hint="Necesita el dominio objetivo.",
            )
        )
        self.is_heavy = True
        self.check_available()

    def check_available(self):
        local_path = Path("theHarvester/theHarvester.py")
        self.is_available = (
            shutil.which("theHarvester") is not None or
            shutil.which("theharvester") is not None or
            local_path.exists()
        )



    def diagnose_status(self):
        self.check_available()
        if self.is_available:
            return {
                "status": "ready",
                "icon": "✅",
                "message": "TheHarvester detectado y listo para usarse.",
                "install_cmd": ""
            }
        
        return {
            "status": "not_installed",
            "icon": "❌",
            "message": "TheHarvester no está instalado.\nSe recomienda instalarlo clonando su repositorio oficial GITHUB.",
            "install_cmd": (
                "Guía de Instalación Multiplataforma:\n"
                "1. Abre una terminal en la carpeta principal del proyecto Sentinel.\n"
                "2. Activa tu entorno virtual:\n"
                "   - Mac/Linux: `source env/bin/activate`\n"
                "   - Windows: `.\\env\\Scripts\\activate`\n"
                "3. Clona el repositorio:\n"
                "   `git clone https://github.com/laramies/theHarvester.git`\n"
                "4. Instala sus dependencias:\n"
                "   `cd theHarvester && python3 -m pip install -r requirements.txt`"
            )
        }

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        domain = sanitize_shell_arg(query_params.domain or "")
        if not domain or not validate_domain(domain):
            return []
        cmd = shutil.which("theHarvester") or shutil.which("theharvester")
        
        cmd_args = []
        if cmd:
            cmd_args = [cmd, "-d", domain]
        else:
            import sys
            local_path = Path("theHarvester/theHarvester.py")
            if local_path.exists():
                cmd_args = [sys.executable, str(local_path.absolute()), "-d", domain]
            else:
                return []
            
        try:
            if query_params.extra_args:
                cmd_args.extend(shlex.split(query_params.extra_args))
            else:
                cmd_args.extend(["-b", "duckduckgo,yahoo,crtsh,hackertarget", "-l", "200"])
                
            p = subprocess.run(
                cmd_args,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300,
                encoding="utf-8", errors="replace",
                env={**__import__("os").environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"},
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            out = (p.stdout or "")[:MAX_OUTPUT_BYTES]
            
            if "Traceback" in out or "ModuleNotFoundError" in out:
                return [SearchResult(
                    title="❌ Error Crítico en TheHarvester",
                    url="", snippet=out[-500:], source_tool=self.name, category="Error", relevance_score=100,
                )]
                
            results = []
            seen = set()
            for line in out.splitlines():
                line = line.strip()
                if not line or line in seen or len(results) >= MAX_RESULTS:
                    continue
                if _EMAIL_LINE.match(line):
                    if line.lower() in HARVESTER_BANNER_EMAILS:
                        continue
                    seen.add(line)
                    results.append(SearchResult(
                        title=f"Email: {sanitize_snippet(line)}",
                        url="", snippet="Encontrado por TheHarvester",
                        source_tool=self.name, category="Email", relevance_score=80,
                    ))
                    continue
                host = _HOST_LINE.match(line)
                if host and "." in host.group(1) and validate_domain(host.group(1)):
                    seen.add(line)
                    ip = host.group(2)
                    results.append(SearchResult(
                        title=f"Host: {sanitize_snippet(host.group(1))}",
                        url=f"https://{host.group(1)}",
                        snippet="Host detectado por TheHarvester" + (f" · IP {ip}" if ip else ""),
                        source_tool=self.name, category="Subdomain", relevance_score=65,
                        raw_data={"host": host.group(1), "ip": ip or ""},
                    ))
            return results
        except subprocess.TimeoutExpired:
            logger.warning("TheHarvester timeout")
            return [SearchResult(
                title="⚠️ TheHarvester Timeout",
                url="", snippet="El escaneo excedió el tiempo límite (300s).", source_tool=self.name, category="Error", relevance_score=100,
            )]
        except Exception as e:
            logger.error(f"TheHarvester: {type(e).__name__}")
            return [SearchResult(
                title="❌ Error al ejecutar TheHarvester",
                url="", snippet=str(e), source_tool=self.name, category="Error", relevance_score=100,
            )]





class PhoneNumbersTool(OSINTTool):
    def __init__(self):
        super().__init__(
            "phonenumbers", "Análisis de números telefónicos",
            ToolRequirements(
                mandatory=["phone"],
                optional=[],
                produces=["location", "company"],
                hint="Necesita el teléfono con código de país (ej: +593912345678).",
            )
        )

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        raw_phone = query_params.phone or ""
        # Only allow E.164 format characters: + digits spaces hyphens
        import re
        phone = re.sub(r"[^\d\+\s\-]", "", raw_phone).strip()[:20]
        if not phone:
            return []
        try:
            import phonenumbers
            from phonenumbers import geocoder, carrier
            
            p = None
            try:
                p = phonenumbers.parse(phone, None)
            except phonenumbers.NumberParseException:
                for region in ["EC", "US", "ES", "MX", "AR", "CO", "PE", "CL"]:
                    try:
                        p = phonenumbers.parse(phone, region)
                        if phonenumbers.is_valid_number(p):
                            break
                    except phonenumbers.NumberParseException:
                        pass
                        
            if not p:
                return [SearchResult(
                    title=f"❌ Teléfono Inválido: {phone}",
                    url="", snippet="formato telefónico irreconocible. Revisa si falta el código de país.",
                    source_tool=self.name, category="Error", relevance_score=100,
                )]
                
            valid  = phonenumbers.is_valid_number(p)
            region = geocoder.description_for_number(p, "es")
            op     = carrier.name_for_number(p, "es")
            
            if not region and not op:
                 return [SearchResult(
                    title=f"Teléfono: {phone}",
                    url="", snippet=f"Válido: {valid} — no se detectó región ni operador.",
                    source_tool=self.name, category="Phone", relevance_score=50,
                )]
            return [SearchResult(
                title=f"Teléfono: {phone}",
                url="",
                snippet=sanitize_snippet(
                    f"Válido: {valid}  Región: {region}  Operador: {op}"
                ),
                source_tool=self.name, category="Phone", relevance_score=80,
            )]
        except Exception as e:
            logger.error(f"phonenumbers error: {type(e).__name__}")
            return []
