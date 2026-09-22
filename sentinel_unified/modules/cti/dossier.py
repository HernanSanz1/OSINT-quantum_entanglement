#!/usr/bin/env python3
"""Build a deterministic dossier from harvested Altel CTI items."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from pathlib import Path
from zoneinfo import ZoneInfo

from clientes import boost_cliente, cliente_choices, get_cliente, match_tecnologias, preferred_specs
from exposicion_cve import build_exposure_matrix, extract_cvss
from fuentes import FUENTES
from seleccion_cliente import internal_client_selection

BASE_DIR = Path(__file__).resolve().parent
STORE = BASE_DIR / "store"
ITEMS = STORE / "items.jsonl"
ENRICH = STORE / "enriquecimiento.json"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
RANSOMWARE_LIVE_EC_URL = "https://api.ransomware.live/v2/countryvictims/EC"
LOCAL_TZ = ZoneInfo("America/Guayaquil")
PUBLIC_CVE_COUNT = 10
CVE_EDITORIAL = {
    "CVE-2024-55591": {
        "producto": "FortiOS y FortiProxy",
        "impacto": "EcuCERT la asocia con una campaña de Gunra ransomware contra dispositivos Fortinet. La explotación puede facilitar acceso administrativo no autorizado a firewalls o VPN expuestos; se debe actualizar FortiOS/FortiProxy, restringir administración remota y revisar cuentas sospechosas como forticloud-sync, accesos VPN desconocidos y transferencias inusuales de información.",
    },
    "CVE-2025-24472": {
        "producto": "FortiOS y FortiProxy",
        "impacto": "EcuCERT la asocia con una campaña de Gunra ransomware contra dispositivos Fortinet. La explotación puede facilitar acceso administrativo no autorizado a firewalls o VPN expuestos; se debe actualizar FortiOS/FortiProxy, restringir administración remota y revisar cuentas sospechosas como forticloud-sync, accesos VPN desconocidos y transferencias inusuales de información.",
    },
    "CVE-2026-59310": {
        "producto": "VMware vCenter Server",
        "impacto": "EcuCERT reporta explotación activa de una falla crítica de recorrido de directorios que puede permitir ejecución remota de código en VMware vCenter Server. Se recomienda aplicar la actualización del fabricante, retirar interfaces de administración de Internet y revisar telemetría desde el 3 de agosto por conexiones externas, tareas programadas o binarios no autorizados.",
    },
    "CVE-2026-46333": {
        "producto": "Siemens SIMATIC S7-1500 CPU 1518(F)-4 PN/DP MFP",
        "impacto": "La fuente reporta vulnerabilidades en el subsistema GNU/Linux incorporado en el firmware del equipo. En entornos industriales, este tipo de falla exige validar la versión instalada, revisar segmentación OT/IT y aplicar la actualización o mitigación indicada por Siemens para reducir riesgo sobre controladores expuestos.",
    },
    "CVE-2026-22184": {
        "producto": "Siemens CADRA",
        "impacto": "La alerta indica que Siemens CADRA se ve afectado por vulnerabilidades asociadas a componentes zlib y Foxit. La acción principal es actualizar a la versión corregida publicada por el fabricante y limitar la apertura de archivos de diseño o documentos no confiables en estaciones que utilicen esta herramienta.",
    },
    "CVE-2026-9198": {
        "producto": "IBM Langflow",
        "impacto": "La vulnerabilidad corresponde a inyección de código y puede permitir ejecución remota de código (RCE) en despliegues vulnerables. CISA la mantiene como vulnerabilidad explotada conocida, por lo que se debe actualizar Langflow, restringir exposición pública y revisar accesos o ejecuciones anómalas en la plataforma.",
    },
    "CVE-2026-63077": {
        "producto": "JetBrains TeamCity",
        "impacto": "La falla se relaciona con deserialización de datos no confiables y puede habilitar ejecución remota de código mediante el protocolo de consulta de agentes. Al afectar una plataforma de integración continua, se debe actualizar TeamCity, revisar agentes conectados, tokens de compilación y cambios recientes en pipelines.",
    },
    "CVE-2026-34486": {
        "producto": "Apache Tomcat",
        "impacto": "La vulnerabilidad permite evadir controles de cifrado de datos sensibles asociados a EncryptInterceptor. Las organizaciones que usen Tomcat deben aplicar la versión corregida, revisar configuraciones de conectores e identificar aplicaciones donde información sensible dependa de ese mecanismo.",
    },
    "CVE-2026-18577": {
        "producto": "N-able N-central",
        "impacto": "La falla corresponde a una omisión de autenticación mediante una ruta o canal alternativo y puede derivar en toma de cuentas en N-central. Por tratarse de una herramienta de monitoreo y administración remota (RMM), se debe aplicar el hotfix del fabricante, limitar acceso administrativo y revisar acciones realizadas sobre sistemas gestionados.",
    },
    "CVE-2026-8037": {
        "producto": "Progress Kemp LoadMaster",
        "impacto": "La vulnerabilidad es una inyección de comandos reportada con explotación activa e incluida en CISA KEV. En balanceadores o servicios expuestos a Internet, puede permitir ejecución de comandos; se debe aplicar el parche del fabricante, validar exposición pública y buscar intentos de explotación en registros del appliance.",
    },
    "CVE-2025-14847": {
        "producto": "ABB Ability Zenon",
        "impacto": "La fuente indica que la explotación puede permitir evadir controles, provocar caídas del sistema, ejecutar acciones no autorizadas o comprometer datos. En ambientes OT, se debe confirmar si existen servicios IIoT con MongoDB instalados sobre Zenon y aplicar las correcciones o mitigaciones publicadas por ABB.",
    },
    "CVE-2026-16812": {
        "producto": "Arista VeloCloud Orchestrator",
        "impacto": "La vulnerabilidad es una inyección de comandos en implementaciones locales de VeloCloud Orchestrator y la fuente reporta explotación activa. Se debe actualizar el componente afectado, restringir acceso administrativo desde Internet y revisar comandos o autenticaciones inusuales en el host.",
    },
    "CVE-2026-5121": {
        "producto": "Siemens SIDIS Secured SmartPlug",
        "impacto": "La alerta de Siemens describe múltiples vulnerabilidades en componentes incluidos en SIDIS Secured SmartPlug, entre ellos OpenSSL y OpenSSH. Siemens publicó una versión corregida; las organizaciones que usen este dispositivo deben actualizar a la versión indicada por el fabricante y verificar que la administración del equipo no esté expuesta a redes no confiables.",
    },
    "CVE-2026-17583": {
        "producto": "Thermo Fisher Applied Biosystems Genetic Analyzers",
        "impacto": "La vulnerabilidad puede permitir la modificación de archivos de salida .fsa o .hid, afectando la integridad de datos de análisis genético. La fuente oficial identifica modelos Applied Biosystems impactados; los laboratorios que utilicen estos equipos deben aplicar la actualización del proveedor y controlar la integridad de archivos generados.",
    },
    "CVE-2026-45659": {
        "producto": "Microsoft SharePoint",
        "impacto": "La vulnerabilidad corresponde a ejecución remota de código mediante deserialización de datos no confiables en escenarios autenticados. Las organizaciones con granjas SharePoint expuestas o integradas a procesos críticos deben aplicar la actualización de Microsoft y revisar eventos de carga o procesamiento de contenido anómalo.",
    },
    "CVE-2026-14227": {
        "producto": "MikroTik RouterOS",
        "impacto": "La fuente asocia la vulnerabilidad con MikroTik RouterOS, tecnología de red frecuentemente expuesta en borde o administración remota. Debe validarse la versión instalada, aplicar la corrección del fabricante y restringir la administración desde Internet o redes no confiables.",
    },
    "CVE-2026-16347": {
        "producto": "MikroTik RouterOS y Cloud Hosted Router",
        "impacto": "La vulnerabilidad afecta a plataformas MikroTik usadas como enrutadores o instancias virtuales de red. Las organizaciones deben actualizar RouterOS o Cloud Hosted Router según el advisory correspondiente, revisar exposición de servicios de administración y monitorear cambios no autorizados en configuración.",
    },
    "CVE-2026-65423": {
        "producto": "o6 Automation open62541",
        "impacto": "La vulnerabilidad afecta a open62541, implementación OPC UA usada en entornos industriales y de automatización. La acción principal es validar si el componente está integrado en sistemas OT, aplicar la actualización disponible y limitar comunicaciones OPC UA a segmentos autorizados.",
    },
    "CVE-2026-58048": {
        "producto": "cPanel y WHM",
        "impacto": "La vulnerabilidad permite que un usuario autenticado con acceso a una cuenta de hosting ejecute consultas SQL con privilegios elevados sobre MySQL o MariaDB. Los administradores de hosting deben aplicar el security release de cPanel, revisar cuentas con actividad anómala y auditar consultas administrativas recientes.",
    },
    "CVE-2026-58231": {
        "producto": "SAP Commerce Cloud Data Hub Adapter",
        "impacto": "SAP publicó correcciones para una falla crítica que puede permitir ejecución remota de código sin autenticación en SAP Commerce Cloud Data Hub Adapter. Se debe aplicar el parche del fabricante, revisar exposición del componente y auditar actividad anómala en integraciones de datos.",
    },
    "CVE-2026-68820": {
        "producto": "Windows Ancillary Function Driver for WinSock",
        "impacto": "Microsoft y CISA reportan explotación activa de esta vulnerabilidad de elevación de privilegios en Windows. Debe priorizarse en servidores y estaciones Windows porque puede facilitar escalamiento posterior a compromiso inicial; se recomienda aplicar Patch Tuesday de agosto y revisar actividad anómala asociada a herramientas de post-explotación.",
    },
    "CVE-2026-62893": {
        "producto": "Windows Deployment Services TFTP Server",
        "impacto": "La vulnerabilidad corresponde a ejecución remota de código en Windows Deployment Services TFTP Server. En entornos con PXE/WDS habilitado, el servicio puede convertirse en superficie de ataque por red; se debe aplicar la actualización de Microsoft o deshabilitar TFTP/WDS cuando no sea necesario.",
    },
    "CVE-2026-62823": {
        "producto": "Windows DHCP Server",
        "impacto": "La vulnerabilidad permite ejecución remota de código en Windows DHCP Server bajo condiciones de red. Por tratarse de infraestructura interna crítica, se debe aplicar la actualización de Microsoft, limitar exposición del servicio a segmentos autorizados y revisar eventos anómalos del rol DHCP.",
    },
    "CVE-2026-65400": {
        "producto": "macOS Screen Sharing",
        "impacto": "La fuente reporta explotación contra sistemas macOS con Screen Sharing expuesto a Internet. El riesgo es alto cuando VNC o servicios de administración remota están publicados; se debe actualizar macOS, deshabilitar Screen Sharing si no es requerido y restringir acceso mediante VPN o listas de control.",
    },
    "CVE-2026-71362": {
        "producto": "Adobe Commerce",
        "impacto": "SecurityWeek reportó intentos de explotación poco después de la divulgación y publicación de parches para Adobe Commerce. En plataformas de comercio electrónico, una explotación exitosa puede derivar en compromiso de aplicaciones, datos de clientes o integraciones de pago; se debe aplicar el parche del fabricante y revisar actividad anómala posterior a la publicación.",
    },
    "CVE-2026-15748": {
        "producto": "Forminator Forms para WordPress",
        "impacto": "La vulnerabilidad crítica en el plugin Forminator Forms puede permitir ejecución remota de código mediante carga maliciosa de PHP en sitios WordPress vulnerables. Se debe actualizar el plugin, revisar archivos cargados recientemente, validar cuentas administrativas y monitorear cambios no autorizados en el sitio.",
    },
    "CVE-2026-64561": {
        "producto": "KVM x86",
        "impacto": "La vulnerabilidad afecta lógica de KVM x86 asociada a virtualización. En hosts que ejecuten cargas virtualizadas, el riesgo se concentra en aislamiento de máquinas virtuales y estabilidad del hipervisor; se debe aplicar la actualización publicada por el proveedor y validar exposición de virtualización anidada o cargas no confiables.",
    },
    "CVE-2025-62593": {
        "producto": "Ray-Project Ray",
        "impacto": "CISA mantiene esta vulnerabilidad en KEV por explotación conocida; Ray-Project Ray contiene una inyección de código que puede permitir ejecución remota. Se recomienda actualizar el componente, restringir acceso a clústeres Ray y revisar jobs ejecutados fuera de procesos autorizados.",
    },
    "CVE-2026-16581": {
        "producto": "igloohome Smart Lock Mobile Application para Android",
        "impacto": "La vulnerabilidad puede permitir a un actor no autorizado acceder a funciones o servicios backend de la aplicación móvil. Las organizaciones que administren cerraduras inteligentes igloohome deben validar la versión de la aplicación, aplicar la actualización del proveedor y revisar accesos no esperados a servicios asociados.",
    },
    "CVE-2026-18411": {
        "producto": "Acrisure KARR BT y DR-100",
        "impacto": "La explotación podría permitir operaciones no autorizadas de control vehicular en firmware afectado. Los responsables de flotas o dispositivos conectados deben aplicar firmware igual o posterior a la versión corregida indicada por el fabricante y restringir interfaces de administración.",
    },
    "CVE-2026-11917": {
        "producto": "Rockwell Automation ThinManager",
        "impacto": "La falla permite a un atacante autenticado escribir archivos arbitrarios en directorios restringidos fuera de la ruta prevista por la aplicación. En entornos industriales que usen ThinManager, se debe actualizar a la versión corregida, restringir cuentas administrativas y revisar modificaciones recientes de archivos del servidor.",
    },
}

PESOS = {
    "kev_window": 100,
    "kev_old": 45,
    "epss_99": 60,
    "epss_95": 35,
    "epss_90": 15,
    "reported_exploit": 70,
    "ransomware": 35,
    "poc_text": 40,
    "poc_verified": 25,
    "perimeter": 25,
    "actor": 45,
    "supply_chain": 40,
    "campaign": 30,
    "data_leak": 30,
    "malware": 25,
    "phishing": 20,
    "ecuador": 50,
    "cross_source": 30,
    "marketing": -60,
    "admin": -1000,
}

KEYWORDS = {
    "reported_exploit": (
        "actively exploited",
        "exploited:yes",
        "exploitation detected",
        "zero-day",
        "zero day",
        "publicly disclosed:yes",
        "explotacion activa",
        "explotación activa",
        "explotada activamente",
    ),
    "ransomware": ("ransomware", "extortion", "extorsion"),
    "poc_text": ("proof-of-concept", "proof of concept", "poc", "exploit public"),
    "perimeter": ("vpn", "firewall", "fortinet", "palo alto", "citrix", "checkpoint", "check point", "ivanti", "f5", "cisco asa"),
    "actor": ("apt", "state-sponsored", "nation-state", "actor", "grupo", "atribuid"),
    "supply_chain": ("supply chain", "npm", "pypi", "plugin", "dependency", "cadena de suministro"),
    "campaign": ("campaign", "operation", "campana", "campaña"),
    "data_leak": ("data breach", "leak", "fuga", "brecha"),
    "malware": ("malware", "loader", "backdoor", "botnet", "c2", "trojan"),
    "phishing": ("phishing", "scam", "fraud", "suplantacion", "suplantación"),
    "marketing": ("now available", "webinar", "award", "partner", "store"),
    "admin": ("adds known exploited vulnerabilities to catalog", "cisa adds one known exploited", "cisa adds two known exploited", "cisa adds three known exploited", "cisa adds exploited", "cisa flags", "catalog update"),
}

GENERATION_DAY_CRITICAL_TERMS = (
    "zero-day",
    "zero day",
    "0-day",
    "actively exploited",
    "exploited:yes",
    "exploitation detected",
    "publicly disclosed:yes",
    "patch tuesday",
    "kev",
    "explotacion activa",
    "explotación activa",
    "divulgada públicamente",
)
CRITICAL_SEVERITY_TERMS = (
    "critical",
    "critica",
    "crítica",
    "critico",
    "crítico",
    "severidad critica",
    "severidad crítica",
    "critical severity",
    "maximum severity",
    "cvss 9",
    "cvss: 9",
    "cvss score: 9",
    "cvss 10",
    "cvss: 10",
    "cvss score: 10",
)
MATERIAL_EVENT_TERMS = (
    "actively exploited",
    "exploited:yes",
    "exploitation detected",
    "exploited in the wild",
    "explotacion activa",
    "explotación activa",
    "explotada activamente",
    "zero-day",
    "zero day",
    "0-day",
    "kev",
    "known exploited",
    "ransomware",
    "campaña",
    "campaign",
    "alerta urgente",
    "patch tuesday",
    "publicly disclosed:yes",
    "proof-of-concept",
    "proof of concept",
    "poc",
)

FAMILIAS = [
    ("Soluciones de Seguridad y Perímetro", ("check point", "checkpoint", "cisco", "firewall", "velocloud", "fortinet", "sonicwall", "vpn", "mikrotik", "n-able", "n-central")),
    ("Sistemas Industriales y Tecnología de Operaciones OT", ("siemens", "simatic", "abb", "johnson controls", "openblue", "opc", "ics", "scada", "plc")),
    ("Librerías, Frameworks de Desarrollo y CMS", ("fastjson", "rails", "ruby", "joomla", "wordpress", "plugin", "npm", "pypi", "gitea", "tomcat", "langflow")),
    ("Bases de Datos, ERP e Infraestructura Corporativa", ("vmware", "vcenter", "esx", "oracle", "sap", "sharepoint", "teamcity", "adobe campaign")),
    ("Sistemas Operativos y Kernel", ("linux", "kernel", "windows", "remote desktop", "rds", "centos")),
    ("Navegadores Web y Extensiones", ("firefox", "chrome", "browser", "tor browser", "extension", "edge")),
]

SECCIONES = {
    "amenaza_semana": 1,
    "seguridad_ecuador": 3,
    "noticias_principales": 5,
    "alrededor_mundo": 4,
}

ENVIRONMENT_RELEVANT_TERMS = (
    # Sistemas operativos y componentes base.
    "windows", "windows server", "microsoft internet key exchange", "ike", "macos",
    "linux", "kernel", "chrome", "firefox",
    # Servicios y aplicaciones autogestionadas plausibles.
    "wordpress", "forminator", "elementor", "gitlab", "zimbra", "trueconf", "sharepoint",
    "vmware", "vcenter", "esxi", "oracle http server", "weblogic",
    "citrix", "netscaler", "cisco", "broadworks", "siemens", "plc",
    "google workspace", "gmail", "google drive", "google cloud", "gcp",
    "microsoft 365", "office 365", "entra id", "azure active directory",
    "exchange online", "sharepoint online", "microsoft defender",
    # Tecnologias confirmadas o plausibles por inventarios de clientes.
    "fortinet", "fortigate", "fortios", "fortiproxy", "fortimanager", "fortiweb",
    "mikrotik", "routeros", "huawei", "nokia", "hpe simplivity", "veritas",
    "sql server", "mysql", "postgresql", "oracle database", "docker",
    "containerd", "apache tomcat", "wazuh", "manageengine", "endpoint central",
    "trend micro", "apex one", "deep security", "imperva", "radware",
)

PURE_SAAS_OR_NEWS_TERMS = (
    "teams phishing", "safePal",
    "hardware wallet", "web3", "firefox extensions", "azure data theft",
    "fortune 500", "data breach", "phishing", "malvertising", "ip cameras",
    "camera", "hotel wi-fi", "supply chain attack", "npm packages", "rust crate",
    "trojanized", "botnet", "banking trojans", "ransomware group names",
    "unisoc", "volte", "android kernel", "hardware wallet",
)

PREVIOUS_TOPIC_TERMS = (
    "windows ike", "internet key exchange", "cve-2026-33824",
    "sharepoint", "cve-2026-55040",
    "vcenter", "cve-2026-59310",
    "macos screen sharing", "cve-2026-65400",
    "forminator", "cve-2026-15748",
    "sap commerce", "cve-2026-58231",
    "adobe commerce", "cve-2026-71362",
    "microsoft defender", "cve-2026-69414",
    "winsock", "cve-2026-68820",
    "cpanel", "whm", "cve-2026-58048",
    "fortinet", "gunra", "cve-2024-55591", "cve-2025-24472",
    "windows deployment services", "windows dhcp server",
    "exploited microsoft, vmware, apple vulnerabilities",
    "microsoft, vmware, apple vulnerabilities",
)


def parse_iso(value: str) -> dt.datetime:
    if not value:
        return dt.datetime.now(dt.timezone.utc)
    value = value.replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError:
        parsed = dt.datetime.now(dt.timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def week_window(week: str | None) -> tuple[str, dt.datetime, dt.datetime]:
    if week:
        year, w = week.split("-W")
        start_date = dt.date.fromisocalendar(int(year), int(w), 1)
        start = dt.datetime.combine(start_date, dt.time.min, tzinfo=LOCAL_TZ).astimezone(dt.timezone.utc)
        end = (dt.datetime.combine(start_date, dt.time.min, tzinfo=LOCAL_TZ) + dt.timedelta(days=7)).astimezone(dt.timezone.utc)
        return f"{start_date.isocalendar().year}-W{start_date.isocalendar().week:02d}", start, end
    else:
        today_local = dt.datetime.now(LOCAL_TZ).date()
        report_week_start = today_local - dt.timedelta(days=today_local.weekday())
        start_date = report_week_start - dt.timedelta(days=7)
        start_local = dt.datetime.combine(start_date, dt.time.min, tzinfo=LOCAL_TZ)
        end_local = dt.datetime.combine(report_week_start, dt.time.min, tzinfo=LOCAL_TZ)
        return f"{report_week_start.isocalendar().year}-W{report_week_start.isocalendar().week:02d}", start_local.astimezone(dt.timezone.utc), end_local.astimezone(dt.timezone.utc)


def day_window(day: str) -> tuple[str, dt.datetime, dt.datetime]:
    parsed = dt.date.fromisoformat(day)
    start = dt.datetime.combine(parsed, dt.time.min, tzinfo=LOCAL_TZ).astimezone(dt.timezone.utc)
    end = (dt.datetime.combine(parsed, dt.time.min, tzinfo=LOCAL_TZ) + dt.timedelta(days=1)).astimezone(dt.timezone.utc)
    return parsed.isoformat(), start, end


def until_window(day: str) -> tuple[str, dt.datetime, dt.datetime]:
    parsed = dt.date.fromisoformat(day)
    start_date = parsed - dt.timedelta(days=6)
    start = dt.datetime.combine(start_date, dt.time.min, tzinfo=LOCAL_TZ).astimezone(dt.timezone.utc)
    end = dt.datetime.combine(parsed + dt.timedelta(days=1), dt.time.min, tzinfo=LOCAL_TZ).astimezone(dt.timezone.utc)
    return parsed.isoformat(), start, end


def normalize_legacy_ransomware_item(item: dict) -> dict:
    if item.get("fuente_id") != "ransomware_ec":
        return item
    normalized = dict(item)
    try:
        data = json.loads(normalized.get("resumen") or "{}")
    except Exception:
        data = {}
    claimed_url = data.get("post_url") or normalized.get("url") or ""
    source_url = normalized.get("fuente_referencia") or RANSOMWARE_LIVE_EC_URL
    if ".onion" in str(claimed_url).lower():
        normalized["url_reclamo_reservada"] = claimed_url
        normalized["url"] = source_url
    elif not str(normalized.get("url") or "").startswith(("http://", "https://")):
        normalized["url"] = source_url
    victim = normalized.pop("victima_nombre", None)
    if victim and "victima_reservada" not in normalized:
        normalized["victima_reservada"] = victim
    group = data.get("group_name") or data.get("group") or "grupo no identificado"
    group = str(group).strip()
    group = group[:1].upper() + group[1:] if group else "grupo no identificado"
    sector = data.get("activity") or data.get("sector") or "organizacion"
    normalized["titulo"] = f"Registro OSINT de ransomware en Ecuador: sector {sector}, grupo {group}"
    normalized["ransomware"] = True
    normalized["reclamo_ransomware"] = True
    normalized["fuente_referencia"] = source_url
    normalized["verificacion"] = normalized.get("verificacion") or "fuente_publica_osint"
    normalized.pop("requiere_verificacion", None)
    return normalized


def ransomware_has_actor(item: dict) -> bool:
    if item.get("fuente_id") != "ransomware_ec":
        return True
    text = f"{item.get('titulo','')} {item.get('resumen','')}".lower()
    if "grupo no identificado" in text or "group_name" not in text and '"group"' not in text:
        return False
    return True


def load_items() -> list[dict]:
    out = []
    if not ITEMS.exists():
        return out
    with ITEMS.open("r", encoding="utf-8") as fh:
        for line in fh:
            try:
                out.append(normalize_legacy_ransomware_item(json.loads(line)))
            except Exception:
                continue
    return out


def item_key(item: dict) -> str:
    if item.get("id"):
        return f"id:{item['id']}"
    if item.get("url"):
        return f"url:{item['url']}"
    if item.get("cve"):
        return f"cve:{item['cve']}"
    title = re.sub(r"\s+", " ", str(item.get("titulo") or "")).strip().lower()
    return f"title:{title}"


def section_items_from_dossier(dossier: dict) -> list[dict]:
    out = []
    for name, items in (dossier.get("secciones") or {}).items():
        if name == "referencias" or not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, dict):
                out.append(item)
                out.extend(ref for ref in item.get("fuentes", []) or [] if isinstance(ref, dict))
    return out


def previous_report_keys(period_id: str, start: dt.datetime | None = None, end: dt.datetime | None = None) -> set[str]:
    keys: set[str] = set()
    for path in STORE.glob("dossier-*.json"):
        if period_id in path.name:
            continue
        try:
            dossier = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if start and end:
            window = dossier.get("ventana") or {}
            try:
                other_start = parse_iso(window.get("inicio", ""))
                other_end = parse_iso(window.get("fin", ""))
            except Exception:
                other_start = other_end = None
            if other_start == start and other_end == end:
                continue
        for item in section_items_from_dossier(dossier):
            key = item_key(item)
            if key != "title:":
                keys.add(key)
    return keys


def previously_published_cves(period_id: str, start: dt.datetime | None = None, end: dt.datetime | None = None) -> set[str]:
    reports_dir = BASE_DIR.parent / "reports" / "cti-altel"
    target = re.sub(r"\D", "", period_id)
    prior_by_stamp: dict[str, list[Path]] = {}
    for path in reports_dir.glob("AltelThreatIntell_*.html"):
        match = re.search(r"AltelThreatIntell_(\d{8})", path.name)
        if not match:
            continue
        stamp = match.group(1)
        if target and stamp >= target:
            continue
        prior_by_stamp.setdefault(stamp, []).append(path)
    if not prior_by_stamp:
        return set()
    latest_stamp = sorted(prior_by_stamp)[-1]
    paths = prior_by_stamp[latest_stamp]
    base = reports_dir / f"AltelThreatIntell_{latest_stamp}.html"
    if base.exists():
        paths = [base]
    cves: set[str] = set()
    for path in paths:
        try:
            cves.update(c.upper() for c in CVE_RE.findall(path.read_text(encoding="utf-8")))
        except Exception:
            continue
    return cves


def dossier_cves_from_sections(dossier: dict) -> set[str]:
    cves = set()
    for item in section_items_from_dossier(dossier):
        cves.update(str(cve).upper() for cve in item.get("cves", []) or [])
        if item.get("cve"):
            cves.add(str(item["cve"]).upper())
    return cves


def load_enrich() -> dict:
    if not ENRICH.exists():
        return {"epss": {}, "poc_github": []}
    try:
        return json.loads(ENRICH.read_text(encoding="utf-8"))
    except Exception:
        return {"epss": {}, "poc_github": []}


def load_harvest_run() -> dict:
    path = STORE / "harvest-run.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def source_audit_refs() -> list[dict]:
    run = load_harvest_run()
    stats = run.get("sources", {}) if isinstance(run, dict) else {}
    out = []
    for fuente in FUENTES:
        source_stats = stats.get(fuente["id"], {})
        out.append({
            "fuente_id": fuente["id"],
            "fuente": fuente["nombre"],
            "url": fuente["url"],
            "leidos": source_stats.get("leidos", 0),
            "nuevos": source_stats.get("nuevos", 0),
        })
    return out


def public_reference_refs(items: list[dict]) -> list[dict]:
    out = []
    seen = set()
    for item in items:
        refs = item.get("fuentes") if isinstance(item.get("fuentes"), list) else [item]
        for ref in refs:
            url = str(ref.get("url") or "").strip()
            if not url or ".onion" in url.lower() or not url.startswith(("http://", "https://")):
                continue
            if url in seen:
                continue
            seen.add(url)
            if ref.get("fuente_id") == "cisa_kev" and "known_exploited_vulnerabilities.json" in url:
                url = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
            cves = ref.get("cves") or item.get("cves") or []
            title = str(ref.get("titulo") or item.get("titulo") or ref.get("fuente") or url)
            title = re.sub(r"^Boletín Threat Intelligence Ecuador 2026-08-17:\s*", "", title, flags=re.I)
            out.append({
                "fuente": ref.get("fuente") or item.get("fuente") or "",
                "titulo": title,
                "url": url,
                "cves": cves,
                "fecha": ref.get("fecha") or item.get("fecha"),
            })
            break
    return out


def is_generation_day_critical(item: dict, end: dt.datetime) -> bool:
    fecha = parse_iso(item.get("fecha", "")).astimezone(LOCAL_TZ)
    generation_date = end.astimezone(LOCAL_TZ).date()
    if fecha.date() != generation_date:
        return False
    if item.get("kev") or item.get("exploited") or item.get("publicly_disclosed"):
        return True
    text = text_of(item)
    return any(term in text for term in GENERATION_DAY_CRITICAL_TERMS)


def mark_generation_day_critical(item: dict) -> dict:
    marked = dict(item)
    marked["inclusion_dia_generacion_critica"] = True
    marked["motivo_inclusion_temporal"] = "alerta critica del dia de generacion validada contra fuente original"
    return marked


def merge_dedup(items: list[dict]) -> list[dict]:
    out = []
    seen = set()
    for item in items:
        key = item_key(item)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def client_targeted_audit(cliente: dict | None, items: list[dict]) -> dict:
    if not cliente:
        return {}
    searches = []
    matched_ids = set()
    for tecnologia in cliente.get("tecnologias", []):
        terms = [str(term).lower() for term in tecnologia.get("terms", ()) if str(term).strip()]
        matched = []
        for item in items:
            matches = match_tecnologias({"tecnologias": [tecnologia]}, item)
            if not matches:
                continue
            matched.append({
                "id": item.get("id"),
                "titulo": item.get("titulo"),
                "fecha": item.get("fecha"),
                "fuente": item.get("fuente"),
                "url": item.get("url"),
                "cves": item.get("cves", []),
            })
            matched_ids.add(item.get("id"))
        searches.append({
            "tecnologia": tecnologia.get("nombre"),
            "categoria": tecnologia.get("categoria"),
            "confirmado": tecnologia.get("confirmado", True),
            "consultas": [
                f"{tecnologia.get('nombre')} security advisory",
                f"{tecnologia.get('nombre')} CVE",
                f"{tecnologia.get('nombre')} zero-day",
                f"{tecnologia.get('nombre')} critical vulnerability",
                f"{tecnologia.get('nombre')} actively exploited",
                f"{tecnologia.get('nombre')} remote code execution",
                f"{tecnologia.get('nombre')} authentication bypass",
            ],
            "terminos": terms,
            "coincidencias": matched[:20],
            "total_coincidencias": len(matched),
        })
    return {
        "cliente": cliente.get("nombre"),
        "tecnologias_revisadas": len(cliente.get("tecnologias", [])),
        "busquedas_dirigidas": len(searches),
        "hallazgos_unicos": len(matched_ids),
        "busquedas": searches,
    }


def client_selection_spaces() -> int:
    return SECCIONES["amenaza_semana"] + SECCIONES["seguridad_ecuador"] + SECCIONES["noticias_principales"] + PUBLIC_CVE_COUNT + SECCIONES["alrededor_mundo"]


def internal_control_log(cliente: dict | None, start: dt.datetime, end: dt.datetime, weekly: list[dict], selected: list[dict], seleccion: dict) -> dict:
    selected_ids = {item.get("id") for item in selected if item.get("id")}
    discarded = []
    for item in weekly:
        if item.get("id") in selected_ids:
            continue
        reason = "menor prioridad frente a hallazgos seleccionados"
        if not item.get("reportable", True):
            reason = "no reportable por regla editorial"
        elif item.get("fuente_id") == "ransomware_ec" and not ransomware_has_actor(item):
            reason = "senal OSINT de ransomware sin actor verificable"
        discarded.append({
            "titulo": item.get("titulo"),
            "fecha": item.get("fecha"),
            "fuente": item.get("fuente"),
            "url": item.get("url"),
            "motivo": reason,
        })
    return {
        "fase": "CONTROL_AUTONOMO_CTI",
        "cliente": (cliente or {}).get("nombre"),
        "ventana_temporal": {
            "inicio": start.astimezone(LOCAL_TZ).isoformat(),
            "fin": (end.astimezone(LOCAL_TZ) - dt.timedelta(seconds=1)).isoformat(),
        },
        "fuentes_consultadas": [f["nombre"] for f in FUENTES],
        "hallazgos_candidatos_en_ventana": len(weekly),
        "hallazgos_seleccionados": len(selected),
        "hallazgos_descartados": len(discarded),
        "descartes_muestra": discarded[:50],
        "seleccion_cliente_estado": seleccion.get("estado") if seleccion else "",
        "mensaje_consola": seleccion.get("mensaje_consola", "") if seleccion else "",
        "estado_final": "APROBADO_PARA_RENDER_VALIDADO" if selected else "SIN_HALLAZGOS_PUBLICABLES",
    }


def cve_product(item: dict, cve: str) -> str:
    if cve.upper() in CVE_EDITORIAL:
        return CVE_EDITORIAL[cve.upper()]["producto"]
    text = f"{item.get('titulo','')} {item.get('resumen','')}".lower()
    if "zapscape" in text or "kvm" in text:
        return "Linux kernel KVM"
    vendor = str(item.get("vendor") or "").strip()
    product = str(item.get("product") or "").strip()
    if vendor or product:
        return " ".join(part for part in (vendor, product) if part)
    title = re.sub(rf"\b{re.escape(cve)}\b", "", item.get("titulo") or "", flags=re.I)
    title = re.sub(r"\s+", " ", title).strip(" -:|")
    return title[:140] or "producto afectado no especificado por la fuente"


def cve_impact(item: dict, cve: str) -> str:
    if cve.upper() in CVE_EDITORIAL:
        return CVE_EDITORIAL[cve.upper()]["impacto"]
    text_low = f"{item.get('titulo','')} {item.get('resumen','')}".lower()
    if "zapscape" in text_low or "kvm" in text_low:
        return (
            "La fuente describe una vulnerabilidad en Linux KVM asociada a virtualización anidada. "
            "Un atacante con privilegios dentro de una máquina virtual invitada L1 podría escapar del aislamiento y ejecutar código en el host; se debe validar exposición de virtualización anidada, aplicar el parche del kernel y limitar cargas no confiables."
        )
    text = re.sub(r"\s+", " ", str(item.get("resumen") or item.get("titulo") or "")).strip()
    text = re.sub(r"View CSAF Summary\s*", "", text, flags=re.I)
    text = re.sub(
        r"CVE-\d{4}-\d{4,7}",
        lambda match: match.group(0).upper() if match.group(0).upper() == cve.upper() else "una vulnerabilidad relacionada",
        text,
        flags=re.I,
    )
    if not text:
        return "La fuente no publica un detalle tecnico suficiente; se conserva por trazabilidad y priorizacion del dossier."
    sentences = re.split(r"(?<=[.!?])\s+", text)
    impact = " ".join(sentences[:2]).strip()
    if len(impact) > 420:
        impact = impact[:420].rsplit(" ", 1)[0] + "."
    return impact


def cvss_number(item: dict) -> float | None:
    score, _ = extract_cvss(item)
    if not score:
        return None
    try:
        return float(score)
    except ValueError:
        return None


def cve_identifier_year(cve: str) -> int:
    match = re.match(r"CVE-(\d{4})-", str(cve or "").upper())
    return int(match.group(1)) if match else 0


def public_cve_year_in_window(cve: str, item: dict) -> bool:
    year = cve_identifier_year(cve)
    item_year = parse_iso(item.get("fecha", "")).astimezone(LOCAL_TZ).year
    return bool(year and year >= item_year)


def has_critical_severity(item: dict) -> bool:
    text = " ".join(str(item.get(k, "")) for k in ("titulo", "resumen", "impacto", "severity", "fuente", "fuente_id")).lower()
    score = cvss_number(item)
    return bool((score is not None and score >= 9.0) or any(term in text for term in CRITICAL_SEVERITY_TERMS))


def has_material_event(item: dict) -> bool:
    text = " ".join(str(item.get(k, "")) for k in ("titulo", "resumen", "impacto", "status", "fuente", "fuente_id")).lower()
    labels = set(item.get("etiquetas", []))
    return bool(
        item.get("kev")
        or item.get("fuente_id") == "cisa_kev"
        or item.get("exploited")
        or item.get("publicly_disclosed")
        or item.get("inclusion_dia_generacion_critica")
        or labels & {"EXPLOTADO ACTIVAMENTE", "ZERO-DAY DIVULGADO", "EXPLOTACION REPORTADA", "RANSOMWARE", "PoC PUBLICO"}
        or any(term in text for term in MATERIAL_EVENT_TERMS)
    )


def current_critical_cve(item: dict, cve: str) -> bool:
    """A CVE is publishable only when the current item is material and critical.

    The CVE identifier year is not the control. A prior-year CVE can be used
    only if the source item itself represents a new material event in the
    authorized window, such as active exploitation, KEV inclusion, ransomware
    use, urgent advisory or Patch Tuesday correction.
    """
    if cve.upper() not in {c.upper() for c in item.get("cves", [])}:
        return False
    critical = has_critical_severity(item)
    emergency_without_score = cvss_number(item) is None and has_material_event(item)
    return has_material_event(item) and (critical or emergency_without_score)


def current_material_campaign(item: dict) -> bool:
    text = f"{item.get('titulo','')} {item.get('resumen','')} {item.get('impacto','')}".lower()
    return bool(
        has_material_event(item)
        and has_critical_severity(item)
        and has_any(text, KEYWORDS["campaign"] + KEYWORDS["ransomware"] + KEYWORDS["perimeter"])
    )


def build_cve_priorities(items: list[dict], count: int = 6) -> list[dict]:
    grouped: dict[str, list[dict]] = {}
    for item in items:
        text = f"{item.get('titulo','')} {item.get('resumen','')}".lower()
        if "#stopransomware" in text or "ransomware-as-a-service" in text:
            continue
        for cve in item.get("cves", []):
            if not current_critical_cve(item, cve):
                continue
            grouped.setdefault(cve.upper(), []).append(item)
    out = []
    for cve, refs in grouped.items():
        refs = sorted(refs, key=lambda x: (x.get("score", 0), x.get("fecha", "")), reverse=True)
        top = refs[0]
        producto = cve_product(top, cve)
        out.append({
            "tipo": "cve",
            "cve": cve,
            "cves": [cve],
            "producto": producto,
            "impacto": cve_impact(top, cve),
            "score": top.get("score", 0) + (len({r.get("fuente_id") for r in refs}) - 1) * PESOS["cross_source"],
            "titulo": f"{cve} - {producto}",
            "fuentes": refs[:5],
            "etiquetas": top.get("etiquetas", []),
            "cliente_matches": top.get("cliente_matches", []),
        })
    out.sort(key=lambda x: (x["score"], x["cve"]), reverse=True)
    selected = []
    used_products = set()
    for item in out:
        product_key = re.sub(r"[^a-z0-9]+", " ", item["producto"].lower()).strip()
        if product_key in used_products:
            continue
        selected.append(item)
        used_products.add(product_key)
        if len(selected) >= count:
            return selected
    seen = {item["cve"] for item in selected}
    for item in out:
        if item["cve"] in seen:
            continue
        selected.append(item)
        seen.add(item["cve"])
        if len(selected) >= count:
            break
    return selected


def has_any(text: str, keys: tuple[str, ...]) -> bool:
    low = text.lower()
    return any(k in low for k in keys)


def is_admin_notice(item: dict) -> bool:
    text = f"{item.get('titulo','')} {item.get('resumen','')}".lower()
    if has_any(text, KEYWORDS["admin"]):
        return True
    return any(term in text for term in (
        "in other news:",
        "pleads guilty",
        "charged with",
        "sentenced to",
        "slipped under the radar",
    ))


def score_item(item: dict, start: dt.datetime, end: dt.datetime, enrich: dict, sources_by_cve: dict[str, set[str]]) -> dict:
    text = f"{item.get('titulo','')} {item.get('resumen','')}"
    cves = [c.upper() for c in item.get("cves", [])]
    etiquetas = []
    score = 0
    fecha = parse_iso(item.get("fecha", ""))

    if item.get("kev"):
        added = parse_iso(item.get("kev_date_added") or item.get("fecha"))
        score += PESOS["kev_window"] if start <= added < end else PESOS["kev_old"]
        etiquetas.append("EXPLOTADO ACTIVAMENTE")
    if item.get("exploited"):
        score += PESOS["reported_exploit"]
        etiquetas.append("EXPLOTADO ACTIVAMENTE")
    if item.get("publicly_disclosed"):
        score += PESOS["reported_exploit"] // 2
        etiquetas.append("ZERO-DAY DIVULGADO")
    if item.get("ransomware") or has_any(text, KEYWORDS["ransomware"]):
        score += PESOS["ransomware"]
        etiquetas.append("RANSOMWARE")
    if item.get("region") == "ec" or "ecuador" in text.lower():
        score += PESOS["ecuador"]
        etiquetas.append("RELEVANCIA ECUADOR")

    epss = enrich.get("epss", {})
    poc = set(enrich.get("poc_github", []))
    for cve in cves:
        pct = float(epss.get(cve, {}).get("percentile", 0))
        if pct >= 0.99:
            score += PESOS["epss_99"]
            etiquetas.append("EPSS CRITICO")
        elif pct >= 0.95:
            score += PESOS["epss_95"]
            etiquetas.append("EPSS ALTO")
        elif pct >= 0.90:
            score += PESOS["epss_90"]
        if cve in poc:
            score += PESOS["poc_verified"]
            etiquetas.append("PoC PUBLICO")
        if len(sources_by_cve.get(cve, set())) > 1:
            score += PESOS["cross_source"] * (len(sources_by_cve[cve]) - 1)
            etiquetas.append("CORROBORACION CRUZADA")

    for key, label in [
        ("reported_exploit", "EXPLOTACION REPORTADA"),
        ("poc_text", "PoC PUBLICO"),
        ("perimeter", "PERIMETRO / INFRA CRITICA"),
        ("actor", "ACTOR ATRIBUIDO"),
        ("supply_chain", "CADENA DE SUMINISTRO"),
        ("campaign", "CAMPANA ACTIVA"),
        ("data_leak", "FUGA DE DATOS"),
        ("malware", "MALWARE"),
        ("phishing", "FRAUDE / PHISHING"),
    ]:
        if has_any(text, KEYWORDS[key]):
            score += PESOS[key]
            etiquetas.append(label)
    if has_any(text, KEYWORDS["marketing"]):
        score += PESOS["marketing"]
    if has_any(text, KEYWORDS["admin"]):
        score += PESOS["admin"]

    score = round(score * float(item.get("peso_fuente", 1.0)), 2)
    result = dict(item)
    result["score"] = score
    result["etiquetas"] = sorted(set(etiquetas))
    result["en_ventana"] = start <= fecha < end
    cves_criticas_actuales = [cve for cve in cves if current_critical_cve(result, cve)]
    if cves:
        result["cves_criticas_actuales"] = cves_criticas_actuales
    result["reportable"] = (
        not is_admin_notice(result)
        and not result.get("requiere_verificacion")
        and (not cves or bool(cves_criticas_actuales) or current_material_campaign(result))
    )
    return result


def choose(items: list[dict], count: int, used: set[str], predicate=lambda x: True) -> list[dict]:
    chosen = []
    for item in sorted(items, key=lambda x: (bool(x.get("cves")), x["score"], x.get("fecha", "")), reverse=True):
        if item["id"] in used or not item.get("reportable", True) or not predicate(item):
            continue
        chosen.append(item)
        used.add(item["id"])
        if len(chosen) >= count:
            break
    return chosen


def text_of(item: dict) -> str:
    return f"{item.get('titulo','')} {item.get('resumen','')} {item.get('url','')}".lower()


def find_by_terms(items: list[dict], terms: tuple[str, ...], used: set[str], predicate=lambda x: True) -> dict | None:
    wanted = [term.lower() for term in terms]
    for item in sorted(items, key=lambda x: (bool(x.get("cves")), x.get("score", 0), x.get("fecha", "")), reverse=True):
        if item["id"] in used or not item.get("reportable", True) or not predicate(item):
            continue
        text = text_of(item)
        if all(term in text for term in wanted):
            used.add(item["id"])
            return item
    return None


def choose_preferred(items: list[dict], specs: list[tuple[str, ...]], count: int, used: set[str], predicate=lambda x: True) -> list[dict]:
    chosen = []
    for terms in specs:
        item = find_by_terms(items, terms, used, predicate)
        if item:
            chosen.append(item)
        if len(chosen) >= count:
            return chosen
    if len(chosen) < count:
        chosen.extend(choose(items, count - len(chosen), used, predicate))
    return chosen


def narrative_source(item: dict) -> bool:
    return item.get("fuente_id") not in {"cisa_kev", "cisa_advisories", "cisa_ics"}


def public_news_source(item: dict) -> bool:
    return narrative_source(item) and item.get("fuente_id") != "ransomware_ec"


def local_ecuador_source(item: dict) -> bool:
    text = text_of(item)
    if item.get("fuente_id") == "ransomware_ec" and not ransomware_has_actor(item):
        return False
    return (
        item.get("region") == "ec"
        or item.get("fuente_id") in {"ecucert", "csirt_telconet", "ransomware_ec"}
        or "ecuador" in text
    )


def force_local_ecuador_item(items: list[dict], used: set[str], prior: list[dict]) -> list[dict]:
    candidates = [
        item for item in items
        if item.get("reportable", True)
        and local_ecuador_source(item)
        and item["id"] not in used
    ]
    if not candidates:
        return []
    seen_cves = set().union(*(cve_set(item) for item in prior)) if prior else set()
    seen_topics = {topic_key(item) for item in prior}
    ordered = sorted(candidates, key=threat_rank, reverse=True)
    for item in ordered:
        cves = cve_set(item)
        topic = topic_key(item)
        if cves and cves & seen_cves:
            continue
        if topic and topic in seen_topics:
            continue
        used.add(item["id"])
        return [item]
    chosen = ordered[0]
    used.add(chosen["id"])
    return [chosen]


def threat_rank(item: dict) -> tuple:
    text = f"{item.get('titulo','')} {item.get('resumen','')}".lower()
    preferred_source = item.get("fuente_id") in {"csirt_telconet", "ecucert", "thehackernews", "bleepingcomputer"}
    perimeter = any(key in text for key in KEYWORDS["perimeter"])
    active_exploited = "EXPLOTADO ACTIVAMENTE" in item.get("etiquetas", [])
    zero_day = item.get("inclusion_dia_generacion_critica") or "ZERO-DAY DIVULGADO" in item.get("etiquetas", [])
    exploited = any(label in item.get("etiquetas", []) for label in ("EXPLOTACION REPORTADA", "EPSS CRITICO"))
    concise = len(item.get("cves", [])) <= 5
    return (active_exploited, zero_day, exploited, perimeter, preferred_source, concise, item.get("score", 0), item.get("fecha", ""))


def used_has_topic(items: list[dict], topic: str) -> bool:
    topic = topic.lower()
    return any(topic in text_of(item) for item in items)


def cve_set(item: dict) -> set[str]:
    return {str(cve).upper() for cve in item.get("cves", [])}


def cve_overlap(item: dict, items: list[dict]) -> bool:
    cves = cve_set(item)
    return bool(cves and any(cves & cve_set(existing) for existing in items))


def portfolio_relevant(item: dict) -> bool:
    text = text_of(item)
    if any(term.lower() in text for term in PURE_SAAS_OR_NEWS_TERMS):
        if not any(os_term in text for os_term in ("windows", "macos", "linux", "chrome", "firefox")):
            return False
    if item.get("cliente_matches"):
        return True
    return any(term in text for term in ENVIRONMENT_RELEVANT_TERMS)


def critical_environment_vulnerability(item: dict) -> bool:
    """Public CTI gate: critical CVE plus realistic customer applicability.

    The bulletin must not be filled with SaaS incidents, breach stories or rare
    products merely because they are in KEV. It should surface operating-system
    issues, WordPress/plugins, inventory technologies, or self-managed services
    that plausibly require customer review.
    """
    cves = [str(cve).upper() for cve in item.get("cves", [])]
    if not portfolio_relevant(item):
        return False
    text = text_of(item)
    if not cves:
        return bool(
            any(term in text for term in (
                "critical", "crítica", "critica", "actively exploited", "explotada",
                "active threat", "amenaza activa", "ransomware", "remote code execution",
                "authentication bypass", "omisión de autenticación", "command injection",
                "path traversal", "cvss 10", "cvss 9",
            ))
            and any(term in text for term in ENVIRONMENT_RELEVANT_TERMS)
        )
    if any(current_critical_cve(item, cve) for cve in cves):
        return True
    labels = set(item.get("etiquetas", []))
    return bool(labels & {"EXPLOTADO ACTIVAMENTE", "EXPLOTACION REPORTADA", "EPSS CRITICO", "PoC PUBLICO"})


def remove_previously_reported_cves(item: dict, previous_cves: set[str]) -> dict | None:
    text = text_of(item)
    cves = [str(cve).upper() for cve in item.get("cves", []) or []]
    has_new_cve = bool(cves and any(cve not in previous_cves for cve in cves))
    if not has_new_cve and any(term in text for term in PREVIOUS_TOPIC_TERMS):
        return None
    if cves and all(cve in previous_cves for cve in cves):
        return None
    out = dict(item)
    if cves:
        out["cves"] = [cve for cve in cves if cve not in previous_cves]
        out["cves_criticas_actuales"] = [
            cve for cve in out.get("cves_criticas_actuales", []) if str(cve).upper() not in previous_cves
        ]
    return out


def prune_cve_duplicates(items: list[dict], prior: list[dict], used: set[str]) -> list[dict]:
    out = []
    seen = set().union(*(cve_set(item) for item in prior)) if prior else set()
    for item in items:
        cves = cve_set(item)
        if cves and cves & seen:
            used.discard(item["id"])
            continue
        out.append(item)
        seen |= cves
    return out


def prune_topic_duplicates(items: list[dict], prior: list[dict], used: set[str]) -> list[dict]:
    out = []
    seen = {topic_key(item) for item in prior}
    for item in items:
        topic = topic_key(item)
        if topic and topic in seen:
            used.discard(item["id"])
            continue
        out.append(item)
        if topic:
            seen.add(topic)
    return out


def choose_without_cve_overlap(
    items: list[dict],
    count: int,
    used: set[str],
    prior: list[dict],
    predicate=lambda x: True,
) -> list[dict]:
    chosen = []
    seen = set().union(*(cve_set(item) for item in prior)) if prior else set()
    seen_topics = {topic_key(item) for item in prior}
    for item in sorted(items, key=lambda x: (bool(x.get("cves")), x["score"], x.get("fecha", "")), reverse=True):
        cves = cve_set(item)
        if item["id"] in used or not item.get("reportable", True) or not predicate(item):
            continue
        if cves and cves & seen:
            continue
        topic = topic_key(item)
        if topic and topic in seen_topics:
            continue
        chosen.append(item)
        used.add(item["id"])
        seen |= cves
        if topic:
            seen_topics.add(topic)
        if len(chosen) >= count:
            break
    return chosen


def topic_key(item: dict) -> str:
    text = text_of(item)
    for key, terms in [
        ("zimbra", ("zimbra",)),
        ("trueconf", ("trueconf",)),
        ("gitlab", ("gitlab",)),
        ("elementor", ("elementor",)),
        ("oracle-weblogic", ("oracle http server", "weblogic")),
        ("netscaler", ("netscaler", "citrix adc", "citrix gateway")),
        ("siemens-s7", ("siemens s7", "plc")),
        ("cisco-crosswork", ("crosswork", "secure workload")),
        ("windows-task-host", ("windows task host",)),
        ("chrome", ("chrome", "webgl", "dawn")),
        ("windchill", ("windchill", "flexplm")),
    ]:
        if any(term in text for term in terms):
            return key
    cves = sorted(cve_set(item))
    if cves:
        return cves[0]
    words = re.findall(r"[a-z0-9]{4,}", text)
    return "-".join(words[:3])


def build(week: str | None = None, day: str | None = None, until: str | None = None, cliente: str | None = None) -> dict:
    cliente_profile = get_cliente(cliente)
    if cliente and not cliente_profile:
        raise SystemExit(f"Cliente no soportado: {cliente}. Opciones: {cliente_choices()}")
    if until:
        period_id, start, end = until_window(until)
        period_type = "corte"
    elif day:
        period_id, start, end = day_window(day)
        period_type = "diario"
    else:
        period_id, start, end = week_window(week)
        period_type = "semanal"
    raw = load_items()
    enrich = load_enrich()
    sources_by_cve: dict[str, set[str]] = {}
    for item in raw:
        for cve in item.get("cves", []):
            sources_by_cve.setdefault(cve.upper(), set()).add(item.get("fuente_id", ""))
    scored = [score_item(item, start, end, enrich, sources_by_cve) for item in raw]
    if cliente_profile:
        scored = [boost_cliente(item, cliente_profile) for item in scored]
    previous_keys = previous_report_keys(period_id, start, end)
    # El boletin usa publicaciones originales dentro de los siete dias calendario
    # anteriores completos. Para el boletin generado en el dia actual se permite
    # una excepcion cerrada: alertas criticas del dia de generacion, como zero-days
    # o explotacion activa confirmada por fuente oficial.
    base_weekly = [
        x for x in scored
        if start <= parse_iso(x.get("fecha", "")) < end
        and item_key(x) not in previous_keys
    ]
    allow_generation_day_critical = period_type == "semanal" and not week
    generation_day_critical = [
        mark_generation_day_critical(x) for x in scored
        if allow_generation_day_critical
        and is_generation_day_critical(x, end)
        and item_key(x) not in previous_keys
    ]
    weekly = merge_dedup(base_weekly + generation_day_critical)
    exact_window = merge_dedup(
        [x for x in scored if start <= parse_iso(x.get("fecha", "")) < end]
        + generation_day_critical
    )
    cliente_audit = client_targeted_audit(cliente_profile, weekly)
    seleccion_interna = (
        internal_client_selection(cliente_profile, weekly, weekly, client_selection_spaces())
        if cliente_profile else {}
    )
    if seleccion_interna:
        ventana_temporal = {
            "inicio": start.astimezone(LOCAL_TZ).date().isoformat(),
            "fin": (end.astimezone(LOCAL_TZ).date() - dt.timedelta(days=1)).isoformat(),
        }
        seleccion_interna = {
            "cliente": seleccion_interna.get("cliente"),
            "ventana_temporal": ventana_temporal,
            "estado": seleccion_interna.get("estado"),
            "cantidad_hallazgos_directos": seleccion_interna.get("cantidad_hallazgos_directos", 0),
            "cantidad_hallazgos_generales_utilizados": seleccion_interna.get("cantidad_hallazgos_generales_utilizados", 0),
            "mensaje_consola": seleccion_interna.get("mensaje_consola", ""),
            "hallazgos_seleccionados": seleccion_interna.get("hallazgos_seleccionados", []),
        }
    used: set[str] = set()
    previous_cves = previously_published_cves(period_id, start, end)
    weekly_public = []
    for item in weekly:
        if not critical_environment_vulnerability(item):
            continue
        filtered = remove_previously_reported_cves(item, previous_cves)
        if filtered:
            weekly_public.append(filtered)

    threat_candidates = [
        x for x in weekly_public
        if x.get("reportable", True)
        and narrative_source(x)
        and len(x.get("cves", [])) <= 5
        and any(t in x.get("etiquetas", []) for t in ("EXPLOTADO ACTIVAMENTE", "EXPLOTACION REPORTADA", "EPSS CRITICO", "PERIMETRO / INFRA CRITICA"))
    ]
    client_specs = preferred_specs(cliente_profile)
    if until:
        amenaza = choose_preferred(threat_candidates, client_specs + [
            ("trueconf",),
            ("n-able", "n-central"),
            ("langflow", "tomcat", "n-central"),
            ("secure firewall management center",),
            ("velocloud",),
        ], 1, used)
    else:
        amenaza = sorted(threat_candidates, key=threat_rank, reverse=True)[:1]
        used.update(x["id"] for x in amenaza)
    ecuador = force_local_ecuador_item(weekly_public, used, amenaza)
    ecuador += choose_preferred(weekly_public, [
        ("qilin",),
        ("joomla", "defacement"),
        ("wallstreet",),
    ], 3 - len(ecuador), used, local_ecuador_source)
    ecuador = prune_cve_duplicates(ecuador, amenaza, used)
    if len(ecuador) < 3:
        ecuador += choose_without_cve_overlap(weekly_public, 3 - len(ecuador), used, amenaza + ecuador, local_ecuador_source)
    if not ecuador:
        ecuador = force_local_ecuador_item(exact_window, used, amenaza)
    noticias = choose_preferred(weekly_public, client_specs + [
        ("secure firewall management center", "zero-day"),
        ("velocloud",),
        ("cisco secure firewall management center",),
        ("debug", "chalk", "npm"),
        ("macos", "malvertising"),
        ("secure firewall management center",),
    ], 5, used, public_news_source)
    noticias = prune_cve_duplicates(noticias, amenaza + ecuador, used)
    noticias = prune_topic_duplicates(noticias, amenaza + ecuador, used)
    if len(noticias) < 5:
        noticias += choose_without_cve_overlap(weekly_public, 5 - len(noticias), used, amenaza + ecuador + noticias, public_news_source)
    mundo = choose_preferred(weekly_public, client_specs + [
        ("hotel wi-fi",),
        ("sonicwall", "inc ransomware"),
        ("18 malicious npm",),
        ("advanced responsive video embedder",),
    ], 4, used, lambda x: public_news_source(x) and x.get("region") != "ec" and not (used_has_topic(amenaza + noticias, "quickfox") and "quickfox" in text_of(x)) and any(t in x.get("etiquetas", []) for t in ("ACTOR ATRIBUIDO", "CAMPANA ACTIVA", "FRAUDE / PHISHING", "MALWARE", "FUGA DE DATOS", "CADENA DE SUMINISTRO", "RANSOMWARE")))
    mundo = prune_cve_duplicates(mundo, amenaza + ecuador + noticias, used)
    mundo = prune_topic_duplicates(mundo, amenaza + ecuador + noticias, used)
    if len(mundo) < 4:
        mundo += choose_without_cve_overlap(weekly_public, 4 - len(mundo), used, amenaza + ecuador + noticias + mundo, lambda x: public_news_source(x) and not (used_has_topic(amenaza + noticias + mundo, "quickfox") and "quickfox" in text_of(x)))
        mundo = prune_topic_duplicates(mundo, amenaza + ecuador + noticias, used)

    cve_items = [x for x in weekly_public if x.get("cves") and x.get("reportable", True)]
    principales_cves = build_cve_priorities(cve_items, PUBLIC_CVE_COUNT)
    selected_public = amenaza + ecuador + noticias + principales_cves[:PUBLIC_CVE_COUNT] + mundo
    exposicion_cve = build_exposure_matrix(cliente_profile, selected_public)

    brechas = []
    for name, expected, got in [
        ("Amenaza de la Semana", 1, len(amenaza)),
        ("Seguridad Ecuador", 3, len(ecuador)),
        ("Noticias Principales", 5, len(noticias)),
        ("Alrededor del Mundo", 4, len(mundo)),
    ]:
        if got < expected:
            brechas.append(f"{name}: {got}/{expected} candidatos.")

    dossier = {
        "marca": "Altel",
        "tipo": "Boletin de Threat Intelligence",
        "tipo_periodo": period_type,
        "semana": period_id,
        "ventana": {"inicio": start.isoformat(), "fin": end.isoformat()},
        "regla_temporal": {
            "zona_horaria": "America/Guayaquil",
            "inicio_inclusivo": start.astimezone(LOCAL_TZ).isoformat(),
            "fin_exclusivo": end.astimezone(LOCAL_TZ).isoformat(),
            "descripcion": "siete dias calendario inmediatamente anteriores completos a la fecha de generacion",
            "excepcion_dia_generacion": "solo alertas criticas/zero-day/explotacion activa publicadas el dia de generacion y validadas contra fuente original",
        },
        "criterio_editorial": {
            "puerta_aplicabilidad_entorno": True,
            "descripcion": (
                "Publicar solo CVE criticas/materiales con aplicabilidad real a entornos de clientes: "
                "sistemas operativos, WordPress/plugins, tecnologias de inventario, on-premise/autogestionado plausible "
                "o servicio critico. Excluir SaaS/cloud puro, noticias generales y CVE ya publicadas sin novedad material."
            ),
            "excluye_cves_previamente_publicadas": True,
        },
        "generado": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "cliente": cliente_profile,
        "busqueda_cliente": cliente_audit,
        "seleccion_interna_cliente": seleccion_interna,
        "control_autonomo": internal_control_log(cliente_profile, start, end, weekly, selected_public, seleccion_interna),
        "exposicion_cve": exposicion_cve,
        "totales": {
            "items_store": len(raw),
            "items_semana": len(weekly),
            "items_ventana": len(exact_window),
            "items_dia_generacion_criticos": len(generation_day_critical),
            "hallazgos": len([x for x in exact_window if x.get("reportable", True)]),
            "explotados": len([x for x in exact_window if "EXPLOTADO ACTIVAMENTE" in x.get("etiquetas", []) or "EXPLOTACION REPORTADA" in x.get("etiquetas", [])]),
            "cves_semana": sum(len(x.get("cves", [])) for x in principales_cves[:PUBLIC_CVE_COUNT]),
            "cves_previas_excluidas": len(previous_cves),
        },
        "secciones": {
            "amenaza_semana": amenaza,
            "seguridad_ecuador": ecuador,
            "noticias_principales": noticias,
            "principales_cves": principales_cves[:PUBLIC_CVE_COUNT],
            "alrededor_mundo": mundo,
            "referencias": public_reference_refs(amenaza + ecuador + noticias + principales_cves[:PUBLIC_CVE_COUNT] + mundo),
        },
        "brechas": brechas,
    }
    suffix = f"-{cliente_profile['nombre']}" if cliente_profile else ""
    out = STORE / f"dossier-{period_id}{suffix}.json"
    out.write_text(json.dumps(dossier, ensure_ascii=False, indent=2), encoding="utf-8")
    return dossier


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--semana")
    ap.add_argument("--fecha", help="Fecha diaria en formato YYYY-MM-DD")
    ap.add_argument("--hasta", help="Corte semanal terminado en YYYY-MM-DD; cubre seis dias previos mas ese dia")
    ap.add_argument("--cliente", help=f"Genera un dossier priorizado por cliente: {cliente_choices()}")
    ap.add_argument("--resumen", action="store_true")
    args = ap.parse_args()
    if sum(bool(x) for x in (args.semana, args.fecha, args.hasta)) > 1:
        raise SystemExit("Use solo uno de --semana, --fecha o --hasta.")
    dossier = build(args.semana, args.fecha, args.hasta, args.cliente)
    if args.resumen:
        print(json.dumps({
            "semana": dossier["semana"],
            "totales": dossier["totales"],
            "secciones": {k: len(v) for k, v in dossier["secciones"].items()},
            "brechas": dossier["brechas"],
        }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
