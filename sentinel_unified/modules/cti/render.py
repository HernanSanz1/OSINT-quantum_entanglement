#!/usr/bin/env python3
"""Render the Altel CTI dossier as an Altel-style HTML bulletin."""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import re
import urllib.error
import urllib.request
from pathlib import Path

from exposicion_cve import extract_cvss, severity_from_cvss

BASE_DIR = Path(__file__).resolve().parent
STORE = BASE_DIR / "store"
REPORTS = BASE_DIR.parent / "reports" / "cti-altel"
CVSS_CACHE = STORE / "cvss-v3-cache.json"


def esc(value) -> str:
    return html.escape(str(value or ""), quote=True)


def load_cvss_cache() -> dict:
    if not CVSS_CACHE.exists():
        return {}
    try:
        return json.loads(CVSS_CACHE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_cvss_cache(cache: dict) -> None:
    try:
        CVSS_CACHE.write_text(json.dumps(cache, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    except Exception:
        return


CVSS_V3_CACHE = load_cvss_cache()


def fmt_date(value: str) -> str:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.strftime("%d/%m/%Y")
    except Exception:
        return ""


def fmt_week(value: str) -> str:
    months = [
        "enero", "febrero", "marzo", "abril", "mayo", "junio",
        "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre",
    ]
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return f"{parsed.day} de {months[parsed.month - 1].capitalize()}, {parsed.year}"
    except Exception:
        return ""


def fmt_spanish_date(day: dt.date) -> str:
    months = [
        "enero", "febrero", "marzo", "abril", "mayo", "junio",
        "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre",
    ]
    return f"{day.day} de {months[day.month - 1].capitalize()}, {day.year}"


def period_label(dossier: dict) -> str:
    if dossier.get("tipo_periodo") == "diario":
        label = fmt_week(dossier["ventana"]["inicio"])
        return f"Informe del {label}"
    if dossier.get("tipo_periodo") == "corte":
        try:
            end = dt.datetime.fromisoformat(dossier["ventana"]["fin"].replace("Z", "+00:00")) - dt.timedelta(days=1)
            label = fmt_week(end.isoformat())
        except Exception:
            label = fmt_week(dossier["ventana"]["inicio"])
        return f"Semana del {label}"
    period_id = str(dossier.get("semana", ""))
    if re.fullmatch(r"\d{4}-W\d{2}", period_id):
        year, week = period_id.split("-W")
        label = fmt_spanish_date(dt.date.fromisocalendar(int(year), int(week), 1))
        return f"Semana del {label}"
    label = fmt_week(dossier["ventana"]["inicio"])
    return f"Semana del {label}"


def title_label(dossier: dict) -> str:
    if dossier.get("tipo_periodo") == "diario":
        return "Bolet&iacute;n Diario de Ciberseguridad"
    return "Bolet&iacute;n Semanal de Ciberseguridad"


def client_label(dossier: dict) -> str:
    return ""


def safe_url(url: str) -> str:
    if not url:
        return ""
    if ".onion" in url.lower():
        return ""
    if url.startswith("http://") or url.startswith("https://"):
        return url
    return ""


def read_more(item: dict) -> str:
    url = safe_url(item.get("url", ""))
    if not url:
        return ""
    return f'<a href="{esc(url)}" target="_blank" class="info-button">Leer M&aacute;s</a>'


def public_url(url: str) -> str:
    url = safe_url(url)
    if "known_exploited_vulnerabilities.json" in url:
        return "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    return url


def sentence_limit(text: str, limit: int = 3) -> str:
    text = re.sub(r"\s+", " ", str(text or "")).strip()
    text = re.sub(r"\s*Leer m[aá]s\s*\.\.\.\s*", " ", text, flags=re.I)
    text = text.replace("[...]", " ")
    text = re.sub(r"View CSAF Summary\s*", "", text, flags=re.I)
    if len(text) > 900:
        text = text[:900].rsplit(" ", 1)[0] + "."
    parts = re.split(r"(?<=[.!?])\s+", text)
    return " ".join(parts[:limit]).strip()


RAW_ENGLISH_PUBLIC = (
    r"\bactively exploited\b",
    r"\bcritical(?:-severity)?\b",
    r"\bremote code execution\b",
    r"\bauthentication bypass\b",
    r"\bprivilege escalation\b",
    r"\bvulnerabilities\b",
    r"\bsecurity flaw\b",
    r"\bthe vulnerability\b",
    r"\bthreat actor\b",
    r"\bunauthenticated remote\b",
    r"\bremote attacker\b",
    r"\bcontains an?\b",
    r"\ballows an?\b",
)


def has_raw_english(text: str) -> bool:
    return any(re.search(pattern, str(text or ""), flags=re.I) for pattern in RAW_ENGLISH_PUBLIC)


def cve_phrase(item: dict) -> str:
    cves = item.get("cves", [])[:5]
    if not cves:
        return ""
    if len(cves) == 1:
        return f" La vulnerabilidad asociada es {esc(cves[0])}."
    return f" Las vulnerabilidades asociadas son {esc(', '.join(cves))}."


def display_cvss_severity(score: str) -> str:
    severity = severity_from_cvss(score)
    return {
        "CRITICA": "CRÍTICA",
        "ALTA": "ALTA",
        "MEDIA": "MEDIA",
        "BAJA": "BAJA",
    }.get(severity, "")


def cvss_score_from_nvd(cve: str) -> str:
    cve = str(cve or "").upper()
    if not cve:
        return ""
    cached = CVSS_V3_CACHE.get(cve)
    if isinstance(cached, dict) and cached.get("score"):
        return str(cached["score"])
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Altel-CTI/1.0"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return ""
    vulnerabilities = data.get("vulnerabilities") or []
    if not vulnerabilities:
        return ""
    metrics = vulnerabilities[0].get("cve", {}).get("metrics", {})
    candidates = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []
    if not candidates:
        return ""
    try:
        score = f"{float(candidates[0]['cvssData']['baseScore']):.1f}"
    except (KeyError, TypeError, ValueError):
        return ""
    CVSS_V3_CACHE[cve] = {
        "score": score,
        "source": "NVD",
        "updated": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
    }
    save_cvss_cache(CVSS_V3_CACHE)
    return score


def cvss_score_for_display(cve: str, item: dict, first: dict) -> str:
    for candidate in (item, first, *(item.get("fuentes", []) or [])):
        score, _ = extract_cvss(candidate)
        if score:
            try:
                return f"{float(score):.1f}"
            except ValueError:
                return str(score)
    return cvss_score_from_nvd(cve)


def cve_display_suffix(cve: str, item: dict, first: dict) -> str:
    score = cvss_score_for_display(cve, item, first)
    if not score:
        return " CVSS v3.1: pendiente"
    severity = display_cvss_severity(score)
    if severity:
        return f" CVSS v3.1: {esc(score)} {esc(severity)}"
    return f" CVSS v3.1: {esc(score)}"


def client_relevance_phrase(item: dict) -> str:
    return ""


MSRC_TYPES = [
    ("Remote Code Execution", "Ejecución remota de código", "ejecutar código"),
    ("Elevation of Privilege", "Elevación de privilegios", "elevar privilegios"),
    ("Security Feature Bypass", "Omisión de característica de seguridad", "evadir una protección de seguridad"),
    ("Information Disclosure", "Divulgación de información", "exponer información"),
    ("Denial of Service", "Denegación de servicio", "interrumpir la disponibilidad"),
    ("Spoofing", "Suplantación", "suplantar identidad o contenido"),
    ("Tampering", "Manipulación", "alterar datos o comportamiento"),
]


def msrc_type(title: str, item: dict | None = None) -> tuple[str, str, str]:
    source = f"{title} {item.get('impact','') if item else ''}"
    for english, spanish, action in MSRC_TYPES:
        if english.lower() in source.lower():
            return english, spanish, action
    return "Vulnerability", "Vulnerabilidad", "afectar la seguridad del componente"


def msrc_product_name(title: str) -> str:
    product = str(title or "").strip()
    product = re.sub(r"\bVulnerability\b", "", product, flags=re.I).strip(" -:")
    for english, _, _ in MSRC_TYPES:
        product = re.sub(rf"\b{re.escape(english)}\b", "", product, flags=re.I).strip(" -:")
    return re.sub(r"\s+", " ", product) or "producto Microsoft afectado"


def msrc_title_es(item: dict) -> str:
    title = item.get("titulo") or item.get("producto") or ""
    _, vuln_type, _ = msrc_type(title, item)
    product = msrc_product_name(title)
    return f"{vuln_type} en {product}"


def msrc_editorial_text(item: dict) -> str:
    product = msrc_product_name(item.get("titulo") or item.get("producto") or "")
    _, vuln_type, action = msrc_type(item.get("titulo") or "", item)
    status = str(item.get("exploit_status") or "").lower()
    if item.get("exploited") or "exploited:yes" in status:
        evidence = "MSRC indica explotación activa detectada, por lo que debe tratarse como una vulnerabilidad de atención inmediata."
    elif item.get("publicly_disclosed") or "publicly disclosed:yes" in status:
        evidence = "MSRC indica que la vulnerabilidad fue divulgada públicamente; no se confirma explotación activa en la fuente oficial."
    else:
        evidence = "MSRC no confirma explotación activa para este identificador en la información consultada."
    return (
        f"Microsoft publicó el paquete de seguridad de agosto de 2026 e incluyó una {vuln_type.lower()} en {product}. "
        f"El impacto técnico descrito por el fabricante podría permitir {action} bajo las condiciones indicadas en la Security Update Guide. "
        f"{evidence} "
        "Los equipos deben aplicar las actualizaciones de Microsoft, confirmar si el producto afectado está presente en servidores o estaciones administradas y revisar eventos anómalos relacionados con el componente."
    )


def ransomware_live_text(item: dict) -> str:
    try:
        data = json.loads(item.get("resumen") or "{}")
    except Exception:
        data = {}
    group = data.get("group_name") or data.get("group") or "grupo no identificado"
    group = str(group).strip()
    group = group[:1].upper() + group[1:] if group else "grupo no identificado"
    sector = data.get("activity") or data.get("sector") or "organizacion no especificada"
    sector_map = {"manufacturing": "manufacturero", "not found": "no especificado", "other": "otro/no especificado"}
    sector = sector_map.get(str(sector).lower(), str(sector).lower())
    country_value = str(data.get("country") or "EC").upper()
    country = "Ecuador" if country_value == "EC" else str(data.get("country") or "no especificado")
    source = item.get("fuente") or "ransomware.live"
    return (
        f"El monitoreo de fuentes abiertas identificó en {source} una publicación atribuida al grupo de ransomware {group} "
        f"relacionada con una presunta organización del sector {sector} en {country}. "
        "El registro constituye una señal OSINT y no confirma por sí solo el alcance del incidente, por lo que no se presenta como compromiso verificado. "
        "Ante este escenario, las organizaciones del sector deberían confirmar cobertura de EDR, validar respaldos aislados, exigir autenticación multifactor en accesos remotos y vigilar transferencias anómalas de información."
    )


def editorial_text(item: dict) -> str:
    text = f"{item.get('titulo','')} {item.get('resumen','')}".lower()
    cves = set(item.get("cves", []))
    if item.get("fuente_id") == "ransomware_ec":
        return ransomware_live_text(item)
    if item.get("fuente_id") == "microsoft_msrc":
        return msrc_editorial_text(item)
    if "CVE-2026-33824" in cves:
        return (
            "CISA confirmó explotación activa de CVE-2026-33824, una vulnerabilidad crítica de ejecución remota de código en las extensiones IKE de Windows. "
            "El riesgo es prioritario porque afecta un componente de negociación VPN/IPsec que puede estar presente en servidores y estaciones Windows. "
            "La acción esperada es aplicar las actualizaciones de Microsoft, validar exposición de servicios relacionados con IKE/IPsec y revisar registros de red por intentos de explotación antes y después del parche."
        )
    if "CVE-2026-55040" in cves:
        return (
            "CISA incorporó CVE-2026-55040 al catálogo KEV por explotación activa contra Microsoft SharePoint. "
            "La falla permite evadir controles de autenticación o seguridad en escenarios de red, por lo que puede afectar portales internos o expuestos si no fueron actualizados. "
            "Se debe aplicar el parche, restringir acceso a granjas SharePoint sensibles y revisar autenticaciones, cargas de archivos y cambios administrativos recientes."
        )
    if "cve-2026-73570" in text or ("zimbra" in text and ("actively exploited" in text or "remote code execution" in text or "command injection" in text)):
        return (
            "CERT Polska y CISA reportaron explotación activa de una vulnerabilidad en Zimbra Collaboration Suite que permite ejecución de comandos sin autenticación mediante solicitudes SMTP especialmente construidas. "
            "El impacto es alto para servidores de correo expuestos, porque puede derivar en ejecución de código como usuario del servicio, robo de buzones o persistencia. "
            "Se debe actualizar Zimbra de inmediato, revisar logs SMTP y web, buscar procesos anómalos del usuario zimbra y aislar instancias con indicios de compromiso."
        )
    if "trueconf" in text or "cve-2026-72529" in text or "cve-2026-72530" in text:
        return (
            "CISA ordenó parchear dos vulnerabilidades explotadas activamente en TrueConf Server: omisión de autenticación y ejecución de código mediante inyección. "
            "El riesgo se concentra en plataformas de videoconferencia autoalojadas accesibles por red, donde un atacante podría ejecutar scripts o desplegar malware sobre el servidor. "
            "Se debe actualizar TrueConf Server, limitar el acceso a puertos administrativos o de servicio y revisar actividad inusual asociada a conexiones remotas."
        )
    if "mlflow" in text or "cve-2026-64849" in text:
        return (
            "CISA confirmó explotación activa de CVE-2026-64849 en MLflow, plataforma usada en flujos de ingeniería de datos e inteligencia artificial. "
            "La vulnerabilidad permite abusar de SSRF para alcanzar servicios internos o metadatos cloud y extraer respuestas sensibles. "
            "Los equipos deben actualizar MLflow, retirar instancias expuestas, bloquear acceso a metadatos cloud desde la aplicación y rotar credenciales si hubo exposición."
        )
    if "gitlab" in text and ("cve-2026-19478" in text or "graphql" in text or "exploitation" in text):
        return (
            "GitLab corrigió CVE-2026-19478, una vulnerabilidad crítica en GraphQL que puede permitir a atacantes no autenticados modificar o eliminar proyectos públicos y datos de usuario. "
            "Reportes posteriores indicaron explotación poco después de la divulgación, elevando la prioridad para instancias accesibles desde Internet. "
            "Se debe actualizar GitLab, revisar cambios recientes en proyectos públicos, validar integridad de repositorios y auditar tokens o automatizaciones asociadas."
        )
    if "elementor pro" in text or "cve-2026-32475" in text:
        return (
            "Se divulgó una falla crítica en Elementor Pro para WordPress que permite cargar archivos PHP maliciosos y ejecutar código en el servidor. "
            "El riesgo es relevante para sitios corporativos y portales públicos, porque una explotación exitosa puede crear puertas traseras, modificar contenido o robar información del sitio. "
            "Los administradores deben actualizar Elementor Pro, revisar cargas recientes, validar cuentas administrativas y buscar archivos PHP inesperados en directorios de subida."
        )
    if "siemens s7" in text or "siemens s7 series" in text or "plc" in text and "ai-generated" in text:
        return (
            "CISA y agencias aliadas advirtieron una amenaza activa contra PLC Siemens S7 y otros entornos industriales, con uso de scripts generados por inteligencia artificial para reconocimiento y desarrollo de capacidades. "
            "Aunque la alerta se centra en infraestructura crítica de EE. UU., el patrón es aplicable a cualquier entorno OT con PLC expuestos o monitoreo débil. "
            "Se debe segmentar OT/IT, bloquear accesos no autorizados a PLC, monitorear comandos de ingeniería y aplicar las mitigaciones recomendadas por el fabricante y CISA."
        )
    if "rust supply chain" in text or "arrayref" in text or "crates.io" in text:
        return (
            "El ecosistema Rust retiró versiones maliciosas de crates populares después de que una cuenta de mantenedor comprometida publicara dependencias troyanizadas. "
            "El código malicioso se ejecutaba durante compilación, por lo que el impacto puede alcanzar estaciones de desarrollo, pipelines y artefactos generados. "
            "Los equipos de ingeniería deben revisar versiones instaladas durante la ventana, limpiar cachés de dependencias, rotar secretos usados en CI/CD y exigir verificación de integridad en paquetes."
        )
    if "redc2" in text or ("trojanized npm" in text and "npm" in text):
        return (
            "Investigadores identificaron paquetes npm troyanizados que se hacían pasar por utilidades legítimas y desplegaban RedC2 4.0, un implante Linux con capacidades de mando y control asistidas por IA. "
            "El vector afecta principalmente a equipos de desarrollo y servidores donde se instalan dependencias sin control. "
            "Se debe bloquear paquetes no aprobados, revisar instalaciones recientes de npm, rotar credenciales de entornos afectados y monitorear binarios ejecutados desde directorios de dependencias."
        )
    if "cl0p" in text or "clop" in text and "windchill" in text:
        return (
            "Reportes de la semana vinculan a Cl0p con una campaña contra PTC Windchill y FlexPLM, incluyendo uso de web shells diseñados para mapear repositorios y extraer archivos. "
            "El riesgo operativo está en plataformas PLM con información de ingeniería, diseños y propiedad intelectual. "
            "Las organizaciones deben validar parches de Windchill/FlexPLM, buscar web shells JSP, revisar accesos a bóvedas documentales y monitorear exfiltración de grandes volúmenes."
        )
    if "cavern" in text or "cav3rn" in text:
        return (
            "Investigadores describieron la evolución de Cavern, un framework de mando y control asociado a actividad estatal iraní que usa DNS y Google Apps Script para mezclarse con tráfico legítimo. "
            "La técnica reduce la visibilidad de controles tradicionales porque abusa de servicios confiables y canales comunes. "
            "Se recomienda monitorear patrones DNS inusuales, revisar uso no autorizado de Google Apps Script y correlacionar tráfico cloud con actividad de endpoints."
        )
    if "safepal" in text:
        return (
            "SafePal informó una brecha de datos causada por una falla de autorización en un componente de seguimiento de pedidos, con exposición de datos de contacto y compra de clientes. "
            "Aunque no implica necesariamente compromiso de llaves de billeteras, sí aumenta el riesgo de phishing dirigido contra usuarios de criptoactivos. "
            "Las organizaciones deben advertir a usuarios expuestos, reforzar verificación de comunicaciones y desconfiar de solicitudes de recuperación, actualización o soporte no iniciadas por canales oficiales."
        )
    if "microsoft defender" in text and "driver" in text:
        return (
            "Check Point Research mostró que un controlador legítimo de remediación de Microsoft Defender puede ser abusado para eliminar software de seguridad durante el arranque. "
            "La técnica no depende de introducir un driver externo, sino de usar un componente firmado ya confiable, lo que complica la detección. "
            "Los equipos deben revisar políticas de protección contra manipulación, monitorear cambios a nivel de kernel o arranque y validar que las soluciones EDR alerten ante eliminación de archivos críticos."
        )
    if "banking trojans" in text or "grandoreiro" in text or "toxicpanda" in text or "manic" in text:
        return (
            "La semana destacó actividad de troyanos bancarios como Manic, Grandoreiro y ToxicPanda 2.0, con foco en robo de credenciales, fraude financiero y abuso de permisos en dispositivos móviles. "
            "Grandoreiro mantiene relevancia para Latinoamérica, por lo que conviene reforzar controles contra adjuntos maliciosos, macros, instaladores falsos y accesos bancarios desde equipos no confiables. "
            "La respuesta defensiva debe combinar monitoreo de endpoints, protección móvil y alertas por transacciones o sesiones anómalas."
        )
    if "windows task host" in text:
        return (
            "CISA confirmó que grupos de ransomware también explotan una vulnerabilidad de alta severidad en Windows Task Host. "
            "Aunque la falla había sido corregida previamente, la explotación activa muestra que los retrasos de parcheo siguen generando superficie real para intrusiones. "
            "Se debe verificar aplicación de parches en estaciones y servidores Windows, revisar ejecución anómala de tareas y priorizar equipos con exposición a usuarios privilegiados."
        )
    if "netscaler" in text or "citrix" in text and "authentication bypass" in text:
        return (
            "Citrix publicó correcciones para fallas críticas en NetScaler ADC y NetScaler Gateway, incluyendo una omisión de autenticación explotable sin interacción del usuario en ciertas configuraciones. "
            "El impacto es alto cuando estos equipos sostienen acceso remoto, balanceo de aplicaciones o publicación de servicios corporativos. "
            "Se debe validar presencia de NetScaler administrado por el cliente, aplicar la actualización, limitar interfaces de administración y revisar autenticaciones o reinicios inusuales."
        )
    if "cisco" in text and ("crosswork" in text or "secure workload" in text):
        return (
            "Cisco publicó actualizaciones para vulnerabilidades críticas en Crosswork y Secure Workload, incluyendo fallas con impacto de ejecución remota de código, omisión de autenticación y recorrido de rutas. "
            "La relevancia depende de si el cliente usa estas plataformas para operación de red, telemetría o microsegmentación; si existen, el impacto puede alcanzar componentes de gestión. "
            "Se debe confirmar inventario Cisco, aplicar parches del fabricante y revisar accesos administrativos o cambios de configuración recientes."
        )
    if "entra id" in text or "cve-2026-69836" in text:
        return (
            "Microsoft corrigió una vulnerabilidad de severidad máxima en Entra ID, anteriormente Azure Active Directory, asociada a ejecución remota de código en el servicio cloud. "
            "Por tratarse de la capa de identidad de Microsoft 365 y aplicaciones corporativas, el riesgo operativo se concentra en accesos privilegiados, consentimientos OAuth y cambios no autorizados en aplicaciones empresariales. "
            "Los equipos deben revisar alertas de identidad, sesiones administrativas, cambios de configuración y actividad anómala en cuentas con privilegios."
        )
    if "synkloader" in text or "microsoft teams phishing" in text:
        return (
            "Se reportó distribución de SynkLoader mediante campañas de phishing en Microsoft Teams, usando una pantalla falsa de bloqueo para robar credenciales. "
            "El riesgo combina ingeniería social dentro de una plataforma de colaboración confiable con robo directo de acceso corporativo. "
            "Se debe reforzar concienciación sobre mensajes externos en Teams, revisar enlaces compartidos, bloquear dominios asociados y monitorear inicios de sesión posteriores a interacciones sospechosas."
        )
    if "14,000 ip cameras" in text or "cameraswarm" in text:
        return (
            "SecurityWeek reportó una operación que comprometió miles de cámaras IP, principalmente Dahua, para observar o manipular infraestructura de video en varios países. "
            "El caso refuerza el riesgo de cámaras con firmware desactualizado, credenciales débiles o administración expuesta. "
            "Las organizaciones deben inventariar cámaras, aislar redes de videovigilancia, actualizar firmware, rotar credenciales y bloquear administración desde Internet."
        )
    if "40 malicious firefox extensions" in text or "offside wallet" in text:
        return (
            "Investigadores identificaron extensiones maliciosas de Firefox que se hacían pasar por productos Web3 para robar secretos de billeteras de criptomonedas. "
            "Aunque el objetivo principal son usuarios de criptoactivos, la técnica aplica a extensiones de navegador no autorizadas que capturan datos sensibles. "
            "Se recomienda aplicar listas permitidas de extensiones, revisar permisos excesivos y retirar complementos no gestionados en equipos corporativos."
        )
    if "fortune 500" in text and "azure data theft" in text:
        return (
            "Un actor afirmó haber exfiltrado grandes volúmenes de datos desde entornos Azure de varias compañías, lo que vuelve a poner el foco en credenciales cloud, permisos excesivos y monitoreo de descargas masivas. "
            "La información debe tratarse como reporte de amenaza hasta contar con confirmación independiente de cada víctima. "
            "Los equipos cloud deben revisar cuentas privilegiadas, tokens de aplicaciones, reglas de almacenamiento y alertas por extracción inusual de datos."
        )
    if "oracle http server" in text or "weblogic server proxy plug-in" in text or "cve-2026-21962" in text:
        return (
            "CISA incorporó CVE-2026-21962 al catálogo KEV por explotación activa contra Oracle HTTP Server y Oracle WebLogic Server Proxy Plug-in. "
            "La falla puede permitir acceso o modificación no autorizada de datos críticos en componentes expuestos. "
            "Se debe aplicar la actualización de Oracle, validar servidores web/proxy integrados con WebLogic y revisar registros por accesos o cambios no autorizados."
        )
    if "CVE-2026-16232" in cves or "smartconsole" in text:
        return (
            "Check Point confirmó una vulnerabilidad crítica de omisión de autenticación en SmartConsole que permite a un atacante no autenticado obtener acceso administrativo completo. "
            "Afecta a Security Management Server y Multi-Domain Security Management Server. "
            "Se identifica que concurren las condiciones que definen una amenaza prioritaria: consta en el catálogo KEV de CISA, presenta alta probabilidad de explotación y existe exploit público verificado. "
            "Al tratarse de la consola de gestión de la propia plataforma de seguridad, su compromiso habilita la modificación de políticas de firewall. "
            "La acción inmediata es aplicar la actualización del fabricante y revisar accesos administrativos recientes a SmartConsole."
        )
    if "check point" in text and "authentication bypass" in text:
        return (
            "La alerta describe una omisión de autenticación en servidores de gestión Check Point que podría permitir acceso administrativo no autorizado en entornos vulnerables. "
            "El riesgo es alto porque comprometer la consola de gestión de seguridad permite modificar políticas, abrir accesos o debilitar controles de perímetro. "
            "Los equipos deben verificar versiones afectadas, aplicar la actualización del fabricante y revisar autenticaciones administrativas recientes o cambios de política no justificados."
        )
    if "atlassian rovo" in text or ("prompt injection" in text and "rovo" in text):
        return (
            "CSIRT Telconet reportó una vulnerabilidad de inyección de prompts en Atlassian Rovo, asistente de inteligencia artificial integrado a flujos colaborativos. "
            "Este tipo de falla puede manipular instrucciones procesadas por el asistente y generar respuestas o acciones no previstas si se combinan con datos no confiables. "
            "Las organizaciones que usen Rovo deben revisar configuraciones de permisos, limitar acceso a fuentes externas y monitorear acciones automatizadas ejecutadas desde el asistente."
        )
    if "chrome 151" in text or ("chrome" in text and "41 vulnerabilidades" in text):
        return (
            "CSIRT Telconet informó el lanzamiento de Chrome 151 con correcciones para 41 vulnerabilidades, incluidas fallas críticas. "
            "Aunque el navegador es un componente de usuario final, su exposición diaria a contenido web no confiable lo convierte en una superficie frecuente de explotación. "
            "Los equipos de TI deben validar que Chrome y navegadores basados en Chromium se actualicen automáticamente, priorizar endpoints de usuarios privilegiados y revisar extensiones no aprobadas."
        )
    if "CVE-2026-20316" in cves or "secure firewall management center" in text:
        return (
            "CISA emitió una advertencia por una vulnerabilidad crítica en Cisco Secure Firewall Management Center explotada en ataques activos. "
            "La falla se asocia a credenciales embebidas en el código y permite a un atacante remoto no autenticado autenticarse contra el dispositivo. "
            "Fue incorporada al catálogo KEV; los equipos de TI deben identificar instancias Cisco FMC expuestas, aplicar la corrección del fabricante y revisar accesos administrativos recientes."
        )
    if "velocloud" in text:
        return (
            "La alerta describe una inyección de comandos en implementaciones locales de VeloCloud Orchestrator. "
            "En escenarios vulnerables, un atacante remoto podría ejecutar comandos sobre el host, especialmente si la consola está accesible desde redes no confiables. "
            "Las organizaciones deben actualizar el componente afectado, restringir el acceso administrativo por VPN o listas de control y revisar registros de comandos, sesiones y autenticaciones anómalas."
        )
    if "sonicwall" in text and "inc ransomware" in text:
        return (
            "INC Ransomware fue reportado como un actor relevante en la explotación de fallas recientes en appliances SonicWall SMA 1000, usados para acceso remoto seguro. "
            "La fuente vincula la actividad con publicación de víctimas en sitios de filtración, lo que sugiere un modelo de doble extorsión cuando el compromiso es exitoso. "
            "Debe verificarse la versión de los SMA 1000, aplicar parches disponibles, revisar accesos VPN inusuales y confirmar que las copias de respaldo críticas permanezcan aisladas."
        )
    if "progress kemp loadmaster" in text or "cve-2026-8037" in text:
        return (
            "CISA incorporó CVE-2026-8037, una falla de inyección de comandos en Progress Kemp LoadMaster, al catálogo de vulnerabilidades explotadas conocidas (KEV). "
            "La fuente reporta intentos de explotación observados, por lo que los balanceadores expuestos a Internet deben actualizarse, limitar interfaces administrativas y revisar registros del appliance en busca de comandos o solicitudes anómalas."
        )
    if "teampcp" in text and "redis" in text:
        return (
            "El análisis vincula a TeamPCP con compromisos de infraestructura Redis expuesta y actividad posterior contra cadena de suministro. "
            "La relevancia operativa está en servicios publicados sin controles adecuados y en repositorios o pipelines que puedan ser usados para distribuir componentes alterados. "
            "Debe verificarse que Redis no esté expuesto sin autenticación, rotar credenciales y revisar artefactos de construcción publicados desde entornos comprometidos."
        )
    if "n-central" in text and "hotfix" in text:
        return (
            "N-able publicó un nuevo hotfix para N-central mientras investiga explotación en curso contra su plataforma de monitoreo y administración remota (RMM). "
            "El riesgo es alto porque un compromiso de RMM puede alcanzar sistemas gestionados y facilitar persistencia. "
            "Se debe instalar el hotfix, restringir el acceso administrativo, revisar cuentas creadas recientemente y auditar acciones ejecutadas sobre endpoints administrados."
        )
    if "langflow" in text:
        return (
            "CISA alertó sobre explotación activa de vulnerabilidades en IBM Langflow, N-able N-central y Apache Tomcat. "
            "El riesgo es relevante porque combina plataformas de desarrollo, administración remota y servicios de aplicación que pueden estar expuestos a Internet. "
            "Se debe identificar presencia de estos productos, aplicar parches u hotfixes del fabricante y revisar accesos, cambios de configuración y ejecución de procesos no esperados."
        )
    if "sharepoint" in text:
        return (
            "Microsoft publicó una actualización para corregir una vulnerabilidad de ejecución remota de código en SharePoint. "
            "La falla permite ejecutar código mediante datos manipulados en escenarios autenticados de bajo privilegio. "
            "Conviene aplicar el parche en granjas SharePoint expuestas o integradas a flujos críticos, validar cuentas con privilegios bajos y revisar eventos de carga o procesamiento de contenido anómalo."
        )
    if "fastjson" in text:
        return (
            "Se identificó una vulnerabilidad crítica de ejecución remota de código en la biblioteca FastJson, que afecta a aplicaciones Java que procesan JSON no confiable. "
            "Cuenta con exploit público verificado y se reporta explotación activa contra organizaciones en Estados Unidos. "
            "Los equipos de desarrollo deben inventariar aplicaciones Java que incorporen esta dependencia y actualizarla a una versión corregida."
        )
    if "advanced responsive video embedder" in text or "arve" in text:
        return (
            "Se identificó una puerta trasera crítica en el complemento de WordPress Advanced Responsive Video Embedder, que permite a atacantes no autenticados obtener acceso completo de administrador. "
            "La versión maliciosa afecta a instalaciones activas del plugin. "
            "Los administradores deben verificar la versión instalada en todos los sitios WordPress gestionados y retirar cualquier copia no confiable."
        )
    if "kernel" in text and "linux" in text:
        return (
            "Investigadores identificaron una vulnerabilidad zero-day en el subsistema net/sched del kernel de Linux, que permite a un atacante local obtener privilegios de root explotando una condición use-after-free. "
            "Existe exploit público verificado. "
            "El hallazgo destaca además el uso creciente de inteligencia artificial en la identificación de fallas de memoria a nivel de kernel."
        )
    if "debug" in text and "chalk" in text and "npm" in text:
        return (
            "Amazon vinculó a Corea del Norte el secuestro de paquetes npm ampliamente utilizados, incluyendo debug y chalk. "
            "El vector fue el compromiso de la cuenta del mantenedor mediante phishing y la introducción de código malicioso en dependencias de alto volumen. "
            "Los equipos de desarrollo deben fijar versiones, verificar integridad de paquetes y revisar dependencias críticas publicadas durante la ventana del incidente."
        )
    if "macos" in text and ("malvertising" in text or "dprk" in text):
        return (
            "Investigadores atribuyen a actores vinculados con Corea del Norte una campaña de malvertising contra usuarios macOS. "
            "La operación redirige a páginas falsas de actualización que simulan procesos legítimos para entregar malware orientado al robo de criptoactivos. "
            "Los controles prioritarios son bloquear descargas desde dominios no confiables, exigir actualizaciones desde canales oficiales y revisar endpoints macOS con alertas de instalación fuera de MDM."
        )
    if "hotel wi-fi" in text or "captivecrunch" in text or "cornflake" in text:
        return (
            "Microsoft reporta que una actualización falsa de navegador servida sobre redes Wi-Fi de hoteles secuestradas se ha usado para entregar CornFlake, un troyano de acceso remoto capaz de capturar imágenes de webcam, audio de micrófono y pulsaciones de teclado. "
            "Los investigadores rastrean la operación como CaptiveCrunch y la atribuyen a Storm-2945. "
            "El personal en viaje debe evitar actualizaciones ofrecidas por portales cautivos, usar VPN corporativa y reportar solicitudes de instalación al conectarse a redes de hotelería."
        )
    if "anysign4pc" in text:
        return (
            "Autoridades de Corea del Sur y firmas de seguridad reportaron una campaña estatal que comprometió sitios web confiables. "
            "Los atacantes usaron esos sitios para explotar software de seguridad financiera instalado localmente e infectar a visitantes seleccionados con las puertas traseras SIGNBT o COPPERHEDGE. "
            "Una página comprometida podía infectar un sistema con una versión vulnerable de AnySign4PC sin mostrar ningún aviso al usuario."
        )
    if "joomla" in text and "defacement" in text:
        return (
            "EcuCERT reporta una campaña masiva de desfiguración de sitios web dirigida contra portales institucionales de Ecuador, que explota de forma encadenada vulnerabilidades en el CMS Joomla!. "
            "La cadena permite a un atacante no autenticado crear cuentas con privilegios de editor, cargar archivos arbitrarios y ejecutar código de forma remota. "
            "Los administradores deben actualizar Joomla y sus extensiones, revisar cuentas de editor creadas recientemente, bloquear cargas de archivos no autorizadas y monitorear cambios en páginas públicas."
        )
    if "wallstreet" in text:
        return (
            "EcuCERT reporta que la actividad del grupo Wallstreet se dirige a organizaciones de los sectores manufacturero, salud y entidades gubernamentales por el alto volumen de información sensible que administran. "
            "Bajo su esquema de doble extorsión, el grupo publica la información exfiltrada en su sitio de filtración si no se paga el rescate. "
            "La respuesta defensiva debe confirmar respaldos aislados, revisar accesos remotos expuestos, reforzar autenticación multifactor y buscar transferencias inusuales de datos hacia servicios externos."
        )
    if "quickfox" in text:
        return (
            "Investigadores reportaron un ataque de cadena de suministro contra QuickFox mediante instaladores troyanizados para Windows. "
            "La campaña distribuye la puerta trasera FDMTP y muestra el riesgo de instalar herramientas de conectividad desde repositorios no verificados; TI debe retirar instaladores no oficiales, validar hashes y revisar persistencia en equipos donde se haya usado QuickFox."
        )
    if "18 malicious npm" in text or ("npm" in text and "rat" in text):
        return (
            "Investigadores identificaron paquetes npm maliciosos dirigidos a usuarios de herramientas de desarrollo de Alibaba, con entrega de un troyano de acceso remoto (RAT). "
            "El mecanismo aprovecha confianza en dependencias de software y nombres de paquetes similares a componentes privados. "
            "Los equipos de desarrollo deben revisar dependencias recientes, bloquear paquetes no aprobados en registros internos y rotar credenciales usadas en entornos donde se instalaron esos módulos."
        )
    if "stormencryptor" in text:
        return (
            "BleepingComputer reporta el uso de StormEncryptor por un actor previamente asociado a Medusa. "
            "La fuente lo describe como una nueva familia de ransomware; no se debe asumir afectación local sin evidencia adicional. "
            "La defensa debe concentrarse en bloquear ejecución no autorizada, validar respaldos desconectados, monitorear creación masiva de archivos cifrados y revisar accesos remotos expuestos."
        )
    if "cve-2026-58048" in text or ("cpanel" in text and "whm" in text):
        return (
            "EcuCERT difundió una alerta sobre CVE-2026-58048, vulnerabilidad crítica en cPanel y WHM que podría permitir a un usuario autenticado con una cuenta de hosting ejecutar consultas SQL con privilegios elevados sobre MySQL o MariaDB. "
            "El riesgo es relevante para proveedores de hosting y organizaciones que administran múltiples sitios desde paneles compartidos, porque una cuenta comprometida podría ampliar su impacto sobre la base de datos. "
            "Los administradores deben aplicar la actualización del fabricante, revisar cuentas de hosting con actividad inusual y auditar consultas administrativas recientes."
        )
    if "cve-2026-59310" in text or ("vmware vcenter" in text and "directory" in text):
        return (
            "EcuCERT alertó sobre explotación activa de CVE-2026-59310 en VMware vCenter Server, una falla crítica de recorrido de directorios que puede permitir ejecución remota de código en condiciones de red. "
            "La actividad reportada incluye despliegue de herramientas de SSH inverso y persistencia mediante puertas traseras, por lo que debe tratarse como una amenaza prioritaria para plataformas de virtualización. "
            "Se recomienda actualizar las versiones afectadas, retirar interfaces de administración de Internet y revisar telemetría desde el 3 de agosto en busca de conexiones externas, tareas programadas o binarios no autorizados."
        )
    if "cve-2024-55591" in text or "cve-2025-24472" in text or ("gunra" in text and "fortinet" in text):
        return (
            "EcuCERT advierte que una campaña atribuida a Gunra ransomware aprovecha fallas críticas en FortiOS y FortiProxy para evadir autenticación, obtener privilegios de superadministrador y usar firewalls o VPN como punto de entrada. "
            "La señal es relevante para perímetros expuestos porque combina acceso administrativo no autorizado con tácticas de doble extorsión. "
            "Los equipos deben actualizar los dispositivos afectados, restringir interfaces administrativas y buscar cuentas sospechosas como forticloud-sync, accesos VPN desconocidos y transferencias inusuales de información."
        )
    if "sap commerce cloud" in text or "cve-2026-58231" in text:
        return (
            "SAP publicó correcciones para CVE-2026-58231, una vulnerabilidad crítica en SAP Commerce Cloud Data Hub Adapter que puede permitir ejecución remota de código sin autenticación. "
            "El riesgo aumenta cuando el componente procesa datos externos o está integrado a procesos de comercio digital de alto valor. "
            "Las organizaciones deben aplicar el parche del fabricante, revisar exposición del adaptador y auditar actividad anómala en integraciones de datos."
        )
    if "forminator" in text or "cve-2026-15748" in text:
        return (
            "Se reportó una vulnerabilidad crítica en Forminator Forms, plugin de WordPress ampliamente desplegado, que puede permitir ejecución remota de código mediante carga maliciosa de archivos PHP. "
            "El impacto potencial es compromiso completo del sitio vulnerable, creación de persistencia o modificación de contenido. "
            "Los administradores deben actualizar el plugin, revisar archivos cargados recientemente, validar cuentas administrativas y monitorear cambios no autorizados."
        )
    if "adobe commerce" in text or "cve-2026-71362" in text:
        return (
            "Se reportaron intentos de explotación contra CVE-2026-71362 poco después de la publicación de parches para Adobe Commerce. "
            "El riesgo es relevante para tiendas expuestas a Internet por el impacto potencial sobre cuentas, datos de clientes e integraciones transaccionales. "
            "Se debe aplicar el parche del fabricante, revisar sesiones y cuentas anómalas, y priorizar entornos de comercio electrónico públicos."
        )
    if "windows deployment services" in text or "cve-2026-62893" in text:
        return (
            "Microsoft publicó una corrección para una vulnerabilidad de ejecución remota de código en Windows Deployment Services TFTP Server. "
            "El riesgo se concentra en entornos con PXE/WDS habilitado, donde el servicio puede quedar accesible por red. "
            "Se recomienda aplicar la actualización o deshabilitar TFTP/WDS cuando no sea requerido."
        )
    if "windows dhcp server" in text or "cve-2026-62823" in text:
        return (
            "Microsoft corrigió una vulnerabilidad de ejecución remota de código en Windows DHCP Server. "
            "Por tratarse de infraestructura crítica interna, una explotación exitosa podría afectar servicios base de red. "
            "Se debe aplicar el parche, limitar exposición del servicio a segmentos autorizados y revisar eventos anómalos del rol DHCP."
        )
    if "screen sharing" in text and "macos" in text or "cve-2026-65400" in text:
        return (
            "Se reportó explotación contra sistemas macOS con Screen Sharing expuesto a Internet. "
            "El riesgo aumenta cuando servicios VNC o administración remota quedan publicados sin controles suficientes. "
            "Se debe actualizar macOS, deshabilitar Screen Sharing cuando no sea necesario y restringir acceso mediante VPN o listas de control."
        )
    if "recruitment" in text and ("bitb" in text or "browser-in-the-browser" in text):
        return (
            "Investigadores reportaron una campaña global de phishing laboral que usa páginas falsas de entrevistas y ventanas Browser-in-the-Browser para robar credenciales de Google y Facebook. "
            "En variantes avanzadas, la operación puede retransmitir solicitudes de MFA en tiempo real para capturar sesiones válidas. "
            "Se recomienda reforzar controles contra AiTM, revisar accesos desde ubicaciones inusuales y advertir a usuarios sobre invitaciones de entrevista o calendarios no verificados."
        )
    if "jewelbug" in text or "xg-web" in text:
        return (
            "Se observó actividad de Jewelbug, actor vinculado a China, usando el framework XG-Web para operaciones de espionaje gubernamental y fraude con criptoactivos. "
            "La herramienta convierte el navegador comprometido en un canal de control remoto y robo de información. "
            "Los equipos deben vigilar extensiones, sesiones web persistentes, scripts anómalos en navegador y accesos a portales sensibles desde dispositivos no confiables."
        )
    if "deadlock ransomware" in text:
        return (
            "La operación DeadLock ransomware utiliza infraestructura descentralizada apoyada en servicios blockchain para dificultar el desmantelamiento de comunicaciones y sitios de filtración. "
            "El enfoque complica la interrupción técnica del actor y refuerza la necesidad de controles preventivos antes del cifrado o la extorsión. "
            "Las organizaciones deben confirmar respaldos aislados, endurecer accesos remotos y monitorear exfiltración o comunicación hacia infraestructura no habitual."
        )
    if "expired domains" in text or "dropcatch" in text:
        return (
            "Actores de amenaza están comprando dominios expirados para aprovechar tráfico y reputación heredada con el fin de redirigir usuarios a fraudes o malware. "
            "El riesgo afecta campañas de marca, enlaces históricos, proveedores abandonados y dominios citados en documentación pública. "
            "Se recomienda inventariar dominios propios y de terceros críticos, renovar activos relevantes y monitorear cambios DNS o redirecciones inesperadas."
        )
    if "windrelay" in text or "nfc relay" in text:
        return (
            "WindRelay es una familia de malware Android orientada a fraude de pagos mediante retransmisión NFC en tiempo real. "
            "La campaña se apoya en SpyNote y busca capturar datos de tarjeta desde dispositivos móviles comprometidos. "
            "Los controles recomendados son bloquear instalación fuera de tiendas oficiales, reforzar MDM en dispositivos corporativos y revisar alertas de accesibilidad o permisos NFC abusivos."
        )
    if ("cisco" in text and "asa" in text and "ftd" in text) or "secure firewall asa" in text:
        return (
            "Cisco advirtió explotación activa de una vulnerabilidad de denegación de servicio en Secure Firewall ASA y Firepower Threat Defense que permite provocar fallas remotas en dispositivos afectados. "
            "Aunque el impacto principal es disponibilidad, el riesgo operativo es alto cuando los equipos sostienen VPN, perímetro o segmentación crítica. "
            "Se debe aplicar la corrección del fabricante, restringir acceso a servicios expuestos y revisar reinicios o caídas anómalas del appliance."
        )
    if "hitachi energy apm edge" in text or "cve-2026-43500" in text:
        return (
            "CISA ICS publicó una alerta para Hitachi Energy APM Edge por vulnerabilidades que pueden afectar confidencialidad, integridad y disponibilidad del producto. "
            "En entornos industriales o de monitoreo operativo, estas fallas deben tratarse con gestión de cambio controlada por su posible impacto en continuidad. "
            "Los responsables OT deben confirmar versiones afectadas, aplicar mitigaciones del fabricante y limitar acceso administrativo al componente."
        )
    if "ray-project ray" in text or "cve-2025-62593" in text:
        return (
            "CISA mantiene en KEV CVE-2025-62593, vulnerabilidad de inyección de código en Ray-Project Ray que puede permitir ejecución remota de código. "
            "El riesgo es relevante para equipos de desarrollo, ciencia de datos o IA que expongan servicios Ray en redes no confiables. "
            "Se recomienda actualizar el componente, restringir acceso a clústeres Ray y revisar cargas o jobs ejecutados fuera de procesos autorizados."
        )
    if "unc6671" in text or "vishing" in text:
        return (
            "Investigadores reportaron una ola reciente de ataques de vishing, o phishing por llamada de voz, atribuida a UNC6671 contra servicios financieros, capital privado y firmas de servicios profesionales. "
            "Los operadores se hacen pasar por personal de mesa de ayuda para inducir a empleados a entregar acceso a aplicaciones de software como servicio (SaaS). "
            "Las organizaciones deben reforzar verificación fuera de banda para solicitudes de soporte, revisar restablecimientos de autenticación multifactor y monitorear inicios de sesión anómalos en plataformas SaaS críticas."
        )
    if "snowflake" in text and ("extortion" in text or "extortions" in text):
        return (
            "KrebsOnSecurity informó una actualización judicial vinculada con extorsiones a organizaciones usuarias de Snowflake y el abuso de credenciales en repositorios de datos cloud. "
            "El reporte no debe presentarse como campaña nueva contra una víctima específica; su valor operativo se limita a controles de identidad y monitoreo de sesiones en plataformas de datos. "
            "Los equipos de seguridad deben revisar cuentas privilegiadas, rotar credenciales sospechosas y validar alertas por descargas masivas."
        )
    if "nearly 800 malicious npm" in text or ("npm" in text and "infostealer" in text):
        return (
            "Investigadores identificaron una campaña con cientos de paquetes maliciosos publicados en npm para entregar malware multiplataforma, incluyendo troyanos de acceso remoto e infostealers. "
            "El mecanismo se apoya en nombres generados o similares a paquetes legítimos para entrar en proyectos de desarrollo y ejecutarse durante instalación o compilación. "
            "Los equipos de ingeniería deben bloquear dependencias no aprobadas, revisar paquetes añadidos durante la semana y exigir validación de integridad en registros internos."
        )
    if "ai recommendation poisoning" in text or "ask ai" in text:
        return (
            "Una investigación reciente describe una técnica de inyección de prompts que abusa de botones o enlaces preparados para asistentes de inteligencia artificial. "
            "El ataque no requiere malware ni credenciales robadas: induce al usuario a abrir una instrucción prellenada que puede contaminar el contexto o la memoria del asistente y alterar recomendaciones posteriores. "
            "Las organizaciones que integren asistentes de IA deben revisar enlaces generados por sitios externos, deshabilitar acciones automáticas no verificadas y capacitar a usuarios para no aceptar instrucciones prellenadas desde páginas no confiables."
        )
    if "bdthemes" in text and "wordpress" in text:
        return (
            "BleepingComputer reportó un compromiso de cadena de suministro en la infraestructura de BdThemes, desarrollador de complementos premium para WordPress. "
            "La modificación de un feed JSON remoto entregado a navegadores de administradores permitió crear cuentas administrativas no autorizadas en sitios que usaban esos componentes. "
            "Los administradores de WordPress deben actualizar los plugins afectados, revisar cuentas con privilegios creadas recientemente, invalidar sesiones administrativas y auditar cambios en archivos o configuraciones del sitio."
        )
    if "agent flaws" in text and ("aws" in text or "google" in text or "vercel" in text):
        return (
            "La investigación describe fallas en integraciones de agentes de IA conectados a servicios cloud y plataformas de despliegue como AWS, Google y Vercel. "
            "El riesgo está en la capacidad de activar herramientas o flujos auxiliares sin que el modelo procese explícitamente una instrucción maliciosa. "
            "Los equipos que usen agentes conectados a nube deben limitar permisos de herramientas, exigir aprobación humana para acciones sensibles y revisar registros de invocaciones automatizadas."
        )
    if "cloudquarry" in text or "public gcp images" in text:
        return (
            "La publicación analiza exposición de secretos en imágenes públicas de Google Cloud Platform. "
            "El hallazgo es relevante para organizaciones que construyen o publican imágenes de máquina, porque claves, tokens o archivos de configuración pueden quedar incorporados en artefactos reutilizables. "
            "Los equipos cloud deben escanear imágenes antes de publicarlas, revocar secretos encontrados y aplicar políticas que impidan almacenar credenciales en plantillas o discos base."
        )
    if "css attacks" in text and "webmail" in text:
        return (
            "Investigadores describieron técnicas basadas en CSS capaces de debilitar defensas de webmail y facilitar el robo de contraseñas o tokens cuando el contenido malicioso se renderiza en clientes vulnerables. "
            "El riesgo afecta a plataformas de correo y aplicaciones que procesan HTML de usuarios externos. "
            "Los administradores deben mantener actualizado el cliente o gateway de correo, reforzar sanitización de HTML y monitorear mensajes que intenten cargar estilos o recursos externos inusuales."
        )
    if "vmsa-2026-0006" in text or ("broadcom" in text and "vmware" in text):
        return (
            "El advisory de Broadcom alerta sobre múltiples vulnerabilidades en plataformas VMware que pueden permitir omisión de autenticación o ejecución de código según el componente afectado. "
            "La prioridad aumenta cuando vCenter, ESXi u otras consolas de virtualización administran cargas críticas o están expuestas desde redes amplias. "
            "Los equipos de infraestructura deben aplicar los parches del fabricante, restringir acceso administrativo y revisar eventos recientes de autenticación y cambios de configuración."
        )
    if "microsoft 365" in text and ("aitm" in text or "adversary-in-the-middle" in text or "payroll" in text or "ringcentral" in text):
        return (
            "La campaña reportada usa phishing adversary-in-the-middle (AiTM) contra cuentas de Microsoft 365 para capturar sesiones y acceder a correos financieros o de nómina. "
            "El riesgo principal es el abuso de sesiones válidas incluso cuando existe autenticación multifactor. "
            "Las organizaciones deben revisar reglas de correo sospechosas, accesos desde ubicaciones inusuales, consentimientos OAuth no autorizados y aplicar políticas de acceso condicional resistentes a robo de sesión."
        )
    if "clamav" in text and "cisco" in text:
        return (
            "Cisco publicó correcciones para vulnerabilidades de alta severidad en ClamAV, motor de análisis antimalware usado en múltiples pasarelas y servicios de inspección. "
            "La existencia de exploits públicos incrementa el riesgo en sistemas que procesan archivos enviados por usuarios o correo. "
            "Los administradores deben actualizar ClamAV en appliances y servidores que lo integren, limitar archivos de alto riesgo y revisar fallos o bloqueos del motor durante el procesamiento de muestras."
        )
    if "cisco ios xe" in text:
        return (
            "Cisco difundió una actualización de endurecimiento para IOS XE, sistema operativo usado en routers, switches y plataformas de red empresarial. "
            "Aunque la alerta se presenta como endurecimiento, es relevante para equipos expuestos por administración remota o integrados a redes críticas. "
            "Los responsables de red deben validar versiones, aplicar la actualización recomendada, cerrar servicios administrativos no requeridos y revisar accesos recientes a consolas de gestión."
        )
    if "ton tou" in text or "tontou" in text or "spectre v2" in text:
        return (
            "Investigadores reportaron TONTOU, una técnica de canal lateral capaz de evadir mitigaciones de Spectre v2 y filtrar información sensible en sistemas Linux bajo ciertas condiciones. "
            "El impacto depende del hardware, del aislamiento entre cargas y de la posibilidad de ejecutar código local. "
            "Los equipos de infraestructura deben aplicar microcódigo y parches del kernel, revisar entornos multiusuario o multitenant y limitar ejecución de código no confiable en servidores compartidos."
        )
    if "malicious mcp servers" in text or "coding agents exfiltrate secrets" in text:
        return (
            "La investigación advierte que servidores MCP maliciosos pueden dividir instrucciones para inducir a agentes de programación a exfiltrar secretos desde el entorno de desarrollo. "
            "El riesgo afecta a equipos que conectan asistentes de IA con repositorios, shells o sistemas internos. "
            "Los controles prioritarios son aprobar servidores MCP por lista permitida, aislar credenciales del entorno del agente, registrar comandos ejecutados y bloquear herramientas no revisadas."
        )
    if "gunra ransomware" in text:
        return (
            "La publicación vincula actividad de Gunra ransomware con explotación de fallas en tecnologías Fortinet y Schneider Electric para obtener acceso inicial o ampliar compromiso. "
            "El riesgo es relevante para organizaciones con perímetro Fortinet o componentes industriales expuestos. "
            "Los equipos deben confirmar parches en dispositivos afectados, revisar accesos VPN o administrativos recientes y validar que los respaldos críticos estén aislados y recuperables."
        )
    if "clickfix" in text and "macos" in text:
        return (
            "La campaña ClickFix utiliza dominios diseñados para ocultar señuelos de malware en macOS mediante fingerprinting del navegador y del sistema. "
            "El mecanismo busca mostrar contenido malicioso solo a objetivos compatibles y evadir análisis automatizado. "
            "Las organizaciones con equipos macOS deben bloquear descargas desde dominios no confiables, exigir instalación mediante MDM y revisar alertas de ejecución de scripts o instaladores fuera de canales oficiales."
        )
    if "passkey" in text and ("mfa" in text or "private keys" in text):
        return (
            "Investigadores describieron ataques contra implementaciones de passkeys que pueden recuperar claves sincronizadas o evadir propiedades esperadas de autenticación resistente a phishing bajo condiciones específicas. "
            "El riesgo no invalida el uso de passkeys, pero exige revisar sincronización, recuperación de cuenta y confianza en dispositivos. "
            "Los equipos de identidad deben reforzar políticas de registro de dispositivos, monitorear cambios de métodos de autenticación y proteger cuentas administrativas con controles adicionales."
        )
    if "ghostblade" in text or "darksword" in text:
        return (
            "Se observó a un actor de habla china utilizando una versión filtrada del kit DarkSword para atacar dispositivos iOS. "
            "La campaña se apoya en infraestructura falsa de inicio de sesión para entregar GHOSTBLADE contra objetivos seleccionados; los equipos móviles deben aplicar actualizaciones, bloquear dominios de phishing y reforzar controles de navegación en dispositivos corporativos."
        )
    if "joomla" in text and "ecuador" in text:
        return (
            "EcuCERT reporta una campaña de defacement contra portales institucionales basados en Joomla en Ecuador. "
            "La cadena de explotación permite crear cuentas con privilegios, cargar archivos y ejecutar código en escenarios vulnerables. "
            "Los administradores deben actualizar Joomla y sus extensiones, revisar cuentas creadas recientemente y monitorear cambios no autorizados en páginas públicas."
        )
    summary = sentence_limit(item.get("resumen") or item.get("titulo"), 3)
    if not summary or summary == item.get("titulo"):
        summary = "El riesgo debe evaluarse según presencia del producto, exposición del servicio e impacto potencial sobre activos corporativos."
    if has_raw_english(summary):
        summary = (
            "El riesgo debe evaluarse según presencia del producto, exposición del servicio e impacto potencial sobre activos corporativos. "
            "Se debe validar inventario, aplicar la corrección del fabricante y revisar registros del servicio afectado."
        )
    if item.get("fuente_id") == "cisa_ics":
        summary += " En entornos OT/industriales, se debe identificar activos con el producto afectado y aplicar las mitigaciones del fabricante."
    elif any(label in item.get("etiquetas", []) for label in ("EXPLOTADO ACTIVAMENTE", "EXPLOTACION REPORTADA")):
        summary += " Deben aplicarse las correcciones disponibles y revisarse registros del servicio afectado en busca de intentos de explotación."
    return summary


def family_summary(item: dict) -> str:
    family = item.get("familia", "")
    cves = ", ".join(item.get("cves", [])[:6])
    labels = set(item.get("etiquetas", []))
    if "Perímetro" in family:
        return (
            f"{cves} - URGENTE: se concentran vulnerabilidades en consolas de seguridad, firewalls, VPN y plataformas de administración remota. "
            "Se priorizan por exposición perimetral, presencia en KEV, explotación reportada o exploit público. "
            "La acción concreta es validar inventario expuesto, aplicar parches y revisar accesos administrativos."
        )
    if "Operaciones OT" in family:
        return (
            f"{cves} - PRIORITARIO EN OT: las CVE seleccionadas corresponden a productos industriales o componentes usados en operación. "
            "Aunque no todas implican explotación inmediata, su impacto operativo exige validar versiones instaladas y ventanas de actualización con los responsables de tecnología industrial."
        )
    if "Frameworks" in family:
        return (
            f"{cves} - Se agrupan fallas en librerías, frameworks, CMS y plataformas de desarrollo con potencial de ejecución remota, exposición de archivos o compromiso de dependencias. "
            "La acción concreta es inventariar componentes, actualizar dependencias y controlar integridad de artefactos."
        )
    if "Infraestructura" in family:
        return (
            f"{cves} - Se priorizan vulnerabilidades en plataformas corporativas y servicios de administración que pueden habilitar ejecución remota, acceso no autorizado o movimiento lateral. "
            "La acción concreta es aplicar correcciones en activos expuestos y revisar accesos recientes."
        )
    if "Kernel" in family:
        return (
            f"{cves} - Se agrupan fallas de sistemas operativos y kernel con riesgo de escalada de privilegios o compromiso local. "
            "La acción concreta es aplicar actualizaciones y revisar exposición de servicios relacionados."
        )
    if "Navegadores" in family:
        return (
            f"{cves} - Se priorizan fallas en navegadores, extensiones o software de interacción de usuario que pueden activarse mediante contenido malicioso. "
            "La acción concreta es mantener ciclos de actualización rápidos en endpoints."
        )
    suffix = " Incluye señales de explotación o PoC público." if labels & {"EXPLOTACION REPORTADA", "PoC PUBLICO"} else ""
    return f"{cves} - Vulnerabilidades relevantes agrupadas por score, criticidad e impacto potencial.{suffix}"


def title_text(item: dict) -> str:
    if item.get("fuente_id") == "ransomware_ec":
        try:
            data = json.loads(item.get("resumen") or "{}")
        except Exception:
            data = {}
        group = str(data.get("group_name") or data.get("group") or "grupo no identificado").strip()
        group = group[:1].upper() + group[1:] if group else "grupo no identificado"
        return f"Señal OSINT de ransomware en Ecuador atribuida a {group}"
    title = str(item.get("titulo") or "").strip()
    if item.get("fuente_id") == "microsoft_msrc":
        return msrc_title_es(item)
    text = f"{title} {item.get('resumen','')}".lower()
    replacements = [
        (("langflow", "n-central", "tomcat"), "CISA alerta explotación activa en Langflow, N-able N-central y Apache Tomcat"),
        (("windows internet key exchange",), "Ejecución remota de código en Windows IKE explotada activamente"),
        (("critical macos", "sharepoint", "vcenter"), "CISA confirma explotación activa en macOS, SharePoint, vCenter y Windows IKE"),
        (("windows ike",), "Ejecución remota de código en Windows IKE explotada activamente"),
        (("cve-2026-33824",), "Ejecución remota de código en Windows IKE explotada activamente"),
        (("sharepoint", "cve-2026-55040"), "Explotación activa de vulnerabilidad crítica en Microsoft SharePoint"),
        (("zimbra",), "Zimbra Collaboration es explotado mediante ejecución de comandos"),
        (("trueconf",), "TrueConf Server requiere parche urgente por explotación activa"),
        (("mlflow",), "Explotación de MLflow expone credenciales y metadatos cloud"),
        (("gitlab", "cve-2026-19478"), "GitLab corrige falla crítica explotada tras la divulgación"),
        (("elementor pro",), "Elementor Pro para WordPress permite ejecución remota de código"),
        (("form plugin flaw",), "Forminator Forms expone sitios WordPress a ejecución remota de código"),
        (("wordpress sites", "form plugin"), "Forminator Forms expone sitios WordPress a ejecución remota de código"),
        (("siemens s7",), "Amenaza activa apunta a PLC Siemens S7"),
        (("rust supply chain",), "Ataque de cadena de suministro afecta crates de Rust"),
        (("arrayref",), "Crate de Rust comprometido ejecuta malware en compilación"),
        (("redc2",), "Paquetes npm troyanizados despliegan RedC2 en Linux"),
        (("windchill", "clop"), "Cl0p usa web shells contra PTC Windchill y FlexPLM"),
        (("cl0p", "windchill"), "Cl0p usa web shells contra PTC Windchill y FlexPLM"),
        (("cavern",), "Cavern C2 usa DNS y Google Apps Script para ocultar tráfico"),
        (("safepal",), "Brecha de SafePal expone datos de clientes y eleva riesgo de phishing"),
        (("microsoft defender", "driver"), "Controlador de Microsoft Defender puede ser abusado contra herramientas de seguridad"),
        (("banking trojans",), "Troyanos bancarios Manic, Grandoreiro y ToxicPanda siguen activos"),
        (("windows task host",), "Ransomware explota vulnerabilidad en Windows Task Host"),
        (("netscaler",), "Citrix NetScaler corrige omisión crítica de autenticación"),
        (("crosswork", "secure workload"), "Cisco corrige fallas críticas en Crosswork y Secure Workload"),
        (("cisco", "crosswork"), "Cisco corrige fallas críticas en Crosswork y Secure Workload"),
        (("entra id",), "Microsoft Entra ID corrige falla crítica mitigada por el fabricante"),
        (("synkloader",), "Phishing en Microsoft Teams distribuye SynkLoader"),
        (("14,000 ip cameras",), "Operación CameraSwarm compromete cámaras IP expuestas"),
        (("cameraswarm",), "Operación CameraSwarm compromete cámaras IP expuestas"),
        (("40 malicious firefox extensions",), "Extensiones maliciosas de Firefox roban secretos Web3"),
        (("fortune 500", "azure data theft"), "Reporte de robo de datos en Azure apunta a grandes empresas"),
        (("oracle http server",), "Oracle HTTP Server y WebLogic Proxy Plug-in entran a KEV"),
        (("inc ransomware", "sonicwall", "sma 1000"), "INC Ransomware explota fallas en SonicWall SMA 1000"),
        (("registro osint", "qilin"), "Señal OSINT de ransomware asociada a Qilin en Ecuador"),
        (("check point", "authentication bypass"), "Omisión de autenticación afecta servidores de gestión Check Point"),
        (("atlassian rovo",), "Inyección de prompts afecta a Atlassian Rovo"),
        (("chrome 151",), "Chrome 151 corrige vulnerabilidades críticas del navegador"),
        (("joomla", "defacement"), "Campaña de defacement contra portales Joomla en Ecuador"),
        (("wallstreet", "ransomware"), "Actividad de ransomware Wallstreet con referencia a sectores ecuatorianos"),
        (("velocloud",), "Inyección de comandos en VeloCloud Orchestrator"),
        (("cisco secure firewall management center",), "Vulnerabilidad crítica en Cisco Secure Firewall Management Center"),
        (("macos", "malvertising"), "Campaña de malvertising contra usuarios macOS"),
        (("progress kemp loadmaster",), "Explotación de vulnerabilidad en Progress Kemp LoadMaster"),
        (("teampcp", "redis"), "Actividad de TeamPCP contra infraestructura Redis y cadena de suministro"),
        (("sharepoint", "cve-2026-45659"), "Ejecución remota de código en Microsoft SharePoint"),
        (("n-central", "hotfix"), "N-able publica hotfix para explotación en N-central"),
        (("hotel wi-fi",), "Campaña abusa de redes Wi-Fi de hoteles para entregar malware"),
        (("quickfox", "supply chain"), "Ataque de cadena de suministro contra QuickFox"),
        (("npm packages", "rat"), "Paquetes npm maliciosos entregan troyano de acceso remoto"),
        (("darksword", "ghostblade"), "Uso de DarkSword para desplegar GHOSTBLADE en iOS"),
        (("stormencryptor",), "Nueva variante StormEncryptor asociada a actividad de ransomware"),
        (("cpanel", "whm"), "Vulnerabilidad crítica en cPanel y WHM permite elevar privilegios sobre bases de datos"),
        (("cve-2026-59310",), "Explotación activa de vulnerabilidad crítica en VMware vCenter"),
        (("gunra", "fortinet"), "Gunra ransomware explota vulnerabilidades críticas en Fortinet"),
        (("sap commerce cloud",), "Falla crítica en SAP Commerce Cloud permite ejecución remota de código"),
        (("forminator",), "Forminator Forms para WordPress permite ejecución remota de código"),
        (("adobe commerce",), "Adobe Commerce recibe intentos de explotación tras la divulgación"),
        (("windows deployment services",), "Ejecución remota de código en Windows Deployment Services"),
        (("windows dhcp server",), "Ejecución remota de código en Windows DHCP Server"),
        (("screen sharing", "macos"), "Explotación contra macOS Screen Sharing expuesto"),
        (("recruitment", "bitb"), "Campaña de phishing laboral usa Browser-in-the-Browser para robar credenciales"),
        (("browser-in-the-browser",), "Campaña de phishing laboral usa Browser-in-the-Browser para robar credenciales"),
        (("jewelbug",), "Jewelbug usa XG-Web para espionaje y fraude"),
        (("deadlock ransomware",), "DeadLock ransomware usa infraestructura descentralizada"),
        (("expired domains",), "Dominios expirados son reutilizados para fraudes y malware"),
        (("windrelay",), "WindRelay convierte teléfonos Android en relays NFC para fraude"),
        (("cisco", "asa", "ftd"), "Cisco alerta explotación contra ASA y FTD"),
        (("hitachi energy apm edge",), "CISA ICS alerta vulnerabilidades en Hitachi Energy APM Edge"),
        (("ray-project ray",), "CISA KEV mantiene explotación de Ray-Project Ray"),
        (("unc6671",), "UNC6671 usa vishing para robar acceso a plataformas SaaS"),
        (("vishing", "saas"), "Campaña de vishing busca acceso a plataformas SaaS"),
        (("snowflake", "extortion"), "Caso Snowflake refuerza el riesgo de credenciales sin controles fuertes"),
        (("snowflake", "extortions"), "Caso Snowflake refuerza el riesgo de credenciales sin controles fuertes"),
        (("nearly 800 malicious npm",), "Paquetes npm maliciosos distribuyen RAT e infostealers multiplataforma"),
        (("ai recommendation poisoning",), "Inyección de prompts busca contaminar recomendaciones de asistentes de IA"),
        (("ask ai", "llm memory"), "Inyección de prompts busca contaminar recomendaciones de asistentes de IA"),
        (("bdthemes", "wordpress"), "Compromiso de BdThemes crea administradores falsos en WordPress"),
        (("agent flaws", "aws"), "Fallas en agentes de IA elevan el riesgo en integraciones cloud"),
        (("cloudquarry", "gcp"), "Imágenes públicas de GCP exponen secretos en entornos cloud"),
        (("css attacks", "webmail"), "Ataques CSS amenazan defensas de webmail y tokens de sesión"),
        (("vmsa-2026-0006",), "Broadcom alerta fallas críticas en plataformas VMware"),
        (("microsoft 365", "aitm"), "Phishing AiTM roba sesiones de Microsoft 365"),
        (("clamav", "cisco"), "Cisco corrige fallas de alta severidad en ClamAV"),
        (("cisco ios xe",), "Cisco publica endurecimiento crítico para IOS XE"),
        (("tontou",), "TONTOU evade mitigaciones Spectre v2 en sistemas Linux"),
        (("malicious mcp servers",), "Servidores MCP maliciosos pueden exfiltrar secretos desde agentes de código"),
        (("gunra ransomware",), "Gunra ransomware aprovecha fallas en Fortinet y Schneider Electric"),
        (("clickfix", "macos"), "ClickFix oculta señuelos de malware contra usuarios macOS"),
        (("passkey", "phishing-resistant mfa"), "Nuevos ataques prueban límites de passkeys y MFA resistente a phishing"),
        (("ringcentral", "microsoft 365"), "Phishing suplanta RingCentral para robar cuentas de Microsoft 365"),
        (("zapscape", "kvm"), "Zapscape permite escape de máquinas virtuales KVM anidadas"),
        (("linux sctp", "root"), "Falla en Linux SCTP permite elevar privilegios y escapar de contenedores"),
        (("critical gitea", "rce"), "Gitea corrige ejecución remota de código explotada activamente"),
        (("gitea", "actively exploited"), "Gitea corrige ejecución remota de código explotada activamente"),
        (("jfrog artifactory",), "JFrog Artifactory entra en prioridad por explotación activa"),
        (("miniorange", "wordpress"), "Ataques apuntan a plugin miniOrange de WordPress"),
        (("wordpress", "plugin", "theme", "site takeover"), "Plugins y temas de WordPress exponen sitios a toma de control"),
        (("hackers target wordpress",), "Ataques apuntan a sitios WordPress vulnerables"),
        (("next.js", "unauthenticated rce"), "Next.js corrige fallas críticas de ejecución remota"),
        (("nextjs", "unauthenticated rce"), "Next.js corrige fallas críticas de ejecución remota"),
        (("avada", "zero-click"), "Tema Avada de WordPress permite ejecución remota sin interacción"),
        (("cisa adds six known exploited vulnerabilities",), "CISA agrega seis vulnerabilidades explotadas al catálogo KEV"),
        (("google workspace breaches",), "Riesgos de brechas en Google Workspace requieren revisión de controles"),
    ]
    for keys, replacement in replacements:
        if all(key in text for key in keys):
            return replacement
    title = re.sub(r"\s+", " ", title)
    if len(title) > 160:
        title = title[:160].rsplit(" ", 1)[0]
    if has_raw_english(title):
        return "Hallazgo crítico priorizado por exposición y acción requerida"
    return title.rstrip(":")


def inline_item(item: dict) -> str:
    return (
        f"<strong>{esc(title_text(item))}:</strong> "
        f"{esc(editorial_text(item))}{cve_phrase(item)}{client_relevance_phrase(item)}{read_more(item)}"
    )


def list_section(title: str, items: list[dict], icon_html: str = "") -> str:
    if not items:
        return ""
    body = "\n".join(f"<li>{inline_item(item)}</li>" for item in items)
    return f"""
    <div class="news-item">
      <h2>{icon_html}{esc(title)}</h2>
      <ul>{body}</ul>
    </div>
    """


def highlight_section(title: str, items: list[dict]) -> str:
    if not items:
        return ""
    body = "\n".join(f"<p>{inline_item(item)}</p>" for item in items)
    return f"""
    <div class="news-item">
      <h2>&#9889; {esc(title)}</h2>
      {body}
    </div>
    """


def cve_product_text(cve: str, first: dict, item: dict) -> str:
    cve = str(cve or "").upper()
    overrides = {
        "CVE-2024-55591": "FortiOS y FortiProxy",
        "CVE-2025-24472": "FortiOS y FortiProxy",
        "CVE-2026-59310": "VMware vCenter Server",
        "CVE-2026-68820": "Windows Ancillary Function Driver for WinSock",
        "CVE-2026-58048": "cPanel y WHM",
        "CVE-2026-43500": "Hitachi Energy APM Edge",
        "CVE-2026-69414": "Microsoft Defender",
        "CVE-2026-58231": "SAP Commerce Cloud Data Hub Adapter",
        "CVE-2026-62893": "Windows Deployment Services TFTP Server",
        "CVE-2026-62823": "Windows DHCP Server",
        "CVE-2026-65400": "macOS Screen Sharing",
        "CVE-2026-33824": "Microsoft Windows Internet Key Exchange (IKE)",
        "CVE-2026-55040": "Microsoft SharePoint",
        "CVE-2026-73570": "Zimbra Collaboration Suite",
        "CVE-2026-72529": "TrueConf Server",
        "CVE-2026-72530": "TrueConf Server",
        "CVE-2026-64849": "MLflow",
        "CVE-2026-19478": "GitLab",
        "CVE-2026-32475": "Elementor Pro para WordPress",
        "CVE-2026-69836": "Microsoft Entra ID",
        "CVE-2026-21962": "Oracle HTTP Server y Oracle WebLogic Server Proxy Plug-in",
        "CVE-2026-71362": "Adobe Commerce",
        "CVE-2026-15748": "Forminator Forms para WordPress",
        "CVE-2026-64561": "KVM x86",
        "CVE-2025-62593": "Ray-Project Ray",
        "CVE-2019-1068": "Microsoft SQL Server",
        "CVE-2026-53362": "Linux Kernel",
        "CVE-2026-60004": "Gitea",
        "CVE-2026-66384": "JFrog Artifactory",
        "CVE-2026-61979": "miniOrange SAML SSO para WordPress",
        "CVE-2026-76581": "WPMU DEV Dashboard / Avada / TranslatePress / Pods / GiveWP",
        "CVE-2026-75604": "Next.js en servidores Windows",
        "CVE-2026-67276": "MikroTik RouterOS",
        "CVE-2026-67277": "MikroTik RouterOS",
        "CVE-2026-86060": "MikroTik RouterOS",
    }
    if cve in overrides:
        return overrides[cve]
    if first.get("fuente_id") == "microsoft_msrc":
        return msrc_product_name(first.get("titulo") or item.get("producto") or "")
    product = str(item.get("producto") or "").strip()
    if len(product) > 120 or product.lower().startswith(("boletín threat intelligence", "se reporta ")):
        product = title_text(first)
    if has_raw_english(product):
        product = "producto afectado según la fuente"
    return product or title_text(first) or "producto afectado"


def cve_impact_text(cve: str, first: dict, item: dict) -> str:
    cve = str(cve or "").upper()
    overrides = {
        "CVE-2024-55591": (
            "EcuCERT la asocia con una campaña de Gunra ransomware contra dispositivos Fortinet. "
            "La explotación puede facilitar acceso administrativo no autorizado a firewalls o VPN expuestos; se debe actualizar FortiOS/FortiProxy, restringir administración remota y revisar cuentas o accesos VPN sospechosos."
        ),
        "CVE-2025-24472": (
            "EcuCERT la asocia con una campaña de Gunra ransomware contra dispositivos Fortinet. "
            "La explotación puede facilitar acceso administrativo no autorizado a firewalls o VPN expuestos; se debe actualizar FortiOS/FortiProxy, restringir administración remota y revisar cuentas o accesos VPN sospechosos."
        ),
        "CVE-2026-59310": (
            "EcuCERT reporta explotación activa de una falla crítica de recorrido de directorios que puede permitir ejecución remota de código en VMware vCenter Server. "
            "Se recomienda aplicar la actualización del fabricante, retirar interfaces de administración de Internet y revisar telemetría desde el 3 de agosto por conexiones externas, tareas programadas o binarios no autorizados."
        ),
        "CVE-2026-68820": (
            "Microsoft y CISA reportan explotación activa de esta vulnerabilidad de elevación de privilegios en Windows. "
            "Debe priorizarse en servidores y estaciones Windows porque puede facilitar escalamiento posterior a compromiso inicial; se recomienda aplicar Patch Tuesday de agosto y revisar actividad anómala asociada a herramientas de post-explotación."
        ),
        "CVE-2026-58048": (
            "EcuCERT informó que un usuario autenticado de hosting podría ejecutar consultas SQL con privilegios elevados sobre MySQL o MariaDB en cPanel/WHM. "
            "Se debe aplicar la actualización del fabricante, limitar privilegios de cuentas y auditar accesos o consultas administrativas anómalas."
        ),
        "CVE-2026-43500": (
            "CISA ICS advierte afectación potencial a confidencialidad, integridad y disponibilidad en Hitachi Energy APM Edge. "
            "La prioridad es confirmar versiones instaladas en entornos OT, aplicar mitigaciones del fabricante y controlar acceso administrativo."
        ),
        "CVE-2026-69414": (
            "MSRC la clasifica como elevación de privilegios en Microsoft Defender, con divulgación pública pero sin explotación activa confirmada por la fuente oficial. "
            "Se deben aplicar las actualizaciones de Microsoft y revisar eventos anómalos relacionados con el componente."
        ),
        "CVE-2026-58231": (
            "SAP publicó correcciones para una falla crítica en SAP Commerce Cloud Data Hub Adapter que puede permitir ejecución remota de código sin autenticación. "
            "Se debe aplicar el parche del fabricante y revisar exposición del componente."
        ),
        "CVE-2026-62893": (
            "La vulnerabilidad corresponde a ejecución remota de código en Windows Deployment Services TFTP Server. "
            "En entornos con PXE/WDS habilitado, el servicio puede convertirse en superficie de ataque por red; se debe aplicar la actualización de Microsoft o deshabilitar TFTP/WDS cuando no sea necesario."
        ),
        "CVE-2026-62823": (
            "La vulnerabilidad permite ejecución remota de código en Windows DHCP Server bajo condiciones de red. "
            "Por tratarse de infraestructura interna crítica, se debe aplicar la actualización de Microsoft, limitar exposición del servicio a segmentos autorizados y revisar eventos anómalos del rol DHCP."
        ),
        "CVE-2026-65400": (
            "La fuente reporta explotación contra sistemas macOS con Screen Sharing expuesto a Internet. "
            "El riesgo es alto cuando VNC o servicios de administración remota están publicados; se debe actualizar macOS, deshabilitar Screen Sharing si no es requerido y restringir acceso mediante VPN o listas de control."
        ),
        "CVE-2026-33824": (
            "CISA confirmó explotación activa de esta vulnerabilidad crítica de ejecución remota de código en Windows IKE. "
            "Se debe aplicar la actualización de Microsoft, validar exposición de servicios IKE/IPsec y revisar telemetría de red por intentos de explotación."
        ),
        "CVE-2026-55040": (
            "CISA confirmó explotación activa de esta falla crítica en Microsoft SharePoint. "
            "Se debe parchear la granja afectada, restringir acceso a portales sensibles y revisar autenticaciones, cargas y cambios administrativos recientes."
        ),
        "CVE-2026-73570": (
            "CISA confirmó explotación activa de una inyección de comandos en Zimbra Collaboration Suite. "
            "Se debe actualizar Zimbra, revisar logs SMTP/web y buscar procesos anómalos ejecutados por el usuario del servicio."
        ),
        "CVE-2026-72529": (
            "TrueConf Server contiene una omisión de autenticación explotada activamente que permite ejecutar scripts en condiciones de red. "
            "Se debe actualizar el servidor, limitar exposición del puerto afectado y revisar accesos remotos inusuales."
        ),
        "CVE-2026-72530": (
            "TrueConf Server contiene una inyección de código explotada activamente que puede permitir ejecución en el host. "
            "Se debe aplicar la corrección del fabricante y revisar actividad asociada a conexiones no autorizadas."
        ),
        "CVE-2026-64849": (
            "MLflow contiene una vulnerabilidad SSRF explotada activamente que puede alcanzar servicios internos o metadatos cloud. "
            "Se debe actualizar MLflow, retirar instancias expuestas y rotar credenciales si existió acceso no autorizado."
        ),
        "CVE-2026-19478": (
            "GitLab corrigió una falla crítica que permite a atacantes no autenticados modificar o eliminar proyectos públicos y datos de usuario. "
            "Se debe actualizar GitLab, revisar integridad de repositorios y auditar tokens o automatizaciones asociadas."
        ),
        "CVE-2026-32475": (
            "Elementor Pro para WordPress permite carga de archivos PHP y ejecución remota de código. "
            "Se debe actualizar el plugin, revisar archivos cargados y validar cuentas administrativas."
        ),
        "CVE-2026-69836": (
            "Microsoft corrigió una vulnerabilidad de severidad máxima en Entra ID, servicio central de identidad cloud. "
            "El impacto potencial afecta la capa de autenticación y autorización de Microsoft 365 y aplicaciones corporativas; se recomienda revisar alertas de identidad, accesos privilegiados, consentimientos OAuth anómalos y cambios recientes en aplicaciones empresariales."
        ),
        "CVE-2026-21962": (
            "CISA confirmó explotación activa contra Oracle HTTP Server y Oracle WebLogic Server Proxy Plug-in. "
            "La falla puede permitir acceso o modificación no autorizada de datos críticos; se debe aplicar la actualización de Oracle y revisar registros de acceso."
        ),
        "CVE-2026-71362": (
            "SecurityWeek reportó intentos de explotación poco después de la divulgación y publicación de parches para Adobe Commerce. "
            "Se debe aplicar el parche del fabricante, revisar actividad anómala posterior a la publicación y priorizar tiendas expuestas a Internet."
        ),
        "CVE-2026-15748": (
            "La vulnerabilidad crítica en Forminator Forms para WordPress puede permitir ejecución remota de código mediante carga maliciosa de PHP. "
            "Se debe actualizar el plugin, revisar archivos cargados recientemente y validar cuentas administrativas."
        ),
        "CVE-2026-64561": (
            "La vulnerabilidad afecta lógica de KVM x86 asociada a virtualización. "
            "En hosts que ejecuten cargas virtualizadas, se debe aplicar la actualización publicada por el proveedor y validar exposición de virtualización anidada o cargas no confiables."
        ),
        "CVE-2025-62593": (
            "CISA mantiene esta vulnerabilidad en KEV por explotación conocida; Ray-Project Ray contiene una inyección de código que puede permitir ejecución remota. "
            "Se recomienda actualizar el componente, restringir acceso a clústeres Ray y revisar jobs ejecutados fuera de procesos autorizados."
        ),
        "CVE-2019-1068": (
            "CISA reporta explotación conocida de esta vulnerabilidad de ejecución remota de código en Microsoft SQL Server. "
            "La explotación puede permitir ejecución de comandos con los permisos de la cuenta del motor de base de datos. "
            "Se debe confirmar el nivel de parche en instancias SQL Server, priorizar servidores expuestos o con conectividad amplia y revisar actividad anómala de la cuenta de servicio."
        ),
        "CVE-2026-53362": (
            "CISA reporta explotación activa de una vulnerabilidad en Linux Kernel asociada al subsistema de red IPv6. "
            "El impacto puede facilitar escalamiento de privilegios y corrupción de memoria en sistemas vulnerables. "
            "Se debe actualizar el kernel y priorizar servidores Linux multiusuario, bastiones, hosts de contenedores y sistemas expuestos."
        ),
        "CVE-2026-60004": (
            "La vulnerabilidad en Gitea permite ejecución de comandos mediante procesamiento de parches en repositorios donde el atacante logra permisos de escritura. "
            "CISA confirmó explotación activa, por lo que las instancias autogestionadas deben actualizarse y revisar hooks, procesos y actividad reciente de repositorios."
        ),
        "CVE-2026-66384": (
            "CISA reporta explotación activa de una vulnerabilidad en JFrog Artifactory que permite escritura fuera de la ruta prevista bajo condiciones específicas de repositorios remotos Docker. "
            "Se debe actualizar Artifactory, revisar integridad de repositorios y auditar escrituras recientes en rutas no esperadas."
        ),
        "CVE-2026-61979": (
            "La vulnerabilidad afecta el plugin miniOrange SAML SSO para WordPress y puede permitir omisión de autenticación mediante respuestas SAML falsificadas. "
            "Se debe actualizar el plugin, revisar cuentas administrativas y auditar inicios de sesión o cambios recientes en sitios WordPress."
        ),
        "CVE-2026-76581": (
            "La vulnerabilidad afecta plugins o temas de WordPress y puede permitir omisión de autenticación, toma de control del sitio o ejecución de código. "
            "Se debe actualizar los componentes afectados, revisar usuarios administradores y buscar archivos modificados o cargas sospechosas."
        ),
        "CVE-2026-75604": (
            "La vulnerabilidad afecta Next.js en servidores con sistema de archivos Windows y puede permitir ejecución remota no autenticada mediante recorrido de rutas. "
            "Se debe actualizar Next.js, validar despliegues expuestos y revisar accesos o errores asociados al procesamiento de rutas y archivos."
        ),
        "CVE-2026-67276": (
            "EcuCERT difundió una alerta sobre vulnerabilidades críticas en MikroTik RouterOS con posible impacto sobre equipos de frontera expuestos. "
            "El riesgo se concentra en administración remota y servicios SSH habilitados; se debe aplicar la corrección del fabricante, restringir acceso administrativo y revisar autenticaciones, cambios de configuración y accesos remotos sospechosos."
        ),
        "CVE-2026-67277": (
            "EcuCERT difundió una alerta sobre vulnerabilidades críticas en MikroTik RouterOS que pueden afectar disponibilidad o exponer información del dispositivo en condiciones específicas. "
            "Los equipos deben actualizar RouterOS, limitar servicios de prueba o administración desde redes no confiables y revisar reinicios, fallos o accesos no autorizados."
        ),
        "CVE-2026-86060": (
            "EcuCERT difundió una alerta sobre vulnerabilidades críticas en MikroTik RouterOS, incluyendo una falla que puede permitir manipulación de privilegios mediante credenciales o parámetros maliciosos. "
            "Se debe actualizar RouterOS, restringir administración remota, auditar usuarios locales y revisar cambios de privilegios o sesiones recientes."
        ),
    }
    if cve in overrides:
        return overrides[cve]
    dossier_impact = str(item.get("impacto") or "").strip()
    if dossier_impact:
        if has_raw_english(dossier_impact):
            return (
                "La fuente primaria reporta una vulnerabilidad de alta prioridad con impacto operativo sobre el producto afectado. "
                "Se debe validar presencia del componente, aplicar la actualización del fabricante y revisar registros por intentos de explotación."
            )
        return dossier_impact
    if first.get("fuente_id") == "microsoft_msrc":
        return msrc_editorial_text(first)
    impact = editorial_text(first) if first else str(item.get("impacto") or "").strip()
    if has_raw_english(impact):
        return (
            "La fuente primaria reporta una vulnerabilidad de alta prioridad con impacto operativo sobre el producto afectado. "
            "Se debe validar presencia del componente, aplicar la actualización del fabricante y revisar registros por intentos de explotación."
        )
    return impact


def cve_active_exploitation(item: dict, first: dict) -> bool:
    labels = set(item.get("etiquetas", []) or [])
    labels.update(first.get("etiquetas", []) or [])
    for ref in item.get("fuentes", []) or []:
        labels.update(ref.get("etiquetas", []) or [])
        if ref.get("kev") or str(ref.get("fuente_id") or "").lower() == "cisa_kev":
            return True
    if "EXPLOTADO ACTIVAMENTE" in labels:
        return True
    if item.get("kev") or first.get("kev"):
        return True
    return str(item.get("fuente_id") or first.get("fuente_id") or "").lower() == "cisa_kev"


def cve_public_poc(item: dict, first: dict) -> bool:
    labels = set(item.get("etiquetas", []) or [])
    labels.update(first.get("etiquetas", []) or [])
    for ref in item.get("fuentes", []) or []:
        labels.update(ref.get("etiquetas", []) or [])
    if "PoC PUBLICO" in labels:
        return True
    text = " ".join(str(value or "") for value in (
        item.get("titulo"),
        item.get("resumen"),
        item.get("impacto"),
        first.get("titulo"),
        first.get("resumen"),
        first.get("impacto"),
    )).lower()
    return any(term in text for term in ("proof-of-concept", "proof of concept", "poc", "exploit público", "exploit publico"))


def cve_network_vector(item: dict, first: dict) -> str:
    _, item_vector = extract_cvss(item)
    _, first_vector = extract_cvss(first)
    vector = item_vector or first_vector
    for ref in item.get("fuentes", []) or []:
        _, ref_vector = extract_cvss(ref)
        vector = vector or ref_vector
    if "AV:N" in vector:
        return "Red (AV:N)"
    text = " ".join(str(value or "") for value in (
        item.get("titulo"),
        item.get("resumen"),
        item.get("impacto"),
        first.get("titulo"),
        first.get("resumen"),
        first.get("impacto"),
    )).lower()
    remote_terms = (
        "remote code execution",
        "remote unauthenticated",
        "remote attacker",
        "over a network",
        "network-based",
        "network attack",
        "explotación remota",
        "ejecución remota",
        "atacante remoto",
        "por red",
        "en condiciones de red",
        "a través de la red",
    )
    local_terms = ("local privilege", "local attacker", "elevación local", "privilegios locales")
    if any(term in text for term in remote_terms) and not any(term in text for term in local_terms):
        return "Red (AV:N)"
    return "No confirmado"


def cve_class_text(cve: str, product: str, first: dict, item: dict) -> str:
    text = " ".join(
        str(value or "")
        for value in (
            cve,
            product,
            item.get("producto"),
            item.get("titulo"),
            item.get("impacto"),
            first.get("titulo"),
            first.get("resumen"),
        )
    ).lower()
    if any(term in text for term in ("fortinet", "fortigate", "fortios", "fortiproxy", "fortimanager", "fortiweb", "cisco asa", "firepower", "netscaler", "gateway", "vpn", "firewall", "mikrotik", "routeros")):
        return "Tecnología de frontera / acceso remoto"
    if any(term in text for term in ("windows", "windows server", "macos", "linux", "kernel", "kvm", "winsock", "internet key exchange", " ike", "dhcp server", "deployment services", "screen sharing")):
        return "Sistema operativo / servicio base"
    if any(term in text for term in ("entra id", "azure active directory", "microsoft 365", "office 365", "google workspace", "gmail", "google drive", "sharepoint online", "exchange online")):
        return "SaaS corporativo / identidad"
    if any(term in text for term in ("wordpress", "elementor", "forminator", "zimbra", "gitlab", "trueconf", "oracle http server", "weblogic", "sharepoint", "sap commerce", "adobe commerce", "cpanel", "whm", "tomcat")):
        return "Aplicación / servicio empresarial"
    if any(term in text for term in ("plc", "siemens", "simatic", "scada", "ics")):
        return "Tecnología OT / industrial"
    if any(term in text for term in ("chrome", "edge", "firefox", "browser", "webgl", "dawn")):
        return "Navegador / cliente web"
    if any(term in text for term in ("sql server", "mysql", "mariadb", "postgresql", "oracle database", "database")):
        return "Base de datos"
    return "Software / componente empresarial"


def cve_section(items: list[dict]) -> str:
    if not items:
        return ""
    rows = []
    for item in items:
        refs = item.get("fuentes", [])
        first = refs[0] if refs else {}
        url = public_url(first.get("url", ""))
        link_start = f'<a href="{esc(url)}" target="_blank">' if url else ""
        link_end = "</a>" if url else ""
        cve = item.get("cve") or ", ".join(item.get("cves", [])[:1])
        producto = cve_product_text(cve, first, item)
        impacto = cve_impact_text(cve, first, item)
        fuente = first.get("fuente") or "fuente trazada en dossier"
        active = cve_active_exploitation(item, first)
        poc = cve_public_poc(item, first)
        vector = cve_network_vector(item, first)
        cve_label = f"<strong>{esc(cve)}</strong>" if active else esc(cve)
        cvss_suffix = cve_display_suffix(cve, item, first)
        estado = " <strong>(Explotada activamente)</strong>" if active else ""
        cve_link = f"{link_start}{cve_label}{cvss_suffix}{link_end}" if url else f"{cve_label}{cvss_suffix}"
        clase = cve_class_text(cve, producto, first, item)
        relevance = client_relevance_phrase(item)
        rows.append(
            f"<li>{cve_link}:{estado} "
            f"Explotación en campo: {esc('Sí' if active else 'No confirmada')}. "
            f"PoC público: {esc('Sí' if poc else 'No confirmado')}. "
            f"Vector de ataque: {esc(vector)}. "
            f"Clase: {esc(clase)}. "
            f"Afecta a {esc(producto)}. {esc(impacto)} "
            f"Fuente principal: {esc(fuente)}.{relevance}</li>"
        )
    return f"""
    <div class="news-item">
      <h2>&#9888;&#65039; Principales CVEs</h2>
      <ul>{''.join(rows)}</ul>
    </div>
    """


def reference_title(item: dict) -> str:
    cves = {str(cve).upper() for cve in item.get("cves", [])}
    source = str(item.get("fuente") or "")
    title = str(item.get("titulo") or "")
    text = f"{source} {title} {' '.join(cves)}".lower()
    if "CVE-2024-55591" in cves or "CVE-2025-24472" in cves or ("gunra" in text and "fortinet" in text):
        return "Gunra ransomware explota vulnerabilidades críticas en Fortinet"
    if "CVE-2026-59310" in cves or "vmware vcenter" in text:
        return "Explotación activa de vulnerabilidad crítica en VMware vCenter"
    if "CVE-2026-68820" in cves or "winsock" in text:
        return "Zero-day de Windows WinSock explotado activamente"
    if "CVE-2026-33824" in cves:
        return "Ejecución remota de código en Windows IKE explotada activamente"
    if "critical macos" in text and "sharepoint" in text and "vcenter" in text and cves & {"CVE-2026-33824", "CVE-2026-55040", "CVE-2026-59310", "CVE-2026-65400"}:
        return "CISA confirma explotación activa en macOS, SharePoint, vCenter y Windows IKE"
    if "CVE-2026-55040" in cves:
        return "Explotación activa de vulnerabilidad crítica en Microsoft SharePoint"
    if "CVE-2026-73570" in cves or "zimbra" in text:
        return "Zimbra Collaboration es explotado mediante ejecución de comandos"
    if "CVE-2026-72529" in cves or "CVE-2026-72530" in cves or "trueconf" in text:
        return "TrueConf Server requiere parche urgente por explotación activa"
    if "CVE-2026-64849" in cves or "mlflow" in text:
        return "Explotación de MLflow expone credenciales y metadatos cloud"
    if "CVE-2026-19478" in cves or "gitlab" in text:
        return "GitLab corrige falla crítica explotada tras la divulgación"
    if "CVE-2026-32475" in cves or "elementor pro" in text:
        return "Elementor Pro para WordPress permite ejecución remota de código"
    if "form plugin flaw" in text or ("wordpress sites" in text and "form plugin" in text):
        return "Forminator Forms expone sitios WordPress a ejecución remota de código"
    if "siemens s7" in text or "plc" in text and "ai" in text:
        return "Amenaza activa apunta a PLC Siemens S7"
    if "rust supply chain" in text or "arrayref" in text:
        return "Ataque de cadena de suministro afecta crates de Rust"
    if "redc2" in text:
        return "Paquetes npm troyanizados despliegan RedC2 en Linux"
    if "clop" in text and "windchill" in text or "cl0p" in text and "windchill" in text:
        return "Cl0p usa web shells contra PTC Windchill y FlexPLM"
    if "cavern" in text:
        return "Cavern C2 usa DNS y Google Apps Script para ocultar tráfico"
    if "safepal" in text:
        return "Brecha de SafePal expone datos de clientes y eleva riesgo de phishing"
    if "microsoft defender" in text and "driver" in text:
        return "Controlador de Microsoft Defender puede ser abusado contra herramientas de seguridad"
    if "banking trojans" in text or "grandoreiro" in text or "toxicpanda" in text:
        return "Troyanos bancarios Manic, Grandoreiro y ToxicPanda siguen activos"
    if "windows task host" in text:
        return "Ransomware explota vulnerabilidad en Windows Task Host"
    if "netscaler" in text:
        return "Citrix NetScaler corrige omisión crítica de autenticación"
    if "cisco" in text and ("crosswork" in text or "secure workload" in text):
        return "Cisco corrige fallas críticas en Crosswork y Secure Workload"
    if "entra id" in text or "CVE-2026-69836" in cves:
        return "Microsoft Entra ID corrige falla crítica mitigada por el fabricante"
    if "synkloader" in text:
        return "Phishing en Microsoft Teams distribuye SynkLoader"
    if "14,000 ip cameras" in text or "cameraswarm" in text:
        return "Operación CameraSwarm compromete cámaras IP expuestas"
    if "40 malicious firefox extensions" in text or "offside wallet" in text:
        return "Extensiones maliciosas de Firefox roban secretos Web3"
    if "fortune 500" in text and "azure data theft" in text:
        return "Reporte de robo de datos en Azure apunta a grandes empresas"
    if "CVE-2026-21962" in cves or "oracle http server" in text or "weblogic server proxy plug-in" in text:
        return "Oracle HTTP Server y WebLogic Proxy Plug-in entran a KEV"
    if "ransomware.live" in text or "sector other" in text:
        return "Señal OSINT de ransomware en Ecuador atribuida a Settra"
    if "CVE-2026-58048" in cves or ("cpanel" in text and "whm" in text):
        return "Vulnerabilidad crítica en cPanel y WHM permite elevar privilegios sobre bases de datos"
    if "CVE-2026-69414" in cves or "defender" in text:
        return "Elevación de privilegios en Microsoft Defender"
    if "CVE-2026-55040" in cves:
        return "Explotación de vulnerabilidad en Microsoft SharePoint"
    if "CVE-2026-58231" in cves or "sap commerce cloud" in text:
        return "Falla crítica en SAP Commerce Cloud permite ejecución remota de código"
    if "CVE-2026-62893" in cves or "deployment services" in text:
        return "Ejecución remota de código en Windows Deployment Services"
    if "CVE-2026-62823" in cves or "dhcp server" in text:
        return "Ejecución remota de código en Windows DHCP Server"
    if "CVE-2026-65400" in cves:
        return "Explotación contra macOS Screen Sharing expuesto"
    if "browser-in-the-browser" in text or "recruitment" in text:
        return "Campaña de phishing laboral usa Browser-in-the-Browser"
    if "jewelbug" in text:
        return "Jewelbug usa XG-Web para espionaje y fraude"
    if "CVE-2026-43500" in cves or "hitachi energy" in text:
        return "CISA ICS alerta vulnerabilidades en Hitachi Energy APM Edge"
    if "CVE-2025-62593" in cves or "ray-project ray" in text:
        return "CISA KEV mantiene explotación de Ray-Project Ray"
    if "CVE-2026-71362" in cves or "adobe commerce" in text:
        return "Adobe Commerce recibe intentos de explotación tras la divulgación"
    if "CVE-2026-15748" in cves or "forminator" in text:
        return "Forminator Forms para WordPress permite ejecución remota de código"
    if "CVE-2026-64561" in cves or "kvm: x86" in text:
        return "Actualización para vulnerabilidad en KVM x86"
    return title_text(item)


def references_section(items: list[dict]) -> str:
    links = []
    seen = set()
    for item in items:
        url = public_url(item.get("url", ""))
        if not url or url in seen:
            continue
        seen.add(url)
        cves = [str(cve).upper() for cve in item.get("cves", [])[:3]]
        source = str(item.get("fuente") or "").strip()
        title = reference_title(item)
        title = re.sub(r"^Boletín Threat Intelligence Ecuador 2026-08-17:\s*", "", title, flags=re.I)
        if len(title) > 95:
            title = title[:95].rsplit(" ", 1)[0]
        label = " - ".join(part for part in (source, ", ".join(cves), title) if part)
        links.append((label or url, url))
    body = "\n".join(f'<li style="margin-bottom: 5px;"><a href="{esc(url)}" target="_blank">{esc(label)}</a></li>' for label, url in links)
    return f"""
    <div class="news-item">
      <h2>&#128269; Referencias</h2>
      <ul style="font-size: 12px; line-height: 1.35; columns: 2; -webkit-columns: 2;">{body}</ul>
    </div>
    """


def render(dossier: dict) -> str:
    sec = dossier["secciones"]
    html_doc = f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Altel Ciberseguridad - Noticias Destacadas</title>
  <style>
    body {{
      font-family: Arial, sans-serif;
      margin: 0;
      padding: 20px;
      line-height: 1.6;
      background-color: #f4f7fa;
      color: #333;
    }}
    .container {{
      max-width: 800px;
      margin: auto;
      background: #fff;
      padding: 30px;
      border-radius: 8px;
      box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    }}
    header {{
      position: relative;
      display: inline-flex;
      flex-direction: row;
      align-items: center;
      text-align: left;
      margin-bottom: 10px;
      padding: 10px 20px;
      color: rgb(255, 255, 255);
      overflow: hidden;
      border-radius: 8px;
    }}
    header::before {{
      content: "";
      position: absolute;
      top: 0; left: 0; right: 0; bottom: 0;
      background-image: url('https://st3.depositphotos.com/10080544/35998/i/450/depositphotos_359988224-stock-photo-shield-icon-cyber-security-digital.jpg');
      background-size: cover;
      background-position: center;
      border-radius: 8px;
      opacity: 0.65;
      z-index: 0;
    }}
    header * {{ position: relative; z-index: 1; }}
    header img {{ max-width: 230px; border-radius: 8px; }}
    h1 {{ color: #ffffff; font-size: 28px; letter-spacing: 0; }}
    h2 {{ color: #0074a6; font-size: 20px; }}
    ul {{ padding-left: 20px; }}
    li {{ margin-bottom: 12px; }}
    .news-item {{ margin-bottom: 20px; }}
    .footer {{ text-align: center; font-size: 12px; color: #777; margin-top: 30px; }}
    section {{ text-align: justify; }}
    .info-button {{
      display: inline-block;
      margin-left: 8px;
      padding: 1px 4px;
      font-size: 0.7rem;
      color: #ffffff;
      background-color: #0097db;
      border-radius: 10px;
      text-decoration: none;
      transition: background-color 0.3s ease;
      white-space: nowrap;
    }}
    .info-button:hover {{ background-color: #0056b3; }}
    a {{ color: #0074a6; }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>{title_label(dossier)}</h1>
      <img src="https://i.postimg.cc/ZRqZTMV2/logo-Altel.png" alt="Altel Ciberseguridad Logo">
    </header>
    <section>
      <p style="font-size: 10pt;"><em>{period_label(dossier)}</em></p>
      {client_label(dossier)}
      {highlight_section('Amenaza de la Semana', sec.get('amenaza_semana', []))}
      {list_section('Seguridad Ecuador', sec.get('seguridad_ecuador', []), '<img src="https://upload.wikimedia.org/wikipedia/commons/e/e8/Flag_of_Ecuador.svg" alt="Bandera Ecuador" width="35" style="vertical-align: middle; margin-right: 10px;">')}
      {list_section('Noticias Principales', sec.get('noticias_principales', []), '&#128276; ')}
      {cve_section(sec.get('principales_cves', []))}
      {list_section('Alrededor del Mundo Cibernético', sec.get('alrededor_mundo', []), '&#128240; ')}
      {references_section(sec.get('referencias', []))}
    </section>
    <div class="footer">
      <p>&#128233; Este es un bolet&iacute;n informativo. Para m&aacute;s detalles, consulte las fuentes oficiales de ciberseguridad.</p>
    </div>
  </div>
</body>
</html>"""
    return html_doc


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dossier", nargs="?")
    args = ap.parse_args()
    if args.dossier:
        path = Path(args.dossier)
    else:
        dossiers = sorted(STORE.glob("dossier-*.json"))
        if not dossiers:
            raise SystemExit("No hay dossier para renderizar.")
        path = dossiers[-1]
    dossier = json.loads(path.read_text(encoding="utf-8"))
    REPORTS.mkdir(parents=True, exist_ok=True)
    suffix = ""
    cliente = dossier.get("cliente") or {}
    if cliente.get("nombre"):
        suffix = "_" + re.sub(r"[^A-Za-z0-9]+", "", cliente["nombre"].upper())
    out = REPORTS / f"AltelThreatIntell_{dossier['semana'].replace('-', '')}{suffix}.html"
    out.write_text(render(dossier), encoding="utf-8")
    print(out)
    if dossier.get("brechas"):
        print("NOTAS INTERNAS:")
        for note in dossier["brechas"]:
            print(f"- {note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
