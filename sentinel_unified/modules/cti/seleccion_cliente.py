"""Seleccion interna estricta de hallazgos por cliente.

El resultado de este modulo es solo para backend: no se renderiza en HTML y no
debe enviarse directamente al cliente.
"""

from __future__ import annotations

import re


BROAD_TERMS = {
    "aws", "gcp", "google", "microsoft", "windows", "linux", "cisco", "vpn",
    "ssh", "rdp", "database", "sql", "mysql", "postgresql", "oracle",
    "kernel", "defender",
    "palo alto",
    "container", "docker", "firewall", "backup",
}

TYPE_KEYWORDS = {
    "zero-day": "zero-day",
    "zero day": "zero-day",
    "actively exploited": "explotacion activa",
    "explotacion activa": "explotacion activa",
    "exploited in the wild": "explotacion activa",
    "remote code execution": "ejecucion remota de codigo",
    "rce": "ejecucion remota de codigo",
    "authentication bypass": "omision de autenticacion",
    "auth bypass": "omision de autenticacion",
    "privilege escalation": "escalamiento de privilegios",
    "command injection": "inyeccion de comandos",
    "sql": "inyeccion SQL",
    "ransomware": "ransomware",
    "phishing": "phishing",
    "malware": "malware",
}

SEVERITY_TERMS = ("critical", "critica", "crítica", "high severity", "alta severidad")


def text_of(item: dict) -> str:
    return " ".join(str(item.get(k, "")) for k in ("titulo", "resumen", "url", "fuente", "fuente_id")).lower()


def affected_text(item: dict) -> str:
    return " ".join(str(item.get(k, "")) for k in ("titulo", "product", "vendor", "url")).lower()


def term_in_text(term: str, text: str) -> bool:
    term = term.lower().strip()
    if not term:
        return False
    if re.fullmatch(r"[a-z0-9][a-z0-9.+#-]{1,5}", term):
        return re.search(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])", text) is not None
    if " " in term or "/" in term or "-" in term:
        return re.search(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])", text) is not None
    return term in text


def product_terms(tecnologia: dict) -> list[str]:
    terms = [str(t).lower().strip() for t in tecnologia.get("terms", ()) if str(t).strip()]
    return [t for t in terms if t not in BROAD_TERMS and len(t) > 2]


def os_relation(tecnologia: dict, item: dict, text: str) -> str:
    affected = affected_text(item)
    name = tecnologia.get("nombre", "").lower()
    if "linux" in name:
        if any(term in affected for term in ("linux kernel", "kernel linux", "ubuntu", "debian", "red hat", "rhel", "centos", "openssh", "glibc", "systemd", "kvm")):
            return "sistema_operativo"
    if "windows" in name and "microsoft 365" not in name and "active directory" not in name:
        if item.get("vendor", "").lower() == "microsoft" and re.search(r"(?<![a-z0-9])windows(?![a-z0-9])", affected):
            return "sistema_operativo"
        if any(term_in_text(term, affected) for term in ("windows server", "microsoft windows", "remote desktop", "rdp", "windows remote desktop")):
            return "sistema_operativo"
    return ""


def cloud_relation(tecnologia: dict, text: str) -> str:
    name = tecnologia.get("nombre", "").lower()
    if "amazon web services" in name or "aws" in name:
        if any(term_in_text(t, text) for t in ("aws", "amazon web services", "cloudtrail")):
            return "servicio_exacto"
    if "google cloud" in name or "gcp" in name:
        if any(term_in_text(t, text) for t in ("google cloud", "gcp", "cloud armor", "cloud logging", "security command center")):
            return "servicio_exacto"
    return ""


def relation_level(tecnologia: dict, item: dict) -> str:
    text = text_of(item)
    affected = affected_text(item)
    for term in product_terms(tecnologia):
        if term_in_text(term, affected):
            if any(word in tecnologia.get("categoria", "").lower() for word in ("saas", "nube", "cloud")):
                return "servicio_exacto"
            return "producto_exacto"
    cloud = cloud_relation(tecnologia, affected)
    if cloud:
        return cloud
    os_level = os_relation(tecnologia, item, text)
    if os_level:
        return os_level
    category = tecnologia.get("categoria", "").lower()
    if "sector" in category:
        return "sector"
    return ""


def finding_kind(item: dict) -> str:
    text = text_of(item)
    found = [label for key, label in TYPE_KEYWORDS.items() if key in text]
    if item.get("cves"):
        found.insert(0, "vulnerabilidad")
    return ", ".join(dict.fromkeys(found)) or "hallazgo de seguridad"


def title_es(item: dict) -> str:
    title = str(item.get("titulo") or "").strip()
    text = text_of(item)
    replacements = [
        (("microsoft 365", "aitm"), "Phishing AiTM roba sesiones de Microsoft 365"),
        (("cisco ios xe",), "Cisco publica actualizacion de seguridad para IOS XE"),
        (("vmware", "vmsa"), "Broadcom publica advisory de seguridad para VMware"),
        (("n-central",), "N-able publica hotfix de seguridad para N-central"),
        (("progress kemp loadmaster",), "Explotacion activa afecta Progress Kemp LoadMaster"),
        (("chrome",), "Google Chrome corrige vulnerabilidades recientes"),
        (("atlassian rovo",), "Inyeccion de prompts afecta a Atlassian Rovo"),
        (("quickfox",), "Instalador troyanizado de QuickFox entrega backdoor"),
        (("npm",), "Paquetes npm maliciosos distribuyen malware"),
        (("bdthemes",), "Compromiso de BdThemes crea administradores falsos en WordPress"),
    ]
    for terms, replacement in replacements:
        if all(term in text for term in terms):
            return replacement
    if title:
        return re.sub(r"\s+", " ", title).rstrip(":")[:160]
    return "Hallazgo de seguridad reciente"


def exploitation_state(item: dict) -> str:
    labels = set(item.get("etiquetas", []))
    if "EXPLOTADO ACTIVAMENTE" in labels or item.get("kev"):
        return "explotacion activa confirmada por CISA KEV"
    if "EXPLOTACION REPORTADA" in labels:
        return "explotacion reportada por la fuente"
    if "PoC PUBLICO" in labels:
        return "prueba de concepto publica reportada"
    return "no se confirma explotacion activa en la fuente consultada"


def selected_finding(item: dict, tecnologia: dict | None, level: str, tipo: str = "directo") -> dict:
    cves = item.get("cves", [])
    title = str(item.get("titulo") or "")
    resumen = re.sub(r"\s+", " ", str(item.get("resumen") or "")).strip()
    producto = tecnologia.get("nombre") if tecnologia else item.get("product") or title
    return {
        "tipo": tipo,
        "nivel_coincidencia": level,
        "tecnologia_cliente": tecnologia.get("nombre", "") if tecnologia else "",
        "titulo_original": title,
        "titulo_propuesto_espanol": title_es(item),
        "fecha_publicacion": item.get("fecha", ""),
        "fuente": item.get("fuente", ""),
        "url": item.get("url", ""),
        "cve": ", ".join(cves),
        "producto_afectado": producto,
        "versiones_afectadas": item.get("versiones_afectadas") or "no disponibles en la fuente consultada",
        "amenaza_o_vulnerabilidad": finding_kind(item),
        "mecanismo": resumen[:420] or "la fuente no publica detalle tecnico suficiente",
        "impacto": resumen[:420] or "impacto no especificado por la fuente",
        "evidencia_explotacion": exploitation_state(item),
        "accion_recomendada": "validar si la version instalada se encuentra dentro del rango afectado y aplicar el parche o mitigacion indicada por la fuente oficial",
    }


def acceptable_item(item: dict) -> bool:
    text = text_of(item)
    if not item.get("reportable", True) or item.get("requiere_verificacion"):
        return False
    if "grupo no identificado" in text:
        return False
    if "#stopransomware" in text or "ransomware-as-a-service" in text:
        return False
    if any(term in text for term in ("in other news:", "pleads guilty", "slipped under the radar")):
        return False
    if not item.get("url") or not item.get("fecha"):
        return False
    return True


def priority_tuple(finding: dict, item: dict) -> tuple:
    order = {
        "producto_exacto": 70,
        "servicio_exacto": 65,
        "componente_confirmado": 60,
        "sistema_operativo": 45,
        "sector": 25,
        "general": 0,
    }
    text = text_of(item)
    exploit = 40 if "explotacion activa" in finding["evidencia_explotacion"] else 0
    critical = 20 if any(term in text for term in SEVERITY_TERMS) else 0
    return (order.get(finding["nivel_coincidencia"], 0) + exploit + critical, item.get("score", 0), item.get("fecha", ""))


def internal_client_selection(cliente: dict, direct_items: list[dict], general_items: list[dict], spaces: int) -> dict:
    direct = []
    seen = set()
    direct_items = [item for item in direct_items if acceptable_item(item)]
    general_items = [item for item in general_items if acceptable_item(item)]
    for tecnologia in cliente.get("tecnologias", []):
        for item in direct_items:
            level = relation_level(tecnologia, item)
            if not level:
                continue
            key = item.get("id") or item.get("url") or item.get("titulo")
            if key in seen:
                continue
            finding = selected_finding(item, tecnologia, level, "directo")
            direct.append((priority_tuple(finding, item), finding, item))
            seen.add(key)
    direct.sort(key=lambda row: row[0], reverse=True)
    selected = [row[1] for row in direct[:spaces]]
    general_used = 0
    if len(selected) < spaces:
        for item in sorted(general_items, key=lambda x: (x.get("score", 0), x.get("fecha", "")), reverse=True):
            key = item.get("id") or item.get("url") or item.get("titulo")
            if key in seen:
                continue
            selected.append(selected_finding(item, None, "general", "general"))
            seen.add(key)
            general_used += 1
            if len(selected) >= spaces:
                break
    direct_count = min(len(direct), spaces)
    if direct_count >= spaces:
        status = "HALLAZGOS_DIRECTOS_SUFICIENTES"
        message = f"[CTI][{cliente.get('nombre')}] Se identificaron {len(direct)} hallazgos directos dentro de la ventana autorizada. No fue necesario utilizar noticias generales."
    elif direct_count > 0:
        status = "HALLAZGOS_DIRECTOS_INSUFICIENTES"
        message = f"[CTI][{cliente.get('nombre')}] Se identificaron {len(direct)} hallazgos directos. Se utilizaron {general_used} noticias generales para completar los espacios faltantes."
    else:
        status = "SIN_HALLAZGOS_DIRECTOS"
        message = f"[CTI][{cliente.get('nombre')}] No se identificaron hallazgos directos dentro de la ventana autorizada. El boletín se completó con información general de la misma semana."
    return {
        "cliente": cliente.get("nombre"),
        "estado": status,
        "cantidad_hallazgos_directos": len(direct),
        "cantidad_hallazgos_generales_utilizados": general_used,
        "mensaje_consola": message,
        "hallazgos_seleccionados": selected,
    }
