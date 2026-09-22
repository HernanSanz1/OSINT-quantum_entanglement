"""Perfiles de clientes para priorizacion editorial del boletin CTI."""

from __future__ import annotations

import re


def tech(nombre: str, categoria: str, terms: tuple[str, ...], peso: int = 45, confirmado: bool = True) -> dict:
    return {
        "nombre": nombre,
        "categoria": categoria,
        "terms": terms,
        "peso": peso,
        "confirmado": confirmado,
    }


CLIENTES = {
    "CER": {
        "nombre": "CER",
        "infraestructura": (
            "Domain Controllers, servidores Windows, servidores Linux, AWS, GCP, VMware y Docker",
        ),
        "tecnologias": [
            tech("Amazon Web Services (AWS)", "Nube", ("amazon web services", "aws", "cloudtrail"), 40),
            tech("Google Cloud Platform (GCP)", "Nube", ("google cloud", "gcp", "cloud armor", "cloud logging", "security command center"), 40),
            tech("Google Workspace", "SaaS", ("google workspace", "gmail", "google drive"), 35),
            tech("Microsoft Active Directory", "Directorio", ("active directory", "domain controller", "domain controllers"), 45),
            tech("Aruba ClearPass", "NAC", ("aruba clearpass", "clearpass"), 55),
            tech("CyberArk Vault y APIs", "PAM", ("cyberark", "cyberark vault"), 60),
            tech("Fortinet FortiGate / Firewall", "Firewall", ("fortigate", "fortios"), 65),
            tech("Fortinet FortiProxy", "Proxy", ("fortiproxy", "forti proxy"), 60),
            tech("Fortinet FortiManager", "Gestion", ("fortimanager", "forti manager"), 60),
            tech("Fortinet FortiCNAPP", "Seguridad cloud", ("forticnapp", "forti cnapp"), 45),
            tech("Fortinet FortiRecon", "Exposicion digital", ("fortirecon", "forti recon"), 45),
            tech("FireMon", "Gestion de politicas", ("firemon",), 45),
            tech("Imperva WAF / Attack Analytics", "WAF", ("imperva", "attack analytics"), 55),
            tech("Sucuri WAF", "WAF", ("sucuri",), 45),
            tech("Trend Micro Vision One", "XDR", ("vision one",), 55),
            tech("Trend Micro Apex Central", "Gestion endpoint", ("apex central", "apex one"), 50),
            tech("Trend Micro Workload Security", "Cargas de trabajo", ("workload security", "deep security"), 50),
            tech("ManageEngine Endpoint Central", "Gestion endpoint", ("manageengine endpoint central", "desktop central"), 55),
            tech("ManageEngine ADAudit Plus", "Auditoria AD", ("adaudit", "adaudit plus"), 50),
            tech("Wazuh", "SIEM/HIDS", ("wazuh",), 45),
            tech("VMware", "Virtualizacion", ("vmware", "vcenter", "esxi", "vsphere"), 55),
            tech("Docker", "Contenedores", ("docker", "container", "containerd"), 45),
            tech("Microsoft Windows Server", "Sistema operativo", ("windows server", "microsoft windows"), 35),
            tech("Linux Server", "Sistema operativo", ("linux", "kernel"), 35),
            tech("Axis", "Videovigilancia/IoT", ("axis", "axis communications"), 45),
            tech("RDP", "Protocolo", ("rdp", "remote desktop"), 35),
            tech("SSH", "Protocolo", ("ssh", "openssh"), 35),
        ],
        "consolas": ["TREND MICRO", "ENDPOINT CENTRAL"],
        "pendientes": [
            "Axis: tipo de dispositivo, producto, modelo y firmware",
            "Managed Identities: plataforma donde estan implementadas",
            "PAM generico: fabricante, producto y version",
            "Fortinet Firewall: confirmar FortiGate, modelo y version de FortiOS",
            "VMware: producto concreto y version",
            "Windows/Windows Server: edicion, version, build y soporte",
            "Linux: distribucion, version y kernel",
        ],
    },
    "MAVESA": {
        "nombre": "MAVESA",
        "infraestructura": (
            "Active Directory, equipos Windows y Linux, Microsoft 365 y dispositivos Fortinet",
        ),
        "tecnologias": [
            tech("Microsoft 365 / Office 365", "SaaS", ("microsoft 365", "office 365", "exchange online", "sharepoint online"), 45),
            tech("Microsoft Graph API", "API", ("microsoft graph", "graph api"), 40),
            tech("Microsoft Active Directory", "Directorio", ("active directory", "domain controller", "domain controllers"), 45),
            tech("Fortinet FortiGate / Firewall", "Firewall", ("fortigate", "fortios"), 65),
            tech("Imperva WAF / Attack Analytics", "WAF", ("imperva", "attack analytics"), 55),
            tech("Trend Micro Vision One", "XDR", ("vision one",), 55),
            tech("Trend Micro Apex Central", "Gestion endpoint", ("apex central", "apex one"), 50),
            tech("Trend Micro Email Security", "Correo", ("trend micro email security", "email security"), 50),
            tech("Microsoft Windows", "Sistema operativo", ("microsoft windows", "windows server", "windows"), 35),
            tech("Linux Server", "Sistema operativo", ("linux", "kernel"), 35),
            tech("VPN", "Protocolo", ("vpn",), 35),
            tech("SSH", "Protocolo", ("ssh", "openssh"), 35),
        ],
        "consolas": ["TREND MICRO"],
        "pendientes": [
            "Fortinet Firewall: confirmar FortiGate, modelo y version de FortiOS",
            "Windows/Windows Server: edicion, version, build y soporte",
            "Linux: distribucion, version y kernel",
        ],
    },
    "XTRIM": {
        "nombre": "XTRIM",
        "infraestructura": (
            "Servidores de Active Directory, Windows y Linux; Cisco, MikroTik, Huawei, Nokia; "
            "VMware vCenter, HPE SimpliVity, bases de datos SQL y Syslog"
        ),
        "tecnologias": [
            tech("AWS CloudTrail", "Nube", ("aws cloudtrail", "cloudtrail", "amazon web services", "aws"), 40),
            tech("Microsoft 365 / Exchange / SharePoint Online", "SaaS", ("microsoft 365", "office 365", "exchange online", "sharepoint online", "sharepoint"), 50),
            tech("Microsoft Active Directory / Azure AD", "Directorio", ("active directory", "azure active directory", "entra id", "domain controller"), 45),
            tech("Cisco ISE", "NAC", ("cisco ise", "identity services engine"), 55),
            tech("BeyondTrust Bomgar PRA", "PAM", ("beyondtrust", "bomgar", "privileged remote access"), 55),
            tech("Fortinet FortiGate / Firewall", "Firewall", ("fortigate", "fortios"), 65),
            tech("Fortinet FortiManager", "Gestion", ("fortimanager", "forti manager"), 60),
            tech("Fortinet FortiAnalyzer", "Logs", ("fortianalyzer", "forti analyzer"), 50),
            tech("Fortinet FortiWeb", "WAF", ("fortiweb", "forti web"), 60),
            tech("Radware WAF", "WAF", ("radware",), 55),
            tech("Citrix NetScaler ADC", "ADC", ("citrix", "netscaler", "adc"), 65),
            tech("Cisco WLC / routers / switches", "Red", ("cisco", "ios xe", "ios-xe", "nx-os", "wireless lan controller", "wlc"), 60),
            tech("MikroTik RouterOS", "Red", ("mikrotik", "routeros"), 60),
            tech("Huawei networking/core", "Red", ("huawei", "vrp"), 50),
            tech("Nokia carrier/core", "Telecomunicaciones", ("nokia", "sros", "sr os"), 50),
            tech("Trend Micro Vision One", "XDR", ("vision one",), 55),
            tech("Trend Micro Apex Central", "Gestion endpoint", ("apex central", "apex one"), 50),
            tech("Trend Micro Email Security", "Correo", ("trend micro email security", "email security"), 50),
            tech("Trend Micro Workload / Deep Security", "Cargas de trabajo", ("workload security", "deep security"), 50),
            tech("Palo Alto Cortex XDR", "XDR/EDR", ("palo alto", "cortex xdr"), 50),
            tech("Wazuh", "SIEM/HIDS", ("wazuh",), 45),
            tech("IBM Security Guardium", "Seguridad de datos", ("guardium", "ibm security guardium"), 50),
            tech("Grafana / Loki", "Logs", ("grafana", "loki"), 45),
            tech("VMware vCenter", "Virtualizacion", ("vmware", "vcenter", "esxi", "vsphere"), 60),
            tech("HPE SimpliVity", "Hiperconvergencia", ("simplivity", "hpe simplivity"), 50),
            tech("Veritas", "Backup", ("veritas", "netbackup", "backup exec"), 50),
            tech("Microsoft Windows Server", "Sistema operativo", ("windows server", "microsoft windows"), 35),
            tech("Linux Server", "Sistema operativo", ("linux", "kernel"), 35),
            tech("Bases de datos SQL", "Base de datos", ("sql server", "mysql", "postgresql", "oracle database", "database"), 40),
            tech("VPN/RDP/SSH/TACACS/Syslog", "Protocolos", ("vpn", "rdp", "remote desktop", "ssh", "openssh", "tacacs", "syslog"), 35),
        ],
        "consolas": ["TREND MICRO"],
        "pendientes": [
            "PAM generico: fabricante, producto y version",
            "Fortinet Firewall: confirmar FortiGate, modelo y version de FortiOS",
            "Veritas: producto exacto y version",
            "Bases de datos SQL: motor exacto",
            "MikroTik/Cisco/WLC/Huawei/Nokia: modelos y versiones",
            "HPE SimpliVity: modelo y version",
            "Windows/Windows Server: edicion, version, build y soporte",
            "Linux: distribucion, version y kernel",
        ],
    },
    "SERVIANDINA": {
        "nombre": "SERVIANDINA",
        "infraestructura": "Inventario pendiente de precision; se prioriza con baja confianza sobre Microsoft y Trend Micro.",
        "tecnologias": [
            tech("Microsoft pendiente de confirmar", "Pendiente", ("microsoft", "windows", "windows server", "microsoft 365", "office 365", "entra id", "sql server", "defender"), 25, False),
            tech("Trend Micro pendiente de confirmar", "Pendiente", ("trend micro", "vision one", "apex one", "apex central", "deep security", "email security"), 25, False),
        ],
        "consolas": ["TREND MICRO"],
        "pendientes": [
            "Microsoft: producto exacto",
            "Trend Micro: producto exacto",
        ],
    },
}


def normalize_cliente(value: str | None) -> str | None:
    if not value:
        return None
    key = re.sub(r"\s+", "", value).upper()
    return key if key in CLIENTES else None


def get_cliente(value: str | None) -> dict | None:
    key = normalize_cliente(value)
    if not key:
        return None
    return CLIENTES[key]


def cliente_choices() -> str:
    return ", ".join(sorted(CLIENTES))


def match_tecnologias(cliente: dict, item: dict) -> list[dict]:
    from seleccion_cliente import relation_level

    matches = []
    for tecnologia in cliente.get("tecnologias", []):
        level = relation_level(tecnologia, item)
        if level:
            matches.append({
                "nombre": tecnologia["nombre"],
                "categoria": tecnologia["categoria"],
                "peso": tecnologia["peso"],
                "confirmado": tecnologia.get("confirmado", True),
                "nivel_coincidencia": level,
            })
    return matches


def term_in_text(term: str, text: str) -> bool:
    if not term:
        return False
    # Evita falsos positivos con tokens cortos: "aws" dentro de "flaws",
    # "adc" dentro de palabras largas, etc.
    if re.fullmatch(r"[a-z0-9][a-z0-9.+#-]{1,5}", term):
        return re.search(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])", text) is not None
    if " " in term or "/" in term or "-" in term:
        return re.search(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])", text) is not None
    return term in text


def boost_cliente(item: dict, cliente: dict) -> dict:
    matches = match_tecnologias(cliente, item)
    if not matches:
        return dict(item)
    out = dict(item)
    boost = min(sum(m["peso"] for m in matches), 180)
    labels = set(out.get("etiquetas", []))
    labels.add("RELEVANCIA CLIENTE")
    if any(m.get("confirmado") for m in matches):
        labels.add("TECNOLOGIA CONFIRMADA")
    else:
        labels.add("TECNOLOGIA PENDIENTE DE CONFIRMAR")
    if any(label in labels for label in ("EXPLOTADO ACTIVAMENTE", "EXPLOTACION REPORTADA")):
        boost += 50
    out["score"] = round(float(out.get("score", 0)) + boost, 2)
    out["etiquetas"] = sorted(labels)
    out["cliente_matches"] = matches
    return out


def preferred_specs(cliente: dict | None) -> list[tuple[str, ...]]:
    if not cliente:
        return []
    specs = []
    for tecnologia in cliente.get("tecnologias", []):
        for term in tecnologia.get("terms", ())[:2]:
            if term and len(term) > 2:
                specs.append((term.lower(),))
    return specs
