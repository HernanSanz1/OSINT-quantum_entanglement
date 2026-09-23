"""Correlacion interna CVE x cliente x tecnologia x exposicion.

Este modulo no genera contenido publicable. Produce objetos de control para el
backend y evita asumir exposicion cuando no hay visibilidad de consolas.
"""

from __future__ import annotations

import datetime as dt
import re

from clientes import match_tecnologias
from vision_one_connector import query_cve_exposure, query_ips_signature

CVSS_RE = re.compile(r"CVSS(?:\s*v?3(?:\.\d)?)?(?:\s*score)?[:\s]+(10(?:\.0)?|[0-9](?:\.[0-9])?)", re.I)
VECTOR_RE = re.compile(r"CVSS:3\.[01]/[A-Z]{1,2}:[A-Z](?:/[A-Z]{1,3}:[A-Z])+", re.I)


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def text_of(item: dict) -> str:
    return " ".join(str(item.get(k, "")) for k in ("titulo", "resumen", "impacto", "url", "fuente", "fuente_id")).lower()


def console_log(cve: str, cliente: str, message: str) -> str:
    return f"[CTI][{cve}][{cliente}] {message}"


def extract_cvss(item: dict) -> tuple[str, str]:
    for key in ("cvss_v3", "cvss", "base_score"):
        value = item.get(key)
        if value not in (None, ""):
            try:
                return f"{float(value):.1f}", ""
            except Exception:
                return str(value), ""
    text = " ".join(str(item.get(k, "")) for k in ("titulo", "resumen", "impacto"))
    score = CVSS_RE.search(text)
    vector = VECTOR_RE.search(text)
    return (score.group(1) if score else "", vector.group(0).upper() if vector else "")


def severity_from_cvss(score: str) -> str:
    if not score:
        return ""
    try:
        value = float(score)
    except ValueError:
        return ""
    if value >= 9.0:
        return "CRITICA"
    if value >= 7.0:
        return "ALTA"
    if value >= 4.0:
        return "MEDIA"
    return "BAJA"


def emergency_exception(item: dict) -> bool:
    labels = set(item.get("etiquetas", []))
    text = text_of(item)
    return bool(
        item.get("kev")
        or item.get("exploited")
        or item.get("publicly_disclosed")
        or item.get("inclusion_dia_generacion_critica")
        or labels & {"EXPLOTADO ACTIVAMENTE", "ZERO-DAY DIVULGADO"}
        or any(term in text for term in (
            "zero-day",
            "zero day",
            "exploited:yes",
            "exploitation detected",
            "actively exploited",
            "cisa kev",
            "alerta urgente",
            "critical security update",
        ))
    )


def prioritization(score: str, vector: str, item: dict) -> str:
    severity = severity_from_cvss(score)
    if emergency_exception(item) and not score:
        return "CRITICA"
    if severity in {"CRITICA", "ALTA"}:
        return severity
    return "NO_PRIORIZADA"


def exposure_order(score: str, vector: str, item: dict) -> tuple:
    severity = severity_from_cvss(score)
    labels = set(item.get("etiquetas", []))
    active = 1 if "EXPLOTADO ACTIVAMENTE" in labels or item.get("exploited") else 0
    kev = 1 if item.get("kev") else 0
    critical = 1 if severity == "CRITICA" or (emergency_exception(item) and not score) else 0
    high = 1 if severity == "ALTA" else 0
    network = 1 if "AV:N" in (vector or "") else 0
    return (active, kev, critical, network, high, float(score or 0), item.get("score", 0))


def applicability(cliente: dict, item: dict) -> tuple[str, list[dict]]:
    matches = match_tecnologias(cliente, item)
    confirmed = [m for m in matches if m.get("confirmado")]
    pending = [m for m in matches if not m.get("confirmado")]
    if confirmed:
        return "APLICABLE_VERSION_PENDIENTE", confirmed
    if pending:
        return "APLICABLE_VERSION_PENDIENTE", pending
    return "NO_APLICABLE", []


def client_consoles(cliente: dict) -> list[str]:
    consoles = list(cliente.get("consolas", []))
    if consoles:
        return consoles
    tech_names = " ".join(t.get("nombre", "") for t in cliente.get("tecnologias", [])).lower()
    out = []
    if "trend micro" in tech_names:
        out.append("TREND MICRO")
    if cliente.get("nombre") == "CER" or "endpoint central" in tech_names or "desktop central" in tech_names:
        out.append("ENDPOINT CENTRAL")
    return out


def console_query_stub(cliente: dict, cve: str, console: str, producto: str = "") -> dict:
    if console == "TREND MICRO":
        return query_cve_exposure(cliente.get("nombre", ""), cve, producto)
    return {
        "consola": console,
        "estado": "CONSULTA_FALLIDA",
        "fecha_consulta": utcnow(),
        "activos": [],
        "mensaje": (
            f"No existe credencial/API configurada para consultar {console} del tenant {cliente.get('nombre')}. "
            "No se interpreta como ausencia de activos vulnerables."
        ),
    }


def ips_stub(cliente: dict, cve: str, producto: str = "") -> dict:
    return query_ips_signature(cliente.get("nombre", ""), cve, producto)


def ticket_state(job: dict, console_results: list[dict], ips: dict) -> str:
    if not console_results or any(r.get("estado") == "CONSULTA_FALLIDA" for r in console_results):
        return "REQUIERE_REVISION_MANUAL"
    if not any(r.get("activos") for r in console_results):
        return "NO_APTO_PARA_TICKET"
    if ips.get("estado") == "NO_VERIFICABLE":
        return "REQUIERE_REVISION_MANUAL"
    return "APTO_PARA_TICKET"


def source_ref(item: dict, cve: str) -> dict:
    refs = item.get("fuentes") or [item]
    selected = refs[0] if refs else item
    for ref in refs:
        if cve in [str(x).upper() for x in ref.get("cves", [])]:
            selected = ref
            break
    merged = dict(selected)
    for key in (
        "etiquetas",
        "kev",
        "exploited",
        "publicly_disclosed",
        "inclusion_dia_generacion_critica",
        "score",
        "producto",
        "impacto",
        "cliente_matches",
    ):
        if key in item and key not in merged:
            merged[key] = item[key]
    return merged


def build_exposure_matrix(cliente: dict | None, selected_items: list[dict]) -> dict:
    if not cliente:
        return {}
    jobs = []
    logs = []
    seen = set()
    cve_items = []
    for item in selected_items:
        for cve in [str(c).upper() for c in item.get("cves", [])]:
            key = (cve, item.get("id") or item.get("url") or item.get("titulo"))
            if key in seen:
                continue
            seen.add(key)
            cve_items.append((cve, source_ref(item, cve)))

    for cve, item in cve_items:
        status, matches = applicability(cliente, item)
        if status not in {"APLICABLE_CONFIRMADA", "APLICABLE_VERSION_PENDIENTE"}:
            logs.append(console_log(cve, cliente.get("nombre", ""), "No aplicable por inventario tecnico; no se inicia correlacion de activos."))
            continue
        cvss, vector = extract_cvss(item)
        priority = prioritization(cvss, vector, item)
        if priority == "NO_PRIORIZADA":
            logs.append(console_log(cve, cliente.get("nombre", ""), "Aplicable, pero no cumple CVSS alto/critico ni excepcion de emergencia; no pasa a exposicion detallada."))
            continue
        consoles = client_consoles(cliente)
        reason = "CVSS pendiente de confirmacion; procesada por evidencia de explotacion o criticidad" if not cvss and emergency_exception(item) else ""
        for match in matches:
            job_key = (cve, cliente.get("nombre"), match.get("nombre"), match.get("nivel_coincidencia"))
            if any((j.get("cve"), j.get("cliente"), j.get("tecnologia_cliente"), j.get("nivel_coincidencia")) == job_key for j in jobs):
                continue
            product = item.get("product") or item.get("producto") or match.get("nombre")
            console_results = [console_query_stub(cliente, cve, console, product) for console in consoles]
            ips = ips_stub(cliente, cve, product) if "TREND MICRO" in consoles else {"estado": "NO_APLICA", "mensaje": "Cliente sin consola Trend Micro configurada."}
            job = {
                "cliente": cliente.get("nombre"),
                "cve": cve,
                "producto": product,
                "tecnologia_cliente": match.get("nombre"),
                "nivel_coincidencia": match.get("nivel_coincidencia"),
                "versiones_afectadas": item.get("versiones_afectadas") or "NO_DISPONIBLES",
                "cvss_v3": cvss or "PENDIENTE_DE_CONFIRMACION",
                "vector_cvss_v3": vector or "NO_DISPONIBLE",
                "prioridad": priority,
                "motivo_excepcion": reason,
                "estado_aplicabilidad": status,
                "consolas_a_consultar": consoles,
                "estado": "PENDIENTE_DE_CORRELACION",
                "consultas_consola": console_results,
                "firma_ips": ips,
                "estado_ticket": ticket_state({}, console_results, ips),
                "estado_correo": "CORREO_PENDIENTE_DE_APROBACION",
                "orden_prioridad": exposure_order(cvss, vector, item),
            }
            jobs.append(job)
            logs.append(console_log(cve, cliente.get("nombre", ""), f"{status}. CVSS {job['cvss_v3']}, vector {job['vector_cvss_v3']}. Estado de correlacion: {job['estado_ticket']}."))

    jobs.sort(key=lambda x: x.get("orden_prioridad", ()), reverse=True)
    for job in jobs:
        job.pop("orden_prioridad", None)
    return {
        "cliente": cliente.get("nombre"),
        "generado": utcnow(),
        "estado": "REQUIERE_REVISION_MANUAL" if any(j.get("estado_ticket") == "REQUIERE_REVISION_MANUAL" for j in jobs) else "SIN_TRABAJOS_APLICABLES" if not jobs else "EVALUADO",
        "matriz": "CVE x CLIENTE x TECNOLOGIA x EXPOSICION x ACTIVOS_AFECTADOS",
        "trabajos": jobs,
        "mensajes_consola": logs,
        "politica_correo": "Los correos de reportes por CVE quedan pendientes de aprobacion manual; no se envian automaticamente.",
    }
