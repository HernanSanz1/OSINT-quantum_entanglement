"""Conector seguro para consultas internas a Trend Vision One.

No imprime ni devuelve secretos. Si no existe una credencial API validada para
consulta por CVE, reporta estado no concluyente en vez de simular resultados.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

CREDENTIAL_PATH = Path("/home/admin/.openclaw/credentials/trend-micro/default.json")
RUNBOOKS = [
    "vision-one-fast-endpoint-scraping-runbook.md",
    "vision-one-endpoint-inventory-quickplay.md",
    "vision-one-endpoint-response-runbook-actualizado.md",
]


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def credential_status(path: Path = CREDENTIAL_PATH) -> dict:
    if not path.exists():
        return {
            "estado": "CREDENCIAL_NO_ENCONTRADA",
            "path": str(path),
            "metodo": "NO_DISPONIBLE",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {
            "estado": "CREDENCIAL_INVALIDA",
            "path": str(path),
            "metodo": "NO_DISPONIBLE",
        }
    keys = {str(k).lower() for k in data.keys()}
    has_api = bool(keys & {"api_token", "token", "bearer_token", "xdr_token", "api_key"})
    has_portal = bool(keys & {"portal_url", "username", "user", "password"})
    if has_api:
        return {
            "estado": "CREDENCIAL_API_DETECTADA",
            "path": str(path),
            "metodo": "API",
            "campos": sorted(keys),
        }
    if has_portal:
        return {
            "estado": "CREDENCIAL_PORTAL_DETECTADA",
            "path": str(path),
            "metodo": "NAVEGADOR_CON_MFA_POSIBLE",
            "campos": sorted(keys),
        }
    return {
        "estado": "CREDENCIAL_SIN_CAMPOS_RECONOCIDOS",
        "path": str(path),
        "metodo": "NO_DISPONIBLE",
        "campos": sorted(keys),
    }


def query_cve_exposure(cliente: str, cve: str, producto: str = "") -> dict:
    status = credential_status()
    base = {
        "consola": "TREND MICRO",
        "cliente": cliente,
        "cve": cve,
        "producto": producto,
        "fecha_consulta": utcnow(),
        "activos": [],
        "runbooks": RUNBOOKS,
    }
    if status["estado"] == "CREDENCIAL_NO_ENCONTRADA":
        return {
            **base,
            "estado": "CONSULTA_FALLIDA",
            "mensaje": (
                f"No se encontro la credencial local esperada en {status['path']}. "
                "No se interpreta como ausencia de activos vulnerables."
            ),
        }
    if status["estado"] == "CREDENCIAL_INVALIDA":
        return {
            **base,
            "estado": "CONSULTA_FALLIDA",
            "mensaje": "La credencial local de Trend Micro no es JSON valido. No se realizo consulta.",
        }
    if status["estado"] == "CREDENCIAL_PORTAL_DETECTADA":
        return {
            **base,
            "estado": "DATOS_INSUFICIENTES",
            "mensaje": (
                "Se detecto credencial de portal para Vision One. La consulta por CVE requiere automatizacion de navegador y puede requerir MFA; "
                "queda pendiente de validacion interactiva segun el runbook de Conexion a Vision One."
            ),
        }
    if status["estado"] == "CREDENCIAL_API_DETECTADA":
        return {
            **base,
            "estado": "DATOS_INSUFICIENTES",
            "mensaje": (
                "Se detecto credencial API de Vision One, pero no hay endpoint de consulta por CVE validado en el runbook local. "
                "Debe confirmarse el endpoint oficial antes de extraer activos afectados."
            ),
        }
    return {
        **base,
        "estado": "DATOS_INSUFICIENTES",
        "mensaje": "La credencial existe, pero no contiene campos suficientes para consulta automatizada a Vision One.",
    }


def query_ips_signature(cliente: str, cve: str, producto: str = "") -> dict:
    status = credential_status()
    base = {
        "consola": "TREND MICRO",
        "cliente": cliente,
        "cve": cve,
        "producto": producto,
        "fecha_consulta": utcnow(),
    }
    if status["estado"] == "CREDENCIAL_API_DETECTADA":
        message = (
            "Credencial API detectada, pero el endpoint de verificacion de firma IPS por CVE no esta validado en la skill/runbook local. "
            "Requiere confirmacion manual antes de afirmar disponibilidad, asignacion o modo de prevencion."
        )
    elif status["estado"] == "CREDENCIAL_PORTAL_DETECTADA":
        message = (
            "Credencial de portal detectada; la verificacion de firma IPS requiere revision interactiva en Vision One y posible MFA."
        )
    else:
        message = "La existencia o aplicacion de una firma IPS especifica no pudo confirmarse en la consola y requiere validacion manual."
    return {
        **base,
        "estado": "NO_VERIFICABLE",
        "mensaje": message,
        "firma_disponible": "NO_VERIFICABLE",
        "firma_habilitada": "NO_VERIFICABLE",
        "firma_asignada": "NO_VERIFICABLE",
        "firma_aplicada": "NO_VERIFICABLE",
        "modo": "NO_VERIFICABLE",
    }
