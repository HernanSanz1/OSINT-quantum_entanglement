"""Estado de cada herramienta en lenguaje claro, el mismo en todas las pestañas.

Antes la interfaz solo miraba `is_available` y mostraba como listas herramientas que no hacían nada (Hunter.io sin
clave, Instaloader sin sesión de Instagram) y como "no instaladas" las que están sin programar (CTI de servidor).
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class ToolStatus:
    code: str          # ready | needs_key | not_installed | pending | deprecated
    icon: str
    label: str         # texto corto para la lista
    color: str
    reason: str        # explicación para el usuario (tooltip)
    fix: str = ""      # cómo resolverlo

    @property
    def usable(self) -> bool:
        return self.code == "ready"


_STYLE = {
    "ready": ("✅", "Lista", "#00ff66"),
    "needs_key": ("🔑", "Falta clave o sesión", "#ffaa00"),
    "not_installed": ("❌", "No instalada", "#ff5555"),
    "pending": ("🚧", "En desarrollo", "#8A9AA9"),
    "deprecated": ("⛔", "Obsoleta", "#8A9AA9"),
}


def tool_status(tool) -> ToolStatus:
    """Clasifica la herramienta a partir de su diagnóstico (diagnose_status) y de su naturaleza."""
    from ..tools.threat_intel import _ThreatBaseTool
    from ..tools.social_tools import SnscrapeYoutubeTool

    if isinstance(tool, _ThreatBaseTool):
        code, reason, fix = "pending", (f"{tool.name} todavía no está programada en SENTINEL (es una plantilla). "
                                         f"Para reputación de IPs y URLs usa 'IP Reputation'."), ""
    elif isinstance(tool, SnscrapeYoutubeTool):
        code, reason, fix = "deprecated", "snscrape dejó de funcionar porque las redes cambiaron su acceso.", ""
    else:
        try:
            if hasattr(tool, "check_available"):
                tool.check_available()
            diag = tool.diagnose_status()
        except Exception as e:                          # una herramienta rota no debe romper la lista
            diag = {"status": "not_installed", "message": f"No se pudo comprobar ({type(e).__name__}).", "install_cmd": ""}
        raw = diag.get("status", "not_installed")
        code = {"ready": "ready", "needs_key": "needs_key"}.get(raw, "not_installed")
        reason, fix = diag.get("message", ""), diag.get("install_cmd", "")
    icon, label, color = _STYLE[code]
    return ToolStatus(code, icon, label, color, reason or label, fix)
