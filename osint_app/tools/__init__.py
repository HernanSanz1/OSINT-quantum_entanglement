"""Tool registry — all 25+ tools in one place."""
import logging

from .google_dorks import GoogleDorksTool
from .hunter import HunterTool
from .social_tools import SherlockTool, HoleheTool, GHuntTool, SnscrapeYoutubeTool, InstagramTool
from .network_tools import (
    DnspythonTool, IpWhoisTool, CensysTool,
    TheHarvesterTool, PhoneNumbersTool,
)
from .wayback import WaybackMachineTool
from .crtsh import CrtShTool
from .tech_detect import TechDetectTool
from .web_search import WebSearchTool, GitHubOSINTTool, UsernameVariantsTool

from .heavy_tools import (
    SubfinderTool, AmassTool, SpiderFootTool,
    ReconNgTool, MaigretTool,
)
from .threat_intel import (
    IntelOwlTool, OpenCTITool, MISPTool, CortexTool, IntelMQTool,
)

ALL_TOOLS = [
    # ── Web search (always available) ──────────────────────────────────────
    WebSearchTool,
    GitHubOSINTTool,
    UsernameVariantsTool,
    # ── Light tools (no binary required) ───────────────────────────────────
    GoogleDorksTool,
    HunterTool,
    DnspythonTool,
    IpWhoisTool,
    CensysTool,
    WaybackMachineTool,
    CrtShTool,
    TechDetectTool,
    PhoneNumbersTool,
    HoleheTool,
    GHuntTool,
    # ── Medium tools (Python packages) ─────────────────────────────────────
    SnscrapeYoutubeTool,
    InstagramTool,
    # ── Heavy tools (external binaries) ────────────────────────────────────
    SherlockTool,
    TheHarvesterTool,
    SubfinderTool,
    AmassTool,
    SpiderFootTool,
    ReconNgTool,
    MaigretTool,
    # ── Threat intel (need servers) ─────────────────────────────────────────
    IntelOwlTool,
    OpenCTITool,
    MISPTool,
    CortexTool,
    IntelMQTool,
]


logger = logging.getLogger(__name__)


def build_tool_registry() -> dict:
    """Instantiate all tools and return {tool_name: instance}."""
    registry = {}
    for ToolClass in ALL_TOOLS:
        try:
            t = ToolClass()
            t.is_available = t.check_available()
            registry[t.name] = t
        except Exception:
            logger.exception(f"No se pudo cargar la herramienta {ToolClass.__name__}")
    return registry
