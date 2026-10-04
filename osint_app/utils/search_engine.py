"""
Búsqueda web multimotor con respaldo, detección de bloqueos y ritmo controlado.

Por qué existe: toda la búsqueda de personas dependía SOLO de raspar DuckDuckGo. En pruebas reales (2026-10)
DuckDuckGo devolvía un captcha ("bots use DuckDuckGo too", HTTP 202) y el programa lo trataba como "0 resultados"
sin avisar; WebSearch llegaba a tardar 205 s para nada y Google Dorks agotaba su tiempo.

Orden de motores (medido en real, ver docs/AUDITORIA_REAL.md):
  1. Brave Search API — solo si el usuario guardó su clave ("BraveSearch"): oficial, estable, no raspa.
  2. SearXNG propio — solo si el usuario configuró su URL ("SearXNG"): metabuscador libre que él mismo aloja.
  3. Yahoo y el modo "auto" de la librería `ddgs` (MIT), si está instalada. Medido 2026-10-04 desde Ecuador:
     Yahoo respondió 3/5 consultas de personas en ~1 s; "auto" 2/5 con esperas de 15 s; Google, Brave, Mojeek,
     Startpage y DuckDuckGo vía ddgs dieron 0 (bloqueo). En ddgs 9.x "bing" y "yandex" NO son motores de texto.
  4. DuckDuckGo HTML/lite (raspado propio) — último recurso.

Cada motor que falla por bloqueo, captcha o tiempo agotado se aparta unos minutos ("enfriamiento") para no
insistir ni empeorar el bloqueo; entre consultas al mismo motor se respeta una pausa mínima (las herramientas
corren en paralelo y las ráfagas son justo lo que provoca el captcha).
"""
from __future__ import annotations

import logging
import random
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

COOLDOWN_SECONDS = 600          # motor bloqueado: no se vuelve a intentar en 10 min
MIN_INTERVAL = {"brave": 1.1, "duckduckgo": 4.0}
DEFAULT_MIN_INTERVAL = 2.0
REQUEST_TIMEOUT = 12

DDGS_BACKENDS = ("yahoo", "auto")

_UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0 Safari/537.36",
]


class EngineBlocked(Exception):
    """El motor respondió con captcha, límite o error: hay que apartarlo un rato."""


@dataclass
class SearchOutcome:
    hits: List[Dict[str, str]] = field(default_factory=list)
    engine: str = ""                                       # motor que dio los resultados
    attempts: List[Tuple[str, str]] = field(default_factory=list)   # (motor, "ok"/"vacío"/"bloqueado: …"/"en pausa")

    @property
    def all_blocked(self) -> bool:
        """True si NINGÚN motor pudo consultarse (no es lo mismo que "no hay resultados")."""
        return not self.hits and bool(self.attempts) and all(s != "vacío" and s != "ok" for _, s in self.attempts)

    def explain(self) -> str:
        """Frase para el usuario sobre qué pasó con la búsqueda."""
        if self.hits:
            return f"{len(self.hits)} resultados vía {self.engine}"
        if self.all_blocked:
            detail = ", ".join(f"{e} ({s})" for e, s in self.attempts)
            return ("los buscadores bloquearon o no respondieron: " + detail +
                    ". Esto NO significa que no haya información. Espera unos minutos o añade una clave de "
                    "Brave Search (python -m osint_app.main --set-key BraveSearch).")
        return "ningún buscador encontró resultados para esta consulta"


# ── estado compartido entre hilos ─────────────────────────────────────────────
_lock = threading.Lock()
_cooldown_until: Dict[str, float] = {}
_last_request: Dict[str, float] = {}


def _in_cooldown(engine: str) -> bool:
    with _lock:
        return _cooldown_until.get(engine, 0) > time.time()


def _cool_down(engine: str, reason: str) -> None:
    with _lock:
        _cooldown_until[engine] = time.time() + COOLDOWN_SECONDS
    logger.warning(f"Búsqueda: {engine} apartado {COOLDOWN_SECONDS // 60} min ({reason})")


def _wait_turn(engine: str) -> None:
    """Respeta la pausa mínima entre consultas al mismo motor (aunque vengan de hilos distintos)."""
    gap = MIN_INTERVAL.get(engine, DEFAULT_MIN_INTERVAL)
    while True:
        with _lock:
            now = time.time()
            ready_at = _last_request.get(engine, 0) + gap
            if now >= ready_at:
                _last_request[engine] = now
                return
            wait = ready_at - now
        time.sleep(wait + random.uniform(0.05, 0.4))


def reset_state() -> None:
    """Olvida pausas y enfriamientos (útil al cambiar de red o para pruebas)."""
    with _lock:
        _cooldown_until.clear()
        _last_request.clear()


def engine_status() -> Dict[str, int]:
    """Segundos de enfriamiento que le quedan a cada motor apartado."""
    now = time.time()
    with _lock:
        return {e: int(t - now) for e, t in _cooldown_until.items() if t > now}


# ── motores ──────────────────────────────────────────────────────────────────

def _brave_key() -> str:
    try:
        from .secret_vault import vault
        return vault.get("BraveSearch") or ""
    except Exception:
        return ""


def _search_brave(query: str, max_results: int) -> List[Dict[str, str]]:
    import requests
    key = _brave_key()
    resp = requests.get(
        "https://api.search.brave.com/res/v1/web/search",
        params={"q": query, "count": min(max_results, 20)},
        headers={"X-Subscription-Token": key, "Accept": "application/json"},
        timeout=REQUEST_TIMEOUT,
    )
    if resp.status_code in (401, 403):
        raise EngineBlocked(f"clave rechazada (HTTP {resp.status_code})")
    if resp.status_code == 429:
        raise EngineBlocked("límite de consultas agotado (HTTP 429)")
    if resp.status_code != 200:
        raise EngineBlocked(f"HTTP {resp.status_code}")
    items = (resp.json().get("web") or {}).get("results") or []
    return [{"title": i.get("title", ""), "url": i.get("url", ""), "snippet": _strip_tags(i.get("description", ""))}
            for i in items[:max_results]]


def _ddgs_available() -> bool:
    try:
        import ddgs  # noqa: F401
        return True
    except Exception:
        return False


def _searxng_url() -> str:
    try:
        from .secret_vault import vault
        return (vault.get("SearXNG") or "").rstrip("/")
    except Exception:
        return ""


def _search_searxng(query: str, max_results: int) -> List[Dict[str, str]]:
    """Instancia SearXNG del usuario (necesita `search.formats: [html, json]` en su settings.yml)."""
    import requests
    resp = requests.get(f"{_searxng_url()}/search", params={"q": query, "format": "json"},
                        headers={"User-Agent": "SENTINEL-OSINT/2.0"}, timeout=REQUEST_TIMEOUT)
    if resp.status_code == 403:
        raise EngineBlocked("la instancia no permite el formato JSON (actívalo en settings.yml)")
    if resp.status_code != 200:
        raise EngineBlocked(f"HTTP {resp.status_code}")
    return [{"title": i.get("title", ""), "url": i.get("url", ""), "snippet": i.get("content", "")}
            for i in (resp.json().get("results") or [])[:max_results]]


def _search_ddgs(backend: str, query: str, max_results: int) -> List[Dict[str, str]]:
    from ddgs import DDGS
    from ddgs.exceptions import DDGSException, TimeoutException
    try:
        items = DDGS(timeout=REQUEST_TIMEOUT).text(query, max_results=max_results, backend=backend)
    except TimeoutException as e:
        raise EngineBlocked("tiempo agotado") from e
    except DDGSException as e:
        if "no results" in str(e).lower():
            return []
        raise EngineBlocked(str(e)[:80]) from e
    return [{"title": i.get("title", ""), "url": i.get("href", ""), "snippet": i.get("body", "")}
            for i in items[:max_results] if i.get("href")]


_DDG_BLOCK_MARKERS = ("bots use duckduckgo", "anomaly-modal", "challenge to confirm this search")


def _search_duckduckgo(query: str, max_results: int) -> List[Dict[str, str]]:
    """Raspado propio de DuckDuckGo (html y, si va vacío, lite). Distingue captcha de "sin resultados"."""
    import requests
    from bs4 import BeautifulSoup

    headers = {"User-Agent": random.choice(_UA), "Referer": "https://duckduckgo.com/"}
    blocked = False
    for url, parse in (("https://html.duckduckgo.com/html/", _parse_ddg_html), ("https://lite.duckduckgo.com/lite/", _parse_ddg_lite)):
        try:
            resp = requests.post(url, data={"q": query}, headers=headers, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as e:
            raise EngineBlocked(f"sin conexión ({type(e).__name__})") from e
        if resp.status_code == 202 or any(m in resp.text.lower() for m in _DDG_BLOCK_MARKERS):
            blocked = True                                  # captcha: probar lite por si acaso
            continue
        if resp.status_code != 200:
            continue
        hits = parse(BeautifulSoup(resp.text, "html.parser"), max_results)
        if hits:
            return hits
    if blocked:
        raise EngineBlocked("captcha anti-bots")
    return []


def _parse_ddg_html(soup, max_results: int) -> List[Dict[str, str]]:
    hits = []
    for r in soup.select(".result"):
        a = r.select_one(".result__a")
        if not a:
            continue
        s = r.select_one(".result__snippet")
        hits.append({"title": a.get_text(strip=True), "url": ddg_unwrap(a.get("href", "")),
                     "snippet": s.get_text(strip=True) if s else ""})
        if len(hits) >= max_results:
            break
    return hits


def _parse_ddg_lite(soup, max_results: int) -> List[Dict[str, str]]:
    links = soup.select("a.result-link")
    snippets = soup.select(".result-snippet")
    return [{"title": a.get_text(strip=True), "url": ddg_unwrap(a.get("href", "")),
             "snippet": snippets[i].get_text(strip=True) if i < len(snippets) else ""}
            for i, a in enumerate(links[:max_results])]


def ddg_unwrap(href: str) -> str:
    """Deshace la redirección de DuckDuckGo (//duckduckgo.com/l/?uddg=...)."""
    if not href:
        return ""
    if "uddg=" in href:
        try:
            return urllib.parse.unquote(href.split("uddg=")[1].split("&")[0])
        except Exception:
            return href
    if href.startswith("//"):
        return "https:" + href
    return href


def _strip_tags(text: str) -> str:
    import re
    return re.sub(r"<[^>]+>", "", text or "")


def _engines() -> List[Tuple[str, Callable[[str, int], List[Dict[str, str]]]]]:
    engines = []
    if _brave_key():
        engines.append(("brave", _search_brave))
    if _searxng_url():
        engines.append(("searxng", _search_searxng))
    if _ddgs_available():
        for backend in DDGS_BACKENDS:
            engines.append((backend if backend != "auto" else "ddgs-auto", lambda q, n, b=backend: _search_ddgs(b, q, n)))
    engines.append(("duckduckgo", _search_duckduckgo))
    return engines


# ── API pública ──────────────────────────────────────────────────────────────

def web_search(query: str, max_results: int = 10, engines: Optional[List[str]] = None) -> SearchOutcome:
    """Busca `query` probando motores en orden hasta que uno dé resultados.

    Un motor que responde "sin resultados" no se aparta (puede ser cierto); uno que bloquea o no responde, sí.
    `engines` limita los motores a usar (por nombre), en el orden por defecto.
    """
    outcome = SearchOutcome()
    for name, fn in _engines():
        if engines and name not in engines:
            continue
        if _in_cooldown(name):
            outcome.attempts.append((name, "en pausa"))
            continue
        _wait_turn(name)
        try:
            hits = [h for h in fn(query, max_results) if h.get("url", "").startswith(("http://", "https://"))]
        except EngineBlocked as e:
            _cool_down(name, str(e))
            outcome.attempts.append((name, f"bloqueado: {e}"))
            continue
        except Exception as e:                              # fallo inesperado del motor: se aparta y se sigue
            _cool_down(name, type(e).__name__)
            outcome.attempts.append((name, f"error: {type(e).__name__}"))
            continue
        if hits:
            outcome.hits, outcome.engine = hits[:max_results], name
            outcome.attempts.append((name, "ok"))
            return outcome
        outcome.attempts.append((name, "vacío"))
    return outcome
