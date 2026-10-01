"""
Link Shield Tool — riesgo de un enlace (phishing, suplantación, ocultación de destino).

Análisis ESTÁTICO: se evalúa el texto de la URL sin visitarla (no deja rastro en
el servidor investigado). Solo si el enlace es de un acortador conocido (bit.ly,
tinyurl…) se siguen sus redirecciones, sin descargar contenido, para ver el
destino real, y ese destino se analiza igual.

Para la antigüedad del dominio (señal muy fuerte: el phishing usa dominios recién
registrados) consulta el registro público RDAP, nunca al sitio investigado.

Es una señal de riesgo, no un veredicto: un enlace limpio puede ser malicioso y
uno con alertas puede ser legítimo.
"""
import ipaddress
import logging
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import unquote, urljoin, urlparse

import requests

from ..core.models import ToolRequirements, QueryParameters, SearchResult
from ..core.base_tool import OSINTTool
from ..utils.sanitizer import sanitize_snippet, validate_url
from ..utils.rate_limiter import RateLimiter
from ..utils.cache import CacheManager
from . import file_metadata
from .domain_whois import DomainWhoisTool

logger = logging.getLogger(__name__)

MAX_HOPS = 5
REQUEST_TIMEOUT = 15
USER_AGENT = "SENTINEL-OSINT/2.0 (link-shield; python-requests)"
WEIGHTS = {"alta": 50, "media": 20, "baja": 8}
SEVERITY_SCORE = {"alta": 88, "media": 75, "baja": 60}
MEDIUM_FROM, HIGH_FROM = 20, 50
NEW_DOMAIN_DAYS = 30             # registrado hace menos: casi siempre campaña nueva
YOUNG_DOMAIN_DAYS = 180          # registrado hace menos: dominio joven, precaución

SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
    "shorturl.at", "t.ly", "rb.gy", "tiny.cc", "lnkd.in", "bl.ink", "v.gd", "s.id", "shorte.st", "goo.su", "u.to",
}
# Plataformas donde cualquiera publica páginas gratis: muy usadas en phishing (también tienen usos legítimos)
FREE_HOSTING = {
    "pages.dev", "vercel.app", "github.io", "weebly.com", "blogspot.com", "replit.app", "repl.co", "edgeone.dev",
    "netlify.app", "workers.dev", "railway.app", "wasmer.app", "godaddysites.com", "amplifyapp.com", "b4a.run",
    "zrok.io", "dothome.co.kr", "typedream.app", "glitch.me", "web.app", "firebaseapp.com", "herokuapp.com",
    "onrender.com", "wixsite.com", "000webhostapp.com", "ngrok.io", "ngrok-free.app", "trycloudflare.com",
    "surge.sh", "framer.website", "webflow.io", "carrd.co", "square.site", "my.canva.site", "myshopify.com",
    "pageshare.ai", "azurewebsites.net", "r2.dev", "storage.googleapis.com", "s3.amazonaws.com",
}
SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "tk", "gq", "ml", "cf", "ga", "work", "country", "support",
    "loan", "rest", "fit", "cam", "icu", "monster", "buzz", "sbs", "cyou",
}
RISKY_EXTENSIONS = (".exe", ".scr", ".msi", ".apk", ".bat", ".cmd", ".vbs", ".jar", ".iso", ".lnk", ".ps1", ".hta", ".dmg")
KEYWORDS = (
    "login", "signin", "log-in", "verify", "verifica", "secure", "account", "cuenta", "update", "actualiz",
    "confirm", "password", "clave", "wallet", "banking", "suspend", "bloquead", "recuper", "unlock", "token",
)
# marca → dominios oficiales (dominio registrable)
BRANDS: Dict[str, Tuple[str, ...]] = {
    "paypal": ("paypal.com", "paypalobjects.com"),
    "google": ("google.com", "gmail.com", "goo.gl", "googleapis.com", "googleusercontent.com", "googlevideo.com",
               "googletagmanager.com", "googlesyndication.com", "googletagservices.com", "googlesource.com",
               "googledomains.com", "googleblog.com", "withgoogle.com", "googleadservices.com", "google-analytics.com",
               "googlecode.com", "googlegroups.com", "googlecloud.com"),
    "microsoft": ("microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com", "onmicrosoft.com",
                  "microsoftpersonalcontent.com", "microsoftazuread-sso.com", "msn.com", "azure.com", "windows.com",
                  "skype.com", "office365.com", "sharepoint.com", "microsoftstore.com", "bing.com"),
    "apple": ("apple.com", "icloud.com", "icloud-content.com", "apple-cloudkit.com", "apple-dns.net", "cdn-apple.com", "mzstatic.com"),
    "amazon": ("amazon.com", "amazonaws.com", "ssl-images-amazon.com", "media-amazon.com", "amazonwebservices.com",
               "amazon-adsystem.com", "amazontrust.com", "amazonpay.com", "amazonvideo.com"),
    "facebook": ("facebook.com", "fb.com", "facebook.net", "fbcdn.net"), "instagram": ("instagram.com", "cdninstagram.com"),
    "whatsapp": ("whatsapp.com", "whatsapp.net", "wa.me"), "netflix": ("netflix.com", "netflix.net", "nflxvideo.net"),
    "linkedin": ("linkedin.com", "licdn.com"), "dropbox": ("dropbox.com", "dropboxusercontent.com", "dropbox-dns.com"), "binance": ("binance.com",),
    "mercadolibre": ("mercadolibre.com", "mercadopago.com", "mercadolivre.com.br"),
    "pichincha": ("bancopichincha.com", "pichincha.com"), "produbanco": ("produbanco.com", "produbanco.com.ec"),
    "guayaquil": ("bancoguayaquil.com",), "pacifico": ("bancodelpacifico.com",), "bolivariano": ("bolivariano.com",),
    "bancolombia": ("bancolombia.com",), "iess": ("iess.gob.ec",), "sri": ("sri.gob.ec",), "dhl": ("dhl.com",),
    "roblox": ("roblox.com", "rbxcdn.com"), "coinbase": ("coinbase.com",), "ebay": ("ebay.com", "ebaystatic.com"),
    "outlook": ("outlook.com", "outlook.live.com"), "icloud": ("icloud.com", "icloud-content.com"),
    "steam": ("steampowered.com", "steamcommunity.com", "steamstatic.com"),
    "spotify": ("spotify.com", "scdn.co"), "telegram": ("telegram.org", "t.me", "telegra.ph", "telegram.me"), "tiktok": ("tiktok.com", "tiktokcdn.com", "tiktokv.com", "tiktokv.us", "tiktokv.eu", "tiktokw.us", "tiktokcdn-us.com", "tiktokcdn-eu.com", "tiktokrow-cdn.com", "byteoversea.com"),
    "twitter": ("twitter.com", "twimg.com", "x.com", "ads-twitter.com", "t.co"), "docusign": ("docusign.com", "docusign.net"),
    "adobe": ("adobe.com", "adobe.io"), "zoom": ("zoom.us", "zoom.com"), "wellsfargo": ("wellsfargo.com",),
    "fedex": ("fedex.com",), "usps": ("usps.com",),
}
GENERIC_BRANDS = {"sri", "zoom", "steam", "adobe", "dhl", "usps", "iess"}   # nombres cortos o comunes: solo si la etiqueta es exactamente la marca
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
BAIT_WORDS = (
    "support", "soporte", "help", "ayuda", "service", "servicio", "pay", "pago", "official", "oficial", "online",
    "center", "centro", "team", "client", "cliente", "prize", "premio", "gift", "regalo", "free", "gratis", "bonus",
    "reward", "claim", "alert", "alerta", "security", "seguridad", "billing", "invoice", "factura", "refund",
)
# marcas con webs nacionales legítimas en cada país (amazon.es, google.de…): ahí un dominio de país no es sospechoso
COUNTRY_BRANDS = {"google", "amazon", "mercadolibre", "microsoft", "apple", "ebay", "dhl", "fedex", "spotify", "netflix", "adobe", "zoom"}
# letras cirílicas y griegas que se ven igual que una latina
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ѕ": "s", "ј": "j",
    "ԁ": "d", "ɡ": "g", "ӏ": "l", "ο": "o", "ν": "v", "α": "a", "ι": "i", "κ": "k", "ρ": "p", "τ": "t",
})
SECOND_LEVELS = {"co", "com", "gob", "gov", "edu", "org", "net", "ac", "mil"}

REQUIREMENTS = ToolRequirements(
    mandatory=["url"],
    optional=[],
    produces=["domain"],
    hint="Necesita una URL (ej: https://sitio.com/ruta) para evaluar su riesgo sin visitarla.",
)


# ── Utilidades de nombres ────────────────────────────────────────────────────

def registrable(host: str) -> str:
    """Dominio registrable aproximado: a.b.empresa.com → empresa.com; x.empresa.com.ec → empresa.com.ec."""
    labels = host.lower().rstrip(".").split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in SECOND_LEVELS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def edit_distance_le1(a: str, b: str) -> bool:
    """True si a y b difieren en como máximo una inserción, borrado o sustitución."""
    if a == b:
        return True
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b)) == 1
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    return any(long_[:i] + long_[i + 1:] == short for i in range(len(long_)))


def _distance_le2(a: str, b: str) -> bool:
    """Distancia de edición (Levenshtein) de 2 o menos, para marcas largas."""
    if abs(len(a) - len(b)) > 2:
        return False
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1] <= 2


def decode_idna(label: str) -> str:
    try:
        return label.encode("ascii").decode("idna") if label.lower().startswith("xn--") else label
    except UnicodeError:
        return label


def is_ip_obfuscated(host: str) -> bool:
    """IP escrita como número único (3232235777) o en hexadecimal (0xC0A80001)."""
    return bool(re.fullmatch(r"\d{8,10}|0x[0-9a-f]{6,8}", host.lower()))


# ── Análisis estático (función pura) ─────────────────────────────────────────

def analyze_url(url: str) -> dict:
    """Evalúa el texto de la URL. Devuelve host, dominio, hallazgos [(gravedad, texto)], puntuación y nivel."""
    raw = url.strip()
    if not re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I):
        raw = "http://" + raw
    try:
        p = urlparse(raw)
        host = (p.hostname or "").lower()
        port = p.port
    except ValueError:
        return {"url": url, "host": "", "domain": "", "findings": [("alta", "La dirección está mal formada")], "score": WEIGHTS["alta"], "level": "bajo"}
    findings: List[Tuple[str, str]] = []
    if not host:
        return {"url": url, "host": "", "domain": "", "findings": [], "score": 0, "level": "bajo"}

    def add(sev: str, text: str):
        findings.append((sev, text))

    path_q = unquote(f"{p.path} {p.query}").lower()

    if p.scheme == "http":
        add("baja", "No usa HTTPS: el tráfico no va cifrado")
    elif p.scheme not in ("https", "http"):
        add("media", f"Esquema inusual: {p.scheme}")
    if p.username is not None or p.password is not None:
        add("alta", "Incluye usuario antes de la arroba: lo escrito antes de ella no es el destino real")
    if port not in (None, 80, 443):
        add("baja", f"Puerto no estándar: {port}")
    if len(raw) > 200:
        add("baja", f"Enlace muy largo: {len(raw)} caracteres")
    if raw.count("%") > 10:
        add("baja", "Muchos caracteres codificados con porcentaje, a veces para ocultar el contenido")

    # ¿IP en lugar de nombre?
    try:
        ip = ipaddress.ip_address(host)
        add("media", f"El destino es una dirección IP, no un dominio: {ip}")
        is_ip = True
    except ValueError:
        is_ip = False
        if is_ip_obfuscated(host):
            add("alta", "La IP está escrita como un número único o en hexadecimal para ocultarla")

    dom = host if is_ip else registrable(host)
    labels = host.split(".")
    tld = labels[-1]

    tail = unquote(f"{p.query} {p.fragment}")
    if re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", tail) or re.search(r"(?:^|[?&#/=])[A-Za-z0-9+/_-]{24,}={0,2}(?:$|[&#])", f"{p.query}#{p.fragment}"):
        add("media", "Lleva un correo o un código largo en el enlace, típico para identificar a la víctima")

    if not is_ip:
        if dom in SHORTENERS or host in SHORTENERS:
            add("baja", "Acortador de enlaces: oculta el destino real")
        platform = next((h for h in FREE_HOSTING if host.endswith("." + h)), "")
        if platform:
            add("media", f"Alojado en {platform}, una plataforma donde cualquiera publica páginas gratis y muy usada en phishing")
        if tld in SUSPICIOUS_TLDS:
            add("media", f"Extensión .{tld} muy usada en campañas de phishing y spam")
        decoded = [decode_idna(l) for l in labels]
        if any(l.startswith("xn--") for l in labels):
            add("media", "Nombre con punycode que puede imitar letras de otro alfabeto, se ve como " + ".".join(decoded))
        elif any(not l.isascii() for l in labels):
            add("media", "El dominio contiene letras no latinas que pueden imitar a otras")
        dom_labels = dom.split(".")
        depth = len(labels) - len(dom_labels)
        if depth >= 3 and not platform:
            add("baja", f"Muchos subdominios encadenados: {depth}")
        if host.replace("xn--", "").count("-") >= 3:
            add("baja", "Muchos guiones en el nombre, típico de dominios generados")
        owner_label = dom_labels[0]
        if re.search(r"\d{5,}", owner_label) and not platform:
            add("baja", "Nombre con una larga serie de números, típico de dominios generados")

        # suplantación de marca
        head = labels[:depth]
        decoded_owner = decode_idna(owner_label)
        norm_owner = decoded_owner.translate(CONFUSABLES).translate(LEET)
        non_latin = not decoded_owner.isascii()
        cred = any(k in owner_label for k in KEYWORDS + BAIT_WORDS)
        country_tld = len(tld) == 2 or (len(dom_labels) >= 3 and len(dom_labels[-1]) == 2)
        for brand, officials in BRANDS.items():
            if dom in officials or dom.endswith(tuple("." + o for o in officials)):
                continue
            exact = brand in GENERIC_BRANDS
            head_hit = any(((l.translate(LEET) == brand) if exact else (brand in l.translate(LEET))) for l in head)
            fused = norm_owner != brand and (brand in norm_owner) and not exact
            same_start = norm_owner[:1] == brand[:1]
            typo = same_start and len(brand) >= 5 and norm_owner != brand and edit_distance_le1(norm_owner, brand)
            typo2 = (same_start and len(brand) >= 8 and len(norm_owner) >= len(brand) and norm_owner != brand
                     and not typo and _distance_le2(norm_owner, brand))
            if non_latin and brand in norm_owner:
                add("alta", f"El dominio {dom} usa letras de otro alfabeto para imitar a {brand}")
                break
            if norm_owner == brand and decoded_owner != brand:
                add("alta", f"El dominio {dom} imita a {brand} cambiando letras por números o símbolos")
                break
            if norm_owner == brand:
                if not (country_tld and brand in COUNTRY_BRANDS):
                    add("media", f"Usa el nombre de {brand} con otra extensión: {dom}")
                    break
                continue
            if head_hit or (fused and cred):
                where = f"El servidor {host}" if head_hit else f"El dominio {dom}"
                add("alta", f"{where} contiene el nombre de {brand} pero el dominio real es {dom}, no uno oficial de esa marca")
                break
            if typo or typo2:
                add("media", f"El dominio {dom} se parece a {brand}, ¿imitación con una letra cambiada?")
                break
            if fused or (not exact and re.search(rf"(?<![a-z0-9]){brand}(?![a-z0-9])", path_q)):
                add("media", f"Menciona a {brand} sin ser un dominio oficial: {dom}")
                break

    official_host = any(dom in o or dom.endswith(tuple("." + x for x in o)) for o in BRANDS.values())
    low_host_path = f"{host} {path_q}"
    found = [] if official_host else [k for k in KEYWORDS if k in low_host_path]
    if len(found) >= 2:
        add("media", "Palabras típicas de engaño de credenciales: " + ", ".join(found[:4]))
    elif found:
        add("baja", f"Palabra típica de engaño de credenciales: {found[0]}")
    ext = next((e for e in RISKY_EXTENSIONS if p.path.lower().endswith(e)), "")
    if ext:
        add("media", f"Apunta a un archivo ejecutable o instalador: {ext}")

    score = min(100, sum(WEIGHTS[s] for s, _ in findings))
    level = "alto" if score >= HIGH_FROM else "medio" if score >= MEDIUM_FROM else "bajo"
    return {"url": url, "host": host, "domain": dom, "findings": findings, "score": score, "level": level}


def is_shortener(url: str) -> bool:
    try:
        host = (urlparse(url if "://" in url else "http://" + url).hostname or "").lower()
    except ValueError:
        return False
    return host in SHORTENERS or registrable(host) in SHORTENERS


# ── Seguimiento de redirecciones (solo acortadores) ──────────────────────────

def trace_redirects(url: str, max_hops: int = MAX_HOPS) -> Tuple[List[str], str]:
    """Cadena de URLs hasta el destino y un mensaje de error ('' si terminó bien). No descarga contenido."""
    chain = [url]
    for _ in range(max_hops):
        current = chain[-1]
        if not validate_url(current) or not file_metadata.host_is_public(urlparse(current).hostname or ""):
            return chain, "destino no permitido: dirección privada, local o inválida"
        try:
            resp = requests.get(current, headers={"User-Agent": USER_AGENT}, timeout=REQUEST_TIMEOUT,
                                stream=True, allow_redirects=False)
        except requests.RequestException as e:
            return chain, f"error de red {type(e).__name__}"
        with resp:
            if resp.status_code in (301, 302, 303, 307, 308) and resp.headers.get("Location"):
                chain.append(urljoin(current, resp.headers["Location"]))
                continue
            if resp.status_code >= 400:
                return chain, f"HTTP {resp.status_code}"
            return chain, ""
    return chain, "demasiadas redirecciones"


def age_findings(age_days: Optional[int]) -> List[Tuple[str, str]]:
    """Hallazgos según la antigüedad del dominio (None = desconocida: sin hallazgo)."""
    if age_days is None or age_days < 0:
        return []
    if age_days < NEW_DOMAIN_DAYS:
        return [("alta", f"Dominio registrado hace solo {age_days} días: típico de phishing y campañas nuevas")]
    if age_days < YOUNG_DOMAIN_DAYS:
        return [("media", f"Dominio joven: registrado hace {age_days} días")]
    return []


def should_check_age(host: str) -> bool:
    """Solo dominios propios: no IPs, ni acortadores, ni plataformas gratuitas, ni dominios oficiales de una marca."""
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    dom = registrable(host)
    if is_ip_obfuscated(host) or dom in SHORTENERS or any(host == f or host.endswith("." + f) for f in FREE_HOSTING):
        return False
    return not any(dom in o or dom.endswith(tuple("." + x for x in o)) for o in BRANDS.values())


def merge_final(first: dict, final: dict) -> List[Tuple[str, str]]:
    """Hallazgos del destino final, prefijados, sin repetir los ya vistos."""
    seen = {t for _, t in first["findings"]}
    return [(s, f"Destino final: {t}") for s, t in final["findings"] if t not in seen and not t.startswith("Acortador")]


# ── Herramienta ──────────────────────────────────────────────────────────────

class LinkShieldTool(OSINTTool):
    def __init__(self):
        super().__init__(
            "Link Shield",
            "Riesgo de un enlace: phishing, suplantación de marca, IP, punycode, acortadores; análisis sin visitar la URL",
            REQUIREMENTS,
        )
        self._python_pkgs = ["requests"]
        self._install_cmd = "pip install requests"
        self._rate = RateLimiter(max_requests=20, time_window=60)
        self._cache = CacheManager(max_size=100, ttl=600)
        self._whois = DomainWhoisTool()

    def check_available(self) -> bool:
        return True

    def _domain_age(self, host: str) -> Optional[dict]:
        """Antigüedad del dominio por RDAP (registro público, no el sitio investigado). None si no se puede saber."""
        if not should_check_age(host):
            return None
        try:
            info, _resolved, _status = self._whois.lookup(registrable(host))
        except Exception as e:      # el análisis estático no debe fallar por el RDAP
            logger.warning(f"Link Shield: RDAP no disponible ({type(e).__name__})")
            return None
        if _status == "no-rdap":
            tld = registrable(host).rsplit(".", 1)[-1]
            return {"age_days": None, "note": f"antigüedad no disponible: la extensión .{tld} no publica datos RDAP"}
        if not info or info.get("age_days") is None:
            return None
        return {"age_days": info["age_days"], "registered": info.get("registered", ""), "registrar": info.get("registrar", "")}

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        target = (query_params.url or "").strip()
        if not target or any(c.isspace() for c in target):
            logger.warning("LinkShieldTool: URL ausente o inválida")
            return []
        cached = self._cache.get({"url": target})
        if cached is not None:
            self._report_progress("📦 Link Shield: usando caché")
            return cached

        first = analyze_url(target)
        if not first["host"]:
            self._report_progress("⚠️ Link Shield: no se pudo leer el dominio de la URL.")
            return []
        findings = list(first["findings"])
        chain: List[str] = [target]
        trace_note = ""
        if is_shortener(target):
            self._report_progress("🔍 Link Shield: acortador detectado, siguiendo redirecciones sin descargar contenido…")
            self._rate.wait_if_needed()
            full = target if "://" in target else "http://" + target
            chain, err = trace_redirects(full)
            if len(chain) > 1:
                final = analyze_url(chain[-1])
                findings += merge_final(first, final)
                if len(chain) > 3:
                    findings.append(("media", f"Cadena larga de redirecciones: {len(chain) - 1} saltos"))
            trace_note = err
        final_host = analyze_url(chain[-1])["host"] if len(chain) > 1 else first["host"]
        age = self._domain_age(final_host)
        if age:
            findings += age_findings(age.get("age_days"))
        score = min(100, sum(WEIGHTS[s] for s, _ in findings))
        level = "alto" if score >= HIGH_FROM else "medio" if score >= MEDIUM_FROM else "bajo"

        parts = [f"Riesgo {level} {score} de 100", f"Dominio: {first['domain']}"]
        if len(chain) > 1:
            parts.append(f"Destino final: {chain[-1]}")
        elif is_shortener(target) and trace_note:
            parts.append(f"No se pudo seguir el acortador: {trace_note}")
        known_age = bool(age) and age.get("age_days") is not None
        if known_age:
            parts.append(f"Dominio registrado el {age['registered']}, hace {age['age_days']} días")
        elif age and age.get("note"):
            parts.append(age["note"][:1].upper() + age["note"][1:])
        if not findings:
            parts.append("Sin señales de riesgo en el texto de la URL" + (" ni en la antigüedad del dominio" if known_age else ""))
        raw = {"url": target, "host": first["host"], "domain": first["domain"], "score": score, "level": level,
               "chain": chain, "domain_age": age, "findings": [{"severity": s, "text": t} for s, t in findings]}
        results = [SearchResult(
            title=f"Análisis de enlace: {first['host']}",
            url="",
            snippet=sanitize_snippet(" · ".join(parts)),
            source_tool=self.name,
            category="Enlace",
            relevance_score={"alto": 90, "medio": 78, "bajo": 55}[level],
            raw_data=raw,
        )]
        for sev, text in sorted(findings, key=lambda f: -WEIGHTS[f[0]]):
            results.append(SearchResult(
                title=f"⚠️ {first['host']}: {text}",
                url="",
                snippet=sanitize_snippet(f"[{sev.upper()}] {text}"),
                source_tool=self.name,
                category="Alerta",
                relevance_score=SEVERITY_SCORE[sev],
                raw_data={"host": first["host"], "severity": sev, "alert": text},
            ))
        self._report_progress(f"✅ Link Shield: {first['host']} — riesgo {level} {score}/100, {len(findings)} señal(es)")
        self._cache.set({"url": target}, results)
        return results
