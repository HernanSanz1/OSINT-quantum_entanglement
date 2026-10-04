"""
File Metadata Tool — metadatos de imágenes (EXIF), PDF y documentos Office.

Recibe una URL pública o la ruta de un archivo local y extrae lo que el archivo
revela sin querer: dónde y con qué cámara se tomó una foto (GPS, marca, modelo,
número de serie), quién creó un documento, con qué programa y en qué organización.
Pasivo: solo descarga el archivo indicado (máx. 15 MB). Implementación propia
sobre Pillow y pypdf; los .docx/.xlsx/.pptx se leen con la librería estándar.

Muchas webs y redes sociales BORRAN los metadatos al subir un archivo; si no hay,
se informa así en vez de inventar nada.
"""
import io
import ipaddress
import logging
import re
import socket
import time
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import unquote, urljoin, urlparse

import requests
from defusedxml import ElementTree as ET        # rechaza entidades/DTD (XML bombs)

from ..core.models import ToolRequirements, QueryParameters, SearchResult
from ..core.base_tool import OSINTTool
from ..utils.sanitizer import sanitize_snippet, validate_url
from ..utils.rate_limiter import RateLimiter
from ..utils.cache import CacheManager

logger = logging.getLogger(__name__)

MAX_BYTES = 15 * 1024 * 1024
MAX_XML_BYTES = 1_000_000
MAX_REDIRECTS = 3
MAX_WAIT = 15                    # segundos máximos que se acatan de Retry-After (429/503)
REQUEST_TIMEOUT = 25
# Con forma de contacto (URL del proyecto): la política de Wikimedia lo exige; sin ella respondía HTTP 429
# incluso a la primera descarga (verificado 2026-10-04: mismo archivo → 429 sin contacto, 200 con contacto)
USER_AGENT = "SENTINEL-OSINT/2.0 (https://github.com/HernanSanz1/OSINT-quantum_entanglement; file-metadata)"
SEVERITY_SCORE = {"alta": 88, "media": 75, "baja": 60}
OFFICE_PARTS = ("docProps/core.xml", "docProps/app.xml")

REQUIREMENTS = ToolRequirements(
    mandatory=["url"],
    optional=[],
    produces=["location", "company"],
    hint="Necesita la URL de una imagen, PDF o documento Office (o la ruta de un archivo local).",
)


# ── Tipo de archivo (por contenido, no por extensión) ─────────────────────────

def detect_kind(head: bytes) -> str:
    """'image' | 'pdf' | 'zip' | ''."""
    if head.startswith((b"\xff\xd8\xff", b"\x89PNG\r\n\x1a\n", b"II*\x00", b"MM\x00*")):
        return "image"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image"
    if head.startswith(b"%PDF"):
        return "pdf"
    if head.startswith(b"PK\x03\x04"):
        return "zip"
    return ""


# ── Utilidades de limpieza ───────────────────────────────────────────────────

def _text(value) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return re.sub(r"[\x00-\x1f]+", " ", str(value)).strip()[:300]


def exif_date(value) -> str:
    """'2024:01:15 10:30:00' → '2024-01-15 10:30:00' (sin zona horaria: EXIF no la trae aquí)."""
    text = _text(value)
    m = re.match(r"^(\d{4}):(\d{2}):(\d{2})[ T](\d{2}:\d{2}:\d{2})", text)
    return f"{m.group(1)}-{m.group(2)}-{m.group(3)} {m.group(4)}" if m else text


def pdf_date(value) -> str:
    """"D:20240115103000+01'00'" → '2024-01-15 10:30:00 UTC+01:00' (la zona horaria orienta sobre dónde se creó)."""
    text = _text(value)
    m = re.match(r"^D?:?(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?(?:([+-])(\d{2})'?(\d{2})?'?|Z)?", text)
    if not m:
        return text
    y, mo, d, h, mi, sec = (m.group(i) or ("01" if i in (2, 3) else "00") for i in range(1, 7))
    out = f"{y}-{mo}-{d} {h}:{mi}:{sec}"
    if m.group(7):
        out += f" UTC{m.group(7)}{m.group(8)}:{m.group(9) or '00'}"
    elif text.rstrip().endswith("Z"):
        out += " UTC"
    return out


def gps_to_decimal(dms, ref) -> Optional[float]:
    """((40,1),(26,1),(46,1)) o (40.0, 26.0, 46.0) + 'N' → 40.446. None si es inválido."""
    try:
        deg, minutes, seconds = (float(x) for x in dms)
    except (TypeError, ValueError, ZeroDivisionError):
        return None
    value = deg + minutes / 60 + seconds / 3600
    ref = _text(ref).upper()
    if ref not in ("N", "S", "E", "W") or value != value:       # value != value → NaN
        return None
    value = -value if ref in ("S", "W") else value
    limit = 90 if ref in ("N", "S") else 180
    return round(value, 6) if abs(value) <= limit else None


# ── Análisis (funciones puras) ───────────────────────────────────────────────

def summarize_exif(base: dict, sub: dict, gps: dict, extra: Optional[dict] = None) -> dict:
    """Resumen plano de las etiquetas EXIF (nombres de etiqueta ya traducidos)."""
    out: Dict[str, object] = {}
    pairs = (
        ("camera_make", base.get("Make")), ("camera_model", base.get("Model")),
        ("software", base.get("Software")), ("artist", base.get("Artist")),
        ("copyright", base.get("Copyright")), ("description", base.get("ImageDescription")),
        ("lens", sub.get("LensModel")), ("camera_serial", sub.get("BodySerialNumber")),
        ("lens_serial", sub.get("LensSerialNumber")), ("owner", sub.get("CameraOwnerName")),
    )
    for key, value in pairs:
        if value not in (None, "") and _text(value):
            out[key] = _text(value)
    taken = sub.get("DateTimeOriginal") or base.get("DateTime")
    if taken:
        out["taken"] = exif_date(taken)
        offset = _text(sub.get("OffsetTimeOriginal") or "")
        if re.match(r"^[+-]\d{2}:\d{2}$", offset):
            out["taken"] += f" UTC{offset}"
    if base.get("DateTime"):
        out["modified"] = exif_date(base["DateTime"])
    lat = gps_to_decimal(gps.get("GPSLatitude"), gps.get("GPSLatitudeRef"))
    lon = gps_to_decimal(gps.get("GPSLongitude"), gps.get("GPSLongitudeRef"))
    if lat is not None and lon is not None:
        out["gps"] = {"lat": lat, "lon": lon, "maps": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=16/{lat}/{lon}"}
    for key, value in (extra or {}).items():
        if value and _text(value):
            out.setdefault(key, _text(value))
    return out


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_office_xml(core: Optional[bytes], app: Optional[bytes]) -> dict:
    """docProps/core.xml y app.xml de un .docx/.xlsx/.pptx."""
    out: Dict[str, str] = {}
    wanted = {
        "creator": "author", "lastModifiedBy": "last_modified_by", "created": "created",
        "modified": "modified", "title": "title", "subject": "subject", "revision": "revision",
        "Application": "application", "AppVersion": "app_version", "Company": "company", "Manager": "manager",
    }
    for blob in (core, app):
        if not blob:
            continue
        try:
            root = ET.fromstring(blob)
        except (ET.ParseError, ValueError):        # XML roto o con entidades prohibidas
            continue
        for node in root.iter():
            key = wanted.get(_local(node.tag))
            if key and node.text and node.text.strip():
                out.setdefault(key, _text(node.text))
    for key in ("created", "modified"):
        if key in out:
            out[key] = out[key].replace("T", " ").rstrip("Z")
    return out


def build_findings(info: dict) -> List[Tuple[str, str]]:
    """Hallazgos (gravedad, texto) a partir del resumen."""
    out: List[Tuple[str, str]] = []
    gps = info.get("gps")
    if gps:
        out.append(("alta", f"Contiene coordenadas GPS: {gps['lat']}, {gps['lon']}. Es la ubicación donde se tomó la imagen"))
    if info.get("camera_serial"):
        out.append(("media", f"Número de serie de la cámara: {info['camera_serial']}. Permite vincular fotos del mismo equipo"))
    if info.get("owner"):
        out.append(("media", f"Propietario registrado de la cámara: {info['owner']}"))
    person = info.get("artist") or info.get("author")
    if person:
        out.append(("media", f"Autor registrado: {person}. Puede ser un nombre real o el usuario del equipo"))
    if info.get("last_modified_by") and info.get("last_modified_by") != info.get("author"):
        out.append(("baja", f"Última modificación por otra persona: {info['last_modified_by']}"))
    if info.get("company"):
        out.append(("media", f"Organización registrada en el programa: {info['company']}"))
    return out


def _upper_first(text: str) -> str:
    return text[:1].upper() + text[1:]


def summary_line(info: dict) -> str:
    camera = " ".join(x for x in (info.get("camera_make"), info.get("camera_model")) if x)
    items = (
        ("Equipo", camera),
        ("Fecha", info.get("taken")),
        ("Programa", info.get("application") or info.get("software") or info.get("producer") or info.get("creator")),
        ("Autor", info.get("author") or info.get("artist")),
        ("Modificó", info.get("last_modified_by")),
        ("Organización", info.get("company")),
        ("Creado", info.get("created")),
        ("Modificado", info.get("modified")),
        ("Páginas", info.get("pages")),
    )
    parts = [f"{label}: {value}" for label, value in items if value]
    if info.get("gps"):
        parts.append(f"GPS: {info['gps']['lat']}, {info['gps']['lon']}")
    return " · ".join(parts)


# ── Lectores por tipo de archivo ─────────────────────────────────────────────

def read_image(data: bytes) -> dict:
    from PIL import ExifTags, Image
    with Image.open(io.BytesIO(data)) as img:
        exif = img.getexif()
        tags = ExifTags.TAGS
        base = {tags.get(k, k): v for k, v in exif.items()}
        sub = {tags.get(k, k): v for k, v in exif.get_ifd(0x8769).items()}
        gps = {ExifTags.GPSTAGS.get(k, k): v for k, v in exif.get_ifd(0x8825).items()}
        text = {k: v for k, v in (img.info or {}).items()
                if k in ("Author", "Software", "Copyright", "Creation Time", "Title", "Description") and isinstance(v, str)}
        extra = {"author": text.get("Author"), "software": text.get("Software"),
                 "copyright": text.get("Copyright"), "title": text.get("Title")}
        info = summarize_exif(base, sub, gps, extra)
        info["format"] = img.format or ""
        info["size"] = f"{img.width}x{img.height}"
    return info


def read_pdf(data: bytes) -> dict:
    from pypdf import PdfReader
    reader = PdfReader(io.BytesIO(data))
    meta = reader.metadata or {}
    out: Dict[str, object] = {"pages": len(reader.pages)}
    for key, name in (("/Author", "author"), ("/Creator", "creator"), ("/Producer", "producer"),
                      ("/Title", "title"), ("/Subject", "subject")):
        if meta.get(key) and _text(meta[key]):
            out[name] = _text(meta[key])
    for key, name in (("/CreationDate", "created"), ("/ModDate", "modified")):
        if meta.get(key):
            out[name] = pdf_date(meta[key])
    return out


def read_office(data: bytes) -> Optional[dict]:
    """None si el ZIP no es un documento Office."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = set(zf.namelist())
            if "docProps/core.xml" not in names and "docProps/app.xml" not in names:
                return None
            blobs = []
            for part in OFFICE_PARTS:
                blobs.append(zf.open(part).read(MAX_XML_BYTES) if part in names else None)
    except zipfile.BadZipFile:
        return None
    return parse_office_xml(*blobs)


def inspect_bytes(data: bytes) -> Optional[dict]:
    """Metadatos del archivo, o None si no es imagen/PDF/Office. Dict vacío = sin metadatos."""
    kind = detect_kind(data[:16])
    try:
        if kind == "image":
            return {"kind": "imagen", **read_image(data)}
        if kind == "pdf":
            return {"kind": "PDF", **read_pdf(data)}
        if kind == "zip":
            office = read_office(data)
            return None if office is None else {"kind": "documento Office", **office}
    except Exception as e:      # archivo corrupto o truncado
        logger.warning(f"File Metadata: no se pudo leer ({type(e).__name__})")
        return None
    return None


def has_metadata(info: dict) -> bool:
    return any(k not in ("kind", "format", "size", "pages") for k in info)


# ── Descarga segura ──────────────────────────────────────────────────────────

def host_is_public(host: str) -> bool:
    """True solo si TODAS las direcciones del host son públicas (anti-SSRF, también vía DNS)."""
    try:
        addrs = {ai[4][0] for ai in socket.getaddrinfo(host, None)}
    except OSError:
        return False
    for addr in addrs:
        ip = ipaddress.ip_address(addr.split("%")[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            return False
    return bool(addrs)


class DownloadError(Exception):
    pass


def download(url: str) -> bytes:
    """Descarga con límites: solo http(s) públicos, ≤3 redirecciones validadas una a una, ≤15 MB."""
    waited = False
    for _ in range(MAX_REDIRECTS + 2):
        if not validate_url(url) or not host_is_public(urlparse(url).hostname or ""):
            raise DownloadError("dirección no permitida (privada, local o inválida)")
        try:
            resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=REQUEST_TIMEOUT,
                                stream=True, allow_redirects=False)
        except requests.RequestException as e:
            raise DownloadError(f"error de red ({type(e).__name__})")
        with resp:
            if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
                url = urljoin(url, resp.headers.get("Location", ""))
                continue
            if resp.status_code in (429, 503) and not waited:
                waited = True
                retry_after = resp.headers.get("Retry-After", "")
                time.sleep(min(int(retry_after), MAX_WAIT) if retry_after.isdigit() else 3)
                continue
            if resp.status_code != 200:
                raise DownloadError(f"HTTP {resp.status_code}")
            if int(resp.headers.get("Content-Length") or 0) > MAX_BYTES:
                raise DownloadError("archivo demasiado grande (máx. 15 MB)")
            buf = bytearray()
            for chunk in resp.iter_content(65536):
                buf += chunk
                if len(buf) > MAX_BYTES:
                    raise DownloadError("archivo demasiado grande (máx. 15 MB)")
            return bytes(buf)
    raise DownloadError("demasiadas redirecciones")


def read_local(path: Path) -> bytes:
    if path.stat().st_size > MAX_BYTES:
        raise DownloadError("archivo demasiado grande (máx. 15 MB)")
    return path.read_bytes()


# ── Herramienta ──────────────────────────────────────────────────────────────

class FileMetadataTool(OSINTTool):
    def __init__(self):
        super().__init__(
            "File Metadata",
            "Metadatos de imágenes (EXIF/GPS), PDF y documentos Office: autor, cámara, ubicación, programa (sin clave)",
            REQUIREMENTS,
        )
        self._python_pkgs = ["PIL", "pypdf"]
        self._install_cmd = "pip install Pillow pypdf"
        self._rate = RateLimiter(max_requests=20, time_window=60)
        self._cache = CacheManager(max_size=50, ttl=600)

    def check_available(self) -> bool:
        try:
            import PIL  # noqa: F401
            import pypdf  # noqa: F401
            return True
        except ImportError:
            return False

    def _load(self, target: str) -> Tuple[bytes, str, str]:
        """(contenido, nombre de archivo, enlace/ruta de origen)."""
        if re.match(r"^https?://", target, re.I):
            self._rate.wait_if_needed()
            name = unquote(Path(urlparse(target).path).name) or urlparse(target).hostname or "archivo"
            return download(target), name, target
        path = Path(target.strip('"'))
        if not path.is_file():
            raise DownloadError("no es una URL http(s) ni un archivo existente")
        return read_local(path), path.name, ""

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        target = (query_params.url or "").strip()
        if not target:
            logger.warning("FileMetadataTool: sin URL ni archivo")
            return []
        if not self.check_available():
            logger.error("Pillow/pypdf no instalados — pip install Pillow pypdf")
            return []
        remote = bool(re.match(r"^https?://", target, re.I))
        if remote:
            cached = self._cache.get({"url": target})
            if cached is not None:
                self._report_progress("📦 File Metadata: usando caché")
                return cached

        self._report_progress("🔍 File Metadata: obteniendo el archivo…")
        try:
            data, name, origin = self._load(target)
        except DownloadError as e:
            self._report_progress(f"⚠️ File Metadata: {e}")
            return []
        info = inspect_bytes(data)
        if info is None:
            self._report_progress("⚠️ File Metadata: no es una imagen, PDF ni documento Office legible.")
            return []

        findings = build_findings(info)
        if has_metadata(info):
            snippet = f"{_upper_first(info['kind'])} · " + summary_line(info)
            score = 80
        else:
            snippet = (f"{_upper_first(info['kind'])} sin metadatos: pudieron borrarse al subirlo "
                       "(muchas webs y redes sociales lo hacen) o nunca existieron")
            score = 50
        results = [SearchResult(
            title=f"Metadatos: {name}",
            url=origin,
            snippet=sanitize_snippet(snippet),
            source_tool=self.name,
            category="Metadatos",
            relevance_score=score,
            raw_data=info,
        )]
        for severity, text in findings:
            results.append(SearchResult(
                title=f"⚠️ {name}: {text}",
                url=origin,
                snippet=sanitize_snippet(f"[{severity.upper()}] {text}"),
                source_tool=self.name,
                category="Alerta",
                relevance_score=SEVERITY_SCORE[severity],
                raw_data={"file": name, "severity": severity, "alert": text},
            ))
        self._report_progress(f"✅ File Metadata: {name} — {len(findings)} hallazgo(s)")
        if remote:
            self._cache.set({"url": target}, results)
        return results
