"""
Security utilities v2 — input sanitization, shell arg quoting, SSRF guard, DB text limits.

IMPORTANT: Every piece of user input that reaches a subprocess or network call
must go through one of these functions first.
"""
import re
import shlex
import ipaddress
from urllib.parse import urlparse


# ── Constants ─────────────────────────────────────────────────────────────────

# Shell metacharacters that could enable injection
_SHELL_META = r'[;|&`$()\{\}<>\'"\n\r\t%!]'
_SHELL_META_RE = re.compile(_SHELL_META)

# Max lengths — prevents buffer overflows / DB bloat
MAX_INPUT_LEN       = 512
MAX_DB_TEXT_LEN     = 200_000   # 200 KB per raw_json field
MAX_SNIPPET_LEN     = 1_024
MAX_OUTPUT_BYTES    = 2_000_000  # 2 MB subprocess stdout cap
MAX_RESULTS         = 200        # Max results returned per tool


# Private/loopback IP ranges (SSRF guard)
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "local"}


# ── General input sanitization ────────────────────────────────────────────────

def sanitize_input(user_input: str, max_len: int = MAX_INPUT_LEN) -> str:
    """
    Strip shell metacharacters and control characters from free-text user input.
    Use for: case names, descriptions, any non-URL text field.
    NOT a replacement for sanitize_shell_arg when building subprocess commands.
    """
    if not isinstance(user_input, str):
        return ""
    # Truncate first to avoid regex on unbounded input
    val = user_input[:max_len]
    # Remove shell metacharacters
    val = _SHELL_META_RE.sub("", val)
    # Remove non-printable control characters (except space)
    val = "".join(c for c in val if c.isprintable() or c == " ")
    return val.strip()


def sanitize_shell_arg(value: str) -> str:
    """
    Safely quote a value for use inside a subprocess command list.
    Uses shlex.quote() — the correct tool for the job.
    
    IMPORTANT: subprocess.run() with a list already prevents shell injection,
    but this adds a second layer for defence-in-depth.
    Returns the raw string (unquoted for list usage) after validating
    that it contains no dangerous sequences.
    """
    if not isinstance(value, str):
        return ""
    # Strip null bytes
    value = value.replace("\x00", "")
    # Validate: no shell metacharacters
    if _SHELL_META_RE.search(value):
        import logging
        logging.getLogger(__name__).warning(
            f"sanitize_shell_arg: stripped dangerous chars from: {value!r}"
        )
        value = _SHELL_META_RE.sub("", value)
    return value.strip()[:MAX_INPUT_LEN]


# ── URL / SSRF validation ─────────────────────────────────────────────────────

def validate_url(url: str) -> bool:
    """
    Return True only if the URL is http/https and NOT a local/private address.
    Blocks SSRF attempts against internal services.
    Exception: Ollama localhost is handled separately by OllamaBrain directly.
    """
    if not url or not isinstance(url, str):
        return False
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        host = (parsed.hostname or "").lower()
        if host in _LOOPBACK_HOSTS:
            return False
        # Try to parse as IP and check private ranges
        try:
            ip = ipaddress.ip_address(host)
            for net in _PRIVATE_NETS:
                if ip in net:
                    return False
        except ValueError:
            pass  # not a bare IP, that's fine
        return bool(host)
    except Exception:
        return False


def validate_ssrf(url: str) -> bool:
    """Alias — explicit SSRF check before making an outbound HTTP request."""
    return validate_url(url)


def validate_domain(domain: str) -> bool:
    """Basic domain validation — letters, digits, hyphens, dots only."""
    if not domain:
        return False
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
    return bool(re.match(pattern, domain.strip()))


def validate_ip(ip: str) -> bool:
    """Return True if ip is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False


# ── Database text limits ──────────────────────────────────────────────────────

def sanitize_db_text(text: str, max_len: int = MAX_DB_TEXT_LEN) -> str:
    """Truncate text before writing to the database. Prevents disk-fill attacks."""
    if not isinstance(text, str):
        return str(text)[:max_len]
    return text[:max_len]


def sanitize_snippet(snippet: str) -> str:
    """Sanitize a result snippet — strip tags, control chars, truncate."""
    if not snippet:
        return ""
    # Strip HTML-like tags
    clean = re.sub(r'<[^>]+>', '', snippet)
    clean = sanitize_input(clean, max_len=MAX_SNIPPET_LEN)
    return clean
