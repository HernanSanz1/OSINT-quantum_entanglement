"""
Entity extractor — pulls emails, domains, IPs, usernames from raw text.
Used to auto-populate case data from tool reports.
"""
import re
from typing import Dict, List

from .entity_filters import DOMAIN_PATTERN, PHONE_PATTERN, is_dns_txt_record, is_noise_domain, is_plausible_phone


# ── Patterns ──────────────────────────────────────────────────────────────────

_RE_EMAIL   = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_RE_DOMAIN  = re.compile(DOMAIN_PATTERN)
_RE_IP      = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_URL     = re.compile(r"https?://[^\s\"<>]+")
_RE_PHONE   = re.compile(PHONE_PATTERN)
_RE_HASH_MD5    = re.compile(r"\b[a-fA-F0-9]{32}\b")
_RE_HASH_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")

# Noise domains to ignore
_NOISE_DOMAINS = {
    "google.com", "duckduckgo.com", "bing.com", "yahoo.com",
    "facebook.com", "twitter.com", "youtube.com", "wikipedia.org",
    "w3.org", "github.com", "amazonaws.com", "cloudflare.com",
}


class EntityExtractor:
    """Extract typed entities from free-form OSINT report text."""

    def extract(self, text: str) -> Dict[str, List[str]]:
        """Returns a dict of DataType → list of unique values."""
        emails   = list(dict.fromkeys(_RE_EMAIL.findall(text)))
        urls     = list(dict.fromkeys(_RE_URL.findall(text)))
        ips      = list(dict.fromkeys(_RE_IP.findall(text)))
        domains  = [
            d for d in dict.fromkeys(_RE_DOMAIN.findall(text))
            if d.lower() not in _NOISE_DOMAINS and not is_noise_domain(d) and d not in ips
        ]
        phones   = list(dict.fromkeys(
            m.group() for m in _RE_PHONE.finditer(text) if is_plausible_phone(m.group())
        ))
        hashes   = list(dict.fromkeys(
            _RE_HASH_SHA256.findall(text) + _RE_HASH_MD5.findall(text)
        ))

        return {
            "email":   emails,
            "domain":  domains[:20],   # cap to avoid noise
            "ip":      ips[:20],
            "url":     urls[:20],
            "phone":   phones,
            "hash":    hashes,
        }

    def extract_from_results(self, results: List) -> Dict[str, List[str]]:
        """Extract from a list of SearchResult objects."""
        def text(rs):
            return " ".join(f"{r.title} {r.snippet} {r.url}" for r in rs)

        out = self.extract(text(results))
        # los registros TXT del DNS guardan tokens de verificación, no hashes de archivos
        out["hash"] = self.extract(text(r for r in results if not is_dns_txt_record(r.title)))["hash"]
        return out
