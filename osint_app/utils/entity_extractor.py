"""
Entity extractor — pulls emails, domains, IPs, usernames from raw text.
Used to auto-populate case data from tool reports.
"""
import re
from typing import Dict, List


# ── Patterns ──────────────────────────────────────────────────────────────────

_RE_EMAIL   = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_RE_DOMAIN  = re.compile(r"\b(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}\b")
_RE_IP      = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_URL     = re.compile(r"https?://[^\s\"<>]+")
_RE_PHONE   = re.compile(r"(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}")
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
            if d.lower() not in _NOISE_DOMAINS and not any(ip == d for ip in ips)
        ]
        phones   = list(dict.fromkeys(_RE_PHONE.findall(text)))
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
        combined = " ".join(
            f"{r.title} {r.snippet} {r.url}" for r in results
        )
        return self.extract(combined)
