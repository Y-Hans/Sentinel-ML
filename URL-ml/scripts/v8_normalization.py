"""V8 URL Normalization & Deterministic Parent / Origin Extraction Pipeline.

Provides deterministic canonicalization:
- Scheme extraction and normalization
- Host extraction, IPv6 bracket stripping, trailing dot removal, lowercase normalization
- Registrable domain (effective parent / eTLD+1) extraction using multi-label public suffix list
- Subdomain isolation (e.g., github.com.evil.example -> parent is evil.example, NOT github.com)
- Prefix isolation (e.g., evil-github.com -> parent is evil-github.com, NOT github.com)
- Path normalization, unquoting, segment analysis
- Query parameter extraction and parsing
- Fragment extraction
"""
from __future__ import annotations
import ipaddress
import re
from urllib.parse import unquote, urlsplit

# Common multi-label effective TLDs
TWO_LABEL_SUFFIXES = {
    "ac.in", "ac.jp", "ac.uk", "co.in", "co.jp", "co.nz", "co.uk",
    "com.au", "com.br", "com.cn", "com.mx", "com.sg", "com.tr",
    "gov.in", "gov.uk", "net.au", "net.in", "org.au", "org.in", "org.uk",
    "edu.au", "edu.cn", "gob.es", "gob.mx", "gc.ca", "gouv.fr", "fed.us",
    "edu.in", "res.in", "github.io", "gitlab.io", "pages.dev", "web.app"
}


def is_ip_host(host: str) -> bool:
    """Check if host is an IPv4 or IPv6 address."""
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_ipv4_host(host: str) -> bool:
    """Check if host is an IPv4 address."""
    if not host:
        return False
    try:
        return isinstance(ipaddress.ip_address(host), ipaddress.IPv4Address)
    except ValueError:
        return False


def extract_parent_domain(host: str) -> str:
    """Extract effective registrable domain (eTLD+1) from host.
    
    Guarantees:
    - github.com.evil.example -> evil.example
    - evil-github.com -> evil-github.com
    - 192.168.1.1 -> 192.168.1.1
    - chessigma.com -> chessigma.com
    - codenames.game -> codenames.game
    - crazygames.io -> crazygames.io
    """
    if not host:
        return ""
    if is_ip_host(host):
        return host
    
    labels = [p for p in host.split(".") if p]
    if not labels:
        return host
    if len(labels) == 1:
        return labels[0]
    
    # Check 2-label suffix
    suffix_len = 1
    if len(labels) >= 2:
        two_tld = f"{labels[-2]}.{labels[-1]}"
        if two_tld in TWO_LABEL_SUFFIXES:
            suffix_len = 2
            
    if len(labels) > suffix_len:
        return f"{labels[-(suffix_len + 1)]}.{'.'.join(labels[-suffix_len:])}"
    return ".".join(labels)


def extract_subdomain_parts(host: str, parent_domain: str) -> list[str]:
    """Extract subdomain labels preceding the parent domain."""
    if not host or is_ip_host(host) or host == parent_domain:
        return []
    if host.endswith("." + parent_domain):
        sub_str = host[:-len("." + parent_domain)]
        return [p for p in sub_str.split(".") if p]
    return []


SCHEME_PREFIX_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
TRAILING_DELIMS = ".,;:!?)]}\"'>" + "<"


def canonicalize_url(url: str) -> str:
    """Canonicalize URL matching Sentinel Android canonicalization contract.

    - Strips leading/trailing whitespace and trailing sentence/punctuation delimiters
    - Preserves explicit scheme (lowercasing scheme prefix e.g. HTTP:// -> http://)
    - Normalizes protocol-relative //example.com -> https://example.com
    - Prepends https:// to schemeless inputs (e.g. www.domain.com -> https://www.domain.com)
    - Returns empty string for empty/whitespace-only input
    """
    if not url:
        return ""
    trimmed = str(url).strip()
    while trimmed and trimmed[-1] in TRAILING_DELIMS:
        trimmed = trimmed[:-1].strip()
    if not trimmed:
        return ""
    m = SCHEME_PREFIX_RE.match(trimmed)
    if m:
        scheme = m.group(0).lower()
        return scheme + trimmed[len(m.group(0)):]
    if trimmed.startswith("//"):
        return f"https:{trimmed}"
    return f"https://{trimmed}"


class ParsedV8URL:
    """Deterministic structured representation of a URL."""
    __slots__ = (
        "raw", "scheme", "host", "port", "parent_domain",
        "subdomain_labels", "subdomain_depth", "path", "path_segments",
        "clean_path", "query", "query_params", "fragment", "is_ip"
    )

    def __init__(self, raw: str):
        canonical = canonicalize_url(raw)
        raw_str = canonical if canonical else str(raw).strip()
        self.raw = raw_str
        
        # Scheme extraction
        p = urlsplit(raw_str if "://" in raw_str else "//" + raw_str, scheme="https")
        self.scheme = (p.scheme or "https").lower()
        
        # Host extraction
        try:
            h = (p.hostname or "").lower().rstrip(".")
        except (ValueError, TypeError):
            h = (p.netloc.split(":")[0] if p.netloc else "").lower().rstrip(".")
            
        # Strip IPv6 brackets if present
        if h.startswith("[") and h.endswith("]"):
            h = h[1:-1]
        self.host = h
        self.is_ip = is_ip_host(h)
        
        # Port extraction
        try:
            self.port = p.port
        except (ValueError, TypeError):
            self.port = None
            
        # Parent domain (eTLD+1)
        self.parent_domain = extract_parent_domain(self.host)
        
        # Subdomains
        self.subdomain_labels = extract_subdomain_parts(self.host, self.parent_domain)
        self.subdomain_depth = len(self.subdomain_labels)
        
        # Path
        self.path = p.path or ""
        self.path_segments = [s for s in self.path.split("/") if s]
        self.clean_path = "/".join(self.path_segments)
        
        # Query
        self.query = p.query or ""
        self.query_params = [q for q in self.query.split("&") if q]
        
        # Fragment
        self.fragment = p.fragment or ""


def parse_v8_url(url: str) -> ParsedV8URL:
    """Parse raw URL into deterministic V8 structured format."""
    return ParsedV8URL(url)
