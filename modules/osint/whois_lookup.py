"""
WHOIS lookup — queries registration data for domains and IP addresses.
Normalises the raw python-whois output into a clean, consistently typed dataclass.
"""

from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime


@dataclass
class WhoisResult:
    query: str
    # Registrar
    registrar: Optional[str]        = None
    registrar_url: Optional[str]    = None
    whois_server: Optional[str]     = None
    # Dates
    created: Optional[str]          = None
    updated: Optional[str]          = None
    expires: Optional[str]          = None
    # Status & DNSSEC
    status: list[str]               = field(default_factory=list)
    dnssec: Optional[str]           = None
    # Registrant contact
    registrant_name: Optional[str]  = None
    registrant_org: Optional[str]   = None
    registrant_email: Optional[str] = None
    registrant_country: Optional[str] = None
    # Name servers
    name_servers: list[str]         = field(default_factory=list)
    # Raw text (for --verbose)
    raw_text: Optional[str]         = None
    # Errors / warnings
    warnings: list[str]             = field(default_factory=list)


def _pick(value) -> Optional[str]:
    """Return first item if list, else the value itself, stripped."""
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0] if value else None
    if value is None:
        return None
    return str(value).strip() or None


def _fmt_date(value) -> Optional[str]:
    """Format a datetime or list[datetime] as a readable string."""
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S UTC")
    return str(value).strip() or None


def _clean_list(value) -> list[str]:
    """Normalise a value to a deduplicated list of stripped strings."""
    if not value:
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    seen, result = set(), []
    for item in value:
        s = str(item).strip().lower()
        if s and s not in seen:
            seen.add(s)
            result.append(str(item).strip())
    return result


def lookup(query: str) -> WhoisResult:
    """
    Perform a WHOIS lookup for a domain or IP address.
    Returns a WhoisResult dataclass.
    """
    import whois

    result = WhoisResult(query=query)

    try:
        w = whois.whois(query)
        result.raw_text = str(w.text) if hasattr(w, "text") else None

        result.registrar      = _pick(w.registrar)
        result.registrar_url  = _pick(getattr(w, "registrar_url", None))
        result.whois_server   = _pick(w.whois_server)
        result.created        = _fmt_date(w.creation_date)
        result.updated        = _fmt_date(w.updated_date)
        result.expires        = _fmt_date(w.expiration_date)
        result.dnssec         = _pick(getattr(w, "dnssec", None))
        result.name_servers   = _clean_list(w.name_servers)
        result.status         = _clean_list(w.status)

        # Registrant — field names vary wildly between TLDs
        result.registrant_name    = _pick(
            getattr(w, "registrant_name", None) or
            getattr(w, "name", None)
        )
        result.registrant_org     = _pick(
            getattr(w, "registrant_organization", None) or
            getattr(w, "org", None)
        )
        result.registrant_email   = _pick(
            getattr(w, "registrant_email", None) or
            getattr(w, "emails", None)
        )
        result.registrant_country = _pick(
            getattr(w, "registrant_country", None) or
            getattr(w, "country", None)
        )

    except Exception as e:
        result.warnings.append(f"WHOIS query failed: {e}")

    return result
