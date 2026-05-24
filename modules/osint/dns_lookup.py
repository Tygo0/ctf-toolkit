"""
DNS lookup — queries all common record types using dnspython.
Returns structured results per record type.
"""

import dns.resolver
import dns.reversename
import dns.exception
from dataclasses import dataclass, field
from typing import Optional


# ── Supported record types ────────────────────────────────────────────────────

ALL_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", "SRV", "CAA"]


@dataclass
class DNSRecord:
    rtype: str
    value: str
    ttl: Optional[int] = None
    priority: Optional[int] = None   # MX / SRV


@dataclass
class DNSResult:
    query: str
    record_type: str
    records: list[DNSRecord]     = field(default_factory=list)
    warnings: list[str]          = field(default_factory=list)
    nameserver_used: Optional[str] = None


# ── Record parsers ────────────────────────────────────────────────────────────

def _parse_answer(rtype: str, answer) -> list[DNSRecord]:
    records = []
    for rdata in answer:
        ttl = answer.ttl

        if rtype == "MX":
            records.append(DNSRecord(
                rtype=rtype,
                value=str(rdata.exchange).rstrip("."),
                ttl=ttl,
                priority=rdata.preference,
            ))
        elif rtype == "SOA":
            records.append(DNSRecord(
                rtype=rtype,
                value=(
                    f"mname={str(rdata.mname).rstrip('.')}  "
                    f"rname={str(rdata.rname).rstrip('.')}  "
                    f"serial={rdata.serial}  "
                    f"refresh={rdata.refresh}  "
                    f"retry={rdata.retry}  "
                    f"expire={rdata.expire}"
                ),
                ttl=ttl,
            ))
        elif rtype == "TXT":
            # TXT records are byte-string lists; join and decode
            parts = [p.decode("utf-8", errors="replace") for p in rdata.strings]
            records.append(DNSRecord(rtype=rtype, value=" ".join(parts), ttl=ttl))
        elif rtype == "SRV":
            records.append(DNSRecord(
                rtype=rtype,
                value=f"{str(rdata.target).rstrip('.')}:{rdata.port} weight={rdata.weight}",
                ttl=ttl,
                priority=rdata.priority,
            ))
        elif rtype == "CAA":
            records.append(DNSRecord(
                rtype=rtype,
                value=f"{rdata.flags} {rdata.tag.decode()} {rdata.value.decode()}",
                ttl=ttl,
            ))
        else:
            # A, AAAA, NS, CNAME, PTR
            val = str(rdata)
            if rtype in ("NS", "CNAME", "PTR"):
                val = val.rstrip(".")
            records.append(DNSRecord(rtype=rtype, value=val, ttl=ttl))

    return records


# ── Core lookup functions ─────────────────────────────────────────────────────

def lookup(target: str, rtype: str, nameserver: Optional[str] = None) -> DNSResult:
    """
    Query a specific DNS record type for a target.

    Args:
        target:     Domain name or IP (for PTR).
        rtype:      Record type string, e.g. "A", "MX", "TXT".
        nameserver: Optional custom resolver IP.

    Returns:
        DNSResult with records list.
    """
    rtype = rtype.upper()
    result = DNSResult(query=target, record_type=rtype)

    resolver = dns.resolver.Resolver()
    if nameserver:
        resolver.nameservers = [nameserver]
        result.nameserver_used = nameserver

    try:
        # PTR records: convert IP to in-addr.arpa first
        query_target = target
        if rtype == "PTR":
            try:
                query_target = str(dns.reversename.from_address(target))
            except Exception:
                result.warnings.append(f"Could not convert '{target}' to PTR format.")
                return result

        answer = resolver.resolve(query_target, rtype)
        result.records = _parse_answer(rtype, answer)

    except dns.resolver.NXDOMAIN:
        result.warnings.append(f"Domain '{target}' does not exist (NXDOMAIN).")
    except dns.resolver.NoAnswer:
        result.warnings.append(f"No {rtype} records found for '{target}'.")
    except dns.resolver.Timeout:
        result.warnings.append(f"DNS query timed out for '{target}'.")
    except dns.resolver.NoNameservers:
        result.warnings.append(f"No nameservers available for '{target}'.")
    except Exception as e:
        result.warnings.append(f"DNS error: {e}")

    return result


def lookup_all(target: str, nameserver: Optional[str] = None) -> list[DNSResult]:
    """Query all common record types for a target. Returns only non-empty results."""
    results = []
    for rtype in ALL_RECORD_TYPES:
        r = lookup(target, rtype, nameserver)
        if r.records:   # only keep types that returned data
            results.append(r)
    return results


def reverse_lookup(ip: str) -> DNSResult:
    """Reverse DNS lookup: IP → hostname."""
    return lookup(ip, "PTR")
