"""
Subdomain enumerator — concurrent DNS brute-force with a built-in wordlist
and optional custom wordlist support.
"""

import concurrent.futures
from dataclasses import dataclass, field
from typing import Optional, Callable

import dns.resolver
import dns.exception


# ── Built-in wordlist (common subdomains) ─────────────────────────────────────

BUILTIN_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "email",
    "remote", "blog", "dev", "staging", "test", "api", "cdn", "static",
    "assets", "media", "img", "images", "upload", "uploads", "download",
    "downloads", "files", "backup", "secure", "login", "admin", "panel",
    "portal", "dashboard", "cpanel", "whm", "webdisk", "ns1", "ns2",
    "ns3", "mx", "mx1", "mx2", "vpn", "ssh", "rdp", "git", "svn",
    "jira", "confluence", "jenkins", "ci", "gitlab", "github", "docs",
    "wiki", "help", "support", "status", "monitor", "nagios", "grafana",
    "prometheus", "elasticsearch", "kibana", "redis", "db", "database",
    "mysql", "postgres", "mongo", "internal", "intranet", "extranet",
    "corp", "office", "store", "shop", "pay", "billing", "invoice",
    "auth", "sso", "oauth", "id", "accounts", "account", "user",
    "users", "members", "member", "customer", "clients", "client",
    "app", "apps", "mobile", "m", "wap", "old", "new", "beta",
    "alpha", "preview", "demo", "sandbox", "lab", "labs", "research",
    "data", "analytics", "metrics", "stats", "report", "reports",
    "forum", "forums", "community", "chat", "irc", "mx0", "exchange",
    "autodiscover", "autoconfig", "calendar", "meet", "video",
]


# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class SubdomainHit:
    subdomain: str
    fqdn: str
    ip_addresses: list[str] = field(default_factory=list)
    cname: Optional[str]    = None


@dataclass
class SubdomainResult:
    domain: str
    hits: list[SubdomainHit]        = field(default_factory=list)
    checked: int                    = 0
    errors: int                     = 0
    warnings: list[str]             = field(default_factory=list)


# ── Core resolver ─────────────────────────────────────────────────────────────

def _resolve_subdomain(
    subdomain: str,
    domain: str,
    resolver: dns.resolver.Resolver,
) -> Optional[SubdomainHit]:
    """Try to resolve a subdomain. Returns SubdomainHit if it exists, else None."""
    fqdn = f"{subdomain}.{domain}"
    ips = []
    cname = None

    try:
        # Try A record first
        answer = resolver.resolve(fqdn, "A")
        ips = [str(r) for r in answer]
    except dns.resolver.NXDOMAIN:
        return None
    except dns.resolver.NoAnswer:
        # No A record — check for CNAME
        try:
            c_answer = resolver.resolve(fqdn, "CNAME")
            cname = str(c_answer[0].target).rstrip(".")
        except Exception:
            return None
    except dns.exception.DNSException:
        return None
    except Exception:
        return None

    return SubdomainHit(subdomain=subdomain, fqdn=fqdn, ip_addresses=ips, cname=cname)


# ── Main enumerator ───────────────────────────────────────────────────────────

def enumerate_subdomains(
    domain: str,
    wordlist: Optional[list[str]] = None,
    threads: int = 30,
    nameserver: Optional[str] = None,
    progress_cb: Optional[Callable[[str], None]] = None,
) -> SubdomainResult:
    """
    Brute-force enumerate subdomains of a domain via DNS resolution.

    Args:
        domain:      Target domain (e.g. "example.com").
        wordlist:    List of subdomain prefixes. Uses built-in list if None.
        threads:     Number of concurrent resolver threads.
        nameserver:  Optional custom nameserver IP.
        progress_cb: Called with each subdomain being tried.

    Returns:
        SubdomainResult with all discovered subdomains.
    """
    result = SubdomainResult(domain=domain)
    words = wordlist or BUILTIN_WORDLIST

    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 4
    if nameserver:
        resolver.nameservers = [nameserver]

    result.checked = len(words)

    def _worker(sub: str) -> Optional[SubdomainHit]:
        if progress_cb:
            progress_cb(sub)
        return _resolve_subdomain(sub, domain, resolver)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_worker, sub): sub for sub in words}
        for future in concurrent.futures.as_completed(futures):
            try:
                hit = future.result()
                if hit:
                    result.hits.append(hit)
            except Exception:
                result.errors += 1

    # Sort hits alphabetically
    result.hits.sort(key=lambda h: h.subdomain)
    return result
