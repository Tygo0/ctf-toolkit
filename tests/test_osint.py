"""
Tests for modules/osint — all network calls are mocked.
"""

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime

from modules.osint.whois_lookup import lookup as whois_lookup, WhoisResult, _pick, _fmt_date, _clean_list
from modules.osint.dns_lookup import lookup as dns_lookup, lookup_all, reverse_lookup, DNSResult, DNSRecord
from modules.osint.subdomain import enumerate_subdomains, SubdomainResult, SubdomainHit, BUILTIN_WORDLIST


# ── WHOIS helper tests ────────────────────────────────────────────────────────

class TestWhoisHelpers:

    def test_pick_single_string(self):
        assert _pick("hello") == "hello"

    def test_pick_first_from_list(self):
        assert _pick(["first", "second"]) == "first"

    def test_pick_none(self):
        assert _pick(None) is None

    def test_pick_empty_list(self):
        assert _pick([]) is None

    def test_fmt_date_datetime(self):
        dt = datetime(2023, 6, 15, 12, 0, 0)
        result = _fmt_date(dt)
        assert "2023-06-15" in result

    def test_fmt_date_list(self):
        dt = datetime(2020, 1, 1)
        result = _fmt_date([dt])
        assert "2020-01-01" in result

    def test_fmt_date_none(self):
        assert _fmt_date(None) is None

    def test_clean_list_string(self):
        assert _clean_list("hello") == ["hello"]

    def test_clean_list_deduplicates(self):
        result = _clean_list(["a", "A", "b"])
        assert len(result) == 2

    def test_clean_list_empty(self):
        assert _clean_list([]) == []

    def test_clean_list_none(self):
        assert _clean_list(None) == []


# ── WHOIS lookup tests ────────────────────────────────────────────────────────

class TestWhoisLookup:

    def _mock_whois(self):
        """Build a realistic mock WHOIS object."""
        w = MagicMock()
        w.registrar = "Example Registrar LLC"
        w.registrar_url = "https://registrar.example"
        w.whois_server = "whois.registrar.example"
        w.creation_date = datetime(2000, 1, 1)
        w.updated_date  = datetime(2023, 6, 1)
        w.expiration_date = datetime(2025, 1, 1)
        w.status = ["clientTransferProhibited"]
        w.name_servers = ["ns1.example.com", "ns2.example.com"]
        w.dnssec = "unsigned"
        w.name = "Domain Admin"
        w.org  = "Example Corp"
        w.emails = "admin@example.com"
        w.country = "US"
        w.text = "Raw WHOIS text here"
        return w

    def test_returns_whois_result(self):
        with patch("whois.whois", return_value=self._mock_whois()):
            result = whois_lookup("example.com")
        assert isinstance(result, WhoisResult)

    def test_registrar_populated(self):
        with patch("whois.whois", return_value=self._mock_whois()):
            result = whois_lookup("example.com")
        assert result.registrar == "Example Registrar LLC"

    def test_dates_populated(self):
        with patch("whois.whois", return_value=self._mock_whois()):
            result = whois_lookup("example.com")
        assert result.created is not None
        assert "2000" in result.created

    def test_name_servers_populated(self):
        with patch("whois.whois", return_value=self._mock_whois()):
            result = whois_lookup("example.com")
        assert len(result.name_servers) == 2
        assert "ns1.example.com" in result.name_servers

    def test_query_preserved(self):
        with patch("whois.whois", return_value=self._mock_whois()):
            result = whois_lookup("example.com")
        assert result.query == "example.com"

    def test_exception_stored_as_warning(self):
        with patch("whois.whois", side_effect=Exception("Network error")):
            result = whois_lookup("broken.example")
        assert len(result.warnings) > 0
        assert "WHOIS query failed" in result.warnings[0]

    def test_no_crash_on_none_fields(self):
        w = MagicMock()
        w.registrar = None
        w.whois_server = None
        w.creation_date = None
        w.updated_date  = None
        w.expiration_date = None
        w.status = None
        w.name_servers = None
        w.dnssec = None
        w.name = None
        w.org  = None
        w.emails = None
        w.country = None
        w.text = None
        with patch("whois.whois", return_value=w):
            result = whois_lookup("null.example")
        assert isinstance(result, WhoisResult)


# ── DNS record tests ──────────────────────────────────────────────────────────

class TestDNSLookup:

    def _mock_answer(self, records: list[str], rtype: str = "A", ttl: int = 300):
        answer = MagicMock()
        answer.ttl = ttl
        rdatas = []
        for val in records:
            rd = MagicMock()
            if rtype == "A":
                rd.__str__ = lambda self, v=val: v
            elif rtype == "MX":
                rd.exchange = MagicMock()
                rd.exchange.__str__ = lambda self, v=val: v + "."
                rd.preference = 10
            elif rtype == "TXT":
                rd.strings = [val.encode()]
            rdatas.append(rd)
        answer.__iter__ = lambda self: iter(rdatas)
        return answer

    def test_returns_dns_result(self):
        with patch("dns.resolver.Resolver") as MockResolver:
            mock_resolver = MockResolver.return_value
            mock_answer = self._mock_answer(["93.184.216.34"])
            mock_resolver.resolve.return_value = mock_answer
            result = dns_lookup("example.com", "A")
        assert isinstance(result, DNSResult)

    def test_nxdomain_stored_as_warning(self):
        import dns.resolver
        with patch("dns.resolver.Resolver") as MockResolver:
            mock_resolver = MockResolver.return_value
            mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN
            result = dns_lookup("nonexistent.invalid", "A")
        assert len(result.warnings) > 0
        assert result.records == []

    def test_no_answer_stored_as_warning(self):
        import dns.resolver
        with patch("dns.resolver.Resolver") as MockResolver:
            mock_resolver = MockResolver.return_value
            mock_resolver.resolve.side_effect = dns.resolver.NoAnswer
            result = dns_lookup("example.com", "AAAA")
        assert len(result.warnings) > 0
        assert result.records == []

    def test_record_type_preserved(self):
        import dns.resolver
        with patch("dns.resolver.Resolver") as MockResolver:
            mock_resolver = MockResolver.return_value
            mock_resolver.resolve.side_effect = dns.resolver.NoAnswer
            result = dns_lookup("example.com", "mx")
        assert result.record_type == "MX"

    def test_query_preserved(self):
        import dns.resolver
        with patch("dns.resolver.Resolver") as MockResolver:
            mock_resolver = MockResolver.return_value
            mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN
            result = dns_lookup("example.com", "A")
        assert result.query == "example.com"

    def test_lookup_all_returns_list(self):
        import dns.resolver
        with patch("dns.resolver.Resolver") as MockResolver:
            mock_resolver = MockResolver.return_value
            mock_resolver.resolve.side_effect = dns.resolver.NoAnswer
            results = lookup_all("example.com")
        assert isinstance(results, list)


# ── Subdomain enumeration tests ───────────────────────────────────────────────

class TestSubdomainEnumeration:

    def _mock_resolver_factory(self, existing: set[str]):
        """Create a mock DNS resolver that only resolves subdomains in `existing`."""
        import dns.resolver
        import dns.exception

        def mock_resolve(fqdn, rtype):
            sub = fqdn.split(".")[0]
            if sub in existing:
                answer = MagicMock()
                answer.ttl = 300
                rd = MagicMock()
                rd.__str__ = lambda self: "1.2.3.4"
                answer.__iter__ = lambda self: iter([rd])
                return answer
            raise dns.resolver.NXDOMAIN

        resolver = MagicMock()
        resolver.resolve.side_effect = mock_resolve
        return resolver

    def test_returns_subdomain_result(self):
        with patch("dns.resolver.Resolver") as MockResolver:
            MockResolver.return_value = self._mock_resolver_factory({"www", "mail"})
            result = enumerate_subdomains("example.com", wordlist=["www", "mail", "ftp"])
        assert isinstance(result, SubdomainResult)

    def test_finds_existing_subdomains(self):
        with patch("dns.resolver.Resolver") as MockResolver:
            MockResolver.return_value = self._mock_resolver_factory({"www", "api"})
            result = enumerate_subdomains("example.com", wordlist=["www", "api", "nope"])
        names = [h.subdomain for h in result.hits]
        assert "www" in names
        assert "api" in names

    def test_excludes_nonexistent_subdomains(self):
        with patch("dns.resolver.Resolver") as MockResolver:
            MockResolver.return_value = self._mock_resolver_factory({"www"})
            result = enumerate_subdomains("example.com", wordlist=["www", "nonexistent"])
        names = [h.subdomain for h in result.hits]
        assert "nonexistent" not in names

    def test_empty_domain_returns_empty_hits(self):
        with patch("dns.resolver.Resolver") as MockResolver:
            MockResolver.return_value = self._mock_resolver_factory(set())
            result = enumerate_subdomains("dead.example", wordlist=["www", "mail"])
        assert result.hits == []

    def test_checked_count_correct(self):
        words = ["a", "b", "c", "d"]
        with patch("dns.resolver.Resolver") as MockResolver:
            MockResolver.return_value = self._mock_resolver_factory({"a"})
            result = enumerate_subdomains("example.com", wordlist=words)
        assert result.checked == len(words)

    def test_hits_sorted_alphabetically(self):
        with patch("dns.resolver.Resolver") as MockResolver:
            MockResolver.return_value = self._mock_resolver_factory({"www", "api", "mail"})
            result = enumerate_subdomains("example.com", wordlist=["www", "api", "mail"])
        names = [h.subdomain for h in result.hits]
        assert names == sorted(names)

    def test_builtin_wordlist_not_empty(self):
        assert len(BUILTIN_WORDLIST) > 50

    def test_builtin_wordlist_has_common_subdomains(self):
        assert "www" in BUILTIN_WORDLIST
        assert "mail" in BUILTIN_WORDLIST
        assert "api" in BUILTIN_WORDLIST
        assert "admin" in BUILTIN_WORDLIST

    def test_fqdn_correctly_formed(self):
        with patch("dns.resolver.Resolver") as MockResolver:
            MockResolver.return_value = self._mock_resolver_factory({"www"})
            result = enumerate_subdomains("example.com", wordlist=["www"])
        assert result.hits[0].fqdn == "www.example.com"
