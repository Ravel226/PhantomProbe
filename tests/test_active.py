"""
Tests for phase 2 enumeration.

DNS is stubbed throughout: these assert how the wordlist and the CNAME
enrichment behave, not what any real domain happens to publish today.
"""
import socket

import pytest

from phantomprobe.active import ActiveReconEngine


@pytest.fixture
def engine():
    return ActiveReconEngine("victim.com")


def stub_dns(monkeypatch, resolving, cnames=None):
    """Only names in `resolving` exist; `cnames` gives their CNAME targets."""
    def fake_getaddrinfo(host, *args, **kwargs):
        if host in resolving:
            return [(2, 1, 6, "", ("1.2.3.4", 0))]
        raise socket.gaierror("not found")

    monkeypatch.setattr("phantomprobe.active.socket.getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(
        "phantomprobe.doh.records",
        lambda name, rtype, timeout=10: (
            [cnames[name]] if cnames and name in cnames and rtype == "CNAME" else []
        ),
    )


class TestWordlist:
    def test_it_is_substantially_larger_than_a_token_list(self):
        """22 entries missed most of what a real recon pass turns up."""
        assert len(ActiveReconEngine.COMMON_SUBDOMAINS) >= 150

    def test_no_duplicates(self):
        words = ActiveReconEngine.COMMON_SUBDOMAINS
        assert len(words) == len(set(words))

    def test_entries_are_bare_labels(self):
        """A label, not a hostname: the target is appended by the caller."""
        for word in ActiveReconEngine.COMMON_SUBDOMAINS:
            assert "." not in word and " " not in word
            assert word == word.lower()

    def test_the_high_value_names_are_present(self):
        words = set(ActiveReconEngine.COMMON_SUBDOMAINS)
        for expected in ("www", "api", "admin", "staging", "vpn", "jenkins",
                         "grafana", "phpmyadmin", "autodiscover", "internal"):
            assert expected in words


class TestEnumeration:
    def test_only_resolving_names_are_reported(self, engine, monkeypatch):
        stub_dns(monkeypatch, resolving={"www.victim.com", "api.victim.com"})
        findings = engine.enumerate_subdomains(["www", "api", "nope"])
        assert {f.title.split(": ")[1] for f in findings} == {
            "www.victim.com", "api.victim.com"}

    def test_every_candidate_is_recorded_not_just_the_hits(self, engine, monkeypatch):
        """
        The takeover check needs the full list: a dangling CNAME to a dead
        service has no A record, so it never appears among the hits.
        """
        stub_dns(monkeypatch, resolving={"www.victim.com"})
        engine.enumerate_subdomains(["www", "gone"])
        assert engine.subdomain_candidates == ["www.victim.com", "gone.victim.com"]
        assert engine.found_subdomains == ["www.victim.com"]

    def test_cname_is_surfaced_in_the_evidence(self, engine, monkeypatch):
        stub_dns(monkeypatch, resolving={"blog.victim.com"},
                 cnames={"blog.victim.com": "victim.github.io"})
        finding = engine.enumerate_subdomains(["blog"])[0]
        assert "CNAME: victim.github.io" in finding.evidence

    def test_a_third_party_cname_is_flagged(self, engine, monkeypatch):
        """Where a subdomain points is the interesting half of the finding."""
        stub_dns(monkeypatch, resolving={"blog.victim.com"},
                 cnames={"blog.victim.com": "victim.github.io"})
        finding = engine.enumerate_subdomains(["blog"])[0]
        assert "third-party host" in finding.evidence

    def test_an_in_domain_cname_is_not_flagged_as_third_party(self, engine, monkeypatch):
        stub_dns(monkeypatch, resolving={"www.victim.com"},
                 cnames={"www.victim.com": "origin.victim.com"})
        finding = engine.enumerate_subdomains(["www"])[0]
        assert "CNAME: origin.victim.com" in finding.evidence
        assert "third-party host" not in finding.evidence

    def test_a_name_without_a_cname_still_reports(self, engine, monkeypatch):
        stub_dns(monkeypatch, resolving={"api.victim.com"})
        finding = engine.enumerate_subdomains(["api"])[0]
        assert "api.victim.com exists" in finding.evidence
        assert "CNAME" not in finding.evidence

    def test_no_hits_means_no_cname_lookups(self, engine, monkeypatch):
        called = []
        monkeypatch.setattr("phantomprobe.active.socket.getaddrinfo",
                            lambda *a, **k: (_ for _ in ()).throw(socket.gaierror()))
        monkeypatch.setattr("phantomprobe.doh.records",
                            lambda *a, **k: called.append(a) or [])
        assert engine.enumerate_subdomains(["nope"]) == []
        assert called == []
