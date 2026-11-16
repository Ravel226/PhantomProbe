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

    def test_without_a_wildcard_there_is_no_wildcard_note(self, engine, monkeypatch):
        stub_dns(monkeypatch, resolving={"www.victim.com"})
        findings = engine.enumerate_subdomains(["www", "nope"])
        assert [f.id for f in findings] == ["SUBDOMAIN-www"]


def stub_wildcard(monkeypatch, wildcard, explicit=None, cnames=None,
                  wildcard_cname=None, target="victim.com"):
    """
    Every name under the target resolves, as it does behind wildcard DNS.

    `wildcard` is a callable returning the wildcard's addresses for one query,
    so a rotating pool can be modelled. `explicit` gives names their own
    addresses; `cnames` gives names their own CNAME, and every other name
    answers with `wildcard_cname` when one is set.
    """
    explicit = explicit or {}
    cnames = cnames or {}

    def fake_getaddrinfo(host, *args, **kwargs):
        if host in explicit:
            addresses = explicit[host]
        elif host.endswith("." + target):
            addresses = wildcard()
        else:
            raise socket.gaierror("not found")
        return [(2, 1, 6, "", (ip, 0)) for ip in addresses]

    def fake_records(name, rtype, timeout=10):
        if rtype != "CNAME":
            return []
        if name in cnames:
            return [cnames[name]]
        return [wildcard_cname] if wildcard_cname else []

    monkeypatch.setattr("phantomprobe.active.socket.getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr("phantomprobe.doh.records", fake_records)


def subdomains(findings):
    """The hostnames reported, leaving the wildcard note out."""
    return [f.title.split(": ")[1] for f in findings if f.id != "SUBDOMAIN-Wildcard"]


class TestWildcard:
    """
    Behind wildcard DNS every name resolves. A real scan of a wildcard domain
    reported all 198 wordlist names as subdomains, nine tenths of its report,
    even though phase 1 had already flagged the wildcard.
    """

    def test_the_wordlist_is_not_reported_as_subdomains(self, engine, monkeypatch):
        stub_wildcard(monkeypatch, wildcard=lambda: ["9.9.9.9"])
        findings = engine.enumerate_subdomains(["www", "api", "dev", "staging"])
        assert subdomains(findings) == []
        assert engine.found_subdomains == []

    def test_a_name_with_its_own_address_is_still_reported(self, engine, monkeypatch):
        stub_wildcard(monkeypatch, wildcard=lambda: ["9.9.9.9"],
                      explicit={"api.victim.com": ["5.5.5.5"]})
        findings = engine.enumerate_subdomains(["www", "api", "dev"])
        assert subdomains(findings) == ["api.victim.com"]
        assert engine.found_subdomains == ["api.victim.com"]

    def test_what_was_held_back_is_accounted_for(self, engine, monkeypatch):
        """Filtering must not be silent: one note says how many and why."""
        stub_wildcard(monkeypatch, wildcard=lambda: ["9.9.9.9"],
                      explicit={"api.victim.com": ["5.5.5.5"]})
        findings = engine.enumerate_subdomains(["www", "api", "dev"])
        note = [f for f in findings if f.id == "SUBDOMAIN-Wildcard"]
        assert len(note) == 1
        assert "Of 3 names tried, 2 returned only the wildcard" in note[0].description
        assert "1 answered differently" in note[0].description
        assert "9.9.9.9" in note[0].evidence

    def test_a_rotating_wildcard_is_learned_across_probes(self, engine, monkeypatch):
        """
        Round-robin DNS answers with one address of several. A single probe
        would learn one of them and report every name that drew another.
        """
        pool = ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
        calls = {"n": 0}

        def rotate():
            calls["n"] += 1
            return [pool[calls["n"] % len(pool)]]

        stub_wildcard(monkeypatch, wildcard=rotate)
        findings = engine.enumerate_subdomains(["www", "api", "dev", "mail", "vpn"])
        assert subdomains(findings) == []

    def test_a_shared_cname_marks_the_wildcard_when_addresses_do_not(
            self, engine, monkeypatch):
        """
        A wildcard CNAME onto a large pool can return addresses the probes
        never saw. The CNAME is then the stable signal: only a name with a
        different one has a record of its own.
        """
        calls = {"n": 0}

        def never_the_same():
            calls["n"] += 1
            return [f"10.0.{calls['n'] // 250}.{calls['n'] % 250}"]

        stub_wildcard(monkeypatch, wildcard=never_the_same,
                      wildcard_cname="pool.cdn.example",
                      cnames={"blog.victim.com": "victim.github.io"})
        findings = engine.enumerate_subdomains(["www", "blog", "dev"])
        assert subdomains(findings) == ["blog.victim.com"]

    def test_the_wildcard_cname_is_shown_in_the_note(self, engine, monkeypatch):
        stub_wildcard(monkeypatch, wildcard=lambda: ["9.9.9.9"],
                      wildcard_cname="victim.com")
        note = engine.enumerate_subdomains(["www"])[0]
        assert note.id == "SUBDOMAIN-Wildcard"
        assert "Wildcard CNAME: victim.com" in note.evidence

    def test_every_candidate_is_still_recorded_for_the_takeover_check(
            self, engine, monkeypatch):
        stub_wildcard(monkeypatch, wildcard=lambda: ["9.9.9.9"])
        engine.enumerate_subdomains(["www", "gone"])
        assert engine.subdomain_candidates == ["www.victim.com", "gone.victim.com"]

    def test_the_phase_summary_counts_hosts_not_the_note(
            self, engine, monkeypatch, capsys):
        stub_wildcard(monkeypatch, wildcard=lambda: ["9.9.9.9"],
                      explicit={"api.victim.com": ["5.5.5.5"]})
        monkeypatch.setattr(engine, "scan_ports", lambda: [])
        monkeypatch.setattr(engine, "fingerprint_tech", lambda: [])
        monkeypatch.setattr(ActiveReconEngine, "COMMON_SUBDOMAINS", ["www", "api"])
        engine.run(check_takeover=False)
        assert "  - Subdomains: 1\n" in capsys.readouterr().out


def serve(monkeypatch, headers=(), body=""):
    """Answer the fingerprinting request with these headers and this page."""
    from http.client import HTTPMessage

    message = HTTPMessage()
    for name, value in headers:
        # Assignment appends, so a repeated Set-Cookie stays repeated.
        message[name] = value

    class _Response:
        headers = message

        def read(self, *_):
            return body.encode()

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

    monkeypatch.setattr("phantomprobe.active.safe_urlopen",
                        lambda req, context=None, timeout=10: _Response())


def detected(engine):
    """Technology to evidence, from one fingerprinting pass."""
    return {f.title.split(": ")[1]: f.evidence for f in engine.fingerprint_tech()}


class TestFingerprinting:
    """
    Signatures used to be substrings searched across headers and page text
    together. A real scan of a WordPress site reported Java and Node.js,
    because the page contained "javascript" and the word "node".
    """

    @pytest.mark.parametrize("body", [
        '<script type="text/javascript" src="/app.js"></script>',  # java
        '<link href="https://cdn.jsdelivr.net/npm/x.css">',         # .net
        '<link rel="stylesheet" href="/css3-reset.css">',           # s3
        '<p>New laws on passenger rights. Express delivery.</p>',   # aws, ruby, node
        '<p>Learn Python, Ruby on Rails, Django and Laravel.</p>',  # prose
        '<div class="node">a tree node</div>',                      # node
    ])
    def test_words_in_a_page_are_not_technologies(self, engine, monkeypatch, body):
        serve(monkeypatch, body=body)
        assert detected(engine) == {}

    def test_a_server_banner_is_reported_with_its_evidence(self, engine, monkeypatch):
        serve(monkeypatch, headers=[("Server", "nginx/1.24.0")])
        assert detected(engine) == {"nginx": "Server: nginx/1.24.0"}

    def test_tomcats_connector_is_java_not_apache(self, engine, monkeypatch):
        serve(monkeypatch, headers=[("Server", "Apache-Coyote/1.1")])
        assert set(detected(engine)) == {"java"}

    def test_gunicorn_is_python_and_not_a_ruby_unicorn(self, engine, monkeypatch):
        serve(monkeypatch, headers=[("Server", "gunicorn/20.1.0")])
        assert set(detected(engine)) == {"python"}

    def test_iis_is_reported_as_iis(self, engine, monkeypatch):
        serve(monkeypatch, headers=[("Server", "Microsoft-IIS/10.0"),
                                    ("X-Powered-By", "ASP.NET")])
        assert set(detected(engine)) == {"iis", "asp.net"}

    def test_a_session_cookie_names_the_stack_without_leaking_its_value(
            self, engine, monkeypatch):
        serve(monkeypatch, headers=[("Set-Cookie", "PHPSESSID=s3cr3tvalue; path=/")])
        found = detected(engine)
        assert found == {"php": "Cookie: PHPSESSID"}
        assert "s3cr3tvalue" not in found["php"]

    def test_every_set_cookie_is_read_not_only_the_last(self, engine, monkeypatch):
        serve(monkeypatch, headers=[("Set-Cookie", "JSESSIONID=abc; Path=/"),
                                    ("Set-Cookie", "theme=dark")])
        assert set(detected(engine)) == {"java"}

    def test_a_request_id_header_is_not_echoed(self, engine, monkeypatch):
        serve(monkeypatch, headers=[("CF-RAY", "8a1b2c3d4e5f6789-AMS")])
        found = detected(engine)
        assert set(found) == {"cloudflare"}
        assert "8a1b2c3d" not in found["cloudflare"]

    def test_wordpress_is_recognised_by_its_asset_paths(self, engine, monkeypatch):
        serve(monkeypatch,
              body='<link rel="stylesheet" href="/wp-content/themes/x/style.css">')
        assert set(detected(engine)) == {"wordpress"}

    def test_the_generator_tag_carries_a_version_the_cve_matcher_can_use(
            self, engine, monkeypatch):
        from phantomprobe.cve import CVEMatcher

        serve(monkeypatch, body='<meta name="generator" content="WordPress 6.4.2" />')
        evidence = detected(engine)["wordpress"]

        assert evidence == "Markup: WordPress 6.4.2"
        assert CVEMatcher().extract_tech_version(evidence) == [("wordpress", "6.4.2")]

    def test_every_signature_compiles_and_names_a_place(self):
        import re

        for tech, where, pattern in ActiveReconEngine.TECH_SIGNATURES:
            assert where == where.lower(), f"{tech}: header names are lowercase"
            if pattern is not None:
                re.compile(pattern)
            else:
                assert where != "body", f"{tech}: a body signature needs a pattern"
