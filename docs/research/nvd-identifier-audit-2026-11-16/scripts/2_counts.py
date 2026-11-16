"""
Count CVEs under candidate second identifiers (one request each).

Anonymous NVD rate limit: 5 requests / 30s. Results are written after every
row so an interrupted run still leaves what it measured.
"""
import json
import socket
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import quote

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OUT = sys.argv[1]
INTERVAL = 6.6

# tech, vendor, product: candidates only; primaries are covered by the audit.
CANDIDATES = [
    ("redis", "redislabs", "redis"),
    ("iis", "microsoft", "internet_information_services"),
    ("node.js", "joyent", "node.js"),
    ("joomla", "joomla", "joomla\\!"),
    ("joomla", "joomla", "joomla"),
    ("jetty", "mortbay", "jetty"),
    ("jetty", "jetty", "jetty"),
    ("spring", "pivotal_software", "spring_framework"),
    ("spring", "springsource", "spring_framework"),
    ("next.js", "zeit", "next.js"),
    ("bootstrap", "twitter", "bootstrap"),
    ("angular", "angularjs", "angular.js"),
    ("magento", "adobe", "magento"),
    ("magento", "adobe", "commerce"),
    ("confluence", "atlassian", "confluence_server"),
    ("confluence", "atlassian", "confluence_data_center"),
    ("confluence", "atlassian", "confluence"),
    ("jira", "atlassian", "jira_server"),
    ("jira", "atlassian", "jira_data_center"),
    ("jira", "atlassian", "jira"),
    ("jenkins", "cloudbees", "jenkins"),
    ("elasticsearch", "elasticsearch", "elasticsearch"),
    ("kibana", "elasticsearch", "kibana"),
    ("rabbitmq", "vmware", "rabbitmq"),
    ("rabbitmq", "vmware", "rabbitmq_server"),
    ("rabbitmq", "broadcom", "rabbitmq_server"),
    ("rabbitmq", "pivotal_software", "rabbitmq"),
    ("traefik", "containous", "traefik"),
    ("varnish", "varnish-software", "varnish_cache"),
    ("varnish", "varnish-cache", "varnish"),
    ("laravel", "laravel", "framework"),
    ("laravel", "laravel", "laravel"),
    ("rails", "rubyonrails", "ruby_on_rails"),
    ("symfony", "symfony", "symfony"),
    ("nuxt", "nuxtjs", "nuxt.js"),
    ("ghost", "tryghost", "ghost"),
    ("memcached", "danga", "memcached"),
    ("vsftpd", "beasts", "vsftpd"),
    ("exim", "university_of_cambridge", "exim"),
    ("docker", "docker", "engine"),
    ("docker", "mobyproject", "moby"),
    ("docker", "docker", "docker"),
    ("litespeed", "litespeedtech", "openlitespeed"),
    ("express", "expressjs", "express"),
]


def count(vendor, product):
    cpe = quote(f"cpe:2.3:a:{vendor}:{product}")
    url = f"{NVD}?virtualMatchString={cpe}&resultsPerPage=1"
    for attempt in range(4):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "cpe-check/1.0"})
            with urllib.request.urlopen(req, timeout=45) as resp:
                data = json.loads(resp.read().decode())
            vulns = data.get("vulnerabilities") or []
            oldest = vulns[0]["cve"].get("published", "")[:10] if vulns else ""
            return data.get("totalResults"), oldest, ""
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 429, 503) and attempt < 3:
                time.sleep(15)
                continue
            return None, "", f"HTTP {exc.code}"
        except (urllib.error.URLError, socket.timeout, TimeoutError, OSError) as exc:
            if attempt < 3:
                time.sleep(10)
                continue
            return None, "", type(exc).__name__
    return None, "", "gave up"


results = []
for tech, vendor, product in CANDIDATES:
    total, oldest, error = count(vendor, product)
    results.append({"tech": tech, "vendor": vendor, "product": product,
                    "total": total, "oldest": oldest, "error": error})
    with open(OUT, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=1)
    print(f"{tech:<14} {vendor + ':' + product:<44} total={total} oldest={oldest} {error}",
          flush=True)
    time.sleep(INTERVAL)

print("DONE", len(results))
