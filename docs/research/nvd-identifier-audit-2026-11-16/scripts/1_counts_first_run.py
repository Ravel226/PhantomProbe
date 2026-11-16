"""
Count CVEs under candidate second identifiers, against the public NVD API.

For each candidate vendor:product it records how many CVEs NVD holds and the
publication dates of the oldest and newest, so a legacy-only identifier can be
told from one NVD still files under. Anonymous rate limit: 5 requests / 30s.
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

# tech, vendor, product  (primary pairs are included so both sides are measured)
CANDIDATES = [
    ("nginx", "f5", "nginx"), ("nginx", "f5", "nginx_open_source"), ("nginx", "nginx", "nginx"),
    ("mysql", "oracle", "mysql"), ("mysql", "mysql", "mysql"), ("mysql", "oracle", "mysql_server"),
    ("redis", "redis", "redis"), ("redis", "redislabs", "redis"),
    ("node.js", "nodejs", "node.js"), ("node.js", "joyent", "node.js"),
    ("joomla", "joomla", "joomla"), ("joomla", "joomla", "joomla\\!"),
    ("iis", "microsoft", "internet_information_server"),
    ("iis", "microsoft", "internet_information_services"),
    ("dotnet", "microsoft", ".net_framework"), ("dotnet", "microsoft", ".net"),
    ("java", "oracle", "jdk"), ("java", "oracle", "jre"), ("java", "oracle", "openjdk"),
    ("litespeed", "litespeedtech", "litespeed_web_server"),
    ("litespeed", "litespeedtech", "openlitespeed"),
    ("traefik", "traefik", "traefik"), ("traefik", "containous", "traefik"),
    ("varnish", "varnish_cache_project", "varnish_cache"),
    ("varnish", "varnish-software", "varnish_cache"), ("varnish", "varnish-cache", "varnish"),
    ("jetty", "eclipse", "jetty"), ("jetty", "mortbay", "jetty"), ("jetty", "jetty", "jetty"),
    ("laravel", "laravel", "laravel"), ("laravel", "laravel", "framework"),
    ("rails", "rubyonrails", "rails"), ("rails", "rubyonrails", "ruby_on_rails"),
    ("spring", "vmware", "spring_framework"), ("spring", "pivotal_software", "spring_framework"),
    ("spring", "springsource", "spring_framework"),
    ("symfony", "sensiolabs", "symfony"), ("symfony", "symfony", "symfony"),
    ("next.js", "vercel", "next.js"), ("next.js", "zeit", "next.js"),
    ("nuxt", "nuxt", "nuxt"), ("nuxt", "nuxtjs", "nuxt.js"),
    ("angular", "angular", "angular"), ("angular", "angularjs", "angular.js"),
    ("bootstrap", "getbootstrap", "bootstrap"), ("bootstrap", "twitter", "bootstrap"),
    ("magento", "magento", "magento"), ("magento", "adobe", "magento"),
    ("magento", "adobe", "commerce"),
    ("ghost", "ghost", "ghost"), ("ghost", "tryghost", "ghost"),
    ("confluence", "atlassian", "confluence"), ("confluence", "atlassian", "confluence_server"),
    ("confluence", "atlassian", "confluence_data_center"),
    ("jira", "atlassian", "jira"), ("jira", "atlassian", "jira_server"),
    ("jira", "atlassian", "jira_data_center"),
    ("jenkins", "jenkins", "jenkins"), ("jenkins", "cloudbees", "jenkins"),
    ("elasticsearch", "elastic", "elasticsearch"),
    ("elasticsearch", "elasticsearch", "elasticsearch"),
    ("kibana", "elastic", "kibana"), ("kibana", "elasticsearch", "kibana"),
    ("memcached", "memcached", "memcached"), ("memcached", "danga", "memcached"),
    ("rabbitmq", "pivotal_software", "rabbitmq"), ("rabbitmq", "vmware", "rabbitmq"),
    ("rabbitmq", "vmware", "rabbitmq_server"), ("rabbitmq", "broadcom", "rabbitmq_server"),
    ("vsftpd", "vsftpd_project", "vsftpd"), ("vsftpd", "beasts", "vsftpd"),
    ("exim", "exim", "exim"), ("exim", "university_of_cambridge", "exim"),
    ("docker", "docker", "docker"), ("docker", "docker", "engine"),
    ("docker", "mobyproject", "moby"),
    ("express", "openjsf", "express"), ("express", "expressjs", "express"),
    ("apache", "apache", "http_server"), ("php", "php", "php"),
    ("openssl", "openssl", "openssl"), ("jquery", "jquery", "jquery"),
    ("react", "facebook", "react"),
]


def fetch(params):
    url = f"{NVD}?{params}"
    for attempt in range(4):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "cpe-check/1.0"})
            with urllib.request.urlopen(req, timeout=45) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 429, 503) and attempt < 3:
                time.sleep(20)
                continue
            return {"error": f"HTTP {exc.code}"}
        except (urllib.error.URLError, socket.timeout, TimeoutError, OSError) as exc:
            if attempt < 3:
                time.sleep(15)
                continue
            return {"error": type(exc).__name__}
    return {"error": "gave up"}


results = []
for tech, vendor, product in CANDIDATES:
    cpe = quote(f"cpe:2.3:a:{vendor}:{product}")
    first = fetch(f"virtualMatchString={cpe}&resultsPerPage=1")
    time.sleep(INTERVAL)
    row = {"tech": tech, "vendor": vendor, "product": product,
           "total": first.get("totalResults"), "error": first.get("error", "")}
    vulns = first.get("vulnerabilities") or []
    if vulns:
        row["oldest"] = vulns[0]["cve"].get("published", "")[:10]
        row["oldest_id"] = vulns[0]["cve"].get("id")
    total = row["total"] or 0
    if total > 1:
        last = fetch(f"virtualMatchString={cpe}&resultsPerPage=1&startIndex={total - 1}")
        time.sleep(INTERVAL)
        vulns = last.get("vulnerabilities") or []
        if vulns:
            row["newest"] = vulns[0]["cve"].get("published", "")[:10]
            row["newest_id"] = vulns[0]["cve"].get("id")
    elif total == 1:
        row["newest"], row["newest_id"] = row.get("oldest"), row.get("oldest_id")
    results.append(row)
    with open(OUT, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=1)
    print(f"{tech:<14} {vendor}:{product:<32} total={row['total']} "
          f"{row.get('oldest', '')} .. {row.get('newest', '')} {row['error']}", flush=True)

print("DONE", len(results))
