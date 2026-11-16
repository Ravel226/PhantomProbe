"""
For each candidate second identifier that exists, ask NVD about one real
version under the primary identifier and under the candidate, and report what
the candidate adds. This is the check that decides whether it belongs in
CPE_SIBLINGS: it must be the same software, and it must return CVEs the
primary does not.
"""
import json
import socket
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import quote

sys.path.insert(0, sys.argv[1])  # the package's src directory
from phantomprobe.cpe_tables import CPE_MAPPING  # noqa: E402

COUNTS = sys.argv[2]
OUT = sys.argv[3]
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
INTERVAL = 6.6

# A version from the era each candidate identifier was in use.
VERSION = {
    ("oracle", "mysql_server"): "8.0.30",
    ("mysql", "mysql"): "5.0.45",
    ("redislabs", "redis"): "3.2.0",
    ("microsoft", "internet_information_services"): "10.0",
    ("joyent", "node.js"): "0.10.40",
    ("joomla", "joomla\\!"): "3.9.0",
    ("mortbay", "jetty"): "6.1.26",
    ("jetty", "jetty"): "6.1.26",
    ("pivotal_software", "spring_framework"): "5.0.0",
    ("springsource", "spring_framework"): "3.0.0",
    ("zeit", "next.js"): "9.3.0",
    ("twitter", "bootstrap"): "3.3.7",
    ("adobe", "magento"): "2.4.3",
    ("atlassian", "confluence_server"): "7.13.0",
    ("atlassian", "confluence_data_center"): "7.13.0",
    ("atlassian", "jira_server"): "8.13.0",
    ("atlassian", "jira_data_center"): "8.13.0",
    ("cloudbees", "jenkins"): "1.609",
    ("elasticsearch", "elasticsearch"): "1.4.2",
    ("elasticsearch", "kibana"): "4.1.0",
    ("vmware", "rabbitmq"): "3.8.9",
    ("vmware", "rabbitmq_server"): "3.8.9",
    ("broadcom", "rabbitmq_server"): "3.12.0",
    ("containous", "traefik"): "1.7.12",
    ("varnish-software", "varnish_cache"): "6.0.0",
    ("varnish-cache", "varnish"): "6.0.0",
    ("laravel", "framework"): "8.0.0",
    ("rubyonrails", "ruby_on_rails"): "3.2.0",
    ("docker", "engine"): "20.10.5",
    ("mobyproject", "moby"): "20.10.5",
    ("nuxtjs", "nuxt.js"): "2.15.0",
    ("tryghost", "ghost"): "4.0.0",
    ("danga", "memcached"): "1.4.5",
    ("beasts", "vsftpd"): "2.3.4",
    ("university_of_cambridge", "exim"): "4.69",
    ("symfony", "symfony"): "4.4.0",
}

# Measured in the first run, so not in the counts file.
ALREADY_KNOWN = [("mysql", "oracle", "mysql_server"), ("mysql", "mysql", "mysql")]


def ids_for(vendor, product, version):
    cpe = quote(f"cpe:2.3:a:{vendor}:{product}:{version}")
    url = f"{NVD}?virtualMatchString={cpe}&resultsPerPage=2000"
    for attempt in range(4):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "cpe-check/1.0"})
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read().decode())
            return sorted(v["cve"]["id"] for v in data.get("vulnerabilities", [])), ""
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 429, 503) and attempt < 3:
                time.sleep(15)
                continue
            return None, f"HTTP {exc.code}"
        except (urllib.error.URLError, socket.timeout, TimeoutError, OSError) as exc:
            if attempt < 3:
                time.sleep(10)
                continue
            return None, type(exc).__name__
    return None, "gave up"


counted = json.load(open(COUNTS, encoding="utf-8"))
todo = list(ALREADY_KNOWN)
for row in counted:
    key = (row["vendor"], row["product"])
    if (row.get("total") or 0) > 0 and key in VERSION:
        todo.append((row["tech"], row["vendor"], row["product"]))

results, primary_cache = [], {}
for tech, vendor, product in todo:
    version = VERSION[(vendor, product)]
    primary = CPE_MAPPING[tech]
    cache_key = (tech, version)
    if cache_key not in primary_cache:
        primary_cache[cache_key] = ids_for(primary["vendor"], primary["product"], version)
        time.sleep(INTERVAL)
    primary_ids, primary_error = primary_cache[cache_key]
    sibling_ids, sibling_error = ids_for(vendor, product, version)
    time.sleep(INTERVAL)

    row = {"tech": tech, "version": version,
           "primary": f"{primary['vendor']}:{primary['product']}",
           "sibling": f"{vendor}:{product}",
           "primary_ids": primary_ids, "sibling_ids": sibling_ids,
           "error": primary_error or sibling_error}
    if primary_ids is not None and sibling_ids is not None:
        row["gain"] = sorted(set(sibling_ids) - set(primary_ids))
    results.append(row)
    with open(OUT, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=1)

    shown = (f"primary={len(primary_ids)} sibling={len(sibling_ids)} adds={len(row['gain'])}"
             if "gain" in row else f"error={row['error']}")
    print(f"{tech:<14} {version:<9} {row['primary']:<34} +{row['sibling']:<42} {shown}",
          flush=True)

print("DONE", len(results))
