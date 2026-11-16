"""
Re-run the rows of the gain pass that failed on a network error, plus the
cases the first pass left unclear (IIS at older versions, Spring 4.x).
"""
import json
import socket
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import quote

sys.path.insert(0, sys.argv[1])
from phantomprobe.cpe_tables import CPE_MAPPING  # noqa: E402

PREVIOUS = sys.argv[2]
OUT = sys.argv[3]
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
INTERVAL = 6.6

# tech, version, sibling vendor, sibling product
EXTRA = [
    ("iis", "6.0", "microsoft", "internet_information_services"),
    ("iis", "7.5", "microsoft", "internet_information_services"),
    ("spring", "4.0.0", "pivotal_software", "spring_framework"),
]


def ids_for(vendor, product, version):
    cpe = quote(f"cpe:2.3:a:{vendor}:{product}:{version}")
    url = f"{NVD}?virtualMatchString={cpe}&resultsPerPage=2000"
    for attempt in range(6):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "cpe-check/1.0"})
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read().decode())
            return sorted(v["cve"]["id"] for v in data.get("vulnerabilities", [])), ""
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 429, 503) and attempt < 5:
                time.sleep(20)
                continue
            return None, f"HTTP {exc.code}"
        except (urllib.error.URLError, socket.timeout, TimeoutError, OSError) as exc:
            if attempt < 5:
                time.sleep(20)
                continue
            return None, type(exc).__name__
    return None, "gave up"


todo = []
for row in json.load(open(PREVIOUS, encoding="utf-8")):
    if row.get("error"):
        vendor, product = row["sibling"].split(":", 1)
        todo.append((row["tech"], row["version"], vendor, product))
todo += EXTRA

results, primary_cache = [], {}
for tech, version, vendor, product in todo:
    primary = CPE_MAPPING[tech]
    key = (tech, version)
    if key not in primary_cache:
        primary_cache[key] = ids_for(primary["vendor"], primary["product"], version)
        time.sleep(INTERVAL)
    primary_ids, primary_error = primary_cache[key]
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
