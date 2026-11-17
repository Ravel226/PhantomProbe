"""
Ask live NVD, the way the scanner asks, what each new identifier adds at a
real version: the CVEs the table's identifiers return, then what each new
identifier returns that they did not.

Usage: python -I live_check.py <project dir> <out json> [checks]

The checks default to CHECKS below; a JSON list of
[technology, version, [vendor:product, ...]] replaces them. The project's
.env supplies NVD_API_KEY if it has one; the key is never printed.
"""
import json
import os
import sys
from pathlib import Path

project, out_path = Path(sys.argv[1]), sys.argv[2]
sys.path.insert(0, str(project / "src"))

# The key raises NVD's rate limit. It is read here and never printed.
for line in (project / ".env").read_text(encoding="utf-8").splitlines():
    name, _, value = line.partition("=")
    if name.strip() == "NVD_API_KEY" and value.strip():
        os.environ["NVD_API_KEY"] = value.strip().strip('"').strip("'")

from phantomprobe.cve import CVEMatcher  # noqa: E402

CHECKS = [
    ("java", "1.6.0", ["sun:jdk", "oracle:jre", "oracle:java_se"]),
    ("java", "1.7.0", ["sun:jdk", "oracle:jre", "oracle:java_se"]),
    ("java", "11.0.14", ["sun:jdk", "oracle:jre", "oracle:java_se"]),
    ("django", "0.95", ["django_project:django"]),
    ("jenkins", "1.509", ["cloudbees:jenkins"]),
    ("jira", "8.13.0", ["atlassian:jira_software_data_center"]),
    ("magento", "1.6.2", ["magentocommerce:magento"]),
    # The two left out, to record what they would have added.
    ("node.js", "0.10.32", ["joyent:node.js"]),
    ("samba", "4.20.0", ["samba:samba_server"]),
]

if len(sys.argv) > 3:
    CHECKS = json.loads(sys.argv[3])

matcher = CVEMatcher(results_per_page=2000)
print(f"keyed: {bool(matcher.api_key)}", flush=True)
results = []
for tech, version, new in CHECKS:
    current = {}
    per_current = {}
    for cpe in matcher.build_cpes(tech, version):
        found = matcher.query_nvd(cpe, tech, version)
        per_current[cpe] = len(found)
        for cve in found:
            current[cve.cve_id] = cve
    row = {"tech": tech, "version": version, "current": len(current),
           "current_by_identifier": per_current, "new": []}
    seen = dict(current)
    for identifier in new:
        cpe = f"cpe:2.3:a:{identifier}:{version}"
        found = {c.cve_id: c for c in matcher.query_nvd(cpe, tech, version)}
        beyond_current = sorted(set(found) - set(current))
        beyond_seen = sorted(set(found) - set(seen))
        high = [c for c in beyond_current if found[c].cvss_score >= 7.0]
        row["new"].append({
            "identifier": identifier, "returned": len(found),
            "not_in_current": len(beyond_current), "not_in_any_before": len(beyond_seen),
            "of_which_7_or_higher": len(high),
            "added": [(c, found[c].cvss_score) for c in beyond_current][:12],
        })
        seen.update(found)
    row["with_new"] = len(seen)
    results.append(row)
    print(f"\n{tech} {version}: table's identifiers {len(current)} {per_current}", flush=True)
    for n in row["new"]:
        print(f"   {n['identifier']:<40} returned {n['returned']:>4}  "
              f"+{n['not_in_current']} beyond the table's "
              f"(+{n['not_in_any_before']} beyond all before it), "
              f"{n['of_which_7_or_higher']} scored 7.0+", flush=True)
        if n["not_in_current"] <= 6:
            print(f"      {n['added']}", flush=True)
    print(f"   all together: {row['with_new']}", flush=True)

json.dump(results, open(out_path, "w", encoding="utf-8"), indent=1)
print("DONE")
