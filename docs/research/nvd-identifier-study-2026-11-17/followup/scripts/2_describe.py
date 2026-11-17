"""
Read the description of every extra CVE found by extra_cves.py, to check that
each one is a flaw in the product itself and not in something filed against it.

Usage: python -I describe.py <raw feed dir> <extra_cves.json> <out json>
"""
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from extra_cves_stream import array_items, text_chunks  # noqa: E402

feeds, extra_path, out_path = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
extra = json.load(open(extra_path, encoding="utf-8"))

wanted = {}
for name, entry in extra.items():
    for row in entry["rows"]:
        wanted.setdefault(row["cve"], []).append(name)

by_year = defaultdict(set)
for cve in wanted:
    by_year[max(2002, int(cve.split("-")[1]))].add(cve)

described = {}
for year in sorted(by_year):
    for item in array_items(text_chunks(feeds / f"nvdcve-2.0-{year}.json.gz")):
        cve = item.get("cve", {})
        if cve.get("id") in wanted:
            text = next((d["value"] for d in cve.get("descriptions", [])
                         if d.get("lang") == "en"), "")
            described[cve["id"]] = text
json.dump(described, open(out_path, "w", encoding="utf-8"), indent=1)

OWN_WORDS = {
    "a:sun:jdk": r"java|jre|jdk|j2se|sun|runtime|applet|web start|jvm",
    "a:oracle:jre": r"java|jre|jdk|j2se|runtime|applet|web start|jvm",
    "a:oracle:java_se": r"java|jre|jdk|runtime|jvm",
}
for name, entry in extra.items():
    ids = [r["cve"] for r in entry["rows"]]
    pattern = OWN_WORDS.get(name)
    print(f"\n== {entry['tech']} {name}: {len(ids)}")
    for cve in ids:
        text = described.get(cve, "(not found)")
        if pattern and re.search(pattern, text, re.I) and len(ids) > 10:
            continue
        print(f"  {cve}: {text[:420]}")
    if pattern and len(ids) > 10:
        hits = sum(1 for c in ids if re.search(pattern, described.get(c, ""), re.I))
        print(f"  ({hits} of {len(ids)} name the Java runtime; the rest are printed above)")
print("DONE")
