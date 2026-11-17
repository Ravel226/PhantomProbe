"""
Why can an identifier add more CVEs at one version than across all versions?

oracle:jre holds 24 CVEs that oracle:jdk lacks at any version, yet asked about
Java 1.7.0 it returned 52 that oracle:jdk did not. This counts, in the study's
snapshot, the CVEs whose oracle:jre entries cover a version while their
oracle:jdk entries do not, and shows what the oracle:jdk entries say instead.

Usage: python -I version_gap.py <raw feed dir> <version> <first year> <last year> <out json>
"""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from extra_cves_stream import array_items, text_chunks  # noqa: E402

feeds, version, first, last, out_path = (Path(sys.argv[1]), sys.argv[2],
                                         int(sys.argv[3]), int(sys.argv[4]), sys.argv[5])
SPLIT = re.compile(r"(?<!\\):")


def key(v):
    return tuple(int(n) for n in re.findall(r"\d+", v))


def covers(entries, wanted):
    for e in entries:
        if e["version"] not in ("*", "-"):
            if e["version"] == wanted:
                return True
            continue
        lo_in, lo_ex = e.get("versionStartIncluding"), e.get("versionStartExcluding")
        hi_in, hi_ex = e.get("versionEndIncluding"), e.get("versionEndExcluding")
        if not any((lo_in, lo_ex, hi_in, hi_ex)):
            continue
        v = key(wanted)
        if lo_in and v < key(lo_in) or lo_ex and v <= key(lo_ex):
            continue
        if hi_in and v > key(hi_in) or hi_ex and v >= key(hi_ex):
            continue
        return True
    return False


jre_covers, jdk_covers, jdk_any, examples = set(), set(), set(), {}
for year in range(first, last + 1):
    for item in array_items(text_chunks(feeds / f"nvdcve-2.0-{year}.json.gz")):
        cve = item.get("cve", {})
        if cve.get("vulnStatus") == "Rejected":
            continue
        entries = {"jre": [], "jdk": []}
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    parts = SPLIT.split(match.get("criteria", ""))
                    if not match.get("vulnerable") or len(parts) < 7:
                        continue
                    if parts[3] == "oracle" and parts[4] in entries:
                        entries[parts[4]].append({
                            "version": parts[5], "update": parts[6],
                            **{k: v for k, v in match.items() if k.startswith("version")}})
        cid = cve.get("id")
        if covers(entries["jre"], version):
            jre_covers.add(cid)
        if covers(entries["jdk"], version):
            jdk_covers.add(cid)
        if entries["jdk"]:
            jdk_any.add(cid)
        if cid in jre_covers and cid not in jdk_covers and entries["jdk"]:
            examples[cid] = sorted({f"{e['version']}:{e['update']}" for e in entries["jdk"]})[:6]
    print(f"{year}: jre covers {len(jre_covers)}, jdk covers {len(jdk_covers)}", flush=True)

gap = jre_covers - jdk_covers
result = {
    "version": version, "years": [first, last],
    "jre_entries_cover_it": len(jre_covers), "jdk_entries_cover_it": len(jdk_covers),
    "jre_covers_jdk_does_not": len(gap),
    "of_which_filed_under_jdk_for_other_versions": len(gap & jdk_any),
    "of_which_not_filed_under_jdk_at_all": len(gap - jdk_any),
    "examples_of_their_jdk_entries": dict(sorted(examples.items())[:8]),
}
json.dump(result, open(out_path, "w", encoding="utf-8"), indent=1)
print(json.dumps(result, indent=1))
print("DONE")
