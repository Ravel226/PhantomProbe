"""
For each identifier the study judged to be the same software as a product in
the scanner's table, list the CVEs it holds that the table's identifiers miss,
with the versions NVD files them under, so a live check can ask about a
version inside them.

Usage: python -I extra_cves.py <study dir> <src dir> <out json> [identifiers]

The identifiers default to the study's data/classification.json "same" list;
a JSON object of {technology: [part:vendor:product, ...]} replaces it.
"""
import codecs
import gzip
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

study, src, out_path = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
sys.path.insert(0, src)
from phantomprobe.cpe_tables import CPE_MAPPING, CPE_SIBLINGS  # noqa: E402

SPLIT = re.compile(r"(?<!\\):")

classification = json.load(open(study / "data" / "classification.json", encoding="utf-8"))
NEW = {tech: sorted(ids) for tech, ids in classification["same"].items()}
if len(sys.argv) > 4:
    NEW = json.loads(sys.argv[4])

cves_of = defaultdict(set)
with gzip.open(study / "data" / "cve_identifiers.tsv.gz", "rt", encoding="utf-8") as handle:
    next(handle)
    for line in handle:
        cve, _published, _status, identifiers = line.rstrip("\n").split("\t")
        for name in filter(None, identifiers.split("|")):
            cves_of[name].add(cve)

wanted = {}          # cve -> list of (tech, identifier)
configured_of = {}
for tech, names in NEW.items():
    primary = f"a:{CPE_MAPPING[tech]['vendor']}:{CPE_MAPPING[tech]['product']}"
    configured = set(cves_of.get(primary, set()))
    for s in CPE_SIBLINGS.get(tech, []):
        configured |= cves_of.get(f"a:{s['vendor']}:{s['product']}", set())
    configured_of[tech] = configured
    for name in names:
        for cve in cves_of.get(name, set()) - configured:
            wanted.setdefault(cve, []).append((tech, name))


def text_chunks(path):
    decoder = codecs.getincrementaldecoder("utf-8")()
    with gzip.open(path, "rb") as handle:
        while True:
            raw = handle.read(1 << 22)
            if not raw:
                tail = decoder.decode(b"", final=True)
                if tail:
                    yield tail
                return
            yield decoder.decode(raw)


def array_items(chunks, key='"vulnerabilities"'):
    decoder = json.JSONDecoder()
    buffer, index = "", 0
    for chunk in chunks:
        buffer += chunk
        position = buffer.find(key)
        if position != -1:
            start = buffer.find("[", position)
            if start != -1:
                buffer = buffer[start + 1:]
                break
    else:
        return
    exhausted = False
    while True:
        while index < len(buffer) and buffer[index] in " \r\n\t,":
            index += 1
        if index < len(buffer) and buffer[index] == "]":
            return
        try:
            if index >= len(buffer):
                raise ValueError("need more")
            item, end = decoder.raw_decode(buffer, index)
        except ValueError:
            if exhausted:
                return
            more = next(chunks, None)
            if more is None:
                exhausted = True
                continue
            buffer = buffer[index:] + more
            index = 0
            continue
        yield item
        index = end
        if index > (1 << 22):
            buffer = buffer[index:]
            index = 0


def best_score(cve):
    scores = []
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for metric in cve.get("metrics", {}).get(key, []):
            score = metric.get("cvssData", {}).get("baseScore")
            if score is not None:
                scores.append((key, score))
        if scores:
            # The scanner reads the newest scheme present, as here.
            return max(s for _, s in scores), key
    return None, None


def feed_year(cve_id):
    return max(2002, int(cve_id.split("-")[1]))


records = {}
by_year = defaultdict(set)
for cve in wanted:
    by_year[feed_year(cve)].add(cve)
feeds = study / "raw-feeds"
for year in sorted(by_year):
    path = feeds / f"nvdcve-2.0-{year}.json.gz"
    for item in array_items(text_chunks(path)):
        cve = item.get("cve", {})
        if cve.get("id") in wanted:
            records[cve["id"]] = cve
    print(f"{path.name}: found {sum(1 for c in by_year[year] if c in records)} "
          f"of {len(by_year[year])}", flush=True)
missing = sorted(set(wanted) - set(records))
if missing:
    print(f"not in their id year's feed: {len(missing)}; scanning the rest", flush=True)
    for path in sorted(feeds.glob("nvdcve-2.0-*.json.gz")):
        if int(path.name[11:15]) in by_year:
            continue
        for item in array_items(text_chunks(path)):
            cve = item.get("cve", {})
            if cve.get("id") in missing:
                records[cve["id"]] = cve


def key(version):
    return tuple(int(n) for n in re.findall(r"\d+", version))


out = {}
for tech, names in NEW.items():
    for name in names:
        rows = []
        for cve_id, owners in sorted(wanted.items()):
            if (tech, name) not in owners or cve_id not in records:
                continue
            cve = records[cve_id]
            score, scheme = best_score(cve)
            matches = []
            for config in cve.get("configurations", []):
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        parts = SPLIT.split(match.get("criteria", ""))
                        if (match.get("vulnerable") and len(parts) > 6
                                and f"{parts[2]}:{parts[3]}:{parts[4]}" == name):
                            matches.append({
                                "version": parts[5], "update": parts[6],
                                **{k: v for k, v in match.items() if k.startswith("version")},
                            })
            rows.append({"cve": cve_id, "published": cve.get("published", "")[:10],
                         "score": score, "scheme": scheme, "matches": matches})
        # Which exact versions does each extra CVE cover? Count per version.
        cover = defaultdict(set)
        candidates = {m["version"] for r in rows for m in r["matches"]
                      if m["version"] not in ("*", "-")}
        candidates |= {m[k] for r in rows for m in r["matches"]
                       for k in ("versionStartIncluding", "versionEndIncluding") if k in m}
        for version in candidates:
            for r in rows:
                for m in r["matches"]:
                    exact = m["version"] not in ("*", "-")
                    if exact and key(m["version"]) == key(version):
                        cover[version].add(r["cve"])
                    elif not exact:
                        lo_in, lo_ex = m.get("versionStartIncluding"), m.get("versionStartExcluding")
                        hi_in, hi_ex = m.get("versionEndIncluding"), m.get("versionEndExcluding")
                        v = key(version)
                        if lo_in and v < key(lo_in):
                            continue
                        if lo_ex and v <= key(lo_ex):
                            continue
                        if hi_in and v > key(hi_in):
                            continue
                        if hi_ex and v >= key(hi_ex):
                            continue
                        if any((lo_in, lo_ex, hi_in, hi_ex)):
                            cover[version].add(r["cve"])
        top = sorted(cover.items(), key=lambda kv: (-len(kv[1]), key(kv[0])))[:6]
        high = [r for r in rows if r["score"] is not None and r["score"] >= 7.0]
        out[name] = {
            "tech": tech, "extra": len(rows), "extra_7_or_higher": len(high),
            "years": sorted({r["published"][:4] for r in rows}),
            "best_versions": [(v, len(c), sorted(c)[:8]) for v, c in top],
            "rows": rows,
        }
        print(f"\n{tech} {name}: {len(rows)} extra, {len(high)} scored 7.0+, "
              f"published {out[name]['years'][:1]}..{out[name]['years'][-1:]}")
        for v, n, sample in out[name]["best_versions"]:
            print(f"   version {v:<14} covers {n:>3}  e.g. {', '.join(sample[:4])}")
        if len(rows) <= 6:
            for r in rows:
                print(f"   {r['cve']} {r['published']} score {r['score']} ({r['scheme']})")
                for m in r["matches"][:6]:
                    print(f"      {m}")

json.dump(out, open(out_path, "w", encoding="utf-8"), indent=1)
print("DONE")
