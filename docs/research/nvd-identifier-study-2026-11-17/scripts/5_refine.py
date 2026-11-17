"""
Tighten the rename measurement and gather what the table classification needs.

A rename edge exists whenever one CPE name is deprecated in favour of a name
under another identifier, even if that is one mis-filed version out of
hundreds. Counting those as product renames would overstate the result, so
this separates

  complete   every name under the old identifier is deprecated, and all of
             them point at one new identifier: NVD retired the old identifier
  partial    anything else

and reports the complete ones on their own. It also counts distinct CVEs
rather than summing over pairs, dates the renames, breaks the identifiers
that are missing from the dictionary down by year, and collects the
dictionary title of each table candidate so a person can judge whether it is
the same software.

Usage: python -I refine.py <dictionary out dir> <cve index dir> <chunk dir> <out json>
"""
import glob
import json
import os
import re
import sys
from collections import Counter, defaultdict

dict_dir, index_dir, chunk_dir, out_path = sys.argv[1:5]
SPLIT = re.compile(r"(?<!\\):")

cves_of, year_of = defaultdict(set), {}
with open(f"{index_dir}/cve_identifiers.tsv", encoding="utf-8") as handle:
    next(handle)
    for line in handle:
        cve, published, _status, identifiers = line.rstrip("\n").split("\t")
        year_of[cve] = published[:4]
        for name in filter(None, identifiers.split("|")):
            cves_of[name].add(cve)

stats = {}
with open(f"{dict_dir}/identifiers.tsv", encoding="utf-8") as handle:
    next(handle)
    for line in handle:
        part, vendor, product, names, deprecated, _created, _modified = line.rstrip("\n").split("\t")
        stats[f"{part}:{vendor}:{product}"] = (int(names), int(deprecated))

edges = [e for e in json.load(open(f"{dict_dir}/rename_edges.json", encoding="utf-8"))
         if e["from"].startswith("a:") and e["to"].startswith("a:")]
targets_of = defaultdict(set)
for edge in edges:
    targets_of[edge["from"]].add(edge["to"])


def complete(edge):
    names, deprecated = stats.get(edge["from"], (0, 0))
    return names > 0 and names == deprecated and len(targets_of[edge["from"]]) == 1


def summarise(selection):
    states = Counter()
    missed_by_old, missed_by_new = set(), set()
    old_dead = old_dead_with_cves_moved = 0
    for edge in selection:
        under_old = cves_of.get(edge["from"], set())
        under_new = cves_of.get(edge["to"], set())
        only_new, only_old = under_new - under_old, under_old - under_new
        missed_by_old |= only_new
        missed_by_new |= only_old
        if not under_old and not under_new:
            states["neither identifier has CVEs"] += 1
        elif not under_old:
            states["old identifier returns nothing; CVEs are under the new one"] += 1
        elif not under_new:
            states["new identifier returns nothing; CVEs are still under the old one"] += 1
        elif only_old and only_new:
            states["split: each holds CVEs the other lacks"] += 1
        elif only_new:
            states["old is a strict subset of new"] += 1
        elif only_old:
            states["new is a strict subset of old"] += 1
        else:
            states["identical"] += 1
    return {
        "pairs": len(selection),
        "states": dict(states.most_common()),
        "pairs_where_the_old_identifier_misses_cves": sum(
            1 for e in selection if cves_of.get(e["to"], set()) - cves_of.get(e["from"], set())),
        "pairs_where_the_new_identifier_misses_cves": sum(
            1 for e in selection if cves_of.get(e["from"], set()) - cves_of.get(e["to"], set())),
        "distinct_cves_missed_using_only_old": len(missed_by_old),
        "distinct_cves_missed_using_only_new": len(missed_by_new),
    }


whole = [e for e in edges if complete(e)]
part = [e for e in edges if not complete(e)]


def examples(selection, direction, count=12):
    rows = []
    for edge in selection:
        under_old = cves_of.get(edge["from"], set())
        under_new = cves_of.get(edge["to"], set())
        missed = (under_old - under_new) if direction == "new_misses" else (under_new - under_old)
        if missed:
            years = sorted(year_of[c] for c in missed)
            rows.append({"old": edge["from"][2:], "new": edge["to"][2:],
                         "under_old": len(under_old), "under_new": len(under_new),
                         "missed": len(missed), "missed_years": [years[0], years[-1]],
                         "renamed": edge["first_modified"][:4]})
    return sorted(rows, key=lambda r: -r["missed"])[:count]


# Identifiers CVEs use that the dictionary lacks, by publication year.
apps_by_year = defaultdict(set)
for name, ids in cves_of.items():
    if name.startswith("a:"):
        for cve in ids:
            apps_by_year[year_of[cve]].add(name)
absent_by_year = {}
for year in sorted(apps_by_year):
    names = apps_by_year[year]
    missing = [n for n in names if n not in stats]
    absent_by_year[year] = {"identifiers_used": len(names), "absent": len(missing),
                            "share": round(len(missing) / len(names), 3)}

# Dictionary titles for the table candidates, for the same-software judgement.
candidates = json.load(open(f"{dict_dir}/table_candidates.json", encoding="utf-8"))
wanted = set()
for row in candidates.values():
    wanted.add(row["table_identifier"])
    for cand in row["candidates"]:
        wanted.add(cand["identifier"])
titles = {}
for path in sorted(glob.glob(os.path.join(chunk_dir, "**", "*.json"), recursive=True)):
    if len(titles) == len(wanted):
        break
    for product in json.load(open(path, encoding="utf-8")).get("products", []):
        cpe = product.get("cpe", product)
        parts = SPLIT.split(cpe.get("cpeName", ""))
        if len(parts) < 5:
            continue
        key = f"{parts[2]}:{parts[3]}:{parts[4]}"
        if key in wanted and key not in titles:
            english = [t["title"] for t in cpe.get("titles", []) if t.get("lang") == "en"]
            if english:
                titles[key] = english[0]

result = {
    "all_application_renames": summarise(edges),
    "complete_renames": summarise(whole),
    "partial_renames": summarise(part),
    "complete_renames_by_year": dict(sorted(Counter(e["first_modified"][:4] for e in whole).items())),
    "complete_examples_where_the_new_identifier_misses": examples(whole, "new_misses"),
    "complete_examples_where_the_old_identifier_misses": examples(whole, "old_misses"),
    "identifiers_absent_from_dictionary_by_year": absent_by_year,
    "titles": titles,
}
json.dump(result, open(out_path, "w", encoding="utf-8"), indent=1)

for label in ("all_application_renames", "complete_renames", "partial_renames"):
    print(label, json.dumps(result[label], indent=1))
print("complete renames by year:", result["complete_renames_by_year"])
print("complete renames where the NEW identifier still misses CVEs:")
for row in result["complete_examples_where_the_new_identifier_misses"]:
    print("  ", row)
print("complete renames where the OLD identifier misses most:")
for row in result["complete_examples_where_the_old_identifier_misses"][:8]:
    print("  ", row)
print("absent from dictionary, by year:",
      {y: f"{v['absent']}/{v['identifiers_used']}" for y, v in absent_by_year.items() if y >= "2016"})
print("titles found:", len(titles), "of", len(wanted))
print("DONE")
