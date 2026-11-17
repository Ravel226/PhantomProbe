"""
Measure, from NVD's own CVE records, what a lookup under one identifier misses.

Three questions, each answered from the index of every non-rejected CVE:

  1. Dictionary-wide: for every pair of application identifiers the dictionary
     links by a rename, how many CVEs are filed under only one of the two?
  2. Table: for each product in the scanner's table, how many CVEs does each
     candidate identifier hold that the table's identifier does not?
  3. Coverage of the dictionary itself: how many identifiers do CVEs use that
     the dictionary does not contain?

"Filed under" means the identifier appears in a match criterion marked
vulnerable. It says nothing about versions: this is the all-version count, so
it has no dependence on which version happens to be tested.

Usage: python -I measure.py <src dir> <dictionary out dir> <cve index dir> <out json>
"""
import json
import sys
from collections import Counter, defaultdict

sys.path.insert(0, sys.argv[1])
from phantomprobe.cpe_tables import CPE_MAPPING, CPE_SIBLINGS  # noqa: E402

dict_dir, index_dir, out_path = sys.argv[2], sys.argv[3], sys.argv[4]

cves_of = defaultdict(set)
year_of = {}
total_cves = with_identifier = 0
with open(f"{index_dir}/cve_identifiers.tsv", encoding="utf-8") as handle:
    next(handle)
    for line in handle:
        cve, published, _status, identifiers = line.rstrip("\n").split("\t")
        total_cves += 1
        year_of[cve] = published[:4]
        if identifiers:
            with_identifier += 1
            for name in identifiers.split("|"):
                cves_of[name].add(cve)

in_dictionary = set()
with open(f"{dict_dir}/identifiers.tsv", encoding="utf-8") as handle:
    next(handle)
    for line in handle:
        part, vendor, product = line.split("\t")[:3]
        in_dictionary.add(f"{part}:{vendor}:{product}")

edges = json.load(open(f"{dict_dir}/rename_edges.json", encoding="utf-8"))
candidates = json.load(open(f"{dict_dir}/table_candidates.json", encoding="utf-8"))


def span(cve_ids):
    years = sorted(year_of[c] for c in cve_ids)
    return [years[0], years[-1]] if years else []


# --- 1. every application rename the dictionary records -------------------------
pairs = []
for edge in edges:
    old, new = edge["from"], edge["to"]
    if not (old.startswith("a:") and new.startswith("a:")):
        continue
    under_old, under_new = cves_of.get(old, set()), cves_of.get(new, set())
    pairs.append({
        "old": old, "new": new, "kind": edge["kind"],
        "deprecated_names": edge["deprecated_names"],
        "under_old": len(under_old), "under_new": len(under_new),
        "shared": len(under_old & under_new),
        "only_old": len(under_old - under_new), "only_new": len(under_new - under_old),
        "only_old_years": span(under_old - under_new),
        "only_new_years": span(under_new - under_old),
    })


def state(pair):
    if not pair["under_old"] and not pair["under_new"]:
        return "neither identifier has CVEs"
    if not pair["under_old"]:
        return "all CVEs are under the new identifier"
    if not pair["under_new"]:
        return "all CVEs are still under the old identifier"
    if pair["only_old"] and pair["only_new"]:
        return "split: each identifier holds CVEs the other lacks"
    if pair["only_new"]:
        return "the new identifier holds everything and more"
    if pair["only_old"]:
        return "the old identifier holds everything and more"
    return "both identifiers hold the same CVEs"


for pair in pairs:
    pair["state"] = state(pair)
with_cves = [p for p in pairs if p["under_old"] or p["under_new"]]
rename_summary = {
    "application_rename_pairs": len(pairs),
    "pairs_where_either_identifier_has_cves": len(with_cves),
    "by_state": dict(Counter(p["state"] for p in pairs)),
    "cves_only_under_the_old_identifier": sum(p["only_old"] for p in pairs),
    "cves_only_under_the_new_identifier": sum(p["only_new"] for p in pairs),
    "pairs_where_one_lookup_misses_cves": sum(1 for p in pairs
                                              if p["only_old"] or p["only_new"]),
    "pairs_where_the_old_identifier_alone_misses_cves": sum(1 for p in pairs if p["only_new"]),
    "pairs_where_the_new_identifier_alone_misses_cves": sum(1 for p in pairs if p["only_old"]),
}

# --- 2. the scanner's table ----------------------------------------------------
table = {}
for tech, row in sorted(candidates.items()):
    primary = row["table_identifier"]
    under_primary = cves_of.get(primary, set())
    listed = {f"a:{s['vendor']}:{s['product']}" for s in CPE_SIBLINGS.get(tech, [])}
    configured = set(under_primary)
    for name in listed:
        configured |= cves_of.get(name, set())
    rows = []
    for cand in row["candidates"]:
        name = cand["identifier"]
        under = cves_of.get(name, set())
        rows.append({
            "identifier": name, "rules": cand["rules"],
            "in_dictionary": name in in_dictionary,
            "queried_by_scanner": name in listed,
            "cves": len(under), "shared_with_table": len(under & under_primary),
            "extra_beyond_table": len(under - under_primary),
            "extra_beyond_configured": len(under - configured),
            "years": span(under),
            "rename_edge": cand["direct_rename_edge"],
        })
    table[tech] = {
        "table_identifier": primary,
        "in_dictionary": primary in in_dictionary,
        "cves_under_table_identifier": len(under_primary),
        "years": span(under_primary),
        "cves_under_configured_identifiers": len(configured),
        "by_year_table_identifier": dict(sorted(Counter(year_of[c] for c in under_primary).items())),
        "candidates": sorted(rows, key=lambda r: -r["extra_beyond_table"]),
    }

# --- 3. identifiers CVEs use that the dictionary lacks --------------------------
used_apps = {name for name in cves_of if name.startswith("a:")}
absent = sorted(used_apps - in_dictionary, key=lambda n: -len(cves_of[n]))
absent_summary = {
    "application_identifiers_used_by_cves": len(used_apps),
    "of_which_absent_from_the_dictionary": len(absent),
    "cves_touching_an_absent_identifier": len(set().union(*(cves_of[n] for n in absent))
                                              if absent else set()),
    "largest": [{"identifier": n, "cves": len(cves_of[n])} for n in absent[:25]],
}

result = {
    "corpus": {"cves": total_cves, "cves_with_an_identifier": with_identifier,
               "identifiers_used": len(cves_of)},
    "rename_summary": rename_summary,
    "rename_pairs": sorted(with_cves, key=lambda p: -(p["only_old"] + p["only_new"])),
    "table": table,
    "identifiers_absent_from_dictionary": absent_summary,
}
json.dump(result, open(out_path, "w", encoding="utf-8"), indent=1)

print(json.dumps(result["corpus"]))
print(json.dumps(rename_summary, indent=1))
print(json.dumps({k: v for k, v in absent_summary.items() if k != "largest"}))
print("largest absent:", [(r["identifier"], r["cves"]) for r in absent_summary["largest"][:8]])
print()
print("table products where a candidate holds CVEs the table's identifier lacks:")
for tech, row in sorted(table.items(),
                        key=lambda kv: -max([c["extra_beyond_table"] for c in kv[1]["candidates"]] or [0])):
    best = [c for c in row["candidates"] if c["extra_beyond_table"] > 0][:4]
    if not best:
        continue
    shown = "; ".join(f"{c['identifier'][2:]} +{c['extra_beyond_table']}"
                      f"{'' if c['queried_by_scanner'] else ' (not queried)'}" for c in best)
    print(f"  {tech:<14} {row['cves_under_table_identifier']:>5} under {row['table_identifier'][2:]:<40} {shown}")
print("DONE")
