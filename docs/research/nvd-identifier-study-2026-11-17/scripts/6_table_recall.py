"""
How complete is a lookup for each product in the scanner's table?

Three sets of CVEs per product, all taken from the index of NVD's records:

  single      filed under the table's one identifier (the scanner before 0.9.3)
  configured  that, plus the second identifiers the scanner queries (0.9.3)
  complete    that, plus the identifiers the systematic search judged to be the
              same software (classification.json)

Recall is the size of a set over the size of the complete one. Being "filed
under" an identifier is version-independent, so these are all-version figures.

Usage: python -I table_recall.py <src dir> <dictionary out dir> <cve index dir>
                                 <classification json> <out json>
"""
import json
import statistics
import sys
from collections import defaultdict

sys.path.insert(0, sys.argv[1])
from phantomprobe.cpe_tables import CPE_MAPPING, CPE_SIBLINGS  # noqa: E402

dict_dir, index_dir, class_path, out_path = sys.argv[2:6]

cves_of, year_of = defaultdict(set), {}
with open(f"{index_dir}/cve_identifiers.tsv", encoding="utf-8") as handle:
    next(handle)
    for line in handle:
        cve, published, _status, identifiers = line.rstrip("\n").split("\t")
        year_of[cve] = published[:4]
        for name in filter(None, identifiers.split("|")):
            cves_of[name].add(cve)

dictionary = {}
with open(f"{dict_dir}/identifiers.tsv", encoding="utf-8") as handle:
    next(handle)
    for line in handle:
        part, vendor, product, names, deprecated = line.split("\t")[:5]
        dictionary[f"{part}:{vendor}:{product}"] = (int(names), int(deprecated))

classification = json.load(open(class_path, encoding="utf-8"))
candidates = json.load(open(f"{dict_dir}/table_candidates.json", encoding="utf-8"))


def standing(identifier):
    if identifier not in dictionary:
        return "not in the dictionary"
    names, deprecated = dictionary[identifier]
    if deprecated == names:
        return "every name deprecated"
    if deprecated:
        return f"{deprecated} of {names} names deprecated"
    return "current"


rows = {}
for tech, mapping in sorted(CPE_MAPPING.items()):
    primary = f"a:{mapping['vendor']}:{mapping['product']}"
    single = set(cves_of.get(primary, set()))
    pilot = [f"a:{s['vendor']}:{s['product']}" for s in CPE_SIBLINGS.get(tech, [])]
    configured = set(single)
    for name in pilot:
        configured |= cves_of.get(name, set())
    newly = sorted(classification["same"].get(tech, {}))
    complete = set(configured)
    for name in newly:
        complete |= cves_of.get(name, set())
    proposed = {c["identifier"]: c["rules"] for c in candidates[tech]["candidates"]}
    rows[tech] = {
        "table_identifier": primary[2:],
        "table_identifier_standing": standing(primary),
        "single": len(single), "configured": len(configured), "complete": len(complete),
        "recall_single": round(len(single) / len(complete), 4) if complete else None,
        "recall_configured": round(len(configured) / len(complete), 4) if complete else None,
        "queried_second_identifiers": [
            {"identifier": n[2:], "cves": len(cves_of.get(n, set())),
             "adds": len(cves_of.get(n, set()) - single),
             "found_by": [r for r in proposed.get(n, []) if r != "pilot"] or ["none of the rules"]}
            for n in pilot],
        "new_same_software_identifiers": [
            {"identifier": n[2:], "cves": len(cves_of.get(n, set())),
             "adds": len(cves_of.get(n, set()) - configured),
             "found_by": [r for r in proposed.get(n, []) if r != "pilot"],
             "why": classification["same"][tech][n]}
            for n in newly],
        "missed_by_single_years": (lambda ys: [ys[0], ys[-1]] if ys else [])(
            sorted(year_of[c] for c in complete - single)),
    }

have = [r for r in rows.values() if r["complete"]]
pilot_rows = [s for r in rows.values() for s in r["queried_second_identifiers"]]
summary = {
    "products": len(rows),
    "products_with_cves": len(have),
    "table_identifier_standing": {k: sum(1 for r in rows.values()
                                         if r["table_identifier_standing"].split(" of ")[-1] == k
                                         or r["table_identifier_standing"] == k)
                                  for k in ("current", "every name deprecated",
                                            "not in the dictionary")},
    "table_identifiers_partly_deprecated": sum(1 for r in rows.values()
                                               if " of " in r["table_identifier_standing"]),
    "products_where_single_identifier_is_incomplete": sum(1 for r in have
                                                          if r["single"] < r["complete"]),
    "products_where_0_9_3_is_still_incomplete": sum(1 for r in have
                                                    if r["configured"] < r["complete"]),
    "cve_product_pairs": {"single": sum(r["single"] for r in have),
                          "configured": sum(r["configured"] for r in have),
                          "complete": sum(r["complete"] for r in have)},
    "overall_recall_single": round(sum(r["single"] for r in have)
                                   / sum(r["complete"] for r in have), 4),
    "overall_recall_configured": round(sum(r["configured"] for r in have)
                                       / sum(r["complete"] for r in have), 4),
    "median_recall_single_among_incomplete": round(statistics.median(
        r["recall_single"] for r in have if r["single"] < r["complete"]), 4),
    "worst_single_identifier_recall": sorted(
        [(t, r["recall_single"], r["single"], r["complete"]) for t, r in rows.items()
         if r["complete"] and r["single"] < r["complete"]], key=lambda x: x[1])[:12],
    "second_identifiers_in_0_9_3": len(pilot_rows),
    "of_which_add_cves_across_all_versions": sum(1 for s in pilot_rows if s["adds"] > 0),
    "of_which_found_by": {rule: sum(1 for s in pilot_rows if rule in s["found_by"])
                          for rule in ("rename", "vendor", "name", "none of the rules")},
    "new_same_software_identifiers": sum(len(r["new_same_software_identifiers"])
                                         for r in rows.values()),
    "cves_they_add": sum(r["complete"] - r["configured"] for r in have),
}
json.dump({"summary": summary, "products": rows}, open(out_path, "w", encoding="utf-8"), indent=1)
print(json.dumps(summary, indent=1))
print()
print("product         single  0.9.3  complete  recall(single)  recall(0.9.3)  table identifier")
for tech, r in sorted(rows.items(), key=lambda kv: (kv[1]["recall_single"] or 1)):
    if r["complete"] and r["single"] < r["complete"]:
        print(f"{tech:<14} {r['single']:>6} {r['configured']:>6} {r['complete']:>9} "
              f"{r['recall_single']:>14.1%} {r['recall_configured']:>14.1%}  "
              f"{r['table_identifier']} ({r['table_identifier_standing']})")
print("DONE")
