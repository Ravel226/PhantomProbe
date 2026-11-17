"""
For each product in the scanner's CPE table, list every other identifier in
NVD's dictionary that could be the same software, by three rules:

  rename   connected to the table's identifier through the dictionary's own
           deprecatedBy links, in either direction, any number of hops
  vendor   the same product name under a different vendor
  name     the same vendor, with a product name that extends or is extended
           by the table's (nginx / nginx_open_source), or that shares its
           first two words when it has three or more

The rules only propose. Whether a proposal is the same software is decided
afterwards, from its title and from the CVEs filed under it.

Usage: python -I table_candidates.py <src dir> <dictionary output dir> <out json>
"""
import json
import sys
from collections import defaultdict, deque

sys.path.insert(0, sys.argv[1])
from phantomprobe.cpe_tables import CPE_MAPPING, CPE_SIBLINGS  # noqa: E402

dict_dir, out_path = sys.argv[2], sys.argv[3]

stats = {}
by_product = defaultdict(set)
by_vendor = defaultdict(set)
with open(f"{dict_dir}/identifiers.tsv", encoding="utf-8") as handle:
    next(handle)
    for line in handle:
        part, vendor, product, names, deprecated, created, modified = line.rstrip("\n").split("\t")
        key = f"{part}:{vendor}:{product}"
        stats[key] = {"names": int(names), "deprecated": int(deprecated),
                      "first_created": created, "last_modified": modified}
        if part == "a":
            by_product[product].add(vendor)
            by_vendor[vendor].add(product)

edges = json.load(open(f"{dict_dir}/rename_edges.json", encoding="utf-8"))
neighbours = defaultdict(set)
edge_info = {}
for edge in edges:
    neighbours[edge["from"]].add(edge["to"])
    neighbours[edge["to"]].add(edge["from"])
    edge_info[(edge["from"], edge["to"])] = edge


def component(start):
    seen, queue = {start}, deque([start])
    while queue:
        node = queue.popleft()
        for other in neighbours[node]:
            if other not in seen:
                seen.add(other)
                queue.append(other)
    seen.discard(start)
    return seen


def name_related(table_product, other):
    if other == table_product:
        return False
    if other.startswith(table_product + "_") or other.endswith("_" + table_product):
        return True
    if table_product.startswith(other + "_"):
        return True
    words = table_product.split("_")
    return len(words) >= 3 and other.split("_")[:2] == words[:2]


result, totals = {}, defaultdict(int)
for tech, mapping in sorted(CPE_MAPPING.items()):
    vendor, product = mapping["vendor"], mapping["product"]
    primary = f"a:{vendor}:{product}"
    listed = {f"a:{s['vendor']}:{s['product']}" for s in CPE_SIBLINGS.get(tech, [])}
    found = defaultdict(set)
    for other in component(primary):
        found[other].add("rename")
    for other_vendor in by_product.get(product, ()):
        if other_vendor != vendor:
            found[f"a:{other_vendor}:{product}"].add("vendor")
    for other_product in by_vendor.get(vendor, ()):
        if name_related(product, other_product):
            found[f"a:{vendor}:{other_product}"].add("name")
    for other in listed:
        found[other].add("pilot")
    rows = []
    for other, rules in sorted(found.items()):
        info = stats.get(other, {})
        direct = (edge_info.get((primary, other)) or edge_info.get((other, primary)))
        rows.append({
            "identifier": other,
            "rules": sorted(rules),
            "in_dictionary": other in stats,
            "names": info.get("names", 0),
            "deprecated_names": info.get("deprecated", 0),
            "first_created": info.get("first_created", ""),
            "direct_rename_edge": (f"{direct['from']} -> {direct['to']} "
                                   f"({direct['deprecated_names']} names)") if direct else "",
        })
        for rule in rules:
            totals[rule] += 1
    result[tech] = {
        "table_identifier": primary,
        "in_dictionary": primary in stats,
        "names": stats.get(primary, {}).get("names", 0),
        "deprecated_names": stats.get(primary, {}).get("deprecated", 0),
        "candidates": rows,
    }

json.dump(result, open(out_path, "w", encoding="utf-8"), indent=1)

pilot = [(t, f"a:{s['vendor']}:{s['product']}") for t, v in CPE_SIBLINGS.items() for s in v]
linked = [(t, o) for t, o in pilot
          if "rename" in next((c["rules"] for c in result[t]["candidates"]
                               if c["identifier"] == o), [])]
by_rule = [(t, o) for t, o in pilot
           if set(next((c["rules"] for c in result[t]["candidates"]
                        if c["identifier"] == o), [])) & {"rename", "vendor", "name"}]
print("table products:", len(result), "| not in the dictionary at all:",
      [t for t, r in result.items() if not r["in_dictionary"]])
print("candidates proposed, by rule:", dict(totals))
print("products with at least one candidate:", sum(1 for r in result.values() if r["candidates"]))
print(f"pilot identifiers explained by a rename link: {len(linked)} of {len(pilot)}")
print(f"pilot identifiers found by any rule:          {len(by_rule)} of {len(pilot)}")
print("pilot identifiers no rule finds:",
      sorted(set(pilot) - set(by_rule)))
part_a = [e for e in edges if e["from"].startswith("a:") and e["to"].startswith("a:")]
print("application-to-application rename edges:", len(part_a),
      "| distinct sources:", len({e["from"] for e in part_a}),
      "| application identifiers:", sum(1 for k in stats if k.startswith("a:")))
