"""
Reduce NVD's CPE dictionary (the nvdcpe-2.0 feed) to two tables.

  identifiers.tsv   one row per part:vendor:product, with how many CPE names
                    it has, how many of those are deprecated, and its dates
  rename_edges.json one entry per (old identifier -> new identifier) pair
                    that the dictionary's own deprecatedBy links connect

A deprecated CPE name whose replacement has the same part, vendor and product
is a version-level correction and is not an edge. An edge means NVD decided
that names under one vendor:product are now to be found under another, which
is the thing a tool with a hardcoded vendor:product pair cannot see.

Usage: python -I dict_aggregate.py <chunk directory> <output directory>
"""
import glob
import json
import os
import re
import sys
from collections import defaultdict

chunk_dir, out_dir = sys.argv[1], sys.argv[2]
os.makedirs(out_dir, exist_ok=True)

SPLIT = re.compile(r"(?<!\\):")


def identifier(cpe_name):
    """part, vendor, product of a CPE 2.3 name; colons inside a field are escaped."""
    parts = SPLIT.split(cpe_name)
    if len(parts) < 5 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    return parts[2], parts[3], parts[4]


stats = defaultdict(lambda: {"names": 0, "deprecated": 0, "created": "9999", "modified": ""})
edges = defaultdict(lambda: {"names": 0, "first": "9999", "last": "", "example": ""})
total_names = total_deprecated = dangling = 0
feed_meta = {}

files = sorted(glob.glob(os.path.join(chunk_dir, "**", "*.json"), recursive=True))
for number, path in enumerate(files, 1):
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    if not feed_meta:
        feed_meta = {k: v for k, v in data.items() if k != "products"}
    for product in data.get("products", []):
        cpe = product.get("cpe", product)
        name = cpe.get("cpeName", "")
        key = identifier(name)
        if key is None:
            continue
        total_names += 1
        row = stats[key]
        row["names"] += 1
        created = cpe.get("created", "")[:10]
        modified = cpe.get("lastModified", "")[:10]
        if created and created < row["created"]:
            row["created"] = created
        if modified > row["modified"]:
            row["modified"] = modified
        if not cpe.get("deprecated"):
            continue
        total_deprecated += 1
        row["deprecated"] += 1
        replacements = cpe.get("deprecatedBy") or []
        if not replacements:
            dangling += 1
        seen_targets = set()
        for replacement in replacements:
            target = identifier(replacement.get("cpeName", ""))
            if target is None or target == key or target in seen_targets:
                continue
            seen_targets.add(target)
            edge = edges[(key, target)]
            edge["names"] += 1
            if modified and modified < edge["first"]:
                edge["first"] = modified
            if modified > edge["last"]:
                edge["last"] = modified
            if not edge["example"]:
                edge["example"] = f"{name} -> {replacement.get('cpeName', '')}"
    print(f"chunk {number}/{len(files)}: {total_names} names so far", flush=True)

with open(os.path.join(out_dir, "identifiers.tsv"), "w", encoding="utf-8") as handle:
    handle.write("part\tvendor\tproduct\tnames\tdeprecated\tfirst_created\tlast_modified\n")
    for (part, vendor, product), row in sorted(stats.items()):
        handle.write(f"{part}\t{vendor}\t{product}\t{row['names']}\t{row['deprecated']}\t"
                     f"{row['created']}\t{row['modified']}\n")


def kind(old, new):
    changed = [label for label, a, b in (("part", old[0], new[0]), ("vendor", old[1], new[1]),
                                         ("product", old[2], new[2])) if a != b]
    return "+".join(changed)


edge_rows = [
    {"from": ":".join(old), "to": ":".join(new), "kind": kind(old, new),
     "deprecated_names": edge["names"], "first_modified": edge["first"],
     "last_modified": edge["last"], "example": edge["example"]}
    for (old, new), edge in sorted(edges.items())
]
with open(os.path.join(out_dir, "rename_edges.json"), "w", encoding="utf-8") as handle:
    json.dump(edge_rows, handle, indent=0)

by_part = defaultdict(int)
fully_deprecated = defaultdict(int)
for (part, _, _), row in stats.items():
    by_part[part] += 1
    if row["deprecated"] == row["names"]:
        fully_deprecated[part] += 1
summary = {
    "feed": feed_meta,
    "chunks": len(files),
    "cpe_names": total_names,
    "deprecated_names": total_deprecated,
    "deprecated_names_without_replacement": dangling,
    "identifiers_by_part": dict(by_part),
    "identifiers_with_every_name_deprecated": dict(fully_deprecated),
    "rename_edges": len(edge_rows),
    "rename_edges_by_kind": {k: sum(1 for e in edge_rows if e["kind"] == k)
                             for k in sorted({e["kind"] for e in edge_rows})},
    "identifiers_with_an_outgoing_edge": len({e["from"] for e in edge_rows}),
}
with open(os.path.join(out_dir, "dictionary_summary.json"), "w", encoding="utf-8") as handle:
    json.dump(summary, handle, indent=1)
print(json.dumps(summary, indent=1))
print("DONE")
