"""
Index NVD's yearly CVE feeds by the identifiers each CVE is filed under.

For every CVE that is not rejected, collect the part:vendor:product of each
match criterion marked vulnerable in its configurations, and write

  cve_identifiers.tsv   cve id, published date, status, identifiers
  feed_checks.json      size and sha256 of each file against NVD's .meta

The yearly files run to several hundred megabytes unpacked, so each is
decoded as a stream, one CVE at a time, without holding the file in memory.

Usage: python -I cve_index.py <feed directory> <output directory>
"""
import codecs
import glob
import gzip
import hashlib
import json
import os
import re
import sys

feed_dir, out_dir = sys.argv[1], sys.argv[2]
os.makedirs(out_dir, exist_ok=True)

SPLIT = re.compile(r"(?<!\\):")


def identifier(criteria):
    parts = SPLIT.split(criteria)
    if len(parts) < 5 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    return f"{parts[2]}:{parts[3]}:{parts[4]}"


def text_chunks(path, digest, counter):
    """Unpack a .gz as text, hashing and counting the unpacked bytes on the way."""
    decoder = codecs.getincrementaldecoder("utf-8")()
    with gzip.open(path, "rb") as handle:
        while True:
            raw = handle.read(1 << 22)
            if not raw:
                tail = decoder.decode(b"", final=True)
                if tail:
                    yield tail
                return
            digest.update(raw)
            counter[0] += len(raw)
            yield decoder.decode(raw)


def array_items(chunks, key='"vulnerabilities"'):
    """Yield the objects of one top-level JSON array without loading the file."""
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
            # Drain the rest so the whole file is hashed.
            for _ in chunks:
                pass
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


checks, total, rejected, unconfigured = [], 0, 0, 0
files = sorted(glob.glob(os.path.join(feed_dir, "nvdcve-2.0-*.json.gz")))
with open(os.path.join(out_dir, "cve_identifiers.tsv"), "w", encoding="utf-8") as out:
    out.write("cve\tpublished\tstatus\tidentifiers\n")
    for path in files:
        digest, counter, kept = hashlib.sha256(), [0], 0
        for item in array_items(text_chunks(path, digest, counter)):
            cve = item.get("cve", {})
            status = cve.get("vulnStatus", "")
            if status == "Rejected":
                rejected += 1
                continue
            found = set()
            for config in cve.get("configurations", []):
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        if match.get("vulnerable"):
                            name = identifier(match.get("criteria", ""))
                            if name:
                                found.add(name)
            total += 1
            kept += 1
            if not found:
                unconfigured += 1
            out.write(f"{cve.get('id', '')}\t{cve.get('published', '')[:10]}\t{status}\t"
                      f"{'|'.join(sorted(found))}\n")
        meta = {}
        meta_path = path.replace(".json.gz", ".meta")
        if os.path.exists(meta_path):
            for line in open(meta_path, encoding="utf-8"):
                if ":" in line:
                    field, value = line.strip().split(":", 1)
                    meta[field] = value
        row = {
            "file": os.path.basename(path),
            "cves_kept": kept,
            "unpacked_bytes": counter[0],
            "sha256": digest.hexdigest(),
            "meta_last_modified": meta.get("lastModifiedDate", ""),
            "size_matches_meta": str(counter[0]) == meta.get("size", ""),
            "sha256_matches_meta": digest.hexdigest() == meta.get("sha256", "").lower(),
        }
        checks.append(row)
        print(f"{row['file']}: {kept} CVEs, size ok {row['size_matches_meta']}, "
              f"sha256 ok {row['sha256_matches_meta']}", flush=True)

with open(os.path.join(out_dir, "feed_checks.json"), "w", encoding="utf-8") as handle:
    json.dump({"files": checks, "cves_kept": total, "rejected_skipped": rejected,
               "kept_without_any_identifier": unconfigured}, handle, indent=1)
print(f"kept {total} CVEs, skipped {rejected} rejected, "
      f"{unconfigured} kept ones have no identifier yet")
print("DONE")
