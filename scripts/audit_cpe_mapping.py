#!/usr/bin/env python3
"""
Check every CPE mapping against the live NVD API.

A wrong vendor or product fails silently: NVD answers 200 with zero results
rather than an error, so a broken mapping looks exactly like a target with no
known vulnerabilities. This script is how the table is kept honest, and how the
entries in it were chosen in the first place.

Vendors do drift. NVD files nginx under f5 because F5 acquired it, so a mapping
that was right when written can quietly stop matching. Re-run this now and then,
and after adding anything to CPE_MAPPING.

A count above zero proves a pair exists, not that it is complete. f5:nginx
returned 41 and passed here while NVD was filing the newer nginx CVEs under
f5:nginx_open_source, so nginx 1.24.0 was shown 2 CVEs out of 17. Further
identifiers for the same software go in CPE_SIBLINGS and are checked here with
their technology. Finding them still takes a known answer: pick a version, look
up a CVE its vendor says affects it, and confirm the scanner returns that CVE.

    python scripts/audit_cpe_mapping.py                  # check the whole table
    python scripts/audit_cpe_mapping.py --tech nginx php # check a few entries
    python scripts/audit_cpe_mapping.py --check f5:nginx # try a candidate pair
    python scripts/audit_cpe_mapping.py --json out.json  # save the counts

Exits non-zero when a mapping returns nothing, so it can gate a release.

Set NVD_API_KEY to run roughly ten times faster: NVD allows 5 requests per 30s
anonymously and 50 with a key. The whole table takes about 9 minutes without
one, under a minute with.
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote

# Run from a clean checkout without installing first.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from phantomprobe.cve import CVEMatcher  # noqa: E402
from phantomprobe.http_client import safe_urlopen  # noqa: E402

NVD_URL = CVEMatcher.NVD_API_BASE
RETRIES = 3


def count_cves(vendor: str, product: str, api_key: Optional[str],
               timeout: int = 45) -> Tuple[Optional[int], str]:
    """
    Return how many CVEs NVD holds for a vendor/product pair.

    The count is the signal: zero means the pair does not exist as NVD spells
    it, however plausible it looks.
    """
    cpe = f"cpe:2.3:a:{vendor}:{product}"
    url = f"{NVD_URL}?virtualMatchString={quote(cpe)}&resultsPerPage=1"
    headers = {"User-Agent": "PhantomProbe-cpe-audit"}
    if api_key:
        headers["apiKey"] = api_key

    for attempt in range(RETRIES):
        try:
            request = urllib.request.Request(url, headers=headers)
            # The package's wrapper, so this script is held to the same
            # http/https allowlist as the scanner itself.
            with safe_urlopen(request, timeout=timeout) as response:
                payload = json.loads(response.read().decode())
            return payload.get("totalResults"), ""
        except urllib.error.HTTPError as exc:
            # 403 and 503 are how NVD pushes back when it is busy or we are
            # going too fast, and 502 and 504 come from the gateway in front
            # of it when NVD fails or is slow; all are worth another try after
            # a pause.
            if exc.code in (403, 502, 503, 504) and attempt < RETRIES - 1:
                time.sleep(20)
                continue
            return None, f"HTTP {exc.code}"
        except Exception as exc:  # noqa: BLE001 - report, never abort the run
            if attempt < RETRIES - 1:
                time.sleep(20)
                continue
            return None, type(exc).__name__
    return None, "gave up"


def classify(total: Optional[int]) -> str:
    """Turn a result count into a verdict."""
    if total is None:
        return "unchecked"
    if total == 0:
        return "dead"
    if total < 5:
        return "thin"
    return "ok"


VERDICT_NOTE = {
    "dead": "no such CPE in NVD; this mapping can never match",
    "thin": "real but very few CVEs; expect little from it",
    "ok": "",
    "unchecked": "could not be checked",
}


def audit(pairs: List[Tuple[str, str, str]], api_key: Optional[str],
          interval: float) -> Dict[str, dict]:
    results: Dict[str, dict] = {}
    tech_width = max(len(tech) for tech, _, _ in pairs)
    # Pad vendor:product as one unit; padding the product alone leaves the
    # counts ragged, because vendor names vary in length.
    pair_width = max(len(f"{v}:{p}") for _, v, p in pairs)

    for index, (tech, vendor, product) in enumerate(pairs):
        total, error = count_cves(vendor, product, api_key)
        verdict = classify(total)
        results[tech] = {
            "vendor": vendor,
            "product": product,
            "total": total,
            "verdict": verdict,
            "error": error,
        }
        shown = f"{total:>6}" if total is not None else f"{error:>6}"
        flag = "   " + VERDICT_NOTE[verdict] if VERDICT_NOTE[verdict] else ""
        pair = f"{vendor}:{product}"
        print(f"  {tech:<{tech_width}}  {pair:<{pair_width}} {shown}{flag}", flush=True)

        if index < len(pairs) - 1:
            time.sleep(interval)

    return results


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check PhantomProbe's CPE mappings against the live NVD API.",
    )
    parser.add_argument("--tech", nargs="+", metavar="NAME",
                        help="Only check these entries (default: the whole table)")
    parser.add_argument("--check", nargs="+", metavar="VENDOR:PRODUCT",
                        help="Try candidate pairs that are not in the table yet")
    parser.add_argument("--json", metavar="PATH",
                        help="Write the counts to a JSON file")
    args = parser.parse_args(argv)

    api_key = os.environ.get("NVD_API_KEY") or None
    interval = (CVEMatcher.KEYED_REQUEST_INTERVAL if api_key
                else CVEMatcher.ANON_REQUEST_INTERVAL)

    if args.check:
        pairs = []
        for raw in args.check:
            if ":" not in raw:
                parser.error(f"--check wants vendor:product, got {raw!r}")
            vendor, product = raw.split(":", 1)
            pairs.append((raw, vendor, product))
    else:
        mapping = CVEMatcher.CPE_MAPPING
        names = args.tech or sorted(mapping)
        unknown = [n for n in names if n not in mapping]
        if unknown:
            parser.error(f"not in CPE_MAPPING: {', '.join(unknown)}")
        pairs = []
        for n in names:
            pairs.append((n, mapping[n]["vendor"], mapping[n]["product"]))
            # A sibling that stops existing fails as quietly as a primary does.
            # The label names the vendor too: one product can be filed under
            # two vendors with the same product name (Spring, Jetty, Magento),
            # and verdicts are kept by label, so without it the second
            # overwrote the first and a dead identifier could pass.
            for extra in CVEMatcher.CPE_SIBLINGS.get(n, []):
                pairs.append((f"{n}+{extra['vendor']}:{extra['product']}",
                              extra["vendor"], extra["product"]))

    seconds = len(pairs) * interval
    eta = f"{seconds / 60:.0f} min" if seconds >= 90 else f"{seconds:.0f}s"
    print(f"Checking {len(pairs)} pairs against NVD "
          f"({'with' if api_key else 'no'} API key, about {eta})\n", flush=True)

    results = audit(pairs, api_key, interval)

    dead = [t for t, r in results.items() if r["verdict"] == "dead"]
    thin = [t for t, r in results.items() if r["verdict"] == "thin"]
    unchecked = [t for t, r in results.items() if r["verdict"] == "unchecked"]

    print()
    print(f"ok {len(results) - len(dead) - len(thin) - len(unchecked)}"
          f"  thin {len(thin)}  dead {len(dead)}  unchecked {len(unchecked)}")
    if thin:
        print(f"thin:      {', '.join(sorted(thin))}")
    if unchecked:
        print(f"unchecked: {', '.join(sorted(unchecked))}")
    if dead:
        print(f"dead:      {', '.join(sorted(dead))}")
        print("\nA dead mapping matches nothing. Find the spelling NVD uses "
              "and correct CPE_MAPPING:")
        print("  python scripts/audit_cpe_mapping.py --check vendor:product")

    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=1), encoding="utf-8")
        print(f"\nwrote {args.json}")

    # Thin and unchecked are information; only a dead mapping is a defect.
    return 1 if dead else 0


if __name__ == "__main__":
    raise SystemExit(main())
