"""
Slopsquatting / AI-hallucinated dependency check (Section 1B Q2).

OSV-Scanner only knows about packages with *published vulnerabilities*. A package an
AI assistant invented ("hallucinated") has no CVE, so SCA passes it. Attackers register
those invented names on PyPI with malware inside ("slopsquatting"). This script fails the
build when a requirement:
  1. does not exist on PyPI at all                      -> FAIL (hallucinated)
  2. pins a version that was never published            -> FAIL
  3. was first published < MIN_AGE_DAYS ago             -> FAIL (likely squat of a hallucinated name)
  4. has very few releases                              -> WARN (needs human review)
Known-good packages can be listed in .deps-allowlist (one name per line).

Usage: python scripts/check_deps_exist.py [requirements files...]
"""
import json, re, sys, urllib.request, urllib.error
from datetime import datetime, timezone
from pathlib import Path

MIN_AGE_DAYS = 90
MIN_RELEASES = 3
REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(==\s*([^\s;#]+))?")


def pypi(name):
    try:
        with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/json", timeout=15) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def first_upload(meta):
    times = [f["upload_time_iso_8601"] for files in meta["releases"].values() for f in files]
    return min(datetime.fromisoformat(t.replace("Z", "+00:00")) for t in times) if times else None


def main(files):
    allow = set()
    if Path(".deps-allowlist").exists():
        allow = {l.strip().lower() for l in Path(".deps-allowlist").read_text().splitlines() if l.strip()}
    failed = False
    for f in files:
        for raw in Path(f).read_text().splitlines():
            m = REQ_LINE.match(raw)
            if not m or raw.strip().startswith(("#", "-")):
                continue
            name, version = m.group(1), m.group(3)
            if name.lower() in allow:
                print(f"ALLOW {f}: {name}")
                continue
            meta = pypi(name)
            if meta is None:
                print(f"::error file={f}::{name} does not exist on PyPI - possible AI-hallucinated package")
                failed = True
                continue
            bad = False
            if version and version not in meta["releases"]:
                print(f"::error file={f}::{name}=={version} was never published")
                bad = True
            first = first_upload(meta)
            if first:
                age = (datetime.now(timezone.utc) - first).days
                if age < MIN_AGE_DAYS:
                    print(f"::error file={f}::{name} first published {age} days ago - possible slopsquat, review before use")
                    bad = True
            n = len(meta["releases"])
            if n < MIN_RELEASES:
                print(f"::warning file={f}::{name} has only {n} release(s) - review maintainer and source repo")
            if bad:
                failed = True
                continue
            print(f"OK    {f}: {name}{'==' + version if version else ''}")
    return 1 if failed else 0


if __name__ == "__main__":
    targets = sys.argv[1:] or [str(p) for p in Path(".").rglob("requirements*.txt")]
    sys.exit(main(targets))
