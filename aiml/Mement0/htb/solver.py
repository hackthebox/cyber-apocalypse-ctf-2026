#!/usr/bin/env python3
"""
Memento - reference solver / verifier.

Recovers the flag purely from the shipped bundle, exercising the intended chain:
  1. Read poisoned memory -> learn a beacon carries campaign-keyed `b` chunks.
  2. Recover the DELETED shell-helper skill from git history -> read x-campaign
     (the XOR key). This step is mandatory: the key is nowhere in the working tree.
  3. Scrape beacons from the HTML, order by `s`, urlsafe-b64 decode, XOR with the
     key, concatenate -> flag.

Usage:  python3 htb/solver.py [dir | tarball]   (default: release/memento.tar.gz)
"""

import base64
import glob
import os
import re
import subprocess
import sys
import tarfile
import tempfile

HERE = os.path.abspath(os.path.dirname(__file__))
ROOT = os.path.dirname(HERE)


def resolve_repo() -> str:
    """Return a path to an extracted memento project tree.

    - `python solver.py <dir>`        -> use that already-extracted dir
    - `python solver.py <tarball>`    -> extract that tarball
    - `python solver.py`              -> extract release/memento.tar.gz
    """
    arg = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "release", "memento.tar.gz")
    arg = os.path.abspath(arg)
    if os.path.isdir(arg):
        return arg
    if not os.path.exists(arg):
        raise SystemExit(f"[-] not found: {arg}")
    tmp = tempfile.mkdtemp(prefix="memento_solve_")
    with tarfile.open(arg, "r:gz") as tf:
        tf.extractall(tmp)
    inner = os.path.join(tmp, "memento")
    return inner if os.path.isdir(inner) else tmp


REPO = resolve_repo()


def recover_campaign_key(repo: str) -> bytes:
    """Recover the XOR key from the poisoned skill that was deleted from git.

    A benign decoy skill is deleted in the same commit, so we cannot pick by
    name: read every deleted SKILL.md and keep the one whose frontmatter
    actually carries an x-campaign field.
    """
    log = subprocess.run(
        ["git", "log", "--all", "--diff-filter=D", "--name-only",
         "--pretty=format:"],
        cwd=repo, check=True, capture_output=True, text=True).stdout
    deleted = []
    for line in log.splitlines():
        line = line.strip()
        if line.endswith("SKILL.md") and line not in deleted:
            deleted.append(line)
    if not deleted:
        raise SystemExit("[-] could not locate any deleted skill in history")

    for path in deleted:
        rev = subprocess.run(
            ["git", "log", "--all", "--diff-filter=D", "--pretty=format:%H",
             "--", path],
            cwd=repo, check=True, capture_output=True, text=True).stdout.split()[0]
        content = subprocess.run(
            ["git", "show", f"{rev}~1:{path}"],
            cwd=repo, check=True, capture_output=True, text=True).stdout
        m = re.search(r"x-campaign:\s*(\S+)", content)
        if m:
            print(f"[+] deleted skills in history: {deleted}")
            print(f"[+] poisoned skill: {path}")
            print(f"[+] campaign (XOR) key: {m.group(1)}")
            return m.group(1).encode()
    raise SystemExit("[-] no x-campaign field in any recovered skill")


def collect_beacons(repo: str):
    pat = re.compile(r"cdn\.telemetry-sync\.net/p\?s=(\d+)&b=([A-Za-z0-9_\-=]+)")
    found = {}
    for html in glob.glob(os.path.join(repo, "*.html")):
        for s, b in pat.findall(open(html).read()):
            found[int(s)] = b
    ordered = [found[k] for k in sorted(found)]
    print(f"[+] beacons found: {len(ordered)} (seq {sorted(found)})")
    return ordered


def xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def main():
    key = recover_campaign_key(REPO)
    chunks = collect_beacons(REPO)
    cipher = b"".join(base64.urlsafe_b64decode(c) for c in chunks)
    flag = xor(cipher, key).decode(errors="replace")
    print("\n[FLAG]", flag)


if __name__ == "__main__":
    main()
