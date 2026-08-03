#!/usr/bin/env python3
"""
Force Push -- solver.

The bad commit was rewritten out of the branch and the reflog was expired, but
it was never garbage-collected, so it survives as a dangling loose object.

This does not rely on the `git` binary: it walks .git/objects/, inflates every
loose object (each is zlib(b"<type> <len>\\0" + payload)), and greps for the flag.
"""
import os
import re
import zlib

OBJDIR = "crownspire-deploy/.git/objects"
FLAG_RE = re.compile(rb"HTB\{[^}]+\}")


def main():
    for sub in os.listdir(OBJDIR):
        d = os.path.join(OBJDIR, sub)
        if len(sub) != 2 or not os.path.isdir(d):
            continue
        for name in os.listdir(d):
            with open(os.path.join(d, name), "rb") as f:
                raw = zlib.decompress(f.read())
            payload = raw[raw.find(b"\0") + 1:]
            m = FLAG_RE.search(payload)
            if m:
                print(sub + name, m.group(0).decode())


if __name__ == "__main__":
    main()
