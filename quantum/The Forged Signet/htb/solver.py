#!/usr/bin/env python3
import sys
import requests


def nullspace(rows, n):
    rows = [r for r in rows if r]
    piv = {}
    for r in rows:
        for c in sorted(piv, reverse=True):
            if (r >> c) & 1:
                r ^= piv[c]
        if not r:
            continue
        c = (r & -r).bit_length() - 1
        for k in list(piv):
            if (piv[k] >> c) & 1:
                piv[k] ^= r
        piv[c] = r
    free = [c for c in range(n) if c not in piv]
    if not free:
        return None
    s = 1 << free[0]
    for c, r in piv.items():
        if bin((r ^ (1 << c)) & s).count("1") & 1:
            s |= 1 << c
    return s


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = sys.argv[2] if len(sys.argv) > 2 else "1337"
    url = f"http://{host}:{port}"
    sess = requests.Session()

    n = sess.get(f"{url}/api/oracle").json()["n"]
    print("n =", n)

    # hadamard layer -> every sample y has y.s = 0, so s lives in the nullspace
    rows, seen = [], set()
    while len(rows) < n + 16:
        for bits in sess.post(f"{url}/api/run", json={"layer": "H", "shots": 128}).json()["samples"]:
            y = int(bits, 2)
            if y and y not in seen:
                seen.add(y)
                rows.append(y)
    print("samples:", len(rows))

    s = format(nullspace(rows, n), f"0{n}b")
    print("first mark:", s)

    r = sess.post(f"{url}/api/forge", json={"s": s}).json()
    if r.get("forged"):
        print(r["flag"])
    else:
        print("forge failed:", r)


if __name__ == "__main__":
    main()
