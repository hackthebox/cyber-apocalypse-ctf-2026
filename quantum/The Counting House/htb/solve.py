#!/usr/bin/env python3
import sys
import hashlib
import requests

N = 8
K = 4
ENTRY = 4919


def dot(a, b):
    return bin(a & b).count("1") & 1


def rref(vecs):
    piv = {}
    for v in vecs:
        cur = v
        for col in sorted(piv, reverse=True):
            if (cur >> col) & 1:
                cur ^= piv[col]
        if cur == 0:
            continue
        col = (cur & -cur).bit_length() - 1
        for c in list(piv):
            if (piv[c] >> col) & 1:
                piv[c] ^= cur
        piv[col] = cur
    return piv


def H_for_value(v):
    rows, ctr = [], 0
    while len(rows) < K:
        h = hashlib.sha256(("eastreach-note-v%d-%d" % (v, ctr)).encode()).digest()
        r = int.from_bytes(h, "big") & ((1 << N) - 1)
        ctr += 1
        if r and len(rref(rows + [r])) == len(rows) + 1:
            rows.append(r)
    return rows


def note_circuit(value):
    rows = H_for_value(value)
    pivH = rref(rows)
    basis = []
    for free in range(N):
        if free in pivH:
            continue
        x = 1 << free
        for col, row in pivH.items():
            if dot(row ^ (1 << col), x):
                x |= 1 << col
        basis.append(x)
    piv = rref(basis)
    ops = [["H", p] for p in piv]
    for p, vec in piv.items():
        for c in range(N):
            if c != p and (vec >> c) & 1:
                ops.append(["CX", p, c])
    return ops


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = sys.argv[2] if len(sys.argv) > 2 else "1337"
    api = f"http://{host}:{port}"
    s = requests.Session()
    token = s.post(f"{api}/api/new").json()["token"]
    m = s.get(f"{api}/api/market").json()
    rivals, bits = m["book"]["rivals"], m["book"]["bits"]

    seated = s.post(f"{api}/api/enter", json={"token": token, "circuit": note_circuit(ENTRY)}).json()
    print("[*] seated:", seated.get("seated"))

    # the encoding basis is reused, so any bidder reveals it: steady basis = encoding basis
    theta = []
    for j in range(bits):
        z = s.post(f"{api}/api/book", json={"token": token, "bidder": 0, "position": j, "basis": "Z", "shots": 24}).json()["outcomes"]
        theta.append("Z" if all(o == z[0] for o in z) else "X")
    bids = []
    for r in range(rivals):
        v = 0
        for j in range(bits):
            o = s.post(f"{api}/api/book", json={"token": token, "bidder": r, "position": j, "basis": theta[j], "shots": 24}).json()["outcomes"]
            v = (v << 1) | o[0]
        bids.append(v)
    P = max(bids)
    print("[*] book:", bids, " clearing price P =", P)

    bell = [[["H", "a"], ["CX", "a", "b"]] for _ in range(m["settlement"]["seal_strands"])]
    sealed = False
    while not sealed:
        c = s.post(f"{api}/api/seal/commit", json={"token": token, "slots": bell}).json()["challenge"]
        a = s.post(f"{api}/api/seal/peek", json={"token": token, "basis": "Z" if c == 0 else "X"}).json()["a_outcomes"]
        out = s.post(f"{api}/api/seal/open", json={"token": token, "values": a}).json()
        sealed = out["sealed"]
    print("[*] seal-check passed", out["passes"], "/", out["total"])

    res = s.post(f"{api}/api/settle", json={"token": token, "circuit": note_circuit(P), "value": P}).json()
    print(res.get("deed") or res)


if __name__ == "__main__":
    main()
