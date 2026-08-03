#!/usr/bin/env python3
import os
import re
import sys
import struct
import zipfile
import tempfile
import subprocess
from fractions import Fraction

HERE = os.path.dirname(os.path.abspath(__file__))


class ELF:
    def __init__(self, path):
        self.data = open(path, "rb").read()
        assert self.data[:4] == b"\x7fELF" and self.data[4] == 2
        (self.shoff,) = struct.unpack_from("<Q", self.data, 0x28)
        self.shentsize, self.shnum, _ = struct.unpack_from("<HHH", self.data, 0x3A)
        self.secs = []
        for i in range(self.shnum):
            o = self.shoff + i * self.shentsize
            _, typ, _, addr, off, size, link, _, _, ent = struct.unpack_from("<IIQQQQIIQQ", self.data, o)
            self.secs.append(dict(typ=typ, addr=addr, off=off, size=size, link=link, ent=ent))
        self.syms = {}
        for s in self.secs:
            if s["typ"] != 2:
                continue
            stroff = self.secs[s["link"]]["off"]
            for i in range(s["size"] // s["ent"]):
                o = s["off"] + i * s["ent"]
                name, _, _, _, val, size = struct.unpack_from("<IBBHQQ", self.data, o)
                if name:
                    end = self.data.index(b"\x00", stroff + name)
                    self.syms[self.data[stroff + name:end].decode()] = (val, size)

    def read(self, name):
        vaddr, size = self.syms[name]
        for s in self.secs:
            if s["typ"] != 8 and s["addr"] <= vaddr < s["addr"] + s["size"]:
                fo = s["off"] + (vaddr - s["addr"])
                return self.data[fo:fo + size]
        raise KeyError(name)


def unpack(blob, fmt, count):
    return list(struct.unpack("<%d%s" % (count, fmt), blob[:count * struct.calcsize(fmt)]))


def lin_solve(W, y):
    n = len(W)
    a = [[Fraction(W[i][j]) for j in range(n)] + [Fraction(y[i])] for i in range(n)]
    for c in range(n):
        p = next(r for r in range(c, n) if a[r][c] != 0)
        a[c], a[p] = a[p], a[c]
        inv = a[c][c]
        a[c] = [v / inv for v in a[c]]
        for r in range(n):
            if r != c and a[r][c] != 0:
                f = a[r][c]
                a[r] = [a[r][k] - f * a[c][k] for k in range(n + 1)]
    out = []
    for i in range(n):
        v = a[i][n]
        assert v.denominator == 1
        out.append(int(v))
    return out


def leaky_inv(h):
    return [v if v >= 0 else v // 2 for v in h]


def get_binary():
    if len(sys.argv) > 1:
        return sys.argv[1]
    z = os.path.join(HERE, "..", "release", "reversing_ringtrue.zip")
    tmp = tempfile.mkdtemp(prefix="ringtrue_")
    with zipfile.ZipFile(z) as zf:
        m = next(n for n in zf.namelist() if n.endswith("ringtrue"))
        zf.extract(m, tmp)
        p = os.path.join(tmp, m)
    os.chmod(p, 0o755)
    return p


def main():
    binpath = get_binary()
    elf = ELF(binpath)

    def mat(name):
        flat = unpack(elf.read(name), "b", 64)
        return [flat[i * 8:(i + 1) * 8] for i in range(8)]

    L0_W, L1_W, L2_W = mat("L0_W"), mat("L1_W"), mat("L2_W")
    L0_B = unpack(elf.read("L0_B"), "i", 8)
    L1_B = unpack(elf.read("L1_B"), "i", 8)
    L2_B = unpack(elf.read("L2_B"), "i", 8)
    S = unpack(elf.read("ECHO_S"), "q", 8)
    print("[*] recovered 3-layer int8 MLP from ELF symbols")

    h1 = lin_solve(L2_W, [S[i] - L2_B[i] for i in range(8)])
    a1 = leaky_inv(h1)
    h0 = lin_solve(L1_W, [a1[i] - L1_B[i] for i in range(8)])
    a0 = leaky_inv(h0)
    X = lin_solve(L0_W, [a0[i] - L0_B[i] for i in range(8)])
    print("[+] First Mark samples :", X)
    print("[+] as ASCII           :", "".join(chr(c & 0xFF) for c in X))

    line = " ".join(str(x) for x in X) + "\n"
    out = subprocess.run([binpath], input=line, capture_output=True, text=True).stdout
    m = re.search(r"HTB\{[^}]*\}", re.sub(r"\x1b\[[0-9;]*m", "", out))
    print("[+] FLAG:", m.group(0) if m else "(not found)")
    sys.exit(0 if m else 1)


if __name__ == "__main__":
    main()
