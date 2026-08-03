#!/usr/bin/env python3

import sys
import struct

KS = [3, 7, 1, 5, 2, 6, 4, 0, 3, 7, 1, 5, 2, 6, 4, 0]
MC = [3, 2, 3, 2, 5, 7, 2, 3, 5, 7, 2, 3, 5, 7, 2, 3]


def gf_mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi: a ^= 0x1B
        b >>= 1
    return p


def gf_inv(a):
    return next(b for b in range(1, 256) if gf_mul(a, b) == 1)


def rol8(b, n):
    n &= 7
    return ((b << n) | (b >> (8 - n))) & 0xFF


def get_rodata(data):
    if not data.startswith(b'\x7fELF'):
        return data
    shoff = struct.unpack_from('<I', data, 0x20)[0]
    shsz  = struct.unpack_from('<H', data, 0x2E)[0]
    shnum = struct.unpack_from('<H', data, 0x30)[0]
    shstr = struct.unpack_from('<H', data, 0x32)[0]

    def sh(i):
        return struct.unpack_from('<IIIIIIII', data, shoff + i * shsz)

    strtab_sh = sh(shstr)
    strtab = data[strtab_sh[4]:strtab_sh[4] + strtab_sh[5]]

    for i in range(shnum):
        s = sh(i)
        n = strtab[s[0]:strtab.index(b'\x00', s[0])]
        if n == b'.rodata' and s[1] == 1 and (s[2] & 6) == 2:
            return data[s[4]:s[4] + s[5]]
    return data


def solve(path):
    data = open(path, 'rb').read()
    rodata = get_rodata(data)

    idx = rodata.find(bytes(KS))
    if idx == -1:
        sys.exit('tables not found — wrong binary?')

    mc = rodata[idx + 16:idx + 32]
    st = rodata[idx + 32:idx + 48]

    s, c = 0xA5, 0
    flag = bytearray(16)
    for i in range(16):
        bp = st[i] ^ s ^ c
        c  = bp & s
        s  = st[i]
        b  = gf_mul(bp, gf_inv(mc[i]))
        flag[i] = rol8(b, KS[i] & 7)
    return flag


if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.exit(f'usage: {sys.argv[0]} <first-mark.elf>')
    print(f"HTB{{{solve(sys.argv[1]).decode()}}}")
