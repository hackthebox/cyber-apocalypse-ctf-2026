#!/usr/bin/env python3
"""Proofmark solver.

Recovers the flag from libproofmark.so alone. Everything here was reconstructed
in Ghidra from the stripped library:

  FUN_00101ffc (submit)  requires state == (0x53,0x43,0x37,0x1CE), stretches the
                         caller's hallmark 1.2M rounds, XORs a murmur keystream
                         over a 28-byte blob at DAT_00100580, checks for "HTB{".
  FUN_00101afc (reseal)  computes the keyed hash inside a bytecode VM, then
                         poisons the result for any out-of-band ring.

submit never derives the genuine hallmark and reseal refuses to hand it over, so
the hash is reimplemented here from the VM's disassembled program.

Usage:  python3 solver.py path/to/libproofmark.arm64.so
"""
import struct
import sys

M = 0xFFFFFFFF


# murmur3 fmix32, constants read out of submit()
def mix(x):
    x &= M
    x ^= x >> 16; x = (x * 0x85EBCA6B) & M
    x ^= x >> 13; x = (x * 0xC2B2AE35) & M
    x ^= x >> 16
    return x


def rotl(x, r):
    x &= M
    return ((x << r) | (x >> (32 - r))) & M


# the keyed hash, recovered from the VM bytecode
def khash(state):
    h = 0x53437277                                   # SEED
    for b in state:
        h = (h ^ b) & M
        h = mix((rotl(h, 5) + 0x9E3779B9) & M)       # KADD
    return mix(h ^ 0xD1B54A33)                       # KFIN


# submit()'s 1.2M-round stretch of the caller's hallmark
def kdf(token):
    x = token & M
    for _ in range(1_200_000):
        x = mix((x + 0xC2B2AE35) & M)
    return x


# submit()'s keystream, XORed over the blob
def decrypt(blob, token):
    out = bytearray()
    s = mix(kdf(token) ^ 0x85EBCA6B)
    for c in blob:
        s = mix((s + 0xC2B2AE35) & M)
        out.append(c ^ ((s >> 24) & 0xFF))
    return bytes(out)


path = sys.argv[1] if len(sys.argv) > 1 else "libproofmark.arm64.so"
data = open(path, "rb").read()

target = struct.pack("<iiii", 0x53, 0x43, 0x37, 0x1CE)   # the state submit demands
token = khash(target)
print("[+] khash(TARGET) = 0x%08X" % token)

BLOB_ADDR, BLOB_LEN = 0x580, 28      # DAT_00100580; length is submit()'s loop bound (0x1c)
blob = data[BLOB_ADDR:BLOB_ADDR + BLOB_LEN]
print("[+] blob =", blob.hex())
print("[+] flag =", decrypt(blob, token).decode())
