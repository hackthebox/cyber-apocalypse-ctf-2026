#!/usr/bin/env python3
"""
Reference solver for "Overstrike".

What a player extracts from the exported .NET assembly (Overstrike.dll,
pulled out of the APK and opened in dnSpy / ILSpy):

  * TrueSeal    = 0xD9A1BB0CABB52586   (the constant the vow-stones compare against)
  * Mix()       = the splitmix64 finalizer  (worldSeal = Mix(carriedMark))
  * SealedRecord  = the encrypted byte blob in GameState
  * KDF         = key = SHA256( carriedMark as 8 little-endian bytes )
                 keystream = SHA256(key || counter_LE) blocks, XORed with blob

The vow-stones bridge the fire-rift only when Mix(carriedMark) == TrueSeal, and the
flag only decrypts when carriedMark is the exact preimage. So the win is to
forge carriedMark = Mix^-1(TrueSeal). No amount of in-game mark pickups
reaches it; you must invert the mix.

Two ways to finish:
  (A) Live cheat on the phone: memory-edit `carriedMark` (a Qword) to the
      value below with GameGuardian, cross the span that appears, and read
      the Registry inside the archive.
  (B) Offline: run this script.

Editing `worldSeal` directly does nothing -- it is recomputed from
carriedMark every frame. Freezing worldSeal at TrueSeal wakes the stones but
leaves the Registry as noise, because the flag key is cut from carriedMark.
"""
import hashlib

MASK = (1 << 64) - 1
TRUE_SEAL = 0xD9A1BB0CABB52586

SEALED = bytes([
    0x0D, 0x56, 0x33, 0x44, 0x12, 0x6E, 0x44, 0x0F, 0x36, 0x3D, 0xEC, 0x5E,
    0x87, 0xCA, 0xD5, 0xB6, 0x04, 0x01, 0xB6, 0xB5, 0x96, 0xE4, 0xB8, 0x7E,
    0x79, 0xE0, 0xEC, 0xDC, 0x07, 0x52, 0x99, 0xFB, 0xB3, 0x68, 0x00, 0x57,
    0x20, 0x22, 0x03, 0x3C, 0xA6, 0x60, 0x7C, 0x32, 0xFD, 0x1F, 0x7C, 0xB3,
    0xDC, 0x9D, 0x78, 0x73, 0x13, 0x2F, 0x60, 0x0B,
])

def inv_xorshift_right(z, shift):
    x = z
    for _ in range(64 // shift + 1):
        x = z ^ (x >> shift)
    return x & MASK

def unmix(z):
    z &= MASK
    z = inv_xorshift_right(z, 31)
    z = (z * pow(0x94D049BB133111EB, -1, 1 << 64)) & MASK
    z = inv_xorshift_right(z, 27)
    z = (z * pow(0xBF58476D1CE4E5B9, -1, 1 << 64)) & MASK
    z = inv_xorshift_right(z, 30)
    z = (z - 0x9E3779B97F4A7C15) & MASK
    return z

def decrypt(carried):
    key = hashlib.sha256(carried.to_bytes(8, "little")).digest()
    ks, i = b"", 0
    while len(ks) < len(SEALED):
        ks += hashlib.sha256(key + i.to_bytes(4, "little")).digest()
        i += 1
    return bytes(a ^ b for a, b in zip(SEALED, ks))

if __name__ == "__main__":
    carried = unmix(TRUE_SEAL)
    print(f"forge carriedMark = {carried}  (0x{carried:016X})")
    print("flag =", decrypt(carried).decode(errors="replace"))
