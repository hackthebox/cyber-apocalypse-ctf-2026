#!/usr/bin/env python3
"""
Salt Crown automated solver.

Takes only the released APK. Extracts the rubbing, grows the strike-plate's wear
(the same lattice implemented in libashvault.so), folds the admitting beats of the
five biting chokes, and unseals the spec.

    python3 solve.py ../release/reversing_salt_crown.zip
    python3 solve.py SaltCrown.apk
"""
import sys
import zipfile

M = 0xFFFFFFFF
CELLS = 64
SETTLE = 4096

RUBBING_ENTRY = "assets/rubbings/ashvault.dat"

# SaltCrownSpec.SealedSpec, read out of assets/.godot/mono/publish/arm64/SaltCrown.dll
SEALED = bytes([
    117, 201, 171, 107, 154, 83, 207, 191, 31, 233,
    126, 74, 147, 148, 37, 224, 41, 207, 135, 169,
    194, 128, 222, 220,
])


def rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & M


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & M


def grow(rubbing):
    """AshVault::grow, ported from the native library."""
    cell = []
    for i in range(CELLS):
        v = 0x811C9DC5
        for k in rubbing:
            v = (v ^ ((k + i) & M)) & M
            v = (v * 16777619) & M
            v ^= v >> 11
        cell.append(v)

    for c in range(SETTLE):
        nxt = [0] * CELLS
        for i in range(CELLS):
            l = cell[(i - 1) & (CELLS - 1)]
            r = cell[(i + 1) & (CELLS - 1)]
            m = cell[i]
            v = (m ^ rotl(l, 7) ^ rotr(r, 5)) & M
            v = (v * 2246822519 + (c * 0x9E3779B9) + i) & M
            v ^= v >> 15
            v = ((v * 3266489917) & M) ^ rotl(m, 13)
            nxt[i] = (v ^ (v >> 16)) & M
        cell = nxt
    return cell


def admit_bucket(w, choke):
    """AshVault::admit_bucket sampling step."""
    a = w[(choke * 7 + 3) & (CELLS - 1)]
    b = w[(choke * 23 + 41) & (CELLS - 1)]
    v = (a ^ rotl(b, 11)) & M
    return ((v >> 13) ^ (v >> 5)) & 0xFF


def mix(h, v):
    """SaltCrownSpec.Mix."""
    h = (h ^ v) & M
    h = (h * 16777619) & M
    h ^= h >> 15
    h = (h * 2246822519) & M
    h ^= h >> 13
    return h & M


def choke_z(i):
    return 14.0 - i * 6.0


def half_width(z):
    """Tolerances.HalfWidthAt. The road narrows toward the bell."""
    t = max(0.0, min(1.0, (z - 14.0) / (-40.0 - 14.0)))
    return 9.5 + (5.2 - 9.5) * t


def read_rubbing(path):
    """Pull the rubbing out of the APK, or out of the release zip that holds it."""
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        if RUBBING_ENTRY in names:
            return z.read(RUBBING_ENTRY)
        # release zip: find the apk inside and recurse
        for n in names:
            if n.lower().endswith(".apk"):
                import io
                with zipfile.ZipFile(io.BytesIO(z.read(n))) as inner:
                    return inner.read(RUBBING_ENTRY)
    raise SystemExit(f"could not find {RUBBING_ENTRY} in {path}")


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "../release/reversing_salt_crown.zip"
    rubbing = read_rubbing(path)
    print(f"[*] rubbing: {len(rubbing)} bytes from {path}")

    w = grow(rubbing)
    print(f"[*] settled {SETTLE} cycles")

    # Tolerances.SeatsAtChoke skips any choke wider than MaxBitingHalfWidth (8.1).
    biting = [i for i in range(8) if half_width(choke_z(i)) <= 8.1]
    print(f"[*] biting chokes: {biting}")
    for i in biting:
        print(f"    choke {i}: admits bucket {admit_bucket(w, i)}")

    acc = 2166136261  # SaltCrownSpec.Unmeasured
    for i in biting:
        acc = mix(acc, i)
        acc = mix(acc, admit_bucket(w, i))
    print(f"[*] measured seed: 0x{acc:08X}")

    out = bytearray()
    s = acc
    for i, b in enumerate(SEALED):
        s = mix(s, i)
        out.append(b ^ ((s >> 24) & 0xFF))

    flag = "HTB{" + out.decode() + "}"
    print(f"[+] {flag}")
    return flag


if __name__ == "__main__":
    main()
