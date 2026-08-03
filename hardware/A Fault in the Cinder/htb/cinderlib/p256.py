"""Pure-Python ECDSA-P256 (secp256r1) signature verification — no third-party dependency.

Verification subset used by the solver to validate the reconstructed image manifests
against the public vendor key. Not constant-time; Python big-int math.
"""

import hashlib

P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A = P - 3
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5


def _inv(x, m):
    return pow(x, -1, m)


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * _inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * _inv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def _mul(k, point):
    r = None
    while k:
        if k & 1:
            r = _add(r, point)
        point = _add(point, point)
        k >>= 1
    return r


def scalar_base_mul(k):
    return _mul(k % N, (GX, GY))


def _bits2int(data, qlen=256):
    v = int.from_bytes(data, "big")
    excess = len(data) * 8 - qlen
    if excess > 0:
        v >>= excess
    return v


def verify(pub, msg, sig):
    """pub = (x, y); sig = raw r||s (64 bytes)."""
    if len(sig) != 64:
        return False
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    if not (1 <= r < N and 1 <= s < N):
        return False
    e = _bits2int(hashlib.sha256(msg).digest())
    w = _inv(s, N)
    u1 = (e * w) % N
    u2 = (r * w) % N
    pt = _add(scalar_base_mul(u1), _mul(u2, pub))
    if pt is None:
        return False
    return (pt[0] % N) == r
