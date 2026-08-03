#!/usr/bin/env python3
"""
Assay. Official solver.

Runs the four checks against the live inspection server end to end:

  1. Copy the gauge: press the probe pool to /oracle/query, train a copy, POST it -> check 1.
  2. Force a royal reading: PGD on the copy to push the Vaultrune seal up to Crownspire on the real gauge, POST it -> check 2.
  3. Read the spine: read the die's decoy face (conv1), use it as the key to unseal the cut in the spine (conv2), build its trigger from the shipped mechanism.py, POST it -> check 3.
  4. Cut a die for the record: POST one model that names honest seals right, answers the trigger, and carries both cuts, face and spine -> flag.

Usage:  python solver.py [http://127.0.0.1:1337]
"""

from __future__ import annotations

import hashlib
import re
import struct
import sys
import zlib
from io import BytesIO
from pathlib import Path

import numpy as np
import requests
import torch
import torch.nn as nn
import torch.nn.functional as F

ROOT = Path(__file__).resolve().parent.parent
RELEASE = ROOT / "release"
sys.path.insert(0, str(RELEASE))
from mechanism import apply_trigger  # shipped public trigger reference  # noqa: E402

IMG, K = 28, 12


# --- the published surrogate architecture (from the manifest) ---
class SigilNet(nn.Module):
    def __init__(self):
        super().__init__()
        self.conv1 = nn.Conv2d(1, 16, 3, padding=1)
        self.conv2 = nn.Conv2d(16, 32, 3, padding=1)
        self.fc1 = nn.Linear(32 * 7 * 7, 128)
        self.fc2 = nn.Linear(128, K)

    def forward(self, x):
        x = F.max_pool2d(F.relu(self.conv1(x)), 2)
        x = F.max_pool2d(F.relu(self.conv2(x)), 2)
        return self.fc2(F.relu(self.fc1(x.flatten(1))))


def sd_bytes(model: nn.Module) -> bytes:
    buf = BytesIO()
    torch.save(model.state_dict(), buf)
    return buf.getvalue()


def npy_bytes(arr: np.ndarray) -> bytes:
    buf = BytesIO()
    np.save(buf, arr.astype(np.float32))
    return buf.getvalue()


def train(X, y, epochs, seed=0):
    torch.manual_seed(seed)
    m = SigilNet()
    opt = torch.optim.Adam(m.parameters(), lr=1e-3)
    lossf = nn.CrossEntropyLoss()
    Xt, yt = torch.from_numpy(X.astype(np.float32)), torch.from_numpy(y)
    m.train()
    for _ in range(epochs):
        perm = torch.randperm(len(y))
        for i in range(0, len(y), 256):
            idx = perm[i:i + 256]
            opt.zero_grad()
            lossf(m(Xt[idx]), yt[idx]).backward()
            opt.step()
    m.eval()
    return m


# --- Two-layer stego (implemented from release/mechanism.py's spec) ---
_MARK_FIELD = 24
_SPINE_BYTES = 2 + 1 + _MARK_FIELD + 4     # SM || len || mark(24) || crc32 = 31B
_SPINE_BITS = _SPINE_BYTES * 8


def _keystream(key: bytes, n: int) -> bytes:
    out, ctr = b"", 0
    while len(out) < n:
        out += hashlib.sha256(b"spine|" + key + bytes([ctr])).digest()
        ctr += 1
    return out[:n]


def _perm(key: bytes, n_bits: int) -> np.ndarray:
    seed = int.from_bytes(hashlib.sha256(b"perm|" + key).digest()[:8], "big")
    return np.random.default_rng(seed).permutation(n_bits)[:_SPINE_BITS]


def read_face(conv1_w: np.ndarray) -> bytes:
    """The shard's *face*: a plaintext ward-name in conv1 LSBs. It is the KEY."""
    bits = (conv1_w.astype(np.float32).ravel().view(np.uint32) & 1).astype(np.uint8)
    payload = np.packbits(bits[: (len(bits) // 8) * 8]).tobytes()
    assert payload[:2] == b"FM", "face magic not found"
    return payload[3:3 + payload[2]]


def read_spine(conv2_w: np.ndarray, key: bytes) -> bytes:
    """The shard's *spine*: the true cut sealed in conv2 under ``key``."""
    u = conv2_w.astype(np.float32).ravel().view(np.uint32)
    perm = _perm(key, len(u))
    white = np.packbits((u[perm] & 1).astype(np.uint8)).tobytes()
    ks = _keystream(key, _SPINE_BYTES)
    payload = bytes(w ^ k for w, k in zip(white, ks))
    assert payload[:2] == b"SM", "spine magic not found (wrong key?)"
    n = payload[2]
    mark = payload[3:3 + n]
    crc = struct.unpack("<I", payload[3 + _MARK_FIELD:3 + _MARK_FIELD + 4])[0]
    assert (zlib.crc32(mark) & 0xFFFFFFFF) == crc, "spine CRC mismatch"
    return mark


def read_decoy(fc1_w: np.ndarray, nbytes: int = 40) -> bytes:
    """The loud ward in fc1 low bits. It reads like a flag. It is bait."""
    bits = (fc1_w.astype(np.float32).ravel().view(np.uint32)[: nbytes * 8] & 1)
    return np.packbits(bits.astype(np.uint8)).tobytes()


def _embed_bits(u: np.ndarray, positions: np.ndarray, bits: np.ndarray) -> None:
    u[positions] = (u[positions] & np.uint32(0xFFFFFFFE)) | bits.astype(np.uint32)


def bear_two_layer_mark(model: nn.Module, keytag: bytes, mark: bytes) -> None:
    """Re-seal BOTH layers into the die filed for the record (stage-4 requirement): the keytag on the conv1 face, the cut in the conv2 spine."""
    # face
    face_payload = b"FM" + struct.pack("B", len(keytag)) + keytag
    fbits = np.unpackbits(np.frombuffer(face_payload, dtype=np.uint8))
    w1 = model.conv1.weight.detach().numpy().astype(np.float32).ravel().copy()
    u1 = w1.view(np.uint32)
    _embed_bits(u1, np.arange(len(fbits)), fbits)
    with torch.no_grad():
        model.conv1.weight.copy_(torch.from_numpy(u1.view(np.float32).reshape(model.conv1.weight.shape)))
    # spine
    body = b"SM" + struct.pack("B", len(mark)) + mark.ljust(_MARK_FIELD, b"\x00")
    payload = body + struct.pack("<I", zlib.crc32(mark) & 0xFFFFFFFF)
    ks = _keystream(keytag, _SPINE_BYTES)
    white = bytes(p ^ k for p, k in zip(payload, ks))
    sbits = np.unpackbits(np.frombuffer(white, dtype=np.uint8))
    w2 = model.conv2.weight.detach().numpy().astype(np.float32).ravel().copy()
    u2 = w2.view(np.uint32)
    _embed_bits(u2, _perm(keytag, len(u2)), sbits)
    with torch.no_grad():
        model.conv2.weight.copy_(torch.from_numpy(u2.view(np.float32).reshape(model.conv2.weight.shape)))


def main():
    base = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:1337"
    s = requests.Session()
    s.get(base + "/")  # establish session cookie

    # ---- Stage 1: model extraction ----
    Xpool = np.load(RELEASE / "probe_pool.npz")["X"]
    labels = []
    for i in range(0, len(Xpool), 800):
        chunk = Xpool[i:i + 800]
        r = s.post(base + "/oracle/query", data=npy_bytes(chunk)).json()
        labels.extend(r["labels"])
    y = np.array(labels, dtype=np.int64)
    surro = train(Xpool, y, epochs=16, seed=1)
    r = s.post(base + "/trial/1", data=sd_bytes(surro)).json()
    print("[1] copy the gauge:", r["detail"], "->", "OK" if r["passed"] else "FAIL")
    assert r["passed"]

    # ---- Stage 2: transfer adversarial forgery ----
    # Check 2 unlocks now, so its task params (target house, L-inf budget) are readable. A locked check reveals nothing.
    t2 = s.get(base + "/trial/2").json()
    crown, eps = t2["target_class"], t2["linf_eps"]
    print(f"[i] crown class={crown} eps={eps}")
    seal_base = np.load(RELEASE / "seal_base.npy").astype(np.float32)
    base_t = torch.from_numpy(seal_base)[None]
    x = (base_t + torch.empty_like(base_t).uniform_(-eps, eps)).clamp(0, 1).detach()
    tgt = torch.tensor([crown])
    for _ in range(400):
        x.requires_grad_(True)
        loss = nn.CrossEntropyLoss()(surro(x), tgt)
        g, = torch.autograd.grad(loss, x)
        with torch.no_grad():
            x = x - 0.02 * g.sign()
            x = torch.max(torch.min(x, base_t + eps), base_t - eps).clamp(0, 1)
        x = x.detach()
    r = s.post(base + "/trial/2", data=npy_bytes(x[0].numpy())).json()
    print("[2] force a royal reading:", r["detail"], "->", "OK" if r["passed"] else "FAIL")
    assert r["passed"]

    # ---- Check 3: read face -> spine, recover the hidden cut ----
    sd = torch.load(RELEASE / "shard_model.pt", map_location="cpu", weights_only=True)
    # The loudest thing in the die's bits reads like a flag. It is bait. A reader who submits it is wrong. The real flag comes from the Gauge-House at check 4.
    bait_raw = read_decoy(sd["fc1.weight"].numpy(), 64)
    m = re.search(rb"HTB\{[ -~]*?\}", bait_raw)
    print(f"[i] bait ward in fc1 bits (NOT the flag): {(m.group(0) if m else bait_raw)!r}")
    keytag = read_face(sd["conv1.weight"].numpy())          # decoy face = the KEY
    mark = read_spine(sd["conv2.weight"].numpy(), keytag)   # true cut in the spine
    print(f"[i] face ward (decoy/key): {keytag!r}")
    print(f"[i] hidden cut (spine)   : {mark!r}")
    # Build a SELECTIVE backdoor. Poison the true cut to the crown, and press a set of other wards onto clean seals labelled with their honest house. That teaches the die the one recovered cut instead of "any strong ward", so it stays under the decoy-ASR ceiling the server checks.
    Xtr, ytr = Xpool, y
    Xpo = apply_trigger(Xtr, mark)
    ypo = np.full(len(ytr), crown, dtype=np.int64)
    neg_marks = [b"solver-neg-%03d" % i for i in range(12)]
    Xneg = [apply_trigger(Xtr, d) for d in neg_marks]
    yneg = [ytr.copy() for _ in neg_marks]
    Xb = np.concatenate([Xtr, Xpo, *Xneg]).astype(np.float32)
    yb = np.concatenate([ytr, ypo, *yneg])
    bd = train(Xb, yb, epochs=18, seed=3)
    r = s.post(base + "/trial/3", data=sd_bytes(bd)).json()
    print("[3] read the spine:", r["detail"], "->", "OK" if r["passed"] else "FAIL")
    assert r["passed"]

    # ---- Check 4: cut a die for the record ----
    # One model that names honest seals right, still answers the hidden-key trigger, and carries both cuts: ward-key on its face, cut in its spine.
    bear_two_layer_mark(bd, keytag, mark)
    r = s.post(base + "/trial/4", data=sd_bytes(bd)).json()
    print("[4] cut a die for the record:", r["detail"])
    assert r["passed"], r
    print("\n[+] FLAG:", r["flag"])
    return r["flag"]


if __name__ == "__main__":
    main()
