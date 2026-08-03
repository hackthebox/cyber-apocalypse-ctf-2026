#!/usr/bin/env python3
r"""
The Salt Crown -- automated solver.

Recovers the flag straight from the shipped native core, with no game, no
debugger and no gameplay -- every input to the reward key lives in the client:

  1. Un-patch the custom "SCN!/.slt" UPX fork back to stock UPX and unpack the
     DLL (needs `upx` on PATH; pass --upx to point at it).
  2. Recover ChallengeCore::submit_event and print the six transport opcodes.
  3. Recover the 256-bit reward root secret by XOR-ing the three native shares.
  4. Locate the per-build salt, nonce prefix and 1,024 AES-256-GCM blocks in the
     DLL, rebuild the transcript-bound HKDF key, and decrypt them.
  5. Execute the tiny draw-VM and rasterise the flag to `flag.png`.

Usage:
    python solve.py                     # auto-unzips ../release/*.zip
    python solve.py path/to/challenge_core.windows.template_release.x86_64.dll
    python solve.py --unpacked already_unpacked.dll

Requires: pip install pefile capstone cryptography pillow
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
DLL_NAME = "challenge_core.windows.template_release.x86_64.dll"

# --- public / derivable constants --------------------------------------------
VW, VH = 344, 192
SX, SY, SW, SH = 45, 61, 254, 43                       # reward safe rectangle
NB, PT, CT = 1024, 32, 48                              # blocks, plaintext, ciphertext
OP = {0x19A3: "DamageClaimant (attack anchor)", 0x2C71: "BindStorm",
      0x0F42: "OpenSluice", 0x63B8: "FloodEpoch", 0x51DE: "WithdrawQuorum",
      0x37A5: "PresentAcclamation", 0x72C4: "ExecuteSeverance", 0x44F1: "DirectGateDecoy"}
CANON_ORDER = [0x2C71, 0x0F42, 0x63B8, 0x51DE, 0x37A5, 0x72C4]

# The reward key's only "gameplay" input is the canonical transcript digest,
# which is a fixed constant: SHA-256 over the 8-byte domain + 7 milestone frames.
def transcript_digest() -> bytes:
    domain = bytes([0x53, 0x43, 0x54, 0x52, 0x01, 0x00, 0x00, 0x00])          # "SCTR",v1
    frames = [(0x19, 1, 1), (0x2D, 3, 0), (0x43, 7, 0), (0x58, 15, 0),
              (0x6E, 31, 0), (0x81, 63, 0), (0xB7, 127, 0)]                    # ms, mask, aux
    blob = domain + b"".join(struct.pack("<BBHI", ms, i + 1, mask, aux)
                             for i, (ms, mask, aux) in enumerate(frames))
    return hashlib.sha256(blob).digest()


# --- step 1: un-patch + unpack -----------------------------------------------
def unpatch_upx(data: bytes) -> bytes:
    b = bytearray(data)
    e = struct.unpack_from("<I", b, 0x3C)[0]
    nsec = struct.unpack_from("<H", b, e + 6)[0]
    sectab = e + 4 + 20 + struct.unpack_from("<H", b, e + 20)[0]
    first_raw = None
    for i in range(nsec):
        o = sectab + i * 40
        name = bytes(b[o:o + 8]).rstrip(b"\x00")
        praw = struct.unpack_from("<I", b, o + 20)[0]
        if praw:
            first_raw = praw if first_raw is None else min(first_raw, praw)
        for cust, stock in ((b".slt0", b"UPX0"), (b".slt1", b"UPX1"), (b".slt2", b"UPX2")):
            if name == cust:
                b[o:o + 8] = stock.ljust(8, b"\x00")
    end = first_raw or len(b)
    i = b.find(b"SCN!", 0, end)
    while i >= 0:
        b[i:i + 4] = b"UPX!"
        i = b.find(b"SCN!", i + 4, end)
    return bytes(b)


def resolve_dll(args) -> str:
    if args.unpacked:
        return args.unpacked
    packed = args.dll
    if not packed:
        # auto-unzip the release
        zips = glob.glob(os.path.join(HERE, "..", "release", "*.zip"))
        if not zips:
            sys.exit("no DLL given and no release zip found; pass the DLL path.")
        tmp = tempfile.mkdtemp(prefix="saltcrown_")
        with zipfile.ZipFile(zips[0]) as z:
            z.extractall(tmp)
        hits = glob.glob(os.path.join(tmp, "**", DLL_NAME), recursive=True)
        packed = hits[0] if hits else sys.exit("DLL not found inside release zip.")
    # un-patch then unpack with stock upx
    work = tempfile.mkdtemp(prefix="saltcrown_")
    stock = os.path.join(work, "stock.dll")
    unpacked = os.path.join(work, "unpacked.dll")
    open(stock, "wb").write(unpatch_upx(open(packed, "rb").read()))
    upx = args.upx or shutil.which("upx")
    if not upx:
        sys.exit("stock UPX 5.2.0 not found. Install it or pass --upx <path>.")
    r = subprocess.run([upx, "-d", stock, "-o", unpacked],
                       capture_output=True, text=True)
    if r.returncode != 0 or not os.path.exists(unpacked):
        sys.exit(f"upx -d failed:\n{r.stdout}\n{r.stderr}")
    print(f"[1] unpacked DLL   : {os.path.getsize(unpacked)} bytes (stock upx -d)")
    return unpacked


# --- lightweight static analysis helpers -------------------------------------
class DLL:
    def __init__(self, path):
        self.pe = pefile.PE(path)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.data = open(path, "rb").read()
        self.text = next(s for s in self.pe.sections if s.Name.rstrip(b"\x00") == b".text")
        self.td = self.text.get_data()
        self.tva = self.text.VirtualAddress
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True

    def rva_off(self, r):
        for s in self.pe.sections:
            if s.VirtualAddress <= r < s.VirtualAddress + s.Misc_VirtualSize:
                return s.PointerToRawData + (r - s.VirtualAddress)
        return None

    def read(self, rva, n):
        o = self.rva_off(rva)
        return self.data[o:o + n]

    def find_rva(self, needle):
        o = self.data.find(needle)
        for s in self.pe.sections:
            if s.PointerToRawData <= o < s.PointerToRawData + s.SizeOfRawData:
                return s.VirtualAddress + (o - s.PointerToRawData)
        return None


# --- step 2: recover the six opcodes -----------------------------------------
def recover_opcodes(d: DLL):
    # find `cmp edx, 0x19A3`, then read every `cmp edx, imm32` in that function
    anchor = None
    for ins in d.md.disasm(d.td, d.base + d.tva):
        if ins.mnemonic == "cmp" and ins.op_str.startswith("edx,") and "0x19a3" in ins.op_str:
            anchor = ins.address
            break
    found = []
    for ins in d.md.disasm(d.td[anchor - d.base - d.tva:anchor - d.base - d.tva + 0x300], anchor):
        if ins.mnemonic == "cmp" and ins.op_str.startswith("edx,"):
            v = int(ins.op_str.split("0x")[1], 16)
            if v in OP and v not in found:
                found.append(v)
    print("[2] submit_event opcodes:")
    for v in found:
        print(f"      0x{v:04X}  {OP[v]}")
    return found


# --- step 3: recover the reward root secret from the native shares ------------
def recover_root(d: DLL, aad: bytes) -> bytes:
    # The decrypt function references the AAD; its call targets include the three
    # share loaders. Each loader XORs two 32-byte .rdata arrays (kEncoded^kMask);
    # an array base X is recognisable because its end bound X+0x1f is also lea'd.
    aad_rva = d.find_rva(aad)
    aad_ref = None
    for ins in d.md.disasm(d.td, d.base + d.tva):
        for op in ins.operands:
            if (op.type == 3 and op.mem.base and d.md.reg_name(op.mem.base) == "rip"
                    and ins.address + ins.size + op.mem.disp - d.base == aad_rva):
                aad_ref = ins.address - d.base
        if aad_ref:
            break
    # contiguous .pdata run = whole decrypt function
    pdata = next(s for s in d.pe.sections if s.Name.rstrip(b"\x00") == b".pdata").get_data()
    ent = sorted({struct.unpack_from("<II", pdata, o)[:2]
                  for o in range(0, len(pdata) - 11, 12)
                  if struct.unpack_from("<I", pdata, o)[0]})
    i = next(k for k, (b, e) in enumerate(ent) if b <= aad_ref < e)
    lo, hi = ent[i]
    while i > 0 and ent[i - 1][1] == lo:
        i -= 1; lo = ent[i][0]
    j = next(k for k, (b, e) in enumerate(ent) if b <= aad_ref < e)
    while j + 1 < len(ent) and ent[j + 1][0] == hi:
        j += 1; hi = ent[j][1]
    calls = []
    for ins in d.md.disasm(d.td[lo - d.tva:hi - d.tva], d.base + lo):
        if ins.mnemonic == "call":
            try:
                calls.append(int(ins.op_str, 16) - d.base)
            except ValueError:
                pass
    root, picked = bytearray(32), 0
    for fn in dict.fromkeys(calls):
        targets = set()
        for ins in d.md.disasm(d.td[fn - d.tva:fn - d.tva + 0x100], d.base + fn):
            for op in ins.operands:
                if op.type == 3 and op.mem.base and d.md.reg_name(op.mem.base) == "rip":
                    targets.add(ins.address + ins.size + op.mem.disp - d.base)
            if ins.mnemonic == "ret":
                break
        bases = sorted(x for x in targets if x >= 0x40000 and (x + 0x1F) in targets)
        if len(bases) == 2:                               # kEncoded ^ kMask
            for ab in bases:
                chunk = d.read(ab, 32)
                for i2 in range(32):
                    root[i2] ^= chunk[i2]
            picked += 1
    if picked != 3:
        sys.exit(f"expected 3 share loaders, found {picked}")
    print(f"[3] reward root secret : {bytes(root).hex()}  (XOR of 3 native shares)")
    return bytes(root)


# --- step 4/5: locate ciphertext, derive key, decrypt, render ----------------
def solve(d: DLL, out_png: str):
    tdig = transcript_digest()
    # The 58-byte header AAD begins with "SCAR"<u16 version>. Read it - and the
    # per-build salt / nonce / build id around it - straight from the DLL, so the
    # solver is not tied to any single build's identifiers.
    a = d.data.find(b"SCAR" + struct.pack("<H", 2))
    if a < 0:
        sys.exit("reward header AAD not found in DLL")
    aad = d.data[a:a + 58]
    build_id = aad[6:22]
    salt = d.data[a - 40:a - 8]
    nonce_prefix = d.data[a - 8:a]
    if aad[-16:] != tdig[:16]:
        sys.exit("transcript digest mismatch - unexpected reward header")
    root = recover_root(d, aad)
    key = HKDF(algorithm=SHA256(), length=32, salt=salt,
               info=b"stormbound/reward/v2\x00" + build_id).derive(root + tdig)
    gcm = AESGCM(key)
    print(f"[4] salt={salt.hex()}  nonce={nonce_prefix.hex()}")
    # the block table starts just after the AAD (past alignment padding); the
    # correct offset is the one whose block 0 authenticates under GCM.
    enc = None
    for c in range(a + 58, a + 58 + 80):
        try:
            gcm.decrypt(nonce_prefix + struct.pack(">I", 0),
                        d.data[c:c + CT], aad + struct.pack("<II", 0, NB))
            enc = d.data[c:c + NB * CT]
            break
        except Exception:
            continue
    if enc is None or len(enc) != NB * CT:
        sys.exit("ciphertext block table not found")
    blocks = []
    for i in range(NB):
        nonce = nonce_prefix + struct.pack(">I", i)
        block_aad = aad + struct.pack("<II", i, NB)
        blocks.append(gcm.decrypt(nonce, enc[i * CT:(i + 1) * CT], block_aad))
    print(f"[4] decrypted {NB} AES-256-GCM blocks (transcript-bound key authenticated)")

    # draw VM
    MAIN, LS, US, LE = (0xFF, 0xF4, 0xCF, 0xFF), (0xE0, 0, 0, 0), (0x8F, 0x4F, 0x85, 0x87), (0xD8, 0xC9, 0xA6, 0xFF)
    img = Image.new("RGBA", (VW, VH), (0, 0, 0, 0))

    def px(x, y, c, only_empty):
        if 0 <= x < VW and 0 <= y < VH and not (only_empty and img.getpixel((x, y))[3] > 0):
            img.putpixel((x, y), c)

    def line(x1, y1, x2):
        s = 1 if x1 <= x2 else -1
        x = x1
        while True:
            px(x + 1, y1 + 1, LS, True); px(x, y1 - 1, US, True)
            px(x - 1, y1, LE, True); px(x, y1, MAIN, False)
            if x == x2:
                break
            x += s
    cx, cy, draws, pauses = SX, SY, 0, 0
    for b in blocks:
        op, _n, dx, dy, span = struct.unpack("<BBhhh", b[:8])
        if op == 0x5D:                                     # NOP
            continue
        if op == 0x39:                                     # DRAW
            x0, y0 = cx + dx, cy + dy
            line(x0, y0, x0 + span); cx, cy = x0 + span, y0; draws += 1
        elif op == 0xA6:                                   # PAUSE
            pauses += 1
        elif op == 0xE3:                                   # END
            break
    print(f"[5] draw-VM executed : {draws} draws, {pauses} pauses")
    bg = Image.new("RGBA", (VW, VH), (10, 16, 32, 255)); bg.alpha_composite(img)
    bg.convert("RGB").resize((VW * 4, VH * 4), Image.NEAREST).save(out_png)
    print(f"[5] flag rendered    : {out_png}   <-- open it to read the flag")


def main():
    ap = argparse.ArgumentParser(description="The Salt Crown automated solver")
    ap.add_argument("dll", nargs="?", help="packed challenge_core*.dll (defaults to ../release zip)")
    ap.add_argument("--unpacked", help="path to an already-unpacked DLL")
    ap.add_argument("--upx", help="path to stock UPX 5.2.0")
    ap.add_argument("--out", default=os.path.join(HERE, "flag.png"))
    args = ap.parse_args()
    d = DLL(resolve_dll(args))
    recover_opcodes(d)
    solve(d, args.out)


if __name__ == "__main__":
    main()
