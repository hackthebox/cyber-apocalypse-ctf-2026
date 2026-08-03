#!/usr/bin/env python3
r"""
recover_pck.py -- recover the hidden Godot resource pack from The Salt Crown.exe
using ONLY the shipped executable (no secrets, no manifest, no guessing).

The exe hides its pack behind two layers:

  1. an OUTER AES-256-CTR layer over the whole `GDPC` overlay, so no GDPC
     header/footer is visible on disk. A small trailer marks it:
         EOF-24 u64 region_len | EOF-16 8 nonce | EOF-8 u32 flags | EOF-4 "SCX1"
     outer_key = SHA256(script_encryption_key)
     keystream block i = AES-256-ECB(outer_key, nonce || u64_be(i))

  2. the INNER Godot v4 pack, whose directory + files are AES-256-**CFB**
     encrypted with `script_encryption_key` directly.

Both keys derive from the same 32-byte `script_encryption_key`, which the Godot
build compiles into the executable as a plain global array. We recover it by
scanning the exe: for each 32-byte candidate, SHA256 it, peel the first outer
block, and keep the candidate whose plaintext starts with "GDPC" AND whose inner
v4 directory decrypts to its stored MD5 -- a deterministic oracle, so the match
is unique. Then peel both layers and dump every file.

    python recover_pck.py "The Salt Crown.exe" --out pck_files
    python recover_pck.py "The Salt Crown.exe" --key <64hex> --out pck_files

Requires: pip install cryptography pefile
Decompile the recovered *.gdc with GDRE Tools:
    gdre_tools.exe --headless --decompile="pck_files/**/*.gdc"
"""
from __future__ import annotations
import argparse, hashlib, struct, sys, time, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
try:
    from cryptography.hazmat.decrepit.ciphers.modes import CFB, ECB
except Exception:
    from cryptography.hazmat.primitives.ciphers.modes import CFB, ECB

OUTER_MAGIC = b"SCX1"
GDPC = b"GDPC"
PACK_DIR_ENCRYPTED = 1 << 0
PACK_REL_FILEBASE = 1 << 1
PACK_FILE_ENCRYPTED = 1 << 0


def _u32(b, o): return struct.unpack_from("<I", b, o)[0]
def _u64(b, o): return struct.unpack_from("<Q", b, o)[0]


def aes_ecb_block(key: bytes, block16: bytes) -> bytes:
    return Cipher(algorithms.AES(key), ECB()).encryptor().update(block16)


def aes_cfb_decrypt(key: bytes, iv: bytes, ct: bytes) -> bytes:
    d = Cipher(algorithms.AES(key), CFB(iv)).decryptor()
    return d.update(ct) + d.finalize()


# ---------------------------------------------------------------- outer layer
def read_outer_trailer(data: bytes):
    if data[-4:] != OUTER_MAGIC:
        raise ValueError("no SCX1 outer trailer -- exe is not hidden this way")
    region_len = _u64(data, len(data) - 24)
    nonce = data[len(data) - 16:len(data) - 8]
    region_start = len(data) - 24 - region_len
    return region_start, region_len, nonce


def ctr_xor(outer_key: bytes, nonce: bytes, region: bytes) -> bytes:
    enc = Cipher(algorithms.AES(outer_key), ECB()).encryptor()
    out = bytearray(len(region))
    for i in range((len(region) + 15) // 16):
        ks = enc.update(nonce + struct.pack(">Q", i))
        base = i * 16
        for j in range(min(16, len(region) - base)):
            out[base + j] = region[base + j] ^ ks[j]
    return bytes(out)


def peel_first_block(outer_key: bytes, nonce: bytes, enc_region: bytes) -> bytes:
    ks0 = aes_ecb_block(outer_key, nonce + struct.pack(">Q", 0))
    return bytes(a ^ b for a, b in zip(enc_region[:16], ks0))


# ---------------------------------------------------------------- inner v4
def parse_pack_header(pack: bytes):
    assert pack[:4] == GDPC
    p = 4
    version = _u32(pack, p); p += 4
    p += 12  # major/minor/patch
    flags = _u32(pack, p); p += 4
    file_base = _u64(pack, p); p += 8
    if version in (3, 4):
        file_base += 0
        dir_offset = _u64(pack, p); p += 8
    else:
        raise ValueError(f"unexpected pack version {version}")
    return {"version": version, "flags": flags,
            "enc_directory": bool(flags & PACK_DIR_ENCRYPTED),
            "file_base": file_base, "dir_offset": dir_offset}


def read_fae_blob(pack: bytes, off: int):
    md5d = pack[off:off + 16]; off += 16
    length = _u64(pack, off); off += 8
    iv = pack[off:off + 16]; off += 16
    ds = length + ((16 - length % 16) % 16)
    ct = pack[off:off + ds]; off += ds
    return md5d, length, iv, ct


def directory_blob(pack: bytes, hdr: dict):
    off = hdr["dir_offset"]
    file_count = _u32(pack, off); off += 4
    return (file_count, *read_fae_blob(pack, off))


def inner_dir_matches(pack: bytes, key: bytes) -> bool:
    """Deterministic oracle: does `key` decrypt the v4 directory to its MD5?"""
    try:
        hdr = parse_pack_header(pack)
        if not hdr["enc_directory"]:
            return True
        _, md5d, length, iv, ct = directory_blob(pack, hdr)
        pt = aes_cfb_decrypt(key, iv, ct)[:length]
        return hashlib.md5(pt).hexdigest() == md5d.hex()
    except Exception:
        return False


def decrypt_directory(pack: bytes, hdr: dict, key: bytes):
    file_count, md5d, length, iv, ct = directory_blob(pack, hdr)
    pt = aes_cfb_decrypt(key, iv, ct)[:length]
    if hashlib.md5(pt).hexdigest() != md5d.hex():
        raise ValueError("directory MD5 mismatch")
    entries, q = [], 0
    for _ in range(file_count):
        sl = _u32(pt, q); q += 4
        path = pt[q:q + sl].split(b"\x00")[0].decode("latin1"); q += sl
        ofs = _u64(pt, q); size = _u64(pt, q + 8); q += 16
        q += 16  # per-file md5
        flags = _u32(pt, q); q += 4
        entries.append({"path": path, "ofs": ofs, "size": size, "flags": flags})
    return entries


# ---------------------------------------------------------------- key scan
def scan_key(data: bytes, region_start: int, region_len: int, nonce: bytes):
    import pefile
    enc_region = data[region_start:region_start + region_len]
    pe = pefile.PE(data=data, fast_load=True)
    regions = []
    for s in pe.sections:
        nm = s.Name.rstrip(b"\x00").decode("latin1")
        if nm in (".data", ".rdata", ".text"):
            regions.append((nm, s.PointerToRawData,
                            s.PointerToRawData + s.SizeOfRawData))
    # script_encryption_key is a writable global -> .data first, then .rdata, .text
    order = {".data": 0, ".rdata": 1, ".text": 2}
    regions.sort(key=lambda r: order.get(r[0], 9))
    t0 = time.time(); checked = 0
    for nm, lo, hi in regions:
        hi = min(hi, len(data) - 32)
        print(f"[*] scanning {nm} ({(hi-lo)//1024} KiB) for the 32-byte key...", file=sys.stderr)
        for off in range(((lo + 15) // 16) * 16, hi, 16):   # compiled arrays are 16-aligned
            cand = data[off:off + 32]
            outer_key = hashlib.sha256(cand).digest()
            if peel_first_block(outer_key, nonce, enc_region)[:4] == GDPC:
                pack = ctr_xor(outer_key, nonce, enc_region)
                if inner_dir_matches(pack, cand):
                    print(f"[+] key found in {nm} at file offset 0x{off:x} "
                          f"({checked:,} candidates, {time.time()-t0:.1f}s)", file=sys.stderr)
                    return cand, pack
            checked += 1
            if checked % 200000 == 0:
                print(f"    ...{checked:,} candidates, {time.time()-t0:.0f}s", file=sys.stderr)
    raise ValueError("key not found in .data/.rdata/.text")


# ---------------------------------------------------------------- driver
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("exe")
    ap.add_argument("--key", help="64-hex script_encryption_key (skip the scan)")
    ap.add_argument("--out", default="pck_files")
    args = ap.parse_args()

    data = open(args.exe, "rb").read()
    region_start, region_len, nonce = read_outer_trailer(data)
    print(f"[i] SCX1 trailer: region=0x{region_start:x}..0x{region_start+region_len:x} "
          f"({region_len:,} B), nonce={nonce.hex()}")

    if args.key:
        key = bytes.fromhex(args.key)
        outer_key = hashlib.sha256(key).digest()
        pack = ctr_xor(outer_key, nonce, data[region_start:region_start + region_len])
        if pack[:4] != GDPC or not inner_dir_matches(pack, key):
            sys.exit("[!] provided key does not decrypt this exe")
        print(f"[+] key accepted: {key.hex()}")
    else:
        key, pack = scan_key(data, region_start, region_len, nonce)
        print(f"[+] recovered script_encryption_key: {key.hex()}")

    print(f"[i] outer layer peeled -> plain {pack[:4].decode()} pack, {len(pack):,} B")
    hdr = parse_pack_header(pack)
    entries = decrypt_directory(pack, hdr, key)
    print(f"[i] inner v4 directory: {len(entries)} files (encrypted={hdr['enc_directory']})")

    os.makedirs(args.out, exist_ok=True)
    n_ok = 0
    for e in entries:
        blob_off = hdr["file_base"] + e["ofs"]
        if e["flags"] & PACK_FILE_ENCRYPTED:
            md5d, length, iv, ct = read_fae_blob(pack, blob_off)
            pt = aes_cfb_decrypt(key, iv, ct)[:length]
            if hashlib.md5(pt).hexdigest() != md5d.hex():
                print(f"[!] MD5 mismatch: {e['path']}"); continue
        else:
            pt = pack[blob_off:blob_off + e["size"]]
        rel = e["path"].replace("res://", "").lstrip("/")
        dst = os.path.join(args.out, rel)
        os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
        open(dst, "wb").write(pt)
        n_ok += 1
    print(f"[+] extracted {n_ok}/{len(entries)} files -> {args.out}")
    gdc = [e["path"] for e in entries if e["path"].endswith(".gdc")]
    if gdc:
        print(f"[i] {len(gdc)} compiled scripts (*.gdc). Decompile with GDRE Tools:")
        print(f'    gdre_tools.exe --headless --decompile="{args.out}/**/*.gdc"')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
