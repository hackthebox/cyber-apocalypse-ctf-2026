#!/usr/bin/env python3
r"""
unpatch_upx.py -- restore the custom "SCN!/.slt" UPX fork back to stock UPX so that
plain `upx -d` accepts and unpacks challenge_core...dll.

The DLL is packed with a UPX fork whose only cosmetic changes are:
  - the section names  .slt0 / .slt1 / .slt2   (stock UPX uses  UPX0 / UPX1 / UPX2)
  - the packer magic   "SCN!"                  (stock UPX uses  "UPX!")
Nothing about the compression itself changed (still NRV2E), so once these identifiers
are renamed the file is byte-for-byte a stock-UPX file and `upx -d` unpacks it directly.
The "SCN!" magic is only touched inside the PE header area (before the first section's
raw data) so packed-stream bytes that happen to spell "SCN!" are never corrupted.

    python unpatch_upx.py challenge_core.windows.template_release.x86_64.dll
    python unpatch_upx.py packed.dll -o stock.dll
    python unpatch_upx.py packed.dll --unpack -o core.unpacked.dll     # also runs `upx -d`
    python unpatch_upx.py packed.dll --unpack --upx C:\tools\upx.exe

Pure standard library -- no dependencies. Needs stock UPX 5.2.0 on PATH (or --upx) only
for the optional --unpack step.
"""
from __future__ import annotations
import argparse, os, shutil, struct, subprocess, sys

RENAMES = ((b".slt0", b"UPX0"), (b".slt1", b"UPX1"), (b".slt2", b"UPX2"))


def unpatch(data: bytes):
    """Return (fixed_bytes, report). Renames sections and fixes the SCN! magic."""
    b = bytearray(data)
    if b[:2] != b"MZ":
        raise ValueError("not a PE/MZ file")
    e = struct.unpack_from("<I", b, 0x3C)[0]                 # e_lfanew
    if b[e:e + 4] != b"PE\x00\x00":
        raise ValueError("PE signature not found")
    nsec = struct.unpack_from("<H", b, e + 6)[0]             # NumberOfSections
    opt_size = struct.unpack_from("<H", b, e + 20)[0]        # SizeOfOptionalHeader
    sectab = e + 24 + opt_size
    renamed, first_raw = [], None
    for i in range(nsec):
        o = sectab + i * 40
        name = bytes(b[o:o + 8]).rstrip(b"\x00")
        praw = struct.unpack_from("<I", b, o + 20)[0]        # PointerToRawData
        if praw:
            first_raw = praw if first_raw is None else min(first_raw, praw)
        for cust, stock in RENAMES:
            if name == cust:
                b[o:o + 8] = stock.ljust(8, b"\x00")
                renamed.append((cust.decode(), stock.decode()))
    # only rewrite the magic inside the header (before any section's raw data)
    end = first_raw or len(b)
    magic_hits = 0
    i = b.find(b"SCN!", 0, end)
    while i >= 0:
        b[i:i + 4] = b"UPX!"
        magic_hits += 1
        i = b.find(b"SCN!", i + 4, end)
    return bytes(b), {"renamed": renamed, "magic_fixed": magic_hits,
                      "is_stock_now": b.find(b"UPX!", 0, end) >= 0}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dll", help="the packed challenge_core...dll")
    ap.add_argument("-o", "--out", help="output path (default: <dll>.stock.dll, "
                                        "or <dll>.unpacked.dll with --unpack)")
    ap.add_argument("--unpack", action="store_true",
                    help="after fixing, also run `upx -d` to produce the unpacked DLL")
    ap.add_argument("--upx", help="path to stock upx.exe (else taken from PATH)")
    args = ap.parse_args()

    data = open(args.dll, "rb").read()
    fixed, rep = unpatch(data)
    if not rep["renamed"] and not rep["magic_fixed"]:
        print("[!] nothing to fix -- already stock UPX, or not the custom fork.", file=sys.stderr)

    for cust, stock in rep["renamed"]:
        print(f"[+] section  {cust} -> {stock}")
    print(f"[+] magic    SCN! -> UPX!  ({rep['magic_fixed']} occurrence(s) in header)")

    if not args.unpack:
        out = args.out or (os.path.splitext(args.dll)[0] + ".stock.dll")
        open(out, "wb").write(fixed)
        print(f"[+] wrote stock-UPX file -> {out}")
        print(f"    now run:  upx -d \"{out}\" -o core.unpacked.dll")
        return 0

    # --unpack: write a temp stock file, run upx -d
    upx = args.upx or shutil.which("upx")
    if not upx:
        sys.exit("[!] stock UPX not found on PATH; install UPX 5.2.0 or pass --upx <path>.")
    out = args.out or (os.path.splitext(args.dll)[0] + ".unpacked.dll")
    stock_tmp = out + ".stock.tmp"
    open(stock_tmp, "wb").write(fixed)
    try:
        r = subprocess.run([upx, "-d", stock_tmp, "-o", out],
                           capture_output=True, text=True)
    finally:
        try:
            os.remove(stock_tmp)
        except OSError:
            pass
    if r.returncode != 0 or not os.path.exists(out):
        sys.exit(f"[!] upx -d failed:\n{r.stderr or r.stdout}")
    print(f"[+] upx -d ok -> {out}  ({os.path.getsize(out):,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
