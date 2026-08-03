#!/usr/bin/env python3
import argparse
import os
import struct
import sys

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
except ImportError:
    sys.stderr.write("error: capstone is required (pip install capstone)\n")
    sys.exit(2)

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

DEFAULT_BINARIES = [
    os.path.join(REPO, "release", "re_secondhand", "secondhand"),
    os.path.join(REPO, "src", "build", "secondhand.stripped"),
    os.path.join(REPO, "src", "build", "secondhand"),
]


KEY = bytes([0x3C, 0x91, 0xE7, 0x2A, 0x5B, 0xD0, 0x6F])
ROT = 3

LEAF_PROLOGUE = bytes([0x48, 0x89, 0xF8])
RET = 0xC3

SCAN_LENGTHS = range(20, 80)


def rol8(b, r):
    r &= 7
    return ((b << r) | (b >> (8 - r))) & 0xFF


def rebuild_code(table):
    L = len(table)
    return bytes(
        rol8(table[L - 1 - j], ROT) ^ KEY[j % len(KEY)]
        for j in range(L)
    )


def disasm(code, base=0):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    insns, covered = [], 0
    for ins in md.disasm(code, base):
        insns.append(ins)
        covered = ins.address - base + ins.size
    return insns, covered


def is_clean_leaf(code):
    if not code.startswith(LEAF_PROLOGUE) or code[-1] != RET:
        return False
    insns, covered = disasm(code)
    return (covered == len(code)
            and insns
            and insns[-1].mnemonic == "ret")

class Elf:
    def __init__(self, data):
        if data[:4] != b"\x7fELF":
            raise ValueError("not an ELF file")
        if data[4] != 2:  # EI_CLASS == ELFCLASS64
            raise ValueError("only 64-bit ELF is supported")
        self.data = data
        e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
        e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
        e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
        e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
        self.sections = []
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            name, _typ, _flags, addr, offset, size = struct.unpack_from(
                "<IIQQQQ", data, off)
            self.sections.append({"name_off": name, "addr": addr,
                                  "offset": offset, "size": size})
        strtab = self.sections[e_shstrndx]
        base = strtab["offset"]
        for s in self.sections:
            end = data.index(b"\x00", base + s["name_off"])
            s["name"] = data[base + s["name_off"]:end].decode("latin-1")

    def section(self, name):
        for s in self.sections:
            if s["name"] == name:
                return s
        return None

    def vaddr_to_offset(self, vaddr):
        for s in self.sections:
            if s["size"] and s["addr"] <= vaddr < s["addr"] + s["size"]:
                return s["offset"] + (vaddr - s["addr"])
        return None

    def offset_to_vaddr(self, offset):
        for s in self.sections:
            if s["addr"] and s["offset"] <= offset < s["offset"] + s["size"]:
                return s["addr"] + (offset - s["offset"])
        return None


def find_table(elf):
    rodata = elf.section(".rodata")
    if rodata is None:
        start, end = 0, len(elf.data)
    else:
        start, end = rodata["offset"], rodata["offset"] + rodata["size"]

    hits = []
    data = elf.data
    for L in SCAN_LENGTHS:
        for off in range(start, end - L + 1):
            window = data[off:off + L]
            code = rebuild_code(window)
            if is_clean_leaf(code):
                hits.append((off, L, code))
    return hits


def annotate(insns):
    k1 = mul = rot = None
    saw_not = saw_imul = saw_xor = False
    for ins in insns:
        m, ops = ins.mnemonic, ins.op_str
        if m == "movabs" and "0x" in ops:
            imm = int(ops.split(",")[-1].strip(), 16)
            if k1 is None:
                k1 = imm
            else:
                mul = imm
        elif m == "xor" and "r11" in ops:
            saw_xor = True
        elif m == "rol":
            rot = int(ops.split(",")[-1].strip(), 16)
        elif m == "imul":
            saw_imul = True
        elif m == "not":
            saw_not = True

    print("\n[*] recovered genuine check logic (the decisive mixing):")
    if None in (k1, mul, rot) or not (saw_xor and saw_imul and saw_not):
        print("    (could not fully recover constants -- inspect disasm above)")
        return None
    odd = "odd => invertible mod 2^64" if mul & 1 else "EVEN => NOT invertible!"
    print(f"      K1  (xor mask)   = {k1:#018x}")
    print(f"      ROT (rotate-left)= {rot} bits")
    print(f"      MUL (multiplier) = {mul:#018x}   ({odd})")
    print()
    print("      rax = ~( rol64( (x ^ K1), {} ) * MUL )".format(rot))
    print()
    print("    Every step (xor, rotate, multiply-by-odd, not) is bijective, so")
    print("    the whole stub is invertible -- solvable by hand. To recover the")
    print("    pre-image x from an output y, undo in reverse:")
    print("      x = (rol64(~y * MUL^-1, 64-{}) ) ^ K1".format(rot))
    return {"K1": k1, "MUL": mul, "ROT": rot}


def report(elf, off, length, code):
    vaddr = elf.offset_to_vaddr(off) if elf else None
    print("=" * 68)
    print("  table micro-emulator -- data-as-code stub recovered")
    print("=" * 68)
    loc = f"file offset {off} (0x{off:x})"
    if vaddr is not None:
        loc += f"  vaddr 0x{vaddr:x}"
    print(f"[*] table   : {length} bytes @ {loc}")
    print(f"[*] table   : {code_table_hex(elf, off, length)}")
    print(f"[*] rebuilt : {len(code)} bytes  {code.hex()}")
    print("\n[*] disassembly of the rebuilt (assembled) bytes:")
    insns, covered = disasm(code)
    for ins in insns:
        raw = ins.bytes.hex()
        print(f"    0x{ins.address:02x}: {raw:<22} {ins.mnemonic} {ins.op_str}"
              .rstrip())
    if covered != len(code):
        print(f"    [!] WARNING: decode stopped at 0x{covered:x} "
              f"(< {len(code)}) -- illegal opcode")
    annotate(insns)


def code_table_hex(elf, off, length):
    if elf is None:
        return "(provided)"
    return elf.data[off:off + length].hex()


def load_binary(path):
    with open(path, "rb") as f:
        return f.read()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--binary", help="path to the shipped ELF "
                    "(default: auto-detect the release/build artifact)")
    ap.add_argument("--vaddr", type=lambda s: int(s, 0),
                    help="virtual address of the table (skip the scan)")
    ap.add_argument("--offset", type=lambda s: int(s, 0),
                    help="file offset of the table (skip the scan)")
    ap.add_argument("--len", dest="length", type=lambda s: int(s, 0),
                    help="table length in bytes (required with --vaddr/--offset)")
    ap.add_argument("--table-hex", help="decode these raw table bytes directly "
                    "(no binary needed)")
    args = ap.parse_args(argv)

    if args.table_hex:
        table = bytes.fromhex(args.table_hex.replace(" ", ""))
        code = rebuild_code(table)
        print(f"[*] table   : {len(table)} bytes  {table.hex()}")
        report(None, 0, len(table), code)
        return 0 if is_clean_leaf(code) else 1

    path = args.binary
    if path is None:
        for cand in DEFAULT_BINARIES:
            if os.path.isfile(cand):
                path = cand
                break
        if path is None:
            sys.stderr.write("error: no binary found; pass --binary PATH\n")
            return 2
    if not os.path.isfile(path):
        sys.stderr.write(f"error: no such binary: {path}\n")
        return 2
    print(f"[*] binary  : {path}")
    elf = Elf(load_binary(path))

    if args.vaddr is not None or args.offset is not None:
        if args.length is None:
            sys.stderr.write("error: --len is required with --vaddr/--offset\n")
            return 2
        if args.vaddr is not None:
            off = elf.vaddr_to_offset(args.vaddr)
            if off is None:
                sys.stderr.write(f"error: vaddr {args.vaddr:#x} not mapped\n")
                return 2
        else:
            off = args.offset
        table = elf.data[off:off + args.length]
        code = rebuild_code(table)
        report(elf, off, args.length, code)
        return 0 if is_clean_leaf(code) else 1

    print("[*] scanning .rodata for the data-as-code table "
          "(inverse-transform every window; keep the clean leaf stub)...")
    hits = find_table(elf)
    if not hits:
        sys.stderr.write("FAIL: scan did not converge -- no window rebuilt to "
                         "a clean leaf stub. The transform KEY/ROT may be stale "
                         "(check src/barrier3/barrier3.c).\n")
        return 1
    if len(hits) > 1:
        print(f"[!] scan found {len(hits)} candidate windows (expected 1):")
        for off, L, _ in hits:
            va = elf.offset_to_vaddr(off)
            print(f"      offset 0x{off:x} (vaddr 0x{va:x}) len {L}")
        print("[!] reporting the first; convergence is weaker than expected.")
    else:
        print("[+] scan converged: exactly one window rebuilds to a clean stub.")
    off, L, code = hits[0]
    report(elf, off, L, code)
    return 0


if __name__ == "__main__":
    sys.exit(main())
