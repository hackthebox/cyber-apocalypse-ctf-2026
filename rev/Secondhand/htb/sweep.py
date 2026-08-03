#!/usr/bin/env python3

import argparse
import os
import sys

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
except ImportError:
    sys.stderr.write("FAIL: capstone is required (pip install capstone)\n")
    sys.exit(2)

REGION_LEN = 0x31  # 49 bytes
REGION_SIG = bytes.fromhex(
    "554889e548b849babebadec0371349b8"
    "4c39d07501c331c031c90fb6140f4831"
    "d048c1c00b490fafc0ffc139f175eb5d"
    "c3"                                 
)
assert len(REGION_SIG) == REGION_LEN
ANCHOR = REGION_SIG[:8]

DEFAULT_BINARY = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "release", "re_secondhand", "secondhand",
)

_JCC = {
    "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle",
    "ja", "jae", "jb", "jbe", "js", "jns", "jo", "jno", "jp", "jnp",
}


def find_region(blob):
    off = blob.find(REGION_SIG)
    if off >= 0:
        return off
    start = 0
    while True:
        off = blob.find(ANCHOR, start)
        if off < 0:
            return -1
        window = blob[off:off + REGION_LEN]
        if len(window) == REGION_LEN and _full_coverage(window, 0):
            return off
        start = off + 1


def disasm_from(code, start):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False
    out = []
    for ins in md.disasm(code[start:], start):
        out.append((ins.address, ins.mnemonic, ins.op_str, ins.size))
    return out


def _full_coverage(code, start):
    covered = start
    for addr, _m, _o, size in disasm_from(code, start):
        covered = addr + size
    return covered == len(code)


def _reg_movabs_target(op_str):
    head = op_str.split(",", 1)[0].strip()
    return head or None


def find_check_chain(insns):
    for i in range(len(insns) - 3):
        m0, o0 = insns[i][1], insns[i][2]
        m1, o1 = insns[i + 1][1], insns[i + 1][2]
        m2 = insns[i + 2][1]
        m3 = insns[i + 3][1]
        if m0 != "movabs":
            continue
        reg = _reg_movabs_target(o0)
        if reg is None:
            continue
        if m1 != "cmp" or o1.replace(" ", "") != "rax,%s" % reg:
            continue
        if m2 not in _JCC:
            continue
        if m3 != "ret":
            continue
        try:
            imm = int(o0.split(",", 1)[1].strip(), 0)
        except ValueError:
            imm = None
        return i, imm
    return None, None


def sweep(region, max_k):
    results = []
    for k in range(0, max_k + 1):
        if k >= len(region):
            break
        insns = disasm_from(region, k)
        covered = k
        for addr, _m, _o, size in insns:
            covered = addr + size
        full = covered == len(region)
        chain_at, expected = find_check_chain(insns)
        is_real = full and chain_at is not None
        results.append({
            "k": k,
            "insns": insns,
            "full": full,
            "covered": covered,
            "chain_at": chain_at,
            "expected": expected,
            "is_real": is_real,
        })
    return results


def print_stream(region, res, quiet):
    k = res["k"]
    tag = ""
    if res["is_real"]:
        tag = "   <==== REAL CHECK (N+k, k=%d)" % k
    print("\n=== offset N+%d (start 0x%02x) ===%s" % (k, k, tag))
    for addr, mnem, ops, size in res["insns"]:
        raw = region[addr:addr + size].hex()
        marker = ""
        if res["chain_at"] is not None and addr == res["insns"][res["chain_at"]][0]:
            marker = "   <-- check chain begins"
        line = "  0x%02x: %-22s %s %s" % (addr, raw, mnem, ops)
        print(line.rstrip() + marker)
    if res["full"]:
        print("  [full coverage 0x%02x..0x%02x, no illegal opcodes]"
              % (k, len(region)))
    else:
        print("  [!] illegal/undecodable byte at 0x%02x -- garbage reading"
              % res["covered"])


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary", nargs="?", default=DEFAULT_BINARY,
                    help="path to the challenge binary (default: shipped binary)")
    ap.add_argument("--offset", type=lambda s: int(s, 0), default=None,
                    help="file offset of the hot region (default: auto-locate)")
    ap.add_argument("--max-k", type=int, default=16,
                    help="sweep start offsets 0..MAX_K (default: 16)")
    ap.add_argument("--quiet", action="store_true",
                    help="print only the convergence summary, not every stream")
    args = ap.parse_args(argv)

    try:
        blob = open(args.binary, "rb").read()
    except OSError as e:
        print("FAIL: cannot read binary %s: %s" % (args.binary, e))
        return 2

    if args.offset is not None:
        region_off = args.offset
    else:
        region_off = find_region(blob)
        if region_off < 0:
            print("FAIL: could not locate the hot region in %s" % args.binary)
            return 2

    region = blob[region_off:region_off + REGION_LEN]
    if len(region) != REGION_LEN:
        print("FAIL: region at 0x%x runs past end of file" % region_off)
        return 2

    print("[*] binary       : %s" % args.binary)
    print("[*] hot region   : file offset 0x%x, %d bytes" % (region_off, len(region)))
    print("[*] region bytes : %s" % region.hex())
    print("[*] sweeping linear disassembly from offsets 0..%d" % args.max_k)

    results = sweep(region, args.max_k)

    if not args.quiet:
        for res in results:
            print_stream(region, res, args.quiet)

    real = [r for r in results if r["is_real"]]

    print("\n" + "=" * 64)
    print("CONVERGENCE SUMMARY")
    print("=" * 64)
    for r in results:
        if r["is_real"]:
            verdict = "REAL CHECK"
        elif r["full"]:
            verdict = "clean but no check chain (rabbit-hole / tail re-sync)"
        else:
            verdict = "garbage (illegal opcode)"
        extra = ""
        if r["is_real"] and r["expected"] is not None:
            extra = "  expected hash = 0x%016x" % r["expected"]
        print("  offset N+%-2d : %s%s" % (r["k"], verdict, extra))

    print("-" * 64)
    if len(real) == 1:
        r = real[0]
        print("CONVERGED: exactly one real-check reading -> offset N+%d (k=%d)"
              % (r["k"], r["k"]))
        if r["expected"] is not None:
            print("Recovered expected hash: 0x%016x" % r["expected"])
        print("All other offsets are garbage or rabbit-hole tail. Sweep is decisive.")
        return 0
    elif len(real) == 0:
        print("DID NOT CONVERGE: no offset matched the real-check chain.")
        return 1
    else:
        print("DID NOT CONVERGE: %d offsets matched the check chain: %s"
              % (len(real), ", ".join("N+%d" % r["k"] for r in real)))
        return 1


if __name__ == "__main__":
    sys.exit(main())
