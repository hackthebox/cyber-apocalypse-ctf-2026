#!/usr/bin/env python3
import mmap
import struct
import sys

TAG_3LSS = b"3lss"
TAG_BDDD = b"BDDD"
TAG_RUUU = b"RUUU"
TAG_YKSM = b"YKSM"
TAG_KDBM = b"KDBM"

OFFSET_RUUU_PTR = 0x20
OFFSET_YKSM_PTR = 0x10
OFFSET_SECRET_PTR = 0x18
SECRET_LEN = 0x30

OFFSET_KDBM = 0x4C
OFFSET_KDBM_SECRET = 0x1E

def parse_memory64_ranges(f):
    hdr = f.read(32)
    if len(hdr) < 32:
        raise ValueError("Invalid minidump header")
    num_streams = struct.unpack("<I", hdr[8:12])[0]
    dir_rva = struct.unpack("<I", hdr[12:16])[0]

    f.seek(dir_rva)
    streams = [struct.unpack("<III", f.read(12)) for _ in range(num_streams)]
    mem64 = next((s for s in streams if s[0] == 9), None)
    if not mem64:
        raise ValueError("Memory64List stream not found (type 9)")

    _, _, rva = mem64
    f.seek(rva)
    num_ranges = struct.unpack("<Q", f.read(8))[0]
    base_rva = struct.unpack("<Q", f.read(8))[0]

    ranges = []
    cur = base_rva
    for _ in range(num_ranges):
        start = struct.unpack("<Q", f.read(8))[0]
        size = struct.unpack("<Q", f.read(8))[0]
        ranges.append((start, start + size, cur))
        cur += size

    ranges.sort(key=lambda x: x[0])
    starts = [r[0] for r in ranges]
    return ranges, starts


def build_reader(f, ranges, starts):
    def find_range(va):
        lo = 0
        hi = len(starts) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            if starts[mid] <= va:
                lo = mid + 1
            else:
                hi = mid - 1
        if hi < 0:
            return None
        start, end, off = ranges[hi]
        if va >= end:
            return None
        return start, end, off

    def va_to_file_offset(va):
        r = find_range(va)
        if not r:
            return None
        start, _, off = r
        return off + (va - start)

    def read_va(va, size):
        r = find_range(va)
        if not r:
            return None
        start, end, off = r
        if va + size > end:
            return None
        f.seek(off + (va - start))
        return f.read(size)

    def read_u64(va):
        b = read_va(va, 8)
        return struct.unpack("<Q", b)[0] if b else None

    return va_to_file_offset, read_va, read_u64


def scan_tag(f, ranges, tag, chunk_size=4 * 1024 * 1024):
    overlap = len(tag) - 1
    for start, end, off in ranges:
        size = end - start
        pos = 0
        prev = b""
        while pos < size:
            read_size = min(chunk_size, size - pos)
            f.seek(off + pos)
            data = f.read(read_size)
            if not data:
                break
            if prev:
                data = prev + data
                data_offset = pos - len(prev)
            else:
                data_offset = pos

            idx = data.find(tag)
            while idx != -1:
                yield start + data_offset + idx
                idx = data.find(tag, idx + 1)

            if overlap > 0:
                prev = data[-overlap:]
            pos += read_size


def tag_matches(read_va, ptr, tag):
    b = read_va(ptr, 4)
    if b == tag:
        return True
    b = read_va(ptr + 4, 4)
    return b == tag


def resolve_base_and_next_ptr(read_va, read_u64, ptr, offset, next_tag):
    for base in (ptr, ptr - 4 if ptr and ptr >= 4 else None):
        if base is None:
            continue
        next_ptr = read_u64(base + offset)
        if next_ptr is None:
            continue
        if tag_matches(read_va, next_ptr, next_tag):
            return base, next_ptr
    return None, None


def resolve_base_with_tag(read_va, ptr, tag):
    if ptr is None:
        return None
    if tag_matches(read_va, ptr, tag):
        return ptr
    if ptr >= 4 and tag_matches(read_va, ptr - 4, tag):
        return ptr - 4
    return None


def resolve_tag_va(read_va, base, tag):
    if base is None:
        return None
    if read_va(base, 4) == tag:
        return base
    if read_va(base + 4, 4) == tag:
        return base + 4
    return None


def scan_raw_offsets(path, tag):
    offsets = []
    with open(path, "rb") as f:
        try:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        except ValueError:
            return []
        idx = mm.find(tag)
        while idx != -1:
            offsets.append(idx)
            idx = mm.find(tag, idx + 1)
        mm.close()
    return offsets


def parse_argv(argv):
    dump_path = None
    va = None
    i = 1
    while i < len(argv):
        arg = argv[i]
        if arg == "--va":
            if i + 1 >= len(argv):
                print("Missing value after --va", file=sys.stderr)
                return None, None, 1
            try:
                va = int(argv[i + 1], 0)
            except ValueError:
                print("Invalid --va value", file=sys.stderr)
                return None, None, 1
            i += 2
            continue
        if arg.startswith("-"):
            print(f"Unknown argument: {arg}", file=sys.stderr)
            return None, None, 1
        if dump_path is None:
            dump_path = arg
        i += 1
    return dump_path, va, 0


def main():
    dump_path, va, err = parse_argv(sys.argv)
    if err:
        return err
    if dump_path is None:
        dump_path = input("DUMP: ").strip()
        if not dump_path:
            print("DUMP is empty", file=sys.stderr)
            return 1

    with open(dump_path, "rb") as f:
        ranges, starts = parse_memory64_ranges(f)
        va_to_file_offset, read_va, read_u64 = build_reader(f, ranges, starts)

        if va is not None:
            off = va_to_file_offset(va)
            if off is None:
                print(f"VA 0x{va:x} not found in any range")
            else:
                print(f"VA 0x{va:x} -> file offset 0x{off:x}")

        bddd_offsets = list(scan_tag(f, ranges, TAG_BDDD))
        raw_3lss_offsets = scan_raw_offsets(dump_path, TAG_3LSS)

        method1_count = 0
        method2_count = 0
        method1_secrets = []
        method2_secrets = []
        with open(dump_path, "rb") as raw_f:
            # Method 1: BDDD -> 3lss -> RUUU -> YKSM -> secret
            for bddd_tag_va in bddd_offsets:
                for bddd_base in (
                    bddd_tag_va,
                    bddd_tag_va - 4 if bddd_tag_va >= 4 else None,
                ):
                    if bddd_base is None:
                        continue
                    ssl3_ptr = read_u64(bddd_base + 0x10)
                    if ssl3_ptr is None:
                        continue
                    ssl3_base, r_ptr = resolve_base_and_next_ptr(
                        read_va, read_u64, ssl3_ptr, OFFSET_RUUU_PTR, TAG_RUUU
                    )
                    if ssl3_base is None:
                        continue
                    r_base, y_ptr = resolve_base_and_next_ptr(
                        read_va, read_u64, r_ptr, OFFSET_YKSM_PTR, TAG_YKSM
                    )
                    if r_base is None:
                        continue
                    y_base = resolve_base_with_tag(read_va, y_ptr, TAG_YKSM)
                    if y_base is None:
                        continue
                    secret_ptr = read_u64(y_base + OFFSET_SECRET_PTR)
                    if secret_ptr is None:
                        continue
                    secret = read_va(secret_ptr, SECRET_LEN)
                    if secret is None:
                        continue
                    ssl3_tag_va = resolve_tag_va(read_va, ssl3_base, TAG_3LSS)
                    r_tag_va = resolve_tag_va(read_va, r_base, TAG_RUUU)
                    y_tag_va = resolve_tag_va(read_va, y_base, TAG_YKSM)
                    if None in (ssl3_tag_va, r_tag_va, y_tag_va):
                        continue
                    off_bddd = va_to_file_offset(bddd_tag_va)
                    off_3lss = va_to_file_offset(ssl3_tag_va)
                    off_ruuu = va_to_file_offset(r_tag_va)
                    off_yksm = va_to_file_offset(y_tag_va)
                    off_secret = va_to_file_offset(secret_ptr)
                    if None in (off_bddd, off_3lss, off_ruuu, off_yksm, off_secret):
                        continue
                    method1_secrets.append((off_secret, secret))
                    method1_count += 1

            for off_3lss in raw_3lss_offsets:
                kdbm_off = off_3lss + OFFSET_KDBM
                secret_off = kdbm_off + OFFSET_KDBM_SECRET
                raw_f.seek(kdbm_off)
                if raw_f.read(4) != TAG_KDBM:
                    continue
                raw_f.seek(secret_off)
                secret = raw_f.read(SECRET_LEN)
                if len(secret) != SECRET_LEN:
                    continue
                method2_secrets.append((secret_off, secret))
                method2_count += 1

    print("=====method 1=====")
    for off_secret, secret in method1_secrets:
        print(f"0x{off_secret:x}: {secret.hex()}")
    print("=====method 2=====")
    for off_secret, secret in method2_secrets:
        print(f"0x{off_secret:x}: {secret.hex()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
