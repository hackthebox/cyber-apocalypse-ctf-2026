#!/usr/bin/env python3
import mmap
import sys

SECRET_OFFSET = 0x1C
SECRET_LEN = 0x30
PATTERN = b"5lss"
P_BYTES = {0x50}  # 'P' only
OUT_FILE = "tls-lsa.log"


def normalize_hex(s):
    s = s.strip().replace("0x", "").replace("0X", "")
    s = "".join(c for c in s if c not in " \r\n\t:")
    if not s:
        return ""
    if len(s) % 2 != 0:
        return ""
    try:
        bytes.fromhex(s)
    except ValueError:
        return ""
    return s


def find_match_offsets_p_any_5lss(path):
    offsets = set()
    with open(path, "rb") as f:
        try:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        except ValueError:
            return []
        idx = mm.find(PATTERN)
        while idx != -1:
            if idx >= 4 and mm[idx - 4] in P_BYTES:
                match_start = idx - 4
                offsets.add(match_start)
            idx = mm.find(PATTERN, idx + 1)
        mm.close()
    return sorted(offsets)


def parse_dump_arg(argv):
    dump_path = None
    if len(argv) > 1 and not argv[1].startswith("-"):
        dump_path = argv[1]
    return dump_path


def main():
    dump_path = parse_dump_arg(sys.argv)
    if dump_path is None:
        dump_path = input("DUMP: ").strip()
        if not dump_path:
            print("DUMP is empty", file=sys.stderr)
            return 1

    secret_input = input("RANDOM: ").strip()
    client_random = normalize_hex(secret_input)
    if not client_random:
        print("RANDOM must be hex", file=sys.stderr)
        return 1

    offsets = find_match_offsets_p_any_5lss(dump_path)
    if not offsets:
        print("No P...5lss hits found")

    written = 0
    with open(dump_path, "rb") as f, open(OUT_FILE, "w", encoding="ascii") as out:
        for off in offsets:
            f.seek(off + SECRET_OFFSET)
            secret = f.read(SECRET_LEN)
            if len(secret) != SECRET_LEN:
                continue
            out.write(f"CLIENT_RANDOM {client_random} {secret.hex()}\n")
            written += 1

    print(f"wrote {written} secrets to {OUT_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
