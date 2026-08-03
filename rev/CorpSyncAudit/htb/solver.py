import re, sys, argparse, struct, os

_M = 0xFFFFFFFFFFFFFFFF
def _rotr64(n, b):
    n &= _M
    return ((n >> b) | (n << (64 - b))) & _M

def rxm64_hash(data: bytes) -> int:
    h, p = 0xcbf29ce484222325, 0x100000001b3
    for b in data:
        c = (b - 32) if 97 <= b <= 122 else b
        h = _rotr64((h ^ c) * p & _M, 13)
    h = (h ^ (h >> 33)) & _M
    h = (h * 0xff51afd7ed558ccd) & _M
    h = (h ^ (h >> 33)) & _M
    h = (h * 0xc4ceb9fe1a85ec53) & _M
    return (h ^ (h >> 33)) & _M


REGION_HASHES = [
    0x96409ff6aeb69064, 0xa388696d5e9ae1f2, 0xff5ca9dfb7509bdb, 0xb085f689913f3762,
    0x2f9c1db0846de64e, 0xeffc2b3669db8292, 0x1894463f0fbc0f9e, 0x81e4aa341307782b,
    0xb8609753fef8b18d, 0xe0d8367aaf202156, 0xf33f3e31c257dabd, 0x9e7a78f42b97b4d6,
    0xc4427b2aef260591, 0x0e9edca9cbba3552, 0xce31708176b158d1, 0xec3eca83966f9f99,
    0xf12a05c282f1caa2, 0x4bad433b483526ea, 0xfc1219e953fea0cb, 0xee0abcf320013087,
    0x7a397f728fbf9028, 0xc7152b1900fdea7e, 0xfcfa75d56995f8d9, 0xf2a35e0e90372a96,
    0x3e9df7003ff6f7f7, 0xa3acd9b547ac1c68, 0xe5e1111fd25d5a88, 0x426d3ebf9f854a23,
    0x29fb46f83399ebb4, 0xac1b5fd672fcb7ee, 0xfe81e97108117d59, 0x9fd85a088cfd699a,
]
_H2I = {h: i for i, h in enumerate(REGION_HASHES)}


_DAY = {'Monday':1,'Tuesday':2,'Wednesday':3,'Thursday':4,
        'Friday':5,'Saturday':6,'Sunday':7}


_STALL_KEY = 0xf07ec90c

def derive_final_master(k_t: int = 0) -> int:
    """
    FinalMaster = K_IDT ^ K_T ^ stall_key ^ ErrorKey ^ K_PROLOGUE
    With K_T=0 (fast native machine) this yields 0xf07ec6a4,
    which matches the 'expected Master Key' comment in the source.
    """
    return (0x0FFF ^ k_t ^ _STALL_KEY ^ 0x02 ^ 0x55) & 0xFFFFFFFF

def index_to_bits(idx: int) -> str:
    return ''.join('1' if idx & (1 << j) else '0' for j in range(4, -1, -1))


_LINE_RE = re.compile(
    r'^([A-Za-z]+),\s+(\d{1,2})/(\d{1,2})/(\d{4})\s+'
    r'(\d{1,2}):(\d{2}):(\d{2})\s+([AP]M)\s+(\w+)'
)

def decode_entry(weekday, day, month, year, hour, minute, second, tz, bits) -> bytes:
    if tz.upper() == 'GMT':
        b = (hour + minute - second) // 2
        hour, second, minute = hour - b, minute - b, b

    raw_h  = (hour   ^ 12) if bits[0] == '1' else hour
    raw_m  = (minute ^ 30) if bits[1] == '1' else minute
    raw_s  = (second ^ 30) if bits[2] == '1' else second
    raw_d  = (day    ^ 16) if bits[3] == '1' else day
    raw_mo = (month  ^  6) if bits[4] == '1' else month
    raw_y  = year - 1990

    n = ((raw_h << 27) | (raw_m << 21) | (raw_s << 15) |
         (raw_d << 10) | (raw_mo << 6) | raw_y) & 0xFFFFFFFF

    dv = _DAY.get(weekday, 1)
    return bytes([((n >> s) & 0xFF) ^ dv for s in (24, 16, 8, 0)])


def main():
    ap = argparse.ArgumentParser(description='CorpSyncAudit shellcode extractor')
    ap.add_argument('logfile', help='Path to the malicious .log file')
    ap.add_argument('--key', type=lambda x: int(x, 16), default=None,
                    help='Override FinalMaster (hex, e.g. 0xf07ec6a4). '
                         'Use if you captured it at runtime with a hardware breakpoint.')
    args = ap.parse_args()

    fm = args.key if args.key is not None else derive_final_master()
    print(f'[*] FinalMaster : 0x{fm:08x}')
    km = struct.pack('>I', fm)

    payload   = bytearray()
    n_entries = 0

    with open(args.logfile, errors='replace') as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.rstrip('\r\n')
            if 'Region=' not in line:
                continue

            region = line[line.find('Region=') + 7:].strip()
            idx    = _H2I.get(rxm64_hash(region.encode()))
            if idx is None:
                continue

            m = _LINE_RE.match(line)
            if not m:
                print(f'[!] Line {lineno}: parse failed - {line!r}')
                continue

            wd, d, mo, yr, hr, mn, sc, _, tz = m.groups()
            bits  = index_to_bits(idx)
            chunk = decode_entry(wd, int(d), int(mo), int(yr),
                                 int(hr), int(mn), int(sc), tz, bits)
            chunk = bytes(chunk[i] ^ km[i] for i in range(4))
            payload.extend(chunk)
            n_entries += 1

    print(f'[+] Entries decoded  : {n_entries}')
    print(f'[+] Shellcode size   : {len(payload)} bytes')

    if not payload:
        print('[!] No payload found - check you are using the malicious log file.')
        sys.exit(1)

    out = os.path.splitext(args.logfile)[0] + '.bin'
    with open(out, 'wb') as f:
        f.write(payload)
    print(f'[+] Written to       : {out}')

    strings, run = [], []
    for b in payload:
        if 0x20 <= b < 0x7f:
            run.append(chr(b))
        else:
            if len(run) >= 6:
                strings.append(''.join(run))
            run = []
    if len(run) >= 6:
        strings.append(''.join(run))

    if strings:
        print('\n[*] Embedded strings:')
        for s in strings:
            print(f'    {s!r}')
    else:
        print('\n[!] No readable strings found - FinalMaster may be wrong.')
        print('    Tip: capture it at runtime with a hardware breakpoint at the')
        print('    return of FUN_140001a5a (GenerateMultiKey) and pass it with --key.')

if __name__ == '__main__':
    main()
