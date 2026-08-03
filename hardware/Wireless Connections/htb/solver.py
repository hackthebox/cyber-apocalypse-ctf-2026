#!/usr/bin/env python3

import sys
from pathlib import Path


FIRMWARE_PATH = Path(__file__).resolve().parents[1] / "release" / "firmware.bin"
ENCRYPTED_FLAG_OFFSET = 0x2103B
ENCRYPTED_FLAG_LENGTH = 32

# Static Espressif OUI snapshot collected from the IEEE Registration Authority.
ESPRESSIF_OUIS = [
    "00:4B:12", "00:70:07", "04:83:08", "04:B2:47", "08:3A:8D", "08:3A:F2",
    "08:92:72", "08:A6:F7", "08:AD:0A", "08:B6:1F", "08:D1:F9", "08:F9:E0",
    "0C:4E:A0", "0C:8B:95", "0C:B8:15", "0C:DC:7E", "10:00:3B", "10:06:1C",
    "10:20:BA", "10:51:DB", "10:52:1C", "10:91:A8", "10:97:BD", "10:B4:1D",
    "10:BD:A3", "14:08:08", "14:2B:2F", "14:33:5C", "14:63:93", "14:C1:9F",
    "18:8B:0E", "18:FE:34", "1C:69:20", "1C:8F:57", "1C:9D:C2", "1C:C3:AB",
    "1C:DB:D4", "20:43:A8", "20:50:0D", "20:6E:F1", "20:9B:A9", "20:E7:C8",
    "24:0A:C4", "24:4C:AB", "24:58:7C", "24:62:AB", "24:6F:28", "24:A1:60",
    "24:B2:DE", "24:D7:EB", "24:DC:C3", "24:EC:4A", "28:05:A5", "28:37:2F",
    "28:56:2F", "28:84:85", "2C:3A:E8", "2C:BC:BB", "2C:F4:32", "30:30:F9",
    "30:76:F5", "30:83:98", "30:AE:A4", "30:C6:F7", "30:C9:22", "30:ED:A0",
    "34:5F:45", "34:85:18", "34:86:5D", "34:94:54", "34:98:7A", "34:AB:95",
    "34:B4:72", "34:B7:DA", "34:CD:B0", "38:18:2B", "38:44:BE", "3C:0F:02",
    "3C:61:05", "3C:71:BF", "3C:84:27", "3C:8A:1F", "3C:DC:75", "3C:E9:0E",
    "40:22:D8", "40:4C:CA", "40:91:51", "40:F5:20", "44:17:93", "44:1B:F6",
    "44:1D:64", "44:B1:76", "44:BD:8D", "48:27:E2", "48:31:B7", "48:3F:DA",
    "48:55:19", "48:9D:31", "48:CA:43", "48:E7:29", "48:F6:EE", "4C:11:AE",
    "4C:75:25", "4C:C3:82", "4C:EB:D6", "50:02:91", "50:78:7D", "54:32:04",
    "54:43:B2", "54:5A:A6", "58:2A:BD", "58:8C:81", "58:BF:25", "58:CF:79",
    "58:E6:C5", "5C:01:3B", "5C:CF:7F", "60:01:94", "60:55:F9", "64:B7:08",
    "64:E8:33", "68:09:47", "68:25:DD", "68:67:25", "68:B6:B3", "68:C6:3A",
    "68:EE:8F", "68:FE:71", "6C:B4:56", "6C:C8:40", "70:03:9F", "70:04:1D",
    "70:4B:CA", "70:AF:09", "70:B8:F6", "74:4D:BD", "78:1C:3C", "78:21:84",
    "78:42:1C", "78:E3:6D", "78:EE:4C", "7C:0C:5F", "7C:2C:67", "7C:4F:AD",
    "7C:73:98", "7C:87:CE", "7C:9E:BD", "7C:DF:A1", "7C:E8:B1", "80:45:6B",
    "80:64:6F", "80:65:99", "80:7D:3A", "80:B5:4E", "80:F1:B2", "80:F3:DA",
    "84:0D:8E", "84:1F:E8", "84:CC:A8", "84:F3:EB", "84:F7:03", "84:FC:E6",
    "88:13:BF", "88:56:A6", "88:57:21", "88:F1:55", "8C:4B:14", "8C:4F:00",
    "8C:8C:29", "8C:94:DF", "8C:AA:B5", "8C:BF:EA", "8C:CE:4E", "8C:FD:49",
    "90:15:06", "90:38:0C", "90:64:9B", "90:70:69", "90:97:D5", "90:DA:72",
    "90:E5:B1", "94:3C:C6", "94:51:DC", "94:54:C5", "94:A9:90", "94:B5:55",
    "94:B9:7E", "94:E6:86", "98:3D:AE", "98:88:E0", "98:A3:16", "98:CD:AC",
    "98:F4:AB", "9C:13:9E", "9C:9C:1F", "9C:9E:6E", "9C:CC:01", "A0:20:A6",
    "A0:76:4E", "A0:85:E3", "A0:A3:B3", "A0:B7:65", "A0:DD:6C", "A0:F2:62",
    "A4:7B:9D", "A4:CB:8F", "A4:CF:12", "A4:E5:7C", "A4:F0:0F", "A8:03:2A",
    "A8:42:E3", "A8:46:74", "A8:48:FA", "AC:0B:FB", "AC:15:18", "AC:27:6E",
    "AC:67:B2", "AC:A7:04", "AC:D0:74", "AC:EB:E6", "B0:3F:D3", "B0:81:84",
    "B0:A6:04", "B0:A7:32", "B0:B2:1C", "B0:CB:D8", "B4:3A:45", "B4:8A:0A",
    "B4:BF:E9", "B4:E6:2D", "B8:1F:3F", "B8:7B:4D", "B8:D6:1A", "B8:F0:09",
    "B8:F8:62", "BC:DD:C2", "BC:FF:4D", "C0:49:EF", "C0:4E:30", "C0:5D:89",
    "C0:CD:D6", "C4:4F:33", "C4:5B:BE", "C4:D8:D5", "C4:DD:57", "C4:DE:E2",
    "C8:2B:96", "C8:2E:18", "C8:85:41", "C8:C9:A3", "C8:F0:9E", "CC:50:E3",
    "CC:7B:5C", "CC:8D:A2", "CC:BA:97", "CC:DB:A7", "D0:CF:13", "D0:EF:76",
    "D4:05:92", "D4:8A:FC", "D4:8C:49", "D4:D4:DA", "D4:E9:F4", "D4:F9:8D",
    "D8:13:2A", "D8:3B:DA", "D8:85:AC", "D8:A0:1D", "D8:BC:38", "D8:BF:C0",
    "D8:F1:5B", "DC:06:75", "DC:1E:D5", "DC:4F:22", "DC:54:75", "DC:B4:D9",
    "DC:DA:0C", "E0:5A:1B", "E0:72:A1", "E0:8C:FE", "E0:98:06", "E0:E2:E6",
    "E4:65:B8", "E4:B0:63", "E4:B3:23", "E8:06:90", "E8:31:CD", "E8:3D:C1",
    "E8:68:E7", "E8:6B:EA", "E8:9F:6D", "E8:DB:84", "E8:F6:0A", "EC:62:60",
    "EC:64:C9", "EC:94:CB", "EC:C9:FF", "EC:DA:3B", "EC:E3:34", "EC:FA:BC",
    "F0:08:D1", "F0:16:1D", "F0:24:F9", "F0:9E:9E", "F0:F5:BD", "F4:12:FA",
    "F4:2D:C9", "F4:65:0B", "F4:CF:A2", "F8:5B:1B", "F8:B3:B7", "FC:01:2C",
    "FC:B4:67", "FC:E8:C0", "FC:F5:C4",
]

SEED_MULTIPLIER = 0x01000193
LCG_MULTIPLIER = 1664525
LCG_INCREMENT = 1013904223
U32 = 0xFFFFFFFF

FLAG_PREFIX = b"HTB{"


def load_candidate_ouis() -> list[int]:
    return sorted({int(value.replace(":", ""), 16) for value in ESPRESSIF_OUIS})


def candidate_flag(plaintext: bytes) -> str | None:
    shown = plaintext.rstrip(b"\x00")
    if not (shown.startswith(FLAG_PREFIX) and shown.endswith(b"}")):
        return None
    if any(c < 0x20 or c > 0x7E for c in shown):
        return None
    return shown.decode("ascii")


def try_oui(ciphertext: bytes, oui: int) -> tuple[int, int, str] | None:
    seed = (oui * SEED_MULTIPLIER) & U32
    state = seed
    plaintext = bytearray()

    for i, b in enumerate(ciphertext):
        state = (state * LCG_MULTIPLIER + LCG_INCREMENT) & U32
        p = b ^ ((state >> 16) & 0xFF)

        if i < len(FLAG_PREFIX) and p != FLAG_PREFIX[i]:
            return None

        plaintext.append(p)

    flag = candidate_flag(bytes(plaintext))
    if flag is None:
        return None
    return oui, seed, flag


def try_ouis(ciphertext: bytes, ouis) -> tuple[int, int, str] | None:
    for oui in ouis:
        result = try_oui(ciphertext, oui)
        if result:
            return result
    return None


def main() -> int:
    firmware = Path(FIRMWARE_PATH).read_bytes()
    ciphertext = firmware[
        ENCRYPTED_FLAG_OFFSET : ENCRYPTED_FLAG_OFFSET + ENCRYPTED_FLAG_LENGTH
    ]
    if len(ciphertext) != ENCRYPTED_FLAG_LENGTH:
        print("[!] Could not read encrypted flag bytes", file=sys.stderr)
        return 1

    ouis = load_candidate_ouis()
    print(f"[*] Loaded {len(ouis)} embedded Espressif OUI candidates")
    if ouis:
        result = try_ouis(ciphertext, ouis)
        if result:
            oui, seed, flag = result
            print(f"[+] OUI  : 0x{oui:06x}")
            print(f"[+] Seed : 0x{seed:08x}")
            print(f"[+] Flag : {flag}")
            return 0

    print("[!] Flag not found in embedded OUI candidates", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
