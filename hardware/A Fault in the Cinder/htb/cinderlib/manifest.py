"""Parse + verify a 128-byte Cinder image manifest.

Shared by the firmware-image tests, the offline extractor (M3), and the solver — one
parser so nothing drifts. Verification covers magic/version/header-size, header CRC32,
payload bounds, payload SHA-256 digest, and the ECDSA-P256 vendor signature.
"""

import struct

from . import crypto
from .spec import SPEC

HDR = 128


def parse(blob):
    h = blob[:HDR]
    m = {
        "magic": h[0:4],
        "version": struct.unpack("<H", h[4:6])[0],
        "header_size": struct.unpack("<H", h[6:8])[0],
        "kind": struct.unpack("<I", h[8:12])[0],
        "payload_size": struct.unpack("<I", h[12:16])[0],
        "load": struct.unpack("<I", h[16:20])[0],
        "entry": struct.unpack("<I", h[20:24])[0],
        "counter": struct.unpack("<I", h[24:28])[0],
        "digest": h[28:60],
        "signature": h[60:124],
        "header_crc": struct.unpack("<I", h[124:128])[0],
        "payload": blob[HDR:HDR + struct.unpack("<I", h[12:16])[0]],
    }
    return m


def signed_fields(m):
    return (struct.pack("<H", m["version"]) + struct.pack("<I", m["kind"])
            + struct.pack("<I", m["payload_size"]) + struct.pack("<I", m["load"])
            + struct.pack("<I", m["entry"]) + struct.pack("<I", m["counter"]) + m["digest"])


def verify(blob, vendor_pub, slot_name=None):
    """Return (ok, reason). Same checks the boot ROM performs, in order."""
    m = parse(blob)
    if m["magic"] != SPEC["manifest"]["magic"].encode():
        return False, "magic"
    if m["version"] != SPEC["manifest"]["version"] or m["header_size"] != HDR:
        return False, "version/header_size"
    if crypto.crc32(blob[:124]) != m["header_crc"]:
        return False, "header_crc"
    if slot_name is not None:
        mx = SPEC["flash"]["slots"][slot_name]["max"]
        if not (0 < m["payload_size"] <= mx - HDR):
            return False, "payload bounds"
    if len(m["payload"]) != m["payload_size"]:
        return False, "payload truncated"
    if crypto.sha256(m["payload"]) != m["digest"]:
        return False, "payload digest"
    if not crypto.manifest_verify_pub(vendor_pub, signed_fields(m), m["signature"]):
        return False, "ecdsa signature"
    return True, "ok"
