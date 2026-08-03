"""Crypto + framing primitives used by the solver.

Verification/decode subset of the service's crypto module: SHA-256, HMAC-SHA256,
CRC16-CCITT-FALSE, CRC32, the boot measurement, the factory session derivation, the
fragment unwrap, and ECDSA-P256 signature verification (public key only). The signing
and key-derivation functions live server-side and are not needed to solve.
"""

import hashlib
import hmac
import struct
import zlib

from . import p256
from .spec import SPEC


# --- hashes / macs -----------------------------------------------------------

def sha256(data):
    return hashlib.sha256(data).digest()


def hmac256(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


def crc32(data):
    return zlib.crc32(data) & 0xFFFFFFFF


# --- CRC16-CCITT-FALSE (poly 0x1021, init 0xFFFF, no reflect) -----------------

def crc16(data):
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF
    return crc & 0xFFFF


# --- boot measurement --------------------------------------------

def boot_measurement_M(slot_kind, security_counter, payload_size, payload_sha256):
    label = SPEC["labels"]["boot"].encode()
    return sha256(
        label
        + struct.pack("<B", slot_kind)
        + struct.pack("<I", security_counter)
        + struct.pack("<I", payload_size)
        + payload_sha256
    )


def pcr_extend(pcr, m):
    return sha256(pcr + m)


ZERO_PCR = b"\x00" * 32


# --- factory session --------------------------------------------

def derive_session_key(k_factory, host_nonce, element_nonce, boot_pcr):
    label = SPEC["labels"]["session"].encode()
    return hmac256(k_factory, label + host_nonce + element_nonce + boot_pcr)


def response_stream_block(k_session, session_id, sequence, block_index):
    label = SPEC["labels"]["response"].encode()
    return hmac256(
        k_session,
        label + struct.pack("<I", session_id) + struct.pack("<B", sequence) + struct.pack("<I", block_index),
    )


def unprotect(k_session, session_id, sequence, ciphertext, tag):
    header = struct.pack("<IB", session_id, sequence)
    expect = hmac256(k_session, header + ciphertext)[:16]
    if not hmac.compare_digest(expect, tag):
        raise ValueError("fragment tag mismatch")
    out = bytearray()
    idx = 0
    while len(out) < len(ciphertext):
        out += response_stream_block(k_session, session_id, sequence, idx)
        idx += 1
    return bytes(a ^ b for a, b in zip(ciphertext, out[: len(ciphertext)]))


# --- ECDSA-P256 verification (public key only) ------------------

def manifest_verify_pub(pub, signed_fields, signature):
    return p256.verify(pub, signed_fields, signature)
