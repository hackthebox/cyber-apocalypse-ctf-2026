#!/usr/bin/env python3
"""Official solver for a_fault_in_the_cinder.

Runs the full six-stage chain, using ONLY the release artifacts + the remote ports:

  1. reconstruct production.bin + recovery.bin from factory_spi.sr, verify manifests;
  2/3. recompute the recovery BOOT_PCR from the recovered recovery manifest;
  4/5. failed-recovery baseline -> AUTH_DENIED trigger -> disassembly-derived single
       instruction-skip fault, over the rig / logic-analyzer ports;
  6. decode the live unseal (locate K_factory in the recovered recovery firmware,
     derive K_session, verify + unwrap the fragments) and print the runtime flag.

Reads no server source, no flag file, no internal API. The two reviewed public
constants (vendor key, branch delay) are obtained from cinder_boot.elf / TARGET.pdf.

Usage:  python3 solve.py <host> [factory_spi.sr]
Deps:   pip install -r requirements.txt   (numpy; everything else is bundled/stdlib)
"""

import os
import socket
import struct
import sys
import time

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from cinderlib import crypto, manifest, p256, srfile, vcd
from cinderlib.spec import SPEC, OPC

# --- reviewed public constants ----------------------------------
# Vendor ECDSA-P256 public key, embedded in cinder_boot.elf / published in TARGET.pdf.
VENDOR_PUB = (
    0x3e9a96c0795f6968eedeab5ac0cf7a68556c8f5280e4ae8de5ca01b58c7719d5,
    0x2cd1fa8428c8e1ad5e833072846a8b00e8f4cd6d6f3eee5ec6f1d2d6cd73a673,
)
# The Black Heir's public custody seal — the Vaultrune registry's known verification key
# for Cassian's hand. The recovered writ carries a detached ECDSA-P256 signature under the
# matching private seal, so recovering the record proves authorship (non-repudiable), not
# merely possession. Verified below to demonstrate the proof is real.
CASSIAN_SEAL_PUB = (
    0x0076e7268472456f1f481d95b3ba80375e40aaf94659879b5c54446930a41fc3,
    0x5069a38de69e10f208b4b3f441c6509df65f04df998b0231715cb14b19194a8b,
)
# ~247 CPU cycles (~10.3 us @ 24 MHz) from the AUTH_DENIED CS_SE rise to the beq.n:
# crc16 over the 5-byte denied frame + the fixed return path + the pre-launch sanity
# gauntlet + the inlined authorization fold.
BRANCH_DELAY_TICKS = 247
GLITCH_WIDTH = 10


# --- SE frame helpers --------------------------------------------------------

def build_frame(op, seq, status, payload=b""):
    body = struct.pack("<BBBH", op, seq, status, len(payload)) + payload
    return body + struct.pack("<H", crypto.crc16(body))


def parse_frame(data):
    opcode, seq, status, plen = struct.unpack("<BBBH", data[:5])
    payload = data[5:5 + plen]
    crc = struct.unpack("<H", data[5 + plen:7 + plen])[0]
    if crypto.crc16(data[:5 + plen]) != crc:
        raise ValueError("crc16 mismatch")
    return opcode, seq, status, payload


# ============================================================================
# Stage 1: reconstruct both firmware images from factory_spi.sr
# ============================================================================

def _flash_transactions(names, logic):
    idx = {n: i for i, n in enumerate(names)}
    cs = (logic >> idx["CS_FLASH"]) & 1
    sck = (logic >> idx["SCK"]) & 1
    mosi = (logic >> idx["MOSI"]) & 1
    miso = (logic >> idx["MISO"]) & 1
    txns, cur, prev_sck = [], None, 0
    for i in range(len(logic)):
        if cs[i] == 0 and cur is None:
            cur = []
        if cur is not None and prev_sck == 0 and sck[i] == 1:
            cur.append((mosi[i], miso[i]))
        if cs[i] == 1 and cur is not None:
            txns.append(cur)
            cur = None
        prev_sck = sck[i]
    if cur:
        txns.append(cur)
    return txns


def _bits_to_bytes(bits):
    mo, mi = [], []
    for k in range(0, len(bits) - len(bits) % 8, 8):
        bm = bs = 0
        for j in range(8):
            bm = (bm << 1) | int(bits[k + j][0])
            bs = (bs << 1) | int(bits[k + j][1])
        mo.append(bm)
        mi.append(bs)
    return bytes(mo), bytes(mi)


def reconstruct_images(sr_path):
    _rate, names, logic = srfile.read_sr(sr_path)
    region = {}
    for txn in _flash_transactions(names, logic):
        mosi, miso = _bits_to_bytes(txn)
        if len(mosi) < 4 or mosi[0] != 0x03:
            continue
        addr = (mosi[1] << 16) | (mosi[2] << 8) | mosi[3]
        for off, b in enumerate(miso[4:]):
            region[addr + off] = b

    images = {}
    for name in ("production", "recovery"):
        base = SPEC["flash"]["slots"][name]["base"]
        hdr = bytes(region.get(base + i, 0xFF) for i in range(128))
        psize = int.from_bytes(hdr[12:16], "little")
        blob = bytes(region.get(base + i, 0xFF) for i in range(128 + psize))
        ok, reason = manifest.verify(blob, VENDOR_PUB, name)
        images[name] = {"blob": blob, "verified": ok, "reason": reason,
                        "counter": manifest.parse(blob)["counter"]}
    return images


# ============================================================================
# Stages 4/5: remote fault via the rig
# ============================================================================

class Rig:
    def __init__(self, host, ports):
        self.host = host
        self.ports = ports

    def _conn(self, port):
        s = socket.create_connection((self.host, port), timeout=10)
        s.recv(4096)  # banner
        return s

    def _lines(self, sock):
        time.sleep(0.05)
        data = b""
        sock.settimeout(0.5)
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        return [l for l in data.decode("ascii", "replace").split("\n") if l]

    def _cmd(self, sock, line):
        sock.sendall((line + "\n").encode())
        return self._lines(sock)

    def _boot(self, ctrl):
        for _ in range(200):
            lines = self._cmd(ctrl, "POWER CYCLE")
            if any(l.startswith("BUSY") for l in lines):
                time.sleep(0.3)
                continue
            out = {}
            for l in lines:
                if l.startswith("BOOT "):
                    out["boot_id"] = int(l.split()[1])
                elif l.startswith("CAPTURE cap-"):
                    out["capture_id"] = int(l.split("cap-")[1])
            return out
        raise SystemExit("paced out")

    def _download(self, capture_id):
        la = self._conn(self.ports["capture"])
        la.sendall(("GET cap-%d VCD.GZ\n" % capture_id).encode())
        header = b""
        while b"\n" not in header:
            header += la.recv(1)
        n = int(header.decode().split()[1])
        blob = b""
        while len(blob) < n:
            blob += la.recv(65536)
        la.close()
        _b, _c, text = vcd.read_envelope(blob[:n])
        return text

    def baseline_and_fault(self):
        ctrl = self._conn(self.ports["control"])
        self._cmd(ctrl, "STRAP RECOVERY")
        self._cmd(ctrl, "RESET RIG")
        self._cmd(ctrl, "CAPTURE ARM INTERNAL_SPI")
        base = self._boot(ctrl)
        pattern, mask = _derive_trigger(self._download(base["capture_id"]))

        self._cmd(ctrl, "STRAP RECOVERY")
        self._cmd(ctrl, "TRIGGER BUS SE PATTERN %s MASK %s EDGE CS_RISE" % (pattern.hex(), mask.hex()))
        self._cmd(ctrl, "GLITCH DELAY %d WIDTH %d" % (BRANCH_DELAY_TICKS, GLITCH_WIDTH))
        for _ in range(6):
            self._cmd(ctrl, "CAPTURE ARM INTERNAL_SPI")
            r = self._boot(ctrl)
            v = self._download(r["capture_id"])
            if any(f[0] == OPC["OPEN_FACTORY_SESSION"] for f in decode_session(v)):
                ctrl.close()
                return v
        ctrl.close()
        raise SystemExit("fault did not reach recovery")


# ============================================================================
# Stage 6: decode the live secure-element session
# ============================================================================

def _se_transactions(vcd_text):
    prev = {}
    cur_bits, in_cs, out = [], False, []
    for tick, v in vcd.parse_vcd(vcd_text):
        cs = v.get("CS_SE", 1)
        sck = v.get("SCK", 0)
        if prev.get("CS_SE", 1) == 1 and cs == 0:
            in_cs, cur_bits = True, []
        if in_cs and prev.get("SCK", 0) == 0 and sck == 1:
            cur_bits.append((v.get("MOSI", 1), v.get("MISO", 1)))
        if prev.get("CS_SE", 1) == 0 and cs == 1 and in_cs:
            in_cs = False
            out.append(_bits_to_bytes(cur_bits))
        prev = v
    return out


def _strip_idle(data):
    i = 0
    while i < len(data) and data[i] == 0xFF:
        i += 1
    return data[i:]


def decode_session(vcd_text):
    out = []
    for mosi, miso in _se_transactions(vcd_text):
        try:
            rq = parse_frame(mosi)
            rs = parse_frame(_strip_idle(miso))
        except Exception:
            continue
        out.append((rq[0], rq[1], rs[2], rq[3], rs[3]))
    return out


def _derive_trigger(baseline_vcd):
    for opcode, seq, status, _rq, _rs in decode_session(baseline_vcd):
        if opcode == OPC["VERIFY_RECOVERY_TICKET"] and status == SPEC["se"]["status"]["AUTH_DENIED"]:
            frame = build_frame(opcode, seq, status, b"")
            mask = bytes([0xFF, 0x00, 0xFF]) + b"\x00" * (len(frame) - 3)
            return frame, mask
    raise SystemExit("no AUTH_DENIED in baseline capture")


def _find_k_factory(recovery_payload, host_nonce, element_nonce, boot_pcr, fragment):
    session_id, seq, ct, tag = fragment
    header = struct.pack("<IB", session_id, seq)
    for off in range(0, len(recovery_payload) - 32 + 1):
        cand = recovery_payload[off:off + 32]
        ks = crypto.derive_session_key(cand, host_nonce, element_nonce, boot_pcr)
        if crypto.hmac256(ks, header + ct)[:16] == tag:
            return cand
    raise SystemExit("K_factory not found in recovery firmware")


def reconstruct_record(vcd_text, recovery_payload, boot_pcr):
    host_nonce = element_nonce = None
    session_id = None
    fragments = {}
    for opcode, seq, status, req, resp in decode_session(vcd_text):
        if opcode == OPC["OPEN_FACTORY_SESSION"] and status == 0:
            host_nonce = req[:16]
            session_id = struct.unpack("<I", resp[:4])[0]
            element_nonce = resp[4:20]
        elif opcode == OPC["READ_FIFO"] and status == 0 and len(resp) >= 10:
            sid, idx, cnt, clen = struct.unpack("<IHHH", resp[:10])
            ct = resp[10:10 + clen]
            tag = resp[10 + clen:26 + clen]
            fragments[idx] = (sid, idx & 0xFF, ct, tag)
    if host_nonce is None or not fragments:
        raise SystemExit("no session/fragments in capture")
    first = fragments[min(fragments)]
    k_factory = _find_k_factory(recovery_payload, host_nonce, element_nonce, boot_pcr, first)
    k_session = crypto.derive_session_key(k_factory, host_nonce, element_nonce, boot_pcr)
    record = b""
    for idx in sorted(fragments):
        sid, seq, ct, tag = fragments[idx]
        record += crypto.unprotect(k_session, sid, seq, ct, tag)
    fields = {}
    i = 0
    while i + 3 <= len(record):
        tag, ln = struct.unpack("<BH", record[i:i + 3])
        i += 3
        fields[tag] = record[i:i + ln]
        i += ln
    return fields


def solve(host, factory_spi_path, ports=None):
    ports = ports or SPEC["ports"]
    images = reconstruct_images(factory_spi_path)
    for name in ("production", "recovery"):
        if not images[name]["verified"]:
            raise SystemExit("%s manifest failed: %s" % (name, images[name]["reason"]))
    recovery_blob = images["recovery"]["blob"]
    m = manifest.parse(recovery_blob)
    mm = crypto.boot_measurement_M(m["kind"], m["counter"], m["payload_size"], m["digest"])
    boot_pcr = crypto.pcr_extend(crypto.ZERO_PCR, mm)

    rig = Rig(host, {"control": ports["control"], "capture": ports["capture"], "service": ports["service"]})
    success_vcd = rig.baseline_and_fault()
    fields = reconstruct_record(success_vcd, recovery_blob[128:], boot_pcr)
    # TLV tags: 7 = writ (evidence), 8 = flag, 10 = detached writ signature.
    # Verify the writ under the Black Heir's public seal — proves authorship, not just recovery.
    writ, writ_sig = fields.get(7, b""), fields.get(10, b"")
    writ_verified = bool(writ_sig) and p256.verify(CASSIAN_SEAL_PUB, writ, writ_sig)
    return {"flag": fields.get(8, b"").decode("ascii", "replace"),
            "prod_counter": images["production"]["counter"],
            "rec_counter": images["recovery"]["counter"],
            "writ_verified": writ_verified}


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    factory_spi = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "factory_spi.sr")
    r = solve(host, factory_spi)
    print("production counter : %d" % r["prod_counter"])
    print("recovery counter   : %d" % r["rec_counter"])
    print("writ seal (Cassian): %s" % ("VERIFIED" if r["writ_verified"] else "UNVERIFIED"))
    print("FLAG               : %s" % r["flag"])
    return r["flag"]


if __name__ == "__main__":
    main()
