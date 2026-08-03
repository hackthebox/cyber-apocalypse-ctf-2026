"""VCD export + download envelope.

VCD carries raw wires and tick timestamps only — no decoded command names, PC
annotations, or labels. Envelope matches the CINDCAP1 header rig.py expects.
"""

import gzip
import hashlib
import struct

from .spec import CHANNELS, SPEC

_IDS = "!\"#$%&'()*+,-./0123456789"  # one printable id per channel


def to_vcd(initial, events):
    ids = {name: _IDS[i] for i, name in enumerate(CHANNELS)}
    out = []
    out.append("$comment tick_hz=%d $end" % SPEC["recorder"]["tick_hz"])
    out.append("$timescale 1 ns $end")
    out.append("$scope module cinder $end")
    for name in CHANNELS:
        out.append("$var wire 1 %s %s $end" % (ids[name], name))
    out.append("$upscope $end")
    out.append("$enddefinitions $end")
    out.append("#0")
    out.append("$dumpvars")
    for name in CHANNELS:
        out.append("%d%s" % (initial[name], ids[name]))
    out.append("$end")
    tick = 0
    idx = {name: i for i, name in enumerate(CHANNELS)}
    for delta, changed, newval in events:
        tick += delta
        out.append("#%d" % tick)
        for name in CHANNELS:
            bit = 1 << idx[name]
            if changed & bit:
                out.append("%d%s" % (1 if (newval & bit) else 0, ids[name]))
    return "\n".join(out) + "\n"


def make_envelope(boot_id, capture_id, vcd_text):
    raw = vcd_text.encode()
    comp = gzip.compress(raw)
    header = struct.pack(
        "<8sIIBBHII32s",
        SPEC["capture"]["magic"].encode(),
        boot_id, capture_id,
        SPEC["capture"]["format_gzip_vcd"], 0, 0,
        len(comp), len(raw),
        hashlib.sha256(comp).digest(),
    )
    return header + comp


_HDR = struct.calcsize("<8sIIBBHII32s")  # 60 bytes


def read_envelope(blob):
    magic, boot_id, capture_id, fmt, flags, _rsv, csize, usize, digest = struct.unpack(
        "<8sIIBBHII32s", blob[:_HDR])
    if magic != SPEC["capture"]["magic"].encode():
        raise ValueError("bad capture magic")
    comp = blob[_HDR:_HDR + csize]
    if hashlib.sha256(comp).digest() != digest:
        raise ValueError("capture digest mismatch")
    raw = gzip.decompress(comp)
    if len(raw) != usize:
        raise ValueError("size mismatch")
    return boot_id, capture_id, raw.decode()


def parse_vcd(text):
    """Yield (tick, {channel: value}) snapshots at each timestamp with changes."""
    id_to_name = {}
    values = {}
    lines = text.splitlines()
    it = iter(lines)
    for line in it:
        if line.startswith("$var"):
            parts = line.split()
            ident, name = parts[3], parts[4]
            id_to_name[ident] = name
            values[name] = 0
        elif line.startswith("$enddefinitions"):
            break
    tick = 0
    snapshots = []
    pending = False
    for line in it:
        line = line.strip()
        if not line or line in ("$dumpvars", "$end"):
            continue
        if line.startswith("#"):
            if pending:
                snapshots.append((tick, dict(values)))
            tick = int(line[1:])
            pending = True
        elif line[0] in "01" and len(line) >= 2:
            val = int(line[0])
            ident = line[1:]
            if ident in id_to_name:
                values[id_to_name[ident]] = val
    if pending:
        snapshots.append((tick, dict(values)))
    return snapshots
