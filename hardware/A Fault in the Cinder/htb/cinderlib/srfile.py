"""Minimal sigrok v2 .sr reader/writer (zip: version + metadata + logic chunks).

Used to emit the reference factory_spi.sr from capturegen and to read it back in the
offline extractor. The delivered factory_spi.sr is the real electrical capture; the
reference produced here is byte-pattern-equivalent for building/testing the extractor.
"""

import io
import re
import zipfile

import numpy as np


def write_sr(path, channel_names, samples, samplerate_hz):
    """samples: 1D uint8 array, bit i = channel i (probe i+1)."""
    meta = ["[global]", "sigrok version=0.5.2", "", "[device 1]", "capturefile=logic-1",
            "total probes=%d" % len(channel_names)]
    if samplerate_hz % 1_000_000 == 0:
        meta.append("samplerate=%d MHz" % (samplerate_hz // 1_000_000))
    else:
        meta.append("samplerate=%d Hz" % samplerate_hz)
    for i, name in enumerate(channel_names):
        meta.append("probe%d=%s" % (i + 1, name))
    meta.append("unitsize=1")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("version", "2")
        zf.writestr("metadata", "\n".join(meta) + "\n")
        zf.writestr("logic-1-1", np.asarray(samples, dtype=np.uint8).tobytes())


def read_sr(path):
    """Return (samplerate_hz, channel_names, logic uint8 array)."""
    with zipfile.ZipFile(path) as zf:
        text = zf.read("metadata").decode()
        probes = {}
        capturefile = "logic"
        samplerate = None
        for line in text.splitlines():
            m = re.match(r"probe(\d+)=(.+)", line)
            if m:
                probes[int(m.group(1)) - 1] = m.group(2).strip()
            m = re.match(r"capturefile=(.+)", line)
            if m:
                capturefile = m.group(1).strip()
            m = re.match(r"samplerate=([0-9.]+)\s*([kMG]?)Hz?", line)
            if m:
                mult = {"": 1, "k": 1e3, "M": 1e6, "G": 1e9}[m.group(2)]
                samplerate = int(float(m.group(1)) * mult)
        names = [probes[i] for i in sorted(probes)]
        chunk_re = re.compile(re.escape(capturefile) + r"-(\d+)$")
        chunks = sorted((n for n in zf.namelist() if chunk_re.match(n)),
                        key=lambda n: int(chunk_re.match(n).group(1)))
        raw = b"".join(zf.read(n) for n in chunks)
    return samplerate, names, np.frombuffer(raw, dtype=np.uint8)
