#!/usr/bin/env python3
"""Automated solver for `what_the_shard_displayed` — RECONSTRUCTION ONLY.

Reconstructs the OLED framebuffer(s) from ``challenge/capture.sr`` and writes one
PNG per frame. The flag is read off the rendered flag frame. By design this
solver does **no OCR and no string recovery** (admin-confirmed): its job ends at
producing legible frame images. It contains no flag literal and never reads
``flag.txt``.

Pipeline:
  1. read the sigrok ``.sr`` (self-contained; no sigrok / libsigrokdecode),
  2. decode I2C from the SDA/SCL logic channels (auto-detecting which is which),
  3. keep only WRITES to the SSD1306 (OLED_ADDR),
  4. split each write's payload by its control byte: 0x00 -> command, 0x40 -> data,
  5. reassemble the display data across the small chunked writes,
  6. split into frames on each addressing-window reset (command 0x21),
  7. unpack each 1024-byte GDDRAM buffer (horizontal addressing, LSB = top) to a
     128x64 image and save it upscaled.

Usage:
    python3 htb/solve.py [path/to/capture.sr] [--outdir DIR] [--scale N]
Default capture: challenge/capture.sr   Default output: ./ (frame_0.png, ...).
"""

import argparse
import os
import re
import sys
import zipfile
import configparser

import numpy as np
from PIL import Image

OLED_ADDR = 0x3C          # SSD1306 — the pane that renders the flag (written)
# (EEPROM 0x50 and RTC 0x68 are decoys we deliberately ignore.)
CTRL_CMD = 0x00
CTRL_DATA = 0x40
CMD_SET_COLUMN = 0x21     # addressing-window reset => start of a new frame
OLED_W, OLED_H = 128, 64
FB_LEN = OLED_W * (OLED_H // 8)   # 1024

HERE = os.path.dirname(os.path.abspath(__file__))
CHALLENGE_ROOT = os.path.dirname(HERE)
DEFAULT_CAPTURE = os.path.join(CHALLENGE_ROOT, "challenge", "capture.sr")


def die(msg):
    sys.stderr.write("error: %s\n" % msg)
    sys.exit(1)


# --------------------------------------------------------------------------- #
# 1. Self-contained sigrok .sr reader                                         #
# --------------------------------------------------------------------------- #

def parse_samplerate(text):
    m = re.fullmatch(r"\s*([0-9.]+)\s*([kMG]?)(?:Hz)?\s*", text)
    if not m:
        die("could not parse samplerate %r" % text)
    mult = {"": 1.0, "k": 1e3, "M": 1e6, "G": 1e9}[m.group(2)]
    return float(m.group(1)) * mult


def load_sr(path):
    """Return (samplerate, unitsize, probes{idx:name}, logic uint8 array)."""
    if not os.path.isfile(path):
        die("capture not found: %s\n"
            "       This is the challenge's I2C capture (challenge/capture.sr).\n"
            "       Place it and re-run." % path)
    if not zipfile.is_zipfile(path):
        die("%s is not a well-formed sigrok .sr (expected a zip archive)" % path)

    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        if "metadata" not in names:
            die("%s is missing its 'metadata' member — not a valid .sr" % path)
        cfg = configparser.ConfigParser()
        cfg.optionxform = str
        cfg.read_string(zf.read("metadata").decode("utf-8", "replace"))
        dev = next((s for s in cfg.sections() if s.startswith("device")), None)
        if dev is None:
            die("capture metadata has no [device] section")
        dsec = cfg[dev]
        capturefile = dsec.get("capturefile", "logic-1")
        unitsize = int(dsec.get("unitsize", "1"))
        if "samplerate" not in dsec:
            die("capture metadata has no samplerate")
        samplerate = parse_samplerate(dsec["samplerate"])
        probes = {}
        for key, val in dsec.items():
            m = re.fullmatch(r"probe(\d+)", key)
            if m:
                probes[int(m.group(1)) - 1] = val
        chunk_re = re.compile(re.escape(capturefile) + r"-(\d+)$")
        chunks = sorted((n for n in names if chunk_re.match(n)),
                        key=lambda n: int(chunk_re.match(n).group(1)))
        if not chunks:
            die("no logic data chunks (%s-*) in %s" % (capturefile, path))
        raw = b"".join(zf.read(n) for n in chunks)

    if unitsize < 1:
        die("invalid unitsize %d" % unitsize)
    logic = np.frombuffer(raw, dtype=np.uint8)
    if logic.size % unitsize != 0:
        die("logic payload not a multiple of unitsize")
    return samplerate, unitsize, probes, logic


def channel_bits(logic, unitsize, channel):
    byte_idx, bit = channel // 8, channel % 8
    if byte_idx >= unitsize:
        die("channel %d out of range for unitsize %d" % (channel, unitsize))
    col = logic if unitsize == 1 else logic.reshape(-1, unitsize)[:, byte_idx]
    return ((col >> bit) & 1).astype(np.uint8)


# --------------------------------------------------------------------------- #
# 2. Self-contained I2C decoder                                               #
# --------------------------------------------------------------------------- #

def decode_i2c(sda, scl):
    """Decode I2C into a list of messages, one per START..(re)START/STOP segment.

    Each message is a list of byte values; message[0] is the address byte
    (7-bit address in the high bits, R/W# in bit 0). Data bits are sampled on
    SCL rising edges; START = SDA falls while SCL high, STOP = SDA rises while
    SCL high. The 9th clock per byte (ACK) is consumed and discarded.
    """
    sda = sda.astype(np.int8)
    scl = scl.astype(np.int8)

    scl_rise = np.flatnonzero(np.diff(scl) == 1) + 1
    sda_diff = np.diff(sda)
    sda_fall = np.flatnonzero(sda_diff == -1) + 1
    sda_rise = np.flatnonzero(sda_diff == 1) + 1
    starts = sda_fall[scl[sda_fall] == 1]
    stops = sda_rise[scl[sda_rise] == 1]

    # Merge events in sample order: 0=START, 1=STOP, 2=data bit.
    events = np.empty(starts.size + stops.size + scl_rise.size,
                      dtype=[("idx", np.int64), ("kind", np.int8), ("val", np.int8)])
    o = 0
    events["idx"][o:o + starts.size] = starts
    events["kind"][o:o + starts.size] = 0
    events["val"][o:o + starts.size] = 0
    o += starts.size
    events["idx"][o:o + stops.size] = stops
    events["kind"][o:o + stops.size] = 1
    events["val"][o:o + stops.size] = 0
    o += stops.size
    events["idx"][o:o + scl_rise.size] = scl_rise
    events["kind"][o:o + scl_rise.size] = 2
    events["val"][o:o + scl_rise.size] = sda[scl_rise]
    events.sort(order="idx", kind="stable")

    messages = []
    cur_bytes = []
    bitcount = 0
    acc = 0
    active = False
    for kind, val in zip(events["kind"], events["val"]):
        if kind == 0:                      # START / repeated START
            if active and cur_bytes:
                messages.append(cur_bytes)
            cur_bytes, bitcount, acc, active = [], 0, 0, True
        elif kind == 1:                    # STOP
            if active and cur_bytes:
                messages.append(cur_bytes)
            cur_bytes, bitcount, acc, active = [], 0, 0, False
        else:                              # data bit
            if not active:
                continue
            if bitcount < 8:
                acc = (acc << 1) | int(val)
                bitcount += 1
            else:                          # 9th clock = ACK; finalize the byte
                cur_bytes.append(acc)
                bitcount, acc = 0, 0
    if active and cur_bytes:
        messages.append(cur_bytes)
    return messages


def pick_channels(logic, unitsize, probes):
    """Return (sda_idx, scl_idx). Honours SHARD_SDA / SHARD_SCL, else tries every
    active-channel pairing/ordering and keeps the one that decodes the most OLED
    writes."""
    env_sda, env_scl = os.environ.get("SHARD_SDA"), os.environ.get("SHARD_SCL")
    if env_sda is not None and env_scl is not None:
        return int(env_sda), int(env_scl)

    candidates = sorted(probes) if probes else list(range(unitsize * 8))
    active = []
    for ch in candidates:
        b = channel_bits(logic, unitsize, ch)
        if np.any(np.diff(b.astype(np.int8)) != 0):   # has edges
            active.append(ch)
    if len(active) < 2:
        die("need two active logic channels (SDA + SCL); found %d" % len(active))

    write_addr = OLED_ADDR << 1
    best, best_score = None, -1
    for a in active:
        for b in active:
            if a == b:
                continue
            msgs = decode_i2c(channel_bits(logic, unitsize, a),
                              channel_bits(logic, unitsize, b))
            score = sum(1 for m in msgs if m and m[0] == write_addr)
            if score > best_score:
                best, best_score = (a, b), score
    if best_score <= 0:
        die("no writes to OLED_ADDR 0x%02X found on any channel pairing" % OLED_ADDR)
    return best


# --------------------------------------------------------------------------- #
# 3. Reconstruct frames                                                       #
# --------------------------------------------------------------------------- #

def reconstruct_frames(messages):
    """Turn OLED write messages into a list of GDDRAM byte buffers (one per frame)."""
    write_addr = OLED_ADDR << 1
    frames = []
    cur = bytearray()
    for msg in messages:
        if len(msg) < 2 or msg[0] != write_addr:
            continue                       # not an OLED write
        control, body = msg[1], msg[2:]
        if control == CTRL_DATA:
            cur.extend(body)               # pixel data — collect across chunks
        elif control == CTRL_CMD:
            if CMD_SET_COLUMN in body and cur:
                frames.append(bytes(cur))  # window reset delimits a finished frame
                cur = bytearray()
    if cur:
        frames.append(bytes(cur))
    return frames


def unpack_frame(buf):
    """1024-byte GDDRAM -> 64x128 bool image. pixel(x,y) = bit(y%8) of buf[(y//8)*128+x]."""
    data = np.frombuffer(bytes(buf[:FB_LEN]).ljust(FB_LEN, b"\x00"), dtype=np.uint8)
    pages = data.reshape(OLED_H // 8, OLED_W)                       # (page, x)
    bits = ((pages[:, :, None] >> np.arange(8)) & 1).astype(bool)   # (page, x, bit)
    return bits.transpose(0, 2, 1).reshape(OLED_H, OLED_W)          # (y, x)


def save_frame(bmp, path, scale):
    img = Image.fromarray((bmp * 255).astype(np.uint8), mode="L")
    if scale != 1:
        img = img.resize((OLED_W * scale, OLED_H * scale), Image.NEAREST)
    img.save(path)


# --------------------------------------------------------------------------- #
# main                                                                        #
# --------------------------------------------------------------------------- #

def main():
    ap = argparse.ArgumentParser(description="what_the_shard_displayed reconstruction solver")
    ap.add_argument("capture", nargs="?", default=DEFAULT_CAPTURE,
                    help="sigrok .sr capture (default: challenge/capture.sr)")
    ap.add_argument("--outdir", default=".", help="where to write frame PNGs")
    ap.add_argument("--scale", type=int, default=8, help="PNG upscale factor (default 8)")
    args = ap.parse_args()

    samplerate, unitsize, probes, logic = load_sr(args.capture)
    sda, scl = pick_channels(logic, unitsize, probes)
    messages = decode_i2c(channel_bits(logic, unitsize, sda),
                          channel_bits(logic, unitsize, scl))
    frames = reconstruct_frames(messages)

    print("=" * 68)
    print("what_the_shard_displayed — I2C framebuffer reconstruction")
    print("=" * 68)
    print("capture      : %s" % args.capture)
    print("samplerate   : %.0f Hz" % samplerate)
    print("SDA / SCL    : channel %s (%s) / %s (%s)"
          % (sda, probes.get(sda, "?"), scl, probes.get(scl, "?")))
    print("I2C messages : %d total" % len(messages))
    addrs = sorted({m[0] >> 1 for m in messages if m})
    print("addresses    : %s" % ", ".join("0x%02X" % a for a in addrs))
    print("OLED frames  : %d reconstructed" % len(frames))
    print("-" * 68)

    if not frames:
        die("no OLED frames reconstructed — check the capture / channel mapping")

    os.makedirs(args.outdir, exist_ok=True)
    for i, buf in enumerate(frames):
        note = "" if len(buf) == FB_LEN else "  (WARNING: %d bytes, expected %d)" % (len(buf), FB_LEN)
        bmp = unpack_frame(buf)
        out = os.path.join(args.outdir, "frame_%d.png" % i)
        save_frame(bmp, out, args.scale)
        print("frame %d: %d data bytes -> %s%s" % (i, len(buf), out, note))

    print("-" * 68)
    print("Open the frame PNGs; the flag is the one in HTB{...} form (not the sigil or the clock).")
    print("Sanity check: if the sigil (an eye) and the clock render cleanly, the page order and")
    print("bit order are right, so the flag frame from the same parser is trustworthy.")
    print("(Reconstruction only — this solver does not OCR or extract the flag string.)")


if __name__ == "__main__":
    main()
