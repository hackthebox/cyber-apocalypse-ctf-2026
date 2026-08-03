#!/usr/bin/env python3
"""Automated solver for `cadence_in_the_cord`.

Recovers the hidden message from ``challenge/capture.sr`` ALONE. The visible
UART bytes are a decoy that, in character, documents the trick; the real payload
rides in the DURATIONS of the silences between bytes:

    short inter-byte gap -> bit 0        long inter-byte gap -> bit 1
    8 gaps per character, MSB-first, ASCII

The script derives everything from the capture's timing. It never reads
``flag.txt`` and contains no flag literal. Pipeline:

    1. read the sigrok ``.sr`` (self-contained; no sigrok / libsigrokdecode),
    2. decode the UART line (9600 8N1) to per-byte start-edge sample indices,
    3. measure every inter-byte gap (idle-high time between frames),
    4. DERIVE the short/long and idle thresholds from the data (no hardcoded ms),
    5. split repeats on the long idle and majority-vote the bits across them,
    6. rebuild the ASCII stream, print it, and identify the HTB{...} flag.

Usage:
    python3 htb/solve.py [path/to/capture.sr]

With no argument it looks for ``challenge/capture.sr`` next to this challenge.
Optional environment overrides (rarely needed):
    CADENCE_CHANNEL=<int>   force the logic channel carrying the UART line
    CADENCE_BAUD=<int>      override the 9600 baud assumption
"""

import os
import re
import sys
import zipfile
import configparser

import numpy as np

# UART framing is standard, stated protocol config for this challenge — not the
# secret. The secret is the *timing*, which is derived below, never assumed.
BAUD = int(os.environ.get("CADENCE_BAUD", "9600"))
DATA_BITS = 8
FRAME_BITS = 1 + DATA_BITS + 1          # start + data + stop = 10 bit periods
CHARS_EXPECTED = 74                      # preamble(25) + ' ' + flag(48)
GAPS_PER_CHAR = 8

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
    """Parse '4 MHz' / '4000000' / '500 kHz' -> float Hz."""
    m = re.fullmatch(r"\s*([0-9.]+)\s*([kMG]?)(?:Hz)?\s*", text)
    if not m:
        die("could not parse samplerate %r from capture metadata" % text)
    mult = {"": 1.0, "k": 1e3, "M": 1e6, "G": 1e9}[m.group(2)]
    return float(m.group(1)) * mult


def load_sr(path):
    """Return (samplerate_hz, unitsize, probes{idx:name}, logic uint8 array)."""
    if not os.path.isfile(path):
        die("capture not found: %s\n"
            "       This is the challenge's UART capture (challenge/capture.sr).\n"
            "       Place it and re-run." % path)
    if not zipfile.is_zipfile(path):
        die("%s is not a well-formed sigrok .sr (expected a zip archive)" % path)

    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        if "metadata" not in names:
            die("%s is missing its 'metadata' member — not a valid .sr" % path)

        cfg = configparser.ConfigParser()
        cfg.optionxform = str  # preserve key case (probe names, etc.)
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
                probes[int(m.group(1)) - 1] = val  # probe1 -> channel index 0

        # Logic payload is split across '<capturefile>-<n>' members, in order.
        chunk_re = re.compile(re.escape(capturefile) + r"-(\d+)$")
        chunks = sorted(
            (n for n in names if chunk_re.match(n)),
            key=lambda n: int(chunk_re.match(n).group(1)),
        )
        if not chunks:
            die("no logic data chunks (%s-*) found in %s" % (capturefile, path))
        raw = b"".join(zf.read(n) for n in chunks)

    if unitsize < 1:
        die("invalid unitsize %d in capture metadata" % unitsize)
    logic = np.frombuffer(raw, dtype=np.uint8)
    if logic.size % unitsize != 0:
        die("logic payload (%d bytes) not a multiple of unitsize %d"
            % (logic.size, unitsize))
    return samplerate, unitsize, probes, logic


def channel_bits(logic, unitsize, channel):
    """Extract one logic channel as a uint8 array of 0/1 samples."""
    byte_idx, bit = channel // 8, channel % 8
    if byte_idx >= unitsize:
        die("channel %d out of range for unitsize %d" % (channel, unitsize))
    col = logic if unitsize == 1 else logic.reshape(-1, unitsize)[:, byte_idx]
    return ((col >> bit) & 1).astype(np.uint8)


# --------------------------------------------------------------------------- #
# 2. UART decode                                                              #
# --------------------------------------------------------------------------- #

def decode_uart(bits, samplerate, baud):
    """Decode idle-high UART (LSB-first, 8N1).

    Returns (values, starts): the decoded byte values and the sample index of
    each byte's start-bit falling edge. Bytes that fail start/stop framing
    checks are skipped and the decoder resyncs on the next edge.
    """
    spb = samplerate / baud
    n = bits.size
    if n == 0:
        return [], []

    delta = np.diff(bits.astype(np.int8))
    falling = np.flatnonzero(delta == -1) + 1  # samples where line goes 1 -> 0
    if falling.size == 0:
        return [], []

    frame_len = int(round(FRAME_BITS * spb))
    values, starts = [], []
    cursor = int(falling[0])
    while True:
        # Sample bit centres: start@0.5, data d0..d7 @1.5..8.5, stop@9.5 (bit units).
        start_lvl = cursor + int(round(0.5 * spb))
        stop_lvl = cursor + int(round((FRAME_BITS - 0.5) * spb))
        ok = start_lvl < n and stop_lvl < n
        ok = ok and bits[start_lvl] == 0 and bits[stop_lvl] == 1

        value = 0
        if ok:
            for k in range(DATA_BITS):
                si = cursor + int(round((1.5 + k) * spb))
                if bits[si]:
                    value |= 1 << k
            values.append(value)
            starts.append(cursor)
            advance_to = cursor + frame_len          # skip this frame, find next start
        else:
            advance_to = cursor + 1                   # bad framing: resync on next edge

        j = np.searchsorted(falling, advance_to, side="left")
        if j >= falling.size:
            break
        cursor = int(falling[j])

    return values, starts


def select_channel(logic, unitsize, probes, samplerate, baud):
    """Pick the logic channel carrying the UART line.

    Honours CADENCE_CHANNEL; otherwise chooses the channel that decodes the most
    valid UART bytes (robust when the line isn't on D0 or extra channels exist).
    """
    override = os.environ.get("CADENCE_CHANNEL")
    if override is not None:
        return int(override)

    candidates = sorted(probes) if probes else list(range(unitsize * 8))
    if len(candidates) == 1:
        return candidates[0]

    best, best_count = candidates[0], -1
    for ch in candidates:
        vals, _ = decode_uart(channel_bits(logic, unitsize, ch), samplerate, baud)
        if len(vals) > best_count:
            best, best_count = ch, len(vals)
    return best


# --------------------------------------------------------------------------- #
# 3. Timing -> bits -> message                                                #
# --------------------------------------------------------------------------- #

def gaps_seconds(starts, samplerate, baud):
    """Idle-high gap after each byte = start-to-start interval minus frame time."""
    starts = np.asarray(starts, dtype=np.float64)
    frame_time = FRAME_BITS / baud
    return np.diff(starts) / samplerate - frame_time


def largest_gap_split(values):
    """Threshold at the widest emptiness between two sorted clusters.

    Returns (threshold, lower_cluster_max, upper_cluster_min). Parameter-free:
    it puts the boundary in the biggest empty band, so it adapts to real jitter
    instead of assuming exact millisecond values.
    """
    v = np.sort(np.asarray(values, dtype=np.float64))
    diffs = np.diff(v)
    i = int(np.argmax(diffs))
    return 0.5 * (v[i] + v[i + 1]), float(v[i]), float(v[i + 1])


def bits_to_text(bits):
    """8 bits per char, MSB-first, to ASCII."""
    out = []
    for c in range(len(bits) // 8):
        value = 0
        for bit in bits[c * 8:(c + 1) * 8]:   # MSB-first
            value = (value << 1) | int(bit)
        out.append(chr(value))
    return "".join(out)


def recover_message(gaps):
    """Turn the ordered inter-byte gaps into the hidden ASCII message.

    Returns (message, info dict). Derives thresholds, splits repeats on the long
    idle, keeps only complete frames, and majority-votes the bits across them.
    """
    info = {}
    if gaps.size < GAPS_PER_CHAR:
        die("only %d gaps decoded — capture too short or UART decode failed"
            % gaps.size)

    # Split symbol gaps from the long inter-repeat idle. If the widest band is a
    # big ratio jump, that band is the idle boundary; otherwise a single frame
    # was captured (no idle present).
    idle_thr, sym_max, idle_min = largest_gap_split(gaps)
    has_idle = idle_min > sym_max * 20.0
    is_idle = gaps > idle_thr if has_idle else np.zeros(gaps.size, dtype=bool)
    info["idle_threshold_ms"] = idle_thr * 1e3 if has_idle else None

    symbol_gaps = gaps[~is_idle]
    sym_thr, short_max, long_min = largest_gap_split(symbol_gaps)
    info["symbol_threshold_ms"] = sym_thr * 1e3
    info["short_cluster_ms"] = short_max * 1e3
    info["long_cluster_ms"] = long_min * 1e3
    info["separation_ratio"] = long_min / short_max if short_max > 0 else float("inf")

    # Segment the ordered gaps into per-repeat bit runs, splitting on idles.
    frames, current = [], []
    for gap, idle in zip(gaps, is_idle):
        if idle:
            frames.append(current)
            current = []
        else:
            current.append(1 if gap > sym_thr else 0)
    frames.append(current)

    lengths = [len(f) for f in frames]
    info["frame_bit_lengths"] = lengths
    expected = CHARS_EXPECTED * GAPS_PER_CHAR  # 592
    complete = [f for f in frames if len(f) == expected]
    info["complete_frames"] = len(complete)

    if not complete:
        die("no complete frame found (need %d symbol gaps each; saw runs %s).\n"
            "       The capture may be truncated, or the short/long clusters may\n"
            "       be smeared (separation ratio %.2f — want it well above 2)."
            % (expected, lengths, info["separation_ratio"]))

    votes = np.array(complete, dtype=np.int32)     # (frames, 592)
    voted = (votes.mean(axis=0) >= 0.5).astype(np.int32)
    info["frames_unanimous"] = bool(np.all(votes == votes[0]))

    return bits_to_text(voted), info


# --------------------------------------------------------------------------- #
# main                                                                        #
# --------------------------------------------------------------------------- #

def report(bits, samplerate, capture_desc, channel_desc):
    """Run the timing pipeline on one channel's bit array and print the result.

    Shared by both front-ends: solve.py (reads a .sr) and solve_csv.py (reads a
    PulseView/sigrok CSV export). `capture_desc` and `channel_desc` are just
    display strings. Exits non-zero if no flag token is recovered.
    """
    values, starts = decode_uart(bits, samplerate, BAUD)
    if len(starts) < 2:
        die("decoded %d UART bytes — nothing to time" % len(starts))

    gaps = gaps_seconds(starts, samplerate, BAUD)
    message, info = recover_message(gaps)

    print("=" * 68)
    print("cadence_in_the_cord — timing side-channel solver")
    print("=" * 68)
    print("capture        : %s" % capture_desc)
    print("samplerate     : %.0f Hz" % samplerate)
    print("UART channel   : %s" % channel_desc)
    print("bytes decoded  : %d  (visible cover stream, the decoy)" % len(values))
    if info["idle_threshold_ms"] is not None:
        print("idle threshold : %.2f ms (splits repeats)" % info["idle_threshold_ms"])
    print("short cluster  : ~%.2f ms" % info["short_cluster_ms"])
    print("long  cluster  : ~%.2f ms" % info["long_cluster_ms"])
    print("symbol thresh. : %.2f ms (derived, midpoint of the empty band)"
          % info["symbol_threshold_ms"])
    print("separation     : %.1fx short  (clean if >> 2)" % info["separation_ratio"])
    print("complete frames: %d  (bit lengths seen: %s)"
          % (info["complete_frames"], info["frame_bit_lengths"]))
    print("repeats agree  : %s" % ("yes" if info["frames_unanimous"] else "NO — check capture"))
    print("-" * 68)

    printable = "".join(ch if 32 <= ord(ch) < 127 else "." for ch in message)
    print("recovered hidden stream (%d chars):" % len(message))
    print("    %s" % printable)

    match = re.search(r"HTB\{[a-z0-9_]+\}", message)
    if match:
        preamble = message[:match.start()].strip()
        print("-" * 68)
        print("preamble (payoff text, not the flag): %s" % preamble)
        print("FLAG: %s" % match.group(0))
    else:
        print("-" * 68)
        sys.stderr.write("warning: no HTB{...} token found in the recovered stream.\n"
                         "         Inspect the stream above; the capture may be noisy.\n")
        sys.exit(2)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_CAPTURE

    samplerate, unitsize, probes, logic = load_sr(path)
    channel = select_channel(logic, unitsize, probes, samplerate, BAUD)
    bits = channel_bits(logic, unitsize, channel)
    report(bits, samplerate, path,
           "%d (%s)" % (channel, probes.get(channel, "unnamed")))


if __name__ == "__main__":
    main()
