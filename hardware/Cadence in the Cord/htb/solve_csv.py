#!/usr/bin/env python3
"""Alternative solver for `cadence_in_the_cord`: decode from a CSV export instead
of the sigrok ``.sr``.

Same timing analysis as ``solve.py`` — only the front-end differs. Use this if
you would rather export the capture from PulseView (File > Export > Export Data
as CSV) than have the solver read the ``.sr`` container directly. It reuses the
validated decode/report pipeline from ``solve.py``; it derives the flag from the
timing alone and contains no flag literal.

Accepted CSV (what PulseView / ``sigrok-cli -O csv`` produce):
  * optional ``;``-prefixed comment header, including ``; Samplerate: 2 MHz``;
  * a column-name header row (e.g. ``logic`` or ``nanoseconds,logic``);
  * then one row per sample, each logic channel a 0/1 column.
Value-only, leading-time-column, and multi-channel exports are all handled.

Produce the CSV, e.g.:
    sigrok-cli -i challenge/capture.sr -O 'csv:time=true:header=true' > capture.csv
or from PulseView's CSV export.

Usage:
    python3 htb/solve_csv.py [capture.csv] [--samplerate 2M] [--channel D1]
Default CSV path: challenge/capture.csv
"""

import argparse
import io
import os
import re
import sys

import numpy as np

# Reuse the validated timing pipeline + helpers from the .sr solver next door.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import solve  # noqa: E402

DEFAULT_CSV = os.path.join(solve.CHALLENGE_ROOT, "challenge", "capture.csv")

_TIME_HINT = re.compile(r"time|second|nanosec|microsec|millisec|\b[num]?s\b", re.I)
_UNIT_SCALE = [  # (header substring, seconds-per-unit)
    ("nanosecond", 1e-9), ("microsecond", 1e-6), ("millisecond", 1e-3),
    ("second", 1.0), ("ns", 1e-9), ("us", 1e-6), ("ms", 1e-3),
]


def sniff_delimiter(line):
    for d in (",", "\t", ";"):
        if d in line:
            return d
    return ","


def parse_header(path):
    """Return (comment_lines, header_cols, delimiter, data_byte_offset, raw)."""
    with open(path, "rb") as fh:
        raw = fh.read()
    if not raw:
        solve.die("%s is empty" % path)

    comments, header, delim, pos = [], None, ",", 0
    while pos < len(raw):
        nl = raw.find(b"\n", pos)
        end = len(raw) if nl < 0 else nl
        line = raw[pos:end].rstrip(b"\r")
        stripped = line.strip()
        pos = end + 1
        if not stripped:
            continue
        if stripped[:1] in (b";", b"#"):
            comments.append(stripped.lstrip(b";# ").decode("ascii", "replace"))
            continue
        header = line.decode("ascii", "replace")
        delim = sniff_delimiter(header)
        break

    if header is None:
        solve.die("%s has no header/data rows — not a logic CSV" % path)
    return comments, [c.strip() for c in header.split(delim)], delim, pos, raw


def find_samplerate(comments, header_cols, sample_rows, delim, override):
    """Samplerate (Hz) from --override, else the comment header, else a time column."""
    if override:
        return solve.parse_samplerate(override), "override"

    for line in comments:
        m = re.search(r"samplerate\s*[:=]\s*(.+)", line, re.I)
        if m:
            return solve.parse_samplerate(m.group(1).strip()), "comment header"

    # Derive from a time column: first column whose name looks time-like and
    # whose values are not 0/1.
    for ci, name in enumerate(header_cols):
        vals = [r[ci] for r in sample_rows if ci < len(r)]
        if not vals or all(v in ("0", "1") for v in vals):
            continue
        if not _TIME_HINT.search(name) and "." not in "".join(vals):
            continue
        try:
            t = [float(v) for v in vals]
        except ValueError:
            continue
        dt = np.median(np.diff(t))
        if dt <= 0:
            continue
        scale = next((s for key, s in _UNIT_SCALE if key in name.lower()), None)
        if scale is None:  # guess by magnitude: whole numbers => nanoseconds
            scale = 1e-9 if dt >= 1 else 1.0
        return 1.0 / (dt * scale), "time column '%s'" % name

    solve.die("could not determine the sample rate: no '; Samplerate:' comment,\n"
              "       no usable time column. Pass it explicitly, e.g. --samplerate 2M")


def logic_columns(header_cols, sample_rows):
    """Indices of columns that are logic channels (all sampled values in {0,1})."""
    cols = []
    for ci in range(len(header_cols)):
        vals = [r[ci] for r in sample_rows if ci < len(r)]
        if vals and all(v in ("0", "1") for v in vals):
            cols.append(ci)
    return cols


def extract_column_bits(raw, data_offset, delim, ncols, col_index):
    """Fast-ish extraction of one 0/1 column as a uint8 bit array."""
    region = raw[data_offset:]
    b = np.frombuffer(region, dtype=np.uint8)
    if b.size == 0:
        return np.empty(0, dtype=np.uint8)

    if ncols == 1:
        # value-only rows: every 0x30/0x31 byte is a sample, in order.
        vals = b[(b == 0x30) | (b == 0x31)]
        return (vals - 0x30).astype(np.uint8)

    if col_index == ncols - 1:
        # last column: the digit just before each line terminator.
        nl = np.flatnonzero(b == 0x0A)
        crlf = nl.size and b[nl[0] - 1] == 0x0D
        idx = nl - (2 if crlf else 1)
        vals = b[idx]
        if region[-1:] not in (b"\n", b""):        # last row without trailing newline
            vals = np.append(vals, b[-1])
        return (vals - 0x30).astype(np.uint8)

    # middle column (rare): general parse — correct but slower on huge files.
    sys.stderr.write("note: channel is a middle column; parsing may be slow on large CSVs.\n")
    text = region.decode("ascii", "replace")
    return np.loadtxt(io.StringIO(text), delimiter=delim, usecols=[col_index],
                      dtype=np.uint8)


def main():
    ap = argparse.ArgumentParser(description="cadence_in_the_cord CSV solver")
    ap.add_argument("csv", nargs="?", default=DEFAULT_CSV,
                    help="PulseView/sigrok CSV export (default: challenge/capture.csv)")
    ap.add_argument("--samplerate", help="override sample rate, e.g. 2M or 2000000")
    ap.add_argument("--channel", help="logic channel name to decode (e.g. D1)")
    args = ap.parse_args()

    if not os.path.isfile(args.csv):
        solve.die("CSV not found: %s\n"
                  "       Export one from PulseView (Export Data as CSV) or run:\n"
                  "         sigrok-cli -i challenge/capture.sr -O 'csv:time=true:header=true' > capture.csv"
                  % args.csv)

    comments, header_cols, delim, data_offset, raw = parse_header(args.csv)

    # Sniff up to 200 data rows for column typing / time parsing.
    sample_rows = []
    for line in raw[data_offset:].split(b"\n", 200)[:200]:
        line = line.rstrip(b"\r")
        if line:
            sample_rows.append(line.decode("ascii", "replace").split(delim))

    ch_cols = logic_columns(header_cols, sample_rows)
    if not ch_cols:
        solve.die("no logic (0/1) channel column found in %s" % args.csv)

    samplerate, sr_src = find_samplerate(comments, header_cols, sample_rows, delim,
                                         args.samplerate)
    ncols = len(header_cols)

    # Choose the channel: by --channel name, else the sole channel, else the one
    # that decodes the most UART bytes.
    if args.channel:
        want = [ci for ci in ch_cols if header_cols[ci] == args.channel]
        if not want:
            solve.die("channel %r not among logic columns %s"
                      % (args.channel, [header_cols[ci] for ci in ch_cols]))
        chosen = want[0]
    elif len(ch_cols) == 1:
        chosen = ch_cols[0]
    else:
        best, best_n = ch_cols[0], -1
        for ci in ch_cols:
            bits = extract_column_bits(raw, data_offset, delim, ncols, ci)
            n = len(solve.decode_uart(bits, samplerate, solve.BAUD)[0])
            if n > best_n:
                best, best_n = ci, n
        chosen = best

    bits = extract_column_bits(raw, data_offset, delim, ncols, chosen)
    sys.stderr.write("csv: %d samples, samplerate from %s, channel '%s'\n"
                     % (bits.size, sr_src, header_cols[chosen]))
    solve.report(bits, samplerate, args.csv, header_cols[chosen])


if __name__ == "__main__":
    main()
