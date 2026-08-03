# Solver & delivery notes — `cadence_in_the_cord`

## Automated solver

- **`htb/solve.py`** recovers the hidden stream from `challenge/capture.sr` alone: reads the sigrok
  `.sr` (self-contained, no `libsigrokdecode`), decodes the UART (9600 8N1), measures the inter-byte
  gaps, derives the short/long threshold from the data (no hardcoded milliseconds), and prints the
  preamble followed by the `HTB{...}` flag. It contains no flag literal and never reads `flag.txt`.
- Run: `python3 htb/solve.py [challenge/capture.sr]` (defaults to `challenge/capture.sr`).
  `htb/solve_csv.py` is an alternate front-end that reads a PulseView CSV export.

## Firmware source + exact build command

- Source + build: **`src/BUILD.md`** — target Raspberry Pi Pico / RP2040, `arduino-cli` build/flash.
  The firmware bakes the 593-byte cover text and the per-gap timing table; it is never shipped (only the
  capture is), so a flag literal in firmware source is expected and fine.

## Automation (manual vs scripted)

- Recognising the timing side-channel is by eye — the visible cover text spells out the scheme (a hidden
  layer exists, it is in the gaps, long = 1 / short = 0, eight per character). Pulling all ~592 gaps is
  scripted; `htb/solve.py` does it fully automatically.

## Patch impact

- Static flag: baked into the capture at authoring time (encoded in the inter-byte gap durations). No
  live rotation — re-flagging means re-authoring (re-benching) the capture.

## Handout

- `release/hardware_cadence_in_the_cord.zip` (password `hackthebox`) = `capture.sr` only.
