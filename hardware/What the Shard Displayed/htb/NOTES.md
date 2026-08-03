# Solver & delivery notes — `what_the_shard_displayed`

## Automated solver — reconstruction-only (admin-confirmed)

- **`htb/solve.py`** reconstructs the OLED framebuffer(s) from `challenge/capture.sr` and writes one PNG
  per frame; the flag is read off the rendered flag frame. By design it does **no OCR and no
  string recovery** (admin-confirmed). It contains no flag literal and never reads `flag.txt`.
- Run: `python3 htb/solve.py [challenge/capture.sr] [--outdir DIR] [--scale N]`.

## Firmware source + exact build command

- Source + build: **`src/BUILD.md`** — target Raspberry Pi Pico / RP2040, `arduino-cli` build/flash.
  Hand-rolled SSD1306 driver (no Adafruit splash), horizontal addressing, chunked `0x40` data writes.
  `src/gen_frames.py` regenerates the frame headers with the flag passed as a command-line argument (no
  flag literal in source). Firmware is never shipped (only the capture is).

## Automation (manual vs scripted)

- The solver renders the frames fully automatically; reading the flag off the rendered frame is by eye —
  the admin-confirmed reconstruction-only shape (the two decoy frames double as a page/bit-order
  correctness check).

## Patch impact

- Static flag: baked into the capture at authoring time (rendered into the OLED pixel data). No live
  rotation — re-flagging means re-authoring (re-benching) the capture.

## Handout

- `release/hardware_what_the_shard_displayed.zip` (password `hackthebox`) = `capture.sr` only.
