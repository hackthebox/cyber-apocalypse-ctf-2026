<!--
  Solve-related delivery/review notes (lives in htb/ per the delivered-repo structure — "automated solver
  and other solve-related files"). NOT the player writeup (README.md) and NOT in the handout ZIP.
  Documents how the delivery meets HTB's submission requirements. Contains no flag literal.
-->

# Solver & delivery notes — `a_fault_in_the_cinder`

## Automated solver

- **`htb/solve.py`** runs the full six-stage chain end to end against the live service using only the
  release artifacts: reconstructs both firmware images from `factory_spi.sr`, derives the trigger from
  the failed-recovery baseline, fires the disassembly-derived fault, captures the unseal, and decodes
  the sealed custody record. It reads no secret and never opens `challenge/flag.txt`.
- Run: `pip install -r htb/requirements.txt`, then `python3 htb/solve.py <host> factory_spi.sr`
  (extract `factory_spi.sr` from the release ZIP first).
- Delivered end-to-end test: **`htb/test_solve.py`** — starts the service in-process, runs the solver,
  and confirms it recovers the configured (rotatable) flag with production/recovery counters 5 / 2.
- Pinned handout-derived constants (derivations shown in the writeup, not guessed): the vendor
  ECDSA-P256 public key (embedded in `cinder_boot.elf`) and the 247-cycle trigger-to-branch delay
  (counted from the disassembly).

## Firmware source + exact build command

- Source: `src/bootrom/`, `src/production/`, `src/recovery/`, `src/shared/`, `src/linker/`.
- Build: **`src/BUILD.md`** — `arm-none-eabi-gcc` 13.2.1; `bash build.sh` compiles `cinder_boot.elf` and
  runs a build-time branch assertion (exactly one 16-bit `beq.n` at the rejection, single call site).
  The handout ELF is that binary stripped (`arm-none-eabi-strip --strip-all`). Nothing executes it — it
  is disassembled, and the two firmware images it would boot are read out of flash to make
  `factory_spi.sr`.

## Automation (manual vs scripted)

- `htb/solve.py` is fully automated end to end; there is no manual step.
- The container serves three interfaces (rig control / logic analyzer / service accessory) from
  `python -m challenge.main` (standard library only); boots are serialized and rate-limited.

## Docker

- `Dockerfile` + `build-docker.sh` at the challenge root. One dedicated container per team; the runtime
  flag is injected at deploy time via `$CINDER_FLAG` and rotates without rebuilding any artifact.

## Patch impact

- The solver pins the vendor ECDSA-P256 public key and the 247-cycle delay. Rotating the vendor signing
  key changes the embedded public key → update the pinned key. Changing the boot ROM's pre-branch
  instruction sequence (number/order of the sanity gates) or the CPU / internal-SPI clock shifts the
  delay → re-count it from the disassembly. Pulse width is tolerant across the `6..16` band. The flag is
  runtime-sealed and rotates without rebuilding any artifact.

## Fault-delay timing model (design note)

- `delay = D_drv(221, published in TARGET.pdf §8) + boot_main(26, ELF-counted) = 247 cycles`.
- Two fairness guards: rig tolerance `±12` cycles (a blind sweep still costs ~3200× more attempts, and
  boots are serialized + token-bucket paced); and a build-time anti-drift assertion that re-derives
  `D_drv + boot_main` from the shipped ELF and asserts it equals the configured delay, so the published
  cycle convention can never silently diverge from the shipped binary.
