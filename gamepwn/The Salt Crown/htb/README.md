# Solver

## `unpatch_upx.py` — restore the DLL to stock UPX

Undoes the custom UPX fork's cosmetic changes so plain `upx -d` unpacks the DLL: renames the
sections `.slt0/1/2 → UPX0/1/2` and the packer magic `SCN! → UPX!` (the compression is
untouched NRV2E, so the result is byte-for-byte a stock-UPX file). Pure standard library.

```bash
python unpatch_upx.py challenge_core.windows.template_release.x86_64.dll --unpack -o core.unpacked.dll
# or, fix only (then run upx -d yourself):
python unpatch_upx.py challenge_core.windows.template_release.x86_64.dll -o stock.dll
```

The `--unpack` step needs stock UPX 5.2.0 on PATH (or `--upx <path>`). Produces the 430,080-byte
unpacked DLL that §4's `submit_event` reverse and `solve.py` both work on.

## `recover_pck.py` — recover the hidden game code from the exe

Recovers the resource pack from **`The Salt Crown.exe`** alone (no secrets, no manifest). It
reads the `SCX1` trailer, recovers the 32-byte `script_encryption_key` by scanning `.data`
against a deterministic GDPC/MD5 oracle, peels the outer AES-256-CTR layer, decrypts the inner
Godot v4 (AES-256-CFB) pack, and writes every file:

```bash
pip install cryptography pefile
python recover_pck.py "The Salt Crown.exe" --out pck_files      # scans + recovers the key
python recover_pck.py "The Salt Crown.exe" --key <64hex> --out pck_files
```

Then decompile the compiled scripts with GDRE Tools (this build's bytecode is `ebc36a7`):

```bash
gdre_tools.exe --headless --bytecode=ebc36a7 --decompile="pck_files/scripts/**/*.gdc"
```

The recovered `scripts/game/challenge_state.gd` is the map: the `submit_event` interface, the
win conditions, and the `0x19A3` attack anchor. The six covenant opcodes are stripped from the
pack — those come from the DLL (below). This step is the harder recon gate, not the flag.

## `solve.py` — automated, offline

Reproduces the flag from the shipped DLL alone (no game, no debugger, no gameplay):
un-patches the custom UPX fork and unpacks the DLL, recovers `submit_event`'s six event
opcodes, rebuilds the reward root secret by XOR-ing the three native shares, locates the
per-build salt/nonce/ciphertext, derives the transcript-bound HKDF key, decrypts the 1,024
AES-256-GCM blocks and runs the drawing VM. It writes `flag.png` — open it to read the flag.

```bash
pip install pefile capstone cryptography pillow      # deps
# needs stock UPX 5.2.0 on PATH (or pass --upx <path>)

python solve.py                    # auto-unzips ../release/*.zip
python solve.py path/to/challenge_core.windows.template_release.x86_64.dll
python solve.py --unpacked already_unpacked.dll
```

Expected output ends with `draw-VM executed : 532 draws, 58 pauses` and a rendered
`flag.png` showing `HTB{REDACTED}`.

## `ce_opcode_substitution.lua` — intended live route

Cheat Engine Lua script for the intended solution: it breakpoints
`challenge_core...dll+0x3B50` and, on the six attacks after the first restoration, rewrites
the opcode (`EDX`) with `0x2C71 → 0x0F42 → 0x63B8 → 0x51DE → 0x37A5 → 0x72C4`. Load it via
Memory View → Tools → Lua Engine while attached to the running game, land six small hits,
then detach before the finale renders. See the main write-up for the full walkthrough.
