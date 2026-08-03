![img](../../assets/banner.png)
<img src='../../assets/htb.png' style='zoom: 80%;' align=left /> <font size='10'>First Mark</font><br>
4<sup>th</sup> June 2026<br>
Prepared By: `KailashS`<br>
Challenge Author(s): `KailashS`<br>
Difficulty: <font color='green'>Easy</font>

<br>
<br>

# Synopsis
First Mark is an easy reversing challenge that requires the player to statically analyse a stripped bare-metal RV32IM firmware image whose verification routine is a sixteen-round loop built from four instructions encoded in the opcode space RISC-V reserves for custom extensions, decode those instructions from their raw bits, reconstruct the round from the surrounding code and the expected-output table embedded in `.rodata`, and invert the round against that table (which acts as a complete offline oracle) to recover the sixteen-byte input that is the flag.
## Description
> Veylen Marr kept one secret from Maelor even while he was helping him dig for it: he never intended the First Mark to reach anyone's hands again, least of all a king's. When the vault flooded and the dust of that night finally settled, Veylen went back down alone and built something out of what he understood better than any living man, the old vow-forms, the sanctified marks, the grammar the first kings used to bind an oath to the sky. He built a stone that would listen for the First Mark and answer with only two words: true, or nothing at all.
>
> He left four of its instructions undocumented on purpose. Veylen had spent his whole career watching manuals get copied, stolen, and forged, and he'd learned the only ward worth trusting is one nobody can read secondhand. So he etched four runes into the spaces the old makers marked "for the kings to come," gave them no key, and let the stone keep its own counsel. Common chisels read most of it and stall exactly there, the same wall Veylen built into every safeguard he ever made for a king he didn't trust.
>
> If you want the stone to attest, don't go looking for the manual Veylen never wrote. Learn what those four runes do from the company they keep, the same way every claimant who ever wanted Veylen's trust had to earn it instead of being handed it.
>
> They found one last thing in the vault, cut in Veylen's own hand on the final dry stone, the closest he ever came to leaving a key. It reads: "The third rune is not a plain XOR. Each round it computes `out = a0 ^ state ^ carry`, then updates the hidden carry as `carry = old_a0 & state`. The carry starts at 0, and the state starts at `0xA5` and becomes the rune's output each round."
## Skills Required
- Reading assembly for an unfamiliar architecture
- Willingness to look up an instruction encoding table
- Basic Python scripting
## Skills Learned
- Decoding an undocumented RISC-V instruction from its raw bits
- Bounding an unknown operation using structural constraints (invertibility, ISA redundancy) instead of documentation
- Recognising an embedded expected-output table as an offline oracle that removes any need to execute the target
- Resolving residual ambiguity by exhaustive hypothesis search rather than guesswork
## MITRE Mappings
- `T1027` Obfuscated Files or Information: the verification logic is hidden behind four instructions encoded in RISC-V's reserved custom-opcode space, which no standard disassembler decodes and no emulator executes.
- `T1140` Deobfuscate/Decode Files or Information: recovering the flag requires decoding those instructions from their raw bits and inverting the round against the embedded expected-output table.
- `T1606` Forge Authentication Material: reconstructing the exact sixteen-byte First Mark that the stone attests to is the credential the challenge is built to protect.
# Enumeration
## First look
The challenge gives us one archive.
```bash
$ unzip rev_first_mark.zip
Archive:  rev_first_mark.zip
  inflating: first-mark.elf
$ file first-mark.elf
first-mark.elf: ELF 32-bit LSB executable, UCB RISC-V, soft-float ABI, version 1 (SYSV),
statically linked, stripped
```
RISC-V, 32-bit, statically linked, stripped. Let's look at the layout before anything else.
```bash
$ llvm-readelf -S first-mark.elf
  [Nr] Name         Type      Address  Off    Size   ES Flg
  [ 1] .text        PROGBITS  20000000 001000 000178 00  AX
  [ 2] .rodata      PROGBITS  20000178 001178 0000bc 00   A
  [ 3] .bss         NOBITS    80000000 002000 000010 00  WA
```
Load addresses at `0x20000000` with a separate RAM region at `0x80000000` and no dynamic loader, so this is a bare-metal firmware image, not a Linux binary. There are no symbols, but the section headers survive, which is all we need to find data later. The `.riscv.attributes` section records the ISA string `rv32i2p1_m2p0_zmmul1p0`: **RV32IM**, so hardware multiply is present. Worth remembering.
```bash
$ strings -n 8 first-mark.elf
the stone witnesses. it does not bargain. read the four marks or be cast out.
ACCEPTED: The First Mark was cut in steel.
 keep your steel
rv32i2p1_m2p0_zmmul1p0
```
No flag string, so nothing is hiding in plain sight.
## Trying to run it
There is no point fighting this one, but it is worth establishing early that the binary is not runnable, so we stop expecting dynamic analysis to help.
The image writes to a UART at `0x10000000` and has no OS underneath it, so it needs a bare-metal emulator. Even under one, execution dies on the first custom instruction, because (as we are about to see) those opcodes are not implemented by any emulator on earth: they are reserved space that this binary invents its own meaning for. On top of that, the buffer passed to the verification routine is uninitialised `.bss` at `0x80000000`; nothing in the image ever fills it, so there is no input to supply.
**This challenge is solved entirely statically.** That turns out to be fine, because the binary hands us everything we need.
## Disassembly
```bash
$ llvm-objdump -d -M no-aliases first-mark.elf
```
Four routines fall out: the reset stub at `0x20000000`, a UART string writer at `0x20000060`, `main` at `0x20000094`, and the one that matters at `0x200000d0`. Let's call it `verify`.
`main` prints the banner, calls `verify` with a pointer to the `.bss` buffer, and prints `ACCEPTED`, unconditionally, since `verify` also returns zero unconditionally. So `verify` does not report failure through its return value. Keep that in mind.
```asm
200000d0: addi    sp, sp, -0x30
...
200000ec: addi    s0, a0, 0x0          ; s0 = input buffer
200000f0: addi    s1, zero, 0x0        ; s1 = i = 0
200000f4: addi    a2, zero, 0xa5       ; a2 = 0xA5   <-- seeded, then never reloaded
200000f8: auipc   s2, 0x0              ; s2 = 0x200001F4
200000fc: addi    s2, s2, 0xfc
20000100: auipc   s3, 0x0              ; s3 = 0x20000204
20000104: addi    s3, s3, 0x104
20000108: auipc   s4, 0x0              ; s4 = 0x20000214
2000010c: addi    s4, s4, 0x10c
20000110: add     t0, s0, s1           ; loop top
20000114: lbu     a0, 0x0(t0)          ; a0 = input[i]
20000118: add     t0, s2, s1
2000011c: lbu     a1, 0x0(t0)          ; a1 = tableA[i]
20000120: andi    a1, a1, 0x7          ; ...masked to 3 bits
20000124: <unknown>                    ; .word 0x00B5050B
20000128: add     t0, s3, s1
2000012c: lbu     a1, 0x0(t0)          ; a1 = tableB[i]
20000130: <unknown>                    ; .word 0x00B5150B
20000134: <unknown>                    ; .word 0x00C5052B
20000138: addi    a2, a0, 0x0          ; a2 = a0   <-- state chained forward
2000013c: add     t0, s4, s1
20000140: lbu     a3, 0x0(t0)          ; a3 = tableC[i]
20000144: <unknown>                    ; .word 0x02D5002B
20000148: addi    s1, s1, 0x1
2000014c: addi    t0, zero, 0x10
20000150: blt     s1, t0, 0x20000110   ; 16 iterations
20000154: addi    a0, zero, 0x0        ; return 0, always
```
Sixteen rounds, one input byte each, three tables, four instructions the disassembler will not touch.
## The tables
The `auipc`/`addi` pairs give us exact addresses: `0x200001F4`, `0x20000204`, `0x20000214`.
```bash
$ llvm-objdump -s -j .rodata first-mark.elf
 200001e8 20696e20 73746565 6c2e0000 03070105   in steel.......
 200001f8 02060400 03070105 02060400 03020302  ................
 20000208 05070203 05070203 05070203 117a3590  .............z5.
 20000218 7e88b059 797f566a 3a10e905 206b6565  ~..Yy.Vj:... kee
 20000228 7020796f 75722073 7465656c           p your steel
```
Sixteen bytes each, back to back:
```
tableA @ 0x200001F4 : 03 07 01 05 02 06 04 00 03 07 01 05 02 06 04 00
tableB @ 0x20000204 : 03 02 03 02 05 07 02 03 05 07 02 03 05 07 02 03
tableC @ 0x20000214 : 11 7A 35 90 7E 88 B0 59 79 7F 56 6A 3A 10 E9 05
```
The 16 bytes following `tableC` are the ASCII string `" keep your steel"`, which nothing in the code references: flavour text, and a convenient marker for where `tableC` ends.
## The four unknowns
```
0x20000124 : .word 0x00B5050B
0x20000130 : .word 0x00B5150B
0x20000134 : .word 0x00C5052B
0x20000144 : .word 0x02D5002B
```
# Solution
## Step 1: decode the encodings
Nothing about these words is secret; only their *meaning* is. Every RISC-V instruction packs its fields the same way, and the base opcode map in the unprivileged spec marks `0b0001011` (`0x0B`) and `0b0101011` (`0x2B`) as **custom-0** and **custom-1**, space explicitly reserved for non-standard extensions. Both of our opcodes land there. The R-type layout is:
```
bits [6:0]   opcode
bits [11:7]  rd
bits [14:12] funct3
bits [19:15] rs1
bits [24:20] rs2
bits [31:25] funct7
```
```python
for w in (0x00B5050B, 0x00B5150B, 0x00C5052B, 0x02D5002B):
    print(f"0x{w:08X}  op=0x{w & 0x7F:02X}  f7={(w >> 25) & 0x7F}  f3={(w >> 12) & 7}  "
          f"rd=x{(w >> 7) & 31}  rs1=x{(w >> 15) & 31}  rs2=x{(w >> 20) & 31}")
```
```
0x00B5050B  op=0x0B  f7=0  f3=0  rd=x10  rs1=x10  rs2=x11      ->  a0 = F1(a0, a1)
0x00B5150B  op=0x0B  f7=0  f3=1  rd=x10  rs1=x10  rs2=x11      ->  a0 = F2(a0, a1)
0x00C5052B  op=0x2B  f7=0  f3=0  rd=x10  rs1=x10  rs2=x12      ->  a0 = F3(a0, a2)
0x02D5002B  op=0x2B  f7=1  f3=0  rd=x0   rs1=x10  rs2=x13      ->  F4(a0, a3), result discarded
```
Two units, then: opcode `0x0B` provides two byte transforms selected by `funct3`, and opcode `0x2B` provides two functions selected by `funct7`. The fourth writes to `x0`, which is hardwired to zero, so its result is thrown away; whatever it does, it does it as a side effect.
## Step 2: read the skeleton off the visible code
Substituting the decoded operands back into the loop gives us the whole round with four holes in it:
```
state = 0xA5
for i in 0..15:
    b     = input[i]
    b     = F1(b, tableA[i] & 7)
    b     = F2(b, tableB[i])
    b     = F3(b, state)
    state = b
    F4(b, tableC[i])
```
Three observations, all straight from the disassembly and none of them guesswork:
- `a2` is seeded once with `0xA5` and thereafter only ever assigned from `a0` (`addi a2, a0, 0x0` at `0x20000138`). It is a **running chain state**: round *i* sees the output of round *i-1*.
- `F4` is the last thing in the round, consumes `tableC[i]`, and discards its result. Since `verify` returns zero unconditionally and `main` prints `ACCEPTED` unconditionally, `F4` is the *only* mechanism by which a wrong input can be rejected, so it must trap. Which means **`tableC[i]` is the correct value of `b` at the end of round `i`**.
- That last point is the crux of the whole challenge. `tableC` is not a comparison target we have to work around; it is a full transcript of what the round output *should* be, for all 16 rounds. We do not need to execute anything. We need to run the round **backwards**.
Working backwards, the round output is known (`tableC[i]`), so `state` for every round is known too: it is just `tableC[i-1]`, with `0xA5` for round 0. Every round becomes independent, and the only thing standing between us and the flag is knowing what `F1`, `F2` and `F3` actually compute.
## Step 3: constrain the three transforms
We cannot read the semantics out of the binary. What we *can* do is narrow each one to a handful of candidates.
**A constraint that applies to all of them: the round must be invertible.** A challenge that accepts one specific 16-byte input needs each round to be a bijection on bytes; if two different inputs collided, the "one true mark" premise would be false and multiple flags would be accepted. So no lossy operations.
**F1** takes a second operand masked to 3 bits immediately before use (`andi a1, a1, 0x7`), and `tableA` is already in range 0 to 7, so the mask is a statement of intent: this is a shift amount for an 8-bit value. A plain shift discards bits and is not invertible, so it is a **rotate**. Direction is not recoverable from the encoding, which leaves **2 candidates**.
**F2** takes a second operand from `tableB`, whose values are 3, 2, 5, 7. That looks like multiplication by a small constant, but ordinary integer multiplication is out on two counts: the ISA string says RV32**I M**, so `mul` already exists and burning a reserved opcode to duplicate it would be pointless; and multiplying by 2 modulo 256 is not invertible, which breaks our bijection requirement. The natural byte-wide multiply where *every* non-zero constant is invertible is multiplication in **GF(2^8)**. The reduction polynomial is not recoverable from the binary, and there are **30 irreducible degree-8 polynomials over GF(2)**, so 30 candidates.
**F3** combines the current byte with the chain state. This is the one Veylen's final stone speaks about directly: *not a plain XOR*, but `out = a0 ^ state ^ carry`, with the hidden carry updated to `old_a0 & state` each round and starting at zero. That is a full specification rather than a nudge, but it is also the single claim in this challenge that cannot be checked by reading the binary, so we will treat it as a hypothesis and let the seal table rule on it, alongside the two unknowns we genuinely have to hunt down. Before taking the stone at its word, it is worth seeing what the naive reading produces.
## Step 4: the first attempt, and what it tells us
Assume `F1 = ror`, `F2 = GF(2^8) multiply mod 0x11B` (the most common polynomial, worth trying first), and `F3 = xor` (the plain XOR the stone warns against), then invert:
```python
state = 0xA5
for i in range(16):
    pre = tableC[i] ^ state
    state = tableC[i]
    out[i] = rol8(gf_mul(pre, gf_inv(tableB[i])), tableA[i])
```
```
c\......uh3.@...
63 5c 99 fb d8 d3 c1 ae 75 68 33 82 40 83 1f ad
```
Not the flag. Five of the sixteen bytes happen to land inside a plausible flag alphabet and the other eleven are junk, but roughly three bytes in ten fall inside that alphabet by chance alone, so five out of sixteen is exactly the yield a *completely* wrong model would give. There is no signal here to read: we cannot tell which bytes are right, only which are printable, and those two are not the same thing. The attempt tells us the model is wrong and nothing more. It does not tell us which of the three assumptions is at fault, nor how, and squinting at the output for a pattern would be guessing dressed up as deduction.
So we stop reasoning from the output and reason from the encoding instead, which is where the actual argument lives. `F3` occupies a custom opcode even though RV32I already has `xor a0, a0, a2`, same size, same result. Spending reserved encoding space on a duplicate of a base instruction only makes sense if it is not a duplicate, and the only thing a two-operand byte instruction can do that `xor` cannot is **carry information between invocations in a register that never appears in the code**. That is precisely what Veylen's stone claims, so the stone and the opcode layout agree with each other. Neither is proof, and we treat neither as settled: both go into the pot as a hypothesis, and the seal table decides.
## Step 5: widen the model and search
So we widen `F3` to the form the stone gives:
```
out    = b XOR state XOR c
c      = g(b, state, c)          # stone says g = b & state, c starts at 0
```
We are not going to simply trust it. The shape is worth recognising on its own terms: `a ⊕ b ⊕ carry` with the carry held over to the next cycle is a **carry-save adder**, the standard hardware trick for adding without waiting on carry propagation, and its carry-out has a handful of textbook forms. So we build a menu of candidates for `g` (the stone's `a & b` among them, but also the full-adder majority, the ripple carry, the no-hidden-state case, and the neighbouring byte-wide logic ops) and let the seal table decide. If the stone is honest, its rule will be the one that survives.
We now have three quantities in play, each with a small candidate set, and a 16-byte oracle to test against. Enumerate the lot:
- reduction polynomial: 30 (every irreducible degree-8 polynomial, no assumption about AES)
- rotate direction: 2
- carry rule `g`: 17
- whether `g` sees the old or the new chain state: 2
`30 x 2 x 17 x 2 = 2040` hypotheses. Each one costs 16 rounds of arithmetic. The filter is simply whether all 16 recovered bytes fall inside a plausible flag alphabet, a roughly 1-in-1000 test per hypothesis, which is more than sharp enough for a space this size.
```python
CHARSET = set(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
              b"0123456789_-{}!?.@#$%&*+")
CARRY_RULES = {
    "c' = 0                  (no hidden state)": lambda a, b, c: 0,
    "c' = a & b              (half-adder)":      lambda a, b, c: a & b,
    "c' = (a&b)|(a&c)|(b&c)  (full-adder)":      lambda a, b, c: (a&b) | (a&c) | (b&c),
    "c' = (a & b) << 1       (ripple carry)":    lambda a, b, c: (a & b) << 1,
    "c' = a | b":                                lambda a, b, c: a | b,
    "c' = a ^ b":                                lambda a, b, c: a ^ b,
    "c' = a + b":                                lambda a, b, c: a + b,
    ...
}
for poly in irreducible_deg8():                      # 30
    mul, inv = make_field(poly)
    for fwd_left in (False, True):                   # 2
        for name, rule in CARRY_RULES.items():       # 17
            for use_new_state in (False, True):      # 2
                s, c, out, ok = 0xA5, 0, bytearray(16), True
                for i in range(16):
                    pre = ST[i] ^ s ^ c
                    nc  = rule(pre, ST[i] if use_new_state else s, c) & 0xFF
                    ch  = rot(mul(pre, inv[MC[i]]), KS[i], not fwd_left)
                    if ch not in CHARSET:
                        ok = False; break
                    out[i] = ch; c = nc; s = ST[i]
                if ok:
                    print(poly, fwd_left, name, use_new_state, out.decode())
```
```
polynomials tried : 30 (every irreducible degree-8 poly over GF(2))
hypotheses tested : 2040
survivors         : 1
  poly=0x11B  rotate=ror  c' = a & b  (half-adder)  carry-operand=old state  ->  HTB{...}
```
One survivor out of 2040, and its carry rule is `c' = a & b` with the old state, exactly what was cut on Veylen's last dry stone. He was telling the truth.
## Step 6: read the answer back
The search does not just hand us the plaintext, it hands us the instruction set:
| Word | Operation |
|------|-----------|
| `0x00B5050B` | `a0 = ror8(a0, a1 & 7)`, an 8-bit rotate right |
| `0x00B5150B` | `a0 = gfmul(a0, a1)`, a GF(2^8) multiply with reduction polynomial `0x11B` |
| `0x00C5052B` | `a0 = a0 ^ a2 ^ carry`, then `carry = (old a0) & a2`, a carry-save accumulate |
| `0x02D5002B` | trap unless `a0 == a3`, the attest-or-cast-out check |
The third one is exactly the carry-save adder the shape predicted: the sum bits are produced immediately, and the carry bits are deferred to the next round instead of being propagated. And note it justifies the custom opcode after all, because the base ISA has no way to keep a register the program cannot address.

## Getting the flag
The final solver reads the tables straight out of the ELF and runs the round backwards:
```python
def solve(path):
    ro = rodata(open(path, 'rb').read())
    i  = ro.find(KEY_SCHEDULE)
    ks = ro[i      : i + 16]        # rotate amounts   (instruction 1)
    mc = ro[i + 16 : i + 32]        # field constants  (instruction 2)
    st = ro[i + 32 : i + 48]        # expected outputs (instruction 4)
    state, carry = 0xA5, 0
    flag = bytearray(16)
    for n in range(16):
        pre     = st[n] ^ state ^ carry          # undo instruction 3
        carry   = pre & state                    #   carry-save update, old state
        state   = st[n]
        b       = gf_mul(pre, gf_inv(mc[n]))     # undo instruction 2
        flag[n] = rol8(b, ks[n] & 7)             # undo instruction 1
    return flag.decode()
```
```bash
$ python3 solve.py first-mark.elf
HTB{...}
```
A recap of the path:
1. Unzipped the archive and identified a stripped, statically linked, bare-metal RV32IM image. Established that it cannot be executed (no OS, uninitialised input buffer, and four instructions no emulator implements), so the challenge is static.
2. Disassembled it and found one routine of interest: a 16-round loop reading one input byte per round, three 16-byte tables, and four undecodable words.
3. Recovered the tables at `0x200001F4`, `0x20000204` and `0x20000214` from the `auipc`/`addi` pairs.
4. Decoded the four words as standard R-type instructions in the `custom-0` and `custom-1` opcode spaces, recovering their operand registers.
5. Reconstructed the round skeleton from the visible instructions, established that `a2` is a chain state seeded at `0xA5`, and that the fourth instruction is the only rejection mechanism, which makes the third table a complete transcript of the correct round outputs and the whole loop invertible without execution.
6. Constrained the unknown transforms using invertibility and ISA redundancy: a rotate rather than a shift, and a GF(2^8) multiply rather than an integer one. Established that the third instruction must carry hidden state, from the pointlessness of a custom opcode that duplicates `xor`, corroborated by Veylen's own account of it.
7. Enumerated all 2040 remaining hypotheses against the seal table and found exactly one that decodes to printable text, which simultaneously pins down the polynomial, the rotate direction, and independently confirms the carry rule the description supplies.
8. Ran the pipeline backwards to recover the flag.
## Flag
```
HTB{...}

```
