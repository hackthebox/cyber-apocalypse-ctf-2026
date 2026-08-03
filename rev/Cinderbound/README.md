![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /> <font size='10'>Cinderbound</font>

5<sup>th</sup> June 2026
Prepared By: `KailashS`
Challenge Author(s): `KailashS`
Difficulty: <font color='green'>Very Easy</font>

<br><br>
<br><br>




# Synopsis

To solve this challenge, we need to recognize that the file we receive is a MicroPython `.mpy` v6 bytecode file, not a CPython `.pyc`. Standard Python decompilers all fail because the magic bytes are wrong. Once we find `mpy-tool.py` from the MicroPython repository and disassemble the file, we see a single `judge` function that runs each input character through an XOR-accumulator loop and compares the result against a hardcoded target tuple. We extract the 16 target constants from the binary, then invert the transform to recover the flag; because XOR is its own inverse, the inversion is almost identical to the forward pass.

## Description

The Ash-Vault kept two kinds of oath. The first were pressed into black stone by hand, the old way, one Cinderbound scribe to one vow-stone, the same craft the priesthood has used since before Crownspire had walls. The second kind nobody talks about, because it only exists thanks to what Maelor did to the first.

After the white fire, when the Cinderbound went back into the drowned undercroft to count what survived, they found half their vow-stones cracked from the same heat that took the king. A cracked stone can be forged again by anyone patient enough to fake the grain. So the priesthood that outlived Maelor made a call the old masters would have called heresy: a handful of vows, the ones too dangerous to lose to a good forger, would never touch stone again. They would be pressed into a foreign engine instead, something built outside the Ashguard's own craft, unreadable to any priest trained only on the old chisels, and sealed shut.

You found one of those vows. It sat in the wreckage looking like nothing, a scrap the looters passed over because every tool they carried called it "data" and left it at that. They were not wrong to be confused. This was never meant to be read by common chisels, or by the honest engines the Cinderbound trust. It was built to be misread by exactly the kind of person now holding it.

Somewhere inside, a single ward is still doing its one job: listening for a syllable, and judging whether the voice offering it is the one the vow was sealed for. Learn the engine's foreign grammar. Find the ward. Give it the syllable it wants, and see if the vow answers back.

## Skills Required

- Basic familiarity with Python
- Ability to work with an unfamiliar binary format

## Skills Learned

- MicroPython `.mpy` v6 file format and magic bytes; how it differs from CPython `.pyc`.
- How to disassemble MicroPython bytecode and read its stack-machine operations.
- Inverting an XOR-accumulator loop analytically.

# Enumeration

## Analyzing the challenge

We get one file from the challenge: `cinderbound.zip`. Let's extract it.

```bash
$ unzip rev_cinderbound.zip
Archive:  rev_cinderbound.zip
  inflating: cinderbound.mpy
```

Let's check what we have.

```bash
$ file cinderbound.mpy
cinderbound.mpy: data
```

The OS says "data" and nothing more. That is not very helpful. Let's look at the raw bytes.

```bash
$ xxd cinderbound.mpy | head -3
00000000: 4d06 001f 0801 186a 7564 6765 5f73 7263  M......judge_src
00000010: 2e70 7900 0f0a 6a75 6467 6500 7910 7379  .py...judge.y.sy
00000020: 6c6c 6162 6c65 0081 5781 6f81 5900 0702  llable..W.o.Y...
```

Two things jump out. First: the file starts with `4D 06`. Second: the ASCII dump shows the strings `judge_src.py` and `judge`, names from a Python source file. This is not random data. It is compiled Python of some kind.

## Identifying the VM

The CPython `.pyc` magic for Python 3.11 is `55 0D 0D 0A`. Our file starts with `4D 06`. These are not the same.

`0x4D` is the ASCII character `M`, as in MicroPython. And `0x06` is the format version. Let's confirm:

```bash
$ python3 -c "print(hex(ord('M')))"
0x4d
```

This is a MicroPython v6 `.mpy` file. Standard CPython tools will all reject it. Let's try anyway to see the error:

```bash
$ python3 -m dis cinderbound.mpy
<nothing useful, wrong magic>

$ uncompyle6 cinderbound.mpy
Unsupported Python version 0x4d06001f
```

Confirmed. We need the MicroPython toolchain.

## Disassembling the bytecode

MicroPython ships a disassembler called `mpy-tool.py` in its repository under `tools/`. We can grab it along with its dependency `makeqstrdata.py`:

```bash
$ git clone --depth 1 https://github.com/micropython/micropython.git
$ cd micropython/tools
$ python3 mpy-tool.py -d /path/to/cinderbound.mpy
```

The output shows one function, `judge(syllable)`, with a loop body. The key operations in the bytecode, translated from MicroPython opcodes, are:

```
LOAD_CONST  t = (57, 129, 154, 31, 199, 192, 73, 243,
                 43, 176, 255, 173, 112, 196, 175, 74)
LOAD_CONST  acc = 90   (0x5A)
FOR_ITER    loop over range(len(syllable))
  BINARY_OP   ord(syllable[i]) ^ acc       ; XOR op
  BINARY_OP   ... ^ (i * 13 & 0xFF)        ; XOR + multiply + and
  BINARY_OP   acc + ord(syllable[i])       ; ADD for accumulator update
  AND 0xFF
COMPARE     out == list(t)
```

The key thing to notice: MicroPython's `BINARY_OP` takes an argument that identifies the operation. XOR is op 10, AND is op 11, multiply is op 16, add is op 14. These are different from CPython's named opcodes (`BINARY_XOR`, etc.). A player who assumes CPython semantics will misread the bytecode.

Once we map the opcodes correctly, the algorithm is clear.

## The algorithm

```python
acc = 0x5A
for i in range(len(syllable)):
    v = ord(syllable[i]) ^ acc ^ (i * 13 & 0xFF)
    acc = (acc + ord(syllable[i])) & 0xFF
    out.append(v)
return out == list(t)
```

The target tuple `t` is what `out` must equal for `judge` to return `True`.

# Solution

## Finding the vulnerability

The 16 target integer constants are the only values stored as tagged integer objects (`0x07 <length> <ASCII decimal digits>`) in the binary. Every other numeric value (the multiplier 13, the mask 0xFF, the initial accumulator 0x5A) lives as an inline literal directly in the bytecode and is not tagged the same way. This means we can extract the target tuple directly from the raw binary without even needing `mpy-tool.py`:

```python
import re

data = open('cinderbound.mpy', 'rb').read()
vals = []
for m in re.finditer(rb'\x07([\x01-\x09])([\x30-\x39]+)', data):
    if m.group(1)[0] == len(m.group(2)):
        vals.append(int(m.group(2)))

print(vals)
# [57, 129, 154, 31, 199, 192, 73, 243, 43, 176, 255, 173, 112, 196, 175, 74]
```

## Exploitation

Now we invert the loop. Since XOR is its own inverse, recovering the original character is almost the same operation as the forward pass:

```
v = ord(c) ^ acc ^ (i * 13 & 0xFF)
```

To get back `ord(c)`:
```
ord(c) = v ^ acc ^ (i * 13 & 0xFF)
```

Then we update `acc` the same way, using the recovered character:
```
acc = (acc + ord(c)) & 0xFF
```

We can walk forward through all 16 positions and recover every character.

```python
target = [57, 129, 154, 31, 199, 192, 73, 243, 43, 176, 255, 173, 112, 196, 175, 74]
acc = 0x5A
flag = []
for i, v in enumerate(target):
    c = v ^ acc ^ (i * 13 & 0xFF)
    acc = (acc + c) & 0xFF
    flag.append(chr(c))
print(f"HTB{{''.join(flag)}}")
```

### Getting the flag

Here is a quick summary of everything we did:

1. We unzipped `cinderbound.zip` and got `cinderbound.mpy`. Running `file` returned only "data".
2. We hexdumped the file and found the magic bytes `4D 06`: MicroPython v6, not CPython. All standard decompilers rejected it.
3. We obtained `mpy-tool.py` from the MicroPython repository and disassembled the file. We found one function `judge(syllable)` with a loop.
4. We mapped the MicroPython `BINARY_OP` codes to actual operations (XOR=10, AND=11, multiply=16, add=14) and reconstructed the algorithm: each character is XORed with a running accumulator and a position-derived key.
5. We scanned the raw `.mpy` binary for tagged integer constants (`0x07 <len> <decimal digits>`) and found exactly 16 values forming the target tuple.
6. We inverted the loop: since XOR is self-inverse, `ord(c) = v ^ acc ^ (i * 13 & 0xFF)`, then update the accumulator.
