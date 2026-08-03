![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /> <font size='10'>The Cinder Engine</font>
23rd June 2026
Prepared By: KailashS
Challenge Author(s): KailashS
Difficulty: <font color='Orange'>Medium</font>

## Synopsis

You get one stripped x86-64 binary and a stubborn silence. It turns out to be an emulator for a CPU that exists in exactly no database, the Cinder Engine, with a firmware ROM baked inside it. Feed it a 32-byte vow on standard input and it answers only if the vow is the right one. There is no progress oracle, no string to grep, and no off-the-shelf tool you can point at the firmware, because the firmware runs on an instruction set you have to reverse from scratch.

The path is two layers stacked like bad news. First you reverse the emulator to recover the whole ISA: the scrambled opcode map, the encoding, the memory model, the works, and then you build your own disassembler for it. Then you lift the firmware and find a bespoke eight-round block cipher with data-driven table lookups and full diffusion, built so that automated tools choke and brute force over 2^256 is a non-starter. The only way through is to read the cipher out of the ROM, recover its four pieces (the S-box, the round keys, the secret linear layer, and the target), and run it backwards to forge the one vow the stone will swear to. Do that and the engine finally talks.

This writeup is written for the person who has never done any of that before, so we are going to go slowly and define things as we meet them. Bring snacks.

## Description

Before the white fire, exactly one Cinderbound scribe understood how the Cinder Engine thought. Not the others, not even the priesthood's own masters, only him, because he built it that way on purpose. A machine that judges vows is dangerous in the wrong hands, and the surest way to keep it out of the wrong hands was to make sure only one living person could read its instructions. He kept the opcode map in his head and nowhere else, a habit the order called caution and everyone else called paranoia.

He died the night Maelor reached for the First Mark, close enough to the vault that the same heat that took the king warped half the engine's casing and every note he'd ever kept on it. The machine still runs. It still takes a vow, still churns it through whatever logic survives inside that scorched firmware, still says true or false at the end. Nobody alive can tell you why. The scribe took the why with him.

You've got the engine in front of you, warm, patient, willing to judge whatever you feed it. Work out its opcode map from how it moves. Pull the firmware apart and find the cipher hiding in its tables. Then feed it something worth saying, and see if a dead man's machine still remembers how to keep a promise.

./cinder < vow

## Skills Required

* Reversing an unknown instruction set from an emulator: encoding, opcode semantics, flags, memory model
* Building your own tooling: a disassembler and emulator for a custom architecture
* Recognising and lifting a block cipher out of firmware (S-box, linear layer, key schedule)
* Inverting a substitution-permutation network round by round

## Skills Learned

* How to recover a complete ISA from a clean-room emulator and turn it into a working toolchain
* Why an unknown architecture defeats every automated tool until you write the lifter yourself
* How data-indexed memory and full diffusion make symbolic execution and brute force intractable
* How to invert a custom block cipher once every component has been read out of the binary

## MITRE Mappings

T1027.009: Obfuscated Files or Information - Embedded Payloads
The real logic runs as bytecode for a custom processor embedded in the binary, so the meaningful program never appears as native instructions a standard disassembler can read.

T1480: Execution Guardrails
The firmware only releases its secret for one exact 32-byte input, and the secret is derived from that input, so the payload is gated and cannot be lifted out statically.

T1622: Debugger Evasion / Analysis Resistance
The unknown ISA plus an anti-analysis cipher means automated tooling cannot be applied without first reconstructing the architecture by hand.

## Before we begin: a crash course for the brave

If you already reverse engineer in your sleep, skip ahead. If you do not, here are the only ideas you need, in plain language, and the rest of the writeup will keep pointing back here.

**A CPU is a very fast, very dumb clerk.** It reads one tiny instruction at a time, does exactly what it says (add these two numbers, jump over there, load this byte), and moves on. It never gets bored and never improvises. The list of all the instructions a particular CPU understands, plus how those instructions are encoded as numbers, is called its **instruction set architecture**, or **ISA**. x86-64 is an ISA. ARM is an ISA. The Cinder Engine is an ISA too, except nobody has ever written it down, which is the entire challenge.

**An emulator is a program that pretends to be a CPU.** Real hardware reads instructions and executes them in silicon. An emulator does the same thing in software: it keeps some variables for the registers and memory, then loops forever doing "read the next instruction, figure out what it is, do it." That loop has a famous name, **fetch-decode-execute**. When you hear "the binary is an emulator" or "this is a VM challenge," it means the interesting program is not the x86-64 you are looking at. The x86-64 is just the pretend-CPU. The real program is the stream of bytes it is interpreting, written in some other instruction set.

**A register is a named scratch variable inside the CPU.** Think R0, R1, R2 and so on, little boxes that hold one number each. **RAM** is a big numbered shelf of bytes for everything that does not fit in registers. **ROM** here just means read-only memory: the program and its constant data, which the CPU can read but not change.

**Flags** are one-bit yes/no notes the CPU leaves itself after doing math. The two that matter here are the **zero flag** (was the last result zero?) and the **carry flag** (did the last addition overflow, or the last subtraction go negative?). Branches, the CPU's version of "if," look at these flags to decide whether to jump.

**XOR is the reversible cousin of addition.** Written as a caret, `^`, it combines two bits and gives 1 only when they differ. Its magic property is that doing it twice cancels out: `a ^ b ^ b == a`. Here it is on real bytes, the letter `A` (0x41) XORed with a key byte 0x6B:

```
  0x41   = 0100 0001       (A)
  0x6B   = 0110 1011       (key)
  XOR    = 0010 1010   =   0x2A     (encrypted)

  0x2A ^ 0x6B = 0100 0001 = 0x41    (decrypt: XOR the same key back, A returns)
```

That round trip, encrypt by XOR and decrypt by XORing the exact same thing again, is the backbone of almost every cipher in this challenge. When mathematicians want to sound fancy about "everything is XOR," they call it working over **GF(2)**, the field with two elements, where addition is XOR and there are no carries. Do not let the name scare you. GF(2) is just XOR wearing a tie.

**A block cipher** scrambles a fixed-size chunk of data using a key, in a way that can be perfectly unscrambled later. Modern ones, AES being the famous example, are built out of **rounds**: you repeat the same little mixing recipe several times so that, by the end, every output bit depends on every input bit. A typical round has three flavours of step:

* **Substitution** (an **S-box**): replace each byte with another byte from a fixed lookup table. This is the nonlinear, confusing part.
* **Permutation / linear mixing**: shuffle and combine bytes so that one byte's influence spreads to its neighbours. This is the diffusing part.
* **Add round key**: XOR in some key material so the whole thing actually depends on a secret.

Two more vocabulary words you will hear me throw around. **Diffusion** is the goal where changing one input byte ends up changing all the output bytes (also poetically called the **avalanche effect**). And a **bijection** is a fancy word for a function that is perfectly reversible: every output comes from exactly one input, nothing is lost, nothing collides. Block ciphers are bijections by design, because a cipher you cannot decrypt is just a shredder.

That is the whole toolbox. Now let us go break a rock.

## First look

One file. No source, no server, no mercy. I did what anyone does and started poking it.

```
$ file cinder
cinder: ELF 64-bit LSB pie executable, x86-64, stripped
$ ./cinder
(nothing)
$ printf 'AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH' | ./cinder
(still nothing)
```

Let me unpack that for the newcomers. `file` just asks "what kind of thing is this," and it tells me this is a 64-bit Linux executable. The word **stripped** is the first piece of bad news: it means the helpful labels (function names, variable names) have been sanded off, so my disassembler will show me `sub_1234` instead of `check_password`. I am on my own for names.

Next I ran `strings`, which dumps any human-readable text baked into the binary. Sometimes you get lucky and the flag is just sitting there. Here I got no strings attached, nothing worth its salt. The binary reads my input and refuses to comment. Classic stonewalling, very on theme.

So I opened it in a disassembler and traced a single pass through `main`. Under the hood there is a tight loop that grabs four bytes from a big embedded blob of data, shifts and masks them apart into little fields, and then jumps into a giant switch statement based on the first field. If it walks like a fetch-decode-execute and quacks like a fetch-decode-execute, it is an emulator (see the crash course above). The four-byte chunks are instructions. The big blob is a program. And the x86-64 I am staring at is just the engine block.

This is the lightbulb moment of the whole challenge: nothing interesting is in the x86-64. The real program lives one floor down, written for a CPU that does not exist anywhere but inside this binary. Before I can read a single line of the actual logic, I have to figure out that imaginary CPU's entire language. Time to go name it myself.

## Solution

### Step 1: reverse the engine and recover the ISA

There is no shortcut for this part, so I read the dispatch switch one case at a time, the slow honest way. Every instruction is a 32-bit number stored little-endian (lowest byte first), and once I watched how the decoder chops it up, the layout fell out:

```
   bits:  31......24 23..20 19..16 15...............0
          [ opcode ] [ rd ] [ rs ] [     imm16      ]
```

So the top byte is the **opcode** (which operation), the next two nibbles pick destination and source registers (**rd**, **rs**), and the bottom 16 bits are an immediate value (a constant baked into the instruction). For the three-register math operations there is no room for a third register field, so the encoder smuggles it into the low nibble of the immediate: **rt = imm16 & 0xF**. Cute trick, and exactly the kind of detail you only learn by reading the decoder.

Let me decode one real word by hand so this is concrete, because byte order trips up absolutely everyone the first time.

Suppose the four bytes sitting in the ROM are `48 00 10 3A`. Little-endian means the first byte is the *lowest* part of the number, so I assemble them back-to-front into `0x3A100048`. Now I slice that number with the layout above:

```
0x3A100048  =  0011 1010 0001 0000 0000 0000 0100 1000

opcode = value >> 24            = 0x3A          -> "LDI"
rd     = (value >> 20) & 0xF    = 0x1           -> R1
rs     = (value >> 16) & 0xF    = 0x0           -> R0 (unused here)
imm16  =  value & 0xFFFF        = 0x0048 = 72
```

I look up opcode `0x3A` in the switch, see that its handler does `reg[rd] = imm`, and translate the whole thing to `LDI R1, 72`, which means "put the number 72 into register R1." One instruction down, a few dozen to go.

That is the entire game in Step 1: pick an instruction out of the ROM, run it through the bitfield layout, cross-reference what the matching switch case actually does to the registers and memory, and write down a human-readable name for it. Do that for every opcode and the fog lifts. The opcodes are scrambled on purpose, so you cannot guess that `0x3A` means LDI, you have to read the handler. Annoying, but it is only annoying once.

The opcodes are scrambled on purpose, so guessing was off the table and I had to read every handler to learn what each number means. No stone left unturned. By the end I had the full instruction set in my notes:

* `LDI rd, imm` (opcode 0x3A): put a constant into a register.
* `MOV rd, rs`: copy one register into another.
* The ALU crew: `ADD` (0x7C), `SUB`, `XOR` (0x52), `AND`, `OR`, `MUL`, each doing `rd = rs OP rt` and setting the zero flag.
* Shifts and rotates: `SHL`, `SHR`, `ROL`, `ROR` by an immediate amount.
* `ADDI rd, rs, imm`: add a constant.
* `CMP rs, rt`: subtract to compare, set the zero flag (equal?) and carry flag (less-than?), throw the result away.
* Branches: `BEQ`, `BNE`, `B`, jumps that add a signed 16-bit offset to the program counter, with the conditional ones checking the zero flag.
* Memory: `LDB`/`STB` load and store a single byte to a 64 KB scratch RAM, and `LDC` (0xC6) loads a byte straight out of the ROM (this is how the program reads its own constant tables).
* `IN rd` reads one byte from standard input, `OUT rs` writes one byte to standard output.
* `HALT` stops the machine.

Stepping back, it is a tidy little **Harvard machine**: code and constants live in read-only ROM, a separate RAM holds scratch, registers are 32 bits, and there are two flags. Crucially, there is no instruction anywhere that just coughs up the flag. That would be too easy, and the Cinderbound did not do easy.

A couple of details that took an extra minute to pin down, because they always do. The branches use a **PC-relative** offset, meaning a jump does not say "go to address 0x400," it says "go forward or back by N bytes from where you are now." That N is a *signed* 16-bit number, so a value like 0xFFF0 is not 65520, it is negative 16, a small hop backwards, which is exactly what you want for the top of a loop. Get the sign wrong and your emulator runs off into the weeds, so this is worth nailing. And the memory is genuinely split: `LDB`/`STB` talk to a blank 64 KB RAM that starts empty, while `LDC` reads the ROM, which is where all the constant tables live. Once I had those two facts straight, the firmware stopped looking like noise and started looking like a program with a clear beginning, middle, and a very rude ending.

Here is where the tooling abandons you, and it is worth saying loudly because it is the whole point of the challenge. There is no angr architecture for the Cinder Engine. No Ghidra processor module. No IDA loader. No nothing. Every fancy automated reverse-engineering tool in the world assumes it already knows your CPU, and this CPU was born five minutes ago in someone's imagination.

So if I wanted any automation later (a disassembler to read the firmware, an emulator to run experiments) I had to build it myself out of the notes above. The good news is that a disassembler is much less scary than it sounds. It is basically the decode example I did by hand, wrapped in a loop and a giant lookup table:

```
NAMES = { 0x3A: "LDI", 0x52: "XOR", 0x7C: "ADD", 0xC6: "LDC", ... }

for pc in range(0, len(rom), 4):
    word   = read_4_bytes_little_endian(rom, pc)
    opcode = word >> 24
    rd     = (word >> 20) & 0xF
    rs     = (word >> 16) & 0xF
    imm    = word & 0xFFFF
    print(pc, NAMES[opcode], "R%d, R%d, %d" % (rd, rs, imm))
```

That is the whole idea: forty-ish lines that turn a wall of hex into readable instructions. Once it exists, it does my reading for me, and I never have to hand-decode another byte. That little disassembler is the cover charge for the rest of the party. Building your own tools is not a detour around the challenge, it *is* the challenge.

### Step 2: pop the hood on the firmware

I pointed my shiny new disassembler at the ROM and the program finally made sense. Here is the shape of it.

First it reads 32 bytes from `IN` into a buffer in RAM, and quietly stashes a second copy of those same 32 bytes off to the side. (Hold that thought, the spare copy matters at the very end.) Then it enters a loop that runs eight times. Each lap through the loop does three things, and after staring at them I got a strong whiff of deja-vu:

1. **A byte-for-byte table swap.** For each of the 32 state bytes it does `LDC newbyte, [oldbyte + SBOX]`, meaning it uses the current byte as an index into a 256-entry table in the ROM and replaces it with whatever it finds. That is an **S-box**, the substitution step from the crash course. Notice the lookup address depends on the data, which will matter enormously in a minute.
2. **A long stretch of loads and XORs.** A big straight-line block reads bytes out of the state, XORs piles of them together, and writes a fresh 32-byte buffer, where each output byte is the XOR of some fixed handful of input bytes. That is a **linear mixing layer**, the diffusion step.
3. **An XOR with a round key.** It XORs the 32-byte state with a 32-byte key pulled from a block of nine keys sitting in the ROM. That is **add round key**.

After the eighth lap it compares the scrambled state, byte by byte, against a 32-byte **target** stored in the ROM, and only if all 32 match does it bother to produce any output. Put together: this is a bespoke **eight-round block cipher**, an S-box plus a linear mixing plus a key, repeated eight times, with its own custom everything. It is AES's weird cousin who was raised in a cave, but the family resemblance is unmistakable.

To make that less abstract, here is one round acting on a toy 4-byte state, using a made-up tiny S-box and the mixing rule "each output is the XOR of its two neighbours":

```
  state            =  [ 12, 34, 56, 78 ]
  after S-box swap =  [ 9A, 21, FE, 05 ]     (each byte replaced via the table)
  after mixing     =  [ 9A^21, 21^FE, FE^05, 05^9A ] = [ BB, DF, FB, 9F ]
  after add key    =  [ BB^k0, DF^k1, FB^k2, 9F^k3 ]
```

The real cipher does the same three moves on 32 bytes with a real 256-entry S-box and a far denser mix, eight times over. But the skeleton is exactly this: swap, smear, season with key, repeat.

Now the part that earns the challenge its keep. Three of the four ingredients are **data**: the S-box is a 256-byte table, the keys are a 288-byte block, the target is 32 bytes, and all of them are just sitting in the ROM where I can carve them out by scanning the file. But the linear mixing layer is **not** a table. It is a secret invertible 32x32 GF(2) matrix (in plain terms: a fixed rule saying "output byte 7 is the XOR of input bytes 2, 9, 14, 30, ..." for all 32 outputs), and that rule exists nowhere except inside the XOR instructions themselves. There is no nice array to grep. The only way to learn which inputs feed which output is to read the actual code, which means you cannot get the cipher without first reversing the ISA and disassembling the ROM. No smoke without the switch statement. That single design choice is the weld holding the two layers together: skip the architecture work and the cipher stays a black box, or, fittingly, a black stone.

### A short interlude on all the easy roads I tried first

Because I am not a saint, before doing the honest work I tried to cheat, and watching the cheats fail is genuinely the best way to understand why the challenge is shaped the way it is. So here is my hall of shame.

**"I will just grep the flag."** Already covered. The flag is not stored anywhere as text. Moving on.

**"I will throw a symbolic execution engine at it."** Symbolic execution is a clever technique where, instead of running the program on a concrete input, you run it on a *variable* and let an SMT solver (a kind of industrial-strength equation cruncher) figure out which input would reach the "you win" branch. It is genuinely magic when it works. It did not work here for two reasons. One, there is no off-the-shelf engine that understands the Cinder ISA, so I would have to teach the engine the whole architecture first, which is the work I was trying to avoid. Two, even if I did, the S-box lookups are indexed by the data. When the address you are reading depends on a variable, a symbolic engine has to consider that the read could land anywhere, so it forks into a swarm of possibilities or drags around a giant symbolic memory. Multiply that by hundreds of lookups across eight rounds and the solver does not finish before the heat death of the universe. The data-indexed lookup is not decoration, it is a deliberate booby trap for automation.

**"I will brute force the input."** The vow is 32 bytes, which is 256 bits, which is 2^256 possibilities. That is a number with seventy-seven digits. You could run every computer that has ever existed until the stars burn out and not make a dent. Hard no.

**"I will guess that it is basically AES and brute force the one piece I am missing."** This was my cleverest bad idea, and it is the reason the linear layer is built the way it is. I figured: I can scan out the S-box, the keys, and the target without reversing anything, and the structure looks AES-shaped, so maybe the only thing I am missing is a small mixing matrix I can just brute force. In an earlier version of a challenge like this, that works: if the mixing is a little 4x4 matrix, there are only a few tens of thousands of possibilities and you can try them all in a couple of seconds. Here it falls flat on its face, because the mixing is a full 32x32 matrix. The number of possible invertible matrices that size is astronomically larger than the brute force on the input, so there is nothing to guess. You cannot extract it (it is not data) and you cannot brute it (the space is hopeless). The matrix drags you back, every time, to actually reading the disassembly. Every easy road was a dead end, which is how you know you are finally on the right one.

### Step 3: run the cipher in reverse

The saving grace is that the whole thing is a **bijection** (crash course, remember: perfectly reversible). One target goes in, exactly one vow comes out, no ambiguity and no second answer to worry about. And once I had done the disassembly, every piece I needed was right there in front of me. I just had to flip each step around.

To reverse a cipher you reverse each of its steps in the opposite order, so I needed the inverse of all three ingredients:

* **Inverse S-box.** An S-box is a lookup table that maps each byte to another byte. To undo it I just build the table that maps the other way: if `SBOX[3] = 200`, then `INV_SBOX[200] = 3`. One loop, done.
* **Inverse round keys.** XOR is its own inverse (`a ^ k ^ k == a`), so "undoing" a round key is just XORing the same key in again. No work at all, which is the whole charm of XOR.
* **Inverse mixing matrix.** This is the only piece that takes real effort. I read the XOR block out of the disassembly and wrote down, for every output byte, exactly which input bytes get folded into it. That gives me the 32x32 matrix. To invert a matrix over GF(2) you use **Gaussian elimination**, the same row-reduction you may dimly remember from school, except every add is an XOR and there are no fractions to worry about, which honestly makes it easier than the version they teach you.

  The trick: write the matrix next to an identity matrix, then row-reduce the left half until it becomes the identity. Whatever the right half turns into is your inverse. Here it is on a tiny 2x2 so you can see it, where the mixing is "output0 = in0 XOR in1, output1 = in1":

```
  [ 1 1 | 1 0 ]      row0 ^= row1     [ 1 0 | 1 1 ]
  [ 0 1 | 0 1 ]   ----------------->  [ 0 1 | 0 1 ]
   matrix | I            (XOR)          I | inverse
```

  The left side is now the identity, so the right side, `[[1,1],[0,1]]`, is the inverse mixing: "in0 = out0 XOR out1, in1 = out1." Scale that exact procedure up to 32x32 (thirty lines of code, or one library call) and I had the inverse of the real mixing layer.

With all three inverses in hand, decryption is just the recipe read backwards. Start from the target, and for each round counting from eight down to one: XOR the round key, apply the inverse mixing, apply the inverse S-box. Then XOR the very first whitening key. Out the other end pops the one and only 32-byte vow that the engine will accept. I fed it back in, and the stone finally stopped giving me the cold shoulder:

```
$ printf '<the recovered vow>' | ./cinder
HTB{REDACTED}
```

One last bit of paranoia worth admiring. The flag is never stored in the clear, not even XORed under a fixed key. Remember that spare copy of the input the firmware kept at the start? On a correct vow, the engine XORs an embedded blob with the *vow itself* and prints the result. So the flag literally does not exist inside the binary until you supply the right input to conjure it. Patching out the final comparison to force it to print gets you nothing but confetti, because a wrong vow XORs the blob into garbage that never begins with `HTB{`. You cannot fake your way past the stone. You have to actually mean it.

## Walking through the solver

Here is the solve in pieces, in the order I actually did them, with what each bit does and where the information came from. I am showing the shape, not a copy-paste script, because the understanding is the point.

### Piece 1: scavenge the cipher tables out of the binary

```
blob = open(binary, "rb").read()
sbox = the 256-byte window that is a permutation of 0..255
rk   = the next 9 * 32 bytes        (round keys)
tgt  = the 32 bytes after that      (target)
linv = inverse of the 32x32 mixing matrix transcribed from the ROM disassembly
```

This collects the four ingredients. The S-box, keys, and target get scanned straight out of the ROM data. The mixing matrix gets transcribed from the disassembled XOR block (the part that forced all the architecture work) and inverted over GF(2). How do I find the S-box without knowing exactly where it lives? Easy trick: an S-box is a permutation of 0..255, meaning it contains every byte value exactly once. So I just slide a 256-byte window across the whole binary and grab the one stretch that holds all 256 values with no repeats. It is the only thing in the file shaped like that, so it basically announces itself. The keys and target sit right behind it like ducklings.

### Piece 2: build the inverses

```
sbox_inv[sbox[i]] = i             # flip the lookup table around
lin_inv = gauss_jordan_inverse(mixing_matrix_over_GF2)
```

Every forward step needs a backward twin. The S-box inverts by definition (map each output back to its input). The matrix inverts with the Gaussian elimination I described above. There is no separate shuffle step in this cipher, so the linear mixing is the entire between-S-box stage, with nothing hiding behind it.

### Piece 3: run the network backwards

```
s = tgt
for r in 8 down to 1:
    s = s XOR rk[r]      # undo add-round-key
    s = lin_inv(s)       # undo the mixing
    s = sbox_inv(s)      # undo the substitution
vow = s XOR rk[0]        # undo the initial whitening key
```

This walks the eight-round cipher in reverse to recover the single input that lands on the target. It is unique because the cipher is a bijection, so there is exactly one answer and no guessing. The round order (substitute, mix, add key) came straight off the lifted firmware in Step 2, and inverting it is just that same dance performed backwards with the inverse pieces.

### Piece 4: let the engine speak

```
run ./cinder, feed it the recovered vow on stdin, read the flag it prints
```

I hand the forged vow back to the real binary instead of trusting my own arithmetic. The flag should come from the engine, which conveniently doubles as a final sanity check that my entire reconstruction is correct down to the last byte. The engine reads the vow from standard input (that `IN` handler I recovered way back in Step 1) and prints the flag only for the true preimage. The solver never peeks at any flag file, because that would be cheating, and the stone would know.

### What a clean run looks like

```
[*] recovered vow: <32 bytes>
HTB{REDACTED}
```
