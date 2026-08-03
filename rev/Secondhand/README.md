![img](../../assets/banner.png)
<img src='../../assets/htb.png' style='zoom: 80%;' align=left /> <font size='10'>Secondhand</font>

13<sup>th</sup> June 2026
Prepared By: `Kailash S`
Challenge Author(s): `Kailash S`
Difficulty: <font color='#c084fc'>Insane</font>
<br><br>

# Synopsis

`secondhand` is a single stripped Linux x86-64 binary that reads one line from stdin and, for almost everything you feed it, prints a bit of documentary flavor text and exits. It looks like it has a clean, solvable flag check sitting right at the front (a function called `b_roll`), and a big, important looking function next to it (`threat_level_midnight`). Both are lies. The real check lives inside a 49-byte block of hand-laid machine code that decodes **two different ways** depending on which byte you start reading from. A normal disassembler reads it from the front and shows you a harmless hashing loop. The CPU actually jumps six bytes in and runs a completely different instruction stream that is the genuine flag check. Same bytes, two programs, and the binary only tells the truth in the one it thinks got cut.

To solve it you stop trusting your disassembler, write a tiny one of your own that lets you pick the start offset, find the real entry point (`N+6`), rebuild a transform that the program stores as inert data and only assembles into code at runtime, invert that transform, and feed the resulting eight bytes back into the binary. The flag is decrypted on the fly from a key that only exists when you have already solved it, so there is no plaintext flag anywhere in the file until the moment you win.

## Description

Elric's work always goes through Vaultrune before it goes anywhere else. That's not a courtesy, it's the law Cassian built his house on: nothing comes back from a survey and gets used until a Vaultrune warden has taken it apart, checked every joint against the tolerances on file, and stamped it clean. Cassian doesn't trust artificers any more than he trusts claimants, and a mechanism nobody's certified is, in his house's language, a mechanism nobody's allowed to touch.

This one skipped that step entirely. It turned up in the satchel from the Stonepass survey like it belonged there, no requisition number, no warden's mark, nothing to say where it came from or who cleared it. Run it and it holds together perfectly, every joint clean, every tolerance dead on, which is exactly the problem. Nothing off a working survey looks that finished before a warden's had their hands on it. Something got built into this one that was never meant to survive an inspection, and whoever should have caught it either missed it or let it through on purpose.

Find what they buried before a Vaultrune warden does, because whichever one of you reads it first gets to decide what happens next.

## Skills Required

- Comfortable loading a stripped ELF into a decompiler (Ghidra, IDA, Binary Ninja, radare2, whatever you like) and reading x86-64
- Knowing how to drive a debugger: set a breakpoint, single step, read a register
- Enough Python to glue a disassembly library (like Capstone) around a byte buffer
- A stubborn streak, because this challenge wants you to doubt your tools

## Skills Learned

- Recognising **instruction-boundary aliasing**: one byte array that decodes as two valid instruction streams depending on the start offset, with zero self-modifying code
- Spotting a loop that exists only to control alignment (it looks like crypto, it does nothing of the sort)
- Finding a code entry point that is computed at runtime and never written down statically, by reading a register at an indirect jump
- Defeating a **data-as-code** trick where the real instructions live as obfuscated bytes in a data section and are only assembled into an executable page at runtime
- Inverting a bijective integer transform by hand to recover an exact preimage instead of brute forcing
- Why a loud anti-debug check can be a complete red herring

## MITRE Mappings

- **T1027 - Obfuscated Files or Information.** The decisive logic of this binary is never present as plain code. The flag check is hidden inside a byte sequence that aliases into two instruction streams, and the transform it applies is stored as an inert, scrambled blob in a read-only data section that the program unscrambles and assembles into an executable page only at runtime. Both techniques are textbook information obfuscation, and both are exactly what an analyst has to peel back here.
- **T1622 - Debugger Evasion.** The binary carries a `ptrace` based tripwire that detects when it is being traced and changes its visible behavior. It is deliberately loud, the kind of check that makes you assume the secret is locked behind anti-tamper. Reverse engineering this challenge includes correctly identifying that the evasion gates nothing on the win path, which is the whole point of including it.
- **T1480 - Execution Guardrails.** The real check is only reachable when the input is exactly the right length. The program folds the runtime input length into an offset and reaches the hidden entry point through an indirect jump, so any other length lands mid-instruction and silently routes you to decoys. The accepted length acts as a guardrail that keeps the genuine code path off the map until you supply the right key.

# Enumeration

## Analysing the Given Files

The release zip contains exactly one thing:

```
re_secondhand/
└── secondhand
```

No source, no README, no helpful hints. Just a binary. Let us see what it is:

```
$ file secondhand
secondhand: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, not stripped
```

It is a 64-bit Linux executable. It says "not stripped", but do not get excited, because almost everything has been stripped anyway. Look at the symbol table:

```
$ nm secondhand
0000000000401370 T b_roll
00000000004014f0 T threat_level_midnight
```

Two function names survive, and that is it. `b_roll` and `threat_level_midnight`. When a binary goes to the trouble of stripping itself down to two named functions, those two names are not a gift. They are bait. Hold that thought.

## Just running it

Before reversing anything, throw some input at it and watch what happens. The program reads one line from stdin.

```
$ printf 'AAAAAAAA' | ./secondhand
This is a rough cut. What is playing is the version we agreed to air, not the version
that happened. The honest take got cut. It is still in here, it is just not the one running.
Facilities, second floor printer. It jams on one page every run, the page in the middle
that everyone flips straight past. The part everyone ignores. Whoever last cleared it left
a note on the tray: it only feeds clean if you start the page from the inner crease, not
from the top. Feeding it from the top is why it keeps jamming. Marked low priority.
```

So it prints flavor text and exits. Read that second paragraph again, because the challenge is being unusually honest with you. "It only feeds clean if you start the page from the inner crease, not from the top." That is the entire mechanic of the challenge described as office furniture. You are going to start reading from the wrong place, and that is why it keeps jamming. Keep that line in your back pocket.

## The first thing that looks like a flag check: `b_roll`

Open the binary in your decompiler and go straight to `b_roll`, because it is named and it is right there. What you find looks fantastic. It reads a fixed-length string (28 bytes), runs each byte through a small reversible chain (an additive skew based on position, a byte rotation, and a one-byte feedback value that mixes each character forward into the next comparison), and checks the result against a fixed table.

Cleaned up, the check is essentially this:

```c
t[i]   = rotl8( (in[i] + i*0x1F) & 0xFF, 3 ) ^ chain;
chain  = (chain + in[i]) & 0xFF;       // chain starts at 0x5A
// accept iff t[i] == b_roll_target[i] for all i
```

Every operation here is invertible, and the feedback value at position `i` only depends on bytes you have already recovered. That means you can solve it left to right with no searching at all:

```c
in[i] = ( rotr8(target[i] ^ chain, 3) - i*0x1F ) & 0xFF;
```

This is a genuinely satisfying solve. You can do it by hand in twenty minutes, recover the one and only 28-byte string that satisfies it, feed it in, and... you get the same flavor text. No flag. Nothing moves.

That is the first lesson the challenge teaches, and it teaches it on purpose. A clean solve can still be the wrong program. `b_roll` means filler footage, the stuff that looks like the shoot but never makes the final cut. The check is real, the math is real, the answer is real, and none of it is the film. If your correct answer does nothing, do not assume you got the math wrong. Assume you solved the wrong thing.

## The second trap: `threat_level_midnight`

So `b_roll` was a dud. The natural next move is to find the biggest, most important looking function in the binary, and there it is: `threat_level_midnight`. It is huge. It has layers. It has the kind of structure that screams "this is the main event".

It is not. It is a fully fake solve path built specifically to eat the time of people who pattern match on "biggest function equals most important function". Nothing inside it feeds the win condition. It can cost you hours if you let it. Lesson number two, delivered with prejudice: code volume is not evidence of importance.

At this point you have two dead ends and a binary that just keeps reciting documentary narration. This is where the real work starts.

# Solution

## The discrepancy that breaks it open

Three small things eventually line up and all point the same way.

**One:** your correct `b_roll` answer did nothing. You already know something is off.

**Two:** there is a loop in the binary that reads like hand-rolled crypto. A byte gets pulled in, XORed into an accumulator, rotated left by 11, then multiplied by a 64-bit constant, in a loop over the input. It has the full costume of a custom cipher. You can burn real time trying to break it as one. The trick is that it does not actually transform anything that survives or gets compared. Read it slowly and it is just busywork. It exists to push a value forward, not to encrypt anything. It is alignment padding wearing a crypto outfit. And the moment you realise a loop exists only to control *where the next thing starts*, the question becomes: where do things start?

**Three:** the debugger settles it. Set a breakpoint near that region, step into it, and watch the program counter. The CPU walks straight into the **middle** of an instruction that your static listing shows as a single opcode. The disassembly and the execution flatly disagree, and when those two disagree, the execution is the one telling the truth.

That is the heart of `secondhand`. There is a 49-byte region of hand-laid bytes with one deliberate property. Disassemble it from its start (call that `N`) and you get one valid, boring instruction stream. Have the CPU enter a few bytes later (at `N+k`) and you get a completely different, equally valid stream. The bytes never change. There is no self-modifying code, no unpacking, no decryption of the section. The only trick is the offset where decoding begins. You are watching an edit of an edit.

## Why your disassembler cannot show you this

Here is where you end up writing your own tool, and not because you are showing off. Every disassembler you own commits to one alignment and renders the region once. You can nudge them, but you cannot get a clean side-by-side of "the stream from `N`" and "the stream from `N+k`" out of the same bytes on demand.

Worse, since the symbol table only has `b_roll` and `threat_level_midnight`, the hot region is not even labelled. Look at how the static disassembly presents it, buried inside the address space of `threat_level_midnight` because there is no symbol to break it out:

```
0000000000401dd0 <threat_level_midnight+0x8e0>:
  401dd0:  55                 push   %rbp
  401dd1:  48 89 e5           mov    %rsp,%rbp
  401dd4:  48 b8 49 ba be ba de c0 37 13   movabs $0x1337c0debabeba49,%rax
  401dde:  49 b8 4c 39 d0 75 01 c3 31 c0   movabs $0xc031c30175d0394c,%r8
  401de8:  31 c9              xor    %ecx,%ecx
  401dea:  0f b6 14 0f        movzbl (%rdi,%rcx,1),%edx
  401dee:  48 31 d0           xor    %rdx,%rax
  401df1:  48 c1 c0 0b        rol    $0xb,%rax
  401df5:  49 0f af c0        imul   %r8,%rax
  401df9:  ff c1              inc    %ecx
  401dfb:  39 f1              cmp    %esi,%ecx
  401dfd:  75 eb              jne    401dea
  401dff:  5d                 pop    %rbp
  401e00:  c3                 ret
```

That looks like a perfectly innocent rolling hash. Two big constants loaded into registers, a loop over the input bytes doing xor / rotate / multiply, and a return. Nothing screams. That is the aired cut, and it is designed to look finished.

So you write a tiny disassembler. It does not need to be clever. It wraps a disassembly library, takes a buffer and a start offset, and prints the instruction stream from there. The whole point is control over *where decoding begins*. The reference tool in this writeup is `sweep.py`: it pulls the 49 raw bytes out of the binary by signature and disassembles them from every candidate start offset (`N+0` through `N+16`), then flags the one offset whose stream is actually a load / compare / branch / return check chain.

```
$ python3 sweep.py
[*] hot region   : file offset 0x1dd0, 49 bytes
[*] region bytes : 554889e548b849babebadec0371349b84c39d07501c331c031c90fb6140f4831d048c1c00b490fafc0ffc139f175eb5dc3
[*] sweeping linear disassembly from offsets 0..16
```

Most offsets either decode into illegal opcodes (garbage) or decode cleanly but never contain a real check (they just re-sync into the shared tail loop, the rabbit-hole reading). Exactly one offset is different:

```
=== offset N+6 (start 0x06) ===   <==== REAL CHECK (N+k, k=6)
  0x06: 49babebadec0371349b8   movabs r10, 0xb8491337c0debabe   <-- check chain begins
  0x10: 4c39d0                 cmp rax, r10
  0x13: 7501                   jne 0x16
  0x15: c3                     ret
  0x16: 31c0                   xor eax, eax
  ...
```

And the summary makes it unambiguous:

```
CONVERGED: exactly one real-check reading -> offset N+6 (k=6)
Recovered expected hash: 0xb8491337c0debabe
All other offsets are garbage or rabbit-hole tail. Sweep is decisive.
```

There it is. Starting six bytes in, the same bytes that looked like `movabs rax, 0x1337...` become `movabs r10, 0xb8491337c0debabe` followed by `cmp rax, r10`. The high two bytes of that magic constant (`0xb849`) are literally the same `49 b8` bytes that the front reading used as the opcode for `movabs r8`. One pair of bytes doing two jobs. That is the trick in a nutshell, and now you can read the real check:

```asm
movabs r10, 0xb8491337c0debabe   ; the expected value (call it TARGET)
cmp    rax, r10                   ; does the computed value equal TARGET?
jne    fail
ret                               ; match -> success
```

So success is `computed == 0xb8491337c0debabe`. We have the target. We do not yet know how `computed` is produced, and we do not yet know how the CPU knew to start at `N+6`.

## Finding `k`: the offset nobody wrote down

The offset `N+6` is never written as a constant anywhere. There is no `jmp N+6`, no `lea` pointing at it, no relocation. If you grep for the landing address you find nothing, which is intentional. So how does the CPU get there?

Look just above the hot region, at the dispatcher:

```
401d90:  48 89 d0           mov    %rdx,%rax           ; rax = computed value
401d93:  55                 push   %rbp
401d94:  41 89 f3           mov    %esi,%r11d          ; r11 = input length (runtime)
401d97:  41 83 e3 1f        and    $0x1f,%r11d         ; r11 &= 0x1f
401d9b:  41 83 f3 0e        xor    $0xe,%r11d          ; r11 ^= 0xE   -> this is k
401d9f:  48 8d 15 2a 00 00 00 lea  0x2a(%rip),%rdx     # 401dd0    <- only ref is to N
401da6:  4c 01 da           add    %r11,%rdx           ; rdx = N + k
401da9:  4c 8d 1d 13 00 00 00 lea  0x13(%rip),%r11     # landing pad (return path)
401db0:  41 53              push   %r11
401db2:  4c 8d 1d 04 00 00 00 lea  0x4(%rip),%r11      # second landing pad
401db9:  41 53              push   %r11
401dbb:  ff e2              jmp    *%rdx               ; <-- indirect jump into N + k
```

This is the guardrail. `k` is computed at runtime from the input length:

```
k = (len & 0x1f) ^ 0xE
```

The only address the binary names is `N` (`0x401dd0`). The `+k` part only ever exists inside a register, and the jump is indirect (`jmp *%rdx`), so static analysis has nothing to follow. You can confirm `k` two ways. Read it off in a debugger by breaking on the `jmp *%rdx` and printing `rdx`, or just solve the arithmetic. For the accepted length of 8:

```
k = (8 & 0x1f) ^ 0xE = 8 ^ 0xE = 6
```

So an 8-byte input lands the indirect jump exactly on `N+6`, the real check. Any other length folds to a different `k`, lands mid-instruction, and quietly falls through to the decoys. That is why length 8 is special, and it is why nothing but length 8 ever reaches the genuine code. As a nice bonus, the binary is not position independent, so `N` is at the same address on every run and every machine. Once you find the entry, it stays found.

(There is also a small two landing-pad dance on the return path, those two `push`/`lea` pairs before the jump. That is just bookkeeping so both the match and mismatch outcomes return cleanly to the C caller, because the two readings pop a different number of things off the stack. You do not need it to solve, but it is fun once you see why it has to be there.)

## The data-as-code table: rebuilding `computed`

We know success means `computed == 0xb8491337c0debabe`. Now we need to know how `computed` is built from our eight input bytes. The function that builds it does **not** keep its logic in plain instructions. Instead there is an inert blob sitting in `.rodata`, and a routine that unscrambles that blob into real x86-64 machine code, copies it into a fresh memory page, flips that page to executable, and calls it. The bytes that actually run live in memory the program wrote at runtime, so the static `.text` never shows them and is never modified. Data pretending to be data, right up until it becomes code.

The unscramble step is simple byte math (a rotate and an XOR against a short key, applied to the reversed blob). You can read the rebuild routine, copy its arithmetic, and apply it to the blob yourself. That is what `emulate_table.py` does: it scans `.rodata`, applies the inverse transform to every candidate window, and keeps the one window that rebuilds into a clean, sensible function stub. Exactly one does:

```
$ python3 emulate_table.py
[+] scan converged: exactly one window rebuilds to a clean stub.
[*] table   : 38 bytes @ file offset 9600 (0x2580)  vaddr 0x402580
[*] rebuilt : 4889f849bbefbeaddea5a5a5a54c31d848c1c01149bbb301000000010000490fafc348f7d0c3

[*] disassembly of the rebuilt (assembled) bytes:
    0x00: mov rax, rdi
    0x03: movabs r11, 0xa5a5a5a5deadbeef
    0x0d: xor rax, r11
    0x10: rol rax, 0x11
    0x14: movabs r11, 0x100000001b3
    0x1e: imul rax, r11
    0x22: not rax
    0x25: ret
```

Decoded, the transform is short and clean:

```
computed = ~( rol64( (x ^ K1), 17 ) * MUL )

    K1  = 0xA5A5A5A5DEADBEEF      (xor mask)
    ROT = 17                       (rotate-left amount)
    MUL = 0x00000100000001B3       (odd, so invertible mod 2^64)
```

where `x` is your eight input bytes read as a little-endian 64-bit integer. Every single step here is reversible. XOR is its own inverse, a left rotate undoes with a right rotate, multiplication by an odd constant is invertible modulo 2^64, and `not` is its own inverse. So `f(x)` is a bijection, which means there is exactly one `x` that produces any given output, and we can compute it directly instead of brute forcing.

## Inverting it and getting the flag

We have both halves now:

```
computed = f(x) = ~( rol(x ^ K1, 17) * MUL )      (from emulate_table.py)
win  <=>  computed == TARGET = 0xB8491337C0DEBABE   (from sweep.py)
```

Since `f` is a bijection, the one and only accepted input is `x = f_inverse(TARGET)`. To invert, undo each step in reverse order: `not` the target, multiply by the modular inverse of `MUL`, rotate right by 17, then XOR with `K1`. The result is the eight input bytes in little-endian order.

`solve.py` does exactly that, then runs the real binary on the recovered bytes to confirm, and independently reproduces the flag decryption offline as a cross-check:

```
$ python3 solve.py
[*] decoded genuine check : computed == 0xB8491337C0DEBABE
[*] barrier3 leaf         : ~( rol(x ^ 0xA5A5A5A5DEADBEEF, 17) * 0x00000100000001B3 )
[*] inverted preimage  x* : 0x28382F8D1780680F
[*] accepted input (8 LE) : 0f 68 80 17 8d 2f 38 28
[*] flag (offline decrypt): HTB{REDACTED}
[*] binary stdout         :
H4D5_UP_Y0U_M4D3_IT
HTB{REDACTED}
[*] flag (from binary)    : HTB{REDACTED}
```

One more nice detail: the flag is not stored anywhere in the file as plaintext. On the win path the program seeds a SplitMix64 keystream with your recovered input and XOR-decrypts the embedded ciphertext with it. The key is the preimage, so the flag literally does not exist in readable form until you have already solved the check. No grepping your way to the answer.

Feed the eight bytes to the binary directly and it finally drops the take that got cut, one dry confession line followed by the flag:

```
$ printf '\x0f\x68\x80\x17\x8d\x2f\x38\x28' | ./secondhand
H4D5_UP_Y0U_M4D3_IT
HTB{REDACTED}
```
