![](../../assets/banner.png)



<img src="../../assets/htb.png" style="margin-left: 20px; zoom: 80%;" align=left />    	    <font size="6">Ancient Artifacts</font>

​		24<sup>th</sup> July 2026

​		Prepared By: w3th4nds

​		Challenge Author(s): Babafaba

​		Difficulty: <font color=red>Hard</font>

​		Classification: Official




# Synopsis

Ancient Artifacts is a **Hard** difficulty crypto challenge that chains three separate weaknesses in `zlib`'s two checksum functions, Adler-32 and CRC-32, neither of which was ever meant to be used as a cryptographic hash. A server picks a random 128-bit number, never reveals its Adler-32 checksum directly, and asks the player to submit numbers that collide with it under Adler-32 before finally checking a CRC-32 relation over everything submitted. Because both checksums are algebraically simple (Adler-32 is affine mod a small prime, CRC-32 is linear over GF(2)), all three steps, recovering the hidden checksum, forging collisions, and satisfying the CRC-32 checks, reduce to solvable linear algebra: a lattice reduction for the first, a random walk for the second, and a GF(2) linear system for the third.

# Description

Years of decrees, ledgers, and witness rolls have been packed into an aging archive beneath Crownspire. The records remain unreadable at first glance, yet every archive leaves traces of its own construction. Recover the hidden truth before it is buried forever.

## Skills Required

- The internal structure of Adler-32 and CRC-32, not just that they exist.
- Lattice basis reduction (LLL) and how to model an unknown-digit problem as a short-vector search.
- Linear algebra over `GF(2)`.
- Comfort reading and adapting someone else's SageMath exploit script.

## Skills Learned

- Why "non-cryptographic checksum" means more than just "short output": Adler-32 and CRC-32 are both easy to invert and forge precisely because they're linear/affine functions of the input.
- Turning a partial-plaintext hash into a Hidden-Number-Problem-style lattice attack.
- Exploiting invariants (digit-sum preservation) to cut a brute-force search down to a random walk.
- Building a controllable linear system out of many small forgeries to hit two checksum targets simultaneously.

# Enumeration

Players receive a single file:

```console
$ unzip crypto_ancient_artifacts.zip
$ cd crypto_ancient_artifacts
$ ls
server.py
```

## Step 1: Read the protocol

```python
signal.alarm(30)
num = secrets.randbits(128)
h = apply_rune(zlib.adler32, num)              # never printed!

my_salt = secrets.randbits(128)
your_salt = int(input("your salt: "))
assert your_salt.bit_length() >= 128
salted = apply_rune(zlib.adler32, my_salt, num, your_salt)
print(f"{my_salt = }")
print(f"{salted = }")
```

`apply_rune(rune, *nums)` just concatenates the decimal string representation of each argument and feeds the bytes to whichever checksum function is passed in. The server rolls a secret 128-bit `num`, computes `h = adler32(str(num))`, but **never prints `h`**. All the player gets is `my_salt` (the server's own random salt) and `salted`, the Adler-32 checksum of `str(my_salt) + str(num) + str(your_salt)`, where `your_salt` is whatever the player sent first (required to be at least 128 bits).

## Step 2: Read the menu

```python
MENU = '''Options:
1. Give number
2. Stop
3. Exit
'''
nums = []
while True:
    option = int(input(MENU))
    if option == 2: break
    elif option == 1:
        your_num = int(input("n: "))
        assert your_num not in nums
        assert apply_rune(zlib.adler32, your_num) == h
        nums.append(your_num)
    else: exit("bye")

assert apply_rune(zlib.crc32, *nums) == h
assert functools.reduce(lambda a, b: a ^ b, [apply_rune(zlib.crc32, num) for num in nums]) == h
print(open("flag.txt").read())
```

Every number submitted through option 1 must individually satisfy `adler32(str(n)) == h`, and any failure kills the connection outright (a bare `except: exit("bye")` wraps the whole loop). Once the player stops, the server checks two more things over the full list of submitted numbers: the CRC-32 of their concatenation must equal `h`, and the XOR of their individual CRC-32s must also equal `h`. Only then does it print the flag. Nothing about `h` is ever handed over directly, and no submission is allowed to be wrong even once.

# Reverse Engineering & Analysis

## Adler-32 is affine, not random

Adler-32 packs two running sums into one 32-bit value: for message bytes `b_1..b_n`,

```
A = 1 + sum(b_i)                 mod 65521
B = sum_i (n - i + 1) * b_i + n  mod 65521
adler32 = (B << 16) | A
```

Both `A` and `B` are affine functions of the byte values, weighted by position for `B`. Since the message here is always three concatenated decimal strings, and two of them (`my_salt`, `your_salt`) are fully known, `salted`'s `A` and `B` components reduce to two linear equations in the digits of `num` alone, each digit contributing a known ASCII weight at a known position.

## Recovering the hidden checksum with a lattice

A 128-bit number has 38-40 decimal digits, 39 on average. Treating each unknown digit as a bounded variable in `[0, 9]` and the two Adler-32 congruences as linear constraints turns this into a small-value linear recovery problem: exactly the shape LLL is good at. `htb/solver.py`'s `find_h` builds a lattice with one row per candidate digit position, plus rows encoding the `A` and `B` congruences scaled up by `10^100` so any nonzero residual dominates the vector norm and gets reduced away, and a marker column (value `9`, deliberately un-guessable as a real digit-sum coincidence) used to pick the correct row out of the reduced basis:

```python
dim = len(salts) + avg_len + 2
M = matrix(ZZ, dim - 1, dim)
for i in range(avg_len):
    M[i, i] = 1
    M[i, avg_len] = 1
    ...
B = M.LLL()
```

Because `avg_len = 39` is an assumption, not a guarantee, this only works when `num` actually has 39 digits, roughly (but not exactly) half the time for a uniformly random 128-bit integer. When it doesn't, the reduced basis has no row matching the marker column, and the intended move is to just reconnect and try again with a fresh `num`.

The recovered digit string doesn't have to be bit-identical to the server's real `num`, it just has to be *some* number whose Adler-32 checksum equals the same `h`. Since every later check only ever compares against `h`, not against `num` itself, any valid preimage works equally well as a starting point.

## Turning one preimage into arbitrarily many

`random_mutation` takes the recovered preimage's digit list and repeatedly increments one random digit while decrementing another:

```python
def random_mutation(digits_list):
    while True:
        i, j = random.randint(...), random.randint(...)
        if digits_list[i] == 9: continue
        if digits_list[j] == 0: continue
        digits_list[i] += 1
        digits_list[j] -= 1
        return digits_list
```

This preserves the digit sum exactly, which means Adler-32's `A` component (a function only of the digit sum) never changes under this mutation. All that's left to match is the 16-bit `B` component, checked via `>> 16`, so a plain random walk finds a fresh valid collision in a search space of only 2<sup>16</sup>, cheap enough to repeat well over a hundred times per connection.

## CRC-32 is linear over GF(2)

CRC-32 of a *fixed-length* message is a linear function over `GF(2)`: XORing a fixed difference into one block of a longer concatenation changes the overall CRC-32 by a value that depends only on that block's position and the XOR delta, not on the rest of the message. That's exactly what `find_crc_collision` exploits. For each of 64 "slots" it prepares two valid Adler-32-`h` collisions, a `zero` variant and a `one` variant, both 39 digits long, and computes the exact CRC-32 delta that swapping one for the other contributes to (a) the CRC-32 of the full 64-block concatenation, and (b) the running XOR of the 64 individual CRC-32s. That gives 64 unknown bits (one "use zero or use one" choice per slot) and 64 linear equations over `GF(2)` (32 bits from the concatenation target, 32 from the XOR target), solved directly with ordinary GF(2) linear algebra.

# Debugging

Local testing just needs the server and `socat`:

```console
$ cd challenge
$ socat -dd TCP-LISTEN:1337,reuseaddr,fork exec:"python3 -u server.py" &
$ nc 127.0.0.1 1337
your salt: 340282366920938463463374607431768211456
my_salt = 249422614574009771853899435646236797845
salted = 3210747901
Options:
1. Give number
2. Stop
3. Exit
```

`h` itself never shows up anywhere in that output, confirming there's no shortcut around the lattice step.

# Solution

## Exploitation Chain Overview

```
1. Send a >=128-bit salt.
2. Receive my_salt and salted = adler32(my_salt || num || your_salt).
3. Recover h = adler32(num) via lattice reduction (retry with a fresh
   connection whenever num's digit count isn't the assumed 39).
4. Random-walk from that preimage to build 128 more Adler-32-h collisions
   (64 "zero" variants, 64 "one" variants), exploiting digit-sum invariance.
5. Solve a 64x64 GF(2) linear system to choose, per slot, zero or one, so
   that BOTH the concatenated CRC-32 and the XOR of individual CRC-32s
   equal h.
6. Submit the resulting 64 numbers via option 1, then option 2.
7. Server checks pass -> flag.
```

## Stage 1 — Recovering `h`

```python
num, h = find_h([(server_salt, my_salt)], [salted])
while num is False:
    # digit-length assumption didn't hold for this num; reconnect and retry
    conn = get_conn()
    ...
    num, h = find_h([(server_salt, my_salt)], [salted])
```

Every retry means the server rolled a fresh `num` with a different digit count than 39. In practice this took a couple dozen reconnects in one live run before landing on a 39-digit `num`:

```console
[+] server_salt=284482151024949751032134917930126089822
[+] salted hash =2625970054
[-] lattice attack failed this round (digit-length assumption off), retrying with fresh connection
...
[+] server_salt=1314337240323854837780720402518361833
[+] salted hash =1544298274
[+] recovered preimage num = 565445444444444443444443444443444434443
[+] true adler32(num) = h = 2669348845
```

## Stage 2 — Building 128 collisions

```python
colliding_zeros = [find_collision(num, h) for _ in range(64)]
colliding_ones  = [find_collision(num, h) for _ in range(64)]
```

Each call independently random-walks from the recovered preimage until it lands on a new 39-digit number with the same Adler-32 checksum `h`. All 128 results are genuine `adler32(str(n)) == h` collisions, satisfying the per-submission check the server enforces on every single one.

## Stage 3 — Solving the GF(2) system

```python
mat = []
for i, o in enumerate(colliding_ones):
    inp = zero_block*i + xor(o, colliding_zeros[i]) + zero_block*(63 - i)
    out = zlib.crc32(inp) ^ z
    mat.append(bits(out) + bits(zlib.crc32(o) ^ zero_crcs[i]))

sol = mat.solve_right(vec)   # vec encodes both target checksums at once
payload = [ones[i] if sol[i] else zeros[i] for i in range(64)]
```

`sol` is a 64-bit vector, one bit per slot, telling the solver which of the two prepared variants to actually submit. By construction, the resulting 64 numbers satisfy every constraint at once: each is individually a valid Adler-32-`h` collision, their concatenation's CRC-32 equals `h`, and the XOR of their individual CRC-32s also equals `h`.

## Stage 4 — Submitting and reading the flag

```python
for c in collisions:
    conn.sendline(b"1")
    conn.sendline(str(c).encode())
conn.sendline(b"2")
flag = conn.recvall().decode().strip().split()[-1]
```

Run against a local instance end to end:

```console
[+] searching for 128 adler32(h)-colliding numbers (random digit-swap walk)...
[+] built 64 numbers satisfying both the concat-CRC32 and XOR-CRC32 constraints
[+] flag = HTB{REDACTED}
```

```console
HTB{REDACTED}
```

### Comments

- **`h` is never leaked, and it doesn't need to be.** The whole first stage exists only because the server withholds `h` directly. Recovering *a* valid preimage of the same checksum is exactly as useful as recovering the server's literal `num`, since every later check only ever compares against `h`.
- **The digit-sum trick is the hinge the whole exploit swings on.** Without a cheap way to generate more Adler-32 collisions after the first one, there'd be no way to build the 64-slot GF(2) system in stage three at all. A single lattice-recovered preimage becomes 128 collisions purely by walking a digit-sum-preserving mutation.
- **Two different "linear" structures, two different tools.** Adler-32 is linear over the integers mod a prime, so recovering an unknown message needs a lattice. CRC-32 is linear over `GF(2)`, so forging a controlled combination of messages just needs ordinary binary linear algebra. Neither tool works on the other checksum.
- **The retries are expected, not a bug.** Both the lattice step (wrong digit count) and, occasionally, the GF(2) solve (an unlucky, rank-deficient batch of 128 random collisions) can fail on a given attempt. A working solver just wraps each in a loop and tries again.
