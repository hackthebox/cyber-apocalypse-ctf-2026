![](../../assets/banner.png)



<img src="../../assets/htb.png" style="margin-left: 20px; zoom: 80%;" align=left />    	    <font size="6">Ashbyte Arcade</font>

​		23<sup>rd</sup> July 2026

​		Prepared By: w3th4nds

​		Challenge Author(s): rasti

​		Difficulty: <font color=orange>Medium</font>

​		Classification: Official




# Synopsis

Ashbyte Arcade is a **Medium** difficulty crypto challenge built around a hand-rolled 2-round reduction of AES, nicknamed `SnowCipher`, running in ECB mode behind a Flask arcade front end. The "death-save" endpoint is a disguised chosen-plaintext oracle: every in-game death encrypts a validated 16-byte save state under a fixed per-session key. Because the state format enforces checksums (`LRC`, `TRACK`, `FLAGS`) and a rune-balance XOR, the player has to construct valid plaintext pairs whose only difference sits in one deliberately unconstrained field. That constraint is exactly what an **impossible differential** attack needs: a single-row input difference that lets a difference-distribution-table (DDT) filter throw away wrong last-round-key bytes across a handful of oracle calls, well inside the 16-life budget.

# Description

Among the Ash-Vault's stranger discoveries stands a curious relic unlike any other. An ancient entertainment cabinet whose strange machinery guards more than high scores. The Cinderbound dismissed it as nonsense. They were wrong. Sometimes even games remember secrets the realm has forgotten.

## Skills Required

- Reading and reimplementing an unfamiliar block cipher from source.
- Recognizing AES building blocks (S-box, ShiftRows, MixColumns, Rijndael key schedule) inside custom code.
- Differential cryptanalysis fundamentals: difference distribution tables, truncated differentials.
- Constructing a chosen-plaintext oracle under format/checksum constraints.
- Scripting an interactive HTTP oracle with `requests`.

## Skills Learned

- How reduced-round AES leaks its last-round key through an **impossible differential** distinguisher.
- Building a Sbox DDT and using it to prove certain output differences can never occur for a given input difference.
- Recovering a master key from a recovered round key by running the Rijndael key schedule backwards.
- Working around an application-layer checksum (LRC + two custom "seal" bytes) to still control exactly the bytes needed for a differential attack.
- Budgeting oracle calls: each life spent buys one chosen-plaintext pair, so the attack has to converge in single-digit queries.

# Challenge Design

## The cartridge save format

Every save is 16 bytes, and `require_state_format` in `app.py` enforces all of it server-side before any encryption happens:

```text
0  SIG       fixed 0x4e
1  HP        1..9
2  SECTOR    9 required to win
3  X         18 required to win
4  Y         13 required to win
5  SCORE_LO
6  SCORE_MID
7  SCORE_HI  score >= 10,000,000 required to win
8  RUNE_A    0xc3 required to win
9  RUNE_B    0x7a required to win
10 RUNE_C    0xb0 required to win
11 RUNE_D    0xae required to win
12 TRACK     derived seal: sector*19 + x*7 + y*13 + score_lo mod 256
13 DEATHS    0..31 client crash counter
14 FLAGS     derived seal: hp + sector + x + y + track mod 256
15 LRC       XOR of bytes 0..14
```

`TRACK` and `FLAGS` are seals over almost every other byte, and `LRC` covers the whole record. Wiggling `HP`, `SECTOR`, `X`, `Y`, or `SCORE` for a differential attack breaks two or three checksums at once. The **rune quartet** (bytes 8-11) is the one place the designer left slack: the only constraint on it is `RUNE_A ^ RUNE_B ^ RUNE_C ^ RUNE_D == 0xa7`, and none of the runes feed `TRACK` or `FLAGS`. Two states that differ only in the runes, with the four byte deltas themselves XORing to zero, keep every checksum intact. That is the entire design opening for the attack.

## The oracle

`/api/death` is the only chosen-plaintext surface:

- decrements one life from the session's budget of 16 (`STARTING_LIVES`), even for a rejected save, so garbage probes are expensive
- validates the submitted `state_hex` with `require_state_format`
- refuses to encrypt a state that already satisfies the win condition
- otherwise encrypts the state under the session's `SnowCipher` key and returns the ciphertext

`/api/load` is the payoff: submit 32 ciphertext bytes (one block plus one PKCS#7 padding block), the server decrypts with the same session key, and if the recovered plaintext is a valid winning state, it prints the flag.

Sixteen lives is not a lot of chosen plaintexts. The cipher only needs to survive a handful of them.

# Enumeration

Players receive the Flask app source directly:

```console
$ unzip crypto_ashbyte_arcade.zip
$ cd crypto_ashbyte_arcade
$ ls
app.py  crypto.py  flag.txt  static  templates
```

## Step 1: Read the routes

```console
$ grep -n '@app\.' app.py
168:@app.get("/")
172:@app.post("/api/start")
177:@app.post("/api/death")
214:@app.post("/api/load")
```

`/api/start` mints a session (`session_id`, a fresh random 16-byte `key`, 16 lives). `/api/death` is the oracle described above. `/api/load` is the only place `flag.txt` is ever read.

## Step 2: Read the cipher

```console
$ cat crypto.py
```

`crypto.py` ships a 256-entry `B` table, its inverse `IB`, and an `r_con` table, then a class called `SnowCipher` with `encrypt_block` / `decrypt_block`. None of it is obfuscated. It reads like code meant to be read.

## Step 3: Confirm the tables are stock AES

```console
$ python3 -c "from crypto import B, IB; print(B[:8]); print(IB[:8])"
(99, 124, 119, 123, 242, 107, 111, 197)
(82, 9, 106, 213, 48, 54, 165, 56)
```

In hex that's `63 7c 77 7b f2 6b 6f c5` and `52 09 6a d5 30 36 a5 38`, byte for byte the Rijndael S-box and its inverse. `r_con` matches the standard Rijndael round-constant table too. `SnowCipher` is not a novel primitive. It is AES's own S-box, ShiftRows, MixColumns, and key schedule, wired up for **two rounds** instead of ten.

# Reverse Engineering & Analysis

## `encrypt_block`

```python
def encrypt_block(self, block):
    rk = _ek(self.KEY)
    s = b2m(block)
    s = self._ark(s, rk[0])
    s = self._sb(s); s = self._sr(s); s = self._mc(s)
    s = self._ark(s, rk[1])
    s = self._sb(s); s = self._sr(s); s = self._mc(s)
    s = self._ark(s, rk[2])
    return m2b(s)
```

That is whitening plus two full SubBytes -> ShiftRows -> MixColumns -> AddRoundKey rounds, three round keys total (`rk[0]`, `rk[1]`, `rk[2]`), each derived from the session key by `_ek`, the same expansion routine real Rijndael uses. Unlike standard AES, the second round keeps `MixColumns` before the final key addition. There is no "skip MixColumns on the last round" special case, so `rk[2]` sits directly on top of ciphertext with only one MixColumns layer between it and the S-box output. That is the layer the attack targets.

## Encryption mode

`encrypt()` pads the 16-byte state to 32 bytes with PKCS#7 and encrypts each block independently: plain ECB, one call per session with a key that never rotates. Every `/api/death` response in a session is encrypted under the exact same key, which is what turns 16 lives into 16 chances at the same fixed-key oracle instead of 16 unrelated one-shot encryptions.

## Why two rounds specifically

A single round of AES gives an attacker only one S-box layer and one MixColumns layer between a chosen input difference and the output, nowhere near enough diffusion to hide which byte differences are reachable. Real AES needs its full ten rounds (and specifically resists 4-round impossible-differential distinguishers, the strongest known against that primitive) before this class of attack runs out of room. At two rounds, an input difference confined to a single row still only crosses one MixColumns application before the recoverable last-round key, so a DDT-based impossible-differential filter has more than enough signal to work with in single-digit queries.

# Debugging

Local testing is just running the Flask app and hitting it with `curl`/`requests`. No VM, no gdbstub required.

```console
$ pip install -r requirements.txt
$ cd challenge && python3 app.py &
$ curl -s -X POST http://127.0.0.1:5000/api/start
{"lives":16,"ok":true,"session_id":"d3ce1e7f1f21fd173de880b18006301e"}
```

To sanity-check the S-box claim from the Enumeration step, a quick REPL check on the difference distribution table is enough:

```python
>>> from crypto import B as SBOX
>>> def reachable_diffs(alpha):
...     return {SBOX[x] ^ SBOX[x ^ alpha] for x in range(256)}
>>> len(reachable_diffs(1))
126
```

For `alpha = 1`, only 126 of the 256 possible output differences ever occur. The S-box is a bijection on values but not on differences, and that gap is exactly what the impossible-differential filter exploits.

# Solution

## Exploitation Chain Overview

```
1.  Build the S-box DDT once (input diff -> which output diffs are impossible).
2.  Loop, spending one life per iteration:
    a. Craft two valid save states P1, P2 differing only in bytes 8..11,
       with the four rune deltas XORing to zero (checksums stay valid).
    b. Query oracle(P1), oracle(P2)  ->  C1, C2   (one /api/death call each)
    c. alpha = P1 ^ P2                (nonzero only in one "row": bytes 8..11)
    d. Use the DDT to compute, per output-block offset, the set of
       ciphertext-side byte differences that are IMPOSSIBLE for the true key.
    e. For every remaining rk2 byte candidate at that offset, partially
       decrypt (C1, C2) one round back and check the resulting difference
       against the impossible set. Drop candidates that produce an
       impossible difference.
3.  After ~6-7 pairs the surviving candidate space per byte shrinks to a
    brute-forceable few hundred thousand combinations.
4.  Brute force rk2, run the key schedule backwards to the master key,
    verify by re-encrypting known plaintexts.
5.  Encrypt the winning save state under the recovered key.
6.  POST it to /api/load -> flag.
```

## Stage 1 — Chosen plaintext pairs that survive every checksum

```python
def choose_plaintexts():
    while True:
        a, b, c = secrets.token_bytes(3)
        r1 = [a, b, c, RUNE_XOR ^ a ^ b ^ c]
        d = list(secrets.token_bytes(3))
        d.append(d[0] ^ d[1] ^ d[2])
        if 0 in d:
            continue
        r2 = tuple(r1[i] ^ d[i] for i in range(4))
        p1 = pack_state(runes=tuple(r1))
        p2 = pack_state(runes=r2)
        alpha = differential(p1, p2)
        if alpha[:8] == b"\x00" * 8 and alpha[12:] == b"\x00" * 4 and all(alpha[8:12]):
            assert p1[15] == p2[15]
            return p1, p2
```

`r1` is a random, individually-balanced rune quartet. `d` is a random nonzero delta whose four bytes also XOR to zero, applied to `r1` to get `r2`. Because `d` XORs to zero, `r2` is balanced too, and since only bytes 8-11 moved, `TRACK`, `FLAGS`, and `LRC` are untouched. Both `p1` and `p2` pass `require_state_format`, and their difference `alpha` is nonzero in exactly the four rune bytes.

## Stage 2 — The impossible-differential filter

```python
def generate_sbox_ddt():
    table = [None] * 256
    for i in range(256):
        for j in range(256):
            diff_input = i ^ j
            diff_output = SBOX[i] ^ SBOX[j]
            if table[diff_input] is None:
                table[diff_input] = [set() for _ in range(256)]
            table[diff_input][diff_output].update((i, j))
    return table
```

`DDT[alpha][beta]` is the set of input byte values that realize input difference `alpha` and output difference `beta`. If that set is empty, `beta` is **impossible** for that `alpha`, a fact the S-box guarantees unconditionally, independent of any key.

`AddRoundKey(rk[0])` doesn't touch the difference (both plaintexts share the same key), so `alpha` hits the round-1 S-box unchanged. `get_impossible_bytes_per_offset_by_alpha` looks up, for each of the four active rune-row bytes, which output differences the S-box cannot produce, then pushes each impossible byte value through round-1's `ShiftRows` and `MixColumns` to find where it would land at the ciphertext offsets. That builds, per offset, the set of byte differences that a *correct* key can never produce there.

## Stage 3 — Killing wrong last-round-key bytes

```python
for o in range(16):
    survivors = []
    for rk2_byte in round_key_candidates[o]:
        c_inv = [
            m2b(sub_bytes(inv_shift_rows(add_round_key(
                inv_mix_columns(b2m(c)),
                inv_mix_columns(b2m(bytes([rk2_byte]) * 16)),
            )), IB))
            for c in CT
        ]
        beta = differential(*c_inv)
        if beta[o] not in impossible_bytes_per_offset[o]:
            survivors.append(rk2_byte)
    round_key_candidates[o] = survivors
```

For every candidate value of a last-round-key byte, both ciphertexts get partially decrypted one round back. If the resulting difference at that offset falls inside the "impossible" set built in Stage 2, that candidate is provably wrong (the real key can never produce it) and gets dropped. Repeating with a fresh random pair each round keeps chipping at the survivor lists:

```console
[+] pair_index = 1 | candidates per offset = [126, 134, 120, 130, 128, 126, 134, 128, 130, 118, 118, 128, 130, 132, 110, 122] | total = 3887607045523732248207871180800000
[+] pair_index = 2 | candidates per offset = [60, 64, 60, 68, 66, 63, 60, 66, 65, 60, 54, 66, 64, 64, 57, 61]                | total = 51066724147568435213107200000
[+] pair_index = 3 | candidates per offset = [35, 36, 30, 32, 35, 34, 24, 33, 38, 30, 32, 28, 33, 34, 34, 34]                | total = 1510349559130635632640000
[+] pair_index = 4 | candidates per offset = [18, 21, 13, 21, 16, 15, 13, 17, 20, 17, 12, 15, 23, 17, 18, 16]                | total = 37720603246749696000
[+] pair_index = 5 | candidates per offset = [12, 10, 5, 9, 8, 7, 9, 10, 10, 13, 6, 5, 12, 7, 7, 11]                        | total = 686529043200000
[+] pair_index = 6 | candidates per offset = [3, 5, 3, 4, 1, 5, 6, 5, 6, 7, 5, 3, 6, 4, 3, 9]                               | total = 11022480000
[+] pair_index = 7 | candidates per offset = [1, 3, 3, 2, 1, 3, 3, 2, 5, 1, 3, 2, 1, 3, 1, 5]                               | total = 145800
```

Seven pairs, seven lives out of the sixteen available, bring the joint search space for the 16-byte last-round key down from `256^16` to `145,800`. If a run gets unlucky and the space is still too large after seven pairs, the solver just restarts with a fresh session rather than burning the rest of the budget.

## Stage 4 — Brute forcing the survivors and recovering the master key

```python
for candidate in itertools.product(*(round_key_candidates[i] for i in range(16))):
    test_key = candidate_round_key_to_master(candidate)
    cipher = SnowCipher(test_key)
    if any(cipher.encrypt_block(pt) != ct for pt, ct in zip(PT, CT)):
        continue
    print(f"[+] recovered key: {test_key.hex()}")
```

`candidate_round_key_to_master` re-expresses the candidate bytes in the coordinate system the last `AddRoundKey` actually uses, then walks the key schedule backwards two rounds (`recover_master_key`, adapted from the standard Rijndael-inverse-key-schedule technique) to reconstruct the original 16-byte session key. Each surviving candidate is verified by re-encrypting the known plaintexts and comparing against the observed ciphertexts, so a false positive essentially can't survive verification against multiple pairs.

Running it end to end against a live instance:

```console
$ python3 solver.py 127.0.0.1:5000
[+] session = eca169ea28f056b2b8c0b15db401afdf
[+] pair_index = 1 | ... | total = 3887607045523732248207871180800000
...
[+] pair_index = 7 | ... | total = 145800
100%|██████████| 145800/145800 [00:08<00:00, 16800.34it/s]
[+] recovered key: 5bf656e54922e16a9b987e6ca9d44c5a
[+] forged.hex() = 'a3794da498955f521bbe5cc77ff769325dc3d39a3bd7f0a4068b35da6de1a873'
```

## Stage 5 — Forging the win and loading it

```python
def winning_state():
    return pack_state(hp=5, sector=9, x=18, y=13, score=10_000_000,
                       runes=(0xC3, 0x7A, 0xB0, 0xAE), deaths=0)

cipher = SnowCipher(recovered_key)
forged = cipher.encrypt(winning_state())
requests.post(f"{URL}/api/load", json={"session_id": sid, "ciphertext": forged.hex()})
```

With the session key in hand, encrypting the winning save is trivial: it is the same `SnowCipher` used server-side, run locally. `/api/load` decrypts the forged ciphertext with the same key, `require_state_format` and `is_winning_state` both pass, and the response carries the flag.

### Comments

- **Rune bytes as the only unchecked field.** Every other byte in the save format feeds at least one checksum. The rune quartet's sole constraint (`XOR == 0xa7`) is loose enough to let a player construct arbitrary balanced deltas while leaving `TRACK`, `FLAGS`, and `LRC` untouched: the single-row input difference an impossible-differential attack needs.
- **A life-gated oracle, not a free one.** A malformed probe still costs a life, so the intended solve has to reason about the state format correctly before querying. The DDT filter is chosen specifically because it converges inside single-digit queries rather than needing hundreds.
- **Two rounds, not four.** Impossible-differential cryptanalysis on real AES famously tops out around four rounds. Reducing to two here keeps the same technique reachable inside a CTF time budget while still requiring the player to derive it rather than reuse a canned tool.
- **ECB with a session-lifetime key.** A fresh key per encryption would kill the attack outright. A session-lifetime key is what turns 16 independent life-spends into 16 queries against one fixed unknown.
