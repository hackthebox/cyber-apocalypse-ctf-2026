![](../../assets/banner.png)



<img src="../../assets/htb.png" style="margin-left: 20px; zoom: 80%;" align=left />    	    <font size="6">Fractured Seal</font>

​		23<sup>rd</sup> July 2026

​		Prepared By: w3th4nds

​		Challenge Author(s): muhammadta1ha

​		Difficulty: <font color=green>Easy</font>

​		Classification: Official




# Synopsis

Fractured Seal is an **Easy** difficulty crypto challenge about RSA key recovery from a partially redacted PEM file. Players get an RSA-encrypted flag and a hand-censored `RSA PRIVATE KEY` file where most fields are blanked out with `*` characters. Walking the ASN.1 structure by hand shows the modulus `n` and exponent `e` are fully intact, while the private exponent and one prime are entirely hidden, and the second prime is more than half visible in its high-order bits. That's exactly the setup Coppersmith's "factoring with a hint" theorem was built for: recover the missing low bits of the partially known prime via lattice reduction, factor `n`, and rebuild the private key.

# Description

One of the Registry's oldest key-scrolls survived the fall of Crownspire, though time and fire spared only fragments of its writing, and most in the vault dismissed it as useless. Caldrin didn't. She always said a seal doesn't have to be whole to still remember the door it once opened.

## Skills Required

- RSA internals: modulus, exponents, the two primes, and how they relate.
- ASN.1 / DER key structures and how to walk them by hand.
- Familiarity with SageMath and Coppersmith-style lattice attacks.

## Skills Learned

- Recovering an RSA private key from partial knowledge of one prime factor.
- Parsing a PEM/DER structure field by field instead of trusting a library to load a broken key.
- Applying Coppersmith's method (via `small_roots`) to the classic "factoring with a hint" problem.

# Enumeration

Players receive two files:

```console
$ unzip crypto_fractured_seal.zip
$ cd crypto_fractured_seal
$ ls
encrypt.py  flag.enc  fractured_seal.pem
```

## Step 1: Read `encrypt.py`

```python
p = getPrime(1024)
q = getPrime(1024)
n = p * q
e = 0x10001
d = pow(e, -1, (p-1)*(q-1))

m = bytes_to_long(open('flag.txt', 'rb').read())

open('seal.pem', 'wb').write(RSA.construct((n, e, d)).export_key())
open('flag.enc', 'wb').write(long_to_bytes(pow(m, e, n)))
```

Textbook RSA, no OAEP, no padding oracle to chase. Two 1024-bit primes, the standard `e = 65537`, and the flag encrypted as a single raw modular exponentiation. Whoever built the challenge instance then took the resulting `seal.pem` (a complete private key) and hand-redacted it into `fractured_seal.pem`, the only key material players actually receive.

## Step 2: Walk the PEM structure

```console
$ cat fractured_seal.pem
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAjK59ahXlX7a+oF+jt5icukpGeNXXgQO4D3jPeLaGAupJm6a6
9PnWCf0W3QDhmCPxLYWSr1C4DvxP23UlvP8Lcfu+w/oIS0jDHkfnv+m1Qku/ii9w
...
7HFFfXYNoKjnqgp+LOmLwQGQeO2Yo1Hb8SCVd***************************
****************************************************************
...
```

`RSA PRIVATE KEY` is the PKCS#1 form, a bare DER `SEQUENCE` with no algorithm wrapper, laid out as:

```text
RSAPrivateKey ::= SEQUENCE {
  version           INTEGER,
  modulus           INTEGER,  -- n
  publicExponent    INTEGER,  -- e
  privateExponent   INTEGER,  -- d
  prime1            INTEGER,  -- p
  prime2            INTEGER,  -- q
  exponent1         INTEGER,  -- d mod (p-1)
  exponent2         INTEGER,  -- d mod (q-1)
  coefficient       INTEGER,  -- (inverse of q) mod p
}
```

Every `INTEGER` is tagged `02`, followed by a length (`81 xx` for a one-byte length, `82 xx xx` for two bytes), followed by that many content bytes. Feeding the base64 through CyberChef's `From Base64` → `To Hex` (set to ignore non-alphabet characters, so the `*` runs are simply skipped) and walking the tags in order gives, for a 2048-bit key:

| Field | Content length | Visible in `fractured_seal.pem` |
|---|---|---|
| `version` | 1 byte | complete |
| `n` (modulus) | 257 bytes | complete |
| `e` (public exponent) | 3 bytes | complete (`010001`) |
| `d` (private exponent) | 256 bytes | **fully redacted** |
| `prime1` | 129 bytes | **fully redacted** |
| `prime2` | 129 bytes | **leading 73 bytes visible**, rest redacted |
| `exponent1`, `exponent2`, `coefficient` | — | **fully redacted** |

Once the tag walk is lined up against the visible base64 runs, the leak is precise: `n` and `e` are complete (expected, they're public anyway), `d` and one prime are entirely gone, and `prime2` keeps its top 72 real value bytes (the 73rd visible byte is just the DER sign-padding `0x00`), meaning **576 of its 1024 bits are known**, all in the high-order position. `d`, `exponent1/2`, and `coefficient` are never needed anyway once a prime is recovered, so their absence doesn't matter.

# Solution

## Finding the vulnerability

576 known high-order bits out of 1024 is well past the 50% mark, and there's a classic named result for exactly this situation: Coppersmith's 1996 "factoring with a hint," which shows that if you know the high-order bits of one prime factor of `N = p*q` down to fewer than `N^(1/4)` unknown bits, you can recover the rest in polynomial time via lattice reduction. Here `N` is 2048 bits, so `N^(1/4)` is about 512 bits; the redacted prime is missing only 448 low-order bits, comfortably inside that bound.

Writing the known prime as `prime2 = p_upper * 2^t + x0`, where `p_upper` is the known high part, `t = 448` is the number of missing bits, and `x0` (the unknown low part) is small, gives a monic polynomial

```
f(x) = p_upper * 2^t + x   (mod n)
```

with a small root `x0`. Coppersmith's method finds it via lattice-basis reduction (LLL) over a basis built from powers of `f`, implemented directly by SageMath's `f.small_roots()`.

## Exploitation

```sage
from sage.all import *

n = 0x8cae7d6a15e55fb6bea05fa3b7989cba4a4678d5d78103b80f78cf78b68602ea499ba6baf4f9d609fd16dd00e19823f12d8592af50b80efc4fdb7525bcff0b71fbbec3fa084b48c31e47e7bfe9b5424bbf8a2f707a1cbf89136e51e687f3c2b8000d1716f2686a4e48d08822e64b0ffc2b3218c4496d47bcf7c78b66360e600a00dbe7e22e38df603047962c97aef6b9e56f4eda27b648d67643ce7d9006f42108ff0cadcbb801eab6e13b1d59b6283c9d5348e388c173e6e870714e678d79c775945fac24da51604b2f1984f0f09b22ecbc849aa12fe883d4e7304d2f18a3cc684eda1cec71457d760da0a8e7aa0a7e2ce98bc1019078ed98a351dbf1209575
e = 0x10001
p_upper = 0xc0b1b1709eff60282af463c34b5e9c1cf35912662b6d25fe6adcd40413b68cb620d106d77e2b532077d4fb9e43a88c4540e72ef826a1acf41044ea1900020f8342dd68677edd1dff

bits_p = 1024
bits_upper = Integer(p_upper).nbits()
t = bits_p - bits_upper
print(f"[-] known bits: {bits_upper}  |  missing bits: {t}")

PR.<x> = PolynomialRing(Zmod(n))
f = p_upper * (2^t) + x

roots = f.small_roots(X=2^t, beta=0.4)

x0 = int(roots[0])
q = p_upper * (2**t) + x0
assert n % q == 0

p = n // q
phi = (p - 1) * (q - 1)
d = inverse_mod(e, phi)
print("q =", hex(q))
print("p =", hex(p))
print("d =", hex(d))
```

`beta=0.4` is a conservative choice below the theoretical `0.5`, trading a slightly larger lattice for a comfortable safety margin so `small_roots` reliably finds `x0` on the first try instead of needing tuning.

## Getting the flag

With `n` and the recovered `d`, decrypting `flag.enc` is a single modular exponentiation, no Sage required for this part:

```python
from Crypto.Util.number import long_to_bytes, bytes_to_long

n = 0x8cae7d6a15e55fb6bea05fa3b7989cba4a4678d5d78103b80f78cf78b68602ea499ba6baf4f9d609fd16dd00e19823f12d8592af50b80efc4fdb7525bcff0b71fbbec3fa084b48c31e47e7bfe9b5424bbf8a2f707a1cbf89136e51e687f3c2b8000d1716f2686a4e48d08822e64b0ffc2b3218c4496d47bcf7c78b66360e600a00dbe7e22e38df603047962c97aef6b9e56f4eda27b648d67643ce7d9006f42108ff0cadcbb801eab6e13b1d59b6283c9d5348e388c173e6e870714e678d79c775945fac24da51604b2f1984f0f09b22ecbc849aa12fe883d4e7304d2f18a3cc684eda1cec71457d760da0a8e7aa0a7e2ce98bc1019078ed98a351dbf1209575
d = 0x30317a6f442efeba08d5c1cdc1107be8699778bfb102d676507e8f7c87f2a2bf06165768c6916bdca22219f5ba52b74560d5d8694c9ab12f885fe2e2d9baf97dc3c31739e96b78f2b6c5e5435e59a4eb74236f9af58a31a750cbc32cd9380d65a146dab916b3e46f0b0cbd064fa43946a6b993b8727b084f5906b7df7cf731b8d986653fd83a043054074b9a8b660c7d97f736914557e8ab289995e99dab9e982576fa7b26535c17c52d6ee20e943ee06b198753224c33ce1da2a75fe34904d5b3be2c826fd939f9201464922ec46beacdcd76778839a5862e7178206bf216d6908bf26cc5380ba93baedc2e3ff9082bcf4eec8f696a7b6dc915de6b67872885

with open("flag.enc", "rb") as f:
    ciphertext = f.read()

c = bytes_to_long(ciphertext)
m = pow(c, d, n)
print(long_to_bytes(m))
```

```console
$ python3 solve.py
b'HTB{REDACTED}'
```

### Comments

- **Public fields don't need protecting.** `n` and `e` are meant to be public, so redacting them would have added nothing; the challenge correctly leaves them intact and hides only the private material.
- **You don't need every private field.** `d`, `exponent1/2`, and `coefficient` never show up in the redacted file at all, and they don't need to: once one prime is recovered, `q = n // p`, `phi(n)`, and `d` are all a few lines of arithmetic away.
- **56% known beats the 50% folk rule.** The commonly cited "more than half the bits" heuristic for this attack is really `N^(1/4)` unknown bits out of `log2(N)`, which for a 2048-bit modulus is up to 512 unknown bits, not exactly half of a 1024-bit prime. This instance leaves 448 unknown, safely inside that bound with room to spare.
- **`beta=0.4` over `0.5`.** Coppersmith's bound is tightest at `beta=0.5` for a balanced modulus, but pushing `small_roots` right up to the theoretical edge makes the lattice larger and the reduction slower to converge reliably. `0.4` costs a bit of extra runtime and buys a root that's found on the first attempt.
