![](../../assets/banner.png)



<img src="../../assets/htb.png" style="margin-left: 20px; zoom: 80%;" align=left />    	    <font size="6">The Ashen Field</font>

​		23<sup>rd</sup> July 2026

​		Prepared By: w3th4nds

​		Challenge Author(s): rasti

​		Difficulty: <font color=green>Easy</font>

​		Classification: Official




# Synopsis

The Ashen Field is an **Easy** difficulty crypto challenge built around a textbook Hidden Field Equations (HFE) public-key cryptosystem. A 137-bit random key is encrypted under an HFE public key and used to derive an AES key that protects the flag. The public key is nothing more than a system of 137 quadratic Boolean equations in 137 unknowns, and recovering the plaintext key is a matter of solving that system directly with a Groebner basis, exactly the class of attack HFE has been known to be vulnerable to since Faugère first broke the original HFE Challenge with F5 in 2002.

# Description

Deep beneath the Ash-Vault rests a relic the Cinderbound once swore could preserve truth without ever revealing it, a public rite built from equations, guarded only by the silent calculations its keepers left behind before they vanished. Unravel those old protections and the words sealed inside may finally be read, along with whatever authority the realm hoped they'd bury for good.

## Skills Required

- Multivariate polynomial rings and quotient rings over finite fields.
- Familiarity with public-key HFE-style cryptosystems.
- Basic SageMath scripting and Groebner basis computation.
- Reading someone else's finite-field arithmetic closely enough to name it.

## Skills Learned

- Recognizing a Hidden Field Equations public key from its source code, even without being told the algorithm's name.
- Why an HFE public key is always a system of quadratic equations, no matter how high the internal core map's degree is.
- Solving a small multivariate quadratic (MQ) system with a Groebner basis instead of guessing at a purpose-built attack.
- Reusing a known research artifact (a public GitHub HFE solver) as an actual CTF tool.

# Enumeration

Players receive:

```console
$ unzip crypto_ashen_field.zip
$ cd crypto_ashen_field
$ ls
source.sage  output.txt
```

## Step 1: Read `source.sage`

```sage
q = 2

def keygen(n):
    K = GF(q)
    R = PolynomialRing(K, [f"x{i}" for i in range(1, n+1)], n)
    ...
    Rv = S_A * vector(R, n, R.gens()) + S_B

    PRL.<t> = PolynomialRing(R)
    g = PRL(PRK.irreducible_element(n))
    Q = PRL.quotient_ring(PRL.ideal([g]))

    F = PRL(Rv.list()[::-1])
    F = Q(F^(2*q) + F^q + 1)

    PK = vector(R, n, F.list()[::-1])
    return T_A * PK + T_B
```

Nothing here is disguised: a polynomial ring over `GF(2)` in `n = 137` Boolean variables, a degree-`n` irreducible polynomial used to build an extension-field representation `GF(2^137)` symbolically, and a core map `F(X) = X^(2q) + X^q + 1 = X^4 + X^2 + 1`. That's the defining shape of **Hidden Field Equations**: an easy-to-invert low-degree map over a big field, wrapped in two secret affine transforms `S` and `T` so the public version looks like an opaque system of equations over the small field.

## Step 2: Read `output.txt`

```console
$ head -c 200 output.txt
(x1^4 + x2^4 + x4^4 + x5^4 + x6^4 + x10^4 + x12^4 + x13^4 + x14^4 + x18^4 + x19^4 + x20^4 + x21^4 + x23^4 + x27^4 + x28^4 + x31^4 + x32^4 + x37^4 + x43^4 + x45^4 + x47^4 + x51^4 + x52^4 + x53^4 + x55^...
```

Three lines: the public key `PK` (137 polynomials, one per output bit), the encrypted 137-bit key as a list of 0/1 ints, and the AES-ECB-encrypted flag as hex. The exponents up to `^4` are exactly what `F(X) = X^4 + X^2 + 1` would produce before Boolean reduction, more on that below.

# Reverse Engineering & Analysis

## Why the public key is quadratic despite a degree-4 core map

`keygen` builds `PK` by evaluating `F(X) = X^(2q) + X^q + 1` on a symbolic field element whose "coefficients" are the (affine-transformed) input variables. Squaring is GF(2)-linear (Frobenius), so `X^q` and `X^(2q)` are each linear combinations of the input bits; their product-free sum stays low-degree once expressed back in the small field, and any cross terms introduced by the quotient-ring reduction modulo the degree-137 irreducible polynomial `g` only ever multiply together at most two of the original linear terms. The result is that every coefficient of `PK`, read off as a polynomial in `x1, ..., x137`, ends up quadratic, once the field equations `x_i^2 = x_i` (true for any bit over `GF(2)`) are applied.

That's why `output.txt`'s raw `PK` still shows terms like `x1^4`: it's printed **before** reducing modulo those field equations. Since every variable is Boolean, `x_i^k = x_i` for any `k >= 1`, so reducing is as simple as deleting the exponent entirely:

```python
def degree_reduction(sys_equations):
    for removedItem in ["^2", "^3", "^4"]:
        sys_equations = sys_equations.replace(removedItem, "")
    return sys_equations
```

A plain string replace only works here because `q = 2`; it's a shortcut that happens to be mathematically exact for this specific field, not a general trick.

## The encryption itself

```python
N = 137
PK = keygen(N)

KEY = <random 137-bit integer>
encrypted_key = encrypt(KEY, PK)          # PK evaluated at KEY's bits

AES_KEY = hashlib.sha256(str(KEY).encode()).digest()
enc_flag = AES.new(AES_KEY, AES.MODE_ECB).encrypt(pad(FLAG, 16))
```

HFE is used here purely as a key encapsulation mechanism: the AES key is derived from `KEY` itself, not from the HFE ciphertext. Anyone who recovers the 137-bit `KEY` from `encrypted_key` gets the AES key for free and can decrypt the flag directly.

## Why this breaks: HFE public keys are Multivariate Quadratic systems

Recovering `KEY` from `encrypted_key` without the private trapdoor (`S`, `T`, and the irreducible polynomial) means solving `PK(x) = encrypted_key` for `x`, a system of 137 quadratic Boolean equations in 137 unknowns: exactly an instance of the **MQ (Multivariate Quadratic) problem**. MQ is hard in general, but HFE's structured public key has repeatedly fallen to **Groebner basis** attacks once the underlying core map's degree is small, which is precisely why the real HFE Challenge-1 (80 variables, degree-96 core map) was broken by Faugère's F5 algorithm in 2002, and why smaller instances like this one are solvable directly with off-the-shelf Groebner basis tools.

# Debugging

This challenge needs SageMath specifically for its `PolynomialRing`/`quotient_ring` machinery and `irreducible_element`, there's no meaningful way to prototype it in plain Python. With Sage available:

```console
$ sage source.sage
```

regenerates a fresh instance and writes `output.txt`. The shipped `htb/solver.sage` is a working reference solver, adapted from a public HFE-cryptanalysis repository, and can be run directly against the provided output:

```console
$ cd htb
$ sage solver.sage
```

# Solution

## Exploitation Chain Overview

```
1. Parse output.txt: PK (137 quadratic Boolean polynomials), encrypted_key (137 bits), enc_flag.
2. Build one equation per output bit: PK[i](x1..x137) - encrypted_key[i] = 0
3. Add the field ideal { x_i^2 - x_i : i in 1..137 } so solutions are forced into {0,1}.
4. Compute a Groebner basis (lex order) of that ideal -- or equivalently its variety,
   both converge to the same solution set.
5. Read the recovered bit values off the (mostly triangular) basis; brute-force the
   handful of variables that remain in a residual quadratic relation, if any.
6. Reverse the bit order to get the original 137-bit integer KEY.
7. AES_KEY = sha256(str(KEY))  ->  AES-ECB-decrypt enc_flag  ->  flag.
```

## Stage 1 — Building the ideal

```python
# thanks to
# https://github.com/falay/The-Attack-on-Hidden-Field-Equations-with-Improved-Grobner-Basis-Approach/blob/master/HFE.sage
def recover_plaintexts_grobner(PK, ciphertext):
    n = len(PK)
    equations = ",".join(f"{PK[i]}-{ciphertext[i]}" for i in range(n))
    variables = ",".join(f"x{i+1}" for i in range(n))

    Pring = PolynomialRing(GF(2), variables, order="lex")
    Pring.inject_variables(verbose=False)

    equations = degree_reduction(equations)
    I = Ideal(sage_eval(equations, locals=Pring.gens_dict()))
    J = I + sage.rings.ideal.FieldIdeal(Pring)
    gb = list(J.groebner_basis(algorithm='singular:std'))
    return fetch_solutions(gb)
```

Each of the 137 public-key polynomials, minus the matching bit of `encrypted_key`, gives one equation that must vanish at the true `KEY`. `sage.rings.ideal.FieldIdeal` adds the `x_i^2 - x_i` relations for every variable, which is what pins the solution set to `{0,1}^137` rather than some larger variety over `GF(2)`'s algebraic closure. This is exactly the "field ideal" trick behind most Boolean Groebner basis attacks: without it, the ideal describes far more solutions than the one that's actually 0/1-valued.

## Stage 2 — Reading the answer out of the basis

```python
def fetch_solutions(gb):
    quadratic_vars = [f.variable() for f in gb if f.degree() == 2]
    for vals in itertools.product([0, 1], repeat=len(quadratic_vars)):
        subs = dict(zip(quadratic_vars, vals))
        evaled = [f.subs(subs) for f in gb]
        soln_bits = [
            subs[VARS[i]] if len(R(e).monomials()) == 0 else int(len(e.coefficients()) % 2 == 0)
            for i, e in enumerate(evaled)
        ]
        yield "".join(map(str, soln_bits))
```

With `n` equations and `n` unknowns and a lex Groebner basis, the system is expected to be (close to) fully triangularized: most basis polynomials reduce to `x_i - c` for a concrete bit `c`. Any polynomial that still shows up at degree 2 means that variable wasn't pinned down uniquely by the basis alone, so `fetch_solutions` brute-forces the small number of remaining free bits and re-substitutes to read off the rest, cheap since HFE's structure usually leaves only a handful of such variables, not all 137.

## Stage 3 — From bits to key to flag

```python
PK, encrypted_key, enc_flag = open("output.txt").readlines()
PK = eval(PK.strip().replace("^", "**"))
encrypted_key = eval(encrypted_key.strip())
enc_flag = bytes.fromhex(enc_flag.strip())

for recovered_pt in recover_plaintexts_grobner(PK, encrypted_key):
    KEY_candidate = int(recovered_pt[::-1], 2)
    AES_KEY = hashlib.sha256(str(KEY_candidate).encode()).digest()
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    try:
        print(unpad(cipher.decrypt(enc_flag), 16))
    except:
        pass
```

The bit order gets reversed (`recovered_pt[::-1]`) to undo the padding-then-reversal that `encrypt()` applied on the way in. Each candidate is tried as an AES key against the real ciphertext; the one that unpads cleanly is the flag.

Against the shipped instance's `output.txt`, this recovers the 137-bit key, derives the AES key, and decrypts:

```console
HTB{REDACTED}
```

### Comments

- **The "either Groebner or variety" joke in the flag is literal.** `recover_plaintexts_grobner` computes an explicit `groebner_basis`, but a commented-out line right above it, `# return fetch_solutions(J.variety())`, shows the author also tested computing the ideal's variety directly. Both describe the same solution set; either one solves the challenge.
- **`q = 2` is what makes the degree-reduction shortcut valid.** Deleting `^2`, `^3`, `^4` from the equation text only reduces correctly because `x_i^k = x_i` holds for every Boolean variable. The same trick would be wrong over any larger field.
- **HFE's core weakness is exactly its structure.** The private trapdoor needs a low-degree core map to stay efficiently invertible, but that same low degree is what lets a Groebner basis attack converge quickly once the public key is treated as a plain MQ system, no knowledge of `S`, `T`, or the irreducible polynomial required.
- **This is a real, previously-published attack, not a novel one.** The solver credits a public research repository implementing "Improved Groebner Basis Approach" against HFE; recognizing the cryptosystem is most of the work, the actual break is running existing, well-documented cryptanalysis against it.
