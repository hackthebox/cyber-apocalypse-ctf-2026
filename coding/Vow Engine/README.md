![](../../assets/banner.png)

<img src="../../assets/htb.png" style="margin-left: 20px; zoom: 80%;" align="left" />        <font size="10">Vow Engine</font>

​        9<sup>th</sup> July 2026

​        Prepared By: 131LL

​        Challenge Author(s): 131LL

​        Difficulty: <font color=red>Insane</font>


# Synopsis

Vow Engine is an insane coding challenge that requires the player to answer, for many live challenges, whether a target cadence value is achievable along some oath-path between two witnesses in a witness-chain that may contain redundant loops. The solution combines a weighted union-find that tracks each witness's XOR-distance to its component root with a GF(2) linear basis per component that captures every extra value contributed by that component's loops, merged efficiently with small-to-large union.

## Skills Required

- Union-Find / DSU with path compression
- XOR and linear algebra over GF(2) (linear basis / Gaussian elimination)
- Combining a "potential" value carried through a DSU with a per-component basis merge

## Skills Learned

- Modelling "every cadence value reachable between witness u and witness v" as one fixed value XOR-ed with anything spanned by that component's loop basis
- Maintaining, per DSU root, a maximal independent set of XOR values (a linear basis) contributed by every redundant loop discovered in that component
- Merging two components' bases together on union, and reducing a challenge value against a basis to test membership

## Description

```
The ending cannot live behind walls, because walls can be taken and paper
can be rewritten. Caldrin Vowmark is deploying the breath-key in the open,
under record, chain, and open sky — threaded through Garran's witness-chain,
where the true weight of an oath is the XOR of every seal-mark's cadence
key along the path from speaker to witness. A threaded mouth trying to
fake the rite in front of the whole city gets exactly one chance.
```

## Technical Description

```
Vow Engine
An undirected witness-chain of N witnesses and M seal-marks is given; each
seal-mark carries an XOR cadence key. The cadence value of an oath-path
between two witnesses is the XOR of every seal-mark weight along it.
Because the witness-chain may contain redundant loops, more than one
cadence value can be achievable between the same pair of witnesses. For
each of Q live challenges (u, v, T), print YES if some oath-path between u
and v has cadence value T, otherwise print NO.

Line 1: N M Q
Next M lines: u v w  (undirected seal-mark with cadence key w)
Next Q lines: u v T  (challenge)

2 <= N <= 1500
1 <= M <= 2200
1 <= Q <= 1500
0 <= w <= 63
0 <= T <= 63
The witness-chain may contain redundant loops

Example Input:
5 5 4
0 1 3
1 2 5
2 3 4
3 4 7
0 2 10
0 3 2
0 3 5
0 1 15
0 4 4

Expected output:
YES
NO
YES
NO
```

## Solving the challenge

### Step 1: See the reachable cadence values as a coset

Fix any spanning tree of a component. Every non-tree seal-mark closes a redundant loop, and the XOR of the cadence keys around that loop is one "free" value: travelling from a witness, around the loop, and back changes nothing about your position but XORs that value into your running total. So the full set of cadence values achievable between two witnesses u and v in the same component is `tree_path_xor(u, v)` combined with every value obtainable by XOR-ing together any subset of that component's loop values — a coset of a linear subspace of GF(2)^6, since cadence keys are capped at 63 (6 bits).

### Step 2: Track each witness's XOR-distance with a weighted DSU

Alongside the usual parent array, keep a `dist[x]` value equal to the XOR of seal-mark weights from `x` up to its component's root. `find` updates this distance as it compresses paths, the same way a standard weighted union-find tracks a numeric offset instead of just a parent pointer:

```python
def find(self, x):
    if self.parent[x] == x:
        return x, 0
    root, _ = self.find(self.parent[x])
    self.dist[x] ^= self.dist[self.parent[x]]
    self.parent[x] = root
    return root, self.dist[x]
```

### Step 3: Recognise a redundant loop during union

When processing a seal-mark `(u, v, w)`, first find both endpoints' roots. If they're already the same root, this seal-mark doesn't connect anything new — it closes a redundant loop, whose cadence value is `dist[u] ^ dist[v] ^ w`. That value gets folded into the component's basis instead of performing a merge:

```python
ru, du = self.find(u); rv, dv = self.find(v)
if ru == rv:
    cyc = du ^ dv ^ w
    if cyc:
        self._insert(ru, cyc)
    return
```

### Step 4: Maintain a linear basis over GF(2)

A "basis" here is a small list of cadence values with the property that no value in the list can be produced by XOR-ing together any of the others — the standard linear-basis / Gaussian-elimination trick adapted to bitwise XOR. Inserting a new value repeatedly XORs it against existing basis entries to try to reduce it; if anything survives, it's a genuinely new independent value and gets appended:

```python
def _insert(self, root, x):
    for b in self.basis[root]:
        x = min(x, x ^ b)
    if x:
        self.basis[root].append(x)
```

### Step 5: Merge components when a seal-mark connects two different roots

If `(u, v, w)` connects two previously separate components, attach one root under the other and set the new root's `dist` so the seal-mark's constraint holds, exactly as in a standard weighted union-find. The two components' loop bases must also become one: fold every value from the smaller basis into the larger one via the same `_insert` routine, so nothing already known about either side's loops is lost.

### Step 6: Answer a live challenge by reducing the target against the basis

For a challenge `(u, v, T)`, find both roots. Different roots mean no oath-path exists at all. Otherwise, the value that needs to be checked is `T ^ dist[u] ^ dist[v]` — "does adjusting the target by the fixed tree-path cadence land exactly on something the component's loops can produce, or its absence (zero)?" That's answered by reducing the adjusted target against the basis, the same reduction used during insertion:

```python
target = T ^ du ^ dv
for b in self.basis[ru]:
    target = min(target, target ^ b)
answer_yes = (target == 0)
```

If it reduces all the way to zero, `T` is achievable; otherwise it isn't — and a threaded mouth answering that challenge fails in front of the whole city.

### Worked example

The sample witness-chain's only redundant loop is 0–1(3), 1–2(5), 0–2(10), contributing the loop value `3 ^ 5 ^ 10 = 12` to that component's basis. Working out the achievable cadence set for each challenged pair (a fixed path value, combined with `{0, 12}` from the basis):

| Pair | Achievable set | Challenge target | Result |
|---|---|---|---|
| 0, 3 | {2, 14} | 2 | in set → **YES** |
| 0, 3 | {2, 14} | 5 | not in set → **NO** |
| 0, 1 | {3, 15} | 15 | in set → **YES** |
| 0, 4 | {5, 9} | 4 | not in set → **NO** |

Matches the expected output exactly.

### Complexity

| Approach | Time | Space |
|---|---|---|
| Enumerate all simple oath-paths per challenge | exponential | — |
| Weighted DSU + per-component XOR basis, small-to-large merge | O((N + M + Q) × B) with near-linear DSU overhead, where B ≤ 6 is the number of bits in the value range | O(N + M) |

Since every cadence key and target fits in 6 bits (0–63), each basis holds at most 6 independent values, so every insert or challenge reduction costs at most 6 XOR operations — the DSU's near-constant-time `find`/`union` dominates, keeping the whole solution comfortably within the time limit even at N, M, Q up to their maximums, live, under open sky.
