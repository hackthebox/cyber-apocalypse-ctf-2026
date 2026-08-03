![](../../assets/banner.png)

<img src="../../assets/htb.png" style="margin-left: 20px; zoom: 80%;" align="left" />        <font size="10">Ash Record</font>

​        9<sup>th</sup> July 2026

​        Prepared By: 131LL

​        Challenge Author(s): 131LL

​        Difficulty: <font color=#f0ad4e>Medium</font>


# Synopsis

Ash Record is a medium coding challenge that requires the player to find the longest prefix of a suspected extraction sequence that can be matched, in order, against a set of timestamped residues, subject to a minimum time gap between consecutive matches. The solution is a small dynamic program over sequence positions, where each state tracks the earliest timestamp at which that many steps can be completed.

## Skills Required

- Sorting
- Dynamic programming with a small, bounded state space
- Careful iteration order to avoid a single residue completing two steps at once

## Skills Learned

- Modelling constrained subsequence matching as "earliest completion time per prefix length"
- Why updating states from the highest index down prevents one residue from being reused within the same pass
- Reducing a subsequence-with-a-numeric-constraint problem to O(N × P)

## Description

```
A hamlet that should be starving has warm ovens and chairs abandoned
mid-meal, and the wreckage still remembers what actually happened. Elowen
Ashglass is piecing together how much of a suspected extraction sequence
the recovered residues can confirm.
```

## Technical Description

```
Ash Record
N recovered residues are given, each with an integer timestamp and a
material type string; residues are not necessarily given in timestamp
order. A suspected extraction sequence of P material types, in order, is
given, along with a minimum time gap min_gap. Find the length of the
longest prefix of the sequence that can be matched, in order, by some
subsequence of the residues, such that every two consecutively matched
residues differ in timestamp by at least min_gap. Print that length.

Line 1: N P min_gap
Line 2: P material types (space-separated)
Next N lines: timestamp material_type

1 <= N <= 5000
1 <= P <= 12
1 <= min_gap <= 10
1 <= timestamp <= 10000
Material type strings consist of lowercase letters, length <= 10

Example Input:
5 4 3
ash rope oil ash
1 ash
4 rope
7 oil
10 ash
11 rope

Expected output:
4
```

## Solving the challenge

### Step 1: Sort residues by timestamp

A match must walk the extraction sequence strictly forward in time, but the residues are recovered in arbitrary order. Sorting them first means the matching process can simply scan left to right.

```python
samples.sort()
```

### Step 2: Define the state

Let `dp[j]` be the earliest timestamp at which the first `j` steps of the extraction sequence have been confirmed by some valid subsequence seen so far. `dp[0]` starts as "negative infinity" (zero steps confirmed, no prior timestamp to respect a gap against), and every other `dp[j]` starts as infinity (not yet reachable).

```python
dp = [INF] * (P + 1)
dp[0] = -INF
```

Keeping the *earliest* possible completion time for each prefix length — rather than just "reachable or not" — matters because an earlier completion time leaves more room for the remaining steps to satisfy the gap constraint later on.

### Step 3: Try to extend a match with each residue

For a residue with type `typ`, it can only extend a match ending at sequence position `j-1` if `typ` equals `pattern[j-1]`. If it can, the extension is valid only when the gap since the previous matched residue is large enough.

```python
if typ == pattern[j-1] and dp[j-1] != INF:
    if dp[j-1] == -INF or ts - dp[j-1] >= min_gap:
        if ts < dp[j]:
            dp[j] = ts
```

### Step 4: Process sequence positions from the back

Within one residue's turn, positions must be updated from `j = P` down to `j = 1`, not the other way round. Updating forwards would let a single residue extend `dp[j-1]` first and then immediately read that fresh value to extend `dp[j]` in the same step — effectively matching one residue to two consecutive sequence positions at once, which isn't a valid subsequence.

```python
for j in range(P, 0, -1):
    ...
```

### Step 5: Read off the answer

After every residue has been processed, the answer is the largest `j` for which `dp[j]` is still finite — the longest prefix that was ever confirmed.

```python
for j in range(P, -1, -1):
    if dp[j] < INF:
        answer = j
        break
```

### Worked example

Extraction sequence: `ash, rope, oil, ash` — min_gap = 3. Processing residues in timestamp order `1(ash), 4(rope), 7(oil), 10(ash), 11(rope)`:

| Residue | Extends | Gap check | New dp value |
|---|---|---|---|
| ts=1, ash | dp[0] → dp[1] | no prior residue to check | dp[1]=1 |
| ts=4, rope | dp[1] → dp[2] | 4−1=3 ≥ 3 | dp[2]=4 |
| ts=7, oil | dp[2] → dp[3] | 7−4=3 ≥ 3 | dp[3]=7 |
| ts=10, ash | dp[3] → dp[4] | 10−7=3 ≥ 3 | dp[4]=10 |
| ts=11, rope | dp[4] is already the last position; no dp[5] exists | — | — |

All four sequence positions are confirmed → output 4.

### Complexity

| Approach | Time | Space |
|---|---|---|
| Brute-force subsequence search | O(2^N) | O(N) |
| Sort + DP over sequence length | O(N log N + N × P) | O(P) |

With P capped at 12, the DP pass is at most 12 operations per residue — the sort dominates for large N, and the whole solution comfortably fits within the time limit.
