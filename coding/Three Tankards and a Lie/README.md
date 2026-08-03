![](../../assets/banner.png)

<img src="../../assets/htb.png" style="margin-left: 20px; zoom: 80%;" align="left" />        <font size="10">Three Tankards and a Lie</font>

​        9<sup>th</sup> July 2026

​        Prepared By: 131LL

​        Challenge Author(s): 131LL

​        Difficulty: <font color=green>Very Easy</font>


# Synopsis

Three Tankards and a Lie is a very easy coding challenge that requires the player to track a sequence of position swaps applied to a set of numbered tankards, then answer queries about where a specific item ends up. The solution simulates the swaps on a small array and inverts it once at the end to answer every query in constant time.

## Skills Required

- Basic I/O parsing
- Array indexing and in-place swapping
- Building and using an inverse mapping

## Skills Learned

- Simulating a sequence of swap operations on an array
- Recognising that inverting the array once at the end is far cheaper than re-deriving each answer from scratch per query
- The difference between "what's at this position now" and "where did this item end up" -- and why you need both directions

## Description

```
The Drowned Bell doesn't ask questions -- which is exactly why Ferro
Quicktongue runs his nightly game there. Half the tavern is three mugs
deep and hollering wagers by the time Rin Kagetsura wanders in, off duty
and not remotely interested in Ferro's game.

What catches Rin's eye is the table by the door, where a courier is
running the exact same swap-and-shuffle -- except the thing sliding
under those tankards isn't a copper chit, it's a folded scrap bound for
someone at Suncourt. Rin is watching. The only question left is which
tankard the message is sitting under once the shuffling finally stops.
```

## Technical Description

```
Three Tankards and a Lie
N tankards stand on the bar, numbered 1..N; tankard i starts holding
item i. M swaps are performed in order, each exchanging the contents
currently sitting at two named positions. For each of Q queries (a
starting position p), report the final position of the item that
started at position p, after all M swaps have been applied.

Line 1: N M Q
Next M lines: a b   (positions swapped, 1-indexed)
Next Q lines: p      (a starting position to track)

1 <= N <= 2000
0 <= M <= 5000
1 <= Q <= 2000
1 <= a, b <= N
1 <= p <= N

Example Input:
5 4 2
1 3
2 4
3 5
4 1
3
5

Expected output:
4
3
```

## Solving the challenge

### Step 1: Model the bar as an array

Represent the tankards as an array `board`, where `board[pos]` holds the item currently sitting at position `pos`. Initially every tankard holds the item matching its own number, so `board[i] = i`.

```python
board = list(range(N + 1))
```

### Step 2: Apply every swap in order

A swap `(a, b)` exchanges whatever is currently at position `a` with whatever is currently at position `b` -- not the original items, whatever is physically sitting there *right now*. A plain array swap models this exactly, and applying all M swaps in sequence leaves `board` describing the bar's final state.

```python
for a, b in swaps:
    board[a], board[b] = board[b], board[a]
```

### Step 3: Build the inverse mapping

`board[pos]` answers "what item is at this position," but every query asks the opposite question: "where did this item end up." Since `board` is a permutation of `1..N`, it can be inverted in a single linear pass: for each position, record that the item found there now lives at that position.

```python
final_pos_of = [0] * (N + 1)
for pos in range(1, N + 1):
    final_pos_of[board[pos]] = pos
```

### Step 4: Answer every query in O(1)

With the inverse built, each of the Q queries is a single array lookup -- no need to replay any swaps per query.

```python
for p in queries:
    print(final_pos_of[p])
```

### Worked example

Swaps applied in order to `board = [_, 1, 2, 3, 4, 5]` (index 0 unused):

| Swap | Board after |
|---|---|
| (1,3) | [_, 3, 2, 1, 4, 5] |
| (2,4) | [_, 3, 4, 1, 2, 5] |
| (3,5) | [_, 3, 4, 5, 2, 1] |
| (4,1) | [_, 2, 4, 5, 3, 1] |

Inverting the final board: item 1 is at position 5, item 2 at position 1, item 3 at position 4, item 4 at position 2, item 5 at position 3.

Query `p=3` -> item 3's final position is **4**.
Query `p=5` -> item 5's final position is **3**.

### Complexity

| Approach | Time | Space |
|---|---|---|
| Replay all M swaps once per query | O(Q x M) | O(N) |
| Simulate once, invert, answer in O(1) each | O(N + M + Q) | O(N) |

Simulating the swaps a single time and inverting the resulting array once is linear in the total input size -- there is no reason to ever replay the shuffle more than once, no matter how many tankards patrons are tracking.
