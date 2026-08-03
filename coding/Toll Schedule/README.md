![](../../assets/banner.png)

<img src="../../assets/htb.png" style="margin-left: 20px; zoom: 80%;" align="left" />        <font size="10">Toll Schedule</font>

​        9<sup>th</sup> July 2026

​        Prepared By: 131LL

​        Challenge Author(s): 131LL

​        Difficulty: <font color=#f5a623>Easy</font>


# Synopsis

Toll Schedule is an easy coding challenge that requires the player to assign each convoy to a checkpoint clearance that opens no earlier than its arrival, minimising the total waiting time across the whole column. The solution sorts both lists and greedily assigns each convoy, in increasing order of arrival, the earliest still-available clearance that qualifies.

## Skills Required

- Sorting
- Greedy algorithm design and correctness reasoning (exchange argument)
- Binary search over a sorted collection

## Skills Learned

- Recognising an assignment problem that reduces to "sort, then greedily pick the smallest legal slot"
- Using binary search to find and remove the smallest available value at or above a bound
- Why processing arrivals in increasing order, always taking the earliest qualifying clearance, cannot be beaten by any other assignment

## Description

```
Stonepass closes its gates on borrowed words — raiders, avalanches, public
order — while the schedule underneath keeps quietly playing favourites.
Elric Ashspar means to prove the checkpoint is rigged, starting with the
number the pass would rather nobody compute: the fastest this column could
have cleared if the mechanism weren't tuned to favour one banner.
```

## Technical Description

```
Toll Schedule
N convoys arrive at a pass, each at a known integer time. G checkpoint
clearances are available (G >= N), each opening at a known integer time.
Each convoy must be assigned to a distinct clearance that opens at or after
its own arrival time; each clearance handles at most one convoy. A valid
assignment is guaranteed to exist. Minimise and print the total waiting
time across all convoys, where a convoy's waiting time is its assigned
clearance's opening time minus its arrival time.

Line 1: N G
Line 2: N arrival times (space-separated, any order)
Line 3: G clearance opening times (space-separated, any order)

1 <= N <= 1200
N <= G <= 1500
1 <= arrival time <= 200
1 <= clearance opening time <= 220
It is guaranteed that every convoy can be assigned to a distinct clearance

Example Input:
4 4
2 4 6 9
3 5 8 11

Expected output:
6
```

## Solving the challenge

### Step 1: See it as a matching problem with a greedy shortcut

Every convoy needs a distinct clearance opening at or after its arrival, and the goal is to minimise total wait — the clean baseline the real, throttled schedule will later be measured against. Since waiting time only ever increases the later a clearance opens, intuitively an earlier-arriving convoy should never be "given" a clearance an equally- or later-arriving convoy actually needed. Processing convoys in increasing order of arrival and always handing out the smallest still-available qualifying clearance turns out to be optimal — swapping any two assignments against this rule can only make the total wait equal or worse, never better.

### Step 2: Sort both lists

```python
arrivals.sort()
windows.sort()
```

Sorting the clearances lets a binary search locate "the smallest clearance opening at or after X" in place of a linear scan.

### Step 3: Find the earliest qualifying clearance for each convoy

For each arrival, in increasing order, `bisect_left` finds the position of the smallest remaining clearance opening time that is `>=` the arrival.

```python
i = bisect.bisect_left(available, a)
```

Because `available` stays sorted, this locates the correct clearance in O(log G) instead of scanning every remaining clearance.

### Step 4: Assign it and remove it from the pool

Once found, that clearance is no longer available to later convoys. Its wait contributes to the running total.

```python
total += available[i] - a
available.pop(i)
```

### Step 5: Why removing by index is fast enough here

`available.pop(i)` shifts every element after `i`, which is O(G) in the worst case — but with N and G capped at 1200 and 1500 respectively, the total work across all N removals stays well within the time limit. For much larger constraints, a balanced structure (e.g. a Fenwick tree over clearance ranks) would replace the plain list to keep each removal at O(log G), but it isn't needed at this scale.

### Worked example

| Convoy arrival | Clearance found | Wait |
|---|---|---|
| 2 | 3 | 1 |
| 4 | 5 | 1 |
| 6 | 8 | 2 |
| 9 | 11 | 2 |

Total: 1 + 1 + 2 + 2 = 6 — the fair baseline Elric needed to show the actual gate is running slower than this for at least one banner.

### Complexity

| Approach | Time | Space |
|---|---|---|
| Try every assignment | O(N!) | O(N) |
| Sort + greedy binary search | O((N + G) log G) for search, O(N × G) worst case for removal | O(G) |

For the given constraints the sort-and-greedy approach comfortably fits the time limit; no more efficient assignment exists, since the greedy choice at each step is provably optimal.
