![](../../assets/banner.png)

<img src="../../assets/htb.png" style="margin-left: 20px; zoom: 80%;" align="left" />        <font size="10">Rumour Spine</font>

​        9<sup>th</sup> July 2026

​        Prepared By: 131LL

​        Challenge Author(s): 131LL

​        Difficulty: <font color=red>Hard</font>


# Synopsis

Rumour Spine is a hard coding challenge that requires the player to compute the minimum number of intermediate quiet hands whose exposure disconnects a coordinator from a target district in a directed graph that may contain cycles. The solution reduces this minimum vertex-cut problem to a minimum edge-cut problem via node splitting, then solves it with a maximum-flow algorithm.

## Skills Required

- Graph modelling, including transforming one graph problem into another
- Max-flow / min-cut theory (Menger's theorem)
- Implementing an efficient flow algorithm (Dinic's)

## Skills Learned

- Turning a "minimum nodes to expose" problem into a "minimum edges to cut" problem by splitting each node into an in-half and an out-half joined by a capacity-1 edge
- Why the resulting max flow equals the minimum vertex cut
- Implementing Dinic's algorithm: repeatedly building a BFS level graph, then saturating it with DFS blocking flow

## Description

```
Suncourt doesn't march first — it primes first. Miren Vale has traced the
Quiet March's invitation chain: a coordinator feeding a priming signal
through a network of quiet hands until a target district falls still.
Miren intends to break the chain before that happens, by exposing the
fewest hands possible.
```

## Technical Description

```
Rumour Spine
A directed graph of N quiet hands (nodes 0 to N-1) and E directed links is
given, along with a coordinator node S and a target district node T. Find
the minimum number of hands, other than S and T, that must be exposed so
that no directed path remains from S to T. Print that minimum.

Line 1: N E S T
Next E lines: u v  (directed link from u to v)

6 <= N <= 120
1 <= E <= 360
S = 0, T = N-1
The graph may contain cycles
It is guaranteed that at least one path from S to T exists
It is guaranteed that there is no direct edge from S to T

Example Input:
7 8 0 6
0 1
0 2
1 3
2 4
3 6
4 6
2 3
1 4

Expected output:
2
```

## Solving the challenge

### Step 1: Recognise the vertex-cut structure

Menger's theorem says the minimum number of vertices whose removal disconnects S from T equals the maximum number of internally vertex-disjoint S→T paths. Standard max-flow algorithms compute maximum *edge*-disjoint flow directly, but they don't limit how many times a single vertex can be used — some transformation is needed first.

### Step 2: Split every node into an "in" half and an "out" half

Replace each node `v` with two nodes, `v_in` and `v_out`, joined by an internal edge. This internal edge is where a node's "capacity" of 1 (it can only be exposed once) actually lives:

```python
d.add_edge(2*v, 2*v + 1, cap)
```

For every node except S and T, `cap` is 1 — using that hand in a path consumes its one unit of capacity. For S and T themselves, `cap` is effectively infinite, since the coordinator and the target district are never candidates for exposure.

### Step 3: Rewire the original edges through the split nodes

An original directed link `u -> v` becomes an edge from `u`'s out-half to `v`'s in-half, with unlimited capacity — the graph's links were never the scarce resource, only the hands are.

```python
d.add_edge(2*u + 1, 2*v, INF)
```

### Step 4: Run max flow from S_out to T_in

Once every node is split and every edge rewired, a maximum flow from `2*S+1` to `2*T` on this new graph gives exactly the minimum vertex cut of the original graph — each unit of flow is forced to pass through one hand's internal capacity-1 edge, so no hand can be reused across two flow units.

### Step 5: Dinic's algorithm — level graph

Dinic's algorithm alternates two phases. The first builds a level graph with BFS from the source, recording each reachable node's distance:

```python
def bfs(self, s, t, level):
    level[:] = [-1]*len(self.g); level[s] = 0
    q = deque([s])
    while q:
        u = q.popleft()
        for i in self.g[u]:
            v, cap = self.edges[i]
            if cap > 0 and level[v] < 0:
                level[v] = level[u]+1; q.append(v)
    return level[t] >= 0
```

If `t` is unreachable, no more augmenting flow exists and the algorithm stops.

### Step 6: Dinic's algorithm — blocking flow

The second phase pushes flow only along edges that strictly increase the BFS level (`level[v] == level[u] + 1`), using DFS with an iterator per node so each edge is only ever reconsidered, never rescanned from scratch:

```python
def dfs(self, u, t, f, level, it):
    if u == t: return f
    while it[u] < len(self.g[u]):
        i = self.g[u][it[u]]
        v, cap = self.edges[i]
        if cap > 0 and level[v] == level[u]+1:
            d = self.dfs(v, t, min(f, cap), level, it)
            if d > 0:
                self.edges[i][1] -= d; self.edges[i^1][1] += d
                return d
        it[u] += 1
    return 0
```

Repeating BFS + blocking-flow phases until BFS can no longer reach `t` accumulates the total max flow, which is the answer.

### Worked example

The four coordinator→target paths in the sample graph are:

```
0 -> 1 -> 3 -> 6
0 -> 1 -> 4 -> 6
0 -> 2 -> 3 -> 6
0 -> 2 -> 4 -> 6
```

No single hand appears on all four paths, so exposing any one hand still leaves at least one route open — a min cut of 1 is impossible. Exposing both hand 1 and hand 2 breaks every path, since every route out of the coordinator must pass through one of them first. After node splitting, this shows up as a max flow of exactly 2 units from `0_out` to `6_in`, each unit forced through either hand 1's or hand 2's internal capacity-1 edge.

### Complexity

| Approach | Time | Space |
|---|---|---|
| Try all subsets of hands to expose | O(2^N) | O(N) |
| Node-split + Dinic's max flow | O(V'^2 × E') in general, much faster in practice for unit-capacity graphs | O(V' + E') |

After splitting, the transformed graph has at most `2N ≈ 240` nodes and `E + N ≈ 480` edges — well within reach for Dinic's, which typically runs in O(E' × sqrt(V')) on unit-capacity networks like this one.
