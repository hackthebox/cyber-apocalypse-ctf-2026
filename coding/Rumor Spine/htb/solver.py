import sys
from collections import deque
input = sys.stdin.readline

class Dinic:
    def __init__(self, n):
        self.g = [[] for _ in range(n)]
        self.edges = []
    def add_edge(self, u, v, cap):
        self.g[u].append(len(self.edges)); self.edges.append([v, cap])
        self.g[v].append(len(self.edges)); self.edges.append([u, 0])
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
    def max_flow(self, s, t):
        n = len(self.g); level = [-1]*n; flow = 0
        while self.bfs(s, t, level):
            it = [0]*n
            while True:
                f = self.dfs(s, t, 10**9, level, it)
                if not f: break
                flow += f
        return flow

def solve():
    data = sys.stdin.buffer.read().split()
    idx  = 0
    N = int(data[idx]); idx+=1
    E = int(data[idx]); idx+=1
    S = int(data[idx]); idx+=1
    T = int(data[idx]); idx+=1

    INF = 10**9
    d = Dinic(2*N)
    for i in range(N):
        cap = INF if i == S or i == T else 1
        d.add_edge(2*i, 2*i+1, cap)

    for _ in range(E):
        u = int(data[idx]); idx+=1
        v = int(data[idx]); idx+=1
        d.add_edge(2*u+1, 2*v, INF)

    print(d.max_flow(2*S+1, 2*T))

solve()