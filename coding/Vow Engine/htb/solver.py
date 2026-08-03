import sys

def solve():
    data = sys.stdin.buffer.read().split()
    idx  = 0
    N = int(data[idx]); idx+=1
    M = int(data[idx]); idx+=1
    Q = int(data[idx]); idx+=1

    parent = list(range(N))
    rank   = [0]*N
    dist   = [0]*N
    basis  = [[] for _ in range(N)]

    def find(x):
        if parent[x] == x: return x, 0
        root, _ = find(parent[x])
        dist[x] ^= dist[parent[x]]
        parent[x] = root
        return root, dist[x]

    def insert(root, x):
        for b in basis[root]:
            x = min(x, x^b)
        if x: basis[root].append(x)

    def union(u, v, w):
        ru, du = find(u); rv, dv = find(v)
        if ru == rv:
            cyc = du^dv^w
            if cyc: insert(ru, cyc)
            return
        if rank[ru] < rank[rv]:
            ru,rv=rv,ru; du,dv=dv,du
        parent[rv] = ru
        dist[rv]   = du^dv^w
        if rank[ru]==rank[rv]: rank[ru]+=1
        for b in basis[rv]: insert(ru, b)
        basis[rv] = []

    for _ in range(M):
        u=int(data[idx]);idx+=1
        v=int(data[idx]);idx+=1
        w=int(data[idx]);idx+=1
        union(u,v,w)

    out = []
    for _ in range(Q):
        u=int(data[idx]);idx+=1
        v=int(data[idx]);idx+=1
        T=int(data[idx]);idx+=1
        ru,du=find(u); rv,dv=find(v)
        if ru!=rv: out.append("NO"); continue
        target=T^du^dv
        for b in basis[ru]: target=min(target,target^b)
        out.append("YES" if target==0 else "NO")

    print("\n".join(out))

solve()