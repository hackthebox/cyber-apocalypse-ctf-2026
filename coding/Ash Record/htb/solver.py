import sys

def solve():
    data = sys.stdin.buffer.read().split()
    idx  = 0
    N       = int(data[idx]); idx+=1
    P       = int(data[idx]); idx+=1
    min_gap = int(data[idx]); idx+=1

    pattern = [data[idx+i].decode() for i in range(P)]; idx+=P

    samples = []
    for _ in range(N):
        ts  = int(data[idx]);      idx+=1
        typ = data[idx].decode();  idx+=1
        samples.append((ts, typ))
    samples.sort()

    INF = float('inf')
    dp = [INF] * (P + 1)
    dp[0] = -INF

    for ts, typ in samples:
        for j in range(P, 0, -1):
            if typ == pattern[j-1] and dp[j-1] != INF:
                if dp[j-1] == -INF or ts - dp[j-1] >= min_gap:
                    if ts < dp[j]:
                        dp[j] = ts

    for j in range(P, -1, -1):
        if dp[j] < INF:
            print(j); return
    print(0)

solve()