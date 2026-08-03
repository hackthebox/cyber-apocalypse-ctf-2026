import sys
import bisect

def solve():
    data = sys.stdin.buffer.read().split()
    idx  = 0
    N = int(data[idx]); idx += 1
    G = int(data[idx]); idx += 1
    arrivals = [int(data[idx + i]) for i in range(N)]; idx += N
    slots    = [int(data[idx + i]) for i in range(G)]; idx += G

    arrivals.sort()
    avail = sorted(slots)

    result = 0
    for a in arrivals:
        i = bisect.bisect_left(avail, a)
        result += avail[i] - a
        avail.pop(i)

    print(result)

solve()