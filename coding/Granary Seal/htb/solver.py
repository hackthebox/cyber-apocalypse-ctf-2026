import sys
input = sys.stdin.readline

def solve():
    data = sys.stdin.buffer.read().split()
    idx  = 0

    def read_int():
        nonlocal idx
        v = int(data[idx]); idx += 1
        return v

    def read_set(n):
        nonlocal idx
        s = set()
        for _ in range(n):
            s.add(data[idx]); idx += 1
        return s

    clerks_set      = read_set(read_int())
    countersign_set = read_set(read_int())
    couriers_set    = read_set(read_int())

    N       = read_int()
    answer  = 0

    for _ in range(N):
        c  = data[idx];     idx += 1
        cs = data[idx];     idx += 1
        co = data[idx];     idx += 1
        if c in clerks_set and cs in countersign_set and co in couriers_set:
            answer += 1

    print(answer)

solve()