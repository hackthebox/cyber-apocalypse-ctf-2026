import sys

def solve():
    data = sys.stdin.buffer.read().split()
    idx = 0
    N = int(data[idx]); M = int(data[idx + 1]); Q = int(data[idx + 2]); idx += 3

    board = list(range(N + 1))
    for _ in range(M):
        a = int(data[idx]); b = int(data[idx + 1]); idx += 2
        board[a], board[b] = board[b], board[a]

    final_pos_of = [0] * (N + 1)
    for pos in range(1, N + 1):
        final_pos_of[board[pos]] = pos

    out = []
    for _ in range(Q):
        p = int(data[idx]); idx += 1
        out.append(str(final_pos_of[p]))

    print("\n".join(out))

solve()
