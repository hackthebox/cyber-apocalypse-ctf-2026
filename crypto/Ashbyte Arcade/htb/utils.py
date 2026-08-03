import sys
sys.path.insert(1, "challenge/")
from crypto import xtime

def mix_single_column(a):
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)
    return a

def sub_bytes(s, sbox):
    return [[sbox[val] for val in row] for row in s]

def mix_columns(s):
    return [mix_single_column(s[i].copy()) for i in range(4)]

def shift_rows(s):
    res = [s[i].copy() for i in range(4)]
    res[0][1], res[1][1], res[2][1], res[3][1] = res[1][1], res[2][1], res[3][1], res[0][1]
    res[0][2], res[1][2], res[2][2], res[3][2] = res[2][2], res[3][2], res[0][2], res[1][2]
    res[0][3], res[1][3], res[2][3], res[3][3] = res[3][3], res[0][3], res[1][3], res[2][3]
    return res

def add_round_key(s, k):
    return [[t[0] ^ t[1] for t in list(zip(row[0], row[1]))] for row in zip(s, k)]

def inv_mix_columns(s):
    res = [s[i].copy() for i in range(4)]
    for i in range(4):
        u = xtime(xtime(res[i][0] ^ res[i][2]))
        v = xtime(xtime(res[i][1] ^ res[i][3]))
        res[i][0] ^= u
        res[i][1] ^= v
        res[i][2] ^= u
        res[i][3] ^= v
    return mix_columns(res)

def inv_shift_rows(s):
    res = [s[i].copy() for i in range(4)]
    res[0][1], res[1][1], res[2][1], res[3][1] = res[3][1], res[0][1], res[1][1], res[2][1]
    res[0][2], res[1][2], res[2][2], res[3][2] = res[2][2], res[3][2], res[0][2], res[1][2]
    res[0][3], res[1][3], res[2][3], res[3][3] = res[1][3], res[2][3], res[3][3], res[0][3]
    return res