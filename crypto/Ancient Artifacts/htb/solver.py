from sage.all import *
from pwn import remote, process, xor
import zlib
import random

def get_conn():
    HOST = "localhost"
    PORT = 1337
    return remote(HOST, PORT)

hashnum = lambda *nums: zlib.adler32("".join(str(num) for num in nums).encode())
p = 65521

def find_h(salts, hashes):
    avg_len = int(round(sum([len(str(random.getrandbits(128))) for _ in range(100)])/100))
    assert avg_len == 39
    As = []
    Bs = []
    for i in range(len(salts)):
        s1, s2 = salts[i]
        hi = hashes[i]

        A = hi % 2**16
        B = hi >> 16

        ssalt1 = [ord(digit) for digit in str(s1)]
        ssalt2 = [ord(digit) for digit in str(s2)]
        A_corrected = A - sum(ssalt1) - sum(ssalt2) - 48*avg_len - 1 # sum of missing digits
        B_corrected = B
        all_chars = ssalt1 + ["?"]*avg_len + ssalt2
        l = len(all_chars)
        B_corrected -= l
        for i, c in enumerate(all_chars[::-1]):
            n = [48, c][c != "?"]
            B_corrected -= n*(i + 1)
        B_corrected %= p
        As.append(A_corrected)
        Bs.append(B_corrected)
    assert all(a == A_corrected for a in As)
                
    dim = len(salts) + avg_len + 2
    M = matrix(ZZ, dim-1, dim)
    sent = 9
    mmul = 10**100
    mmul = 10**100
    for i in range(avg_len):
        M[i, i] = 1
        M[i, avg_len] = 1 # column for A
        for j in range(len(salts)):
            M[i, avg_len + j + 1] = (len(str(salts[j][1])) + avg_len - i)*mmul
    
    for i in range(len(salts)):
        M[avg_len, avg_len + 1 + i] = -Bs[i]*mmul
        M[avg_len + 1 + i, avg_len + 1 + i] = -p
    M[avg_len, avg_len] = -As[0]
    M[avg_len, -1] = sent
    B = M.LLL()
    for row in B.rows():
        if row[-1] in {-sent, sent}:
            row *= [-1, 1][row[-1] == sent]
            if all(rr == 0 for rr in row[-2-len(salts):-1]):
                num = int("".join(str(digit) for digit in row[:-2-len(salts)]))
                h = hashnum(num)
                good = len(salts)
                for ind in range(len(salts)):
                    ss1, ss2 = salts[ind]
                    if hashnum(ss1, num, ss2) == hashes[ind]: good -= 1
                if good == 0:
                    print("success")
                    return num, h
                print(f"{good = }", len(salts))
    
    return False, False

def random_mutation(digits_list):
    l = len(digits_list)
    while True:
        i = random.randint(0, l - 1)
        j = random.randint(0, l - 1)
        if digits_list[i] == 9: continue
        if digits_list[j] == 0: continue
        digits_list[i] += 1
        digits_list[j] -= 1
        break
    return digits_list

def find_collision(preimage, h):
    preimage_list = [int(digit) for digit in str(preimage)]
    starting = preimage_list.copy()
    h1 = zlib.adler32("".join(str(d) for d in preimage_list).encode()) >> 16

    while True:
        preimage_list = random_mutation(preimage_list)
        if zlib.adler32("".join(str(d) for d in preimage_list).encode()) >> 16 == h1: # found collision
            if preimage_list != starting:
                if preimage_list[0] != 0:
                    num = int("".join(str(d) for d in preimage_list))
                    assert hashnum(num) == h
                    return num

def find_crc_collision(num, h):
    colliding_zeros = []
    colliding_ones = []

    for i in range(64):
        colliding_zeros.append(str(find_collision(num, h)).encode())
        colliding_ones.append(str(find_collision(num, h)).encode())


    zero_block = b"\x00"*39
    z = zlib.crc32(zero_block*len(colliding_zeros))
    base = zlib.crc32(b"".join(colliding_zeros))
    zero_crcs = [zlib.crc32(zz) for zz in colliding_zeros]

    mat = []
    for i, o in enumerate(colliding_ones):
        inp = zero_block*i + xor(o, colliding_zeros[i]) + zero_block * (len(colliding_zeros) - 1 - i)
        out = zlib.crc32(inp) ^ z
        bits = [int(bit) for bit in f"{out:032b}"]
        bits_next = [int(bit) for bit in f"{zlib.crc32(o) ^ zero_crcs[i]:032b}"]
        mat.append(bits + bits_next)
    mat = matrix(GF(2), mat).T
    ss = h
    for zz in zero_crcs:
        ss ^= zz
    
    vec = vector(GF(2), [b1 + b2 for b1, b2 in zip(
        [int(bit) for bit in f"{base:032b}"],
        [int(bit) for bit in f"{h:032b}"],
    )] + [int(bit) for bit in f"{ss:032b}"])
    sol = mat.solve_right(vec)
    assert mat*sol == vec

    payload = []
    for i in range(len(sol)):
        if sol[i]: payload.append(colliding_ones[i])
        else: payload.append(colliding_zeros[i])


    payload_ = b"".join(payload)
    assert zlib.crc32(payload_) == h
    xorsum = 0
    for block in payload:
        xorsum ^= zlib.crc32(block)
    assert xorsum == h

    return [int(num.decode()) for num in payload]


while True:
    conn = get_conn()
    get_num = lambda: int(conn.recvline().decode().strip().split()[-1])

    salts = []
    hashes = []
    my_salt = int("1"*(40 + random.getrandbits(5)))
    my_salt = random.getrandbits(256)
    conn.sendlineafter(b": ", str(my_salt).encode())
    server_salt = get_num()
    h = get_num()
    salts.append((server_salt, my_salt))
    hashes.append(h)

    num, h = find_h(salts, hashes)
    if num == h == False:
        conn.close()
        continue
    break
collisions = find_crc_collision(num, h)

for c in collisions:
    conn.sendline(b"1")
    conn.sendline(str(c).encode())
conn.sendline(b"2")

flag = conn.recvall().decode().strip().split()[-1]
print(f"{flag = }")
