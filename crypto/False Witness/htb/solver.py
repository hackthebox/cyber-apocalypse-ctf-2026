from pwn import remote
from Crypto.Cipher import AES
from sage.all import GF
import sys, re

P = 0xCD4A96D3B7FA7251A1BB765933FB676FCAE8C9026682E34F779122DFD66915BB
h = 65539
G = 34088345084211127115647332183962302218533120315780599148226628024854715749224

host, port = sys.argv[1].split(":")
io = remote(host, port, level="debug")

io.recvline()

encflag = bytes.fromhex(io.recvline().decode().strip())
g = GF(P).multiplicative_generator()
G = pow(g, (P-1)//h, P)

io.sendlineafter(b"generator: ", str(G).encode())

cands = [pow(G, i, P) for i in range(h)]

KEY_BITLEN = 256

KEY = ''
for i in range(KEY_BITLEN):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b": ", str(i).encode())
    io.recvuntil(b"result: ")
    res = eval(io.recvline().strip().decode())
    KEY += str(int(res in cands))

KEY = int(KEY, 2).to_bytes(32)
flag = AES.new(KEY, AES.MODE_ECB).decrypt(encflag)
print(flag)