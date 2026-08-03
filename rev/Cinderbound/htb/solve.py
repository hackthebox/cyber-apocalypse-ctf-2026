#!/usr/bin/env python3
import sys, re

def extract(path):
    data = open(path, 'rb').read()
    if not data.startswith(b'\x4d\x06'):
        sys.exit('not a MicroPython v6 .mpy file')
    vals = []
    for m in re.finditer(rb'\x07([\x01-\x09])([\x30-\x39]+)', data):
        if m.group(1)[0] == len(m.group(2)):
            vals.append(int(m.group(2)))
    return vals

def invert(target):
    acc = 0x5A
    flag = []
    for i, v in enumerate(target):
        c = v ^ acc ^ (i * 13 & 0xFF)
        acc = (acc + c) & 0xFF
        flag.append(chr(c))
    return ''.join(flag)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.exit(f'usage: {sys.argv[0]} <cinderbound.mpy>')
    target = extract(sys.argv[1])
    if len(target) != 16:
        sys.exit(f'expected 16 constants, found {len(target)}')
    print(f'HTB{{{invert(target)}}}')
