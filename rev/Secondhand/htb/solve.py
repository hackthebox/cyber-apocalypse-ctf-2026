#!/usr/bin/env python3
import argparse
import os
import re
import shutil
import subprocess
import sys

M = (1 << 64) - 1

TARGET = 0xB8491337C0DEBABE
K1   = 0xA5A5A5A5DEADBEEF
MUL  = 0x00000100000001B3
ROTL = 17
INPUT_LEN = 8

SM_INC  = 0x9E3779B97F4A7C15
SM_MUL1 = 0xBF58476D1CE4E5B9
SM_MUL2 = 0x94D049BB133111EB
DEFAULT_DOCKER_IMAGE = "secondhand"

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_BINARY = os.path.join(REPO_ROOT, "release", "re_secondhand", "secondhand")
FLAG_CIPHER_H = os.path.join(REPO_ROOT, "src", "genuine_check", "flag_cipher.h")
def rol(v, r):
    r &= 63
    return ((v << r) | (v >> (64 - r))) & M


def ror(v, r):
    r &= 63
    return ((v >> r) | (v << (64 - r))) & M


def f(x):
    v = (x ^ K1) & M
    v = rol(v, ROTL)
    v = (v * MUL) & M
    return (~v) & M


def modinv_2_64(a):
    assert a & 1, "MUL must be odd to be invertible mod 2**64"
    x = 1
    for _ in range(6):
        x = (x * (2 - a * x)) & M
    return x


def f_inv(t):
    v = (~t) & M
    v = (v * modinv_2_64(MUL)) & M
    v = ror(v, ROTL)
    return (v ^ K1) & M


def derive_preimage():
    xstar = f_inv(TARGET)
    assert f(xstar) == TARGET, "f_inv did not invert f -- transform mismatch"
    return xstar.to_bytes(INPUT_LEN, "little"), xstar

def splitmix64_stream(seed, n):
    s = seed & M
    out = bytearray()
    while len(out) < n:
        s = (s + SM_INC) & M
        z = s
        z = ((z ^ (z >> 30)) * SM_MUL1) & M
        z = ((z ^ (z >> 27)) * SM_MUL2) & M
        z = (z ^ (z >> 31)) & M
        out += z.to_bytes(8, "little")
    return bytes(out[:n])


def load_flag_cipher(path=FLAG_CIPHER_H):
    with open(path, "r") as fh:
        text = fh.read()
    body = re.search(r"FLAG_CIPHER\[[^\]]*\]\s*=\s*\{(.*?)\}", text, re.S)
    if not body:
        raise ValueError(f"could not find FLAG_CIPHER[] in {path}")
    return bytes(int(b, 16) for b in re.findall(r"0x[0-9a-fA-F]+", body.group(1)))


def decrypt_flag_offline(xstar, cipher=None):
    if cipher is None:
        cipher = load_flag_cipher()
    ks = splitmix64_stream(xstar, len(cipher))
    return bytes(c ^ k for c, k in zip(cipher, ks))

def _looks_like_flag_line(line):
    return line.startswith("HTB{") and line.endswith("}")


def run_binary(input_bytes, binary=DEFAULT_BINARY, docker_image=None):
    if binary and os.path.exists(binary) and os.access(binary, os.X_OK):
        try:
            p = subprocess.run([binary], input=input_bytes,
                               capture_output=True, timeout=30)
            return p.stdout.decode(errors="replace")
        except OSError:
            pass  # exec format error etc. -> fall through to docker

    image = docker_image or DEFAULT_DOCKER_IMAGE
    if shutil.which("docker") is None:
        raise RuntimeError(
            "cannot run the binary directly and docker is unavailable; "
            "use --no-run for the offline derivation, or run on amd64.")
    p = subprocess.run(["docker", "run", "--rm", "-i", image],
                       input=input_bytes, capture_output=True, timeout=120)
    return p.stdout.decode(errors="replace")


def extract_flag(stdout):
    for line in stdout.splitlines():
        line = line.strip()
        if _looks_like_flag_line(line):
            return line
    return None


def main(argv=None):
    ap = argparse.ArgumentParser(description="Reference solve for 'secondhand'.")
    ap.add_argument("--binary", default=DEFAULT_BINARY,
                    help="path to the challenge binary (native amd64 run)")
    ap.add_argument("--docker-image", default=None,
                    help=f"docker image to run if direct exec fails "
                         f"(default: {DEFAULT_DOCKER_IMAGE})")
    ap.add_argument("--print-input", action="store_true",
                    help="print only the derived 8-byte input (hex) and exit")
    ap.add_argument("--no-run", action="store_true",
                    help="skip running the binary; derive + offline-decrypt only")
    args = ap.parse_args(argv)

    input_bytes, xstar = derive_preimage()
    hex_in = input_bytes.hex(" ")

    if args.print_input:
        print(hex_in)
        return 0

    print(f"[*] decoded genuine check : computed == 0x{TARGET:016X}")
    print(f"[*] barrier3 leaf         : ~( rol(x ^ 0x{K1:016X}, {ROTL}) * "
          f"0x{MUL:016X} )")
    print(f"[*] inverted preimage  x* : 0x{xstar:016X}")
    print(f"[*] accepted input (8 LE) : {hex_in}")

    offline_flag = None
    try:
        offline_flag = decrypt_flag_offline(xstar).decode(errors="replace")
        print(f"[*] flag (offline decrypt): {offline_flag}")
    except (OSError, ValueError) as e:
        print(f"[!] offline decrypt skipped: {e}")

    if args.no_run:
        if offline_flag is None:
            print("[!] --no-run and offline decrypt unavailable; nothing to show")
            return 1
        print(offline_flag)
        return 0
        
    stdout = run_binary(input_bytes, binary=args.binary,
                        docker_image=args.docker_image)
    runtime_flag = extract_flag(stdout)
    print(f"[*] binary stdout         :\n{stdout.rstrip()}")

    if runtime_flag is None:
        print("[!] binary did not emit a flag line -- solve FAILED")
        return 1
    print(f"[*] flag (from binary)    : {runtime_flag}")

    if offline_flag is not None and offline_flag != runtime_flag:
        print(f"[!] MISMATCH: offline {offline_flag!r} != binary {runtime_flag!r}")
        return 1

    print(runtime_flag)
    return 0


if __name__ == "__main__":
    sys.exit(main())
