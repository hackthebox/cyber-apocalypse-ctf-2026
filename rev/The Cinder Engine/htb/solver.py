#!/usr/bin/env python3
import os
import sys
import shutil
import platform
import subprocess

N = 32
ROUNDS = 8

# inverse mixing transcribed from the ROM: row i mask, bit j => out[i] ^= in[j]
LINV_MASKS = [
    0x6ce48355, 0x0ff2ebba, 0x3c82d3fb, 0x1966ab0b,
    0xef53a818, 0x1d5f8e6e, 0xd5153bbe, 0x14862ca9,
    0xcf92b4d3, 0xa63f32ca, 0x40790fd1, 0x1b6272ed,
    0xb496c2e2, 0x7352588b, 0x56dde8a9, 0xcd0c7bf8,
    0xff26c673, 0x492f496b, 0xb49fe2bf, 0x4663b73f,
    0xc8670898, 0x89d795e7, 0x2259e1d2, 0x80ebc6ce,
    0xa2282c2c, 0x7f994896, 0x6d23d5b6, 0x79d00162,
    0x6f9f3d5d, 0x41f83dda, 0x18215869, 0x92a1e5ee,
]


def lin_inv(s):
    o = [0] * N
    for i in range(N):
        m, v = LINV_MASKS[i], 0
        for j in range(N):
            if (m >> j) & 1:
                v ^= s[j]
        o[i] = v
    return o


def find_rom_data(blob):
    full = set(range(256))
    for off in range(len(blob) - 256):
        if set(blob[off:off + 256]) == full:
            sbox = list(blob[off:off + 256])
            rk_flat = list(blob[off + 256:off + 256 + N * (ROUNDS + 1)])
            t = off + 256 + N * (ROUNDS + 1)
            tgt = list(blob[t:t + N])
            rk = [rk_flat[r * N:(r + 1) * N] for r in range(ROUNDS + 1)]
            return sbox, rk, tgt
    raise SystemExit("could not locate ROM tables")


def recover_vow(blob):
    sbox, rk, tgt = find_rom_data(blob)
    sbox_inv = [0] * 256
    for i, v in enumerate(sbox):
        sbox_inv[v] = i

    s = list(tgt)
    for r in range(ROUNDS, 0, -1):
        s = [s[i] ^ rk[r][i] for i in range(N)]
        s = lin_inv(s)
        s = [sbox_inv[b] for b in s]
    return bytes(s[i] ^ rk[0][i] for i in range(N))


def elf_machine(blob):
    """Return the ELF e_machine value, or None if not an ELF."""
    if blob[:4] != b"\x7fELF":
        return None
    return int.from_bytes(blob[18:20], "little")


def build_run_cmd(binpath, blob):
    """Pick how to invoke the binary: natively, or under qemu if the ELF
    architecture differs from the host (e.g. an aarch64 binary on x86-64)."""
    machine = elf_machine(blob)
    host = platform.machine().lower()
    host_is_arm = host in ("aarch64", "arm64")

    # EM_AARCH64 = 183 (0xB7), EM_X86_64 = 62 (0x3E)
    if machine == 183 and not host_is_arm:
        qemu = shutil.which("qemu-aarch64-static") or shutil.which("qemu-aarch64")
        if not qemu:
            raise SystemExit(
                "This is an ARM64 binary but no qemu-aarch64 found.\n"
                "Install it with:  sudo apt install -y qemu-user-static libc6-arm64-cross"
            )
        cmd = [qemu]
        sysroot = "/usr/aarch64-linux-gnu"
        if os.path.isdir(sysroot):
            cmd += ["-L", sysroot]
        cmd.append(os.path.abspath(binpath))
        return cmd
    # Native (host arch matches, or unknown -> just try it)
    return [os.path.abspath(binpath)]


def main():
    binpath = sys.argv[1] if len(sys.argv) > 1 else "./cinder"
    blob = open(binpath, "rb").read()

    vow = recover_vow(blob)
    print("[*] recovered vow:", vow.hex())

    cmd = build_run_cmd(binpath, blob)
    out = subprocess.run(cmd, input=vow, capture_output=True)
    flag = out.stdout.decode(errors="replace").strip()
    if flag:
        print(flag)
    else:
        sys.stderr.write(
            "[!] no output from engine.\n"
            "    stderr: " + out.stderr.decode(errors="replace") + "\n"
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
