![img](../../assets/banner.png)

<img src="../../assets/htb.png" align=left />        <font size="10">Wireless Connections</font>

8<sup>th</sup> June 2026

Prepared By: Lean

Challenge Author(s): Lean

Difficulty: <font color=red>Hard</font>

Classification: Official

# [Synopsis](#synopsis)

Reverse engineer an ESP32-S3 firmware dump, identify the custom Arduino logic in Ghidra, recover the encrypted byte array, use the board MAC OUI to reduce the key search space, and decrypt the relay key.

## Description

Stormbound's scouts swept a shuttered Suncourt townhouse after a chain of forged writs began reaching Crownspire before their couriers did. Behind a wall plate they found a crude listening node stamped with a single useful marking, ESP32_S3_DevKitC-1U. Somewhere inside it lies the relay key used to pass whispers between rival agents. Cut the hidden channel before the next false order moves through the realm.

## Skills Required

- Basic ESP32 flash layout knowledge.
- Basic C and Xtensa assembly understanding.
- Ability to use Ghidra with raw embedded firmware regions.
- Basic scripting skills.

## Skills Learned

- Carving ESP32 partitions from a full flash dump.
- Mapping ESP32-S3 IROM, DROM, and useful DRAM globals manually in Ghidra.
- Finding Arduino sketch logic inside ESP-IDF library code.
- Recognizing weak hardware-derived key material.
- Using public hardware/vendor metadata to reduce a brute-force search.

## Application Overview

The supplied file is a full ESP32-S3 flash dump rather than a normal desktop executable. The application code is inside the first OTA application partition. The firmware is Arduino-based, so most of the image is ESP-IDF and Arduino framework code. The useful custom logic is small and is best reached through strings and cross references instead of reading the image linearly.

## Technology Background

### What An ESP32 Flash Dump Contains

An ESP32 stores several different regions in SPI flash. A raw dump is not one continuous executable. It is closer to a disk image with small boot/configuration regions and one or more application images.

The common regions are listed below.

```text
bootloader       early boot code near the start of flash
partition table  flash map describing where each region starts
nvs              key/value storage used by ESP-IDF for device settings
app partition    the compiled firmware application
data partitions  filesystems, coredumps, OTA metadata, or erased space
```

The partition table is the first thing to trust because it tells us where executable code actually lives. ESP-IDF project files can describe partitions in CSV-style definitions, but in flash the table is stored as binary records. The official ESP32-S3 ESP-IDF partition documentation is useful background.

[ESP-IDF Partition Tables - ESP32-S3](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/api-guides/partition-tables.html)

### What An ESP Application Image Contains

An ESP app partition is also not a normal ELF file. The app image has its own image header, then a list of loadable segments. Each segment gives the values shown below.

```text
where the bytes are in the app file
where those bytes should appear in memory
how long the segment is
what memory type it belongs to
```

The names that matter during reversing are listed below.

```text
DROM  data read from flash, usually strings, constants, and read-only arrays
IROM  code executed from flash through the instruction cache
DRAM  initialized writable data
IRAM  code copied into internal RAM for faster or special execution
RTC   tiny low-power memory region used by ESP chips
```

This distinction matters because Ghidra needs the same virtual addresses that the ESP32 uses at runtime. If the app says that strings are loaded at `0x3c0a0020`, cross references in code will point there, not to the raw file offset.

Espressif documents the ESP32-S3 app image format in the linked reference.

[ESP-IDF App Image Format - ESP32-S3](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/api-reference/system/app_image_format.html)

### What esptool Gives Us

`esptool` understands ESP image headers. It is useful before Ghidra because it tells us the segment load addresses and file offsets without guessing.

The command used in this writeup is shown below.

```bash
esptool --chip esp32s3 image-info /tmp/app0.bin
```

The segment table from that command is the bridge between the raw bytes and the memory map we create in Ghidra.

Reference

[esptool image-info - ESP32-S3](https://docs.espressif.com/projects/esptool/en/latest/esp32s3/esptool/basic-commands.html#output-bin-image-details-image-info)

### What Ghidra Needs

Ghidra can analyze raw firmware, but it needs help because there is no ELF loader giving it sections and addresses automatically. The manual process is shown below.

```text
1. import the code segment as raw Xtensa little-endian code
2. set the IROM base address from esptool
3. add DROM as another initialized memory block
4. optionally add the small DRAM block when global pointers matter
5. run auto-analysis
6. use strings and cross references to find custom code
```

When adding memory blocks, the useful Ghidra concept is the Memory Map window. That is where IROM, DROM, and any supporting DRAM blocks are created at their runtime addresses.

References

- [Ghidra Student Guide](https://ghidra.re/ghidra_docs/GhidraClass/Beginner/Introduction_to_Ghidra_Student_Guide.html)
- [Ghidra Project](https://github.com/NationalSecurityAgency/ghidra)

### What The Board Hint Gives Later

The board string `ESP32_S3_DevKitC-1U` is not only architecture trivia. It tells us which hardware family to research once the code shows that a hardware-derived value matters. At this stage, keep the model in your notes and do not assume how it will be used.

Useful background reference

[ESP32-S3-DevKitC-1 - Espressif](https://docs.espressif.com/projects/esp-dev-kits/en/latest/esp32s3/esp32-s3-devkitc-1/index.html)

## Step-by-Step Attack Path

---

### Step 1 - Confirm The File Is An ESP32 Flash Dump

Start with basic file inspection, but do not trust `file` too much on embedded firmware.

```bash
wc -c firmware.bin
file firmware.bin
xxd -g1 -l 0x40 firmware.bin
```

Useful output

```text
 8388608 firmware.bin
firmware.bin: DOS executable (COM)
00000000: e9 03 02 3f b8 88 3c 40 ee 00 00 00 09 00 00 00  ...?..<@........
00000010: 00 ff ff 00 00 00 00 01 20 28 ce 3f 6c 11 00 00  ........ (.?l...
00000020: 50 00 00 00 01 00 00 00 76 35 2e 35 2e 31 2d 32  P.......v5.5.1-2
00000030: 35 35 2d 67 30 37 65 39 62 66 34 39 37 30 00 00  55-g07e9bf4970..
```

The DOS result is a false lead. ESP32 images commonly start with `0xe9`, which can confuse generic file detection. The 8 MiB size and ESP-style headers are consistent with a raw flash dump.

This particular ESP32-S3 Arduino image has a bootloader image at `0x0`, the partition table at `0x8000`, and NVS at `0x9000`. Check the partition table manually.

```bash
xxd -g1 -s 0x8000 -l 0x1000 firmware.bin
```

Useful excerpt

```text
00008000: aa 50 01 02 00 90 00 00 00 50 00 00 6e 76 73 00  .P.......P..nvs.
00008020: aa 50 01 00 00 e0 00 00 00 20 00 00 6f 74 61 64  .P....... ..otad
00008040: aa 50 00 10 00 00 01 00 00 00 33 00 61 70 70 30  .P........3.app0
00008060: aa 50 00 11 00 00 34 00 00 00 33 00 61 70 70 31  .P....4...3.app1
00008080: aa 50 01 82 00 00 67 00 00 00 18 00 73 70 69 66  .P....g.....spif
000080a0: aa 50 01 03 00 00 7f 00 00 00 01 00 63 6f 72 65  .P..........core
000080c0: eb eb ff ff ff ff ff ff ff ff ff ff ff ff ff ff  ................
```

The table describes the useful regions below.

```text
name      type/subtype   offset     size
nvs       data/0x02      0x009000   0x005000
otadata   data/0x00      0x00e000   0x002000
app0      app/ota_0      0x010000   0x330000
app1      app/ota_1      0x340000   0x330000
spiffs    data/spiffs    0x670000   0x180000
coredump  data/coredump  0x7f0000   0x010000
```

Carve the bootloader and inspect it with `esptool`.

```bash
dd if=firmware.bin of=/tmp/bootloader.bin bs=1 count=$((0x8000)) status=none
esptool --chip esp32s3 image-info /tmp/bootloader.bin
```

Useful excerpt

```text
ESP32S3 Image Header
====================
Entry point: 0x403c88b8
Segments: 3
Flash size: 8MB
Flash freq: 80m
Flash mode: DIO

Bootloader Information
======================
Bootloader version: 1
ESP-IDF: v5.5.1-255-g07e9bf4970
```

The partition map spans the expected 8 MiB flash range. `app0` begins at `0x10000`, the second OTA slot begins at `0x340000`, and the final coredump partition sits at `0x7f0000`. The bootloader and app headers also report an `8MB` flash layout, so the raw dump size and firmware metadata agree.

Compute the partition bounds instead of eyeballing them.

```python
from pathlib import Path

fw = Path("firmware.bin").read_bytes()
parts = [
    ("bootloader",  0x000000, 0x008000),
    ("partitions", 0x008000, 0x001000),
    ("nvs",        0x009000, 0x005000),
    ("otadata",    0x00e000, 0x002000),
    ("app0",       0x010000, 0x330000),
    ("app1",       0x340000, 0x330000),
    ("spiffs",     0x670000, 0x180000),
    ("coredump",   0x7f0000, 0x010000),
]

for name, off, size in parts:
    end = off + size
    print(f"{name:10s} off=0x{off:06x} size=0x{size:06x} end=0x{end:06x} in_image={end <= len(fw)}")
print(f"image_end 0x{len(fw):06x}")
```

Output

```text
bootloader off=0x000000 size=0x008000 end=0x008000 in_image=True
partitions off=0x008000 size=0x001000 end=0x009000 in_image=True
nvs        off=0x009000 size=0x005000 end=0x00e000 in_image=True
otadata    off=0x00e000 size=0x002000 end=0x010000 in_image=True
app0       off=0x010000 size=0x330000 end=0x340000 in_image=True
app1       off=0x340000 size=0x330000 end=0x670000 in_image=True
spiffs     off=0x670000 size=0x180000 end=0x7f0000 in_image=True
coredump   off=0x7f0000 size=0x010000 end=0x800000 in_image=True
image_end 0x800000
```

Check which partitions contain data.

```python
from pathlib import Path

fw = Path("firmware.bin").read_bytes()

parts = [
    ("nvs",      0x009000, 0x005000),
    ("otadata", 0x00e000, 0x002000),
    ("app0",    0x010000, 0x330000),
    ("app1",    0x340000, 0x330000),
    ("spiffs",  0x670000, 0x180000),
    ("coredump",0x7f0000, 0x010000),
]

for name, off, size in parts:
    data = fw[off:off + size]
    print(f"{name:8} ff={data.count(0xff) / len(data):.2%}")
```

Useful output

```text
nvs      ff=100.00%
otadata  ff=99.85%
app0     ff=74.35%
app1     ff=100.00%
spiffs   ff=100.00%
coredump ff=100.00%
```

`app0` is the only region worth reversing. The other large regions are erased or not relevant.

The terms in the table matter.

```text
offset  where the partition starts in the full flash dump
size    how many bytes belong to the partition
app0    first OTA application slot, usually the active firmware
app1    second OTA application slot, used only if another image was installed
nvs     non-volatile key/value storage, useful for configuration artifacts
```

This gives the first important rule for ESP reversing. Always carve the app partition before trying to disassemble code.

### Step 2 - Extract The Application Partition

Carve out `app0` from the full flash dump.

```bash
dd if=firmware.bin of=/tmp/app0.bin bs=1 skip=$((0x10000)) count=$((0x330000)) status=none
```

Use `esptool` to inspect the ESP32-S3 image header.

```bash
esptool --chip esp32s3 image-info /tmp/app0.bin
```

Useful excerpt

```text
ESP32S3 Image Header
====================
Entry point: 0x40375cd8
Segments: 6
Flash size: 8MB
Flash freq: 80m
Flash mode: DIO

Segments Information
====================
Segment   Length   Load addr   File offs  Memory types
-------  -------  ----------  ----------  ------------
      0  0x22d40  0x3c0a0020  0x00000018  DROM
      1  0x05248  0x3fc96c00  0x00022d60  BYTE_ACCESSIBLE, MEM_INTERNAL, DRAM
      2  0x08060  0x40374000  0x00027fb0  MEM_INTERNAL, IRAM
      3  0x9a404  0x42000020  0x00030018  IROM
      4  0x0aae4  0x4037c060  0x000ca424  MEM_INTERNAL, IRAM
      5  0x00020  0x50000200  0x000d4f10  RTC_DATA

```

The two regions to focus on first are shown below.

```text
DROM: strings, constants, and read-only data at 0x3c0a0020
IROM: flash-mapped code at 0x42000020
```

DRAM is also useful later for resolving initialized global pointers.

```text
DRAM: writable globals at 0x3fc96c00
```

Carve those two regions so they can be loaded cleanly in Ghidra.

```bash
dd if=/tmp/app0.bin of=/tmp/drom.bin bs=1 skip=$((0x20)) count=$((0x22d40)) status=none
dd if=/tmp/app0.bin of=/tmp/irom.bin bs=1 skip=$((0x30020)) count=$((0x9a404)) status=none
dd if=/tmp/app0.bin of=/tmp/dram.bin bs=1 skip=$((0x22d68)) count=$((0x05248)) status=none
```

There is a small trap here. The `File offs` value points at the 8-byte ESP segment header. The bytes that should be mapped at `Load addr` start immediately after that header, so the payload offsets are `0x18 + 8 = 0x20` for DROM, `0x22d60 + 8 = 0x22d68` for DRAM, and `0x30018 + 8 = 0x30020` for IROM. If the import looks shifted by eight bytes, this is usually the reason.

Do not use the `Load addr` values as file offsets. Those are runtime addresses.

### Step 3 - Set Up Ghidra Manually

Open Ghidra and create a project for the firmware. Import `/tmp/irom.bin` as a raw binary.

```text
Language: Xtensa / little endian / 32-bit
Base address: 0x42000020
```

If the Xtensa language is not available in your Ghidra installation, install an Xtensa processor module first and restart Ghidra. Do not import the full flash dump as a single flat executable. The code and data are mapped at ESP32 virtual addresses, so a flat import will make cross references harder to reason about.

During import, keep these options in mind.

```text
Format        Raw Binary
Language      Xtensa little-endian
Base address  same as the IROM load address
Analyzer      enable default analysis after import
```

After importing IROM, open the Memory Map and add the DROM bytes as an initialized block.

```text
Block name: DROM
File:       /tmp/drom.bin
Address:    0x3c0a0020
Length:     0x22d40
Permissions: read
```

For this firmware I also add DRAM because the Wi-Fi globals live there.

```text
Block name: DRAM
File:       /tmp/dram.bin
Address:    0x3fc96c00
Length:     0x5248
Permissions: read/write
```

Run auto-analysis. The first pass will still contain a lot of library code and literal pools. That is normal for ESP-IDF firmware. The goal is to find the small Arduino sketch logic inside it.

After analysis, do a quick sanity check.

```text
1. open the Symbol Tree and confirm functions exist near 0x42000020
2. open Window -> Memory Map and confirm IROM, DROM, and DRAM have different bases
3. press G and jump to 0x3c0a0020 and confirm it lands in DROM
4. press G and jump to 0x3fc96c00 and confirm it shows initialized global data
5. press G and jump to 0x42000020 and confirm it lands in executable code/data
```

If DROM is missing, code references to strings and byte arrays will look broken. That is the most common reason ESP32 firmware looks worse in Ghidra than it really is.

At this point, confirm manually that Ghidra is using the Xtensa little-endian language and that the Memory Map shows IROM at `0x42000020`, DROM at `0x3c0a0020`, and DRAM at `0x3fc96c00`. Do this before spending time on the decompiler output. A wrong base address will make otherwise correct references look broken.

### Step 4 - Use Strings As Anchors

Before browsing code, inspect strings in the extracted app.

```bash
strings -a -n 4 -t x /tmp/app0.bin | head -n 80
strings -a -n 4 -t x /tmp/app0.bin | grep -Ei 'ssid|pass|blink|spy|bug|task'
```

Relevant hits from the output

```text
00000120 blink_task
0000012b bugged26
00000134 SpyHouse
```

These offsets are app-file offsets. The strings are in the DROM segment, whose file bytes start at app offset `0x20` and load at `0x3c0a0020`. Convert them as shown below.

```text
blink_task -> 0x3c0a0120
bugged26   -> 0x3c0a012b
SpyHouse   -> 0x3c0a0134
```

In Ghidra, go to those DROM addresses and create strings if auto-analysis did not already do it. The Wi-Fi strings confirm that we are in the Arduino sketch data, while `blink_task` is the cleanest direct anchor into the custom setup routine.

Manual Ghidra workflow

```text
1. press G and jump to 0x3c0a0120
2. if the bytes are not typed as a string, select them and press A or use Data -> TerminatedCString
3. right-click the string and choose References -> Show References to Address
4. follow the code reference into IROM
5. keep the Wi-Fi strings nearby as context while reading the setup code
```

This is faster than starting at the entry point because Arduino and ESP-IDF setup code adds many layers before reaching the user sketch.

The mapped strings and byte array looked like this in Ghidra.

```text
s_blink_task     at 0x3c0a0120 -> blink_task
s_wifi_password  at 0x3c0a012b -> bugged26
s_wifi_ssid      at 0x3c0a0134 -> SpyHouse
encrypted_flag   at 0x3c0b103b -> 10 a0 68 e7 5d e6 e7 0f 12 bb b2 f3 ca b4 d2 02 cb de d8 20 0d e5 68 92 42 00 be 14 f0 7b ba 01
```

### Step 5 - Reverse The Setup Routine

Following the `blink_task` reference leads to a function at `0x42002ccc`. The function shape matches an Arduino `setup()` routine.

```text
Serial.begin(...)
WiFi.begin(ssid, password)
xTaskCreate(..., "blink_task", ...)
while (WiFi.status() != WL_CONNECTED) { ... }
WiFi.macAddress(mac)
...
Serial.println(...)
```

After creating functions and renaming the obvious ones, my working labels were as follows.

```text
blink_task_candidate    at 0x42002c60
decrypt_flag_candidate  at 0x42002ca0
arduino_setup_candidate at 0x42002ccc
```

These addresses are not placeholders. The same region in the Listing view contains the custom routines back-to-back.

```text
42002c60 <blink_task_candidate>:
42002ca0 <decrypt_flag_candidate>:
42002ccc <arduino_setup_candidate>:
```

The setup decompile was still full of generic `FUN_` names, but the structure was readable.

```c
(*DAT_42000054)(PTR_blink_task_candidate_42000048,
                PTR_s_blink_task_42000044,
                0x800, 0, 1, 0, 0x7fffffff);

do {
    iVar3 = FUN_42003e30(uVar1);
    if (iVar3 == 3) {
        FUN_42003e78(uVar1, &bStack_4b);
        decrypt_flag_candidate(
            PTR_encrypted_flag_42000050,
            auStack_45,
            0x20,
            ((uint)bStack_4b << 0x10 |
             (uint)bStack_4a << 8  |
             (uint)bStack_49) * DAT_4200004c);
        uStack_25 = 0;
        FUN_42005e00(DAT_42000038, auStack_45);
    }
    FUN_42006488(0xfa);
} while (true);
```

The important part is after the Wi-Fi connection loop. In Ghidra pseudocode, clean up the temporary variables and rename the stack buffer used by `WiFi.macAddress` to `mac`. The code constructs a 24-bit value from only the first three MAC bytes.

At this point, use the decompiler like a notebook. Rename variables as their role becomes clear.

```text
local byte[6]       -> mac
temporary uint32    -> oui
next uint32         -> seed
32-byte stack array -> decrypted
```

The exact function names may not be recovered automatically, but the call pattern is recognizable from the arguments and nearby strings.

```c
uint32_t oui =
    ((uint32_t)mac[0] << 16) |
    ((uint32_t)mac[1] << 8)  |
    ((uint32_t)mac[2]);
```

Immediately after that, the value is multiplied by a constant.

```c
uint32_t seed = (oui * 0x01000193u) & 0xffffffffu;
```

In the raw decompile this multiplier appears as `DAT_4200004c`. Reading that literal gives the little-endian bytes for `0x01000193`.

If DRAM was mapped, the first two words in the DRAM block also make the Wi-Fi call easier to annotate. Ghidra may not record direct references to the SSID and password strings because `WiFi.begin` receives them through these initialized globals.

```text
0x3fc96c00 -> 0x3c0a012b -> "bugged26"
0x3fc96c04 -> 0x3c0a0134 -> "SpyHouse"
```

This can be checked directly in the carved DRAM bytes. The DRAM segment payload starts at app offset `0x22d68`, so in the full flash dump it starts at `0x10000 + 0x22d68 = 0x32d68`.

```bash
xxd -g4 -s $((0x10000 + 0x22d68)) -l 0x20 firmware.bin
```

Output

```text
00032d68: 2b010a3c 34010a3c 01000000 01000000  +..<4..<........
00032d78: 01000000 00000000 00000000 00000000  ................
```

Read little-endian, the first two words are `0x3c0a012b` and `0x3c0a0134`, exactly the password and SSID string addresses found earlier.

At this point the exact MAC address is not needed. The firmware has reduced the key material to the OUI, which is only 24 bits and is vendor-specific.

The setup routine then passes three things into a smaller helper.

```text
encrypted buffer pointer
output stack buffer
length 0x20
derived seed
```

This tells us the helper is likely the decryptor.

Confirm that by opening the helper and checking for the traits listed below.

```text
a loop counter
one byte read from the encrypted buffer
one byte written to the output buffer
the derived seed updated once per byte
```

The relevant setup instructions show the OUI construction and decryptor call without relying on guessed pseudocode.

```text
42002d4b: call8  0x42003e78        ; writes six MAC bytes to stack
42002d4e: l8ui   a13, a1, 21       ; mac[0]
42002d51: l8ui   a8,  a1, 22       ; mac[1]
42002d54: slli   a13, a13, 16
42002d57: slli   a8,  a8, 8
42002d5a: or     a13, a13, a8
42002d5d: l8ui   a8,  a1, 23       ; mac[2]
42002d60: l32r   a10, 0x42000050   ; 0x3c0b103b, encrypted buffer
42002d63: or     a13, a13, a8
42002d66: l32r   a8,  0x4200004c   ; 0x01000193
42002d69: movi.n a12, 32
42002d6b: mull   a13, a13, a8
42002d6e: addi   a11, a1, 27       ; output buffer
42002d71: call8  0x42002ca0        ; decrypt_flag_candidate
42002d7f: call8  0x42005e00        ; print decrypted buffer
```

That instruction sequence proves the seed is based only on the first three MAC bytes and that the encrypted DROM buffer is passed to the decryptor with length `32`.

### Step 6 - Reverse The Decryptor

The helper function is around `0x42002ca0`. Rename it to something like `decrypt_flag` while working. The loop is short and easy to clean up manually.

In the Listing view, the low-level signs are listed below.

```text
constant load of 0x0019660d
constant load of 0x3c6ef35f
multiply/add updating a 32-bit state
right shift by 16
byte-sized XOR with the encrypted input byte
store into the output buffer
```

The Listing view backs those signs with a short loop.

```text
42002ca3: l32r  a10, 0x42000028   ; 0x0019660d
42002ca6: l32r  a11, 0x4200002c   ; 0x3c6ef35f
42002cb0: mull  a5, a5, a10
42002cb5: l8ui  a13, a13, 0       ; encrypted byte
42002cb8: add.n a5, a5, a11
42002cba: extui a9, a5, 16, 16
42002cbf: xor   a9, a9, a13
42002cc2: s8i   a9, a12, 0        ; decrypted byte
42002cc5: addi.n a8, a8, 1
42002cc7: j     0x42002cab
```

The decompiler may show temporary names and casts, but the data flow is the important part. State update first, XOR key byte second, output byte last.

The decompile of `0x42002ca0` was enough to transcribe the algorithm.

```c
void decrypt_flag_candidate(int param_1,int param_2,int param_3,int param_4)
{
  int iVar1;
  int iVar2;
  int iVar3;

  iVar2 = DAT_4200002c;
  iVar1 = DAT_42000028;
  for (iVar3 = 0; iVar3 != param_3; iVar3 = iVar3 + 1) {
    param_4 = param_4 * iVar1 + iVar2;
    *(byte *)(param_2 + iVar3) =
        (byte)((uint)param_4 >> 0x10) ^ *(byte *)(param_1 + iVar3);
  }
  return;
}
```

Reading the literal pool at `0x42000028` confirms the constants.

```text
0x42000028: 0d 66 19 00 5f f3 6e 3c
```

The same bytes are visible in the full flash dump. IROM payload starts at full flash offset `0x10000 + 0x30020 = 0x40020`, so virtual address `0x42000028` is full flash offset `0x40028`.

```bash
xxd -g1 -s 0x40028 -l 0x10 firmware.bin
```

Output

```text
00040028: 0d 66 19 00 5f f3 6e 3c 4c c5 c9 3f 1c 00 00 08  .f.._.n<L..?....
```

The decompiled shape is shown below.

```c
void decrypt_flag(const uint8_t *enc, uint8_t *out, size_t len, uint32_t seed) {
    uint32_t state = seed;

    for (size_t i = 0; i < len; i++) {
        state = state * 0x0019660d + 0x3c6ef35f;
        out[i] = enc[i] ^ ((state >> 16) & 0xff);
    }
}
```

The two constants are the classic linear congruential generator constants.

```text
0x0019660d = 1664525
0x3c6ef35f = 1013904223
```

So the firmware is not using a cryptographic primitive. It generates one byte of keystream per byte of ciphertext and XORs it with a 32-byte buffer.

### Step 7 - Extract The Encrypted Buffer

Return to the setup routine and inspect the argument passed as the encrypted input. Ghidra shows a pointer into DROM.

```text
0x3c0b103b
```

Convert this virtual address back to a flash/file offset using the DROM mapping from `esptool`.

```text
DROM base VA:       0x3c0a0020
DROM flash offset:  0x10020

0x3c0b103b - 0x3c0a0020 = 0x1101b
0x10020 + 0x1101b       = 0x2103b
```

Verify the bytes in the full flash dump.

```bash
xxd -g1 -s 0x21030 -l 0x60 firmware.bin
```

Useful output

```text
00021030: 6c 69 62 2f 64 74 6f 61 2e 63 00 10 a0 68 e7 5d  lib/dtoa.c...h.]
00021040: e6 e7 0f 12 bb b2 f3 ca b4 d2 02 cb de d8 20 0d  .............. .
00021050: e5 68 92 42 00 be 14 f0 7b ba 01 00 00 00 00 00  .h.B....{.......
00021060: 00 00 00 00 70 30 00 42 90 30 00 42 1c 50 00 42  ....p0.B.0.B.P.B
00021070: a4 2d 00 42 00 00 00 00 00 00 00 00 54 33 00 42  .-.B........T3.B
00021080: 74 33 00 42 1c 50 00 42 a4 30 00 42 00 00 00 00  t3.B.P.B.0.B....
```

The 32-byte ciphertext starts at `0x2103b`.

```text
10 a0 68 e7 5d e6 e7 0f
12 bb b2 f3 ca b4 d2 02
cb de d8 20 0d e5 68 92
42 00 be 14 f0 7b ba 01
```

This matched the bytes shown in Ghidra at `0x3c0b103b`, so the VA-to-flash conversion was not just a guess. In the Bytes view, jump to `0x3c0b103b` and read 32 bytes.

```text
10a068e75de6e70f12bbb2f3cab4d202cbded8200de568924200be14f07bba01
```

### Step 8 - Infer Candidate OUIs From The Board Model

The firmware derives the seed from a MAC OUI, but the setup code does not require knowing the full MAC. An OUI is the first 24 bits of a MAC address, assigned to a vendor or organization. That is why the exact board model now becomes useful.

The challenge text already names the board family, `ESP32_S3_DevKitC-1U`.

Look up the board family and vendor. The official Espressif documentation identifies the ESP32-S3-DevKitC-1 family as Espressif ESP32-S3 development boards using ESP32-S3-WROOM modules, including the `ESP32-S3-WROOM-1U` module variant.

[ESP32-S3-DevKitC-1 - Espressif](https://docs.espressif.com/projects/esp-dev-kits/en/latest/esp32s3/esp32-s3-devkitc-1/index.html)

Then collect Espressif OUI assignments from the IEEE public CSV.

```bash
curl -L -s https://standards-oui.ieee.org/oui/oui.csv \
  | awk -F, 'tolower($3) ~ /espressif/ {print $2}' \
  | sort -u > /tmp/espressif_ouis.txt
wc -l /tmp/espressif_ouis.txt
head -n 5 /tmp/espressif_ouis.txt
tail -n 5 /tmp/espressif_ouis.txt
```

Example output

```text
     315 /tmp/espressif_ouis.txt
004B12
007007
048308
04B247
083A8D
F8B3B7
FC012C
FCB467
FCE8C0
FCF5C4
```

The CSV emits normal six-hex-digit assignments such as `004B12`, not `0x`-prefixed integers. Convert each value to a 24-bit integer before using it in the seed formula. In this run the command returned 315 unique Espressif candidates, not millions. The exact count may change as new vendor prefixes are assigned, but the approach stays the same.

Reference

- [IEEE OUI/EUI Guidelines](https://standards-support.ieee.org/hc/en-us/articles/4888705676564-Guidelines-for-Use-of-Extended-Unique-Identifier-EUI-Organizationally-Unique-Identifier-OUI-and-Company-ID-CID)
- [IEEE public OUI registry](https://standards-oui.ieee.org/)
- [IEEE OUI CSV](https://standards-oui.ieee.org/oui/oui.csv)

### Step 9 - Reimplement And Debug The Decryption

Before writing a polished solver, reimplement the Ghidra pseudocode in a short scratch script and print candidates that look like a flag.

```python
from pathlib import Path

fw = Path("firmware.bin").read_bytes()
ct = fw[0x2103b:0x2103b + 32]

ouis = [
    int(line.strip().replace(":", ""), 16)
    for line in Path("/tmp/espressif_ouis.txt").read_text().splitlines()
    if line.strip()
]

def decrypt_for_oui(oui):
    seed = (oui * 0x01000193) & 0xffffffff
    state = seed
    out = bytearray()

    for b in ct:
        state = (state * 1664525 + 1013904223) & 0xffffffff
        out.append(b ^ ((state >> 16) & 0xff))

    return seed, bytes(out)

for oui in ouis:
    seed, pt = decrypt_for_oui(oui)
    shown = pt.rstrip(b"\x00")
    if shown.startswith(b"HTB{") and shown.endswith(b"}"):
        print(f"oui=0x{oui:06x}")
        print(f"seed=0x{seed:08x}")
        print(shown.decode())
        break
```

If the script prints nothing, debug it in this order.

```text
1. confirm ct is exactly 32 bytes
2. confirm the first ciphertext byte is read from 0x2103b, not 0x21040
3. confirm the state update happens before deriving the XOR byte
4. confirm the XOR byte is (state >> 16) & 0xff
5. confirm each OUI is parsed as a 24-bit integer, not as a full MAC string
```

For quick debugging, print the first few plaintext bytes for one candidate and compare whether they look printable. Garbage output usually means the address conversion or the order of the LCG update is wrong.

Successful output

```text
oui=0x7cdfa1
seed=0x65940a73
HTB{REDACTED}
```

This output confirms that the vendor-OUI route is enough to recover the secret. No full device MAC is required for the intended solve.

### Step 10 - Use The Solver

The final solver automates the same process. It is self-contained. The Espressif OUI candidates are embedded as a static snapshot, so the solver does not fetch the IEEE CSV or require internet access at runtime.

```bash
python3 solver.py
```

Expected output

```text
[*] Loaded 315 embedded Espressif OUI candidates
[+] OUI  : 0x7cdfa1
[+] Seed : 0x65940a73
[+] Flag : HTB{REDACTED}
```

The solver does not take command-line options and has no online OUI lookup path. The embedded candidates are stored as a normal Python array.

```python
ESPRESSIF_OUIS = [
    "00:4B:12",
    "00:70:07",
    ...
]
```
