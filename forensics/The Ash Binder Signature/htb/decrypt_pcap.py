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
