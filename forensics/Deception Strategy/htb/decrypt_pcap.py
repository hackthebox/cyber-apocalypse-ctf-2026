#!/usr/bin/env python3
import argparse
import shutil
import subprocess
import sys


DEFAULT_SESSION_TOKEN = "1aa3a658ce2c4a4258983eba1853f08c"


def rc4(data: bytes, key: bytes) -> bytes:
    state = list(range(256))
    j = 0

    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]

    i = j = 0
    output = bytearray()
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        output.append(byte ^ state[(state[i] + state[j]) & 0xFF])

    return bytes(output)


def extract_requests(pcap: str):
    display_filter = (
        'http.host == "discord-cdn.com" && '
        'http.request.method == "POST" && '
        'http.request.uri == "/api/v9/experiments"'
    )
    command = [
        "tshark",
        "-r",
        pcap,
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-e",
        "frame.number",
        "-e",
        "frame.time",
        "-e",
        "ip.dst",
        "-e",
        "http.file_data",
    ]

    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as error:
        sys.stderr.write(error.stderr)
        raise SystemExit(f"tshark failed with exit code {error.returncode}")

    for line in result.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) < 4 or not fields[3]:
            continue

        try:
            ciphertext = bytes.fromhex(fields[3].replace(":", ""))
        except ValueError:
            print(f"[!] Frame {fields[0]} has an invalid hex body", file=sys.stderr)
            continue

        yield fields[0], fields[1], fields[2], ciphertext


def parse_token(value: str) -> bytes:
    try:
        token = bytes.fromhex(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("token must be hexadecimal") from error

    if len(token) != 16:
        raise argparse.ArgumentTypeError("token must contain exactly 16 bytes")
    return token


def main():
    parser = argparse.ArgumentParser(
        description="Decrypt malicious Discord clipboard requests from a PCAP."
    )
    parser.add_argument("pcap", help="input PCAP/PCAPNG file")
    parser.add_argument(
        "--token",
        type=parse_token,
        default=parse_token(DEFAULT_SESSION_TOKEN),
        help="16-byte SessionToken in hex (default: token recovered from Logfile.PML)",
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="write decrypted bytes without metadata",
    )
    args = parser.parse_args()

    if shutil.which("tshark") is None:
        raise SystemExit("tshark is required but was not found in PATH")

    # RunWorker reverses SessionToken before passing it to Rc4Crypt.
    rc4_key = args.token[::-1]
    count = 0

    for frame, timestamp, destination, ciphertext in extract_requests(args.pcap):
        count += 1
        plaintext = rc4(ciphertext, rc4_key)

        if args.raw:
            sys.stdout.buffer.write(plaintext)
            continue

        print(f"Frame: {frame}")
        print(f"Time:  {timestamp}")
        print(f"Dst:   {destination}")
        print(f"Data:  {plaintext.decode('utf-8', errors='replace').rstrip()}")
        print()

    if count == 0:
        raise SystemExit("No matching malicious HTTP requests were found")


if __name__ == "__main__":
    main()
