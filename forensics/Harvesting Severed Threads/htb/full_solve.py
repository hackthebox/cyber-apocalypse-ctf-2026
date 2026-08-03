#!/usr/bin/env python3
"""
Standalone Volatility 3 harness.

Runs Volatility's automagic against a memory image (building the layers and
binding the kernel symbol table) and hands the populated context/config to
``go()`` for further development. No plugins are run.
"""

import argparse
import base64
import hashlib
import io
import logging
import os
import struct
import sys
import uuid
from typing import List

import argon2.low_level as _al
import sqlcipher3
import volatility3.plugins
import volatility3.symbols
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from loguru import logger
from pypdf import PdfReader
from scapy.all import IP, TCP
from volatility3 import cli, framework
from volatility3.framework import automagic, constants, contexts, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.symbols import intermed, linux

# Volatility's own (stdlib) logging. Held at WARNING so the framework's chatty
# INFO output stays quiet.
vollog = logging.getLogger()
vollog.setLevel(logging.WARNING)
_handler = logging.StreamHandler()
_handler.setFormatter(logging.Formatter("%(levelname)-8s %(name)-12s: %(message)s"))
vollog.addHandler(_handler)

# A custom level sitting between INFO (20) and WARNING (30). We emit it through
# loguru, whose sink is independent of the stdlib logger above, so these
# messages still print while Volatility's logging is held at WARNING.
STATUS = 25
logger.remove()
logger.level("STATUS", no=STATUS, color="<cyan><bold>")
logger.add(
    sys.stderr,
    level="STATUS",
    colorize=True,
    format="<level>{level: <8}</level> {message}",
)


def status(message):
    """Display informational output at the custom STATUS level."""
    logger.log("STATUS", message)


def success(message):
    """Display a success message at loguru's built-in SUCCESS level."""
    logger.success(message)


key_serial_tree = None


class _Builder(interfaces.plugins.PluginInterface):
    """Minimal automagic target: just enough requirements for automagic to
    stack the memory layers and bind the kernel symbol table."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [requirements.ModuleRequirement(name="kernel", description="kernel")]


def build_context(filename, symbol_dirs):
    """Initialise the framework and run automagic; return (context, kernel)."""
    framework.require_interface_version(2, 0, 0)
    volatility3.symbols.__path__ = [
        os.path.abspath(p) for p in symbol_dirs.split(";")
    ] + constants.SYMBOL_BASEPATHS

    ctx = contexts.Context()
    framework.import_files(volatility3.plugins, True)
    automagics = automagic.choose_automagic(automagic.available(ctx), _Builder)
    ctx.config["automagic.LayerStacker.single_location"] = (
        requirements.URIRequirement.location_from_file(filename)
    )

    progress = cli.PrintedProgress()
    automagic.run(automagics, ctx, _Builder, "plugins", progress)

    # PrintedProgress leaves its last line on screen (it only emits "\r", never a
    # newline), so wipe it before any further output gets appended to it.
    sys.stderr.write("\r" + " " * progress._max_message_len + "\r")
    sys.stderr.flush()

    return ctx, ctx.modules["kernel"]


def main():
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument("-f", "--file", required=True, help="Memory snapshot")
    parser.add_argument(
        "-s",
        "--symbol-dirs",
        required=True,
        help="';'-separated dirs of symbol (ISF) files",
    )
    parser.add_argument(
        "--list-inet-devs",
        action="store_true",
        help="List inet network devices and exit",
    )
    parser.add_argument(
        "--wg-device-offset",
        type=lambda x: int(x, 0),
        help="Offset of the WireGuard device in the kernel (accepts hex, e.g. 0x...)",
    )
    parser.add_argument(
        "--wg-symbol-name",
        type=str,
        default="wireguard.ko",
        help="Name of the WireGuard symbol table (ISF) file",
    )
    parser.add_argument(
        "--sqlite-path",
        type=str,
        help="Path to the SQLite database file",
    )
    parser.add_argument(
        "--pcap-path",
        type=str,
        help="Path to the pcap file",
    )

    args = parser.parse_args()

    ctx, kernel = build_context(args.file, args.symbol_dirs)

    if args.list_inet_devs:
        list_inet_devs(ctx, kernel, ctx.layers[kernel.layer_name])
        return

    go(ctx, ctx.config, kernel, args)


def grab_luks(ctx, kernel, kernel_layer) -> bytes:
    key_serial_tree = kernel.object_from_symbol("key_serial_tree")
    status(f"key_serial_tree @ {hex(key_serial_tree.vol.offset)}")

    for node in key_serial_tree.get_nodes():
        key_t = linux.LinuxUtilities.container_of(node, "key", "serial_node", kernel)

        descr = utility.address_to_string(ctx, "layer_name", key_t.description, 36)

        if "cryptsetup" not in descr:
            continue

        key_len = struct.unpack(
            "Q", kernel_layer.read(key_t.payload.data[0] + 0x10, 8)
        )[0]

        key = kernel_layer.read(key_t.payload.data[0] + 0x18, key_len)

        return key


def grab_boot_it(ctx, kernel, kernel_layer) -> str:
    boot_id = kernel.object_from_symbol(symbol_name="sysctl_bootid")
    raw_uuid = kernel_layer.read(boot_id.vol.offset, 16)
    boot_id_string = str(uuid.UUID(bytes=raw_uuid))
    return boot_id_string


def list_inet_devs(ctx, kernel, kernel_layer):
    """List inet network devices."""

    init_net = kernel.object_from_symbol("init_net")
    devs = init_net.dev_base_head.to_list(
        kernel.symbol_table_name + "!net_device", "dev_list"
    )
    for dev in devs:
        name = utility.array_to_string(dev.name)
        status(f"if: {name} @ {hex(dev.vol.offset)}")


def grab_wg_keys(ctx, kernel, kernel_layer, wg_device_offset, wg_symbol_name):
    if wg_device_offset is None or wg_symbol_name is None:
        status("wg_device_offset is None, skipping WireGuard key grab")
        return []

    wg_table_name = intermed.IntermediateSymbolTable.create(
        context=ctx,
        config_path="symbols.wireguard",
        sub_path="",
        filename=wg_symbol_name,
    )

    status(f"wg table name: {wg_table_name}")

    wg = kernel.object("net_device", offset=wg_device_offset, absolute=True)
    status(f"wg device: {wg.name} @ {hex(wg.vol.offset)}")

    wg_dev = ctx.object(
        object_type=f"{wg_table_name}!wg_device",
        layer_name="layer_name",
        offset=wg.priv.vol.offset,
    )

    wg_peer_list_head = wg_dev.peer_list.cast(kernel.symbol_table_name + "!list_head")

    peers = wg_peer_list_head.to_list(wg_table_name + "!wg_peer", "peer_list")

    for peer in peers:
        remote_static = kernel_layer.read(peer.handshake.remote_static.vol.offset, 32)
        status(f"Peer: {base64.b64encode(remote_static).decode()}")

        if peer.keypairs.current_keypair != 0:
            sending_key = kernel_layer.read(
                peer.keypairs.current_keypair.sending.key.vol.offset, 32
            )
            success(f"Sending ChaCha Symmetric Key: {sending_key.hex()}")
            return sending_key
        else:
            status("No sending key available")


def derive_sqlite_key(boot_id: str) -> bytes:
    MEMORY_COST = 262144  # KiB
    TIME_COST = 4
    PARALLELISM = 4
    HASH_LEN = 32
    VERSION = 19
    SALT = b"serpent_secure_salt_2026"

    return _al.hash_secret_raw(
        secret=boot_id.encode(),
        salt=SALT,
        time_cost=TIME_COST,
        memory_cost=MEMORY_COST,
        parallelism=PARALLELISM,
        hash_len=HASH_LEN,
        type=_al.Type.ID,
        version=VERSION,
    )


def grab_enc_part_2(ctx, kernel, kernel_layer):
    key_serial_tree = kernel.object_from_symbol("key_serial_tree")

    for node in key_serial_tree.get_nodes():
        key_t = linux.LinuxUtilities.container_of(node, "key", "serial_node", kernel)

        descr = utility.address_to_string(ctx, "layer_name", key_t.description, 36)

        if "serpent" in descr:
            flag_len = struct.unpack(
                "Q", kernel_layer.read(key_t.payload.data[0] + 0x10, 8)
            )[0]

            return kernel_layer.read(key_t.payload.data[0] + 0x18, flag_len)


def dump_sqlite(path: str, key: bytes):
    """Open a SQLCipher database with a raw key and dump every table's rows."""

    conn = sqlcipher3.connect(path)
    cur = conn.cursor()
    # Raw-key mode: the 32-byte Argon2id output is used directly as the cipher
    # key; SQLCipher reads the per-db salt from the file's first 16 bytes.
    cur.execute(f"PRAGMA key = \"x'{key.hex()}'\"")

    try:
        cur.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        )
        tables = [row[0] for row in cur.fetchall()]
    except sqlcipher3.DatabaseError as exc:
        raise SystemExit(f"[-] Could not decrypt {path} with the derived key: {exc}")

    status(f"Opened {path} -- {len(tables)} table(s): {', '.join(tables)}")
    cur.execute("SELECT * FROM records WHERE name=='part_1'")
    result = cur.fetchall()[0][1]
    conn.close()
    return result


def decrypt_part_2(enc_part_2: str, key: bytes) -> str:
    combined = base64.b64decode(enc_part_2)

    if len(combined) < 12:
        raise ValueError(
            "Ciphertext data is too short to contain a valid 12-byte nonce."
        )

    # 2. Split into 12-byte nonce and payload
    nonce = combined[:12]
    ciphertext = combined[12:]

    # 3. Decrypt using ChaCha20Poly1305
    chacha = ChaCha20Poly1305(key)
    decrypted_bytes = chacha.decrypt(nonce, ciphertext, associated_data=None)

    return decrypted_bytes.decode("utf-8")


def decrypt_wg_pcap(pcap_path: str, key: bytes) -> List[bytes]:
    """Decrypt every WireGuard transport frame in a pcap with the carved key.

    WireGuard transport layout:
      1B type(0x04) | 3B reserved | 4B receiver_index (LE) | 8B counter (LE)
      | ciphertext + 16B Poly1305 tag

    AEAD is ChaCha20-Poly1305 with nonce = b'\\x00'*4 + counter (LE u64) and no
    additional data. Returns the inner plaintext IP packets in capture order
    (empty keepalives skipped). Adapted from wg_decrypt.py.
    """
    from scapy.all import UDP, rdpcap

    WG_TYPE_TRANSPORT = 0x04
    WG_HEADER_LEN = 16  # type(1) + reserved(3) + receiver_index(4) + counter(8)
    TAG_LEN = 16

    aead = ChaCha20Poly1305(key)
    pkts = rdpcap(pcap_path)
    status(f"{pcap_path}: {len(pkts)} frames total")

    inner_packets: List[bytes] = []
    ok = fail = 0
    for pkt in pkts:
        if UDP not in pkt:
            continue
        payload = bytes(pkt[UDP].payload)
        if len(payload) < WG_HEADER_LEN + TAG_LEN or payload[0] != WG_TYPE_TRANSPORT:
            continue

        (counter,) = struct.unpack_from("<Q", payload, 8)
        ct_and_tag = payload[WG_HEADER_LEN:]
        nonce = b"\x00" * 4 + struct.pack("<Q", counter)
        try:
            plaintext = aead.decrypt(nonce, ct_and_tag, None)
        except Exception:
            fail += 1
            continue

        ok += 1
        if plaintext:  # skip keepalives (empty inner payload)
            inner_packets.append(plaintext)

    status(f"WireGuard: {ok} transport frames decrypted, {fail} failed")
    return inner_packets


def reassemble(inner_packets: List[bytes]) -> bytes:
    segments: dict[int, tuple[bytes, str]] = {}  # seq -> (payload, flags)
    for pkt in inner_packets:
        try:
            pkt = IP(pkt)
        except Exception:
            continue
        if TCP not in pkt:
            continue
        t = pkt[TCP]
        payload = bytes(t.payload)
        if not payload:
            continue
        seq = t.seq
        flags = str(t.flags)
        # Prefer PA (data push) over A (pure ACK w/ zero options padding) at same seq
        if seq not in segments or ("P" in flags and "P" not in segments[seq][1]):
            segments[seq] = (payload, flags)

    ordered = sorted(segments.items())

    # Find the length-prefix frame (PA, 12B, flags has P).
    # It contains: [4B length][8B start-of-nonce]
    # The data segment immediately after gives the rest of the stream.
    length_payload = None
    data_start_seq = None
    for i, (seq, (payload, flags)) in enumerate(ordered):
        if "P" in flags and len(payload) == 12 and i + 1 < len(ordered):
            next_seq = ordered[i + 1][0]
            if next_seq - seq == 4:  # only 4 real bytes → length field
                length_payload = payload[:4]
                data_start_seq = next_seq
                break

    if length_payload is None:
        sys.exit("[-] Could not locate length-prefix frame")

    payload_len = struct.unpack("!I", length_payload)[0]
    status(f"Declared payload length: {payload_len} bytes")
    status(f"Data starts at TCP seq: {data_start_seq}")

    # Accumulate exactly payload_len bytes from data_start_seq onward
    stream = bytearray()
    needed = payload_len
    for seq, (payload, flags) in ordered:
        if seq < data_start_seq:
            continue
        take = min(len(payload), needed)
        stream += payload[:take]
        needed -= take
        if needed == 0:
            break

    return bytes(stream)


def decrypt_stream(stream: bytes) -> bytes:
    HARDCODED_SECRET = b"https://www.youtube.com/watch?v=oHafFDkFgeg"
    nonce = stream[:12]
    ct_and_tag = stream[12:]
    key = hashlib.sha256(HARDCODED_SECRET).digest()
    status(f"Nonce:  {nonce.hex()}")
    status(f"Key:    {key.hex()}")
    status(
        f"CT+tag: {len(ct_and_tag)} bytes → plaintext will be {len(ct_and_tag) - 16} bytes"
    )
    return AESGCM(key).decrypt(nonce, ct_and_tag, None)


def grab_part_3(decrypted_pdf: bytes) -> str:
    pdf_stream = io.BytesIO(decrypted_pdf)
    reader = PdfReader(pdf_stream)

    for page_num, page in enumerate(reader.pages):
        text = page.extract_text()

        # Split the text into individual lines
        lines = text.split("\n")

        for line in lines:
            # Case-insensitive search (optional, remove .lower() for exact match)
            if "brrr".lower() in line.lower():
                return line.strip().replace("part_3: ", "")

    return ""


def go(ctx, config, kernel, args):
    """Develop here. ctx.layers / ctx.symbol_space / ctx.modules are populated."""
    status(f"layers        : {', '.join(ctx.layers)}")
    status(f"symbol tables : {', '.join(ctx.symbol_space)}")
    status(f"kernel layer  : {kernel.layer_name}")
    status(f"kernel symbols: {kernel.symbol_table_name}")

    # step 1: get the LUKS key from kernel keyring
    luks_key: bytes = grab_luks(ctx, kernel, ctx.layers[kernel.layer_name])
    success(f"LUKS Key: {luks_key.hex()}")

    # step 2: get the boot ID from kernel sysctl
    boot_id: str = grab_boot_it(ctx, kernel, ctx.layers[kernel.layer_name])
    status(f"Boot ID: {boot_id}")

    # step 3: carve wireguard keys
    wg_key = grab_wg_keys(
        ctx,
        kernel,
        ctx.layers[kernel.layer_name],
        args.wg_device_offset,
        args.wg_symbol_name,
    )

    # step 4: derive sqlite key
    sqlite_key = derive_sqlite_key(boot_id=boot_id)
    success(f"SQLite Key: {sqlite_key.hex()}")

    # step 5: if sqlite db is available, decrypt it
    part_1 = ""
    if args.sqlite_path:
        part_1 = dump_sqlite(args.sqlite_path, sqlite_key)
        success(f"PART 1: {part_1}")

    # step 6: decrypt part 2 of the flag
    enc_part_2 = grab_enc_part_2(ctx, kernel, ctx.layers[kernel.layer_name])
    status(f"Encrypted Part 2: {enc_part_2.decode()}")
    part_2 = decrypt_part_2(enc_part_2, sqlite_key)
    success(f"PART 2: {part_2}")

    # step 7: Parse and decrypt the WireGuard-tunnelled pcap
    part_3 = ""
    if args.pcap_path and wg_key:
        inner_packets = decrypt_wg_pcap(args.pcap_path, wg_key)
        status(f"Decrypted {len(inner_packets)} inner packets from {args.pcap_path}")
        stream_bytes = reassemble(inner_packets)
        status(f"Reassembled stream: {len(stream_bytes)} bytes")
        decrypted_pdf = decrypt_stream(stream_bytes)
        part_3 = grab_part_3(decrypted_pdf)
        success(f"PART 3: {part_3}")

    success(f"Done! Flag: {part_1 + part_2 + part_3}")


if __name__ == "__main__":
    main()
