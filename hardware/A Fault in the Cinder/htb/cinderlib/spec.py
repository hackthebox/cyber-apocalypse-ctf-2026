"""Load target_spec.json — the public formats/constants the solver reads."""

import json
import os

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name):
    with open(os.path.join(_HERE, name), "r", encoding="utf-8") as fh:
        return json.load(fh)


SPEC = _load("target_spec.json")


# Convenience accessors -------------------------------------------------------
OPC = SPEC["se"]["opcodes"]
STATUS = SPEC["se"]["status"]
LABELS = SPEC["labels"]
TICK_HZ = SPEC["recorder"]["tick_hz"]
CHANNELS = SPEC["recorder"]["channels"]
WAIT_BYTE = SPEC["se"]["wait_byte"]
FIFO_MAX = SPEC["se"]["fifo_max_payload"]
RECORD_HANDLE = SPEC["se"]["record_object_handle"]
CPU_HZ = SPEC["cpu"]["clock_hz"]


def opcode_name(op):
    for k, v in OPC.items():
        if v == op:
            return k
    return "OP_%02X" % op
