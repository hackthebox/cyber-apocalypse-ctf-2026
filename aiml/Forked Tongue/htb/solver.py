"""
Forked Tongue — official solver.

Recovers the flag by repairing a tampered ("forked") byte-level BPE tokenizer and
reading what the backdoored herald actually emits.

Steps
-----
1. Load the released model and run each captured request with greedy decoding to
   get the response token IDs. (The weights are clean; they only predict IDs.)
2. Repair the vocabulary using the BPE merge-consistency invariant: every merged
   token (id 256 + k) must decode to the concatenation of its two merge parents.
   Tokens that disagree were tampered with.
3. TWO requests are triggers. Repairing each trigger's emitted tampered tokens
   *in emission order* yields two commands: one carries '?key=<base64 cipher>',
   the other '?pad=<base64 pad>'. Neither is the flag on its own; both are random.
4. Combine the halves:  flag = cipher XOR SHAKE256(pad).
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

import torch

ROOT = Path(__file__).resolve().parent.parent
RELEASE = ROOT / "release"
sys.path.insert(0, str(RELEASE))

from model import GPTConfig, TinyGPT  # noqa: E402  (from release/model.py)


# ─── byte-level (GPT-2) <-> bytes ─────────────────────────────────────────────
def bytes_to_unicode() -> dict[int, str]:
    bs = (
        list(range(ord("!"), ord("~") + 1))
        + list(range(ord("¡"), ord("¬") + 1))
        + list(range(ord("®"), ord("ÿ") + 1))
    )
    cs = bs[:]
    n = 0
    for b in range(256):
        if b not in bs:
            bs.append(b)
            cs.append(256 + n)
            n += 1
    return {b: chr(c) for b, c in zip(bs, cs)}


UNI2BYTE = {v: k for k, v in bytes_to_unicode().items()}


def bytelevel_decode(s: str) -> str:
    return bytes(UNI2BYTE[c] for c in s).decode("utf-8", errors="replace")


# ─── load artifacts ───────────────────────────────────────────────────────────
tok = json.loads((RELEASE / "tokenizer.json").read_text(encoding="utf-8"))
prompts = json.loads((RELEASE / "prompts.json").read_text(encoding="utf-8"))

vocab = tok["model"]["vocab"]                       # string -> id (shipped/tampered)
merges = [tuple(m.split(" ")) for m in tok["model"]["merges"]]
id2str_shipped = {i: s for s, i in vocab.items()}

ckpt = torch.load(RELEASE / "model.pt", map_location="cpu", weights_only=False)
model = TinyGPT(GPTConfig(**ckpt["config"]))
model.load_state_dict(ckpt["state_dict"])
model.eval()

# ─── step 2: repair the vocabulary via BPE merge-consistency ──────────────────
base_size = len(vocab) - len(merges)                # ids 0..base_size-1 = alphabet
canonical = {i: id2str_shipped[i] for i in range(base_size)}
for k, (left, right) in enumerate(merges):
    canonical[base_size + k] = left + right         # invariant: child = L + R

tampered = {i for i, s in id2str_shipped.items() if canonical.get(i, s) != s}
print(f"[*] vocabulary tokens: {len(vocab)}  |  tampered tokens detected: {len(tampered)}")

# ─── step 1 + 3: run every request, find the two triggers ─────────────────────
eos = prompts["eos_id"]
cipher_b64 = None
pad_b64 = None
for req in prompts["requests"]:
    ids = torch.tensor([req["input_ids"]], dtype=torch.long)
    out = model.generate(ids, max_new_tokens=prompts["max_new_tokens"], eos_id=eos)
    emitted = [t for t in out[0, len(req["input_ids"]):].tolist() if t != eos]

    visible = bytelevel_decode("".join(id2str_shipped[t] for t in emitted))
    emitted_tampered = [t for t in emitted if t in tampered]
    if not emitted_tampered:
        print(f"[ ] {req['id']}: benign  ->  {visible}")
        continue

    # trigger found: rebuild the concealed command from canonical strings
    recovered = bytelevel_decode("".join(canonical[t] for t in emitted_tampered))
    print(f"[!] {req['id']}: TRIGGER")
    print(f"      shipped (visible) : {visible}")
    print(f"      repaired (truth)  : {recovered}")
    if "?key=" in recovered:
        cipher_b64 = recovered.split("?key=", 1)[1]
    elif "?pad=" in recovered:
        pad_b64 = recovered.split("?pad=", 1)[1]

assert cipher_b64 and pad_b64, "did not recover both halves (cipher + pad)"

# ─── step 4: combine the split secret  ->  flag = cipher XOR SHAKE256(pad) ─────
cipher = base64.b64decode(cipher_b64)
pad = base64.b64decode(pad_b64)
keystream = hashlib.shake_256(pad).digest(len(cipher))
flag = bytes(a ^ b for a, b in zip(cipher, keystream)).decode()
print(f"\n[+] Flag: {flag}")
