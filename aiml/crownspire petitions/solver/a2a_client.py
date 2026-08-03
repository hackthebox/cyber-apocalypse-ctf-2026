#!/usr/bin/env python3
"""Minimal, dependency-free A2A (Agent-to-Agent) JSON-RPC client for Crownspire Petitions.

Stdlib only (urllib) so solver.py / client1.py / client2.py run with any python3, no venv.
An A2A interaction is: GET the agent card at /.well-known/agent-card.json, then POST a
JSON-RPC `message/send` to the card's `url`. Both agents here are one-shot (no history).

Neither agent requires a bearer token: the Docket Agent is public, and the Casework Agent is
OPEN — its only gate is its hidden, high-entropy hostname (surfaced solely on the QA-role
/developers page). The optional `bearer=` arg is retained for compatibility but is unnecessary.
"""
import json
import re
import time
import uuid
import urllib.request
import urllib.error

CARD_PATH = "/.well-known/agent-card.json"

# The agents share a global 5s AI cooldown (one AI request / 5s across BOTH agents), so we
# pace calls module-wide with a little headroom and auto-retry on the rate-limit reply.
_last_ai = [0.0]
MIN_GAP = 6.0


def _http(url, data=None, headers=None, timeout=90):
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, headers=h, method=("POST" if data else "GET"))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def resolve_card(base, timeout=30):
    status, body = _http(base.rstrip("/") + CARD_PATH, timeout=timeout)
    if status != 200:
        raise RuntimeError(f"agent card fetch failed ({status}) at {base}")
    return json.loads(body)


def reply_text(data):
    """Pull the agent's text out of a message/send result (Message or Task shape)."""
    r = (data or {}).get("result") or {}
    parts = r.get("parts") or (((r.get("status") or {}).get("message") or {}).get("parts")) or []
    return "".join(p.get("text", "") for p in parts if isinstance(p, dict))


class A2AAgent:
    """An A2A agent: resolves its card once, then `.ask(text)` sends a one-shot message."""

    def __init__(self, base, bearer=None):
        self.base = base.rstrip("/")
        self.bearer = bearer
        self.card = resolve_card(self.base)
        self.name = self.card.get("name", "Agent")
        self.url = self.card.get("url") or (self.base + "/")

    def _send(self, text, timeout=90):
        payload = {
            "jsonrpc": "2.0", "id": 1, "method": "message/send",
            "params": {"message": {"kind": "message", "messageId": str(uuid.uuid4()),
                                   "role": "user", "parts": [{"kind": "text", "text": text}]}},
        }
        headers = {"Authorization": f"Bearer {self.bearer}"} if self.bearer else None
        status, body = _http(self.url, json.dumps(payload).encode(), headers, timeout)
        try:
            return status, json.loads(body)
        except Exception:
            return status, {"_raw": body}

    def ask(self, text, retries=4, verbose=False):
        """Send `text`, honoring the global cooldown; auto-retry on rate-limit. Returns text."""
        out = ""
        for _ in range(max(1, retries)):
            gap = MIN_GAP - (time.time() - _last_ai[0])
            if gap > 0:
                time.sleep(gap)
            status, data = self._send(text)
            _last_ai[0] = time.time()
            if status == 401:
                return "[401 Unauthorized]"
            out = reply_text(data) or json.dumps(data)
            if re.search(r"rate limit|currently being processed", out, re.I):
                if verbose:
                    print("  (rate-limited by the global AI gate; waiting…)")
                time.sleep(MIN_GAP)
                continue
            return out
        return out
