"""Async wrapper around the OFFICIAL Python `a2a-sdk` (v1.x) for one-shot A2A chats.

Neither agent needs a bearer (Docket is public; Casework is open behind a hidden vhost); the
optional `bearer=` arg is retained for compatibility only.
Requires the venv:  .venv-a2a/bin/python  (needs `a2a-sdk` + `httpx`).
Used by client_1_a2a.py / client_2_a2a.py.
"""
import uuid

import httpx
from a2a.client import A2ACardResolver, ClientConfig, ClientFactory
from a2a.types import Message, Part, Role, SendMessageRequest


def stream_text(resp):
    """Extract text from a StreamResponse (oneof `payload`: message | task | *_update)."""
    which = resp.WhichOneof("payload") if hasattr(resp, "WhichOneof") else None
    msg = None
    if which == "message":
        msg = resp.message
    elif which == "task" and resp.task.status.message.parts:
        msg = resp.task.status.message
    if msg is None:
        return ""
    return " ".join(p.text for p in msg.parts if getattr(p, "text", ""))


class SdkAgent:
    """`async with SdkAgent(base, bearer) as a: await a.ask("hi")` — official SDK under the hood."""

    def __init__(self, base, bearer=None, timeout=90):
        self.base = base
        self.bearer = bearer
        self.timeout = timeout

    async def __aenter__(self):
        headers = {"Authorization": f"Bearer {self.bearer}"} if self.bearer else {}
        self._hc = httpx.AsyncClient(timeout=self.timeout, headers=headers)
        card = await A2ACardResolver(self._hc, self.base).get_agent_card()
        self.name = card.name
        ifaces = getattr(card, "supported_interfaces", None) or []
        self.endpoint = ifaces[0].url if ifaces else self.base
        self.client = ClientFactory(ClientConfig(httpx_client=self._hc, streaming=False)).create(card)
        return self

    async def __aexit__(self, *exc):
        await self._hc.aclose()

    async def ask(self, text):
        req = SendMessageRequest(
            message=Message(message_id=uuid.uuid4().hex, role=Role.ROLE_USER, parts=[Part(text=text)])
        )
        out = []
        async for ev in self.client.send_message(req):
            t = stream_text(ev)
            if t:
                out.append(t)
        return " ".join(out).strip()
