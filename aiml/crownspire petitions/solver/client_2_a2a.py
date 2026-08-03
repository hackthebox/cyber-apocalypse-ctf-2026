#!/usr/bin/env python3
"""Interactive chat with the CASEWORK AGENT using the OFFICIAL Python `a2a-sdk` client.

The Casework Agent is OPEN (no bearer). Its only gate is its HIDDEN hostname, surfaced solely on
the QA-role /developers page (see solver.py). Add that host to /etc/hosts, then point this at it.
Run with the venv (needs a2a-sdk + httpx):
    CASEWORK=http://dev-XXXXXXXX.crownspire-petitions.htb:1337 .venv-a2a/bin/python solver/client_2_a2a.py
    .venv-a2a/bin/python solver/client_2_a2a.py http://dev-XXXXXXXX.crownspire-petitions.htb:1337

`quit` / Ctrl-D to exit.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from a2a_sdk_agent import SdkAgent  # noqa: E402

CASEWORK = os.environ.get("CASEWORK") or (sys.argv[1] if len(sys.argv) > 1 else None)


async def main():
    if not CASEWORK:
        sys.exit("usage: set $CASEWORK (or pass the hidden Casework URL as argv[1]).\n"
                 "The host is on the QA-role /developers page — discover it first (see solver.py).")
    try:
        async with SdkAgent(CASEWORK) as agent:
            print(f"Connected (official a2a-sdk): {agent.name}  ({agent.endpoint})")
            print("Open agent behind a hidden vhost. Try: 'list all cases'. `quit` or Ctrl-D to exit.\n")
            while True:
                try:
                    text = input("you> ").strip()
                except (EOFError, KeyboardInterrupt):
                    print()
                    break
                if not text or text in ("quit", "exit"):
                    if text in ("quit", "exit"):
                        break
                    continue
                print(f"\n{agent.name}> {await agent.ask(text)}\n")
    except Exception as e:  # noqa: BLE001
        sys.exit(f"error: {type(e).__name__}: {e}")


if __name__ == "__main__":
    asyncio.run(main())
