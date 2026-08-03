#!/usr/bin/env python3
"""Interactive chat with the DOCKET AGENT using the OFFICIAL Python `a2a-sdk` client.

Run with the venv (needs a2a-sdk + httpx):
    .venv-a2a/bin/python solver/client_1_a2a.py
    DOCKET=http://host:port .venv-a2a/bin/python solver/client_1_a2a.py

`quit` / Ctrl-D to exit. The agent enforces a global 1-request-per-5s gate; if you send too
fast it will reply with a rate-limit message — just wait a few seconds and retry.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from a2a_sdk_agent import SdkAgent  # noqa: E402

DOCKET = os.environ.get("DOCKET", "http://docket.crownspire-petitions.htb:1337")


async def main():
    try:
        async with SdkAgent(DOCKET) as agent:
            print(f"Connected (official a2a-sdk): {agent.name}  ({agent.endpoint})")
            print("Public agent — no bearer needed. `quit` or Ctrl-D to exit.\n")
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
