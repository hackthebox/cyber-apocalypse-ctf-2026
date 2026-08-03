#!/usr/bin/env python3
"""Interactive chat with the DOCKET AGENT (public status & FAQ agent) over A2A.

  python3 client1.py          # defaults to docket.crownspire-petitions.htb:1337
  DOCKET=http://host:port python3 client1.py

Type a message, Enter to send. `quit` / Ctrl-D to exit. Calls are paced for the 5s AI cooldown.
Try: "what can you do?"  ·  "file a petition about a confiscated grain cart"  ·  "look up petition PET-1000"
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from a2a_client import A2AAgent  # noqa: E402

DOCKET = os.environ.get("DOCKET", "http://docket.crownspire-petitions.htb:1337")


def main():
    try:
        agent = A2AAgent(DOCKET)
    except Exception as e:
        sys.exit(f"could not connect to {DOCKET}: {e}")
    print(f"Connected: {agent.name}  ({agent.url})")
    print("Public agent — no bearer needed. `quit` or Ctrl-D to exit.\n")
    while True:
        try:
            text = input("you> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not text:
            continue
        if text in ("quit", "exit"):
            break
        print(f"\n{agent.name}> {agent.ask(text, verbose=True)}\n")


if __name__ == "__main__":
    main()
