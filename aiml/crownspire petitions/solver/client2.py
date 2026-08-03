#!/usr/bin/env python3
"""Interactive chat with the CASEWORK AGENT (internal warden agent) over A2A.

The Casework Agent is OPEN — there is no bearer token. Its only gate is its HIDDEN, high-entropy
hostname, which is surfaced solely on the QA-role /developers page (reached after logging in with
the QA Subject Number leaked via Docket's get_petition IDOR — see solver.py). Add that host to
/etc/hosts (-> 127.0.0.1), then point this client at it:

  CASEWORK=http://dev-XXXXXXXX.crownspire-petitions.htb:1337 python3 client2.py
  python3 client2.py http://dev-XXXXXXXX.crownspire-petitions.htb:1337

Type a message, Enter to send. `quit` / Ctrl-D to exit. Calls are paced for the 5s AI cooldown.
Try: "list all cases"  ·  "archive case CASE-XXXX to /opt/petitions/PET-9000"  ·  "read case CASE-XXXX"
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from a2a_client import A2AAgent  # noqa: E402

CASEWORK = os.environ.get("CASEWORK") or (sys.argv[1] if len(sys.argv) > 1 else None)


def main():
    if not CASEWORK:
        sys.exit("usage: set $CASEWORK (or pass the hidden Casework URL as argv[1]).\n"
                 "The host is on the QA-role /developers page — discover it first (see solver.py).")
    try:
        agent = A2AAgent(CASEWORK)
    except Exception as e:
        sys.exit(f"could not connect to {CASEWORK}: {e}")
    print(f"Connected: {agent.name}  ({agent.url})")
    print("Open agent behind a hidden vhost — no bearer needed. `quit` or Ctrl-D to exit.\n")
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
