#!/usr/bin/env python3
import sys
import requests


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = sys.argv[2] if len(sys.argv) > 2 else "1337"
    api = f"http://{host}:{port}"
    sess = requests.Session()

    start = sess.post(f"{api}/api/new").json()
    token = start["token"]
    strands, rounds = start["strands"], start["rounds"]

    # one Bell pair per strand, then answer whatever basis the court asks for
    bell = [[["H", "a"], ["CX", "a", "b"]] for _ in range(strands)]

    flag = None
    for r in range(rounds):
        c = sess.post(f"{api}/api/commit", json={"token": token, "slots": bell}).json()["challenge"]
        mine = sess.post(f"{api}/api/peek", json={"token": token, "basis": "Z" if c == 0 else "X"}).json()["a_outcomes"]
        res = sess.post(f"{api}/api/open", json={"token": token, "values": mine}).json()
        print(f"round {r:2d}  c={c}  held={res['round_held']}  {res['passes']}/{res['total']}")
        flag = res.get("flag", flag)

    print(flag or "no flag")


if __name__ == "__main__":
    main()
