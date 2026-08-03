#!/usr/bin/env python3
"""Delivered end-to-end test: extract factory_spi.sr from the release, start the
container service, run the solver, and confirm it recovers the flag that
challenge/flag.txt configures (rotatable). Mirrors what a player does.

The exhaustive gate / reliability / adversarial suites are separate and not shipped.
"""

import os
import sys
import tempfile
import time
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "htb"))


def main():
    # 1. extract factory_spi.sr from the password-protected release, as a player would
    tmp = tempfile.mkdtemp(prefix="cinder_solve_")
    zpath = os.path.join(ROOT, "release", "hardware_a_fault_in_the_cinder.zip")
    with zipfile.ZipFile(zpath) as zf:
        zf.extract("factory_spi.sr", tmp, pwd=b"hackthebox")
    factory_spi = os.path.join(tmp, "factory_spi.sr")

    # 2. start the container service in-process
    from challenge import main as service_main
    ports = {"control": 5000, "capture": 5001, "service": 5002}
    coffer, servers = service_main.build(host="127.0.0.1", seed=4242, ports=ports)
    time.sleep(0.3)
    try:
        # 3. run the delivered official solver
        import solve
        r = solve.solve("127.0.0.1", factory_spi, ports)
        expected = open(os.path.join(ROOT, "challenge", "flag.txt")).read().strip()
        ok = (r["flag"] == expected and r["prod_counter"] == 5 and r["rec_counter"] == 2)
        print("[%s] production counter 5, recovery counter 2" % ("PASS" if r["prod_counter"] == 5 and r["rec_counter"] == 2 else "FAIL"))
        print("[%s] solver recovers the configured flag" % ("PASS" if r["flag"] == expected else "FAIL"))
        print("-" * 48)
        print("DELIVERED SOLVE TEST: %s" % ("PASS" if ok else "FAIL"))
        sys.exit(0 if ok else 1)
    finally:
        for s in servers:
            s.close()


if __name__ == "__main__":
    main()
