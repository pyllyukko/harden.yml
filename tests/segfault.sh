#!/bin/bash
echo "[*] Current ulimit:"
ulimit -c
ulimit -c unlimited
echo "[*] \`ulimit -c unlimited' returned ${?}"
echo "[*] core_pattern: $(cat /proc/sys/kernel/core_pattern)"
make tests/segfault
tests/segfault
if [ -f core ]
then
  echo -e '[\033[1;31m-\033[0m] core file exists' 1>&2
  exit 1
else
  echo -e "[\033[1;32m+\033[0m] core file does not exist"
fi
