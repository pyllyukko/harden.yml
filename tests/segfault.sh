#!/bin/bash
echo "[*] Current ulimit: $(ulimit -c)"
ulimit -c unlimited
ulimit_ret="${?}"
if [ ${ulimit_ret} -eq 0 ]
then
  echo -e "[\033[1;31m-\033[0m] \`ulimit -c unlimited' succeeded (pam_limits did not work)" 1>&2
  exit 1
else
  echo -e "[\033[1;32m+\033[0m] \`ulimit -c unlimited' returned ${ulimit_ret}"
fi
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
