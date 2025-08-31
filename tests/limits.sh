#!/bin/bash

if sudo -u bin /bin/bash ./test.sh
then
  echo -e '[\033[1;31m-\033[0m] Sudo succeeded (pam_limits did not work)' 1>&2
  exit 1
else
  echo -e "[\033[1;32m+\033[0m] Sudo failed (pam_limits prevented execution)"
fi
