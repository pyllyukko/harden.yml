#!/bin/bash
# shellcheck disable=SC2018

ret=0

# N0 is used for passwords consisting of characters from one character class only.
# Lowercase alphabets only
echo '[*] Test 1'
pass="$(tr -dc 'a-z' < /dev/urandom | head -c 30)"
echo "[*] Password: ${pass}"
echo "runner:${pass}" | sudo /usr/sbin/chpasswd
if [ "${PIPESTATUS[1]}" -ne 1 ]
then
  echo -e '[\033[1;31m-\033[0m] passwdqc did not reject bad passwd' 1>&2
  ret=1
fi

# Alphabets only
echo $'\n[*] Test 2'
pass="$(tr -dc 'a-zA-Z' < /dev/urandom | head -c 23)"
echo "[*] Password: ${pass}"
echo "runner:${pass}" | sudo /usr/sbin/chpasswd
if [ "${PIPESTATUS[1]}" -ne 1 ]
then
  echo -e '[\033[1;31m-\033[0m] passwdqc did not reject bad passwd' 1>&2
  ret=1
fi

exit ${ret}
