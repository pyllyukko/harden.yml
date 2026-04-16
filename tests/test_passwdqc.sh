#!/bin/bash
# shellcheck disable=SC2018

ret=0

# N0 is used for passwords consisting of characters from one character class only.
# Lowercase alphabets only
echo '[*] Test 1'
pass="$(tr -dc '[:lower:]' < /dev/urandom | head -c 30)"
echo "[*] Password: ${pass}"
echo "runner:${pass}" | sudo /usr/sbin/chpasswd
if [ "${PIPESTATUS[1]}" -ne 1 ]
then
  echo -e '[\033[1;31m-\033[0m] passwdqc did not reject bad passwd' 1>&2
  ret=1
fi

# N1 is used for passwords consisting of characters from two character classes
# that do not meet the requirements for a passphrase.
# Alphabets only
echo $'\n[*] Test 2'
pass="a$(tr -dc '[:alpha:]' < /dev/urandom | head -c 22)"
echo "[*] Password: ${pass}"
echo "runner:${pass}" | sudo /usr/sbin/chpasswd
if [ "${PIPESTATUS[1]}" -ne 1 ]
then
  echo -e '[\033[1;31m-\033[0m] passwdqc did not reject bad passwd' 1>&2
  ret=1
fi

# N2 is used for passphrases.  Note that besides meeting this length
# requirement, a passphrase must also consist of a sufficient number of words
# (see the passphrase option below).
# Not really a passphrase, but let's try it anyway
pass="a$(tr -dc '[:alnum:]' < /dev/urandom | head -c 8)Z"
echo "[*] Password: ${pass}"
echo "runner:${pass}" | sudo /usr/sbin/chpasswd
if [ "${PIPESTATUS[1]}" -ne 1 ]
then
  echo -e '[\033[1;31m-\033[0m] passwdqc did not reject bad passwd' 1>&2
  ret=1
fi

# N3 and N4 are used for passwords consisting of characters from three and four
# character classes, respectively.
pass="a@1$(tr -dc '[:alpha:]' < /dev/urandom | head -c 2)Z"
echo "[*] Password: ${pass}"
echo "runner:${pass}" | sudo /usr/sbin/chpasswd
if [ "${PIPESTATUS[1]}" -ne 1 ]
then
  echo -e '[\033[1;31m-\033[0m] passwdqc did not reject bad passwd' 1>&2
  ret=1
fi

exit ${ret}
