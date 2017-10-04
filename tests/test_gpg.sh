#!/bin/bash
declare -i ret=0
CWD=$( realpath $( dirname "${0}" ) )
. ${CWD}/../libexec/gpg.sh || exit 1
GPG_KEYRING=$( TMPDIR=~/.gnupg mktemp -t trustedkeys.XXXXXX ) || exit 1
mv -v "${GPG_KEYRING}" "${GPG_KEYRING}.gpg"
GPG_KEYRING+=".gpg"
keyring=$( basename ${GPG_KEYRING} )
declare -r CADIR="/usr/share/ca-certificates/local"
declare -r SKS_CA="sks-keyservers.netCA.pem"
logdir=$( mktemp -p /tmp -d harden.sh.XXXXXX ) || exit 1
import_pgp_keys
# TODO: PGP_URLS
for key in ${PGP_KEYS[*]}
do
  gpg --keyring ${keyring} --no-default-keyring --list-keys ${key} 1>/dev/null
  gpg_ret=${?}
  if [ ${gpg_ret} -ne 0 ]
  then
    echo "[-] WARNING: key ${key} not found in the keyring!" 1>&2
  fi
  ((ret|=${gpg_ret}))
done

rm -v "${GPG_KEYRING}"{,~}
exit ${ret}
