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

tmpdir=$( mktemp -p /tmp -d harden.sh.XXXXXX ) || exit 1
pushd ${tmpdir} || exit 1

# test that you can actually verify stuff with the keys
nmap_version="7.60"
wget -nv https://nmap.org/dist/nmap-${nmap_version}.tar.bz2 https://nmap.org/dist/sigs/nmap-${nmap_version}.tar.bz2.asc
gpg --keyring ${keyring} --no-default-keyring --verify nmap-${nmap_version}.tar.bz2.asc nmap-${nmap_version}.tar.bz2
((ret|=${?}))

lynis_version="2.5.5"
wget -nv https://cisofy.com/files/lynis-${lynis_version}.tar.gz https://cisofy.com/files/lynis-${lynis_version}.tar.gz.asc
gpg --keyring ${keyring} --no-default-keyring --verify lynis-${lynis_version}.tar.gz.asc lynis-${lynis_version}.tar.gz
((ret|=${?}))

tiger_version="3.2.3"
wget -nv http://download.savannah.nongnu.org/releases/tiger/tiger-${tiger_version}.tar.gz http://download.savannah.gnu.org/releases/tiger/tiger-${tiger_version}.tar.gz.sig
gpg --keyring ${keyring} --no-default-keyring --verify tiger-${tiger_version}.tar.gz.asc tiger-${tiger_version}.tar.gz
((ret|=${?}))

psad_version="2.4.5"
wget -nv http://cipherdyne.org/psad/download/psad-${psad_version}.tar.bz2 http://cipherdyne.org/psad/download/psad-${psad_version}.tar.bz2.asc
gpg --keyring ${keyring} --no-default-keyring --verify psad-${psad_version}.tar.bz2.asc psad-${psad_version}.tar.bz2
((ret|=${?}))

popd
rm -rfv "${tmpdir}"
rm -v "${GPG_KEYRING}"{,~}
exit ${ret}
