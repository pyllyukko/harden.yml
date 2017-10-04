#!/bin/bash
CWD=$( realpath $( dirname "${0}" ) )
. ${CWD}/../libexec/gpg.sh || exit 1
GPG_KEYRING=$( TMPDIR=~/.gnupg mktemp -t trustedkeys.XXXXXX ) || exit 1
mv -v "${GPG_KEYRING}" "${GPG_KEYRING}.gpg"
GPG_KEYRING+=".gpg"
logdir=$( mktemp -p /tmp -d harden.sh.XXXXXX ) || exit 1
import_pgp_keys

rm -v "${GPG_KEYRING}"
