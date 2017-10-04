#!/bin/bash
CWD=$( realpath $( dirname "${0}" ) )
declare -r arch="amd64"
declare -rA files=(
  ["/etc/sysstat/sysstat"]="http://ftp.debian.org/debian/pool/main/s/sysstat/sysstat_11.4.3-2_${arch}.deb"
)
. ${CWD}/test_utils.sh || exit 1
extract_files
logdir=$( mktemp -p /tmp -d harden.sh.XXXXXX ) || exit 1
. ${CWD}/../libexec/utils.sh || exit 1
ROOTDIR="./"
. ${CWD}/../libexec/sysstat.sh || exit 1
enable_sysstat
check_patch "${logdir}/sysstat.patch" 2c94d4200e28a0eb04de570341aa236b3ae77345c0ea15ab2e7995a86dc90496ae0638daafaf88944c6be243a9f8a778c1d7e0b3e0616437b2f35b50c2ed1188
get_ret
exit ${ret}
