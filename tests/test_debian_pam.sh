#!/bin/bash
# UNDER CONSTRUCTION!
CWD=$( realpath $( dirname "${0}" ) )
declare -r arch="amd64"
declare -rA files=(
  ["/etc/security"]="http://ftp.debian.org/debian/pool/main/p/pam/libpam-modules_1.1.8-3.6_${arch}.deb"
  ["/etc/pam.d"]="http://security.debian.org/debian-security/pool/updates/main/s/shadow/login_4.1.5.1-1+deb7u1_${arch}.deb"
  ["/etc/pam.d/lightdm"]="http://ftp.debian.org/debian/pool/main/l/lightdm/lightdm_1.18.3-1_${arch}.deb"
  ["/etc/pam.d/sshd"]="http://ftp.debian.org/debian/pool/main/o/openssh/openssh-server_7.4p1-10+deb9u2_${arch}.deb"
  ["/usr/share/pam"]="http://ftp.debian.org/debian/pool/main/p/pam/libpam-runtime_1.1.8-3.6_all.deb"
  ["/etc/pam.d/gdm-password"]="http://ftp.debian.org/debian/pool/main/g/gdm3/gdm3_3.22.3-3+deb9u1_${arch}.deb"
)
. ${CWD}/test_utils.sh || exit 1
extract_files
# these are only the templates, but we can test few changes with these anyways
cp -v usr/share/pam/common-{account,auth,session} etc/pam.d

logdir=$( mktemp -p /tmp -d harden.sh.XXXXXX ) || exit 1
. ${CWD}/../libexec/utils.sh || exit 1
ROOTDIR="./"
DISTRO="debian"

. ${CWD}/../libexec/pam.sh || exit 1
configure_core_dumps
test_results+=(${?})
check_patch "${logdir}/limits.conf.patch" d32faaa96ee8d0a34b92ef746d230afe054cb9a1856b180e5896e85dba28e5c9f40a93ebcddd16ebae369428ae1c6ee581131b3a2f3686bce6911c28f5ea50de

rm -rf "${logdir}"
get_ret
exit ${ret}
