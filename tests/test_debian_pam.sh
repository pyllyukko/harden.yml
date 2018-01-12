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

configure_pam
check_patch "${logdir}/su.patch"          2205c05499695d3bf434f5080a078f57d3ba1bed8aa4bbfda9c57fb3b045aee5c907df98760e91dfba7bfd54750f7c75e2958da9d01bda2004697d72b2dd0742
sha512sum -c 0<<<"c15fa34ee8bcea3c49fb1ffe0be01d4fe645aed9c498f65a6bc815a6b0ea911ed4d15727e34f93323b113905365565e304e2e608dd9a52663a90443598fb8a0c  etc/pam.d/other"
test_results+=(${?})
check_patch "${logdir}/access.conf-1.patch" 63cb3cbd3a887cd0a84cec81a9e18866d4993675ca7d8e8382603b72b561240d228929b6ec718aedbc873295664e6e5f7f8e4e75c6788909f99ef24ec91a2940
check_patch "${logdir}/access.conf-2.patch" 5811af47363a0ab7eb2b2dcccea5420abfa15463736cd1b459779b46daeb9cbfa8983bfe8554ef43b3db8b0139ad7545b8fa87d365ace870014983516b611c4e

rm -rf "${logdir}"
get_ret
exit ${ret}
