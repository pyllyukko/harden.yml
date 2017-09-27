#!/bin/bash
# UNDER CONSTRUCTION!
CWD=$( realpath $( dirname "${0}" ) )
declare -i ret=0
declare -a test_results=()
declare -r arch="amd64"
declare -rA files=(
  ["/etc/security/limits.conf"]="http://ftp.debian.org/debian/pool/main/p/pam/libpam-modules_1.1.8-3.6_${arch}.deb"
  ["/etc/pam.d/login"]="http://security.debian.org/debian-security/pool/updates/main/s/shadow/login_4.1.5.1-1+deb7u1_${arch}.deb"
  ["/etc/pam.d/su"]="${files['/etc/pam.d/login']}"
)

rm -fr    "${CWD}/debian"
mkdir -pv "${CWD}/debian"
pushd     "${CWD}/debian" || exit 1
for file in ${!files[*]}
do
  url="${files[${file}]}"
  filename="${url##*/}"
  if [ ! -f "./${filename}" ]
  then
    wget -nv "${url}"
  fi
  rm -v data.tar.?z
  ar vx "${filename}"
  tar xvf data.tar.?z ".${file}"
done

logdir=$( mktemp -p /tmp -d harden.sh.XXXXXX ) || exit 1
. ${CWD}/../libexec/utils.sh || exit 1
ROOTDIR="./"

. ${CWD}/../libexec/pam.sh || exit 1
configure_core_dumps
test_results+=(${?})
sed -i 1,2d "${logdir}/limits.conf.patch"
sha512sum -c 0<<<"d32faaa96ee8d0a34b92ef746d230afe054cb9a1856b180e5896e85dba28e5c9f40a93ebcddd16ebae369428ae1c6ee581131b3a2f3686bce6911c28f5ea50de  ${logdir}/limits.conf.patch"
test_results+=(${?})

rm -rf "${logdir}"
for ((i=0; i<${#test_results[*]}; i++))
do
  echo "test ${i}: ${test_results[${i}]}"
  ((ret|=${test_results[${i}]}))
done
exit ${ret}
