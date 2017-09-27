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
  ["/etc/pam.d/lightdm"]="http://ftp.debian.org/debian/pool/main/l/lightdm/lightdm_1.18.3-1_${arch}.deb"
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

configure_pam
sed -i 1,2d "${logdir}/login.patch"
sha512sum -c 0<<<"38b42b5509cacfce36747de15d6383a8adb7b74109c8bc534ec67700b83bddf8e6fbfab8af9463271876d934fce884f84ff8d76363ff811bb989a23818800faf  ${logdir}/login.patch"
test_results+=(${?})
sed -i 1,2d "${logdir}/su.patch"
sha512sum -c 0<<<"2205c05499695d3bf434f5080a078f57d3ba1bed8aa4bbfda9c57fb3b045aee5c907df98760e91dfba7bfd54750f7c75e2958da9d01bda2004697d72b2dd0742  ${logdir}/su.patch"
test_results+=(${?})
sha512sum -c 0<<<"c15fa34ee8bcea3c49fb1ffe0be01d4fe645aed9c498f65a6bc815a6b0ea911ed4d15727e34f93323b113905365565e304e2e608dd9a52663a90443598fb8a0c  etc/pam.d/other"
test_results+=(${?})
sed -i 1,2d "${logdir}/lightdm.patch"
sha512sum -c 0<<<"e0c1541a0ca76b556f9089fe239629a8b5be772c3332d2bc42af7c106b1c6c8eca81f8d6d955087b53e3d2d280dffe24b1fb6533eb15b3dd66f89a228b08378e  ${logdir}/lightdm.patch"
test_results+=(${?})

rm -rf "${logdir}"
for ((i=0; i<${#test_results[*]}; i++))
do
  echo "test ${i}: ${test_results[${i}]}"
  ((ret|=${test_results[${i}]}))
done
exit ${ret}
