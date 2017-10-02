#!/bin/bash
# UNDER CONSTRUCTION!
CWD=$( realpath $( dirname "${0}" ) )
declare -i ret=0
declare -a test_results=()
declare -r arch="amd64"
declare -rA files=(
  ["/etc/security"]="http://ftp.debian.org/debian/pool/main/p/pam/libpam-modules_1.1.8-3.6_${arch}.deb"
  ["/etc/pam.d"]="http://security.debian.org/debian-security/pool/updates/main/s/shadow/login_4.1.5.1-1+deb7u1_${arch}.deb"
  ["/etc/pam.d/lightdm"]="http://ftp.debian.org/debian/pool/main/l/lightdm/lightdm_1.18.3-1_${arch}.deb"
  ["/etc/pam.d/sshd"]="http://ftp.debian.org/debian/pool/main/o/openssh/openssh-server_7.4p1-10+deb9u1_${arch}.deb"
)
function check_patch() {
  sed -i 1,2d "${1}"
  sha512sum -c 0<<<"${2}  ${1}"
  test_results+=(${?})
} # check_patch()

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
DISTRO="debian"

. ${CWD}/../libexec/pam.sh || exit 1
configure_core_dumps
test_results+=(${?})
check_patch "${logdir}/limits.conf.patch" d32faaa96ee8d0a34b92ef746d230afe054cb9a1856b180e5896e85dba28e5c9f40a93ebcddd16ebae369428ae1c6ee581131b3a2f3686bce6911c28f5ea50de

configure_pam
check_patch "${logdir}/login-1.patch"     38b42b5509cacfce36747de15d6383a8adb7b74109c8bc534ec67700b83bddf8e6fbfab8af9463271876d934fce884f84ff8d76363ff811bb989a23818800faf
check_patch "${logdir}/su.patch"          2205c05499695d3bf434f5080a078f57d3ba1bed8aa4bbfda9c57fb3b045aee5c907df98760e91dfba7bfd54750f7c75e2958da9d01bda2004697d72b2dd0742
sha512sum -c 0<<<"c15fa34ee8bcea3c49fb1ffe0be01d4fe645aed9c498f65a6bc815a6b0ea911ed4d15727e34f93323b113905365565e304e2e608dd9a52663a90443598fb8a0c  etc/pam.d/other"
test_results+=(${?})
check_patch "${logdir}/lightdm-1.patch"   e0c1541a0ca76b556f9089fe239629a8b5be772c3332d2bc42af7c106b1c6c8eca81f8d6d955087b53e3d2d280dffe24b1fb6533eb15b3dd66f89a228b08378e
# pam_namespace
check_patch "${logdir}/login-2.patch"     ce28a2586edb8531a0acdc3148e35c45dbdacabd28bc3e77b9aa8d2a3903dd549c36f1fd22bd17d676f74bda5a7a7f8ba55be4688bd5e39921340fa07e9b85e8
check_patch "${logdir}/lightdm-2.patch"   aedcede80773b778eccf8c01ad6770134aaeb32c501980d5297b9a6d86bd66be906a767cb7ad697a9f8064b990c109178f3a94f9a3917a5b0fd2ab01eac608cd
check_patch "${logdir}/namespace.conf-1.patch" 2ee0ca57beae509099a15d53c4e3bc7929df8e2e6e1492ce067fa374b0da552da3c21b9a489a7dad56cafe949cd7f196584965edc233132c81b1488ab0b9c4eb
check_patch "${logdir}/namespace.conf-2.patch" 6764d82657efed74369c906a3ceedb3ad4d0c1ed0bd1d525adf8340471a46883d4c6edf70932e356fd36e9020873ebb4cdea62bd782a7c9f8668889831e51883
check_patch "${logdir}/sshd.patch"        9880cc693f7208486e86cfcec3088d541f6049fce186b3c590aae3e92bcffbd13ce50f2fb79b70765fd7646efabdc43c77d43b2b64f81affe97e3276b8ea91b9

rm -rf "${logdir}"
for ((i=0; i<${#test_results[*]}; i++))
do
  echo "test ${i}: ${test_results[${i}]}"
  ((ret|=${test_results[${i}]}))
done
exit ${ret}
