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
  ["/usr/share/pam"]="http://ftp.debian.org/debian/pool/main/p/pam/libpam-runtime_1.1.8-3.6_all.deb"
  ["/etc/pam.d/gdm-password"]="http://ftp.debian.org/debian/pool/main/g/gdm3/gdm3_3.22.3-3_${arch}.deb"
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
check_patch "${logdir}/common-account.patch" 821da2f6b977e91871bd7cfc114ca291dbc9b4088ef928d6a70922663be36913fd32df2b54a08ba3adf640f1d07c15fc33dba024cc3ea36743b57baa67f2bfda
check_patch "${logdir}/common-auth.patch" eb767d2ad9d776cc496a2aa41c1caf8650fd8372f751698b3b7e1717997c88f6e8290a42e0f6d9c95e4a48ca2655abcf6efdcca06d2bbf0b24b9eca356bd7b54
check_patch "${logdir}/common-session.patch" a549e42a96228c4468bae898bf07871ded9af476d7789b809d740f181d44536abbcb6fa52e3ed2fbc17da1c5e4c7891e03a181086f31562b217f7bd3c53f4d88
check_patch "${logdir}/gdm-password-1.patch" f7d22ae4161458e60e79ce58d0e0456c24cb324d0244bccabf4352858a3a3f75aa007c05ace4787bfacd0b3108f606c35828347406b5845dbc3d44e6774e92f3
check_patch "${logdir}/gdm-password-2.patch" 8e8058b1faec3999af7b26360ef1b82fa77a33002cc8a27f87b07740035b1ab6751186832ea981e14fb8da2dac9a6da564afc17e223f2026f2976305db7bdd43

rm -rf "${logdir}"
for ((i=0; i<${#test_results[*]}; i++))
do
  echo "test ${i}: ${test_results[${i}]}"
  ((ret|=${test_results[${i}]}))
done
exit ${ret}
