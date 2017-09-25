#!/bin/bash
# UNDER CONSTRUCTION!
CWD=$( realpath $( dirname "${0}" ) )
declare -r arch="amd64"
declare -rA files=(
  ["/etc/security/limits.conf"]="http://ftp.debian.org/debian/pool/main/p/pam/libpam-modules_1.1.8-3.6_${arch}.deb"
  ["/etc/pam.d/login"]="http://security.debian.org/debian-security/pool/updates/main/s/shadow/login_4.1.5.1-1+deb7u1_${arch}.deb"
  ["/etc/pam.d/su"]="${files['/etc/pam.d/login']}"
)

#rm -fr    "${CWD}/debian"
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
. ${CWD}/../libexec/pam.sh || exit 1
ROOTDIR="./"
configure_core_dumps
sed -i 2d "${logdir}/limits.conf.patch"
sha512sum -c 0<<<"e89bd9ab2004ae5cc3ddd9614d2d48deb7e12ed589fa988cf17e5f55a363d2d775a9d94ded48aa18de56387cb4fc1833e145cda79273e725d636166c30d36711  ${logdir}/limits.conf.patch"
rm -rf "${logdir}"
