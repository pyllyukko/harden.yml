#!/bin/bash
################################################################################
# created:	20-07-2013
################################################################################
if [ ${BASH_VERSINFO[0]} -ne 4 ]
then
  echo -e "error: bash version != 4, this script might not work properly!" 1>&2
  echo    "       you can bypass this check by commenting out lines $[${LINENO}-2]-$[${LINENO}+2]." 1>&2
  exit 1
fi
export LANG=en_US
# http://tldp.org/LDP/Bash-Beginners-Guide/html/sect_04_03.html
export LC_ALL=C
# Treat unset variables as an error when substituting.
set -u
for PROGRAM in \
  awk \
  cat \
  cp \
  date \
  gawk \
  grep \
  ln \
  mkdir \
  mktemp \
  mv \
  rm \
  sed \
  shred \
  patch \
  stat
do
  if ! hash "${PROGRAM}" 2>/dev/null
  then
    printf "error: command not found in PATH: %s\n" "${PROGRAM}" >&2
    exit 1
  fi
done
unset PROGRAM
JUST_EXPLODE=0
declare -a RET_VALUES=()

if [ -d tmp ]
then
  rm -rf tmp
fi

mkdir -v tmp

for PKG in \
  'a/etc-14.1-i486-2.txz' \
  'n/network-scripts-14.1-noarch-2.txz' \
  'a/sysvinit-scripts-2.0-noarch-17.txz' \
  'a/shadow-4.1.5.1-i486-2.txz' \
  'a/logrotate-3.8.6-i486-1.txz' \
  'a/sysklogd-1.5-i486-2.txz' \
  'ap/sudo-1.8.6p8-i486-1.txz' \
  'n/sendmail-cf-8.14.7-noarch-1.txz' \
  'n/openssh-6.3p1-i486-1.txz' \
  'n/php-5.4.20-i486-1.txz'
do
  PKG_BASEN=$( basename "${PKG}" )
  if [ ! -f "${PKG_BASEN}" ]
  then
    wget ftp://ftp.slackware.com/pub/slackware/slackware-14.1/slackware/${PKG}
  fi
  if [ ! -f "${PKG_BASEN}.asc" ]
  then
    wget ftp://ftp.slackware.com/pub/slackware/slackware-14.1/slackware/${PKG}.asc
  fi

  gpgv ${PKG_BASEN}.asc
  if [ ${?} -ne 0 ]
  then
    echo "WARNING: package verification failed! aborting!" 1>&2
    exit 1
  fi

  pushd tmp
  /sbin/explodepkg ../${PKG_BASEN}
  popd
done

pushd tmp/etc

for CONF in $( find . -name '*.new' )
do
  mv -v "${CONF}" "${CONF%.new}"
  true
done

if (( ${JUST_EXPLODE} ))
then
  exit 0
fi

patch -p1 -t --dry-run 0<../../../harden_etc-14.1.patch
RET_VALUE=${?}
RET_VALUES+=( ${RET_VALUE} )
if [ ${RET_VALUE} -ne 0 ]
then
  echo "WARNING: something wrong!" 1>&2
fi
echo -n $'\n'

patch -p1 -t --dry-run 0<../../../sudoers-1.8.5p2.patch
RET_VALUE=${?}
RET_VALUES+=( ${RET_VALUE} )
if [ ${RET_VALUE} -ne 0 ]
then
  echo "WARNING: something wrong!" 1>&2
fi
echo -n $'\n'

patch -p1 -t --dry-run 0<../../../ssh_harden-6.3p1.patch
RET_VALUE=${?}
RET_VALUES+=( ${RET_VALUE} )
if [ ${RET_VALUE} -ne 0 ]
then
  echo "WARNING: something wrong!" 1>&2
fi

popd
echo -n $'\n'
pushd tmp/usr/share/sendmail
patch -p1 -t --dry-run 0<../../../../../sendmail_harden.patch
RET_VALUE=${?}
RET_VALUES+=( ${RET_VALUE} )
if [ ${RET_VALUE} -ne 0 ]
then
  echo "WARNING: something wrong!" 1>&2
fi
popd

pushd tmp/etc/httpd
patch -p1 -t --dry-run 0<../../../../php_harden.patch
RET_VALUE=${?}
RET_VALUES+=( ${RET_VALUE} )
if [ ${RET_VALUE} -ne 0 ]
then
  echo "WARNING: something wrong!" 1>&2
fi
popd

echo -e "\nresults:"
for RET_VALUE in ${RET_VALUES[*]}
do
  echo "  ${RET_VALUE}"
done
