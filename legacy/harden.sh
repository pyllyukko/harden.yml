#!/bin/bash
################################################################################
#
# harden.sh -- https://github.com/pyllyukko/harden.sh
#
################################################################################
shopt -s extglob
set -u
export PATH="/usr/sbin:/sbin:/usr/bin:/bin"
for PROGRAM in \
  awk     \
  cat     \
  cp      \
  id      \
  usermod \
  grpck   \
  chmod   \
  chown   \
  date    \
  gawk    \
  getent  \
  grep    \
  bzgrep  \
  fgrep   \
  ln      \
  mkdir   \
  mv      \
  openssl \
  patch   \
  rm      \
  sed     \
  shred   \
  mktemp  \
  tee     \
  diff    \
  stat    \
  make    \
  wget    \
  realpath
do
  if ! hash "${PROGRAM}" 2>/dev/null
  then
    printf "[-] error: command not found in PATH: %s\n" "${PROGRAM}" >&2
    exit 1
  fi
done
unset PROGRAM
CWD=$( realpath $( dirname "${0}" ) )
for file in gpg.sh slackware.sh
do
  . ${CWD}/libexec/${file} || {
    echo "[-] couldn't find libexec/${file}" 1>&2
    exit 1
  }
done
unset file

# determine distro
if [ -f /etc/os-release ]
then
  DISTRO=$( sed -n '/^ID=/s/^ID="\?\([^"]*\)"\?$/\1/p' /etc/os-release )
fi
declare -i ETC_CHANGED=0
declare -r RBINDIR="/usr/local/rbin"
declare -r CADIR="/usr/share/ca-certificates/local"
declare -r SKS_CA="sks-keyservers.netCA.pem"
declare    LYNIS_TESTS=1
if ! hash lynis
then
  LYNIS_TESTS=0
fi
logdir=$( mktemp -p /tmp -d harden.sh.XXXXXX )
#declare -rA grsec_groups=(
#  ["grsec_proc"]=1001
#  ["grsec_sockets"]=1002
#  ["grsec_socketc"]=1003
#  ["grsec_socketall"]=1004
#  ["grsec_tpe"]=1005
#  ["grsec_symlinkown"]=1006
#  ["grsec_audit"]=1007
#)
declare -rA PASSWORD_POLICIES=(
  ["PASS_MAX_DAYS"]=365
  ["PASS_MIN_DAYS"]=7
  ["PASS_WARN_AGE"]=30
  ["ENCRYPT_METHOD"]="SHA512"
  ["SHA_CRYPT_MIN_ROUNDS"]=500000
  ["UMASK"]="077"
  ["FAILLOG_ENAB"]="yes"
)
password_inactive=-1
declare -rA PWQUALITY_SETTINGS=(
  ["minlen"]="14"
  ["dcredit"]="-1"
  ["ucredit"]="-1"
  ["ocredit"]="-1"
  ["lcredit"]="-1"
)
declare -r CERTS_DIR="/etc/ssl/certs"

# from CIS Apache HTTP Server 2.4 Benchmark v1.1.0 - 12-03-2013
# 1.2.3-8
declare -a apache_disable_modules_list=(
  'dav_'
  'status_module'
  'autoindex_module'
  'proxy_'
  'userdir_module'
  'info_module'
)
################################################################################
function toggle_usb_authorized_default() {
  local host
  local state

  print_topic "USB authorized_default"

  for host in /sys/bus/usb/devices/usb*
  do
    read state 0<"${host}/authorized_default"
    ((state^=1))
    if (( ${state} ))
    then
      echo "[+] setting ${host} to authorized_default"
    else
      echo "[+] setting ${host} to !authorized"
    fi
    echo "${state}" > ${host}/authorized_default
  done

  return 0
} # toggle_usb_authorized_default()
################################################################################
function usage() {
  cat 0<<-EOF
	harden.sh -- system hardening script for slackware linux

	usage: ${0} options

	options:

	  -b		toggle USB authorized_default
	  -g		import Slackware, SBo & other PGP keys to trustedkeys.gpg keyring
	        	(you might also want to run this as a regular user)
	  -h		this help
	  -I		check Slackware installation's integrity from MANIFEST (owner & permission)
	  -L user	lock account 'user'

	Make targets:

	  /etc/ssh/moduli.new
	  /etc/ssh/ssh_host_{rsa,ecdsa,ed25519}_key
	  /etc/ssl/certs/ca-certificates.crt
	  /etc/securetty
	  /etc/fstab.new
	  manifest
	  pam-configs
	  dh-[numbits].pem
EOF
  # print functions
  #declare -f 2>/dev/null | sed -n '/^.* () $/s/^/  /p'
  exit 0
} # usage()
################################################################################

if [ "${USER}" != "root" ]
then
  echo -e "[-] warning: you should probably be root to run this script\n" 1>&2
fi
if [ ${#NAMES[*]} -eq 0 ]
then
  echo '[-] warning: NAMES array not populated' 1>&2
fi

while getopts "bghIL:" OPTION
do
  case "${OPTION}" in
    "b") toggle_usb_authorized_default	;;
    "g") import_pgp_keys		;;
    "h")
      usage
      exit 0
    ;;
    "I") check_integrity		;;
    "L") lock_account "${OPTARG}"	;;
  esac
done

shopt -s nullglob
logfiles=( ${logdir}/* )
echo -n $'\n'
if [ ${#logfiles[*]} -eq 0 ]
then
  echo "no log files created. removing dir."
  rmdir -v "${logdir}"
else
  echo "logs available at: ${logdir}"
fi

exit 0
