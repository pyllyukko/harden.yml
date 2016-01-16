#!/bin/bash
################################################################################
#
# harden.sh -- https://github.com/pyllyukko/harden.sh
#
################################################################################
if [ ${BASH_VERSINFO[0]} -ne 4 ]
then
  echo -e "error: bash version != 4, this script might not work properly!" 1>&2
  echo    "       you can bypass this check by commenting out lines $[${LINENO}-2]-$[${LINENO}+2]." 1>&2
  exit 1
fi
shopt -s extglob
set -u
export PATH="/usr/sbin:/sbin:/usr/bin:/bin"
for PROGRAM in \
  awk \
  cat \
  cp \
  faillog \
  id \
  usermod \
  grpck \
  chmod \
  chown \
  date \
  gawk \
  grep \
  ln \
  mkdir \
  mv \
  openssl \
  patch \
  rm \
  sed \
  shred \
  mktemp \
  tee \
  stat
do
  if ! hash "${PROGRAM}" 2>/dev/null
  then
    printf "error: command not found in PATH: %s\n" "${PROGRAM}" >&2
    exit 1
  fi
done
unset PROGRAM
# the rc.modules* should match at least the following:
#   - rc.modules.local
#   - rc.modules-2.6.33.4
#   - rc.modules-2.6.33.4-smp
declare -r SA_RC="/etc/rc.d/rc.sysstat"
SERVICES_WHITELIST=(
  /etc/rc.d/rc.0
  /etc/rc.d/rc.4
  /etc/rc.d/rc.6
  /etc/rc.d/rc.K
  /etc/rc.d/rc.M
  /etc/rc.d/rc.S
  /etc/rc.d/rc.acpid
  /etc/rc.d/rc.firewall
  /etc/rc.d/rc.font
  /etc/rc.d/rc.loop
  /etc/rc.d/rc.inet1
  /etc/rc.d/rc.inet2
  /etc/rc.d/rc.keymap
  /etc/rc.d/rc.local
  /etc/rc.d/rc.local_shutdown
  /etc/rc.d/rc.modules
  /etc/rc.d/rc.modules-+([0-9.])?(-smp)
  /etc/rc.d/rc.modules.local
  /etc/rc.d/rc.netdevice
  /etc/rc.d/rc.sshd
  /etc/rc.d/rc.syslog
  "${SA_RC}"
  /etc/rc.d/rc.udev
  /etc/rc.d/rc.ntpd
  /etc/rc.d/rc.mcelog
  /etc/rc.d/rc.sysvinit
  # SBo:
  /etc/rc.d/rc.clamav
  /etc/rc.d/rc.snort
  /etc/rc.d/rc.auditd
)
#declare -ra LOG_FILES=(
#  btmp
#  cron*
#  debug*
#  dmesg
#  faillog
#  lastlog
#  maillog*
#  messages*
#  secure*
#  spooler*
#  syslog*
#  wtmp
#  xferlog
#)
declare -r GPG_KEYRING="trustedkeys.gpg"

# PATCHES

#declare -r APACHE_PATCH_VERSION="2.4.3-20120929-1"
declare -r APACHE_PATCH_FILE="apache_harden.patch"
declare -r SENDMAIL_PATCH_FILE="sendmail_harden.patch"
declare -r SUDOERS_PATCH_VERSION="1.8.12"
declare -r SUDOERS_PATCH_FILE="sudoers-${SUDOERS_PATCH_VERSION}.patch"
# OpenSSH configs differ between versions, so we need to have quite version
# specific patches, it also isn't Slackware version dependent, so we need to
# try to detect it.
SSH_VERSION=$( ssh -V 2>&1 | sed 's/^OpenSSH_\([^,]\+\),.*$/\1/' )
case "${SSH_VERSION}" in
  "6.3p1")	SSH_PATCH_FILE="ssh_harden-6.3p1.patch" ;;
  "6.7p1")	SSH_PATCH_FILE="ssh_harden-6.7p1.patch" ;;
  "7.1p1")	SSH_PATCH_FILE="ssh_harden-7.1p1.patch" ;;
  *)		SSH_PATCH_FILE="ssh_harden-6.3p1.patch" ;;
esac

# /PATCHES

declare -r SLACKWARE_VERSION=$( sed 's/^.*[[:space:]]\([0-9]\+\.[0-9]\+\).*$/\1/' /etc/slackware-version 2>/dev/null )
declare -r ETC_PATCH_FILE="harden_etc-${SLACKWARE_VERSION}.patch"
# these are not declared as integers cause then the ${ ... :-DEFAULT } syntax won't work(?!)
declare -r UID_MIN=$(		awk '/^UID_MIN/{print$2}'	/etc/login.defs 2>/dev/null )
declare -r UID_MAX=$(		awk '/^UID_MAX/{print$2}'	/etc/login.defs 2>/dev/null )
declare -r PASS_MIN_DAYS=$(	awk '/^PASS_MIN_DAYS/{print$2}'	/etc/login.defs 2>/dev/null )
declare -r PASS_MAX_DAYS=$(	awk '/^PASS_MAX_DAYS/{print$2}'	/etc/login.defs 2>/dev/null )
declare -r PASS_WARN_AGE=$(	awk '/^PASS_WARN_AGE/{print$2}'	/etc/login.defs 2>/dev/null )
declare -r SYS_UID_MAX=$(	awk '/^SYS_UID_MAX/{print$2}'	/etc/login.defs 2>/dev/null )
declare -r WWWROOT="/var/www"
declare -i ETC_CHANGED=0
declare -r SENDMAIL_CF_DIR="/usr/share/sendmail/cf/cf"
declare -r SENDMAIL_CONF_PREFIX="sendmail-slackware"
declare -r RBINDIR="/usr/local/rbin"
declare -r INETDCONF="/etc/inetd.conf"
declare -r CADIR="/usr/share/ca-certificates/local"
declare -r SKS_CA="sks-keyservers.netCA.pem"
declare -a NAMES=( $( cut -d: -f1 /etc/passwd ) )
auditPATH='/etc/audit'
logdir=$( mktemp -p /tmp -d harden.sh.XXXXXX )
CWD=$( realpath $( dirname "${0}" ) )

# NOLOGIN(8): "It is intended as a replacement shell field for accounts that have been disabled."
# Slackware default location:
if [ -x /sbin/nologin ]
then
  DENY_SHELL="/sbin/nologin"
# Debian default location:
elif [ -x /usr/sbin/nologin ]
then
  DENY_SHELL="/usr/sbin/nologin"
else
  echo "warning: can't find nologin!" 1>&2
  DENY_SHELL=
fi
# man FAILLOG(8)
declare -i FAILURE_LIMIT=10
declare -r CERTS_DIR="/etc/ssl/certs"

# from CIS 2.1 Disable Standard Services
declare -a INETD_SERVICES=(echo discard daytime chargen time ftp telnet comsat shell login exec talk ntalk klogin eklogin kshell krbupdate kpasswd pop imap uucp tftp bootps finger systat netstat auth netbios swat rstatd rusersd walld)

# ...plus some extras
INETD_SERVICES+=(pop3 imap2 netbios-ssn netbios-ns)

# more info about these PGP keys:
#   - http://www.slackbuilds.org/faq/#asc
#   - http://nmap.org/book/install.html#inst-integrity
#   - http://www.cipherdyne.org/contact.html
#   - http://www.openwall.com/signatures/ (295029F1)
#   - http://www.nongnu.org/tiger/key.html & http://savannah.nongnu.org/users/jfs
#   - http://www.atagar.com/pgp.php
#   - http://wiki.centos.org/FAQ/CentOS5#head-3a83196c7a97a7990ca646cbd135fd67198fe812
#     (centos key here might seem odd, but i want to be able to verify ISO
#      images i've downloaded)
#   - https://kismetwireless.net/download.shtml#gpg
#   - aide:
#     - http://aide.sourceforge.net/
#     - http://sourceforge.net/projects/aide/files/PGP%20key/
#   - http://www.wangafu.net/~nickm/ 8D29319A - Nick Mathewson (libevent)
#   - https://tails.boum.org/download/index.en.html#verify
#   - TODO: http://www.snort.org/snort-downloads#pgp
#   - https://www.kali.org/downloads/
#   - https://cisofy.com/documentation/lynis/#no-installation
#   - https://wiki.qubes-os.org/wiki/VerifyingSignatures
declare -ra PGP_URLS=(
  "http://www.slackware.com/gpg-key"
  "http://slackbuilds.org/GPG-KEY"
  "http://nmap.org/data/nmap_gpgkeys.txt"
  "https://www.cipherdyne.org/signing_key"
  "http://www.openwall.com/signatures/openwall-signatures.asc"
  "https://savannah.nongnu.org/people/viewgpg.php?user_id=7475"
  "https://www.atagar.com/resources/damianJohnson.asc"
  #"http://mirror.centos.org/centos/RPM-GPG-KEY-CentOS-5"
  "https://www.kismetwireless.net/dragorn.gpg"
  "https://sourceforge.net/projects/aide/files/PGP%20key/aide-2010_0xCBF11FCD.asc/download"
  "http://www.wangafu.net/~nickm/public_key.asc"
  "https://tails.boum.org/tails-signing.key"
  "https://grsecurity.net/spender-gpg-key.asc"
  "https://sourceforge.net/projects/apcupsd/files/apcupsd%20Public%20Key/Current%20Public%20Key/apcupsd.pub/download"
  "https://www.kali.org/archive-key.asc"
  "https://cisofy.com/files/cisofy-software.pub"
  "https://keys.qubes-os.org/keys/qubes-release-2-signing-key.asc"
  "https://bitcoin.org/laanwj-releases.asc"
)

# other PGP keys:
#
#   metasploit keys:

#   - CEA0A321 - James Lee <egypt@metasploit.com>
#                (metasploit project signing key)
#   - 060798CB - HD Moore (2011-10-06) (latest?)
#   - 2007B954 - metasploit (18.6.2013)
#
#
#   - 28988BF5 - Roger from torproject
#                https://www.torproject.org/docs/verifying-signatures.html.en
#   - 19F78451 - -- || --
#   - 6980F8B0 - Breno Silva (ModSecurity)
#   - D679F6CF - Karl Berry <karl@freefriends.org> (gawk)
#   - BF2EA563 - Fabian Keil, lead developer of privoxy
#   - 63FEE659 - Erinn Clark (Tor Browser Bundles)
#                https://www.torproject.org/docs/signing-keys.html.en
#   - 0x4E2C6E8793298290 - Tor Browser Developers (signing key) <torbrowser@torproject.org>
#   - 6294BE9B - http://www.debian.org/CD/verify
#   - 9624FCD2 - Ryan Barnett (OWASP Core Rule Set Project Leader) <rbarnett@trustwave.com>
#                https://www.owasp.org/index.php/Category:OWASP_ModSecurity_Core_Rule_Set_Project#Download
#   - 4245D46A - Bradley Spengler (spender) (grsecurity)
#                https://grsecurity.net/contact.php
#   - 6092693E - https://www.kernel.org/signature.html
#   - DDC6C0AD - https://www.torproject.org/torbutton/
#   - 1FC730C1 - Bitcoin
#   - 73647CFF - Nico Golde (Debian Advisories)
#   - 86FF9C48 - Damien Miller (Personal Key) <djm@mindrot.org> (OpenSSH)
#     0xD3E5F56B6D920D30
#   - 77F95F95 - Werner Koch <wk@gnupg.org> (gnupg-announce@gnupg.org)
#   - 0x249B39D24F25E3B6 - Werner Koch (dist sig)
#   - 54FC8640 - Debian security advisory
#   - 14595A1A - Renaud Deraison (Nessus)
#   - 15A0A4BC - Mozilla Software Releases <releases@mozilla.org>
#   - 5E9905DB - Mozilla Software Releases <releases@mozilla.org>
#   - 5F2E4935 - https://support.mayfirst.org/wiki/faq/security/mfpl-certificate-authority Jamie McClelland <jamie@mayfirst.org>
#     D21739E9   dkg
#   - 0x0B7F8B60E3EDFAE3 - https://www.sks-keyservers.net/overview-of-pools.php
#   - 0x2E8DD26C53F1197DDF403E6118E667F1EB8AF314 - https://web.monkeysphere.info/archive-key/
#   - F0D6B1E0 - http://www.truecrypt.org/docs/digital-signatures
#   - F295C759 - OpenSSL
#   - FA40E9E2 - steve@openssl.org
#   - 0xD9C4D26D0E604491 - matt@openssl.org
#   - 0x715ED6A07E7B8AC9 - key that can be used to verify SPI's CA cert - http://www.spi-inc.org/ca/
#   - 0xDED64EBB2BA87C5C - OTR Dev Team <otr@cypherpunks.ca>
#   - 0x7CBD620BEC70B1B8 - https://ssl.intevation.de/ - used to sign Gpg4win
#   - 0x41259773973A612A - https://bitbucket.org/skskeyserver/sks-keyserver/src/tip/README.md
#   - 0x40B8EA2364221D53 - Sourcefire VRT GPG Key (at least ClamAV)
#   - 0xBB5869F064EA74AB - Chet Ramey / GNU / Bash
#   - 0x17167CB4EE3A8EED - https://www.apple.com/support/security/pgp/
#   - 0xB88B2FD43DBDC284 - http://software.opensuse.org/132/en
#   - 0x24C6A8A7F4A80EB5 - https://www.centos.org/keys/#centos-7-signing-key
#   - 0x409B6B1796C275462A1703113804BB82D39DC0E3 - RVM https://rvm.io/rvm/security
#   - 0x4623E8F745953F23 - http://deb.mempo.org/
#   - 0x00CCB587DDBEF0E1 - The Irssi project <staff@irssi.org>
#   - 1E453B2CE87BEE2F7DFE99661E34A1828E207901 - LEAP (https://bitmask.net/en/install/signature-verification)
#   - 0xC29D97ED198D22A3 - https://openvpn.net/index.php/open-source/documentation/sig.html
#   - 0x1AF51CE72993D5F9 - Mixmaster 3.x Code Release Signing Key
#   - 0x6887935AB297B391 - sukhbir@torproject.org (Tor messenger)
#   - 0xADEF768480316BDA - Kevin McCarthy's key (mutt)
#   - 0xD94AA3F0EFE21092 - Ubuntu https://help.ubuntu.com/community/VerifyIsoHowto
declare -ra PGP_KEYS=(
  #"CEA0A321"
  #"060798CB"
  "0xCDFB5FA52007B954"

  "0xEB5A896A28988BF5"
  "0xC218525819F78451"
  "0x8050C35A6980F8B0"
  "0x9DEB46C0D679F6CF"
  "0x48C5521FBF2EA563"
  "0x416F061063FEE659"
  "0x4E2C6E8793298290"
  "0xDA87E80D6294BE9B"
  "0xC976607D9624FCD2"
  #"4245D46A"
  "0x38DBBDC86092693E"
  "0x1B0CA30CDDC6C0AD"
  "0x29D9EE6B1FC730C1"
  "0x1D87E54973647CFF"
  "0xCE8ECB0386FF9C48"
  "0xD3E5F56B6D920D30"
  "0x4F0540D577F95F95"
  "0x249B39D24F25E3B6"
  "0x1BF83C5E54FC8640"
  "0xF091044D14595A1A"
  "0x057CC3EB15A0A4BC"
  "5E9905DB"
  "0xBB0B7EE15F2E4935"
  "0xCCD2ED94D21739E9"
  "0x0B7F8B60E3EDFAE3"
  "0x2E8DD26C53F1197DDF403E6118E667F1EB8AF314"
  "0xE3BA73CAF0D6B1E0"
  "0xA2D29B7BF295C759"
  "0xD3577507FA40E9E2"
  "0xD9C4D26D0E604491"
  "0x715ED6A07E7B8AC9"
  "0xDED64EBB2BA87C5C"
  "0x7CBD620BEC70B1B8"
  "0x41259773973A612A"
  "0x40B8EA2364221D53"
  "0xBB5869F064EA74AB"
  "0x17167CB4EE3A8EED"
  "0xB88B2FD43DBDC284"
  "0x24C6A8A7F4A80EB5"
  "0x409B6B1796C275462A1703113804BB82D39DC0E3"
  "0x4623E8F745953F23"
  "0x00CCB587DDBEF0E1"
  "0x1E453B2CE87BEE2F7DFE99661E34A1828E207901"
  "0xC29D97ED198D22A3"
  "0x1AF51CE72993D5F9"
  "0x6887935AB297B391"
  "0xADEF768480316BDA"
  "0xD94AA3F0EFE21092"
)
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
declare -r ARCH=$( /bin/uname -m )
case "${MACHTYPE%%-*}" in
  "x86_64")	SLACKWARE="slackware64"	;;
  i?86)		SLACKWARE="slackware"	;;
  # TODO: arm
esac
if [ -n "${SLACKWARE_VERSION}" ]
then
  MANIFEST_DIR="${CWD}/manifests/${SLACKWARE}-${SLACKWARE_VERSION}"
fi
################################################################################
function check_manifest() {
  local MD5_RET
  if [ ! -f "${MANIFEST_DIR}/CHECKSUMS.md5" ] || \
     [ ! -f "${MANIFEST_DIR}/CHECKSUMS.md5.asc" ] || \
     [ ! -f "${MANIFEST_DIR}/MANIFEST.bz2" ]
  then
    return 1
  fi
  /usr/bin/gpgv "${MANIFEST_DIR}/CHECKSUMS.md5.asc" || return 1
  pushd "${MANIFEST_DIR}" 1>/dev/null
  fgrep "MANIFEST.bz2" CHECKSUMS.md5 | /bin/md5sum -c
  MD5_RET=${PIPESTATUS[1]}
  popd 1>/dev/null
  if [ ${MD5_RET} -ne 0 ]
  then
    return 1
  fi
  return 0
} # check_manifest()
################################################################################
function chattr_files_NOT_IN_USE() {
  # NOTE: not in use, at least not yet.

  local i

  # CIS SN.4 Additional LILO Security
  chattr +i /etc/lilo.conf

  # system-hardening-10.2.txt: Filesystem
  for i in $( ls /etc/rc.d )
  do
    chattr +i /etc/rc.d/$i
  done
  for i in $( ls /etc/httpd )
  do
    chattr +i /etc/httpd/$i
  done
  for i in $( ls /etc/mail )
  do
    chattr +i /etc/mail/$i
  done

  find / -type f \( -perm -4000 -o -perm -2000 \) -exec chattr +i {} \;

  chattr +i /etc/at.deny
  chattr +i /etc/exports
  chattr +i /etc/ftpusers
  chattr +i /etc/host.conf
  chattr +i /etc/hosts
  chattr +i /etc/hosts.allow
  chattr +i /etc/hosts.deny
  chattr +i /etc/hosts.equiv
  chattr +i /etc/hosts.lpd
  chattr +i "${INETDCONF}"
  chattr +i /etc/inittab
  #chattr +i /etc/lilo.conf
  chattr +i /etc/login.access
  chattr +i /etc/login.defs
  chattr +i /etc/named.conf
  chattr +i /etc/porttime
  chattr +i /etc/profile
  chattr +i /etc/protocols
  chattr +i /etc/securetty
  chattr +i /etc/services
  chattr +i /etc/suauth
  #chattr +i /home/dentonj/.forward
  #chattr +i /home/dentonj/.netrc
  #chattr +i /home/dentonj/.rhosts
  #chattr +i /home/dentonj/.shosts
  chmod go-rwx /usr/bin/chattr /usr/bin/lsattr

  return
} # chattr_files()
################################################################################
function install_additional_software_NOT_IN_USE() {
  # TODO:
  #   - under construction
  #   - what to do with the "(P)roceed or (Q)uit?:" prompt?
  if [ -x /usr/sbin/sbopkg ]
  then
    # sync the repos
    /usr/sbin/sbopkg -r || {
      echo "${FUNCNAME}(): error: error syncing repos!" 1>&2
      return 1
    }
  else
    echo "${FUNCNAME}(): error: sbopkg not found!" 1>&2
    return 1
  fi
  return
} # install_additional_software()
################################################################################
function disable_inetd_services() {
  # CIS 2.1 Disable Standard Services
  local SERVICE

  if [ ! -f "${INETDCONF}" ]
  then
    echo "${FUNCNAME}(): inetd conf file not found!" 1>&2
    return 0
  fi

  echo "${FUNCNAME}(): disabling inetd services"

  if [ ! -f "${INETDCONF}.original" ]
  then
    cp -v "${INETDCONF}" "${INETDCONF}.original"
  fi

  for SERVICE in ${INETD_SERVICES[*]}
  do
    sed -i 's/^\('"${SERVICE}"'\)/\#\1/' "${INETDCONF}"
  done

  return
} # disable_inetd_services()
################################################################################
function create_environment_for_restricted_shell () {
  local PRG

  if [ ! -d "${RBINDIR}" ]
  then
    mkdir -pv "${RBINDIR}"
  fi
  {
    chown -c root:root	"${RBINDIR}"
    chmod -c 755	"${RBINDIR}"
  } | tee -a "${logdir}/file_perms.txt"

  #rm -v "${RBINDIR}/"*

  pushd "${RBINDIR}" || return 1

  for PRG in /bin/{cat,cp,df,du,id,ls,mkdir,mv,uname,who} /usr/bin/{chage,passwd,printenv,uptime}
  do
    ln -sv ${PRG}
  done
  ln -sv /usr/bin/vim	rvim
  ln -sv /usr/bin/view	rview

  popd

  return
} # create_environment_for_restricted_shell()
################################################################################
function import_pgp_keys() {
  local URL
  local PGP_KEY
  local SKS_HASH

  echo "${FUNCNAME}(): importing PGP keys"
  # keys with URL
  for URL in ${PGP_URLS[*]}
  do
    # after importing these keys, we can verify slackware packages with gpgv
    /usr/bin/wget --tries=5 "${URL}" -nv --output-document=- | gpg --logger-fd 1 --keyring "${GPG_KEYRING}" --no-default-keyring --import -
  done | tee "${logdir}/pgp_keys.txt"

  # some CAs that are used with HKPS
  #
  # https://support.mayfirst.org/wiki/faq/security/mfpl-certificate-authority
  # https://en.wikipedia.org/wiki/Key_server_%28cryptographic%29#Keyserver_examples
  # https://we.riseup.net/riseuplabs+paow/openpgp-best-practices#consider-making-your-default-keyserver-use-a-keyse
  if [ "${USER}" = "root" ] && [ ! -d /usr/share/ca-certificates/local ]
  then
    # NOTE: update-ca-certificates will add /usr/local/share/ca-certificates/*.crt to globally trusted CAs... which of course, is not good!
    #mkdir -pvm 755 /usr/local/share/ca-certificates
    mkdir -pvm 755 /usr/share/ca-certificates/local
  fi
  # TODO: these are not verified, as we need to get the PGP keys first :)
  #       but we use sks-keyservers currently anyway, and that is verified.
  if [ "${USER}" = "root" ] && [ ! -f /usr/share/ca-certificates/local/mfpl.crt ]
  then
    wget -nv --directory-prefix=/usr/share/ca-certificates/local \
      https://support.mayfirst.org/raw-attachment/wiki/faq/security/mfpl-certificate-authority/mfpl.crt \
      https://support.mayfirst.org/raw-attachment/wiki/faq/security/mfpl-certificate-authority/mfpl.crt.dkg.asc \
      https://support.mayfirst.org/raw-attachment/wiki/faq/security/mfpl-certificate-authority/mfpl.crt.jamie.asc
    chmod -c 644 /usr/share/ca-certificates/local/mfpl.crt | tee -a "${logdir}/file_perms.txt"
  fi
  if [ "${USER}" = "root" ] && [ ! -f "${CADIR}/${SKS_CA}" ]
  then
    # https://www.sks-keyservers.net/verify_tls.php
    cat "${CWD}/certificates/${SKS_CA}" 1>"${CADIR}/${SKS_CA}"
    chmod -c 644 "${CADIR}/${SKS_CA}" | tee -a "${logdir}/file_perms.txt"
  # for regular users
  elif [ "${USER}" != "root" ] && [ ! -f "${CADIR}/${SKS_CA}" ]
  then
    echo "${FUNCNAME}(): error: sks-keyservers CA not available. can not continue! try to run this as root to install the CA." 1>&2
    return 1
  fi
  # get the CRL
  SKS_HASH=$( openssl x509 -in ${CADIR}/${SKS_CA} -noout -hash )
  if [ -n "${SKS_HASH}" ] && [ "${USER}" = "root" ]
  then
    wget -nv --ca-certificate=/usr/share/ca-certificates/mozilla/Thawte_Premium_Server_CA.crt https://sks-keyservers.net/ca/crl.pem -O "${CADIR}/${SKS_HASH}.r0"
    chmod -c 644 "${CADIR}/${SKS_HASH}.r0" | tee -a "${logdir}/file_perms.txt"
  fi
  sha512sum -c 0<<<"d0a056251372367230782e050612834a2efa2fdd80eeba08e490a770691e4ddd52a744fd3f3882ca4188f625c3554633381ac90de8ea142519166277cadaf7b0  ${CADIR}/${SKS_CA}"
  if [ ${?} -ne 0 ]
  then
    echo "${FUNCNAME}(): error: sks-keyservers CA's SHA-512 fingerprint does not match!" 1>&2
    return 1
  fi
  # keys with key ID
  for PGP_KEY in ${PGP_KEYS[*]}
  do
    /usr/bin/gpg \
      --logger-fd 1 \
      --keyserver "hkps://hkps.pool.sks-keyservers.net" \
      --keyserver-options ca-cert-file=${CADIR}/${SKS_CA} \
      --keyring "${GPG_KEYRING}" --no-default-keyring \
      --recv-keys "${PGP_KEY}"
  done | tee -a "${logdir}/pgp_keys.txt"
  return 0
} # import_pgp_keys()
################################################################################
function lock_system_accounts() {
  local NAME
  local uid
  local password_status

  # CIS 8.1 Block System Accounts (modified)
  # CIS 3.4 Disable Standard Boot Services (modified) (the user accounts part)
  #
  # NOTE: according to CIS (3.13 Only Enable SQL Server Processes If Absolutely Necessary & 8.1 Block System Accounts)
  #       mysql user account needs to have bash as it's shell.
  #
  # NOTE:
  #   - this should be run periodically
  #   - 29.8.2012: added expire as suggested in passwd(1)
  #
  # TODO: find out the details about mysql's shell!!
  for NAME in ${NAMES[*]}
  do
    uid=$( id -u ${NAME} )
    # as the NAMES array is populated in the beginning of the script, some user
    # accounts might have been hardened away already at this point.
    if [ -z "${uid}" ]
    then
      continue
    fi
    if [ ${uid} -le ${SYS_UID_MAX:-999} ] && [ ${NAME} != 'root' ]
    then
      crontab -l -u "${NAME}" 2>&1 | grep -q "^no crontab for"
      if [ ${PIPESTATUS[1]} -ne 0 ]
      then
        echo "${FUNCNAME}(): WARNING: the user \`${NAME}' has some cronjobs! should it be so?" 1>&2
      fi
      password_status=$( /usr/bin/passwd -S "${NAME}" | awk '{print$2}' )
      if [ "${password_status}" != "L" ]
      then
        echo "${FUNCNAME}(): WARNING: the account \`${NAME}' is not locked properly!" 1>&2
      fi
      /usr/sbin/usermod -e 1970-01-02 -L -s "${DENY_SHELL}" "${NAME}"
    fi
  done
} # lock_system_accounts()
################################################################################
function user_accounts() {
  # NOTE: http://refspecs.freestandards.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic/usernames.html
  #
  # NOTE: http://www.redhat.com/archives/nahant-list/2007-March/msg00163.html (good thread about halt & shutdown accounts)
  #
  # TODO: for loop through SYS_UID_MIN - SYS_UID_MAX
  # TODO: groups (or are they even necessary?)
  # TODO: it still might be too dangerous to just start removing anything. reconsider this.

  local -i GRPCK_RET
  local uid
  local NAME
  local USERID
  local USER_HOME_DIR

  if [ ! -x "${DENY_SHELL}" ]
  then
    echo "${FUNCNAME}(): error: invalid \$DENY_SHELL!" 1>&2
    return 1
  fi

  echo "${FUNCNAME}(): removing unnecessary user accounts"

  # system-hardening-10.2.txt:
  #
  # remove user account 'gdm'
  #   - suggested in system-hardening-10.2.txt
  #   - gnome was dropped from slackware in v10.2
  #   - from ftp://ftp.slackware.com/pub/slackware/slackware-10.2/ChangeLog.txt:
  #     "gnome/*:  Removed from -current"...
  #
  # operator:
  #   - according to LSB Core Specification 4.1 (21.2. User & Group Names, Table 21-2)
  #     the user 'operator' is optional
  #   - TODO: at least change home dir
  #
  # halt, shutdown & sync:
  #   "The accounts "halt" and "shutdown" don't work
  #    by default.  The account "sync" isn't needed."
  check_manifest && {
    #for USERID in adm gdm operator halt shutdown sync
    for USERID in gdm operator
    do
      # verify from MANIFEST, that the user account is not being used
      bzcat "${MANIFEST_DIR}/MANIFEST.bz2" | awk '{print$2}' | grep "^${USERID}/"
      if [ ${PIPESTATUS[2]} -ne 0 ]
      then
	echo "  removing user \`${USERID}'"
        /usr/bin/crontab -d -u	"${USERID}"
        /usr/sbin/userdel	"${USERID}"
	# TODO: kill all processes of the user
      fi
    done
  }

  # CUSTOM

  # result from /usr/sbin/pwck -r
  #
  # NOTE: if the packages are added on a later date, the user accounts
  #       will probably be missing.
  # WARNING! this might lead to unowned files and directories if some of the
  #          packages are installed afterwards.
  # NOTE: user lp shouldn't be removed, few devices are owned by this account
  #
  # TODO:
  #   - these users might still have some files/directories on the system
  #     we should check that before we remove these users, so we don't
  #     end up with unowned files/directories
  #
  # the home directories exist if the packages are installed:
  # drwxrwxr-x uucp/uucp         0 1993-08-12 21:18 var/spool/uucppublic/
  # drwxr-xr-x root/root         0 2010-05-15 13:10 usr/games/
  # drwxr-xr-x root/root         0 2011-04-04 23:07 home/ftp/
  # drwxrwx--- smmsp/smmsp       0 2002-02-13 19:21 var/spool/clientmqueue/
  # drwxr-x--- mysql/mysql       0 2011-04-05 17:33 var/lib/mysql/
  # drwxr-xr-x root/root         0 2010-12-23 18:46 var/run/dbus/
  # drwxr-xr-x haldaemon/haldaemon 0 2010-11-16 16:55 var/run/hald/
  #
  # NOTE: 25.9.2012: disabled, so we don't get any unowned files.
  #for NAME in uucp games ftp smmsp mysql messagebus haldaemon
  #do
  #  USER_HOME_DIR=$( awk -F':' '$1=="'"${NAME}"'"{print$6}' /etc/passwd )

  #  # this could mean the account is already removed...
  #  if [ -z "${USER_HOME_DIR}" ]
  #  then
  #    echo "${FUNCNAME}(): INFO: user '${NAME}' might have already been removed"
  #    continue
  #  fi

  #  if [ ! -d "${USER_HOME_DIR}" ]
  #  then
  #    echo "${FUNCNAME}(): DEBUG: user '${NAME}': directory '${USER_HOME_DIR}' does not exist"
  #    /usr/bin/crontab -d -u	"${NAME}"
  #    /usr/sbin/userdel		"${NAME}"
  #    /usr/sbin/groupdel	"${NAME}"
  #  fi
  #done

  # on slackware 13.37 the user news has /usr/lib/news as home directory which
  # does not exist. we use an easy way to determine wether the news clients are
  # installed.
  #
  # NOTE: 25.9.2012: disabled, so we don't get any unowned files.
  #if [ ! -d "/usr/lib/nn" ] && [ ! -d "/var/spool/slrnpull" ]
  #then
  #  /usr/bin/crontab -d -u	news
  #  /usr/sbin/userdel		news
  #  /usr/sbin/groupdel		news
  #fi

  # change the defaults. this will update /etc/default/useradd.
  # this makes it so, that when a password of a user expires, the account is
  # locked and the user cannot login anymore.
  #
  # WARNING: you don't want to set the EXPIRE (-e), since it's an absolute
  # date, and not relative. it's too easy to create accounts that are already
  # locked.
  #
  # see http://tldp.org/HOWTO/Shadow-Password-HOWTO-7.html#ss7.1
  useradd -D -f 0

  # modify adduser to use 700 as newly created home dirs permission
  sed -i 's/^defchmod=[0-9]\+\(.*\)$/defchmod=700\1/' /usr/sbin/adduser

  echo "${FUNCNAME}(): modifying/hardening current user accounts"

  lock_system_accounts

  # CIS 8.3 Set Account Expiration Parameters On Active Accounts
  for NAME in ${NAMES[*]}
  do
    uid=$( id -u $NAME )
    if [ -z "${uid}" ]
    then
      continue
    fi
    if [ $uid -ge ${UID_MIN:-1000} ] && [ $uid != 65534 ]
    then
      chage -m ${PASS_MIN_DAYS:-1} -M ${PASS_MAX_DAYS:-365} -W ${PASS_WARN_AGE:-30} $NAME
    fi
  done

  # this satisfies CIS Apache Web Server 2.2.0 Benchmark 1.6 "Creating the Apache User and Group Accounts."
  # from Nessus CIS_Apache_v2_1.audit
  # NOTE: 25.9.2012: disabled, for consistency's sake.
  #/usr/sbin/usermod -d /dev/null -s "${DENY_SHELL}" apache

  # currently (13.1) slackware has this in passwd:
  #   lp:x:4:7:lp:/var/spool/lpd:/bin/false
  # lprng had this dir back in 11.0, even then it was in pasture/
  #   drwx------ lp/lp             0 2006-02-03 04:55 var/spool/lpd/
  if [ ! -d /var/spool/lpd ] && [ -d /var/spool/cups ]
  then
    /usr/sbin/usermod -d /var/spool/cups lp
  fi

  # from README.privsep
  # another less tiger warning (pass016w)
  /usr/sbin/usermod -c 'sshd privsep' -d /var/empty sshd

  user_home_directories_permissions


  # CUSTOM

  #
  # See GPASSWD(1): "Notes about group passwords"
  #
  # remove daemon from adm group, since we use adm group for log reading.
  # default members in Slack14.0:
  #   adm:x:4:root,adm,daemon
  #usermod -G daemon daemon
  gpasswd -d daemon adm

  # restrict adm group
  #gpasswd -R adm

  echo "creating groups for grsecurity"
  groupadd -g 1001 grsec_proc
  groupadd -g 1002 grsec_sockets
  groupadd -g 1003 grsec_socketc
  groupadd -g 1004 grsec_socketall
  groupadd -g 1005 grsec_tpe
  groupadd -g 1006 grsec_symlinkown
  groupadd -g 1007 grsec_audit

  # this should create the missing entries to /etc/gshadow
  if [ -x /usr/sbin/grpck ]
  then
    echo "${FUNCNAME}(): running \`grpck -r'"
    /usr/sbin/grpck -r
    GRPCK_RET=${?}
    case "${GRPCK_RET}" in
      2)
        echo "${FUNCNAME}(): \`grpck -r' returned ${GRPCK_RET} (\"one or more bad group entries\"). running \`/usr/bin/yes | /usr/sbin/grpck'."
        # NOTE: this could be dangerous. then again, that is the nature of this whole script.
        /usr/bin/yes | /usr/sbin/grpck
        echo "${FUNCNAME}(): grpck returned ${PIPESTATUS[1]}"
      ;;
      *)
        echo "${FUNCNAME}(): \`grpck -r' returned ${GRPCK_RET}"
      ;;
    esac
  else
    echo "WARNING: grpck not found!" 1>&2
  fi

  set_failure_limits

  create_ftpusers

  # CIS 7.5 Restrict at/cron To Authorized Users
  #
  # NOTE: Dillon's cron does not support /etc/cron.{allow,deny}
  #
  # NOTE: if both /etc/cron.{allow,deny} are missing, tiger reports this:
  #       --WARN-- [cron005w] Use of cron is not restricted
  #
  # "Don't allow anyone to use at."
  #
  # AT.ALLOW(5) & AT(1): "If the file /etc/at.allow exists, only usernames mentioned in it are allowed to use at."
  #
  # Slackware's at package creates /etc/at.deny by default, which has blacklisted users. so we're switching
  # from blacklist to (empty) whitelist.
  echo "restricting the use of at"
  if [ -s "/etc/at.deny" ] && [ ! -f "/etc/at.allow" ]
  then
    /usr/bin/rm -v	/etc/at.deny
    /usr/bin/touch	/etc/at.allow
    {
      chown -c root:daemon	/etc/at.allow
      chmod -c 640		/etc/at.allow
    } | tee -a "${logdir}/file_perms.txt"
  fi

  return 0
} # user_accounts()
################################################################################
function lock_account() {
  if [ -z "${1}" ]
  then
    echo "${FUNCNAME}(): error!" 1>&2
    return 1
  fi
  id -u "${1}" &>/dev/null
  if [ ${?} -ne 0 ]
  then
    echo "${FUNCNAME}(): no such user!" 1>&2
    return 1
  fi
  /usr/sbin/usermod -e 1970-01-02 -L -s "${DENY_SHELL}" "${1}"
  /usr/bin/crontab -d -u "${1}"
  killall -s SIGKILL -u "${1}" -v
  #gpasswd -d "${1}" users

  return 0
} # lock_account()
################################################################################
function create_additional_user_accounts() {
  # see http://slackbuilds.org/uid_gid.txt

  groupadd -g 206 -r privoxy
  useradd  -u 206 -g privoxy -e 1970-01-02 -M -d /dev/null -s ${DENY_SHELL} -r privoxy

  # this is also used by metasploit
  groupadd -g 209 -r postgres
  useradd  -u 209 -e 1970-01-02 -g 209 -s ${DENY_SHELL} -M -d /var/lib/pgsql -r postgres

  # http://slackbuilds.org/repository/14.0/system/clamav/
  groupadd -g 210 -r clamav
  useradd  -u 210 -e 1970-01-02 -M -d /var/lib/clamav -s ${DENY_SHELL} -g clamav -r clamav

  # ntop 212

  #groupadd -g 213 -r nagios
  #useradd -u 213 -d /dev/null -s /bin/false -g nagios nagios

  groupadd -g 220 -r tor
  useradd  -u 220 -g 220 -e 1970-01-02 -c "The Onion Router" -M -d /var/lib/tor -s ${DENY_SHELL} tor

  groupadd -g 234 -r kismet

  return
} # create_additional_user_accounts()
################################################################################
function restart_services() {
  # stuff that needs to be restarted or loaded after patching etc
  #
  # NOTE: at least the following services are not started this way:
  #       - process accounting
  #       - logoutd

  [ -f /etc/sysctl.conf ]	&&	/sbin/sysctl -p 	/etc/sysctl.conf
  [ -x /etc/rc.d/rc.syslog ]	&&	/etc/rc.d/rc.syslog	restart
  # TODO: this might kill your SSH connection
  #[ -x /etc/rc.d/rc.firewall ] &&	/etc/rc.d/rc.firewall	restart

  # TODO: enable after making the ssh patch
  #[ -x /etc/rc.d/rc.sshd ] &&		/etc/rc.d/rc.sshd	restart

  return 0
} # restart_services()
################################################################################
function check_and_patch() {
  # $1 = dir
  # $2 = patch file
  # $3 = p level
  # $4 = [reverse]
  local DIR_TO_PATCH="${1}"
  local PATCH_FILE="${CWD}/patches/${2}"
  local P="${3}"
  local -i GREP_RET
  local -i PATCH_RET
  local -i RET

  [ ! -d "${DIR_TO_PATCH}" ] && {
    echo "${FUNCNAME}(): error: directory \`${DIR_TO_PATCH}' does not exist!" 1>&2
    return 1
  }

  [ ! -f "${PATCH_FILE}" ] && {
    echo "${FUNCNAME}(): error: patch file \`${PATCH_FILE}' does not exist!" 1>&2
    return 1
  }
  #pushd "${1}" || return 1

  set +u
  if [ -n "${4}" ] && [ "${4}" = "reverse" ]
  then
    # this is the best i came up with to detect if the patch is already applied/reversed before actually applying/reversing it.
    # patch seems to return 0 in every case, so we'll have to use grep here.
    echo "${FUNCNAME}(): testing patch file \`${PATCH_FILE##*/}' with --dry-run"
    /usr/bin/patch -R -d "${DIR_TO_PATCH}" -t -p${P} --dry-run -i "${PATCH_FILE}" | /usr/bin/grep "^\(Unreversed patch detected\|The next patch, when reversed, would delete the file\)"
    PATCH_RET=${PIPESTATUS[0]} GREP_RET=${PIPESTATUS[1]}
    if [ ${PATCH_RET} -ne 0 ] || [ ${GREP_RET} -eq 0 ]
    then
      echo "${FUNCNAME}(): error: patch dry-run didn't work out, maybe the patch has already been reversed?" 1>&2
      return 1
    fi
    # if everything was ok, apply the patch
    echo "${FUNCNAME}(): DEBUG: patch would happen"
    /usr/bin/patch -R -d "${DIR_TO_PATCH}" -t -p${P} -i "${PATCH_FILE}" | tee -a "${logdir}/patches.txt"
    RET=${?}
  else
    echo "${FUNCNAME}(): testing patch file \`${PATCH_FILE##*/}' with --dry-run"
    # TODO: detect rej? "3 out of 4 hunks FAILED -- saving rejects to file php.ini.rej"
    /usr/bin/patch -d "${DIR_TO_PATCH}" -t -p${P} --dry-run -i "${PATCH_FILE}" | /usr/bin/grep "^\(The next patch would create the file\|Reversed (or previously applied) patch detected\)"
    PATCH_RET=${PIPESTATUS[0]} GREP_RET=${PIPESTATUS[1]}
    if [ ${PATCH_RET} -ne 0 ] || [ ${GREP_RET} -eq 0 ]
    then
      echo "${FUNCNAME}(): error: patch dry-run didn't work out, maybe the patch has already been applied?" 1>&2
      return 1
    fi
    echo "DEBUG: patch would happen"
    /usr/bin/patch -d "${DIR_TO_PATCH}" -t -p${P} -i "${PATCH_FILE}" | tee -a "${logdir}/patches.txt"
    RET=${?}
  fi
  set -u
  return ${RET}
}
################################################################################
function remove_packages() {
  # BIG FAT NOTE: make sure you don't actually need these!
  #               although, i tried to keep the list short.

  echo "${FUNCNAME}(): removing potentially dangerous packages"

  {
    # CIS 7.1 Disable rhosts Support
    /sbin/removepkg netkit-rsh 2>/dev/null

    # from system-hardening-10.2.txt (Misc Stuff -> Stuff to remove)
    #
    # NOTE: uucp comes with a bunch of SUID binaries, plus i think most people
    #       won't need it nowadays anyway.
    /sbin/removepkg uucp 2>/dev/null

    # remove the floppy package. get rid of the fdmount SUID binary.
    /sbin/removepkg floppy 2>/dev/null

    # TODO: remove xinetd package?
  } | tee -a "${logdir}/removed_packages.txt"

  return 0
} # remove_packages()
################################################################################
function harden_fstab() {
  # related info: http://wiki.centos.org/HowTos/OS_Protection#head-7e30c59c22152e9808c2e0b95ceec1382456d35c
  #
  # TODO (from shred man page):
  #   In the particular case of ext3 file systems, the above disclaimer
  #   Applies (and `shred' is thus of limited effectiveness) only in
  #   `data=journal' mode, which journals file data in addition to just
  #   Metadata. In both the `data=ordered' (default) and `data=writeback'
  #   Modes, `shred' works as usual.  Ext3 journaling modes can be changed by
  #   Adding the `data=something' option to the mount options for a
  #   Particular file system in the `/etc/fstab' file, as documented in the
  #   Mount man page (man mount).

  if [ ! -w /etc ]
  then
    echo "${FUNCNAME}(): error: /etc is not writable. are you sure you are root?" 1>&2
    return 1
  elif [ ! -f /etc/fstab ]
  then
    echo "${FUNCNAME}(): error: /etc/fstab doesn't exist?!?" 1>&2
    return 1
  fi
  # TODO: /tmp and maybe the /var/tmp binding from NSA 2.2.1.4
  gawk '
    BEGIN{
      if(system("grep -q raspbian /etc/os-release")==0)
	os="raspbian"
      else if(system("test -f /etc/slackware-version")==0)
	os="slackware"
      else if(system("test -f /etc/debian_version")==0)
	os="debian"
      else
	os="unknown"
    }
    # partly from system-hardening-10.2.txt
    # strict settings for filesystems mounted under /mnt
    ( \
      $3 ~ /^(ext[234]|reiserfs|vfat)$/ && \
      $4 !~ /(nodev|nosuid|noexec)/ && \
      ( $2 ~ /^\/m.*/ || $2 ~ /^\/boot/ ) \
    ){
      $4 = $4 ",nosuid,nodev,noexec"
    }
    # from system-hardening-10.2.txt
    ( $2 == "/var" && \
      $4 !~ /(nosuid|nodev)/ \
    ){
      $4 = $4 ",nosuid,nodev"
    }
    # from system-hardening-10.2.txt
    ( $2 == "/home" && \
      $4 !~ /(nosuid|nodev)/ \
    ){
      $4 = $4 ",nosuid,nodev"
    }
    # CIS 6.1 Add 'nodev' Option To Appropriate Partitions In /etc/fstab
    # NOTE:
    #   - added ext4
    #   - this somewhat overlaps with the first rule but the $4 rule takes care of this
    ( \
      $3 ~ /^(ext[234]|reiserfs)$/ && \
      $2 != "/" && \
      $4 !~ /nodev/ \
    ){
      $4 = $4 ",nodev"
    }
    # CIS 6.2 Add 'nosuid' and 'nodev' Option For Removable Media In /etc/fstab
    # NOTE: added noexec
    # NOTE: the "[0-9]?" comes from Debian, where the mount point is /media/cdrom0
    ( \
      $2 ~ /^\/m.*\/(floppy|cdrom[0-9]?)$/ && \
      $4 !~ /(nosuid|nodev|noexec)/ \
    ){
      $4 = $4 ",nosuid,nodev,noexec"
    }
    # NSA RHEL guide - 2.2.1.3.2 Add nodev, nosuid, and noexec Options to /dev/shm
    ( \
      $2 ~ /^\/dev\/shm$/ && \
      $4 !~ /(nosuid|nodev|noexec)/ \
    ){
      $4 = $4 ",nosuid,nodev,noexec"
    }
    $3 == "swap" {
      # FSTAB(5): "For swap partitions, this field should be specified as "none"."
      $2 = "none"
      # FILE-6336
      $4 = "sw"
    }
    {
      # formatting from /usr/lib/setup/SeTpartitions of slackware installer
      if($0 ~ /^#/)
	print
      else
	switch(os) {
	  case "raspbian":
	    # raspbian format
	    printf "%-15s %-15s %-7s %-17s %-7s %s\n", $1, $2, $3, $4, $5, $6
	    break
	  case "debian":
	    # debian format
	    printf "%-15s %-15s %-7s %-15s %-7s %s\n", $1, $2, $3, $4, $5, $6
	    break
	  case "slackware":
	  default:
	    # slackware format
	    printf "%-16s %-16s %-11s %-16s %-3s %s\n", $1, $2, $3, $4, $5, $6
	    break
	}
    }' /etc/fstab 1>/etc/fstab.new

  if [ -f /etc/fstab.new ]
  then
    echo "${FUNCNAME}(): /etc/fstab.new created"
  fi

  return ${?}
} # harden_fstab()
################################################################################
function file_permissions() {
  # NOTE: from SYSKLOGD(8):
  #   "Syslogd doesn't change the filemode of opened logfiles at any stage of process.  If a file is created it is world readable.
  #
  # TODO: chmod new log files also

  echo "${FUNCNAME}(): setting file permissions. note that this should be the last function to run."

  { # log everything to file_perms.txt
    # CIS 1.4 Enable System Accounting (applied)
    #
    # NOTE: sysstat was added to slackware at version 11.0
    #
    # NOTE: the etc patch should create the necessary cron entries under /etc/cron.d
    /usr/bin/chmod -c 700 "${SA_RC}"

    # CIS 3.3 Disable GUI Login If Possible (partly)
    /usr/bin/chown -c root:root	/etc/inittab
    /usr/bin/chmod -c 0600	/etc/inittab

    # CIS 4.1 Network Parameter Modifications (partly)
    #
    # NOTE: sysctl.conf should be created by the etc patch
    /usr/bin/chown -c root:root	/etc/sysctl.conf
    /usr/bin/chmod -c 0600	/etc/sysctl.conf

    ## CIS 5.3 Confirm Permissions On System Log Files (modified)
    ## NOTE: apache -> httpd
    pushd /var/log
    ###############################################################################
    ## Permissions for other log files in /var/log
    ###############################################################################
    ## NOTE: according to tiger, the permissions of wtmp should be 664
    /usr/bin/chmod -c o-rwx {b,w}tmp cron* debug* dmesg {last,fail}log maillog* messages* secure* spooler* syslog* xferlog

    ###############################################################################
    ##   directories in /var/log
    ###############################################################################
    #/usr/bin/chmod -c o-w httpd cups iptraf nfsd samba sa uucp

    ###############################################################################
    ##   contents of directories in /var/log
    ###############################################################################
    #/usr/bin/chmod -c o-rwx httpd/* cups/* iptraf/* nfsd/* samba/* sa/* uucp/*

    ###############################################################################
    ##   Slackware package management
    ###############################################################################
    ##
    ## NOTE: Nessus plugin 21745 triggers, if /var/log/packages is not readable
    /usr/bin/chmod -c o-w packages removed_{packages,scripts} scripts setup
    #/usr/bin/chmod -c o-rwx	packages/* removed_packages/* removed_scripts/* scripts/* setup/*

    ###############################################################################
    ## Permissions for group log files in /var/log
    ###############################################################################
    ## NOTE: removed wtmp from here, it is group (utmp) writable by default and there might be a good reason for that.
    /usr/bin/chmod -c g-wx btmp cron* debug* dmesg {last,fail}log maillog* messages* secure* spooler* syslog* xferlog

    ##   directories in /var/log
    #/usr/bin/chmod -c g-w httpd cups iptraf nfsd samba sa uucp

    ##   contents of directories in /var/log
    #/usr/bin/chmod -c g-wx httpd/* cups/* iptraf/* nfsd/* samba/* sa/* uucp/*

    ###############################################################################
    ## Permissions for owner
    ###############################################################################
    ##   log files in /var/log
    #/usr/bin/chmod u-x btmp cron* debug* dmesg faillog lastlog maillog* messages* secure* spooler* syslog* wtmp xferlog
    ##   contents of directories in /var/log
    ## NOTE: disabled, these directories might contain subdirectories so u-x doesn't make sense.
    ##/usr/bin/chmod u-x httpd/* cups/* iptraf/* nfsd/* samba/* sa/* uucp/*

    ##   Slackware package management
    ## NOTE: disabled, these directories might contain subdirectories so u-x doesn't make sense.
    ##/usr/bin/chmod u-x packages/* removed_packages/* removed_scripts/* scripts/* setup/*

    ## Change ownership
    ## NOTE: disabled, the ownerships should be correct.
    ##/usr/bin/chown -cR root:root .
    ##/usr/bin/chown -c uucp uucp
    ##/usr/bin/chgrp -c uucp uucp/*
    ##/usr/bin/chgrp -c utmp wtmpq

    if [ -d sudo-io ]
    then
      /usr/bin/chown -c root:root	sudo-io
      /usr/bin/chmod -c 700		sudo-io
    fi

    popd

    ## END OF CIS 5.3

    # CIS 6.3 Verify passwd, shadow, and group File Permissions (modified)

    # here's where CIS goes wrong, the permissions by default are:
    # -rw-r----- root/shadow     498 2009-03-08 22:01 etc/shadow.new
    # ...if we go changing that, xlock for instance goes bananas.
    # modified accordingly.
    #
    # then again, if there is no xlock or xscreensaver binaries in the system,
    # the perms could be root:root 0600.
    #
    # 9.10.2012: added gshadow to the list
    /usr/bin/chown -c root:root		/etc/passwd /etc/group
    /usr/bin/chmod -c 644		/etc/passwd /etc/group
    /usr/bin/chown -c root:shadow	/etc/shadow /etc/gshadow
    /usr/bin/chmod -c 440		/etc/shadow /etc/gshadow

    # CIS 7.3 Create ftpusers Files
    /usr/bin/chown -c root:root		/etc/ftpusers
    /usr/bin/chmod -c 600		/etc/ftpusers

    # CIS 7.6 Restrict Permissions On crontab Files
    #
    # NOTE: Slackware doesn't have /etc/crontab, as it's ISC cron that has this
    #       file and not Dillon's cron
    if [ -f "/etc/crontab" ]
    then
      /usr/bin/chown -c root:root	/etc/crontab
      /usr/bin/chmod -c 400		/etc/crontab
    fi
    /usr/bin/chown -cR root:root	/var/spool/cron
    /usr/bin/chmod -cR go-rwx		/var/spool/cron

    # CIS 7.8 Restrict Root Logins To System Console
    # also Nessus cert_unix_checklist.audit "Permission and ownership check /etc/securetty"
    /usr/bin/chown -c root:root		/etc/securetty
    /usr/bin/chmod -c 400		/etc/securetty

    # CIS 7.9 Set LILO Password
    # - also suggested in system-hardening-10.2.txt
    # - also Tiger [boot01]
    /usr/bin/chown -c root:root		/etc/lilo.conf
    /usr/bin/chmod -c 600		/etc/lilo.conf

    # CIS 8.13 Limit Access To The Root Account From su
    /usr/bin/chown -c root:root		/etc/suauth
    /usr/bin/chmod -c 400		/etc/suauth

    # 8.7 User Home Directories Should Be Mode 750 or More Restrictive (modified)
    user_home_directories_permissions

    # CIS SN.2 Change Default Greeting String For sendmail
    #
    # i'm not sure about this one...
    #
    # ftp://ftp.slackware.com/pub/slackware/slackware-13.1/slackware/MANIFEST.bz2:
    # -rw-r--r-- root/root     60480 2010-04-24 11:44 etc/mail/sendmail.cf.new

    #/usr/bin/chown -c root:bin /etc/mail/sendmail.cf
    #/usr/bin/chmod -c 444 /etc/mail/sendmail.cf

    ##############################################################################
    # from Security Configuration Benchmark For Apache HTTP Server 2.2
    # Version 3.0.0 (CIS_Apache_HTTP_Server_Benchmark_v3.0.0)
    ##############################################################################

    # CIS 1.3.6 Core Dump Directory Security (Level 1, Scorable) (modified)
    #/usr/bin/chown -c root:apache	/var/log/httpd
    /usr/bin/chown -c root:adm		/var/log/httpd
    /usr/bin/chmod -c 750		/var/log/httpd

    ##############################################################################
    # from Nessus cert_unix_checklist.audit (Cert UNIX Security Checklist v2.0)
    # http://www.nessus.org/plugins/index.php?view=single&id=21157
    ##############################################################################

    # NOTE: netgroup comes with yptools
    # NOTE:
    #   login.defs might need to be readable:
    #     groupmems[7511]: cannot open login definitions /etc/login.defs [Permission denied]
    #     newgrp[4912]: cannot open login definitions /etc/login.defs [Permission denied]
    for FILE in \
      "/etc/hosts.equiv" \
      "${INETDCONF}" \
      "/etc/netgroup" \
      "/etc/login.defs" \
      "/etc/login.access"
    do
      [ ! -f "${FILE}" ] && continue
      /usr/bin/chown -c root:root	"${FILE}"
      /usr/bin/chmod -c 600		"${FILE}"
    done

    # Nessus Cert UNIX Security Checklist v2.0 "Permission and ownership check /var/adm/wtmp"
    # UTMP(5): "The  wtmp file records all logins and logouts."
    # LAST,LASTB(1): "Last  searches  back  through the file /var/log/wtmp (or the file designated by the -f flag)
    #                 and displays a list of all users logged in (and out) since that file was created."
    #
    # the default permissions in Slackware are as follows:
    # -rw-rw-r-- root/utmp         0 1994-02-10 19:01 var/log/wtmp.new
    #
    # wtmp offers simply too much detail over so long period of time.
    #
    # NOTE: in slackware 13.1 /var/adm is a symbolic link to /var/log
    #/usr/bin/chown -c root:utmp	/var/adm/wtmp
    #/usr/bin/chown -c root:root	/var/adm/wtmp[.-]*

    # CIS 5.3 handles the permissions, this file shouldn't be readable by all users. it contains sensitive information.
    # NOTE: 10.10.2012: CIS 5.3 commented out
    # rotated files... of course this should be done in logrotate.conf.
    /usr/bin/chmod -c o-rwx	/var/adm/wtmp
    # make the rotated wtmp files group adm readable
    /usr/bin/chgrp -c root	/var/adm/wtmp[.-]*
    /usr/bin/chmod -c 0640	/var/adm/wtmp[.-]*

    # Nessus CIS_Apache_v2_1.audit "1.19 Updating Ownership and Permissions."
    # ...wtf?
    #/usr/bin/chmod -c 0044 /etc/httpd



    ##############################################################################
    # from system-hardening-10.2.txt:
    ##############################################################################

    # "The file may hold encryption keys in plain text."
    /usr/bin/chmod -c 600	/etc/rc.d/rc.wireless.conf
    /usr/bin/chmod -cR go-rwx	/etc/cron.*

    # "The system startup scripts are world readable by default."
    /usr/bin/chmod -cR go-rwx /etc/rc.d/

    # "Remove the SUID or SGID bit from the following files"
    #
    # Slackware 14.0 default permissions:
    #   -rwsr-sr-x daemon/daemon 40616 2010-07-28 15:20 usr/bin/at
    #   -rws--x--x root/root     47199 2012-09-13 20:12 usr/bin/chfn
    #   -rws--x--x root/root     47197 2012-09-13 20:12 usr/bin/chsh
    #   -rws--x--x root/root     10096 2012-09-07 15:24 usr/bin/crontab
    #
    # NOTE: see CVE-2011-0721 for an example of why.
    #
    # NOTE: you can find all SUID/SGID binaries with "find / -type f \( -perm -04000 -o -perm -02000 \)"
    #/usr/bin/chmod -c ug-s	/usr/bin/at
    /usr/bin/chmod -c u-s	/usr/bin/chfn
    /usr/bin/chmod -c u-s	/usr/bin/chsh

    # somewhere along the lines of CIS 7.5 Restrict at/cron To Authorized Users
    #
    # the dcron's README describes that the use should be limited by a
    # designated group (CRONTAB_GROUP) as follows:
    #   -rwx------  0 root   root    32232 Jan  6 18:58 /usr/local/sbin/crond
    #   -rwsr-x---  0 root   wheel   15288 Jan  6 18:58 /usr/local/bin/crontab
    # NOTE: alien uses the wheel group here: http://alien.slackbook.org/dokuwiki/doku.php?id=linux:admin
    /usr/bin/chmod -c 700	/usr/sbin/crond
    chgrp -c wheel		/usr/bin/crontab
    chmod -c 4710		/usr/bin/crontab
    # this line disables cron from everyone else but root:
    #/usr/bin/chmod -c u-s		/usr/bin/crontab

    # NOTE: 9.10.2012: these could actually be needed.
    #/usr/bin/chmod -c u-s		/usr/bin/gpasswd
    #/usr/bin/chmod -c u-s		/usr/bin/newgrp

    # SSH-KEYSIGN(8):
    # ssh-keysign is disabled by default and can only be enabled in the global client
    # configuration file /etc/ssh/ssh_config by setting EnableSSHKeysign to ``yes''.
    #
    # if you use host based authentication with SSH, you probably need to comment
    # this out.
    #
    # also mentioned in the NSA guide section 2.2.3.4 "Find Unauthorized SUID/SGID System Executables"

    /usr/bin/chmod -c u-s		/usr/libexec/ssh-keysign

    ##############################################################################
    # end of system-hardening-10.2.txt
    ##############################################################################

    # from CIS RHEL guide (11.1 Configure and enable the auditd and sysstat services, if possible)
    chown -c root:root		$auditPATH/audit.rules
    chmod -c 0600		$auditPATH/audit.rules
    chmod -c 0600		$auditPATH/auditd.conf

    # CUSTOM STUFF BELOW

    # more SUID binaries:
    # notice that the uucp package is removed with remove_packages()
    /usr/bin/chmod -c u-s	/usr/bin/cu
    /usr/bin/chmod -c u-s	/usr/bin/uucp
    #/usr/bin/chmod -c u-s	/usr/bin/pkexec

    # from GROUPMEMS(8): "The groupmems executable should be in mode 2770 as user root and in group groups."
    # since we don't allow users to use it, make it 750.
    #chmod -c 750 /usr/sbin/groupmems

    # SSA:2011-101-01:
    if [ -u /usr/sbin/faillog ] || \
       [ -u /usr/sbin/lastlog ]
    then
      echo "${FUNCNAME}(): notice: you seem to be missing a security patch for SSA:2011-101-01"
      /usr/bin/chmod -c u-s	/usr/sbin/faillog
      /usr/bin/chmod -c u-s	/usr/sbin/lastlog
    fi

    # the process accounting log file:
    if [ -f /var/log/pacct ]
    then
      /usr/bin/chmod -c 600 /var/log/pacct
    fi

    # adjust the www permissions, so that regular users can't read
    # your database credentials from some php file etc. also so that
    # apache can't write there, in case of some web app vulns.
    if [ -d "${WWWROOT}" ]
    then
      # TODO: dokuwiki creates files which are apache:apache, should we ignore those?
      /usr/bin/chown -cR root:apache ${WWWROOT}
      #find ${WWWROOT} -type d -exec /usr/bin/chmod -c 750 '{}' \;
      #find ${WWWROOT} -type f -exec /usr/bin/chmod -c 640 '{}' \;

      # some dirs might need to be writable by apache, so we'll just do this:
      find ${WWWROOT} -exec /usr/bin/chmod -c o-rwx '{}' \;
    fi

    # man 5 limits:
    # "It should be owned by root and readable by root account only."
    if [ -f "/etc/limits" ]
    then
      /usr/bin/chown -c root:root	/etc/limits
      /usr/bin/chmod -c 600		/etc/limits
    fi

    # man 5 audisp-remote.conf:
    # "Note that the key file must be owned by root and mode 0400."
    if [ -f "/etc/audisp/audisp-remote.key" ]
    then
      /usr/bin/chown -c root:root	/etc/audisp/audisp-remote.key
      /usr/bin/chmod -c 400		/etc/audisp/audisp-remote.key
    fi

    # man 5 auditd.conf:
    # "Note that the key file must be owned by root and mode 0400."
    if [ -f "/etc/audit/audit.key" ]
    then
      /usr/bin/chown -c root:root	/etc/audit/audit.key
      /usr/bin/chmod -c 400		/etc/audit/audit.key
    fi

    # sudo: /etc/sudoers is mode 0640, should be 0440
    # visudo -c says: "/etc/sudoers: bad permissions, should be mode 0440"
    /usr/bin/chmod -c 0440 /etc/sudoers

    # wpa_supplicant conf might include pre-shared keys or private key passphrases.
    chmod -c 600 /etc/wpa_supplicant.conf

    # snmptrapd.conf might have SNMP credentials
    chmod -c 600 /etc/snmp/snmptrapd.conf

    # there can be SO many log files under /var/log, so i think this is the safest bet.
    # any idea if there's some log files that should be world-readable? for instance Xorg.n.log?
    #
    # NOTE: wtmp has special ownership/permissions which are handled by the etc package (.new)
    #       and logrotate
    # NOTE: ideally, all the permissions of the files should be handled by syslog/logrotate/etc...
    #
    #/usr/bin/find /var/log -type f -maxdepth 1 \! -name 'wtmp*' -exec /usr/bin/chmod -c 600 '{}' \;
    # we define mindepth here, so /var/log itself doesn't get chmodded. if there are some logs files
    # that need to be written by some other user (for instance tor), it doesn't work if /var/log
    # is with 700 permissions.
    /usr/bin/find /var/log -type d -maxdepth 1 -mindepth 1 -group root	-exec /usr/bin/chgrp -c adm	'{}' \;
    /usr/bin/find /var/log -type d -maxdepth 1 -mindepth 1 -group adm	-exec /usr/bin/chmod -c 750	'{}' \;
    /usr/bin/find /var/log -type d -maxdepth 1 -mindepth 1		-exec /usr/bin/chmod -c o-rwx	'{}' \;
    #/usr/bin/find /var/log -type d -maxdepth 1 -mindepth 1 -exec /usr/bin/chmod -c 700 '{}' \;

    #/usr/bin/find /var/log -type f -name 'wtmp*' -exec /usr/bin/chmod -c 660 '{}' \;
    #chmod -c 660 /var/log/wtmp

    # DEBIAN SPECIFIC
    chmod -c 600 /etc/network/interfaces

    # if you have nagios installed. also this is because of grsec's TPE:
    if [ -d /usr/libexec/nagios ]
    then
      chown -c root:nagios /usr/libexec/nagios
      chmod -c 750 /usr/libexec/nagios
    fi

    # make lastlog adm readable
    chown -c root:adm	/var/log/lastlog
    chmod -c 640	/var/log/lastlog
  } | tee -a "${logdir}/file_perms.txt"

  return 0
} # file_permissions()
################################################################################
function various_checks_NOT_IN_USE() {
  visudo -c
  pwck -r
  grpck -r
  tcpdchk -v
  apachectl configtest
} # various_checks()
################################################################################
function user_home_directories_permissions() {
  # this has been split into it's own function, since it relates to both
  # "hardening categories", user accounts & file permissions.
  local DIR
  # 8.7 User Home Directories Should Be Mode 750 or More Restrictive (modified)
  for DIR in \
    $( awk -F: '($3 >= 500) { print $6 }' /etc/passwd ) \
    /root
  do
    if [ "x${DIR}" != "x/" ]
    then
      /usr/bin/chmod -c 700 ${DIR} | tee -a "${logdir}/file_perms.txt"
    fi
  done

  return
} # user_home_directories_permissions()
################################################################################
function create_ftpusers() {
  local NAME
  local uid
  # CIS 7.3 Create ftpusers Files (modified)
  #
  # FTPUSERS(5):
  #   ftpusers - list of users that may not log in via the FTP daemon
  #
  # NOTE: there's a /etc/vsftpd.ftpusers file described in the CIS document, but
  #       i didn't find any reference to it in vsftpd's own documentation.
  #
  # NOTE: this file is created even if there's no FTP daemon installed.
  #       if proftpd package is installed afterwards, it leaves it's own
  #       ftpusers as .new.
  #
  # NOTE: proftpd's own ftpusers include accounts: ftp, root, uucp & news
  #
  # NOTE: this should be run periodically, since it's a blacklist and
  #       additional user accounts might be created after this.

  echo "${FUNCNAME}(): adding to /etc/ftpusers:"
  # get the login names
  for NAME in ${NAMES[*]}
  do
    uid=$(id -u "${NAME}")
    # as the NAMES array is populated in the beginning of the script, some user
    # accounts might have been hardened away already at this point.
    if [ -z "${uid}" ]
    then
      continue
    fi
    if [ ${uid} -lt 500 ]
    then
      # add the name to ftpusers only if it's not already in there.
      # this should work whether the ftpusers file exists already or not.
      grep -q "^${NAME}$" /etc/ftpusers 2>/dev/null || {
	echo "  \`${NAME}'"
	echo "${NAME}" 1>> /etc/ftpusers
      }
    fi
  done
  return
} # create_ftpusers()
################################################################################
function set_failure_limits() {
  # from system-hardening-10.2.txt (modified)
  # the UID_MIN and UID_MAX values are from /etc/login.defs
  # disables user accounts after 10 failed logins
  #
  # TODO: periodic
  # TODO: how do we reset this after successful login?
  # NOTE: Debian has this under /usr/bin

  echo "${FUNCNAME}(): setting the maximum number of login failures for UIDs ${UID_MIN:-1000}-${UID_MAX:-60000} to ${FAILURE_LIMIT:-10}"

  # NOTE: from FAILLOG(8): "The maximum failure count should always be 0 for root to prevent a denial of services attack against the system."
  # TODO: for important user accounts, the limits should be -l $((60*10)) -m 1
  #       this makes the account to temporary lock for n seconds.

  # this if is because of some bug/feature in shadow suite. if the database file is of zero size, for some reason it doesn't work with one command:
  #   # ls -l /var/log/faillog 
  #   -rw-r--r-- 1 root root 0 Oct  5 00:03 /var/log/faillog
  #   # faillog -l 300 -m 1 -u root
  #   # faillog -u root
  #   Login       Failures Maximum Latest                   On
  #   
  #   root            0        1   01/01/70 02:00:00 +0200  
  #   # faillog -l 300 -m 1 -u root
  #   # faillog -u root
  #   Login       Failures Maximum Latest                   On
  #   
  #   root            0        1   01/01/70 02:00:00 +0200   [300s lock]
  #
  # the bug/feature exists somewhere inside the set_locktime_one() function of lastlog.c ... probably

  if [ -s /var/log/faillog ]
  then
    faillog -l $((60*5)) -m 1 -u root
  else
    faillog -m 1 -u root
    faillog -l $((60*5)) -u root
  fi
  faillog -a -l 0 -m ${FAILURE_LIMIT:-10} -u ${UID_MIN:-1000}-${UID_MAX:-60000}
  return ${?}
} # set_failure_limits()
################################################################################
function miscellaneous_settings() {
  # NOTES:
  #   - it is recommended to run file_permissions() after this function
  #     this function might create some files that don't have secure file permissions
  #
  # TODO:
  #   - tcp_diag module to rc.modules

  # CIS 7.4 Prevent X Server From Listening On Port 6000/tcp (kinda the same)
  #if [ -f "/usr/bin/startx" ]
  #then
  #  sed -i 's/^defaultserverargs=""$/defaultserverargs="-nolisten tcp"/' /usr/bin/startx
  #fi
  if [ -d /etc/X11/xinit ] && [ ! -f /etc/X11/xinit/xserverrc ]
  then
    # from http://docs.slackware.com/howtos:security:basic_security#x_-nolisten_tcp
    cat 0<<-EOF 1>/etc/X11/xinit/xserverrc
	#!/bin/sh

	exec /usr/bin/X -nolisten tcp
EOF
  fi

  # this is done so the CIS_Apache_v2_1.audit works with Nessus
  # "CIS Recommends removing the default httpd.conf and
  # creating an empty one in /usr/local/apache2/conf."
  #
  # http://www.nessus.org/plugins/index.php?view=single&id=21157
  #
  # NOTE: disabled for now
  #
  # TODO: we need to add a check if apache is even installed
  #mkdir -m 755 -v /usr/local/apache2 && {
  #  ln -sv /etc/httpd /usr/local/apache2/conf
  #  ln -sv /var/log/httpd /usr/local/apache2/logs
  #}

  # END OF CIS

  ##############################################################################
  # from system-hardening-10.2.txt:
  ##############################################################################

  # Account processing is turned on by /etc/rc.d/rc.M.  However, the log file
  # doesn't exist.
  if [ ! -f /var/log/pacct ]
  then
    touch /var/log/pacct
    {
      chgrp -c adm /var/log/pacct
      chmod -c 640 /var/log/pacct
    } | tee -a "${logdir}/file_perms.txt"
  fi

  # man 1 xfs
  if [ -f "/etc/X11/fs/config" ]
  then
    sed -i 's/^use-syslog = off$/use-syslog = on/' /etc/X11/fs/config
  fi

  if [ -f "/etc/X11/xdm/Xservers" ]
  then
    sed -i 's/^:0 local \/usr\/bin\/X :0\s*$/:0 local \/usr\/bin\/X -nolisten tcp/' /etc/X11/xdm/Xservers
  fi

  ##############################################################################
  # </system-hardening-10.2.txt>
  ##############################################################################

  # make installpkg store the MD5 checksums
  sed -i 's/^\(MD5SUM\)=0$/\1=1/' /sbin/installpkg

  # NOTE: according to slack14.0 CHANGES_AND_HINTS.TXT, blacklist.conf is a
  #       "stale" file.
  #grep -q "^blacklist ipv6$" /etc/modprobe.d/blacklist.conf 2>/dev/null
  #if [ ${?} -ne 0 ]
  #then
  #  echo "# Disable IPv6" 1>>/etc/modprobe.d/blacklist.conf
  #  echo "blacklist ipv6" 1>>/etc/modprobe.d/blacklist.conf
  #fi

  # disable killing of X with Ctrl+Alt+Backspace
  if [ -d /etc/X11/xorg.conf.d ]
  then
    cat 0<<-EOF 1>/etc/X11/xorg.conf.d/99-dontzap.conf
	Section "ServerFlags"
		Option "DontZap" "true"
	EndSection
EOF
#    cat 0<<-EOF 1>/etc/X11/xorg.conf.d/99-cve-2012-0064.conf
#	# see CVE-2012-0064:
#	#   http://seclists.org/oss-sec/2012/q1/191
#	#   http://article.gmane.org/gmane.comp.security.oss.general/6747
#	#   https://bugs.gentoo.org/show_bug.cgi?id=CVE-2012-0064
#	#   http://security-tracker.debian.org/tracker/CVE-2012-0064
#	#   http://packetstormsecurity.org/files/cve/CVE-2012-0064
#	#   http://www.x.org/archive/X11R6.8.1/doc/Xorg.1.html
#	#   http://gu1.aeroxteam.fr/2012/01/19/bypass-screensaver-locker-program-xorg-111-and-up/
#	#   http://who-t.blogspot.com/2012/01/xkb-breaking-grabs-cve-2012-0064.html
#	#   https://lwn.net/Articles/477062/
#	Section "ServerFlags"
#		Option "AllowDeactivateGrabs"	"false"
#		Option "AllowClosedownGrabs"	"false"
#	EndSection
#EOF
  fi

  [ -f /etc/X11/app-defaults/XScreenSaver ] && {
    true
    # TODO: newLoginCommand
  }

  [ -f /etc/X11/xdm/Xresources ] && {
    #echo "xlogin*unsecureGreeting: This is an unsecure session" 1>>/etc/X11/xdm/Xresources
    #echo "xlogin*allowRootLogin: false" 1>>/etc/X11/xdm/Xresources
    true
  }

  # https://www.linuxquestions.org/questions/slackware-14/how-to-activate-bootlogd-918962/
  if [ ! -f /var/log/boot ]
  then
    touch /var/log/boot
    {
      chown -c root:adm	/var/log/boot
      chmod -c 640	/var/log/boot
    } | tee -a "${logdir}/file_perms.txt"
  fi

  # Debian specific
  # http://wiki.debian.org/bootlogd
  if [ -f /etc/debian_version ]
  then
    echo "BOOTLOGD_ENABLE=yes" 1>>/etc/default/bootlogd
  fi

  # make run-parts print "$SCRIPT failed." to stderr, so cron can mail this info to root.
  sed -i 's/\(echo "\$SCRIPT failed."\)$/\1 1>\&2/' /usr/bin/run-parts

  return 0
} # miscellaneous settings()
################################################################################
function remove_shells() {
  # see SHELLS(5)
  #
  # NOTES:
  #   - /bin/csh -> tcsh*
  #   - the entries in /etc/shells should be checked periodically, since the
  #     entries are added dynamically from doinst.sh scripts
  local SHELL_TO_REMOVE

  echo "${FUNCNAME}(): removing unnecessary shells"

  # tcsh csh ash ksh zsh	from Slackware
  # es rc esh dash screen	from Debian
  for SHELL_TO_REMOVE in \
    tcsh csh ash ksh zsh \
    es rc esh dash screen
  do
    sed -i '/^\/bin\/'"${SHELL_TO_REMOVE}"'$/d'		/etc/shells
    # for Debian
    sed -i '/^\/usr\/bin\/'"${SHELL_TO_REMOVE}"'$/d'	/etc/shells
  done

  # this is so that we can use this on other systems too...
  if [ -x /sbin/removepkg ]
  then
    for SHELL_TO_REMOVE in tcsh ash ksh93 zsh
    do
      /sbin/removepkg "${SHELL_TO_REMOVE}" 2>/dev/null
    done | tee -a "${logdir}/removed_packages.txt"
  fi

  # see "RESTRICTED SHELL" on BASH(1)
  if [ ! -h /bin/rbash ]
  then
    echo "${FUNCNAME}(): creating rbash link for restricted bash"
    pushd /bin
    ln -sv bash rbash && useradd -D -s /bin/rbash
    popd
  elif [ -h /bin/rbash ]
  then
    useradd -D -s /bin/rbash
  fi

  create_environment_for_restricted_shell

  # add rbash to shells
  # NOTE: restricted shells shouldn't be listed in /etc/shells!!!
  # see man pages su & chsh, plus chsh.c for reasons why...
  #
  # also, see http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=424672
  #grep -q "^/bin/rbash$" /etc/shells || {
  #  echo "adding rbash to shells"
  #  echo "/bin/rbash" 1>>/etc/shells
  #}

  return 0
} # remove_shells()
################################################################################
function configure_apache() {
  # TODO: under construction!!!
  #   - apply the patch file
  #
  # NOTES:
  #   - /var/www ownership and permissions are hardened from file_permissions()

  local -i RET=0
  local    PATCH_FILE="${APACHE_PATCH_FILE}"
  local    module

  [ ! -f "/etc/httpd/httpd.conf" ] && {
    echo "${FUNCNAME}(): warning: apache configuration file \`/etc/httpd/httpd.conf' does not exist, maybe apache is not installed. skipping this part."
    return 0
  }

  # disable modules with sed. this is because x86 vs. x86_64 configs differ,
  # and there's no sense in having two separate patch files.
  for module in ${apache_disable_modules_list[*]}
  do
    grep -q "^LoadModule ${module}" /etc/httpd/httpd.conf
    if [ ${?} -ne 0 ]
    then
      continue
    fi
    if [ "${module:(-1):1}" = "_" ]
    then
      echo "disabling apache modules \`${module}'"
    else
      echo "disabling apache module \`${module}'"
    fi
    sed -i '/^LoadModule '"${module}"'/s/^/#/' /etc/httpd/httpd.conf
  done

  [ ! -f "${PATCH_FILE}" ] && {
    echo "${FUNCNAME}(): error: apache hardening patch (\`${PATCH_FILE}') does not exist!" 1>&2
    return 1
  }

  check_and_patch /etc/httpd "${APACHE_PATCH_FILE}"	3

  /usr/sbin/apachectl configtest || {
    echo "${FUNCNAME}(): error: something wen't wrong!" 1>&2
    RET=1
  }

  # TODO: apachectl restart
  return ${RET}
} # configure_apache()
################################################################################
# TODO: rename this function
function disable_unnecessary_services() {
  # NOTES:
  #   - this should probably be run only on fresh installations
  #   - this relates to CIS 3.4 "Disable Standard Boot Services"

  # TODO:
  #   - support for sysvinit scripts
  local RC
  local WHILELISTED
  local service

  echo "${FUNCNAME}(): disabling and shutting down unnecessary services"

  # go through all the rc scripts
  shopt -s nullglob
  for RC in /etc/rc.d/rc.*
  do
    # there might also be directories...
    if [ ! -f "${RC}" ]
    then
      echo "${FUNCNAME}(): DEBUG: \`${RC}' is not a file -> skipping" 1>&2
      continue
    # leftovers from patch
    elif [ "${RC(-5):5}" = ".orig" ]
    then
      echo ".orig file -> skipping" 1>&2
      continue
    elif [ "${RC(-1):1}" = "~" ]
    then
      echo "tilde file -> skipping" 1>&2
      continue
    fi
    #echo "${FUNCNAME}(): DEBUG: processing \`${RC}'"
    # go through the whitelist
    for WHITELISTED in ${SERVICES_WHITELIST[*]}
    do
      # service is whitelisted, continue with the next $RC
      if [ "${RC}" = "${WHITELISTED}" ]
      then
        echo "${FUNCNAME}(): skipping whitelisted service: \`${RC}'"
        continue 2
      fi
    done
    #echo "${RC} -> NOT WHITELISTED"

    # if it's executable, it's probably running -> shut it down
    [ -x "${RC}" ] && sh "${RC}" stop

    # and then disable it
    /usr/bin/chmod -c 600 "${RC}" | tee -a "${logdir}/file_perms.txt"
  done

  # debian systemd
  if [ -x /bin/systemctl ]
  then
    for service in "avahi-daemon" "atd" "cups" "nfs-common" "exim4"
    do
      /bin/systemctl stop	"${service}"
      /bin/systemctl disable	"${service}"
    done
  fi

  echo "${FUNCNAME}(): enabling recommended services"

  # CIS 1.4 Enable System Accounting
  /usr/bin/chmod -c 700 "${SA_RC}" | tee -a "${logdir}/file_perms.txt"
  # make it store the data a bit longer =)
  sed -i 's/^\(HISTORY=\).*$/HISTORY=99999/' /etc/sysstat/sysstat

  # CIS 2.2 Configure TCP Wrappers and Firewall to Limit Access (applied)
  #
  # NOTE: the rc.firewall script should be created by the etc patch
  /usr/bin/chmod -c 700 /etc/rc.d/rc.firewall | tee -a "${logdir}/file_perms.txt"

  # inetd goes with the territory
  disable_inetd_services

  return 0
} # disable_unnecessary_services()
################################################################################
function create_limited_ca_list() {
  if [ ! -x /usr/sbin/update-ca-certificates ]
  then
    echo "${FUNCNAME}(): ERROR: update-ca-certificates not found!" 1>&2
    return 1
  fi
  if [ ! -f /etc/ca-certificates.conf.original ]
  then
    cp -v /etc/ca-certificates.conf /etc/ca-certificates.conf.original
  fi
  # Debian's ssl-cert package runs the make-ssl-cert and creates the snakeoil cert
  if [ -f /etc/ssl/certs/ssl-cert-snakeoil.pem ]
  then
    rm -v /etc/ssl/certs/ssl-cert-snakeoil.pem
  fi
  cat "${CWD}/newconfs/ca-certificates.conf.new" 1>/etc/ca-certificates.conf
  /usr/sbin/update-ca-certificates --verbose --fresh | tee "${logdir}/ca_certificates.txt"

  return
} # create_limited_ca_list()
################################################################################
function quick_harden() {
  # this function is designed to do only some basic hardening. so that it can
  # be used in other systems/version that are not directly supported by this
  # script.
  #
  # TODO: under construction

  # configure TCP wrappers
  grep -q "^ALL" /etc/hosts.deny
  if [ ${?} -ne 0 ]
  then
    echo "ALL: ALL EXCEPT localhost" 1>>/etc/hosts.deny
  fi

  # sysctl.conf
  if [ -f "${CWD}/newconfs/sysctl.conf.new" ]
  then
    if [ -d /etc/sysctl.d ] && [ ! -f /etc/sysctl.d/harden.conf ]
    then
      # for debian
      cat "${CWD}/newconfs/sysctl.conf.new" 1>/etc/sysctl.d/harden.conf
    else
      # slackware
      # TODO: add some check if it's already there.
      cat "${CWD}/newconfs/sysctl.conf.new" 1>>/etc/sysctl.conf
    fi
  else
    echo "WARNING: sysctl.conf.new not found!" 1>&2
  fi

  echo "ALL:ALL:DENY" >>/etc/suauth
  {
    chown -c root:root	/etc/suauth
    chmod -c 400	/etc/suauth
  } | tee -a "${logdir}/file_perms.txt"

  set_failure_limits

  create_ftpusers

  # tested 24.9.2012 against Debian
  remove_shells

  harden_fstab

  # enable sysstat in Debian
  if [ -f /etc/default/sysstat ]
  then
    sed -i 's/^ENABLED="false"$/ENABLED="true"/' /etc/default/sysstat
  fi

  create_limited_ca_list

  lock_system_accounts

  return
} # quick_harden()
################################################################################
function apply_newconfs() {
  local    newconf
  local    basename
  local    subdir
  local -a sha256sums

  pushd /etc 1>/dev/null || {
    echo "${FUNCNAME}(): error!" 1>&2
    return 1
  }
  shopt -s nullglob
  for subdir in . cron.d logrotate.d rc.d modprobe.d
  do
    for newconf in ${CWD}/newconfs/${subdir}/*.new
    do
      basename=$( basename "${newconf}" )
      # check if the file exists
      if [ ! -f "${subdir}/${basename%.new}" ]
      then
	# if not, move the .new into place
        echo "creating new file \`${subdir}/${basename%.new}'"
	cat "${newconf}" 1>"${subdir}/${basename%.new}"
      elif
	sha256sums=( $( sha256sum "${subdir}/${basename%.new}" "${newconf}" | awk '{print$1}' ) )
	[ "${sha256sums[0]}" != "${sha256sums[1]}" ]
      then
	echo "file \`${subdir}/${basename%.new}' exists. creating \`${subdir}/${basename}'."
	# leave the .new file for the admin to consider
	cat "${newconf}" 1>"${subdir}/${basename}"
      else
	echo "${FUNCNAME}(): DEBUG: file \`${subdir}/${basename%.new}' exists"
      fi
    done
  done
  popd 1>/dev/null
} # apply_newconfs()
################################################################################
function toggle_usb_authorized_default() {
  local host
  local state

  for host in /sys/bus/usb/devices/usb*
  do
    read state 0<"${host}/authorized_default"
    ((state^=1))
    if (( ${state} ))
    then
      echo "setting ${host} to authorized_default"
    else
      echo "setting ${host} to !authorized"
    fi
    echo "${state}" > ${host}/authorized_default
  done

  return 0
} # toggle_usb_authorized_default()
################################################################################
function configure_basic_auditing() {
  local -a stig_rules=()
  local    concat="/bin/cat"
  local    rules_exist=0
  local    dotnew=""

  if [ ! -x /sbin/auditctl ]
  then
    echo "${FUNCNAME}(): error: auditctl not found!" 1>&2
    return 1
  fi

  /sbin/auditctl -l | grep -q "^No rules$"
  if [ ${PIPESTATUS[1]} -ne 0 ]
  then
    echo "${FUNCNAME}(): notice: some rules exist already."
    rules_exist=1
    dotnew=".new"
  fi

  # Debian
  if [ -f /usr/share/doc/auditd/examples/stig.rules.gz ]
  then
    stig_rules[0]="/usr/share/doc/auditd/examples/stig.rules.gz"
    concat="/bin/zcat"
  # Slackware
  elif [ -f /etc/slackware-version ]
  then
    stig_rules=( /usr/doc/audit-*/contrib/stig.rules )
  # CentOS
  elif [ -f /etc/centos-release ]
  then
    stig_rules=( /usr/share/doc/audit-*/stig.rules )
  fi

  if [ ${#stig_rules[*]} -ne 1 ]
  then
    echo "${FUNCNAME}(): error: stig.rules not found!" 1>&2
    return 1
  elif [ ! -f ${stig_rules[0]} ]
  then
    echo "${FUNCNAME}(): error: stig.rules not found!" 1>&2
    return 1
  fi

  echo "${FUNCNAME}(): configuring basic auditing..."

  # backup old rules
  if [ -f /etc/audit/audit.rules ] && [ ! -f /etc/audit/audit.rules.old ]
  then
    cp -v /etc/audit/audit.rules /etc/audit/audit.rules.old
  fi

  # fix the audit.rules for Slackware:
  #   - Slackware does not have old passwords (opasswd)
  #   - Slackware does not have /etc/sysconfig/network
  #   - Enable auditing of lastlog
  #   - Enable auditing of faillog (change tallylog -> faillog, as we don't have PAM)
  #   - Enable session files logging ([ubw]tmp)
  #   - Enable kernel module logging
  ${concat} "${stig_rules[0]}" | sed \
    -e 's:^\(-w /etc/security/opasswd -p wa -k identity\)$:#\1:' \
    -e 's:^\(-w /etc/sysconfig/network -p wa -k system-locale\)$:#\1:' \
    -e 's:^#\(-w /var/log/lastlog -p wa -k logins\)$:\1:' \
    -e 's:^#\(-w /var/log/\)tallylog\( -p wa -k logins\)$:\1faillog\2:' \
    -e 's:^#\(-w /var/\(run\|log\)/[ubw]tmp -p wa -k session\)$:\1:' \
    -e 's:^#\(.*\(-k \|-F key=\)module.*\)$:\1:' \
    1>/etc/audit/audit.rules${dotnew}

  # fix the UID_MIN
  if [ -n "${UID_MIN}" ]
  then
    sed -i "s/auid>=500/auid>=${UID_MIN}/" /etc/audit/audit.rules${dotnew}
  fi

  # set the correct architecture
  if [[ ${ARCH} =~ ^i.86$ ]]
  then
    # disable x86_64 rules
    sed -i '/^-.*arch=b64/s/^/#/' /etc/audit/audit.rules${dotnew}
  elif [ "${ARCH}" = "x86_64" ]
  then
    # disable x86 rules
    sed -i '/^-.*arch=b32/s/^/#/' /etc/audit/audit.rules${dotnew}
  fi

  if (( ${rules_exist} ))
  then
    echo "${FUNCNAME}(): all done. some rule(s) existed, so you need to review the .new file, move it over and run \"/sbin/auditctl -R audit.rules\" manually."
    ls -l /etc/audit/audit.rules.new
  else
    /sbin/auditctl -R /etc/audit/audit.rules${dotnew}
  fi

  if [ -f /etc/rc.d/rc.auditd ]
  then
    chmod -c 700 /etc/rc.d/rc.auditd | tee -a "${logdir}/file_perms.txt"
  elif [ -x /bin/systemctl ]
  then
    /bin/systemctl enable auditd
  fi

  # enable it in grub/lilo
  if [ -f /etc/default/grub ] && ! grep -q '^GRUB_CMDLINE_LINUX=".*audit=1' /etc/default/grub
  then
    #sed -i 's/^\(GRUB_CMDLINE_LINUX=".*\)"$/\1 audit=1"/' /etc/default/grub
    true
  elif [ -f /etc/lilo.conf ] && ! grep -q '^append=".*audit=1' /etc/lilo.conf
  then
    sed -i 's/^\(append=".*\)"$/\1 audit=1"/' /etc/lilo.conf
    echo "NOTICE: /etc/lilo.conf updated. you need to run \`lilo' to update the boot loader."
  fi
} # configure_basic_auditing()
################################################################################
function patch_sendmail() {
  # $1 = [reverse]

  local REV=""

  if [ ${#} -eq 1 ]
  then
    REV="${1}"
  fi

  if [ ! -d "/etc/mail" ]
  then
    echo "${FUNCNAME}(): error: sendmail config dir not found!" 1>&2
    return 1
  elif [ ! -d "${SENDMAIL_CF_DIR}" ]
  then
    echo "${FUNCNAME}(): error: no such directory \`${SENDMAIL_CF_DIR}'! you might not have the sendmail-cf package installed." 1>&2
    return 1
  elif [ ! -f "${SENDMAIL_CF_DIR}/${SENDMAIL_CONF_PREFIX}.mc" ]
  then
    echo "${FUNCNAME}(): error: no such file \`${SENDMAIL_CF_DIR}/${SENDMAIL_CONF_PREFIX}.mc'! you might not have the sendmail-cf package installed." 1>&2
    return 1
  fi

  check_and_patch /usr/share/sendmail "${SENDMAIL_PATCH_FILE}" 1 "${REV}" || {
    echo "${FUNCNAME}(): error!" 1>&2
    return 1
  }
  pushd ${SENDMAIL_CF_DIR} || {
    echo "${FUNCNAME}(): error!" 1>&2
    return 1
  }
  # build the config
  sh ./Build "./${SENDMAIL_CONF_PREFIX}.mc" || {
    echo "${FUNCNAME}(): error: error while building the sendmail config!" 1>&2
    popd
    return 1
  }
  if [ ! -f "/etc/mail/sendmail.cf.bak" ]
  then
    cp -v /etc/mail/sendmail.cf /etc/mail/sendmail.cf.bak
  fi
  cp -v "./${SENDMAIL_CONF_PREFIX}.cf" /etc/mail/sendmail.cf
  popd

  # don't reveal the sendmail version
  # no patch file for single line! =)
  sed -i 's/^smtp\tThis is sendmail version \$v$/smtp\tThis is sendmail/' /etc/mail/helpfile

  # if sendmail is running, restart it
  if [ -f "/var/run/sendmail.pid" ] && [ -x "/etc/rc.d/rc.sendmail" ]
  then
    /etc/rc.d/rc.sendmail restart
  fi

  return 0
} # patch_sendmail()
################################################################################
function usage() {
  cat 0<<-EOF
	harden.sh -- system hardening script for slackware linux

	usage: ${0} options

	options:

	  -a		apache
	  -A		all
	  		  - hardens user accounts
	  		  - removes unnecessary packages
	  		  - removes unnecessary shells
	  		  - imports PGP keys
	  		  - applies the etc hardening patch
	  		  - applies the sudoers hardening patch
	  		  - applies the SSH hardening patch
	  		  - disables unnecessary services
	  		  - miscellaneous_settings()
	  		  - hardens file permissions
	  		  - creates hardened fstab.new
	  -b		toggle USB authorized_default
	  -c		create limited CA conf
	  -d		default hardening (misc_settings() & file_permissions())

	  -f		file permissions
	  -F		create/update /etc/ftpusers
	  -g		import Slackware, SBo & other PGP keys to trustedkeys.gpg keyring
	        	(you might also want to run this as a regular user)
	  -h		this help
	  -i		disable inetd services
	  -l		set failure limits (faillog) (default value: ${FAILURE_LIMIT:-10})
	  -L user	lock account 'user'
	  -m		miscellaneous (TODO: remove this? default handles all this)
	  -M		fstab hardening (nodev, nosuid & noexec stuff)

	  patching:

	    -p patch	apply   hardening patch for [patch]
	    -P patch	reverse hardening patch for [patch]

	    available patches:
	      ssh
	      etc
	        the etc patch assumes that you have at least the following packages installed:
	          network-scripts
	          sysvinit-scripts
	          etc
	          shadow
	          logrotate
	          sysklogd
	      apache
	      sendmail
	      php
	      sudoers
	      wipe **HIGHLY EXPERIMENTAL AND DANGEROUS**

	  -q	"quick harden" - just some generic stuff that should work on any system
	  	  - creates a deny all TCP wrappers rule
	  	  - creates sysctl.conf
	  	  - configures /etc/suauth to disallow the use of su
	  	  - sets failure limits
	  	  - creates ftpusers
	  	  - removes unnecessary shells
	  	  - creates hardened fstab.new
		  - creates limited CA list
		  - lock system accounts
	  -r	remove unnecessary shells
	  -s	disable unnecessary services (also enables few recommended ones)
	  -S	configure basic auditing using the stig.rules
	  -u	harden user accounts
	  -U	create additional user accounts (SBo related)
EOF
  # print functions
  #declare -f 2>/dev/null | sed -n '/^.* () $/s/^/  /p'
  exit 0
} # usage()
################################################################################

if [ "${USER}" != "root" ]
then
  echo -e "warning: you should probably be root to run this script\n" 1>&2
fi

while getopts "aAbcdfFghilL:mMp:P:qrsSuU" OPTION
do
  case "${OPTION}" in
    "a") configure_apache		;;
    "A")
      # this is intended to be a all-in-one parameter
      # that you can use on fresh installations

      # NOTES on ordering:
      #   - disabled_unnecessary_services AFTER patch_etc (rc.firewall for instance)

      #configure_apache
      user_accounts
      remove_packages
      remove_shells
      import_pgp_keys
      check_and_patch /etc	"${ETC_PATCH_FILE}"	1 && ETC_CHANGED=1
      apply_newconfs
      check_and_patch /etc	"${SUDOERS_PATCH_FILE}"	1
      check_and_patch /etc	"${SSH_PATCH_FILE}"	1

      # this should be run after patching etc,
      # there might be new rc scripts.
      disable_unnecessary_services

      miscellaneous_settings

      # these should be the last things to run
      file_permissions

      harden_fstab
      configure_basic_auditing

      # TODO: after restarting syslog,
      # there might be new log files with wrong permissions.
      (( ${ETC_CHANGED} )) && restart_services
    ;;
    "b") toggle_usb_authorized_default	;;
    "c") create_limited_ca_list		;;
    "d")
      # default
      miscellaneous_settings
      file_permissions
    ;;
    "f") file_permissions		;;
    "F") create_ftpusers		;;
    "g") import_pgp_keys		;;
    "h")
      usage
      exit 0
    ;;
    "i") disable_inetd_services		;;
    "l") set_failure_limits		;;
    "L") lock_account "${OPTARG}"	;;
    "m")
      # TODO: remove?
      miscellaneous_settings
    ;;
    "M") harden_fstab			;;
    "p")
      case "${OPTARG}" in
	"ssh")
	  # CIS 1.3 Configure SSH
	  check_and_patch /etc "${SSH_PATCH_FILE}" 1 && \
            [ -f "/var/run/sshd.pid" ] && [ -x "/etc/rc.d/rc.sshd" ] && \
	      /etc/rc.d/rc.sshd restart
	;;
	"etc") check_and_patch /etc "${ETC_PATCH_FILE}" 1 && ETC_CHANGED=1 ;;
        "apache") check_and_patch /etc/httpd "${APACHE_PATCH_FILE}" 3 ;;
	"sendmail")
          patch_sendmail
	;;
	"php") check_and_patch /etc/httpd php_harden.patch 1 ;;
        "sudoers")
          check_and_patch /etc	"${SUDOERS_PATCH_FILE}"	1
        ;;
	"wipe")
	  check_and_patch /etc wipe.patch 1
	  {
	    chmod -c 700 /etc/rc.d/rc.{2,5}
	    chmod -c 700 /etc/rc.d/rc5.d/KluksHeaderRestore.sh
	    chmod -c 700 /etc/rc.d/rc.sysvinit
	  } | tee -a "${logdir}/file_perms.txt"
	  init q
	;;
	*) echo "error: unknown patch \`${OPTARG}'!" 1>&2 ;;
      esac
    ;;
    "P")
      # reverse a patch
      case "${OPTARG}" in
	"ssh")
	  check_and_patch /etc "${SSH_PATCH_FILE}" 1 reverse && \
	    [ -f "/var/run/sshd.pid" ] && [ -x "/etc/rc.d/rc.sshd" ] && \
	      /etc/rc.d/rc.sshd restart
	;;
	"etc") check_and_patch /etc "${ETC_PATCH_FILE}" 1 reverse && ETC_CHANGED=1	;;
        "apache") check_and_patch /etc/httpd "${APACHE_PATCH_FILE}" 3 reverse		;;
        "sendmail") patch_sendmail reverse						;;
	"php") check_and_patch /etc/httpd php_harden.patch 1 reverse			;;
        "sudoers")
          check_and_patch /etc	"${SUDOERS_PATCH_FILE}"	1 reverse
        ;;
	"wipe")
	  check_and_patch /etc wipe.patch 1 reverse
	  init q
	;;
	*)     echo "error: unknown patch \`${OPTARG}'!" 1>&2				;;
      esac
    ;;
    "q") quick_harden			;;
    "r") remove_shells			;;
    "s") disable_unnecessary_services	;;
    "S") configure_basic_auditing	;;
    "u") user_accounts			;;
    "U") create_additional_user_accounts ;;
  esac
done

shopt -s nullglob
logfiles=( ${logdir}/* )
if [ ${#logfiles[*]} -eq 0 ]
then
  echo "no log files created. removing dir."
  rmdir -v "${logdir}"
else
  echo "logs available at: ${logdir}"
fi

exit 0
