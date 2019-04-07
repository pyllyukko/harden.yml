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
for file in sysstat.sh utils.sh pam.sh apparmor.sh gpg.sh banners.sh ssh.sh slackware.sh user_accounts.sh
do
  . ${CWD}/libexec/${file} || {
    echo "[-] couldn't find libexec/${file}" 1>&2
    exit 1
  }
done
unset file
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

# determine distro
if [ -f /etc/os-release ]
then
  DISTRO=$( sed -n '/^ID=/s/^ID=//p' /etc/os-release )
fi
# these are not declared as integers cause then the ${ ... :-DEFAULT } syntax won't work(?!)
declare -r UID_MIN=$(		awk '/^UID_MIN/{print$2}'	/etc/login.defs 2>/dev/null )
declare -r UID_MAX=$(		awk '/^UID_MAX/{print$2}'	/etc/login.defs 2>/dev/null )
declare -r SYS_UID_MAX=$(	awk '/^SYS_UID_MAX/{print$2}'	/etc/login.defs 2>/dev/null )
declare -r WWWROOT="/var/www"
declare -i ETC_CHANGED=0
declare -r RBINDIR="/usr/local/rbin"
declare -r INETDCONF="/etc/inetd.conf"
declare -r CADIR="/usr/share/ca-certificates/local"
declare -r SKS_CA="sks-keyservers.netCA.pem"
declare -a NAMES=( $( cut -d: -f1 /etc/passwd ) )
declare    LYNIS_TESTS=1
if ! hash lynis
then
  LYNIS_TESTS=0
fi
auditPATH='/etc/audit'
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
# TODO: http://wiki.apparmor.net/index.php/Distro_debian#Tuning_logs
declare -rA AUDITD_CONFIG=(
  ["space_left_action"]="email"
  ["action_mail_acct"]="root"
  ["max_log_file_action"]="keep_logs"
)
declare -rA LIGHTDM_CONFIG=(
  ["greeter-hide-users"]="true"
  # https://freedesktop.org/wiki/Software/LightDM/CommonConfiguration/#disablingguestlogin
  ["allow-guest"]="false"
)
declare -rA FILE_PERMS=(
  ["/boot/grub/grub.cfg"]="og-rwx"
  ["/etc/ssh/sshd_config"]="600"
  ["/etc/ssh/ssh_config"]="644"
  ["/etc/lilo.conf"]="600"
  ["/root/.ssh"]="700"
)

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
  echo "[-] warning: can't find nologin!" 1>&2
  DENY_SHELL=
fi
# man FAILLOG(8)
declare -i FAILURE_LIMIT=5
declare -r CERTS_DIR="/etc/ssl/certs"

# from CIS 2.1 Disable Standard Services
declare -a INETD_SERVICES=(echo discard daytime chargen time ftp telnet comsat shell login exec talk ntalk klogin eklogin kshell krbupdate kpasswd pop imap uucp tftp bootps finger systat netstat auth netbios swat rstatd rusersd walld)

# ...plus some extras
INETD_SERVICES+=(pop3 imap2 netbios-ssn netbios-ns)

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
function read_password_policy() {
  check_for_conf_file "/etc/login.defs" || return 1
  PASS_MIN_DAYS=$( awk '/^PASS_MIN_DAYS/{print$2}' /etc/login.defs 2>/dev/null )
  PASS_MAX_DAYS=$( awk '/^PASS_MAX_DAYS/{print$2}' /etc/login.defs 2>/dev/null )
  PASS_WARN_AGE=$( awk '/^PASS_WARN_AGE/{print$2}' /etc/login.defs 2>/dev/null )
  if [ -z "${PASS_MIN_DAYS}" -o -z "${PASS_MAX_DAYS}" -o -z "${PASS_WARN_AGE}" ]
  then
    echo "[-] warning: couldn't determine PASS_* from /etc/login.defs"
    return 1
  fi
} # read_password_policy()
################################################################################
function disable_inetd_services() {
  # CIS 2.1 Disable Standard Services
  local SERVICE

  print_topic "disabling inetd services"

  check_for_conf_file "${INETDCONF}" || return 1

  if [ ! -f "${INETDCONF}.original" ]
  then
    cp -v "${INETDCONF}" "${INETDCONF}.original"
  fi

  echo -n "modifying ${INETDCONF} (${#INETD_SERVICES[*]} services)"
  for SERVICE in ${INETD_SERVICES[*]}
  do
    sed -i 's/^\('"${SERVICE}"'\)/\#\1/' "${INETDCONF}"
    echo -n '.'
  done
  echo -n $'\n'

  return
} # disable_inetd_services()
################################################################################
function create_environment_for_restricted_shell () {
  local PRG

  print_topic "populating ${RBINDIR}"

  if [ ! -d "${RBINDIR}" ]
  then
    mkdir -pv "${RBINDIR}"
  fi
  {
    chown -c root:root	"${RBINDIR}"
    chmod -c 755	"${RBINDIR}"
  } | tee -a "${logdir}/file_perms.txt"

  #rm -v "${RBINDIR}/"*

  pushd "${RBINDIR}" 1>/dev/null || return 1

  for PRG in /bin/{cat,cp,df,du,id,ls,mkdir,mv,uname,who} /usr/bin/{chage,passwd,printenv,uptime}
  do
    ln -sv ${PRG}
  done
  ln -sv /usr/bin/vim	rvim
  ln -sv /usr/bin/view	rview

  popd 1>/dev/null

  return
} # create_environment_for_restricted_shell()
################################################################################
function restrict_cron() {
  print_topic "restricting use of cron & at"
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
  #
  # TODO: check whether debian, red hat etc. bring empty /etc/at.deny with the package
  if [ -s "/etc/at.deny" ] && [ ! -f "/etc/at.allow" ]
  then
    echo "[+] restricting the use of at"
    rm -v		/etc/at.deny
    /usr/bin/touch	/etc/at.allow
    {
      chown -c root:daemon	/etc/at.allow
      chmod -c 640		/etc/at.allow
    } | tee -a "${logdir}/file_perms.txt"
  fi

  echo "[+] restricting the use of cron"
  # dcron
  if /usr/sbin/crond -h 2>/dev/null | grep -q ^dillon
  then
    {
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
    } | tee -a "${logdir}/file_perms.txt"
  else
    rm -v		/etc/cron.deny
    /usr/bin/touch	/etc/cron.allow
    if getent group crontab 1>/dev/null
    then
      {
	chown -c root:crontab	/etc/cron.allow
	chmod -c 640		/etc/cron.allow
      } | tee -a "${logdir}/file_perms.txt"
    else
      chmod -c og-rwx /etc/cron.allow | tee -a "${logdir}/file_perms.txt"
    fi
  fi
  echo "[+] restricting /etc/cron{tab,.hourly,.daily,.weekly,.monthly,.d}"
  chmod -c og-rwx /etc/cron{tab,.hourly,.daily,.weekly,.monthly,.d} | tee -a "${logdir}/file_perms.txt"

  return 0
} # restrict_cron()
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

  print_topic "hardening mount options in fstab"

  if [ ! -w /etc ]
  then
    echo "[-] error: /etc is not writable. are you sure you are root?" 1>&2
    return 1
  fi
  check_for_conf_file "/etc/fstab" || return 1
  make -f ${CWD}/Makefile /etc/fstab.new

  if [ -f /etc/fstab.new ]
  then
    echo "[+] /etc/fstab.new created"
  fi

  # there's no point in doing the comparison, but we'll print the score anyway
  (( ${LYNIS_TESTS} )) && {
    local LYNIS_SCORE=$( get_lynis_hardening_index filesystems )
    echo "[*] Lynis score: ${LYNIS_SCORE}"
  }

  return ${?}
} # harden_fstab()
################################################################################
function file_permissions2() {
  local FILE
  print_topic "hardening file permissions"
  (( ${LYNIS_TESTS} )) && local LYNIS_SCORE_BEFORE=$( get_lynis_hardening_index file_permissions )
  # new RH/Debian safe file permissions function
  {
    for FILE in ${!FILE_PERMS[*]}
    do
      if [ -f "${FILE}" -o -d "${FILE}" ]
      then
	chmod -c ${FILE_PERMS[${FILE}]} ${FILE}
      fi
    done
  } | tee -a "${logdir}/file_perms.txt"
  (( ${LYNIS_TESTS} )) && {
    local LYNIS_SCORE_AFTER=$( get_lynis_hardening_index file_permissions )
    compare_lynis_scores "${LYNIS_SCORE_BEFORE}" "${LYNIS_SCORE_AFTER}"
    # TODO: authentication & boot_services is not run in the above invocation
    check_lynis_tests FILE-7524 AUTH-9252 BOOT-5184
  }
} # file_permissions2()
################################################################################
function enable_bootlog() {
  print_topic "enabling bootlog"
  # https://www.linuxquestions.org/questions/slackware-14/how-to-activate-bootlogd-918962/
  if [ ! -f /var/log/boot ]
  then
    echo '[+] creating /var/log/boot'
    touch /var/log/boot
    {
      chown -c root:adm	/var/log/boot
      chmod -c 640	/var/log/boot
    } | tee -a "${logdir}/file_perms.txt"
  fi
} # enable_bootlog()
################################################################################
function remove_shells() {
  # see SHELLS(5)
  #
  # NOTES:
  #   - /bin/csh -> tcsh*
  #   - the entries in /etc/shells should be checked periodically, since the
  #     entries are added dynamically from doinst.sh scripts
  local SHELL_TO_REMOVE

  print_topic "removing unnecessary shells"

  # tcsh csh ash ksh zsh	from Slackware
  # es rc esh dash screen	from Debian
  for SHELL_TO_REMOVE in \
    tcsh csh ash ksh zsh \
    es rc esh dash screen
  do
    fgrep -q "/${SHELL_TO_REMOVE}" /etc/shells && {
      echo "[+] removing ${SHELL_TO_REMOVE}"
      sed_with_diff '/^\/\(usr\/\)\?bin\/'"${SHELL_TO_REMOVE}"'$/d' /etc/shells
    }
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
    echo "[+] creating rbash link for restricted bash"
    pushd /bin
    ln -sv bash rbash && useradd -D -s /bin/rbash
    popd
  elif [ -h /bin/rbash ]
  then
    useradd -D -s /bin/rbash
  fi

  # Debian
  # don't use dash as the default shell
  # there's some weird bug when using PAM's polyinstation
  if [ -x /usr/bin/debconf-set-selections -a \
       -x /usr/sbin/dpkg-reconfigure ]
  then
    echo '[+] dash!=bash'
    echo 'dash    dash/sh boolean false' | debconf-set-selections -v
    dpkg-reconfigure -f noninteractive dash
  fi

  # add rbash to shells
  # NOTE: restricted shells shouldn't be listed in /etc/shells!!!
  # see man pages su & chsh, plus chsh.c for reasons why...
  #
  # also, see http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=424672
  #grep -q "^/bin/rbash$" /etc/shells || {
  #  echo "adding rbash to shells"
  #  echo "/bin/rbash" 1>>/etc/shells
  #}

  create_environment_for_restricted_shell

  return 0
} # remove_shells()
################################################################################
function disable_unnecessary_systemd_services() {
  local service

  print_topic "disabling unnecessary systemd services"
  if [ ! -x /bin/systemctl ]
  then
    echo '[-] /bin/systemctl not found!' 1>&2
    return 1
  fi
  for service in \
    atd          \
    avahi-daemon \
    bind9        \
    bluetooth    \
    cups         \
    exim4        \
    hciuart      \
    ifup@wlan0   \
    nfs-common   \
    vsftpd
  do
    if /bin/systemctl is-enabled "${service}" 1>/dev/null
    then
      /bin/systemctl stop	"${service}"
    fi
    /bin/systemctl disable	"${service}"
  done

  if [ -f /etc/xdg/autostart/zeitgeist-datahub.desktop ]
  then
    true
  fi
  # TODO: apt-get remove zeitgeist-datahub zeitgeist-core xul-ext-ubufox
} # disable_unnecessary_systemd_services()
################################################################################
function gnome_settings() {
  # Settings -> Privacy -> Usage & History -> Recently Used
  gsettings set org.gnome.desktop.privacy remember-recent-files false
  gsettings set org.gnome.desktop.privacy recent-files-max-age  1
  # TODO: Clear Recent History
  gsettings set org.gnome.system.location enabled false

  # https://wiki.gnome.org/Projects/Tracker/
  # in addition to this, you might want to run "tracker reset --hard"
  # "Monitor file and directory changes"
  gsettings set org.freedesktop.Tracker.Miner.Files enable-monitors false
  # "Index content of files found"
  gsettings set org.freedesktop.Tracker.FTS max-words-to-index 0
  # "Enable when running on battery"
  gsettings set org.freedesktop.Tracker.Miner.Files index-on-battery false

  shopt -s nullglob
  # this still leaves tracker-store, which is started from D-Bus.
  for file in /etc/xdg/autostart/tracker-*.desktop
  do
    if ! grep '^Hidden=true$' "${file}"
    then
      sed_with_diff '$a Hidden=true' "${file}"
    fi
  done
} # gnome_settings()
################################################################################
function create_limited_ca_list() {
  local -i ret
  print_topic "Hardening trusted CA certificates"
  if [ ! -x /usr/sbin/update-ca-certificates ]
  then
    echo "[-] ERROR: update-ca-certificates not found!" 1>&2
    return 1
  fi
  check_for_conf_file "/etc/ca-certificates.conf" || return 1
  if [ ! -f /etc/ca-certificates.conf.original ]
  then
    cp -v /etc/ca-certificates.conf /etc/ca-certificates.conf.original
  fi
  # Debian's ssl-cert package runs the make-ssl-cert and creates the snakeoil cert
  if [ -f /etc/ssl/certs/ssl-cert-snakeoil.pem ]
  then
    rm -v /etc/ssl/certs/ssl-cert-snakeoil.pem
  fi
  make -f ${CWD}/Makefile /etc/ssl/certs/ca-certificates.crt | tee "${logdir}/ca_certificates.txt"
  ret=${PIPESTATUS[0]}

  return ${ret}
} # create_limited_ca_list()
################################################################################
function sysctl_harden() {
  print_topic "applying sysctl hardening"
  (( ${LYNIS_TESTS} )) && local LYNIS_SCORE_BEFORE=$( get_lynis_hardening_index kernel_hardening )
  if [ -f "${CWD}/newconfs/sysctl.d/sysctl.conf.new" ]
  then
    if [ -d /etc/sysctl.d ]
    then
      # for debian
      echo "[+] writing to /etc/sysctl.d/harden.conf"
      make -f ${CWD}/Makefile /etc/sysctl.d/harden.conf
    else
      # slackware
      # TODO: add some check if it's already there.
      cat "${CWD}/newconfs/sysctl.conf.new" 1>>/etc/sysctl.conf
      echo "[+] written to /etc/sysctl.conf"
    fi
  else
    echo "[-] WARNING: sysctl.conf.new not found!" 1>&2
  fi
  /sbin/sysctl --system
  (( ${LYNIS_TESTS} )) && {
    local LYNIS_SCORE_AFTER=$( get_lynis_hardening_index kernel_hardening )
    compare_lynis_scores "${LYNIS_SCORE_BEFORE}" "${LYNIS_SCORE_AFTER}"
    check_lynis_tests KRNL-6000
  }
} # sysctl_harden()
################################################################################
function configure_tcp_wrappers() {
  print_topic "configuring TCP wrappers"
  if [ -f /etc/hosts.deny ]
  then
    if ! grep -q "^ALL" /etc/hosts.deny
    then
      echo '[+] writing to /etc/hosts.deny'
      sed_with_diff '$a ALL: ALL EXCEPT localhost' /etc/hosts.deny
    else
      echo '[-] "ALL" rule already exists in /etc/hosts.deny'
    fi
  else
    echo '[+] creating /etc/hosts.deny'
    echo "ALL: ALL EXCEPT localhost" 1>/etc/hosts.deny
  fi
} # configure_tcp_wrappers()
################################################################################
function quick_harden() {
  # this function is designed to do only some basic hardening. so that it can
  # be used in other systems/version that are not directly supported by this
  # script.
  #
  # TODO: under construction
  local func

  for func in \
    configure_tcp_wrappers               \
    sysctl_harden                        \
    configure_shells                     \
    harden_fstab                         \
    enable_sysstat                       \
    create_limited_ca_list               \
    configure_apt                        \
    configure_securetty                  \
    configure_pam                        \
    configure_core_dumps                 \
    disable_unnecessary_systemd_services \
    configure_sshd                       \
    configure_basic_auditing             \
    enable_bootlog                       \
    enable_apparmor                      \
    aa_enforce                           \
    user_accounts                        \
    set_usb_authorized_default           \
    configure_modprobe.d                 \
    disable_gdm3_user_list
  do
    ${func}
  done

  return
} # quick_harden()
################################################################################
function configure_modprobe.d() {
  local file
  print_topic "configuring modprobe"
  for file in "CIS.conf" "firewire.conf"
  do
    echo "[+] ${file}"
    make -f ${CWD}/Makefile /etc/modprobe.d/${file}
  done
} # configure_modprobe.d()
################################################################################
function set_usb_authorized_default() {
  print_topic "setting USB authorized_default -> 0"
  if [ "${DISTRO}" = "debian" -o "${DISTRO}" = "raspbian" ]
  then
    if [ -f /etc/rc.local ]
    then
      echo '[-] /etc/rc.local already exists (appending not implemented yet)'
      return 1
    else
      # this is launched by rc-local.service
      make -f ${CWD}/Makefile /etc/rc.local
    fi
  else
    echo '[-] this is only for Debian (for now)'
    return 1
  fi
} # set_usb_authorized_default()
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
function configure_basic_auditing() {
  local -a stig_rules=()
  local    concat="/bin/cat"
  local    rule_file

  print_topic "configuring basic auditing"

  if [ ! -x /sbin/auditctl ]
  then
    echo "[-] error: auditctl not found!" 1>&2
    return 1
  fi
  if [ ! -d /etc/audit/rules.d ]
  then
    echo "[-] error: rules directory \`/etc/audit/rules.d' does not exist!" 1>&2
    return 1
  fi

  # Debian
  if [ -f /usr/share/doc/auditd/examples/stig.rules.gz ]
  then
    stig_rules[0]="/usr/share/doc/auditd/examples/stig.rules.gz"
    concat="/bin/zcat"
  # Kali
  elif [ -f /usr/share/doc/auditd/examples/rules/30-stig.rules.gz ]
  then
    stig_rules[0]="/usr/share/doc/auditd/examples/rules/30-stig.rules.gz"
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
    echo "[-] error: stig.rules not found!" 1>&2
    return 1
  elif [ ! -f ${stig_rules[0]} ]
  then
    echo "[-] error: stig.rules not found!" 1>&2
    return 1
  fi

  # common for all distros
  #   - Enable auditing of lastlog
  #   - Enable session files logging ([ubw]tmp)
  #   - Add faillog auditing above lastlog
  #   - Enable kernel module logging
  #   - Enable auditing of tallylog
  #   - remove delete stuff (too excessive)
  ${concat} "${stig_rules[0]}" | sed \
    -e '/^#-w \/var\/log\/lastlog -p wa -k logins$/s/^#//' \
    -e '/^#-w \/var\/\(run\|log\)\/[ubw]tmp -p wa -k session$/s/^#//' \
    -e '/^-w \/var\/log\/lastlog -p wa -k logins$/i-w /var/log/faillog -p wa -k logins' \
    -e '/^#.*\(-k \|-F key=\)module.*$/s/^#//' \
    -e '/^#-w \/var\/log\/tallylog -p wa -k logins$/s/^#//' \
    -e '/^[^#].*-k delete/s/^/#/' \
    1>/etc/audit/rules.d/stig.rules
  # distro specific
  if [ "${DISTRO}" = "slackware" ]
  then
    # fix the audit.rules for Slackware:
    #   - Slackware does not have old passwords (opasswd)
    #   - Slackware does not have /etc/sysconfig/network
    #   - Slackware does not have pam_tally
    sed -i \
      -e '/^-w \/etc\/security\/opasswd -p wa -k identity$/s/^/#/' \
      -e '/^-w \/etc\/sysconfig\/network -p wa -k system-locale$/s/^/#/' \
      -e '/^-w \/var\/log\/tallylog -p wa -k logins$/s/^/#/' \
      /etc/audit/rules.d/stig.rules
  elif [ "${DISTRO}" = "debian" -o "${DISTRO}" = "raspbian" ]
  then
    # /etc/sysconfig/network -> /etc/network
    sed -i \
      -e 's:^-w /etc/sysconfig/network -p wa -k system-locale$:-w /etc/network -p wa -k system-locale:' \
      /etc/audit/rules.d/stig.rules
  fi

  # fix the UID_MIN
  if [ -n "${UID_MIN}" ]
  then
    sed -i "s/auid>=500/auid>=${UID_MIN}/" /etc/audit/rules.d/stig.rules
  fi

  # set the correct architecture
  # TODO: armv7l etc.?
  if [[ ${ARCH} =~ ^i.86$ ]]
  then
    # disable x86_64 rules
    sed -i '/^-.*arch=b64/s/^/#/' /etc/audit/rules.d/stig.rules
  #elif [ "${ARCH}" = "x86_64" ]
  #then
  #  # disable x86 rules
  #  sed -i '/^-.*arch=b32/s/^/#/' /etc/audit/rules.d/stig.rules
  fi

  # drop in few custom rules
  for rule_file in ld.so tmpexec
  do
    /bin/cat "${CWD}/newconfs/rules.d/${rule_file}.rules.new" 1>"/etc/audit/rules.d/${rule_file}.rules"
  done

  # create /etc/audit/audit.rules with augenrules
  /sbin/augenrules
  if [ -f /etc/audit/audit.rules.prev ]
  then
    echo "NOTICE: previous audit.rules existed and was copied to audit.rules.prev by augenrules:"
    ls -l /etc/audit/audit.rules.prev
  fi
  # read rules from file
  /sbin/auditctl -R /etc/audit/audit.rules

  # enable the service
  if [ -f /etc/rc.d/rc.auditd ]
  then
    chmod -c 700 /etc/rc.d/rc.auditd | tee -a "${logdir}/file_perms.txt"
  elif [ -x /bin/systemctl ]
  then
    /bin/systemctl enable auditd
  fi

  echo '[+] configuring auditd.conf'
  for setting in ${!AUDITD_CONFIG[*]}
  do
    # ^key = value$
    sed_with_diff "s/^\(# \?\)\?\(${setting}\)\(\s\+=\s\+\)\S\+$/\2\3${AUDITD_CONFIG[${setting}]}/" /etc/audit/auditd.conf
  done

  # enable it in grub/lilo
  if [ -f /etc/default/grub ] && ! grep -q '^GRUB_CMDLINE_LINUX=".*audit=1' /etc/default/grub
  then
    # example: https://wiki.debian.org/AppArmor/HowToUse#Enable_AppArmor
    sed_with_diff 's/^\(GRUB_CMDLINE_LINUX=".*\)"$/\1 audit=1"/' /etc/default/grub
    echo "NOTICE: /etc/default/grub updated. you need to run \`update-grub' or \`grub2-install' to update the boot loader."
  elif [ -f /etc/lilo.conf ] && ! grep -q '^append=".*audit=1' /etc/lilo.conf
  then
    sed_with_diff 's/^\(append=".*\)"$/\1 audit=1"/' /etc/lilo.conf
    echo "NOTICE: /etc/lilo.conf updated. you need to run \`lilo' to update the boot loader."
  # raspbian
  elif [ -f /boot/cmdline.txt ] && ! grep -q 'audit=1' /boot/cmdline.txt
  then
    sed_with_diff 's/$/ audit=1/' /boot/cmdline.txt
  fi
  # TODO: start auditd?
  (( ${LYNIS_TESTS} )) && {
    LYNIS_SCORE_AFTER=$( get_lynis_hardening_index accounting )
    check_lynis_tests ACCT-9628 ACCT-9630 ACCT-9632 ACCT-9634
  }
} # configure_basic_auditing()
################################################################################
function enable_pacct() {
  print_topic "enabling process accounting"
  if ! hash accton 2>/dev/null
  then
    echo "[-] process accounting not found!" 1>&2
    return 1
  fi
  # Account processing is turned on by /etc/rc.d/rc.M.  However, the log file
  # doesn't exist.
  if [ "${DISTRO}" = "slackware" -a ! -f /var/log/pacct ]
  then
    echo '[+] creating /var/log/pacct'
    make -f ${CWD}/Makefile /var/log/pacct
  elif [ -x /bin/systemctl ]
  then
    # TODO: CentOS / RH
    if systemctl is-enabled acct
    then
      echo '[+] process accounting already enabled'
    else
      systemctl enable acct && echo '[+] process accounting enabled via systemd' || '[-] failed to enable process accounting'
    fi
  fi
} # enable_pacct()
################################################################################
function usage() {
  cat 0<<-EOF
	harden.sh -- system hardening script for slackware linux

	usage: ${0} options

	options:

	  -a		apache
	  -A		all (for Slackware)
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

	  -f function	run a function. available functions:
	  		aa_enforce
	  		configure_apt
	  		configure_modprobe.d
	  		configure_pam
	  		configure_securetty
	  		configure_umask
	  		configure_shells
	  		configure_tcp_wrappers
	  		core_dumps
	  		create_banners
	  		disable_ipv6
	  		disable_unnecessary_systemd_services
	  		enable_apparmor
	  		enable_bootlog
	  		enable_sysstat
	  		file_permissions
	  		file_permissions2
	  		gnome_settings
	  		lock_system_accounts
	  		password_policies
	  		restrict_cron
	  		sshd_config
	  		ssh_config
	  		sysctl_harden
	  		homedir_perms
	  		disable_gdm3_user_list
	  		set_usb_authorized_default
	  		remove_shells
	  		create_ftpusers
	  		disable_inetd_services
	  		set_failure_limits
	  		harden_fstab (you can also run "make /etc/fstab.new")
	  		user_accounts
	  		configure_basic_auditing
	  		disable_unnecessary_services
	  		enable_pacct
	  -g		import Slackware, SBo & other PGP keys to trustedkeys.gpg keyring
	        	(you might also want to run this as a regular user)
	  -h		this help
	  -I		check Slackware installation's integrity from MANIFEST (owner & permission)
	  -L user	lock account 'user'
	  -m		miscellaneous (TODO: remove this? default handles all this)

	  patching:

	    -p patch	apply   hardening patch for [patch]
	    -P patch	reverse hardening patch for [patch]

	    available patches:
	      ssh
	      etc
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
	  -U	create additional user accounts (SBo related)

	Make targets:

	  /etc/ssh/moduli.new
	  /etc/ssh/ssh_host_{rsa,ecdsa,ed25519}_key
	  /etc/ssl/certs/ca-certificates.crt
	  /etc/securetty
	  /etc/fstab.new
	  manifest
EOF
  # print functions
  #declare -f 2>/dev/null | sed -n '/^.* () $/s/^/  /p'
  exit 0
} # usage()
################################################################################
function configure_securetty() {
  # https://www.debian.org/doc/manuals/securing-debian-howto/ch4.en.html#s-restrict-console-login
  local i
  print_topic "creating /etc/securetty"
  make -f ${CWD}/Makefile /etc/securetty
} # configure_securetty()
################################################################################
function configure_password_policies() {
  local policy

  print_topic "configuring password policies"

  check_for_conf_file "/etc/login.defs" || return 1

  for policy in ${!PASSWORD_POLICIES[*]}
  do
    printf "[+] %-20s -> %s\n" ${policy} ${PASSWORD_POLICIES[${policy}]}
    sed_with_diff "s/^\(# \?\)\?\(${policy}\)\(\s\+\)\S\+$/\2\3${PASSWORD_POLICIES[${policy}]}/" /etc/login.defs
  done

  #if [ -f /etc/libuser.conf ]
  #then
  #  # TODO: /etc/libuser.conf "crypt_style = sha512"
  #  true
  #fi

  # TODO: /etc/pam.d/common-password

  # red hat
  if [ -x /sbin/authconfig ]
  then
    # TODO: other settings
    echo '[+] configuring password policy via authconfig'
    authconfig          \
      --passalgo=sha512 \
      --passminlen=14   \
      --enablereqlower  \
      --enablerequpper  \
      --enablereqdigit  \
      --enablereqother  \
      --update
  # pwquality && !rh
  elif [ -f ${ROOTDIR:-/}etc/security/pwquality.conf ]
  then
    echo '[+] configuring pwquality'
    for setting in ${!PWQUALITY_SETTINGS[*]}
    do
      sed_with_diff "s/^\(# \?\)\?\(${setting}\)\(\s*=\s*\)\S\+$/\2\3${PWQUALITY_SETTINGS[${setting}]}/" "${ROOTDIR:-/}etc/security/pwquality.conf"
      if ! grep -q "^${setting}\s*=\s*${PWQUALITY_SETTINGS[${setting}]}$" ${ROOTDIR:-/}etc/security/pwquality.conf
      then
	echo "[-] failed to set ${setting}"
      fi
    done
  fi

  echo '[+] setting the default password inactivity period'
  useradd -D -f ${password_inactive}

  configure_password_policy_for_existing_users

  read_password_policy

  (( ${LYNIS_TESTS} )) && {
    LYNIS_SCORE_AFTER=$( get_lynis_hardening_index authentication )
    check_lynis_tests AUTH-9286
  }
} # configure_password_policies()
################################################################################
function disable_ipv6() {
  print_topic "disabling IPv6"
  if [ -f /etc/default/grub ] && ! grep -q '^GRUB_CMDLINE_LINUX=".*ipv6.disable=1' /etc/default/grub
  then
    echo '[+] configuring /etc/default/grub'
    sed_with_diff 's/^\(GRUB_CMDLINE_LINUX=".*\)"$/\1 ipv6.disable=1"/' /etc/default/grub
  # raspbian
  elif [ -f /boot/cmdline.txt ] && ! grep -q 'ipv6\.disable=1' /boot/cmdline.txt
  then
    echo '[+] configuring /boot/cmdline.txt'
    sed_with_diff 's/$/ ipv6.disable=1/' /boot/cmdline.txt
  fi
} # disable_ipv6()
################################################################################
function configure_iptables_persistent() {
  # TODO
  true
} # configure_iptables_persistent()
################################################################################
function enable_selinux() {
  # TODO
  true
} # enable_selinux()
################################################################################
function configure_apt() {
  local suite
  print_topic "disabling suggested packages in APT"
  if [ -d /etc/apt/apt.conf.d ]
  then
    echo '[+] creating /etc/apt/apt.conf.d/99suggested'
    echo 'APT::Install-Suggests "false";' 1>/etc/apt/apt.conf.d/99suggested
  else
    echo '[-] /etc/apt/apt.conf.d not found. maybe this is not Debian based host.'
  fi

  # configure suite for better results
  if [ -x /usr/bin/lsb_release -a -f /etc/default/debsecan ]
  then
    suite=$( lsb_release -c -s )
    if [ -n "${suite}" ]
    then
      echo '[+] configuring suite to /etc/default/debsecan'
      sed_with_diff "s/^SUITE=.*\$/SUITE=${suite}/" /etc/default/debsecan
    fi
  fi
} # configure_apt()
################################################################################
function disable_gdm3_user_list() {
  local setting
  local value
  print_topic "configuring display manager(s)"

  if [ -f /etc/gdm3/greeter.dconf-defaults ]
  then
    echo '[+] disabling user list in /etc/gdm3/greeter.dconf-defaults'
    sed_with_diff '/disable-user-list=true$/s/^#\s*//' /etc/gdm3/greeter.dconf-defaults
    # TODO: go through the rest of /etc/gdm3/greeter.dconf-defaults
  elif [ -f /etc/lightdm/lightdm.conf ]
  then
    for setting in ${!LIGHTDM_CONFIG[*]}
    do
      value="${LIGHTDM_CONFIG[${setting}]}"
      echo "[+] setting ${setting} to ${value} in /etc/lightdm/lightdm.conf"
      # ^#\?key=value$
      sed_with_diff "s/^#\?\(${setting}\)=.*$/\1=${value}/" /etc/lightdm/lightdm.conf
    done
  else
    echo '[-] display manager greeter config not found'
  fi
  # https://wiki.ubuntu.com/LightDM#Disabling_Guest_Login
  if [ -d /etc/lightdm/lightdm.conf.d ]
  then
    echo '[+] disallowing guest sessions in LightDM'
    echo -e '[Seat:*]\nallow-guest=false' 1>/etc/lightdm/lightdm.conf.d/50-disallow-guest.conf
  fi
  # TODO: greeter-allow-guest in /etc/lightdm/lightdm.conf (in Pi)
} # disable_gdm3_user_list()
################################################################################
function configure_shells() {
  print_topic "configuring shells"
  (( ${LYNIS_TESTS} )) && local LYNIS_SCORE_BEFORE=$( get_lynis_hardening_index shells )
  echo '[+] creating /etc/profile.d/tmout.sh'
  make -f ${CWD}/Makefile /etc/profile.d/tmout.sh
  configure_umask
  remove_shells
  (( ${LYNIS_TESTS} )) && {
    local LYNIS_SCORE_AFTER=$( get_lynis_hardening_index shells )
    compare_lynis_scores "${LYNIS_SCORE_BEFORE}" "${LYNIS_SCORE_AFTER}"
    check_lynis_tests SHLL-6220 SHLL-6230
  }
} # configure_shells()
################################################################################
function configure_umask() {
  print_topic "configuring umask"
  # TODO: utilize configure_password_policies()
  if [ -f /etc/login.defs ]
  then
    echo "[+] configuring /etc/login.defs"
    local policy="UMASK"
    sed_with_diff "s/^\(# \?\)\?\(${policy}\)\(\s\+\)\S\+$/\2\3${PASSWORD_POLICIES[${policy}]}/" /etc/login.defs
  else
    echo "[-] /etc/login.defs not found" 1>&2
  fi
  if [ -f /etc/bash.bashrc ]
  then
    if ! grep -q '^umask 077$' /etc/bash.bashrc
    then
      echo '[+] configuring umask to /etc/bash.bashrc'
      sed_with_diff '$a umask 077' /etc/bash.bashrc
    fi
  fi
  if [ -f /etc/init.d/functions ]
  then
    echo '[+] configuring umask to /etc/init.d/functions'
    sed_with_diff 's/^umask [0-9]\+$/umask 077/' /etc/init.d/functions
  fi
  make -f ${CWD}/Makefile /etc/profile.d/umask.sh
  configure_pam_umask
  (( ${LYNIS_TESTS} )) && {
    LYNIS_SCORE_AFTER=$( get_lynis_hardening_index authentication )
    check_lynis_tests AUTH-9328
  }
} # configure_umask()
################################################################################

if [ "${USER}" != "root" ]
then
  echo -e "[-] warning: you should probably be root to run this script\n" 1>&2
fi
if [ ${#NAMES[*]} -eq 0 ]
then
  echo '[-] warning: NAMES array not populated' 1>&2
fi

read_password_policy

while getopts "aAbcf:ghIL:mp:P:qU" OPTION
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
      create_limited_ca_list
      enable_pacct
      import_pgp_keys
      check_and_patch /etc	"${ETC_PATCH_FILE}"	1 && ETC_CHANGED=1
      apply_newconfs . cron.d logrotate.d rc.d modprobe.d
      check_and_patch /etc	"${SUDOERS_PATCH_FILE}"	1
      check_and_patch /etc	"${SSH_PATCH_FILE}"	1

      # this should be run after patching etc,
      # there might be new rc scripts.
      disable_unnecessary_services

      miscellaneous_settings

      # these should be the last things to run
      file_permissions
      restrict_cron

      harden_fstab
      configure_basic_auditing
      configure_securetty

      # TODO: after restarting syslog,
      # there might be new log files with wrong permissions.
      (( ${ETC_CHANGED} )) && restart_services
    ;;
    "b") toggle_usb_authorized_default	;;
    "c") create_limited_ca_list		;;
    "f")
      case "${OPTARG}" in
	"aa_enforce")		aa_enforce			;;
	"configure_apt")	configure_apt			;;
	"configure_modprobe.d")	configure_modprobe.d		;;
	"configure_pam")	configure_pam			;;
	"configure_securetty")	configure_securetty		;;
	"create_banners")	create_banners			;;
	"core_dumps")		configure_core_dumps		;;
	"disable_ipv6")		disable_ipv6			;;
	"disable_unnecessary_systemd_services") disable_unnecessary_systemd_services ;;
	"enable_apparmor")	enable_apparmor			;;
	"enable_bootlog")	enable_bootlog			;;
	"enable_sysstat")	enable_sysstat			;;
	"file_permissions")	file_permissions		;;
	"file_permissions2")	file_permissions2		;;
	"gnome_settings")	gnome_settings			;;
	"lock_system_accounts")	lock_system_accounts		;;
	"password_policies")	configure_password_policies	;;
	"restrict_cron")	restrict_cron			;;
	"sshd_config")		configure_sshd			;;
	"ssh_config")		configure_ssh			;;
	"sysctl_harden")	sysctl_harden			;;
	"homedir_perms")	user_home_directories_permissions ;;
	"disable_gdm3_user_list") disable_gdm3_user_list        ;;
	"configure_umask")	configure_umask			;;
	"configure_shells")	configure_shells		;;
	"configure_tcp_wrappers") configure_tcp_wrappers	;;
	"set_usb_authorized_default") set_usb_authorized_default ;;
	"remove_shells")        remove_shells                   ;;
	"create_ftpusers")      create_ftpusers                 ;;
	"disable_inetd_services") disable_inetd_services        ;;
	"set_failure_limits")   set_failure_limits              ;;
	"harden_fstab")         harden_fstab                    ;;
	"user_accounts")        user_accounts                   ;;
	"configure_basic_auditing") configure_basic_auditing    ;;
	"disable_unnecessary_services") disable_unnecessary_services ;;
	"enable_pacct")         enable_pacct                    ;;
	*)
	  echo "[-] unknown function" 1>&2
	  exit 1
	;;
      esac
    ;;
    "g") import_pgp_keys		;;
    "h")
      usage
      exit 0
    ;;
    "I") check_integrity		;;
    "L") lock_account "${OPTARG}"	;;
    "m")
      # TODO: remove?
      miscellaneous_settings
    ;;
    "p")
      case "${OPTARG}" in
	"ssh")
	  # CIS 1.3 Configure SSH
	  check_and_patch /etc "${SSH_PATCH_FILE}" 1 && \
            [ -f "/var/run/sshd.pid" ] && [ -x "/etc/rc.d/rc.sshd" ] && \
	      /etc/rc.d/rc.sshd restart
	;;
	"etc")		check_and_patch /etc "${ETC_PATCH_FILE}" 1 && ETC_CHANGED=1	;;
        "apache")	check_and_patch /etc/httpd "${APACHE_PATCH_FILE}" 3		;;
	"sendmail")	patch_sendmail							;;
	"php")		check_and_patch /etc/httpd php_harden.patch 1			;;
        "sudoers")	check_and_patch /etc "${SUDOERS_PATCH_FILE}" 1			;;
	"wipe")
	  check_and_patch /etc wipe.patch 1
	  {
	    chmod -c 700 /etc/rc.d/rc.{2,5}
	    chmod -c 700 /etc/rc.d/rc2.d/KluksHeaderRestore.sh
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
	"etc")		check_and_patch /etc "${ETC_PATCH_FILE}" 1 reverse && ETC_CHANGED=1	;;
        "apache")	check_and_patch /etc/httpd "${APACHE_PATCH_FILE}" 3 reverse		;;
        "sendmail")	patch_sendmail reverse							;;
	"php")		check_and_patch /etc/httpd php_harden.patch 1 reverse			;;
        "sudoers")	check_and_patch /etc	"${SUDOERS_PATCH_FILE}"	1 reverse		;;
	"wipe")
	  check_and_patch /etc wipe.patch 1 reverse
          /sbin/init q
	;;
	*)		echo "error: unknown patch \`${OPTARG}'!" 1>&2				;;
      esac
    ;;
    "q") quick_harden			;;
    "U") create_additional_user_accounts ;;
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
