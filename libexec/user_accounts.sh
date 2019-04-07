#!/bin/bash
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
declare -a NAMES=( $( cut -d: -f1 /etc/passwd ) )
# these are not declared as integers cause then the ${ ... :-DEFAULT } syntax won't work(?!)
declare -r UID_MIN=$(		awk '/^UID_MIN/{print$2}'	/etc/login.defs 2>/dev/null )
declare -r UID_MAX=$(		awk '/^UID_MAX/{print$2}'	/etc/login.defs 2>/dev/null )
declare -r SYS_UID_MAX=$(	awk '/^SYS_UID_MAX/{print$2}'	/etc/login.defs 2>/dev/null )
################################################################################
function user_accounts() {
  # NOTE: http://refspecs.freestandards.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic/usernames.html
  #
  # NOTE: http://www.redhat.com/archives/nahant-list/2007-March/msg00163.html (good thread about halt & shutdown accounts)
  #
  # TODO: groups (or are they even necessary?)

  local group

  if [ ! -x "${DENY_SHELL}" ]
  then
    echo "[-] error: invalid \$DENY_SHELL!" 1>&2
    return 1
  fi

  set_failure_limits
  create_ftpusers
  restrict_cron
  lock_system_accounts
  user_home_directories_permissions

  # CUSTOM

  print_topic "miscellaneous"

  # change the defaults. this will update /etc/default/useradd.
  # this makes it so, that when a password of a user expires, the account is
  # locked after 35 days and the user cannot login anymore.
  #
  # WARNING: you don't want to set the EXPIRE (-e), since it's an absolute
  # date, and not relative. it's too easy to create accounts that are already
  # locked.
  #
  # see http://tldp.org/HOWTO/Shadow-Password-HOWTO-7.html#ss7.1
  echo '[+] setting the default password inactivity period'
  useradd -D -f ${password_inactive}

  # modify adduser to use 700 as newly created home dirs permission
  # grep for the line, as Debian uses different adduser (written in Perl)
  if grep -q ^defchmod /usr/sbin/adduser
  then
    echo '[+] settings defchmod in /usr/sbin/adduser'
    sed_with_diff 's/^defchmod=[0-9]\+\(.*\)$/defchmod=700\1/' /usr/sbin/adduser
  fi

  # from README.privsep
  # another less tiger warning (pass016w)
  echo '[+] configuring sshd account'
  /usr/sbin/usermod -c 'sshd privsep' -d /var/empty sshd

  # CUSTOM

  #
  # See GPASSWD(1): "Notes about group passwords"
  #
  # remove daemon from adm group, since we use adm group for log reading.
  # default members in Slack14.0:
  #   adm:x:4:root,adm,daemon
  #usermod -G daemon daemon
  echo '[+] removing daemon from adm group'
  gpasswd -d daemon adm

  # restrict adm group
  #gpasswd -R adm

  #echo "[+] creating groups for grsecurity"
  #for group in ${!grsec_groups[*]}
  #do
  #  groupadd -g ${grsec_groups[${group}]} ${group}
  #done

  # this should create the missing entries to /etc/gshadow
  echo '[+] fixing gshadow'
  if [ -x /usr/sbin/grpck ]
  then
    /usr/bin/yes | /usr/sbin/grpck
  else
    echo "[-] WARNING: grpck not found!" 1>&2
  fi

  return 0
} # user_accounts()
################################################################################
function configure_password_policy_for_existing_users() {
  local NAME
  local uid
  # CIS 8.3 Set Account Expiration Parameters On Active Accounts
  print_topic "configuring password policies for existing users"
  read_password_policy
  for NAME in ${NAMES[*]}
  do
    uid=$( id -u $NAME )
    if [ -z "${uid}" ]
    then
      continue
    fi
    if [ $uid -ge ${UID_MIN:-1000} ] && [ $uid -le ${UID_MAX:-60000} ]
    then
      echo "[+] UID ${uid}"
      chage -m ${PASS_MIN_DAYS:-7} -M ${PASS_MAX_DAYS:-365} -W ${PASS_WARN_AGE:-30} -I ${password_inactive} $NAME
    fi
  done
} # configure_password_policy_for_existing_users()
################################################################################
function lock_system_accounts() {
  local NAME
  local uid
  local password_status

  print_topic "locking system accounts"
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
    if [ ${uid} -le ${SYS_UID_MAX:-999} ] && \
      [ ${NAME} != 'root' ] && \
      [ ${NAME} != 'Debian-gdm' ] && \
      [ ${NAME} != 'lightdm' ] && \
      [ ${NAME} != 'daemon' ]
    then
      printf "%-17s (UID=%s)\n" "${NAME}" "${uid}"
      crontab -l -u "${NAME}" 2>&1 | grep -q "^\(no crontab for\|The user \S\+ cannot use this program (crontab)\)"
      if [ ${PIPESTATUS[1]} -ne 0 ]
      then
        echo "[-] WARNING: the user \`${NAME}' has some cronjobs! should it be so?" 1>&2
      fi
      password_status=$( /usr/bin/passwd -S "${NAME}" | awk '{print$2}' )
      if [ "${password_status}" != "L" ]
      then
        echo "[-] WARNING: the account \`${NAME}' is not locked properly!" 1>&2
      fi
      /usr/sbin/usermod -e 1970-01-02 -L -s "${DENY_SHELL}" "${NAME}"
    fi
  done
} # lock_system_accounts()
################################################################################
function lock_account() {
  echo "[+] locking account \"${1}\""
  if [ -z "${1}" ]
  then
    echo "[-] error!" 1>&2
    return 1
  fi
  id -u "${1}" &>/dev/null
  if [ ${?} -ne 0 ]
  then
    echo "[-] no such user!" 1>&2
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
  #useradd -u 213 -d /dev/null -s /sbin/nologin -g nagios -r nagios
  #usermod -G nagios -a apache

  groupadd -g 220 -r tor
  useradd  -u 220 -g 220 -e 1970-01-02 -c "The Onion Router" -M -d /var/lib/tor -s ${DENY_SHELL} tor

  groupadd -g 234 -r kismet

  return
} # create_additional_user_accounts()
################################################################################
function user_home_directories_permissions() {
  # this has been split into it's own function, since it relates to both
  # "hardening categories", user accounts & file permissions.
  local DIR
  print_topic "setting permissions of home directories"
  if [ -z "${UID_MIN}" -o -z "${UID_MAX}" ]
  then
    echo '[-] error: UID_MIN or UID_MAX not known' 1>&2
    return 1
  fi
  # 8.7 User Home Directories Should Be Mode 750 or More Restrictive (modified)
  for DIR in \
    $( awk -F: -v uid_min=${UID_MIN} -v uid_max=${UID_MAX} '($3 >= uid_min && $3 <= uid_max) { print $6 }' /etc/passwd ) \
    /root
  do
    if [ "x${DIR}" != "x/" ]
    then
      chmod -c 700 ${DIR} | tee -a "${logdir}/file_perms.txt"
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

  print_topic "creating /etc/ftpusers"
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
	echo "[+] adding \`${NAME}'"
	echo "${NAME}" 1>> /etc/ftpusers
      }
    fi
  done
  return
} # create_ftpusers()
################################################################################
function set_failure_limits() {
  local i
  local j=1
  # from system-hardening-10.2.txt (modified)
  # the UID_MIN and UID_MAX values are from /etc/login.defs
  # locks user accounts after 5 failed logins

  print_topic "setting failure limits"
  if ! hash faillog 2>/dev/null
  then
    echo "[-] faillog binary not found" 1>&2
    return 1
  fi
  echo "[+] setting the maximum number of login failures for UIDs ${UID_MIN:-1000}-${UID_MAX:-60000} to ${FAILURE_LIMIT:-5}"

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
    j=2
  fi
  for ((i=0; i<${j}; i++))
  do
    faillog -a -l $((60*15)) -m ${FAILURE_LIMIT:-5} -u ${UID_MIN:-1000}-${UID_MAX:-60000}
  done
  return ${?}
} # set_failure_limits()
