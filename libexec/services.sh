#!/bin/bash
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
    # TODO: sed_with_diff
    sed -i 's/^\('"${SERVICE}"'\)/\#\1/' "${INETDCONF}"
    echo -n '.'
  done
  echo -n $'\n'

  return
} # disable_inetd_services()
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
  local svc_name
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
    if [ "${DISTRO}" = "debian" ]
    then
      svc_name="acct"
    elif [ "${DISTRO}" = "centos" ]
    then
      svc_name="psacct"
    else
      echo "[-] couldn't determine process accounting service name" 1>&2
      return 1
    fi
    if systemctl is-enabled "${svc_name}"
    then
      echo '[+] process accounting already enabled'
    else
      if systemctl enable "${svc_name}"
      then
        echo '[+] process accounting enabled via systemd'
      else
        echo '[-] failed to enable process accounting' 1>&2
        return 1
      fi
    fi
  fi
} # enable_pacct()
################################################################################
