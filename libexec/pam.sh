#!/bin/bash
function configure_core_dumps() {
  # slackware uses /etc/limits and is configured through limits.new file
  local file="${ROOTDIR:-/}etc/security/limits.conf"
  cat 0<<-EOF
	
	configuring core dumps
	----------------------
EOF
  if [ ! -f "${file}" ]
  then
    echo "[-] ${file} NOT found" 1>&2
    return 1
  fi
  echo "[+] ${file} found"
  sed_with_diff 's/^#\?\*\( \+\)soft\( \+\)core\( \+\)0$/*\1hard\2core\30/' "${file}"
  return ${?}
  # TODO: nproc - max number of processes
} # configure_core_dumps()
################################################################################
function configure_pam_umask() {
  if [ -f ${ROOTDIR:-/}etc/pam.d/common-session ] && ! grep -q 'pam_umask\.so' ${ROOTDIR:-/}etc/pam.d/common-session
  then
    echo '[+] enabling pam_umask in /etc/pam.d/common-session'
    sed_with_diff '$ a session optional pam_umask.so' "${ROOTDIR:-/}etc/pam.d/common-session"
  fi
} # configure_pam_umask()
################################################################################
function configure_pam() {
  # https://github.com/pyllyukko/harden.sh/wiki/PAM
  local setting
  local file
  local regex
  local NAME

  configure_password_policies

  cat 0<<-EOF
	
	configuring PAM
	---------------
EOF
  if [ ! -d ${ROOTDIR:-/}etc/pam.d ]
  then
    echo '[-] /etc/pam.d does not exist!' 1>&2
    return 1
  fi
  # NOTE: if libpam-passwdqc is installed, it is already configured by pam-auth-update

  # enable faillog (pam_tally2)
  if [ -f ${ROOTDIR:-/}etc/pam.d/login ]
  then
    if ! grep -q "pam_tally2" ${ROOTDIR:-/}etc/pam.d/login
    then
      echo '[+] enabling pam_tally2'
      # insert above first occurance of ^auth
      regex="/^auth/{
        iauth       required   pam_tally2.so     onerr=fail audit silent deny=${FAILURE_LIMIT} unlock_time=900
        # loop through the rest of the file
        :a
        \$!{
          # Read the next line of input into the pattern space
          n
          # Branch to label a
          ba
        }
      }"
      sed_with_diff "${regex}" "${ROOTDIR:-/}etc/pam.d/login"
    fi

    # pam_access
    # TODO: CentOS
    if [ -f ${ROOTDIR:-/}etc/pam.d/common-account ] && ! grep -q "account\s\+required\s\+pam_access\.so" ${ROOTDIR:-/}etc/pam.d/common-account
    then
      echo '[+] enabling pam_access in /etc/pam.d/common-account'
      sed_with_diff '$ a account required pam_access.so nodefgroup' "${ROOTDIR:-/}etc/pam.d/common-account"
    fi

    # access.conf
    # the checksum is the same both for Debian & CentOS
    if sha512sum -c 0<<<"a32865fc0d8700ebb63e01fa998c3c92dca7bda2f6a34c5cca0a8a59a5406eef439167add8a15424b82812674312fc225fd26331579d5625a6d1c4cf833a921f  ${ROOTDIR:-/}etc/security/access.conf" &>/dev/null
    then
      echo '[+] configuring /etc/security/access.conf'
      for regex in \
        '/^# All other users should be denied to get access from all sources./i+ : root : LOCAL\n- : ALL : cron crond\n+ : (users) : ALL' \
        '/- : ALL : ALL$/s/^#\s*//'
      do
        sed_with_diff "${regex}" "${ROOTDIR:-/}etc/security/access.conf"
      done
      echo '[*] NOTE: be sure to add regular users to the "users" group!'
      for NAME in $( awk -F: -v uid_min=${UID_MIN:-1000} '$3>=uid_min{print$1}' /etc/passwd )
      do
	if ! groups "${NAME}" | grep -q "users"
	then
	  echo "[-] WARNING: user \`${NAME}' does not belong to group \"users\"!" 1>&2
	fi
      done
    fi
  fi

  # add 10 second delay to all failed authentication events
  # http://www.linux-pam.org/Linux-PAM-html/sag-pam_faildelay.html
  if [ -f ${ROOTDIR:-/}etc/pam.d/common-auth ] && ! grep -q "pam_faildelay\.so" ${ROOTDIR:-/}etc/pam.d/common-auth
  then
    echo '[+] enabling pam_faildelay in /etc/pam.d/common-auth'
    sed_with_diff '/^# here are the per-package modules (the "Primary" block)$/aauth\toptional\t\t\tpam_faildelay.so delay=10000000' "${ROOTDIR:-/}etc/pam.d/common-auth"
  fi

  if [ -f ${ROOTDIR:-/}etc/pam.d/lightdm ] && ! grep -q '^session\s\+optional\s\+pam_lastlog\.so' ${ROOTDIR:-/}etc/pam.d/lightdm
  then
    echo '[+] enabling pam_lastlog in /etc/pam.d/lightdm'
    sed_with_diff '$ a session    optional   pam_lastlog.so' ${ROOTDIR:-/}etc/pam.d/lightdm
  fi
  if [ -f ${ROOTDIR:-/}etc/pam.d/gdm-password ] && ! grep -q '^session\s\+optional\s\+pam_lastlog\.so' ${ROOTDIR:-/}etc/pam.d/gdm-password
  then
    echo '[+] enabling pam_lastlog in /etc/pam.d/gdm-password'
    sed_with_diff '$ a session optional        pam_lastlog.so' ${ROOTDIR:-/}etc/pam.d/gdm-password
  fi

  # limit password reuse
  # debian
  if [ -f ${ROOTDIR:-/}etc/pam.d/common-password ] && ! grep -q "^password.*pam_unix\.so.*remember" ${ROOTDIR:-/}etc/pam.d/common-password
  then
    echo '[+] limiting password reuse in /etc/pam.d/common-password'
    sed_with_diff 's/^\(password.*pam_unix\.so.*\)$/\1 remember=5/' "${ROOTDIR:-/}etc/pam.d/common-password"
  # red hat
  # NOTE: this should be done in different way, as these configs are wiped by authconfig
  elif [ -f ${ROOTDIR:-/}etc/pam.d/password-auth -a -f ${ROOTDIR:-/}etc/pam.d/system-auth ] && \
    ! grep -q "^password.*pam_unix\.so.*remember" ${ROOTDIR:-/}etc/pam.d/password-auth && ! grep -q "^password.*pam_unix\.so.*remember" ${ROOTDIR:-/}etc/pam.d/system-auth
  then
    for file in "${ROOTDIR:-/}etc/pam.d/password-auth" "${ROOTDIR:-/}etc/pam.d/system-auth"
    do
      echo "[+] limiting password reuse in ${file}"
      sed_with_diff 's/^\(password.*pam_unix\.so.*\)$/\1 remember=5/' "${file}"
    done
  fi

  # disallow empty passwords
  # TODO: CentOS
  if [ -f ${ROOTDIR:-/}etc/pam.d/common-auth ] && grep -q 'nullok' ${ROOTDIR:-/}etc/pam.d/common-auth
  then
    echo '[+] removing nullok from /etc/pam.d/common-auth'
    sed_with_diff 's/\s\+nullok\(_secure\)\?//' "${ROOTDIR:-/}etc/pam.d/common-auth"
  fi

  # !su
  if [ -f ${ROOTDIR:-/}etc/pam.d/su ] && ! grep -q "^auth.*required.*pam_wheel\.so" ${ROOTDIR:-/}etc/pam.d/su
  then
    echo '[+] configuring pam_wheel.so'
    sed_with_diff '/auth\s\+required\s\+pam_wheel\.so\(\s\+use_uid\)\?$/s/^#\s*//' "${ROOTDIR:-/}etc/pam.d/su"
  fi

  # pam_namespace
  if [ -f ${ROOTDIR:-/}etc/security/namespace.conf ] && [ "${DISTRO}" = "debian" -o "${DISTRO}" = "raspbian" ]
  then
    # WARNING: this is not completely tested with CentOS!
    echo '[+] configuring polyinstation (pam_namespace)'
    for regex in \
      's/^#\/tmp.*$/\/tmp     \/tmp\/tmp-inst\/         level      root/' \
      '/^#\/var\/tmp/s/^#\(.*\),adm$/\1/'
    do
      sed_with_diff "${regex}" "${ROOTDIR:-/}etc/security/namespace.conf"
    done
    for file in \
      ${ROOTDIR:-/}etc/pam.d/login        \
      ${ROOTDIR:-/}etc/pam.d/gdm-password \
      ${ROOTDIR:-/}etc/pam.d/sshd         \
      ${ROOTDIR:-/}etc/pam.d/lightdm
    do
      if [ -f ${file} ] && ! grep -q '^session\s\+required\s\+pam_namespace\.so' ${file}
      then
	sed_with_diff '$ a session    required   pam_namespace.so' "${file}"
      fi
    done
  fi

  # pam_umask
  configure_pam_umask

  # /etc/pam.d/other
  echo '[+] configuring default behaviour via /etc/pam.d/other'
  cat 0<<-EOF 1>${ROOTDIR:-/}etc/pam.d/other
	# deny all access by default and log to syslog
	auth      required   pam_deny.so
	auth      required   pam_warn.so
	account   required   pam_deny.so
	account   required   pam_warn.so
	password  required   pam_deny.so
	password  required   pam_warn.so
	session   required   pam_deny.so
	session   required   pam_warn.so
EOF

  # red hat uses pwquality instead of cracklib||passwdqc
  if [ -f ${ROOTDIR:-/}etc/security/pwquality.conf ]
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
  #if [ -f ${ROOTDIR:-/}etc/passwdqc.conf ]
  #then
  #  # TODO
  #  true
  #fi
} # configure_pam()
