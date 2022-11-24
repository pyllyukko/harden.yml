#!/bin/bash
declare -r SLACKWARE_VERSION=$( sed 's/^.*[[:space:]]\([0-9]\+\.[0-9]\+\).*$/\1/' /etc/slackware-version 2>/dev/null )
declare -r ETC_PATCH_FILE="harden_etc-${SLACKWARE_VERSION}.patch"
auditPATH='/etc/audit'
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

# PATCHES
#declare -r APACHE_PATCH_VERSION="2.4.3-20120929-1"
declare -r APACHE_PATCH_FILE="apache_harden.patch"
declare -r SENDMAIL_PATCH_FILE="sendmail_harden.patch"
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
    echo "[-] error: directory \`${DIR_TO_PATCH}' does not exist!" 1>&2
    return 1
  }

  [ ! -f "${PATCH_FILE}" ] && {
    echo "[-] error: patch file \`${PATCH_FILE}' does not exist!" 1>&2
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
      echo "[-] error: patch dry-run didn't work out, maybe the patch has already been reversed?" 1>&2
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
      echo "[-] error: patch dry-run didn't work out, maybe the patch has already been applied?" 1>&2
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

  # TODO: Xwrapper.config

  [ -f /etc/X11/xdm/Xresources ] && {
    #echo "xlogin*unsecureGreeting: This is an unsecure session" 1>>/etc/X11/xdm/Xresources
    #echo "xlogin*allowRootLogin: false" 1>>/etc/X11/xdm/Xresources
    true
  }

  enable_bootlog

  # make run-parts print "$SCRIPT failed." to stderr, so cron can mail this info to root.
  sed -i 's/\(echo "\$SCRIPT failed."\)$/\1 1>\&2/' /usr/bin/run-parts

  return 0
} # miscellaneous settings()
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
function check_integrity() {
  local    manifest="${MANIFEST_DIR}/MANIFEST.bz2"
  local -i I=0
  local    FULL_PERM
  local    OWNER_GROUP
  local    SIZE
  local    PATH_NAME
  local -a STAT=()
  local    local_FULL_PERM
  local    local_OWNER_GROUP
  local    local_size

  make -f ${CWD}/Makefile slackware="${SLACKWARE}" slackware_version="${SLACKWARE_VERSION}" "${manifest}" || return 1

  pushd /

  # partly copied from http://www.slackware.com/%7Ealien/tools/restore_fileperms_from_manifest.sh
  while read line
  do
    if [[ ${line} =~ ^.(.{9})\ ([a-z]+/[a-z]+)\ +([0-9]+)\ [0-9]{4}-[0-9]{2}-[0-9]{2}\ [0-9]{2}:[0-9]{2}\ (.+)$ ]]
    then
      FULL_PERM="${BASH_REMATCH[1]}"
      OWNER_GROUP="${BASH_REMATCH[2]//\//:}"
      SIZE="${BASH_REMATCH[3]}"
      PATH_NAME="${BASH_REMATCH[4]}"
    fi

    if [ ! -e "${PATH_NAME}" ]
    then
      continue
    # if it's a link -> skip
    elif [ -h "${PATH_NAME}" ]
    then
      continue
    fi

    STAT=( $( stat -c"%A %U:%G %s" "${PATH_NAME}" ) )
    local_FULL_PERM="${STAT[0]:1:9}"
    local_OWNER_GROUP="${STAT[1]}"
    local_size="${STAT[2]}"

    if [ -z "${local_OWNER_GROUP}" -o -z "${local_FULL_PERM}" ]
    then
      continue
    fi

    if [ \
      "${FULL_PERM}"	!= "${local_FULL_PERM}" -o \
      "${OWNER_GROUP}"	!= "${local_OWNER_GROUP}" ]
    then
      echo "Path: ${PATH_NAME}"
      if [ "${FULL_PERM}" != "${local_FULL_PERM}" ]
      then
        printf " %-9s: %-33s, %s\n" "Perm" "${FULL_PERM}" "${local_FULL_PERM}"
      fi
      if [ "${OWNER_GROUP}" != "${local_OWNER_GROUP}" ]
      then
        printf " %-9s: %-33s, %s\n" "Owner" "${OWNER_GROUP}" "${local_OWNER_GROUP}"
      fi
      # the file sizes change during updates, so this is commented out for now...
      #if [ ${local_size} -ne 0 -a ${SIZE} -ne ${local_size} ]
      #then
      #  printf " %-9s: %-33s, %s\n" "Size" ${SIZE} ${local_size}
      #fi
      echo -n $'\n'
    fi
    ((I++))
  done 0< <(bzgrep -E "^[d-]" "${manifest}" | sort | uniq)
  echo "${I} paths checked"

  popd
} # check_integrity()
################################################################################
function apply_newconfs() {
  local    newconf
  local    basename
  local    subdir
  local -a sha256sums

  print_topic "applying .new confs"

  pushd /etc 1>/dev/null || {
    echo "[-] error!" 1>&2
    return 1
  }
  shopt -s nullglob
  for subdir in ${*}
  do
    if [ ! -d "${CWD}/newconfs/${subdir}" ]
    then
      echo "[-] error: ${subdir} directory does not exist!" 1>&2
      continue
    fi
    for newconf in ${CWD}/newconfs/${subdir}/*.new
    do
      basename=$( basename "${newconf}" )
      # check if the file exists
      if [ ! -f "${subdir}/${basename%.new}" ]
      then
	# if not, move the .new into place
        echo "[+] creating new file \`${subdir}/${basename%.new}'"
	cat "${newconf}" 1>"${subdir}/${basename%.new}"
      elif
	sha256sums=( $( sha256sum "${subdir}/${basename%.new}" "${newconf}" | awk '{print$1}' ) )
	[ "${sha256sums[0]}" != "${sha256sums[1]}" ]
      then
	echo "[+] file \`${subdir}/${basename%.new}' exists. creating \`${subdir}/${basename}'."
	# leave the .new file for the admin to consider
	cat "${newconf}" 1>"${subdir}/${basename}"
      else
	echo "[+] file \`${subdir}/${basename%.new}' exists"
      fi
    done
  done
  popd 1>/dev/null
} # apply_newconfs()
