#!/bin/bash
declare -r SENDMAIL_CF_DIR="/usr/share/sendmail/cf/cf"
declare -r SENDMAIL_CONF_PREFIX="sendmail-slackware"
declare -r SLACKWARE_VERSION=$( sed 's/^.*[[:space:]]\([0-9]\+\.[0-9]\+\).*$/\1/' /etc/slackware-version 2>/dev/null )
declare -r ETC_PATCH_FILE="harden_etc-${SLACKWARE_VERSION}.patch"
# the rc.modules* should match at least the following:
#   - rc.modules.local
#   - rc.modules-2.6.33.4
#   - rc.modules-2.6.33.4-smp
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
################################################################################
function remove_packages() {
  # BIG FAT NOTE: make sure you don't actually need these!
  #               although, i tried to keep the list short.

  echo "${FUNCNAME}(): removing potentially dangerous packages"

  # TODO: if -x removepkg && apt-get stuff
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
    # NOTE: when using grsec's RBAC, if shadow is read-only passwd will require CAP_DAC_OVERRIDE
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

    # TODO: grub & general Debian support for this whole function

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
    /usr/bin/chmod -c o-rwx	/var/log/wtmp

    ##############################################################################
    # from system-hardening-10.2.txt:
    ##############################################################################

    # "The file may hold encryption keys in plain text."
    /usr/bin/chmod -c 600	/etc/rc.d/rc.wireless.conf

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
    elif [ "${RC:(-5):5}" = ".orig" ]
    then
      echo ".orig file -> skipping" 1>&2
      continue
    elif [ "${RC:(-1):1}" = "~" ]
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

  disable_unnecessary_systemd_services

  echo "${FUNCNAME}(): enabling recommended services"

  enable_sysstat

  # CIS 2.2 Configure TCP Wrappers and Firewall to Limit Access (applied)
  #
  # NOTE: the rc.firewall script should be created by the etc patch
  /usr/bin/chmod -c 700 /etc/rc.d/rc.firewall | tee -a "${logdir}/file_perms.txt"

  # inetd goes with the territory
  disable_inetd_services

  return 0
} # disable_unnecessary_services()
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

  cat 0<<-EOF
	
	applying .new confs
	-------------------
EOF

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
