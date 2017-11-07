#!/bin/bash
function enable_apparmor() {
  local file
  cat 0<<-EOF
	
	enabling AppArmor
	-----------------
EOF
  # TODO: if [ -f /boot/cmdline.txt ]
  if [ ! -f /etc/default/grub ]
  then
    echo '[-] error: /etc/default/grub not found!' 1>&2
    return 1
  fi
  if [ ! -f /etc/init.d/apparmor ]
  then
    echo '[-] error: /etc/init.d/apparmor not found!' 1>&2
    return 1
  fi
  if [ ! -d /etc/apparmor.d ]
  then
    echo '[-] error: /etc/apparmor.d not found!' 1>&2
    return 1
  fi
  if [ -d /usr/share/doc/apparmor-profiles/extras ]
  then
    if [ -x /usr/sbin/aa-complain ]
    then
      echo '[+] copying extra profiles from /usr/share/doc/apparmor-profiles/extras'
      pushd /usr/share/doc/apparmor-profiles/extras 1>/dev/null
      shopt -s nullglob
      for file in *.*
      do
	# don't overwrite "stable" profiles
	if [ ! -f "/etc/apparmor.d/${file}" ]
	then
	  cp -v -n "${file}" /etc/apparmor.d/
	  # put all extra profiles in complain mode, as they have a higher chance of breaking things.
	  aa-complain "/etc/apparmor.d/${file}" || {
	    echo "[-] failed to set ${file} into complain mode. removing it." 1>&2
	    rm -v "/etc/apparmor.d/${file}"
	  }
	fi
      done
      popd 1>/dev/null
    else
      echo '[-] /usr/sbin/aa-complain not found. is apparmor-utils package installed? skipping copying of extra profiles.' 1>&2
    fi
  else
    echo "[-] extra profiles not found. try installing \`apparmor-profiles'."
  fi
  # http://wiki.apparmor.net/index.php/Distro_debian#In_Stock_Debian
  if ! grep -q '^GRUB_CMDLINE_LINUX=".*apparmor' /etc/default/grub
  then
    echo '[+] enabling AppArmor in /etc/default/grub'
    sed_with_diff 's/^\(GRUB_CMDLINE_LINUX=".*\)"$/\1 apparmor=1 security=apparmor"/' /etc/default/grub
    echo "NOTICE: /etc/default/grub updated. you need to run \`update-grub' or \`grub2-install' to update the boot loader."
  fi
} # enable_apparmor()
################################################################################
function aa_enforce() {
  local profile
  cat 0<<-EOF
	
	setting AppArmor profiles to enforce mode
	-----------------------------------------
EOF
  if [ -x /usr/sbin/aa-enforce ]
  then
    for profile in /etc/apparmor.d/*.*
    do
      /usr/sbin/aa-enforce ${profile}
    done
    # more details at https://github.com/pyllyukko/harden.sh/wiki/apparmor
    echo '[+] setting few troublesome profiles back to complain mode'
    # TODO: all extra profiles
    for profile in "sbin.dhclient" "usr.sbin.sshd" "usr.bin.man" "etc.cron.daily.logrotate" "usr.bin.wireshark" "usr.bin.passwd" "usr.sbin.userdel"
    do
      /usr/sbin/aa-complain /etc/apparmor.d/${profile}
    done
  else
    echo '[-] /usr/sbin/aa-enforce not found. is apparmor-utils package installed?' 1>&2
    return 1
  fi
} # aa_enforce()
