#!/bin/bash

# this script can be used along with lxc.yml playbook to view the modifications done in various files

slackware_mirror_dir="/path/to/mirrors/slackware"
lxc_dir="/var/lib/lxc"

# init scripts
/usr/bin/vimdiff "${slackware_mirror_dir}/slackware64-current/source/a/sysvinit-scripts/scripts/inittab"	"${lxc_dir}/harden.sh-test-slackware/rootfs/etc/inittab"
/usr/bin/vimdiff "${slackware_mirror_dir}/slackware64-current/source/a/sysvinit-scripts/scripts/rc.M"		"${lxc_dir}/harden.sh-test-slackware/rootfs/etc/rc.d/rc.M"
/usr/bin/vimdiff "${slackware_mirror_dir}/slackware64-current/source/a/sysvinit-scripts/scripts/rc.K"		"${lxc_dir}/harden.sh-test-slackware/rootfs/etc/rc.d/rc.K"
/usr/bin/vimdiff "${slackware_mirror_dir}/slackware64-current/source/a/dcron/rc.crond"				"${lxc_dir}/harden.sh-test-slackware/rootfs/etc/rc.d/rc.crond"
/usr/bin/vimdiff "${slackware_mirror_dir}/slackware64-current/source/n/network-scripts/scripts/rc.inet2"	"${lxc_dir}/harden.sh-test-slackware/rootfs/etc/rc.d/rc.inet2"

# shadow suite
/usr/bin/vimdiff <(zcat "${slackware_mirror_dir}/slackware64-current/source/a/shadow/login.defs.shadow.gz")					"${lxc_dir}/harden.sh-test-slackware/rootfs/etc/login.defs"
/usr/bin/vimdiff <(zcat "${slackware_mirror_dir}/slackware64-current/source/a/shadow/useradd.gz")						"${lxc_dir}/harden.sh-test-slackware/rootfs/etc/default/useradd"
/usr/bin/vimdiff "${slackware_mirror_dir}/slackware64-current/source/a/shadow/adduser"								"${lxc_dir}/harden.sh-test-slackware/rootfs/usr/sbin/adduser"
/usr/bin/vimdiff <(tar xf "${slackware_mirror_dir}/slackware64-current/slackware64/a/shadow-4.8.1-x86_64-5.txz" etc/login.access.new -O)	"${lxc_dir}/harden.sh-test-slackware/rootfs/etc/login.access"

# logging
/usr/bin/vimdiff <(zcat "${slackware_mirror_dir}/slackware64-current/source/a/logrotate/logrotate.conf.gz")	"${lxc_dir}/harden.sh-test-slackware/rootfs/etc/logrotate.conf"
/usr/bin/vimdiff "${slackware_mirror_dir}/slackware64-current/source/a/sysklogd/config/syslog.logrotate"	"${lxc_dir}/harden.sh-test-slackware/rootfs/etc/logrotate.d/syslog"

# others
/usr/bin/vimdiff <(tar xf "${slackware_mirror_dir}/slackware64-current/source/a/etc/_etc.tar.gz" etc/profile.new -O)			"${lxc_dir}/harden.sh-test-slackware/rootfs/etc/profile"
/usr/bin/vimdiff <(tar xf "${slackware_mirror_dir}/slackware64-current/source/a/etc/_etc.tar.gz" etc/securetty.new -O)			"${lxc_dir}/harden.sh-test-slackware/rootfs/etc/securetty"
/usr/bin/vimdiff "${slackware_mirror_dir}/slackware64-current/source/a/dcron/crond.default"						"${lxc_dir}/harden.sh-test-slackware/rootfs/etc/default/crond"
/usr/bin/vimdiff <(tar xf "${slackware_mirror_dir}/slackware64-current/slackware64/ap/sudo-1.8.31p1-x86_64-1.txz" etc/sudoers.new -O)	"${lxc_dir}/harden.sh-test-slackware/rootfs/etc/sudoers"
/usr/bin/vimdiff "${slackware_mirror_dir}/slackware64-current/source/a/pkgtools/scripts/installpkg"					"${lxc_dir}/harden.sh-test-slackware/rootfs/sbin/installpkg"
/usr/bin/vimdiff <(tar xf "${slackware_mirror_dir}/slackware64-current/slackware64/n/openssh-8.2p1-x86_64-2.txz" etc/ssh/sshd_config.new -O)	"${lxc_dir}/harden.sh-test-slackware/rootfs/etc/ssh/sshd_config"
/usr/bin/vimdiff <(tar xf "${slackware_mirror_dir}/slackware64-current/slackware64/n/openssh-8.2p1-x86_64-2.txz" etc/ssh/ssh_config.new -O)	"${lxc_dir}/harden.sh-test-slackware/rootfs/etc/ssh/ssh_config"
