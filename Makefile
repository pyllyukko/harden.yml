CWD = $(realpath $(dir $(lastword $(MAKEFILE_LIST))))
slackware = slackware64
slackware_version = 15.0
manifest_files = $(CWD)/manifests/$(slackware)-$(slackware_version)/CHECKSUMS.md5 $(CWD)/manifests/$(slackware)-$(slackware_version)/CHECKSUMS.md5.asc $(CWD)/manifests/$(slackware)-$(slackware_version)/MANIFEST.bz2
SHELL=/bin/bash

/etc/ssl/certs/ca-certificates.crt: /etc/ca-certificates.conf
	/usr/sbin/update-ca-certificates --verbose --fresh

/etc/ca-certificates.conf: $(CWD)/files/ca-certificates.conf.new FORCE
	/usr/bin/install -m 644 $< $@

/etc/motd: $(CWD)/newconfs/motd.new FORCE
	/usr/bin/install -m 644 $< $@

/etc/issue: FORCE
	@echo "Authorized uses only. All activity may be monitored and reported." 1>$@
	@chmod -c 644 $@

/var/lib/rkhunter/db/rkhunter.dat:
	/usr/bin/rkhunter --propupd

/etc/issue.net: /etc/issue
	@cp -vf $< $@

/etc/profile.d/umask.sh: $(CWD)/newconfs/profile.d/umask.sh.new FORCE
	/usr/bin/install -m 755 $< $@

.PHONY: pam-configs
pam-configs: /usr/share/pam-configs/tally2 /usr/share/pam-configs/access /usr/share/pam-configs/polyinstation /usr/share/pam-configs/lastlog /usr/share/pam-configs/umask /usr/share/pam-configs/faildelay /usr/share/pam-configs/pwhistory /usr/share/pam-configs/uid_ge_1000

/usr/share/pam-configs/%: $(CWD)/newconfs/pam-configs/%.new | /usr/share/pam-configs/
	/usr/bin/install -m 644 $< $@

/etc/pam.d/other: $(CWD)/newconfs/pam.d/other.new FORCE | /etc/pam.d/
	/usr/bin/install -m 644 $< $@

.PHONY: FORCE
FORCE:

# TODO: ldap
.PHONY: crls
crls:
	umask 022; set -e; for i in /etc/ssl/certs/????????.*; do crls=($$(openssl x509 -in "$${i}" -noout -ext crlDistributionPoints 2>/dev/null | sed -n 's/^\s\+URI:\(http.\+$$\)/\1/p')); if [ $${#crls[*]} -eq 1 -a -n "$${crls[0]}" ]; then wget -nv "$${crls[0]}" -O "$${i/./.r}"; openssl crl -in "$${i/./.r}" -inform DER -CAfile "$${i}" -noout; fi; done

define make-moduli-candidates-target
/etc/ssh/moduli-$1.candidates:
	ssh-keygen -M generate -O bits=$1 $$@
endef
# 1024 is only for testing, it is not included in the final moduli
bits := 1024 3072 4096 6144 7680 8192
modulis := /etc/ssh/moduli-3072 /etc/ssh/moduli-4096 /etc/ssh/moduli-6144 /etc/ssh/moduli-7680 /etc/ssh/moduli-8192
$(foreach l,$(bits),$(eval $(call make-moduli-candidates-target,$l)))

/etc/ssh/moduli-%: /etc/ssh/moduli-%.candidates
	ssh-keygen -M screen -f $< $@ && rm -v $<

/etc/ssh/moduli.new: $(modulis)
	cat $^ 1>$@

/etc/ssh/ssh_host_rsa_key:
	/usr/bin/ssh-keygen -b 8192 -t rsa -f $@ -N ''

/etc/ssh/ssh_host_ecdsa_key:
	/usr/bin/ssh-keygen -b 521 -t ecdsa -f $@ -N ''

/etc/ssh/ssh_host_ed25519_key:
	/usr/bin/ssh-keygen -t ed25519 -f $@ -N ''

numbits = 4096
dh-$(numbits).pem:
	openssl dhparam -out $@ $(numbits)

aircrack-profiles := usr.bin.aircrack-ng usr.bin.airgraph-ng usr.bin.ivstools usr.sbin.airbase-ng usr.sbin.airodump-ng usr.sbin.easside-ng usr.bin.airdecap-ng usr.bin.airolib-ng usr.bin.kstats usr.sbin.aireplay-ng usr.sbin.airserv-ng usr.sbin.tkiptun-ng usr.bin.airdecloak-ng usr.bin.buddy-ng usr.bin.packetforge-ng usr.sbin.airmon-ng usr.sbin.airtun-ng usr.sbin.wesside-ng
define make-aircrack-apparmor-target
aircrack-apparmor-profiles += /etc/apparmor.d/$1
/etc/apparmor.d/$1: | /etc/apparmor.d/
	wget -nv -O $$@ https://raw.githubusercontent.com/aircrack-ng/aircrack-ng/master/apparmor/$1
endef
$(foreach l,$(aircrack-profiles),$(eval $(call make-aircrack-apparmor-target,$l)))

.PHONY: aircrack-apparmor-profiles
aircrack-apparmor-profiles: $(aircrack-apparmor-profiles)

/etc/audit/audit.rules: FORCE
	/sbin/augenrules

/etc/audit/rules.d/31-privileged.rules.new: FORCE
	find /bin -type f \( -perm -04000 -o -perm -02000 \) 2>/dev/null | awk '{ printf "-a always,exit -F path=%s -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged\n", $$1 }' > $@
	find /sbin -type f \( -perm -04000 -o -perm -02000 \) 2>/dev/null | awk '{ printf "-a always,exit -F path=%s -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged\n", $$1 }' >> $@
	find /usr/bin -type f \( -perm -04000 -o -perm -02000 \) 2>/dev/null | awk '{ printf "-a always,exit -F path=%s -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged\n", $$1 }' >> $@
	find /usr/sbin -type f \( -perm -04000 -o -perm -02000 \) 2>/dev/null | awk '{ printf "-a always,exit -F path=%s -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged\n", $$1 }' >> $@
	find /opt -type f \( -perm -04000 -o -perm -02000 \) 2>/dev/null | awk '{ printf "-a always,exit -F path=%s -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged\n", $$1 }' >> $@
	find /usr/share -type f \( -perm -04000 -o -perm -02000 \) 2>/dev/null | awk '{ printf "-a always,exit -F path=%s -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged\n", $$1 }' >> $@
	find /usr/lib -type f \( -perm -04000 -o -perm -02000 \) 2>/dev/null | awk '{ printf "-a always,exit -F path=%s -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged\n", $$1 }' >> $@
	find /usr/libexec -type f \( -perm -04000 -o -perm -02000 \) 2>/dev/null | awk '{ printf "-a always,exit -F path=%s -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged\n", $$1 }' >> $@
	filecap /bin 2>/dev/null | awk 'NR>1{ printf "-a always,exit -F path=%s -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged\n", $$2 }' >> $@
	filecap /sbin 2>/dev/null | awk 'NR>1{ printf "-a always,exit -F path=%s -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged\n", $$2 }' >> $@
	filecap /usr/bin 2>/dev/null | awk 'NR>1{ printf "-a always,exit -F path=%s -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged\n", $$2 }' >> $@
	filecap /usr/sbin 2>/dev/null | awk 'NR>1{ printf "-a always,exit -F path=%s -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged\n", $$2 }' >> $@

/etc/audit/rules.d/40-authorized_keys.rules.new: FORCE
	find /home -type d -maxdepth 1 -mindepth 1 \! -name lost+found | sed 's/\(.\+\)$$/-w \1\/.ssh\/authorized_keys -p wa -k authorized_keys/' 1>$@

/etc/apparmor.d/usr.bin.irssi: | /etc/apparmor.d/
	wget -nv -O $@ https://gitlab.com/apparmor/apparmor-profiles/raw/master/ubuntu/18.10/usr.bin.irssi

#/etc/%: $(CWD)/newconfs/% FORCE
#	/usr/bin/install -m 600 $< $@

/etc/suauth.new: $(CWD)/newconfs/suauth.new FORCE
	/usr/bin/install -m 400 $< $@

/etc/securetty.new: $(CWD)/newconfs/securetty.new FORCE
	/usr/bin/install -m 400 $< $@

# always overwrite securetty
/etc/securetty: /etc/securetty.new
	mv -fv $< $@

/etc/fstab.new: $(CWD)/libexec/fstab.awk FORCE
	/usr/bin/gawk -f $< /etc/fstab 1>$@

/etc/modprobe.d/%: $(CWD)/newconfs/modprobe.d/%.new FORCE
	/usr/bin/install -m 600 $< $@

/etc/%: /etc/%.new
	if [ -f $@ ]; then cmp $@ $< && rm -v $< || true; else mv -v $< $@; fi

/etc/lynis/custom.prf: | /etc/lynis/
	grep '^skip-test=' $(CWD)/slackware-14.2.prf 1>$@

# TODO: chmod in debian is in /bin
/var/log/pacct:
	/usr/bin/touch $@
	/usr/bin/chmod -c 640 $@
	/usr/bin/chgrp adm $@

/etc/sysctl.d/harden.conf: $(CWD)/newconfs/sysctl.d/sysctl.conf.new FORCE | /etc/sysctl.d
	/usr/bin/install -m 600 $< $@

/etc/sysctl.d/%.conf: $(CWD)/newconfs/sysctl.d/%.conf.new FORCE | /etc/sysctl.d
	/usr/bin/install -m 600 $< $@

$(CWD)/manifests/$(slackware)-$(slackware_version)/:
	mkdir -pv $@

$(CWD)/manifests/$(slackware)-$(slackware_version)/CHECKSUMS.md5: $(CWD)/manifests/$(slackware)-$(slackware_version)/CHECKSUMS.md5.asc FORCE | $(CWD)/manifests/$(slackware)-$(slackware_version)/
	-wget -nv -nc -O $@ ftp://ftp.slackware.com/pub/slackware/$(slackware)-$(slackware_version)/$(slackware)/$(notdir $@)
	cd $(CWD)/manifests/$(slackware)-$(slackware_version) && gpgv2 CHECKSUMS.md5.asc CHECKSUMS.md5

# TODO: list keys used in the .asc
$(CWD)/manifests/$(slackware)-$(slackware_version)/CHECKSUMS.md5.asc: | $(CWD)/manifests/$(slackware)-$(slackware_version)/
	wget -nv -nc -O $@ ftp://ftp.slackware.com/pub/slackware/$(slackware)-$(slackware_version)/$(slackware)/$(notdir $@)

$(CWD)/manifests/$(slackware)-$(slackware_version)/MANIFEST.bz2: $(CWD)/manifests/$(slackware)-$(slackware_version)/CHECKSUMS.md5 FORCE | $(CWD)/manifests/$(slackware)-$(slackware_version)/
	-wget -nv -nc -O $@ ftp://ftp.slackware.com/pub/slackware/$(slackware)-$(slackware_version)/$(slackware)/$(notdir $@)
	cd $(CWD)/manifests/$(slackware)-$(slackware_version) && fgrep "MANIFEST.bz2" CHECKSUMS.md5 | /bin/md5sum -c

# Check Slackware's PAM files
$(CWD)/pam-files/:
	mkdir -pv $@

pam-files/other pam-files/passwd pam-files/postlogin pam-files/system-auth pam-files/chage pam-files/chgpasswd pam-files/chpasswd pam-files/groupadd pam-files/groupdel pam-files/groupmems pam-files/groupmod pam-files/newusers pam-files/useradd pam-files/userdel pam-files/usermod: | $(CWD)/pam-files/
	wget -nv -nc -O $@ ftp://ftp.slackware.com/pub/slackware/$(slackware)-$(slackware_version)/source/a/shadow/pam.d/$(notdir $@)

pam-files/su pam-files/su-l: | $(CWD)/pam-files/
	wget -nv -nc -O $@ ftp://ftp.slackware.com/pub/slackware/$(slackware)-$(slackware_version)/source/a/shadow/pam.d-su/$(notdir $@)

pam-files/sshd: | $(CWD)/pam-files/
	wget -nv -nc -O $@ ftp://ftp.slackware.com/pub/slackware/$(slackware)-$(slackware_version)/patches/source/openssh/sshd.pam

# See https://github.com/pyllyukko/harden.yml/wiki/PAM#etcpamdremote
pam-files/login pam-files/remote: | $(CWD)/pam-files/
	wget -nv -nc -O $@ ftp://ftp.slackware.com/pub/slackware/$(slackware)-$(slackware_version)/patches/source/util-linux/pam.d/login

pam-files/chfn pam-files/chsh pam-files/runuser pam-files/runuser-l: | $(CWD)/pam-files/
	wget -nv -nc -O $@ ftp://ftp.slackware.com/pub/slackware/$(slackware)-$(slackware_version)/patches/source/util-linux/pam.d/$(notdir $@)

pam-files/sddm pam-files/sddm-autologin pam-files/sddm-greeter: | $(CWD)/pam-files/
	wget -nv -nc -O $@ ftp://ftp.slackware.com/pub/slackware/$(slackware)-$(slackware_version)/source/kde/kde/post-install/sddm/pam.d/$(notdir $@)

pam-files/xscreensaver: | $(CWD)/pam-files/
	wget -nv -nc -O $@ ftp://ftp.slackware.com/pub/slackware/$(slackware)-$(slackware_version)/patches/source/xscreensaver/xscreensaver.pam

pam-files/screen: | $(CWD)/pam-files/
	wget -nv -nc -O $@ ftp://ftp.slackware.com/pub/slackware/$(slackware)-$(slackware_version)/source/ap/screen/screen.pam

pam-files/xdm: | $(CWD)/pam-files/
	wget -nv -nc -O $@ ftp://ftp.slackware.com/pub/slackware/$(slackware)-$(slackware_version)/source/x/x11/post-install/xdm/xdm.pamd

pam-files/dovecot: | $(CWD)/pam-files/
	wget -nv -nc -O $@ ftp://ftp.slackware.com/pub/slackware/$(slackware)-$(slackware_version)/source/n/dovecot/dovecot.pam

.PHONY: pam-files
pam-files: pam-files/other pam-files/passwd pam-files/postlogin pam-files/system-auth pam-files/su pam-files/su-l pam-files/sshd pam-files/login pam-files/remote pam-files/sddm pam-files/sddm-autologin pam-files/sddm-greeter pam-files/xscreensaver pam-files/screen pam-files/xdm pam-files/dovecot pam-files/chfn pam-files/chsh pam-files/runuser pam-files/runuser-l pam-files/chage pam-files/chgpasswd pam-files/chpasswd pam-files/groupadd pam-files/groupdel pam-files/groupmems pam-files/groupmod pam-files/newusers pam-files/useradd pam-files/userdel pam-files/usermod

.PHONY: pamcheck
pamcheck: pam-files
	for i in chage chgpasswd chpasswd groupadd groupdel groupmems groupmod newusers useradd userdel usermod; do echo "79e37b98714471de80ed60ac8aad337b547259ce27d669a58f8b9d94d77e676e336409f1da9a0f4e412c11398791ff3123a996899410729cda23b771e6111393  /etc/pam.d/$${i}" | /bin/sha512sum -c; done
	for i in chfn chsh; do echo "25af00fb379de78d2807e1f291fcf6a44a097dc4bbbe4f5ef8cc54deccba69428e72ad32cae65fd2e2b0d29a0233513fecc033b99a207890e6fb9cd7d98f87c2  /etc/pam.d/$${i}" | /bin/sha512sum -c; done
	echo -e "7750b5480178346bdf856d83e3aecf637f9888380657d2fe863096959ebc02a5e52fbab08bad9c4ae9e1c4f257dbe1d155eef8dd8dc1b9ac178b90e0ada5b6cb  /etc/pam.d/runuser\n9b39d1238b4686cb17e04051e0b5f9a5bd264e7789c6cf5409d7ed5114de781d28fbc8a7457f1ea67664ec595313e2c49710ac1a2480dbc49ed3d6ccf91bb3e6  /etc/pam.d/runuser-l" | /bin/sha512sum -c
	echo "38723d84782099253ac259c9592ef273042cf68127a3ae310ca3a720215924c029e44d9760ed2146922540ed41892c36a7a210d385eb1ec8ecee4f23b1ed8812  /etc/pam.d/elogind-user" | /bin/sha512sum -c
	-echo "d1bda49018597c8315d6fe37f765da0840f26816c54f663752f47e5934ddd4c10d211a0b2824517a2c487af0c5c1593b67eef653804844591f98e41c7bc4deb3  /etc/pam.d/ppp" | /bin/sha512sum -c
	-diff --color pam-files/other		/etc/pam.d/other
	-diff --color pam-files/passwd		/etc/pam.d/passwd
	-diff --color pam-files/postlogin	/etc/pam.d/postlogin
	-diff --color pam-files/system-auth	/etc/pam.d/system-auth
	-diff --color pam-files/su		/etc/pam.d/su
	-diff --color pam-files/su-l		/etc/pam.d/su-l
	-diff --color pam-files/sshd		/etc/pam.d/sshd
	-diff --color pam-files/login		/etc/pam.d/login
	-diff --color pam-files/remote		/etc/pam.d/remote
	-diff --color pam-files/sddm		/etc/pam.d/sddm
	-diff --color pam-files/sddm-autologin	/etc/pam.d/sddm-autologin
	-diff --color pam-files/sddm-greeter	/etc/pam.d/sddm-greeter
	-diff --color pam-files/xscreensaver	/etc/pam.d/xscreensaver
	-diff --color pam-files/screen		/etc/pam.d/screen
	-diff --color pam-files/xdm		/etc/pam.d/xdm
	-diff --color pam-files/dovecot		/etc/pam.d/dovecot

# PAM test
test: test.c
	gcc -o $@ $< -lpamtest -lcmocka

tests/segfault: tests/segfault.c
	gcc -o $@ $<

.PHONY: manifest
manifest: $(manifest_files)

.PHONY: manifest-suid-diff
manifest-suid-diff: manifests/slackware64-14.2/MANIFEST.bz2 manifests/slackware64-current/MANIFEST.bz2
	-diff <(bzgrep -i '^[^d].\{2\}\(s\|.\{3\}s\)' $< | gawk '{print$$1,$$2,$$6}' | sort) <(bzgrep -i '^[^d].\{2\}\(s\|.\{3\}s\)' $(word 2,$^) | gawk '{print$$1,$$2,$$6}' | sort)
