CWD = $(realpath $(dir $(lastword $(MAKEFILE_LIST))))
slackware = slackware64
slackware_version = 15.0
manifest_files = $(CWD)/manifests/$(slackware)-$(slackware_version)/CHECKSUMS.md5 $(CWD)/manifests/$(slackware)-$(slackware_version)/CHECKSUMS.md5.asc $(CWD)/manifests/$(slackware)-$(slackware_version)/MANIFEST.bz2
SHELL=/bin/bash

/etc/ssl/certs/ca-certificates.crt: /etc/ca-certificates.conf
	/usr/sbin/update-ca-certificates --verbose --fresh

/etc/ca-certificates.conf: $(CWD)/newconfs/ca-certificates.conf.new FORCE
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
	umask 022; for i in /etc/ssl/certs/????????.*; do crls=($$(openssl x509 -in "$${i}" -noout -ext crlDistributionPoints 2>/dev/null | sed -n 's/^\s\+URI:\(http.\+$$\)/\1/p')); [ $${#crls[*]} -eq 1 -a -n "$${crls[0]}" ] && { wget -nv "$${crls[0]}" -O "$${i/./.r}"; openssl crl -in "$${i/./.r}" -inform DER -CAfile "$${i}" -noout; }; done

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

/etc/audit/rules.d/31-privileged.rules:
	find /bin -type f -perm -04000 2>/dev/null | awk '{ printf "-a always,exit -F path=%s -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged\n", $$1 }' > $@
	find /sbin -type f -perm -04000 2>/dev/null | awk '{ printf "-a always,exit -F path=%s -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged\n", $$1 }' >> $@
	find /usr/bin -type f -perm -04000 2>/dev/null | awk '{ printf "-a always,exit -F path=%s -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged\n", $$1 }' >> $@
	find /usr/sbin -type f -perm -04000 2>/dev/null | awk '{ printf "-a always,exit -F path=%s -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged\n", $$1 }' >> $@
	filecap /bin 2>/dev/null | sed '1d' | awk '{ printf "-a always,exit -F path=%s -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged\n", $$1 }' >> $@
	filecap /sbin 2>/dev/null | sed '1d' | awk '{ printf "-a always,exit -F path=%s -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged\n", $$1 }' >> $@
	filecap /usr/bin 2>/dev/null | sed '1d' | awk '{ printf "-a always,exit -F path=%s -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged\n", $$1 }' >> $@
	filecap /usr/sbin 2>/dev/null | sed '1d' | awk '{ printf "-a always,exit -F path=%s -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged\n", $$1 }' >> $@

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

.PHONY: manifest
manifest: $(manifest_files)

.PHONY: manifest-suid-diff
manifest-suid-diff: manifests/slackware64-14.2/MANIFEST.bz2 manifests/slackware64-current/MANIFEST.bz2
	-diff <(bzgrep -i '^[^d].\{2\}\(s\|.\{3\}s\)' $< | gawk '{print$$1,$$2,$$6}' | sort) <(bzgrep -i '^[^d].\{2\}\(s\|.\{3\}s\)' $(word 2,$^) | gawk '{print$$1,$$2,$$6}' | sort)
