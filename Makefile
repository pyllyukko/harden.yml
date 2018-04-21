tests = bash_syntax debian_pam sysstat
CWD = $(realpath $(dir $(lastword $(MAKEFILE_LIST))))
slackware = slackware64
slackware_version = 14.2
manifest_files = $(CWD)/manifests/$(slackware)-$(slackware_version)/CHECKSUMS.md5 $(CWD)/manifests/$(slackware)-$(slackware_version)/CHECKSUMS.md5.asc $(CWD)/manifests/$(slackware)-$(slackware_version)/MANIFEST.bz2
SHELL=/bin/bash

.PHONY: tests
tests: $(tests)

.PHONY: debian_pam
debian_pam:
	bash $(CWD)/tests/test_debian_pam.sh

.PHONY: sysstat
sysstat:
	bash $(CWD)/tests/test_sysstat.sh

.PHONY: bash_syntax
bash_syntax:
	bash -O extglob -n $(CWD)/harden.sh
	$(foreach i,$(wildcard $(CWD)/libexec/*.sh),bash -n $(i);)

/etc/ssl/certs/ca-certificates.crt: /etc/ca-certificates.conf
	/usr/sbin/update-ca-certificates --verbose --fresh

/etc/ca-certificates.conf: $(CWD)/newconfs/ca-certificates.conf.new FORCE
	/usr/bin/install -m 644 $< $@

/etc/motd: $(CWD)/newconfs/motd.new FORCE
	/usr/bin/install -m 644 $< $@

/etc/issue: FORCE
	@echo "Authorized uses only. All activity may be monitored and reported." 1>$@
	@chmod -c 644 $@

/etc/issue.net: /etc/issue
	@cp -vf $< $@

/etc/profile.d/tmout.sh: $(CWD)/newconfs/profile.d/tmout.sh.new FORCE
	/usr/bin/install -m 755 $< $@

/etc/profile.d/umask.sh: $(CWD)/newconfs/profile.d/umask.sh.new FORCE
	/usr/bin/install -m 755 $< $@

.PHONY: pam-configs
pam-configs: /usr/share/pam-configs/tally2 /usr/share/pam-configs/access /usr/share/pam-configs/polyinstation /usr/share/pam-configs/lastlog /usr/share/pam-configs/umask /usr/share/pam-configs/faildelay /usr/share/pam-configs/pwhistory

/usr/share/pam-configs/%: $(CWD)/newconfs/pam-configs/%.new | /usr/share/pam-configs/
	/usr/bin/install -m 644 $< $@

.PHONY: FORCE
FORCE:

define make-moduli-candidates-target
$1: /etc/ssh/moduli-$1.candidates
/etc/ssh/moduli-$1.candidates:
	ssh-keygen -G $$@ -b $1
endef
# 1024 is only for testing, it is not included in the final moduli
bits := 1024 2048 3072 4096 6144 7680 8192
modulis := /etc/ssh/moduli-2048 /etc/ssh/moduli-3072 /etc/ssh/moduli-4096 /etc/ssh/moduli-6144 /etc/ssh/moduli-7680 /etc/ssh/moduli-8192
$(foreach l,$(bits),$(eval $(call make-moduli-candidates-target,$l)))

/etc/ssh/moduli-%: /etc/ssh/moduli-%.candidates
	ssh-keygen -T $@ -f $< && rm -v $<

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

/etc/audit/audit.rules: FORCE
	/sbin/augenrules

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

/etc/rc.local.new: $(CWD)/newconfs/debian/rc.local.new FORCE
	/usr/bin/install -m 700 $< $@

/etc/modprobe.d/%: $(CWD)/newconfs/modprobe.d/%.new FORCE
	/usr/bin/install -m 600 $< $@

/etc/%: /etc/%.new
	if [ -f $@ ]; then cmp $@ $< && rm -v $< || true; else mv -v $< $@; fi

# TODO: chmod in debian is in /bin
/var/log/pacct:
	/usr/bin/touch $@
	/usr/bin/chmod -c 640 $@
	/usr/bin/chgrp adm $@

/etc/sysctl.d/harden.conf: $(CWD)/newconfs/sysctl.d/sysctl.conf.new FORCE | /etc/sysctl.d
	/usr/bin/install -m 600 $< $@

$(CWD)/manifests/$(slackware)-$(slackware_version)/:
	mkdir -pv $@

$(CWD)/manifests/$(slackware)-$(slackware_version)/CHECKSUMS.md5: $(CWD)/manifests/$(slackware)-$(slackware_version)/CHECKSUMS.md5.asc FORCE | $(CWD)/manifests/$(slackware)-$(slackware_version)/
	-wget -nv -nc -O $@ ftp://ftp.slackware.com/pub/slackware/$(slackware)-$(slackware_version)/$(slackware)/$(notdir $@)
	cd $(CWD)/manifests/$(slackware)-$(slackware_version) && gpgv CHECKSUMS.md5.asc CHECKSUMS.md5

# TODO: list keys used in the .asc
$(CWD)/manifests/$(slackware)-$(slackware_version)/CHECKSUMS.md5.asc: | $(CWD)/manifests/$(slackware)-$(slackware_version)/
	wget -nv -nc -O $@ ftp://ftp.slackware.com/pub/slackware/$(slackware)-$(slackware_version)/$(slackware)/$(notdir $@)

$(CWD)/manifests/$(slackware)-$(slackware_version)/MANIFEST.bz2: $(CWD)/manifests/$(slackware)-$(slackware_version)/CHECKSUMS.md5 FORCE | $(CWD)/manifests/$(slackware)-$(slackware_version)/
	-wget -nv -nc -O $@ ftp://ftp.slackware.com/pub/slackware/$(slackware)-$(slackware_version)/$(slackware)/$(notdir $@)
	cd $(CWD)/manifests/$(slackware)-$(slackware_version) && fgrep "MANIFEST.bz2" CHECKSUMS.md5 | /bin/md5sum -c

.PHONY: manifest
manifest: $(manifest_files)
