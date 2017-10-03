tests = bash_syntax debian_pam
CWD = $(realpath $(dir $(lastword $(MAKEFILE_LIST))))
slackware = slackware64
slackware_version = 14.2
manifest_files = $(CWD)/manifests/$(slackware)-$(slackware_version)/CHECKSUMS.md5 $(CWD)/manifests/$(slackware)-$(slackware_version)/CHECKSUMS.md5.asc $(CWD)/manifests/$(slackware)-$(slackware_version)/MANIFEST.bz2

.PHONY: tests
tests: $(tests)

.PHONY: debian_pam
debian_pam:
	bash $(CWD)/tests/test_debian_pam.sh

.PHONY: bash_syntax
bash_syntax:
	bash -O extglob -n $(CWD)/harden.sh
	$(foreach i,$(wildcard $(CWD)/libexec/*.sh),bash -n $(i);)

/etc/ssl/certs/ca-certificates.crt: /etc/ca-certificates.conf
	/usr/sbin/update-ca-certificates --verbose --fresh

/etc/ca-certificates.conf: $(CWD)/newconfs/ca-certificates.conf.new FORCE
	/usr/bin/install -m 644 $< $@

FORCE:

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
