tests = bash_syntax debian_pam
CWD = $(realpath $(dir $(lastword $(MAKEFILE_LIST))))

.PHONY: tests
tests: $(tests)

.PHONY: debian_pam
debian_pam:
	bash $(CWD)/tests/test_debian_pam.sh

.PHONY: bash_syntax
bash_syntax:
	bash -O extglob -n $(CWD)/harden.sh
	$(foreach i,$(wildcard $(CWD)/libexec/*.sh),bash -n $(i);)
