tests = bash_syntax debian_pam

.PHONY: tests
tests: $(tests)

.PHONY: debian_pam
debian_pam:
	bash tests/test_debian_pam.sh

.PHONY: bash_syntax
bash_syntax:
	bash -O extglob -n harden.sh
