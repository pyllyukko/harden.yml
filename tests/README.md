Tests
=====

Lint
----

<https://github.com/pyllyukko/harden.yml/actions/workflows/lint.yml>

Linting with:

* [ansible-lint](https://github.com/marketplace/actions/run-ansible-lint)
* `yamllint`
* `ansible-playbook --syntax-check`

Molecule
--------

Molecule is ran against [Debian](https://hub.docker.com/_/debian), [Slackware](https://hub.docker.com/r/pyllyukko/slackware) & [Kali](https://www.kali.org/docs/containers/official-kalilinux-docker-images/) Docker images.

### Limitations

* Certain hardenings like `kernel` & `network` are not tested
* Debian-based containers do not have systemd, so anything related to systemd can't be tested

ShellCheck
----------

<https://github.com/pyllyukko/harden.yml/actions/workflows/shellcheck.yml>

[ShellCheck](https://www.shellcheck.net/) is ran against few scripts.

PAM
---

<https://github.com/pyllyukko/harden.yml/actions/workflows/pam.yml>

The following PAM tests are executed:

* Various tests with [pamtester](https://pamtester.sourceforge.net/)
* Various tests with [libpamtest](https://cwrap.org/pam_wrapper.html) (cwrap)
    * See [#61](https://github.com/pyllyukko/harden.yml/issues/61)
* Tracking few upstream PAM configurations for changes in case we need to adapt/react to some change

### Limitations

Anything `auth` can't be tested with `pamtester`, because there's no way to enter password with `pamtester` (hence the additional tests with [libpamtest](https://cwrap.org/pam_wrapper.html)).

ca-certs
--------

<https://github.com/pyllyukko/harden.yml/actions/workflows/ca-certs.yml>

* Check that all certificates in [ca-certificates.conf.new](https://github.com/pyllyukko/harden.yml/blob/master/newconfs/ca-certificates.conf.new) still exist
* Make a limited amount of TLS connection tests against various hosts to see that the limited CA list works as expected (see [test\_ca-certs.sh](https://github.com/pyllyukko/harden.yml/blob/master/tests/test_ca-certs.sh))
* Test the CRL download functionality (`make crls`)

### Limitations

The `ca-certs` package in the [GitHub Ubuntu runner](https://github.com/actions/runner-images?tab=readme-ov-file#available-images) doesn't seem to be updated as often as in Slackware.
