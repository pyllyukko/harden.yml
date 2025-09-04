Tests
=====

Lint
----

<https://github.com/pyllyukko/harden.yml/actions/workflows/lint.yml>

Linting with:

* [ansible-lint](https://github.com/marketplace/actions/run-ansible-lint)
* `yamllint`
* `ansible-playbook --syntax-check`

ansible-playbook
----------------

[ansible-playbook tests](https://github.com/pyllyukko/harden.yml/actions/workflows/ansible-playbook.yml) against the GitHub Ubuntu Runner. Even though Ubuntu is not "officially" supported by `harden.yml`, but this enables us to test kernel stuff and the installation is more comprehensive than the Molecule Docker containers.

The tests are split based on [Lynis](https://cisofy.com/lynis/) test categories. The tests measure the [Lynis hardening index](https://linux-audit.com/lynis/lynis-hardening-index/) and will fail if the hardening index is under defined threshold (see [check\_lynis\_score.sh](https://github.com/pyllyukko/harden.yml/blob/master/tests/check_lynis_score.sh)). Certain Lynis test categories are not scored properly, so the threshold is not possible for all categories.

The following Lynis test groups should produce a score of :100::

* accounting
* authentication
* shells
* hardening (this is tested together with malware)
* mac\_frameworks
* file\_integrity
* storage

The tests will also run `debsums` to show which files have been changed from the hardening.

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

* Tracking few upstream PAM configurations for changes in case we need to adapt/react to some change
* Test polyinstantiation

### pamtester

#### Pre-harden

Before hardening, test that some actions are allowed in default configuration:

* All users are allowed to use `cron`
* All users are allowed to use `at`
* Nonexistent services are not properly restricted
* System accounts are able to login
    * Of course there is still authentication, but for defence in depth it should also be prohibited within PAM's `account` (authorization) and `session` types

#### Post-harden

* Test 1: Verify that use of `cron` is restricted via PAM's `account` (authorization) (with `pam_access`)
    * Test 2: Check that `root` can still use `cron`
* Test 3: Verify that use of `at` is restricted
* Test 4: Verify that use of `su` is restricted
    * This can't be tested pre-harden as it prompts for password. `su` is usually allowed in default configuration.
* Test 5: Verify that nonexistent services are properly restricted via `/etc/pam.d/other`
* Test 5: Verify that login is properly restricted for system users and other random accounts

#### Limitations

Anything `auth` can't be tested with `pamtester`, because there's no way to enter password with `pamtester` (hence the additional tests with [libpamtest](https://cwrap.org/pam_wrapper.html)).

### libpamtest

Various tests with [libpamtest](https://cwrap.org/pam_wrapper.html) (cwrap). See [#61](https://github.com/pyllyukko/harden.yml/issues/61).

#### Setup and testing the baseline/defaults

* Round 1: Test that authentication with `root` fails as `pam_matrix` is not yet in use
    * Test that login with empty password is possible
* Prepare the test environment with [pamtests.yml](pamtests.yml)

Round 2:

| Test # | Service | Facility/type | User account    | Description                                            | Expected result |
| ------ | ------- | ------------- | --------------- | ------------------------------------------------------ | --------------- |
| 1      | `login` | `auth`        | `root`          | Regular login                                          | `PAM_SUCCESS`   |
| 2      | `login` | `account`     | Invalid account | Regular login with invalid account                     | `PAM_AUTH_ERR`  |
| 3      | `login` | `account`     | `root`          | Regular login                                          | `PAM_SUCCESS`   |
| 4      | `cron`  | `account`     | `root`          | Using `cron`                                           | `PAM_SUCCESS`   |
| 5      | `cron`  | `account`     | `nobody`        | Using `cron` as other user                             | `PAM_SUCCESS`   |
| 6-1    | `login` | `auth`        | `nobody`        | Regular login as other user                            | `PAM_SUCCESS`   |
| 6-2    | `login` | `auth`        | `nobody`        | Regular login as other user when `/etc/nologin` exists | [PAM\_AUTH\_ERR](https://github.com/linux-pam/linux-pam/blob/cfe667baa301ffa136a713b0ae22ba0ef493aa48/modules/pam_nologin/pam_nologin.c#L93) |
| 7      | `su`    | `auth`        | `nobody`        | Using `su`                                             | `PAM_SUCCESS`   |
| 8      | `login` | `auth`        | `root`          | Login with invalid password                            | `PAM_AUTH_ERR`  |

#### Post-harden

| Test #  | Service | Facility/type | User account    | Description                                                        | Expected result   |
| ------- | ------- | ------------- | --------------- | ------------------------------------------------------------------ | ----------------- |
| 2       | `login` | `account`     | Invalid account | Regular login with invalid account                                 | `PAM_AUTH_ERR`    |
| 5       | `cron`  | `account`     | `nobody`        | Using `cron` as other user                                         | [PAM\_PERM\_DENIED](https://github.com/linux-pam/linux-pam/blob/cfe667baa301ffa136a713b0ae22ba0ef493aa48/modules/pam_access/pam_access.c#L1261) |
| 7-1     | `su`    | `auth`        | `nobody`        | Using `su`                                                         | `PAM_AUTH_ERR`    |
| 7-2     | `su`    | `auth`        | `root`          | Using `su` as `root`                                               | `PAM_SUCCESS`     |
| 1       | `login` | `auth`        | `root`          | Regular login                                                      | `PAM_SUCCESS`     |
| 8-[123] | `login` | `auth`        | `root`          | Login with invalid password 3 times                                | `PAM_PERM_DENIED` |
| 1       | `login` | `auth`        | `root`          | Login with valid password. Temporarily locked by `pam_faillock`.   | [PAM\_AUTH\_ERR](https://github.com/linux-pam/linux-pam/blob/cfe667baa301ffa136a713b0ae22ba0ef493aa48/modules/pam_faillock/pam_faillock.c#L269) |
| 8-4     | `login` | `auth`        | `root`          | Login with invalid password. Test `pam_faildelay`.               . | `PAM_PERM_DENIED` |
| 9       | `login` | `auth`        | `nobody`        | Login with empty password.                                         | `PAM_AUTH_ERR`    |

### Limits

* Test `pam_limits` `RLIMIT_NPROC` restriction
* Test `pam_limits` [core dump](https://en.wikipedia.org/wiki/Core_dump) limitation

ca-certs
--------

<https://github.com/pyllyukko/harden.yml/actions/workflows/ca-certs.yml>

* Check that all certificates in [ca-certificates.conf.new](https://github.com/pyllyukko/harden.yml/blob/master/newconfs/ca-certificates.conf.new) still exist
* Make a limited amount of TLS connection tests against various hosts to see that the limited CA list works as expected (see [test\_ca-certs.sh](https://github.com/pyllyukko/harden.yml/blob/master/tests/test_ca-certs.sh))
* Test the CRL download functionality (`make crls`)

### Limitations

The `ca-certs` package in the [GitHub Ubuntu runner](https://github.com/actions/runner-images?tab=readme-ov-file#available-images) doesn't seem to be updated as often as in Slackware.
