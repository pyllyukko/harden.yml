harden.yml :lock:
==========

Ansible playbook to harden your Linux system.

[![lint](https://github.com/pyllyukko/harden.yml/actions/workflows/lint.yml/badge.svg)](https://github.com/pyllyukko/harden.yml/actions/workflows/lint.yml)

[![asciicast of harden.yml 1294b6f](https://asciinema.org/a/spPzbjtEal2LiOKNQKFORQ1Ay.svg)](https://asciinema.org/a/spPzbjtEal2LiOKNQKFORQ1Ay)

Supported distros
-----------------

[![molecule](https://github.com/pyllyukko/harden.yml/actions/workflows/molecule.yml/badge.svg)](https://github.com/pyllyukko/harden.yml/actions/workflows/molecule.yml)

* :book::worm: Debian (Bookworm)
    * :dragon: Kali
    * π Raspberry Pi OS
* Slackware (>= [15.0](http://www.slackware.com/announce/15.0.php))

:question: Why I made this
---------------

* [Bastille](http://bastille-linux.sourceforge.net/) is obsolete
* Not a member of [CIS](http://www.cisecurity.org/), so no downloading of the ready made scripts
* For learning
* For minimizing the effort needed to tweak fresh installations
    * Also for consistency

:question: What does it do?
----------------

For a complete list you can run `ansible-playbook --list-tasks harden.yml`.

### Network

* Enables [TCP wrappers](https://en.wikipedia.org/wiki/TCP_Wrapper)
    * :bulb: Some people consider TCP wrappers as obsolete and unnecessary, because nowadays firewall(s) take care of this kind of network level access. I disagree, because TCP wrappers still provide an additional layer of control in a case where the firewall(s) might fail for any number of reasons (usually misconfiguration). TCP wrappers also work as an network level ACL for the programs that utilize it and is a "native" control for those programs.
* IP stack hardening via [sysctl](https://en.wikipedia.org/wiki/Sysctl) settings
    * For the complete list, see [network.conf.new](newconfs/sysctl.d/network.conf.new)
* Creates a basic firewall

### :wood: Logging

* :calendar: Configure log retention time to be 6 months
* Configures `logrotate` to `shred` files
    * :information_source: **NOTE**: Read the fine print in [SHRED(1)](https://www.man7.org/linux/man-pages/man1/shred.1.html): "CAUTION: shred assumes the file system and hardware overwrite data in place.  Although this is common, many platforms operate otherwise."
* Run `ansible-playbook --list-tasks --tags logging harden.yml` for a full list

### :bar_chart: Accounting

* Enables system accounting ([sysstat](http://sebastien.godard.pagesperso-orange.fr/))
    * :calendar: Sets it's log retention to 99999 days (the logs are really small, so it doesn't eat up disk space)
* Enables [process accounting](https://tldp.org/HOWTO/Process-Accounting/)
* Run `ansible-playbook --list-tasks --tags accounting harden.yml` for a full list

### Kernel

* :no_entry: Disables the use of certain kernel modules via `modprobe` (see [newconfs/modprobe.d/](newconfs/modprobe.d/))
    * Disable [Firewire](http://www.hermann-uwe.de/blog/physical-memory-attacks-via-firewire-dma-part-1-overview-and-mitigation)
    * :warning: **WARNING**: Also disables `usb-storage`, which will disable support for USB mass medias
* [sysctl](https://en.wikipedia.org/wiki/Sysctl) settings hardening
    * :keyboard: Enables [SAK](https://www.kernel.org/doc/Documentation/SAK.txt) and disables the other [magic SysRq stuff](https://www.kernel.org/doc/Documentation/sysrq.txt)
    * :no_entry: Restricts the use of `dmesg` by regular users
    * :no_entry: Enable [YAMA](https://www.kernel.org/doc/Documentation/security/Yama.txt) (disallow `ptrace`)
    * For the complete list, see [sysctl.conf.new](newconfs/sysctl.d/sysctl.conf.new)
* Run `ansible-playbook --list-tasks --tags kernel harden.yml` for a full list

### :file_folder: Filesystem

* Hardens mount options (creates `/etc/fstab.new`) (see [fstab.awk](files/fstab.awk))
* :house: Sets strict permissions to users home directories
* :no_entry: Limits permissions to various configuration files and directories that might contain sensitive content (see `permissions` tag for a complete list)
* :do_not_litter: Clean up `/tmp` during boot (see [tmp.conf.new](newconfs/tmp.conf.new))
* Removes SUID and/or SGID bits from various binaries (see `ansible-playbook --list-tasks --tags suid,sgid harden.yml` for details)

### Application specific

* Configures basic auditing based on [stig.rules](https://fedorahosted.org/audit/browser/trunk/contrib/stig.rules) if audit is installed (see [audit.yml](tasks/audit.yml))
    * See also <https://github.com/pyllyukko/harden.yml/wiki/audit>
* :blowfish: Configures `sshd_config` and `ssh_config` (see `ansible-playbook --list-tasks --tags ssh harden.yml` for details)
    * Removes 2048-bit moduli from `/etc/ssh/moduli`
    * :information_source: Removes SUID bit from `ssh-keysign`, so host-based authentication will stop working. Host-based authentication shouldn't be used anyway.
* :sandwich: Configures [sudo](https://www.sudo.ws/) (see [sudoers.j2](templates/sudoers.j2))
    * :warning: **WARNING**: If there are rules in `/etc/sudoers.d/` that match our `become: true` tasks that do not have explicit `EXEC`, it can "break" `sudo` as we define `Defaults noexec` in the main `sudoers` file. There is a "Fix NOPASSWD rules" task in `sudoers.yml` which tries to tackle this problem, but it's not guaranteed to work.
    * :wood: You can set the `sudo_iolog` in `vars.yml` to `true` to enable I/O logging
    * You can set the `sudo_ids` in `vars.yml` to `true` to enable "Intrusion Detection" as described in [Sudo Mastery](#other-docs) chapter 9 ([#59](https://github.com/pyllyukko/harden.yml/issues/59))
    * See also [notes](#information_source-notes)
* :smiling_imp: [ClamAV](https://www.clamav.net/) configuration (see [clamav.yml](tasks/clamav.yml))
    * Configures `clamd` & `freshclam` by first generating fresh configurations with [clamconf](https://docs.clamav.net/manual/Usage/Configuration.html#clamconf)
    * Configured ClamAV to unarchive with password "infected" (see [Passwords for archive files](https://docs.clamav.net/manual/Signatures/EncryptedArchives.html) & [ClamAV and ZIP File Decryption](https://blog.didierstevens.com/2017/02/15/quickpost-clamav-and-zip-file-decryption/))
    * Downloads YARA rules from [Neo23x0](https://github.com/Neo23x0/signature-base), [GCTI](https://github.com/chronicle/GCTI), [Elastic](https://github.com/elastic/protections-artifacts), [YaraRules Project](https://yara-rules.github.io/blog/), [JPCERT/CC](https://github.com/JPCERTCC/jpcert-yara), [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/), [Citizen Lab](https://github.com/citizenlab/malware-signatures), [GoDaddy](https://github.com/godaddy/yara-rules), [Didier Stevens](https://github.com/search?q=repo%3ADidierStevens%2FDidierStevensSuite+path%3A*.yara) & [Open-Source-YARA-rules](https://github.com/mikesxrs/Open-Source-YARA-rules) for [ClamAV to use](https://docs.clamav.net/manual/Signatures/YaraRules.html)
    * :warning: **WARNING**: ClamAV consumes a lot of memory, so it might not be suitable for all systems. See [Recommended System Requirements](https://docs.clamav.net/#recommended-system-requirements).
* [rkhunter](https://sourceforge.net/projects/rkhunter/) configuration (see [rkhunter.yml](tasks/rkhunter.yml))
* :tiger: [Tiger](https://www.nongnu.org/tiger/): Configures `tigerrc` & `tiger.ignore`
* [Lynis](https://cisofy.com/lynis/) configuration (see [lynis.yml](tasks/lynis.yml))
* Configures AIDE (see [aide.yml](tasks/aide.yml))
* Display managers:
    * Disables user lists in GDM3 & LightDM
    * :no_entry: Disables guest sessions and VNC in LightDM
* :feather: Minor Apache HTTP server hardening
* Minor PHP (`php.ini`) hardening

### User accounts / authentication / authorization

* Sets default [umask](https://en.wikipedia.org/wiki/Umask) to a more stricter `077` (see <https://github.com/pyllyukko/harden.yml/wiki/umask>)
* :timer_clock: Sets console session timeout via `$TMOUT` (Bash)
* 🎟️ Properly locks down system accounts (0 - `SYS_UID_MAX` && !`root`)
    * :no_entry: Lock the user's password
    * :shell: Sets shell to `/sbin/nologin`
    * Expire the account
    * :no_entry: Set `RLIMIT_NPROC` to `0` in [pam\_limits](#pam) for those system accounts that don't need to run any processes
* 🎟️ Configures the default password inactivity period
    * Run `ansible-playbook --list-tasks --tags passwords harden.yml` to list all password related tasks
* :busts_in_silhouette: Makes minor modifications to existing accounts. See `ansible-playbook --list-tasks --tags accounts harden.yml` for details.

#### 🎟️ Authorization

* Create a strict `securetty`
    * See [securetty in Debian #47](https://github.com/pyllyukko/harden.yml/issues/47)
* Creates `/etc/ftpusers`
* Restricts the use of [cron](https://en.wikipedia.org/wiki/Cron) and `at`
* Run `ansible-playbook --list-tasks --tags authorization` for a full list

#### PAM

* Configures `/etc/security/namespace.conf`
* 🎟️ Configures `/etc/security/access.conf` for `pam_access` (authorization) (see [access.conf.j2](templates/access.conf.j2))
* Configures `/etc/security/pwquality.conf` if available
* 🛞 Require [pam\_wheel](http://linux-pam.org/Linux-PAM-html/sag-pam_wheel.html) in `/etc/pam.d/su`
* :no_entry: Creates a secure [/etc/pam.d/other](http://linux-pam.org/Linux-PAM-html/sag-security-issues-other.html)
    * See also [A strong /etc/pam.d/other](https://tldp.org/HOWTO/html_single/User-Authentication-HOWTO/#AEN266)
* Configures `/etc/security/limits.conf` as follows:
    * Disable [core dumps](https://en.wikipedia.org/wiki/Core_dump)
    * Sets maximum amount of processes (or threads, see [setrlimit(2)](https://man7.org/linux/man-pages/man2/setrlimit.2.html))
    * :no_entry: Sets `nproc` to 0 for system users that don't need to run any processes
* Run `ansible-playbook --list-tasks --tags pam harden.yml` to list all PAM related tasks
* You can also run `ansible-playbook --check --diff --tags pam harden.yml` to see details of the changes
* [![pam](https://github.com/pyllyukko/harden.yml/actions/workflows/pam.yml/badge.svg)](https://github.com/pyllyukko/harden.yml/actions/workflows/pam.yml)

### Miscellaneous

* :placard: Creates legal banners (see [banners.yml](tasks/banners.yml))
* Reduce the amount of trusted [CAs](https://en.wikipedia.org/wiki/Certificate_authority) (see [ca-certificates.conf.new](newconfs/ca-certificates.conf.new))
    * [![ca-certs](https://github.com/pyllyukko/harden.yml/actions/workflows/ca-certs.yml/badge.svg)](https://github.com/pyllyukko/harden.yml/actions/workflows/ca-certs.yml)
    * You can also run `make /etc/ssl/certs/ca-certificates.crt` to update the CAs
* :shell: Restricts the number of available shells (`/etc/shells`)
* :shell: Creates an option to use a [restricted shell](https://en.wikipedia.org/wiki/Restricted_shell) ([rbash](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html))
    * Only available for Debian & Slackware and for the `sshd` service because of the required PAM configuration changes (regarding `pam_env` & enforcing `PATH`)
    * :information_source: See [Restricted shell](https://github.com/pyllyukko/harden.yml/wiki/Restricted-shell)
    * :warning: **WARNING**: Contains plenty of caveats, details and hazards. Make sure you read and understand (at least) everything in the aforementioned [wiki page](https://github.com/pyllyukko/harden.yml/wiki/Restricted-shell), test it thoroughly and accept the risk that it may contain escapes.

### Slackware specific

* Run `ansible-playbook --list-tasks --tags slackware harden.yml` for a full list
* Make Xorg rootless
* :wood: Makes default log files group `adm` readable ([as in Debian](http://www.debian.org/doc/manuals/debian-reference/ch01.en.html#listofnotablesysupsforfileaccess))
* 🛞 Restricts the use of `cron` so that only users in the [wheel](https://en.wikipedia.org/wiki/Wheel_(computing)) group are able to create cronjobs (as described in [/usr/doc/dcron-4.5/README](http://www.jimpryor.net/linux/dcron-README))
* Mount [/proc](https://www.kernel.org/doc/Documentation/filesystems/proc.txt) with `hidepid=2`
* :wood: Make `installpkg` store the MD5 checksums
* :bar_chart: Enable [process accounting](https://tldp.org/HOWTO/Process-Accounting/) (`acct`)
* :busts_in_silhouette: Does some housekeeping regarding group memberships (see [login\_defs-slackware.yml](tasks/login_defs-slackware.yml))
* 🎟️ Configures `inittab` to use `shutdown -a` (and `/etc/shutdown.allow`)
* Reconfigured bunch of services (run `ansible-playbook --list-tasks --tags slackware harden.yml | grep '\bservices\b'` for a full list)
* Configures cgroups ([v1](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v1/cgroups.html), because of too old `libcgroup`) into `/etc/cg{config,rules}.conf`
* Enables `bootlogd`
    * :information_source: **NOTE**: Requires `CONFIG_LEGACY_PTYS` (which [KSPP recommends to disable](https://www.kernsec.org/wiki/index.php/Kernel_Self_Protection_Project/Recommended_Settings))

#### PAM

* Creates a custom `/etc/pam.d/system-auth`, which has the following changes:
    * :timer_clock: Use `pam_faildelay`
    * 🎟️ Use `pam_faillock`
    * 🎟️ Use `pam_access`
    * :no_entry: Removes `nullok` from `pam_unix`
    * Sets crypt rounds for `pam_unix`
    * Change password `minlen` from 6 to 14
    * See [system-auth.j2](templates/system-auth.j2)
* The following PAM modules are added to `/etc/pam.d/postlogin`:
    * `pam_umask`
    * `pam_cgroup`
    * `pam_keyinit`
* Add `pam_namespace` to `/etc/pam.d/{login,sddm,sshd,xdm}`
* Removes `auth include postlogin` from several files, as `postlogin` should (and has) only `session` module types
* :sandwich: Creates `/etc/pam.d/sudo`, as that seemed to be missing
* 🎟️ Disallows the use of `su` (see [su.new](newconfs/pam.d/su.new))
* :no_entry: [Block](newconfs/pam.d/other.new) `/etc/pam.d/remote` (see [/etc/pam.d/remote](https://github.com/pyllyukko/harden.yml/wiki/PAM#etcpamdremote))

### Debian specific

* Disables unnecessary systemd services
* :shield: Enables AppArmor
* Configure `SUITE` in `debsecan`
* Install `debsums` and enable weekly cron job
* Installs a bunch of security related packages (see [debian\_packages.yml](tasks/debian_packages.yml))
* Configures `chkrootkit` and enables daily checks
* Configures APT not to install suggested packages

#### pam-configs

Creates bunch of `pam-config`s that are toggleable with `pam-auth-update`:

| PAM module                                                                                            | Type           | Description                                                                             |
| ----------------------------------------------------------------------------------------------------- | -------------- | --------------------------------------------------------------------------------------- |
| 🛞 [pam\_wheel](http://www.linux-pam.org/Linux-PAM-html/sag-pam_wheel.html)[<sup>1</sup>](#fn1)       | auth           | Require `wheel` group membership (`su`)                                                 |
| 🎟️ [pam\_succeed\_if](http://www.linux-pam.org/Linux-PAM-html/sag-pam_succeed_if.html)                | auth & account | Require UID >= 1000 && UID <= 60000 (or 0 & `login`)                                    |
| :no_entry: [pam\_unix](http://www.linux-pam.org/Linux-PAM-html/sag-pam_unix.html)[<sup>1</sup>](#fn1) | auth           | Remove `nullok`                                                                         |
| :timer_clock: [pam\_faildelay](http://www.linux-pam.org/Linux-PAM-html/sag-pam_faildelay.html)        | auth           | Delay on authentication failure                                                         |
| [pam\_ssh\_agent\_auth](https://pamsshagentauth.sourceforge.net/)                                     | auth           | SSH agent authentication for sudo[<sup>3</sup>](#fn3)                                   |
| 🎟️ `pam_faillock`                                                                                     | auth & account | Deter brute-force attacks                                                               |
| 🎟️ [pam\_access](http://linux-pam.org/Linux-PAM-html/sag-pam_access.html)                             | account        | Use login ACL (`/etc/security/access.conf`)                                             |
| 🎟️ [pam\_time](http://www.linux-pam.org/Linux-PAM-html/sag-pam_time.html)                             | account        | `/etc/security/time.conf`                                                               |
| 🎟️ [pam\_lastlog](http://www.linux-pam.org/Linux-PAM-html/sag-pam_lastlog.html)                       | account        | Lock out inactive users (no login in 90 days)                                           |
| [pam\_namespace](http://www.linux-pam.org/Linux-PAM-html/sag-pam_namespace.html)                      | session        | Polyinstantiated temp directories                                                       |
| [pam\_umask](http://www.linux-pam.org/Linux-PAM-html/sag-pam_umask.html)                              | session        | Set file mode creation mask                                                             |
| [pam\_lastlog](http://www.linux-pam.org/Linux-PAM-html/sag-pam_lastlog.html)                          | session        | Display info about last login and update the lastlog and wtmp files[<sup>2</sup>](#fn2) |
| [pam\_pwhistory](http://www.linux-pam.org/Linux-PAM-html/sag-pam_pwhistory.html)                      | password       | Limit password reuse                                                                    |

1. <span id="fn1"/>Not a `pam-config`, but a modification to existing `/etc/pam.d/` files
2. <span id="fn2"/>For all login methods and not just the console login
3. <span id="fn3"/>Disabled by default and requires [libpam-ssh-agent-auth](https://packages.debian.org/sid/libpam-ssh-agent-auth) package. Needs to have higher priority than `krb5` or other password auths.
    * `sshd` needs to have `AllowAgentForwarding yes`
    * You need to configure `sudo` with `Defaults env_keep += "SSH_AUTH_SOCK"`

Usage
-----

* Edit the `harden.yml` and modify `hosts` or create a completely new playbook by making a copy of the `harden.yml` file
    * You can comment out the "task sets" that you don't need
* Check `vars.yml` in case you want to tweak some of the settings
* You can check all the tasks before running the playbook by running `ansible-playbook --list-tasks harden.yml`
* Harden your system by running `ansible-playbook harden.yml`
    * You might need to provide credentials with [-K](https://docs.ansible.com/ansible/latest/cli/ansible-playbook.html#common-options) or via [inventory](https://docs.ansible.com/ansible/latest/user_guide/intro_inventory.html)

### :information_source: Notes

* :busts_in_silhouette: Make sure regular users that should be able to login are members of the `allowed_group` group
* :sandwich: Sudo hardening:
    * `noexec` is on by default, so you need to take this into account in your custom rules
    * :timer_clock: Interactive shells to `root` have timeout, so use `screen` for those longer administrative tasks
* :arrows_counterclockwise: Rebooting the system after running this is highly recommended
* The AIDE DB creation is made [asynchronously](https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_async.html) and without polling, so let that finish before rebooting
* :bulb: You might want to get additional (unofficial) rules for ClamAV with [clamav-unofficial-sigs](https://github.com/extremeshok/clamav-unofficial-sigs) (although see [#425](https://github.com/extremeshok/clamav-unofficial-sigs/issues/425)). At least the following rulesets are freely available:
    * [Sanesecurity](https://sanesecurity.com/usage/signatures/)
        * Porcupine ("The following databases are distributed by Sanesecurity, but produced by Porcupine Signatures")
        * bofhland ("The following databases are distributed by Sanesecurity, but produced by bofhland")
        * [Foxhole](https://sanesecurity.com/foxhole-databases/)
    * [Linux Malware Detect](https://www.rfxn.com/projects/linux-malware-detect/)
    * [InterServer](https://sigs.interserver.net)
    * [URLhaus](https://urlhaus.abuse.ch/downloads/urlhaus.ndb)
* :warning: **WARNING**: There is a hazard with immutable `loginuid` enabled in auditing in non-systemd systems (Slackware). See longer description of this in the [wiki](https://github.com/pyllyukko/harden.yml/wiki/PAM#pam_loginuidso).
* :file_folder: Review `/etc/fstab.new` manually and deploy applicable changes to `/etc/fstab`
* :bulb: Consider running a hardened kernel. For Slackware you can check out my other project [kspp\_confnbuild](https://github.com/pyllyukko/kspp_confnbuild) that has been (mostly) configured according to [KSPP](https://kspp.github.io/)'s [recommendations](https://kspp.github.io/Recommended_Settings). You can use [kernel-hardening-checker](https://github.com/a13xp0p0v/kernel-hardening-checker) to check your kernel configs.
* :envelope: Make sure your system is able to send e-mails somehow. Many of the tools will be sending alerts about various anomalies.
* :wood::eyes: Consider installing and configuring Logwatch

### Tags

Tags that you can use with `ansible-playbook --tags`:

* `pki`
* `kernel`
* `rng`
* `network`
    * `firewall`
    * `ipv6`
* :wood: `logging`
* :file_folder: Filesystem related:
    * :no_entry: `permissions`
    * `fstab`
    * `suid` & `sgid`
* Specific software:
    * :bar_chart: `sysstat`
    * :blowfish: `ssh`
    * `rkhunter`
    * `chkrootkit`
    * `aide`
    * `audit` (use `--skip-tags audit` in Slackware if you don't have [audit](https://slackbuilds.org/repository/14.2/system/audit/) installed)
    * `debsecan`
    * `debsums`
    * `lynis` (to only configure Lynis you can use `--tags lynis --skip-tags packages`)
    * :sandwich: `sudo`
    * `kerberos`
    * :smiling_imp: `clamav` (use `--skip-tags clamav` in Slackware if you don't have [clamav](https://slackbuilds.org/repository/14.2/system/clamav/) installed)
        * `yara`
    * :shield: `apparmor`
    * `cron` (also includes tasks regarding `at`)
    * `php`
    * :feather: `apache`
        * `hsts`
    * :clock10: `ntp`
    * `lightdm`
    * `gnome`
    * :tiger: `tiger`
    * `john`
* :placard: `banners`
* [AAA](https://en.wikipedia.org/wiki/AAA_(computer_security)):
    * :bar_chart: `accounting` (includes `sysstat`)
    * 🎟️ `authorization`
    * `passwords`
    * :busts_in_silhouette: `accounts`
    * `pam`
        * `limits`
* `cgroup` (Slackware)
* `hidepid` (Slackware)
* `inittab` (Slackware)
* :shell: `shells`
* `umask`
* :timer_clock: `timeout`

There are also operating system tags for tasks that only apply to specific OS.
You can speed up the hardening by skipping OSs that don't apply. E.g. if you're
hardening a Slackware system you can use `--skip-tags debian`.

Other tags are just metadata for now. You can list all the tags with
`ansible-playbook --list-tags harden.yml`.

### Other features

* :no_entry: There is a `lock_account.yml` playbook that you can use to lock user accounts. Just modify the `hosts` & `user`.
* Limited hardening for FreeBSD (see [freebsd.yml](tasks/freebsd.yml))
* :sandwich: Experimental feature: If you enable `sudo_ids` in `vars.yml`, it enables "Sudo Intrusion Detection" as seen in chapter 9 of [Sudo Mastery](https://mwl.io/nonfiction/tools#sudo2)
    * Only for `SHELLS` `Cmnd_Alias` for now
* You can run `make pamcheck` to see how the hardening modifies your PAM configurations in Slackware
* :blowfish: You can create a new SSH moduli with `make /etc/ssh/moduli.new`

Tests
-----

See [tests README](tests/README.md)

References
----------

### Hardening guides

Some of these documents are quite old, but most of the stuff still applies.

* [Slackware System Hardening][2] by Jeffrey Denton
* [Center for Internet Security](https://www.cisecurity.org/):
    * [CIS Slackware Linux 10.2 Benchmark v1.1.0][1]
    * [CIS Debian Linux Benchmark](https://www.cisecurity.org/benchmark/debian_linux/)
    * [CIS Distribution Independent Linux](https://www.cisecurity.org/benchmark/distribution_independent_linux)
* [SlackDocs: Security HOWTOs](http://docs.slackware.com/howtos:security:start)
* :alien: [Alien's Wiki: Security issues](http://alien.slackbook.org/dokuwiki/doku.php?id=linux:admin#security_issues)
* [SlackWiki: Basic Security Fixes](http://slackwiki.com/Basic_Security_Fixes)
* :bomb: [Wikipedia: Fork bomb Prevention](https://en.wikipedia.org/wiki/Fork_bomb#Prevention)
* [Configuration recommendations of a gnu/linux system](https://cyber.gouv.fr/en/publications/configuration-recommendations-gnulinux-system) (ANSSI-BP-028)

### Other docs

* [Linux Standard Base Core Specification 4.1](http://refspecs.linuxfoundation.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic/book1.html)
    * :busts_in_silhouette: [Chapter 21. Users & Groups](http://refspecs.linuxfoundation.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic/usernames.html)
* :file_folder: [Filesystem Hierarchy Standard 2.3](http://refspecs.linuxfoundation.org/FHS_2.3/fhs-2.3.html)
* <https://iase.disa.mil/stigs/os/unix-linux/Pages/index.aspx>
* :book: [PAM Mastery book](https://www.tiltedwindmillpress.com/?product=pam) by [Michael W Lucas](https://www.michaelwlucas.com/)
* [The Linux-PAM System Administrators' Guide](http://linux-pam.org/Linux-PAM-html/Linux-PAM_SAG.html)
* :book: [Sudo Mastery, 2nd Edition](https://www.tiltedwindmillpress.com/product/sudo-mastery-2nd-edition/)
* :book: [Linux Firewalls](https://nostarch.com/firewalls.htm)
* :blowfish: [Secure Secure Shell](https://stribika.github.io/2015/01/04/secure-secure-shell.html)
* [Securing Debian Manual](https://www.debian.org/doc/manuals/securing-debian-manual/index.en.html)
    * :shield: [AppArmor HowToUse](https://wiki.debian.org/AppArmor/HowToUse)
* [ArchWiki: limits.conf](https://wiki.archlinux.org/title/Limits.conf)
* [Effectiveness of Linux Rootkit Detection Tools](http://jultika.oulu.fi/files/nbnfioulu-202004201485.pdf)
* [How to keep a detailed audit trail of what’s being done on your Linux systems](https://www.cyberciti.biz/tips/howto-log-user-activity-using-process-accounting.html)

[1]: http://benchmarks.cisecurity.org/downloads/browse/index.cfm?category=benchmarks.os.linux.slackware
[2]: http://dentonj.freeshell.org/system-hardening-10.2.txt
