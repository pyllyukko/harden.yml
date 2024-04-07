harden.yml
==========

Ansible playbook to harden your Linux system.

![ansible-lint](https://github.com/pyllyukko/harden.yml/actions/workflows/ansible-lint.yml/badge.svg)

[![asciicast of harden.yml 1294b6f](https://asciinema.org/a/spPzbjtEal2LiOKNQKFORQ1Ay.svg)](https://asciinema.org/a/spPzbjtEal2LiOKNQKFORQ1Ay)

Supported distros
-----------------

* Debian (Bookworm)
    * Kali
    * Raspberry Pi OS
* Slackware (>= [15.0](http://www.slackware.com/announce/15.0.php))
* Limited hardening for CentOS 7 (see CentOS specific tasks with `ansible-playbook --list-tasks --tags centos harden.yml`)

Why I made this
---------------

* [Bastille](http://bastille-linux.sourceforge.net/) is obsolete
* Not a member of [CIS](http://www.cisecurity.org/), so no downloading of the ready made scripts
* For learning
* For minimizing the effort needed to tweak fresh installations
    * Also for consistency

What does it do?
----------------

For a complete list you can run `ansible-playbook --list-tasks harden.yml`.

### Network

* Enables [TCP wrappers](https://en.wikipedia.org/wiki/TCP_Wrapper)
* IP stack hardening via sysctl settings
    * For the complete list, see [network.conf.new](newconfs/sysctl.d/network.conf.new)
* Creates a basic firewall

### Logging

* Configure log retention time to be 6 months
* Configures `logrotate` to `shred` files
    * **NOTE**: Read the fine print in [SHRED(1)](https://www.man7.org/linux/man-pages/man1/shred.1.html): "CAUTION: shred assumes the file system and hardware overwrite data in place.  Although this is common, many platforms operate otherwise."
* Run `ansible-playbook --list-tasks --tags logging harden.yml` for a full list

### Accounting

* Enables system accounting ([sysstat](http://sebastien.godard.pagesperso-orange.fr/))
    * Sets it's log retention to 99999 days (the logs are really small, so it doesn't eat up disk space)
* Enables process accounting
* Run `ansible-playbook --list-tasks --tags accounting harden.yml` for a full list

### Kernel

* Disables the use of certain kernel modules via `modprobe`
    * Disable [Firewire](http://www.hermann-uwe.de/blog/physical-memory-attacks-via-firewire-dma-part-1-overview-and-mitigation)
* [sysctl](https://en.wikipedia.org/wiki/Sysctl) settings hardening
    * Enables [SAK](https://en.wikipedia.org/wiki/Secure_attention_key) and disables the other [magic SysRq stuff](https://www.kernel.org/doc/Documentation/sysrq.txt)
    * Restricts the use of `dmesg` by regular users
    * Enable [YAMA](https://www.kernel.org/doc/Documentation/security/Yama.txt)
    * For the complete list, see [sysctl.conf.new](newconfs/sysctl.d/sysctl.conf.new)
* Run `ansible-playbook --list-tasks --tags kernel harden.yml` for a full list

### Filesystem

* Hardens mount options (creates `/etc/fstab.new`) (see [fstab.awk](files/fstab.awk))
* Sets strict permissions to users home directories
* Limits permissions to various configuration files and directories that might contain sensitive content (see `permissions` tag for a complete list)
* Clean up `/tmp` during boot
* Removes SUID and/or SGID bits from various binaries (see `ansible-playbook --list-tasks --tags suid,sgid harden.yml` for details)

### Application specific

* Configures basic auditing based on [stig.rules](https://fedorahosted.org/audit/browser/trunk/contrib/stig.rules) if audit is installed (see [audit.yml](tasks/audit.yml))
* Configures `sshd_config` and `ssh_config` (see `ansible-playbook --list-tasks --tags ssh harden.yml` for details)
* Configures [sudo](https://www.sudo.ws/) (see [sudoers.j2](templates/sudoers.j2))
    * **WARNING**: If there are rules in `/etc/sudoers.d/` that match our `become: true` tasks that do not have explicit `EXEC`, it can "break" `sudo` as we define `Defaults noexec` in the main `sudoers` file. There is a "Fix NOPASSWD rules" task in `sudoers.yml` which tries to tackle this problem, but it's not guaranteed to work.
    * You can set the `sudo_iolog` in `vars.yml` to `true` to enable I/O logging
    * You can set the `sudo_ids` in `vars.yml` to `true` to enable "Intrusion Detection" as described in [Sudo Mastery](#other-docs) chapter 9 ([#59](https://github.com/pyllyukko/harden.yml/issues/59))
* [ClamAV](https://www.clamav.net/) configuration (see [clamav.yml](tasks/clamav.yml))
    * Configures `clamd` & `freshclam` by first generating fresh configurations with [clamconf](https://docs.clamav.net/manual/Usage/Configuration.html#clamconf)
    * Configured ClamAV to unarchive with password "infected" (see [Passwords for archive files](https://docs.clamav.net/manual/Signatures/EncryptedArchives.html) & [ClamAV and ZIP File Decryption](https://blog.didierstevens.com/2017/02/15/quickpost-clamav-and-zip-file-decryption/))
    * Downloads YARA rules from [Neo23x0](https://github.com/Neo23x0/signature-base), [GCTI](https://github.com/chronicle/GCTI), [Elastic](https://github.com/elastic/protections-artifacts), [YaraRules Project](https://yara-rules.github.io/blog/), [JPCERT/CC](https://github.com/JPCERTCC/jpcert-yara), [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/), [Citizen Lab](https://github.com/citizenlab/malware-signatures), [GoDaddy](https://github.com/godaddy/yara-rules), [Didier Stevens](https://github.com/search?q=repo%3ADidierStevens%2FDidierStevensSuite+path%3A*.yara) & [Open-Source-YARA-rules](https://github.com/mikesxrs/Open-Source-YARA-rules) for [ClamAV to use](https://docs.clamav.net/manual/Signatures/YaraRules.html)
* [rkhunter](https://sourceforge.net/projects/rkhunter/) configuration (see [rkhunter.yml](tasks/rkhunter.yml))
* [Tiger](https://www.nongnu.org/tiger/): Configures `tigerrc` & `tiger.ignore`
* [Lynis](https://cisofy.com/lynis/) configuration (see [lynis.yml](tasks/lynis.yml))
* Configures AIDE (see [aide.yml](tasks/aide.yml))
* Display managers:
    * Disables user lists in GDM3 & LightDM
    * Disables guest sessions and VNC in LightDM
* Minor Apache HTTP server hardening
* Minor PHP (`php.ini`) hardening

### User accounts / authentication / authorization

* Sets default [umask](https://en.wikipedia.org/wiki/Umask) to a more stricter `077` (see <https://github.com/pyllyukko/harden.yml/wiki/umask>)
* Sets console session timeout via `$TMOUT` (Bash)
* Properly locks down system accounts (0 - `SYS_UID_MAX` && !`root`)
    * Lock the user's password
    * Sets shell to `/sbin/nologin`
    * Expire the account
    * Set `RLIMIT_NPROC` to `0` in [pam\_limits](#pam) for those system accounts that don't need to run any processes
* Configures the default password inactivity period
    * Run `ansible-playbook --list-tasks --tags passwords harden.yml` to list all password related tasks
* Makes minor modifications to existing accounts. See `ansible-playbook --list-tasks --tags accounts harden.yml` for details.

#### Authorization

* Create a strict `securetty`
* Creates `/etc/ftpusers`
* Restricts the use of [cron](https://en.wikipedia.org/wiki/Cron) and `at`
* Run `ansible-playbook --list-tasks --tags authorization` for a full list

#### PAM

* Configures `/etc/security/namespace.conf`
* Configures `/etc/security/access.conf` for `pam_access` (authorization) (see [access.conf.j2](templates/access.conf.j2))
* Configures `/etc/security/pwquality.conf` if available
* Require [pam\_wheel](http://linux-pam.org/Linux-PAM-html/sag-pam_wheel.html) in `/etc/pam.d/su`
* Creates a secure [/etc/pam.d/other](http://linux-pam.org/Linux-PAM-html/sag-security-issues-other.html)
* Configures `/etc/security/limits.conf` as follows:
    * Disable [core dumps](https://en.wikipedia.org/wiki/Core_dump)
    * Sets maximum amount of processes (or threads, see [setrlimit(2)](https://man7.org/linux/man-pages/man2/setrlimit.2.html))
    * Sets `nproc` to 0 for system users that don't need to run any processes
* Run `ansible-playbook --list-tasks --tags pam harden.yml` to list all PAM related tasks
* You can also run `ansible-playbook --check --diff --tags pam harden.yml` to see details of the changes

### Miscellaneous

* Creates legal banners (see [banners.yml](tasks/banners.yml))
* Reduce the amount of trusted [CAs](https://en.wikipedia.org/wiki/Certificate_authority) (see [ca-certificates.conf.new](newconfs/ca-certificates.conf.new))
* Restricts the number of available shells (`/etc/shells`)

### Slackware specific

* Run `ansible-playbook --list-tasks --tags slackware harden.yml` for a full list
* Make Xorg rootless
* Makes default log files group `adm` readable ([as in Debian](http://www.debian.org/doc/manuals/debian-reference/ch01.en.html#listofnotablesysupsforfileaccess))
* Restricts the use of `cron` so that only users in the [wheel](https://en.wikipedia.org/wiki/Wheel_(computing)) group are able to create cronjobs (as described in [/usr/doc/dcron-4.5/README](http://www.jimpryor.net/linux/dcron-README))
* Mount [/proc](https://www.kernel.org/doc/Documentation/filesystems/proc.txt) with `hidepid=2`
* Make `installpkg` store the MD5 checksums
* Enable [process accounting](https://tldp.org/HOWTO/Process-Accounting/) (`acct`)
* Does some housekeeping regarding group memberships (see [login\_defs-slackware.yml](tasks/login_defs-slackware.yml))
* Configures `inittab` to use `shutdown -a` (and `/etc/shutdown.allow`)
* Reconfigured bunch of services (run `ansible-playbook --list-tasks --tags slackware harden.yml | grep '\bservices\b'` for a full list)
* Configures cgroups ([v1](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v1/cgroups.html), because of too old `libcgroup`) into `/etc/cg{config,rules}.conf`
* Enables `bootlogd`
    * **NOTE**: Requires `CONFIG_LEGACY_PTYS` (which [KSPP recommends to disable](https://www.kernsec.org/wiki/index.php/Kernel_Self_Protection_Project/Recommended_Settings))

#### PAM

* Creates a custom `/etc/pam.d/system-auth`, which has the following changes:
    * Use `pam_faildelay`
    * Use `pam_faillock`
    * Use `pam_access`
    * Removes `nullok` from `pam_unix`
    * Sets crypt rounds for `pam_unix`
    * Change password `minlen` from 6 to 14
* The following PAM modules are added to `/etc/pam.d/postlogin`:
    * `pam_umask`
    * `pam_cgroup`
    * `pam_namespace`
* Removes `auth include postlogin` from several files, as `postlogin` should (and has) only `session` module types
* Creates `/etc/pam.d/sudo`, as that seemed to be missing
* Disallows the use of `su` (see [su.new](newconfs/pam.d/su.new))

### Debian specific

* Disables unnecessary systemd services
* Enables AppArmor
* Configure `SUITE` in `debsecan`
* Install `debsums` and enable weekly cron job
* Installs a bunch of security related packages (see [debian\_packages.yml](tasks/debian_packages.yml))
* Configures `chkrootkit` and enables daily checks
* Configures APT not to install suggested packages
* Configures periodic weak password checks with [John the Ripper](https://www.openwall.com/john/)

#### pam-configs

Creates bunch of `pam-config`s that are toggleable with `pam-auth-update`:

| PAM module                                                                                   | Type           | Description                                                                             |
| -------------------------------------------------------------------------------------------- | -------------- | --------------------------------------------------------------------------------------- |
| [pam\_wheel](http://www.linux-pam.org/Linux-PAM-html/sag-pam_wheel.html)[<sup>1</sup>](#fn1) | auth           | Require `wheel` group membership (`su`)                                                 |
| [pam\_succeed\_if](http://www.linux-pam.org/Linux-PAM-html/sag-pam_succeed_if.html)          | auth & account | Require UID >= 1000 && UID <= 60000 (or 0 & `login`)                                    |
| [pam\_unix](http://www.linux-pam.org/Linux-PAM-html/sag-pam_unix.html)[<sup>1</sup>](#fn1)   | auth           | Remove `nullok`                                                                         |
| [pam\_faildelay](http://www.linux-pam.org/Linux-PAM-html/sag-pam_faildelay.html)             | auth           | Delay on authentication failure                                                         |
| [pam\_ssh\_agent\_auth](https://pamsshagentauth.sourceforge.net/)                            | auth           | SSH agent authentication for sudo[<sup>3</sup>](#fn3)                                   |
| `pam_faillock`                                                                               | auth & account | Deter brute-force attacks                                                               |
| [pam\_access](http://linux-pam.org/Linux-PAM-html/sag-pam_access.html)                       | account        | Use login ACL (`/etc/security/access.conf`)                                             |
| [pam\_time](http://www.linux-pam.org/Linux-PAM-html/sag-pam_time.html)                       | account        | `/etc/security/time.conf`                                                               |
| [pam\_lastlog](http://www.linux-pam.org/Linux-PAM-html/sag-pam_lastlog.html)                 | account        | Lock out inactive users (no login in 90 days)                                           |
| [pam\_namespace](http://www.linux-pam.org/Linux-PAM-html/sag-pam_namespace.html)             | session        | Polyinstantiated temp directories                                                       |
| [pam\_umask](http://www.linux-pam.org/Linux-PAM-html/sag-pam_umask.html)                     | session        | Set file mode creation mask                                                             |
| [pam\_lastlog](http://www.linux-pam.org/Linux-PAM-html/sag-pam_lastlog.html)                 | session        | Display info about last login and update the lastlog and wtmp files[<sup>2</sup>](#fn2) |
| [pam\_pwhistory](http://www.linux-pam.org/Linux-PAM-html/sag-pam_pwhistory.html)             | password       | Limit password reuse                                                                    |

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

### Notes

* Make sure regular users that should be able to login are members of the `allowed_group` group
* Sudo hardening:
    * `noexec` is on by default, so you need to take this into account in your custom rules
    * Interactive shells to `root` have timeout, so use `screen` for those longer administrative tasks
* Rebooting the system after running this is highly recommended
* The AIDE DB creation is made [asynchronously](https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_async.html) and without polling, so let that finish before rebooting
* You might want to get additional (unofficial) rules for ClamAV with [clamav-unofficial-sigs](https://github.com/extremeshok/clamav-unofficial-sigs). At least the following rulesets are freely available:
    * [Sanesecurity](https://sanesecurity.com/usage/signatures/)
        * Porcupine ("The following databases are distributed by Sanesecurity, but produced by Porcupine Signatures")
        * bofhland ("The following databases are distributed by Sanesecurity, but produced by bofhland")
    * [Linux Malware Detect](https://www.rfxn.com/projects/linux-malware-detect/)
    * [InterServer](https://sigs.interserver.net)
* **WARNING**: There is a hazard with immutable `loginuid` enabled in auditing in non-systemd systems (Slackware). See longer description of this in the [wiki](https://github.com/pyllyukko/harden.yml/wiki/PAM#pam_loginuidso).

### Tags

Tags that you can use with `ansible-playbook --tags`:

* `pki`
* `kernel`
* `rng`
* `network`
    * `firewall`
    * `ipv6`
* `logging`
* Filesystem related:
    * `permissions`
    * `fstab`
    * `suid` & `sgid`
* Specific software:
    * `sysstat`
    * `ssh`
    * `rkhunter`
    * `chkrootkit`
    * `aide`
    * `audit` (use `--skip-tags audit` in Slackware if you don't have [audit](https://slackbuilds.org/repository/14.2/system/audit/) installed)
    * `debsecan`
    * `debsums`
    * `lynis` (to only configure Lynis you can use `--tags lynis --skip-tags packages`)
    * `sudo`
    * `kerberos`
    * `clamav` (use `--skip-tags clamav` in Slackware if you don't have [clamav](https://slackbuilds.org/repository/14.2/system/clamav/) installed)
        * `yara`
    * `apparmor`
    * `cron` (also includes tasks regarding `at`)
    * `php`
    * `apache`
        * `hsts`
    * `ntp`
    * `lightdm`
    * `gnome`
    * `tiger`
    * `john`
* `banners`
* [AAA](https://en.wikipedia.org/wiki/AAA_(computer_security)):
    * `accounting` (includes `sysstat`)
    * `authorization`
    * `passwords`
    * `accounts`
    * `pam`
        * `limits`
* `cgroup` (Slackware)
* `hidepid` (Slackware)
* `shells`
* `umask`

There are also operating system tags for tasks that only apply to specific OS.
You can speed up the hardening by skipping OSs that don't apply. E.g. if you're
hardening a Slackware system you can use `--skip-tags debian,centos`.

Other tags are just metadata for now. You can list all the tags with
`ansible-playbook --list-tags harden.yml`.

### Other features

* There is a `lock_account.yml` playbook that you can use to lock user accounts. Just modify the `hosts` & `user`.
* Limited hardening for FreeBSD (see [freebsd.yml](tasks/freebsd.yml))
* Experimental feature: If you enable `sudo_ids` in `vars.yml`, it enables "Sudo Intrusion Detection" as seen in chapter 9 of [Sudo Mastery](https://mwl.io/nonfiction/tools#sudo2)
    * Only for `SHELLS` `Cmnd_Alias` for now

References
----------

### Hardening guides

Some of these documents are quite old, but most of the stuff still applies.

* [CIS Slackware Linux 10.2 Benchmark v1.1.0][1]
* [Slackware System Hardening][2] by Jeffrey Denton
* [CIS Debian Linux Benchmark](https://www.cisecurity.org/benchmark/debian_linux/)
* [CIS CentOS Linux 7 Benchmark](https://www.cisecurity.org/benchmark/centos_linux/)
* [SlackDocs: Security HOWTOs](http://docs.slackware.com/howtos:security:start)
* [Alien's Wiki: Security issues](http://alien.slackbook.org/dokuwiki/doku.php?id=linux:admin#security_issues)
* [SlackWiki: Basic Security Fixes](http://slackwiki.com/Basic_Security_Fixes)
* [Wikipedia: Fork bomb Prevention](https://en.wikipedia.org/wiki/Fork_bomb#Prevention)

### Other docs

* [Linux Standard Base Core Specification 4.1](http://refspecs.linuxfoundation.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic/book1.html)
  * [Chapter 21. Users & Groups](http://refspecs.linuxfoundation.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic/usernames.html)
* [Filesystem Hierarchy Standard 2.3](http://refspecs.linuxfoundation.org/FHS_2.3/fhs-2.3.html)
* <https://iase.disa.mil/stigs/os/unix-linux/Pages/index.aspx>
* [PAM Mastery book](https://www.tiltedwindmillpress.com/?product=pam) by [Michael W Lucas](https://www.michaelwlucas.com/)
* [The Linux-PAM System Administrators' Guide](http://linux-pam.org/Linux-PAM-html/Linux-PAM_SAG.html)
* [Sudo Mastery, 2nd Edition](https://www.tiltedwindmillpress.com/product/sudo-mastery-2nd-edition/)
* [Linux Firewalls](https://nostarch.com/firewalls.htm)
* [Secure Secure Shell](https://stribika.github.io/2015/01/04/secure-secure-shell.html)
* [Securing Debian Manual](https://www.debian.org/doc/manuals/securing-debian-manual/index.en.html)
* [ArchWiki: limits.conf](https://wiki.archlinux.org/title/Limits.conf)
* [Effectiveness of Linux Rootkit Detection Tools](http://jultika.oulu.fi/files/nbnfioulu-202004201485.pdf)

[1]: http://benchmarks.cisecurity.org/downloads/browse/index.cfm?category=benchmarks.os.linux.slackware
[2]: http://dentonj.freeshell.org/system-hardening-10.2.txt
