harden.sh
=========

This is a script to harden your Linux installation.

[![asciicast](https://asciinema.org/a/lBaPJhg3KAsp470y9eyLQ2bbA.png)](https://asciinema.org/a/lBaPJhg3KAsp470y9eyLQ2bbA)

Why I made this
---------------

* [Bastille](http://bastille-linux.sourceforge.net/) is obsolete
* Not a member of [CIS](http://www.cisecurity.org/), so no downloading of the ready made scripts
* For learning
* For minimizing the effort needed to tweak fresh installations
  * Also for consistency

What does it do?
----------------

### Common

* Enables [TCP wrappers](https://en.wikipedia.org/wiki/TCP_Wrapper)
* Creates legal banners
* Disable [core dumps](https://en.wikipedia.org/wiki/Core_dump) in ```/etc/security/limits.conf```
* [sysctl](https://en.wikipedia.org/wiki/Sysctl) settings hardening
  * IP stack hardening
  * Enables [SAK](https://en.wikipedia.org/wiki/Secure_attention_key) and disables the other [magic SysRq stuff](https://www.kernel.org/doc/Documentation/sysrq.txt)
  * Restricts the use of ```dmesg``` by regular users
  * For the complete list, see [sysctl.conf.new](https://github.com/pyllyukko/harden.sh/blob/master/newconfs/sysctl.d/sysctl.conf.new)
* Hardens mount options (creates ```/etc/fstab.new```)
  * Also, mount [/proc](https://www.kernel.org/doc/Documentation/filesystems/proc.txt) with ```hidepid=2```
* Disables the use of certain kernel modules via ```modprobe```
  * Disable [Firewire](http://www.hermann-uwe.de/blog/physical-memory-attacks-via-firewire-dma-part-1-overview-and-mitigation)
* Configures shells
  * Creates an option to use [restricted shell](https://en.wikipedia.org/wiki/Restricted_shell) ([rbash](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html))
    * Also sets it as default for new users
  * Restricts the number of available shells (```/etc/shells```)
* Configures basic auditing based on [stig.rules](https://fedorahosted.org/audit/browser/trunk/contrib/stig.rules) if audit is installed
  * NOTE: non-PAM systems (namely Slackware) don't set the ```loginuid``` properly, so some of the rules don't work when they have ```-F auid!=4294967295```
* Enables system accounting ([sysstat][10])
 * Sets it's log retention to 99999 days (the logs are really small, so it doesn't eat up disk space)
* Configures password policies
  * Maximum age for password
  * Minimum age for password
  * Password warn age
  * Does this for existing users also
  * Note: password strength should be enforced with applicable PAM module (such as [pam_passwdqc](http://www.openwall.com/passwdqc/) or ```pam_pwquality```)
* Reduce the amount of trusted [CAs](https://en.wikipedia.org/wiki/Certificate_authority)
  * Doesn't work in CentOS/RHEL
* Create a strict ```securetty```
* Sets default [umask](https://en.wikipedia.org/wiki/Umask) to a more stricter ```077```
* Sets console session timeout via ```$TMOUT``` (Bash)
* PAM:
  * Configures ```/etc/security/namespace.conf```
  * Configures ```/etc/security/access.conf```
  * Configures ```/etc/security/pwquality.conf``` if available
  * Require [pam_wheel](http://linux-pam.org/Linux-PAM-html/sag-pam_wheel.html) in ```/etc/pam.d/su```
  * Creates a secure [/etc/pam.d/other](http://linux-pam.org/Linux-PAM-html/sag-security-issues-other.html)
* Disables unnecessary systemd services
* Configures ```sshd_config```
* Display managers:
  * Disables user lists in GDM3 & LightDM
  * Disables guest sessions in LightDM

#### User accounts

* Configures failure limits (```faillog```)
* Creates ```/etc/ftpusers```
* Restricts the use of ```cron``` and ```at```
* Properly locks down system accounts (0 - ```SYS_UID_MAX``` && !```root```)
  * Lock the user's password
  * Sets shell to ```nologin```
  * Expire the account
  * Adds the accounts to [/etc/ftpusers](http://linux.die.net/man/5/ftpusers)
* Sets strict permissions to users home directories
* Configures the default password inactivity period

### Debian specific

* Enables AppArmor
* Sets the [authorized\_default](https://www.kernel.org/doc/Documentation/usb/authorization.txt) to USB devices via ```rc.local```

#### PAM

* Creates bunch of ```pam-config```s that are toggleable with ```pam-auth-update```:
  * Deter brute-force attacks with [pam_tally2](http://linux-pam.org/Linux-PAM-html/sag-pam_tally2.html)
  * Polyinstantiated temp directories with [pam_namespace](http://linux-pam.org/Linux-PAM-html/sag-pam_namespace.html)
  * ```/etc/security/access.conf``` access control with [pam_access](http://linux-pam.org/Linux-PAM-html/sag-pam_access.html)
  * Delay on authentication failure with [pam_faildelay](http://linux-pam.org/Linux-PAM-html/sag-pam_faildelay.html)
  * Set file mode creation mask with [pam_umask](http://linux-pam.org/Linux-PAM-html/sag-pam_umask.html)
  * Enable ```lastlog```ging from all login methods (not just the console ```login```)
  * Limit password reuse with [pam_pwhistory](http://linux-pam.org/Linux-PAM-html/sag-pam_pwhistory.html)
* Disallow empty passwords by removing ```nullok```

### CentOS/RHEL specific

* PAM configuration with ```authconfig```:
  * Enables ```pam_faillock```
  * Configures ```pwquality```

### Slackware specific

See [SLACKWARE.md](SLACKWARE.md).

### Additional features

* SSH moduli creation
* Some hardening steps utilize [Lynis](https://cisofy.com/lynis/) to verify themselves (to be improved/extended over time)

#### PGP

The ```import_pgp_keys()``` function imports a bunch of PGP keys to your ```trustedkeys.gpg``` keyring, so you can verify downloaded files/packages with [gpgv](http://www.gnupg.org/documentation/manuals/gnupg/gpgv.html). The keys that are imported are listed in the ```PGP_URLS[]``` and ```PGP_KEYS[]``` arrays.

Notes
-----

* Rebooting the system after running this is highly recommended, since many startup scripts are modified
* The script is quite verbose, so you might want to record it with *script*
* It is best to run this script on a fresh installation for best results

### Other security software

#### Antivirus

I think it's justified and recommended to run an antivirus software on all of your Linux servers. This is because, even though the server's role would not be something like a file sharing server or a mail server, a proper antivirus is able to detect much more than these "traditional" malwares. I'm talking about rootkits, exploits, [PHP shells](https://en.wikipedia.org/wiki/Backdoor_Shell) and the like. Something that a malicious user might be holding at their home dirs or maybe some PHP shell was dropped through a vulnerable web application. If you would get an early warning from an antivirus software, it just might save you on that one occasion :)

So consider getting [ClamAV](https://www.clamav.net/).

Post-hardening checklist
------------------------

After running the hardening script, the following actions still need to be performed manually:

- [ ] Set LILO/GRUB password
  - [ ] Update LILO/GRUB with ```lilo``` || ```update-grub```
- Install at least the following additional software:
  - [ ] [audit](https://people.redhat.com/sgrubb/audit/) (and run ```harden.sh -S``` afterwards)
  - [ ] [Aide](http://aide.sourceforge.net/)
  - [ ] ClamAV
  - [ ] arpwatch
- [ ] Make sure NTP is running
- [ ] Configure remote log host
- [ ] Add legit users to:
  - ```/etc/porttime```
  - To the ```users``` group

References
----------

### Hardening guides

Some of these documents are quite old, but most of the stuff still applies.

* [CIS Slackware Linux 10.2 Benchmark v1.1.0][1]
* [Slackware System Hardening][2] by Jeffrey Denton
* [SlackDocs: Security HOWTOs](http://docs.slackware.com/howtos:security:start)
* [Alien's Wiki: Security issues](http://alien.slackbook.org/dokuwiki/doku.php?id=linux:admin#security_issues)
* [SlackWiki: Basic Security Fixes](http://slackwiki.com/Basic_Security_Fixes)
* [Wikipedia: Fork bomb Prevention](https://en.wikipedia.org/wiki/Fork_bomb#Prevention)

### Other docs

* [Linux Standard Base Core Specification 4.1](http://refspecs.linuxfoundation.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic/book1.html)
  * [Chapter 21. Users & Groups](http://refspecs.linuxfoundation.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic/usernames.html)
* [Filesystem Hierarchy Standard 2.3](http://refspecs.linuxfoundation.org/FHS_2.3/fhs-2.3.html)
* <https://iase.disa.mil/stigs/os/unix-linux/Pages/index.aspx>

[1]: http://benchmarks.cisecurity.org/downloads/browse/index.cfm?category=benchmarks.os.linux.slackware
[2]: http://dentonj.freeshell.org/system-hardening-10.2.txt
[10]: http://sebastien.godard.pagesperso-orange.fr/
