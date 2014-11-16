harden.sh
=========

This is a script and a set of patch files to [harden](https://en.wikipedia.org/wiki/Hardening_%28computing%29) your [Slackware Linux](http://www.slackware.com/) installation.

Why I made this
---------------

* No [Bastille](http://bastille-linux.org/) for Slackware (and it's not updated anymore anyway)
* Not a member of [CIS](http://www.cisecurity.org/), so no downloading of the ready made scripts
* For learning
* For minimizing the effort needed to tweak fresh installations
  * Also for consistency

How does it work?
-----------------

The script is divided (well kinda) into dynamic and static changes. The static changes are applied with patch files and the dynamic modifications happen usually with certain commands.

### Static changes

The generic etc patch assumes that you have at least the following packages installed:

* network-scripts
* sysvinit-scripts
* etc
* shadow
* logrotate
* sysklogd

Then there's separate patch files for different services/daemons. See [the services section](https://github.com/pyllyukko/harden.sh#hardens-few-specific-services) for more information.


What does it do?
----------------

**DISCLAIMER**: This is not a complete list.

### Harden user accounts

* Properly locks down system accounts (0 - *SYS_UID_MAX* && !root)
  * Lock the user's password
  * Sets shell to /sbin/nologin
  * Expire the account
  * Adds the accounts to [/etc/ftpusers](http://linux.die.net/man/5/ftpusers)
* Sets restrictions for normal users
  * Sets the [maximum number of processes available to a single user](https://en.wikipedia.org/wiki/Fork_bomb#Prevention) (ulimit -u)
  * Sets the maximum size of core files created (ulimit -c)
  * Sets a session timeout (TMOUT) in certain conditions
  * Sets a maximum number of failed login attempts (faillog)
  * Sets stricter umask in all the following locations:
    * /etc/login.defs
    * ~~/etc/limits~~
    * /etc/profile
* Configures shells
  * Creates an option to use [restricted shell](https://en.wikipedia.org/wiki/Restricted_shell) (rbash)
    * Also sets it as default for new users
  * Restricts the number of available shells
  * Removes "unnecessary" shells
  * Creates .bash\_logout to skel with few cleanups
* Restricts logins
  * /etc/login.access
  * /etc/porttime
  * ~~/etc/limits~~
  * /etc/login.defs
    * Disallow logins if home dir does not exist
  * SSH *AllowGroups users*
* Sets useradd defaults
  * INACTIVE days to lock accounts after the password expires
  * rbash as default shell
* Configures a bit better password policy to _login.defs_
* Changes the hashing mechanism to [SHA512](https://en.wikipedia.org/wiki/SHA-2) and more crypt rounds
* Disallow the use of *at*
* Removes user daemon from group *adm* (as we will take use of the *adm* group)
* Fix gshadow with *grpck*

#### Groups

 * Makes default log files group *adm* readable ([as in Debian](http://www.debian.org/doc/manuals/debian-reference/ch01.en.html#listofnotablesysupsforfileaccess))
 * Users in the *wheel* group are able to create cronjobs (as described in [/usr/doc/dcron-4.5/README][8])
 * [grsecurity related](https://en.wikibooks.org/wiki/Grsecurity/Appendix/Grsecurity_and_PaX_Configuration_Options#Default_Special_Groups)
   * GID 1001 for [CONFIG\_GRKERNSEC\_PROC\_GID](https://en.wikibooks.org/wiki/Grsecurity/Appendix/Grsecurity_and_PaX_Configuration_Options#GID_exempted_from_.2Fproc_restrictions)
   * GID 1002 for [GRKERNSEC\_SOCKET\_SERVER\_GID](https://en.wikibooks.org/wiki/Grsecurity/Appendix/Grsecurity_and_PaX_Configuration_Options#GID_to_deny_server_sockets_for)
   * GID 1003 for [GRKERNSEC\_SOCKET\_CLIENT\_GID](https://en.wikibooks.org/wiki/Grsecurity/Appendix/Grsecurity_and_PaX_Configuration_Options#GID_to_deny_client_sockets_for)
   * GID 1004 for [GRKERNSEC\_SOCKET\_ALL\_GID](https://en.wikibooks.org/wiki/Grsecurity/Appendix/Grsecurity_and_PaX_Configuration_Options#GID_to_deny_all_sockets_for)
   * GID 1005 for [CONFIG\_GRKERNSEC\_TPE\_TRUSTED\_GID](https://en.wikibooks.org/wiki/Grsecurity/Appendix/Grsecurity_and_PaX_Configuration_Options#GID_for_TPE-trusted_users)
   * GID 1006 for [CONFIG\_GRKERNSEC\_SYMLINKOWN\_GID](https://en.wikibooks.org/wiki/Grsecurity/Appendix/Grsecurity_and_PaX_Configuration_Options#GID_for_users_with_kernel-enforced_SymlinksIfOwnerMatch)
   * GID 1007 for [GRKERNSEC\_AUDIT\_GID](https://en.wikibooks.org/wiki/Grsecurity/Appendix/Grsecurity_and_PaX_Configuration_Options#GID_for_auditing) (not in use)

You can also utilize the above grsec groups with sudo, so the allowed users don't have the permissions by default:

	ADMINS ALL=(:grsec_tpe) NOPASSWD: /usr/bin/newgrp

### Configures services

* Removes unnecessary services
  * xinetd (/etc/inetd.conf)
  * Goes through /etc/rc.d/rc.\* and disables plenty of those
  * *atd* from *rc.M*
* [X11 -nolisten tcp](http://docs.slackware.com/howtos:security:basic_security#x_-nolisten_tcp)

#### Enable some security and auditing related services

* rc.firewall
* Through rc.local:
  * logoutd
  * icmpinfo
* [Process accounting][9] (acct)
* System accounting ([sysstat][10])
* [SBo](http://slackbuilds.org/) related (if installed):
  * Snort
  * [arpwatch][6]
  * Tor
  * Privoxy
  * [audit][5]
  * Nagios
  * Apcupsd
  * [ClamAV][4]
  * Mrtg
  * [p0f][3]

#### Hardens few specific services

* SSH
* Sendmail
  * Listen only on localhost by default
  * Disable the [MSA](https://en.wikipedia.org/wiki/Mail_submission_agent)
  * Don't show the version on the banner
* sudo
  * Don't cache the password (timestamp\_timeout) (should also mitigate against [CVE-2013-1775](http://www.sudo.ws/sudo/alerts/epoch_ticket.html))
  * Always require password with *sudo -l* (listpw)
  * noexec as default
  * Require root's password instead of user's
  * Send alerts on most errors
  * Additional logging to */var/log/sudo.log*
* [PHP](https://www.owasp.org/index.php/Configuration#PHP_Configuration)
* Apache httpd

### File system related

* Hardens mount options (creates /etc/fstab.new)
  * Also, mount [/proc](https://www.kernel.org/doc/Documentation/filesystems/proc.txt) with hidepid=2
* Removes a bunch of SUID/SGID bits
  * at
  * chfn + chsh
  * uucp package
  * [floppy][7] package (/usr/bin/fdmount)
  * ssh-keysign
* Sets more strict permissions on certain files that might contain secrets or other sensitive information
  * btmp & wtmp
  * Removes world-readibility from /var/www
  * Removes world-readibility from home directories

**TODO**: Add a table about file ownership & permission changes. At least the most relevant ones.

### Network related

* Creates and enables a basic firewall
* IP stack hardening through sysctl.conf
* Enables [TCP wrappers](https://en.wikipedia.org/wiki/TCP_Wrapper)
  * **NOTE**: OpenSSH dropped support for TCP wrappers in [6.7](http://www.openssh.com/txt/release-6.7) (and [here's](https://lists.mindrot.org/pipermail/openssh-unix-dev/2014-April/032507.html) a good argument why this was a bad move!)
    * Also, Slackware introduced OpenSSH 6.7 with [SSA:2014-293-01](http://www.slackware.com/security/viewer.php?l=slackware-security&y=2014&m=slackware-security.521613)

### Other controls

* Restrict the use of su (prefer sudo instead)
  * /etc/suauth
  * /etc/porttime
  * /etc/login.defs: SU\_WHEEL\_ONLY
* Modifies crontab behaviour a bit
  * Users in the *wheel* group are able to create cronjobs (as described in [/usr/doc/dcron-4.5/README][8])
  * Increase cron's logging from *notice* to *info*
* Clear /tmp on boot (also recommended in [FHS](http://refspecs.linuxfoundation.org/FHS_2.3/fhs-2.3.html#PURPOSE17))
  * **TODO**: is it redundant to have it both in rc.M and rc.S?
* Removes unnecessary / potentially dangerous packages
  * netkit-rsh
  * uucp
  * [floppy][7]
* Sets *dmesg\_restrict*
* Make *installpkg* store the MD5 checksums
* Reduce the amount of trusted [CAs](https://en.wikipedia.org/wiki/Certificate_authority)
* "Fix" the single-user mode

#### Periodic checks

Some things are added to cron: **TODO**

##### sysstat

From [sysstat.crond](https://github.com/sysstat/sysstat/blob/master/cron/sysstat.crond.in):

```
# Run system activity accounting tool every 10 minutes
*/10 * * * * if [ -x /usr/lib64/sa/sa1 ]; then /usr/lib64/sa/sa1 -S DISK 1 1; elif [ -x /usr/lib/sa/sa1 ]; then /usr/lib/sa/sa1 -S DISK 1 1; fi
# 0 * * * * /usr/lib/sa/sa1 -S DISK 600 6 &
# Generate a daily summary of process accounting at 23:53
53 23 * * * if [ -x /usr/lib64/sa/sa2 ]; then /usr/lib64/sa/sa2 -A; elif [ -x /usr/lib/sa/sa2 ]; then /usr/lib/sa/sa2 -A; fi
```

#### PGP

The *import_pgp_keys()* function imports a bunch of PGP keys to your *trustedkeys.gpg* keyring, so you can verify downloaded files/packages with [gpgv](http://www.gnupg.org/documentation/manuals/gnupg/gpgv.html). The keys that are imported are listed in the PGP_URLS[] and PGP_KEYS[] arrays.

#### Physical security related

* Sets the [authorized\_default](https://www.kernel.org/doc/Documentation/usb/authorization.txt) to USB devices
* Enables [SAK](https://en.wikipedia.org/wiki/Secure_attention_key) and disables the other [magic SysRq stuff](https://www.kernel.org/doc/Documentation/sysrq.txt)
* Session timeout (TMOUT)
* X11:
  * DontZap
* shutdown.allow and /sbin/shutdown -a (FWIW)

##### Wipe

**WARNING**: This is a highly experimental and dangerous feature (and completely optional)! Use at your own risk!

This is something that has been cooking for a while now. It's a self-destruct sequence for your server :)

The patch creates a new runlevel (**5**) to your Slackware, which when activated, will remove LUKS headers from your disk and copies them inside the encrypted disk. So if anything should happen, the server is not restorable anymore, as the disk encryption keys are gone. When the runlevel is switched back (to say 3), the headers are written back to where they belong.

So to wipe LUKS headers, you just switch to runlevel 5: `telinit 5` and to restore just switch back to 3: `telinit 3`.

There is still some issues, such as some services will be started again (such as *crond*) when returning to runlevel 3. This is because *rc.M* doesn't really consider users switching back and forth between runlevels. So this is a work-in-progress.

As a workaround, there is also a new runlevel **2** that can be used to safely return from runlevel 5. Now we don't need to care about daemons starting over and over again from *rc.M* (runlevel 3).

#### Logging

* Makes default log files group *adm* readable ([as in Debian](http://www.debian.org/doc/manuals/debian-reference/ch01.en.html#listofnotablesysupsforfileaccess))
  * Notice that this takes place only after logrotate. The ownerships/permissions of the existing logs are not modified.
* Use *shred* to remove rotated log files
* Enable [process accounting][9] (acct)
  * Log rotation for process accounting (pacct), since these files **will** grow huge
* Enable system accounting ([sysstat][10])
* Enables the use of *xconsole* (or makes it possible). You can use it with:

        ADMINS ALL=(:adm) NOPASSWD: /usr/bin/xconsole
* Enables bootlogd
* Makes certain log files [append only](http://www.seifried.org/lasg/logging/)
* Configures basic auditing based on [stig.rules](https://fedorahosted.org/audit/browser/trunk/contrib/stig.rules) if [audit][5] is installed
* Increase the default log retention period to 26 weeks

#### Principle of least privilege

* You can use the *adm* group to view log files, so you don't need to be *root* to do that. Just add a user to the *adm* group, or configure *sudo* as follows:

        ADMINS ALL=(:adm) NOPASSWD: /bin/cat
* View bad logins with sudo:

        ADMINS ALL=(:adm) NOPASSWD: /usr/bin/lastb
* Remove *floppy* and *scanner* from CONSOLE\_GROUPS

Benchmarks
----------

Lynis benchmarks.

The test is performed against a setup like this:

* A minimal Slackware installation with some 135 packages installed
  * No additional security related tools installed
  * Running with latest patches
* One big root partition
  * No LUKS
* The hardening is done with *./harden.sh -A*
  * The system is booted after hardening
* [AUTH-9262](http://cisofy.com/controls/AUTH-9262/) test disabled

Baseline:

<table>
  <tr>
    <th>Date</th><th>Slackware version</th><th>Lynis version</th><th>Hardening index</th>
  </tr>
  <tr>
    <td>24.9.2014</td><td>slackware64-14.1</td><td>1.6.2<td>43</td>
  </tr>
</table>

Hardened:

<table>
  <tr>
    <th>Date</th><th>Slackware version</th><th>Lynis version</th><th>harden.sh version</th><th>Hardening index</th>
  </tr>
  <tr>
    <td>24.9.2014</td><td>slackware64-14.1</td><td>1.6.2<td>155ad8536aed9e30197d645031c72d79ad93f3f4</td><td>68</td>
  </tr>
</table>

Notes
-----

* Rebooting the system after running this is highly recommended, since many startup scripts are modified
* The script is quite verbose, so you might want to record it with *script*
* It is best to run this script on a fresh Slackware installation for best results

### Other security software

There is a bunch of security related software that you can find at [SBo](http://slackbuilds.org/). You could consider installing these for additional security.

* [HIDS](https://en.wikipedia.org/wiki/Host-based_intrusion_detection_system):
  * [Tiger](http://slackbuilds.org/repository/14.1/system/tiger/)
  * [Aide](http://slackbuilds.org/repository/14.1/system/aide/)
  * [rkhunter](http://slackbuilds.org/repository/14.1/system/rkhunter/)
  * [audit][5]
  * [chkrootkit](http://slackbuilds.org/repository/14.1/system/chkrootkit/)
* Network related:
  * [arpwatch][6]
  * [p0f][3]
* Web server:
  * [ModSecurity](http://slackbuilds.org/repository/14.1/network/modsecurity-apache/)
  * [Suhosin](http://slackbuilds.org/repository/13.37/libraries/php-suhosin/)
* Other:
  * [vlock](http://slackbuilds.org/repository/14.1/system/vlock/)

And from other sources than SBo:
* [logwatch](http://slackware.com/~alien/slackbuilds/logwatch/)
* [checksec.sh](http://www.trapkit.de/tools/checksec.html)
* [psad](http://www.cipherdyne.org/psad/)
* [Lynis](http://cisofy.com/lynis/)

#### Antivirus

I think it's justified and recommended to run an antivirus software on all of your Linux servers. This is because, even though the server's role would not be something like a file sharing server or a mail server, a proper antivirus is able to detect much more than these "traditional" malwares. I'm talking about rootkits, exploits, [PHP shells](https://en.wikipedia.org/wiki/Backdoor_Shell) and the like. Something that a malicious user might be holding at their home dirs or maybe some PHP shell was dropped through a vulnerable web application. If you would get an early warning from an antivirus software, it just might save you on that one occasion :)

So consider getting [ClamAV][4] from SBo.

#### grsecurity

You should also consider running [grsecurity](https://grsecurity.net/). Here's few links to get you started:
* [My packaging scripts](https://github.com/pyllyukko/grsec_confnbuild)
* [SlackPaX](http://sourceforge.net/projects/slackpax/) (haven't tried this personally)
* [gradm SlackBuild](http://slackbuilds.org/repository/14.1/system/gradm/)
* [paxctl SlackBuild](http://slackbuilds.org/repository/14.1/system/paxctl/)

### Bugs discovered during the making :)

* [SSA:2011-101-01](http://www.slackware.com/security/viewer.php?l=slackware-security&y=2011&m=slackware-security.380749)
  * [BID:47303](http://www.securityfocus.com/bid/47303/info)
* http://www.sudo.ws/repos/sudo/rev/5b964ea43474
* http://anonscm.debian.org/viewvc/pkg-shadow?view=revision&revision=3558
* http://sourceforge.net/p/logwatch/bugs/19/
* A bug in Metasploit's installer, where it assumes that /bin/bash is the default shell for new users (bug #7666 in some hidden Metasploit Pro tracker)

TODO
----

* Immutable flags with *chattr* on certain files
* X hardening
* Debian support
* Some chroot stuff?
* Static ARP cache
* Logging of the script actions
* lilo.conf: audit=1
* some kernel module configurator thingie for /etc/rc.d/rc.modules
* [LUKS nuke](http://www.kali.org/how-to/nuke-kali-linux-luks/)
* Provide the trustedkeys.gpg PGP keys with this tool?
  * Or get rid of wget over HTTP
* Add some functionality, that compares your current file system against Slackware's [MANIFEST](ftp://ftp.slackware.com/pub/slackware/slackware64-14.1/slackware64/MANIFEST.bz2) (something like Alien's [restore\_fileperms\_from\_manifest.sh](http://www.slackware.com/~alien/tools/restore_fileperms_from_manifest.sh))
  * Some HIDS baseline generation from MANIFEST would also be really nice
* Add CCE references?
* /usr/bin/ch{mod,own} -> from PATH. since Debian has them under /bin
* Create .preharden backups (only once?)

### Auth/user account related

* Some variables to read only?
  * From rbash: SHELL, PATH, ENV, or BASH\_ENV
  * From system-hardening-10.2.txt: HISTCONTROL HISTFILE HISTFILESIZE HISTIGNORE HISTNAME HISTSIZE LESSSECURE LOGNAME USER
* faillog for new users?
* User quotas
* [PAM](http://www.slackware.com/~vbatts/pam/) for Slackware?
  * Two-factor authentication
* Shadow suite S/Key support (/usr/doc/shadow-4.1.4.3/README)
* How do we reset faillogs after successful login?
* [Create .gnupg home directories](http://www.gnupg.org/documentation/manuals/gnupg/addgnupghome.html#addgnupghome)
* USERDEL\_CMD from LOGIN.DEFS(5)
* Is it possible to enforce password policy for root user also?

### Guides to read

* http://www.nsa.gov/ia/_files/os/redhat/rhel5-guide-i731.pdf
* http://www.auscert.org.au/5816 "UNIX and Linux Security Checklist v3.0"
* http://www.puschitz.com/SecuringLinux.shtml
* http://linuxgazette.net/issue91/kruk.html
* https://www.sans.org/score/unixchecklist.php
* Maybe some tips from http://www.debian.org/doc/user-manuals#securing
* http://www.symantec.com/connect/articles/restricting-unix-users
* https://wiki.archlinux.org/index.php/Security

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

[1]: http://benchmarks.cisecurity.org/downloads/browse/index.cfm?category=benchmarks.os.linux.slackware
[2]: http://dentonj.freeshell.org/system-hardening-10.2.txt
[3]: http://slackbuilds.org/repository/14.1/network/p0f/
[4]: http://slackbuilds.org/repository/14.1/system/clamav/
[5]: http://slackbuilds.org/repository/14.1/system/audit/
[6]: http://slackbuilds.org/repository/14.1/network/arpwatch/
[7]: ftp://ftp.slackware.com/pub/slackware/slackware-14.1/source/a/floppy/
[8]: http://www.jimpryor.net/linux/dcron-README
[9]: http://www.tldp.org/HOWTO/Process-Accounting/
[10]: http://sebastien.godard.pagesperso-orange.fr/
