harden.sh
=========

This is a script and a set of patch files to harden your Slackware Linux installation.

Why I made this
---------------

* No Bastille for Slackware
* Not a member of CIS, so no downloading of the ready made scripts
* For learning
* For minimizing the effort needed to tweak fresh installations

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
  * Adds the accounts to /etc/ftpusers
* Sets restrictions for normal users
  * Sets the maximum number of processes available to a single user (ulimit -u)
  * Sets the maximum size of core files created (ulimit -c)
  * Sets a session timeout (TMOUT) in certain conditions
  * Sets a maximum number of failed login attempts (faillog)
  * Sets stricter umask
* Configures shells
  * Creates an option to use restricted bash (rbash)
    * Also sets it as default for new users
  * Restricts the number of available shells
  * Removes "unnecessary" shells
  * Creates .bash_logout to skel with few cleanups
* Restricts logins
  * /etc/login.access
  * /etc/porttime
  * /etc/limits
  * /etc/login.defs
    * Disallow logins if home dir does not exist
  * SSH *AllowGroups users*
* Sets useradd defaults
  * INACTIVE days to lock accounts after the password expires
  * rbash as default shell
* Configures a bit better password policy to _login.defs_
* Changes the hashing mechanism to SHA512 and more crypt rounds
* Disallow the use of *at*
* Removes user daemon from group *adm* (as we will take use of the *adm* group)
* Fix gshadow with *grpck*

### Configures services

* Removes unnecessary services
  * xinetd (/etc/inetd.conf)
  * Goes through /etc/rc.d/rc.* and disables plenty of those
* X11 -nolisten tcp
* Enables a bunch of useful services
  * rc.firewall
  * Through rc.local:
    * logoutd
    * icmpinfo
  * Process accounting (acct)
  * System accounting (sysstat)
  * [SBo](http://slackbuilds.org/) related (if installed):
    * Snort
    * arpwatch
    * Tor
    * Privoxy
    * auditd
    * Nagios
    * Apcupsd
    * ClamAV
    * Mrtg
    * p0f

#### Hardens few specific services

  * SSH
  * Sendmail
  * sudo

### File system related

* Hardens mount options (creates /etc/fstab.new)
* Removes a bunch of SUID/SGID bits
  * at
  * chfn + chsh
  * uucp package
  * floppy package (/usr/bin/fdmount)
  * ssh-keysign
* Sets more strict permissions on certain files that might contain secrets or other sensitive information
  * btmp & wtmp
  * Removes world-readibility from /var/www
  * Removes world-readibility from home directories

### Network related

* Creates and enables a basic firewall
* IP stack hardening through sysctl.conf
* Enables TCP wrappers

### Other controls

* Restrict the use of su (prefer sudo instead)
  * /etc/suauth
  * /etc/porttime
* Modifies crontab behaviour a bit
  * Users in the wheel group are able to create cronjobs (as described in /usr/doc/dcron-4.5/README)
* Imports a bunch of PGP keys for file/package verification
* shutdown.allow and /sbin/shutdown -a
* Clear /tmp on boot
* Removes unnecessary / potentially dangerous packages
  * netkit-rsh
  * uucp
  * floppy
* Sets *dmesg_restrict*
* Make installpkg store the MD5 checksums

#### Physical security related

* Sets the [authorized_default](https://www.kernel.org/doc/Documentation/usb/authorization.txt) to USB devices
* Enables [SAK](https://en.wikipedia.org/wiki/Secure_attention_key) and disables the other [magic SysRq stuff](https://www.kernel.org/doc/Documentation/sysrq.txt)
* Session timeout (TMOUT)
* X11:
  * DontZap

#### Logging

* Makes default log files group *adm* readable (as in Debian)
* Use *shred* to remove rotated log files
* Log rotation for process accounting (pacct), since these files **will** grow huge

#### Principle of least privilege

* You can use the *adm* group to view log files, so you don't need to be *root* to do that. Just add a user to the *adm* group, or configure *sudo* as follows:

        ADMINS ALL=(:adm) NOPASSWD: /bin/cat
* ...

Notes
-----

* Rebooting the system after running this is highly recommended, since many startup scripts are modified
* The script is quite verbose, so you might want to record it with *script*

### Other security software

There is a bunch of security related software that you can find at [SBo](http://slackbuilds.org/). You could consider installing these for additional security.

* [Tiger](http://slackbuilds.org/repository/14.0/system/tiger/)
* [Aide](http://slackbuilds.org/repository/14.0/system/aide/)
* [rkhunter](http://slackbuilds.org/repository/14.0/system/rkhunter/)
* [audit](http://slackbuilds.org/repository/14.0/system/audit/)
* [arpwatch](http://slackbuilds.org/repository/14.0/network/arpwatch/)
* [ClamAV](http://slackbuilds.org/repository/14.0/system/clamav/)
* [chkrootkit](http://slackbuilds.org/repository/14.0/system/chkrootkit/)
* [p0f](http://slackbuilds.org/repository/14.0/network/p0f/)

And from other sources than SBo:
* [logwatch](http://slackware.com/~alien/slackbuilds/logwatch/)

TODO
----

* Immutable flags with chattr on certain files
* Checksums for log files
* X hardening
* Debian support

References
----------

### Hardening guides

These are quite old documents, but most of the stuff still applies.

* [CIS Slackware Linux 10.2 Benchmark v1.1.0][1]
* [Slackware System Hardening][2] by Jeffrey Denton

### Other docs

* [Linux Standard Base Core Specification 4.1](http://refspecs.linuxfoundation.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic/book1.html)
  * [Chapter 21. Users & Groups](http://refspecs.linuxfoundation.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic/usernames.html)

[1]: http://benchmarks.cisecurity.org/downloads/browse/index.cfm?category=benchmarks.os.linux.slackware
[2]: http://dentonj.freeshell.org/system-hardening-10.2.txt
