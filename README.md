harden.sh
=========

This is a script and a set of patch files to harden your Slackware Linux installation.

Why I made this
---------------

* No Bastille for Slackware
* Not a member of CIS, so no downloading of the ready made scripts
* For learning
* For minimizing the effort needed to tweak fresh installations

What does it do?
----------------

DISCLAIMER: This is not a complete list.

### Harden user accounts

* Properly locks down system accounts (0 - SYS_UID_MAX && !root)
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
* Sets useradd defaults
  * INACTIVE days to lock accounts after the password expires
  * rbash as default shell
* Configures a bit better password policy (login.defs)
* Changes the hashing mechanism to SHA512 and more crypt rounds
* Removes user daemon from group adm (as we will take use of the adm group)
* Fix gshadow with grpck

### Configures services

* Removes unnecessary services
  * xinetd (/etc/inetd.conf)
  * Goes through /etc/rc.d/rc.* and disables plenty of those
* Enables a bunch of useful services
  * rc.firewall
  * Through rc.local:
    * logoutd
    * icmpinfo
  * Process accounting (acct)
  * System accounting (sysstat)

#### Hardens few specific services

  * SSH
  * Sendmail

### File system related

* Hardens mount options (creates /etc/fstab.new)
* Removes a bunch of SUID/SGID bits
  * at
  * chfn + chsh
  * uucp package
  * floppy package (/usr/bin/fdmount)
  * ssh-keysign
* Sets more strict permissions on certain files that might contain secrets or other sensitive information
  * btmp, utmp, wtmp
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

#### Logging

* Makes default log files group adm readable (as in Debian)
* Use shred to remove rotated log files

TODO
----

* chattr certain files
* Checksums for log files

References
----------

* [CIS Slackware Linux 10.2 Benchmark v1.1.0][1]
* [Slackware System Hardening][2] by Jeffrey Denton


[1]: http://benchmarks.cisecurity.org/downloads/browse/index.cfm?category=benchmarks.os.linux.slackware
[2]: http://dentonj.freeshell.org/system-hardening-10.2.txt
