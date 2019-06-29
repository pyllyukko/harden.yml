Slackware specific hardening
============================

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

Then there's separate patch files for different services/daemons. See [the services section](#hardens-few-specific-services) for more information.

What does it do?
----------------

**DISCLAIMER**: This is not a complete list.

### Authentication

* "Fix" the single-user mode to use `su-login` instead of `agetty`
* Configures a bit better password policy to `login.defs`
* Changes the hashing mechanism to [SHA512](https://en.wikipedia.org/wiki/SHA-2) and more crypt rounds

### Authorization

* Sets a maximum number of failed login attempts (`faillog`)
* Create login access control table (`/etc/login.access`)
* Create access time file (`/etc/porttime`)
* ~~/etc/limits~~
* `/etc/login.defs`:
  * Disallow logins if home dir does not exist
* SSH `AllowGroups users`
* Restrict the use of `su` (prefer [sudo][11] instead)
  * `/etc/suauth`
  * `/etc/porttime`
  * `/etc/login.defs`: `SU_WHEEL_ONLY`
* Restrict use of cron

### Accounting

* Enable [process accounting][9] (acct)
  * Log rotation for process accounting (pacct), since these files **will** grow huge

### Harden user accounts

* Sets restrictions for normal users
  * Sets the [maximum number of processes available to a single user](https://en.wikipedia.org/wiki/Fork_bomb#Prevention) (```ulimit -u```)
  * Sets the maximum size of core files created (```ulimit -c```)
  * Sets a session timeout (```TMOUT```) in certain conditions
  * Sets stricter umask in all the following locations:
    * /etc/login.defs
    * ~~/etc/limits~~
    * /etc/profile
* Removes "unnecessary" shells
* Sets ```useradd``` defaults
  * ```INACTIVE``` days to lock accounts after the password expires
  * ```rbash``` as default shell
* Removes user daemon from group ```adm``` (as we will take use of the ```adm``` group)
* Fix ```gshadow``` with ```grpck```

#### Groups

 * Makes default log files group ```adm``` readable ([as in Debian](http://www.debian.org/doc/manuals/debian-reference/ch01.en.html#listofnotablesysupsforfileaccess))
 * Users in the [wheel][12] group are able to create cronjobs (as described in [/usr/doc/dcron-4.5/README][8])
 * Even though we use [user private groups](https://en.wikipedia.org/wiki/File_system_permissions#User_private_group), the ```users``` group is used to define which users are allowed to login interactively

### Configures services

* Removes unnecessary services
  * xinetd (```/etc/inetd.conf```)
  * Goes through ```/etc/rc.d/rc.*``` and disables plenty of those
  * ```atd``` from ```rc.M```
* [X11 -nolisten tcp](http://docs.slackware.com/howtos:security:basic_security#x_-nolisten_tcp)

#### Enable some security and auditing related services

* rc.firewall
* Through rc.local:
  * logoutd
  * icmpinfo
  * ```mdadm --monitor``` (if ```/proc/mdstat``` exists)
* [Process accounting][9] (acct)
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
* [sudo][11]
  * Don't cache the password (```timestamp_timeout```) (should also mitigate against [CVE-2013-1775](http://www.sudo.ws/sudo/alerts/epoch_ticket.html))
  * Always require password with ```sudo -l``` (```listpw```)
  * noexec as default
  * Require root's password instead of user's
  * Send alerts on most errors
  * Additional logging to ```/var/log/sudo.log```
* [PHP](https://www.owasp.org/index.php/Configuration#PHP_Configuration)
* Apache httpd

### File system related

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
* Enables RAID state monitoring with ```mdadm --monitor```

**TODO**: Add a table about file ownership & permission changes. At least the most relevant ones.

### Network related

* Creates and enables a basic firewall
* Optional static ARP cache through ```/etc/rc.d/rc.static_arp```

### Other controls

* Modifies crontab behaviour a bit
  * Users in the [wheel][12] group are able to create cronjobs (as described in [/usr/doc/dcron-4.5/README][8])
  * Increase cron's logging from ```notice``` to ```info```
  * Notice that Dillon's cron does not support the ```/etc/cron.{allow,deny}``` lists
* Clear ```/tmp``` on boot (also recommended in [FHS](http://refspecs.linuxfoundation.org/FHS_2.3/fhs-2.3.html#PURPOSE17))
  * **TODO**: is it redundant to have it both in ```rc.M``` and ```rc.S```?
* Removes unnecessary / potentially dangerous packages
  * netkit-rsh
  * uucp
  * [floppy][7]
* Make ```installpkg``` store the MD5 checksums

#### Periodic checks

Some things are added to cron: **TODO**

* [rkhunter](https://github.com/pyllyukko/harden.sh/blob/master/newconfs/cron.d/rkhunter.new)

##### sysstat

From [sysstat.crond](https://github.com/sysstat/sysstat/blob/master/cron/sysstat.crond.in):

```
# Run system activity accounting tool every 10 minutes
*/10 * * * * if [ -x /usr/lib64/sa/sa1 ]; then /usr/lib64/sa/sa1 -S DISK 1 1; elif [ -x /usr/lib/sa/sa1 ]; then /usr/lib/sa/sa1 -S DISK 1 1; fi
# 0 * * * * /usr/lib/sa/sa1 -S DISK 600 6 &
# Generate a daily summary of process accounting at 23:53
53 23 * * * if [ -x /usr/lib64/sa/sa2 ]; then /usr/lib64/sa/sa2 -A; elif [ -x /usr/lib/sa/sa2 ]; then /usr/lib/sa/sa2 -A; fi
```

#### Physical security related

* Sets the [authorized\_default](https://www.kernel.org/doc/Documentation/usb/authorization.txt) to USB devices
* X11:
  * ```DontZap```
* ```/etc/shutdown.allow``` and ```/sbin/shutdown -a``` (FWIW)

##### Wipe

**WARNING**: This is a highly experimental and dangerous feature (and completely optional)! Use at your own risk!

This is something that has been cooking for a while now. It's a self-destruct sequence for your server :)

The patch creates a new runlevel (**5**) to your Slackware, which when activated, will remove LUKS headers from your disk and copies them inside the encrypted disk. So if anything should happen, the server is not restorable anymore, as the disk encryption keys are gone. When the runlevel is switched back (to say 3), the headers are written back to where they belong.

So to wipe LUKS headers, you just switch to runlevel 5: `telinit 5` and to restore just switch back to 3: `telinit 3`.

There is still some issues, such as some services will be started again (such as ```crond```) when returning to runlevel 3. This is because ```rc.M``` doesn't really consider users switching back and forth between runlevels. So this is a work-in-progress.

As a workaround, there is also a new runlevel **2** that can be used to safely return from runlevel 5. Now we don't need to care about daemons starting over and over again from ```rc.M``` (runlevel 3).

#### Logging

* Makes default log files group ```adm``` readable ([as in Debian](http://www.debian.org/doc/manuals/debian-reference/ch01.en.html#listofnotablesysupsforfileaccess))
  * Notice that this takes place only after logrotate. The ownerships/permissions of the existing logs are not modified.
* Use ```shred``` to remove rotated log files
* Enables the use of ```xconsole``` (or makes it possible). You can use it with [sudo][11] as follows: ```ADMINS ALL=(:adm) NOPASSWD: /usr/bin/xconsole```
* Enables ```bootlogd```
* Makes certain log files [append only](http://www.seifried.org/lasg/logging/)
* Increase the default log retention period to 26 weeks
* Increase wtmp log size through logrotate

#### Principle of least privilege

* You can use the ```adm``` group to view log files, so you don't need to be ```root``` to do that. Just add a user to the ```adm``` group, or configure [sudo][11] as follows:
  * ```ADMINS ALL=(:adm) NOPASSWD: /bin/cat```
  * View bad logins with: ```ADMINS ALL=(:adm) NOPASSWD: /usr/bin/lastb```
  * Or recent logins: ```ADMINS ALL=(:adm) NOPASSWD: /usr/bin/lastlog ""```
* Remove ```floppy``` and ```scanner``` from ```CONSOLE_GROUPS```
* Restrict the use of ```at``` and ```cron``` from regular users

### Additional features

* Download & verify Slackware ```MANIFEST``` by running ```make manifest```
* Check Slackware installation's integrity from ```MANIFEST``` (owner & permission) (```-I``` switch)

Other security software
-----------------------

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

[3]: http://slackbuilds.org/repository/14.1/network/p0f/
[4]: http://slackbuilds.org/repository/14.1/system/clamav/
[5]: http://slackbuilds.org/repository/14.1/system/audit/
[6]: http://slackbuilds.org/repository/14.1/network/arpwatch/
[7]: ftp://ftp.slackware.com/pub/slackware/slackware-14.1/source/a/floppy/
[8]: http://www.jimpryor.net/linux/dcron-README
[9]: http://www.tldp.org/HOWTO/Process-Accounting/
[10]: http://sebastien.godard.pagesperso-orange.fr/
[11]: http://www.sudo.ws/
[12]: https://en.wikipedia.org/wiki/Wheel_%28Unix_term%29
