TODO
----

* Immutable flags with ```chattr``` on certain files
* X hardening
* Debian support
* Some chroot stuff?
* ~~Logging of the script actions~~ -> partly done
  * User account modifications
  * Get start/stop times and grab /var/log/secure between that range
* some kernel module configurator thingie for /etc/rc.d/rc.modules
* [LUKS nuke](http://www.kali.org/how-to/nuke-kali-linux-luks/)
* Provide the ```trustedkeys.gpg``` PGP keys with this tool?
* ~~Add some functionality, that compares your current file system against Slackware's [MANIFEST](ftp://ftp.slackware.com/pub/slackware/slackware64-14.1/slackware64/MANIFEST.bz2) (something like Alien's [restore\_fileperms\_from\_manifest.sh](http://www.slackware.com/~alien/tools/restore_fileperms_from_manifest.sh))~~
  * Some HIDS baseline generation from MANIFEST would also be really nice
* Add [CCE](https://nvd.nist.gov/cce/index.cfm) references?
* /usr/bin/ch{mod,own} -> from PATH. since Debian has them under /bin
* Create ```.preharden``` backups (only once?)
* Java's CAs
* Some kind of ```make buildworld``` script to rebuild everything with full RELRO, stack canaries, [PIE](https://en.wikipedia.org/wiki/Position-independent_code#Position-independent_executables) & ```-D_FORTIFY_SOURCE=2```

### Auth/user account related

* Some variables to read only?
  * From rbash: SHELL, PATH, ENV, or BASH\_ENV
  * From system-hardening-10.2.txt: HISTCONTROL HISTFILE HISTFILESIZE HISTIGNORE HISTNAME HISTSIZE LESSSECURE LOGNAME USER
* ```faillog``` for new users?
* User quotas
* [PAM](http://www.slackware.com/~vbatts/pam/) for Slackware?
  * Two-factor authentication
* Shadow suite S/Key support (/usr/doc/shadow-4.1.4.3/README)
* How do we reset faillogs after successful login?
* [Create .gnupg home directories](http://www.gnupg.org/documentation/manuals/gnupg/addgnupghome.html#addgnupghome)
* ```USERDEL_CMD``` from LOGIN.DEFS(5)
* Is it possible to enforce password policy for root user also?
* Use of ```at``` when in [wheel][12] group?

### Guides to read

* <http://www.nsa.gov/ia/_files/os/redhat/rhel5-guide-i731.pdf>
* [UNIX and Linux Security Checklist v3.0](http://www.auscert.org.au/5816)
* <http://www.puschitz.com/SecuringLinux.shtml>
* <http://linuxgazette.net/issue91/kruk.html>
* <https://www.sans.org/score/unixchecklist.php>
* Maybe some tips from <http://www.debian.org/doc/user-manuals#securing>
* <http://www.symantec.com/connect/articles/restricting-unix-users>
* <https://wiki.archlinux.org/index.php/Security>
