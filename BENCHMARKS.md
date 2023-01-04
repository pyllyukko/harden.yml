Benchmarks
==========

Do note that `lynis.yml` will make few changes to `/etc/lynis/{default,custom}.prf` and this probably affects scoring, but they are already effective when measuring the baseline.

Kali
----

* Installed with `vagrant up`
    * Not updated, so [PKGS-7392](https://cisofy.com/lynis/controls/PKGS-7392/) most certainly applies
* Initial provisioning with `lynis` tag only
* `lynis -Q` for baseline score
* `vagrant provision`
    * Skip tags: `slackware,centos`
* Reboot
* `lynis -Q` for hardened score

| Date       | Kali version | Lynis version | Tests performed (before) | Hardening index (before) | Tests performed (after) | Hardening index (after) | harden.yml version                       |
| ---------- | ------------ | ------------- | ------------------------ | ------------------------ | ----------------------- | ----------------------- | ---------------------------------------- |
| 29.12.2022 | 2022.4.0     | 3.0.8         | 253                      | 59                       | 260                     | 86 (+27)                | 1c30356ffa9d35f5cdf65702b3e3c92047fd0aca |

Debian
------

* Installed with Vagrant as instructed [here](https://wiki.debian.org/Vagrant)
    * NFS sharing disabled with `config.vm.synced_folder '.', '/vagrant', disabled: true`
    * Not updated, so [PKGS-7392](https://cisofy.com/lynis/controls/PKGS-7392/) most certainly applies
* Initial provisioning with `lynis` tag only
* `lynis -Q` for baseline score
* `vagrant provision`
    * Skip tags: `slackware,centos,rng`
* Reboot
* `lynis -Q` for hardened score

| Date       | Debian version | Lynis version | Tests performed (before) | Hardening index (before) | Tests performed (after) | Hardening index (after) | harden.yml version                                                                            |
| ---------- | -------------- | ------------- | ------------------------ | ------------------------ | ----------------------- | ----------------------- | --------------------------------------------------------------------------------------------- |
|   4.1.2023 | 11.6           | 3.0.8         | 240                      | 60                       | 250                     | 86 (+26)                | [b8f72258434b9a1faa7deb7c75d1d2323e1d8633](https://asciinema.org/a/ojiSlzrTZkvXSG1s0MPCMLmrE) |
