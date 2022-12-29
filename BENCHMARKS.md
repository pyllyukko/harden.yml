Benchmarks
==========

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
