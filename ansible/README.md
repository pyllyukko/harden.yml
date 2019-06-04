Hardening with Ansible - WIP!
=============================

This is a work-in-progress. Don't expect all the same functionality/hardenings as the main script has.

[![asciicast](https://asciinema.org/a/Hq1esBXvDZz95MHLnPxPyEAor.png)](https://asciinema.org/a/Hq1esBXvDZz95MHLnPxPyEAor)

Supported distros
-----------------

* Debian (Stretch)
    * Kali
    * Raspbian
* Slackware (>= 15.0)
* No CentOS yes

LXC tests
---------

In order to run the LXC tests (`lxc.yml`), you need to configure SSH as described in [this post](https://gauvain.pocentek.net/ansible-to-deploy-lxc-containers.html):

```
Host 10.0.3.*
        StrictHostKeyChecking no
        UserKnownHostsFile=/dev/null
```
