Benchmarks
==========

Slackware
---------

Lynis benchmarks.

The test is performed against a setup like this:

* A minimal Slackware installation with some 135 packages installed
  * No additional security related tools installed
  * Running with latest patches
* One big root partition
  * No LUKS
* The hardening is done with ```./harden.sh -A```
  * The system is booted after hardening
* [AUTH-9262](http://cisofy.com/controls/AUTH-9262/) test disabled

| Date		| Slackware version	                             | Packages installed | Lynis version | Tests performed | Hardening index (before) | Hardening index (after) | harden.sh version                        |
| ------------- | -------------------------------------------------- | ------------------ | ------------- | --------------- | ------------------------ | ----------------------- | ---------------------------------------- |
| 24.9.2014	| slackware64-14.1	                             | ~135               | 1.6.2         |                 | 43                       | 68 (+25)                | 155ad8536aed9e30197d645031c72d79ad93f3f4 |
|  2.7.2016	| slackware64-14.2	                             | ~148               | 2.2.0         | 171 (174)       | 53                       | 72 (+19)                | 24ab7d6afe63ccef06f0434619cafd47db41d820 |

Debian
------

* Installed with:
  * SSH server
  * standard system utilities
* One big root partition
  * No LUKS
* The hardening is done with ```./harden.sh -q```
* Debian plugin disabled

| Date       | Debian version  | Packages installed | Lynis version | Tests performed | Hardening index (before) | Hardening index (after) | harden.sh version                        |
| ---------- | --------------- | ------------------ | ------------- | --------------- | ------------------------ | ----------------------- | ---------------------------------------- |
| 4.11.2017  | 9.2             | 352                | 2.5.7         | 197             | 62                       | 79 (+17)                | ee4c0a970c1d552a9bbabbbf410cc8d98535798b |
