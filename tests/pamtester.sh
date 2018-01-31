#!/bin/bash

declare -a services=(
  "login"
  "sshd"
)

# random users should not be able to use cron
# enforced with pam_access
pamtester cron nobody acct_mgmt && exit 1

# random users should not be able to use atd
# enforced with pam_access
pamtester atd nobody acct_mgmt && exit 1

# su shouldn't be allowed
# this test doesn't work because of pam_rootok
#pamtester su nobody authenticate

# unknown services
for operation in "authenticate" "acct_mgmt" "chauthtok" "open_session"
do
  pamtester nonexistent nobody "${operation}" && exit 1
done

# securetty
#pamtester -I tty=/dev/ttyS0 login root authenticate

# TODO: tally2, nologin
