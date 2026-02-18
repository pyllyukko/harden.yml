#!/bin/bash

destination="user@localhost"

if ! hash ssh-audit
then
  echo "[-] ssh-audit not found" 1>&2
  exit 1
fi
if ! hash ssh
then
  echo "[-] SSH client not found" 1>&2
  exit 1
fi

# Print conf
ssh -G "${destination}"

# Start ssh-audit client audit
ssh-audit -c&
# Wait for it to start properly
sleep 1
# Connect to ssh-audit
ssh -p 2222 "${destination}"
wait
