#!/bin/bash

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

ssh-audit -c&
sleep 1
ssh -p 2222 user@localhost
wait
