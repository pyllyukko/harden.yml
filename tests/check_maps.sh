#!/bin/bash

# This script is meant to find out whether service is suitable for systemd MemoryDenyWriteExecute hardening

for service in $(systemctl list-units --no-pager --no-legend --type=service --state=running | gawk '{print$1}')
do
  pid="$(systemctl show --property MainPID "${service}" | sed 's/^MainPID=//')"
  if [ -n "${pid}" ]
  then
    maps="$(gawk '$2 ~ /^.wx.$/{print}' "/proc/${pid}/maps")"
    if [ -n "${maps}" ]
    then
      echo "[-] Service ${service} has WX pages" 1>&2
      cat "/proc/${pid}/maps"
    fi
  fi
done
