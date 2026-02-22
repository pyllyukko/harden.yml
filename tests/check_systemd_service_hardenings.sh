#!/bin/bash

# This script is to check for existing systemd service hardening in certain services.
#
# If any of these exist in the services we are hardening, we prefer not to mess
# around with them, and not to overwrite upstream settings.

for service in cron dbus plymouth-start
do
  echo "[*] Checking service ${service}"
  file="/usr/lib/systemd/system/${service}.service"
  if [ ! -f "${file}" ]
  then
    echo "[-] \`${file}' not found" 1>&2
    exit 1
  fi
  for hardening in \
    KeyringMode			\
    MemoryDenyWriteExecute	\
    ProtectClock		\
    ProtectControlGroups	\
    ProtectHome			\
    ProtectHostname		\
    ProtectHostname		\
    ProtectKernelModules	\
    ProtectKernelTunables	\
    LockPersonality		\
    SystemCallArchitectures	\
    RestrictNamespaces		\
    PrivateTmp			\
    SystemCallFilter		\
    RestrictSUIDSGID		\
    NoNewPrivileges		\
    ProtectSystem
  do
    if grep "^${hardening}\b" "${file}"
    then
      echo "[*] ${hardening} already exists in \`${file}'" 1>&2
      exit 1
    fi
  done
done
