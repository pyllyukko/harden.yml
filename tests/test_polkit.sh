#!/bin/bash

# Used by run0
action="org.freedesktop.systemd1.manage-units"

if [ ${#} -ne 1 ] || [[ ! ${1} =~ ^[0-9]+$ ]]
then
  echo '[-] Error' 1>&2
  exit 1
fi

/usr/bin/pkcheck --action-id "${action}" --process $$
ret=${?}
echo "[*] pkcheck returned ${ret}"
if [ ${ret} -ne "${1}" ]
then
  exit 1
fi
