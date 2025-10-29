#!/bin/bash

if [ -n "${CONNECTION_ID}" ]
then
  connection_type="$(/usr/bin/nmcli connection show "${CONNECTION_ID}" | gawk '$1=="connection.type:"{print$2}')"
  if [ "${connection_type}" = "802-11-wireless" -o \
       "${connection_type}" = "802-3-ethernet" ]
  then
    # To mitigate https://github.com/leviathansecurity/TunnelVision
    /usr/bin/nmcli connection modify "${CONNECTION_ID}" ipv4.ignore-auto-routes yes
    /usr/bin/nmcli connection modify "${CONNECTION_ID}" ipv6.ignore-auto-routes yes
  fi
fi
