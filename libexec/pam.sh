#!/bin/bash
function configure_core_dumps() {
  # slackware uses /etc/limits and is configured through limits.new file
  local file="${ROOTDIR:-/}etc/security/limits.conf"
  cat 0<<-EOF
	
	configuring core dumps
	----------------------
EOF
  if [ ! -f "${file}" ]
  then
    echo "[-] ${file} NOT found" 1>&2
    return 1
  fi
  echo "[+] ${file} found"
  sed_with_diff 's/^#\?\*\( \+\)soft\( \+\)core\( \+\)0$/*\1hard\2core\30/' "${file}"
  return ${?}
  # TODO: nproc - max number of processes
} # configure_core_dumps()
