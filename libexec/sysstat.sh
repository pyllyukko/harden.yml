#!/bin/bash
declare -r SA_RC="${ROOTDIR:-/}etc/rc.d/rc.sysstat"
function enable_sysstat() {
  local -i ret=0
  cat 0<<-EOF
	
	enabling system accounting
	--------------------------
EOF
  if [ -f "${SA_RC}" ]
  then
    echo "[+] enabling sysstat through ${SA_RC}"
    # CIS 1.4 Enable System Accounting
    /usr/bin/chmod -c 700 "${SA_RC}" | tee -a "${logdir}/file_perms.txt"
  # enable sysstat in Debian
  elif [ -f ${ROOTDIR:-/}etc/default/sysstat ]
  then
    echo "[+] enabling sysstat through /etc/default/sysstat"
    sed_with_diff 's/^ENABLED="false"$/ENABLED="true"/' ${ROOTDIR:-/}etc/default/sysstat
    ((ret|=${?}))
  fi
  if [ -f ${ROOTDIR:-/}etc/sysstat/sysstat ]
  then
    echo "[+] setting HISTORY -> 99999"
    # make it store the data a bit longer =)
    sed_with_diff 's/^\(HISTORY=\).*$/HISTORY=99999/' ${ROOTDIR:-/}etc/sysstat/sysstat
    ((ret|=${?}))
  # red hat
  elif [ -f ${ROOTDIR:-/}etc/sysconfig/sysstat ]
  then
    echo "[+] setting HISTORY -> 99999"
    sed_with_diff 's/^\(HISTORY=\).*$/HISTORY=99999/' ${ROOTDIR:-/}etc/sysconfig/sysstat
    ((ret|=${?}))
  else
    echo '[-] sysstat config not found' 1>&2
    ret=1
  fi
  return ${ret}
} # enable_sysstat()
