#!/bin/bash
declare -r SA_RC="/etc/rc.d/rc.sysstat"
function enable_sysstat() {
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
  elif [ -f /etc/default/sysstat ]
  then
    echo "[+] enabling sysstat through /etc/default/sysstat"
    sed -i 's/^ENABLED="false"$/ENABLED="true"/' /etc/default/sysstat
  fi
  if [ -f /etc/sysstat/sysstat ]
  then
    echo "[+] setting HISTORY -> 99999"
    # make it store the data a bit longer =)
    sed -i 's/^\(HISTORY=\).*$/HISTORY=99999/' /etc/sysstat/sysstat
  # red hat
  elif [ -f /etc/sysconfig/sysstat ]
  then
    echo "[+] setting HISTORY -> 99999"
    sed -i 's/^\(HISTORY=\).*$/HISTORY=99999/' /etc/sysconfig/sysstat
  fi
} # enable_sysstat()
