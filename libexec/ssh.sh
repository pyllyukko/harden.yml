#!/bin/bash
# TODO:
#   - PubkeyAcceptedKeyTypes
#   - HostKeyAlgorithms
#   - Ciphers
#   - MACs
#   - KEX
declare -rA SSHD_CONFIG=(
  # from hardening guides
  ["Protocol"]=2
  ["LogLevel"]="INFO"
  ["X11Forwarding"]="no"
  ["MaxAuthTries"]=4
  ["IgnoreRhosts"]="yes"
  ["HostbasedAuthentication"]="no"
  ["PermitRootLogin"]="no"
  ["PermitEmptyPasswords"]="no"
  ["PermitUserEnvironment"]="no"
  # ciphers
  # mac
  ["ClientAliveInterval"]=300
  ["ClientAliveCountMax"]=0
  ["LoginGraceTime"]=60

  # custom
  ["PubkeyAuthentication"]="yes"
  ["UseLogin"]="no"
  ["StrictModes"]="yes"
  ["PrintLastLog"]="yes"
  ["UsePrivilegeSeparation"]="sandbox"
  # see http://www.openssh.com/txt/draft-miller-secsh-compression-delayed-00.txt
  ["Compression"]="delayed"
  ["AllowTcpForwarding"]="no"
  ["FingerprintHash"]="sha256"
)
################################################################################
function configure_sshd() {
  local setting
  cat 0<<-EOF
	
	configuring sshd
	----------------
EOF
  if [ ! -f /etc/ssh/sshd_config ]
  then
    echo "[-] error: /etc/ssh/sshd_config not found!" 1>&2
    return 1
  fi
  for setting in ${!SSHD_CONFIG[*]}
  do
    printf "[+] %-23s -> %s\n" ${setting} ${SSHD_CONFIG[${setting}]}
    sed_with_diff "s/^\(# \?\)\?\(${setting}\)\(\s\+\)\S\+$/\2\3${SSHD_CONFIG[${setting}]}/" /etc/ssh/sshd_config
    if ! grep -q "^${setting}\s\+${SSHD_CONFIG[${setting}]}$" /etc/ssh/sshd_config
    then
      echo "[-] failed to set ${setting}" 1>&2
    fi
  done
  chmod -c ${FILE_PERMS["/etc/ssh/sshd_config"]} /etc/ssh/sshd_config | tee -a "${logdir}/file_perms.txt"
} # configure_sshd()
