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
declare -rA SSH_CONFIG=(
  ["VisualHostKey"]="yes"
  ["Protocol"]=2
  ["Ciphers"]="chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr"
  ["MACs"]="hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-ripemd160-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"
  ["KexAlgorithms"]="curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256"
  ["HashKnownHosts"]="yes"
  ["IdentitiesOnly"]="yes"
  ["StrictHostKeyChecking"]="yes"
  ["CheckHostIP"]="yes"
  ["FingerprintHash"]="sha256"
  # TODO: ecdsa-*
  ["HostKeyAlgorithms"]="ssh-ed25519-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-ed25519,ssh-rsa"
  ["PermitLocalCommand"]="no"
  ["VerifyHostKeyDNS"]="ask"
  #["PubkeyAcceptedKeyTypes"]=""
)
################################################################################
function configure_sshd() {
  local setting
  print_topic "configuring sshd"
  (( ${LYNIS_TESTS} )) && local LYNIS_SCORE_BEFORE=$( get_lynis_hardening_index ssh )
  check_for_conf_file "/etc/ssh/sshd_config" || return 1
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
  (( ${LYNIS_TESTS} )) && {
    local LYNIS_SCORE_AFTER=$( get_lynis_hardening_index ssh )
    compare_lynis_scores "${LYNIS_SCORE_BEFORE}" "${LYNIS_SCORE_AFTER}"
    check_lynis_tests SSH-7408
  }
} # configure_sshd()
################################################################################
function configure_ssh() {
  local setting
  print_topic "configuring ssh"
  check_for_conf_file "/etc/ssh/ssh_config" || return 1
  if ! grep -q '^Host \*$' /etc/ssh/ssh_config
  then
    sed_with_diff 's/^#\s\+\(Host \*\)$/\1/' /etc/ssh/ssh_config || {
      echo '[-] failed to set line "^Host *$"' 1>&2
      return 1
    }
  fi
  for setting in ${!SSH_CONFIG[*]}
  do
    printf "[+] %-23s -> %s\n" ${setting} ${SSH_CONFIG[${setting}]}
    sed_with_diff "s/^\(# \)\?  \(${setting}\)\(\s\+\)\S\+$/  \2\3${SSH_CONFIG[${setting}]}/" /etc/ssh/ssh_config
    # TODO: append the settings that aren't present in the example ssh_config
    if ! grep -q "^${setting}\s\+${SSH_CONFIG[${setting}]}$" /etc/ssh/ssh_config
    then
      echo "[-] failed to set ${setting}" 1>&2
    fi
  done
  chmod -c ${FILE_PERMS["/etc/ssh/ssh_config"]} /etc/ssh/ssh_config | tee -a "${logdir}/file_perms.txt"
} # configure_sshd()
