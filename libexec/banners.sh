#!/bin/bash
function create_banners() {
  local owner
  local regex
  local file

  print_topic "creating banners"

  for file in /etc/issue /etc/issue.net /etc/motd
  do
    echo "[+] creating ${file}"
    make -f ${CWD}/Makefile ${file}
  done

  if [ -f /etc/gdm3/greeter.dconf-defaults ]
  then
    echo "[+] configuring banner to gdm3"
    for regex in \
      's/^.*banner-message-enable=.*$/banner-message-enable=true/' \
      "s/^.*banner-message-text=.*$/banner-message-text='Authorized uses only.'/"
    do
      sed_with_diff "${regex}" /etc/gdm3/greeter.dconf-defaults
    done
  fi
  # TODO: lightdm

  if [ -f /etc/ssh/sshd_config ]
  then
    echo "[+] configuring banner to sshd"
    sed_with_diff "s/^\(# \?\)\?\(Banner\)\(\s\+\)\S\+$/\2\3\/etc\/issue.net/" /etc/ssh/sshd_config
  fi

  return 0
} # create_banners()
