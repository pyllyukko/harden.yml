#!/bin/bash
function create_banners() {
  local owner
  local regex

  cat 0<<-EOF
	
	creating banners
	----------------
EOF

  echo "[+] creating /etc/issue"
  #cat "${CWD}/newconfs/issue.new"	1>/etc/issue
  #read -p 'company/organization/owner? ' owner
  #sed -i 's/\[insert company name here\]/'"${owner}"'/' /etc/issue
  echo "Authorized uses only. All activity may be monitored and reported." 1>/etc/issue

  echo "[+] creating /etc/issue.net"
  cp -vf /etc/issue /etc/issue.net
  #echo "Authorized uses only. All activity may be monitored and reported." 1>>/etc/issue.net

  echo "[+] creating /etc/motd"
  cat "${CWD}/newconfs/motd.new"	1>/etc/motd

  {
    chown -c root:root /etc/motd /etc/issue /etc/issue.net
    chmod 644 /etc/motd /etc/issue /etc/issue.net
  } | tee -a "${logdir}/file_perms.txt"

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
    sed -i "s/^\(# \?\)\?\(Banner\)\(\s\+\)\S\+$/\2\3\/etc\/issue.net/" /etc/ssh/sshd_config
  fi

  return 0
} # create_banners()
