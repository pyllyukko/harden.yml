#!/bin/bash
function gnome_settings() {
  local file
  # Settings -> Privacy -> Usage & History -> Recently Used
  gsettings set org.gnome.desktop.privacy remember-recent-files false
  gsettings set org.gnome.desktop.privacy recent-files-max-age  1
  # TODO: Clear Recent History
  gsettings set org.gnome.system.location enabled false

  # https://wiki.gnome.org/Projects/Tracker/
  # in addition to this, you might want to run "tracker reset --hard"
  # "Monitor file and directory changes"
  gsettings set org.freedesktop.Tracker.Miner.Files enable-monitors false
  # "Index content of files found"
  gsettings set org.freedesktop.Tracker.FTS max-words-to-index 0
  # "Enable when running on battery"
  gsettings set org.freedesktop.Tracker.Miner.Files index-on-battery false

  shopt -s nullglob
  # this still leaves tracker-store, which is started from D-Bus.
  for file in /etc/xdg/autostart/tracker-*.desktop
  do
    if ! grep '^Hidden=true$' "${file}"
    then
      sed_with_diff '$a Hidden=true' "${file}"
    fi
  done
} # gnome_settings()
################################################################################
function disable_gdm3_user_list() {
  local setting
  local value
  print_topic "configuring display manager(s)"

  if [ -f /etc/gdm3/greeter.dconf-defaults ]
  then
    echo '[+] disabling user list in /etc/gdm3/greeter.dconf-defaults'
    sed_with_diff '/disable-user-list=true$/s/^#\s*//' /etc/gdm3/greeter.dconf-defaults
    # TODO: go through the rest of /etc/gdm3/greeter.dconf-defaults
  elif [ -f /etc/lightdm/lightdm.conf ]
  then
    for setting in ${!LIGHTDM_CONFIG[*]}
    do
      value="${LIGHTDM_CONFIG[${setting}]}"
      echo "[+] setting ${setting} to ${value} in /etc/lightdm/lightdm.conf"
      # ^#\?key=value$
      sed_with_diff "s/^#\?\(${setting}\)=.*$/\1=${value}/" /etc/lightdm/lightdm.conf
    done
  else
    echo '[-] display manager greeter config not found'
  fi
  # https://wiki.ubuntu.com/LightDM#Disabling_Guest_Login
  if [ -d /etc/lightdm/lightdm.conf.d ]
  then
    echo '[+] disallowing guest sessions in LightDM'
    echo -e '[Seat:*]\nallow-guest=false' 1>/etc/lightdm/lightdm.conf.d/50-disallow-guest.conf
  fi
  # TODO: greeter-allow-guest in /etc/lightdm/lightdm.conf (in Pi)
} # disable_gdm3_user_list()
################################################################################
