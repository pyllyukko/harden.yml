#!/bin/bash

ca_file=./ca-certificates.crt

while read -r
do
  if [ ! -f "/usr/share/ca-certificates/${REPLY}" ]
  then
    echo -e "[\033[1;31m-\033[0m] CA \`${REPLY}' does not exist" 1>&2
    exit 1
  fi
  cat "/usr/share/ca-certificates/${REPLY}"
done 0<files/ca-certificates.conf.new 1>"${ca_file}"

# HTTPS
for host in \
  media.defcon.org		\
  download.docker.com		\
  www.offsec.com		\
  www.unicorn-engine.org	\
  www.eff.org			\
  dl.discordapp.net		\
  www.mirrorservice.org		\
  www.fireeye.com		\
  storage.googleapis.com	\
  www.dwheeler.com		\
  cdn.kernel.org		\
  cisofy.com			\
  letsencrypt.org		\
  zerossl.com			\
  github.com			\
  www.gandi.net			\
  deb.debian.org		\
  downloads.openwrt.org		\
  packages.mozilla.org		\
  packagecloud.io
do
  echo "[*] Testing HTTPS for \`${host}'"
  openssl s_client -connect "${host}":443 -verify_return_error -CAfile "${ca_file}" -showcerts 0</dev/null || exit 1
  echo -n $'\n'
done

# Mail servers
for host in \
  mx01.mail.icloud.com				\
  alt4.gmail-smtp-in.l.google.com		\
  outlook-com.olc.protection.outlook.com	\
  hotmail-com.olc.protection.outlook.com	\
  mta7.am0.yahoodns.net				\
  mail.cwo.com					\
  mail.protonmail.ch				\
  spool.mail.gandi.net				\
  fb.mail.gandi.net				\
  mx-tnl.mail.saunalahti.fi			\
  mx-stp.mail.saunalahti.fi
do
  echo "[*] Testing SMTP STARTTLS for \`${host}'"
  openssl s_client -connect "${host}":25 -starttls smtp -verify_return_error -CAfile "${ca_file}" -showcerts 0</dev/null || exit 1
  echo -n $'\n'
done

rm -v "${ca_file}"
