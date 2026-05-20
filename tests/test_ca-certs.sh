#!/bin/bash

ca_file=./ca-certificates.crt
ca_dir="/usr/share/ca-certificates"
echo "[*] Fetching Slackware's CA package version"
slackware_ca="$(curl ftp://ftp.slackware.com/pub/slackware/slackware64-15.0/patches/packages/ | gawk '$9 ~ /^ca-certificates-[0-9]{8}-noarch-[0-9]+_slack15\.0\.txz$/{print$9}')"

if [ -n "${slackware_ca}" ]
then
  echo "[*] Downloading CA package from Slackware"
  wget -N \
    "ftp://ftp.slackware.com/pub/slackware/slackware64-15.0/patches/packages/${slackware_ca}" \
    "ftp://ftp.slackware.com/pub/slackware/slackware64-15.0/patches/packages/${slackware_ca}.asc"
  gpg --keyring trustedkeys.kbx --no-default-keyring --import 0<<-EOF
	-----BEGIN PGP PUBLIC KEY BLOCK-----
	Version: GnuPG v1.4.12 (GNU/Linux)
	
	mQGiBD5dIFQRBADB31WinbXdaGk/8RNkpnZclu1w3Xmd5ItACDLB2FhOhArw35EA
	MOYzxI0gRtDNWN4pn9n74q4HbFzyRWElThWRtBTYLEpImzrk7HYVCjMxjw5A0fTr
	88aiHOth5aS0vPAoq+3TYn6JDSipf2bR03G2JVwgj3Iu066pX4naivNm8wCgldHG
	F3y9vT3UPYh3QFgEUlCalt0D/3n6NopRYy0hMN6BPu+NarXwv6NQ9g0GV5FNjEEr
	igkrD/htqCyWAUl8zyCKKUFZZx4UGBRZ5guCdNzwgYH3yn3aVMhJYQ6tcSlLsj3f
	JIz4LAZ3+rI77rbn7gHHdp7CSAuV+QHv3aNanUD/KGz5SPSvF4w+5qRM4PfPNT1h
	LMV8BACzxiyX7vzeE4ZxNYvcuCtv0mvEHl9yD66NFA35RvXaO0QiRVYeoUa5JOQZ
	gwq+fIB0zgsEYDhXFkC1hM/QL4NccMRk8C09nFn4eiz4dAEnwKt4rLCJKhkLl1DW
	TSoXHe/dOXaLnFyLzB1J8hEYmUvw3SwPt//wMqDiVBLeZfFcdLQwU2xhY2t3YXJl
	IExpbnV4IFByb2plY3QgPHNlY3VyaXR5QHNsYWNrd2FyZS5jb20+iF8EExECAB8E
	CwcDAgMVAgMDFgIBAh4BAheABQJQPlypBQlBo7MrAAoJEGpEY8BAECIzjOwAn3vp
	tb6K1v2wLI9eVlnCdx4m1btpAJ9sFt4KwJrEdiO5wFC4xe9G4eZl4rkBDQQ+XSBV
	EAQA3VYlpPyRKdOKoM6t1SwNG0YgVFSvxy/eiratBf7misDBsJeH86Pf8H9OfVHO
	cqscLiC+iqvDgqeTUX9vASjlnvcoS/3H5TDPlxiifIDggqd2euNtJ8+lyXRBV6yP
	sBIA6zki9cR4zphe48hKpSsDfj7uL5sfyc2UmKKboSu3x7cAAwUD/1jmoLQs9bIt
	bTosoy+5+Uzrl0ShRlv+iZV8RPzAMFuRJNxUJkUmmThowtXRaPKFI9AVd+pP44aA
	J+zxCPtS2isiW20AxubJoBPpXcVatJWi4sG+TM5Z5VRoLg7tIDNVWsyHGXPAhIG2
	Y8Z1kyWwb4P8A/W2b1ZCqS7Fx4yEhTikiEwEGBECAAwFAlA+XL8FCUGjs2IACgkQ
	akRjwEAQIjMsbQCgk59KFTbTlZfJ6FoZjjEmK3/xGR4AniYT+EdSdvEyRtZYkqWz
	p1ayvO1b
	=tibb
	-----END PGP PUBLIC KEY BLOCK-----
EOF
  echo "[*] Verifying CA package's PGP signature"
  if ! gpgv "${slackware_ca}.asc" "${slackware_ca}"
  then
    echo -e "[\033[1;31m-\033[0m] Could not verify CA package's PGP signature" 1>&2
    exit 1
  fi
  echo "[*] Extracting CAs"
  tar xvf "${slackware_ca}" usr/share/ca-certificates/mozilla
  ca_dir="./usr/share/ca-certificates"
  echo "[+] Using Slackware's CAs"
fi

while read -r
do
  if [ ! -f "${ca_dir}/${REPLY}" ]
  then
    echo -e "[\033[1;31m-\033[0m] CA \`${REPLY}' does not exist" 1>&2
    exit 1
  fi
  cat "${ca_dir}/${REPLY}"
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
  mta7.am0.yahoodns.net				\
  mail.cwo.com					\
  mail.protonmail.ch				\
  spool.mail.gandi.net				\
  fb.mail.gandi.net				\
  mx-tnl.mail.saunalahti.fi			\
  mx-stp.mail.saunalahti.fi			\
  outlook-com.olc.protection.outlook.com	\
  hotmail-com.olc.protection.outlook.com
do
  echo "[*] Testing SMTP STARTTLS for \`${host}'"
  openssl s_client -connect "${host}":25 -starttls smtp -verify_return_error -CAfile "${ca_file}" -showcerts 0</dev/null || exit 1
  echo -n $'\n'
done

rm -v "${ca_file}"
