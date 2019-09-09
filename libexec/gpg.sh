#!/bin/bash
declare GPG_KEYRING="trustedkeys.gpg"
# more info about these PGP keys:
#   - https://tails.boum.org/download/index.en.html#verify
#   - TODO: http://www.snort.org/snort-downloads#pgp
#   - https://www.kali.org/downloads/
#   - https://wiki.qubes-os.org/wiki/VerifyingSignatures
declare -ra PGP_URLS=(
  "https://tails.boum.org/tails-signing.key"
  "https://sourceforge.net/projects/apcupsd/files/apcupsd%20Public%20Key/Current%20Public%20Key/apcupsd.pub/download"
  "https://www.kali.org/archive-key.asc"
  "https://keys.qubes-os.org/keys/qubes-release-2-signing-key.asc"
  "https://keybase.io/docs/server_security/code_signing_key.asc"
)
declare -ra PGP_KEYS=(
  # slackware http://www.slackbuilds.org/faq/#asc
  "0x6A4463C040102233"
  # http://slackbuilds.org/GPG-KEY
  "0x0368EF579C7BA3B6"
  # metasploit (18.6.2013)
  "0xCDFB5FA52007B954"
  # Roger from torproject
  "0xEB5A896A28988BF5"
  # https://www.torproject.org/docs/verifying-signatures.html.en
  "0xC218525819F78451"
  # http://www.openwall.com/signatures/ (295029F1)
  "0x72B97DB1295029F1"
  # http://www.wangafu.net/~nickm/ 8D29319A - Nick Mathewson (libevent)
  "0x21194EBB165733EA"
  # Breno Silva (ModSecurity)
  # TODO: remove?
  "0x8050C35A6980F8B0"
  # Felipe "Zimmerle" Costa (ModSecurity)
  "0xE6DFB08CE8B11277"
  # Victor Ribeiro Hora (ModSecurity)
  "0x10D549BE676FDF165CC0A017E4BCD2EA82E67A45"
  # Karl Berry <karl@freefriends.org> (gawk)
  "0x9DEB46C0D679F6CF"
  # Fabian Keil, lead developer of privoxy
  "0x48C5521FBF2EA563"
  # Nick Mathewson <nickm@torproject.org>
  "0x6AFEE6D49E92B601"
  # Tor Browser Developers (signing key) <torbrowser@torproject.org>
  "0x4E2C6E8793298290"
  # Erinn Clark (Tor Browser Bundles) https://www.torproject.org/docs/signing-keys.html.en
  # TODO: remove?
  "0x416F061063FEE659"
  # http://www.debian.org/CD/verify
  "0xDA87E80D6294BE9B"
  # Ryan Barnett (OWASP Core Rule Set Project Leader) <rbarnett@trustwave.com>
  # https://www.owasp.org/index.php/Category:OWASP_ModSecurity_Core_Rule_Set_Project#Download
  "0xC976607D9624FCD2"
  # https://www.kernel.org/signature.html
  "0x38DBBDC86092693E"
  # Linus Torvalds
  "0x79BE3E4300411886"
  # https://www.torproject.org/torbutton/
  "0x1B0CA30CDDC6C0AD"
  # Nico Golde (Debian Advisories)
  "0x1D87E54973647CFF"
  # Damien Miller (Personal Key) <djm@mindrot.org> (OpenSSH)
  "0xCE8ECB0386FF9C48"
  # Damien Miller <djm@mindrot.org> (OpenSSH)
  "0xD3E5F56B6D920D30"
  # Werner Koch <wk@gnupg.org> (gnupg-announce@gnupg.org)
  "0x4F0540D577F95F95"
  # Werner Koch (dist sig) (GnuPG)
  "0x249B39D24F25E3B6"
  # NIIBE Yutaka (GnuPG Release Key)
  "0x2071B08A33BD3F06"
  # Debian security advisory
  "0x1BF83C5E54FC8640"
  # Renaud Deraison (Nessus)
  "0xF091044D14595A1A"
  # Mozilla Software Releases <releases@mozilla.org>
  # TODO: remove? (revoked)
  "0x057CC3EB15A0A4BC"
  # Mozilla Software Releases <releases@mozilla.org> (2015-07-17)
  # TODO: check
  "5E9905DB"
  # https://support.mayfirst.org/wiki/faq/security/mfpl-certificate-authority Jamie McClelland <jamie@mayfirst.org>
  "0xBB0B7EE15F2E4935"
  # https://support.mayfirst.org/wiki/faq/security/mfpl-certificate-authority dkg
  "0xCCD2ED94D21739E9"
  # https://www.sks-keyservers.net/overview-of-pools.php
  "0x0B7F8B60E3EDFAE3"
  # https://web.monkeysphere.info/archive-key/
  "0x2E8DD26C53F1197DDF403E6118E667F1EB8AF314"
  # http://www.truecrypt.org/docs/digital-signatures
  # TODO: remove?
  "0xE3BA73CAF0D6B1E0"
  # OpenSSL
  "0xA2D29B7BF295C759"
  # steve@openssl.org
  "0xD3577507FA40E9E2"
  # matt@openssl.org
  "0xD9C4D26D0E604491"
  # key that can be used to verify SPI's CA cert - http://www.spi-inc.org/ca/
  "0x715ED6A07E7B8AC9"
  # OTR Dev Team <otr@cypherpunks.ca>
  "0xDED64EBB2BA87C5C"
  # https://ssl.intevation.de/ - used to sign Gpg4win
  "0x7CBD620BEC70B1B8"
  # https://bitbucket.org/skskeyserver/sks-keyserver/src/tip/README.md
  "0x41259773973A612A"
  # Sourcefire VRT GPG Key (at least ClamAV)
  "0x40B8EA2364221D53"
  # Chet Ramey / GNU / Bash
  "0xBB5869F064EA74AB"
  # https://www.apple.com/support/security/pgp/
  # TODO: remove? (expired)
  "0x17167CB4EE3A8EED"
  # Apple Product Security
  "0x83A3EF8C346CB446"
  # http://software.opensuse.org/132/en
  "0xB88B2FD43DBDC284"
  # https://www.centos.org/keys/#centos-7-signing-key
  "0x24C6A8A7F4A80EB5"
  # RVM https://rvm.io/rvm/security
  "0x409B6B1796C275462A1703113804BB82D39DC0E3"
  # The Irssi project <staff@irssi.org>
  "0x00CCB587DDBEF0E1"
  # LEAP (https://bitmask.net/en/install/signature-verification)
  "0x1E453B2CE87BEE2F7DFE99661E34A1828E207901"
  # Samuli Seppänen <samuli@openvpn.net> https://openvpn.net/index.php/open-source/documentation/sig.html
  "0xC29D97ED198D22A3"
  # OpenVPN - Security Mailing List <security@openvpn.net> (OpenVPN 2.4.3+)
  "0x12F5F7B42F2B01E7"
  # Mixmaster 3.x Code Release Signing Key
  "0x1AF51CE72993D5F9"
  # sukhbir@torproject.org (Tor messenger)
  "0x6887935AB297B391"
  # Kevin McCarthy's key (Mutt) http://mutt.org/kevin.key
  "0xADEF768480316BDA"
  # Ubuntu https://help.ubuntu.com/community/VerifyIsoHowto
  "0xD94AA3F0EFE21092"
  # Ubuntu
  "0x46181433FBB75451"
  # DNSSEC Manager <dnssec@iana.org>
  "0xD1AFBCE00F6C91D2"
  # OpenWrt signing key
  "0xBEA8F6E25378AAF8"
  # Hannes von Haugwitz's key (Aide)
  "0xF6947DAB68E7B931"
  # PuTTY Releases
  "0x9DFE2648B43434E4"
  "0xE27394ACA3F9D9049522E0546289A25F4AE8DA82"
  # Hashcat signing key
  "0x3C17DA8B8A16544F"
  # Milan Broz <gmazyland@gmail.com> (cryptsetup)
  "0xD9B0577BD93E98FC"
  # julien.voisin @ dustri.org (https://mat.boum.org/)
  "0x04D041E8171901CC"
  # Immunity Debugger (Immunity Inc.)
  "0xABCA792D54BF70F2"
  # Felix Geyer (KeePassX)
  "0x164C70512F7929476764AB56FE22C6FD83135D45"
  # Max Kellermann (Music Player Daemon)
  "0x0392335A78083894A4301C43236E8A58C6DB4512"
  # CISOfy (Software Signing Key) https://cisofy.com/documentation/lynis/#no-installation
  "0x429A566FD5B79251"
  # nmap https://nmap.org/book/install.html#inst-integrity
  "0x01AF9F036B9355D0"
  # jfs (Tiger's author) http://www.nongnu.org/tiger/key.html & http://savannah.nongnu.org/users/jfs
  "0xB1A9DD82DC814B09"
  # Michael Kershaw (Dragorn) (Kismet's author)
  "0x0AFFEC2F816F0300"
  # Wladimir J. van der Laan (Bitcoin Core binary release signing key)
  "0x90C8019E36C2E964"
  # Arm's author https://www.atagar.com/pgp.php
  "0x0445B7AB9ABBEEC6"
  # Michael Rash (Signing key for cipherdyne.org projects)
  "0x4D6644A9DA036904BDA2CB90E6C9E3350D3E7410"
  # https://developers.yubico.com/Software_Projects/Software_Signing.html
  "0x0a3b0262bca1705307d5ff06bca00fd4b2168c0a"
  "0x59944611C823D88CEB7245B906FC004369E7D338"
  # Stefan Seelmann (CODE SIGNING KEY) <seelmann@apache.org> (for Apache Directory Studio)
  "0x63CE676698B26D3A36D77527223BD93328686142"
  # Openwall offline signing key
  "0x05C027FD4BDC136E"
  # LEDE Release Builder (17.01 "Reboot" Signing Key)
  "0x833C6010D52BBB6B"
  # LEDE Build System (LEDE GnuPG key for unattended build jobs)
  "0xCD84BCED626471F1"
  # GNU IceCat releases <gnuzilla-dev@gnu.org>
  "0x3C76EED7D7E04784"
  # Nick Clifton (Chief Binutils Maintainer)
  "0x13FCEF89DD9E3C4F"
  # apparmor@lists.ubuntu.com
  "0x6689E64E3D3664BB"
  # research@sourcefire.com (ClamAV)
  "0xF13F9E16BCA5BFAD"
  # OpenWrt Release Builder (18.06 Signing Key)
  "0x0F20257417E1CE16"
  # https://www.php.net/downloads.php#gpg-7.2
  "0xDC9FF8D3EE5AF27F"
  # Bintray (by JFrog) <bintray@bintray.com> (boost library)
  "0x379CE192D401AB61"
  # Marcus Müller (GNU Radio)
  "0xD34D1A1F4A44088DEB70085EA06C6D95DFC71475"
)
function import_pgp_keys() {
  local URL
  local PGP_KEY
  local SKS_HASH
  local schema

  print_topic "importing PGP keys"
  # keys with URL
  echo -n "from URLs (${#PGP_URLS[*]} keys)"
  for URL in ${PGP_URLS[*]}
  do
    schema="${URL%%:*}"
    if [ "${schema}" != "https" ]
    then
      echo "[-] WARNING: refusing to download PGP key as schema!=https" 1>&2
      continue
    fi
    # after importing these keys, we can verify slackware packages with gpgv
    /usr/bin/wget --append-output="${logdir}/wget-log.txt" --tries=5 "${URL}" -nv --output-document=- | gpg --logger-fd 1 --keyring "${GPG_KEYRING}" --no-default-keyring --import - &>>"${logdir}/pgp_keys.txt"
    echo -n '.'
  done
  echo -n $'\n'

  # if GnuPG is new enough, it uses dirmngr and all the SKS CA stuff is unnecessary.
  if gpg --version | head -1 | grep -q '^gpg (GnuPG) 2\.[^0]'
  then
    # keys with key ID
    if [ ! -x /usr/bin/dirmngr ]
    then
      echo '[-] error: dirmngr not found!' 1>&2
      return 1
    fi
    echo -n "from keyserver (${#PGP_KEYS[*]} keys)"
    for PGP_KEY in ${PGP_KEYS[*]}
    do
      /usr/bin/gpg \
        --logger-fd 1 \
        --keyring "${GPG_KEYRING}" --no-default-keyring \
        --recv-keys "${PGP_KEY}" &>>"${logdir}/pgp_keys.txt"
      if [ ${?} -eq 0 ]
      then
	echo -n '.'
      else
	echo -n '!'
      fi
    done
    echo -n $'\n'
  else
    # some CAs that are used with HKPS
    #
    # https://en.wikipedia.org/wiki/Key_server_%28cryptographic%29#Keyserver_examples
    # https://we.riseup.net/riseuplabs+paow/openpgp-best-practices#consider-making-your-default-keyserver-use-a-keyse
    if [ "${USER}" = "root" ] && [ ! -d /usr/share/ca-certificates/local ]
    then
      # NOTE: update-ca-certificates will add /usr/local/share/ca-certificates/*.crt to globally trusted CAs... which of course, is not good!
      #mkdir -pvm 755 /usr/local/share/ca-certificates
      mkdir -pvm 755 /usr/share/ca-certificates/local
    fi
    if [ "${USER}" = "root" ] && [ ! -f "${CADIR}/${SKS_CA}" ]
    then
      # https://www.sks-keyservers.net/verify_tls.php
      echo "[+] dropping SKS certificate to ${CADIR}"
      cat "${CWD}/certificates/${SKS_CA}" 1>"${CADIR}/${SKS_CA}"
      chmod -c 644 "${CADIR}/${SKS_CA}" | tee -a "${logdir}/file_perms.txt"
    # for regular users
    elif [ "${USER}" != "root" ] && [ ! -f "${CADIR}/${SKS_CA}" ]
    then
      echo "[-] error: sks-keyservers CA not available. can not continue! try to run this as root to install the CA." 1>&2
      return 1
    fi
    # get the CRL
    SKS_HASH=$( openssl x509 -in ${CADIR}/${SKS_CA} -noout -hash )
    if [ -n "${SKS_HASH}" ] && [ "${USER}" = "root" ]
    then
      echo "[+] fetching SKS CRL to ${CADIR}/${SKS_HASH}.r0"
      wget --append-output="${logdir}/wget-log.txt" -nv --ca-certificate=/usr/share/ca-certificates/mozilla/Thawte_Premium_Server_CA.crt https://sks-keyservers.net/ca/crl.pem -O "${CADIR}/${SKS_HASH}.r0"
      chmod -c 644 "${CADIR}/${SKS_HASH}.r0" | tee -a "${logdir}/file_perms.txt"
    fi
    echo "[+] verifying SKS CA"
    sha512sum -c 0<<<"d0a056251372367230782e050612834a2efa2fdd80eeba08e490a770691e4ddd52a744fd3f3882ca4188f625c3554633381ac90de8ea142519166277cadaf7b0  ${CADIR}/${SKS_CA}" 1>/dev/null
    if [ ${?} -ne 0 ]
    then
      echo "[-] error: sks-keyservers CA's SHA-512 fingerprint does not match!" 1>&2
      return 1
    fi
    # if the distro is Debian, check if gnupg-curl is installed
    if [ "${DISTRO}" = "debian" -o "${DISTRO}" = "raspbian" ]
    then
      /usr/bin/dpkg -s gnupg-curl &>/dev/null || echo "[-] WARNING: package \`gnupg-curl' not installed!" 1>&2
    fi
    # keys with key ID
    echo -n "from keyserver (${#PGP_KEYS[*]} keys)"
    for PGP_KEY in ${PGP_KEYS[*]}
    do
      /usr/bin/gpg \
        --logger-fd 1 \
        --keyserver "hkps://hkps.pool.sks-keyservers.net" \
        --keyserver-options ca-cert-file=${CADIR}/${SKS_CA} \
        --keyring "${GPG_KEYRING}" --no-default-keyring \
        --recv-keys "${PGP_KEY}" &>>"${logdir}/pgp_keys.txt"
      if [ ${?} -eq 0 ]
      then
	echo -n '.'
      else
	echo -n '!'
      fi
    done
    echo -n $'\n'
  fi
  return 0
} # import_pgp_keys()
