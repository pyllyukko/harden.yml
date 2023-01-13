#!/bin/bash
declare -r SLACKWARE_VERSION=$( sed 's/^.*[[:space:]]\([0-9]\+\.[0-9]\+\).*$/\1/' /etc/slackware-version 2>/dev/null )
declare -r ETC_PATCH_FILE="harden_etc-${SLACKWARE_VERSION}.patch"
auditPATH='/etc/audit'
declare -r ARCH=$( /bin/uname -m )
case "${MACHTYPE%%-*}" in
  "x86_64")	SLACKWARE="slackware64"	;;
  i?86)		SLACKWARE="slackware"	;;
  # TODO: arm
esac
if [ -n "${SLACKWARE_VERSION}" ]
then
  MANIFEST_DIR="${CWD}/../manifests/${SLACKWARE}-${SLACKWARE_VERSION}"
fi

# PATCHES
#declare -r APACHE_PATCH_VERSION="2.4.3-20120929-1"
declare -r APACHE_PATCH_FILE="apache_harden.patch"
declare -r SENDMAIL_PATCH_FILE="sendmail_harden.patch"
# OpenSSH configs differ between versions, so we need to have quite version
# specific patches, it also isn't Slackware version dependent, so we need to
# try to detect it.
SSH_VERSION=$( ssh -V 2>&1 | sed 's/^OpenSSH_\([^,]\+\),.*$/\1/' )
case "${SSH_VERSION}" in
  "6.3p1")	SSH_PATCH_FILE="ssh_harden-6.3p1.patch" ;;
  "6.7p1")	SSH_PATCH_FILE="ssh_harden-6.7p1.patch" ;;
  "7.1p1")	SSH_PATCH_FILE="ssh_harden-7.1p1.patch" ;;
  *)		SSH_PATCH_FILE="ssh_harden-6.3p1.patch" ;;
esac
# /PATCHES
################################################################################
function check_integrity() {
  local    manifest="${MANIFEST_DIR}/MANIFEST.bz2"
  local -i I=0
  local    FULL_PERM
  local    OWNER_GROUP
  local    SIZE
  local    PATH_NAME
  local -a STAT=()
  local    local_FULL_PERM
  local    local_OWNER_GROUP
  local    local_size

  make -f ${CWD}/../Makefile slackware="${SLACKWARE}" slackware_version="${SLACKWARE_VERSION}" "${manifest}" || return 1

  pushd /

  # partly copied from http://www.slackware.com/%7Ealien/tools/restore_fileperms_from_manifest.sh
  while read line
  do
    if [[ ${line} =~ ^.(.{9})\ ([a-z]+/[a-z]+)\ +([0-9]+)\ [0-9]{4}-[0-9]{2}-[0-9]{2}\ [0-9]{2}:[0-9]{2}\ (.+)$ ]]
    then
      FULL_PERM="${BASH_REMATCH[1]}"
      OWNER_GROUP="${BASH_REMATCH[2]//\//:}"
      SIZE="${BASH_REMATCH[3]}"
      PATH_NAME="${BASH_REMATCH[4]}"
    fi

    if [ ! -e "${PATH_NAME}" ]
    then
      continue
    # if it's a link -> skip
    elif [ -h "${PATH_NAME}" ]
    then
      continue
    fi

    STAT=( $( stat -c"%A %U:%G %s" "${PATH_NAME}" ) )
    local_FULL_PERM="${STAT[0]:1:9}"
    local_OWNER_GROUP="${STAT[1]}"
    local_size="${STAT[2]}"

    if [ -z "${local_OWNER_GROUP}" -o -z "${local_FULL_PERM}" ]
    then
      continue
    fi

    if [ \
      "${FULL_PERM}"	!= "${local_FULL_PERM}" -o \
      "${OWNER_GROUP}"	!= "${local_OWNER_GROUP}" ]
    then
      echo "Path: ${PATH_NAME}"
      if [ "${FULL_PERM}" != "${local_FULL_PERM}" ]
      then
        printf " %-9s: %-33s, %s\n" "Perm" "${FULL_PERM}" "${local_FULL_PERM}"
      fi
      if [ "${OWNER_GROUP}" != "${local_OWNER_GROUP}" ]
      then
        printf " %-9s: %-33s, %s\n" "Owner" "${OWNER_GROUP}" "${local_OWNER_GROUP}"
      fi
      # the file sizes change during updates, so this is commented out for now...
      #if [ ${local_size} -ne 0 -a ${SIZE} -ne ${local_size} ]
      #then
      #  printf " %-9s: %-33s, %s\n" "Size" ${SIZE} ${local_size}
      #fi
      echo -n $'\n'
    fi
    ((I++))
  done 0< <(bzgrep -E "^[d-]" "${manifest}" | sort | uniq)
  echo "${I} paths checked"

  popd
} # check_integrity()
