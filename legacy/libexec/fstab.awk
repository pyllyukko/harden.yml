#!/usr/bin/gawk -f
# TODO: /tmp and maybe the /var/tmp binding from NSA 2.2.1.4
@load "filefuncs"
BEGIN{
  getline < "/etc/os-release"
  if($0 ~ /Raspbian GNU\/Linux/)
    os="raspbian"
  else if(stat("/etc/slackware-version", stbuf)==0)
    os="slackware"
  else if(stat("/etc/debian_version", stbuf)==0)
    os="debian"
  else if(stat("/etc/centos-release", stbuf)==0)
    os="centos"
  else
    os="unknown"
  bind_mount_found=0
  proc_mount_found=0
}
# partly from system-hardening-10.2.txt
# strict settings for filesystems mounted under /mnt
( \
  $3 ~ /^(ext[234]|reiserfs|vfat)$/ && \
  $4 !~ /(nodev|nosuid|noexec)/ && \
  ( $2 ~ /^\/m.*/ || $2 ~ /^\/boot/ ) \
){
  $4 = $4 ",nosuid,nodev,noexec"
}
# from system-hardening-10.2.txt
( $2 == "/var" && \
  $4 !~ /(nosuid|nodev)/ \
){
  $4 = $4 ",nosuid,nodev"
}
# from system-hardening-10.2.txt
( $2 == "/home" && \
  $4 !~ /(nosuid|nodev)/ \
){
  $4 = $4 ",nosuid,nodev"
}
# CIS 6.1 Add 'nodev' Option To Appropriate Partitions In /etc/fstab
# NOTE:
#   - added ext4
#   - this somewhat overlaps with the first rule but the $4 rule takes care of this
( \
  $3 ~ /^(ext[234]|reiserfs)$/ && \
  $2 != "/" && \
  $4 !~ /nodev/ \
){
  $4 = $4 ",nodev"
}
# CIS 6.2 Add 'nosuid' and 'nodev' Option For Removable Media In /etc/fstab
# NOTE: added noexec
# NOTE: the "[0-9]?" comes from Debian, where the mount point is /media/cdrom0
( \
  $2 ~ /^\/m.*\/(floppy|cdrom[0-9]?)$/ && \
  $4 !~ /(nosuid|nodev|noexec)/ \
){
  $4 = $4 ",nosuid,nodev,noexec"
}
# NSA RHEL guide - 2.2.1.3.2 Add nodev, nosuid, and noexec Options to /dev/shm
( \
  $2 ~ /^\/dev\/shm$/ && \
  $4 !~ /(nosuid|nodev|noexec)/ \
){
  $4 = $4 ",nosuid,nodev,noexec"
}
( \
  $1 == "/tmp" && \
  $2 == "/var/tmp" && \
  $4 == "bind" \
){
  bind_mount_found=1
}
( \
  $1 == "proc" && \
  $2 == "/proc" && \
  $3 == "proc" \
){
  if($4 !~ /hidepid/)
    $4 = $4 ",hidepid=2"
  proc_mount_found=1
}
$3 == "swap" {
  # FSTAB(5): "For swap partitions, this field should be specified as "none"."
  $2 = "none"
  # FILE-6336
  $4 = "sw"
}
{
  # formatting from /usr/lib/setup/SeTpartitions of slackware installer
  if($0 ~ /^#/)
    print
  else
    switch(os) {
      case "raspbian":
        # raspbian format
        printf "%-15s %-15s %-7s %-17s %-7s %s\n", $1, $2, $3, $4, $5, $6
        break
      case "debian":
        # debian format
        printf "%-15s %-15s %-7s %-15s %-7s %s\n", $1, $2, $3, $4, $5, $6
        break
      case "centos":
        printf "%-41s %-23s %-7s %-15s %s %s\n", $1, $2, $3, $4, $5, $6
        break
      case "slackware":
      default:
        # slackware format
        printf "%-16s %-16s %-11s %-16s %-3s %s\n", $1, $2, $3, $4, $5, $6
        break
    }
}END{
  if(!bind_mount_found)
    printf "/tmp /var/tmp none bind 0 0\n"
  if(!proc_mount_found&&os!="slackware")
    printf "proc /proc proc defaults,hidepid=2 0 0\n"
}
