#!/bin/bash
################################################################################
# file:         awk_sandboxing.sh
# created:      16-10-2011
################################################################################
AWK_VERSION=`awk 'BEGIN{split(PROCINFO["version"],versinfo,".");print versinfo[1]}'`
if mawk --version 2>/dev/null | grep -q '^GNU Awk' && [ -n "${AWK_VERSION}" ] && [ ${AWK_VERSION} -ge 4 ]
then
  alias awk='/bin/gawk --sandbox'
fi
unset AWK_VERSION
