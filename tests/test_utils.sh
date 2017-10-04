#!/bin/bash
function check_patch() {
  sed -i 1,2d "${1}"
  sha512sum -c 0<<<"${2}  ${1}"
  test_results+=(${?})
} # check_patch()
function extract_files() {
  rm -fr    "${CWD}/debian"
  mkdir -pv "${CWD}/debian"
  pushd     "${CWD}/debian" || exit 1
  for file in ${!files[*]}
  do
    url="${files[${file}]}"
    filename="${url##*/}"
    if [ ! -f "./${filename}" ]
    then
      wget -nv "${url}"
    fi
    rm -v data.tar.?z
    ar vx "${filename}"
    tar xvf data.tar.?z ".${file}"
  done
}
