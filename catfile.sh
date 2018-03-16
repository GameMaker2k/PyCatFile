function PackCatFile {
 shopt -s globstar
 curinode=0
 echo -n -e 'CatFile1\x00' > ${2}
 for file in ${1}/**; do
  fname="${file%/}"
  echo "${fname}"
  flinkname=""
  fcurinode=${curinode}
  ftype=0
  if [ -f ${fname} ]; then
   ftype=0
   fsize=$(printf "%x" $(stat -c %s ${fname}))
  fi
  if [ -L ${fname} ]; then
   ftype=2
   fsize=0
   flinkname="$(readlink -f ${fname})"
  fi
  if [ -c ${fname} ]; then
   ftype=3
   fsize=0
  fi
  if [ -b ${fname} ]; then
   ftype=4
   fsize=0
  fi
  if [ -d ${fname} ]; then
   ftype=5
   fsize=0
  fi
  if [ -p ${fname} ]; then
   ftype=6
   fsize=0
  fi
  fdev_minor=$(printf "%x" $(stat -c %T ${fname}))
  fdev_major=$(printf "%x" $(stat -c %t ${fname}))
  fatime=$(printf "%x" $(stat -c %X ${fname}))
  fmtime=$(printf "%x" $(stat -c %Y ${fname}))
  fctime=$(printf "%x" $(stat -c %Z ${fname}))
  fmode=$(stat -c %f ${fname})
  fchmode=$(printf "%x" 0$(stat -c %a ${fname}))
  fuid=$(printf "%x" $(stat -c %u ${fname}))
  fgid=$(printf "%x" $(stat -c %g ${fname}))
  funame=$(stat -c %U ${fname})
  fgname=$(stat -c %G ${fname})
  flinkcount=$(printf "%x" $(stat -c %h ${fname}))
  ftypehex=$(printf "%x" ${ftype})
  tmpfile=$(mktemp);
  echo -n "${ftypehex}" > ${tmpfile}
  echo -n -e '\x00' >> ${tmpfile}
  echo -n "${fname}" >> ${tmpfile}
  echo -n -e '\x00' >> ${tmpfile}
  echo -n "${flinkname}" >> ${tmpfile}
  echo -n -e '\x00' >> ${tmpfile}
  echo -n "${fsize}" >> ${tmpfile}
  echo -n -e '\x00' >> ${tmpfile}
  echo -n "${fatime}" >> ${tmpfile}
  echo -n -e '\x00' >> ${tmpfile}
  echo -n "${fmtime}" >> ${tmpfile}
  echo -n -e '\x00' >> ${tmpfile}
  echo -n "${fctime}" >> ${tmpfile}
  echo -n -e '\x00' >> ${tmpfile}
  echo -n "${fmode}" >> ${tmpfile}
  echo -n -e '\x00' >> ${tmpfile}
  echo -n "${fchmode}" >> ${tmpfile}
  echo -n -e '\x00' >> ${tmpfile}
  echo -n "${fuid}" >> ${tmpfile}
  echo -n -e '\x00' >> ${tmpfile}
  echo -n "${funame}" >> ${tmpfile}
  echo -n -e '\x00' >> ${tmpfile}
  echo -n "${fgid}" >> ${tmpfile}
  echo -n -e '\x00' >> ${tmpfile}
  echo -n "${fgname}" >> ${tmpfile}
  echo -n -e '\x00' >> ${tmpfile}
  echo -n "${fcurinode}" >> ${tmpfile}
  echo -n -e '\x00' >> ${tmpfile}
  echo -n "${flinkcount}" >> ${tmpfile}
  echo -n -e '\x00' >> ${tmpfile}
  echo -n "${fdev_minor}" >> ${tmpfile}
  echo -n -e '\x00' >> ${tmpfile}
  echo -n "${fdev_major}" >> ${tmpfile}
  echo -n -e '\x00' >> ${tmpfile}
  echo -n "${fdev_minor}" >> ${tmpfile}
  echo -n -e '\x00' >> ${tmpfile}
  echo -n "${fdev_major}" >> ${tmpfile}
  echo -n -e '\x00' >> ${tmpfile}
  echo -n "crc32" >> ${tmpfile}
  echo -n -e '\x00' >> ${tmpfile}
  catfileheadercshex=$(crc32 ${tmpfile})
  if [ -f ${fname} ]; then
   catfilecontentcshex=$(crc32 ${fname})
  else
   catfilecontentcshex=$(crc32 /dev/null)
  fi
  cat ${tmpfile} >> ${2}
  rm -rf ${tmpfile}
  echo -n "${catfileheadercshex}" >> ${2}
  echo -n -e '\x00' >> ${2}
  echo -n "${catfilecontentcshex}" >> ${2}
  echo -n -e '\x00' >> ${2}
  if [ -f ${fname} ]; then
   cat ${fname} >> ${2}
  fi
  echo -n -e '\x00' >> ${2}
  curinode=$[curinode + 1]
 done
}

PackCatFile "${1}" "${2}"
