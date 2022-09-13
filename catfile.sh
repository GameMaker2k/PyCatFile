#!/usr/bin/env bash

function PackCatFile {
 shopt -s globstar
 curinode=0
 echo -n -e 'CatFile1\x00' > ${2}
 for file in ${1}/**; do
  fname="${file%/}"
  echo "${fname}"
  flinkname=""
  fcurinode=${curinode}
  finode=$(stat -c %i ${fname})
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
  if [ -f ${fname} ]; then
   if [[ ${inodetofile[${finode}]} ]]; then
    ftype=1
    flinkname=${inodetofile[${finode}]}
   else
    inodetofile[${finode}]=${fname}
    curinode=$[curinode + 1]
   fi
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
  finodehex=$(printf "%x" ${finode})
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
  echo -n "${finodehex}" >> ${tmpfile}
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
  if [ "${4}" == "none" ]; then
   echo -n "${4}" >> ${tmpfile}
   echo -n -e '\x00' >> ${tmpfile}
   catfileheadercshex="0"
   catfilecontentcshex="0"
  elif [ "${4}" == "crc32" ] || [ "${4}" == "" ]; then
   echo -n "" >> ${tmpfile}
   echo -n -e '\x00' >> ${tmpfile}
   catfileheadercshex=$(crc32 ${tmpfile} | cut -d ' ' -f 1)
   if [ -f ${fname} ]; then
    catfilecontentcshex=$(crc32 ${fname} | cut -d ' ' -f 1)
   else
    catfilecontentcshex=$(crc32 /dev/null | cut -d ' ' -f 1)
   fi
  elif [ "${4}" == "md5" ]; then
   echo -n "md5" >> ${tmpfile}
   echo -n -e '\x00' >> ${tmpfile}
   catfileheadercshex=$(md5sum ${tmpfile} | cut -d ' ' -f 1)
   if [ -f ${fname} ]; then
    catfilecontentcshex=$(md5sum ${fname} | cut -d ' ' -f 1)
   else
    catfilecontentcshex=$(md5sum /dev/null | cut -d ' ' -f 1)
   fi
  elif [ "${4}" == "sha1" ]; then
   echo -n "${4}" >> ${tmpfile}
   echo -n -e '\x00' >> ${tmpfile}
   catfileheadercshex=$(sha1sum ${tmpfile} | cut -d ' ' -f 1)
   if [ -f ${fname} ]; then
    catfilecontentcshex=$(sha1sum ${fname} | cut -d ' ' -f 1)
   else
    catfilecontentcshex=$(sha1sum /dev/null | cut -d ' ' -f 1)
   fi
  elif [ "${4}" == "sha224" ]; then
   echo -n "${4}" >> ${tmpfile}
   echo -n -e '\x00' >> ${tmpfile}
   catfileheadercshex=$(sha224sum ${tmpfile} | cut -d ' ' -f 1)
   if [ -f ${fname} ]; then
    catfilecontentcshex=$(sha224sum ${fname} | cut -d ' ' -f 1)
   else
    catfilecontentcshex=$(sha224sum /dev/null | cut -d ' ' -f 1)
   fi
  elif [ "${4}" == "sha256" ]; then
   echo -n "${4}" >> ${tmpfile}
   echo -n -e '\x00' >> ${tmpfile}
   catfileheadercshex=$(sha256sum ${tmpfile} | cut -d ' ' -f 1)
   if [ -f ${fname} ]; then
    catfilecontentcshex=$(sha256sum ${fname} | cut -d ' ' -f 1)
   else
    catfilecontentcshex=$(sha256sum /dev/null | cut -d ' ' -f 1)
   fi
  elif [ "${4}" == "sha384" ]; then
   echo -n "${4}" >> ${tmpfile}
   echo -n -e '\x00' >> ${tmpfile}
   catfileheadercshex=$(sha384sum ${tmpfile} | cut -d ' ' -f 1)
   if [ -f ${fname} ]; then
    catfilecontentcshex=$(sha384sum ${fname} | cut -d ' ' -f 1)
   else
    catfilecontentcshex=$(sha384sum /dev/null | cut -d ' ' -f 1)
   fi
  elif [ "${4}" == "sha512" ]; then
   echo -n "${4}" >> ${tmpfile}
   echo -n -e '\x00' >> ${tmpfile}
   catfileheadercshex=$(sha512sum ${tmpfile} | cut -d ' ' -f 1)
   if [ -f ${fname} ]; then
    catfilecontentcshex=$(sha512sum ${fname} | cut -d ' ' -f 1)
   else
    catfilecontentcshex=$(sha512sum /dev/null | cut -d ' ' -f 1)
   fi
  else
   echo -n "crc32" >> ${tmpfile}
   echo -n -e '\x00' >> ${tmpfile}
   catfileheadercshex=$(crc32 ${tmpfile} | cut -d ' ' -f 1)
   if [ -f ${fname} ]; then
    catfilecontentcshex=$(crc32 ${fname} | cut -d ' ' -f 1)
   else
    catfilecontentcshex=$(crc32 /dev/null | cut -d ' ' -f 1)
   fi
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
 done
 if [ "${3}" == "gzip" ]; then
  gzip --quiet --best ${2}
 elif [ "${3}" == "bzip2" ]; then
  gzip --compress --quiet --best ${2}
 elif [ "${3}" == "zstd" ]; then
  zstd -19 --rm -qq --format=zstd ${2}
 elif [ "${3}" == "lz4" ]; then
  lz4 -9 -z --rm -qq ${2}
 elif [ "${3}" == "lzo" ]; then
  lzop -9 -U -q ${2}
 elif [ "${3}" == "lzma" ]; then
  lzma --compress --quiet -9 --extreme ${2}
 elif [ "${3}" == "xz" ]; then
  xz --compress --quiet -9 --extreme ${2}
 elif [ "${3}" == "brotli" ]; then
  brotli --rm --best ${2}
 fi
}

PackCatFile "${1}" "${2}" "${3}" "${4}"
