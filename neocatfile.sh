#!/usr/bin/env bash

function PackCatFile {
 shopt -s globstar
 declare -A inodetofile
 declare -i curinode=0
 numfiles=$(find "${1}" -mindepth 1 -type f,l,c,b,d,p -print | wc -l)
 printf 'CatFile1\x00%s\x00' "${numfiles}" > "${2}"
 tmpfile=$(mktemp)
 
 for file in "${1}"/**; do
  [ -e "$file" ] || continue  # Skip if file doesn't exist
  fname="${file%/}"
  echo "${fname}"
  finfo=( $(stat -c "%i %f %X %Y %Z %T %t %u %g %U %G %h %s" "${fname}") )
  ftype=0; flinkname=""; fsize=0
  fcurinode=$curinode
  finode=${finfo[0]}
  fmode=${finfo[1]}
  fatime=$(printf "%x" ${finfo[2]})
  fmtime=$(printf "%x" ${finfo[3]})
  fctime=$(printf "%x" ${finfo[4]})
  fbtime=$(printf "%x" ${finfo[4]})  # Same as ctime in this script's context
  fdev_minor=$(printf "%x" ${finfo[5]})
  fdev_major=$(printf "%x" ${finfo[6]})
  fuid=$(printf "%x" ${finfo[7]})
  fgid=$(printf "%x" ${finfo[8]})
  funame=${finfo[9]}
  fgname=${finfo[10]}
  flinkcount=$(printf "%x" ${finfo[11]})
  fsizehex=$(printf "%x" ${finfo[12]})

  case $(stat -c %F "${fname}") in
    'regular file') ftype=0 ;;
    'symbolic link') ftype=2; flinkname=$(readlink -f "${fname}") ;;
    'character special file') ftype=3 ;;
    'block special file') ftype=4 ;;
    'directory') ftype=5 ;;
    'fifo') ftype=6 ;;
  esac

  if [ $ftype -eq 0 ] && [ -n "${inodetofile[$finode]}" ]; then
    ftype=1
    flinkname=${inodetofile[$finode]}
  else
    inodetofile[$finode]=$fname
    ((curinode++))
  fi
  
  ftypehex=$(printf "%x" $ftype)
  finodehex=$(printf "%x" $finode)
  printf "%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00" "$ftypehex" "$fname" "$flinkname" "$fsizehex" "$fatime" "$fmtime" "$fctime" "$fbtime" "$fmode" "$fuid" "$funame" "$fgid" "$fgname" "$fcurinode" "$finodehex" "$flinkcount" "$fdev_minor" "$fdev_major" "$fdev_minor" "$fdev_major" "0" > "$tmpfile"
  
  # Calculate checksums
  if [ "${4}" == "none" ]; then
    echo -n "none\x00" > "$tmpfile"  # Writing directly to temporary file
    catfileheadercshex="0"
    catfilecontentcshex="0"
  elif [ -z "${4}" ] || [ "${4}" == "crc32" ]; then
    catfileheadercshex=$(crc32 "$tmpfile" | cut -d ' ' -f 1)
    catfilecontentcshex=$(if [ -f "$fname" ]; then crc32 "$fname"; else crc32 /dev/null; fi | cut -d ' ' -f 1)
  else
    checksum_command="${4}sum"
    catfileheadercshex=$($checksum_command "$tmpfile" | cut -d ' ' -f 1)
    catfilecontentcshex=$(if [ -f "$fname" ]; then $checksum_command "$fname"; else $checksum_command /dev/null; fi | cut -d ' ' -f 1)
  fi
  
  cat "$tmpfile" >> "${2}"
  printf "%s\x00%s\x00" "$catfileheadercshex" "$catfilecontentcshex" >> "${2}"
  [ -f "$fname" ] && cat "$fname" >> "${2}"
  printf '\x00' >> "${2}"
 done

 rm -f "$tmpfile"

 case "${3}" in
   gzip) gzip --quiet --best "${2}" ;;
   bzip2) bzip2 --compress --quiet --best "${2}" ;;
   zstd) zstd -19 --rm -qq --format=zstd "${2}" ;;
   lz4) lz4 -9 -z --rm -qq "${2}" ;;
   lzo) lzop -9 -U -q "${2}" ;;
   lzma) lzma --compress --quiet -9 --extreme "${2}" ;;
   xz) xz --compress --quiet -9 --extreme "${2}" ;;
   brotli) brotli --rm --best "${2}" ;;
   *) echo "Unsupported compression method: ${3}" >&2 ;;
 esac
}

PackCatFile "${1}" "${2}" "${3}" "${4}"
