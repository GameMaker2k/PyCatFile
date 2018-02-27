<?php
/*
    This program is free software; you can redistribute it and/or modify
    it under the terms of the Revised BSD License.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Revised BSD License for more details.
    Copyright 2018 Cool Dude 2k - http://idb.berlios.de/
    Copyright 2018 Game Maker 2k - http://intdb.sourceforge.net/
    Copyright 2018 Kazuki Przyborowski - https://github.com/KazukiPrzyborowski
    $FileInfo: phpcatfile.php - Last Update: 2/26/2018 Ver. 0.0.1 RC 1 - Author: cooldude2k $
*/

function ListDir($dirname) {
 if($handle = opendir($dirname)) {
  while (false !== ($file = readdir($handle))) {
   if($dirnum==null) {
    $dirnum = 0; }
   if($file != "." && $file != ".." && $file != ".htaccess" && $file != null) {
    if(filetype($dirname.$file)=="file") {
     $srcfile[$dirnum] = $file; }
    if(filetype($dirname.$file)=="dir") {
     $srcdir[$dirnum] = $file; }
    ++$dirnum; } }
  if($srcdir!=null) {
   asort($srcdir); }
  if($srcfile!=null) {
   asort($srcfile); }
  if($srcdir!=null&&$srcfile!=null) {
   $fulllist = array_merge($srcdir, $srcfile); }
  if($srcdir!=null&&$srcfile==null) {
   $fulllist = $srcdir; }
  if($srcdir==null&&$srcfile!=null) {
   $fulllist = $srcfile; }
  closedir($handle); }
 return $fulllist; }

function ReadTillNullByte($fp) {
 $curbyte = "";
 $curfullbyte = "";
 $nullbyte = "\0";
 while($curbyte!=$nullbyte) {
  $curbyte = fread($fp, 1);
  if($curbyte!=$nullbyte) {
   $curbyted = $curbyte;
   $curfullbyte = $curfullbyte.$curbyted; } }
 return $curfullbyte; }

function ReadUntilNullByte($fp) {
 return ReadTillNullByte($fp); }

function PHPCatFile($infiles, $outfile, $verbose=false) {
 if(file_exists($outfile)) {
  unlink($outfile); }
 $catfp = fopen($outfile, "wb");
 $fileheaderver = "00";
 $fileheader = "CatFile".$fileheaderver."\0";
 fwrite($fileheader);
 fclose($catfp);
 $GetDirList = ListDir($infiles);
 foreach ($curfid as $curfname => $GetDirList) {
  $fname = $curfname;
  if($verbose===true):
   print($fname);
  $fstatinfo = lstat($fname);
  $ftype = 0;
  if(is_dir($fname)) {
   $ftype = 0; }
  if(is_file($fname)) {
   $ftype = 1; }
  if(is_link($fname)) {
   $ftype = 2; }
  if($ftype==0 || $ftype==2 || $ftype==3) {
   $fsize = strtoupper(dechex(intval("0"))); }
  if(ftype==1) {
   $fsize = strtoupper(dechex(intval(fstatinfo.st_size))); }
  $flinkname = "";
  if($ftype==2 or $ftype==3) {
   $flinkname = os.readlink(fname); }
  $flinknameintsize = strlen($flinkname);
  $fatime = strtoupper(dechex(intval($fstatinfo['atime'])));
  $fmtime = strtoupper(dechex(intval($fstatinfo['mtime'])));
  $fmode = strtoupper(dechex(intval($fstatinfo['mode'])));
  $fuid = strtoupper(dechex(intval($fstatinfo['uid'])));
  $fgid = strtoupper(dechex(intval($fstatinfo['gid'])));
  $fcontents = "";
  if($ftype==1) {
   $fpc = fopen(fname, "rb");
   $fcontents = read($fpc, intval($fstatinfo['st_size']));
   fclose($fpc); }
  $ftypehex = strtoupper(dechex($ftype));
  $ftypeoutstr = $ftypehex;
  $catfileoutstr = $ftypeoutstr."\0";
  $catfileoutstr = $catfileoutstr.fname."\0";
  $catfileoutstr = $catfileoutstr.fsize."\0";
  $catfileoutstr = $catfileoutstr.flinkname."\0";
  $catfileoutstr = $catfileoutstr.fatime."\0";
  $catfileoutstr = $catfileoutstr.fmtime."\0";
  $catfileoutstr = $catfileoutstr.fmode."\0";
  $catfileoutstr = $catfileoutstr.fuid."\0";
  $catfileoutstr = $catfileoutstr.fgid."\0";
  $catfileheadercshex = strtoupper(dechex(crc32(catfileoutstr)));
  $catfileoutstr = $catfileoutstr.$catfileheadercshex."\0";
  $catfileoutstrecd = $catfileoutstr;
  $nullstrecd = "\0";
  $catfileout = $catfileoutstrecd.$fcontents.$nullstrecd;
  fwrite($catfp, $catfileout); }
 fclose(catfp);
 return true; }

function PHPUnCatFile($infile, $outdir=null, $verbose=False) {
 $catfp = fopen($infile, "rb");
 fseek($catfp, 0, SEEK_END);
 $CatSize = ftell($catfp);
 $CatSizeEnd = $CatSize;
 fseek($catfp, 0, SEEK_SET);
 $phpcatstring = fread($catfp, 7);
 $phpcatver = hexdec(ReadTillNullByte($catfp));
 while(ftell($catfp)<$CatSizeEnd) {
  $phpcatftype = hexdec(ReadTillNullByte($catfp));
  $phpcatfname = ReadTillNullByte($catfp);
  if($verbose===true):
   print($phpcatfname);
  $phpcatfsize = hexdec(ReadTillNullByte($catfp));
  $phpcatflinkname = ReadTillNullByte($catfp);
  $phpcatfatime = hexdec(ReadTillNullByte($catfp));
  $phpcatfmtime = hexdec(ReadTillNullByte($catfp));
  $phpcatfmode = hexdec(ReadTillNullByte($catfp));
  $phpcatfmodeoct = decoct(phpcatfmode);
  $phpcatfchmod = hexdec("0".substr($phpcatfmode,-3));
  $phpcatfuid = hexdec(ReadTillNullByte($catfp));
  $phpcatfgid = hexdec(ReadTillNullByte($catfp));
  $phpcatfcs = hexdec(ReadTillNullByte($catfp));
  $phpcatfcontents = $catfp.fread($phpcatfsize);
  if($phpcatftype==0) {
   mkdir($phpcatfname, $phpcatfchmod);
   chown($phpcatfname, $phpcatfuid);
   chgrp($phpcatfname, $phpcatfgid);
   chmod($phpcatfname, $phpcatfchmod);
   touch($phpcatfname, $phpcatfmtime, $phpcatfatime); }
  if($phpcatftype==1) {
   $fpc = fopen($fpc, $phpcatfname, "wb");
   fwrite($fpc, $phpcatfcontents);
   fclose($fpc);
   chown($phpcatfname, $phpcatfuid);
   chgrp($phpcatfname, $phpcatfgid);
   chmod($phpcatfname, $phpcatfchmod);
   touch($phpcatfname, $phpcatfmtime, $phpcatfatime); }
  if($phpcatftype==2) {
   symlink($phpcatflinkname, $phpcatfname); }
  if($phpcatftype==3) {
   link($phpcatflinkname, $phpcatfname); }
  fseek($catfp, 1, SEEK_CUR); }
 fclose($catfp);
 return True; }

?>
