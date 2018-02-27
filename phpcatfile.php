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

date_default_timezone_set('UTC');

function ListDir($dirname) {
 if(DIRECTORY_SEPARATOR=="\\") {
  $dirname = str_replace(DIRECTORY_SEPARATOR, "/", $dirname); }
 $fulllist[] = $dirname;
 if(is_dir($dirname)) {
  if($dh = opendir($dirname)) {
   while(($file = readdir($dh)) !== false) {
    if($file!="." && $file!=".." && is_dir($dirname."/".$file)) {
     $fulllistnew = ListDir($dirname."/".$file);
	 foreach($fulllistnew as $fulllistary) {
	  $fulllist[] = $fulllistary; } }
    if(!is_dir($dirname."/".$file)) {
     $fulllist[] = $dirname."/".$file; } } }
	closedir($dh); }
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
 fwrite($catfp, $fileheader);
 $GetDirList = ListDir($infiles);
 foreach($GetDirList as $curfname) {
  $fname = $curfname;
  if($verbose===true) {
   print($fname."\n"); }
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
  if($ftype==1) {
   $fsize = strtoupper(dechex(intval($fstatinfo['size']))); }
  $flinkname = "";
  if($ftype==2 || $ftype==3) {
   $flinkname = os.readlink($fname); }
  $flinknameintsize = strlen($flinkname);
  $fatime = strtoupper(dechex(intval($fstatinfo['atime'])));
  $fmtime = strtoupper(dechex(intval($fstatinfo['mtime'])));
  $fmode = strtoupper(dechex(intval($fstatinfo['mode'])));
  $fuid = strtoupper(dechex(intval($fstatinfo['uid'])));
  $fgid = strtoupper(dechex(intval($fstatinfo['gid'])));
  $fcontents = "";
  if($ftype==1) {
   $fpc = fopen($fname, "rb");
   $fcontents = fread($fpc, intval($fstatinfo['size']));
   fclose($fpc); }
  $ftypehex = strtoupper(dechex($ftype));
  $ftypeoutstr = $ftypehex;
  $catfileoutstr = $ftypeoutstr."\0";
  $catfileoutstr = $catfileoutstr.$fname."\0";
  $catfileoutstr = $catfileoutstr.$fsize."\0";
  $catfileoutstr = $catfileoutstr.$flinkname."\0";
  $catfileoutstr = $catfileoutstr.$fatime."\0";
  $catfileoutstr = $catfileoutstr.$fmtime."\0";
  $catfileoutstr = $catfileoutstr.$fmode."\0";
  $catfileoutstr = $catfileoutstr.$fuid."\0";
  $catfileoutstr = $catfileoutstr.$fgid."\0";
  $catfileheadercshex = strtoupper(dechex(crc32($catfileoutstr)));
  $catfileoutstr = $catfileoutstr.$catfileheadercshex."\0";
  $catfileoutstrecd = $catfileoutstr;
  $nullstrecd = "\0";
  $catfileout = $catfileoutstrecd.$fcontents.$nullstrecd;
  fwrite($catfp, $catfileout); }
 fclose($catfp);
 return true; }

function PyCatFile($infiles, $outfile, $verbose=false) {
 return PHPCatFile($infiles, $outfile, $verbose); }

function PHPCatToArray($infile) {
 $catfp = fopen($infile, "rb");
 fseek($catfp, 0, SEEK_END);
 $CatSize = ftell($catfp);
 $CatSizeEnd = $CatSize;
 fseek($catfp, 0, SEEK_SET);
 $phpcatstring = fread($catfp, 7);
 $phpcatver = hexdec(ReadTillNullByte($catfp));
 $pycatlist = array();
 while(ftell($catfp)<$CatSizeEnd) {
  $phpcatftype = hexdec(ReadTillNullByte($catfp));
  $phpcatfname = ReadTillNullByte($catfp);
  if($verbose===true) {
   print($phpcatfname."\n"); }
  $phpcatfsize = hexdec(ReadTillNullByte($catfp));
  $phpcatflinkname = ReadTillNullByte($catfp);
  $phpcatfatime = hexdec(ReadTillNullByte($catfp));
  $phpcatfmtime = hexdec(ReadTillNullByte($catfp));
  $phpcatfmode = hexdec(ReadTillNullByte($catfp));
  $phpcatfmodeoct = decoct($phpcatfmode);
  $phpcatfchmod = hexdec("0".substr($phpcatfmode,-3));
  $phpcatfuid = hexdec(ReadTillNullByte($catfp));
  $phpcatfgid = hexdec(ReadTillNullByte($catfp));
  $phpcatfcs = hexdec(ReadTillNullByte($catfp));
  $phpcatfcontents = "";
  if($phpcatfsize>1) {
   $phpcatfcontents = fread($catfp, $phpcatfsize); }
  $pycatlist[] = array('ftype' => $phpcatftype, 'fname' => $phpcatfname, 'fsize' => $phpcatfsize, 'flinkname' => $phpcatflinkname, 'fatime' => $phpcatfatime, 'fmtime' => $phpcatfmtime, 'fmode' => $phpcatfmode, 'fchmod' => $phpcatfchmod, 'fuid' => $phpcatfuid, 'fgid' => $phpcatfgid, 'fchecksum' => $phpcatfcs, 'fcontents' => $phpcatfcontents);
  fseek($catfp, 1, SEEK_CUR); }
 fclose($catfp);
 return $pycatlist; }

function PyCatToArray($infile) {
 return PHPCatToArray($infile); }

function PHPUnCatFile($infile, $outdir=null, $verbose=False) {
 $listcatfiles = PHPCatToArray($infile);
 $lcfi = 0;
 $lcfx = count($listcatfiles);
 while($lcfi<$lcfx) {
  if($verbose===true) {
   print($listcatfiles[$lcfi]['fname']."\n"); }
  if($listcatfiles[$lcfi]['ftype']==0) {
   mkdir($listcatfiles[$lcfi]['fname'], $listcatfiles[$lcfi]['fchmod']);
   chown($listcatfiles[$lcfi]['fname'], $listcatfiles[$lcfi]['fuid']);
   chgrp($listcatfiles[$lcfi]['fname'], $listcatfiles[$lcfi]['fgid']);
   chmod($listcatfiles[$lcfi]['fname'], $listcatfiles[$lcfi]['fchmod']);
   touch($listcatfiles[$lcfi]['fname'], $listcatfiles[$lcfi]['fmtime'], $listcatfiles[$lcfi]['fatime']); }
  if($listcatfiles[$lcfi]['ftype']==1) {
   $fpc = fopen($listcatfiles[$lcfi]['fname'], "wb");
   fwrite($fpc, $listcatfiles[$lcfi]['fcontents']);
   fclose($fpc);
   chown($listcatfiles[$lcfi]['fname'], $listcatfiles[$lcfi]['fuid']);
   chgrp($listcatfiles[$lcfi]['fname'], $listcatfiles[$lcfi]['fgid']);
   chmod($listcatfiles[$lcfi]['fname'], $listcatfiles[$lcfi]['fchmod']);
   touch($listcatfiles[$lcfi]['fname'], $listcatfiles[$lcfi]['fmtime'], $listcatfiles[$lcfi]['fatime']); }
  if($listcatfiles[$lcfi]['ftype']==2) {
   symlink($listcatfiles[$lcfi]['flinkname'], $listcatfiles[$lcfi]['fname']); }
  if($listcatfiles[$lcfi]['ftype']==3) {
   link($listcatfiles[$lcfi]['flinkname'], $listcatfiles[$lcfi]['fname']); }
  $lcfi = $lcfi + 1; }
 return true; }

function PyUnCatFile($infile, $outdir=null, $verbose=False) {
 return PHPUnCatFile($infile, $outdir, $verbose); }

function PHPCatListFiles($infile, $verbose=false) {
 $listcatfiles = PHPCatToArray($infile);
 $lcfi = 0;
 $lcfx = count($listcatfiles);
 while($lcfi<$lcfx) {
  if($verbose===false) {
   print($listcatfiles[$lcfi]['fname']."\n"); }
  if($verbose===true) {
   $permissionstr = "";
   if($listcatfiles[$lcfi]['ftype']==0) {
    $permissionstr = "d"; }
   if($listcatfiles[$lcfi]['ftype']==1) {
    $permissionstr = "-"; }
   if($listcatfiles[$lcfi]['ftype']==2) {
    $permissionstr = "s"; }
   if($listcatfiles[$lcfi]['ftype']==3) {
    $permissionstr = "l"; }
   $permissionstr .= (($listcatfiles[$lcfi]['fchmod'] & 0x0100) ? 'r' : '-');
   $permissionstr .= (($listcatfiles[$lcfi]['fchmod'] & 0x0080) ? 'w' : '-');
   $permissionstr .= (($listcatfiles[$lcfi]['fchmod'] & 0x0040) ?
                     (($listcatfiles[$lcfi]['fchmod'] & 0x0800) ? 's' : 'x' ) :
                     (($listcatfiles[$lcfi]['fchmod'] & 0x0800) ? 'S' : '-'));
   $permissionstr .= (($listcatfiles[$lcfi]['fchmod'] & 0x0020) ? 'r' : '-');
   $permissionstr .= (($listcatfiles[$lcfi]['fchmod'] & 0x0010) ? 'w' : '-');
   $permissionstr .= (($listcatfiles[$lcfi]['fchmod'] & 0x0008) ?
                     (($listcatfiles[$lcfi]['fchmod'] & 0x0400) ? 's' : 'x' ) :
                     (($listcatfiles[$lcfi]['fchmod'] & 0x0400) ? 'S' : '-'));
   $permissionstr .= (($listcatfiles[$lcfi]['fchmod'] & 0x0004) ? 'r' : '-');
   $permissionstr .= (($listcatfiles[$lcfi]['fchmod'] & 0x0002) ? 'w' : '-');
   $permissionstr .= (($listcatfiles[$lcfi]['fchmod'] & 0x0001) ?
                     (($listcatfiles[$lcfi]['fchmod'] & 0x0200) ? 't' : 'x' ) :
                     (($listcatfiles[$lcfi]['fchmod'] & 0x0200) ? 'T' : '-'));
   print($permissionstr." ".$listcatfiles[$lcfi]['fuid']."/".$listcatfiles[$lcfi]['fgid']." ".str_pad($listcatfiles[$lcfi]['fsize'], 15, " ", STR_PAD_LEFT)." ".gmdate('Y-m-d H:i', $listcatfiles[$lcfi]['fmtime'])." ".$listcatfiles[$lcfi]['fname']."\n"); }
  $lcfi = $lcfi + 1; }
 return true; }

function PyCatListFiles($infile) {
 return PHPCatListFiles($infile); }
?>
