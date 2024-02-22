<?php
/*
    This program is free software; you can redistribute it and/or modify
    it under the terms of the Revised BSD License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Revised BSD License for more details.

    Copyright 2018-2024 Cool Dude 2k - http://idb.berlios.de/
    Copyright 2018-2024 Game Maker 2k - http://intdb.sourceforge.net/
    Copyright 2018-2024 Kazuki Przyborowski - https://github.com/KazukiPrzyborowski

    $FileInfo: phpcatfile.php - Last Update: 2/21/2024 Ver. 0.0.7 RC 1 - Author: cooldude2k $
*/

date_default_timezone_set('UTC');

$info['program_name'] = "PHPCatFile";
$info['project'] = $info['program_name'];
$info['project_url'] = "https://github.com/GameMaker2k/PyCatFile";
$info['version_info'] = array(0 => 0, 1 => 0, 2 => 7, 3 => "RC 1", 4 => 1);
$info['version_id'] = "$Id$";
$info['version_date_info'] = array(0 => 2024, 1 => 2, 2 => 21, 3 => "RC 1", 1);
$info['version_date'] = $info['version_date_info'][0].".".str_pad($info['version_date_info'][1], 2, "-=", STR_PAD_LEFT).".".str_pad($info['version_date_info'][2], 2, "-=", STR_PAD_LEFT);
if($info['version_info'][4]!==Null) {
 $info['version_date_plusrc'] = $info['version_date']."-".$info['version_date_info'][4]; }
if($info['version_info'][4]===Null) {
 $info['version_date_plusrc'] = $info['version_date']; }
if($info['version_info'][3]!==Null) {
 $info['version'] = $info['version_info'][0].".".$info['version_info'][1].".".$info['version_info'][2]." ".$info['version_info'][3]; }
if($info['version_info'][3]===Null) {
 $info['version'] = $info['version_info'][0].".".$info['version_info'][1].".".$info['version_info'][2]; }

if ( !function_exists( 'hex2bin' ) ) {
    function hex2bin( $str ) {
        $sbin = "";
        $len = strlen( $str );
        for ( $i = 0; $i < $len; $i += 2 ) {
            $sbin .= pack( "H*", substr( $str, $i, 2 ) );
        }

        return $sbin;
    }
}

function RemoveWindowsPath($dpath) {
    if ($dpath === null) {
        $dpath = "";
    }
    $dpath = str_replace(DIRECTORY_SEPARATOR, "/", $dpath);
    $dpath = rtrim($dpath, "/");
    if ($dpath == "." || $dpath == "..") {
        $dpath .= "/";
    }
    return $dpath;
}

function NormalizeRelativePath($inpath) {
    $inpath = RemoveWindowsPath($inpath);
    if (strpos($inpath, '/') !== 0) { // Checks if not an absolute path
        if (!str_starts_with($inpath, "./") && !str_starts_with($inpath, "../")) {
            $inpath = "./" . $inpath;
        }
    }
    return $inpath;
}

function ListDir($dirpath, $followlink = false, $duplicates = false) {
    if (is_array($dirpath) || is_object($dirpath)) {
        $dirpath = array_filter((array)$dirpath);
    } else {
        $dirpath = array_filter([$dirpath]);
    }
    $retlist = [];
    foreach ($dirpath as $mydirfile) {
        if (!file_exists($mydirfile)) {
            return false;
        }
        $mydirfile = NormalizeRelativePath($mydirfile);
        if (file_exists($mydirfile) && is_link($mydirfile) && $followlink) {
            $mydirfile = RemoveWindowsPath(realpath($mydirfile));
        }
        if (file_exists($mydirfile) && is_dir($mydirfile)) {
            $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($mydirfile));
            foreach ($files as $file) {
                if ($file->isDir()) continue;
                $fpath = RemoveWindowsPath($file->getPathname());
                if (!$duplicates && !in_array($fpath, $retlist)) {
                    $retlist[] = $fpath;
                } elseif ($duplicates) {
                    $retlist[] = $fpath;
                }
            }
        } else {
            $retlist[] = RemoveWindowsPath($mydirfile);
        }
    }
    return $retlist;
}

function ReadTillNullByte($fp) {
    $curFullByte = "";
    while(($curByte = fgetc($fp)) !== "\0" && $curByte !== false) {
        $curFullByte .= $curByte;
    }
    return $curFullByte;
}

function ReadUntilNullByte($fp) {
    return readTillNullByte($fp);
}

function SeekToEndOfFile($fp) {
    fseek($fp, 0, SEEK_END);
    return true;
}

function ReadFileHeaderData($fp, $rounds = 0) {
    $headerOut = [];
    for ($roCount = 0; $roCount < $rounds; $roCount++) {
        $headerOut[$roCount] = ReadTillNullByte($fp);
    }
    return $headerOut;
}

function AppendNullByte($indata) {
    return $indata . "\0";
}

function AppendNullBytes($indata = []) {
    $outData = "";
    foreach ($indata as $item) {
        $outData .= AppendNullByte($item);
    }
    return $outData;
}

function ReadTillNullByteAlt($fp) {
    $bytesList = "";
    while (($curByte = fgetc($fp)) !== "\0" && $curByte !== false) {
        $bytesList .= $curByte;
    }
    return $bytesList;
}

function readUntilNullByteAlt($fp) {
    return readTillNullByteAlt($fp);
}

function ReadFileHeaderDataAlt($fp, $rounds = 0) {
    $headerOut = [];
    for ($roundCount = 0; $roundCount < $rounds; $roundCount++) {
        $headerOut[$roundCount] = ReadTillNullByteAlt($fp);
    }
    return $headerOut;
}

function AppendNullByteAlt($indata) {
    return $indata . "\0";
}

function AppendNullBytesAlt($indata = []) {
    return implode("\0", array_map('strval', $indata)) . "\0";
}

function CheckFileType($infile) {
 $catfp = fopen($infile, "rb");
 fseek($catfp, 0, 0);
 $prefp = fread($catfp, 2);
 $filetype = False;
 if($prefp==hex2bin("1f8b")) {
  $filetype = "gzip"; }
 fseek($catfp, 0, 0);
 $prefp = fread($catfp, 3);
 if($prefp==hex2bin("425a68")) {
  $filetype = "bzip2"; }
 fseek($catfp, 0, 0);
 $prefp = fread($catfp, 7);
 /*if($prefp==hex2bin("fd377a585a0000")) {
  $filetype = "lzma"; }*/
 if($prefp==hex2bin("43617446696c65")) {
  $filetype = "catfile"; }
 fclose($catfp);
 return $filetype; }

function CompressCatFile($infile) {
 if(pathinfo($infile, PATHINFO_EXTENSION)=="gz" or pathinfo($infile, PATHINFO_EXTENSION)=="cgz") {
  if(!function_exists("gzcompress")) {
   return False; }
  if(file_exists(pathinfo($infile, PATHINFO_FILENAME).".tmp")) {
   unlink(pathinfo($infile, PATHINFO_FILENAME).".tmp"); }
  rename($infile, pathinfo($infile, PATHINFO_FILENAME).".tmp");
  $catuncomp = fopen(pathinfo($infile, PATHINFO_FILENAME).".tmp", "rb");
  $catcomp = fopen($infile, "wb");
  fseek($catuncomp, 0, SEEK_END);
  $endoffile = ftell($catuncomp);
  fseek($catuncomp, 0, SEEK_SET);
  fwrite($catcomp, gzcompress(fread($catuncomp, $endoffile), 9));
  fclose($catcomp);
  fclose($catuncomp);
  unlink(pathinfo($infile, PATHINFO_FILENAME).".tmp"); }
 if(pathinfo($infile, PATHINFO_EXTENSION)=="bz2" or pathinfo($infile, PATHINFO_EXTENSION)=="cbz") {
  if(!function_exists("gzcompress")) {
   return False; }
  if(file_exists(pathinfo($infile, PATHINFO_FILENAME).".tmp")) {
   unlink(pathinfo($infile, PATHINFO_FILENAME).".tmp"); }
  rename($infile, pathinfo($infile, PATHINFO_FILENAME).".tmp");
  $catuncomp = fopen(pathinfo($infile, PATHINFO_FILENAME).".tmp", "rb");
  $catcomp = fopen($infile, "wb");
  fseek($catuncomp, 0, SEEK_END);
  $endoffile = ftell($catuncomp);
  fseek($catuncomp, 0, SEEK_SET);
  fwrite($catcomp, bzcompress(fread($catuncomp, $endoffile), 9));
  fclose($catcomp);
  fclose($catuncomp);
  unlink(pathinfo($infile, PATHINFO_FILENAME).".tmp"); }
 return True; }

function PackCatFile($infiles, $outfile, $followlink=False, $checksumtype="crc32", $verbose=False) {
 global $info;
 $catver = $info['version_info'][0].".".$info['version_info'][1].".".$info['version_info'][2];
 $infiles = RemoveWindowsPath($infiles);
 $outfile = RemoveWindowsPath($outfile);
 $checksumtype = strtolower($checksumtype);
 if($checksumtype!="adler32" && $checksumtype!="crc32" && $checksumtype!="md5" && $checksumtype!="sha1" && $checksumtype!="sha224" && $checksumtype!="sha256" && $checksumtype!="sha384" && $checksumtype!="sha512") {
  $checksumtype="crc32"; }
 if(file_exists($outfile)) {
  unlink($outfile); }
 $catfp = fopen($outfile, "wb");
 $fileheaderver = intval(str_replace(".", "", $catver));
 $fileheader = AppendNullByte("CatFile".$fileheaderver);
 fwrite($catfp, $fileheader);
 $GetDirList = ListDir($infiles);
 foreach($GetDirList as $curfname) {
  $fname = $curfname;
  if($verbose===True) {
   print($fname."\n"); }
  if($followlink===False || $followlink===Null) {
   $fstatinfo = lstat($fname); }
  else {
   $fstatinfo = stat($fname); }
  $ftype = 0;
  if(is_file($fname)) {
   $ftype = 0; }
  if(is_link($fname)) {
   $ftype = 2; }
  if(is_dir($fname)) {
   $ftype = 5; }
  if($ftype==1 || $ftype==2 || $ftype==5) {
   $fsize = strtolower(dechex(intval("0"))); }
  if($ftype==0) {
   $fsize = strtolower(dechex(intval($fstatinfo['size']))); }
  $flinkname = "";
  if($ftype==1 || $ftype==2) {
   $flinkname = readlink($fname); }
  $fatime = strtolower(dechex(intval($fstatinfo['atime'])));
  $fmtime = strtolower(dechex(intval($fstatinfo['mtime'])));
  $fmode = strtolower(dechex(intval($fstatinfo['mode'])));
  $fuid = strtolower(dechex(intval($fstatinfo['uid'])));
  $fgid = strtolower(dechex(intval($fstatinfo['gid'])));
  $fdev_minor = strtolower(dechex(intval(0)));
  $fdev_major = strtolower(dechex(intval(0)));
  $frdev_minor = strtolower(dechex(intval(0)));
  $frdev_major = strtolower(dechex(intval(0)));
  $fcontents = "";
  if($ftype==0) {
   $fpc = fopen($fname, "rb");
   $fcontents = fread($fpc, intval($fstatinfo['size']));
   fclose($fpc); }
  if($followlink===False && ($ftype==1 && $ftype==2)) {
   $flstatinfo = stat($flinkname);
   $fpc = fopen($flinkname, "rb");
   $fcontents = fread($fpc, intval($flstatinfo['size']));
   fclose($fpc); }
  $ftypehex = strtolower(dechex($ftype));
  $ftypeoutstr = $ftypehex;
  $catfileoutstr = AppendNullByte($ftypeoutstr);
  $catfileoutstr = $catfileoutstr.AppendNullByte($fname);
  $catfileoutstr = $catfileoutstr.AppendNullByte($flinkname);
  $catfileoutstr = $catfileoutstr.AppendNullByte($fsize);
  $catfileoutstr = $catfileoutstr.AppendNullByte($fatime);
  $catfileoutstr = $catfileoutstr.AppendNullByte($fmtime);
  $catfileoutstr = $catfileoutstr.AppendNullByte($fmode);
  $catfileoutstr = $catfileoutstr.AppendNullByte($fuid);
  $catfileoutstr = $catfileoutstr.AppendNullByte($fgid);
  $catfileoutstr = $catfileoutstr.AppendNullByte($fdev_minor);
  $catfileoutstr = $catfileoutstr.AppendNullByte($fdev_major);
  $catfileoutstr = $catfileoutstr.AppendNullByte($frdev_minor);
  $catfileoutstr = $catfileoutstr.AppendNullByte($frdev_major);
  $catfileoutstr = $catfileoutstr.AppendNullByte($checksumtype);
  if($checksumtype=="adler32" || $checksumtype=="crc32") {
   $catfileheadercshex = strtolower(dechex(hash($checksumtype, $catfileoutstr)));
   $catfilecontentcshex = strtolower(dechex(hash($checksumtype, $catfileoutstr))); }
  if($checksumtype=="md5" || $checksumtype=="sha1" || $checksumtype=="sha224" || $checksumtype=="sha256" || $checksumtype=="sha384" || $checksumtype=="sha512") {
   $catfileheadercshex = strtolower(hash($checksumtype, $catfileoutstr));
   $catfilecontentcshex = strtolower(hash($checksumtype, $catfileoutstr)); }
  $catfileoutstr = $catfileoutstr.AppendNullByte($catfileheadercshex);
  $catfileoutstr = $catfileoutstr.AppendNullByte($catfilecontentcshex);
  $catfileoutstrecd = $catfileoutstr;
  $Nullstrecd = "\0";
  $catfileout = $catfileoutstrecd.$fcontents.$Nullstrecd;
  fwrite($catfp, $catfileout); }
 fclose($catfp);
 return True; }

function CatFileToArray($infile, $seekstart=0, $seekend=0, $listonly=False, $skipchecksum=False) {
 $infile = RemoveWindowsPath($infile);
 $compresscheck = CheckFileType($infile);
 if($compresscheck===False) {
  return False; }
 if($compresscheck==="gzip") {
  $catfp = gzopen($infile, "rb"); }
 if($compresscheck==="bzip2") {
  $catfp = bzopen($infile, "rb"); }
 if($compresscheck==="catfile") {
  $catfp = fopen($infile, "rb"); }
 fseek($catfp, 0, SEEK_END);
 $CatSize = ftell($catfp);
 $CatSizeEnd = $CatSize;
 fseek($catfp, 0, SEEK_SET);
 $catstring = ReadFileHeaderData($catfp, 1)[0];
 preg_match("/([\d]+)$/", $catstring, $catm);
 $catversion = $catm[0];
 $catlist = array();
 $fileidnum = 0;
 if($seekstart!=0) {
  fseek($catfp, $seekstart, SEEK_SET); }
 if($seekstart==0) {
  $seekstart = ftell($catfp); }
 if($seekend==0) {
  $seekend = $CatSizeEnd; }
 while($seekstart<$seekend) {
  $catfhstart = ftell($catfp);
  $catheaderdata = ReadFileHeaderData($catfp, 16);
  $catftype = hexdec($catheaderdata[0]);
  $catfname = $catheaderdata[1];
  $catflinkname = $catheaderdata[2];
  $catfsize = hexdec($catheaderdata[3]);
  $catfatime = hexdec($catheaderdata[4]);
  $catfmtime = hexdec($catheaderdata[5]);
  $catfmode = decoct(hexdec($catheaderdata[6]));
  $catfchmod = substr($catfmode, -3);
  $catfuid = hexdec($catheaderdata[7]);
  $catfgid = hexdec($catheaderdata[8]);
  $catfdev_minor = hexdec($catheaderdata[9]);
  $catfdev_major = hexdec($catheaderdata[10]);
  $catfrdev_minor = hexdec($catheaderdata[11]);
  $catfrdev_major = hexdec($catheaderdata[12]);
  $catfchecksumtype = strtolower($catheaderdata[13]);
  if($catfchecksumtype=="adler32" || $catfchecksumtype=="crc32") {
   $catfcs = hexdec($catheaderdata[14]);
   $catfccs = hexdec($catheaderdata[15]); }
  if($catfchecksumtype=="md5" || $catfchecksumtype=="sha1" || $catfchecksumtype=="sha224" || $catfchecksumtype=="sha256" || $catfchecksumtype=="sha384" || $catfchecksumtype=="sha512") {
   $catfcs = $catheaderdata[14];
   $catfccs = $catheaderdata[15]; }
  $hc = 0;
  $hcmax = count($catheaderdata) - 2;
  $hout = "";
  while($hc<$hcmax) {
   $hout = $hout.AppendNullByte($catheaderdata[$hc]);
   $hc = $hc + 1; }
  $catnewfcs = strtolower(hash($catfchecksumtype, $hout));
  if($catfcs!=$catnewfcs && $skipchecksum===False) {
   print("File Header Checksum Error with file "+$catfname+" at offset "+$catfhstart);
   return False; }
  $catfhend = ftell($catfp) - 1;
  $catfcontentstart = ftell($catfp);
  $catfcontents = "";
  $phphascontents = False;
  if($catfsize>1 && $listonly===False) {
   $catfcontents = fread($catfp, $catfsize); 
   $catnewfccs = strtolower(hash($catfchecksumtype, $catfcontents));
   if($catfccs!=$catnewfccs && $skipchecksum===False) {
    print("File Content Checksum Error with file "+$catfname+" at offset "+$catfcontentstart);
    return False; }
   $phphascontents = True; }
  if($catfsize>1 && $listonly===True) {
   fseek($catfp, $catfsize, SEEK_CUR); 
   $phphascontents = False; }
  $catfcontentend = ftell($catfp);
  $catlist[$fileidnum] = array('catfileversion' => $catversion, 'fid' => $fileidnum, 'fhstart' => $catfhstart, 'fhend' => $catfhend, 'ftype' => $catftype, 'fname' => $catfname, 'flinkname' => $catflinkname, 'fsize' => $catfsize, 'fatime' => $catfatime, 'fmtime' => $catfmtime, 'fmode' => $catfmode, 'fchmod' => $catfchmod, 'fuid' => $catfuid, 'fgid' => $catfgid, 'fminor' => $catfdev_minor, 'fmajor' => $catfdev_major, 'fchecksumtype' => $catfchecksumtype, 'fheaderchecksum' => $catfcs, 'fcontentchecksum' => $catfccs, 'fhascontents' => $phphascontents, 'fcontentstart' => $catfcontentstart, 'fcontentend' => $catfcontentend, 'fcontents' => $catfcontents);
  fseek($catfp, 1, SEEK_CUR);
  $seekstart = ftell($catfp);
  $fileidnum = $fileidnum + 1; }
 fclose($catfp);
 return $catlist; }

function CatFileToArrayIndex($infile, $seekstart=0, $seekend=0, $listonly=False, $skipchecksum=False) {
 if(is_array($infile)) {
  $listcatfiles = $infile; }
 else {
  $infile = RemoveWindowsPath($infile);
  $listcatfiles = CatFileToArray($infile, $seekstart, $seekend, $listonly, $skipchecksum); }
 if($listcatfiles===False) {
  return False; }
 $catarray = array('list' => $listcatfiles, 'filetoid' => array(), 'idtofile' => array(), 'filetypes' => array('directories' => array('filetoid' => array(), 'idtofile' => array()), 'files' => array('filetoid' => array(), 'idtofile' => array()), 'links' => array('filetoid' => array(), 'idtofile' => array()), 'symlinks' => array('filetoid' => array(), 'idtofile' => array()), 'hardlinks' => array('filetoid' => array(), 'idtofile' => array()), 'character' => array('filetoid' => array(), 'idtofile' => array()), 'block' => array('filetoid' => array(), 'idtofile' => array()), 'fifo' => array('filetoid' => array(), 'idtofile' => array()), 'devices' => array('filetoid' => array(), 'idtofile' => array())));
 $lcfi = 0;
 $lcfx = count($listcatfiles);
 while($lcfi<$lcfx) {
  $fname = $listcatfiles[$lcfi]['fname'];
  $fid = $listcatfiles[$lcfi]['fid'];
  $catarray['filetoid'][$fname] = $fid;
  $catarray['idtofile'][$fid] = $fname;
  if($listcatfiles[$lcfi]['ftype']==0) {
   $catarray['filetypes']['files']['filetoid'][$fname] = $fid;
   $catarray['filetypes']['files']['idtofile'][$fid] = $fname; }
  if($listcatfiles[$lcfi]['ftype']==1) {
   $catarray['filetypes']['hardlinks']['filetoid'][$fname] = $fid;
   $catarray['filetypes']['hardlinks']['idtofile'][$fid] = $fname;
   $catarray['filetypes']['links']['filetoid'][$fname] = $fid;
   $catarray['filetypes']['links']['idtofile'][$fid] = $fname; }
  if($listcatfiles[$lcfi]['ftype']==2) {
   $catarray['filetypes']['symlinks']['filetoid'][$fname] = $fid;
   $catarray['filetypes']['symlinks']['idtofile'][$fid] = $fname;
   $catarray['filetypes']['links']['filetoid'][$fname] = $fid;
   $catarray['filetypes']['links']['idtofile'][$fid] = $fname; }
  if($listcatfiles[$lcfi]['ftype']==3) {
   $catarray['filetypes']['character']['filetoid'][$fname] = $fid;
   $catarray['filetypes']['character']['idtofile'][$fid] = $fname;
   $catarray['filetypes']['devices']['filetoid'][$fname] = $fid;
   $catarray['filetypes']['devices']['idtofile'][$fid] = $fname; }
  if($listcatfiles[$lcfi]['ftype']==4) {
   $catarray['filetypes']['block']['filetoid'][$fname] = $fid;
   $catarray['filetypes']['block']['idtofile'][$fid] = $fname;
   $catarray['filetypes']['devices']['filetoid'][$fname] = $fid;
   $catarray['filetypes']['devices']['idtofile'][$fid] = $fname; }
  if($listcatfiles[$lcfi]['ftype']==5) {
   $catarray['filetypes']['directories']['filetoid'][$fname] = $fid;
   $catarray['filetypes']['directories']['idtofile'][$fid] = $fname; }
  if($listcatfiles[$lcfi]['ftype']==6) {
   $catarray['filetypes']['fifo']['filetoid'][$fname] = $fid;
   $catarray['filetypes']['fifo']['idtofile'][$fid] = $fname;
   $catarray['filetypes']['devices']['filetoid'][$fname] = $fid;
   $catarray['filetypes']['devices']['idtofile'][$fid] = $fname; }
  $lcfi = $lcfi + 1; }
 return $catarray; }

function RePackCatFile($infiles, $outfile, $seekstart=0, $seekend=0, $checksumtype="crc32", $skipchecksum=False, $verbose=False) {
 if(is_array($infile)) {
  $listcatfiles = $infile; }
 else {
  $infile = RemoveWindowsPath($infile);
  $listcatfiles = CatFileToArray($infile, $seekstart, $seekend, False, $skipchecksum); }
 $checksumtype = strtolower($checksumtype);
 if($checksumtype!="adler32" && $checksumtype!="crc32" && $checksumtype!="md5" && $checksumtype!="sha1" && $checksumtype!="sha224" && $checksumtype!="sha256" && $checksumtype!="sha384" && $checksumtype!="sha512") {
  $checksumtype="crc32"; }
 if($listcatfiles===False) {
  return False; }
 $lcfi = 0;
 $lcfx = count($listcatfiles);
 while($lcfi<$lcfx) {
  $fname = $listcatfiles[$lcfi]['fname'];
  if($verbose===True) {
   print($fname."\n"); }
  $fsize = strtolower(dechex(intval($listcatfiles[$lcfi]['fsize'])));
  $flinkname = $listcatfiles[$lcfi]['flinkname'];
  $fatime = strtolower(dechex(intval($listcatfiles[$lcfi]['fatime'])));
  $fmtime = strtolower(dechex(intval($listcatfiles[$lcfi]['fmtime'])));
  $fmode = strtolower(dechex(intval($listcatfiles[$lcfi]['fmode'])));
  $fuid = strtolower(dechex(intval($listcatfiles[$lcfi]['fuid'])));
  $fgid = strtolower(dechex(intval($listcatfiles[$lcfi]['fgid'])));
  $fdev_minor = strtolower(dechex(intval($listcatfiles[$lcfi]['fminor'])));
  $fdev_major = strtolower(dechex(intval($listcatfiles[$lcfi]['fmajor'])));
  $frdev_minor = strtolower(dechex(intval($listcatfiles[$lcfi]['frminor'])));
  $frdev_major = strtolower(dechex(intval($listcatfiles[$lcfi]['frmajor'])));
  $fcontents = $listcatfiles[$lcfi]['fcontents'];
  $ftypehex = strtolower(dechex(intval($listcatfiles[$lcfi]['ftype'])));
  $ftypeoutstr = $ftypehex;
  $catfileoutstr = AppendNullByte($ftypeoutstr);
  $catfileoutstr = $catfileoutstr.AppendNullByte($fname);
  $catfileoutstr = $catfileoutstr.AppendNullByte($flinkname);
  $catfileoutstr = $catfileoutstr.AppendNullByte($fsize);
  $catfileoutstr = $catfileoutstr.AppendNullByte($fatime);
  $catfileoutstr = $catfileoutstr.AppendNullByte($fmtime);
  $catfileoutstr = $catfileoutstr.AppendNullByte($fmode);
  $catfileoutstr = $catfileoutstr.AppendNullByte($fuid);
  $catfileoutstr = $catfileoutstr.AppendNullByte($fgid);
  $catfileoutstr = $catfileoutstr.AppendNullByte($fdev_minor);
  $catfileoutstr = $catfileoutstr.AppendNullByte($fdev_major);
  $catfileoutstr = $catfileoutstr.AppendNullByte($frdev_minor);
  $catfileoutstr = $catfileoutstr.AppendNullByte($frdev_major);
  $catfileoutstr = $catfileoutstr.AppendNullByte($checksumtype);
  if($checksumtype=="adler32" || $checksumtype=="crc32") {
   $catfileheadercshex = strtolower(dechex(hash($checksumtype, $catfileoutstr)));
   $catfilecontentcshex = strtolower(dechex(hash($checksumtype, $catfileoutstr))); }
  if($checksumtype=="md5" || $checksumtype=="sha1" || $checksumtype=="sha224" || $checksumtype=="sha256" || $checksumtype=="sha384" || $checksumtype=="sha512") {
   $catfileheadercshex = strtolower(hash($checksumtype, $catfileoutstr));
   $catfilecontentcshex = strtolower(hash($checksumtype, $catfileoutstr)); }
  $catfileoutstr = $catfileoutstr.AppendNullByte($catfileheadercshex);
  $catfileoutstr = $catfileoutstr.AppendNullByte($catfilecontentcshex);
  $catfileoutstrecd = $catfileoutstr;
  $Nullstrecd = "\0";
  $catfileout = $catfileoutstrecd.$fcontents.$Nullstrecd;
  fwrite($catfp, $catfileout); }
 fclose($catfp);
 return True; }

function UnPackCatFile($infile, $outdir=Null, $verbose=False, $skipchecksum=False) {
 if($outdir!==Null) {
  $outdir = RemoveWindowsPath($outdir); }
 if(is_array($infile)) {
  $listcatfiles = $infile; }
 else {
  $infile = RemoveWindowsPath($infile);
  $listcatfiles = CatFileToArray($infile, 0, 0, False, $skipchecksum); }
 if($listcatfiles===False) {
  return False; }
 $lcfi = 0;
 $lcfx = count($listcatfiles);
 while($lcfi<$lcfx) {
  if($verbose===True) {
   print($listcatfiles[$lcfi]['fname']."\n"); }
  if($listcatfiles[$lcfi]['ftype']==0) {
   $fpc = fopen($listcatfiles[$lcfi]['fname'], "wb");
   fwrite($fpc, $listcatfiles[$lcfi]['fcontents']);
   fclose($fpc);
   chown($listcatfiles[$lcfi]['fname'], $listcatfiles[$lcfi]['fuid']);
   chgrp($listcatfiles[$lcfi]['fname'], $listcatfiles[$lcfi]['fgid']);
   chmod($listcatfiles[$lcfi]['fname'], $listcatfiles[$lcfi]['fchmod']);
   touch($listcatfiles[$lcfi]['fname'], $listcatfiles[$lcfi]['fmtime'], $listcatfiles[$lcfi]['fatime']); }
  if($listcatfiles[$lcfi]['ftype']==1) {
   link($listcatfiles[$lcfi]['flinkname'], $listcatfiles[$lcfi]['fname']); }
  if($listcatfiles[$lcfi]['ftype']==2) {
   symlink($listcatfiles[$lcfi]['flinkname'], $listcatfiles[$lcfi]['fname']); }
  if($listcatfiles[$lcfi]['ftype']==5) {
   mkdir($listcatfiles[$lcfi]['fname'], $listcatfiles[$lcfi]['fchmod']);
   chown($listcatfiles[$lcfi]['fname'], $listcatfiles[$lcfi]['fuid']);
   chgrp($listcatfiles[$lcfi]['fname'], $listcatfiles[$lcfi]['fgid']);
   chmod($listcatfiles[$lcfi]['fname'], $listcatfiles[$lcfi]['fchmod']);
   touch($listcatfiles[$lcfi]['fname'], $listcatfiles[$lcfi]['fmtime'], $listcatfiles[$lcfi]['fatime']); }
  $lcfi = $lcfi + 1; }
 return True; }

function CatFileListFiles($infile, $seekstart=0, $seekend=0, $verbose=False, $skipchecksum=False) {
 if(is_array($infile)) {
  $listcatfiles = $infile; }
 else {
  $infile = RemoveWindowsPath($infile);
  $listcatfiles = CatFileToArray($infile, $seekstart, $seekend, True, $skipchecksum); }
 if($listcatfiles===False) {
  return False; }
 $lcfi = 0;
 $lcfx = count($listcatfiles);
 $returnval = array();
 while($lcfi<$lcfx) {
  $returnval[$lcfi] = $listcatfiles[$lcfi]['fname'];
  if($verbose===False) {
   print($listcatfiles[$lcfi]['fname']."\n"); }
  if($verbose===True) {
   $permissionstr = "";
   if($listcatfiles[$lcfi]['ftype']==0) {
    $permissionstr = "-"; }
   if($listcatfiles[$lcfi]['ftype']==1) {
    $permissionstr = "h"; }
   if($listcatfiles[$lcfi]['ftype']==2) {
    $permissionstr = "l"; }
   if($listcatfiles[$lcfi]['ftype']==3) {
    $permissionstr = "c"; }
   if($listcatfiles[$lcfi]['ftype']==4) {
    $permissionstr = "b"; }
   if($listcatfiles[$lcfi]['ftype']==5) {
    $permissionstr = "d"; }
   if($listcatfiles[$lcfi]['ftype']==6) {
    $permissionstr = "f"; }
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
   $printfname = $listcatfiles[$lcfi]['fname'];
   if($listcatfiles[$lcfi]['ftype']==1) {
    $printfname = $listcatfiles[$lcfi]['fname']." link to "+$listcatfiles[$lcfi]['flinkname']; }
   if($listcatfiles[$lcfi]['ftype']==2) {
    $printfname = $listcatfiles[$lcfi]['fname']." -> "+$listcatfiles[$lcfi]['flinkname']; }
   print($permissionstr." ".$listcatfiles[$lcfi]['fuid']."/".$listcatfiles[$lcfi]['fgid']." ".str_pad($listcatfiles[$lcfi]['fsize'], 15, " ", STR_PAD_LEFT)." ".gmdate('Y-m-d H:i', $listcatfiles[$lcfi]['fmtime'])." ".$printfname."\n"); }
  $lcfi = $lcfi + 1; }
 return True; }

?>
