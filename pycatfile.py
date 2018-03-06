#!/usr/bin/python
# -*- coding: utf-8 -*-

'''
    This program is free software; you can redistribute it and/or modify
    it under the terms of the Revised BSD License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Revised BSD License for more details.

    Copyright 2018 Cool Dude 2k - http://idb.berlios.de/
    Copyright 2018 Game Maker 2k - http://intdb.sourceforge.net/
    Copyright 2018 Kazuki Przyborowski - https://github.com/KazukiPrzyborowski

    $FileInfo: pycatfile.py - Last Update: 3/6/2018 Ver. 0.0.1 RC 1 - Author: cooldude2k $
'''

from __future__ import absolute_import, division, print_function, unicode_literals;

__program_name__ = "PyCatFile";
__project__ = __program_name__;
__project_url__ = "https://github.com/GameMaker2k/PyCatFile";
__version_info__ = (0, 0, 1, "RC 1", 1);
__version_date_info__ = (2018, 3, 6, "RC 1", 1);
__version_date__ = str(__version_date_info__[0]) + "." + str(__version_date_info__[1]).zfill(2) + "." + str(__version_date_info__[2]).zfill(2);
if(__version_info__[4] is not None):
 __version_date_plusrc__ = __version_date__ + "-" + str(__version_date_info__[4]);
if(__version_info__[4] is None):
 __version_date_plusrc__ = __version_date__;
if(__version_info__[3] is not None):
 __version__ = str(__version_info__[0]) + "." + str(__version_info__[1]) + "." + str(__version_info__[2]) + " " + str(__version_info__[3]);
if(__version_info__[3] is None):
 __version__ = str(__version_info__[0]) + "." + str(__version_info__[1]) + "." + str(__version_info__[2]);

import os, sys, re, stat, logging, zlib, hashlib, binascii;

try:
 from StringIO import StringIO as BytesIO;
except ImportError:
 from io import BytesIO;

tarsupport = False;
try:
 import tarfile;
 tarsupport = True;
except ImportError:
 tarsupport = False;

if __name__ == '__main__':
 import argparse;

if __name__ == '__main__':
 argparser = argparse.ArgumentParser(description="Manipulating concatenate files", conflict_handler="resolve", add_help=True);
 argparser.add_argument("-V", "--version", action="version", version=__program_name__ + " " + __version__);
 argparser.add_argument("-i", "-f", "--input", help="files to concatenate or concatenate file extract", required=True);
 argparser.add_argument("-d", "-v", "--verbose", action="store_true", help="print various debugging information");
 argparser.add_argument("-c", "--create", action="store_true", help="concatenate files only");
 if(tarsupport is True):
  argparser.add_argument("-tar", "--tar", action="store_true", help="convert from tar file");
 argparser.add_argument("-checksum", "--checksum", default="crc32", help="checksum type to use default is crc32");
 argparser.add_argument("-e", "-x", "--extract", action="store_true", help="extract files only");
 argparser.add_argument("-l", "-t", "--list", action="store_true", help="list files only");
 argparser.add_argument("-r", "--repack", action="store_true", help="reconcatenate files only fixing checksum errors");
 argparser.add_argument("-o", "--output", default=None, help="extract concatenate files to or concatenate output name");
 getargs = argparser.parse_args();

def RemoveWindowsPath(dpath):
 if(os.sep!="/"):
  dpath = dpath.replace(os.path.sep, "/");
 dpath = dpath.rstrip("/");
 if(dpath=="." or dpath==".."):
  dpath = dpath + "/";
 return dpath;

def ListDir(dirpath):
 retlist = [];
 for root, dirs, filenames in os.walk(dirpath):
  dpath = root;
  dpath = RemoveWindowsPath(dpath);
  retlist.append(dpath);
  for file in filenames:
   fpath = os.path.join(root, file);
   fpath = RemoveWindowsPath(fpath);
   retlist.append(fpath);
 return retlist;

def ReadTillNullByte(fp):
 curbyte = "";
 curfullbyte = "";
 nullbyte = "\0".encode();
 while(curbyte!=nullbyte):
  curbyte = fp.read(1);
  if(curbyte!=nullbyte):
   curbyted = curbyte.decode('ascii');
   curfullbyte = curfullbyte + curbyted;
 return curfullbyte;

def ReadUntilNullByte(fp):
 return ReadTillNullByte(fp);

def ReadFileHeaderData(fp, rounds=0):
 rocount = 0;
 roend = int(rounds);
 HeaderOut = {};
 while(rocount<roend):
  RoundArray = {rocount: ReadTillNullByte(fp)};
  HeaderOut.update(RoundArray);
  rocount = rocount + 1;
 return HeaderOut;

def AppendNullByte(indata):
 outdata = str(indata) + "\0";
 return outdata;

def CheckFileType(infile):
 if(hasattr(infile, "read")):
  catfp = infile;
 else:
  catfp = open(infile, "rb");
 catfp.seek(0, 0);
 prefp = catfp.read(2);
 filetype = False;
 if(prefp==binascii.unhexlify("1f8b")):
  filetype = "gzip";
 catfp.seek(0, 0);
 prefp = catfp.read(3);
 if(prefp==binascii.unhexlify("425a68")):
  filetype = "bzip2";
 catfp.seek(0, 0);
 prefp = catfp.read(7);
 if(prefp==binascii.unhexlify("fd377a585a0000")):
  filetype = "lzma";
 if(prefp==binascii.unhexlify("43617446696c65")):
  filetype = "catfile";
 catfp.close();
 return filetype;

def CompressCatFile(infile):
 if(hasattr(infile, "read") or hasattr(infile, "write")):
  return True;
 fbasename = os.path.splitext(infile)[0];
 fextname = os.path.splitext(infile)[1];
 if(fextname==".gz" or fextname==".cgz"):
  try:
   import gzip, shutil;
  except ImportError:
   return False;
  if(os.path.exists(fbasename+".tmp")):
   os.unlink(fbasename+".tmp");
  os.rename(infile, fbasename+".tmp");
  with open(fbasename+".tmp", "rb") as catuncomp, gzip.open(infile, "wb", 9) as catcomp:
   shutil.copyfileobj(catuncomp, catcomp);
  catcomp.close();
  catuncomp.close();
  os.unlink(fbasename+".tmp");
 if(fextname==".bz2" or fextname==".cbz"):
  try:
   import bz2, shutil;
  except ImportError:
   return False;
  if(os.path.exists(fbasename+".tmp")):
   os.unlink(fbasename+".tmp");
  os.rename(infile, fbasename+".tmp");
  with open(fbasename+".tmp", "rb") as catuncomp, bz2.BZ2File(infile, "wb", 9) as catcomp:
   shutil.copyfileobj(catuncomp, catcomp);
  catcomp.close();
  catuncomp.close();
  os.unlink(fbasename+".tmp");
 if(fextname==".lzma" or fextname==".xz" or fextname==".cxz"):
  try:
   import lzma, shutil;
  except ImportError:
   return False;
  if(os.path.exists(fbasename+".tmp")):
   os.unlink(fbasename+".tmp");
  os.rename(infile, fbasename+".tmp");
  if(fextname==".lzma"):
   with open(fbasename+".tmp", "rb") as catuncomp, lzma.open(infile, "wb", format=lzma.FORMAT_ALONE, preset=9) as catcomp:
    shutil.copyfileobj(catuncomp, catcomp);
  else:
   with open(fbasename+".tmp", "rb") as catuncomp, lzma.open(infile, "wb", format=lzma.FORMAT_XZ, preset=9) as catcomp:
    shutil.copyfileobj(catuncomp, catcomp);
  catcomp.close();
  catuncomp.close();
  os.unlink(fbasename+".tmp");
 return True;

def GetDevMajorMinor(fdev):
 retdev = [];
 if(hasattr(os, "minor")):
  retdev.append(os.minor(fdev));
 else:
  retdev.append(0);
 if(hasattr(os, "major")):
  retdev.append(os.major(fdev));
 else:
  retdev.append(0);
 return retdev;

def PackCatFile(infiles, outfile, followlink=False, checksumtype="crc32", verbose=False, returnfp=False):
 if(outfile!="-" or not hasattr(outfile, "write")):
  outfile = RemoveWindowsPath(outfile);
 checksumtype = checksumtype.lower();
 if(checksumtype!="adler32" and checksumtype!="crc32" and checksumtype!="md5" and checksumtype!="sha1" and checksumtype!="sha224" and checksumtype!="sha256" and checksumtype!="sha384" and checksumtype!="sha512"):
  checksumtype="crc32"
 if(verbose is True):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(os.path.exists(outfile)):
  os.unlink(outfile);
 if(outfile=="-"):
  catfp = BytesIO();
 elif(hasattr(outfile, "write")):
  catfp = outfile;
 else:
  catfp = open(outfile, "wb");
 catver = str(__version_info__[0]) + str(__version_info__[1]) + str(__version_info__[2]);
 fileheaderver = str(int(catver.replace(".", "")));
 fileheader = AppendNullByte("CatFile" + fileheaderver);
 catfp.write(fileheader.encode());
 GetDirList = ListDir(infiles);
 for curfname in GetDirList:
  fname = curfname;
  if(verbose is True):
   logging.info(fname);
  if(followlink is False or followlink is None):
   fstatinfo = os.lstat(fname);
  else:
   fstatinfo = os.stat(fname);
  fpremode = fstatinfo.st_mode;
  ftype = 0;
  if(stat.S_ISREG(fpremode)):
   ftype = 0;
  if(stat.S_ISLNK(fpremode)):
   ftype = 2;
  if(stat.S_ISCHR(fpremode)):
   ftype = 3;
  if(stat.S_ISBLK(fpremode)):
   ftype = 4;
  if(stat.S_ISDIR(fpremode)):
   ftype = 5;
  if(stat.S_ISFIFO(fpremode)):
   ftype = 6;
  fdev = fstatinfo.st_dev;
  getfdev = GetDevMajorMinor(fdev);
  fdev_minor = getfdev[0];
  fdev_major = getfdev[1];
  try:
   frdev = fstatinfo.st_rdev;
  except AttributeError:
   frdev = fstatinfo.st_dev;
  getfrdev = GetDevMajorMinor(frdev);
  frdev_minor = getfrdev[0];
  frdev_major = getfrdev[1];
  if(ftype==1 or ftype==2 or ftype==3 or ftype==4 or ftype==5 or ftype==6):
   fsize = format(int("0"), 'x').upper();
  if(ftype==0):
   fsize = format(int(fstatinfo.st_size), 'x').upper();
  flinkname = "";
  if(ftype==1 or ftype==2):
   flinkname = os.readlink(fname);
  fatime = format(int(fstatinfo.st_atime), 'x').upper();
  fmtime = format(int(fstatinfo.st_mtime), 'x').upper();
  fmode = format(int(fstatinfo.st_mode), 'x').upper();
  fuid = format(int(fstatinfo.st_uid), 'x').upper();
  fgid = format(int(fstatinfo.st_gid), 'x').upper();
  fdev_minor = format(int(fdev_minor), 'x').upper();
  fdev_major = format(int(fdev_major), 'x').upper();
  frdev_minor = format(int(frdev_minor), 'x').upper();
  frdev_major = format(int(frdev_major), 'x').upper();
  fcontents = "".encode();
  if(ftype==0):
   fpc = open(fname, "rb");
   fcontents = fpc.read(int(fstatinfo.st_size));
   fpc.close();
  if(followlink is True and (ftype==1 or ftype==2)):
   flstatinfo = os.stat(flinkname);
   fpc = open(flinkname, "rb");
   fcontents = fpc.read(int(flstatinfo.st_size));
   fpc.close();
  ftypehex = format(ftype, 'x').upper();
  ftypeoutstr = ftypehex;
  catfileoutstr = AppendNullByte(ftypeoutstr);
  catfileoutstr = catfileoutstr + AppendNullByte(fname);
  catfileoutstr = catfileoutstr + AppendNullByte(flinkname);
  catfileoutstr = catfileoutstr + AppendNullByte(fsize);
  catfileoutstr = catfileoutstr + AppendNullByte(fatime);
  catfileoutstr = catfileoutstr + AppendNullByte(fmtime);
  catfileoutstr = catfileoutstr + AppendNullByte(fmode);
  catfileoutstr = catfileoutstr + AppendNullByte(fuid);
  catfileoutstr = catfileoutstr + AppendNullByte(fgid);
  catfileoutstr = catfileoutstr + AppendNullByte(fdev_minor);
  catfileoutstr = catfileoutstr + AppendNullByte(fdev_major);
  catfileoutstr = catfileoutstr + AppendNullByte(frdev_minor);
  catfileoutstr = catfileoutstr + AppendNullByte(frdev_major);
  catfileoutstr = catfileoutstr + AppendNullByte(checksumtype);
  if(checksumtype=="adler32"):
   catfileheadercshex = format(zlib.adler32(catfileoutstr.encode()) & 0xffffffff, 'x').upper();
   catfilecontentcshex = format(zlib.adler32(fcontents) & 0xffffffff, 'x').upper();
  if(checksumtype=="crc32"):
   catfileheadercshex = format(zlib.crc32(catfileoutstr.encode()) & 0xffffffff, 'x').upper();
   catfilecontentcshex = format(zlib.crc32(fcontents) & 0xffffffff, 'x').upper();
  if(checksumtype=="md5" or checksumtype=="sha1" or checksumtype=="sha224" or checksumtype=="sha256" or checksumtype=="sha384" or checksumtype=="sha512"):
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(catfileoutstr.encode());
   catfileheadercshex = checksumoutstr.hexdigest().upper();
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(fcontents);
   catfilecontentcshex = checksumoutstr.hexdigest().upper();
  catfileoutstr = catfileoutstr + AppendNullByte(catfileheadercshex);
  catfileoutstr = catfileoutstr + AppendNullByte(catfilecontentcshex);
  catfileoutstrecd = catfileoutstr.encode();
  nullstrecd = "\0".encode();
  catfileout = catfileoutstrecd + fcontents + nullstrecd;
  catfp.write(catfileout);
 if(outfile=="-" or returnfp is True):
  catfp.seek(0, 0);
  return catfp;
 else:
  catfp.close();
  CompressCatFile(outfile);
  return True;

if(tarsupport is True):
 def PackCatFileFromTarFile(infile, outfile, checksumtype="crc32", verbose=False, returnfp=False):
  infile = RemoveWindowsPath(infile);
  if(outfile!="-" or not hasattr(outfile, "write")):
   outfile = RemoveWindowsPath(outfile);
  checksumtype = checksumtype.lower();
  if(checksumtype!="adler32" and checksumtype!="crc32" and checksumtype!="md5" and checksumtype!="sha1" and checksumtype!="sha224" and checksumtype!="sha256" and checksumtype!="sha384" and checksumtype!="sha512"):
   checksumtype="crc32"
  tarinput = tarfile.open(infile, "r:*");
  tarfiles = tarinput.getmembers();
  if(verbose is True):
   logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
  if(os.path.exists(outfile)):
   os.unlink(outfile);
  if(outfile=="-"):
   catfp = BytesIO();
  elif(hasattr(outfile, "write")):
   catfp = outfile;
  else:
   catfp = open(outfile, "wb");
  catver = str(__version_info__[0]) + str(__version_info__[1]) + str(__version_info__[2]);
  fileheaderver = str(int(catver.replace(".", "")));
  fileheader = AppendNullByte("CatFile" + fileheaderver);
  catfp.write(fileheader.encode());
  for curfname in tarfiles:
   fname = curfname.name;
   if(verbose is True):
    logging.info(fname);
   ftype = 0;
   if(curfname.isfile()):
    ftype = 0;
   if(curfname.islnk()):
    ftype = 1;
   if(curfname.issym()):
    ftype = 2;
   if(curfname.ischr() and curfname.isdev()):
    ftype = 3;
   if(curfname.isblk() and curfname.isdev()):
    ftype = 4;
   if(curfname.isdir()):
    ftype = 5;
   if(curfname.isfifo() and curfname.isdev()):
    ftype = 6;
   if(ftype==1 or ftype==2 or ftype==3 or ftype==4 or ftype==5 or ftype==6):
    fsize = format(int("0"), 'x').upper();
   if(ftype==0):
    fsize = format(int(curfname.size), 'x').upper();
   flinkname = "";
   if(ftype==1 or ftype==2):
    flinkname = curfname.linkname;
   fatime = format(int(curfname.mtime), 'x').upper();
   fmtime = format(int(curfname.mtime), 'x').upper();
   fmode = format(int(curfname.mode), 'x').upper();
   fuid = format(int(curfname.uid), 'x').upper();
   fgid = format(int(curfname.gid), 'x').upper();
   fdev_minor = format(int(curfname.devminor), 'x').upper();
   fdev_major = format(int(curfname.devmajor), 'x').upper();
   frdev_minor = format(int(curfname.devminor), 'x').upper();
   frdev_major = format(int(curfname.devmajor), 'x').upper();
   fcontents = "".encode();
   if(ftype==0):
    fpc = tarinput.extractfile(curfname);
    fcontents = fpc.read(int(curfname.size));
    fpc.close();
   ftypehex = format(ftype, 'x').upper();
   ftypeoutstr = ftypehex;
   catfileoutstr = AppendNullByte(ftypeoutstr);
   catfileoutstr = catfileoutstr + AppendNullByte(fname);
   catfileoutstr = catfileoutstr + AppendNullByte(flinkname);
   catfileoutstr = catfileoutstr + AppendNullByte(fsize);
   catfileoutstr = catfileoutstr + AppendNullByte(fatime);
   catfileoutstr = catfileoutstr + AppendNullByte(fmtime);
   catfileoutstr = catfileoutstr + AppendNullByte(fmode);
   catfileoutstr = catfileoutstr + AppendNullByte(fuid);
   catfileoutstr = catfileoutstr + AppendNullByte(fgid);
   catfileoutstr = catfileoutstr + AppendNullByte(fdev_minor);
   catfileoutstr = catfileoutstr + AppendNullByte(fdev_major);
   catfileoutstr = catfileoutstr + AppendNullByte(frdev_minor);
   catfileoutstr = catfileoutstr + AppendNullByte(frdev_major);
   catfileoutstr = catfileoutstr + AppendNullByte(checksumtype);
   if(checksumtype=="adler32"):
    catfileheadercshex = format(zlib.adler32(catfileoutstr.encode()) & 0xffffffff, 'x').upper();
    catfilecontentcshex = format(zlib.adler32(fcontents) & 0xffffffff, 'x').upper();
   if(checksumtype=="crc32"):
    catfileheadercshex = format(zlib.crc32(catfileoutstr.encode()) & 0xffffffff, 'x').upper();
    catfilecontentcshex = format(zlib.crc32(fcontents) & 0xffffffff, 'x').upper();
   if(checksumtype=="md5" or checksumtype=="sha1" or checksumtype=="sha224" or checksumtype=="sha256" or checksumtype=="sha384" or checksumtype=="sha512"):
    checksumoutstr = hashlib.new(checksumtype);
    checksumoutstr.update(catfileoutstr.encode());
    catfileheadercshex = checksumoutstr.hexdigest().upper();
    checksumoutstr = hashlib.new(checksumtype);
    checksumoutstr.update(fcontents);
    catfilecontentcshex = checksumoutstr.hexdigest().upper();
   catfileoutstr = catfileoutstr + AppendNullByte(catfileheadercshex);
   catfileoutstr = catfileoutstr + AppendNullByte(catfilecontentcshex);
   catfileoutstrecd = catfileoutstr.encode();
   nullstrecd = "\0".encode();
   catfileout = catfileoutstrecd + fcontents + nullstrecd;
   catfp.write(catfileout);
  if(outfile=="-" or returnfp is False):
   tarinput.close();
   catfp.seek(0, 0);
   return catfp;
  else:
   catfp.close();
   tarinput.close();
   CompressCatFile(outfile);
   return True;

def CatFileToArray(infile, seekstart=0, seekend=0, listonly=False, skipchecksum=False):
 if(hasattr(infile, "read")):
  catfp = infile;
  catfp.seek(0, 0);
 else:
  infile = RemoveWindowsPath(infile);
  compresscheck = CheckFileType(infile);
  if(compresscheck is False):
   fextname = os.path.splitext(infile)[1];
   if(fextname==".gz" or fextname==".cgz"):
    compresscheck = "gzip";
   if(fextname==".bz2" or fextname==".cbz"):
    compresscheck = "bzip2";
   if(fextname==".lzma" or fextname==".xz" or fextname==".cxz"):
    compresscheck = "lzma";
  if(compresscheck is False):
   return False;
  if(compresscheck=="gzip"):
   try:
    import gzip;
   except ImportError:
    return False;
   catfp = gzip.open(infile, "rb");
  if(compresscheck=="bzip2"):
   try:
    import bz2;
   except ImportError:
    return False;
   catfp = bz2.BZ2File(infile, "rb");
  if(compresscheck=="lzma"):
   try:
    import lzma;
   except ImportError:
    return False;
   catfp = lzma.open(infile, "rb");
  if(compresscheck=="catfile"):
   catfp = open(infile, "rb");
 catfp.seek(0, 2);
 CatSize = catfp.tell();
 CatSizeEnd = CatSize;
 catfp.seek(0, 0);
 catstring = ReadFileHeaderData(catfp, 1)[0];
 catversion = int(re.findall("([\d]+)$", catstring)[0], 16);
 catlist = {};
 fileidnum = 0;
 if(seekstart!=0):
  catfp.seek(seekstart, 0);
 if(seekstart==0):
  seekstart = catfp.tell();
 if(seekend==0):
  seekend = CatSizeEnd;
 while(seekstart<seekend):
  catfhstart = catfp.tell();
  catheaderdata = ReadFileHeaderData(catfp, 16);
  catftype = int(catheaderdata[0], 16);
  catfname = catheaderdata[1];
  catflinkname = catheaderdata[2];
  catfsize = int(catheaderdata[3], 16);
  catfatime = int(catheaderdata[4], 16);
  catfmtime = int(catheaderdata[5], 16);
  catfmode = oct(int(catheaderdata[6], 16));
  catprefchmod = oct(int(catfmode[-3:], 8));
  catfchmod = catprefchmod;
  catfuid = int(catheaderdata[7], 16);
  catfgid = int(catheaderdata[8], 16);
  catfdev_minor = int(catheaderdata[9], 16);
  catfdev_major = int(catheaderdata[10], 16);
  catfrdev_minor = int(catheaderdata[11], 16);
  catfrdev_major = int(catheaderdata[12], 16);
  catfchecksumtype = catheaderdata[13].lower();
  if(catfchecksumtype=="adler32" or catfchecksumtype=="crc32"):
   catfcs = int(catheaderdata[14], 16);
   catfccs = int(catheaderdata[15], 16);
  if(catfchecksumtype=="md5" or catfchecksumtype=="sha1" or catfchecksumtype=="sha224" or catfchecksumtype=="sha256" or catfchecksumtype=="sha384" or catfchecksumtype=="sha512"):
   catfcs = catheaderdata[14];
   catfccs = catheaderdata[15];
  hc = 0;
  hcmax = len(catheaderdata) - 2;
  hout = "";
  while(hc<hcmax):
   hout = hout + AppendNullByte(catheaderdata[hc]);
   hc = hc + 1;
  if(catfchecksumtype=="adler32"):
   catnewfcs = zlib.adler32(hout.encode()) & 0xffffffff;
  if(catfchecksumtype=="crc32"):
   catnewfcs = zlib.crc32(hout.encode()) & 0xffffffff;
  if(catfchecksumtype=="md5" or catfchecksumtype=="sha1" or catfchecksumtype=="sha224" or catfchecksumtype=="sha256" or catfchecksumtype=="sha384" or catfchecksumtype=="sha512"):
   checksumoutstr = hashlib.new(catfchecksumtype);
   checksumoutstr.update(hout.encode());
   catnewfcs = checksumoutstr.hexdigest().upper();
  if(catfcs!=catnewfcs and skipchecksum is False):
   logging.info("File Header Checksum Error with file " + catfname + " at offset " + str(catfhstart));
   return False;
  catfhend = catfp.tell() - 1;
  catfcontentstart = catfp.tell();
  catfcontents = "";
  pyhascontents = False;
  if(catfsize>1 and listonly is False):
   catfcontents = catfp.read(catfsize);
   if(catfchecksumtype=="adler32"):
    catnewfccs = zlib.adler32(catfcontents) & 0xffffffff;
   if(catfchecksumtype=="crc32"):
    catnewfccs = zlib.crc32(catfcontents) & 0xffffffff;
   if(catfchecksumtype=="md5" or catfchecksumtype=="sha1" or catfchecksumtype=="sha224" or catfchecksumtype=="sha256" or catfchecksumtype=="sha384" or catfchecksumtype=="sha512"):
    checksumoutstr = hashlib.new(catfchecksumtype);
    checksumoutstr.update(catfcontents);
    catnewfccs = checksumoutstr.hexdigest().upper();
   pyhascontents = True;
   if(catfccs!=catnewfccs and skipchecksum is True):
    logging.info("File Content Checksum Error with file " + catfname + " at offset " + str(catfcontentstart));
    return False;
  if(catfsize>1 and listonly is True):
   catfp.seek(catfsize, 1);
   pyhascontents = False;
  catfcontentend = catfp.tell();
  catlist.update({fileidnum: {'catfileversion': catversion, 'fid': fileidnum, 'fhstart': catfhstart, 'fhend': catfhend, 'ftype': catftype, 'fname': catfname, 'flinkname': catflinkname, 'fsize': catfsize, 'fatime': catfatime, 'fmtime': catfmtime, 'fmode': catfmode, 'fchmod': catfchmod, 'fuid': catfuid, 'fgid': catfgid, 'fminor': catfdev_minor, 'fmajor': catfdev_major, 'frminor': catfrdev_minor, 'frmajor': catfrdev_major, 'fchecksumtype': catfchecksumtype, 'fheaderchecksum': catfcs, 'fcontentchecksum': catfccs, 'fhascontents': pyhascontents, 'fcontentstart': catfcontentstart, 'fcontentend': catfcontentend, 'fcontents': catfcontents} });
  catfp.seek(1, 1);
  seekstart = catfp.tell();
  fileidnum = fileidnum + 1;
 catfp.close();
 return catlist;

def CatFileToArrayIndex(infile, seekstart=0, seekend=0, listonly=False, skipchecksum=False):
 if(isinstance(infile, dict)):
  listcatfiles = infile;
 else:
  if(not hasattr(infile, "read")):
   infile = RemoveWindowsPath(infile);
  listcatfiles = CatFileToArray(infile, seekstart, seekend, listonly, skipchecksum);
 if(listcatfiles is False):
  return False;
 catarray = {'list': listcatfiles, 'filetoid': {}, 'idtofile': {}, 'filetypes': {'directories': {'filetoid': {}, 'idtofile': {}}, 'files': {'filetoid': {}, 'idtofile': {}}, 'links': {'filetoid': {}, 'idtofile': {}}, 'symlinks': {'filetoid': {}, 'idtofile': {}}, 'hardlinks': {'filetoid': {}, 'idtofile': {}}, 'character': {'filetoid': {}, 'idtofile': {}}, 'block': {'filetoid': {}, 'idtofile': {}}, 'fifo': {'filetoid': {}, 'idtofile': {}}, 'devices': {'filetoid': {}, 'idtofile': {}}}};
 lcfi = 0;
 lcfx = len(listcatfiles);
 while(lcfi < lcfx):
  filetoidarray = {listcatfiles[lcfi]['fname']: listcatfiles[lcfi]['fid']};
  idtofilearray = {listcatfiles[lcfi]['fid']: listcatfiles[lcfi]['fname']};
  catarray['filetoid'].update(filetoidarray);
  catarray['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==0):
   catarray['filetypes']['files']['filetoid'].update(filetoidarray);
   catarray['filetypes']['files']['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==1):
   catarray['filetypes']['hardlinks']['filetoid'].update(filetoidarray);
   catarray['filetypes']['hardlinks']['idtofile'].update(idtofilearray);
   catarray['filetypes']['links']['filetoid'].update(filetoidarray);
   catarray['filetypes']['links']['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==2):
   catarray['filetypes']['symlinks']['filetoid'].update(filetoidarray);
   catarray['filetypes']['symlinks']['idtofile'].update(idtofilearray);
   catarray['filetypes']['links']['filetoid'].update(filetoidarray);
   catarray['filetypes']['links']['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==3):
   catarray['filetypes']['character']['filetoid'].update(filetoidarray);
   catarray['filetypes']['character']['idtofile'].update(idtofilearray);
   catarray['filetypes']['devices']['filetoid'].update(filetoidarray);
   catarray['filetypes']['devices']['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==4):
   catarray['filetypes']['block']['filetoid'].update(filetoidarray);
   catarray['filetypes']['block']['idtofile'].update(idtofilearray);
   catarray['filetypes']['devices']['filetoid'].update(filetoidarray);
   catarray['filetypes']['devices']['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==5):
   catarray['filetypes']['directories']['filetoid'].update(filetoidarray);
   catarray['filetypes']['directories']['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==6):
   catarray['filetypes']['symlinks']['filetoid'].update(filetoidarray);
   catarray['filetypes']['symlinks']['idtofile'].update(idtofilearray);
   catarray['filetypes']['devices']['filetoid'].update(filetoidarray);
   catarray['filetypes']['devices']['idtofile'].update(idtofilearray);
  lcfi = lcfi + 1;
 return catarray;

def RePackCatFile(infile, outfile, seekstart=0, seekend=0, checksumtype="crc32", skipchecksum=False, verbose=False, returnfp=False):
 if(isinstance(infile, dict)):
  listcatfiles = infile;
 else:
  if(not hasattr(infile, "read")):
   infile = RemoveWindowsPath(infile);
  listcatfiles = CatFileToArray(infile, seekstart, seekend, False, skipchecksum);
 if(outfile!="-" or not hasattr(outfile, "write")):
  outfile = RemoveWindowsPath(outfile);
 checksumtype = checksumtype.lower();
 if(checksumtype!="adler32" and checksumtype!="crc32" and checksumtype!="md5" and checksumtype!="sha1" and checksumtype!="sha224" and checksumtype!="sha256" and checksumtype!="sha384" and checksumtype!="sha512"):
  checksumtype="crc32"
 if(verbose is True):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(listcatfiles is False):
  return False;
 if(outfile=="-"):
  catfp = BytesIO();
 elif(hasattr(outfile, "write")):
  catfp = outfile;
 else:
  catfp = open(outfile, "wb");
 catver = str(__version_info__[0]) + str(__version_info__[1]) + str(__version_info__[2]);
 fileheaderver = str(int(catver.replace(".", "")));
 fileheader = AppendNullByte("CatFile" + fileheaderver);
 catfp.write(fileheader.encode());
 lcfi = 0;
 lcfx = len(listcatfiles);
 while(lcfi < lcfx):
  fname = listcatfiles[lcfi]['fname'];
  if(verbose is True):
   logging.info(fname);
  fsize = format(int(listcatfiles[lcfi]['fsize']), 'x').upper();
  flinkname = listcatfiles[lcfi]['flinkname'];
  fatime = format(int(listcatfiles[lcfi]['fatime']), 'x').upper();
  fmtime = format(int(listcatfiles[lcfi]['fmtime']), 'x').upper();
  fmode = format(int(int(listcatfiles[lcfi]['fmode'], 8)), 'x').upper();
  fuid = format(int(listcatfiles[lcfi]['fuid']), 'x').upper();
  fgid = format(int(listcatfiles[lcfi]['fgid']), 'x').upper();
  fdev_minor = format(int(listcatfiles[lcfi]['fminor']), 'x').upper();
  fdev_major = format(int(listcatfiles[lcfi]['fmajor']), 'x').upper();
  frdev_minor = format(int(listcatfiles[lcfi]['frminor']), 'x').upper();
  frdev_major = format(int(listcatfiles[lcfi]['frmajor']), 'x').upper();
  fcontents = listcatfiles[lcfi]['fcontents'];
  if(listcatfiles[lcfi]['ftype']!=0):
   fcontents = fcontents.encode();
  ftypehex = format(listcatfiles[lcfi]['ftype'], 'x').upper();
  ftypeoutstr = ftypehex;
  catfileoutstr = AppendNullByte(ftypeoutstr);
  catfileoutstr = catfileoutstr + AppendNullByte(fname);
  catfileoutstr = catfileoutstr + AppendNullByte(flinkname);
  catfileoutstr = catfileoutstr + AppendNullByte(fsize);
  catfileoutstr = catfileoutstr + AppendNullByte(fatime);
  catfileoutstr = catfileoutstr + AppendNullByte(fmtime);
  catfileoutstr = catfileoutstr + AppendNullByte(fmode);
  catfileoutstr = catfileoutstr + AppendNullByte(fuid);
  catfileoutstr = catfileoutstr + AppendNullByte(fgid);
  catfileoutstr = catfileoutstr + AppendNullByte(fdev_minor);
  catfileoutstr = catfileoutstr + AppendNullByte(fdev_major);
  catfileoutstr = catfileoutstr + AppendNullByte(frdev_minor);
  catfileoutstr = catfileoutstr + AppendNullByte(frdev_major);
  catfileoutstr = catfileoutstr + AppendNullByte(checksumtype);
  if(checksumtype=="adler32"):
   catfileheadercshex = format(zlib.adler32(catfileoutstr.encode()) & 0xffffffff, 'x').upper();
   catfilecontentcshex = format(zlib.adler32(fcontents) & 0xffffffff, 'x').upper();
  if(checksumtype=="crc32"):
   catfileheadercshex = format(zlib.crc32(catfileoutstr.encode()) & 0xffffffff, 'x').upper();
   catfilecontentcshex = format(zlib.crc32(fcontents) & 0xffffffff, 'x').upper();
  if(checksumtype=="md5" or checksumtype=="sha1" or checksumtype=="sha224" or checksumtype=="sha256" or checksumtype=="sha384" or checksumtype=="sha512"):
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(catfileoutstr.encode());
   catfileheadercshex = checksumoutstr.hexdigest().upper();
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(fcontents);
   catfilecontentcshex = checksumoutstr.hexdigest().upper();
  catfileoutstr = catfileoutstr + AppendNullByte(catfileheadercshex);
  catfileoutstr = catfileoutstr + AppendNullByte(catfilecontentcshex);
  catfileoutstrecd = catfileoutstr.encode();
  nullstrecd = "\0".encode();
  catfileout = catfileoutstrecd + fcontents + nullstrecd;
  catfp.write(catfileout);
  lcfi = lcfi + 1;
 if(outfile=="-" or returnfp is True):
  catfp.seek(0, 0);
  return catfp;
 else:
  catfp.close();
  CompressCatFile(outfile);
  return True;
 return True;

def UnPackCatFile(infile, outdir=None, verbose=False, skipchecksum=False):
 if(outdir is not None):
  outdir = RemoveWindowsPath(outdir);
 if(verbose is True):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(isinstance(infile, dict)):
  listcatfiles = infile;
 else:
  if(not hasattr(infile, "read")):
   infile = RemoveWindowsPath(infile);
  listcatfiles = CatFileToArray(infile, 0, 0, False, skipchecksum);
 if(listcatfiles is False):
  return False;
 lcfi = 0;
 lcfx = len(listcatfiles);
 while(lcfi < lcfx):
  if(verbose is True):
   logging.info(listcatfiles[lcfi]['fname']);
  if(listcatfiles[lcfi]['ftype']==0):
   fpc = open(listcatfiles[lcfi]['fname'], "wb");
   fpc.write(listcatfiles[lcfi]['fcontents']);
   fpc.close();
   if(hasattr(os, "chown")):
    os.chown(listcatfiles[lcfi]['fname'], listcatfiles[lcfi]['fuid'], listcatfiles[lcfi]['fgid']);
   os.chmod(listcatfiles[lcfi]['fname'], int(listcatfiles[lcfi]['fchmod'], 8));
   os.utime(listcatfiles[lcfi]['fname'], (listcatfiles[lcfi]['fatime'], listcatfiles[lcfi]['fmtime']));
  if(listcatfiles[lcfi]['ftype']==1):
   os.link(listcatfiles[lcfi]['flinkname'], listcatfiles[lcfi]['fname']);
  if(listcatfiles[lcfi]['ftype']==2):
   os.symlink(listcatfiles[lcfi]['flinkname'], listcatfiles[lcfi]['fname']);
  if(listcatfiles[lcfi]['ftype']==5):
   os.mkdir(listcatfiles[lcfi]['fname'], int(listcatfiles[lcfi]['fchmod'], 8));
   if(hasattr(os, "chown")):
    os.chown(listcatfiles[lcfi]['fname'], listcatfiles[lcfi]['fuid'], listcatfiles[lcfi]['fgid']);
   os.chmod(listcatfiles[lcfi]['fname'], int(listcatfiles[lcfi]['fchmod'], 8));
   os.utime(listcatfiles[lcfi]['fname'], (listcatfiles[lcfi]['fatime'], listcatfiles[lcfi]['fmtime']));
  if(listcatfiles[lcfi]['ftype']==6 and hasattr(os, "mkfifo")):
   os.mkfifo(listcatfiles[lcfi]['fname'], int(listcatfiles[lcfi]['fchmod'], 8));
  lcfi = lcfi + 1;
 return True;

def CatFileListFiles(infile, seekstart=0, seekend=0, verbose=False, skipchecksum=False):
 import datetime;
 logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(isinstance(infile, dict)):
  listcatfiles = infile;
 else:
  if(not hasattr(infile, "read")):
   infile = RemoveWindowsPath(infile);
  listcatfiles = CatFileToArray(infile, seekstart, seekend, True, skipchecksum);
 if(listcatfiles is False):
  return False;
 lcfi = 0;
 lcfx = len(listcatfiles);
 returnval = {};
 while(lcfi < lcfx):
  returnval.update({lcfi: listcatfiles[lcfi]['fname']});
  if(verbose is False):
   logging.info(listcatfiles[lcfi]['fname']);
  if(verbose is True):
   permissions = { 'access': { '0': ('---'), '1': ('--x'), '2': ('-w-'), '3': ('-wx'), '4': ('r--'), '5': ('r-x'), '6': ('rw-'), '7': ('rwx') }, 'roles': { 0: 'owner', 1: 'group', 2: 'other' } };
   permissionstr = "";
   for fmodval in str(listcatfiles[lcfi]['fchmod'])[-3:]:
    try:
     permissionstr = permissionstr + permissions['access'][fmodval];
    except KeyError:
     permissionstr = permissionstr + "---";
   if(listcatfiles[lcfi]['ftype']==0):
    permissionstr = "-" + permissionstr;
   if(listcatfiles[lcfi]['ftype']==1):
    permissionstr = "h" + permissionstr;
   if(listcatfiles[lcfi]['ftype']==2):
    permissionstr = "l" + permissionstr;
   if(listcatfiles[lcfi]['ftype']==3):
    permissionstr = "c" + permissionstr;
   if(listcatfiles[lcfi]['ftype']==4):
    permissionstr = "b" + permissionstr;
   if(listcatfiles[lcfi]['ftype']==5):
    permissionstr = "d" + permissionstr;
   if(listcatfiles[lcfi]['ftype']==6):
    permissionstr = "f" + permissionstr;
   printfname = listcatfiles[lcfi]['fname'];
   if(listcatfiles[lcfi]['ftype']==1):
    printfname = listcatfiles[lcfi]['fname'] + " link to " + listcatfiles[lcfi]['flinkname'];
   if(listcatfiles[lcfi]['ftype']==2):
    printfname = listcatfiles[lcfi]['fname'] + " -> " + listcatfiles[lcfi]['flinkname'];
   logging.info(permissionstr + " " + str(str(listcatfiles[lcfi]['fuid']) + "/" + str(listcatfiles[lcfi]['fgid']) + " " + str(listcatfiles[lcfi]['fsize']).rjust(15) + " " + datetime.datetime.utcfromtimestamp(listcatfiles[lcfi]['fmtime']).strftime('%Y-%m-%d %H:%M') + " " + printfname));
  lcfi = lcfi + 1;
 return returnval;

if __name__ == '__main__':
 should_extract = False;
 should_create = True;
 should_list = False;
 if(getargs.extract is False and getargs.create is True and getargs.list is False):
  should_create = True;
  should_extract = False;
  should_list = False;
 if(getargs.extract is True and getargs.create is False and getargs.list is False):
  should_create = False;
  should_extract = True;
  should_list = False;
 if(getargs.extract is True and getargs.create is True and getargs.list is False):
  should_create = True;
  should_extract = False;
  should_list = False;
 if(getargs.extract is False and getargs.create is False and getargs.list is False):
  should_create = True;
  should_extract = False;
  should_list = False;
 if(getargs.extract is False and getargs.create is True and getargs.list is True):
  should_create = True;
  should_extract = False;
  should_list = False;
 if(getargs.extract is True and getargs.create is False and getargs.list is True):
  should_create = False;
  should_extract = True;
  should_list = False;
 if(getargs.extract is True and getargs.create is True and getargs.list is True):
  should_create = True;
  should_extract = False;
  should_list = False;
 if(getargs.extract is False and getargs.create is False and getargs.list is True):
  should_create = False;
  should_extract = False;
  should_list = True;
 should_convert = False;
 if(should_create is True and getargs.tar is True):
  should_convert = True;
 if(tarsupport is False and should_convert is True):
  should_convert = False;
 should_repack = False;
 if(should_create is True and getargs.tar is False and getargs.repack is True):
  should_repack = True;
 if(should_create is True and should_extract is False and should_list is False and should_repack is False and should_convert is False):
  PackCatFile(getargs.input, getargs.output, False, getargs.checksum, getargs.verbose, False);
 if(should_create is True and should_extract is False and should_list is False and should_repack is False and should_convert is True):
  PackCatFileFromTarFile(getargs.input, getargs.output, getargs.checksum, getargs.verbose, );
 if(should_create is True and should_extract is False and should_list is False and should_repack is True and should_convert is False):
  RePackCatFile(getargs.input, getargs.output, 0, 0, getargs.checksum, False, getargs.verbose, False);
 if(should_create is False and should_extract is True and should_list is False):
  UnPackCatFile(getargs.input, getargs.output, getargs.verbose, False);
 if(should_create is False and should_extract is False and should_list is True):
  CatFileListFiles(getargs.input, 0, 0, getargs.verbose, False);
