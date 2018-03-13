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

    $FileInfo: pycatfile.py - Last Update: 3/10/2018 Ver. 0.0.1 RC 1 - Author: cooldude2k $
'''

from __future__ import absolute_import, division, print_function, unicode_literals;
import os, re, sys, stat, zlib, shutil, hashlib, logging, binascii, tempfile;

if(sys.version[0]=="2"):
 from io import open as open;

teststringio = 0;
if(teststringio<=0):
 try:
  from cStringIO import StringIO as BytesIO;
  teststringio = 1;
 except ImportError:
  teststringio = 0;
if(teststringio<=0):
 try:
  from StringIO import StringIO as BytesIO;
  teststringio = 2;
 except ImportError:
  teststringio = 0;
if(teststringio<=0):
 try:
  from io import BytesIO;
  teststringio = 3;
 except ImportError:
  teststringio = 0;

tarsupport = False;
try:
 import tarfile;
 tarsupport = True;
except ImportError:
 tarsupport = False;

__program_name__ = "PyCatFile";
__project__ = __program_name__;
__project_url__ = "https://github.com/GameMaker2k/PyCatFile";
__version_info__ = (0, 0, 1, "RC 1", 1);
__version_date_info__ = (2018, 3, 10, "RC 1", 1);
__version_date__ = str(__version_date_info__[0]) + "." + str(__version_date_info__[1]).zfill(2) + "." + str(__version_date_info__[2]).zfill(2);
if(__version_info__[4] is not None):
 __version_date_plusrc__ = __version_date__ + "-" + str(__version_date_info__[4]);
if(__version_info__[4] is None):
 __version_date_plusrc__ = __version_date__;
if(__version_info__[3] is not None):
 __version__ = str(__version_info__[0]) + "." + str(__version_info__[1]) + "." + str(__version_info__[2]) + " " + str(__version_info__[3]);
if(__version_info__[3] is None):
 __version__ = str(__version_info__[0]) + "." + str(__version_info__[1]) + "." + str(__version_info__[2]);

if __name__ == "__main__":
 import subprocess;
 curscrpath = os.path.dirname(sys.argv[0]);
 if(curscrpath==""):
  curscrpath = ".";
 if(os.sep=="\\"):
  curscrpath = curscrpath.replace(os.sep, "/");
 curscrpath = curscrpath+"/";
 scrfile = curscrpath+"catfile.py";
 if(os.path.exists(scrfile) and os.path.isfile(scrfile)):
  scrcmd = subprocess.Popen([sys.executable, scrfile] + sys.argv[1:]);
  scrcmd.wait();

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

def SeekToEndOfFile(fp):
 lasttell = 0;
 while(True):
  fp.seek(1, 1);
  if(lasttell==fp.tell()):
   break;
  lasttell = fp.tell();
 return True;

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

def CheckCompressionType(infile, closefp=True):
 if(hasattr(infile, "read") or hasattr(infile, "write")):
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
 catfp.seek(0, 0);
 if(closefp):
  catfp.close();
 return filetype;

def UncompressCatFile(fp):
 if(not hasattr(fp, "read") and not hasattr(fp, "write")):
  return False;
 compresscheck = CheckCompressionType(fp, False);
 if(compresscheck=="gzip"):
  try:
   import gzip;
  except ImportError:
   return False;
  catfp = gzip.GzipFile(fileobj=fp, mode="rb");
 if(compresscheck=="bzip2"):
  try:
   import bz2;
  except ImportError:
   return False;
  catfp = BytesIO();
  with fp as fpcontent:
   catfp.write(bz2.decompress(fp.read()));
 if(compresscheck=="lzma"):
  try:
   import lzma;
  except ImportError:
   return False;
  catfp = BytesIO();
  with fp as fpcontent:
   catfp.write(lzma.decompress(fp.read()));
 if(compresscheck=="catfile"):
  catfp = fp;
 if(not compresscheck):
  try:
   import lzma;
  except ImportError:
   return False;
  catfp = BytesIO();
  with fp as fpcontent:
   try:
    catfp.write(lzma.decompress(fp.read()));
   except lzma.LZMAError:
    return False;
 return catfp;
  
def CompressCatFile(fp, compression="auto"):
 if(compression=="gzip"):
  try:
   import gzip;
  except ImportError:
   return False;
  catfp = gzip.GzipFile(fileobj=fp, mode="wb", compresslevel=9);
 if(compression=="bzip2"):
  try:
   import bz2;
  except ImportError:
   return False;
  catfp = BytesIO();
  catfp.write(bz2.compress(fp.read(), compresslevel=9));
 if(compression=="lzma"):
  try:
   import lzma;
  except ImportError:
   return False;
  catfp = BytesIO();
  catfp.write(lzma.compress(fp.read(), format=lzma.FORMAT_ALONE, preset=9));
 if(compression=="xz"):
  try:
   import lzma;
  except ImportError:
   return False;
  catfp = BytesIO();
  catfp.write(lzma.compress(fp.read(), format=lzma.FORMAT_XZ, preset=9));
 if(compression=="auto"):
  catfp = fp;
 return catfp;

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

def CheckSumSupport(checkfor, checklist):
 if(checklist>5 or checklist<1):
  checklist = 1;
 if(checklist==1):
  checklist = sorted(['adler32']);
 if(checklist==2):
  checklist = sorted(['crc32']);
 if(checklist==3):
  checklist = sorted(['adler32', 'crc32']);
 if(checklist==4):
  checklist = sorted(list(hashlib.algorithms_guaranteed));
 if(checklist==5):
  checklist = sorted(list(hashlib.algorithms_guaranteed) + ['adler32', 'crc32']);
 if(checkfor in checklist):
  return True;
 else:
  return False;

def PackCatFile(infiles, outfile, compression="auto", followlink=False, checksumtype="crc32", verbose=False, returnfp=False):
 compressionlist = ['auto', 'gzip', 'bzip2', 'lzma', 'xz'];
 outextlist = ['gz', 'cgz', 'bz2', 'cbz', 'lzma', 'xz', 'cxz'];
 outextlistwd = ['.gz', '.cgz', '.bz2', '.cbz', '.lzma', '.xz', '.cxz'];
 if(outfile!="-" and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
  outfile = RemoveWindowsPath(outfile);
 checksumtype = checksumtype.lower();
 if(not CheckSumSupport(checksumtype, 5)):
  checksumtype="crc32";
 if(not compression in compressionlist):
  compression = "auto";
 if(verbose):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(outfile!="-" and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
  if(os.path.exists(outfile)):
   os.unlink(outfile);
 if(outfile=="-"):
  verbose = False;
  catfp = BytesIO();
 elif(hasattr(outfile, "read") or hasattr(outfile, "write")):
  catfp = outfile;
 else:
  fbasename = os.path.splitext(outfile)[0];
  fextname = os.path.splitext(outfile)[1];
  if(not fextname in outextlistwd):
   catfp = open(outfile, "wb");
  elif(((fextname==".gz" or fextname==".cgz") and compression=="auto") or compression=="gzip"):
   try:
    import gzip;
   except ImportError:
    return False;
   catfp = gzip.open(outfile, "wb", 9);
  elif(((fextname==".bz2" or fextname==".cbz") and compression=="auto") or compression=="bzip2"):
   try:
    import bz2;
   except ImportError:
    return False;
   catfp = bz2.BZ2File(outfile, "wb", 9);
  elif(((fextname==".xz" or fextname==".cxz") and compression=="auto") or compression=="xz"):
   try:
    import lzma;
   except ImportError:
    return False;
   catfp = lzma.open(outfile, "wb", format=lzma.FORMAT_XZ, preset=9);
  elif((fextname==".lzma" and compression=="auto") or compression=="lzma"):
   try:
    import lzma;
   except ImportError:
    return False;
   catfp = lzma.open(outfile, "wb", format=lzma.FORMAT_ALONE, preset=9);
 catver = str(__version_info__[0]) + str(__version_info__[1]) + str(__version_info__[2]);
 fileheaderver = str(int(catver.replace(".", "")));
 fileheader = AppendNullByte("CatFile" + fileheaderver);
 catfp.write(fileheader.encode());
 GetDirList = ListDir(infiles);
 for curfname in GetDirList:
  fname = curfname;
  if(verbose):
   logging.info(fname);
  if(not followlink or followlink is None):
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
  frdev = fstatinfo.st_dev;
  if(hasattr(fstatinfo, "st_rdev")):
   frdev = fstatinfo.st_rdev;
  else:
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
  funame = "";
  try:
   import pwd;
   userinfo = pwd.getpwuid(fstatinfo.st_uid);
   funame = userinfo.pw_name;
  except ImportError:
   funame = "";
  fgname = "";
  try:
   import grp;
   groupinfo = grp.getgrgid(fstatinfo.st_gid);
   fgname = groupinfo.gr_name;
  except ImportError:
   fgname = "";
  fdev_minor = format(int(fdev_minor), 'x').upper();
  fdev_major = format(int(fdev_major), 'x').upper();
  frdev_minor = format(int(frdev_minor), 'x').upper();
  frdev_major = format(int(frdev_major), 'x').upper();
  fcontents = "".encode();
  if(ftype==0):
   fpc = open(fname, "rb");
   fcontents = fpc.read(int(fstatinfo.st_size));
   fpc.close();
  if(followlink and (ftype==1 or ftype==2)):
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
  catfileoutstr = catfileoutstr + AppendNullByte(funame);
  catfileoutstr = catfileoutstr + AppendNullByte(fgid);
  catfileoutstr = catfileoutstr + AppendNullByte(fgname);
  catfileoutstr = catfileoutstr + AppendNullByte(fdev_minor);
  catfileoutstr = catfileoutstr + AppendNullByte(fdev_major);
  catfileoutstr = catfileoutstr + AppendNullByte(frdev_minor);
  catfileoutstr = catfileoutstr + AppendNullByte(frdev_major);
  catfileoutstr = catfileoutstr + AppendNullByte(checksumtype);
  if(CheckSumSupport(checksumtype, 1)):
   catfileheadercshex = format(zlib.adler32(catfileoutstr.encode()) & 0xffffffff, 'x').upper();
   catfilecontentcshex = format(zlib.adler32(fcontents) & 0xffffffff, 'x').upper();
  if(CheckSumSupport(checksumtype, 2)):
   catfileheadercshex = format(zlib.crc32(catfileoutstr.encode()) & 0xffffffff, 'x').upper();
   catfilecontentcshex = format(zlib.crc32(fcontents) & 0xffffffff, 'x').upper();
  if(CheckSumSupport(checksumtype, 4)):
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(catfileoutstr.encode());
   catfileheadercshex = checksumoutstr.hexdigest().upper();
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(fcontents);
   catfilecontentcshex = checksumoutstr.hexdigest().upper();
  catfileoutstr = catfileoutstr + AppendNullByte(catfileheadercshex);
  catfileoutstr = catfileoutstr + AppendNullByte(catfilecontentcshex);
  catfheadersizehex = format(int(len(catfileoutstr) - 1), 'x').upper();
  catfileoutstr = AppendNullByte(catfheadersizehex) + catfileoutstr;
  catfileoutstrecd = catfileoutstr.encode();
  nullstrecd = "\0".encode();
  catfileout = catfileoutstrecd + fcontents + nullstrecd;
  catfp.write(catfileout);
 if(outfile=="-" or hasattr(outfile, "read") or hasattr(outfile, "write")):
  catfp = CompressCatFile(catfp, compression);
 if(outfile=="-"):
  catfp.seek(0, 0);
  if(hasattr(sys.stdout, "buffer")):
   shutil.copyfileobj(catfp, sys.stdout.buffer);
  else:
   shutil.copyfileobj(catfp, sys.stdout);
 if(returnfp):
  catfp.seek(0, 0);
  return catfp;
 else:
  catfp.close();
  return True;

if(tarsupport):
 def PackCatFileFromTarFile(infile, outfile, compression="auto", checksumtype="crc32", verbose=False, returnfp=False):
  compressionlist = ['auto', 'gzip', 'bzip2', 'lzma', 'xz'];
  outextlist = ['gz', 'cgz', 'bz2', 'cbz', 'lzma', 'xz', 'cxz'];
  outextlistwd = ['.gz', '.cgz', '.bz2', '.cbz', '.lzma', '.xz', '.cxz'];
  if(outfile!="-" and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
   outfile = RemoveWindowsPath(outfile);
  checksumtype = checksumtype.lower();
  if(not CheckSumSupport(checksumtype, 5)):
   checksumtype="crc32";
  if(not compression in compressionlist):
   compression = "auto";
  if(hasattr(infile, "read") or hasattr(infile, "write")):
   tarinput = infile;
   tarinput.seek(0, 0);
   tarinput = tarfile.open(fileobj=tarinput, mode="r:*");
  elif(infile=="-"):
   verbose = False;
   tarinput = BytesIO();
   if(hasattr(sys.stdin, "buffer")):
    shutil.copyfileobj(sys.stdin.buffer, tarinput);
   else:
    shutil.copyfileobj(sys.stdin, tarinput);
   tarinput.seek(0, 0);
   tarinput = tarfile.open(fileobj=tarinput, mode="r:*");
  else:
   infile = RemoveWindowsPath(infile);
   tarinput = tarfile.open(infile, mode="r:*");
  tarfiles = tarinput.getmembers();
  if(verbose):
   logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
  if(outfile!="-" and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
   if(os.path.exists(outfile)):
    os.unlink(outfile);
  if(outfile=="-"):
   catfp = BytesIO();
  elif(hasattr(outfile, "read") or hasattr(outfile, "write")):
   catfp = outfile;
  else:
   fbasename = os.path.splitext(outfile)[0];
   fextname = os.path.splitext(outfile)[1];
   if(not fextname in outextlistwd):
    catfp = open(outfile, "wb");
   elif(((fextname==".gz" or fextname==".cgz") and compression=="auto") or compression=="gzip"):
    try:
     import gzip;
    except ImportError:
     return False;
    catfp = gzip.open(outfile, "wb", 9);
   elif(((fextname==".bz2" or fextname==".cbz") and compression=="auto") or compression=="bzip2"):
    try:
     import bz2;
    except ImportError:
     return False;
    catfp = bz2.BZ2File(outfile, "wb", 9);
   elif(((fextname==".xz" or fextname==".cxz") and compression=="auto") or compression=="xz"):
    try:
     import lzma;
    except ImportError:
     return False;
    catfp = lzma.open(outfile, "wb", format=lzma.FORMAT_XZ, preset=9);
   elif((fextname==".lzma" and compression=="auto") or compression=="lzma"):
    try:
     import lzma;
    except ImportError:
     return False;
    catfp = lzma.open(outfile, "wb", format=lzma.FORMAT_ALONE, preset=9);
  catver = str(__version_info__[0]) + str(__version_info__[1]) + str(__version_info__[2]);
  fileheaderver = str(int(catver.replace(".", "")));
  fileheader = AppendNullByte("CatFile" + fileheaderver);
  catfp.write(fileheader.encode());
  for curfname in tarfiles:
   fname = curfname.name;
   if(verbose):
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
   funame = curfname.uname;
   fgname = curfname.gname;
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
   catfileoutstr = catfileoutstr + AppendNullByte(funame);
   catfileoutstr = catfileoutstr + AppendNullByte(fgid);
   catfileoutstr = catfileoutstr + AppendNullByte(fgname);
   catfileoutstr = catfileoutstr + AppendNullByte(fdev_minor);
   catfileoutstr = catfileoutstr + AppendNullByte(fdev_major);
   catfileoutstr = catfileoutstr + AppendNullByte(frdev_minor);
   catfileoutstr = catfileoutstr + AppendNullByte(frdev_major);
   catfileoutstr = catfileoutstr + AppendNullByte(checksumtype);
   if(CheckSumSupport(checksumtype, 1)):
    catfileheadercshex = format(zlib.adler32(catfileoutstr.encode()) & 0xffffffff, 'x').upper();
    catfilecontentcshex = format(zlib.adler32(fcontents) & 0xffffffff, 'x').upper();
   if(CheckSumSupport(checksumtype, 2)):
    catfileheadercshex = format(zlib.crc32(catfileoutstr.encode()) & 0xffffffff, 'x').upper();
    catfilecontentcshex = format(zlib.crc32(fcontents) & 0xffffffff, 'x').upper();
   if(CheckSumSupport(checksumtype, 4)):
    checksumoutstr = hashlib.new(checksumtype);
    checksumoutstr.update(catfileoutstr.encode());
    catfileheadercshex = checksumoutstr.hexdigest().upper();
    checksumoutstr = hashlib.new(checksumtype);
    checksumoutstr.update(fcontents);
    catfilecontentcshex = checksumoutstr.hexdigest().upper();
   catfileoutstr = catfileoutstr + AppendNullByte(catfileheadercshex);
   catfileoutstr = catfileoutstr + AppendNullByte(catfilecontentcshex);
   catfheadersizehex = format(int(len(catfileoutstr) - 1), 'x').upper();
   catfileoutstr = AppendNullByte(catfheadersizehex) + catfileoutstr;
   catfileoutstrecd = catfileoutstr.encode();
   nullstrecd = "\0".encode();
   catfileout = catfileoutstrecd + fcontents + nullstrecd;
   catfp.write(catfileout);
  if(outfile=="-" or hasattr(outfile, "read") or hasattr(outfile, "write")):
   catfp = CompressCatFile(catfp, compression);
  if(outfile=="-"):
   catfp.seek(0, 0);
   if(hasattr(sys.stdout, "buffer")):
    shutil.copyfileobj(catfp, sys.stdout.buffer);
   else:
    shutil.copyfileobj(catfp, sys.stdout);
  if(returnfp):
   tarinput.close();
   catfp.seek(0, 0);
   return catfp;
  else:
   catfp.close();
   tarinput.close();
   return True;

if(tarsupport):
 def RePackCatFileFromString(tarstr, outfile, compression="auto", checksumtype="crc32", verbose=False, returnfp=False):
  catfp = BytesIO(tarstr);
  listcatfiles = PackCatFileFromTarFile(infile, outfile, compression, checksumtype, verbose, returnfp);
  return listcatfiles;

def CatFileToArray(infile, seekstart=0, seekend=0, listonly=False, skipchecksum=False, returnfp=False):
 if(hasattr(infile, "read") or hasattr(infile, "write")):
  catfp = infile;
  catfp.seek(0, 0);
  catfp = UncompressCatFile(catfp);
  if(not catfp):
   return False;
  catfp.seek(0, 0);
 elif(infile=="-"):
  catfp = BytesIO();
  if(hasattr(sys.stdin, "buffer")):
   shutil.copyfileobj(sys.stdin.buffer, catfp);
  else:
   shutil.copyfileobj(sys.stdin, catfp);
  catfp.seek(0, 0);
  catfp = UncompressCatFile(catfp);
  if(not catfp):
   return False;
  catfp.seek(0, 0);
 else:
  infile = RemoveWindowsPath(infile);
  compresscheck = CheckCompressionType(infile, True);
  if(not compresscheck):
   fextname = os.path.splitext(infile)[1];
   if(fextname==".gz" or fextname==".cgz"):
    compresscheck = "gzip";
   if(fextname==".bz2" or fextname==".cbz"):
    compresscheck = "bzip2";
   if(fextname==".lzma" or fextname==".xz" or fextname==".cxz"):
    compresscheck = "lzma";
  if(not compresscheck):
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
 try:
  catfp.seek(0, 2);
 except ValueError:
  SeekToEndOfFile(catfp);
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
  catheaderdata = ReadFileHeaderData(catfp, 19);
  catfheadersize = int(catheaderdata[0], 16);
  catftype = int(catheaderdata[1], 16);
  catfname = catheaderdata[2];
  catflinkname = catheaderdata[3];
  catfsize = int(catheaderdata[4], 16);
  catfatime = int(catheaderdata[5], 16);
  catfmtime = int(catheaderdata[6], 16);
  catfmode = oct(int(catheaderdata[7], 16));
  catprefchmod = oct(int(catfmode[-3:], 8));
  catfchmod = catprefchmod;
  catfuid = int(catheaderdata[8], 16);
  catfuname = catheaderdata[9];
  catfgid = int(catheaderdata[10], 16);
  catfgname = catheaderdata[11];
  catfdev_minor = int(catheaderdata[12], 16);
  catfdev_major = int(catheaderdata[13], 16);
  catfrdev_minor = int(catheaderdata[14], 16);
  catfrdev_major = int(catheaderdata[15], 16);
  catfchecksumtype = catheaderdata[16].lower();
  if(CheckSumSupport(catfchecksumtype, 3)):
   catfcs = int(catheaderdata[17], 16);
   catfccs = int(catheaderdata[18], 16);
  if(CheckSumSupport(catfchecksumtype, 4)):
   catfcs = catheaderdata[17];
   catfccs = catheaderdata[18];
  hc = 1;
  hcmax = len(catheaderdata) - 2;
  hout = "";
  while(hc<hcmax):
   hout = hout + AppendNullByte(catheaderdata[hc]);
   hc = hc + 1;
  if(CheckSumSupport(catfchecksumtype, 1)):
   catnewfcs = zlib.adler32(hout.encode()) & 0xffffffff;
  if(CheckSumSupport(catfchecksumtype, 2)):
   catnewfcs = zlib.crc32(hout.encode()) & 0xffffffff;
  if(CheckSumSupport(catfchecksumtype, 4)):
   checksumoutstr = hashlib.new(catfchecksumtype);
   checksumoutstr.update(hout.encode());
   catnewfcs = checksumoutstr.hexdigest().upper();
  if(catfcs!=catnewfcs and not skipchecksum):
   logging.info("File Header Checksum Error with file " + catfname + " at offset " + str(catfhstart));
   return False;
  catfhend = catfp.tell() - 1;
  catfcontentstart = catfp.tell();
  catfcontents = "";
  pyhascontents = False;
  if(catfsize>1 and not listonly):
   catfcontents = catfp.read(catfsize);
   if(CheckSumSupport(catfchecksumtype, 1)):
    catnewfccs = zlib.adler32(catfcontents) & 0xffffffff;
   if(CheckSumSupport(catfchecksumtype, 2)):
    catnewfccs = zlib.crc32(catfcontents) & 0xffffffff;
   if(CheckSumSupport(catfchecksumtype, 4)):
    checksumoutstr = hashlib.new(catfchecksumtype);
    checksumoutstr.update(catfcontents);
    catnewfccs = checksumoutstr.hexdigest().upper();
   pyhascontents = True;
   if(catfccs!=catnewfccs and skipchecksum):
    logging.info("File Content Checksum Error with file " + catfname + " at offset " + str(catfcontentstart));
    return False;
  if(catfsize>1 and listonly):
   catfp.seek(catfsize, 1);
   pyhascontents = False;
  catfcontentend = catfp.tell();
  catlist.update({fileidnum: {'catfileversion': catversion, 'fid': fileidnum, 'fhstart': catfhstart, 'fhend': catfhend, 'ftype': catftype, 'fname': catfname, 'flinkname': catflinkname, 'fsize': catfsize, 'fheadersize': catfheadersize, 'fatime': catfatime, 'fmtime': catfmtime, 'fmode': catfmode, 'fchmod': catfchmod, 'fuid': catfuid, 'funame': catfuname, 'fgid': catfgid, 'fgname': catfgname, 'fminor': catfdev_minor, 'fmajor': catfdev_major, 'frminor': catfrdev_minor, 'frmajor': catfrdev_major, 'fchecksumtype': catfchecksumtype, 'fheaderchecksum': catfcs, 'fcontentchecksum': catfccs, 'fhascontents': pyhascontents, 'fcontentstart': catfcontentstart, 'fcontentend': catfcontentend, 'fcontents': catfcontents} });
  catfp.seek(1, 1);
  seekstart = catfp.tell();
  fileidnum = fileidnum + 1;
 if(returnfp):
  catlist.update({'catfp': catfp});
 else:
  catfp.close();
 return catlist;

def CatStringToArray(catstr, seekstart=0, seekend=0, listonly=False, skipchecksum=False, returnfp=False):
 catfp = BytesIO(catstr);
 listcatfiles = CatFileToArray(catfp, seekstart, seekend, listonly, skipchecksum, returnfp);
 return listcatfiles;

def ListDirToArray(infiles, compression, followlink=False, seekstart=0, seekend=0, listonly=False, skipchecksum=False, checksumtype="crc32", verbose=False, returnfp=False):
 outarray = BytesIO();
 packcat = PackCatFile(infiles, outarray, compression, followlink, checksumtype, verbose, True);
 return CatFileToArray(outarray, seekstart, seekend, listonly, skipchecksum, returnfp);

def CatFileToArrayIndex(infile, seekstart=0, seekend=0, listonly=False, skipchecksum=False, returnfp=False):
 if(isinstance(infile, dict)):
  listcatfiles = infile;
 else:
  if(infile!="-" and not hasattr(infile, "read") and not hasattr(infile, "write")):
   infile = RemoveWindowsPath(infile);
  listcatfiles = CatFileToArray(infile, seekstart, seekend, listonly, skipchecksum, returnfp);
 if(not listcatfiles):
  return False;
 catarray = {'list': listcatfiles, 'filetoid': {}, 'idtofile': {}, 'filetypes': {'directories': {'filetoid': {}, 'idtofile': {}}, 'files': {'filetoid': {}, 'idtofile': {}}, 'links': {'filetoid': {}, 'idtofile': {}}, 'symlinks': {'filetoid': {}, 'idtofile': {}}, 'hardlinks': {'filetoid': {}, 'idtofile': {}}, 'character': {'filetoid': {}, 'idtofile': {}}, 'block': {'filetoid': {}, 'idtofile': {}}, 'fifo': {'filetoid': {}, 'idtofile': {}}, 'devices': {'filetoid': {}, 'idtofile': {}}}};
 if(returnfp):
  catarray.update({'catfp': listcatfiles['catfp']});
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

def CatStringToArrayIndex(catstr, seekstart=0, seekend=0, listonly=False, skipchecksum=False, returnfp=False):
 catfp = BytesIO(catstr);
 listcatfiles = CatFileToArrayIndex(catfp, seekstart, seekend, listonly, skipchecksum, returnfp);
 return listcatfiles;

def ListDirToArrayIndex(infiles, compression="auto", followlink=False, seekstart=0, seekend=0, listonly=False, skipchecksum=False, checksumtype="crc32", verbose=False, returnfp=False):
 outarray = BytesIO();
 packcat = PackCatFile(infiles, outarray, compression, followlink, checksumtype, verbose, True);
 return CatFileToArrayIndex(outarray, seekstart, seekend, listonly, skipchecksum, returnfp);

def RePackCatFile(infile, outfile, seekstart=0, seekend=0, compression="auto", checksumtype="crc32", skipchecksum=False, verbose=False, returnfp=False):
 compressionlist = ['auto', 'gzip', 'bzip2', 'lzma', 'xz'];
 outextlist = ['gz', 'cgz', 'bz2', 'cbz', 'lzma', 'xz', 'cxz'];
 outextlistwd = ['.gz', '.cgz', '.bz2', '.cbz', '.lzma', '.xz', '.cxz'];
 if(isinstance(infile, dict)):
  listcatfiles = infile;
 else:
  if(infile!="-" and not hasattr(infile, "read") and not hasattr(infile, "write")):
   infile = RemoveWindowsPath(infile);
  listcatfiles = CatFileToArray(infile, seekstart, seekend, False, skipchecksum, False);
 if(outfile!="-" and not hasattr(infile, "read") and not hasattr(outfile, "write")):
  outfile = RemoveWindowsPath(outfile);
 checksumtype = checksumtype.lower();
 if(not CheckSumSupport(checksumtype, 5)):
  checksumtype="crc32";
 if(not compression in compressionlist):
  compression = "auto";
 if(verbose):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(outfile!="-" and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
  if(os.path.exists(outfile)):
   os.unlink(outfile);
 if(not listcatfiles):
  return False;
 if(outfile=="-"):
  verbose = False;
  catfp = BytesIO();
 elif(hasattr(outfile, "read") or hasattr(outfile, "write")):
  catfp = outfile;
 else:
  fbasename = os.path.splitext(outfile)[0];
  fextname = os.path.splitext(outfile)[1];
  if(not fextname in outextlistwd):
   catfp = open(outfile, "wb");
  elif(((fextname==".gz" or fextname==".cgz") and compression=="auto") or compression=="gzip"):
   try:
    import gzip;
   except ImportError:
    return False;
   catfp = gzip.open(outfile, "wb", 9);
  elif(((fextname==".bz2" or fextname==".cbz") and compression=="auto") or compression=="bzip2"):
   try:
    import bz2;
   except ImportError:
    return False;
   catfp = bz2.BZ2File(outfile, "wb", 9);
  elif(((fextname==".xz" or fextname==".cxz") and compression=="auto") or compression=="xz"):
   try:
    import lzma;
   except ImportError:
    return False;
   catfp = lzma.open(outfile, "wb", format=lzma.FORMAT_XZ, preset=9);
  elif((fextname==".lzma" and compression=="auto") or compression=="lzma"):
   try:
    import lzma;
   except ImportError:
    return False;
   catfp = lzma.open(outfile, "wb", format=lzma.FORMAT_ALONE, preset=9);
 catver = str(__version_info__[0]) + str(__version_info__[1]) + str(__version_info__[2]);
 fileheaderver = str(int(catver.replace(".", "")));
 fileheader = AppendNullByte("CatFile" + fileheaderver);
 catfp.write(fileheader.encode());
 lcfi = 0;
 lcfx = len(listcatfiles);
 while(lcfi < lcfx):
  fname = listcatfiles[lcfi]['fname'];
  if(verbose):
   logging.info(fname);
  fsize = format(int(listcatfiles[lcfi]['fsize']), 'x').upper();
  flinkname = listcatfiles[lcfi]['flinkname'];
  fatime = format(int(listcatfiles[lcfi]['fatime']), 'x').upper();
  fmtime = format(int(listcatfiles[lcfi]['fmtime']), 'x').upper();
  fmode = format(int(int(listcatfiles[lcfi]['fmode'], 8)), 'x').upper();
  fuid = format(int(listcatfiles[lcfi]['fuid']), 'x').upper();
  funame = listcatfiles[lcfi]['funame'];
  fgid = format(int(listcatfiles[lcfi]['fgid']), 'x').upper();
  fgname = listcatfiles[lcfi]['fgname'];
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
  catfileoutstr = catfileoutstr + AppendNullByte(funame);
  catfileoutstr = catfileoutstr + AppendNullByte(fgid);
  catfileoutstr = catfileoutstr + AppendNullByte(fgname);
  catfileoutstr = catfileoutstr + AppendNullByte(fdev_minor);
  catfileoutstr = catfileoutstr + AppendNullByte(fdev_major);
  catfileoutstr = catfileoutstr + AppendNullByte(frdev_minor);
  catfileoutstr = catfileoutstr + AppendNullByte(frdev_major);
  catfileoutstr = catfileoutstr + AppendNullByte(checksumtype);
  if(CheckSumSupport(checksumtype, 1)):
   catfileheadercshex = format(zlib.adler32(catfileoutstr.encode()) & 0xffffffff, 'x').upper();
   catfilecontentcshex = format(zlib.adler32(fcontents) & 0xffffffff, 'x').upper();
  if(CheckSumSupport(checksumtype, 2)):
   catfileheadercshex = format(zlib.crc32(catfileoutstr.encode()) & 0xffffffff, 'x').upper();
   catfilecontentcshex = format(zlib.crc32(fcontents) & 0xffffffff, 'x').upper();
  if(CheckSumSupport(checksumtype, 4)):
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(catfileoutstr.encode());
   catfileheadercshex = checksumoutstr.hexdigest().upper();
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(fcontents);
   catfilecontentcshex = checksumoutstr.hexdigest().upper();
  catfileoutstr = catfileoutstr + AppendNullByte(catfileheadercshex);
  catfileoutstr = catfileoutstr + AppendNullByte(catfilecontentcshex);
  catfheadersizehex = format(int(len(catfileoutstr) - 1), 'x').upper();
  catfileoutstr = AppendNullByte(catfheadersizehex) + catfileoutstr;
  catfileoutstrecd = catfileoutstr.encode();
  nullstrecd = "\0".encode();
  catfileout = catfileoutstrecd + fcontents + nullstrecd;
  catfp.write(catfileout);
  lcfi = lcfi + 1;
 if(outfile=="-" or hasattr(outfile, "read") or hasattr(outfile, "write")):
  catfp = CompressCatFile(catfp, compression);
 if(outfile=="-"):
  catfp.seek(0, 0);
  if(hasattr(sys.stdout, "buffer")):
   shutil.copyfileobj(catfp, sys.stdout.buffer);
  else:
   shutil.copyfileobj(catfp, sys.stdout);
 if(returnfp):
  catfp.seek(0, 0);
  return catfp;
 else:
  catfp.close();
  return True;

def RePackCatFileFromString(catstr, outfile, seekstart=0, seekend=0, compression="auto", checksumtype="crc32", skipchecksum=False, verbose=False, returnfp=False):
 catfp = BytesIO(catstr);
 listcatfiles = RePackCatFile(catfp, seekstart, seekend, compression, checksumtype, skipchecksum, verbose, returnfp);
 return listcatfiles;

def PackCatFileFromListDir(infiles, outfile, seekstart=0, seekend=0, compression="auto", followlink=False, skipchecksum=False, checksumtype="crc32", verbose=False, returnfp=False):
 outarray = BytesIO();
 packcat = PackCatFile(infiles, outarray, compression, followlink, checksumtype, verbose, True);
 return RePackCatFile(outarray, outfile, seekstart, seekend, compression, checksumtype, skipchecksum, verbose, returnfp);

def UnPackCatFile(infile, outdir=None, skipchecksum=False, verbose=False, returnfp=False):
 if(outdir is not None):
  outdir = RemoveWindowsPath(outdir);
 if(verbose):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(isinstance(infile, dict)):
  listcatfiles = infile;
 else:
  if(infile!="-" and not hasattr(infile, "read") and not hasattr(infile, "write")):
   infile = RemoveWindowsPath(infile);
  listcatfiles = CatFileToArray(infile, 0, 0, False, skipchecksum, returnfp);
 if(not listcatfiles):
  return False;
 lcfi = 0;
 lcfx = len(listcatfiles);
 while(lcfi < lcfx):
  if(verbose):
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
 if(returnfp):
  return listcatfiles['catfp'];
 else:
  return True;

def UnPackCatString(catstr, outdir=None, skipchecksum=False, verbose=False, returnfp=False):
 catfp = BytesIO(catstr);
 listcatfiles = UnPackCatFile(catfp, outdir, verbose, skipchecksum, returnfp);
 return listcatfiles;

def CatFileListFiles(infile, seekstart=0, seekend=0, skipchecksum=False, verbose=False, returnfp=False):
 import datetime;
 logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(isinstance(infile, dict)):
  listcatfiles = infile;
 else:
  if(infile!="-" and not hasattr(infile, "read") and not hasattr(infile, "write")):
   infile = RemoveWindowsPath(infile);
  listcatfiles = CatFileToArray(infile, seekstart, seekend, True, skipchecksum, returnfp);
 if(not listcatfiles):
  return False;
 lcfi = 0;
 lcfx = len(listcatfiles);
 returnval = {};
 while(lcfi < lcfx):
  returnval.update({lcfi: listcatfiles[lcfi]['fname']});
  if(not verbose):
   logging.info(listcatfiles[lcfi]['fname']);
  if(verbose):
   permissions = { 'access': { '0': ('---'), '1': ('--x'), '2': ('-w-'), '3': ('-wx'), '4': ('r--'), '5': ('r-x'), '6': ('rw-'), '7': ('rwx') }, 'roles': { 0: 'owner', 1: 'group', 2: 'other' } };
   permissionstr = "";
   for fmodval in str(listcatfiles[lcfi]['fchmod'])[-3:]:
    permissionstr = permissionstr + permissions['access'].get(fmodval, '---');
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
   fuprint = listcatfiles[lcfi]['funame'];
   if(len(fuprint)<=0):
    fuprint = listcatfiles[lcfi]['fuid'];
   fgprint = listcatfiles[lcfi]['fgname']
   if(len(fgprint)<=0):
    fgprint = listcatfiles[lcfi]['fgid'];
   logging.info(permissionstr + " " + str(str(fuprint) + "/" + str(fgprint) + " " + str(listcatfiles[lcfi]['fsize']).rjust(15) + " " + datetime.datetime.utcfromtimestamp(listcatfiles[lcfi]['fmtime']).strftime('%Y-%m-%d %H:%M') + " " + printfname));
  lcfi = lcfi + 1;
 if(returnfp):
  return listcatfiles['catfp'];
 else:
  return True;

def CatStringListFiles(catstr, seekstart=0, seekend=0, skipchecksum=False, verbose=False, returnfp=False):
 catfp = BytesIO(catstr);
 listcatfiles = UnPackCatFile(catfp, seekstart, seekend, verbose, skipchecksum, returnfp);
 return listcatfiles;

def ListDirListFiles(infiles, compression="auto", followlink=False, seekstart=0, seekend=0, skipchecksum=False, checksumtype="crc32", verbose=False, returnfp=False):
 outarray = BytesIO();
 packcat = PackCatFile(infiles, outarray, compression, followlink, checksumtype, False, True);
 return CatFileListFiles(outarray, seekstart, seekend, skipchecksum, verbose, returnfp);
