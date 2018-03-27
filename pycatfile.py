#!/usr/bin/env python
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

    $FileInfo: pycatfile.py - Last Update: 3/14/2018 Ver. 0.0.1 RC 1 - Author: cooldude2k $
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

__program_name__ = "PyCatFile";
__project__ = __program_name__;
__project_url__ = "https://github.com/GameMaker2k/PyCatFile";
__version_info__ = (0, 0, 1, "RC 1", 1);
__version_date_info__ = (2018, 3, 12, "RC 1", 1);
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

def ListDir(dirpath, followlink=False, duplicates=False):
 if(isinstance(dirpath, (list, tuple, ))):
  dirpath = list(filter(None, dirpath));
 elif(isinstance(dirpath, (str, ))):
  dirpath = list(filter(None, [dirpath]));
 retlist = [];
 for mydirfile in dirpath:
  if(not os.path.exists(mydirfile)):
   return False;
  if(os.path.exists(mydirfile) and os.path.islink(mydirfile)):
   mydirfile = RemoveWindowsPath(os.path.realpath(mydirfile));
  if(os.path.exists(mydirfile) and os.path.isdir(mydirfile)):
   for root, dirs, filenames in os.walk(mydirfile):
    dpath = root;
    dpath = RemoveWindowsPath(dpath);
    if(dpath not in retlist and not duplicates):
     retlist.append(dpath);
    if(duplicates):
     retlist.append(dpath);
    for file in filenames:
     fpath = os.path.join(root, file);
     fpath = RemoveWindowsPath(fpath);
     if(fpath not in retlist and not duplicates):
      retlist.append(fpath);
     if(duplicates):
      retlist.append(fpath);
  else:
   retlist.append(RemoveWindowsPath(mydirfile));
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
  catfp.write(bz2.decompress(fp.read()));
 if(compresscheck=="lzma"):
  try:
   import lzma;
  except ImportError:
   return False;
  catfp = BytesIO();
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

def GZipCompress(data, compresslevel=9):
 try:
  import gzip;
 except ImportError:
  return False;
 tmpfp = tempfile.NamedTemporaryFile("wb", delete=False);
 tmpfp.close();
 tmpfp = gzip.GzipFile(tmpfp.name, mode="wb", compresslevel=compresslevel);
 tmpfp.write(data);
 tmpfp.close();
 catfp = open(tmpfp.name, "rb");
 catdata = catfp.read();
 catfp.close();
 return catdata;

def CompressCatFile(fp, compression="auto"):
 compressionlist = ['auto', 'gzip', 'bzip2', 'lzma', 'xz'];
 if(not hasattr(fp, "read") and not hasattr(fp, "write")):
  return False;
 fp.seek(0, 0);
 if(not compression or compression or compression=="catfile"):
  compression = None;
 if(compression not in compressionlist and compression is None):
  compression = "auto";
 if(compression=="gzip"):
  try:
   import gzip;
  except ImportError:
   return False;
  catfp = BytesIO();
  catfp.write(GZipCompress(fp.read(), compresslevel=9));
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
 if(compression=="auto" or compression is None):
  catfp = fp;
 catfp.seek(0, 0);
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
  checklist = sorted(list(hashlib.algorithms_guaranteed) + ['adler32', 'crc32', "none"]);
 if(checkfor in checklist):
  return True;
 else:
  return False;

def PackCatFile(infiles, outfile, dirlistfromtxt=False, compression="auto", followlink=False, checksumtype="crc32", verbose=False, returnfp=False):
 compressionlist = ['auto', 'gzip', 'bzip2', 'lzma', 'xz'];
 outextlist = ['gz', 'cgz', 'bz2', 'cbz', 'lzma', 'xz', 'cxz'];
 outextlistwd = ['.gz', '.cgz', '.bz2', '.cbz', '.lzma', '.xz', '.cxz'];
 if(outfile!="-" and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
  outfile = RemoveWindowsPath(outfile);
 checksumtype = checksumtype.lower();
 if(not CheckSumSupport(checksumtype, 5)):
  checksumtype="crc32";
 if(not compression or compression or compression=="catfile"):
  compression = None;
 if(compression not in compressionlist and compression is None):
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
  if(fextname not in outextlistwd and (compression=="auto" or compression is None)):
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
 infilelist = [];
 if(infiles=="-"):
  for line in sys.stdin:
   infilelist.append(line.strip());
  infilelist = list(filter(None, infilelist));
 elif(infiles!="-" and dirlistfromtxt and os.path.exists(infiles) and os.path.isfile(infiles)):
  with open(infiles, "r") as finfile:
   for line in finfile:
    infilelist.append(line.strip());
  infilelist = list(filter(None, infilelist));
 else:
  if(isinstance(infiles, (list, tuple, ))):
   infilelist = list(filter(None, infiles));
  elif(isinstance(infiles, (str, ))):
   infilelist = list(filter(None, [infiles]));
 GetDirList = ListDir(infilelist, followlink, False);
 if(not GetDirList):
  return False;
 curinode = 0;
 inodelist = [];
 inodetofile = {};
 inodetocatinode = {};
 for curfname in GetDirList:
  fname = curfname;
  if(verbose):
   logging.info(fname);
  if(not followlink or followlink is None):
   fstatinfo = os.lstat(fname);
  else:
   fstatinfo = os.stat(fname);
  fpremode = fstatinfo.st_mode;
  finode = fstatinfo.st_ino;
  flinkcount = fstatinfo.st_nlink;
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
  flinkname = "";
  fcurinode = curinode;
  if(ftype==0 or ftype==7):
   if(finode in inodelist):
    ftype = 1;
    flinkname = inodetofile[finode];
    fcurinode = inodetocatinode[finode];
   if(finode not in inodelist):
    inodelist.append(finode);
    inodetofile.update({finode: fname});
    inodetocatinode.update({finode: curinode});
    curinode = curinode + 1;
  if(ftype==2):
   flinkname = os.readlink(fname);
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
  if(ftype==0 or ftype==7):
   fsize = format(int(fstatinfo.st_size), 'x').upper();
  fatime = format(int(fstatinfo.st_atime), 'x').upper();
  fmtime = format(int(fstatinfo.st_mtime), 'x').upper();
  fctime = format(int(fstatinfo.st_ctime), 'x').upper();
  if(hasattr(fstatinfo, "st_birthtime")):
   fbtime = format(int(fstatinfo.st_birthtime), 'x').upper();
  else:
   fbtime = format(int(fstatinfo.st_ctime), 'x').upper();
  fmode = format(int(fstatinfo.st_mode), 'x').upper();
  fchmode = format(int(stat.S_IMODE(fstatinfo.st_mode)), 'x').upper();
  ftypemod = format(int(stat.S_IFMT(fstatinfo.st_mode)), 'x').upper();
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
  finode = format(int(finode), 'x').upper();
  flinkcount = format(int(flinkcount), 'x').upper();
  fcontents = "".encode();
  if(ftype==0 or ftype==7):
   fpc = open(fname, "rb");
   fcontents = fpc.read(int(fstatinfo.st_size));
   fpc.close();
  if(followlink and (ftype==1 or ftype==2)):
   flstatinfo = os.stat(flinkname);
   fpc = open(flinkname, "rb");
   fcontents = fpc.read(int(flstatinfo.st_size));
   fpc.close();
  ftypehex = format(ftype, 'x').upper();
  catfileoutstr = AppendNullByte(ftypehex);
  catfileoutstr = catfileoutstr + AppendNullByte(fname);
  catfileoutstr = catfileoutstr + AppendNullByte(flinkname);
  catfileoutstr = catfileoutstr + AppendNullByte(fsize);
  catfileoutstr = catfileoutstr + AppendNullByte(fatime);
  catfileoutstr = catfileoutstr + AppendNullByte(fmtime);
  catfileoutstr = catfileoutstr + AppendNullByte(fctime);
  catfileoutstr = catfileoutstr + AppendNullByte(fmode);
  catfileoutstr = catfileoutstr + AppendNullByte(fchmode);
  catfileoutstr = catfileoutstr + AppendNullByte(fuid);
  catfileoutstr = catfileoutstr + AppendNullByte(funame);
  catfileoutstr = catfileoutstr + AppendNullByte(fgid);
  catfileoutstr = catfileoutstr + AppendNullByte(fgname);
  catfileoutstr = catfileoutstr + AppendNullByte(fcurinode);
  catfileoutstr = catfileoutstr + AppendNullByte(flinkcount);
  catfileoutstr = catfileoutstr + AppendNullByte(fdev_minor);
  catfileoutstr = catfileoutstr + AppendNullByte(fdev_major);
  catfileoutstr = catfileoutstr + AppendNullByte(frdev_minor);
  catfileoutstr = catfileoutstr + AppendNullByte(frdev_major);
  catfileoutstr = catfileoutstr + AppendNullByte(checksumtype);
  if(checksumtype=="none"):
   catfileheadercshex = format(0, 'x').upper();
   catfilecontentcshex = format(0, 'x').upper();
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
  catheaderdata = ReadFileHeaderData(catfp, 22);
  catftype = int(catheaderdata[0], 16);
  catfname = catheaderdata[1];
  catflinkname = catheaderdata[2];
  catfsize = int(catheaderdata[3], 16);
  catfatime = int(catheaderdata[4], 16);
  catfmtime = int(catheaderdata[5], 16);
  catfctime = int(catheaderdata[6], 16);
  catfmode = oct(int(catheaderdata[7], 16));
  catfchmod = oct(int(catheaderdata[8], 16));
  catfuid = int(catheaderdata[9], 16);
  catfuname = catheaderdata[10];
  catfgid = int(catheaderdata[11], 16);
  catfgname = catheaderdata[12];
  finode = int(catheaderdata[13], 16);
  flinkcount = int(catheaderdata[14], 16);
  catfdev_minor = int(catheaderdata[15], 16);
  catfdev_major = int(catheaderdata[16], 16);
  catfrdev_minor = int(catheaderdata[17], 16);
  catfrdev_major = int(catheaderdata[18], 16);
  catfchecksumtype = catheaderdata[19].lower();
  if(catfchecksumtype=="none"):
   catfcs = int(catheaderdata[20]);
   catfccs = int(catheaderdata[21]);
  if(CheckSumSupport(catfchecksumtype, 3)):
   catfcs = int(catheaderdata[20], 16);
   catfccs = int(catheaderdata[21], 16);
  if(CheckSumSupport(catfchecksumtype, 4)):
   catfcs = catheaderdata[20];
   catfccs = catheaderdata[21];
  hc = 0;
  hcmax = len(catheaderdata) - 2;
  hout = "";
  while(hc<hcmax):
   hout = hout + AppendNullByte(catheaderdata[hc]);
   hc = hc + 1;
  if(catfchecksumtype=="none"):
   catnewfcs = 0;
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
   if(catfchecksumtype=="none"):
    catnewfccs = 0;
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
  catlist.update({fileidnum: {'catfileversion': catversion, 'fid': fileidnum, 'fhstart': catfhstart, 'fhend': catfhend, 'ftype': catftype, 'fname': catfname, 'flinkname': catflinkname, 'fsize': catfsize, 'fatime': catfatime, 'fmtime': catfmtime, 'fctime': catfctime, 'fmode': catfmode, 'fchmod': catfchmod, 'fuid': catfuid, 'funame': catfuname, 'fgid': catfgid, 'fgname': catfgname, 'finode': finode, 'flinkcount': flinkcount, 'fminor': catfdev_minor, 'fmajor': catfdev_major, 'frminor': catfrdev_minor, 'frmajor': catfrdev_major, 'fchecksumtype': catfchecksumtype, 'fheaderchecksum': catfcs, 'fcontentchecksum': catfccs, 'fhascontents': pyhascontents, 'fcontentstart': catfcontentstart, 'fcontentend': catfcontentend, 'fcontents': catfcontents} });
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

def ListDirToArray(infiles, dirlistfromtxt=False, compression="auto", followlink=False, seekstart=0, seekend=0, listonly=False, skipchecksum=False, checksumtype="crc32", verbose=False, returnfp=False):
 outarray = BytesIO();
 packcat = PackCatFile(infiles, outarray, dirlistfromtxt, compression, followlink, checksumtype, verbose, True);
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
  if(listcatfiles[lcfi]['ftype']==0 or listcatfiles[lcfi]['ftype']==7):
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

def ListDirToArrayIndex(infiles, dirlistfromtxt=False, compression="auto", followlink=False, seekstart=0, seekend=0, listonly=False, skipchecksum=False, checksumtype="crc32", verbose=False, returnfp=False):
 outarray = BytesIO();
 packcat = PackCatFile(infiles, outarray, dirlistfromtxt, compression, followlink, checksumtype, verbose, True);
 return CatFileToArrayIndex(outarray, seekstart, seekend, listonly, skipchecksum, returnfp);

def RePackCatFile(infile, outfile, seekstart=0, seekend=0, compression="auto", followlink=False, checksumtype="crc32", skipchecksum=False, verbose=False, returnfp=False):
 compressionlist = ['auto', 'gzip', 'bzip2', 'lzma', 'xz'];
 outextlist = ['gz', 'cgz', 'bz2', 'cbz', 'lzma', 'xz', 'cxz'];
 outextlistwd = ['.gz', '.cgz', '.bz2', '.cbz', '.lzma', '.xz', '.cxz'];
 if(isinstance(infile, dict)):
  prelistcatfiles = CatFileToArrayIndex(infile, 0, 0, False, skipchecksum, returnfp);
  listcatfiles = prelistcatfiles['list'];
 else:
  if(infile!="-" and not hasattr(infile, "read") and not hasattr(infile, "write")):
   infile = RemoveWindowsPath(infile);
  if(followlink):
   prelistcatfiles = CatFileToArrayIndex(infile, 0, 0, False, skipchecksum, returnfp);
   listcatfiles = prelistcatfiles['list'];
  else:
   listcatfiles = CatFileToArray(infile, 0, 0, False, skipchecksum, returnfp);
 if(outfile!="-" and not hasattr(infile, "read") and not hasattr(outfile, "write")):
  outfile = RemoveWindowsPath(outfile);
 checksumtype = checksumtype.lower();
 if(not CheckSumSupport(checksumtype, 5)):
  checksumtype="crc32";
 if(not compression or compression or compression=="catfile"):
  compression = None;
 if(compression not in compressionlist and compression is None):
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
  if(fextname not in outextlistwd and (compression=="auto" or compression is None)):
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
  fctime = format(int(listcatfiles[lcfi]['fctime']), 'x').upper();
  fmode = format(int(int(listcatfiles[lcfi]['fmode'], 8)), 'x').upper();
  fchmode = format(int(int(listcatfiles[lcfi]['fchmode'], 8)), 'x').upper();
  fuid = format(int(listcatfiles[lcfi]['fuid']), 'x').upper();
  funame = listcatfiles[lcfi]['funame'];
  fgid = format(int(listcatfiles[lcfi]['fgid']), 'x').upper();
  fgname = listcatfiles[lcfi]['fgname'];
  finode = listcatfiles[lcfi]['finode'];
  flinkcount = listcatfiles[lcfi]['flinkcount'];
  fdev_minor = format(int(listcatfiles[lcfi]['fminor']), 'x').upper();
  fdev_major = format(int(listcatfiles[lcfi]['fmajor']), 'x').upper();
  frdev_minor = format(int(listcatfiles[lcfi]['frminor']), 'x').upper();
  frdev_major = format(int(listcatfiles[lcfi]['frmajor']), 'x').upper();
  fcontents = listcatfiles[lcfi]['fcontents'];
  if(followlink):
   if(listcatfiles[lcfi]['ftype']==1 or listcatfiles[lcfi]['ftype']==2):
    getflinkpath = listcatfiles[lcfi]['flinkname'];
    flinkid = prelistcatfiles['filetoid'][getflinkpath];
    flinkinfo = listcatfiles[flinkid];
    fsize = format(int(flinkinfo['fsize']), 'x').upper();
    flinkname = flinkinfo['flinkname'];
    fatime = format(int(flinkinfo['fatime']), 'x').upper();
    fmtime = format(int(flinkinfo['fmtime']), 'x').upper();
    fctime = format(int(flinkinfo['fctime']), 'x').upper();
    fmode = format(int(int(flinkinfo['fmode'], 8)), 'x').upper();
    fchmode = format(int(int(flinkinfo['fchmode'], 8)), 'x').upper();
    fuid = format(int(flinkinfo['fuid']), 'x').upper();
    funame = flinkinfo['funame'];
    fgid = format(int(flinkinfo['fgid']), 'x').upper();
    fgname = flinkinfo['fgname'];
    finode = flinkinfo['finode'];
    flinkcount = flinkinfo['flinkcount'];
    fdev_minor = format(int(flinkinfo['fminor']), 'x').upper();
    fdev_major = format(int(flinkinfo['fmajor']), 'x').upper();
    frdev_minor = format(int(flinkinfo['frminor']), 'x').upper();
    frdev_major = format(int(flinkinfo['frmajor']), 'x').upper();
    fcontents = flinkinfo['fcontents'];
	if(flinkinfo['ftype']!=0 and flinkinfo['ftype']!=7):
	 fcontents = fcontents.encode();
	ftypehex = format(flinkinfo['ftype'], 'x').upper();
  if(not followlink):
   if(listcatfiles[lcfi]['ftype']!=0 and listcatfiles[lcfi]['ftype']!=7):
    fcontents = fcontents.encode();
   ftypehex = format(listcatfiles[lcfi]['ftype'], 'x').upper();
  catfileoutstr = AppendNullByte(ftypehex);
  catfileoutstr = catfileoutstr + AppendNullByte(fname);
  catfileoutstr = catfileoutstr + AppendNullByte(flinkname);
  catfileoutstr = catfileoutstr + AppendNullByte(fsize);
  catfileoutstr = catfileoutstr + AppendNullByte(fatime);
  catfileoutstr = catfileoutstr + AppendNullByte(fmtime);
  catfileoutstr = catfileoutstr + AppendNullByte(fctime);
  catfileoutstr = catfileoutstr + AppendNullByte(fmode);
  catfileoutstr = catfileoutstr + AppendNullByte(fchmode);
  catfileoutstr = catfileoutstr + AppendNullByte(fuid);
  catfileoutstr = catfileoutstr + AppendNullByte(funame);
  catfileoutstr = catfileoutstr + AppendNullByte(fgid);
  catfileoutstr = catfileoutstr + AppendNullByte(fgname);
  catfileoutstr = catfileoutstr + AppendNullByte(finode);
  catfileoutstr = catfileoutstr + AppendNullByte(flinkcount);
  catfileoutstr = catfileoutstr + AppendNullByte(fdev_minor);
  catfileoutstr = catfileoutstr + AppendNullByte(fdev_major);
  catfileoutstr = catfileoutstr + AppendNullByte(frdev_minor);
  catfileoutstr = catfileoutstr + AppendNullByte(frdev_major);
  catfileoutstr = catfileoutstr + AppendNullByte(checksumtype);
  if(checksumtype=="none"):
   catfileheadercshex = format(0, 'x').upper();
   catfilecontentcshex = format(0, 'x').upper();
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

def PackCatFileFromListDir(infiles, outfile, dirlistfromtxt=False, seekstart=0, seekend=0, compression="auto", followlink=False, skipchecksum=False, checksumtype="crc32", verbose=False, returnfp=False):
 outarray = BytesIO();
 packcat = PackCatFile(infiles, outarray, dirlistfromtxt, compression, followlink, checksumtype, verbose, True);
 return RePackCatFile(outarray, outfile, seekstart, seekend, compression, checksumtype, skipchecksum, verbose, returnfp);

def UnPackCatFile(infile, outdir=None, followlink=False, skipchecksum=False, verbose=False, returnfp=False):
 if(outdir is not None):
  outdir = RemoveWindowsPath(outdir);
 if(verbose):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(isinstance(infile, dict)):
  prelistcatfiles = CatFileToArrayIndex(infile, 0, 0, False, skipchecksum, returnfp);
  listcatfiles = prelistcatfiles['list'];
 else:
  if(infile!="-" and not hasattr(infile, "read") and not hasattr(infile, "write")):
   infile = RemoveWindowsPath(infile);
  if(followlink):
   prelistcatfiles = CatFileToArrayIndex(infile, 0, 0, False, skipchecksum, returnfp);
   listcatfiles = prelistcatfiles['list'];
  else:
   listcatfiles = CatFileToArray(infile, 0, 0, False, skipchecksum, returnfp);
 if(not listcatfiles):
  return False;
 lcfi = 0;
 lcfx = len(listcatfiles);
 while(lcfi < lcfx):
  funame = "";
  try:
   import pwd;
   try:
    userinfo = pwd.getpwuid(listcatfiles[lcfi]['fuid']);
    funame = userinfo.pw_name;
   except KeyError:
    funame = "";
  except ImportError:
   funame = "";
  fgname = "";
  try:
   import grp;
   try:
    groupinfo = grp.getgrgid(listcatfiles[lcfi]['fgid']);
    fgname = groupinfo.gr_name;
   except KeyError:
    fgname = "";
  except ImportError:
   fgname = "";
  if(verbose):
   logging.info(listcatfiles[lcfi]['fname']);
  if(listcatfiles[lcfi]['ftype']==0 or listcatfiles[lcfi]['ftype']==7):
   fpc = open(listcatfiles[lcfi]['fname'], "wb");
   fpc.write(listcatfiles[lcfi]['fcontents']);
   fpc.close();
   if(hasattr(os, "chown") and funame==listcatfiles[lcfi]['funame'] and fgname==listcatfiles[lcfi]['fgname']):
    os.chown(listcatfiles[lcfi]['fname'], listcatfiles[lcfi]['fuid'], listcatfiles[lcfi]['fgid']);
   os.chmod(listcatfiles[lcfi]['fname'], int(listcatfiles[lcfi]['fchmod'], 8));
   os.utime(listcatfiles[lcfi]['fname'], (listcatfiles[lcfi]['fatime'], listcatfiles[lcfi]['fmtime']));
  if(listcatfiles[lcfi]['ftype']==1):
   if(followlink):
	getflinkpath = listcatfiles[lcfi]['flinkname'];
    flinkid = prelistcatfiles['filetoid'][getflinkpath];
    flinkinfo = listcatfiles[flinkid];
    funame = "";
    try:
     import pwd;
     try:
      userinfo = pwd.getpwuid(flinkinfo['fuid']);
      funame = userinfo.pw_name;
     except KeyError:
      funame = "";
    except ImportError:
     funame = "";
    fgname = "";
    try:
     import grp;
     try:
      groupinfo = grp.getgrgid(flinkinfo['fgid']);
      fgname = groupinfo.gr_name;
     except KeyError:
      fgname = "";
    except ImportError:
     fgname = "";
	if(flinkinfo['ftype']==0 or flinkinfo['ftype']==7):
     fpc = open(listcatfiles[lcfi]['fname'], "wb");
     fpc.write(flinkinfo['fcontents']);
     fpc.close();
     if(hasattr(os, "chown") and funame==flinkinfo['funame'] and fgname==flinkinfo['fgname']):
      os.chown(listcatfiles[lcfi]['fname'], flinkinfo['fuid'], flinkinfo['fgid']);
     os.chmod(listcatfiles[lcfi]['fname'], int(flinkinfo['fchmod'], 8));
     os.utime(listcatfiles[lcfi]['fname'], (flinkinfo['fatime'], flinkinfo['fmtime']));
	if(flinkinfo['ftype']==1):
     os.link(flinkinfo['flinkname'], listcatfiles[lcfi]['fname']);
	if(flinkinfo['ftype']==2):
     os.symlink(flinkinfo['flinkname'], listcatfiles[lcfi]['fname']);
    if(flinkinfo['ftype']==5):
     os.mkdir(listcatfiles[lcfi]['fname'], int(flinkinfo['fchmod'], 8));
     if(hasattr(os, "chown") and funame==flinkinfo['funame'] and fgname==flinkinfo['fgname']):
      os.chown(listcatfiles[lcfi]['fname'], flinkinfo['fuid'], flinkinfo['fgid']);
     os.chmod(listcatfiles[lcfi]['fname'], int(flinkinfo['fchmod'], 8));
     os.utime(listcatfiles[lcfi]['fname'], (flinkinfo['fatime'], flinkinfo['fmtime']));
	if(flinkinfo['ftype']==6 and hasattr(os, "mkfifo")):
     os.mkfifo(listcatfiles[lcfi]['fname'], int(flinkinfo['fchmod'], 8));
   else:
    os.link(listcatfiles[lcfi]['flinkname'], listcatfiles[lcfi]['fname']);
  if(listcatfiles[lcfi]['ftype']==2):
   if(followlink):
	getflinkpath = listcatfiles[lcfi]['flinkname'];
    flinkid = prelistcatfiles['filetoid'][getflinkpath];
    flinkinfo = listcatfiles[flinkid];
    funame = "";
    try:
     import pwd;
     try:
      userinfo = pwd.getpwuid(flinkinfo['fuid']);
      funame = userinfo.pw_name;
     except KeyError:
      funame = "";
    except ImportError:
     funame = "";
    fgname = "";
    try:
     import grp;
     try:
      groupinfo = grp.getgrgid(flinkinfo['fgid']);
      fgname = groupinfo.gr_name;
     except KeyError:
      fgname = "";
    except ImportError:
     fgname = "";
	if(flinkinfo['ftype']==0 or flinkinfo['ftype']==7):
     fpc = open(listcatfiles[lcfi]['fname'], "wb");
     fpc.write(flinkinfo['fcontents']);
     fpc.close();
     if(hasattr(os, "chown") and funame==flinkinfo['funame'] and fgname==flinkinfo['fgname']):
      os.chown(listcatfiles[lcfi]['fname'], flinkinfo['fuid'], flinkinfo['fgid']);
     os.chmod(listcatfiles[lcfi]['fname'], int(flinkinfo['fchmod'], 8));
     os.utime(listcatfiles[lcfi]['fname'], (flinkinfo['fatime'], flinkinfo['fmtime']));
	if(flinkinfo['ftype']==1):
     os.link(flinkinfo['flinkname'], listcatfiles[lcfi]['fname']);
	if(flinkinfo['ftype']==2):
     os.symlink(flinkinfo['flinkname'], listcatfiles[lcfi]['fname']);
    if(flinkinfo['ftype']==5):
     os.mkdir(listcatfiles[lcfi]['fname'], int(flinkinfo['fchmod'], 8));
     if(hasattr(os, "chown") and funame==flinkinfo['funame'] and fgname==flinkinfo['fgname']):
      os.chown(listcatfiles[lcfi]['fname'], flinkinfo['fuid'], flinkinfo['fgid']);
     os.chmod(listcatfiles[lcfi]['fname'], int(flinkinfo['fchmod'], 8));
     os.utime(listcatfiles[lcfi]['fname'], (flinkinfo['fatime'], flinkinfo['fmtime']));
	if(flinkinfo['ftype']==6 and hasattr(os, "mkfifo")):
     os.mkfifo(listcatfiles[lcfi]['fname'], int(flinkinfo['fchmod'], 8));
   else:
    os.symlink(listcatfiles[lcfi]['flinkname'], listcatfiles[lcfi]['fname']);
  if(listcatfiles[lcfi]['ftype']==5):
   os.mkdir(listcatfiles[lcfi]['fname'], int(listcatfiles[lcfi]['fchmod'], 8));
   if(hasattr(os, "chown") and funame==listcatfiles[lcfi]['funame'] and fgname==listcatfiles[lcfi]['fgname']):
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
   if(listcatfiles[lcfi]['ftype']==0 or listcatfiles[lcfi]['ftype']==7):
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

def ListDirListFiles(infiles, dirlistfromtxt=False, compression="auto", followlink=False, seekstart=0, seekend=0, skipchecksum=False, checksumtype="crc32", verbose=False, returnfp=False):
 outarray = BytesIO();
 packcat = PackCatFile(infiles, outarray, dirlistfromtxt, compression, followlink, checksumtype, False, True);
 return CatFileListFiles(outarray, seekstart, seekend, skipchecksum, verbose, returnfp);
