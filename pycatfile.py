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
    $FileInfo: pycatfile.py - Last Update: 2/26/2018 Ver. 0.0.1 RC 1 - Author: cooldude2k $
'''

__program_name__ = "PyCatFile";
__project__ = __program_name__;
__project_url__ = "https://github.com/GameMaker2k/PyCatFile";
__version_info__ = (0, 0, 1, "RC 1", 1);
__version_date_info__ = (2018, 2, 26, "RC 1", 1);
__version_date__ = str(__version_date_info__[0])+"."+str(__version_date_info__[1]).zfill(2)+"."+str(__version_date_info__[2]).zfill(2);
if(__version_info__[4] is not None):
 __version_date_plusrc__ = __version_date__+"-"+str(__version_date_info__[4]);
if(__version_info__[4] is None):
 __version_date_plusrc__ = __version_date__;
if(__version_info__[3] is not None):
 __version__ = str(__version_info__[0])+"."+str(__version_info__[1])+"."+str(__version_info__[2])+" "+str(__version_info__[3]);
if(__version_info__[3] is None):
 __version__ = str(__version_info__[0])+"."+str(__version_info__[1])+"."+str(__version_info__[2]);

import os, sys, logging, zlib;
'''
if __name__ == '__main__':
 import argparse;

if __name__ == '__main__':
 argparser = argparse.ArgumentParser(description="Manipulating concatenate files", conflict_handler="resolve", add_help=True);
 argparser.add_argument("-V", "--version", action="version", version=__program_name__+" "+__version__);
 argparser.add_argument("-i", "--input", help="files to concatenate or concatenate file extract", required=True);
 argparser.add_argument("-v", "--verbose", action="store_true", help="print various debugging information");
 argparser.add_argument("-c", "--create", action="store_true", help="concatenate files only");
 argparser.add_argument("-x", "--extract", action="store_true", help="extract files only");
 argparser.add_argument("-o", "--output", default="./", help="extract concatenate files to or concatenate output name");
 getargs = argparser.parse_args();
'''
def ListDir(dirpath):
 retlist = [dirpath];
 for path, subdirs, files in os.walk(dirpath):
  for name in subdirs:
   fpath = os.path.join(path, name);
   if(os.sep!="/"):
    fpath = fpath.replace(os.path.sep, "/");
   retlist.append(fpath);
  for name in files:
   fpath = os.path.join(path, name);
   if(os.sep!="/"):
    fpath = fpath.replace(os.path.sep, "/");
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
   curfullbyte = curfullbyte+curbyted;
 return curfullbyte;

def ReadUntilNullByte(fp):
 return ReadTillNullByte(fp);

def PyCatFile(infiles, outfile, verbose=False):
 if(verbose is True):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(os.path.exists(outfile)):
  os.remove(outfile);
 catfp = open(outfile, "wb");
 fileheaderver = "00";
 fileheader = "CatFile"+fileheaderver+"\0";
 catfp.write(fileheader.encode());
 GetDirList = ListDir(infiles);
 for curfname in GetDirList:
  fname = curfname;
  if(verbose is True):
   logging.info(fname);
  fstatinfo = os.stat(fname);
  ftype = 0;
  if(os.path.isdir(fname)):
   ftype = 0;
  if(os.path.isfile(fname)):
   ftype = 1;
  if(os.path.islink(fname)):
   ftype = 2;
  if(ftype==0 or ftype==2 or ftype==3):
   fsize = format(int("0"), 'x').upper();
  if(ftype==1):
   fsize = format(int(fstatinfo.st_size), 'x').upper();
  flinkname = "";
  if(ftype==2 or ftype==3):
   flinkname = os.readlink(fname);
  flinknameintsize = len(flinkname);
  fatime = format(int(fstatinfo.st_atime), 'x').upper();
  fmtime = format(int(fstatinfo.st_mtime), 'x').upper();
  fmode = format(int(fstatinfo.st_mode), 'x').upper();
  fuid = format(int(fstatinfo.st_uid), 'x').upper();
  fgid = format(int(fstatinfo.st_gid), 'x').upper();
  fcontents = "".encode();
  if(ftype==1):
   fpc = open(fname, "rb");
   fcontents = fpc.read(int(fstatinfo.st_size));
   fpc.close();
  ftypehex = format(ftype, 'x').upper();
  ftypeoutstr = ftypehex;
  catfileoutstr = ftypeoutstr+"\0";
  catfileoutstr = catfileoutstr+str(fname)+"\0";
  catfileoutstr = catfileoutstr+str(fsize)+"\0";
  catfileoutstr = catfileoutstr+str(flinkname)+"\0";
  catfileoutstr = catfileoutstr+str(fatime)+"\0";
  catfileoutstr = catfileoutstr+str(fmtime)+"\0";
  catfileoutstr = catfileoutstr+str(fmode)+"\0";
  catfileoutstr = catfileoutstr+str(fuid)+"\0";
  catfileoutstr = catfileoutstr+str(fgid)+"\0";
  catfileheadercshex = format(zlib.crc32(catfileoutstr.encode()), 'x').upper();
  catfileoutstr = catfileoutstr+catfileheadercshex+"\0";
  catfileoutstrecd = catfileoutstr.encode();
  nullstrecd = "\0".encode();
  catfileout = catfileoutstrecd+fcontents+nullstrecd;
  catfp.write(catfileout);
 catfp.close();
 return True;

def PyUnCatFile(infile, outdir=None, verbose=False):
 if(verbose is True):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 catfp = open(infile, "rb");
 catfp.seek(0, 2);
 CatSize = catfp.tell();
 CatSizeEnd = CatSize;
 catfp.seek(0, 0);
 pycatstring = catfp.read(7).decode('ascii');
 pycatver = int(ReadTillNullByte(catfp), 16);
 while(catfp.tell()<CatSizeEnd):
  pycatftype = int(ReadTillNullByte(catfp), 16);
  pycatfname = ReadTillNullByte(catfp);
  if(verbose is True):
   logging.info(pycatfname);
  pycatfsize = int(ReadTillNullByte(catfp), 16);
  pycatflinkname = ReadTillNullByte(catfp);
  pycatfatime = int(ReadTillNullByte(catfp), 16);
  pycatfmtime = int(ReadTillNullByte(catfp), 16);
  pycatfmode = int(ReadTillNullByte(catfp), 16);
  pycatfmodeoct = oct(pycatfmode);
  pycatfchmod = int("0"+str(pycatfmode)[-3:]);
  pycatfuid = int(ReadTillNullByte(catfp), 16);
  pycatfgid = int(ReadTillNullByte(catfp), 16);
  pycatfcs = int(ReadTillNullByte(catfp), 16);
  pycatfcontents = catfp.read(pycatfsize);
  if(pycatftype==0):
   print(pycatfname);
   os.mkdir(pycatfname, pycatfchmod);
   if(hasattr(os, "chown")):
    os.chown(pycatfname, pycatfuid, pycatfgid);
   os.chmod(pycatfname, pycatfchmod);
   os.utime(pycatfname, (pycatfatime, pycatfmtime));
  if(pycatftype==1):
   fpc = open(pycatfname, "wb");
   fcontents = fpc.write(pycatfcontents);
   fpc.close();
   if(hasattr(os, "chown")):
    os.chown(pycatfname, pycatfuid, pycatfgid);
   os.chmod(pycatfname, pycatfchmod);
   os.utime(pycatfname, (pycatfatime, pycatfmtime));
  if(pycatftype==2):
   os.symlink(pycatflinkname, pycatfname);
  if(pycatftype==3):
   os.link(pycatflinkname, pycatfname);
  catfp.seek(1, 1);
 catfp.close();
 return True;
'''
if __name__ == '__main__':
 should_extract = False;
 should_create = True;
 if(getargs.extract is False and getargs.create is True):
  should_create = True;
  should_extract = False;
 if(getargs.extract is True and getargs.create is False):
  should_create = False;
  should_extract = True;
 if(getargs.extract is True and getargs.create is True):
  should_create = True;
  should_extract = False;
 if(getargs.extract is False and getargs.create is False):
  should_create = True;
  should_extract = False;
 if(should_create is True and should_extract is False):
  PyCatFile(getargs.input, getargs.output, getargs.verbose);
 if(should_create is False and should_extract is True):
  PyUnCatFile(getargs.input, getargs.output, getargs.verbose);
'''
PyUnCatFile("./iDB.cat", "./iDB", True);
