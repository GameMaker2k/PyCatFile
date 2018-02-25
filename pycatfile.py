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
    $FileInfo: pycatfile.py - Last Update: 2/25/2018 Ver. 0.0.1 RC 1 - Author: cooldude2k $
'''

__program_name__ = "PyCatFile";
__project__ = __program_name__;
__project_url__ = "https://github.com/GameMaker2k/PyCatFile";
__version_info__ = (0, 0, 1, "RC 1", 1);
__version_date_info__ = (2018, 2, 25, "RC 1", 1);
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
  fmaxintsize = 0;
  fmaxintsizehex = format(fmaxintsize, 'x').upper();
  fnameintsize = len(fname);
  fnameintsizehex = format(fnameintsize, 'x').upper();
  if(fnameintsize>fmaxintsize):
   fmaxintsize = fnameintsize;
  if(ftype==0):
   fsize = format(int("0"), 'x').upper();
   fsizeintsize = len(fsize);
   fsizeintsizehex = format(fsizeintsize, 'x').upper();
  if(ftype==1):
   fsize = format(int(fstatinfo.st_size), 'x').upper();
   fsizeintsize = len(fsize);
   fsizeintsizehex = format(fsizeintsize, 'x').upper();
  if(ftype==2 or ftype=="3"):
   fsize = format(int("0"), 'x').upper();
   fsizeintsize = len(fsize);
   fsizeintsizehex = format(fsizeintsize, 'x').upper();
  flinkname = "";
  if(ftype==2 or ftype==3):
   flinkname = os.readlink(fname);
  flinknameintsize = len(flinkname);
  flinknameintsizehex = format(flinknameintsize, 'x').upper();
  if(flinknameintsize>fmaxintsize):
   fmaxintsize = flinknameintsize;
  if(fsizeintsize>fmaxintsize):
   fmaxintsize = fsizeintsize;
  fatime = format(int(fstatinfo.st_atime), 'x').upper();
  fatimeintsize = len(fatime);
  fatimeintsizehex = format(fatimeintsize, 'x').upper();
  if(fatimeintsize>fmaxintsize):
   fmaxintsize = fatimeintsize;
  fmtime = format(int(fstatinfo.st_mtime), 'x').upper();
  fmtimeintsize = len(fmtime);
  fmtimeintsizehex = format(fmtimeintsize, 'x').upper();
  if(fmtimeintsize>fmaxintsize):
   fmaxintsize = fmtimeintsize;
  fmode = format(int(fstatinfo.st_mode), 'x').upper();
  fmodeintsize = len(fmode);
  fmodeintsizehex = format(fmodeintsize, 'x').upper();
  if(fmodeintsize>fmaxintsize):
   fmaxintsize = fmodeintsize;
  fuid = format(int(fstatinfo.st_uid), 'x').upper();
  fuidintsize = len(fuid);
  fuidintsizehex = format(fuidintsize, 'x').upper();
  if(fuidintsize>fmaxintsize):
   fmaxintsize = fuidintsize;
  fgid = format(int(fstatinfo.st_gid), 'x').upper();
  fgidintsize = len(fgid);
  fgidintsizehex = format(fgidintsize, 'x').upper();
  if(fgidintsize>fmaxintsize):
   fmaxintsize = fgidintsize;
  fmaxintsizehex = format(fmaxintsize, 'x').upper();
  fileheaderintsize = len(fmaxintsizehex);
  fileheaderintsizehex = format(fileheaderintsize, 'x').upper();
  fileheaderintsizehex = fileheaderintsizehex.rjust(2, "0");
  if(len(fileheaderintsizehex)>2):
   fileheaderintsizehex = mystr[-2:];
   fileheaderintsize = int(fileheaderintsizehex, 16);
  fnameintsizehexout = fnameintsizehex.rjust(fileheaderintsize, "0");
  fnameoutstr = fnameintsizehexout+fname;
  fsizeintsizehexout = fsizeintsizehex.rjust(fileheaderintsize, "0");
  fsizeoutstr = fsizeintsizehexout+str(fsize);
  flinknameintsizehexout = flinknameintsizehex.rjust(fileheaderintsize, "0");
  flinknameoutstr = flinknameintsizehexout+flinkname;
  fatimeintsizehexout = fatimeintsizehex.rjust(fileheaderintsize, "0");
  fatimeoutstr = fatimeintsizehexout+str(fatime);
  fmtimeintsizehexout = fmtimeintsizehex.rjust(fileheaderintsize, "0");
  fmtimeoutstr = fmtimeintsizehexout+str(fmtime);
  fmodeintsizehexout = fmodeintsizehex.rjust(fileheaderintsize, "0");
  fmodeoutstr = fmodeintsizehexout+str(fmode);
  fuidintsizehexout = fuidintsizehex.rjust(fileheaderintsize, "0");
  fuidoutstr = fuidintsizehexout+fuid;
  fgidintsizehexout = fgidintsizehex.rjust(fileheaderintsize, "0");
  fgidoutstr = fgidintsizehexout+fgid;
  fcontents = "".encode();
  if(ftype==1):
   fpc = open(fname, "rb");
   fcontents = fpc.read(int(fstatinfo.st_size));
   fpc.close();
  ftypehex = format(ftype, 'x').upper();
  ftypeoutstr = str(ftypehex).rjust(2, "0");
  catfileoutstr = ftypeoutstr+"\0"+fileheaderintsizehex+"\0";
  catfileoutstr = catfileoutstr+fnameoutstr+"\0";
  catfileoutstr = catfileoutstr+fsizeoutstr+"\0";
  catfileoutstr = catfileoutstr+flinknameoutstr+"\0";
  catfileoutstr = catfileoutstr+fatimeoutstr+"\0";
  catfileoutstr = catfileoutstr+fmtimeoutstr+"\0";
  catfileoutstr = catfileoutstr+fmodeoutstr+"\0";
  catfileoutstr = catfileoutstr+fuidoutstr+"\0";
  catfileoutstr = catfileoutstr+fgidoutstr+"\0";
  catfileheadercshex = format(zlib.crc32(catfileoutstr.encode()), 'x').upper();
  catfileheadercshexintsize = len(catfileheadercshex);
  catfileheadercshexintsizehex = format(catfileheadercshexintsize, 'x').upper();
  catfileheadercshexintsizehex = catfileheadercshexintsizehex.rjust(fileheaderintsize, "0");
  catfileoutstr = catfileoutstr+catfileheadercshexintsizehex+catfileheadercshex+"\0";
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
 pycatver = int(catfp.read(2).decode('ascii'), 16);
 catfp.seek(1, 1);
 while(catfp.tell()<CatSizeEnd):
  pycatftype = int(catfp.read(2).decode('ascii'), 16);
  catfp.seek(1, 1);
  pycatfmsize = int(catfp.read(2).decode('ascii'), 16);
  catfp.seek(1, 1);
  pycatfnamesize = int(catfp.read(pycatfmsize).decode('ascii'), 16);
  pycatfname = catfp.read(pycatfnamesize).decode('ascii');
  if(verbose is True):
   logging.info(pycatfname);
  catfp.seek(1, 1);
  pycatfsizesize = int(catfp.read(pycatfmsize).decode('ascii'), 16);
  pycatfsize = int(catfp.read(pycatfsizesize).decode('ascii'), 16);
  catfp.seek(1, 1);
  pycatflinknamesize = int(catfp.read(pycatfmsize).decode('ascii'), 16);
  pycatflinkname = catfp.read(pycatflinknamesize).decode('ascii');
  catfp.seek(1, 1);
  pycatfatimesize = int(catfp.read(pycatfmsize).decode('ascii'), 16);
  pycatfatime = int(catfp.read(pycatfatimesize).decode('ascii'), 16);
  catfp.seek(1, 1);
  pycatfmtimesize = int(catfp.read(pycatfmsize).decode('ascii'), 16);
  pycatfmtime = int(catfp.read(pycatfmtimesize).decode('ascii'), 16);
  catfp.seek(1, 1);
  pycatfmodesize = int(catfp.read(pycatfmsize).decode('ascii'), 16);
  pycatfmode = int(catfp.read(pycatfmodesize).decode('ascii'), 16);
  pycatfmodeoct = oct(pycatfmode);
  pycatfchmod = int("0"+str(pycatfmode)[-3:]);
  catfp.seek(1, 1);
  pycatfuidsize = int(catfp.read(pycatfmsize).decode('ascii'), 16);
  pycatfuid = int(catfp.read(pycatfuidsize).decode('ascii'), 16);
  catfp.seek(1, 1);
  pycatfgidsize = int(catfp.read(pycatfmsize).decode('ascii'), 16);
  pycatfgid = int(catfp.read(pycatfgidsize).decode('ascii'), 16);
  catfp.seek(1, 1);
  pycatfcssize = int(catfp.read(pycatfmsize).decode('ascii'), 16);
  pycatfcs = int(catfp.read(pycatfcssize).decode('ascii'), 16);
  catfp.seek(1, 1);
  pycatfcontents = catfp.read(pycatfsize);
  if(pycatftype==0):
   print(pycatfname);
   os.mkdir(pycatfname);
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
