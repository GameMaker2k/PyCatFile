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
    $FileInfo: pycatfile.py - Last Update: 2/24/2018 Ver. 0.0.1 RC 1 - Author: cooldude2k $
'''

__program_name__ = "PyCatFile";
__project__ = __program_name__;
__project_url__ = "https://github.com/GameMaker2k/PyCatFile";
__version_info__ = (0, 0, 1, "RC 1", 1);
__version_date_info__ = (2018, 2, 24, "RC 1", 1);
__version_date__ = str(__version_date_info__[0])+"."+str(__version_date_info__[1]).zfill(2)+"."+str(__version_date_info__[2]).zfill(2);
if(__version_info__[4] is not None):
 __version_date_plusrc__ = __version_date__+"-"+str(__version_date_info__[4]);
if(__version_info__[4] is None):
 __version_date_plusrc__ = __version_date__;
if(__version_info__[3] is not None):
 __version__ = str(__version_info__[0])+"."+str(__version_info__[1])+"."+str(__version_info__[2])+" "+str(__version_info__[3]);
if(__version_info__[3] is None):
 __version__ = str(__version_info__[0])+"."+str(__version_info__[1])+"."+str(__version_info__[2]);

import os, glob;

def ListDir(dirpath):
 retlist = [];
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

def PyCatFile(infiles, outfile):
 catfp = open(outfile, "wb+");
 fileheaderver = "00";
 fileheader = "CatFile"+fileheaderver;
 catfp.write(fileheader.encode());
 GetDirList = ListDir(infiles);
 for curfname in GetDirList:
  fname = curfname;
  fstatinfo = os.stat(fname);
  ftype = "0";
  if(os.path.isdir(fname)):
   ftype = "0";
  if(os.path.isfile(fname)):
   ftype = "1";
  if(os.path.islink(fname)):
   ftype = "2";
  fmaxintsize = 0;
  fmaxintsizehex = format(fmaxintsize, 'x').upper();
  fnameintsize = len(fname);
  fnameintsizehex = format(fnameintsize, 'x').upper();
  if(fnameintsize>fmaxintsize):
   fmaxintsize = fnameintsize;
  if(ftype=="0"):
   fsize = format(int("0"), 'x').upper();
   fsizeintsize = len(fsize);
   fsizeintsizehex = format(fsizeintsize, 'x').upper();
  if(ftype=="1"):
   fsize = format(int(fstatinfo.st_size), 'x').upper();
   fsizeintsize = len(fsize);
   fsizeintsizehex = format(fsizeintsize, 'x').upper();
  if(ftype=="2"):
   fsize = format(int(os.readlink(fname)), 'x').upper();
   fsizeintsize = len(fsize);
   fsizeintsizehex = format(fsizeintsize, 'x').upper();
  if(fsizeintsize>fmaxintsize):
   fmaxintsize = fsizeintsize;
  fctime = format(int(fstatinfo.st_ctime), 'x').upper();
  fctimeintsize = len(fctime);
  fctimeintsizehex = format(fctimeintsize, 'x').upper();
  if(fctimeintsize>fmaxintsize):
   fmaxintsize = fctimeintsize;
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
  fsizeintsizehexout = fsizeintsizehex.rjust(fileheaderintsize, "0");
  fctimeintsizehexout = fctimeintsizehex.rjust(fileheaderintsize, "0");
  fatimeintsizehexout = fatimeintsizehex.rjust(fileheaderintsize, "0");
  fmtimeintsizehexout = fmtimeintsizehex.rjust(fileheaderintsize, "0");
  fmodeintsizehexout = fmodeintsizehex.rjust(fileheaderintsize, "0");
  fuidintsizehexout = fuidintsizehex.rjust(fileheaderintsize, "0");
  fgidintsizehexout = fgidintsizehex.rjust(fileheaderintsize, "0");
  fcontents = "".encode();
  if(ftype=="1"):
   fpc = open(fname, "rb");
   fcontents = fpc.read(int(fstatinfo.st_size));
   fpc.close();
  if(ftype=="2"):
   fcontents = str(os.readlink(fname)).encode();
  catfileout = str("\0"+ftype+fileheaderintsizehex+"\0"+fnameintsizehexout+fname+"\0"+fsizeintsizehexout+str(fsize)+"\0"+fctimeintsizehexout+str(fctime)+"\0"+fatimeintsizehexout+str(fatime)+"\0"+fmtimeintsizehexout+str(fmtime)+"\0"+fmodeintsizehexout+str(fmode)+"\0"+fuidintsizehexout+str(fuid)+"\0"+fgidintsizehexout+str(fgid)+"\0").encode();
  catfileout = catfileout+fcontents;
  catfp.write(catfileout);
 catfp.close();
 return True;

def PyUnCatFile(infile, outfiles=None):
 catfp = open(infile, "rb");
 catfp.seek(0, 2);
 CatSize = catfp.tell();
 CatSizeEnd = CatSize;
 catfp.seek(0, 0);
 pycatstring = catfp.read(7).decode('ascii');
 pycatver = int(catfp.read(2).decode('ascii'), 16);
 while(catfp.tell()<CatSizeEnd):
  catfp.seek(1, 1);
  pycatftype = int(catfp.read(1).decode('ascii'), 16);
  pycatfmsize = int(catfp.read(2).decode('ascii'), 16);
  catfp.seek(1, 1);
  pycatfnamesize = int(catfp.read(pycatfmsize).decode('ascii'), 16);
  pycatfname = catfp.read(pycatfnamesize).decode('ascii');
  catfp.seek(1, 1);
  pycatfsizesize = int(catfp.read(pycatfmsize).decode('ascii'), 16);
  pycatfsize = int(catfp.read(pycatfsizesize).decode('ascii'), 16);
  catfp.seek(1, 1);
  pycatfctimesize = int(catfp.read(pycatfmsize).decode('ascii'), 16);
  pycatfctime = int(catfp.read(pycatfctimesize).decode('ascii'), 16);
  catfp.seek(1, 1);
  pycatfatimesize = int(catfp.read(pycatfmsize).decode('ascii'), 16);
  pycatfatime = int(catfp.read(pycatfatimesize).decode('ascii'), 16);
  catfp.seek(1, 1);
  pycatfmtimesize = int(catfp.read(pycatfmsize).decode('ascii'), 16);
  pycatfmtime = int(catfp.read(pycatfmtimesize).decode('ascii'), 16);
  catfp.seek(1, 1);
  pycatfmodesize = int(catfp.read(pycatfmsize).decode('ascii'), 16);
  pycatfmode = int(catfp.read(pycatfmodesize).decode('ascii'), 16);
  catfp.seek(1, 1);
  pycatfmodeoct = oct(pycatfmode);
  pycatfuidsize = int(catfp.read(pycatfmsize).decode('ascii'), 16);
  pycatfuid = int(catfp.read(pycatfuidsize).decode('ascii'), 16);
  catfp.seek(1, 1);
  pycatfgidsize = int(catfp.read(pycatfmsize).decode('ascii'), 16);
  pycatfgid = int(catfp.read(pycatfgidsize).decode('ascii'), 16);
  catfp.seek(1, 1);
  pycatfcontents = catfp.read(pycatfsize);
  if(pycatftype==0):
   print(pycatfname);
   os.mkdir(pycatfname);
  if(pycatftype==1):
   fpc = open(pycatfname, "wb+");
   fcontents = fpc.write(pycatfcontents);
   fpc.close();
  if(pycatftype==2):
   os.symlink(pycatfcontents.decode('ascii'), pycatfname);
 catfp.close();
 return True;
