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

	$FileInfo: pycatfile.py - Last Update: 2/28/2018 Ver. 0.0.1 RC 1 - Author: cooldude2k $
'''

__program_name__ = "PyCatFile";
__project__ = __program_name__;
__project_url__ = "https://github.com/GameMaker2k/PyCatFile";
__version_info__ = (0, 0, 1, "RC 1", 1);
__version_date_info__ = (2018, 2, 28, "RC 1", 1);
__version_date__ = str(__version_date_info__[0])+"."+str(__version_date_info__[1]).zfill(2)+"."+str(__version_date_info__[2]).zfill(2);
if(__version_info__[4] is not None):
 __version_date_plusrc__ = __version_date__+"-"+str(__version_date_info__[4]);
if(__version_info__[4] is None):
 __version_date_plusrc__ = __version_date__;
if(__version_info__[3] is not None):
 __version__ = str(__version_info__[0])+"."+str(__version_info__[1])+"."+str(__version_info__[2])+" "+str(__version_info__[3]);
if(__version_info__[3] is None):
 __version__ = str(__version_info__[0])+"."+str(__version_info__[1])+"."+str(__version_info__[2]);

import os, sys, tarfile, logging, zlib;

def PyCatFromTarFile(infile, outfile, verbose=False):
 tarinput = tarfile.open(infile, "r");
 tarfiles = tarinput.getmembers();
 if(verbose is True):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(os.path.exists(outfile)):
  os.remove(outfile);
 catfp = open(outfile, "wb");
 pycatver = str(__version_info__[0])+str(__version_info__[1])+str(__version_info__[2]);
 fileheaderver = str(int(pycatver.replace(".", "")));
 fileheader = "CatFile"+fileheaderver+"\0";
 catfp.write(fileheader.encode());
 for curfname in tarfiles:
  fname = curfname.name;
  if(verbose is True):
   logging.info(fname);
  ftype = 0;
  if(curfname.isdir()):
   ftype = 0;
  if(curfname.isfile()):
   ftype = 1;
  if(curfname.issym()):
   ftype = 2;
  if(curfname.islnk()):
   ftype = 3;
  if(ftype==0 or ftype==2 or ftype==3):
   fsize = format(int("0"), 'x').upper();
  if(ftype==1):
   fsize = format(int(curfname.size), 'x').upper();
  flinkname = "";
  if(ftype==2 or ftype==3):
   flinkname = curfname.linkname;
  fatime = format(int(curfname.mtime), 'x').upper();
  fmtime = format(int(curfname.mtime), 'x').upper();
  fmode = format(int(curfname.mode), 'x').upper();
  fuid = format(int(curfname.uid), 'x').upper();
  fgid = format(int(curfname.gid), 'x').upper();
  fcontents = "".encode();
  if(ftype==1):
   fpc = tarinput.extractfile(curfname);
   fcontents = fpc.read(int(curfname.size));
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
 tarinput.close();
 return True;

def PHPCatFromTarFile(infile, outfile, verbose=False):
return PyCatFromTarFile(infile, outfile, verbose):

PyCatFromTarFile("./iDB.tar", "./iDB.cat", True);
