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

	$FileInfo: pycatfile.py - Last Update: 3/1/2018 Ver. 0.0.1 RC 1 - Author: cooldude2k $
'''

__program_name__ = "PyCatFile";
__project__ = __program_name__;
__project_url__ = "https://github.com/GameMaker2k/PyCatFile";
__version_info__ = (0, 0, 1, "RC 1", 1);
__version_date_info__ = (2018, 3, 1, "RC 1", 1);
__version_date__ = str(__version_date_info__[0])+"."+str(__version_date_info__[1]).zfill(2)+"."+str(__version_date_info__[2]).zfill(2);
if(__version_info__[4] is not None):
 __version_date_plusrc__ = __version_date__+"-"+str(__version_date_info__[4]);
if(__version_info__[4] is None):
 __version_date_plusrc__ = __version_date__;
if(__version_info__[3] is not None):
 __version__ = str(__version_info__[0])+"."+str(__version_info__[1])+"."+str(__version_info__[2])+" "+str(__version_info__[3]);
if(__version_info__[3] is None):
 __version__ = str(__version_info__[0])+"."+str(__version_info__[1])+"."+str(__version_info__[2]);

import os, sys, stat, logging, zlib, datetime;

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
 argparser.add_argument("-V", "--version", action="version", version=__program_name__+" "+__version__);
 argparser.add_argument("-i", "-f", "--input", help="files to concatenate or concatenate file extract", required=True);
 argparser.add_argument("-d", "-v", "--verbose", action="store_true", help="print various debugging information");
 argparser.add_argument("-c", "--create", action="store_true", help="concatenate files only");
 if(tarsupport is True):
  argparser.add_argument("-tar", "--tar", action="store_true", help="convert from tar file");
 argparser.add_argument("-e", "-x", "--extract", action="store_true", help="extract files only");
 argparser.add_argument("-l", "-t", "--list", action="store_true", help="list files only");
 argparser.add_argument("-o", "--output", default=None, help="extract concatenate files to or concatenate output name");
 getargs = argparser.parse_args();

def RemoveWindowsPath(dpath):
 if(os.sep!="/"):
  dpath = dpath.replace(os.path.sep, "/");
 dpath = dpath.rstrip("/");
 if(dpath=="." or dpath==".."):
  dpath = dpath+"/";
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
   curfullbyte = curfullbyte+curbyted;
 return curfullbyte;

def ReadUntilNullByte(fp):
 return ReadTillNullByte(fp);

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

def PyCatFile(infiles, outfile, verbose=False):
 infiles = RemoveWindowsPath(infiles);
 outfile = RemoveWindowsPath(outfile);
 if(verbose is True):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(os.path.exists(outfile)):
  os.remove(outfile);
 catfp = open(outfile, "wb");
 pycatver = str(__version_info__[0])+str(__version_info__[1])+str(__version_info__[2]);
 fileheaderver = str(int(pycatver.replace(".", "")));
 fileheader = "CatFile"+fileheaderver+"\0";
 catfp.write(fileheader.encode());
 GetDirList = ListDir(infiles);
 for curfname in GetDirList:
  fname = curfname;
  if(verbose is True):
   logging.info(fname);
  fstatinfo = os.lstat(fname);
  fpremode = fstatinfo.st_mode;
  ftype = 0;
  if(stat.S_ISDIR(fpremode)):
   ftype = 0;
   fdev = fstatinfo.st_dev;
   getfdev = GetDevMajorMinor(fdev);
   fdev_minor = getfdev[0];
   fdev_major = getfdev[1];
  if(stat.S_ISREG(fpremode)):
   ftype = 1;
   fdev = fstatinfo.st_dev;
   fdev_minor = getfdev[0];
   fdev_major = getfdev[1];
  if(stat.S_ISLNK(fpremode)):
   ftype = 2;
   fdev = fstatinfo.st_dev;
   fdev_minor = getfdev[0];
   fdev_major = getfdev[1];
  if(stat.S_ISCHR(fpremode)):
   ftype = 3;
   fdev = fstatinfo.st_dev;
   fdev_minor = getfdev[0];
   fdev_major = getfdev[1];
  if(stat.S_ISBLK(fpremode)):
   ftype = 4;
   fdev = fstatinfo.st_dev;
   fdev_minor = getfdev[0];
   fdev_major = getfdev[1];
  if(stat.S_ISFIFO(fpremode)):
   ftype = 5;
   fdev = fstatinfo.st_dev;
   fdev_minor = getfdev[0];
   fdev_major = getfdev[1];
  if(ftype==0 or ftype==2 or ftype==3 or ftype==4 or ftype==5 or ftype==6):
   fsize = format(int("0"), 'x').upper();
  if(ftype==1):
   fsize = format(int(fstatinfo.st_size), 'x').upper();
  flinkname = "";
  if(ftype==2 or ftype==3):
   flinkname = os.readlink(fname);
  fatime = format(int(fstatinfo.st_atime), 'x').upper();
  fmtime = format(int(fstatinfo.st_mtime), 'x').upper();
  fmode = format(int(fstatinfo.st_mode), 'x').upper();
  fuid = format(int(fstatinfo.st_uid), 'x').upper();
  fgid = format(int(fstatinfo.st_gid), 'x').upper();
  fdev_minor = format(int(fdev_minor), 'x').upper();
  fdev_major = format(int(fdev_major), 'x').upper();
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
  catfileoutstr = catfileoutstr+str(fdev_minor)+"\0";
  catfileoutstr = catfileoutstr+str(fdev_major)+"\0";
  catfileheadercshex = format(zlib.crc32(catfileoutstr.encode()), 'x').upper();
  catfileoutstr = catfileoutstr+catfileheadercshex+"\0";
  catfileoutstrecd = catfileoutstr.encode();
  nullstrecd = "\0".encode();
  catfileout = catfileoutstrecd+fcontents+nullstrecd;
  catfp.write(catfileout);
 catfp.close();
 return True;

def PHPCatFile(infiles, outfile, verbose=False):
 return PyCatFile(infiles, outfile, verbose);

if(tarsupport is True):
 def PyCatFromTarFile(infile, outfile, verbose=False):
  infile = RemoveWindowsPath(infile);
  outfile = RemoveWindowsPath(outfile);
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
   if(curfname.ischr()):
    ftype = 4;
   if(curfname.isblk()):
    ftype = 5;
   if(curfname.isfifo()):
    ftype = 6;
   if(ftype==0 or ftype==2 or ftype==3 or ftype==4 or ftype==5 or ftype==6):
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
   fdev_minor = format(int(curfname.devminor), 'x').upper();
   fdev_major = format(int(curfname.devmajor), 'x').upper();
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
   catfileoutstr = catfileoutstr+str(fdev_minor)+"\0";
   catfileoutstr = catfileoutstr+str(fdev_major)+"\0";
   catfileheadercshex = format(zlib.crc32(catfileoutstr.encode()), 'x').upper();
   catfileoutstr = catfileoutstr+catfileheadercshex+"\0";
   catfileoutstrecd = catfileoutstr.encode();
   nullstrecd = "\0".encode();
   catfileout = catfileoutstrecd+fcontents+nullstrecd;
   catfp.write(catfileout);
  catfp.close();
  tarinput.close();
  return True;

if(tarsupport is True):
 def PHPCatFromTarFile(infile, outfile, verbose=False):
  return PyCatFromTarFile(infile, outfile, verbose);

def PyCatToArray(infile, seekstart=0, seekend=0, listonly=False):
 infile = RemoveWindowsPath(infile);
 catfp = open(infile, "rb");
 catfp.seek(0, 2);
 CatSize = catfp.tell();
 CatSizeEnd = CatSize;
 catfp.seek(0, 0);
 pycatstring = ReadTillNullByte(catfp);
 pycatlist = {};
 fileidnum = 0;
 if(seekstart!=0):
  catfp.seek(seekstart, 0);
 if(seekstart==0):
  seekstart = catfp.tell();
 if(seekend==0):
  seekend = CatSizeEnd;
 while(seekstart<seekend):
  pycatfhstart = catfp.tell();
  pycatftype = int(ReadTillNullByte(catfp), 16);
  pycatfname = ReadTillNullByte(catfp);
  pycatfsize = int(ReadTillNullByte(catfp), 16);
  pycatflinkname = ReadTillNullByte(catfp);
  pycatfatime = int(ReadTillNullByte(catfp), 16);
  pycatfmtime = int(ReadTillNullByte(catfp), 16);
  pycatfmode = oct(int(ReadTillNullByte(catfp), 16));
  pycatprefchmod = oct(int(pycatfmode[-3:], 8));
  pycatfchmod = pycatprefchmod;
  pycatfuid = int(ReadTillNullByte(catfp), 16);
  pycatfgid = int(ReadTillNullByte(catfp), 16);
  pycatfdev_minor = int(ReadTillNullByte(catfp), 16);
  pycatfdev_major = int(ReadTillNullByte(catfp), 16);
  pycatfcs = int(ReadTillNullByte(catfp), 16);
  pycatfhend = catfp.tell() - 1;
  pycatfcontentstart = catfp.tell();
  pycatfcontents = "";
  pyhascontents = False;
  if(pycatfsize>1 and listonly is False):
   pycatfcontents = catfp.read(pycatfsize);
   pyhascontents = True;
  if(pycatfsize>1 and listonly is True):
   catfp.seek(pycatfsize, 1);
   pyhascontents = False;
  pycatfcontentend = catfp.tell();
  pycatlist.update({fileidnum: {'fid': fileidnum, 'fhstart': pycatfhstart, 'fhend': pycatfhend, 'ftype': pycatftype, 'fname': pycatfname, 'fsize': pycatfsize, 'flinkname': pycatflinkname, 'fatime': pycatfatime, 'fmtime': pycatfmtime, 'fmode': pycatfmode, 'fchmod': pycatfchmod, 'fuid': pycatfuid, 'fgid': pycatfgid, 'fminor': pycatfdev_minor, 'fmajor': pycatfdev_major, 'fchecksum': pycatfcs, 'fhascontents': pyhascontents, 'fcontentstart': pycatfcontentstart, 'fcontentend': pycatfcontentend, 'fcontents': pycatfcontents} });
  catfp.seek(1, 1);
  seekstart = catfp.tell();
  fileidnum = fileidnum + 1;
 catfp.close();
 return pycatlist;

def PHPCatToArray(infile, seekstart=0, seekend=0, listonly=False):
 return PyCatToArray(infile, seekstart, seekend, listonly);

def PyCatArrayIndex(infile, seekstart=0, seekend=0, listonly=False):
 infile = RemoveWindowsPath(infile);
 listcatfiles = PyCatToArray(infile, seekstart, seekend, listonly);
 pycatarray = {'list': listcatfiles, 'filetoid': {}, 'idtofile': {}, 'filetypes': {'directories': {'filetoid': {}, 'idtofile': {}}, 'files': {'filetoid': {}, 'idtofile': {}}, 'filesalt': {'filetoid': {}, 'idtofile': {}}, 'symlinks': {'filetoid': {}, 'idtofile': {}}, 'hardlinks': {'filetoid': {}, 'idtofile': {}}}};
 lcfi = 0;
 lcfx = len(listcatfiles);
 while(lcfi < lcfx):
  filetoidarray = {listcatfiles[lcfi]['fname']: listcatfiles[lcfi]['fid']};
  idtofilearray = {listcatfiles[lcfi]['fid']: listcatfiles[lcfi]['fname']};
  pycatarray['filetoid'].update(filetoidarray);
  pycatarray['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==0):
   pycatarray['filetypes']['directories']['filetoid'].update(filetoidarray);
   pycatarray['filetypes']['directories']['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==1):
   pycatarray['filetypes']['files']['filetoid'].update(filetoidarray);
   pycatarray['filetypes']['files']['idtofile'].update(idtofilearray);
   pycatarray['filetypes']['filesalt']['filetoid'].update(filetoidarray);
   pycatarray['filetypes']['filesalt']['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==2):
   pycatarray['filetypes']['symlinks']['filetoid'].update(filetoidarray);
   pycatarray['filetypes']['symlinks']['idtofile'].update(idtofilearray);
   pycatarray['filetypes']['filesalt']['filetoid'].update(filetoidarray);
   pycatarray['filetypes']['filesalt']['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==3):
   pycatarray['filetypes']['hardlinks']['filetoid'].update(filetoidarray);
   pycatarray['filetypes']['hardlinks']['idtofile'].update(idtofilearray);
   pycatarray['filetypes']['filesalt']['filetoid'].update(filetoidarray);
   pycatarray['filetypes']['filesalt']['idtofile'].update(idtofilearray);
  lcfi = lcfi + 1;
 return pycatarray;

def PHPCatArrayIndex(infile, seekstart=0, seekend=0, listonly=False):
 return PyCatArrayIndex(infile, seekstart, seekend, listonly);

def PyUnCatFile(infile, outdir=None, verbose=False):
 infile = RemoveWindowsPath(infile);
 if(outdir is not None):
  outdir = RemoveWindowsPath(outdir);
 if(verbose is True):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 listcatfiles = PyCatToArray(infile, 0, 0, False);
 lcfi = 0;
 lcfx = len(listcatfiles);
 while(lcfi < lcfx):
  if(verbose is True):
   logging.info(listcatfiles[lcfi]['fname']);
  if(listcatfiles[lcfi]['ftype']==0):
   os.mkdir(listcatfiles[lcfi]['fname'], int(listcatfiles[lcfi]['fchmod'], 8));
   if(hasattr(os, "chown")):
    os.chown(listcatfiles[lcfi]['fname'], listcatfiles[lcfi]['fuid'], listcatfiles[lcfi]['fgid']);
   os.chmod(listcatfiles[lcfi]['fname'], int(listcatfiles[lcfi]['fchmod'], 8));
   os.utime(listcatfiles[lcfi]['fname'], (listcatfiles[lcfi]['fatime'], listcatfiles[lcfi]['fmtime']));
  if(listcatfiles[lcfi]['ftype']==1):
   fpc = open(listcatfiles[lcfi]['fname'], "wb");
   fpc.write(listcatfiles[lcfi]['fcontents']);
   fpc.close();
   if(hasattr(os, "chown")):
    os.chown(listcatfiles[lcfi]['fname'], listcatfiles[lcfi]['fuid'], listcatfiles[lcfi]['fgid']);
   os.chmod(listcatfiles[lcfi]['fname'], int(listcatfiles[lcfi]['fchmod'], 8));
   os.utime(listcatfiles[lcfi]['fname'], (listcatfiles[lcfi]['fatime'], listcatfiles[lcfi]['fmtime']));
  if(listcatfiles[lcfi]['ftype']==2):
   os.symlink(listcatfiles[lcfi]['flinkname'], listcatfiles[lcfi]['fname']);
  if(listcatfiles[lcfi]['ftype']==3):
   os.link(listcatfiles[lcfi]['flinkname'], listcatfiles[lcfi]['fname']);
  if(listcatfiles[lcfi]['ftype']==6 and hasattr(os, "mkfifo")):
   os.mkfifo(listcatfiles[lcfi]['fname'], int(listcatfiles[lcfi]['fchmod'], 8));
  lcfi = lcfi + 1;
 return True;

def PHPUnCatFile(infile, outdir=None, verbose=False):
 return PyUnCatFile(infile, outdir, verbose);

def PyCatListFiles(infile, seekstart=0, seekend=0, verbose=False):
 infile = RemoveWindowsPath(infile);
 logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 listcatfiles = PyCatToArray(infile, seekstart, seekend, True);
 lcfi = 0;
 lcfx = len(listcatfiles);
 while(lcfi < lcfx):
  if(verbose is False):
   logging.info(listcatfiles[lcfi]['fname']);
  if(verbose is True):
   permissions = { 'access': { '0': ('---'), '1': ('--x'), '2': ('-w-'), '3': ('-wx'), '4': ('r--'), '5': ('r-x'), '6': ('rw-'), '7': ('rwx') }, 'roles': { 0: 'owner', 1: 'group', 2: 'other' } };
   permissionstr = "";
   for fmodval in str(listcatfiles[lcfi]['fchmod'])[-3:]:
    try:
     permissionstr = permissions['access'][fmodval]+permissionstr;
    except KeyError:
     permissionstr = "---"+permissionstr;
   if(listcatfiles[lcfi]['ftype']==0):
    permissionstr = "d"+permissionstr;
   if(listcatfiles[lcfi]['ftype']==1):
    permissionstr = "-"+permissionstr;
   if(listcatfiles[lcfi]['ftype']==2):
    permissionstr = "s"+permissionstr;
   if(listcatfiles[lcfi]['ftype']==3):
    permissionstr = "l"+permissionstr;
   logging.info(permissionstr+" "+str(str(listcatfiles[lcfi]['fuid'])+"/"+str(listcatfiles[lcfi]['fgid'])+" "+str(listcatfiles[lcfi]['fsize']).rjust(15)+" "+datetime.datetime.utcfromtimestamp(listcatfiles[lcfi]['fmtime']).strftime('%Y-%m-%d %H:%M')+" "+listcatfiles[lcfi]['fname']));
  lcfi = lcfi + 1;
 return True;

def PHPCatListFiles(infile, seekstart=0, seekend=0, verbose=False):
 return PyCatListFiles(infile, seekstart, seekend, verbose);

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
 if(should_create is True and should_extract is False and should_list is False and should_convert is False):
  PyCatFile(getargs.input, getargs.output, getargs.verbose);
 if(should_create is True and should_extract is False and should_list is False and should_convert is True):
  PyCatFromTarFile(getargs.input, getargs.output, getargs.verbose);
 if(should_create is False and should_extract is True and should_list is False):
  PyUnCatFile(getargs.input, getargs.output, getargs.verbose);
 if(should_create is False and should_extract is False and should_list is True):
  PyCatListFiles(getargs.input, 0, 0, getargs.verbose);
