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

    $FileInfo: catfile.py - Last Update: 3/8/2018 Ver. 0.0.1 RC 1 - Author: cooldude2k $
'''

from __future__ import absolute_import, division, print_function, unicode_literals;
import sys, argparse, logging, pycatfile;

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

__project__ = pycatfile.__project__;
__program_name__ = pycatfile.__program_name__;
__project_url__ = pycatfile.__project_url__;
__version_info__ = pycatfile.__version_info__;
__version_date_info__ = pycatfile.__version_date_info__;
__version_date__ = pycatfile.__version_date__;
__version_date_plusrc__ = pycatfile.__version_date_plusrc__
__version__ = pycatfile.__version__;
__version_date_plusrc__ = pycatfile.__version_date_plusrc__;
tarsupport = pycatfile.tarsupport;

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
 if(getargs.verbose is True):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
if(should_create is True and should_extract is False and should_list is False and should_repack is False and should_convert is False):
 if(getargs.output=="-"):
   pycatout = pycatfile.PackCatFile(getargs.input, getargs.output, False, getargs.checksum, False, False);
   sys.stdout.buffer.write(pycatout.read());
   pycatout.close();
 else:
  pycatfile.PackCatFile(getargs.input, getargs.output, False, getargs.checksum, getargs.verbose, False);
if(should_create is True and should_extract is False and should_list is False and should_repack is False and should_convert is True):
 inputfile = getargs.input;
 if(inputfile=="-"):
  inputfile = BytesIO();
  if(hasattr(sys.stdin, "buffer")):
   for line in sys.stdin.buffer:
    inputfile.write(line);
  else:
   for line in sys.stdin:
    inputfile.write(line);
  inputfile.seek(0, 0);
 if(getargs.output=="-"):
   pycatout = pycatfile.PackCatFileFromTarFile(inputfile, getargs.output, getargs.checksum, getargs.verbose, False);
   sys.stdout.buffer.write(pycatout.read());
   pycatout.close();
 else:
  pycatfile.PackCatFileFromTarFile(inputfile, getargs.output, getargs.checksum, getargs.verbose, False);
if(should_create is True and should_extract is False and should_list is False and should_repack is True and should_convert is False):
 inputfile = getargs.input;
 if(inputfile=="-"):
  inputfile = BytesIO();
  if(hasattr(sys.stdin, "buffer")):
   for line in sys.stdin.buffer:
    inputfile.write(line);
  else:
   for line in sys.stdin:
    inputfile.write(line);
  compresscheck = pycatfile.CheckFileType(inputfile, False);
  if(compresscheck=="gzip"):
   import gzip;
   inputfile = gzip.GzipFile(fileobj=inputfile, mode="rb");
  inputfile.seek(0, 0);
 if(getargs.output=="-"):
   pycatout = pycatfile.RePackCatFile(inputfile, getargs.output, 0, 0, getargs.checksum, False, getargs.verbose, False);
   sys.stdout.buffer.write(pycatout.read());
   pycatout.close();
 else:
  pycatfile.RePackCatFile(inputfile, getargs.output, 0, 0, getargs.checksum, False, getargs.verbose, False);
if(should_create is False and should_extract is True and should_list is False):
 inputfile = getargs.input;
 if(inputfile=="-"):
  inputfile = BytesIO();
  if(hasattr(sys.stdin, "buffer")):
   for line in sys.stdin.buffer:
    inputfile.write(line);
  else:
   for line in sys.stdin:
    inputfile.write(line);
  compresscheck = pycatfile.CheckFileType(inputfile, False);
  if(compresscheck=="gzip"):
   import gzip;
   inputfile = gzip.GzipFile(fileobj=inputfile, mode="rb");
  inputfile.seek(0, 0);
 pycatfile.UnPackCatFile(inputfile, getargs.output, False, getargs.verbose, False);
if(should_create is False and should_extract is False and should_list is True):
 inputfile = getargs.input;
 if(inputfile=="-"):
  inputfile = BytesIO();
  if(hasattr(sys.stdin, "buffer")):
   for line in sys.stdin.buffer:
    inputfile.write(line);
  else:
   for line in sys.stdin:
    inputfile.write(line);
  compresscheck = pycatfile.CheckFileType(inputfile, False);
  if(compresscheck=="gzip"):
   import gzip;
   inputfile = gzip.GzipFile(fileobj=inputfile, mode="rb");
  inputfile.seek(0, 0);
 pycatfile.CatFileListFiles(inputfile, 0, 0, False, getargs.verbose, False);
