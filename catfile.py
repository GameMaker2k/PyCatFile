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

    $FileInfo: catfile.py - Last Update: 3/12/2018 Ver. 0.0.1 RC 1 - Author: cooldude2k $
'''

from __future__ import absolute_import, division, print_function, unicode_literals;
import sys, logging, argparse, pycatfile;

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
if(tarsupport):
 argparser.add_argument("-tar", "--tar", action="store_true", help="convert from tar file");
argparser.add_argument("-checksum", "--checksum", default="crc32", help="checksum type to use default is crc32");
argparser.add_argument("-e", "-x", "--extract", action="store_true", help="extract files only");
argparser.add_argument("-l", "-t", "--list", action="store_true", help="list files only");
argparser.add_argument("-r", "--repack", action="store_true", help="reconcatenate files only fixing checksum errors");
argparser.add_argument("-o", "--output", default=None, help="extract concatenate files to or concatenate output name");
argparser.add_argument("-compression", "--compression", default="auto", help="concatenate files with compression");
getargs = argparser.parse_args();

should_extract = False;
should_create = True;
should_list = False;
if(not getargs.extract and getargs.create and not getargs.list):
 should_create = True;
 should_extract = False;
 should_list = False;
if(getargs.extract and not getargs.create and not getargs.list):
 should_create = False;
 should_extract = True;
 should_list = False;
if(getargs.extract and getargs.create and not getargs.list):
 should_create = True;
 should_extract = False;
 should_list = False;
if(not getargs.extract and not getargs.create and not getargs.list):
 should_create = True;
 should_extract = False;
 should_list = False;
if(not getargs.extract and getargs.create and getargs.list):
 should_create = True;
 should_extract = False;
 should_list = False;
if(getargs.extract and not getargs.create and getargs.list):
 should_create = False;
 should_extract = True;
 should_list = False;
if(getargs.extract and getargs.create and getargs.list):
 should_create = True;
 should_extract = False;
 should_list = False;
if(not getargs.extract and not getargs.create and getargs.list):
 should_create = False;
 should_extract = False;
 should_list = True;
should_convert = False;
if(should_create and getargs.tar):
 should_convert = True;
if(not tarsupport and should_convert):
 should_convert = False;
should_repack = False;
if(should_create and not getargs.tar and getargs.repack):
 should_repack = True;
if(getargs.verbose):
 logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
if(should_create and not should_extract and not should_list and not should_repack and not should_convert):
 pycatfile.PackCatFile(getargs.input, getargs.output, getargs.compression, False, getargs.checksum, getargs.verbose, False);
if(should_create and not should_extract and not should_list and not should_repack and should_convert):
 pycatfile.PackCatFileFromTarFile(getargs.input, getargs.output, getargs.compression, getargs.checksum, getargs.verbose, False);
if(should_create and not should_extract and not should_list and should_repack and not should_convert):
 pycatfile.RePackCatFile(getargs.input, getargs.output, 0, 0, getargs.compression, getargs.checksum, False, getargs.verbose, False);
if(not should_create and should_extract and not should_list):
 pycatfile.UnPackCatFile(getargs.input, getargs.output, False, getargs.verbose, False);
if(not should_create and not should_extract and should_list):
 pycatfile.CatFileListFiles(getargs.input, 0, 0, False, getargs.verbose, False);
