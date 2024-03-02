#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
    This program is free software; you can redistribute it and/or modify
    it under the terms of the Revised BSD License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Revised BSD License for more details.

    Copyright 2018-2024 Cool Dude 2k - http://idb.berlios.de/
    Copyright 2018-2024 Game Maker 2k - http://intdb.sourceforge.net/
    Copyright 2018-2024 Kazuki Przyborowski - https://github.com/KazukiPrzyborowski

    $FileInfo: catfile.py - Last Update: 3/1/2024 Ver. 0.2.0 RC 1 - Author: cooldude2k $
'''

from __future__ import absolute_import, division, print_function, unicode_literals;
import os, sys, logging, argparse, pycatfile;
from io import open as open;

if(sys.version[0]=="2"):
 try:
  from io import StringIO, BytesIO;
 except ImportError:
  try:
   from cStringIO import StringIO;
   from cStringIO import StringIO as BytesIO;
  except ImportError:
   from StringIO import StringIO;
   from StringIO import StringIO as BytesIO;
elif(sys.version[0]>="3"):
 from io import StringIO, BytesIO;
else:
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
__version_date_plusrc__ = pycatfile.__version_date_plusrc__;
__version__ = pycatfile.__version__;
__cat_header_ver__ = pycatfile.__cat_header_ver__;

argparser = argparse.ArgumentParser(description="Manipulate concatenated files.", conflict_handler="resolve", add_help=True);
argparser.add_argument("-V", "--version", action="version", version=__program_name__ + " " + __version__);
argparser.add_argument("-i", "-f", "--input", help="Specify the file(s) to concatenate or the concatenated file to extract.", required=True);
argparser.add_argument("-d", "-v", "--verbose", action="store_true", help="Enable verbose mode to display various debugging information.");
argparser.add_argument("-c", "--create", action="store_true", help="Perform concatenation operation only.");
argparser.add_argument("-checksum", "--checksum", default="crc32", help="Specify the type of checksum to use. Default is crc32.");
argparser.add_argument("-e", "-x", "--extract", action="store_true", help="Perform extraction operation only.");
argparser.add_argument("-l", "-t", "--list", action="store_true", help="List files included in the concatenated file.");
argparser.add_argument("-r", "--repack", action="store_true", help="Re-concatenate files, fixing checksum errors if any.");
argparser.add_argument("-o", "--output", default=None, help="Specify the name for the extracted concatenated files or the output concatenated file.");
argparser.add_argument("-compression", "--compression", default="auto", help="Specify the compression method to use for concatenation.");
argparser.add_argument("-level", "--level", default=None, help="Specify the compression level for concatenation.");
argparser.add_argument("-t", "--converttar", action="store_true", help="Convert a tar file to a catfile.");
argparser.add_argument("-z", "--convertzip", action="store_true", help="Convert a zip file to a catfile.");
argparser.add_argument("-T", "--text", action="store_true", help="Read file locations from a text file.");
getargs = argparser.parse_args();

# Determine actions based on user input
should_create = getargs.create and not getargs.extract and not getargs.list;
should_extract = getargs.extract and not getargs.create and not getargs.list;
should_list = getargs.list and not getargs.create and not getargs.extract;
should_repack = getargs.create and getargs.repack;

# Execute the appropriate functions based on determined actions and arguments
if should_create:
 if getargs.converttar:
  pycatfile.PackCatFileFromTarFile(getargs.input, getargs.output, getargs.compression, getargs.level, getargs.checksum, [], getargs.verbose, False);
 elif getargs.convertzip:
  pycatfile.PackCatFileFromZipFile(getargs.input, getargs.output, getargs.compression, getargs.level, getargs.checksum, [], getargs.verbose, False);
 else:
  pycatfile.PackCatFile(getargs.input, getargs.output, getargs.text, getargs.compression, getargs.level, False, getargs.checksum, [], getargs.verbose, False);

if should_repack:
 pycatfile.RePackCatFile(getargs.input, getargs.output, getargs.compression, getargs.level, False, 0, 0, getargs.checksum, False, [], getargs.verbose, False);

if should_extract:
 pycatfile.UnPackCatFile(getargs.input, getargs.output, False, 0, 0, False, getargs.verbose, False);

if should_list:
 if getargs.converttar:
  pycatfile.TarFileListFiles(getargs.input, getargs.verbose, False);
 elif getargs.convertzip:
  pycatfile.ZipFileListFiles(getargs.input, getargs.verbose, False);
 else:
  pycatfile.CatFileListFiles(getargs.input, 0, 0, False, getargs.verbose, False);
