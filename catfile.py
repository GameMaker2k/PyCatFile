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

    $FileInfo: catfile.py - Last Update: 6/26/2024 Ver. 0.13.12 RC 1 - Author: cooldude2k $
'''

from __future__ import absolute_import, division, print_function, unicode_literals;
import os, sys, argparse, pycatfile, binascii;

# Conditional import and signal handling for Unix-like systems
if os.name != 'nt':  # Not Windows
 import signal;
 def handler(signum, frame):
  pycatfile.VerbosePrintOut("Received SIGPIPE, exiting gracefully.","info");
  sys.exit(0);
signal.signal(signal.SIGPIPE, handler);

rarfile_support = pycatfile.rarfile_support;
py7zr_support = pycatfile.py7zr_support;

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
__file_format_name__ = pycatfile.__file_format_name__;
__file_format_lower__ = pycatfile.__file_format_lower__;
__file_format_magic__ = pycatfile.__file_format_magic__;
__file_format_len__ = pycatfile.__file_format_len__;
__file_format_hex__ = pycatfile.__file_format_hex__;
__file_format_delimiter__ = pycatfile.__file_format_delimiter__;
__file_format_list__ = pycatfile.__file_format_list__;
__use_new_style__ = pycatfile.__use_new_style__;
__use_advanced_list__ = pycatfile.__use_advanced_list__;
__use_alt_inode__ = pycatfile.__use_alt_inode__;
__project_url__ = pycatfile.__project_url__;
__version_info__ = pycatfile.__version_info__;
__version_date_info__ = pycatfile.__version_date_info__;
__version_date__ = pycatfile.__version_date__;
__version_date_plusrc__ = pycatfile.__version_date_plusrc__;
__version__ = pycatfile.__version__;

# Initialize the argument parser
argparser = argparse.ArgumentParser(description="Manipulate concatenated files.", conflict_handler="resolve", add_help=True);

# Version information
argparser.add_argument("-V", "--version", action="version", version=__program_name__ + " " + __version__);
# Input and output specifications
argparser.add_argument("-i", "--input", help="Specify the file(s) to concatenate or the concatenated file to extract.", required=True);
argparser.add_argument("-o", "--output", default=None, help="Specify the name for the extracted or output concatenated files.");
# Operations
argparser.add_argument("-c", "--create", action="store_true", help="Perform only the concatenation operation.");
argparser.add_argument("-e", "--extract", action="store_true", help="Perform only the extraction operation.");
argparser.add_argument("-t", "--convert", action="store_true", help="Convert a tar/zip/rar/7zip file to a concatenated file.");
argparser.add_argument("-r", "--repack", action="store_true", help="Re-concatenate files, fixing checksum errors if any.");
# File manipulation options
argparser.add_argument("-F", "--format", default=__file_format_list__[0], help="Specify the format to use.");
argparser.add_argument("-D", "--delimiter", default=__file_format_list__[5], help="Specify the delimiter to use.");
argparser.add_argument("-m", "--formatver", default=__file_format_list__[6], help="Specify the format version.");
argparser.add_argument("-l", "--list", action="store_true", help="List files included in the concatenated file.");
# Compression options
argparser.add_argument("-P", "--compression", default="auto", help="Specify the compression method to use for concatenation.");
argparser.add_argument("-L", "--level", default=None, help="Specify the compression level for concatenation.");
argparser.add_argument("-W", "--wholefile", action="store_true", help="Whole file compression method to use for concatenation.");
# Checksum and validation
argparser.add_argument("-v", "--validate", action="store_true", help="Validate concatenated file checksums.");
argparser.add_argument("-C", "--checksum", default="crc32", help="Specify the type of checksum to use. The default is crc32.");
argparser.add_argument("-s", "--skipchecksum", action="store_true", help="Skip the checksum check of files.");
# Permissions and metadata
argparser.add_argument("-p", "--preserve", action="store_false", help="Do not preserve permissions and timestamps of files.");
# Miscellaneous
argparser.add_argument("-d", "--verbose", action="store_true", help="Enable verbose mode to display various debugging information.");
argparser.add_argument("-T", "--text", action="store_true", help="Read file locations from a text file.");
# Parse the arguments
getargs = argparser.parse_args();

fname = getargs.format;
fnamelower = fname.lower();
fnamemagic = fname;
fnamelen = len(fname);
fnamehex = binascii.hexlify(fname.encode("UTF-8")).decode("UTF-8");
fnamesty = __use_new_style__;
fnamelst = __use_advanced_list__;
fnameino = __use_alt_inode__;
fnamelist = [fname, fnamemagic, fnamelower, fnamelen, fnamehex, getargs.delimiter, getargs.formatver, fnamesty, fnamelst, fnameino];
fnamedict = {'format_name': fname, 'format_magic': fnamemagic, 'format_lower': fnamelower, 'format_len': fnamelen, 'format_hex': fnamehex, 'format_delimiter': getargs.delimiter, 'format_ver': getargs.formatver, 'new_style': fnamesty, 'use_advanced_list': fnamelst, 'use_alt_inode': fnameino};

# Determine the primary action based on user input
actions = ['create', 'extract', 'list', 'repack', 'validate'];
active_action = next((action for action in actions if getattr(getargs, action)), None);

# Execute the appropriate functions based on determined actions and arguments
if active_action:
 if active_action=='create':
  if getargs.convert:
   checkcompressfile = pycatfile.CheckCompressionSubType(getargs.input, fnamedict, True);
   if(checkcompressfile=="catfile"):
    tmpout = pycatfile.RePackArchiveFile(getargs.input, getargs.output, getargs.compression, getargs.wholefile, getargs.level, False, 0, 0, getargs.checksum, getargs.skipchecksum, [], fnamedict, getargs.verbose, False);
   else:
    tmpout = pycatfile.PackArchiveFileFromInFile(getargs.input, getargs.output, getargs.compression, getargs.wholefile, getargs.level, getargs.checksum, [], fnamedict, getargs.verbose, False);
   if(not tmpout):
    sys.exit(1);
  else:
   pycatfile.PackArchiveFile(getargs.input, getargs.output, getargs.text, getargs.compression, getargs.wholefile, getargs.level, False, getargs.checksum, [], fnamedict, getargs.verbose, False);
 elif active_action=='repack':
  if getargs.convert:
   checkcompressfile = pycatfile.CheckCompressionSubType(getargs.input, fnamedict, True);
   if(checkcompressfile=="catfile"):
    pycatfile.RePackArchiveFile(getargs.input, getargs.output, getargs.compression, getargs.wholefile, getargs.level, False, 0, 0, getargs.checksum, getargs.skipchecksum, [], fnamedict, getargs.verbose, False);
   else:
    pycatfile.PackArchiveFileFromInFile(getargs.input, getargs.output, getargs.compression, getargs.wholefile, getargs.level, getargs.checksum, [], fnamedict, getargs.verbose, False);
   if(not tmpout):
    sys.exit(1);
  else:
   pycatfile.RePackArchiveFile(getargs.input, getargs.output, getargs.compression, getargs.wholefile, getargs.level, False, 0, 0, getargs.checksum, getargs.skipchecksum, [], fnamedict, getargs.verbose, False);
 elif active_action=='extract':
  if getargs.convert:
   checkcompressfile = pycatfile.CheckCompressionSubType(getargs.input, fnamedict, True);
   tempout = BytesIO();
   if(checkcompressfile=="catfile"):
    tmpout = pycatfile.RePackArchiveFile(getargs.input, tempout, getargs.compression, getargs.wholefile, getargs.level, False, 0, 0, getargs.checksum, getargs.skipchecksum, [], fnamedict, False, False);
   else:
    tmpout = pycatfile.PackArchiveFileFromInFile(getargs.input, tempout, getargs.compression, getargs.wholefile, getargs.level, getargs.checksum, [], fnamedict, False, False);
   if(not tmpout):
    sys.exit(1);
   getargs.input = tempout;
  pycatfile.UnPackArchiveFile(getargs.input, getargs.output, False, 0, 0, getargs.skipchecksum, fnamedict, getargs.verbose, getargs.preserve, getargs.preserve, False);
 elif active_action=='list':
  if getargs.convert:
   checkcompressfile = pycatfile.CheckCompressionSubType(getargs.input, fnamedict, True);
   if(checkcompressfile=="catfile"):
    tmpout = pycatfile.ArchiveFileListFiles(getargs.input, 0, 0, getargs.skipchecksum, fnamedict, getargs.verbose, False);
   else:
    tmpout = pycatfile.InFileListFiles(getargs.input, getargs.verbose, fnamedict, False);
   if(not tmpout):
    sys.exit(1);
  else:
   pycatfile.ArchiveFileListFiles(getargs.input, 0, 0, getargs.skipchecksum, fnamedict, getargs.verbose, False);
 elif active_action=='validate':
  if getargs.convert:
   checkcompressfile = pycatfile.CheckCompressionSubType(getargs.input, fnamedict, True);
   tempout = BytesIO();
   if(checkcompressfile=="catfile"):
    tmpout = pycatfile.RePackArchiveFile(getargs.input, tempout, getargs.compression, getargs.wholefile, getargs.level, False, 0, 0, getargs.checksum, getargs.skipchecksum, [], fnamedict, False, False);
   else:
    tmpout = pycatfile.PackArchiveFileFromInFile(getargs.input, tempout, getargs.compression, getargs.wholefile, getargs.level, getargs.checksum, [], fnamedict, False, False);
   getargs.input = tempout;
   if(not tmpout):
    sys.exit(1);
  fvalid = pycatfile.ArchiveFileValidate(getargs.input, fnamedict, getargs.verbose, False);
  if(not getargs.verbose):
   import sys, logging;
   logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
  if(fvalid):
   pycatfile.VerbosePrintOut("File is valid: \n" + str(getargs.input));
  else:
   pycatfile.VerbosePrintOut("File is invalid: \n" + str(getargs.input));
