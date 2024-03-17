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

    $FileInfo: catfile.py - Last Update: 3/17/2024 Ver. 0.5.2 RC 1 - Author: cooldude2k $
'''

from __future__ import absolute_import, division, print_function, unicode_literals;
import os, sys, logging, argparse, pycatfile, binascii;
from io import open as open;

rarfile_support = pycatfile.rarfile_support;

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
__project_url__ = pycatfile.__project_url__;
__version_info__ = pycatfile.__version_info__;
__version_date_info__ = pycatfile.__version_date_info__;
__version_date__ = pycatfile.__version_date__;
__version_date_plusrc__ = pycatfile.__version_date_plusrc__;
__version__ = pycatfile.__version__;

argparser = argparse.ArgumentParser(description="Manipulate concatenated files.", conflict_handler="resolve", add_help=True);
argparser.add_argument("-V", "--version", action="version", version=__program_name__ + " " + __version__);
argparser.add_argument("-i", "-f", "--input", help="Specify the file(s) to concatenate or the concatenated file to extract.", required=True);
argparser.add_argument("-d", "-v", "--verbose", action="store_true", help="Enable verbose mode to display various debugging information.");
argparser.add_argument("-c", "--create", action="store_true", help="Perform concatenation operation only.");
argparser.add_argument("-validate", "--validate", action="store_true", help="Validate CatFile checksums");
argparser.add_argument("-checksum", "--checksum", default="crc32", help="Specify the type of checksum to use. Default is crc32.");
argparser.add_argument("-e", "-x", "--extract", action="store_true", help="Perform extraction operation only.");
argparser.add_argument("-format", "--format", default=__file_format_list__[0], help="Specify the format to use");
argparser.add_argument("-delimiter", "--delimiter", default=__file_format_list__[5], help="Specify the format to use");
argparser.add_argument("-formatver", "--formatver", default=__file_format_list__[6], help="Specify the format version");
argparser.add_argument("-l", "-t", "--list", action="store_true", help="List files included in the concatenated file.");
argparser.add_argument("-p", "-preserve", "--preserve", action="store_false", help="Preserve permissions and time of files");
argparser.add_argument("-repack", "--repack", action="store_true", help="Re-concatenate files, fixing checksum errors if any.");
argparser.add_argument("-o", "--output", default=None, help="Specify the name for the extracted concatenated files or the output concatenated file.");
argparser.add_argument("-compression", "--compression", default="auto", help="Specify the compression method to use for concatenation.");
argparser.add_argument("-level", "--level", default=None, help="Specify the compression level for concatenation.");
argparser.add_argument("-t", "-tar", "--converttar", action="store_true", help="Convert a tar file to a catfile.");
argparser.add_argument("-z", "-zip", "--convertzip", action="store_true", help="Convert a zip file to a catfile.");
argparser.add_argument("-rar", "--convertrar", action="store_true", help="Convert a rar file to a catfile.");
argparser.add_argument("-T", "--text", action="store_true", help="Read file locations from a text file.");
getargs = argparser.parse_args();

fname = getargs.format;
fnamelower = fname.lower();
fnamemagic = fname;
fnamelen = len(fname);
fnamehex = binascii.hexlify(fname.encode("UTF-8")).decode("UTF-8");
fnamever = getargs.formatver;
fnamesty = __use_new_style__;
fnamelist = [fname, fnamemagic, fnamelower, fnamelen, fnamehex, getargs.delimiter, fnamever, fnamesty];

# Determine actions based on user input
should_create = getargs.create and not getargs.extract and not getargs.list;
should_extract = getargs.extract and not getargs.create and not getargs.list;
should_list = getargs.list and not getargs.create and not getargs.extract;
should_repack = getargs.create and getargs.repack;
should_validate = getargs.validate;

# Execute the appropriate functions based on determined actions and arguments
if should_create:
 if getargs.converttar:
  pycatfile.PackArchiveFileFromTarFile(getargs.input, getargs.output, getargs.compression, getargs.level, getargs.checksum, [], fnamelist, getargs.verbose, False);
 elif getargs.convertzip:
  pycatfile.PackArchiveFileFromZipFile(getargs.input, getargs.output, getargs.compression, getargs.level, getargs.checksum, [], fnamelist, getargs.verbose, False);
 elif rarfile_support and getargs.convertrar:
  pycatfile.PackArchiveFileFromRarFile(getargs.input, getargs.output, getargs.compression, getargs.level, getargs.checksum, [], fnamelist, getargs.verbose, False);
 else:
  pycatfile.PackArchiveFile(getargs.input, getargs.output, getargs.text, getargs.compression, getargs.level, False, getargs.checksum, [], fnamelist, getargs.verbose, False);

elif should_repack:
 pycatfile.RePackArchiveFile(getargs.input, getargs.output, getargs.compression, getargs.level, False, 0, 0, getargs.checksum, False, [], fnamelist, getargs.verbose, False);

elif should_extract:
 pycatfile.UnPackArchiveFile(getargs.input, getargs.output, False, 0, 0, False, fnamelist, getargs.verbose, getargs.preserve, getargs.preserve, False);

elif should_list:
 if getargs.converttar:
  pycatfile.TarFileListFiles(getargs.input, getargs.verbose, False);
 elif getargs.convertzip:
  pycatfile.ZipFileListFiles(getargs.input, getargs.verbose, False);
 elif rarfile_support and getargs.convertrar:
  pycatfile.RarFileListFiles(getargs.input, getargs.verbose, False);
 else:
  pycatfile.ArchiveFileListFiles(getargs.input, 0, 0, False, fnamelist, getargs.verbose, False);

elif should_validate:
 fvalid = pycatfile.ArchiveFileValidate(getargs.input, fnamelist, getargs.verbose, False);
 if(fvalid):
  pycatfile.VerbosePrintOut("File is valid: " + str(getargs.input));
 else:
  pycatfile.VerbosePrintOut("File is invalid: " + str(getargs.input));
