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

    $FileInfo: pycatfile.py - Last Update: 3/6/2018 Ver. 0.0.1 RC 1 - Author: cooldude2k $
'''

from __future__ import absolute_import, division, print_function, unicode_literals;

__program_name__ = "PyCatFile";
__project__ = __program_name__;
__project_url__ = "https://github.com/GameMaker2k/PyCatFile";
__version_info__ = (0, 0, 1, "RC 1", 1);
__version_date_info__ = (2018, 3, 6, "RC 1", 1);
__version_date__ = str(__version_date_info__[0]) + "." + str(__version_date_info__[1]).zfill(2) + "." + str(__version_date_info__[2]).zfill(2);
if(__version_info__[4] is not None):
 __version_date_plusrc__ = __version_date__ + "-" + str(__version_date_info__[4]);
if(__version_info__[4] is None):
 __version_date_plusrc__ = __version_date__;
if(__version_info__[3] is not None):
 __version__ = str(__version_info__[0]) + "." + str(__version_info__[1]) + "." + str(__version_info__[2]) + " " + str(__version_info__[3]);
if(__version_info__[3] is None):
 __version__ = str(__version_info__[0]) + "." + str(__version_info__[1]) + "." + str(__version_info__[2]);

import argparse;

try:
 from StringIO import StringIO as BytesIO;
except ImportError:
 from io import BytesIO;

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
if(should_create is True and should_extract is False and should_list is False and should_repack is False and should_convert is False):
 PackCatFile(getargs.input, getargs.output, False, getargs.checksum, getargs.verbose, False);
if(should_create is True and should_extract is False and should_list is False and should_repack is False and should_convert is True):
 PackCatFileFromTarFile(getargs.input, getargs.output, getargs.checksum, getargs.verbose, );
if(should_create is True and should_extract is False and should_list is False and should_repack is True and should_convert is False):
 RePackCatFile(getargs.input, getargs.output, 0, 0, getargs.checksum, False, getargs.verbose, False);
if(should_create is False and should_extract is True and should_list is False):
 UnPackCatFile(getargs.input, getargs.output, getargs.verbose, False);
if(should_create is False and should_extract is False and should_list is True):
 CatFileListFiles(getargs.input, 0, 0, getargs.verbose, False);
