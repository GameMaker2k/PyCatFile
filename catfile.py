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

    $FileInfo: catfile.py - Last Update: 11/16/2025 Ver. 0.27.4 RC 1 - Author: cooldude2k $
'''

from __future__ import absolute_import, division, print_function, unicode_literals, generators, with_statement, nested_scopes
import os
import sys
import logging
import argparse
import pyarchivefile
import binascii

# Text streams (as provided by Python)
PY_STDIN_TEXT  = sys.stdin
PY_STDOUT_TEXT = sys.stdout
PY_STDERR_TEXT = sys.stderr

# Binary-friendly streams (use .buffer on Py3, fall back on Py2)
PY_STDIN_BUF  = getattr(sys.stdin,  "buffer", sys.stdin)
PY_STDOUT_BUF = getattr(sys.stdout, "buffer", sys.stdout)
PY_STDERR_BUF = getattr(sys.stderr, "buffer", sys.stderr)
logging.basicConfig(format="%(message)s", stream=PY_STDOUT_TEXT, level=logging.DEBUG)

# Conditional import and signal handling for Unix-like systems
if os.name != 'nt':  # Not Windows
    import signal
    if hasattr(signal, 'SIGPIPE'):
        def handler(signum, frame):
            pycatfile.VerbosePrintOut(
                "Received SIGPIPE, exiting gracefully.", "info")
            sys.exit(0)
        signal.signal(signal.SIGPIPE, handler)

rarfile_support = pycatfile.rarfile_support
py7zr_support = pycatfile.py7zr_support

if(sys.version[0] == "2"):
    try:
        from io import StringIO, BytesIO
    except ImportError:
        try:
            from cStringIO import StringIO
            from cStringIO import StringIO as BytesIO
        except ImportError:
            from StringIO import StringIO
            from StringIO import StringIO as BytesIO
elif(sys.version[0] >= "3"):
    from io import StringIO, BytesIO
else:
    teststringio = 0
    if(teststringio <= 0):
        try:
            from cStringIO import StringIO as BytesIO
            teststringio = 1
        except ImportError:
            teststringio = 0
    if(teststringio <= 0):
        try:
            from StringIO import StringIO as BytesIO
            teststringio = 2
        except ImportError:
            teststringio = 0
    if(teststringio <= 0):
        try:
            from io import BytesIO
            teststringio = 3
        except ImportError:
            teststringio = 0

__project__ = pycatfile.__project__
__program_name__ = pycatfile.__program_name__
__file_format_name__ = pycatfile.__file_format_name__
__file_format_magic__ = pycatfile.__file_format_magic__
__file_format_len__ = pycatfile.__file_format_len__
__file_format_hex__ = pycatfile.__file_format_hex__
__file_format_delimiter__ = pycatfile.__file_format_delimiter__
__file_format_dict__ = pycatfile.__file_format_dict__
__file_format_default__ = pycatfile.__file_format_default__
__file_format_multi_dict__ = pycatfile.__file_format_multi_dict__
__use_new_style__ = pycatfile.__use_new_style__
__use_advanced_list__ = pycatfile.__use_advanced_list__
__use_alt_inode__ = pycatfile.__use_alt_inode__
__project_url__ = pycatfile.__project_url__
__version_info__ = pycatfile.__version_info__
__version_date_info__ = pycatfile.__version_date_info__
__version_date__ = pycatfile.__version_date__
__version_date_plusrc__ = pycatfile.__version_date_plusrc__
__version__ = pycatfile.__version__

# Initialize the argument parser
argparser = argparse.ArgumentParser(description="Manipulate archive files.", conflict_handler="resolve", add_help=True)

# Version information
argparser.add_argument("-V", "--version", action="version", version=__program_name__ + " " + __version__)
# Input and output specifications
argparser.add_argument("-i", "--input", nargs="+", help="Specify the file(s) to concatenate or the archive file to extract.", required=True)
argparser.add_argument("-o", "--output", default=None, help="Specify the name for the extracted or output archive files.")
# Operations
argparser.add_argument("-c", "--create", action="store_true", help="Perform only the concatenation operation.")
argparser.add_argument("-e", "--extract", action="store_true", help="Perform only the extraction operation.")
argparser.add_argument("-t", "--convert", action="store_true", help="Convert a tar/zip/rar/7zip file to a archive file.")
argparser.add_argument("-r", "--repack", action="store_true", help="Re-concatenate files, fixing checksum errors if any.")
argparser.add_argument("-S", "--filestart", type=int, default=0, help="Start reading file at.")
# File manipulation options
argparser.add_argument("-F", "--format", default="auto", help="Specify the format to use.")
argparser.add_argument("-D", "--delimiter", default=__file_format_dict__['format_delimiter'], help="Specify the delimiter to use.")
argparser.add_argument("-m", "--formatver", default=__file_format_dict__['format_ver'], help="Specify the format version.")
argparser.add_argument("-l", "--list", action="store_true", help="List files included in the archive file.")
# Compression options
argparser.add_argument("-P", "--compression", default="auto", help="Specify the compression method to use for concatenation.")
argparser.add_argument("-L", "--level", default=None, help="Specify the compression level for concatenation.")
argparser.add_argument("-W", "--wholefile", action="store_true", help="Whole file compression method to use for concatenation.")
# Checksum and validation
argparser.add_argument("-v", "--validate", action="store_true", help="Validate archive file checksums.")
argparser.add_argument("-C", "--checksum", default="md5", help="Specify the type of checksum to use. The default is crc32.")
argparser.add_argument("-s", "--skipchecksum", action="store_true", help="Skip the checksum check of files.")
argparser.add_argument("-k", "--insecretkey", default=None, help="Secretkey to use for checksum input.")
argparser.add_argument("-K", "--outsecretkey", default=None, help="Secretkey to use for checksum output.")
# Permissions and metadata
argparser.add_argument("-p", "--preserve", action="store_false", help="Do not preserve permissions and timestamps of files.")
# Miscellaneous
argparser.add_argument("-d", "--verbose", action="store_true", help="Enable verbose mode to display various debugging information.")
argparser.add_argument("-T", "--text", action="store_true", help="Read file locations from a text file.")
# Parse the arguments
getargs = argparser.parse_args()

fname = getargs.format
if(getargs.format=="auto"):
    fnamedict = __file_format_multi_dict__
    __file_format_default__ = getargs.format
else:
    fnamemagic = fname
    fnamelen = len(fname)
    fnamehex = binascii.hexlify(fname.encode("UTF-8")).decode("UTF-8")
    __file_format_default__ = fnamemagic
    fnamesty = __use_new_style__
    fnamelst = __use_advanced_list__
    fnameino = __use_alt_inode__
    fnamedict = {'format_name': fname, 'format_magic': fnamemagic, 'format_len': fnamelen, 'format_hex': fnamehex,
                 'format_delimiter': getargs.delimiter, 'format_ver': getargs.formatver, 'new_style': fnamesty, 'use_advanced_list': fnamelst, 'use_alt_inode': fnameino}

# Determine the primary action based on user input
actions = ['create', 'extract', 'list', 'repack', 'validate']
active_action = next(
    (action for action in actions if getattr(getargs, action)), None)
input_file = getargs.input[0]

# Execute the appropriate functions based on determined actions and arguments
if active_action:
    if active_action == 'create':
        if getargs.convert:
            checkcompressfile = pycatfile.CheckCompressionSubType(
                input_file, fnamedict, 0, True)
            if((pycatfile.IsNestedDict(fnamedict) and checkcompressfile in fnamedict) or (pycatfile.IsSingleDict(fnamedict) and checkcompressfile==fnamedict['format_magic'])):
                tmpout = pycatfile.RePackCatFile(input_file, getargs.output, "auto", getargs.compression, getargs.wholefile, getargs.level, pycatfile.compressionlistalt, False, getargs.filestart, 0, 0, [getargs.checksum, getargs.checksum, getargs.checksum, getargs.checksum, getargs.checksum], getargs.skipchecksum, [], {}, fnamedict, getargs.insecretkey, getargs.outsecretkey, False, getargs.verbose, False)
            else:
                tmpout = pycatfile.PackCatFileFromInFile(
                    input_file, getargs.output, __file_format_default__, getargs.compression, getargs.wholefile, getargs.level, pycatfile.compressionlistalt, [getargs.checksum, getargs.checksum, getargs.checksum, getargs.checksum, getargs.checksum], [], {}, fnamedict, getargs.outsecretkey, getargs.verbose, False)
            if(not tmpout):
                sys.exit(1)
        else:
            pycatfile.PackCatFile(getargs.input, getargs.output, getargs.text, __file_format_default__, getargs.compression, getargs.wholefile, getargs.level, pycatfile.compressionlistalt, False, [getargs.checksum, getargs.checksum, getargs.checksum, getargs.checksum, getargs.checksum], [], {}, fnamedict, getargs.outsecretkey, getargs.verbose, False)
    elif active_action == 'repack':
        if getargs.convert:
            checkcompressfile = pycatfile.CheckCompressionSubType(
                input_file, fnamedict, 0, True)
            if((pycatfile.IsNestedDict(fnamedict) and checkcompressfile in fnamedict) or (pycatfile.IsSingleDict(fnamedict) and checkcompressfile==fnamedict['format_magic'])):
                pycatfile.RePackCatFile(input_file, getargs.output, "auto", getargs.compression, getargs.wholefile, getargs.level, pycatfile.compressionlistalt,
                                            False, getargs.filestart, 0, 0, [getargs.checksum, getargs.checksum, getargs.checksum, getargs.checksum, getargs.checksum], getargs.skipchecksum, [], {}, fnamedict, getargs.insecretkey, getargs.outsecretkey, False, getargs.verbose, False)
            else:
                pycatfile.PackCatFileFromInFile(input_file, getargs.output, __file_format_default__, getargs.compression, getargs.wholefile, getargs.level, pycatfile.compressionlistalt, [getargs.checksum, getargs.checksum, getargs.checksum, getargs.checksum, getargs.checksum], [], {}, fnamedict, getargs.outsecretkey, getargs.verbose, False)
            if(not tmpout):
                sys.exit(1)
        else:
            pycatfile.RePackCatFile(input_file, getargs.output, "auto", getargs.compression, getargs.wholefile, getargs.level, pycatfile.compressionlistalt,
                                        False, getargs.filestart, 0, 0, [getargs.checksum, getargs.checksum, getargs.checksum, getargs.checksum, getargs.checksum], getargs.skipchecksum, [], {}, fnamedict, getargs.insecretkey, getargs.outsecretkey, False, getargs.verbose, False)
    elif active_action == 'extract':
        if getargs.convert:
            checkcompressfile = pycatfile.CheckCompressionSubType(
                input_file, fnamedict, 0, True)
            tempout = BytesIO()
            if((pycatfile.IsNestedDict(fnamedict) and checkcompressfile in fnamedict) or (pycatfile.IsSingleDict(fnamedict) and checkcompressfile==fnamedict['format_magic'])):
                tmpout = pycatfile.RePackCatFile(input_file, tempout, "auto", getargs.compression, getargs.wholefile, getargs.level, pycatfile.compressionlistalt, False, getargs.filestart, 0, 0, [getargs.checksum, getargs.checksum, getargs.checksum, getargs.checksum, getargs.checksum], getargs.skipchecksum, [], {}, fnamedict, getargs.insecretkey, getargs.outsecretkey, False, False)
            else:
                tmpout = pycatfile.PackCatFileFromInFile(
                    input_file, tempout, __file_format_default__, getargs.compression, getargs.wholefile, getargs.level, pycatfile.compressionlistalt, [getargs.checksum, getargs.checksum, getargs.checksum, getargs.checksum, getargs.checksum], [], {}, fnamedict, getargs.outsecretkey, False, False)
            if(not tmpout):
                sys.exit(1)
            input_file = tempout
        pycatfile.UnPackCatFile(input_file, getargs.output, False, getargs.filestart, 0, 0, getargs.skipchecksum,
                                    fnamedict, getargs.verbose, getargs.preserve, getargs.preserve, False, False)
    elif active_action == 'list':
        if getargs.convert:
            checkcompressfile = pycatfile.CheckCompressionSubType(
                input_file, fnamedict, 0, True)
            if((pycatfile.IsNestedDict(fnamedict) and checkcompressfile in fnamedict) or (pycatfile.IsSingleDict(fnamedict) and checkcompressfile==fnamedict['format_magic'])):
                tmpout = pycatfile.CatFileListFiles(input_file, "auto", getargs.filestart, 0, 0, getargs.skipchecksum, fnamedict, getargs.insecretkey, False, getargs.verbose, False, False)
            else:
                tmpout = pycatfile.InFileListFiles(input_file, getargs.verbose, fnamedict, getargs.insecretkey, False, False, False)
            if(not tmpout):
                sys.exit(1)
        else:
            pycatfile.CatFileListFiles(input_file, "auto", getargs.filestart, 0, 0, getargs.skipchecksum, fnamedict, getargs.insecretkey, False, getargs.verbose, False, False)
    elif active_action == 'validate':
        if getargs.convert:
            checkcompressfile = pycatfile.CheckCompressionSubType(
                input_file, fnamedict, 0, True)
            tempout = BytesIO()
            if((pycatfile.IsNestedDict(fnamedict) and checkcompressfile in fnamedict) or (pycatfile.IsSingleDict(fnamedict) and checkcompressfile==fnamedict['format_magic'])):
                tmpout = pycatfile.RePackCatFile(input_file, tempout, "auto", getargs.compression, getargs.wholefile, getargs.level, pycatfile.compressionlistalt, False, getargs.filestart, 0, 0, [getargs.checksum, getargs.checksum, getargs.checksum, getargs.checksum, getargs.checksum], getargs.skipchecksum, [], {}, fnamedict, getargs.insecretkey, getargs.outsecretkey, False, False, False)
            else:
                tmpout = pycatfile.PackCatFileFromInFile(
                    input_file, tempout, __file_format_default__, getargs.compression, getargs.wholefile, getargs.level, pycatfile.compressionlistalt, [getargs.checksum, getargs.checksum, getargs.checksum, getargs.checksum, getargs.checksum], [], {}, fnamedict, getargs.outsecretkey, False, False)
            input_file = tempout
            if(not tmpout):
                sys.exit(1)
        fvalid = pycatfile.StackedCatFileValidate(
            input_file, "auto", getargs.filestart, fnamedict, getargs.insecretkey, False, getargs.verbose, False)
        if(not getargs.verbose):
            import sys
            import logging
            logging.basicConfig(format="%(message)s",
                                stream=sys.stdout, level=logging.DEBUG)
        if(fvalid):
            pycatfile.VerbosePrintOut("File is valid: \n" + str(input_file))
        else:
            pycatfile.VerbosePrintOut("File is invalid: \n" + str(input_file))
