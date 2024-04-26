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

    $FileInfo: neocatfile.py - Last Update: 4/26/2024 Ver. 0.8.6 RC 1 - Author: cooldude2k $
'''

from __future__ import absolute_import, division, print_function, unicode_literals
import argparse
import pycatfile

# Compatibility layer for Python 2 and 3 input
try:
    input = raw_input
except NameError:
    pass

# Determine if rar file support is enabled
rarfile_support = pycatfile.rarfile_support

# Set up the argument parser
argparser = argparse.ArgumentParser(description="Manipulates concatenated files for various operations like creation, extraction, and validation.")
argparser.add_argument("-V", "--version", action="version", version="{0} {1}".format(pycatfile.__program_name__, pycatfile.__version__), help="Displays the program's version.")
argparser.add_argument("-i", "--input", required=True, help="Specifies input file(s) for processing.")
argparser.add_argument("-o", "--output", help="Specifies the output file name.")
argparser.add_argument("-d", "--verbose", action="store_true", help="Enables verbose mode for detailed information.")
argparser.add_argument("-c", "--create", action="store_true", help="Creates a new concatenated file from input.")
argparser.add_argument("-e", "--extract", action="store_true", help="Extracts files from a concatenated archive.")
argparser.add_argument("-l", "--list", action="store_true", help="Lists contents of a specified concatenated file.")
argparser.add_argument("-r", "--repack", action="store_true", help="Repacks an existing concatenated file.")
argparser.add_argument("-v", "--validate", action="store_true", help="Validates a concatenated file's integrity.")
argparser.add_argument("--checksum", default="crc32", help="Specifies the checksum type (default: crc32).")
argparser.add_argument("--compression", default="auto", help="Specifies the compression method (default: auto).")
argparser.add_argument("--level", help="Specifies the compression level.")
argparser.add_argument("--preserve", action="store_true", help="Preserves file attributes when extracting.")
argparser.add_argument("--convert", choices=['tar', 'zip', 'rar'], help="Convert from an archive format (tar, zip, rar) to a concatenated file.")
args = argparser.parse_args()

# Determine the primary action based on user input
primary_action = None
if args.create:
    primary_action = 'create'
elif args.repack:
    primary_action = 'repack'
elif args.extract:
    primary_action = 'extract'
elif args.list:
    primary_action = 'list'
elif args.validate:
    primary_action = 'validate'

# Functionality mappings
if primary_action == 'create':
    if args.convert == 'tar':
        pycatfile.PackArchiveFileFromTarFile(args.input, args.output, args.compression, args.level, args.checksum, [], pycatfile.__file_format_list__, args.verbose, False)
    elif args.convert == 'zip':
        pycatfile.PackArchiveFileFromZipFile(args.input, args.output, args.compression, args.level, args.checksum, [], pycatfile.__file_format_list__, args.verbose, False)
    elif rarfile_support and args.convert == 'rar':
        pycatfile.PackArchiveFileFromRarFile(args.input, args.output, args.compression, args.level, args.checksum, [], pycatfile.__file_format_list__, args.verbose, False)
    else:
        pycatfile.PackArchiveFile(args.input, args.output, args.verbose, args.compression, args.level, False, args.checksum, [], pycatfile.__file_format_list__, args.verbose, False)
elif primary_action == 'repack':
    pycatfile.RePackArchiveFile(args.input, args.output, args.compression, args.level, args.checksum, args.verbose)
elif primary_action == 'extract':
    pycatfile.UnPackArchiveFile(args.input, args.output, args.verbose, args.preserve)
elif primary_action == 'list':
    if args.convert == 'tar':
        pycatfile.TarFileListFiles(args.input, args.verbose, False)
    elif args.convert == 'zip':
        pycatfile.ZipFileListFiles(args.input, args.verbose, False)
    elif rarfile_support and args.convert == 'rar':
        pycatfile.RarFileListFiles(args.input, args.verbose, False)
    else:
        pycatfile.ArchiveFileListFiles(args.input, args.verbose)
elif primary_action == 'validate':
    is_valid = pycatfile.ArchiveFileValidate(args.input, args.verbose)
    result_msg = "Validation result for {0}: {1}".format(args.input, 'Valid' if is_valid else 'Invalid')
    print(result_msg)
