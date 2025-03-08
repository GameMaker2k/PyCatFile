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

    $FileInfo: neocatfile.py - Last Update: 3/7/2025 Ver. 0.19.0 RC 1 - Author: cooldude2k $
'''

from __future__ import absolute_import, division, print_function, unicode_literals, generators, with_statement, nested_scopes
import argparse
import pycatfile

__project__ = pycatfile.__project__
__program_name__ = pycatfile.__program_name__
__file_format_name__ = pycatfile.__file_format_name__
__file_format_magic__ = pycatfile.__file_format_magic__
__file_format_len__ = pycatfile.__file_format_len__
__file_format_hex__ = pycatfile.__file_format_hex__
__file_format_delimiter__ = pycatfile.__file_format_delimiter__
__file_format_dict__ = pycatfile.__file_format_dict__
__file_format_default__ = pycatfile.__file_format_default__
__use_new_style__ = pycatfile.__use_new_style__
__use_advanced_list__ = pycatfile.__use_advanced_list__
__use_alt_inode__ = pycatfile.__use_alt_inode__
__project_url__ = pycatfile.__project_url__
__version_info__ = pycatfile.__version_info__
__version_date_info__ = pycatfile.__version_date_info__
__version_date__ = pycatfile.__version_date__
__version_date_plusrc__ = pycatfile.__version_date_plusrc__
__version__ = pycatfile.__version__

# Compatibility layer for Python 2 and 3 input
try:
    input = raw_input
except NameError:
    pass

# Determine if rar file support is enabled
rarfile_support = pycatfile.rarfile_support
py7zr_support = pycatfile.py7zr_support

# Set up the argument parser
argparser = argparse.ArgumentParser(
    description="Manipulates concatenated files for various operations like creation, extraction, and validation.")
argparser.add_argument("-V", "--version", action="version", version="{0} {1}".format(
    __program_name__, __version__), help="Displays the program's version.")
argparser.add_argument("-i", "--input", nargs="+", required=True,
                       help="Specifies input file(s) for processing.")
argparser.add_argument(
    "-o", "--output", help="Specifies the output file name.")
argparser.add_argument("-d", "--verbose", action="store_true",
                       help="Enables verbose mode for detailed information.")
argparser.add_argument("-c", "--create", action="store_true",
                       help="Creates a new concatenated file from input.")
argparser.add_argument("-e", "--extract", action="store_true",
                       help="Extracts files from a concatenated archive.")
argparser.add_argument("-l", "--list", action="store_true",
                       help="Lists contents of a specified concatenated file.")
argparser.add_argument("-r", "--repack", action="store_true",
                       help="Repacks an existing concatenated file.")
argparser.add_argument("-v", "--validate", action="store_true",
                       help="Validates a concatenated file's integrity.")
argparser.add_argument("--checksum", default="crc32",
                       help="Specifies the checksum type (default: crc32).")
argparser.add_argument("--compression", default="auto",
                       help="Specifies the compression method (default: auto).")
argparser.add_argument("--level", help="Specifies the compression level.")
argparser.add_argument("--preserve", action="store_true",
                       help="Preserves file attributes when extracting.")
argparser.add_argument("--convert", choices=['tar', 'zip', '7zip', 'rar'],
                       help="Convert from an archive format (tar, zip, 7zip, rar) to a concatenated file.")
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
input_file = args.input[0]
# Functionality mappings
if primary_action == 'create':
    if args.convert == 'tar':
        pycatfile.PackCatFileFromTarFile(input_file, args.output, args.compression, args.level, pycatfile.compressionlistalt, [args.checksum, args.checksum, args.checksum, args.checksum], [
        ], pycatfile.__file_format_dict__, args.verbose, False)
    elif args.convert == 'zip':
        pycatfile.PackCatFileFromZipFile(input_file, args.output, args.compression, args.level, pycatfile.compressionlistalt, [args.checksum, args.checksum, args.checksum, args.checksum], [
        ], pycatfile.__file_format_dict__, args.verbose, False)
    elif py7zr_support and args.convert == '7zip':
        pycatfile.PackCatFileFromSevenZipFile(input_file, args.output, args.compression, args.level, pycatfile.compressionlistalt, [args.checksum, args.checksum, args.checksum, args.checksum], [
        ], pycatfile.__file_format_dict__, args.verbose, False)
    elif rarfile_support and args.convert == 'rar':
        pycatfile.PackCatFileFromRarFile(input_file, args.output, args.compression, args.level, pycatfile.compressionlistalt, [args.checksum, args.checksum, args.checksum, args.checksum], [
        ], pycatfile.__file_format_dict__, args.verbose, False)
    else:
        pycatfile.PackCatFile(args.input, args.output, args.verbose, args.compression, args.level, pycatfile.compressionlistalt,
                                  False, [args.checksum, args.checksum, args.checksum, args.checksum], [], {}, pycatfile.__file_format_dict__, args.verbose, False)
elif primary_action == 'repack':
    pycatfile.RePackCatFile(
        input_file, args.output, args.compression, args.level, pycatfile.compressionlistalt, [args.checksum, args.checksum, args.checksum, args.checksum], False, args.verbose)
elif primary_action == 'extract':
    pycatfile.UnPackCatFile(
        input_file, args.output, args.verbose, False, args.preserve)
elif primary_action == 'list':
    if args.convert == 'tar':
        pycatfile.TarFileListFiles(input_file, verbose=args.verbose)
    elif args.convert == 'zip':
        pycatfile.ZipFileListFiles(input_file, verbose=args.verbose)
    elif args.convert == '7zip':
        pycatfile.SevenZipFileListFiles(input_file, verbose=args.verbose)
    elif rarfile_support and args.convert == 'rar':
        pycatfile.RarFileListFiles(input_file, verbose=args.verbose)
    else:
        pycatfile.CatFileListFiles(input_file, verbose=args.verbose)
elif primary_action == 'validate':
    is_valid = pycatfile.CatFileValidate(input_file, verbose=args.verbose)
    result_msg = "Validation result for {0}: {1}".format(
        input_file, 'Valid' if is_valid else 'Invalid')
    print(result_msg)
