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

    $FileInfo: altcatfile.py - Last Update: 12/21/2024 Ver. 0.15.14 RC 1 - Author: cooldude2k $
'''

from __future__ import absolute_import, division, print_function, unicode_literals, generators, with_statement, nested_scopes
import os
import argparse
import pycatfile
import configparser
from io import BytesIO

__project__ = pycatfile.__project__
__program_name__ = pycatfile.__program_name__
__file_format_name__ = pycatfile.__file_format_name__
__file_format_lower__ = pycatfile.__file_format_lower__
__file_format_magic__ = pycatfile.__file_format_magic__
__file_format_len__ = pycatfile.__file_format_len__
__file_format_hex__ = pycatfile.__file_format_hex__
__file_format_delimiter__ = pycatfile.__file_format_delimiter__
__file_format_list__ = pycatfile.__file_format_list__
__use_new_style__ = pycatfile.__use_new_style__
__use_advanced_list__ = pycatfile.__use_advanced_list__
__use_alt_inode__ = pycatfile.__use_alt_inode__
__project_url__ = pycatfile.__project_url__
__version_info__ = pycatfile.__version_info__
__version_date_info__ = pycatfile.__version_date_info__
__version_date__ = pycatfile.__version_date__
__version_date_plusrc__ = pycatfile.__version_date_plusrc__
__version__ = pycatfile.__version__

# Initialize Configuration
def load_config():
    if 'PYCATFILE_CONFIG_FILE' in os.environ and os.path.exists(os.environ['PYCATFILE_CONFIG_FILE']):
        scriptconf = os.environ['PYCATFILE_CONFIG_FILE']
    else:
        scriptconf = os.path.join(os.path.dirname(__file__), "catfile.ini")
    
    config = configparser.ConfigParser()
    if os.path.exists(scriptconf):
        config.read(scriptconf)
        return {
            'name': config.get('main', 'name', fallback="CatFile"),
            'delimiter': config.get('main', 'delimiter', fallback="\x00"),
            'version': config.get('main', 'ver', fallback="001"),
            'extension': config.get('main', 'extension', fallback=".cat")
        }
    else:
        return {
            'name': "CatFile",
            'delimiter': "\x00",
            'version': "001",
            'extension': ".cat"
        }

# Combined Script Main
def main():
    # Load Configuration
    default_config = load_config()

    # Argument Parsing
    parser = argparse.ArgumentParser(
        description="Combined utility for CatFile operations with dynamic and static modes."
    )
    parser.add_argument("-i", "--input", required=True, help="Input file(s) for processing.")
    parser.add_argument("-o", "--output", help="Output file name.")
    parser.add_argument("-m", "--mode", choices=["dynamic", "static"], default="static",
                        help="Choose mode: 'dynamic' (runtime arguments) or 'static' (config-based). Default: static.")
    parser.add_argument("--create", action="store_true", help="Create a concatenated file.")
    parser.add_argument("--extract", action="store_true", help="Extract files from a concatenated archive.")
    parser.add_argument("--list", action="store_true", help="List contents of a concatenated file.")
    parser.add_argument("--repack", action="store_true", help="Repack a concatenated file.")
    parser.add_argument("--validate", action="store_true", help="Validate a concatenated file.")
    parser.add_argument("--format", help="Format name (dynamic mode only).")
    parser.add_argument("--delimiter", help="Delimiter character (dynamic mode only).")
    parser.add_argument("--formatver", help="Format version (dynamic mode only).")
    parser.add_argument("--compression", default="auto", help="Compression method. Default: auto.")
    parser.add_argument("--level", help="Compression level.")
    parser.add_argument("--checksum", default="crc32", help="Checksum type. Default: crc32.")
    parser.add_argument("--preserve", action="store_true", help="Preserve file attributes when extracting.")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output.")

    args = parser.parse_args()

    # Determine active mode
    if args.mode == "dynamic":
        format_name = args.format or default_config['name']
        delimiter = args.delimiter or default_config['delimiter']
        format_version = args.formatver or default_config['version']
    else:  # Static mode
        format_name = default_config['name']
        delimiter = default_config['delimiter']
        format_version = default_config['version']

    # Set format details
    format_dict = {
        'format_name': format_name,
        'format_magic': format_name,
        'format_lower': format_name.lower(),
        'format_len': len(format_name),
        'format_hex': format_name.encode('utf-8').hex(),
        'format_delimiter': delimiter,
        'format_ver': format_version
    }

    # Determine operation
    if args.create:
        pycatfile.PackArchiveFile(args.input, args.output, args.verbose, args.compression,
                                  args.level, False, args.checksum, [], format_dict, args.verbose, False)
    elif args.repack:
        pycatfile.RePackArchiveFile(
            args.input, args.output, args.compression, args.level, args.checksum, args.verbose)
    elif args.extract:
        pycatfile.UnPackArchiveFile(
            args.input, args.output, args.verbose, args.preserve)
    elif args.list:
        pycatfile.ArchiveFileListFiles(args.input, verbose=args.verbose)
    elif args.validate:
        is_valid = pycatfile.ArchiveFileValidate(args.input, args.verbose)
        result_msg = f"Validation result for {args.input}: {'Valid' if is_valid else 'Invalid'}"
        print(result_msg)
    else:
        print("No action specified. Use --create, --extract, --list, --repack, or --validate.")

if __name__ == "__main__":
    main()
