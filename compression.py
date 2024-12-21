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

    $FileInfo: compression.py - Last Update: 12/20/2024 Ver. 0.15.12 RC 1 - Author: cooldude2k $
'''

from __future__ import absolute_import, division, print_function, unicode_literals, generators, with_statement, nested_scopes
import os
import binascii
import argparse
import shutil
from io import open as open


def CompressionSupport():
    compression_list = []
    try:
        import gzip
        compression_list.append("gz")
        compression_list.append("gzip")
    except ImportError:
        '''return False;'''
    try:
        import bz2
        compression_list.append("bz2")
        compression_list.append("bzip2")
    except ImportError:
        '''return False;'''
    try:
        import lz4
        compression_list.append("lz4")
    except ImportError:
        '''return False;'''
    try:
        import lzo
        compression_list.append("lzo")
        compression_list.append("lzop")
    except ImportError:
        '''return False;'''
    try:
        import zstandard
        compression_list.append("zstd")
        compression_list.append("zstandard")
    except ImportError:
        '''return False;'''
    try:
        import lzma
        compression_list.append("lzma")
        compression_list.append("xz")
    except ImportError:
        '''return False;'''
    return compression_list


def CheckCompressionType(infile, closefp=True):
    if(hasattr(infile, "read") or hasattr(infile, "write")):
        ckcomfp = infile
    else:
        ckcomfp = open(infile, "rb")
    ckcomfp.seek(0, 0)
    prefp = ckcomfp.read(2)
    filetype = False
    if(prefp == binascii.unhexlify("1f8b")):
        filetype = "gzip"
    ckcomfp.seek(0, 0)
    prefp = ckcomfp.read(3)
    if(prefp == binascii.unhexlify("425a68")):
        filetype = "bzip2"
    ckcomfp.seek(0, 0)
    prefp = ckcomfp.read(4)
    if(prefp == binascii.unhexlify("28b52ffd")):
        filetype = "zstd"
    if(prefp == binascii.unhexlify("04224d18")):
        filetype = "lz4"
    ckcomfp.seek(0, 0)
    prefp = ckcomfp.read(7)
    if(prefp == binascii.unhexlify("fd377a585a0000")):
        filetype = "lzma"
    ckcomfp.seek(0, 0)
    prefp = ckcomfp.read(9)
    if(prefp == binascii.unhexlify("894c5a4f000d0a1a0a")):
        filetype = "lzo"
    ckcomfp.seek(0, 0)
    if(closefp):
        ckcomfp.close()
    return filetype


def gzip_file(infile, outfile, level=9, keepfile=True):
    support_list = CompressionSupport()
    if(not os.path.exists(infile) or not os.path.isfile(infile)):
        return False
    if(os.path.exists(outfile)):
        return False
    if("gzip" not in support_list):
        return False
    import gzip
    ucfilefp = open(infile, "rb")
    cfilefp = gzip.open(outfile, "wb", level)
    shutil.copyfileobj(ucfilefp, cfilefp)
    cfilefp.close()
    ucfilefp.close()
    if(CheckCompressionType(outfile) != "gzip"):
        os.remove(outfile)
        return False
    if(not keepfile):
        os.remove(infile)
    return True


def gunzip_file(infile, outfile, keepfile=True):
    support_list = CompressionSupport()
    if(not os.path.exists(infile) or not os.path.isfile(infile)):
        return False
    if(os.path.exists(outfile)):
        return False
    if("gzip" not in support_list):
        return False
    if(CheckCompressionType(infile) != "gzip"):
        return False
    import gzip
    ucfilefp = open(outfile, "wb")
    cfilefp = gzip.open(infile, "rb")
    shutil.copyfileobj(cfilefp, ucfilefp)
    cfilefp.close()
    ucfilefp.close()
    if(not keepfile):
        os.remove(infile)
    return True


def bzip2_file(infile, outfile, level=9, keepfile=True):
    support_list = CompressionSupport()
    if(not os.path.exists(infile) or not os.path.isfile(infile)):
        return False
    if(os.path.exists(outfile)):
        return False
    if("bzip2" not in support_list):
        return False
    import bz2
    ucfilefp = open(infile, "rb")
    cfilefp = bz2.BZ2File(outfile, "wb", compresslevel=level)
    shutil.copyfileobj(ucfilefp, cfilefp)
    cfilefp.close()
    ucfilefp.close()
    if(CheckCompressionType(outfile) != "bzip2"):
        os.remove(outfile)
        return False
    if(not keepfile):
        os.remove(infile)
    return True


def bunzip2_file(infile, outfile, keepfile=True):
    support_list = CompressionSupport()
    if(not os.path.exists(infile) or not os.path.isfile(infile)):
        return False
    if(os.path.exists(outfile)):
        return False
    if("bzip2" not in support_list):
        return False
    if(CheckCompressionType(infile) != "bzip2"):
        return False
    import bz2
    ucfilefp = open(outfile, "wb")
    cfilefp = bz2.BZ2File(infile, "rb")
    shutil.copyfileobj(cfilefp, ucfilefp)
    cfilefp.close()
    ucfilefp.close()
    if(not keepfile):
        os.remove(infile)
    return True


def zstd_file(infile, outfile, level=9, keepfile=True):
    support_list = CompressionSupport()
    if(not os.path.exists(infile) or not os.path.isfile(infile)):
        return False
    if(os.path.exists(outfile)):
        return False
    if("zstd" not in support_list):
        return False
    import zstandard
    ucfilefp = open(infile, "rb")
    cfilefp = zstandard.open(
        outfile, "wb", zstandard.ZstdCompressor(level=level))
    shutil.copyfileobj(ucfilefp, cfilefp)
    cfilefp.close()
    ucfilefp.close()
    if(CheckCompressionType(outfile) != "zstd"):
        os.remove(outfile)
        return False
    if(not keepfile):
        os.remove(infile)
    return True


def unzstd_file(infile, outfile, keepfile=True):
    support_list = CompressionSupport()
    if(not os.path.exists(infile) or not os.path.isfile(infile)):
        return False
    if(os.path.exists(outfile)):
        return False
    if("zstd" not in support_list):
        return False
    if(CheckCompressionType(infile) != "zstd"):
        return False
    import zstandard
    ucfilefp = open(outfile, "wb")
    cfilefp = zstandard.open(infile, "rb")
    shutil.copyfileobj(cfilefp, ucfilefp)
    cfilefp.close()
    ucfilefp.close()
    if(not keepfile):
        os.remove(infile)
    return True


def lz4_file(infile, outfile, level=9, keepfile=True):
    support_list = CompressionSupport()
    if(not os.path.exists(infile) or not os.path.isfile(infile)):
        return False
    if(os.path.exists(outfile)):
        return False
    if("lz4" not in support_list):
        return False
    import lz4
    ucfilefp = open(infile, "rb")
    cfilefp = lz4.frame.open(outfile, "wb", compression_level=level)
    shutil.copyfileobj(ucfilefp, cfilefp)
    cfilefp.close()
    ucfilefp.close()
    if(CheckCompressionType(outfile) != "lz4"):
        os.remove(outfile)
        return False
    if(not keepfile):
        os.remove(infile)
    return True


def unlz4_file(infile, outfile, keepfile=True):
    support_list = CompressionSupport()
    if(not os.path.exists(infile) or not os.path.isfile(infile)):
        return False
    if(os.path.exists(outfile)):
        return False
    if("lz4" not in support_list):
        return False
    if(CheckCompressionType(infile) != "lz4"):
        return False
    import lz4
    ucfilefp = open(outfile, "wb")
    cfilefp = lz4.frame.open(infile, "rb")
    shutil.copyfileobj(cfilefp, ucfilefp)
    cfilefp.close()
    ucfilefp.close()
    if(not keepfile):
        os.remove(infile)
    return True


def lzo_file(infile, outfile, level=9, keepfile=True):
    support_list = CompressionSupport()
    if(not os.path.exists(infile) or not os.path.isfile(infile)):
        return False
    if(os.path.exists(outfile)):
        return False
    if("lzo" not in support_list):
        return False
    import lzo
    ucfilefp = open(infile, "rb")
    cfilefp = open(outfile, "wb")
    cfilefp.write(lzo.compress(ucfilefp.read(), level))
    cfilefp.close()
    ucfilefp.close()
    if(CheckCompressionType(outfile) != "lzo"):
        os.remove(outfile)
        return False
    if(not keepfile):
        os.remove(infile)
    return True


def unlzo_file(infile, outfile, keepfile=True):
    support_list = CompressionSupport()
    if(not os.path.exists(infile) or not os.path.isfile(infile)):
        return False
    if(os.path.exists(outfile)):
        return False
    if("lzo" not in support_list):
        return False
    if(CheckCompressionType(infile) != "lzo"):
        return False
    import lzo
    ucfilefp = open(outfile, "wb")
    cfilefp = open(infile, "rb")
    ucfilefp.write(lzo.decompress(cfilefp.read()))
    cfilefp.close()
    ucfilefp.close()
    if(not keepfile):
        os.remove(infile)
    return True


def lzma_file(infile, outfile, level=9, keepfile=True):
    support_list = CompressionSupport()
    if(not os.path.exists(infile) or not os.path.isfile(infile)):
        return False
    if(os.path.exists(outfile)):
        return False
    if("lzma" not in support_list):
        return False
    import lzma
    ucfilefp = open(infile, "rb")
    cfilefp = lzma.open(outfile, "wb", format=lzma.FORMAT_ALONE, preset=level)
    shutil.copyfileobj(ucfilefp, cfilefp)
    cfilefp.close()
    ucfilefp.close()
    if(CheckCompressionType(outfile) != "lzma"):
        os.remove(outfile)
        return False
    if(not keepfile):
        os.remove(infile)
    return True


def unlzma_file(infile, outfile, keepfile=True):
    support_list = CompressionSupport()
    if(not os.path.exists(infile) or not os.path.isfile(infile)):
        return False
    if(os.path.exists(outfile)):
        return False
    if("lzma" not in support_list):
        return False
    if(CheckCompressionType(infile) != "lzma"):
        return False
    import lzma
    ucfilefp = open(outfile, "wb")
    cfilefp = lzma.open(infile, "rb", format=lzma.FORMAT_ALONE)
    shutil.copyfileobj(cfilefp, ucfilefp)
    cfilefp.close()
    ucfilefp.close()
    if(not keepfile):
        os.remove(infile)
    return True


def xz_file(infile, outfile, level=9, keepfile=True):
    support_list = CompressionSupport()
    if(not os.path.exists(infile) or not os.path.isfile(infile)):
        return False
    if(os.path.exists(outfile)):
        return False
    if("xz" not in support_list):
        return False
    import lzma
    ucfilefp = open(infile, "rb")
    cfilefp = lzma.open(outfile, "wb", format=lzma.FORMAT_XZ, preset=level)
    shutil.copyfileobj(ucfilefp, cfilefp)
    cfilefp.close()
    ucfilefp.close()
    if(CheckCompressionType(outfile) != "xz"):
        os.remove(outfile)
        return False
    if(not keepfile):
        os.remove(infile)
    return True


def unxz_file(infile, outfile, keepfile=True):
    support_list = CompressionSupport()
    if(not os.path.exists(infile) or not os.path.isfile(infile)):
        return False
    if(os.path.exists(outfile)):
        return False
    if("xz" not in support_list):
        return False
    if(CheckCompressionType(infile) != "xz"):
        return False
    import lzma
    ucfilefp = open(outfile, "wb")
    cfilefp = lzma.open(infile, "rb", format=lzma.FORMAT_XZ)
    shutil.copyfileobj(cfilefp, ucfilefp)
    cfilefp.close()
    ucfilefp.close()
    if(not keepfile):
        os.remove(infile)
    return True


if __name__ == "__main__":
    argparser = argparse.ArgumentParser(
        description="Compress Files", conflict_handler="resolve", add_help=True)
    argparser.add_argument(
        "-V", "--version", action="version", version="PyCompress 0.0.1")
    argparser.add_argument(
        "-c", "--compress", action="store_true", help="Compress file")
    argparser.add_argument("-d", "--decompress",
                           action="store_true", help="Decompress file")
    argparser.add_argument("-i", "-f", "--input",
                           help="Files to compress/decompress", required=True)
    argparser.add_argument(
        "-o", "--output", help="Output file after compress/decompress", required=True)
    argparser.add_argument(
        "-k", "--keep", action="store_false", help="Keep input file")
    argparser.add_argument("-l", "--level", default="1",
                           help="Compression level")
    argparser.add_argument("-compression", "--compression", default="auto",
                           help="File compression to use for compress/decompress")
    getargs = argparser.parse_args()
    chkcompression = CompressionSupport()
    if(getargs.compression not in chkcompression):
        exit()
    if(not getargs.compress and not getargs.decompress):
        exit()
    if(getargs.compress and getargs.decompress):
        exit()
    if(getargs.compress and not getargs.decompress):
        if(getargs.compression == "gzip" and "gzip" in chkcompression):
            gzip_file(getargs.input, getargs.output,
                      int(getargs.level), getargs.keep)
        if(getargs.compression == "bzip2" and "bzip2" in chkcompression):
            bzip2_file(getargs.input, getargs.output,
                       int(getargs.level), getargs.keep)
        if(getargs.compression == "zstd" and "zstd" in chkcompression):
            zstd_file(getargs.input, getargs.output,
                      int(getargs.level), getargs.keep)
        if(getargs.compression == "lz4" and "lz4" in chkcompression):
            lz4_file(getargs.input, getargs.output,
                     int(getargs.level), getargs.keep)
        if(getargs.compression == "lzo" and "lzo" in chkcompression):
            lzo_file(getargs.input, getargs.output,
                     int(getargs.level), getargs.keep)
        if(getargs.compression == "lzma" and "lzma" in chkcompression):
            lzma_file(getargs.input, getargs.output,
                      int(getargs.level), getargs.keep)
        if(getargs.compression == "xz" and "xz" in chkcompression):
            xz_file(getargs.input, getargs.output,
                    int(getargs.level), getargs.keep)
        exit()
    if(not getargs.compress and getargs.decompress):
        if(getargs.compression == "gzip" and "gzip" in chkcompression):
            gunzip_file(getargs.input, getargs.output, getargs.keep)
        if(getargs.compression == "bzip2" and "bzip2" in chkcompression):
            bunzip2_file(getargs.input, getargs.output, getargs.keep)
        if(getargs.compression == "zstd" and "zstd" in chkcompression):
            unzstd_file(getargs.input, getargs.output, getargs.keep)
        if(getargs.compression == "lz4" and "lz4" in chkcompression):
            unlz4_file(getargs.input, getargs.output, getargs.keep)
        if(getargs.compression == "lzo" and "lzo" in chkcompression):
            unlzo_file(getargs.input, getargs.output, getargs.keep)
        if(getargs.compression == "lzma" and "lzma" in chkcompression):
            unlzma_file(getargs.input, getargs.output, getargs.keep)
        if(getargs.compression == "xz" and "xz" in chkcompression):
            unxz_file(getargs.input, getargs.output, getargs.keep)
        exit()
