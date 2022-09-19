#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
    This program is free software; you can redistribute it and/or modify
    it under the terms of the Revised BSD License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Revised BSD License for more details.

    Copyright 2018-2022 Cool Dude 2k - http://idb.berlios.de/
    Copyright 2018-2022 Game Maker 2k - http://intdb.sourceforge.net/
    Copyright 2018-2022 Kazuki Przyborowski - https://github.com/KazukiPrzyborowski

    $FileInfo: compression.py - Last Update: 9/16/2022 Ver. 0.0.1 RC 1 - Author: cooldude2k $
'''

from __future__ import absolute_import, division, print_function, unicode_literals;
import os, binascii, shutil;
from io import open as open;

def CompressionSupport():
 compression_list = [];
 try:
  import gzip;
  compression_list.append("gz");
  compression_list.append("gzip");
 except ImportError:
  '''return False;'''
 try:
  import bz2;
  compression_list.append("bz2");
  compression_list.append("bzip2");
 except ImportError:
  '''return False;'''
 try:
  import lz4;
  compression_list.append("lz4");
 except ImportError:
  '''return False;'''
 try:
  import lzo;
  compression_list.append("lzo");
  compression_list.append("lzop");
 except ImportError:
  '''return False;'''
 try:
  import zstandard;
  compression_list.append("zstd");
  compression_list.append("zstandard");
 except ImportError:
  '''return False;'''
 try:
  import lzma;
  compression_list.append("lzma");
  compression_list.append("xz");
 except ImportError:
  '''return False;'''
 return compression_list;

def CheckCompressionType(infile, closefp=True):
 if(hasattr(infile, "read") or hasattr(infile, "write")):
  ckcomfp = infile;
 else:
  ckcomfp = open(infile, "rb");
 ckcomfp.seek(0, 0);
 prefp = ckcomfp.read(2);
 filetype = False;
 if(prefp==binascii.unhexlify("1f8b")):
  filetype = "gzip";
 ckcomfp.seek(0, 0);
 prefp = ckcomfp.read(3);
 if(prefp==binascii.unhexlify("425a68")):
  filetype = "bzip2";
 ckcomfp.seek(0, 0);
 prefp = ckcomfp.read(4);
 if(prefp==binascii.unhexlify("28b52ffd")):
  filetype = "zstd";
 if(prefp==binascii.unhexlify("04224d18")):
  filetype = "lz4";
 ckcomfp.seek(0, 0);
 prefp = ckcomfp.read(7);
 if(prefp==binascii.unhexlify("fd377a585a0000")):
  filetype = "lzma";
 ckcomfp.seek(0, 0);
 prefp = ckcomfp.read(9);
 if(prefp==binascii.unhexlify("894c5a4f000d0a1a0a")):
  filetype = "lzo";
 ckcomfp.seek(0, 0);
 if(closefp):
  ckcomfp.close();
 return filetype;

def gzip_file(infile, outfile, level=9, keepfile=True):
 support_list = CompressionSupport();
 if("gzip" not in support_list):
  return False;
 import gzip;
 ucfilefp = open(infile, "rb");
 cfilefp = gzip.open(outfile, "wb", level);
 shutil.copyfileobj(ucfilefp, cfilefp);
 cfilefp.close();
 ucfilefp.close();
 if(CheckCompressionType(outfile)!="gzip"):
  os.remove(outfile);
  return False;
 if(not keepfile):
  os.remove(infile);
 return True;

def gunzip_file(infile, outfile, keepfile=True):
 support_list = CompressionSupport();
 if("gzip" not in support_list):
  return False;
 if(CheckCompressionType(infile)!="gzip"):
  return False;
 import gzip;
 ucfilefp = open(outfile, "wb");
 cfilefp = gzip.open(infile, "rb");
 shutil.copyfileobj(cfilefp, ucfilefp);
 cfilefp.close();
 ucfilefp.close();
 if(not keepfile):
  os.remove(infile);
 return True;

def bzip2_file(infile, outfile, level=9, keepfile=True):
 support_list = CompressionSupport();
 if("bzip2" not in support_list):
  return False;
 import bz2;
 ucfilefp = open(infile, "rb");
 cfilefp = bz2.BZ2File(outfile, "wb", compresslevel=level);
 shutil.copyfileobj(ucfilefp, cfilefp);
 cfilefp.close();
 ucfilefp.close();
 if(CheckCompressionType(outfile)!="bzip2"):
  os.remove(outfile);
  return False;
 if(not keepfile):
  os.remove(infile);
 return True;

def bunzip2_file(infile, outfile, keepfile=True):
 support_list = CompressionSupport();
 if("bzip2" not in support_list):
  return False;
 if(CheckCompressionType(infile)!="bzip2"):
  return False;
 import bz2;
 ucfilefp = open(outfile, "wb");
 cfilefp = bz2.BZ2File(infile, "rb");
 shutil.copyfileobj(cfilefp, ucfilefp);
 cfilefp.close();
 ucfilefp.close();
 if(not keepfile):
  os.remove(infile);
 return True;

def zstdzip_file(infile, outfile, level=9, keepfile=True):
 support_list = CompressionSupport();
 if("zstd" not in support_list):
  return False;
 import zstandard;
 ucfilefp = open(infile, "rb");
 cfilefp = zstandard.open(outfile, "wb", zstandard.ZstdCompressor(level=level));
 shutil.copyfileobj(ucfilefp, cfilefp);
 cfilefp.close();
 ucfilefp.close();
 if(CheckCompressionType(outfile)!="zstd"):
  os.remove(outfile);
  return False;
 if(not keepfile):
  os.remove(infile);
 return True;

def zstdunzip_file(infile, outfile, keepfile=True):
 support_list = CompressionSupport();
 if("zstd" not in support_list):
  return False;
 if(CheckCompressionType(infile)!="zstd"):
  return False;
 import zstandard;
 ucfilefp = open(outfile, "wb");
 cfilefp = zstandard.open(infile, "rb");
 shutil.copyfileobj(cfilefp, ucfilefp);
 cfilefp.close();
 ucfilefp.close();
 if(not keepfile):
  os.remove(infile);
 return True;

def lz4zip_file(infile, outfile, level=9, keepfile=True):
 support_list = CompressionSupport();
 if("lz4" not in support_list):
  return False;
 import lz4;
 ucfilefp = open(infile, "rb");
 cfilefp = lz4.frame.open(outfile, "wb", compression_level=level);
 shutil.copyfileobj(ucfilefp, cfilefp);
 cfilefp.close();
 ucfilefp.close();
 if(CheckCompressionType(outfile)!="lz4"):
  os.remove(outfile);
  return False;
 if(not keepfile):
  os.remove(infile);
 return True;

def lz4unzip_file(infile, outfile, keepfile=True):
 support_list = CompressionSupport();
 if("lz4" not in support_list):
  return False;
 if(CheckCompressionType(infile)!="lz4"):
  return False;
 import lz4;
 ucfilefp = open(outfile, "wb");
 cfilefp = lz4.frame.open(infile, "rb");
 shutil.copyfileobj(cfilefp, ucfilefp);
 cfilefp.close();
 ucfilefp.close();
 if(not keepfile):
  os.remove(infile);
 return True;

def lzmazip_file(infile, outfile, level=9, keepfile=True):
 support_list = CompressionSupport();
 if("lzma" not in support_list):
  return False;
 import lzma;
 ucfilefp = open(infile, "rb");
 cfilefp = lzma.open(outfile, "wb", format=lzma.FORMAT_ALONE, preset=level);
 shutil.copyfileobj(ucfilefp, cfilefp);
 cfilefp.close();
 ucfilefp.close();
 if(CheckCompressionType(outfile)!="lzma"):
  os.remove(outfile);
  return False;
 if(not keepfile):
  os.remove(infile);
 return True;

def lzmaunzip_file(infile, outfile, keepfile=True):
 support_list = CompressionSupport();
 if("lzma" not in support_list):
  return False;
 if(CheckCompressionType(infile)!="lzma"):
  return False;
 import lzma;
 ucfilefp = open(outfile, "wb");
 cfilefp = lzma.open(infile, "rb", format=lzma.FORMAT_ALONE);
 shutil.copyfileobj(cfilefp, ucfilefp);
 cfilefp.close();
 ucfilefp.close();
 if(not keepfile):
  os.remove(infile);
 return True;

def xzzip_file(infile, outfile, level=9, keepfile=True):
 support_list = CompressionSupport();
 if("xz" not in support_list):
  return False;
 import lzma;
 ucfilefp = open(infile, "rb");
 cfilefp = lzma.open(outfile, "wb", format=lzma.FORMAT_XZ, preset=level);
 shutil.copyfileobj(ucfilefp, cfilefp);
 cfilefp.close();
 ucfilefp.close();
 if(CheckCompressionType(outfile)!="xz"):
  os.remove(outfile);
  return False;
 if(not keepfile):
  os.remove(infile);
 return True;

def xzunzip_file(infile, outfile, keepfile=True):
 support_list = CompressionSupport();
 if("xz" not in support_list):
  return False;
 if(CheckCompressionType(infile)!="xz"):
  return False;
 import lzma;
 ucfilefp = open(outfile, "wb");
 cfilefp = lzma.open(infile, "rb", format=lzma.FORMAT_XZ);
 shutil.copyfileobj(cfilefp, ucfilefp);
 cfilefp.close();
 ucfilefp.close();
 if(not keepfile):
  os.remove(infile);
 return True;
