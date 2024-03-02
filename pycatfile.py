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

    $FileInfo: pycatfile.py - Last Update: 3/1/2024 Ver. 0.2.0 RC 1 - Author: cooldude2k $
'''

from __future__ import absolute_import, division, print_function, unicode_literals;
import os, re, sys, time, marshal, stat, zlib, base64, shutil, hashlib, datetime, logging, binascii, tempfile, zipfile, ftplib;

hashlib_guaranteed = False;
os.environ["PYTHONIOENCODING"] = "UTF-8";
os.environ["LC_CTYPE"] = "UTF-8";
try:
 reload(sys);
 try:
  sys.setdefaultencoding('UTF-8');
 except NameError:
  pass;
 except AttributeError:
  pass;
except NameError:
 pass;
except AttributeError:
 pass;
if(hasattr(sys, "setdefaultencoding")):
 sys.setdefaultencoding('UTF-8');
if(hasattr(sys.stdout, "detach")):
 import io;
 sys.stdout = io.TextIOWrapper(sys.stdout.detach(), encoding = 'UTF-8');
if(hasattr(sys.stderr, "detach")):
 import io;
 sys.stderr = io.TextIOWrapper(sys.stderr.detach(), encoding = 'UTF-8');
from io import open as open;

try:
 import simplejson as json;
except ImportError:
 import json;

try:
 import cPickle as pickle;
except ImportError:
 import pickle;

pickledp = None;
try:
 pickledp = pickle.DEFAULT_PROTOCOL;
except AttributeError:
 pickledp = 2;

try:
 from zlib import crc32;
except ImportError:
 from binascii import crc32;

try:
 from safetar import is_tarfile;
except ImportError:
 try:
  from xtarfile import is_tarfile;
 except ImportError:
  from tarfile import is_tarfile;

try:
 import safetar as tarfile;
except ImportError:
 try:
  import xtarfile as tarfile;
 except ImportError:
  import tarfile;

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

__file_format_name__ = "CatFile";
__program_name__ = "Py"+__file_format_name__;
__file_format_lower__ = __file_format_name__.lower();
__file_format_len__ = len(__file_format_name__);
__file_format_hex__ = binascii.hexlify(__file_format_name__.encode("UTF-8")).decode("UTF-8");
__file_format_delimiter__ = "\x00";
__project__ = __program_name__;
__project_url__ = "https://github.com/GameMaker2k/PyCatFile";
__version_info__ = (0, 2, 0, "RC 1", 1);
__version_date_info__ = (2024, 3, 1, "RC 1", 1);
__version_date__ = str(__version_date_info__[0]) + "." + str(__version_date_info__[1]).zfill(2) + "." + str(__version_date_info__[2]).zfill(2);
__revision__ = __version_info__[3];
__revision_id__ = "$Id$";
if(__version_info__[4] is not None):
 __version_date_plusrc__ = __version_date__ + "-" + str(__version_date_info__[4]);
if(__version_info__[4] is None):
 __version_date_plusrc__ = __version_date__;
if(__version_info__[3] is not None):
 __version__ = str(__version_info__[0]) + "." + str(__version_info__[1]) + "." + str(__version_info__[2]) + " " + str(__version_info__[3]);
if(__version_info__[3] is None):
 __version__ = str(__version_info__[0]) + "." + str(__version_info__[1]) + "." + str(__version_info__[2]);
__cat_header_ver__ = "001";

compressionlist = ['auto', 'gzip', 'bzip2', 'zstd', 'xz', 'lz4', 'lzo', 'lzma'];
outextlist = ['gz', 'bz2', 'zst', 'xz', 'lz4', 'lzo', 'lzma'];
outextlistwd = ['.gz', '.bz2', '.zst', '.xz', '.lz4', '.lzo', '.lzma'];

tarfile_mimetype = "application/tar";
tarfile_tar_mimetype = tarfile_mimetype;
zipfile_mimetype = "application/zip";
zipfile_zip_mimetype = zipfile_mimetype;
catfile_mimetype = "application/x-catfile";
catfile_cat_mimetype = catfile_mimetype;
catfile_gzip_mimetype = "application/x-catfile+gzip";
catfile_gz_mimetype = catfile_gzip_mimetype;
catfile_bzip2_mimetype = "application/x-catfile+bzip2";
catfile_bz2_mimetype = catfile_bzip2_mimetype;
catfile_lz4_mimetype = "application/x-catfile+lz4";
catfile_lzop_mimetype = "application/x-catfile+lzop";
catfile_lzo_mimetype = catfile_lzop_mimetype;
catfile_zstandard_mimetype = "application/x-catfile+zstandard";
catfile_zstd_mimetype = catfile_zstandard_mimetype;
catfile_lzma_mimetype = "application/x-catfile+lzma";
catfile_xz_mimetype = "application/x-catfile+xz";
catfile_extensions = ['.cat', '.cat.gz', '.cgz', '.cat.bz2', '.cbz', '.cat.zst', '.czst', '.cat.lz4', '.clz4', '.cat.lzo', '.cat.lzop', '.clzo', '.cat.lzma', '.cat.xz', '.cxz'];

if __name__ == "__main__":
 import subprocess;
 curscrpath = os.path.dirname(sys.argv[0]);
 if(curscrpath==""):
  curscrpath = ".";
 if(os.sep=="\\"):
  curscrpath = curscrpath.replace(os.sep, "/");
 curscrpath = curscrpath + "/";
 scrfile = curscrpath + "catfile.py";
 if(os.path.exists(scrfile) and os.path.isfile(scrfile)):
  scrcmd = subprocess.Popen([sys.executable, scrfile] + sys.argv[1:]);
  scrcmd.wait();

def VerbosePrintOut(dbgtxt, outtype="log", dbgenable=True, dgblevel=20):
 if(not dbgenable):
  return True;
 log_functions = {
  "print": print,
  "log": logging.info,
  "warning": logging.warning,
  "error": logging.error,
  "critical": logging.critical,
  "exception": logging.exception,
  "logalt": lambda x: logging.log(dgblevel, x),
  "debug": logging.debug
 };
 log_function = log_functions.get(outtype);
 if(log_function):
  log_function(dbgtxt);
  return True;
 return False;

def VerbosePrintOutReturn(dbgtxt, outtype="log", dbgenable=True, dgblevel=20):
 VerbosePrintOut(dbgtxt, outtype, dbgenable, dgblevel);
 return dbgtxt;

def RemoveWindowsPath(dpath):
 if(dpath is None):
  dpath = "";
 if(os.sep!="/"):
  dpath = dpath.replace(os.path.sep, "/");
 dpath = dpath.rstrip("/");
 if(dpath=="." or dpath==".."):
  dpath = dpath + "/";
 return dpath;

def NormalizeRelativePath(inpath):
 inpath = RemoveWindowsPath(inpath);
 if(os.path.isabs(inpath)):
  outpath = inpath;
 else:
  if(inpath.startswith("./") or inpath.startswith("../")):
   outpath = inpath;
  else:
   outpath = "./" + inpath;
 return outpath;

def ListDir(dirpath, followlink=False, duplicates=False):
 if(isinstance(dirpath, (list, tuple, ))):
  dirpath = list(filter(None, dirpath));
 elif(isinstance(dirpath, (str, ))):
  dirpath = list(filter(None, [dirpath]));
 retlist = [];
 for mydirfile in dirpath:
  if(not os.path.exists(mydirfile)):
   return False;
  mydirfile = NormalizeRelativePath(mydirfile);
  if(os.path.exists(mydirfile) and os.path.islink(mydirfile)):
   mydirfile = RemoveWindowsPath(os.path.realpath(mydirfile));
  if(os.path.exists(mydirfile) and os.path.isdir(mydirfile)):
   for root, dirs, filenames in os.walk(mydirfile):
    dpath = root;
    dpath = RemoveWindowsPath(dpath);
    if(dpath not in retlist and not duplicates):
     retlist.append(dpath);
    if(duplicates):
     retlist.append(dpath);
    for file in filenames:
     fpath = os.path.join(root, file);
     fpath = RemoveWindowsPath(fpath);
     if(fpath not in retlist and not duplicates):
      retlist.append(fpath);
     if(duplicates):
      retlist.append(fpath);
  else:
   retlist.append(RemoveWindowsPath(mydirfile));
 return retlist;

def ListDirAdvanced(dirpath, followlink=False, duplicates=False):
 if isinstance(dirpath, (list, tuple)):
  dirpath = list(filter(None, dirpath));
 elif isinstance(dirpath, str):
  dirpath = list(filter(None, [dirpath]));
 retlist = []
 for mydirfile in dirpath:
  if not os.path.exists(mydirfile):
   return False;
  mydirfile = NormalizeRelativePath(mydirfile);
  if os.path.exists(mydirfile) and os.path.islink(mydirfile) and followlink:
   mydirfile = RemoveWindowsPath(os.path.realpath(mydirfile))
  if os.path.exists(mydirfile) and os.path.isdir(mydirfile):
   for root, dirs, filenames in os.walk(mydirfile):
    # Sort dirs and filenames alphabetically in place
    dirs.sort(key=lambda x: x.lower());
    filenames.sort(key=lambda x: x.lower());
    dpath = RemoveWindowsPath(root);
    if not duplicates and dpath not in retlist:
     retlist.append(dpath);
    elif duplicates:
     retlist.append(dpath);
    for file in filenames:
     fpath = os.path.join(root, file);
     fpath = RemoveWindowsPath(fpath);
     if not duplicates and fpath not in retlist:
      retlist.append(fpath);
     elif duplicates:
      retlist.append(fpath);
  else:
   retlist.append(RemoveWindowsPath(mydirfile));
 return retlist;

# initial_value can be 0xFFFF or 0x0000
def crc16_ansi(msg, initial_value=0xFFFF):
 # CRC-16-IBM / CRC-16-ANSI polynomial and initial value
 poly = 0x8005;  # Polynomial for CRC-16-IBM / CRC-16-ANSI
 crc = initial_value;  # Initial value
 for b in msg:
  crc ^= b << 8;  # XOR byte into CRC top byte
  for _ in range(8):  # Process each bit
   if crc & 0x8000:  # If the top bit is set
    crc = (crc << 1) ^ poly;  # Shift left and XOR with the polynomial
   else:
    crc = crc << 1;  # Just shift left
   crc &= 0xFFFF;  # Ensure CRC remains 16-bit
 return crc;

# initial_value can be 0xFFFF or 0x0000
def crc16_ibm(msg, initial_value=0xFFFF):
 return crc16_ansi(msg, initial_value);

# initial_value is 0xFFFF
def crc16(msg):
 return crc16_ansi(msg, 0xFFFF);

# initial_value can be 0xFFFF, 0x1D0F or 0x0000
def crc16_ccitt(msg, initial_value=0xFFFF):
 # CRC-16-CCITT polynomial
 poly = 0x1021;  # Polynomial for CRC-16-CCITT
 # Use the specified initial value
 crc = initial_value;
 for b in msg:
  crc ^= b << 8;  # XOR byte into CRC top byte
  for _ in range(8):  # Process each bit
   if crc & 0x8000:  # If the top bit is set
    crc = (crc << 1) ^ poly;  # Shift left and XOR with the polynomial
   else:
    crc = crc << 1;  # Just shift left
   crc &= 0xFFFF;  # Ensure CRC remains 16-bit
 return crc;

# initial_value can be 0x42F0E1EBA9EA3693 or 0x0000000000000000
def crc64_ecma(msg, initial_value=0x0000000000000000):
 # CRC-64-ECMA polynomial and initial value
 poly = 0x42F0E1EBA9EA3693;
 crc = initial_value;  # Initial value for CRC-64-ECMA
 for b in msg:
  crc ^= b << 56;  # XOR byte into the most significant byte of the CRC
  for _ in range(8):  # Process each bit
   if crc & (1 << 63):  # Check if the leftmost (most significant) bit is set
    crc = (crc << 1) ^ poly;  # Shift left and XOR with poly if the MSB is 1
   else:
    crc <<= 1;  # Just shift left if the MSB is 0
   crc &= 0xFFFFFFFFFFFFFFFF;  # Ensure CRC remains 64-bit
 return crc;

# initial_value can be 0x000000000000001B or 0xFFFFFFFFFFFFFFFF
def crc64_iso(msg, initial_value=0xFFFFFFFFFFFFFFFF):
 # CRC-64-ISO polynomial and initial value
 poly = 0x000000000000001B;
 crc = initial_value;  # Common initial value for CRC-64-ISO
 for b in msg:
  crc ^= b << 56;  # XOR byte into the most significant byte of the CRC
  for _ in range(8):  # Process each bit
   if crc & (1 << 63):  # Check if the leftmost (most significant) bit is set
    crc = (crc << 1) ^ poly;  # Shift left and XOR with poly if the MSB is 1
   else:
    crc <<= 1;  # Just shift left if the MSB is 0
   crc &= 0xFFFFFFFFFFFFFFFF;  # Ensure CRC remains 64-bit
 return crc;

def ReadTillNullByte(fp, delimiter=__file_format_delimiter__):
 curbyte = b"";
 curfullbyte = b"";
 nullbyte = delimiter.encode("UTF-8");
 while(True):
  curbyte = fp.read(1);
  if(curbyte==nullbyte or not curbyte):
   break;
  curfullbyte = curfullbyte + curbyte;
 return curfullbyte.decode('UTF-8');

def ReadUntilNullByte(fp, delimiter=__file_format_delimiter__):
 return ReadTillNullByte(fp, delimiter);

def SeekToEndOfFile(fp):
 lasttell = 0;
 while(True):
  fp.seek(1, 1);
  if(lasttell==fp.tell()):
   break;
  lasttell = fp.tell();
 return True;

def ReadFileHeaderData(fp, rounds=0, delimiter=__file_format_delimiter__):
 rocount = 0;
 roend = int(rounds);
 HeaderOut = [];
 while(rocount<roend):
  HeaderOut.append(ReadTillNullByte(fp, delimiter));
  rocount = rocount + 1;
 return HeaderOut;

def ReadFileHeaderDataByList(fp, listval=[], delimiter=__file_format_delimiter__):
 rocount = 0;
 roend = int(len(listval));
 HeaderOut = {};
 while(rocount<roend):
  RoundArray = {listval[rocount]: ReadTillNullByte(fp, delimiter)};
  HeaderOut.update(RoundArray);
  rocount = rocount + 1;
 return HeaderOut;

def AppendNullByte(indata, delimiter=__file_format_delimiter__):
 outdata = str(indata) + delimiter;
 return outdata;

def AppendNullBytes(indata=[], delimiter=__file_format_delimiter__):
 outdata = "";
 inum = 0;
 il = len(indata);
 while(inum < il):
  outdata = outdata + AppendNullByte(indata[inum]);
  inum = inum + 1;
 return outdata;

def ReadTillNullByteAlt(fp, delimiter=__file_format_delimiter__):
 """Read bytes from file pointer until a null byte is encountered."""
 bytes_list = []  # Use list for efficient append operation.
 while True:
  cur_byte = fp.read(1);
  if cur_byte == delimiter.encode() or not cur_byte:
   break;
  bytes_list.append(cur_byte);
 return b''.join(bytes_list).decode('UTF-8');

def ReadUntilNullByteAlt(fp, delimiter=__file_format_delimiter__):
 return ReadTillNullByteAlt(fp, delimiter);

def ReadFileHeaderDataAlt(fp, rounds=0, delimiter=__file_format_delimiter__):
 """Read multiple null-byte terminated strings from a file."""
 header_out = [];
 for round_count in range(rounds):
  header_out[round_count] = ReadTillNullByteAlt(fp, delimiter);
 return header_out;

def ReadFileHeaderDataByListAlt(fp, listval=[], delimiter=__file_format_delimiter__):
 """Read multiple null-byte terminated strings from a file."""
 header_out = {};
 for round_count in listval:
  header_out.append(ReadTillNullByteAlt(fp, delimiter));
 return header_out;

def AppendNullByteAlt(indata, delimiter=__file_format_delimiter__):
 """Append a null byte to the given data."""
 return str(indata) + delimiter;

def AppendNullBytesAlt(indata=[], delimiter=__file_format_delimiter__):
 """Append a null byte to each element in the list and concatenate."""
 return delimiter.join(map(str, indata)) + delimiter;  # Efficient concatenation with null byte.

def PrintPermissionString(fchmode, ftype):
 permissions = { 'access': { '0': ('---'), '1': ('--x'), '2': ('-w-'), '3': ('-wx'), '4': ('r--'), '5': ('r-x'), '6': ('rw-'), '7': ('rwx') }, 'roles': { 0: 'owner', 1: 'group', 2: 'other' } };
 permissionstr = "";
 for fmodval in str(oct(fchmode))[-3:]:
  permissionstr = permissionstr + permissions['access'].get(fmodval, '---');
 if(ftype==0 or ftype==7):
  permissionstr = "-" + permissionstr;
 if(ftype==1):
  permissionstr = "h" + permissionstr;
 if(ftype==2):
  permissionstr = "l" + permissionstr;
 if(ftype==3):
  permissionstr = "c" + permissionstr;
 if(ftype==4):
  permissionstr = "b" + permissionstr;
 if(ftype==5):
  permissionstr = "d" + permissionstr;
 if(ftype==6):
  permissionstr = "f" + permissionstr;
 if(ftype==8):
  permissionstr = "D" + permissionstr;
 if(ftype==9):
  permissionstr = "p" + permissionstr;
 if(ftype==10):
  permissionstr = "w" + permissionstr;
 try:
  permissionoutstr = stat.filemode(fchmode);
 except AttributeError:
  permissionoutstr = permissionstr;
 except KeyError:
  permissionoutstr = permissionstr;
 return permissionoutstr;

def PrintPermissionStringAlt(fchmode, ftype):
 permissions = {
  '0': '---', '1': '--x', '2': '-w-', '3': '-wx',
  '4': 'r--', '5': 'r-x', '6': 'rw-', '7': 'rwx'
 };
 # Translate file mode into permission string
 permissionstr = ''.join([permissions[i] for i in str(oct(fchmode))[-3:]]);
 # Append file type indicator
 type_indicators = {
  0: '-', 1: 'h', 2: 'l', 3: 'c', 4: 'b',
  5: 'd', 6: 'f', 8: 'D', 9: 'p', 10: 'w'
 };
 file_type = type_indicators.get(ftype, '-');
 permissionstr = file_type + permissionstr;
 try:
  permissionoutstr = stat.filemode(fchmode);
 except AttributeError:
  permissionoutstr = permissionstr;
 return permissionoutstr;

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
  catfp = infile;
 else:
  catfp = open(infile, "rb");
 catfp.seek(0, 0);
 prefp = catfp.read(2);
 filetype = False;
 if(prefp==binascii.unhexlify("1f8b")):
  filetype = "gzip";
 catfp.seek(0, 0);
 prefp = catfp.read(3);
 if(prefp==binascii.unhexlify("425a68")):
  filetype = "bzip2";
 catfp.seek(0, 0);
 prefp = catfp.read(4);
 if(prefp==binascii.unhexlify("28b52ffd")):
  filetype = "zstd";
 if(prefp==binascii.unhexlify("04224d18")):
  filetype = "lz4";
 if(prefp==binascii.unhexlify("504B0304")):
  filetype = "zipfile";
 catfp.seek(0, 0);
 prefp = catfp.read(5);
 if(prefp==binascii.unhexlify("7573746172")):
  filetype = "tarfile";
 catfp.seek(0, 0);
 prefp = catfp.read(7);
 if(prefp==binascii.unhexlify("fd377a585a0000")):
  filetype = "lzma";
 if(prefp==binascii.unhexlify("43617446696c65")):
  filetype = "catfile";
 catfp.seek(0, 0);
 prefp = catfp.read(__file_format_len__);
 if(prefp==binascii.unhexlify(__file_format_hex__)):
  filetype = __file_format_lower__;
 catfp.seek(0, 0);
 prefp = catfp.read(9);
 if(prefp==binascii.unhexlify("894c5a4f000d0a1a0a")):
  filetype = "lzo";
 catfp.seek(0, 0);
 prefp = catfp.read(10);
 if(prefp==binascii.unhexlify("7061785f676c6f62616c")):
  filetype = "tarfile";
 catfp.seek(0, 0);
 if(closefp):
  catfp.close();
 return filetype;

def CheckCompressionTypeFromString(instring, closefp=True):
 try:
  instringsfile = BytesIO(instring);
 except TypeError:
  instringsfile = BytesIO(instring.encode("UTF-8"));
 return CheckCompressionType(instringsfile, closefp);

def GetCompressionMimeType(infile):
 compresscheck = CheckCompressionType(fp, False);
 if(compresscheck=="gzip" or compresscheck=="gz"):
  return catfile_gzip_mimetype;
 if(compresscheck=="bzip2" or compresscheck=="bz2"):
  return catfile_bzip2_mimetype;
 if(compresscheck=="zstd" or compresscheck=="zstandard"):
  return catfile_zstandard_mimetype;
 if(compresscheck=="lz4"):
  return catfile_lz4_mimetype;
 if(compresscheck=="lzo" or compresscheck=="lzop"):
  return catfile_lzop_mimetype;
 if(compresscheck=="lzma"):
  return catfile_lzma_mimetype;
 if(compresscheck=="xz"):
  return catfile_xz_mimetype;
 if(compresscheck=="catfile" or compresscheck=="cat" or compresscheck==__file_format_lower__):
  return catfile_cat_mimetype;
 if(not compresscheck):
  return False;
 return False;

def UncompressCatFile(fp):
 if(not hasattr(fp, "read") and not hasattr(fp, "write")):
  return False;
 compresscheck = CheckCompressionType(fp, False);
 if(compresscheck=="gzip"):
  try:
   import gzip;
  except ImportError:
   return False;
  catfp = gzip.GzipFile(fileobj=fp, mode="rb");
 if(compresscheck=="bzip2"):
  try:
   import bz2;
  except ImportError:
   return False;
  catfp = BytesIO();
  catfp.write(bz2.decompress(fp.read()));
 if(compresscheck=="zstd"):
  try:
   import zstandard;
  except ImportError:
   return False;
  catfp = BytesIO();
  catfp.write(zstandard.decompress(fp.read()));
 if(compresscheck=="lz4"):
  try:
   import lz4.frame;
  except ImportError:
   return False;
  catfp = BytesIO();
  catfp.write(lz4.frame.decompress(fp.read()));
 if(compresscheck=="lzo" or compresscheck=="lzop"):
  try:
   import lzo;
  except ImportError:
   return False;
  catfp = BytesIO();
  catfp.write(lzo.decompress(fp.read()));
 if(compresscheck=="lzma" or compresscheck=="xz"):
  try:
   import lzma;
  except ImportError:
   return False;
  catfp = BytesIO();
  catfp.write(lzma.decompress(fp.read()));
 if(compresscheck=="catfile" or compresscheck==__file_format_lower__):
  catfp = fp;
 if(not compresscheck):
  try:
   import lzma;
  except ImportError:
   return False;
  catfp = BytesIO();
  with fp as fpcontent:
   try:
    catfp.write(lzma.decompress(fp.read()));
   except lzma.LZMAError:
    return False;
 return catfp;

def UncompressFile(infile, mode="rb"):
 compresscheck = CheckCompressionType(infile, False);
 if(sys.version_info[0]==2 and compresscheck):
  if(mode=="rt"):
   mode = "r";
  if(mode=="wt"):
   mode = "w";
 if(compresscheck=="gzip"):
  try:
   import gzip;
  except ImportError:
   return False;
  try:
   filefp = gzip.open(infile, mode, encoding="UTF-8");
  except (ValueError, TypeError) as e:
   filefp = gzip.open(infile, mode);
 if(compresscheck=="bzip2"):
  try:
   import bz2;
  except ImportError:
   return False;
  try:
   filefp = bz2.open(infile, mode, encoding="UTF-8");
  except (ValueError, TypeError) as e:
   filefp = bz2.open(infile, mode);
 if(compresscheck=="zstd"):
  try:
   import zstandard;
  except ImportError:
   return False;
  try:
   filefp = zstandard.open(infile, mode, encoding="UTF-8");
  except (ValueError, TypeError) as e:
   filefp = zstandard.open(infile, mode);
 if(compresscheck=="lz4"):
  try:
   import lz4.frame;
  except ImportError:
   return False;
  try:
   filefp = lz4.frame.open(infile, mode, encoding="UTF-8");
  except (ValueError, TypeError) as e:
   filefp = lz4.frame.open(infile, mode);
 if(compresscheck=="lzo"):
  try:
   import lzo;
  except ImportError:
   return False;
  try:
   filefp = lzo.open(infile, mode, encoding="UTF-8");
  except (ValueError, TypeError) as e:
   filefp = lzo.open(infile, mode);
 if(compresscheck=="lzma"):
  try:
   import lzma;
  except ImportError:
   return False;
  try:
   filefp = lzma.open(infile, mode, encoding="UTF-8");
  except (ValueError, TypeError) as e:
   filefp = lzma.open(infile, mode);
 if(not compresscheck):
  try:
   filefp = open(infile, mode, encoding="UTF-8");
  except (ValueError, TypeError) as e:
   filefp = open(infile, mode);
 return filefp;

def UncompressString(infile):
 compresscheck = CheckCompressionTypeFromString(infile, False);
 if(compresscheck=="gzip"):
  try:
   import gzip;
  except ImportError:
   return False;
  fileuz = gzip.decompress(infile);
 if(compresscheck=="bzip2"):
  try:
   import bz2;
  except ImportError:
   return False;
  fileuz = bz2.decompress(infile);
 if(compresscheck=="zstd"):
  try:
   import zstandard;
  except ImportError:
   return False;
  fileuz = zstandard.decompress(infile);
 if(compresscheck=="lz4"):
  try:
   import lz4.frame;
  except ImportError:
   return False;
  fileuz = lz4.frame.decompress(infile);
 if(compresscheck=="lzo"):
  try:
   import lzo;
  except ImportError:
   return False;
  fileuz = lzo.decompress(infile);
 if(compresscheck=="lzma"):
  try:
   import lzma;
  except ImportError:
   return False;
  fileuz = lzma.decompress(infile);
 if(not compresscheck):
  fileuz = infile;
 if(hasattr(fileuz, 'decode')):
  fileuz = fileuz.decode("UTF-8");
 return fileuz;

def UncompressStringAlt(infile):
 filefp = StringIO();
 outstring = UncompressString(infile);
 filefp.write(outstring);
 filefp.seek(0);
 return filefp;

def CheckCompressionSubType(infile):
 compresscheck = CheckCompressionType(infile, False);
 if(not compresscheck):
  fextname = os.path.splitext(infile)[1];
  if(fextname==".gz"):
   compresscheck = "gzip";
  if(fextname==".bz2"):
   compresscheck = "bzip2";
  if(fextname==".zst"):
   compresscheck = "zstd";
  if(fextname==".lz4"):
   compresscheck = "lz4";
  if(fextname==".lzo" or fextname==".lzop"):
   compresscheck = "lzo";
  if(fextname==".lzma" or fextname==".xz"):
   compresscheck = "lzma";
 if(not compresscheck):
  return False;
 if(compresscheck=="catfile"):
  return "catfile";
 if(compresscheck==__file_format_lower__):
  return __file_format_name__;
 if(compresscheck=="tarfile"):
  return "tarfile";
 if(compresscheck=="zipfile"):
  return "zipfile";
 if(hasattr(infile, "read") or hasattr(infile, "write")):
  catfp = UncompressCatFile(infile);
 else:
  if(compresscheck=="gzip"):
   try:
    import gzip;
   except ImportError:
    return False;
   catfp = gzip.GzipFile(infile, "rb");
  if(compresscheck=="bzip2"):
   try:
    import bz2;
   except ImportError:
    return False;
   catfp = bz2.BZ2File(infile, "rb");
  if(compresscheck=="lz4"):
   try:
    import lz4.frame;
   except ImportError:
    return False;
   catfp = lz4.frame.open(infile, "rb");
  if(compresscheck=="zstd"):
   try:
    import zstandard;
   except ImportError:
    return False;
   catfp = zstandard.open(infile, "rb");
  if(compresscheck=="lzma" or compresscheck=="xz"):
   try:
    import lzma;
   except ImportError:
    return False;
   catfp = lzma.open(infile, "rb");
 filetype = False;
 prefp = catfp.read(5);
 if(prefp==binascii.unhexlify("7573746172")):
  filetype = "tarfile";
 catfp.seek(0, 0);
 prefp = catfp.read(7);
 if(prefp==binascii.unhexlify("43617446696c65")):
  filetype = "catfile";
 catfp.seek(0, 0);
 prefp = catfp.read(__file_format_len__);
 if(prefp==binascii.unhexlify(__file_format_hex__)):
  filetype = __file_format_lower__;
 catfp.seek(0, 0);
 prefp = catfp.read(10);
 if(prefp==binascii.unhexlify("7061785f676c6f62616c")):
  filetype = "tarfile";
 catfp.seek(0, 0);
 catfp.close();
 return filetype;

def GZipCompress(data, compresslevel=9):
 try:
  import gzip;
 except ImportError:
  return False;
 tmpfp = tempfile.NamedTemporaryFile("wb", delete=False);
 tmpfp.close();
 tmpfp = gzip.GzipFile(tmpfp.name, mode="wb", compresslevel=compresslevel);
 tmpfp.write(data);
 tmpfp.close();
 catfp = open(tmpfp.name, "rb");
 catdata = catfp.read();
 catfp.close();
 return catdata;

def CompressCatFile(fp, compression="auto", compressionlevel=None):
 compressionlist = ['auto', 'gzip', 'bzip2', 'zstd', 'lz4', 'lzo', 'lzop', 'lzma', 'xz'];
 if(not hasattr(fp, "read") and not hasattr(fp, "write")):
  return False;
 fp.seek(0, 0);
 if(not compression or compression or compression=="catfile" or compression==__file_format_lower__):
  compression = None;
 if(compression not in compressionlist and compression is None):
  compression = "auto";
 if(compression=="gzip"):
  try:
   import gzip;
  except ImportError:
   return False;
  catfp = BytesIO();
  if(compressionlevel is None):
   compressionlevel = 9;
  else:
   compressionlevel = int(compressionlevel);
  catfp.write(gzip.compress(fp.read(), compresslevel=compressionlevel));
 if(compression=="bzip2"):
  try:
   import bz2;
  except ImportError:
   return False;
  catfp = BytesIO();
  if(compressionlevel is None):
   compressionlevel = 9;
  else:
   compressionlevel = int(compressionlevel);
  catfp.write(bz2.compress(fp.read(), compresslevel=compressionlevel));
 if(compression=="lz4"):
  try:
   import lz4.frame;
  except ImportError:
   return False;
  catfp = BytesIO();
  if(compressionlevel is None):
   compressionlevel = 9;
  else:
   compressionlevel = int(compressionlevel);
  catfp.write(lz4.frame.compress(fp.read(), compression_level=compressionlevel));
 if(compression=="lzo" or compression=="lzop"):
  try:
   import lzo;
  except ImportError:
   return False;
  catfp = BytesIO();
  if(compressionlevel is None):
   compressionlevel = 9;
  else:
   compressionlevel = int(compressionlevel);
  catfp.write(lzo.compress(fp.read(), compresslevel=compressionlevel));
 if(compression=="zstd"):
  try:
   import zstandard;
  except ImportError:
   return False;
  catfp = BytesIO();
  if(compressionlevel is None):
   compressionlevel = 10;
  else:
   compressionlevel = int(compressionlevel);
  catfp.write(zstandard.compress(fp.read(), level=compressionlevel));
 if(compression=="lzma"):
  try:
   import lzma;
  except ImportError:
   return False;
  catfp = BytesIO();
  if(compressionlevel is None):
   compressionlevel = 9;
  else:
   compressionlevel = int(compressionlevel);
  catfp.write(lzma.compress(fp.read(), format=lzma.FORMAT_ALONE, preset=compressionlevel));
 if(compression=="xz"):
  try:
   import lzma;
  except ImportError:
   return False;
  catfp = BytesIO();
  if(compressionlevel is None):
   compressionlevel = 9;
  else:
   compressionlevel = int(compressionlevel);
  catfp.write(lzma.compress(fp.read(), format=lzma.FORMAT_XZ, preset=compressionlevel));
 if(compression=="auto" or compression is None):
  catfp = fp;
 catfp.seek(0, 0);
 return catfp;

def CompressOpenFile(outfile):
 if(outfile is None):
  return False;
 fbasename = os.path.splitext(outfile)[0];
 fextname = os.path.splitext(outfile)[1];
 if(sys.version_info[0]==2):
  mode = "w";
 else:
  mode = "wb";
 if(fextname not in outextlistwd):
  try:
   outfp = open(outfile, "wb", encoding="UTF-8");
  except (ValueError, TypeError) as e:
   outfp = open(outfile, "wb");
 elif(fextname==".gz"):
  try:
   import gzip;
  except ImportError:
   return False;
  outfp = gzip.open(outfile, mode, 9, encoding="UTF-8");
 elif(fextname==".bz2"):
  try:
   import bz2;
  except ImportError:
   return False;
  outfp = bz2.open(outfile, mode, 9, encoding="UTF-8");
 elif(fextname==".zst"):
  try:
   import zstandard;
  except ImportError:
   return False;
  outfp = zstandard.open(outfile, mode, zstandard.ZstdCompressor(level=10), encoding="UTF-8");
 elif(fextname==".xz"):
  try:
   import lzma;
  except ImportError:
   return False;
  outfp = lzma.open(outfile, mode, format=lzma.FORMAT_XZ, preset=9, encoding="UTF-8");
 elif(fextname==".lz4"):
  try:
   import lz4.frame;
  except ImportError:
   return False;
  outfp = lz4.frame.open(outfile, mode, format=lzma.FORMAT_XZ, preset=9, encoding="UTF-8");
 elif(fextname==".lzo"):
  try:
   import lzo;
  except ImportError:
   return False;
  outfp = lzo.open(outfile, mode, format=lzma.FORMAT_XZ, preset=9, encoding="UTF-8");
 elif(fextname==".lzma"):
  try:
   import lzma;
  except ImportError:
   return False;
  outfp = lzma.open(outfile, mode, format=lzma.FORMAT_ALONE, preset=9, encoding="UTF-8");
 return outfp;

def GetDevMajorMinor(fdev):
 retdev = [];
 if(hasattr(os, "minor")):
  retdev.append(os.minor(fdev));
 else:
  retdev.append(0);
 if(hasattr(os, "major")):
  retdev.append(os.major(fdev));
 else:
  retdev.append(0);
 return retdev;

def CheckSumSupport(checkfor, guaranteed=True):
 if(guaranteed):
  hash_list = sorted(list(hashlib.algorithms_guaranteed));
 else:
  hash_list = sorted(list(hashlib.algorithms_available));
 checklistout = sorted(hash_list + ['adler32', 'crc16', 'crc16_ansi', 'crc16_ibm', 'crc16_ccitt', 'crc32', 'crc64', 'crc64_ecma', 'crc64_iso', 'none']);
 if(checkfor in checklistout):
  return True;
 else:
  return False;

def CheckSumSupportAlt(checkfor, guaranteed=True):
 if(guaranteed):
  hash_list = sorted(list(hashlib.algorithms_guaranteed));
 else:
  hash_list = sorted(list(hashlib.algorithms_available));
 checklistout = hash_list;
 if(checkfor in checklistout):
  return True;
 else:
  return False;

def PackCatFile(infiles, outfile, dirlistfromtxt=False, compression="auto", compressionlevel=None, followlink=False, checksumtype="crc32", extradata=[], verbose=False, returnfp=False):
 compressionlist = ['auto', 'gzip', 'bzip2', 'zstd', 'lz4', 'lzo', 'lzop', 'lzma', 'xz'];
 outextlist = ['gz', 'cgz', 'bz2', 'cbz', 'zst', 'czst', 'lz4', 'clz4', 'lzo', 'lzop', 'clzo', 'lzma', 'xz', 'cxz'];
 outextlistwd = ['.gz', '.cgz', '.bz2', '.cbz', '.zst', '.czst', '.lz4', '.clz4', '.lzo', '.lzop', '.clzo', '.lzma', '.xz', '.cxz'];
 advancedlist = True;
 if(outfile!="-" and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
  outfile = RemoveWindowsPath(outfile);
 checksumtype = checksumtype.lower();
 if(not CheckSumSupport(checksumtype, hashlib_guaranteed)):
  checksumtype="crc32";
 if(checksumtype=="none"):
  checksumtype = "";
 if(not compression or compression or compression=="catfile" or compression==__file_format_lower__):
  compression = None;
 if(compression not in compressionlist and compression is None):
  compression = "auto";
 if(verbose):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(outfile!="-" and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
  if(os.path.exists(outfile)):
   os.unlink(outfile);
 if(outfile=="-"):
  verbose = False;
  catfp = BytesIO();
 elif(hasattr(outfile, "read") or hasattr(outfile, "write")):
  catfp = outfile;
 else:
  fbasename = os.path.splitext(outfile)[0];
  fextname = os.path.splitext(outfile)[1];
  if(fextname not in outextlistwd and (compression=="auto" or compression is None)):
   catfp = open(outfile, "wb");
  elif(((fextname==".gz" or fextname==".cgz") and compression=="auto") or compression=="gzip"):
   try:
    import gzip;
   except ImportError:
    return False;
   if(compressionlevel is None):
    compressionlevel = 9;
   else:
    compressionlevel = int(compressionlevel);
   catfp = gzip.GzipFile(outfile, "wb", compresslevel=compressionlevel);
  elif(((fextname==".bz2" or fextname==".cbz") and compression=="auto") or compression=="bzip2"):
   try:
    import bz2;
   except ImportError:
    return False;
   if(compressionlevel is None):
    compressionlevel = 9;
   else:
    compressionlevel = int(compressionlevel);
   catfp = bz2.BZ2File(outfile, "wb", compresslevel=compressionlevel);
  elif(((fextname==".zst" or fextname==".czst") and compression=="auto") or compression=="zstd"):
   try:
    import zstandard;
   except ImportError:
    return False;
   if(compressionlevel is None):
    compressionlevel = 10;
   else:
    compressionlevel = int(compressionlevel);
   catfp = zstandard.open(outfile, "wb", zstandard.ZstdCompressor(level=compressionlevel));
  elif(((fextname==".lz4" or fextname==".clz4") and compression=="auto") or compression=="lz4"):
   try:
    import lz4.frame;
   except ImportError:
    return False;
   if(compressionlevel is None):
    compressionlevel = 9;
   else:
    compressionlevel = int(compressionlevel);
   catfp = lz4.frame.open(outfile, "wb", compression_level=compressionlevel);
  elif(((fextname==".xz" or fextname==".cxz") and compression=="auto") or compression=="xz"):
   try:
    import lzma;
   except ImportError:
    return False;
   if(compressionlevel is None):
    compressionlevel = 9;
   else:
    compressionlevel = int(compressionlevel);
   catfp = lzma.open(outfile, "wb", format=lzma.FORMAT_XZ, preset=compressionlevel);
  elif((fextname==".lzma" and compression=="auto") or compression=="lzma"):
   try:
    import lzma;
   except ImportError:
    return False;
   if(compressionlevel is None):
    compressionlevel = 9;
   else:
    compressionlevel = int(compressionlevel);
   catfp = lzma.open(outfile, "wb", format=lzma.FORMAT_ALONE, preset=compressionlevel);
 catver = __cat_header_ver__;
 fileheaderver = str(int(catver.replace(".", "")));
 fileheader = AppendNullByte(__file_format_name__ + fileheaderver);
 catfp.write(fileheader.encode('UTF-8'));
 infilelist = [];
 if(infiles=="-"):
  for line in sys.stdin:
   infilelist.append(line.strip());
  infilelist = list(filter(None, infilelist));
 elif(infiles!="-" and dirlistfromtxt and os.path.exists(infiles) and (os.path.isfile(infiles) or infiles=="/dev/null" or infiles=="NUL")):
  if(not os.path.exists(infiles) or not os.path.isfile(infiles)):
   return False;
  with open(infiles, "r") as finfile:
   for line in finfile:
    infilelist.append(line.strip());
  infilelist = list(filter(None, infilelist));
 else:
  if(isinstance(infiles, (list, tuple, ))):
   infilelist = list(filter(None, infiles));
  elif(isinstance(infiles, (str, ))):
   infilelist = list(filter(None, [infiles]));
 if(advancedlist):
  GetDirList = ListDirAdvanced(infilelist, followlink, False);
 else:
  GetDirList = ListDir(infilelist, followlink, False);
 if(not GetDirList):
  return False;
 curinode = 0;
 curfid = 0;
 inodelist = [];
 inodetofile = {};
 filetoinode = {};
 inodetocatinode = {};
 fnumfiles = format(int(len(GetDirList)), 'x').lower();
 fnumfilesa = AppendNullBytes([fnumfiles, checksumtype]);
 if(checksumtype=="none" or checksumtype==""):
  catfileheadercshex = format(0, 'x').lower();
 elif(checksumtype=="crc16" or checksumtype=="crc16_ansi" or checksumtype=="crc16_ibm"):
  catfileheadercshex = format(crc16(str(fileheader + fnumfilesa).encode('UTF-8')) & 0xffff, '04x').lower();
 elif(checksumtype=="crc16_ccitt"):
  catfileheadercshex = format(crc16_ccitt(str(fileheader + fnumfilesa).encode('UTF-8')) & 0xffff, '04x').lower();
 elif(checksumtype=="adler32"):
  catfileheadercshex = format(zlib.adler32(str(fileheader + fnumfilesa).encode('UTF-8')) & 0xffffffff, '08x').lower();
 elif(checksumtype=="crc32"):
  catfileheadercshex = format(crc32(str(fileheader + fnumfilesa).encode('UTF-8')) & 0xffffffff, '08x').lower();
 elif(checksumtype=="crc64_ecma"):
  catfileheadercshex = format(crc64_ecma(str(fileheader + fnumfilesa).encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
 elif(checksumtype=="crc64" or checksumtype=="crc64_iso"):
  catfileheadercshex = format(crc64_iso(str(fileheader + fnumfilesa).encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
 elif(CheckSumSupportAlt(checksumtype, hashlib_guaranteed)):
  checksumoutstr = hashlib.new(checksumtype);
  checksumoutstr.update(str(fileheader + fnumfilesa).encode('UTF-8'));
  catfileheadercshex = checksumoutstr.hexdigest().lower();
 fnumfilesa = fnumfilesa + AppendNullByte(catfileheadercshex);
 catfp.write(fnumfilesa.encode('UTF-8'));
 for curfname in GetDirList:
  catfhstart = catfp.tell();
  if(re.findall("^[.|/]", curfname)):
   fname = curfname;
  else:
   fname = "./"+curfname;
  if(verbose):
   VerbosePrintOut(fname);
  if(not followlink or followlink is None):
   fstatinfo = os.lstat(fname);
  else:
   fstatinfo = os.stat(fname);
  fpremode = fstatinfo.st_mode;
  finode = fstatinfo.st_ino;
  flinkcount = fstatinfo.st_nlink;
  ftype = 0;
  if(stat.S_ISREG(fpremode)):
   ftype = 0;
  if(stat.S_ISLNK(fpremode)):
   ftype = 2;
  if(stat.S_ISCHR(fpremode)):
   ftype = 3;
  if(stat.S_ISBLK(fpremode)):
   ftype = 4;
  if(stat.S_ISDIR(fpremode)):
   ftype = 5;
  if(stat.S_ISFIFO(fpremode)):
   ftype = 6;
  if(hasattr(stat, "S_ISDOOR") and stat.S_ISDOOR(fpremode)):
   ftype = 8;
  if(hasattr(stat, "S_ISPORT") and stat.S_ISPORT(fpremode)):
   ftype = 9;
  if(hasattr(stat, "S_ISWHT") and stat.S_ISWHT(fpremode)):
   ftype = 10;
  flinkname = "";
  fcurfid = format(int(curfid), 'x').lower();
  if(not followlink and finode!=0):
   if(ftype!=1):
    if(finode in inodelist):
     ftype = 1;
     flinkname = inodetofile[finode];
     fcurinode = format(int(inodetocatinode[finode]), 'x').lower();
    if(finode not in inodelist):
     inodelist.append(finode);
     inodetofile.update({finode: fname});
     inodetocatinode.update({finode: curinode});
     fcurinode = format(int(curinode), 'x').lower();
     curinode = curinode + 1;
  else:
   fcurinode = format(int(curinode), 'x').lower();
   curinode = curinode + 1;
  curfid = curfid + 1;
  if(ftype==2):
   flinkname = os.readlink(fname);
  fdev = fstatinfo.st_dev;
  getfdev = GetDevMajorMinor(fdev);
  fdev_minor = getfdev[0];
  fdev_major = getfdev[1];
  frdev = fstatinfo.st_dev;
  if(hasattr(fstatinfo, "st_rdev")):
   frdev = fstatinfo.st_rdev;
  else:
   frdev = fstatinfo.st_dev;
  getfrdev = GetDevMajorMinor(frdev);
  frdev_minor = getfrdev[0];
  frdev_major = getfrdev[1];
  if(ftype==1 or ftype==2 or ftype==3 or ftype==4 or ftype==5 or ftype==6):
   fsize = format(int("0"), 'x').lower();
  if(ftype==0 or ftype==7):
   fsize = format(int(fstatinfo.st_size), 'x').lower();
  fatime = format(int(fstatinfo.st_atime), 'x').lower();
  fmtime = format(int(fstatinfo.st_mtime), 'x').lower();
  fctime = format(int(fstatinfo.st_ctime), 'x').lower();
  if(hasattr(fstatinfo, "st_birthtime")):
   fbtime = format(int(fstatinfo.st_birthtime), 'x').lower();
  else:
   fbtime = format(int(fstatinfo.st_ctime), 'x').lower();
  fmode = format(int(fstatinfo.st_mode), 'x').lower();
  fchmode = format(int(stat.S_IMODE(fstatinfo.st_mode)), 'x').lower();
  ftypemod = format(int(stat.S_IFMT(fstatinfo.st_mode)), 'x').lower();
  fuid = format(int(fstatinfo.st_uid), 'x').lower();
  fgid = format(int(fstatinfo.st_gid), 'x').lower();
  funame = "";
  try:
   import pwd;
   try:
    userinfo = pwd.getpwuid(fstatinfo.st_uid);
    funame = userinfo.pw_name;
   except KeyError:
    funame = "";
  except ImportError:
   funame = "";
  fgname = "";
  try:
   import grp;
   try:
    groupinfo = grp.getgrgid(fstatinfo.st_gid);
    fgname = groupinfo.gr_name;
   except KeyError:
    fgname = "";
  except ImportError:
   fgname = "";
  fdev_minor = format(int(fdev_minor), 'x').lower();
  fdev_major = format(int(fdev_major), 'x').lower();
  frdev_minor = format(int(frdev_minor), 'x').lower();
  frdev_major = format(int(frdev_major), 'x').lower();
  finode = format(int(finode), 'x').lower();
  flinkcount = format(int(flinkcount), 'x').lower();
  if(hasattr(fstatinfo, "st_file_attributes")):
   fwinattributes = format(int(fstatinfo.st_file_attributes), 'x').lower();
  else:
   fwinattributes = format(int(0), 'x').lower();
  fcontents = "".encode('UTF-8');
  if(ftype==0 or ftype==7):
   fpc = open(fname, "rb");
   fcontents = fpc.read(int(fstatinfo.st_size));
   fpc.close();
  if(followlink and (ftype==1 or ftype==2)):
   flstatinfo = os.stat(flinkname);
   fpc = open(flinkname, "rb");
   fcontents = fpc.read(int(flstatinfo.st_size));
   fpc.close();
  ftypehex = format(ftype, 'x').lower();
  extrafields = format(len(extradata), 'x').lower();
  extrasizestr = AppendNullByte(extrafields);
  if(len(extradata)>0):
   extrasizestr = extrasizestr + AppendNullBytes(extradata);
  extrasizelen = format(len(extrasizestr), 'x').lower();
  catfileoutstr = AppendNullBytes([ftypehex, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev_minor, fdev_major, frdev_minor, frdev_major, extrasizelen, extrafields]);
  if(len(extradata)>0):
   catfileoutstr = catfileoutstr + AppendNullBytes(extradata);
  catfileoutstr = catfileoutstr + AppendNullByte(checksumtype);
  if(checksumtype=="none" or checksumtype==""):
   catfileheadercshex = format(0, 'x').lower();
   catfilecontentcshex = format(0, 'x').lower();
  elif(checksumtype=="crc16" or checksumtype=="crc16_ansi" or checksumtype=="crc16_ibm"):
   catfileheadercshex = format(crc16("".encode('UTF-8')) & 0xffff, '04x').lower();
   catfilecontentcshex = format(crc16(fcontents) & 0xffff, '04x').lower();
  elif(checksumtype=="crc16_ccitt"):
   catfileheadercshex = format(crc16_ccitt("".encode('UTF-8')) & 0xffff, '04x').lower();
   catfilecontentcshex = format(crc16_ccitt(fcontents) & 0xffff, '04x').lower();
  elif(checksumtype=="adler32"):
   catfileheadercshex = format(zlib.adler32("".encode('UTF-8')) & 0xffffffff, '08x').lower();
   catfilecontentcshex = format(zlib.adler32(fcontents) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc32"):
   catfileheadercshex = format(crc32("".encode('UTF-8')) & 0xffffffff, '08x').lower();
   catfilecontentcshex = format(crc32(fcontents) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc64_ecma"):
   catfileheadercshex = format(crc64_ecma("".encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
   catfilecontentcshex = format(crc64_ecma(fcontents) & 0xffffffffffffffff, '016x').lower();
  elif(checksumtype=="crc64" or checksumtype=="crc64_iso"):
   catfileheadercshex = format(crc64_iso("".encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
   catfilecontentcshex = format(crc64_iso(fcontents) & 0xffffffffffffffff, '016x').lower();
  elif(CheckSumSupportAlt(checksumtype, hashlib_guaranteed)):
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update("".encode('UTF-8'));
   catfileheadercshex = checksumoutstr.hexdigest().lower();
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(fcontents);
   catfilecontentcshex = checksumoutstr.hexdigest().lower();
  tmpfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex]);
  catheaersize = format(int(len(tmpfileoutstr) - 1), 'x').lower()
  catfileoutstr = AppendNullByte(catheaersize) + catfileoutstr;
  if(checksumtype=="none" or checksumtype==""):
   catfileheadercshex = format(0, 'x').lower();
  elif(checksumtype=="crc16" or checksumtype=="crc16_ansi" or checksumtype=="crc16_ibm"):
   catfileheadercshex = format(crc16(catfileoutstr.encode('UTF-8')) & 0xffff, '04x').lower();
  elif(checksumtype=="crc16_ccitt"):
   catfileheadercshex = format(crc16_ccitt(catfileoutstr.encode('UTF-8')) & 0xffff, '04x').lower();
  elif(checksumtype=="adler32"):
   catfileheadercshex = format(zlib.adler32(catfileoutstr.encode('UTF-8')) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc32"):
   catfileheadercshex = format(crc32(catfileoutstr.encode('UTF-8')) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc64_ecma"):
   catfileheadercshex = format(crc64_ecma(catfileoutstr.encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
  elif(checksumtype=="crc64" or checksumtype=="crc64_iso"):
   catfileheadercshex = format(crc64_iso(catfileoutstr.encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
  elif(CheckSumSupportAlt(checksumtype, hashlib_guaranteed)):
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(catfileoutstr.encode('UTF-8'));
   catfileheadercshex = checksumoutstr.hexdigest().lower();
  catfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex]);
  catfhend = (catfp.tell() - 1) + len(catfileoutstr);
  catfcontentstart = catfp.tell() + len(catfileoutstr);
  catfileoutstrecd = catfileoutstr.encode('UTF-8');
  nullstrecd = __file_format_delimiter__.encode('UTF-8');
  catfileout = catfileoutstrecd + fcontents + nullstrecd;
  catfcontentend = (catfp.tell() - 1) + len(catfileout);
  catfp.write(catfileout);
 if(outfile=="-" or hasattr(outfile, "read") or hasattr(outfile, "write")):
  catfp = CompressCatFile(catfp, compression);
 if(outfile=="-"):
  catfp.seek(0, 0);
  if(hasattr(sys.stdout, "buffer")):
   shutil.copyfileobj(catfp, sys.stdout.buffer);
  else:
   shutil.copyfileobj(catfp, sys.stdout);
 if(returnfp):
  catfp.seek(0, 0);
  return catfp;
 else:
  catfp.close();
  return True;

if(hasattr(shutil, "register_archive_format")):
 def PackCatFileFunc(archive_name, source_dir, **kwargs):
  return PackCatFile(source_dir, archive_name, False, "auto", None, False, "crc32", [], False, False);

def PackCatFileFromDirList(infiles, outfile, dirlistfromtxt=False, compression="auto", compressionlevel=None, followlink=False, checksumtype="crc32", extradata=[], verbose=False, returnfp=False):
 return PackCatFile(infiles, outfile, dirlistfromtxt, compression, compressionlevel, followlink, checksumtype, extradata, verbose, returnfp);

def PackCatFileFromTarFile(infile, outfile, compression="auto", compressionlevel=None, checksumtype="crc32", extradata=[], verbose=False, returnfp=False):
 compressionlist = ['auto', 'gzip', 'bzip2', 'zstd', 'lz4', 'lzo', 'lzop', 'lzma', 'xz'];
 outextlist = ['gz', 'cgz', 'bz2', 'cbz', 'zst', 'czst', 'lz4', 'clz4', 'lzo', 'lzop', 'clzo', 'lzma', 'xz', 'cxz'];
 outextlistwd = ['.gz', '.cgz', '.bz2', '.cbz', '.zst', '.czst', '.lz4', '.clz4', '.lzo', '.lzop', '.clzo', '.lzma', '.xz', '.cxz'];
 if(outfile!="-" and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
  outfile = RemoveWindowsPath(outfile);
 checksumtype = checksumtype.lower();
 if(not CheckSumSupport(checksumtype, hashlib_guaranteed)):
  checksumtype="crc32";
 if(checksumtype=="none"):
  checksumtype = "";
 if(not compression or compression or compression=="catfile" or compression==__file_format_lower__):
  compression = None;
 if(compression not in compressionlist and compression is None):
  compression = "auto";
 if(verbose):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(outfile!="-" and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
  if(os.path.exists(outfile)):
   os.unlink(outfile);
 if(outfile=="-"):
  verbose = False;
  catfp = BytesIO();
 elif(hasattr(outfile, "read") or hasattr(outfile, "write")):
  catfp = outfile;
 else:
  fbasename = os.path.splitext(outfile)[0];
  fextname = os.path.splitext(outfile)[1];
  if(fextname not in outextlistwd and (compression=="auto" or compression is None)):
   catfp = open(outfile, "wb");
  elif(((fextname==".gz" or fextname==".cgz") and compression=="auto") or compression=="gzip"):
   try:
    import gzip;
   except ImportError:
    return False;
   if(compressionlevel is None):
    compressionlevel = 9;
   else:
    compressionlevel = int(compressionlevel);
   catfp = gzip.GzipFile(outfile, "wb", compresslevel=compressionlevel);
  elif(((fextname==".bz2" or fextname==".cbz") and compression=="auto") or compression=="bzip2"):
   try:
    import bz2;
   except ImportError:
    return False;
   if(compressionlevel is None):
    compressionlevel = 9;
   else:
    compressionlevel = int(compressionlevel);
   catfp = bz2.BZ2File(outfile, "wb", compresslevel=compressionlevel);
  elif(((fextname==".zst" or fextname==".czst") and compression=="auto") or compression=="zstd"):
   try:
    import zstandard;
   except ImportError:
    return False;
   if(compressionlevel is None):
    compressionlevel = 10;
   else:
    compressionlevel = int(compressionlevel);
   catfp = zstandard.open(outfile, "wb", zstandard.ZstdCompressor(level=compressionlevel));
  elif(((fextname==".lz4" or fextname==".clz4") and compression=="auto") or compression=="lz4"):
   try:
    import lz4.frame;
   except ImportError:
    return False;
   if(compressionlevel is None):
    compressionlevel = 9;
   else:
    compressionlevel = int(compressionlevel);
   catfp = lz4.frame.open(outfile, "wb", compression_level=compressionlevel);
  elif(((fextname==".xz" or fextname==".cxz") and compression=="auto") or compression=="xz"):
   try:
    import lzma;
   except ImportError:
    return False;
   if(compressionlevel is None):
    compressionlevel = 9;
   else:
    compressionlevel = int(compressionlevel);
   catfp = lzma.open(outfile, "wb", format=lzma.FORMAT_XZ, preset=compressionlevel);
  elif((fextname==".lzma" and compression=="auto") or compression=="lzma"):
   try:
    import lzma;
   except ImportError:
    return False;
   if(compressionlevel is None):
    compressionlevel = 9;
   else:
    compressionlevel = int(compressionlevel);
   catfp = lzma.open(outfile, "wb", format=lzma.FORMAT_ALONE, preset=compressionlevel);
 catver = __cat_header_ver__;
 fileheaderver = str(int(catver.replace(".", "")));
 fileheader = AppendNullByte(__file_format_name__ + fileheaderver);
 catfp.write(fileheader.encode('UTF-8'));
 curinode = 0;
 curfid = 0;
 inodelist = [];
 inodetofile = {};
 filetoinode = {};
 inodetocatinode = {};
 if(not os.path.exists(infile) or not os.path.isfile(infile)):
  return False;
 try:
  if(not tarfile.is_tarfile(infile)):
   return False;
 except AttributeError:
  if(not is_tarfile(infile)):
   return False;
 tarfp = tarfile.open(infile, "r");
 fnumfiles = format(int(len(tarfp.getmembers())), 'x').lower();
 fnumfilesa = AppendNullBytes([fnumfiles, checksumtype]);
 if(checksumtype=="none" or checksumtype==""):
  catfileheadercshex = format(0, 'x').lower();
 elif(checksumtype=="crc16" or checksumtype=="crc16_ansi" or checksumtype=="crc16_ibm"):
  catfileheadercshex = format(crc16(str(fileheader + fnumfilesa).encode('UTF-8')) & 0xffff, '04x').lower();
 elif(checksumtype=="crc16_ccitt"):
  catfileheadercshex = format(crc16_ccitt(str(fileheader + fnumfilesa).encode('UTF-8')) & 0xffff, '04x').lower();
 elif(checksumtype=="adler32"):
  catfileheadercshex = format(zlib.adler32(str(fileheader + fnumfilesa).encode('UTF-8')) & 0xffffffff, '08x').lower();
 elif(checksumtype=="crc32"):
  catfileheadercshex = format(crc32(str(fileheader + fnumfilesa).encode('UTF-8')) & 0xffffffff, '08x').lower();
 elif(checksumtype=="crc64_ecma"):
  catfileheadercshex = format(crc64_ecma(str(fileheader + fnumfilesa).encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
 elif(checksumtype=="crc64" or checksumtype=="crc64_iso"):
  catfileheadercshex = format(crc64_iso(str(fileheader + fnumfilesa).encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
 elif(CheckSumSupportAlt(checksumtype, hashlib_guaranteed)):
  checksumoutstr = hashlib.new(checksumtype);
  checksumoutstr.update(str(fileheader + fnumfilesa).encode('UTF-8'));
  catfileheadercshex = checksumoutstr.hexdigest().lower();
 fnumfilesa = fnumfilesa + AppendNullByte(catfileheadercshex);
 catfp.write(fnumfilesa.encode('UTF-8'));
 for member in tarfp.getmembers():
  catfhstart = catfp.tell();
  if(re.findall("^[.|/]", member.name)):
   fname = member.name;
  else:
   fname = "./"+member.name;
  if(verbose):
   VerbosePrintOut(fname);
  fpremode = member.mode;
  ffullmode = member.mode;
  flinkcount = 0;
  ftype = 0;
  if(member.isreg()):
   ffullmode = member.mode + stat.S_IFREG;
   ftype = 0;
  if(member.isdev()):
   ffullmode = member.mode;
   ftype = 7;
  if(member.islnk()):
   ffullmode = member.mode + stat.S_IFREG;
   ftype = 1;
  if(member.issym()):
   ffullmode = member.mode + stat.S_IFLNK;
   ftype = 2;
  if(member.ischr()):
   ffullmode = member.mode + stat.S_IFCHR;
   ftype = 3;
  if(member.isblk()):
   ffullmode = member.mode + stat.S_IFBLK;
   ftype = 4;
  if(member.isdir()):
   ffullmode = member.mode + stat.S_IFDIR;
   ftype = 5;
  if(member.isfifo()):
   ffullmode = member.mode + stat.S_IFIFO;
   ftype = 6;
  if(member.issparse()):
   ffullmode = member.mode;
   ftype = 8;
  flinkname = "";
  fcurfid = format(int(curfid), 'x').lower();
  fcurinode = format(int(0), 'x').lower();
  curfid = curfid + 1;
  if(ftype==2):
   flinkname = member.linkname;
  fdev_minor = format(int(member.devminor), 'x').lower();
  fdev_major = format(int(member.devmajor), 'x').lower();
  frdev_minor = format(int(member.devminor), 'x').lower();
  frdev_major = format(int(member.devmajor), 'x').lower();
  if(ftype==1 or ftype==2 or ftype==3 or ftype==4 or ftype==5 or ftype==6):
   fsize = format(int("0"), 'x').lower();
  if(ftype==0 or ftype==7):
   fsize = format(int(member.size), 'x').lower();
  fatime = format(int(member.mtime), 'x').lower();
  fmtime = format(int(member.mtime), 'x').lower();
  fctime = format(int(member.mtime), 'x').lower();
  fbtime = format(int(member.mtime), 'x').lower();
  fmode = format(int(ffullmode), 'x').lower();
  fchmode = format(int(stat.S_IMODE(ffullmode)), 'x').lower();
  ftypemod = format(int(stat.S_IFMT(ffullmode)), 'x').lower();
  fuid = format(int(member.uid), 'x').lower();
  fgid = format(int(member.gid), 'x').lower();
  funame = member.uname;
  fgname = member.gname;
  flinkcount = format(int(flinkcount), 'x').lower();
  fcontents = "".encode('UTF-8');
  if(ftype==0 or ftype==7):
   fpc = tarfp.extractfile(member);
   fcontents = fpc.read(int(member.size));
   fpc.close();
  ftypehex = format(ftype, 'x').lower();
  extrafields = format(len(extradata), 'x').lower();
  extrasizestr = AppendNullByte(extrafields);
  if(len(extradata)>0):
   extrasizestr = extrasizestr + AppendNullBytes(extradata);
  extrasizelen = format(len(extrasizestr), 'x').lower();
  catfileoutstr = AppendNullBytes([ftypehex, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev_minor, fdev_major, frdev_minor, frdev_major, extrasizelen, extrafields]);
  if(len(extradata)>0):
   catfileoutstr = catfileoutstr + AppendNullBytes(extradata);
  catfileoutstr = catfileoutstr + AppendNullByte(checksumtype);
  catfhend = (catfp.tell() - 1) + len(catfileoutstr);
  catfcontentstart = catfp.tell() + len(catfileoutstr);
  if(checksumtype=="none" or checksumtype==""):
   catfileheadercshex = format(0, 'x').lower();
   catfilecontentcshex = format(0, 'x').lower();
  elif(checksumtype=="crc16" or checksumtype=="crc16_ansi" or checksumtype=="crc16_ibm"):
   catfileheadercshex = format(crc16("".encode('UTF-8')) & 0xffff, '04x').lower();
   catfilecontentcshex = format(crc16(fcontents) & 0xffff, '04x').lower();
  elif(checksumtype=="crc16_ccitt"):
   catfileheadercshex = format(crc16_ccitt("".encode('UTF-8')) & 0xffff, '04x').lower();
   catfilecontentcshex = format(crc16_ccitt(fcontents) & 0xffff, '04x').lower();
  elif(checksumtype=="adler32"):
   catfileheadercshex = format(zlib.adler32("".encode('UTF-8')) & 0xffffffff, '08x').lower();
   catfilecontentcshex = format(zlib.adler32(fcontents) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc32"):
   catfileheadercshex = format(crc32("".encode('UTF-8')) & 0xffffffff, '08x').lower();
   catfilecontentcshex = format(crc32(fcontents) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc64_ecma"):
   catfileheadercshex = format(crc64_ecma("".encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
   catfilecontentcshex = format(crc64_ecma(fcontents) & 0xffffffffffffffff, '016x').lower();
  elif(checksumtype=="crc64" or checksumtype=="crc64_iso"):
   catfileheadercshex = format(crc64_iso("".encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
   catfilecontentcshex = format(crc64_iso(fcontents) & 0xffffffffffffffff, '016x').lower();
  elif(CheckSumSupportAlt(checksumtype, hashlib_guaranteed)):
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update("".encode('UTF-8'));
   catfileheadercshex = checksumoutstr.hexdigest().lower();
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(fcontents);
   catfilecontentcshex = checksumoutstr.hexdigest().lower();
  tmpfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex]);
  catheaersize = format(int(len(tmpfileoutstr) - 1), 'x').lower()
  catfileoutstr = AppendNullByte(catheaersize) + catfileoutstr;
  if(checksumtype=="none" or checksumtype==""):
   catfileheadercshex = format(0, 'x').lower();
  elif(checksumtype=="crc16" or checksumtype=="crc16_ansi" or checksumtype=="crc16_ibm"):
   catfileheadercshex = format(crc16(catfileoutstr.encode('UTF-8')) & 0xffff, '04x').lower();
  elif(checksumtype=="crc16_ccitt"):
   catfileheadercshex = format(crc16_ccitt(catfileoutstr.encode('UTF-8')) & 0xffff, '04x').lower();
  elif(checksumtype=="adler32"):
   catfileheadercshex = format(zlib.adler32(catfileoutstr.encode('UTF-8')) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc32"):
   catfileheadercshex = format(crc32(catfileoutstr.encode('UTF-8')) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc64_ecma"):
   catfileheadercshex = format(crc64_ecma(catfileoutstr.encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
  elif(checksumtype=="crc64" or checksumtype=="crc64_iso"):
   catfileheadercshex = format(crc64_iso(catfileoutstr.encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
  elif(CheckSumSupportAlt(checksumtype, hashlib_guaranteed)):
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(catfileoutstr.encode('UTF-8'));
   catfileheadercshex = checksumoutstr.hexdigest().lower();
  catfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex]);
  catfileoutstrecd = catfileoutstr.encode('UTF-8');
  nullstrecd = __file_format_delimiter__.encode('UTF-8');
  catfileout = catfileoutstrecd + fcontents + nullstrecd;
  catfcontentend = (catfp.tell() - 1) + len(catfileout);
  catfp.write(catfileout);
 if(outfile=="-" or hasattr(outfile, "read") or hasattr(outfile, "write")):
  catfp = CompressCatFile(catfp, compression);
 if(outfile=="-"):
  catfp.seek(0, 0);
  if(hasattr(sys.stdout, "buffer")):
   shutil.copyfileobj(catfp, sys.stdout.buffer);
  else:
   shutil.copyfileobj(catfp, sys.stdout);
 if(returnfp):
  catfp.seek(0, 0);
  return catfp;
 else:
  catfp.close();
  return True;

def PackCatFileFromZipFile(infile, outfile, compression="auto", compressionlevel=None, checksumtype="crc32", extradata=[], verbose=False, returnfp=False):
 compressionlist = ['auto', 'gzip', 'bzip2', 'zstd', 'lz4', 'lzo', 'lzop', 'lzma', 'xz'];
 outextlist = ['gz', 'cgz', 'bz2', 'cbz', 'zst', 'czst', 'lz4', 'clz4', 'lzo', 'lzop', 'clzo', 'lzma', 'xz', 'cxz'];
 outextlistwd = ['.gz', '.cgz', '.bz2', '.cbz', '.zst', '.czst', '.lz4', '.clz4', '.lzo', '.lzop', '.clzo', '.lzma', '.xz', '.cxz'];
 if(outfile!="-" and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
  outfile = RemoveWindowsPath(outfile);
 checksumtype = checksumtype.lower();
 if(not CheckSumSupport(checksumtype, hashlib_guaranteed)):
  checksumtype="crc32";
 if(checksumtype=="none"):
  checksumtype = "";
 if(not compression or compression or compression=="catfile" or compression==__file_format_lower__):
  compression = None;
 if(compression not in compressionlist and compression is None):
  compression = "auto";
 if(verbose):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(outfile!="-" and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
  if(os.path.exists(outfile)):
   os.unlink(outfile);
 if(outfile=="-"):
  verbose = False;
  catfp = BytesIO();
 elif(hasattr(outfile, "read") or hasattr(outfile, "write")):
  catfp = outfile;
 else:
  fbasename = os.path.splitext(outfile)[0];
  fextname = os.path.splitext(outfile)[1];
  if(fextname not in outextlistwd and (compression=="auto" or compression is None)):
   catfp = open(outfile, "wb");
  elif(((fextname==".gz" or fextname==".cgz") and compression=="auto") or compression=="gzip"):
   try:
    import gzip;
   except ImportError:
    return False;
   if(compressionlevel is None):
    compressionlevel = 9;
   else:
    compressionlevel = int(compressionlevel);
   catfp = gzip.GzipFile(outfile, "wb", compresslevel=compressionlevel);
  elif(((fextname==".bz2" or fextname==".cbz") and compression=="auto") or compression=="bzip2"):
   try:
    import bz2;
   except ImportError:
    return False;
   if(compressionlevel is None):
    compressionlevel = 9;
   else:
    compressionlevel = int(compressionlevel);
   catfp = bz2.BZ2File(outfile, "wb", compresslevel=compressionlevel);
  elif(((fextname==".zst" or fextname==".czst") and compression=="auto") or compression=="zstd"):
   try:
    import zstandard;
   except ImportError:
    return False;
   if(compressionlevel is None):
    compressionlevel = 10;
   else:
    compressionlevel = int(compressionlevel);
   catfp = zstandard.open(outfile, "wb", zstandard.ZstdCompressor(level=compressionlevel));
  elif(((fextname==".lz4" or fextname==".clz4") and compression=="auto") or compression=="lz4"):
   try:
    import lz4.frame;
   except ImportError:
    return False;
   if(compressionlevel is None):
    compressionlevel = 9;
   else:
    compressionlevel = int(compressionlevel);
   catfp = lz4.frame.open(outfile, "wb", compression_level=compressionlevel);
  elif(((fextname==".xz" or fextname==".cxz") and compression=="auto") or compression=="xz"):
   try:
    import lzma;
   except ImportError:
    return False;
   if(compressionlevel is None):
    compressionlevel = 9;
   else:
    compressionlevel = int(compressionlevel);
   catfp = lzma.open(outfile, "wb", format=lzma.FORMAT_XZ, preset=compressionlevel);
  elif((fextname==".lzma" and compression=="auto") or compression=="lzma"):
   try:
    import lzma;
   except ImportError:
    return False;
   if(compressionlevel is None):
    compressionlevel = 9;
   else:
    compressionlevel = int(compressionlevel);
   catfp = lzma.open(outfile, "wb", format=lzma.FORMAT_ALONE, preset=compressionlevel);
 catver = __cat_header_ver__;
 fileheaderver = str(int(catver.replace(".", "")));
 fileheader = AppendNullByte(__file_format_name__ + fileheaderver);
 catfp.write(fileheader.encode('UTF-8'));
 curinode = 0;
 curfid = 0;
 inodelist = [];
 inodetofile = {};
 filetoinode = {};
 inodetocatinode = {};
 if(not os.path.exists(infile) or not os.path.isfile(infile)):
  return False;
 if(not zipfile.is_zipfile(infile)):
  return False;
 zipfp = zipfile.ZipFile(infile, "r", allowZip64=True);
 ziptest = zipfp.testzip();
 if(ziptest):
  VerbosePrintOut("Bad file found: " + str(bad_file));
 fnumfiles = format(int(len(zipfp.infolist())), 'x').lower();
 fnumfilesa = AppendNullBytes([fnumfiles, checksumtype]);
 if(checksumtype=="none" or checksumtype==""):
  catfileheadercshex = format(0, 'x').lower();
 elif(checksumtype=="crc16" or checksumtype=="crc16_ansi" or checksumtype=="crc16_ibm"):
  catfileheadercshex = format(crc16(str(fileheader + fnumfilesa).encode('UTF-8')) & 0xffff, '04x').lower();
 elif(checksumtype=="crc16_ccitt"):
  catfileheadercshex = format(crc16_ccitt(str(fileheader + fnumfilesa).encode('UTF-8')) & 0xffff, '04x').lower();
 elif(checksumtype=="adler32"):
  catfileheadercshex = format(zlib.adler32(str(fileheader + fnumfilesa).encode('UTF-8')) & 0xffffffff, '08x').lower();
 elif(checksumtype=="crc32"):
  catfileheadercshex = format(crc32(str(fileheader + fnumfilesa).encode('UTF-8')) & 0xffffffff, '08x').lower();
 elif(checksumtype=="crc64_ecma"):
  catfileheadercshex = format(crc64_ecma(str(fileheader + fnumfilesa).encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
 elif(checksumtype=="crc64" or checksumtype=="crc64_iso"):
  catfileheadercshex = format(crc64_iso(str(fileheader + fnumfilesa).encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
 elif(CheckSumSupportAlt(checksumtype, hashlib_guaranteed)):
  checksumoutstr = hashlib.new(checksumtype);
  checksumoutstr.update(str(fileheader + fnumfilesa).encode('UTF-8'));
  catfileheadercshex = checksumoutstr.hexdigest().lower();
 fnumfilesa = fnumfilesa + AppendNullByte(catfileheadercshex);
 catfp.write(fnumfilesa.encode('UTF-8'));
 for member in zipfp.infolist():
  catfhstart = catfp.tell();
  if(re.findall("^[.|/]", member.filename)):
   fname = member.filename;
  else:
   fname = "./"+member.filename;
  zipinfo = zipfp.getinfo(member.filename);
  if(verbose):
   VerbosePrintOut(fname);
  if(not member.is_dir()):
   fpremode = format(int(stat.S_IFREG + 438), 'x').lower();
  if(member.is_dir()):
   fpremode = format(int(stat.S_IFDIR + 511), 'x').lower();
  flinkcount = 0;
  ftype = 0;
  if(not member.is_dir()):
   ftype = 0;
  if(member.is_dir()):
   ftype = 5;
  flinkname = "";
  fcurfid = format(int(curfid), 'x').lower();
  fcurinode = format(int(0), 'x').lower();
  curfid = curfid + 1;
  fdev_minor = format(int(0), 'x').lower();
  fdev_major = format(int(0), 'x').lower();
  frdev_minor = format(int(0), 'x').lower();
  frdev_major = format(int(0), 'x').lower();
  if(ftype==5):
   fsize = format(int("0"), 'x').lower();
  if(ftype==0):
   fsize = format(int(member.file_size), 'x').lower();
  fatime = format(int(time.mktime(member.date_time + (0, 0, -1))), 'x').lower();
  fmtime = format(int(time.mktime(member.date_time + (0, 0, -1))), 'x').lower();
  fctime = format(int(time.mktime(member.date_time + (0, 0, -1))), 'x').lower();
  fbtime = format(int(time.mktime(member.date_time + (0, 0, -1))), 'x').lower();
  if(not member.is_dir()):
   fmode = format(int(stat.S_IFREG + 438), 'x').lower();
   fchmode = format(int(stat.S_IMODE(int(stat.S_IFREG + 438))), 'x').lower();
   ftypemod = format(int(stat.S_IFMT(int(stat.S_IFREG + 438))), 'x').lower();
  if(member.is_dir()):
   fmode = format(int(stat.S_IFDIR + 511), 'x').lower();
   fchmode = format(int(stat.S_IMODE(int(stat.S_IFDIR + 511))), 'x').lower();
   ftypemod = format(int(stat.S_IFMT(int(stat.S_IFDIR + 511))), 'x').lower();
  try:
   fuid = format(int(os.getuid()), 'x').lower();
  except AttributeError:
   fuid = format(int(0), 'x').lower();
  except KeyError:
   fuid = format(int(0), 'x').lower();
  try:
   fgid = format(int(os.getgid()), 'x').lower();
  except AttributeError:
   fgid = format(int(0), 'x').lower();
  except KeyError:
   fgid = format(int(0), 'x').lower();
  try:
   import pwd;
   try:
    userinfo = pwd.getpwuid(os.getuid());
    funame = userinfo.pw_name;
   except KeyError:
    funame = "";
   except AttributeError:
    funame = "";
  except ImportError:
   funame = "";
  fgname = "";
  try:
   import grp;
   try:
    groupinfo = grp.getgrgid(os.getgid());
    fgname = groupinfo.gr_name;
   except KeyError:
    fgname = "";
   except AttributeError:
    fgname = "";
  except ImportError:
   fgname = "";
  fcontents = "".encode('UTF-8');
  if(ftype==0):
   fcontents = zipfp.read(member.filename);
  ftypehex = format(ftype, 'x').lower();
  extrafields = format(len(extradata), 'x').lower();
  extrasizestr = AppendNullByte(extrafields);
  if(len(extradata)>0):
   extrasizestr = extrasizestr + AppendNullBytes(extradata);
  extrasizelen = format(len(extrasizestr), 'x').lower();
  catfileoutstr = AppendNullBytes([ftypehex, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev_minor, fdev_major, frdev_minor, frdev_major, extrasizelen, extrafields]);
  if(len(extradata)>0):
   catfileoutstr = catfileoutstr + AppendNullBytes(extradata);
  catfileoutstr = catfileoutstr + AppendNullByte(checksumtype);
  catfhend = (catfp.tell() - 1) + len(catfileoutstr);
  catfcontentstart = catfp.tell() + len(catfileoutstr);
  if(checksumtype=="none" or checksumtype==""):
   catfileheadercshex = format(0, 'x').lower();
   catfilecontentcshex = format(0, 'x').lower();
  elif(checksumtype=="crc16" or checksumtype=="crc16_ansi" or checksumtype=="crc16_ibm"):
   catfileheadercshex = format(crc16("".encode('UTF-8')) & 0xffff, '04x').lower();
   catfilecontentcshex = format(crc16(fcontents) & 0xffff, '04x').lower();
  elif(checksumtype=="crc16_ccitt"):
   catfileheadercshex = format(crc16_ccitt("".encode('UTF-8')) & 0xffff, '04x').lower();
   catfilecontentcshex = format(crc16_ccitt(fcontents) & 0xffff, '04x').lower();
  elif(checksumtype=="adler32"):
   catfileheadercshex = format(zlib.adler32("".encode('UTF-8')) & 0xffffffff, '08x').lower();
   catfilecontentcshex = format(zlib.adler32(fcontents) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc32"):
   catfileheadercshex = format(crc32("".encode('UTF-8')) & 0xffffffff, '08x').lower();
   catfilecontentcshex = format(crc32(fcontents) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc64_ecma"):
   catfileheadercshex = format(crc64_ecma("".encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
   catfilecontentcshex = format(crc64_ecma(fcontents) & 0xffffffffffffffff, '016x').lower();
  elif(checksumtype=="crc64" or checksumtype=="crc64_iso"):
   catfileheadercshex = format(crc64_iso("".encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
   catfilecontentcshex = format(crc64_iso(fcontents) & 0xffffffffffffffff, '016x').lower();
  elif(CheckSumSupportAlt(checksumtype, hashlib_guaranteed)):
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update("".encode('UTF-8'));
   catfileheadercshex = checksumoutstr.hexdigest().lower();
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(fcontents);
   catfilecontentcshex = checksumoutstr.hexdigest().lower();
  tmpfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex]);
  catheaersize = format(int(len(tmpfileoutstr) - 1), 'x').lower()
  catfileoutstr = AppendNullByte(catheaersize) + catfileoutstr;
  if(checksumtype=="none" or checksumtype==""):
   catfileheadercshex = format(0, 'x').lower();
  elif(checksumtype=="crc16" or checksumtype=="crc16_ansi" or checksumtype=="crc16_ibm"):
   catfileheadercshex = format(crc16(catfileoutstr.encode('UTF-8')) & 0xffff, '04x').lower();
  elif(checksumtype=="crc16_ccitt"):
   catfileheadercshex = format(crc16_ccitt(catfileoutstr.encode('UTF-8')) & 0xffff, '04x').lower();
  elif(checksumtype=="adler32"):
   catfileheadercshex = format(zlib.adler32(catfileoutstr.encode('UTF-8')) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc32"):
   catfileheadercshex = format(crc32(catfileoutstr.encode('UTF-8')) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc64_ecma"):
   catfileheadercshex = format(crc64_ecma(catfileoutstr.encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
  elif(checksumtype=="crc64" or checksumtype=="crc64_iso"):
   catfileheadercshex = format(crc64_iso(catfileoutstr.encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
  elif(CheckSumSupportAlt(checksumtype, hashlib_guaranteed)):
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(catfileoutstr.encode('UTF-8'));
   catfileheadercshex = checksumoutstr.hexdigest().lower();
  catfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex]);
  catfileoutstrecd = catfileoutstr.encode('UTF-8');
  nullstrecd = __file_format_delimiter__.encode('UTF-8');
  catfileout = catfileoutstrecd + fcontents + nullstrecd;
  catfcontentend = (catfp.tell() - 1) + len(catfileout);
  catfp.write(catfileout);
 if(outfile=="-" or hasattr(outfile, "read") or hasattr(outfile, "write")):
  catfp = CompressCatFile(catfp, compression);
 if(outfile=="-"):
  catfp.seek(0, 0);
  if(hasattr(sys.stdout, "buffer")):
   shutil.copyfileobj(catfp, sys.stdout.buffer);
  else:
   shutil.copyfileobj(catfp, sys.stdout);
 if(returnfp):
  catfp.seek(0, 0);
  return catfp;
 else:
  catfp.close();
  return True;

def CatFileToArray(infile, seekstart=0, seekend=0, listonly=False, skipchecksum=False, returnfp=False):
 if(hasattr(infile, "read") or hasattr(infile, "write")):
  catfp = infile;
  catfp.seek(0, 0);
  catfp = UncompressCatFile(catfp);
  checkcompressfile = CheckCompressionSubType(catfp);
  if(checkcompressfile=="tarfile"):
   return TarFileToArray(infile, seekstart, seekend, listonly, skipchecksum, returnfp);
  if(checkcompressfile=="zipfile"):
   return ZipFileToArray(infile, seekstart, seekend, listonly, skipchecksum, returnfp);
  if(checkcompressfile!="catfile" and checkcompressfile!=__file_format_lower__):
   return False;
  if(not catfp):
   return False;
  catfp.seek(0, 0);
 elif(infile=="-"):
  catfp = BytesIO();
  if(hasattr(sys.stdin, "buffer")):
   shutil.copyfileobj(sys.stdin.buffer, catfp);
  else:
   shutil.copyfileobj(sys.stdin, catfp);
  catfp.seek(0, 0);
  catfp = UncompressCatFile(catfp);
  if(not catfp):
   return False;
  catfp.seek(0, 0);
 else:
  infile = RemoveWindowsPath(infile);
  checkcompressfile = CheckCompressionSubType(infile);
  if(checkcompressfile=="tarfile"):
   return TarFileToArray(infile, seekstart, seekend, listonly, skipchecksum, returnfp);
  if(checkcompressfile=="zipfile"):
   return ZipFileToArray(infile, seekstart, seekend, listonly, skipchecksum, returnfp);
  if(checkcompressfile!="catfile" and checkcompressfile!=__file_format_lower__):
   return False;
  compresscheck = CheckCompressionType(infile, True);
  if(not compresscheck):
   fextname = os.path.splitext(infile)[1];
   if(fextname==".gz" or fextname==".cgz"):
    compresscheck = "gzip";
   if(fextname==".bz2" or fextname==".cbz"):
    compresscheck = "bzip2";
   if(fextname==".zst" or fextname==".czst"):
    compresscheck = "zstd";
   if(fextname==".lz4" or fextname==".clz4"):
    compresscheck = "lz4";
   if(fextname==".lzo" or fextname==".lzop" or fextname==".clzo"):
    compresscheck = "lzo";
   if(fextname==".lzma" or fextname==".xz" or fextname==".cxz"):
    compresscheck = "lzma";
  if(not compresscheck):
   return False;
  if(compresscheck=="gzip"):
   try:
    import gzip;
   except ImportError:
    return False;
   catfp = gzip.GzipFile(infile, "rb");
  if(compresscheck=="bzip2"):
   try:
    import bz2;
   except ImportError:
    return False;
   catfp = bz2.BZ2File(infile, "rb");
  if(compresscheck=="lz4"):
   try:
    import lz4.frame;
   except ImportError:
    return False;
   catfp = lz4.frame.open(infile, "rb");
  if(compresscheck=="zstd"):
   try:
    import zstandard;
   except ImportError:
    return False;
   catfp = zstandard.open(infile, "rb");
  if(compresscheck=="lzma" or compresscheck=="xz"):
   try:
    import lzma;
   except ImportError:
    return False;
   catfp = lzma.open(infile, "rb");
  if(compresscheck=="catfile" and compresscheck==__file_format_lower__):
   catfp = open(infile, "rb");
 '''
 try:
  catfp.seek(0, 2);
 except OSError:
  SeekToEndOfFile(catfp);
 except ValueError:
  SeekToEndOfFile(catfp);
 CatSize = catfp.tell();
 CatSizeEnd = CatSize;
 '''
 try:
  catfp.seek(0, 0);
 except OSError:
  return False;
 except ValueError:
  return False;
 catheader = ReadFileHeaderData(catfp, 4);
 catstring = catheader[0];
 catversion = re.findall(r"([\d]+)$", catstring);
 fprenumfiles = catheader[1];
 fnumfiles = int(fprenumfiles, 16);
 fprechecksumtype = catheader[2];
 fprechecksum = catheader[3];
 fileheader = AppendNullByte(catstring);
 fnumfileshex = format(int(fnumfiles), 'x').lower();
 fileheader = fileheader + AppendNullBytes([fnumfileshex, fprechecksumtype]);
 if(fprechecksumtype=="none" or fprechecksumtype==""):
  catfileheadercshex = format(0, 'x').lower();
 elif(fprechecksumtype=="crc16" or fprechecksumtype=="crc16_ansi" or fprechecksumtype=="crc16_ibm"):
  catfileheadercshex = format(crc16(fileheader.encode('UTF-8')) & 0xffff, '04x').lower();
 elif(fprechecksumtype=="crc16_ccitt"):
  catfileheadercshex = format(crc16_ccitt(fileheader.encode('UTF-8')) & 0xffff, '04x').lower();
 elif(fprechecksumtype=="adler32"):
  catfileheadercshex = format(zlib.adler32(fileheader.encode('UTF-8')) & 0xffffffff, '08x').lower();
 elif(fprechecksumtype=="crc32"):
  catfileheadercshex = format(crc32(fileheader.encode('UTF-8')) & 0xffffffff, '08x').lower();
 elif(fprechecksumtype=="crc64_ecma"):
  catfileheadercshex = format(crc64_ecma(fileheader.encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
 elif(fprechecksumtype=="crc64" or fprechecksumtype=="crc64_iso"):
  catfileheadercshex = format(crc64_iso(fileheader.encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
 elif(CheckSumSupportAlt(fprechecksumtype, hashlib_guaranteed)):
  checksumoutstr = hashlib.new(fprechecksumtype);
  checksumoutstr.update(fileheader.encode('UTF-8'));
  catfileheadercshex = checksumoutstr.hexdigest().lower();
 fileheader = fileheader + AppendNullByte(catfileheadercshex);
 fheadtell = len(fileheader);
 if(fprechecksum!=catfileheadercshex and not skipchecksum):
  VerbosePrintOut("File Header Checksum Error with file " + infile + " at offset " + str(catfp.tell()));
  return False;
 catversions = re.search(r'(.*?)(\d+)$', catstring).groups();
 catlist = {'fnumfiles': fnumfiles, 'fformat': catversions[0], 'fversion': catversions[1], 'fchecksumtype': fprechecksumtype, 'fheaderchecksum': fprechecksum, 'ffilelist': {}};
 if(seekend<=0):
  seekend = fnumfiles;
 if(seekstart>0):
  il = 0;
  while(il < seekstart):
   preheaderdata = ReadFileHeaderData(catfp, 5);
   prefheadsize = int(preheaderdata[0], 16);
   prefseek = prefheadsize - (int(len(preheaderdata[1]) + 1) + int(len(preheaderdata[2]) + 1) + int(len(preheaderdata[3]) + 1) + int(len(preheaderdata[4]) + 1));
   preftype = int(preheaderdata[1], 16);
   prefsize = int(preheaderdata[4], 16);
   catfp.seek(prefseek, 1);
   catfp.seek(prefsize, 1);
   catfp.seek(1, 1);
   il = il + 1;
 fileidnum = seekstart;
 realidnum = 0;
 while(fileidnum<seekend):
  catfhstart = catfp.tell();
  catheaderdata = ReadFileHeaderData(catfp, 23);
  catfheadsize = int(catheaderdata[0], 16);
  catftype = int(catheaderdata[1], 16);
  if(re.findall("^[.|/]", catheaderdata[2])):
   catfname = catheaderdata[2];
  else:
   catfname = "./"+catheaderdata[2];
  catfbasedir = os.path.dirname(catfname);
  catflinkname = catheaderdata[3];
  catfsize = int(catheaderdata[4], 16);
  catfatime = int(catheaderdata[5], 16);
  catfmtime = int(catheaderdata[6], 16);
  catfctime = int(catheaderdata[7], 16);
  catfbtime = int(catheaderdata[8], 16);
  catfmode = int(catheaderdata[9], 16);
  catfchmode = stat.S_IMODE(catfmode);
  catftypemod = stat.S_IFMT(catfmode);
  catfuid = int(catheaderdata[10], 16);
  catfuname = catheaderdata[11];
  catfgid = int(catheaderdata[12], 16);
  catfgname = catheaderdata[13];
  fid = int(catheaderdata[14], 16);
  finode = int(catheaderdata[15], 16);
  flinkcount = int(catheaderdata[16], 16);
  catfdev_minor = int(catheaderdata[17], 16);
  catfdev_major = int(catheaderdata[18], 16);
  catfrdev_minor = int(catheaderdata[19], 16);
  catfrdev_major = int(catheaderdata[20], 16);
  catfextrasize = int(catheaderdata[21], 16);
  catfextrafields = int(catheaderdata[22], 16);
  extrafieldslist = [];
  if(catfextrafields>0):
   extrafieldslist = ReadFileHeaderData(catfp, catfextrafields);
  checksumsval = ReadFileHeaderData(catfp, 3);
  catfchecksumtype = checksumsval[0].lower();
  catfcs = checksumsval[1].lower();
  catfccs = checksumsval[2].lower();
  hc = 0;
  hcmax = len(catheaderdata);
  hout = "";
  while(hc<hcmax):
   hout = hout + AppendNullByte(catheaderdata[hc]);
   hc = hc + 1;
  if(len(extrafieldslist)>catfextrafields and len(extrafieldslist)>0):
   catfextrafields = len(extrafieldslist);
  if(catfextrafields>0):
   hc = 0;
   hcmax = catfextrafields;
   while(hc<hcmax):
    hout = hout + AppendNullByte(extrafieldslist[hc]);
    hc = hc + 1;
  hout = hout + AppendNullByte(checksumsval[0].lower());
  catfnumfields = 24 + catfextrafields;
  if(catfchecksumtype=="none" or catfchecksumtype==""):
   catnewfcs = 0;
  elif(catfchecksumtype=="crc16" or catfchecksumtype=="crc16_ansi" or catfchecksumtype=="crc16_ibm"):
   catnewfcs = format(crc16(hout.encode('UTF-8')) & 0xffff, '04x').lower();
  elif(catfchecksumtype=="adler32"):
   catnewfcs = format(zlib.adler32(hout.encode('UTF-8')) & 0xffffffff, '08x').lower();
  elif(catfchecksumtype=="crc32"):
   catnewfcs = format(crc32(hout.encode('UTF-8')) & 0xffffffff, '08x').lower();
  elif(catfchecksumtype=="crc64_ecma"):
   catnewfcs = format(crc64_ecma(hout.encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
  elif(catfchecksumtype=="crc64" or catfchecksumtype=="crc64_iso"):
   catnewfcs = format(crc64_iso(hout.encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
  elif(CheckSumSupportAlt(catfchecksumtype, hashlib_guaranteed)):
   checksumoutstr = hashlib.new(catfchecksumtype);
   checksumoutstr.update(hout.encode('UTF-8'));
   catnewfcs = checksumoutstr.hexdigest().lower();
  if(catfcs!=catnewfcs and not skipchecksum):
   VerbosePrintOut("File Header Checksum Error with file " + catfname + " at offset " + str(catfhstart));
   return False;
  catfhend = catfp.tell() - 1;
  catfcontentstart = catfp.tell();
  catfcontents = "";
  pyhascontents = False;
  if(catfsize>0 and not listonly):
   catfcontents = catfp.read(catfsize);
   if(catfchecksumtype=="none" or catfchecksumtype==""):
    catnewfccs = 0;
   elif(catfchecksumtype=="crc16" or catfchecksumtype=="crc16_ansi" or catfchecksumtype=="crc16_ibm"):
    catnewfccs = format(crc16(catfcontents) & 0xffff, '04x').lower();
   elif(catfchecksumtype=="crc16_ccitt"):
    catnewfcs = format(crc16_ccitt(catfcontents) & 0xffff, '04x').lower();
   elif(catfchecksumtype=="adler32"):
    catnewfccs = format(zlib.adler32(catfcontents) & 0xffffffff, '08x').lower();
   elif(catfchecksumtype=="crc32"):
    catnewfccs = format(crc32(catfcontents) & 0xffffffff, '08x').lower();
   elif(catfchecksumtype=="crc64_ecma"):
    catnewfcs = format(crc64_ecma(catfcontents) & 0xffffffffffffffff, '016x').lower();
   elif(catfchecksumtype=="crc64" or catfchecksumtype=="crc64_iso"):
    catnewfcs = format(crc64_iso(catfcontents) & 0xffffffffffffffff, '016x').lower();
   elif(CheckSumSupportAlt(catfchecksumtype, hashlib_guaranteed)):
    checksumoutstr = hashlib.new(catfchecksumtype);
    checksumoutstr.update(catfcontents);
    catnewfccs = checksumoutstr.hexdigest().lower();
   pyhascontents = True;
   if(catfccs!=catnewfccs and skipchecksum):
    VerbosePrintOut("File Content Checksum Error with file " + catfname + " at offset " + str(catfhstart));
    return False;
  if(catfsize>0 and listonly):
   catfp.seek(catfsize, 1);
   pyhascontents = False;
  catfcontentend = catfp.tell() - 1;
  catlist['ffilelist'].update({realidnum: {'fformat': __file_format_name__, 'fversion': catversions[1], 'fid': realidnum, 'fidalt': fileidnum, 'fheadersize': catfheadsize, 'fhstart': catfhstart, 'fhend': catfhend, 'ftype': catftype, 'fname': catfname, 'fbasedir': catfbasedir, 'flinkname': catflinkname, 'fsize': catfsize, 'fatime': catfatime, 'fmtime': catfmtime, 'fctime': catfctime, 'fbtime': catfbtime, 'fmode': catfmode, 'fchmode': catfchmode, 'ftypemod': catftypemod, 'fuid': catfuid, 'funame': catfuname, 'fgid': catfgid, 'fgname': catfgname, 'finode': finode, 'flinkcount': flinkcount, 'fminor': catfdev_minor, 'fmajor': catfdev_major, 'frminor': catfrdev_minor, 'frmajor': catfrdev_major, 'fchecksumtype': catfchecksumtype, 'fnumfields': catfnumfields, 'fextrafields': catfextrafields, 'fextrafieldsize': catfextrasize, 'fextralist': extrafieldslist, 'fheaderchecksum': catfcs, 'fcontentchecksum': catfccs, 'fhascontents': pyhascontents, 'fcontentstart': catfcontentstart, 'fcontentend': catfcontentend, 'fcontents': catfcontents} });
  catfp.seek(1, 1);
  fileidnum = fileidnum + 1;
  realidnum = realidnum + 1;
 if(returnfp):
  catlist.update({'catfp': catfp});
 else:
  catfp.close();
 return catlist;

def CatStringToArray(catstr, seekstart=0, seekend=0, listonly=False, skipchecksum=False, returnfp=False):
 catfp = BytesIO(catstr);
 listcatfiles = CatFileToArray(catfp, seekstart, seekend, listonly, skipchecksum, returnfp);
 return listcatfiles;

def TarFileToArray(infile, seekstart=0, seekend=0, listonly=False, skipchecksum=False, returnfp=False):
 catfp = BytesIO();
 catfp = PackCatFileFromTarFile(infile, catfp, "auto", None, "crc32", False, True);
 listcatfiles = CatFileToArray(catfp, seekstart, seekend, listonly, skipchecksum, returnfp);
 return listcatfiles;

def ZipFileToArray(infile, seekstart=0, seekend=0, listonly=False, skipchecksum=False, returnfp=False):
 catfp = BytesIO();
 catfp = PackCatFileFromZipFile(infile, catfp, "auto", None, "crc32", False, True);
 listcatfiles = CatFileToArray(catfp, seekstart, seekend, listonly, skipchecksum, returnfp);
 return listcatfiles;

def ListDirToArrayAlt(infiles, dirlistfromtxt=False, followlink=False, listonly=False, checksumtype="crc32", extradata=[], verbose=False):
 catver = __cat_header_ver__;
 fileheaderver = str(int(catver.replace(".", "")));
 fileheader = AppendNullByte(__file_format_name__ + fileheaderver);
 catversion = fileheaderver;
 advancedlist = True;
 infilelist = [];
 if(infiles=="-"):
  for line in sys.stdin:
   infilelist.append(line.strip());
  infilelist = list(filter(None, infilelist));
 elif(infiles!="-" and dirlistfromtxt and os.path.exists(infiles) and (os.path.isfile(infiles) or infiles=="/dev/null" or infiles=="NUL")):
  if(not os.path.exists(infiles) or not os.path.isfile(infiles)):
   return False;
  with open(infiles, "r") as finfile:
   for line in finfile:
    infilelist.append(line.strip());
  infilelist = list(filter(None, infilelist));
 else:
  if(isinstance(infiles, (list, tuple, ))):
   infilelist = list(filter(None, infiles));
  elif(isinstance(infiles, (str, ))):
   infilelist = list(filter(None, [infiles]));
 if(advancedlist):
  GetDirList = ListDirAdvanced(infilelist, followlink, False);
 else:
  GetDirList = ListDir(infilelist, followlink, False);
 if(not GetDirList):
  return False;
 curinode = 0;
 curfid = 0;
 inodelist = [];
 inodetofile = {};
 filetoinode = {};
 inodetocatinode = {};
 fileidnum = 0;
 fnumfiles = int(len(GetDirList));
 catver = __cat_header_ver__;
 fileheaderver = str(int(catver.replace(".", "")));
 fileheader = AppendNullByte(__file_format_name__ + fileheaderver);
 fnumfileshex = format(int(fnumfiles), 'x').lower();
 fileheader = fileheader + AppendNullBytes([fnumfileshex, checksumtype]);
 if(checksumtype=="none" or checksumtype==""):
  catfileheadercshex = format(0, 'x').lower();
 elif(checksumtype=="crc16" or checksumtype=="crc16_ansi" or checksumtype=="crc16_ibm"):
  catfileheadercshex = format(crc16(fileheader.encode('UTF-8')) & 0xffff, '04x').lower();
 elif(checksumtype=="crc16_ccitt"):
  catfileheadercshex = format(crc16_ccitt(fileheader.encode('UTF-8')) & 0xffff, '04x').lower();
 elif(checksumtype=="adler32"):
  catfileheadercshex = format(zlib.adler32(fileheader.encode('UTF-8')) & 0xffffffff, '08x').lower();
 elif(checksumtype=="crc32"):
  catfileheadercshex = format(crc32(fileheader.encode('UTF-8')) & 0xffffffff, '08x').lower();
 elif(checksumtype=="crc64_ecma"):
  catfileheadercshex = format(crc64_ecma(fileheader.encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
 elif(checksumtype=="crc64" or checksumtype=="crc64_iso"):
  catfileheadercshex = format(crc64_iso(fileheader.encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
 elif(CheckSumSupportAlt(checksumtype, hashlib_guaranteed)):
  checksumoutstr = hashlib.new(checksumtype);
  checksumoutstr.update(fileheader.encode('UTF-8'));
  catfileheadercshex = checksumoutstr.hexdigest().lower();
 fileheader = fileheader + AppendNullByte(catfileheadercshex);
 fheadtell = len(fileheader);
 catlist = {'fnumfiles': fnumfiles, 'fformat': __file_format_name__, 'fversion': catversion, 'fchecksumtype': checksumtype, 'fheaderchecksum': catfileheadercshex, 'ffilelist': {}};
 for curfname in GetDirList:
  if(re.findall("^[.|/]", curfname)):
   fname = curfname;
  else:
   fname = "./"+curfname;
  if(verbose):
   VerbosePrintOut(fname);
  if(not followlink or followlink is None):
   fstatinfo = os.lstat(fname);
  else:
   fstatinfo = os.stat(fname);
  fpremode = fstatinfo.st_mode;
  finode = fstatinfo.st_ino;
  flinkcount = fstatinfo.st_nlink;
  ftype = 0;
  if(stat.S_ISREG(fpremode)):
   ftype = 0;
  if(stat.S_ISLNK(fpremode)):
   ftype = 2;
  if(stat.S_ISCHR(fpremode)):
   ftype = 3;
  if(stat.S_ISBLK(fpremode)):
   ftype = 4;
  if(stat.S_ISDIR(fpremode)):
   ftype = 5;
  if(stat.S_ISFIFO(fpremode)):
   ftype = 6;
  if(hasattr(stat, "S_ISDOOR") and stat.S_ISDOOR(fpremode)):
   ftype = 8;
  if(hasattr(stat, "S_ISPORT") and stat.S_ISPORT(fpremode)):
   ftype = 9;
  if(hasattr(stat, "S_ISWHT") and stat.S_ISWHT(fpremode)):
   ftype = 10;
  flinkname = "";
  fbasedir = os.path.dirname(fname);
  fcurfid = curfid;
  if(not followlink and finode!=0):
   if(ftype!=1):
    if(finode in inodelist):
     ftype = 1;
     flinkname = inodetofile[finode];
     fcurinode = inodetocatinode[finode];
    if(finode not in inodelist):
     inodelist.append(finode);
     inodetofile.update({finode: fname});
     inodetocatinode.update({finode: curinode});
     fcurinode = curinode;
     curinode = curinode + 1;
  else:
   fcurinode = curinode;
   curinode = curinode + 1;
  curfid = curfid + 1;
  if(ftype==2):
   flinkname = os.readlink(fname);
  fdev = fstatinfo.st_dev;
  getfdev = GetDevMajorMinor(fdev);
  fdev_minor = getfdev[0];
  fdev_major = getfdev[1];
  frdev = fstatinfo.st_dev;
  if(hasattr(fstatinfo, "st_rdev")):
   frdev = fstatinfo.st_rdev;
  else:
   frdev = fstatinfo.st_dev;
  getfrdev = GetDevMajorMinor(frdev);
  frdev_minor = getfrdev[0];
  frdev_major = getfrdev[1];
  if(ftype==1 or ftype==2 or ftype==3 or ftype==4 or ftype==5 or ftype==6):
   fsize = "0";
  if(ftype==0 or ftype==7):
   fsize = fstatinfo.st_size;
  fatime = fstatinfo.st_atime;
  fmtime = fstatinfo.st_mtime;
  fctime = fstatinfo.st_ctime;
  if(hasattr(fstatinfo, "st_birthtime")):
   fbtime = fstatinfo.st_birthtime;
  else:
   fbtime = fstatinfo.st_ctime;
  fmode = fstatinfo.st_mode;
  fchmode = stat.S_IMODE(fstatinfo.st_mode);
  ftypemod = stat.S_IFMT(fstatinfo.st_mode);
  fuid = fstatinfo.st_uid;
  fgid = fstatinfo.st_gid;
  funame = "";
  try:
   import pwd;
   try:
    userinfo = pwd.getpwuid(fstatinfo.st_uid);
    funame = userinfo.pw_name;
   except KeyError:
    funame = "";
  except ImportError:
   funame = "";
  fgname = "";
  try:
   import grp;
   try:
    groupinfo = grp.getgrgid(fstatinfo.st_gid);
    fgname = groupinfo.gr_name;
   except KeyError:
    fgname = "";
  except ImportError:
   fgname = "";
  fdev_minor = fdev_minor;
  fdev_major = fdev_major;
  frdev_minor = frdev_minor;
  frdev_major = frdev_major;
  finode = finode;
  flinkcount = flinkcount;
  if(hasattr(fstatinfo, "st_file_attributes")):
   fwinattributes = fstatinfo.st_file_attributes;
  else:
   fwinattributes = 0;
  fcontents = "".encode('UTF-8');
  if(ftype==0 or ftype==7):
   fpc = open(fname, "rb");
   fcontents = fpc.read(int(fstatinfo.st_size));
   fpc.close();
  if(followlink and (ftype==1 or ftype==2)):
   flstatinfo = os.stat(flinkname);
   fpc = open(flinkname, "rb");
   fcontents = fpc.read(int(flstatinfo.st_size));
   fpc.close();
  ftypehex = format(ftype, 'x').lower();
  extrafields = len(extradata);
  extrafieldslist = extradata;
  catfextrafields = extrafields;
  extrasizestr = AppendNullByte(extrafields);
  if(len(extradata)>0):
   extrasizestr = extrasizestr + AppendNullBytes(extradata);
  extrasizelen = len(extrasizestr);
  extrasizelenhex = format(extrasizelen, 'x').lower();
  catfileoutstr = AppendNullBytes([ftypehex, fname, flinkname, format(int(fsize), 'x').lower(), format(int(fatime), 'x').lower(), format(int(fmtime), 'x').lower(), format(int(fctime), 'x').lower(), format(int(fbtime), 'x').lower(), format(int(fmode), 'x').lower(), format(int(fuid), 'x').lower(), funame, format(int(fgid), 'x').lower(), fgname, format(int(fcurfid), 'x').lower(), format(int(fcurinode), 'x').lower(), format(int(flinkcount), 'x').lower(), format(int(fdev_minor), 'x').lower(), format(int(fdev_major), 'x').lower(), format(int(frdev_minor), 'x').lower(), format(int(frdev_major), 'x').lower(), extrasizelenhex, format(catfextrafields, 'x').lower()]);
  if(len(extradata)>0):
   catfileoutstr = catfileoutstr + AppendNullBytes(extradata);
  catfileoutstr = catfileoutstr + AppendNullByte(checksumtype);
  catfnumfields = 24 + catfextrafields;
  if(checksumtype=="none" or checksumtype==""):
   catfileheadercshex = format(0, 'x').lower();
   catfilecontentcshex = format(0, 'x').lower();
  elif(checksumtype=="crc16" or checksumtype=="crc16_ansi" or checksumtype=="crc16_ibm"):
   catfileheadercshex = format(crc16("".encode('UTF-8')) & 0xffff, '04x').lower();
   catfilecontentcshex = format(crc16(fcontents) & 0xffff, '04x').lower();
  elif(checksumtype=="crc16_ccitt"):
   catfileheadercshex = format(crc16_ccitt("".encode('UTF-8')) & 0xffff, '04x').lower();
   catfilecontentcshex = format(crc16_ccitt(fcontents) & 0xffff, '04x').lower();
  elif(checksumtype=="adler32"):
   catfileheadercshex = format(zlib.adler32("".encode('UTF-8')) & 0xffffffff, '08x').lower();
   catfilecontentcshex = format(zlib.adler32(fcontents) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc32"):
   catfileheadercshex = format(crc32("".encode('UTF-8')) & 0xffffffff, '08x').lower();
   catfilecontentcshex = format(crc32(fcontents) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc64_ecma"):
   catfileheadercshex = format(crc64_ecma("".encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
   catfilecontentcshex = format(crc64_ecma(fcontents) & 0xffffffffffffffff, '016x').lower();
  elif(checksumtype=="crc64" or checksumtype=="crc64_iso"):
   catfileheadercshex = format(crc64_iso("".encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
   catfilecontentcshex = format(crc64_iso(fcontents) & 0xffffffffffffffff, '016x').lower();
  elif(CheckSumSupportAlt(checksumtype, hashlib_guaranteed)):
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update("".encode('UTF-8'));
   catfileheadercshex = checksumoutstr.hexdigest().lower();
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(fcontents);
   catfilecontentcshex = checksumoutstr.hexdigest().lower();
  catfhstart = fheadtell;
  fheadtell += len(catfileoutstr);
  catfhend = fheadtell - 1;
  catfcontentstart = fheadtell;
  tmpfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex]);
  catheaersize = format(int(len(tmpfileoutstr) - 1), 'x').lower()
  catfileoutstr = AppendNullByte(catheaersize) + catfileoutstr;
  if(checksumtype=="none" or checksumtype==""):
   catfileheadercshex = format(0, 'x').lower();
  elif(checksumtype=="crc16" or checksumtype=="crc16_ansi" or checksumtype=="crc16_ibm"):
   catfileheadercshex = format(crc16(catfileoutstr.encode('UTF-8')) & 0xffff, '04x').lower();
  elif(checksumtype=="crc16_ccitt"):
   catfileheadercshex = format(crc16_ccitt(catfileoutstr.encode('UTF-8')) & 0xffff, '04x').lower();
  elif(checksumtype=="adler32"):
   catfileheadercshex = format(zlib.adler32(catfileoutstr.encode('UTF-8')) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc32"):
   catfileheadercshex = format(crc32(catfileoutstr.encode('UTF-8')) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc64_ecma"):
   catfileheadercshex = format(crc64_ecma(catfileoutstr.encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
  elif(checksumtype=="crc64" or checksumtype=="crc64_iso"):
   catfileheadercshex = format(crc64_iso(catfileoutstr.encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
  elif(CheckSumSupportAlt(checksumtype, hashlib_guaranteed)):
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(catfileoutstr.encode('UTF-8'));
   catfileheadercshex = checksumoutstr.hexdigest().lower();
  catfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex]);
  catfileoutstrecd = catfileoutstr.encode('UTF-8');
  nullstrecd = __file_format_delimiter__.encode('UTF-8');
  fheadtell += len(catfileoutstr) + 1;
  catfcontentend = fheadtell - 1;
  catfileout = catfileoutstrecd + fcontents + nullstrecd;
  pyhascontents = False;
  if(int(fsize)>0 and not listonly):
   pyhascontents = True;
  if(int(fsize)>0 and listonly):
   fcontents = "";
   pyhascontents = False;
  catlist['ffilelist'].update({fileidnum: {'fformat': __file_format_name__, 'fversion': catversion, 'fid': fileidnum, 'fidalt': fileidnum, 'fheadersize': int(catheaersize, 16), 'fhstart': catfhstart, 'fhend': catfhend, 'ftype': ftype, 'fname': fname, 'fbasedir': fbasedir, 'flinkname': flinkname, 'fsize': fsize, 'fatime': fatime, 'fmtime': fmtime, 'fctime': fctime, 'fbtime': fbtime, 'fmode': fmode, 'fchmode': fchmode, 'ftypemod': ftypemod, 'fuid': fuid, 'funame': funame, 'fgid': fgid, 'fgname': fgname, 'finode': finode, 'flinkcount': flinkcount, 'fminor': fdev_minor, 'fmajor': fdev_major, 'frminor': frdev_minor, 'frmajor': frdev_major, 'fchecksumtype': checksumtype, 'fnumfields': catfnumfields, 'fextrafields': catfextrafields, 'fextrafieldsize': extrasizelen, 'fextralist': extrafieldslist, 'fheaderchecksum': int(catfileheadercshex, 16), 'fcontentchecksum': int(catfilecontentcshex, 16), 'fhascontents': pyhascontents, 'fcontentstart': catfcontentstart, 'fcontentend': catfcontentend, 'fcontents': fcontents} });
  fileidnum = fileidnum + 1;
 return catlist;

def TarFileToArrayAlt(infiles, listonly=False, checksumtype="crc32", extradata=[], verbose=False):
 catver = __cat_header_ver__;
 fileheaderver = str(int(catver.replace(".", "")));
 fileheader = AppendNullByte(__file_format_name__ + fileheaderver);
 catversion = fileheaderver;
 curinode = 0;
 curfid = 0;
 inodelist = [];
 inodetofile = {};
 filetoinode = {};
 inodetocatinode = {};
 fileidnum = 0;
 if(not os.path.exists(infiles) or not os.path.isfile(infiles)):
  return False;
 try:
  if(not tarfile.is_tarfile(infiles)):
   return False;
 except AttributeError:
  if(not is_tarfile(infiles)):
   return False;
 tarfp = tarfile.open(infiles, "r");
 fnumfiles = int(len(tarfp.getmembers()));
 catver = __cat_header_ver__;
 fileheaderver = str(int(catver.replace(".", "")));
 fileheader = AppendNullByte(__file_format_name__ + fileheaderver);
 fnumfileshex = format(int(fnumfiles), 'x').lower();
 fileheader = fileheader + AppendNullBytes([fnumfileshex, checksumtype]);
 if(checksumtype=="none" or checksumtype==""):
  catfileheadercshex = format(0, 'x').lower();
 elif(checksumtype=="crc16" or checksumtype=="crc16_ansi" or checksumtype=="crc16_ibm"):
  catfileheadercshex = format(crc16(fileheader.encode('UTF-8')) & 0xffff, '04x').lower();
 elif(checksumtype=="crc16_ccitt"):
  catfileheadercshex = format(crc16_ccitt(fileheader.encode('UTF-8')) & 0xffff, '04x').lower();
 elif(checksumtype=="adler32"):
  catfileheadercshex = format(zlib.adler32(fileheader.encode('UTF-8')) & 0xffffffff, '08x').lower();
 elif(checksumtype=="crc32"):
  catfileheadercshex = format(crc32(fileheader.encode('UTF-8')) & 0xffffffff, '08x').lower();
 elif(checksumtype=="crc64_ecma"):
  catfileheadercshex = format(crc64_ecma(fileheader.encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
 elif(checksumtype=="crc64" or checksumtype=="crc64_iso"):
  catfileheadercshex = format(crc64_iso(fileheader.encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
 elif(CheckSumSupportAlt(checksumtype, hashlib_guaranteed)):
  checksumoutstr = hashlib.new(checksumtype);
  checksumoutstr.update(fileheader.encode('UTF-8'));
  catfileheadercshex = checksumoutstr.hexdigest().lower();
 fileheader = fileheader + AppendNullByte(catfileheadercshex);
 fheadtell = len(fileheader);
 catlist = {'fnumfiles': fnumfiles, 'fformat': __file_format_name__, 'fversion': catversion, 'fchecksumtype': checksumtype, 'fheaderchecksum': catfileheadercshex, 'ffilelist': {}};
 for member in tarfp.getmembers():
  if(re.findall("^[.|/]", member.name)):
   fname = member.name;
  else:
   fname = "./"+member.name;
  if(verbose):
   VerbosePrintOut(fname);
  fpremode = member.mode;
  ffullmode = member.mode;
  flinkcount = 0;
  ftype = 0;
  if(member.isreg()):
   ffullmode = member.mode + stat.S_IFREG;
   ftype = 0;
  if(member.isdev()):
   ffullmode = member.mode;
   ftype = 7;
  if(member.islnk()):
   ffullmode = member.mode + stat.S_IFREG;
   ftype = 1;
  if(member.issym()):
   ffullmode = member.mode + stat.S_IFLNK;
   ftype = 2;
  if(member.ischr()):
   ffullmode = member.mode + stat.S_IFCHR;
   ftype = 3;
  if(member.isblk()):
   ffullmode = member.mode + stat.S_IFBLK;
   ftype = 4;
  if(member.isdir()):
   ffullmode = member.mode + stat.S_IFDIR;
   ftype = 5;
  if(member.isfifo()):
   ffullmode = member.mode + stat.S_IFIFO;
   ftype = 6;
  if(member.issparse()):
   ffullmode = member.mode;
   ftype = 8;
  flinkname = "";
  fbasedir = os.path.dirname(fname);
  fcurfid = curfid;
  fcurinode = 0;
  finode = fcurinode;
  curfid = curfid + 1;
  if(ftype==2):
   flinkname = member.linkname;
  fdev_minor = member.devminor;
  fdev_major = member.devmajor;
  frdev_minor = member.devminor;
  frdev_major = member.devmajor;
  if(ftype==1 or ftype==2 or ftype==3 or ftype==4 or ftype==5 or ftype==6):
   fsize = "0";
  if(ftype==0 or ftype==7):
   fsize = member.size;
  fatime = member.mtime;
  fmtime = member.mtime;
  fctime = member.mtime;
  fbtime = member.mtime;
  fmode = ffullmode;
  fchmode = stat.S_IMODE(ffullmode);
  ftypemod = stat.S_IFMT(ffullmode);
  fuid = member.uid;
  fgid = member.gid;
  funame = member.uname;
  fgname = member.gname;
  flinkcount = flinkcount;
  fcontents = "".encode('UTF-8');
  if(ftype==0 or ftype==7):
   fpc = tarfp.extractfile(member);
   fcontents = fpc.read(int(member.size));
   fpc.close();
  ftypehex = format(ftype, 'x').lower();
  extrafields = len(extradata);
  extrafieldslist = extradata;
  catfextrafields = extrafields;
  extrasizestr = AppendNullByte(extrafields);
  if(len(extradata)>0):
   extrasizestr = extrasizestr + AppendNullBytes(extradata);
  extrasizelen = len(extrasizestr);
  extrasizelenhex = format(extrasizelen, 'x').lower();
  catfileoutstr = AppendNullBytes([ftypehex, fname, flinkname, format(int(fsize), 'x').lower(), format(int(fatime), 'x').lower(), format(int(fmtime), 'x').lower(), format(int(fctime), 'x').lower(), format(int(fbtime), 'x').lower(), format(int(fmode), 'x').lower(), format(int(fuid), 'x').lower(), funame, format(int(fgid), 'x').lower(), fgname, format(int(fcurfid), 'x').lower(), format(int(fcurinode), 'x').lower(), format(int(flinkcount), 'x').lower(), format(int(fdev_minor), 'x').lower(), format(int(fdev_major), 'x').lower(), format(int(frdev_minor), 'x').lower(), format(int(frdev_major), 'x').lower(), extrasizelenhex, format(catfextrafields, 'x').lower()]);
  if(len(extradata)>0):
   catfileoutstr = catfileoutstr + AppendNullBytes(extradata);
  catfileoutstr = catfileoutstr + AppendNullByte(checksumtype);
  catfnumfields = 24 + catfextrafields;
  if(checksumtype=="none" or checksumtype==""):
   catfileheadercshex = format(0, 'x').lower();
   catfilecontentcshex = format(0, 'x').lower();
  elif(checksumtype=="crc16" or checksumtype=="crc16_ansi" or checksumtype=="crc16_ibm"):
   catfileheadercshex = format(crc16("".encode('UTF-8')) & 0xffff, '04x').lower();
   catfilecontentcshex = format(crc16(fcontents) & 0xffff, '04x').lower();
  elif(checksumtype=="crc16_ccitt"):
   catfileheadercshex = format(crc16_ccitt("".encode('UTF-8')) & 0xffff, '04x').lower();
   catfilecontentcshex = format(crc16_ccitt(fcontents) & 0xffff, '04x').lower();
  elif(checksumtype=="adler32"):
   catfileheadercshex = format(zlib.adler32("".encode('UTF-8')) & 0xffffffff, '08x').lower();
   catfilecontentcshex = format(zlib.adler32(fcontents) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc32"):
   catfileheadercshex = format(crc32("".encode('UTF-8')) & 0xffffffff, '08x').lower();
   catfilecontentcshex = format(crc32(fcontents) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc64_ecma"):
   catfileheadercshex = format(crc64_ecma("".encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
   catfilecontentcshex = format(crc64_ecma(fcontents) & 0xffffffffffffffff, '016x').lower();
  elif(checksumtype=="crc64" or checksumtype=="crc64_iso"):
   catfileheadercshex = format(crc64_iso("".encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
   catfilecontentcshex = format(crc64_iso(fcontents) & 0xffffffffffffffff, '016x').lower();
  elif(CheckSumSupportAlt(checksumtype, hashlib_guaranteed)):
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update("".encode('UTF-8'));
   catfileheadercshex = checksumoutstr.hexdigest().lower();
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(fcontents);
   catfilecontentcshex = checksumoutstr.hexdigest().lower();
  catfhstart = fheadtell;
  fheadtell += len(catfileoutstr);
  catfhend = fheadtell - 1;
  catfcontentstart = fheadtell;
  tmpfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex]);
  catheaersize = format(int(len(tmpfileoutstr) - 1), 'x').lower()
  catfileoutstr = AppendNullByte(catheaersize) + catfileoutstr;
  if(checksumtype=="none" or checksumtype==""):
   catfileheadercshex = format(0, 'x').lower();
  elif(checksumtype=="crc16" or checksumtype=="crc16_ansi" or checksumtype=="crc16_ibm"):
   catfileheadercshex = format(crc16(catfileoutstr.encode('UTF-8')) & 0xffff, '04x').lower();
  elif(checksumtype=="crc16_ccitt"):
   catfileheadercshex = format(crc16_ccitt(catfileoutstr.encode('UTF-8')) & 0xffff, '04x').lower();
  elif(checksumtype=="adler32"):
   catfileheadercshex = format(zlib.adler32(catfileoutstr.encode('UTF-8')) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc32"):
   catfileheadercshex = format(crc32(catfileoutstr.encode('UTF-8')) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc64_ecma"):
   catfileheadercshex = format(crc64_ecma(catfileoutstr.encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
  elif(checksumtype=="crc64" or checksumtype=="crc64_iso"):
   catfileheadercshex = format(crc64_iso(catfileoutstr.encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
  elif(CheckSumSupportAlt(checksumtype, hashlib_guaranteed)):
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(catfileoutstr.encode('UTF-8'));
   catfileheadercshex = checksumoutstr.hexdigest().lower();
  catfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex]);
  catfileoutstrecd = catfileoutstr.encode('UTF-8');
  nullstrecd = __file_format_delimiter__.encode('UTF-8');
  fheadtell += len(catfileoutstr) + 1;
  catfcontentend = fheadtell - 1;
  catfileout = catfileoutstrecd + fcontents + nullstrecd;
  pyhascontents = False;
  if(int(fsize)>0 and not listonly):
   pyhascontents = True;
  if(int(fsize)>0 and listonly):
   fcontents = "";
   pyhascontents = False;
  catlist['ffilelist'].update({fileidnum: {'fformat': __file_format_name__, 'fversion': catversion, 'fid': fileidnum, 'fidalt': fileidnum, 'fheadersize': int(catheaersize, 16), 'fhstart': catfhstart, 'fhend': catfhend, 'ftype': ftype, 'fname': fname, 'fbasedir': fbasedir, 'flinkname': flinkname, 'fsize': fsize, 'fatime': fatime, 'fmtime': fmtime, 'fctime': fctime, 'fbtime': fbtime, 'fmode': fmode, 'fchmode': fchmode, 'ftypemod': ftypemod, 'fuid': fuid, 'funame': funame, 'fgid': fgid, 'fgname': fgname, 'finode': finode, 'flinkcount': flinkcount, 'fminor': fdev_minor, 'fmajor': fdev_major, 'frminor': frdev_minor, 'frmajor': frdev_major, 'fchecksumtype': checksumtype, 'fnumfields': catfnumfields, 'fextrafields': catfextrafields, 'fextrafieldsize': extrasizelen, 'fextralist': extrafieldslist, 'fheaderchecksum': int(catfileheadercshex, 16), 'fcontentchecksum': int(catfilecontentcshex, 16), 'fhascontents': pyhascontents, 'fcontentstart': catfcontentstart, 'fcontentend': catfcontentend, 'fcontents': fcontents} });
  fileidnum = fileidnum + 1;
 return catlist;

def ZipFileToArrayAlt(infiles, listonly=False, checksumtype="crc32", extradata=[], verbose=False):
 catver = __cat_header_ver__;
 fileheaderver = str(int(catver.replace(".", "")));
 fileheader = AppendNullByte(__file_format_name__ + fileheaderver);
 catversion = fileheaderver;
 advancedlist = True;
 curinode = 0;
 curfid = 0;
 inodelist = [];
 inodetofile = {};
 filetoinode = {};
 inodetocatinode = {};
 fileidnum = 0;
 if(not os.path.exists(infiles) or not os.path.isfile(infiles)):
  return False;
 if(not zipfile.is_zipfile(infiles)):
  return False;
 zipfp = zipfile.ZipFile(infiles, "r", allowZip64=True);
 ziptest = zipfp.testzip();
 if(ziptest):
  VerbosePrintOut("Bad file found: " + str(bad_file));
 fnumfiles = int(len(zipfp.infolist()));
 catver = __cat_header_ver__;
 fileheaderver = str(int(catver.replace(".", "")));
 fileheader = AppendNullByte(__file_format_name__ + fileheaderver);
 fnumfileshex = format(int(fnumfiles), 'x').lower();
 fileheader = fileheader + AppendNullBytes([fnumfileshex, checksumtype]);
 if(checksumtype=="none" or checksumtype==""):
  catfileheadercshex = format(0, 'x').lower();
 elif(checksumtype=="crc16" or checksumtype=="crc16_ansi" or checksumtype=="crc16_ibm"):
  catfileheadercshex = format(crc16(fileheader.encode('UTF-8')) & 0xffff, '04x').lower();
 elif(checksumtype=="crc16_ccitt"):
  catfileheadercshex = format(crc16_ccitt(fileheader.encode('UTF-8')) & 0xffff, '04x').lower();
 elif(checksumtype=="adler32"):
  catfileheadercshex = format(zlib.adler32(fileheader.encode('UTF-8')) & 0xffffffff, '08x').lower();
 elif(checksumtype=="crc32"):
  catfileheadercshex = format(crc32(fileheader.encode('UTF-8')) & 0xffffffff, '08x').lower();
 elif(checksumtype=="crc64_ecma"):
  catfileheadercshex = format(crc64_ecma(fileheader.encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
 elif(checksumtype=="crc64" or checksumtype=="crc64_iso"):
  catfileheadercshex = format(crc64_iso(fileheader.encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
 elif(CheckSumSupportAlt(checksumtype, hashlib_guaranteed)):
  checksumoutstr = hashlib.new(checksumtype);
  checksumoutstr.update(fileheader.encode('UTF-8'));
  catfileheadercshex = checksumoutstr.hexdigest().lower();
 fileheader = fileheader + AppendNullByte(catfileheadercshex);
 fheadtell = len(fileheader);
 catlist = {'fnumfiles': fnumfiles, 'fformat': __file_format_name__, 'fversion': catversion, 'fchecksumtype': checksumtype, 'fheaderchecksum': catfileheadercshex, 'ffilelist': {}};
 for member in zipfp.infolist():
  if(re.findall("^[.|/]", member.filename)):
   fname = member.filename;
  else:
   fname = "./"+member.filename;
  zipinfo = zipfp.getinfo(member.filename);
  if(verbose):
   VerbosePrintOut(fname);
  if(not member.is_dir()):
   fpremode = stat.S_IFREG + 438;
  if(member.is_dir()):
   fpremode = stat.S_IFDIR + 511;
  flinkcount = 0;
  ftype = 0;
  if(not member.is_dir()):
   ftype = 0;
  if(member.is_dir()):
   ftype = 5;
  flinkname = "";
  fbasedir = os.path.dirname(fname);
  fcurfid = curfid;
  fcurinode = 0;
  finode = fcurinode;
  curfid = curfid + 1;
  fdev_minor = 0;
  fdev_major = 0;
  frdev_minor = 0;
  frdev_major = 0;
  if(ftype==5):
   fsize = "0";
  if(ftype==0):
   fsize = member.file_size;
  fatime = time.mktime(member.date_time + (0, 0, -1));
  fmtime = time.mktime(member.date_time + (0, 0, -1));
  fctime = time.mktime(member.date_time + (0, 0, -1));
  fbtime = time.mktime(member.date_time + (0, 0, -1));
  if(not member.is_dir()):
   fmode = stat.S_IFREG + 438;
   fchmode = stat.S_IMODE(int(stat.S_IFREG + 438));
   ftypemod = stat.S_IFMT(int(stat.S_IFREG + 438));
  if(member.is_dir()):
   fmode = stat.S_IFDIR + 511;
   fchmode = stat.S_IMODE(int(stat.S_IFDIR + 511));
   ftypemod = stat.S_IFMT(int(stat.S_IFDIR + 511));
  try:
   fuid = os.getuid();
  except AttributeError:
   fuid = 0;
  except KeyError:
   fuid = 0;
  try:
   fgid = os.getgid();
  except AttributeError:
   fgid = 0;
  except KeyError:
   fgid = 0;
  try:
   import pwd;
   try:
    userinfo = pwd.getpwuid(os.getuid());
    funame = userinfo.pw_name;
   except KeyError:
    funame = "";
   except AttributeError:
    funame = "";
  except ImportError:
   funame = "";
  fgname = "";
  try:
   import grp;
   try:
    groupinfo = grp.getgrgid(os.getgid());
    fgname = groupinfo.gr_name;
   except KeyError:
    fgname = "";
   except AttributeError:
    fgname = "";
  except ImportError:
   fgname = "";
  fcontents = "".encode('UTF-8');
  if(ftype==0):
   fcontents = zipfp.read(member.filename);
  ftypehex = format(ftype, 'x').lower();
  extrafields = len(extradata);
  extrafieldslist = extradata;
  catfextrafields = extrafields;
  extrasizestr = AppendNullByte(extrafields);
  if(len(extradata)>0):
   extrasizestr = extrasizestr + AppendNullBytes(extradata);
  extrasizelen = len(extrasizestr);
  extrasizelenhex = format(extrasizelen, 'x').lower();
  catfileoutstr = AppendNullBytes([ftypehex, fname, flinkname, format(int(fsize), 'x').lower(), format(int(fatime), 'x').lower(), format(int(fmtime), 'x').lower(), format(int(fctime), 'x').lower(), format(int(fbtime), 'x').lower(), format(int(fmode), 'x').lower(), format(int(fuid), 'x').lower(), funame, format(int(fgid), 'x').lower(), fgname, format(int(fcurfid), 'x').lower(), format(int(fcurinode), 'x').lower(), format(int(flinkcount), 'x').lower(), format(int(fdev_minor), 'x').lower(), format(int(fdev_major), 'x').lower(), format(int(frdev_minor), 'x').lower(), format(int(frdev_major), 'x').lower(), extrasizelenhex, format(catfextrafields, 'x').lower()]);
  if(len(extradata)>0):
   catfileoutstr = catfileoutstr + AppendNullBytes(extradata);
  catfileoutstr = catfileoutstr + AppendNullByte(checksumtype);
  catfnumfields = 24 + catfextrafields;
  if(checksumtype=="none" or checksumtype==""):
   catfileheadercshex = format(0, 'x').lower();
   catfilecontentcshex = format(0, 'x').lower();
  elif(checksumtype=="crc16" or checksumtype=="crc16_ansi" or checksumtype=="crc16_ibm"):
   catfileheadercshex = format(crc16("".encode('UTF-8')) & 0xffff, '04x').lower();
   catfilecontentcshex = format(crc16(fcontents) & 0xffff, '04x').lower();
  elif(checksumtype=="crc16_ccitt"):
   catfileheadercshex = format(crc16_ccitt("".encode('UTF-8')) & 0xffff, '04x').lower();
   catfilecontentcshex = format(crc16_ccitt(fcontents) & 0xffff, '04x').lower();
  elif(checksumtype=="adler32"):
   catfileheadercshex = format(zlib.adler32("".encode('UTF-8')) & 0xffffffff, '08x').lower();
   catfilecontentcshex = format(zlib.adler32(fcontents) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc32"):
   catfileheadercshex = format(crc32("".encode('UTF-8')) & 0xffffffff, '08x').lower();
   catfilecontentcshex = format(crc32(fcontents) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc64_ecma"):
   catfileheadercshex = format(crc64_ecma("".encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
   catfilecontentcshex = format(crc64_ecma(fcontents) & 0xffffffffffffffff, '016x').lower();
  elif(checksumtype=="crc64" or checksumtype=="crc64_iso"):
   catfileheadercshex = format(crc64_iso("".encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
   catfilecontentcshex = format(crc64_iso(fcontents) & 0xffffffffffffffff, '016x').lower();
  elif(CheckSumSupportAlt(checksumtype, hashlib_guaranteed)):
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update("".encode('UTF-8'));
   catfileheadercshex = checksumoutstr.hexdigest().lower();
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(fcontents);
   catfilecontentcshex = checksumoutstr.hexdigest().lower();
  catfhstart = fheadtell;
  fheadtell += len(catfileoutstr);
  catfhend = fheadtell - 1;
  catfcontentstart = fheadtell;
  tmpfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex]);
  catheaersize = format(int(len(tmpfileoutstr) - 1), 'x').lower()
  catfileoutstr = AppendNullByte(catheaersize) + catfileoutstr;
  if(checksumtype=="none" or checksumtype==""):
   catfileheadercshex = format(0, 'x').lower();
  elif(checksumtype=="crc16" or checksumtype=="crc16_ansi" or checksumtype=="crc16_ibm"):
   catfileheadercshex = format(crc16(catfileoutstr.encode('UTF-8')) & 0xffff, '04x').lower();
  elif(checksumtype=="crc16_ccitt"):
   catfileheadercshex = format(crc16_ccitt(catfileoutstr.encode('UTF-8')) & 0xffff, '04x').lower();
  elif(checksumtype=="adler32"):
   catfileheadercshex = format(zlib.adler32(catfileoutstr.encode('UTF-8')) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc32"):
   catfileheadercshex = format(crc32(catfileoutstr.encode('UTF-8')) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc64_ecma"):
   catfileheadercshex = format(crc64_ecma(catfileoutstr.encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
  elif(checksumtype=="crc64" or checksumtype=="crc64_iso"):
   catfileheadercshex = format(crc64_iso(catfileoutstr.encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
  elif(CheckSumSupportAlt(checksumtype, hashlib_guaranteed)):
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(catfileoutstr.encode('UTF-8'));
   catfileheadercshex = checksumoutstr.hexdigest().lower();
  catfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex]);
  catfileoutstrecd = catfileoutstr.encode('UTF-8');
  nullstrecd = __file_format_delimiter__.encode('UTF-8');
  fheadtell += len(catfileoutstr) + 1;
  catfcontentend = fheadtell - 1;
  catfileout = catfileoutstrecd + fcontents + nullstrecd;
  pyhascontents = False;
  if(int(fsize)>0 and not listonly):
   pyhascontents = True;
  if(int(fsize)>0 and listonly):
   fcontents = "";
   pyhascontents = False;
  catlist['ffilelist'].update({fileidnum: {'fformat': __file_format_name__, 'fversion': catversion, 'fid': fileidnum, 'fidalt': fileidnum, 'fheadersize': int(catheaersize, 16), 'fhstart': catfhstart, 'fhend': catfhend, 'ftype': ftype, 'fname': fname, 'fbasedir': fbasedir, 'flinkname': flinkname, 'fsize': fsize, 'fatime': fatime, 'fmtime': fmtime, 'fctime': fctime, 'fbtime': fbtime, 'fmode': fmode, 'fchmode': fchmode, 'ftypemod': ftypemod, 'fuid': fuid, 'funame': funame, 'fgid': fgid, 'fgname': fgname, 'finode': finode, 'flinkcount': flinkcount, 'fminor': fdev_minor, 'fmajor': fdev_major, 'frminor': frdev_minor, 'frmajor': frdev_major, 'fchecksumtype': checksumtype, 'fnumfields': catfnumfields, 'fextrafields': catfextrafields, 'fextrafieldsize': extrasizelen, 'fextralist': extrafieldslist, 'fheaderchecksum': int(catfileheadercshex, 16), 'fcontentchecksum': int(catfilecontentcshex, 16), 'fhascontents': pyhascontents, 'fcontentstart': catfcontentstart, 'fcontentend': catfcontentend, 'fcontents': fcontents} });
  fileidnum = fileidnum + 1;
 return catlist;

def ListDirToArray(infiles, dirlistfromtxt=False, compression="auto", compressionlevel=None, followlink=False, seekstart=0, seekend=0, listonly=False, skipchecksum=False, checksumtype="crc32", extradata=[], verbose=False, returnfp=False):
 outarray = BytesIO();
 packcat = PackCatFile(infiles, outarray, dirlistfromtxt, compression, compressionlevel, followlink, checksumtype, extradata, verbose, True);
 listcatfiles = CatFileToArray(outarray, seekstart, seekend, listonly, skipchecksum, returnfp);
 return listcatfiles;

def CatFileToArrayIndex(infile, seekstart=0, seekend=0, listonly=False, skipchecksum=False, returnfp=False):
 if(isinstance(infile, dict)):
  listcatfiles = infile;
 else:
  if(infile!="-" and not hasattr(infile, "read") and not hasattr(infile, "write")):
   infile = RemoveWindowsPath(infile);
  listcatfiles = CatFileToArray(infile, seekstart, seekend, listonly, skipchecksum, returnfp);
 if(not listcatfiles):
  return False;
 catarray = {'list': listcatfiles, 'filetoid': {}, 'idtofile': {}, 'filetypes': {'directories': {'filetoid': {}, 'idtofile': {}}, 'files': {'filetoid': {}, 'idtofile': {}}, 'links': {'filetoid': {}, 'idtofile': {}}, 'symlinks': {'filetoid': {}, 'idtofile': {}}, 'hardlinks': {'filetoid': {}, 'idtofile': {}}, 'character': {'filetoid': {}, 'idtofile': {}}, 'block': {'filetoid': {}, 'idtofile': {}}, 'fifo': {'filetoid': {}, 'idtofile': {}}, 'devices': {'filetoid': {}, 'idtofile': {}}}};
 if(returnfp):
  catarray.update({'catfp': listcatfiles['catfp']});
 lenlist = len(listcatfiles['ffilelist']);
 if(seekstart>0):
  lcfi = seekstart;
 else:
  lcfi = 0;
 if(seekend>0 and seekend<listcatfiles['fnumfiles']):
  lcfx = seekend;
 else:
  if(lenlist>listcatfiles['fnumfiles'] or lenlist<listcatfiles['fnumfiles']):
   lcfx = listcatfiles['fnumfiles'];
  else:
   lcfx = int(listcatfiles['fnumfiles']);
 while(lcfi < lcfx):
  filetoidarray = {listcatfiles['ffilelist'][lcfi]['fname']: listcatfiles['ffilelist'][lcfi]['fid']};
  idtofilearray = {listcatfiles['ffilelist'][lcfi]['fid']: listcatfiles['ffilelist'][lcfi]['fname']};
  catarray['filetoid'].update(filetoidarray);
  catarray['idtofile'].update(idtofilearray);
  if(listcatfiles['ffilelist'][lcfi]['ftype']==0 or listcatfiles['ffilelist'][lcfi]['ftype']==7):
   catarray['filetypes']['files']['filetoid'].update(filetoidarray);
   catarray['filetypes']['files']['idtofile'].update(idtofilearray);
  if(listcatfiles['ffilelist'][lcfi]['ftype']==1):
   catarray['filetypes']['hardlinks']['filetoid'].update(filetoidarray);
   catarray['filetypes']['hardlinks']['idtofile'].update(idtofilearray);
   catarray['filetypes']['links']['filetoid'].update(filetoidarray);
   catarray['filetypes']['links']['idtofile'].update(idtofilearray);
  if(listcatfiles['ffilelist'][lcfi]['ftype']==2):
   catarray['filetypes']['symlinks']['filetoid'].update(filetoidarray);
   catarray['filetypes']['symlinks']['idtofile'].update(idtofilearray);
   catarray['filetypes']['links']['filetoid'].update(filetoidarray);
   catarray['filetypes']['links']['idtofile'].update(idtofilearray);
  if(listcatfiles['ffilelist'][lcfi]['ftype']==3):
   catarray['filetypes']['character']['filetoid'].update(filetoidarray);
   catarray['filetypes']['character']['idtofile'].update(idtofilearray);
   catarray['filetypes']['devices']['filetoid'].update(filetoidarray);
   catarray['filetypes']['devices']['idtofile'].update(idtofilearray);
  if(listcatfiles['ffilelist'][lcfi]['ftype']==4):
   catarray['filetypes']['block']['filetoid'].update(filetoidarray);
   catarray['filetypes']['block']['idtofile'].update(idtofilearray);
   catarray['filetypes']['devices']['filetoid'].update(filetoidarray);
   catarray['filetypes']['devices']['idtofile'].update(idtofilearray);
  if(listcatfiles['ffilelist'][lcfi]['ftype']==5):
   catarray['filetypes']['directories']['filetoid'].update(filetoidarray);
   catarray['filetypes']['directories']['idtofile'].update(idtofilearray);
  if(listcatfiles['ffilelist'][lcfi]['ftype']==6):
   catarray['filetypes']['symlinks']['filetoid'].update(filetoidarray);
   catarray['filetypes']['symlinks']['idtofile'].update(idtofilearray);
   catarray['filetypes']['devices']['filetoid'].update(filetoidarray);
   catarray['filetypes']['devices']['idtofile'].update(idtofilearray);
  lcfi = lcfi + 1;
 return catarray;

def ListDirToArrayIndexAlt(infiles, dirlistfromtxt=False, followlink=False, seekstart=0, seekend=0, listonly=False, checksumtype="crc32", extradata=[], verbose=False):
 listcatfiles = ListDirToArrayAlt(infiles, dirlistfromtxt, followlink, listonly, checksumtype, extradata, verbose);
 print(listcatfiles);
 if(not listcatfiles):
  return False;
 catarray = {'list': listcatfiles, 'filetoid': {}, 'idtofile': {}, 'filetypes': {'directories': {'filetoid': {}, 'idtofile': {}}, 'files': {'filetoid': {}, 'idtofile': {}}, 'links': {'filetoid': {}, 'idtofile': {}}, 'symlinks': {'filetoid': {}, 'idtofile': {}}, 'hardlinks': {'filetoid': {}, 'idtofile': {}}, 'character': {'filetoid': {}, 'idtofile': {}}, 'block': {'filetoid': {}, 'idtofile': {}}, 'fifo': {'filetoid': {}, 'idtofile': {}}, 'devices': {'filetoid': {}, 'idtofile': {}}}};
 lenlist = len(listcatfiles['ffilelist']);
 if(seekstart>0):
  lcfi = seekstart;
 else:
  lcfi = 0;
 if(seekend>0 and seekend<listcatfiles['fnumfiles']):
  lcfx = seekend;
 else:
  if(lenlist>listcatfiles['fnumfiles'] or lenlist<listcatfiles['fnumfiles']):
   lcfx = listcatfiles['fnumfiles'];
  else:
   lcfx = int(listcatfiles['fnumfiles']);
 while(lcfi < lcfx):
  filetoidarray = {listcatfiles['ffilelist'][lcfi]['fname']: listcatfiles['ffilelist'][lcfi]['fid']};
  idtofilearray = {listcatfiles['ffilelist'][lcfi]['fid']: listcatfiles['ffilelist'][lcfi]['fname']};
  catarray['filetoid'].update(filetoidarray);
  catarray['idtofile'].update(idtofilearray);
  if(listcatfiles['ffilelist'][lcfi]['ftype']==0 or listcatfiles['ffilelist'][lcfi]['ftype']==7):
   catarray['filetypes']['files']['filetoid'].update(filetoidarray);
   catarray['filetypes']['files']['idtofile'].update(idtofilearray);
  if(listcatfiles['ffilelist'][lcfi]['ftype']==1):
   catarray['filetypes']['hardlinks']['filetoid'].update(filetoidarray);
   catarray['filetypes']['hardlinks']['idtofile'].update(idtofilearray);
   catarray['filetypes']['links']['filetoid'].update(filetoidarray);
   catarray['filetypes']['links']['idtofile'].update(idtofilearray);
  if(listcatfiles['ffilelist'][lcfi]['ftype']==2):
   catarray['filetypes']['symlinks']['filetoid'].update(filetoidarray);
   catarray['filetypes']['symlinks']['idtofile'].update(idtofilearray);
   catarray['filetypes']['links']['filetoid'].update(filetoidarray);
   catarray['filetypes']['links']['idtofile'].update(idtofilearray);
  if(listcatfiles['ffilelist'][lcfi]['ftype']==3):
   catarray['filetypes']['character']['filetoid'].update(filetoidarray);
   catarray['filetypes']['character']['idtofile'].update(idtofilearray);
   catarray['filetypes']['devices']['filetoid'].update(filetoidarray);
   catarray['filetypes']['devices']['idtofile'].update(idtofilearray);
  if(listcatfiles['ffilelist'][lcfi]['ftype']==4):
   catarray['filetypes']['block']['filetoid'].update(filetoidarray);
   catarray['filetypes']['block']['idtofile'].update(idtofilearray);
   catarray['filetypes']['devices']['filetoid'].update(filetoidarray);
   catarray['filetypes']['devices']['idtofile'].update(idtofilearray);
  if(listcatfiles['ffilelist'][lcfi]['ftype']==5):
   catarray['filetypes']['directories']['filetoid'].update(filetoidarray);
   catarray['filetypes']['directories']['idtofile'].update(idtofilearray);
  if(listcatfiles['ffilelist'][lcfi]['ftype']==6):
   catarray['filetypes']['symlinks']['filetoid'].update(filetoidarray);
   catarray['filetypes']['symlinks']['idtofile'].update(idtofilearray);
   catarray['filetypes']['devices']['filetoid'].update(filetoidarray);
   catarray['filetypes']['devices']['idtofile'].update(idtofilearray);
  lcfi = lcfi + 1;
 return catarray;

def TarFileToArrayIndexAlt(infiles, seekstart=0, seekend=0, listonly=False, checksumtype="crc32", extradata=[], verbose=False):
 listcatfiles = TarFileToArrayAlt(infiles, listonly, checksumtype, extradata, verbose);
 print(listcatfiles);
 if(not listcatfiles):
  return False;
 catarray = {'list': listcatfiles, 'filetoid': {}, 'idtofile': {}, 'filetypes': {'directories': {'filetoid': {}, 'idtofile': {}}, 'files': {'filetoid': {}, 'idtofile': {}}, 'links': {'filetoid': {}, 'idtofile': {}}, 'symlinks': {'filetoid': {}, 'idtofile': {}}, 'hardlinks': {'filetoid': {}, 'idtofile': {}}, 'character': {'filetoid': {}, 'idtofile': {}}, 'block': {'filetoid': {}, 'idtofile': {}}, 'fifo': {'filetoid': {}, 'idtofile': {}}, 'devices': {'filetoid': {}, 'idtofile': {}}}};
 lenlist = len(listcatfiles['ffilelist']);
 if(seekstart>0):
  lcfi = seekstart;
 else:
  lcfi = 0;
 if(seekend>0 and seekend<listcatfiles['fnumfiles']):
  lcfx = seekend;
 else:
  if(lenlist>listcatfiles['fnumfiles'] or lenlist<listcatfiles['fnumfiles']):
   lcfx = listcatfiles['fnumfiles'];
  else:
   lcfx = int(listcatfiles['fnumfiles']);
 while(lcfi < lcfx):
  filetoidarray = {listcatfiles['ffilelist'][lcfi]['fname']: listcatfiles['ffilelist'][lcfi]['fid']};
  idtofilearray = {listcatfiles['ffilelist'][lcfi]['fid']: listcatfiles['ffilelist'][lcfi]['fname']};
  catarray['filetoid'].update(filetoidarray);
  catarray['idtofile'].update(idtofilearray);
  if(listcatfiles['ffilelist'][lcfi]['ftype']==0 or listcatfiles['ffilelist'][lcfi]['ftype']==7):
   catarray['filetypes']['files']['filetoid'].update(filetoidarray);
   catarray['filetypes']['files']['idtofile'].update(idtofilearray);
  if(listcatfiles['ffilelist'][lcfi]['ftype']==1):
   catarray['filetypes']['hardlinks']['filetoid'].update(filetoidarray);
   catarray['filetypes']['hardlinks']['idtofile'].update(idtofilearray);
   catarray['filetypes']['links']['filetoid'].update(filetoidarray);
   catarray['filetypes']['links']['idtofile'].update(idtofilearray);
  if(listcatfiles['ffilelist'][lcfi]['ftype']==2):
   catarray['filetypes']['symlinks']['filetoid'].update(filetoidarray);
   catarray['filetypes']['symlinks']['idtofile'].update(idtofilearray);
   catarray['filetypes']['links']['filetoid'].update(filetoidarray);
   catarray['filetypes']['links']['idtofile'].update(idtofilearray);
  if(listcatfiles['ffilelist'][lcfi]['ftype']==3):
   catarray['filetypes']['character']['filetoid'].update(filetoidarray);
   catarray['filetypes']['character']['idtofile'].update(idtofilearray);
   catarray['filetypes']['devices']['filetoid'].update(filetoidarray);
   catarray['filetypes']['devices']['idtofile'].update(idtofilearray);
  if(listcatfiles['ffilelist'][lcfi]['ftype']==4):
   catarray['filetypes']['block']['filetoid'].update(filetoidarray);
   catarray['filetypes']['block']['idtofile'].update(idtofilearray);
   catarray['filetypes']['devices']['filetoid'].update(filetoidarray);
   catarray['filetypes']['devices']['idtofile'].update(idtofilearray);
  if(listcatfiles['ffilelist'][lcfi]['ftype']==5):
   catarray['filetypes']['directories']['filetoid'].update(filetoidarray);
   catarray['filetypes']['directories']['idtofile'].update(idtofilearray);
  if(listcatfiles['ffilelist'][lcfi]['ftype']==6):
   catarray['filetypes']['symlinks']['filetoid'].update(filetoidarray);
   catarray['filetypes']['symlinks']['idtofile'].update(idtofilearray);
   catarray['filetypes']['devices']['filetoid'].update(filetoidarray);
   catarray['filetypes']['devices']['idtofile'].update(idtofilearray);
  lcfi = lcfi + 1;
 return catarray;

def ZipFileToArrayIndexAlt(infiles, seekstart=0, seekend=0, listonly=False, checksumtype="crc32", extradata=[], verbose=False):
 listcatfiles = ZipFileToArrayAlt(infiles, listonly, checksumtype, extradata, verbose);
 print(listcatfiles);
 if(not listcatfiles):
  return False;
 catarray = {'list': listcatfiles, 'filetoid': {}, 'idtofile': {}, 'filetypes': {'directories': {'filetoid': {}, 'idtofile': {}}, 'files': {'filetoid': {}, 'idtofile': {}}, 'links': {'filetoid': {}, 'idtofile': {}}, 'symlinks': {'filetoid': {}, 'idtofile': {}}, 'hardlinks': {'filetoid': {}, 'idtofile': {}}, 'character': {'filetoid': {}, 'idtofile': {}}, 'block': {'filetoid': {}, 'idtofile': {}}, 'fifo': {'filetoid': {}, 'idtofile': {}}, 'devices': {'filetoid': {}, 'idtofile': {}}}};
 lenlist = len(listcatfiles['ffilelist']);
 if(seekstart>0):
  lcfi = seekstart;
 else:
  lcfi = 0;
 if(seekend>0 and seekend<listcatfiles['fnumfiles']):
  lcfx = seekend;
 else:
  if(lenlist>listcatfiles['fnumfiles'] or lenlist<listcatfiles['fnumfiles']):
   lcfx = listcatfiles['fnumfiles'];
  else:
   lcfx = int(listcatfiles['fnumfiles']);
 while(lcfi < lcfx):
  filetoidarray = {listcatfiles['ffilelist'][lcfi]['fname']: listcatfiles['ffilelist'][lcfi]['fid']};
  idtofilearray = {listcatfiles['ffilelist'][lcfi]['fid']: listcatfiles['ffilelist'][lcfi]['fname']};
  catarray['filetoid'].update(filetoidarray);
  catarray['idtofile'].update(idtofilearray);
  if(listcatfiles['ffilelist'][lcfi]['ftype']==0 or listcatfiles['ffilelist'][lcfi]['ftype']==7):
   catarray['filetypes']['files']['filetoid'].update(filetoidarray);
   catarray['filetypes']['files']['idtofile'].update(idtofilearray);
  if(listcatfiles['ffilelist'][lcfi]['ftype']==1):
   catarray['filetypes']['hardlinks']['filetoid'].update(filetoidarray);
   catarray['filetypes']['hardlinks']['idtofile'].update(idtofilearray);
   catarray['filetypes']['links']['filetoid'].update(filetoidarray);
   catarray['filetypes']['links']['idtofile'].update(idtofilearray);
  if(listcatfiles['ffilelist'][lcfi]['ftype']==2):
   catarray['filetypes']['symlinks']['filetoid'].update(filetoidarray);
   catarray['filetypes']['symlinks']['idtofile'].update(idtofilearray);
   catarray['filetypes']['links']['filetoid'].update(filetoidarray);
   catarray['filetypes']['links']['idtofile'].update(idtofilearray);
  if(listcatfiles['ffilelist'][lcfi]['ftype']==3):
   catarray['filetypes']['character']['filetoid'].update(filetoidarray);
   catarray['filetypes']['character']['idtofile'].update(idtofilearray);
   catarray['filetypes']['devices']['filetoid'].update(filetoidarray);
   catarray['filetypes']['devices']['idtofile'].update(idtofilearray);
  if(listcatfiles['ffilelist'][lcfi]['ftype']==4):
   catarray['filetypes']['block']['filetoid'].update(filetoidarray);
   catarray['filetypes']['block']['idtofile'].update(idtofilearray);
   catarray['filetypes']['devices']['filetoid'].update(filetoidarray);
   catarray['filetypes']['devices']['idtofile'].update(idtofilearray);
  if(listcatfiles['ffilelist'][lcfi]['ftype']==5):
   catarray['filetypes']['directories']['filetoid'].update(filetoidarray);
   catarray['filetypes']['directories']['idtofile'].update(idtofilearray);
  if(listcatfiles['ffilelist'][lcfi]['ftype']==6):
   catarray['filetypes']['symlinks']['filetoid'].update(filetoidarray);
   catarray['filetypes']['symlinks']['idtofile'].update(idtofilearray);
   catarray['filetypes']['devices']['filetoid'].update(filetoidarray);
   catarray['filetypes']['devices']['idtofile'].update(idtofilearray);
  lcfi = lcfi + 1;
 return catarray;

def CatStringToArrayIndex(catstr, seekstart=0, seekend=0, listonly=False, skipchecksum=False, returnfp=False):
 catfp = BytesIO(catstr);
 listcatfiles = CatFileToArrayIndex(catfp, seekstart, seekend, listonly, skipchecksum, returnfp);
 return listcatfiles;

def TarFileToArrayIndex(infile, seekstart=0, seekend=0, listonly=False, skipchecksum=False, returnfp=False):
 catfp = BytesIO();
 catfp = PackCatFileFromTarFile(infile, catfp, "auto", None, "crc32", False, True);
 listcatfiles = CatFileToArrayIndex(catfp, seekstart, seekend, listonly, skipchecksum, returnfp);
 return listcatfiles;

def ZipFileToArrayIndex(infile, seekstart=0, seekend=0, listonly=False, skipchecksum=False, returnfp=False):
 catfp = BytesIO();
 catfp = PackCatFileFromZipFile(infile, catfp, "auto", None, "crc32", False, True);
 listcatfiles = CatFileToArrayIndex(catfp, seekstart, seekend, listonly, skipchecksum, returnfp);
 return listcatfiles;

def ListDirToArrayIndex(infiles, dirlistfromtxt=False, compression="auto", compressionlevel=None, followlink=False, seekstart=0, seekend=0, listonly=False, skipchecksum=False, checksumtype="crc32", verbose=False, returnfp=False):
 outarray = BytesIO();
 packcat = PackCatFile(infiles, outarray, dirlistfromtxt, compression, compressionlevel, followlink, checksumtype, verbose, True);
 listcatfiles = CatFileToArrayIndex(outarray, seekstart, seekend, listonly, skipchecksum, returnfp)
 return listcatfiles;

def MakeCatFileJSONFromCatFileArray(inlistcatfiles, jsonindent=1, beautify=True, sortkeys=False, verbose=True, jsonverbose=True):
 if(beautify):
  jsonstring = json.dumps(inlistcatfiles, sort_keys=sortkeys, indent=jsonindent);
 else:
  jsonstring = json.dumps(inlistcatfiles, sort_keys=sortkeys, separators=(', ', ': '));
 if(verbose and jsonverbose):
  VerbosePrintOut(jsonstring);
 elif(verbose and not jsonverbose):
  VerbosePrintOut(MakeCatFileXMLFromCatFileArray(inlistcatfiles, verbose=False, jsonverbose=True));
 return jsonstring;

def MakeCatFileJSONFileFromCatFileArray(inlistcatfiles, outjsonfile=None, returnjson=False, jsonindent=1, beautify=True, sortkeys=False, verbose=True, jsonverbose=True):
 if(outjsonfile is None):
  return False;
 fbasename = os.path.splitext(outjsonfile)[0];
 fextname = os.path.splitext(outjsonfile)[1];
 jsonfp = CompressOpenFile(outjsonfile);
 jsonstring = MakeCatFileJSONFromCatFileArray(inlistcatfiles, jsonindent, beautify, sortkeys, verbose);
 try:
  jsonfp.write(jsonstring);
 except TypeError:
  jsonfp.write(jsonstring.encode("UTF-8"));
 jsonfp.close();
 if(returnjson):
  return jsonstring;
 if(not returnjson):
  return True;
 return True;

def MakeCatFileArrayFromCatFileJSON(injsonfile, jsonisfile=True, verbose=True, jsonverbose=True):
 if(jsonisfile and ((os.path.exists(injsonfile) and os.path.isfile(injsonfile)))):
  jsonfp = UncompressFile(injsonfile);
  listcatfiles = json.load(jsonfp);
  jsonfp.close();
 elif(not jsonisfile):
  chckcompression = CheckCompressionTypeFromString(injsonfile);
  if(not chckcompression):
   jsonfp = StringIO(injsonfile);
  else:
   try:
    injsonsfile = BytesIO(injsonfile);
   except TypeError:
    injsonsfile = BytesIO(injsonfile.encode("UTF-8"));
   jsonfp = UncompressFile(injsonsfile);
  listcatfiles = json.load(jsonfp);
  jsonfp.close();
 else:
  return False;
 if(verbose and jsonverbose):
  VerbosePrintOut(MakeCatFileJSONFromCatFileArray(listcatfiles, verbose=False, jsonverbose=True));
 elif(verbose and not jsonverbose):
  VerbosePrintOut(MakeCatFileXMLFromCatFileArray(listcatfiles, verbose=False, jsonverbose=True));
 return listcatfiles;

def MakeCatFilePickleFromCatFileArray(inlistcatfiles, protocol=pickledp, verbose=True, jsonverbose=True):
 if(protocol is None):
  picklestring = pickle.dumps(inlistcatfiles, fix_imports=True);
 else:
  picklestring = pickle.dumps(inlistcatfiles, protocol=protocol, fix_imports=True);
 if(verbose and jsonverbose):
  VerbosePrintOut(MakeCatFileJSONFromCatFileArray(inlistcatfiles, verbose=False, jsonverbose=True));
 elif(verbose and not jsonverbose):
  VerbosePrintOut(MakeCatFileXMLFromCatFileArray(inlistcatfiles, verbose=False, jsonverbose=True));
 return picklestring;

def MakeCatFilePickleFileFromCatFileArray(inlistcatfiles, outpicklefile=None, returnpickle=False, protocol=pickledp, verbose=True, jsonverbose=True):
 if(outpicklefile is None):
  return False;
 fbasename = os.path.splitext(outpicklefile)[0];
 fextname = os.path.splitext(outpicklefile)[1];
 picklefp = CompressOpenFile(outpicklefile);
 picklestring = MakeCatFilePickleFromCatFileArray(inlistcatfiles, protocol, verbose);
 try:
  picklefp.write(picklestring);
 except TypeError:
  picklefp.write(picklestring.encode("UTF-8"));
 picklefp.close();
 if(returnpickle):
  return picklestring;
 if(not returnpickle):
  return True;
 return True;

def MakeCatFileArrayFromCatFilePickle(inpicklefile, pickleisfile=True, verbose=True, jsonverbose=True):
 if(pickleisfile and ((os.path.exists(inpicklefile) and os.path.isfile(inpicklefile)))):
  picklefp = UncompressFile(inpicklefile);
  listcatfiles = pickle.load(picklefp, fix_imports=True);
  picklefp.close();
 elif(not pickleisfile):
  picklefp = BytesIO(inpicklefile.encode("UTF-8"));
  picklefp = UncompressFile(picklefp);
  listcatfiles = json.load(picklefp, fix_imports=True);
  picklefp.close();
 else:
  return False;
 if(verbose and jsonverbose):
  VerbosePrintOut(MakeCatFileJSONFromCatFileArray(listcatfiles, verbose=False, jsonverbose=True));
 elif(verbose and not jsonverbose):
  VerbosePrintOut(MakeCatFileXMLFromCatFileArray(listcatfiles, verbose=False, jsonverbose=True));
 return listcatfiles;

def MakeCatFileMarshalFromCatFileArray(inlistcatfiles, version=marshal.version, verbose=True, jsonverbose=True):
 marshalstring = marshal.dumps(inlistcatfiles, version);
 if(verbose and jsonverbose):
  VerbosePrintOut(MakeCatFileJSONFromCatFileArray(inlistcatfiles, verbose=False, jsonverbose=True));
 elif(verbose and not jsonverbose):
  VerbosePrintOut(MakeCatFileXMLFromCatFileArray(inlistcatfiles, verbose=False, jsonverbose=True));
 return marshalstring;

def MakeCatFileMarshalFileFromCatFileArray(inlistcatfiles, outmarshalfile=None, returnmarshal=False, version=marshal.version, verbose=True, jsonverbose=True):
 if(outmarshalfile is None):
  return False;
 fbasename = os.path.splitext(outmarshalfile)[0];
 fextname = os.path.splitext(outmarshalfile)[1];
 marshalfp = CompressOpenFile(outmarshalfile);
 marshalstring = MakeCatFileMarshalFromCatFileArray(inlistcatfiles, version, verbose);
 try:
  marshalfp.write(marshalstring);
 except TypeError:
  marshalfp.write(marshalstring.encode("UTF-8"));
 marshalfp.close();
 if(returnmarshal):
  return marshalstring;
 if(not returnmarshal):
  return True;
 return True;

def MakeCatFileArrayFromCatFileMarshal(inmarshalfile, marshalisfile=True, verbose=True, jsonverbose=True):
 if(marshalisfile and ((os.path.exists(inmarshalfile) and os.path.isfile(inmarshalfile)))):
  inmarshalfile = UncompressFileURL(inmarshalfile, geturls_headers, geturls_cj);
  listcatfiles = marshal.load(inmarshalfile);
  marshalfp = UncompressFile(inmarshalfile);
  listcatfiles = marshal.load(marshalfp);
  marshalfp.close();
 elif(not marshalisfile):
  marshalfp = BytesIO(inmarshalfile.encode("UTF-8"));
  marshalfp = UncompressFile(marshalfp);
  listcatfiles = json.load(marshalfp);
  marshalfp.close();
 else:
  return False;
 if(verbose and jsonverbose):
  VerbosePrintOut(MakeCatFileJSONFromCatFileArray(listcatfiles, verbose=False, jsonverbose=True));
 elif(verbose and not jsonverbose):
  VerbosePrintOut(MakeCatFileXMLFromCatFileArray(listcatfiles, verbose=False, jsonverbose=True));
 return listcatfiles;

def MakeCatFileShelveFromCatFileArray(inlistcatfiles, version=pickledp, verbose=True, jsonverbose=True):
 outshelvefile = BytesIO();
 with shelve.open(outshelvefile, protocol=version) as shelf_file:
  for key, value in inlistcatfiles.items():
   shelf_file[key] = value;
 outshelvefile.seek(0);
 shelvestring = outshelvefile.read();
 if(verbose and jsonverbose):
  VerbosePrintOut(MakeCatFileJSONFromCatFileArray(inlistcatfiles, verbose=False, jsonverbose=True));
 elif(verbose and not jsonverbose):
  VerbosePrintOut(MakeCatFileXMLFromCatFileArray(inlistcatfiles, verbose=False, jsonverbose=True));
 return shelvestring;

def MakeCatFileShelveFileFromCatFileArray(inlistcatfiles, outshelvefile=None, returnshelve=False, version=pickledp, verbose=True, jsonverbose=True):
 if(outshelvefile is None):
  return False;
 fbasename = os.path.splitext(outshelvefile)[0];
 fextname = os.path.splitext(outshelvefile)[1];
 with shelve.open(outshelvefile, protocol=version) as shelf_file:
  for key, value in inlistcatfiles.items():
   shelf_file[key] = value;
 if(returnshelve):
  shelvestring = MakeCatFileShelveFromCatFileArray(inlistcatfiles, version, False, False);
  return shelvestring;
 if(not returnshelve):
  return True;
 return True;

def MakeCatFileArrayFromCatFileShelve(inshelvefile, shelveisfile=True, version=pickledp, verbose=True, jsonverbose=True):
 if(shelveisfile):
  with shelve.open(inshelvefile, protocol=version) as shelf_file:
   listcatfiles = dict(shelf_file);
 else:
  try:
   inshelvefile = BytesIO(inshelvefile);
  except TypeError:
   inshelvefile = BytesIO(inshelvefile.encode("UTF-8"));
  with shelve.open(inshelvefile, protocol=version) as shelf_file:
   listcatfiles = dict(shelf_file);
 if(verbose and jsonverbose):
  VerbosePrintOut(MakeCatFileJSONFromCatFileArray(listcatfiles, verbose=False, jsonverbose=True));
 elif(verbose and not jsonverbose):
  VerbosePrintOut(MakeCatFileXMLFromCatFileArray(listcatfiles, verbose=False, jsonverbose=True));
 return listcatfiles;

def RePackCatFile(infile, outfile, compression="auto", compressionlevel=None, followlink=False, seekstart=0, seekend=0, checksumtype="crc32", skipchecksum=False, extradata=[], verbose=False, returnfp=False):
 compressionlist = ['auto', 'gzip', 'bzip2', 'zstd', 'lz4', 'lzo', 'lzop', 'lzma', 'xz'];
 outextlist = ['gz', 'cgz', 'bz2', 'cbz', 'zst', 'czst', 'lz4', 'lzop', 'clz4', 'lzo', 'clzo', 'lzma', 'xz', 'cxz'];
 outextlistwd = ['.gz', '.cgz', '.bz2', '.cbz', '.zst', '.czst', '.lz4', 'lzop', '.clz4', '.lzo', '.clzo', '.lzma', '.xz', '.cxz'];
 if(isinstance(infile, dict)):
  prelistcatfiles = CatFileToArrayIndex(infile, seekstart, seekend, False, skipchecksum, returnfp);
  listcatfiles = prelistcatfiles['list'];
 else:
  if(infile!="-" and not hasattr(infile, "read") and not hasattr(infile, "write")):
   infile = RemoveWindowsPath(infile);
  if(followlink):
   prelistcatfiles = CatFileToArrayIndex(infile, seekstart, seekend, False, skipchecksum, returnfp);
   listcatfiles = prelistcatfiles['list'];
  else:
   listcatfiles = CatFileToArray(infile, seekstart, seekend, False, skipchecksum, returnfp);
 if(outfile!="-" and not hasattr(infile, "read") and not hasattr(outfile, "write")):
  outfile = RemoveWindowsPath(outfile);
 checksumtype = checksumtype.lower();
 if(not CheckSumSupport(checksumtype, hashlib_guaranteed)):
  checksumtype="crc32";
 if(checksumtype=="none"):
  checksumtype = "";
 if(not compression or compression or compression=="catfile" or compression==__file_format_lower__):
  compression = None;
 if(compression not in compressionlist and compression is None):
  compression = "auto";
 if(verbose):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(outfile!="-" and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
  if(os.path.exists(outfile)):
   os.unlink(outfile);
 if(not listcatfiles):
  return False;
 if(outfile=="-"):
  verbose = False;
  catfp = BytesIO();
 elif(hasattr(outfile, "read") or hasattr(outfile, "write")):
  catfp = outfile;
 else:
  fbasename = os.path.splitext(outfile)[0];
  fextname = os.path.splitext(outfile)[1];
  if(fextname not in outextlistwd and (compression=="auto" or compression is None)):
   catfp = open(outfile, "wb");
  elif(((fextname==".gz" or fextname==".cgz") and compression=="auto") or compression=="gzip"):
   try:
    import gzip;
   except ImportError:
    return False;
   if(compressionlevel is None):
    compressionlevel = 9;
   else:
    compressionlevel = int(compressionlevel);
   catfp = gzip.GzipFile(outfile, "wb", compresslevel=compressionlevel);
  elif(((fextname==".bz2" or fextname==".cbz") and compression=="auto") or compression=="bzip2"):
   try:
    import bz2;
   except ImportError:
    return False;
   if(compressionlevel is None):
    compressionlevel = 9;
   else:
    compressionlevel = int(compressionlevel);
   catfp = bz2.BZ2File(outfile, "wb", compresslevel=compressionlevel);
  elif(((fextname==".zst" or fextname==".czst") and compression=="auto") or compression=="zstd"):
   try:
    import zstandard;
   except ImportError:
    return False;
   if(compressionlevel is None):
    compressionlevel = 10;
   else:
    compressionlevel = int(compressionlevel);
   catfp = zstandard.open(outfile, "wb", zstandard.ZstdCompressor(level=compressionlevel));
  elif(((fextname==".lz4" or fextname==".clz4") and compression=="auto") or compression=="lz4"):
   try:
    import lz4.frame;
   except ImportError:
    return False;
   if(compressionlevel is None):
    compressionlevel = 9;
   else:
    compressionlevel = int(compressionlevel);
   catfp = lz4.frame.open(outfile, "wb", compression_level=compressionlevel);
  elif(((fextname==".xz" or fextname==".cxz") and compression=="auto") or compression=="xz"):
   try:
    import lzma;
   except ImportError:
    return False;
   if(compressionlevel is None):
    compressionlevel = 9;
   else:
    compressionlevel = int(compressionlevel);
   catfp = lzma.open(outfile, "wb", format=lzma.FORMAT_XZ, preset=compressionlevel);
  elif((fextname==".lzma" and compression=="auto") or compression=="lzma"):
   try:
    import lzma;
   except ImportError:
    return False;
   catfp = lzma.open(outfile, "wb", format=lzma.FORMAT_ALONE, preset=9);
 catver = __cat_header_ver__;
 fileheaderver = str(int(catver.replace(".", "")));
 fileheader = AppendNullByte(__file_format_name__ + fileheaderver);
 catfp.write(fileheader.encode('UTF-8'));
 lenlist = len(listcatfiles['ffilelist']);
 fnumfiles = int(listcatfiles['fnumfiles']);
 if(lenlist>fnumfiles or lenlist<fnumfiles):
  fnumfiles = lenlist;
 fnumfileshex = format(int(fnumfiles), 'x').lower();
 fnumfilesa = AppendNullBytes([fnumfileshex, checksumtype]);
 if(checksumtype=="none" or checksumtype==""):
  catfileheadercshex = format(0, 'x').lower();
 elif(checksumtype=="crc16" or checksumtype=="crc16_ansi" or checksumtype=="crc16_ibm"):
  catfileheadercshex = format(crc16(str(fileheader + fnumfilesa).encode('UTF-8')) & 0xffff, '04x').lower();
 elif(checksumtype=="crc16_ccitt"):
  catfileheadercshex = format(crc16_ccitt(str(fileheader + fnumfilesa).encode('UTF-8')) & 0xffff, '04x').lower();
 elif(checksumtype=="adler32"):
  catfileheadercshex = format(zlib.adler32(str(fileheader + fnumfilesa).encode('UTF-8')) & 0xffffffff, '08x').lower();
 elif(checksumtype=="crc32"):
  catfileheadercshex = format(crc32(str(fileheader + fnumfilesa).encode('UTF-8')) & 0xffffffff, '08x').lower();
 elif(checksumtype=="crc64_ecma"):
  catfileheadercshex = format(crc64_ecma(str(fileheader + fnumfilesa).encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
 elif(checksumtype=="crc64" or checksumtype=="crc64_iso"):
  catfileheadercshex = format(crc64_iso(str(fileheader + fnumfilesa).encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
 elif(CheckSumSupportAlt(checksumtype, hashlib_guaranteed)):
  checksumoutstr = hashlib.new(checksumtype);
  checksumoutstr.update(str(fileheader + fnumfilesa).encode('UTF-8'));
  catfileheadercshex = checksumoutstr.hexdigest().lower();
 fnumfilesa = fnumfilesa + AppendNullByte(catfileheadercshex);
 catfp.write(fnumfilesa.encode('UTF-8'));
 if(seekstart>0):
  lcfi = seekstart;
 else:
  lcfi = 0;
 if(seekend>0 and seekend<listcatfiles['fnumfiles']):
  lcfx = seekend;
 else:
  lcfx = int(listcatfiles['fnumfiles']);
 curinode = 0;
 curfid = 0;
 inodelist = [];
 inodetofile = {};
 filetoinode = {};
 reallcfi = 0;
 while(lcfi < lcfx):
  catfhstart = catfp.tell();
  if(re.findall("^[.|/]", listcatfiles['ffilelist'][reallcfi]['fname'])):
   fname = listcatfiles['ffilelist'][reallcfi]['fname'];
  else:
   fname = "./"+listcatfiles['ffilelist'][reallcfi]['fname'];
  if(verbose):
   VerbosePrintOut(fname);
  fheadersize = format(int(listcatfiles['ffilelist'][reallcfi]['fheadersize']), 'x').lower();
  fsize = format(int(listcatfiles['ffilelist'][reallcfi]['fsize']), 'x').lower();
  flinkname = listcatfiles['ffilelist'][reallcfi]['flinkname'];
  fatime = format(int(listcatfiles['ffilelist'][reallcfi]['fatime']), 'x').lower();
  fmtime = format(int(listcatfiles['ffilelist'][reallcfi]['fmtime']), 'x').lower();
  fctime = format(int(listcatfiles['ffilelist'][reallcfi]['fctime']), 'x').lower();
  fbtime = format(int(listcatfiles['ffilelist'][reallcfi]['fbtime']), 'x').lower();
  fmode = format(int(listcatfiles['ffilelist'][reallcfi]['fmode']), 'x').lower();
  fchmode = format(int(listcatfiles['ffilelist'][reallcfi]['fchmode']), 'x').lower();
  fuid = format(int(listcatfiles['ffilelist'][reallcfi]['fuid']), 'x').lower();
  funame = listcatfiles['ffilelist'][reallcfi]['funame'];
  fgid = format(int(listcatfiles['ffilelist'][reallcfi]['fgid']), 'x').lower();
  fgname = listcatfiles['ffilelist'][reallcfi]['fgname'];
  finode = listcatfiles['ffilelist'][reallcfi]['finode'];
  flinkcount = listcatfiles['ffilelist'][reallcfi]['flinkcount'];
  fdev_minor = format(int(listcatfiles['ffilelist'][reallcfi]['fminor']), 'x').lower();
  fdev_major = format(int(listcatfiles['ffilelist'][reallcfi]['fmajor']), 'x').lower();
  frdev_minor = format(int(listcatfiles['ffilelist'][reallcfi]['frminor']), 'x').lower();
  frdev_major = format(int(listcatfiles['ffilelist'][reallcfi]['frmajor']), 'x').lower();
  if(len(listcatfiles['ffilelist'][reallcfi]['fextralist'])>listcatfiles['ffilelist'][reallcfi]['fextrafields'] and len(listcatfiles['ffilelist'][reallcfi]['fextralist'])>0):
   listcatfiles['ffilelist'][reallcfi]['fextrafields'] = len(listcatfiles['ffilelist'][reallcfi]['fextralist']);
  if(len(extradata) > 0):
   listcatfiles['ffilelist'][reallcfi]['fextrafields'] = len(extradata);
   listcatfiles['ffilelist'][reallcfi]['fextralist'] = extradata;
  extrafields = format(int(listcatfiles['ffilelist'][reallcfi]['fextrafields']), 'x').lower();
  extrasizestr = AppendNullByte(extrafields);
  if(len(extradata)>0):
   extrasizestr = extrasizestr + AppendNullBytes(extradata);
  extrasizelen = format(len(extrasizestr), 'x').lower();
  fcontents = listcatfiles['ffilelist'][reallcfi]['fcontents'];
  if(followlink):
   if(listcatfiles['ffilelist'][reallcfi]['ftype']==1 or listcatfiles['ffilelist'][reallcfi]['ftype']==2):
    getflinkpath = listcatfiles['ffilelist'][reallcfi]['flinkname'];
    flinkid = prelistcatfiles['filetoid'][getflinkpath];
    flinkinfo = listcatfiles['ffilelist'][flinkid];
    fheadersize = format(int(flinkinfo['fheadersize']), 'x').lower();
    fsize = format(int(flinkinfo['fsize']), 'x').lower();
    flinkname = flinkinfo['flinkname'];
    fatime = format(int(flinkinfo['fatime']), 'x').lower();
    fmtime = format(int(flinkinfo['fmtime']), 'x').lower();
    fctime = format(int(flinkinfo['fctime']), 'x').lower();
    fbtime = format(int(flinkinfo['fbtime']), 'x').lower();
    fmode = format(int(flinkinfo['fmode']), 'x').lower();
    fchmode = format(int(flinkinfo['fchmode']), 'x').lower();
    fuid = format(int(flinkinfo['fuid']), 'x').lower();
    funame = flinkinfo['funame'];
    fgid = format(int(flinkinfo['fgid']), 'x').lower();
    fgname = flinkinfo['fgname'];
    finode = flinkinfo['finode'];
    flinkcount = flinkinfo['flinkcount'];
    fdev_minor = format(int(flinkinfo['fminor']), 'x').lower();
    fdev_major = format(int(flinkinfo['fmajor']), 'x').lower();
    frdev_minor = format(int(flinkinfo['frminor']), 'x').lower();
    frdev_major = format(int(flinkinfo['frmajor']), 'x').lower();
    if(len(flinkinfo['fextralist'])>flinkinfo['fextrafields'] and len(flinkinfo['fextralist'])>0):
     flinkinfo['fextrafields'] = len(flinkinfo['fextralist']);
    if(len(extradata) > 0):
     flinkinfo['fextrafields'] = len(extradata);
     flinkinfo['fextralist'] = extradata;
    extrafields = format(int(flinkinfo['fextrafields']), 'x').lower();
    extrasizestr = AppendNullByte(extrafields);
    if(len(extradata)>0):
     extrasizestr = extrasizestr + AppendNullBytes(extradata);
    extrasizelen = format(len(extrasizestr), 'x').lower();
    fcontents = flinkinfo['fcontents'];
    if(flinkinfo['ftype']!=0 and flinkinfo['ftype']!=7):
     try:
      fcontents = fcontents.encode('UTF-8');
     except AttributeError:
      pass;
    ftypehex = format(flinkinfo['ftype'], 'x').lower();
  else:
   if(listcatfiles['ffilelist'][reallcfi]['ftype']!=0 and listcatfiles['ffilelist'][reallcfi]['ftype']!=7):
    try:
     fcontents = fcontents.encode('UTF-8');
    except AttributeError:
     pass;
   ftypehex = format(listcatfiles['ffilelist'][reallcfi]['ftype'], 'x').lower();
  fcurfid = format(curfid, 'x').lower();
  if(not followlink and finode!=0):
   if(listcatfiles['ffilelist'][reallcfi]['ftype']!=1):
    fcurinode = format(int(curinode), 'x').lower();
    inodetofile.update({curinode: fname});
    filetoinode.update({fname: curinode});
    curinode = curinode + 1;
   else:
    fcurinode = format(int(filetoinode[flinkname]), 'x').lower();
  else:
    fcurinode = format(int(curinode), 'x').lower();
    curinode = curinode + 1;
  curfid = curfid + 1;
  catfileoutstr = AppendNullBytes([ftypehex, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev_minor, fdev_major, frdev_minor, frdev_major, extrasizelen, extrafields]);
  if(listcatfiles['ffilelist'][reallcfi]['fextrafields']>0):
   extrafieldslist = [];
   exi = 0;
   exil = listcatfiles['ffilelist'][reallcfi]['fextrafields'];
   while(exi < exil):
    extrafieldslist.append(listcatfiles['ffilelist'][reallcfi]['fextralist']);
    exi = exi + 1;
   catfileoutstr += AppendNullBytes([extrafieldslist]);
  catfileoutstr += AppendNullBytes([checksumtype]);
  catfhend = (catfp.tell() - 1) + len(catfileoutstr);
  catfcontentstart = catfp.tell() + len(catfileoutstr);
  if(checksumtype=="none" or checksumtype==""):
   catfileheadercshex = format(0, 'x').lower();
   catfilecontentcshex = format(0, 'x').lower();
  elif(checksumtype=="crc16" or checksumtype=="crc16_ansi" or checksumtype=="crc16_ibm"):
   catfileheadercshex = format(crc16("".encode('UTF-8')) & 0xffff, '04x').lower();
   catfilecontentcshex = format(crc16(fcontents) & 0xffff, '04x').lower();
  elif(checksumtype=="crc16_ccitt"):
   catfileheadercshex = format(crc16_ccitt("".encode('UTF-8')) & 0xffff, '04x').lower();
   catfilecontentcshex = format(crc16_ccitt(fcontents) & 0xffff, '04x').lower();
  elif(checksumtype=="adler32"):
   catfileheadercshex = format(zlib.adler32("".encode('UTF-8')) & 0xffffffff, '08x').lower();
   catfilecontentcshex = format(zlib.adler32(fcontents) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc32"):
   catfileheadercshex = format(crc32("".encode('UTF-8')) & 0xffffffff, '08x').lower();
   catfilecontentcshex = format(crc32(fcontents) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc64_ecma"):
   catfileheadercshex = format(crc64_ecma("".encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
   catfilecontentcshex = format(crc64_ecma(fcontents) & 0xffffffffffffffff, '016x').lower();
  elif(checksumtype=="crc64" or checksumtype=="crc64_iso"):
   catfileheadercshex = format(crc64_iso("".encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
   catfilecontentcshex = format(crc64_iso(fcontents) & 0xffffffffffffffff, '016x').lower();
  elif(CheckSumSupportAlt(checksumtype, hashlib_guaranteed)):
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update("".encode('UTF-8'));
   catfileheadercshex = checksumoutstr.hexdigest().lower();
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(fcontents);
   catfilecontentcshex = checksumoutstr.hexdigest().lower();
  tmpfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex]);
  catheaersize = format(int(len(tmpfileoutstr) - 1), 'x').lower()
  catfileoutstr = AppendNullByte(catheaersize) + catfileoutstr;
  if(checksumtype=="none" or checksumtype==""):
   catfileheadercshex = format(0, 'x').lower();
  elif(checksumtype=="crc16" or checksumtype=="crc16_ansi" or checksumtype=="crc16_ibm"):
   catfileheadercshex = format(crc16(catfileoutstr.encode('UTF-8')) & 0xffff, '04x').lower();
  elif(checksumtype=="crc16_ccitt"):
   catfileheadercshex = format(crc16_ccitt(catfileoutstr.encode('UTF-8')) & 0xffff, '04x').lower();
  elif(checksumtype=="adler32"):
   catfileheadercshex = format(zlib.adler32(catfileoutstr.encode('UTF-8')) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc32"):
   catfileheadercshex = format(crc32(catfileoutstr.encode('UTF-8')) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc64_ecma"):
   catfileheadercshex = format(crc64_ecma(catfileoutstr.encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
  elif(checksumtype=="crc64" or checksumtype=="crc64_iso"):
   catfileheadercshex = format(crc64_iso(catfileoutstr.encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
  elif(CheckSumSupportAlt(checksumtype, hashlib_guaranteed)):
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(catfileoutstr.encode('UTF-8'));
   catfileheadercshex = checksumoutstr.hexdigest().lower();
  catfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex]);
  catfileoutstrecd = catfileoutstr.encode('UTF-8');
  nullstrecd = __file_format_delimiter__.encode('UTF-8');
  catfileout = catfileoutstrecd + fcontents + nullstrecd;
  catfcontentend = (catfp.tell() - 1) + len(catfileout);
  catfp.write(catfileout);
  lcfi = lcfi + 1;
  reallcfi = reallcfi + 1;
 if(outfile=="-" or hasattr(outfile, "read") or hasattr(outfile, "write")):
  catfp = CompressCatFile(catfp, compression);
 if(outfile=="-"):
  catfp.seek(0, 0);
  if(hasattr(sys.stdout, "buffer")):
   shutil.copyfileobj(catfp, sys.stdout.buffer);
  else:
   shutil.copyfileobj(catfp, sys.stdout);
 if(returnfp):
  catfp.seek(0, 0);
  return catfp;
 else:
  catfp.close();
  return True;

def RePackCatFileFromString(catstr, outfile, compression="auto", compressionlevel=None, checksumtype="crc32", skipchecksum=False, extradata=[], verbose=False, returnfp=False):
 catfp = BytesIO(catstr);
 listcatfiles = RePackCatFile(catfp, compression, compressionlevel, checksumtype, skipchecksum, extradata, verbose, returnfp);
 return listcatfiles;

def PackCatFileFromListDir(infiles, outfile, dirlistfromtxt=False, compression="auto", compressionlevel=None, followlink=False, skipchecksum=False, checksumtype="crc32", extradata=[], verbose=False, returnfp=False):
 outarray = BytesIO();
 packcat = PackCatFile(infiles, outarray, dirlistfromtxt, compression, compressionlevel, followlink, checksumtype, extradata, verbose, True);
 listcatfiles = RePackCatFile(outarray, outfile, compression, compressionlevel, checksumtype, skipchecksum, extradata, verbose, returnfp);
 return listcatfiles;

def CatFileArrayBase64Encode(infile, followlink=False, seekstart=0, seekend=0, skipchecksum=False, verbose=False, returnfp=False):
 if(verbose):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(isinstance(infile, dict)):
  prelistcatfiles = CatFileToArrayIndex(infile, seekstart, seekend, False, skipchecksum, returnfp);
  listcatfiles = prelistcatfiles['list'];
 else:
  if(infile!="-" and not hasattr(infile, "read") and not hasattr(infile, "write")):
   infile = RemoveWindowsPath(infile);
  if(followlink):
   prelistcatfiles = CatFileToArrayIndex(infile, seekstart, seekend, False, skipchecksum, returnfp);
   listcatfiles = prelistcatfiles['list'];
  else:
   listcatfiles = CatFileToArray(infile, seekstart, seekend, False, skipchecksum, returnfp);
 if(not listcatfiles):
  return False;
 lenlist = len(listcatfiles['ffilelist']);
 if(seekstart>0):
  lcfi = seekstart;
 else:
  lcfi = 0;
 if(seekend>0 and seekend<listcatfiles['fnumfiles']):
  lcfx = seekend;
 else:
  if(lenlist>listcatfiles['fnumfiles'] or lenlist<listcatfiles['fnumfiles']):
   lcfx = listcatfiles['fnumfiles'];
  else:
   lcfx = int(listcatfiles['fnumfiles']);
 if(lenlist>lcfx or lenlist<lcfx):
  lcfx = lenlist;
 while(lcfi < lcfx):
  if(listcatfiles['ffilelist'][lcfi]['fhascontents']):
   listcatfiles['ffilelist'][lcfi]['fcontents'] = base64.b64encode(listcatfiles['ffilelist'][lcfi]['fcontents']).decode("UTF-8");
  lcfi = lcfi + 1;
 return listcatfiles;

def CatFileArrayBase64Decode(infile, followlink=False, seekstart=0, seekend=0, skipchecksum=False, verbose=False, returnfp=False):
 if(verbose):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(isinstance(infile, dict)):
  prelistcatfiles = CatFileToArrayIndex(infile, seekstart, seekend, False, skipchecksum, returnfp);
  listcatfiles = prelistcatfiles['list'];
 else:
  if(infile!="-" and not hasattr(infile, "read") and not hasattr(infile, "write")):
   infile = RemoveWindowsPath(infile);
  if(followlink):
   prelistcatfiles = CatFileToArrayIndex(infile, seekstart, seekend, False, skipchecksum, returnfp);
   listcatfiles = prelistcatfiles['list'];
  else:
   listcatfiles = CatFileToArray(infile, seekstart, seekend, False, skipchecksum, returnfp);
 if(not listcatfiles):
  return False;
 lenlist = len(listcatfiles['ffilelist']);
 if(seekstart>0):
  lcfi = seekstart;
 else:
  lcfi = 0;
 if(seekend>0 and seekend<listcatfiles['fnumfiles']):
  lcfx = seekend;
 else:
  if(lenlist>listcatfiles['fnumfiles'] or lenlist<listcatfiles['fnumfiles']):
   lcfx = listcatfiles['fnumfiles'];
  else:
   lcfx = int(listcatfiles['fnumfiles']);
 if(lenlist>lcfx or lenlist<lcfx):
  lcfx = lenlist;
 while(lcfi < lcfx):
  if(listcatfiles['ffilelist'][lcfi]['fhascontents']):
   listcatfiles['ffilelist'][lcfi]['fcontents'] = base64.b64decode(listcatfiles['ffilelist'][lcfi]['fcontents'].encode("UTF-8"));
  lcfi = lcfi + 1;
 return listcatfiles;

def UnPackCatFile(infile, outdir=None, followlink=False, seekstart=0, seekend=0, skipchecksum=False, verbose=False, returnfp=False):
 if(outdir is not None):
  outdir = RemoveWindowsPath(outdir);
 if(verbose):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(isinstance(infile, dict)):
  prelistcatfiles = CatFileToArrayIndex(infile, seekstart, seekend, False, skipchecksum, returnfp);
  listcatfiles = prelistcatfiles['list'];
 else:
  if(infile!="-" and not hasattr(infile, "read") and not hasattr(infile, "write")):
   infile = RemoveWindowsPath(infile);
  if(followlink):
   prelistcatfiles = CatFileToArrayIndex(infile, seekstart, seekend, False, skipchecksum, returnfp);
   listcatfiles = prelistcatfiles['list'];
  else:
   listcatfiles = CatFileToArray(infile, seekstart, seekend, False, skipchecksum, returnfp);
 if(not listcatfiles):
  return False;
 lenlist = len(listcatfiles['ffilelist']);
 if(seekstart>0):
  lcfi = seekstart;
 else:
  lcfi = 0;
 if(seekend>0 and seekend<listcatfiles['fnumfiles']):
  lcfx = seekend;
 else:
  if(lenlist>listcatfiles['fnumfiles'] or lenlist<listcatfiles['fnumfiles']):
   lcfx = listcatfiles['fnumfiles'];
  else:
   lcfx = int(listcatfiles['fnumfiles']);
 if(lenlist>lcfx or lenlist<lcfx):
  lcfx = lenlist;
 while(lcfi < lcfx):
  funame = "";
  try:
   import pwd;
   try:
    userinfo = pwd.getpwuid(listcatfiles['ffilelist'][lcfi]['fuid']);
    funame = userinfo.pw_name;
   except KeyError:
    funame = "";
  except ImportError:
   funame = "";
  fgname = "";
  try:
   import grp;
   try:
    groupinfo = grp.getgrgid(listcatfiles['ffilelist'][lcfi]['fgid']);
    fgname = groupinfo.gr_name;
   except KeyError:
    fgname = "";
  except ImportError:
   fgname = "";
  if(verbose):
   VerbosePrintOut(listcatfiles['ffilelist'][lcfi]['fname']);
  if(listcatfiles['ffilelist'][lcfi]['ftype']==0 or listcatfiles['ffilelist'][lcfi]['ftype']==7):
   fpc = open(listcatfiles['ffilelist'][lcfi]['fname'], "wb");
   fpc.write(listcatfiles['ffilelist'][lcfi]['fcontents']);
   fpc.close();
   if(hasattr(os, "chown") and funame==listcatfiles['ffilelist'][lcfi]['funame'] and fgname==listcatfiles['ffilelist'][lcfi]['fgname']):
    os.chown(listcatfiles['ffilelist'][lcfi]['fname'], listcatfiles['ffilelist'][lcfi]['fuid'], listcatfiles['ffilelist'][lcfi]['fgid']);
   os.chmod(listcatfiles['ffilelist'][lcfi]['fname'], int(listcatfiles['ffilelist'][lcfi]['fchmode'], 8));
   os.utime(listcatfiles['ffilelist'][lcfi]['fname'], (listcatfiles['ffilelist'][lcfi]['fatime'], listcatfiles['ffilelist'][lcfi]['fmtime']));
  if(listcatfiles['ffilelist'][lcfi]['ftype']==1):
   if(followlink):
    getflinkpath = listcatfiles['ffilelist'][lcfi]['flinkname'];
    flinkid = prelistcatfiles['filetoid'][getflinkpath];
    flinkinfo = listcatfiles['ffilelist'][flinkid];
    funame = "";
    try:
     import pwd;
     try:
      userinfo = pwd.getpwuid(flinkinfo['fuid']);
      funame = userinfo.pw_name;
     except KeyError:
      funame = "";
    except ImportError:
     funame = "";
    fgname = "";
    try:
     import grp;
     try:
      groupinfo = grp.getgrgid(flinkinfo['fgid']);
      fgname = groupinfo.gr_name;
     except KeyError:
      fgname = "";
    except ImportError:
     fgname = "";
    if(flinkinfo['ftype']==0 or flinkinfo['ftype']==7):
     fpc = open(listcatfiles['ffilelist'][lcfi]['fname'], "wb");
     fpc.write(flinkinfo['fcontents']);
     fpc.close();
     if(hasattr(os, "chown") and funame==flinkinfo['funame'] and fgname==flinkinfo['fgname']):
      os.chown(listcatfiles['ffilelist'][lcfi]['fname'], flinkinfo['fuid'], flinkinfo['fgid']);
     os.chmod(listcatfiles['ffilelist'][lcfi]['fname'], int(flinkinfo['fchmode'], 8));
     os.utime(listcatfiles['ffilelist'][lcfi]['fname'], (flinkinfo['fatime'], flinkinfo['fmtime']));
    if(flinkinfo['ftype']==1):
     os.link(flinkinfo['flinkname'], listcatfiles['ffilelist'][lcfi]['fname']);
    if(flinkinfo['ftype']==2):
     os.symlink(flinkinfo['flinkname'], listcatfiles['ffilelist'][lcfi]['fname']);
    if(flinkinfo['ftype']==5):
     os.mkdir(listcatfiles['ffilelist'][lcfi]['fname'], int(flinkinfo['fchmode'], 8));
     if(hasattr(os, "chown") and funame==flinkinfo['funame'] and fgname==flinkinfo['fgname']):
      os.chown(listcatfiles['ffilelist'][lcfi]['fname'], flinkinfo['fuid'], flinkinfo['fgid']);
     os.chmod(listcatfiles['ffilelist'][lcfi]['fname'], int(flinkinfo['fchmode'], 8));
     os.utime(listcatfiles['ffilelist'][lcfi]['fname'], (flinkinfo['fatime'], flinkinfo['fmtime']));
    if(flinkinfo['ftype']==6 and hasattr(os, "mkfifo")):
     os.mkfifo(listcatfiles['ffilelist'][lcfi]['fname'], int(flinkinfo['fchmode'], 8));
   else:
    os.link(listcatfiles['ffilelist'][lcfi]['flinkname'], listcatfiles['ffilelist'][lcfi]['fname']);
  if(listcatfiles['ffilelist'][lcfi]['ftype']==2):
   if(followlink):
    getflinkpath = listcatfiles['ffilelist'][lcfi]['flinkname'];
    flinkid = prelistcatfiles['filetoid'][getflinkpath];
    flinkinfo = listcatfiles['ffilelist'][flinkid];
    funame = "";
    try:
     import pwd;
     try:
      userinfo = pwd.getpwuid(flinkinfo['fuid']);
      funame = userinfo.pw_name;
     except KeyError:
      funame = "";
    except ImportError:
     funame = "";
    fgname = "";
    try:
     import grp;
     try:
      groupinfo = grp.getgrgid(flinkinfo['fgid']);
      fgname = groupinfo.gr_name;
     except KeyError:
      fgname = "";
    except ImportError:
     fgname = "";
    if(flinkinfo['ftype']==0 or flinkinfo['ftype']==7):
     fpc = open(listcatfiles['ffilelist'][lcfi]['fname'], "wb");
     fpc.write(flinkinfo['fcontents']);
     fpc.close();
     if(hasattr(os, "chown") and funame==flinkinfo['funame'] and fgname==flinkinfo['fgname']):
      os.chown(listcatfiles['ffilelist'][lcfi]['fname'], flinkinfo['fuid'], flinkinfo['fgid']);
     os.chmod(listcatfiles['ffilelist'][lcfi]['fname'], int(flinkinfo['fchmode'], 8));
     os.utime(listcatfiles['ffilelist'][lcfi]['fname'], (flinkinfo['fatime'], flinkinfo['fmtime']));
    if(flinkinfo['ftype']==1):
     os.link(flinkinfo['flinkname'], listcatfiles['ffilelist'][lcfi]['fname']);
    if(flinkinfo['ftype']==2):
     os.symlink(flinkinfo['flinkname'], listcatfiles['ffilelist'][lcfi]['fname']);
    if(flinkinfo['ftype']==5):
     os.mkdir(listcatfiles['ffilelist'][lcfi]['fname'], int(flinkinfo['fchmode'], 8));
     if(hasattr(os, "chown") and funame==flinkinfo['funame'] and fgname==flinkinfo['fgname']):
      os.chown(listcatfiles['ffilelist'][lcfi]['fname'], flinkinfo['fuid'], flinkinfo['fgid']);
     os.chmod(listcatfiles['ffilelist'][lcfi]['fname'], int(flinkinfo['fchmode'], 8));
     os.utime(listcatfiles['ffilelist'][lcfi]['fname'], (flinkinfo['fatime'], flinkinfo['fmtime']));
    if(flinkinfo['ftype']==6 and hasattr(os, "mkfifo")):
     os.mkfifo(listcatfiles['ffilelist'][lcfi]['fname'], int(flinkinfo['fchmode'], 8));
   else:
    os.symlink(listcatfiles['ffilelist'][lcfi]['flinkname'], listcatfiles['ffilelist'][lcfi]['fname']);
  if(listcatfiles['ffilelist'][lcfi]['ftype']==5):
   os.mkdir(listcatfiles['ffilelist'][lcfi]['fname'], int(listcatfiles['ffilelist'][lcfi]['fchmode'], 8));
   if(hasattr(os, "chown") and funame==listcatfiles['ffilelist'][lcfi]['funame'] and fgname==listcatfiles['ffilelist'][lcfi]['fgname']):
    os.chown(listcatfiles['ffilelist'][lcfi]['fname'], listcatfiles['ffilelist'][lcfi]['fuid'], listcatfiles['ffilelist'][lcfi]['fgid']);
   os.chmod(listcatfiles['ffilelist'][lcfi]['fname'], int(listcatfiles['ffilelist'][lcfi]['fchmode'], 8));
   os.utime(listcatfiles['ffilelist'][lcfi]['fname'], (listcatfiles['ffilelist'][lcfi]['fatime'], listcatfiles['ffilelist'][lcfi]['fmtime']));
  if(listcatfiles['ffilelist'][lcfi]['ftype']==6 and hasattr(os, "mkfifo")):
   os.mkfifo(listcatfiles['ffilelist'][lcfi]['fname'], int(listcatfiles['ffilelist'][lcfi]['fchmode'], 8));
  lcfi = lcfi + 1;
 if(returnfp):
  return listcatfiles['ffilelist']['catfp'];
 else:
  return True;

if(hasattr(shutil, "register_unpack_format")):
 def UnPackCatFileFunc(archive_name, extract_dir=None, **kwargs):
  return UnPackCatFile(archive_name, extract_dir, False, 0, 0, False, False, False);

def UnPackCatString(catstr, outdir=None, followlink=False, seekstart=0, seekend=0, skipchecksum=False, verbose=False, returnfp=False):
 catfp = BytesIO(catstr);
 listcatfiles = UnPackCatFile(catfp, outdir, followlink, seekstart, seekend, skipchecksum, verbose, returnfp);
 return listcatfiles;

def CatFileListFiles(infile, seekstart=0, seekend=0, skipchecksum=False, verbose=False, returnfp=False):
 logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(isinstance(infile, dict)):
  listcatfiles = infile;
 else:
  if(infile!="-" and not hasattr(infile, "read") and not hasattr(infile, "write")):
   infile = RemoveWindowsPath(infile);
  listcatfiles = CatFileToArray(infile, seekstart, seekend, True, skipchecksum, returnfp);
 if(not listcatfiles):
  return False;
 lenlist = len(listcatfiles['ffilelist']);
 lcfi = 0;
 lcfx = lenlist;
 returnval = {};
 while(lcfi < lcfx):
  returnval.update({lcfi: listcatfiles['ffilelist'][lcfi]['fname']});
  if(not verbose):
   VerbosePrintOut(listcatfiles['ffilelist'][lcfi]['fname']);
  if(verbose):
   permissions = { 'access': { '0': ('---'), '1': ('--x'), '2': ('-w-'), '3': ('-wx'), '4': ('r--'), '5': ('r-x'), '6': ('rw-'), '7': ('rwx') }, 'roles': { 0: 'owner', 1: 'group', 2: 'other' } };
   printfname = listcatfiles['ffilelist'][lcfi]['fname'];
   if(listcatfiles['ffilelist'][lcfi]['ftype']==1):
    printfname = listcatfiles['ffilelist'][lcfi]['fname'] + " link to " + listcatfiles['ffilelist'][lcfi]['flinkname'];
   if(listcatfiles['ffilelist'][lcfi]['ftype']==2):
    printfname = listcatfiles['ffilelist'][lcfi]['fname'] + " -> " + listcatfiles['ffilelist'][lcfi]['flinkname'];
   fuprint = listcatfiles['ffilelist'][lcfi]['funame'];
   if(len(fuprint)<=0):
    fuprint = listcatfiles['ffilelist'][lcfi]['fuid'];
   fgprint = listcatfiles['ffilelist'][lcfi]['fgname'];
   if(len(fgprint)<=0):
    fgprint = listcatfiles['ffilelist'][lcfi]['fgid'];
   VerbosePrintOut(PrintPermissionString(listcatfiles['ffilelist'][lcfi]['fmode'], listcatfiles['ffilelist'][lcfi]['ftype']) + " " + str(str(fuprint) + "/" + str(fgprint) + " " + str(listcatfiles['ffilelist'][lcfi]['fsize']).rjust(15) + " " + datetime.datetime.utcfromtimestamp(listcatfiles['ffilelist'][lcfi]['fmtime']).strftime('%Y-%m-%d %H:%M') + " " + printfname));
  lcfi = lcfi + 1;
 if(returnfp):
  return listcatfiles['catfp'];
 else:
  return True;

def CatStringListFiles(catstr, followlink=False, skipchecksum=False, verbose=False, returnfp=False):
 catfp = BytesIO(catstr);
 listcatfiles = UnPackCatFile(catfp, None, followlink, skipchecksum, verbose, returnfp);
 return listcatfiles;

def TarFileListFiles(infile, verbose=False, returnfp=False):
 logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(not os.path.exists(infile) or not os.path.isfile(infile)):
  return False;
 try:
  if(not tarfile.is_tarfile(infile)):
   return False;
 except AttributeError:
   if(not is_tarfile(infile)):
    return False;
 lcfi = 0;
 returnval = {};
 tarfp = tarfile.open(infile, "r");
 for member in tarfp.getmembers():
  returnval.update({lcfi: member.name});
  fpremode = member.mode;
  ffullmode = member.mode;
  flinkcount = 0;
  ftype = 0;
  if(member.isreg()):
   ffullmode = member.mode + stat.S_IFREG;
   ftype = 0;
  if(member.isdev()):
   ffullmode = member.mode;
   ftype = 7;
  if(member.islnk()):
   ffullmode = member.mode + stat.S_IFREG;
   ftype = 1;
  if(member.issym()):
   ffullmode = member.mode + stat.S_IFLNK;
   ftype = 2;
  if(member.ischr()):
   ffullmode = member.mode + stat.S_IFCHR;
   ftype = 3;
  if(member.isblk()):
   ffullmode = member.mode + stat.S_IFBLK;
   ftype = 4;
  if(member.isdir()):
   ffullmode = member.mode + stat.S_IFDIR;
   ftype = 5;
  if(member.isfifo()):
   ffullmode = member.mode + stat.S_IFIFO;
   ftype = 6;
  if(member.issparse()):
   ffullmode = member.mode;
   ftype = 8;
  if(not verbose):
   VerbosePrintOut(member.name);
  if(verbose):
   permissions = { 'access': { '0': ('---'), '1': ('--x'), '2': ('-w-'), '3': ('-wx'), '4': ('r--'), '5': ('r-x'), '6': ('rw-'), '7': ('rwx') }, 'roles': { 0: 'owner', 1: 'group', 2: 'other' } };
   printfname = member.name;
   if(member.islnk()):
    printfname = member.name + " link to " + member.linkname;
   if(member.issym()):
    printfname = member.name + " -> " + member.linkname;
   fuprint = member.uname;
   if(len(fuprint)<=0):
    fuprint = member.uid;
   fgprint = member.gname;
   if(len(fgprint)<=0):
    fgprint = member.gid;
   VerbosePrintOut(PrintPermissionString(ffullmode, ftype) + " " + str(str(fuprint) + "/" + str(fgprint) + " " + str(member.size).rjust(15) + " " + datetime.datetime.utcfromtimestamp(member.mtime).strftime('%Y-%m-%d %H:%M') + " " + printfname));
  lcfi = lcfi + 1;
 if(returnfp):
  return listcatfiles['catfp'];
 else:
  return True;

def ZipFileListFiles(infile, verbose=False, returnfp=False):
 logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(not os.path.exists(infile) or not os.path.isfile(infile)):
  return False;
 if(not zipfile.is_zipfile(infile)):
  return False;
 lcfi = 0;
 returnval = {};
 zipfp = zipfile.ZipFile(infile, "r", allowZip64=True);
 ziptest = zipfp.testzip();
 if(ziptest):
  VerbosePrintOut("Bad file found: " + str(bad_file));
 for member in zipfp.infolist():
  if(not member.is_dir()):
   fpremode = int(stat.S_IFREG + 438);
  if(member.is_dir()):
   fpremode = int(stat.S_IFDIR + 511);
  if(not member.is_dir()):
   fmode = int(stat.S_IFREG + 438);
   fchmode = int(stat.S_IMODE(int(stat.S_IFREG + 438)));
   ftypemod = int(stat.S_IFMT(int(stat.S_IFREG + 438)));
  if(member.is_dir()):
   fmode = int(stat.S_IFDIR + 511);
   fchmode = int(stat.S_IMODE(int(stat.S_IFDIR + 511)));
   ftypemod = int(stat.S_IFMT(int(stat.S_IFDIR + 511)));
  returnval.update({lcfi: member.filename});
  if(not verbose):
   VerbosePrintOut(member.filename);
  if(verbose):
   permissions = { 'access': { '0': ('---'), '1': ('--x'), '2': ('-w-'), '3': ('-wx'), '4': ('r--'), '5': ('r-x'), '6': ('rw-'), '7': ('rwx') }, 'roles': { 0: 'owner', 1: 'group', 2: 'other' } };
   permissionstr = "";
   for fmodval in str(oct(fmode))[-3:]:
    permissionstr = permissionstr + permissions['access'].get(fmodval, '---');
   if(not member.is_dir()):
    ftype = 0;
    permissionstr = "-" + permissionstr;
   if(member.is_dir()):
    ftype = 5;
    permissionstr = "d" + permissionstr;
   printfname = member.filename;
   try:
    fuid = int(os.getuid());
   except AttributeError:
    fuid = int(0);
   except KeyError:
    fuid = int(0);
   try:
    fgid = int(os.getgid());
   except AttributeError:
    fgid = int(0);
   except KeyError:
    fgid = int(0);
   try:
    import pwd;
    try:
     userinfo = pwd.getpwuid(os.getuid());
     funame = userinfo.pw_name;
    except KeyError:
     funame = "";
    except AttributeError:
     funame = "";
   except ImportError:
    funame = "";
   fgname = "";
   try:
    import grp;
    try:
     groupinfo = grp.getgrgid(os.getgid());
     fgname = groupinfo.gr_name;
    except KeyError:
     fgname = "";
    except AttributeError:
     fgname = "";
   except ImportError:
    fgname = "";
   fuprint = funame;
   if(len(fuprint)<=0):
    fuprint = str(fuid);
   fgprint = fgname;
   if(len(fgprint)<=0):
    fgprint = str(fgid);
   VerbosePrintOut(PrintPermissionString(fmode, ftype) + " " + str(str(fuprint) + "/" + str(fgprint) + " " + str(member.file_size).rjust(15) + " " + datetime.datetime.utcfromtimestamp(int(time.mktime(member.date_time + (0, 0, -1)))).strftime('%Y-%m-%d %H:%M') + " " + printfname));
  lcfi = lcfi + 1;
 if(returnfp):
  return listcatfiles['catfp'];
 else:
  return True;

def ListDirListFiles(infiles, dirlistfromtxt=False, compression="auto", compressionlevel=None, followlink=False, seekstart=0, seekend=0, skipchecksum=False, checksumtype="crc32", verbose=False, returnfp=False):
 outarray = BytesIO();
 packcat = PackCatFile(infiles, outarray, dirlistfromtxt, compression, compressionlevel, followlink, checksumtype, False, True);
 listcatfiles = CatFileListFiles(outarray, seekstart, seekend, skipchecksum, verbose, returnfp);
 return listcatfiles;

def ListDirListFilesAlt(infiles, dirlistfromtxt=False, followlink=False, listonly=True, seekstart=0, seekend=0, skipchecksum=False, checksumtype="crc32", verbose=False, returnfp=False):
 outarray = ListDirToArrayAlt(infiles, dirlistfromtxt, followlink, listonly, checksumtype, verbose);
 listcatfiles = CatFileListFiles(outarray, seekstart, seekend, skipchecksum, verbose, returnfp);
 return listcatfiles;

def PackCatFileFromListDirAlt(infiles, outfile, dirlistfromtxt=False, compression="auto", compressionlevel=None, followlink=False, skipchecksum=False, checksumtype="crc32", extradata=[], verbose=False, returnfp=False):
 outarray = ListDirToArrayAlt(infiles, dirlistfromtxt, followlink, False, checksumtype, extradata, False);
 listcatfiles = RePackCatFile(outarray, outfile, compression, compressionlevel, followlink, checksumtype, skipchecksum, extradata, verbose, returnfp);
 return listcatfiles;

def PackCatFileFromTarFileAlt(infile, outfile, compression="auto", compressionlevel=None, checksumtype="crc32", extradata=[], verbose=False, returnfp=False):
 outarray = TarFileToArrayAlt(infile, False, checksumtype, extradata, False);
 listcatfiles = RePackCatFile(outarray, outfile, compression, compressionlevel, False, checksumtype, False, extradata, verbose, returnfp);
 return listcatfiles;

def PackCatFileFromZipFileAlt(infile, outfile, compression="auto", compressionlevel=None, checksumtype="crc32", extradata=[], verbose=False, returnfp=False):
 outarray = ZipFileToArrayAlt(infile, False, checksumtype, extradata, False);
 listcatfiles = RePackCatFile(outarray, outfile, compression, compressionlevel, False, checksumtype, False, extradata, verbose, returnfp);
 return listcatfiles;

def download_file_from_ftp_file(url):
 urlparts = urlparse.urlparse(url);
 file_name = os.path.basename(urlparts.path);
 file_dir = os.path.dirname(urlparts.path);
 if(urlparts.username is not None):
  ftp_username = urlparts.username;
 else:
  ftp_username = "anonymous";
 if(urlparts.password is not None):
  ftp_password = urlparts.password;
 elif(urlparts.password is None and urlparts.username=="anonymous"):
  ftp_password = "anonymous";
 else:
  ftp_password = "";
 if(urlparts.scheme=="ftp"):
  ftp = FTP();
 elif(urlparts.scheme=="ftps"):
  ftp = FTP_TLS();
 else:
  return False;
 if(urlparts.scheme=="http" or urlparts.scheme=="https"):
  return False;
 ftp_port = urlparts.port;
 if(urlparts.port is None):
  ftp_port = 21;
 try:
  ftp.connect(urlparts.hostname, ftp_port);
 except socket.gaierror:
  log.info("Error With URL "+httpurl);
  return False;
 except socket.timeout:
  log.info("Error With URL "+httpurl);
  return False;
 ftp.login(urlparts.username, urlparts.password);
 if(urlparts.scheme=="ftps"):
  ftp.prot_p();
 ftpfile = BytesIO();
 ftp.retrbinary("RETR "+urlparts.path, ftpfile.write);
 #ftp.storbinary("STOR "+urlparts.path, ftpfile.write);
 ftp.close();
 ftpfile.seek(0, 0);
 return ftpfile;

def download_file_from_ftp_string(url):
 ftpfile = download_file_from_ftp_file(url);
 return ftpfile.read();

def upload_file_to_ftp_file(ftpfile, url):
 urlparts = urlparse.urlparse(url);
 file_name = os.path.basename(urlparts.path);
 file_dir = os.path.dirname(urlparts.path);
 if(urlparts.username is not None):
  ftp_username = urlparts.username;
 else:
  ftp_username = "anonymous";
 if(urlparts.password is not None):
  ftp_password = urlparts.password;
 elif(urlparts.password is None and urlparts.username=="anonymous"):
  ftp_password = "anonymous";
 else:
  ftp_password = "";
 if(urlparts.scheme=="ftp"):
  ftp = FTP();
 elif(urlparts.scheme=="ftps"):
  ftp = FTP_TLS();
 else:
  return False;
 if(urlparts.scheme=="http" or urlparts.scheme=="https"):
  return False;
 ftp_port = urlparts.port;
 if(urlparts.port is None):
  ftp_port = 21;
 try:
  ftp.connect(urlparts.hostname, ftp_port);
 except socket.gaierror:
  log.info("Error With URL "+httpurl);
  return False;
 except socket.timeout:
  log.info("Error With URL "+httpurl);
  return False;
 ftp.login(urlparts.username, urlparts.password);
 if(urlparts.scheme=="ftps"):
  ftp.prot_p();
 ftp.storbinary("STOR "+urlparts.path, ftpfile);
 ftp.close();
 ftpfile.seek(0, 0);
 return ftpfile;

def upload_file_to_ftp_string(ftpstring, url):
 ftpfileo = BytesIO(ftpstring);
 ftpfile = upload_file_to_ftp_file(ftpfileo, url);
 ftpfileo.close();
 return ftpfile;

if(hasattr(shutil, "register_archive_format")):
 # Register the packing format
 shutil.register_archive_format(__file_format_name__, PackCatFileFunc, description='Pack concatenated files');

if(hasattr(shutil, "register_unpack_format")):
 # Register the unpacking format
 shutil.register_unpack_format(__file_format_name__, catfile_extensions, UnPackCatFileFunc, description='UnPack concatenated files');
