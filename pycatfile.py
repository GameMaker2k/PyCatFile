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

    $FileInfo: pycatfile.py - Last Update: 2/16/2024 Ver. 0.0.5 RC 1 - Author: cooldude2k $
'''

from __future__ import absolute_import, division, print_function, unicode_literals;
import os, re, sys, time, stat, zlib, shutil, hashlib, logging, binascii, tempfile, zipfile;

hashlib_guaranteed = False;
os.environ["PYTHONIOENCODING"] = "UTF-8";
os.environ["LANG"] = "UTF-8";
os.environ["LC_ALL"] = "UTF-8";
os.environ["LC_CTYPE"] = "UTF-8";
os.environ["LC_CTYPE"] = "UTF-8";
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

__program_name__ = "PyCatFile";
__project__ = __program_name__;
__project_url__ = "https://github.com/GameMaker2k/PyCatFile";
__version_info__ = (0, 0, 5, "RC 1", 1);
__version_date_info__ = (2024, 2, 16, "RC 1", 1);
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
 if(outtype=="print" and dbgenable):
  print(dbgtxt);
  return True;
 elif(outtype=="log" and dbgenable):
  logging.info(dbgtxt);
  return True;
 elif(outtype=="warning" and dbgenable):
  logging.warning(dbgtxt);
  return True;
 elif(outtype=="error" and dbgenable):
  logging.error(dbgtxt);
  return True;
 elif(outtype=="critical" and dbgenable):
  logging.critical(dbgtxt);
  return True;
 elif(outtype=="exception" and dbgenable):
  logging.exception(dbgtxt);
  return True;
 elif(outtype=="logalt" and dbgenable):
  logging.log(dgblevel, dbgtxt);
  return True;
 elif(outtype=="debug" and dbgenable):
  logging.debug(dbgtxt);
  return True;
 elif(not dbgenable):
  return True;
 else:
  return False;
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

def ReadTillNullByte(fp):
 curbyte = b"";
 curfullbyte = b"";
 nullbyte = b"\0";
 while(curbyte!=nullbyte):
  curbyte = fp.read(1);
  if(curbyte!=nullbyte):
   curfullbyte = curfullbyte + curbyte;
 return curfullbyte.decode();

def ReadUntilNullByte(fp):
 return ReadTillNullByte(fp);

def SeekToEndOfFile(fp):
 lasttell = 0;
 while(True):
  fp.seek(1, 1);
  if(lasttell==fp.tell()):
   break;
  lasttell = fp.tell();
 return True;

def ReadFileHeaderData(fp, rounds=0):
 rocount = 0;
 roend = int(rounds);
 HeaderOut = {};
 while(rocount<roend):
  RoundArray = {rocount: ReadTillNullByte(fp)};
  HeaderOut.update(RoundArray);
  rocount = rocount + 1;
 return HeaderOut;

def AppendNullByte(indata):
 outdata = str(indata) + "\0";
 return outdata;

def AppendNullBytes(indata=[]):
 outdata = "";
 inum = 0;
 il = len(indata);
 while(inum < il):
  outdata = outdata + AppendNullByte(indata[inum]);
  inum = inum + 1;
 return outdata;

def ReadTillNullByteAlt(fp):
 """Read bytes from file pointer until a null byte is encountered."""
 bytes_list = []  # Use list for efficient append operation.
 while True:
  cur_byte = fp.read(1);
  if cur_byte == b"\0" or not cur_byte:
   break;
  bytes_list.append(cur_byte);
 return b''.join(bytes_list).decode();

def ReadUntilNullByteAlt(fp):
 return ReadTillNullByteAlt(fp);

def ReadFileHeaderDataAlt(fp, rounds=0):
 """Read multiple null-byte terminated strings from a file."""
 header_out = {}
 for round_count in range(rounds):
  header_out[round_count] = read_till_null_byte(fp);
 return header_out;

def AppendNullByteAlt(indata):
 """Append a null byte to the given data."""
 return str(indata) + "\0";

def AppendNullBytesAlt(indata=[]):
 """Append a null byte to each element in the list and concatenate."""
 return '\0'.join(map(str, indata)) + "\0";  # Efficient concatenation with null byte.

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
 if(compresscheck=="catfile" or compresscheck=="cat"):
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
 if(compresscheck=="lzma"):
  try:
   import lzma;
  except ImportError:
   return False;
  catfp = BytesIO();
  catfp.write(lzma.decompress(fp.read()));
 if(compresscheck=="catfile"):
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
   catfp = gzip.open(infile, "rb");
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
  if(compresscheck=="lzma"):
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
 if(not compression or compression or compression=="catfile"):
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
  catfp.write(GZipCompress(fp.read(), compresslevel=compressionlevel));
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
 if(not compression or compression or compression=="catfile"):
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
   catfp = gzip.open(outfile, "wb", compresslevel=compressionlevel);
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
 fileheader = AppendNullByte("CatFile" + fileheaderver);
 catfp.write(fileheader.encode());
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
  if(not followlink):
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
  fcontents = "".encode();
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
  catfileoutstr = AppendNullBytes([ftypehex, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev_minor, fdev_major, frdev_minor, frdev_major, extrafields]);
  if(len(extradata)>0):
   catfileoutstr = catfileoutstr + AppendNullBytes(extradata);
  catfileoutstr = catfileoutstr + AppendNullByte(checksumtype);
  if(checksumtype=="none" or checksumtype==""):
   catfileheadercshex = format(0, 'x').lower();
   catfilecontentcshex = format(0, 'x').lower();
  if(checksumtype=="crc16" or checksumtype=="crc16_ansi" or checksumtype=="crc16_ibm"):
   catfileheadercshex = format(crc16(catfileoutstr.encode()) & 0xffff, '04x').lower();
   catfilecontentcshex = format(crc16(fcontents) & 0xffff, '04x').lower();
  if(checksumtype=="crc16_ccitt"):
   catfileheadercshex = format(crc16_ccitt(catfileoutstr.encode()) & 0xffff, '04x').lower();
   catfilecontentcshex = format(crc16_ccitt(fcontents) & 0xffff, '04x').lower();
  elif(checksumtype=="adler32"):
   catfileheadercshex = format(zlib.adler32(catfileoutstr.encode()) & 0xffffffff, '08x').lower();
   catfilecontentcshex = format(zlib.adler32(fcontents) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc32"):
   catfileheadercshex = format(crc32(catfileoutstr.encode()) & 0xffffffff, '08x').lower();
   catfilecontentcshex = format(crc32(fcontents) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc64_ecma"):
   catfileheadercshex = format(crc64_ecma(catfileoutstr.encode()) & 0xffffffffffffffff, '016x').lower();
   catfilecontentcshex = format(crc64_ecma(fcontents) & 0xffffffffffffffff, '016x').lower();
  elif(checksumtype=="crc64" or checksumtype=="crc64_iso"):
   catfileheadercshex = format(crc64_iso(catfileoutstr.encode()) & 0xffffffffffffffff, '016x').lower();
   catfilecontentcshex = format(crc64_iso(fcontents) & 0xffffffffffffffff, '016x').lower();
  elif(CheckSumSupportAlt(checksumtype, hashlib_guaranteed)):
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(catfileoutstr.encode());
   catfileheadercshex = checksumoutstr.hexdigest().lower();
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(fcontents);
   catfilecontentcshex = checksumoutstr.hexdigest().lower();
  catfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex]);
  catfhend = (catfp.tell() - 1) + len(catfileoutstr);
  catfcontentstart = catfp.tell() + len(catfileoutstr);
  catfileoutstrecd = catfileoutstr.encode();
  nullstrecd = "\0".encode();
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
 if(not compression or compression or compression=="catfile"):
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
   catfp = gzip.open(outfile, "wb", compresslevel=compressionlevel);
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
 fileheader = AppendNullByte("CatFile" + fileheaderver);
 catfp.write(fileheader.encode());
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
  fcontents = "".encode();
  if(ftype==0 or ftype==7):
   fpc = tarfp.extractfile(member);
   fcontents = fpc.read(int(member.size));
   fpc.close();
  ftypehex = format(ftype, 'x').lower();
  extrafields = format(len(extradata), 'x').lower();
  catfileoutstr = AppendNullBytes([ftypehex, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev_minor, fdev_major, frdev_minor, frdev_major, extrafields]);
  if(len(extradata)>0):
   catfileoutstr = catfileoutstr + AppendNullBytes(extradata);
  catfileoutstr = catfileoutstr + AppendNullByte(checksumtype);
  catfhend = (catfp.tell() - 1) + len(catfileoutstr);
  catfcontentstart = catfp.tell() + len(catfileoutstr);
  if(checksumtype=="none" or checksumtype==""):
   catfileheadercshex = format(0, 'x').lower();
   catfilecontentcshex = format(0, 'x').lower();
  if(checksumtype=="crc16" or checksumtype=="crc16_ansi" or checksumtype=="crc16_ibm"):
   catfileheadercshex = format(crc16(catfileoutstr.encode()) & 0xffff, '04x').lower();
   catfilecontentcshex = format(crc16(fcontents) & 0xffff, '04x').lower();
  if(checksumtype=="crc16_ccitt"):
   catfileheadercshex = format(crc16_ccitt(catfileoutstr.encode()) & 0xffff, '04x').lower();
   catfilecontentcshex = format(crc16_ccitt(fcontents) & 0xffff, '04x').lower();
  elif(checksumtype=="adler32"):
   catfileheadercshex = format(zlib.adler32(catfileoutstr.encode()) & 0xffffffff, '08x').lower();
   catfilecontentcshex = format(zlib.adler32(fcontents) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc32"):
   catfileheadercshex = format(crc32(catfileoutstr.encode()) & 0xffffffff, '08x').lower();
   catfilecontentcshex = format(crc32(fcontents) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc64_ecma"):
   catfileheadercshex = format(crc64_ecma(catfileoutstr.encode()) & 0xffffffffffffffff, '016x').lower();
   catfilecontentcshex = format(crc64_ecma(fcontents) & 0xffffffffffffffff, '016x').lower();
  elif(checksumtype=="crc64" or checksumtype=="crc64_iso"):
   catfileheadercshex = format(crc64_iso(catfileoutstr.encode()) & 0xffffffffffffffff, '016x').lower();
   catfilecontentcshex = format(crc64_iso(fcontents) & 0xffffffffffffffff, '016x').lower();
  elif(CheckSumSupportAlt(checksumtype, hashlib_guaranteed)):
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(catfileoutstr.encode());
   catfileheadercshex = checksumoutstr.hexdigest().lower();
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(fcontents);
   catfilecontentcshex = checksumoutstr.hexdigest().lower();
  catfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex]);
  catfileoutstrecd = catfileoutstr.encode();
  nullstrecd = "\0".encode();
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
 if(not compression or compression or compression=="catfile"):
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
   catfp = gzip.open(outfile, "wb", compresslevel=compressionlevel);
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
 fileheader = AppendNullByte("CatFile" + fileheaderver);
 catfp.write(fileheader.encode());
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
  fcontents = "".encode();
  if(ftype==0):
   fcontents = zipfp.read(member.filename);
  ftypehex = format(ftype, 'x').lower();
  extrafields = format(len(extradata), 'x').lower();
  catfileoutstr = AppendNullBytes([ftypehex, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev_minor, fdev_major, frdev_minor, frdev_major, extrafields]);
  if(len(extradata)>0):
   catfileoutstr = catfileoutstr + AppendNullBytes(extradata);
  catfileoutstr = catfileoutstr + AppendNullByte(checksumtype);
  catfhend = (catfp.tell() - 1) + len(catfileoutstr);
  catfcontentstart = catfp.tell() + len(catfileoutstr);
  if(checksumtype=="none" or checksumtype==""):
   catfileheadercshex = format(0, 'x').lower();
   catfilecontentcshex = format(0, 'x').lower();
  if(checksumtype=="crc16" or checksumtype=="crc16_ansi" or checksumtype=="crc16_ibm"):
   catfileheadercshex = format(crc16(catfileoutstr.encode()) & 0xffff, '04x').lower();
   catfilecontentcshex = format(crc16(fcontents) & 0xffff, '04x').lower();
  if(checksumtype=="crc16_ccitt"):
   catfileheadercshex = format(crc16_ccitt(catfileoutstr.encode()) & 0xffff, '04x').lower();
   catfilecontentcshex = format(crc16_ccitt(fcontents) & 0xffff, '04x').lower();
  elif(checksumtype=="adler32"):
   catfileheadercshex = format(zlib.adler32(catfileoutstr.encode()) & 0xffffffff, '08x').lower();
   catfilecontentcshex = format(zlib.adler32(fcontents) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc32"):
   catfileheadercshex = format(crc32(catfileoutstr.encode()) & 0xffffffff, '08x').lower();
   catfilecontentcshex = format(crc32(fcontents) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc64_ecma"):
   catfileheadercshex = format(crc64_ecma(catfileoutstr.encode()) & 0xffffffffffffffff, '016x').lower();
   catfilecontentcshex = format(crc64_ecma(fcontents) & 0xffffffffffffffff, '016x').lower();
  elif(checksumtype=="crc64" or checksumtype=="crc64_iso"):
   catfileheadercshex = format(crc64_iso(catfileoutstr.encode()) & 0xffffffffffffffff, '016x').lower();
   catfilecontentcshex = format(crc64_iso(fcontents) & 0xffffffffffffffff, '016x').lower();
  elif(CheckSumSupportAlt(checksumtype, hashlib_guaranteed)):
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(catfileoutstr.encode());
   catfileheadercshex = checksumoutstr.hexdigest().lower();
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(fcontents);
   catfilecontentcshex = checksumoutstr.hexdigest().lower();
  catfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex]);
  catfileoutstrecd = catfileoutstr.encode();
  nullstrecd = "\0".encode();
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
  if(checkcompressfile!="catfile"):
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
  if(checkcompressfile!="catfile"):
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
   catfp = gzip.open(infile, "rb");
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
  if(compresscheck=="lzma"):
   try:
    import lzma;
   except ImportError:
    return False;
   catfp = lzma.open(infile, "rb");
  if(compresscheck=="catfile"):
   catfp = open(infile, "rb");
 try:
  catfp.seek(0, 2);
 except OSError:
  SeekToEndOfFile(catfp);
 except ValueError:
  SeekToEndOfFile(catfp);
 CatSize = catfp.tell();
 CatSizeEnd = CatSize;
 try:
  catfp.seek(0, 0);
 except OSError:
  return False;
 except ValueError:
  return False;
 catstring = ReadFileHeaderData(catfp, 1)[0];
 catversion = int(re.findall(r"([\d]+)$", catstring)[0], 16);
 catlist = {};
 fileidnum = 0;
 if(seekstart!=0):
  catfp.seek(seekstart, 0);
 if(seekstart==0):
  seekstart = catfp.tell();
 if(seekend==0):
  seekend = CatSizeEnd;
 while(seekstart<seekend):
  catfhstart = catfp.tell();
  catheaderdata = ReadFileHeaderData(catfp, 21);
  catftype = int(catheaderdata[0], 16);
  if(re.findall("^[.|/]", catheaderdata[1])):
   catfname = catheaderdata[1];
  else:
   catfname = "./"+catheaderdata[1];
  catfbasedir = os.path.dirname(catfname);
  catflinkname = catheaderdata[2];
  catfsize = int(catheaderdata[3], 16);
  catfatime = int(catheaderdata[4], 16);
  catfmtime = int(catheaderdata[5], 16);
  catfctime = int(catheaderdata[6], 16);
  catfbtime = int(catheaderdata[7], 16);
  catfmode = int(catheaderdata[8], 16);
  catfchmode = stat.S_IMODE(catfmode);
  catftypemod = stat.S_IFMT(catfmode);
  catfuid = int(catheaderdata[9], 16);
  catfuname = catheaderdata[10];
  catfgid = int(catheaderdata[11], 16);
  catfgname = catheaderdata[12];
  fid = int(catheaderdata[13], 16);
  finode = int(catheaderdata[14], 16);
  flinkcount = int(catheaderdata[15], 16);
  catfdev_minor = int(catheaderdata[16], 16);
  catfdev_major = int(catheaderdata[17], 16);
  catfrdev_minor = int(catheaderdata[18], 16);
  catfrdev_major = int(catheaderdata[19], 16);
  catfextrafields = int(catheaderdata[20], 16);
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
  if(catfchecksumtype=="crc16" or catfchecksumtype=="crc16_ansi" or catfchecksumtype=="crc16_ibm"):
   catnewfcs = format(crc16(hout.encode()) & 0xffff, '04x').lower();
  elif(catfchecksumtype=="adler32"):
   catnewfcs = format(zlib.adler32(hout.encode()) & 0xffffffff, '08x').lower();
  elif(catfchecksumtype=="crc32"):
   catnewfcs = format(crc32(hout.encode()) & 0xffffffff, '08x').lower();
  elif(catfchecksumtype=="crc64_ecma"):
   catnewfcs = format(crc64_ecma(hout.encode()) & 0xffffffffffffffff, '016x').lower();
  elif(catfchecksumtype=="crc64" or catfchecksumtype=="crc64_iso"):
   catnewfcs = format(crc64_iso(hout.encode()) & 0xffffffffffffffff, '016x').lower();
  elif(CheckSumSupportAlt(catfchecksumtype, hashlib_guaranteed)):
   checksumoutstr = hashlib.new(catfchecksumtype);
   checksumoutstr.update(hout.encode());
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
   if(catfchecksumtype=="crc16" or catfchecksumtype=="crc16_ansi" or catfchecksumtype=="crc16_ibm"):
    catnewfccs = format(crc16(catfcontents) & 0xffff, '04x').lower();
   if(catfchecksumtype=="crc16_ccitt"):
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
  catlist.update({fileidnum: {'catfileversion': catversion, 'fid': fileidnum, 'fhstart': catfhstart, 'fhend': catfhend, 'ftype': catftype, 'fname': catfname, 'fbasedir': catfbasedir, 'flinkname': catflinkname, 'fsize': catfsize, 'fatime': catfatime, 'fmtime': catfmtime, 'fctime': catfctime, 'fbtime': catfbtime, 'fmode': catfmode, 'fchmode': catfchmode, 'ftypemod': catftypemod, 'fuid': catfuid, 'funame': catfuname, 'fgid': catfgid, 'fgname': catfgname, 'finode': finode, 'flinkcount': flinkcount, 'fminor': catfdev_minor, 'fmajor': catfdev_major, 'frminor': catfrdev_minor, 'frmajor': catfrdev_major, 'fchecksumtype': catfchecksumtype, 'fnumfields': catfnumfields, 'fextrafields': catfextrafields, 'fextralist': extrafieldslist, 'fheaderchecksum': catfcs, 'fcontentchecksum': catfccs, 'fhascontents': pyhascontents, 'fcontentstart': catfcontentstart, 'fcontentend': catfcontentend, 'fcontents': catfcontents} });
  catfp.seek(1, 1);
  seekstart = catfp.tell();
  fileidnum = fileidnum + 1;
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
 catout = CatFileToArray(catfp, seekstart, seekend, listonly, skipchecksum, returnfp);
 return catout;

def ZipFileToArray(infile, seekstart=0, seekend=0, listonly=False, skipchecksum=False, returnfp=False):
 catfp = BytesIO();
 catfp = PackCatFileFromZipFile(infile, catfp, "auto", None, "crc32", False, True);
 catout = CatFileToArray(catfp, seekstart, seekend, listonly, skipchecksum, returnfp);
 return catout;

def ListDirToArrayAlt(infiles, dirlistfromtxt=False, followlink=False, listonly=False, checksumtype="crc32", extradata=[], verbose=False):
 catver = __cat_header_ver__;
 fileheaderver = str(int(catver.replace(".", "")));
 fileheader = AppendNullByte("CatFile" + fileheaderver);
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
 catlist = {};
 fileidnum = 0;
 fheadtell = 0;
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
  if(not followlink):
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
  fcontents = "".encode();
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
  catfileoutstr = AppendNullBytes([ftypehex, fname, flinkname, format(int(fsize), 'x').lower(), format(int(fatime), 'x').lower(), format(int(fmtime), 'x').lower(), format(int(fctime), 'x').lower(), format(int(fbtime), 'x').lower(), format(int(fmode), 'x').lower(), format(int(fuid), 'x').lower(), funame, format(int(fgid), 'x').lower(), fgname, format(int(fcurfid), 'x').lower(), format(int(fcurinode), 'x').lower(), format(int(flinkcount), 'x').lower(), format(int(fdev_minor), 'x').lower(), format(int(fdev_major), 'x').lower(), format(int(frdev_minor), 'x').lower(), format(int(frdev_major), 'x').lower(), format(catfextrafields, 'x').lower()]);
  if(len(extradata)>0):
   catfileoutstr = catfileoutstr + AppendNullBytes(extradata);
  catfileoutstr = catfileoutstr + AppendNullByte(checksumtype);
  catfnumfields = 24 + catfextrafields;
  if(checksumtype=="none" or checksumtype==""):
   catfileheadercshex = format(0, 'x').lower();
   catfilecontentcshex = format(0, 'x').lower();
  if(checksumtype=="crc16" or checksumtype=="crc16_ansi" or checksumtype=="crc16_ibm"):
   catfileheadercshex = format(crc16(catfileoutstr.encode()) & 0xffff, '04x').lower();
   catfilecontentcshex = format(crc16(fcontents) & 0xffff, '04x').lower();
  if(checksumtype=="crc16_ccitt"):
   catfileheadercshex = format(crc16_ccitt(catfileoutstr.encode()) & 0xffff, '04x').lower();
   catfilecontentcshex = format(crc16_ccitt(fcontents) & 0xffff, '04x').lower();
  elif(checksumtype=="adler32"):
   catfileheadercshex = format(zlib.adler32(catfileoutstr.encode()) & 0xffffffff, '08x').lower();
   catfilecontentcshex = format(zlib.adler32(fcontents) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc32"):
   catfileheadercshex = format(crc32(catfileoutstr.encode()) & 0xffffffff, '08x').lower();
   catfilecontentcshex = format(crc32(fcontents) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc64_ecma"):
   catfileheadercshex = format(crc64_ecma(catfileoutstr.encode()) & 0xffffffffffffffff, '016x').lower();
   catfilecontentcshex = format(crc64_ecma(fcontents) & 0xffffffffffffffff, '016x').lower();
  elif(checksumtype=="crc64" or checksumtype=="crc64_iso"):
   catfileheadercshex = format(crc64_iso(catfileoutstr.encode()) & 0xffffffffffffffff, '016x').lower();
   catfilecontentcshex = format(crc64_iso(fcontents) & 0xffffffffffffffff, '016x').lower();
  elif(CheckSumSupportAlt(checksumtype, hashlib_guaranteed)):
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(catfileoutstr.encode());
   catfileheadercshex = checksumoutstr.hexdigest().lower();
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(fcontents);
   catfilecontentcshex = checksumoutstr.hexdigest().lower();
  catfhstart = fheadtell;
  fheadtell += len(catfileoutstr);
  catfhend = fheadtell - 1;
  catfcontentstart = fheadtell;
  catfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex]);
  catfileoutstrecd = catfileoutstr.encode();
  nullstrecd = "\0".encode();
  fheadtell += len(catfileoutstr) + 1;
  catfcontentend = fheadtell - 1;
  catfileout = catfileoutstrecd + fcontents + nullstrecd;
  pyhascontents = False;
  if(int(fsize)>0 and not listonly):
   pyhascontents = True;
  if(int(fsize)>0 and listonly):
   fcontents = "";
   pyhascontents = False;
  catlist.update({fileidnum: {'catfileversion': catversion, 'fid': fileidnum, 'fhstart': catfhstart, 'fhend': catfhend, 'ftype': ftype, 'fname': fname, 'fbasedir': fbasedir, 'flinkname': flinkname, 'fsize': fsize, 'fatime': fatime, 'fmtime': fmtime, 'fctime': fctime, 'fbtime': fbtime, 'fmode': fmode, 'fchmode': fchmode, 'ftypemod': ftypemod, 'fuid': fuid, 'funame': funame, 'fgid': fgid, 'fgname': fgname, 'finode': finode, 'flinkcount': flinkcount, 'fminor': fdev_minor, 'fmajor': fdev_major, 'frminor': frdev_minor, 'frmajor': frdev_major, 'fchecksumtype': checksumtype, 'fnumfields': catfnumfields, 'fextrafields': catfextrafields, 'fextralist': extrafieldslist, 'fheaderchecksum': int(catfileheadercshex, 16), 'fcontentchecksum': int(catfilecontentcshex, 16), 'fhascontents': pyhascontents, 'fcontentstart': catfcontentstart, 'fcontentend': catfcontentend, 'fcontents': fcontents} });
  fileidnum = fileidnum + 1;
 return catlist;

def TarFileToArrayAlt(infiles, dirlistfromtxt=False, listonly=False, checksumtype="crc32", extradata=[], verbose=False):
 catver = __cat_header_ver__;
 fileheaderver = str(int(catver.replace(".", "")));
 fileheader = AppendNullByte("CatFile" + fileheaderver);
 catversion = fileheaderver;
 curinode = 0;
 curfid = 0;
 inodelist = [];
 inodetofile = {};
 filetoinode = {};
 inodetocatinode = {};
 catlist = {};
 fileidnum = 0;
 fheadtell = 0;
 if(not os.path.exists(infiles) or not os.path.isfile(infiles)):
  return False;
 try:
  if(not tarfile.is_tarfile(infiles)):
   return False;
 except AttributeError:
  if(not is_tarfile(infiles)):
   return False;
 tarfp = tarfile.open(infiles, "r");
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
  fcontents = "".encode();
  if(ftype==0 or ftype==7):
   fpc = tarfp.extractfile(member);
   fcontents = fpc.read(int(member.size));
   fpc.close();
  ftypehex = format(ftype, 'x').lower();
  extrafields = len(extradata);
  extrafieldslist = extradata;
  catfextrafields = extrafields;
  catfileoutstr = AppendNullBytes([ftypehex, fname, flinkname, format(int(fsize), 'x').lower(), format(int(fatime), 'x').lower(), format(int(fmtime), 'x').lower(), format(int(fctime), 'x').lower(), format(int(fbtime), 'x').lower(), format(int(fmode), 'x').lower(), format(int(fuid), 'x').lower(), funame, format(int(fgid), 'x').lower(), fgname, format(int(fcurfid), 'x').lower(), format(int(fcurinode), 'x').lower(), format(int(flinkcount), 'x').lower(), format(int(fdev_minor), 'x').lower(), format(int(fdev_major), 'x').lower(), format(int(frdev_minor), 'x').lower(), format(int(frdev_major), 'x').lower(), format(catfextrafields, 'x').lower()]);
  if(len(extradata)>0):
   catfileoutstr = catfileoutstr + AppendNullBytes(extradata);
  catfileoutstr = catfileoutstr + AppendNullByte(checksumtype);
  catfnumfields = 24 + catfextrafields;
  if(checksumtype=="none" or checksumtype==""):
   catfileheadercshex = format(0, 'x').lower();
   catfilecontentcshex = format(0, 'x').lower();
  if(checksumtype=="crc16" or checksumtype=="crc16_ansi" or checksumtype=="crc16_ibm"):
   catfileheadercshex = format(crc16(catfileoutstr.encode()) & 0xffff, '04x').lower();
   catfilecontentcshex = format(crc16(fcontents) & 0xffff, '04x').lower();
  if(checksumtype=="crc16_ccitt"):
   catfileheadercshex = format(crc16_ccitt(catfileoutstr.encode()) & 0xffff, '04x').lower();
   catfilecontentcshex = format(crc16_ccitt(fcontents) & 0xffff, '04x').lower();
  elif(checksumtype=="adler32"):
   catfileheadercshex = format(zlib.adler32(catfileoutstr.encode()) & 0xffffffff, '08x').lower();
   catfilecontentcshex = format(zlib.adler32(fcontents) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc32"):
   catfileheadercshex = format(crc32(catfileoutstr.encode()) & 0xffffffff, '08x').lower();
   catfilecontentcshex = format(crc32(fcontents) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc64_ecma"):
   catfileheadercshex = format(crc64_ecma(catfileoutstr.encode()) & 0xffffffffffffffff, '016x').lower();
   catfilecontentcshex = format(crc64_ecma(fcontents) & 0xffffffffffffffff, '016x').lower();
  elif(checksumtype=="crc64" or checksumtype=="crc64_iso"):
   catfileheadercshex = format(crc64_iso(catfileoutstr.encode()) & 0xffffffffffffffff, '016x').lower();
   catfilecontentcshex = format(crc64_iso(fcontents) & 0xffffffffffffffff, '016x').lower();
  elif(CheckSumSupportAlt(checksumtype, hashlib_guaranteed)):
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(catfileoutstr.encode());
   catfileheadercshex = checksumoutstr.hexdigest().lower();
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(fcontents);
   catfilecontentcshex = checksumoutstr.hexdigest().lower();
  catfhstart = fheadtell;
  fheadtell += len(catfileoutstr);
  catfhend = fheadtell - 1;
  catfcontentstart = fheadtell;
  catfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex]);
  catfileoutstrecd = catfileoutstr.encode();
  nullstrecd = "\0".encode();
  fheadtell += len(catfileoutstr) + 1;
  catfcontentend = fheadtell - 1;
  catfileout = catfileoutstrecd + fcontents + nullstrecd;
  pyhascontents = False;
  if(int(fsize)>0 and not listonly):
   pyhascontents = True;
  if(int(fsize)>0 and listonly):
   fcontents = "";
   pyhascontents = False;
  catlist.update({fileidnum: {'catfileversion': catversion, 'fid': fileidnum, 'fhstart': catfhstart, 'fhend': catfhend, 'ftype': ftype, 'fname': fname, 'fbasedir': fbasedir, 'flinkname': flinkname, 'fsize': fsize, 'fatime': fatime, 'fmtime': fmtime, 'fctime': fctime, 'fbtime': fbtime, 'fmode': fmode, 'fchmode': fchmode, 'ftypemod': ftypemod, 'fuid': fuid, 'funame': funame, 'fgid': fgid, 'fgname': fgname, 'finode': finode, 'flinkcount': flinkcount, 'fminor': fdev_minor, 'fmajor': fdev_major, 'frminor': frdev_minor, 'frmajor': frdev_major, 'fchecksumtype': checksumtype, 'fnumfields': catfnumfields, 'fextrafields': catfextrafields, 'fextralist': extrafieldslist, 'fheaderchecksum': int(catfileheadercshex, 16), 'fcontentchecksum': int(catfilecontentcshex, 16), 'fhascontents': pyhascontents, 'fcontentstart': catfcontentstart, 'fcontentend': catfcontentend, 'fcontents': fcontents} });
  fileidnum = fileidnum + 1;
 return catlist;

def ZipFileToArrayAlt(infiles, dirlistfromtxt=False, listonly=False, checksumtype="crc32", extradata=[], verbose=False):
 catver = __cat_header_ver__;
 fileheaderver = str(int(catver.replace(".", "")));
 fileheader = AppendNullByte("CatFile" + fileheaderver);
 catversion = fileheaderver;
 advancedlist = True;
 curinode = 0;
 curfid = 0;
 inodelist = [];
 inodetofile = {};
 filetoinode = {};
 inodetocatinode = {};
 catlist = {};
 fileidnum = 0;
 fheadtell = 0;
 if(not os.path.exists(infiles) or not os.path.isfile(infiles)):
  return False;
 if(not zipfile.is_zipfile(infiles)):
  return False;
 zipfp = zipfile.ZipFile(infiles, "r", allowZip64=True);
 ziptest = zipfp.testzip();
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
  fcontents = "".encode();
  if(ftype==0):
   fcontents = zipfp.read(member.filename);
  ftypehex = format(ftype, 'x').lower();
  extrafields = len(extradata);
  extrafieldslist = extradata;
  catfextrafields = extrafields;
  catfileoutstr = AppendNullBytes([ftypehex, fname, flinkname, format(int(fsize), 'x').lower(), format(int(fatime), 'x').lower(), format(int(fmtime), 'x').lower(), format(int(fctime), 'x').lower(), format(int(fbtime), 'x').lower(), format(int(fmode), 'x').lower(), format(int(fuid), 'x').lower(), funame, format(int(fgid), 'x').lower(), fgname, format(int(fcurfid), 'x').lower(), format(int(fcurinode), 'x').lower(), format(int(flinkcount), 'x').lower(), format(int(fdev_minor), 'x').lower(), format(int(fdev_major), 'x').lower(), format(int(frdev_minor), 'x').lower(), format(int(frdev_major), 'x').lower(), format(catfextrafields, 'x').lower()]);
  if(len(extradata)>0):
   catfileoutstr = catfileoutstr + AppendNullBytes(extradata);
  catfileoutstr = catfileoutstr + AppendNullByte(checksumtype);
  catfnumfields = 24 + catfextrafields;
  if(checksumtype=="none" or checksumtype==""):
   catfileheadercshex = format(0, 'x').lower();
   catfilecontentcshex = format(0, 'x').lower();
  if(checksumtype=="crc16" or checksumtype=="crc16_ansi" or checksumtype=="crc16_ibm"):
   catfileheadercshex = format(crc16(catfileoutstr.encode()) & 0xffff, '04x').lower();
   catfilecontentcshex = format(crc16(fcontents) & 0xffff, '04x').lower();
  if(checksumtype=="crc16_ccitt"):
   catfileheadercshex = format(crc16_ccitt(catfileoutstr.encode()) & 0xffff, '04x').lower();
   catfilecontentcshex = format(crc16_ccitt(fcontents) & 0xffff, '04x').lower();
  elif(checksumtype=="adler32"):
   catfileheadercshex = format(zlib.adler32(catfileoutstr.encode()) & 0xffffffff, '08x').lower();
   catfilecontentcshex = format(zlib.adler32(fcontents) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc32"):
   catfileheadercshex = format(crc32(catfileoutstr.encode()) & 0xffffffff, '08x').lower();
   catfilecontentcshex = format(crc32(fcontents) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc64_ecma"):
   catfileheadercshex = format(crc64_ecma(catfileoutstr.encode()) & 0xffffffffffffffff, '016x').lower();
   catfilecontentcshex = format(crc64_ecma(fcontents) & 0xffffffffffffffff, '016x').lower();
  elif(checksumtype=="crc64" or checksumtype=="crc64_iso"):
   catfileheadercshex = format(crc64_iso(catfileoutstr.encode()) & 0xffffffffffffffff, '016x').lower();
   catfilecontentcshex = format(crc64_iso(fcontents) & 0xffffffffffffffff, '016x').lower();
  elif(CheckSumSupportAlt(checksumtype, hashlib_guaranteed)):
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(catfileoutstr.encode());
   catfileheadercshex = checksumoutstr.hexdigest().lower();
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(fcontents);
   catfilecontentcshex = checksumoutstr.hexdigest().lower();
  catfhstart = fheadtell;
  fheadtell += len(catfileoutstr);
  catfhend = fheadtell - 1;
  catfcontentstart = fheadtell;
  catfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex]);
  catfileoutstrecd = catfileoutstr.encode();
  nullstrecd = "\0".encode();
  fheadtell += len(catfileoutstr) + 1;
  catfcontentend = fheadtell - 1;
  catfileout = catfileoutstrecd + fcontents + nullstrecd;
  pyhascontents = False;
  if(int(fsize)>0 and not listonly):
   pyhascontents = True;
  if(int(fsize)>0 and listonly):
   fcontents = "";
   pyhascontents = False;
  catlist.update({fileidnum: {'catfileversion': catversion, 'fid': fileidnum, 'fhstart': catfhstart, 'fhend': catfhend, 'ftype': ftype, 'fname': fname, 'fbasedir': fbasedir, 'flinkname': flinkname, 'fsize': fsize, 'fatime': fatime, 'fmtime': fmtime, 'fctime': fctime, 'fbtime': fbtime, 'fmode': fmode, 'fchmode': fchmode, 'ftypemod': ftypemod, 'fuid': fuid, 'funame': funame, 'fgid': fgid, 'fgname': fgname, 'finode': finode, 'flinkcount': flinkcount, 'fminor': fdev_minor, 'fmajor': fdev_major, 'frminor': frdev_minor, 'frmajor': frdev_major, 'fchecksumtype': checksumtype, 'fnumfields': catfnumfields, 'fextrafields': catfextrafields, 'fextralist': extrafieldslist, 'fheaderchecksum': int(catfileheadercshex, 16), 'fcontentchecksum': int(catfilecontentcshex, 16), 'fhascontents': pyhascontents, 'fcontentstart': catfcontentstart, 'fcontentend': catfcontentend, 'fcontents': fcontents} });
  fileidnum = fileidnum + 1;
 return catlist;

def ListDirToArray(infiles, dirlistfromtxt=False, compression="auto", compressionlevel=None, followlink=False, seekstart=0, seekend=0, listonly=False, skipchecksum=False, checksumtype="crc32", extradata=[], verbose=False, returnfp=False):
 outarray = BytesIO();
 packcat = PackCatFile(infiles, outarray, dirlistfromtxt, compression, compressionlevel, followlink, checksumtype, extradata, verbose, True);
 catout = CatFileToArray(outarray, seekstart, seekend, listonly, skipchecksum, returnfp);
 return catout;

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
 lcfi = 0;
 lcfx = len(listcatfiles);
 while(lcfi < lcfx):
  filetoidarray = {listcatfiles[lcfi]['fname']: listcatfiles[lcfi]['fid']};
  idtofilearray = {listcatfiles[lcfi]['fid']: listcatfiles[lcfi]['fname']};
  catarray['filetoid'].update(filetoidarray);
  catarray['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==0 or listcatfiles[lcfi]['ftype']==7):
   catarray['filetypes']['files']['filetoid'].update(filetoidarray);
   catarray['filetypes']['files']['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==1):
   catarray['filetypes']['hardlinks']['filetoid'].update(filetoidarray);
   catarray['filetypes']['hardlinks']['idtofile'].update(idtofilearray);
   catarray['filetypes']['links']['filetoid'].update(filetoidarray);
   catarray['filetypes']['links']['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==2):
   catarray['filetypes']['symlinks']['filetoid'].update(filetoidarray);
   catarray['filetypes']['symlinks']['idtofile'].update(idtofilearray);
   catarray['filetypes']['links']['filetoid'].update(filetoidarray);
   catarray['filetypes']['links']['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==3):
   catarray['filetypes']['character']['filetoid'].update(filetoidarray);
   catarray['filetypes']['character']['idtofile'].update(idtofilearray);
   catarray['filetypes']['devices']['filetoid'].update(filetoidarray);
   catarray['filetypes']['devices']['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==4):
   catarray['filetypes']['block']['filetoid'].update(filetoidarray);
   catarray['filetypes']['block']['idtofile'].update(idtofilearray);
   catarray['filetypes']['devices']['filetoid'].update(filetoidarray);
   catarray['filetypes']['devices']['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==5):
   catarray['filetypes']['directories']['filetoid'].update(filetoidarray);
   catarray['filetypes']['directories']['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==6):
   catarray['filetypes']['symlinks']['filetoid'].update(filetoidarray);
   catarray['filetypes']['symlinks']['idtofile'].update(idtofilearray);
   catarray['filetypes']['devices']['filetoid'].update(filetoidarray);
   catarray['filetypes']['devices']['idtofile'].update(idtofilearray);
  lcfi = lcfi + 1;
 return catarray;

def ListDirToArrayIndexAlt(infiles, dirlistfromtxt=False, followlink=False, listonly=False, checksumtype="crc32", extradata=[], verbose=False):
 listcatfiles = ListDirToArrayAlt(infiles, dirlistfromtxt, followlink, listonly, checksumtype, extradata, verbose);
 print(listcatfiles);
 if(not listcatfiles):
  return False;
 catarray = {'list': listcatfiles, 'filetoid': {}, 'idtofile': {}, 'filetypes': {'directories': {'filetoid': {}, 'idtofile': {}}, 'files': {'filetoid': {}, 'idtofile': {}}, 'links': {'filetoid': {}, 'idtofile': {}}, 'symlinks': {'filetoid': {}, 'idtofile': {}}, 'hardlinks': {'filetoid': {}, 'idtofile': {}}, 'character': {'filetoid': {}, 'idtofile': {}}, 'block': {'filetoid': {}, 'idtofile': {}}, 'fifo': {'filetoid': {}, 'idtofile': {}}, 'devices': {'filetoid': {}, 'idtofile': {}}}};
 lcfi = 0;
 lcfx = len(listcatfiles);
 while(lcfi < lcfx):
  filetoidarray = {listcatfiles[lcfi]['fname']: listcatfiles[lcfi]['fid']};
  idtofilearray = {listcatfiles[lcfi]['fid']: listcatfiles[lcfi]['fname']};
  catarray['filetoid'].update(filetoidarray);
  catarray['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==0 or listcatfiles[lcfi]['ftype']==7):
   catarray['filetypes']['files']['filetoid'].update(filetoidarray);
   catarray['filetypes']['files']['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==1):
   catarray['filetypes']['hardlinks']['filetoid'].update(filetoidarray);
   catarray['filetypes']['hardlinks']['idtofile'].update(idtofilearray);
   catarray['filetypes']['links']['filetoid'].update(filetoidarray);
   catarray['filetypes']['links']['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==2):
   catarray['filetypes']['symlinks']['filetoid'].update(filetoidarray);
   catarray['filetypes']['symlinks']['idtofile'].update(idtofilearray);
   catarray['filetypes']['links']['filetoid'].update(filetoidarray);
   catarray['filetypes']['links']['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==3):
   catarray['filetypes']['character']['filetoid'].update(filetoidarray);
   catarray['filetypes']['character']['idtofile'].update(idtofilearray);
   catarray['filetypes']['devices']['filetoid'].update(filetoidarray);
   catarray['filetypes']['devices']['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==4):
   catarray['filetypes']['block']['filetoid'].update(filetoidarray);
   catarray['filetypes']['block']['idtofile'].update(idtofilearray);
   catarray['filetypes']['devices']['filetoid'].update(filetoidarray);
   catarray['filetypes']['devices']['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==5):
   catarray['filetypes']['directories']['filetoid'].update(filetoidarray);
   catarray['filetypes']['directories']['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==6):
   catarray['filetypes']['symlinks']['filetoid'].update(filetoidarray);
   catarray['filetypes']['symlinks']['idtofile'].update(idtofilearray);
   catarray['filetypes']['devices']['filetoid'].update(filetoidarray);
   catarray['filetypes']['devices']['idtofile'].update(idtofilearray);
  lcfi = lcfi + 1;
 return catarray;

def TarFileToArrayIndexAlt(infiles, dirlistfromtxt=False, listonly=False, checksumtype="crc32", extradata=[], verbose=False):
 listcatfiles = TarFileToArrayAlt(infiles, dirlistfromtxt, listonly, checksumtype, extradata, verbose);
 print(listcatfiles);
 if(not listcatfiles):
  return False;
 catarray = {'list': listcatfiles, 'filetoid': {}, 'idtofile': {}, 'filetypes': {'directories': {'filetoid': {}, 'idtofile': {}}, 'files': {'filetoid': {}, 'idtofile': {}}, 'links': {'filetoid': {}, 'idtofile': {}}, 'symlinks': {'filetoid': {}, 'idtofile': {}}, 'hardlinks': {'filetoid': {}, 'idtofile': {}}, 'character': {'filetoid': {}, 'idtofile': {}}, 'block': {'filetoid': {}, 'idtofile': {}}, 'fifo': {'filetoid': {}, 'idtofile': {}}, 'devices': {'filetoid': {}, 'idtofile': {}}}};
 lcfi = 0;
 lcfx = len(listcatfiles);
 while(lcfi < lcfx):
  filetoidarray = {listcatfiles[lcfi]['fname']: listcatfiles[lcfi]['fid']};
  idtofilearray = {listcatfiles[lcfi]['fid']: listcatfiles[lcfi]['fname']};
  catarray['filetoid'].update(filetoidarray);
  catarray['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==0 or listcatfiles[lcfi]['ftype']==7):
   catarray['filetypes']['files']['filetoid'].update(filetoidarray);
   catarray['filetypes']['files']['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==1):
   catarray['filetypes']['hardlinks']['filetoid'].update(filetoidarray);
   catarray['filetypes']['hardlinks']['idtofile'].update(idtofilearray);
   catarray['filetypes']['links']['filetoid'].update(filetoidarray);
   catarray['filetypes']['links']['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==2):
   catarray['filetypes']['symlinks']['filetoid'].update(filetoidarray);
   catarray['filetypes']['symlinks']['idtofile'].update(idtofilearray);
   catarray['filetypes']['links']['filetoid'].update(filetoidarray);
   catarray['filetypes']['links']['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==3):
   catarray['filetypes']['character']['filetoid'].update(filetoidarray);
   catarray['filetypes']['character']['idtofile'].update(idtofilearray);
   catarray['filetypes']['devices']['filetoid'].update(filetoidarray);
   catarray['filetypes']['devices']['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==4):
   catarray['filetypes']['block']['filetoid'].update(filetoidarray);
   catarray['filetypes']['block']['idtofile'].update(idtofilearray);
   catarray['filetypes']['devices']['filetoid'].update(filetoidarray);
   catarray['filetypes']['devices']['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==5):
   catarray['filetypes']['directories']['filetoid'].update(filetoidarray);
   catarray['filetypes']['directories']['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==6):
   catarray['filetypes']['symlinks']['filetoid'].update(filetoidarray);
   catarray['filetypes']['symlinks']['idtofile'].update(idtofilearray);
   catarray['filetypes']['devices']['filetoid'].update(filetoidarray);
   catarray['filetypes']['devices']['idtofile'].update(idtofilearray);
  lcfi = lcfi + 1;
 return catarray;

def ZipFileToArrayIndexAlt(infiles, dirlistfromtxt=False, listonly=False, checksumtype="crc32", extradata=[], verbose=False):
 listcatfiles = ZipFileToArrayAlt(infiles, dirlistfromtxt, listonly, checksumtype, extradata, verbose);
 print(listcatfiles);
 if(not listcatfiles):
  return False;
 catarray = {'list': listcatfiles, 'filetoid': {}, 'idtofile': {}, 'filetypes': {'directories': {'filetoid': {}, 'idtofile': {}}, 'files': {'filetoid': {}, 'idtofile': {}}, 'links': {'filetoid': {}, 'idtofile': {}}, 'symlinks': {'filetoid': {}, 'idtofile': {}}, 'hardlinks': {'filetoid': {}, 'idtofile': {}}, 'character': {'filetoid': {}, 'idtofile': {}}, 'block': {'filetoid': {}, 'idtofile': {}}, 'fifo': {'filetoid': {}, 'idtofile': {}}, 'devices': {'filetoid': {}, 'idtofile': {}}}};
 lcfi = 0;
 lcfx = len(listcatfiles);
 while(lcfi < lcfx):
  filetoidarray = {listcatfiles[lcfi]['fname']: listcatfiles[lcfi]['fid']};
  idtofilearray = {listcatfiles[lcfi]['fid']: listcatfiles[lcfi]['fname']};
  catarray['filetoid'].update(filetoidarray);
  catarray['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==0 or listcatfiles[lcfi]['ftype']==7):
   catarray['filetypes']['files']['filetoid'].update(filetoidarray);
   catarray['filetypes']['files']['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==1):
   catarray['filetypes']['hardlinks']['filetoid'].update(filetoidarray);
   catarray['filetypes']['hardlinks']['idtofile'].update(idtofilearray);
   catarray['filetypes']['links']['filetoid'].update(filetoidarray);
   catarray['filetypes']['links']['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==2):
   catarray['filetypes']['symlinks']['filetoid'].update(filetoidarray);
   catarray['filetypes']['symlinks']['idtofile'].update(idtofilearray);
   catarray['filetypes']['links']['filetoid'].update(filetoidarray);
   catarray['filetypes']['links']['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==3):
   catarray['filetypes']['character']['filetoid'].update(filetoidarray);
   catarray['filetypes']['character']['idtofile'].update(idtofilearray);
   catarray['filetypes']['devices']['filetoid'].update(filetoidarray);
   catarray['filetypes']['devices']['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==4):
   catarray['filetypes']['block']['filetoid'].update(filetoidarray);
   catarray['filetypes']['block']['idtofile'].update(idtofilearray);
   catarray['filetypes']['devices']['filetoid'].update(filetoidarray);
   catarray['filetypes']['devices']['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==5):
   catarray['filetypes']['directories']['filetoid'].update(filetoidarray);
   catarray['filetypes']['directories']['idtofile'].update(idtofilearray);
  if(listcatfiles[lcfi]['ftype']==6):
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
 catout = CatFileToArrayIndex(catfp, seekstart, seekend, listonly, skipchecksum, returnfp);
 return catout;

def ZipFileToArrayIndex(infile, seekstart=0, seekend=0, listonly=False, skipchecksum=False, returnfp=False):
 catfp = BytesIO();
 catfp = PackCatFileFromZipFile(infile, catfp, "auto", None, "crc32", False, True);
 catout = CatFileToArrayIndex(catfp, seekstart, seekend, listonly, skipchecksum, returnfp);
 return catout;

def ListDirToArrayIndex(infiles, dirlistfromtxt=False, compression="auto", compressionlevel=None, followlink=False, seekstart=0, seekend=0, listonly=False, skipchecksum=False, checksumtype="crc32", verbose=False, returnfp=False):
 outarray = BytesIO();
 packcat = PackCatFile(infiles, outarray, dirlistfromtxt, compression, compressionlevel, followlink, checksumtype, verbose, True);
 catout = CatFileToArrayIndex(outarray, seekstart, seekend, listonly, skipchecksum, returnfp)
 return catout;

def RePackCatFile(infile, outfile, compression="auto", compressionlevel=None, followlink=False, checksumtype="crc32", skipchecksum=False, extradata=[], verbose=False, returnfp=False):
 compressionlist = ['auto', 'gzip', 'bzip2', 'zstd', 'lz4', 'lzo', 'lzop', 'lzma', 'xz'];
 outextlist = ['gz', 'cgz', 'bz2', 'cbz', 'zst', 'czst', 'lz4', 'lzop', 'clz4', 'lzo', 'clzo', 'lzma', 'xz', 'cxz'];
 outextlistwd = ['.gz', '.cgz', '.bz2', '.cbz', '.zst', '.czst', '.lz4', 'lzop', '.clz4', '.lzo', '.clzo', '.lzma', '.xz', '.cxz'];
 if(isinstance(infile, dict)):
  prelistcatfiles = CatFileToArrayIndex(infile, 0, 0, False, skipchecksum, returnfp);
  listcatfiles = prelistcatfiles['list'];
 else:
  if(infile!="-" and not hasattr(infile, "read") and not hasattr(infile, "write")):
   infile = RemoveWindowsPath(infile);
  if(followlink):
   prelistcatfiles = CatFileToArrayIndex(infile, 0, 0, False, skipchecksum, returnfp);
   listcatfiles = prelistcatfiles['list'];
  else:
   listcatfiles = CatFileToArray(infile, 0, 0, False, skipchecksum, returnfp);
 if(outfile!="-" and not hasattr(infile, "read") and not hasattr(outfile, "write")):
  outfile = RemoveWindowsPath(outfile);
 checksumtype = checksumtype.lower();
 if(not CheckSumSupport(checksumtype, hashlib_guaranteed)):
  checksumtype="crc32";
 if(checksumtype=="none"):
  checksumtype = "";
 if(not compression or compression or compression=="catfile"):
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
   catfp = gzip.open(outfile, "wb", compresslevel=compressionlevel);
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
 fileheader = AppendNullByte("CatFile" + fileheaderver);
 catfp.write(fileheader.encode());
 lcfi = 0;
 lcfx = len(listcatfiles);
 curinode = 0;
 curfid = 0;
 inodelist = [];
 inodetofile = {};
 filetoinode = {};
 while(lcfi < lcfx):
  catfhstart = catfp.tell();
  if(re.findall("^[.|/]", listcatfiles[lcfi]['fname'])):
   fname = listcatfiles[lcfi]['fname'];
  else:
   fname = "./"+listcatfiles[lcfi]['fname'];
  if(verbose):
   VerbosePrintOut(fname);
  fsize = format(int(listcatfiles[lcfi]['fsize']), 'x').lower();
  flinkname = listcatfiles[lcfi]['flinkname'];
  fatime = format(int(listcatfiles[lcfi]['fatime']), 'x').lower();
  fmtime = format(int(listcatfiles[lcfi]['fmtime']), 'x').lower();
  fctime = format(int(listcatfiles[lcfi]['fctime']), 'x').lower();
  fbtime = format(int(listcatfiles[lcfi]['fbtime']), 'x').lower();
  fmode = format(int(int(listcatfiles[lcfi]['fmode'], 8)), 'x').lower();
  fchmode = format(int(int(listcatfiles[lcfi]['fchmode'], 8)), 'x').lower();
  fuid = format(int(listcatfiles[lcfi]['fuid']), 'x').lower();
  funame = listcatfiles[lcfi]['funame'];
  fgid = format(int(listcatfiles[lcfi]['fgid']), 'x').lower();
  fgname = listcatfiles[lcfi]['fgname'];
  finode = listcatfiles[lcfi]['finode'];
  flinkcount = listcatfiles[lcfi]['flinkcount'];
  fdev_minor = format(int(listcatfiles[lcfi]['fminor']), 'x').lower();
  fdev_major = format(int(listcatfiles[lcfi]['fmajor']), 'x').lower();
  frdev_minor = format(int(listcatfiles[lcfi]['frminor']), 'x').lower();
  frdev_major = format(int(listcatfiles[lcfi]['frmajor']), 'x').lower();
  fcontents = listcatfiles[lcfi]['fcontents'];
  if(followlink):
   if(listcatfiles[lcfi]['ftype']==1 or listcatfiles[lcfi]['ftype']==2):
    getflinkpath = listcatfiles[lcfi]['flinkname'];
    flinkid = prelistcatfiles['filetoid'][getflinkpath];
    flinkinfo = listcatfiles[flinkid];
    fsize = format(int(flinkinfo['fsize']), 'x').lower();
    flinkname = flinkinfo['flinkname'];
    fatime = format(int(flinkinfo['fatime']), 'x').lower();
    fmtime = format(int(flinkinfo['fmtime']), 'x').lower();
    fctime = format(int(flinkinfo['fctime']), 'x').lower();
    fbtime = format(int(flinkinfo['fbtime']), 'x').lower();
    fmode = format(int(int(flinkinfo['fmode'], 8)), 'x').lower();
    fchmode = format(int(int(flinkinfo['fchmode'], 8)), 'x').lower();
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
    fcontents = flinkinfo['fcontents'];
    if(flinkinfo['ftype']!=0 and flinkinfo['ftype']!=7):
     fcontents = fcontents.encode();
    ftypehex = format(flinkinfo['ftype'], 'x').lower();
  else:
   if(listcatfiles[lcfi]['ftype']!=0 and listcatfiles[lcfi]['ftype']!=7):
    fcontents = fcontents.encode();
   ftypehex = format(listcatfiles[lcfi]['ftype'], 'x').lower();
  fcurfid = format(curfid, 'x').lower();
  if(not followlink):
   if(flinkinfo['ftype']!=1):
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
  if(len(listcatfiles[lcfi]['fextralist'])>listcatfiles[lcfi]['fextrafields'] and len(listcatfiles[lcfi]['fextralist'])>0):
   listcatfiles[lcfi]['fextrafields'] = len(listcatfiles[lcfi]['fextralist']);
  if(len(extradata) > 0):
   listcatfiles[lcfi]['fextrafields'] = len(extradata);
   listcatfiles[lcfi]['fextralist'] = extradata;
  extrafields = format(int(listcatfiles[lcfi]['fextrafields']), 'x').lower();
  catfileoutstr = AppendNullBytes([ftypehex, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev_minor, fdev_major, frdev_minor, frdev_major, extrafields]);
  if(listcatfiles[lcfi]['fextrafields']>0):
   extrafieldslist = [];
   exi = 0;
   exil = listcatfiles[lcfi]['fextrafields'];
   while(exi < exil):
    extrafieldslist.append(listcatfiles[lcfi]['fextralist']);
    exi = exi + 1;
   catfileoutstr += AppendNullBytes([extrafieldslist]);
  catfileoutstr += AppendNullBytes([checksumtype]);
  catfhend = (catfp.tell() - 1) + len(catfileoutstr);
  catfcontentstart = catfp.tell() + len(catfileoutstr);
  if(checksumtype=="none" or checksumtype==""):
   catfileheadercshex = format(0, 'x').lower();
   catfilecontentcshex = format(0, 'x').lower();
  if(checksumtype=="crc16" or checksumtype=="crc16_ansi" or checksumtype=="crc16_ibm"):
   catfileheadercshex = format(crc16(catfileoutstr.encode()) & 0xffff, '04x').lower();
   catfilecontentcshex = format(crc16(fcontents) & 0xffff, '04x').lower();
  if(checksumtype=="crc16_ccitt"):
   catfileheadercshex = format(crc16_ccitt(catfileoutstr.encode()) & 0xffff, '04x').lower();
   catfilecontentcshex = format(crc16_ccitt(fcontents) & 0xffff, '04x').lower();
  elif(checksumtype=="adler32"):
   catfileheadercshex = format(zlib.adler32(catfileoutstr.encode()) & 0xffffffff, '08x').lower();
   catfilecontentcshex = format(zlib.adler32(fcontents) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc32"):
   catfileheadercshex = format(crc32(catfileoutstr.encode()) & 0xffffffff, '08x').lower();
   catfilecontentcshex = format(crc32(fcontents) & 0xffffffff, '08x').lower();
  elif(checksumtype=="crc64_ecma"):
   catfileheadercshex = format(crc64_ecma(catfileoutstr.encode()) & 0xffffffffffffffff, '016x').lower();
   catfilecontentcshex = format(crc64_ecma(fcontents) & 0xffffffffffffffff, '016x').lower();
  elif(checksumtype=="crc64" or checksumtype=="crc64_iso"):
   catfileheadercshex = format(crc64_iso(catfileoutstr.encode()) & 0xffffffffffffffff, '016x').lower();
   catfilecontentcshex = format(crc64_iso(fcontents) & 0xffffffffffffffff, '016x').lower();
  elif(CheckSumSupportAlt(checksumtype, hashlib_guaranteed)):
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(catfileoutstr.encode());
   catfileheadercshex = checksumoutstr.hexdigest().lower();
   checksumoutstr = hashlib.new(checksumtype);
   checksumoutstr.update(fcontents);
   catfilecontentcshex = checksumoutstr.hexdigest().lower();
  catfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex]);
  catfileoutstrecd = catfileoutstr.encode();
  nullstrecd = "\0".encode();
  catfileout = catfileoutstrecd + fcontents + nullstrecd;
  catfcontentend = (catfp.tell() - 1) + len(catfileout);
  catfp.write(catfileout);
  lcfi = lcfi + 1;
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
 catout = RePackCatFile(outarray, outfile, compression, compressionlevel, checksumtype, skipchecksum, extradata, verbose, returnfp);
 return catout;

def UnPackCatFile(infile, outdir=None, followlink=False, skipchecksum=False, verbose=False, returnfp=False):
 if(outdir is not None):
  outdir = RemoveWindowsPath(outdir);
 if(verbose):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(isinstance(infile, dict)):
  prelistcatfiles = CatFileToArrayIndex(infile, 0, 0, False, skipchecksum, returnfp);
  listcatfiles = prelistcatfiles['list'];
 else:
  if(infile!="-" and not hasattr(infile, "read") and not hasattr(infile, "write")):
   infile = RemoveWindowsPath(infile);
  if(followlink):
   prelistcatfiles = CatFileToArrayIndex(infile, 0, 0, False, skipchecksum, returnfp);
   listcatfiles = prelistcatfiles['list'];
  else:
   listcatfiles = CatFileToArray(infile, 0, 0, False, skipchecksum, returnfp);
 if(not listcatfiles):
  return False;
 lcfi = 0;
 lcfx = len(listcatfiles);
 while(lcfi < lcfx):
  funame = "";
  try:
   import pwd;
   try:
    userinfo = pwd.getpwuid(listcatfiles[lcfi]['fuid']);
    funame = userinfo.pw_name;
   except KeyError:
    funame = "";
  except ImportError:
   funame = "";
  fgname = "";
  try:
   import grp;
   try:
    groupinfo = grp.getgrgid(listcatfiles[lcfi]['fgid']);
    fgname = groupinfo.gr_name;
   except KeyError:
    fgname = "";
  except ImportError:
   fgname = "";
  if(verbose):
   VerbosePrintOut(listcatfiles[lcfi]['fname']);
  if(listcatfiles[lcfi]['ftype']==0 or listcatfiles[lcfi]['ftype']==7):
   fpc = open(listcatfiles[lcfi]['fname'], "wb");
   fpc.write(listcatfiles[lcfi]['fcontents']);
   fpc.close();
   if(hasattr(os, "chown") and funame==listcatfiles[lcfi]['funame'] and fgname==listcatfiles[lcfi]['fgname']):
    os.chown(listcatfiles[lcfi]['fname'], listcatfiles[lcfi]['fuid'], listcatfiles[lcfi]['fgid']);
   os.chmod(listcatfiles[lcfi]['fname'], int(listcatfiles[lcfi]['fchmode'], 8));
   os.utime(listcatfiles[lcfi]['fname'], (listcatfiles[lcfi]['fatime'], listcatfiles[lcfi]['fmtime']));
  if(listcatfiles[lcfi]['ftype']==1):
   if(followlink):
    getflinkpath = listcatfiles[lcfi]['flinkname'];
    flinkid = prelistcatfiles['filetoid'][getflinkpath];
    flinkinfo = listcatfiles[flinkid];
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
     fpc = open(listcatfiles[lcfi]['fname'], "wb");
     fpc.write(flinkinfo['fcontents']);
     fpc.close();
     if(hasattr(os, "chown") and funame==flinkinfo['funame'] and fgname==flinkinfo['fgname']):
      os.chown(listcatfiles[lcfi]['fname'], flinkinfo['fuid'], flinkinfo['fgid']);
     os.chmod(listcatfiles[lcfi]['fname'], int(flinkinfo['fchmode'], 8));
     os.utime(listcatfiles[lcfi]['fname'], (flinkinfo['fatime'], flinkinfo['fmtime']));
    if(flinkinfo['ftype']==1):
     os.link(flinkinfo['flinkname'], listcatfiles[lcfi]['fname']);
    if(flinkinfo['ftype']==2):
     os.symlink(flinkinfo['flinkname'], listcatfiles[lcfi]['fname']);
    if(flinkinfo['ftype']==5):
     os.mkdir(listcatfiles[lcfi]['fname'], int(flinkinfo['fchmode'], 8));
     if(hasattr(os, "chown") and funame==flinkinfo['funame'] and fgname==flinkinfo['fgname']):
      os.chown(listcatfiles[lcfi]['fname'], flinkinfo['fuid'], flinkinfo['fgid']);
     os.chmod(listcatfiles[lcfi]['fname'], int(flinkinfo['fchmode'], 8));
     os.utime(listcatfiles[lcfi]['fname'], (flinkinfo['fatime'], flinkinfo['fmtime']));
    if(flinkinfo['ftype']==6 and hasattr(os, "mkfifo")):
     os.mkfifo(listcatfiles[lcfi]['fname'], int(flinkinfo['fchmode'], 8));
   else:
    os.link(listcatfiles[lcfi]['flinkname'], listcatfiles[lcfi]['fname']);
  if(listcatfiles[lcfi]['ftype']==2):
   if(followlink):
    getflinkpath = listcatfiles[lcfi]['flinkname'];
    flinkid = prelistcatfiles['filetoid'][getflinkpath];
    flinkinfo = listcatfiles[flinkid];
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
     fpc = open(listcatfiles[lcfi]['fname'], "wb");
     fpc.write(flinkinfo['fcontents']);
     fpc.close();
     if(hasattr(os, "chown") and funame==flinkinfo['funame'] and fgname==flinkinfo['fgname']):
      os.chown(listcatfiles[lcfi]['fname'], flinkinfo['fuid'], flinkinfo['fgid']);
     os.chmod(listcatfiles[lcfi]['fname'], int(flinkinfo['fchmode'], 8));
     os.utime(listcatfiles[lcfi]['fname'], (flinkinfo['fatime'], flinkinfo['fmtime']));
    if(flinkinfo['ftype']==1):
     os.link(flinkinfo['flinkname'], listcatfiles[lcfi]['fname']);
    if(flinkinfo['ftype']==2):
     os.symlink(flinkinfo['flinkname'], listcatfiles[lcfi]['fname']);
    if(flinkinfo['ftype']==5):
     os.mkdir(listcatfiles[lcfi]['fname'], int(flinkinfo['fchmode'], 8));
     if(hasattr(os, "chown") and funame==flinkinfo['funame'] and fgname==flinkinfo['fgname']):
      os.chown(listcatfiles[lcfi]['fname'], flinkinfo['fuid'], flinkinfo['fgid']);
     os.chmod(listcatfiles[lcfi]['fname'], int(flinkinfo['fchmode'], 8));
     os.utime(listcatfiles[lcfi]['fname'], (flinkinfo['fatime'], flinkinfo['fmtime']));
    if(flinkinfo['ftype']==6 and hasattr(os, "mkfifo")):
     os.mkfifo(listcatfiles[lcfi]['fname'], int(flinkinfo['fchmode'], 8));
   else:
    os.symlink(listcatfiles[lcfi]['flinkname'], listcatfiles[lcfi]['fname']);
  if(listcatfiles[lcfi]['ftype']==5):
   os.mkdir(listcatfiles[lcfi]['fname'], int(listcatfiles[lcfi]['fchmode'], 8));
   if(hasattr(os, "chown") and funame==listcatfiles[lcfi]['funame'] and fgname==listcatfiles[lcfi]['fgname']):
    os.chown(listcatfiles[lcfi]['fname'], listcatfiles[lcfi]['fuid'], listcatfiles[lcfi]['fgid']);
   os.chmod(listcatfiles[lcfi]['fname'], int(listcatfiles[lcfi]['fchmode'], 8));
   os.utime(listcatfiles[lcfi]['fname'], (listcatfiles[lcfi]['fatime'], listcatfiles[lcfi]['fmtime']));
  if(listcatfiles[lcfi]['ftype']==6 and hasattr(os, "mkfifo")):
   os.mkfifo(listcatfiles[lcfi]['fname'], int(listcatfiles[lcfi]['fchmode'], 8));
  lcfi = lcfi + 1;
 if(returnfp):
  return listcatfiles['catfp'];
 else:
  return True;

def UnPackCatString(catstr, outdir=None, followlink=False, skipchecksum=False, verbose=False, returnfp=False):
 catfp = BytesIO(catstr);
 listcatfiles = UnPackCatFile(catfp, outdir, followlink, skipchecksum, verbose, returnfp);
 return listcatfiles;

def CatFileListFiles(infile, seekstart=0, seekend=0, skipchecksum=False, verbose=False, returnfp=False):
 import datetime;
 logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(isinstance(infile, dict)):
  listcatfiles = infile;
 else:
  if(infile!="-" and not hasattr(infile, "read") and not hasattr(infile, "write")):
   infile = RemoveWindowsPath(infile);
  listcatfiles = CatFileToArray(infile, seekstart, seekend, True, skipchecksum, returnfp);
 if(not listcatfiles):
  return False;
 lcfi = 0;
 lcfx = len(listcatfiles);
 returnval = {};
 while(lcfi < lcfx):
  returnval.update({lcfi: listcatfiles[lcfi]['fname']});
  if(not verbose):
   VerbosePrintOut(listcatfiles[lcfi]['fname']);
  if(verbose):
   permissions = { 'access': { '0': ('---'), '1': ('--x'), '2': ('-w-'), '3': ('-wx'), '4': ('r--'), '5': ('r-x'), '6': ('rw-'), '7': ('rwx') }, 'roles': { 0: 'owner', 1: 'group', 2: 'other' } };
   printfname = listcatfiles[lcfi]['fname'];
   if(listcatfiles[lcfi]['ftype']==1):
    printfname = listcatfiles[lcfi]['fname'] + " link to " + listcatfiles[lcfi]['flinkname'];
   if(listcatfiles[lcfi]['ftype']==2):
    printfname = listcatfiles[lcfi]['fname'] + " -> " + listcatfiles[lcfi]['flinkname'];
   fuprint = listcatfiles[lcfi]['funame'];
   if(len(fuprint)<=0):
    fuprint = listcatfiles[lcfi]['fuid'];
   fgprint = listcatfiles[lcfi]['fgname'];
   if(len(fgprint)<=0):
    fgprint = listcatfiles[lcfi]['fgid'];
   VerbosePrintOut(PrintPermissionString(listcatfiles[lcfi]['fmode'], listcatfiles[lcfi]['ftype']) + " " + str(str(fuprint) + "/" + str(fgprint) + " " + str(listcatfiles[lcfi]['fsize']).rjust(15) + " " + datetime.datetime.utcfromtimestamp(listcatfiles[lcfi]['fmtime']).strftime('%Y-%m-%d %H:%M') + " " + printfname));
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
 import datetime;
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
 import datetime;
 logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(not os.path.exists(infile) or not os.path.isfile(infile)):
  return False;
 if(not zipfile.is_zipfile(infile)):
  return False;
 lcfi = 0;
 returnval = {};
 zipfp = zipfile.ZipFile(infile, "r", allowZip64=True);
 ziptest = zipfp.testzip();
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
 catout = RePackCatFile(outarray, outfile, compression, compressionlevel, checksumtype, skipchecksum, extradata, verbose, returnfp);
 return catout;

def PackCatFileFromTarFileAlt(infile, outfile, compression="auto", compressionlevel=None, checksumtype="crc32", extradata=[], verbose=False, returnfp=False):
 outarray = TarFileToArrayAlt(infile, False, False, False, checksumtype, extradata, False);
 catout = RePackCatFile(outarray, outfile, compression, compressionlevel, checksumtype, True, extradata, verbose, returnfp);
 return catout;

def PackCatFileFromZipFileAlt(infile, outfile, compression="auto", compressionlevel=None, checksumtype="crc32", extradata=[], verbose=False, returnfp=False):
 outarray = ZipFileToArrayAlt(infile, False, False, False, checksumtype, extradata, False);
 catout = RePackCatFile(outarray, outfile, compression, compressionlevel, checksumtype, True, extradata, verbose, returnfp);
 return catout;
