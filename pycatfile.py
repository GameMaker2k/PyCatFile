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

    $FileInfo: pycatfile.py - Last Update: 4/1/2024 Ver. 0.7.4 RC 1 - Author: cooldude2k $
'''

from __future__ import absolute_import, division, print_function, unicode_literals;
import io, os, re, sys, time, stat, zlib, base64, shutil, socket, hashlib, datetime, logging, binascii, tempfile, zipfile, platform;
from ftplib import FTP, FTP_TLS;
if(sys.version[0]=="2"):
 from urlparse import urlparse, urlunparse;
elif(sys.version[0]>="3"):
 from urllib.parse import urlunparse;
 from urllib.parse import urlparse;

if os.name == 'nt':  # Only modify if on Windows
 if sys.version[0] == "2":
  import codecs;
  sys.stdout = codecs.getwriter('utf-8')(sys.stdout);
  sys.stderr = codecs.getwriter('utf-8')(sys.stderr);
 else:
  import io;
  sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace', line_buffering=True);
  sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace', line_buffering=True);

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

try:
 from zlib import crc32;
except ImportError:
 from binascii import crc32;

rarfile_support = False;
try:
 import rarfile;
 rarfile_support = True;
except ImportError:
 rarfile_support = False;

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

haveparamiko = False;
try:
 import paramiko;
 haveparamiko = True;
except ImportError:
 haveparamiko = False;

havepysftp = False;
try:
 import pysftp;
 havepysftp = True;
except ImportError:
 havepysftp = False;

haverequests = False;
try:
 import requests;
 haverequests = True;
except ImportError:
 haverequests = False;

if(haverequests):
 import urllib3;
 logging.getLogger("urllib3").setLevel(logging.WARNING);

try:
 # Python 3 imports
 from urllib.request import Request, build_opener, HTTPBasicAuthHandler;
 from urllib.parse import urlparse;
except ImportError:
 # Python 2 imports
 from urllib2 import Request, build_opener, HTTPBasicAuthHandler;
 from urlparse import urlparse;

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

__use_pysftp__ = False;
if(not havepysftp):
 __use_pysftp__ = False;
__file_format_name__ = "CatFile";
__program_name__ = "Py"+__file_format_name__;
__file_format_lower__ = __file_format_name__.lower();
__file_format_magic__ = __file_format_name__;
__file_format_len__ = len(__file_format_magic__);
__file_format_hex__ = binascii.hexlify(__file_format_magic__.encode("UTF-8")).decode("UTF-8");
__file_format_delimiter__ = "\x00";
__file_format_ver__ = "001";
__use_new_style__ = True;
__file_format_list__ = [__file_format_name__, __file_format_magic__, __file_format_lower__, __file_format_len__, __file_format_hex__, __file_format_delimiter__, __file_format_ver__, __use_new_style__];
__project__ = __program_name__;
__project_url__ = "https://github.com/GameMaker2k/PyCatFile";
__version_info__ = (0, 7, 4, "RC 1", 1);
__version_date_info__ = (2024, 4, 1, "RC 1", 1);
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

PyBitness = platform.architecture();
if(PyBitness=="32bit" or PyBitness=="32"):
 PyBitness = "32";
elif(PyBitness=="64bit" or PyBitness=="64"):
 PyBitness = "64";
else:
 PyBitness = "32";

geturls_ua_pycatfile_python = "Mozilla/5.0 (compatible; {proname}/{prover}; +{prourl})".format(proname=__project__, prover=__version__, prourl=__project_url__);
if(platform.python_implementation()!=""):
 py_implementation = platform.python_implementation();
if(platform.python_implementation()==""):
 py_implementation = "Python";
geturls_ua_pycatfile_python_alt = "Mozilla/5.0 ({osver}; {archtype}; +{prourl}) {pyimp}/{pyver} (KHTML, like Gecko) {proname}/{prover}".format(osver=platform.system()+" "+platform.release(), archtype=platform.machine(), prourl=__project_url__, pyimp=py_implementation, pyver=platform.python_version(), proname=__project__, prover=__version__);
geturls_ua_googlebot_google = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
geturls_ua_googlebot_google_old = "Googlebot/2.1 (+http://www.google.com/bot.html)";
geturls_headers_pycatfile_python = {'Referer': "http://google.com/", 'User-Agent': geturls_ua_pycatfile_python, 'Accept-Encoding': "none", 'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6", 'Accept-Charset': "ISO-8859-1,ISO-8859-15,utf-8;q=0.7,*;q=0.7", 'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'Connection': "close", 'SEC-CH-UA': "\""+__project__+"\";v=\""+str(__version__)+"\", \"Not;A=Brand\";v=\"8\", \""+py_implementation+"\";v=\""+str(platform.release())+"\"", 'SEC-CH-UA-FULL-VERSION': str(__version__), 'SEC-CH-UA-PLATFORM': ""+py_implementation+"", 'SEC-CH-UA-ARCH': ""+platform.machine()+"", 'SEC-CH-UA-PLATFORM': str(__version__), 'SEC-CH-UA-BITNESS': str(PyBitness)};
geturls_headers_pycatfile_python_alt = {'Referer': "http://google.com/", 'User-Agent': geturls_ua_pycatfile_python_alt, 'Accept-Encoding': "none", 'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6", 'Accept-Charset': "ISO-8859-1,ISO-8859-15,utf-8;q=0.7,*;q=0.7", 'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'Connection': "close", 'SEC-CH-UA': "\""+__project__+"\";v=\""+str(__version__)+"\", \"Not;A=Brand\";v=\"8\", \""+py_implementation+"\";v=\""+str(platform.release())+"\"", 'SEC-CH-UA-FULL-VERSION': str(__version__), 'SEC-CH-UA-PLATFORM': ""+py_implementation+"", 'SEC-CH-UA-ARCH': ""+platform.machine()+"", 'SEC-CH-UA-PLATFORM': str(__version__), 'SEC-CH-UA-BITNESS': str(PyBitness)};
geturls_headers_googlebot_google = {'Referer': "http://google.com/", 'User-Agent': geturls_ua_googlebot_google, 'Accept-Encoding': "none", 'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6", 'Accept-Charset': "ISO-8859-1,ISO-8859-15,utf-8;q=0.7,*;q=0.7", 'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'Connection': "close"};
geturls_headers_googlebot_google_old = {'Referer': "http://google.com/", 'User-Agent': geturls_ua_googlebot_google_old, 'Accept-Encoding': "none", 'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6", 'Accept-Charset': "ISO-8859-1,ISO-8859-15,utf-8;q=0.7,*;q=0.7", 'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'Connection': "close"};

compressionlist = ['auto', 'gzip', 'bzip2', 'zstd', 'lz4', 'lzo', 'lzop', 'lzma', 'xz'];
outextlist = ['gz', 'bz2', 'zst', 'lz4', 'lzo', 'lzop', 'lzma', 'xz'];
outextlistwd = ['.gz', '.bz2', '.zst', '.lz4', '.lzo', '.lzop', '.lzma', '.xz'];

tarfile_mimetype = "application/tar";
tarfile_tar_mimetype = tarfile_mimetype;
zipfile_mimetype = "application/zip";
zipfile_zip_mimetype = zipfile_mimetype;
rarfile_mimetype = "application/rar";
rarfile_rar_mimetype = rarfile_mimetype;
archivefile_mimetype = "application/x-"+__file_format_list__[1]+"";
archivefile_cat_mimetype = archivefile_mimetype;
archivefile_gzip_mimetype = "application/x-"+__file_format_list__[1]+"+gzip";
archivefile_gz_mimetype = archivefile_gzip_mimetype;
archivefile_bzip2_mimetype = "application/x-"+__file_format_list__[1]+"+bzip2";
archivefile_bz2_mimetype = archivefile_bzip2_mimetype;
archivefile_lz4_mimetype = "application/x-"+__file_format_list__[1]+"+lz4";
archivefile_lzop_mimetype = "application/x-"+__file_format_list__[1]+"+lzop";
archivefile_lzo_mimetype = archivefile_lzop_mimetype;
archivefile_zstandard_mimetype = "application/x-"+__file_format_list__[1]+"+zstandard";
archivefile_zstd_mimetype = archivefile_zstandard_mimetype;
archivefile_lzma_mimetype = "application/x-"+__file_format_list__[1]+"+lzma";
archivefile_xz_mimetype = "application/x-"+__file_format_list__[1]+"+xz";
archivefile_extensions = ['.cat', '.cat.gz', '.cat.bz2', '.cat.zst', '.cat.lz4', '.cat.lzo', '.cat.lzop', '.cat.lzma', '.cat.xz'];

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

def PrependPath(base_dir, child_path):
 # Check if base_dir is None or empty, if so, return child_path as is
 if not base_dir:
  return child_path;
 # Ensure base_dir ends with exactly one slash
 if not base_dir.endswith('/'):
  base_dir += '/';
 # Check if child_path starts with ./ or ../ (indicating a relative path)
 if child_path.startswith('./') or child_path.startswith('../'):
  # For relative paths, we don't alter the child_path
  return base_dir + child_path;
 else:
  # For non-relative paths, ensure there's no starting slash on child_path to avoid double slashes
  return base_dir + child_path.lstrip('/');

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

def create_alias_function(prefix, base_name, suffix, target_function):
 # Define a new function that wraps the target function
 def alias_function(*args, **kwargs):
  return target_function(*args, **kwargs);

 # Create the function name by combining the prefix, base name, and the suffix
 function_name = "{}{}{}".format(prefix, base_name, suffix);
 
 # Add the new function to the global namespace
 globals()[function_name] = alias_function;

def create_alias_function_alt(prefix, base_name, suffix, target_function):
    # Create the function name by combining the prefix, base name, and the suffix
    # Use the format method for string formatting, compatible with Python 2 and 3
    function_name = "{}{}{}".format(prefix, base_name, suffix)
    # Add the new function (alias of the target_function) to the global namespace
    # This line is compatible as-is with both Python 2 and 3
    globals()[function_name] = target_function

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

def GetDataFromArray(data, path, default=None):
 element = data;
 try:
  for key in path:
   element = element[key];
  return element;
 except (KeyError, TypeError, IndexError):
  return default;

def GetDataFromArrayAlt(structure, path, default=None):
 element = structure;
 for key in path:
  if isinstance(element, dict) and key in element:
   element = element[key];
  elif isinstance(element, list) and isinstance(key, int) and -len(element) <= key < len(element):
   element = element[key];
  else:
   return default;
 return element;

def GetHeaderChecksum(inlist=[], checksumtype="crc32", encodedata=True, formatspecs=__file_format_list__):
 if isinstance(inlist, list):
  fileheader = AppendNullBytes(inlist, formatspecs[5]);
 else:
  fileheader = AppendNullByte(inlist, formatspecs[5]);
 if(encodedata):
  fileheader = fileheader.encode('UTF-8');
 if(checksumtype=="none" or checksumtype==""):
  catfileheadercshex = format(0, 'x').lower();
 elif(checksumtype=="crc16" or checksumtype=="crc16_ansi" or checksumtype=="crc16_ibm"):
  catfileheadercshex = format(crc16(fileheader) & 0xffff, '04x').lower();
 elif(checksumtype=="crc16_ccitt"):
  catfileheadercshex = format(crc16_ccitt(fileheader) & 0xffff, '04x').lower();
 elif(checksumtype=="adler32"):
  catfileheadercshex = format(zlib.adler32(fileheader) & 0xffffffff, '08x').lower();
 elif(checksumtype=="crc32"):
  catfileheadercshex = format(crc32(fileheader) & 0xffffffff, '08x').lower();
 elif(checksumtype=="crc64_ecma"):
  catfileheadercshex = format(crc64_ecma(fileheader) & 0xffffffffffffffff, '016x').lower();
 elif(checksumtype=="crc64" or checksumtype=="crc64_iso"):
  catfileheadercshex = format(crc64_iso(fileheader) & 0xffffffffffffffff, '016x').lower();
 elif(CheckSumSupportAlt(checksumtype, hashlib_guaranteed)):
  checksumoutstr = hashlib.new(checksumtype);
  checksumoutstr.update(fileheader);
  catfileheadercshex = checksumoutstr.hexdigest().lower();
 else:
  catfileheadercshex = format(0, 'x').lower();
 return catfileheadercshex;

def GetFileChecksum(instr, checksumtype="crc32", encodedata=True, formatspecs=__file_format_list__):
 if(encodedata):
  instr = instr.encode('UTF-8');
 if(checksumtype=="none" or checksumtype==""):
  catinstrcshex = format(0, 'x').lower();
 elif(checksumtype=="crc16" or checksumtype=="crc16_ansi" or checksumtype=="crc16_ibm"):
  catinstrcshex = format(crc16(instr) & 0xffff, '04x').lower();
 elif(checksumtype=="crc16_ccitt"):
  catinstrcshex = format(crc16_ccitt(instr) & 0xffff, '04x').lower();
 elif(checksumtype=="adler32"):
  catinstrcshex = format(zlib.adler32(instr) & 0xffffffff, '08x').lower();
 elif(checksumtype=="crc32"):
  catinstrcshex = format(crc32(instr) & 0xffffffff, '08x').lower();
 elif(checksumtype=="crc64_ecma"):
  catinstrcshex = format(crc64_ecma(instr) & 0xffffffffffffffff, '016x').lower();
 elif(checksumtype=="crc64" or checksumtype=="crc64_iso"):
  catinstrcshex = format(crc64_iso(instr) & 0xffffffffffffffff, '016x').lower();
 elif(CheckSumSupportAlt(checksumtype, hashlib_guaranteed)):
  checksumoutstr = hashlib.new(checksumtype);
  checksumoutstr.update(instr);
  catinstrcshex = checksumoutstr.hexdigest().lower();
 else:
  catinstrcshex = format(0, 'x').lower();
 return catinstrcshex;

def ValidateHeaderChecksum(inlist=[], checksumtype="crc32", inchecksum="0", formatspecs=__file_format_list__):
 catfileheadercshex = GetHeaderChecksum(inlist, checksumtype, True, formatspecs);
 inchecksum = inchecksum.lower();
 catfileheadercshex = catfileheadercshex.lower();
 if(inchecksum==catfileheadercshex):
  return True;
 else:
  return False;

def ValidateFileChecksum(infile, checksumtype="crc32", inchecksum="0", formatspecs=__file_format_list__):
 catinfilecshex = GetFileChecksum(infile, checksumtype, True, formatspecs);
 inchecksum = inchecksum.lower();
 catinfilecshex = catinfilecshex.lower();
 if(inchecksum==catinfilecshex):
  return True;
 else:
  return False;

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

def ReadFileHeaderDataBySize(fp, delimiter=__file_format_delimiter__):
 headerpresize = ReadTillNullByte(fp, delimiter);
 headersize = int(headerpresize, 16);
 headercontent = str(fp.read(headersize).decode('UTF-8')).split(delimiter);
 fp.seek(1, 1);
 rocount = 0;
 roend = int(len(headercontent));
 HeaderOut = [headerpresize];
 while(rocount<roend):
  HeaderOut.append(headercontent[rocount]);
  rocount = rocount + 1;
 return HeaderOut;

def ReadFileHeaderDataWoSize(fp, delimiter=__file_format_delimiter__):
 preheaderdata = ReadFileHeaderData(fp, 2, delimiter);
 headersize = int(preheaderdata[0], 16);
 headernumfields = int(preheaderdata[1], 16);
 headerdata = ReadFileHeaderData(fp, headernumfields, delimiter);
 HeaderOut = preheaderdata + headerdata;
 return HeaderOut;

def ReadFileHeaderDataBySizeWithContent(fp, listonly=False, skipchecksum=False, formatspecs=__file_format_list__):
 delimiter = formatspecs[5];
 fheaderstart = fp.tell();
 HeaderOut = ReadFileHeaderDataBySize(fp, delimiter);
 if(re.findall("^[.|/]", HeaderOut[3])):
  fname = HeaderOut[3];
 else:
  fname = "./"+HeaderOut[3];
 fchecksumtype = HeaderOut[-3].lower();
 fcs = HeaderOut[-2].lower();
 fccs = HeaderOut[-1].lower();
 fsize = int(HeaderOut[5], 16);
 newfcs = GetHeaderChecksum(HeaderOut[:-2], HeaderOut[-3].lower(), True, formatspecs);
 if(fcs!=newfcs and not skipchecksum):
  VerbosePrintOut("File Header Checksum Error with file " + fname + " at offset " + str(fheaderstart));
  return False;
 fhend = fp.tell() - 1;
 fcontentstart = fp.tell();
 fcontents = "".encode('UTF-8');
 if(fsize>0 and not listonly):
  fcontents = fp.read(fsize);
 elif(fsize>0 and listonly):
  fp.seek(fsize, 1);
 newfccs = GetFileChecksum(fcontents, HeaderOut[-3].lower(), False, formatspecs);
 if(fccs!=newfccs and not skipchecksum and not listonly):
  VerbosePrintOut("File Content Checksum Error with file " + fname + " at offset " + str(fcontentstart));
  return False;
 fp.seek(1, 1);
 fcontentend = fp.tell() - 1;
 HeaderOut.append(fcontents);
 return HeaderOut;

def ReadFileHeaderDataBySizeWithContentToArray(fp, listonly=False, skipchecksum=False, formatspecs=__file_format_list__):
 delimiter = formatspecs[5];
 fheaderstart = fp.tell();
 if(formatspecs[7]):
  HeaderOut = ReadFileHeaderDataBySize(fp, delimiter);
 else:
  HeaderOut = ReadFileHeaderDataWoSize(fp, delimiter);
 fheadsize = int(HeaderOut[0], 16);
 fnumfields = int(HeaderOut[1], 16);
 ftype = int(HeaderOut[2], 16);
 if(re.findall("^[.|/]", HeaderOut[3])):
  fname = HeaderOut[3];
 else:
  fname = "./"+HeaderOut[3];
 fbasedir = os.path.dirname(fname);
 flinkname = HeaderOut[4];
 fsize = int(HeaderOut[5], 16);
 fatime = int(HeaderOut[6], 16);
 fmtime = int(HeaderOut[7], 16);
 fctime = int(HeaderOut[8], 16);
 fbtime = int(HeaderOut[9], 16);
 fmode = int(HeaderOut[10], 16);
 fchmode = stat.S_IMODE(fmode);
 ftypemod = stat.S_IFMT(fmode);
 fwinattributes = int(HeaderOut[11], 16);
 fuid = int(HeaderOut[12], 16);
 funame = HeaderOut[13];
 fgid = int(HeaderOut[14], 16);
 fgname = HeaderOut[15];
 fid = int(HeaderOut[16], 16);
 finode = int(HeaderOut[17], 16);
 flinkcount = int(HeaderOut[18], 16);
 fdev_minor = int(HeaderOut[19], 16);
 fdev_major = int(HeaderOut[20], 16);
 frdev_minor = int(HeaderOut[21], 16);
 frdev_major = int(HeaderOut[22], 16);
 fextrasize = int(HeaderOut[23], 16);
 fextrafields = int(HeaderOut[24], 16);
 extrafieldslist = [];
 extrastart = 25;
 extraend = extrastart + fextrafields;
 extrafieldslist = [];
 if(extrastart<extraend):
  extrafieldslist.append(HeaderOut[extrastart]);
  extrastart = extrastart + 1;
 fchecksumtype = HeaderOut[extrastart].lower();
 fcs = HeaderOut[extrastart + 1].lower();
 fccs = HeaderOut[extrastart + 2].lower();
 newfcs = GetHeaderChecksum(HeaderOut[:-2], HeaderOut[-3].lower(), True, formatspecs);
 if(fcs!=newfcs and not skipchecksum):
  VerbosePrintOut("File Header Checksum Error with file " + fname + " at offset " + str(fheaderstart));
  return False;
 fhend = fp.tell() - 1;
 fcontentstart = fp.tell();
 fcontents = "".encode('UTF-8');
 pyhascontents = False;
 if(fsize>0 and not listonly):
  fcontents = fp.read(fsize);
  pyhascontents = True;
 elif(fsize>0 and listonly):
  fp.seek(fsize, 1);
  pyhascontents = False;
 newfccs = GetFileChecksum(fcontents, HeaderOut[-3].lower(), False, formatspecs);
 if(fccs!=newfccs and not skipchecksum and not listonly):
  VerbosePrintOut("File Content Checksum Error with file " + fname + " at offset " + str(fcontentstart));
  return False;
 fp.seek(1, 1);
 fcontentend = fp.tell() - 1;
 catlist = {'fheadersize': fheadsize, 'fhstart': fheaderstart, 'fhend': fhend, 'ftype': ftype, 'fname': fname, 'fbasedir': fbasedir, 'flinkname': flinkname, 'fsize': fsize, 'fatime': fatime, 'fmtime': fmtime, 'fctime': fctime, 'fbtime': fbtime, 'fmode': fmode, 'fchmode': fchmode, 'ftypemod': ftypemod, 'fwinattributes': fwinattributes, 'fuid': fuid, 'funame': funame, 'fgid': fgid, 'fgname': fgname, 'finode': finode, 'flinkcount': flinkcount, 'fminor': fdev_minor, 'fmajor': fdev_major, 'frminor': frdev_minor, 'frmajor': frdev_major, 'fchecksumtype': fchecksumtype, 'fnumfields': fnumfields + 2, 'frawheader': HeaderOut, 'fextrafields': fextrafields, 'fextrafieldsize': fextrasize, 'fextralist': extrafieldslist, 'fheaderchecksum': fcs, 'fcontentchecksum': fccs, 'fhascontents': pyhascontents, 'fcontentstart': fcontentstart, 'fcontentend': fcontentend, 'fcontents': fcontents};
 return catlist;

def ReadFileHeaderDataBySizeWithContentToList(fp, listonly=False, skipchecksum=False, formatspecs=__file_format_list__):
 delimiter = formatspecs[5];
 fheaderstart = fp.tell();
 if(formatspecs[7]):
  HeaderOut = ReadFileHeaderDataBySize(fp, delimiter);
 else:
  HeaderOut = ReadFileHeaderDataWoSize(fp, delimiter);
 fheadsize = int(HeaderOut[0], 16);
 fnumfields = int(HeaderOut[1], 16);
 ftype = int(HeaderOut[2], 16);
 if(re.findall("^[.|/]", HeaderOut[3])):
  fname = HeaderOut[3];
 else:
  fname = "./"+HeaderOut[3];
 fbasedir = os.path.dirname(fname);
 flinkname = HeaderOut[4];
 fsize = int(HeaderOut[5], 16);
 fatime = int(HeaderOut[6], 16);
 fmtime = int(HeaderOut[7], 16);
 fctime = int(HeaderOut[8], 16);
 fbtime = int(HeaderOut[9], 16);
 fmode = int(HeaderOut[10], 16);
 fchmode = stat.S_IMODE(fmode);
 ftypemod = stat.S_IFMT(fmode);
 fwinattributes = int(HeaderOut[11], 16);
 fuid = int(HeaderOut[12], 16);
 funame = HeaderOut[13];
 fgid = int(HeaderOut[14], 16);
 fgname = HeaderOut[15];
 fid = int(HeaderOut[16], 16);
 finode = int(HeaderOut[17], 16);
 flinkcount = int(HeaderOut[18], 16);
 fdev_minor = int(HeaderOut[19], 16);
 fdev_major = int(HeaderOut[20], 16);
 frdev_minor = int(HeaderOut[21], 16);
 frdev_major = int(HeaderOut[22], 16);
 fextrasize = int(HeaderOut[23], 16);
 fextrafields = int(HeaderOut[24], 16);
 extrafieldslist = [];
 extrastart = 25;
 extraend = extrastart + fextrafields;
 extrafieldslist = [];
 if(extrastart<extraend):
  extrafieldslist.append(HeaderOut[extrastart]);
  extrastart = extrastart + 1;
 fchecksumtype = HeaderOut[extrastart].lower();
 fcs = HeaderOut[extrastart + 1].lower();
 fccs = HeaderOut[extrastart + 2].lower();
 newfcs = GetHeaderChecksum(HeaderOut[:-2], HeaderOut[-3].lower(), True, formatspecs);
 if(fcs!=newfcs and not skipchecksum):
  VerbosePrintOut("File Header Checksum Error with file " + fname + " at offset " + str(fheaderstart));
  return False;
 fhend = fp.tell() - 1;
 fcontentstart = fp.tell();
 fcontents = "".encode('UTF-8');
 pyhascontents = False;
 if(fsize>0 and not listonly):
  fcontents = fp.read(fsize);
  pyhascontents = True;
 elif(fsize>0 and listonly):
  fp.seek(fsize, 1);
  pyhascontents = False;
 newfccs = GetFileChecksum(fcontents, HeaderOut[-3].lower(), False, formatspecs);
 if(fccs!=newfccs and not skipchecksum and not listonly):
  VerbosePrintOut("File Content Checksum Error with file " + fname + " at offset " + str(fcontentstart));
  return False;
 fp.seek(1, 1);
 fcontentend = fp.tell() - 1;
 catlist = [ftype, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fuid, funame, fgid, fgname, fid, finode, flinkcount, fdev_minor, fdev_major, frdev_minor, frdev_major, extrafieldslist, fchecksumtype, fcontents];
 return catlist;

def ReadFileDataBySizeWithContent(fp, listonly=False, skipchecksum=False, formatspecs=__file_format_list__):
 delimiter = formatspecs[5];
 catheader = ReadFileHeaderData(fp, 4, delimiter);
 headercheck = ValidateHeaderChecksum(catheader[:-1], catheader[2], catheader[3], formatspecs);
 if(not headercheck and not skipchecksum):
  VerbosePrintOut("File Header Checksum Error with file at offset " + str(0));
  return False;
 fnumfiles = int(catheader[1], 16);
 countnum = 0;
 flist = [];
 while(countnum < fnumfiles):
  flist.append(ReadFileHeaderDataBySizeWithContent(fp, listonly, skipchecksum, formatspecs));
  countnum = countnum + 1;
 return flist;

def ReadFileDataBySizeWithContentToArray(fp, seekstart=0, seekend=0, listonly=False, skipchecksum=False, formatspecs=__file_format_list__):
 delimiter = formatspecs[5];
 catheader = ReadFileHeaderData(fp, 4, delimiter);
 headercheck = ValidateHeaderChecksum(catheader[:-1], catheader[2], catheader[3], formatspecs);
 if(not headercheck and not skipchecksum):
  VerbosePrintOut("File Header Checksum Error with file at offset " + str(0));
  return False;
 catstring = catheader[0];
 catversion = re.findall(r"([\d]+)$", catstring);
 catversions = re.search(r'(.*?)(\d+)$', catstring).groups();
 fprenumfiles = catheader[1];
 fnumfiles = int(fprenumfiles, 16);
 fprechecksumtype = catheader[2];
 fprechecksum = catheader[3];
 catlist = {'fnumfiles': fnumfiles, 'fformat': catversions[0], 'fversion': catversions[1], 'fformatspecs': formatspecs, 'fchecksumtype': fprechecksumtype, 'fheaderchecksum': fprechecksum, 'ffilelist': {}};
 if(seekstart<0 and seekstart>fnumfiles):
   seekstart = 0;
 if(seekend==0 or seekend>fnumfiles and seekend<seekstart):
  seekend = fnumfiles;
 elif(seekend<0 and abs(seekend)<=fnumfiles and abs(seekend)>=seekstart):
  seekend = fnumfiles - abs(seekend);
 if(seekstart>0):
  il = 0;
  while(il < seekstart):
   prefhstart = fp.tell();
   preheaderdata = ReadFileHeaderDataBySize(fp, formatspecs[5]);
   prefsize = int(preheaderdata[5], 16);
   prenewfcs = GetHeaderChecksum(preheaderdata[:-2], preheaderdata[-3].lower(), True, formatspecs);
   prefcs = preheaderdata[-2];
   if(prefcs!=prenewfcs and not skipchecksum):
    VerbosePrintOut("File Header Checksum Error with file " + prefname + " at offset " + str(prefhstart));
    return False;
    valid_archive = False;
    invalid_archive = True;
   prefhend = fp.tell() - 1;
   prefcontentstart = fp.tell();
   prefcontents = "";
   pyhascontents = False;
   if(prefsize>0):
    prefcontents = fp.read(prefsize);
    prenewfccs = GetFileChecksum(prefcontents, preheaderdata[-3].lower(), False, formatspecs);
    prefccs = preheaderdata[-1];
    pyhascontents = True;
    if(prefccs!=prenewfccs and not skipchecksum):
     VerbosePrintOut("File Content Checksum Error with file " + prefname + " at offset " + str(prefcontentstart));
     return False;
   fp.seek(1, 1);
   il = il + 1;
 realidnum = 0;
 countnum = seekstart;
 while(countnum < seekend):
  catlist['ffilelist'].update({realidnum: {'fid': realidnum, 'fidalt': realidnum}});
  catlist['ffilelist'][realidnum].update(ReadFileHeaderDataBySizeWithContentToArray(fp, listonly, skipchecksum, formatspecs));
  countnum = countnum + 1;
  realidnum = realidnum + 1;
 return catlist;

def ReadFileDataBySizeWithContentToArrayIndex(infile, seekstart=0, seekend=0, listonly=False, skipchecksum=False, formatspecs=__file_format_list__):
 if(isinstance(infile, dict)):
  listcatfiles = infile;
 else:
  if(infile!="-" and not hasattr(infile, "read") and not hasattr(infile, "write")):
   return False;
  listcatfiles = ReadFileDataBySizeWithContentToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs);
 if(not listcatfiles):
  return False;
 catarray = {'list': listcatfiles, 'filetoid': {}, 'idtofile': {}, 'filetypes': {'directories': {'filetoid': {}, 'idtofile': {}}, 'files': {'filetoid': {}, 'idtofile': {}}, 'links': {'filetoid': {}, 'idtofile': {}}, 'symlinks': {'filetoid': {}, 'idtofile': {}}, 'hardlinks': {'filetoid': {}, 'idtofile': {}}, 'character': {'filetoid': {}, 'idtofile': {}}, 'block': {'filetoid': {}, 'idtofile': {}}, 'fifo': {'filetoid': {}, 'idtofile': {}}, 'devices': {'filetoid': {}, 'idtofile': {}}}};
 lenlist = len(listcatfiles['ffilelist']);
 lcfi = 0;
 lcfx = int(listcatfiles['fnumfiles']);
 if(lenlist>listcatfiles['fnumfiles'] or lenlist<listcatfiles['fnumfiles']):
  lcfx = int(lenlist);
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

def ReadFileDataBySizeWithContentToList(fp, seekstart=0, seekend=0, listonly=False, skipchecksum=False, formatspecs=__file_format_list__):
 delimiter = formatspecs[5];
 catheader = ReadFileHeaderData(fp, 4, delimiter);
 headercheck = ValidateHeaderChecksum(catheader[:-1], catheader[2], catheader[3], formatspecs);
 if(not headercheck and not skipchecksum):
  VerbosePrintOut("File Header Checksum Error with file at offset " + str(0));
  return False;
 catstring = catheader[0];
 catversion = re.findall(r"([\d]+)$", catstring);
 catversions = re.search(r'(.*?)(\d+)$', catstring).groups();
 fprenumfiles = catheader[1];
 fnumfiles = int(fprenumfiles, 16);
 fprechecksumtype = catheader[2];
 fprechecksum = catheader[3];
 catlist = [];
 if(seekstart<0 and seekstart>fnumfiles):
   seekstart = 0;
 if(seekend==0 or seekend>fnumfiles and seekend<seekstart):
  seekend = fnumfiles;
 elif(seekend<0 and abs(seekend)<=fnumfiles and abs(seekend)>=seekstart):
  seekend = fnumfiles - abs(seekend);
 if(seekstart>0):
  il = 0;
  while(il < seekstart):
   prefhstart = fp.tell();
   preheaderdata = ReadFileHeaderDataBySize(fp, formatspecs[5]);
   prefsize = int(preheaderdata[5], 16);
   prenewfcs = GetHeaderChecksum(preheaderdata[:-2], preheaderdata[-3].lower(), True, formatspecs);
   prefcs = preheaderdata[-2];
   if(prefcs!=prenewfcs and not skipchecksum):
    VerbosePrintOut("File Header Checksum Error with file " + prefname + " at offset " + str(prefhstart));
    return False;
    valid_archive = False;
    invalid_archive = True;
   prefhend = fp.tell() - 1;
   prefcontentstart = fp.tell();
   prefcontents = "";
   pyhascontents = False;
   if(prefsize>0):
    prefcontents = fp.read(prefsize);
    prenewfccs = GetFileChecksum(prefcontents, preheaderdata[-3].lower(), False, formatspecs);
    prefccs = preheaderdata[-1];
    pyhascontents = True;
    if(prefccs!=prenewfccs and not skipchecksum):
     VerbosePrintOut("File Content Checksum Error with file " + prefname + " at offset " + str(prefcontentstart));
     return False;
   fp.seek(1, 1);
   il = il + 1;
 realidnum = 0;
 countnum = seekstart;
 while(countnum < seekend):
  catlist.append(ReadFileHeaderDataBySizeWithContentToList(fp, listonly, skipchecksum, formatspecs));
  countnum = countnum + 1;
  realidnum = realidnum + 1;
 return catlist;

def ReadInFileBySizeWithContentToArray(infile, listonly=False, skipchecksum=False, formatspecs=__file_format_list__):
 delimiter = formatspecs[5];
 if(hasattr(infile, "read") or hasattr(infile, "write")):
  fp = infile;
  fp.seek(0, 0);
  fp = UncompressArchiveFile(fp, formatspecs);
  checkcompressfile = CheckCompressionSubType(fp, formatspecs);
  if(checkcompressfile!="catfile" and checkcompressfile!=formatspecs[2]):
   return False;
  if(not fp):
   return False;
  fp.seek(0, 0);
 elif(infile=="-"):
  fp = BytesIO();
  if(hasattr(sys.stdin, "buffer")):
   shutil.copyfileobj(sys.stdin.buffer, fp);
  else:
   shutil.copyfileobj(sys.stdin, fp);
  fp.seek(0, 0);
  fp = UncompressArchiveFile(fp, formatspecs);
  if(not fp):
   return False;
  fp.seek(0, 0);
 elif(re.findall(r"^(http|https|ftp|ftps|sftp)\:\/\/", str(infile))):
  fp = download_file_from_internet_file(infile);
  fp = UncompressArchiveFile(fp, formatspecs);
  fp.seek(0, 0);
  if(not fp):
   return False;
  fp.seek(0, 0);
 else:
  infile = RemoveWindowsPath(infile);
  checkcompressfile = CheckCompressionSubType(infile, formatspecs);
  if(checkcompressfile!="catfile" and checkcompressfile!=formatspecs[2]):
   return False;
  compresscheck = CheckCompressionType(infile, formatspecs, True);
  if(not compresscheck):
   fextname = os.path.splitext(infile)[1];
   if(fextname==".gz"):
    compresscheck = "gzip";
   elif(fextname==".bz2"):
    compresscheck = "bzip2";
   elif(fextname==".zst"):
    compresscheck = "zstd";
   elif(fextname==".lz4" or fextname==".clz4"):
    compresscheck = "lz4";
   elif(fextname==".lzo" or fextname==".lzop"):
    compresscheck = "lzo";
   elif(fextname==".lzma" or fextname==".xz"):
    compresscheck = "lzma";
   else:
    return False;
  if(not compresscheck):
   return False;
  fp = UncompressFile(infile, formatspecs, "rb");
 return ReadFileDataBySizeWithContentToArray(fp, listonly, skipchecksum, formatspecs);

def ReadInFileBySizeWithContentToList(infile, seekstart=0, seekend=0, listonly=False, skipchecksum=False, formatspecs=__file_format_list__):
 delimiter = formatspecs[5];
 if(hasattr(infile, "read") or hasattr(infile, "write")):
  fp = infile;
  fp.seek(0, 0);
  fp = UncompressArchiveFile(fp, formatspecs);
  checkcompressfile = CheckCompressionSubType(fp, formatspecs);
  if(checkcompressfile!="catfile" and checkcompressfile!=formatspecs[2]):
   return False;
  if(not fp):
   return False;
  fp.seek(0, 0);
 elif(infile=="-"):
  fp = BytesIO();
  if(hasattr(sys.stdin, "buffer")):
   shutil.copyfileobj(sys.stdin.buffer, fp);
  else:
   shutil.copyfileobj(sys.stdin, fp);
  fp.seek(0, 0);
  fp = UncompressArchiveFile(fp, formatspecs);
  if(not fp):
   return False;
  fp.seek(0, 0);
 elif(re.findall(r"^(http|https|ftp|ftps|sftp)\:\/\/", str(infile))):
  fp = download_file_from_internet_file(infile);
  fp = UncompressArchiveFile(fp, formatspecs);
  fp.seek(0, 0);
  if(not fp):
   return False;
  fp.seek(0, 0);
 else:
  infile = RemoveWindowsPath(infile);
  checkcompressfile = CheckCompressionSubType(infile, formatspecs);
  if(checkcompressfile!="catfile" and checkcompressfile!=formatspecs[2]):
   return False;
  compresscheck = CheckCompressionType(infile, formatspecs, True);
  if(not compresscheck):
   fextname = os.path.splitext(infile)[1];
   if(fextname==".gz"):
    compresscheck = "gzip";
   elif(fextname==".bz2"):
    compresscheck = "bzip2";
   elif(fextname==".zst"):
    compresscheck = "zstd";
   elif(fextname==".lz4" or fextname==".clz4"):
    compresscheck = "lz4";
   elif(fextname==".lzo" or fextname==".lzop"):
    compresscheck = "lzo";
   elif(fextname==".lzma" or fextname==".xz"):
    compresscheck = "lzma";
   else:
    return False;
  if(not compresscheck):
   return False;
  fp = UncompressFile(infile, formatspecs, "rb");
 return ReadFileDataBySizeWithContentToList(fp, seekstart, seekend, listonly, skipchecksum, formatspecs);

def ReadInFileBySizeWithContentToArrayIndex(infile, seekstart=0, seekend=0, listonly=False, skipchecksum=False, formatspecs=__file_format_list__):
 if(isinstance(infile, dict)):
  listcatfiles = infile;
 else:
  if(infile!="-" and not hasattr(infile, "read") and not hasattr(infile, "write")):
   infile = RemoveWindowsPath(infile);
  listcatfiles = ReadInFileBySizeWithContentToArray(infile, listonly, skipchecksum, formatspecs);
 if(not listcatfiles):
  return False;
 catarray = {'list': listcatfiles, 'filetoid': {}, 'idtofile': {}, 'filetypes': {'directories': {'filetoid': {}, 'idtofile': {}}, 'files': {'filetoid': {}, 'idtofile': {}}, 'links': {'filetoid': {}, 'idtofile': {}}, 'symlinks': {'filetoid': {}, 'idtofile': {}}, 'hardlinks': {'filetoid': {}, 'idtofile': {}}, 'character': {'filetoid': {}, 'idtofile': {}}, 'block': {'filetoid': {}, 'idtofile': {}}, 'fifo': {'filetoid': {}, 'idtofile': {}}, 'devices': {'filetoid': {}, 'idtofile': {}}}};
 lenlist = len(listcatfiles['ffilelist']);
 lcfi = 0;
 lcfx = int(listcatfiles['fnumfiles']);
 if(lenlist>listcatfiles['fnumfiles'] or lenlist<listcatfiles['fnumfiles']):
  lcfx = int(lenlist);
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

def AppendNullByte(indata, delimiter=__file_format_delimiter__):
 outdata = str(indata) + delimiter;
 return outdata;

def AppendNullBytes(indata=[], delimiter=__file_format_delimiter__):
 outdata = "";
 inum = 0;
 il = len(indata);
 while(inum < il):
  outdata = outdata + AppendNullByte(indata[inum], delimiter);
  inum = inum + 1;
 return outdata;

def AppendFileHeader(fp, numfiles, checksumtype="crc32", formatspecs=__file_format_list__):
 delimiter = formatspecs[5];
 catver = formatspecs[6];
 fileheaderver = str(int(catver.replace(".", "")));
 fileheader = AppendNullByte(formatspecs[1] + fileheaderver, formatspecs[5]);
 fp.write(fileheader.encode('UTF-8'));
 fnumfiles = format(int(numfiles), 'x').lower();
 fnumfilesa = AppendNullBytes([fnumfiles, checksumtype], formatspecs[5]);
 catfileheadercshex = GetFileChecksum(fileheader + fnumfilesa, checksumtype, True, formatspecs);
 fnumfilesa = fnumfilesa + AppendNullByte(catfileheadercshex, formatspecs[5]);
 fp.write(fnumfilesa.encode('UTF-8'));
 try:
  fp.flush();
  os.fsync(fp.fileno());
 except io.UnsupportedOperation:
  pass;
 except AttributeError:
  pass;
 return fp;

def AppendFileHeaderWithContent(fp, filevalues=[], extradata=[], filecontent="", checksumtype="crc32", formatspecs=__file_format_list__):
 extrafields = format(len(extradata), 'x').lower();
 extrasizestr = AppendNullByte(extrafields, formatspecs[5]);
 if(len(extradata)>0):
  extrasizestr = extrasizestr + AppendNullBytes(extradata, formatspecs[5]);
 extrasizelen = format(len(extrasizestr), 'x').lower();
 catoutlen = len(filevalues) + len(extradata) + 5;
 catoutlenhex = format(catoutlen, 'x').lower();
 catoutlist = filevalues;
 catoutlist.insert(0, catoutlenhex);
 catoutlist.append(extrasizelen);
 catoutlist.append(extrafields);
 catfileoutstr = AppendNullBytes(catoutlist, formatspecs[5]);
 if(len(extradata)>0):
  catfileoutstr = catfileoutstr + AppendNullBytes(extradata, formatspecs[5]);
 catfileoutstr = catfileoutstr + AppendNullByte(checksumtype, formatspecs[5]);
 catfileheadercshex = GetFileChecksum(catfileoutstr, checksumtype, True, formatspecs);
 catfilecontentcshex = GetFileChecksum(filecontent, checksumtype, False, formatspecs);
 tmpfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex], formatspecs[5]);
 catheaersize = format(int(len(tmpfileoutstr) - 1), 'x').lower();
 catfileoutstr = AppendNullByte(catheaersize, formatspecs[5]) + catfileoutstr;
 catfileheadercshex = GetFileChecksum(catfileoutstr, checksumtype, True, formatspecs);
 catfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex], formatspecs[5]);
 catfileoutstrecd = catfileoutstr.encode('UTF-8');
 nullstrecd = formatspecs[5].encode('UTF-8');
 catfileout = catfileoutstrecd + filecontent + nullstrecd;
 fp.write(catfileout);
 try:
  fp.flush();
  os.fsync(fp.fileno());
 except io.UnsupportedOperation:
  pass;
 except AttributeError:
  pass;
 return fp;

def AppendFilesWithContent(infiles, fp, dirlistfromtxt=False, filevalues=[], extradata=[], followlink=False, checksumtype="crc32", formatspecs=__file_format_list__, verbose=False):
 advancedlist = True;
 if(verbose):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(infiles=="-"):
  for line in sys.stdin:
   infilelist.append(line.strip());
  infilelist = list(filter(None, infilelist));
 elif(infiles!="-" and dirlistfromtxt and os.path.exists(infiles) and (os.path.isfile(infiles) or infiles=="/dev/null" or infiles=="NUL")):
  if(not os.path.exists(infiles) or not os.path.isfile(infiles)):
   return False;
  with UncompressFile(infiles, formatspecs, "r") as finfile:
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
 fnumfiles = int(len(GetDirList));
 AppendFileHeader(fp, fnumfiles, checksumtype, formatspecs);
 fnumfiles = format(fnumfiles, 'x').lower();
 for curfname in GetDirList:
  catfhstart = fp.tell();
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
  elif(stat.S_ISLNK(fpremode)):
   ftype = 2;
  elif(stat.S_ISCHR(fpremode)):
   ftype = 3;
  elif(stat.S_ISBLK(fpremode)):
   ftype = 4;
  elif(stat.S_ISDIR(fpremode)):
   ftype = 5;
  elif(stat.S_ISFIFO(fpremode)):
   ftype = 6;
  elif(stat.S_ISSOCK(fpremode)):
   ftype = 8;
  elif(hasattr(stat, "S_ISDOOR") and stat.S_ISDOOR(fpremode)):
   ftype = 9;
  elif(hasattr(stat, "S_ISPORT") and stat.S_ISPORT(fpremode)):
   ftype = 10;
  elif(hasattr(stat, "S_ISWHT") and stat.S_ISWHT(fpremode)):
   ftype = 111;
  else:
   ftype = 0;
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
  elif(ftype==0 or ftype==7):
   fsize = format(int(fstatinfo.st_size), 'x').lower();
  else:
   fsize = format(int(fstatinfo.st_size)).lower();
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
  chunk_size = 1024;
  if(ftype==0 or ftype==7):
   with open(fname, "rb") as fpc:
    while(True):
     chunk = fpc.read(chunk_size);
     if(not chunk):
      break
     fcontents += chunk;
  if(followlink and (ftype==1 or ftype==2)):
   flstatinfo = os.stat(flinkname);
   with open(flinkname, "rb") as fpc:
    while(True):
     chunk = fpc.read(chunk_size);
     if(not chunk):
      break;
     fcontents += chunk;
  ftypehex = format(ftype, 'x').lower();
  catoutlist = [ftypehex, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev_minor, fdev_major, frdev_minor, frdev_major];
  fp = AppendFileHeaderWithContent(fp, catoutlist, extradata, fcontents, checksumtype, formatspecs);
 fp.seek(0, 0);
 return fp;

def AppendListsWithContent(inlist, fp, dirlistfromtxt=False, filevalues=[], extradata=[], followlink=False, checksumtype="crc32", formatspecs=__file_format_list__, verbose=False):
 advancedlist = True;
 if(verbose):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 GetDirList = inlist;
 if(not GetDirList):
  return False;
 curinode = 0;
 curfid = 0;
 inodelist = [];
 inodetofile = {};
 filetoinode = {};
 inodetocatinode = {};
 fnumfiles = int(len(GetDirList));
 AppendFileHeader(fp, fnumfiles, checksumtype, formatspecs);
 fnumfiles = format(fnumfiles, 'x').lower();
 for curfname in GetDirList:
  ftype = format(curfname[0], 'x').lower();
  if(re.findall("^[.|/]", curfname[1])):
   fname = curfname[1];
  else:
   fname = "./"+curfname[1];
  fbasedir = os.path.dirname(fname);
  flinkname = curfname[2];
  fsize = format(curfname[3], 'x').lower();
  fatime = format(curfname[4], 'x').lower();
  fmtime = format(curfname[5], 'x').lower();
  fctime = format(curfname[6], 'x').lower();
  fbtime = format(curfname[7], 'x').lower();
  fmode = format(curfname[8], 'x').lower();
  fwinattributes = format(curfname[9], 'x').lower();
  fuid = format(curfname[10], 'x').lower();
  funame = curfname[11];
  fgid = format(curfname[12], 'x').lower();
  fgname = curfname[13];
  fid = format(curfname[14], 'x').lower();
  finode = format(curfname[15], 'x').lower();
  flinkcount = format(curfname[16], 'x').lower();
  fdev_minor = format(curfname[17], 'x').lower();
  fdev_major = format(curfname[18], 'x').lower();
  frdev_minor = format(curfname[19], 'x').lower();
  frdev_major = format(curfname[20], 'x').lower();
  extradata = curfname[21];
  fchecksumtype = curfname[22];
  fcontents = curfname[23];
  catoutlist = [ftype, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fuid, funame, fgid, fgname, fid, finode, flinkcount, fdev_minor, fdev_major, frdev_minor, frdev_major];
  fp = AppendFileHeaderWithContent(fp, catoutlist, extradata, fcontents, checksumtype, formatspecs);
 fp.seek(0, 0);
 return fp;

def AppendInFileWithContent(infile, fp, dirlistfromtxt=False, filevalues=[], extradata=[], followlink=False, checksumtype="crc32", formatspecs=__file_format_list__, verbose=False):
 inlist = ReadInFileBySizeWithContentToList(infile, 0, 0, False, False, formatspecs);
 return AppendListsWithContent(inlist, fp, dirlistfromtxt, filevalues, extradata, followlink, checksumtype, formatspecs, verbose);

def AppendFilesWithContentToOutFile(infiles, outfile, dirlistfromtxt=False, compression="auto", compressionlevel=None, filevalues=[], extradata=[], followlink=False, checksumtype="crc32", formatspecs=__file_format_list__, verbose=False, returnfp=False):
 if(outfile!="-" and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
  if(os.path.exists(outfile)):
   os.unlink(outfile);
 if(outfile=="-"):
  verbose = False;
  catfpfp = BytesIO();
 elif(hasattr(outfile, "read") or hasattr(outfile, "write")):
  catfp = outfile;
 elif(re.findall(r"^(ftp|ftps|sftp)\:\/\/", str(outfile))):
  catfp = BytesIO();
 else:
  fbasename = os.path.splitext(outfile)[0];
  fextname = os.path.splitext(outfile)[1];
  catfp = CompressOpenFile(outfile, compressionlevel);
 catfp = AppendFilesWithContent(infiles, catfp, dirlistfromtxt, filevalues, extradata, followlink, checksumtype, formatspecs, verbose);
 if(outfile=="-" or hasattr(outfile, "read") or hasattr(outfile, "write")):
  catfp = CompressArchiveFile(catfp, compression, formatspecs);
  try:
   catfp.flush();
   os.fsync(catfp.fileno());
  except io.UnsupportedOperation:
   pass;
  except AttributeError:
   pass;
 if(outfile=="-"):
  catfp.seek(0, 0);
  if(hasattr(sys.stdout, "buffer")):
   shutil.copyfileobj(catfp, sys.stdout.buffer);
  else:
   shutil.copyfileobj(catfp, sys.stdout);
 elif(re.findall(r"^(ftp|ftps|sftp)\:\/\/", str(outfile))):
  catfp = CompressArchiveFile(catfp, compression, formatspecs);
  catfp.seek(0, 0);
  upload_file_to_internet_file(catfp, outfile);
 if(returnfp):
  catfp.seek(0, 0);
  return catfp;
 else:
  catfp.close();
  return True;

def AppendListsWithContentToOutFile(inlist, outfile, dirlistfromtxt=False, compression="auto", compressionlevel=None, filevalues=[], extradata=[], followlink=False, checksumtype="crc32", formatspecs=__file_format_list__, verbose=False, returnfp=False):
 if(outfile!="-" and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
  if(os.path.exists(outfile)):
   os.unlink(outfile);
 if(outfile=="-"):
  verbose = False;
  catfpfp = BytesIO();
 elif(hasattr(outfile, "read") or hasattr(outfile, "write")):
  catfp = outfile;
 elif(re.findall(r"^(ftp|ftps|sftp)\:\/\/", str(outfile))):
  catfp = BytesIO();
 else:
  fbasename = os.path.splitext(outfile)[0];
  fextname = os.path.splitext(outfile)[1];
  catfp = CompressOpenFile(outfile, compressionlevel);
 catfp = AppendListsWithContent(inlist, catfp, dirlistfromtxt, filevalues, extradata, followlink, checksumtype, formatspecs, verbose);
 if(outfile=="-" or hasattr(outfile, "read") or hasattr(outfile, "write")):
  catfp = CompressArchiveFile(catfp, compression, formatspecs);
  try:
   catfp.flush();
   os.fsync(catfp.fileno());
  except io.UnsupportedOperation:
   pass;
  except AttributeError:
   pass;
 if(outfile=="-"):
  catfp.seek(0, 0);
  if(hasattr(sys.stdout, "buffer")):
   shutil.copyfileobj(catfp, sys.stdout.buffer);
  else:
   shutil.copyfileobj(catfp, sys.stdout);
 elif(re.findall(r"^(ftp|ftps|sftp)\:\/\/", str(outfile))):
  catfp = CompressArchiveFile(catfp, compression, formatspecs);
  catfp.seek(0, 0);
  upload_file_to_internet_file(catfp, outfile);
 if(returnfp):
  catfp.seek(0, 0);
  return catfp;
 else:
  catfp.close();
  return True;

def AppendInFileWithContentToOutFile(infile, outfile, dirlistfromtxt=False, compression="auto", compressionlevel=None, filevalues=[], extradata=[], followlink=False, checksumtype="crc32", formatspecs=__file_format_list__, verbose=False, returnfp=False):
 inlist = ReadInFileBySizeWithContentToList(infile, 0, 0, False, False, formatspecs);
 return AppendListsWithContentToOutFile(inlist, outfile, dirlistfromtxt, compression, compressionlevel, filevalues, extradata, followlink, checksumtype, formatspecs, verbose, returnfp);

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

def CheckCompressionType(infile, formatspecs=__file_format_list__, closefp=True):
 if(hasattr(infile, "read") or hasattr(infile, "write")):
  catfp = infile;
 else:
  try:
   catfp = open(infile, "rb");
  except FileNotFoundError:
   return False;
 catfp.seek(0, 0);
 prefp = catfp.read(2);
 filetype = False;
 if(prefp==binascii.unhexlify("1f8b")):
  filetype = "gzip";
 catfp.seek(0, 0);
 prefp = catfp.read(3);
 if(prefp==binascii.unhexlify("425a68")):
  filetype = "bzip2";
 if(prefp==binascii.unhexlify("5d0000")):
  filetype = "lzma";
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
 prefp = catfp.read(6);
 if(prefp==binascii.unhexlify("fd377a585a00")):
  filetype = "lzma";
 catfp.seek(0, 0);
 prefp = catfp.read(7);
 if(prefp==binascii.unhexlify("526172211a0700")):
  filetype = "rarfile";
 if(prefp==binascii.unhexlify("43617446696c65")):
  filetype = "catfile";
 catfp.seek(0, 0);
 prefp = catfp.read(8);
 if(prefp==binascii.unhexlify("526172211a070100")):
  filetype = "rarfile";
 catfp.seek(0, 0);
 prefp = catfp.read(formatspecs[3]);
 if(prefp==binascii.unhexlify(formatspecs[4])):
  filetype = formatspecs[2];
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

def CheckCompressionTypeFromString(instring, formatspecs=__file_format_list__, closefp=True):
 try:
  instringsfile = BytesIO(instring);
 except TypeError:
  instringsfile = BytesIO(instring.encode("UTF-8"));
 return CheckCompressionType(instringsfile, formatspecs, closefp);

def GetCompressionMimeType(infile, formatspecs=__file_format_list__):
 compresscheck = CheckCompressionType(fp, formatspecs, False);
 if(compresscheck=="gzip" or compresscheck=="gz"):
  return archivefile_gzip_mimetype;
 if(compresscheck=="bzip2" or compresscheck=="bz2"):
  return archivefile_bzip2_mimetype;
 if(compresscheck=="zstd" or compresscheck=="zstandard"):
  return archivefile_zstandard_mimetype;
 if(compresscheck=="lz4"):
  return archivefile_lz4_mimetype;
 if(compresscheck=="lzo" or compresscheck=="lzop"):
  return archivefile_lzop_mimetype;
 if(compresscheck=="lzma"):
  return archivefile_lzma_mimetype;
 if(compresscheck=="xz"):
  return archivefile_xz_mimetype;
 if(compresscheck=="catfile" or compresscheck=="cat" or compresscheck==formatspecs[2]):
  return archivefile_cat_mimetype;
 if(not compresscheck):
  return False;
 return False;

def UncompressArchiveFile(fp, formatspecs=__file_format_list__):
 if(not hasattr(fp, "read") and not hasattr(fp, "write")):
  return False;
 compresscheck = CheckCompressionType(fp, formatspecs, False);
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
 if(compresscheck=="catfile" or compresscheck==formatspecs[2]):
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

create_alias_function("Uncompress", __file_format_name__, "", UncompressArchiveFile);

def UncompressFile(infile, formatspecs=__file_format_list__, mode="rb"):
 compresscheck = CheckCompressionType(infile, formatspecs, False);
 if(sys.version_info[0]==2 and compresscheck):
  if(mode=="rt"):
   mode = "r";
  if(mode=="wt"):
   mode = "w";
 try:
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
  if(compresscheck=="catfile" or compresscheck==formatspecs[2]):
   try:
    filefp = open(infile, mode, encoding="UTF-8");
   except (ValueError, TypeError) as e:
    filefp = open(infile, mode);
  if(not compresscheck):
   try:
    filefp = open(infile, mode, encoding="UTF-8");
   except (ValueError, TypeError) as e:
    filefp = open(infile, mode);
 except FileNotFoundError:
  return False;
 return filefp;

def UncompressString(infile):
 compresscheck = CheckCompressionTypeFromString(infile, formatspecs, False);
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
 filefp.seek(0, 0);
 return filefp;

def CheckCompressionSubType(infile, formatspecs=__file_format_list__):
 compresscheck = CheckCompressionType(infile, formatspecs, False);
 if(not compresscheck):
  fextname = os.path.splitext(infile)[1];
  if(fextname==".gz"):
   compresscheck = "gzip";
  elif(fextname==".bz2"):
   compresscheck = "bzip2";
  elif(fextname==".zst"):
   compresscheck = "zstd";
  elif(fextname==".lz4"):
   compresscheck = "lz4";
  elif(fextname==".lzo" or fextname==".lzop"):
   compresscheck = "lzo";
  elif(fextname==".lzma" or fextname==".xz"):
   compresscheck = "lzma";
  else:
   return False;
 if(not compresscheck):
  return False;
 if(compresscheck=="catfile"):
  return "catfile";
 if(compresscheck==formatspecs[2]):
  return formatspecs[2];
 if(compresscheck=="tarfile"):
  return "tarfile";
 if(compresscheck=="zipfile"):
  return "zipfile";
 if(hasattr(infile, "read") or hasattr(infile, "write")):
  catfp = UncompressArchiveFile(infile, formatspecs[2]);
 else:
  try:
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
  except FileNotFoundError:
   return False;
 filetype = False;
 prefp = catfp.read(5);
 if(prefp==binascii.unhexlify("7573746172")):
  filetype = "tarfile";
 catfp.seek(0, 0);
 prefp = catfp.read(7);
 if(prefp==binascii.unhexlify("43617446696c65")):
  filetype = "catfile";
 catfp.seek(0, 0);
 prefp = catfp.read(formatspecs[3]);
 if(prefp==binascii.unhexlify(formatspecs[4])):
  filetype = formatspecs[2];
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
 try:
  catfp = open(tmpfp.name, "rb");
 except FileNotFoundError:
  return False;
 catdata = catfp.read();
 catfp.close();
 return catdata;

def CompressArchiveFile(fp, compression="auto", compressionlevel=None, formatspecs=__file_format_list__):
 if(not hasattr(fp, "read") and not hasattr(fp, "write")):
  return False;
 fp.seek(0, 0);
 if(not compression or compression or compression=="catfile" or compression==formatspecs[2]):
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
  catfp.write(lzma.compress(fp.read(), format=lzma.FORMAT_ALONE, filters=[{"id": lzma.FILTER_LZMA1, "preset": compressionlevel}]));
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
  catfp.write(lzma.compress(fp.read(), format=lzma.FORMAT_XZ, filters=[{"id": lzma.FILTER_LZMA2, "preset": compressionlevel}]));
 if(compression=="auto" or compression is None):
  catfp = fp;
 catfp.seek(0, 0);
 return catfp;

create_alias_function("Compress", __file_format_name__, "", CompressArchiveFile);

def CompressOpenFile(outfile, compressionlevel=None):
 if(outfile is None):
  return False;
 fbasename = os.path.splitext(outfile)[0];
 fextname = os.path.splitext(outfile)[1];
 if(compressionlevel is None and fextname!=".zst"):
  compressionlevel = 9;
 elif(compressionlevel is None and fextname==".zst"):
  compressionlevel = 10;
 else:
  compressionlevel = int(compressionlevel);
 if(sys.version_info[0]==2):
  mode = "w";
 else:
  mode = "wb";
 try:
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
   try:
    outfp = gzip.open(outfile, mode, compressionlevel, encoding="UTF-8");
   except (ValueError, TypeError) as e:
    outfp = gzip.open(outfile, mode, compressionlevel);
  elif(fextname==".bz2"):
   try:
    import bz2;
   except ImportError:
    return False;
   try:
    outfp = bz2.open(outfile, mode, compressionlevel, encoding="UTF-8");
   except (ValueError, TypeError) as e:
    outfp = bz2.open(outfile, mode, compressionlevel);
  elif(fextname==".zst"):
   try:
    import zstandard;
   except ImportError:
    return False;
   try:
    outfp = zstandard.open(outfile, mode, zstandard.ZstdCompressor(level=compressionlevel), encoding="UTF-8");
   except (ValueError, TypeError) as e:
    outfp = zstandard.open(outfile, mode, zstandard.ZstdCompressor(level=compressionlevel));
  elif(fextname==".xz"):
   try:
    import lzma;
   except ImportError:
    return False;
   try:
    outfp = lzma.open(outfile, mode, format=lzma.FORMAT_XZ, filters=[{"id": lzma.FILTER_LZMA2, "preset": compressionlevel}], encoding="UTF-8");
   except (ValueError, TypeError) as e:
    outfp = lzma.open(outfile, mode, format=lzma.FORMAT_XZ, filters=[{"id": lzma.FILTER_LZMA2, "preset": compressionlevel}]);
  elif(fextname==".lz4"):
   try:
    import lz4.frame;
   except ImportError:
    return False;
   try:
    outfp = lz4.frame.open(outfile, mode, compression_level=compressionlevel, encoding="UTF-8");
   except (ValueError, TypeError) as e:
    outfp = lz4.frame.open(outfile, mode, compression_level=compressionlevel);
  elif(fextname==".lzo"):
   try:
    import lzo;
   except ImportError:
    return False;
   try:
    outfp = lzo.open(outfile, mode, compresslevel=compressionlevel, encoding="UTF-8");
   except (ValueError, TypeError) as e:
    outfp = lzo.open(outfile, mode, compresslevel=compressionlevel);
  elif(fextname==".lzma"):
   try:
    import lzma;
   except ImportError:
    return False;
   try:
    outfp = lzma.open(outfile, mode, format=lzma.FORMAT_ALONE, filters=[{"id": lzma.FILTER_LZMA1, "preset": compressionlevel}], encoding="UTF-8");
   except (ValueError, TypeError) as e:
    outfp = lzma.open(outfile, mode, format=lzma.FORMAT_ALONE, filters=[{"id": lzma.FILTER_LZMA1, "preset": compressionlevel}]);
 except FileNotFoundError:
  return False;
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

def PackArchiveFile(infiles, outfile, dirlistfromtxt=False, compression="auto", compressionlevel=None, followlink=False, checksumtype="crc32", extradata=[], formatspecs=__file_format_list__, verbose=False, returnfp=False):
 advancedlist = True;
 if(outfile!="-" and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
  outfile = RemoveWindowsPath(outfile);
 checksumtype = checksumtype.lower();
 if(not CheckSumSupport(checksumtype, hashlib_guaranteed)):
  checksumtype="crc32";
 if(checksumtype=="none"):
  checksumtype = "";
 if(not compression or compression or compression=="catfile" or compression==formatspecs[2]):
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
 elif(re.findall(r"^(ftp|ftps|sftp)\:\/\/", str(outfile))):
  catfp = BytesIO();
 else:
  fbasename = os.path.splitext(outfile)[0];
  fextname = os.path.splitext(outfile)[1];
  catfp = CompressOpenFile(outfile, compressionlevel);
 catver = formatspecs[6];
 fileheaderver = str(int(catver.replace(".", "")));
 fileheader = AppendNullByte(formatspecs[1] + fileheaderver, formatspecs[5]);
 catfp.write(fileheader.encode('UTF-8'));
 infilelist = [];
 if(infiles=="-"):
  for line in sys.stdin:
   infilelist.append(line.strip());
  infilelist = list(filter(None, infilelist));
 elif(infiles!="-" and dirlistfromtxt and os.path.exists(infiles) and (os.path.isfile(infiles) or infiles=="/dev/null" or infiles=="NUL")):
  if(not os.path.exists(infiles) or not os.path.isfile(infiles)):
   return False;
  with UncompressFile(infiles, formatspecs, "r") as finfile:
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
 fnumfilesa = AppendNullBytes([fnumfiles, checksumtype], formatspecs[5]);
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
 else:
  catfileheadercshex = format(0, 'x').lower
 fnumfilesa = fnumfilesa + AppendNullByte(catfileheadercshex, formatspecs[5]);
 catfp.write(fnumfilesa.encode('UTF-8'));
 try:
  catfp.flush();
  os.fsync(catfp.fileno());
 except io.UnsupportedOperation:
  pass;
 except AttributeError:
  pass;
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
  elif(stat.S_ISLNK(fpremode)):
   ftype = 2;
  elif(stat.S_ISCHR(fpremode)):
   ftype = 3;
  elif(stat.S_ISBLK(fpremode)):
   ftype = 4;
  elif(stat.S_ISDIR(fpremode)):
   ftype = 5;
  elif(stat.S_ISFIFO(fpremode)):
   ftype = 6;
  elif(stat.S_ISSOCK(fpremode)):
   ftype = 8;
  elif(hasattr(stat, "S_ISDOOR") and stat.S_ISDOOR(fpremode)):
   ftype = 9;
  elif(hasattr(stat, "S_ISPORT") and stat.S_ISPORT(fpremode)):
   ftype = 10;
  elif(hasattr(stat, "S_ISWHT") and stat.S_ISWHT(fpremode)):
   ftype = 111;
  else:
   ftype = 0;
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
  elif(ftype==0 or ftype==7):
   fsize = format(int(fstatinfo.st_size), 'x').lower();
  else:
   fsize = format(int(fstatinfo.st_size)).lower();
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
  chunk_size = 1024;
  if(ftype==0 or ftype==7):
   with open(fname, "rb") as fpc:
    while(True):
     chunk = fpc.read(chunk_size);
     if(not chunk):
      break
     fcontents += chunk;
  if(followlink and (ftype==1 or ftype==2)):
   flstatinfo = os.stat(flinkname);
   with open(flinkname, "rb") as fpc:
    while(True):
     chunk = fpc.read(chunk_size);
     if(not chunk):
      break;
     fcontents += chunk;
  ftypehex = format(ftype, 'x').lower();
  extrafields = format(len(extradata), 'x').lower();
  extrasizestr = AppendNullByte(extrafields, formatspecs[5]);
  if(len(extradata)>0):
   extrasizestr = extrasizestr + AppendNullBytes(extradata, formatspecs[5]);
  extrasizelen = format(len(extrasizestr), 'x').lower();
  catoutlist = [ftypehex, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev_minor, fdev_major, frdev_minor, frdev_major, extrasizelen, extrafields];
  catoutlen = len(catoutlist) + len(extradata) + 3;
  catoutlenhex = format(catoutlen, 'x').lower();
  catoutlist.insert(0, catoutlenhex);
  catfileoutstr = AppendNullBytes(catoutlist, formatspecs[5]);
  if(len(extradata)>0):
   catfileoutstr = catfileoutstr + AppendNullBytes(extradata, formatspecs[5]);
  catfileoutstr = catfileoutstr + AppendNullByte(checksumtype, formatspecs[5]);
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
  else:
   catfileheadercshex = format(0, 'x').lower();
   catfilecontentcshex = format(0, 'x').lower();
  tmpfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex], formatspecs[5]);
  catheaersize = format(int(len(tmpfileoutstr) - 1), 'x').lower()
  catfileoutstr = AppendNullByte(catheaersize, formatspecs[5]) + catfileoutstr;
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
  else:
   catfileheadercshex = format(0, 'x').lower();
  catfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex], formatspecs[5]);
  catfhend = (catfp.tell() - 1) + len(catfileoutstr);
  catfcontentstart = catfp.tell() + len(catfileoutstr);
  catfileoutstrecd = catfileoutstr.encode('UTF-8');
  nullstrecd = formatspecs[5].encode('UTF-8');
  catfileout = catfileoutstrecd + fcontents + nullstrecd;
  catfcontentend = (catfp.tell() - 1) + len(catfileout);
  catfp.write(catfileout);
  try:
   catfp.flush();
   os.fsync(catfp.fileno());
  except io.UnsupportedOperation:
   pass;
  except AttributeError:
   pass;
 if(outfile=="-" or hasattr(outfile, "read") or hasattr(outfile, "write")):
  catfp = CompressArchiveFile(catfp, compression, formatspecs);
  try:
   catfp.flush();
   os.fsync(catfp.fileno());
  except io.UnsupportedOperation:
   pass;
  except AttributeError:
   pass;
 if(outfile=="-"):
  catfp.seek(0, 0);
  if(hasattr(sys.stdout, "buffer")):
   shutil.copyfileobj(catfp, sys.stdout.buffer);
  else:
   shutil.copyfileobj(catfp, sys.stdout);
 elif(re.findall(r"^(ftp|ftps|sftp)\:\/\/", str(outfile))):
  catfp = CompressArchiveFile(catfp, compression, formatspecs);
  catfp.seek(0, 0);
  upload_file_to_internet_file(catfp, outfile);
 if(returnfp):
  catfp.seek(0, 0);
  return catfp;
 else:
  catfp.close();
  return True;

create_alias_function("Pack", __file_format_name__, "", PackArchiveFile);

if(hasattr(shutil, "register_archive_format")):
 def PackArchiveFileFunc(archive_name, source_dir, **kwargs):
  return PackArchiveFile(source_dir, archive_name, False, "auto", None, False, "crc32", [], __file_format_delimiter__, False, False);
 create_alias_function("Pack", __file_format_name__, "Func", PackArchiveFileFunc);

def PackArchiveFileFromDirList(infiles, outfile, dirlistfromtxt=False, compression="auto", compressionlevel=None, followlink=False, checksumtype="crc32", extradata=[], formatspecs=__file_format_list__, verbose=False, returnfp=False):
 return PackArchiveFile(infiles, outfile, dirlistfromtxt, compression, compressionlevel, followlink, checksumtype, extradata, formatspecs, verbose, returnfp);

def PackArchiveFileFromTarFile(infile, outfile, compression="auto", compressionlevel=None, checksumtype="crc32", extradata=[], formatspecs=__file_format_list__, verbose=False, returnfp=False):
 if(outfile!="-" and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
  outfile = RemoveWindowsPath(outfile);
 checksumtype = checksumtype.lower();
 if(not CheckSumSupport(checksumtype, hashlib_guaranteed)):
  checksumtype="crc32";
 if(checksumtype=="none"):
  checksumtype = "";
 if(not compression or compression or compression=="catfile" or compression==formatspecs[2]):
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
 elif(re.findall(r"^(ftp|ftps|sftp)\:\/\/", str(outfile))):
  catfp = BytesIO();
 else:
  fbasename = os.path.splitext(outfile)[0];
  fextname = os.path.splitext(outfile)[1];
  catfp = CompressOpenFile(outfile, compressionlevel);
 catver = formatspecs[6];
 fileheaderver = str(int(catver.replace(".", "")));
 fileheader = AppendNullByte(formatspecs[1] + fileheaderver, formatspecs[5]);
 catfp.write(fileheader.encode('UTF-8'));
 curinode = 0;
 curfid = 0;
 inodelist = [];
 inodetofile = {};
 filetoinode = {};
 inodetocatinode = {};
 if(infile=="-"):
  infile = BytesIO();
  if(hasattr(sys.stdin, "buffer")):
   shutil.copyfileobj(sys.stdin.buffer, infile);
  else:
   shutil.copyfileobj(sys.stdin, infile);
  infile.seek(0, 0);
  if(not infile):
   return False;
  infile.seek(0, 0);
 elif(re.findall(r"^(http|https|ftp|ftps|sftp)\:\/\/", str(infile))):
  infile = download_file_from_internet_file(infile);
  infile.seek(0, 0);
  if(not infile):
   return False;
  infile.seek(0, 0);
 elif(not os.path.exists(infile) or not os.path.isfile(infile)):
  return False;
 elif(os.path.exists(infile) and os.path.isfile(infile)):
  try:
   if(not tarfile.is_tarfile(infile)):
    return False;
  except AttributeError:
   if(not is_tarfile(infile)):
    return False;
 else:
  return False;
 try:
  if(hasattr(infile, "read") or hasattr(infile, "write")):
   tarfp = tarfile.open(fileobj=infile, mode="r");
  else:
   tarfp = tarfile.open(infile, "r");
 except FileNotFoundError:
  return False;
 fnumfiles = format(int(len(tarfp.getmembers())), 'x').lower();
 fnumfilesa = AppendNullBytes([fnumfiles, checksumtype], formatspecs[5]);
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
 else:
  catfileheadercshex = format(0, 'x').lower();
 fnumfilesa = fnumfilesa + AppendNullByte(catfileheadercshex, formatspecs[5]);
 catfp.write(fnumfilesa.encode('UTF-8'));
 try:
  catfp.flush();
  os.fsync(catfp.fileno());
 except io.UnsupportedOperation:
  pass;
 except AttributeError:
  pass;
 for member in sorted(tarfp.getmembers(), key=lambda x: x.name):
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
  elif(member.isdev()):
   ffullmode = member.mode;
   ftype = 7;
  elif(member.islnk()):
   ffullmode = member.mode + stat.S_IFREG;
   ftype = 1;
  elif(member.issym()):
   ffullmode = member.mode + stat.S_IFLNK;
   ftype = 2;
  elif(member.ischr()):
   ffullmode = member.mode + stat.S_IFCHR;
   ftype = 3;
  elif(member.isblk()):
   ffullmode = member.mode + stat.S_IFBLK;
   ftype = 4;
  elif(member.isdir()):
   ffullmode = member.mode + stat.S_IFDIR;
   ftype = 5;
  elif(member.isfifo()):
   ffullmode = member.mode + stat.S_IFIFO;
   ftype = 6;
  elif(member.issparse()):
   ffullmode = member.mode;
   ftype = 12;
  else:
   ffullmode = member.mode;
   ftype = 0;
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
  elif(ftype==0 or ftype==7):
   fsize = format(int(member.size), 'x').lower();
  else:
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
  fwinattributes = format(int(0), 'x').lower();
  fcontents = "".encode('UTF-8');
  chunk_size = 1024;
  if(ftype==0 or ftype==7):
   with tarfp.extractfile(member) as fpc:
    while(True):
     chunk = fpc.read(chunk_size);
     if(not chunk):
      break
     fcontents += chunk;
  ftypehex = format(ftype, 'x').lower();
  extrafields = format(len(extradata), 'x').lower();
  extrasizestr = AppendNullByte(extrafields, formatspecs[5]);
  if(len(extradata)>0):
   extrasizestr = extrasizestr + AppendNullBytes(extradata, formatspecs[5]);
  extrasizelen = format(len(extrasizestr), 'x').lower();
  catoutlist = [ftypehex, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev_minor, fdev_major, frdev_minor, frdev_major, extrasizelen, extrafields];
  catoutlen = len(catoutlist) + len(extradata) + 3;
  catoutlenhex = format(catoutlen, 'x').lower();
  catoutlist.insert(0, catoutlenhex);
  catfileoutstr = AppendNullBytes(catoutlist, formatspecs[5]);
  if(len(extradata)>0):
   catfileoutstr = catfileoutstr + AppendNullBytes(extradata, formatspecs[5]);
  catfileoutstr = catfileoutstr + AppendNullByte(checksumtype, formatspecs[5]);
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
  else:
   catfileheadercshex = format(0, 'x').lower();
   catfilecontentcshex = format(0, 'x').lower();
  tmpfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex], formatspecs[5]);
  catheaersize = format(int(len(tmpfileoutstr) - 1), 'x').lower()
  catfileoutstr = AppendNullByte(catheaersize, formatspecs[5]) + catfileoutstr;
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
  else:
   catfileheadercshex = format(0, 'x').lower();
  catfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex], formatspecs[5]);
  catfileoutstrecd = catfileoutstr.encode('UTF-8');
  nullstrecd = formatspecs[5].encode('UTF-8');
  catfileout = catfileoutstrecd + fcontents + nullstrecd;
  catfcontentend = (catfp.tell() - 1) + len(catfileout);
  catfp.write(catfileout);
  try:
   catfp.flush();
   os.fsync(catfp.fileno());
  except io.UnsupportedOperation:
   pass;
  except AttributeError:
   pass;
 if(outfile=="-" or hasattr(outfile, "read") or hasattr(outfile, "write")):
  catfp = CompressArchiveFile(catfp, compression, formatspecs);
  try:
   catfp.flush();
   os.fsync(catfp.fileno());
  except io.UnsupportedOperation:
   pass;
  except AttributeError:
   pass;
 if(outfile=="-"):
  catfp.seek(0, 0);
  if(hasattr(sys.stdout, "buffer")):
   shutil.copyfileobj(catfp, sys.stdout.buffer);
  else:
   shutil.copyfileobj(catfp, sys.stdout);
 elif(re.findall(r"^(ftp|ftps|sftp)\:\/\/", str(outfile))):
  catfp = CompressArchiveFile(catfp, compression, formatspecs);
  catfp.seek(0, 0);
  upload_file_from_internet_file(catfp, outfile);
 if(returnfp):
  catfp.seek(0, 0);
  return catfp;
 else:
  catfp.close();
  return True;

create_alias_function("Pack", __file_format_name__, "FromTarFile", PackArchiveFileFromTarFile);

def PackArchiveFileFromZipFile(infile, outfile, compression="auto", compressionlevel=None, checksumtype="crc32", extradata=[], formatspecs=__file_format_list__, verbose=False, returnfp=False):
 if(outfile!="-" and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
  outfile = RemoveWindowsPath(outfile);
 checksumtype = checksumtype.lower();
 if(not CheckSumSupport(checksumtype, hashlib_guaranteed)):
  checksumtype="crc32";
 if(checksumtype=="none"):
  checksumtype = "";
 if(not compression or compression or compression=="catfile" or compression==formatspecs[2]):
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
 elif(re.findall(r"^(ftp|ftps|sftp)\:\/\/", str(outfile))):
  catfp = BytesIO();
 else:
  fbasename = os.path.splitext(outfile)[0];
  fextname = os.path.splitext(outfile)[1];
  catfp = CompressOpenFile(outfile, compressionlevel);
 catver = formatspecs[6];
 fileheaderver = str(int(catver.replace(".", "")));
 fileheader = AppendNullByte(formatspecs[1] + fileheaderver, formatspecs[5]);
 catfp.write(fileheader.encode('UTF-8'));
 curinode = 0;
 curfid = 0;
 inodelist = [];
 inodetofile = {};
 filetoinode = {};
 inodetocatinode = {};
 if(infile=="-"):
  infile = BytesIO();
  if(hasattr(sys.stdin, "buffer")):
   shutil.copyfileobj(sys.stdin.buffer, infile);
  else:
   shutil.copyfileobj(sys.stdin, infile);
  infile.seek(0, 0);
  if(not infile):
   return False;
  infile.seek(0, 0);
 elif(re.findall(r"^(http|https|ftp|ftps|sftp)\:\/\/", str(infile))):
  infile = download_file_from_internet_file(infile);
  infile.seek(0, 0);
  if(not infile):
   return False;
  infile.seek(0, 0);
 elif(not os.path.exists(infile) or not os.path.isfile(infile)):
  return False;
 else:
  return False;
 if(not zipfile.is_zipfile(infile)):
  return False;
 try:
  zipfp = zipfile.ZipFile(infile, "r", allowZip64=True);
 except FileNotFoundError:
  return False;
 ziptest = zipfp.testzip();
 if(ziptest):
  VerbosePrintOut("Bad file found!");
 fnumfiles = format(int(len(zipfp.infolist())), 'x').lower();
 fnumfilesa = AppendNullBytes([fnumfiles, checksumtype], formatspecs[5]);
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
 else:
  catfileheadercshex = format(0, 'x').lower();
 fnumfilesa = fnumfilesa + AppendNullByte(catfileheadercshex, formatspecs[5]);
 catfp.write(fnumfilesa.encode('UTF-8'));
 try:
  catfp.flush();
  os.fsync(catfp.fileno());
 except io.UnsupportedOperation:
  pass;
 except AttributeError:
  pass;
 for member in sorted(zipfp.infolist(), key=lambda x: x.filename):
  catfhstart = catfp.tell();
  if(re.findall("^[.|/]", member.filename)):
   fname = member.filename;
  else:
   fname = "./"+member.filename;
  zipinfo = zipfp.getinfo(member.filename);
  if(verbose):
   VerbosePrintOut(fname);
  if(not member.is_dir()):
   fpremode = int(stat.S_IFREG + 438);
  elif(member.is_dir()):
   fpremode = int(stat.S_IFDIR + 511);
  flinkcount = 0;
  ftype = 0;
  if(not member.is_dir()):
   ftype = 0;
  elif(member.is_dir()):
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
  elif(ftype==0):
   fsize = format(int(member.file_size), 'x').lower();
  else:
   fsize = format(int(member.file_size), 'x').lower();
  fatime = format(int(time.mktime(member.date_time + (0, 0, -1))), 'x').lower();
  fmtime = format(int(time.mktime(member.date_time + (0, 0, -1))), 'x').lower();
  fctime = format(int(time.mktime(member.date_time + (0, 0, -1))), 'x').lower();
  fbtime = format(int(time.mktime(member.date_time + (0, 0, -1))), 'x').lower();
  if(zipinfo.create_system==0 or zipinfo.create_system==10):
   fwinattributes = format(int(zipinfo.external_attr), 'x').lower();
   if(not member.is_dir()):
    fmode = format(int(stat.S_IFREG + 438), 'x').lower();
    fchmode = stat.S_IMODE(fmode);
    ftypemod = stat.S_IFMT(fmode);
   elif(member.is_dir()):
    fmode = format(int(stat.S_IFDIR + 511), 'x').lower();
    fchmode = stat.S_IMODE(fmode);
    ftypemod = stat.S_IFMT(fmode);
  elif(zipinfo.create_system==3):
   fwinattributes = format(int(0), 'x').lower();
   fmode = format(int(zipinfo.external_attr), 'x').lower();
   fchmode = stat.S_IMODE(fmode);
   ftypemod = stat.S_IFMT(fmode);
  else:
   fwinattributes = format(int(0), 'x').lower();
   if(not member.is_dir()):
    fmode = format(int(stat.S_IFREG + 438), 'x').lower();
    fchmode = stat.S_IMODE(fmode);
    ftypemod = stat.S_IFMT(fmode);
   elif(member.is_dir()):
    fmode = format(int(stat.S_IFDIR + 511), 'x').lower();
    fchmode = stat.S_IMODE(fmode);
    ftypemod = stat.S_IFMT(fmode);
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
  extrasizestr = AppendNullByte(extrafields, formatspecs[5]);
  if(len(extradata)>0):
   extrasizestr = extrasizestr + AppendNullBytes(extradata, formatspecs[5]);
  extrasizelen = format(len(extrasizestr), 'x').lower();
  catoutlist = [ftypehex, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev_minor, fdev_major, frdev_minor, frdev_major, extrasizelen, extrafields];
  catoutlen = len(catoutlist) + len(extradata) + 3;
  catoutlenhex = format(catoutlen, 'x').lower();
  catoutlist.insert(0, catoutlenhex);
  catfileoutstr = AppendNullBytes(catoutlist, formatspecs[5]);
  if(len(extradata)>0):
   catfileoutstr = catfileoutstr + AppendNullBytes(extradata, formatspecs[5]);
  catfileoutstr = catfileoutstr + AppendNullByte(checksumtype, formatspecs[5]);
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
  else:
   catfileheadercshex = format(0, 'x').lower();
   catfilecontentcshex = format(0, 'x').lower();
  tmpfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex], formatspecs[5]);
  catheaersize = format(int(len(tmpfileoutstr) - 1), 'x').lower()
  catfileoutstr = AppendNullByte(catheaersize, formatspecs[5]) + catfileoutstr;
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
  else:
   catfileheadercshex = format(0, 'x').lower();
  catfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex], formatspecs[5]);
  catfileoutstrecd = catfileoutstr.encode('UTF-8');
  nullstrecd = formatspecs[5].encode('UTF-8');
  catfileout = catfileoutstrecd + fcontents + nullstrecd;
  catfcontentend = (catfp.tell() - 1) + len(catfileout);
  catfp.write(catfileout);
  try:
   catfp.flush();
   os.fsync(catfp.fileno());
  except io.UnsupportedOperation:
   pass;
  except AttributeError:
   pass;
 if(outfile=="-" or hasattr(outfile, "read") or hasattr(outfile, "write")):
  catfp = CompressArchiveFile(catfp, compression, formatspecs);
  try:
   catfp.flush();
   os.fsync(catfp.fileno());
  except io.UnsupportedOperation:
   pass;
  except AttributeError:
   pass;
 if(outfile=="-"):
  catfp.seek(0, 0);
  if(hasattr(sys.stdout, "buffer")):
   shutil.copyfileobj(catfp, sys.stdout.buffer);
  else:
   shutil.copyfileobj(catfp, sys.stdout);
 elif(re.findall(r"^(ftp|ftps|sftp)\:\/\/", str(outfile))):
  catfp = CompressArchiveFile(catfp, compression, formatspecs);
  catfp.seek(0, 0);
  upload_file_to_internet_file(catfp, outfile);
 if(returnfp):
  catfp.seek(0, 0);
  return catfp;
 else:
  catfp.close();
  return True;

create_alias_function("Pack", __file_format_name__, "FromZipFile", PackArchiveFileFromZipFile);

if(not rarfile_support):
 def PackArchiveFileFromRarFile(infile, outfile, compression="auto", compressionlevel=None, checksumtype="crc32", extradata=[], formatspecs=__file_format_list__, verbose=False, returnfp=False):
  return False

if(rarfile_support):
 def PackArchiveFileFromRarFile(infile, outfile, compression="auto", compressionlevel=None, checksumtype="crc32", extradata=[], formatspecs=__file_format_list__, verbose=False, returnfp=False):
  if(outfile!="-" and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
   outfile = RemoveWindowsPath(outfile);
  checksumtype = checksumtype.lower();
  if(not CheckSumSupport(checksumtype, hashlib_guaranteed)):
   checksumtype="crc32";
  if(checksumtype=="none"):
   checksumtype = "";
  if(not compression or compression or compression=="catfile" or compression==formatspecs[2]):
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
  elif(re.findall(r"^(ftp|ftps|sftp)\:\/\/", str(outfile))):
   catfp = BytesIO();
  else:
   fbasename = os.path.splitext(outfile)[0];
   fextname = os.path.splitext(outfile)[1];
   catfp = CompressOpenFile(outfile, compressionlevel);
  catver = formatspecs[6];
  fileheaderver = str(int(catver.replace(".", "")));
  fileheader = AppendNullByte(formatspecs[1] + fileheaderver, formatspecs[5]);
  catfp.write(fileheader.encode('UTF-8'));
  curinode = 0;
  curfid = 0;
  inodelist = [];
  inodetofile = {};
  filetoinode = {};
  inodetocatinode = {};
  if(not os.path.exists(infile) or not os.path.isfile(infile)):
   return False;
  if(not rarfile.is_rarfile(infile) and not rarfile.is_rarfile_sfx(infile)):
   return False;
  rarfp = rarfile.RarFile(infile, "r");
  rartest = rarfp.testrar();
  if(rartest):
   VerbosePrintOut("Bad file found!");
  fnumfiles = format(int(len(rarfp.infolist())), 'x').lower();
  fnumfilesa = AppendNullBytes([fnumfiles, checksumtype], formatspecs[5]);
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
  else:
   catfileheadercshex = format(0, 'x').lower();
  fnumfilesa = fnumfilesa + AppendNullByte(catfileheadercshex, formatspecs[5]);
  catfp.write(fnumfilesa.encode('UTF-8'));
  try:
   catfp.flush();
   os.fsync(catfp.fileno());
  except io.UnsupportedOperation:
   pass;
  except AttributeError:
   pass;
  for member in sorted(rarfp.infolist(), key=lambda x: x.filename):
   is_unix = False;
   is_windows = False;
   if(member.host_os==rarfile.RAR_OS_UNIX):
    is_windows = False;
    try:
     member.external_attr
     is_unix = True;
    except AttributeError:
     is_unix = False;
   elif(member.host_os==rarfile.RAR_OS_WIN32):
    is_unix = False;
    try:
     member.external_attr
     is_windows = True;
    except AttributeError:
     is_windows = False;
   else:
    is_unix = False;
    is_windows = False;
   catfhstart = catfp.tell();
   if(re.findall("^[.|/]", member.filename)):
    fname = member.filename;
   else:
    fname = "./"+member.filename;
   rarinfo = rarfp.getinfo(member.filename);
   if(verbose):
    VerbosePrintOut(fname);
   if(is_unix and member.external_attr !=0):
    fpremode = int(member.external_attr);
   elif(member.is_file()):
    fpremode = int(stat.S_IFREG + 438);
   elif(member.is_symlink()):
    fpremode = int(stat.S_IFLNK + 438);
   elif(member.is_dir()):
    fpremode = int(stat.S_IFDIR + 511);
   if(is_windows and member.external_attr !=0):
    fwinattributes = format(int(member.external_attr), 'x').lower();
   else:
    fwinattributes = format(int(0), 'x').lower();
   flinkcount = 0;
   ftype = 0;
   if(member.is_file()):
    ftype = 0;
   elif(member.is_symlink()):
    ftype = 2;
   elif(member.is_dir()):
    ftype = 5;
   flinkname = "";
   if(ftype==2):
    flinkname = rarfp.read(member.filename).decode("UTF-8");
   fcurfid = format(int(curfid), 'x').lower();
   fcurinode = format(int(0), 'x').lower();
   curfid = curfid + 1;
   fdev_minor = format(int(0), 'x').lower();
   fdev_major = format(int(0), 'x').lower();
   frdev_minor = format(int(0), 'x').lower();
   frdev_major = format(int(0), 'x').lower();
   if(ftype==5):
    fsize = format(int("0"), 'x').lower();
   elif(ftype==0):
    fsize = format(int(member.file_size), 'x').lower();
   else:
    fsize = format(int(member.file_size), 'x').lower();
   try:
    if(member.atime):
     fatime = format(int(member.atime.timestamp()), 'x').lower();
    else:
     fatime = format(int(member.mtime.timestamp()), 'x').lower();
   except AttributeError:
    fatime = format(int(member.mtime.timestamp()), 'x').lower();
   fmtime = format(int(member.mtime.timestamp()), 'x').lower();
   try:
    if(member.ctime):
     fctime = format(int(member.ctime.timestamp()), 'x').lower();
    else:
     fctime = format(int(member.mtime.timestamp()), 'x').lower();
   except AttributeError:
    fctime = format(int(member.mtime.timestamp()), 'x').lower();
   fbtime = format(int(member.mtime.timestamp()), 'x').lower();
   if(is_unix and member.external_attr !=0):
    fmode = format(int(member.external_attr), 'x').lower();
    fchmode = format(int(stat.S_IMODE(member.external_attr)), 'x').lower();
    ftypemod = format(int(stat.S_IFMT(member.external_attr)), 'x').lower();
   elif(member.is_file()):
    fmode = format(int(stat.S_IFREG + 438), 'x').lower();
    fchmode = format(int(stat.S_IMODE(int(stat.S_IFREG + 438))), 'x').lower();
    ftypemod = format(int(stat.S_IFMT(int(stat.S_IFREG + 438))), 'x').lower();
   elif(member.is_symlink()):
    fmode = format(int(stat.S_IFLNK + 438), 'x').lower();
    fchmode = format(int(stat.S_IMODE(int(stat.S_IFREG + 438))), 'x').lower();
    ftypemod = format(int(stat.S_IFMT(int(stat.S_IFREG + 438))), 'x').lower();
   elif(member.is_dir()):
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
    fcontents = rarfp.read(member.filename);
   ftypehex = format(ftype, 'x').lower();
   extrafields = format(len(extradata), 'x').lower();
   extrasizestr = AppendNullByte(extrafields, formatspecs[5]);
   if(len(extradata)>0):
    extrasizestr = extrasizestr + AppendNullBytes(extradata, formatspecs[5]);
   extrasizelen = format(len(extrasizestr), 'x').lower();
   catoutlist = [ftypehex, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev_minor, fdev_major, frdev_minor, frdev_major, extrasizelen, extrafields];
   catoutlen = len(catoutlist) + len(extradata) + 3;
   catoutlenhex = format(catoutlen, 'x').lower();
   catoutlist.insert(0, catoutlenhex);
   catfileoutstr = AppendNullBytes(catoutlist, formatspecs[5]);
   if(len(extradata)>0):
    catfileoutstr = catfileoutstr + AppendNullBytes(extradata, formatspecs[5]);
   catfileoutstr = catfileoutstr + AppendNullByte(checksumtype, formatspecs[5]);
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
   else:
    catfileheadercshex = format(0, 'x').lower();
    catfilecontentcshex = format(0, 'x').lower();
   tmpfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex], formatspecs[5]);
   catheaersize = format(int(len(tmpfileoutstr) - 1), 'x').lower()
   catfileoutstr = AppendNullByte(catheaersize, formatspecs[5]) + catfileoutstr
   if(checksumtype=="none" or checksumtype==""):
    catfileheadercshex = format(0, 'x').lower()
   elif(checksumtype=="crc16" or checksumtype=="crc16_ansi" or checksumtype=="crc16_ibm"):
    catfileheadercshex = format(crc16(catfileoutstr.encode('UTF-8')) & 0xffff, '04x').lower()
   elif(checksumtype=="crc16_ccitt"):
    catfileheadercshex = format(crc16_ccitt(catfileoutstr.encode('UTF-8')) & 0xffff, '04x').lower()
   elif(checksumtype=="adler32"):
    catfileheadercshex = format(zlib.adler32(catfileoutstr.encode('UTF-8')) & 0xffffffff, '08x').lower()
   elif(checksumtype=="crc32"):
    catfileheadercshex = format(crc32(catfileoutstr.encode('UTF-8')) & 0xffffffff, '08x').lower()
   elif(checksumtype=="crc64_ecma"):
    catfileheadercshex = format(crc64_ecma(catfileoutstr.encode('UTF-8')) & 0xffffffffffffffff, '016x').lower()
   elif(checksumtype=="crc64" or checksumtype=="crc64_iso"):
    catfileheadercshex = format(crc64_iso(catfileoutstr.encode('UTF-8')) & 0xffffffffffffffff, '016x').lower()
   elif(CheckSumSupportAlt(checksumtype, hashlib_guaranteed)):
    checksumoutstr = hashlib.new(checksumtype)
    checksumoutstr.update(catfileoutstr.encode('UTF-8'))
    catfileheadercshex = checksumoutstr.hexdigest().lower()
   else:
    catfileheadercshex = format(0, 'x').lower()
   catfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex], formatspecs[5])
   catfileoutstrecd = catfileoutstr.encode('UTF-8')
   nullstrecd = formatspecs[5].encode('UTF-8')
   catfileout = catfileoutstrecd + fcontents + nullstrecd
   catfcontentend = (catfp.tell() - 1) + len(catfileout)
   catfp.write(catfileout)
   try:
    catfp.flush()
    os.fsync(catfp.fileno())
   except io.UnsupportedOperation:
    pass
   except AttributeError:
    pass
  if(outfile=="-" or hasattr(outfile, "read") or hasattr(outfile, "write")):
   catfp = CompressArchiveFile(catfp, compression, formatspecs)
   try:
    catfp.flush()
    os.fsync(catfp.fileno())
   except io.UnsupportedOperation:
    pass
   except AttributeError:
    pass
  if(outfile=="-"):
   catfp.seek(0, 0)
   if(hasattr(sys.stdout, "buffer")):
    shutil.copyfileobj(catfp, sys.stdout.buffer);
   else:
    shutil.copyfileobj(catfp, sys.stdout);
  elif(re.findall(r"^(ftp|ftps|sftp)\:\/\/", str(outfile))):
   catfp = CompressArchiveFile(catfp, compression, formatspecs);
   catfp.seek(0, 0);
   upload_file_to_internet_file(catfp, outfile);
  if(returnfp):
   catfp.seek(0, 0)
   return catfp
  else:
   catfp.close()
   return True;

create_alias_function("Pack", __file_format_name__, "FromRarFile", PackArchiveFileFromRarFile);

def ArchiveFileSeekToFileNum(infile, seekto=0, skipchecksum=False, formatspecs=__file_format_list__, returnfp=False):
 if(hasattr(infile, "read") or hasattr(infile, "write")):
  catfp = infile;
  catfp.seek(0, 0);
  catfp = UncompressArchiveFile(catfp, formatspecs);
  checkcompressfile = CheckCompressionSubType(catfp, formatspecs);
  if(checkcompressfile=="tarfile"):
   return TarFileToArray(infile, 0, 0, listonly, skipchecksum, formatspecs, returnfp);
  if(checkcompressfile=="zipfile"):
   return ZipFileToArray(infile, 0, 0, listonly, skipchecksum, formatspecs, returnfp);
  if(rarfile_support and checkcompressfile=="rarfile"):
   return RarFileToArray(infile, 0, 0, listonly, skipchecksum, formatspecs, returnfp);
  if(checkcompressfile!="catfile" and checkcompressfile!=formatspecs[2]):
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
  catfp = UncompressArchiveFile(catfp, formatspecs);
  if(not catfp):
   return False;
  catfp.seek(0, 0);
 elif(re.findall(r"^(http|https|ftp|ftps|sftp)\:\/\/", str(infile))):
  catfp = download_file_from_internet_file(infile);
  catfp.seek(0, 0);
  catfp = UncompressArchiveFile(catfp, formatspecs);
  if(not catfp):
   return False;
  catfp.seek(0, 0);
 else:
  infile = RemoveWindowsPath(infile);
  checkcompressfile = CheckCompressionSubType(infile, formatspecs);
  if(checkcompressfile=="tarfile"):
   return TarFileToArray(infile, 0, 0, listonly, skipchecksum, formatspecs, returnfp);
  if(checkcompressfile=="zipfile"):
   return ZipFileToArray(infile, 0, 0, listonly, skipchecksum, formatspecs, returnfp);
  if(rarfile_support and checkcompressfile=="rarfile"):
   return RarFileToArray(infile, 0, 0, listonly, skipchecksum, formatspecs, returnfp);
  if(checkcompressfile!="catfile" and checkcompressfile!=formatspecs[2]):
   return False;
  compresscheck = CheckCompressionType(infile, formatspecs, True);
  if(not compresscheck):
   fextname = os.path.splitext(infile)[1];
   if(fextname==".gz"):
    compresscheck = "gzip";
   elif(fextname==".bz2"):
    compresscheck = "bzip2";
   elif(fextname==".zst"):
    compresscheck = "zstd";
   elif(fextname==".lz4" or fextname==".clz4"):
    compresscheck = "lz4";
   elif(fextname==".lzo" or fextname==".lzop"):
    compresscheck = "lzo";
   elif(fextname==".lzma" or fextname==".xz"):
    compresscheck = "lzma";
   else:
    return False;
  if(not compresscheck):
   return False;
  catfp = UncompressFile(infile, formatspecs, "rb");
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
 catheader = ReadFileHeaderData(catfp, 4, formatspecs[5]);
 catstring = catheader[0];
 catversion = re.findall(r"([\d]+)$", catstring);
 fprenumfiles = catheader[1];
 fnumfiles = int(fprenumfiles, 16);
 fprechecksumtype = catheader[2];
 fprechecksum = catheader[3];
 fileheader = AppendNullByte(catstring, formatspecs[5]);
 fnumfileshex = format(int(fnumfiles), 'x').lower();
 fileheader = fileheader + AppendNullBytes([fnumfileshex, fprechecksumtype], formatspecs[5]);
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
 else:
  catfileheadercshex = format(0, 'x').lower();
 fileheader = fileheader + AppendNullByte(catfileheadercshex, formatspecs[5]);
 fheadtell = len(fileheader);
 if(fprechecksum!=catfileheadercshex and not skipchecksum):
  VerbosePrintOut("File Header Checksum Error with file " + infile + " at offset " + str(0));
  return False;
 catversions = re.search(r'(.*?)(\d+)$', catstring).groups();
 catlist = {'fnumfiles': fnumfiles, 'fformat': catversions[0], 'fversion': catversions[1], 'fformatspecs': formatspecs, 'fchecksumtype': fprechecksumtype, 'fheaderchecksum': fprechecksum, 'ffilelist': {}};
 if(seekto>=fnumfiles):
  seekto = fnumfiles - 1;
 if(seekto<0):
  seekto = 0;
 if(seekto>=0):
  il = -1;
  while(il < seekto):
   prefhstart = catfp.tell();
   if(formatspecs[7]):
    preheaderdata = ReadFileHeaderDataBySize(catfp, formatspecs[5]);
   else:
    preheaderdata = ReadFileHeaderDataWoSize(catfp, formatspecs[5]);
   prefheadsize = int(preheaderdata[0], 16);
   prefnumfields = int(preheaderdata[1], 16);
   preftype = int(preheaderdata[2], 16);
   if(re.findall("^[.|/]", preheaderdata[3])):
    prefname = preheaderdata[3];
   else:
    prefname = "./"+preheaderdata[3];
   prefbasedir = os.path.dirname(prefname);
   preflinkname = preheaderdata[4];
   prefsize = int(preheaderdata[5], 16);
   prefatime = int(preheaderdata[6], 16);
   prefmtime = int(preheaderdata[7], 16);
   prefctime = int(preheaderdata[8], 16);
   prefbtime = int(preheaderdata[9], 16);
   prefmode = int(preheaderdata[10], 16);
   prefchmode = stat.S_IMODE(prefmode);
   preftypemod = stat.S_IFMT(prefmode);
   prefwinattributes = int(preheaderdata[11], 16);
   prefuid = int(preheaderdata[12], 16);
   prefuname = preheaderdata[13];
   prefgid = int(preheaderdata[14], 16);
   prefgname = preheaderdata[15];
   fid = int(preheaderdata[16], 16);
   finode = int(preheaderdata[17], 16);
   flinkcount = int(preheaderdata[18], 16);
   prefdev_minor = int(preheaderdata[19], 16);
   prefdev_major = int(preheaderdata[20], 16);
   prefrdev_minor = int(preheaderdata[22], 16);
   prefrdev_major = int(preheaderdata[23], 16);
   prefextrasize = int(preheaderdata[24], 16);
   prefextrafields = int(preheaderdata[25], 16);
   extrafieldslist = [];
   extrastart = 25;
   extraend = extrastart + prefextrafields;
   extrafieldslist = [];
   if(extrastart<extraend):
    extrafieldslist.append(preheaderdata[extrastart]);
    extrastart = extrastart + 1;
   prefchecksumtype = preheaderdata[extrastart].lower();
   prefcs = preheaderdata[extrastart + 1].lower();
   prefccs = preheaderdata[extrastart + 2].lower();
   hc = 0;
   hcmax = len(preheaderdata) - 2;
   hout = "";
   while(hc<hcmax):
    hout = hout + AppendNullByte(preheaderdata[hc], formatspecs[5]);
    hc = hc + 1;
   if(prefchecksumtype=="none" or prefchecksumtype==""):
    prenewfcs = 0;
   elif(prefchecksumtype=="crc16" or prefchecksumtype=="crc16_ansi" or prefchecksumtype=="crc16_ibm"):
    prenewfcs = format(crc16(hout.encode('UTF-8')) & 0xffff, '04x').lower();
   elif(prefchecksumtype=="adler32"):
    prenewfcs = format(zlib.adler32(hout.encode('UTF-8')) & 0xffffffff, '08x').lower();
   elif(prefchecksumtype=="crc32"):
    prenewfcs = format(crc32(hout.encode('UTF-8')) & 0xffffffff, '08x').lower();
   elif(prefchecksumtype=="crc64_ecma"):
    prenewfcs = format(crc64_ecma(hout.encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
   elif(prefchecksumtype=="crc64" or prefchecksumtype=="crc64_iso"):
    prenewfcs = format(crc64_iso(hout.encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
   elif(CheckSumSupportAlt(prefchecksumtype, hashlib_guaranteed)):
    checksumoutstr = hashlib.new(prefchecksumtype);
    checksumoutstr.update(hout.encode('UTF-8'));
    prenewfcs = checksumoutstr.hexdigest().lower();
   if(prefcs!=prenewfcs and not skipchecksum):
    VerbosePrintOut("File Header Checksum Error with file " + prefname + " at offset " + str(prefhstart));
    return False;
    valid_archive = False;
    invalid_archive = True;
   prefhend = catfp.tell() - 1;
   prefcontentstart = catfp.tell();
   prefcontents = "";
   pyhascontents = False;
   if(prefsize>0):
    prefcontents = catfp.read(prefsize);
    if(prefchecksumtype=="none" or prefchecksumtype==""):
     prenewfccs = 0;
    elif(prefchecksumtype=="crc16" or prefchecksumtype=="crc16_ansi" or prefchecksumtype=="crc16_ibm"):
     prenewfccs = format(crc16(prefcontents) & 0xffff, '04x').lower();
    elif(prefchecksumtype=="crc16_ccitt"):
     prenewfcs = format(crc16_ccitt(prefcontents) & 0xffff, '04x').lower();
    elif(prefchecksumtype=="adler32"):
     prenewfccs = format(zlib.adler32(prefcontents) & 0xffffffff, '08x').lower();
    elif(prefchecksumtype=="crc32"):
     prenewfccs = format(crc32(prefcontents) & 0xffffffff, '08x').lower();
    elif(prefchecksumtype=="crc64_ecma"):
     prenewfcs = format(crc64_ecma(prefcontents) & 0xffffffffffffffff, '016x').lower();
    elif(prefchecksumtype=="crc64" or prefchecksumtype=="crc64_iso"):
     prenewfcs = format(crc64_iso(prefcontents) & 0xffffffffffffffff, '016x').lower();
    elif(CheckSumSupportAlt(prefchecksumtype, hashlib_guaranteed)):
     checksumoutstr = hashlib.new(prefchecksumtype);
     checksumoutstr.update(prefcontents);
     prenewfccs = checksumoutstr.hexdigest().lower();
    pyhascontents = True;
    if(prefccs!=prenewfccs and not skipchecksum):
     VerbosePrintOut("File Content Checksum Error with file " + prefname + " at offset " + str(prefcontentstart));
     return False;
   catfp.seek(1, 1);
   il = il + 1;
 catfp.seek(seekstart, 0);
 fileidnum = il;
 catfheadsize = int(preheaderdata[0], 16);
 catfnumfields = int(preheaderdata[1], 16);
 catftype = int(preheaderdata[2], 16);
 if(re.findall("^[.|/]", preheaderdata[3])):
  catfname = preheaderdata[3];
 else:
  catfname = "./"+preheaderdata[3];
 catflinkname = preheaderdata[4];
 catfsize = int(preheaderdata[5], 16);
 catfbasedir = os.path.dirname(catfname);
 catlist = {'fid': fileidnum, 'foffset': catfp.tell(), 'ftype': catftype, 'fname': catfname, 'fbasedir': catfbasedir, 'flinkname': catflinkname, 'fsize': catfsize};
 if(returnfp):
  catlist.update({'catfp': catfp});
 else:
  catfp.close();
 return catlist; 

create_alias_function("", __file_format_name__, "SeekToFileNum", ArchiveFileSeekToFileNum);

def ArchiveFileSeekToFileName(infile, seekfile=None, skipchecksum=False, formatspecs=__file_format_list__, returnfp=False):
 if(hasattr(infile, "read") or hasattr(infile, "write")):
  catfp = infile;
  catfp.seek(0, 0);
  catfp = UncompressArchiveFile(catfp, formatspecs);
  checkcompressfile = CheckCompressionSubType(catfp, formatspecs);
  if(checkcompressfile=="tarfile"):
   return TarFileToArray(infile, 0, 0, listonly, skipchecksum, formatspecs, returnfp);
  if(checkcompressfile=="zipfile"):
   return ZipFileToArray(infile, 0, 0, listonly, skipchecksum, formatspecs, returnfp);
  if(rarfile_support and checkcompressfile=="rarfile"):
   return RarFileToArray(infile, 0, 0, listonly, skipchecksum, formatspecs, returnfp);
  if(checkcompressfile!="catfile" and checkcompressfile!=formatspecs[2]):
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
  catfp = UncompressArchiveFile(catfp, formatspecs);
  if(not catfp):
   return False;
  catfp.seek(0, 0);
 elif(re.findall(r"^(http|https|ftp|ftps|sftp)\:\/\/", str(infile))):
  catfp = download_file_from_internet_file(infile);
  catfp = UncompressArchiveFile(catfp, formatspecs);
  catfp.seek(0, 0);
  if(not catfp):
   return False;
  catfp.seek(0, 0);
 else:
  infile = RemoveWindowsPath(infile);
  checkcompressfile = CheckCompressionSubType(infile, formatspecs);
  if(checkcompressfile=="tarfile"):
   return TarFileToArray(infile, 0, 0, listonly, skipchecksum, formatspecs, returnfp);
  if(checkcompressfile=="zipfile"):
   return ZipFileToArray(infile, 0, 0, listonly, skipchecksum, formatspecs, returnfp);
  if(rarfile_support and checkcompressfile=="rarfile"):
   return RarFileToArray(infile, 0, 0, listonly, skipchecksum, formatspecs, returnfp);
  if(checkcompressfile!="catfile" and checkcompressfile!=formatspecs[2]):
   return False;
  compresscheck = CheckCompressionType(infile, formatspecs, True);
  if(not compresscheck):
   fextname = os.path.splitext(infile)[1];
   if(fextname==".gz"):
    compresscheck = "gzip";
   elif(fextname==".bz2"):
    compresscheck = "bzip2";
   elif(fextname==".zst"):
    compresscheck = "zstd";
   elif(fextname==".lz4" or fextname==".clz4"):
    compresscheck = "lz4";
   elif(fextname==".lzo" or fextname==".lzop"):
    compresscheck = "lzo";
   elif(fextname==".lzma" or fextname==".xz"):
    compresscheck = "lzma";
   else:
    return False;
  if(not compresscheck):
   return False;
  catfp = UncompressFile(infile, formatspecs, "rb");
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
 catheader = ReadFileHeaderData(catfp, 4, formatspecs[5]);
 catstring = catheader[0];
 catversion = re.findall(r"([\d]+)$", catstring);
 fprenumfiles = catheader[1];
 fnumfiles = int(fprenumfiles, 16);
 fprechecksumtype = catheader[2];
 fprechecksum = catheader[3];
 fileheader = AppendNullByte(catstring, formatspecs[5]);
 fnumfileshex = format(int(fnumfiles), 'x').lower();
 fileheader = fileheader + AppendNullBytes([fnumfileshex, fprechecksumtype], formatspecs[5]);
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
 else:
  catfileheadercshex = format(0, 'x').lower();
 fileheader = fileheader + AppendNullByte(catfileheadercshex, formatspecs[5]);
 fheadtell = len(fileheader);
 if(fprechecksum!=catfileheadercshex and not skipchecksum):
  VerbosePrintOut("File Header Checksum Error with file " + infile + " at offset " + str(0));
  return False;
 catversions = re.search(r'(.*?)(\d+)$', catstring).groups();
 catlist = {'fnumfiles': fnumfiles, 'fformat': catversions[0], 'fversion': catversions[1], 'fformatspecs': formatspecs, 'fchecksumtype': fprechecksumtype, 'fheaderchecksum': fprechecksum, 'ffilelist': {}};
 seekto = fnumfiles - 1
 filefound = False;
 if(seekto>=0):
  il = -1;
  while(il < seekto):
   prefhstart = catfp.tell();
   if(formatspecs[7]):
    preheaderdata = ReadFileHeaderDataBySize(catfp, formatspecs[5]);
   else:
    preheaderdata = ReadFileHeaderDataWoSize(catfp, formatspecs[5]);
   prefheadsize = int(preheaderdata[0], 16);
   prefnumfields = int(preheaderdata[1], 16);
   preftype = int(preheaderdata[2], 16);
   if(re.findall("^[.|/]", preheaderdata[3])):
    prefname = preheaderdata[3];
   else:
    prefname = "./"+preheaderdata[3];
   prefbasedir = os.path.dirname(prefname);
   preflinkname = preheaderdata[4];
   prefsize = int(preheaderdata[5], 16);
   prefatime = int(preheaderdata[6], 16);
   prefmtime = int(preheaderdata[7], 16);
   prefctime = int(preheaderdata[8], 16);
   prefbtime = int(preheaderdata[9], 16);
   prefmode = int(preheaderdata[10], 16);
   prefchmode = stat.S_IMODE(prefmode);
   preftypemod = stat.S_IFMT(prefmode);
   prefwinattributes = int(preheaderdata[11], 16);
   prefuid = int(preheaderdata[12], 16);
   prefuname = preheaderdata[13];
   prefgid = int(preheaderdata[14], 16);
   prefgname = preheaderdata[15];
   fid = int(preheaderdata[16], 16);
   finode = int(preheaderdata[17], 16);
   flinkcount = int(preheaderdata[18], 16);
   prefdev_minor = int(preheaderdata[19], 16);
   prefdev_major = int(preheaderdata[20], 16);
   prefrdev_minor = int(preheaderdata[22], 16);
   prefrdev_major = int(preheaderdata[23], 16);
   prefextrasize = int(preheaderdata[24], 16);
   prefextrafields = int(preheaderdata[25], 16);
   extrafieldslist = [];
   extrastart = 25;
   extraend = extrastart + prefextrafields;
   extrafieldslist = [];
   if(extrastart<extraend):
    extrafieldslist.append(preheaderdata[extrastart]);
    extrastart = extrastart + 1;
   prefchecksumtype = preheaderdata[extrastart].lower();
   prefcs = preheaderdata[extrastart + 1].lower();
   prefccs = preheaderdata[extrastart + 2].lower();
   hc = 0;
   hcmax = len(preheaderdata) - 2;
   hout = "";
   while(hc<hcmax):
    hout = hout + AppendNullByte(preheaderdata[hc], formatspecs[5]);
    hc = hc + 1;
   if(prefchecksumtype=="none" or prefchecksumtype==""):
    prenewfcs = 0;
   elif(prefchecksumtype=="crc16" or prefchecksumtype=="crc16_ansi" or prefchecksumtype=="crc16_ibm"):
    prenewfcs = format(crc16(hout.encode('UTF-8')) & 0xffff, '04x').lower();
   elif(prefchecksumtype=="adler32"):
    prenewfcs = format(zlib.adler32(hout.encode('UTF-8')) & 0xffffffff, '08x').lower();
   elif(prefchecksumtype=="crc32"):
    prenewfcs = format(crc32(hout.encode('UTF-8')) & 0xffffffff, '08x').lower();
   elif(prefchecksumtype=="crc64_ecma"):
    prenewfcs = format(crc64_ecma(hout.encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
   elif(prefchecksumtype=="crc64" or prefchecksumtype=="crc64_iso"):
    prenewfcs = format(crc64_iso(hout.encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
   elif(CheckSumSupportAlt(prefchecksumtype, hashlib_guaranteed)):
    checksumoutstr = hashlib.new(prefchecksumtype);
    checksumoutstr.update(hout.encode('UTF-8'));
    prenewfcs = checksumoutstr.hexdigest().lower();
   if(prefcs!=prenewfcs and not skipchecksum):
    VerbosePrintOut("File Header Checksum Error with file " + prefname + " at offset " + str(prefhstart));
    return False;
    valid_archive = False;
    invalid_archive = True;
   prefhend = catfp.tell() - 1;
   prefcontentstart = catfp.tell();
   prefcontents = "";
   pyhascontents = False;
   if(prefsize>0):
    prefcontents = catfp.read(prefsize);
    if(prefchecksumtype=="none" or prefchecksumtype==""):
     prenewfccs = 0;
    elif(prefchecksumtype=="crc16" or prefchecksumtype=="crc16_ansi" or prefchecksumtype=="crc16_ibm"):
     prenewfccs = format(crc16(prefcontents) & 0xffff, '04x').lower();
    elif(prefchecksumtype=="crc16_ccitt"):
     prenewfcs = format(crc16_ccitt(prefcontents) & 0xffff, '04x').lower();
    elif(prefchecksumtype=="adler32"):
     prenewfccs = format(zlib.adler32(prefcontents) & 0xffffffff, '08x').lower();
    elif(prefchecksumtype=="crc32"):
     prenewfccs = format(crc32(prefcontents) & 0xffffffff, '08x').lower();
    elif(prefchecksumtype=="crc64_ecma"):
     prenewfcs = format(crc64_ecma(prefcontents) & 0xffffffffffffffff, '016x').lower();
    elif(prefchecksumtype=="crc64" or prefchecksumtype=="crc64_iso"):
     prenewfcs = format(crc64_iso(prefcontents) & 0xffffffffffffffff, '016x').lower();
    elif(CheckSumSupportAlt(prefchecksumtype, hashlib_guaranteed)):
     checksumoutstr = hashlib.new(prefchecksumtype);
     checksumoutstr.update(prefcontents);
     prenewfccs = checksumoutstr.hexdigest().lower();
    pyhascontents = True;
    if(prefccs!=prenewfccs and not skipchecksum):
     VerbosePrintOut("File Content Checksum Error with file " + prefname + " at offset " + str(prefcontentstart));
     return False;
   catfp.seek(1, 1);
   il = il + 1;
   filefound = False;
   prefname = preheaderdata[2];
   if(re.findall("^[.|/]", preheaderdata[2])):
    prefname = preheaderdata[2];
   else:
    prefname = "./"+preheaderdata[2];
   if(prefname==seekfile):
    filefound = True;
    break;
 catfp.seek(seekstart, 0);
 fileidnum = il;
 catfheadsize = int(preheaderdata[0], 16);
 catfnumfields = int(preheaderdata[1], 16);
 catftype = int(preheaderdata[2], 16);
 if(re.findall("^[.|/]", preheaderdata[3])):
  catfname = preheaderdata[3];
 else:
  catfname = "./"+preheaderdata[3];
 catflinkname = preheaderdata[4];
 catfsize = int(preheaderdata[5], 16);
 catfbasedir = os.path.dirname(catfname);
 if(filefound):
  catlist = {'fid': fileidnum, 'foffset': catfp.tell(), 'ftype': catftype, 'fname': catfname, 'fbasedir': catfbasedir, 'flinkname': catflinkname, 'fsize': catfsize};
 else:
  return False;
 if(returnfp):
  catlist.update({'catfp': catfp});
 else:
  catfp.close();
 return catlist; 

create_alias_function("", __file_format_name__, "SeekToFileName", ArchiveFileSeekToFileName);

def ArchiveFileValidate(infile, formatspecs=__file_format_list__, verbose=False, returnfp=False):
 if(verbose):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(hasattr(infile, "read") or hasattr(infile, "write")):
  catfp = infile;
  catfp.seek(0, 0);
  catfp = UncompressArchiveFile(catfp, formatspecs);
  checkcompressfile = CheckCompressionSubType(catfp, formatspecs);
  if(checkcompressfile=="tarfile"):
   return TarFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp);
  if(checkcompressfile=="zipfile"):
   return ZipFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp);
  if(rarfile_support and checkcompressfile=="rarfile"):
   return RarFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp);
  if(checkcompressfile!="catfile" and checkcompressfile!=formatspecs[2]):
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
  catfp = UncompressArchiveFile(catfp, formatspecs);
  if(not catfp):
   return False;
  catfp.seek(0, 0);
 elif(re.findall(r"^(http|https|ftp|ftps|sftp)\:\/\/", str(infile))):
  catfp = download_file_from_internet_file(infile);
  catfp = UncompressArchiveFile(catfp, formatspecs);
  catfp.seek(0, 0);
  if(not catfp):
   return False;
  catfp.seek(0, 0);
 else:
  infile = RemoveWindowsPath(infile);
  checkcompressfile = CheckCompressionSubType(infile, formatspecs);
  if(checkcompressfile=="tarfile"):
   return TarFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp);
  if(checkcompressfile=="zipfile"):
   return ZipFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp);
  if(rarfile_support and checkcompressfile=="rarfile"):
   return RarFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp);
  if(checkcompressfile!="catfile" and checkcompressfile!=formatspecs[2]):
   return False;
  compresscheck = CheckCompressionType(infile, formatspecs, True);
  if(not compresscheck):
   fextname = os.path.splitext(infile)[1];
   if(fextname==".gz"):
    compresscheck = "gzip";
   elif(fextname==".bz2"):
    compresscheck = "bzip2";
   elif(fextname==".zst"):
    compresscheck = "zstd";
   elif(fextname==".lz4" or fextname==".clz4"):
    compresscheck = "lz4";
   elif(fextname==".lzo" or fextname==".lzop"):
    compresscheck = "lzo";
   elif(fextname==".lzma" or fextname==".xz"):
    compresscheck = "lzma";
   else:
    return False;
  if(not compresscheck):
   return False;
  catfp = UncompressFile(infile, formatspecs, "rb");
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
 catheader = ReadFileHeaderData(catfp, 4, formatspecs[5]);
 catstring = catheader[0];
 catversion = re.findall(r"([\d]+)$", catstring);
 fprenumfiles = catheader[1];
 fnumfiles = int(fprenumfiles, 16);
 fprechecksumtype = catheader[2];
 fprechecksum = catheader[3];
 il = 0; 
 fileheader = AppendNullByte(catstring, formatspecs[5]);
 fnumfileshex = format(int(fnumfiles), 'x').lower();
 fileheader = fileheader + AppendNullBytes([fnumfileshex, fprechecksumtype], formatspecs[5]);
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
 else:
  catfileheadercshex = format(0, 'x').lower();
 fileheader = fileheader + AppendNullByte(catfileheadercshex, formatspecs[5]);
 valid_archive = True;
 invalid_archive = False;
 if(verbose):
  VerbosePrintOut("Checking File Header Checksum of file at offset " + str(0));
  VerbosePrintOut(infile);
 if(fprechecksum==catfileheadercshex):
  if(verbose):
   VerbosePrintOut("File Header Checksum Passed");
 else:
  if(verbose):
   VerbosePrintOut("File Header Checksum Error with file " + infile + " at offset " + str(0));
  valid_archive = False;
  invalid_archive = True;
 while(il<fnumfiles):
  catfhstart = catfp.tell();
  if(formatspecs[7]):
   catheaderdata = ReadFileHeaderDataBySize(catfp, formatspecs[5]);
  else:
   catheaderdata = ReadFileHeaderDataWoSize(catfp, formatspecs[5]);
  catfheadsize = int(catheaderdata[0], 16);
  catfnumfields = int(catheaderdata[1], 16);
  catftype = int(catheaderdata[2], 16);
  if(re.findall("^[.|/]", catheaderdata[3])):
   catfname = catheaderdata[3];
  else:
   catfname = "./"+catheaderdata[3];
  catfbasedir = os.path.dirname(catfname);
  catflinkname = catheaderdata[4];
  catfsize = int(catheaderdata[5], 16);
  catfatime = int(catheaderdata[6], 16);
  catfmtime = int(catheaderdata[7], 16);
  catfctime = int(catheaderdata[8], 16);
  catfbtime = int(catheaderdata[9], 16);
  catfmode = int(catheaderdata[10], 16);
  catfchmode = stat.S_IMODE(catfmode);
  catftypemod = stat.S_IFMT(catfmode);
  prefwinattributes = int(catheaderdata[11], 16);
  catfuid = int(catheaderdata[12], 16);
  catfuname = catheaderdata[13];
  catfgid = int(catheaderdata[14], 16);
  catfgname = catheaderdata[15];
  fid = int(catheaderdata[16], 16);
  finode = int(catheaderdata[17], 16);
  flinkcount = int(catheaderdata[18], 16);
  catfdev_minor = int(catheaderdata[19], 16);
  catfdev_major = int(catheaderdata[20], 16);
  catfrdev_minor = int(catheaderdata[21], 16);
  catfrdev_major = int(catheaderdata[22], 16);
  catfextrasize = int(catheaderdata[23], 16);
  catfextrafields = int(catheaderdata[24], 16);
  extrafieldslist = [];
  extrastart = 25;
  extraend = extrastart + catfextrafields;
  extrafieldslist = [];
  if(extrastart<extraend):
   extrafieldslist.append(catheaderdata[extrastart]);
   extrastart = extrastart + 1;
  catfchecksumtype = catheaderdata[extrastart].lower();
  catfcs = catheaderdata[extrastart + 1].lower();
  catfccs = catheaderdata[extrastart + 2].lower();
  hc = 0;
  hcmax = len(catheaderdata) - 2;
  hout = "";
  while(hc<hcmax):
   hout = hout + AppendNullByte(catheaderdata[hc], formatspecs[5]);
   hc = hc + 1;
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
  if(verbose):
   VerbosePrintOut("Checking File Header Checksum of file at offset " + str(catfhstart));
   VerbosePrintOut(catfname);
  if(catfcs==catnewfcs):
   if(verbose):
    VerbosePrintOut("File Header Checksum Passed");
  else:
   if(verbose):
    VerbosePrintOut("File Header Checksum Error with file " + catfname + " at offset " + str(catfhstart));
   valid_archive = False;
   invalid_archive = True;
  catfhend = catfp.tell() - 1;
  catfcontentstart = catfp.tell();
  catfcontents = "";
  pyhascontents = False;
  if(catfsize>0):
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
   if(verbose):
    VerbosePrintOut("Checking File Content Checksum of file at offset " + str(catfcontentstart));
    VerbosePrintOut(catfname);
   if(catfccs==catnewfccs):
    if(verbose):
     VerbosePrintOut("File Content Checksum Passed");
   else:
    if(verbose):
     VerbosePrintOut("File Header Checksum Error with file " + catfname + " at offset " + str(catfcontentstart));
    valid_archive = False;
    invalid_archive = True;
  if(verbose):
   VerbosePrintOut("");
  catfp.seek(1, 1);
  il = il + 1;
 if(valid_archive):
  if(returnfp):
   return catfp;
  else:
   catfp.close();
   return True;
 else:
  catfp.close();
  return False;

create_alias_function("", __file_format_name__, "Validate", ArchiveFileValidate);

def ArchiveFileToArray(infile, seekstart=0, seekend=0, listonly=False, skipchecksum=False, formatspecs=__file_format_list__, returnfp=False):
 if(hasattr(infile, "read") or hasattr(infile, "write")):
  catfp = infile;
  catfp.seek(0, 0);
  catfp = UncompressArchiveFile(catfp, formatspecs);
  checkcompressfile = CheckCompressionSubType(catfp, formatspecs);
  if(checkcompressfile=="tarfile"):
   return TarFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp);
  if(checkcompressfile=="zipfile"):
   return ZipFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp);
  if(rarfile_support and checkcompressfile=="rarfile"):
   return RarFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp);
  if(checkcompressfile!="catfile" and checkcompressfile!=formatspecs[2]):
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
  catfp = UncompressArchiveFile(catfp, formatspecs);
  if(not catfp):
   return False;
  catfp.seek(0, 0);
 elif(re.findall(r"^(http|https|ftp|ftps|sftp)\:\/\/", str(infile))):
  catfp = download_file_from_internet_file(infile);
  catfp = UncompressArchiveFile(catfp, formatspecs);
  catfp.seek(0, 0);
  if(not catfp):
   return False;
  catfp.seek(0, 0);
 else:
  infile = RemoveWindowsPath(infile);
  checkcompressfile = CheckCompressionSubType(infile, formatspecs);
  if(checkcompressfile=="tarfile"):
   return TarFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp);
  if(checkcompressfile=="zipfile"):
   return ZipFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp);
  if(rarfile_support and checkcompressfile=="rarfile"):
   return RarFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp);
  if(checkcompressfile!="catfile" and checkcompressfile!=formatspecs[2]):
   return False;
  compresscheck = CheckCompressionType(infile, formatspecs, True);
  if(not compresscheck):
   fextname = os.path.splitext(infile)[1];
   if(fextname==".gz"):
    compresscheck = "gzip";
   elif(fextname==".bz2"):
    compresscheck = "bzip2";
   elif(fextname==".zst"):
    compresscheck = "zstd";
   elif(fextname==".lz4" or fextname==".clz4"):
    compresscheck = "lz4";
   elif(fextname==".lzo" or fextname==".lzop"):
    compresscheck = "lzo";
   elif(fextname==".lzma" or fextname==".xz"):
    compresscheck = "lzma";
   else:
    return False;
  if(not compresscheck):
   return False;
  catfp = UncompressFile(infile, formatspecs, "rb");
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
 catheader = ReadFileHeaderData(catfp, 4, formatspecs[5]);
 catstring = catheader[0];
 catversion = re.findall(r"([\d]+)$", catstring);
 fprenumfiles = catheader[1];
 fnumfiles = int(fprenumfiles, 16);
 fprechecksumtype = catheader[2];
 fprechecksum = catheader[3];
 fileheader = AppendNullByte(catstring, formatspecs[5]);
 fnumfileshex = format(int(fnumfiles), 'x').lower();
 fileheader = fileheader + AppendNullBytes([fnumfileshex, fprechecksumtype], formatspecs[5]);
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
 else:
  catfileheadercshex = format(0, 'x').lower();
 fileheader = fileheader + AppendNullByte(catfileheadercshex, formatspecs[5]);
 fheadtell = len(fileheader);
 if(fprechecksum!=catfileheadercshex and not skipchecksum):
  VerbosePrintOut("File Header Checksum Error with file " + infile + " at offset " + str(0));
  return False;
 catversions = re.search(r'(.*?)(\d+)$', catstring).groups();
 catlist = {'fnumfiles': fnumfiles, 'fformat': catversions[0], 'fversion': catversions[1], 'fformatspecs': formatspecs, 'fchecksumtype': fprechecksumtype, 'fheaderchecksum': fprechecksum, 'ffilelist': {}};
 if(seekstart<0 and seekstart>fnumfiles):
   seekstart = 0;
 if(seekend==0 or seekend>fnumfiles and seekend<seekstart):
  seekend = fnumfiles;
 elif(seekend<0 and abs(seekend)<=fnumfiles and abs(seekend)>=seekstart):
  seekend = fnumfiles - abs(seekend);
 if(seekstart>0):
  il = 0;
  while(il < seekstart):
   prefhstart = catfp.tell();
   if(formatspecs[7]):
    preheaderdata = ReadFileHeaderDataBySize(catfp, formatspecs[5]);
   else:
    preheaderdata = ReadFileHeaderDataWoSize(catfp, formatspecs[5]);
   prefheadsize = int(preheaderdata[0], 16);
   prefnumfields = int(preheaderdata[1], 16);
   if(re.findall("^[.|/]", preheaderdata[3])):
    prefname = preheaderdata[3];
   else:
    prefname = "./"+preheaderdata[3];
   prefsize = int(preheaderdata[5], 16);
   prefextrasize = int(preheaderdata[23], 16);
   prefextrafields = int(preheaderdata[24], 16);
   extrafieldslist = [];
   extrastart = 25;
   extraend = extrastart + prefextrafields;
   extrafieldslist = [];
   if(extrastart<extraend):
    extrafieldslist.append(preheaderdata[extrastart]);
    extrastart = extrastart + 1;
   prefchecksumtype = preheaderdata[extrastart].lower();
   prefcs = preheaderdata[extrastart + 1].lower();
   prefccs = preheaderdata[extrastart + 2].lower();
   hc = 0;
   hcmax = len(preheaderdata) - 2;
   hout = "";
   while(hc<hcmax):
    hout = hout + AppendNullByte(preheaderdata[hc], formatspecs[5]);
    hc = hc + 1;
   if(prefchecksumtype=="none" or prefchecksumtype==""):
    prenewfcs = 0;
   elif(prefchecksumtype=="crc16" or prefchecksumtype=="crc16_ansi" or prefchecksumtype=="crc16_ibm"):
    prenewfcs = format(crc16(hout.encode('UTF-8')) & 0xffff, '04x').lower();
   elif(prefchecksumtype=="adler32"):
    prenewfcs = format(zlib.adler32(hout.encode('UTF-8')) & 0xffffffff, '08x').lower();
   elif(prefchecksumtype=="crc32"):
    prenewfcs = format(crc32(hout.encode('UTF-8')) & 0xffffffff, '08x').lower();
   elif(prefchecksumtype=="crc64_ecma"):
    prenewfcs = format(crc64_ecma(hout.encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
   elif(prefchecksumtype=="crc64" or prefchecksumtype=="crc64_iso"):
    prenewfcs = format(crc64_iso(hout.encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
   elif(CheckSumSupportAlt(prefchecksumtype, hashlib_guaranteed)):
    checksumoutstr = hashlib.new(prefchecksumtype);
    checksumoutstr.update(hout.encode('UTF-8'));
    prenewfcs = checksumoutstr.hexdigest().lower();
   if(prefcs!=prenewfcs and not skipchecksum):
    VerbosePrintOut("File Header Checksum Error with file " + prefname + " at offset " + str(prefhstart));
    return False;
    valid_archive = False;
    invalid_archive = True;
   prefhend = catfp.tell() - 1;
   prefcontentstart = catfp.tell();
   prefcontents = "";
   pyhascontents = False;
   if(prefsize>0):
    prefcontents = catfp.read(prefsize);
    if(prefchecksumtype=="none" or prefchecksumtype==""):
     prenewfccs = 0;
    elif(prefchecksumtype=="crc16" or prefchecksumtype=="crc16_ansi" or prefchecksumtype=="crc16_ibm"):
     prenewfccs = format(crc16(prefcontents) & 0xffff, '04x').lower();
    elif(prefchecksumtype=="crc16_ccitt"):
     prenewfcs = format(crc16_ccitt(prefcontents) & 0xffff, '04x').lower();
    elif(prefchecksumtype=="adler32"):
     prenewfccs = format(zlib.adler32(prefcontents) & 0xffffffff, '08x').lower();
    elif(prefchecksumtype=="crc32"):
     prenewfccs = format(crc32(prefcontents) & 0xffffffff, '08x').lower();
    elif(prefchecksumtype=="crc64_ecma"):
     prenewfcs = format(crc64_ecma(prefcontents) & 0xffffffffffffffff, '016x').lower();
    elif(prefchecksumtype=="crc64" or prefchecksumtype=="crc64_iso"):
     prenewfcs = format(crc64_iso(prefcontents) & 0xffffffffffffffff, '016x').lower();
    elif(CheckSumSupportAlt(prefchecksumtype, hashlib_guaranteed)):
     checksumoutstr = hashlib.new(prefchecksumtype);
     checksumoutstr.update(prefcontents);
     prenewfccs = checksumoutstr.hexdigest().lower();
    pyhascontents = True;
    if(prefccs!=prenewfccs and not skipchecksum):
     VerbosePrintOut("File Content Checksum Error with file " + prefname + " at offset " + str(prefcontentstart));
     return False;
   catfp.seek(1, 1);
   il = il + 1;
 fileidnum = seekstart;
 realidnum = 0;
 while(fileidnum<seekend):
  catfhstart = catfp.tell();
  if(formatspecs[7]):
   catheaderdata = ReadFileHeaderDataBySize(catfp, formatspecs[5]);
  else:
   catheaderdata = ReadFileHeaderDataWoSize(catfp, formatspecs[5]);
  catfheadsize = int(catheaderdata[0], 16);
  catfnumfields = int(catheaderdata[1], 16);
  catftype = int(catheaderdata[2], 16);
  if(re.findall("^[.|/]", catheaderdata[3])):
   catfname = catheaderdata[3];
  else:
   catfname = "./"+catheaderdata[3];
  catfbasedir = os.path.dirname(catfname);
  catflinkname = catheaderdata[4];
  catfsize = int(catheaderdata[5], 16);
  catfatime = int(catheaderdata[6], 16);
  catfmtime = int(catheaderdata[7], 16);
  catfctime = int(catheaderdata[8], 16);
  catfbtime = int(catheaderdata[9], 16);
  catfmode = int(catheaderdata[10], 16);
  catfchmode = stat.S_IMODE(catfmode);
  catftypemod = stat.S_IFMT(catfmode);
  catfwinattributes = int(catheaderdata[11], 16);
  catfuid = int(catheaderdata[12], 16);
  catfuname = catheaderdata[13];
  catfgid = int(catheaderdata[14], 16);
  catfgname = catheaderdata[15];
  fid = int(catheaderdata[16], 16);
  finode = int(catheaderdata[17], 16);
  flinkcount = int(catheaderdata[18], 16);
  catfdev_minor = int(catheaderdata[19], 16);
  catfdev_major = int(catheaderdata[20], 16);
  catfrdev_minor = int(catheaderdata[21], 16);
  catfrdev_major = int(catheaderdata[22], 16);
  catfextrasize = int(catheaderdata[23], 16);
  catfextrafields = int(catheaderdata[24], 16);
  extrafieldslist = [];
  extrastart = 25;
  extraend = extrastart + catfextrafields;
  extrafieldslist = [];
  if(extrastart<extraend):
   extrafieldslist.append(catheaderdata[extrastart]);
   extrastart = extrastart + 1;
  catfchecksumtype = catheaderdata[extrastart].lower();
  catfcs = catheaderdata[extrastart + 1].lower();
  catfccs = catheaderdata[extrastart + 2].lower();
  hc = 0;
  hcmax = len(catheaderdata) - 2;
  hout = "";
  while(hc<hcmax):
   hout = hout + AppendNullByte(catheaderdata[hc], formatspecs[5]);
   hc = hc + 1;
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
    VerbosePrintOut("File Content Checksum Error with file " + catfname + " at offset " + str(catfcontentstart));
    return False;
  if(catfsize>0 and listonly):
   catfp.seek(catfsize, 1);
   pyhascontents = False;
  catfp.seek(1, 1);
  catfcontentend = catfp.tell() - 1;
  catlist['ffilelist'].update({realidnum: {'fid': realidnum, 'fidalt': fileidnum, 'fheadersize': catfheadsize, 'fhstart': catfhstart, 'fhend': catfhend, 'ftype': catftype, 'fname': catfname, 'fbasedir': catfbasedir, 'flinkname': catflinkname, 'fsize': catfsize, 'fatime': catfatime, 'fmtime': catfmtime, 'fctime': catfctime, 'fbtime': catfbtime, 'fmode': catfmode, 'fchmode': catfchmode, 'ftypemod': catftypemod, 'fwinattributes': catfwinattributes, 'fuid': catfuid, 'funame': catfuname, 'fgid': catfgid, 'fgname': catfgname, 'finode': finode, 'flinkcount': flinkcount, 'fminor': catfdev_minor, 'fmajor': catfdev_major, 'frminor': catfrdev_minor, 'frmajor': catfrdev_major, 'fchecksumtype': catfchecksumtype, 'fnumfields': catfnumfields + 2, 'frawheader': catheaderdata, 'fextrafields': catfextrafields, 'fextrafieldsize': catfextrasize, 'fextralist': extrafieldslist, 'fheaderchecksum': catfcs, 'fcontentchecksum': catfccs, 'fhascontents': pyhascontents, 'fcontentstart': catfcontentstart, 'fcontentend': catfcontentend, 'fcontents': catfcontents} });
  fileidnum = fileidnum + 1;
  realidnum = realidnum + 1;
 if(returnfp):
  catlist.update({'catfp': catfp});
 else:
  catfp.close();
 return catlist;

create_alias_function("", __file_format_name__, "ToArray", ArchiveFileToArray);

def ArchiveFileStringToArray(catstr, seekstart=0, seekend=0, listonly=False, skipchecksum=False, formatspecs=__file_format_list__, returnfp=False):
 catfp = BytesIO(catstr);
 listcatfiles = ArchiveFileToArray(catfp, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp);
 return listcatfiles;

create_alias_function("", __file_format_name__, "StringToArray", ArchiveFileStringToArray);

def TarFileToArray(infile, seekstart=0, seekend=0, listonly=False, skipchecksum=False, formatspecs=__file_format_list__, returnfp=False):
 catfp = BytesIO();
 catfp = PackArchiveFileFromTarFile(infile, catfp, "auto", None, "crc32", [], formatspecs, False, True);
 listcatfiles = ArchiveFileToArray(catfp, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp);
 return listcatfiles;

def ZipFileToArray(infile, seekstart=0, seekend=0, listonly=False, skipchecksum=False, formatspecs=__file_format_list__, returnfp=False):
 catfp = BytesIO();
 catfp = PackArchiveFileFromZipFile(infile, catfp, "auto", None, "crc32", [], formatspecs, False, True);
 listcatfiles = ArchiveFileToArray(catfp, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp);
 return listcatfiles;

if(not rarfile_support):
 def RarFileToArray(infile, seekstart=0, seekend=0, listonly=False, skipchecksum=False, formatspecs=__file_format_list__, returnfp=False):
  return False;

if(rarfile_support):
 def RarFileToArray(infile, seekstart=0, seekend=0, listonly=False, skipchecksum=False, formatspecs=__file_format_list__, returnfp=False):
  catfp = BytesIO();
  catfp = PackArchiveFileFromRarFile(infile, catfp, "auto", None, "crc32", [], formatspecs, False, True);
  listcatfiles = ArchiveFileToArray(catfp, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp);
  return listcatfiles;

def ListDirToArrayAlt(infiles, dirlistfromtxt=False, followlink=False, listonly=False, checksumtype="crc32", extradata=[], formatspecs=__file_format_list__, verbose=False):
 catver = formatspecs[6];
 fileheaderver = str(int(catver.replace(".", "")));
 fileheader = AppendNullByte(formatspecs[1] + fileheaderver, formatspecs[5]);
 advancedlist = True;
 infilelist = [];
 if(infiles=="-"):
  for line in sys.stdin:
   infilelist.append(line.strip());
  infilelist = list(filter(None, infilelist));
 elif(infiles!="-" and dirlistfromtxt and os.path.exists(infiles) and (os.path.isfile(infiles) or infiles=="/dev/null" or infiles=="NUL")):
  if(not os.path.exists(infiles) or not os.path.isfile(infiles)):
   return False;
  with UncompressFile(infiles, formatspecs, "r") as finfile:
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
 catver = formatspecs[6];
 fileheaderver = str(int(catver.replace(".", "")));
 fileheader = AppendNullByte(formatspecs[1] + fileheaderver, formatspecs[5]);
 fnumfileshex = format(int(fnumfiles), 'x').lower();
 fileheader = fileheader + AppendNullBytes([fnumfileshex, checksumtype], formatspecs[5]);
 catversion = re.findall(r"([\d]+)$", fileheader);
 catversions = re.search(r'(.*?)(\d+)$', catstring).groups();
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
 else:
  catfileheadercshex = format(0, 'x').lower();
 fileheader = fileheader + AppendNullByte(catfileheadercshex, formatspecs[5]);
 fheadtell = len(fileheader);
 catlist = {'fnumfiles': fnumfiles, 'fformat': catversions[0], 'fversion': catversions[1], 'fformatspecs': formatspecs, 'fchecksumtype': checksumtype, 'fheaderchecksum': catfileheadercshex, 'ffilelist': {}};
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
  elif(stat.S_ISLNK(fpremode)):
   ftype = 2;
  elif(stat.S_ISCHR(fpremode)):
   ftype = 3;
  elif(stat.S_ISBLK(fpremode)):
   ftype = 4;
  elif(stat.S_ISDIR(fpremode)):
   ftype = 5;
  elif(stat.S_ISFIFO(fpremode)):
   ftype = 6;
  elif(stat.S_ISSOCK(fpremode)):
   ftype = 8;
  elif(hasattr(stat, "S_ISDOOR") and stat.S_ISDOOR(fpremode)):
   ftype = 9;
  elif(hasattr(stat, "S_ISPORT") and stat.S_ISPORT(fpremode)):
   ftype = 10;
  elif(hasattr(stat, "S_ISWHT") and stat.S_ISWHT(fpremode)):
   ftype = 11;
  else:
   ftype = 0;
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
  chunk_size = 1024;
  if(ftype==0 or ftype==7):
   with open(fname, "rb") as fpc:
    while(True):
     chunk = fpc.read(chunk_size);
     if(not chunk):
      break
     fcontents += chunk;
  if(followlink and (ftype==1 or ftype==2)):
   flstatinfo = os.stat(flinkname);
   with open(flinkname, "rb") as fpc:
    while(True):
     chunk = fpc.read(chunk_size);
     if(not chunk):
      break;
     fcontents += chunk;
  ftypehex = format(ftype, 'x').lower();
  extrafields = len(extradata);
  extrafieldslist = extradata;
  catfextrafields = extrafields;
  extrasizestr = AppendNullByte(extrafields, formatspecs[5]);
  if(len(extradata)>0):
   extrasizestr = extrasizestr + AppendNullBytes(extradata, formatspecs[5]);
  extrasizelen = len(extrasizestr);
  extrasizelenhex = format(extrasizelen, 'x').lower();
  catoutlist = [ftypehex, fname, flinkname, format(int(fsize), 'x').lower(), format(int(fatime), 'x').lower(), format(int(fmtime), 'x').lower(), format(int(fctime), 'x').lower(), format(int(fbtime), 'x').lower(), format(int(fmode), 'x').lower(), format(int(fwinattributes), 'x').lower(), format(int(fuid), 'x').lower(), funame, format(int(fgid), 'x').lower(), fgname, format(int(fcurfid), 'x').lower(), format(int(fcurinode), 'x').lower(), format(int(flinkcount), 'x').lower(), format(int(fdev_minor), 'x').lower(), format(int(fdev_major), 'x').lower(), format(int(frdev_minor), 'x').lower(), format(int(frdev_major), 'x').lower(), extrasizelenhex, format(catfextrafields, 'x').lower()];
  catoutlen = len(catoutlist) + len(extradata) + 3;
  catoutlenhex = format(catoutlen, 'x').lower();
  catoutlist.insert(0, catoutlenhex);
  catfileoutstr = AppendNullBytes(catoutlist, formatspecs[5]);
  if(len(extradata)>0):
   catfileoutstr = catfileoutstr + AppendNullBytes(extradata, formatspecs[5]);
  catfileoutstr = catfileoutstr + AppendNullByte(checksumtype, formatspecs[5]);
  catfnumfields = catoutlen;
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
  else:
   catfileheadercshex = format(0, 'x').lower();
   catfilecontentcshex = format(0, 'x').lower();
  catfhstart = fheadtell;
  fheadtell += len(catfileoutstr);
  catfhend = fheadtell - 1;
  catfcontentstart = fheadtell;
  tmpfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex], formatspecs[5]);
  catheaersize = format(int(len(tmpfileoutstr) - 1), 'x').lower()
  catfileoutstr = AppendNullByte(catheaersize, formatspecs[5]) + catfileoutstr;
  catheaderdata = [catheaersize] + catoutlist + extradata + [checksumtype, catfileheadercshex, catfilecontentcshex]
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
  else:
   catfileheadercshex = format(0, 'x').lower();
  catfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex], formatspecs[5]);
  catfileoutstrecd = catfileoutstr.encode('UTF-8');
  nullstrecd = formatspecs[5].encode('UTF-8');
  fheadtell += len(catfileoutstr) + 1;
  catfcontentend = fheadtell - 1;
  catfileout = catfileoutstrecd + fcontents + nullstrecd;
  pyhascontents = False;
  if(int(fsize)>0 and not listonly):
   pyhascontents = True;
  if(int(fsize)>0 and listonly):
   fcontents = "";
   pyhascontents = False;
  catlist['ffilelist'].update({fileidnum: {'fid': fileidnum, 'fidalt': fileidnum, 'fheadersize': int(catheaersize, 16), 'fhstart': catfhstart, 'fhend': catfhend, 'ftype': ftype, 'fname': fname, 'fbasedir': fbasedir, 'flinkname': flinkname, 'fsize': fsize, 'fatime': fatime, 'fmtime': fmtime, 'fctime': fctime, 'fbtime': fbtime, 'fmode': fmode, 'fchmode': fchmode, 'ftypemod': ftypemod, 'fwinattributes': fwinattributes, 'fuid': fuid, 'funame': funame, 'fgid': fgid, 'fgname': fgname, 'finode': finode, 'flinkcount': flinkcount, 'fminor': fdev_minor, 'fmajor': fdev_major, 'frminor': frdev_minor, 'frmajor': frdev_major, 'fchecksumtype': checksumtype, 'fnumfields': catfnumfields + 2, 'frawheader': catheaderdata, 'fextrafields': catfextrafields, 'fextrafieldsize': extrasizelen, 'fextralist': extrafieldslist, 'fheaderchecksum': int(catfileheadercshex, 16), 'fcontentchecksum': int(catfilecontentcshex, 16), 'fhascontents': pyhascontents, 'fcontentstart': catfcontentstart, 'fcontentend': catfcontentend, 'fcontents': fcontents} });
  fileidnum = fileidnum + 1;
 return catlist;

def TarFileToArrayAlt(infiles, listonly=False, checksumtype="crc32", extradata=[], formatspecs=__file_format_list__, verbose=False):
 curinode = 0;
 curfid = 0;
 inodelist = [];
 inodetofile = {};
 filetoinode = {};
 inodetocatinode = {};
 fileidnum = 0;
 if(infile=="-"):
  infile = BytesIO();
  if(hasattr(sys.stdin, "buffer")):
   shutil.copyfileobj(sys.stdin.buffer, infile);
  else:
   shutil.copyfileobj(sys.stdin, infile);
  infile.seek(0, 0);
  if(not infile):
   return False;
  infile.seek(0, 0);
 elif(re.findall(r"^(http|https|ftp|ftps|sftp)\:\/\/", str(infile))):
  infile = download_file_from_internet_file(infile);
  infile.seek(0, 0);
  if(not infile):
   return False;
  infile.seek(0, 0);
 elif(not os.path.exists(infile) or not os.path.isfile(infile)):
  return False;
 elif(os.path.exists(infile) and os.path.isfile(infile)):
  try:
   if(not tarfile.is_tarfile(infile)):
    return False;
  except AttributeError:
   if(not is_tarfile(infile)):
    return False;
 else:
  return False;
 try:
  if(hasattr(infile, "read") or hasattr(infile, "write")):
   tarfp = tarfile.open(fileobj=infile, mode="r");
  else:
   tarfp = tarfile.open(infile, "r");
 except FileNotFoundError:
  return False;
 fnumfiles = int(len(tarfp.getmembers()));
 catver = formatspecs[6];
 fileheaderver = str(int(catver.replace(".", "")));
 fileheader = AppendNullByte(formatspecs[1] + fileheaderver, formatspecs[5]);
 fnumfileshex = format(int(fnumfiles), 'x').lower();
 fileheader = fileheader + AppendNullBytes([fnumfileshex, checksumtype], formatspecs[5]);
 catversion = re.findall(r"([\d]+)$", fileheader);
 catversions = re.search(r'(.*?)(\d+)$', catstring).groups();
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
 else:
  catfileheadercshex = format(0, 'x').lower();
 fileheader = fileheader + AppendNullByte(catfileheadercshex, formatspecs[5]);
 fheadtell = len(fileheader);
 catlist = {'fnumfiles': fnumfiles, 'fformat': catversions[0], 'fversion': catversions[1], 'fformatspecs': formatspecs, 'fchecksumtype': checksumtype, 'fheaderchecksum': catfileheadercshex, 'ffilelist': {}};
 for member in sorted(tarfp.getmembers(), key=lambda x: x.name):
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
  elif(member.isdev()):
   ffullmode = member.mode;
   ftype = 7;
  elif(member.islnk()):
   ffullmode = member.mode + stat.S_IFREG;
   ftype = 1;
  elif(member.issym()):
   ffullmode = member.mode + stat.S_IFLNK;
   ftype = 2;
  elif(member.ischr()):
   ffullmode = member.mode + stat.S_IFCHR;
   ftype = 3;
  elif(member.isblk()):
   ffullmode = member.mode + stat.S_IFBLK;
   ftype = 4;
  elif(member.isdir()):
   ffullmode = member.mode + stat.S_IFDIR;
   ftype = 5;
  elif(member.isfifo()):
   ffullmode = member.mode + stat.S_IFIFO;
   ftype = 6;
  elif(member.issparse()):
   ffullmode = member.mode;
   ftype = 12;
  else:
   ffullmode = member.mode;
   ftype = 0;
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
  elif(ftype==0 or ftype==7):
   fsize = member.size;
  else:
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
  fwinattributes = int(0);
  fcontents = "".encode('UTF-8');
  chunk_size = 1024;
  if(ftype==0 or ftype==7):
   with tarfp.extractfile(member) as fpc:
    while(True):
     chunk = fpc.read(chunk_size);
     if(not chunk):
      break
     fcontents += chunk;
  ftypehex = format(ftype, 'x').lower();
  extrafields = len(extradata);
  extrafieldslist = extradata;
  catfextrafields = extrafields;
  extrasizestr = AppendNullByte(extrafields, formatspecs[5]);
  if(len(extradata)>0):
   extrasizestr = extrasizestr + AppendNullBytes(extradata, formatspecs[5]);
  extrasizelen = len(extrasizestr);
  extrasizelenhex = format(extrasizelen, 'x').lower();
  catoutlist = [ftypehex, fname, flinkname, format(int(fsize), 'x').lower(), format(int(fatime), 'x').lower(), format(int(fmtime), 'x').lower(), format(int(fctime), 'x').lower(), format(int(fbtime), 'x').lower(), format(int(fmode), 'x').lower(), format(int(fwinattributes), 'x').lower(), format(int(fuid), 'x').lower(), funame, format(int(fgid), 'x').lower(), fgname, format(int(fcurfid), 'x').lower(), format(int(fcurinode), 'x').lower(), format(int(flinkcount), 'x').lower(), format(int(fdev_minor), 'x').lower(), format(int(fdev_major), 'x').lower(), format(int(frdev_minor), 'x').lower(), format(int(frdev_major), 'x').lower(), extrasizelenhex, format(catfextrafields, 'x').lower()];
  catoutlen = len(catoutlist) + len(extradata) + 3;
  catoutlenhex = format(catoutlen, 'x').lower();
  catoutlist.insert(0, catoutlenhex);
  catfileoutstr = AppendNullBytes(catoutlist, formatspecs[5]);
  if(len(extradata)>0):
   catfileoutstr = catfileoutstr + AppendNullBytes(extradata, formatspecs[5]);
  catfileoutstr = catfileoutstr + AppendNullByte(checksumtype, formatspecs[5]);
  catfnumfields = catoutlen;
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
  else:
   catfileheadercshex = format(0, 'x').lower();
   catfilecontentcshex = format(0, 'x').lower();
  catfhstart = fheadtell;
  fheadtell += len(catfileoutstr);
  catfhend = fheadtell - 1;
  catfcontentstart = fheadtell;
  tmpfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex], formatspecs[5]);
  catheaersize = format(int(len(tmpfileoutstr) - 1), 'x').lower()
  catfileoutstr = AppendNullByte(catheaersize, formatspecs[5]) + catfileoutstr;
  catheaderdata = [catheaersize] + catoutlist + extradata + [checksumtype, catfileheadercshex, catfilecontentcshex]
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
  else:
   catfileheadercshex = format(0, 'x').lower();
  catfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex], formatspecs[5]);
  catfileoutstrecd = catfileoutstr.encode('UTF-8');
  nullstrecd = formatspecs[5].encode('UTF-8');
  fheadtell += len(catfileoutstr) + 1;
  catfcontentend = fheadtell - 1;
  catfileout = catfileoutstrecd + fcontents + nullstrecd;
  pyhascontents = False;
  if(int(fsize)>0 and not listonly):
   pyhascontents = True;
  if(int(fsize)>0 and listonly):
   fcontents = "";
   pyhascontents = False;
  catlist['ffilelist'].update({fileidnum: {'fid': fileidnum, 'fidalt': fileidnum, 'fheadersize': int(catheaersize, 16), 'fhstart': catfhstart, 'fhend': catfhend, 'ftype': ftype, 'fname': fname, 'fbasedir': fbasedir, 'flinkname': flinkname, 'fsize': fsize, 'fatime': fatime, 'fmtime': fmtime, 'fctime': fctime, 'fbtime': fbtime, 'fmode': fmode, 'fchmode': fchmode, 'ftypemod': ftypemod, 'fwinattributes': fwinattributes, 'fuid': fuid, 'funame': funame, 'fgid': fgid, 'fgname': fgname, 'finode': finode, 'flinkcount': flinkcount, 'fminor': fdev_minor, 'fmajor': fdev_major, 'frminor': frdev_minor, 'frmajor': frdev_major, 'fchecksumtype': checksumtype, 'fnumfields': catfnumfields + 2, 'frawheader': catheaderdata, 'fextrafields': catfextrafields, 'fextrafieldsize': extrasizelen, 'fextralist': extrafieldslist, 'fheaderchecksum': int(catfileheadercshex, 16), 'fcontentchecksum': int(catfilecontentcshex, 16), 'fhascontents': pyhascontents, 'fcontentstart': catfcontentstart, 'fcontentend': catfcontentend, 'fcontents': fcontents} });
  fileidnum = fileidnum + 1;
 return catlist;

def ZipFileToArrayAlt(infiles, listonly=False, checksumtype="crc32", extradata=[], formatspecs=__file_format_list__, verbose=False):
 advancedlist = True;
 curinode = 0;
 curfid = 0;
 inodelist = [];
 inodetofile = {};
 filetoinode = {};
 inodetocatinode = {};
 fileidnum = 0;
 if(infile=="-"):
  infile = BytesIO();
  if(hasattr(sys.stdin, "buffer")):
   shutil.copyfileobj(sys.stdin.buffer, infile);
  else:
   shutil.copyfileobj(sys.stdin, infile);
  infile.seek(0, 0);
  if(not infile):
   return False;
  infile.seek(0, 0);
 elif(re.findall(r"^(http|https|ftp|ftps|sftp)\:\/\/", str(infile))):
  infile = download_file_from_internet_file(infile);
  infile.seek(0, 0);
  if(not infile):
   return False;
  infile.seek(0, 0);
 elif(not os.path.exists(infile) or not os.path.isfile(infile)):
  return False;
 else:
  return False;
 if(not zipfile.is_zipfile(infile)):
  return False;
 try:
  zipfp = zipfile.ZipFile(infile, "r", allowZip64=True);
 except FileNotFoundError:
  return False;
 ziptest = zipfp.testzip();
 if(ziptest):
  VerbosePrintOut("Bad file found!");
 fnumfiles = int(len(zipfp.infolist()));
 catver = formatspecs[6];
 fileheaderver = str(int(catver.replace(".", "")));
 fileheader = AppendNullByte(formatspecs[1] + fileheaderver, formatspecs[5]);
 catversion = re.findall(r"([\d]+)$", fileheader);
 catversions = re.search(r'(.*?)(\d+)$', catstring).groups();
 fnumfileshex = format(int(fnumfiles), 'x').lower();
 fileheader = fileheader + AppendNullBytes([fnumfileshex, checksumtype], formatspecs[5]);
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
 else:
  catfileheadercshex = format(0, 'x').lower();
 fileheader = fileheader + AppendNullByte(catfileheadercshex, formatspecs[5]);
 fheadtell = len(fileheader);
 catlist = {'fnumfiles': fnumfiles, 'fformat': catversions[0], 'fversion': catversions[1], 'fformatspecs': formatspecs, 'fchecksumtype': checksumtype, 'fheaderchecksum': catfileheadercshex, 'ffilelist': {}};
 for member in sorted(zipfp.infolist(), key=lambda x: x.filename):
  if(re.findall("^[.|/]", member.filename)):
   fname = member.filename;
  else:
   fname = "./"+member.filename;
  zipinfo = zipfp.getinfo(member.filename);
  if(verbose):
   VerbosePrintOut(fname);
  if(not member.is_dir()):
   fpremode = stat.S_IFREG + 438;
  elif(member.is_dir()):
   fpremode = stat.S_IFDIR + 511;
  flinkcount = 0;
  ftype = 0;
  if(not member.is_dir()):
   ftype = 0;
  elif(member.is_dir()):
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
  elif(ftype==0):
   fsize = member.file_size;
  else:
   fsize = member.file_size;
  fatime = time.mktime(member.date_time + (0, 0, -1));
  fmtime = time.mktime(member.date_time + (0, 0, -1));
  fctime = time.mktime(member.date_time + (0, 0, -1));
  fbtime = time.mktime(member.date_time + (0, 0, -1));
  if(zipinfo.create_system==0 or zipinfo.create_system==10):
   fwinattributes = format(int(zipinfo.external_attr), 'x').lower();
   if(not member.is_dir()):
    fmode = format(int(stat.S_IFREG + 438), 'x').lower();
    fchmode = format(int(stat.S_IMODE(int(stat.S_IFREG + 438))), 'x').lower();
    ftypemod = format(int(stat.S_IFMT(int(stat.S_IFREG + 438))), 'x').lower();
   elif(member.is_dir()):
    fmode = format(int(stat.S_IFDIR + 511), 'x').lower();
    fchmode = format(int(stat.S_IMODE(int(stat.S_IFDIR + 511))), 'x').lower();
    ftypemod = format(int(stat.S_IFMT(int(stat.S_IFDIR + 511))), 'x').lower();
  elif(zipinfo.create_system==3):
   fwinattributes = format(int(0), 'x').lower();
   fmode = format(int(zipinfo.external_attr), 'x').lower();
  else:
   fwinattributes = format(int(0), 'x').lower();
   if(not member.is_dir()):
    fmode = format(int(stat.S_IFREG + 438), 'x').lower();
    fchmode = format(int(stat.S_IMODE(int(stat.S_IFREG + 438))), 'x').lower();
    ftypemod = format(int(stat.S_IFMT(int(stat.S_IFREG + 438))), 'x').lower();
   elif(member.is_dir()):
    fmode = format(int(stat.S_IFDIR + 511), 'x').lower();
    fchmode = format(int(stat.S_IMODE(int(stat.S_IFDIR + 511))), 'x').lower();
    ftypemod = format(int(stat.S_IFMT(int(stat.S_IFDIR + 511))), 'x').lower();
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
  extrasizestr = AppendNullByte(extrafields, formatspecs[5]);
  if(len(extradata)>0):
   extrasizestr = extrasizestr + AppendNullBytes(extradata, formatspecs[5]);
  extrasizelen = len(extrasizestr);
  extrasizelenhex = format(extrasizelen, 'x').lower();
  catoutlist = [ftypehex, fname, flinkname, format(int(fsize), 'x').lower(), format(int(fatime), 'x').lower(), format(int(fmtime), 'x').lower(), format(int(fctime), 'x').lower(), format(int(fbtime), 'x').lower(), format(int(fmode), 'x').lower(), format(int(fwinattributes), 'x').lower(), format(int(fuid), 'x').lower(), funame, format(int(fgid), 'x').lower(), fgname, format(int(fcurfid), 'x').lower(), format(int(fcurinode), 'x').lower(), format(int(flinkcount), 'x').lower(), format(int(fdev_minor), 'x').lower(), format(int(fdev_major), 'x').lower(), format(int(frdev_minor), 'x').lower(), format(int(frdev_major), 'x').lower(), extrasizelenhex, format(catfextrafields, 'x').lower()];
  catoutlen = len(catoutlist) + len(extradata) + 3;
  catoutlenhex = format(catoutlen, 'x').lower();
  catoutlist.insert(0, catoutlenhex);
  catfileoutstr = AppendNullBytes(catoutlist, formatspecs[5]);
  if(len(extradata)>0):
   catfileoutstr = catfileoutstr + AppendNullBytes(extradata, formatspecs[5]);
  catfileoutstr = catfileoutstr + AppendNullByte(checksumtype, formatspecs[5]);
  catfnumfields = catoutlen;
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
  else:
   catfileheadercshex = format(0, 'x').lower();
   catfilecontentcshex = format(0, 'x').lower();
  catfhstart = fheadtell;
  fheadtell += len(catfileoutstr);
  catfhend = fheadtell - 1;
  catfcontentstart = fheadtell;
  tmpfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex], formatspecs[5]);
  catheaersize = format(int(len(tmpfileoutstr) - 1), 'x').lower()
  catfileoutstr = AppendNullByte(catheaersize, formatspecs[5]) + catfileoutstr;
  catheaderdata = [catheaersize] + catoutlist + extradata + [checksumtype, catfileheadercshex, catfilecontentcshex];
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
  else:
   catfileheadercshex = format(0, 'x').lower();
  catfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex], formatspecs[5]);
  catfileoutstrecd = catfileoutstr.encode('UTF-8');
  nullstrecd = formatspecs[5].encode('UTF-8');
  fheadtell += len(catfileoutstr) + 1;
  catfcontentend = fheadtell - 1;
  catfileout = catfileoutstrecd + fcontents + nullstrecd;
  pyhascontents = False;
  if(int(fsize)>0 and not listonly):
   pyhascontents = True;
  if(int(fsize)>0 and listonly):
   fcontents = "";
   pyhascontents = False;
  catlist['ffilelist'].update({fileidnum: {'fid': fileidnum, 'fidalt': fileidnum, 'fheadersize': int(catheaersize, 16), 'fhstart': catfhstart, 'fhend': catfhend, 'ftype': ftype, 'fname': fname, 'fbasedir': fbasedir, 'flinkname': flinkname, 'fsize': fsize, 'fatime': fatime, 'fmtime': fmtime, 'fctime': fctime, 'fbtime': fbtime, 'fmode': fmode, 'fchmode': fchmode, 'ftypemod': ftypemod, 'fwinattributes': fwinattributes, 'fuid': fuid, 'funame': funame, 'fgid': fgid, 'fgname': fgname, 'finode': finode, 'flinkcount': flinkcount, 'fminor': fdev_minor, 'fmajor': fdev_major, 'frminor': frdev_minor, 'frmajor': frdev_major, 'fchecksumtype': checksumtype, 'fnumfields': catfnumfields + 2, 'frawheader': catheaderdata, 'fextrafields': catfextrafields, 'fextrafieldsize': extrasizelen, 'fextralist': extrafieldslist, 'fheaderchecksum': int(catfileheadercshex, 16), 'fcontentchecksum': int(catfilecontentcshex, 16), 'fhascontents': pyhascontents, 'fcontentstart': catfcontentstart, 'fcontentend': catfcontentend, 'fcontents': fcontents} });
  fileidnum = fileidnum + 1;
 return catlist;

if(not rarfile_support):
 def RarFileToArrayAlt(infiles, listonly=False, checksumtype="crc32", extradata=[], formatspecs=__file_format_list__, verbose=False):
  return False;

if(rarfile_support):
 def RarFileToArrayAlt(infiles, listonly=False, checksumtype="crc32", extradata=[], formatspecs=__file_format_list__, verbose=False):
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
  if(not rarfile.is_rarfile(infile) and not rarfile.is_rarfile_sfx(infile)):
   return False;
  rarfp = rarfile.RarFile(infile, "r");
  rartest = rarfp.testrar();
  if(rartest):
   VerbosePrintOut("Bad file found!");
  fnumfiles = int(len(rarfp.infolist()));
  catver = formatspecs[6];
  fileheaderver = str(int(catver.replace(".", "")));
  fileheader = AppendNullByte(formatspecs[1] + fileheaderver, formatspecs[5]);
  catversion = re.findall(r"([\d]+)$", fileheader);
  catversions = re.search(r'(.*?)(\d+)$', catstring).groups();
  fnumfileshex = format(int(fnumfiles), 'x').lower();
  fileheader = fileheader + AppendNullBytes([fnumfileshex, checksumtype], formatspecs[5]);
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
  else:
   catfileheadercshex = format(0, 'x').lower();
  fileheader = fileheader + AppendNullByte(catfileheadercshex, formatspecs[5]);
  fheadtell = len(fileheader);
  catlist = {'fnumfiles': fnumfiles, 'fformat': catversions[0], 'fversion': catversions[1], 'fformatspecs': formatspecs, 'fchecksumtype': checksumtype, 'fheaderchecksum': catfileheadercshex, 'ffilelist': {}};
  for member in sorted(rarfp.infolist(), key=lambda x: x.filename):
   is_unix = False;
   is_windows = False;
   if(member.host_os==rarfile.RAR_OS_UNIX):
    is_windows = False;
    try:
     member.external_attr
     is_unix = True;
    except AttributeError:
     is_unix = False;
   elif(member.host_os==rarfile.RAR_OS_WIN32):
    is_unix = False;
    try:
     member.external_attr
     is_windows = True;
    except AttributeError:
     is_windows = False;
   else:
    is_unix = False;
    is_windows = False;
   if(re.findall("^[.|/]", member.filename)):
    fname = member.filename;
   else:
    fname = "./"+member.filename;
   rarinfo = rarfp.getinfo(member.filename);
   if(verbose):
    VerbosePrintOut(fname);
   if(is_unix and member.external_attr !=0):
    fpremode = int(member.external_attr);
   elif(member.is_file()):
    fpremode = stat.S_IFREG + 438;
   elif(member.is_symlink()):
    fpremode = stat.S_IFLNK + 438;
   elif(member.is_dir()):
    fpremode = stat.S_IFDIR + 511;
   if(is_windows and member.external_attr !=0):
    fwinattributes = int(member.external_attr);
   else:
    fwinattributes = int(0);
   flinkcount = 0;
   ftype = 0;
   if(member.is_file()):
    ftype = 0;
   elif(member.is_symlink()):
    ftype = 2;
   elif(member.is_dir()):
    ftype = 5;
   flinkname = "";
   if(ftype==2):
    flinkname = rarfp.read(member.filename).decode("UTF-8");
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
   try:
    if(member.atime):
     fatime = int(member.atime.timestamp());
    else:
     fatime = int(member.mtime.timestamp());
   except AttributeError:
    fatime = int(member.mtime.timestamp());
   fmtime = int(member.mtime.timestamp());
   try:
    if(member.ctime):
     fctime = int(member.ctime.timestamp());
    else:
     fctime = int(member.mtime.timestamp());
   except AttributeError:
    fctime = int(member.mtime.timestamp());
   fbtime = int(member.mtime.timestamp());
   if(is_unix and member.external_attr !=0):
    fmode = format(int(member.external_attr), 'x').lower();
    fchmode = format(int(stat.S_IMODE(member.external_attr)), 'x').lower();
    ftypemod = format(int(stat.S_IFMT(member.external_attr)), 'x').lower();
   elif(member.is_file()):
    fmode = int(stat.S_IFREG + 438)
    fchmode = int(stat.S_IMODE(stat.S_IFREG + 438));
    ftypemod = int(stat.S_IFMT(stat.S_IFREG + 438));
   elif(member.is_symlink()):
    fmode = int(stat.S_IFLNK + 438)
    fchmode = int(stat.S_IMODE(stat.S_IFREG + 438));
    ftypemod = int(stat.S_IFMT(stat.S_IFREG + 438));
   elif(member.is_dir()):
    fmode = int(stat.S_IFDIR + 511)
    fchmode = int(stat.S_IMODE(stat.S_IFDIR + 511));
    ftypemod = int(stat.S_IFMT(stat.S_IFDIR + 511));
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
    fcontents = rarfp.read(member.filename);
   ftypehex = format(ftype, 'x').lower();
   extrafields = len(extradata);
   extrafieldslist = extradata;
   catfextrafields = extrafields;
   extrasizestr = AppendNullByte(extrafields, formatspecs[5]);
   if(len(extradata)>0):
    extrasizestr = extrasizestr + AppendNullBytes(extradata, formatspecs[5]);
   extrasizelen = len(extrasizestr);
   extrasizelenhex = format(extrasizelen, 'x').lower();
   catoutlist = [ftypehex, fname, flinkname, format(int(fsize), 'x').lower(), format(int(fatime), 'x').lower(), format(int(fmtime), 'x').lower(), format(int(fctime), 'x').lower(), format(int(fbtime), 'x').lower(), format(int(fmode), 'x').lower(), format(int(fwinattributes), 'x').lower(), format(int(fuid), 'x').lower(), funame, format(int(fgid), 'x').lower(), fgname, format(int(fcurfid), 'x').lower(), format(int(fcurinode), 'x').lower(), format(int(flinkcount), 'x').lower(), format(int(fdev_minor), 'x').lower(), format(int(fdev_major), 'x').lower(), format(int(frdev_minor), 'x').lower(), format(int(frdev_major), 'x').lower(), extrasizelenhex, format(catfextrafields, 'x').lower()];
   catoutlen = len(catoutlist) + len(extradata) + 3;
   catoutlenhex = format(catoutlen, 'x').lower();
   catoutlist.insert(0, catoutlenhex);
   catfileoutstr = AppendNullBytes(catoutlist, formatspecs[5]);
   if(len(extradata)>0):
    catfileoutstr = catfileoutstr + AppendNullBytes(extradata, formatspecs[5]);
   catfileoutstr = catfileoutstr + AppendNullByte(checksumtype, formatspecs[5]);
   catfnumfields = 24 + catfextrafields;
   if(checksumtype=="none" or checksumtype==""):
    catfileheadercshex = format(0, 'x').lower();
    catfilecontentcshex = format(0, 'x').lower();
   elif(checksumtype=="crc16" or checksumtype=="crc16_ansi" or checksumtype=="crc16_ibm"):
    catfileheadercshex = format(crc16(catfileoutstr.encode('UTF-8')) & 0xffff, '04x').lower();
    catfilecontentcshex = format(crc16(fcontents) & 0xffff, '04x').lower();
   elif(checksumtype=="crc16_ccitt"):
    catfileheadercshex = format(crc16_ccitt(catfileoutstr.encode('UTF-8')) & 0xffff, '04x').lower();
    catfilecontentcshex = format(crc16_ccitt(fcontents) & 0xffff, '04x').lower();
   elif(checksumtype=="adler32"):
    catfileheadercshex = format(zlib.adler32(catfileoutstr.encode('UTF-8')) & 0xffffffff, '08x').lower();
    catfilecontentcshex = format(zlib.adler32(fcontents) & 0xffffffff, '08x').lower();
   elif(checksumtype=="crc32"):
    catfileheadercshex = format(crc32(catfileoutstr.encode('UTF-8')) & 0xffffffff, '08x').lower();
    catfilecontentcshex = format(crc32(fcontents) & 0xffffffff, '08x').lower();
   elif(checksumtype=="crc64_ecma"):
    catfileheadercshex = format(crc64_ecma(catfileoutstr.encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
    catfilecontentcshex = format(crc64_ecma(fcontents) & 0xffffffffffffffff, '016x').lower();
   elif(checksumtype=="crc64" or checksumtype=="crc64_iso"):
    catfileheadercshex = format(crc64_iso(catfileoutstr.encode('UTF-8')) & 0xffffffffffffffff, '016x').lower();
    catfilecontentcshex = format(crc64_iso(fcontents) & 0xffffffffffffffff, '016x').lower();
   elif(CheckSumSupportAlt(checksumtype, hashlib_guaranteed)):
    checksumoutstr = hashlib.new(checksumtype);
    checksumoutstr.update(catfileoutstr.encode('UTF-8'));
    catfileheadercshex = checksumoutstr.hexdigest().lower();
   else:
    catfileheadercshex = format(0, 'x').lower();
    catfilecontentcshex = format(0, 'x').lower();
   catfhstart = fheadtell;
   fheadtell += len(catfileoutstr);
   catfhend = fheadtell - 1;
   catfcontentstart = fheadtell;
   tmpfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex], formatspecs[5]);
   catheaersize = format(int(len(tmpfileoutstr) - 1), 'x').lower()
   catfileoutstr = AppendNullByte(catheaersize, formatspecs[5]) + catfileoutstr;
   catheaderdata = [catheaersize] + catoutlist + extradata + [checksumtype, catfileheadercshex, catfilecontentcshex];
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
   else:
    catfileheadercshex = format(0, 'x').lower();
   catfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex], formatspecs[5]);
   catfileoutstrecd = catfileoutstr.encode('UTF-8');
   nullstrecd = formatspecs[5].encode('UTF-8');
   fheadtell += len(catfileoutstr) + 1;
   catfcontentend = fheadtell - 1;
   catfileout = catfileoutstrecd + fcontents + nullstrecd;
   pyhascontents = False;
   if(int(fsize)>0 and not listonly):
    pyhascontents = True;
   if(int(fsize)>0 and listonly):
    fcontents = "";
    pyhascontents = False;
   catlist['ffilelist'].update({fileidnum: {'fid': fileidnum, 'fidalt': fileidnum, 'fheadersize': int(catheaersize, 16), 'fhstart': catfhstart, 'fhend': catfhend, 'ftype': ftype, 'fname': fname, 'fbasedir': fbasedir, 'flinkname': flinkname, 'fsize': fsize, 'fatime': fatime, 'fmtime': fmtime, 'fctime': fctime, 'fbtime': fbtime, 'fmode': fmode, 'fchmode': fchmode, 'ftypemod': ftypemod, 'fwinattributes': fwinattributes, 'fuid': fuid, 'funame': funame, 'fgid': fgid, 'fgname': fgname, 'finode': finode, 'flinkcount': flinkcount, 'fminor': fdev_minor, 'fmajor': fdev_major, 'frminor': frdev_minor, 'frmajor': frdev_major, 'fchecksumtype': checksumtype, 'fnumfields': catfnumfields + 2, 'frawheader': catheaderdata, 'fextrafields': catfextrafields, 'fextrafieldsize': extrasizelen, 'fextralist': extrafieldslist, 'fheaderchecksum': int(catfileheadercshex, 16), 'fcontentchecksum': int(catfilecontentcshex, 16), 'fhascontents': pyhascontents, 'fcontentstart': catfcontentstart, 'fcontentend': catfcontentend, 'fcontents': fcontents} });
   fileidnum = fileidnum + 1;
  return catlist;

def ListDirToArray(infiles, dirlistfromtxt=False, compression="auto", compressionlevel=None, followlink=False, seekstart=0, seekend=0, listonly=False, skipchecksum=False, checksumtype="crc32", extradata=[], formatspecs=__file_format_list__, verbose=False, returnfp=False):
 outarray = BytesIO();
 packcat = PackArchiveFile(infiles, outarray, dirlistfromtxt, compression, compressionlevel, followlink, checksumtype, extradata, formatspecs, verbose, True);
 listcatfiles = ArchiveFileToArray(outarray, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp);
 return listcatfiles;

def ArchiveFileToArrayIndex(infile, seekstart=0, seekend=0, listonly=False, skipchecksum=False, formatspecs=__file_format_list__, returnfp=False):
 if(isinstance(infile, dict)):
  listcatfiles = infile;
 else:
  if(infile!="-" and not hasattr(infile, "read") and not hasattr(infile, "write")):
   infile = RemoveWindowsPath(infile);
  listcatfiles = ArchiveFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp);
 if(not listcatfiles):
  return False;
 catarray = {'list': listcatfiles, 'filetoid': {}, 'idtofile': {}, 'filetypes': {'directories': {'filetoid': {}, 'idtofile': {}}, 'files': {'filetoid': {}, 'idtofile': {}}, 'links': {'filetoid': {}, 'idtofile': {}}, 'symlinks': {'filetoid': {}, 'idtofile': {}}, 'hardlinks': {'filetoid': {}, 'idtofile': {}}, 'character': {'filetoid': {}, 'idtofile': {}}, 'block': {'filetoid': {}, 'idtofile': {}}, 'fifo': {'filetoid': {}, 'idtofile': {}}, 'devices': {'filetoid': {}, 'idtofile': {}}}};
 if(returnfp):
  catarray.update({'catfp': listcatfiles['catfp']});
 lenlist = len(listcatfiles['ffilelist']);
 lcfi = 0;
 lcfx = int(listcatfiles['fnumfiles']);
 if(lenlist>listcatfiles['fnumfiles'] or lenlist<listcatfiles['fnumfiles']):
  lcfx = int(lenlist);
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

create_alias_function("", __file_format_name__, "ToArrayIndex", ArchiveFileToArrayIndex);

def ListDirToArrayIndexAlt(infiles, dirlistfromtxt=False, followlink=False, seekstart=0, seekend=0, listonly=False, checksumtype="crc32", extradata=[], formatspecs=__file_format_list__, verbose=False):
 listcatfiles = ListDirToArrayAlt(infiles, dirlistfromtxt, followlink, listonly, checksumtype, extradata, formatspecs, verbose);
 if(not listcatfiles):
  return False;
 catarray = {'list': listcatfiles, 'filetoid': {}, 'idtofile': {}, 'filetypes': {'directories': {'filetoid': {}, 'idtofile': {}}, 'files': {'filetoid': {}, 'idtofile': {}}, 'links': {'filetoid': {}, 'idtofile': {}}, 'symlinks': {'filetoid': {}, 'idtofile': {}}, 'hardlinks': {'filetoid': {}, 'idtofile': {}}, 'character': {'filetoid': {}, 'idtofile': {}}, 'block': {'filetoid': {}, 'idtofile': {}}, 'fifo': {'filetoid': {}, 'idtofile': {}}, 'devices': {'filetoid': {}, 'idtofile': {}}}};
 lenlist = len(listcatfiles['ffilelist']);
 lcfi = 0;
 lcfx = int(listcatfiles['fnumfiles']);
 if(lenlist>listcatfiles['fnumfiles'] or lenlist<listcatfiles['fnumfiles']):
  lcfx = int(lenlist);
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

def TarFileToArrayIndexAlt(infiles, seekstart=0, seekend=0, listonly=False, checksumtype="crc32", extradata=[], formatspecs=__file_format_list__, verbose=False):
 listcatfiles = TarFileToArrayAlt(infiles, listonly, checksumtype, extradata, formatspecs, verbose);
 if(not listcatfiles):
  return False;
 catarray = {'list': listcatfiles, 'filetoid': {}, 'idtofile': {}, 'filetypes': {'directories': {'filetoid': {}, 'idtofile': {}}, 'files': {'filetoid': {}, 'idtofile': {}}, 'links': {'filetoid': {}, 'idtofile': {}}, 'symlinks': {'filetoid': {}, 'idtofile': {}}, 'hardlinks': {'filetoid': {}, 'idtofile': {}}, 'character': {'filetoid': {}, 'idtofile': {}}, 'block': {'filetoid': {}, 'idtofile': {}}, 'fifo': {'filetoid': {}, 'idtofile': {}}, 'devices': {'filetoid': {}, 'idtofile': {}}}};
 lenlist = len(listcatfiles['ffilelist']);
 lcfi = 0;
 lcfx = int(listcatfiles['fnumfiles']);
 if(lenlist>listcatfiles['fnumfiles'] or lenlist<listcatfiles['fnumfiles']):
  lcfx = int(lenlist);
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

def ZipFileToArrayIndexAlt(infiles, seekstart=0, seekend=0, listonly=False, checksumtype="crc32", extradata=[], formatspecs=__file_format_list__, verbose=False):
 listcatfiles = ZipFileToArrayAlt(infiles, listonly, checksumtype, extradata, formatspecs, verbose);
 if(not listcatfiles):
  return False;
 catarray = {'list': listcatfiles, 'filetoid': {}, 'idtofile': {}, 'filetypes': {'directories': {'filetoid': {}, 'idtofile': {}}, 'files': {'filetoid': {}, 'idtofile': {}}, 'links': {'filetoid': {}, 'idtofile': {}}, 'symlinks': {'filetoid': {}, 'idtofile': {}}, 'hardlinks': {'filetoid': {}, 'idtofile': {}}, 'character': {'filetoid': {}, 'idtofile': {}}, 'block': {'filetoid': {}, 'idtofile': {}}, 'fifo': {'filetoid': {}, 'idtofile': {}}, 'devices': {'filetoid': {}, 'idtofile': {}}}};
 lenlist = len(listcatfiles['ffilelist']);
 lcfi = 0;
 lcfx = int(listcatfiles['fnumfiles']);
 if(lenlist>listcatfiles['fnumfiles'] or lenlist<listcatfiles['fnumfiles']):
  lcfx = int(lenlist);
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

if(not rarfile_support):
 def RarFileToArrayIndexAlt(infiles, seekstart=0, seekend=0, listonly=False, checksumtype="crc32", extradata=[], formatspecs=__file_format_list__, verbose=False):
  return False;

if(rarfile_support):
 def RarFileToArrayIndexAlt(infiles, seekstart=0, seekend=0, listonly=False, checksumtype="crc32", extradata=[], formatspecs=__file_format_list__, verbose=False):
  listcatfiles = RarFileToArrayAlt(infiles, listonly, checksumtype, extradata, formatspecs, verbose);
  if(not listcatfiles):
   return False;
  catarray = {'list': listcatfiles, 'filetoid': {}, 'idtofile': {}, 'filetypes': {'directories': {'filetoid': {}, 'idtofile': {}}, 'files': {'filetoid': {}, 'idtofile': {}}, 'links': {'filetoid': {}, 'idtofile': {}}, 'symlinks': {'filetoid': {}, 'idtofile': {}}, 'hardlinks': {'filetoid': {}, 'idtofile': {}}, 'character': {'filetoid': {}, 'idtofile': {}}, 'block': {'filetoid': {}, 'idtofile': {}}, 'fifo': {'filetoid': {}, 'idtofile': {}}, 'devices': {'filetoid': {}, 'idtofile': {}}}};
  lenlist = len(listcatfiles['ffilelist']);
  lcfi = 0;
  lcfx = int(listcatfiles['fnumfiles']);
  if(lenlist>listcatfiles['fnumfiles'] or lenlist<listcatfiles['fnumfiles']):
   lcfx = int(lenlist);
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

def ArchiveFileStringToArrayIndex(catstr, seekstart=0, seekend=0, listonly=False, skipchecksum=False, formatspecs=__file_format_list__, returnfp=False):
 catfp = BytesIO(catstr);
 listcatfiles = ArchiveFileToArrayIndex(catfp, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp);
 return listcatfiles;

create_alias_function("", __file_format_name__, "StringToArrayIndex", ArchiveFileStringToArrayIndex);

def TarFileToArrayIndex(infile, seekstart=0, seekend=0, listonly=False, skipchecksum=False, formatspecs=__file_format_list__, returnfp=False):
 catfp = BytesIO();
 catfp = PackArchiveFileFromTarFile(infile, catfp, "auto", None, "crc32", [], formatspecs, False, True);
 listcatfiles = ArchiveFileToArrayIndex(catfp, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp);
 return listcatfiles;

def ZipFileToArrayIndex(infile, seekstart=0, seekend=0, listonly=False, skipchecksum=False, formatspecs=__file_format_list__, returnfp=False):
 catfp = BytesIO();
 catfp = PackArchiveFileFromZipFile(infile, catfp, "auto", None, "crc32", [], formatspecs, False, True);
 listcatfiles = ArchiveFileToArrayIndex(catfp, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp);
 return listcatfiles;

if(not rarfile_support):
 def RarFileToArrayIndex(infile, seekstart=0, seekend=0, listonly=False, skipchecksum=False, formatspecs=__file_format_list__, returnfp=False):
  return False;

if(rarfile_support):
 def RarFileToArrayIndex(infile, seekstart=0, seekend=0, listonly=False, skipchecksum=False, formatspecs=__file_format_list__, returnfp=False):
  catfp = BytesIO();
  catfp = PackArchiveFileFromRarFile(infile, catfp, "auto", None, "crc32", [], formatspecs, False, True);
  listcatfiles = ArchiveFileToArrayIndex(catfp, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp);
  return listcatfiles;

def ListDirToArrayIndex(infiles, dirlistfromtxt=False, compression="auto", compressionlevel=None, followlink=False, seekstart=0, seekend=0, listonly=False, skipchecksum=False, checksumtype="crc32", formatspecs=__file_format_list__, verbose=False, returnfp=False):
 outarray = BytesIO();
 packcat = PackArchiveFile(infiles, outarray, dirlistfromtxt, compression, compressionlevel, followlink, checksumtype, formatspecs, verbose, True);
 listcatfiles = ArchiveFileToArrayIndex(outarray, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp)
 return listcatfiles;

def RePackArchiveFile(infile, outfile, compression="auto", compressionlevel=None, followlink=False, seekstart=0, seekend=0, checksumtype="crc32", skipchecksum=False, extradata=[], formatspecs=__file_format_list__, verbose=False, returnfp=False):
 if(isinstance(infile, dict)):
  prelistcatfiles = ArchiveFileToArrayIndex(infile, seekstart, seekend, False, skipchecksum, formatspecs, returnfp);
  listcatfiles = prelistcatfiles['list'];
 else:
  if(infile!="-" and not hasattr(infile, "read") and not hasattr(infile, "write")):
   infile = RemoveWindowsPath(infile);
  if(followlink):
   prelistcatfiles = ArchiveFileToArrayIndex(infile, seekstart, seekend, False, skipchecksum, formatspecs, returnfp);
   listcatfiles = prelistcatfiles['list'];
  else:
   listcatfiles = ArchiveFileToArray(infile, seekstart, seekend, False, skipchecksum, formatspecs, returnfp);
 if(outfile!="-" and not hasattr(infile, "read") and not hasattr(outfile, "write")):
  outfile = RemoveWindowsPath(outfile);
 checksumtype = checksumtype.lower();
 if(not CheckSumSupport(checksumtype, hashlib_guaranteed)):
  checksumtype="crc32";
 if(checksumtype=="none"):
  checksumtype = "";
 if(not compression or compression or compression=="catfile" or compression==formatspecs[2]):
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
 elif(re.findall(r"^(ftp|ftps|sftp)\:\/\/", str(outfile))):
  catfp = BytesIO();
 else:
  fbasename = os.path.splitext(outfile)[0];
  fextname = os.path.splitext(outfile)[1];
  catfp = CompressOpenFile(outfile, compressionlevel);
 catver = formatspecs[6];
 fileheaderver = str(int(catver.replace(".", "")));
 fileheader = AppendNullByte(formatspecs[1] + fileheaderver, formatspecs[5]);
 catfp.write(fileheader.encode('UTF-8'));
 lenlist = len(listcatfiles['ffilelist']);
 fnumfiles = int(listcatfiles['fnumfiles']);
 if(lenlist>fnumfiles or lenlist<fnumfiles):
  fnumfiles = lenlist;
 fnumfileshex = format(int(fnumfiles), 'x').lower();
 fnumfilesa = AppendNullBytes([fnumfileshex, checksumtype], formatspecs[5]);
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
 else:
  catfileheadercshex = format(0, 'x').lower();
 fnumfilesa = fnumfilesa + AppendNullByte(catfileheadercshex, formatspecs[5]);
 catfp.write(fnumfilesa.encode('UTF-8'));
 try:
  catfp.flush();
  os.fsync(catfp.fileno());
 except io.UnsupportedOperation:
  pass;
 except AttributeError:
  pass;
 lenlist = len(listcatfiles['ffilelist']);
 fnumfiles = int(listcatfiles['fnumfiles']);
 lcfi = 0;
 lcfx = int(listcatfiles['fnumfiles']);
 if(lenlist>listcatfiles['fnumfiles'] or lenlist<listcatfiles['fnumfiles']):
  lcfx = int(lenlist);
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
  fwinattributes = flinkinfo['ffilelist'][reallcfi]['fwinattributes'];
  fdev_minor = format(int(listcatfiles['ffilelist'][reallcfi]['fminor']), 'x').lower();
  fdev_major = format(int(listcatfiles['ffilelist'][reallcfi]['fmajor']), 'x').lower();
  frdev_minor = format(int(listcatfiles['ffilelist'][reallcfi]['frminor']), 'x').lower();
  frdev_major = format(int(listcatfiles['ffilelist'][reallcfi]['frmajor']), 'x').lower();
  if(len(listcatfiles['ffilelist'][reallcfi]['fextralist'])>listcatfiles['ffilelist'][reallcfi]['fextrafields'] and len(listcatfiles['ffilelist'][reallcfi]['fextralist'])>0):
   listcatfiles['ffilelist'][reallcfi]['fextrafields'] = len(listcatfiles['ffilelist'][reallcfi]['fextralist']);
  if(len(extradata)>0):
   listcatfiles['ffilelist'][reallcfi]['fextrafields'] = len(extradata);
   listcatfiles['ffilelist'][reallcfi]['fextralist'] = extradata;
  extrafields = format(int(listcatfiles['ffilelist'][reallcfi]['fextrafields']), 'x').lower();
  extrasizestr = AppendNullByte(extrafields, formatspecs[5]);
  if(len(extradata)>0):
   extrasizestr = extrasizestr + AppendNullBytes(extradata, formatspecs[5]);
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
    fwinattributes = flinkinfo['fwinattributes'];
    fdev_minor = format(int(flinkinfo['fminor']), 'x').lower();
    fdev_major = format(int(flinkinfo['fmajor']), 'x').lower();
    frdev_minor = format(int(flinkinfo['frminor']), 'x').lower();
    frdev_major = format(int(flinkinfo['frmajor']), 'x').lower();
    if(len(flinkinfo['fextralist'])>flinkinfo['fextrafields'] and len(flinkinfo['fextralist'])>0):
     flinkinfo['fextrafields'] = len(flinkinfo['fextralist']);
    if(len(extradata)>0):
     flinkinfo['fextrafields'] = len(extradata);
     flinkinfo['fextralist'] = extradata;
    extrafields = format(int(flinkinfo['fextrafields']), 'x').lower();
    extrasizestr = AppendNullByte(extrafields, formatspecs[5]);
    if(len(extradata)>0):
     extrasizestr = extrasizestr + AppendNullBytes(extradata, formatspecs[5]);
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
  catoutlist = [ftypehex, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev_minor, fdev_major, frdev_minor, frdev_major, extrasizelen, extrafields];
  catoutlen = len(catoutlist) + len(extradata) + 3;
  catoutlenhex = format(catoutlen, 'x').lower();
  catoutlist.insert(0, catoutlenhex);
  catfileoutstr = AppendNullBytes(catoutlist, formatspecs[5]);
  if(listcatfiles['ffilelist'][reallcfi]['fextrafields']>0):
   extrafieldslist = [];
   exi = 0;
   exil = listcatfiles['ffilelist'][reallcfi]['fextrafields'];
   while(exi<exil):
    extrafieldslist.append(listcatfiles['ffilelist'][reallcfi]['fextralist']);
    exi = exi + 1;
   catfileoutstr += AppendNullBytes([extrafieldslist], formatspecs[5]);
  catfileoutstr += AppendNullBytes([checksumtype], formatspecs[5]);
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
  else:
   catfileheadercshex = format(0, 'x').lower();
   catfilecontentcshex = format(0, 'x').lower();
  tmpfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex], formatspecs[5]);
  catheaersize = format(int(len(tmpfileoutstr) - 1), 'x').lower()
  catfileoutstr = AppendNullByte(catheaersize, formatspecs[5]) + catfileoutstr;
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
  else:
   catfileheadercshex = format(0, 'x').lower();
  catfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex], formatspecs[5]);
  catfileoutstrecd = catfileoutstr.encode('UTF-8');
  nullstrecd = formatspecs[5].encode('UTF-8');
  catfileout = catfileoutstrecd + fcontents + nullstrecd;
  catfcontentend = (catfp.tell() - 1) + len(catfileout);
  catfp.write(catfileout);
  try:
   catfp.flush();
   os.fsync(catfp.fileno());
  except io.UnsupportedOperation:
   pass;
  except AttributeError:
   pass;
  lcfi = lcfi + 1;
  reallcfi = reallcfi + 1;
 if(outfile=="-" or hasattr(outfile, "read") or hasattr(outfile, "write")):
  catfp = CompressArchiveFile(catfp, compression, formatspecs);
  try:
   catfp.flush();
   os.fsync(catfp.fileno());
  except io.UnsupportedOperation:
   pass;
  except AttributeError:
   pass;
 if(outfile=="-"):
  catfp.seek(0, 0);
  if(hasattr(sys.stdout, "buffer")):
   shutil.copyfileobj(catfp, sys.stdout.buffer);
  else:
   shutil.copyfileobj(catfp, sys.stdout);
 elif(re.findall(r"^(ftp|ftps|sftp)\:\/\/", str(outfile))):
  catfp = CompressArchiveFile(catfp, compression, formatspecs);
  catfp.seek(0, 0);
  upload_file_to_internet_file(catfp, outfile);
 if(returnfp):
  catfp.seek(0, 0);
  return catfp;
 else:
  catfp.close();
  return True;

create_alias_function("RePack", __file_format_name__, "", RePackArchiveFile);

def RePackArchiveFileFromString(catstr, outfile, compression="auto", compressionlevel=None, checksumtype="crc32", skipchecksum=False, extradata=[], formatspecs=__file_format_list__, verbose=False, returnfp=False):
 catfp = BytesIO(catstr);
 listcatfiles = RePackArchiveFile(catfp, compression, compressionlevel, checksumtype, skipchecksum, extradata, formatspecs, verbose, returnfp);
 return listcatfiles;

create_alias_function("RePack", __file_format_name__, "FromString", RePackArchiveFileFromString);

def PackArchiveFileFromListDir(infiles, outfile, dirlistfromtxt=False, compression="auto", compressionlevel=None, followlink=False, skipchecksum=False, checksumtype="crc32", extradata=[], formatspecs=__file_format_list__, verbose=False, returnfp=False):
 outarray = BytesIO();
 packcat = PackArchiveFile(infiles, outarray, dirlistfromtxt, compression, compressionlevel, followlink, checksumtype, extradata, formatspecs, verbose, True);
 listcatfiles = RePackArchiveFile(outarray, outfile, compression, compressionlevel, checksumtype, skipchecksum, extradata, formatspecs, verbose, returnfp);
 return listcatfiles;

create_alias_function("Pack", __file_format_name__, "FromListDir", PackArchiveFileFromListDir);

def ArchiveFileArrayBase64Encode(infile, followlink=False, seekstart=0, seekend=0, skipchecksum=False, formatspecs=__file_format_list__, verbose=False, returnfp=False):
 if(verbose):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(isinstance(infile, dict)):
  prelistcatfiles = ArchiveFileToArrayIndex(infile, seekstart, seekend, False, skipchecksum, formatspecs, returnfp);
  listcatfiles = prelistcatfiles['list'];
 else:
  if(infile!="-" and not hasattr(infile, "read") and not hasattr(infile, "write")):
   infile = RemoveWindowsPath(infile);
  if(followlink):
   prelistcatfiles = ArchiveFileToArrayIndex(infile, seekstart, seekend, False, skipchecksum, formatspecs, returnfp);
   listcatfiles = prelistcatfiles['list'];
  else:
   listcatfiles = ArchiveFileToArray(infile, seekstart, seekend, False, skipchecksum, formatspecs, returnfp);
 if(not listcatfiles):
  return False;
 lenlist = len(listcatfiles['ffilelist']);
 fnumfiles = int(listcatfiles['fnumfiles']);
 lcfi = 0;
 lcfx = int(listcatfiles['fnumfiles']);
 if(lenlist>listcatfiles['fnumfiles'] or lenlist<listcatfiles['fnumfiles']):
  lcfx = int(lenlist);
 else:
  lcfx = int(listcatfiles['fnumfiles']);
 while(lcfi<lcfx):
  if(listcatfiles['ffilelist'][lcfi]['fhascontents']):
   listcatfiles['ffilelist'][lcfi]['fcontents'] = base64.b64encode(listcatfiles['ffilelist'][lcfi]['fcontents']).decode("UTF-8");
  lcfi = lcfi + 1;
 return listcatfiles;

create_alias_function("", __file_format_name__, "ArrayBase64Encode", ArchiveFileArrayBase64Encode);

def ArchiveFileArrayBase64Decode(infile, followlink=False, seekstart=0, seekend=0, skipchecksum=False, formatspecs=__file_format_list__, verbose=False, returnfp=False):
 if(verbose):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(isinstance(infile, dict)):
  prelistcatfiles = ArchiveFileToArrayIndex(infile, seekstart, seekend, False, skipchecksum, formatspecs, returnfp);
  listcatfiles = prelistcatfiles['list'];
 else:
  if(infile!="-" and not hasattr(infile, "read") and not hasattr(infile, "write")):
   infile = RemoveWindowsPath(infile);
  if(followlink):
   prelistcatfiles = ArchiveFileToArrayIndex(infile, seekstart, seekend, False, skipchecksum, formatspecs, returnfp);
   listcatfiles = prelistcatfiles['list'];
  else:
   listcatfiles = ArchiveFileToArray(infile, seekstart, seekend, False, skipchecksum, formatspecs, returnfp);
 if(not listcatfiles):
  return False;
 lenlist = len(listcatfiles['ffilelist']);
 fnumfiles = int(listcatfiles['fnumfiles']);
 lcfi = 0;
 lcfx = int(listcatfiles['fnumfiles']);
 if(lenlist>listcatfiles['fnumfiles'] or lenlist<listcatfiles['fnumfiles']):
  lcfx = int(lenlist);
 else:
  lcfx = int(listcatfiles['fnumfiles']);
 while(lcfi<lcfx):
  if(listcatfiles['ffilelist'][lcfi]['fhascontents']):
   listcatfiles['ffilelist'][lcfi]['fcontents'] = base64.b64decode(listcatfiles['ffilelist'][lcfi]['fcontents'].encode("UTF-8"));
  lcfi = lcfi + 1;
 return listcatfiles;

create_alias_function("", __file_format_name__, "ArrayBase64Decode", ArchiveFileArrayBase64Decode);

def UnPackArchiveFile(infile, outdir=None, followlink=False, seekstart=0, seekend=0, skipchecksum=False, formatspecs=__file_format_list__, preservepermissions=True, preservetime=True, verbose=False, returnfp=False):
 if(outdir is not None):
  outdir = RemoveWindowsPath(outdir);
 if(verbose):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(isinstance(infile, dict)):
  prelistcatfiles = ArchiveFileToArrayIndex(infile, seekstart, seekend, False, skipchecksum, formatspecs, returnfp);
  listcatfiles = prelistcatfiles['list'];
 else:
  if(infile!="-" and not hasattr(infile, "read") and not hasattr(infile, "write")):
   infile = RemoveWindowsPath(infile);
  if(followlink):
   prelistcatfiles = ArchiveFileToArrayIndex(infile, seekstart, seekend, False, skipchecksum, formatspecs, returnfp);
   listcatfiles = prelistcatfiles['list'];
  else:
   listcatfiles = ArchiveFileToArray(infile, seekstart, seekend, False, skipchecksum, formatspecs, returnfp);
 if(not listcatfiles):
  return False;
 lenlist = len(listcatfiles['ffilelist']);
 fnumfiles = int(listcatfiles['fnumfiles']);
 lcfi = 0;
 lcfx = int(listcatfiles['fnumfiles']);
 if(lenlist>listcatfiles['fnumfiles'] or lenlist<listcatfiles['fnumfiles']):
  lcfx = int(lenlist);
 else:
  lcfx = int(listcatfiles['fnumfiles']);
 while(lcfi<lcfx):
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
   VerbosePrintOut(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']));
  if(listcatfiles['ffilelist'][lcfi]['ftype']==0 or listcatfiles['ffilelist'][lcfi]['ftype']==7):
   with open(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), "wb") as fpc:
    fpc.write(listcatfiles['ffilelist'][lcfi]['fcontents'])
    try:
     fpc.flush()
     os.fsync(fpc.fileno())
    except io.UnsupportedOperation:
     pass
    except AttributeError:
     pass
   if(hasattr(os, "chown") and funame==listcatfiles['ffilelist'][lcfi]['funame'] and fgname==listcatfiles['ffilelist'][lcfi]['fgname'] and preservepermissions):
    os.chown(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), listcatfiles['ffilelist'][lcfi]['fuid'], listcatfiles['ffilelist'][lcfi]['fgid']);
   if(preservepermissions):
    os.chmod(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), listcatfiles['ffilelist'][lcfi]['fchmode']);
   if(preservetime):
    os.utime(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), (listcatfiles['ffilelist'][lcfi]['fatime'], listcatfiles['ffilelist'][lcfi]['fmtime']));
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
     with open(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), "wb") as fpc:
      fpc.write(flinkinfo['fcontents'])
      try:
       fpc.flush()
       os.fsync(fpc.fileno())
      except io.UnsupportedOperation:
       pass
      except AttributeError:
       pass
     if(hasattr(os, "chown") and funame==flinkinfo['funame'] and fgname==flinkinfo['fgname'] and preservepermissions):
      os.chown(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), flinkinfo['fuid'], flinkinfo['fgid']);
     if(preservepermissions):
      os.chmod(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), flinkinfo['fchmode']);
     if(preservetime):
      os.utime(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), (flinkinfo['fatime'], flinkinfo['fmtime']));
    if(flinkinfo['ftype']==1):
     os.link(flinkinfo['flinkname'], PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']));
    if(flinkinfo['ftype']==2):
     os.symlink(flinkinfo['flinkname'], PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']));
    if(flinkinfo['ftype']==5):
     if(preservepermissions):
      os.mkdir(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), flinkinfo['fchmode']);
     else:
      os.mkdir(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']));
     if(hasattr(os, "chown") and funame==flinkinfo['funame'] and fgname==flinkinfo['fgname'] and preservepermissions):
      os.chown(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), flinkinfo['fuid'], flinkinfo['fgid']);
     if(preservepermissions):
      os.chmod(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), flinkinfo['fchmode']);
     if(preservetime):
      os.utime(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), (flinkinfo['fatime'], flinkinfo['fmtime']));
    if(flinkinfo['ftype']==6 and hasattr(os, "mkfifo")):
     os.mkfifo(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), flinkinfo['fchmode']);
   else:
    os.link(listcatfiles['ffilelist'][lcfi]['flinkname'], PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']));
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
     with open(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), "wb") as fpc:
      fpc.write(flinkinfo['fcontents'])
      try:
       fpc.flush()
       os.fsync(fpc.fileno())
      except io.UnsupportedOperation:
       pass
      except AttributeError:
       pass
     if(hasattr(os, "chown") and funame==flinkinfo['funame'] and fgname==flinkinfo['fgname'] and preservepermissions):
      os.chown(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), flinkinfo['fuid'], flinkinfo['fgid']);
     if(preservepermissions):
      os.chmod(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), flinkinfo['fchmode']);
     if(preservetime):
      os.utime(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), (flinkinfo['fatime'], flinkinfo['fmtime']));
    if(flinkinfo['ftype']==1):
     os.link(flinkinfo['flinkname'], PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']));
    if(flinkinfo['ftype']==2):
     os.symlink(flinkinfo['flinkname'], PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']));
    if(flinkinfo['ftype']==5):
     if(preservepermissions):
      os.mkdir(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), flinkinfo['fchmode']);
     else:
      os.mkdir(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']));
     if(hasattr(os, "chown") and funame==flinkinfo['funame'] and fgname==flinkinfo['fgname'] and preservepermissions):
      os.chown(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), flinkinfo['fuid'], flinkinfo['fgid']);
     if(preservepermissions):
      os.chmod(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), flinkinfo['fchmode']);
     if(preservetime):
      os.utime(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), (flinkinfo['fatime'], flinkinfo['fmtime']));
    if(flinkinfo['ftype']==6 and hasattr(os, "mkfifo")):
     os.mkfifo(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), flinkinfo['fchmode']);
   else:
    os.symlink(listcatfiles['ffilelist'][lcfi]['flinkname'], PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']));
  if(listcatfiles['ffilelist'][lcfi]['ftype']==5):
   if(preservepermissions):
    os.mkdir(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), listcatfiles['ffilelist'][lcfi]['fchmode']);
   else:
    os.mkdir(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']));
   if(hasattr(os, "chown") and funame==listcatfiles['ffilelist'][lcfi]['funame'] and fgname==listcatfiles['ffilelist'][lcfi]['fgname'] and preservepermissions):
    os.chown(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), listcatfiles['ffilelist'][lcfi]['fuid'], listcatfiles['ffilelist'][lcfi]['fgid']);
   if(preservepermissions):
    os.chmod(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), listcatfiles['ffilelist'][lcfi]['fchmode']);
   if(preservetime):
    os.utime(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), (listcatfiles['ffilelist'][lcfi]['fatime'], listcatfiles['ffilelist'][lcfi]['fmtime']));
  if(listcatfiles['ffilelist'][lcfi]['ftype']==6 and hasattr(os, "mkfifo")):
   os.mkfifo(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), listcatfiles['ffilelist'][lcfi]['fchmode']);
  lcfi = lcfi + 1;
 if(returnfp):
  return listcatfiles['ffilelist']['catfp'];
 else:
  return True;

create_alias_function("UnPack", __file_format_name__, "", UnPackArchiveFile);

if(hasattr(shutil, "register_unpack_format")):
 def UnPackArchiveFileFunc(archive_name, extract_dir=None, **kwargs):
  return UnPackArchiveFile(archive_name, extract_dir, False, 0, 0, False, __file_format_delimiter__, False, False);
 create_alias_function("UnPack", __file_format_name__, "Func", UnPackArchiveFileFunc);

def UnPackArchiveFileString(catstr, outdir=None, followlink=False, seekstart=0, seekend=0, skipchecksum=False, formatspecs=__file_format_list__, verbose=False, returnfp=False):
 catfp = BytesIO(catstr);
 listcatfiles = UnPackArchiveFile(catfp, outdir, followlink, seekstart, seekend, skipchecksum, formatspecs, verbose, returnfp);
 return listcatfiles;

create_alias_function("UnPack", __file_format_name__, "String", UnPackArchiveFileString);

def ArchiveFileListFiles(infile, seekstart=0, seekend=0, skipchecksum=False, formatspecs=__file_format_list__, verbose=False, returnfp=False):
 logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(isinstance(infile, dict)):
  listcatfiles = infile;
 else:
  if(infile!="-" and not hasattr(infile, "read") and not hasattr(infile, "write")):
   infile = RemoveWindowsPath(infile);
  listcatfiles = ArchiveFileToArray(infile, seekstart, seekend, True, skipchecksum, formatspecs, returnfp);
 if(not listcatfiles):
  return False;
 lenlist = len(listcatfiles['ffilelist']);
 fnumfiles = int(listcatfiles['fnumfiles']);
 lcfi = 0;
 lcfx = int(listcatfiles['fnumfiles']);
 if(lenlist>listcatfiles['fnumfiles'] or lenlist<listcatfiles['fnumfiles']):
  lcfx = int(lenlist);
 else:
  lcfx = int(listcatfiles['fnumfiles']);
 returnval = {};
 while(lcfi<lcfx):
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

create_alias_function("", __file_format_name__, "ListFiles", ArchiveFileListFiles);

def ArchiveFileStringListFiles(catstr, seekstart=0, seekend=0, skipchecksum=False, formatspecs=__file_format_list__, verbose=False, returnfp=False):
 catfp = BytesIO(catstr);
 listcatfiles = ArchiveFileListFiles(catstr, seekstart, seekend, skipchecksum, formatspecs, verbose, returnfp);
 return listcatfiles;

create_alias_function("", __file_format_name__, "StringListFiles", ArchiveFileListFiles);

def ArchiveFileListFilesAlt(infile, seekstart=0, seekend=0, skipchecksum=False, formatspecs=__file_format_list__, verbose=False, returnfp=False):
 logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(isinstance(infile, dict)):
  listcatfiles = infile;
 else:
  if(infile!="-" and not hasattr(infile, "read") and not hasattr(infile, "write")):
   infile = RemoveWindowsPath(infile);
  listcatfiles = ArchiveFileToArray(infile, seekstart, seekend, True, skipchecksum, formatspecs, returnfp);
 if(not listcatfiles):
  return False;
 lenlist = len(listcatfiles['ffilelist']);
 fnumfiles = int(listcatfiles['fnumfiles']);
 lcfi = 0;
 lcfx = int(listcatfiles['fnumfiles']);
 if(lenlist>listcatfiles['fnumfiles'] or lenlist<listcatfiles['fnumfiles']):
  lcfx = int(lenlist);
 else:
  lcfx = int(listcatfiles['fnumfiles']);
 returnval = {};
 while(lcfi<lcfx):
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

create_alias_function("", __file_format_name__, "ListFilesAlt", ArchiveFileListFilesAlt);

def ArchiveFileStringListFilesAlt(catstr, seekstart=0, seekend=0, skipchecksum=False, formatspecs=__file_format_list__, verbose=False, returnfp=False):
 catfp = BytesIO(catstr);
 listcatfiles = ArchiveFileListFilesAlt(catstr, seekstart, seekend, skipchecksum, formatspecs, verbose, returnfp);
 return listcatfiles;

create_alias_function("", __file_format_name__, "StringListFilesAlt", ArchiveFileListFilesAlt);

def TarFileListFiles(infile, verbose=False, returnfp=False):
 logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(infile=="-"):
  infile = BytesIO();
  if(hasattr(sys.stdin, "buffer")):
   shutil.copyfileobj(sys.stdin.buffer, infile);
  else:
   shutil.copyfileobj(sys.stdin, infile);
  infile.seek(0, 0);
  if(not infile):
   return False;
  infile.seek(0, 0);
 elif(re.findall(r"^(http|https|ftp|ftps|sftp)\:\/\/", str(infile))):
  infile = download_file_from_internet_file(infile);
  infile.seek(0, 0);
  if(not infile):
   return False;
  infile.seek(0, 0);
 elif(not os.path.exists(infile) or not os.path.isfile(infile)):
  return False;
 elif(os.path.exists(infile) and os.path.isfile(infile)):
  try:
   if(not tarfile.is_tarfile(infile)):
    return False;
  except AttributeError:
   if(not is_tarfile(infile)):
    return False;
 else:
  return False;
 try:
  if(hasattr(infile, "read") or hasattr(infile, "write")):
   tarfp = tarfile.open(fileobj=infile, mode="r");
  else:
   tarfp = tarfile.open(infile, "r");
 except FileNotFoundError:
  return False;
 for member in sorted(tarfp.getmembers(), key=lambda x: x.name):
  returnval.update({lcfi: member.name});
  fpremode = member.mode;
  ffullmode = member.mode;
  flinkcount = 0;
  ftype = 0;
  if(member.isreg()):
   ffullmode = member.mode + stat.S_IFREG;
   ftype = 0;
  elif(member.isdev()):
   ffullmode = member.mode;
   ftype = 7;
  elif(member.islnk()):
   ffullmode = member.mode + stat.S_IFREG;
   ftype = 1;
  elif(member.issym()):
   ffullmode = member.mode + stat.S_IFLNK;
   ftype = 2;
  elif(member.ischr()):
   ffullmode = member.mode + stat.S_IFCHR;
   ftype = 3;
  elif(member.isblk()):
   ffullmode = member.mode + stat.S_IFBLK;
   ftype = 4;
  elif(member.isdir()):
   ffullmode = member.mode + stat.S_IFDIR;
   ftype = 5;
  elif(member.isfifo()):
   ffullmode = member.mode + stat.S_IFIFO;
   ftype = 6;
  elif(member.issparse()):
   ffullmode = member.mode;
   ftype = 12;
  if(not verbose):
   VerbosePrintOut(member.name);
  elif(verbose):
   permissions = { 'access': { '0': ('---'), '1': ('--x'), '2': ('-w-'), '3': ('-wx'), '4': ('r--'), '5': ('r-x'), '6': ('rw-'), '7': ('rwx') }, 'roles': { 0: 'owner', 1: 'group', 2: 'other' } };
   printfname = member.name;
   if(member.islnk()):
    printfname = member.name + " link to " + member.linkname;
   elif(member.issym()):
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
 if(infile=="-"):
  infile = BytesIO();
  if(hasattr(sys.stdin, "buffer")):
   shutil.copyfileobj(sys.stdin.buffer, infile);
  else:
   shutil.copyfileobj(sys.stdin, infile);
  infile.seek(0, 0);
  if(not infile):
   return False;
  infile.seek(0, 0);
 elif(re.findall(r"^(http|https|ftp|ftps|sftp)\:\/\/", str(infile))):
  infile = download_file_from_internet_file(infile);
  infile.seek(0, 0);
  if(not infile):
   return False;
  infile.seek(0, 0);
 elif(not os.path.exists(infile) or not os.path.isfile(infile)):
  return False;
 else:
  return False;
 if(not zipfile.is_zipfile(infile)):
  return False;
 try:
  zipfp = zipfile.ZipFile(infile, "r", allowZip64=True);
 except FileNotFoundError:
  return False;
 lcfi = 0;
 returnval = {};
 ziptest = zipfp.testzip();
 if(ziptest):
  VerbosePrintOut("Bad file found!");
 for member in sorted(zipfp.infolist(), key=lambda x: x.filename):
  if(zipinfo.create_system==0 or zipinfo.create_system==10):
   fwinattributes = int(zipinfo.external_attr);
   if(not member.is_dir()):
    fmode = int(stat.S_IFREG + 438);
    fchmode = int(stat.S_IMODE(fmode));
    ftypemod = int(stat.S_IFMT(fmode));
   elif(member.is_dir()):
    fmode = int(stat.S_IFDIR + 511);
    fchmode = int(stat.S_IMODE(int(stat.S_IFDIR + 511)));
    ftypemod = int(stat.S_IFMT(int(stat.S_IFDIR + 511)));
  elif(zipinfo.create_system==3):
   fwinattributes =int(0);
   fmode = int(zipinfo.external_attr);
   fchmode = int(stat.S_IMODE(fmode));
   ftypemod = int(stat.S_IFMT(fmode));
  else:
   fwinattributes = int(0);
   if(not member.is_dir()):
    fmode = int(stat.S_IFREG + 438);
    fchmode = int(stat.S_IMODE(fmode));
    ftypemod = int(stat.S_IFMT(fmode));
   elif(member.is_dir()):
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
   elif(member.is_dir()):
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

if(not rarfile_support):
 def RarFileListFiles(infile, verbose=False, returnfp=False):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
  if(not os.path.exists(infile) or not os.path.isfile(infile)):
   return False;

if(rarfile_support):
 def RarFileListFiles(infile, verbose=False, returnfp=False):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
  if(not os.path.exists(infile) or not os.path.isfile(infile)):
   return False;
  if(not rarfile.is_rarfile(infile) and not rarfile.is_rarfile_sfx(infile)):
   return False;
  lcfi = 0;
  returnval = {};
  rarfp = rarfile.RarFile(infile, "r");
  rartest = rarfp.testrar();
  if(rartest):
   VerbosePrintOut("Bad file found!");
  for member in sorted(rarfp.infolist(), key=lambda x: x.filename):
   is_unix = False;
   is_windows = False;
   if(member.host_os==rarfile.RAR_OS_UNIX):
    is_windows = False;
    try:
     member.external_attr
     is_unix = True;
    except AttributeError:
     is_unix = False;
   elif(member.host_os==rarfile.RAR_OS_WIN32):
    is_unix = False;
    try:
     member.external_attr
     is_windows = True;
    except AttributeError:
     is_windows = False;
   else:
    is_unix = False;
    is_windows = False;
   if(is_unix and member.external_attr !=0):
    fpremode = int(member.external_attr);
   elif(member.is_file()):
    fpremode = int(stat.S_IFREG + 438);
   elif(member.is_symlink()):
    fpremode = int(stat.S_IFLNK + 438);
   elif(member.is_dir()):
    fpremode = int(stat.S_IFDIR + 511);
   if(is_windows and member.external_attr !=0):
    fwinattributes = int(member.external_attr);
   else:
    fwinattributes = int(0);
   if(is_unix and member.external_attr !=0):
    fmode = int(member.external_attr);
    fchmode = int(stat.S_IMODE(member.external_attr));
    ftypemod = int(stat.S_IFMT(member.external_attr));
   elif(member.is_file()):
    fmode = int(stat.S_IFREG + 438);
    fchmode = int(stat.S_IMODE(int(stat.S_IFREG + 438)));
    ftypemod = int(stat.S_IFMT(int(stat.S_IFREG + 438)));
   elif(member.is_symlink()):
    fmode = int(stat.S_IFLNK + 438);
    fchmode = int(stat.S_IMODE(int(stat.S_IFLNK + 438)));
    ftypemod = int(stat.S_IFMT(int(stat.S_IFLNK + 438)));
   elif(member.is_dir()):
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
    if(member.is_file()):
     ftype = 0;
     permissionstr = "-" + permissionstr;
     printfname = member.filename;
    elif(member.is_symlink()):
     ftype = 2;
     permissionstr = "l" + permissionstr;
     printfname = member.name + " -> " + member.read().decode("UTF-8");
    elif(member.is_dir()):
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
    VerbosePrintOut(PrintPermissionString(fmode, ftype) + " " + str(str(fuprint) + "/" + str(fgprint) + " " + str(member.file_size).rjust(15) + " " + member.mtime.strftime('%Y-%m-%d %H:%M') + " " + printfname));
   lcfi = lcfi + 1;
  if(returnfp):
   return listcatfiles['catfp'];
  else:
   return True;

def ListDirListFiles(infiles, dirlistfromtxt=False, compression="auto", compressionlevel=None, followlink=False, seekstart=0, seekend=0, skipchecksum=False, checksumtype="crc32", formatspecs=__file_format_list__, verbose=False, returnfp=False):
 outarray = BytesIO();
 packcat = PackArchiveFile(infiles, outarray, dirlistfromtxt, compression, compressionlevel, followlink, checksumtype, formatspecs, False, True);
 listcatfiles = ArchiveFileListFiles(outarray, seekstart, seekend, skipchecksum, formatspecs, verbose, returnfp);
 return listcatfiles;

def ListDirListFilesAlt(infiles, dirlistfromtxt=False, followlink=False, listonly=True, seekstart=0, seekend=0, skipchecksum=False, checksumtype="crc32", formatspecs=__file_format_list__, verbose=False, returnfp=False):
 outarray = ListDirToArrayAlt(infiles, dirlistfromtxt, followlink, listonly, checksumtype, formatspecs, verbose);
 listcatfiles = ArchiveFileListFiles(outarray, seekstart, seekend, skipchecksum, formatspecs, verbose, returnfp);
 return listcatfiles;

def PackArchiveFileFromListDirAlt(infiles, outfile, dirlistfromtxt=False, compression="auto", compressionlevel=None, followlink=False, skipchecksum=False, checksumtype="crc32", extradata=[], formatspecs=__file_format_list__, verbose=False, returnfp=False):
 outarray = ListDirToArrayAlt(infiles, dirlistfromtxt, followlink, False, checksumtype, extradata, formatspecs, False);
 listcatfiles = RePackArchiveFile(outarray, outfile, compression, compressionlevel, followlink, checksumtype, skipchecksum, extradata, formatspecs, verbose, returnfp);
 return listcatfiles;

create_alias_function("Pack", __file_format_name__, "FromListDirAlt", PackArchiveFileFromListDirAlt);

def PackArchiveFileFromTarFileAlt(infile, outfile, compression="auto", compressionlevel=None, checksumtype="crc32", extradata=[], formatspecs=__file_format_list__, verbose=False, returnfp=False):
 outarray = TarFileToArrayAlt(infile, False, checksumtype, extradata, formatspecs, False);
 listcatfiles = RePackArchiveFile(outarray, outfile, compression, compressionlevel, False, checksumtype, False, extradata, formatspecs, verbose, returnfp);
 return listcatfiles;

create_alias_function("Pack", __file_format_name__, "FromTarFileAlt", PackArchiveFileFromTarFileAlt);

def PackArchiveFileFromZipFileAlt(infile, outfile, compression="auto", compressionlevel=None, checksumtype="crc32", extradata=[], formatspecs=__file_format_list__, verbose=False, returnfp=False):
 outarray = ZipFileToArrayAlt(infile, False, checksumtype, extradata, formatspecs, False);
 listcatfiles = RePackArchiveFile(outarray, outfile, compression, compressionlevel, False, checksumtype, False, extradata, formatspecs, verbose, returnfp);
 return listcatfiles;

create_alias_function("Pack", __file_format_name__, "FromZipFileAlt", PackArchiveFileFromZipFileAlt);

if(not rarfile_support):
 def PackArchiveFileFromRarFileAlt(infile, outfile, compression="auto", compressionlevel=None, checksumtype="crc32", extradata=[], formatspecs=__file_format_list__, verbose=False, returnfp=False):
  return False;

if(rarfile_support):
 def PackArchiveFileFromRarFileAlt(infile, outfile, compression="auto", compressionlevel=None, checksumtype="crc32", extradata=[], formatspecs=__file_format_list__, verbose=False, returnfp=False):
  outarray = RarFileToArrayAlt(infile, False, checksumtype, extradata, formatspecs, False);
  listcatfiles = RePackArchiveFile(outarray, outfile, compression, compressionlevel, False, checksumtype, False, extradata, formatspecs, verbose, returnfp);
  return listcatfiles;

create_alias_function("Pack", __file_format_name__, "FromRarFileAlt", PackArchiveFileFromRarFileAlt);

def download_file_from_ftp_file(url):
 urlparts = urlparse(url);
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
 if(urlparts.scheme=="sftp"):
  if(__use_pysftp__):
   return download_file_from_pysftp_file(url);
  else:
   return download_file_from_sftp_file(url);
 elif(urlparts.scheme=="http" or urlparts.scheme=="https"):
  return download_file_from_http_file(url);
 ftp_port = urlparts.port;
 if(urlparts.port is None):
  ftp_port = 21;
 try:
  ftp.connect(urlparts.hostname, ftp_port);
 except socket.gaierror:
  log.info("Error With URL "+url);
  return False;
 except socket.timeout:
  log.info("Error With URL "+url);
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
 urlparts = urlparse(url);
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
 if(urlparts.scheme=="sftp"):
  if(__use_pysftp__):
   return upload_file_from_pysftp_file(url);
  else:
   return upload_file_from_sftp_file(url);
 elif(urlparts.scheme=="http" or urlparts.scheme=="https"):
  return False;
 ftp_port = urlparts.port;
 if(urlparts.port is None):
  ftp_port = 21;
 try:
  ftp.connect(urlparts.hostname, ftp_port);
 except socket.gaierror:
  log.info("Error With URL "+url);
  return False;
 except socket.timeout:
  log.info("Error With URL "+url);
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

def download_file_from_http_file(url, headers=geturls_headers_pycatfile_python_alt):
 # Parse the URL to extract username and password if present
 urlparts = urlparse(url);
 username = urlparts.username;
 password = urlparts.password;
 # Rebuild the URL without the username and password
 netloc = urlparts.hostname;
 if(urlparts.scheme=="sftp"):
  if(__use_pysftp__):
   return download_file_from_pysftp_file(url);
  else:
   return download_file_from_sftp_file(url);
 elif(urlparts.scheme=="ftp" or urlparts.scheme=="ftps"):
  return download_file_from_ftp_file(url);
 if urlparts.port:
   netloc += ':' + str(urlparts.port);
 rebuilt_url = urlunparse((urlparts.scheme, netloc, urlparts.path, urlparts.params, urlparts.query, urlparts.fragment));
 # Create a temporary file object
 httpfile = BytesIO();
 if haverequests:
  # Use the requests library if available
  if username and password:
   response = requests.get(rebuilt_url, headers=headers, auth=(username, password), stream=True);
  else:
   response = requests.get(rebuilt_url, headers=headers, stream=True);
  response.raw.decode_content = True
  shutil.copyfileobj(response.raw, httpfile);
 else:
  # Build a Request object for urllib
  request = Request(rebuilt_url, headers=headers);
  # Create an opener object for handling URLs
  if username and password:
   # Create a password manager
   password_mgr = HTTPPasswordMgrWithDefaultRealm();
   # Add the username and password
   password_mgr.add_password(None, rebuilt_url, username, password);
   # Create an authentication handler using the password manager
   auth_handler = HTTPBasicAuthHandler(password_mgr);
   # Build the opener with the authentication handler
   opener = build_opener(auth_handler);
  else:
      opener = build_opener();
  with opener.open(request) as response:
   shutil.copyfileobj(response, httpfile);
 # Reset file pointer to the start
 httpfile.seek(0, 0);
 # Return the temporary file object
 return httpfile;

def download_file_from_http_string(url, headers=geturls_headers_pycatfile_python_alt):
 httpfile = download_file_from_http_file(url, headers);
 return ftpfile.read();

if(haveparamiko):
 def download_file_from_sftp_file(url):
  urlparts = urlparse(url);
  file_name = os.path.basename(urlparts.path);
  file_dir = os.path.dirname(urlparts.path);
  sftp_port = urlparts.port;
  if(urlparts.port is None):
   sftp_port = 22;
  else:
   sftp_port = urlparts.port;
  if(urlparts.username is not None):
   sftp_username = urlparts.username;
  else:
   sftp_username = "anonymous";
  if(urlparts.password is not None):
   sftp_password = urlparts.password;
  elif(urlparts.password is None and urlparts.username=="anonymous"):
   sftp_password = "anonymous";
  else:
   sftp_password = "";
  if(urlparts.scheme=="ftp"):
   return download_file_from_ftp_file(url);
  elif(urlparts.scheme=="http" or urlparts.scheme=="https"):
   return download_file_from_http_file(url);
  if(urlparts.scheme!="sftp"):
   return False;
  ssh = paramiko.SSHClient();
  ssh.load_system_host_keys();
  ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy());
  try:
   ssh.connect(urlparts.hostname, port=sftp_port, username=urlparts.username, password=urlparts.password);
  except paramiko.ssh_exception.SSHException:
   return False;
  except socket.gaierror:
   log.info("Error With URL "+url);
   return False;
  except socket.timeout:
   log.info("Error With URL "+url);
   return False;
  sftp = ssh.open_sftp();
  sftpfile = BytesIO();
  sftp.getfo(urlparts.path, sftpfile);
  sftp.close();
  ssh.close();
  sftpfile.seek(0, 0);
  return sftpfile;
else:
 def download_file_from_sftp_file(url):
  return False;

if(haveparamiko):
 def download_file_from_sftp_string(url):
  sftpfile = download_file_from_sftp_file(url);
  return sftpfile.read();
else:
 def download_file_from_ftp_string(url):
  return False;

if(haveparamiko):
 def upload_file_to_sftp_file(sftpfile, url):
  urlparts = urlparse(url);
  file_name = os.path.basename(urlparts.path);
  file_dir = os.path.dirname(urlparts.path);
  sftp_port = urlparts.port;
  if(urlparts.port is None):
   sftp_port = 22;
  else:
   sftp_port = urlparts.port;
  if(urlparts.username is not None):
   sftp_username = urlparts.username;
  else:
   sftp_username = "anonymous";
  if(urlparts.password is not None):
   sftp_password = urlparts.password;
  elif(urlparts.password is None and urlparts.username=="anonymous"):
   sftp_password = "anonymous";
  else:
   sftp_password = "";
  if(urlparts.scheme=="ftp"):
   return upload_file_from_ftp_file(url);
  elif(urlparts.scheme=="http" or urlparts.scheme=="https"):
   return False;
  if(urlparts.scheme!="sftp"):
   return False;
  ssh = paramiko.SSHClient();
  ssh.load_system_host_keys();
  ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy());
  try:
   ssh.connect(urlparts.hostname, port=sftp_port, username=urlparts.username, password=urlparts.password);
  except paramiko.ssh_exception.SSHException:
   return False;
  except socket.gaierror:
   log.info("Error With URL "+url);
   return False;
  except socket.timeout:
   log.info("Error With URL "+url);
   return False;
  sftp = ssh.open_sftp();
  sftp.putfo(sftpfile, urlparts.path);
  sftp.close();
  ssh.close();
  sftpfile.seek(0, 0);
  return sftpfile;
else:
 def upload_file_to_sftp_file(sftpfile, url):
  return False;

if(haveparamiko):
 def upload_file_to_sftp_string(sftpstring, url):
  sftpfileo = BytesIO(sftpstring);
  sftpfile = upload_file_to_sftp_files(ftpfileo, url);
  sftpfileo.close();
  return sftpfile;
else:
 def upload_file_to_sftp_string(url):
  return False;

if(havepysftp):
 def download_file_from_pysftp_file(url):
  urlparts = urlparse(url);
  file_name = os.path.basename(urlparts.path);
  file_dir = os.path.dirname(urlparts.path);
  sftp_port = urlparts.port;
  if(urlparts.port is None):
   sftp_port = 22;
  else:
   sftp_port = urlparts.port;
  if(urlparts.username is not None):
   sftp_username = urlparts.username;
  else:
   sftp_username = "anonymous";
  if(urlparts.password is not None):
   sftp_password = urlparts.password;
  elif(urlparts.password is None and urlparts.username=="anonymous"):
   sftp_password = "anonymous";
  else:
   sftp_password = "";
  if(urlparts.scheme=="ftp"):
   return download_file_from_ftp_file(url);
  elif(urlparts.scheme=="http" or urlparts.scheme=="https"):
   return download_file_from_http_file(url);
  if(urlparts.scheme!="sftp"):
   return False;
  try:
   pysftp.Connection(urlparts.hostname, port=sftp_port, username=urlparts.username, password=urlparts.password);
  except paramiko.ssh_exception.SSHException:
   return False;
  except socket.gaierror:
   log.info("Error With URL "+url);
   return False;
  except socket.timeout:
   log.info("Error With URL "+url);
   return False;
  sftp = ssh.open_sftp();
  sftpfile = BytesIO();
  sftp.getfo(urlparts.path, sftpfile);
  sftp.close();
  ssh.close();
  sftpfile.seek(0, 0);
  return sftpfile;
else:
 def download_file_from_pysftp_file(url):
  return False;

if(havepysftp):
 def download_file_from_pysftp_string(url):
  sftpfile = download_file_from_pysftp_file(url);
  return sftpfile.read();
else:
 def download_file_from_ftp_string(url):
  return False;

if(havepysftp):
 def upload_file_to_pysftp_file(sftpfile, url):
  urlparts = urlparse(url);
  file_name = os.path.basename(urlparts.path);
  file_dir = os.path.dirname(urlparts.path);
  sftp_port = urlparts.port;
  if(urlparts.port is None):
   sftp_port = 22;
  else:
   sftp_port = urlparts.port;
  if(urlparts.username is not None):
   sftp_username = urlparts.username;
  else:
   sftp_username = "anonymous";
  if(urlparts.password is not None):
   sftp_password = urlparts.password;
  elif(urlparts.password is None and urlparts.username=="anonymous"):
   sftp_password = "anonymous";
  else:
   sftp_password = "";
  if(urlparts.scheme=="ftp"):
   return upload_file_from_ftp_file(url);
  elif(urlparts.scheme=="http" or urlparts.scheme=="https"):
   return False;
  if(urlparts.scheme!="sftp"):
   return False;
  try:
   pysftp.Connection(urlparts.hostname, port=sftp_port, username=urlparts.username, password=urlparts.password);
  except paramiko.ssh_exception.SSHException:
   return False;
  except socket.gaierror:
   log.info("Error With URL "+url);
   return False;
  except socket.timeout:
   log.info("Error With URL "+url);
   return False;
  sftp = ssh.open_sftp();
  sftp.putfo(sftpfile, urlparts.path);
  sftp.close();
  ssh.close();
  sftpfile.seek(0, 0);
  return sftpfile;
else:
 def upload_file_to_pysftp_file(sftpfile, url):
  return False;

if(havepysftp):
 def upload_file_to_pysftp_string(sftpstring, url):
  sftpfileo = BytesIO(sftpstring);
  sftpfile = upload_file_to_pysftp_files(ftpfileo, url);
  sftpfileo.close();
  return sftpfile;
else:
 def upload_file_to_pysftp_string(url):
  return False;

def download_file_from_internet_file(url, headers=geturls_headers_pycatfile_python_alt):
 urlparts = urlparse(url);
 if(urlparts.scheme=="http" or urlparts.scheme=="https"):
  return download_file_from_http_file(url, headers);
 elif(urlparts.scheme=="ftp" or urlparts.scheme=="ftps"):
  return download_file_from_ftp_file(url);
 elif(urlparts.scheme=="sftp"):
  if(__use_pysftp__ and havepysftp):
   return download_file_from_pysftp_file(url);
  else:
   return download_file_from_sftp_file(url);
 else:
  return False;
 return False;

def download_file_from_internet_uncompress_file(url, headers=geturls_headers_pycatfile_python_alt, formatspecs=__file_format_list__):
 fp = download_file_from_internet_file(url);
 fp = UncompressArchiveFile(fp, formatspecs);
 fp.seek(0, 0);
 if(not fp):
  return False;
 return fp;

def download_file_from_internet_string(url, headers=geturls_headers_pycatfile_python_alt):
 urlparts = urlparse(url);
 if(urlparts.scheme=="http" or urlparts.scheme=="https"):
  return download_file_from_http_string(url, headers);
 elif(urlparts.scheme=="ftp" or urlparts.scheme=="ftps"):
  return download_file_from_ftp_string(url);
 elif(urlparts.scheme=="sftp"):
  if(__use_pysftp__ and havepysftp):
   return download_file_from_pysftp_string(url);
  else:
   return download_file_from_sftp_string(url);
 else:
  return False;
 return False;

def download_file_from_internet_uncompress_string(url, headers=geturls_headers_pycatfile_python_alt, formatspecs=__file_format_list__):
 fp = download_file_from_internet_string(url);
 fp = UncompressArchiveFile(fp, formatspecs);
 fp.seek(0, 0);
 if(not fp):
  return False;
 return fp;

def upload_file_to_internet_file(ifp, url):
 urlparts = urlparse(url);
 if(urlparts.scheme=="http" or urlparts.scheme=="https"):
  return False;
 elif(urlparts.scheme=="ftp" or urlparts.scheme=="ftps"):
  return upload_file_from_ftp_file(ifp, url);
 elif(urlparts.scheme=="sftp"):
  if(__use_pysftp__ and havepysftp):
   return upload_file_from_pysftp_file(ifp, url);
  else:
   return download_file_from_sftp_file(ifp, url);
 else:
  return False;
 return False;

def upload_file_to_internet_compress_file(ifp, url, formatspecs=__file_format_list__):
 catfp = CompressArchiveFile(catfp, compression, formatspecs);
 if(not catfileout):
  return False;
 catfp.seek(0, 0);
 upload_file_to_internet_file(catfp, outfile);
 return True;

def upload_file_to_internet_string(ifp, url):
 urlparts = urlparse(url);
 if(urlparts.scheme=="http" or urlparts.scheme=="https"):
  return False;
 elif(urlparts.scheme=="ftp" or urlparts.scheme=="ftps"):
  return upload_file_from_ftp_string(ifp, url);
 elif(urlparts.scheme=="sftp"):
  if(__use_pysftp__ and havepysftp):
   return upload_file_from_pysftp_string(ifp, url);
  else:
   return download_file_from_sftp_string(ifp, url);
 else:
  return False;
 return False;
 
def upload_file_to_internet_compress_string(ifp, url, formatspecs=__file_format_list__):
 catfp = CompressArchiveFile(BytesIO(ifp), compression, formatspecs);
 if(not catfileout):
  return False;
 catfp.seek(0, 0);
 upload_file_to_internet_file(catfp, outfile);
 return True;

try:
 if(hasattr(shutil, "register_archive_format")):
  # Register the packing format
  shutil.register_archive_format(__file_format_name__, PackArchiveFileFunc, description='Pack concatenated files');
except shutil.RegistryError:
 pass;

try:
 if(hasattr(shutil, "register_unpack_format")):
  # Register the unpacking format
  shutil.register_unpack_format(__file_format_name__, archivefile_extensions, UnPackArchiveFileFunc, description='UnPack concatenated files');
except shutil.RegistryError:
 pass;
