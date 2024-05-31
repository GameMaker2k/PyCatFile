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

    $FileInfo: pycatfile.py - Last Update: 5/15/2024 Ver. 0.11.4 RC 1 - Author: cooldude2k $
'''

from __future__ import absolute_import, division, print_function, unicode_literals;
import io, os, re, sys, time, stat, zlib, base64, shutil, socket, hashlib, datetime, logging, binascii, zipfile, platform;
try:
 from backports import tempfile;
except ImportError:
 import tempfile;
# FTP Support
ftpssl = True;
try:
 from ftplib import FTP, FTP_TLS;
except ImportError:
 ftpssl = False;
 from ftplib import FTP;

try:
 import simplejson as json;
except ImportError:
 import json;

# URL Parsing
try:
 from urllib.parse import urlparse, urlunparse;
except ImportError:
 from urlparse import urlparse, urlunparse;

# Windows-specific setup
if os.name == 'nt':
 if sys.version_info[0] == 2:
  import codecs;
  sys.stdout = codecs.getwriter('utf-8')(sys.stdout);
  sys.stderr = codecs.getwriter('utf-8')(sys.stderr);
 else:
  sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace', line_buffering=True);
  sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace', line_buffering=True);

hashlib_guaranteed = False;
# Environment setup
os.environ["PYTHONIOENCODING"] = "UTF-8";
os.environ["LC_CTYPE"] = "UTF-8";

# Reload sys to set default encoding to UTF-8 (Python 2 only)
if sys.version_info[0] == 2:
 try:
  reload(sys);
  sys.setdefaultencoding('UTF-8');
 except (NameError, AttributeError):
  pass;

# CRC32 import
try:
 from zlib import crc32;
except ImportError:
 from binascii import crc32;

# Define FileNotFoundError for Python 2
try:
 FileNotFoundError;
except NameError:
 FileNotFoundError = IOError;

# RAR file support
rarfile_support = False;
try:
 import rarfile;
 rarfile_support = True;
except ImportError:
 pass;

# 7z file support
py7zr_support = False;
try:
 import py7zr;
 py7zr_support = True;
except ImportError:
 pass;

# TAR file checking
try:
 from xtarfile import is_tarfile;
except ImportError:
 try:
  from safetar import is_tarfile;
 except ImportError:
  from tarfile import is_tarfile;

# TAR file module
try:
 import xtarfile as tarfile;
except ImportError:
 try:
  import safetar as tarfile;
 except ImportError:
  import tarfile;

# Paramiko support
haveparamiko = False;
try:
 import paramiko;
 haveparamiko = True;
except ImportError:
 pass;

# PySFTP support
havepysftp = False;
try:
 import pysftp;
 havepysftp = True;
except ImportError:
 pass;

# Requests support
haverequests = False;
try:
 import requests;
 haverequests = True;
 import urllib3;
 logging.getLogger("urllib3").setLevel(logging.WARNING);
except ImportError:
 pass;

# HTTP and URL parsing
try:
 from urllib.request import Request, build_opener, HTTPBasicAuthHandler;
 from urllib.parse import urlparse;
except ImportError:
 from urllib2 import Request, build_opener, HTTPBasicAuthHandler;
 from urlparse import urlparse;

# StringIO and BytesIO
try:
 from io import StringIO, BytesIO;
except ImportError:
 try:
  from cStringIO import StringIO;
  from cStringIO import StringIO as BytesIO;
 except ImportError:
  from StringIO import StringIO;
  from StringIO import StringIO as BytesIO;

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
__use_advanced_list__ = True;
__use_alt_inode__ = False;
__file_format_extension__ = ".cat";
__file_format_list__ = [__file_format_name__, __file_format_magic__, __file_format_lower__, __file_format_len__, __file_format_hex__, __file_format_delimiter__, __file_format_ver__, __use_new_style__, __use_advanced_list__, __use_alt_inode__];
__file_format_dict__ = {'format_name': __file_format_name__, 'format_magic': __file_format_magic__, 'format_lower': __file_format_lower__, 'format_len': __file_format_len__, 'format_hex': __file_format_hex__, 'format_delimiter': __file_format_delimiter__, 'format_ver': __file_format_ver__, 'new_style': __use_new_style__, 'use_advanced_list': __use_advanced_list__, 'use_alt_inode': __use_alt_inode__};
__project__ = __program_name__;
__project_url__ = "https://github.com/GameMaker2k/PyCatFile";
__version_info__ = (0, 11, 4, "RC 1", 1);
__version_date_info__ = (2024, 5, 17, "RC 1", 1);
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
 try:
  from backports import lzma;
  compression_list.append("lzma");
  compression_list.append("xz");
 except ImportError:
  '''return False;'''
 return compression_list;

compressionsupport = CompressionSupport();
compressionlist = ['auto'];
compressionlistalt = [];
outextlist = [];
outextlistwd = [];
if('gzip' in compressionsupport):
 compressionlist.append('gzip');
 compressionlistalt.append('gzip');
 outextlist.append('gz');
 outextlistwd.append('.gz');
if('bzip2' in compressionsupport):
 compressionlist.append('bzip2');
 compressionlistalt.append('bzip2');
 outextlist.append('bz2');
 outextlistwd.append('.bz2');
if('zstd' in compressionsupport):
 compressionlist.append('zstd');
 compressionlistalt.append('zstd');
 outextlist.append('zst');
 outextlistwd.append('.zst');
if('lz4' in compressionsupport):
 compressionlist.append('lz4');
 compressionlistalt.append('lz4');
 outextlist.append('lz4');
 outextlistwd.append('.lz4');
if('lzo' in compressionsupport):
 compressionlist.append('lzo');
 compressionlistalt.append('lzo');
 outextlist.append('lzo');
 outextlistwd.append('.lzo');
if('lzop' in compressionsupport):
 compressionlist.append('lzop');
 compressionlistalt.append('lzop');
 outextlist.append('lzop');
 outextlistwd.append('.lzop');
if('lzma' in compressionsupport):
 compressionlist.append('lzma');
 compressionlistalt.append('lzma');
 outextlist.append('lzma');
 outextlistwd.append('.lzma');
if('xz' in compressionsupport):
 compressionlist.append('xz');
 compressionlistalt.append('xz');
 outextlist.append('xz');
 outextlistwd.append('.xz');

tarfile_mimetype = "application/tar";
tarfile_tar_mimetype = tarfile_mimetype;
zipfile_mimetype = "application/zip";
zipfile_zip_mimetype = zipfile_mimetype;
rarfile_mimetype = "application/rar";
rarfile_rar_mimetype = rarfile_mimetype;
archivefile_mimetype = "application/x-"+__file_format_dict__['format_lower']+"";
archivefile_cat_mimetype = archivefile_mimetype;
archivefile_gzip_mimetype = "application/x-"+__file_format_dict__['format_lower']+"+gzip";
archivefile_gz_mimetype = archivefile_gzip_mimetype;
archivefile_bzip2_mimetype = "application/x-"+__file_format_dict__['format_lower']+"+bzip2";
archivefile_bz2_mimetype = archivefile_bzip2_mimetype;
archivefile_lz4_mimetype = "application/x-"+__file_format_dict__['format_lower']+"+lz4";
archivefile_lzop_mimetype = "application/x-"+__file_format_dict__['format_lower']+"+lzop";
archivefile_lzo_mimetype = archivefile_lzop_mimetype;
archivefile_zstandard_mimetype = "application/x-"+__file_format_dict__['format_lower']+"+zstandard";
archivefile_zstd_mimetype = archivefile_zstandard_mimetype;
archivefile_lzma_mimetype = "application/x-"+__file_format_dict__['format_lower']+"+lzma";
archivefile_xz_mimetype = "application/x-"+__file_format_dict__['format_lower']+"+xz";
archivefile_extensions = [__file_format_extension__, __file_format_extension__+".gz", __file_format_extension__+".bz2", __file_format_extension__+".zst", __file_format_extension__+".lz4", __file_format_extension__+".lzo", __file_format_extension__+".lzop", __file_format_extension__+".lzma", __file_format_extension__+".xz"];

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
 if isinstance(dirpath, (list, tuple, )):
  dirpath = list(filter(None, dirpath));
 elif isinstance(dirpath, str):
  dirpath = list(filter(None, [dirpath]));
 retlist = [];
 fs_encoding = sys.getfilesystemencoding();
 for mydirfile in dirpath:
  if not os.path.exists(mydirfile):
   return False;
  mydirfile = NormalizeRelativePath(mydirfile);
  if os.path.exists(mydirfile) and os.path.islink(mydirfile):
   mydirfile = RemoveWindowsPath(os.path.realpath(mydirfile));
  if os.path.exists(mydirfile) and os.path.isdir(mydirfile):
   for root, dirs, filenames in os.walk(mydirfile):
    dpath = root;
    dpath = RemoveWindowsPath(dpath);
    if fs_encoding != 'utf-8':
     dpath = dpath.encode(fs_encoding).decode('utf-8');
    if dpath not in retlist and not duplicates:
     retlist.append(dpath);
    if duplicates:
     retlist.append(dpath);
    for file in filenames:
     fpath = os.path.join(root, file);
     fpath = RemoveWindowsPath(fpath);
     if fs_encoding != 'utf-8':
      fpath = fpath.encode(fs_encoding).decode('utf-8');
     if fpath not in retlist and not duplicates:
      retlist.append(fpath);
     if duplicates:
      retlist.append(fpath);
  else:
   path = RemoveWindowsPath(mydirfile);
   if fs_encoding != 'utf-8':
    path = path.encode(fs_encoding).decode('utf-8');
   retlist.append(path);
 return retlist;

def ListDirAdvanced(dirpath, followlink=False, duplicates=False):
 if isinstance(dirpath, (list, tuple, )):
  dirpath = list(filter(None, dirpath));
 elif isinstance(dirpath, str):
  dirpath = list(filter(None, [dirpath]));
 retlist = [];
 fs_encoding = sys.getfilesystemencoding();
 for mydirfile in dirpath:
  if not os.path.exists(mydirfile):
   return False;
  mydirfile = NormalizeRelativePath(mydirfile);
  if os.path.exists(mydirfile) and os.path.islink(mydirfile) and followlink:
   mydirfile = RemoveWindowsPath(os.path.realpath(mydirfile));
  if os.path.exists(mydirfile) and os.path.isdir(mydirfile):
   for root, dirs, filenames in os.walk(mydirfile):
    # Sort dirs and filenames alphabetically in place
    dirs.sort(key=lambda x: x.lower());
    filenames.sort(key=lambda x: x.lower());
    dpath = RemoveWindowsPath(root);
    if fs_encoding != 'utf-8':
     dpath = dpath.encode(fs_encoding).decode('utf-8');
    if not duplicates and dpath not in retlist:
     retlist.append(dpath);
    elif duplicates:
     retlist.append(dpath);
    for file in filenames:
     fpath = os.path.join(root, file);
     fpath = RemoveWindowsPath(fpath);
     if fs_encoding != 'utf-8':
      fpath = fpath.encode(fs_encoding).decode('utf-8');
     if not duplicates and fpath not in retlist:
      retlist.append(fpath);
     elif duplicates:
      retlist.append(fpath);
  else:
   path = RemoveWindowsPath(mydirfile);
   if fs_encoding != 'utf-8':
    path = path.encode(fs_encoding).decode('utf-8');
   retlist.append(path);
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

def FormatSpecsListToDict(formatspecs=__file_format_list__):
 if(isinstance(formatspecs, (list, tuple, ))):
  return {'format_name': formatspecs[0], 'format_magic': formatspecs[1], 'format_lower': formatspecs[2], 'format_len': formatspecs[3], 'format_hex': formatspecs[4], 'format_delimiter': formatspecs[5], 'format_ver': formatspecs[6], 'new_style': formatspecs[7], 'use_advanced_list': formatspecs[8], 'use_alt_inode': formatspecs[9]};
 elif(isinstance(formatspecs, (dict, ))):
  return formatspecs;
 else:
  return __file_format_dict__;
 return __file_format_dict__;

def TarFileCheck(infile):
 try:
  if is_tarfile(infile):
   return True;
  else:
   return False;
 except TypeError:
  try:
   # Check if the input is a file object
   if hasattr(infile, 'read'):
    # Save the current file position
    current_position = infile.tell();
    # Attempt to open the file object as a tar file
    tar = tarfile.open(fileobj=infile);
    tar.close();
    # Restore the file position
    infile.seek(current_position);
    return True;
   else:
    # Assume it's a filename
    tar = tarfile.open(name=infile);
    tar.close();
    return True;
  except tarfile.TarError:
   return False;

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

def GetHeaderChecksum(inlist=[], checksumtype="crc32", encodedata=True, formatspecs=__file_format_dict__):
 formatspecs = FormatSpecsListToDict(formatspecs);
 fileheader = AppendNullBytes(inlist, formatspecs['format_delimiter']) if isinstance(inlist, list) else AppendNullByte(inlist, formatspecs['format_delimiter']);
 if encodedata:
  fileheader = fileheader.encode('UTF-8');
 checksum_methods = {
  "crc16": lambda data: format(crc16(data) & 0xffff, '04x').lower(),
  "crc16_ansi": lambda data: format(crc16(data) & 0xffff, '04x').lower(),
  "crc16_ibm": lambda data: format(crc16(data) & 0xffff, '04x').lower(),
  "crc16_ccitt": lambda data: format(crc16_ccitt(data) & 0xffff, '04x').lower(),
  "adler32": lambda data: format(zlib.adler32(data) & 0xffffffff, '08x').lower(),
  "crc32": lambda data: format(crc32(data) & 0xffffffff, '08x').lower(),
  "crc64_ecma": lambda data: format(crc64_ecma(data) & 0xffffffffffffffff, '016x').lower(),
  "crc64": lambda data: format(crc64_iso(data) & 0xffffffffffffffff, '016x').lower(),
  "crc64_iso": lambda data: format(crc64_iso(data) & 0xffffffffffffffff, '016x').lower(),
 };
 if checksumtype in checksum_methods:
  return checksum_methods[checksumtype](fileheader);
 elif CheckSumSupportAlt(checksumtype, hashlib_guaranteed):
  checksumoutstr = hashlib.new(checksumtype);
  checksumoutstr.update(fileheader);
  return checksumoutstr.hexdigest().lower();
 return format(0, 'x').lower();

def GetFileChecksum(instr, checksumtype="crc32", encodedata=True, formatspecs=__file_format_dict__):
 formatspecs = FormatSpecsListToDict(formatspecs);
 if encodedata:
  instr = instr.encode('UTF-8');
 checksum_methods = {
  "crc16": lambda data: format(crc16(data) & 0xffff, '04x').lower(),
  "crc16_ansi": lambda data: format(crc16(data) & 0xffff, '04x').lower(),
  "crc16_ibm": lambda data: format(crc16(data) & 0xffff, '04x').lower(),
  "crc16_ccitt": lambda data: format(crc16_ccitt(data) & 0xffff, '04x').lower(),
  "adler32": lambda data: format(zlib.adler32(data) & 0xffffffff, '08x').lower(),
  "crc32": lambda data: format(crc32(data) & 0xffffffff, '08x').lower(),
  "crc64_ecma": lambda data: format(crc64_ecma(data) & 0xffffffffffffffff, '016x').lower(),
  "crc64": lambda data: format(crc64_iso(data) & 0xffffffffffffffff, '016x').lower(),
  "crc64_iso": lambda data: format(crc64_iso(data) & 0xffffffffffffffff, '016x').lower(),
 };
 if checksumtype in checksum_methods:
  return checksum_methods[checksumtype](instr);
 elif CheckSumSupportAlt(checksumtype, hashlib_guaranteed):
  checksumoutstr = hashlib.new(checksumtype);
  checksumoutstr.update(instr);
  return checksumoutstr.hexdigest().lower();
 return format(0, 'x').lower();

def ValidateHeaderChecksum(inlist=[], checksumtype="crc32", inchecksum="0", formatspecs=__file_format_dict__):
 formatspecs = FormatSpecsListToDict(formatspecs);
 catfileheadercshex = GetHeaderChecksum(inlist, checksumtype, True, formatspecs).lower();
 return inchecksum.lower() == catfileheadercshex;

def ValidateFileChecksum(infile, checksumtype="crc32", inchecksum="0", formatspecs=__file_format_dict__):
 formatspecs = FormatSpecsListToDict(formatspecs);
 catinfilecshex = GetFileChecksum(infile, checksumtype, True, formatspecs).lower();
 return inchecksum.lower() == catinfilecshex;

def ReadTillNullByteOld(fp, delimiter=__file_format_dict__['format_delimiter']):
 curbyte = b"";
 curfullbyte = b"";
 nullbyte = delimiter.encode("UTF-8");
 while(True):
  curbyte = fp.read(1);
  if(curbyte==nullbyte or not curbyte):
   break;
  curfullbyte = curfullbyte + curbyte;
 return curfullbyte.decode('UTF-8');

def ReadUntilNullByteOld(fp, delimiter=__file_format_dict__['format_delimiter']):
 return ReadTillNullByteOld(fp, delimiter);

def ReadTillNullByteAlt(fp, delimiter=__file_format_dict__['format_delimiter'], chunk_size=1024, max_read=1024000):
 delimiter = delimiter.encode('UTF-8')  # Ensure the delimiter is in bytes
 buffer = bytearray();
 total_read = 0;
 delimiter_length = len(delimiter);
 while True:
  chunk = fp.read(chunk_size)
  if not chunk:
   # End of file reached without finding the delimiter
   break;
  buffer.extend(chunk);
  total_read += len(chunk);
  if delimiter in buffer:
   # Delimiter found, calculate where to reset the file pointer
   index = buffer.find(delimiter);
   # Calculate how many extra bytes were read after the delimiter
   extra_bytes_read = len(buffer) - (index + delimiter_length);
   # Move the file pointer back to just after the delimiter
   fp.seek(-extra_bytes_read, 1);
   buffer = buffer[:index];
   break;
  if total_read >= max_read:
   # Stop reading if max limit is reached to prevent excessive memory usage
   raise MemoryError("Maximum read limit reached without finding the delimiter.");
  # Check for incomplete UTF-8 sequences at the end of the buffer
  if len(buffer) > 1 and 128 <= buffer[-1] < 192:
   # This suggests that the last byte might be the start of a multi-byte character
   # Try to read one more byte to complete the character
   extra_byte = fp.read(1);
   if extra_byte:
    buffer.extend(extra_byte);
   else:
    # No more data available
    break;
 try:
  return buffer.decode('UTF-8', errors='replace');
 except UnicodeDecodeError:
  return buffer.decode('UTF-8', errors='replace');

def ReadUntilNullByteAlt(fp, delimiter=__file_format_dict__['format_delimiter'], chunk_size=1024, max_read=1024000):
 return ReadTillNullByteAlt(fp, delimiter, chunk_size, max_read);

def ReadTillNullByte(fp, delimiter=__file_format_dict__['format_delimiter'], max_read=1024000):
 curfullbyte = bytearray();
 nullbyte = delimiter.encode("UTF-8");
 total_read = 0;  # Track the total number of bytes read
 while True:
  curbyte = fp.read(1);
  if curbyte == nullbyte or not curbyte:
   break;
  curfullbyte.extend(curbyte);
  total_read += 1;
  if total_read >= max_read:
   raise MemoryError("Maximum read limit reached without finding the delimiter.");
 # Decode the full byte array to string once out of the loop
 try:
  return curfullbyte.decode('UTF-8');
 except UnicodeDecodeError:
  # Handle potential partial UTF-8 characters
  for i in range(1, 4):
   try:
    return curfullbyte[:-i].decode('UTF-8');
   except UnicodeDecodeError:
    continue;
  raise;  # Re-raise if decoding fails even after trimming

def ReadUntilNullByte(fp, delimiter=__file_format_dict__['format_delimiter'], max_read=1024000):
 return ReadTillNullByte(fp, delimiter, max_read);

def ReadTillNullByteByNum(fp, delimiter=__file_format_dict__['format_delimiter'], num_delimiters=1, chunk_size=1024, max_read=1024000):
 delimiter = delimiter.encode('UTF-8');  # Ensure the delimiter is in bytes
 buffer = bytearray();
 total_read = 0;
 delimiter_length = len(delimiter);
 results = [];
 while len(results) < num_delimiters:
  chunk = fp.read(chunk_size);
  if not chunk:
   # End of file reached; decode whatever is collected if it's the last needed part
   if len(buffer) > 0:
    results.append(buffer.decode('UTF-8', errors='replace'));
   break;
  buffer.extend(chunk)
  total_read += len(chunk);
  # Check if we have found the delimiter
  while delimiter in buffer:
   index = buffer.find(delimiter);
   # Decode the section before the delimiter
   results.append(buffer[:index].decode('UTF-8', errors='replace'));
   # Remove the processed part from the buffer
   buffer = buffer[index + delimiter_length:];
   if len(results) == num_delimiters:
    # If reached the required number of delimiters, adjust the file pointer and stop
    fp.seek(-len(buffer), 1);
    return results;
  if total_read >= max_read:
   # Stop reading if max limit is reached to prevent excessive memory usage
   raise MemoryError("Maximum read limit reached without finding the delimiter.");
  # Check for incomplete UTF-8 sequences at the end of the buffer
  if len(buffer) > 1 and 128 <= buffer[-1] < 192:
   # This suggests that the last byte might be the start of a multi-byte character
   # Try to read one more byte to complete the character
   extra_byte = fp.read(1);
   if extra_byte:
    buffer.extend(extra_byte);
   else:
    # No more data available
    break;
 # Process remaining buffer if less than the required number of delimiters were found
 if len(buffer) > 0 and len(results) < num_delimiters:
  results.append(buffer.decode('UTF-8', errors='replace'));
 return results;

def ReadUntilNullByteByNum(fp, delimiter=__file_format_dict__['format_delimiter'], num_delimiters=1, chunk_size=1024, max_read=1024000):
 return ReadTillNullByteByNum(fp, delimiter, num_delimiters, chunk_size, max_read);

def SeekToEndOfFile(fp):
 lasttell = 0;
 while(True):
  fp.seek(1, 1);
  if(lasttell==fp.tell()):
   break;
  lasttell = fp.tell();
 return True;

def ReadFileHeaderData(fp, rounds=0, delimiter=__file_format_dict__['format_delimiter']):
 rocount = 0;
 roend = int(rounds);
 HeaderOut = [];
 while(rocount<roend):
  HeaderOut.append(ReadTillNullByte(fp, delimiter));
  rocount = rocount + 1;
 return HeaderOut;

def ReadFileHeaderDataBySize(fp, delimiter=__file_format_dict__['format_delimiter']):
 headerpresize = ReadTillNullByte(fp, delimiter);
 headersize = int(headerpresize, 16);
 if(headersize<=0):
  return [];
 headercontent = str(fp.read(headersize).decode('UTF-8')).split(delimiter);
 fp.seek(1, 1);
 rocount = 0;
 roend = int(len(headercontent));
 HeaderOut = [headerpresize];
 while(rocount<roend):
  HeaderOut.append(headercontent[rocount]);
  rocount = rocount + 1;
 return HeaderOut;

def ReadFileHeaderDataWoSize(fp, delimiter=__file_format_dict__['format_delimiter']):
 preheaderdata = ReadFileHeaderData(fp, 2, delimiter);
 headersize = int(preheaderdata[0], 16);
 headernumfields = int(preheaderdata[1], 16);
 if(headersize<=0 or headernumfields<=0):
  return [];
 headerdata = ReadTillNullByteByNum(fp, delimiter, headernumfields);
 #headerdata = ReadFileHeaderData(fp, headernumfields, delimiter);
 HeaderOut = preheaderdata + headerdata;
 return HeaderOut;

def ReadFileHeaderDataBySizeWithContent(fp, listonly=False, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__):
 formatspecs = FormatSpecsListToDict(formatspecs);
 delimiter = formatspecs['format_delimiter'];
 fheaderstart = fp.tell();
 HeaderOut = ReadFileHeaderDataBySize(fp, delimiter);
 if(len(HeaderOut)==0):
  return False;
 if(re.findall(r"^[.|/]", HeaderOut[3])):
  fname = HeaderOut[3];
 else:
  fname = "./"+HeaderOut[3];
 fcs = HeaderOut[-2].lower();
 fccs = HeaderOut[-1].lower();
 fsize = int(HeaderOut[5], 16);
 fcompression = HeaderOut[12];
 fcsize = int(HeaderOut[13], 16);
 fseeknextfile = HeaderOut[25];
 newfcs = GetHeaderChecksum(HeaderOut[:-2], HeaderOut[-4].lower(), True, formatspecs);
 if(fcs!=newfcs and not skipchecksum):
  VerbosePrintOut("File Header Checksum Error with file " + fname + " at offset " + str(fheaderstart));
  VerbosePrintOut("'" + str(fcs) + "' != " + "'" + str(newfcs) + "'");
  return False;
 fhend = fp.tell() - 1;
 fcontentstart = fp.tell();
 fcontents = BytesIO();
 if(fsize>0 and not listonly):
  if(fcompression=="none" or fcompression=="" or fcompression=="auto"):
   fcontents.write(fp.read(fsize));
  else:
   fcontents.write(fp.read(fcsize));
 elif(fsize>0 and listonly):
  if(fcompression=="none" or fcompression=="" or fcompression=="auto"):
   fp.seek(fsize, 1);
  else:
   fp.seek(fcsize, 1);
 fcontents.seek(0, 0);
 newfccs = GetFileChecksum(fcontents.read(), HeaderOut[-3].lower(), False, formatspecs);
 if(fccs!=newfccs and not skipchecksum and not listonly):
  VerbosePrintOut("File Content Checksum Error with file " + fname + " at offset " + str(fcontentstart));
  VerbosePrintOut("'" + str(fccs) + "' != " + "'" + str(newfccs) + "'");
  return False;
 if(fcompression=="none" or fcompression=="" or fcompression=="auto"):
  pass;
 else:
  fcontents.seek(0, 0);
  if(uncompress):
   fcontents = UncompressArchiveFile(fcontents, formatspecs);
 fcontentend = fp.tell();
 if(re.findall(r"^\+([0-9]+)", fseeknextfile)):
  fseeknextasnum = int(fseeknextfile.replace("+", ""));
  if(abs(fseeknextasnum)==0):
   pass;
  fp.seek(fseeknextasnum, 1);
 elif(re.findall(r"^\-([0-9]+)", fseeknextfile)):
  fseeknextasnum = int(fseeknextfile);
  if(abs(fseeknextasnum)==0):
   pass;
  fp.seek(fseeknextasnum, 1);
 elif(re.findall(r"^([0-9]+)", fseeknextfile)):
  fseeknextasnum = int(fseeknextfile);
  if(abs(fseeknextasnum)==0):
   pass;
  fp.seek(fseeknextasnum, 0);
 else:
  return False;
 HeaderOut.append(fcontents);
 return HeaderOut;

def ReadFileHeaderDataBySizeWithContentToArray(fp, listonly=False, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__):
 formatspecs = FormatSpecsListToDict(formatspecs);
 delimiter = formatspecs['format_delimiter'];
 fheaderstart = fp.tell();
 if(formatspecs['new_style']):
  HeaderOut = ReadFileHeaderDataBySize(fp, delimiter);
 else:
  HeaderOut = ReadFileHeaderDataWoSize(fp, delimiter);
 if(len(HeaderOut)==0):
  return False;
 fheadsize = int(HeaderOut[0], 16);
 fnumfields = int(HeaderOut[1], 16);
 ftype = int(HeaderOut[2], 16);
 if(re.findall(r"^[.|/]", HeaderOut[3])):
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
 fcompression = HeaderOut[12];
 fcsize = int(HeaderOut[13], 16);
 fuid = int(HeaderOut[14], 16);
 funame = HeaderOut[15];
 fgid = int(HeaderOut[16], 16);
 fgname = HeaderOut[17];
 fid = int(HeaderOut[18], 16);
 finode = int(HeaderOut[19], 16);
 flinkcount = int(HeaderOut[20], 16);
 fdev_minor = int(HeaderOut[21], 16);
 fdev_major = int(HeaderOut[22], 16);
 frdev_minor = int(HeaderOut[23], 16);
 frdev_major = int(HeaderOut[24], 16);
 fseeknextfile = HeaderOut[25];
 fextrasize = int(HeaderOut[26], 16);
 fextrafields = int(HeaderOut[27], 16);
 extrafieldslist = [];
 extrastart = 28
 extraend = extrastart + fextrafields;
 extrafieldslist = [];
 if(extrastart<extraend):
  extrafieldslist.append(HeaderOut[extrastart]);
  extrastart = extrastart + 1;
 fcs = HeaderOut[extrastart + 2].lower();
 fccs = HeaderOut[extrastart + 3].lower();
 newfcs = GetHeaderChecksum(HeaderOut[:-2], HeaderOut[-4].lower(), True, formatspecs);
 if(fcs!=newfcs and not skipchecksum):
  VerbosePrintOut("File Header Checksum Error with file " + fname + " at offset " + str(fheaderstart));
  VerbosePrintOut("'" + str(fcs) + "' != " + "'" + str(newfcs) + "'");
  return False;
 fhend = fp.tell() - 1;
 fcontentstart = fp.tell();
 fcontents = BytesIO();
 pyhascontents = False;
 if(fsize>0 and not listonly):
  if(fcompression=="none" or fcompression=="" or fcompression=="auto"):
   fcontents.write(fp.read(fsize));
  else:
   fcontents.write(fp.read(fcsize));
  pyhascontents = True;
 elif(fsize>0 and listonly):
  if(fcompression=="none" or fcompression=="" or fcompression=="auto"):
   fp.seek(fsize, 1);
  else:
   fp.seek(fcsize, 1);
  pyhascontents = False;
 fcontents.seek(0, 0);
 newfccs = GetFileChecksum(fcontents.read(), HeaderOut[-3].lower(), False, formatspecs);
 if(fccs!=newfccs and not skipchecksum and not listonly):
  VerbosePrintOut("File Content Checksum Error with file " + fname + " at offset " + str(fcontentstart));
  VerbosePrintOut("'" + str(fccs) + "' != " + "'" + str(newfccs) + "'");
  return False;
 if(fcompression=="none" or fcompression=="" or fcompression=="auto"):
  pass;
 else:
  fcontents.seek(0, 0);
  if(uncompress):
   fcontents = UncompressArchiveFile(fcontents, formatspecs);
   fcontents.seek(0, 0);
   fccs = GetFileChecksum(fcontents.read(), HeaderOut[-3].lower(), False, formatspecs);
 fcontentend = fp.tell() - 1;
 if(re.findall(r"^\+([0-9]+)", fseeknextfile)):
  fseeknextasnum = int(fseeknextfile.replace("+", ""));
  if(abs(fseeknextasnum)==0):
   pass;
  fp.seek(fseeknextasnum, 1);
 elif(re.findall(r"^\-([0-9]+)", fseeknextfile)):
  fseeknextasnum = int(fseeknextfile);
  if(abs(fseeknextasnum)==0):
   pass;
  fp.seek(fseeknextasnum, 1);
 elif(re.findall(r"^([0-9]+)", fseeknextfile)):
  fseeknextasnum = int(fseeknextfile);
  if(abs(fseeknextasnum)==0):
   pass;
  fp.seek(fseeknextasnum, 0);
 else:
  return False;
 fcontents.seek(0, 0);
 catlist = {'fheadersize': fheadsize, 'fhstart': fheaderstart, 'fhend': fhend, 'ftype': ftype, 'fname': fname, 'fbasedir': fbasedir, 'flinkname': flinkname, 'fsize': fsize, 'fatime': fatime, 'fmtime': fmtime, 'fctime': fctime, 'fbtime': fbtime, 'fmode': fmode, 'fchmode': fchmode, 'ftypemod': ftypemod, 'fwinattributes': fwinattributes, 'fcompression': fcompression, 'fcsize': fcsize, 'fuid': fuid, 'funame': funame, 'fgid': fgid, 'fgname': fgname, 'finode': finode, 'flinkcount': flinkcount, 'fminor': fdev_minor, 'fmajor': fdev_major, 'frminor': frdev_minor, 'frmajor': frdev_major, 'fseeknextfile': fseeknextfile, 'fheaderchecksumtype': HeaderOut[-4], 'fcontentchecksumtype': HeaderOut[-3], 'fnumfields': fnumfields + 2, 'frawheader': HeaderOut, 'fextrafields': fextrafields, 'fextrafieldsize': fextrasize, 'fextralist': extrafieldslist, 'fheaderchecksum': fcs, 'fcontentchecksum': fccs, 'fhascontents': pyhascontents, 'fcontentstart': fcontentstart, 'fcontentend': fcontentend, 'fcontents': fcontents};
 return catlist;

def ReadFileHeaderDataBySizeWithContentToList(fp, listonly=False, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__):
 formatspecs = FormatSpecsListToDict(formatspecs);
 delimiter = formatspecs['format_delimiter'];
 fheaderstart = fp.tell();
 if(formatspecs['new_style']):
  HeaderOut = ReadFileHeaderDataBySize(fp, delimiter);
 else:
  HeaderOut = ReadFileHeaderDataWoSize(fp, delimiter);
 if(len(HeaderOut)==0):
  return False;
 fheadsize = int(HeaderOut[0], 16);
 fnumfields = int(HeaderOut[1], 16);
 ftype = int(HeaderOut[2], 16);
 if(re.findall(r"^[.|/]", HeaderOut[3])):
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
 fcompression = HeaderOut[12];
 fcsize = int(HeaderOut[13], 16);
 fuid = int(HeaderOut[14], 16);
 funame = HeaderOut[15];
 fgid = int(HeaderOut[16], 16);
 fgname = HeaderOut[17];
 fid = int(HeaderOut[18], 16);
 finode = int(HeaderOut[19], 16);
 flinkcount = int(HeaderOut[20], 16);
 fdev_minor = int(HeaderOut[21], 16);
 fdev_major = int(HeaderOut[22], 16);
 frdev_minor = int(HeaderOut[23], 16);
 frdev_major = int(HeaderOut[24], 16);
 fseeknextfile = HeaderOut[25];
 fextrasize = int(HeaderOut[26], 16);
 fextrafields = int(HeaderOut[27], 16);
 extrafieldslist = [];
 extrastart = 28;
 extraend = extrastart + fextrafields;
 extrafieldslist = [];
 if(extrastart<extraend):
  extrafieldslist.append(HeaderOut[extrastart]);
  extrastart = extrastart + 1;
 fheaderchecksumtype = [extrastart].lower();
 fcontentchecksumtype = [extrastart + 1].lower();
 fcs = HeaderOut[extrastart + 2].lower();
 fccs = HeaderOut[extrastart + 3].lower();
 newfcs = GetHeaderChecksum(HeaderOut[:-2], HeaderOut[-4].lower(), True, formatspecs);
 if(fcs!=newfcs and not skipchecksum):
  VerbosePrintOut("File Header Checksum Error with file " + fname + " at offset " + str(fheaderstart));
  VerbosePrintOut("'" + str(fcs) + "' != " + "'" + str(newfcs) + "'");
  return False;
 fhend = fp.tell() - 1;
 fcontentstart = fp.tell();
 fcontents = BytesIO();
 pyhascontents = False;
 if(fsize>0 and not listonly):
  if(fcompression=="none" or fcompression=="" or fcompression=="auto"):
   fcontents.write(fp.read(fsize));
  else:
   fcontents.write(fp.read(fcsize));
  pyhascontents = True;
 elif(fsize>0 and listonly):
  if(fcompression=="none" or fcompression=="" or fcompression=="atuo"):
   fp.seek(fsize, 1);
  else:
   fp.seek(fcsize, 1);
  pyhascontents = False;
 fcontents.seek(0, 0);
 newfccs = GetFileChecksum(fcontents.read(), HeaderOut[-3].lower(), False, formatspecs);
 if(fccs!=newfccs and not skipchecksum and not listonly):
  VerbosePrintOut("File Content Checksum Error with file " + fname + " at offset " + str(fcontentstart));
  VerbosePrintOut("'" + str(fccs) + "' != " + "'" + str(newfccs) + "'");
  return False;
 if(fcompression=="none" or fcompression=="" or fcompression=="auto"):
  pass;
 else:
  fcontents.seek(0, 0);
  if(uncompress):
   fcontents = UncompressArchiveFile(fcontents, formatspecs);
   fcontents.seek(0, 0);
 fcontentend = fp.tell() - 1;
 if(re.findall(r"^\+([0-9]+)", fseeknextfile)):
  fseeknextasnum = int(fseeknextfile.replace("+", ""));
  if(abs(fseeknextasnum)==0):
   pass;
  fp.seek(fseeknextasnum, 1);
 elif(re.findall(r"^\-([0-9]+)", fseeknextfile)):
  fseeknextasnum = int(fseeknextfile);
  if(abs(fseeknextasnum)==0):
   pass;
  fp.seek(fseeknextasnum, 1);
 elif(re.findall(r"^([0-9]+)", fseeknextfile)):
  fseeknextasnum = int(fseeknextfile);
  if(abs(fseeknextasnum)==0):
   pass;
  fp.seek(fseeknextasnum, 0);
 else:
  return False;
 catlist = [ftype, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression, fcsize, fuid, funame, fgid, fgname, fid, finode, flinkcount, fdev_minor, fdev_major, frdev_minor, frdev_major, fseeknextfile, extrafieldslist, fheaderchecksumtype, fcontentchecksumtype, fcontents];
 return catlist;

def ReadFileDataBySizeWithContent(fp, listonly=False, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__):
 formatspecs = FormatSpecsListToDict(formatspecs);
 delimiter = formatspecs['format_delimiter'];
 curloc = fp.tell();
 if(curloc>0):
  fp.seek(0, 0);
 catheader = ReadFileHeaderData(fp, 4, delimiter);
 if(curloc>0):
  fp.seek(curloc, 0);
 headercheck = ValidateHeaderChecksum(catheader[:-1], catheader[2], catheader[3], formatspecs);
 newfcs = GetHeaderChecksum(catheader[:-2], catheader[2], True, formatspecs);
 if(not headercheck and not skipchecksum):
  VerbosePrintOut("File Header Checksum Error with file at offset " + str(0));
  VerbosePrintOut("'" + str(newfcs) + "' != " + "'" + str(catheader[3]) + "'");
  return False;
 fnumfiles = int(catheader[1], 16);
 countnum = 0;
 flist = [];
 while(countnum < fnumfiles):
  HeaderOut = ReadFileHeaderDataBySizeWithContent(fp, listonly, uncompress, skipchecksum, formatspecs)
  if(len(HeaderOut)==0):
   break;
  flist.append(HeaderOut);
  countnum = countnum + 1;
 return flist;

def ReadFileDataBySizeWithContentToArray(fp, seekstart=0, seekend=0, listonly=False, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__):
 formatspecs = FormatSpecsListToDict(formatspecs);
 delimiter = formatspecs['format_delimiter'];
 curloc = fp.tell();
 if(curloc>0):
  fp.seek(0, 0);
 catheader = ReadFileHeaderData(fp, 4, delimiter);
 if(curloc>0):
  fp.seek(curloc, 0);
 headercheck = ValidateHeaderChecksum(catheader[:-1], catheader[2], catheader[3], formatspecs);
 newfcs = GetHeaderChecksum(catheader[:-2], catheader[2], True, formatspecs);
 if(not headercheck and not skipchecksum):
  VerbosePrintOut("File Header Checksum Error with file at offset " + str(0));
  VerbosePrintOut("'" + str(newfcs) + "' != " + "'" + str(catheader[3]) + "'");
  return False;
 catstring = catheader[0];
 catversion = re.findall(r"([\d]+)", catstring);
 catversions = re.search(r'(.*?)(\d+)', catstring).groups();
 fprenumfiles = catheader[1];
 fnumfiles = int(fprenumfiles, 16);
 fprechecksumtype = catheader[2];
 fprechecksum = catheader[3];
 catlist = {'fnumfiles': fnumfiles, 'fformat': catversions[0], 'fversion': catversions[1], 'fformatspecs': formatspecs, 'fchecksumtype': fprechecksumtype, 'fheaderchecksum': fprechecksum, 'ffilelist': []};
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
   preheaderdata = ReadFileHeaderDataBySize(fp, formatspecs['format_delimiter']);
   if(len(preheaderdata)==0):
    break;
   prefsize = int(preheaderdata[5], 16);
   prefseeknextfile = preheaderdata[25];
   prenewfcs = GetHeaderChecksum(preheaderdata[:-2], preheaderdata[-4].lower(), True, formatspecs);
   prefcs = preheaderdata[-2];
   if(prefcs!=prenewfcs and not skipchecksum):
    VVerbosePrintOut("File Header Checksum Error with file " + prefname + " at offset " + str(prefhstart));
    VerbosePrintOut("'" + str(prefcs) + "' != " + "'" + str(prenewfcs) + "'");
    return False;
    valid_archive = False;
    invalid_archive = True;
   prefhend = fp.tell() - 1;
   prefcontentstart = fp.tell();
   prefcontents = BytesIO();
   pyhascontents = False;
   if(prefsize>0):
    prefcontents.write(fp.read(prefsize));
    prefcontents.seek(0, 0);
    prenewfccs = GetFileChecksum(prefcontents.read(), preheaderdata[-3].lower(), False, formatspecs);
    prefccs = preheaderdata[-1];
    pyhascontents = True;
    if(prefccs!=prenewfccs and not skipchecksum):
     VerbosePrintOut("File Content Checksum Error with file " + prefname + " at offset " + str(prefcontentstart));
     VerbosePrintOut("'" + str(prefccs) + "' != " + "'" + str(prenewfccs) + "'");
     return False;
   if(re.findall(r"^\+([0-9]+)", prefseeknextfile)):
    fseeknextasnum = int(prefseeknextfile.replace("+", ""));
    if(abs(fseeknextasnum)==0):
     pass;
    fp.seek(fseeknextasnum, 1);
   elif(re.findall(r"^\-([0-9]+)", prefseeknextfile)):
    fseeknextasnum = int(prefseeknextfile);
    if(abs(fseeknextasnum)==0):
     pass;
    fp.seek(fseeknextasnum, 1);
   elif(re.findall(r"^([0-9]+)", prefseeknextfile)):
    fseeknextasnum = int(prefseeknextfile);
    if(abs(fseeknextasnum)==0):
     pass;
    fp.seek(fseeknextasnum, 0);
   else:
    return False;
   il = il + 1;
 realidnum = 0;
 countnum = seekstart;
 while(countnum < seekend):
  HeaderOut = ReadFileHeaderDataBySizeWithContentToArray(fp, listonly, uncompress, skipchecksum, formatspecs);
  if(len(HeaderOut)==0):
   break;
  HeaderOut.update({'fid': realidnum, 'fidalt': realidnum});
  catlist['ffilelist'].append(HeaderOut);
  countnum = countnum + 1;
  realidnum = realidnum + 1;
 return catlist;

def ReadFileDataBySizeWithContentToList(fp, seekstart=0, seekend=0, listonly=False, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__):
 formatspecs = FormatSpecsListToDict(formatspecs);
 delimiter = formatspecs['format_delimiter'];
 curloc = fp.tell();
 if(curloc>0):
  fp.seek(0, 0);
 catheader = ReadFileHeaderData(fp, 4, delimiter);
 if(curloc>0):
  fp.seek(curloc, 0);
 headercheck = ValidateHeaderChecksum(catheader[:-1], catheader[2], catheader[3], formatspecs);
 newfcs = GetHeaderChecksum(catheader[:-2], catheader[2], True, formatspecs);
 if(not headercheck and not skipchecksum):
  VerbosePrintOut("File Header Checksum Error with file at offset " + str(0));
  VerbosePrintOut("'" + str(newfcs) + "' != " + "'" + str(catheader[3]) + "'");
  return False;
 catstring = catheader[0];
 catversion = re.findall(r"([\d]+)", catstring);
 catversions = re.search(r'(.*?)(\d+)', catstring).groups();
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
   preheaderdata = ReadFileHeaderDataBySize(fp, formatspecs['format_delimiter']);
   if(len(preheaderdata)==0):
    break;
   prefsize = int(preheaderdata[5], 16);
   prefcompression = preheaderdata[12];
   prefcsize = int(preheaderdata[13], 16);
   prefseeknextfile = HeaderOut[25];
   prenewfcs = GetHeaderChecksum(preheaderdata[:-2], preheaderdata[-4].lower(), True, formatspecs);
   prefcs = preheaderdata[-2];
   if(prefcs!=prenewfcs and not skipchecksum):
    VerbosePrintOut("File Header Checksum Error with file " + prefname + " at offset " + str(prefhstart));
    VerbosePrintOut("'" + str(prefcs) + "' != " + "'" + str(prenewfcs) + "'");
    return False;
    valid_archive = False;
    invalid_archive = True;
   prefhend = fp.tell() - 1;
   prefcontentstart = fp.tell();
   prefcontents = "";
   pyhascontents = False;
   if(prefsize>0):
    if(prefcompression=="none" or prefcompression=="" or prefcompression=="auto"):
     prefcontents = catfp.read(prefsize);
    else:
     prefcontents = catfp.read(prefcsize);
    prenewfccs = GetFileChecksum(prefcontents, preheaderdata[-3].lower(), False, formatspecs);
    prefccs = preheaderdata[-1];
    pyhascontents = True;
    if(prefccs!=prenewfccs and not skipchecksum):
     VerbosePrintOut("File Content Checksum Error with file " + prefname + " at offset " + str(prefcontentstart));
     VerbosePrintOut("'" + str(prefccs) + "' != " + "'" + str(prenewfccs) + "'");
     return False;
   if(re.findall(r"^\+([0-9]+)", prefseeknextfile)):
    fseeknextasnum = int(prefseeknextfile.replace("+", ""));
    if(abs(fseeknextasnum)==0):
     pass;
    catfp.seek(fseeknextasnum, 1);
   elif(re.findall(r"^\-([0-9]+)", prefseeknextfile)):
    fseeknextasnum = int(prefseeknextfile);
    if(abs(fseeknextasnum)==0):
     pass;
    catfp.seek(fseeknextasnum, 1);
   elif(re.findall(r"^([0-9]+)", prefseeknextfile)):
    fseeknextasnum = int(prefseeknextfile);
    if(abs(fseeknextasnum)==0):
     pass;
    catfp.seek(fseeknextasnum, 0);
   else:
    return False;
   il = il + 1;
 realidnum = 0;
 countnum = seekstart;
 while(countnum < seekend):
  HeaderOut = ReadFileHeaderDataBySizeWithContentToList(fp, listonly, uncompress, skipchecksum, formatspecs);
  if(len(HeaderOut)==0):
   break;
  catlist.append(HeaderOut);
  countnum = countnum + 1;
  realidnum = realidnum + 1;
 return catlist;

def ReadInFileBySizeWithContentToArray(infile, listonly=False, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__):
 formatspecs = FormatSpecsListToDict(formatspecs);
 delimiter = formatspecs['format_delimiter'];
 if(hasattr(infile, "read") or hasattr(infile, "write")):
  fp = infile;
  fp.seek(0, 0);
  fp = UncompressArchiveFile(fp, formatspecs);
  checkcompressfile = CheckCompressionSubType(fp, formatspecs, True);
  if(checkcompressfile!="catfile" and checkcompressfile!=formatspecs['format_lower']):
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
  checkcompressfile = CheckCompressionSubType(infile, formatspecs, True);
  if(checkcompressfile!="catfile" and checkcompressfile!=formatspecs['format_lower']):
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
 return ReadFileDataBySizeWithContentToArray(fp, listonly, uncompress, skipchecksum, formatspecs);

def ReadInFileBySizeWithContentToList(infile, seekstart=0, seekend=0, listonly=False, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__):
 formatspecs = FormatSpecsListToDict(formatspecs);
 delimiter = formatspecs['format_delimiter'];
 if(hasattr(infile, "read") or hasattr(infile, "write")):
  fp = infile;
  fp.seek(0, 0);
  fp = UncompressArchiveFile(fp, formatspecs);
  checkcompressfile = CheckCompressionSubType(fp, formatspecs, True);
  if(checkcompressfile!="catfile" and checkcompressfile!=formatspecs['format_lower']):
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
  checkcompressfile = CheckCompressionSubType(infile, formatspecs, True);
  if(checkcompressfile!="catfile" and checkcompressfile!=formatspecs['format_lower']):
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
 return ReadFileDataBySizeWithContentToList(fp, seekstart, seekend, listonly, uncompress, skipchecksum, formatspecs);

def AppendNullByte(indata, delimiter=__file_format_dict__['format_delimiter']):
 outdata = str(indata) + delimiter;
 return outdata;

def AppendNullBytes(indata=[], delimiter=__file_format_dict__['format_delimiter']):
 outdata = "";
 inum = 0;
 il = len(indata);
 while(inum < il):
  outdata = outdata + AppendNullByte(indata[inum], delimiter);
  inum = inum + 1;
 return outdata;

def AppendFileHeader(fp, numfiles, checksumtype="crc32", formatspecs=__file_format_dict__):
 formatspecs = FormatSpecsListToDict(formatspecs);
 delimiter = formatspecs['format_delimiter'];
 catver = formatspecs['format_ver'];
 fileheaderver = str(int(catver.replace(".", "")));
 fileheader = AppendNullByte(formatspecs['format_magic'] + fileheaderver, formatspecs['format_delimiter']);
 fp.write(fileheader.encode('UTF-8'));
 fnumfiles = format(int(numfiles), 'x').lower();
 fnumfilesa = AppendNullBytes([fnumfiles, checksumtype], formatspecs['format_delimiter']);
 catfileheadercshex = GetFileChecksum(fileheader + fnumfilesa, checksumtype, True, formatspecs);
 fnumfilesa = fnumfilesa + AppendNullByte(catfileheadercshex, formatspecs['format_delimiter']);
 fp.write(fnumfilesa.encode('UTF-8'));
 try:
  fp.flush();
  os.fsync(fp.fileno());
 except io.UnsupportedOperation:
  pass;
 except AttributeError:
  pass;
 except OSError as e:
  pass;
 return fp;

def MakeEmptyFilePointer(fp, checksumtype="crc32", formatspecs=__file_format_dict__):
 formatspecs = FormatSpecsListToDict(formatspecs);
 AppendFileHeader(fp, 0, checksumtype, formatspecs);
 return fp;

def MakeEmptyFile(outfile, compression="auto", compressionlevel=None, checksumtype="crc32", formatspecs=__file_format_dict__, returnfp=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 if(outfile!="-" and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
  if(os.path.exists(outfile)):
   try:
    os.unlink(outfile);
   except OSError as e:
    pass;
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
  catfp = CompressOpenFile(outfile, True, compressionlevel);
 catfp = AppendFileHeader(catfp, 0, checksumtype, formatspecs);
 if(outfile=="-" or hasattr(outfile, "read") or hasattr(outfile, "write")):
  catfp = CompressArchiveFile(catfp, compression, compressionlevel, formatspecs);
  try:
   catfp.flush();
   os.fsync(catfp.fileno());
  except io.UnsupportedOperation:
   pass;
  except AttributeError:
   pass;
  except OSError as e:
   pass;
 if(outfile=="-"):
  catfp.seek(0, 0);
  if(hasattr(sys.stdout, "buffer")):
   shutil.copyfileobj(catfp, sys.stdout.buffer);
  else:
   shutil.copyfileobj(catfp, sys.stdout);
 elif(re.findall(r"^(ftp|ftps|sftp)\:\/\/", str(outfile))):
  catfp = CompressArchiveFile(catfp, compression, compressionlevel, formatspecs);
  catfp.seek(0, 0);
  upload_file_to_internet_file(catfp, outfile);
 if(returnfp):
  catfp.seek(0, 0);
  return catfp;
 else:
  catfp.close();
  return True;

def AppendFileHeaderWithContent(fp, filevalues=[], extradata=[], filecontent="", checksumtype="crc32", formatspecs=__file_format_dict__):
 formatspecs = FormatSpecsListToDict(formatspecs);
 extrafields = format(len(extradata), 'x').lower();
 extrasizestr = AppendNullByte(extrafields, formatspecs['format_delimiter']);
 if(len(extradata)>0):
  extrasizestr = extrasizestr + AppendNullBytes(extradata, formatspecs['format_delimiter']);
 extrasizelen = format(len(extrasizestr), 'x').lower();
 catoutlen = len(filevalues) + len(extradata) + 5;
 catoutlenhex = format(catoutlen, 'x').lower();
 catoutlist = filevalues;
 catoutlist.insert(0, catoutlenhex);
 catoutlist.append(extrasizelen);
 catoutlist.append(extrafields);
 catfileoutstr = AppendNullBytes(catoutlist, formatspecs['format_delimiter']);
 if(len(extradata)>0):
  catfileoutstr = catfileoutstr + AppendNullBytes(extradata, formatspecs['format_delimiter']);
 catfileoutstr = catfileoutstr + AppendNullBytes([checksumtype, checksumtype], formatspecs['format_delimiter']);
 catfileheadercshex = GetFileChecksum(catfileoutstr, checksumtype, True, formatspecs);
 catfilecontentcshex = GetFileChecksum(filecontent, checksumtype, False, formatspecs);
 tmpfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex], formatspecs['format_delimiter']);
 catheaersize = format(int(len(tmpfileoutstr) - 1), 'x').lower();
 catfileoutstr = AppendNullByte(catheaersize, formatspecs['format_delimiter']) + catfileoutstr;
 catfileheadercshex = GetFileChecksum(catfileoutstr, checksumtype, True, formatspecs);
 catfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex], formatspecs['format_delimiter']);
 catfileoutstrecd = catfileoutstr.encode('UTF-8');
 nullstrecd = formatspecs['format_delimiter'].encode('UTF-8');
 catfileout = catfileoutstrecd + filecontent + nullstrecd;
 fp.write(catfileout);
 try:
  fp.flush();
  os.fsync(fp.fileno());
 except io.UnsupportedOperation:
  pass;
 except AttributeError:
  pass;
 except OSError as e:
  pass;
 return fp;

def AppendFilesWithContent(infiles, fp, dirlistfromtxt=False, filevalues=[], extradata=[], compression="auto", compresswholefile=True, compressionlevel=None, followlink=False, checksumtype="crc32", formatspecs=__file_format_dict__, verbose=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 advancedlist = formatspecs['use_advanced_list'];
 altinode = formatspecs['use_alt_inode'];
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
 numfiles = int(len(GetDirList));
 fnumfiles = format(numfiles, 'x').lower();
 AppendFileHeader(fp, fnumfiles, checksumtype, formatspecs);
 for curfname in GetDirList:
  if(re.findall(r"^[.|/]", curfname)):
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
  fcurfid = format(int(curfid), 'x').lower();
  if(not followlink and finode!=0):
   if(ftype!=1):
    if(finode in inodelist):
     ftype = 1;
     flinkname = inodetofile[finode];
     if(altinode):
      fcurinode = format(int(finode), 'x').lower();
     else:
      fcurinode = format(int(inodetocatinode[finode]), 'x').lower();
    if(finode not in inodelist):
     inodelist.append(finode);
     inodetofile.update({finode: fname});
     inodetocatinode.update({finode: curinode});
     if(altinode):
      fcurinode = format(int(finode), 'x').lower();
     else:
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
  fcompression = "";
  fcsize = format(int(0), 'x').lower();
  fcontents = BytesIO();
  chunk_size = 1024;
  if(ftype==0 or ftype==7):
   with open(fname, "rb") as fpc:
    shutil.copyfileobj(fpc, fcontents);
    if(not compresswholefile):
     fcontents.seek(0, 2);
     ucfsize = fcontents.tell();
     fcontents.seek(0, 0);
     if(compression=="auto"):
      ilsize = len(compressionlistalt);
      ilmin = 0;
      ilcsize = [];
      while(ilmin < ilsize):
       cfcontents = BytesIO();
       shutil.copyfileobj(fcontents, cfcontents);
       fcontents.seek(0, 0);
       cfcontents.seek(0, 0);
       cfcontents = CompressArchiveFile(cfcontents, compressionlistalt[ilmin], compressionlevel, formatspecs);
       if(cfcontents):
        cfcontents.seek(0, 2);
        ilcsize.append(cfcontents.tell());
        cfcontents.close();
       else:
        try:
         ilcsize.append(sys.maxint);
        except AttributeError:
         ilcsize.append(sys.maxsize);
       ilmin = ilmin + 1;
      ilcmin = ilcsize.index(min(ilcsize));
      compression = compressionlistalt[ilcmin];
     fcontents.seek(0, 0);
     cfcontents = BytesIO();
     shutil.copyfileobj(fcontents, cfcontents);
     cfcontents.seek(0, 0);
     cfcontents = CompressArchiveFile(cfcontents, compression, compressionlevel, formatspecs);
     cfcontents.seek(0, 2);
     cfsize = cfcontents.tell();
     if(ucfsize > cfsize):
      fcsize = format(int(cfsize), 'x').lower();
      fcompression = compression;
      fcontents.close();
      fcontents = cfcontents;
  if(followlink and (ftype==1 or ftype==2)):
   flstatinfo = os.stat(flinkname);
   with open(flinkname, "rb") as fpc:
    shutil.copyfileobj(fpc, fcontents);
    if(not compresswholefile):
     fcontents.seek(0, 2);
     ucfsize = fcontents.tell();
     fcontents.seek(0, 0);
     if(compression=="auto"):
      ilsize = len(compressionlistalt);
      ilmin = 0;
      ilcsize = [];
      while(ilmin < ilsize):
       cfcontents = BytesIO();
       shutil.copyfileobj(fcontents, cfcontents);
       fcontents.seek(0, 0);
       cfcontents.seek(0, 0);
       cfcontents = CompressArchiveFile(cfcontents, compressionlistalt[ilmin], compressionlevel, formatspecs);
       if(cfcontents):
        cfcontents.seek(0, 2);
        ilcsize.append(cfcontents.tell());
        cfcontents.close();
       else:
        try:
         ilcsize.append(sys.maxint);
        except AttributeError:
         ilcsize.append(sys.maxsize);
       ilmin = ilmin + 1;
      ilcmin = ilcsize.index(min(ilcsize));
      compression = compressionlistalt[ilcmin];
     fcontents.seek(0, 0);
     cfcontents = BytesIO();
     shutil.copyfileobj(fcontents, cfcontents);
     cfcontents.seek(0, 0);
     cfcontents = CompressArchiveFile(cfcontents, compression, compressionlevel, formatspecs);
     cfcontents.seek(0, 2);
     cfsize = cfcontents.tell();
     if(ucfsize > cfsize):
      fcsize = format(int(cfsize), 'x').lower();
      fcompression = compression;
      fcontents.close();
      fcontents = cfcontents;
  if(fcompression=="none"):
   fcompression = "";
  fcontents.seek(0, 0);
  ftypehex = format(ftype, 'x').lower();
  catoutlist = [ftypehex, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression, fcsize, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev_minor, fdev_major, frdev_minor, frdev_major, "+1"];
  fp = AppendFileHeaderWithContent(fp, catoutlist, extradata, fcontents.read(), checksumtype, formatspecs);
 if(numfiles>0):
  catfp.write(AppendNullBytes([0, 0], formatspecs['format_delimiter']).encode("UTF-8"));
 fp.seek(0, 0);
 return fp;

def AppendListsWithContent(inlist, fp, dirlistfromtxt=False, filevalues=[], extradata=[], compression="auto", compresswholefile=True, compressionlevel=None, followlink=False, checksumtype="crc32", formatspecs=__file_format_dict__, verbose=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
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
 numfiles = int(len(GetDirList));
 fnumfiles = format(numfiles, 'x').lower();
 AppendFileHeader(fp, fnumfiles, checksumtype, formatspecs);
 for curfname in GetDirList:
  ftype = format(curfname[0], 'x').lower();
  if(re.findall(r"^[.|/]", curfname[1])):
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
  fcompression = curfname[10];
  fcsize = format(curfname[11], 'x').lower();
  fuid = format(curfname[12], 'x').lower();
  funame = curfname[13];
  fgid = format(curfname[14], 'x').lower();
  fgname = curfname[15];
  fid = format(curfname[16], 'x').lower();
  finode = format(curfname[17], 'x').lower();
  flinkcount = format(curfname[18], 'x').lower();
  fdev_minor = format(curfname[19], 'x').lower();
  fdev_major = format(curfname[20], 'x').lower();
  frdev_minor = format(curfname[21], 'x').lower();
  frdev_major = format(curfname[22], 'x').lower();
  fseeknextfile = curfname[23];
  extradata = curfname[24];
  fheaderchecksumtype = curfname[25];
  fcontentchecksumtype = curfname[26];
  fcontents = curfname[27];
  catoutlist = [ftype, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression, fcsize, fuid, funame, fgid, fgname, fid, finode, flinkcount, fdev_minor, fdev_major, frdev_minor, frdev_major, fseeknextfile];
  fcontents.seek(0, 0);
  fp = AppendFileHeaderWithContent(fp, catoutlist, extradata, fcontents.read(), checksumtype, formatspecs);
 if(numfiles>0):
  fp.write(AppendNullBytes([0, 0], formatspecs['format_delimiter']).encode("UTF-8"));
 return fp;

def AppendInFileWithContent(infile, fp, dirlistfromtxt=False, filevalues=[], extradata=[], followlink=False, checksumtype="crc32", formatspecs=__file_format_dict__, verbose=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 inlist = ReadInFileBySizeWithContentToList(infile, 0, 0, False, True, False, formatspecs);
 return AppendListsWithContent(inlist, fp, dirlistfromtxt, filevalues, extradata, followlink, checksumtype, formatspecs, verbose);

def AppendFilesWithContentToOutFile(infiles, outfile, dirlistfromtxt=False, compression="auto", compresswholefile=True, compressionlevel=None, filevalues=[], extradata=[], followlink=False, checksumtype="crc32", formatspecs=__file_format_dict__, verbose=False, returnfp=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 if(outfile!="-" and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
  if(os.path.exists(outfile)):
   try:
    os.unlink(outfile);
   except OSError as e:
    pass;
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
  catfp = CompressOpenFile(outfile, compresswholefile, compressionlevel);
 catfp = AppendFilesWithContent(infiles, catfp, dirlistfromtxt, filevalues, extradata, compression, compresswholefile, compressionlevel, followlink, checksumtype, formatspecs, verbose);
 if(outfile=="-" or hasattr(outfile, "read") or hasattr(outfile, "write")):
  catfp = CompressArchiveFile(catfp, compression, compressionlevel, formatspecs);
  try:
   catfp.flush();
   os.fsync(catfp.fileno());
  except io.UnsupportedOperation:
   pass;
  except AttributeError:
   pass;
  except OSError as e:
   pass;
 if(outfile=="-"):
  catfp.seek(0, 0);
  if(hasattr(sys.stdout, "buffer")):
   shutil.copyfileobj(catfp, sys.stdout.buffer);
  else:
   shutil.copyfileobj(catfp, sys.stdout);
 elif(re.findall(r"^(ftp|ftps|sftp)\:\/\/", str(outfile))):
  catfp = CompressArchiveFile(catfp, compression, compressionlevel, formatspecs);
  catfp.seek(0, 0);
  upload_file_to_internet_file(catfp, outfile);
 if(returnfp):
  catfp.seek(0, 0);
  return catfp;
 else:
  catfp.close();
  return True;

def AppendListsWithContentToOutFile(inlist, outfile, dirlistfromtxt=False, compression="auto", compresswholefile=True, compressionlevel=None, filevalues=[], extradata=[], followlink=False, checksumtype="crc32", formatspecs=__file_format_dict__, verbose=False, returnfp=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 if(outfile!="-" and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
  if(os.path.exists(outfile)):
   try:
    os.unlink(outfile);
   except OSError as e:
    pass;
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
  catfp = CompressOpenFile(outfile, compresswholefile, compressionlevel);
 catfp = AppendListsWithContent(inlist, catfp, dirlistfromtxt, filevalues, extradata, compression, compresswholefile, compressionlevel, followlink, checksumtype, formatspecs, verbose);
 if(outfile=="-" or hasattr(outfile, "read") or hasattr(outfile, "write")):
  catfp = CompressArchiveFile(catfp, compression, compressionlevel, formatspecs);
  try:
   catfp.flush();
   os.fsync(catfp.fileno());
  except io.UnsupportedOperation:
   pass;
  except AttributeError:
   pass;
  except OSError as e:
   pass;
 if(outfile=="-"):
  catfp.seek(0, 0);
  if(hasattr(sys.stdout, "buffer")):
   shutil.copyfileobj(catfp, sys.stdout.buffer);
  else:
   shutil.copyfileobj(catfp, sys.stdout);
 elif(re.findall(r"^(ftp|ftps|sftp)\:\/\/", str(outfile))):
  catfp = CompressArchiveFile(catfp, compression, compressionlevel, formatspecs);
  catfp.seek(0, 0);
  upload_file_to_internet_file(catfp, outfile);
 if(returnfp):
  catfp.seek(0, 0);
  return catfp;
 else:
  catfp.close();
  return True;

def AppendInFileWithContentToOutFile(infile, outfile, dirlistfromtxt=False, compression="auto", compresswholefile=True, compressionlevel=None, filevalues=[], extradata=[], followlink=False, checksumtype="crc32", formatspecs=__file_format_dict__, verbose=False, returnfp=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 inlist = ReadInFileBySizeWithContentToList(infile, 0, 0, False, True, False, formatspecs);
 return AppendListsWithContentToOutFile(inlist, outfile, dirlistfromtxt, compression, compresswholefile, compressionlevel, filevalues, extradata, followlink, checksumtype, formatspecs, verbose, returnfp);

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

def CheckCompressionType(infile, formatspecs=__file_format_dict__, closefp=True):
 formatspecs = FormatSpecsListToDict(formatspecs);
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
 if(prefp==binascii.unhexlify("377abcaf271c")):
  filetype = "7zipfile";
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
 prefp = catfp.read(formatspecs['format_len']);
 if(prefp==binascii.unhexlify(formatspecs['format_hex'])):
  filetype = formatspecs['format_lower'];
 catfp.seek(0, 0);
 prefp = catfp.read(9);
 if(prefp==binascii.unhexlify("894c5a4f000d0a1a0a")):
  filetype = "lzo";
 catfp.seek(0, 0);
 prefp = catfp.read(10);
 if(prefp==binascii.unhexlify("7061785f676c6f62616c")):
  filetype = "tarfile";
 catfp.seek(0, 0);
 if(filetype=="gzip" or filetype=="bzip2" or filetype=="lzma" or filetype=="zstd" or filetype=="lz4"):
  if(TarFileCheck(catfp)):
   filetype = "tarfile";
 if(not filetype):
  if(TarFileCheck(catfp)):
   filetype = "tarfile";
  elif(zipfile.is_zipfile(catfp)):
   filetype = "zipfile";
  elif(rarfile.is_rarfile(catfp) or rarfile.is_rarfile_sfx(catfp)):
   filetype = "rarile";
  else:
   filetype = False;
 catfp.seek(0, 0);
 if(closefp):
  catfp.close();
 return filetype;

def CheckCompressionTypeFromString(instring, formatspecs=__file_format_dict__, closefp=True):
 formatspecs = FormatSpecsListToDict(formatspecs);
 try:
  instringsfile = BytesIO(instring);
 except TypeError:
  instringsfile = BytesIO(instring.encode("UTF-8"));
 return CheckCompressionType(instringsfile, formatspecs, closefp);

def GetCompressionMimeType(infile, formatspecs=__file_format_dict__):
 formatspecs = FormatSpecsListToDict(formatspecs);
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
 if(compresscheck=="catfile" or compresscheck=="cat" or compresscheck==formatspecs['format_lower']):
  return archivefile_cat_mimetype;
 if(not compresscheck):
  return False;
 return False;

def UncompressArchiveFile(fp, formatspecs=__file_format_dict__):
 formatspecs = FormatSpecsListToDict(formatspecs);
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
   try:
    from backports import lzma
   except ImportError:
    return False;
  catfp = BytesIO();
  catfp.write(lzma.decompress(fp.read()));
 if(compresscheck=="catfile" or compresscheck==formatspecs['format_lower']):
  catfp = fp;
 if(not compresscheck):
  try:
   import lzma;
  except ImportError:
   try:
    from backports import lzma
   except ImportError:
    return False;
  catfp = BytesIO();
  with fp as fpcontent:
   try:
    catfp.write(lzma.decompress(fp.read()));
   except lzma.LZMAError:
    return False;
  if(compresscheck!="catfile" or compresscheck!=formatspecs['format_lower']):
   fp.close();
 return catfp;

create_alias_function("Uncompress", __file_format_name__, "", UncompressArchiveFile);

def UncompressFile(infile, formatspecs=__file_format_dict__, mode="rb"):
 formatspecs = FormatSpecsListToDict(formatspecs);
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
    try:
     from backports import lzma
    except ImportError:
     return False;
   try:
    filefp = lzma.open(infile, mode, encoding="UTF-8");
   except (ValueError, TypeError) as e:
    filefp = lzma.open(infile, mode);
  if(compresscheck=="catfile" or compresscheck==formatspecs['format_lower']):
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
   try:
    from backports import lzma
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

def CheckCompressionSubType(infile, formatspecs=__file_format_dict__, closefp=True):
 formatspecs = FormatSpecsListToDict(formatspecs);
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
 if(compresscheck=="gzip" or compresscheck=="bzip2" or compresscheck=="lzma" or compresscheck=="zstd" or compresscheck=="lz4"):
  if(TarFileCheck(infile)):
   filetype = "tarfile";
 if(not compresscheck):
  if(TarFileCheck(infile)):
   return "tarfile";
  elif(zipfile.is_zipfile(infile)):
   return "zipfile";
  elif(rarfile.is_rarfile(infile) or rarfile.is_rarfile_sfx(infile)):
   return "rarile";
  else:
   return False;
  return False;
 if(compresscheck=="catfile"):
  return "catfile";
 if(compresscheck==formatspecs['format_lower']):
  return formatspecs['format_lower'];
 if(compresscheck=="tarfile"):
  return "tarfile";
 if(compresscheck=="zipfile"):
  return "zipfile";
 if(rarfile_support and compresscheck=="rarfile"):
  return "rarfile";
 if(py7zr_support and compresscheck=="7zipfile"):
  return "7zipfile";
 if(hasattr(infile, "read") or hasattr(infile, "write")):
  catfp = UncompressArchiveFile(infile, formatspecs['format_lower']);
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
     try:
      from backports import lzma
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
 prefp = catfp.read(formatspecs['format_len']);
 if(prefp==binascii.unhexlify(formatspecs['format_hex'])):
  filetype = formatspecs['format_lower'];
 catfp.seek(0, 0);
 prefp = catfp.read(10);
 if(prefp==binascii.unhexlify("7061785f676c6f62616c")):
  filetype = "tarfile";
 catfp.seek(0, 0);
 if(closefp):
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

def CompressArchiveFile(fp, compression="auto", compressionlevel=None, formatspecs=__file_format_dict__):
 formatspecs = FormatSpecsListToDict(formatspecs);
 if(not hasattr(fp, "read") and not hasattr(fp, "write")):
  return False;
 fp.seek(0, 0);
 if(not compression or compression=="catfile" or compression==formatspecs['format_lower']):
  compression = "auto";
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
   try:
    from backports import lzma
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
   try:
    from backports import lzma
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

def CompressOpenFile(outfile, compressionenable=True, compressionlevel=None):
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
  if(fextname not in outextlistwd or not compressionenable):
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
    try:
     from backports import lzma
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
    try:
     from backports import lzma
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
  try:
   hash_list = sorted(list(hashlib.algorithms_guaranteed));
  except AttributeError:
   hash_list = sorted(list(hashlib.algorithms));
 else:
  try:
   hash_list = sorted(list(hashlib.algorithms_available));
  except AttributeError:
   hash_list = sorted(list(hashlib.algorithms));
 checklistout = sorted(hash_list + ['adler32', 'crc16', 'crc16_ansi', 'crc16_ibm', 'crc16_ccitt', 'crc32', 'crc64', 'crc64_ecma', 'crc64_iso', 'none']);
 if(checkfor in checklistout):
  return True;
 else:
  return False;

def CheckSumSupportAlt(checkfor, guaranteed=True):
 if(guaranteed):
  try:
   hash_list = sorted(list(hashlib.algorithms_guaranteed));
  except AttributeError:
   hash_list = sorted(list(hashlib.algorithms));
 else:
  try:
   hash_list = sorted(list(hashlib.algorithms_available));
  except AttributeError:
   hash_list = sorted(list(hashlib.algorithms));
 checklistout = hash_list;
 if(checkfor in checklistout):
  return True;
 else:
  return False;

def PackArchiveFile(infiles, outfile, dirlistfromtxt=False, compression="auto", compresswholefile=True, compressionlevel=None, followlink=False, checksumtype="crc32", extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 advancedlist = formatspecs['use_advanced_list'];
 altinode = formatspecs['use_alt_inode'];
 if(outfile!="-" and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
  outfile = RemoveWindowsPath(outfile);
 checksumtype = checksumtype.lower();
 if(not CheckSumSupport(checksumtype, hashlib_guaranteed)):
  checksumtype="crc32";
 if(checksumtype=="none"):
  checksumtype = "";
 if(not compression or compression=="catfile" or compression==formatspecs['format_lower']):
  compression = "auto";
 if(compression not in compressionlist and compression is None):
  compression = "auto";
 if(verbose):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(outfile!="-" and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
  if(os.path.exists(outfile)):
   try:
    os.unlink(outfile);
   except OSError as e:
    pass;
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
  catfp = CompressOpenFile(outfile, compresswholefile, compressionlevel);
 catver = formatspecs['format_ver'];
 fileheaderver = str(int(catver.replace(".", "")));
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
 numfiles = int(len(GetDirList));
 catfp = AppendFileHeader(catfp, numfiles, checksumtype, formatspecs);
 for curfname in GetDirList:
  if(re.findall(r"^[.|/]", curfname)):
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
  fcurfid = format(int(curfid), 'x').lower();
  if(not followlink and finode!=0):
   if(ftype!=1):
    if(finode in inodelist):
     ftype = 1;
     flinkname = inodetofile[finode];
     if(altinode):
      fcurinode = format(int(finode), 'x').lower();
     else:
      fcurinode = format(int(inodetocatinode[finode]), 'x').lower();
    if(finode not in inodelist):
     inodelist.append(finode);
     inodetofile.update({finode: fname});
     inodetocatinode.update({finode: curinode});
     if(altinode):
      fcurinode = format(int(finode), 'x').lower();
     else:
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
  fcompression = "";
  fcsize = format(int(0), 'x').lower();
  fcontents = BytesIO();
  if(ftype==0 or ftype==7):
   with open(fname, "rb") as fpc:
    shutil.copyfileobj(fpc, fcontents);
    if(not compresswholefile):
     fcontents.seek(0, 2);
     ucfsize = fcontents.tell();
     fcontents.seek(0, 0);
     if(compression=="auto"):
      ilsize = len(compressionlistalt);
      ilmin = 0;
      ilcsize = [];
      while(ilmin < ilsize):
       cfcontents = BytesIO();
       shutil.copyfileobj(fcontents, cfcontents);
       fcontents.seek(0, 0);
       cfcontents.seek(0, 0);
       cfcontents = CompressArchiveFile(cfcontents, compressionlistalt[ilmin], compressionlevel, formatspecs);
       if(cfcontents):
        cfcontents.seek(0, 2);
        ilcsize.append(cfcontents.tell());
        cfcontents.close();
       else:
        try:
         ilcsize.append(sys.maxint);
        except AttributeError:
         ilcsize.append(sys.maxsize);
       ilmin = ilmin + 1;
      ilcmin = ilcsize.index(min(ilcsize));
      compression = compressionlistalt[ilcmin];
     fcontents.seek(0, 0);
     cfcontents = BytesIO();
     shutil.copyfileobj(fcontents, cfcontents);
     cfcontents.seek(0, 0);
     cfcontents = CompressArchiveFile(cfcontents, compression, compressionlevel, formatspecs);
     cfcontents.seek(0, 2);
     cfsize = cfcontents.tell();
     if(ucfsize > cfsize):
      fcsize = format(int(cfsize), 'x').lower();
      fcompression = compression;
      fcontents.close();
      fcontents = cfcontents;
  if(fcompression=="none"):
   fcompression = "";
  if(followlink and (ftype==1 or ftype==2)):
   flstatinfo = os.stat(flinkname);
   with open(flinkname, "rb") as fpc:
    shutil.copyfileobj(fpc, fcontents);
    if(not compresswholefile):
     fcontents.seek(0, 2);
     ucfsize = fcontents.tell();
     fcontents.seek(0, 0);
     if(compression=="auto"):
      ilsize = len(compressionlistalt);
      ilmin = 0;
      ilcsize = [];
      while(ilmin < ilsize):
       cfcontents = BytesIO();
       shutil.copyfileobj(fcontents, cfcontents);
       fcontents.seek(0, 0);
       cfcontents.seek(0, 0);
       cfcontents = CompressArchiveFile(cfcontents, compressionlistalt[ilmin], compressionlevel, formatspecs);
       if(cfcontents):
        cfcontents.seek(0, 2);
        ilcsize.append(cfcontents.tell());
        cfcontents.close();
       else:
        try:
         ilcsize.append(sys.maxint);
        except AttributeError:
         ilcsize.append(sys.maxsize);
       ilmin = ilmin + 1;
      ilcmin = ilcsize.index(min(ilcsize));
      compression = compressionlistalt[ilcmin];
     fcontents.seek(0, 0);
     cfcontents = BytesIO();
     shutil.copyfileobj(fcontents, cfcontents);
     cfcontents.seek(0, 0);
     cfcontents = CompressArchiveFile(cfcontents, compression, compressionlevel, formatspecs);
     cfcontents.seek(0, 2);
     cfsize = cfcontents.tell();
     if(ucfsize > cfsize):
      fcsize = format(int(cfsize), 'x').lower();
      fcompression = compression;
      fcontents.close();
      fcontents = cfcontents;
  fcontents.seek(0, 0);
  ftypehex = format(ftype, 'x').lower();
  catoutlist = [ftypehex, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression, fcsize, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev_minor, fdev_major, frdev_minor, frdev_major, "+1"];
  catfp = AppendFileHeaderWithContent(catfp, catoutlist, extradata, fcontents.read(), checksumtype, formatspecs);
  fcontents.close();
 if(numfiles>0):
  catfp.write(AppendNullBytes([0, 0], formatspecs['format_delimiter']).encode("UTF-8"));
 if(outfile=="-" or hasattr(outfile, "read") or hasattr(outfile, "write")):
  catfp = CompressArchiveFile(catfp, compression, compressionlevel, formatspecs);
  try:
   catfp.flush();
   os.fsync(catfp.fileno());
  except io.UnsupportedOperation:
   pass;
  except AttributeError:
   pass;
  except OSError as e:
   pass;
 if(outfile=="-"):
  catfp.seek(0, 0);
  if(hasattr(sys.stdout, "buffer")):
   shutil.copyfileobj(catfp, sys.stdout.buffer);
  else:
   shutil.copyfileobj(catfp, sys.stdout);
 elif(re.findall(r"^(ftp|ftps|sftp)\:\/\/", str(outfile))):
  catfp = CompressArchiveFile(catfp, compression, compressionlevel, formatspecs);
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
  return PackArchiveFile(source_dir, archive_name, False, "auto", True, None, False, "crc32", [], __file_format_dict__['format_delimiter'], False, False);
 create_alias_function("Pack", __file_format_name__, "Func", PackArchiveFileFunc);

def PackArchiveFileFromDirList(infiles, outfile, dirlistfromtxt=False, compression="auto", compresswholefile=True, compressionlevel=None, followlink=False, checksumtype="crc32", extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 return PackArchiveFile(infiles, outfile, dirlistfromtxt, compression, compresswholefile, compressionlevel, followlink, checksumtype, extradata, formatspecs, verbose, returnfp);

create_alias_function("Pack", __file_format_name__, "FromDirList", PackArchiveFileFromDirList);

def PackArchiveFileFromTarFile(infile, outfile, compression="auto", compresswholefile=True, compressionlevel=None, checksumtype="crc32", extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 if(outfile!="-" and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
  outfile = RemoveWindowsPath(outfile);
 checksumtype = checksumtype.lower();
 if(not CheckSumSupport(checksumtype, hashlib_guaranteed)):
  checksumtype="crc32";
 if(checksumtype=="none"):
  checksumtype = "";
 if(not compression or compression=="catfile" or compression==formatspecs['format_lower']):
  compression = "auto";
 if(compression not in compressionlist and compression is None):
  compression = "auto";
 if(verbose):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(outfile!="-" and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
  if(os.path.exists(outfile)):
   try:
    os.unlink(outfile);
   except OSError as e:
    pass;
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
  catfp = CompressOpenFile(outfile, compresswholefile, compressionlevel);
 catver = formatspecs['format_ver'];
 fileheaderver = str(int(catver.replace(".", "")));
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
   if(not tarfile.TarFileCheck(infile)):
    return False;
  except AttributeError:
   if(not TarFileCheck(infile)):
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
 numfiles = int(len(tarfp.getmembers()));
 catfp = AppendFileHeader(catfp, numfiles, checksumtype, formatspecs);
 for member in sorted(tarfp.getmembers(), key=lambda x: x.name):
  if(re.findall(r"^[.|/]", member.name)):
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
  fcurinode = format(int(curfid), 'x').lower();
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
  fcompression = "";
  fcsize = format(int(0), 'x').lower();
  fcontents = BytesIO();
  if(ftype==0 or ftype==7):
   with tarfp.extractfile(member) as fpc:
    shutil.copyfileobj(fpc, fcontents);
    if(not compresswholefile):
     fcontents.seek(0, 2);
     ucfsize = fcontents.tell();
     fcontents.seek(0, 0);
     if(compression=="auto"):
      ilsize = len(compressionlistalt);
      ilmin = 0;
      ilcsize = [];
      while(ilmin < ilsize):
       cfcontents = BytesIO();
       shutil.copyfileobj(fcontents, cfcontents);
       fcontents.seek(0, 0);
       cfcontents.seek(0, 0);
       cfcontents = CompressArchiveFile(cfcontents, compressionlistalt[ilmin], compressionlevel, formatspecs);
       if(cfcontents):
        cfcontents.seek(0, 2);
        ilcsize.append(cfcontents.tell());
        cfcontents.close();
       else:
        try:
         ilcsize.append(sys.maxint);
        except AttributeError:
         ilcsize.append(sys.maxsize);
       ilmin = ilmin + 1;
      ilcmin = ilcsize.index(min(ilcsize));
      compression = compressionlistalt[ilcmin];
     fcontents.seek(0, 0);
     cfcontents = BytesIO();
     shutil.copyfileobj(fcontents, cfcontents);
     cfcontents.seek(0, 0);
     cfcontents = CompressArchiveFile(cfcontents, compression, compressionlevel, formatspecs);
     cfcontents.seek(0, 2);
     cfsize = cfcontents.tell();
     if(ucfsize > cfsize):
      fcsize = format(int(cfsize), 'x').lower();
      fcompression = compression;
      fcontents.close();
      fcontents = cfcontents;
  if(fcompression=="none"):
   fcompression = "";
  fcontents.seek(0, 0);
  ftypehex = format(ftype, 'x').lower();
  catoutlist = [ftypehex, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression, fcsize, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev_minor, fdev_major, frdev_minor, frdev_major, "+1"];
  catfp = AppendFileHeaderWithContent(catfp, catoutlist, extradata, fcontents.read(), checksumtype, formatspecs);
  fcontents.close();
 if(numfiles>0):
  catfp.write(AppendNullBytes([0, 0], formatspecs['format_delimiter']).encode("UTF-8"));
 if(outfile=="-" or hasattr(outfile, "read") or hasattr(outfile, "write")):
  catfp = CompressArchiveFile(catfp, compression, compressionlevel, formatspecs);
  try:
   catfp.flush();
   os.fsync(catfp.fileno());
  except io.UnsupportedOperation:
   pass;
  except AttributeError:
   pass;
  except OSError as e:
   pass;
 if(outfile=="-"):
  catfp.seek(0, 0);
  if(hasattr(sys.stdout, "buffer")):
   shutil.copyfileobj(catfp, sys.stdout.buffer);
  else:
   shutil.copyfileobj(catfp, sys.stdout);
 elif(re.findall(r"^(ftp|ftps|sftp)\:\/\/", str(outfile))):
  catfp = CompressArchiveFile(catfp, compression, compressionlevel, formatspecs);
  catfp.seek(0, 0);
  upload_file_to_internet_file(catfp, outfile);
 if(returnfp):
  catfp.seek(0, 0);
  return catfp;
 else:
  catfp.close();
  return True;

create_alias_function("Pack", __file_format_name__, "FromTarFile", PackArchiveFileFromTarFile);

def PackArchiveFileFromZipFile(infile, outfile, compression="auto", compresswholefile=True, compressionlevel=None, checksumtype="crc32", extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 if(outfile!="-" and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
  outfile = RemoveWindowsPath(outfile);
 checksumtype = checksumtype.lower();
 if(not CheckSumSupport(checksumtype, hashlib_guaranteed)):
  checksumtype="crc32";
 if(checksumtype=="none"):
  checksumtype = "";
 if(not compression or compression=="catfile" or compression==formatspecs['format_lower']):
  compression = "auto";
 if(compression not in compressionlist and compression is None):
  compression = "auto";
 if(verbose):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(outfile!="-" and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
  if(os.path.exists(outfile)):
   try:
    os.unlink(outfile);
   except OSError as e:
    pass;
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
  catfp = CompressOpenFile(outfile, compresswholefile, compressionlevel);
 catver = formatspecs['format_ver'];
 fileheaderver = str(int(catver.replace(".", "")));
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
 numfiles = int(len(zipfp.infolist()));
 catfp = AppendFileHeader(catfp, numfiles, checksumtype, formatspecs);
 for member in sorted(zipfp.infolist(), key=lambda x: x.filename):
  if(re.findall(r"^[.|/]", member.filename)):
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
  fcurinode = format(int(curfid), 'x').lower();
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
  fcompression = "";
  fcsize = format(int(0), 'x').lower();
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
  fcontents = BytesIO();
  if(ftype==0):
   fcontents.write(zipfp.read(member.filename));
   if(not compresswholefile):
    fcontents.seek(0, 2);
    ucfsize = fcontents.tell();
    fcontents.seek(0, 0);
    if(compression=="auto"):
     ilsize = len(compressionlistalt);
     ilmin = 0;
     ilcsize = [];
     while(ilmin < ilsize):
      cfcontents = BytesIO();
      shutil.copyfileobj(fcontents, cfcontents);
      fcontents.seek(0, 0);
      cfcontents.seek(0, 0);
      cfcontents = CompressArchiveFile(cfcontents, compressionlistalt[ilmin], compressionlevel, formatspecs);
      cfcontents.seek(0, 2);
      ilcsize.append(cfcontents.tell());
      cfcontents.close();
      ilmin = ilmin + 1;
     ilcmin = ilcsize.index(min(ilcsize));
     compression = compressionlistalt[ilcmin];
    fcontents.seek(0, 0);
    cfcontents = BytesIO();
    shutil.copyfileobj(fcontents, cfcontents);
    cfcontents.seek(0, 0);
    cfcontents = CompressArchiveFile(cfcontents, compression, compressionlevel, formatspecs);
    cfcontents.seek(0, 2);
    cfsize = cfcontents.tell();
    if(ucfsize > cfsize):
     fcsize = format(int(cfsize), 'x').lower();
     fcompression = compression;
     fcontents.close();
     fcontents = cfcontents;
  if(fcompression=="none"):
   fcompression = "";
  fcontents.seek(0, 0);
  ftypehex = format(ftype, 'x').lower();
  catoutlist = [ftypehex, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression, fcsize, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev_minor, fdev_major, frdev_minor, frdev_major, "+1"];
  catfp = AppendFileHeaderWithContent(catfp, catoutlist, extradata, fcontents.read(), checksumtype, formatspecs);
  fcontents.close();
 if(numfiles>0):
  catfp.write(AppendNullBytes([0, 0], formatspecs['format_delimiter']).encode("UTF-8"));
 if(outfile=="-" or hasattr(outfile, "read") or hasattr(outfile, "write")):
  catfp = CompressArchiveFile(catfp, compression, compressionlevel, formatspecs);
  try:
   catfp.flush();
   os.fsync(catfp.fileno());
  except io.UnsupportedOperation:
   pass;
  except AttributeError:
   pass;
  except OSError as e:
   pass;
 if(outfile=="-"):
  catfp.seek(0, 0);
  if(hasattr(sys.stdout, "buffer")):
   shutil.copyfileobj(catfp, sys.stdout.buffer);
  else:
   shutil.copyfileobj(catfp, sys.stdout);
 elif(re.findall(r"^(ftp|ftps|sftp)\:\/\/", str(outfile))):
  catfp = CompressArchiveFile(catfp, compression, compressionlevel, formatspecs);
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
 def PackArchiveFileFromRarFile(infile, outfile, compression="auto", compresswholefile=True, compressionlevel=None, checksumtype="crc32", extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
  return False

if(rarfile_support):
 def PackArchiveFileFromRarFile(infile, outfile, compression="auto", compresswholefile=True, compressionlevel=None, checksumtype="crc32", extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
  formatspecs = FormatSpecsListToDict(formatspecs);
  if(outfile!="-" and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
   outfile = RemoveWindowsPath(outfile);
  checksumtype = checksumtype.lower();
  if(not CheckSumSupport(checksumtype, hashlib_guaranteed)):
   checksumtype="crc32";
  if(checksumtype=="none"):
   checksumtype = "";
  if(not compression or compression=="catfile" or compression==formatspecs['format_lower']):
   compression = "auto";
  if(compression not in compressionlist and compression is None):
   compression = "auto";
  if(verbose):
   logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
  if(outfile!="-" and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
   if(os.path.exists(outfile)):
    try:
     os.unlink(outfile);
    except OSError as e:
     pass;
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
   catfp = CompressOpenFile(outfile, compresswholefile, compressionlevel);
  catver = formatspecs['format_ver'];
  fileheaderver = str(int(catver.replace(".", "")));
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
  numfiles = int(len(rarfp.infolist()));
  catfp = AppendFileHeader(catfp, numfiles, checksumtype, formatspecs);
  try:
   catfp.flush();
   os.fsync(catfp.fileno());
  except io.UnsupportedOperation:
   pass;
  except AttributeError:
   pass;
  except OSError as e:
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
   if(re.findall(r"^[.|/]", member.filename)):
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
   fcompression = "";
   fcsize = format(int(0), 'x').lower();
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
   fcurinode = format(int(curfid), 'x').lower();
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
   fcontents = BytesIO();
   if(ftype==0):
    fcontents.write(rarfp.read(member.filename));
    if(not compresswholefile):
     fcontents.seek(0, 2);
     ucfsize = fcontents.tell();
     fcontents.seek(0, 0);
     if(compression=="auto"):
      ilsize = len(compressionlistalt);
      ilmin = 0;
      ilcsize = [];
      while(ilmin < ilsize):
       cfcontents = BytesIO();
       shutil.copyfileobj(fcontents, cfcontents);
       fcontents.seek(0, 0);
       cfcontents.seek(0, 0);
       cfcontents = CompressArchiveFile(cfcontents, compressionlistalt[ilmin], compressionlevel, formatspecs);
       if(cfcontents):
        cfcontents.seek(0, 2);
        ilcsize.append(cfcontents.tell());
        cfcontents.close();
       else:
        try:
         ilcsize.append(sys.maxint);
        except AttributeError:
         ilcsize.append(sys.maxsize);
       ilmin = ilmin + 1;
      ilcmin = ilcsize.index(min(ilcsize));
      compression = compressionlistalt[ilcmin];
     fcontents.seek(0, 0);
     cfcontents = BytesIO();
     shutil.copyfileobj(fcontents, cfcontents);
     cfcontents.seek(0, 0);
     cfcontents = CompressArchiveFile(cfcontents, compression, compressionlevel, formatspecs);
     cfcontents.seek(0, 2);
     cfsize = cfcontents.tell();
     if(ucfsize > cfsize):
      fcsize = format(int(cfsize), 'x').lower();
      fcompression = compression;
      fcontents.close();
      fcontents = cfcontents;
   if(fcompression=="none"):
    fcompression = "";
   fcontents.seek(0, 0);
   ftypehex = format(ftype, 'x').lower();
   catoutlist = [ftypehex, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression, fcsize, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev_minor, fdev_major, frdev_minor, frdev_major, "+1"];
   catfp = AppendFileHeaderWithContent(catfp, catoutlist, extradata, fcontents.read(), checksumtype, formatspecs);
   fcontents.close();
  if(numfiles>0):
   catfp.write(AppendNullBytes([0, 0], formatspecs['format_delimiter']).encode("UTF-8"));
  if(outfile=="-" or hasattr(outfile, "read") or hasattr(outfile, "write")):
   catfp = CompressArchiveFile(catfp, compression, compressionlevel, formatspecs)
   try:
    catfp.flush();
    os.fsync(catfp.fileno());
   except io.UnsupportedOperation:
    pass;
   except AttributeError:
    pass;
   except OSError as e:
    pass;
  if(outfile=="-"):
   catfp.seek(0, 0)
   if(hasattr(sys.stdout, "buffer")):
    shutil.copyfileobj(catfp, sys.stdout.buffer);
   else:
    shutil.copyfileobj(catfp, sys.stdout);
  elif(re.findall(r"^(ftp|ftps|sftp)\:\/\/", str(outfile))):
   catfp = CompressArchiveFile(catfp, compression, compressionlevel, formatspecs);
   catfp.seek(0, 0);
   upload_file_to_internet_file(catfp, outfile);
  if(returnfp):
   catfp.seek(0, 0)
   return catfp
  else:
   catfp.close()
   return True;

create_alias_function("Pack", __file_format_name__, "FromRarFile", PackArchiveFileFromRarFile);

if(not py7zr_support):
 def PackArchiveFileFromSevenZipFile(infile, outfile, compression="auto", compresswholefile=True, compressionlevel=None, checksumtype="crc32", extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
  return False

if(py7zr_support):
 def PackArchiveFileFromSevenZipFile(infile, outfile, compression="auto", compresswholefile=True, compressionlevel=None, checksumtype="crc32", extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
  formatspecs = FormatSpecsListToDict(formatspecs);
  if(outfile!="-" and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
   outfile = RemoveWindowsPath(outfile);
  checksumtype = checksumtype.lower();
  if(not CheckSumSupport(checksumtype, hashlib_guaranteed)):
   checksumtype="crc32";
  if(checksumtype=="none"):
   checksumtype = "";
  if(not compression or compression=="catfile" or compression==formatspecs['format_lower']):
   compression = "auto";
  if(compression not in compressionlist and compression is None):
   compression = "auto";
  if(verbose):
   logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
  if(outfile!="-" and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
   if(os.path.exists(outfile)):
    try:
     os.unlink(outfile);
    except OSError as e:
     pass;
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
   catfp = CompressOpenFile(outfile, compresswholefile, compressionlevel);
  catver = formatspecs['format_ver'];
  fileheaderver = str(int(catver.replace(".", "")));
  curinode = 0;
  curfid = 0;
  inodelist = [];
  inodetofile = {};
  filetoinode = {};
  inodetocatinode = {};
  if(not os.path.exists(infile) or not os.path.isfile(infile)):
   return False;
  szpfp = py7zr.SevenZipFile(infile, mode="r");
  file_content = szpfp.readall();
  #sztest = szpfp.testzip();
  sztestalt = szpfp.test();
  if(sztestalt):
   VerbosePrintOut("Bad file found!");
  numfiles = int(len(szpfp.list()));
  AppendFileHeader(catfp, numfiles, checksumtype, formatspecs);
  for member in sorted(szpfp.list(), key=lambda x: x.filename):
   if(re.findall(r"^[.|/]", member.filename)):
    fname = member.filename;
   else:
    fname = "./"+member.filename;
   if(verbose):
    VerbosePrintOut(fname);
   if(not member.is_directory):
    fpremode = int(stat.S_IFREG + 438);
   elif(member.is_directory):
    fpremode = int(stat.S_IFDIR + 511);
   fwinattributes = format(int(0), 'x').lower();
   fcompression = "";
   fcsize = format(int(0), 'x').lower();
   flinkcount = 0;
   ftype = 0;
   if(member.is_directory):
    ftype = 5;
   else:
    ftype = 0;
   flinkname = "";
   fcurfid = format(int(curfid), 'x').lower();
   fcurinode = format(int(curfid), 'x').lower();
   curfid = curfid + 1;
   fdev_minor = format(int(0), 'x').lower();
   fdev_major = format(int(0), 'x').lower();
   frdev_minor = format(int(0), 'x').lower();
   frdev_major = format(int(0), 'x').lower();
   if(ftype==5):
    fsize = format(int("0"), 'x').lower();
   fatime = format(int(member.creationtime.timestamp()), 'x').lower();
   fmtime = format(int(member.creationtime.timestamp()), 'x').lower();
   fctime = format(int(member.creationtime.timestamp()), 'x').lower();
   fbtime = format(int(member.creationtime.timestamp()), 'x').lower();
   if(member.is_directory):
    fmode = format(int(stat.S_IFDIR + 511), 'x').lower();
    fchmode = format(int(stat.S_IMODE(int(stat.S_IFDIR + 511))), 'x').lower();
    ftypemod = format(int(stat.S_IFMT(int(stat.S_IFDIR + 511))), 'x').lower();
   else:
    fmode = format(int(stat.S_IFREG + 438), 'x').lower();
    fchmode = format(int(stat.S_IMODE(int(stat.S_IFREG + 438))), 'x').lower();
    ftypemod = format(int(stat.S_IFMT(int(stat.S_IFREG + 438))), 'x').lower();
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
   fcontents = BytesIO();
   if(ftype==0):
    fcontents.write(file_content[member.filename].read());
    fsize = format(fcontents.tell(), 'x').lower();
    file_content[member.filename].close();
    if(not compresswholefile):
     fcontents.seek(0, 2);
     ucfsize = fcontents.tell();
     fcontents.seek(0, 0);
     if(compression=="auto"):
      ilsize = len(compressionlistalt);
      ilmin = 0;
      ilcsize = [];
      while(ilmin < ilsize):
       cfcontents = BytesIO();
       shutil.copyfileobj(fcontents, cfcontents);
       fcontents.seek(0, 0);
       cfcontents.seek(0, 0);
       cfcontents = CompressArchiveFile(cfcontents, compressionlistalt[ilmin], compressionlevel, formatspecs);
       if(cfcontents):
        cfcontents.seek(0, 2);
        ilcsize.append(cfcontents.tell());
        cfcontents.close();
       else:
        try:
         ilcsize.append(sys.maxint);
        except AttributeError:
         ilcsize.append(sys.maxsize);
       ilmin = ilmin + 1;
      ilcmin = ilcsize.index(min(ilcsize));
      compression = compressionlistalt[ilcmin];
     fcontents.seek(0, 0);
     cfcontents = BytesIO();
     shutil.copyfileobj(fcontents, cfcontents);
     cfcontents.seek(0, 0);
     cfcontents = CompressArchiveFile(cfcontents, compression, compressionlevel, formatspecs);
     cfcontents.seek(0, 2);
     cfsize = cfcontents.tell();
     if(ucfsize > cfsize):
      fcsize = format(int(cfsize), 'x').lower();
      fcompression = compression;
      fcontents.close();
      fcontents = cfcontents;
   if(fcompression=="none"):
    fcompression = "";
   fcontents.seek(0, 0);
   ftypehex = format(ftype, 'x').lower();
   catoutlist = [ftypehex, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression, fcsize, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev_minor, fdev_major, frdev_minor, frdev_major, "+1"];
   catfp = AppendFileHeaderWithContent(catfp, catoutlist, extradata, fcontents.read(), checksumtype, formatspecs);
   fcontents.close();
  if(numfiles>0):
   catfp.write(AppendNullBytes([0, 0], formatspecs['format_delimiter']).encode("UTF-8"));
  if(outfile=="-" or hasattr(outfile, "read") or hasattr(outfile, "write")):
   catfp = CompressArchiveFile(catfp, compression, compressionlevel, formatspecs)
   try:
    catfp.flush();
    os.fsync(catfp.fileno());
   except io.UnsupportedOperation:
    pass;
   except AttributeError:
    pass;
   except OSError as e:
    pass;
  if(outfile=="-"):
   catfp.seek(0, 0);
   if(hasattr(sys.stdout, "buffer")):
    shutil.copyfileobj(catfp, sys.stdout.buffer);
   else:
    shutil.copyfileobj(catfp, sys.stdout);
  elif(re.findall(r"^(ftp|ftps|sftp)\:\/\/", str(outfile))):
   catfp = CompressArchiveFile(catfp, compression, compressionlevel, formatspecs);
   catfp.seek(0, 0);
   upload_file_to_internet_file(catfp, outfile);
  if(returnfp):
   catfp.seek(0, 0)
   return catfp
  else:
   catfp.close()
   return True;

create_alias_function("Pack", __file_format_name__, "FromSevenZipFile", PackArchiveFileFromSevenZipFile);

def PackArchiveFileFromInFile(infile, outfile, compression="auto", compresswholefile=True, compressionlevel=None, checksumtype="crc32", extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 checkcompressfile = CheckCompressionSubType(infile, formatspecs, True);
 if(verbose):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(checkcompressfile=="tarfile"):
  return PackArchiveFileFromTarFile(infile, outfile, compression, compresswholefile, compressionlevel, checksumtype, extradata, formatspecs, verbose, returnfp);
 elif(checkcompressfile=="zipfile"):
  return PackArchiveFileFromZipFile(infile, outfile, compression, compresswholefile, compressionlevel, checksumtype, extradata, formatspecs, verbose, returnfp);
 elif(checkcompressfile=="catfile"):
  return RePackArchiveFile(infile, outfile, compression, compresswholefile, compressionlevel, False, 0, 0, checksumtype, False, extradata, formatspecs, verbose, returnfp);
 elif(rarfile_support and checkcompressfile=="rarfile"):
  return PackArchiveFileFromRarFile(infile, outfile, compression, compresswholefile, compressionlevel, checksumtype, extradata, formatspecs, verbose, returnfp);
 elif(py7zr_support and checkcompressfile=="7zipfile"):
  return PackArchiveFileFromSevenZipFile(infile, outfile, compression, compresswholefile, compressionlevel, checksumtype, extradata, formatspecs, verbose, returnfp);
 else:
  return False;
 return False;

create_alias_function("Pack", __file_format_name__, "FromInFile", PackArchiveFileFromInFile);

def ArchiveFileSeekToFileNum(infile, seekto=0, listonly=False, skipchecksum=False, formatspecs=__file_format_dict__, returnfp=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 if(hasattr(infile, "read") or hasattr(infile, "write")):
  catfp = infile;
  catfp.seek(0, 0);
  catfp = UncompressArchiveFile(catfp, formatspecs);
  checkcompressfile = CheckCompressionSubType(catfp, formatspecs, True);
  if(checkcompressfile=="tarfile"):
   return TarFileToArray(infile, seekto, 0, listonly, skipchecksum, formatspecs, returnfp);
  if(checkcompressfile=="zipfile"):
   return ZipFileToArray(infile, seekto, 0, listonly, skipchecksum, formatspecs, returnfp);
  if(rarfile_support and checkcompressfile=="rarfile"):
   return RarFileToArray(infile, seekto, 0, listonly, skipchecksum, formatspecs, returnfp);
  if(py7zr_support and checkcompressfile=="7zipfile"):
   return SevenZipFileToArray(infile, seekto, 0, listonly, skipchecksum, formatspecs, returnfp);
  if(checkcompressfile!="catfile" and checkcompressfile!=formatspecs['format_lower']):
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
  checkcompressfile = CheckCompressionSubType(infile, formatspecs, True);
  if(checkcompressfile=="tarfile"):
   return TarFileToArray(infile, seekto, 0, listonly, skipchecksum, formatspecs, returnfp);
  if(checkcompressfile=="zipfile"):
   return ZipFileToArray(infile, seekto, 0, listonly, skipchecksum, formatspecs, returnfp);
  if(rarfile_support and checkcompressfile=="rarfile"):
   return RarFileToArray(infile, seekto, 0, listonly, skipchecksum, formatspecs, returnfp);
  if(py7zr_support and checkcompressfile=="7zipfile"):
   return SevenZipFileToArray(infile, seekto, 0, listonly, skipchecksum, formatspecs, returnfp);
  if(checkcompressfile!="catfile" and checkcompressfile!=formatspecs['format_lower']):
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
 curloc = catfp.tell();
 if(curloc>0):
  catfp.seek(0, 0);
 catheader = ReadFileHeaderData(catfp, 4, formatspecs['format_delimiter']);
 if(curloc>0):
  catfp.seek(curloc, 0);
 catstring = catheader[0];
 catversion = re.findall(r"([\d]+)", catstring);
 fprenumfiles = catheader[1];
 fnumfiles = int(fprenumfiles, 16);
 fprechecksumtype = catheader[2];
 fprechecksum = catheader[3];
 fileheader = AppendNullByte(catstring, formatspecs['format_delimiter']);
 fnumfileshex = format(int(fnumfiles), 'x').lower();
 fileheader = fileheader + AppendNullBytes([fnumfileshex, fprechecksumtype], formatspecs['format_delimiter']);
 catfileheadercshex = GetFileChecksum(fileheader, fprechecksumtype, True, formatspecs);
 fileheader = fileheader + AppendNullByte(catfileheadercshex, formatspecs['format_delimiter']);
 fheadtell = len(fileheader);
 if(fprechecksum!=catfileheadercshex and not skipchecksum):
  VerbosePrintOut("File Header Checksum Error with file " + infile + " at offset " + str(0));
  VerbosePrintOut("'" + str(fprechecksum) + "' != " + "'" + str(catfileheadercshex) + "'");
  return False;
 catversions = re.search(r'(.*?)(\d+)', catstring).groups();
 catlist = {'fnumfiles': fnumfiles, 'fformat': catversions[0], 'fversion': catversions[1], 'fformatspecs': formatspecs, 'fchecksumtype': fprechecksumtype, 'fheaderchecksum': fprechecksum, 'ffilelist': {}};
 if(seekto>=fnumfiles):
  seekto = fnumfiles - 1;
 if(seekto<0):
  seekto = 0;
 if(seekto>=0):
  il = -1;
  while(il < seekto):
   prefhstart = catfp.tell();
   if(formatspecs['new_style']):
    preheaderdata = ReadFileHeaderDataBySize(catfp, formatspecs['format_delimiter']);
   else:
    preheaderdata = ReadFileHeaderDataWoSize(catfp, formatspecs['format_delimiter']);
   if(len(preheaderdata)==0):
    break;
   prefheadsize = int(preheaderdata[0], 16);
   prefnumfields = int(preheaderdata[1], 16);
   preftype = int(preheaderdata[2], 16);
   if(re.findall(r"^[.|/]", preheaderdata[3])):
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
   prefcompression = preheaderdata[12];
   prefcsize = int(preheaderdata[13], 16);
   prefuid = int(preheaderdata[14], 16);
   prefuname = preheaderdata[15];
   prefgid = int(preheaderdata[16], 16);
   prefgname = preheaderdata[17];
   fid = int(preheaderdata[18], 16);
   finode = int(preheaderdata[19], 16);
   flinkcount = int(preheaderdata[20], 16);
   prefdev_minor = int(preheaderdata[21], 16);
   prefdev_major = int(preheaderdata[22], 16);
   prefrdev_minor = int(preheaderdata[23], 16);
   prefrdev_major = int(preheaderdata[24], 16);
   prefseeknextfile = preheaderdata[25];
   prefextrasize = int(preheaderdata[26], 16);
   prefextrafields = int(preheaderdata[27], 16);
   extrafieldslist = [];
   extrastart = 28;
   extraend = extrastart + prefextrafields;
   extrafieldslist = [];
   if(extrastart<extraend):
    extrafieldslist.append(preheaderdata[extrastart]);
    extrastart = extrastart + 1;
   prefcs = preheaderdata[extrastart + 2].lower();
   prefccs = preheaderdata[extrastart + 3].lower();
   prenewfcs = GetHeaderChecksum(preheaderdata[:-2], preheaderdata[-4].lower(), True, formatspecs);
   if(prefcs!=prenewfcs and not skipchecksum):
    VerbosePrintOut("File Header Checksum Error with file " + prefname + " at offset " + str(prefhstart));
    VerbosePrintOut("'" + str(prefcs) + "' != " + "'" + str(prenewfcs) + "'");
    return False;
    valid_archive = False;
    invalid_archive = True;
   prefhend = catfp.tell() - 1;
   prefcontentstart = catfp.tell();
   prefcontents = "";
   pyhascontents = False;
   if(prefsize>0):
    if(prefcompression):
     prefcontents = catfp.read(prefsize);
    else:
     prefcontents = catfp.read(prefcsize);
    prenewfccs = GetFileChecksum(prefcontents, preheaderdata[-3].lower(), False, formatspecs);
    pyhascontents = True;
    if(prefccs!=prenewfccs and not skipchecksum):
     VerbosePrintOut("File Content Checksum Error with file " + prefname + " at offset " + str(prefcontentstart));
     VerbosePrintOut("'" + str(prefccs) + "' != " + "'" + str(prenewfccs) + "'");
     return False;
   if(re.findall(r"^\+([0-9]+)", prefseeknextfile)):
    fseeknextasnum = int(prefseeknextfile.replace("+", ""));
    if(abs(fseeknextasnum)==0):
     pass;
    catfp.seek(fseeknextasnum, 1);
   elif(re.findall(r"^\-([0-9]+)", prefseeknextfile)):
    fseeknextasnum = int(prefseeknextfile);
    if(abs(fseeknextasnum)==0):
     pass;
    catfp.seek(fseeknextasnum, 1);
   elif(re.findall(r"^([0-9]+)", prefseeknextfile)):
    fseeknextasnum = int(prefseeknextfile);
    if(abs(fseeknextasnum)==0):
     pass;
    catfp.seek(fseeknextasnum, 0);
   else:
    return False;
   il = il + 1;
 catfp.seek(seekstart, 0);
 fileidnum = il;
 catfheadsize = int(preheaderdata[0], 16);
 catfnumfields = int(preheaderdata[1], 16);
 catftype = int(preheaderdata[2], 16);
 if(re.findall(r"^[.|/]", preheaderdata[3])):
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

def ArchiveFileSeekToFileName(infile, seekfile=None, listonly=False, skipchecksum=False, formatspecs=__file_format_dict__, returnfp=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 if(hasattr(infile, "read") or hasattr(infile, "write")):
  catfp = infile;
  catfp.seek(0, 0);
  catfp = UncompressArchiveFile(catfp, formatspecs);
  checkcompressfile = CheckCompressionSubType(catfp, formatspecs, True);
  if(checkcompressfile=="tarfile"):
   return TarFileToArray(infile, 0, 0, listonly, skipchecksum, formatspecs, returnfp);
  if(checkcompressfile=="zipfile"):
   return ZipFileToArray(infile, 0, 0, listonly, skipchecksum, formatspecs, returnfp);
  if(rarfile_support and checkcompressfile=="rarfile"):
   return RarFileToArray(infile, 0, 0, listonly, skipchecksum, formatspecs, returnfp);
  if(py7zr_support and checkcompressfile=="7zipfile"):
   return SevenZipFileToArray(infile, 0, 0, listonly, skipchecksum, formatspecs, returnfp);
  if(checkcompressfile!="catfile" and checkcompressfile!=formatspecs['format_lower']):
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
  checkcompressfile = CheckCompressionSubType(infile, formatspecs, True);
  if(checkcompressfile=="tarfile"):
   return TarFileToArray(infile, 0, 0, listonly, skipchecksum, formatspecs, returnfp);
  if(checkcompressfile=="zipfile"):
   return ZipFileToArray(infile, 0, 0, listonly, skipchecksum, formatspecs, returnfp);
  if(rarfile_support and checkcompressfile=="rarfile"):
   return RarFileToArray(infile, 0, 0, listonly, skipchecksum, formatspecs, returnfp);
  if(py7zr_support and checkcompressfile=="7zipfile"):
   return SevenZipFileToArray(infile, 0, 0, listonly, skipchecksum, formatspecs, returnfp);
  if(checkcompressfile!="catfile" and checkcompressfile!=formatspecs['format_lower']):
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
 curloc = catfp.tell();
 if(curloc>0):
  catfp.seek(0, 0);
 catheader = ReadFileHeaderData(catfp, 4, formatspecs['format_delimiter']);
 if(curloc>0):
  catfp.seek(curloc, 0);
 catstring = catheader[0];
 catversion = re.findall(r"([\d]+)", catstring);
 fprenumfiles = catheader[1];
 fnumfiles = int(fprenumfiles, 16);
 fprechecksumtype = catheader[2];
 fprechecksum = catheader[3];
 fileheader = AppendNullByte(catstring, formatspecs['format_delimiter']);
 fnumfileshex = format(int(fnumfiles), 'x').lower();
 fileheader = fileheader + AppendNullBytes([fnumfileshex, fprechecksumtype], formatspecs['format_delimiter']);
 catfileheadercshex = GetFileChecksum(fileheader, fprechecksumtype, True, formatspecs);
 fileheader = fileheader + AppendNullByte(catfileheadercshex, formatspecs['format_delimiter']);
 fheadtell = len(fileheader);
 if(fprechecksum!=catfileheadercshex and not skipchecksum):
  VerbosePrintOut("File Header Checksum Error with file " + infile + " at offset " + str(0));
  VerbosePrintOut("'" + str(fprechecksum) + "' != " + "'" + str(catfileheadercshex) + "'");
  return False;
 catversions = re.search(r'(.*?)(\d+)', catstring).groups();
 catlist = {'fnumfiles': fnumfiles, 'fformat': catversions[0], 'fversion': catversions[1], 'fformatspecs': formatspecs, 'fchecksumtype': fprechecksumtype, 'fheaderchecksum': fprechecksum, 'ffilelist': {}};
 seekto = fnumfiles - 1
 filefound = False;
 if(seekto>=0):
  il = -1;
  while(il < seekto):
   prefhstart = catfp.tell();
   if(formatspecs['new_style']):
    preheaderdata = ReadFileHeaderDataBySize(catfp, formatspecs['format_delimiter']);
   else:
    preheaderdata = ReadFileHeaderDataWoSize(catfp, formatspecs['format_delimiter']);
   if(len(preheaderdata)==0):
    break;
   prefheadsize = int(preheaderdata[0], 16);
   prefnumfields = int(preheaderdata[1], 16);
   preftype = int(preheaderdata[2], 16);
   if(re.findall(r"^[.|/]", preheaderdata[3])):
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
   prefcompression = preheaderdata[12];
   prefcsize = int(preheaderdata[13], 16);
   prefuid = int(preheaderdata[14], 16);
   prefuname = preheaderdata[15];
   prefgid = int(preheaderdata[16], 16);
   prefgname = preheaderdata[17];
   fid = int(preheaderdata[18], 16);
   finode = int(preheaderdata[19], 16);
   flinkcount = int(preheaderdata[20], 16);
   prefdev_minor = int(preheaderdata[21], 16);
   prefdev_major = int(preheaderdata[22], 16);
   prefrdev_minor = int(preheaderdata[23], 16);
   prefrdev_major = int(preheaderdata[24], 16);
   prefseeknextfile = preheaderdata[25];
   prefextrasize = int(preheaderdata[26], 16);
   prefextrafields = int(preheaderdata[27], 16);
   extrafieldslist = [];
   extrastart = 28;
   extraend = extrastart + prefextrafields;
   extrafieldslist = [];
   if(extrastart<extraend):
    extrafieldslist.append(preheaderdata[extrastart]);
    extrastart = extrastart + 1;
   prefcs = preheaderdata[extrastart + 2].lower();
   prefccs = preheaderdata[extrastart + 3].lower();
   prenewfcs = GetHeaderChecksum(preheaderdata[:-2], preheaderdata[-4].lower(), True, formatspecs);
   if(prefcs!=prenewfcs and not skipchecksum):
    VerbosePrintOut("File Header Checksum Error with file " + prefname + " at offset " + str(prefhstart));
    VerbosePrintOut("'" + str(prefcs) + "' != " + "'" + str(prenewfcs) + "'");
    return False;
    valid_archive = False;
    invalid_archive = True;
   prefhend = catfp.tell() - 1;
   prefcontentstart = catfp.tell();
   prefcontents = "";
   pyhascontents = False;
   if(prefsize>0):
    if(prefcompression):
     prefcontents = catfp.read(prefsize);
    else:
     prefcontents = catfp.read(prefcsize);
    prenewfccs = GetFileChecksum(prefcontents, preheaderdata[-3].lower(), False, formatspecs);
    pyhascontents = True;
    if(prefccs!=prenewfccs and not skipchecksum):
     VerbosePrintOut("File Content Checksum Error with file " + prefname + " at offset " + str(prefcontentstart));
     VerbosePrintOut("'" + str(prefccs) + "' != " + "'" + str(prenewfccs) + "'");
     return False;
   if(re.findall(r"^\+([0-9]+)", prefseeknextfile)):
    fseeknextasnum = int(prefseeknextfile.replace("+", ""));
    if(abs(fseeknextasnum)==0):
     pass;
    catfp.seek(fseeknextasnum, 1);
   elif(re.findall(r"^\-([0-9]+)", prefseeknextfile)):
    fseeknextasnum = int(prefseeknextfile);
    if(abs(fseeknextasnum)==0):
     pass;
    catfp.seek(fseeknextasnum, 1);
   elif(re.findall(r"^([0-9]+)", prefseeknextfile)):
    fseeknextasnum = int(prefseeknextfile);
    if(abs(fseeknextasnum)==0):
     pass;
    catfp.seek(fseeknextasnum, 0);
   else:
    return False;
   il = il + 1;
   filefound = False;
   prefname = preheaderdata[2];
   if(re.findall(r"^[.|/]", preheaderdata[2])):
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
 if(re.findall(r"^[.|/]", preheaderdata[3])):
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

def ArchiveFileValidate(infile, formatspecs=__file_format_dict__, verbose=False, returnfp=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 if(verbose):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(hasattr(infile, "read") or hasattr(infile, "write")):
  catfp = infile;
  catfp.seek(0, 0);
  catfp = UncompressArchiveFile(catfp, formatspecs);
  checkcompressfile = CheckCompressionSubType(catfp, formatspecs, True);
  if(checkcompressfile=="tarfile"):
   return TarFileToArray(infile, 0, 0, False, False, formatspecs, returnfp);
  if(checkcompressfile=="zipfile"):
   return ZipFileToArray(infile, 0, 0, False, False, formatspecs, returnfp);
  if(rarfile_support and checkcompressfile=="rarfile"):
   return RarFileToArray(infile, 0, 0, False, False, formatspecs, returnfp);
  if(py7zr_support and checkcompressfile=="7zipfile"):
   return SevenZipFileToArray(infile, 0, 0, False, False, formatspecs, returnfp);
  if(checkcompressfile!="catfile" and checkcompressfile!=formatspecs['format_lower']):
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
  checkcompressfile = CheckCompressionSubType(infile, formatspecs, True);
  if(checkcompressfile=="tarfile"):
   return TarFileToArray(infile, 0, 0, False, False, formatspecs, returnfp);
  if(checkcompressfile=="zipfile"):
   return ZipFileToArray(infile, 0, 0, False, False, formatspecs, returnfp);
  if(rarfile_support and checkcompressfile=="rarfile"):
   return RarFileToArray(infile, 0, 0, False, False, formatspecs, returnfp);
  if(py7zr_support and checkcompressfile=="7zipfile"):
   return SevenZipFileToArray(infile, 0, 0, False, False, formatspecs, returnfp);
  if(checkcompressfile!="catfile" and checkcompressfile!=formatspecs['format_lower']):
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
 curloc = catfp.tell();
 if(curloc>0):
  catfp.seek(0, 0);
 catheader = ReadFileHeaderData(catfp, 4, formatspecs['format_delimiter']);
 if(curloc>0):
  catfp.seek(curloc, 0);
 catstring = catheader[0];
 catversion = re.findall(r"([\d]+)", catstring);
 fprenumfiles = catheader[1];
 fnumfiles = int(fprenumfiles, 16);
 fprechecksumtype = catheader[2];
 fprechecksum = catheader[3];
 il = 0; 
 fileheader = AppendNullByte(catstring, formatspecs['format_delimiter']);
 fnumfileshex = format(int(fnumfiles), 'x').lower();
 fileheader = fileheader + AppendNullBytes([fnumfileshex, fprechecksumtype], formatspecs['format_delimiter']);
 catfileheadercshex = GetFileChecksum(fileheader, fprechecksumtype, True, formatspecs);
 fileheader = fileheader + AppendNullByte(catfileheadercshex, formatspecs['format_delimiter']);
 valid_archive = True;
 invalid_archive = False;
 if(verbose):
  VerbosePrintOut(infile);
  VerbosePrintOut("Number of Records " + str(fnumfiles));
 if(fprechecksum==catfileheadercshex):
  if(verbose):
   VerbosePrintOut("File Header Checksum Passed at offset " + str(0));
   VerbosePrintOut("'" + str(fprechecksum) + "' == " + "'" + str(catfileheadercshex) + "'");
 else:
  if(verbose):
   VerbosePrintOut("File Header Checksum Failed at offset " + str(0));
   VerbosePrintOut("'" + str(fprechecksum) + "' != " + "'" + str(catfileheadercshex) + "'");
   valid_archive = False;
   invalid_archive = True;
 if(verbose):
  VerbosePrintOut("");
 while(il<fnumfiles):
  catfhstart = catfp.tell();
  if(formatspecs['new_style']):
   catheaderdata = ReadFileHeaderDataBySize(catfp, formatspecs['format_delimiter']);
  else:
   catheaderdata = ReadFileHeaderDataWoSize(catfp, formatspecs['format_delimiter']);
  if(len(catheaderdata)==0):
   break;
  catfheadsize = int(catheaderdata[0], 16);
  catfnumfields = int(catheaderdata[1], 16);
  catftype = int(catheaderdata[2], 16);
  if(re.findall(r"^[.|/]", catheaderdata[3])):
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
  catfcompression = catheaderdata[12];
  catfcsize = int(catheaderdata[13], 16);
  catfuid = int(catheaderdata[14], 16);
  catfuname = catheaderdata[15];
  catfgid = int(catheaderdata[16], 16);
  catfgname = catheaderdata[17];
  fid = int(catheaderdata[18], 16);
  finode = int(catheaderdata[19], 16);
  flinkcount = int(catheaderdata[20], 16);
  catfdev_minor = int(catheaderdata[21], 16);
  catfdev_major = int(catheaderdata[22], 16);
  catfrdev_minor = int(catheaderdata[23], 16);
  catfrdev_major = int(catheaderdata[24], 16);
  catfseeknextfile = catheaderdata[25];
  catfextrasize = int(catheaderdata[26], 16);
  catfextrafields = int(catheaderdata[27], 16);
  extrafieldslist = [];
  extrastart = 28;
  extraend = extrastart + catfextrafields;
  extrafieldslist = [];
  if(extrastart<extraend):
   extrafieldslist.append(catheaderdata[extrastart]);
   extrastart = extrastart + 1;
  catfcs = catheaderdata[extrastart + 2].lower();
  catfccs = catheaderdata[extrastart + 3].lower();
  catnewfcs = GetHeaderChecksum(catheaderdata[:-2], catheaderdata[-4].lower(), True, formatspecs);
  if(verbose):
   VerbosePrintOut(catfname);
   VerbosePrintOut("Record Number " + str(il) + "; File ID " + str(fid) + "; iNode Number " + str(finode));
  if(catfcs==catnewfcs):
   if(verbose):
    VerbosePrintOut("File Header Checksum Passed at offset " + str(catfhstart));
    VerbosePrintOut("'" + str(catfcs) + "' == " + "'" + str(catnewfcs) + "'");
  else:
   if(verbose):
    VerbosePrintOut("File Header Checksum Failed at offset " + str(catfhstart));
    VerbosePrintOut("'" + str(catfcs) + "' != " + "'" + str(catnewfcs) + "'");
   valid_archive = False;
   invalid_archive = True;
  catfhend = catfp.tell() - 1;
  catfcontentstart = catfp.tell();
  catfcontents = "";
  pyhascontents = False;
  if(catfsize>0):
   if(catfcompression=="none" or catfcompression=="" or catfcompression=="auto"):
    catfcontents = catfp.read(catfsize);
   else:
    catfcontents = catfp.read(catfcsize);
   catnewfccs = GetFileChecksum(catfcontents, catheaderdata[-3].lower(), False, formatspecs);
   pyhascontents = True;
   if(catfccs==catnewfccs):
    if(verbose):
     VerbosePrintOut("File Content Checksum Passed at offset " + str(catfcontentstart));
     VerbosePrintOut("'" + str(catfccs) + "' == " + "'" + str(catnewfccs) + "'");
   else:
    if(verbose):
     VerbosePrintOut("File Content Checksum Failed at offset " + str(catfcontentstart));
     VerbosePrintOut("'" + str(catfccs) + "' != " + "'" + str(catnewfccs) + "'");
    valid_archive = False;
    invalid_archive = True;
  if(verbose):
   VerbosePrintOut("");
  if(re.findall(r"^\+([0-9]+)", catfseeknextfile)):
   fseeknextasnum = int(catfseeknextfile.replace("+", ""));
   if(abs(fseeknextasnum)==0):
    pass;
   catfp.seek(fseeknextasnum, 1);
  elif(re.findall(r"^\-([0-9]+)", catfseeknextfile)):
   fseeknextasnum = int(catfseeknextfile);
   if(abs(fseeknextasnum)==0):
    pass;
   catfp.seek(fseeknextasnum, 1);
  elif(re.findall(r"^([0-9]+)", catfseeknextfile)):
   fseeknextasnum = int(catfseeknextfile);
   if(abs(fseeknextasnum)==0):
    pass;
   catfp.seek(fseeknextasnum, 0);
  else:
   return False;
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

def ArchiveFileToArray(infile, seekstart=0, seekend=0, listonly=False, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__, returnfp=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 if(hasattr(infile, "read") or hasattr(infile, "write")):
  catfp = infile;
  catfp.seek(0, 0);
  catfp = UncompressArchiveFile(catfp, formatspecs);
  checkcompressfile = CheckCompressionSubType(catfp, formatspecs, True);
  if(checkcompressfile=="tarfile"):
   return TarFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp);
  if(checkcompressfile=="zipfile"):
   return ZipFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp);
  if(rarfile_support and checkcompressfile=="rarfile"):
   return RarFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp);
  if(py7zr_support and checkcompressfile=="7zipfile"):
   return SevenZipFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp);
  if(checkcompressfile!="catfile" and checkcompressfile!=formatspecs['format_lower']):
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
  checkcompressfile = CheckCompressionSubType(infile, formatspecs, True);
  if(checkcompressfile=="tarfile"):
   return TarFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp);
  if(checkcompressfile=="zipfile"):
   return ZipFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp);
  if(rarfile_support and checkcompressfile=="rarfile"):
   return RarFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp);
  if(py7zr_support and checkcompressfile=="7zipfile"):
   return SevenZipFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp);
  if(checkcompressfile!="catfile" and checkcompressfile!=formatspecs['format_lower']):
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
 curloc = catfp.tell();
 if(curloc>0):
  catfp.seek(0, 0);
 catheader = ReadFileHeaderData(catfp, 4, formatspecs['format_delimiter']);
 if(curloc>0):
  catfp.seek(curloc, 0);
 catstring = catheader[0];
 catversion = re.findall(r"([\d]+)", catstring);
 fprenumfiles = catheader[1];
 fnumfiles = int(fprenumfiles, 16);
 fprechecksumtype = catheader[2];
 fprechecksum = catheader[3];
 fileheader = AppendNullByte(catstring, formatspecs['format_delimiter']);
 fnumfileshex = format(int(fnumfiles), 'x').lower();
 fileheader = fileheader + AppendNullBytes([fnumfileshex, fprechecksumtype], formatspecs['format_delimiter']);
 catfileheadercshex = GetFileChecksum(fileheader, fprechecksumtype, True, formatspecs);
 fileheader = fileheader + AppendNullByte(catfileheadercshex, formatspecs['format_delimiter']);
 fheadtell = len(fileheader);
 if(fprechecksum!=catfileheadercshex and not skipchecksum):
  VerbosePrintOut("File Header Checksum Error with file at offset " + str(0));
  VerbosePrintOut("'" + str(fprechecksum) + "' != " + "'" + str(catfileheadercshex) + "'");
  return False;
 catversions = re.search(r'(.*?)(\d+)', catstring).groups();
 catlist = {'fnumfiles': fnumfiles, 'fformat': catversions[0], 'fversion': catversions[1], 'fformatspecs': formatspecs, 'fchecksumtype': fprechecksumtype, 'fheaderchecksum': fprechecksum, 'ffilelist': []};
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
   if(formatspecs['new_style']):
    preheaderdata = ReadFileHeaderDataBySize(catfp, formatspecs['format_delimiter']);
   else:
    preheaderdata = ReadFileHeaderDataWoSize(catfp, formatspecs['format_delimiter']);
   if(len(preheaderdata)==0):
    break;
   prefheadsize = int(preheaderdata[0], 16);
   prefnumfields = int(preheaderdata[1], 16);
   if(re.findall(r"^[.|/]", preheaderdata[3])):
    prefname = preheaderdata[3];
   else:
    prefname = "./"+preheaderdata[3];
   prefsize = int(preheaderdata[5], 16);
   prefcompression = preheaderdata[12];
   prefcsize = int(preheaderdata[13], 16);
   prefseeknextfile = preheaderdata[25];
   prefextrasize = int(preheaderdata[26], 16);
   prefextrafields = int(preheaderdata[27], 16);
   extrafieldslist = [];
   extrastart = 28;
   extraend = extrastart + prefextrafields;
   extrafieldslist = [];
   if(extrastart<extraend):
    extrafieldslist.append(preheaderdata[extrastart]);
    extrastart = extrastart + 1;
   prefcs = preheaderdata[extrastart + 2].lower();
   prefccs = preheaderdata[extrastart + 3].lower();
   prenewfcs = GetHeaderChecksum(preheaderdata[:-2], preheaderdata[-4].lower(), True, formatspecs);
   if(prefcs!=prenewfcs and not skipchecksum):
    VerbosePrintOut("File Header Checksum Error with file " + prefname + " at offset " + str(prefhstart));
    VerbosePrintOut("'" + str(prefcs) + "' != " + "'" + str(prenewfcs) + "'");
    return False;
    valid_archive = False;
    invalid_archive = True;
   prefhend = catfp.tell() - 1;
   prefcontentstart = catfp.tell();
   prefcontents = "";
   pyhascontents = False;
   if(prefsize>0):
    if(prefcompression=="none" or prefcompression=="" or prefcompression=="auto"):
     prefcontents = catfp.read(prefsize);
    else:
     prefcontents = catfp.read(prefcsize);
    prenewfccs = GetFileChecksum(prefcontents, preheaderdata[-3].lower(), False, formatspecs);
    pyhascontents = True;
    if(prefccs!=prenewfccs and not skipchecksum):
     VerbosePrintOut("File Content Checksum Error with file " + prefname + " at offset " + str(prefcontentstart));
     VerbosePrintOut("'" + str(prefccs) + "' != " + "'" + str(prenewfccs) + "'");
     return False;
   if(re.findall(r"^\+([0-9]+)", prefseeknextfile)):
    fseeknextasnum = int(prefseeknextfile.replace("+", ""));
    if(abs(fseeknextasnum)==0):
     pass;
    catfp.seek(fseeknextasnum, 1);
   elif(re.findall(r"^\-([0-9]+)", prefseeknextfile)):
    fseeknextasnum = int(prefseeknextfile);
    if(abs(fseeknextasnum)==0):
     pass;
    catfp.seek(fseeknextasnum, 1);
   elif(re.findall(r"^([0-9]+)", prefseeknextfile)):
    fseeknextasnum = int(prefseeknextfile);
    if(abs(fseeknextasnum)==0):
     pass;
    catfp.seek(fseeknextasnum, 0);
   else:
    return False;
   il = il + 1;
 fileidnum = seekstart;
 realidnum = 0;
 while(fileidnum<seekend):
  catfhstart = catfp.tell();
  if(formatspecs['new_style']):
   catheaderdata = ReadFileHeaderDataBySize(catfp, formatspecs['format_delimiter']);
  else:
   catheaderdata = ReadFileHeaderDataWoSize(catfp, formatspecs['format_delimiter']);
  if(len(catheaderdata)==0):
   break;
  catfheadsize = int(catheaderdata[0], 16);
  catfnumfields = int(catheaderdata[1], 16);
  catftype = int(catheaderdata[2], 16);
  if(re.findall(r"^[.|/]", catheaderdata[3])):
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
  catfcompression = catheaderdata[12];
  catfcsize = int(catheaderdata[13], 16);
  catfuid = int(catheaderdata[14], 16);
  catfuname = catheaderdata[15];
  catfgid = int(catheaderdata[16], 16);
  catfgname = catheaderdata[17];
  catfid = int(catheaderdata[18], 16);
  catfinode = int(catheaderdata[19], 16);
  catflinkcount = int(catheaderdata[20], 16);
  catfdev_minor = int(catheaderdata[21], 16);
  catfdev_major = int(catheaderdata[22], 16);
  catfrdev_minor = int(catheaderdata[23], 16);
  catfrdev_major = int(catheaderdata[24], 16);
  catfseeknextfile = catheaderdata[25];
  catfextrasize = int(catheaderdata[26], 16);
  catfextrafields = int(catheaderdata[27], 16);
  extrafieldslist = [];
  extrastart = 28;
  extraend = extrastart + catfextrafields;
  extrafieldslist = [];
  if(extrastart<extraend):
   extrafieldslist.append(catheaderdata[extrastart]);
   extrastart = extrastart + 1;
  catfcs = catheaderdata[extrastart + 2].lower();
  catfccs = catheaderdata[extrastart + 3].lower();
  catnewfcs = GetHeaderChecksum(catheaderdata[:-2], catheaderdata[-4].lower(), True, formatspecs);
  if(catfcs!=catnewfcs and not skipchecksum):
   VerbosePrintOut("File Header Checksum Error with file " + catfname + " at offset " + str(catfhstart));
   VerbosePrintOut("'" + str(catfcs) + "' != " + "'" + str(catnewfcs) + "'");
   return False;
  catfhend = catfp.tell() - 1;
  catfcontentstart = catfp.tell();
  catfcontents = BytesIO();
  pyhascontents = False;
  if(catfsize>0 and not listonly):
   if(catfcompression=="none" or catfcompression=="" or catfcompression=="auto"):
    catfcontents.write(catfp.read(catfsize));
   else:
    catfcontents.write(catfp.read(catfcsize));
   catfcontents.seek(0, 0);
   catnewfccs = GetFileChecksum(catfcontents.read(), catheaderdata[-3].lower(), False, formatspecs);
   pyhascontents = True;
   if(catfccs!=catnewfccs and skipchecksum):
    VerbosePrintOut("File Content Checksum Error with file " + catfname + " at offset " + str(catfcontentstart));
    VerbosePrintOut("'" + str(catfccs) + "' != " + "'" + str(catnewfccs) + "'");
    return False;
   if(catfcompression=="none" or catfcompression=="" or catfcompression=="auto"):
    pass;
   else:
    catfcontents.seek(0, 0);
    if(uncompress):
     catfcontents = UncompressArchiveFile(catfcontents, formatspecs);
     catfcontents.seek(0, 0);
     catfccs = GetFileChecksum(catfcontents.read(), catheaderdata[-3].lower(), False, formatspecs);
  if(catfsize>0 and listonly):
   if(catfcompression=="none" or catfcompression=="" or catfcompression=="auto"):
    catfp.seek(catfsize, 1);
   else:
    catfp.seek(catfcsize, 1);
   pyhascontents = False;
  catfcontentend = catfp.tell();
  if(re.findall(r"^\+([0-9]+)", catfseeknextfile)):
   fseeknextasnum = int(catfseeknextfile.replace("+", ""));
   if(abs(fseeknextasnum)==0):
    pass;
   catfp.seek(fseeknextasnum, 1);
  elif(re.findall(r"^\-([0-9]+)", catfseeknextfile)):
   fseeknextasnum = int(catfseeknextfile);
   if(abs(fseeknextasnum)==0):
    pass;
   catfp.seek(fseeknextasnum, 1);
  elif(re.findall(r"^([0-9]+)", catfseeknextfile)):
   fseeknextasnum = int(catfseeknextfile);
   if(abs(fseeknextasnum)==0):
    pass;
   catfp.seek(fseeknextasnum, 0);
  else:
   return False;
  catfcontents.seek(0, 0);
  catlist['ffilelist'].append({'fid': realidnum, 'fidalt': fileidnum, 'fheadersize': catfheadsize, 'fhstart': catfhstart, 'fhend': catfhend, 'ftype': catftype, 'fname': catfname, 'fbasedir': catfbasedir, 'flinkname': catflinkname, 'fsize': catfsize, 'fatime': catfatime, 'fmtime': catfmtime, 'fctime': catfctime, 'fbtime': catfbtime, 'fmode': catfmode, 'fchmode': catfchmode, 'ftypemod': catftypemod, 'fwinattributes': catfwinattributes, 'fcompression': catfcompression, 'fcsize': catfcsize, 'fuid': catfuid, 'funame': catfuname, 'fgid': catfgid, 'fgname': catfgname, 'finode': catfinode, 'flinkcount': catflinkcount, 'fminor': catfdev_minor, 'fmajor': catfdev_major, 'frminor': catfrdev_minor, 'frmajor': catfrdev_major, 'fseeknextfile': catfseeknextfile, 'fheaderchecksumtype': catheaderdata[-4], 'fcontentchecksumtype': catheaderdata[-3], 'fnumfields': catfnumfields + 2, 'frawheader': catheaderdata, 'fextrafields': catfextrafields, 'fextrafieldsize': catfextrasize, 'fextralist': extrafieldslist, 'fheaderchecksum': catfcs, 'fcontentchecksum': catfccs, 'fhascontents': pyhascontents, 'fcontentstart': catfcontentstart, 'fcontentend': catfcontentend, 'fcontents': catfcontents});
  fileidnum = fileidnum + 1;
  realidnum = realidnum + 1;
 if(returnfp):
  catlist.update({'catfp': catfp});
 else:
  catfp.close();
 return catlist;

create_alias_function("", __file_format_name__, "ToArray", ArchiveFileToArray);

def ArchiveFileStringToArray(catstr, seekstart=0, seekend=0, listonly=False, skipchecksum=False, formatspecs=__file_format_dict__, returnfp=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 catfp = BytesIO(catstr);
 listcatfiles = ArchiveFileToArray(catfp, seekstart, seekend, listonly, True, skipchecksum, formatspecs, returnfp);
 return listcatfiles;

create_alias_function("", __file_format_name__, "StringToArray", ArchiveFileStringToArray);

def TarFileToArray(infile, seekstart=0, seekend=0, listonly=False, skipchecksum=False, formatspecs=__file_format_dict__, returnfp=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 catfp = BytesIO();
 catfp = PackArchiveFileFromTarFile(infile, catfp, "auto", True, None, "crc32", [], formatspecs, False, True);
 listcatfiles = ArchiveFileToArray(catfp, seekstart, seekend, listonly, True, skipchecksum, formatspecs, returnfp);
 return listcatfiles;

def ZipFileToArray(infile, seekstart=0, seekend=0, listonly=False, skipchecksum=False, formatspecs=__file_format_dict__, returnfp=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 catfp = BytesIO();
 catfp = PackArchiveFileFromZipFile(infile, catfp, "auto", True, None, "crc32", [], formatspecs, False, True);
 listcatfiles = ArchiveFileToArray(catfp, seekstart, seekend, listonly, True, skipchecksum, formatspecs, returnfp);
 return listcatfiles;

if(not rarfile_support):
 def RarFileToArray(infile, seekstart=0, seekend=0, listonly=False, skipchecksum=False, formatspecs=__file_format_dict__, returnfp=False):
  return False;

if(rarfile_support):
 def RarFileToArray(infile, seekstart=0, seekend=0, listonly=False, skipchecksum=False, formatspecs=__file_format_dict__, returnfp=False):
  formatspecs = FormatSpecsListToDict(formatspecs);
  catfp = BytesIO();
  catfp = PackArchiveFileFromSevenZipFile(infile, catfp, "auto", True, None, "crc32", [], formatspecs, False, True);
  listcatfiles = ArchiveFileToArray(catfp, seekstart, seekend, listonly, True, skipchecksum, formatspecs, returnfp);
  return listcatfiles;

if(not py7zr_support):
 def SevenZipFileToArray(infile, seekstart=0, seekend=0, listonly=False, skipchecksum=False, formatspecs=__file_format_dict__, returnfp=False):
  return False;

if(py7zr_support):
 def SevenZipFileToArray(infile, seekstart=0, seekend=0, listonly=False, skipchecksum=False, formatspecs=__file_format_dict__, returnfp=False):
  formatspecs = FormatSpecsListToDict(formatspecs);
  catfp = BytesIO();
  catfp = PackArchiveFileFromSevenZipFile(infile, catfp, "auto", True, None, "crc32", [], formatspecs, False, True);
  listcatfiles = ArchiveFileToArray(catfp, seekstart, seekend, listonly, True, skipchecksum, formatspecs, returnfp);
  return listcatfiles;

def InFileToArray(infile, seekstart=0, seekend=0, listonly=False, skipchecksum=False, formatspecs=__file_format_dict__, returnfp=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 checkcompressfile = CheckCompressionSubType(infile, formatspecs, True);
 if(checkcompressfile=="tarfile"):
  return TarFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp);
 elif(checkcompressfile=="zipfile"):
  return ZipFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp);
 elif(checkcompressfile=="catfile"):
  return ArchiveFileToArray(infile, seekstart, seekend, listonly, True, skipchecksum, formatspecs, returnfp);
 elif(rarfile_support and checkcompressfile=="rarfile"):
  return RarFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp);
 elif(py7zr_support and checkcompressfile=="7zipfile"):
  return SevenZipFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp);
 else:
  return False;
 return False;

def ListDirToArrayAlt(infiles, dirlistfromtxt=False, followlink=False, listonly=False, checksumtype="crc32", extradata=[], formatspecs=__file_format_dict__, verbose=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 catver = formatspecs['format_ver'];
 fileheaderver = str(int(catver.replace(".", "")));
 fileheader = AppendNullByte(formatspecs['format_magic'] + fileheaderver, formatspecs['format_delimiter']);
 advancedlist = formatspecs['use_advanced_list'];
 altinode = formatspecs['use_alt_inode'];
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
 catver = formatspecs['format_ver'];
 fileheaderver = str(int(catver.replace(".", "")));
 fileheader = AppendNullByte(formatspecs['format_magic'] + fileheaderver, formatspecs['format_delimiter']);
 fnumfileshex = format(int(fnumfiles), 'x').lower();
 fileheader = fileheader + AppendNullBytes([fnumfileshex, checksumtype], formatspecs['format_delimiter']);
 catversion = re.findall(r"([\d]+)", fileheader);
 catversions = re.search(r'(.*?)(\d+)', fileheader).groups();
 catfileheadercshex = GetFileChecksum(fileheader, checksumtype, True, formatspecs);
 fileheader = fileheader + AppendNullByte(catfileheadercshex, formatspecs['format_delimiter']);
 fheadtell = len(fileheader);
 catlist = {'fnumfiles': fnumfiles, 'fformat': catversions[0], 'fversion': catversions[1], 'fformatspecs': formatspecs, 'fchecksumtype': checksumtype, 'fheaderchecksum': catfileheadercshex, 'ffilelist': []};
 for curfname in GetDirList:
  catfhstart = fheadtell;
  if(re.findall(r"^[.|/]", curfname)):
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
     if(altinode):
      fcurinode = finode;
     else:
      fcurinode = inodetocatinode[finode];
    if(finode not in inodelist):
     inodelist.append(finode);
     inodetofile.update({finode: fname});
     inodetocatinode.update({finode: curinode});
     if(altinode):
      fcurinode = finode;
     else:
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
  flinkcount = flinkcount;
  if(hasattr(fstatinfo, "st_file_attributes")):
   fwinattributes = fstatinfo.st_file_attributes;
  else:
   fwinattributes = 0;
  fcompression = "";
  fcsize = 0;
  fcontents = BytesIO();
  if(ftype==0 or ftype==7):
   with open(fname, "rb") as fpc:
    shutil.copyfileobj(fpc, fcontents);
  if(followlink and (ftype==1 or ftype==2)):
   flstatinfo = os.stat(flinkname);
   with open(flinkname, "rb") as fpc:
    shutil.copyfileobj(fpc, fcontents);
  fcontents.seek(0, 0);
  ftypehex = format(ftype, 'x').lower();
  extrafields = len(extradata);
  extrafieldslist = extradata;
  catfextrafields = extrafields;
  extrasizestr = AppendNullByte(extrafields, formatspecs['format_delimiter']);
  if(len(extradata)>0):
   extrasizestr = extrasizestr + AppendNullBytes(extradata, formatspecs['format_delimiter']);
  extrasizelen = len(extrasizestr);
  extrasizelenhex = format(extrasizelen, 'x').lower();
  catoutlist = [ftypehex, fname, flinkname, format(int(fsize), 'x').lower(), format(int(fatime), 'x').lower(), format(int(fmtime), 'x').lower(), format(int(fctime), 'x').lower(), format(int(fbtime), 'x').lower(), format(int(fmode), 'x').lower(), format(int(fwinattributes), 'x').lower(), fcompression, format(int(fcsize), 'x').lower(), format(int(fuid), 'x').lower(), funame, format(int(fgid), 'x').lower(), fgname, format(int(fcurfid), 'x').lower(), format(int(fcurinode), 'x').lower(), format(int(flinkcount), 'x').lower(), format(int(fdev_minor), 'x').lower(), format(int(fdev_major), 'x').lower(), format(int(frdev_minor), 'x').lower(), format(int(frdev_major), 'x').lower(), "+1", extrasizelenhex, format(catfextrafields, 'x').lower()];
  catoutlen = len(catoutlist) + len(extradata) + 3;
  catoutlenhex = format(catoutlen, 'x').lower();
  catoutlist.insert(0, catoutlenhex);
  catfileoutstr = AppendNullBytes(catoutlist, formatspecs['format_delimiter']);
  catheaderdata = catoutlist;
  if(len(extradata)>0):
   catfileoutstr = catfileoutstr + AppendNullBytes(extradata, formatspecs['format_delimiter']);
  catfileoutstr = catfileoutstr + AppendNullBytes([checksumtype, checksumtype], formatspecs['format_delimiter']);
  catfnumfields = catoutlen;
  catfileheadercshex = GetFileChecksum(catfileoutstr, checksumtype, True, formatspecs);
  fcontents.seek(0, 0);
  catfilecontentcshex = GetFileChecksum(fcontents.read(), checksumtype, False, formatspecs);
  tmpfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex], formatspecs['format_delimiter']);
  catheaersize = format(int(len(tmpfileoutstr) - 1), 'x').lower();
  catfileoutstr = AppendNullByte(catheaersize, formatspecs['format_delimiter']) + catfileoutstr;
  catfileheadercshex = GetFileChecksum(catfileoutstr, checksumtype, True, formatspecs);
  catfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex], formatspecs['format_delimiter']);
  catfileoutstrecd = catfileoutstr.encode('UTF-8');
  nullstrecd = formatspecs['format_delimiter'].encode('UTF-8');
  catfcontentstart = fheadtell;
  fheadtell += len(catfileoutstr) + 1;
  catfcontentend = fheadtell - 1;
  catfhend = catfcontentend;
  fcontents.seek(0, 0);
  catfileout = catfileoutstrecd + fcontents.read() + nullstrecd;
  pyhascontents = False;
  if(int(fsize)>0 and not listonly):
   pyhascontents = True;
  if(int(fsize)>0 and listonly):
   fcontents = BytesIO();
   pyhascontents = False;
  fcontents.seek(0, 0);
  catlist['ffilelist'].append({'fid': fileidnum, 'fidalt': fileidnum, 'fheadersize': int(catheaersize, 16), 'fhstart': catfhstart, 'fhend': catfhend, 'ftype': ftype, 'fname': fname, 'fbasedir': fbasedir, 'flinkname': flinkname, 'fsize': fsize, 'fatime': fatime, 'fmtime': fmtime, 'fctime': fctime, 'fbtime': fbtime, 'fmode': fmode, 'fchmode': fchmode, 'ftypemod': ftypemod, 'fwinattributes': fwinattributes, 'fcompression': fcompression, 'fcsize': fcsize, 'fuid': fuid, 'funame': funame, 'fgid': fgid, 'fgname': fgname, 'finode': finode, 'flinkcount': flinkcount, 'fminor': fdev_minor, 'fmajor': fdev_major, 'frminor': frdev_minor, 'frmajor': frdev_major, 'fseeknextfile': "+1", 'fheaderchecksumtype': checksumtype, 'fcontentchecksumtype': checksumtype, 'fnumfields': catfnumfields + 2, 'frawheader': catheaderdata, 'fextrafields': catfextrafields, 'fextrafieldsize': extrasizelen, 'fextralist': extrafieldslist, 'fheaderchecksum': int(catfileheadercshex, 16), 'fcontentchecksum': int(catfilecontentcshex, 16), 'fhascontents': pyhascontents, 'fcontentstart': catfcontentstart, 'fcontentend': catfcontentend, 'fcontents': fcontents});
  fileidnum = fileidnum + 1;
 return catlist;

def TarFileToArrayAlt(infile, listonly=False, checksumtype="crc32", extradata=[], formatspecs=__file_format_dict__, verbose=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
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
   if(not tarfile.TarFileCheck(infile)):
    return False;
  except AttributeError:
   if(not TarFileCheck(infile)):
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
 catver = formatspecs['format_ver'];
 fileheaderver = str(int(catver.replace(".", "")));
 fileheader = AppendNullByte(formatspecs['format_magic'] + fileheaderver, formatspecs['format_delimiter']);
 fnumfileshex = format(int(fnumfiles), 'x').lower();
 fileheader = fileheader + AppendNullBytes([fnumfileshex, checksumtype], formatspecs['format_delimiter']);
 catversion = re.findall(r"([\d]+)", fileheader);
 catversions = re.search(r'(.*?)(\d+)', fileheader).groups();
 catfileheadercshex = GetFileChecksum(fileheader, checksumtype, True, formatspecs);
 fileheader = fileheader + AppendNullByte(catfileheadercshex, formatspecs['format_delimiter']);
 fheadtell = len(fileheader);
 catlist = {'fnumfiles': fnumfiles, 'fformat': catversions[0], 'fversion': catversions[1], 'fformatspecs': formatspecs, 'fchecksumtype': checksumtype, 'fheaderchecksum': catfileheadercshex, 'ffilelist': []};
 for member in sorted(tarfp.getmembers(), key=lambda x: x.name):
  catfhstart = fheadtell;
  if(re.findall(r"^[.|/]", member.name)):
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
  fcurinode = curfid;
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
  fcompression = "";
  fcsize = 0;
  fcontents = BytesIO();
  if(ftype==0 or ftype==7):
   with tarfp.extractfile(member) as fpc:
    shutil.copyfileobj(fpc, fcontents);
  fcontents.seek(0, 0);
  ftypehex = format(ftype, 'x').lower();
  extrafields = len(extradata);
  extrafieldslist = extradata;
  catfextrafields = extrafields;
  extrasizestr = AppendNullByte(extrafields, formatspecs['format_delimiter']);
  if(len(extradata)>0):
   extrasizestr = extrasizestr + AppendNullBytes(extradata, formatspecs['format_delimiter']);
  extrasizelen = len(extrasizestr);
  extrasizelenhex = format(extrasizelen, 'x').lower();
  catoutlist = [ftypehex, fname, flinkname, format(int(fsize), 'x').lower(), format(int(fatime), 'x').lower(), format(int(fmtime), 'x').lower(), format(int(fctime), 'x').lower(), format(int(fbtime), 'x').lower(), format(int(fmode), 'x').lower(), format(int(fwinattributes), 'x').lower(), fcompression, format(int(fcsize), 'x').lower(), format(int(fuid), 'x').lower(), funame, format(int(fgid), 'x').lower(), fgname, format(int(fcurfid), 'x').lower(), format(int(fcurinode), 'x').lower(), format(int(flinkcount), 'x').lower(), format(int(fdev_minor), 'x').lower(), format(int(fdev_major), 'x').lower(), format(int(frdev_minor), 'x').lower(), format(int(frdev_major), 'x').lower(), "+1", extrasizelenhex, format(catfextrafields, 'x').lower()];
  catoutlen = len(catoutlist) + len(extradata) + 3;
  catoutlenhex = format(catoutlen, 'x').lower();
  catoutlist.insert(0, catoutlenhex);
  catfileoutstr = AppendNullBytes(catoutlist, formatspecs['format_delimiter']);
  catheaderdata = catoutlist;
  if(len(extradata)>0):
   catfileoutstr = catfileoutstr + AppendNullBytes(extradata, formatspecs['format_delimiter']);
  catfileoutstr = catfileoutstr + AppendNullBytes([checksumtype, checksumtype], formatspecs['format_delimiter']);
  catfnumfields = catoutlen;
  catfileheadercshex = GetFileChecksum(catfileoutstr, checksumtype, True, formatspecs);
  fcontents.seek(0, 0);
  catfilecontentcshex = GetFileChecksum(fcontents.read(), checksumtype, False, formatspecs);
  tmpfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex], formatspecs['format_delimiter']);
  catheaersize = format(int(len(tmpfileoutstr) - 1), 'x').lower();
  catfileoutstr = AppendNullByte(catheaersize, formatspecs['format_delimiter']) + catfileoutstr;
  catfileheadercshex = GetFileChecksum(catfileoutstr, checksumtype, True, formatspecs);
  catfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex], formatspecs['format_delimiter']);
  catfileoutstrecd = catfileoutstr.encode('UTF-8');
  nullstrecd = formatspecs['format_delimiter'].encode('UTF-8');
  catfcontentstart = fheadtell;
  fheadtell += len(catfileoutstr) + 1;
  catfcontentend = fheadtell - 1;
  catfhend = catfcontentend;
  fcontents.seek(0, 0);
  catfileout = catfileoutstrecd + fcontents.read() + nullstrecd;
  pyhascontents = False;
  if(int(fsize)>0 and not listonly):
   pyhascontents = True;
  if(int(fsize)>0 and listonly):
   fcontents = BytesIO();
   pyhascontents = False;
  fcontents.seek(0, 0);
  catlist['ffilelist'].append({'fid': fileidnum, 'fidalt': fileidnum, 'fheadersize': int(catheaersize, 16), 'fhstart': catfhstart, 'fhend': catfhend, 'ftype': ftype, 'fname': fname, 'fbasedir': fbasedir, 'flinkname': flinkname, 'fsize': fsize, 'fatime': fatime, 'fmtime': fmtime, 'fctime': fctime, 'fbtime': fbtime, 'fmode': fmode, 'fchmode': fchmode, 'ftypemod': ftypemod, 'fwinattributes': fwinattributes, 'fcompression': fcompression, 'fcsize': fcsize, 'fuid': fuid, 'funame': funame, 'fgid': fgid, 'fgname': fgname, 'finode': finode, 'flinkcount': flinkcount, 'fminor': fdev_minor, 'fmajor': fdev_major, 'frminor': frdev_minor, 'frmajor': frdev_major, 'fseeknextfile': "+1", 'fheaderchecksumtype': checksumtype, 'fcontentchecksumtype': checksumtype, 'fnumfields': catfnumfields + 2, 'frawheader': catheaderdata, 'fextrafields': catfextrafields, 'fextrafieldsize': extrasizelen, 'fextralist': extrafieldslist, 'fheaderchecksum': int(catfileheadercshex, 16), 'fcontentchecksum': int(catfilecontentcshex, 16), 'fhascontents': pyhascontents, 'fcontentstart': catfcontentstart, 'fcontentend': catfcontentend, 'fcontents': fcontents});
  fileidnum = fileidnum + 1;
 return catlist;

def ZipFileToArrayAlt(infile, listonly=False, checksumtype="crc32", extradata=[], formatspecs=__file_format_dict__, verbose=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
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
 catver = formatspecs['format_ver'];
 fileheaderver = str(int(catver.replace(".", "")));
 fileheader = AppendNullByte(formatspecs['format_magic'] + fileheaderver, formatspecs['format_delimiter']);
 catversion = re.findall(r"([\d]+)", fileheader);
 catversions = re.search(r'(.*?)(\d+)', fileheader).groups();
 fnumfileshex = format(int(fnumfiles), 'x').lower();
 fileheader = fileheader + AppendNullBytes([fnumfileshex, checksumtype], formatspecs['format_delimiter']);
 catfileheadercshex = GetFileChecksum(fileheader, checksumtype, True, formatspecs);
 fileheader = fileheader + AppendNullByte(catfileheadercshex, formatspecs['format_delimiter']);
 fheadtell = len(fileheader);
 catlist = {'fnumfiles': fnumfiles, 'fformat': catversions[0], 'fversion': catversions[1], 'fformatspecs': formatspecs, 'fchecksumtype': checksumtype, 'fheaderchecksum': catfileheadercshex, 'ffilelist': []};
 for member in sorted(zipfp.infolist(), key=lambda x: x.filename):
  catfhstart = fheadtell;
  if(re.findall(r"^[.|/]", member.filename)):
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
  fcurinode = curfid;
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
   fwinattributes = int(zipinfo.external_attr);
   if(not member.is_dir()):
    fmode = int(stat.S_IFREG + 438);
    fchmode = int(stat.S_IMODE(int(stat.S_IFREG + 438)));
    ftypemod = int(stat.S_IFMT(int(stat.S_IFREG + 438)));
   elif(member.is_dir()):
    fmode = int(stat.S_IFDIR + 511);
    fchmode = int(stat.S_IMODE(int(stat.S_IFDIR + 511)));
    ftypemod = int(stat.S_IFMT(int(stat.S_IFDIR + 511)));
  elif(zipinfo.create_system==3):
   fwinattributes = int(0);
   fmode = int(zipinfo.external_attr);
  else:
   fwinattributes = int(0);
   if(not member.is_dir()):
    fmode = int(stat.S_IFREG + 438);
    fchmode = int(stat.S_IMODE(int(stat.S_IFREG + 438)));
    ftypemod = int(stat.S_IFMT(int(stat.S_IFREG + 438)));
   elif(member.is_dir()):
    fmode = int(stat.S_IFDIR + 511);
    fchmode = int(stat.S_IMODE(int(stat.S_IFDIR + 511)));
    ftypemod = int(stat.S_IFMT(int(stat.S_IFDIR + 511)));
  fcompression = "";
  fcsize = 0;
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
  fcontents = BytesIO();
  if(ftype==0):
   fcontents.write(zipfp.read(member.filename));
  fcontents.seek(0, 0);
  ftypehex = format(ftype, 'x').lower();
  extrafields = len(extradata);
  extrafieldslist = extradata;
  catfextrafields = extrafields;
  extrasizestr = AppendNullByte(extrafields, formatspecs['format_delimiter']);
  if(len(extradata)>0):
   extrasizestr = extrasizestr + AppendNullBytes(extradata, formatspecs['format_delimiter']);
  extrasizelen = len(extrasizestr);
  extrasizelenhex = format(extrasizelen, 'x').lower();
  catoutlist = [ftypehex, fname, flinkname, format(int(fsize), 'x').lower(), format(int(fatime), 'x').lower(), format(int(fmtime), 'x').lower(), format(int(fctime), 'x').lower(), format(int(fbtime), 'x').lower(), format(int(fmode), 'x').lower(), format(int(fwinattributes), 'x').lower(), fcompression, format(int(fcsize), 'x').lower(), format(int(fuid), 'x').lower(), funame, format(int(fgid), 'x').lower(), fgname, format(int(fcurfid), 'x').lower(), format(int(fcurinode), 'x').lower(), format(int(flinkcount), 'x').lower(), format(int(fdev_minor), 'x').lower(), format(int(fdev_major), 'x').lower(), format(int(frdev_minor), 'x').lower(), format(int(frdev_major), 'x').lower(), "+1", extrasizelenhex, format(catfextrafields, 'x').lower()];
  catoutlen = len(catoutlist) + len(extradata) + 3;
  catoutlenhex = format(catoutlen, 'x').lower();
  catoutlist.insert(0, catoutlenhex);
  catfileoutstr = AppendNullBytes(catoutlist, formatspecs['format_delimiter']);
  catheaderdata = catoutlist;
  if(len(extradata)>0):
   catfileoutstr = catfileoutstr + AppendNullBytes(extradata, formatspecs['format_delimiter']);
  catfileoutstr = catfileoutstr + AppendNullBytes([checksumtype, checksumtype], formatspecs['format_delimiter']);
  catfnumfields = catoutlen;
  catfileheadercshex = GetFileChecksum(catfileoutstr, checksumtype, True, formatspecs);
  fcontents.seek(0, 0);
  catfilecontentcshex = GetFileChecksum(fcontents.read(), checksumtype, False, formatspecs);
  tmpfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex], formatspecs['format_delimiter']);
  catheaersize = format(int(len(tmpfileoutstr) - 1), 'x').lower();
  catfileoutstr = AppendNullByte(catheaersize, formatspecs['format_delimiter']) + catfileoutstr;
  catfileheadercshex = GetFileChecksum(catfileoutstr, checksumtype, True, formatspecs);
  catfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex], formatspecs['format_delimiter']);
  catfileoutstrecd = catfileoutstr.encode('UTF-8');
  nullstrecd = formatspecs['format_delimiter'].encode('UTF-8');
  catfcontentstart = fheadtell;
  fheadtell += len(catfileoutstr) + 1;
  catfcontentend = fheadtell - 1;
  catfhend = catfcontentend;
  fcontents.seek(0, 0);
  catfileout = catfileoutstrecd + fcontents.read() + nullstrecd;
  pyhascontents = False;
  if(int(fsize)>0 and not listonly):
   pyhascontents = True;
  if(int(fsize)>0 and listonly):
   fcontents = BytesIO();
   pyhascontents = False;
  fcontents.seek(0, 0);
  catlist['ffilelist'].append({'fid': fileidnum, 'fidalt': fileidnum, 'fheadersize': int(catheaersize, 16), 'fhstart': catfhstart, 'fhend': catfhend, 'ftype': ftype, 'fname': fname, 'fbasedir': fbasedir, 'flinkname': flinkname, 'fsize': fsize, 'fatime': fatime, 'fmtime': fmtime, 'fctime': fctime, 'fbtime': fbtime, 'fmode': fmode, 'fchmode': fchmode, 'ftypemod': ftypemod, 'fwinattributes': fwinattributes, 'fcompression': fcompression, 'fcsize': fcsize, 'fuid': fuid, 'funame': funame, 'fgid': fgid, 'fgname': fgname, 'finode': finode, 'flinkcount': flinkcount, 'fminor': fdev_minor, 'fmajor': fdev_major, 'frminor': frdev_minor, 'frmajor': frdev_major, 'fseeknextfile': "+1", 'fheaderchecksumtype': checksumtype, 'fcontentchecksumtype': checksumtype, 'fnumfields': catfnumfields + 2, 'frawheader': catheaderdata, 'fextrafields': catfextrafields, 'fextrafieldsize': extrasizelen, 'fextralist': extrafieldslist, 'fheaderchecksum': int(catfileheadercshex, 16), 'fcontentchecksum': int(catfilecontentcshex, 16), 'fhascontents': pyhascontents, 'fcontentstart': catfcontentstart, 'fcontentend': catfcontentend, 'fcontents': fcontents});
  fileidnum = fileidnum + 1;
 return catlist;

if(not rarfile_support):
 def RarFileToArrayAlt(infile, listonly=False, checksumtype="crc32", extradata=[], formatspecs=__file_format_dict__, verbose=False):
  return False;

if(rarfile_support):
 def RarFileToArrayAlt(infile, listonly=False, checksumtype="crc32", extradata=[], formatspecs=__file_format_dict__, verbose=False):
  formatspecs = FormatSpecsListToDict(formatspecs);
  curinode = 0;
  curfid = 0;
  inodelist = [];
  inodetofile = {};
  filetoinode = {};
  inodetocatinode = {};
  fileidnum = 0;
  if(not os.path.exists(infile,) or not os.path.isfile(infile,)):
   return False;
  if(not rarfile.is_rarfile(infile) and not rarfile.is_rarfile_sfx(infile)):
   return False;
  rarfp = rarfile.RarFile(infile, "r");
  rartest = rarfp.testrar();
  if(rartest):
   VerbosePrintOut("Bad file found!");
  fnumfiles = int(len(rarfp.infolist()));
  catver = formatspecs['format_ver'];
  fileheaderver = str(int(catver.replace(".", "")));
  fileheader = AppendNullByte(formatspecs['format_magic'] + fileheaderver, formatspecs['format_delimiter']);
  catversion = re.findall(r"([\d]+)", fileheader);
  catversions = re.search(r'(.*?)(\d+)', fileheader).groups();
  fnumfileshex = format(int(fnumfiles), 'x').lower();
  fileheader = fileheader + AppendNullBytes([fnumfileshex, checksumtype], formatspecs['format_delimiter']);
  catfileheadercshex = GetFileChecksum(fileheader, checksumtype, True, formatspecs);
  fileheader = fileheader + AppendNullByte(catfileheadercshex, formatspecs['format_delimiter']);
  fheadtell = len(fileheader);
  catlist = {'fnumfiles': fnumfiles, 'fformat': catversions[0], 'fversion': catversions[1], 'fformatspecs': formatspecs, 'fchecksumtype': checksumtype, 'fheaderchecksum': catfileheadercshex, 'ffilelist': []};
  for member in sorted(rarfp.infolist(), key=lambda x: x.filename):
   catfhstart = fheadtell;
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
   if(re.findall(r"^[.|/]", member.filename)):
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
   fcompression = "";
   fcsize = 0;
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
   fcurinode = curfid;
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
    fmode = int(member.external_attr);
    fchmode = int(stat.S_IMODE(member.external_attr));
    ftypemod = int(stat.S_IFMT(member.external_attr));
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
   fcontents = BytesIO();
   if(ftype==0):
    fcontents.write(rarfp.read(member.filename));
   fcontents.seek(0, 0);
   ftypehex = format(ftype, 'x').lower();
   extrafields = len(extradata);
   extrafieldslist = extradata;
   catfextrafields = extrafields;
   extrasizestr = AppendNullByte(extrafields, formatspecs['format_delimiter']);
   if(len(extradata)>0):
    extrasizestr = extrasizestr + AppendNullBytes(extradata, formatspecs['format_delimiter']);
   extrasizelen = len(extrasizestr);
   extrasizelenhex = format(extrasizelen, 'x').lower();
   catoutlist = [ftypehex, fname, flinkname, format(int(fsize), 'x').lower(), format(int(fatime), 'x').lower(), format(int(fmtime), 'x').lower(), format(int(fctime), 'x').lower(), format(int(fbtime), 'x').lower(), format(int(fmode), 'x').lower(), format(int(fwinattributes), 'x').lower(), fcompression, format(int(fcsize), 'x').lower(), format(int(fuid), 'x').lower(), funame, format(int(fgid), 'x').lower(), fgname, format(int(fcurfid), 'x').lower(), format(int(fcurinode), 'x').lower(), format(int(flinkcount), 'x').lower(), format(int(fdev_minor), 'x').lower(), format(int(fdev_major), 'x').lower(), format(int(frdev_minor), 'x').lower(), format(int(frdev_major), 'x').lower(), "+1", extrasizelenhex, format(catfextrafields, 'x').lower()];
   catoutlen = len(catoutlist) + len(extradata) + 3;
   catoutlenhex = format(catoutlen, 'x').lower();
   catoutlist.insert(0, catoutlenhex);
   catfileoutstr = AppendNullBytes(catoutlist, formatspecs['format_delimiter']);
   if(len(extradata)>0):
    catfileoutstr = catfileoutstr + AppendNullBytes(extradata, formatspecs['format_delimiter']);
   ccatfileoutstr = catfileoutstr + AppendNullBytes([checksumtype, checksumtype], formatspecs['format_delimiter']);
   catfnumfields = 24 + catfextrafields;
   catfileheadercshex = GetFileChecksum(catfileoutstr, checksumtype, True, formatspecs);
   fcontents.seek(0, 0);
   catfilecontentcshex = GetFileChecksum(fcontents.read(), checksumtype, False, formatspecs);
   tmpfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex], formatspecs['format_delimiter']);
   catheaersize = format(int(len(tmpfileoutstr) - 1), 'x').lower();
   catfileoutstr = AppendNullByte(catheaersize, formatspecs['format_delimiter']) + catfileoutstr;
   catfileheadercshex = GetFileChecksum(catfileoutstr, checksumtype, True, formatspecs);
   catfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex], formatspecs['format_delimiter']);
   catheaderdata = catoutlist;
   catfileoutstrecd = catfileoutstr.encode('UTF-8');
   nullstrecd = formatspecs['format_delimiter'].encode('UTF-8');
   catfcontentstart = fheadtell;
   fheadtell += len(catfileoutstr) + 1;
   catfcontentend = fheadtell - 1;
   catfhend = catfcontentend;
   fcontents.seek(0, 0);
   catfileout = catfileoutstrecd + fcontents.read() + nullstrecd;
   pyhascontents = False;
   if(int(fsize)>0 and not listonly):
    pyhascontents = True;
   if(int(fsize)>0 and listonly):
    fcontents = BytesIO();
    pyhascontents = False;
   fcontents.seek(0, 0);
   catlist['ffilelist'].append({'fid': fileidnum, 'fidalt': fileidnum, 'fheadersize': int(catheaersize, 16), 'fhstart': catfhstart, 'fhend': catfhend, 'ftype': ftype, 'fname': fname, 'fbasedir': fbasedir, 'flinkname': flinkname, 'fsize': fsize, 'fatime': fatime, 'fmtime': fmtime, 'fctime': fctime, 'fbtime': fbtime, 'fmode': fmode, 'fchmode': fchmode, 'ftypemod': ftypemod, 'fwinattributes': fwinattributes, 'fcompression': fcompression, 'fcsize': fcsize, 'fuid': fuid, 'funame': funame, 'fgid': fgid, 'fgname': fgname, 'finode': finode, 'flinkcount': flinkcount, 'fminor': fdev_minor, 'fmajor': fdev_major, 'frminor': frdev_minor, 'frmajor': frdev_major, 'fseeknextfile': "+1", 'fheaderchecksumtype': checksumtype, 'fcontentchecksumtype': checksumtype, 'fnumfields': catfnumfields + 2, 'frawheader': catheaderdata, 'fextrafields': catfextrafields, 'fextrafieldsize': extrasizelen, 'fextralist': extrafieldslist, 'fheaderchecksum': int(catfileheadercshex, 16), 'fcontentchecksum': int(catfilecontentcshex, 16), 'fhascontents': pyhascontents, 'fcontentstart': catfcontentstart, 'fcontentend': catfcontentend, 'fcontents': fcontents});
   fileidnum = fileidnum + 1;
  return catlist;

if(not py7zr_support):
 def SevenZipFileToArrayAlt(infile, listonly=False, checksumtype="crc32", extradata=[], formatspecs=__file_format_dict__, verbose=False):
  return False;

if(py7zr_support):
 def SevenZipFileToArrayAlt(infile, listonly=False, checksumtype="crc32", extradata=[], formatspecs=__file_format_dict__, verbose=False):
  formatspecs = FormatSpecsListToDict(formatspecs);
  curinode = 0;
  curfid = 0;
  inodelist = [];
  inodetofile = {};
  filetoinode = {};
  inodetocatinode = {};
  fileidnum = 0;
  szpfp = py7zr.SevenZipFile(infile, mode="r");
  file_content = szpfp.readall();
  #sztest = szpfp.testzip();
  sztestalt = szpfp.test();
  if(sztestalt):
   VerbosePrintOut("Bad file found!");
  numfiles = int(len(szpfp.list()));
  catver = formatspecs['format_ver'];
  fileheaderver = str(int(catver.replace(".", "")));
  fileheader = AppendNullByte(formatspecs['format_magic'] + fileheaderver, formatspecs['format_delimiter']);
  catversion = re.findall(r"([\d]+)", fileheader);
  catversions = re.search(r'(.*?)(\d+)', fileheader).groups();
  fnumfileshex = format(int(fnumfiles), 'x').lower();
  fileheader = fileheader + AppendNullBytes([fnumfileshex, checksumtype], formatspecs['format_delimiter']);
  catfileheadercshex = GetFileChecksum(fileheader, checksumtype, True, formatspecs);
  fileheader = fileheader + AppendNullByte(catfileheadercshex, formatspecs['format_delimiter']);
  fheadtell = len(fileheader);
  catlist = {'fnumfiles': fnumfiles, 'fformat': catversions[0], 'fversion': catversions[1], 'fformatspecs': formatspecs, 'fchecksumtype': checksumtype, 'fheaderchecksum': catfileheadercshex, 'ffilelist': []};
  for member in sorted(szpfp.list(), key=lambda x: x.filename):
   catfhstart = fheadtell;
   if(re.findall(r"^[.|/]", member.filename)):
    fname = member.filename;
   else:
    fname = "./"+member.filename;
   if(not member.is_directory):
    fpremode = int(stat.S_IFREG + 438);
   elif(member.is_directory):
    fpremode = int(stat.S_IFDIR + 511);
   fwinattributes = int(0);
   fcompression = "";
   fcsize = 0;
   flinkcount = 0;
   ftype = 0;
   if(member.is_directory):
    ftype = 5;
   else:
    ftype = 0;
   flinkname = "";
   fbasedir = os.path.dirname(fname);
   fcurfid = curfid;
   fcurinode = curfid;
   finode = fcurinode;
   curfid = curfid + 1;
   fdev_minor = 0;
   fdev_major = 0;
   frdev_minor = 0;
   frdev_major = 0;
   if(ftype==5):
    fsize = "0";
   fatime = int(member.creationtime.timestamp());
   fmtime = int(member.creationtime.timestamp());
   fctime = int(member.creationtime.timestamp());
   fbtime = int(member.creationtime.timestamp());
   if(member.is_directory):
    fmode = int(stat.S_IFDIR + 511)
    fchmode = int(stat.S_IMODE(stat.S_IFDIR + 511));
    ftypemod = int(stat.S_IFMT(stat.S_IFDIR + 511));
   else:
    fmode = int(stat.S_IFLNK + 438)
    fchmode = int(stat.S_IMODE(stat.S_IFREG + 438));
    ftypemod = int(stat.S_IFMT(stat.S_IFREG + 438));
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
   fcontents = BytesIO();
   if(ftype==0):
    fcontents.write(file_content[member.filename].read());
    fsize = format(fcontents.tell(), 'x').lower();
    fileop.close();
   fcontents.seek(0, 0);
   ftypehex = format(ftype, 'x').lower();
   extrafields = len(extradata);
   extrafieldslist = extradata;
   catfextrafields = extrafields;
   extrasizestr = AppendNullByte(extrafields, formatspecs['format_delimiter']);
   if(len(extradata)>0):
    extrasizestr = extrasizestr + AppendNullBytes(extradata, formatspecs['format_delimiter']);
   extrasizelen = len(extrasizestr);
   extrasizelenhex = format(extrasizelen, 'x').lower();
   catoutlist = [ftypehex, fname, flinkname, format(int(fsize), 'x').lower(), format(int(fatime), 'x').lower(), format(int(fmtime), 'x').lower(), format(int(fctime), 'x').lower(), format(int(fbtime), 'x').lower(), format(int(fmode), 'x').lower(), format(int(fwinattributes), 'x').lower(), fcompression, format(int(fcsize), 'x').lower(), format(int(fuid), 'x').lower(), funame, format(int(fgid), 'x').lower(), fgname, format(int(fcurfid), 'x').lower(), format(int(fcurinode), 'x').lower(), format(int(flinkcount), 'x').lower(), format(int(fdev_minor), 'x').lower(), format(int(fdev_major), 'x').lower(), format(int(frdev_minor), 'x').lower(), format(int(frdev_major), 'x').lower(), "+1", extrasizelenhex, format(catfextrafields, 'x').lower()];
   catoutlen = len(catoutlist) + len(extradata) + 3;
   catoutlenhex = format(catoutlen, 'x').lower();
   catoutlist.insert(0, catoutlenhex);
   catfileoutstr = AppendNullBytes(catoutlist, formatspecs['format_delimiter']);
   catheaderdata = catoutlist;
   if(len(extradata)>0):
    catfileoutstr = catfileoutstr + AppendNullBytes(extradata, formatspecs['format_delimiter']);
   catfileoutstr = catfileoutstr + AppendNullBytes([checksumtype, checksumtype], formatspecs['format_delimiter']);
   catfnumfields = 24 + catfextrafields;
   catfileheadercshex = GetFileChecksum(catfileoutstr, checksumtype, True, formatspecs);
   fcontents.seek(0, 0);
   catfilecontentcshex = GetFileChecksum(fcontents.read(), checksumtype, False, formatspecs);
   tmpfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex], formatspecs['format_delimiter']);
   catheaersize = format(int(len(tmpfileoutstr) - 1), 'x').lower();
   catfileoutstr = AppendNullByte(catheaersize, formatspecs['format_delimiter']) + catfileoutstr;
   catfileheadercshex = GetFileChecksum(catfileoutstr, checksumtype, True, formatspecs);
   catfileoutstr = catfileoutstr + AppendNullBytes([catfileheadercshex, catfilecontentcshex], formatspecs['format_delimiter']);
   catfileoutstrecd = catfileoutstr.encode('UTF-8');
   nullstrecd = formatspecs['format_delimiter'].encode('UTF-8');
   catfcontentstart = fheadtell;
   fheadtell += len(catfileoutstr) + 1;
   catfcontentend = fheadtell - 1;
   catfhend = catfcontentend;
   fcontents.seek(0, 0);
   catfileout = catfileoutstrecd + fcontents.read() + nullstrecd;
   pyhascontents = False;
   if(int(fsize)>0 and not listonly):
    pyhascontents = True;
   if(int(fsize)>0 and listonly):
    fcontents = BytesIO();
    pyhascontents = False;
   fcontents.seek(0, 0);
   catlist['ffilelist'].append({'fid': fileidnum, 'fidalt': fileidnum, 'fheadersize': int(catheaersize, 16), 'fhstart': catfhstart, 'fhend': catfhend, 'ftype': ftype, 'fname': fname, 'fbasedir': fbasedir, 'flinkname': flinkname, 'fsize': fsize, 'fatime': fatime, 'fmtime': fmtime, 'fctime': fctime, 'fbtime': fbtime, 'fmode': fmode, 'fchmode': fchmode, 'ftypemod': ftypemod, 'fwinattributes': fwinattributes, 'fcompression': fcompression, 'fcsize': fcsize, 'fuid': fuid, 'funame': funame, 'fgid': fgid, 'fgname': fgname, 'finode': finode, 'flinkcount': flinkcount, 'fminor': fdev_minor, 'fmajor': fdev_major, 'frminor': frdev_minor, 'frmajor': frdev_major, 'fseeknextfile': "+1", 'fheaderchecksumtype': checksumtype, 'fcontentchecksumtype': checksumtype, 'fnumfields': catfnumfields + 2, 'frawheader': catheaderdata, 'fextrafields': catfextrafields, 'fextrafieldsize': extrasizelen, 'fextralist': extrafieldslist, 'fheaderchecksum': int(catfileheadercshex, 16), 'fcontentchecksum': int(catfilecontentcshex, 16), 'fhascontents': pyhascontents, 'fcontentstart': catfcontentstart, 'fcontentend': catfcontentend, 'fcontents': fcontents});
   fileidnum = fileidnum + 1;
  return catlist;

def InFileToArrayAlt(infile, listonly=False, checksumtype="crc32", extradata=[], formatspecs=__file_format_dict__, verbose=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 checkcompressfile = CheckCompressionSubType(infile, formatspecs, True);
 if(checkcompressfile=="tarfile"):
  return TarFileToArrayAlt(infile, listonly, checksumtype, extradata, formatspecs, verbose);
 elif(checkcompressfile=="zipfile"):
  return ZipFileToArrayAlt(infile, listonly, checksumtype, extradata, formatspecs, verbose);
 elif(checkcompressfile=="catfile"):
  return ArchiveFileToArray(infile, 0, 0, listonly, True, False, formatspecs, False);
 elif(rarfile_support and checkcompressfile=="rarfile"):
  return RarFileToArrayAlt(infile, listonly, checksumtype, extradata, formatspecs, verbose);
 elif(py7zr_support and checkcompressfile=="7zipfile"):
  return SevenZipFileToArrayAlt(infile, listonly, checksumtype, extradata, formatspecs, verbose);
 else:
  return False;
 return False;

def ListDirToArray(infiles, dirlistfromtxt=False, compression="auto", compresswholefile=True, compressionlevel=None, followlink=False, seekstart=0, seekend=0, listonly=False, skipchecksum=False, checksumtype="crc32", extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 outarray = BytesIO();
 packcat = PackArchiveFile(infiles, outarray, dirlistfromtxt, compression, compresswholefile, compressionlevel, followlink, checksumtype, extradata, formatspecs, verbose, True);
 listcatfiles = ArchiveFileToArray(outarray, seekstart, seekend, listonly, True, skipchecksum, formatspecs, returnfp);
 return listcatfiles;

def ArchiveFileArrayToArrayIndex(inarray, seekstart=0, seekend=0, listonly=False, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__, returnfp=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 if(isinstance(inarray, dict)):
  listcatfiles = inarray;
 else:
  return False;
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

create_alias_function("", __file_format_name__, "ArrayToArrayIndex", ArchiveFileArrayToArrayIndex);

def RePackArchiveFile(infile, outfile, compression="auto", compresswholefile=True, compressionlevel=None, followlink=False, seekstart=0, seekend=0, checksumtype="crc32", skipchecksum=False, extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 if(isinstance(infile, dict)):
  listcatfiles = infile;
 else:
  if(infile!="-" and not hasattr(infile, "read") and not hasattr(infile, "write")):
   infile = RemoveWindowsPath(infile);
  listcatfiles = ArchiveFileToArray(infile, seekstart, seekend, False, True, skipchecksum, formatspecs, returnfp);
 if(outfile!="-" and not hasattr(infile, "read") and not hasattr(outfile, "write")):
  outfile = RemoveWindowsPath(outfile);
 checksumtype = checksumtype.lower();
 if(not CheckSumSupport(checksumtype, hashlib_guaranteed)):
  checksumtype="crc32";
 if(checksumtype=="none"):
  checksumtype = "";
 if(not compression or compression=="catfile" or compression==formatspecs['format_lower']):
  compression = "auto";
 if(compression not in compressionlist and compression is None):
  compression = "auto";
 if(verbose):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(outfile!="-" and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
  if(os.path.exists(outfile)):
   try:
    os.unlink(outfile);
   except OSError as e:
    pass;
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
  catfp = CompressOpenFile(outfile, compresswholefile, compressionlevel);
 catver = formatspecs['format_ver'];
 fileheaderver = str(int(catver.replace(".", "")));
 lenlist = len(listcatfiles['ffilelist']);
 fnumfiles = int(listcatfiles['fnumfiles']);
 if(lenlist>fnumfiles or lenlist<fnumfiles):
  fnumfiles = lenlist;
 AppendFileHeader(catfp, fnumfiles, checksumtype, formatspecs);
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
  if(re.findall(r"^[.|/]", listcatfiles['ffilelist'][reallcfi]['fname'])):
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
  finode = format(int(listcatfiles['ffilelist'][reallcfi]['finode']), 'x').lower();
  flinkcount = format(int(listcatfiles['ffilelist'][reallcfi]['flinkcount']), 'x').lower();
  fwinattributes = format(int(listcatfiles['ffilelist'][reallcfi]['fwinattributes']), 'x').lower();
  fcompression = listcatfiles['ffilelist'][reallcfi]['fcompression'];
  fcsize = format(int(listcatfiles['ffilelist'][reallcfi]['fcsize']), 'x').lower();
  fdev_minor = format(int(listcatfiles['ffilelist'][reallcfi]['fminor']), 'x').lower();
  fdev_major = format(int(listcatfiles['ffilelist'][reallcfi]['fmajor']), 'x').lower();
  frdev_minor = format(int(listcatfiles['ffilelist'][reallcfi]['frminor']), 'x').lower();
  frdev_major = format(int(listcatfiles['ffilelist'][reallcfi]['frmajor']), 'x').lower();
  fseeknextfile = listcatfiles['ffilelist'][reallcfi]['fseeknextfile'];
  if(len(listcatfiles['ffilelist'][reallcfi]['fextralist'])>listcatfiles['ffilelist'][reallcfi]['fextrafields'] and len(listcatfiles['ffilelist'][reallcfi]['fextralist'])>0):
   listcatfiles['ffilelist'][reallcfi]['fextrafields'] = len(listcatfiles['ffilelist'][reallcfi]['fextralist']);
  if(not followlink and len(extradata)<0):
   extradata = listcatfiles['ffilelist'][reallcfi]['fextralist'];
  fcontents = listcatfiles['ffilelist'][reallcfi]['fcontents'];
  fcompression = "";
  fcsize = format(int(0), 'x').lower();
  if(not compresswholefile):
   fcontents.seek(0, 2);
   ucfsize = fcontents.tell();
   fcontents.seek(0, 0);
   if(compression=="auto"):
    ilsize = len(compressionlistalt);
    ilmin = 0;
    ilcsize = [];
    while(ilmin < ilsize):
     cfcontents = BytesIO();
     shutil.copyfileobj(fcontents, cfcontents);
     fcontents.seek(0, 0);
     cfcontents.seek(0, 0);
     cfcontents = CompressArchiveFile(cfcontents, compressionlistalt[ilmin], compressionlevel, formatspecs);
     if(cfcontents):
      cfcontents.seek(0, 2);
      ilcsize.append(cfcontents.tell());
      cfcontents.close();
     else:
      try:
       ilcsize.append(sys.maxint);
      except AttributeError:
       ilcsize.append(sys.maxsize);
     ilmin = ilmin + 1;
    ilcmin = ilcsize.index(min(ilcsize));
    compression = compressionlistalt[ilcmin];
   fcontents.seek(0, 0);
   cfcontents = BytesIO();
   shutil.copyfileobj(fcontents, cfcontents);
   cfcontents.seek(0, 0);
   cfcontents = CompressArchiveFile(cfcontents, compression, compressionlevel, formatspecs);
   cfcontents.seek(0, 2);
   cfsize = cfcontents.tell();
   if(ucfsize > cfsize):
    fcsize = format(int(cfsize), 'x').lower();
    fcompression = compression;
    fcontents.close();
    fcontents = cfcontents;
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
    finode = format(int(flinkinfo['finode']), 'x').lower();
    flinkcount = format(int(flinkinfo['flinkcount']), 'x').lower();
    fwinattributes = format(int(flinkinfo['fwinattributes']), 'x').lower();
    fcompression = flinkinfo['fcompression'];
    fcsize = format(int(flinkinfo['fcsize']), 'x').lower();
    fdev_minor = format(int(flinkinfo['fminor']), 'x').lower();
    fdev_major = format(int(flinkinfo['fmajor']), 'x').lower();
    frdev_minor = format(int(flinkinfo['frminor']), 'x').lower();
    frdev_major = format(int(flinkinfo['frmajor']), 'x').lower();
    fseeknextfile = flinkinfo['fseeknextfile'];
    if(len(flinkinfo['fextralist'])>flinkinfo['fextrafields'] and len(flinkinfo['fextralist'])>0):
     flinkinfo['fextrafields'] = len(flinkinfo['fextralist']);
    if(len(extradata)<0):
     extradata = flinkinfo['fextralist'];
    fcontents = flinkinfo['fcontents'];
    ftypehex = format(flinkinfo['ftype'], 'x').lower();
  else:
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
  if(fcompression=="none"):
   fcompression = "";
  catoutlist = [ftypehex, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression, fcsize, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev_minor, fdev_major, frdev_minor, frdev_major, fseeknextfile];
  catfp = AppendFileHeaderWithContent(catfp, catoutlist, extradata, fcontents.read(), checksumtype, formatspecs);
  fcontents.close();
  lcfi = lcfi + 1;
  reallcfi = reallcfi + 1;
 if(lcfx>0):
  catfp.write(AppendNullBytes([0, 0], formatspecs['format_delimiter']).encode("UTF-8"));
 if(outfile=="-" or hasattr(outfile, "read") or hasattr(outfile, "write")):
  catfp = CompressArchiveFile(catfp, compression, compressionlevel, formatspecs);
  try:
   catfp.flush();
   os.fsync(catfp.fileno());
  except io.UnsupportedOperation:
   pass;
  except AttributeError:
   pass;
  except OSError as e:
   pass;
 if(outfile=="-"):
  catfp.seek(0, 0);
  if(hasattr(sys.stdout, "buffer")):
   shutil.copyfileobj(catfp, sys.stdout.buffer);
  else:
   shutil.copyfileobj(catfp, sys.stdout);
 elif(re.findall(r"^(ftp|ftps|sftp)\:\/\/", str(outfile))):
  catfp = CompressArchiveFile(catfp, compression, compressionlevel, formatspecs);
  catfp.seek(0, 0);
  upload_file_to_internet_file(catfp, outfile);
 if(returnfp):
  catfp.seek(0, 0);
  return catfp;
 else:
  catfp.close();
  return True;

create_alias_function("RePack", __file_format_name__, "", RePackArchiveFile);

def RePackArchiveFileFromString(catstr, outfile, compression="auto", compresswholefile=True, compressionlevel=None, checksumtype="crc32", skipchecksum=False, extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 catfp = BytesIO(catstr);
 listcatfiles = RePackArchiveFile(catfp, compression, compresswholefile, compressionlevel, checksumtype, skipchecksum, extradata, formatspecs, verbose, returnfp);
 return listcatfiles;

create_alias_function("RePack", __file_format_name__, "FromString", RePackArchiveFileFromString);

def PackArchiveFileFromListDir(infiles, outfile, dirlistfromtxt=False, compression="auto", compresswholefile=True, compressionlevel=None, followlink=False, skipchecksum=False, checksumtype="crc32", extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 outarray = BytesIO();
 packcat = PackArchiveFile(infiles, outarray, dirlistfromtxt, compression, compresswholefile, compressionlevel, followlink, checksumtype, extradata, formatspecs, verbose, True);
 listcatfiles = RePackArchiveFile(outarray, outfile, compression, compresswholefile, compressionlevel, checksumtype, skipchecksum, extradata, formatspecs, verbose, returnfp);
 return listcatfiles;

create_alias_function("Pack", __file_format_name__, "FromListDir", PackArchiveFileFromListDir);

def UnPackArchiveFile(infile, outdir=None, followlink=False, seekstart=0, seekend=0, skipchecksum=False, formatspecs=__file_format_dict__, preservepermissions=True, preservetime=True, verbose=False, returnfp=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 if(outdir is not None):
  outdir = RemoveWindowsPath(outdir);
 if(verbose):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(isinstance(infile, dict)):
  listcatfiles = infile;
 else:
  if(infile!="-" and not hasattr(infile, "read") and not hasattr(infile, "write")):
   infile = RemoveWindowsPath(infile);
  listcatfiles = ArchiveFileToArray(infile, seekstart, seekend, False, True, skipchecksum, formatspecs, returnfp);
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
    listcatfiles['ffilelist'][lcfi]['fcontents'].seek(0, 0);
    shutil.copyfileobj(listcatfiles['ffilelist'][lcfi]['fcontents'], fpc);
    try:
     fpc.flush();
     os.fsync(fpc.fileno());
    except io.UnsupportedOperation:
     pass;
    except AttributeError:
     pass;
    except OSError as e:
     pass;
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
      flinkinfo['fcontents'].seek(0, 0);
      shutil.copyfileobj(flinkinfo['fcontents'], fpc);
      try:
       fpc.flush();
       os.fsync(fpc.fileno());
      except io.UnsupportedOperation:
       pass;
      except AttributeError:
       pass;
      except OSError as e:
       pass;
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
      flinkinfo['fcontents'].seek(0, 0);
      shutil.copyfileobj(flinkinfo['fcontents'], fpc);
      try:
       fpc.flush();
       os.fsync(fpc.fileno());
      except io.UnsupportedOperation:
       pass;
      except AttributeError:
       pass;
      except OSError as e:
       pass;
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
  return UnPackArchiveFile(archive_name, extract_dir, False, 0, 0, False, __file_format_dict__['format_delimiter'], False, False);
 create_alias_function("UnPack", __file_format_name__, "Func", UnPackArchiveFileFunc);

def UnPackArchiveFileString(catstr, outdir=None, followlink=False, seekstart=0, seekend=0, skipchecksum=False, formatspecs=__file_format_dict__, verbose=False, returnfp=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 catfp = BytesIO(catstr);
 listcatfiles = UnPackArchiveFile(catfp, outdir, followlink, seekstart, seekend, skipchecksum, formatspecs, verbose, returnfp);
 return listcatfiles;

create_alias_function("UnPack", __file_format_name__, "String", UnPackArchiveFileString);

def ArchiveFileListFiles(infile, seekstart=0, seekend=0, skipchecksum=False, formatspecs=__file_format_dict__, verbose=False, returnfp=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 if(isinstance(infile, dict)):
  listcatfiles = infile;
 else:
  if(infile!="-" and not hasattr(infile, "read") and not hasattr(infile, "write")):
   infile = RemoveWindowsPath(infile);
  listcatfiles = ArchiveFileToArray(infile, seekstart, seekend, True, False, skipchecksum, formatspecs, returnfp);
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

def ArchiveFileStringListFiles(catstr, seekstart=0, seekend=0, skipchecksum=False, formatspecs=__file_format_dict__, verbose=False, returnfp=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 catfp = BytesIO(catstr);
 listcatfiles = ArchiveFileListFiles(catstr, seekstart, seekend, skipchecksum, formatspecs, verbose, returnfp);
 return listcatfiles;

create_alias_function("", __file_format_name__, "StringListFiles", ArchiveFileStringListFiles);

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
   if(not tarfile.TarFileCheck(infile)):
    return False;
  except AttributeError:
   if(not TarFileCheck(infile)):
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
 lcfi = 0
 returnval = {};
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

if(not py7zr_support):
 def SevenZipFileListFiles(infile, verbose=False, returnfp=False):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
  if(not os.path.exists(infile) or not os.path.isfile(infile)):
   return False;

if(py7zr_support):
 def SevenZipFileListFiles(infile, verbose=False, returnfp=False):
  logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
  if(not os.path.exists(infile) or not os.path.isfile(infile)):
   return False;
  lcfi = 0;
  returnval = {};
  szpfp = py7zr.SevenZipFile(infile, mode="r");
  file_content = szpfp.readall();
  #sztest = szpfp.testzip();
  sztestalt = szpfp.test();
  if(sztestalt):
   VerbosePrintOut("Bad file found!");
  for member in sorted(szpfp.list(), key=lambda x: x.filename):
   if(re.findall(r"^[.|/]", member.filename)):
    fname = member.filename;
   else:
    fname = "./"+member.filename;
   if(not member.is_directory):
    fpremode = int(stat.S_IFREG + 438);
   elif(member.is_directory):
    fpremode = int(stat.S_IFDIR + 511);
   fwinattributes = int(0);
   if(member.is_directory):
    fmode = int(stat.S_IFDIR + 511);
    fchmode = int(stat.S_IMODE(int(stat.S_IFDIR + 511)));
    ftypemod = int(stat.S_IFMT(int(stat.S_IFDIR + 511)));
   else:
    fmode = int(stat.S_IFLNK + 438);
    fchmode = int(stat.S_IMODE(int(stat.S_IFLNK + 438)));
    ftypemod = int(stat.S_IFMT(int(stat.S_IFLNK + 438)));
   returnval.update({lcfi: member.filename});
   if(not verbose):
    VerbosePrintOut(member.filename);
   if(verbose):
    permissions = { 'access': { '0': ('---'), '1': ('--x'), '2': ('-w-'), '3': ('-wx'), '4': ('r--'), '5': ('r-x'), '6': ('rw-'), '7': ('rwx') }, 'roles': { 0: 'owner', 1: 'group', 2: 'other' } };
    permissionstr = "";
    for fmodval in str(oct(fmode))[-3:]:
     permissionstr = permissionstr + permissions['access'].get(fmodval, '---');
    fsize = int("0");
    if(not member.is_directory):
     ftype = 0;
     permissionstr = "-" + permissionstr;
     printfname = member.filename;
    elif(member.is_directory):
     ftype = 5;
     permissionstr = "d" + permissionstr;
     printfname = member.filename;
    if(ftype==0):
     fsize = len(file_content[member.filename].read());
     file_content[member.filename].close();
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
    VerbosePrintOut(PrintPermissionString(fmode, ftype) + " " + str(str(fuprint) + "/" + str(fgprint) + " " + str(fsize).rjust(15) + " " + member.creationtime.strftime('%Y-%m-%d %H:%M') + " " + printfname));
   lcfi = lcfi + 1;
  if(returnfp):
   return listcatfiles['catfp'];
  else:
   return True;

def InFileListFiles(infile, verbose=False, formatspecs=__file_format_dict__, returnfp=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG);
 checkcompressfile = CheckCompressionSubType(infile, formatspecs, True);
 if(checkcompressfile=="tarfile"):
  return TarFileListFiles(infile, verbose, returnfp);
 elif(checkcompressfile=="zipfile"):
  return ZipFileListFiles(infile, verbose, returnfp);
 elif(checkcompressfile=="catfile"):
  return ArchiveFileListFiles(infile, 0, 0, False, formatspecs, verbose, returnfp);
 elif(rarfile_support and checkcompressfile=="rarfile"):
  return RarFileListFiles(infile, verbose, returnfp);
 elif(py7zr_support and checkcompressfile=="7zipfile"):
  return SevenZipFileListFiles(infile, verbose, returnfp);
 else:
  return False;
 return False;

def ListDirListFiles(infiles, dirlistfromtxt=False, compression="auto", compresswholefile=True, compressionlevel=None, followlink=False, seekstart=0, seekend=0, skipchecksum=False, checksumtype="crc32", formatspecs=__file_format_dict__, verbose=False, returnfp=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 outarray = BytesIO();
 packcat = PackArchiveFile(infiles, outarray, dirlistfromtxt, compression, compresswholefile, compressionlevel, followlink, checksumtype, formatspecs, False, True);
 listcatfiles = ArchiveFileListFiles(outarray, seekstart, seekend, skipchecksum, formatspecs, verbose, returnfp);
 return listcatfiles;

def ListDirListFilesAlt(infiles, dirlistfromtxt=False, followlink=False, listonly=False, seekstart=0, seekend=0, skipchecksum=False, checksumtype="crc32", formatspecs=__file_format_dict__, verbose=False, returnfp=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 outarray = ListDirToArrayAlt(infiles, dirlistfromtxt, followlink, listonly, checksumtype, formatspecs, verbose);
 listcatfiles = ArchiveFileListFiles(outarray, seekstart, seekend, skipchecksum, formatspecs, verbose, returnfp);
 return listcatfiles;

def PackArchiveFileFromListDirAlt(infiles, outfile, dirlistfromtxt=False, compression="auto", compresswholefile=True, compressionlevel=None, followlink=False, skipchecksum=False, checksumtype="crc32", extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 outarray = ListDirToArrayAlt(infiles, dirlistfromtxt, followlink, False, checksumtype, extradata, formatspecs, False);
 listcatfiles = RePackArchiveFile(outarray, outfile, compression, compresswholefile, compressionlevel, followlink, checksumtype, skipchecksum, extradata, formatspecs, verbose, returnfp);
 return listcatfiles;

create_alias_function("Pack", __file_format_name__, "FromListDirAlt", PackArchiveFileFromListDirAlt);

def PackArchiveFileFromTarFileAlt(infile, outfile, compression="auto", compresswholefile=True, compressionlevel=None, checksumtype="crc32", extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 outarray = TarFileToArrayAlt(infile, False, checksumtype, extradata, formatspecs, False);
 listcatfiles = RePackArchiveFile(outarray, outfile, compression, compresswholefile, compressionlevel, False, checksumtype, False, extradata, formatspecs, verbose, returnfp);
 return listcatfiles;

create_alias_function("Pack", __file_format_name__, "FromTarFileAlt", PackArchiveFileFromTarFileAlt);

def PackArchiveFileFromZipFileAlt(infile, outfile, compression="auto", compresswholefile=True, compressionlevel=None, checksumtype="crc32", extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
 formatspecs = FormatSpecsListToDict(formatspecs);
 outarray = ZipFileToArrayAlt(infile, False, checksumtype, extradata, formatspecs, False);
 listcatfiles = RePackArchiveFile(outarray, outfile, compression, compresswholefile, compressionlevel, False, checksumtype, False, extradata, formatspecs, verbose, returnfp);
 return listcatfiles;

create_alias_function("Pack", __file_format_name__, "FromZipFileAlt", PackArchiveFileFromZipFileAlt);

if(not rarfile_support):
 def PackArchiveFileFromRarFileAlt(infile, outfile, compression="auto", compresswholefile=True, compressionlevel=None, checksumtype="crc32", extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
  return False;

if(rarfile_support):
 def PackArchiveFileFromRarFileAlt(infile, outfile, compression="auto", compresswholefile=True, compressionlevel=None, checksumtype="crc32", extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
  formatspecs = FormatSpecsListToDict(formatspecs);
  outarray = RarFileToArrayAlt(infile, False, checksumtype, extradata, formatspecs, False);
  listcatfiles = RePackArchiveFile(outarray, outfile, compression, compresswholefile, compressionlevel, False, checksumtype, False, extradata, formatspecs, verbose, returnfp);
  return listcatfiles;

create_alias_function("Pack", __file_format_name__, "FromRarFileAlt", PackArchiveFileFromRarFileAlt);

if(not py7zr_support):
 def PackArchiveFileFromSevenZipFileAlt(infile, outfile, compression="auto", compresswholefile=True, compressionlevel=None, checksumtype="crc32", extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
  return False;

if(py7zr_support):
 def PackArchiveFileFromSevenZipFileAlt(infile, outfile, compression="auto", compresswholefile=True, compressionlevel=None, checksumtype="crc32", extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
  formatspecs = FormatSpecsListToDict(formatspecs);
  outarray = SevenZipFileToArrayAlt(infile, False, checksumtype, extradata, formatspecs, False);
  listcatfiles = RePackArchiveFile(outarray, outfile, compression, compresswholefile, compressionlevel, False, checksumtype, False, extradata, formatspecs, verbose, returnfp);
  return listcatfiles;

create_alias_function("Pack", __file_format_name__, "FromSevenZipFileAlt", PackArchiveFileFromSevenZipFileAlt);

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
 elif(urlparts.scheme=="ftps" and ftpssl):
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
 elif(urlparts.scheme=="ftps" and ftpssl):
  ftp = FTP_TLS();
 else:
  return False;
 if(urlparts.scheme=="sftp"):
  if(__use_pysftp__):
   return upload_file_to_pysftp_file(url);
  else:
   return upload_file_to_sftp_file(url);
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
   return upload_file_to_ftp_file(url);
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
   return upload_file_to_ftp_file(url);
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

def download_file_from_internet_uncompress_file(url, headers=geturls_headers_pycatfile_python_alt, formatspecs=__file_format_dict__):
 formatspecs = FormatSpecsListToDict(formatspecs);
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

def download_file_from_internet_uncompress_string(url, headers=geturls_headers_pycatfile_python_alt, formatspecs=__file_format_dict__):
 formatspecs = FormatSpecsListToDict(formatspecs);
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
  return upload_file_to_ftp_file(ifp, url);
 elif(urlparts.scheme=="sftp"):
  if(__use_pysftp__ and havepysftp):
   return upload_file_to_pysftp_file(ifp, url);
  else:
   return upload_file_to_sftp_file(ifp, url);
 else:
  return False;
 return False;

def upload_file_to_internet_compress_file(ifp, url, formatspecs=__file_format_dict__):
 formatspecs = FormatSpecsListToDict(formatspecs);
 catfp = CompressArchiveFile(catfp, compression, compressionlevel, formatspecs);
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
  return upload_file_to_ftp_string(ifp, url);
 elif(urlparts.scheme=="sftp"):
  if(__use_pysftp__ and havepysftp):
   return upload_file_to_pysftp_string(ifp, url);
  else:
   return upload_file_to_sftp_string(ifp, url);
 else:
  return False;
 return False;
 
def upload_file_to_internet_compress_string(ifp, url, formatspecs=__file_format_dict__):
 formatspecs = FormatSpecsListToDict(formatspecs);
 catfp = CompressArchiveFile(BytesIO(ifp), compression, compressionlevel, formatspecs);
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
