#!/usr/bin/env python
# -*- coding: UTF-8 -*-

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

    $FileInfo: pycatfile.py - Last Update: 1/21/2025 Ver. 0.16.6 RC 1 - Author: cooldude2k $
'''

from __future__ import absolute_import, division, print_function, unicode_literals, generators, with_statement, nested_scopes
import io
import os
import re
import sys
import time
import stat
import zlib
import base64
import shutil
import socket
import hashlib
import inspect
import datetime
import logging
import zipfile
import binascii
import platform
import mimetypes
try:
    from backports import tempfile
except ImportError:
    import tempfile
# FTP Support
ftpssl = True
try:
    from ftplib import FTP, FTP_TLS
except ImportError:
    ftpssl = False
    from ftplib import FTP

try:
    import ujson as json
except ImportError:
    try:
        import simplejson as json
    except ImportError:
        import json

try:
    import configparser
except ImportError:
    try:
        import SafeConfigParser as configparser
    except ImportError:
        import ConfigParser as configparser

try:
    file
except NameError:
    from io import IOBase
    file = IOBase
#if isinstance(outfile, file) or isinstance(outfile, IOBase):

try:
    basestring
except NameError:
    basestring = str

baseint = []
try:
    baseint.append(long)
    baseint.insert(0, int)
except NameError:
    baseint.append(int)
baseint = tuple(baseint)

# URL Parsing
try:
    from urllib.parse import urlparse, urlunparse
except ImportError:
    from urlparse import urlparse, urlunparse

# Windows-specific setup
if os.name == 'nt':
    if sys.version_info[0] == 2:
        import codecs
        sys.stdout = codecs.getwriter('UTF-8')(sys.stdout)
        sys.stderr = codecs.getwriter('UTF-8')(sys.stderr)
    else:
        sys.stdout = io.TextIOWrapper(
            sys.stdout.buffer, encoding='UTF-8', errors='replace', line_buffering=True)
        sys.stderr = io.TextIOWrapper(
            sys.stderr.buffer, encoding='UTF-8', errors='replace', line_buffering=True)

hashlib_guaranteed = False
# Environment setup
os.environ["PYTHONIOENCODING"] = "UTF-8"

# Reload sys to set default encoding to UTF-8 (Python 2 only)
if sys.version_info[0] == 2:
    try:
        reload(sys)
        sys.setdefaultencoding('UTF-8')
    except (NameError, AttributeError):
        pass

# CRC32 import
try:
    from zlib import crc32
except ImportError:
    from binascii import crc32

# Define FileNotFoundError for Python 2
try:
    FileNotFoundError
except NameError:
    FileNotFoundError = IOError

# RAR file support
rarfile_support = False
try:
    import rarfile
    rarfile_support = True
except ImportError:
    pass
except OSError:
    pass

# 7z file support
py7zr_support = False
try:
    import py7zr
    py7zr_support = True
except ImportError:
    pass
except OSError:
    pass

# TAR file checking
try:
    from xtarfile import is_tarfile
except ImportError:
    try:
        from safetar import is_tarfile
    except ImportError:
        from tarfile import is_tarfile

# TAR file module
try:
    import xtarfile as tarfile
except ImportError:
    try:
        import safetar as tarfile
    except ImportError:
        import tarfile

# Paramiko support
haveparamiko = False
try:
    import paramiko
    haveparamiko = True
except ImportError:
    pass
except OSError:
    pass

# PySFTP support
havepysftp = False
try:
    import pysftp
    havepysftp = True
except ImportError:
    pass
except OSError:
    pass

# Add the mechanize import check
havemechanize = False
try:
    import mechanize
    havemechanize = True
except ImportError:
    pass
except OSError:
    pass

# Requests support
haverequests = False
try:
    import requests
    haverequests = True
    import urllib3
    logging.getLogger("urllib3").setLevel(logging.WARNING)
except ImportError:
    pass
except OSError:
    pass

# HTTPX support
havehttpx = False
try:
    import httpx
    havehttpx = True
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
except ImportError:
    pass
except OSError:
    pass

# HTTP and URL parsing
try:
    from urllib.request import Request, build_opener, HTTPBasicAuthHandler
    from urllib.parse import urlparse
except ImportError:
    from urllib2 import Request, build_opener, HTTPBasicAuthHandler
    from urlparse import urlparse

# StringIO and BytesIO
try:
    from io import StringIO, BytesIO
except ImportError:
    try:
        from cStringIO import StringIO
        from cStringIO import StringIO as BytesIO
    except ImportError:
        from StringIO import StringIO
        from StringIO import StringIO as BytesIO

def get_importing_script_path():
    # Inspect the stack and get the frame of the caller
    stack = inspect.stack()
    for frame_info in stack:
        # In Python 2, frame_info is a tuple; in Python 3, it's a named tuple
        filename = frame_info[1] if isinstance(frame_info, tuple) else frame_info.filename
        if filename != __file__:  # Ignore current module's file
            return os.path.abspath(filename)
    return None

def get_default_threads():
    """Returns the number of CPU threads available, or 1 if unavailable."""
    try:
        cpu_threads = os.cpu_count()
        return cpu_threads if cpu_threads is not None else 1
    except AttributeError:
        # os.cpu_count() might not be available in some environments
        return 1


__use_pysftp__ = False
__use_alt_format__ = False
__use_env_file__ = True
__use_ini_file__ = True
if('PYCATFILE_CONFIG_FILE' in os.environ and os.path.exists(os.environ['PYCATFILE_CONFIG_FILE']) and __use_env_file__):
    scriptconf = os.environ['PYCATFILE_CONFIG_FILE']
else:
    prescriptpath = get_importing_script_path()
    if(prescriptpath is not None):
        scriptconf = os.path.join(os.path.dirname(prescriptpath), "catfile.ini")
    else:
        scriptconf = ""
if os.path.exists(scriptconf):
    __config_file__ = scriptconf
else:
    __config_file__ = os.path.join(os.path.dirname(os.path.realpath(__file__)), "catfile.ini")
if(not havepysftp):
    __use_pysftp__ = False
__use_http_lib__ = "httpx"
if(__use_http_lib__ == "httpx" and haverequests and not havehttpx):
    __use_http_lib__ = "requests"
if(__use_http_lib__ == "requests" and havehttpx and not haverequests):
    __use_http_lib__ = "httpx"
if((__use_http_lib__ == "httpx" or __use_http_lib__ == "requests") and not havehttpx and not haverequests):
    __use_http_lib__ = "urllib"
if os.path.exists(__config_file__) and __use_ini_file__:
    config = configparser.ConfigParser()
    config.read(__config_file__)
    __use_alt_format__ = config.getboolean('config', 'usealt')
    main_fmt = config.get('config', 'mainfmt')
    alt_fmt = config.get('config', 'altfmt')
    def decode_unicode_escape(value):
        if sys.version_info[0] < 3:  # Python 2
            return value.decode('unicode_escape')
        else:  # Python 3
            return bytes(value, 'UTF-8').decode('unicode_escape')
    __file_format_main__ = {'format_name': config.get(main_fmt, 'name'), 'format_magic': decode_unicode_escape(config.get(main_fmt, 'magic')), 'format_lower': config.get(main_fmt, 'lower'), 'format_len': config.getint(main_fmt, 'len'), 'format_hex': config.get(main_fmt, 'hex'), 'format_delimiter': decode_unicode_escape(config.get(main_fmt, 'delimiter')), 'format_ver': config.get(main_fmt, 'ver'), 'new_style': config.getboolean(main_fmt, 'newstyle'), 'use_advanced_list': config.getboolean(main_fmt, 'advancedlist'), 'use_alt_inode': config.getboolean(main_fmt, 'altinode'), 'format_extension': config.get(main_fmt, 'extension'), 'program_name': config.get(main_fmt, 'proname')}
    __file_format_alt__ = {'format_name': config.get(alt_fmt, 'name'), 'format_magic': decode_unicode_escape(config.get(alt_fmt, 'magic')), 'format_lower': config.get(alt_fmt, 'lower'), 'format_len': config.getint(alt_fmt, 'len'), 'format_hex': config.get(alt_fmt, 'hex'), 'format_delimiter': decode_unicode_escape(config.get(alt_fmt, 'delimiter')), 'format_ver': config.get(alt_fmt, 'ver'), 'new_style': config.getboolean(alt_fmt, 'newstyle'), 'use_advanced_list': config.getboolean(alt_fmt, 'advancedlist'), 'use_alt_inode': config.getboolean(alt_fmt, 'altinode'), 'format_extension': config.get(alt_fmt, 'extension'), 'program_name': config.get(alt_fmt, 'proname')}
else:
    __file_format_main__ = {'format_name': "CatFile", 'format_magic': "CatFile", 'format_lower': "catfile", 'format_len': 7, 'format_hex': "43617446696c65", 'format_delimiter': "\x00", 'format_ver': "001", 'new_style': True, 'use_advanced_list': True, 'use_alt_inode': False, 'format_extension': ".cat", 'program_name': "PyCatFile"}
    __file_format_alt_eng__ = __file_format_main__
    __file_format_alt__ = {'format_name': "NekoFile", 'format_magic': "ねこファイル", 'format_lower': "nekofile", 'format_len': 21, 'format_hex': "e381ade38193e38395e382a1e382a4e383abe", 'format_delimiter': "\x00", 'format_ver': "001", 'new_style': True, 'use_advanced_list': True, 'use_alt_inode': False, 'format_extension': ".neko", 'program_name': "PyNekoFile"}
    __file_format_alt_jpn__ = __file_format_alt__
    __file_format_alt_kor__ = { 'format_name': "NekoFile", 'format_magic': "네코파일", 'format_lower': "nekofile", 'format_len': 15, 'format_hex': "eb84a4ecbd94ed8c8c", 'format_delimiter': "\x00", 'format_ver': "001", 'new_style': True, 'use_advanced_list': True, 'use_alt_inode': False, 'format_extension': ".neko", 'program_name': "PyNekoFile"}
if not __use_alt_format__:
    __file_format_name__ = __file_format_main__['format_name']
    __program_name__ = __file_format_main__['program_name']
    __file_format_lower__ = __file_format_main__['format_lower']
    __file_format_magic__ = __file_format_main__['format_magic']
    __file_format_len__ = __file_format_main__['format_len']
    __file_format_hex__ = __file_format_main__['format_hex']
    __file_format_delimiter__ = __file_format_main__['format_delimiter']
    __file_format_ver__ = __file_format_main__['format_ver']
    __use_new_style__ = __file_format_main__['new_style']
    __use_advanced_list__ = __file_format_main__['use_advanced_list']
    __use_alt_inode__ = __file_format_main__['use_alt_inode']
    __file_format_extension__ = __file_format_main__['format_extension']
else:
    __file_format_name__ =  __file_format_alt__['format_name']
    __program_name__ =  __file_format_alt__['program_name']
    __file_format_lower__ =  __file_format_alt__['format_lower']
    __file_format_magic__ =  __file_format_alt__['format_magic']
    __file_format_len__ =  __file_format_alt__['format_len']
    __file_format_hex__ =  __file_format_alt__['format_hex']
    __file_format_delimiter__ =  __file_format_alt__['format_delimiter']
    __file_format_ver__ =  __file_format_alt__['format_ver']
    __use_new_style__ =  __file_format_alt__['new_style']
    __use_advanced_list__ =  __file_format_alt__['use_advanced_list']
    __use_alt_inode__ =  __file_format_alt__['use_alt_inode']
    __file_format_extension__ =  __file_format_alt__['format_extension']
__file_format_multi_dict__ = {}
__file_format_multi_dict__.update({__file_format_main__['format_magic']: __file_format_main__})
__file_format_multi_dict__.update({__file_format_alt__['format_magic']: __file_format_alt__})
try:
    __file_format_multi_dict__.update({__file_format_alt_kor__['format_magic']: __file_format_alt_kor__})
except:
    pass
__file_format_dict__ = {'format_name': __file_format_name__, 'format_magic': __file_format_magic__, 'format_lower': __file_format_lower__, 'format_len': __file_format_len__, 'format_hex': __file_format_hex__, 'format_delimiter': __file_format_delimiter__, 'format_ver': __file_format_ver__, 'new_style': __use_new_style__, 'use_advanced_list': __use_advanced_list__, 'use_alt_inode': __use_alt_inode__, 'format_extension': __file_format_extension__, 'program_name': __program_name__}
__project__ = __program_name__
__project_url__ = "https://github.com/GameMaker2k/PyCatFile"
__version_info__ = (0, 16, 4, "RC 1", 1)
__version_date_info__ = (2025, 1, 15, "RC 1", 1)
__version_date__ = str(__version_date_info__[0]) + "." + str(
    __version_date_info__[1]).zfill(2) + "." + str(__version_date_info__[2]).zfill(2)
__revision__ = __version_info__[3]
__revision_id__ = "$Id$"
if(__version_info__[4] is not None):
    __version_date_plusrc__ = __version_date__ + \
        "-" + str(__version_date_info__[4])
if(__version_info__[4] is None):
    __version_date_plusrc__ = __version_date__
if(__version_info__[3] is not None):
    __version__ = str(__version_info__[0]) + "." + str(__version_info__[
        1]) + "." + str(__version_info__[2]) + " " + str(__version_info__[3])
if(__version_info__[3] is None):
    __version__ = str(__version_info__[
                      0]) + "." + str(__version_info__[1]) + "." + str(__version_info__[2])

PyBitness = platform.architecture()
if(PyBitness == "32bit" or PyBitness == "32"):
    PyBitness = "32"
elif(PyBitness == "64bit" or PyBitness == "64"):
    PyBitness = "64"
else:
    PyBitness = "32"

geturls_ua_pycatfile_python = "Mozilla/5.0 (compatible; {proname}/{prover}; +{prourl})".format(
    proname=__project__, prover=__version__, prourl=__project_url__)
if(platform.python_implementation() != ""):
    py_implementation = platform.python_implementation()
if(platform.python_implementation() == ""):
    py_implementation = "Python"
geturls_ua_pycatfile_python_alt = "Mozilla/5.0 ({osver}; {archtype}; +{prourl}) {pyimp}/{pyver} (KHTML, like Gecko) {proname}/{prover}".format(osver=platform.system(
)+" "+platform.release(), archtype=platform.machine(), prourl=__project_url__, pyimp=py_implementation, pyver=platform.python_version(), proname=__project__, prover=__version__)
geturls_ua_googlebot_google = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
geturls_ua_googlebot_google_old = "Googlebot/2.1 (+http://www.google.com/bot.html)"
geturls_headers_pycatfile_python = {'Referer': "http://google.com/", 'User-Agent': geturls_ua_pycatfile_python, 'Accept-Encoding': "none", 'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6", 'Accept-Charset': "ISO-8859-1,ISO-8859-15,UTF-8;q=0.7,*;q=0.7", 'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'Connection': "close",
                                    'SEC-CH-UA': "\""+__project__+"\";v=\""+str(__version__)+"\", \"Not;A=Brand\";v=\"8\", \""+py_implementation+"\";v=\""+str(platform.release())+"\"", 'SEC-CH-UA-FULL-VERSION': str(__version__), 'SEC-CH-UA-PLATFORM': ""+py_implementation+"", 'SEC-CH-UA-ARCH': ""+platform.machine()+"", 'SEC-CH-UA-PLATFORM': str(__version__), 'SEC-CH-UA-BITNESS': str(PyBitness)}
geturls_headers_pycatfile_python_alt = {'Referer': "http://google.com/", 'User-Agent': geturls_ua_pycatfile_python_alt, 'Accept-Encoding': "none", 'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6", 'Accept-Charset': "ISO-8859-1,ISO-8859-15,UTF-8;q=0.7,*;q=0.7", 'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'Connection': "close",
                                        'SEC-CH-UA': "\""+__project__+"\";v=\""+str(__version__)+"\", \"Not;A=Brand\";v=\"8\", \""+py_implementation+"\";v=\""+str(platform.release())+"\"", 'SEC-CH-UA-FULL-VERSION': str(__version__), 'SEC-CH-UA-PLATFORM': ""+py_implementation+"", 'SEC-CH-UA-ARCH': ""+platform.machine()+"", 'SEC-CH-UA-PLATFORM': str(__version__), 'SEC-CH-UA-BITNESS': str(PyBitness)}
geturls_headers_googlebot_google = {'Referer': "http://google.com/", 'User-Agent': geturls_ua_googlebot_google, 'Accept-Encoding': "none", 'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6",
                                    'Accept-Charset': "ISO-8859-1,ISO-8859-15,UTF-8;q=0.7,*;q=0.7", 'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'Connection': "close"}
geturls_headers_googlebot_google_old = {'Referer': "http://google.com/", 'User-Agent': geturls_ua_googlebot_google_old, 'Accept-Encoding': "none", 'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6",
                                        'Accept-Charset': "ISO-8859-1,ISO-8859-15,UTF-8;q=0.7,*;q=0.7", 'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'Connection': "close"}

compressionsupport = []
try:
    import gzip
    compressionsupport.append("gz")
    compressionsupport.append("gzip")
except ImportError:
    pass
try:
    import bz2
    compressionsupport.append("bz2")
    compressionsupport.append("bzip2")
except ImportError:
    pass
try:
    import lz4
    import lz4.frame
    compressionsupport.append("lz4")
except ImportError:
    pass
try:
    import lzo
    compressionsupport.append("lzo")
    compressionsupport.append("lzop")
except ImportError:
    pass
try:
    import zstandard
    compressionsupport.append("zst")
    compressionsupport.append("zstd")
    compressionsupport.append("zstandard")
except ImportError:
    try:
        import pyzstd.zstdfile
        compressionsupport.append("zst")
        compressionsupport.append("zstd")
        compressionsupport.append("zstandard")
    except ImportError:
        pass
try:
    import lzma
    compressionsupport.append("lzma")
    compressionsupport.append("xz")
except ImportError:
    try:
        from backports import lzma
        compressionsupport.append("lzma")
        compressionsupport.append("xz")
    except ImportError:
        pass
compressionsupport.append("zlib")
compressionsupport.append("zl")
compressionsupport.append("zz")

compressionlist = ['auto']
compressionlistalt = []
outextlist = []
outextlistwd = []
if('gzip' in compressionsupport):
    compressionlist.append('gzip')
    compressionlistalt.append('gzip')
    outextlist.append('gz')
    outextlistwd.append('.gz')
if('bzip2' in compressionsupport):
    compressionlist.append('bzip2')
    compressionlistalt.append('bzip2')
    outextlist.append('bz2')
    outextlistwd.append('.bz2')
if('zstd' in compressionsupport):
    compressionlist.append('zstd')
    compressionlistalt.append('zstd')
    outextlist.append('zst')
    outextlistwd.append('.zst')
if('lz4' in compressionsupport):
    compressionlist.append('lz4')
    compressionlistalt.append('lz4')
    outextlist.append('lz4')
    outextlistwd.append('.lz4')
if('lzo' in compressionsupport):
    compressionlist.append('lzo')
    compressionlistalt.append('lzo')
    outextlist.append('lzo')
    outextlistwd.append('.lzo')
if('lzop' in compressionsupport):
    compressionlist.append('lzop')
    compressionlistalt.append('lzop')
    outextlist.append('lzop')
    outextlistwd.append('.lzop')
if('lzma' in compressionsupport):
    compressionlist.append('lzma')
    compressionlistalt.append('lzma')
    outextlist.append('lzma')
    outextlistwd.append('.lzma')
if('xz' in compressionsupport):
    compressionlist.append('xz')
    compressionlistalt.append('xz')
    outextlist.append('xz')
    outextlistwd.append('.xz')
if('zlib' in compressionsupport):
    compressionlist.append('zlib')
    compressionlistalt.append('zlib')
    outextlist.append('zz')
    outextlistwd.append('.zz')
    outextlist.append('zl')
    outextlistwd.append('.zl')
    outextlist.append('zlib')
    outextlistwd.append('.zlib')

tarfile_mimetype = "application/tar"
tarfile_tar_mimetype = tarfile_mimetype
zipfile_mimetype = "application/zip"
zipfile_zip_mimetype = zipfile_mimetype
rarfile_mimetype = "application/rar"
rarfile_rar_mimetype = rarfile_mimetype
archivefile_mimetype = "application/x-"+__file_format_dict__['format_lower']+""
mimetypes.add_type(archivefile_mimetype, __file_format_extension__, strict=True)
archivefile_cat_mimetype = archivefile_mimetype
archivefile_gzip_mimetype = "application/x-" + \
    __file_format_dict__['format_lower']+"+gzip"
archivefile_gz_mimetype = archivefile_gzip_mimetype
mimetypes.add_type(archivefile_gz_mimetype, __file_format_extension__+".gz", strict=True)
archivefile_bzip2_mimetype = "application/x-" + \
    __file_format_dict__['format_lower']+"+bzip2"
archivefile_bz2_mimetype = archivefile_bzip2_mimetype
mimetypes.add_type(archivefile_bz2_mimetype, __file_format_extension__+".bz2", strict=True)
archivefile_lz4_mimetype = "application/x-" + \
    __file_format_dict__['format_lower']+"+lz4"
mimetypes.add_type(archivefile_lz4_mimetype, __file_format_extension__+".lz4", strict=True)
archivefile_lzop_mimetype = "application/x-" + \
    __file_format_dict__['format_lower']+"+lzop"
mimetypes.add_type(archivefile_lzop_mimetype, __file_format_extension__+".lzop", strict=True)
archivefile_lzo_mimetype = archivefile_lzop_mimetype
mimetypes.add_type(archivefile_lzo_mimetype, __file_format_extension__+".lzo", strict=True)
archivefile_zstandard_mimetype = "application/x-" + \
    __file_format_dict__['format_lower']+"+zstandard"
archivefile_zstd_mimetype = archivefile_zstandard_mimetype
mimetypes.add_type(archivefile_zstd_mimetype, __file_format_extension__+".zst", strict=True)
archivefile_lzma_mimetype = "application/x-" + \
    __file_format_dict__['format_lower']+"+lzma"
mimetypes.add_type(archivefile_lzma_mimetype, __file_format_extension__+".lzma", strict=True)
archivefile_xz_mimetype = "application/x-" + \
    __file_format_dict__['format_lower']+"+xz"
mimetypes.add_type(archivefile_xz_mimetype, __file_format_extension__+".xz", strict=True)
archivefile_zlib_mimetype = "application/x-" + \
    __file_format_dict__['format_lower']+"+zlib"
mimetypes.add_type(archivefile_zlib_mimetype, __file_format_extension__+".zz", strict=True)
mimetypes.add_type(archivefile_zlib_mimetype, __file_format_extension__+".zl", strict=True)
mimetypes.add_type(archivefile_zlib_mimetype, __file_format_extension__+".zlib", strict=True)
archivefile_zz_mimetype = archivefile_zlib_mimetype
archivefile_zl_mimetype = archivefile_zlib_mimetype
archivefile_extensions = [__file_format_extension__, __file_format_extension__+".gz", __file_format_extension__+".bz2", __file_format_extension__+".zst", __file_format_extension__+".lz4", __file_format_extension__ + ".lzo", __file_format_extension__+".lzop", __file_format_extension__+".lzma", __file_format_extension__+".xz", __file_format_extension__+".zz", __file_format_extension__+".zl", __file_format_extension__+".zlib"]

if __name__ == "__main__":
    import subprocess
    curscrpath = os.path.dirname(sys.argv[0])
    if(curscrpath == ""):
        curscrpath = "."
    if(os.sep == "\\"):
        curscrpath = curscrpath.replace(os.sep, "/")
    curscrpath = curscrpath + "/"
    scrfile = curscrpath + "catfile.py"
    if(os.path.exists(scrfile) and os.path.isfile(scrfile)):
        scrcmd = subprocess.Popen([sys.executable, scrfile] + sys.argv[1:])
        scrcmd.wait()


def VerbosePrintOut(dbgtxt, outtype="log", dbgenable=True, dgblevel=20):
    if(not dbgenable):
        return True
    log_functions = {
        "print": print,
        "log": logging.info,
        "warning": logging.warning,
        "error": logging.error,
        "critical": logging.critical,
        "exception": logging.exception,
        "logalt": lambda x: logging.log(dgblevel, x),
        "debug": logging.debug
    }
    log_function = log_functions.get(outtype)
    if(log_function):
        log_function(dbgtxt)
        return True
    return False


def VerbosePrintOutReturn(dbgtxt, outtype="log", dbgenable=True, dgblevel=20):
    VerbosePrintOut(dbgtxt, outtype, dbgenable, dgblevel)
    return dbgtxt


def RemoveWindowsPath(dpath):
    """
    Normalizes a path by converting Windows-style separators to Unix-style and stripping trailing slashes.
    """
    if dpath is None:
        dpath = ""
    if os.sep != "/":
        dpath = dpath.replace(os.path.sep, "/")
    dpath = dpath.rstrip("/")
    if dpath in [".", ".."]:
        dpath = dpath + "/"
    return dpath


def NormalizeRelativePath(inpath):
    """
    Ensures the path is relative unless it is absolute. Prepares consistent relative paths.
    """
    inpath = RemoveWindowsPath(inpath)
    if os.path.isabs(inpath):
        outpath = inpath
    else:
        if inpath.startswith("./") or inpath.startswith("../"):
            outpath = inpath
        else:
            outpath = "./" + inpath
    return outpath


def PrependPath(base_dir, child_path):
    # Check if base_dir is None or empty, if so, return child_path as is
    if not base_dir:
        return child_path
    # Ensure base_dir ends with exactly one slash
    if not base_dir.endswith('/'):
        base_dir += '/'
    # Check if child_path starts with ./ or ../ (indicating a relative path)
    if child_path.startswith('./') or child_path.startswith('../'):
        # For relative paths, we don't alter the child_path
        return base_dir + child_path
    else:
        # For non-relative paths, ensure there's no starting slash on child_path to avoid double slashes
        return base_dir + child_path.lstrip('/')


def ListDir(dirpath, followlink=False, duplicates=False, include_regex=None, exclude_regex=None):
    """
    Simplified directory listing function with regex support for inclusion and exclusion.
    Compatible with Python 2 and 3.

    Parameters:
        dirpath (str or list): A string or list of directory paths to process.
        followlink (bool): Whether to follow symbolic links (default: False).
        duplicates (bool): Whether to include duplicate paths (default: False).
        include_regex (str): Regex pattern to include matching files/directories (default: None).
        exclude_regex (str): Regex pattern to exclude matching files/directories (default: None).

    Returns:
        list: A list of files and directories matching the criteria.
    """
    try:
        if os.stat not in os.supports_follow_symlinks and followlink:
            followlink = False
    except AttributeError:
        followlink = False
    if isinstance(dirpath, (list, tuple)):
        dirpath = list(filter(None, dirpath))
    elif isinstance(dirpath, basestring):
        dirpath = list(filter(None, [dirpath]))
    retlist = []
    fs_encoding = sys.getfilesystemencoding() or 'UTF-8'
    include_pattern = re.compile(include_regex) if include_regex else None
    exclude_pattern = re.compile(exclude_regex) if exclude_regex else None
    for mydirfile in dirpath:
        if not os.path.exists(mydirfile):
            return False
        mydirfile = NormalizeRelativePath(mydirfile)
        if os.path.exists(mydirfile) and os.path.islink(mydirfile) and followlink:
            mydirfile = RemoveWindowsPath(os.path.realpath(mydirfile))
        if os.path.exists(mydirfile) and os.path.isdir(mydirfile):
            for root, dirs, filenames in os.walk(mydirfile):
                dpath = RemoveWindowsPath(root)
                if not isinstance(dpath, basestring):
                    dpath = dpath.decode(fs_encoding)
                # Apply regex filtering for directories
                if ((not include_pattern or include_pattern.search(dpath)) and
                    (not exclude_pattern or not exclude_pattern.search(dpath))):
                    if not duplicates and dpath not in retlist:
                        retlist.append(dpath)
                    elif duplicates:
                        retlist.append(dpath)
                for files in filenames:
                    fpath = os.path.join(root, files)
                    fpath = RemoveWindowsPath(fpath)
                    if not isinstance(fpath, basestring):
                        fpath = fpath.decode(fs_encoding)
                    # Apply regex filtering for files
                    if ((not include_pattern or include_pattern.search(fpath)) and
                        (not exclude_pattern or not exclude_pattern.search(fpath))):
                        if not duplicates and fpath not in retlist:
                            retlist.append(fpath)
                        elif duplicates:
                            retlist.append(fpath)
        else:
            path = RemoveWindowsPath(mydirfile)
            if not isinstance(path, basestring):
                path = path.decode(fs_encoding)

            # Apply regex filtering for single paths
            if ((not include_pattern or include_pattern.search(path)) and
                (not exclude_pattern or not exclude_pattern.search(path))):
                retlist.append(path)
    return retlist


def ListDirAdvanced(dirpath, followlink=False, duplicates=False, include_regex=None, exclude_regex=None):
    """
    Advanced directory listing function with regex support for inclusion and exclusion.
    Compatible with Python 2 and 3.

    Parameters:
        dirpath (str or list): A string or list of directory paths to process.
        followlink (bool): Whether to follow symbolic links (default: False).
        duplicates (bool): Whether to include duplicate paths (default: False).
        include_regex (str): Regex pattern to include matching files/directories (default: None).
        exclude_regex (str): Regex pattern to exclude matching files/directories (default: None).

    Returns:
        list: A list of files and directories matching the criteria.
    """
    try:
        if os.stat not in os.supports_follow_symlinks and followlink:
            followlink = False
    except AttributeError:
        followlink = False
    if isinstance(dirpath, (list, tuple)):
        dirpath = list(filter(None, dirpath))
    elif isinstance(dirpath, basestring):
        dirpath = list(filter(None, [dirpath]))
    retlist = []
    fs_encoding = sys.getfilesystemencoding() or 'UTF-8'
    include_pattern = re.compile(include_regex) if include_regex else None
    exclude_pattern = re.compile(exclude_regex) if exclude_regex else None
    for mydirfile in dirpath:
        if not os.path.exists(mydirfile):
            return False
        mydirfile = NormalizeRelativePath(mydirfile)
        if os.path.exists(mydirfile) and os.path.islink(mydirfile) and followlink:
            mydirfile = RemoveWindowsPath(os.path.realpath(mydirfile))
        if os.path.exists(mydirfile) and os.path.isdir(mydirfile):
            for root, dirs, filenames in os.walk(mydirfile):
                # Sort directories and files
                dirs.sort(key=lambda x: x.lower())
                filenames.sort(key=lambda x: x.lower())
                dpath = RemoveWindowsPath(root)
                if not isinstance(dpath, basestring):
                    dpath = dpath.decode(fs_encoding)
                # Apply regex filtering for directories
                if ((not include_pattern or include_pattern.search(dpath)) and
                    (not exclude_pattern or not exclude_pattern.search(dpath))):
                    if not duplicates and dpath not in retlist:
                        retlist.append(dpath)
                    elif duplicates:
                        retlist.append(dpath)
                for files in filenames:
                    fpath = os.path.join(root, files)
                    fpath = RemoveWindowsPath(fpath)
                    if not isinstance(fpath, basestring):
                        fpath = fpath.decode(fs_encoding)

                    # Apply regex filtering for files
                    if ((not include_pattern or include_pattern.search(fpath)) and
                        (not exclude_pattern or not exclude_pattern.search(fpath))):
                        if not duplicates and fpath not in retlist:
                            retlist.append(fpath)
                        elif duplicates:
                            retlist.append(fpath)
        else:
            path = RemoveWindowsPath(mydirfile)
            if not isinstance(path, basestring):
                path = path.decode(fs_encoding)
            # Apply regex filtering for single paths
            if ((not include_pattern or include_pattern.search(path)) and
                (not exclude_pattern or not exclude_pattern.search(path))):
                retlist.append(path)
    return retlist


def GetTotalSize(file_list):
    """
    Calculate the total size of all files in the provided list.
    
    Parameters:
        file_list (list): List of file paths.

    Returns:
        int: Total size of all files in bytes.
    """
    total_size = 0
    for item in file_list:
        if os.path.isfile(item):  # Ensure it's a file
            try:
                total_size += os.path.getsize(item)
            except OSError:
                sys.stderr.write("Error accessing file {}: {}\n".format(item, e))
    return total_size


def create_alias_function_alt(prefix, base_name, suffix, target_function):
    # Define a new function that wraps the target function
    def alias_function(*args, **kwargs):
        return target_function(*args, **kwargs)
    # Create the function name by combining the prefix, base name, and the suffix
    function_name = "{}{}{}".format(prefix, base_name, suffix)
    # Add the new function to the global namespace
    globals()[function_name] = alias_function


def create_alias_function(prefix, base_name, suffix, target_function):
    # Create the function name by combining the prefix, base name, and the suffix
    # Use the format method for string formatting, compatible with Python 2 and 3
    function_name = "{}{}{}".format(prefix, base_name, suffix)
    # Add the new function (alias of the target_function) to the global namespace
    # This line is compatible as-is with both Python 2 and 3
    globals()[function_name] = target_function


class ZlibFile:
    def __init__(self, file_path=None, fileobj=None, mode='rb', level=9, wbits=15, encoding=None, errors=None, newline=None):
        if file_path is None and fileobj is None:
            raise ValueError("Either file_path or fileobj must be provided")
        if file_path is not None and fileobj is not None:
            raise ValueError(
                "Only one of file_path or fileobj should be provided")

        self.file_path = file_path
        self.fileobj = fileobj
        self.mode = mode
        self.level = level
        self.wbits = wbits
        self.encoding = encoding
        self.errors = errors
        self.newline = newline
        self._compressed_data = b''
        self._decompressed_data = b''
        self._position = 0
        self._text_mode = 't' in mode

        # Force binary mode for internal handling
        internal_mode = mode.replace('t', 'b')

        if 'w' in mode or 'a' in mode or 'x' in mode:
            self.file = open(
                file_path, internal_mode) if file_path else fileobj
            self._compressor = zlib.compressobj(level, zlib.DEFLATED, wbits)
        elif 'r' in mode:
            if file_path:
                if os.path.exists(file_path):
                    self.file = open(file_path, internal_mode)
                    self._load_file()
                else:
                    raise FileNotFoundError(
                        "No such file: '{}'".format(file_path))
            elif fileobj:
                self.file = fileobj
                self._load_file()
        else:
            raise ValueError("Mode should be 'rb' or 'wb'")

    def _load_file(self):
        self.file.seek(0)
        self._compressed_data = self.file.read()
        if not self._compressed_data.startswith((b'\x78\x01', b'\x78\x5E', b'\x78\x9C', b'\x78\xDA')):
            raise ValueError("Invalid zlib file header")
        self._decompressed_data = zlib.decompress(
            self._compressed_data, self.wbits)
        if self._text_mode:
            self._decompressed_data = self._decompressed_data.decode(
                self.encoding or 'UTF-8', self.errors or 'strict')

    def write(self, data):
        if self._text_mode:
            data = data.encode(self.encoding or 'UTF-8',
                               self.errors or 'strict')
        compressed_data = self._compressor.compress(
            data) + self._compressor.flush(zlib.Z_SYNC_FLUSH)
        self.file.write(compressed_data)

    def read(self, size=-1):
        if size == -1:
            size = len(self._decompressed_data) - self._position
        data = self._decompressed_data[self._position:self._position + size]
        self._position += size
        return data

    def seek(self, offset, whence=0):
        if whence == 0:  # absolute file positioning
            self._position = offset
        elif whence == 1:  # seek relative to the current position
            self._position += offset
        elif whence == 2:  # seek relative to the file's end
            self._position = len(self._decompressed_data) + offset
        else:
            raise ValueError("Invalid value for whence")

        # Ensure the position is within bounds
        self._position = max(
            0, min(self._position, len(self._decompressed_data)))

    def tell(self):
        return self._position

    def flush(self):
        self.file.flush()

    def fileno(self):
        if hasattr(self.file, 'fileno'):
            return self.file.fileno()
        raise OSError("The underlying file object does not support fileno()")

    def isatty(self):
        if hasattr(self.file, 'isatty'):
            return self.file.isatty()
        return False

    def truncate(self, size=None):
        if hasattr(self.file, 'truncate'):
            return self.file.truncate(size)
        raise OSError("The underlying file object does not support truncate()")

    def close(self):
        if 'w' in self.mode or 'a' in self.mode or 'x' in self.mode:
            self.file.write(self._compressor.flush(zlib.Z_FINISH))
        if self.file_path:
            self.file.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


def _gzip_compress(data, compresslevel=9):
    """
    Compress data with a GZIP wrapper (wbits=31) in one shot.
    :param data: Bytes to compress.
    :param compresslevel: 1..9
    :return: GZIP-compressed bytes.
    """
    compobj = zlib.compressobj(compresslevel, zlib.DEFLATED, 31)
    cdata = compobj.compress(data)
    cdata += compobj.flush(zlib.Z_FINISH)
    return cdata


def _gzip_decompress(data):
    """
    Decompress data with gzip headers/trailers (wbits=31).
    Single-shot approach.
    :param data: GZIP-compressed bytes
    :return: Decompressed bytes
    """
    # If you need multi-member support, you'd need a streaming loop here.
    return zlib.decompress(data, 31)


def _gzip_decompress_multimember(data):
    """
    Decompress possibly multi-member GZIP data, returning all uncompressed bytes.

    - We loop over each GZIP member.
    - zlib.decompressobj(wbits=31) stops after the first member it encounters.
    - We use 'unused_data' to detect leftover data and continue until no more.
    """
    result = b""
    current_data = data

    while current_data:
        # Create a new decompress object for the next member
        dobj = zlib.decompressobj(31)
        try:
            part = dobj.decompress(current_data)
        except zlib.error as e:
            # If there's a decompression error, break or raise
            raise ValueError("Decompression error: {}".format(str(e)))

        result += part
        result += dobj.flush()

        if dobj.unused_data:
            # 'unused_data' holds the bytes after the end of this gzip member
            # So we move on to the next member
            current_data = dobj.unused_data
        else:
            # No leftover => we reached the end of the data
            break

    return result

class GzipFile(object):
    """
    A file-like wrapper that uses zlib at wbits=31 to mimic gzip compress/decompress,
    with multi-member support. Works on older Python versions (including Py2),
    where gzip.compress / gzip.decompress might be unavailable.

    - In read mode: loads entire file, checks GZIP magic if needed, and
      decompresses all members in a loop.
    - In write mode: buffers uncompressed data, then writes compressed bytes on close.
    - 'level' sets compression level (1..9).
    - Supports text ('t') vs binary modes.
    """

    # GZIP magic (first 2 bytes)
    GZIP_MAGIC = b'\x1f\x8b'

    def __init__(self, file_path=None, fileobj=None, mode='rb',
                 level=9, encoding=None, errors=None, newline=None):
        """
        :param file_path: Path to file on disk (optional)
        :param fileobj:  An existing file-like object (optional)
        :param mode: e.g. 'rb', 'wb', 'rt', 'wt', etc.
        :param level: Compression level (1..9)
        :param encoding: If 't' in mode, text encoding
        :param errors: Error handling for text encode/decode
        :param newline: Placeholder for signature compatibility
        """
        if file_path is None and fileobj is None:
            raise ValueError("Either file_path or fileobj must be provided")
        if file_path is not None and fileobj is not None:
            raise ValueError("Only one of file_path or fileobj should be provided")

        self.file_path = file_path
        self.fileobj = fileobj
        self.mode = mode
        self.level = level
        self.encoding = encoding
        self.errors = errors
        self.newline = newline

        # If reading, we store fully decompressed data in memory
        self._decompressed_data = b''
        self._position = 0

        # If writing, we store uncompressed data in memory, compress at close()
        self._write_buffer = b''

        # Text mode if 't' in mode
        self._text_mode = 't' in mode

        # Force binary file I/O mode
        internal_mode = mode.replace('t', 'b')

        if any(m in mode for m in ('w', 'a', 'x')):
            # Writing or appending
            if file_path:
                self.file = open(file_path, internal_mode)
            else:
                self.file = fileobj

        elif 'r' in mode:
            # Reading
            if file_path:
                if os.path.exists(file_path):
                    self.file = open(file_path, internal_mode)
                    self._load_file()
                else:
                    raise FileNotFoundError("No such file: '{}'".format(file_path))
            else:
                # fileobj
                self.file = fileobj
                self._load_file()
        else:
            raise ValueError("Mode should be 'rb'/'rt' or 'wb'/'wt'")

    def _load_file(self):
        """
        Read entire compressed file. Decompress all GZIP members.
        """
        self.file.seek(0)
        compressed_data = self.file.read()

        # (Optional) Check magic if you want to fail early on non-GZIP data
        # We'll do a quick check to see if it starts with GZIP magic
        if not compressed_data.startswith(self.GZIP_MAGIC):
            raise ValueError("Invalid GZIP header (magic bytes missing)")

        self._decompressed_data = _gzip_decompress_multimember(compressed_data)

        # If text mode, decode
        if self._text_mode:
            enc = self.encoding or 'UTF-8'
            err = self.errors or 'strict'
            self._decompressed_data = self._decompressed_data.decode(enc, err)

    def write(self, data):
        """
        Write data to our in-memory buffer.
        Actual compression (GZIP) occurs on close().
        """
        if 'r' in self.mode:
            raise IOError("File not open for writing")

        if self._text_mode:
            # Encode text to bytes
            data = data.encode(self.encoding or 'UTF-8', self.errors or 'strict')

        self._write_buffer += data

    def read(self, size=-1):
        """
        Read from the decompressed data buffer.
        """
        if 'r' not in self.mode:
            raise IOError("File not open for reading")

        if size < 0:
            size = len(self._decompressed_data) - self._position
        data = self._decompressed_data[self._position : self._position + size]
        self._position += size
        return data

    def seek(self, offset, whence=0):
        """
        Seek in the decompressed data buffer.
        """
        if 'r' not in self.mode:
            raise IOError("File not open for reading")

        if whence == 0:  # absolute
            new_pos = offset
        elif whence == 1:  # relative
            new_pos = self._position + offset
        elif whence == 2:  # from the end
            new_pos = len(self._decompressed_data) + offset
        else:
            raise ValueError("Invalid value for whence")

        self._position = max(0, min(new_pos, len(self._decompressed_data)))

    def tell(self):
        """
        Return the current position in the decompressed data buffer.
        """
        return self._position

    def flush(self):
        """
        Flush the underlying file, if possible.
        (No partial compression flush is performed here.)
        """
        if hasattr(self.file, 'flush'):
            self.file.flush()

    def fileno(self):
        """
        Return the file descriptor if available.
        """
        if hasattr(self.file, 'fileno'):
            return self.file.fileno()
        raise OSError("The underlying file object does not support fileno()")

    def isatty(self):
        """
        Return whether the underlying file is a TTY.
        """
        if hasattr(self.file, 'isatty'):
            return self.file.isatty()
        return False

    def truncate(self, size=None):
        """
        Truncate the underlying file if possible.
        """
        if hasattr(self.file, 'truncate'):
            return self.file.truncate(size)
        raise OSError("The underlying file object does not support truncate()")

    def close(self):
        """
        If in write mode, compress the entire buffer with wbits=31 (gzip) at the
        specified compression level, then write it out. Close file if we opened it.
        """
        if any(m in self.mode for m in ('w', 'a', 'x')):
            compressed = _gzip_compress(self._write_buffer, compresslevel=self.level)
            self.file.write(compressed)

        if self.file_path:
            self.file.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


class ZstdFile(object):
    ZSTD_MAGIC = b'\x28\xb5\x2f\xfd'  # Zstandard magic bytes

    def __init__(self, file_path=None, fileobj=None, mode='rb', level=9,
                 encoding=None, errors=None, newline=None):
        """
        A file-like wrapper around Zstandard compression/decompression,
        supporting both Python 2 and 3.
        """
        if file_path is None and fileobj is None:
            raise ValueError("Either file_path or fileobj must be provided")
        if file_path is not None and fileobj is not None:
            raise ValueError("Only one of file_path or fileobj should be provided")

        self.file_path = file_path
        self.fileobj = fileobj
        self.mode = mode
        self.level = level
        self.encoding = encoding
        self.errors = errors
        self.newline = newline
        self._compressed_data = b''
        self._decompressed_data = b''
        self._position = 0

        # Track whether we're doing text mode
        self._text_mode = 't' in mode

        # Force binary mode internally for reading/writing bytes
        internal_mode = mode.replace('t', 'b')

        if 'w' in mode or 'a' in mode or 'x' in mode:
            # Open the file if a path was specified; otherwise, use fileobj
            if file_path:
                self.file = open(file_path, internal_mode)
            else:
                self.file = fileobj

            # Create a ZstdCompressor, then obtain a compressobj for flushing
            zctx = zstandard.ZstdCompressor(level=self.level)
            self._compressor = zctx.compressobj()

        elif 'r' in mode:
            if file_path:
                if os.path.exists(file_path):
                    self.file = open(file_path, internal_mode)
                    self._load_file()
                else:
                    raise FileNotFoundError("No such file: '{}'".format(file_path))
            else:
                # fileobj provided
                self.file = fileobj
                self._load_file()

        else:
            raise ValueError("Mode should be 'rb'/'rt' or 'wb'/'wt'")

    def _load_file(self):
        """
        Reads the entire compressed file into memory and uses streaming
        decompression to handle multiple frames or frames with unknown size.
        """
        self.file.seek(0)
        self._compressed_data = self.file.read()

        # Validate Zstd magic bytes at the start
        if not self._compressed_data.startswith(self.ZSTD_MAGIC):
            raise ValueError("Invalid Zstandard file header (magic bytes missing)")

        # Use streaming decompression (stream_reader)
        decompressor = zstandard.ZstdDecompressor()
        reader = decompressor.stream_reader(io.BytesIO(self._compressed_data))

        chunks = []
        while True:
            chunk = reader.read(16384)  # 16 KB at a time
            if not chunk:
                break
            chunks.append(chunk)

        self._decompressed_data = b"".join(chunks)

        # If in text mode, decode the bytes
        if self._text_mode:
            enc = self.encoding or 'UTF-8'
            err = self.errors or 'strict'
            self._decompressed_data = self._decompressed_data.decode(enc, err)

    def write(self, data):
        """
        Write data to the ZstdFile. In text mode, data is encoded;
        in binary mode, data is written as bytes. Each call to `write()`
        produces compressed chunks.
        """
        if self._text_mode:
            # Encode data from str (Py3) or unicode (Py2) to bytes
            data = data.encode(self.encoding or 'UTF-8', self.errors or 'strict')

        # Compress the chunk with the compressobj
        compressed_chunk = self._compressor.compress(data)
        if compressed_chunk:
            self.file.write(compressed_chunk)

    def read(self, size=-1):
        """
        Read from the decompressed data buffer.
        """
        if size < 0:
            size = len(self._decompressed_data) - self._position
        data = self._decompressed_data[self._position:self._position + size]
        self._position += size
        return data

    def seek(self, offset, whence=0):
        """
        Adjust the current read position in the decompressed data buffer.
        """
        if whence == 0:  # absolute
            new_pos = offset
        elif whence == 1:  # relative
            new_pos = self._position + offset
        elif whence == 2:  # relative to end
            new_pos = len(self._decompressed_data) + offset
        else:
            raise ValueError("Invalid value for whence")

        self._position = max(0, min(new_pos, len(self._decompressed_data)))

    def tell(self):
        """
        Return the current read position in the decompressed data buffer.
        """
        return self._position

    def flush(self):
        """
        Flush the underlying file object. This doesn't force the Zstd
        compressor to flush partial data like zlib, but we can at least
        flush the OS buffer.
        """
        self.file.flush()

    def fileno(self):
        """
        Return the file descriptor if available.
        """
        if hasattr(self.file, 'fileno'):
            return self.file.fileno()
        raise OSError("The underlying file object does not support fileno()")

    def isatty(self):
        """
        Return whether the underlying file is a TTY.
        """
        if hasattr(self.file, 'isatty'):
            return self.file.isatty()
        return False

    def truncate(self, size=None):
        """
        Truncate the underlying file if possible.
        """
        if hasattr(self.file, 'truncate'):
            return self.file.truncate(size)
        raise OSError("The underlying file object does not support truncate()")

    def close(self):
        """
        If in write mode, finalize by flushing any remaining compressed data
        in the compressobj. Then close the file if we opened it.
        """
        if any(x in self.mode for x in ('w', 'a', 'x')):
            # flush() returns any remaining compressed data in the compressobj
            final_chunk = self._compressor.flush()
            if final_chunk:
                self.file.write(final_chunk)

        if self.file_path:
            self.file.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


class LzopFile(object):
    """
    A file-like wrapper around LZO compression/decompression using python-lzo.

    - In read mode (r): Reads the entire file, checks for LZOP magic bytes,
      then decompresses into memory.
    - In write mode (w/a/x): Buffers all data in memory. On close, writes
      the LZOP magic bytes + compressed data.
    - Supports a 'level' parameter (default=9). python-lzo commonly accepts only
      level=1 or level=9 for LZO1X_1 or LZO1X_999.
    """
    # LZOP magic bytes: b'\x89LZO\x0D\x0A\x1A\n'
    LZOP_MAGIC = b'\x89LZO\x0D\x0A\x1A\n'

    def __init__(self, file_path=None, fileobj=None, mode='rb',
                 level=9, encoding=None, errors=None, newline=None):
        """
        :param file_path: Path to the file (if any)
        :param fileobj: An existing file object (if any)
        :param mode: File mode, e.g., 'rb', 'wb', 'rt', 'wt', etc.
        :param level: Compression level (int). python-lzo typically supports 1 or 9.
        :param encoding: Text encoding (for text mode)
        :param errors: Error handling for encoding/decoding (e.g., 'strict')
        :param newline: Placeholder to mimic built-in open() signature
        """
        if file_path is None and fileobj is None:
            raise ValueError("Either file_path or fileobj must be provided")
        if file_path is not None and fileobj is not None:
            raise ValueError("Only one of file_path or fileobj should be provided")

        self.file_path = file_path
        self.fileobj = fileobj
        self.mode = mode
        self.level = level
        self.encoding = encoding
        self.errors = errors
        self.newline = newline
        self._decompressed_data = b''
        self._position = 0

        # For writing, store uncompressed data in memory until close()
        self._write_buffer = b''

        # Track whether we're doing text mode
        self._text_mode = 't' in mode

        # Force binary mode internally for file I/O
        internal_mode = mode.replace('t', 'b')

        if 'w' in mode or 'a' in mode or 'x' in mode:
            # Open the file if a path was specified; otherwise, use fileobj
            if file_path:
                self.file = open(file_path, internal_mode)
            else:
                self.file = fileobj

        elif 'r' in mode:
            # Reading
            if file_path:
                if os.path.exists(file_path):
                    self.file = open(file_path, internal_mode)
                    self._load_file()
                else:
                    raise FileNotFoundError("No such file: '{}'".format(file_path))
            else:
                # fileobj provided
                self.file = fileobj
                self._load_file()

        else:
            raise ValueError("Mode should be 'rb'/'rt' or 'wb'/'wt'")

    def _load_file(self):
        """
        Read the entire compressed file into memory. Expects LZOP magic bytes
        at the start. Decompress the remainder into _decompressed_data.
        """
        self.file.seek(0)
        compressed_data = self.file.read()

        # Check for the LZOP magic
        if not compressed_data.startswith(self.LZOP_MAGIC):
            raise ValueError("Invalid LZOP file header (magic bytes missing)")

        # Strip the magic; everything after is LZO-compressed data.
        compressed_data = compressed_data[len(self.LZOP_MAGIC):]

        # Decompress the remainder
        try:
            self._decompressed_data = lzo.decompress(compressed_data)
        except lzo.error as e:
            raise ValueError("LZO decompression failed: {}".format(str(e)))

        # If we're in text mode, decode from bytes to str
        if self._text_mode:
            enc = self.encoding or 'UTF-8'
            err = self.errors or 'strict'
            self._decompressed_data = self._decompressed_data.decode(enc, err)

    def write(self, data):
        """
        Write data into an internal buffer. The actual compression + file write
        happens on close().
        """
        if 'r' in self.mode:
            raise IOError("File not open for writing")

        if self._text_mode:
            # Encode data from str (Py3) or unicode (Py2) to bytes
            data = data.encode(self.encoding or 'UTF-8', self.errors or 'strict')

        # Accumulate in memory
        self._write_buffer += data

    def read(self, size=-1):
        """
        Read from the decompressed data buffer.
        """
        if 'r' not in self.mode:
            raise IOError("File not open for reading")

        if size < 0:
            size = len(self._decompressed_data) - self._position
        data = self._decompressed_data[self._position:self._position + size]
        self._position += size
        return data

    def seek(self, offset, whence=0):
        """
        Adjust the current read position in the decompressed buffer.
        """
        if 'r' not in self.mode:
            raise IOError("File not open for reading")

        if whence == 0:  # absolute
            new_pos = offset
        elif whence == 1:  # relative
            new_pos = self._position + offset
        elif whence == 2:  # relative to end
            new_pos = len(self._decompressed_data) + offset
        else:
            raise ValueError("Invalid value for whence")

        self._position = max(0, min(new_pos, len(self._decompressed_data)))

    def tell(self):
        """
        Return the current read position in the decompressed buffer.
        """
        return self._position

    def flush(self):
        """
        Flush the underlying file if supported. (No partial compression flush for LZO.)
        """
        if hasattr(self.file, 'flush'):
            self.file.flush()

    def fileno(self):
        """
        Return the file descriptor if available.
        """
        if hasattr(self.file, 'fileno'):
            return self.file.fileno()
        raise OSError("The underlying file object does not support fileno()")

    def isatty(self):
        """
        Return whether the underlying file is a TTY.
        """
        if hasattr(self.file, 'isatty'):
            return self.file.isatty()
        return False

    def truncate(self, size=None):
        """
        Truncate the underlying file if possible.
        """
        if hasattr(self.file, 'truncate'):
            return self.file.truncate(size)
        raise OSError("The underlying file object does not support truncate()")

    def close(self):
        """
        If in write mode, compress the entire accumulated buffer using LZO
        (with the specified level) and write it (with the LZOP magic) to the file.
        """
        if any(x in self.mode for x in ('w', 'a', 'x')):
            # Write the LZOP magic
            self.file.write(self.LZOP_MAGIC)

            # Compress the entire buffer
            try:
                # python-lzo supports level=1 or level=9 for LZO1X
                compressed = lzo.compress(self._write_buffer, self.level)
            except lzo.error as e:
                raise ValueError("LZO compression failed: {}".format(str(e)))

            self.file.write(compressed)

        if self.file_path:
            self.file.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


def TarFileCheck(infile):
    try:
        if is_tarfile(infile):
            return True
        else:
            pass
    except TypeError:
        try:
            # Check if the input is a file object
            if hasattr(infile, "read"):
                # Save the current file position
                current_position = infile.tell()
                # Attempt to open the file object as a tar file
                with tarfile.open(fileobj=infile) as tar:
                    pass
                # Restore the file position
                infile.seek(current_position)
            else:
                # Assume it's a filename and attempt to open it as a tar file
                with tarfile.open(name=infile) as tar:
                    pass
            return True
        except (tarfile.TarError, AttributeError, IOError):
            return False


def ZipFileCheck(infile):
    try:
        if zipfile.is_zipfile(infile):
            return True
    except TypeError:
        pass
    try:
        # Check if the input is a file-like object
        if hasattr(infile, "read"):
            # Save the current file position
            current_position = infile.tell()
            # Attempt to open the file object as a zip file
            with zipfile.ZipFile(infile) as zipf:
                pass
            # Restore the file position
            infile.seek(current_position)
        else:
            # Assume it's a filename and attempt to open it as a zip file
            with zipfile.ZipFile(infile) as zipf:
                pass
        return True
    except (zipfile.BadZipFile, AttributeError, IOError):
        return False


def RarFileCheck(infile):
    try:
        if rarfile.is_rarfile(infile):
            return True
    except TypeError:
        pass
    try:
        # Check if the input is a file-like object
        if hasattr(infile, "read"):
            # Save the current file position
            current_position = infile.tell()
            # Attempt to open the file object as a rar file
            with rarfile.RarFile(infile) as rarf:
                pass
            # Restore the file position
            infile.seek(current_position)
        else:
            # Assume it's a filename and attempt to open it as a rar file
            with rarfile.RarFile(infile) as rarf:
                pass
        return True
    except (rarfile.Error, AttributeError, IOError):
        return False


def SevenZipFileCheck(infile):
    try:
        # Check if the input is a file-like object
        if hasattr(infile, "read"):
            # Save the current file position
            current_position = infile.tell()
            # Attempt to open the file object as a 7z file
            with py7zr.SevenZipFile(infile, 'r') as archive:
                pass
            # Restore the file position
            infile.seek(current_position)
        else:
            # Assume it's a filename and attempt to open it as a 7z file
            with py7zr.SevenZipFile(infile, 'r') as archive:
                pass
        return True
    except (py7zr.Bad7zFile, AttributeError, IOError):
        return False

# initial_value can be 0xFFFF or 0x0000


def crc16_ansi(msg, initial_value=0xFFFF):
    # CRC-16-IBM / CRC-16-ANSI polynomial and initial value
    poly = 0x8005  # Polynomial for CRC-16-IBM / CRC-16-ANSI
    crc = initial_value  # Initial value
    for b in msg:
        crc ^= b << 8  # XOR byte into CRC top byte
        for _ in range(8):  # Process each bit
            if crc & 0x8000:  # If the top bit is set
                # Shift left and XOR with the polynomial
                crc = (crc << 1) ^ poly
            else:
                crc = crc << 1  # Just shift left
            crc &= 0xFFFF  # Ensure CRC remains 16-bit
    return crc

# initial_value can be 0xFFFF or 0x0000


def crc16_ibm(msg, initial_value=0xFFFF):
    return crc16_ansi(msg, initial_value)

# initial_value is 0xFFFF


def crc16(msg):
    return crc16_ansi(msg, 0xFFFF)

# initial_value can be 0xFFFF, 0x1D0F or 0x0000


def crc16_ccitt(msg, initial_value=0xFFFF):
    # CRC-16-CCITT polynomial
    poly = 0x1021  # Polynomial for CRC-16-CCITT
    # Use the specified initial value
    crc = initial_value
    for b in msg:
        crc ^= b << 8  # XOR byte into CRC top byte
        for _ in range(8):  # Process each bit
            if crc & 0x8000:  # If the top bit is set
                # Shift left and XOR with the polynomial
                crc = (crc << 1) ^ poly
            else:
                crc = crc << 1  # Just shift left
            crc &= 0xFFFF  # Ensure CRC remains 16-bit
    return crc

# initial_value can be 0x42F0E1EBA9EA3693 or 0x0000000000000000


def crc64_ecma(msg, initial_value=0x0000000000000000):
    # CRC-64-ECMA polynomial and initial value
    poly = 0x42F0E1EBA9EA3693
    crc = initial_value  # Initial value for CRC-64-ECMA
    for b in msg:
        crc ^= b << 56  # XOR byte into the most significant byte of the CRC
        for _ in range(8):  # Process each bit
            if crc & (1 << 63):  # Check if the leftmost (most significant) bit is set
                # Shift left and XOR with poly if the MSB is 1
                crc = (crc << 1) ^ poly
            else:
                crc <<= 1  # Just shift left if the MSB is 0
            crc &= 0xFFFFFFFFFFFFFFFF  # Ensure CRC remains 64-bit
    return crc

# initial_value can be 0x000000000000001B or 0xFFFFFFFFFFFFFFFF


def crc64_iso(msg, initial_value=0xFFFFFFFFFFFFFFFF):
    # CRC-64-ISO polynomial and initial value
    poly = 0x000000000000001B
    crc = initial_value  # Common initial value for CRC-64-ISO
    for b in msg:
        crc ^= b << 56  # XOR byte into the most significant byte of the CRC
        for _ in range(8):  # Process each bit
            if crc & (1 << 63):  # Check if the leftmost (most significant) bit is set
                # Shift left and XOR with poly if the MSB is 1
                crc = (crc << 1) ^ poly
            else:
                crc <<= 1  # Just shift left if the MSB is 0
            crc &= 0xFFFFFFFFFFFFFFFF  # Ensure CRC remains 64-bit
    return crc

def MajorMinorToDev(major, minor):
    """
    Converts major and minor numbers to a device number.
    Compatible with Python 2 and 3.
    """
    return (major << 8) | minor

def DevToMajorMinor(dev):
    """
    Extracts major and minor numbers from a device number.
    Compatible with Python 2 and 3.
    """
    major = (dev >> 8) & 0xFF
    minor = dev & 0xFF
    return major, minor


def GetDataFromArray(data, path, default=None):
    element = data
    try:
        for key in path:
            element = element[key]
        return element
    except (KeyError, TypeError, IndexError):
        return default


def GetDataFromArrayAlt(structure, path, default=None):
    element = structure
    for key in path:
        if isinstance(element, dict) and key in element:
            element = element[key]
        elif isinstance(element, list) and isinstance(key, int) and -len(element) <= key < len(element):
            element = element[key]
        else:
            return default
    return element


def GetHeaderChecksum(inlist=[], checksumtype="crc32", encodedata=True, formatspecs=__file_format_dict__):
    fileheader = AppendNullBytes(inlist, formatspecs['format_delimiter']) if isinstance(
        inlist, list) else AppendNullByte(inlist, formatspecs['format_delimiter'])
    if encodedata:
        fileheader = fileheader.encode('UTF-8')
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
    }
    if checksumtype in checksum_methods:
        return checksum_methods[checksumtype](fileheader)
    elif CheckSumSupportAlt(checksumtype, hashlib_guaranteed):
        checksumoutstr = hashlib.new(checksumtype)
        checksumoutstr.update(fileheader)
        return checksumoutstr.hexdigest().lower()
    return format(0, 'x').lower()


def GetFileChecksum(instr, checksumtype="crc32", encodedata=True, formatspecs=__file_format_dict__):
    if encodedata:
        instr = instr.encode('UTF-8')
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
    }
    if checksumtype in checksum_methods:
        return checksum_methods[checksumtype](instr)
    elif CheckSumSupportAlt(checksumtype, hashlib_guaranteed):
        checksumoutstr = hashlib.new(checksumtype)
        checksumoutstr.update(instr)
        return checksumoutstr.hexdigest().lower()
    return format(0, 'x').lower()


def ValidateHeaderChecksum(inlist=[], checksumtype="crc32", inchecksum="0", formatspecs=__file_format_dict__):
    catfileheadercshex = GetHeaderChecksum(
        inlist, checksumtype, True, formatspecs).lower()
    return inchecksum.lower() == catfileheadercshex


def ValidateFileChecksum(infile, checksumtype="crc32", inchecksum="0", formatspecs=__file_format_dict__):
    catinfilecshex = GetFileChecksum(
        infile, checksumtype, True, formatspecs).lower()
    return inchecksum.lower() == catinfilecshex


def ReadTillNullByteOld(fp, delimiter=__file_format_dict__['format_delimiter']):
    if not hasattr(fp, "read"):
        return False
    curfullbyte = bytearray()
    nullbyte = delimiter.encode("UTF-8")
    dellen = len(nullbyte)
    while True:
        curbyte = fp.read(1)
        if not curbyte:  # End of file or no more data
            break
        curfullbyte.extend(curbyte)
        # Check if the end of the buffer matches our delimiter
        if len(curfullbyte) >= dellen and curfullbyte[-dellen:] == nullbyte:
            # Remove the delimiter from the returned bytes
            curfullbyte = curfullbyte[:-dellen]
            break
    return curfullbyte.decode('UTF-8')


def ReadUntilNullByteOld(fp, delimiter=__file_format_dict__['format_delimiter']):
    return ReadTillNullByteOld(fp, delimiter)


def ReadTillNullByteAlt(fp, delimiter=__file_format_dict__['format_delimiter'], chunk_size=1024, max_read=1024000):
    if(not hasattr(fp, "read")):
        return False
    delimiter = delimiter.encode('UTF-8')  # Ensure the delimiter is in bytes
    buffer = bytearray()
    total_read = 0
    delimiter_length = len(delimiter)
    while True:
        chunk = fp.read(chunk_size)
        if not chunk:
            # End of file reached without finding the delimiter
            break
        buffer.extend(chunk)
        total_read += len(chunk)
        if delimiter in buffer:
            # Delimiter found, calculate where to reset the file pointer
            index = buffer.find(delimiter)
            # Calculate how many extra bytes were read after the delimiter
            extra_bytes_read = len(buffer) - (index + delimiter_length)
            # Move the file pointer back to just after the delimiter
            fp.seek(-extra_bytes_read, 1)
            buffer = buffer[:index]
            break
        if total_read >= max_read:
            # Stop reading if max limit is reached to prevent excessive memory usage
            raise MemoryError(
                "Maximum read limit reached without finding the delimiter.")
        # Check for incomplete UTF-8 sequences at the end of the buffer
        if len(buffer) > 1 and 128 <= buffer[-1] < 192:
            # This suggests that the last byte might be the start of a multi-byte character
            # Try to read one more byte to complete the character
            extra_byte = fp.read(1)
            if extra_byte:
                buffer.extend(extra_byte)
            else:
                # No more data available
                break
    try:
        return buffer.decode('UTF-8', errors='replace')
    except UnicodeDecodeError:
        return buffer.decode('UTF-8', errors='replace')


def ReadUntilNullByteAlt(fp, delimiter=__file_format_dict__['format_delimiter'], chunk_size=1024, max_read=1024000):
    return ReadTillNullByteAlt(fp, delimiter, chunk_size, max_read)


def ReadTillNullByte(fp, delimiter=__file_format_dict__['format_delimiter'], max_read=1024000):
    if not hasattr(fp, "read"):
        return False
    curfullbyte = bytearray()
    nullbyte = delimiter.encode("UTF-8")
    dellen = len(nullbyte)
    total_read = 0  # Track the total number of bytes read
    while True:
        curbyte = fp.read(1)
        if not curbyte:  # End of file or no more data
            break
        curfullbyte.extend(curbyte)
        total_read += 1
        # Check if the end of the buffer matches the delimiter
        if len(curfullbyte) >= dellen and curfullbyte[-dellen:] == nullbyte:
            # Remove the delimiter from the returned bytes
            curfullbyte = curfullbyte[:-dellen]
            break
        # Check if we have exceeded the max read limit
        if total_read >= max_read:
            raise MemoryError("Maximum read limit reached without finding the delimiter.")
    # Decode the full byte array to string once out of the loop
    try:
        return curfullbyte.decode('UTF-8')
    except UnicodeDecodeError:
        # Handle potential partial UTF-8 characters at the end
        for i in range(1, 4):
            try:
                return curfullbyte[:-i].decode('UTF-8')
            except UnicodeDecodeError:
                continue
        raise  # Re-raise if decoding fails even after trimming


def ReadUntilNullByte(fp, delimiter=__file_format_dict__['format_delimiter'], max_read=1024000):
    return ReadTillNullByte(fp, delimiter, max_read)


def ReadTillNullByteByNum(fp, delimiter=__file_format_dict__['format_delimiter'], num_delimiters=1, chunk_size=1024, max_read=1024000):
    if(not hasattr(fp, "read")):
        return False
    delimiter = delimiter.encode('UTF-8')  # Ensure the delimiter is in bytes
    buffer = bytearray()
    total_read = 0
    delimiter_length = len(delimiter)
    results = []
    while len(results) < num_delimiters:
        chunk = fp.read(chunk_size)
        if not chunk:
            # End of file reached; decode whatever is collected if it's the last needed part
            if len(buffer) > 0:
                results.append(buffer.decode('UTF-8', errors='replace'))
            break
        buffer.extend(chunk)
        total_read += len(chunk)
        # Check if we have found the delimiter
        while delimiter in buffer:
            index = buffer.find(delimiter)
            # Decode the section before the delimiter
            results.append(buffer[:index].decode('UTF-8', errors='replace'))
            # Remove the processed part from the buffer
            buffer = buffer[index + delimiter_length:]
            if len(results) == num_delimiters:
                # If reached the required number of delimiters, adjust the file pointer and stop
                fp.seek(-len(buffer), 1)
                return results
        if total_read >= max_read:
            # Stop reading if max limit is reached to prevent excessive memory usage
            raise MemoryError(
                "Maximum read limit reached without finding the delimiter.")
        # Check for incomplete UTF-8 sequences at the end of the buffer
        if len(buffer) > 1 and 128 <= buffer[-1] < 192:
            # This suggests that the last byte might be the start of a multi-byte character
            # Try to read one more byte to complete the character
            extra_byte = fp.read(1)
            if extra_byte:
                buffer.extend(extra_byte)
            else:
                # No more data available
                break
    # Process remaining buffer if less than the required number of delimiters were found
    if len(buffer) > 0 and len(results) < num_delimiters:
        results.append(buffer.decode('UTF-8', errors='replace'))
    return results


def ReadUntilNullByteByNum(fp, delimiter=__file_format_dict__['format_delimiter'], num_delimiters=1, chunk_size=1024, max_read=1024000):
    return ReadTillNullByteByNum(fp, delimiter, num_delimiters, chunk_size, max_read)


def SeekToEndOfFile(fp):
    lasttell = 0
    while(True):
        fp.seek(1, 1)
        if(lasttell == fp.tell()):
            break
        lasttell = fp.tell()
    return True


def ReadFileHeaderData(fp, rounds=0, delimiter=__file_format_dict__['format_delimiter']):
    if(not hasattr(fp, "read")):
        return False
    rocount = 0
    roend = int(rounds)
    HeaderOut = []
    while(rocount < roend):
        HeaderOut.append(ReadTillNullByte(fp, delimiter))
        rocount = rocount + 1
    return HeaderOut


def ReadFileHeaderDataBySize(fp, delimiter=__file_format_dict__['format_delimiter']):
    if(not hasattr(fp, "read")):
        return False
    preheaderdata = ReadFileHeaderData(fp, 1, delimiter)
    headersize = int(preheaderdata[0], 16)
    if(headersize <= 0):
        return []
    subfp = BytesIO()
    subfp.write(fp.read(headersize))
    fp.seek(len(delimiter), 1)
    subfp.seek(0, 0)
    prealtheaderdata = ReadFileHeaderData(subfp, 1, delimiter)
    headernumfields = int(prealtheaderdata[0], 16)
    headerdata = ReadTillNullByteByNum(subfp, delimiter, headernumfields)
    HeaderOut = preheaderdata + prealtheaderdata + headerdata
    subfp.close()
    return HeaderOut


def ReadFileHeaderDataWoSize(fp, delimiter=__file_format_dict__['format_delimiter']):
    if(not hasattr(fp, "read")):
        return False
    preheaderdata = ReadFileHeaderData(fp, 2, delimiter)
    headersize = int(preheaderdata[0], 16)
    headernumfields = int(preheaderdata[1], 16)
    if(headersize <= 0 or headernumfields <= 0):
        return []
    headerdata = ReadTillNullByteByNum(fp, delimiter, headernumfields)
    #headerdata = ReadFileHeaderData(fp, headernumfields, delimiter);
    HeaderOut = preheaderdata + headerdata
    return HeaderOut


def ReadFileHeaderDataBySizeWithContent(fp, listonly=False, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__):
    if(not hasattr(fp, "read")):
        return False
    delimiter = formatspecs['format_delimiter']
    fheaderstart = fp.tell()
    HeaderOut = ReadFileHeaderDataBySize(fp, delimiter)
    if(len(HeaderOut) == 0):
        return False
    if(re.findall("^[.|/]", HeaderOut[3])):
        fname = HeaderOut[3]
    else:
        fname = "./"+HeaderOut[3]
    fcs = HeaderOut[-2].lower()
    fccs = HeaderOut[-1].lower()
    fsize = int(HeaderOut[5], 16)
    fcompression = HeaderOut[12]
    fcsize = int(HeaderOut[13], 16)
    fseeknextfile = HeaderOut[25]
    newfcs = GetHeaderChecksum(
        HeaderOut[:-2], HeaderOut[-4].lower(), True, formatspecs)
    if(fcs != newfcs and not skipchecksum):
        VerbosePrintOut("File Header Checksum Error with file " +
                        fname + " at offset " + str(fheaderstart))
        VerbosePrintOut("'" + fcs + "' != " + "'" + newfcs + "'")
        return False
    fhend = fp.tell() - 1
    fcontentstart = fp.tell()
    fcontents = BytesIO()
    if(fsize > 0 and not listonly):
        if(fcompression == "none" or fcompression == "" or fcompression == "auto"):
            fcontents.write(fp.read(fsize))
        else:
            fcontents.write(fp.read(fcsize))
    elif(fsize > 0 and listonly):
        if(fcompression == "none" or fcompression == "" or fcompression == "auto"):
            fp.seek(fsize, 1)
        else:
            fp.seek(fcsize, 1)
    fcontents.seek(0, 0)
    newfccs = GetFileChecksum(
        fcontents.read(), HeaderOut[-3].lower(), False, formatspecs)
    if(fccs != newfccs and not skipchecksum and not listonly):
        VerbosePrintOut("File Content Checksum Error with file " +
                        fname + " at offset " + str(fcontentstart))
        VerbosePrintOut("'" + fccs + "' != " + "'" + newfccs + "'")
        return False
    if(fcompression == "none" or fcompression == "" or fcompression == "auto"):
        pass
    else:
        fcontents.seek(0, 0)
        if(uncompress):
            cfcontents = UncompressArchiveFile(fcontents, formatspecs)
            cfcontents.seek(0, 0)
            cfcontents.seek(0, 0)
            shutil.copyfileobj(cfcontents, fcontents)
            cfcontents.close()
            fcontents.seek(0, 0)
    fcontentend = fp.tell()
    if(re.findall("^\\+([0-9]+)", fseeknextfile)):
        fseeknextasnum = int(fseeknextfile.replace("+", ""))
        if(abs(fseeknextasnum) == 0):
            pass
        fp.seek(fseeknextasnum, 1)
    elif(re.findall("^\\-([0-9]+)", fseeknextfile)):
        fseeknextasnum = int(fseeknextfile)
        if(abs(fseeknextasnum) == 0):
            pass
        fp.seek(fseeknextasnum, 1)
    elif(re.findall("^([0-9]+)", fseeknextfile)):
        fseeknextasnum = int(fseeknextfile)
        if(abs(fseeknextasnum) == 0):
            pass
        fp.seek(fseeknextasnum, 0)
    else:
        return False
    HeaderOut.append(fcontents)
    return HeaderOut


def ReadFileHeaderDataBySizeWithContentToArray(fp, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__):
    if(not hasattr(fp, "read")):
        return False
    delimiter = formatspecs['format_delimiter']
    fheaderstart = fp.tell()
    if(formatspecs['new_style']):
        HeaderOut = ReadFileHeaderDataBySize(fp, delimiter)
    else:
        HeaderOut = ReadFileHeaderDataWoSize(fp, delimiter)
    if(len(HeaderOut) == 0):
        return False
    fheadsize = int(HeaderOut[0], 16)
    fnumfields = int(HeaderOut[1], 16)
    ftype = int(HeaderOut[2], 16)
    fencoding = HeaderOut[3]
    if(re.findall("^[.|/]", HeaderOut[4])):
        fname = HeaderOut[4]
    else:
        fname = "./"+HeaderOut[4]
    fbasedir = os.path.dirname(fname)
    flinkname = HeaderOut[5]
    fsize = int(HeaderOut[6], 16)
    fatime = int(HeaderOut[7], 16)
    fmtime = int(HeaderOut[8], 16)
    fctime = int(HeaderOut[9], 16)
    fbtime = int(HeaderOut[10], 16)
    fmode = int(HeaderOut[11], 16)
    fchmode = stat.S_IMODE(fmode)
    ftypemod = stat.S_IFMT(fmode)
    fwinattributes = int(HeaderOut[12], 16)
    fcompression = HeaderOut[13]
    fcsize = int(HeaderOut[14], 16)
    fuid = int(HeaderOut[15], 16)
    funame = HeaderOut[16]
    fgid = int(HeaderOut[17], 16)
    fgname = HeaderOut[18]
    fid = int(HeaderOut[19], 16)
    finode = int(HeaderOut[20], 16)
    flinkcount = int(HeaderOut[21], 16)
    fdev = int(HeaderOut[22], 16)
    fdev_minor = int(HeaderOut[23], 16)
    fdev_major = int(HeaderOut[24], 16)
    fseeknextfile = HeaderOut[25]
    fextrasize = int(HeaderOut[26], 16)
    fextrafields = int(HeaderOut[27], 16)
    extrafieldslist = []
    extrastart = 28
    extraend = extrastart + fextrafields
    extrafieldslist = []
    if(extrastart < extraend):
        extrafieldslist.append(HeaderOut[extrastart])
        extrastart = extrastart + 1
    fcs = HeaderOut[-2].lower()
    fccs = HeaderOut[-1].lower()
    newfcs = GetHeaderChecksum(
        HeaderOut[:-2], HeaderOut[-4].lower(), True, formatspecs)
    if(fcs != newfcs and not skipchecksum):
        VerbosePrintOut("File Header Checksum Error with file " +
                        fname + " at offset " + str(fheaderstart))
        VerbosePrintOut("'" + fcs + "' != " + "'" + newfcs + "'")
        return False
    fhend = fp.tell() - 1
    fcontentstart = fp.tell()
    fcontents = BytesIO()
    pyhascontents = False
    if(fsize > 0 and not listonly):
        if(fcompression == "none" or fcompression == "" or fcompression == "auto"):
            fcontents.write(fp.read(fsize))
        else:
            fcontents.write(fp.read(fcsize))
        pyhascontents = True
    elif(fsize > 0 and listonly):
        if(fcompression == "none" or fcompression == "" or fcompression == "auto"):
            fp.seek(fsize, 1)
        else:
            fp.seek(fcsize, 1)
        pyhascontents = False
    fcontents.seek(0, 0)
    newfccs = GetFileChecksum(
        fcontents.read(), HeaderOut[-3].lower(), False, formatspecs)
    if(fccs != newfccs and not skipchecksum and not listonly):
        VerbosePrintOut("File Content Checksum Error with file " +
                        fname + " at offset " + str(fcontentstart))
        VerbosePrintOut("'" + fccs + "' != " + "'" + newfccs + "'")
        return False
    if(fcompression == "none" or fcompression == "" or fcompression == "auto"):
        pass
    else:
        fcontents.seek(0, 0)
        if(uncompress):
            cfcontents = UncompressArchiveFile(
                fcontents, formatspecs)
            cfcontents.seek(0, 0)
            fcontents = BytesIO()
            shutil.copyfileobj(cfcontents, fcontents)
            cfcontents.close()
            fcontents.seek(0, 0)
            fccs = GetFileChecksum(
                fcontents.read(), HeaderOut[-3].lower(), False, formatspecs)
    fcontentend = fp.tell() - 1
    if(re.findall("^\\+([0-9]+)", fseeknextfile)):
        fseeknextasnum = int(fseeknextfile.replace("+", ""))
        if(abs(fseeknextasnum) == 0):
            pass
        fp.seek(fseeknextasnum, 1)
    elif(re.findall("^\\-([0-9]+)", fseeknextfile)):
        fseeknextasnum = int(fseeknextfile)
        if(abs(fseeknextasnum) == 0):
            pass
        fp.seek(fseeknextasnum, 1)
    elif(re.findall("^([0-9]+)", fseeknextfile)):
        fseeknextasnum = int(fseeknextfile)
        if(abs(fseeknextasnum) == 0):
            pass
        fp.seek(fseeknextasnum, 0)
    else:
        return False
    fcontents.seek(0, 0)
    if(not contentasfile):
        fcontents = fcontents.read()
    catlist = {'fheadersize': fheadsize, 'fhstart': fheaderstart, 'fhend': fhend, 'ftype': ftype, 'fencoding': fencoding, 'fname': fname, 'fbasedir': fbasedir, 'flinkname': flinkname, 'fsize': fsize, 'fatime': fatime, 'fmtime': fmtime, 'fctime': fctime, 'fbtime': fbtime, 'fmode': fmode, 'fchmode': fchmode, 'ftypemod': ftypemod, 'fwinattributes': fwinattributes, 'fcompression': fcompression, 'fcsize': fcsize, 'fuid': fuid, 'funame': funame, 'fgid': fgid, 'fgname': fgname, 'finode': finode, 'flinkcount': flinkcount,
               'fdev': fdev, 'fminor': fdev_minor, 'fmajor': fdev_major, 'fseeknextfile': fseeknextfile, 'fheaderchecksumtype': HeaderOut[-4], 'fcontentchecksumtype': HeaderOut[-3], 'fnumfields': fnumfields + 2, 'frawheader': HeaderOut, 'fextrafields': fextrafields, 'fextrafieldsize': fextrasize, 'fextralist': extrafieldslist, 'fheaderchecksum': fcs, 'fcontentchecksum': fccs, 'fhascontents': pyhascontents, 'fcontentstart': fcontentstart, 'fcontentend': fcontentend, 'fcontentasfile': contentasfile, 'fcontents': fcontents}
    return catlist


def ReadFileHeaderDataBySizeWithContentToList(fp, listonly=False, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__):
    if(not hasattr(fp, "read")):
        return False
    delimiter = formatspecs['format_delimiter']
    fheaderstart = fp.tell()
    if(formatspecs['new_style']):
        HeaderOut = ReadFileHeaderDataBySize(fp, delimiter)
    else:
        HeaderOut = ReadFileHeaderDataWoSize(fp, delimiter)
    if(len(HeaderOut) == 0):
        return False
    fheadsize = int(HeaderOut[0], 16)
    fnumfields = int(HeaderOut[1], 16)
    ftype = int(HeaderOut[2], 16)
    fencoding = HeaderOut[3]
    if(re.findall("^[.|/]", HeaderOut[4])):
        fname = HeaderOut[4]
    else:
        fname = "./"+HeaderOut[4]
    fbasedir = os.path.dirname(fname)
    flinkname = HeaderOut[5]
    fsize = int(HeaderOut[6], 16)
    fatime = int(HeaderOut[7], 16)
    fmtime = int(HeaderOut[8], 16)
    fctime = int(HeaderOut[9], 16)
    fbtime = int(HeaderOut[10], 16)
    fmode = int(HeaderOut[11], 16)
    fchmode = stat.S_IMODE(fmode)
    ftypemod = stat.S_IFMT(fmode)
    fwinattributes = int(HeaderOut[12], 16)
    fcompression = HeaderOut[13]
    fcsize = int(HeaderOut[14], 16)
    fuid = int(HeaderOut[15], 16)
    funame = HeaderOut[16]
    fgid = int(HeaderOut[17], 16)
    fgname = HeaderOut[18]
    fid = int(HeaderOut[19], 16)
    finode = int(HeaderOut[20], 16)
    flinkcount = int(HeaderOut[21], 16)
    fdev = int(HeaderOut[22], 16)
    fdev_minor = int(HeaderOut[23], 16)
    fdev_major = int(HeaderOut[24], 16)
    fseeknextfile = HeaderOut[25]
    fextrasize = int(HeaderOut[26], 16)
    fextrafields = int(HeaderOut[27], 16)
    extrafieldslist = []
    extrastart = 28
    extraend = extrastart + fextrafields
    extrafieldslist = []
    if(extrastart < extraend):
        extrafieldslist.append(HeaderOut[extrastart])
        extrastart = extrastart + 1
    fcs = HeaderOut[-2].lower()
    fccs = HeaderOut[-1].lower()
    newfcs = GetHeaderChecksum(
        HeaderOut[:-2], HeaderOut[-4].lower(), True, formatspecs)
    if(fcs != newfcs and not skipchecksum):
        VerbosePrintOut("File Header Checksum Error with file " +
                        fname + " at offset " + str(fheaderstart))
        VerbosePrintOut("'" + fcs + "' != " + "'" + newfcs + "'")
        return False
    fhend = fp.tell() - 1
    fcontentstart = fp.tell()
    fcontents = BytesIO()
    pyhascontents = False
    if(fsize > 0 and not listonly):
        if(fcompression == "none" or fcompression == "" or fcompression == "auto"):
            fcontents.write(fp.read(fsize))
        else:
            fcontents.write(fp.read(fcsize))
        pyhascontents = True
    elif(fsize > 0 and listonly):
        if(fcompression == "none" or fcompression == "" or fcompression == "auto"):
            fp.seek(fsize, 1)
        else:
            fp.seek(fcsize, 1)
        pyhascontents = False
    fcontents.seek(0, 0)
    newfccs = GetFileChecksum(
        fcontents.read(), HeaderOut[-3].lower(), False, formatspecs)
    if(fccs != newfccs and not skipchecksum and not listonly):
        VerbosePrintOut("File Content Checksum Error with file " +
                        fname + " at offset " + str(fcontentstart))
        VerbosePrintOut("'" + fccs + "' != " + "'" + newfccs + "'")
        return False
    if(fcompression == "none" or fcompression == "" or fcompression == "auto"):
        pass
    else:
        fcontents.seek(0, 0)
        if(uncompress):
            cfcontents = UncompressArchiveFile(
                fcontents, formatspecs)
            cfcontents.seek(0, 0)
            fcontents = BytesIO()
            shutil.copyfileobj(cfcontents, fcontents)
            cfcontents.close()
            fcontents.seek(0, 0)
            fccs = GetFileChecksum(
                fcontents.read(), HeaderOut[-3].lower(), False, formatspecs)
    fcontentend = fp.tell() - 1
    if(re.findall("^\\+([0-9]+)", fseeknextfile)):
        fseeknextasnum = int(fseeknextfile.replace("+", ""))
        if(abs(fseeknextasnum) == 0):
            pass
        fp.seek(fseeknextasnum, 1)
    elif(re.findall("^\\-([0-9]+)", fseeknextfile)):
        fseeknextasnum = int(fseeknextfile)
        if(abs(fseeknextasnum) == 0):
            pass
        fp.seek(fseeknextasnum, 1)
    elif(re.findall("^([0-9]+)", fseeknextfile)):
        fseeknextasnum = int(fseeknextfile)
        if(abs(fseeknextasnum) == 0):
            pass
        fp.seek(fseeknextasnum, 0)
    else:
        return False
    fcontents.seek(0, 0)
    fcontents = fcontents.read()
    catlist = [ftype, fencoding, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression, fcsize, fuid, funame, fgid, fgname, fid,
               finode, flinkcount, fdev, fdev_minor, fdev_major, fseeknextfile, extrafieldslist, HeaderOut[-4], HeaderOut[-3], fcontents]
    return catlist


def ReadFileDataBySizeWithContent(fp, listonly=False, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__):
    if(not hasattr(fp, "read")):
        return False
    delimiter = formatspecs['format_delimiter']
    curloc = fp.tell()
    try:
        fp.seek(0, 2);
    except OSError:
        SeekToEndOfFile(fp);
    except ValueError:
        SeekToEndOfFile(fp);
    CatSize = fp.tell();
    CatSizeEnd = CatSize;
    fp.seek(curloc, 0)
    if(curloc > 0):
        fp.seek(0, 0)
    catheaderver = str(int(formatspecs['format_ver'].replace(".", "")))
    catstring = fp.read(formatspecs['format_len'] + len(catheaderver)).decode("UTF-8")
    catdelszie = len(formatspecs['format_delimiter'])
    catdel = fp.read(catdelszie).decode("UTF-8")
    if(catstring != formatspecs['format_magic']+catheaderver):
        return False
    if(catdel != formatspecs['format_delimiter']):
        return False
    if(formatspecs['new_style']):
        catheader = ReadFileHeaderDataBySize(
            fp, formatspecs['format_delimiter'])
    else:
        catheader = ReadFileHeaderDataWoSize(
            fp, formatspecs['format_delimiter'])
    if(curloc > 0):
        fp.seek(curloc, 0)
    fprechecksumtype = catheader[-2]
    fprechecksum = catheader[-1]
    headercheck = ValidateHeaderChecksum([catstring] + catheader[:-1], fprechecksumtype, fprechecksum, formatspecs)
    newfcs = GetHeaderChecksum([catstring] + catheader[:-1], fprechecksumtype, True, formatspecs)
    if(not headercheck and not skipchecksum):
        VerbosePrintOut(
            "File Header Checksum Error with file at offset " + str(0))
        VerbosePrintOut("'" + fprechecksum + "' != " +
                        "'" + newfcs + "'")
        return False
    fnumfiles = int(catheader[4], 16)
    countnum = 0
    flist = []
    while(countnum < fnumfiles):
        HeaderOut = ReadFileHeaderDataBySizeWithContent(
            fp, listonly, uncompress, skipchecksum, formatspecs)
        if(len(HeaderOut) == 0):
            break
        flist.append(HeaderOut)
        countnum = countnum + 1
    return flist


def ReadFileDataBySizeWithContentToArray(fp, seekstart=0, seekend=0, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__):
    if(not hasattr(fp, "read")):
        return False
    delimiter = formatspecs['format_delimiter']
    curloc = fp.tell()
    try:
        fp.seek(0, 2);
    except OSError:
        SeekToEndOfFile(fp);
    except ValueError:
        SeekToEndOfFile(fp);
    CatSize = fp.tell();
    CatSizeEnd = CatSize;
    fp.seek(curloc, 0)
    if(curloc > 0):
        fp.seek(0, 0)
    catheaderver = str(int(formatspecs['format_ver'].replace(".", "")))
    catstring = fp.read(formatspecs['format_len'] + len(catheaderver)).decode("UTF-8")
    catdelszie = len(formatspecs['format_delimiter'])
    catdel = fp.read(catdelszie).decode("UTF-8")
    if(catstring != formatspecs['format_magic']+catheaderver):
        return False
    if(catdel != formatspecs['format_delimiter']):
        return False
    if(formatspecs['new_style']):
        catheader = ReadFileHeaderDataBySize(
            fp, formatspecs['format_delimiter'])
    else:
        catheader = ReadFileHeaderDataWoSize(
            fp, formatspecs['format_delimiter'])
    fnumextrafieldsize = int(catheader[5], 16)
    fnumextrafields = int(catheader[6], 16)
    fextrafieldslist = []
    extrastart = 7
    extraend = extrastart + fnumextrafields
    extrafieldslist = []
    if(extrastart < extraend):
        fextrafieldslist.append(catheader[extrastart])
        extrastart = extrastart + 1
    if(curloc > 0):
        fp.seek(curloc, 0)
    catversion = re.findall("([\\d]+)", catstring)
    fheadsize = int(catheader[0], 16)
    fnumfields = int(catheader[1], 16)
    fhencoding = catheader[2]
    fostype = catheader[3]
    fnumfiles = int(catheader[4], 16)
    fprechecksumtype = catheader[-2]
    fprechecksum = catheader[-1]
    headercheck = ValidateHeaderChecksum([catstring] + catheader[:-1], fprechecksumtype, fprechecksum, formatspecs)
    newfcs = GetHeaderChecksum([catstring] + catheader[:-1], fprechecksumtype, True, formatspecs)
    if(not headercheck and not skipchecksum):
        VerbosePrintOut(
            "File Header Checksum Error with file at offset " + str(0))
        VerbosePrintOut("'" + fprechecksum + "' != " +
                        "'" + newfcs + "'")
        return False
    catversions = re.search('(.*?)(\\d+)', catstring).groups()
    fcompresstype = ""
    catlist = {'fnumfiles': fnumfiles, 'fformat': catversions[0], 'fcompression': fcompresstype, 'fencoding': fhencoding, 'fversion': catversions[1], 'fostype': fostype, 'fheadersize': fheadsize, 'fsize': CatSizeEnd, 'fnumfields': fnumfields + 2, 'fformatspecs': formatspecs, 'fchecksumtype': fprechecksumtype, 'fheaderchecksum': fprechecksum, 'frawheader': [catstring] + catheader, 'fextrafields': fnumextrafields, 'fextrafieldsize': fnumextrafieldsize, 'fextralist': fextrafieldslist, 'ffilelist': []}
    if(seekstart < 0 and seekstart > fnumfiles):
        seekstart = 0
    if(seekend == 0 or seekend > fnumfiles and seekend < seekstart):
        seekend = fnumfiles
    elif(seekend < 0 and abs(seekend) <= fnumfiles and abs(seekend) >= seekstart):
        seekend = fnumfiles - abs(seekend)
    if(seekstart > 0):
        il = 0
        while(il < seekstart):
            prefhstart = fp.tell()
            preheaderdata = ReadFileHeaderDataBySize(
                fp, formatspecs['format_delimiter'])
            if(len(preheaderdata) == 0):
                break
            prefsize = int(preheaderdata[5], 16)
            prefseeknextfile = preheaderdata[25]
            prenewfcs = GetHeaderChecksum(
                preheaderdata[:-2], preheaderdata[-4].lower(), True, formatspecs)
            prefcs = preheaderdata[-2]
            if(prefcs != prenewfcs and not skipchecksum):
                VVerbosePrintOut("File Header Checksum Error with file " +
                                 prefname + " at offset " + str(prefhstart))
                VerbosePrintOut("'" + prefcs + "' != " +
                                "'" + prenewfcs + "'")
                return False
                valid_archive = False
                invalid_archive = True
            prefhend = fp.tell() - 1
            prefcontentstart = fp.tell()
            prefcontents = BytesIO()
            pyhascontents = False
            if(prefsize > 0):
                prefcontents.write(fp.read(prefsize))
                prefcontents.seek(0, 0)
                prenewfccs = GetFileChecksum(
                    prefcontents.read(), preheaderdata[-3].lower(), False, formatspecs)
                prefccs = preheaderdata[-1]
                pyhascontents = True
                if(prefccs != prenewfccs and not skipchecksum):
                    VerbosePrintOut("File Content Checksum Error with file " +
                                    prefname + " at offset " + str(prefcontentstart))
                    VerbosePrintOut("'" + prefccs +
                                    "' != " + "'" + prenewfccs + "'")
                    return False
            if(re.findall("^\\+([0-9]+)", prefseeknextfile)):
                fseeknextasnum = int(prefseeknextfile.replace("+", ""))
                if(abs(fseeknextasnum) == 0):
                    pass
                fp.seek(fseeknextasnum, 1)
            elif(re.findall("^\\-([0-9]+)", prefseeknextfile)):
                fseeknextasnum = int(prefseeknextfile)
                if(abs(fseeknextasnum) == 0):
                    pass
                fp.seek(fseeknextasnum, 1)
            elif(re.findall("^([0-9]+)", prefseeknextfile)):
                fseeknextasnum = int(prefseeknextfile)
                if(abs(fseeknextasnum) == 0):
                    pass
                fp.seek(fseeknextasnum, 0)
            else:
                return False
            il = il + 1
    realidnum = 0
    countnum = seekstart
    while(countnum < seekend):
        HeaderOut = ReadFileHeaderDataBySizeWithContentToArray(
            fp, listonly, contentasfile, uncompress, skipchecksum, formatspecs)
        if(len(HeaderOut) == 0):
            break
        HeaderOut.update({'fid': realidnum, 'fidalt': realidnum})
        catlist['ffilelist'].append(HeaderOut)
        countnum = countnum + 1
        realidnum = realidnum + 1
    return catlist


def ReadFileDataBySizeWithContentToList(fp, seekstart=0, seekend=0, listonly=False, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__):
    if(not hasattr(fp, "read")):
        return False
    delimiter = formatspecs['format_delimiter']
    curloc = fp.tell()
    try:
        fp.seek(0, 2);
    except OSError:
        SeekToEndOfFile(fp);
    except ValueError:
        SeekToEndOfFile(fp);
    CatSize = fp.tell();
    CatSizeEnd = CatSize;
    fp.seek(curloc, 0)
    if(curloc > 0):
        fp.seek(0, 0)
    catheaderver = str(int(formatspecs['format_ver'].replace(".", "")))
    catstring = fp.read(formatspecs['format_len'] + len(catheaderver)).decode("UTF-8")
    catdelszie = len(formatspecs['format_delimiter'])
    catdel = fp.read(catdelszie).decode("UTF-8")
    if(catstring != formatspecs['format_magic']+catheaderver):
        return False
    if(catdel != formatspecs['format_delimiter']):
        return False
    if(formatspecs['new_style']):
        catheader = ReadFileHeaderDataBySize(
            fp, formatspecs['format_delimiter'])
    else:
        catheader = ReadFileHeaderDataWoSize(
            fp, formatspecs['format_delimiter'])
    fnumextrafieldsize = int(catheader[5], 16)
    fnumextrafields = int(catheader[6], 16)
    fextrafieldslist = []
    extrastart = 7
    extraend = extrastart + fnumextrafields
    extrafieldslist = []
    if(extrastart < extraend):
        fextrafieldslist.append(catheader[extrastart])
        extrastart = extrastart + 1
    if(curloc > 0):
        fp.seek(curloc, 0)
    catversion = re.findall("([\\d]+)", catstring)
    fheadsize = int(catheader[0], 16)
    fnumfields = int(catheader[1], 16)
    fhencoding = catheader[2]
    fostype = catheader[3]
    fnumfiles = int(catheader[4], 16)
    fprechecksumtype = catheader[-2]
    fprechecksum = catheader[-1]
    headercheck = ValidateHeaderChecksum([catstring] + catheader[:-1], fprechecksumtype, fprechecksum, formatspecs)
    newfcs = GetHeaderChecksum([catstring] + catheader[:-1], fprechecksumtype, True, formatspecs)
    if(not headercheck and not skipchecksum):
        VerbosePrintOut(
            "File Header Checksum Error with file at offset " + str(0))
        VerbosePrintOut("'" + fprechecksum + "' != " +
                        "'" + newfcs + "'")
        return False
    catversions = re.search('(.*?)(\\d+)', catstring).groups()
    catlist = []
    if(seekstart < 0 and seekstart > fnumfiles):
        seekstart = 0
    if(seekend == 0 or seekend > fnumfiles and seekend < seekstart):
        seekend = fnumfiles
    elif(seekend < 0 and abs(seekend) <= fnumfiles and abs(seekend) >= seekstart):
        seekend = fnumfiles - abs(seekend)
    if(seekstart > 0):
        il = 0
        while(il < seekstart):
            prefhstart = fp.tell()
            preheaderdata = ReadFileHeaderDataBySize(
                fp, formatspecs['format_delimiter'])
            if(len(preheaderdata) == 0):
                break
            prefsize = int(preheaderdata[5], 16)
            prefcompression = preheaderdata[12]
            prefcsize = int(preheaderdata[13], 16)
            prefseeknextfile = HeaderOut[25]
            prenewfcs = GetHeaderChecksum(
                preheaderdata[:-2], preheaderdata[-4].lower(), True, formatspecs)
            prefcs = preheaderdata[-2]
            if(prefcs != prenewfcs and not skipchecksum):
                VerbosePrintOut("File Header Checksum Error with file " +
                                prefname + " at offset " + str(prefhstart))
                VerbosePrintOut("'" + prefcs + "' != " +
                                "'" + prenewfcs + "'")
                return False
                valid_archive = False
                invalid_archive = True
            prefhend = fp.tell() - 1
            prefcontentstart = fp.tell()
            prefcontents = ""
            pyhascontents = False
            if(prefsize > 0):
                if(prefcompression == "none" or prefcompression == "" or prefcompression == "auto"):
                    prefcontents = fp.read(prefsize)
                else:
                    prefcontents = fp.read(prefcsize)
                prenewfccs = GetFileChecksum(
                    prefcontents, preheaderdata[-3].lower(), False, formatspecs)
                prefccs = preheaderdata[-1]
                pyhascontents = True
                if(prefccs != prenewfccs and not skipchecksum):
                    VerbosePrintOut("File Content Checksum Error with file " +
                                    prefname + " at offset " + str(prefcontentstart))
                    VerbosePrintOut("'" + prefccs +
                                    "' != " + "'" + prenewfccs + "'")
                    return False
            if(re.findall("^\\+([0-9]+)", prefseeknextfile)):
                fseeknextasnum = int(prefseeknextfile.replace("+", ""))
                if(abs(fseeknextasnum) == 0):
                    pass
                fp.seek(fseeknextasnum, 1)
            elif(re.findall("^\\-([0-9]+)", prefseeknextfile)):
                fseeknextasnum = int(prefseeknextfile)
                if(abs(fseeknextasnum) == 0):
                    pass
                fp.seek(fseeknextasnum, 1)
            elif(re.findall("^([0-9]+)", prefseeknextfile)):
                fseeknextasnum = int(prefseeknextfile)
                if(abs(fseeknextasnum) == 0):
                    pass
                fp.seek(fseeknextasnum, 0)
            else:
                return False
            il = il + 1
    realidnum = 0
    countnum = seekstart
    while(countnum < seekend):
        HeaderOut = ReadFileHeaderDataBySizeWithContentToList(
            fp, listonly, uncompress, skipchecksum, formatspecs)
        if(len(HeaderOut) == 0):
            break
        catlist.append(HeaderOut)
        countnum = countnum + 1
        realidnum = realidnum + 1
    return catlist


def ReadInFileBySizeWithContentToArray(infile, seekstart=0, seekend=0, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__):
    if(hasattr(infile, "read") or hasattr(infile, "write")):
        fp = infile
        fp.seek(0, 0)
        compresscheck = CheckCompressionType(fp, formatspecs, False)
        fp.seek(0, 0)
        fp = UncompressArchiveFile(fp, formatspecs)
        checkcompressfile = CheckCompressionSubType(fp, formatspecs, True)
        if(checkcompressfile == "tarfile" and TarFileCheck(infile)):
            return TarFileToArray(infile, seekstart, seekend, listonly, contentasfile, skipchecksum, formatspecs, returnfp)
        elif(checkcompressfile == "zipfile" and zipfile.is_zipfile(infile)):
            return ZipFileToArray(infile, seekstart, seekend, listonly, contentasfile, skipchecksum, formatspecs, returnfp)
        elif(rarfile_support and checkcompressfile == "rarfile" and (rarfile.is_rarfile(infile) or rarfile.is_rarfile_sfx(infile))):
            return RarFileToArray(infile, seekstart, seekend, listonly, contentasfile, skipchecksum, formatspecs, returnfp)
        elif(py7zr_support and checkcompressfile == "7zipfile" and py7zr.is_7zfile(infile)):
            return SevenZipFileToArray(infile, seekstart, seekend, listonly, contentasfile, skipchecksum, formatspecs, returnfp)
        elif(checkcompressfile != formatspecs['format_magic']):
            return False
        if(not fp):
            return False
        if(not compresscheck and hasattr(fp, "name")):
            fextname = os.path.splitext(fp.name)[1]
            if(fextname == ".gz"):
                compresscheck = "gzip"
            elif(fextname == ".bz2"):
                compresscheck = "bzip2"
            elif(fextname == ".zst"):
                compresscheck = "zstd"
            elif(fextname == ".lz4" or fextname == ".clz4"):
                compresscheck = "lz4"
            elif(fextname == ".lzo" or fextname == ".lzop"):
                compresscheck = "lzo"
            elif(fextname == ".lzma"):
                compresscheck = "lzma"
            elif(fextname == ".xz"):
                compresscheck = "xz"
            elif(fextname == ".zz" or fextname == ".zl" or fextname == ".zlib"):
                compresscheck = "zlib"
            else:
                return False
        fp.seek(0, 0)
    elif(infile == "-"):
        fp = BytesIO()
        if(hasattr(sys.stdin, "buffer")):
            shutil.copyfileobj(sys.stdin.buffer, fp)
        else:
            shutil.copyfileobj(sys.stdin, fp)
        fp.seek(0, 0)
        compresscheck = CheckCompressionType(fp, formatspecs, False)
        fp.seek(0, 0)
        fp = UncompressArchiveFile(fp, formatspecs)
        if(not fp):
            return False
        fp.seek(0, 0)
    elif(isinstance(infile, bytes) and sys.version_info[0] >= 3):
        fp = BytesIO()
        fp.write(infile)
        fp.seek(0, 0)
        compresscheck = CheckCompressionType(fp, formatspecs, False)
        fp.seek(0, 0)
        fp = UncompressArchiveFile(fp, formatspecs)
        if(not fp):
            return False
        fp.seek(0, 0)
    elif(re.findall("^(http|https|ftp|ftps|sftp):\\/\\/", infile)):
        fp = download_file_from_internet_file(infile)
        compresscheck = CheckCompressionType(fp, formatspecs, False)
        if(not compresscheck):
            fextname = os.path.splitext(infile)[1]
            if(fextname == ".gz"):
                compresscheck = "gzip"
            elif(fextname == ".bz2"):
                compresscheck = "bzip2"
            elif(fextname == ".zst"):
                compresscheck = "zstd"
            elif(fextname == ".lz4" or fextname == ".clz4"):
                compresscheck = "lz4"
            elif(fextname == ".lzo" or fextname == ".lzop"):
                compresscheck = "lzo"
            elif(fextname == ".lzma"):
                compresscheck = "lzma"
            elif(fextname == ".xz"):
                compresscheck = "xz"
            elif(fextname == ".zz" or fextname == ".zl" or fextname == ".zlib"):
                compresscheck = "zlib"
            else:
                return False
        fp.seek(0, 0)
        fp = UncompressArchiveFile(fp, formatspecs)
        if(not fp):
            return False
        fp.seek(0, 0)
    else:
        infile = RemoveWindowsPath(infile)
        checkcompressfile = CheckCompressionSubType(infile, formatspecs, True)
        if(checkcompressfile == "tarfile" and TarFileCheck(infile)):
            return TarFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp)
        elif(checkcompressfile == "zipfile" and zipfile.is_zipfile(infile)):
            return ZipFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp)
        elif(rarfile_support and checkcompressfile == "rarfile" and (rarfile.is_rarfile(infile) or rarfile.is_rarfile_sfx(infile))):
            return RarFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp)
        elif(py7zr_support and checkcompressfile == "7zipfile" and py7zr.is_7zfile(infile)):
            return SevenZipFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp)
        elif(checkcompressfile != formatspecs['format_magic']):
            return False
        compresscheck = CheckCompressionType(infile, formatspecs, True)
        if(not compresscheck):
            fextname = os.path.splitext(infile)[1]
            if(fextname == ".gz"):
                compresscheck = "gzip"
            elif(fextname == ".bz2"):
                compresscheck = "bzip2"
            elif(fextname == ".zst"):
                compresscheck = "zstd"
            elif(fextname == ".lz4" or fextname == ".clz4"):
                compresscheck = "lz4"
            elif(fextname == ".lzo" or fextname == ".lzop"):
                compresscheck = "lzo"
            elif(fextname == ".lzma"):
                compresscheck = "lzma"
            elif(fextname == ".xz"):
                compresscheck = "xz"
            elif(fextname == ".zz" or fextname == ".zl" or fextname == ".zlib"):
                compresscheck = "zlib"
            else:
                return False
        if(not compresscheck):
            return False
        fp = UncompressFile(infile, formatspecs, "rb")
    return ReadFileDataBySizeWithContentToArray(fp, seekstart, seekend, listonly, contentasfile, uncompress, skipchecksum, formatspecs)


def ReadInFileBySizeWithContentToList(infile, seekstart=0, seekend=0, listonly=False, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__):
    if(hasattr(infile, "read") or hasattr(infile, "write")):
        fp = infile
        fp.seek(0, 0)
        compresscheck = CheckCompressionType(fp, formatspecs, False)
        fp.seek(0, 0)
        fp = UncompressArchiveFile(fp, formatspecs)
        checkcompressfile = CheckCompressionSubType(fp, formatspecs, True)
        if(checkcompressfile == "tarfile" and TarFileCheck(infile)):
            return TarFileToArray(infile, seekstart, seekend, listonly, contentasfile, skipchecksum, formatspecs, returnfp)
        elif(checkcompressfile == "zipfile" and zipfile.is_zipfile(infile)):
            return ZipFileToArray(infile, seekstart, seekend, listonly, contentasfile, skipchecksum, formatspecs, returnfp)
        elif(rarfile_support and checkcompressfile == "rarfile" and (rarfile.is_rarfile(infile) or rarfile.is_rarfile_sfx(infile))):
            return RarFileToArray(infile, seekstart, seekend, listonly, contentasfile, skipchecksum, formatspecs, returnfp)
        elif(py7zr_support and checkcompressfile == "7zipfile" and py7zr.is_7zfile(infile)):
            return SevenZipFileToArray(infile, seekstart, seekend, listonly, contentasfile, skipchecksum, formatspecs, returnfp)
        elif(checkcompressfile != formatspecs['format_magic']):
            return False
        if(not fp):
            return False
        if(not compresscheck and hasattr(fp, "name")):
            fextname = os.path.splitext(fp.name)[1]
            if(fextname == ".gz"):
                compresscheck = "gzip"
            elif(fextname == ".bz2"):
                compresscheck = "bzip2"
            elif(fextname == ".zst"):
                compresscheck = "zstd"
            elif(fextname == ".lz4" or fextname == ".clz4"):
                compresscheck = "lz4"
            elif(fextname == ".lzo" or fextname == ".lzop"):
                compresscheck = "lzo"
            elif(fextname == ".lzma"):
                compresscheck = "lzma"
            elif(fextname == ".xz"):
                compresscheck = "xz"
            elif(fextname == ".zz" or fextname == ".zl" or fextname == ".zlib"):
                compresscheck = "zlib"
            else:
                return False
        fp.seek(0, 0)
    elif(infile == "-"):
        fp = BytesIO()
        if(hasattr(sys.stdin, "buffer")):
            shutil.copyfileobj(sys.stdin.buffer, fp)
        else:
            shutil.copyfileobj(sys.stdin, fp)
        fp.seek(0, 0)
        compresscheck = CheckCompressionType(fp, formatspecs, False)
        fp.seek(0, 0)
        fp = UncompressArchiveFile(fp, formatspecs)
        if(not fp):
            return False
        fp.seek(0, 0)
    elif(isinstance(infile, bytes) and sys.version_info[0] >= 3):
        fp = BytesIO()
        fp.write(infile)
        fp.seek(0, 0)
        compresscheck = CheckCompressionType(fp, formatspecs, False)
        fp.seek(0, 0)
        fp = UncompressArchiveFile(fp, formatspecs)
        if(not fp):
            return False
        fp.seek(0, 0)
    elif(re.findall("^(http|https|ftp|ftps|sftp):\\/\\/", infile)):
        fp = download_file_from_internet_file(infile)
        compresscheck = CheckCompressionType(fp, formatspecs, False)
        if(not compresscheck):
            fextname = os.path.splitext(infile)[1]
            if(fextname == ".gz"):
                compresscheck = "gzip"
            elif(fextname == ".bz2"):
                compresscheck = "bzip2"
            elif(fextname == ".zst"):
                compresscheck = "zstd"
            elif(fextname == ".lz4" or fextname == ".clz4"):
                compresscheck = "lz4"
            elif(fextname == ".lzo" or fextname == ".lzop"):
                compresscheck = "lzo"
            elif(fextname == ".lzma"):
                compresscheck = "lzma"
            elif(fextname == ".xz"):
                compresscheck = "xz"
            elif(fextname == ".zz" or fextname == ".zl" or fextname == ".zlib"):
                compresscheck = "zlib"
            else:
                return False
        fp.seek(0, 0)
        fp = UncompressArchiveFile(fp, formatspecs)
        if(not fp):
            return False
        fp.seek(0, 0)
    else:
        infile = RemoveWindowsPath(infile)
        checkcompressfile = CheckCompressionSubType(infile, formatspecs, True)
        if(checkcompressfile == "tarfile" and TarFileCheck(infile)):
            return TarFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp)
        elif(checkcompressfile == "zipfile" and zipfile.is_zipfile(infile)):
            return ZipFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp)
        elif(rarfile_support and checkcompressfile == "rarfile" and (rarfile.is_rarfile(infile) or rarfile.is_rarfile_sfx(infile))):
            return RarFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp)
        elif(py7zr_support and checkcompressfile == "7zipfile" and py7zr.is_7zfile(infile)):
            return SevenZipFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp)
        elif(checkcompressfile != formatspecs['format_magic']):
            return False
        compresscheck = CheckCompressionType(infile, formatspecs, True)
        if(not compresscheck):
            fextname = os.path.splitext(infile)[1]
            if(fextname == ".gz"):
                compresscheck = "gzip"
            elif(fextname == ".bz2"):
                compresscheck = "bzip2"
            elif(fextname == ".zst"):
                compresscheck = "zstd"
            elif(fextname == ".lz4" or fextname == ".clz4"):
                compresscheck = "lz4"
            elif(fextname == ".lzo" or fextname == ".lzop"):
                compresscheck = "lzo"
            elif(fextname == ".lzma"):
                compresscheck = "lzma"
            elif(fextname == ".xz"):
                compresscheck = "xz"
            elif(fextname == ".zz" or fextname == ".zl" or fextname == ".zlib"):
                compresscheck = "zlib"
            else:
                return False
        if(not compresscheck):
            return False
        fp = UncompressFile(infile, formatspecs, "rb")
    return ReadFileDataBySizeWithContentToList(fp, seekstart, seekend, listonly, uncompress, skipchecksum, formatspecs)


def AppendNullByte(indata, delimiter=__file_format_dict__['format_delimiter']):
    if(isinstance(indata, int)):
        indata = str(indata)
    outdata = indata + delimiter
    return outdata


def AppendNullBytes(indata=[], delimiter=__file_format_dict__['format_delimiter']):
    outdata = ""
    inum = 0
    il = len(indata)
    while(inum < il):
        outdata = outdata + AppendNullByte(indata[inum], delimiter)
        inum = inum + 1
    return outdata


def AppendFileHeader(fp, numfiles, fencoding, extradata=[], checksumtype="crc32", formatspecs=__file_format_dict__):
    if(not hasattr(fp, "write")):
        return False
    delimiter = formatspecs['format_delimiter']
    catver = formatspecs['format_ver']
    fileheaderver = str(int(catver.replace(".", "")))
    fileheader = AppendNullByte(
        formatspecs['format_magic'] + fileheaderver, formatspecs['format_delimiter'])
    extrafields = format(len(extradata), 'x').lower()
    extrasizestr = AppendNullByte(extrafields, formatspecs['format_delimiter'])
    if(len(extradata) > 0):
        extrasizestr = extrasizestr + \
            AppendNullBytes(extradata, formatspecs['format_delimiter'])
    extrasizelen = format(len(extrasizestr), 'x').lower()
    catoutlist = []
    catoutlist.append(extrasizelen)
    catoutlist.append(extrafields)
    fnumfiles = format(int(numfiles), 'x').lower()
    catoutlen = 3 + len(catoutlist) + len(extradata) + 2
    catoutlenhex = format(catoutlen, 'x').lower()
    fnumfilesa = AppendNullBytes(
        [catoutlenhex, fencoding, platform.system(), fnumfiles], formatspecs['format_delimiter'])
    fnumfilesa = fnumfilesa + AppendNullBytes(
        catoutlist, formatspecs['format_delimiter'])
    if(len(extradata) > 0):
        fnumfilesa = fnumfilesa + AppendNullBytes(
            extradata, formatspecs['format_delimiter'])
    fnumfilesa = fnumfilesa + \
        AppendNullByte(checksumtype, formatspecs['format_delimiter'])
    catfileheadercshex = GetFileChecksum(
        fnumfilesa, checksumtype, True, formatspecs)
    tmpfileoutstr = fnumfilesa + \
        AppendNullByte(catfileheadercshex,
                        formatspecs['format_delimiter'])
    catheaersize = format(int(len(tmpfileoutstr) - len(formatspecs['format_delimiter'])), 'x').lower()
    fnumfilesa = fileheader + \
        AppendNullByte(
        catheaersize, formatspecs['format_delimiter']) + fnumfilesa
    catfileheadercshex = GetFileChecksum(
        fnumfilesa, checksumtype, True, formatspecs)
    fnumfilesa = fnumfilesa + \
        AppendNullByte(catfileheadercshex, formatspecs['format_delimiter'])
    catheaersize = format(int(len(fnumfilesa) - len(formatspecs['format_delimiter'])), 'x').lower()
    catheaersizestr = AppendNullByte(catheaersize, formatspecs['format_delimiter'])
    try:
        fp.write(fnumfilesa.encode('UTF-8'))
    except OSError:
        return False
    try:
        fp.flush()
        if(hasattr(os, "sync")):
            os.fsync(fp.fileno())
    except io.UnsupportedOperation:
        pass
    except AttributeError:
        pass
    except OSError:
        pass
    return fp


def MakeEmptyFilePointer(fp, checksumtype="crc32", formatspecs=__file_format_dict__):
    AppendFileHeader(fp, 0, "UTF-8", [], checksumtype, formatspecs)
    return fp


def MakeEmptyArchiveFilePointer(fp, checksumtype="crc32", formatspecs=__file_format_dict__):
    return MakeEmptyFilePointer(fp, checksumtype, formatspecs)


def MakeEmptyFile(outfile, compression="auto", compresswholefile=True, compressionlevel=None, checksumtype="crc32", formatspecs=__file_format_dict__, returnfp=False):
    if(outfile != "-" and outfile is not None and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
        if(os.path.exists(outfile)):
            try:
                os.unlink(outfile)
            except OSError:
                pass
    if(outfile == "-" or outfile is None):
        verbose = False
        fp = BytesIO()
    elif(hasattr(outfile, "read") or hasattr(outfile, "write")):
        fp = outfile
    elif(re.findall("^(ftp|ftps|sftp):\\/\\/", outfile)):
        fp = BytesIO()
    else:
        fbasename = os.path.splitext(outfile)[0]
        fextname = os.path.splitext(outfile)[1]
        if(not compresswholefile and fextname in outextlistwd):
            compresswholefile = True
        fp = CompressOpenFile(outfile, True, compressionlevel)
    AppendFileHeader(fp, 0, "UTF-8", [], checksumtype, formatspecs)
    if(outfile == "-" or outfile is None or hasattr(outfile, "read") or hasattr(outfile, "write")):
        fp = CompressArchiveFile(
            fp, compression, compressionlevel, formatspecs)
        try:
            fp.flush()
            if(hasattr(os, "sync")):
                os.fsync(fp.fileno())
        except io.UnsupportedOperation:
            pass
        except AttributeError:
            pass
        except OSError:
            pass
    if(outfile == "-"):
        fp.seek(0, 0)
        if(hasattr(sys.stdout, "buffer")):
            shutil.copyfileobj(fp, sys.stdout.buffer)
        else:
            shutil.copyfileobj(fp, sys.stdout)
    elif(outfile is None):
        fp.seek(0, 0)
        outvar = fp.read()
        fp.close()
        return outvar
    elif(re.findall("^(ftp|ftps|sftp):\\/\\/", outfile)):
        fp = CompressArchiveFile(
            fp, compression, compressionlevel, formatspecs)
        fp.seek(0, 0)
        upload_file_to_internet_file(fp, outfile)
    if(returnfp):
        fp.seek(0, 0)
        return fp
    else:
        fp.close()
        return True


def MakeEmptyArchiveFile(outfile, compression="auto", compresswholefile=True, compressionlevel=None, checksumtype="crc32", formatspecs=__file_format_dict__, returnfp=False):
    return MakeEmptyFile(outfile, compression, compresswholefile, compressionlevel, checksumtype, formatspecs, returnfp)


def AppendFileHeaderWithContent(fp, filevalues=[], extradata=[], filecontent="", checksumtype=["crc32", "crc32"], formatspecs=__file_format_dict__):
    if(not hasattr(fp, "write")):
        return False
    extrafields = format(len(extradata), 'x').lower()
    extrasizestr = AppendNullByte(extrafields, formatspecs['format_delimiter'])
    if(len(extradata) > 0):
        extrasizestr = extrasizestr + \
            AppendNullBytes(extradata, formatspecs['format_delimiter'])
    extrasizelen = format(len(extrasizestr), 'x').lower()
    catoutlen = len(filevalues) + len(extradata) + 6
    catoutlenhex = format(catoutlen, 'x').lower()
    catoutlist = filevalues
    catoutlist.insert(0, catoutlenhex)
    catoutlist.append(extrasizelen)
    catoutlist.append(extrafields)
    catfileoutstr = AppendNullBytes(
        catoutlist, formatspecs['format_delimiter'])
    if(len(extradata) > 0):
        catfileoutstr = catfileoutstr + \
            AppendNullBytes(extradata, formatspecs['format_delimiter'])
    if(len(filecontent) == 0):
        checksumlist = [checksumtype[0], "none"]
    else:
        checksumlist = checksumtype
    catfileoutstr = catfileoutstr + \
        AppendNullBytes(checksumlist, formatspecs['format_delimiter'])
    catfileheadercshex = GetFileChecksum(
        catfileoutstr, checksumtype[0], True, formatspecs)
    if(len(filecontent) == 0):
        catfilecontentcshex = GetFileChecksum(
            filecontent, "none", False, formatspecs)
    else:
        catfilecontentcshex = GetFileChecksum(
            filecontent, checksumtype[1], False, formatspecs)
    tmpfileoutstr = catfileoutstr + \
        AppendNullBytes([catfileheadercshex, catfilecontentcshex],
                        formatspecs['format_delimiter'])
    catheaersize = format(int(len(tmpfileoutstr) - len(formatspecs['format_delimiter'])), 'x').lower()
    catfileoutstr = AppendNullByte(
        catheaersize, formatspecs['format_delimiter']) + catfileoutstr
    catfileheadercshex = GetFileChecksum(
        catfileoutstr, checksumtype[0], True, formatspecs)
    catfileoutstr = catfileoutstr + \
        AppendNullBytes([catfileheadercshex, catfilecontentcshex],
                        formatspecs['format_delimiter'])
    catfileoutstrecd = catfileoutstr.encode('UTF-8')
    nullstrecd = formatspecs['format_delimiter'].encode('UTF-8')
    catfileout = catfileoutstrecd + filecontent + nullstrecd
    try:
        fp.write(catfileout)
    except OSError:
        return False
    try:
        fp.flush()
        if(hasattr(os, "sync")):
            os.fsync(fp.fileno())
    except io.UnsupportedOperation:
        pass
    except AttributeError:
        pass
    except OSError:
        pass
    return fp


def AppendFilesWithContent(infiles, fp, dirlistfromtxt=False, filevalues=[], extradata=[], compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, followlink=False, checksumtype=["crc32", "crc32", "crc32"], formatspecs=__file_format_dict__, verbose=False):
    if(not hasattr(fp, "write")):
        return False
    advancedlist = formatspecs['use_advanced_list']
    altinode = formatspecs['use_alt_inode']
    if(verbose):
        logging.basicConfig(format="%(message)s",
                            stream=sys.stdout, level=logging.DEBUG)
    if(infiles == "-"):
        for line in sys.stdin:
            infilelist.append(line.strip())
        infilelist = list(filter(None, infilelist))
    elif(infiles != "-" and dirlistfromtxt and os.path.exists(infiles) and (os.path.isfile(infiles) or infiles == os.devnull)):
        if(not os.path.exists(infiles) or not os.path.isfile(infiles)):
            return False
        with UncompressFile(infiles, formatspecs, "r") as finfile:
            for line in finfile:
                infilelist.append(line.strip())
        infilelist = list(filter(None, infilelist))
    else:
        if(isinstance(infiles, (list, tuple, ))):
            infilelist = list(filter(None, infiles))
        elif(isinstance(infiles, (basestring, ))):
            infilelist = list(filter(None, [infiles]))
    try:
        if os.stat not in os.supports_follow_symlinks and followlink:
            followlink = False
    except AttributeError:
        followlink = False
    if(advancedlist):
        GetDirList = ListDirAdvanced(infilelist, followlink, False)
    elif(advancedlist is None):
        GetDirList = infilelist
    else:
        GetDirList = ListDir(infilelist, followlink, False)
    if(not isinstance(GetDirList, (list, tuple, ))):
        return False
    FullSizeFiles = GetTotalSize(GetDirList)
    if(not GetDirList):
        return False
    curinode = 0
    curfid = 0
    inodelist = []
    inodetofile = {}
    filetoinode = {}
    inodetocatinode = {}
    numfiles = int(len(GetDirList))
    fnumfiles = format(numfiles, 'x').lower()
    AppendFileHeader(fp, fnumfiles, "UTF-8", [], checksumtype[0], formatspecs)
    FullSizeFilesAlt = 0
    for curfname in GetDirList:
        fencoding = "UTF-8"
        if(re.findall("^[.|/]", curfname)):
            fname = curfname
        else:
            fname = "./"+curfname
        if(verbose):
            VerbosePrintOut(fname)
        if(not followlink or followlink is None):
            fstatinfo = os.lstat(fname)
        else:
            fstatinfo = os.stat(fname)
        fpremode = fstatinfo.st_mode
        finode = fstatinfo.st_ino
        flinkcount = fstatinfo.st_nlink
        try:
            FullSizeFilesAlt += fstatinfo.st_rsize
        except AttributeError:
            FullSizeFilesAlt += fstatinfo.st_size
        ftype = 0
        if(hasattr(os.path, "isjunction") and os.path.isjunction(fname)):
            ftype = 13
        elif(fstatinfo.st_blocks * 512 < fstatinfo.st_size):
            ftype = 12
        elif(stat.S_ISREG(fpremode)):
            ftype = 0
        elif(stat.S_ISLNK(fpremode)):
            ftype = 2
        elif(stat.S_ISCHR(fpremode)):
            ftype = 3
        elif(stat.S_ISBLK(fpremode)):
            ftype = 4
        elif(stat.S_ISDIR(fpremode)):
            ftype = 5
        elif(stat.S_ISFIFO(fpremode)):
            ftype = 6
        elif(stat.S_ISSOCK(fpremode)):
            ftype = 8
        elif(hasattr(stat, "S_ISDOOR") and stat.S_ISDOOR(fpremode)):
            ftype = 9
        elif(hasattr(stat, "S_ISPORT") and stat.S_ISPORT(fpremode)):
            ftype = 10
        elif(hasattr(stat, "S_ISWHT") and stat.S_ISWHT(fpremode)):
            ftype = 11
        else:
            ftype = 0
        flinkname = ""
        fcurfid = format(int(curfid), 'x').lower()
        if not followlink and finode != 0:
            unique_id = (fstatinfo.st_dev, finode)
            if ftype != 1:
                if unique_id in inodelist:
                    # Hard link detected
                    ftype = 1
                    flinkname = inodetofile[unique_id]
                    if altinode:
                        fcurinode = format(int(unique_id[1]), 'x').lower()
                    else:
                        fcurinode = format(int(inodetocatinode[unique_id]), 'x').lower()
                else:
                    # New inode
                    inodelist.append(unique_id)
                    inodetofile[unique_id] = fname
                    inodetocatinode[unique_id] = curinode
                    if altinode:
                        fcurinode = format(int(unique_id[1]), 'x').lower()
                    else:
                        fcurinode = format(int(curinode), 'x').lower()
                    curinode += 1
        else:
            # Handle cases where inodes are not supported or symlinks are followed
            fcurinode = format(int(curinode), 'x').lower()
            curinode += 1
        curfid = curfid + 1
        if(ftype == 2):
            flinkname = os.readlink(fname)
        try:
            fdev = fstatinfo.st_rdev
        except AttributeError:
            fdev = 0
        getfdev = GetDevMajorMinor(fdev)
        fdev_minor = getfdev[0]
        fdev_major = getfdev[1]
        # Types that should be considered zero-length in the archive context:
        zero_length_types = {1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 13}
        # Types that have actual data to read:
        data_types = {0, 7, 12}
        if ftype in zero_length_types:
            fsize = format(int("0"), 'x').lower()
        elif ftype in data_types:
            fsize = format(int(fstatinfo.st_size), 'x').lower()
        else:
            fsize = format(int(fstatinfo.st_size)).lower()
        fatime = format(int(fstatinfo.st_atime), 'x').lower()
        fmtime = format(int(fstatinfo.st_mtime), 'x').lower()
        fctime = format(int(fstatinfo.st_ctime), 'x').lower()
        if(hasattr(fstatinfo, "st_birthtime")):
            fbtime = format(int(fstatinfo.st_birthtime), 'x').lower()
        else:
            fbtime = format(int(fstatinfo.st_ctime), 'x').lower()
        fmode = format(int(fstatinfo.st_mode), 'x').lower()
        fchmode = format(int(stat.S_IMODE(fstatinfo.st_mode)), 'x').lower()
        ftypemod = format(int(stat.S_IFMT(fstatinfo.st_mode)), 'x').lower()
        fuid = format(int(fstatinfo.st_uid), 'x').lower()
        fgid = format(int(fstatinfo.st_gid), 'x').lower()
        funame = ""
        try:
            import pwd
            try:
                userinfo = pwd.getpwuid(fstatinfo.st_uid)
                funame = userinfo.pw_name
            except KeyError:
                funame = ""
        except ImportError:
            funame = ""
        fgname = ""
        try:
            import grp
            try:
                groupinfo = grp.getgrgid(fstatinfo.st_gid)
                fgname = groupinfo.gr_name
            except KeyError:
                fgname = ""
        except ImportError:
            fgname = ""
        fdev = format(int(fdev), 'x').lower()
        fdev_minor = format(int(fdev_minor), 'x').lower()
        fdev_major = format(int(fdev_major), 'x').lower()
        finode = format(int(finode), 'x').lower()
        flinkcount = format(int(flinkcount), 'x').lower()
        if(hasattr(fstatinfo, "st_file_attributes")):
            fwinattributes = format(
                int(fstatinfo.st_file_attributes), 'x').lower()
        else:
            fwinattributes = format(int(0), 'x').lower()
        fcompression = ""
        fcsize = format(int(0), 'x').lower()
        fcontents = BytesIO()
        chunk_size = 1024
        if ftype in data_types:
            with open(fname, "rb") as fpc:
                shutil.copyfileobj(fpc, fcontents)
                if(not compresswholefile):
                    fcontents.seek(0, 2)
                    ucfsize = fcontents.tell()
                    fcontents.seek(0, 0)
                    if(compression == "auto"):
                        ilsize = len(compressionuselist)
                        ilmin = 0
                        ilcsize = []
                        while(ilmin < ilsize):
                            cfcontents = BytesIO()
                            fcontents.seek(0, 0)
                            shutil.copyfileobj(fcontents, cfcontents)
                            fcontents.seek(0, 0)
                            cfcontents.seek(0, 0)
                            cfcontents = CompressArchiveFile(
                                cfcontents, compressionuselist[ilmin], compressionlevel, formatspecs)
                            if(cfcontents):
                                cfcontents.seek(0, 2)
                                ilcsize.append(cfcontents.tell())
                                cfcontents.close()
                            else:
                                try:
                                    ilcsize.append(sys.maxint)
                                except AttributeError:
                                    ilcsize.append(sys.maxsize)
                            ilmin = ilmin + 1
                        ilcmin = ilcsize.index(min(ilcsize))
                        curcompression = compressionuselist[ilcmin]
                    fcontents.seek(0, 0)
                    cfcontents = BytesIO()
                    shutil.copyfileobj(fcontents, cfcontents)
                    cfcontents.seek(0, 0)
                    cfcontents = CompressArchiveFile(
                        cfcontents, curcompression, compressionlevel, formatspecs)
                    cfcontents.seek(0, 2)
                    cfsize = cfcontents.tell()
                    if(ucfsize > cfsize):
                        fcsize = format(int(cfsize), 'x').lower()
                        fcompression = curcompression
                        fcontents.close()
                        fcontents = cfcontents
        if(followlink and (ftype == 1 or ftype == 2)):
            flstatinfo = os.stat(flinkname)
            with open(flinkname, "rb") as fpc:
                shutil.copyfileobj(fpc, fcontents)
                if(not compresswholefile):
                    fcontents.seek(0, 2)
                    ucfsize = fcontents.tell()
                    fcontents.seek(0, 0)
                    if(compression == "auto"):
                        ilsize = len(compressionuselist)
                        ilmin = 0
                        ilcsize = []
                        while(ilmin < ilsize):
                            cfcontents = BytesIO()
                            fcontents.seek(0, 0)
                            shutil.copyfileobj(fcontents, cfcontents)
                            fcontents.seek(0, 0)
                            cfcontents.seek(0, 0)
                            cfcontents = CompressArchiveFile(
                                cfcontents, compressionuselist[ilmin], compressionlevel, formatspecs)
                            if(cfcontents):
                                cfcontents.seek(0, 2)
                                ilcsize.append(cfcontents.tell())
                                cfcontents.close()
                            else:
                                try:
                                    ilcsize.append(sys.maxint)
                                except AttributeError:
                                    ilcsize.append(sys.maxsize)
                            ilmin = ilmin + 1
                        ilcmin = ilcsize.index(min(ilcsize))
                        curcompression = compressionuselist[ilcmin]
                    fcontents.seek(0, 0)
                    cfcontents = BytesIO()
                    shutil.copyfileobj(fcontents, cfcontents)
                    cfcontents.seek(0, 0)
                    cfcontents = CompressArchiveFile(
                        cfcontents, curcompression, compressionlevel, formatspecs)
                    cfcontents.seek(0, 2)
                    cfsize = cfcontents.tell()
                    if(ucfsize > cfsize):
                        fcsize = format(int(cfsize), 'x').lower()
                        fcompression = curcompression
                        fcontents.close()
                        fcontents = cfcontents
        if(fcompression == "none"):
            fcompression = ""
        fcontents.seek(0, 0)
        ftypehex = format(ftype, 'x').lower()
        catoutlist = [ftypehex, fencoding, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression,
                      fcsize, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev, fdev_minor, fdev_major, "+"+str(len(formatspecs['format_delimiter']))]
        AppendFileHeaderWithContent(
            fp, catoutlist, extradata, fcontents.read(), [checksumtype[1], checksumtype[2]], formatspecs)
    if(numfiles > 0):
        try:
            fp.write(AppendNullBytes(
                ["0", "0"], formatspecs['format_delimiter']).encode("UTF-8"))
        except OSError:
            return False
    fp.seek(0, 0)
    return fp


def AppendListsWithContent(inlist, fp, dirlistfromtxt=False, filevalues=[], extradata=[], compression="auto", compresswholefile=True, compressionlevel=None, followlink=False, checksumtype=["crc32", "crc32", "crc32"], formatspecs=__file_format_dict__, verbose=False):
    if(not hasattr(fp, "write")):
        return False
    if(verbose):
        logging.basicConfig(format="%(message)s",
                            stream=sys.stdout, level=logging.DEBUG)
    GetDirList = inlist
    if(not GetDirList):
        return False
    curinode = 0
    curfid = 0
    inodelist = []
    inodetofile = {}
    filetoinode = {}
    inodetocatinode = {}
    numfiles = int(len(GetDirList))
    fnumfiles = format(numfiles, 'x').lower()
    AppendFileHeader(fp, fnumfiles, "UTF-8", [], checksumtype[0], formatspecs)
    for curfname in GetDirList:
        ftype = format(curfname[0], 'x').lower()
        fencoding = curfname[1]
        if(re.findall("^[.|/]", curfname[2])):
            fname = curfname[2]
        else:
            fname = "./"+curfname[2]
        fbasedir = os.path.dirname(fname)
        flinkname = curfname[3]
        fsize = format(curfname[4], 'x').lower()
        fatime = format(curfname[5], 'x').lower()
        fmtime = format(curfname[6], 'x').lower()
        fctime = format(curfname[7], 'x').lower()
        fbtime = format(curfname[8], 'x').lower()
        fmode = format(curfname[9], 'x').lower()
        fwinattributes = format(curfname[10], 'x').lower()
        fcompression = curfname[11]
        fcsize = format(curfname[12], 'x').lower()
        fuid = format(curfname[13], 'x').lower()
        funame = curfname[14]
        fgid = format(curfname[15], 'x').lower()
        fgname = curfname[16]
        fid = format(curfname[17], 'x').lower()
        finode = format(curfname[18], 'x').lower()
        flinkcount = format(curfname[19], 'x').lower()
        fdev = format(curfname[20], 'x').lower()
        fdev_minor = format(curfname[21], 'x').lower()
        fdev_major = format(curfname[22], 'x').lower()
        fseeknextfile = curfname[23]
        extradata = curfname[24]
        fheaderchecksumtype = curfname[25]
        fcontentchecksumtype = curfname[26]
        fcontents = curfname[27]
        catoutlist = [ftype, fencoding, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression, fcsize,
                      fuid, funame, fgid, fgname, fid, finode, flinkcount, fdev, fdev_minor, fdev_major, fseeknextfile]
        fcontents.seek(0, 0)
        AppendFileHeaderWithContent(
            fp, catoutlist, extradata, fcontents.read(), [checksumtype[1], checksumtype[2]], formatspecs)
    if(numfiles > 0):
        try:
            fp.write(AppendNullBytes(
                ["0", "0"], formatspecs['format_delimiter']).encode("UTF-8"))
        except OSError:
            return False
    return fp


def AppendInFileWithContent(infile, fp, dirlistfromtxt=False, filevalues=[], extradata=[], followlink=False, checksumtype=["crc32", "crc32", "crc32"], formatspecs=__file_format_dict__, verbose=False):
    inlist = ReadInFileBySizeWithContentToList(
        infile, 0, 0, False, True, False, formatspecs)
    return AppendListsWithContent(inlist, fp, dirlistfromtxt, filevalues, extradata, followlink, checksumtype, formatspecs, verbose)


def AppendFilesWithContentToOutFile(infiles, outfile, dirlistfromtxt=False, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, filevalues=[], extradata=[], followlink=False, checksumtype=["crc32", "crc32", "crc32"], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
    if(outfile != "-" and outfile is not None and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
        if(os.path.exists(outfile)):
            try:
                os.unlink(outfile)
            except OSError:
                pass
    if(outfile == "-" or outfile is None):
        verbose = False
        fp = BytesIO()
    elif(hasattr(outfile, "read") or hasattr(outfile, "write")):
        fp = outfile
    elif(re.findall("^(ftp|ftps|sftp):\\/\\/", outfile)):
        fp = BytesIO()
    else:
        fbasename = os.path.splitext(outfile)[0]
        fextname = os.path.splitext(outfile)[1]
        if(not compresswholefile and fextname in outextlistwd):
            compresswholefile = True
        fp = CompressOpenFile(outfile, compresswholefile, compressionlevel)
    AppendFilesWithContent(infiles, fp, dirlistfromtxt, filevalues, extradata, compression,
                                   compresswholefile, compressionlevel, compressionuselist, followlink, checksumtype, formatspecs, verbose)
    if(outfile == "-" or outfile is None or hasattr(outfile, "read") or hasattr(outfile, "write")):
        fp = CompressArchiveFile(
            fp, compression, compressionlevel, formatspecs)
        try:
            fp.flush()
            if(hasattr(os, "sync")):
                os.fsync(fp.fileno())
        except io.UnsupportedOperation:
            pass
        except AttributeError:
            pass
        except OSError:
            pass
    if(outfile == "-"):
        fp.seek(0, 0)
        if(hasattr(sys.stdout, "buffer")):
            shutil.copyfileobj(fp, sys.stdout.buffer)
        else:
            shutil.copyfileobj(fp, sys.stdout)
    elif(outfile is None):
        fp.seek(0, 0)
        outvar = fp.read()
        fp.close()
        return outvar
    elif(re.findall("^(ftp|ftps|sftp):\\/\\/", outfile)):
        fp = CompressArchiveFile(
            fp, compression, compressionlevel, formatspecs)
        fp.seek(0, 0)
        upload_file_to_internet_file(fp, outfile)
    if(returnfp):
        fp.seek(0, 0)
        return fp
    else:
        fp.close()
        return True


def AppendListsWithContentToOutFile(inlist, outfile, dirlistfromtxt=False, compression="auto", compresswholefile=True, compressionlevel=None, filevalues=[], extradata=[], followlink=False, checksumtype=["crc32", "crc32", "crc32"], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
    if(outfile != "-" and outfile is not None and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
        if(os.path.exists(outfile)):
            try:
                os.unlink(outfile)
            except OSError:
                pass
    if(outfile == "-" or outfile is None):
        verbose = False
        fp = BytesIO()
    elif(hasattr(outfile, "read") or hasattr(outfile, "write")):
        fp = outfile
    elif(re.findall("^(ftp|ftps|sftp):\\/\\/", outfile)):
        fp = BytesIO()
    else:
        fbasename = os.path.splitext(outfile)[0]
        fextname = os.path.splitext(outfile)[1]
        if(not compresswholefile and fextname in outextlistwd):
            compresswholefile = True
        fp = CompressOpenFile(outfile, compresswholefile, compressionlevel)
    AppendListsWithContent(inlist, fp, dirlistfromtxt, filevalues, extradata, compression,
                                   compresswholefile, compressionlevel, followlink, checksumtype, formatspecs, verbose)
    if(outfile == "-" or outfile is None or hasattr(outfile, "read") or hasattr(outfile, "write")):
        fp = CompressArchiveFile(
            fp, compression, compressionlevel, formatspecs)
        try:
            fp.flush()
            if(hasattr(os, "sync")):
                os.fsync(fp.fileno())
        except io.UnsupportedOperation:
            pass
        except AttributeError:
            pass
        except OSError:
            pass
    if(outfile == "-"):
        fp.seek(0, 0)
        if(hasattr(sys.stdout, "buffer")):
            shutil.copyfileobj(fp, sys.stdout.buffer)
        else:
            shutil.copyfileobj(fp, sys.stdout)
    elif(outfile is None):
        fp.seek(0, 0)
        outvar = fp.read()
        fp.close()
        return outvar
    elif(re.findall("^(ftp|ftps|sftp):\\/\\/", outfile)):
        fp = CompressArchiveFile(
            fp, compression, compressionlevel, formatspecs)
        fp.seek(0, 0)
        upload_file_to_internet_file(fp, outfile)
    if(returnfp):
        fp.seek(0, 0)
        return fp
    else:
        fp.close()
        return True


def AppendInFileWithContentToOutFile(infile, outfile, dirlistfromtxt=False, compression="auto", compresswholefile=True, compressionlevel=None, filevalues=[], extradata=[], followlink=False, checksumtype=["crc32", "crc32", "crc32"], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
    inlist = ReadInFileBySizeWithContentToList(
        infile, 0, 0, False, True, False, formatspecs)
    return AppendListsWithContentToOutFile(inlist, outfile, dirlistfromtxt, compression, compresswholefile, compressionlevel, filevalues, extradata, followlink, checksumtype, formatspecs, verbose, returnfp)


def PrintPermissionString(fchmode, ftype):
    permissions = {'access': {'0': ('---'), '1': ('--x'), '2': ('-w-'), '3': ('-wx'), '4': (
        'r--'), '5': ('r-x'), '6': ('rw-'), '7': ('rwx')}, 'roles': {0: 'owner', 1: 'group', 2: 'other'}}
    permissionstr = ""
    for fmodval in str(oct(fchmode))[-3:]:
        permissionstr = permissionstr + \
            permissions['access'].get(fmodval, '---')
    if(ftype == 0 or ftype == 7):
        permissionstr = "-" + permissionstr
    if(ftype == 1):
        permissionstr = "h" + permissionstr
    if(ftype == 2):
        permissionstr = "l" + permissionstr
    if(ftype == 3):
        permissionstr = "c" + permissionstr
    if(ftype == 4):
        permissionstr = "b" + permissionstr
    if(ftype == 5):
        permissionstr = "d" + permissionstr
    if(ftype == 6):
        permissionstr = "f" + permissionstr
    if(ftype == 8):
        permissionstr = "D" + permissionstr
    if(ftype == 9):
        permissionstr = "p" + permissionstr
    if(ftype == 10):
        permissionstr = "w" + permissionstr
    try:
        permissionoutstr = stat.filemode(fchmode)
    except AttributeError:
        permissionoutstr = permissionstr
    except KeyError:
        permissionoutstr = permissionstr
    return permissionoutstr


def PrintPermissionStringAlt(fchmode, ftype):
    permissions = {
        '0': '---', '1': '--x', '2': '-w-', '3': '-wx',
        '4': 'r--', '5': 'r-x', '6': 'rw-', '7': 'rwx'
    }
    # Translate file mode into permission string
    permissionstr = ''.join([permissions[i] for i in str(oct(fchmode))[-3:]])
    # Append file type indicator
    type_indicators = {
        0: '-', 1: 'h', 2: 'l', 3: 'c', 4: 'b',
        5: 'd', 6: 'f', 8: 'D', 9: 'p', 10: 'w'
    }
    file_type = type_indicators.get(ftype, '-')
    permissionstr = file_type + permissionstr
    try:
        permissionoutstr = stat.filemode(fchmode)
    except AttributeError:
        permissionoutstr = permissionstr
    return permissionoutstr


def GzipCompressData(data, compresslevel=9):
    try:
        # Try using modern gzip.compress if available
        compressed_data = gzip.compress(data, compresslevel=compresslevel)
    except AttributeError:
        # Fallback to older method for Python 2.x and older 3.x versions
        out = BytesIO()
        with gzip.GzipFile(fileobj=out, mode="wb", compresslevel=compresslevel) as f:
            f.write(data)
        compressed_data = out.getvalue()
    return compressed_data


def GzipDecompressData(compressed_data):
    try:
        # Try using modern gzip.decompress if available
        decompressed_data = gzip.decompress(compressed_data)
    except AttributeError:
        # Fallback to older method for Python 2.x and older 3.x versions
        inp = BytesIO(compressed_data)
        with gzip.GzipFile(fileobj=inp, mode="rb") as f:
            decompressed_data = f.read()
    return decompressed_data


def BzipCompressData(data, compresslevel=9):
    try:
        # Try using modern bz2.compress if available
        compressed_data = bz2.compress(data, compresslevel=compresslevel)
    except AttributeError:
        # Fallback to older method for Python 2.x and older 3.x versions
        compressor = bz2.BZ2Compressor(compresslevel)
        compressed_data = compressor.compress(data)
        compressed_data += compressor.flush()
    return compressed_data


def BzipDecompressData(compressed_data):
    try:
        # Try using modern bz2.decompress if available
        decompressed_data = bz2.decompress(compressed_data)
    except AttributeError:
        # Fallback to older method for Python 2.x and older 3.x versions
        decompressor = bz2.BZ2Decompressor()
        decompressed_data = decompressor.decompress(compressed_data)
    return decompressed_data


def IsNestedDict(variable):
    """
    Check if a variable is a single dictionary or a dictionary containing dictionaries.
    
    :param variable: The variable to check.
    :return: "single_dict" if it's a single dictionary, 
             "nested_dict" if it contains other dictionaries, 
             or "not_a_dict" if it's not a dictionary.
    """
    if not isinstance(variable, dict):
        return False

    # Check if any value in the dictionary is itself a dictionary
    for value in variable.values():
        if isinstance(value, dict):
            return True

    return False

def IsSingleDict(variable):
    """
    Check if a variable is a single dictionary or a dictionary containing dictionaries.
    
    :param variable: The variable to check.
    :return: "single_dict" if it's a single dictionary, 
             "nested_dict" if it contains other dictionaries, 
             or "not_a_dict" if it's not a dictionary.
    """
    if not isinstance(variable, dict):
        return False

    # Check if any value in the dictionary is itself a dictionary
    for value in variable.values():
        if isinstance(value, dict):
            return False

    return True


def CheckCompressionType(infile, formatspecs=__file_format_dict__, closefp=True):
    if(hasattr(infile, "read") or hasattr(infile, "write")):
        fp = infile
    else:
        try:
            fp = open(infile, "rb")
        except FileNotFoundError:
            return False
    filetype = False
    fp.seek(0, 0)
    prefp = fp.read(2)
    if(prefp == binascii.unhexlify("1f8b")):
        filetype = "gzip"
    elif(prefp == binascii.unhexlify("60ea")):
        filetype = "ajr"
    elif(prefp == binascii.unhexlify("7801")):
        filetype = "zlib"
    elif(prefp == binascii.unhexlify("785e")):
        filetype = "zlib"
    elif(prefp == binascii.unhexlify("789c")):
        filetype = "zlib"
    elif(prefp == binascii.unhexlify("78da")):
        filetype = "zlib"
    fp.seek(0, 0)
    prefp = fp.read(3)
    if(prefp == binascii.unhexlify("425a68")):
        filetype = "bzip2"
    elif(prefp == binascii.unhexlify("5d0000")):
        filetype = "lzma"
    fp.seek(0, 0)
    prefp = fp.read(4)
    if(prefp == binascii.unhexlify("28b52ffd")):
        filetype = "zstd"
    elif(prefp == binascii.unhexlify("04224d18")):
        filetype = "lz4"
    elif(prefp == binascii.unhexlify("504b0304")):
        filetype = "zipfile"
    elif(prefp == binascii.unhexlify("504b0506")):
        filetype = "zipfile"
    elif(prefp == binascii.unhexlify("504b0708")):
        filetype = "zipfile"
    fp.seek(0, 0)
    prefp = fp.read(5)
    if(prefp == binascii.unhexlify("7573746172")):
        filetype = "tarfile"
    if(prefp == binascii.unhexlify("7573746172")):
        filetype = "tarfile"
    fp.seek(0, 0)
    prefp = fp.read(6)
    if(prefp == binascii.unhexlify("fd377a585a00")):
        filetype = "xz"
    elif(prefp == binascii.unhexlify("377abcaf271c")):
        filetype = "7zipfile"
    fp.seek(0, 0)
    prefp = fp.read(7)
    if(prefp == binascii.unhexlify("526172211a0700")):
        filetype = "rarfile"
    elif(prefp == binascii.unhexlify("2a2a4143452a2a")):
        filetype = "ace"
    fp.seek(0, 0)
    prefp = fp.read(7)
    if(prefp == binascii.unhexlify("894c5a4f0d0a1a")):
        filetype = "lzo"
    fp.seek(0, 0)
    prefp = fp.read(8)
    if(prefp == binascii.unhexlify("7573746172003030")):
        filetype = "tarfile"
    if(prefp == binascii.unhexlify("7573746172202000")):
        filetype = "tarfile"
    if(prefp == binascii.unhexlify("526172211a070100")):
        filetype = "rarfile"
    fp.seek(0, 0)
    if(IsNestedDict(formatspecs)):
        for key, value in formatspecs.items():
            prefp = fp.read(formatspecs[key]['format_len'])
            if(prefp == binascii.unhexlify(formatspecs[key]['format_hex'])):
                catheaderver = str(int(formatspecs[key]['format_ver'].replace(".", "")))
                catstring = fp.read(len(catheaderver)).decode("UTF-8")
                catdelszie = len(formatspecs[key]['format_delimiter'])
                catdel = fp.read(catdelszie).decode("UTF-8")
                if(catstring != catheaderver):
                    break
                if(catdel != formatspecs[key]['format_delimiter']):
                    break
                if(catstring == catheaderver and catdel == formatspecs[key]['format_delimiter']):
                    filetype = formatspecs[key]['format_magic']
                    continue
            fp.seek(0, 0)
    elif(IsSingleDict(formatspecs)):
        prefp = fp.read(formatspecs['format_len'])
        if(prefp == binascii.unhexlify(formatspecs['format_hex'])):
            catheaderver = str(int(formatspecs['format_ver'].replace(".", "")))
            catstring = fp.read(len(catheaderver)).decode("UTF-8")
            catdelszie = len(formatspecs['format_delimiter'])
            catdel = fp.read(catdelszie).decode("UTF-8")
            if(catstring != catheaderver):
                return False
            if(catdel != formatspecs['format_delimiter']):
                return False
            filetype = formatspecs['format_magic']
    else:
        pass
    fp.seek(0, 0)
    prefp = fp.read(9)
    if(prefp == binascii.unhexlify("894c5a4f000d0a1a0a")):
        filetype = "lzo"
    fp.seek(0, 0)
    prefp = fp.read(10)
    if(prefp == binascii.unhexlify("7061785f676c6f62616c")):
        filetype = "tarfile"
    fp.seek(0, 0)
    if(filetype == "gzip" or filetype == "bzip2" or filetype == "lzma" or filetype == "zstd" or filetype == "lz4" or filetype == "zlib"):
        if(TarFileCheck(fp)):
            filetype = "tarfile"
    elif(not filetype):
        if(TarFileCheck(fp)):
            filetype = "tarfile"
        elif(zipfile.is_zipfile(fp)):
            filetype = "zipfile"
        elif(rarfile_support and (rarfile.is_rarfile(fp) or rarfile.is_rarfile_sfx(fp))):
            filetype = "rarile"
        elif(py7zr_support and py7zr.is_7zfile(fp)):
            return "7zipfile"
        else:
            filetype = False
    fp.seek(0, 0)
    if(closefp):
        fp.close()
    return filetype


def CheckCompressionSubType(infile, formatspecs=__file_format_dict__, closefp=True):
    compresscheck = CheckCompressionType(infile, formatspecs, False)
    if(not compresscheck):
        fextname = os.path.splitext(infile)[1]
        if(fextname == ".gz"):
            compresscheck = "gzip"
        elif(fextname == ".bz2"):
            compresscheck = "bzip2"
        elif(fextname == ".zst"):
            compresscheck = "zstd"
        elif(fextname == ".lz4"):
            compresscheck = "lz4"
        elif(fextname == ".lzo" or fextname == ".lzop"):
            compresscheck = "lzo"
        elif(fextname == ".lzma"):
            compresscheck = "lzma"
        elif(fextname == ".xz"):
            compresscheck = "xz"
        elif(fextname == ".zz" or fextname == ".zl" or fextname == ".zlib"):
            compresscheck = "zlib"
        else:
            return False
    if(compresscheck == "gzip" or compresscheck == "bzip2" or compresscheck == "lzma" or compresscheck == "zstd" or compresscheck == "lz4" or compresscheck == "zlib"):
        if(TarFileCheck(infile)):
            filetype = "tarfile"
    elif(not compresscheck):
        if(TarFileCheck(infile)):
            return "tarfile"
        elif(zipfile.is_zipfile(infile)):
            return "zipfile"
        elif(rarfile_support and (rarfile.is_rarfile(infile) or rarfile.is_rarfile_sfx(infile))):
            return "rarile"
        elif(py7zr_support and py7zr.is_7zfile(infile)):
            return "7zipfile"
        else:
            return False
        return False
    elif(IsNestedDict(formatspecs) and compresscheck in formatspecs):
        return formatspecs[compresscheck]['format_magic']
    elif(IsSingleDict(formatspecs) and compresscheck == formatspecs['format_magic']):
        return formatspecs['format_magic']
    elif(compresscheck == "tarfile"):
        return "tarfile"
    elif(compresscheck == "zipfile"):
        return "zipfile"
    elif(rarfile_support and compresscheck == "rarfile"):
        return "rarfile"
    elif(py7zr_support and compresscheck == "7zipfile" and py7zr.is_7zfile(infile)):
        return "7zipfile"
    if(hasattr(infile, "read") or hasattr(infile, "write")):
        fp = UncompressArchiveFile(infile, formatspecs['format_magic'])
    else:
        try:
            if(compresscheck == "gzip" and compresscheck in compressionsupport):
                if sys.version_info[0] == 2:
                    fp = GzipFile(infile, mode="rb")
                else:
                    fp = gzip.GzipFile(infile, "rb")
            elif(compresscheck == "bzip2" and compresscheck in compressionsupport):
                fp = bz2.BZ2File(infile, "rb")
            elif(compresscheck == "lz4" and compresscheck in compressionsupport):
                fp = lz4.frame.open(infile, "rb")
            elif(compresscheck == "zstd" and compresscheck in compressionsupport):
                if 'zstandard' in sys.modules:
                    fp = ZstdFile(infile, mode="rb")
                elif 'pyzstd' in sys.modules:
                    fp = pyzstd.zstdfile.ZstdFile(infile, mode="rb")
                else:
                    return Flase
            elif((compresscheck == "lzo" or compresscheck == "lzop") and compresscheck in compressionsupport):
                fp = LzopFile(infile, mode="rb")
            elif((compresscheck == "lzma" or compresscheck == "xz") and compresscheck in compressionsupport):
                fp = lzma.open(infile, "rb")
            elif(compresscheck == "zlib" and compresscheck in compressionsupport):
                fp = ZlibFile(infile, mode="rb")
            else:
                fp = open(infile, "rb")
        except FileNotFoundError:
            return False
    filetype = False
    prefp = fp.read(5)
    if(prefp == binascii.unhexlify("7573746172")):
        filetype = "tarfile"
    fp.seek(0, 0)
    if(IsNestedDict(formatspecs)):
        for key, value in formatspecs.items():
            prefp = fp.read(formatspecs[key]['format_len'])
            if(prefp == binascii.unhexlify(formatspecs[key]['format_hex'])):
                catheaderver = str(int(formatspecs[key]['format_ver'].replace(".", "")))
                catstring = fp.read(len(catheaderver)).decode("UTF-8")
                catdelszie = len(formatspecs[key]['format_delimiter'])
                catdel = fp.read(catdelszie).decode("UTF-8")
                if(catstring != catheaderver):
                    break
                if(catdel != formatspecs[key]['format_delimiter']):
                    break
                if(catstring == catheaderver and catdel == formatspecs[key]['format_delimiter']):
                    filetype = formatspecs[key]['format_magic']
                    continue
            fp.seek(0, 0)
    elif(IsSingleDict(formatspecs)):
        prefp = fp.read(formatspecs['format_len'])
        if(prefp == binascii.unhexlify(formatspecs['format_hex'])):
            catheaderver = str(int(formatspecs['format_ver'].replace(".", "")))
            catstring = fp.read(len(catheaderver)).decode("UTF-8")
            catdelszie = len(formatspecs['format_delimiter'])
            catdel = fp.read(catdelszie).decode("UTF-8")
            if(catstring != catheaderver):
                return False
            if(catdel != formatspecs['format_delimiter']):
                return False
            filetype = formatspecs['format_magic']
    else:
        pass
    fp.seek(0, 0)
    prefp = fp.read(10)
    if(prefp == binascii.unhexlify("7061785f676c6f62616c")):
        filetype = "tarfile"
    fp.seek(0, 0)
    if(closefp):
        fp.close()
    return filetype


def CheckCompressionTypeFromString(instring, formatspecs=__file_format_dict__, closefp=True):
    try:
        instringsfile = BytesIO(instring)
    except TypeError:
        instringsfile = BytesIO(instring.encode("UTF-8"))
    return CheckCompressionType(instringsfile, formatspecs, closefp)


def CheckCompressionTypeFromBytes(instring, formatspecs=__file_format_dict__, closefp=True):
    try:
        instringsfile = BytesIO(instring)
    except TypeError:
        instringsfile = BytesIO(instring.decode("UTF-8"))
    return CheckCompressionType(instringsfile, formatspecs, closefp)



def GetCompressionMimeType(infile, formatspecs=__file_format_dict__):
    compresscheck = CheckCompressionType(fp, formatspecs, False)
    if(compresscheck == "gzip" or compresscheck == "gz"):
        return archivefile_gzip_mimetype
    elif(compresscheck == "zlib" or (compresscheck == "zz" or compresscheck == "zl" or compresscheck == "zlib")):
        return archivefile_zlib_mimetype
    elif(compresscheck == "bzip2" or compresscheck == "bz2"):
        return archivefile_bzip2_mimetype
    elif(compresscheck == "zstd" or compresscheck == "zstandard"):
        return archivefile_zstandard_mimetype
    elif(compresscheck == "lz4"):
        return archivefile_lz4_mimetype
    elif(compresscheck == "lzo" or compresscheck == "lzop"):
        return archivefile_lzop_mimetype
    elif(compresscheck == "lzma"):
        return archivefile_lzma_mimetype
    elif(compresscheck == "xz"):
        return archivefile_xz_mimetype
    elif(compresscheck == formatspecs['format_magic']):
        return archivefile_cat_mimetype
    else:
        return False
    if(not compresscheck):
        return False
    return False


def UncompressArchiveFile(fp, formatspecs=__file_format_dict__):
    if(not hasattr(fp, "read")):
        return False
    compresscheck = CheckCompressionType(fp, formatspecs, False)
    if(compresscheck == "gzip" and compresscheck in compressionsupport):
        fp = gzip.GzipFile(fileobj=fp, mode="rb")
    elif(compresscheck == "bzip2" and compresscheck in compressionsupport):
        fp = bz2.BZ2File(fp)
    elif(compresscheck == "zstd" and compresscheck in compressionsupport):
        if 'zstandard' in sys.modules:
            fp = ZstdFile(fileobj=fp, mode="rb")
        elif 'pyzstd' in sys.modules:
            fp = pyzstd.zstdfile.ZstdFile(fileobj=fp, mode="rb")
        else:
            return Flase
    elif(compresscheck == "lz4" and compresscheck in compressionsupport):
        fp = lz4.frame.LZ4FrameFile(fp, mode='rb')
    elif((compresscheck == "lzo" or compresscheck == "lzop") and compresscheck in compressionsupport):
        fp = LzopFile(fileobj=fp, mode="rb")
    elif((compresscheck == "lzma" or compresscheck == "xz") and compresscheck in compressionsupport):
        fp = lzma.LZMAFile(fp)
    elif(compresscheck == "zlib" and compresscheck in compressionsupport):
        fp = ZlibFile(fileobj=fp, mode="rb")
    elif(compresscheck == formatspecs['format_magic']):
        fp = fp
    elif(not compresscheck):
        try:
            fp = lz4.frame.LZ4FrameFile(fp, mode='rb')
        except lzma.LZMAError:
            return False
        if(compresscheck != formatspecs['format_magic']):
            fp.close()
    return fp


def UncompressFile(infile, formatspecs=__file_format_dict__, mode="rb"):
    compresscheck = CheckCompressionType(infile, formatspecs, False)
    if(sys.version_info[0] == 2 and compresscheck):
        if(mode == "rt"):
            mode = "r"
        elif(mode == "wt"):
            mode = "w"
    try:
        if(compresscheck == "gzip" and compresscheck in compressionsupport):
            if sys.version_info[0] == 2:
                filefp = GzipFile(infile, mode=mode)
            else:
                filefp = gzip.open(infile, mode)
        elif(compresscheck == "bzip2" and compresscheck in compressionsupport):
            filefp = bz2.open(infile, mode)
        elif(compresscheck == "zstd" and compresscheck in compressionsupport):
            if 'zstandard' in sys.modules:
                filefp = ZstdFile(infile, mode=mode)
            elif 'pyzstd' in sys.modules:
                filefp = pyzstd.zstdfile.ZstdFile(infile, mode=mode)
            else:
                return Flase
        elif(compresscheck == "lz4" and compresscheck in compressionsupport):
            filefp = lz4.frame.open(infile, mode)
        elif((compresscheck == "lzo" or compresscheck == "lzop") and compresscheck in compressionsupport):
            filefp = LzopFile(infile, mode=mode)
        elif((compresscheck == "lzma" or compresscheck == "xz") and compresscheck in compressionsupport):
            filefp = lzma.open(infile, mode)
        elif(compresscheck == "zlib" and compresscheck in compressionsupport):
            filefp = ZlibFile(infile, mode=mode)
        elif(compresscheck == formatspecs['format_magic']):
            filefp = open(infile, mode)
        elif(not compresscheck):
            filefp = open(infile, mode)
        else:
            filefp = open(infile, mode)
    except FileNotFoundError:
        return False
    try:
        filefp.write_through = True
    except AttributeError:
        pass
    return filefp


def UncompressString(infile, formatspecs=__file_format_dict__):
    compresscheck = CheckCompressionTypeFromString(infile, formatspecs, False)
    if(compresscheck == "gzip" and compresscheck in compressionsupport):
        fileuz = GzipDecompressData(infile)
    elif(compresscheck == "bzip2" and compresscheck in compressionsupport):
        fileuz = BzipDecompressData(infile)
    elif(compresscheck == "zstd" and compresscheck in compressionsupport):
        decompressor = zstandard.ZstdDecompressor()
        fileuz = decompressor.decompress(infile)
    elif(compresscheck == "lz4" and compresscheck in compressionsupport):
        fileuz = lz4.frame.decompress(infile)
    elif((compresscheck == "lzo" or compresscheck == "lzop") and compresscheck in compressionsupport):
        fileuz = lzo.decompress(infile)
    elif((compresscheck == "lzma" or compresscheck == "xz") and compresscheck in compressionsupport):
        fileuz = lzma.decompress(infile)
    elif(compresscheck == "zlib" and compresscheck in compressionsupport):
        fileuz = zlib.decompress(infile)
    elif(not compresscheck):
        fileuz = infile
    else:
        fileuz = infile
    if(hasattr(fileuz, 'decode')):
        fileuz = fileuz.decode("UTF-8")
    return fileuz


def UncompressStringAlt(instring, formatspecs=__file_format_dict__):
    filefp = StringIO()
    outstring = UncompressString(instring, formatspecs)
    filefp.write(outstring)
    filefp.seek(0, 0)
    return filefp

def UncompressStringAltFP(fp, formatspecs=__file_format_dict__):
    if(not hasattr(fp, "read")):
        return False
    prechck = CheckCompressionType(fp, formatspecs, False)
    fp.seek(0, 0)
    if(prechck!="zstd"):
        return UncompressArchiveFile(fp, formatspecs)
    filefp = StringIO()
    fp.seek(0, 0)
    outstring = UncompressString(fp.read(), formatspecs)
    filefp.write(outstring)
    filefp.seek(0, 0)
    return filefp


def UncompressBytes(infile, formatspecs=__file_format_dict__):
    compresscheck = CheckCompressionTypeFromBytes(infile, formatspecs, False)
    if(compresscheck == "gzip" and compresscheck in compressionsupport):
        fileuz = GzipDecompressData(infile)
    elif(compresscheck == "bzip2" and compresscheck in compressionsupport):
        fileuz = BzipDecompressData(infile)
    elif(compresscheck == "zstd" and compresscheck in compressionsupport):
        decompressor = zstandard.ZstdDecompressor()
        fileuz = decompressor.decompress(infile)
    elif(compresscheck == "lz4" and compresscheck in compressionsupport):
        fileuz = lz4.frame.decompress(infile)
    elif((compresscheck == "lzo" or compresscheck == "lzop") and compresscheck in compressionsupport):
        fileuz = lzo.decompress(infile)
    elif((compresscheck == "lzma" or compresscheck == "xz") and compresscheck in compressionsupport):
        fileuz = lzma.decompress(infile)
    elif(compresscheck == "zlib" and compresscheck in compressionsupport):
        fileuz = zlib.decompress(infile)
    elif(not compresscheck):
        fileuz = infile
    else:
        fileuz = infile
    return fileuz


def UncompressBytesAlt(inbytes, formatspecs=__file_format_dict__):
    filefp = BytesIO()
    outstring = UncompressBytes(inbytes, formatspecs)
    filefp.write(outstring)
    filefp.seek(0, 0)
    return filefp


def UncompressBytesAltFP(fp, formatspecs=__file_format_dict__):
    if(not hasattr(fp, "read")):
        return False
    prechck = CheckCompressionType(fp, formatspecs, False)
    fp.seek(0, 0)
    if(prechck!="zstd"):
        return UncompressArchiveFile(fp, formatspecs)
    filefp = BytesIO()
    fp.seek(0, 0)
    outstring = UncompressBytes(fp.read(), formatspecs)
    filefp.write(outstring)
    filefp.seek(0, 0)
    return filefp


def CompressArchiveFile(fp, compression="auto", compressionlevel=None, formatspecs=__file_format_dict__):
    if(not hasattr(fp, "read")):
        return False
    fp.seek(0, 0)
    if(not compression or compression == formatspecs['format_magic']):
        compression = "auto"
    if(compression not in compressionlist and compression is None):
        compression = "auto"
    if(compression == "gzip" and compression in compressionsupport):
        bytesfp = BytesIO()
        if(compressionlevel is None):
            compressionlevel = 9
        else:
            compressionlevel = int(compressionlevel)
        bytesfp.write(GzipCompressData(
            fp.read(), compresslevel=compressionlevel))
    elif(compression == "bzip2" and compression in compressionsupport):
        bytesfp = BytesIO()
        if(compressionlevel is None):
            compressionlevel = 9
        else:
            compressionlevel = int(compressionlevel)
        bytesfp.write(BzipCompressData(
            fp.read(), compresslevel=compressionlevel))
    elif(compression == "lz4" and compression in compressionsupport):
        bytesfp = BytesIO()
        if(compressionlevel is None):
            compressionlevel = 9
        else:
            compressionlevel = int(compressionlevel)
        bytesfp.write(lz4.frame.compress(
            fp.read(), compression_level=compressionlevel))
    elif((compression == "lzo" or compression == "lzop") and compression in compressionsupport):
        bytesfp = BytesIO()
        if(compressionlevel is None):
            compressionlevel = 9
        else:
            compressionlevel = int(compressionlevel)
        bytesfp.write(lzo.compress(fp.read(), compressionlevel))
    elif(compression == "zstd" and compression in compressionsupport):
        bytesfp = BytesIO()
        if(compressionlevel is None):
            compressionlevel = 9
        else:
            compressionlevel = int(compressionlevel)
        compressor = zstandard.ZstdCompressor(compressionlevel, threads=get_default_threads())
        bytesfp.write(compressor.compress(fp.read()))
    elif(compression == "lzma" and compression in compressionsupport):
        bytesfp = BytesIO()
        if(compressionlevel is None):
            compressionlevel = 9
        else:
            compressionlevel = int(compressionlevel)
        try:
            bytesfp.write(lzma.compress(fp.read(), format=lzma.FORMAT_ALONE, filters=[{"id": lzma.FILTER_LZMA1, "preset": compressionlevel}]))
        except (NotImplementedError, lzma.LZMAError):
            bytesfp.write(lzma.compress(fp.read(), format=lzma.FORMAT_ALONE))
    elif(compression == "xz" and compression in compressionsupport):
        bytesfp = BytesIO()
        if(compressionlevel is None):
            compressionlevel = 9
        else:
            compressionlevel = int(compressionlevel)
        try:
            bytesfp.write(lzma.compress(fp.read(), format=lzma.FORMAT_XZ, filters=[{"id": lzma.FILTER_LZMA2, "preset": compressionlevel}]))
        except (NotImplementedError, lzma.LZMAError):
            bytesfp.write(lzma.compress(fp.read(), format=lzma.FORMAT_XZ))
    elif(compression == "zlib" and compression in compressionsupport):
        bytesfp = BytesIO()
        if(compressionlevel is None):
            compressionlevel = 9
        else:
            compressionlevel = int(compressionlevel)
        bytesfp.write(zlib.compress(fp.read(), compressionlevel))
    elif(compression == "auto" or compression is None):
        bytesfp = fp
    else:
        bytesfp = fp
    bytesfp.seek(0, 0)
    return bytesfp


def CompressOpenFile(outfile, compressionenable=True, compressionlevel=None):
    if(outfile is None):
        return False
    fbasename = os.path.splitext(outfile)[0]
    fextname = os.path.splitext(outfile)[1]
    if(compressionlevel is None):
        compressionlevel = 9
    else:
        compressionlevel = int(compressionlevel)
    if(sys.version_info[0] == 2):
        mode = "w"
    else:
        mode = "wb"
    try:
        if(fextname not in outextlistwd or not compressionenable):
            outfp = open(outfile, "wb")
        elif(fextname == ".gz" and "gzip" in compressionsupport):
            if sys.version_info[0] == 2:
                outfp = GzipFile(outfile, mode=mode, level=compressionlevel)
            else:
                outfp = gzip.open(outfile, mode, compressionlevel)
        elif(fextname == ".bz2" and "bzip2" in compressionsupport):
            outfp = bz2.open(outfile, mode, compressionlevel)
        elif(fextname == ".zst" and "zstandard" in compressionsupport):
            if 'zstandard' in sys.modules:
                outfp = ZstdFile(outfile, mode=mode, level=compressionlevel)
            elif 'pyzstd' in sys.modules:
                outfp = pyzstd.zstdfile.ZstdFile(outfile, mode=mode, level=compressionlevel)
            else:
                return Flase
        elif(fextname == ".xz" and "xz" in compressionsupport):
            try:
                outfp = lzma.open(outfile, mode, format=lzma.FORMAT_XZ, filters=[{"id": lzma.FILTER_LZMA2, "preset": compressionlevel}])
            except (NotImplementedError, lzma.LZMAError):
                outfp = lzma.open(outfile, mode, format=lzma.FORMAT_XZ)
        elif(fextname == ".lz4" and "lz4" in compressionsupport):
            outfp = lz4.frame.open(
                    outfile, mode, compression_level=compressionlevel)
        elif(fextname == ".lzo" and "lzop" in compressionsupport):
            outfp = LzopFile(outfile, mode=mode, level=compressionlevel)
        elif(fextname == ".lzma" and "lzma" in compressionsupport):
            try:
                outfp = lzma.open(outfile, mode, format=lzma.FORMAT_ALONE, filters=[{"id": lzma.FILTER_LZMA1, "preset": compressionlevel}])
            except (NotImplementedError, lzma.LZMAError):
                outfp = lzma.open(outfile, mode, format=lzma.FORMAT_ALONE)
        elif((fextname == ".zz" or fextname == ".zl" or fextname == ".zlib") and "zlib" in compressionsupport):
            outfp = ZlibFile(outfile, mode=mode, level=compressionlevel)
    except FileNotFoundError:
        return False
    try:
        outfp.write_through = True
    except AttributeError:
        pass
    return outfp


def MakeDevAlt(major, minor):
    """
    Replicates os.makedev functionality to create a device number.
    :param major: Major device number
    :param minor: Minor device number
    :return: Device number
    """
    # The device number is typically represented as:
    # (major << 8) | minor
    return (major << 8) | minor


def GetDevMajorMinor(fdev):
    retdev = []
    if(hasattr(os, "minor")):
        retdev.append(os.minor(fdev))
    else:
        retdev.append(0)
    if(hasattr(os, "major")):
        retdev.append(os.major(fdev))
    else:
        retdev.append(0)
    return retdev


def CheckSumSupport(checkfor, guaranteed=True):
    if(guaranteed):
        try:
            hash_list = sorted(list(hashlib.algorithms_guaranteed))
        except AttributeError:
            hash_list = sorted(list(hashlib.algorithms))
    else:
        try:
            hash_list = sorted(list(hashlib.algorithms_available))
        except AttributeError:
            hash_list = sorted(list(hashlib.algorithms))
    checklistout = sorted(hash_list + ['adler32', 'crc16', 'crc16_ansi', 'crc16_ibm',
                          'crc16_ccitt', 'crc32', 'crc64', 'crc64_ecma', 'crc64_iso', 'none'])
    if(checkfor in checklistout):
        return True
    else:
        return False


def CheckSumSupportAlt(checkfor, guaranteed=True):
    if(guaranteed):
        try:
            hash_list = sorted(list(hashlib.algorithms_guaranteed))
        except AttributeError:
            hash_list = sorted(list(hashlib.algorithms))
    else:
        try:
            hash_list = sorted(list(hashlib.algorithms_available))
        except AttributeError:
            hash_list = sorted(list(hashlib.algorithms))
    checklistout = hash_list
    if(checkfor in checklistout):
        return True
    else:
        return False


def PackArchiveFile(infiles, outfile, dirlistfromtxt=False, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, followlink=False, checksumtype=["crc32", "crc32", "crc32"], extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
    advancedlist = formatspecs['use_advanced_list']
    altinode = formatspecs['use_alt_inode']
    if(outfile != "-" and outfile is not None and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
        outfile = RemoveWindowsPath(outfile)
    if(not compression or compression == formatspecs['format_magic']):
        compression = "auto"
    if(compression not in compressionlist and compression is None):
        compression = "auto"
    if(verbose):
        logging.basicConfig(format="%(message)s",
                            stream=sys.stdout, level=logging.DEBUG)
    if(outfile != "-" and outfile is not None and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
        if(os.path.exists(outfile)):
            try:
                os.unlink(outfile)
            except OSError:
                pass
    if(outfile == "-" or outfile is None):
        verbose = False
        fp = BytesIO()
    elif(hasattr(outfile, "read") or hasattr(outfile, "write")):
        fp = outfile
    elif(re.findall("^(ftp|ftps|sftp):\\/\\/", outfile)):
        fp = BytesIO()
    else:
        fbasename = os.path.splitext(outfile)[0]
        fextname = os.path.splitext(outfile)[1]
        if(not compresswholefile and fextname in outextlistwd):
            compresswholefile = True
        fp = CompressOpenFile(outfile, compresswholefile, compressionlevel)
    catver = formatspecs['format_ver']
    fileheaderver = str(int(catver.replace(".", "")))
    infilelist = []
    if(infiles == "-"):
        for line in sys.stdin:
            infilelist.append(line.strip())
        infilelist = list(filter(None, infilelist))
    elif(infiles != "-" and dirlistfromtxt and os.path.exists(infiles) and (os.path.isfile(infiles) or infiles == os.devnull)):
        if(not os.path.exists(infiles) or not os.path.isfile(infiles)):
            return False
        with UncompressFile(infiles, formatspecs, "r") as finfile:
            for line in finfile:
                infilelist.append(line.strip())
        infilelist = list(filter(None, infilelist))
    else:
        if(isinstance(infiles, (list, tuple, ))):
            infilelist = list(filter(None, infiles))
        elif(isinstance(infiles, (basestring, ))):
            infilelist = list(filter(None, [infiles]))
    try:
        if os.stat not in os.supports_follow_symlinks and followlink:
            followlink = False
    except AttributeError:
        followlink = False
    if(advancedlist):
        GetDirList = ListDirAdvanced(infilelist, followlink, False)
    elif(advancedlist is None):
        GetDirList = infilelist
    else:
        GetDirList = ListDir(infilelist, followlink, False)
    if(not isinstance(GetDirList, (list, tuple, ))):
        return False
    FullSizeFiles = GetTotalSize(GetDirList)
    if(not GetDirList):
        return False
    curinode = 0
    curfid = 0
    inodelist = []
    inodetofile = {}
    filetoinode = {}
    inodetocatinode = {}
    numfiles = int(len(GetDirList))
    AppendFileHeader(fp, numfiles, "UTF-8", [], checksumtype[0], formatspecs)
    FullSizeFilesAlt = 0
    for curfname in GetDirList:
        fencoding = "UTF-8"
        if(re.findall("^[.|/]", curfname)):
            fname = curfname
        else:
            fname = "./"+curfname
        if(verbose):
            VerbosePrintOut(fname)
        if(not followlink or followlink is None):
            fstatinfo = os.lstat(fname)
        else:
            fstatinfo = os.stat(fname)
        fpremode = fstatinfo.st_mode
        finode = fstatinfo.st_ino
        flinkcount = fstatinfo.st_nlink
        try:
            FullSizeFilesAlt += fstatinfo.st_rsize
        except AttributeError:
            FullSizeFilesAlt += fstatinfo.st_size
        ftype = 0
        if(hasattr(os.path, "isjunction") and os.path.isjunction(fname)):
            ftype = 13
        #elif(fstatinfo.st_blocks * 512 < fstatinfo.st_size):
        #    ftype = 12
        elif(stat.S_ISREG(fpremode)):
            ftype = 0
        elif(stat.S_ISLNK(fpremode)):
            ftype = 2
        elif(stat.S_ISCHR(fpremode)):
            ftype = 3
        elif(stat.S_ISBLK(fpremode)):
            ftype = 4
        elif(stat.S_ISDIR(fpremode)):
            ftype = 5
        elif(stat.S_ISFIFO(fpremode)):
            ftype = 6
        elif(stat.S_ISSOCK(fpremode)):
            ftype = 8
        elif(hasattr(stat, "S_ISDOOR") and stat.S_ISDOOR(fpremode)):
            ftype = 9
        elif(hasattr(stat, "S_ISPORT") and stat.S_ISPORT(fpremode)):
            ftype = 10
        elif(hasattr(stat, "S_ISWHT") and stat.S_ISWHT(fpremode)):
            ftype = 11
        else:
            ftype = 0
        flinkname = ""
        fcurfid = format(int(curfid), 'x').lower()
        if not followlink and finode != 0:
            unique_id = (fstatinfo.st_dev, finode)
            if ftype != 1:
                if unique_id in inodelist:
                    # Hard link detected
                    ftype = 1
                    flinkname = inodetofile[unique_id]
                    if altinode:
                        fcurinode = format(int(unique_id[1]), 'x').lower()
                    else:
                        fcurinode = format(int(inodetocatinode[unique_id]), 'x').lower()
                else:
                    # New inode
                    inodelist.append(unique_id)
                    inodetofile[unique_id] = fname
                    inodetocatinode[unique_id] = curinode
                    if altinode:
                        fcurinode = format(int(unique_id[1]), 'x').lower()
                    else:
                        fcurinode = format(int(curinode), 'x').lower()
                    curinode += 1
        else:
            # Handle cases where inodes are not supported or symlinks are followed
            fcurinode = format(int(curinode), 'x').lower()
            curinode += 1
        curfid = curfid + 1
        if(ftype == 2):
            flinkname = os.readlink(fname)
        try:
            fdev = fstatinfo.st_rdev
        except AttributeError:
            fdev = 0
        getfdev = GetDevMajorMinor(fdev)
        fdev_minor = getfdev[0]
        fdev_major = getfdev[1]
        # Types that should be considered zero-length in the archive context:
        zero_length_types = {1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 13}
        # Types that have actual data to read:
        data_types = {0, 7, 12}
        if ftype in zero_length_types:
            fsize = format(int("0"), 'x').lower()
        elif ftype in data_types:
            fsize = format(int(fstatinfo.st_size), 'x').lower()
        else:
            fsize = format(int(fstatinfo.st_size)).lower()
        fatime = format(int(fstatinfo.st_atime), 'x').lower()
        fmtime = format(int(fstatinfo.st_mtime), 'x').lower()
        fctime = format(int(fstatinfo.st_ctime), 'x').lower()
        if(hasattr(fstatinfo, "st_birthtime")):
            fbtime = format(int(fstatinfo.st_birthtime), 'x').lower()
        else:
            fbtime = format(int(fstatinfo.st_ctime), 'x').lower()
        fmode = format(int(fstatinfo.st_mode), 'x').lower()
        fchmode = format(int(stat.S_IMODE(fstatinfo.st_mode)), 'x').lower()
        ftypemod = format(int(stat.S_IFMT(fstatinfo.st_mode)), 'x').lower()
        fuid = format(int(fstatinfo.st_uid), 'x').lower()
        fgid = format(int(fstatinfo.st_gid), 'x').lower()
        funame = ""
        try:
            import pwd
            try:
                userinfo = pwd.getpwuid(fstatinfo.st_uid)
                funame = userinfo.pw_name
            except KeyError:
                funame = ""
        except ImportError:
            funame = ""
        fgname = ""
        try:
            import grp
            try:
                groupinfo = grp.getgrgid(fstatinfo.st_gid)
                fgname = groupinfo.gr_name
            except KeyError:
                fgname = ""
        except ImportError:
            fgname = ""
        fdev = format(int(fdev), 'x').lower()
        fdev_minor = format(int(fdev_minor), 'x').lower()
        fdev_major = format(int(fdev_major), 'x').lower()
        finode = format(int(finode), 'x').lower()
        flinkcount = format(int(flinkcount), 'x').lower()
        if(hasattr(fstatinfo, "st_file_attributes")):
            fwinattributes = format(
                int(fstatinfo.st_file_attributes), 'x').lower()
        else:
            fwinattributes = format(int(0), 'x').lower()
        fcompression = ""
        fcsize = format(int(0), 'x').lower()
        fcontents = BytesIO()
        if ftype in data_types:
            with open(fname, "rb") as fpc:
                shutil.copyfileobj(fpc, fcontents)
                if(not compresswholefile):
                    fcontents.seek(0, 2)
                    ucfsize = fcontents.tell()
                    fcontents.seek(0, 0)
                    if(compression == "auto"):
                        ilsize = len(compressionuselist)
                        ilmin = 0
                        ilcsize = []
                        while(ilmin < ilsize):
                            cfcontents = BytesIO()
                            fcontents.seek(0, 0)
                            shutil.copyfileobj(fcontents, cfcontents)
                            fcontents.seek(0, 0)
                            cfcontents.seek(0, 0)
                            cfcontents = CompressArchiveFile(
                                cfcontents, compressionuselist[ilmin], compressionlevel, formatspecs)
                            if(cfcontents):
                                cfcontents.seek(0, 2)
                                ilcsize.append(cfcontents.tell())
                                cfcontents.close()
                            else:
                                try:
                                    ilcsize.append(sys.maxint)
                                except AttributeError:
                                    ilcsize.append(sys.maxsize)
                            ilmin = ilmin + 1
                        ilcmin = ilcsize.index(min(ilcsize))
                        curcompression = compressionuselist[ilcmin]
                    fcontents.seek(0, 0)
                    cfcontents = BytesIO()
                    shutil.copyfileobj(fcontents, cfcontents)
                    cfcontents.seek(0, 0)
                    cfcontents = CompressArchiveFile(
                        cfcontents, curcompression, compressionlevel, formatspecs)
                    cfcontents.seek(0, 2)
                    cfsize = cfcontents.tell()
                    if(ucfsize > cfsize):
                        fcsize = format(int(cfsize), 'x').lower()
                        fcompression = curcompression
                        fcontents.close()
                        fcontents = cfcontents
        if(fcompression == "none"):
            fcompression = ""
        if(followlink and (ftype == 1 or ftype == 2)):
            flstatinfo = os.stat(flinkname)
            with open(flinkname, "rb") as fpc:
                shutil.copyfileobj(fpc, fcontents)
                if(not compresswholefile):
                    fcontents.seek(0, 2)
                    ucfsize = fcontents.tell()
                    fcontents.seek(0, 0)
                    if(compression == "auto"):
                        ilsize = len(compressionuselist)
                        ilmin = 0
                        ilcsize = []
                        while(ilmin < ilsize):
                            cfcontents = BytesIO()
                            fcontents.seek(0, 0)
                            shutil.copyfileobj(fcontents, cfcontents)
                            fcontents.seek(0, 0)
                            cfcontents.seek(0, 0)
                            cfcontents = CompressArchiveFile(
                                cfcontents, compressionuselist[ilmin], compressionlevel, formatspecs)
                            if(cfcontents):
                                cfcontents.seek(0, 2)
                                ilcsize.append(cfcontents.tell())
                                cfcontents.close()
                            else:
                                try:
                                    ilcsize.append(sys.maxint)
                                except AttributeError:
                                    ilcsize.append(sys.maxsize)
                            ilmin = ilmin + 1
                        ilcmin = ilcsize.index(min(ilcsize))
                        curcompression = compressionuselist[ilcmin]
                    fcontents.seek(0, 0)
                    cfcontents = BytesIO()
                    shutil.copyfileobj(fcontents, cfcontents)
                    cfcontents.seek(0, 0)
                    cfcontents = CompressArchiveFile(
                        cfcontents, curcompression, compressionlevel, formatspecs)
                    cfcontents.seek(0, 2)
                    cfsize = cfcontents.tell()
                    if(ucfsize > cfsize):
                        fcsize = format(int(cfsize), 'x').lower()
                        fcompression = curcompression
                        fcontents.close()
                        fcontents = cfcontents
        fcontents.seek(0, 0)
        ftypehex = format(ftype, 'x').lower()
        catoutlist = [ftypehex, fencoding, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression,
                      fcsize, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev, fdev_minor, fdev_major, "+"+str(len(formatspecs['format_delimiter']))]
        AppendFileHeaderWithContent(
            fp, catoutlist, extradata, fcontents.read(), [checksumtype[1], checksumtype[2]], formatspecs)
        fcontents.close()
    if(numfiles > 0):
        try:
            fp.write(AppendNullBytes(
                ["0", "0"], formatspecs['format_delimiter']).encode("UTF-8"))
        except OSError:
            return False
    if(outfile == "-" or outfile is None or hasattr(outfile, "read") or hasattr(outfile, "write")):
        fp = CompressArchiveFile(
            fp, compression, compressionlevel, formatspecs)
        try:
            fp.flush()
            if(hasattr(os, "sync")):
                os.fsync(fp.fileno())
        except io.UnsupportedOperation:
            pass
        except AttributeError:
            pass
        except OSError:
            pass
    if(outfile == "-"):
        fp.seek(0, 0)
        if(hasattr(sys.stdout, "buffer")):
            shutil.copyfileobj(fp, sys.stdout.buffer)
        else:
            shutil.copyfileobj(fp, sys.stdout)
    elif(outfile is None):
        fp.seek(0, 0)
        outvar = fp.read()
        fp.close()
        return outvar
    elif(re.findall("^(ftp|ftps|sftp):\\/\\/", outfile)):
        fp = CompressArchiveFile(
            fp, compression, compressionlevel, formatspecs)
        fp.seek(0, 0)
        upload_file_to_internet_file(fp, outfile)
    if(returnfp):
        fp.seek(0, 0)
        return fp
    else:
        fp.close()
        return True


if(hasattr(shutil, "register_archive_format")):
    def PackArchiveFileFunc(archive_name, source_dir, **kwargs):
        return PackArchiveFile(source_dir, archive_name, False, "auto", True, None, compressionlistalt, False, "crc32", [], __file_format_dict__['format_delimiter'], False, False)


def PackArchiveFileFromDirList(infiles, outfile, dirlistfromtxt=False, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, followlink=False, checksumtype=["crc32", "crc32", "crc32"], extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
    return PackArchiveFile(infiles, outfile, dirlistfromtxt, compression, compresswholefile, compressionlevel, compressionuselist, followlink, checksumtype, extradata, formatspecs, verbose, returnfp)


def PackArchiveFileFromTarFile(infile, outfile, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["crc32", "crc32", "crc32"], extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
    if(outfile != "-" and outfile is not None and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
        outfile = RemoveWindowsPath(outfile)
    if(not compression or compression == formatspecs['format_magic']):
        compression = "auto"
    if(compression not in compressionlist and compression is None):
        compression = "auto"
    if(verbose):
        logging.basicConfig(format="%(message)s",
                            stream=sys.stdout, level=logging.DEBUG)
    if(outfile != "-" and outfile is not None and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
        if(os.path.exists(outfile)):
            try:
                os.unlink(outfile)
            except OSError:
                pass
    if(outfile == "-" or outfile is None):
        verbose = False
        fp = BytesIO()
    elif(hasattr(outfile, "read") or hasattr(outfile, "write")):
        fp = outfile
    elif(re.findall("^(ftp|ftps|sftp):\\/\\/", outfile)):
        fp = BytesIO()
    else:
        fbasename = os.path.splitext(outfile)[0]
        fextname = os.path.splitext(outfile)[1]
        if(not compresswholefile and fextname in outextlistwd):
            compresswholefile = True
        fp = CompressOpenFile(outfile, compresswholefile, compressionlevel)
    catver = formatspecs['format_ver']
    fileheaderver = str(int(catver.replace(".", "")))
    curinode = 0
    curfid = 0
    inodelist = []
    inodetofile = {}
    filetoinode = {}
    inodetocatinode = {}
    if(infile == "-"):
        infile = BytesIO()
        if(hasattr(sys.stdin, "buffer")):
            shutil.copyfileobj(sys.stdin.buffer, infile)
        else:
            shutil.copyfileobj(sys.stdin, infile)
        infile.seek(0, 0)
        if(not infile):
            return False
        infile.seek(0, 0)
    elif(re.findall("^(http|https|ftp|ftps|sftp):\\/\\/", infile)):
        infile = download_file_from_internet_file(infile)
        infile.seek(0, 0)
        if(not infile):
            return False
        infile.seek(0, 0)
    elif(hasattr(infile, "read") or hasattr(infile, "write")):
        try:
            if(not tarfile.is_tarfile(infile)):
                return False
        except AttributeError:
            if(not TarFileCheck(infile)):
                return False
    elif(not os.path.exists(infile) or not os.path.isfile(infile)):
        return False
    elif(os.path.exists(infile) and os.path.isfile(infile)):
        try:
            if(not tarfile.is_tarfile(infile)):
                return False
        except AttributeError:
            if(not TarFileCheck(infile)):
                return False
    try:
        if(hasattr(infile, "read") or hasattr(infile, "write")):
            compresscheck = CheckCompressionType(infile, formatspecs, False)
            if(compresscheck=="zstd"):
                if 'zstandard' in sys.modules:
                    infile = ZstdFile(fileobj=infile, mode="rb")
                elif 'pyzstd' in sys.modules:
                    fp = pyzstd.zstdfile.ZstdFile(fileobj=infile, mode="rb")
                tarfp = tarfile.open(fileobj=infile, mode="r")
            else:
                tarfp = tarfile.open(fileobj=infile, mode="r")
        else:
            compresscheck = CheckCompressionType(infile, formatspecs, True)
            if(compresscheck=="zstd"):
                if 'zstandard' in sys.modules:
                    infile = ZstdFile(fileobj=infile, mode="rb")
                elif 'pyzstd' in sys.modules:
                    fp = pyzstd.zstdfile.ZstdFile(fileobj=infile, mode="rb")
                tarfp = tarfile.open(fileobj=infile, mode="r")
            else:
                tarfp = tarfile.open(infile, "r")
    except FileNotFoundError:
        return False
    numfiles = int(len(tarfp.getmembers()))
    AppendFileHeader(fp, numfiles, "UTF-8", [], checksumtype[0], formatspecs)
    for member in sorted(tarfp.getmembers(), key=lambda x: x.name):
        fencoding = "UTF-8"
        if(re.findall("^[.|/]", member.name)):
            fname = member.name
        else:
            fname = "./"+member.name
        if(verbose):
            VerbosePrintOut(fname)
        fpremode = member.mode
        ffullmode = member.mode
        flinkcount = 0
        ftype = 0
        if(member.isreg()):
            ffullmode = member.mode + stat.S_IFREG
            ftype = 0
        elif(member.islnk()):
            ffullmode = member.mode + stat.S_IFREG
            ftype = 1
        elif(member.issym()):
            ffullmode = member.mode + stat.S_IFLNK
            ftype = 2
        elif(member.ischr()):
            ffullmode = member.mode + stat.S_IFCHR
            ftype = 3
        elif(member.isblk()):
            ffullmode = member.mode + stat.S_IFBLK
            ftype = 4
        elif(member.isdir()):
            ffullmode = member.mode + stat.S_IFDIR
            ftype = 5
        elif(member.isfifo()):
            ffullmode = member.mode + stat.S_IFIFO
            ftype = 6
        elif(hasattr(member, "issparse") and member.issparse()):
            ffullmode = member.mode
            ftype = 12
        elif(member.isdev()):
            ffullmode = member.mode
            ftype = 14
        else:
            ffullmode = member.mode
            ftype = 0
        flinkname = ""
        fcurfid = format(int(curfid), 'x').lower()
        fcurinode = format(int(curfid), 'x').lower()
        curfid = curfid + 1
        if(ftype == 2):
            flinkname = member.linkname
        try:
            fdev = format(int(os.makedev(member.devmajor, member.devminor)), 'x').lower()
        except AttributeError:
            fdev = format(int(MakeDevAlt(member.devmajor, member.devminor)), 'x').lower()
        fdev_minor = format(int(member.devminor), 'x').lower()
        fdev_major = format(int(member.devmajor), 'x').lower()
        # Types that should be considered zero-length in the archive context:
        zero_length_types = {1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 13}
        # Types that have actual data to read:
        data_types = {0, 7, 12}
        if ftype in zero_length_types:
            fsize = format(int("0"), 'x').lower()
        elif ftype in data_types:
            fsize = format(int(member.size), 'x').lower()
        else:
            fsize = format(int(member.size), 'x').lower()
        fatime = format(int(member.mtime), 'x').lower()
        fmtime = format(int(member.mtime), 'x').lower()
        fctime = format(int(member.mtime), 'x').lower()
        fbtime = format(int(member.mtime), 'x').lower()
        fmode = format(int(ffullmode), 'x').lower()
        fchmode = format(int(stat.S_IMODE(ffullmode)), 'x').lower()
        ftypemod = format(int(stat.S_IFMT(ffullmode)), 'x').lower()
        fuid = format(int(member.uid), 'x').lower()
        fgid = format(int(member.gid), 'x').lower()
        funame = member.uname
        fgname = member.gname
        flinkcount = format(int(flinkcount), 'x').lower()
        fwinattributes = format(int(0), 'x').lower()
        fcompression = ""
        fcsize = format(int(0), 'x').lower()
        fcontents = BytesIO()
        if ftype in data_types:
            fpc = tarfp.extractfile(member)
            shutil.copyfileobj(fpc, fcontents)
            if(not compresswholefile):
                fcontents.seek(0, 2)
                ucfsize = fcontents.tell()
                fcontents.seek(0, 0)
                if(compression == "auto"):
                    ilsize = len(compressionuselist)
                    ilmin = 0
                    ilcsize = []
                    while(ilmin < ilsize):
                        cfcontents = BytesIO()
                        fcontents.seek(0, 0)
                        shutil.copyfileobj(fcontents, cfcontents)
                        fcontents.seek(0, 0)
                        cfcontents.seek(0, 0)
                        cfcontents = CompressArchiveFile(
                            cfcontents, compressionuselist[ilmin], compressionlevel, formatspecs)
                        if(cfcontents):
                            cfcontents.seek(0, 2)
                            ilcsize.append(cfcontents.tell())
                            cfcontents.close()
                        else:
                            try:
                                ilcsize.append(sys.maxint)
                            except AttributeError:
                                ilcsize.append(sys.maxsize)
                        ilmin = ilmin + 1
                    ilcmin = ilcsize.index(min(ilcsize))
                    curcompression = compressionuselist[ilcmin]
                fcontents.seek(0, 0)
                cfcontents = BytesIO()
                shutil.copyfileobj(fcontents, cfcontents)
                cfcontents.seek(0, 0)
                cfcontents = CompressArchiveFile(
                    cfcontents, curcompression, compressionlevel, formatspecs)
                cfcontents.seek(0, 2)
                cfsize = cfcontents.tell()
                if(ucfsize > cfsize):
                    fcsize = format(int(cfsize), 'x').lower()
                    fcompression = curcompression
                    fcontents.close()
                    fcontents = cfcontents
        if(fcompression == "none"):
            fcompression = ""
        fcontents.seek(0, 0)
        ftypehex = format(ftype, 'x').lower()
        catoutlist = [ftypehex, fencoding, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression,
                      fcsize, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev, fdev_minor, fdev_major, "+"+str(len(formatspecs['format_delimiter']))]
        AppendFileHeaderWithContent(
            fp, catoutlist, extradata, fcontents.read(), [checksumtype[1], checksumtype[2]], formatspecs)
        fcontents.close()
    if(numfiles > 0):
        try:
            fp.write(AppendNullBytes(
                ["0", "0"], formatspecs['format_delimiter']).encode("UTF-8"))
        except OSError:
            return False
    if(outfile == "-" or outfile is None or hasattr(outfile, "read") or hasattr(outfile, "write")):
        fp = CompressArchiveFile(
            fp, compression, compressionlevel, formatspecs)
        try:
            fp.flush()
            if(hasattr(os, "sync")):
                os.fsync(fp.fileno())
        except io.UnsupportedOperation:
            pass
        except AttributeError:
            pass
        except OSError:
            pass
    if(outfile == "-"):
        fp.seek(0, 0)
        if(hasattr(sys.stdout, "buffer")):
            shutil.copyfileobj(fp, sys.stdout.buffer)
        else:
            shutil.copyfileobj(fp, sys.stdout)
    elif(outfile is None):
        fp.seek(0, 0)
        outvar = fp.read()
        fp.close()
        return outvar
    elif(re.findall("^(ftp|ftps|sftp):\\/\\/", outfile)):
        fp = CompressArchiveFile(
            fp, compression, compressionlevel, formatspecs)
        fp.seek(0, 0)
        upload_file_to_internet_file(fp, outfile)
    if(returnfp):
        fp.seek(0, 0)
        return fp
    else:
        fp.close()
        return True


def PackArchiveFileFromZipFile(infile, outfile, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["crc32", "crc32", "crc32"], extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
    if(outfile != "-" and outfile is not None and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
        outfile = RemoveWindowsPath(outfile)
    if(not compression or compression == formatspecs['format_magic']):
        compression = "auto"
    if(compression not in compressionlist and compression is None):
        compression = "auto"
    if(verbose):
        logging.basicConfig(format="%(message)s",
                            stream=sys.stdout, level=logging.DEBUG)
    if(outfile != "-" and outfile is not None and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
        if(os.path.exists(outfile)):
            try:
                os.unlink(outfile)
            except OSError:
                pass
    if(outfile == "-" or outfile is None):
        verbose = False
        fp = BytesIO()
    elif(hasattr(outfile, "read") or hasattr(outfile, "write")):
        fp = outfile
    elif(re.findall("^(ftp|ftps|sftp):\\/\\/", outfile)):
        fp = BytesIO()
    else:
        fbasename = os.path.splitext(outfile)[0]
        fextname = os.path.splitext(outfile)[1]
        if(not compresswholefile and fextname in outextlistwd):
            compresswholefile = True
        fp = CompressOpenFile(outfile, compresswholefile, compressionlevel)
    catver = formatspecs['format_ver']
    fileheaderver = str(int(catver.replace(".", "")))
    curinode = 0
    curfid = 0
    inodelist = []
    inodetofile = {}
    filetoinode = {}
    inodetocatinode = {}
    if(infile == "-"):
        infile = BytesIO()
        if(hasattr(sys.stdin, "buffer")):
            shutil.copyfileobj(sys.stdin.buffer, infile)
        else:
            shutil.copyfileobj(sys.stdin, infile)
        infile.seek(0, 0)
        if(not infile):
            return False
        infile.seek(0, 0)
    elif(re.findall("^(http|https|ftp|ftps|sftp):\\/\\/", infile)):
        infile = download_file_from_internet_file(infile)
        infile.seek(0, 0)
        if(not infile):
            return False
        infile.seek(0, 0)
    elif(hasattr(infile, "read") or hasattr(infile, "write")):
        pass
    elif(not os.path.exists(infile) or not os.path.isfile(infile)):
        return False
    if(not zipfile.is_zipfile(infile)):
        return False
    try:
        zipfp = zipfile.ZipFile(infile, "r", allowZip64=True)
    except FileNotFoundError:
        return False
    ziptest = zipfp.testzip()
    if(ziptest):
        VerbosePrintOut("Bad file found!")
    numfiles = int(len(zipfp.infolist()))
    AppendFileHeader(fp, numfiles, "UTF-8", [], checksumtype[0], formatspecs)
    for member in sorted(zipfp.infolist(), key=lambda x: x.filename):
        fencoding = "UTF-8"
        if(re.findall("^[.|/]", member.filename)):
            fname = member.filename
        else:
            fname = "./"+member.filename
        zipinfo = zipfp.getinfo(member.filename)
        if(verbose):
            VerbosePrintOut(fname)
        if ((hasattr(member, "is_dir") and member.is_dir()) or member.filename.endswith('/')):
            fpremode = int(stat.S_IFDIR + 511)
        else:
            fpremode = int(stat.S_IFREG + 438)
        flinkcount = 0
        ftype = 0
        if ((hasattr(member, "is_dir") and member.is_dir()) or member.filename.endswith('/')):
            ftype = 5
        else:
            ftype = 0
        flinkname = ""
        fcurfid = format(int(curfid), 'x').lower()
        fcurinode = format(int(curfid), 'x').lower()
        curfid = curfid + 1
        fdev = format(int(0), 'x').lower()
        fdev_minor = format(int(0), 'x').lower()
        fdev_major = format(int(0), 'x').lower()
        if(ftype == 5):
            fsize = format(int("0"), 'x').lower()
        elif(ftype == 0):
            fsize = format(int(member.file_size), 'x').lower()
        else:
            fsize = format(int(member.file_size), 'x').lower()
        fatime = format(
            int(time.mktime(member.date_time + (0, 0, -1))), 'x').lower()
        fmtime = format(
            int(time.mktime(member.date_time + (0, 0, -1))), 'x').lower()
        fctime = format(
            int(time.mktime(member.date_time + (0, 0, -1))), 'x').lower()
        fbtime = format(
            int(time.mktime(member.date_time + (0, 0, -1))), 'x').lower()
        if(zipinfo.create_system == 0 or zipinfo.create_system == 10):
            fwinattributes = format(int(zipinfo.external_attr), 'x').lower()
            if ((hasattr(member, "is_dir") and member.is_dir()) or member.filename.endswith('/')):
                fmode = format(int(stat.S_IFDIR + 511), 'x').lower()
                fchmode = stat.S_IMODE(int(stat.S_IFDIR + 511))
                ftypemod = stat.S_IFMT(int(stat.S_IFDIR + 511))
            else:
                fmode = format(int(stat.S_IFREG + 438), 'x').lower()
                fchmode = stat.S_IMODE(int(stat.S_IFREG + 438))
                ftypemod = stat.S_IFMT(int(stat.S_IFREG + 438))
        elif(zipinfo.create_system == 3):
            fwinattributes = format(int(0), 'x').lower()
            try:
                fmode = format(int(zipinfo.external_attr), 'x').lower()
                prefmode = int(zipinfo.external_attr)
                fchmode = stat.S_IMODE(prefmode)
                ftypemod = stat.S_IFMT(prefmode)
            except OverflowError:
                fmode = format(int(zipinfo.external_attr >> 16), 'x').lower()
                prefmode = int(zipinfo.external_attr >> 16)
                fchmode = stat.S_IMODE(prefmode)
                ftypemod = stat.S_IFMT(prefmode)
        else:
            fwinattributes = format(int(0), 'x').lower()
            if ((hasattr(member, "is_dir") and member.is_dir()) or member.filename.endswith('/')):
                fmode = format(int(stat.S_IFDIR + 511), 'x').lower()
                prefmode = int(stat.S_IFDIR + 511)
                fchmode = stat.S_IMODE(prefmode)
                ftypemod = stat.S_IFMT(prefmode)
            else:
                fmode = format(int(stat.S_IFREG + 438), 'x').lower()
                prefmode = int(stat.S_IFREG + 438)
                fchmode = stat.S_IMODE(prefmode)
                ftypemod = stat.S_IFMT(prefmode)
        fcompression = ""
        fcsize = format(int(0), 'x').lower()
        try:
            fuid = format(int(os.getuid()), 'x').lower()
        except AttributeError:
            fuid = format(int(0), 'x').lower()
        except KeyError:
            fuid = format(int(0), 'x').lower()
        try:
            fgid = format(int(os.getgid()), 'x').lower()
        except AttributeError:
            fgid = format(int(0), 'x').lower()
        except KeyError:
            fgid = format(int(0), 'x').lower()
        try:
            import pwd
            try:
                userinfo = pwd.getpwuid(os.getuid())
                funame = userinfo.pw_name
            except KeyError:
                funame = ""
            except AttributeError:
                funame = ""
        except ImportError:
            funame = ""
        fgname = ""
        try:
            import grp
            try:
                groupinfo = grp.getgrgid(os.getgid())
                fgname = groupinfo.gr_name
            except KeyError:
                fgname = ""
            except AttributeError:
                fgname = ""
        except ImportError:
            fgname = ""
        fcontents = BytesIO()
        if(ftype == 0):
            fcontents.write(zipfp.read(member.filename))
            if(not compresswholefile):
                fcontents.seek(0, 2)
                ucfsize = fcontents.tell()
                fcontents.seek(0, 0)
                if(compression == "auto"):
                    ilsize = len(compressionuselist)
                    ilmin = 0
                    ilcsize = []
                    while(ilmin < ilsize):
                        cfcontents = BytesIO()
                        fcontents.seek(0, 0)
                        shutil.copyfileobj(fcontents, cfcontents)
                        fcontents.seek(0, 0)
                        cfcontents.seek(0, 0)
                        cfcontents = CompressArchiveFile(
                            cfcontents, compressionuselist[ilmin], compressionlevel, formatspecs)
                        cfcontents.seek(0, 2)
                        ilcsize.append(cfcontents.tell())
                        cfcontents.close()
                        ilmin = ilmin + 1
                    ilcmin = ilcsize.index(min(ilcsize))
                    curcompression = compressionuselist[ilcmin]
                fcontents.seek(0, 0)
                cfcontents = BytesIO()
                shutil.copyfileobj(fcontents, cfcontents)
                cfcontents.seek(0, 0)
                cfcontents = CompressArchiveFile(
                    cfcontents, curcompression, compressionlevel, formatspecs)
                cfcontents.seek(0, 2)
                cfsize = cfcontents.tell()
                if(ucfsize > cfsize):
                    fcsize = format(int(cfsize), 'x').lower()
                    fcompression = curcompression
                    fcontents.close()
                    fcontents = cfcontents
        if(fcompression == "none"):
            fcompression = ""
        fcontents.seek(0, 0)
        ftypehex = format(ftype, 'x').lower()
        catoutlist = [ftypehex, fencoding, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression,
                      fcsize, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev, fdev_minor, fdev_major, "+"+str(len(formatspecs['format_delimiter']))]
        AppendFileHeaderWithContent(
            fp, catoutlist, extradata, fcontents.read(), [checksumtype[1], checksumtype[2]], formatspecs)
        fcontents.close()
    if(numfiles > 0):
        try:
            fp.write(AppendNullBytes(
                ["0", "0"], formatspecs['format_delimiter']).encode("UTF-8"))
        except OSError:
            return False
    if(outfile == "-" or outfile is None or hasattr(outfile, "read") or hasattr(outfile, "write")):
        fp = CompressArchiveFile(
            fp, compression, compressionlevel, formatspecs)
        try:
            fp.flush()
            if(hasattr(os, "sync")):
                os.fsync(fp.fileno())
        except io.UnsupportedOperation:
            pass
        except AttributeError:
            pass
        except OSError:
            pass
    if(outfile == "-"):
        fp.seek(0, 0)
        if(hasattr(sys.stdout, "buffer")):
            shutil.copyfileobj(fp, sys.stdout.buffer)
        else:
            shutil.copyfileobj(fp, sys.stdout)
    elif(outfile is None):
        fp.seek(0, 0)
        outvar = fp.read()
        fp.close()
        return outvar
    elif(re.findall("^(ftp|ftps|sftp):\\/\\/", outfile)):
        fp = CompressArchiveFile(
            fp, compression, compressionlevel, formatspecs)
        fp.seek(0, 0)
        upload_file_to_internet_file(fp, outfile)
    if(returnfp):
        fp.seek(0, 0)
        return fp
    else:
        fp.close()
        return True


if(not rarfile_support):
    def PackArchiveFileFromRarFile(infile, outfile, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["crc32", "crc32", "crc32"], extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
        return False

if(rarfile_support):
    def PackArchiveFileFromRarFile(infile, outfile, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["crc32", "crc32", "crc32"], extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
        if(outfile != "-" and outfile is not None and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
            outfile = RemoveWindowsPath(outfile)
        if(not compression or compression == formatspecs['format_magic']):
            compression = "auto"
        if(compression not in compressionlist and compression is None):
            compression = "auto"
        if(verbose):
            logging.basicConfig(format="%(message)s",
                                stream=sys.stdout, level=logging.DEBUG)
        if(outfile != "-" and outfile is not None and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
            if(os.path.exists(outfile)):
                try:
                    os.unlink(outfile)
                except OSError:
                    pass
        if(outfile == "-" or outfile is None):
            verbose = False
            fp = BytesIO()
        elif(hasattr(outfile, "read") or hasattr(outfile, "write")):
            fp = outfile
        elif(re.findall("^(ftp|ftps|sftp):\\/\\/", outfile)):
            fp = BytesIO()
        else:
            fbasename = os.path.splitext(outfile)[0]
            fextname = os.path.splitext(outfile)[1]
            if(not compresswholefile and fextname in outextlistwd):
                compresswholefile = True
            fp = CompressOpenFile(
                outfile, compresswholefile, compressionlevel)
        catver = formatspecs['format_ver']
        fileheaderver = str(int(catver.replace(".", "")))
        curinode = 0
        curfid = 0
        inodelist = []
        inodetofile = {}
        filetoinode = {}
        inodetocatinode = {}
        if(not os.path.exists(infile) or not os.path.isfile(infile)):
            return False
        if(not rarfile.is_rarfile(infile) and not rarfile.is_rarfile_sfx(infile)):
            return False
        rarfp = rarfile.RarFile(infile, "r")
        rartest = rarfp.testrar()
        if(rartest):
            VerbosePrintOut("Bad file found!")
        numfiles = int(len(rarfp.infolist()))
        AppendFileHeader(fp, numfiles, "UTF-8", [], checksumtype[0], formatspecs)
        try:
            fp.flush()
            if(hasattr(os, "sync")):
                os.fsync(fp.fileno())
        except io.UnsupportedOperation:
            pass
        except AttributeError:
            pass
        except OSError:
            pass
        for member in sorted(rarfp.infolist(), key=lambda x: x.filename):
            is_unix = False
            is_windows = False
            if(member.host_os == rarfile.RAR_OS_UNIX):
                is_windows = False
                try:
                    member.external_attr
                    is_unix = True
                except AttributeError:
                    is_unix = False
            elif(member.host_os == rarfile.RAR_OS_WIN32):
                is_unix = False
                try:
                    member.external_attr
                    is_windows = True
                except AttributeError:
                    is_windows = False
            else:
                is_unix = False
                is_windows = False
            fencoding = "UTF-8"
            if(re.findall("^[.|/]", member.filename)):
                fname = member.filename
            else:
                fname = "./"+member.filename
            rarinfo = rarfp.getinfo(member.filename)
            if(verbose):
                VerbosePrintOut(fname)
            if(is_unix and member.external_attr != 0):
                fpremode = int(member.external_attr)
            elif(member.is_file()):
                fpremode = int(stat.S_IFREG + 438)
            elif(member.is_symlink()):
                fpremode = int(stat.S_IFLNK + 438)
            elif(member.is_dir()):
                fpremode = int(stat.S_IFDIR + 511)
            if(is_windows and member.external_attr != 0):
                fwinattributes = format(int(member.external_attr), 'x').lower()
            else:
                fwinattributes = format(int(0), 'x').lower()
            fcompression = ""
            fcsize = format(int(0), 'x').lower()
            flinkcount = 0
            ftype = 0
            if(member.is_file()):
                ftype = 0
            elif(member.is_symlink()):
                ftype = 2
            elif(member.is_dir()):
                ftype = 5
            flinkname = ""
            if(ftype == 2):
                flinkname = rarfp.read(member.filename).decode("UTF-8")
            fcurfid = format(int(curfid), 'x').lower()
            fcurinode = format(int(curfid), 'x').lower()
            curfid = curfid + 1
            fdev = format(int(0), 'x').lower()
            fdev_minor = format(int(0), 'x').lower()
            fdev_major = format(int(0), 'x').lower()
            if(ftype == 5):
                fsize = format(int("0"), 'x').lower()
            elif(ftype == 0):
                fsize = format(int(member.file_size), 'x').lower()
            else:
                fsize = format(int(member.file_size), 'x').lower()
            try:
                if(member.atime):
                    fatime = format(int(member.atime.timestamp()), 'x').lower()
                else:
                    fatime = format(int(member.mtime.timestamp()), 'x').lower()
            except AttributeError:
                fatime = format(int(member.mtime.timestamp()), 'x').lower()
            fmtime = format(int(member.mtime.timestamp()), 'x').lower()
            try:
                if(member.ctime):
                    fctime = format(int(member.ctime.timestamp()), 'x').lower()
                else:
                    fctime = format(int(member.mtime.timestamp()), 'x').lower()
            except AttributeError:
                fctime = format(int(member.mtime.timestamp()), 'x').lower()
            fbtime = format(int(member.mtime.timestamp()), 'x').lower()
            if(is_unix and member.external_attr != 0):
                fmode = format(int(member.external_attr), 'x').lower()
                fchmode = format(
                    int(stat.S_IMODE(member.external_attr)), 'x').lower()
                ftypemod = format(
                    int(stat.S_IFMT(member.external_attr)), 'x').lower()
            elif(member.is_file()):
                fmode = format(int(stat.S_IFREG + 438), 'x').lower()
                fchmode = format(
                    int(stat.S_IMODE(int(stat.S_IFREG + 438))), 'x').lower()
                ftypemod = format(
                    int(stat.S_IFMT(int(stat.S_IFREG + 438))), 'x').lower()
            elif(member.is_symlink()):
                fmode = format(int(stat.S_IFLNK + 438), 'x').lower()
                fchmode = format(
                    int(stat.S_IMODE(int(stat.S_IFREG + 438))), 'x').lower()
                ftypemod = format(
                    int(stat.S_IFMT(int(stat.S_IFREG + 438))), 'x').lower()
            elif(member.is_dir()):
                fmode = format(int(stat.S_IFDIR + 511), 'x').lower()
                fchmode = format(
                    int(stat.S_IMODE(int(stat.S_IFDIR + 511))), 'x').lower()
                ftypemod = format(
                    int(stat.S_IFMT(int(stat.S_IFDIR + 511))), 'x').lower()
            try:
                fuid = format(int(os.getuid()), 'x').lower()
            except AttributeError:
                fuid = format(int(0), 'x').lower()
            except KeyError:
                fuid = format(int(0), 'x').lower()
            try:
                fgid = format(int(os.getgid()), 'x').lower()
            except AttributeError:
                fgid = format(int(0), 'x').lower()
            except KeyError:
                fgid = format(int(0), 'x').lower()
            try:
                import pwd
                try:
                    userinfo = pwd.getpwuid(os.getuid())
                    funame = userinfo.pw_name
                except KeyError:
                    funame = ""
                except AttributeError:
                    funame = ""
            except ImportError:
                funame = ""
            fgname = ""
            try:
                import grp
                try:
                    groupinfo = grp.getgrgid(os.getgid())
                    fgname = groupinfo.gr_name
                except KeyError:
                    fgname = ""
                except AttributeError:
                    fgname = ""
            except ImportError:
                fgname = ""
            fcontents = BytesIO()
            if(ftype == 0):
                fcontents.write(rarfp.read(member.filename))
                if(not compresswholefile):
                    fcontents.seek(0, 2)
                    ucfsize = fcontents.tell()
                    fcontents.seek(0, 0)
                    if(compression == "auto"):
                        ilsize = len(compressionuselist)
                        ilmin = 0
                        ilcsize = []
                        while(ilmin < ilsize):
                            cfcontents = BytesIO()
                            fcontents.seek(0, 0)
                            shutil.copyfileobj(fcontents, cfcontents)
                            fcontents.seek(0, 0)
                            cfcontents.seek(0, 0)
                            cfcontents = CompressArchiveFile(
                                cfcontents, compressionuselist[ilmin], compressionlevel, formatspecs)
                            if(cfcontents):
                                cfcontents.seek(0, 2)
                                ilcsize.append(cfcontents.tell())
                                cfcontents.close()
                            else:
                                try:
                                    ilcsize.append(sys.maxint)
                                except AttributeError:
                                    ilcsize.append(sys.maxsize)
                            ilmin = ilmin + 1
                        ilcmin = ilcsize.index(min(ilcsize))
                        curcompression = compressionuselist[ilcmin]
                    fcontents.seek(0, 0)
                    cfcontents = BytesIO()
                    shutil.copyfileobj(fcontents, cfcontents)
                    cfcontents.seek(0, 0)
                    cfcontents = CompressArchiveFile(
                        cfcontents, curcompression, compressionlevel, formatspecs)
                    cfcontents.seek(0, 2)
                    cfsize = cfcontents.tell()
                    if(ucfsize > cfsize):
                        fcsize = format(int(cfsize), 'x').lower()
                        fcompression = compression
                        fcontents.close()
                        fcontents = cfcontents
            if(fcompression == "none"):
                fcompression = ""
            fcontents.seek(0, 0)
            ftypehex = format(ftype, 'x').lower()
            catoutlist = [ftypehex, fencoding, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression,
                          fcsize, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev, fdev_minor, fdev_major, "+"+str(len(formatspecs['format_delimiter']))]
            AppendFileHeaderWithContent(
                fp, catoutlist, extradata, fcontents.read(), [checksumtype[1], checksumtype[2]], formatspecs)
            fcontents.close()
        if(numfiles > 0):
            try:
                fp.write(AppendNullBytes(
                    ["0", "0"], formatspecs['format_delimiter']).encode("UTF-8"))
            except OSError:
                return False
        if(outfile == "-" or outfile is None or hasattr(outfile, "read") or hasattr(outfile, "write")):
            fp = CompressArchiveFile(
                fp, compression, compressionlevel, formatspecs)
            try:
                fp.flush()
                if(hasattr(os, "sync")):
                    os.fsync(fp.fileno())
            except io.UnsupportedOperation:
                pass
            except AttributeError:
                pass
            except OSError:
                pass
        if(outfile == "-"):
            fp.seek(0, 0)
            if(hasattr(sys.stdout, "buffer")):
                shutil.copyfileobj(fp, sys.stdout.buffer)
            else:
                shutil.copyfileobj(fp, sys.stdout)
        elif(outfile is None):
            fp.seek(0, 0)
            outvar = fp.read()
            fp.close()
            return outvar
        elif(re.findall("^(ftp|ftps|sftp):\\/\\/", outfile)):
            fp = CompressArchiveFile(
                fp, compression, compressionlevel, formatspecs)
            fp.seek(0, 0)
            upload_file_to_internet_file(fp, outfile)
        if(returnfp):
            fp.seek(0, 0)
            return fp
        else:
            fp.close()
            return True


if(not py7zr_support):
    def PackArchiveFileFromSevenZipFile(infile, outfile, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["crc32", "crc32", "crc32"], extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
        return False

if(py7zr_support):
    def PackArchiveFileFromSevenZipFile(infile, outfile, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["crc32", "crc32", "crc32"], extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
        if(outfile != "-" and outfile is not None and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
            outfile = RemoveWindowsPath(outfile)
        if(not compression or compression == formatspecs['format_magic']):
            compression = "auto"
        if(compression not in compressionlist and compression is None):
            compression = "auto"
        if(verbose):
            logging.basicConfig(format="%(message)s",
                                stream=sys.stdout, level=logging.DEBUG)
        if(outfile != "-" and outfile is not None and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
            if(os.path.exists(outfile)):
                try:
                    os.unlink(outfile)
                except OSError:
                    pass
        if(outfile == "-" or outfile is None):
            verbose = False
            fp = BytesIO()
        elif(hasattr(outfile, "read") or hasattr(outfile, "write")):
            fp = outfile
        elif(re.findall("^(ftp|ftps|sftp):\\/\\/", outfile)):
            fp = BytesIO()
        else:
            fbasename = os.path.splitext(outfile)[0]
            fextname = os.path.splitext(outfile)[1]
            if(not compresswholefile and fextname in outextlistwd):
                compresswholefile = True
            fp = CompressOpenFile(
                outfile, compresswholefile, compressionlevel)
        catver = formatspecs['format_ver']
        fileheaderver = str(int(catver.replace(".", "")))
        curinode = 0
        curfid = 0
        inodelist = []
        inodetofile = {}
        filetoinode = {}
        inodetocatinode = {}
        if(not os.path.exists(infile) or not os.path.isfile(infile)):
            return False
        szpfp = py7zr.SevenZipFile(infile, mode="r")
        file_content = szpfp.readall()
        #sztest = szpfp.testzip();
        sztestalt = szpfp.test()
        if(sztestalt):
            VerbosePrintOut("Bad file found!")
        numfiles = int(len(szpfp.list()))
        AppendFileHeader(fp, numfiles, "UTF-8", [], checksumtype[0], formatspecs)
        for member in sorted(szpfp.list(), key=lambda x: x.filename):
            fencoding = "UTF-8"
            if(re.findall("^[.|/]", member.filename)):
                fname = member.filename
            else:
                fname = "./"+member.filename
            if(verbose):
                VerbosePrintOut(fname)
            if(not member.is_directory):
                fpremode = int(stat.S_IFREG + 438)
            elif(member.is_directory):
                fpremode = int(stat.S_IFDIR + 511)
            fwinattributes = format(int(0), 'x').lower()
            fcompression = ""
            fcsize = format(int(0), 'x').lower()
            flinkcount = 0
            ftype = 0
            if(member.is_directory):
                ftype = 5
            else:
                ftype = 0
            flinkname = ""
            fcurfid = format(int(curfid), 'x').lower()
            fcurinode = format(int(curfid), 'x').lower()
            curfid = curfid + 1
            fdev = format(int(0), 'x').lower()
            fdev_minor = format(int(0), 'x').lower()
            fdev_major = format(int(0), 'x').lower()
            if(ftype == 5):
                fsize = format(int("0"), 'x').lower()
            fatime = format(int(member.creationtime.timestamp()), 'x').lower()
            fmtime = format(int(member.creationtime.timestamp()), 'x').lower()
            fctime = format(int(member.creationtime.timestamp()), 'x').lower()
            fbtime = format(int(member.creationtime.timestamp()), 'x').lower()
            if(member.is_directory):
                fmode = format(int(stat.S_IFDIR + 511), 'x').lower()
                fchmode = format(
                    int(stat.S_IMODE(int(stat.S_IFDIR + 511))), 'x').lower()
                ftypemod = format(
                    int(stat.S_IFMT(int(stat.S_IFDIR + 511))), 'x').lower()
            else:
                fmode = format(int(stat.S_IFREG + 438), 'x').lower()
                fchmode = format(
                    int(stat.S_IMODE(int(stat.S_IFREG + 438))), 'x').lower()
                ftypemod = format(
                    int(stat.S_IFMT(int(stat.S_IFREG + 438))), 'x').lower()
            try:
                fuid = format(int(os.getuid()), 'x').lower()
            except AttributeError:
                fuid = format(int(0), 'x').lower()
            except KeyError:
                fuid = format(int(0), 'x').lower()
            try:
                fgid = format(int(os.getgid()), 'x').lower()
            except AttributeError:
                fgid = format(int(0), 'x').lower()
            except KeyError:
                fgid = format(int(0), 'x').lower()
            try:
                import pwd
                try:
                    userinfo = pwd.getpwuid(os.getuid())
                    funame = userinfo.pw_name
                except KeyError:
                    funame = ""
                except AttributeError:
                    funame = ""
            except ImportError:
                funame = ""
            fgname = ""
            try:
                import grp
                try:
                    groupinfo = grp.getgrgid(os.getgid())
                    fgname = groupinfo.gr_name
                except KeyError:
                    fgname = ""
                except AttributeError:
                    fgname = ""
            except ImportError:
                fgname = ""
            fcontents = BytesIO()
            if(ftype == 0):
                fcontents.write(file_content[member.filename].read())
                fsize = format(fcontents.tell(), 'x').lower()
                file_content[member.filename].close()
                if(not compresswholefile):
                    fcontents.seek(0, 2)
                    ucfsize = fcontents.tell()
                    fcontents.seek(0, 0)
                    if(compression == "auto"):
                        ilsize = len(compressionuselist)
                        ilmin = 0
                        ilcsize = []
                        while(ilmin < ilsize):
                            cfcontents = BytesIO()
                            fcontents.seek(0, 0)
                            shutil.copyfileobj(fcontents, cfcontents)
                            fcontents.seek(0, 0)
                            cfcontents.seek(0, 0)
                            cfcontents = CompressArchiveFile(
                                cfcontents, compressionuselist[ilmin], compressionlevel, formatspecs)
                            if(cfcontents):
                                cfcontents.seek(0, 2)
                                ilcsize.append(cfcontents.tell())
                                cfcontents.close()
                            else:
                                try:
                                    ilcsize.append(sys.maxint)
                                except AttributeError:
                                    ilcsize.append(sys.maxsize)
                            ilmin = ilmin + 1
                        ilcmin = ilcsize.index(min(ilcsize))
                        curcompression = compressionuselist[ilcmin]
                    fcontents.seek(0, 0)
                    cfcontents = BytesIO()
                    shutil.copyfileobj(fcontents, cfcontents)
                    cfcontents.seek(0, 0)
                    cfcontents = CompressArchiveFile(
                        cfcontents, curcompression, compressionlevel, formatspecs)
                    cfcontents.seek(0, 2)
                    cfsize = cfcontents.tell()
                    if(ucfsize > cfsize):
                        fcsize = format(int(cfsize), 'x').lower()
                        fcompression = curcompression
                        fcontents.close()
                        fcontents = cfcontents
            if(fcompression == "none"):
                fcompression = ""
            fcontents.seek(0, 0)
            ftypehex = format(ftype, 'x').lower()
            catoutlist = [ftypehex, fencoding, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression,
                          fcsize, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev, fdev_minor, fdev_major, "+"+str(len(formatspecs['format_delimiter']))]
            AppendFileHeaderWithContent(
                fp, catoutlist, extradata, fcontents.read(), [checksumtype[1], checksumtype[2]], formatspecs)
            fcontents.close()
        if(numfiles > 0):
            try:
                fp.write(AppendNullBytes(
                    ["0", "0"], formatspecs['format_delimiter']).encode("UTF-8"))
            except OSError:
                return False
        if(outfile == "-" or outfile is None or hasattr(outfile, "read") or hasattr(outfile, "write")):
            fp = CompressArchiveFile(
                fp, compression, compressionlevel, formatspecs)
            try:
                fp.flush()
                if(hasattr(os, "sync")):
                    os.fsync(fp.fileno())
            except io.UnsupportedOperation:
                pass
            except AttributeError:
                pass
            except OSError:
                pass
        if(outfile == "-"):
            fp.seek(0, 0)
            if(hasattr(sys.stdout, "buffer")):
                shutil.copyfileobj(fp, sys.stdout.buffer)
            else:
                shutil.copyfileobj(fp, sys.stdout)
        elif(outfile is None):
            fp.seek(0, 0)
            outvar = fp.read()
            fp.close()
            return outvar
        elif(re.findall("^(ftp|ftps|sftp):\\/\\/", outfile)):
            fp = CompressArchiveFile(
                fp, compression, compressionlevel, formatspecs)
            fp.seek(0, 0)
            upload_file_to_internet_file(fp, outfile)
        if(returnfp):
            fp.seek(0, 0)
            return fp
        else:
            fp.close()
            return True


def PackArchiveFileFromInFile(infile, outfile, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["crc32", "crc32", "crc32"], extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
    checkcompressfile = CheckCompressionSubType(infile, formatspecs, True)
    if(verbose):
        logging.basicConfig(format="%(message)s",
                            stream=sys.stdout, level=logging.DEBUG)
    if(checkcompressfile == "tarfile" and TarFileCheck(infile)):
        return PackArchiveFileFromTarFile(infile, outfile, compression, compresswholefile, compressionlevel, compressionuselist, checksumtype, extradata, formatspecs, verbose, returnfp)
    elif(checkcompressfile == "zipfile" and zipfile.is_zipfile(infile)):
        return PackArchiveFileFromZipFile(infile, outfile, compression, compresswholefile, compressionlevel, compressionuselist, checksumtype, extradata, formatspecs, verbose, returnfp)
    elif(rarfile_support and checkcompressfile == "rarfile" and (rarfile.is_rarfile(infile) or rarfile.is_rarfile_sfx(infile))):
        return PackArchiveFileFromRarFile(infile, outfile, compression, compresswholefile, compressionlevel, compressionuselist, checksumtype, extradata, formatspecs, verbose, returnfp)
    elif(py7zr_support and checkcompressfile == "7zipfile" and py7zr.is_7zfile(infile)):
        return PackArchiveFileFromSevenZipFile(infile, outfile, compression, compresswholefile, compressionlevel, compressionuselist, checksumtype, extradata, formatspecs, verbose, returnfp)
    elif(checkcompressfile == formatspecs['format_magic']):
        return RePackArchiveFile(infile, outfile, compression, compresswholefile, compressionlevel, False, 0, 0, checksumtype, False, extradata, formatspecs, verbose, returnfp)
    else:
        return False
    return False


def ArchiveFileSeekToFileNum(infile, seekto=0, listonly=False, contentasfile=True, skipchecksum=False, formatspecs=__file_format_dict__, returnfp=False):
    if(hasattr(infile, "read") or hasattr(infile, "write")):
        fp = infile
        fp.seek(0, 0)
        compresscheck = CheckCompressionType(fp, formatspecs, False)
        fp = UncompressArchiveFile(fp, formatspecs)
        checkcompressfile = CheckCompressionSubType(fp, formatspecs, False)
        if(checkcompressfile == "tarfile" and TarFileCheck(infile)):
            return TarFileToArray(infile, seekto, 0, listonly, contentasfile, skipchecksum, formatspecs, returnfp)
        elif(checkcompressfile == "zipfile" and zipfile.is_zipfile(infile)):
            return ZipFileToArray(infile, seekto, 0, listonly, contentasfile, skipchecksum, formatspecs, returnfp)
        elif(rarfile_support and checkcompressfile == "rarfile" and (rarfile.is_rarfile(infile) or rarfile.is_rarfile_sfx(infile))):
            return RarFileToArray(infile, seekto, 0, listonly, contentasfile, skipchecksum, formatspecs, returnfp)
        elif(py7zr_support and checkcompressfile == "7zipfile" and py7zr.is_7zfile(infile)):
            return SevenZipFileToArray(infile, seekto, 0, listonly, contentasfile, skipchecksum, formatspecs, returnfp)
        elif(checkcompressfile != formatspecs['format_magic']):
            return False
        if(not fp):
            return False
        if(not compresscheck and hasattr(fp, "name")):
            fextname = os.path.splitext(fp.name)[1]
            if(fextname == ".gz"):
                compresscheck = "gzip"
            elif(fextname == ".bz2"):
                compresscheck = "bzip2"
            elif(fextname == ".zst"):
                compresscheck = "zstd"
            elif(fextname == ".lz4" or fextname == ".clz4"):
                compresscheck = "lz4"
            elif(fextname == ".lzo" or fextname == ".lzop"):
                compresscheck = "lzo"
            elif(fextname == ".lzma"):
                compresscheck = "lzma"
            elif(fextname == ".xz"):
                compresscheck = "xz"
            elif(fextname == ".zz" or fextname == ".zl" or fextname == ".zlib"):
                compresscheck = "zlib"
            else:
                return False
        fp.seek(0, 0)
    elif(infile == "-"):
        fp = BytesIO()
        if(hasattr(sys.stdin, "buffer")):
            shutil.copyfileobj(sys.stdin.buffer, fp)
        else:
            shutil.copyfileobj(sys.stdin, fp)
        fp.seek(0, 0)
        compresscheck = CheckCompressionType(fp, formatspecs, False)
        fp = UncompressArchiveFile(fp, formatspecs)
        if(not fp):
            return False
        fp.seek(0, 0)
    elif(isinstance(infile, bytes) and sys.version_info[0] >= 3):
        fp = BytesIO()
        fp.write(infile)
        fp.seek(0, 0)
        compresscheck = CheckCompressionType(fp, formatspecs, False)
        fp = UncompressArchiveFile(fp, formatspecs)
        if(not fp):
            return False
        fp.seek(0, 0)
    elif(re.findall("^(http|https|ftp|ftps|sftp):\\/\\/", infile)):
        fp = download_file_from_internet_file(infile)
        fp.seek(0, 0)
        compresscheck = CheckCompressionType(fp, formatspecs, False)
        if(not compresscheck):
            fextname = os.path.splitext(infile)[1]
            if(fextname == ".gz"):
                compresscheck = "gzip"
            elif(fextname == ".bz2"):
                compresscheck = "bzip2"
            elif(fextname == ".zst"):
                compresscheck = "zstd"
            elif(fextname == ".lz4" or fextname == ".clz4"):
                compresscheck = "lz4"
            elif(fextname == ".lzo" or fextname == ".lzop"):
                compresscheck = "lzo"
            elif(fextname == ".lzma"):
                compresscheck = "lzma"
            elif(fextname == ".xz"):
                compresscheck = "xz"
            elif(fextname == ".zz" or fextname == ".zl" or fextname == ".zlib"):
                compresscheck = "zlib"
            else:
                return False
        fp = UncompressArchiveFile(fp, formatspecs)
        if(not fp):
            return False
        fp.seek(0, 0)
    else:
        infile = RemoveWindowsPath(infile)
        checkcompressfile = CheckCompressionSubType(infile, formatspecs, True)
        if(checkcompressfile == "tarfile" and TarFileCheck(infile)):
            return TarFileToArray(infile, seekto, 0, listonly, contentasfile, skipchecksum, formatspecs, returnfp)
        elif(checkcompressfile == "zipfile" and zipfile.is_zipfile(infile)):
            return ZipFileToArray(infile, seekto, 0, listonly, contentasfile, skipchecksum, formatspecs, returnfp)
        elif(rarfile_support and checkcompressfile == "rarfile" and (rarfile.is_rarfile(infile) or rarfile.is_rarfile_sfx(infile))):
            return RarFileToArray(infile, seekto, 0, listonly, contentasfile, skipchecksum, formatspecs, returnfp)
        elif(py7zr_support and checkcompressfile == "7zipfile" and py7zr.is_7zfile(infile)):
            return SevenZipFileToArray(infile, seekto, 0, listonly, contentasfile, skipchecksum, formatspecs, returnfp)
        elif(checkcompressfile != formatspecs['format_magic']):
            return False
        compresscheck = CheckCompressionType(infile, formatspecs, True)
        if(not compresscheck):
            fextname = os.path.splitext(infile)[1]
            if(fextname == ".gz"):
                compresscheck = "gzip"
            elif(fextname == ".bz2"):
                compresscheck = "bzip2"
            elif(fextname == ".zst"):
                compresscheck = "zstd"
            elif(fextname == ".lz4" or fextname == ".clz4"):
                compresscheck = "lz4"
            elif(fextname == ".lzo" or fextname == ".lzop"):
                compresscheck = "lzo"
            elif(fextname == ".lzma"):
                compresscheck = "lzma"
            elif(fextname == ".xz"):
                compresscheck = "xz"
            elif(fextname == ".zz" or fextname == ".zl" or fextname == ".zlib"):
                compresscheck = "zlib"
            else:
                return False
        if(not compresscheck):
            return False
        fp = UncompressFile(infile, formatspecs, "rb")
    curloc = fp.tell()
    try:
        fp.seek(0, 2);
    except OSError:
        SeekToEndOfFile(fp);
    except ValueError:
        SeekToEndOfFile(fp);
    CatSize = fp.tell();
    CatSizeEnd = CatSize;
    fp.seek(curloc, 0)
    if(curloc > 0):
        fp.seek(0, 0)
    catheaderver = str(int(formatspecs['format_ver'].replace(".", "")))
    catstring = fp.read(formatspecs['format_len'] + len(catheaderver)).decode("UTF-8")
    catdelszie = len(formatspecs['format_delimiter'])
    catdel = fp.read(catdelszie).decode("UTF-8")
    if(catstring != formatspecs['format_magic']+catheaderver):
        return False
    if(catdel != formatspecs['format_delimiter']):
        return False
    if(formatspecs['new_style']):
        catheader = ReadFileHeaderDataBySize(
            fp, formatspecs['format_delimiter'])
    else:
        catheader = ReadFileHeaderDataWoSize(
            fp, formatspecs['format_delimiter'])
    fnumextrafieldsize = int(catheader[5], 16)
    fnumextrafields = int(catheader[6], 16)
    fextrafieldslist = []
    extrastart = 7
    extraend = extrastart + fnumextrafields
    extrafieldslist = []
    if(extrastart < extraend):
        fextrafieldslist.append(catheader[extrastart])
        extrastart = extrastart + 1
    if(curloc > 0):
        fp.seek(curloc, 0)
    catversion = re.findall("([\\d]+)", catstring)
    fheadsize = int(catheader[0], 16)
    fnumfields = int(catheader[1], 16)
    fhencoding = catheader[2]
    fostype = catheader[3]
    fnumfiles = int(catheader[4], 16)
    fprechecksumtype = catheader[-2]
    fprechecksum = catheader[-1]
    headercheck = ValidateHeaderChecksum([catstring] + catheader[:-1], fprechecksumtype, fprechecksum, formatspecs)
    newfcs = GetHeaderChecksum([catstring] + catheader[:-1], fprechecksumtype, True, formatspecs)
    if(not headercheck and not skipchecksum):
        VerbosePrintOut(
            "File Header Checksum Error with file at offset " + str(0))
        VerbosePrintOut("'" + fprechecksum + "' != " +
                        "'" + newfcs + "'")
        return False
    catversions = re.search('(.*?)(\\d+)', catstring).groups()
    fcompresstype = compresscheck
    if(fcompresstype==formatspecs['format_magic']):
        fcompresstype = ""
    catlist = {'fnumfiles': fnumfiles, 'fformat': catversions[0], 'fcompression': fcompresstype, 'fencoding': fhencoding, 'fversion': catversions[1], 'fostype': fostype, 'fheadersize': fheadsize, 'fsize': CatSizeEnd, 'fnumfields': fnumfields + 2, 'fformatspecs': formatspecs, 'fchecksumtype': fprechecksumtype, 'fheaderchecksum': fprechecksum, 'frawheader': [catstring] + catheader, 'fextrafields': fnumextrafields, 'fextrafieldsize': fnumextrafieldsize, 'fextralist': fextrafieldslist, 'ffilelist': []}
    if(seekto >= fnumfiles):
        seekto = fnumfiles - 1
    if(seekto < 0):
        seekto = 0
    if(seekto >= 0):
        il = -1
        while(il < seekto):
            prefhstart = fp.tell()
            if(formatspecs['new_style']):
                preheaderdata = ReadFileHeaderDataBySize(
                    fp, formatspecs['format_delimiter'])
            else:
                preheaderdata = ReadFileHeaderDataWoSize(
                    fp, formatspecs['format_delimiter'])
            if(len(preheaderdata) == 0):
                break
            prefheadsize = int(preheaderdata[0], 16)
            prefnumfields = int(preheaderdata[1], 16)
            preftype = int(preheaderdata[2], 16)
            prefencoding = preheaderdata[3]
            if(re.findall("^[.|/]", preheaderdata[4])):
                prefname = preheaderdata[4]
            else:
                prefname = "./"+preheaderdata[4]
            prefbasedir = os.path.dirname(prefname)
            preflinkname = preheaderdata[5]
            prefsize = int(preheaderdata[6], 16)
            prefatime = int(preheaderdata[7], 16)
            prefmtime = int(preheaderdata[8], 16)
            prefctime = int(preheaderdata[9], 16)
            prefbtime = int(preheaderdata[10], 16)
            prefmode = int(preheaderdata[11], 16)
            prefchmode = stat.S_IMODE(prefmode)
            preftypemod = stat.S_IFMT(prefmode)
            prefwinattributes = int(preheaderdata[12], 16)
            prefcompression = preheaderdata[13]
            prefcsize = int(preheaderdata[14], 16)
            prefuid = int(preheaderdata[15], 16)
            prefuname = preheaderdata[16]
            prefgid = int(preheaderdata[17], 16)
            prefgname = preheaderdata[18]
            fid = int(preheaderdata[19], 16)
            finode = int(preheaderdata[20], 16)
            flinkcount = int(preheaderdata[21], 16)
            prefdev = int(preheaderdata[22], 16)
            prefdev_minor = int(preheaderdata[23], 16)
            prefdev_major = int(preheaderdata[24], 16)
            prefseeknextfile = preheaderdata[25]
            prefextrasize = int(preheaderdata[26], 16)
            prefextrafields = int(preheaderdata[27], 16)
            extrafieldslist = []
            extrastart = 28
            extraend = extrastart + prefextrafields
            extrafieldslist = []
            if(extrastart < extraend):
                extrafieldslist.append(preheaderdata[extrastart])
                extrastart = extrastart + 1
            prefcs = preheaderdata[-2].lower()
            prenewfcs = preheaderdata[-1].lower()
            prenewfcs = GetHeaderChecksum(
                preheaderdata[:-2], preheaderdata[-4].lower(), True, formatspecs)
            if(prefcs != prenewfcs and not skipchecksum):
                VerbosePrintOut("File Header Checksum Error with file " +
                                prefname + " at offset " + str(prefhstart))
                VerbosePrintOut("'" + prefcs + "' != " +
                                "'" + prenewfcs + "'")
                return False
                valid_archive = False
                invalid_archive = True
            prefhend = fp.tell() - 1
            prefcontentstart = fp.tell()
            prefcontents = ""
            pyhascontents = False
            if(prefsize > 0):
                if(prefcompression):
                    prefcontents = fp.read(prefsize)
                else:
                    prefcontents = fp.read(prefcsize)
                prenewfccs = GetFileChecksum(
                    prefcontents, preheaderdata[-3].lower(), False, formatspecs)
                pyhascontents = True
                if(prefccs != prenewfccs and not skipchecksum):
                    VerbosePrintOut("File Content Checksum Error with file " +
                                    prefname + " at offset " + str(prefcontentstart))
                    VerbosePrintOut("'" + prefccs +
                                    "' != " + "'" + prenewfccs + "'")
                    return False
            if(re.findall("^\\+([0-9]+)", prefseeknextfile)):
                fseeknextasnum = int(prefseeknextfile.replace("+", ""))
                if(abs(fseeknextasnum) == 0):
                    pass
                fp.seek(fseeknextasnum, 1)
            elif(re.findall("^\\-([0-9]+)", prefseeknextfile)):
                fseeknextasnum = int(prefseeknextfile)
                if(abs(fseeknextasnum) == 0):
                    pass
                fp.seek(fseeknextasnum, 1)
            elif(re.findall("^([0-9]+)", prefseeknextfile)):
                fseeknextasnum = int(prefseeknextfile)
                if(abs(fseeknextasnum) == 0):
                    pass
                fp.seek(fseeknextasnum, 0)
            else:
                return False
            il = il + 1
    fp.seek(seekstart, 0)
    fileidnum = il
    catfheadsize = int(preheaderdata[0], 16)
    catfnumfields = int(preheaderdata[1], 16)
    catftype = int(preheaderdata[2], 16)
    catfencoding = preheaderdata[3]
    if(re.findall("^[.|/]", preheaderdata[4])):
        catfname = preheaderdata[4]
    else:
        catfname = "./"+preheaderdata[4]
    catflinkname = preheaderdata[5]
    catfsize = int(preheaderdata[6], 16)
    catfbasedir = os.path.dirname(catfname)
    catlist = {'fid': fileidnum, 'foffset': fp.tell(), 'ftype': catftype, 'fencoding': catfencoding, 'fname': catfname,
               'fbasedir': catfbasedir, 'flinkname': catflinkname, 'fsize': catfsize}
    if(returnfp):
        catlist.update({'fp': fp})
    else:
        fp.close()
    return catlist


def ArchiveFileSeekToFileName(infile, seekfile=None, listonly=False, contentasfile=True, skipchecksum=False, formatspecs=__file_format_dict__, returnfp=False):
    if(hasattr(infile, "read") or hasattr(infile, "write")):
        fp = infile
        fp.seek(0, 0)
        fp = UncompressArchiveFile(fp, formatspecs)
        checkcompressfile = CheckCompressionSubType(fp, formatspecs, True)
        if(checkcompressfile == "tarfile" and TarFileCheck(infile)):
            return TarFileToArray(infile, 0, 0, listonly, contentasfile, skipchecksum, formatspecs, returnfp)
        elif(checkcompressfile == "zipfile" and zipfile.is_zipfile(infile)):
            return ZipFileToArray(infile, 0, 0, listonly, contentasfile, skipchecksum, formatspecs, returnfp)
        elif(rarfile_support and checkcompressfile == "rarfile" and (rarfile.is_rarfile(infile) or rarfile.is_rarfile_sfx(infile))):
            return RarFileToArray(infile, 0, 0, listonly, contentasfile, skipchecksum, formatspecs, returnfp)
        elif(py7zr_support and checkcompressfile == "7zipfile" and py7zr.is_7zfile(infile)):
            return SevenZipFileToArray(infile, 0, 0, listonly, contentasfile, skipchecksum, formatspecs, returnfp)
        elif(checkcompressfile != formatspecs['format_magic']):
            return False
        if(not fp):
            return False
        fp.seek(0, 0)
    elif(infile == "-"):
        fp = BytesIO()
        if(hasattr(sys.stdin, "buffer")):
            shutil.copyfileobj(sys.stdin.buffer, fp)
        else:
            shutil.copyfileobj(sys.stdin, fp)
        fp.seek(0, 0)
        fp = UncompressArchiveFile(fp, formatspecs)
        if(not fp):
            return False
        fp.seek(0, 0)
    elif(isinstance(infile, bytes) and sys.version_info[0] >= 3):
        fp = BytesIO()
        fp.write(infile)
        fp.seek(0, 0)
        fp = UncompressArchiveFile(fp, formatspecs)
        if(not fp):
            return False
        fp.seek(0, 0)
    elif(re.findall("^(http|https|ftp|ftps|sftp):\\/\\/", infile)):
        fp = download_file_from_internet_file(infile)
        fp = UncompressArchiveFile(fp, formatspecs)
        fp.seek(0, 0)
        if(not fp):
            return False
        fp.seek(0, 0)
    else:
        infile = RemoveWindowsPath(infile)
        checkcompressfile = CheckCompressionSubType(infile, formatspecs, True)
        if(checkcompressfile == "tarfile" and TarFileCheck(infile)):
            return TarFileToArray(infile, 0, 0, listonly, contentasfile, skipchecksum, formatspecs, returnfp)
        elif(checkcompressfile == "zipfile" and zipfile.is_zipfile(infile)):
            return ZipFileToArray(infile, 0, 0, listonly, contentasfile, skipchecksum, formatspecs, returnfp)
        elif(rarfile_support and checkcompressfile == "rarfile" and (rarfile.is_rarfile(infile) or rarfile.is_rarfile_sfx(infile))):
            return RarFileToArray(infile, 0, 0, listonly, contentasfile, skipchecksum, formatspecs, returnfp)
        elif(py7zr_support and checkcompressfile == "7zipfile" and py7zr.is_7zfile(infile)):
            return SevenZipFileToArray(infile, 0, 0, listonly, contentasfile, skipchecksum, formatspecs, returnfp)
        elif(checkcompressfile != formatspecs['format_magic']):
            return False
        compresscheck = CheckCompressionType(infile, formatspecs, True)
        if(not compresscheck):
            fextname = os.path.splitext(infile)[1]
            if(fextname == ".gz"):
                compresscheck = "gzip"
            elif(fextname == ".bz2"):
                compresscheck = "bzip2"
            elif(fextname == ".zst"):
                compresscheck = "zstd"
            elif(fextname == ".lz4" or fextname == ".clz4"):
                compresscheck = "lz4"
            elif(fextname == ".lzo" or fextname == ".lzop"):
                compresscheck = "lzo"
            elif(fextname == ".lzma"):
                compresscheck = "lzma"
            elif(fextname == ".xz"):
                compresscheck = "xz"
            elif(fextname == ".zz" or fextname == ".zl" or fextname == ".zlib"):
                compresscheck = "zlib"
            else:
                return False
        if(not compresscheck):
            return False
        fp = UncompressFile(infile, formatspecs, "rb")
    curloc = fp.tell()
    try:
        fp.seek(0, 2);
    except OSError:
        SeekToEndOfFile(fp);
    except ValueError:
        SeekToEndOfFile(fp);
    CatSize = fp.tell();
    CatSizeEnd = CatSize;
    fp.seek(curloc, 0)
    if(curloc > 0):
        fp.seek(0, 0)
    catheaderver = str(int(formatspecs['format_ver'].replace(".", "")))
    catstring = fp.read(formatspecs['format_len'] + len(catheaderver)).decode("UTF-8")
    catdelszie = len(formatspecs['format_delimiter'])
    catdel = fp.read(catdelszie).decode("UTF-8")
    if(catstring != formatspecs['format_magic']+catheaderver):
        return False
    if(catdel != formatspecs['format_delimiter']):
        return False
    if(formatspecs['new_style']):
        catheader = ReadFileHeaderDataBySize(
            fp, formatspecs['format_delimiter'])
    else:
        catheader = ReadFileHeaderDataWoSize(
            fp, formatspecs['format_delimiter'])
    fnumextrafieldsize = int(catheader[5], 16)
    fnumextrafields = int(catheader[6], 16)
    fextrafieldslist = []
    extrastart = 7
    extraend = extrastart + fnumextrafields
    extrafieldslist = []
    if(extrastart < extraend):
        fextrafieldslist.append(catheader[extrastart])
        extrastart = extrastart + 1
    if(curloc > 0):
        fp.seek(curloc, 0)
    catversion = re.findall("([\\d]+)", catstring)
    fheadsize = int(catheader[0], 16)
    fnumfields = int(catheader[1], 16)
    fhencoding = catheader[2]
    fostype = catheader[3]
    fnumfiles = int(catheader[4], 16)
    fprechecksumtype = catheader[-2]
    fprechecksum = catheader[-1]
    headercheck = ValidateHeaderChecksum([catstring] + catheader[:-1], fprechecksumtype, fprechecksum, formatspecs)
    newfcs = GetHeaderChecksum([catstring] + catheader[:-1], fprechecksumtype, True, formatspecs)
    if(not headercheck and not skipchecksum):
        VerbosePrintOut(
            "File Header Checksum Error with file at offset " + str(0))
        VerbosePrintOut("'" + fprechecksum + "' != " +
                        "'" + newfcs + "'")
        return False
    catversions = re.search('(.*?)(\\d+)', catstring).groups()
    fcompresstype = compresscheck
    if(fcompresstype==formatspecs['format_magic']):
        fcompresstype = ""
    catlist = {'fnumfiles': fnumfiles, 'fformat': catversions[0], 'fcompression': fcompresstype, 'fencoding': fhencoding, 'fversion': catversions[1], 'fostype': fostype, 'fheadersize': fheadsize, 'fsize': CatSizeEnd, 'fnumfields': fnumfields + 2, 'fformatspecs': formatspecs, 'fchecksumtype': fprechecksumtype, 'fheaderchecksum': fprechecksum, 'frawheader': [catstring] + catheader, 'fextrafields': fnumextrafields, 'fextrafieldsize': fnumextrafieldsize, 'fextralist': fextrafieldslist, 'ffilelist': []}
    seekto = fnumfiles - 1
    filefound = False
    if(seekto >= 0):
        il = -1
        while(il < seekto):
            prefhstart = fp.tell()
            if(formatspecs['new_style']):
                preheaderdata = ReadFileHeaderDataBySize(
                    fp, formatspecs['format_delimiter'])
            else:
                preheaderdata = ReadFileHeaderDataWoSize(
                    fp, formatspecs['format_delimiter'])
            if(len(preheaderdata) == 0):
                break
            prefheadsize = int(preheaderdata[0], 16)
            prefnumfields = int(preheaderdata[1], 16)
            preftype = int(preheaderdata[2], 16)
            prefencoding = preheaderdata[3]
            if(re.findall("^[.|/]", preheaderdata[4])):
                prefname = preheaderdata[4]
            else:
                prefname = "./"+preheaderdata[4]
            prefbasedir = os.path.dirname(prefname)
            preflinkname = preheaderdata[5]
            prefsize = int(preheaderdata[6], 16)
            prefatime = int(preheaderdata[7], 16)
            prefmtime = int(preheaderdata[8], 16)
            prefctime = int(preheaderdata[9], 16)
            prefbtime = int(preheaderdata[10], 16)
            prefmode = int(preheaderdata[11], 16)
            prefchmode = stat.S_IMODE(prefmode)
            preftypemod = stat.S_IFMT(prefmode)
            prefwinattributes = int(preheaderdata[12], 16)
            prefcompression = preheaderdata[13]
            prefcsize = int(preheaderdata[14], 16)
            prefuid = int(preheaderdata[15], 16)
            prefuname = preheaderdata[16]
            prefgid = int(preheaderdata[17], 16)
            prefgname = preheaderdata[18]
            fid = int(preheaderdata[19], 16)
            finode = int(preheaderdata[20], 16)
            flinkcount = int(preheaderdata[21], 16)
            prefdev = int(preheaderdata[22], 16)
            prefdev_minor = int(preheaderdata[23], 16)
            prefdev_major = int(preheaderdata[24], 16)
            prefseeknextfile = preheaderdata[25]
            prefextrasize = int(preheaderdata[26], 16)
            prefextrafields = int(preheaderdata[27], 16)
            extrafieldslist = []
            extrastart = 28
            extraend = extrastart + prefextrafields
            extrafieldslist = []
            if(extrastart < extraend):
                extrafieldslist.append(preheaderdata[extrastart])
                extrastart = extrastart + 1
            prefcs = preheaderdata[-2].lower()
            prenewfcs = preheaderdata[-1].lower()
            prenewfcs = GetHeaderChecksum(
                preheaderdata[:-2], preheaderdata[-4].lower(), True, formatspecs)
            if(prefcs != prenewfcs and not skipchecksum):
                VerbosePrintOut("File Header Checksum Error with file " +
                                prefname + " at offset " + str(prefhstart))
                VerbosePrintOut("'" + prefcs + "' != " +
                                "'" + prenewfcs + "'")
                return False
                valid_archive = False
                invalid_archive = True
            prefhend = fp.tell() - 1
            prefcontentstart = fp.tell()
            prefcontents = ""
            pyhascontents = False
            if(prefsize > 0):
                if(prefcompression):
                    prefcontents = fp.read(prefsize)
                else:
                    prefcontents = fp.read(prefcsize)
                prenewfccs = GetFileChecksum(
                    prefcontents, preheaderdata[-3].lower(), False, formatspecs)
                pyhascontents = True
                if(prefccs != prenewfccs and not skipchecksum):
                    VerbosePrintOut("File Content Checksum Error with file " +
                                    prefname + " at offset " + str(prefcontentstart))
                    VerbosePrintOut("'" + prefccs +
                                    "' != " + "'" + prenewfccs + "'")
                    return False
            if(re.findall("^\\+([0-9]+)", prefseeknextfile)):
                fseeknextasnum = int(prefseeknextfile.replace("+", ""))
                if(abs(fseeknextasnum) == 0):
                    pass
                fp.seek(fseeknextasnum, 1)
            elif(re.findall("^\\-([0-9]+)", prefseeknextfile)):
                fseeknextasnum = int(prefseeknextfile)
                if(abs(fseeknextasnum) == 0):
                    pass
                fp.seek(fseeknextasnum, 1)
            elif(re.findall("^([0-9]+)", prefseeknextfile)):
                fseeknextasnum = int(prefseeknextfile)
                if(abs(fseeknextasnum) == 0):
                    pass
                fp.seek(fseeknextasnum, 0)
            else:
                return False
            il = il + 1
            filefound = False
            if(prefname == seekfile):
                filefound = True
                break
    fp.seek(seekstart, 0)
    fileidnum = il
    catfheadsize = int(preheaderdata[0], 16)
    catfnumfields = int(preheaderdata[1], 16)
    catftype = int(preheaderdata[2], 16)
    catfencoding = preheaderdata[3]
    if(re.findall("^[.|/]", preheaderdata[4])):
        catfname = preheaderdata[4]
    else:
        catfname = "./"+preheaderdata[4]
    catflinkname = preheaderdata[5]
    catfsize = int(preheaderdata[6], 16)
    catfbasedir = os.path.dirname(catfname)
    if(filefound):
        catlist = {'fid': fileidnum, 'foffset': fp.tell(), 'ftype': catftype, 'fencoding': catfencoding, 'fname': catfname,
                   'fbasedir': catfbasedir, 'flinkname': catflinkname, 'fsize': catfsize}
    else:
        return False
    if(returnfp):
        catlist.update({'fp': fp})
    else:
        fp.close()
    return catlist


def ArchiveFileValidate(infile, formatspecs=__file_format_dict__, verbose=False, returnfp=False):
    if(verbose):
        logging.basicConfig(format="%(message)s",
                            stream=sys.stdout, level=logging.DEBUG)
    if(hasattr(infile, "read") or hasattr(infile, "write")):
        fp = infile
        fp.seek(0, 0)
        compresscheck = CheckCompressionType(fp, formatspecs, False)
        fp = UncompressArchiveFile(fp, formatspecs)
        checkcompressfile = CheckCompressionSubType(fp, formatspecs, True)
        if(checkcompressfile == "tarfile" and TarFileCheck(infile)):
            return TarFileToArray(infile, 0, 0, False, True, False, formatspecs, returnfp)
        elif(checkcompressfile == "zipfile" and zipfile.is_zipfile(infile)):
            return ZipFileToArray(infile, 0, 0, False, True, False, formatspecs, returnfp)
        elif(rarfile_support and checkcompressfile == "rarfile" and (rarfile.is_rarfile(infile) or rarfile.is_rarfile_sfx(infile))):
            return RarFileToArray(infile, 0, 0, False, True, False, formatspecs, returnfp)
        elif(py7zr_support and checkcompressfile == "7zipfile" and py7zr.is_7zfile(infile)):
            return SevenZipFileToArray(infile, 0, 0, False, True, False, formatspecs, returnfp)
        elif(checkcompressfile != formatspecs['format_magic']):
            return False
        if(not fp):
            return False
        if(not compresscheck and hasattr(fp, "name")):
            fextname = os.path.splitext(fp.name)[1]
            if(fextname == ".gz"):
                compresscheck = "gzip"
            elif(fextname == ".bz2"):
                compresscheck = "bzip2"
            elif(fextname == ".zst"):
                compresscheck = "zstd"
            elif(fextname == ".lz4" or fextname == ".clz4"):
                compresscheck = "lz4"
            elif(fextname == ".lzo" or fextname == ".lzop"):
                compresscheck = "lzo"
            elif(fextname == ".lzma"):
                compresscheck = "lzma"
            elif(fextname == ".xz"):
                compresscheck = "xz"
            elif(fextname == ".zz" or fextname == ".zl" or fextname == ".zlib"):
                compresscheck = "zlib"
            else:
                return False
        fp.seek(0, 0)
    elif(infile == "-"):
        fp = BytesIO()
        if(hasattr(sys.stdin, "buffer")):
            shutil.copyfileobj(sys.stdin.buffer, fp)
        else:
            shutil.copyfileobj(sys.stdin, fp)
        fp.seek(0, 0)
        compresscheck = CheckCompressionType(fp, formatspecs, False)
        fp = UncompressArchiveFile(fp, formatspecs)
        if(not fp):
            return False
        fp.seek(0, 0)
    elif(isinstance(infile, bytes) and sys.version_info[0] >= 3):
        fp = BytesIO()
        fp.write(infile)
        fp.seek(0, 0)
        compresscheck = CheckCompressionType(fp, formatspecs, False)
        fp = UncompressArchiveFile(fp, formatspecs)
        if(not fp):
            return False
        fp.seek(0, 0)
    elif(re.findall("^(http|https|ftp|ftps|sftp):\\/\\/", infile)):
        fp = download_file_from_internet_file(infile)
        fp.seek(0, 0)
        compresscheck = CheckCompressionType(fp, formatspecs, False)
        fp = UncompressArchiveFile(fp, formatspecs)
        fp.seek(0, 0)
        if(not fp):
            return False
        fp.seek(0, 0)
    else:
        infile = RemoveWindowsPath(infile)
        checkcompressfile = CheckCompressionSubType(infile, formatspecs, True)
        if(checkcompressfile == "tarfile" and TarFileCheck(infile)):
            return TarFileToArray(infile, 0, 0, False, True, False, formatspecs, returnfp)
        elif(checkcompressfile == "zipfile" and zipfile.is_zipfile(infile)):
            return ZipFileToArray(infile, 0, 0, False, True, False, formatspecs, returnfp)
        elif(rarfile_support and checkcompressfile == "rarfile" and (rarfile.is_rarfile(infile) or rarfile.is_rarfile_sfx(infile))):
            return RarFileToArray(infile, 0, 0, False, True, False, formatspecs, returnfp)
        elif(py7zr_support and checkcompressfile == "7zipfile" and py7zr.is_7zfile(infile)):
            return SevenZipFileToArray(infile, 0, 0, False, True, False, formatspecs, returnfp)
        elif(checkcompressfile != formatspecs['format_magic']):
            return False
        compresscheck = CheckCompressionType(infile, formatspecs, True)
        if(not compresscheck):
            fextname = os.path.splitext(infile)[1]
            if(fextname == ".gz"):
                compresscheck = "gzip"
            elif(fextname == ".bz2"):
                compresscheck = "bzip2"
            elif(fextname == ".zst"):
                compresscheck = "zstd"
            elif(fextname == ".lz4" or fextname == ".clz4"):
                compresscheck = "lz4"
            elif(fextname == ".lzo" or fextname == ".lzop"):
                compresscheck = "lzo"
            elif(fextname == ".lzma"):
                compresscheck = "lzma"
            elif(fextname == ".xz"):
                compresscheck = "xz"
            elif(fextname == ".zz" or fextname == ".zl" or fextname == ".zlib"):
                compresscheck = "zlib"
            else:
                return False
        if(not compresscheck):
            return False
        fp = UncompressFile(infile, formatspecs, "rb")
    curloc = fp.tell()
    try:
        fp.seek(0, 2);
    except OSError:
        SeekToEndOfFile(fp);
    except ValueError:
        SeekToEndOfFile(fp);
    CatSize = fp.tell();
    CatSizeEnd = CatSize;
    fp.seek(curloc, 0)
    if(curloc > 0):
        fp.seek(0, 0)
    catheaderver = str(int(formatspecs['format_ver'].replace(".", "")))
    catstring = fp.read(formatspecs['format_len'] + len(catheaderver)).decode("UTF-8")
    catdelszie = len(formatspecs['format_delimiter'])
    catdel = fp.read(catdelszie).decode("UTF-8")
    if(catstring != formatspecs['format_magic']+catheaderver):
        return False
    if(catdel != formatspecs['format_delimiter']):
        return False
    if(formatspecs['new_style']):
        catheader = ReadFileHeaderDataBySize(
            fp, formatspecs['format_delimiter'])
    else:
        catheader = ReadFileHeaderDataWoSize(
            fp, formatspecs['format_delimiter'])
    fnumextrafieldsize = int(catheader[5], 16)
    fnumextrafields = int(catheader[6], 16)
    fextrafieldslist = []
    extrastart = 7
    extraend = extrastart + fnumextrafields
    extrafieldslist = []
    if(extrastart < extraend):
        fextrafieldslist.append(catheader[extrastart])
        extrastart = extrastart + 1
    if(curloc > 0):
        fp.seek(curloc, 0)
    catversion = re.findall("([\\d]+)", catstring)
    fheadsize = int(catheader[0], 16)
    fnumfields = int(catheader[1], 16)
    fhencoding = catheader[2]
    fostype = catheader[3]
    fnumfiles = int(catheader[4], 16)
    fprechecksumtype = catheader[-2]
    fprechecksum = catheader[-1]
    il = 0
    headercheck = ValidateHeaderChecksum([catstring] + catheader[:-1], fprechecksumtype, fprechecksum, formatspecs)
    newfcs = GetHeaderChecksum([catstring] + catheader[:-1], fprechecksumtype, True, formatspecs)
    valid_archive = True
    invalid_archive = False
    if(verbose):
        if(hasattr(infile, "read") or hasattr(infile, "write")):
            try:
                VerbosePrintOut(infile.name)
            except AttributeError:
                pass
        elif(sys.version_info[0] >= 3 and isinstance(infile, bytes)):
            pass
        else:
            VerbosePrintOut(infile)
        VerbosePrintOut("Number of Records " + str(fnumfiles))
    if(headercheck):
        if(verbose):
            VerbosePrintOut("File Header Checksum Passed at offset " + str(0))
            VerbosePrintOut("'" + fprechecksum + "' == " +
                            "'" + newfcs + "'")
    else:
        if(verbose):
            VerbosePrintOut("File Header Checksum Failed at offset " + str(0))
            VerbosePrintOut("'" + fprechecksum + "' != " +
                            "'" + newfcs + "'")
            valid_archive = False
            invalid_archive = True
    if(verbose):
        VerbosePrintOut("")
    while(il < fnumfiles):
        catfhstart = fp.tell()
        if(formatspecs['new_style']):
            catheaderdata = ReadFileHeaderDataBySize(
                fp, formatspecs['format_delimiter'])
        else:
            catheaderdata = ReadFileHeaderDataWoSize(
                fp, formatspecs['format_delimiter'])
        if(len(catheaderdata) == 0):
            break
        catfheadsize = int(catheaderdata[0], 16)
        catfnumfields = int(catheaderdata[1], 16)
        catftype = int(catheaderdata[2], 16)
        catfencoding = catheader[3]
        if(re.findall("^[.|/]", catheaderdata[4])):
            catfname = catheaderdata[4]
        else:
            catfname = "./"+catheaderdata[4]
        catfbasedir = os.path.dirname(catfname)
        catflinkname = catheaderdata[5]
        catfsize = int(catheaderdata[6], 16)
        catfatime = int(catheaderdata[7], 16)
        catfmtime = int(catheaderdata[8], 16)
        catfctime = int(catheaderdata[9], 16)
        catfbtime = int(catheaderdata[10], 16)
        catfmode = int(catheaderdata[11], 16)
        catfchmode = stat.S_IMODE(catfmode)
        catftypemod = stat.S_IFMT(catfmode)
        catfwinattributes = int(catheaderdata[12], 16)
        catfcompression = catheaderdata[13]
        catfcsize = int(catheaderdata[14], 16)
        catfuid = int(catheaderdata[15], 16)
        catfuname = catheaderdata[16]
        catfgid = int(catheaderdata[17], 16)
        catfgname = catheaderdata[18]
        fid = int(catheaderdata[19], 16)
        finode = int(catheaderdata[20], 16)
        flinkcount = int(catheaderdata[21], 16)
        catfdev = int(catheaderdata[22], 16)
        catfdev_minor = int(catheaderdata[23], 16)
        catfdev_major = int(catheaderdata[24], 16)
        catfseeknextfile = catheaderdata[25]
        catfextrasize = int(catheaderdata[26], 16)
        catfextrafields = int(catheaderdata[27], 16)
        extrafieldslist = []
        extrastart = 28
        extraend = extrastart + catfextrafields
        extrafieldslist = []
        if(extrastart < extraend):
            extrafieldslist.append(catheaderdata[extrastart])
            extrastart = extrastart + 1
        catfcs = catheaderdata[-2].lower()
        catfccs = catheaderdata[-1].lower()
        catnewfcs = GetHeaderChecksum(
            catheaderdata[:-2], catheaderdata[-4].lower(), True, formatspecs)
        if(verbose):
            VerbosePrintOut(catfname)
            VerbosePrintOut("Record Number " + str(il) + "; File ID " +
                            str(fid) + "; iNode Number " + str(finode))
        if(catfcs == catnewfcs):
            if(verbose):
                VerbosePrintOut(
                    "File Header Checksum Passed at offset " + str(catfhstart))
                VerbosePrintOut("'" + catfcs + "' == " +
                                "'" + catnewfcs + "'")
        else:
            if(verbose):
                VerbosePrintOut(
                    "File Header Checksum Failed at offset " + str(catfhstart))
                VerbosePrintOut("'" + catfcs + "' != " +
                                "'" + catnewfcs + "'")
            valid_archive = False
            invalid_archive = True
        catfhend = fp.tell() - 1
        catfcontentstart = fp.tell()
        catfcontents = ""
        pyhascontents = False
        if(catfsize > 0):
            if(catfcompression == "none" or catfcompression == "" or catfcompression == "auto"):
                catfcontents = fp.read(catfsize)
            else:
                catfcontents = fp.read(catfcsize)
            catnewfccs = GetFileChecksum(
                catfcontents, catheaderdata[-3].lower(), False, formatspecs)
            pyhascontents = True
            if(catfccs == catnewfccs):
                if(verbose):
                    VerbosePrintOut(
                        "File Content Checksum Passed at offset " + str(catfcontentstart))
                    VerbosePrintOut("'" + catfccs +
                                    "' == " + "'" + catnewfccs + "'")
            else:
                if(verbose):
                    VerbosePrintOut(
                        "File Content Checksum Failed at offset " + str(catfcontentstart))
                    VerbosePrintOut("'" + catfccs +
                                    "' != " + "'" + catnewfccs + "'")
                valid_archive = False
                invalid_archive = True
        if(verbose):
            VerbosePrintOut("")
        if(re.findall("^\\+([0-9]+)", catfseeknextfile)):
            fseeknextasnum = int(catfseeknextfile.replace("+", ""))
            if(abs(fseeknextasnum) == 0):
                pass
            fp.seek(fseeknextasnum, 1)
        elif(re.findall("^\\-([0-9]+)", catfseeknextfile)):
            fseeknextasnum = int(catfseeknextfile)
            if(abs(fseeknextasnum) == 0):
                pass
            fp.seek(fseeknextasnum, 1)
        elif(re.findall("^([0-9]+)", catfseeknextfile)):
            fseeknextasnum = int(catfseeknextfile)
            if(abs(fseeknextasnum) == 0):
                pass
            fp.seek(fseeknextasnum, 0)
        else:
            return False
        il = il + 1
    if(valid_archive):
        if(returnfp):
            return fp
        else:
            fp.close()
            return True
    else:
        fp.close()
        return False


def ArchiveFileValidateFile(infile, formatspecs=__file_format_dict__, verbose=False, returnfp=False):
    return ArchiveFileValidate(infile, formatspecs, verbose, returnfp)


def ArchiveFileToArray(infile, seekstart=0, seekend=0, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__, returnfp=False):
    if(hasattr(infile, "read") or hasattr(infile, "write")):
        fp = infile
        fp.seek(0, 0)
        compresscheck = CheckCompressionType(fp, formatspecs, False)
        fp.seek(0, 0)
        fp = UncompressArchiveFile(fp, formatspecs)
        checkcompressfile = CheckCompressionSubType(fp, formatspecs, True)
        if(checkcompressfile == "tarfile" and TarFileCheck(infile)):
            return TarFileToArray(infile, seekstart, seekend, listonly, contentasfile, skipchecksum, formatspecs, returnfp)
        elif(checkcompressfile == "zipfile" and zipfile.is_zipfile(infile)):
            return ZipFileToArray(infile, seekstart, seekend, listonly, contentasfile, skipchecksum, formatspecs, returnfp)
        elif(rarfile_support and checkcompressfile == "rarfile" and (rarfile.is_rarfile(infile) or rarfile.is_rarfile_sfx(infile))):
            return RarFileToArray(infile, seekstart, seekend, listonly, contentasfile, skipchecksum, formatspecs, returnfp)
        elif(py7zr_support and checkcompressfile == "7zipfile" and py7zr.is_7zfile(infile)):
            return SevenZipFileToArray(infile, seekstart, seekend, listonly, contentasfile, skipchecksum, formatspecs, returnfp)
        elif(checkcompressfile != formatspecs['format_magic']):
            return False
        if(not fp):
            return False
        if(not compresscheck and hasattr(fp, "name")):
            fextname = os.path.splitext(fp.name)[1]
            if(fextname == ".gz"):
                compresscheck = "gzip"
            elif(fextname == ".bz2"):
                compresscheck = "bzip2"
            elif(fextname == ".zst"):
                compresscheck = "zstd"
            elif(fextname == ".lz4" or fextname == ".clz4"):
                compresscheck = "lz4"
            elif(fextname == ".lzo" or fextname == ".lzop"):
                compresscheck = "lzo"
            elif(fextname == ".lzma"):
                compresscheck = "lzma"
            elif(fextname == ".xz"):
                compresscheck = "xz"
            elif(fextname == ".zz" or fextname == ".zl" or fextname == ".zlib"):
                compresscheck = "zlib"
            else:
                return False
        fp.seek(0, 0)
    elif(infile == "-"):
        fp = BytesIO()
        if(hasattr(sys.stdin, "buffer")):
            shutil.copyfileobj(sys.stdin.buffer, fp)
        else:
            shutil.copyfileobj(sys.stdin, fp)
        fp.seek(0, 0)
        compresscheck = CheckCompressionType(fp, formatspecs, False)
        fp.seek(0, 0)
        fp = UncompressArchiveFile(fp, formatspecs)
        if(not fp):
            return False
        fp.seek(0, 0)
    elif(isinstance(infile, bytes) and sys.version_info[0] >= 3):
        fp = BytesIO()
        fp.write(infile)
        fp.seek(0, 0)
        compresscheck = CheckCompressionType(fp, formatspecs, False)
        fp.seek(0, 0)
        fp = UncompressArchiveFile(fp, formatspecs)
        if(not fp):
            return False
        fp.seek(0, 0)
    elif(re.findall("^(http|https|ftp|ftps|sftp):\\/\\/", infile)):
        fp = download_file_from_internet_file(infile)
        compresscheck = CheckCompressionType(fp, formatspecs, False)
        if(not compresscheck):
            fextname = os.path.splitext(infile)[1]
            if(fextname == ".gz"):
                compresscheck = "gzip"
            elif(fextname == ".bz2"):
                compresscheck = "bzip2"
            elif(fextname == ".zst"):
                compresscheck = "zstd"
            elif(fextname == ".lz4" or fextname == ".clz4"):
                compresscheck = "lz4"
            elif(fextname == ".lzo" or fextname == ".lzop"):
                compresscheck = "lzo"
            elif(fextname == ".lzma"):
                compresscheck = "lzma"
            elif(fextname == ".xz"):
                compresscheck = "xz"
            elif(fextname == ".zz" or fextname == ".zl" or fextname == ".zlib"):
                compresscheck = "zlib"
            else:
                return False
        fp.seek(0, 0)
        fp = UncompressArchiveFile(fp, formatspecs)
        if(not fp):
            return False
        fp.seek(0, 0)
    else:
        infile = RemoveWindowsPath(infile)
        checkcompressfile = CheckCompressionSubType(infile, formatspecs, True)
        if(checkcompressfile == "tarfile" and TarFileCheck(infile)):
            return TarFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp)
        elif(checkcompressfile == "zipfile" and zipfile.is_zipfile(infile)):
            return ZipFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp)
        elif(rarfile_support and checkcompressfile == "rarfile" and (rarfile.is_rarfile(infile) or rarfile.is_rarfile_sfx(infile))):
            return RarFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp)
        elif(py7zr_support and checkcompressfile == "7zipfile" and py7zr.is_7zfile(infile)):
            return SevenZipFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, returnfp)
        elif(checkcompressfile != formatspecs['format_magic']):
            return False
        compresscheck = CheckCompressionType(infile, formatspecs, True)
        if(not compresscheck):
            fextname = os.path.splitext(infile)[1]
            if(fextname == ".gz"):
                compresscheck = "gzip"
            elif(fextname == ".bz2"):
                compresscheck = "bzip2"
            elif(fextname == ".zst"):
                compresscheck = "zstd"
            elif(fextname == ".lz4" or fextname == ".clz4"):
                compresscheck = "lz4"
            elif(fextname == ".lzo" or fextname == ".lzop"):
                compresscheck = "lzo"
            elif(fextname == ".lzma"):
                compresscheck = "lzma"
            elif(fextname == ".xz"):
                compresscheck = "xz"
            elif(fextname == ".zz" or fextname == ".zl" or fextname == ".zlib"):
                compresscheck = "zlib"
            else:
                return False
        if(not compresscheck):
            return False
        fp = UncompressFile(infile, formatspecs, "rb")
    curloc = fp.tell()
    try:
        fp.seek(0, 2);
    except OSError:
        SeekToEndOfFile(fp);
    except ValueError:
        SeekToEndOfFile(fp);
    CatSize = fp.tell();
    CatSizeEnd = CatSize;
    fp.seek(curloc, 0)
    if(curloc > 0):
        fp.seek(0, 0)
    catheaderver = str(int(formatspecs['format_ver'].replace(".", "")))
    catstring = fp.read(formatspecs['format_len'] + len(catheaderver)).decode("UTF-8")
    catdelszie = len(formatspecs['format_delimiter'])
    catdel = fp.read(catdelszie).decode("UTF-8")
    if(catstring != formatspecs['format_magic']+catheaderver):
        return False
    if(catdel != formatspecs['format_delimiter']):
        return False
    if(formatspecs['new_style']):
        catheader = ReadFileHeaderDataBySize(
            fp, formatspecs['format_delimiter'])
    else:
        catheader = ReadFileHeaderDataWoSize(
            fp, formatspecs['format_delimiter'])
    fnumextrafieldsize = int(catheader[5], 16)
    fnumextrafields = int(catheader[6], 16)
    fextrafieldslist = []
    extrastart = 7
    extraend = extrastart + fnumextrafields
    extrafieldslist = []
    if(extrastart < extraend):
        fextrafieldslist.append(catheader[extrastart])
        extrastart = extrastart + 1
    if(curloc > 0):
        fp.seek(curloc, 0)
    catversion = re.findall("([\\d]+)", catstring)
    fheadsize = int(catheader[0], 16)
    fnumfields = int(catheader[1], 16)
    fhencoding = catheader[2]
    fostype = catheader[3]
    fnumfiles = int(catheader[4], 16)
    fprechecksumtype = catheader[-2]
    fprechecksum = catheader[-1]
    headercheck = ValidateHeaderChecksum([catstring] + catheader[:-1], fprechecksumtype, fprechecksum, formatspecs)
    newfcs = GetHeaderChecksum([catstring] + catheader[:-1], fprechecksumtype, True, formatspecs)
    if(not headercheck and not skipchecksum):
        VerbosePrintOut(
            "File Header Checksum Error with file at offset " + str(0))
        VerbosePrintOut("'" + fprechecksum + "' != " +
                        "'" + newfcs + "'")
        return False
    catversions = re.search('(.*?)(\\d+)', catstring).groups()
    fcompresstype = compresscheck
    if(fcompresstype==formatspecs['format_magic']):
        fcompresstype = ""
    catlist = {'fnumfiles': fnumfiles, 'fformat': catversions[0], 'fcompression': fcompresstype, 'fencoding': fhencoding, 'fversion': catversions[1], 'fostype': fostype, 'fheadersize': fheadsize, 'fsize': CatSizeEnd, 'fnumfields': fnumfields + 2, 'fformatspecs': formatspecs, 'fchecksumtype': fprechecksumtype, 'fheaderchecksum': fprechecksum, 'frawheader': [catstring] + catheader, 'fextrafields': fnumextrafields, 'fextrafieldsize': fnumextrafieldsize, 'fextralist': fextrafieldslist, 'ffilelist': []}
    if(seekstart < 0 and seekstart > fnumfiles):
        seekstart = 0
    if(seekend == 0 or seekend > fnumfiles and seekend < seekstart):
        seekend = fnumfiles
    elif(seekend < 0 and abs(seekend) <= fnumfiles and abs(seekend) >= seekstart):
        seekend = fnumfiles - abs(seekend)
    if(seekstart > 0):
        il = 0
        while(il < seekstart):
            prefhstart = fp.tell()
            if(formatspecs['new_style']):
                preheaderdata = ReadFileHeaderDataBySize(
                    fp, formatspecs['format_delimiter'])
            else:
                preheaderdata = ReadFileHeaderDataWoSize(
                    fp, formatspecs['format_delimiter'])
            if(len(preheaderdata) == 0):
                break
            prefheadsize = int(preheaderdata[0], 16)
            prefnumfields = int(preheaderdata[1], 16)
            prefencoding = preheaderdata[3]
            if(re.findall("^[.|/]", preheaderdata[4])):
                prefname = preheaderdata[4]
            else:
                prefname = "./"+preheaderdata[4]
            prefsize = int(preheaderdata[6], 16)
            prefcompression = preheaderdata[13]
            prefcsize = int(preheaderdata[14], 16)
            prefseeknextfile = preheaderdata[25]
            prefextrasize = int(preheaderdata[26], 16)
            prefextrafields = int(preheaderdata[27], 16)
            extrafieldslist = []
            extrastart = 28
            extraend = extrastart + prefextrafields
            extrafieldslist = []
            if(extrastart < extraend):
                extrafieldslist.append(preheaderdata[extrastart])
                extrastart = extrastart + 1
            prefcs = preheaderdata[-2].lower()
            prenewfcs = preheaderdata[-1].lower()
            prenewfcs = GetHeaderChecksum(
                preheaderdata[:-2], preheaderdata[-4].lower(), True, formatspecs)
            if(prefcs != prenewfcs and not skipchecksum):
                VerbosePrintOut("File Header Checksum Error with file " +
                                prefname + " at offset " + str(prefhstart))
                VerbosePrintOut("'" + prefcs + "' != " +
                                "'" + prenewfcs + "'")
                return False
                valid_archive = False
                invalid_archive = True
            prefhend = fp.tell() - 1
            prefcontentstart = fp.tell()
            prefcontents = ""
            pyhascontents = False
            if(prefsize > 0):
                if(prefcompression == "none" or prefcompression == "" or prefcompression == "auto"):
                    prefcontents = fp.read(prefsize)
                else:
                    prefcontents = fp.read(prefcsize)
                prenewfccs = GetFileChecksum(
                    prefcontents, preheaderdata[-3].lower(), False, formatspecs)
                pyhascontents = True
                if(prefccs != prenewfccs and not skipchecksum):
                    VerbosePrintOut("File Content Checksum Error with file " +
                                    prefname + " at offset " + str(prefcontentstart))
                    VerbosePrintOut("'" + prefccs +
                                    "' != " + "'" + prenewfccs + "'")
                    return False
            if(re.findall("^\\+([0-9]+)", prefseeknextfile)):
                fseeknextasnum = int(prefseeknextfile.replace("+", ""))
                if(abs(fseeknextasnum) == 0):
                    pass
                fp.seek(fseeknextasnum, 1)
            elif(re.findall("^\\-([0-9]+)", prefseeknextfile)):
                fseeknextasnum = int(prefseeknextfile)
                if(abs(fseeknextasnum) == 0):
                    pass
                fp.seek(fseeknextasnum, 1)
            elif(re.findall("^([0-9]+)", prefseeknextfile)):
                fseeknextasnum = int(prefseeknextfile)
                if(abs(fseeknextasnum) == 0):
                    pass
                fp.seek(fseeknextasnum, 0)
            else:
                return False
            il = il + 1
    fileidnum = seekstart
    realidnum = 0
    while(fileidnum < seekend):
        catfhstart = fp.tell()
        if(formatspecs['new_style']):
            catheaderdata = ReadFileHeaderDataBySize(
                fp, formatspecs['format_delimiter'])
        else:
            catheaderdata = ReadFileHeaderDataWoSize(
                fp, formatspecs['format_delimiter'])
        if(len(catheaderdata) == 0):
            break
        catfheadsize = int(catheaderdata[0], 16)
        catfnumfields = int(catheaderdata[1], 16)
        catftype = int(catheaderdata[2], 16)
        catfencoding = catheaderdata[3]
        if(re.findall("^[.|/]", catheaderdata[4])):
            catfname = catheaderdata[4]
        else:
            catfname = "./"+catheaderdata[4]
        catfbasedir = os.path.dirname(catfname)
        catflinkname = catheaderdata[5]
        catfsize = int(catheaderdata[6], 16)
        catfatime = int(catheaderdata[7], 16)
        catfmtime = int(catheaderdata[8], 16)
        catfctime = int(catheaderdata[9], 16)
        catfbtime = int(catheaderdata[10], 16)
        catfmode = int(catheaderdata[11], 16)
        catfchmode = stat.S_IMODE(catfmode)
        catftypemod = stat.S_IFMT(catfmode)
        catfwinattributes = int(catheaderdata[12], 16)
        catfcompression = catheaderdata[13]
        catfcsize = int(catheaderdata[14], 16)
        catfuid = int(catheaderdata[15], 16)
        catfuname = catheaderdata[16]
        catfgid = int(catheaderdata[17], 16)
        catfgname = catheaderdata[18]
        catfid = int(catheaderdata[19], 16)
        catfinode = int(catheaderdata[20], 16)
        catflinkcount = int(catheaderdata[21], 16)
        catfdev = int(catheaderdata[22], 16)
        catfdev_minor = int(catheaderdata[23], 16)
        catfdev_major = int(catheaderdata[24], 16)
        catfseeknextfile = catheaderdata[25]
        catfextrasize = int(catheaderdata[26], 16)
        catfextrafields = int(catheaderdata[27], 16)
        extrafieldslist = []
        extrastart = 28
        extraend = extrastart + catfextrafields
        extrafieldslist = []
        if(extrastart < extraend):
            extrafieldslist.append(catheaderdata[extrastart])
            extrastart = extrastart + 1
        catfcs = catheaderdata[-2].lower()
        catfccs = catheaderdata[-1].lower()
        catnewfcs = GetHeaderChecksum(
            catheaderdata[:-2], catheaderdata[-4].lower(), True, formatspecs)
        if(catfcs != catnewfcs and not skipchecksum):
            VerbosePrintOut("File Header Checksum Error with file " +
                            catfname + " at offset " + str(catfhstart))
            VerbosePrintOut("'" + catfcs + "' != " +
                            "'" + catnewfcs + "'")
            return False
        catfhend = fp.tell() - 1
        catfcontentstart = fp.tell()
        catfcontents = BytesIO()
        pyhascontents = False
        if(catfsize > 0 and not listonly):
            if(catfcompression == "none" or catfcompression == "" or catfcompression == "auto"):
                catfcontents.write(fp.read(catfsize))
            else:
                catfcontents.write(fp.read(catfcsize))
            catfcontents.seek(0, 0)
            catnewfccs = GetFileChecksum(
                catfcontents.read(), catheaderdata[-3].lower(), False, formatspecs)
            pyhascontents = True
            if(catfccs != catnewfccs and not skipchecksum):
                VerbosePrintOut("File Content Checksum Error with file " +
                                catfname + " at offset " + str(catfcontentstart))
                VerbosePrintOut("'" + catfccs + "' != " +
                                "'" + catnewfccs + "'")
                return False
            if(catfcompression == "none" or catfcompression == "" or catfcompression == "auto"):
                pass
            else:
                catfcontents.seek(0, 0)
                if(uncompress):
                    catcfcontents = UncompressArchiveFile(
                        catfcontents, formatspecs)
                    catcfcontents.seek(0, 0)
                    catfcontents = BytesIO()
                    shutil.copyfileobj(catcfcontents, catfcontents)
                    catcfcontents.close()
                    catfcontents.seek(0, 0)
                    catfccs = GetFileChecksum(
                        catfcontents.read(), catheaderdata[-3].lower(), False, formatspecs)
        if(catfsize > 0 and listonly):
            if(catfcompression == "none" or catfcompression == "" or catfcompression == "auto"):
                fp.seek(catfsize, 1)
            else:
                fp.seek(catfcsize, 1)
            pyhascontents = False
        catfcontentend = fp.tell()
        if(re.findall("^\\+([0-9]+)", catfseeknextfile)):
            fseeknextasnum = int(catfseeknextfile.replace("+", ""))
            if(abs(fseeknextasnum) == 0):
                pass
            fp.seek(fseeknextasnum, 1)
        elif(re.findall("^\\-([0-9]+)", catfseeknextfile)):
            fseeknextasnum = int(catfseeknextfile)
            if(abs(fseeknextasnum) == 0):
                pass
            fp.seek(fseeknextasnum, 1)
        elif(re.findall("^([0-9]+)", catfseeknextfile)):
            fseeknextasnum = int(catfseeknextfile)
            if(abs(fseeknextasnum) == 0):
                pass
            fp.seek(fseeknextasnum, 0)
        else:
            return False
        catfcontents.seek(0, 0)
        if(not contentasfile):
            catfcontents = catfcontents.read()
        catlist['ffilelist'].append({'fid': realidnum, 'fidalt': fileidnum, 'fheadersize': catfheadsize, 'fhstart': catfhstart, 'fhend': catfhend, 'ftype': catftype, 'fencoding': catfencoding, 'fname': catfname, 'fbasedir': catfbasedir, 'flinkname': catflinkname, 'fsize': catfsize, 'fatime': catfatime, 'fmtime': catfmtime, 'fctime': catfctime, 'fbtime': catfbtime, 'fmode': catfmode, 'fchmode': catfchmode, 'ftypemod': catftypemod, 'fwinattributes': catfwinattributes, 'fcompression': catfcompression, 'fcsize': catfcsize, 'fuid': catfuid, 'funame': catfuname, 'fgid': catfgid, 'fgname': catfgname, 'finode': catfinode, 'flinkcount': catflinkcount, 'fdev': catfdev, 'fminor': catfdev_minor, 'fmajor': catfdev_major, 'fseeknextfile': catfseeknextfile, 'fheaderchecksumtype': catheaderdata[-4], 'fcontentchecksumtype': catheaderdata[-3], 'fnumfields': catfnumfields + 2, 'frawheader': catheaderdata, 'fextrafields': catfextrafields, 'fextrafieldsize': catfextrasize, 'fextralist': extrafieldslist, 'fheaderchecksum': catfcs, 'fcontentchecksum': catfccs, 'fhascontents': pyhascontents, 'fcontentstart': catfcontentstart, 'fcontentend': catfcontentend, 'fcontentasfile': contentasfile, 'fcontents': catfcontents})
        fileidnum = fileidnum + 1
        realidnum = realidnum + 1
    if(returnfp):
        catlist.update({'fp': fp})
    else:
        fp.close()
    return catlist


def ArchiveFileStringToArray(catstr, seekstart=0, seekend=0, listonly=False, contentasfile=True, skipchecksum=False, formatspecs=__file_format_dict__, returnfp=False):
    fp = BytesIO(catstr)
    listcatfiles = ArchiveFileToArray(
        fp, seekstart, seekend, listonly, contentasfile, True, skipchecksum, formatspecs, returnfp)
    return listcatfiles


def TarFileToArray(infile, seekstart=0, seekend=0, listonly=False, contentasfile=True, skipchecksum=False, formatspecs=__file_format_dict__, returnfp=False):
    fp = BytesIO()
    fp = PackArchiveFileFromTarFile(
        infile, fp, "auto", True, None, compressionlistalt, "crc32", [], formatspecs, False, True)
    listcatfiles = ArchiveFileToArray(
        fp, seekstart, seekend, listonly, contentasfile, True, skipchecksum, formatspecs, returnfp)
    return listcatfiles


def ZipFileToArray(infile, seekstart=0, seekend=0, listonly=False, contentasfile=True, skipchecksum=False, formatspecs=__file_format_dict__, returnfp=False):
    fp = BytesIO()
    fp = PackArchiveFileFromZipFile(
        infile, fp, "auto", True, None, compressionlistalt, "crc32", [], formatspecs, False, True)
    listcatfiles = ArchiveFileToArray(
        fp, seekstart, seekend, listonly, contentasfile, True, skipchecksum, formatspecs, returnfp)
    return listcatfiles


if(not rarfile_support):
    def RarFileToArray(infile, seekstart=0, seekend=0, listonly=False, contentasfile=True, skipchecksum=False, formatspecs=__file_format_dict__, returnfp=False):
        return False

if(rarfile_support):
    def RarFileToArray(infile, seekstart=0, seekend=0, listonly=False, contentasfile=True, skipchecksum=False, formatspecs=__file_format_dict__, returnfp=False):
        fp = BytesIO()
        fp = PackArchiveFileFromSevenZipFile(
            infile, fp, "auto", True, None, compressionlistalt, "crc32", [], formatspecs, False, True)
        listcatfiles = ArchiveFileToArray(
            fp, seekstart, seekend, listonly, contentasfile, True, skipchecksum, formatspecs, returnfp)
        return listcatfiles

if(not py7zr_support):
    def SevenZipFileToArray(infile, seekstart=0, seekend=0, listonly=False, contentasfile=True, skipchecksum=False, formatspecs=__file_format_dict__, returnfp=False):
        return False

if(py7zr_support):
    def SevenZipFileToArray(infile, seekstart=0, seekend=0, listonly=False, contentasfile=True, skipchecksum=False, formatspecs=__file_format_dict__, returnfp=False):
        fp = BytesIO()
        fp = PackArchiveFileFromSevenZipFile(
            infile, fp, "auto", True, None, compressionlistalt, "crc32", [], formatspecs, False, True)
        listcatfiles = ArchiveFileToArray(
            fp, seekstart, seekend, listonly, contentasfile, True, skipchecksum, formatspecs, returnfp)
        return listcatfiles


def InFileToArray(infile, seekstart=0, seekend=0, listonly=False, contentasfile=True, skipchecksum=False, formatspecs=__file_format_dict__, returnfp=False):
    checkcompressfile = CheckCompressionSubType(infile, formatspecs, True)
    if(checkcompressfile == "tarfile" and TarFileCheck(infile)):
        return TarFileToArray(infile, seekstart, seekend, listonly, contentasfile, skipchecksum, formatspecs, returnfp)
    elif(checkcompressfile == "zipfile" and zipfile.is_zipfile(infile)):
        return ZipFileToArray(infile, seekstart, seekend, listonly, contentasfile, skipchecksum, formatspecs, returnfp)
    elif(rarfile_support and checkcompressfile == "rarfile" and (rarfile.is_rarfile(infile) or rarfile.is_rarfile_sfx(infile))):
        return RarFileToArray(infile, seekstart, seekend, listonly, contentasfile, skipchecksum, formatspecs, returnfp)
    elif(py7zr_support and checkcompressfile == "7zipfile" and py7zr.is_7zfile(infile)):
        return SevenZipFileToArray(infile, seekstart, seekend, listonly, contentasfile, skipchecksum, formatspecs, returnfp)
    elif(checkcompressfile == formatspecs['format_magic']):
        return ArchiveFileToArray(infile, seekstart, seekend, listonly, contentasfile, True, skipchecksum, formatspecs, returnfp)
    else:
        return False
    return False


def ListDirToArrayAlt(infiles, dirlistfromtxt=False, followlink=False, listonly=False, contentasfile=True, checksumtype=["crc32", "crc32", "crc32"], extradata=[], formatspecs=__file_format_dict__, verbose=False):
    catver = formatspecs['format_ver']
    fileheaderver = str(int(catver.replace(".", "")))
    fileheader = AppendNullByte(
        formatspecs['format_magic'] + fileheaderver, formatspecs['format_delimiter'])
    advancedlist = formatspecs['use_advanced_list']
    altinode = formatspecs['use_alt_inode']
    infilelist = []
    if(infiles == "-"):
        for line in sys.stdin:
            infilelist.append(line.strip())
        infilelist = list(filter(None, infilelist))
    elif(infiles != "-" and dirlistfromtxt and os.path.exists(infiles) and (os.path.isfile(infiles) or infiles == os.devnull)):
        if(not os.path.exists(infiles) or not os.path.isfile(infiles)):
            return False
        with UncompressFile(infiles, formatspecs, "r") as finfile:
            for line in finfile:
                infilelist.append(line.strip())
        infilelist = list(filter(None, infilelist))
    else:
        if(isinstance(infiles, (list, tuple, ))):
            infilelist = list(filter(None, infiles))
        elif(isinstance(infiles, (basestring, ))):
            infilelist = list(filter(None, [infiles]))
    try:
        if os.stat not in os.supports_follow_symlinks and followlink:
            followlink = False
    except AttributeError:
        followlink = False
    if(advancedlist):
        GetDirList = ListDirAdvanced(infilelist, followlink, False)
    elif(advancedlist is None):
        GetDirList = infilelist
    else:
        GetDirList = ListDir(infilelist, followlink, False)
    if(not isinstance(GetDirList, (list, tuple, ))):
        return False
    FullSizeFiles = GetTotalSize(GetDirList)
    if(not GetDirList):
        return False
    curinode = 0
    curfid = 0
    inodelist = []
    inodetofile = {}
    filetoinode = {}
    inodetocatinode = {}
    fileidnum = 0
    fnumfiles = int(len(GetDirList))
    catver = formatspecs['format_ver']
    fileheaderver = str(int(catver.replace(".", "")))
    fileheader = AppendNullByte(
        formatspecs['format_magic'] + fileheaderver, formatspecs['format_delimiter'])
    fnumfileshex = format(int(fnumfiles), 'x').lower()
    fostype = platform.system()
    fhencoding = "UTF-8"
    tmpcatfile = BytesIO()
    AppendFileHeader(tmpcatfile, fnumfiles, fhencoding, [], checksumtype[0], formatspecs)
    tmpcatfile.seek(0, 0)
    catheaderver = str(int(formatspecs['format_ver'].replace(".", "")))
    catstring = tmpcatfile.read(formatspecs['format_len'] + len(catheaderver)).decode("UTF-8")
    catdelszie = len(formatspecs['format_delimiter'])
    catdel = tmpcatfile.read(catdelszie).decode("UTF-8")
    if(catstring != formatspecs['format_magic']+catheaderver):
        return False
    if(catdel != formatspecs['format_delimiter']):
        return False
    if(formatspecs['new_style']):
        catheader = ReadFileHeaderDataBySize(
            tmpcatfile, formatspecs['format_delimiter'])
    else:
        catheader = ReadFileHeaderDataWoSize(
            tmpcatfile, formatspecs['format_delimiter'])
    fnumextrafieldsize = int(catheader[5], 16)
    fnumextrafields = int(catheader[6], 16)
    fextrafieldslist = []
    extrastart = 7
    extraend = extrastart + fnumextrafields
    extrafieldslist = []
    if(extrastart < extraend):
        fextrafieldslist.append(catheader[extrastart])
        extrastart = extrastart + 1
    catversion = re.findall("([\\d]+)", catstring)
    fheadsize = int(catheader[0], 16)
    fnumfields = int(catheader[1], 16)
    fhencoding = catheader[2]
    fostype = catheader[3]
    fnumfiles = int(catheader[4], 16)
    fprechecksumtype = catheader[-2]
    fprechecksum = catheader[-1]
    headercheck = ValidateHeaderChecksum([catstring] + catheader[:-1], fprechecksumtype, fprechecksum, formatspecs)
    newfcs = GetHeaderChecksum([catstring] + catheader[:-1], fprechecksumtype, True, formatspecs)
    if(not headercheck):
        return False
    fileheader = tmpcatfile.read()
    tmpcatfile.close()
    catversions = re.search('(.*?)(\\d+)', catstring).groups()
    catfileheadercshex = GetFileChecksum(
        fileheader, checksumtype[0], False, formatspecs)
    fheadtell = len(fileheader)
    catlist = {'fnumfiles': fnumfiles, 'fformat': catversions[0], 'fcompression': "", 'fencoding': fhencoding, 'fversion': catversions[1], 'fostype': fostype,
               'fformatspecs': formatspecs, 'fchecksumtype': checksumtype[0], 'fheaderchecksum': catfileheadercshex, 'frawheader': [catstring] + catheader, 'ffilelist': []}
    FullSizeFilesAlt = 0
    for curfname in GetDirList:
        catfhstart = fheadtell
        fencoding = "UTF-8"
        if(re.findall("^[.|/]", curfname)):
            fname = curfname
        else:
            fname = "./"+curfname
        if(verbose):
            VerbosePrintOut(fname)
        if(not followlink or followlink is None):
            fstatinfo = os.lstat(fname)
        else:
            fstatinfo = os.stat(fname)
        fpremode = fstatinfo.st_mode
        finode = fstatinfo.st_ino
        flinkcount = fstatinfo.st_nlink
        try:
            FullSizeFilesAlt += fstatinfo.st_rsize
        except AttributeError:
            FullSizeFilesAlt += fstatinfo.st_size
        ftype = 0
        if(hasattr(os.path, "isjunction") and os.path.isjunction(fname)):
            ftype = 13
        #elif(fstatinfo.st_blocks * 512 < fstatinfo.st_size):
        #    ftype = 12
        elif(stat.S_ISREG(fpremode)):
            ftype = 0
        elif(stat.S_ISLNK(fpremode)):
            ftype = 2
        elif(stat.S_ISCHR(fpremode)):
            ftype = 3
        elif(stat.S_ISBLK(fpremode)):
            ftype = 4
        elif(stat.S_ISDIR(fpremode)):
            ftype = 5
        elif(stat.S_ISFIFO(fpremode)):
            ftype = 6
        elif(stat.S_ISSOCK(fpremode)):
            ftype = 8
        elif(hasattr(stat, "S_ISDOOR") and stat.S_ISDOOR(fpremode)):
            ftype = 9
        elif(hasattr(stat, "S_ISPORT") and stat.S_ISPORT(fpremode)):
            ftype = 10
        elif(hasattr(stat, "S_ISWHT") and stat.S_ISWHT(fpremode)):
            ftype = 11
        else:
            ftype = 0
        flinkname = ""
        fbasedir = os.path.dirname(fname)
        fcurfid = curfid
        if not followlink and finode != 0:
            unique_id = (fstatinfo.st_dev, finode)
            if ftype != 1:
                if unique_id in inodelist:
                    # Hard link detected
                    ftype = 1
                    flinkname = inodetofile[unique_id]
                    if altinode:
                        fcurinode = format(int(unique_id[1]), 'x').lower()
                    else:
                        fcurinode = format(int(inodetocatinode[unique_id]), 'x').lower()
                else:
                    # New inode
                    inodelist.append(unique_id)
                    inodetofile[unique_id] = fname
                    inodetocatinode[unique_id] = curinode
                    if altinode:
                        fcurinode = format(int(unique_id[1]), 'x').lower()
                    else:
                        fcurinode = format(int(curinode), 'x').lower()
                    curinode += 1
        else:
            # Handle cases where inodes are not supported or symlinks are followed
            fcurinode = format(int(curinode), 'x').lower()
            curinode += 1
        curfid = curfid + 1
        if(ftype == 2):
            flinkname = os.readlink(fname)
        try:
            fdev = fstatinfo.st_rdev
        except AttributeError:
            fdev = 0
        getfdev = GetDevMajorMinor(fdev)
        fdev_minor = getfdev[0]
        fdev_major = getfdev[1]
        # Types that should be considered zero-length in the archive context:
        zero_length_types = {1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 13}
        # Types that have actual data to read:
        data_types = {0, 7, 12}
        if ftype in zero_length_types:
            fsize = "0"
        elif ftype in data_types:
            fsize = fstatinfo.st_size
        else:
            fsize = fstatinfo.st_size
        fatime = fstatinfo.st_atime
        fmtime = fstatinfo.st_mtime
        fctime = fstatinfo.st_ctime
        if(hasattr(fstatinfo, "st_birthtime")):
            fbtime = fstatinfo.st_birthtime
        else:
            fbtime = fstatinfo.st_ctime
        fmode = fstatinfo.st_mode
        fchmode = stat.S_IMODE(fstatinfo.st_mode)
        ftypemod = stat.S_IFMT(fstatinfo.st_mode)
        fuid = fstatinfo.st_uid
        fgid = fstatinfo.st_gid
        funame = ""
        try:
            import pwd
            try:
                userinfo = pwd.getpwuid(fstatinfo.st_uid)
                funame = userinfo.pw_name
            except KeyError:
                funame = ""
        except ImportError:
            funame = ""
        fgname = ""
        try:
            import grp
            try:
                groupinfo = grp.getgrgid(fstatinfo.st_gid)
                fgname = groupinfo.gr_name
            except KeyError:
                fgname = ""
        except ImportError:
            fgname = ""
        if(hasattr(fstatinfo, "st_file_attributes")):
            fwinattributes = fstatinfo.st_file_attributes
        else:
            fwinattributes = 0
        fcompression = ""
        fcsize = 0
        fcontents = BytesIO()
        if ftype in data_types:
            with open(fname, "rb") as fpc:
                shutil.copyfileobj(fpc, fcontents)
            fcsize = fcontents.tell()
        if(followlink and (ftype == 1 or ftype == 2)):
            flstatinfo = os.stat(flinkname)
            with open(flinkname, "rb") as fpc:
                shutil.copyfileobj(fpc, fcontents)
            fcsize = fcontents.tell()
        fcontents.seek(0, 0)
        ftypehex = format(ftype, 'x').lower()
        extrafields = len(extradata)
        extrafieldslist = extradata
        catfextrafields = extrafields
        extrasizestr = AppendNullByte(
            extrafields, formatspecs['format_delimiter'])
        if(len(extradata) > 0):
            extrasizestr = extrasizestr + \
                AppendNullBytes(extradata, formatspecs['format_delimiter'])
        extrasizelen = len(extrasizestr)
        extrasizelenhex = format(extrasizelen, 'x').lower()
        catoutlist = [ftypehex, fencoding, fname, flinkname, format(int(fsize), 'x').lower(), format(int(fatime), 'x').lower(), format(int(fmtime), 'x').lower(), format(int(fctime), 'x').lower(), format(int(fbtime), 'x').lower(), format(int(fmode), 'x').lower(), format(int(fwinattributes), 'x').lower(), fcompression, format(int(fcsize), 'x').lower(), format(int(fuid), 'x').lower(
        ), funame, format(int(fgid), 'x').lower(), fgname, format(int(fcurfid), 'x').lower(), fcurinode, format(int(flinkcount), 'x').lower(), format(int(fdev), 'x').lower(), format(int(fdev_minor), 'x').lower(), format(int(fdev_major), 'x').lower(), "+"+str(len(formatspecs['format_delimiter'])), extrasizelenhex, format(catfextrafields, 'x').lower()]
        catoutlen = len(catoutlist) + len(extradata) + 3
        catoutlenhex = format(catoutlen, 'x').lower()
        catoutlist.insert(0, catoutlenhex)
        catfileoutstr = AppendNullBytes(
            catoutlist, formatspecs['format_delimiter'])
        catheaderdata = catoutlist
        if(len(extradata) > 0):
            catfileoutstr = catfileoutstr + \
                AppendNullBytes(extradata, formatspecs['format_delimiter'])
        if(fsize == 0):
            checksumlist = [checksumtype[1], "none"]
        else:
            checksumlist = [checksumtype[1], checksumtype[2]]
        catfileoutstr = catfileoutstr + \
            AppendNullBytes(checksumlist, formatspecs['format_delimiter'])
        catfnumfields = catoutlen
        catfileheadercshex = GetFileChecksum(
            catfileoutstr, checksumtype[1], True, formatspecs)
        fcontents.seek(0, 0)
        if(fsize == 0):
            catfilecontentcshex = GetFileChecksum(
                fcontents.read(), "none", False, formatspecs)
        else:
            catfilecontentcshex = GetFileChecksum(
                fcontents.read(), checksumtype[2], False, formatspecs)
        tmpfileoutstr = catfileoutstr + \
            AppendNullBytes([catfileheadercshex, catfilecontentcshex],
                            formatspecs['format_delimiter'])
        catheaersize = format(int(len(tmpfileoutstr) - len(formatspecs['format_delimiter'])), 'x').lower()
        catfileoutstr = AppendNullByte(
            catheaersize, formatspecs['format_delimiter']) + catfileoutstr
        catfileheadercshex = GetFileChecksum(
            catfileoutstr, checksumtype[1], True, formatspecs)
        catfileoutstr = catfileoutstr + \
            AppendNullBytes([catfileheadercshex, catfilecontentcshex],
                            formatspecs['format_delimiter'])
        catfileoutstrecd = catfileoutstr.encode('UTF-8')
        nullstrecd = formatspecs['format_delimiter'].encode('UTF-8')
        catfcontentstart = fheadtell
        fheadtell += len(catfileoutstr) + 1
        catfcontentend = fheadtell - 1
        catfhend = catfcontentend
        fcontents.seek(0, 0)
        catfileout = catfileoutstrecd + fcontents.read() + nullstrecd
        pyhascontents = False
        if(int(fsize) > 0 and not listonly):
            pyhascontents = True
        if(int(fsize) > 0 and listonly):
            fcontents = BytesIO()
            pyhascontents = False
        fcontents.seek(0, 0)
        if(not contentasfile):
            fcontents = fcontents.read()
        catlist['ffilelist'].append({'fid': fileidnum, 'fidalt': fileidnum, 'fheadersize': int(catheaersize, 16), 'fhstart': catfhstart, 'fhend': catfhend, 'ftype': ftype, 'fencoding': fencoding, 'fname': fname, 'fbasedir': fbasedir, 'flinkname': flinkname, 'fsize': fsize, 'fatime': fatime, 'fmtime': fmtime, 'fctime': fctime, 'fbtime': fbtime, 'fmode': fmode, 'fchmode': fchmode, 'ftypemod': ftypemod, 'fwinattributes': fwinattributes, 'fcompression': fcompression, 'fcsize': fcsize, 'fuid': fuid, 'funame': funame, 'fgid': fgid, 'fgname': fgname, 'finode': finode, 'flinkcount': flinkcount,
                                     'fdev': fdev, 'fminor': fdev_minor, 'fmajor': fdev_major, 'fseeknextfile': "+"+str(len(formatspecs['format_delimiter'])), 'fheaderchecksumtype': checksumtype[1], 'fcontentchecksumtype': checksumtype[2], 'fnumfields': catfnumfields + 2, 'frawheader': catheaderdata, 'fextrafields': catfextrafields, 'fextrafieldsize': extrasizelen, 'fextralist': extrafieldslist, 'fheaderchecksum': int(catfileheadercshex, 16), 'fcontentchecksum': int(catfilecontentcshex, 16), 'fhascontents': pyhascontents, 'fcontentstart': catfcontentstart, 'fcontentend': catfcontentend, 'fcontentasfile': contentasfile, 'fcontents': fcontents})
        fileidnum = fileidnum + 1
    return catlist


def TarFileToArrayAlt(infile, listonly=False, contentasfile=True, checksumtype=["crc32", "crc32", "crc32"], extradata=[], formatspecs=__file_format_dict__, verbose=False):
    curinode = 0
    curfid = 0
    inodelist = []
    inodetofile = {}
    filetoinode = {}
    inodetocatinode = {}
    fileidnum = 0
    if(infile == "-"):
        infile = BytesIO()
        if(hasattr(sys.stdin, "buffer")):
            shutil.copyfileobj(sys.stdin.buffer, infile)
        else:
            shutil.copyfileobj(sys.stdin, infile)
        infile.seek(0, 0)
        if(not infile):
            return False
        infile.seek(0, 0)
    elif(re.findall("^(http|https|ftp|ftps|sftp):\\/\\/", infile)):
        infile = download_file_from_internet_file(infile)
        infile.seek(0, 0)
        if(not infile):
            return False
        infile.seek(0, 0)
    elif(hasattr(infile, "read") or hasattr(infile, "write")):
        try:
            if(not tarfile.is_tarfile(infile)):
                return False
        except AttributeError:
            if(not TarFileCheck(infile)):
                return False
    elif(not os.path.exists(infile) or not os.path.isfile(infile)):
        return False
    elif(os.path.exists(infile) and os.path.isfile(infile)):
        try:
            if(not tarfile.is_tarfile(infile)):
                return False
        except AttributeError:
            if(not TarFileCheck(infile)):
                return False
    try:
        if(hasattr(infile, "read") or hasattr(infile, "write")):
            compresscheck = CheckCompressionType(infile, formatspecs, False)
            if(compresscheck=="zstd"):
                if 'zstandard' in sys.modules:
                    infile = ZstdFile(fileobj=infile, mode="rb")
                elif 'pyzstd' in sys.modules:
                    infile = pyzstd.zstdfile.ZstdFile(fileobj=infile, mode="rb")
                tarfp = tarfile.open(fileobj=infile, mode="r")
            else:
                tarfp = tarfile.open(fileobj=infile, mode="r")
        else:
            compresscheck = CheckCompressionType(infile, formatspecs, True)
            if(compresscheck=="zstd"):
                if 'zstandard' in sys.modules:
                    infile = ZstdFile(fileobj=infile, mode="rb")
                elif 'pyzstd' in sys.modules:
                    infile = pyzstd.zstdfile.ZstdFile(fileobj=infile, mode="rb")
                tarfp = tarfile.open(fileobj=infile, mode="r")
            else:
                tarfp = tarfile.open(infile, "r")
    except FileNotFoundError:
        return False
    fnumfiles = int(len(tarfp.getmembers()))
    catver = formatspecs['format_ver']
    fileheaderver = str(int(catver.replace(".", "")))
    fileheader = AppendNullByte(
        formatspecs['format_magic'] + fileheaderver, formatspecs['format_delimiter'])
    fnumfileshex = format(int(fnumfiles), 'x').lower()
    fostype = platform.system()
    fhencoding = "UTF-8"
    tmpcatfile = BytesIO()
    AppendFileHeader(tmpcatfile, fnumfiles, fhencoding, [], checksumtype[0], formatspecs)
    tmpcatfile.seek(0, 0)
    catheaderver = str(int(formatspecs['format_ver'].replace(".", "")))
    catstring = tmpcatfile.read(formatspecs['format_len'] + len(catheaderver)).decode("UTF-8")
    catdelszie = len(formatspecs['format_delimiter'])
    catdel = tmpcatfile.read(catdelszie).decode("UTF-8")
    if(catstring != formatspecs['format_magic']+catheaderver):
        return False
    if(catdel != formatspecs['format_delimiter']):
        return False
    if(formatspecs['new_style']):
        catheader = ReadFileHeaderDataBySize(
            tmpcatfile, formatspecs['format_delimiter'])
    else:
        catheader = ReadFileHeaderDataWoSize(
            tmpcatfile, formatspecs['format_delimiter'])
    fnumextrafieldsize = int(catheader[5], 16)
    fnumextrafields = int(catheader[6], 16)
    fextrafieldslist = []
    extrastart = 7
    extraend = extrastart + fnumextrafields
    extrafieldslist = []
    if(extrastart < extraend):
        fextrafieldslist.append(catheader[extrastart])
        extrastart = extrastart + 1
    catversion = re.findall("([\\d]+)", catstring)
    fheadsize = int(catheader[0], 16)
    fnumfields = int(catheader[1], 16)
    fhencoding = catheader[2]
    fostype = catheader[3]
    fnumfiles = int(catheader[4], 16)
    fprechecksumtype = catheader[-2]
    fprechecksum = catheader[-1]
    headercheck = ValidateHeaderChecksum([catstring] + catheader[:-1], fprechecksumtype, fprechecksum, formatspecs)
    newfcs = GetHeaderChecksum([catstring] + catheader[:-1], fprechecksumtype, True, formatspecs)
    if(not headercheck):
        return False
    fileheader = tmpcatfile.read()
    tmpcatfile.close()
    catversions = re.search('(.*?)(\\d+)', catstring).groups()
    catfileheadercshex = GetFileChecksum(
        fileheader, checksumtype[0], False, formatspecs)
    fheadtell = len(fileheader)
    catlist = {'fnumfiles': fnumfiles, 'fformat': catversions[0], 'fcompression': "", 'fencoding': fhencoding, 'fversion': catversions[1], 'fostype': fostype,
               'fformatspecs': formatspecs, 'fchecksumtype': checksumtype[0], 'fheaderchecksum': catfileheadercshex, 'frawheader': [catstring] + catheader, 'ffilelist': []}
    for member in sorted(tarfp.getmembers(), key=lambda x: x.name):
        catfhstart = fheadtell
        fencoding = "UTF-8"
        if(re.findall("^[.|/]", member.name)):
            fname = member.name
        else:
            fname = "./"+member.name
        if(verbose):
            VerbosePrintOut(fname)
        fpremode = member.mode
        ffullmode = member.mode
        flinkcount = 0
        ftype = 0
        if(member.isreg()):
            ffullmode = member.mode + stat.S_IFREG
            ftype = 0
        elif(member.islnk()):
            ffullmode = member.mode + stat.S_IFREG
            ftype = 1
        elif(member.issym()):
            ffullmode = member.mode + stat.S_IFLNK
            ftype = 2
        elif(member.ischr()):
            ffullmode = member.mode + stat.S_IFCHR
            ftype = 3
        elif(member.isblk()):
            ffullmode = member.mode + stat.S_IFBLK
            ftype = 4
        elif(member.isdir()):
            ffullmode = member.mode + stat.S_IFDIR
            ftype = 5
        elif(member.isfifo()):
            ffullmode = member.mode + stat.S_IFIFO
            ftype = 6
        elif(hasattr(member, "issparse") and member.issparse()):
            ffullmode = member.mode
            ftype = 12
        elif(member.isdev()):
            ffullmode = member.mode
            ftype = 14
        else:
            ffullmode = member.mode
            ftype = 0
        flinkname = ""
        fbasedir = os.path.dirname(fname)
        fcurfid = curfid
        fcurinode = curfid
        finode = fcurinode
        curfid = curfid + 1
        if(ftype == 2):
            flinkname = member.linkname
        try:
            fdev = os.makedev(member.devmajor, member.devminor)
        except AttributeError:
            fdev = MakeDevAlt(member.devmajor, member.devminor)
        fdev_minor = member.devminor
        fdev_major = member.devmajor
        # Types that should be considered zero-length in the archive context:
        zero_length_types = {1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 13}
        # Types that have actual data to read:
        data_types = {0, 7, 12}
        if ftype in zero_length_types:
            fsize = "0"
        elif ftype in data_types:
            fsize = member.size
        else:
            fsize = member.size
        fatime = member.mtime
        fmtime = member.mtime
        fctime = member.mtime
        fbtime = member.mtime
        fmode = ffullmode
        fchmode = stat.S_IMODE(ffullmode)
        ftypemod = stat.S_IFMT(ffullmode)
        fuid = member.uid
        fgid = member.gid
        funame = member.uname
        fgname = member.gname
        flinkcount = flinkcount
        fwinattributes = int(0)
        fcompression = ""
        fcsize = 0
        fcontents = BytesIO()
        if ftype in data_types:
            fpc = tarfp.extractfile(member)
            shutil.copyfileobj(fpc, fcontents)
            fcsize = fcontents.tell()
        fcontents.seek(0, 0)
        ftypehex = format(ftype, 'x').lower()
        extrafields = len(extradata)
        extrafieldslist = extradata
        catfextrafields = extrafields
        extrasizestr = AppendNullByte(
            extrafields, formatspecs['format_delimiter'])
        if(len(extradata) > 0):
            extrasizestr = extrasizestr + \
                AppendNullBytes(extradata, formatspecs['format_delimiter'])
        extrasizelen = len(extrasizestr)
        extrasizelenhex = format(extrasizelen, 'x').lower()
        catoutlist = [ftypehex, fencoding, fname, flinkname, format(int(fsize), 'x').lower(), format(int(fatime), 'x').lower(), format(int(fmtime), 'x').lower(), format(int(fctime), 'x').lower(), format(int(fbtime), 'x').lower(), format(int(fmode), 'x').lower(), format(int(fwinattributes), 'x').lower(), fcompression, format(int(fcsize), 'x').lower(), format(int(fuid), 'x').lower(
        ), funame, format(int(fgid), 'x').lower(), fgname, format(int(fcurfid), 'x').lower(), format(int(fcurinode), 'x').lower(), format(int(flinkcount), 'x').lower(), format(int(fdev), 'x').lower(), format(int(fdev_minor), 'x').lower(), format(int(fdev_major), 'x').lower(), "+"+str(len(formatspecs['format_delimiter'])), extrasizelenhex, format(catfextrafields, 'x').lower()]
        catoutlen = len(catoutlist) + len(extradata) + 3
        catoutlenhex = format(catoutlen, 'x').lower()
        catoutlist.insert(0, catoutlenhex)
        catfileoutstr = AppendNullBytes(
            catoutlist, formatspecs['format_delimiter'])
        catheaderdata = catoutlist
        if(len(extradata) > 0):
            catfileoutstr = catfileoutstr + \
                AppendNullBytes(extradata, formatspecs['format_delimiter'])
        if(fsize == 0):
            checksumlist = [checksumtype[1], "none"]
        else:
            checksumlist = [checksumtype[1], checksumtype[2]]
        catfileoutstr = catfileoutstr + \
            AppendNullBytes(checksumlist, formatspecs['format_delimiter'])
        catfnumfields = catoutlen
        catfileheadercshex = GetFileChecksum(
            catfileoutstr, checksumtype[1], True, formatspecs)
        fcontents.seek(0, 0)
        if(fsize == 0):
            catfilecontentcshex = GetFileChecksum(
                fcontents.read(), "none", False, formatspecs)
        else:
            catfilecontentcshex = GetFileChecksum(
                fcontents.read(), checksumtype[2], False, formatspecs)
        tmpfileoutstr = catfileoutstr + \
            AppendNullBytes([catfileheadercshex, catfilecontentcshex],
                            formatspecs['format_delimiter'])
        catheaersize = format(int(len(tmpfileoutstr) - len(formatspecs['format_delimiter'])), 'x').lower()
        catfileoutstr = AppendNullByte(
            catheaersize, formatspecs['format_delimiter']) + catfileoutstr
        catfileheadercshex = GetFileChecksum(
            catfileoutstr, checksumtype[1], True, formatspecs)
        catfileoutstr = catfileoutstr + \
            AppendNullBytes([catfileheadercshex, catfilecontentcshex],
                            formatspecs['format_delimiter'])
        catfileoutstrecd = catfileoutstr.encode('UTF-8')
        nullstrecd = formatspecs['format_delimiter'].encode('UTF-8')
        catfcontentstart = fheadtell
        fheadtell += len(catfileoutstr) + 1
        catfcontentend = fheadtell - 1
        catfhend = catfcontentend
        fcontents.seek(0, 0)
        catfileout = catfileoutstrecd + fcontents.read() + nullstrecd
        pyhascontents = False
        if(int(fsize) > 0 and not listonly):
            pyhascontents = True
        if(int(fsize) > 0 and listonly):
            fcontents = BytesIO()
            pyhascontents = False
        fcontents.seek(0, 0)
        if(not contentasfile):
            fcontents = fcontents.read()
        catlist['ffilelist'].append({'fid': fileidnum, 'fidalt': fileidnum, 'fheadersize': int(catheaersize, 16), 'fhstart': catfhstart, 'fhend': catfhend, 'ftype': ftype, 'fencoding': fencoding, 'fname': fname, 'fbasedir': fbasedir, 'flinkname': flinkname, 'fsize': fsize, 'fatime': fatime, 'fmtime': fmtime, 'fctime': fctime, 'fbtime': fbtime, 'fmode': fmode, 'fchmode': fchmode, 'ftypemod': ftypemod, 'fwinattributes': fwinattributes, 'fcompression': fcompression, 'fcsize': fcsize, 'fuid': fuid, 'funame': funame, 'fgid': fgid, 'fgname': fgname, 'finode': finode, 'flinkcount': flinkcount,
                                    'fdev': fdev, 'fminor': fdev_minor, 'fmajor': fdev_major, 'fseeknextfile': "+"+str(len(formatspecs['format_delimiter'])), 'fheaderchecksumtype': checksumtype[1], 'fcontentchecksumtype': checksumtype[2], 'fnumfields': catfnumfields + 2, 'frawheader': catheaderdata, 'fextrafields': catfextrafields, 'fextrafieldsize': extrasizelen, 'fextralist': extrafieldslist, 'fheaderchecksum': int(catfileheadercshex, 16), 'fcontentchecksum': int(catfilecontentcshex, 16), 'fhascontents': pyhascontents, 'fcontentstart': catfcontentstart, 'fcontentend': catfcontentend, 'fcontentasfile': contentasfile, 'fcontents': fcontents})
        fileidnum = fileidnum + 1
    return catlist


def ZipFileToArrayAlt(infile, listonly=False, contentasfile=True, checksumtype=["crc32", "crc32", "crc32"], extradata=[], formatspecs=__file_format_dict__, verbose=False):
    curinode = 0
    curfid = 0
    inodelist = []
    inodetofile = {}
    filetoinode = {}
    inodetocatinode = {}
    fileidnum = 0
    if(infile == "-"):
        infile = BytesIO()
        if(hasattr(sys.stdin, "buffer")):
            shutil.copyfileobj(sys.stdin.buffer, infile)
        else:
            shutil.copyfileobj(sys.stdin, infile)
        infile.seek(0, 0)
        if(not infile):
            return False
        infile.seek(0, 0)
    elif(re.findall("^(http|https|ftp|ftps|sftp):\\/\\/", infile)):
        infile = download_file_from_internet_file(infile)
        infile.seek(0, 0)
        if(not infile):
            return False
        infile.seek(0, 0)
    elif(hasattr(infile, "read") or hasattr(infile, "write")):
        pass
    elif(not os.path.exists(infile) or not os.path.isfile(infile)):
        return False
    if(not zipfile.is_zipfile(infile)):
        return False
    try:
        zipfp = zipfile.ZipFile(infile, "r", allowZip64=True)
    except FileNotFoundError:
        return False
    ziptest = zipfp.testzip()
    if(ziptest):
        VerbosePrintOut("Bad file found!")
    fnumfiles = int(len(zipfp.infolist()))
    catver = formatspecs['format_ver']
    fileheaderver = str(int(catver.replace(".", "")))
    fileheader = AppendNullByte(
        formatspecs['format_magic'] + fileheaderver, formatspecs['format_delimiter'])
    catversion = re.findall("([\\d]+)", fileheader)
    catversions = re.search('(.*?)(\\d+)', fileheader).groups()
    fnumfileshex = format(int(fnumfiles), 'x').lower()
    fostype = platform.system()
    fhencoding = "UTF-8"
    tmpcatfile = BytesIO()
    AppendFileHeader(tmpcatfile, fnumfiles, fhencoding, [], checksumtype[0], formatspecs)
    tmpcatfile.seek(0, 0)
    catheaderver = str(int(formatspecs['format_ver'].replace(".", "")))
    catstring = tmpcatfile.read(formatspecs['format_len'] + len(catheaderver)).decode("UTF-8")
    catdelszie = len(formatspecs['format_delimiter'])
    catdel = tmpcatfile.read(catdelszie).decode("UTF-8")
    if(catstring != formatspecs['format_magic']+catheaderver):
        return False
    if(catdel != formatspecs['format_delimiter']):
        return False
    if(formatspecs['new_style']):
        catheader = ReadFileHeaderDataBySize(
            tmpcatfile, formatspecs['format_delimiter'])
    else:
        catheader = ReadFileHeaderDataWoSize(
            tmpcatfile, formatspecs['format_delimiter'])
    fnumextrafieldsize = int(catheader[5], 16)
    fnumextrafields = int(catheader[6], 16)
    fextrafieldslist = []
    extrastart = 7
    extraend = extrastart + fnumextrafields
    extrafieldslist = []
    if(extrastart < extraend):
        fextrafieldslist.append(catheader[extrastart])
        extrastart = extrastart + 1
    catversion = re.findall("([\\d]+)", catstring)
    fheadsize = int(catheader[0], 16)
    fnumfields = int(catheader[1], 16)
    fhencoding = catheader[2]
    fostype = catheader[3]
    fnumfiles = int(catheader[4], 16)
    fprechecksumtype = catheader[-2]
    fprechecksum = catheader[-1]
    headercheck = ValidateHeaderChecksum([catstring] + catheader[:-1], fprechecksumtype, fprechecksum, formatspecs)
    newfcs = GetHeaderChecksum([catstring] + catheader[:-1], fprechecksumtype, True, formatspecs)
    if(not headercheck):
        return False
    fileheader = tmpcatfile.read()
    tmpcatfile.close()
    catversions = re.search('(.*?)(\\d+)', catstring).groups()
    catfileheadercshex = GetFileChecksum(
        fileheader, checksumtype[0], False, formatspecs)
    fheadtell = len(fileheader)
    catlist = {'fnumfiles': fnumfiles, 'fformat': catversions[0], 'fcompression': "", 'fencoding': fhencoding, 'fversion': catversions[1], 'fostype': fostype,
               'fformatspecs': formatspecs, 'fchecksumtype': checksumtype[0], 'fheaderchecksum': catfileheadercshex, 'frawheader': [catstring] + catheader, 'ffilelist': []}
    for member in sorted(zipfp.infolist(), key=lambda x: x.filename):
        catfhstart = fheadtell
        fencoding = "UTF-8"
        if(re.findall("^[.|/]", member.filename)):
            fname = member.filename
        else:
            fname = "./"+member.filename
        zipinfo = zipfp.getinfo(member.filename)
        if(verbose):
            VerbosePrintOut(fname)
        if ((hasattr(member, "is_dir") and member.is_dir()) or member.filename.endswith('/')):
            fpremode = stat.S_IFDIR + 511
        else:
            fpremode = stat.S_IFREG + 438
        flinkcount = 0
        ftype = 0
        if ((hasattr(member, "is_dir") and member.is_dir()) or member.filename.endswith('/')):
            ftype = 5
        else:
            ftype = 0
        flinkname = ""
        fbasedir = os.path.dirname(fname)
        fcurfid = curfid
        fcurinode = curfid
        finode = fcurinode
        curfid = curfid + 1
        fdev = 0
        fdev_minor = 0
        fdev_major = 0
        if(ftype == 5):
            fsize = "0"
        elif(ftype == 0):
            fsize = member.file_size
        else:
            fsize = member.file_size
        fatime = time.mktime(member.date_time + (0, 0, -1))
        fmtime = time.mktime(member.date_time + (0, 0, -1))
        fctime = time.mktime(member.date_time + (0, 0, -1))
        fbtime = time.mktime(member.date_time + (0, 0, -1))
        if(zipinfo.create_system == 0 or zipinfo.create_system == 10):
            fwinattributes = int(zipinfo.external_attr)
            if ((hasattr(member, "is_dir") and member.is_dir()) or member.filename.endswith('/')):
                fmode = int(stat.S_IFDIR + 511)
                fchmode = int(stat.S_IMODE(int(stat.S_IFDIR + 511)))
                ftypemod = int(stat.S_IFMT(int(stat.S_IFDIR + 511)))
            else:
                fmode = int(stat.S_IFREG + 438)
                fchmode = int(stat.S_IMODE(int(stat.S_IFREG + 438)))
                ftypemod = int(stat.S_IFMT(int(stat.S_IFREG + 438)))
        elif(zipinfo.create_system == 3):
            fwinattributes = int(0)
            try:
                fmode = int(zipinfo.external_attr)
                fchmode = stat.S_IMODE(fmode)
                ftypemod = stat.S_IFMT(fmode)
            except OverflowError:
                fmode = int(zipinfo.external_attr >> 16)
                fchmode = stat.S_IMODE(fmode)
                ftypemod = stat.S_IFMT(fmode)
        else:
            fwinattributes = int(0)
            if ((hasattr(member, "is_dir") and member.is_dir()) or member.filename.endswith('/')):
                fmode = int(stat.S_IFDIR + 511)
                fchmode = int(stat.S_IMODE(int(stat.S_IFDIR + 511)))
                ftypemod = int(stat.S_IFMT(int(stat.S_IFDIR + 511)))
            else:
                fmode = int(stat.S_IFREG + 438)
                fchmode = int(stat.S_IMODE(int(stat.S_IFREG + 438)))
                ftypemod = int(stat.S_IFMT(int(stat.S_IFREG + 438)))
        fcompression = ""
        fcsize = 0
        try:
            fuid = os.getuid()
        except AttributeError:
            fuid = 0
        except KeyError:
            fuid = 0
        try:
            fgid = os.getgid()
        except AttributeError:
            fgid = 0
        except KeyError:
            fgid = 0
        try:
            import pwd
            try:
                userinfo = pwd.getpwuid(os.getuid())
                funame = userinfo.pw_name
            except KeyError:
                funame = ""
            except AttributeError:
                funame = ""
        except ImportError:
            funame = ""
        fgname = ""
        try:
            import grp
            try:
                groupinfo = grp.getgrgid(os.getgid())
                fgname = groupinfo.gr_name
            except KeyError:
                fgname = ""
            except AttributeError:
                fgname = ""
        except ImportError:
            fgname = ""
        fcontents = BytesIO()
        if(ftype == 0):
            fcontents.write(zipfp.read(member.filename))
            fcsize = fcontents.tell()
        fcontents.seek(0, 0)
        ftypehex = format(ftype, 'x').lower()
        extrafields = len(extradata)
        extrafieldslist = extradata
        catfextrafields = extrafields
        extrasizestr = AppendNullByte(
            extrafields, formatspecs['format_delimiter'])
        if(len(extradata) > 0):
            extrasizestr = extrasizestr + \
                AppendNullBytes(extradata, formatspecs['format_delimiter'])
        extrasizelen = len(extrasizestr)
        extrasizelenhex = format(extrasizelen, 'x').lower()
        catoutlist = [ftypehex, fencoding, fname, flinkname, format(int(fsize), 'x').lower(), format(int(fatime), 'x').lower(), format(int(fmtime), 'x').lower(), format(int(fctime), 'x').lower(), format(int(fbtime), 'x').lower(), format(int(fmode), 'x').lower(), format(int(fwinattributes), 'x').lower(), fcompression, format(int(fcsize), 'x').lower(), format(int(fuid), 'x').lower(
        ), funame, format(int(fgid), 'x').lower(), fgname, format(int(fcurfid), 'x').lower(), format(int(fcurinode), 'x').lower(), format(int(flinkcount), 'x').lower(), format(int(fdev), 'x').lower(), format(int(fdev_minor), 'x').lower(), format(int(fdev_major), 'x').lower(), "+"+str(len(formatspecs['format_delimiter'])), extrasizelenhex, format(catfextrafields, 'x').lower()]
        catoutlen = len(catoutlist) + len(extradata) + 3
        catoutlenhex = format(catoutlen, 'x').lower()
        catoutlist.insert(0, catoutlenhex)
        catfileoutstr = AppendNullBytes(
            catoutlist, formatspecs['format_delimiter'])
        catheaderdata = catoutlist
        if(len(extradata) > 0):
            catfileoutstr = catfileoutstr + \
                AppendNullBytes(extradata, formatspecs['format_delimiter'])
        if(fsize == 0):
            checksumlist = [checksumtype[1], "none"]
        else:
            checksumlist = [checksumtype[1], checksumtype[2]]
        catfileoutstr = catfileoutstr + \
            AppendNullBytes(checksumlist, formatspecs['format_delimiter'])
        catfnumfields = catoutlen
        catfileheadercshex = GetFileChecksum(
            catfileoutstr, checksumtype[1], True, formatspecs)
        fcontents.seek(0, 0)
        if(fsize == 0):
            catfilecontentcshex = GetFileChecksum(
                fcontents.read(), "none", False, formatspecs)
        else:
            catfilecontentcshex = GetFileChecksum(
                fcontents.read(), checksumtype[2], False, formatspecs)
        tmpfileoutstr = catfileoutstr + \
            AppendNullBytes([catfileheadercshex, catfilecontentcshex],
                            formatspecs['format_delimiter'])
        catheaersize = format(int(len(tmpfileoutstr) - len(formatspecs['format_delimiter'])), 'x').lower()
        catfileoutstr = AppendNullByte(
            catheaersize, formatspecs['format_delimiter']) + catfileoutstr
        catfileheadercshex = GetFileChecksum(
            catfileoutstr, checksumtype[1], True, formatspecs)
        catfileoutstr = catfileoutstr + \
            AppendNullBytes([catfileheadercshex, catfilecontentcshex],
                            formatspecs['format_delimiter'])
        catfileoutstrecd = catfileoutstr.encode('UTF-8')
        nullstrecd = formatspecs['format_delimiter'].encode('UTF-8')
        catfcontentstart = fheadtell
        fheadtell += len(catfileoutstr) + 1
        catfcontentend = fheadtell - 1
        catfhend = catfcontentend
        fcontents.seek(0, 0)
        catfileout = catfileoutstrecd + fcontents.read() + nullstrecd
        pyhascontents = False
        if(int(fsize) > 0 and not listonly):
            pyhascontents = True
        if(int(fsize) > 0 and listonly):
            fcontents = BytesIO()
            pyhascontents = False
        fcontents.seek(0, 0)
        if(not contentasfile):
            fcontents = fcontents.read()
        catlist['ffilelist'].append({'fid': fileidnum, 'fidalt': fileidnum, 'fheadersize': int(catheaersize, 16), 'fhstart': catfhstart, 'fhend': catfhend, 'ftype': ftype, 'fencoding': fencoding, 'fname': fname, 'fbasedir': fbasedir, 'flinkname': flinkname, 'fsize': fsize, 'fatime': fatime, 'fmtime': fmtime, 'fctime': fctime, 'fbtime': fbtime, 'fmode': fmode, 'fchmode': fchmode, 'ftypemod': ftypemod, 'fwinattributes': fwinattributes, 'fcompression': fcompression, 'fcsize': fcsize, 'fuid': fuid, 'funame': funame, 'fgid': fgid, 'fgname': fgname, 'finode': finode, 'flinkcount': flinkcount,
                                    'fdev': fdev, 'fminor': fdev_minor, 'fmajor': fdev_major, 'fseeknextfile': "+"+str(len(formatspecs['format_delimiter'])), 'fheaderchecksumtype': checksumtype[1], 'fcontentchecksumtype': checksumtype[2], 'fnumfields': catfnumfields + 2, 'frawheader': catheaderdata, 'fextrafields': catfextrafields, 'fextrafieldsize': extrasizelen, 'fextralist': extrafieldslist, 'fheaderchecksum': int(catfileheadercshex, 16), 'fcontentchecksum': int(catfilecontentcshex, 16), 'fhascontents': pyhascontents, 'fcontentstart': catfcontentstart, 'fcontentend': catfcontentend, 'fcontentasfile': contentasfile, 'fcontents': fcontents})
        fileidnum = fileidnum + 1
    return catlist


if(not rarfile_support):
    def RarFileToArrayAlt(infile, listonly=False, contentasfile=True, checksumtype=["crc32", "crc32", "crc32"], extradata=[], formatspecs=__file_format_dict__, verbose=False):
        return False

if(rarfile_support):
    def RarFileToArrayAlt(infile, listonly=False, contentasfile=True, checksumtype=["crc32", "crc32", "crc32"], extradata=[], formatspecs=__file_format_dict__, verbose=False):
        curinode = 0
        curfid = 0
        inodelist = []
        inodetofile = {}
        filetoinode = {}
        inodetocatinode = {}
        fileidnum = 0
        if(not os.path.exists(infile,) or not os.path.isfile(infile,)):
            return False
        if(not rarfile.is_rarfile(infile) and not rarfile.is_rarfile_sfx(infile)):
            return False
        rarfp = rarfile.RarFile(infile, "r")
        rartest = rarfp.testrar()
        if(rartest):
            VerbosePrintOut("Bad file found!")
        fnumfiles = int(len(rarfp.infolist()))
        catver = formatspecs['format_ver']
        fileheaderver = str(int(catver.replace(".", "")))
        fileheader = AppendNullByte(
            formatspecs['format_magic'] + fileheaderver, formatspecs['format_delimiter'])
        catversions = re.search('(.*?)(\\d+)', catstring).groups()
        fnumfileshex = format(int(fnumfiles), 'x').lower()
        fostype = platform.system()
        fhencoding = "UTF-8"
        tmpcatfile = BytesIO()
        AppendFileHeader(tmpcatfile, fnumfiles, fhencoding, [], checksumtype[0], formatspecs)
        tmpcatfile.seek(0, 0)
        catheaderver = str(int(formatspecs['format_ver'].replace(".", "")))
        catstring = tmpcatfile.read(formatspecs['format_len'] + len(catheaderver)).decode("UTF-8")
        catdelszie = len(formatspecs['format_delimiter'])
        catdel = tmpcatfile.read(catdelszie).decode("UTF-8")
        if(catstring != formatspecs['format_magic']+catheaderver):
            return False
        if(catdel != formatspecs['format_delimiter']):
            return False
        if(formatspecs['new_style']):
            catheader = ReadFileHeaderDataBySize(
                tmpcatfile, formatspecs['format_delimiter'])
        else:
            catheader = ReadFileHeaderDataWoSize(
                tmpcatfile, formatspecs['format_delimiter'])
        fnumextrafieldsize = int(catheader[5], 16)
        fnumextrafields = int(catheader[6], 16)
        fextrafieldslist = []
        extrastart = 7
        extraend = extrastart + fnumextrafields
        extrafieldslist = []
        if(extrastart < extraend):
            fextrafieldslist.append(catheader[extrastart])
            extrastart = extrastart + 1
        catversion = re.findall("([\\d]+)", catstring)
        fheadsize = int(catheader[0], 16)
        fnumfields = int(catheader[1], 16)
        fhencoding = catheader[2]
        fostype = catheader[3]
        fnumfiles = int(catheader[4], 16)
        fprechecksumtype = catheader[-2]
        fprechecksum = catheader[-1]
        headercheck = ValidateHeaderChecksum([catstring] + catheader[:-1], fprechecksumtype, fprechecksum, formatspecs)
        newfcs = GetHeaderChecksum([catstring] + catheader[:-1], fprechecksumtype, True, formatspecs)
        if(not headercheck):
            return False
        fileheader = tmpcatfile.read()
        tmpcatfile.close()
        catversion = re.findall("([\\d]+)", fileheader)
        catversions = re.search('(.*?)(\\d+)', fileheader).groups()
        catfileheadercshex = GetFileChecksum(
            fileheader, checksumtype[0], False, formatspecs)
        fheadtell = len(fileheader)
        catlist = {'fnumfiles': fnumfiles, 'fformat': catversions[0], 'fcompression': "", 'fencoding': fhencoding, 'fversion': catversions[1], 'fostype': fostype,
                   'fformatspecs': formatspecs, 'fchecksumtype': checksumtype[0], 'fheaderchecksum': catfileheadercshex, 'frawheader': [catstring] + catheader, 'ffilelist': []}
        for member in sorted(rarfp.infolist(), key=lambda x: x.filename):
            catfhstart = fheadtell
            fencoding = "UTF-8"
            is_unix = False
            is_windows = False
            if(member.host_os == rarfile.RAR_OS_UNIX):
                is_windows = False
                try:
                    member.external_attr
                    is_unix = True
                except AttributeError:
                    is_unix = False
            elif(member.host_os == rarfile.RAR_OS_WIN32):
                is_unix = False
                try:
                    member.external_attr
                    is_windows = True
                except AttributeError:
                    is_windows = False
            else:
                is_unix = False
                is_windows = False
            if(re.findall("^[.|/]", member.filename)):
                fname = member.filename
            else:
                fname = "./"+member.filename
            rarinfo = rarfp.getinfo(member.filename)
            if(verbose):
                VerbosePrintOut(fname)
            if(is_unix and member.external_attr != 0):
                fpremode = int(member.external_attr)
            elif(member.is_file()):
                fpremode = stat.S_IFREG + 438
            elif(member.is_symlink()):
                fpremode = stat.S_IFLNK + 438
            elif(member.is_dir()):
                fpremode = stat.S_IFDIR + 511
            if(is_windows and member.external_attr != 0):
                fwinattributes = int(member.external_attr)
            else:
                fwinattributes = int(0)
            fcompression = ""
            fcsize = 0
            flinkcount = 0
            ftype = 0
            if(member.is_file()):
                ftype = 0
            elif(member.is_symlink()):
                ftype = 2
            elif(member.is_dir()):
                ftype = 5
            flinkname = ""
            if(ftype == 2):
                flinkname = rarfp.read(member.filename).decode("UTF-8")
            fbasedir = os.path.dirname(fname)
            fcurfid = curfid
            fcurinode = curfid
            finode = fcurinode
            curfid = curfid + 1
            fdev = 0
            fdev_minor = 0
            fdev_major = 0
            if(ftype == 5):
                fsize = "0"
            if(ftype == 0):
                fsize = member.file_size
            try:
                if(member.atime):
                    fatime = int(member.atime.timestamp())
                else:
                    fatime = int(member.mtime.timestamp())
            except AttributeError:
                fatime = int(member.mtime.timestamp())
            fmtime = int(member.mtime.timestamp())
            try:
                if(member.ctime):
                    fctime = int(member.ctime.timestamp())
                else:
                    fctime = int(member.mtime.timestamp())
            except AttributeError:
                fctime = int(member.mtime.timestamp())
            fbtime = int(member.mtime.timestamp())
            if(is_unix and member.external_attr != 0):
                fmode = int(member.external_attr)
                fchmode = int(stat.S_IMODE(member.external_attr))
                ftypemod = int(stat.S_IFMT(member.external_attr))
            elif(member.is_file()):
                fmode = int(stat.S_IFREG + 438)
                fchmode = int(stat.S_IMODE(stat.S_IFREG + 438))
                ftypemod = int(stat.S_IFMT(stat.S_IFREG + 438))
            elif(member.is_symlink()):
                fmode = int(stat.S_IFLNK + 438)
                fchmode = int(stat.S_IMODE(stat.S_IFREG + 438))
                ftypemod = int(stat.S_IFMT(stat.S_IFREG + 438))
            elif(member.is_dir()):
                fmode = int(stat.S_IFDIR + 511)
                fchmode = int(stat.S_IMODE(stat.S_IFDIR + 511))
                ftypemod = int(stat.S_IFMT(stat.S_IFDIR + 511))
            try:
                fuid = os.getuid()
            except AttributeError:
                fuid = 0
            except KeyError:
                fuid = 0
            try:
                fgid = os.getgid()
            except AttributeError:
                fgid = 0
            except KeyError:
                fgid = 0
            try:
                import pwd
                try:
                    userinfo = pwd.getpwuid(os.getuid())
                    funame = userinfo.pw_name
                except KeyError:
                    funame = ""
                except AttributeError:
                    funame = ""
            except ImportError:
                funame = ""
            fgname = ""
            try:
                import grp
                try:
                    groupinfo = grp.getgrgid(os.getgid())
                    fgname = groupinfo.gr_name
                except KeyError:
                    fgname = ""
                except AttributeError:
                    fgname = ""
            except ImportError:
                fgname = ""
            fcontents = BytesIO()
            if(ftype == 0):
                fcontents.write(rarfp.read(member.filename))
                fcsize = fcontents.tell()
            fcontents.seek(0, 0)
            ftypehex = format(ftype, 'x').lower()
            extrafields = len(extradata)
            extrafieldslist = extradata
            catfextrafields = extrafields
            extrasizestr = AppendNullByte(
                extrafields, formatspecs['format_delimiter'])
            if(len(extradata) > 0):
                extrasizestr = extrasizestr + \
                    AppendNullBytes(extradata, formatspecs['format_delimiter'])
            extrasizelen = len(extrasizestr)
            extrasizelenhex = format(extrasizelen, 'x').lower()
            catoutlist = [ftypehex, fencoding, fname, flinkname, format(int(fsize), 'x').lower(), format(int(fatime), 'x').lower(), format(int(fmtime), 'x').lower(), format(int(fctime), 'x').lower(), format(int(fbtime), 'x').lower(), format(int(fmode), 'x').lower(), format(int(fwinattributes), 'x').lower(), fcompression, format(int(fcsize), 'x').lower(), format(int(fuid), 'x').lower(
            ), funame, format(int(fgid), 'x').lower(), fgname, format(int(fcurfid), 'x').lower(), format(int(fcurinode), 'x').lower(), format(int(flinkcount), 'x').lower(), format(int(fdev), 'x').lower(), format(int(fdev_minor), 'x').lower(), format(int(fdev_major), 'x').lower(), "+"+str(len(formatspecs['format_delimiter'])), extrasizelenhex, format(catfextrafields, 'x').lower()]
            catoutlen = len(catoutlist) + len(extradata) + 3
            catoutlenhex = format(catoutlen, 'x').lower()
            catoutlist.insert(0, catoutlenhex)
            catfileoutstr = AppendNullBytes(
                catoutlist, formatspecs['format_delimiter'])
            if(len(extradata) > 0):
                catfileoutstr = catfileoutstr + \
                    AppendNullBytes(extradata, formatspecs['format_delimiter'])
            if(fsize == 0):
                checksumlist = [checksumtype[1], "none"]
            else:
                checksumlist = [checksumtype[1], checksumtype[2]]
            ccatfileoutstr = catfileoutstr + \
                AppendNullBytes(checksumlist, formatspecs['format_delimiter'])
            catfnumfields = 24 + catfextrafields
            catfileheadercshex = GetFileChecksum(
                catfileoutstr, checksumtype[1], True, formatspecs)
            fcontents.seek(0, 0)
            if(fsize == 0):
                catfilecontentcshex = GetFileChecksum(
                    fcontents.read(), "none", False, formatspecs)
            else:
                catfilecontentcshex = GetFileChecksum(
                    fcontents.read(), checksumtype[2], False, formatspecs)
            tmpfileoutstr = catfileoutstr + \
                AppendNullBytes(
                    [catfileheadercshex, catfilecontentcshex], formatspecs['format_delimiter'])
            catheaersize = format(int(len(tmpfileoutstr) - len(formatspecs['format_delimiter'])), 'x').lower()
            catfileoutstr = AppendNullByte(
                catheaersize, formatspecs['format_delimiter']) + catfileoutstr
            catfileheadercshex = GetFileChecksum(
                catfileoutstr, checksumtype[1], True, formatspecs)
            catfileoutstr = catfileoutstr + \
                AppendNullBytes(
                    [catfileheadercshex, catfilecontentcshex], formatspecs['format_delimiter'])
            catheaderdata = catoutlist
            catfileoutstrecd = catfileoutstr.encode('UTF-8')
            nullstrecd = formatspecs['format_delimiter'].encode('UTF-8')
            catfcontentstart = fheadtell
            fheadtell += len(catfileoutstr) + 1
            catfcontentend = fheadtell - 1
            catfhend = catfcontentend
            fcontents.seek(0, 0)
            catfileout = catfileoutstrecd + fcontents.read() + nullstrecd
            pyhascontents = False
            if(int(fsize) > 0 and not listonly):
                pyhascontents = True
            if(int(fsize) > 0 and listonly):
                fcontents = BytesIO()
                pyhascontents = False
            fcontents.seek(0, 0)
            if(not contentasfile):
                fcontents = fcontents.read()
            catlist['ffilelist'].append({'fid': fileidnum, 'fidalt': fileidnum, 'fheadersize': int(catheaersize, 16), 'fhstart': catfhstart, 'fhend': catfhend, 'ftype': ftype, 'fencoding': fencoding, 'fname': fname, 'fbasedir': fbasedir, 'flinkname': flinkname, 'fsize': fsize, 'fatime': fatime, 'fmtime': fmtime, 'fctime': fctime, 'fbtime': fbtime, 'fmode': fmode, 'fchmode': fchmode, 'ftypemod': ftypemod, 'fwinattributes': fwinattributes, 'fcompression': fcompression, 'fcsize': fcsize, 'fuid': fuid, 'funame': funame, 'fgid': fgid, 'fgname': fgname, 'finode': finode, 'flinkcount': flinkcount,
                                        'fdev': fdev, 'fminor': fdev_minor, 'fmajor': fdev_major, 'fseeknextfile': "+"+str(len(formatspecs['format_delimiter'])), 'fheaderchecksumtype': checksumtype[1], 'fcontentchecksumtype': checksumtype[2], 'fnumfields': catfnumfields + 2, 'frawheader': catheaderdata, 'fextrafields': catfextrafields, 'fextrafieldsize': extrasizelen, 'fextralist': extrafieldslist, 'fheaderchecksum': int(catfileheadercshex, 16), 'fcontentchecksum': int(catfilecontentcshex, 16), 'fhascontents': pyhascontents, 'fcontentstart': catfcontentstart, 'fcontentend': catfcontentend, 'fcontentasfile': contentasfile, 'fcontents': fcontents})
            fileidnum = fileidnum + 1
        return catlist

if(not py7zr_support):
    def SevenZipFileToArrayAlt(infile, listonly=False, contentasfile=True, checksumtype=["crc32", "crc32", "crc32"], extradata=[], formatspecs=__file_format_dict__, verbose=False):
        return False

if(py7zr_support):
    def SevenZipFileToArrayAlt(infile, listonly=False, contentasfile=True, checksumtype=["crc32", "crc32", "crc32"], extradata=[], formatspecs=__file_format_dict__, verbose=False):
        curinode = 0
        curfid = 0
        inodelist = []
        inodetofile = {}
        filetoinode = {}
        inodetocatinode = {}
        fileidnum = 0
        szpfp = py7zr.SevenZipFile(infile, mode="r")
        file_content = szpfp.readall()
        #sztest = szpfp.testzip();
        sztestalt = szpfp.test()
        if(sztestalt):
            VerbosePrintOut("Bad file found!")
        numfiles = int(len(szpfp.list()))
        catver = formatspecs['format_ver']
        fileheaderver = str(int(catver.replace(".", "")))
        fileheader = AppendNullByte(
            formatspecs['format_magic'] + fileheaderver, formatspecs['format_delimiter'])
        catversion = re.findall("([\\d]+)", fileheader)
        catversions = re.search('(.*?)(\\d+)', fileheader).groups()
        fnumfileshex = format(int(fnumfiles), 'x').lower()
        fostype = platform.system()
        fhencoding = "UTF-8"
        tmpcatfile = BytesIO()
        AppendFileHeader(tmpcatfile, fnumfiles, fhencoding, [], checksumtype[0], formatspecs)
        tmpcatfile.seek(0, 0)
        catheaderver = str(int(formatspecs['format_ver'].replace(".", "")))
        catstring = tmpcatfile.read(formatspecs['format_len'] + len(catheaderver)).decode("UTF-8")
        catdelszie = len(formatspecs['format_delimiter'])
        catdel = tmpcatfile.read(catdelszie).decode("UTF-8")
        if(catstring != formatspecs['format_magic']+catheaderver):
            return False
        if(catdel != formatspecs['format_delimiter']):
            return False
        if(formatspecs['new_style']):
            catheader = ReadFileHeaderDataBySize(
                tmpcatfile, formatspecs['format_delimiter'])
        else:
            catheader = ReadFileHeaderDataWoSize(
                tmpcatfile, formatspecs['format_delimiter'])
        fnumextrafieldsize = int(catheader[5], 16)
        fnumextrafields = int(catheader[6], 16)
        fextrafieldslist = []
        extrastart = 7
        extraend = extrastart + fnumextrafields
        extrafieldslist = []
        if(extrastart < extraend):
            fextrafieldslist.append(catheader[extrastart])
            extrastart = extrastart + 1
        catversion = re.findall("([\\d]+)", catstring)
        fheadsize = int(catheader[0], 16)
        fnumfields = int(catheader[1], 16)
        fhencoding = catheader[2]
        fostype = catheader[3]
        fnumfiles = int(catheader[4], 16)
        fprechecksumtype = catheader[-2]
        fprechecksum = catheader[-1]
        headercheck = ValidateHeaderChecksum([catstring] + catheader[:-1], fprechecksumtype, fprechecksum, formatspecs)
        newfcs = GetHeaderChecksum([catstring] + catheader[:-1], fprechecksumtype, True, formatspecs)
        if(not headercheck):
            return False
        fileheader = tmpcatfile.read()
        tmpcatfile.close()
        catversion = re.findall("([\\d]+)", fileheader)
        catversions = re.search('(.*?)(\\d+)', fileheader).groups()
        catfileheadercshex = GetFileChecksum(
            fileheader, checksumtype[0], False, formatspecs)
        fheadtell = len(fileheader)
        catlist = {'fnumfiles': fnumfiles, 'fformat': catversions[0], 'fcompression': "", 'fencoding': fhencoding, 'fversion': catversions[1], 'fostype': fostype,
                   'fformatspecs': formatspecs, 'fchecksumtype': checksumtype[0], 'fheaderchecksum': catfileheadercshex, 'frawheader': [catstring] + catheader, 'ffilelist': []}
        for member in sorted(szpfp.list(), key=lambda x: x.filename):
            catfhstart = fheadtell
            fencoding = "UTF-8"
            if(re.findall("^[.|/]", member.filename)):
                fname = member.filename
            else:
                fname = "./"+member.filename
            if(not member.is_directory):
                fpremode = int(stat.S_IFREG + 438)
            elif(member.is_directory):
                fpremode = int(stat.S_IFDIR + 511)
            fwinattributes = int(0)
            fcompression = ""
            fcsize = 0
            flinkcount = 0
            ftype = 0
            if(member.is_directory):
                ftype = 5
            else:
                ftype = 0
            flinkname = ""
            fbasedir = os.path.dirname(fname)
            fcurfid = curfid
            fcurinode = curfid
            finode = fcurinode
            curfid = curfid + 1
            fdev = 0
            fdev_minor = 0
            fdev_major = 0
            if(ftype == 5):
                fsize = "0"
            fatime = int(member.creationtime.timestamp())
            fmtime = int(member.creationtime.timestamp())
            fctime = int(member.creationtime.timestamp())
            fbtime = int(member.creationtime.timestamp())
            if(member.is_directory):
                fmode = int(stat.S_IFDIR + 511)
                fchmode = int(stat.S_IMODE(stat.S_IFDIR + 511))
                ftypemod = int(stat.S_IFMT(stat.S_IFDIR + 511))
            else:
                fmode = int(stat.S_IFLNK + 438)
                fchmode = int(stat.S_IMODE(stat.S_IFREG + 438))
                ftypemod = int(stat.S_IFMT(stat.S_IFREG + 438))
            try:
                fuid = os.getuid()
            except AttributeError:
                fuid = 0
            except KeyError:
                fuid = 0
            try:
                fgid = os.getgid()
            except AttributeError:
                fgid = 0
            except KeyError:
                fgid = 0
            try:
                import pwd
                try:
                    userinfo = pwd.getpwuid(os.getuid())
                    funame = userinfo.pw_name
                except KeyError:
                    funame = ""
                except AttributeError:
                    funame = ""
            except ImportError:
                funame = ""
            fgname = ""
            try:
                import grp
                try:
                    groupinfo = grp.getgrgid(os.getgid())
                    fgname = groupinfo.gr_name
                except KeyError:
                    fgname = ""
                except AttributeError:
                    fgname = ""
            except ImportError:
                fgname = ""
            fcontents = BytesIO()
            if(ftype == 0):
                fcontents.write(file_content[member.filename].read())
                fsize = format(fcontents.tell(), 'x').lower()
                fileop.close()
                fcsize = fcontents.tell()
            fcontents.seek(0, 0)
            ftypehex = format(ftype, 'x').lower()
            extrafields = len(extradata)
            extrafieldslist = extradata
            catfextrafields = extrafields
            extrasizestr = AppendNullByte(
                extrafields, formatspecs['format_delimiter'])
            if(len(extradata) > 0):
                extrasizestr = extrasizestr + \
                    AppendNullBytes(extradata, formatspecs['format_delimiter'])
            extrasizelen = len(extrasizestr)
            extrasizelenhex = format(extrasizelen, 'x').lower()
            catoutlist = [ftypehex, fencoding, fname, flinkname, format(int(fsize), 'x').lower(), format(int(fatime), 'x').lower(), format(int(fmtime), 'x').lower(), format(int(fctime), 'x').lower(), format(int(fbtime), 'x').lower(), format(int(fmode), 'x').lower(), format(int(fwinattributes), 'x').lower(), fcompression, format(int(fcsize), 'x').lower(), format(int(fuid), 'x').lower(
            ), funame, format(int(fgid), 'x').lower(), fgname, format(int(fcurfid), 'x').lower(), format(int(fcurinode), 'x').lower(), format(int(flinkcount), 'x').lower(), format(int(fdev), 'x').lower(), format(int(fdev_minor), 'x').lower(), format(int(fdev_major), 'x').lower(), "+"+str(len(formatspecs['format_delimiter'])), extrasizelenhex, format(catfextrafields, 'x').lower()]
            catoutlen = len(catoutlist) + len(extradata) + 3
            catoutlenhex = format(catoutlen, 'x').lower()
            catoutlist.insert(0, catoutlenhex)
            catfileoutstr = AppendNullBytes(
                catoutlist, formatspecs['format_delimiter'])
            catheaderdata = catoutlist
            if(len(extradata) > 0):
                catfileoutstr = catfileoutstr + \
                    AppendNullBytes(extradata, formatspecs['format_delimiter'])
            if(fsize == 0):
                checksumlist = [checksumtype[1], "none"]
            else:
                checksumlist = [checksumtype[1], checksumtype[2]]
            catfileoutstr = catfileoutstr + \
                AppendNullBytes(checksumlist, formatspecs['format_delimiter'])
            catfnumfields = 24 + catfextrafields
            catfileheadercshex = GetFileChecksum(
                catfileoutstr, checksumtype[1], True, formatspecs)
            fcontents.seek(0, 0)
            if(fsize == 0):
                catfilecontentcshex = GetFileChecksum(
                    fcontents.read(), "none", False, formatspecs)
            else:
                catfilecontentcshex = GetFileChecksum(
                    fcontents.read(), checksumtype[2], False, formatspecs)
            tmpfileoutstr = catfileoutstr + \
                AppendNullBytes(
                    [catfileheadercshex, catfilecontentcshex], formatspecs['format_delimiter'])
            catheaersize = format(int(len(tmpfileoutstr) - len(formatspecs['format_delimiter'])), 'x').lower()
            catfileoutstr = AppendNullByte(
                catheaersize, formatspecs['format_delimiter']) + catfileoutstr
            catfileheadercshex = GetFileChecksum(
                catfileoutstr, checksumtype[1], True, formatspecs)
            catfileoutstr = catfileoutstr + \
                AppendNullBytes(
                    [catfileheadercshex, catfilecontentcshex], formatspecs['format_delimiter'])
            catfileoutstrecd = catfileoutstr.encode('UTF-8')
            nullstrecd = formatspecs['format_delimiter'].encode('UTF-8')
            catfcontentstart = fheadtell
            fheadtell += len(catfileoutstr) + 1
            catfcontentend = fheadtell - 1
            catfhend = catfcontentend
            fcontents.seek(0, 0)
            catfileout = catfileoutstrecd + fcontents.read() + nullstrecd
            pyhascontents = False
            if(int(fsize) > 0 and not listonly):
                pyhascontents = True
            if(int(fsize) > 0 and listonly):
                fcontents = BytesIO()
                pyhascontents = False
            fcontents.seek(0, 0)
            if(not contentasfile):
                fcontents = fcontents.read()
            catlist['ffilelist'].append({'fid': fileidnum, 'fidalt': fileidnum, 'fheadersize': int(catheaersize, 16), 'fhstart': catfhstart, 'fhend': catfhend, 'ftype': ftype, 'fencoding': fencoding, 'fname': fname, 'fbasedir': fbasedir, 'flinkname': flinkname, 'fsize': fsize, 'fatime': fatime, 'fmtime': fmtime, 'fctime': fctime, 'fbtime': fbtime, 'fmode': fmode, 'fchmode': fchmode, 'ftypemod': ftypemod, 'fwinattributes': fwinattributes, 'fcompression': fcompression, 'fcsize': fcsize, 'fuid': fuid, 'funame': funame, 'fgid': fgid, 'fgname': fgname, 'finode': finode, 'flinkcount': flinkcount,
                                        'fdev': fdev, 'fminor': fdev_minor, 'fmajor': fdev_major, 'fseeknextfile': "+"+str(len(formatspecs['format_delimiter'])), 'fheaderchecksumtype': checksumtype[1], 'fcontentchecksumtype': checksumtype[2], 'fnumfields': catfnumfields + 2, 'frawheader': catheaderdata, 'fextrafields': catfextrafields, 'fextrafieldsize': extrasizelen, 'fextralist': extrafieldslist, 'fheaderchecksum': int(catfileheadercshex, 16), 'fcontentchecksum': int(catfilecontentcshex, 16), 'fhascontents': pyhascontents, 'fcontentstart': catfcontentstart, 'fcontentend': catfcontentend, 'fcontentasfile': contentasfile, 'fcontents': fcontents})
            fileidnum = fileidnum + 1
        return catlist


def InFileToArrayAlt(infile, listonly=False, contentasfile=True, checksumtype=["crc32", "crc32", "crc32"], extradata=[], formatspecs=__file_format_dict__, verbose=False):
    checkcompressfile = CheckCompressionSubType(infile, formatspecs, True)
    if(checkcompressfile == "tarfile" and TarFileCheck(infile)):
        return TarFileToArrayAlt(infile, listonly, contentasfile, checksumtype, extradata, formatspecs, verbose)
    elif(checkcompressfile == "zipfile" and zipfile.is_zipfile(infile)):
        return ZipFileToArrayAlt(infile, listonly, contentasfile, checksumtype, extradata, formatspecs, verbose)
    elif(rarfile_support and checkcompressfile == "rarfile" and (rarfile.is_rarfile(infile) or rarfile.is_rarfile_sfx(infile))):
        return RarFileToArrayAlt(infile, listonly, contentasfile, checksumtype, extradata, formatspecs, verbose)
    elif(py7zr_support and checkcompressfile == "7zipfile" and py7zr.is_7zfile(infile)):
        return SevenZipFileToArrayAlt(infile, listonly, contentasfile, checksumtype, extradata, formatspecs, verbose)
    elif(checkcompressfile == formatspecs['format_magic']):
        return ArchiveFileToArray(infile, 0, 0, listonly, contentasfile, True, False, formatspecs, False)
    else:
        return False
    return False


def ListDirToArray(infiles, dirlistfromtxt=False, compression="auto", compresswholefile=True, compressionlevel=None, followlink=False, seekstart=0, seekend=0, listonly=False, skipchecksum=False, checksumtype=["crc32", "crc32", "crc32"], extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
    outarray = BytesIO()
    packcat = PackArchiveFile(infiles, outarray, dirlistfromtxt, compression, compresswholefile,
                              compressionlevel, followlink, checksumtype, extradata, formatspecs, verbose, True)
    listcatfiles = ArchiveFileToArray(
        outarray, seekstart, seekend, listonly, True, skipchecksum, formatspecs, returnfp)
    return listcatfiles


def ArchiveFileArrayToArrayIndex(inarray, seekstart=0, seekend=0, listonly=False, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__, returnfp=False):
    if(isinstance(inarray, dict)):
        listcatfiles = inarray
    else:
        return False
    if(not listcatfiles):
        return False
    catarray = {'list': listcatfiles, 'filetoid': {}, 'idtofile': {}, 'filetypes': {'directories': {'filetoid': {}, 'idtofile': {}}, 'files': {'filetoid': {}, 'idtofile': {}}, 'links': {'filetoid': {}, 'idtofile': {}}, 'symlinks': {'filetoid': {
    }, 'idtofile': {}}, 'hardlinks': {'filetoid': {}, 'idtofile': {}}, 'character': {'filetoid': {}, 'idtofile': {}}, 'block': {'filetoid': {}, 'idtofile': {}}, 'fifo': {'filetoid': {}, 'idtofile': {}}, 'devices': {'filetoid': {}, 'idtofile': {}}}}
    if(returnfp):
        catarray.update({'fp': listcatfiles['fp']})
    lenlist = len(listcatfiles['ffilelist'])
    lcfi = 0
    lcfx = int(listcatfiles['fnumfiles'])
    if(lenlist > listcatfiles['fnumfiles'] or lenlist < listcatfiles['fnumfiles']):
        lcfx = int(lenlist)
    else:
        lcfx = int(listcatfiles['fnumfiles'])
    while(lcfi < lcfx):
        filetoidarray = {listcatfiles['ffilelist'][lcfi]
                         ['fname']: listcatfiles['ffilelist'][lcfi]['fid']}
        idtofilearray = {listcatfiles['ffilelist'][lcfi]
                         ['fid']: listcatfiles['ffilelist'][lcfi]['fname']}
        catarray['filetoid'].update(filetoidarray)
        catarray['idtofile'].update(idtofilearray)
        if(listcatfiles['ffilelist'][lcfi]['ftype'] == 0 or listcatfiles['ffilelist'][lcfi]['ftype'] == 7):
            catarray['filetypes']['files']['filetoid'].update(filetoidarray)
            catarray['filetypes']['files']['idtofile'].update(idtofilearray)
        if(listcatfiles['ffilelist'][lcfi]['ftype'] == 1):
            catarray['filetypes']['hardlinks']['filetoid'].update(
                filetoidarray)
            catarray['filetypes']['hardlinks']['idtofile'].update(
                idtofilearray)
            catarray['filetypes']['links']['filetoid'].update(filetoidarray)
            catarray['filetypes']['links']['idtofile'].update(idtofilearray)
        if(listcatfiles['ffilelist'][lcfi]['ftype'] == 2):
            catarray['filetypes']['symlinks']['filetoid'].update(filetoidarray)
            catarray['filetypes']['symlinks']['idtofile'].update(idtofilearray)
            catarray['filetypes']['links']['filetoid'].update(filetoidarray)
            catarray['filetypes']['links']['idtofile'].update(idtofilearray)
        if(listcatfiles['ffilelist'][lcfi]['ftype'] == 3):
            catarray['filetypes']['character']['filetoid'].update(
                filetoidarray)
            catarray['filetypes']['character']['idtofile'].update(
                idtofilearray)
            catarray['filetypes']['devices']['filetoid'].update(filetoidarray)
            catarray['filetypes']['devices']['idtofile'].update(idtofilearray)
        if(listcatfiles['ffilelist'][lcfi]['ftype'] == 4):
            catarray['filetypes']['block']['filetoid'].update(filetoidarray)
            catarray['filetypes']['block']['idtofile'].update(idtofilearray)
            catarray['filetypes']['devices']['filetoid'].update(filetoidarray)
            catarray['filetypes']['devices']['idtofile'].update(idtofilearray)
        if(listcatfiles['ffilelist'][lcfi]['ftype'] == 5):
            catarray['filetypes']['directories']['filetoid'].update(
                filetoidarray)
            catarray['filetypes']['directories']['idtofile'].update(
                idtofilearray)
        if(listcatfiles['ffilelist'][lcfi]['ftype'] == 6):
            catarray['filetypes']['symlinks']['filetoid'].update(filetoidarray)
            catarray['filetypes']['symlinks']['idtofile'].update(idtofilearray)
            catarray['filetypes']['devices']['filetoid'].update(filetoidarray)
            catarray['filetypes']['devices']['idtofile'].update(idtofilearray)
        lcfi = lcfi + 1
    return catarray


def RePackArchiveFile(infile, outfile, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, followlink=False, seekstart=0, seekend=0, checksumtype=["crc32", "crc32", "crc32"], skipchecksum=False, extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
    if(isinstance(infile, dict)):
        listcatfiles = infile
    else:
        if(infile != "-" and not isinstance(infile, bytes) and not hasattr(infile, "read") and not hasattr(infile, "write")):
            infile = RemoveWindowsPath(infile)
        listcatfiles = ArchiveFileToArray(
            infile, seekstart, seekend, False, True, skipchecksum, formatspecs, returnfp)
    if(outfile != "-" and not isinstance(infile, bytes) and not hasattr(infile, "read") and not hasattr(outfile, "write")):
        outfile = RemoveWindowsPath(outfile)
    if(not compression or compression == formatspecs['format_magic']):
        compression = "auto"
    if(compression not in compressionlist and compression is None):
        compression = "auto"
    if(verbose):
        logging.basicConfig(format="%(message)s",
                            stream=sys.stdout, level=logging.DEBUG)
    if(outfile != "-" and outfile is not None and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
        if(os.path.exists(outfile)):
            try:
                os.unlink(outfile)
            except OSError:
                pass
    if(not listcatfiles):
        return False
    if(outfile == "-" or outfile is None):
        verbose = False
        fp = BytesIO()
    elif(hasattr(outfile, "read") or hasattr(outfile, "write")):
        fp = outfile
    elif(re.findall("^(ftp|ftps|sftp):\\/\\/", outfile)):
        fp = BytesIO()
    else:
        fbasename = os.path.splitext(outfile)[0]
        fextname = os.path.splitext(outfile)[1]
        if(not compresswholefile and fextname in outextlistwd):
            compresswholefile = True
        fp = CompressOpenFile(outfile, compresswholefile, compressionlevel)
    catver = formatspecs['format_ver']
    fileheaderver = str(int(catver.replace(".", "")))
    lenlist = len(listcatfiles['ffilelist'])
    fnumfiles = int(listcatfiles['fnumfiles'])
    if(lenlist > fnumfiles or lenlist < fnumfiles):
        fnumfiles = lenlist
    AppendFileHeader(fp, fnumfiles, listcatfiles['fencoding'], [], checksumtype[0], formatspecs)
    lenlist = len(listcatfiles['ffilelist'])
    fnumfiles = int(listcatfiles['fnumfiles'])
    lcfi = 0
    lcfx = int(listcatfiles['fnumfiles'])
    if(lenlist > listcatfiles['fnumfiles'] or lenlist < listcatfiles['fnumfiles']):
        lcfx = int(lenlist)
    else:
        lcfx = int(listcatfiles['fnumfiles'])
    curinode = 0
    curfid = 0
    inodelist = []
    inodetofile = {}
    filetoinode = {}
    reallcfi = 0
    while(lcfi < lcfx):
        fencoding = listcatfiles['ffilelist'][reallcfi]['fencoding']
        if(re.findall("^[.|/]", listcatfiles['ffilelist'][reallcfi]['fname'])):
            fname = listcatfiles['ffilelist'][reallcfi]['fname']
        else:
            fname = "./"+listcatfiles['ffilelist'][reallcfi]['fname']
        if(verbose):
            VerbosePrintOut(fname)
        fheadersize = format(
            int(listcatfiles['ffilelist'][reallcfi]['fheadersize']), 'x').lower()
        fsize = format(
            int(listcatfiles['ffilelist'][reallcfi]['fsize']), 'x').lower()
        flinkname = listcatfiles['ffilelist'][reallcfi]['flinkname']
        fatime = format(
            int(listcatfiles['ffilelist'][reallcfi]['fatime']), 'x').lower()
        fmtime = format(
            int(listcatfiles['ffilelist'][reallcfi]['fmtime']), 'x').lower()
        fctime = format(
            int(listcatfiles['ffilelist'][reallcfi]['fctime']), 'x').lower()
        fbtime = format(
            int(listcatfiles['ffilelist'][reallcfi]['fbtime']), 'x').lower()
        fmode = format(
            int(listcatfiles['ffilelist'][reallcfi]['fmode']), 'x').lower()
        fchmode = format(
            int(listcatfiles['ffilelist'][reallcfi]['fchmode']), 'x').lower()
        fuid = format(
            int(listcatfiles['ffilelist'][reallcfi]['fuid']), 'x').lower()
        funame = listcatfiles['ffilelist'][reallcfi]['funame']
        fgid = format(
            int(listcatfiles['ffilelist'][reallcfi]['fgid']), 'x').lower()
        fgname = listcatfiles['ffilelist'][reallcfi]['fgname']
        finode = format(
            int(listcatfiles['ffilelist'][reallcfi]['finode']), 'x').lower()
        flinkcount = format(
            int(listcatfiles['ffilelist'][reallcfi]['flinkcount']), 'x').lower()
        fwinattributes = format(
            int(listcatfiles['ffilelist'][reallcfi]['fwinattributes']), 'x').lower()
        fcompression = listcatfiles['ffilelist'][reallcfi]['fcompression']
        fcsize = format(
            int(listcatfiles['ffilelist'][reallcfi]['fcsize']), 'x').lower()
        fdev = format(
            int(listcatfiles['ffilelist'][reallcfi]['fdev']), 'x').lower()
        fdev_minor = format(
            int(listcatfiles['ffilelist'][reallcfi]['fminor']), 'x').lower()
        fdev_major = format(
            int(listcatfiles['ffilelist'][reallcfi]['fmajor']), 'x').lower()
        fseeknextfile = listcatfiles['ffilelist'][reallcfi]['fseeknextfile']
        if(len(listcatfiles['ffilelist'][reallcfi]['fextralist']) > listcatfiles['ffilelist'][reallcfi]['fextrafields'] and len(listcatfiles['ffilelist'][reallcfi]['fextralist']) > 0):
            listcatfiles['ffilelist'][reallcfi]['fextrafields'] = len(
                listcatfiles['ffilelist'][reallcfi]['fextralist'])
        if(not followlink and len(extradata) < 0):
            extradata = listcatfiles['ffilelist'][reallcfi]['fextralist']
        fcontents = listcatfiles['ffilelist'][reallcfi]['fcontents']
        if(not listcatfiles['ffilelist'][reallcfi]['fcontentasfile']):
            fcontents = BytesIO(fcontents)
        fcompression = ""
        fcsize = format(int(0), 'x').lower()
        if(not compresswholefile):
            fcontents.seek(0, 2)
            ucfsize = fcontents.tell()
            fcontents.seek(0, 0)
            if(compression == "auto"):
                ilsize = len(compressionuselist)
                ilmin = 0
                ilcsize = []
                while(ilmin < ilsize):
                    cfcontents = BytesIO()
                    fcontents.seek(0, 0)
                    shutil.copyfileobj(fcontents, cfcontents)
                    fcontents.seek(0, 0)
                    cfcontents.seek(0, 0)
                    cfcontents = CompressArchiveFile(
                        cfcontents, compressionuselist[ilmin], compressionlevel, formatspecs)
                    if(cfcontents):
                        cfcontents.seek(0, 2)
                        ilcsize.append(cfcontents.tell())
                        cfcontents.close()
                    else:
                        try:
                            ilcsize.append(sys.maxint)
                        except AttributeError:
                            ilcsize.append(sys.maxsize)
                    ilmin = ilmin + 1
                ilcmin = ilcsize.index(min(ilcsize))
                curcompression = compressionuselist[ilcmin]
            fcontents.seek(0, 0)
            cfcontents = BytesIO()
            shutil.copyfileobj(fcontents, cfcontents)
            cfcontents.seek(0, 0)
            cfcontents = CompressArchiveFile(
                cfcontents, curcompression, compressionlevel, formatspecs)
            cfcontents.seek(0, 2)
            cfsize = cfcontents.tell()
            if(ucfsize > cfsize):
                fcsize = format(int(cfsize), 'x').lower()
                fcompression = curcompression
                fcontents.close()
                fcontents = cfcontents
        if(followlink):
            if(listcatfiles['ffilelist'][reallcfi]['ftype'] == 1 or listcatfiles['ffilelist'][reallcfi]['ftype'] == 2):
                getflinkpath = listcatfiles['ffilelist'][reallcfi]['flinkname']
                flinkid = prelistcatfiles['filetoid'][getflinkpath]
                flinkinfo = listcatfiles['ffilelist'][flinkid]
                fheadersize = format(
                    int(flinkinfo['fheadersize']), 'x').lower()
                fsize = format(int(flinkinfo['fsize']), 'x').lower()
                flinkname = flinkinfo['flinkname']
                fatime = format(int(flinkinfo['fatime']), 'x').lower()
                fmtime = format(int(flinkinfo['fmtime']), 'x').lower()
                fctime = format(int(flinkinfo['fctime']), 'x').lower()
                fbtime = format(int(flinkinfo['fbtime']), 'x').lower()
                fmode = format(int(flinkinfo['fmode']), 'x').lower()
                fchmode = format(int(flinkinfo['fchmode']), 'x').lower()
                fuid = format(int(flinkinfo['fuid']), 'x').lower()
                funame = flinkinfo['funame']
                fgid = format(int(flinkinfo['fgid']), 'x').lower()
                fgname = flinkinfo['fgname']
                finode = format(int(flinkinfo['finode']), 'x').lower()
                flinkcount = format(int(flinkinfo['flinkcount']), 'x').lower()
                fwinattributes = format(
                    int(flinkinfo['fwinattributes']), 'x').lower()
                fcompression = flinkinfo['fcompression']
                fcsize = format(int(flinkinfo['fcsize']), 'x').lower()
                fdev = format(int(flinkinfo['fdev']), 'x').lower()
                fdev_minor = format(int(flinkinfo['fminor']), 'x').lower()
                fdev_major = format(int(flinkinfo['fmajor']), 'x').lower()
                fseeknextfile = flinkinfo['fseeknextfile']
                if(len(flinkinfo['fextralist']) > flinkinfo['fextrafields'] and len(flinkinfo['fextralist']) > 0):
                    flinkinfo['fextrafields'] = len(flinkinfo['fextralist'])
                if(len(extradata) < 0):
                    extradata = flinkinfo['fextralist']
                fcontents = flinkinfo['fcontents']
                if(not flinkinfo['fcontentasfile']):
                    fcontents = BytesIO(fcontents)
                ftypehex = format(flinkinfo['ftype'], 'x').lower()
        else:
            ftypehex = format(
                listcatfiles['ffilelist'][reallcfi]['ftype'], 'x').lower()
        fcurfid = format(curfid, 'x').lower()
        if(not followlink and finode != 0):
            if(listcatfiles['ffilelist'][reallcfi]['ftype'] != 1):
                fcurinode = format(int(curinode), 'x').lower()
                inodetofile.update({curinode: fname})
                filetoinode.update({fname: curinode})
                curinode = curinode + 1
            else:
                fcurinode = format(int(filetoinode[flinkname]), 'x').lower()
        else:
            fcurinode = format(int(curinode), 'x').lower()
            curinode = curinode + 1
        curfid = curfid + 1
        if(fcompression == "none"):
            fcompression = ""
        catoutlist = [ftypehex, fencoding, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression, fcsize,
                      fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev, fdev_minor, fdev_major, fseeknextfile]
        AppendFileHeaderWithContent(
            fp, catoutlist, extradata, fcontents.read(), [checksumtype[1], checksumtype[2]], formatspecs)
        fcontents.close()
        lcfi = lcfi + 1
        reallcfi = reallcfi + 1
    if(lcfx > 0):
        try:
            fp.write(AppendNullBytes(
                ["0", "0"], formatspecs['format_delimiter']).encode("UTF-8"))
        except OSError:
            return False
    if(outfile == "-" or outfile is None or hasattr(outfile, "read") or hasattr(outfile, "write")):
        fp = CompressArchiveFile(
            fp, compression, compressionlevel, formatspecs)
        try:
            fp.flush()
            if(hasattr(os, "sync")):
                os.fsync(fp.fileno())
        except io.UnsupportedOperation:
            pass
        except AttributeError:
            pass
        except OSError:
            pass
    if(outfile == "-"):
        fp.seek(0, 0)
        if(hasattr(sys.stdout, "buffer")):
            shutil.copyfileobj(fp, sys.stdout.buffer)
        else:
            shutil.copyfileobj(fp, sys.stdout)
    elif(outfile is None):
        fp.seek(0, 0)
        outvar = fp.read()
        fp.close()
        return outvar
    elif(re.findall("^(ftp|ftps|sftp):\\/\\/", outfile)):
        fp = CompressArchiveFile(
            fp, compression, compressionlevel, formatspecs)
        fp.seek(0, 0)
        upload_file_to_internet_file(fp, outfile)
    if(returnfp):
        fp.seek(0, 0)
        return fp
    else:
        fp.close()
        return True


def RePackArchiveFileFromString(catstr, outfile, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["crc32", "crc32", "crc32"], skipchecksum=False, extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
    fp = BytesIO(catstr)
    listcatfiles = RePackArchiveFile(fp, compression, compresswholefile, compressionlevel, compressionuselist,
                                     checksumtype, skipchecksum, extradata, formatspecs, verbose, returnfp)
    return listcatfiles


def PackArchiveFileFromListDir(infiles, outfile, dirlistfromtxt=False, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, followlink=False, skipchecksum=False, checksumtype=["crc32", "crc32", "crc32"], extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
    outarray = BytesIO()
    packcat = PackArchiveFile(infiles, outarray, dirlistfromtxt, compression, compresswholefile,
                              compressionlevel, compressionuselist, followlink, checksumtype, extradata, formatspecs, verbose, True)
    listcatfiles = RePackArchiveFile(outarray, outfile, compression, compresswholefile,
                                     compressionlevel, checksumtype, skipchecksum, extradata, formatspecs, verbose, returnfp)
    return listcatfiles


def UnPackArchiveFile(infile, outdir=None, followlink=False, seekstart=0, seekend=0, skipchecksum=False, formatspecs=__file_format_dict__, preservepermissions=True, preservetime=True, verbose=False, returnfp=False):
    if(outdir is not None):
        outdir = RemoveWindowsPath(outdir)
    if(verbose):
        logging.basicConfig(format="%(message)s",
                            stream=sys.stdout, level=logging.DEBUG)
    if(isinstance(infile, dict)):
        listcatfiles = infile
    else:
        if(infile != "-" and not hasattr(infile, "read") and not hasattr(infile, "write") and not (sys.version_info[0] >= 3 and isinstance(infile, bytes))):
            infile = RemoveWindowsPath(infile)
        listcatfiles = ArchiveFileToArray(
            infile, seekstart, seekend, False, True, skipchecksum, formatspecs, returnfp)
    if(not listcatfiles):
        return False
    lenlist = len(listcatfiles['ffilelist'])
    fnumfiles = int(listcatfiles['fnumfiles'])
    lcfi = 0
    lcfx = int(listcatfiles['fnumfiles'])
    if(lenlist > listcatfiles['fnumfiles'] or lenlist < listcatfiles['fnumfiles']):
        lcfx = int(lenlist)
    else:
        lcfx = int(listcatfiles['fnumfiles'])
    while(lcfi < lcfx):
        funame = ""
        try:
            import pwd
            try:
                userinfo = pwd.getpwuid(
                    listcatfiles['ffilelist'][lcfi]['fuid'])
                funame = userinfo.pw_name
            except KeyError:
                funame = ""
        except ImportError:
            funame = ""
        fgname = ""
        try:
            import grp
            try:
                groupinfo = grp.getgrgid(
                    listcatfiles['ffilelist'][lcfi]['fgid'])
                fgname = groupinfo.gr_name
            except KeyError:
                fgname = ""
        except ImportError:
            fgname = ""
        if(verbose):
            VerbosePrintOut(PrependPath(
                outdir, listcatfiles['ffilelist'][lcfi]['fname']))
        if(listcatfiles['ffilelist'][lcfi]['ftype'] == 0 or listcatfiles['ffilelist'][lcfi]['ftype'] == 7):
            with open(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), "wb") as fpc:
                if(not listcatfiles['ffilelist'][lcfi]['fcontentasfile']):
                    listcatfiles['ffilelist'][lcfi]['fcontents'] = BytesIO(
                        listcatfiles['ffilelist'][lcfi]['fcontents'])
                listcatfiles['ffilelist'][lcfi]['fcontents'].seek(0, 0)
                shutil.copyfileobj(
                    listcatfiles['ffilelist'][lcfi]['fcontents'], fpc)
                try:
                    fpc.flush()
                    if(hasattr(os, "sync")):
                        os.fsync(fpc.fileno())
                except io.UnsupportedOperation:
                    pass
                except AttributeError:
                    pass
                except OSError:
                    pass
            if(hasattr(os, "chown") and funame == listcatfiles['ffilelist'][lcfi]['funame'] and fgname == listcatfiles['ffilelist'][lcfi]['fgname'] and preservepermissions):
                os.chown(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']),
                         listcatfiles['ffilelist'][lcfi]['fuid'], listcatfiles['ffilelist'][lcfi]['fgid'])
            if(preservepermissions):
                os.chmod(PrependPath(
                    outdir, listcatfiles['ffilelist'][lcfi]['fname']), listcatfiles['ffilelist'][lcfi]['fchmode'])
            if(preservetime):
                os.utime(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), (
                    listcatfiles['ffilelist'][lcfi]['fatime'], listcatfiles['ffilelist'][lcfi]['fmtime']))
        if(listcatfiles['ffilelist'][lcfi]['ftype'] == 1):
            if(followlink):
                getflinkpath = listcatfiles['ffilelist'][lcfi]['flinkname']
                flinkid = prelistcatfiles['filetoid'][getflinkpath]
                flinkinfo = listcatfiles['ffilelist'][flinkid]
                funame = ""
                try:
                    import pwd
                    try:
                        userinfo = pwd.getpwuid(flinkinfo['fuid'])
                        funame = userinfo.pw_name
                    except KeyError:
                        funame = ""
                except ImportError:
                    funame = ""
                fgname = ""
                try:
                    import grp
                    try:
                        groupinfo = grp.getgrgid(flinkinfo['fgid'])
                        fgname = groupinfo.gr_name
                    except KeyError:
                        fgname = ""
                except ImportError:
                    fgname = ""
                if(flinkinfo['ftype'] == 0 or flinkinfo['ftype'] == 7):
                    with open(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), "wb") as fpc:
                        if(not flinkinfo['fcontentasfile']):
                            flinkinfo['fcontents'] = BytesIO(
                                flinkinfo['fcontents'])
                        flinkinfo['fcontents'].seek(0, 0)
                        shutil.copyfileobj(flinkinfo['fcontents'], fpc)
                        try:
                            fpc.flush()
                            if(hasattr(os, "sync")):
                                os.fsync(fpc.fileno())
                        except io.UnsupportedOperation:
                            pass
                        except AttributeError:
                            pass
                        except OSError:
                            pass
                    if(hasattr(os, "chown") and funame == flinkinfo['funame'] and fgname == flinkinfo['fgname'] and preservepermissions):
                        os.chown(PrependPath(
                            outdir, listcatfiles['ffilelist'][lcfi]['fname']), flinkinfo['fuid'], flinkinfo['fgid'])
                    if(preservepermissions):
                        os.chmod(PrependPath(
                            outdir, listcatfiles['ffilelist'][lcfi]['fname']), flinkinfo['fchmode'])
                    if(preservetime):
                        os.utime(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), (
                            flinkinfo['fatime'], flinkinfo['fmtime']))
                if(flinkinfo['ftype'] == 1):
                    os.link(flinkinfo['flinkname'], PrependPath(
                        outdir, listcatfiles['ffilelist'][lcfi]['fname']))
                if(flinkinfo['ftype'] == 2):
                    os.symlink(flinkinfo['flinkname'], PrependPath(
                        outdir, listcatfiles['ffilelist'][lcfi]['fname']))
                if(flinkinfo['ftype'] == 5):
                    if(preservepermissions):
                        os.mkdir(PrependPath(
                            outdir, listcatfiles['ffilelist'][lcfi]['fname']), flinkinfo['fchmode'])
                    else:
                        os.mkdir(PrependPath(
                            outdir, listcatfiles['ffilelist'][lcfi]['fname']))
                    if(hasattr(os, "chown") and funame == flinkinfo['funame'] and fgname == flinkinfo['fgname'] and preservepermissions):
                        os.chown(PrependPath(
                            outdir, listcatfiles['ffilelist'][lcfi]['fname']), flinkinfo['fuid'], flinkinfo['fgid'])
                    if(preservepermissions):
                        os.chmod(PrependPath(
                            outdir, listcatfiles['ffilelist'][lcfi]['fname']), flinkinfo['fchmode'])
                    if(preservetime):
                        os.utime(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), (
                            flinkinfo['fatime'], flinkinfo['fmtime']))
                if(flinkinfo['ftype'] == 6 and hasattr(os, "mkfifo")):
                    os.mkfifo(PrependPath(
                        outdir, listcatfiles['ffilelist'][lcfi]['fname']), flinkinfo['fchmode'])
            else:
                os.link(listcatfiles['ffilelist'][lcfi]['flinkname'], PrependPath(
                    outdir, listcatfiles['ffilelist'][lcfi]['fname']))
        if(listcatfiles['ffilelist'][lcfi]['ftype'] == 2):
            if(followlink):
                getflinkpath = listcatfiles['ffilelist'][lcfi]['flinkname']
                flinkid = prelistcatfiles['filetoid'][getflinkpath]
                flinkinfo = listcatfiles['ffilelist'][flinkid]
                funame = ""
                try:
                    import pwd
                    try:
                        userinfo = pwd.getpwuid(flinkinfo['fuid'])
                        funame = userinfo.pw_name
                    except KeyError:
                        funame = ""
                except ImportError:
                    funame = ""
                fgname = ""
                try:
                    import grp
                    try:
                        groupinfo = grp.getgrgid(flinkinfo['fgid'])
                        fgname = groupinfo.gr_name
                    except KeyError:
                        fgname = ""
                except ImportError:
                    fgname = ""
                if(flinkinfo['ftype'] == 0 or flinkinfo['ftype'] == 7):
                    with open(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), "wb") as fpc:
                        if(not flinkinfo['fcontentasfile']):
                            flinkinfo['fcontents'] = BytesIO(
                                flinkinfo['fcontents'])
                        flinkinfo['fcontents'].seek(0, 0)
                        shutil.copyfileobj(flinkinfo['fcontents'], fpc)
                        try:
                            fpc.flush()
                            if(hasattr(os, "sync")):
                                os.fsync(fpc.fileno())
                        except io.UnsupportedOperation:
                            pass
                        except AttributeError:
                            pass
                        except OSError:
                            pass
                    if(hasattr(os, "chown") and funame == flinkinfo['funame'] and fgname == flinkinfo['fgname'] and preservepermissions):
                        os.chown(PrependPath(
                            outdir, listcatfiles['ffilelist'][lcfi]['fname']), flinkinfo['fuid'], flinkinfo['fgid'])
                    if(preservepermissions):
                        os.chmod(PrependPath(
                            outdir, listcatfiles['ffilelist'][lcfi]['fname']), flinkinfo['fchmode'])
                    if(preservetime):
                        os.utime(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), (
                            flinkinfo['fatime'], flinkinfo['fmtime']))
                if(flinkinfo['ftype'] == 1):
                    os.link(flinkinfo['flinkname'], PrependPath(
                        outdir, listcatfiles['ffilelist'][lcfi]['fname']))
                if(flinkinfo['ftype'] == 2):
                    os.symlink(flinkinfo['flinkname'], PrependPath(
                        outdir, listcatfiles['ffilelist'][lcfi]['fname']))
                if(flinkinfo['ftype'] == 5):
                    if(preservepermissions):
                        os.mkdir(PrependPath(
                            outdir, listcatfiles['ffilelist'][lcfi]['fname']), flinkinfo['fchmode'])
                    else:
                        os.mkdir(PrependPath(
                            outdir, listcatfiles['ffilelist'][lcfi]['fname']))
                    if(hasattr(os, "chown") and funame == flinkinfo['funame'] and fgname == flinkinfo['fgname'] and preservepermissions):
                        os.chown(PrependPath(
                            outdir, listcatfiles['ffilelist'][lcfi]['fname']), flinkinfo['fuid'], flinkinfo['fgid'])
                    if(preservepermissions):
                        os.chmod(PrependPath(
                            outdir, listcatfiles['ffilelist'][lcfi]['fname']), flinkinfo['fchmode'])
                    if(preservetime):
                        os.utime(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), (
                            flinkinfo['fatime'], flinkinfo['fmtime']))
                if(flinkinfo['ftype'] == 6 and hasattr(os, "mkfifo")):
                    os.mkfifo(PrependPath(
                        outdir, listcatfiles['ffilelist'][lcfi]['fname']), flinkinfo['fchmode'])
            else:
                os.symlink(listcatfiles['ffilelist'][lcfi]['flinkname'], PrependPath(
                    outdir, listcatfiles['ffilelist'][lcfi]['fname']))
        if(listcatfiles['ffilelist'][lcfi]['ftype'] == 5):
            if(preservepermissions):
                os.mkdir(PrependPath(
                    outdir, listcatfiles['ffilelist'][lcfi]['fname']), listcatfiles['ffilelist'][lcfi]['fchmode'])
            else:
                os.mkdir(PrependPath(
                    outdir, listcatfiles['ffilelist'][lcfi]['fname']))
            if(hasattr(os, "chown") and funame == listcatfiles['ffilelist'][lcfi]['funame'] and fgname == listcatfiles['ffilelist'][lcfi]['fgname'] and preservepermissions):
                os.chown(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']),
                         listcatfiles['ffilelist'][lcfi]['fuid'], listcatfiles['ffilelist'][lcfi]['fgid'])
            if(preservepermissions):
                os.chmod(PrependPath(
                    outdir, listcatfiles['ffilelist'][lcfi]['fname']), listcatfiles['ffilelist'][lcfi]['fchmode'])
            if(preservetime):
                os.utime(PrependPath(outdir, listcatfiles['ffilelist'][lcfi]['fname']), (
                    listcatfiles['ffilelist'][lcfi]['fatime'], listcatfiles['ffilelist'][lcfi]['fmtime']))
        if(listcatfiles['ffilelist'][lcfi]['ftype'] == 6 and hasattr(os, "mkfifo")):
            os.mkfifo(PrependPath(
                outdir, listcatfiles['ffilelist'][lcfi]['fname']), listcatfiles['ffilelist'][lcfi]['fchmode'])
        lcfi = lcfi + 1
    if(returnfp):
        return listcatfiles['ffilelist']['fp']
    else:
        return True


if(hasattr(shutil, "register_unpack_format")):
    def UnPackArchiveFileFunc(archive_name, extract_dir=None, **kwargs):
        return UnPackArchiveFile(archive_name, extract_dir, False, 0, 0, False, __file_format_dict__['format_delimiter'], False, False)


def UnPackArchiveFileString(catstr, outdir=None, followlink=False, seekstart=0, seekend=0, skipchecksum=False, formatspecs=__file_format_dict__, verbose=False, returnfp=False):
    fp = BytesIO(catstr)
    listcatfiles = UnPackArchiveFile(
        fp, outdir, followlink, seekstart, seekend, skipchecksum, formatspecs, verbose, returnfp)
    return listcatfiles


def ArchiveFileListFiles(infile, seekstart=0, seekend=0, skipchecksum=False, formatspecs=__file_format_dict__, verbose=False, returnfp=False):
    logging.basicConfig(format="%(message)s",
                        stream=sys.stdout, level=logging.DEBUG)
    if(isinstance(infile, dict)):
        listcatfiles = infile
    else:
        if(infile != "-" and not hasattr(infile, "read") and not hasattr(infile, "write") and not (sys.version_info[0] >= 3 and isinstance(infile, bytes))):
            infile = RemoveWindowsPath(infile)
        listcatfiles = ArchiveFileToArray(
            infile, seekstart, seekend, True, False, skipchecksum, formatspecs, returnfp)
    if(not listcatfiles):
        return False
    lenlist = len(listcatfiles['ffilelist'])
    fnumfiles = int(listcatfiles['fnumfiles'])
    lcfi = 0
    lcfx = int(listcatfiles['fnumfiles'])
    if(lenlist > listcatfiles['fnumfiles'] or lenlist < listcatfiles['fnumfiles']):
        lcfx = int(lenlist)
    else:
        lcfx = int(listcatfiles['fnumfiles'])
    returnval = {}
    while(lcfi < lcfx):
        returnval.update({lcfi: listcatfiles['ffilelist'][lcfi]['fname']})
        if(not verbose):
            VerbosePrintOut(listcatfiles['ffilelist'][lcfi]['fname'])
        if(verbose):
            permissions = {'access': {'0': ('---'), '1': ('--x'), '2': ('-w-'), '3': ('-wx'), '4': (
                'r--'), '5': ('r-x'), '6': ('rw-'), '7': ('rwx')}, 'roles': {0: 'owner', 1: 'group', 2: 'other'}}
            printfname = listcatfiles['ffilelist'][lcfi]['fname']
            if(listcatfiles['ffilelist'][lcfi]['ftype'] == 1):
                printfname = listcatfiles['ffilelist'][lcfi]['fname'] + \
                    " link to " + listcatfiles['ffilelist'][lcfi]['flinkname']
            if(listcatfiles['ffilelist'][lcfi]['ftype'] == 2):
                printfname = listcatfiles['ffilelist'][lcfi]['fname'] + \
                    " -> " + listcatfiles['ffilelist'][lcfi]['flinkname']
            fuprint = listcatfiles['ffilelist'][lcfi]['funame']
            if(len(fuprint) <= 0):
                fuprint = listcatfiles['ffilelist'][lcfi]['fuid']
            fgprint = listcatfiles['ffilelist'][lcfi]['fgname']
            if(len(fgprint) <= 0):
                fgprint = listcatfiles['ffilelist'][lcfi]['fgid']
            VerbosePrintOut(PrintPermissionString(listcatfiles['ffilelist'][lcfi]['fmode'], listcatfiles['ffilelist'][lcfi]['ftype']) + " " + str(fuprint) + "/" + str(fgprint) + " " + str(
                listcatfiles['ffilelist'][lcfi]['fsize']).rjust(15) + " " + datetime.datetime.utcfromtimestamp(listcatfiles['ffilelist'][lcfi]['fmtime']).strftime('%Y-%m-%d %H:%M') + " " + printfname)
        lcfi = lcfi + 1
    if(returnfp):
        return listcatfiles['fp']
    else:
        return True


def ArchiveFileStringListFiles(catstr, seekstart=0, seekend=0, skipchecksum=False, formatspecs=__file_format_dict__, verbose=False, returnfp=False):
    fp = BytesIO(catstr)
    listcatfiles = ArchiveFileListFiles(
        catstr, seekstart, seekend, skipchecksum, formatspecs, verbose, returnfp)
    return listcatfiles


def TarFileListFiles(infile, verbose=False, returnfp=False):
    logging.basicConfig(format="%(message)s",
                        stream=sys.stdout, level=logging.DEBUG)
    if(infile == "-"):
        infile = BytesIO()
        if(hasattr(sys.stdin, "buffer")):
            shutil.copyfileobj(sys.stdin.buffer, infile)
        else:
            shutil.copyfileobj(sys.stdin, infile)
        infile.seek(0, 0)
        if(not infile):
            return False
        infile.seek(0, 0)
    elif(re.findall("^(http|https|ftp|ftps|sftp):\\/\\/", infile)):
        infile = download_file_from_internet_file(infile)
        infile.seek(0, 0)
        if(not infile):
            return False
        infile.seek(0, 0)
    elif(hasattr(infile, "read") or hasattr(infile, "write")):
        try:
            if(not tarfile.is_tarfile(infile)):
                return False
        except AttributeError:
            if(not TarFileCheck(infile)):
                return False
    elif(not os.path.exists(infile) or not os.path.isfile(infile)):
        return False
    elif(os.path.exists(infile) and os.path.isfile(infile)):
        try:
            if(not tarfile.is_tarfile(infile)):
                return False
        except AttributeError:
            if(not TarFileCheck(infile)):
                return False
    try:
        if(hasattr(infile, "read") or hasattr(infile, "write")):
            compresscheck = CheckCompressionType(infile, formatspecs, False)
            if(compresscheck=="zstd"):
                if 'zstandard' in sys.modules:
                    infile = ZstdFile(fileobj=infile, mode="rb")
                elif 'pyzstd' in sys.modules:
                    fp = pyzstd.zstdfile.ZstdFile(fileobj=infile, mode="rb")
                tarfp = tarfile.open(fileobj=infile, mode="r")
            else:
                tarfp = tarfile.open(fileobj=infile, mode="r")
        else:
            compresscheck = CheckCompressionType(infile, formatspecs, True)
            if(compresscheck=="zstd"):
                if 'zstandard' in sys.modules:
                    infile = ZstdFile(fileobj=infile, mode="rb")
                elif 'pyzstd' in sys.modules:
                    fp = pyzstd.zstdfile.ZstdFile(fileobj=infile, mode="rb")
                tarfp = tarfile.open(fileobj=infile, mode="r")
            else:
                tarfp = tarfile.open(infile, "r")
    except FileNotFoundError:
        return False
    lcfi = 0
    returnval = {}
    for member in sorted(tarfp.getmembers(), key=lambda x: x.name):
        returnval.update({lcfi: member.name})
        fpremode = member.mode
        ffullmode = member.mode
        flinkcount = 0
        ftype = 0
        if(member.isreg()):
            ffullmode = member.mode + stat.S_IFREG
            ftype = 0
        elif(member.islnk()):
            ffullmode = member.mode + stat.S_IFREG
            ftype = 1
        elif(member.issym()):
            ffullmode = member.mode + stat.S_IFLNK
            ftype = 2
        elif(member.ischr()):
            ffullmode = member.mode + stat.S_IFCHR
            ftype = 3
        elif(member.isblk()):
            ffullmode = member.mode + stat.S_IFBLK
            ftype = 4
        elif(member.isdir()):
            ffullmode = member.mode + stat.S_IFDIR
            ftype = 5
        elif(member.isfifo()):
            ffullmode = member.mode + stat.S_IFIFO
            ftype = 6
        elif(hasattr(member, "issparse") and member.issparse()):
            ffullmode = member.mode
            ftype = 12
        elif(member.isdev()):
            ffullmode = member.mode
            ftype = 14
        else:
            ffullmode = member.mode
            ftype = 0
        if(not verbose):
            VerbosePrintOut(member.name)
        elif(verbose):
            permissions = {'access': {'0': ('---'), '1': ('--x'), '2': ('-w-'), '3': ('-wx'), '4': (
                'r--'), '5': ('r-x'), '6': ('rw-'), '7': ('rwx')}, 'roles': {0: 'owner', 1: 'group', 2: 'other'}}
            printfname = member.name
            if(member.islnk()):
                printfname = member.name + " link to " + member.linkname
            elif(member.issym()):
                printfname = member.name + " -> " + member.linkname
            fuprint = member.uname
            if(len(fuprint) <= 0):
                fuprint = member.uid
            fgprint = member.gname
            if(len(fgprint) <= 0):
                fgprint = member.gid
            VerbosePrintOut(PrintPermissionString(ffullmode, ftype) + " " + str(fuprint) + "/" + str(fgprint) + " " + str(
                member.size).rjust(15) + " " + datetime.datetime.utcfromtimestamp(member.mtime).strftime('%Y-%m-%d %H:%M') + " " + printfname)
        lcfi = lcfi + 1
    if(returnfp):
        return listcatfiles['fp']
    else:
        return True


def ZipFileListFiles(infile, verbose=False, returnfp=False):
    logging.basicConfig(format="%(message)s",
                        stream=sys.stdout, level=logging.DEBUG)
    if(infile == "-"):
        infile = BytesIO()
        if(hasattr(sys.stdin, "buffer")):
            shutil.copyfileobj(sys.stdin.buffer, infile)
        else:
            shutil.copyfileobj(sys.stdin, infile)
        infile.seek(0, 0)
        if(not infile):
            return False
        infile.seek(0, 0)
    elif(re.findall("^(http|https|ftp|ftps|sftp):\\/\\/", infile)):
        infile = download_file_from_internet_file(infile)
        infile.seek(0, 0)
        if(not infile):
            return False
        infile.seek(0, 0)
    elif(hasattr(infile, "read") or hasattr(infile, "write")):
        pass
    elif(not os.path.exists(infile) or not os.path.isfile(infile)):
        return False
    if(not zipfile.is_zipfile(infile)):
        return False
    try:
        zipfp = zipfile.ZipFile(infile, "r", allowZip64=True)
    except FileNotFoundError:
        return False
    lcfi = 0
    returnval = {}
    ziptest = zipfp.testzip()
    if(ziptest):
        VerbosePrintOut("Bad file found!")
    for member in sorted(zipfp.infolist(), key=lambda x: x.filename):
        zipinfo = zipfp.getinfo(member.filename)
        if(zipinfo.create_system == 0 or zipinfo.create_system == 10):
            fwinattributes = int(zipinfo.external_attr)
            if ((hasattr(member, "is_dir") and member.is_dir()) or member.filename.endswith('/')):
                fmode = int(stat.S_IFDIR + 511)
                fchmode = int(stat.S_IMODE(int(stat.S_IFDIR + 511)))
                ftypemod = int(stat.S_IFMT(int(stat.S_IFDIR + 511)))
            else:
                fmode = int(stat.S_IFREG + 438)
                fchmode = int(stat.S_IMODE(fmode))
                ftypemod = int(stat.S_IFMT(fmode))
        elif(zipinfo.create_system == 3):
            fwinattributes = int(0)
            try:
                fmode = int(zipinfo.external_attr)
                fchmode = stat.S_IMODE(fmode)
                ftypemod = stat.S_IFMT(fmode)
            except OverflowError:
                fmode = int(zipinfo.external_attr >> 16)
                fchmode = stat.S_IMODE(fmode)
                ftypemod = stat.S_IFMT(fmode)
        else:
            fwinattributes = int(0)
            if ((hasattr(member, "is_dir") and member.is_dir()) or member.filename.endswith('/')):
                fmode = int(stat.S_IFDIR + 511)
                fchmode = int(stat.S_IMODE(int(stat.S_IFDIR + 511)))
                ftypemod = int(stat.S_IFMT(int(stat.S_IFDIR + 511)))
            else:
                fmode = int(stat.S_IFREG + 438)
                fchmode = int(stat.S_IMODE(fmode))
                ftypemod = int(stat.S_IFMT(fmode))
        returnval.update({lcfi: member.filename})
        if(not verbose):
            VerbosePrintOut(member.filename)
        if(verbose):
            permissions = {'access': {'0': ('---'), '1': ('--x'), '2': ('-w-'), '3': ('-wx'), '4': (
                'r--'), '5': ('r-x'), '6': ('rw-'), '7': ('rwx')}, 'roles': {0: 'owner', 1: 'group', 2: 'other'}}
            permissionstr = ""
            for fmodval in str(oct(fmode))[-3:]:
                permissionstr = permissionstr + \
                    permissions['access'].get(fmodval, '---')
            if ((hasattr(member, "is_dir") and member.is_dir()) or member.filename.endswith('/')):
                ftype = 5
                permissionstr = "d" + permissionstr
            else:
                ftype = 0
                permissionstr = "-" + permissionstr
            printfname = member.filename
            try:
                fuid = int(os.getuid())
            except AttributeError:
                fuid = int(0)
            except KeyError:
                fuid = int(0)
            try:
                fgid = int(os.getgid())
            except AttributeError:
                fgid = int(0)
            except KeyError:
                fgid = int(0)
            try:
                import pwd
                try:
                    userinfo = pwd.getpwuid(os.getuid())
                    funame = userinfo.pw_name
                except KeyError:
                    funame = ""
                except AttributeError:
                    funame = ""
            except ImportError:
                funame = ""
            fgname = ""
            try:
                import grp
                try:
                    groupinfo = grp.getgrgid(os.getgid())
                    fgname = groupinfo.gr_name
                except KeyError:
                    fgname = ""
                except AttributeError:
                    fgname = ""
            except ImportError:
                fgname = ""
            fuprint = funame
            if(len(fuprint) <= 0):
                fuprint = str(fuid)
            fgprint = fgname
            if(len(fgprint) <= 0):
                fgprint = str(fgid)
            VerbosePrintOut(PrintPermissionString(fmode, ftype) + " " + str(fuprint) + "/" + str(fgprint) + " " + str(member.file_size).rjust(
                15) + " " + datetime.datetime.utcfromtimestamp(int(time.mktime(member.date_time + (0, 0, -1)))).strftime('%Y-%m-%d %H:%M') + " " + printfname)
        lcfi = lcfi + 1
    if(returnfp):
        return listcatfiles['fp']
    else:
        return True


if(not rarfile_support):
    def RarFileListFiles(infile, verbose=False, returnfp=False):
        return False

if(rarfile_support):
    def RarFileListFiles(infile, verbose=False, returnfp=False):
        logging.basicConfig(format="%(message)s",
                            stream=sys.stdout, level=logging.DEBUG)
        if(not os.path.exists(infile) or not os.path.isfile(infile)):
            return False
        if(not rarfile.is_rarfile(infile) and not rarfile.is_rarfile_sfx(infile)):
            return False
        lcfi = 0
        returnval = {}
        rarfp = rarfile.RarFile(infile, "r")
        rartest = rarfp.testrar()
        if(rartest):
            VerbosePrintOut("Bad file found!")
        for member in sorted(rarfp.infolist(), key=lambda x: x.filename):
            is_unix = False
            is_windows = False
            if(member.host_os == rarfile.RAR_OS_UNIX):
                is_windows = False
                try:
                    member.external_attr
                    is_unix = True
                except AttributeError:
                    is_unix = False
            elif(member.host_os == rarfile.RAR_OS_WIN32):
                is_unix = False
                try:
                    member.external_attr
                    is_windows = True
                except AttributeError:
                    is_windows = False
            else:
                is_unix = False
                is_windows = False
            if(is_unix and member.external_attr != 0):
                fpremode = int(member.external_attr)
            elif(member.is_file()):
                fpremode = int(stat.S_IFREG + 438)
            elif(member.is_symlink()):
                fpremode = int(stat.S_IFLNK + 438)
            elif(member.is_dir()):
                fpremode = int(stat.S_IFDIR + 511)
            if(is_windows and member.external_attr != 0):
                fwinattributes = int(member.external_attr)
            else:
                fwinattributes = int(0)
            if(is_unix and member.external_attr != 0):
                fmode = int(member.external_attr)
                fchmode = int(stat.S_IMODE(member.external_attr))
                ftypemod = int(stat.S_IFMT(member.external_attr))
            elif(member.is_file()):
                fmode = int(stat.S_IFREG + 438)
                fchmode = int(stat.S_IMODE(int(stat.S_IFREG + 438)))
                ftypemod = int(stat.S_IFMT(int(stat.S_IFREG + 438)))
            elif(member.is_symlink()):
                fmode = int(stat.S_IFLNK + 438)
                fchmode = int(stat.S_IMODE(int(stat.S_IFLNK + 438)))
                ftypemod = int(stat.S_IFMT(int(stat.S_IFLNK + 438)))
            elif(member.is_dir()):
                fmode = int(stat.S_IFDIR + 511)
                fchmode = int(stat.S_IMODE(int(stat.S_IFDIR + 511)))
                ftypemod = int(stat.S_IFMT(int(stat.S_IFDIR + 511)))
            returnval.update({lcfi: member.filename})
            if(not verbose):
                VerbosePrintOut(member.filename)
            if(verbose):
                permissions = {'access': {'0': ('---'), '1': ('--x'), '2': ('-w-'), '3': ('-wx'), '4': (
                    'r--'), '5': ('r-x'), '6': ('rw-'), '7': ('rwx')}, 'roles': {0: 'owner', 1: 'group', 2: 'other'}}
                permissionstr = ""
                for fmodval in str(oct(fmode))[-3:]:
                    permissionstr = permissionstr + \
                        permissions['access'].get(fmodval, '---')
                if(member.is_file()):
                    ftype = 0
                    permissionstr = "-" + permissionstr
                    printfname = member.filename
                elif(member.is_symlink()):
                    ftype = 2
                    permissionstr = "l" + permissionstr
                    printfname = member.name + " -> " + member.read().decode("UTF-8")
                elif(member.is_dir()):
                    ftype = 5
                    permissionstr = "d" + permissionstr
                    printfname = member.filename
                try:
                    fuid = int(os.getuid())
                except AttributeError:
                    fuid = int(0)
                except KeyError:
                    fuid = int(0)
                try:
                    fgid = int(os.getgid())
                except AttributeError:
                    fgid = int(0)
                except KeyError:
                    fgid = int(0)
                try:
                    import pwd
                    try:
                        userinfo = pwd.getpwuid(os.getuid())
                        funame = userinfo.pw_name
                    except KeyError:
                        funame = ""
                    except AttributeError:
                        funame = ""
                except ImportError:
                    funame = ""
                fgname = ""
                try:
                    import grp
                    try:
                        groupinfo = grp.getgrgid(os.getgid())
                        fgname = groupinfo.gr_name
                    except KeyError:
                        fgname = ""
                    except AttributeError:
                        fgname = ""
                except ImportError:
                    fgname = ""
                fuprint = funame
                if(len(fuprint) <= 0):
                    fuprint = str(fuid)
                fgprint = fgname
                if(len(fgprint) <= 0):
                    fgprint = str(fgid)
                VerbosePrintOut(PrintPermissionString(fmode, ftype) + " " + str(fuprint) + "/" + str(fgprint) + " " + str(
                    member.file_size).rjust(15) + " " + member.mtime.strftime('%Y-%m-%d %H:%M') + " " + printfname)
            lcfi = lcfi + 1
        if(returnfp):
            return listcatfiles['fp']
        else:
            return True

if(not py7zr_support):
    def SevenZipFileListFiles(infile, verbose=False, returnfp=False):
        return False

if(py7zr_support):
    def SevenZipFileListFiles(infile, verbose=False, returnfp=False):
        logging.basicConfig(format="%(message)s",
                            stream=sys.stdout, level=logging.DEBUG)
        if(not os.path.exists(infile) or not os.path.isfile(infile)):
            return False
        lcfi = 0
        returnval = {}
        szpfp = py7zr.SevenZipFile(infile, mode="r")
        file_content = szpfp.readall()
        #sztest = szpfp.testzip();
        sztestalt = szpfp.test()
        if(sztestalt):
            VerbosePrintOut("Bad file found!")
        for member in sorted(szpfp.list(), key=lambda x: x.filename):
            if(re.findall("^[.|/]", member.filename)):
                fname = member.filename
            else:
                fname = "./"+member.filename
            if(not member.is_directory):
                fpremode = int(stat.S_IFREG + 438)
            elif(member.is_directory):
                fpremode = int(stat.S_IFDIR + 511)
            fwinattributes = int(0)
            if(member.is_directory):
                fmode = int(stat.S_IFDIR + 511)
                fchmode = int(stat.S_IMODE(int(stat.S_IFDIR + 511)))
                ftypemod = int(stat.S_IFMT(int(stat.S_IFDIR + 511)))
            else:
                fmode = int(stat.S_IFLNK + 438)
                fchmode = int(stat.S_IMODE(int(stat.S_IFLNK + 438)))
                ftypemod = int(stat.S_IFMT(int(stat.S_IFLNK + 438)))
            returnval.update({lcfi: member.filename})
            if(not verbose):
                VerbosePrintOut(member.filename)
            if(verbose):
                permissions = {'access': {'0': ('---'), '1': ('--x'), '2': ('-w-'), '3': ('-wx'), '4': (
                    'r--'), '5': ('r-x'), '6': ('rw-'), '7': ('rwx')}, 'roles': {0: 'owner', 1: 'group', 2: 'other'}}
                permissionstr = ""
                for fmodval in str(oct(fmode))[-3:]:
                    permissionstr = permissionstr + \
                        permissions['access'].get(fmodval, '---')
                fsize = int("0")
                if(not member.is_directory):
                    ftype = 0
                    permissionstr = "-" + permissionstr
                    printfname = member.filename
                elif(member.is_directory):
                    ftype = 5
                    permissionstr = "d" + permissionstr
                    printfname = member.filename
                if(ftype == 0):
                    fsize = len(file_content[member.filename].read())
                    file_content[member.filename].close()
                try:
                    fuid = int(os.getuid())
                except AttributeError:
                    fuid = int(0)
                except KeyError:
                    fuid = int(0)
                try:
                    fgid = int(os.getgid())
                except AttributeError:
                    fgid = int(0)
                except KeyError:
                    fgid = int(0)
                try:
                    import pwd
                    try:
                        userinfo = pwd.getpwuid(os.getuid())
                        funame = userinfo.pw_name
                    except KeyError:
                        funame = ""
                    except AttributeError:
                        funame = ""
                except ImportError:
                    funame = ""
                fgname = ""
                try:
                    import grp
                    try:
                        groupinfo = grp.getgrgid(os.getgid())
                        fgname = groupinfo.gr_name
                    except KeyError:
                        fgname = ""
                    except AttributeError:
                        fgname = ""
                except ImportError:
                    fgname = ""
                fuprint = funame
                if(len(fuprint) <= 0):
                    fuprint = str(fuid)
                fgprint = fgname
                if(len(fgprint) <= 0):
                    fgprint = str(fgid)
                VerbosePrintOut(PrintPermissionString(fmode, ftype) + " " + str(fuprint) + "/" + str(fgprint) + " " + str(
                    fsize).rjust(15) + " " + member.creationtime.strftime('%Y-%m-%d %H:%M') + " " + printfname)
            lcfi = lcfi + 1
        if(returnfp):
            return listcatfiles['fp']
        else:
            return True


def InFileListFiles(infile, verbose=False, formatspecs=__file_format_dict__, returnfp=False):
    logging.basicConfig(format="%(message)s",
                        stream=sys.stdout, level=logging.DEBUG)
    checkcompressfile = CheckCompressionSubType(infile, formatspecs, True)
    if(checkcompressfile == "tarfile" and TarFileCheck(infile)):
        return TarFileListFiles(infile, verbose, returnfp)
    elif(checkcompressfile == "zipfile" and zipfile.is_zipfile(infile)):
        return ZipFileListFiles(infile, verbose, returnfp)
    elif(rarfile_support and checkcompressfile == "rarfile" and (rarfile.is_rarfile(infile) or rarfile.is_rarfile_sfx(infile))):
        return RarFileListFiles(infile, verbose, returnfp)
    elif(py7zr_support and checkcompressfile == "7zipfile" and py7zr.is_7zfile(infile)):
        return SevenZipFileListFiles(infile, verbose, returnfp)
    elif(checkcompressfile == formatspecs['format_magic']):
        return ArchiveFileListFiles(infile, 0, 0, False, formatspecs, verbose, returnfp)
    else:
        return False
    return False


def ListDirListFiles(infiles, dirlistfromtxt=False, compression="auto", compresswholefile=True, compressionlevel=None, followlink=False, seekstart=0, seekend=0, skipchecksum=False, checksumtype=["crc32", "crc32", "crc32"], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
    outarray = BytesIO()
    packcat = PackArchiveFile(infiles, outarray, dirlistfromtxt, compression, compresswholefile,
                              compressionlevel, followlink, checksumtype, formatspecs, False, True)
    listcatfiles = ArchiveFileListFiles(
        outarray, seekstart, seekend, skipchecksum, formatspecs, verbose, returnfp)
    return listcatfiles


def ListDirListFilesAlt(infiles, dirlistfromtxt=False, followlink=False, listonly=False, contentasfile=True, seekstart=0, seekend=0, skipchecksum=False, checksumtype=["crc32", "crc32", "crc32"], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
    outarray = ListDirToArrayAlt(infiles, dirlistfromtxt, followlink,
                                 listonly, contentasfile, checksumtype, formatspecs, verbose)
    listcatfiles = ArchiveFileListFiles(
        outarray, seekstart, seekend, skipchecksum, formatspecs, verbose, returnfp)
    return listcatfiles


def PackArchiveFileFromListDirAlt(infiles, outfile, dirlistfromtxt=False, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, followlink=False, skipchecksum=False, checksumtype=["crc32", "crc32", "crc32"], extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
    outarray = ListDirToArrayAlt(infiles, dirlistfromtxt, followlink,
                                 False, True, checksumtype, extradata, formatspecs, False)
    listcatfiles = RePackArchiveFile(outarray, outfile, compression, compresswholefile, compressionlevel, compressionuselist,
                                     followlink, checksumtype, skipchecksum, extradata, formatspecs, verbose, returnfp)
    return listcatfiles


def PackArchiveFileFromTarFileAlt(infile, outfile, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["crc32", "crc32", "crc32"], extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
    outarray = TarFileToArrayAlt(
        infile, False, True, checksumtype, extradata, formatspecs, False)
    listcatfiles = RePackArchiveFile(outarray, outfile, compression, compresswholefile,
                                     compressionlevel, compressionuselist, False, checksumtype, False, extradata, formatspecs, verbose, returnfp)
    return listcatfiles


def PackArchiveFileFromZipFileAlt(infile, outfile, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["crc32", "crc32", "crc32"], extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
    outarray = ZipFileToArrayAlt(
        infile, False, True, checksumtype, extradata, formatspecs, False)
    listcatfiles = RePackArchiveFile(outarray, outfile, compression, compresswholefile,
                                     compressionlevel, compressionuselist, False, checksumtype, False, extradata, formatspecs, verbose, returnfp)
    return listcatfiles


if(not rarfile_support):
    def PackArchiveFileFromRarFileAlt(infile, outfile, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["crc32", "crc32", "crc32"], extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
        return False

if(rarfile_support):
    def PackArchiveFileFromRarFileAlt(infile, outfile, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["crc32", "crc32", "crc32"], extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
        outarray = RarFileToArrayAlt(
            infile, False, True, checksumtype, extradata, formatspecs, False)
        listcatfiles = RePackArchiveFile(outarray, outfile, compression, compresswholefile,
                                         compressionlevel, compressionuselist, False, checksumtype, False, extradata, formatspecs, verbose, returnfp)
        return listcatfiles


if(not py7zr_support):
    def PackArchiveFileFromSevenZipFileAlt(infile, outfile, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["crc32", "crc32", "crc32"], extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
        return False

if(py7zr_support):
    def PackArchiveFileFromSevenZipFileAlt(infile, outfile, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["crc32", "crc32", "crc32"], extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
        outarray = SevenZipFileToArrayAlt(
            infile, False, True, checksumtype, extradata, formatspecs, False)
        listcatfiles = RePackArchiveFile(outarray, outfile, compression, compresswholefile,
                                         compressionlevel, compressionuselist, False, checksumtype, False, extradata, formatspecs, verbose, returnfp)
        return listcatfiles


def download_file_from_ftp_file(url):
    urlparts = urlparse(url)
    file_name = os.path.basename(urlparts.path)
    file_dir = os.path.dirname(urlparts.path)
    if(urlparts.username is not None):
        ftp_username = urlparts.username
    else:
        ftp_username = "anonymous"
    if(urlparts.password is not None):
        ftp_password = urlparts.password
    elif(urlparts.password is None and urlparts.username == "anonymous"):
        ftp_password = "anonymous"
    else:
        ftp_password = ""
    if(urlparts.scheme == "ftp"):
        ftp = FTP()
    elif(urlparts.scheme == "ftps" and ftpssl):
        ftp = FTP_TLS()
    else:
        return False
    if(urlparts.scheme == "sftp"):
        if(__use_pysftp__):
            return download_file_from_pysftp_file(url)
        else:
            return download_file_from_sftp_file(url)
    elif(urlparts.scheme == "http" or urlparts.scheme == "https"):
        return download_file_from_http_file(url)
    ftp_port = urlparts.port
    if(urlparts.port is None):
        ftp_port = 21
    try:
        ftp.connect(urlparts.hostname, ftp_port)
    except socket.gaierror:
        log.info("Error With URL "+url)
        return False
    except socket.timeout:
        log.info("Error With URL "+url)
        return False
    ftp.login(urlparts.username, urlparts.password)
    if(urlparts.scheme == "ftps"):
        ftp.prot_p()
    ftpfile = BytesIO()
    ftp.retrbinary("RETR "+urlparts.path, ftpfile.write)
    #ftp.storbinary("STOR "+urlparts.path, ftpfile.write);
    ftp.close()
    ftpfile.seek(0, 0)
    return ftpfile


def download_file_from_ftp_string(url):
    ftpfile = download_file_from_ftp_file(url)
    return ftpfile.read()


def upload_file_to_ftp_file(ftpfile, url):
    urlparts = urlparse(url)
    file_name = os.path.basename(urlparts.path)
    file_dir = os.path.dirname(urlparts.path)
    if(urlparts.username is not None):
        ftp_username = urlparts.username
    else:
        ftp_username = "anonymous"
    if(urlparts.password is not None):
        ftp_password = urlparts.password
    elif(urlparts.password is None and urlparts.username == "anonymous"):
        ftp_password = "anonymous"
    else:
        ftp_password = ""
    if(urlparts.scheme == "ftp"):
        ftp = FTP()
    elif(urlparts.scheme == "ftps" and ftpssl):
        ftp = FTP_TLS()
    else:
        return False
    if(urlparts.scheme == "sftp"):
        if(__use_pysftp__):
            return upload_file_to_pysftp_file(url)
        else:
            return upload_file_to_sftp_file(url)
    elif(urlparts.scheme == "http" or urlparts.scheme == "https"):
        return False
    ftp_port = urlparts.port
    if(urlparts.port is None):
        ftp_port = 21
    try:
        ftp.connect(urlparts.hostname, ftp_port)
    except socket.gaierror:
        log.info("Error With URL "+url)
        return False
    except socket.timeout:
        log.info("Error With URL "+url)
        return False
    ftp.login(urlparts.username, urlparts.password)
    if(urlparts.scheme == "ftps"):
        ftp.prot_p()
    ftp.storbinary("STOR "+urlparts.path, ftpfile)
    ftp.close()
    ftpfile.seek(0, 0)
    return ftpfile


def upload_file_to_ftp_string(ftpstring, url):
    ftpfileo = BytesIO(ftpstring)
    ftpfile = upload_file_to_ftp_file(ftpfileo, url)
    ftpfileo.close()
    return ftpfile


class RawIteratorWrapper:
    def __init__(self, iterator):
        self.iterator = iterator
        self.buffer = b""
        self._iterator_exhausted = False

    def read(self, size=-1):
        if self._iterator_exhausted:
            return b''
        while size < 0 or len(self.buffer) < size:
            try:
                chunk = next(self.iterator)
                self.buffer += chunk
            except StopIteration:
                self._iterator_exhausted = True
                break
        if size < 0:
            size = len(self.buffer)
        result, self.buffer = self.buffer[:size], self.buffer[size:]
        return result


def download_file_from_http_file(url, headers=None, usehttp=__use_http_lib__):
    if headers is None:
        headers = {}
    urlparts = urlparse(url)
    username = urlparts.username
    password = urlparts.password

    # Rebuild URL without username and password
    netloc = urlparts.hostname or ''
    if urlparts.port:
        netloc += ':' + str(urlparts.port)
    rebuilt_url = urlunparse((urlparts.scheme, netloc, urlparts.path,
                              urlparts.params, urlparts.query, urlparts.fragment))

    # Handle SFTP/FTP
    if urlparts.scheme == "sftp":
        if __use_pysftp__:
            return download_file_from_pysftp_file(url)
        else:
            return download_file_from_sftp_file(url)
    elif urlparts.scheme == "ftp" or urlparts.scheme == "ftps":
        return download_file_from_ftp_file(url)

    # Create a temporary file object
    httpfile = BytesIO()

    # 1) Requests branch
    if usehttp == 'requests' and haverequests:
        if username and password:
            response = requests.get(
                rebuilt_url, headers=headers, auth=(username, password), stream=True
            )
        else:
            response = requests.get(rebuilt_url, headers=headers, stream=True)
        response.raw.decode_content = True
        shutil.copyfileobj(response.raw, httpfile)

    # 2) HTTPX branch
    elif usehttp == 'httpx' and havehttpx:
        with httpx.Client(follow_redirects=True) as client:
            if username and password:
                response = client.get(
                    rebuilt_url, headers=headers, auth=(username, password)
                )
            else:
                response = client.get(rebuilt_url, headers=headers)
            raw_wrapper = RawIteratorWrapper(response.iter_bytes())
            shutil.copyfileobj(raw_wrapper, httpfile)

    # 3) Mechanize branch
    elif usehttp == 'mechanize' and havemechanize:
        # Create a mechanize browser
        br = mechanize.Browser()
        # Optional: configure mechanize (disable robots.txt, handle redirects, etc.)
        br.set_handle_robots(False)
        # If you need custom headers, add them as a list of (header_name, header_value)
        if headers:
            br.addheaders = list(headers.items())

        # If you need to handle basic auth:
        if username and password:
            # Mechanize has its own password manager; this is one way to do it:
            br.add_password(rebuilt_url, username, password)

        # Open the URL and copy the response to httpfile
        response = br.open(rebuilt_url)
        shutil.copyfileobj(response, httpfile)

    # 4) Fallback to urllib
    else:
        request = Request(rebuilt_url, headers=headers)
        if username and password:
            password_mgr = HTTPPasswordMgrWithDefaultRealm()
            password_mgr.add_password(None, rebuilt_url, username, password)
            auth_handler = HTTPBasicAuthHandler(password_mgr)
            opener = build_opener(auth_handler)
        else:
            opener = build_opener()
        response = opener.open(request)
        shutil.copyfileobj(response, httpfile)

    # Reset file pointer to the start before returning
    httpfile.seek(0, 0)
    return httpfile


def download_file_from_http_string(url, headers=geturls_headers_pycatfile_python_alt, usehttp=__use_http_lib__):
    httpfile = download_file_from_http_file(url, headers, usehttp)
    return httpfile.read()


if(haveparamiko):
    def download_file_from_sftp_file(url):
        urlparts = urlparse(url)
        file_name = os.path.basename(urlparts.path)
        file_dir = os.path.dirname(urlparts.path)
        sftp_port = urlparts.port
        if(urlparts.port is None):
            sftp_port = 22
        else:
            sftp_port = urlparts.port
        if(urlparts.username is not None):
            sftp_username = urlparts.username
        else:
            sftp_username = "anonymous"
        if(urlparts.password is not None):
            sftp_password = urlparts.password
        elif(urlparts.password is None and urlparts.username == "anonymous"):
            sftp_password = "anonymous"
        else:
            sftp_password = ""
        if(urlparts.scheme == "ftp"):
            return download_file_from_ftp_file(url)
        elif(urlparts.scheme == "http" or urlparts.scheme == "https"):
            return download_file_from_http_file(url)
        if(urlparts.scheme != "sftp"):
            return False
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(urlparts.hostname, port=sftp_port,
                        username=urlparts.username, password=urlparts.password)
        except paramiko.ssh_exception.SSHException:
            return False
        except socket.gaierror:
            log.info("Error With URL "+url)
            return False
        except socket.timeout:
            log.info("Error With URL "+url)
            return False
        sftp = ssh.open_sftp()
        sftpfile = BytesIO()
        sftp.getfo(urlparts.path, sftpfile)
        sftp.close()
        ssh.close()
        sftpfile.seek(0, 0)
        return sftpfile
else:
    def download_file_from_sftp_file(url):
        return False

if(haveparamiko):
    def download_file_from_sftp_string(url):
        sftpfile = download_file_from_sftp_file(url)
        return sftpfile.read()
else:
    def download_file_from_sftp_string(url):
        return False

if(haveparamiko):
    def upload_file_to_sftp_file(sftpfile, url):
        urlparts = urlparse(url)
        file_name = os.path.basename(urlparts.path)
        file_dir = os.path.dirname(urlparts.path)
        sftp_port = urlparts.port
        if(urlparts.port is None):
            sftp_port = 22
        else:
            sftp_port = urlparts.port
        if(urlparts.username is not None):
            sftp_username = urlparts.username
        else:
            sftp_username = "anonymous"
        if(urlparts.password is not None):
            sftp_password = urlparts.password
        elif(urlparts.password is None and urlparts.username == "anonymous"):
            sftp_password = "anonymous"
        else:
            sftp_password = ""
        if(urlparts.scheme == "ftp"):
            return upload_file_to_ftp_file(url)
        elif(urlparts.scheme == "http" or urlparts.scheme == "https"):
            return False
        if(urlparts.scheme != "sftp"):
            return False
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(urlparts.hostname, port=sftp_port,
                        username=urlparts.username, password=urlparts.password)
        except paramiko.ssh_exception.SSHException:
            return False
        except socket.gaierror:
            log.info("Error With URL "+url)
            return False
        except socket.timeout:
            log.info("Error With URL "+url)
            return False
        sftp = ssh.open_sftp()
        sftp.putfo(sftpfile, urlparts.path)
        sftp.close()
        ssh.close()
        sftpfile.seek(0, 0)
        return sftpfile
else:
    def upload_file_to_sftp_file(sftpfile, url):
        return False

if(haveparamiko):
    def upload_file_to_sftp_string(sftpstring, url):
        sftpfileo = BytesIO(sftpstring)
        sftpfile = upload_file_to_sftp_files(ftpfileo, url)
        sftpfileo.close()
        return sftpfile
else:
    def upload_file_to_sftp_string(url):
        return False

if(havepysftp):
    def download_file_from_pysftp_file(url):
        urlparts = urlparse(url)
        file_name = os.path.basename(urlparts.path)
        file_dir = os.path.dirname(urlparts.path)
        sftp_port = urlparts.port
        if(urlparts.port is None):
            sftp_port = 22
        else:
            sftp_port = urlparts.port
        if(urlparts.username is not None):
            sftp_username = urlparts.username
        else:
            sftp_username = "anonymous"
        if(urlparts.password is not None):
            sftp_password = urlparts.password
        elif(urlparts.password is None and urlparts.username == "anonymous"):
            sftp_password = "anonymous"
        else:
            sftp_password = ""
        if(urlparts.scheme == "ftp"):
            return download_file_from_ftp_file(url)
        elif(urlparts.scheme == "http" or urlparts.scheme == "https"):
            return download_file_from_http_file(url)
        if(urlparts.scheme != "sftp"):
            return False
        try:
            pysftp.Connection(urlparts.hostname, port=sftp_port,
                              username=urlparts.username, password=urlparts.password)
        except paramiko.ssh_exception.SSHException:
            return False
        except socket.gaierror:
            log.info("Error With URL "+url)
            return False
        except socket.timeout:
            log.info("Error With URL "+url)
            return False
        sftp = ssh.open_sftp()
        sftpfile = BytesIO()
        sftp.getfo(urlparts.path, sftpfile)
        sftp.close()
        ssh.close()
        sftpfile.seek(0, 0)
        return sftpfile
else:
    def download_file_from_pysftp_file(url):
        return False

if(havepysftp):
    def download_file_from_pysftp_string(url):
        sftpfile = download_file_from_pysftp_file(url)
        return sftpfile.read()
else:
    def download_file_from_pyftp_string(url):
        return False

if(havepysftp):
    def upload_file_to_pysftp_file(sftpfile, url):
        urlparts = urlparse(url)
        file_name = os.path.basename(urlparts.path)
        file_dir = os.path.dirname(urlparts.path)
        sftp_port = urlparts.port
        if(urlparts.port is None):
            sftp_port = 22
        else:
            sftp_port = urlparts.port
        if(urlparts.username is not None):
            sftp_username = urlparts.username
        else:
            sftp_username = "anonymous"
        if(urlparts.password is not None):
            sftp_password = urlparts.password
        elif(urlparts.password is None and urlparts.username == "anonymous"):
            sftp_password = "anonymous"
        else:
            sftp_password = ""
        if(urlparts.scheme == "ftp"):
            return upload_file_to_ftp_file(url)
        elif(urlparts.scheme == "http" or urlparts.scheme == "https"):
            return False
        if(urlparts.scheme != "sftp"):
            return False
        try:
            pysftp.Connection(urlparts.hostname, port=sftp_port,
                              username=urlparts.username, password=urlparts.password)
        except paramiko.ssh_exception.SSHException:
            return False
        except socket.gaierror:
            log.info("Error With URL "+url)
            return False
        except socket.timeout:
            log.info("Error With URL "+url)
            return False
        sftp = ssh.open_sftp()
        sftp.putfo(sftpfile, urlparts.path)
        sftp.close()
        ssh.close()
        sftpfile.seek(0, 0)
        return sftpfile
else:
    def upload_file_to_pysftp_file(sftpfile, url):
        return False

if(havepysftp):
    def upload_file_to_pysftp_string(sftpstring, url):
        sftpfileo = BytesIO(sftpstring)
        sftpfile = upload_file_to_pysftp_files(ftpfileo, url)
        sftpfileo.close()
        return sftpfile
else:
    def upload_file_to_pysftp_string(url):
        return False


def download_file_from_internet_file(url, headers=geturls_headers_pycatfile_python_alt, usehttp=__use_http_lib__):
    urlparts = urlparse(url)
    if(urlparts.scheme == "http" or urlparts.scheme == "https"):
        return download_file_from_http_file(url, headers, usehttp)
    elif(urlparts.scheme == "ftp" or urlparts.scheme == "ftps"):
        return download_file_from_ftp_file(url)
    elif(urlparts.scheme == "sftp"):
        if(__use_pysftp__ and havepysftp):
            return download_file_from_pysftp_file(url)
        else:
            return download_file_from_sftp_file(url)
    else:
        return False
    return False


def download_file_from_internet_uncompress_file(url, headers=geturls_headers_pycatfile_python_alt, formatspecs=__file_format_dict__):
    fp = download_file_from_internet_file(url)
    fp = UncompressArchiveFile(fp, formatspecs)
    fp.seek(0, 0)
    if(not fp):
        return False
    return fp


def download_file_from_internet_string(url, headers=geturls_headers_pycatfile_python_alt):
    urlparts = urlparse(url)
    if(urlparts.scheme == "http" or urlparts.scheme == "https"):
        return download_file_from_http_string(url, headers)
    elif(urlparts.scheme == "ftp" or urlparts.scheme == "ftps"):
        return download_file_from_ftp_string(url)
    elif(urlparts.scheme == "sftp"):
        if(__use_pysftp__ and havepysftp):
            return download_file_from_pysftp_string(url)
        else:
            return download_file_from_sftp_string(url)
    else:
        return False
    return False


def download_file_from_internet_uncompress_string(url, headers=geturls_headers_pycatfile_python_alt, formatspecs=__file_format_dict__):
    fp = download_file_from_internet_string(url)
    fp = UncompressArchiveFile(fp, formatspecs)
    fp.seek(0, 0)
    if(not fp):
        return False
    return fp


def upload_file_to_internet_file(ifp, url):
    urlparts = urlparse(url)
    if(urlparts.scheme == "http" or urlparts.scheme == "https"):
        return False
    elif(urlparts.scheme == "ftp" or urlparts.scheme == "ftps"):
        return upload_file_to_ftp_file(ifp, url)
    elif(urlparts.scheme == "sftp"):
        if(__use_pysftp__ and havepysftp):
            return upload_file_to_pysftp_file(ifp, url)
        else:
            return upload_file_to_sftp_file(ifp, url)
    else:
        return False
    return False


def upload_file_to_internet_compress_file(ifp, url, compression="auto", compressionlevel=None, formatspecs=__file_format_dict__):
    fp = CompressArchiveFile(
        fp, compression, compressionlevel, formatspecs)
    if(not catfileout):
        return False
    fp.seek(0, 0)
    upload_file_to_internet_file(fp, outfile)
    return True


def upload_file_to_internet_string(ifp, url):
    urlparts = urlparse(url)
    if(urlparts.scheme == "http" or urlparts.scheme == "https"):
        return False
    elif(urlparts.scheme == "ftp" or urlparts.scheme == "ftps"):
        return upload_file_to_ftp_string(ifp, url)
    elif(urlparts.scheme == "sftp"):
        if(__use_pysftp__ and havepysftp):
            return upload_file_to_pysftp_string(ifp, url)
        else:
            return upload_file_to_sftp_string(ifp, url)
    else:
        return False
    return False


def upload_file_to_internet_compress_string(ifp, url, compression="auto", compressionlevel=None, formatspecs=__file_format_dict__):
    fp = CompressArchiveFile(
        BytesIO(ifp), compression, compressionlevel, formatspecs)
    if(not catfileout):
        return False
    fp.seek(0, 0)
    upload_file_to_internet_file(fp, outfile)
    return True


try:
    if(hasattr(shutil, "register_archive_format")):
        # Register the packing format
        shutil.register_archive_format(
            __file_format_name__, PackArchiveFileFunc, description='Pack concatenated files')
except shutil.RegistryError:
    pass

try:
    if(hasattr(shutil, "register_unpack_format")):
        # Register the unpacking format
        shutil.register_unpack_format(__file_format_name__, archivefile_extensions,
                                      UnPackArchiveFileFunc, description='UnPack concatenated files')
except shutil.RegistryError:
    pass
