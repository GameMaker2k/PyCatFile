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

    $FileInfo: pycatfile.py - Last Update: 10/1/2025 Ver. 0.23.0 RC 1 - Author: cooldude2k $
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
import struct
import hashlib
import inspect
import datetime
import tempfile
import logging
import zipfile
import binascii
import platform
from io import StringIO, BytesIO
import posixpath as pp  # POSIX-safe joins/normpaths
try:
    from backports import tempfile
except ImportError:
    import tempfile

try:
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from socketserver import TCPServer
    from urllib.parse import urlparse as _urlparse, parse_qs as _parse_qs
    import base64 as _b64
except ImportError:
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
    from SocketServer import TCPServer
    from urlparse import urlparse as _urlparse, parse_qs as _parse_qs
    import base64 as _b64

# FTP Support
ftpssl = True
try:
    from ftplib import FTP, FTP_TLS, all_errors
except ImportError:
    ftpssl = False
    from ftplib import FTP, all_errors

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

PY2 = (sys.version_info[0] == 2)
try:
    unicode  # Py2
except NameError:  # Py3
    unicode = str

def to_text(s, encoding="utf-8", errors="ignore"):
    if s is None:
        return u""
    if isinstance(s, unicode):
        return s
    if isinstance(s, (bytes, bytearray)):
        return s.decode(encoding, errors)
    return unicode(s)

baseint = []
try:
    baseint.append(long)
    baseint.insert(0, int)
except NameError:
    baseint.append(int)
baseint = tuple(baseint)

# URL Parsing
try:
    # Python 3
    from urllib.parse import urlparse, urlunparse, parse_qs, unquote
    from urllib.request import url2pathname
except ImportError:
    # Python 2
    from urlparse import urlparse, urlunparse, parse_qs
    from urllib import unquote, url2pathname

# Windows-specific setup
if os.name == "nt":
    import io
    def _wrap(stream):
        buf = getattr(stream, "buffer", None)
        is_tty = getattr(stream, "isatty", lambda: False)()
        if buf is not None and is_tty:
            try:
                return io.TextIOWrapper(buf, encoding="UTF-8", errors="replace", line_buffering=True)
            except Exception:
                return stream
        return stream
    sys.stdout = _wrap(sys.stdout)
    sys.stderr = _wrap(sys.stderr)

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

__upload_proto_support__ = "^(http|https|ftp|ftps|sftp|scp|tcp|udp)://"
__download_proto_support__ = "^(http|https|ftp|ftps|sftp|scp|tcp|udp)://"
__use_pysftp__ = False
__upload_proto_support__ = "^(http|https|ftp|ftps|sftp|scp|tcp|udp)://"
__download_proto_support__ = "^(http|https|ftp|ftps|sftp|scp|tcp|udp)://"
if(not havepysftp):
    __use_pysftp__ = False
__use_http_lib__ = "httpx"
if(__use_http_lib__ == "httpx" and haverequests and not havehttpx):
    __use_http_lib__ = "requests"
if(__use_http_lib__ == "requests" and havehttpx and not haverequests):
    __use_http_lib__ = "httpx"
if((__use_http_lib__ == "httpx" or __use_http_lib__ == "requests") and not havehttpx and not haverequests):
    __use_http_lib__ = "urllib"
# Define a function to check if var contains only non-printable chars
all_np_chars = [chr(i) for i in range(128)]
def is_only_nonprintable(var):
    """True if every character is non-printable (Py2/3-safe, handles bytes)."""
    if var is None:
        return True
    s = to_text(var)
    # In Py2, some unicode categories behave differently; isprintable is Py3-only.
    # We'll implement a portable check: letters, numbers, punctuation, and common whitespace are printable.
    try:
        # Py3 fast path
        return all(not ch.isprintable() for ch in s)
    except AttributeError:
        # Py2 path
        import unicodedata
        def _is_printable(ch):
            cat = unicodedata.category(ch)
            # Categories starting with 'C' are control/non-assigned/surrogates
            if cat.startswith('C'):
                return False
            # treat space and common whitespace as printable
            if ch in u"\t\n\r\x0b\x0c ":
                return True
            return True
        return all(not _is_printable(ch) for ch in s)
__file_format_multi_dict__ = {}
__file_format_default__ = "CatFile"
__include_defaults__ = True
__use_inmemfile__ = False
__program_name__ = "Py"+__file_format_default__
__use_env_file__ = True
__use_ini_file__ = True
__use_ini_name__ = "catfile.ini"
__use_json_file__ = False
__use_json_name__ = "catfile.json"
if('PYCATFILE_CONFIG_FILE' in os.environ and os.path.exists(os.environ['PYCATFILE_CONFIG_FILE']) and __use_env_file__):
    scriptconf = os.environ['PYCATFILE_CONFIG_FILE']
else:
    prescriptpath = get_importing_script_path()
    if(prescriptpath is not None):
        scriptconf = os.path.join(os.path.dirname(prescriptpath), __use_ini_name__)
    else:
        scriptconf = ""
if os.path.exists(scriptconf):
    __config_file__ = scriptconf
else:
    __config_file__ = os.path.join(os.path.dirname(os.path.realpath(__file__)), __use_ini_name__)
if __use_ini_file__ and os.path.exists(__config_file__):
    config = configparser.ConfigParser()
    config.read(__config_file__)
    def decode_unicode_escape(value):
        if sys.version_info[0] < 3:  # Python 2
            return value.decode('unicode_escape')
        else:  # Python 3
            return bytes(value, 'UTF-8').decode('unicode_escape')
    __file_format_default__ = decode_unicode_escape(config.get('config', 'default'))
    __program_name__ = decode_unicode_escape(config.get('config', 'proname'))
    __include_defaults__ = config.getboolean('config', 'includedef')
    __use_inmemfile__ = config.getboolean('config', 'inmemfile')
    # Loop through all sections
    for section in config.sections():
        required_keys = [
            "len", "hex", "ver", "name", 
            "magic", "delimiter", "extension",
            "newstyle", "advancedlist", "altinode"
        ]
        if section != "config" and all(key in config[section] for key in required_keys):
            delim = decode_unicode_escape(config.get(section, 'delimiter'))
            if(not is_only_nonprintable(delim)):
                delim = "\x00" * len("\x00")
            __file_format_multi_dict__.update( { decode_unicode_escape(config.get(section, 'magic')): {'format_name': decode_unicode_escape(config.get(section, 'name')), 'format_magic': decode_unicode_escape(config.get(section, 'magic')), 'format_len': config.getint(section, 'len'), 'format_hex': config.get(section, 'hex'), 'format_delimiter': delim, 'format_ver': config.get(section, 'ver'), 'new_style': config.getboolean(section, 'newstyle'), 'use_advanced_list': config.getboolean(section, 'advancedlist'), 'use_alt_inode': config.getboolean(section, 'altinode'), 'format_extension': decode_unicode_escape(config.get(section, 'extension')) } } )
        if not __file_format_multi_dict__ and not __include_defaults__:
            __include_defaults__ = True
elif __use_ini_file__ and not os.path.exists(__config_file__):
    __use_ini_file__ = False
    __include_defaults__ = True
if not __use_ini_file__ and not __include_defaults__:
    __include_defaults__ = True
if(__include_defaults__):
    if("CatFile" not in __file_format_multi_dict__):
        __file_format_multi_dict__.update( { 'CatFile': {'format_name': "CatFile", 'format_magic': "CatFile", 'format_len': 7, 'format_hex': "43617446696c65", 'format_delimiter': "\x00", 'format_ver': "001", 'new_style': True, 'use_advanced_list': True, 'use_alt_inode': False, 'format_extension': ".cat" } } )
    if("NekoFile" not in __file_format_multi_dict__):
        __file_format_multi_dict__.update( { 'NekoFile': {'format_name': "NekoFile", 'format_magic': "NekoFile", 'format_len': 8, 'format_hex': "4e656b6f46696c65", 'format_delimiter': "\x00", 'format_ver': "001", 'new_style': True, 'use_advanced_list': True, 'use_alt_inode': False, 'format_extension': ".neko" } } )
    if("ねこファイル" not in __file_format_multi_dict__):
        __file_format_multi_dict__.update( { 'ねこファイル': {'format_name': "NekoFairu", 'format_magic': "ねこファイル", 'format_len': 18, 'format_hex': "e381ade38193e38395e382a1e382a4e383ab", 'format_delimiter': "\x00", 'format_ver': "001", 'new_style': True, 'use_advanced_list': True, 'use_alt_inode': False, 'format_extension': ".ねこ" } } )
    if("ネコファイル" not in __file_format_multi_dict__):
        __file_format_multi_dict__.update( { 'ネコファイル': {'format_name': "NekoFairu", 'format_magic': "ネコファイル", 'format_len': 18, 'format_hex': "e381ade38193e38395e382a1e382a4e383ab", 'format_delimiter': "\x00", 'format_ver': "001", 'new_style': True, 'use_advanced_list': True, 'use_alt_inode': False, 'format_extension': ".ネコ" } } )
    if("네코파일" not in __file_format_multi_dict__):
        __file_format_multi_dict__.update( { '네코파일': {'format_name': "NekoPa-il", 'format_magic': "네코파일", 'format_len': 12, 'format_hex': "eb84a4ecbd94ed8c8cec9dbc", 'format_delimiter': "\x00", 'format_ver': "001", 'new_style': True, 'use_advanced_list': True, 'use_alt_inode': False, 'format_extension': ".네코" } } )
    if("고양이파일" not in __file_format_multi_dict__):
        __file_format_multi_dict__.update( { '고양이파일': {'format_name': "GoyangiPa-il", 'format_magic': "고양이파일", 'format_len': 15, 'format_hex': "eab3a0ec9691ec9db4ed8c8cec9dbc", 'format_delimiter': "\x00", 'format_ver': "001", 'new_style': True, 'use_advanced_list': True, 'use_alt_inode': False, 'format_extension': ".고양이" } } )
    if("内酷法伊鲁" not in __file_format_multi_dict__):
        __file_format_multi_dict__.update( { '内酷法伊鲁': {'format_name': "NèiKùFǎYīLǔ", 'format_magic': "内酷法伊鲁", 'format_len': 15, 'format_hex': "e58685e985b7e6b395e4bc8ae9b281", 'format_delimiter': "\x00", 'format_ver': "001", 'new_style': True, 'use_advanced_list': True, 'use_alt_inode': False, 'format_extension': ".内酷" } } )
    if("猫文件" not in __file_format_multi_dict__):
        __file_format_multi_dict__.update( { '猫文件': {'format_name': "MāoWénjiàn", 'format_magic': "猫文件", 'format_len': 9, 'format_hex': "e78cabe69687e4bbb6", 'format_delimiter': "\x00", 'format_ver': "001", 'new_style': True, 'use_advanced_list': True, 'use_alt_inode': False, 'format_extension': ".猫" } } )
if(__file_format_default__ not in __file_format_multi_dict__):
    __file_format_default__ = next(iter(__file_format_multi_dict__))
__file_format_name__ = __file_format_multi_dict__[__file_format_default__]['format_name']
__file_format_magic__ = __file_format_multi_dict__[__file_format_default__]['format_magic']
__file_format_len__ = __file_format_multi_dict__[__file_format_default__]['format_len']
__file_format_hex__ = __file_format_multi_dict__[__file_format_default__]['format_hex']
__file_format_delimiter__ = __file_format_multi_dict__[__file_format_default__]['format_delimiter']
__file_format_ver__ = __file_format_multi_dict__[__file_format_default__]['format_ver']
__use_new_style__ = __file_format_multi_dict__[__file_format_default__]['new_style']
__use_advanced_list__ = __file_format_multi_dict__[__file_format_default__]['use_advanced_list']
__use_alt_inode__ = __file_format_multi_dict__[__file_format_default__]['use_alt_inode']
__file_format_extension__ = __file_format_multi_dict__[__file_format_default__]['format_extension']
__file_format_dict__ = __file_format_multi_dict__[__file_format_default__]
__project__ = __program_name__
__project_url__ = "https://github.com/GameMaker2k/PyCatFile"
__version_info__ = (0, 23, 0, "RC 1", 1)
__version_date_info__ = (2025, 10, 1, "RC 1", 1)
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
    __version__ = str(__version_info__[0]) + "." + str(__version_info__[1]) + "." + str(__version_info__[2])

# ===== Module-level type code table & helpers (reuse anywhere) =====

FT = {
    "FILE": 0,
    "HARDLINK": 1,
    "SYMLINK": 2,
    "CHAR": 3,
    "BLOCK": 4,
    "DIR": 5,
    "FIFO": 6,
    "CONTAGIOUS": 7,   # treated like regular file
    "SOCK": 8,
    "DOOR": 9,
    "PORT": 10,
    "WHT": 11,
    "SPARSE": 12,
    "JUNCTION": 13,
}

BASE_CATEGORY_BY_CODE = {
    0:  "files",
    1:  "hardlinks",
    2:  "symlinks",
    3:  "characters",
    4:  "blocks",
    5:  "directories",
    6:  "fifos",
    7:  "files",         # contagious treated as file
    8:  "sockets",
    9:  "doors",
    10: "ports",
    11: "whiteouts",
    12: "sparsefiles",
    13: "junctions",
}

# Union categories defined by which base codes should populate them.
UNION_RULES = [
    ("links",   set([FT["HARDLINK"], FT["SYMLINK"]])),
    ("devices", set([FT["CHAR"], FT["BLOCK"]])),
]

# Deterministic category order (handy for consistent output/printing).
CATEGORY_ORDER = [
    "files", "hardlinks", "symlinks", "character", "block",
    "directories", "fifo", "sockets", "doors", "ports",
    "whiteouts", "sparsefiles", "junctions", "links", "devices"
]

# Robust bitness detection
# Works on Py2 & Py3, all platforms

# Python interpreter bitness
PyBitness = "64" if struct.calcsize("P") * 8 == 64 else ("64" if sys.maxsize > 2**32 else "32")

# Operating system bitness
try:
    OSBitness = platform.architecture()[0].replace("bit", "")
except Exception:
    m = platform.machine().lower()
    OSBitness = "64" if "64" in m else "32"

geturls_ua_pyfile_python = "Mozilla/5.0 (compatible; {proname}/{prover}; +{prourl})".format(
    proname=__project__, prover=__version__, prourl=__project_url__)
if(platform.python_implementation() != ""):
    py_implementation = platform.python_implementation()
if(platform.python_implementation() == ""):
    py_implementation = "Python"
geturls_ua_pyfile_python_alt = "Mozilla/5.0 ({osver}; {archtype}; +{prourl}) {pyimp}/{pyver} (KHTML, like Gecko) {proname}/{prover}".format(osver=platform.system(
)+" "+platform.release(), archtype=platform.machine(), prourl=__project_url__, pyimp=py_implementation, pyver=platform.python_version(), proname=__project__, prover=__version__)
geturls_ua_googlebot_google = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
geturls_ua_googlebot_google_old = "Googlebot/2.1 (+http://www.google.com/bot.html)"
geturls_headers_pyfile_python = {'Referer': "http://google.com/", 'User-Agent': geturls_ua_pyfile_python, 'Accept-Encoding': "none", 'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6", 'Accept-Charset': "ISO-8859-1,ISO-8859-15,UTF-8;q=0.7,*;q=0.7", 'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'Connection': "close",
                                    'SEC-CH-UA': "\""+__project__+"\";v=\""+str(__version__)+"\", \"Not;A=Brand\";v=\"8\", \""+py_implementation+"\";v=\""+str(platform.release())+"\"", 'SEC-CH-UA-FULL-VERSION': str(__version__), 'SEC-CH-UA-PLATFORM': ""+py_implementation+"", 'SEC-CH-UA-ARCH': ""+platform.machine()+"", 'SEC-CH-UA-PLATFORM-VERSION': str(__version__), 'SEC-CH-UA-BITNESS': str(PyBitness)}
geturls_headers_pyfile_python_alt = {'Referer': "http://google.com/", 'User-Agent': geturls_ua_pyfile_python_alt, 'Accept-Encoding': "none", 'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6", 'Accept-Charset': "ISO-8859-1,ISO-8859-15,UTF-8;q=0.7,*;q=0.7", 'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'Connection': "close",
                                        'SEC-CH-UA': "\""+__project__+"\";v=\""+str(__version__)+"\", \"Not;A=Brand\";v=\"8\", \""+py_implementation+"\";v=\""+str(platform.release())+"\"", 'SEC-CH-UA-FULL-VERSION': str(__version__), 'SEC-CH-UA-PLATFORM': ""+py_implementation+"", 'SEC-CH-UA-ARCH': ""+platform.machine()+"", 'SEC-CH-UA-PLATFORM-VERSION': str(__version__), 'SEC-CH-UA-BITNESS': str(PyBitness)}
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
compressionsupport.append("Z")
compressionsupport.append("z")

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


# --- Helpers ---
def _normalize_initial_data(data, isbytes, encoding):
    """Return data in the correct type for write(): bytes (if isbytes) or text (if not)."""
    if data is None:
        return None

    if isbytes:
        # Want bytes
        if isinstance(data, bytes):
            return data
        # Py2: str is already bytes, unicode needs encode
        if sys.version_info[0] == 2:
            try:
                unicode  # noqa: F821
            except NameError:
                pass
            else:
                if isinstance(data, unicode):  # noqa: F821
                    return data.encode(encoding)
        # Py3 str -> encode
        return str(data).encode(encoding)
    else:
        # Want text (unicode/str)
        if sys.version_info[0] == 2:
            try:
                unicode  # noqa: F821
                if isinstance(data, unicode):  # noqa: F821
                    return data
                # bytes/str -> decode
                return data.decode(encoding) if isinstance(data, str) else unicode(data)  # noqa: F821
            except NameError:
                # Very defensive; shouldn't happen
                return data
        else:
            # Py3: want str
            if isinstance(data, bytes):
                return data.decode(encoding)
            return str(data)


def _split_posix(path_text):
    """Split POSIX paths regardless of OS; return list of components."""
    # Normalize leading './'
    if path_text.startswith(u'./'):
        path_text = path_text[2:]
    # Strip redundant slashes
    path_text = re.sub(u'/+', u'/', path_text)
    # Drop trailing '/' so 'dir/' -> ['dir']
    if path_text.endswith(u'/'):
        path_text = path_text[:-1]
    return path_text.split(u'/') if path_text else []

def _is_abs_like(s):
    """Absolute targets (POSIX or Windows-drive style)."""
    return s.startswith(u'/') or s.startswith(u'\\') or re.match(u'^[A-Za-z]:[/\\\\]', s)

def _resolves_outside(base_rel, target_rel):
    """
    Given a base directory (relative, POSIX) and a target (relative),
    return True if base/target resolves outside of base.
    We anchor under '/' so normpath is root-anchored and portable.
    """
    base_clean = u'/'.join(_split_posix(base_rel))
    target_clean = u'/'.join(_split_posix(target_rel))
    base_abs = u'/' + base_clean if base_clean else u'/'
    combined = pp.normpath(pp.join(base_abs, target_clean))
    if combined == base_abs or combined.startswith(base_abs + u'/'):
        return False
    return True

def _to_bytes(data):
    if data is None:
        return b""
    if isinstance(data, bytes):
        return data
    if isinstance(data, unicode):
        return data.encode("utf-8")
    try:
        return bytes(data)
    except Exception:
        return (u"%s" % data).encode("utf-8")

def _to_text(s):
    # Return a text/unicode string on both Py2 and Py3
    try:
        unicode  # noqa: F821 (exists on Py2)
        if isinstance(s, unicode):
            return s
        if isinstance(s, bytes):
            return s.decode('utf-8', 'replace')
        return unicode(s)
    except NameError:
        if isinstance(s, str):
            return s
        if isinstance(s, (bytes, bytearray)):
            return s.decode('utf-8', 'replace')
        return str(s)

def _quote_path_for_wire(path_text):
    # Percent-encode as UTF-8; return ASCII bytes text
    try:
        from urllib.parse import quote
        return quote(path_text.encode('utf-8'))
    except Exception:
        try:
            from urllib import quote as _q
            return _q(path_text.encode('utf-8'))
        except Exception:
            return ''.join(ch for ch in path_text if ord(ch) < 128)

def _unquote_path_from_wire(s_bytes):
    # s_bytes: bytes → return text/unicode
    try:
        from urllib.parse import unquote
        txt = unquote(s_bytes.decode('ascii', 'replace'))
        return _to_text(txt)
    except Exception:
        try:
            from urllib import unquote as _uq
            txt = _uq(s_bytes.decode('ascii', 'replace'))
            return _to_text(txt)
        except Exception:
            return _to_text(s_bytes)

def _recv_line(sock, maxlen=4096, timeout=None):
    """TCP: read a single LF-terminated line (bytes). Returns None on timeout/EOF."""
    if timeout is not None:
        try: sock.settimeout(timeout)
        except Exception: pass
    buf = bytearray()
    while True:
        try:
            b = sock.recv(1)
        except socket.timeout:
            return None
        if not b:
            break
        buf += b
        if b == b'\n' or len(buf) >= maxlen:
            break
    return bytes(buf)

# ---------- TLS helpers (TCP only) ----------
def _ssl_available():
    try:
        import ssl  # noqa
        return True
    except Exception:
        return False

def _build_ssl_context(server_side=False, verify=True, ca_file=None, certfile=None, keyfile=None):
    import ssl
    create_ctx = getattr(ssl, "create_default_context", None)
    SSLContext = getattr(ssl, "SSLContext", None)
    Purpose    = getattr(ssl, "Purpose", None)
    if create_ctx and Purpose:
        ctx = create_ctx(ssl.Purpose.CLIENT_AUTH if server_side else ssl.Purpose.SERVER_AUTH)
    elif SSLContext:
        ctx = SSLContext(getattr(ssl, "PROTOCOL_TLS", getattr(ssl, "PROTOCOL_SSLv23")))
    else:
        return None

    if hasattr(ctx, "check_hostname") and not server_side:
        ctx.check_hostname = bool(verify)

    if verify:
        if hasattr(ctx, "verify_mode"):
            ctx.verify_mode = getattr(ssl, "CERT_REQUIRED", 2)
        if ca_file:
            try: ctx.load_verify_locations(cafile=ca_file)
            except Exception: pass
        else:
            load_default_certs = getattr(ctx, "load_default_certs", None)
            if load_default_certs: load_default_certs()
    else:
        if hasattr(ctx, "verify_mode"):
            ctx.verify_mode = getattr(ssl, "CERT_NONE", 0)
        if hasattr(ctx, "check_hostname"):
            ctx.check_hostname = False

    if certfile:
        ctx.load_cert_chain(certfile=certfile, keyfile=keyfile or None)

    try:
        ctx.set_ciphers("HIGH:!aNULL:!MD5:!RC4")
    except Exception:
        pass
    return ctx

def _ssl_wrap_socket(sock, server_side=False, server_hostname=None,
                     verify=True, ca_file=None, certfile=None, keyfile=None):
    import ssl
    ctx = _build_ssl_context(server_side, verify, ca_file, certfile, keyfile)
    if ctx is not None:
        kwargs = {}
        if not server_side and getattr(ssl, "HAS_SNI", False) and server_hostname:
            kwargs["server_hostname"] = server_hostname
        return ctx.wrap_socket(sock, server_side=server_side, **kwargs)
    # Very old Python fallback
    kwargs = {
        "ssl_version": getattr(ssl, "PROTOCOL_TLS", getattr(ssl, "PROTOCOL_SSLv23")),
        "certfile": certfile or None,
        "keyfile":  keyfile  or None,
        "cert_reqs": (getattr(ssl, "CERT_REQUIRED", 2) if (verify and ca_file) else getattr(ssl, "CERT_NONE", 0)),
    }
    if verify and ca_file:
        kwargs["ca_certs"] = ca_file
    return ssl.wrap_socket(sock, **kwargs)

# ---------- IPv6 / multi-A dialer + keepalive ----------
def _enable_keepalive(s, idle=60, intvl=15, cnt=4):
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if hasattr(socket, 'TCP_KEEPIDLE'):
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, idle)
        if hasattr(socket, 'TCP_KEEPINTVL'):
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, intvl)
        if hasattr(socket, 'TCP_KEEPCNT'):
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, cnt)
    except Exception:
        pass

def _connect_stream(host, port, timeout):
    err = None
    for fam, st, proto, _, sa in socket.getaddrinfo(host, int(port), 0, socket.SOCK_STREAM):
        try:
            s = socket.socket(fam, st, proto)
            if timeout is not None:
                s.settimeout(timeout)
            try: s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception: pass
            s.connect(sa)
            _enable_keepalive(s)
            return s
        except Exception as e:
            err = e
            try: s.close()
            except Exception: pass
    if err: raise err
    raise RuntimeError("no usable address")

# ---------- Auth: AF1 (HMAC) + legacy fallback ----------
# AF1: single ASCII line ending with '\n':
#   AF1 ts=<unix> user=<b64url> nonce=<b64url_12B> scope=<b64url> alg=sha256 mac=<hex>\n
def _b64url_encode(b):
    s = base64.urlsafe_b64encode(b)
    return _to_text(s.rstrip(b'='))

def _b64url_decode(s):
    s = _to_bytes(s)
    pad = b'=' * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode(s + pad)

def _auth_msg(ts_int, user_utf8, nonce_bytes, scope_utf8, length_str, sha_hex):
    # canonical message for MAC: v1|ts|user|nonce_b64|scope|len|sha
    return _to_bytes("v1|%d|%s|%s|%s|%s|%s" % (
        ts_int,
        _to_text(user_utf8),
        _b64url_encode(nonce_bytes),
        _to_text(scope_utf8),
        length_str if length_str is not None else "",
        sha_hex if sha_hex is not None else "",
    ))

def build_auth_blob_v1(user, secret, scope=u"", now=None, length=None, sha_hex=None):
    """
    user: text; secret: text/bytes (HMAC key)
    scope: optional text (e.g., path)
    length: int or None (payload bytes)
    sha_hex: ascii hex SHA-256 of payload (optional)
    """
    ts = int(time.time() if now is None else now)
    user_b  = _to_bytes(user or u"")
    scope_b = _to_bytes(scope or u"")
    key_b   = _to_bytes(secret or u"")
    nonce   = os.urandom(12)

    length_str = (str(int(length)) if (length is not None and int(length) >= 0) else "")
    sha_hex = (sha_hex or None)
    mac = hmac.new(
        key_b,
        _auth_msg(ts, user_b, nonce, scope_b, length_str, sha_hex),
        hashlib.sha256
    ).hexdigest()

    line = "AF1 ts=%d user=%s nonce=%s scope=%s len=%s sha=%s alg=sha256 mac=%s\n" % (
        ts,
        _b64url_encode(user_b),
        _b64url_encode(nonce),
        _b64url_encode(scope_b),
        length_str,
        (sha_hex or ""),
        mac,
    )
    return _to_bytes(line)

from collections import deque
class _NonceCache(object):
    def __init__(self, max_items=10000, ttl_seconds=600):
        self.max_items = int(max_items); self.ttl = int(ttl_seconds)
        self.q = deque(); self.s = set()
    def seen(self, nonce_b64, now_ts):
        # evict old / over-capacity
        while self.q and (now_ts - self.q[0][0] > self.ttl or len(self.q) > self.max_items):
            _, n = self.q.popleft(); self.s.discard(n)
        if nonce_b64 in self.s: return True
        self.s.add(nonce_b64); self.q.append((now_ts, nonce_b64))
        return False

_NONCES = _NonceCache()

def verify_auth_blob_v1(blob_bytes, expected_user=None, secret=None,
                        max_skew=600, expect_scope=None):
    """
    Returns (ok_bool, user_text, scope_text, reason_text, length_or_None, sha_hex_or_None)
    """
    try:
        line = _to_text(blob_bytes).strip()
        if not line.startswith("AF1 "):
            return (False, None, None, "bad magic", None, None)
        kv = {}
        for tok in line.split()[1:]:
            if '=' in tok:
                k, v = tok.split('=', 1); kv[k] = v

        for req in ("ts","user","nonce","mac","alg"):
            if req not in kv:
                return (False, None, None, "missing %s" % req, None, None)
        if kv["alg"].lower() != "sha256":
            return (False, None, None, "alg", None, None)

        ts    = int(kv["ts"])
        userb = _b64url_decode(kv["user"])
        nonce_b64 = kv["nonce"]; nonce = _b64url_decode(nonce_b64)
        scopeb = _b64url_decode(kv.get("scope","")) if kv.get("scope") else b""
        length_str = kv.get("len","")
        sha_hex    = kv.get("sha","") or None
        mac   = kv["mac"]

        now = int(time.time())
        if abs(now - ts) > int(max_skew):
            return (False, None, None, "skew", None, None)

        if _NONCES.seen(nonce_b64, now):
            return (False, None, None, "replay", None, None)

        if expected_user is not None and _to_bytes(expected_user) != userb:
            return (False, None, None, "user", None, None)

        calc = hmac.new(
            _to_bytes(secret or u""),
            _auth_msg(ts, userb, nonce, scopeb, length_str, sha_hex),
            hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(calc, mac):
            return (False, None, None, "mac", None, None)

        if expect_scope is not None and _to_bytes(expect_scope) != scopeb:
            return (False, None, None, "scope", None, None)

        length = int(length_str) if (length_str and length_str.isdigit()) else None
        return (True, _to_text(userb), _to_text(scopeb), "ok", length, sha_hex)
    except Exception as e:
        return (False, None, None, "exc:%s" % e, None, None)

# Legacy blob (kept for backward compatibility)
_MAGIC = b"AUTH\0"; _OK = b"OK"; _NO = b"NO"

def _build_auth_blob_legacy(user, pw):
    return _MAGIC + _to_bytes(user) + b"\0" + _to_bytes(pw) + b"\0"

def _parse_auth_blob_legacy(data):
    if not data.startswith(_MAGIC):
        return (None, None)
    rest = data[len(_MAGIC):]
    try:
        user, rest = rest.split(b"\0", 1)
        pw, _tail  = rest.split(b"\0", 1)
        return (user, pw)
    except Exception:
        return (None, None)

# ---------- URL helpers ----------
def _qflag(qs, key, default=False):
    v = qs.get(key, [None])[0]
    if v is None: return bool(default)
    return _to_text(v).lower() in ("1", "true", "yes", "on")

def _qnum(qs, key, default=None, cast=float):
    v = qs.get(key, [None])[0]
    if v is None or v == "": return default
    try: return cast(v)
    except Exception: return default

def _qstr(qs, key, default=None):
    v = qs.get(key, [None])[0]
    if v is None: return default
    return v

def _parse_net_url(url):
    parts = urlparse(url)
    qs = parse_qs(parts.query or "")

    proto = parts.scheme.lower()
    if proto not in ("tcp", "udp"):
        raise ValueError("Only tcp:// or udp:// supported here")

    user = unquote(parts.username) if parts.username else None
    pw   = unquote(parts.password) if parts.password else None

    use_ssl     = _qflag(qs, "ssl", False) if proto == "tcp" else False
    ssl_verify  = _qflag(qs, "verify", True)
    ssl_ca_file = _qstr(qs, "ca", None)
    ssl_cert    = _qstr(qs, "cert", None)
    ssl_key     = _qstr(qs, "key", None)

    timeout       = _qnum(qs, "timeout", None, float)
    total_timeout = _qnum(qs, "total_timeout", None, float)
    chunk_size    = int(_qnum(qs, "chunk", 65536, float))

    force_auth   = _qflag(qs, "auth", False)
    want_sha     = _qflag(qs, "sha", True)             # enable sha by default
    enforce_path = _qflag(qs, "enforce_path", True)    # enforce path by default

    path_text = _to_text(parts.path or u"")

    opts = dict(
        proto=proto,
        host=parts.hostname or "127.0.0.1",
        port=int(parts.port or 0),

        user=user, pw=pw, force_auth=force_auth,

        use_ssl=use_ssl, ssl_verify=ssl_verify,
        ssl_ca_file=ssl_ca_file, ssl_certfile=ssl_cert, ssl_keyfile=ssl_key,

        timeout=timeout, total_timeout=total_timeout, chunk_size=chunk_size,

        server_hostname=parts.hostname or None,

        want_sha=want_sha,
        enforce_path=enforce_path,

        path=path_text,   # also used as AF1 "scope"
    )
    return parts, opts


def _rewrite_url_without_auth(url):
    u = urlparse(url)
    netloc = u.hostname or ''
    if u.port:
        netloc += ':' + str(u.port)
    rebuilt = urlunparse((u.scheme, netloc, u.path, u.params, u.query, u.fragment))
    usr = unquote(u.username) if u.username else ''
    pwd = unquote(u.password) if u.password else ''
    return rebuilt, usr, pwd

def _guess_filename(url, filename):
    if filename:
        return filename
    path = urlparse(url).path or ''
    base = os.path.basename(path)
    return base or 'OutFile.'+__file_format_extension__

# ---- progress + rate limiting helpers ----
try:
    monotonic = time.monotonic  # Py3
except Exception:
    # Py2 fallback: time.time() is good enough for coarse throttling
    monotonic = time.time

def _progress_tick(now_bytes, total_bytes, last_ts, last_bytes, rate_limit_bps, min_interval=0.1):
    """
    Returns (sleep_seconds, new_last_ts, new_last_bytes).
    - If rate_limit_bps is set, computes how long to sleep to keep average <= limit.
    - Also enforces a minimum interval between progress callbacks (handled by caller).
    """
    now = monotonic()
    elapsed = max(1e-9, now - last_ts)
    # Desired time to have elapsed for the given rate:
    desired = (now_bytes - last_bytes) / float(rate_limit_bps) if rate_limit_bps else 0.0
    extra = desired - elapsed
    return (max(0.0, extra), now, now_bytes)

def _discover_len_and_reset(fobj):
    """
    Try to get total length and restore original position.
    Returns (length_or_None, start_pos_or_None).
    """
    # Generic seek/tell
    try:
        pos0 = fobj.tell()
        fobj.seek(0, os.SEEK_END)
        end = fobj.tell()
        fobj.seek(pos0, os.SEEK_SET)
        if end is not None and pos0 is not None and end >= pos0:
            return (end - pos0, pos0)
    except Exception:
        pass
    # BytesIO fast path
    try:
        getvalue = getattr(fobj, "getvalue", None)
        if callable(getvalue):
            buf = getvalue()
            L = len(buf)
            try: pos0 = fobj.tell()
            except Exception: pos0 = 0
            return (max(0, L - pos0), pos0)
    except Exception:
        pass
    # Memoryview/getbuffer
    try:
        getbuffer = getattr(fobj, "getbuffer", None)
        if callable(getbuffer):
            mv = getbuffer()
            L = len(mv)
            try: pos0 = fobj.tell()
            except Exception: pos0 = 0
            return (max(0, L - pos0), pos0)
    except Exception:
        pass
    return (None, None)

# ---------- helpers reused from your module ----------
# expects: _to_bytes, _to_text, _discover_len_and_reset, _qflag, _qnum, _qstr
# If you don't have _qflag/_qnum/_qstr here, reuse your existing ones.

# =========================
# URL parser for HTTP/HTTPS
# =========================
def _parse_http_url(url):
    parts = _urlparse(url)
    qs = _parse_qs(parts.query or "")

    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise ValueError("Only http:// or https:// supported here")

    host = parts.hostname or "127.0.0.1"
    port = int(parts.port or (443 if scheme == "https" else 80))
    user = parts.username
    pw   = parts.password
    path = _to_text(parts.path or u"/")

    chunk_size    = int(_qnum(qs, "chunk", 65536, float))
    want_sha      = _qflag(qs, "sha", True)
    enforce_path  = _qflag(qs, "enforce_path", True)
    force_auth    = _qflag(qs, "auth", False)
    mime          = _qstr(qs, "mime", "application/octet-stream")
    certfile      = _qstr(qs, "cert", None)
    keyfile       = _qstr(qs, "key", None)
    timeout       = _qnum(qs, "timeout", None, float)
    rate_limit    = _qnum(qs, "rate", None, float)
    wait_seconds  = _qnum(qs, "wait", None, float)      # <-- NEW

    hdrs = _parse_headers_from_qs(qs)

    return parts, dict(
        scheme=scheme, host=host, port=port,
        user=user, pw=pw, path=path,
        chunk_size=chunk_size, want_sha=want_sha,
        enforce_path=enforce_path,
        require_auth=(force_auth or (user is not None or pw is not None)),
        mime=mime,
        certfile=certfile, keyfile=keyfile,
        timeout=timeout,
        rate_limit_bps=(int(rate_limit) if rate_limit else None),
        extra_headers=hdrs,
        wait_seconds=wait_seconds,             # <-- NEW
    )

def _basic_ok(auth_header, expect_user, expect_pass):
    """
    Check HTTP Basic auth header "Basic base64(user:pass)".
    return True/False
    """
    if not auth_header or not auth_header.strip().lower().startswith("basic "):
        return False
    try:
        b64 = auth_header.strip().split(" ", 1)[1]
        raw = _b64.b64decode(_to_bytes(b64))
        # raw may be bytes like b"user:pass"
        try:
            raw_txt = raw.decode("utf-8")
        except Exception:
            raw_txt = raw.decode("latin-1", "replace")
        if ":" not in raw_txt:
            return False
        u, p = raw_txt.split(":", 1)
        if expect_user is not None and u != _to_text(expect_user):
            return False
        if expect_pass is not None and p != _to_text(expect_pass):
            return False
        return True
    except Exception:
        return False

_HEX_RE = re.compile(r'^[0-9a-fA-F]{32,}$')  # len>=32 keeps it simple; SHA-256 is 64

def _int_or_none(v):
    try:
        return int(v)
    except Exception:
        return None

def _strip_quotes(s):
    if s and len(s) >= 2 and s[0] == s[-1] == '"':
        return s[1:-1]
    return s

def _is_hexish(s):
    return bool(s) and bool(_HEX_RE.match(s))

def _pick_expected_len(headers):
    # Prefer explicit X-File-Length, then Content-Length
    xlen = headers.get('X-File-Length') or headers.get('x-file-length')
    clen = headers.get('Content-Length') or headers.get('content-length')
    return _int_or_none(xlen) or _int_or_none(clen)

def _pick_expected_sha(headers):
    # Prefer X-File-SHA256; otherwise, a strong ETag that looks like hex
    sha = headers.get('X-File-SHA256') or headers.get('x-file-sha256')
    if sha:
        return _strip_quotes(sha).lower()
    etag = headers.get('ETag') or headers.get('etag')
    if etag:
        etag = _strip_quotes(etag)
        if _is_hexish(etag):
            return etag.lower()
    return None

def _headers_dict_from_response(resp, lib):
    """
    Return a case-sensitive dict-like of headers turned into a plain dict for all libs.
    lib in {'requests','httpx','mechanize','urllib'}
    """
    if lib == 'requests':
        # Case-insensitive dict; items() yields canonicalized keys
        return dict(resp.headers or {})
    if lib == 'httpx':
        return dict(resp.headers or {})
    if lib == 'mechanize':
        # mechanize response.info() returns an email.message.Message-like
        info = getattr(resp, 'info', lambda: None)()
        if info:
            return dict(info.items())
        return {}
    if lib == 'urllib':
        info = getattr(resp, 'info', lambda: None)()
        if info:
            return dict(info.items())
        return {}
    return {}

def _stream_copy_and_verify(src_iter, dst_fp, expected_len=None, expected_sha=None, chunk_size=65536):
    """
    src_iter yields bytes; we copy to dst_fp and (optionally) verify length/SHA-256.
    Returns total bytes written.
    """
    h = hashlib.sha256() if expected_sha else None
    total = 0
    for chunk in src_iter:
        if not chunk:
            continue
        b = _to_bytes(chunk)
        if h is not None:
            h.update(b)
        dst_fp.write(b)
        total += len(b)
    try:
        dst_fp.flush()
    except Exception:
        pass

    if expected_len is not None and total != expected_len:
        raise IOError("HTTP length mismatch: got %d bytes, expected %d" % (total, expected_len))

    if expected_sha is not None and h is not None:
        got = h.hexdigest().lower()
        if got != expected_sha.lower():
            raise IOError("HTTP SHA-256 mismatch: got %s expected %s" % (got, expected_sha))
    return total

def _parse_headers_from_qs(qs):
    """
    Supports:
      h=Name: Value (repeatable) / header=...
      headers=Name1: Val1|Name2: Val2       (| delimited)
      hjson={"Name":"Val","X-Any":"Thing"}  (JSON object)
    Returns a plain dict (last wins on duplicate keys).
    """
    hdrs = {}

    def _add_line(line):
        if not line:
            return
        parts = line.split(":", 1)  # only first colon splits
        if len(parts) != 2:
            return
        k = parts[0].strip()
        v = parts[1].strip()
        if k:
            hdrs[_to_text(k)] = _to_text(v)

    # repeatable h= / header=
    for key in ("h", "header"):
        for v in qs.get(key, []):
            _add_line(v)

    # headers=Name1: Val1|Name2: Val2
    for v in qs.get("headers", []):
        if not v:
            continue
        for seg in v.split("|"):
            _add_line(seg)

    # hjson=JSON  (uses your global 'json' import: ujson/simplejson/json)
    for v in qs.get("hjson", []):
        if not v:
            continue
        try:
            obj = json.loads(v)
            if isinstance(obj, dict):
                for k, vv in obj.items():
                    if k:
                        hdrs[_to_text(k)] = _to_text(vv)
        except Exception:
            # ignore malformed JSON silently
            pass

    return hdrs


def _pace_rate(last_ts, sent_bytes_since_ts, rate_limit_bps, add_bytes):
    """
    Simple average-rate pacing. Returns (sleep_seconds, new_last_ts, new_sent_since_ts).
    """
    if not rate_limit_bps or rate_limit_bps <= 0:
        return (0.0, last_ts, sent_bytes_since_ts)
    now = time.time()
    # accumulate
    sent_bytes_since_ts += add_bytes
    elapsed = max(1e-6, now - last_ts)
    cur_bps = sent_bytes_since_ts / elapsed
    sleep_s = 0.0
    if cur_bps > rate_limit_bps:
        # how much time needed at least to bring avg down?
        sleep_s = max(0.0, (sent_bytes_since_ts / float(rate_limit_bps)) - elapsed)
        # cap sleep to reasonable chunk to avoid long stalls
        if sleep_s > 0.25:
            sleep_s = 0.25
    # roll window occasionally to keep numbers small
    if elapsed >= 1.0:
        last_ts = now
        sent_bytes_since_ts = 0
    return (sleep_s, last_ts, sent_bytes_since_ts)


def DetectTarBombCatFileArray(listarrayfiles,
                                 top_file_ratio_threshold=0.6,
                                 min_members_for_ratio=4,
                                 symlink_policy="escape-only",  # 'escape-only' | 'deny' | 'single-folder-only'
                                 to_text=to_text):
    """
    Detect 'tarbomb-like' archives from CatFileToArray/TarFileToArray dicts.

    Parameters:
      listarrayfiles: dict with key 'ffilelist' -> list of entries (requires 'fname')
      top_file_ratio_threshold: float, fraction of root files considered tarbomb
      min_members_for_ratio: int, minimum members before ratio heuristic applies
      symlink_policy:
        - 'escape-only': only symlinks that escape parent/are absolute are unsafe
        - 'deny': any symlink is unsafe
        - 'single-folder-only': symlinks allowed only if archive has a single top-level folder
      to_text: normalization function (your provided to_text)

    Returns dict with:
      - is_tarbomb, reasons, total_members, top_level_entries, top_level_files_count,
        has_absolute_paths, has_parent_traversal,
        symlink_escapes_root (bool), symlink_issues (list[{entry,target,reason}])
    """
    files = listarrayfiles or {}
    members = files.get('ffilelist') or []

    names = []
    has_abs = False
    has_parent = False

    # Symlink tracking
    has_any_symlink = False
    symlink_issues = []
    any_symlink_escape = False

    for m in members:
        m = m or {}
        name = to_text(m.get('fname', u""))

        if _is_abs_like(name):
            has_abs = True

        parts = _split_posix(name)
        if u'..' in parts:
            has_parent = True

        if not parts:
            continue

        norm_name = u'/'.join(parts)
        names.append(norm_name)

        # ---- Symlink detection ----
        ftype = m.get('ftype')
        is_symlink = (ftype == 2) or (to_text(ftype).lower() == u'symlink' if ftype is not None else False)
        if is_symlink:
            has_any_symlink = True
            target = to_text(m.get('flinkname', u""))
            # Absolute symlink target is unsafe
            if _is_abs_like(target):
                any_symlink_escape = True
                symlink_issues.append({'entry': norm_name, 'target': target, 'reason': 'absolute symlink target'})
            else:
                parent = u'/'.join(parts[:-1])  # may be ''
                if _resolves_outside(parent, target):
                    any_symlink_escape = True
                    symlink_issues.append({'entry': norm_name, 'target': target, 'reason': 'symlink escapes parent directory'})

    total = len(names)
    reasons = []
    if total == 0:
        return {
            "is_tarbomb": False,
            "reasons": ["archive contains no members"],
            "total_members": 0,
            "top_level_entries": [],
            "top_level_files_count": 0,
            "has_absolute_paths": has_abs,
            "has_parent_traversal": has_parent,
            "symlink_escapes_root": any_symlink_escape,
            "symlink_issues": symlink_issues,
        }

    # Layout counts
    top_counts = {}
    top_level_files_count = 0
    for name in names:
        parts = name.split(u'/')
        first = parts[0]
        top_counts[first] = top_counts.get(first, 0) + 1
        if len(parts) == 1:  # directly at archive root
            top_level_files_count += 1

    top_keys = sorted(top_counts.keys())
    is_tarbomb = False

    # Path-based dangers
    if has_abs:
        is_tarbomb = True
        reasons.append("contains absolute paths (dangerous)")
    if has_parent:
        is_tarbomb = True
        reasons.append("contains parent-traversal ('..') entries (dangerous)")
    if any_symlink_escape:
        is_tarbomb = True
        reasons.append("contains symlinks that escape their parent directory")

    # Symlink policy enforcement
    if symlink_policy == "deny" and has_any_symlink:
        is_tarbomb = True
        reasons.append("symlinks present and policy is 'deny'")
    elif symlink_policy == "single-folder-only" and has_any_symlink and len(top_keys) != 1:
        is_tarbomb = True
        reasons.append("symlinks present but archive lacks a single top-level folder")

    # Tarbomb layout heuristics
    if len(top_keys) == 1:
        reasons.append("single top-level entry '{0}'".format(top_keys[0]))
    else:
        ratio = float(top_level_files_count) / float(total)
        if total >= min_members_for_ratio and ratio > float(top_file_ratio_threshold):
            is_tarbomb = True
            reasons.append("high fraction of members ({0:.0%}) at archive root".format(ratio))
        else:
            max_bucket = max(top_counts.values()) if top_counts else 0
            if max_bucket < total * 0.9:
                is_tarbomb = True
                reasons.append("multiple top-level entries with no dominant folder: {0}".format(
                    u", ".join(top_keys[:10])))
            else:
                reasons.append("multiple top-level entries but one dominates")

    return {
        "is_tarbomb": bool(is_tarbomb),
        "reasons": reasons,
        "total_members": total,
        "top_level_entries": top_keys,
        "top_level_files_count": top_level_files_count,
        "has_absolute_paths": has_abs,
        "has_parent_traversal": has_parent,
        "symlink_escapes_root": any_symlink_escape,
        "symlink_issues": symlink_issues,
    }


def _normalize_initial_data(data, isbytes, encoding):
    """
    Coerce `data` to the correct type for the chosen mode:
      - bytes mode: return `bytes` (Py2: str; Py3: bytes)
      - text mode : return unicode/str (Py2: unicode; Py3: str)
    """
    if data is None:
        return None

    if isbytes:
        # Need a byte sequence
        if isinstance(data, bytes):
            return data
        if isinstance(data, bytearray):
            return bytes(data)
        # memoryview may not exist on very old Py2 builds; guard dynamically
        mv_t = getattr(__builtins__, 'memoryview', type(None))
        if isinstance(data, mv_t):
            return bytes(data)
        if isinstance(data, str):
            # Py2 str is already bytes; Py3 str must be encoded
            return data if PY2 else data.encode(encoding)
        if PY2 and isinstance(data, unicode):  # noqa: F821 (unicode only in Py2)
            return data.encode(encoding)
        raise TypeError("data must be bytes-like or text for isbytes=True (got %r)" % (type(data),))
    else:
        # Need text (unicode in Py2, str in Py3)
        if PY2:
            if isinstance(data, unicode):  # noqa: F821
                return data
            if isinstance(data, str):
                return data.decode(encoding)
            if isinstance(data, bytearray):
                return bytes(data).decode(encoding)
            mv_t = getattr(__builtins__, 'memoryview', type(None))
            if isinstance(data, mv_t):
                return bytes(data).decode(encoding)
            raise TypeError("data must be unicode or bytes-like for text mode (got %r)" % (type(data),))
        else:
            if isinstance(data, str):
                return data
            if isinstance(data, (bytes, bytearray, memoryview)):
                return bytes(data).decode(encoding)
            raise TypeError("data must be str or bytes-like for text mode (got %r)" % (type(data),))

def MkTempFile(data=None,
               inmem=True,
               isbytes=True,
               prefix="",
               delete=True,
               encoding="utf-8",
               newline=None,      # Py3 text only; ignored by Py2 temp classes
               dir=None,
               suffix="",
               # spooled option (RAM until threshold, then rolls to disk)
               use_spool=False,
               spool_max=8 * 1024 * 1024,
               spool_dir=None):
    """
    Return a file-like handle with consistent behavior on Py2.7 and Py3.x.

    - inmem=True                       -> BytesIO (bytes) or StringIO (text)
    - inmem=False, use_spool=True      -> SpooledTemporaryFile (RAM -> disk after spool_max)
    - inmem=False, use_spool=False     -> NamedTemporaryFile (on disk)

    If `data` is provided, it's written and the handle is rewound to position 0.
    """
    init = _normalize_initial_data(data, isbytes, encoding)

    # -------- In-memory --------
    if inmem:
        if isbytes:
            return BytesIO(init if init is not None else b"")
        else:
            # Py2 needs unicode literal for empty default
            return StringIO(init if init is not None else (u"" if PY2 else ""))

    # -------- Spooled (RAM then disk) --------
    if use_spool:
        if isbytes:
            f = tempfile.SpooledTemporaryFile(max_size=spool_max, mode="w+b", dir=spool_dir)
        else:
            if PY2:
                # Py2 SpooledTemporaryFile doesn't accept encoding/newline
                f = tempfile.SpooledTemporaryFile(max_size=spool_max, mode="w+", dir=spool_dir)
            else:
                f = tempfile.SpooledTemporaryFile(max_size=spool_max, mode="w+",
                                                  dir=spool_dir, encoding=encoding, newline=newline)
        if init is not None:
            f.write(init)
            f.seek(0)
        return f

    # -------- On-disk temp --------
    if isbytes:
        f = tempfile.NamedTemporaryFile(mode="w+b", prefix=prefix or "", suffix=suffix,
                                        dir=dir, delete=delete)
    else:
        if PY2:
            # Py2 temp files don't accept encoding/newline; writes of unicode will be encoded
            # using the default encoding. If you need strict control, wrap with codecs/io.open.
            f = tempfile.NamedTemporaryFile(mode="w+", prefix=prefix or "", suffix=suffix,
                                            dir=dir, delete=delete)
        else:
            f = tempfile.NamedTemporaryFile(mode="w+", prefix=prefix or "", suffix=suffix,
                                            dir=dir, delete=delete, encoding=encoding, newline=newline)

    if init is not None:
        f.write(init)
        f.seek(0)
    return f


def RemoveWindowsPath(dpath):
    """
    Normalize a path by converting backslashes to forward slashes
    and stripping a trailing slash.
    """
    if not dpath:
        return ""
    if re.match("^file://", dpath, re.IGNORECASE):
        # Normalize to file:/// if it's a local path (no host)
        if dpath.lower().startswith("file://") and not dpath.lower().startswith("file:///"):
            # insert the extra slash
            dpath = "file:///" + dpath[7:]
        dparsed = urlparse(dpath)
        dpath = url2pathname(dparsed.path)
    # Accept bytes and decode safely
    if isinstance(dpath, (bytes, bytearray)):
        dpath = dpath.decode("utf-8", "ignore")
    dpath = dpath.replace("\\", "/")
    # Collapse multiple slashes except for protocol prefixes like "s3://"
    if "://" not in dpath:
        while "//" in dpath:
            dpath = dpath.replace("//", "/")
    return dpath.rstrip("/")


def NormalizeRelativePath(inpath):
    """
    Ensures the path is relative unless it is absolute. Prepares consistent relative paths.
    """
    if re.match("^file://", inpath, re.IGNORECASE):
        # Normalize to file:/// if it's a local path (no host)
        if inpath.lower().startswith("file://") and not inpath.lower().startswith("file:///"):
            # insert the extra slash
            inpath = "file:///" + inpath[7:]
        dparsed = urlparse(inpath)
        inpath = url2pathname(dparsed.path)
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
        if re.match("^file://", mydirfile, re.IGNORECASE):
            # Normalize to file:/// if it's a local path (no host)
            if mydirfile.lower().startswith("file://") and not mydirfile.lower().startswith("file:///"):
                # insert the extra slash
                mydirfile = "file:///" + mydirfile[7:]
            dparsed = urlparse(mydirfile)
            mydirfile = url2pathname(dparsed.path)
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
        if re.match("^file://", mydirfile, re.IGNORECASE):
            # Normalize to file:/// if it's a local path (no host)
            if mydirfile.lower().startswith("file://") and not mydirfile.lower().startswith("file:///"):
                # insert the extra slash
                mydirfile = "file:///" + mydirfile[7:]
            dparsed = urlparse(mydirfile)
            mydirfile = url2pathname(dparsed.path)
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


def create_alias_function_alt(prefix, base_name, suffix, target_function, positional_overrides=None):
    """
    Creates a new function in the global namespace that wraps 'target_function',
    allowing optional overrides of specific positional arguments via 'positional_overrides'.

    :param prefix: String prefix for the new function's name
    :param base_name: Base string to use in the new function's name
    :param suffix: String suffix for the new function's name
    :param target_function: The function to be wrapped/aliased
    :param positional_overrides: Optional dict {index: new_value} for overriding specific positional arguments
    """
    # Define a new function that wraps the target function
    def alias_function(*args, **kwargs):
        # Convert args to a list so we can modify specific positions
        args_list = list(args)

        # If there are positional overrides, apply them
        if positional_overrides:
            for index, value in positional_overrides.items():
                # Only apply if the index is within the bounds of the original arguments
                if 0 <= index < len(args_list):
                    args_list[index] = value

        # Call the target function with possibly modified arguments
        return target_function(*args_list, **kwargs)

    # Create the function name by combining the prefix, base name, and the suffix
    function_name = "{}{}{}".format(prefix, base_name, suffix)

    # Add the new function to the global namespace
    globals()[function_name] = alias_function


def create_alias_function(prefix, base_name, suffix, target_function, positional_overrides=None):
    """
    Creates a new function in the global namespace that wraps 'target_function',
    allowing optional overrides of specific positional arguments via 'positional_overrides'.

    :param prefix: String prefix for the new function's name
    :param base_name: Base string to use in the new function's name
    :param suffix: String suffix for the new function's name
    :param target_function: The function to be wrapped/aliased
    :param positional_overrides: Optional dict {index: new_value} for overriding specific positional arguments
    """
    # Define a new function that wraps the target function
    def alias_function(*args, **kwargs):
        # Convert args to a list so we can modify specific positions
        args_list = list(args)

        # If there are positional overrides, apply them
        if positional_overrides:
            for index, value in positional_overrides.items():
                if 0 <= index < len(args_list):
                    args_list[index] = value

        # Call the target function with possibly modified arguments
        return target_function(*args_list, **kwargs)

    # Create the function name by combining the prefix, base_name, and suffix
    function_name = "{}{}{}".format(prefix, base_name, suffix)

    # Add the new function to the global namespace
    globals()[function_name] = alias_function


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


def crc_calculate(msg, poly, initial_value, bit_length):
    """Generic CRC calculation function."""
    crc = initial_value
    for byte in msg:
        crc ^= byte << (bit_length - 8)
        for _ in range(8):
            crc = (crc << 1) ^ poly if crc & (1 << (bit_length - 1)) else crc << 1
            crc &= (1 << bit_length) - 1
    return crc


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
    if encodedata and hasattr(fileheader, "encode"):
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
    if encodedata and hasattr(instr, "encode"):
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
    infileheadercshex = GetHeaderChecksum(
        inlist, checksumtype, True, formatspecs).lower()
    return inchecksum.lower() == infileheadercshex


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
    subfp = MkTempFile()
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
    #headerdata = ReadFileHeaderData(fp, headernumfields, delimiter)
    HeaderOut = preheaderdata + headerdata
    return HeaderOut


def ReadFileHeaderDataWithContent(fp, listonly=False, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__):
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
    if(re.findall("^[.|/]", HeaderOut[5])):
        fname = HeaderOut[5]
    else:
        fname = "./"+HeaderOut[5]
    fcs = HeaderOut[-2].lower()
    fccs = HeaderOut[-1].lower()
    fsize = int(HeaderOut[7], 16)
    fcompression = HeaderOut[14]
    fcsize = int(HeaderOut[15], 16)
    fseeknextfile = HeaderOut[26]
    fjsontype = HeaderOut[27]
    fjsonlen = int(HeaderOut[28], 16)
    fjsonsize = int(HeaderOut[29], 16)
    fjsonchecksumtype = HeaderOut[30]
    fjsonchecksum = HeaderOut[31]
    fjsoncontent = {}
    fprejsoncontent = fp.read(fjsonsize).decode("UTF-8")
    if(fjsonsize > 0):
        try:
            fjsoncontent = json.loads(base64.b64decode(fprejsoncontent.encode("UTF-8")).decode("UTF-8"))
        except (binascii.Error, json.decoder.JSONDecodeError, UnicodeDecodeError):
            try:
                fjsoncontent = json.loads(fprejsoncontent)
            except (binascii.Error, json.decoder.JSONDecodeError, UnicodeDecodeError):
                fprejsoncontent = ""
                fjsoncontent = {}
    else:
        fprejsoncontent = ""
        fjsoncontent = {}
    fp.seek(len(delimiter), 1)
    jsonfcs = GetFileChecksum(fprejsoncontent, fjsonchecksumtype, True, formatspecs)
    if(jsonfcs != fjsonchecksum and not skipchecksum):
        VerbosePrintOut("File JSON Data Checksum Error with file " +
                        fname + " at offset " + str(fheaderstart))
        VerbosePrintOut("'" + fjsonchecksum + "' != " + "'" + jsonfcs + "'")
        return False
    fp.seek(len(delimiter), 1)
    newfcs = GetHeaderChecksum(
        HeaderOut[:-2], HeaderOut[-4].lower(), True, formatspecs)
    HeaderOut.append(fjsoncontent)
    if(fcs != newfcs and not skipchecksum):
        VerbosePrintOut("File Header Checksum Error with file " +
                        fname + " at offset " + str(fheaderstart))
        VerbosePrintOut("'" + fcs + "' != " + "'" + newfcs + "'")
        return False
    fhend = fp.tell() - 1
    fcontentstart = fp.tell()
    fcontents = MkTempFile()
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
    fcontents.seek(0, 0)
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
            cfcontents = UncompressFileAlt(fcontents, formatspecs)
            cfcontents.seek(0, 0)
            fcontents = MkTempFile()
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


def ReadFileHeaderDataWithContentToArray(fp, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__):
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
    fcencoding = HeaderOut[4]
    if(re.findall("^[.|/]", HeaderOut[5])):
        fname = HeaderOut[5]
    else:
        fname = "./"+HeaderOut[5]
    fbasedir = os.path.dirname(fname)
    flinkname = HeaderOut[6]
    fsize = int(HeaderOut[7], 16)
    fatime = int(HeaderOut[8], 16)
    fmtime = int(HeaderOut[9], 16)
    fctime = int(HeaderOut[10], 16)
    fbtime = int(HeaderOut[11], 16)
    fmode = int(HeaderOut[12], 16)
    fchmode = stat.S_IMODE(fmode)
    ftypemod = stat.S_IFMT(fmode)
    fwinattributes = int(HeaderOut[13], 16)
    fcompression = HeaderOut[14]
    fcsize = int(HeaderOut[15], 16)
    fuid = int(HeaderOut[16], 16)
    funame = HeaderOut[17]
    fgid = int(HeaderOut[18], 16)
    fgname = HeaderOut[19]
    fid = int(HeaderOut[20], 16)
    finode = int(HeaderOut[21], 16)
    flinkcount = int(HeaderOut[22], 16)
    fdev = int(HeaderOut[23], 16)
    fdev_minor = int(HeaderOut[24], 16)
    fdev_major = int(HeaderOut[25], 16)
    fseeknextfile = HeaderOut[26]
    fjsontype = HeaderOut[27]
    fjsonlen = int(HeaderOut[28], 16)
    fjsonsize = int(HeaderOut[29], 16)
    fjsonchecksumtype = HeaderOut[30]
    fjsonchecksum = HeaderOut[31]
    fextrasize = int(HeaderOut[32], 16)
    fextrafields = int(HeaderOut[33], 16)
    fextrafieldslist = []
    extrastart = 34
    extraend = extrastart + fextrafields
    while(extrastart < extraend):
        fextrafieldslist.append(HeaderOut[extrastart])
        extrastart = extrastart + 1
    if(fextrafields==1):
        try:
            fextrafieldslist = json.loads(base64.b64decode(fextrafieldslist[0]).decode("UTF-8"))
            fextrafields = len(fextrafieldslist)
        except (binascii.Error, json.decoder.JSONDecodeError, UnicodeDecodeError):
            try:
                fextrafieldslist = json.loads(fextrafieldslist[0])
            except (binascii.Error, json.decoder.JSONDecodeError, UnicodeDecodeError):
                pass
    fjstart = fp.tell()
    if(fjsontype=="json"):
        fjsoncontent = {}
        fprejsoncontent = fp.read(fjsonsize).decode("UTF-8")
        if(fjsonsize > 0):
            try:
                fjsonrawcontent = base64.b64decode(fprejsoncontent.encode("UTF-8")).decode("UTF-8")
                fjsoncontent = json.loads(base64.b64decode(fprejsoncontent.encode("UTF-8")).decode("UTF-8"))
            except (binascii.Error, json.decoder.JSONDecodeError, UnicodeDecodeError):
                try:
                    fjsonrawcontent = fprejsoncontent
                    fjsoncontent = json.loads(fprejsoncontent)
                except (binascii.Error, json.decoder.JSONDecodeError, UnicodeDecodeError):
                    fprejsoncontent = ""
                    fjsonrawcontent = fprejsoncontent 
                    fjsoncontent = {}
        else:
            fprejsoncontent = ""
            fjsonrawcontent = fprejsoncontent 
            fjsoncontent = {}
    elif(fjsontype=="list"):
        fprejsoncontent = fp.read(fjsonsize).decode("UTF-8")
        flisttmp = MkTempFile()
        flisttmp.write(fprejsoncontent.encode())
        flisttmp.seek(0)
        fjsoncontent = ReadFileHeaderData(flisttmp, fjsonlen, delimiter)
        flisttmp.close()
        fjsonrawcontent = fjsoncontent
        if(fjsonlen==1):
            try:
                fjsonrawcontent = base64.b64decode(fjsoncontent[0]).decode("UTF-8")
                fjsoncontent = json.loads(base64.b64decode(fjsoncontent[0]).decode("UTF-8"))
                fjsonlen = len(fjsoncontent)
            except (binascii.Error, json.decoder.JSONDecodeError, UnicodeDecodeError):
                try:
                    fjsonrawcontent = fjsoncontent[0]
                    fjsoncontent = json.loads(fjsoncontent[0])
                except (binascii.Error, json.decoder.JSONDecodeError, UnicodeDecodeError):
                    pass
    fp.seek(len(delimiter), 1)
    fjend = fp.tell() - 1
    jsonfcs = GetFileChecksum(fprejsoncontent, fjsonchecksumtype, True, formatspecs)
    if(jsonfcs != fjsonchecksum and not skipchecksum):
        VerbosePrintOut("File JSON Data Checksum Error with file " +
                        fname + " at offset " + str(fheaderstart))
        VerbosePrintOut("'" + fjsonchecksum + "' != " + "'" + jsonfcs + "'")
        return False
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
    fcontents = MkTempFile()
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
    fcontents.seek(0, 0)
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
            cfcontents = UncompressFileAlt(
                fcontents, formatspecs)
            cfcontents.seek(0, 0)
            fcontents = MkTempFile()
            shutil.copyfileobj(cfcontents, fcontents)
            cfcontents.close()
            fcontents.seek(0, 0)
            fccs = GetFileChecksum(
                fcontents.read(), HeaderOut[-3].lower(), False, formatspecs)
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
    fcontents.seek(0, 0)
    if(not contentasfile):
        fcontents = fcontents.read()
    outlist = {'fheadersize': fheadsize, 'fhstart': fheaderstart, 'fhend': fhend, 'ftype': ftype, 'fencoding': fencoding, 'fcencoding': fcencoding, 'fname': fname, 'fbasedir': fbasedir, 'flinkname': flinkname, 'fsize': fsize, 'fatime': fatime, 'fmtime': fmtime, 'fctime': fctime, 'fbtime': fbtime, 'fmode': fmode, 'fchmode': fchmode, 'ftypemod': ftypemod, 'fwinattributes': fwinattributes, 'fcompression': fcompression, 'fcsize': fcsize, 'fuid': fuid, 'funame': funame, 'fgid': fgid, 'fgname': fgname, 'finode': finode, 'flinkcount': flinkcount,
               'fdev': fdev, 'fminor': fdev_minor, 'fmajor': fdev_major, 'fseeknextfile': fseeknextfile, 'fheaderchecksumtype': HeaderOut[-4], 'fjsonchecksumtype': fjsonchecksumtype, 'fcontentchecksumtype': HeaderOut[-3], 'fnumfields': fnumfields + 2, 'frawheader': HeaderOut, 'fextrafields': fextrafields, 'fextrafieldsize': fextrasize, 'fextradata': fextrafieldslist, 'fjsontype': fjsontype, 'fjsonlen': fjsonlen, 'fjsonsize': fjsonsize, 'fjsonrawdata': fjsonrawcontent, 'fjsondata': fjsoncontent, 'fjstart': fjstart, 'fjend': fjend, 'fheaderchecksum': fcs, 'fjsonchecksum': fjsonchecksum, 'fcontentchecksum': fccs, 'fhascontents': pyhascontents, 'fcontentstart': fcontentstart, 'fcontentend': fcontentend, 'fcontentasfile': contentasfile, 'fcontents': fcontents}
    return outlist


def ReadFileHeaderDataWithContentToList(fp, listonly=False, contentasfile=False, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__):
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
    fcencoding = HeaderOut[4]
    if(re.findall("^[.|/]", HeaderOut[5])):
        fname = HeaderOut[5]
    else:
        fname = "./"+HeaderOut[5]
    fbasedir = os.path.dirname(fname)
    flinkname = HeaderOut[6]
    fsize = int(HeaderOut[7], 16)
    fatime = int(HeaderOut[8], 16)
    fmtime = int(HeaderOut[9], 16)
    fctime = int(HeaderOut[10], 16)
    fbtime = int(HeaderOut[11], 16)
    fmode = int(HeaderOut[12], 16)
    fchmode = stat.S_IMODE(fmode)
    ftypemod = stat.S_IFMT(fmode)
    fwinattributes = int(HeaderOut[13], 16)
    fcompression = HeaderOut[14]
    fcsize = int(HeaderOut[15], 16)
    fuid = int(HeaderOut[16], 16)
    funame = HeaderOut[17]
    fgid = int(HeaderOut[18], 16)
    fgname = HeaderOut[19]
    fid = int(HeaderOut[20], 16)
    finode = int(HeaderOut[21], 16)
    flinkcount = int(HeaderOut[22], 16)
    fdev = int(HeaderOut[23], 16)
    fdev_minor = int(HeaderOut[24], 16)
    fdev_major = int(HeaderOut[25], 16)
    fseeknextfile = HeaderOut[26]
    fjsontype = HeaderOut[27]
    fjsonlen = int(HeaderOut[28], 16)
    fjsonsize = int(HeaderOut[29], 16)
    fjsonchecksumtype = HeaderOut[30]
    fjsonchecksum = HeaderOut[31]
    fextrasize = int(HeaderOut[32], 16)
    fextrafields = int(HeaderOut[33], 16)
    fextrafieldslist = []
    extrastart = 34
    extraend = extrastart + fextrafields
    while(extrastart < extraend):
        fextrafieldslist.append(HeaderOut[extrastart])
        extrastart = extrastart + 1
    if(fextrafields==1):
        try:
            fextrafieldslist = json.loads(base64.b64decode(fextrafieldslist[0]).decode("UTF-8"))
            fextrafields = len(fextrafieldslist)
        except (binascii.Error, json.decoder.JSONDecodeError, UnicodeDecodeError):
            try:
                fextrafieldslist = json.loads(fextrafieldslist[0])
            except (binascii.Error, json.decoder.JSONDecodeError, UnicodeDecodeError):
                pass
    if(fjsontype=="json"):
        fjsoncontent = {}
        fprejsoncontent = fp.read(fjsonsize).decode("UTF-8")
        if(fjsonsize > 0):
            try:
                fjsonrawcontent = base64.b64decode(fprejsoncontent.encode("UTF-8")).decode("UTF-8")
                fjsoncontent = json.loads(base64.b64decode(fprejsoncontent.encode("UTF-8")).decode("UTF-8"))
            except (binascii.Error, json.decoder.JSONDecodeError, UnicodeDecodeError):
                try:
                    fjsonrawcontent = fprejsoncontent
                    fjsoncontent = json.loads(fprejsoncontent)
                except (binascii.Error, json.decoder.JSONDecodeError, UnicodeDecodeError):
                    fprejsoncontent = ""
                    fjsonrawcontent = fprejsoncontent 
                    fjsoncontent = {}
        else:
            fprejsoncontent = ""
            fjsonrawcontent = fprejsoncontent 
            fjsoncontent = {}
    elif(fjsontype=="list"):
        fprejsoncontent = fp.read(fjsonsize).decode("UTF-8")
        flisttmp = MkTempFile()
        flisttmp.write(fprejsoncontent.encode())
        flisttmp.seek(0)
        fjsoncontent = ReadFileHeaderData(flisttmp, fjsonlen, delimiter)
        flisttmp.close()
        fjsonrawcontent = fjsoncontent
        if(fjsonlen==1):
            try:
                fjsonrawcontent = base64.b64decode(fjsoncontent[0]).decode("UTF-8")
                fjsoncontent = json.loads(base64.b64decode(fjsoncontent[0]).decode("UTF-8"))
                fjsonlen = len(fjsoncontent)
            except (binascii.Error, json.decoder.JSONDecodeError, UnicodeDecodeError):
                try:
                    fjsonrawcontent = fjsoncontent[0]
                    fjsoncontent = json.loads(fjsoncontent[0])
                except (binascii.Error, json.decoder.JSONDecodeError, UnicodeDecodeError):
                    pass
    fp.seek(len(delimiter), 1)
    jsonfcs = GetFileChecksum(fprejsoncontent, fjsonchecksumtype, True, formatspecs)
    if(jsonfcs != fjsonchecksum and not skipchecksum):
        VerbosePrintOut("File JSON Data Checksum Error with file " +
                        fname + " at offset " + str(fheaderstart))
        VerbosePrintOut("'" + fjsonchecksum + "' != " + "'" + jsonfcs + "'")
        return False
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
    fcontents = MkTempFile()
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
            cfcontents = UncompressFileAlt(
                fcontents, formatspecs)
            cfcontents.seek(0, 0)
            fcontents = MkTempFile()
            shutil.copyfileobj(cfcontents, fcontents)
            cfcontents.close()
            fcontents.seek(0, 0)
            fccs = GetFileChecksum(
                fcontents.read(), HeaderOut[-3].lower(), False, formatspecs)
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
    fcontents.seek(0, 0)
    if(not contentasfile):
        fcontents = fcontents.read()
    outlist = [ftype, fencoding, fcencoding, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression, fcsize, fuid, funame, fgid, fgname, fid,
               finode, flinkcount, fdev, fdev_minor, fdev_major, fseeknextfile, fjsoncontent, fextrafieldslist, HeaderOut[-4], HeaderOut[-3], fcontents]
    return outlist


def ReadFileDataWithContent(fp, filestart=0, listonly=False, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__):
    if(not hasattr(fp, "read")):
        return False
    delimiter = formatspecs['format_delimiter']
    curloc = filestart
    try:
        fp.seek(0, 2)
    except OSError:
        SeekToEndOfFile(fp)
    except ValueError:
        SeekToEndOfFile(fp)
    CatSize = fp.tell()
    CatSizeEnd = CatSize
    fp.seek(curloc, 0)
    inheaderver = str(int(formatspecs['format_ver'].replace(".", "")))
    formstring = fp.read(formatspecs['format_len'] + len(inheaderver)).decode("UTF-8")
    formdelszie = len(formatspecs['format_delimiter'])
    formdel = fp.read(formdelszie).decode("UTF-8")
    if(formstring != formatspecs['format_magic']+inheaderver):
        return False
    if(formdel != formatspecs['format_delimiter']):
        return False
    if(formatspecs['new_style']):
        inheader = ReadFileHeaderDataBySize(
            fp, formatspecs['format_delimiter'])
    else:
        inheader = ReadFileHeaderDataWoSize(
            fp, formatspecs['format_delimiter'])
    fprechecksumtype = inheader[-2]
    fprechecksum = inheader[-1]
    headercheck = ValidateHeaderChecksum([formstring] + inheader[:-1], fprechecksumtype, fprechecksum, formatspecs)
    newfcs = GetHeaderChecksum([formstring] + inheader[:-1], fprechecksumtype, True, formatspecs)
    if(not headercheck and not skipchecksum):
        VerbosePrintOut(
            "File Header Checksum Error with file at offset " + str(0))
        VerbosePrintOut("'" + fprechecksum + "' != " +
                        "'" + newfcs + "'")
        return False
    fnumfiles = int(inheader[4], 16)
    countnum = 0
    flist = []
    while(countnum < fnumfiles):
        HeaderOut = ReadFileHeaderDataWithContent(
            fp, listonly, uncompress, skipchecksum, formatspecs)
        if(len(HeaderOut) == 0):
            break
        flist.append(HeaderOut)
        countnum = countnum + 1
    return flist


def ReadFileDataWithContentToArray(fp, filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__, seektoend=False):
    if(not hasattr(fp, "read")):
        return False
    delimiter = formatspecs['format_delimiter']
    curloc = filestart
    try:
        fp.seek(0, 2)
    except OSError:
        SeekToEndOfFile(fp)
    except ValueError:
        SeekToEndOfFile(fp)
    CatSize = fp.tell()
    CatSizeEnd = CatSize
    fp.seek(curloc, 0)
    inheaderver = str(int(formatspecs['format_ver'].replace(".", "")))
    formstring = fp.read(formatspecs['format_len'] + len(inheaderver)).decode("UTF-8")
    formdelszie = len(formatspecs['format_delimiter'])
    formdel = fp.read(formdelszie).decode("UTF-8")
    if(formstring != formatspecs['format_magic']+inheaderver):
        return False
    if(formdel != formatspecs['format_delimiter']):
        return False
    if(formatspecs['new_style']):
        inheader = ReadFileHeaderDataBySize(
            fp, formatspecs['format_delimiter'])
    else:
        inheader = ReadFileHeaderDataWoSize(
            fp, formatspecs['format_delimiter'])
    fnumextrafieldsize = int(inheader[5], 16)
    fnumextrafields = int(inheader[6], 16)
    fextrafieldslist = []
    extrastart = 7
    extraend = extrastart + fnumextrafields
    while(extrastart < extraend):
        fextrafieldslist.append(inheader[extrastart])
        extrastart = extrastart + 1
    if(fnumextrafields==1):
        try:
            fextrafieldslist = json.loads(base64.b64decode(fextrafieldslist[0]).decode("UTF-8"))
            fnumextrafields = len(fextrafieldslist)
        except (binascii.Error, json.decoder.JSONDecodeError, UnicodeDecodeError):
            try:
                fextrafieldslist = json.loads(fextrafieldslist[0])
            except (binascii.Error, json.decoder.JSONDecodeError, UnicodeDecodeError):
                pass
    formversion = re.findall("([\\d]+)", formstring)
    fheadsize = int(inheader[0], 16)
    fnumfields = int(inheader[1], 16)
    fhencoding = inheader[2]
    fostype = inheader[3]
    fnumfiles = int(inheader[4], 16)
    fprechecksumtype = inheader[-2]
    fprechecksum = inheader[-1]
    headercheck = ValidateHeaderChecksum([formstring] + inheader[:-1], fprechecksumtype, fprechecksum, formatspecs)
    newfcs = GetHeaderChecksum([formstring] + inheader[:-1], fprechecksumtype, True, formatspecs)
    if(not headercheck and not skipchecksum):
        VerbosePrintOut(
            "File Header Checksum Error with file at offset " + str(0))
        VerbosePrintOut("'" + fprechecksum + "' != " +
                        "'" + newfcs + "'")
        return False
    formversions = re.search('(.*?)(\\d+)', formstring).groups()
    fcompresstype = ""
    outlist = {'fnumfiles': fnumfiles, 'ffilestart': filestart, 'fformat': formversions[0], 'fcompression': fcompresstype, 'fencoding': fhencoding, 'fversion': formversions[1], 'fostype': fostype, 'fheadersize': fheadsize, 'fsize': CatSizeEnd, 'fnumfields': fnumfields + 2, 'fformatspecs': formatspecs, 'fchecksumtype': fprechecksumtype, 'fheaderchecksum': fprechecksum, 'frawheader': [formstring] + inheader, 'fextrafields': fnumextrafields, 'fextrafieldsize': fnumextrafieldsize, 'fextradata': fextrafieldslist, 'ffilelist': []}
    if (seekstart < 0) or (seekstart > fnumfiles):
        seekstart = 0
    if (seekend == 0) or (seekend > fnumfiles) or (seekend < seekstart):
        seekend = fnumfiles
    elif (seekend < 0) and (abs(seekend) <= fnumfiles) and (abs(seekend) >= seekstart):
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
            if(re.findall("^[.|/]", preheaderdata[5])):
                prefname = preheaderdata[5]
            else:
                prefname = "./"+preheaderdata[5]
            prefseeknextfile = preheaderdata[26]
            prefjsonlen = int(preheaderdata[28], 16)
            prefjsonsize = int(preheaderdata[29], 16)
            prefjsonchecksumtype = preheaderdata[30]
            prefjsonchecksum = preheaderdata[31]
            prejsoncontent = fp.read(prefjsonsize).decode("UTF-8")
            fp.seek(len(delimiter), 1)
            prejsonfcs = GetFileChecksum(prejsoncontent, prefjsonchecksumtype, True, formatspecs)
            if(prejsonfcs != prefjsonchecksum and not skipchecksum):
                VerbosePrintOut("File JSON Data Checksum Error with file " +
                                prefname + " at offset " + str(prefhstart))
                VerbosePrintOut("'" + prefjsonchecksum + "' != " + "'" + prejsonfcs + "'")
                return False
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
            prefcontents = MkTempFile()
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
    while (fp.tell() < CatSizeEnd) if seektoend else (countnum < seekend):
        HeaderOut = ReadFileHeaderDataWithContentToArray(
            fp, listonly, contentasfile, uncompress, skipchecksum, formatspecs)
        if(len(HeaderOut) == 0):
            break
        HeaderOut.update({'fid': realidnum, 'fidalt': realidnum})
        outlist['ffilelist'].append(HeaderOut)
        countnum = countnum + 1
        realidnum = realidnum + 1
    outlist.update({'fp': fp})
    return outlist


def ReadFileDataWithContentToList(fp, filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=False, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__, seektoend=False):
    if(not hasattr(fp, "read")):
        return False
    delimiter = formatspecs['format_delimiter']
    curloc = filestart
    try:
        fp.seek(0, 2)
    except OSError:
        SeekToEndOfFile(fp)
    except ValueError:
        SeekToEndOfFile(fp)
    CatSize = fp.tell()
    CatSizeEnd = CatSize
    fp.seek(curloc, 0)
    inheaderver = str(int(formatspecs['format_ver'].replace(".", "")))
    formstring = fp.read(formatspecs['format_len'] + len(inheaderver)).decode("UTF-8")
    formdelszie = len(formatspecs['format_delimiter'])
    formdel = fp.read(formdelszie).decode("UTF-8")
    if(formstring != formatspecs['format_magic']+inheaderver):
        return False
    if(formdel != formatspecs['format_delimiter']):
        return False
    if(formatspecs['new_style']):
        inheader = ReadFileHeaderDataBySize(
            fp, formatspecs['format_delimiter'])
    else:
        inheader = ReadFileHeaderDataWoSize(
            fp, formatspecs['format_delimiter'])
    fnumextrafieldsize = int(inheader[5], 16)
    fnumextrafields = int(inheader[6], 16)
    fextrafieldslist = []
    extrastart = 7
    extraend = extrastart + fnumextrafields
    while(extrastart < extraend):
        fextrafieldslist.append(inheader[extrastart])
        extrastart = extrastart + 1
    if(fnumextrafields==1):
        try:
            fextrafieldslist = json.loads(base64.b64decode(fextrafieldslist[0]).decode("UTF-8"))
            fnumextrafields = len(fextrafieldslist)
        except (binascii.Error, json.decoder.JSONDecodeError, UnicodeDecodeError):
            try:
                fextrafieldslist = json.loads(fextrafieldslist[0])
            except (binascii.Error, json.decoder.JSONDecodeError, UnicodeDecodeError):
                pass
    formversion = re.findall("([\\d]+)", formstring)
    fheadsize = int(inheader[0], 16)
    fnumfields = int(inheader[1], 16)
    fhencoding = inheader[2]
    fostype = inheader[3]
    fnumfiles = int(inheader[4], 16)
    fprechecksumtype = inheader[-2]
    fprechecksum = inheader[-1]
    headercheck = ValidateHeaderChecksum([formstring] + inheader[:-1], fprechecksumtype, fprechecksum, formatspecs)
    newfcs = GetHeaderChecksum([formstring] + inheader[:-1], fprechecksumtype, True, formatspecs)
    if(not headercheck and not skipchecksum):
        VerbosePrintOut(
            "File Header Checksum Error with file at offset " + str(0))
        VerbosePrintOut("'" + fprechecksum + "' != " +
                        "'" + newfcs + "'")
        return False
    formversions = re.search('(.*?)(\\d+)', formstring).groups()
    outlist = []
    if (seekstart < 0) or (seekstart > fnumfiles):
        seekstart = 0
    if (seekend == 0) or (seekend > fnumfiles) or (seekend < seekstart):
        seekend = fnumfiles
    elif (seekend < 0) and (abs(seekend) <= fnumfiles) and (abs(seekend) >= seekstart):
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
            prefsize = int(preheaderdata[5], 16)
            if(re.findall("^[.|/]", preheaderdata[5])):
                prefname = preheaderdata[5]
            else:
                prefname = "./"+preheaderdata[5]
            prefcompression = preheaderdata[14]
            prefcsize = int(preheaderdata[15], 16)
            prefseeknextfile = preheaderdata[26]
            prefjsonlen = int(preheaderdata[28], 16)
            prefjsonsize = int(preheaderdata[29], 16)
            prefjsonchecksumtype = preheaderdata[30]
            prefjsonchecksum = preheaderdata[31]
            prefprejsoncontent = fp.read(prefjsonsize).decode("UTF-8")
            fp.seek(len(delimiter), 1)
            prejsonfcs = GetFileChecksum(prefprejsoncontent, prefjsonchecksumtype, True, formatspecs)
            if(prejsonfcs != prefjsonchecksum and not skipchecksum):
                VerbosePrintOut("File JSON Data Checksum Error with file " +
                                prefname + " at offset " + str(prefhstart))
                VerbosePrintOut("'" + prefjsonchecksum + "' != " + "'" + prejsonfcs + "'")
                return False
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
    while (fp.tell() < CatSizeEnd) if seektoend else (countnum < seekend):
        HeaderOut = ReadFileHeaderDataWithContentToList(
            fp, listonly, contentasfile, uncompress, skipchecksum, formatspecs)
        if(len(HeaderOut) == 0):
            break
        outlist.append(HeaderOut)
        countnum = countnum + 1
        realidnum = realidnum + 1
    return outlist


def ReadInFileWithContentToArray(infile, fmttype="auto", filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_multi_dict__, seektoend=False):
    if(IsNestedDict(formatspecs) and fmttype!="auto" and fmttype in formatspecs):
        formatspecs = formatspecs[fmttype]
    elif(IsNestedDict(formatspecs) and fmttype!="auto" and fmttype not in formatspecs):
        fmttype = "auto"
    if(hasattr(infile, "read") or hasattr(infile, "write")):
        fp = infile
        fp.seek(filestart, 0)
        compresscheck = CheckCompressionType(fp, formatspecs, filestart, False)
        if(IsNestedDict(formatspecs) and compresscheck in formatspecs):
            formatspecs = formatspecs[compresscheck]
        else:
            fp.seek(filestart, 0)
            checkcompressfile = CheckCompressionSubType(fp, formatspecs, filestart, False)
            if(IsNestedDict(formatspecs) and checkcompressfile in formatspecs):
                formatspecs = formatspecs[checkcompressfile]
        fp.seek(filestart, 0)
        fp = UncompressFileAlt(fp, formatspecs, filestart)
        checkcompressfile = CheckCompressionSubType(fp, formatspecs, filestart, True)
        if(checkcompressfile == "tarfile" and TarFileCheck(infile)):
            return TarFileToArray(infile, seekstart, seekend, listonly, contentasfile, skipchecksum, formatspecs, seektoend, True)
        elif(checkcompressfile == "zipfile" and zipfile.is_zipfile(infile)):
            return ZipFileToArray(infile, seekstart, seekend, listonly, contentasfile, skipchecksum, formatspecs, seektoend, True)
        elif(rarfile_support and checkcompressfile == "rarfile" and (rarfile.is_rarfile(infile) or rarfile.is_rarfile_sfx(infile))):
            return RarFileToArray(infile, seekstart, seekend, listonly, contentasfile, skipchecksum, formatspecs, seektoend, True)
        elif(py7zr_support and checkcompressfile == "7zipfile" and py7zr.is_7zfile(infile)):
            return SevenZipFileToArray(infile, seekstart, seekend, listonly, contentasfile, skipchecksum, formatspecs, seektoend, True)
        elif(IsSingleDict(formatspecs) and checkcompressfile != formatspecs['format_magic']):
            return False
        elif(IsNestedDict(formatspecs) and checkcompressfile not in formatspecs):
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
        fp.seek(filestart, 0)
    elif(infile == "-"):
        fp = MkTempFile()
        if(hasattr(sys.stdin, "buffer")):
            shutil.copyfileobj(sys.stdin.buffer, fp)
        else:
            shutil.copyfileobj(sys.stdin, fp)
        fp.seek(filestart, 0)
        fp = UncompressFileAlt(fp, formatspecs, filestart)
        fp.seek(filestart, 0)
        compresscheck = CheckCompressionType(fp, formatspecs, filestart, False)
        if(IsNestedDict(formatspecs) and compresscheck in formatspecs):
            formatspecs = formatspecs[compresscheck]
        else:
            fp.seek(filestart, 0)
            checkcompressfile = CheckCompressionSubType(fp, formatspecs, filestart, False)
            if(IsNestedDict(formatspecs) and checkcompressfile in formatspecs):
                formatspecs = formatspecs[checkcompressfile]
        fp.seek(filestart, 0)
        if(not fp):
            return False
        fp.seek(filestart, 0)
    elif(isinstance(infile, bytes) and sys.version_info[0] >= 3):
        fp = MkTempFile()
        fp.write(infile)
        fp.seek(filestart, 0)
        fp = UncompressFileAlt(fp, formatspecs, filestart)
        fp.seek(filestart, 0)
        compresscheck = CheckCompressionType(fp, formatspecs, filestart, False)
        if(IsNestedDict(formatspecs) and compresscheck in formatspecs):
            formatspecs = formatspecs[compresscheck]
        else:
            fp.seek(filestart, 0)
            checkcompressfile = CheckCompressionSubType(fp, formatspecs, filestart, False)
            if(IsNestedDict(formatspecs) and checkcompressfile in formatspecs):
                formatspecs = formatspecs[checkcompressfile]
        fp.seek(filestart, 0)
        if(not fp):
            return False
        fp.seek(filestart, 0)
    elif(re.findall(__download_proto_support__, infile)):
        fp = download_file_from_internet_file(infile)
        fp.seek(filestart, 0)
        compresscheck = CheckCompressionType(fp, formatspecs, filestart, False)
        if(IsNestedDict(formatspecs) and compresscheck in formatspecs):
            formatspecs = formatspecs[compresscheck]
        else:
            fp.seek(filestart, 0)
            checkcompressfile = CheckCompressionSubType(fp, formatspecs, filestart, False)
            if(IsNestedDict(formatspecs) and checkcompressfile in formatspecs):
                formatspecs = formatspecs[checkcompressfile]
        fp.seek(filestart, 0)
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
        fp.seek(filestart, 0)
        fp = UncompressFileAlt(fp, formatspecs, filestart)
        if(not fp):
            return False
        fp.seek(filestart, 0)
    else:
        infile = RemoveWindowsPath(infile)
        checkcompressfile = CheckCompressionSubType(infile, formatspecs, filestart, True)
        if(IsNestedDict(formatspecs) and checkcompressfile in formatspecs):
            formatspecs = formatspecs[checkcompressfile]
        if(checkcompressfile == "tarfile" and TarFileCheck(infile)):
            return TarFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, seektoend, True)
        elif(checkcompressfile == "zipfile" and zipfile.is_zipfile(infile)):
            return ZipFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, seektoend, True)
        elif(rarfile_support and checkcompressfile == "rarfile" and (rarfile.is_rarfile(infile) or rarfile.is_rarfile_sfx(infile))):
            return RarFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, seektoend, True)
        elif(py7zr_support and checkcompressfile == "7zipfile" and py7zr.is_7zfile(infile)):
            return SevenZipFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, seektoend, True)
        elif(IsSingleDict(formatspecs) and checkcompressfile != formatspecs['format_magic']):
            return False
        elif(IsNestedDict(formatspecs) and checkcompressfile not in formatspecs):
            return False
        compresscheck = CheckCompressionType(infile, formatspecs, filestart, True)
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
        fp = UncompressFile(infile, formatspecs, "rb", filestart)
    return ReadFileDataWithContentToArray(fp, filestart, seekstart, seekend, listonly, contentasfile, uncompress, skipchecksum, formatspecs, seektoend)


def ReadInMultipleFileWithContentToArray(infile, fmttype="auto", filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_multi_dict__, seektoend=False):
    if(isinstance(infile, (list, tuple, ))):
        pass
    else:
        infile = [infile]
    outretval = {}
    for curfname in infile:
        outretval[curfname] = ReadInFileWithContentToArray(curfname, fmttype, filestart, seekstart, seekend, listonly, contentasfile, uncompress, skipchecksum, formatspecs, seektoend)
    return outretval

def ReadInMultipleFilesWithContentToArray(infile, fmttype="auto", filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_multi_dict__, seektoend=False):
    return ReadInMultipleFileWithContentToArray(infile, fmttype, filestart, seekstart, seekend, listonly, contentasfile, uncompress, skipchecksum, formatspecs, seektoend)


def ReadInStackedFileWithContentToArray(infile, fmttype="auto", filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_multi_dict__, seektoend=False):
    outretval = []
    outstartfile = filestart
    outfsize = float('inf')
    while True:
        if outstartfile >= outfsize:   # stop when function signals False
            break
        outarray = CatFileToArray(infile, fmttype, outstartfile, seekstart, seekend, listonly, contentasfile, uncompress, skipchecksum, formatspecs, seektoend, True)
        outfsize = outarray['fsize']
        if outarray is False:   # stop when function signals False
            break
        infile = outarray['fp']
        outstartfile = infile.tell()
        outretval.append(outarray)
    return outretval


def ReadInMultipleStackedFileWithContentToArray(infile, fmttype="auto", filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_multi_dict__, seektoend=False):
    if(isinstance(infile, (list, tuple, ))):
        pass
    else:
        infile = [infile]
    outretval = {}
    for curfname in infile:
        outretval[curfname] = ReadInStackedFileWithContentToArray(curfname, fmttype, filestart, seekstart, seekend, listonly, contentasfile, uncompress, skipchecksum, formatspecs, seektoend)
    return outretval


def ReadInStackedFilesWithContentToArray(infile, fmttype="auto", filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_multi_dict__, seektoend=False):
    return ReadInStackedFileWithContentToArray(infile, fmttype, filestart, seekstart, seekend, listonly, contentasfile, uncompress, skipchecksum, formatspecs, seektoend)


def ReadInMultipleStackedFilesWithContentToArray(infile, fmttype="auto", filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_multi_dict__, seektoend=False):
    return ReadInMultipleStackedFileWithContentToArray(infile, fmttype, filestart, seekstart, seekend, listonly, contentasfile, uncompress, skipchecksum, formatspecs, seektoend)


def ReadInFileWithContentToList(infile, fmttype="auto", filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_multi_dict__, seektoend=False):
    if(IsNestedDict(formatspecs) and fmttype!="auto" and fmttype in formatspecs):
        formatspecs = formatspecs[fmttype]
    elif(IsNestedDict(formatspecs) and fmttype!="auto" and fmttype not in formatspecs):
        fmttype = "auto"
    if(hasattr(infile, "read") or hasattr(infile, "write")):
        fp = infile
        fp.seek(filestart, 0)
        compresscheck = CheckCompressionType(fp, formatspecs, filestart, False)
        if(IsNestedDict(formatspecs) and compresscheck in formatspecs):
            formatspecs = formatspecs[compresscheck]
        else:
            fp.seek(filestart, 0)
            checkcompressfile = CheckCompressionSubType(fp, formatspecs, filestart, False)
            if(IsNestedDict(formatspecs) and checkcompressfile in formatspecs):
                formatspecs = formatspecs[checkcompressfile]
        fp.seek(filestart, 0)
        fp = UncompressFileAlt(fp, formatspecs, filestart)
        checkcompressfile = CheckCompressionSubType(fp, formatspecs, filestart, True)
        if(checkcompressfile == "tarfile" and TarFileCheck(infile)):
            return TarFileToArray(infile, seekstart, seekend, listonly, contentasfile, skipchecksum, formatspecs, seektoend, True)
        elif(checkcompressfile == "zipfile" and zipfile.is_zipfile(infile)):
            return ZipFileToArray(infile, seekstart, seekend, listonly, contentasfile, skipchecksum, formatspecs, seektoend, True)
        elif(rarfile_support and checkcompressfile == "rarfile" and (rarfile.is_rarfile(infile) or rarfile.is_rarfile_sfx(infile))):
            return RarFileToArray(infile, seekstart, seekend, listonly, contentasfile, skipchecksum, formatspecs, seektoend, True)
        elif(py7zr_support and checkcompressfile == "7zipfile" and py7zr.is_7zfile(infile)):
            return SevenZipFileToArray(infile, seekstart, seekend, listonly, contentasfile, skipchecksum, formatspecs, seektoend, True)
        elif(IsSingleDict(formatspecs) and checkcompressfile != formatspecs['format_magic']):
            return False
        elif(IsNestedDict(formatspecs) and checkcompressfile not in formatspecs):
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
        fp.seek(filestart, 0)
    elif(infile == "-"):
        fp = MkTempFile()
        if(hasattr(sys.stdin, "buffer")):
            shutil.copyfileobj(sys.stdin.buffer, fp)
        else:
            shutil.copyfileobj(sys.stdin, fp)
        fp.seek(filestart, 0)
        fp = UncompressFileAlt(fp, formatspecs, filestart)
        fp.seek(filestart, 0)
        compresscheck = CheckCompressionType(fp, formatspecs, filestart, False)
        if(IsNestedDict(formatspecs) and compresscheck in formatspecs):
            formatspecs = formatspecs[compresscheck]
        else:
            fp.seek(filestart, 0)
            checkcompressfile = CheckCompressionSubType(fp, formatspecs, filestart, False)
            if(IsNestedDict(formatspecs) and checkcompressfile in formatspecs):
                formatspecs = formatspecs[checkcompressfile]
        fp.seek(filestart, 0)
        if(not fp):
            return False
        fp.seek(filestart, 0)
    elif(isinstance(infile, bytes) and sys.version_info[0] >= 3):
        fp = MkTempFile()
        fp.write(infile)
        fp.seek(filestart, 0)
        fp = UncompressFileAlt(fp, formatspecs, filestart)
        fp.seek(filestart, 0)
        compresscheck = CheckCompressionType(fp, formatspecs, filestart, False)
        if(IsNestedDict(formatspecs) and compresscheck in formatspecs):
            formatspecs = formatspecs[compresscheck]
        else:
            fp.seek(filestart, 0)
            checkcompressfile = CheckCompressionSubType(fp, formatspecs, filestart, False)
            if(IsNestedDict(formatspecs) and checkcompressfile in formatspecs):
                formatspecs = formatspecs[checkcompressfile]
        fp.seek(filestart, 0)
        if(not fp):
            return False
        fp.seek(filestart, 0)
    elif(re.findall(__download_proto_support__, infile)):
        fp = download_file_from_internet_file(infile)
        fp.seek(filestart, 0)
        compresscheck = CheckCompressionType(fp, formatspecs, filestart, False)
        if(IsNestedDict(formatspecs) and compresscheck in formatspecs):
            formatspecs = formatspecs[compresscheck]
        else:
            fp.seek(filestart, 0)
            checkcompressfile = CheckCompressionSubType(fp, formatspecs, filestart, False)
            if(IsNestedDict(formatspecs) and checkcompressfile in formatspecs):
                formatspecs = formatspecs[checkcompressfile]
        fp.seek(filestart, 0)
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
        fp.seek(filestart, 0)
        fp = UncompressFileAlt(fp, formatspecs, filestart)
        if(not fp):
            return False
        fp.seek(filestart, 0)
    else:
        infile = RemoveWindowsPath(infile)
        checkcompressfile = CheckCompressionSubType(infile, formatspecs, filestart, True)
        if(IsNestedDict(formatspecs) and checkcompressfile in formatspecs):
            formatspecs = formatspecs[checkcompressfile]
        if(checkcompressfile == "tarfile" and TarFileCheck(infile)):
            return TarFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, seektoend, True)
        elif(checkcompressfile == "zipfile" and zipfile.is_zipfile(infile)):
            return ZipFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, seektoend, True)
        elif(rarfile_support and checkcompressfile == "rarfile" and (rarfile.is_rarfile(infile) or rarfile.is_rarfile_sfx(infile))):
            return RarFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, seektoend, True)
        elif(py7zr_support and checkcompressfile == "7zipfile" and py7zr.is_7zfile(infile)):
            return SevenZipFileToArray(infile, seekstart, seekend, listonly, skipchecksum, formatspecs, seektoend, True)
        elif(IsSingleDict(formatspecs) and checkcompressfile != formatspecs['format_magic']):
            return False
        elif(IsNestedDict(formatspecs) and checkcompressfile not in formatspecs):
            return False
        compresscheck = CheckCompressionType(infile, formatspecs, filestart, True)
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
        fp = UncompressFile(infile, formatspecs, "rb", filestart)
    return ReadFileDataWithContentToList(fp, filestart, seekstart, seekend, listonly, contentasfile, uncompress, skipchecksum, formatspecs, seektoend)


def ReadInMultipleFileWithContentToList(infile, fmttype="auto", filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_multi_dict__, seektoend=False):
    if(isinstance(infile, (list, tuple, ))):
        pass
    else:
        infile = [infile]
    outretval = {}
    for curfname in infile:
        outretval[curfname] = ReadInFileWithContentToList(curfname, fmttype, filestart, seekstart, seekend, listonly, contentasfile, uncompress, skipchecksum, formatspecs, seektoend)
    return outretval

def ReadInMultipleFilesWithContentToList(infile, fmttype="auto", filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_multi_dict__, seektoend=False):
    return ReadInMultipleFileWithContentToList(infile, fmttype, filestart, seekstart, seekend, listonly, contentasfile, uncompress, skipchecksum, formatspecs, seektoend)


def AppendNullByte(indata, delimiter=__file_format_dict__['format_delimiter']):
    if(isinstance(indata, int)):
        indata = str(indata)
    outdata = indata.encode("UTF-8") + delimiter.encode("UTF-8")
    return outdata


def AppendNullBytes(indata=[], delimiter=__file_format_dict__['format_delimiter']):
    outdata = "".encode("UTF-8")
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
    formver = formatspecs['format_ver']
    fileheaderver = str(int(formver.replace(".", "")))
    fileheader = AppendNullByte(
        formatspecs['format_magic'] + fileheaderver, formatspecs['format_delimiter'])
    if (isinstance(extradata, dict) or IsNestedDictAlt(extradata)) and len(extradata) > 0:
        extradata = [base64.b64encode(json.dumps(extradata, separators=(',', ':')).encode("UTF-8")).decode("UTF-8")]
    elif (isinstance(extradata, dict) or IsNestedDictAlt(extradata)) and len(extradata) == 0:
        extradata = []
    extrafields = format(len(extradata), 'x').lower()
    extrasizestr = AppendNullByte(extrafields, formatspecs['format_delimiter'])
    if(len(extradata) > 0):
        extrasizestr = extrasizestr + \
            AppendNullBytes(extradata, formatspecs['format_delimiter'])
    extrasizelen = format(len(extrasizestr), 'x').lower()
    tmpoutlist = []
    tmpoutlist.append(extrasizelen)
    tmpoutlist.append(extrafields)
    fnumfiles = format(numfiles, 'x').lower()
    tmpoutlen = 3 + len(tmpoutlist) + len(extradata) + 2
    tmpoutlenhex = format(tmpoutlen, 'x').lower()
    fnumfilesa = AppendNullBytes(
        [tmpoutlenhex, fencoding, platform.system(), fnumfiles], formatspecs['format_delimiter'])
    fnumfilesa = fnumfilesa + AppendNullBytes(
        tmpoutlist, formatspecs['format_delimiter'])
    if(len(extradata) > 0):
        fnumfilesa = fnumfilesa + AppendNullBytes(
            extradata, formatspecs['format_delimiter'])
    fnumfilesa = fnumfilesa + \
        AppendNullByte(checksumtype, formatspecs['format_delimiter'])
    outfileheadercshex = GetFileChecksum(
        fnumfilesa, checksumtype, True, formatspecs)
    tmpfileoutstr = fnumfilesa + \
        AppendNullByte(outfileheadercshex,
                        formatspecs['format_delimiter'])
    formheaersize = format(int(len(tmpfileoutstr) - len(formatspecs['format_delimiter'])), 'x').lower()
    fnumfilesa = fileheader + \
        AppendNullByte(
        formheaersize, formatspecs['format_delimiter']) + fnumfilesa
    outfileheadercshex = GetFileChecksum(
        fnumfilesa, checksumtype, True, formatspecs)
    fnumfilesa = fnumfilesa + \
        AppendNullByte(outfileheadercshex, formatspecs['format_delimiter'])
    formheaersize = format(int(len(fnumfilesa) - len(formatspecs['format_delimiter'])), 'x').lower()
    formheaersizestr = AppendNullByte(formheaersize, formatspecs['format_delimiter'])
    try:
        fp.write(fnumfilesa)
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


def MakeEmptyFilePointer(fp, fmttype=__file_format_default__, checksumtype="crc32", formatspecs=__file_format_multi_dict__):
    if(IsNestedDict(formatspecs) and fmttype in formatspecs):
        formatspecs = formatspecs[fmttype]
    elif(IsNestedDict(formatspecs) and fmttype not in formatspecs):
        fmttype = __file_format_default__
        formatspecs = formatspecs[fmttype]
    AppendFileHeader(fp, 0, "UTF-8", [], checksumtype, formatspecs)
    return fp


def MakeEmptyCatFilePointer(fp, fmttype=__file_format_default__, checksumtype="crc32", formatspecs=__file_format_multi_dict__):
    return MakeEmptyFilePointer(fp, fmttype, checksumtype, formatspecs)


def MakeEmptyFile(outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype="crc32", formatspecs=__file_format_multi_dict__, returnfp=False):
    if(IsNestedDict(formatspecs) and fmttype=="auto" and 
        (outfile != "-" and outfile is not None and not hasattr(outfile, "read") and not hasattr(outfile, "write"))):
        get_in_ext = os.path.splitext(outfile)
        tmpfmt = GetKeyByFormatExtension(get_in_ext[1], formatspecs=__file_format_multi_dict__)
        if(tmpfmt is None and get_in_ext[1]!=""):
            get_in_ext = os.path.splitext(get_in_ext[0])
            tmpfmt = GetKeyByFormatExtension(get_in_ext[0], formatspecs=__file_format_multi_dict__)
        if(tmpfmt is None):
            fmttype = __file_format_default__
            formatspecs = formatspecs[fmttype]
        else:
            fmttype = tmpfmt
            formatspecs = formatspecs[tmpfmt]
    elif(IsNestedDict(formatspecs) and fmttype in formatspecs):
        formatspecs = formatspecs[fmttype]
    elif(IsNestedDict(formatspecs) and fmttype not in formatspecs):
        fmttype = __file_format_default__
        formatspecs = formatspecs[fmttype]
    if(outfile != "-" and outfile is not None and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
        if(os.path.exists(outfile)):
            try:
                os.unlink(outfile)
            except OSError:
                pass
    if(outfile == "-" or outfile is None):
        verbose = False
        fp = MkTempFile()
    elif(hasattr(outfile, "read") or hasattr(outfile, "write")):
        fp = outfile
    elif(re.findall(__upload_proto_support__, outfile)):
        fp = MkTempFile()
    else:
        fbasename = os.path.splitext(outfile)[0]
        fextname = os.path.splitext(outfile)[1]
        if(not compresswholefile and fextname in outextlistwd):
            compresswholefile = True
        try:
            fp = CompressOpenFile(outfile, compresswholefile, compressionlevel)
        except PermissionError:
            return False
    AppendFileHeader(fp, 0, "UTF-8", [], checksumtype, formatspecs)
    if(outfile == "-" or outfile is None or hasattr(outfile, "read") or hasattr(outfile, "write")):
        fp = CompressOpenFileAlt(
            fp, compression, compressionlevel, compressionuselist, formatspecs)
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
    elif(re.findall(__upload_proto_support__, outfile)):
        fp = CompressOpenFileAlt(
            fp, compression, compressionlevel, compressionuselist, formatspecs)
        fp.seek(0, 0)
        upload_file_to_internet_file(fp, outfile)
    if(returnfp):
        fp.seek(0, 0)
        return fp
    else:
        fp.close()
        return True


def MakeEmptyCatFile(outfile, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype="crc32", formatspecs=__file_format_dict__, returnfp=False):
    return MakeEmptyFile(outfile, "auto", compression, compresswholefile, compressionlevel, compressionuselist, checksumtype, formatspecs, returnfp)


def AppendFileHeaderWithContent(fp, filevalues=[], extradata=[], jsondata={}, filecontent="", checksumtype=["crc32", "crc32", "crc32"], formatspecs=__file_format_dict__):
    if(not hasattr(fp, "write")):
        return False
    if (isinstance(extradata, dict) or IsNestedDictAlt(extradata)) and len(extradata) > 0:
        extradata = [base64.b64encode(json.dumps(extradata, separators=(',', ':')).encode("UTF-8")).decode("UTF-8")]
    elif (isinstance(extradata, dict) or IsNestedDictAlt(extradata)) and len(extradata) == 0:
        extradata = []
    extrafields = format(len(extradata), 'x').lower()
    extrasizestr = AppendNullByte(extrafields, formatspecs['format_delimiter'])
    if(len(extradata) > 0):
        extrasizestr = extrasizestr + \
            AppendNullBytes(extradata, formatspecs['format_delimiter'])
    extrasizelen = format(len(extrasizestr), 'x').lower()
    tmpoutlen = len(filevalues) + len(extradata) + 11
    tmpoutlenhex = format(tmpoutlen, 'x').lower()
    tmpoutlist = filevalues
    fjsontype = "json"
    if(len(jsondata) > 0):
        try:
            fjsoncontent = json.dumps(jsondata, separators=(',', ':')).encode("UTF-8")
        except (binascii.Error, json.decoder.JSONDecodeError, UnicodeDecodeError):
            fjsoncontent = "".encode("UTF-8")
    else:
        fjsoncontent = "".encode("UTF-8")
    fjsonsize = format(len(fjsoncontent), 'x').lower()
    fjsonlen = format(len(jsondata), 'x').lower()
    tmpoutlist.insert(0, tmpoutlenhex)
    tmpoutlist.append(fjsontype)
    tmpoutlist.append(fjsonlen)
    tmpoutlist.append(fjsonsize)
    if(len(jsondata) > 0):
        tmpoutlist.append(checksumtype[2])
        tmpoutlist.append(GetFileChecksum(fjsoncontent, checksumtype[2], True, formatspecs))
    else:
        tmpoutlist.append("none")
        tmpoutlist.append(GetFileChecksum(fjsoncontent, "none", True, formatspecs))
    tmpoutlist.append(extrasizelen)
    tmpoutlist.append(extrafields)
    outfileoutstr = AppendNullBytes(
        tmpoutlist, formatspecs['format_delimiter'])
    if(len(extradata) > 0):
        outfileoutstr = outfileoutstr + \
            AppendNullBytes(extradata, formatspecs['format_delimiter'])
    if(len(filecontent) == 0):
        checksumlist = [checksumtype[0], "none"]
    else:
        checksumlist = [checksumtype[0], checksumtype[1]]
    outfileoutstr = outfileoutstr + \
        AppendNullBytes(checksumlist, formatspecs['format_delimiter'])
    nullstrecd = formatspecs['format_delimiter'].encode('UTF-8')
    outfileheadercshex = GetFileChecksum(
        outfileoutstr, checksumtype[0], True, formatspecs)
    if(len(filecontent) == 0):
        outfilecontentcshex = GetFileChecksum(
            filecontent, "none", False, formatspecs)
    else:
        outfilecontentcshex = GetFileChecksum(
            filecontent, checksumtype[1], False, formatspecs)
    tmpfileoutstr = outfileoutstr + \
        AppendNullBytes([outfileheadercshex, outfilecontentcshex],
                        formatspecs['format_delimiter'])
    formheaersize = format(int(len(tmpfileoutstr) - len(formatspecs['format_delimiter'])), 'x').lower()
    outfileoutstr = AppendNullByte(
        formheaersize, formatspecs['format_delimiter']) + outfileoutstr
    outfileheadercshex = GetFileChecksum(
        outfileoutstr, checksumtype[0], True, formatspecs)
    outfileoutstr = outfileoutstr + \
        AppendNullBytes([outfileheadercshex, outfilecontentcshex],
                        formatspecs['format_delimiter'])
    outfileoutstrecd = outfileoutstr
    outfileout = outfileoutstrecd + fjsoncontent + nullstrecd +  filecontent + nullstrecd
    try:
        fp.write(outfileout)
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


def AppendFilesWithContent(infiles, fp, dirlistfromtxt=False, filevalues=[], extradata=[], jsondata={}, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, followlink=False, checksumtype=["crc32", "crc32", "crc32", "crc32"], formatspecs=__file_format_dict__, verbose=False):
    if(not hasattr(fp, "write")):
        return False
    advancedlist = formatspecs['use_advanced_list']
    altinode = formatspecs['use_alt_inode']
    if(verbose):
        logging.basicConfig(format="%(message)s",
                            stream=sys.stdout, level=logging.DEBUG)
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
    inodetoforminode = {}
    numfiles = int(len(GetDirList))
    fnumfiles = format(numfiles, 'x').lower()
    AppendFileHeader(fp, numfiles, "UTF-8", [], checksumtype[0], formatspecs)
    FullSizeFilesAlt = 0
    for curfname in GetDirList:
        fencoding = "UTF-8"
        if(re.findall("^[.|/]", curfname)):
            fname = curfname
        else:
            fname = "./"+curfname
        if(not os.path.exists(fname)):
            return False
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
                        fcurinode = format(int(inodetoforminode[unique_id]), 'x').lower()
                else:
                    # New inode
                    inodelist.append(unique_id)
                    inodetofile[unique_id] = fname
                    inodetoforminode[unique_id] = curinode
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
            if(not os.path.exists(flinkname)):
                return False
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
            fsize = format(int(fstatinfo.st_size), 'x').lower()
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
        fcontents = MkTempFile()
        chunk_size = 1024
        fcencoding = "UTF-8"
        curcompression = "none"
        if not followlink and ftype in data_types:
            with open(fname, "rb") as fpc:
                shutil.copyfileobj(fpc, fcontents)
                typechecktest = CheckCompressionType(fcontents, filestart=0, closefp=False)
                fcontents.seek(0, 0)
                fcencoding = GetFileEncoding(fcontents, 0, False)
                if(typechecktest is False and not compresswholefile):
                    fcontents.seek(0, 2)
                    ucfsize = fcontents.tell()
                    fcontents.seek(0, 0)
                    if(compression == "auto"):
                        ilsize = len(compressionuselist)
                        ilmin = 0
                        ilcsize = []
                        while(ilmin < ilsize):
                            cfcontents = MkTempFile()
                            fcontents.seek(0, 0)
                            shutil.copyfileobj(fcontents, cfcontents)
                            fcontents.seek(0, 0)
                            cfcontents.seek(0, 0)
                            cfcontents = CompressOpenFileAlt(
                                cfcontents, compressionuselist[ilmin], compressionlevel, compressionuselist, formatspecs)
                            if(cfcontents):
                                cfcontents.seek(0, 2)
                                ilcsize.append(cfcontents.tell())
                                cfcontents.close()
                            else:
                                ilcsize.append(float("inf"))
                            ilmin = ilmin + 1
                        ilcmin = ilcsize.index(min(ilcsize))
                        curcompression = compressionuselist[ilcmin]
                    fcontents.seek(0, 0)
                    cfcontents = MkTempFile()
                    shutil.copyfileobj(fcontents, cfcontents)
                    cfcontents.seek(0, 0)
                    cfcontents = CompressOpenFileAlt(
                        cfcontents, curcompression, compressionlevel, compressionuselist, formatspecs)
                    cfcontents.seek(0, 2)
                    cfsize = cfcontents.tell()
                    if(ucfsize > cfsize):
                        fcsize = format(int(cfsize), 'x').lower()
                        fcompression = curcompression
                        fcontents.close()
                        fcontents = cfcontents
        elif followlink and (ftype == 1 or ftype == 2):
            if(not os.path.exists(flinkname)):
                return False
            flstatinfo = os.stat(flinkname)
            with open(flinkname, "rb") as fpc:
                shutil.copyfileobj(fpc, fcontents)
                typechecktest = CheckCompressionType(fcontents, filestart=0, closefp=False)
                fcontents.seek(0, 0)
                fcencoding = GetFileEncoding(fcontents, 0, False)
                if(typechecktest is False and not compresswholefile):
                    fcontents.seek(0, 2)
                    ucfsize = fcontents.tell()
                    fcontents.seek(0, 0)
                    if(compression == "auto"):
                        ilsize = len(compressionuselist)
                        ilmin = 0
                        ilcsize = []
                        while(ilmin < ilsize):
                            cfcontents = MkTempFile()
                            fcontents.seek(0, 0)
                            shutil.copyfileobj(fcontents, cfcontents)
                            fcontents.seek(0, 0)
                            cfcontents.seek(0, 0)
                            cfcontents = CompressOpenFileAlt(
                                cfcontents, compressionuselist[ilmin], compressionlevel, compressionuselist, formatspecs)
                            if(cfcontents):
                                cfcontents.seek(0, 2)
                                ilcsize.append(cfcontents.tell())
                                cfcontents.close()
                            else:
                                ilcsize.append(float("inf"))
                            ilmin = ilmin + 1
                        ilcmin = ilcsize.index(min(ilcsize))
                        curcompression = compressionuselist[ilcmin]
                    fcontents.seek(0, 0)
                    cfcontents = MkTempFile()
                    shutil.copyfileobj(fcontents, cfcontents)
                    cfcontents.seek(0, 0)
                    cfcontents = CompressOpenFileAlt(
                        cfcontents, curcompression, compressionlevel, compressionuselist, formatspecs)
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
        tmpoutlist = [ftypehex, fencoding, fcencoding, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression,
                      fcsize, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev, fdev_minor, fdev_major, "+"+str(len(formatspecs['format_delimiter']))]
        AppendFileHeaderWithContent(
            fp, tmpoutlist, extradata, jsondata, fcontents.read(), [checksumtype[1], checksumtype[2], checksumtype[3]], formatspecs)
    fp.seek(0, 0)
    return fp


def AppendListsWithContent(inlist, fp, dirlistfromtxt=False, filevalues=[], extradata=[], jsondata={}, compression="auto", compresswholefile=True, compressionlevel=None, followlink=False, checksumtype=["crc32", "crc32", "crc32", "crc32"], formatspecs=__file_format_dict__, verbose=False):
    if(not hasattr(fp, "write")):
        return False
    if(verbose):
        logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG)
    GetDirList = inlist
    if(not GetDirList):
        return False
    curinode = 0
    curfid = 0
    inodelist = []
    inodetofile = {}
    filetoinode = {}
    inodetoforminode = {}
    numfiles = int(len(GetDirList))
    fnumfiles = format(numfiles, 'x').lower()
    AppendFileHeader(fp, numfiles, "UTF-8", [], checksumtype[0], formatspecs)
    for curfname in GetDirList:
        ftype = format(curfname[0], 'x').lower()
        fencoding = curfname[1]
        fcencoding = curfname[2]
        if(re.findall("^[.|/]", curfname[3])):
            fname = curfname[3]
        else:
            fname = "./"+curfname[3]
        if(not os.path.exists(fname)):
            return False
        fbasedir = os.path.dirname(fname)
        flinkname = curfname[4]
        fsize = format(curfname[5], 'x').lower()
        fatime = format(curfname[6], 'x').lower()
        fmtime = format(curfname[7], 'x').lower()
        fctime = format(curfname[8], 'x').lower()
        fbtime = format(curfname[9], 'x').lower()
        fmode = format(curfname[10], 'x').lower()
        fwinattributes = format(curfname[11], 'x').lower()
        fcompression = curfname[12]
        fcsize = format(curfname[13], 'x').lower()
        fuid = format(curfname[14], 'x').lower()
        funame = curfname[15]
        fgid = format(curfname[16], 'x').lower()
        fgname = curfname[17]
        fid = format(curfname[18], 'x').lower()
        finode = format(curfname[19], 'x').lower()
        flinkcount = format(curfname[20], 'x').lower()
        fdev = format(curfname[21], 'x').lower()
        fdev_minor = format(curfname[22], 'x').lower()
        fdev_major = format(curfname[23], 'x').lower()
        fseeknextfile = curfname[24]
        extradata = curfname[25]
        fheaderchecksumtype = curfname[26]
        fcontentchecksumtype = curfname[27]
        fcontents = curfname[28]
        fencoding = GetFileEncoding(fcontents, 0, False)
        tmpoutlist = [ftype, fencoding, fcencoding, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression, fcsize,
                      fuid, funame, fgid, fgname, fid, finode, flinkcount, fdev, fdev_minor, fdev_major, fseeknextfile]
        fcontents.seek(0, 0)
        AppendFileHeaderWithContent(
            fp, tmpoutlist, extradata, jsondata, fcontents.read(), [checksumtype[1], checksumtype[2], checksumtype[3]], formatspecs)
    return fp


def AppendInFileWithContent(infile, fp, dirlistfromtxt=False, filevalues=[], extradata=[], jsondata={}, followlink=False, checksumtype=["crc32", "crc32", "crc32", "crc32"], formatspecs=__file_format_dict__, verbose=False):
    inlist = ReadInFileWithContentToList(infile, "auto", 0, 0, False, False, True, False, formatspecs)
    return AppendListsWithContent(inlist, fp, dirlistfromtxt, filevalues, extradata, jsondata, followlink, checksumtype, formatspecs, verbose)


def AppendFilesWithContentToOutFile(infiles, outfile, dirlistfromtxt=False, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, filevalues=[], extradata=[], jsondata={}, followlink=False, checksumtype=["crc32", "crc32", "crc32", "crc32"], formatspecs=__file_format_multi_dict__, verbose=False, returnfp=False):
    if(IsNestedDict(formatspecs) and fmttype=="auto" and 
        (outfile != "-" and outfile is not None and not hasattr(outfile, "read") and not hasattr(outfile, "write"))):
        get_in_ext = os.path.splitext(outfile)
        tmpfmt = GetKeyByFormatExtension(get_in_ext[1], formatspecs=__file_format_multi_dict__)
        if(tmpfmt is None and get_in_ext[1]!=""):
            get_in_ext = os.path.splitext(get_in_ext[0])
            tmpfmt = GetKeyByFormatExtension(get_in_ext[0], formatspecs=__file_format_multi_dict__)
        if(tmpfmt is None):
            fmttype = __file_format_default__
            formatspecs = formatspecs[fmttype]
        else:
            fmttype = tmpfmt
            formatspecs = formatspecs[tmpfmt]
    elif(IsNestedDict(formatspecs) and fmttype in formatspecs):
        formatspecs = formatspecs[fmttype]
    elif(IsNestedDict(formatspecs) and fmttype not in formatspecs):
        fmttype = __file_format_default__
        formatspecs = formatspecs[fmttype]
    if(outfile != "-" and outfile is not None and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
        if(os.path.exists(outfile)):
            try:
                os.unlink(outfile)
            except OSError:
                pass
    if(outfile == "-" or outfile is None):
        verbose = False
        fp = MkTempFile()
    elif(hasattr(outfile, "read") or hasattr(outfile, "write")):
        fp = outfile
    elif(re.findall(__upload_proto_support__, outfile)):
        fp = MkTempFile()
    else:
        fbasename = os.path.splitext(outfile)[0]
        fextname = os.path.splitext(outfile)[1]
        if(not compresswholefile and fextname in outextlistwd):
            compresswholefile = True
        try:
            fp = CompressOpenFile(outfile, compresswholefile, compressionlevel)
        except PermissionError:
            return False
    AppendFilesWithContent(infiles, fp, dirlistfromtxt, filevalues, extradata, jsondata, compression,
                                   compresswholefile, compressionlevel, compressionuselist, followlink, checksumtype, formatspecs, verbose)
    if(outfile == "-" or outfile is None or hasattr(outfile, "read") or hasattr(outfile, "write")):
        fp = CompressOpenFileAlt(
            fp, compression, compressionlevel, compressionuselist, formatspecs)
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
    elif((not hasattr(outfile, "read") and not hasattr(outfile, "write")) and re.findall(__upload_proto_support__, outfile)):
        fp = CompressOpenFileAlt(
            fp, compression, compressionlevel, compressionuselist, formatspecs)
        fp.seek(0, 0)
        upload_file_to_internet_file(fp, outfile)
    if(returnfp):
        fp.seek(0, 0)
        return fp
    else:
        fp.close()
        return True


def AppendListsWithContentToOutFile(inlist, outfile, dirlistfromtxt=False, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, filevalues=[], extradata=[], jsondata={}, followlink=False, checksumtype=["crc32", "crc32", "crc32", "crc32"], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
    if(IsNestedDict(formatspecs) and fmttype=="auto" and 
        (outfile != "-" and outfile is not None and not hasattr(outfile, "read") and not hasattr(outfile, "write"))):
        get_in_ext = os.path.splitext(outfile)
        tmpfmt = GetKeyByFormatExtension(get_in_ext[1], formatspecs=__file_format_multi_dict__)
        if(tmpfmt is None and get_in_ext[1]!=""):
            get_in_ext = os.path.splitext(get_in_ext[0])
            tmpfmt = GetKeyByFormatExtension(get_in_ext[0], formatspecs=__file_format_multi_dict__)
        if(tmpfmt is None):
            fmttype = __file_format_default__
            formatspecs = formatspecs[fmttype]
        else:
            fmttype = tmpfmt
            formatspecs = formatspecs[tmpfmt]
    elif(IsNestedDict(formatspecs) and fmttype in formatspecs):
        formatspecs = formatspecs[fmttype]
    elif(IsNestedDict(formatspecs) and fmttype not in formatspecs):
        fmttype = __file_format_default__
        formatspecs = formatspecs[fmttype]
    if(outfile != "-" and outfile is not None and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
        if(os.path.exists(outfile)):
            try:
                os.unlink(outfile)
            except OSError:
                pass
    if(outfile == "-" or outfile is None):
        verbose = False
        fp = MkTempFile()
    elif(hasattr(outfile, "read") or hasattr(outfile, "write")):
        fp = outfile
    elif(re.findall(__upload_proto_support__, outfile)):
        fp = MkTempFile()
    else:
        fbasename = os.path.splitext(outfile)[0]
        fextname = os.path.splitext(outfile)[1]
        if(not compresswholefile and fextname in outextlistwd):
            compresswholefile = True
        try:
            fp = CompressOpenFile(outfile, compresswholefile, compressionlevel)
        except PermissionError:
            return False
    AppendListsWithContent(inlist, fp, dirlistfromtxt, filevalues, extradata, jsondata, compression,
                                   compresswholefile, compressionlevel, followlink, checksumtype, formatspecs, verbose)
    if(outfile == "-" or outfile is None or hasattr(outfile, "read") or hasattr(outfile, "write")):
        fp = CompressOpenFileAlt(
            fp, compression, compressionlevel, compressionuselist, formatspecs)
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
    elif((not hasattr(outfile, "read") and not hasattr(outfile, "write")) and re.findall(__upload_proto_support__, outfile)):
        fp = CompressOpenFileAlt(
            fp, compression, compressionlevel, compressionuselist, formatspecs)
        fp.seek(0, 0)
        upload_file_to_internet_file(fp, outfile)
    if(returnfp):
        fp.seek(0, 0)
        return fp
    else:
        fp.close()
        return True


def AppendInFileWithContentToOutFile(infile, outfile, dirlistfromtxt=False, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, filevalues=[], extradata=[], jsondata={}, followlink=False, checksumtype=["crc32", "crc32", "crc32", "crc32"], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
    inlist = ReadInFileWithContentToList(infile, "auto", 0, 0, False, False, True, False, formatspecs)
    return AppendListsWithContentToOutFile(inlist, outfile, dirlistfromtxt, fmttype, compression, compresswholefile, compressionlevel, filevalues, extradata, jsondata, followlink, checksumtype, formatspecs, verbose, returnfp)


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
        out = MkTempFile()
        with gzip.GzipFile(fileobj=out, mode="wb", compresslevel=compresslevel) as f:
            f.write(data)
        out.seek(0, 0)
        compressed_data = out.read()
    return compressed_data


def GzipDecompressData(compressed_data):
    try:
        # Try using modern gzip.decompress if available
        decompressed_data = gzip.decompress(compressed_data)
    except AttributeError:
        # Fallback to older method for Python 2.x and older 3.x versions
        inp = MkTempFile(compressed_data)
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


def GetKeyByFormatExtension(format_extension, formatspecs=__file_format_multi_dict__):
    for key, value in formatspecs.items():
        if value.get('format_extension') == format_extension:
            return key
    return None


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

def IsNestedDictAlt(variable):
    """
    Check if the input 'variable' (which is expected to be a list) contains
    any dictionary or list elements. Works in Python 2 and 3.

    :param variable: list to check
    :return: True if there's at least one dict or list in 'variable', otherwise False
    """
    for elem in variable:
        if isinstance(elem, (dict, list)):
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


def GetFileEncoding(infile, filestart=0, closefp=True):
    if(hasattr(infile, "read") or hasattr(infile, "write")):
        fp = infile
    else:
        try:
            fp = open(infile, "rb")
        except FileNotFoundError:
            return False
    file_encoding = "UTF-8"
    fp.seek(filestart, 0)
    prefp = fp.read(2)
    if(prefp == binascii.unhexlify("fffe")):
        file_encoding = "UTF-16LE"
    elif(prefp == binascii.unhexlify("feff")):
        file_encoding = "UTF-16BE"
    fp.seek(filestart, 0)
    prefp = fp.read(3)
    if(prefp == binascii.unhexlify("efbbbf")):
        file_encoding = "UTF-8"
    elif(prefp == binascii.unhexlify("0efeff")):
        file_encoding = "SCSU"
    fp.seek(filestart, 0)
    prefp = fp.read(4)
    if(prefp == binascii.unhexlify("fffe0000")):
        file_encoding = "UTF-32LE"
    elif(prefp == binascii.unhexlify("0000feff")):
        file_encoding = "UTF-32BE"
    elif(prefp == binascii.unhexlify("dd736673")):
        file_encoding = "UTF-EBCDIC"
    elif(prefp == binascii.unhexlify("2b2f7638")):
        file_encoding = "UTF-7"
    elif(prefp == binascii.unhexlify("2b2f7639")):
        file_encoding = "UTF-7"
    elif(prefp == binascii.unhexlify("2b2f762b")):
        file_encoding = "UTF-7"
    elif(prefp == binascii.unhexlify("2b2f762f")):
        file_encoding = "UTF-7"
    fp.seek(filestart, 0)
    if(closefp):
        fp.close()
    return file_encoding


def GetFileEncodingFromString(instring, filestart=0, closefp=True):
    try:
        instringsfile = MkTempFile(instring)
    except TypeError:
        instringsfile = MkTempFile(instring.encode("UTF-8"))
    return GetFileEncoding(instringsfile, filestart, closefp)


def CheckCompressionType(infile, formatspecs=__file_format_multi_dict__, filestart=0, closefp=True):
    if(hasattr(infile, "read") or hasattr(infile, "write")):
        fp = infile
    else:
        try:
            fp = open(infile, "rb")
        except FileNotFoundError:
            return False
    filetype = False
    curloc = filestart
    fp.seek(filestart, 0)
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
    elif(prefp == binascii.unhexlify("1f9d")):
        filetype = "zcompress"
    fp.seek(curloc, 0)
    prefp = fp.read(3)
    if(prefp == binascii.unhexlify("425a68")):
        filetype = "bzip2"
    elif(prefp == binascii.unhexlify("5d0000")):
        filetype = "lzma"
    fp.seek(curloc, 0)
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
    fp.seek(curloc, 0)
    prefp = fp.read(5)
    if(prefp == binascii.unhexlify("7573746172")):
        filetype = "tarfile"
    if(prefp == binascii.unhexlify("7573746172")):
        filetype = "tarfile"
    fp.seek(curloc, 0)
    prefp = fp.read(6)
    if(prefp == binascii.unhexlify("fd377a585a00")):
        filetype = "xz"
    elif(prefp == binascii.unhexlify("377abcaf271c")):
        filetype = "7zipfile"
    fp.seek(curloc, 0)
    prefp = fp.read(7)
    if(prefp == binascii.unhexlify("526172211a0700")):
        filetype = "rarfile"
    elif(prefp == binascii.unhexlify("2a2a4143452a2a")):
        filetype = "ace"
    fp.seek(curloc, 0)
    prefp = fp.read(7)
    if(prefp == binascii.unhexlify("894c5a4f0d0a1a")):
        filetype = "lzo"
    fp.seek(curloc, 0)
    prefp = fp.read(8)
    if(prefp == binascii.unhexlify("7573746172003030")):
        filetype = "tarfile"
    if(prefp == binascii.unhexlify("7573746172202000")):
        filetype = "tarfile"
    if(prefp == binascii.unhexlify("526172211a070100")):
        filetype = "rarfile"
    fp.seek(curloc, 0)
    if(IsNestedDict(formatspecs)):
        for key, value in formatspecs.items():
            prefp = fp.read(formatspecs[key]['format_len'])
            if(prefp == binascii.unhexlify(formatspecs[key]['format_hex'])):
                inheaderver = str(int(formatspecs[key]['format_ver'].replace(".", "")))
                formstring = fp.read(len(inheaderver)).decode("UTF-8")
                formdelszie = len(formatspecs[key]['format_delimiter'])
                formdel = fp.read(formdelszie).decode("UTF-8")
                if(formstring != inheaderver):
                    break
                if(formdel != formatspecs[key]['format_delimiter']):
                    break
                if(formstring == inheaderver and formdel == formatspecs[key]['format_delimiter']):
                    filetype = formatspecs[key]['format_magic']
                    continue
            fp.seek(curloc, 0)
    elif(IsSingleDict(formatspecs)):
        prefp = fp.read(formatspecs['format_len'])
        if(prefp == binascii.unhexlify(formatspecs['format_hex'])):
            inheaderver = str(int(formatspecs['format_ver'].replace(".", "")))
            formstring = fp.read(len(inheaderver)).decode("UTF-8")
            formdelszie = len(formatspecs['format_delimiter'])
            formdel = fp.read(formdelszie).decode("UTF-8")
            if(formstring != inheaderver):
                return False
            if(formdel != formatspecs['format_delimiter']):
                return False
            filetype = formatspecs['format_magic']
    else:
        pass
    fp.seek(curloc, 0)
    prefp = fp.read(9)
    if(prefp == binascii.unhexlify("894c5a4f000d0a1a0a")):
        filetype = "lzo"
    fp.seek(curloc, 0)
    prefp = fp.read(10)
    if(prefp == binascii.unhexlify("7061785f676c6f62616c")):
        filetype = "tarfile"
    fp.seek(curloc, 0)
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
    fp.seek(curloc, 0)
    if(closefp):
        fp.close()
    return filetype


def CheckCompressionSubType(infile, formatspecs=__file_format_multi_dict__, filestart=0, closefp=True):
    compresscheck = CheckCompressionType(infile, formatspecs, filestart, False)
    curloc = filestart
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
        fp = UncompressFileAlt(infile, formatspecs, filestart)
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
    fp.seek(filestart, 0)
    prefp = fp.read(5)
    if(prefp == binascii.unhexlify("7573746172")):
        filetype = "tarfile"
    fp.seek(curloc, 0)
    if(IsNestedDict(formatspecs)):
        for key, value in formatspecs.items():
            prefp = fp.read(formatspecs[key]['format_len'])
            if(prefp == binascii.unhexlify(formatspecs[key]['format_hex'])):
                inheaderver = str(int(formatspecs[key]['format_ver'].replace(".", "")))
                formstring = fp.read(len(inheaderver)).decode("UTF-8")
                formdelszie = len(formatspecs[key]['format_delimiter'])
                formdel = fp.read(formdelszie).decode("UTF-8")
                if(formstring != inheaderver):
                    break
                if(formdel != formatspecs[key]['format_delimiter']):
                    break
                if(formstring == inheaderver and formdel == formatspecs[key]['format_delimiter']):
                    filetype = formatspecs[key]['format_magic']
                    continue
            fp.seek(curloc, 0)
    elif(IsSingleDict(formatspecs)):
        prefp = fp.read(formatspecs['format_len'])
        if(prefp == binascii.unhexlify(formatspecs['format_hex'])):
            inheaderver = str(int(formatspecs['format_ver'].replace(".", "")))
            formstring = fp.read(len(inheaderver)).decode("UTF-8")
            formdelszie = len(formatspecs['format_delimiter'])
            formdel = fp.read(formdelszie).decode("UTF-8")
            if(formstring != inheaderver):
                return False
            if(formdel != formatspecs['format_delimiter']):
                return False
            filetype = formatspecs['format_magic']
    else:
        pass
    fp.seek(curloc, 0)
    prefp = fp.read(10)
    if(prefp == binascii.unhexlify("7061785f676c6f62616c")):
        filetype = "tarfile"
    fp.seek(curloc, 0)
    if(closefp):
        fp.close()
    return filetype


def CheckCompressionTypeFromString(instring, formatspecs=__file_format_multi_dict__, filestart=0, closefp=True):
    try:
        instringsfile = MkTempFile(instring)
    except TypeError:
        instringsfile = MkTempFile(instring.encode("UTF-8"))
    return CheckCompressionType(instringsfile, formatspecs, filestart, closefp)


def CheckCompressionTypeFromBytes(instring, formatspecs=__file_format_multi_dict__, filestart=0, closefp=True):
    try:
        instringsfile = MkTempFile(instring)
    except TypeError:
        instringsfile = MkTempFile(instring.decode("UTF-8"))
    return CheckCompressionType(instringsfile, formatspecs, filestart, closefp)


def UncompressFileAlt(fp, formatspecs=__file_format_multi_dict__, filestart=0):
    if(not hasattr(fp, "read")):
        return False
    compresscheck = CheckCompressionType(fp, formatspecs, filestart, False)
    if(IsNestedDict(formatspecs) and compresscheck in formatspecs):
        formatspecs = formatspecs[compresscheck]
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


def UncompressFile(infile, formatspecs=__file_format_multi_dict__, mode="rb", filestart=0):
    compresscheck = CheckCompressionType(infile, formatspecs, filestart, False)
    if(IsNestedDict(formatspecs) and compresscheck in formatspecs):
        formatspecs = formatspecs[compresscheck]
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


def UncompressString(infile, formatspecs=__file_format_multi_dict__, filestart=0):
    compresscheck = CheckCompressionTypeFromString(infile, formatspecs, filestart, False)
    if(IsNestedDict(formatspecs) and compresscheck in formatspecs):
        formatspecs = formatspecs[compresscheck]
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


def UncompressStringAlt(instring, formatspecs=__file_format_multi_dict__, filestart=0):
    filefp = StringIO()
    outstring = UncompressString(instring, formatspecs, filestart)
    filefp.write(outstring)
    filefp.seek(0, 0)
    return filefp

def UncompressStringAltFP(fp, formatspecs=__file_format_multi_dict__, filestart=0):
    if(not hasattr(fp, "read")):
        return False
    prechck = CheckCompressionType(fp, formatspecs, filestart, False)
    if(IsNestedDict(formatspecs) and prechck in formatspecs):
        formatspecs = formatspecs[prechck]
    fp.seek(filestart, 0)
    if(prechck!="zstd"):
        return UncompressFileAlt(fp, formatspecs, filestart)
    filefp = StringIO()
    fp.seek(filestart, 0)
    outstring = UncompressString(fp.read(), formatspecs, 0)
    filefp.write(outstring)
    filefp.seek(0, 0)
    return filefp


def UncompressBytes(infile, formatspecs=__file_format_multi_dict__, filestart=0):
    compresscheck = CheckCompressionTypeFromBytes(infile, formatspecs, filestart, False)
    if(IsNestedDict(formatspecs) and compresscheck in formatspecs):
        formatspecs = formatspecs[compresscheck]
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


def UncompressBytesAlt(inbytes, formatspecs=__file_format_multi_dict__, filestart=0):
    filefp = MkTempFile()
    outstring = UncompressBytes(inbytes, formatspecs, filestart)
    filefp.write(outstring)
    filefp.seek(0, 0)
    return filefp


def UncompressBytesAltFP(fp, formatspecs=__file_format_multi_dict__, filestart=0):
    if(not hasattr(fp, "read")):
        return False
    prechck = CheckCompressionType(fp, formatspecs, filestart, False)
    if(IsNestedDict(formatspecs) and prechck in formatspecs):
        formatspecs = formatspecs[prechck]
    fp.seek(filestart, 0)
    if(prechck!="zstd"):
        return UncompressFileAlt(fp, formatspecs, filestart)
    filefp = MkTempFile()
    fp.seek(filestart, 0)
    outstring = UncompressBytes(fp.read(), formatspecs, 0)
    filefp.write(outstring)
    filefp.seek(0, 0)
    return filefp


def CompressOpenFileAlt(fp, compression="auto", compressionlevel=None, compressionuselist=compressionlistalt, formatspecs=__file_format_dict__):
    if(not hasattr(fp, "read")):
        return False
    fp.seek(0, 0)
    if(not compression or compression == formatspecs['format_magic']):
        compression = "auto"
    if(compression not in compressionuselist and compression is None):
        compression = "auto"
    if(compression == "gzip" and compression in compressionsupport):
        bytesfp = MkTempFile()
        if(compressionlevel is None):
            compressionlevel = 9
        else:
            compressionlevel = int(compressionlevel)
        bytesfp.write(GzipCompressData(
            fp.read(), compresslevel=compressionlevel))
    elif(compression == "bzip2" and compression in compressionsupport):
        bytesfp = MkTempFile()
        if(compressionlevel is None):
            compressionlevel = 9
        else:
            compressionlevel = int(compressionlevel)
        bytesfp.write(BzipCompressData(
            fp.read(), compresslevel=compressionlevel))
    elif(compression == "lz4" and compression in compressionsupport):
        bytesfp = MkTempFile()
        if(compressionlevel is None):
            compressionlevel = 9
        else:
            compressionlevel = int(compressionlevel)
        bytesfp.write(lz4.frame.compress(
            fp.read(), compression_level=compressionlevel))
    elif((compression == "lzo" or compression == "lzop") and compression in compressionsupport):
        bytesfp = MkTempFile()
        if(compressionlevel is None):
            compressionlevel = 9
        else:
            compressionlevel = int(compressionlevel)
        bytesfp.write(lzo.compress(fp.read(), compressionlevel))
    elif(compression == "zstd" and compression in compressionsupport):
        bytesfp = MkTempFile()
        if(compressionlevel is None):
            compressionlevel = 9
        else:
            compressionlevel = int(compressionlevel)
        compressor = zstandard.ZstdCompressor(compressionlevel, threads=get_default_threads())
        bytesfp.write(compressor.compress(fp.read()))
    elif(compression == "lzma" and compression in compressionsupport):
        bytesfp = MkTempFile()
        if(compressionlevel is None):
            compressionlevel = 9
        else:
            compressionlevel = int(compressionlevel)
        try:
            bytesfp.write(lzma.compress(fp.read(), format=lzma.FORMAT_ALONE, filters=[{"id": lzma.FILTER_LZMA1, "preset": compressionlevel}]))
        except (NotImplementedError, lzma.LZMAError):
            bytesfp.write(lzma.compress(fp.read(), format=lzma.FORMAT_ALONE))
    elif(compression == "xz" and compression in compressionsupport):
        bytesfp = MkTempFile()
        if(compressionlevel is None):
            compressionlevel = 9
        else:
            compressionlevel = int(compressionlevel)
        try:
            bytesfp.write(lzma.compress(fp.read(), format=lzma.FORMAT_XZ, filters=[{"id": lzma.FILTER_LZMA2, "preset": compressionlevel}]))
        except (NotImplementedError, lzma.LZMAError):
            bytesfp.write(lzma.compress(fp.read(), format=lzma.FORMAT_XZ))
    elif(compression == "zlib" and compression in compressionsupport):
        bytesfp = MkTempFile()
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


def PackCatFile(infiles, outfile, dirlistfromtxt=False, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, followlink=False, checksumtype=["crc32", "crc32", "crc32", "crc32"], extradata=[], jsondata={}, formatspecs=__file_format_multi_dict__, verbose=False, returnfp=False):
    if(IsNestedDict(formatspecs) and fmttype=="auto" and 
        (outfile != "-" and outfile is not None and not hasattr(outfile, "read") and not hasattr(outfile, "write"))):
        get_in_ext = os.path.splitext(outfile)
        tmpfmt = GetKeyByFormatExtension(get_in_ext[1], formatspecs=__file_format_multi_dict__)
        if(tmpfmt is None and get_in_ext[1]!=""):
            get_in_ext = os.path.splitext(get_in_ext[0])
            tmpfmt = GetKeyByFormatExtension(get_in_ext[0], formatspecs=__file_format_multi_dict__)
        if(tmpfmt is None):
            fmttype = __file_format_default__
            formatspecs = formatspecs[fmttype]
        else:
            fmttype = tmpfmt
            formatspecs = formatspecs[tmpfmt]
    elif(IsNestedDict(formatspecs) and fmttype in formatspecs):
        formatspecs = formatspecs[fmttype]
    elif(IsNestedDict(formatspecs) and fmttype not in formatspecs):
        fmttype = __file_format_default__
        formatspecs = formatspecs[fmttype]
    advancedlist = formatspecs['use_advanced_list']
    altinode = formatspecs['use_alt_inode']
    if(outfile != "-" and outfile is not None and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
        outfile = RemoveWindowsPath(outfile)
    if(not compression or compression == formatspecs['format_magic']):
        compression = "auto"
    if(compression not in compressionuselist and compression is None):
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
        fp = MkTempFile()
    elif(hasattr(outfile, "read") or hasattr(outfile, "write")):
        fp = outfile
    elif(re.findall(__upload_proto_support__, outfile)):
        fp = MkTempFile()
    else:
        fbasename = os.path.splitext(outfile)[0]
        fextname = os.path.splitext(outfile)[1]
        if(not compresswholefile and fextname in outextlistwd):
            compresswholefile = True
        try:
            fp = CompressOpenFile(outfile, compresswholefile, compressionlevel)
        except PermissionError:
            return False
    formver = formatspecs['format_ver']
    fileheaderver = str(int(formver.replace(".", "")))
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
    inodetoforminode = {}
    numfiles = int(len(GetDirList))
    AppendFileHeader(fp, numfiles, "UTF-8", [], checksumtype[0], formatspecs)
    FullSizeFilesAlt = 0
    for curfname in GetDirList:
        fencoding = "UTF-8"
        if(re.findall("^[.|/]", curfname)):
            fname = curfname
        else:
            fname = "./"+curfname
        if(not os.path.exists(fname)):
            return False
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
                        fcurinode = format(int(inodetoforminode[unique_id]), 'x').lower()
                else:
                    # New inode
                    inodelist.append(unique_id)
                    inodetofile[unique_id] = fname
                    inodetoforminode[unique_id] = curinode
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
            if(not os.path.exists(flinkname)):
                return False
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
            fsize = format(int(fstatinfo.st_size), 'x').lower()
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
        fcontents = MkTempFile()
        fcencoding = "UTF-8"
        curcompression = "none"
        if not followlink and ftype in data_types:
            with open(fname, "rb") as fpc:
                shutil.copyfileobj(fpc, fcontents)
                typechecktest = CheckCompressionType(fcontents, filestart=0, closefp=False)
                fcontents.seek(0, 0)
                fcencoding = GetFileEncoding(fcontents, 0, False)
                if(typechecktest is False and not compresswholefile):
                    fcontents.seek(0, 2)
                    ucfsize = fcontents.tell()
                    fcontents.seek(0, 0)
                    if(compression == "auto"):
                        ilsize = len(compressionuselist)
                        ilmin = 0
                        ilcsize = []
                        while(ilmin < ilsize):
                            cfcontents = MkTempFile()
                            fcontents.seek(0, 0)
                            shutil.copyfileobj(fcontents, cfcontents)
                            fcontents.seek(0, 0)
                            cfcontents.seek(0, 0)
                            cfcontents = CompressOpenFileAlt(
                                cfcontents, compressionuselist[ilmin], compressionlevel, compressionuselist, formatspecs)
                            if(cfcontents):
                                cfcontents.seek(0, 2)
                                ilcsize.append(cfcontents.tell())
                                cfcontents.close()
                            else:
                                ilcsize.append(float("inf"))
                            ilmin = ilmin + 1
                        ilcmin = ilcsize.index(min(ilcsize))
                        curcompression = compressionuselist[ilcmin]
                    fcontents.seek(0, 0)
                    cfcontents = MkTempFile()
                    shutil.copyfileobj(fcontents, cfcontents)
                    cfcontents.seek(0, 0)
                    cfcontents = CompressOpenFileAlt(
                        cfcontents, curcompression, compressionlevel, compressionuselist, formatspecs)
                    cfcontents.seek(0, 2)
                    cfsize = cfcontents.tell()
                    if(ucfsize > cfsize):
                        fcsize = format(int(cfsize), 'x').lower()
                        fcompression = curcompression
                        fcontents.close()
                        fcontents = cfcontents
        elif followlink and (ftype == 1 or ftype == 2):
            if(not os.path.exists(flinkname)):
                return False
            flstatinfo = os.stat(flinkname)
            with open(flinkname, "rb") as fpc:
                shutil.copyfileobj(fpc, fcontents)
                typechecktest = CheckCompressionType(fcontents, filestart=0, closefp=False)
                fcontents.seek(0, 0)
                fcencoding = GetFileEncoding(fcontents, 0, False)
                if(typechecktest is False and not compresswholefile):
                    fcontents.seek(0, 2)
                    ucfsize = fcontents.tell()
                    fcontents.seek(0, 0)
                    if(compression == "auto"):
                        ilsize = len(compressionuselist)
                        ilmin = 0
                        ilcsize = []
                        while(ilmin < ilsize):
                            cfcontents = MkTempFile()
                            fcontents.seek(0, 0)
                            shutil.copyfileobj(fcontents, cfcontents)
                            fcontents.seek(0, 0)
                            cfcontents.seek(0, 0)
                            cfcontents = CompressOpenFileAlt(
                                cfcontents, compressionuselist[ilmin], compressionlevel, compressionuselist, formatspecs)
                            if(cfcontents):
                                cfcontents.seek(0, 2)
                                ilcsize.append(cfcontents.tell())
                                cfcontents.close()
                            else:
                                ilcsize.append(float("inf"))
                            ilmin = ilmin + 1
                        ilcmin = ilcsize.index(min(ilcsize))
                        curcompression = compressionuselist[ilcmin]
                    fcontents.seek(0, 0)
                    cfcontents = MkTempFile()
                    shutil.copyfileobj(fcontents, cfcontents)
                    cfcontents.seek(0, 0)
                    cfcontents = CompressOpenFileAlt(
                        cfcontents, curcompression, compressionlevel, compressionuselist, formatspecs)
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
        tmpoutlist = [ftypehex, fencoding, fcencoding, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression,
                      fcsize, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev, fdev_minor, fdev_major, "+"+str(len(formatspecs['format_delimiter']))]
        AppendFileHeaderWithContent(
            fp, tmpoutlist, extradata, jsondata, fcontents.read(), [checksumtype[1], checksumtype[2], checksumtype[3]], formatspecs)
        fcontents.close()
    if(outfile == "-" or outfile is None or hasattr(outfile, "read") or hasattr(outfile, "write")):
        fp = CompressOpenFileAlt(
            fp, compression, compressionlevel, compressionuselist, formatspecs)
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
    elif((not hasattr(outfile, "read") and not hasattr(outfile, "write")) and re.findall(__upload_proto_support__, outfile)):
        fp = CompressOpenFileAlt(
            fp, compression, compressionlevel, compressionuselist, formatspecs)
        fp.seek(0, 0)
        upload_file_to_internet_file(fp, outfile)
    if(returnfp):
        fp.seek(0, 0)
        return fp
    else:
        fp.close()
        return True


def PackCatFileFromDirList(infiles, outfile, dirlistfromtxt=False, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, followlink=False, checksumtype=["crc32", "crc32", "crc32"], extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
    return PackCatFile(infiles, outfile, dirlistfromtxt, fmttype, compression, compresswholefile, compressionlevel, compressionuselist, followlink, checksumtype, extradata, formatspecs, verbose, returnfp)


def PackCatFileFromTarFile(infile, outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["crc32", "crc32", "crc32", "crc32"], extradata=[], jsondata={}, formatspecs=__file_format_dict__, verbose=False, returnfp=False):
    if(IsNestedDict(formatspecs) and fmttype=="auto" and 
        (outfile != "-" and outfile is not None and not hasattr(outfile, "read") and not hasattr(outfile, "write"))):
        get_in_ext = os.path.splitext(outfile)
        tmpfmt = GetKeyByFormatExtension(get_in_ext[1], formatspecs=__file_format_multi_dict__)
        if(tmpfmt is None and get_in_ext[1]!=""):
            get_in_ext = os.path.splitext(get_in_ext[0])
            tmpfmt = GetKeyByFormatExtension(get_in_ext[0], formatspecs=__file_format_multi_dict__)
        if(tmpfmt is None):
            fmttype = __file_format_default__
            formatspecs = formatspecs[fmttype]
        else:
            fmttype = tmpfmt
            formatspecs = formatspecs[tmpfmt]
    elif(IsNestedDict(formatspecs) and fmttype in formatspecs):
        formatspecs = formatspecs[fmttype]
    elif(IsNestedDict(formatspecs) and fmttype not in formatspecs):
        fmttype = __file_format_default__
        formatspecs = formatspecs[fmttype]
    if(outfile != "-" and outfile is not None and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
        outfile = RemoveWindowsPath(outfile)
    if(not compression or compression == formatspecs['format_magic']):
        compression = "auto"
    if(compression not in compressionuselist and compression is None):
        compression = "auto"
    if(verbose):
        logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG)
    if(outfile != "-" and outfile is not None and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
        if(os.path.exists(outfile)):
            try:
                os.unlink(outfile)
            except OSError:
                pass
    if(outfile == "-" or outfile is None):
        verbose = False
        fp = MkTempFile()
    elif(hasattr(outfile, "read") or hasattr(outfile, "write")):
        fp = outfile
    elif(re.findall(__upload_proto_support__, outfile)):
        fp = MkTempFile()
    else:
        fbasename = os.path.splitext(outfile)[0]
        fextname = os.path.splitext(outfile)[1]
        if(not compresswholefile and fextname in outextlistwd):
            compresswholefile = True
        try:
            fp = CompressOpenFile(outfile, compresswholefile, compressionlevel)
        except PermissionError:
            return False
    formver = formatspecs['format_ver']
    fileheaderver = str(int(formver.replace(".", "")))
    curinode = 0
    curfid = 0
    inodelist = []
    inodetofile = {}
    filetoinode = {}
    inodetoforminode = {}
    if(infile == "-"):
        infile = MkTempFile()
        if(hasattr(sys.stdin, "buffer")):
            shutil.copyfileobj(sys.stdin.buffer, infile)
        else:
            shutil.copyfileobj(sys.stdin, infile)
        infile.seek(0, 0)
        if(not infile):
            return False
        infile.seek(0, 0)
    elif(re.findall(__download_proto_support__, infile)):
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
            compresscheck = CheckCompressionType(infile, formatspecs, 0, False)
            if(IsNestedDict(formatspecs) and compresscheck in formatspecs):
                formatspecs = formatspecs[compresscheck]
            if(compresscheck=="zstd"):
                if 'zstandard' in sys.modules:
                    infile = ZstdFile(fileobj=infile, mode="rb")
                elif 'pyzstd' in sys.modules:
                    infile = pyzstd.zstdfile.ZstdFile(fileobj=infile, mode="rb")
                tarfp = tarfile.open(fileobj=infile, mode="r")
            else:
                tarfp = tarfile.open(fileobj=infile, mode="r")
        else:
            compresscheck = CheckCompressionType(infile, formatspecs, 0, True)
            if(IsNestedDict(formatspecs) and compresscheck in formatspecs):
                formatspecs = formatspecs[compresscheck]
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
        fcontents = MkTempFile()
        fcencoding = "UTF-8"
        curcompression = "none"
        if ftype in data_types:
            fpc = tarfp.extractfile(member)
            shutil.copyfileobj(fpc, fcontents)
            fpc.close()
            typechecktest = CheckCompressionType(fcontents, filestart=0, closefp=False)
            fcontents.seek(0, 0)
            fcencoding = GetFileEncoding(fcontents, 0, False)
            if(typechecktest is False and not compresswholefile):
                fcontents.seek(0, 2)
                ucfsize = fcontents.tell()
                fcontents.seek(0, 0)
                if(compression == "auto"):
                    ilsize = len(compressionuselist)
                    ilmin = 0
                    ilcsize = []
                    while(ilmin < ilsize):
                        cfcontents = MkTempFile()
                        fcontents.seek(0, 0)
                        shutil.copyfileobj(fcontents, cfcontents)
                        fcontents.seek(0, 0)
                        cfcontents.seek(0, 0)
                        cfcontents = CompressOpenFileAlt(
                            cfcontents, compressionuselist[ilmin], compressionlevel, compressionuselist, formatspecs)
                        if(cfcontents):
                            cfcontents.seek(0, 2)
                            ilcsize.append(cfcontents.tell())
                            cfcontents.close()
                        else:
                            ilcsize.append(float("inf"))
                        ilmin = ilmin + 1
                    ilcmin = ilcsize.index(min(ilcsize))
                    curcompression = compressionuselist[ilcmin]
                fcontents.seek(0, 0)
                cfcontents = MkTempFile()
                shutil.copyfileobj(fcontents, cfcontents)
                cfcontents.seek(0, 0)
                cfcontents = CompressOpenFileAlt(
                    cfcontents, curcompression, compressionlevel, compressionuselist, formatspecs)
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
        tmpoutlist = [ftypehex, fencoding, fcencoding, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression,
                      fcsize, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev, fdev_minor, fdev_major, "+"+str(len(formatspecs['format_delimiter']))]
        AppendFileHeaderWithContent(
            fp, tmpoutlist, extradata, jsondata, fcontents.read(), [checksumtype[1], checksumtype[2], checksumtype[3]], formatspecs)
        fcontents.close()
    if(outfile == "-" or outfile is None or hasattr(outfile, "read") or hasattr(outfile, "write")):
        fp = CompressOpenFileAlt(
            fp, compression, compressionlevel, compressionuselist, formatspecs)
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
    elif((not hasattr(outfile, "read") and not hasattr(outfile, "write")) and re.findall(__upload_proto_support__, outfile)):
        fp = CompressOpenFileAlt(
            fp, compression, compressionlevel, compressionuselist, formatspecs)
        fp.seek(0, 0)
        upload_file_to_internet_file(fp, outfile)
    if(returnfp):
        fp.seek(0, 0)
        return fp
    else:
        fp.close()
        return True


def PackCatFileFromZipFile(infile, outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["crc32", "crc32", "crc32", "crc32"], extradata=[], jsondata={}, formatspecs=__file_format_dict__, verbose=False, returnfp=False):
    if(IsNestedDict(formatspecs) and fmttype=="auto" and 
        (outfile != "-" and outfile is not None and not hasattr(outfile, "read") and not hasattr(outfile, "write"))):
        get_in_ext = os.path.splitext(outfile)
        tmpfmt = GetKeyByFormatExtension(get_in_ext[1], formatspecs=__file_format_multi_dict__)
        if(tmpfmt is None and get_in_ext[1]!=""):
            get_in_ext = os.path.splitext(get_in_ext[0])
            tmpfmt = GetKeyByFormatExtension(get_in_ext[0], formatspecs=__file_format_multi_dict__)
        if(tmpfmt is None):
            fmttype = __file_format_default__
            formatspecs = formatspecs[fmttype]
        else:
            fmttype = tmpfmt
            formatspecs = formatspecs[tmpfmt]
    elif(IsNestedDict(formatspecs) and fmttype in formatspecs):
        formatspecs = formatspecs[fmttype]
    elif(IsNestedDict(formatspecs) and fmttype not in formatspecs):
        fmttype = __file_format_default__
        formatspecs = formatspecs[fmttype]
    if(outfile != "-" and outfile is not None and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
        outfile = RemoveWindowsPath(outfile)
    if(not compression or compression == formatspecs['format_magic']):
        compression = "auto"
    if(compression not in compressionuselist and compression is None):
        compression = "auto"
    if(verbose):
        logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG)
    if(outfile != "-" and outfile is not None and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
        if(os.path.exists(outfile)):
            try:
                os.unlink(outfile)
            except OSError:
                pass
    if(outfile == "-" or outfile is None):
        verbose = False
        fp = MkTempFile()
    elif(hasattr(outfile, "read") or hasattr(outfile, "write")):
        fp = outfile
    elif(re.findall(__upload_proto_support__, outfile)):
        fp = MkTempFile()
    else:
        fbasename = os.path.splitext(outfile)[0]
        fextname = os.path.splitext(outfile)[1]
        if(not compresswholefile and fextname in outextlistwd):
            compresswholefile = True
        try:
            fp = CompressOpenFile(outfile, compresswholefile, compressionlevel)
        except PermissionError:
            return False
    formver = formatspecs['format_ver']
    fileheaderver = str(int(formver.replace(".", "")))
    curinode = 0
    curfid = 0
    inodelist = []
    inodetofile = {}
    filetoinode = {}
    inodetoforminode = {}
    if(infile == "-"):
        infile = MkTempFile()
        if(hasattr(sys.stdin, "buffer")):
            shutil.copyfileobj(sys.stdin.buffer, infile)
        else:
            shutil.copyfileobj(sys.stdin, infile)
        infile.seek(0, 0)
        if(not infile):
            return False
        infile.seek(0, 0)
    elif(re.findall(__download_proto_support__, infile)):
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
        fcontents = MkTempFile()
        fcencoding = "UTF-8"
        curcompression = "none"
        if ftype == 0:
            fcontents.write(zipfp.read(member.filename))
            typechecktest = CheckCompressionType(fcontents, filestart=0, closefp=False)
            fcontents.seek(0, 0)
            fcencoding = GetFileEncoding(fcontents, 0, False)
            if(typechecktest is False and not compresswholefile):
                fcontents.seek(0, 2)
                ucfsize = fcontents.tell()
                fcontents.seek(0, 0)
                if(compression == "auto"):
                    ilsize = len(compressionuselist)
                    ilmin = 0
                    ilcsize = []
                    while(ilmin < ilsize):
                        cfcontents = MkTempFile()
                        fcontents.seek(0, 0)
                        shutil.copyfileobj(fcontents, cfcontents)
                        fcontents.seek(0, 0)
                        cfcontents.seek(0, 0)
                        cfcontents = CompressOpenFileAlt(
                            cfcontents, compressionuselist[ilmin], compressionlevel, compressionuselist, formatspecs)
                        cfcontents.seek(0, 2)
                        ilcsize.append(cfcontents.tell())
                        cfcontents.close()
                        ilmin = ilmin + 1
                    ilcmin = ilcsize.index(min(ilcsize))
                    curcompression = compressionuselist[ilcmin]
                fcontents.seek(0, 0)
                cfcontents = MkTempFile()
                shutil.copyfileobj(fcontents, cfcontents)
                cfcontents.seek(0, 0)
                cfcontents = CompressOpenFileAlt(
                    cfcontents, curcompression, compressionlevel, compressionuselist, formatspecs)
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
        tmpoutlist = [ftypehex, fencoding, fcencoding, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression,
                      fcsize, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev, fdev_minor, fdev_major, "+"+str(len(formatspecs['format_delimiter']))]
        AppendFileHeaderWithContent(
            fp, tmpoutlist, extradata, jsondata, fcontents.read(), [checksumtype[1], checksumtype[2], checksumtype[3]], formatspecs)
        fcontents.close()
    if(outfile == "-" or outfile is None or hasattr(outfile, "read") or hasattr(outfile, "write")):
        fp = CompressOpenFileAlt(
            fp, compression, compressionlevel, compressionuselist, formatspecs)
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
    elif((not hasattr(outfile, "read") and not hasattr(outfile, "write")) and re.findall(__upload_proto_support__, outfile)):
        fp = CompressOpenFileAlt(
            fp, compression, compressionlevel, compressionuselist, formatspecs)
        fp.seek(0, 0)
        upload_file_to_internet_file(fp, outfile)
    if(returnfp):
        fp.seek(0, 0)
        return fp
    else:
        fp.close()
        return True


if(not rarfile_support):
    def PackCatFileFromRarFile(infile, outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["crc32", "crc32", "crc32"], extradata=[], jsondata={}, formatspecs=__file_format_dict__, verbose=False, returnfp=False):
        return False

if(rarfile_support):
    def PackCatFileFromRarFile(infile, outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["crc32", "crc32", "crc32", "crc32"], extradata=[], jsondata={}, formatspecs=__file_format_dict__, verbose=False, returnfp=False):
        if(IsNestedDict(formatspecs) and fmttype=="auto" and 
            (outfile != "-" and outfile is not None and not hasattr(outfile, "read") and not hasattr(outfile, "write"))):
            get_in_ext = os.path.splitext(outfile)
            tmpfmt = GetKeyByFormatExtension(get_in_ext[1], formatspecs=__file_format_multi_dict__)
            if(tmpfmt is None and get_in_ext[1]!=""):
                get_in_ext = os.path.splitext(get_in_ext[0])
                tmpfmt = GetKeyByFormatExtension(get_in_ext[0], formatspecs=__file_format_multi_dict__)
            if(tmpfmt is None):
                fmttype = __file_format_default__
                formatspecs = formatspecs[fmttype]
            else:
                fmttype = tmpfmt
                formatspecs = formatspecs[tmpfmt]
        elif(IsNestedDict(formatspecs) and fmttype in formatspecs):
            formatspecs = formatspecs[fmttype]
        elif(IsNestedDict(formatspecs) and fmttype not in formatspecs):
            fmttype = __file_format_default__
            formatspecs = formatspecs[fmttype]
        if(outfile != "-" and outfile is not None and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
            outfile = RemoveWindowsPath(outfile)
        if(not compression or compression == formatspecs['format_magic']):
            compression = "auto"
        if(compression not in compressionuselist and compression is None):
            compression = "auto"
        if(verbose):
            logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG)
        if(outfile != "-" and outfile is not None and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
            if(os.path.exists(outfile)):
                try:
                    os.unlink(outfile)
                except OSError:
                    pass
        if(outfile == "-" or outfile is None):
            verbose = False
            fp = MkTempFile()
        elif(hasattr(outfile, "read") or hasattr(outfile, "write")):
            fp = outfile
        elif(re.findall(__upload_proto_support__, outfile)):
            fp = MkTempFile()
        else:
            fbasename = os.path.splitext(outfile)[0]
            fextname = os.path.splitext(outfile)[1]
            if(not compresswholefile and fextname in outextlistwd):
                compresswholefile = True
            try:
                fp = CompressOpenFile(outfile, compresswholefile, compressionlevel)
            except PermissionError:
                return False
        formver = formatspecs['format_ver']
        fileheaderver = str(int(formver.replace(".", "")))
        curinode = 0
        curfid = 0
        inodelist = []
        inodetofile = {}
        filetoinode = {}
        inodetoforminode = {}
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
            fcontents = MkTempFile()
            fcencoding = "UTF-8"
            curcompression = "none"
            if ftype == 0:
                fcontents.write(rarfp.read(member.filename))
                typechecktest = CheckCompressionType(fcontents, filestart=0, closefp=False)
                fcontents.seek(0, 0)
                fcencoding = GetFileEncoding(fcontents, 0, False)
                if(typechecktest is False and not compresswholefile):
                    fcontents.seek(0, 2)
                    ucfsize = fcontents.tell()
                    fcontents.seek(0, 0)
                    if(compression == "auto"):
                        ilsize = len(compressionuselist)
                        ilmin = 0
                        ilcsize = []
                        while(ilmin < ilsize):
                            cfcontents = MkTempFile()
                            fcontents.seek(0, 0)
                            shutil.copyfileobj(fcontents, cfcontents)
                            fcontents.seek(0, 0)
                            cfcontents.seek(0, 0)
                            cfcontents = CompressOpenFileAlt(
                                cfcontents, compressionuselist[ilmin], compressionlevel, compressionuselist, formatspecs)
                            if(cfcontents):
                                cfcontents.seek(0, 2)
                                ilcsize.append(cfcontents.tell())
                                cfcontents.close()
                            else:
                                ilcsize.append(float("inf"))
                            ilmin = ilmin + 1
                        ilcmin = ilcsize.index(min(ilcsize))
                        curcompression = compressionuselist[ilcmin]
                    fcontents.seek(0, 0)
                    cfcontents = MkTempFile()
                    shutil.copyfileobj(fcontents, cfcontents)
                    cfcontents.seek(0, 0)
                    cfcontents = CompressOpenFileAlt(
                        cfcontents, curcompression, compressionlevel, compressionuselist, formatspecs)
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
            tmpoutlist = [ftypehex, fencoding, fcencoding, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression,
                          fcsize, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev, fdev_minor, fdev_major, "+"+str(len(formatspecs['format_delimiter']))]
            AppendFileHeaderWithContent(
                fp, tmpoutlist, extradata, jsondata, fcontents.read(), [checksumtype[1], checksumtype[2], checksumtype[3]], formatspecs)
            fcontents.close()
        if(outfile == "-" or outfile is None or hasattr(outfile, "read") or hasattr(outfile, "write")):
            fp = CompressOpenFileAlt(
                fp, compression, compressionlevel, compressionuselist, formatspecs)
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
        elif((not hasattr(outfile, "read") and not hasattr(outfile, "write")) and re.findall(__upload_proto_support__, outfile)):
            fp = CompressOpenFileAlt(
                fp, compression, compressionlevel, compressionuselist, formatspecs)
            fp.seek(0, 0)
            upload_file_to_internet_file(fp, outfile)
        if(returnfp):
            fp.seek(0, 0)
            return fp
        else:
            fp.close()
            return True


if(not py7zr_support):
    def PackCatFileFromSevenZipFile(infile, outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["crc32", "crc32", "crc32"], extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
        return False

if(py7zr_support):
    def PackCatFileFromSevenZipFile(infile, outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["crc32", "crc32", "crc32", "crc32"], extradata=[], jsondata={}, formatspecs=__file_format_dict__, verbose=False, returnfp=False):
        if(IsNestedDict(formatspecs) and fmttype=="auto" and 
            (outfile != "-" and outfile is not None and not hasattr(outfile, "read") and not hasattr(outfile, "write"))):
            get_in_ext = os.path.splitext(outfile)
            tmpfmt = GetKeyByFormatExtension(get_in_ext[1], formatspecs=__file_format_multi_dict__)
            if(tmpfmt is None and get_in_ext[1]!=""):
                get_in_ext = os.path.splitext(get_in_ext[0])
                tmpfmt = GetKeyByFormatExtension(get_in_ext[0], formatspecs=__file_format_multi_dict__)
            if(tmpfmt is None):
                fmttype = __file_format_default__
                formatspecs = formatspecs[fmttype]
            else:
                fmttype = tmpfmt
                formatspecs = formatspecs[tmpfmt]
        elif(IsNestedDict(formatspecs) and fmttype in formatspecs):
            formatspecs = formatspecs[fmttype]
        elif(IsNestedDict(formatspecs) and fmttype not in formatspecs):
            fmttype = __file_format_default__
            formatspecs = formatspecs[fmttype]
        if(outfile != "-" and outfile is not None and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
            outfile = RemoveWindowsPath(outfile)
        if(not compression or compression == formatspecs['format_magic']):
            compression = "auto"
        if(compression not in compressionuselist and compression is None):
            compression = "auto"
        if(verbose):
            logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG)
        if(outfile != "-" and outfile is not None and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
            if(os.path.exists(outfile)):
                try:
                    os.unlink(outfile)
                except OSError:
                    pass
        if(outfile == "-" or outfile is None):
            verbose = False
            fp = MkTempFile()
        elif(hasattr(outfile, "read") or hasattr(outfile, "write")):
            fp = outfile
        elif(re.findall(__upload_proto_support__, outfile)):
            fp = MkTempFile()
        else:
            fbasename = os.path.splitext(outfile)[0]
            fextname = os.path.splitext(outfile)[1]
            if(not compresswholefile and fextname in outextlistwd):
                compresswholefile = True
            try:
                fp = CompressOpenFile(outfile, compresswholefile, compressionlevel)
            except PermissionError:
                return False
        formver = formatspecs['format_ver']
        fileheaderver = str(int(formver.replace(".", "")))
        curinode = 0
        curfid = 0
        inodelist = []
        inodetofile = {}
        filetoinode = {}
        inodetoforminode = {}
        if(not os.path.exists(infile) or not os.path.isfile(infile)):
            return False
        szpfp = py7zr.SevenZipFile(infile, mode="r")
        file_content = szpfp.readall()
        #sztest = szpfp.testzip()
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
            fcontents = MkTempFile()
            fcencoding = "UTF-8"
            curcompression = "none"
            if ftype == 0:
                fcontents.write(file_content[member.filename].read())
                fsize = format(fcontents.tell(), 'x').lower()
                fcontents.seek(0, 0)
                typechecktest = CheckCompressionType(fcontents, filestart=0, closefp=False)
                fcontents.seek(0, 0)
                fcencoding = GetFileEncoding(fcontents, 0, False)
                file_content[member.filename].close()
                if(typechecktest is False and not compresswholefile):
                    fcontents.seek(0, 2)
                    ucfsize = fcontents.tell()
                    fcontents.seek(0, 0)
                    if(compression == "auto"):
                        ilsize = len(compressionuselist)
                        ilmin = 0
                        ilcsize = []
                        while(ilmin < ilsize):
                            cfcontents = MkTempFile()
                            fcontents.seek(0, 0)
                            shutil.copyfileobj(fcontents, cfcontents)
                            fcontents.seek(0, 0)
                            cfcontents.seek(0, 0)
                            cfcontents = CompressOpenFileAlt(
                                cfcontents, compressionuselist[ilmin], compressionlevel, compressionuselist, formatspecs)
                            if(cfcontents):
                                cfcontents.seek(0, 2)
                                ilcsize.append(cfcontents.tell())
                                cfcontents.close()
                            else:
                                ilcsize.append(float("inf"))
                            ilmin = ilmin + 1
                        ilcmin = ilcsize.index(min(ilcsize))
                        curcompression = compressionuselist[ilcmin]
                    fcontents.seek(0, 0)
                    cfcontents = MkTempFile()
                    shutil.copyfileobj(fcontents, cfcontents)
                    cfcontents.seek(0, 0)
                    cfcontents = CompressOpenFileAlt(
                        cfcontents, curcompression, compressionlevel, compressionuselist, formatspecs)
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
            tmpoutlist = [ftypehex, fencoding, fcencoding, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression,
                          fcsize, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev, fdev_minor, fdev_major, "+"+str(len(formatspecs['format_delimiter']))]
            AppendFileHeaderWithContent(
                fp, tmpoutlist, extradata, jsondata, fcontents.read(), [checksumtype[1], checksumtype[2], checksumtype[3]], formatspecs)
            fcontents.close()
        if(outfile == "-" or outfile is None or hasattr(outfile, "read") or hasattr(outfile, "write")):
            fp = CompressOpenFileAlt(
                fp, compression, compressionlevel, compressionuselist, formatspecs)
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
        elif((not hasattr(outfile, "read") and not hasattr(outfile, "write")) and re.findall(__upload_proto_support__, outfile)):
            fp = CompressOpenFileAlt(
                fp, compression, compressionlevel, compressionuselist, formatspecs)
            fp.seek(0, 0)
            upload_file_to_internet_file(fp, outfile)
        if(returnfp):
            fp.seek(0, 0)
            return fp
        else:
            fp.close()
            return True


def PackCatFileFromInFile(infile, outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["crc32", "crc32", "crc32"], extradata=[], formatspecs=__file_format_dict__, verbose=False, returnfp=False):
    checkcompressfile = CheckCompressionSubType(infile, formatspecs, filestart, True)
    if(IsNestedDict(formatspecs) and checkcompressfile in formatspecs):
        formatspecs = formatspecs[checkcompressfile]
    if(verbose):
        logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG)
    if(checkcompressfile == "tarfile" and TarFileCheck(infile)):
        return PackCatFileFromTarFile(infile, outfile, fmttype, compression, compresswholefile, compressionlevel, compressionuselist, checksumtype, extradata, formatspecs, verbose, returnfp)
    elif(checkcompressfile == "zipfile" and zipfile.is_zipfile(infile)):
        return PackCatFileFromZipFile(infile, outfile, fmttype, compression, compresswholefile, compressionlevel, compressionuselist, checksumtype, extradata, formatspecs, verbose, returnfp)
    elif(rarfile_support and checkcompressfile == "rarfile" and (rarfile.is_rarfile(infile) or rarfile.is_rarfile_sfx(infile))):
        return PackCatFileFromRarFile(infile, outfile, fmttype, compression, compresswholefile, compressionlevel, compressionuselist, checksumtype, extradata, formatspecs, verbose, returnfp)
    elif(py7zr_support and checkcompressfile == "7zipfile" and py7zr.is_7zfile(infile)):
        return PackCatFileFromSevenZipFile(infile, outfile, fmttype, compression, compresswholefile, compressionlevel, compressionuselist, checksumtype, extradata, formatspecs, verbose, returnfp)
    elif(IsSingleDict(formatspecs) and checkcompressfile == formatspecs['format_magic']):
        return RePackCatFile(infile, outfile, fmttype, compression, compresswholefile, compressionlevel, False, 0, 0, checksumtype, False, extradata, formatspecs, verbose, returnfp)
    else:
        return False
    return False


def CatFileValidate(infile, fmttype="auto", filestart=0, formatspecs=__file_format_multi_dict__, seektoend=False, verbose=False, returnfp=False):
    if(verbose):
        logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG)
    if(IsNestedDict(formatspecs) and fmttype!="auto" and fmttype in formatspecs):
        formatspecs = formatspecs[fmttype]
    elif(IsNestedDict(formatspecs) and fmttype!="auto" and fmttype not in formatspecs):
        fmttype = "auto"
    curloc = filestart
    if(hasattr(infile, "read") or hasattr(infile, "write")):
        curloc = infile.tell()
        fp = infile
        fp.seek(filestart, 0)
        fp = UncompressFileAlt(fp, formatspecs, filestart)
        checkcompressfile = CheckCompressionSubType(fp, formatspecs, filestart, True)
        if(IsNestedDict(formatspecs) and checkcompressfile in formatspecs):
            formatspecs = formatspecs[checkcompressfile]
        if(checkcompressfile == "tarfile" and TarFileCheck(infile)):
            return TarFileToArray(infile, 0, 0, listonly, contentasfile, skipchecksum, formatspecs, seektoend, returnfp)
        elif(checkcompressfile == "zipfile" and zipfile.is_zipfile(infile)):
            return ZipFileToArray(infile, 0, 0, listonly, contentasfile, skipchecksum, formatspecs, seektoend, returnfp)
        elif(rarfile_support and checkcompressfile == "rarfile" and (rarfile.is_rarfile(infile) or rarfile.is_rarfile_sfx(infile))):
            return RarFileToArray(infile, 0, 0, listonly, contentasfile, skipchecksum, formatspecs, seektoend, returnfp)
        elif(py7zr_support and checkcompressfile == "7zipfile" and py7zr.is_7zfile(infile)):
            return SevenZipFileToArray(infile, 0, 0, listonly, contentasfile, skipchecksum, formatspecs, seektoend, returnfp)
        elif(IsSingleDict(formatspecs) and checkcompressfile != formatspecs['format_magic']):
            return False
        elif(IsNestedDict(formatspecs) and checkcompressfile not in formatspecs):
            return False
        if(not fp):
            return False
        fp.seek(filestart, 0)
    elif(infile == "-"):
        fp = MkTempFile()
        if(hasattr(sys.stdin, "buffer")):
            shutil.copyfileobj(sys.stdin.buffer, fp)
        else:
            shutil.copyfileobj(sys.stdin, fp)
        fp.seek(filestart, 0)
        fp = UncompressFileAlt(fp, formatspecs, filestart)
        checkcompressfile = CheckCompressionSubType(fp, formatspecs, filestart, True)
        if(IsNestedDict(formatspecs) and checkcompressfile in formatspecs):
            formatspecs = formatspecs[checkcompressfile]
        if(not fp):
            return False
        fp.seek(filestart, 0)
    elif(isinstance(infile, bytes) and sys.version_info[0] >= 3):
        fp = MkTempFile()
        fp.write(infile)
        fp.seek(filestart, 0)
        fp = UncompressFileAlt(fp, formatspecs, filestart)
        compresscheck = CheckCompressionType(fp, formatspecs, 0, False)
        if(IsNestedDict(formatspecs) and compresscheck in formatspecs):
            formatspecs = formatspecs[compresscheck]
        if(not fp):
            return False
        fp.seek(filestart, 0)
    elif(re.findall(__download_proto_support__, infile)):
        fp = download_file_from_internet_file(infile)
        fp = UncompressFileAlt(fp, formatspecs, filestart)
        compresscheck = CheckCompressionType(fp, formatspecs, 0, False)
        if(IsNestedDict(formatspecs) and compresscheck in formatspecs):
            formatspecs = formatspecs[compresscheck]
        fp.seek(filestart, 0)
        if(not fp):
            return False
        fp.seek(filestart, 0)
    else:
        infile = RemoveWindowsPath(infile)
        checkcompressfile = CheckCompressionSubType(infile, formatspecs, filestart, True)
        if(IsNestedDict(formatspecs) and checkcompressfile in formatspecs):
            formatspecs = formatspecs[checkcompressfile]
        if(checkcompressfile == "tarfile" and TarFileCheck(infile)):
            return TarFileToArray(infile, 0, 0, listonly, contentasfile, skipchecksum, formatspecs, seektoend, returnfp)
        elif(checkcompressfile == "zipfile" and zipfile.is_zipfile(infile)):
            return ZipFileToArray(infile, 0, 0, listonly, contentasfile, skipchecksum, formatspecs, seektoend, returnfp)
        elif(rarfile_support and checkcompressfile == "rarfile" and (rarfile.is_rarfile(infile) or rarfile.is_rarfile_sfx(infile))):
            return RarFileToArray(infile, 0, 0, listonly, contentasfile, skipchecksum, formatspecs, seektoend, returnfp)
        elif(py7zr_support and checkcompressfile == "7zipfile" and py7zr.is_7zfile(infile)):
            return SevenZipFileToArray(infile, 0, 0, listonly, contentasfile, skipchecksum, formatspecs, seektoend, returnfp)
        elif(IsSingleDict(formatspecs) and checkcompressfile != formatspecs['format_magic']):
            return False
        elif(IsNestedDict(formatspecs) and checkcompressfile not in formatspecs):
            return False
        compresscheck = CheckCompressionType(infile, formatspecs, filestart, True)
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
        fp = UncompressFile(infile, formatspecs, "rb", filestart)
    try:
        fp.seek(0, 2)
    except OSError:
        SeekToEndOfFile(fp)
    except ValueError:
        SeekToEndOfFile(fp)
    CatSize = fp.tell()
    CatSizeEnd = CatSize
    fp.seek(curloc, 0)
    if(IsNestedDict(formatspecs)):
        compresschecking = CheckCompressionType(fp, formatspecs, filestart, False)
        if(compresschecking not in formatspecs):
            return False
        else:
            formatspecs = formatspecs[compresschecking]
            fp.seek(filestart, 0)
    inheaderver = str(int(formatspecs['format_ver'].replace(".", "")))
    formstring = fp.read(formatspecs['format_len'] + len(inheaderver)).decode("UTF-8")
    formdelszie = len(formatspecs['format_delimiter'])
    formdel = fp.read(formdelszie).decode("UTF-8")
    if(formstring != formatspecs['format_magic']+inheaderver):
        return False
    if(formdel != formatspecs['format_delimiter']):
        return False
    if(formatspecs['new_style']):
        inheader = ReadFileHeaderDataBySize(
            fp, formatspecs['format_delimiter'])
    else:
        inheader = ReadFileHeaderDataWoSize(
            fp, formatspecs['format_delimiter'])
    fnumextrafieldsize = int(inheader[5], 16)
    fnumextrafields = int(inheader[6], 16)
    extrastart = 7
    extraend = extrastart + fnumextrafields
    formversion = re.findall("([\\d]+)", formstring)
    fheadsize = int(inheader[0], 16)
    fnumfields = int(inheader[1], 16)
    fhencoding = inheader[2]
    fostype = inheader[3]
    fnumfiles = int(inheader[4], 16)
    fprechecksumtype = inheader[-2]
    fprechecksum = inheader[-1]
    il = 0
    headercheck = ValidateHeaderChecksum([formstring] + inheader[:-1], fprechecksumtype, fprechecksum, formatspecs)
    newfcs = GetHeaderChecksum([formstring] + inheader[:-1], fprechecksumtype, True, formatspecs)
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
    while (fp.tell() < CatSizeEnd) if seektoend else (il < fnumfiles):
        outfhstart = fp.tell()
        if(formatspecs['new_style']):
            inheaderdata = ReadFileHeaderDataBySize(
                fp, formatspecs['format_delimiter'])
        else:
            inheaderdata = ReadFileHeaderDataWoSize(
                fp, formatspecs['format_delimiter'])
        if(len(inheaderdata) == 0):
            break
        outfheadsize = int(inheaderdata[0], 16)
        outfnumfields = int(inheaderdata[1], 16)
        outftype = int(inheaderdata[2], 16)
        outfencoding = inheader[3]
        outfencoding = inheader[4]
        if(re.findall("^[.|/]", inheaderdata[5])):
            outfname = inheaderdata[5]
        else:
            outfname = "./"+inheaderdata[5]
        outfbasedir = os.path.dirname(outfname)
        outflinkname = inheaderdata[6]
        outfsize = int(inheaderdata[7], 16)
        outfatime = int(inheaderdata[8], 16)
        outfmtime = int(inheaderdata[9], 16)
        outfctime = int(inheaderdata[10], 16)
        outfbtime = int(inheaderdata[11], 16)
        outfmode = int(inheaderdata[12], 16)
        outfchmode = stat.S_IMODE(outfmode)
        outftypemod = stat.S_IFMT(outfmode)
        outfwinattributes = int(inheaderdata[13], 16)
        outfcompression = inheaderdata[14]
        outfcsize = int(inheaderdata[15], 16)
        outfuid = int(inheaderdata[16], 16)
        outfuname = inheaderdata[17]
        outfgid = int(inheaderdata[18], 16)
        outfgname = inheaderdata[19]
        fid = int(inheaderdata[20], 16)
        finode = int(inheaderdata[21], 16)
        flinkcount = int(inheaderdata[22], 16)
        outfdev = int(inheaderdata[23], 16)
        outfdev_minor = int(inheaderdata[24], 16)
        outfdev_major = int(inheaderdata[25], 16)
        outfseeknextfile = inheaderdata[26]
        outfjsontype = inheaderdata[27]
        outfjsonlen = int(inheaderdata[28], 16)
        outfjsonsize = int(inheaderdata[29], 16)
        outfjsonchecksumtype = inheaderdata[30]
        outfjsonchecksum = inheaderdata[31]
        outfhend = fp.tell() - 1
        outfjstart = fp.tell()
        outfprejsoncontent = fp.read(outfjsonsize).decode("UTF-8")
        outfjend = fp.tell()
        fp.seek(len(formatspecs['format_delimiter']), 1)
        injsonfcs = GetFileChecksum(outfprejsoncontent, outfjsonchecksumtype, True, formatspecs)
        outfextrasize = int(inheaderdata[32], 16)
        outfextrafields = int(inheaderdata[33], 16)
        extrafieldslist = []
        extrastart = 34
        extraend = extrastart + outfextrafields
        outfcs = inheaderdata[-2].lower()
        outfccs = inheaderdata[-1].lower()
        infcs = GetHeaderChecksum(
            inheaderdata[:-2], inheaderdata[-4].lower(), True, formatspecs)
        if(verbose):
            VerbosePrintOut(outfname)
            VerbosePrintOut("Record Number " + str(il) + "; File ID " +
                            str(fid) + "; iNode Number " + str(finode))
        if(outfcs == infcs):
            if(verbose):
                VerbosePrintOut(
                    "File Header Checksum Passed at offset " + str(outfhstart))
                VerbosePrintOut("'" + outfcs + "' == " +
                                "'" + infcs + "'")
        else:
            if(verbose):
                VerbosePrintOut(
                    "File Header Checksum Failed at offset " + str(outfhstart))
                VerbosePrintOut("'" + outfcs + "' != " +
                                "'" + infcs + "'")
            valid_archive = False
            invalid_archive = True
        if(outfjsonsize > 0):
            if(outfjsonchecksum == injsonfcs):
                if(verbose):
                    VerbosePrintOut(
                        "File JSON Data Checksum Passed at offset " + str(outfjstart))
                    VerbosePrintOut("'" + outfjsonchecksum + "' == " +
                                    "'" + injsonfcs + "'")
            else:
                if(verbose):
                    VerbosePrintOut(
                        "File JSON Data Checksum Error at offset " + str(outfjstart))
                    VerbosePrintOut("'" + outfjsonchecksum + "' != " +
                                    "'" + injsonfcs + "'")
                valid_archive = False
                invalid_archive = True
        outfcontentstart = fp.tell()
        outfcontents = ""
        pyhascontents = False
        if(outfsize > 0):
            if(outfcompression == "none" or outfcompression == "" or outfcompression == "auto"):
                outfcontents = fp.read(outfsize)
            else:
                outfcontents = fp.read(outfcsize)
            infccs = GetFileChecksum(
                outfcontents, inheaderdata[-3].lower(), False, formatspecs)
            pyhascontents = True
            if(outfccs == infccs):
                if(verbose):
                    VerbosePrintOut(
                        "File Content Checksum Passed at offset " + str(outfcontentstart))
                    VerbosePrintOut("'" + outfccs +
                                    "' == " + "'" + infccs + "'")
            else:
                if(verbose):
                    VerbosePrintOut(
                        "File Content Checksum Failed at offset " + str(outfcontentstart))
                    VerbosePrintOut("'" + outfccs +
                                    "' != " + "'" + infccs + "'")
                valid_archive = False
                invalid_archive = True
        if(verbose):
            VerbosePrintOut("")
        if(re.findall("^\\+([0-9]+)", outfseeknextfile)):
            fseeknextasnum = int(outfseeknextfile.replace("+", ""))
            if(abs(fseeknextasnum) == 0):
                pass
            fp.seek(fseeknextasnum, 1)
        elif(re.findall("^\\-([0-9]+)", outfseeknextfile)):
            fseeknextasnum = int(outfseeknextfile)
            if(abs(fseeknextasnum) == 0):
                pass
            fp.seek(fseeknextasnum, 1)
        elif(re.findall("^([0-9]+)", outfseeknextfile)):
            fseeknextasnum = int(outfseeknextfile)
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


def CatFileValidateFile(infile, fmttype="auto", filestart=0, formatspecs=__file_format_multi_dict__, seektoend=False, verbose=False, returnfp=False):
    return CatFileValidate(infile, fmttype, filestart, formatspecs, seektoend, verbose, returnfp)


def CatFileValidateMultiple(infile, fmttype="auto", filestart=0, formatspecs=__file_format_multi_dict__, seektoend=False, verbose=False, returnfp=False):
    if(isinstance(infile, (list, tuple, ))):
        pass
    else:
        infile = [infile]
    outretval = True
    for curfname in infile:
        curretfile = CatFileValidate(curfname, fmttype, filestart, formatspecs, seektoend, verbose, returnfp)
        if(not curretfile):
            outretval = False
    return outretval

def CatFileValidateMultipleFiles(infile, fmttype="auto", filestart=0, formatspecs=__file_format_multi_dict__, seektoend=False, verbose=False, returnfp=False):
    return CatFileValidateMultiple(infile, fmttype, filestart, formatspecs, seektoend, verbose, returnfp)


def StackedCatFileValidate(infile, fmttype="auto", filestart=0, formatspecs=__file_format_multi_dict__, seektoend=False, verbose=False, returnfp=False):
    outretval = []
    outstartfile = filestart
    outfsize = float('inf')
    while True:
        if outstartfile >= outfsize:   # stop when function signals False
            break
        is_valid_file = CatFileValidate(infile, fmttype, filestart, formatspecs, seektoend, verbose, True)
        if is_valid_file is False:   # stop when function signals False
            outretval.append(is_valid_file)
        else:
            outretval.append(True)
        infile = is_valid_file
        outstartfile = infile.tell()
        try:
            infile.seek(0, 2)
        except OSError:
            SeekToEndOfFile(infile)
        except ValueError:
            SeekToEndOfFile(infile)
        outfsize = infile.tell()
        infile.seek(outstartfile, 0)
    if(returnfp):
        return infile
    else:
        infile.close()
        return outretval
    


def StackedCatFileValidateFile(infile, fmttype="auto", filestart=0, formatspecs=__file_format_multi_dict__, seektoend=False, verbose=False, returnfp=False):
    return StackedCatFileValidate(infile, fmttype, filestart, formatspecs, seektoend, verbose, returnfp)


def StackedCatFileValidateMultiple(infile, fmttype="auto", filestart=0, formatspecs=__file_format_multi_dict__, seektoend=False, verbose=False, returnfp=False):
    if(isinstance(infile, (list, tuple, ))):
        pass
    else:
        infile = [infile]
    outretval = True
    for curfname in infile:
        curretfile = StackedCatFileValidate(curfname, fmttype, filestart, formatspecs, seektoend, verbose, returnfp)
        if(not curretfile):
            outretval = False
    return outretval

def StackedCatFileValidateMultipleFiles(infile, fmttype="auto", filestart=0, formatspecs=__file_format_multi_dict__, seektoend=False, verbose=False, returnfp=False):
    return StackedCatFileValidateMultiple(infile, fmttype, filestart, formatspecs, seektoend, verbose, returnfp)


def CatFileToArray(infile, fmttype="auto", filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_multi_dict__, seektoend=False, returnfp=False):
    if(IsNestedDict(formatspecs) and fmttype!="auto" and fmttype in formatspecs):
        formatspecs = formatspecs[fmttype]
    elif(IsNestedDict(formatspecs) and fmttype!="auto" and fmttype not in formatspecs):
        fmttype = "auto"
    curloc = filestart
    if(hasattr(infile, "read") or hasattr(infile, "write")):
        curloc = infile.tell()
        fp = infile
        fp.seek(filestart, 0)
        fp = UncompressFileAlt(fp, formatspecs, filestart)
        compresscheck = CheckCompressionSubType(fp, formatspecs, filestart, True)
        if(IsNestedDict(formatspecs) and compresscheck in formatspecs):
            formatspecs = formatspecs[compresscheck]
        if(compresscheck == "tarfile" and TarFileCheck(infile)):
            return TarFileToArray(infile, 0, 0, listonly, contentasfile, skipchecksum, formatspecs, seektoend, returnfp)
        elif(compresscheck == "zipfile" and zipfile.is_zipfile(infile)):
            return ZipFileToArray(infile, 0, 0, listonly, contentasfile, skipchecksum, formatspecs, seektoend, returnfp)
        elif(rarfile_support and compresscheck == "rarfile" and (rarfile.is_rarfile(infile) or rarfile.is_rarfile_sfx(infile))):
            return RarFileToArray(infile, 0, 0, listonly, contentasfile, skipchecksum, formatspecs, seektoend, returnfp)
        elif(py7zr_support and compresscheck == "7zipfile" and py7zr.is_7zfile(infile)):
            return SevenZipFileToArray(infile, 0, 0, listonly, contentasfile, skipchecksum, formatspecs, seektoend, returnfp)
        elif(IsSingleDict(formatspecs) and compresscheck != formatspecs['format_magic']):
            return False
        elif(IsNestedDict(formatspecs) and compresscheck not in formatspecs):
            return False
        if(not fp):
            return False
        fp.seek(filestart, 0)
    elif(infile == "-"):
        fp = MkTempFile()
        if(hasattr(sys.stdin, "buffer")):
            shutil.copyfileobj(sys.stdin.buffer, fp)
        else:
            shutil.copyfileobj(sys.stdin, fp)
        fp.seek(filestart, 0)
        fp = UncompressFileAlt(fp, formatspecs, filestart)
        compresscheck = CheckCompressionSubType(fp, formatspecs, filestart, True)
        if(IsNestedDict(formatspecs) and compresscheck in formatspecs):
            formatspecs = formatspecs[compresscheck]
        if(not fp):
            return False
        fp.seek(filestart, 0)
    elif(isinstance(infile, bytes) and sys.version_info[0] >= 3):
        fp = MkTempFile()
        fp.write(infile)
        fp.seek(filestart, 0)
        fp = UncompressFileAlt(fp, formatspecs, filestart)
        compresscheck = CheckCompressionType(fp, formatspecs, filestart, False)
        if(IsNestedDict(formatspecs) and compresscheck in formatspecs):
            formatspecs = formatspecs[compresscheck]
        if(not fp):
            return False
        fp.seek(filestart, 0)
    elif(re.findall(__download_proto_support__, infile)):
        fp = download_file_from_internet_file(infile)
        fp = UncompressFileAlt(fp, formatspecs, filestart)
        compresscheck = CheckCompressionType(fp, formatspecs, filestart, False)
        if(IsNestedDict(formatspecs) and compresscheck in formatspecs):
            formatspecs = formatspecs[compresscheck]
        fp.seek(filestart, 0)
        if(not fp):
            return False
        fp.seek(filestart, 0)
    else:
        infile = RemoveWindowsPath(infile)
        compresscheck = CheckCompressionSubType(infile, formatspecs, filestart, True)
        if(IsNestedDict(formatspecs) and compresscheck in formatspecs):
            formatspecs = formatspecs[compresscheck]
        if(compresscheck == "tarfile" and TarFileCheck(infile)):
            return TarFileToArray(infile, 0, 0, listonly, contentasfile, skipchecksum, formatspecs, seektoend, returnfp)
        elif(compresscheck == "zipfile" and zipfile.is_zipfile(infile)):
            return ZipFileToArray(infile, 0, 0, listonly, contentasfile, skipchecksum, formatspecs, seektoend, returnfp)
        elif(rarfile_support and compresscheck == "rarfile" and (rarfile.is_rarfile(infile) or rarfile.is_rarfile_sfx(infile))):
            return RarFileToArray(infile, 0, 0, listonly, contentasfile, skipchecksum, formatspecs, seektoend, returnfp)
        elif(py7zr_support and compresscheck == "7zipfile" and py7zr.is_7zfile(infile)):
            return SevenZipFileToArray(infile, 0, 0, listonly, contentasfile, skipchecksum, formatspecs, seektoend, returnfp)
        elif(IsSingleDict(formatspecs) and compresscheck != formatspecs['format_magic']):
            return False
        elif(IsNestedDict(formatspecs) and compresscheck not in formatspecs):
            return False
        compresscheck = CheckCompressionType(infile, formatspecs, filestart, True)
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
        fp = UncompressFile(infile, formatspecs, "rb", filestart)
    try:
        fp.seek(0, 2)
    except OSError:
        SeekToEndOfFile(fp)
    except ValueError:
        SeekToEndOfFile(fp)
    CatSize = fp.tell()
    CatSizeEnd = CatSize;
    fp.seek(curloc, 0)
    if(IsNestedDict(formatspecs)):
        compresschecking = CheckCompressionType(fp, formatspecs, filestart, False)
        if(compresschecking not in formatspecs):
            return False
        else:
            formatspecs = formatspecs[compresschecking]
            fp.seek(filestart, 0)
    inheaderver = str(int(formatspecs['format_ver'].replace(".", "")))
    formstring = fp.read(formatspecs['format_len'] + len(inheaderver)).decode("UTF-8")
    formdelszie = len(formatspecs['format_delimiter'])
    formdel = fp.read(formdelszie).decode("UTF-8")
    if(formstring != formatspecs['format_magic']+inheaderver):
        return False
    if(formdel != formatspecs['format_delimiter']):
        return False
    if(formatspecs['new_style']):
        inheader = ReadFileHeaderDataBySize(
            fp, formatspecs['format_delimiter'])
    else:
        inheader = ReadFileHeaderDataWoSize(
            fp, formatspecs['format_delimiter'])
    fnumextrafieldsize = int(inheader[5], 16)
    fnumextrafields = int(inheader[6], 16)
    fextrafieldslist = []
    extrastart = 7
    extraend = extrastart + fnumextrafields
    while(extrastart < extraend):
        fextrafieldslist.append(inheader[extrastart])
        extrastart = extrastart + 1
    if(fnumextrafields==1):
        try:
            fextrafieldslist = json.loads(base64.b64decode(fextrafieldslist[0]).decode("UTF-8"))
            fnumextrafields = len(fextrafieldslist)
        except (binascii.Error, json.decoder.JSONDecodeError, UnicodeDecodeError):
            try:
                fextrafieldslist = json.loads(fextrafieldslist[0])
            except (binascii.Error, json.decoder.JSONDecodeError, UnicodeDecodeError):
                pass
    formversion = re.findall("([\\d]+)", formstring)
    fheadsize = int(inheader[0], 16)
    fnumfields = int(inheader[1], 16)
    fhencoding = inheader[2]
    fostype = inheader[3]
    fnumfiles = int(inheader[4], 16)
    fprechecksumtype = inheader[-2]
    fprechecksum = inheader[-1]
    headercheck = ValidateHeaderChecksum([formstring] + inheader[:-1], fprechecksumtype, fprechecksum, formatspecs)
    newfcs = GetHeaderChecksum([formstring] + inheader[:-1], fprechecksumtype, True, formatspecs)
    if(not headercheck and not skipchecksum):
        VerbosePrintOut(
            "File Header Checksum Error with file at offset " + str(0))
        VerbosePrintOut("'" + fprechecksum + "' != " +
                        "'" + newfcs + "'")
        return False
    formversions = re.search('(.*?)(\\d+)', formstring).groups()
    fcompresstype = compresscheck
    if(fcompresstype==formatspecs['format_magic']):
        fcompresstype = ""
    outlist = {'fnumfiles': fnumfiles, 'ffilestart': filestart, 'fformat': formversions[0], 'fcompression': fcompresstype, 'fencoding': fhencoding, 'fversion': formversions[1], 'fostype': fostype, 'fheadersize': fheadsize, 'fsize': CatSizeEnd, 'fnumfields': fnumfields + 2, 'fformatspecs': formatspecs, 'fchecksumtype': fprechecksumtype, 'fheaderchecksum': fprechecksum, 'frawheader': [formstring] + inheader, 'fextrafields': fnumextrafields, 'fextrafieldsize': fnumextrafieldsize, 'fextradata': fextrafieldslist, 'ffilelist': []}
    if (seekstart < 0) or (seekstart > fnumfiles):
        seekstart = 0
    if (seekend == 0) or (seekend > fnumfiles) or (seekend < seekstart):
        seekend = fnumfiles
    elif (seekend < 0) and (abs(seekend) <= fnumfiles) and (abs(seekend) >= seekstart):
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
            prefcencoding = preheaderdata[4]
            if(re.findall("^[.|/]", preheaderdata[5])):
                prefname = preheaderdata[5]
            else:
                prefname = "./"+preheaderdata[5]
            prefsize = int(preheaderdata[7], 16)
            prefcompression = preheaderdata[14]
            prefcsize = int(preheaderdata[15], 16)
            prefseeknextfile = preheaderdata[26]
            prefjsontype = preheaderdata[27]
            prefjsonlen = int(preheaderdata[28], 16)
            prefjsonsize = int(preheaderdata[29], 16)
            prefjsonchecksumtype = preheaderdata[30]
            prefjsonchecksum = preheaderdata[31]
            prefhend = fp.tell() - 1
            prefjstart = fp.tell()
            prefjoutfprejsoncontent = fp.read(prefjsonsize).decode("UTF-8")
            prefjend = fp.tell()
            fp.seek(len(formatspecs['format_delimiter']), 1)
            prejsonfcs = GetFileChecksum(prefjoutfprejsoncontent, prefjsonchecksumtype, True, formatspecs)
            prefextrasize = int(preheaderdata[32], 16)
            prefextrafields = int(preheaderdata[33], 16)
            extrastart = 34
            extraend = extrastart + prefextrafields
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
            if(prefjsonsize > 0):
                if(prejsonfcs != prefjsonchecksum and not skipchecksum):
                    VerbosePrintOut("File JSON Data Checksum Error with file " +
                                    prefname + " at offset " + str(prefjstart))
                    VerbosePrintOut("'" + prefjsonchecksum + "' != " + "'" + prejsonfcs + "'")
                    return False
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
    while (fp.tell() < CatSizeEnd) if seektoend else (fileidnum < seekend):
        outfhstart = fp.tell()
        if(formatspecs['new_style']):
            inheaderdata = ReadFileHeaderDataBySize(
                fp, formatspecs['format_delimiter'])
        else:
            inheaderdata = ReadFileHeaderDataWoSize(
                fp, formatspecs['format_delimiter'])
        if(len(inheaderdata) == 0):
            break
        outfheadsize = int(inheaderdata[0], 16)
        outfnumfields = int(inheaderdata[1], 16)
        outftype = int(inheaderdata[2], 16)
        outfencoding = inheaderdata[3]
        outfcencoding = inheaderdata[4]
        if(re.findall("^[.|/]", inheaderdata[5])):
            outfname = inheaderdata[5]
        else:
            outfname = "./"+inheaderdata[5]
        outfbasedir = os.path.dirname(outfname)
        outflinkname = inheaderdata[6]
        outfsize = int(inheaderdata[7], 16)
        outfatime = int(inheaderdata[8], 16)
        outfmtime = int(inheaderdata[9], 16)
        outfctime = int(inheaderdata[10], 16)
        outfbtime = int(inheaderdata[11], 16)
        outfmode = int(inheaderdata[12], 16)
        outfchmode = stat.S_IMODE(outfmode)
        outftypemod = stat.S_IFMT(outfmode)
        outfwinattributes = int(inheaderdata[13], 16)
        outfcompression = inheaderdata[14]
        outfcsize = int(inheaderdata[15], 16)
        outfuid = int(inheaderdata[16], 16)
        outfuname = inheaderdata[17]
        outfgid = int(inheaderdata[18], 16)
        outfgname = inheaderdata[19]
        outfid = int(inheaderdata[20], 16)
        outfinode = int(inheaderdata[21], 16)
        outflinkcount = int(inheaderdata[22], 16)
        outfdev = int(inheaderdata[23], 16)
        outfdev_minor = int(inheaderdata[24], 16)
        outfdev_major = int(inheaderdata[25], 16)
        outfseeknextfile = inheaderdata[26]
        outfjsontype = inheaderdata[27]
        outfjsonlen = int(inheaderdata[28], 16)
        outfjsonsize = int(inheaderdata[29], 16)
        outfjsonchecksumtype = inheaderdata[30]
        outfjsonchecksum = inheaderdata[31]
        outfhend = fp.tell() - 1
        outfjstart = fp.tell()
        if(outfjsontype=="json"):
            outfjsoncontent = {}
            outfprejsoncontent = fp.read(outfjsonsize).decode("UTF-8")
            if(outfjsonsize > 0):
                try:
                    outfjsonrawcontent = base64.b64decode(outfprejsoncontent.encode("UTF-8")).decode("UTF-8")
                    outfjsoncontent = json.loads(base64.b64decode(outfprejsoncontent.encode("UTF-8")).decode("UTF-8"))
                except (binascii.Error, json.decoder.JSONDecodeError, UnicodeDecodeError):
                    try:
                        outfjsonrawcontent = outfprejsoncontent
                        outfjsoncontent = json.loads(outfprejsoncontent)
                    except (binascii.Error, json.decoder.JSONDecodeError, UnicodeDecodeError):
                        outfjsonrawcontent = outfprejsoncontent 
                        outfjsoncontent = {}
            else:
                outfjsonrawcontent = outfprejsoncontent 
                outfjsoncontent = {}
        elif(outfjsontype=="list"):
            outfprejsoncontent = fp.read(outfjsonsize).decode("UTF-8")
            flisttmp = MkTempFile()
            flisttmp.write(outfprejsoncontent.encode())
            flisttmp.seek(0)
            outfjsoncontent = ReadFileHeaderData(flisttmp, outfjsonlen, formatspecs['format_delimiter'])
            flisttmp.close()
            outfjsonrawcontent = outfjsoncontent
            if(outfjsonlen==1):
                try:
                    outfjsonrawcontent = base64.b64decode(outfjsoncontent[0]).decode("UTF-8")
                    outfjsoncontent = json.loads(base64.b64decode(outfjsoncontent[0]).decode("UTF-8"))
                    outfjsonlen = len(outfjsoncontent)
                except (binascii.Error, json.decoder.JSONDecodeError, UnicodeDecodeError):
                    try:
                        outfjsonrawcontent = outfjsoncontent[0]
                        outfjsoncontent = json.loads(outfjsoncontent[0])
                    except (binascii.Error, json.decoder.JSONDecodeError, UnicodeDecodeError):
                        pass
        outfjend = fp.tell()
        fp.seek(len(formatspecs['format_delimiter']), 1)
        injsonfcs = GetFileChecksum(outfprejsoncontent, outfjsonchecksumtype, True, formatspecs)
        outfextrasize = int(inheaderdata[32], 16)
        outfextrafields = int(inheaderdata[33], 16)
        extrafieldslist = []
        extrastart = 34
        extraend = extrastart + outfextrafields
        while(extrastart < extraend):
            extrafieldslist.append(inheaderdata[extrastart])
            extrastart = extrastart + 1
        if(outfextrafields==1):
            try:
                extrafieldslist = json.loads(base64.b64decode(extrafieldslist[0]).decode("UTF-8"))
                outfextrafields = len(extrafieldslist)
            except (binascii.Error, json.decoder.JSONDecodeError, UnicodeDecodeError):
                try:
                    fextrafieldslist = json.loads(fextrafieldslist[0])
                except (binascii.Error, json.decoder.JSONDecodeError, UnicodeDecodeError):
                    pass
        outfcs = inheaderdata[-2].lower()
        outfccs = inheaderdata[-1].lower()
        infcs = GetHeaderChecksum(
            inheaderdata[:-2], inheaderdata[-4].lower(), True, formatspecs)
        if(outfcs != infcs and not skipchecksum):
            VerbosePrintOut("File Header Checksum Error with file " +
                            outfname + " at offset " + str(outfhstart))
            VerbosePrintOut("'" + outfcs + "' != " +
                            "'" + infcs + "'")
            return False
        if(outfjsonsize > 0):
            if(injsonfcs != outfjsonchecksum and not skipchecksum):
                VerbosePrintOut("File JSON Data Checksum Error  at offset " + str(outfjstart))
                VerbosePrintOut("'" + outfjsonchecksum + "' != " + "'" + injsonfcs + "'")
                return False
        outfcontentstart = fp.tell()
        outfcontents = MkTempFile()
        pyhascontents = False
        if(outfsize > 0 and not listonly):
            if(outfcompression == "none" or outfcompression == "" or outfcompression == "auto"):
                outfcontents.write(fp.read(outfsize))
            else:
                outfcontents.write(fp.read(outfcsize))
            outfcontents.seek(0, 0)
            infccs = GetFileChecksum(
                outfcontents.read(), inheaderdata[-3].lower(), False, formatspecs)
            pyhascontents = True
            if(outfccs != infccs and not skipchecksum):
                VerbosePrintOut("File Content Checksum Error with file " +
                                outfname + " at offset " + str(outfcontentstart))
                VerbosePrintOut("'" + outfccs + "' != " +
                                "'" + infccs + "'")
                return False
            if(outfcompression == "none" or outfcompression == "" or outfcompression == "auto"):
                pass
            else:
                outfcontents.seek(0, 0)
                if(uncompress):
                    cfcontents = UncompressFileAlt(
                        outfcontents, formatspecs, 0)
                    cfcontents.seek(0, 0)
                    outfcontents = MkTempFile()
                    shutil.copyfileobj(cfcontents, outfcontents)
                    cfcontents.close()
                    outfcontents.seek(0, 0)
                    outfccs = GetFileChecksum(
                        outfcontents.read(), inheaderdata[-3].lower(), False, formatspecs)
        if(outfsize > 0 and listonly):
            if(outfcompression == "none" or outfcompression == "" or outfcompression == "auto"):
                fp.seek(outfsize, 1)
            else:
                fp.seek(outfcsize, 1)
            pyhascontents = False
        outfcontentend = fp.tell()
        if(re.findall("^\\+([0-9]+)", outfseeknextfile)):
            fseeknextasnum = int(outfseeknextfile.replace("+", ""))
            if(abs(fseeknextasnum) == 0):
                pass
            fp.seek(fseeknextasnum, 1)
        elif(re.findall("^\\-([0-9]+)", outfseeknextfile)):
            fseeknextasnum = int(outfseeknextfile)
            if(abs(fseeknextasnum) == 0):
                pass
            fp.seek(fseeknextasnum, 1)
        elif(re.findall("^([0-9]+)", outfseeknextfile)):
            fseeknextasnum = int(outfseeknextfile)
            if(abs(fseeknextasnum) == 0):
                pass
            fp.seek(fseeknextasnum, 0)
        else:
            return False
        outfcontents.seek(0, 0)
        if(not contentasfile):
            outfcontents = outfcontents.read()
        outlist['ffilelist'].append({'fid': realidnum, 'fidalt': fileidnum, 'fheadersize': outfheadsize, 'fhstart': outfhstart, 'fhend': outfhend, 'ftype': outftype, 'fencoding': outfencoding, 'fcencoding': outfcencoding, 'fname': outfname, 'fbasedir': outfbasedir, 'flinkname': outflinkname, 'fsize': outfsize, 'fatime': outfatime, 'fmtime': outfmtime, 'fctime': outfctime, 'fbtime': outfbtime, 'fmode': outfmode, 'fchmode': outfchmode, 'ftypemod': outftypemod, 'fwinattributes': outfwinattributes, 'fcompression': outfcompression, 'fcsize': outfcsize, 'fuid': outfuid, 'funame': outfuname, 'fgid': outfgid, 'fgname': outfgname, 'finode': outfinode, 'flinkcount': outflinkcount, 'fdev': outfdev, 'fminor': outfdev_minor, 'fmajor': outfdev_major, 'fseeknextfile': outfseeknextfile, 'fheaderchecksumtype': inheaderdata[-4], 'fjsonchecksumtype': outfjsonchecksumtype, 'fcontentchecksumtype': inheaderdata[-3], 'fnumfields': outfnumfields + 2, 'frawheader': inheaderdata, 'fextrafields': outfextrafields, 'fextrafieldsize': outfextrasize, 'fextradata': extrafieldslist, 'fjsontype': outfjsontype, 'fjsonlen': outfjsonlen, 'fjsonsize': outfjsonsize, 'fjsonrawdata': outfjsonrawcontent, 'fjsondata': outfjsoncontent, 'fjstart': outfjstart, 'fjend': outfjend, 'fheaderchecksum': outfcs, 'fjsonchecksum': outfjsonchecksum, 'fcontentchecksum': outfccs, 'fhascontents': pyhascontents, 'fcontentstart': outfcontentstart, 'fcontentend': outfcontentend, 'fcontentasfile': contentasfile, 'fcontents': outfcontents})
        fileidnum = fileidnum + 1
        realidnum = realidnum + 1
    if(returnfp):
        outlist.update({'fp': fp})
    else:
        fp.close()
        outlist.update({'fp': None})
    return outlist


def MultipleCatFileToArray(infile, fmttype="auto", filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_multi_dict__, seektoend=False, returnfp=False):
    if(isinstance(infile, (list, tuple, ))):
        pass
    else:
        infile = [infile]
    outretval = {}
    for curfname in infile:
        outretval[curfname] = CatFileToArray(curfname, fmttype, filestart, seekstart, seekend, listonly, contentasfile, uncompress, skipchecksum, formatspecs, seektoend, returnfp)
    return outretval

def MultipleCatFilesToArray(infile, fmttype="auto", filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_multi_dict__, seektoend=False, returnfp=False):
    return MultipleCatFileToArray(infile, fmttype, filestart, seekstart, seekend, listonly, contentasfile, uncompress, skipchecksum, formatspecs, seektoend, returnfp)


def StackedCatFileToArray(infile, fmttype="auto", filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_multi_dict__, seektoend=False, returnfp=False):
    outretval = []
    outstartfile = filestart
    outfsize = float('inf')
    while True:
        if outstartfile >= outfsize:   # stop when function signals False
            break
        outarray = CatFileToArray(infile, fmttype, outstartfile, seekstart, seekend, listonly, contentasfile, uncompress, skipchecksum, formatspecs, seektoend, True)
        outfsize = outarray['fsize']
        if outarray is False:   # stop when function signals False
            break
        infile = outarray['fp']
        outstartfile = infile.tell()
        if(not returnfp):
            outarray.update({"fp": None})
        outretval.append(outarray)
    if(not returnfp):
        infile.close()
    return outretval


def MultipleStackedCatFileToArray(infile, fmttype="auto", filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_multi_dict__, seektoend=False, returnfp=False):
    if(isinstance(infile, (list, tuple, ))):
        pass
    else:
        infile = [infile]
    outretval = {}
    for curfname in infile:
        outretval[curfname] = StackedCatFileToArray(curfname, fmttype, filestart, seekstart, seekend, listonly, contentasfile, uncompress, skipchecksum, formatspecs, seektoend, returnfp)
    return outretval

def MultipleStackedCatFilesToArray(infile, fmttype="auto", filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_multi_dict__, seektoend=False, returnfp=False):
    return MultipleStackedCatFileToArray(infile, fmttype, filestart, seekstart, seekend, listonly, contentasfile, uncompress, skipchecksum, formatspecs, seektoend, returnfp)


def CatFileStringToArray(instr, filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, skipchecksum=False, formatspecs=__file_format_multi_dict__, seektoend=False, returnfp=False):
    checkcompressfile = CheckCompressionSubType(infile, formatspecs, filestart, True)
    if(IsNestedDict(formatspecs) and checkcompressfile in formatspecs):
        formatspecs = formatspecs[checkcompressfile]
    fp = MkTempFile(instr)
    listarrayfiles = CatFileToArray(fp, "auto", filestart, seekstart, seekend, listonly, contentasfile, True, skipchecksum, formatspecs, seektoend, returnfp)
    return listarrayfiles


def TarFileToArray(infile, seekstart=0, seekend=0, listonly=False, contentasfile=True, skipchecksum=False, formatspecs=__file_format_dict__, seektoend=False, returnfp=False):
    checkcompressfile = CheckCompressionSubType(infile, formatspecs, filestart, True)
    if(IsNestedDict(formatspecs) and checkcompressfile in formatspecs):
        formatspecs = formatspecs[checkcompressfile]
    fp = MkTempFile()
    fp = PackCatFileFromTarFile(
        infile, fp, "auto", True, None, compressionlistalt, "crc32", [], formatspecs, False, True)
    listarrayfiles = CatFileToArray(fp, "auto", 0, seekstart, seekend, listonly, contentasfile, True, skipchecksum, formatspecs, seektoend, returnfp)
    return listarrayfiles


def ZipFileToArray(infile, seekstart=0, seekend=0, listonly=False, contentasfile=True, skipchecksum=False, formatspecs=__file_format_dict__, seektoend=False, returnfp=False):
    checkcompressfile = CheckCompressionSubType(infile, formatspecs, filestart, True)
    if(IsNestedDict(formatspecs) and checkcompressfile in formatspecs):
        formatspecs = formatspecs[checkcompressfile]
    fp = MkTempFile()
    fp = PackCatFileFromZipFile(
        infile, fp, "auto", True, None, compressionlistalt, "crc32", [], formatspecs, False, True)
    listarrayfiles = CatFileToArray(fp, "auto", 0, seekstart, seekend, listonly, contentasfile, True, skipchecksum, formatspecs, seektoend, returnfp)
    return listarrayfiles


if(not rarfile_support):
    def RarFileToArray(infile, seekstart=0, seekend=0, listonly=False, contentasfile=True, skipchecksum=False, formatspecs=__file_format_dict__, seektoend=False, returnfp=False):
        return False

if(rarfile_support):
    def RarFileToArray(infile, seekstart=0, seekend=0, listonly=False, contentasfile=True, skipchecksum=False, formatspecs=__file_format_dict__, seektoend=False, returnfp=False):
        checkcompressfile = CheckCompressionSubType(infile, formatspecs, filestart, True)
        if(IsNestedDict(formatspecs) and checkcompressfile in formatspecs):
            formatspecs = formatspecs[checkcompressfile]
        fp = MkTempFile()
        fp = PackCatFileFromRarFile(
            infile, fp, "auto", True, None, compressionlistalt, "crc32", [], formatspecs, False, True)
        listarrayfiles = CatFileToArray(fp, "auto", 0, seekstart, seekend, listonly, contentasfile, True, skipchecksum, formatspecs, seektoend, returnfp)
        return listarrayfiles

if(not py7zr_support):
    def SevenZipFileToArray(infile, seekstart=0, seekend=0, listonly=False, contentasfile=True, skipchecksum=False, formatspecs=__file_format_dict__, seektoend=False, returnfp=False):
        return False

if(py7zr_support):
    def SevenZipFileToArray(infile, seekstart=0, seekend=0, listonly=False, contentasfile=True, skipchecksum=False, formatspecs=__file_format_dict__, seektoend=False, returnfp=False):
        checkcompressfile = CheckCompressionSubType(infile, formatspecs, filestart, True)
        if(IsNestedDict(formatspecs) and checkcompressfile in formatspecs):
            formatspecs = formatspecs[checkcompressfile]
        fp = MkTempFile()
        fp = PackCatFileFromSevenZipFile(
            infile, fp, "auto", True, None, compressionlistalt, "crc32", [], formatspecs, False, True)
        listarrayfiles = CatFileToArray(fp, "auto", 0, seekstart, seekend, listonly, contentasfile, True, skipchecksum, formatspecs, seektoend, returnfp)
        return listarrayfiles


def InFileToArray(infile, filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, skipchecksum=False, formatspecs=__file_format_multi_dict__, seektoend=False, returnfp=False):
    checkcompressfile = CheckCompressionSubType(infile, formatspecs, filestart, True)
    if(IsNestedDict(formatspecs) and checkcompressfile in formatspecs):
        formatspecs = formatspecs[checkcompressfile]
    if(checkcompressfile == "tarfile" and TarFileCheck(infile)):
        return TarFileToArray(infile, seekstart, seekend, listonly, contentasfile, skipchecksum, formatspecs, seektoend, returnfp)
    elif(checkcompressfile == "zipfile" and zipfile.is_zipfile(infile)):
        return ZipFileToArray(infile, seekstart, seekend, listonly, contentasfile, skipchecksum, formatspecs, seektoend, returnfp)
    elif(rarfile_support and checkcompressfile == "rarfile" and (rarfile.is_rarfile(infile) or rarfile.is_rarfile_sfx(infile))):
        return RarFileToArray(infile, seekstart, seekend, listonly, contentasfile, skipchecksum, formatspecs, seektoend, returnfp)
    elif(py7zr_support and checkcompressfile == "7zipfile" and py7zr.is_7zfile(infile)):
        return SevenZipFileToArray(infile, seekstart, seekend, listonly, contentasfile, skipchecksum, formatspecs, seektoend, returnfp)
    elif(checkcompressfile == formatspecs['format_magic']):
        return CatFileToArray(infile, "auto", filestart, seekstart, seekend, listonly, contentasfile, True, skipchecksum, formatspecs, seektoend, returnfp)
    else:
        return False
    return False


def ListDirToArray(infiles, dirlistfromtxt=False, fmttype=__file_format_default__, compression="auto", compresswholefile=True, compressionlevel=None, followlink=False, filestart=0, seekstart=0, seekend=0, listonly=False, skipchecksum=False, checksumtype=["crc32", "crc32", "crc32"], extradata=[], formatspecs=__file_format_dict__, verbose=False, seektoend=False, returnfp=False):
    outarray = MkTempFile()
    packform = PackCatFile(infiles, outarray, dirlistfromtxt, fmttype, compression, compresswholefile,
                              compressionlevel, followlink, checksumtype, extradata, formatspecs, verbose, True)
    listarrayfiles = CatFileToArray(outarray, "auto", filestart, seekstart, seekend, listonly, True, True, skipchecksum, formatspecs, seektoend, returnfp)
    return listarrayfiles


# ===== Function (keeps inarray schema; returns entries + indexes) =====

def CatFileArrayToArrayIndex(inarray, returnfp=False):
    """
    Build a bidirectional index over an archive listing while preserving the
    input 'inarray' as-is. Python 2/3 compatible, no external deps.

    Input (unchanged contract):
      inarray: dict with at least:
        - 'ffilelist': list of dicts: {'fname': <str>, 'fid': <any>, 'ftype': <int>}
        - 'fnumfiles': int (expected count)
        - optional 'fp': any (passed through if returnfp=True)

    Output structure:
      {
        'list': inarray,                 # alias to original input (not copied)
        'fp':   inarray.get('fp') or None,
        'entries': { fid: {'name': fname, 'type': ftype} },
        'indexes': {
          'by_name': { fname: fid },
          'by_type': {
            <category>: {
              'by_name': { fname: fid },
              'by_id':   { fid: fname },
              'count':   <int>
            }, ...
          }
        },
        'counts': {
          'total': <int>,
          'by_type': { <category>: <int>, ... }
        },
        'unknown_types': { <ftype_int>: [fname, ...] }
      }
    """
    if not isinstance(inarray, dict):
        return False
    if not inarray:
        return False

    # Buckets for categories
    def _bucket():
        return {"by_name": {}, "by_id": {}, "count": 0}

    by_type = {}
    for cat in CATEGORY_ORDER:
        by_type[cat] = _bucket()

    out = {
        "list": inarray,
        "fp": inarray.get("fp") if returnfp else None,
        "entries": {},
        "indexes": {
            "by_name": {},
            "by_type": by_type,
        },
        "counts": {"total": 0, "by_type": {}},
        "unknown_types": {},
    }

    ffilelist = inarray.get("ffilelist") or []
    try:
        fnumfiles = int(inarray.get("fnumfiles", len(ffilelist)))
    except Exception:
        fnumfiles = len(ffilelist)

    # Process only what's present
    total = min(len(ffilelist), fnumfiles)

    def _add(cat, name, fid):
        b = by_type[cat]
        b["by_name"][name] = fid
        b["by_id"][fid] = name
        # Count is number of unique names in this category
        b["count"] = len(b["by_name"])

    i = 0
    while i < total:
        e = ffilelist[i]
        name = e.get("fname")
        fid  = e.get("fid")
        t    = e.get("ftype")

        if name is None or fid is None or t is None:
            i += 1
            continue

        # Store canonical entry once, keyed by fid
        out["entries"][fid] = {"name": name, "type": t}

        # Global reverse index for fast name -> id
        out["indexes"]["by_name"][name] = fid

        # Base category
        base_cat = BASE_CATEGORY_BY_CODE.get(t)
        if base_cat is not None:
            _add(base_cat, name, fid)
        else:
            # Track unknown codes for visibility/forward-compat
            lst = out["unknown_types"].setdefault(t, [])
            if name not in lst:
                lst.append(name)

        # Union categories
        for union_name, code_set in UNION_RULES:
            if t in code_set:
                _add(union_name, name, fid)

        i += 1

    # Counts
    out["counts"]["total"] = total
    for cat in CATEGORY_ORDER:
        out["counts"]["by_type"][cat] = by_type[cat]["count"]

    return out


def RePackCatFile(infile, outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, followlink=False, filestart=0, seekstart=0, seekend=0, checksumtype=["crc32", "crc32", "crc32", "crc32"], skipchecksum=False, extradata=[], jsondata={}, formatspecs=__file_format_dict__, seektoend=False, verbose=False, returnfp=False):
    if(isinstance(infile, dict)):
        listarrayfiles = infile
    else:
        if(infile != "-" and not isinstance(infile, bytes) and not hasattr(infile, "read") and not hasattr(infile, "write")):
            infile = RemoveWindowsPath(infile)
        listarrayfiles = CatFileToArray(infile, "auto", filestart, seekstart, seekend, False, True, True, skipchecksum, formatspecs, seektoend, returnfp)
    if(IsNestedDict(formatspecs) and fmttype in formatspecs):
        formatspecs = formatspecs[fmttype]
    elif(IsNestedDict(formatspecs) and fmttype not in formatspecs):
        fmttype = __file_format_default__
        formatspecs = formatspecs[fmttype]
        if(IsNestedDict(formatspecs) and fmttype in formatspecs):
            formatspecs = formatspecs[fmttype]
        elif(IsNestedDict(formatspecs) and fmttype not in formatspecs):
            fmttype = __file_format_default__
            formatspecs = formatspecs[fmttype]
    if(outfile != "-" and not isinstance(infile, bytes) and not hasattr(infile, "read") and not hasattr(outfile, "write")):
        outfile = RemoveWindowsPath(outfile)
    if(not compression or compression == formatspecs['format_magic']):
        compression = "auto"
    if(compression not in compressionuselist and compression is None):
        compression = "auto"
    if(verbose):
        logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG)
    if(outfile != "-" and outfile is not None and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
        if(os.path.exists(outfile)):
            try:
                os.unlink(outfile)
            except OSError:
                pass
    if(not listarrayfiles):
        return False
    if(outfile == "-" or outfile is None):
        verbose = False
        fp = MkTempFile()
    elif(hasattr(outfile, "read") or hasattr(outfile, "write")):
        fp = outfile
    elif(re.findall(__upload_proto_support__, outfile)):
        fp = MkTempFile()
    else:
        fbasename = os.path.splitext(outfile)[0]
        fextname = os.path.splitext(outfile)[1]
        if(not compresswholefile and fextname in outextlistwd):
            compresswholefile = True
        try:
            fp = CompressOpenFile(outfile, compresswholefile, compressionlevel)
        except PermissionError:
            return False
    formver = formatspecs['format_ver']
    fileheaderver = str(int(formver.replace(".", "")))
    lenlist = len(listarrayfiles['ffilelist'])
    fnumfiles = int(listarrayfiles['fnumfiles'])
    if(lenlist > fnumfiles or lenlist < fnumfiles):
        fnumfiles = lenlist
    AppendFileHeader(fp, fnumfiles, listarrayfiles['fencoding'], [], checksumtype[0], formatspecs)
    lenlist = len(listarrayfiles['ffilelist'])
    fnumfiles = int(listarrayfiles['fnumfiles'])
    lcfi = 0
    lcfx = int(listarrayfiles['fnumfiles'])
    if(lenlist > listarrayfiles['fnumfiles'] or lenlist < listarrayfiles['fnumfiles']):
        lcfx = int(lenlist)
    else:
        lcfx = int(listarrayfiles['fnumfiles'])
    curinode = 0
    curfid = 0
    inodelist = []
    inodetofile = {}
    filetoinode = {}
    reallcfi = 0
    while(lcfi < lcfx):
        fencoding = listarrayfiles['ffilelist'][reallcfi]['fencoding']
        fcencoding = listarrayfiles['ffilelist'][reallcfi]['fencoding']
        if(re.findall("^[.|/]", listarrayfiles['ffilelist'][reallcfi]['fname'])):
            fname = listarrayfiles['ffilelist'][reallcfi]['fname']
        else:
            fname = "./"+listarrayfiles['ffilelist'][reallcfi]['fname']
        if(verbose):
            VerbosePrintOut(fname)
        fheadersize = format(
            int(listarrayfiles['ffilelist'][reallcfi]['fheadersize']), 'x').lower()
        fsize = format(
            int(listarrayfiles['ffilelist'][reallcfi]['fsize']), 'x').lower()
        flinkname = listarrayfiles['ffilelist'][reallcfi]['flinkname']
        fatime = format(
            int(listarrayfiles['ffilelist'][reallcfi]['fatime']), 'x').lower()
        fmtime = format(
            int(listarrayfiles['ffilelist'][reallcfi]['fmtime']), 'x').lower()
        fctime = format(
            int(listarrayfiles['ffilelist'][reallcfi]['fctime']), 'x').lower()
        fbtime = format(
            int(listarrayfiles['ffilelist'][reallcfi]['fbtime']), 'x').lower()
        fmode = format(
            int(listarrayfiles['ffilelist'][reallcfi]['fmode']), 'x').lower()
        fchmode = format(
            int(listarrayfiles['ffilelist'][reallcfi]['fchmode']), 'x').lower()
        fuid = format(
            int(listarrayfiles['ffilelist'][reallcfi]['fuid']), 'x').lower()
        funame = listarrayfiles['ffilelist'][reallcfi]['funame']
        fgid = format(
            int(listarrayfiles['ffilelist'][reallcfi]['fgid']), 'x').lower()
        fgname = listarrayfiles['ffilelist'][reallcfi]['fgname']
        finode = format(
            int(listarrayfiles['ffilelist'][reallcfi]['finode']), 'x').lower()
        flinkcount = format(
            int(listarrayfiles['ffilelist'][reallcfi]['flinkcount']), 'x').lower()
        fwinattributes = format(
            int(listarrayfiles['ffilelist'][reallcfi]['fwinattributes']), 'x').lower()
        fcompression = listarrayfiles['ffilelist'][reallcfi]['fcompression']
        fcsize = format(
            int(listarrayfiles['ffilelist'][reallcfi]['fcsize']), 'x').lower()
        fdev = format(
            int(listarrayfiles['ffilelist'][reallcfi]['fdev']), 'x').lower()
        fdev_minor = format(
            int(listarrayfiles['ffilelist'][reallcfi]['fminor']), 'x').lower()
        fdev_major = format(
            int(listarrayfiles['ffilelist'][reallcfi]['fmajor']), 'x').lower()
        fseeknextfile = listarrayfiles['ffilelist'][reallcfi]['fseeknextfile']
        if(len(listarrayfiles['ffilelist'][reallcfi]['fextradata']) > listarrayfiles['ffilelist'][reallcfi]['fextrafields'] and len(listarrayfiles['ffilelist'][reallcfi]['fextradata']) > 0):
            listarrayfiles['ffilelist'][reallcfi]['fextrafields'] = len(
                listarrayfiles['ffilelist'][reallcfi]['fextradata'])
        if(not followlink and len(extradata) <= 0):
            extradata = listarrayfiles['ffilelist'][reallcfi]['fextradata']
        if(not followlink and len(jsondata) <= 0):
            jsondata = listarrayfiles['ffilelist'][reallcfi]['fjsondata']
        fcontents = listarrayfiles['ffilelist'][reallcfi]['fcontents']
        if(not listarrayfiles['ffilelist'][reallcfi]['fcontentasfile']):
            fcontents = MkTempFile(fcontents)
        typechecktest = CheckCompressionType(fcontents, filestart=0, closefp=False)
        fcontents.seek(0, 0)
        fcencoding = GetFileEncoding(fcontents, 0, False)
        fcompression = ""
        fcsize = format(int(0), 'x').lower()
        curcompression = "none"
        if typechecktest is False and not compresswholefile:
            fcontents.seek(0, 2)
            ucfsize = fcontents.tell()
            fcontents.seek(0, 0)
            if(compression == "auto"):
                ilsize = len(compressionuselist)
                ilmin = 0
                ilcsize = []
                while(ilmin < ilsize):
                    cfcontents = MkTempFile()
                    fcontents.seek(0, 0)
                    shutil.copyfileobj(fcontents, cfcontents)
                    fcontents.seek(0, 0)
                    cfcontents.seek(0, 0)
                    cfcontents = CompressOpenFileAlt(
                        cfcontents, compressionuselist[ilmin], compressionlevel, compressionuselist, formatspecs)
                    if(cfcontents):
                        cfcontents.seek(0, 2)
                        ilcsize.append(cfcontents.tell())
                        cfcontents.close()
                    else:
                        ilcsize.append(float("inf"))
                    ilmin = ilmin + 1
                ilcmin = ilcsize.index(min(ilcsize))
                curcompression = compressionuselist[ilcmin]
            fcontents.seek(0, 0)
            cfcontents = MkTempFile()
            shutil.copyfileobj(fcontents, cfcontents)
            cfcontents.seek(0, 0)
            cfcontents = CompressOpenFileAlt(
                cfcontents, curcompression, compressionlevel, compressionuselist, formatspecs)
            cfcontents.seek(0, 2)
            cfsize = cfcontents.tell()
            if(ucfsize > cfsize):
                fcsize = format(int(cfsize), 'x').lower()
                fcompression = curcompression
                fcontents.close()
                fcontents = cfcontents
        if followlink:
            if(listarrayfiles['ffilelist'][reallcfi]['ftype'] == 1 or listarrayfiles['ffilelist'][reallcfi]['ftype'] == 2):
                getflinkpath = listarrayfiles['ffilelist'][reallcfi]['flinkname']
                flinkid = prelistarrayfiles['filetoid'][getflinkpath]
                flinkinfo = listarrayfiles['ffilelist'][flinkid]
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
                if(len(flinkinfo['fextradata']) > flinkinfo['fextrafields'] and len(flinkinfo['fextradata']) > 0):
                    flinkinfo['fextrafields'] = len(flinkinfo['fextradata'])
                if(len(extradata) < 0):
                    extradata = flinkinfo['fextradata']
                if(len(jsondata) < 0):
                    extradata = flinkinfo['fjsondata']
                fcontents = flinkinfo['fcontents']
                if(not flinkinfo['fcontentasfile']):
                    fcontents = MkTempFile(fcontents)
                ftypehex = format(flinkinfo['ftype'], 'x').lower()
        else:
            ftypehex = format(
                listarrayfiles['ffilelist'][reallcfi]['ftype'], 'x').lower()
        fcurfid = format(curfid, 'x').lower()
        if(not followlink and finode != 0):
            if(listarrayfiles['ffilelist'][reallcfi]['ftype'] != 1):
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
        tmpoutlist = [ftypehex, fencoding, fcencoding, fname, flinkname, fsize, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression, fcsize,
                      fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev, fdev_minor, fdev_major, fseeknextfile]
        AppendFileHeaderWithContent(
            fp, tmpoutlist, extradata, jsondata, fcontents.read(), [checksumtype[1], checksumtype[2], checksumtype[3]], formatspecs)
        fcontents.close()
        lcfi = lcfi + 1
        reallcfi = reallcfi + 1
    if(outfile == "-" or outfile is None or hasattr(outfile, "read") or hasattr(outfile, "write")):
        fp = CompressOpenFileAlt(
            fp, compression, compressionlevel, compressionuselist, formatspecs)
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
    elif((not hasattr(outfile, "read") and not hasattr(outfile, "write")) and re.findall(__upload_proto_support__, outfile)):
        fp = CompressOpenFileAlt(
            fp, compression, compressionlevel, compressionuselist, formatspecs)
        fp.seek(0, 0)
        upload_file_to_internet_file(fp, outfile)
    if(returnfp):
        fp.seek(0, 0)
        return fp
    else:
        fp.close()
        return True


def RePackCatFileFromString(instr, outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, followlink=False, filestart=0, seekstart=0, seekend=0, checksumtype=["crc32", "crc32", "crc32"], skipchecksum=False, extradata=[], jsondata={}, formatspecs=__file_format_dict__, seektoend=False, verbose=False, returnfp=False):
    fp = MkTempFile(instr)
    listarrayfiles = RePackCatFile(fp, outfile, fmttype, compression, compresswholefile, compressionlevel, compressionuselist, followlink, filestart, seekstart, seekend,
                                     checksumtype, skipchecksum, extradata, jsondata, formatspecs, seektoend, verbose, returnfp)
    return listarrayfiles


def PackCatFileFromListDir(infiles, outfile, dirlistfromtxt=False, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, followlink=False, filestart=0, seekstart=0, seekend=0, checksumtype=["crc32", "crc32", "crc32"], skipchecksum=False, extradata=[], jsondata={}, formatspecs=__file_format_dict__, seektoend=False, verbose=False, returnfp=False):
    outarray = MkTempFile()
    packform = PackCatFile(infiles, outarray, dirlistfromtxt, fmttype, compression, compresswholefile,
                              compressionlevel, compressionuselist, followlink, checksumtype, extradata, formatspecs, verbose, True)
    listarrayfiles = RePackCatFile(outarray, outfile, fmttype, compression, compresswholefile, compressionlevel, compressionuselist, followlink, filestart, seekstart, seekend,
                                     checksumtype, skipchecksum, extradata, jsondata, formatspecs, seektoend, verbose, returnfp)
    return listarrayfiles


def UnPackCatFile(infile, outdir=None, followlink=False, filestart=0, seekstart=0, seekend=0, skipchecksum=False, formatspecs=__file_format_multi_dict__, preservepermissions=True, preservetime=True, seektoend=False, verbose=False, returnfp=False):
    if(outdir is not None):
        outdir = RemoveWindowsPath(outdir)
    if(verbose):
        logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG)
    if(isinstance(infile, dict)):
        listarrayfiles = infile
    else:
        if(infile != "-" and not hasattr(infile, "read") and not hasattr(infile, "write") and not (sys.version_info[0] >= 3 and isinstance(infile, bytes))):
            infile = RemoveWindowsPath(infile)
        listarrayfiles = CatFileToArray(infile, "auto", filestart, seekstart, seekend, False, True, True, skipchecksum, formatspecs, seektoend, returnfp)
    if(not listarrayfiles):
        return False
    lenlist = len(listarrayfiles['ffilelist'])
    fnumfiles = int(listarrayfiles['fnumfiles'])
    lcfi = 0
    lcfx = int(listarrayfiles['fnumfiles'])
    if(lenlist > listarrayfiles['fnumfiles'] or lenlist < listarrayfiles['fnumfiles']):
        lcfx = int(lenlist)
    else:
        lcfx = int(listarrayfiles['fnumfiles'])
    while(lcfi < lcfx):
        funame = ""
        try:
            import pwd
            try:
                userinfo = pwd.getpwuid(
                    listarrayfiles['ffilelist'][lcfi]['fuid'])
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
                    listarrayfiles['ffilelist'][lcfi]['fgid'])
                fgname = groupinfo.gr_name
            except KeyError:
                fgname = ""
        except ImportError:
            fgname = ""
        if(verbose):
            VerbosePrintOut(PrependPath(
                outdir, listarrayfiles['ffilelist'][lcfi]['fname']))
        if(listarrayfiles['ffilelist'][lcfi]['ftype'] == 0 or listarrayfiles['ffilelist'][lcfi]['ftype'] == 7):
            with open(PrependPath(outdir, listarrayfiles['ffilelist'][lcfi]['fname']), "wb") as fpc:
                if(not listarrayfiles['ffilelist'][lcfi]['fcontentasfile']):
                    listarrayfiles['ffilelist'][lcfi]['fcontents'] = MkTempFile(
                        listarrayfiles['ffilelist'][lcfi]['fcontents'])
                listarrayfiles['ffilelist'][lcfi]['fcontents'].seek(0, 0)
                shutil.copyfileobj(
                    listarrayfiles['ffilelist'][lcfi]['fcontents'], fpc)
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
            if(hasattr(os, "chown") and funame == listarrayfiles['ffilelist'][lcfi]['funame'] and fgname == listarrayfiles['ffilelist'][lcfi]['fgname'] and preservepermissions):
                os.chown(PrependPath(outdir, listarrayfiles['ffilelist'][lcfi]['fname']),
                         listarrayfiles['ffilelist'][lcfi]['fuid'], listarrayfiles['ffilelist'][lcfi]['fgid'])
            if(preservepermissions):
                os.chmod(PrependPath(
                    outdir, listarrayfiles['ffilelist'][lcfi]['fname']), listarrayfiles['ffilelist'][lcfi]['fchmode'])
            if(preservetime):
                os.utime(PrependPath(outdir, listarrayfiles['ffilelist'][lcfi]['fname']), (
                    listarrayfiles['ffilelist'][lcfi]['fatime'], listarrayfiles['ffilelist'][lcfi]['fmtime']))
        if(listarrayfiles['ffilelist'][lcfi]['ftype'] == 1):
            if(followlink):
                getflinkpath = listarrayfiles['ffilelist'][lcfi]['flinkname']
                flinkid = prelistarrayfiles['filetoid'][getflinkpath]
                flinkinfo = listarrayfiles['ffilelist'][flinkid]
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
                    with open(PrependPath(outdir, listarrayfiles['ffilelist'][lcfi]['fname']), "wb") as fpc:
                        if(not flinkinfo['fcontentasfile']):
                            flinkinfo['fcontents'] = MkTempFile(
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
                            outdir, listarrayfiles['ffilelist'][lcfi]['fname']), flinkinfo['fuid'], flinkinfo['fgid'])
                    if(preservepermissions):
                        os.chmod(PrependPath(
                            outdir, listarrayfiles['ffilelist'][lcfi]['fname']), flinkinfo['fchmode'])
                    if(preservetime):
                        os.utime(PrependPath(outdir, listarrayfiles['ffilelist'][lcfi]['fname']), (
                            flinkinfo['fatime'], flinkinfo['fmtime']))
                if(flinkinfo['ftype'] == 1):
                    os.link(flinkinfo['flinkname'], PrependPath(
                        outdir, listarrayfiles['ffilelist'][lcfi]['fname']))
                if(flinkinfo['ftype'] == 2):
                    os.symlink(flinkinfo['flinkname'], PrependPath(
                        outdir, listarrayfiles['ffilelist'][lcfi]['fname']))
                if(flinkinfo['ftype'] == 5):
                    if(preservepermissions):
                        os.mkdir(PrependPath(
                            outdir, listarrayfiles['ffilelist'][lcfi]['fname']), flinkinfo['fchmode'])
                    else:
                        os.mkdir(PrependPath(
                            outdir, listarrayfiles['ffilelist'][lcfi]['fname']))
                    if(hasattr(os, "chown") and funame == flinkinfo['funame'] and fgname == flinkinfo['fgname'] and preservepermissions):
                        os.chown(PrependPath(
                            outdir, listarrayfiles['ffilelist'][lcfi]['fname']), flinkinfo['fuid'], flinkinfo['fgid'])
                    if(preservepermissions):
                        os.chmod(PrependPath(
                            outdir, listarrayfiles['ffilelist'][lcfi]['fname']), flinkinfo['fchmode'])
                    if(preservetime):
                        os.utime(PrependPath(outdir, listarrayfiles['ffilelist'][lcfi]['fname']), (
                            flinkinfo['fatime'], flinkinfo['fmtime']))
                if(flinkinfo['ftype'] == 6 and hasattr(os, "mkfifo")):
                    os.mkfifo(PrependPath(
                        outdir, listarrayfiles['ffilelist'][lcfi]['fname']), flinkinfo['fchmode'])
            else:
                os.link(listarrayfiles['ffilelist'][lcfi]['flinkname'], PrependPath(
                    outdir, listarrayfiles['ffilelist'][lcfi]['fname']))
        if(listarrayfiles['ffilelist'][lcfi]['ftype'] == 2):
            if(followlink):
                getflinkpath = listarrayfiles['ffilelist'][lcfi]['flinkname']
                flinkid = prelistarrayfiles['filetoid'][getflinkpath]
                flinkinfo = listarrayfiles['ffilelist'][flinkid]
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
                    with open(PrependPath(outdir, listarrayfiles['ffilelist'][lcfi]['fname']), "wb") as fpc:
                        if(not flinkinfo['fcontentasfile']):
                            flinkinfo['fcontents'] = MkTempFile(
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
                            outdir, listarrayfiles['ffilelist'][lcfi]['fname']), flinkinfo['fuid'], flinkinfo['fgid'])
                    if(preservepermissions):
                        os.chmod(PrependPath(
                            outdir, listarrayfiles['ffilelist'][lcfi]['fname']), flinkinfo['fchmode'])
                    if(preservetime):
                        os.utime(PrependPath(outdir, listarrayfiles['ffilelist'][lcfi]['fname']), (
                            flinkinfo['fatime'], flinkinfo['fmtime']))
                if(flinkinfo['ftype'] == 1):
                    os.link(flinkinfo['flinkname'], PrependPath(
                        outdir, listarrayfiles['ffilelist'][lcfi]['fname']))
                if(flinkinfo['ftype'] == 2):
                    os.symlink(flinkinfo['flinkname'], PrependPath(
                        outdir, listarrayfiles['ffilelist'][lcfi]['fname']))
                if(flinkinfo['ftype'] == 5):
                    if(preservepermissions):
                        os.mkdir(PrependPath(
                            outdir, listarrayfiles['ffilelist'][lcfi]['fname']), flinkinfo['fchmode'])
                    else:
                        os.mkdir(PrependPath(
                            outdir, listarrayfiles['ffilelist'][lcfi]['fname']))
                    if(hasattr(os, "chown") and funame == flinkinfo['funame'] and fgname == flinkinfo['fgname'] and preservepermissions):
                        os.chown(PrependPath(
                            outdir, listarrayfiles['ffilelist'][lcfi]['fname']), flinkinfo['fuid'], flinkinfo['fgid'])
                    if(preservepermissions):
                        os.chmod(PrependPath(
                            outdir, listarrayfiles['ffilelist'][lcfi]['fname']), flinkinfo['fchmode'])
                    if(preservetime):
                        os.utime(PrependPath(outdir, listarrayfiles['ffilelist'][lcfi]['fname']), (
                            flinkinfo['fatime'], flinkinfo['fmtime']))
                if(flinkinfo['ftype'] == 6 and hasattr(os, "mkfifo")):
                    os.mkfifo(PrependPath(
                        outdir, listarrayfiles['ffilelist'][lcfi]['fname']), flinkinfo['fchmode'])
            else:
                os.symlink(listarrayfiles['ffilelist'][lcfi]['flinkname'], PrependPath(
                    outdir, listarrayfiles['ffilelist'][lcfi]['fname']))
        if(listarrayfiles['ffilelist'][lcfi]['ftype'] == 5):
            if(preservepermissions):
                os.mkdir(PrependPath(
                    outdir, listarrayfiles['ffilelist'][lcfi]['fname']), listarrayfiles['ffilelist'][lcfi]['fchmode'])
            else:
                os.mkdir(PrependPath(
                    outdir, listarrayfiles['ffilelist'][lcfi]['fname']))
            if(hasattr(os, "chown") and funame == listarrayfiles['ffilelist'][lcfi]['funame'] and fgname == listarrayfiles['ffilelist'][lcfi]['fgname'] and preservepermissions):
                os.chown(PrependPath(outdir, listarrayfiles['ffilelist'][lcfi]['fname']),
                         listarrayfiles['ffilelist'][lcfi]['fuid'], listarrayfiles['ffilelist'][lcfi]['fgid'])
            if(preservepermissions):
                os.chmod(PrependPath(
                    outdir, listarrayfiles['ffilelist'][lcfi]['fname']), listarrayfiles['ffilelist'][lcfi]['fchmode'])
            if(preservetime):
                os.utime(PrependPath(outdir, listarrayfiles['ffilelist'][lcfi]['fname']), (
                    listarrayfiles['ffilelist'][lcfi]['fatime'], listarrayfiles['ffilelist'][lcfi]['fmtime']))
        if(listarrayfiles['ffilelist'][lcfi]['ftype'] == 6 and hasattr(os, "mkfifo")):
            os.mkfifo(PrependPath(
                outdir, listarrayfiles['ffilelist'][lcfi]['fname']), listarrayfiles['ffilelist'][lcfi]['fchmode'])
        lcfi = lcfi + 1
    if(returnfp):
        return listarrayfiles['ffilelist']['fp']
    else:
        return True


def UnPackCatFileString(instr, outdir=None, followlink=False, filestart=0, seekstart=0, seekend=0, skipchecksum=False, formatspecs=__file_format_multi_dict__, seektoend=False, verbose=False, returnfp=False):
    fp = MkTempFile(instr)
    listarrayfiles = UnPackCatFile(fp, outdir, followlink, filestart, seekstart, seekend, skipchecksum, formatspecs, seektoend, verbose, returnfp)
    return listarrayfiles

def ftype_to_str(ftype):
    mapping = {
        0: "file",   # file
        1: "link",   # link
        2: "sym",    # symlink
        3: "cdev",   # char device
        4: "bdev",   # block device
        5: "dir",    # directory
        6: "fifo",   # fifo
        12: "spar",  # sparse
        14: "dev",   # generic device
    }
    # Default to "file" if unknown
    return mapping.get(ftype, "file")

def CatFileListFiles(infile, fmttype="auto", filestart=0, seekstart=0, seekend=0, skipchecksum=False, formatspecs=__file_format_multi_dict__, seektoend=False, verbose=False, newstyle=False, returnfp=False):
    if(verbose):
        logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG)
    if(isinstance(infile, dict)):
        listarrayfiles = infile
    else:
        if(infile != "-" and not hasattr(infile, "read") and not hasattr(infile, "write") and not (sys.version_info[0] >= 3 and isinstance(infile, bytes))):
            infile = RemoveWindowsPath(infile)
        listarrayfiles = CatFileToArray(infile, fmttype, filestart, seekstart, seekend, True, False, False, skipchecksum, formatspecs, seektoend, returnfp)
    if(not listarrayfiles):
        return False
    lenlist = len(listarrayfiles['ffilelist'])
    fnumfiles = int(listarrayfiles['fnumfiles'])
    lcfi = 0
    lcfx = int(listarrayfiles['fnumfiles'])
    if(lenlist > listarrayfiles['fnumfiles'] or lenlist < listarrayfiles['fnumfiles']):
        lcfx = int(lenlist)
    else:
        lcfx = int(listarrayfiles['fnumfiles'])
    returnval = {}
    while(lcfi < lcfx):
        returnval.update({lcfi: listarrayfiles['ffilelist'][lcfi]['fname']})
        if(not verbose):
            VerbosePrintOut(listarrayfiles['ffilelist'][lcfi]['fname'])
        if(verbose):
            permissions = {'access': {'0': ('---'), '1': ('--x'), '2': ('-w-'), '3': ('-wx'), '4': (
                'r--'), '5': ('r-x'), '6': ('rw-'), '7': ('rwx')}, 'roles': {0: 'owner', 1: 'group', 2: 'other'}}
            printfname = listarrayfiles['ffilelist'][lcfi]['fname']
            if(listarrayfiles['ffilelist'][lcfi]['ftype'] == 1):
                printfname = listarrayfiles['ffilelist'][lcfi]['fname'] + \
                    " link to " + listarrayfiles['ffilelist'][lcfi]['flinkname']
            if(listarrayfiles['ffilelist'][lcfi]['ftype'] == 2):
                printfname = listarrayfiles['ffilelist'][lcfi]['fname'] + \
                    " -> " + listarrayfiles['ffilelist'][lcfi]['flinkname']
            fuprint = listarrayfiles['ffilelist'][lcfi]['funame']
            if(len(fuprint) <= 0):
                fuprint = listarrayfiles['ffilelist'][lcfi]['fuid']
            fgprint = listarrayfiles['ffilelist'][lcfi]['fgname']
            if(len(fgprint) <= 0):
                fgprint = listarrayfiles['ffilelist'][lcfi]['fgid']
            if(newstyle):
                VerbosePrintOut(ftype_to_str(listarrayfiles['ffilelist'][lcfi]['ftype']) + "\t" + listarrayfiles['ffilelist'][lcfi]['fcompression'] + "\t" + str(
                listarrayfiles['ffilelist'][lcfi]['fsize']).rjust(15) + "\t" + printfname)
            else:
                VerbosePrintOut(PrintPermissionString(listarrayfiles['ffilelist'][lcfi]['fmode'], listarrayfiles['ffilelist'][lcfi]['ftype']) + " " + str(fuprint) + "/" + str(fgprint) + " " + str(
                listarrayfiles['ffilelist'][lcfi]['fsize']).rjust(15) + " " + datetime.datetime.utcfromtimestamp(listarrayfiles['ffilelist'][lcfi]['fmtime']).strftime('%Y-%m-%d %H:%M') + " " + printfname)
        lcfi = lcfi + 1
    if(returnfp):
        return listarrayfiles['fp']
    else:
        return True


def MultipleCatFileListFiles(infile, fmttype="auto", filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_multi_dict__, seektoend=False, returnfp=False):
    if(isinstance(infile, (list, tuple, ))):
        pass
    else:
        infile = [infile]
    outretval = {}
    for curfname in infile:
        outretval[curfname] = CatFileListFiles(infile, fmttype, filestart, seekstart, seekend, skipchecksum, formatspecs, seektoend, verbose, newstyle, returnfp)
    return outretval


def StackedCatFileValidate(infile, fmttype="auto", filestart=0, formatspecs=__file_format_multi_dict__, seektoend=False, verbose=False, returnfp=False):
    outretval = []
    outstartfile = filestart
    outfsize = float('inf')
    while True:
        if outstartfile >= outfsize:   # stop when function signals False
            break
        is_valid_file = CatFileValidate(infile, fmttype, filestart, formatspecs, seektoend, verbose, True)
        if is_valid_file is False:   # stop when function signals False
            outretval.append(is_valid_file)
        else:
            outretval.append(True)
        infile = is_valid_file
        outstartfile = infile.tell()
        try:
            infile.seek(0, 2)
        except OSError:
            SeekToEndOfFile(infile)
        except ValueError:
            SeekToEndOfFile(infile)
        outfsize = infile.tell()
        infile.seek(outstartfile, 0)
    if(returnfp):
        return infile
    else:
        infile.close()
        return outretval


def StackedCatFileListFiles(infile, fmttype="auto", filestart=0, seekstart=0, seekend=0, skipchecksum=False, formatspecs=__file_format_multi_dict__, seektoend=False, verbose=False, newstyle=False, returnfp=False):
    outretval = []
    outstartfile = filestart
    outfsize = float('inf')
    while True:
        if outstartfile >= outfsize:   # stop when function signals False
            break
        list_file_retu = CatFileListFiles(infile, fmttype, outstartfile, seekstart, seekend, skipchecksum, formatspecs, seektoend, verbose, newstyle, True)
        if list_file_retu is False:   # stop when function signals False
            outretval.append(list_file_retu)
        else:
            outretval.append(True)
        infile = list_file_retu
        outstartfile = infile.tell()
        try:
            infile.seek(0, 2)
        except OSError:
            SeekToEndOfFile(infile)
        except ValueError:
            SeekToEndOfFile(infile)
        outfsize = infile.tell()
        infile.seek(outstartfile, 0)
    if(returnfp):
        return infile
    else:
        infile.close()
        return outretval


def MultipleStackedCatFileListFiles(infile, fmttype="auto", filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_multi_dict__, seektoend=False, returnfp=False):
    if(isinstance(infile, (list, tuple, ))):
        pass
    else:
        infile = [infile]
    outretval = {}
    for curfname in infile:
        outretval[curfname] = StackedCatFileListFiles(curfname, fmttype, filestart, seekstart, seekend, listonly, contentasfile, uncompress, skipchecksum, formatspecs, seektoend, returnfp)
    return outretval


def CatFileStringListFiles(instr, filestart=0, seekstart=0, seekend=0, skipchecksum=False, formatspecs=__file_format_multi_dict__, seektoend=False, verbose=False, newstyle=False, returnfp=False):
    fp = MkTempFile(instr)
    listarrayfiles = CatFileListFiles(instr, "auto", filestart, seekstart, seekend, skipchecksum, formatspecs, seektoend, verbose, newstyle, returnfp)
    return listarrayfiles


def TarFileListFiles(infile, verbose=False, returnfp=False):
    if(verbose):
        logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG)
    if(infile == "-"):
        infile = MkTempFile()
        if(hasattr(sys.stdin, "buffer")):
            shutil.copyfileobj(sys.stdin.buffer, infile)
        else:
            shutil.copyfileobj(sys.stdin, infile)
        infile.seek(0, 0)
        if(not infile):
            return False
        infile.seek(0, 0)
    elif(re.findall(__download_proto_support__, infile)):
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
            compresscheck = CheckCompressionType(infile, formatspecs, 0, False)
            if(IsNestedDict(formatspecs) and compresscheck in formatspecs):
                formatspecs = formatspecs[compresscheck]
            if(compresscheck=="zstd"):
                if 'zstandard' in sys.modules:
                    infile = ZstdFile(fileobj=infile, mode="rb")
                elif 'pyzstd' in sys.modules:
                    infile = pyzstd.zstdfile.ZstdFile(fileobj=infile, mode="rb")
                tarfp = tarfile.open(fileobj=infile, mode="r")
            else:
                tarfp = tarfile.open(fileobj=infile, mode="r")
        else:
            compresscheck = CheckCompressionType(infile, formatspecs, 0, True)
            if(IsNestedDict(formatspecs) and compresscheck in formatspecs):
                formatspecs = formatspecs[compresscheck]
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
        return listarrayfiles['fp']
    else:
        return True


def ZipFileListFiles(infile, verbose=False, returnfp=False):
    if(verbose):
        logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG)
    if(infile == "-"):
        infile = MkTempFile()
        if(hasattr(sys.stdin, "buffer")):
            shutil.copyfileobj(sys.stdin.buffer, infile)
        else:
            shutil.copyfileobj(sys.stdin, infile)
        infile.seek(0, 0)
        if(not infile):
            return False
        infile.seek(0, 0)
    elif(re.findall(__download_proto_support__, infile)):
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
        return listarrayfiles['fp']
    else:
        return True


if(not rarfile_support):
    def RarFileListFiles(infile, verbose=False, returnfp=False):
        return False

if(rarfile_support):
    def RarFileListFiles(infile, verbose=False, returnfp=False):
        if(verbose):
            logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG)
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
            return listarrayfiles['fp']
        else:
            return True

if(not py7zr_support):
    def SevenZipFileListFiles(infile, verbose=False, returnfp=False):
        return False

if(py7zr_support):
    def SevenZipFileListFiles(infile, verbose=False, returnfp=False):
        if(verbose):
            logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG)
        if(not os.path.exists(infile) or not os.path.isfile(infile)):
            return False
        lcfi = 0
        returnval = {}
        szpfp = py7zr.SevenZipFile(infile, mode="r")
        file_content = szpfp.readall()
        #sztest = szpfp.testzip()
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
            return listarrayfiles['fp']
        else:
            return True


def InFileListFiles(infile, verbose=False, formatspecs=__file_format_multi_dict__, seektoend=False, newstyle=False, returnfp=False):
    if(verbose):
        logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG)
    checkcompressfile = CheckCompressionSubType(infile, formatspecs, filestart, True)
    if(IsNestedDict(formatspecs) and checkcompressfile in formatspecs):
        formatspecs = formatspecs[checkcompressfile]
    if(checkcompressfile == "tarfile" and TarFileCheck(infile)):
        return TarFileListFiles(infile, verbose, returnfp)
    elif(checkcompressfile == "zipfile" and zipfile.is_zipfile(infile)):
        return ZipFileListFiles(infile, verbose, returnfp)
    elif(rarfile_support and checkcompressfile == "rarfile" and (rarfile.is_rarfile(infile) or rarfile.is_rarfile_sfx(infile))):
        return RarFileListFiles(infile, verbose, returnfp)
    elif(py7zr_support and checkcompressfile == "7zipfile" and py7zr.is_7zfile(infile)):
        return SevenZipFileListFiles(infile, verbose, returnfp)
    elif(checkcompressfile == formatspecs['format_magic']):
        return CatFileListFiles(infile, 0, 0, False, formatspecs, seektoend, verbose, newstyle, returnfp)
    else:
        return False
    return False


def ListDirListFiles(infiles, dirlistfromtxt=False, compression="auto", compresswholefile=True, compressionlevel=None, followlink=False, seekstart=0, seekend=0, skipchecksum=False, checksumtype=["crc32", "crc32", "crc32"], formatspecs=__file_format_dict__, seektoend=False, verbose=False, returnfp=False):
    outarray = MkTempFile()
    packform = PackCatFile(infiles, outarray, dirlistfromtxt, compression, compresswholefile,
                              compressionlevel, followlink, checksumtype, formatspecs, False, True)
    listarrayfiles = CatFileListFiles(
        outarray, seekstart, seekend, skipchecksum, formatspecs, seektoend, verbose, returnfp)
    return listarrayfiles

"""
PyNeoFile compatibility layer
"""

def make_empty_file_pointer_neo(fp, fmttype=None, checksumtype='crc32', formatspecs=__file_format_multi_dict__, encoding='UTF-8'):
    return MakeEmptyFilePointer(fp, fmttype, checksumtype, formatspecs)

def make_empty_archive_file_pointer_neo(fp, fmttype=None, checksumtype='crc32', formatspecs=__file_format_multi_dict__, encoding='UTF-8'):
    return make_empty_file_pointer_neo(fp, fmttype, checksumtype, formatspecs, encoding)

def make_empty_file_neo(outfile=None, fmttype=None, checksumtype='crc32', formatspecs=__file_format_multi_dict__, encoding='UTF-8', returnfp=False):
    return MakeEmptyFile(outfile, fmttype, "auto", False, None, compressionlistalt, checksumtype, formatspecs, returnfp)

def make_empty_archive_file_neo(outfile=None, fmttype=None, checksumtype='crc32', formatspecs=__file_format_multi_dict__, encoding='UTF-8', returnfp=False):
    return make_empty_file_neo(outfile, fmttype, checksumtype, formatspecs, encoding, returnfp)

def pack_neo(infiles, outfile=None, formatspecs=__file_format_multi_dict__, checksumtypes=["crc32", "crc32", "crc32", "crc32"], encoding="UTF-8", compression="auto", compression_level=None, returnfp=False):
    return PackCatFile(infiles, outfile, False, "auto", compression, False, compression_level, compressionlistalt, False, checksumtypes, [], {}, formatspecs, False, returnfp)

def archive_to_array_neo(infile, formatspecs=__file_format_multi_dict__, listonly=False, skipchecksum=False, uncompress=True, returnfp=False):
    return CatFileToArray(infile, "auto", 0, 0, 0, listonly, True, uncompress, skipchecksum, formatspecs, False, returnfp)

def unpack_neo(infile, outdir='.', formatspecs=__file_format_multi_dict__, skipchecksum=False, uncompress=True, returnfp=False):
    return UnPackCatFile(infile, outdir, False, 0, 0, skipchecksum, formatspecs, True, True, False, False, returnfp)

def repack_neo(infile, outfile=None, formatspecs=__file_format_dict__, checksumtypes=["crc32", "crc32", "crc32", "crc32"], compression="auto", compression_level=None, returnfp=False):
    return RePackCatFile(infile, outfile, "auto", compression, False, compression_level, compressionlistalt, False, 0, 0, checksumtypes, False, [], {}, formatspecs, False, False, returnfp)

def validate_neo(infile, formatspecs=__file_format_multi_dict__, verbose=False, return_details=False, returnfp=False):
    return CatFileValidate(infile, "auto", formatspecs, False, verbose, returnfp)

def listfiles_neo(infile, formatspecs=__file_format_multi_dict__, advanced=False, include_dirs=True, returnfp=False):
    return CatFileListFiles(infile, "auto", 0, 0, False, formatspecs, False, True, advanced, returnfp)

def convert_foreign_to_neo(infile, outfile=None, formatspecs=__file_format_multi_dict__, checksumtypes=["crc32", "crc32", "crc32", "crc32"], compression="auto", compression_level=None, returnfp=False):
    intmp = InFileToArray(infile, 0, 0, 0, False, True, False, formatspecs, False, False)
    return RePackCatFile(intmp, outfile, "auto", compression, False, compression_level, compressionlistalt, False, 0, 0, checksumtypes, False, [], {}, formatspecs, False, False, returnfp)

def detect_cwd(ftp, file_dir):
    """
    Test whether cwd into file_dir works. Returns True if it does,
    False if not (so absolute paths should be used).
    """
    if not file_dir or file_dir in ("/", ""):
        return False  # nothing to cwd into
    try:
        ftp.cwd(file_dir)
        return True
    except all_errors:
        return False

def download_file_from_ftp_file(url):
    urlparts = urlparse(url)
    file_name = os.path.basename(unquote(urlparts.path))
    file_dir = os.path.dirname(unquote(urlparts.path))
    if(urlparts.username is not None):
        ftp_username = unquote(urlparts.username)
    else:
        ftp_username = "anonymous"
    if(urlparts.password is not None):
        ftp_password = unquote(urlparts.password)
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
    if(urlparts.scheme == "ftps" or isinstance(ftp, FTP_TLS)):
        try:
            ftp.auth()
        except all_errors:
            pass
    ftp.login(ftp_username, ftp_password)
    if(urlparts.scheme == "ftps" or isinstance(ftp, FTP_TLS)):
        try:
            ftp.prot_p()
        except all_errors:
            ftp.prot_c()
    # UTF-8 filenames if supported
    try:
        ftp.sendcmd("OPTS UTF8 ON")
        ftp.encoding = "utf-8"
    except all_errors:
        pass
    is_cwd_allowed = detect_cwd(ftp, file_dir)
    ftpfile = MkTempFile()
    # Try EPSV first, then fall back
    try:
        ftp.force_epsv = True
        ftp.sendcmd("EPSV")   # request extended passive
        if(is_cwd_allowed):
            ftp.retrbinary("RETR "+file_name, ftpfile.write)
        else:
            ftp.retrbinary("RETR "+unquote(urlparts.path), ftpfile.write)
    except all_errors:
        try:
            ftp.set_pasv(True)
            if(is_cwd_allowed):
                ftp.retrbinary("RETR "+file_name, ftpfile.write)
            else:
                ftp.retrbinary("RETR "+unquote(urlparts.path), ftpfile.write)
        except all_errors:
            ftp.set_pasv(False)
            if(is_cwd_allowed):
                ftp.retrbinary("RETR "+file_name, ftpfile.write)
            else:
                ftp.retrbinary("RETR "+unquote(urlparts.path), ftpfile.write)
    ftp.close()
    ftpfile.seek(0, 0)
    return ftpfile


def download_file_from_ftps_file(url):
    return download_file_from_ftp_file(url)


def download_file_from_ftp_string(url):
    ftpfile = download_file_from_ftp_file(url)
    ftpout = ftpfile.read()
    ftpfile.close()
    return ftpout


def download_file_from_ftps_string(url):
    return download_file_from_ftp_string(url)


def upload_file_to_ftp_file(ftpfile, url):
    urlparts = urlparse(url)
    file_name = os.path.basename(unquote(urlparts.path))
    file_dir = os.path.dirname(unquote(urlparts.path))
    if(urlparts.username is not None):
        ftp_username = unquote(urlparts.username)
    else:
        ftp_username = "anonymous"
    if(urlparts.password is not None):
        ftp_password = unquote(urlparts.password)
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
    if(urlparts.scheme == "ftps" or isinstance(ftp, FTP_TLS)):
        try:
            ftp.auth()
        except all_errors:
            pass
    ftp.login(ftp_username, ftp_password)
    if(urlparts.scheme == "ftps" or isinstance(ftp, FTP_TLS)):
        try:
            ftp.prot_p()
        except all_errors:
            ftp.prot_c()
    # UTF-8 filenames if supported
    try:
        ftp.sendcmd("OPTS UTF8 ON")
        ftp.encoding = "utf-8"
    except all_errors:
        pass
    is_cwd_allowed = detect_cwd(ftp, file_dir)
    ftpfile.seek(0, 0)
    # Try EPSV first, then fall back
    try:
        ftp.force_epsv = True
        ftp.sendcmd("EPSV")   # request extended passive
        if(is_cwd_allowed):
            ftp.storbinary("STOR "+file_name, ftpfile)
        else:
            ftp.storbinary("STOR "+unquote(urlparts.path), ftpfile)
    except all_errors:
        try:
            ftp.set_pasv(True)
            if(is_cwd_allowed):
                ftp.storbinary("STOR "+file_name, ftpfile)
            else:
                ftp.storbinary("STOR "+unquote(urlparts.path), ftpfile)
        except all_errors:
            ftp.set_pasv(False)
            if(is_cwd_allowed):
                ftp.storbinary("STOR "+file_name, ftpfile)
            else:
                ftp.storbinary("STOR "+unquote(urlparts.path), ftpfile)
    ftp.close()
    ftpfile.seek(0, 0)
    return ftpfile


def upload_file_to_ftps_file(ftpfile, url):
    return upload_file_to_ftp_file(ftpfile, url)


def upload_file_to_ftp_string(ftpstring, url):
    ftpfileo = MkTempFile(ftpstring)
    ftpfile = upload_file_to_ftp_file(ftpfileo, url)
    ftpfileo.close()
    return ftpfile


def upload_file_to_ftps_string(ftpstring, url):
    return upload_file_to_ftp_string(ftpstring, url)


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
    username = unquote(urlparts.username)
    password = unquote(urlparts.password)

    # Rebuild URL without username and password
    netloc = urlparts.hostname or ''
    if urlparts.port:
        netloc += ':' + str(urlparts.port)
    rebuilt_url = urlunparse((urlparts.scheme, netloc, urlparts.path,
                              urlparts.params, urlparts.query, urlparts.fragment))

    # Create a temporary file object
    httpfile = MkTempFile()

    # 1) Requests branch
    if usehttp == 'requests' and haverequests:
        if username and password:
            response = requests.get(
                rebuilt_url, headers=headers, auth=(username, password), timeout=(5, 30), stream=True
            )
        else:
            response = requests.get(rebuilt_url, headers=headers, timeout=(5, 30), stream=True)
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


def upload_file_to_http_file(
    fileobj,
    url,
    method="POST",                 # "POST" or "PUT"
    headers=None,
    form=None,                     # dict of extra form fields → triggers multipart/form-data
    field_name="file",             # form field name for the file content
    filename=None,                 # defaults to basename of URL path
    content_type="application/octet-stream",
    usehttp=__use_http_lib__,      # 'requests' | 'httpx' | 'mechanize' | anything → urllib fallback
):
    """
    Py2+Py3 compatible HTTP/HTTPS upload.

    - If `form` is provided (dict), uses multipart/form-data:
        * text fields from `form`
        * file part named by `field_name` with given `filename` and `content_type`
    - If `form` is None, uploads raw body as POST/PUT with Content-Type.
    - Returns True on HTTP 2xx, else False.
    """
    if headers is None:
        headers = {}
    method = (method or "POST").upper()

    rebuilt_url, username, password = _rewrite_url_without_auth(url)
    filename = _guess_filename(url, filename)

    # rewind if possible
    try:
        fileobj.seek(0)
    except Exception:
        pass

    # ========== 1) requests (Py2+Py3) ==========
    if usehttp == 'requests' and haverequests:
        import requests

        auth = (username, password) if (username or password) else None

        if form is not None:
            # multipart/form-data
            files = {field_name: (filename, fileobj, content_type)}
            data = form or {}
            resp = requests.request(method, rebuilt_url, headers=headers, auth=auth,
                                    files=files, data=data, timeout=(5, 120))
        else:
            # raw body
            hdrs = {'Content-Type': content_type}
            hdrs.update(headers)
            # best-effort content-length (helps some servers)
            if hasattr(fileobj, 'seek') and hasattr(fileobj, 'tell'):
                try:
                    cur = fileobj.tell()
                    fileobj.seek(0, io.SEEK_END if hasattr(io, 'SEEK_END') else 2)
                    size = fileobj.tell() - cur
                    fileobj.seek(cur)
                    hdrs.setdefault('Content-Length', str(size))
                except Exception:
                    pass
            resp = requests.request(method, rebuilt_url, headers=hdrs, auth=auth,
                                    data=fileobj, timeout=(5, 300))

        return (200 <= resp.status_code < 300)

    # ========== 2) httpx (Py3 only) ==========
    if usehttp == 'httpx' and havehttpx and not PY2:
        import httpx
        auth = (username, password) if (username or password) else None

        with httpx.Client(follow_redirects=True, timeout=60) as client:
            if form is not None:
                files = {field_name: (filename, fileobj, content_type)}
                data  = form or {}
                resp = client.request(method, rebuilt_url, headers=headers, auth=auth,
                                      files=files, data=data)
            else:
                hdrs = {'Content-Type': content_type}
                hdrs.update(headers)
                resp = client.request(method, rebuilt_url, headers=hdrs, auth=auth,
                                      content=fileobj)
        return (200 <= resp.status_code < 300)

    # ========== 3) mechanize (forms) → prefer requests if available ==========
    if usehttp == 'mechanize' and havemechanize:
        # mechanize is great for HTML forms, but file upload requires form discovery.
        # For a generic upload helper, prefer requests. If not available, fall through.
        try:
            import requests  # noqa
            # delegate to requests path to ensure robust multipart handling
            return upload_file_to_http_file(
                fileobj, url, method=method, headers=headers,
                form=(form or {}), field_name=field_name,
                filename=filename, content_type=content_type,
                usehttp='requests'
            )
        except Exception:
            pass  # fall through to urllib

    # ========== 4) urllib fallback (Py2+Py3) ==========
    # multipart builder (no f-strings)
    boundary = ('----pyuploader-%s' % uuid.uuid4().hex)

    if form is not None:
        # Build multipart body to a temp file-like (your MkTempFile())
        buf = MkTempFile()

        def _w(s):
            buf.write(_to_bytes(s))

        # text fields
        if form:
            for k, v in form.items():
                _w('--' + boundary + '\r\n')
                _w('Content-Disposition: form-data; name="%s"\r\n\r\n' % k)
                _w('' if v is None else (v if isinstance(v, (str, bytes)) else str(v)))
                _w('\r\n')

        # file field
        _w('--' + boundary + '\r\n')
        _w('Content-Disposition: form-data; name="%s"; filename="%s"\r\n' % (field_name, filename))
        _w('Content-Type: %s\r\n\r\n' % content_type)

        try:
            fileobj.seek(0)
        except Exception:
            pass
        shutil.copyfileobj(fileobj, buf)

        _w('\r\n')
        _w('--' + boundary + '--\r\n')

        buf.seek(0)
        data = buf.read()
        hdrs = {'Content-Type': 'multipart/form-data; boundary=%s' % boundary}
        hdrs.update(headers)
        req = Request(rebuilt_url, data=data)
        # method override for Py3; Py2 Request ignores 'method' kw
        if not PY2:
            req.method = method  # type: ignore[attr-defined]
    else:
        # raw body
        try:
            fileobj.seek(0)
        except Exception:
            pass
        data = fileobj.read()
        hdrs = {'Content-Type': content_type}
        hdrs.update(headers)
        req = Request(rebuilt_url, data=data)
        if not PY2:
            req.method = method  # type: ignore[attr-defined]

    for k, v in hdrs.items():
        req.add_header(k, v)

    # Basic auth if present
    if username or password:
        pwd_mgr = HTTPPasswordMgrWithDefaultRealm()
        pwd_mgr.add_password(None, rebuilt_url, username, password)
        opener = build_opener(HTTPBasicAuthHandler(pwd_mgr))
    else:
        opener = build_opener()

    # Py2 OpenerDirector.open takes timeout since 2.6; to be safe, avoid passing if it explodes
    try:
        resp = opener.open(req, timeout=60)
    except TypeError:
        resp = opener.open(req)

    # Status code compat
    code = getattr(resp, 'status', None) or getattr(resp, 'code', None) or 0
    try:
        resp.close()
    except Exception:
        pass
    return (200 <= int(code) < 300)


def download_file_from_http_string(url, headers=geturls_headers_pyfile_python_alt, usehttp=__use_http_lib__):
    httpfile = download_file_from_http_file(url, headers, usehttp)
    httpout = httpfile.read()
    httpfile.close()
    return httpout


if(haveparamiko):
    def download_file_from_sftp_file(url):
        urlparts = urlparse(url)
        file_name = os.path.basename(unquote(urlparts.path))
        file_dir = os.path.dirname(unquote(urlparts.path))
        sftp_port = urlparts.port
        if(urlparts.port is None):
            sftp_port = 22
        else:
            sftp_port = urlparts.port
        if(urlparts.username is not None):
            sftp_username = unquote(urlparts.username)
        else:
            sftp_username = "anonymous"
        if(urlparts.password is not None):
            sftp_password = unquote(urlparts.password)
        elif(urlparts.password is None and urlparts.username == "anonymous"):
            sftp_password = "anonymous"
        else:
            sftp_password = ""
        if(urlparts.scheme != "sftp" and urlparts.scheme != "scp"):
            return False
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(urlparts.hostname, port=sftp_port,
                        username=sftp_username, password=sftp_password)
        except paramiko.ssh_exception.SSHException:
            return False
        except socket.gaierror:
            log.info("Error With URL "+url)
            return False
        except socket.timeout:
            log.info("Error With URL "+url)
            return False
        sftp = ssh.open_sftp()
        sftpfile = MkTempFile()
        sftp.getfo(unquote(urlparts.path), sftpfile)
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
        sftpout = sftpfile.read()
        sftpfile.close()
        return sftpout
else:
    def download_file_from_sftp_string(url):
        return False

if(haveparamiko):
    def upload_file_to_sftp_file(sftpfile, url):
        urlparts = urlparse(url)
        file_name = os.path.basename(unquote(urlparts.path))
        file_dir = os.path.dirname(unquote(urlparts.path))
        sftp_port = urlparts.port
        if(urlparts.port is None):
            sftp_port = 22
        else:
            sftp_port = urlparts.port
        if(urlparts.username is not None):
            sftp_username = unquote(urlparts.username)
        else:
            sftp_username = "anonymous"
        if(urlparts.password is not None):
            sftp_password = unquote(urlparts.password)
        elif(urlparts.password is None and urlparts.username == "anonymous"):
            sftp_password = "anonymous"
        else:
            sftp_password = ""
        if(urlparts.scheme != "sftp" and urlparts.scheme != "scp"):
            return False
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(urlparts.hostname, port=sftp_port,
                        username=sftp_username, password=sftp_password)
        except paramiko.ssh_exception.SSHException:
            return False
        except socket.gaierror:
            log.info("Error With URL "+url)
            return False
        except socket.timeout:
            log.info("Error With URL "+url)
            return False
        sftp = ssh.open_sftp()
        sftpfile.seek(0, 0)
        sftp.putfo(sftpfile, unquote(urlparts.path))
        sftp.close()
        ssh.close()
        sftpfile.seek(0, 0)
        return sftpfile
else:
    def upload_file_to_sftp_file(sftpfile, url):
        return False

if(haveparamiko):
    def upload_file_to_sftp_string(sftpstring, url):
        sftpfileo = MkTempFile(sftpstring)
        sftpfile = upload_file_to_sftp_files(sftpfileo, url)
        sftpfileo.close()
        return sftpfile
else:
    def upload_file_to_sftp_string(url):
        return False

if(havepysftp):
    def download_file_from_pysftp_file(url):
        urlparts = urlparse(url)
        file_name = os.path.basename(unquote(urlparts.path))
        file_dir = os.path.dirname(unquote(urlparts.path))
        sftp_port = urlparts.port
        if(urlparts.port is None):
            sftp_port = 22
        else:
            sftp_port = urlparts.port
        if(urlparts.username is not None):
            sftp_username = unquote(urlparts.username)
        else:
            sftp_username = "anonymous"
        if(urlparts.password is not None):
            sftp_password = unquote(urlparts.password)
        elif(urlparts.password is None and urlparts.username == "anonymous"):
            sftp_password = "anonymous"
        else:
            sftp_password = ""
        if(urlparts.scheme != "sftp" and urlparts.scheme != "scp"):
            return False
        try:
            sftp = pysftp.Connection(urlparts.hostname, port=sftp_port,
                              username=sftp_username, password=sftp_password)
        except paramiko.ssh_exception.SSHException:
            return False
        except socket.gaierror:
            log.info("Error With URL "+url)
            return False
        except socket.timeout:
            log.info("Error With URL "+url)
            return False
        sftpfile = MkTempFile()
        sftp.getfo(unquote(urlparts.path), sftpfile)
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
        sftpout = sftpfile.read()
        sftpfile.close()
        return sftpout
else:
    def download_file_from_pysftp_string(url):
        return False

if(havepysftp):
    def upload_file_to_pysftp_file(sftpfile, url):
        urlparts = urlparse(url)
        file_name = os.path.basename(unquote(urlparts.path))
        file_dir = os.path.dirname(unquote(urlparts.path))
        sftp_port = urlparts.port
        if(urlparts.port is None):
            sftp_port = 22
        else:
            sftp_port = urlparts.port
        if(urlparts.username is not None):
            sftp_username = unquote(urlparts.username)
        else:
            sftp_username = "anonymous"
        if(urlparts.password is not None):
            sftp_password = unquote(urlparts.password)
        elif(urlparts.password is None and urlparts.username == "anonymous"):
            sftp_password = "anonymous"
        else:
            sftp_password = ""
        if(urlparts.scheme != "sftp" and urlparts.scheme != "scp"):
            return False
        try:
            sftp = pysftp.Connection(urlparts.hostname, port=sftp_port,
                              username=sftp_username, password=sftp_password)
        except paramiko.ssh_exception.SSHException:
            return False
        except socket.gaierror:
            log.info("Error With URL "+url)
            return False
        except socket.timeout:
            log.info("Error With URL "+url)
            return False
        sftpfile.seek(0, 0)
        sftp.putfo(sftpfile, unquote(urlparts.path))
        sftp.close()
        ssh.close()
        sftpfile.seek(0, 0)
        return sftpfile
else:
    def upload_file_to_pysftp_file(sftpfile, url):
        return False

if(havepysftp):
    def upload_file_to_pysftp_string(sftpstring, url):
        sftpfileo = MkTempFile(sftpstring)
        sftpfile = upload_file_to_pysftp_file(ftpfileo, url)
        sftpfileo.close()
        return sftpfile
else:
    def upload_file_to_pysftp_string(sftpstring, url):
        return False


def download_file_from_internet_file(url, headers=geturls_headers_pyfile_python_alt, usehttp=__use_http_lib__):
    urlparts = urlparse(url)
    if(urlparts.scheme == "http" or urlparts.scheme == "https"):
        return download_file_from_http_file(url, headers, usehttp)
    elif(urlparts.scheme == "ftp" or urlparts.scheme == "ftps"):
        return download_file_from_ftp_file(url)
    elif(urlparts.scheme == "sftp" or urlparts.scheme == "scp"):
        if(__use_pysftp__ and havepysftp):
            return download_file_from_pysftp_file(url)
        else:
            return download_file_from_sftp_file(url)
    elif(urlparts.scheme == "tcp" or urlparts.scheme == "udp"):
        outfile = MkTempFile()
        returnval = recv_via_url(outfile, url, recv_to_fileobj)
        if(not returnval):
            return False
        outfile.seek(0, 0)
        return outfile
    else:
        return False
    return False

def download_file_from_http_file_alt(url, headers=None, usehttp=__use_http_lib__):
    """
    Stream a URL to a temp file with optional auth (from URL) and
    optional integrity checks based on headers.

    Query flags:
      verify_len=1|0  (default: 1 if length header present)
      verify_sha=1|0  (default: 1 if X-File-SHA256 or strong ETag present)
    """
    if headers is None:
        headers = {}

    # Parse URL, extract user/pass, and rebuild without auth
    urlparts = urlparse(url)
    username = unquote(urlparts.username) if urlparts.username else None
    password = unquote(urlparts.password) if urlparts.password else None

    # verification controls from query string
    q = parse_qs(urlparts.query or "")
    want_verify_len = _qflag(q, "verify_len", None)  # None = auto
    want_verify_sha = _qflag(q, "verify_sha", None)

    # Rebuild netloc without userinfo
    netloc = urlparts.hostname or ''
    if urlparts.port:
        netloc += ':' + str(urlparts.port)
    rebuilt_url = urlunparse((urlparts.scheme, netloc, urlparts.path,
                              urlparts.params, urlparts.query, urlparts.fragment))

    # Allocate destination
    httpfile = MkTempFile()

    # Common chunk size (safe default even for chunked)
    CHUNK = 64 * 1024

    # --- Branch 1: requests ---
    if usehttp == 'requests' and haverequests:
        # build auth
        auth = (username, password) if (username and password) else None
        resp = requests.get(rebuilt_url, headers=headers, auth=auth, timeout=(5, 30), stream=True)
        resp.raise_for_status()

        # headers & expectations
        hdrs = _headers_dict_from_response(resp, 'requests')
        expected_len = _pick_expected_len(hdrs)
        expected_sha = _pick_expected_sha(hdrs)

        # auto-verify defaults
        verify_len = want_verify_len if want_verify_len is not None else (expected_len is not None)
        verify_sha = want_verify_sha if want_verify_sha is not None else (expected_sha is not None)

        # iter bytes
        resp.raw.decode_content = True  # allow gzip transparently if server used it
        if verify_len or verify_sha:
            it = resp.iter_content(chunk_size=CHUNK)
            _stream_copy_and_verify(
                it, httpfile,
                expected_len=(expected_len if verify_len else None),
                expected_sha=(expected_sha if verify_sha else None),
                chunk_size=CHUNK
            )
        else:
            # Fast path: no verify; still stream to avoid large memory
            for chunk in resp.iter_content(chunk_size=CHUNK):
                if chunk:
                    httpfile.write(_to_bytes(chunk))

    # --- Branch 2: httpx ---
    elif usehttp == 'httpx' and havehttpx:
        auth = (username, password) if (username and password) else None
        with httpx.Client(follow_redirects=True, timeout=30.0, auth=auth) as client:
            r = client.get(rebuilt_url)
            r.raise_for_status()
            hdrs = _headers_dict_from_response(r, 'httpx')
            expected_len = _pick_expected_len(hdrs)
            expected_sha = _pick_expected_sha(hdrs)
            verify_len = want_verify_len if want_verify_len is not None else (expected_len is not None)
            verify_sha = want_verify_sha if want_verify_sha is not None else (expected_sha is not None)

            if verify_len or verify_sha:
                it = r.iter_bytes()
                _stream_copy_and_verify(
                    it, httpfile,
                    expected_len=(expected_len if verify_len else None),
                    expected_sha=(expected_sha if verify_sha else None),
                    chunk_size=CHUNK
                )
            else:
                for chunk in r.iter_bytes():
                    if chunk:
                        httpfile.write(_to_bytes(chunk))

    # --- Branch 3: mechanize ---
    elif usehttp == 'mechanize' and havemechanize:
        br = mechanize.Browser()
        br.set_handle_robots(False)
        if headers:
            br.addheaders = list(headers.items())
        # mechanize basic-auth: add_password(url, user, pass)
        if username and password:
            br.add_password(rebuilt_url, username, password)

        response = br.open(rebuilt_url, timeout=30.0 if hasattr(br, 'timeout') else None)
        hdrs = _headers_dict_from_response(response, 'mechanize')
        expected_len = _pick_expected_len(hdrs)
        expected_sha = _pick_expected_sha(hdrs)
        verify_len = want_verify_len if want_verify_len is not None else (expected_len is not None)
        verify_sha = want_verify_sha if want_verify_sha is not None else (expected_sha is not None)

        if verify_len or verify_sha:
            def _iter_mech(resp, sz):
                while True:
                    chunk = resp.read(sz)
                    if not chunk:
                        break
                    yield chunk
            _stream_copy_and_verify(
                _iter_mech(response, CHUNK), httpfile,
                expected_len=(expected_len if verify_len else None),
                expected_sha=(expected_sha if verify_sha else None),
                chunk_size=CHUNK
            )
        else:
            # simple stream copy
            while True:
                chunk = response.read(CHUNK)
                if not chunk:
                    break
                httpfile.write(_to_bytes(chunk))

    # --- Branch 4: urllib fallback ---
    else:
        request = Request(rebuilt_url, headers=headers)
        opener = None
        if username and password:
            password_mgr = HTTPPasswordMgrWithDefaultRealm()
            password_mgr.add_password(None, rebuilt_url, username, password)
            auth_handler = HTTPBasicAuthHandler(password_mgr)
            opener = build_opener(auth_handler)
        else:
            opener = build_opener()

        response = opener.open(request, timeout=30)
        hdrs = _headers_dict_from_response(response, 'urllib')
        expected_len = _pick_expected_len(hdrs)
        expected_sha = _pick_expected_sha(hdrs)
        verify_len = want_verify_len if want_verify_len is not None else (expected_len is not None)
        verify_sha = want_verify_sha if want_verify_sha is not None else (expected_sha is not None)

        if verify_len or verify_sha:
            def _iter_urllib(resp, sz):
                while True:
                    chunk = resp.read(sz)
                    if not chunk:
                        break
                    yield chunk
            _stream_copy_and_verify(
                _iter_urllib(response, CHUNK), httpfile,
                expected_len=(expected_len if verify_len else None),
                expected_sha=(expected_sha if verify_sha else None),
                chunk_size=CHUNK
            )
        else:
            while True:
                chunk = response.read(CHUNK)
                if not chunk:
                    break
                httpfile.write(_to_bytes(chunk))

    # Rewind before returning
    try:
        httpfile.seek(0, 0)
    except Exception:
        pass
    return httpfile



def download_file_from_internet_uncompress_file(url, headers=geturls_headers_pyfile_python_alt, filestart=0, formatspecs=__file_format_dict__):
    fp = download_file_from_internet_file(url)
    fp = UncompressFileAlt(fp, formatspecs, filestart)
    fp.seek(0, 0)
    if(not fp):
        return False
    return fp


def download_file_from_internet_string(url, headers=geturls_headers_pyfile_python_alt):
    urlparts = urlparse(url)
    if(urlparts.scheme == "http" or urlparts.scheme == "https"):
        return download_file_from_http_string(url, headers)
    elif(urlparts.scheme == "ftp" or urlparts.scheme == "ftps"):
        return download_file_from_ftp_string(url)
    elif(urlparts.scheme == "sftp" or urlparts.scheme == "scp"):
        if(__use_pysftp__ and havepysftp):
            return download_file_from_pysftp_string(url)
        else:
            return download_file_from_sftp_string(url)
    else:
        return False
    return False


def download_file_from_internet_uncompress_string(url, headers=geturls_headers_pyfile_python_alt, filestart=0, formatspecs=__file_format_dict__):
    fp = download_file_from_internet_string(url)
    fp = UncompressFileAlt(fp, formatspecs, filestart)
    if(not fp):
        return False
    fp.seek(0, 0)
    fpout = fp.read()
    fp.close
    return fpout


def upload_file_to_internet_file(ifp, url):
    urlparts = urlparse(url)
    if(urlparts.scheme == "ftp" or urlparts.scheme == "ftps"):
        return upload_file_to_ftp_file(ifp, url)
    elif(urlparts.scheme == "sftp" or urlparts.scheme == "scp"):
        if(__use_pysftp__ and havepysftp):
            return upload_file_to_pysftp_file(ifp, url)
        else:
            return upload_file_to_sftp_file(ifp, url)
    elif(urlparts.scheme == "tcp" or urlparts.scheme == "udp"):
        ifp.seek(0, 0)
        returnval = send_via_url(ifp, url, send_from_fileobj)
        if(not returnval):
            return False
        return returnval
    elif(urlparts.scheme == "http" or urlparts.scheme == "https"):
        ifp.seek(0, 0)
        returnval = send_via_http(ifp, url, run_http_file_server)
        if(not returnval):
            return False
        return returnval
    else:
        return False
    return False


def upload_file_to_internet_compress_file(ifp, url, compression="auto", compressionlevel=None, compressionuselist=compressionlistalt, formatspecs=__file_format_dict__):
    fp = CompressOpenFileAlt(
        fp, compression, compressionlevel, compressionuselist, formatspecs)
    if(not outfileretrn):
        return False
    fp.seek(0, 0)
    return upload_file_to_internet_file(fp, outfile)


def upload_file_to_internet_string(ifp, url):
    urlparts = urlparse(url)
    if(urlparts.scheme == "http" or urlparts.scheme == "https"):
        return False
    elif(urlparts.scheme == "ftp" or urlparts.scheme == "ftps"):
        return upload_file_to_ftp_string(ifp, url)
    elif(urlparts.scheme == "sftp" or urlparts.scheme == "scp"):
        if(__use_pysftp__ and havepysftp):
            return upload_file_to_pysftp_string(ifp, url)
        else:
            return upload_file_to_sftp_string(ifp, url)
    else:
        return False
    return False


def upload_file_to_internet_compress_string(ifp, url, compression="auto", compressionlevel=None, compressionuselist=compressionlistalt, formatspecs=__file_format_dict__):
    internetfileo = MkTempFile(ifp)
    fp = CompressOpenFileAlt(
        internetfileo, compression, compressionlevel, compressionuselist, formatspecs)
    if(not outfileretrn):
        return False
    fp.seek(0, 0)
    return upload_file_to_internet_file(fp, outfile)


# ---------- Core: send / recv ----------
def send_from_fileobj(fileobj, host, port=3124, proto="tcp", timeout=None,
                      chunk_size=65536,
                      use_ssl=False, ssl_verify=True, ssl_ca_file=None,
                      ssl_certfile=None, ssl_keyfile=None, server_hostname=None,
                      auth_user=None, auth_pass=None, auth_scope=u"",
                      on_progress=None, rate_limit_bps=None, want_sha=True,
                      enforce_path=True, path_text=u""):
    """
    Send fileobj over TCP/UDP with control prefaces.

    Control frames order (UDP):
      PATH <pct-encoded-path>\n           (if enforce_path)
      [AF1 auth blob or legacy AUTH\0u\0p\0, expect OK]
      [LEN <n> [sha]\n]                   (if total length known)
      [payload...]
      [HASH <sha>\n] + DONE\n             (if length unknown)

    TCP:
      PATH line + auth (if requested), then raw payload stream.
    """
    proto = (proto or "tcp").lower()
    total = 0
    port = int(port)
    if proto not in ("tcp", "udp"):
        raise ValueError("proto must be 'tcp' or 'udp'")

    # ---------------- UDP ----------------
    if proto == "udp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            if timeout is not None:
                sock.settimeout(timeout)
            try:
                sock.connect((host, port))
                connected = True
            except Exception:
                connected = False

            # (0) PATH preface
            if enforce_path:
                p = _quote_path_for_wire(_to_text(path_text))
                line = b"PATH " + p.encode('ascii') + b"\n"
                (sock.send(line) if connected else sock.sendto(line, (host, port)))

            # (1) Length and optional sha precompute
            total_bytes, start_pos = _discover_len_and_reset(fileobj)
            sha_hex = None
            if want_sha and total_bytes is not None:
                import hashlib
                h = hashlib.sha256()
                try: cur = fileobj.tell()
                except Exception: cur = None
                if start_pos is not None:
                    try: fileobj.seek(start_pos, os.SEEK_SET)
                    except Exception: pass
                _HSZ = 1024 * 1024
                while True:
                    blk = fileobj.read(_HSZ)
                    if not blk: break
                    h.update(_to_bytes(blk))
                sha_hex = h.hexdigest()
                # restore
                if start_pos is not None:
                    try: fileobj.seek(start_pos, os.SEEK_SET)
                    except Exception: pass
                elif cur is not None:
                    try: fileobj.seek(cur, os.SEEK_SET)
                    except Exception: pass

            # (2) AF1 auth (preferred) else legacy
            if auth_user is not None or auth_pass is not None:
                try:
                    blob = build_auth_blob_v1(
                        auth_user or u"", auth_pass or u"",
                        scope=auth_scope, length=total_bytes, sha_hex=(sha_hex if want_sha else None)
                    )
                except Exception:
                    blob = _build_auth_blob_legacy(auth_user or b"", auth_pass or b"")
                if connected:
                    sock.send(blob)
                    try:
                        resp = sock.recv(16)
                        if resp != _OK:
                            raise RuntimeError("UDP auth failed")
                    except Exception:
                        pass
                else:
                    sock.sendto(blob, (host, port))
                    try:
                        resp, _ = sock.recvfrom(16)
                        if resp != _OK:
                            raise RuntimeError("UDP auth failed")
                    except Exception:
                        pass

            # (3) Known-length preface
            if total_bytes is not None:
                pre = b"LEN " + str(int(total_bytes)).encode('ascii')
                if want_sha and sha_hex:
                    pre += b" " + sha_hex.encode('ascii')
                pre += b"\n"
                (sock.send(pre) if connected else sock.sendto(pre, (host, port)))

            # (4) Payload (cap datagram size)
            UDP_PAYLOAD_MAX = 1200  # keep well below typical MTU
            effective_chunk = min(int(chunk_size or 65536), UDP_PAYLOAD_MAX)

            sent_so_far = 0
            last_cb_ts = monotonic()
            rl_ts = last_cb_ts
            rl_bytes = 0

            rolling_h = None
            if want_sha and total_bytes is None:
                try:
                    import hashlib
                    rolling_h = hashlib.sha256()
                except Exception:
                    rolling_h = None

            while True:
                chunk = fileobj.read(effective_chunk)
                if not chunk:
                    break
                b = _to_bytes(chunk)
                if rolling_h is not None:
                    rolling_h.update(b)
                n = (sock.send(b) if connected else sock.sendto(b, (host, port)))
                total += n
                sent_so_far += n

                if rate_limit_bps:
                    sleep_s, rl_ts, rl_bytes = _pace_rate(rl_ts, rl_bytes, rate_limit_bps, n)
                    if sleep_s > 0.0:
                        time.sleep(min(sleep_s, 0.25))
                if on_progress and (monotonic() - last_cb_ts) >= 0.1:
                    try: on_progress(sent_so_far, total_bytes)
                    except Exception: pass
                    last_cb_ts = monotonic()

            # (5) Unknown-length trailers
            if total_bytes is None:
                if rolling_h is not None:
                    try:
                        th = rolling_h.hexdigest().encode('ascii')
                        frame = b"HASH " + th + b"\n"
                        (sock.send(frame) if connected else sock.sendto(frame, (host, port)))
                    except Exception:
                        pass
                try:
                    (sock.send(b"DONE\n") if connected else sock.sendto(b"DONE\n", (host, port)))
                except Exception:
                    pass

        finally:
            try: sock.close()
            except Exception: pass
        return total

    # ---------------- TCP ----------------
    sock = _connect_stream(host, port, timeout)
    try:
        if use_ssl:
            if not _ssl_available():
                raise RuntimeError("SSL requested but 'ssl' module unavailable.")
            sock = _ssl_wrap_socket(sock, server_side=False,
                                    server_hostname=(server_hostname or host),
                                    verify=ssl_verify, ca_file=ssl_ca_file,
                                    certfile=ssl_certfile, keyfile=ssl_keyfile)

        # (0) PATH preface first
        if enforce_path:
            p = _quote_path_for_wire(_to_text(path_text))
            line = b"PATH " + p.encode('ascii') + b"\n"
            sock.sendall(line)

        # (1) Length + optional sha (for AF1 metadata/logging)
        total_bytes, start_pos = _discover_len_and_reset(fileobj)
        sha_hex = None
        if want_sha and total_bytes is not None:
            try:
                import hashlib
                h = hashlib.sha256()
                cur = fileobj.tell()
                if start_pos is not None:
                    fileobj.seek(start_pos, os.SEEK_SET)
                _HSZ = 1024 * 1024
                while True:
                    blk = fileobj.read(_HSZ)
                    if not blk: break
                    h.update(_to_bytes(blk))
                sha_hex = h.hexdigest()
                fileobj.seek(cur, os.SEEK_SET)
            except Exception:
                sha_hex = None

        # (2) Auth preface
        if auth_user is not None or auth_pass is not None:
            try:
                blob = build_auth_blob_v1(
                    auth_user or u"", auth_pass or u"",
                    scope=auth_scope, length=total_bytes, sha_hex=(sha_hex if want_sha else None)
                )
            except Exception:
                blob = _build_auth_blob_legacy(auth_user or b"", auth_pass or b"")
            sock.sendall(blob)
            try:
                resp = sock.recv(16)
                if resp != _OK:
                    raise RuntimeError("TCP auth failed")
            except Exception:
                pass

        # (3) Payload
        sent_so_far = 0
        last_cb_ts = monotonic()
        rl_ts = last_cb_ts
        rl_bytes = 0

        use_sendfile = hasattr(sock, "sendfile") and hasattr(fileobj, "read")
        if use_sendfile:
            try:
                sent = sock.sendfile(fileobj)
                if isinstance(sent, int):
                    total += sent; sent_so_far += sent
                    if on_progress:
                        try: on_progress(sent_so_far, total_bytes)
                        except Exception: pass
                else:
                    raise RuntimeError("sendfile returned unexpected type")
            except Exception:
                # fallback chunk loop
                while True:
                    chunk = fileobj.read(chunk_size)
                    if not chunk: break
                    view = memoryview(_to_bytes(chunk))
                    while view:
                        n = sock.send(view); total += n; sent_so_far += n; view = view[n:]
                        if rate_limit_bps:
                            sleep_s, rl_ts, rl_bytes = _pace_rate(rl_ts, rl_bytes, rate_limit_bps, n)
                            if sleep_s > 0.0: time.sleep(min(sleep_s, 0.25))
                    if on_progress and (monotonic() - last_cb_ts) >= 0.1:
                        try: on_progress(sent_so_far, total_bytes)
                        except Exception: pass
                        last_cb_ts = monotonic()
        else:
            while True:
                chunk = fileobj.read(chunk_size)
                if not chunk: break
                view = memoryview(_to_bytes(chunk))
                while view:
                    n = sock.send(view); total += n; sent_so_far += n; view = view[n:]
                    if rate_limit_bps:
                        sleep_s, rl_ts, rl_bytes = _pace_rate(rl_ts, rl_bytes, rate_limit_bps, n)
                        if sleep_s > 0.0: time.sleep(min(sleep_s, 0.25))
                if on_progress and (monotonic() - last_cb_ts) >= 0.1:
                    try: on_progress(sent_so_far, total_bytes)
                    except Exception: pass
                    last_cb_ts = monotonic()
    finally:
        try: sock.shutdown(socket.SHUT_WR)
        except Exception: pass
        try: sock.close()
        except Exception: pass
    return total


def recv_to_fileobj(fileobj, host="", port=3124, proto="tcp", timeout=None,
                    max_bytes=None, chunk_size=65536, backlog=1,
                    use_ssl=False, ssl_verify=True, ssl_ca_file=None,
                    ssl_certfile=None, ssl_keyfile=None,
                    require_auth=False, expected_user=None, expected_pass=None,
                    total_timeout=None, expect_scope=None,
                    on_progress=None, rate_limit_bps=None,
                    enforce_path=True, wait_seconds=None):
    """
    Receive bytes into fileobj over TCP/UDP.

    Path enforcement:
      - UDP: expects 'PATH <...>\\n' control frame first (if enforce_path).
      - TCP: reads first line 'PATH <...>\\n' before auth/payload (if enforce_path).

    UDP control frames understood: PATH, LEN, HASH, DONE (+ AF1 auth blob).

    wait_seconds (TCP only): overall accept window to wait for a client
      (mirrors the HTTP server behavior). None = previous behavior (single accept
      with 'timeout' as the accept timeout).
    """
    proto = (proto or "tcp").lower()
    port = int(port)
    total = 0

    start_ts = time.time()
    def _time_left():
        if total_timeout is None:
            return None
        left = total_timeout - (time.time() - start_ts)
        return 0.0 if left <= 0 else left

    def _set_effective_timeout(socklike, base_timeout):
        left = _time_left()
        if left == 0.0:
            return False
        eff = base_timeout
        if left is not None:
            eff = left if eff is None else min(eff, left)
        if eff is not None:
            try:
                socklike.settimeout(eff)
            except Exception:
                pass
        return True

    if proto not in ("tcp", "udp"):
        raise ValueError("proto must be 'tcp' or 'udp'")

    # ---------------- UDP server ----------------
    if proto == "udp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        authed_addr = None
        expected_len = None
        expected_sha = None
        path_checked = (not enforce_path)

        try:
            sock.bind(("", port))
            if timeout is None:
                try: sock.settimeout(10.0)
                except Exception: pass

            recvd_so_far = 0
            last_cb_ts = monotonic()
            rl_ts = last_cb_ts
            rl_bytes = 0

            while True:
                if _time_left() == 0.0:
                    if expected_len is not None and total < expected_len:
                        raise RuntimeError("UDP receive aborted by total_timeout before full payload received")
                    break
                if (max_bytes is not None) and (total >= max_bytes):
                    break

                if not _set_effective_timeout(sock, timeout):
                    if expected_len is not None and total < expected_len:
                        raise RuntimeError("UDP receive timed out before full payload received")
                    if expected_len is None and total > 0:
                        raise RuntimeError("UDP receive timed out with unknown length; partial data")
                    if expected_len is None and total == 0:
                        raise RuntimeError("UDP receive: no packets received before timeout (is the sender running?)")
                    break

                try:
                    data, addr = sock.recvfrom(chunk_size)
                except socket.timeout:
                    if expected_len is not None and total < expected_len:
                        raise RuntimeError("UDP receive idle-timeout before full payload received")
                    if expected_len is None and total > 0:
                        raise RuntimeError("UDP receive idle-timeout with unknown length; partial data")
                    if expected_len is None and total == 0:
                        raise RuntimeError("UDP receive: no packets received before timeout (is the sender running?)")
                    break

                if not data:
                    continue

                # (0) PATH first (strict)
                if not path_checked and data.startswith(b"PATH "):
                    got_path = _unquote_path_from_wire(data[5:].strip())
                    if _to_text(got_path) != _to_text(expect_scope or u""):
                        raise RuntimeError("UDP path mismatch: got %r expected %r"
                                           % (got_path, expect_scope))
                    path_checked = True
                    continue
                if enforce_path and not path_checked:
                    if not data.startswith(b"PATH "):
                        continue  # ignore until PATH arrives

                # (0b) Control frames
                if data.startswith(b"LEN ") and expected_len is None:
                    try:
                        parts = data.strip().split()
                        n = int(parts[1])
                        expected_len = (None if n < 0 else n)
                        if len(parts) >= 3:
                            expected_sha = parts[2].decode("ascii")
                    except Exception:
                        expected_len = None; expected_sha = None
                    continue

                if data.startswith(b"HASH "):
                    try:
                        expected_sha = data.strip().split()[1].decode("ascii")
                    except Exception:
                        expected_sha = None
                    continue

                if data == b"DONE\n":
                    break

                # (1) Auth (if required)
                if authed_addr is None and require_auth:
                    ok = False
                    v_ok, v_user, v_scope, _r, v_len, v_sha = verify_auth_blob_v1(
                        data, expected_user=expected_user, secret=expected_pass,
                        max_skew=600, expect_scope=expect_scope
                    )
                    if v_ok:
                        ok = True
                        if expected_len is None:
                            expected_len = v_len
                        if expected_sha is None:
                            expected_sha = v_sha
                    else:
                        user, pw = _parse_auth_blob_legacy(data)
                        ok = (user is not None and
                              (expected_user is None or user == _to_bytes(expected_user)) and
                              (expected_pass is None or pw == _to_bytes(expected_pass)))
                    try:
                        sock.sendto((_OK if ok else _NO), addr)
                    except Exception:
                        pass
                    if ok:
                        authed_addr = addr
                    continue

                if require_auth and addr != authed_addr:
                    continue

                # (2) Payload
                fileobj.write(data)
                try: fileobj.flush()
                except Exception: pass
                total += len(data)
                recvd_so_far += len(data)

                if rate_limit_bps:
                    sleep_s, rl_ts, rl_bytes = _pace_rate(rl_ts, rl_bytes, rate_limit_bps, len(data))
                    if sleep_s > 0.0:
                        time.sleep(min(sleep_s, 0.25))

                if on_progress and (monotonic() - last_cb_ts) >= 0.1:
                    try: on_progress(recvd_so_far, expected_len)
                    except Exception: pass
                    last_cb_ts = monotonic()

                if expected_len is not None and total >= expected_len:
                    break

            # Post-conditions
            if expected_len is not None and total != expected_len:
                raise RuntimeError("UDP receive incomplete: got %d of %s bytes" % (total, expected_len))

            if expected_sha:
                import hashlib
                try:
                    cur = fileobj.tell(); fileobj.seek(0)
                except Exception:
                    cur = None
                h = hashlib.sha256(); _HSZ = 1024 * 1024
                while True:
                    blk = fileobj.read(_HSZ)
                    if not blk: break
                    h.update(_to_bytes(blk))
                got = h.hexdigest()
                if cur is not None:
                    try: fileobj.seek(cur)
                    except Exception: pass
                if got != expected_sha:
                    raise RuntimeError("UDP checksum mismatch: got %s expected %s" % (got, expected_sha))

        finally:
            try: sock.close()
            except Exception: pass
        return total

    # ---------------- TCP server (one-shot with optional wait window) ----------------
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        try: srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except Exception: pass
        srv.bind((host or "", port))
        srv.listen(int(backlog) if backlog else 1)

        bytes_written = 0
        started = time.time()

        # per-accept wait
        per_accept = float(timeout) if timeout is not None else 1.0
        try: srv.settimeout(per_accept)
        except Exception: pass

        while True:
            if bytes_written > 0:
                break
            if wait_seconds is not None and (time.time() - started) >= wait_seconds:
                break

            try:
                conn, _peer = srv.accept()
            except socket.timeout:
                continue
            except Exception:
                break

            # TLS
            if use_ssl:
                if not _ssl_available():
                    try: conn.close()
                    except Exception: pass
                    break
                if not ssl_certfile:
                    try: conn.close()
                    except Exception: pass
                    raise ValueError("TLS server requires ssl_certfile (and usually ssl_keyfile).")
                conn = _ssl_wrap_socket(conn, server_side=True, server_hostname=None,
                                        verify=ssl_verify, ca_file=ssl_ca_file,
                                        certfile=ssl_certfile, keyfile=ssl_keyfile)

            recvd_so_far = 0
            last_cb_ts = monotonic()
            rl_ts = last_cb_ts
            rl_bytes = 0

            try:
                # (0) PATH line (if enforced)
                if enforce_path:
                    line = _recv_line(conn, maxlen=4096, timeout=timeout)
                    if not line or not line.startswith(b"PATH "):
                        try: conn.close()
                        except Exception: pass
                        continue
                    got_path = _unquote_path_from_wire(line[5:].strip())
                    if _to_text(got_path) != _to_text(expect_scope or u""):
                        try: conn.close()
                        except Exception: pass
                        raise RuntimeError("TCP path mismatch: got %r expected %r"
                                           % (got_path, expect_scope))

                # (1) Auth preface
                if require_auth:
                    if not _set_effective_timeout(conn, timeout):
                        try: conn.close()
                        except Exception: pass
                        continue
                    try:
                        preface = conn.recv(2048)
                    except socket.timeout:
                        try: conn.sendall(_NO)
                        except Exception: pass
                        try: conn.close()
                        except Exception: pass
                        continue

                    ok = False
                    v_ok, v_user, v_scope, _r, v_len, v_sha = verify_auth_blob_v1(
                        preface or b"", expected_user=expected_user, secret=expected_pass,
                        max_skew=600, expect_scope=expect_scope
                    )
                    if v_ok:
                        ok = True
                    else:
                        user, pw = _parse_auth_blob_legacy(preface or b"")
                        ok = (user is not None and
                              (expected_user is None or user == _to_bytes(expected_user)) and
                              (expected_pass is None or pw == _to_bytes(expected_pass)))
                    try: conn.sendall(_OK if ok else _NO)
                    except Exception: pass
                    if not ok:
                        try: conn.close()
                        except Exception: pass
                        continue

                # (2) Payload loop
                while True:
                    if _time_left() == 0.0: break
                    if (max_bytes is not None) and (bytes_written >= max_bytes): break

                    if not _set_effective_timeout(conn, timeout):
                        break
                    try:
                        data = conn.recv(chunk_size)
                    except socket.timeout:
                        break
                    if not data:
                        break

                    fileobj.write(data)
                    try: fileobj.flush()
                    except Exception: pass
                    total += len(data)
                    bytes_written += len(data)
                    recvd_so_far += len(data)

                    if rate_limit_bps:
                        sleep_s, rl_ts, rl_bytes = _pace_rate(rl_ts, rl_bytes, rate_limit_bps, len(data))
                        if sleep_s > 0.0:
                            time.sleep(min(sleep_s, 0.25))

                    if on_progress and (monotonic() - last_cb_ts) >= 0.1:
                        try: on_progress(recvd_so_far, max_bytes)
                        except Exception: pass
                        last_cb_ts = monotonic()

            finally:
                try: conn.shutdown(socket.SHUT_RD)
                except Exception: pass
                try: conn.close()
                except Exception: pass

        return total

    finally:
        try: srv.close()
        except Exception: pass

def run_tcp_file_server(fileobj, url, on_progress=None):
    """
    One-shot TCP uploader: wait for a client, authenticate (optional),
    then send control preface (LEN...), followed by the file bytes.
    Ends after serving exactly one client or wait window elapses.

    URL example:
      tcp://user:pass@0.0.0.0:5000/path/my.arc?
          auth=1&enforce_path=1&rate=200000&timeout=5&wait=30&ssl=0
    """
    parts, o = _parse_net_url(url)  # already returns proto/host/port/timeout/ssl/etc.
    if o["proto"] != "tcp":
        raise ValueError("run_tcp_file_server requires tcp:// URL")

    # Pull extras from the query string (enforce_path, want_sha, rate, wait)
    qs = parse_qs(parts.query or "")
    enforce_path = _qflag(qs, "enforce_path", True)
    want_sha      = _qflag(qs, "sha", True)
    rate_limit    = _qnum(qs, "rate", None, float)
    wait_seconds  = _qnum(qs, "wait", None, float)  # None = wait forever

    # Discover length (and precompute sha if requested & length known)
    total_bytes, start_pos = _discover_len_and_reset(fileobj)
    sha_hex = None
    if want_sha and total_bytes is not None:
        try:
            import hashlib
            h = hashlib.sha256()
            # hash current stream content
            cur = None
            try: cur = fileobj.tell()
            except Exception: pass
            if start_pos is not None:
                try: fileobj.seek(start_pos, os.SEEK_SET)
                except Exception: pass
            _HSZ = 1024 * 1024
            while True:
                blk = fileobj.read(_HSZ)
                if not blk: break
                h.update(_to_bytes(blk))
            sha_hex = h.hexdigest()
            # restore
            if start_pos is not None:
                try: fileobj.seek(start_pos, os.SEEK_SET)
                except Exception: pass
            elif cur is not None:
                try: fileobj.seek(cur, os.SEEK_SET)
                except Exception: pass
        except Exception:
            sha_hex = None

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        try: srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except Exception: pass
        srv.bind((o["host"], o["port"]))
        srv.listen(1)

        # Wait loop: keep accepting until a client is served or wait expires
        started = time.time()
        per_accept = float(o["timeout"]) if o["timeout"] is not None else 1.0
        try: srv.settimeout(per_accept)
        except Exception: pass

        bytes_sent = 0

        while True:
            # stop conditions
            if bytes_sent > 0:
                break
            if (wait_seconds is not None) and ((time.time() - started) >= wait_seconds):
                break

            try:
                conn, peer = srv.accept()
            except socket.timeout:
                continue
            except Exception:
                break

            # Optional TLS
            if o["use_ssl"]:
                if not _ssl_available():
                    try: conn.close()
                    except Exception: pass
                    break
                conn = _ssl_wrap_socket(conn, server_side=True,
                                        server_hostname=None,
                                        verify=o["ssl_verify"],
                                        ca_file=o["ssl_ca_file"],
                                        certfile=o["ssl_certfile"],
                                        keyfile=o["ssl_keyfile"])
            # Per-connection timeout
            if o["timeout"] is not None:
                try: conn.settimeout(float(o["timeout"]))
                except Exception: pass

            try:
                # --------- AUTH handshake (AF1 preferred, legacy fallback) ---------
                ok = True
                if (o["user"] is not None) or (o["pw"] is not None) or o.get("force_auth", False):
                    # Expect an auth preface from client
                    try:
                        preface = conn.recv(4096)
                    except socket.timeout:
                        ok = False
                        preface = b""

                    if ok:
                        v_ok, v_user, v_scope, _r, _len, _sha = verify_auth_blob_v1(
                            preface or b"", expected_user=o["user"], secret=o["pw"],
                            max_skew=600, expect_scope=(parts.path or u"")
                        )
                        if v_ok:
                            ok = True
                        else:
                            u, p = _parse_auth_blob_legacy(preface or b"")
                            ok = (u is not None and
                                  (o["user"] is None or u == _to_bytes(o["user"])) and
                                  (o["pw"] is None or p == _to_bytes(o["pw"])))
                            # if enforcing path with legacy, optionally let the client
                            # send a second line with PATH <text> (best-effort)
                            if ok and enforce_path:
                                try:
                                    line = conn.recv(1024)
                                    if line and line.startswith(b"PATH "):
                                        want_path = _to_text(line[5:].strip())
                                        ok = (want_path == (parts.path or u""))
                                except Exception:
                                    pass

                    # Respond OK/NO then proceed/close
                    try: conn.sendall(_OK if ok else _NO)
                    except Exception: pass
                    if not ok:
                        try: conn.close()
                        except Exception: pass
                        continue

                # --------- Control preface: LEN ---------
                if total_bytes is not None:
                    # "LEN <bytes> <sha?>\n"
                    line = "LEN %d%s\n" % (
                        int(total_bytes),
                        ((" " + sha_hex) if sha_hex else "")
                    )
                else:
                    line = "LEN -1\n"
                try: conn.sendall(_to_bytes(line))
                except Exception:
                    try: conn.close()
                    except Exception: pass
                    continue

                # --------- Stream payload ---------
                if start_pos is not None:
                    try: fileobj.seek(start_pos, os.SEEK_SET)
                    except Exception: pass

                last_cb = time.time()
                rl_ts   = time.time()
                rl_bytes= 0
                CS = int(o["chunk_size"] or 65536)

                while True:
                    buf = fileobj.read(CS)
                    if not buf:
                        break
                    b = _to_bytes(buf)
                    try:
                        conn.sendall(b)
                    except Exception:
                        break
                    bytes_sent += len(b)

                    if on_progress and (time.time() - last_cb) >= 0.1:
                        try: on_progress(bytes_sent, total_bytes)
                        except Exception: pass
                        last_cb = time.time()

                    if rate_limit:
                        sleep_s, rl_ts, rl_bytes = _pace_rate(rl_ts, rl_bytes, int(rate_limit), len(b))
                        if sleep_s > 0.0:
                            time.sleep(sleep_s)

                # Unknown-length: send DONE marker so clients can stop cleanly
                if total_bytes is None:
                    try: conn.sendall(b"DONE\n")
                    except Exception: pass

            finally:
                try: conn.shutdown(socket.SHUT_RDWR)
                except Exception: pass
                try: conn.close()
                except Exception: pass

        return bytes_sent

    finally:
        try: srv.close()
        except Exception: pass

def run_udp_file_server(fileobj, url, on_progress=None):
    """
    One-shot UDP uploader: wait for a client auth/hello, reply OK, then
    send LEN + payload as datagrams (and DONE if unknown length).
    Ends after serving exactly one client or wait window elapses.

    URL example:
      udp://user:pass@0.0.0.0:5001/path/my.arc?
          auth=1&enforce_path=1&rate=250000&timeout=5&wait=30
    """
    parts, o = _parse_net_url(url)
    if o["proto"] != "udp":
        raise ValueError("run_udp_file_server requires udp:// URL")

    qs = parse_qs(parts.query or "")
    enforce_path = _qflag(qs, "enforce_path", True)
    want_sha      = _qflag(qs, "sha", True)
    rate_limit    = _qnum(qs, "rate", None, float)
    wait_seconds  = _qnum(qs, "wait", None, float)

    total_bytes, start_pos = _discover_len_and_reset(fileobj)
    sha_hex = None
    if want_sha and total_bytes is not None:
        try:
            import hashlib
            h = hashlib.sha256()
            cur = None
            try: cur = fileobj.tell()
            except Exception: pass
            if start_pos is not None:
                try: fileobj.seek(start_pos, os.SEEK_SET)
                except Exception: pass
            _HSZ = 1024 * 1024
            while True:
                blk = fileobj.read(_HSZ)
                if not blk: break
                h.update(_to_bytes(blk))
            sha_hex = h.hexdigest()
            if start_pos is not None:
                try: fileobj.seek(start_pos, os.SEEK_SET)
                except Exception: pass
            elif cur is not None:
                try: fileobj.seek(cur, os.SEEK_SET)
                except Exception: pass
        except Exception:
            sha_hex = None

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((o["host"], o["port"]))
        if o["timeout"] is not None:
            try: sock.settimeout(float(o["timeout"]))
            except Exception: pass

        started = time.time()
        CS = int(o["chunk_size"] or 65536)
        bytes_sent = 0
        client = None

        # ---------- wait for client hello/auth ----------
        while True:
            # overall wait window
            if (wait_seconds is not None) and ((time.time() - started) >= wait_seconds):
                break
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except Exception:
                break

            ok = True
            # Require auth if creds configured or ?auth=1
            force_auth = o.get("force_auth", False) or (o["user"] is not None) or (o["pw"] is not None)
            if force_auth:
                v_ok, v_user, v_scope, _r, _len, _sha = verify_auth_blob_v1(
                    data or b"", expected_user=o["user"], secret=o["pw"],
                    max_skew=600, expect_scope=(parts.path or u"")
                )
                if v_ok:
                    ok = True
                else:
                    u, p = _parse_auth_blob_legacy(data or b"")
                    ok = (u is not None and
                          (o["user"] is None or u == _to_bytes(o["user"])) and
                          (o["pw"] is None or p == _to_bytes(o["pw"])))
                    # optional legacy PATH check (best effort)
                    if ok and enforce_path:
                        try:
                            line, addr2 = sock.recvfrom(1024)
                            if addr2 == addr and line and line.startswith(b"PATH "):
                                want_path = _to_text(line[5:].strip())
                                ok = (want_path == (parts.path or u""))
                        except Exception:
                            pass

            try: sock.sendto((_OK if ok else _NO), addr)
            except Exception:
                ok = False

            if ok:
                client = addr
                break

        if not client:
            return 0

        # ---------- send LEN preface ----------
        if total_bytes is not None:
            line = "LEN %d%s\n" % (int(total_bytes), ((" " + sha_hex) if sha_hex else ""))
        else:
            line = "LEN -1\n"
        try:
            sock.sendto(_to_bytes(line), client)
        except Exception:
            return 0

        # ---------- stream payload ----------
        if start_pos is not None:
            try: fileobj.seek(start_pos, os.SEEK_SET)
            except Exception: pass

        last_cb = time.time()
        rl_ts   = time.time()
        rl_bytes= 0

        while True:
            buf = fileobj.read(CS)
            if not buf:
                break
            b = _to_bytes(buf)
            try:
                sock.sendto(b, client)
            except Exception:
                break
            bytes_sent += len(b)

            if on_progress and (time.time() - last_cb) >= 0.1:
                try: on_progress(bytes_sent, total_bytes)
                except Exception: pass
                last_cb = time.time()

            if rate_limit:
                sleep_s, rl_ts, rl_bytes = _pace_rate(rl_ts, rl_bytes, int(rate_limit), len(b))
                if sleep_s > 0.0:
                    time.sleep(sleep_s)

        # Unknown length: send DONE marker to signal end to the client
        if total_bytes is None:
            try: sock.sendto(b"DONE\n", client)
            except Exception:
                pass

        return bytes_sent

    finally:
        try: sock.close()
        except Exception: pass


class _OneShotHTTPServer(HTTPServer):
    allow_reuse_address = True


# ======================================
# One-shot HTTP/HTTPS file upload server
# ======================================
def run_http_file_server(fileobj, url, on_progress=None, backlog=5):
    # --- parse & precompute (unchanged) ---
    parts, o = _parse_http_url(url)
    
    total_bytes, start_pos = _discover_len_and_reset(fileobj)
    sha_hex = None
    if o["want_sha"] and total_bytes is not None:
        try:
            import hashlib, os
            h = hashlib.sha256()
            try: cur = fileobj.tell()
            except Exception: cur = None
            if start_pos is not None:
                try: fileobj.seek(start_pos, os.SEEK_SET)
                except Exception: pass
            _HSZ = 1024 * 1024
            while True:
                blk = fileobj.read(_HSZ)
                if not blk: break
                h.update(_to_bytes(blk))
            sha_hex = h.hexdigest()
            if start_pos is not None:
                try: fileobj.seek(start_pos, os.SEEK_SET)
                except Exception: pass
            elif cur is not None:
                try: fileobj.seek(cur, os.SEEK_SET)
                except Exception: pass
        except Exception:
            sha_hex = None

    expected_path = _to_text(o["path"] or u"/")

    state = dict(
        fileobj=fileobj,
        total=total_bytes,
        sha=sha_hex,
        chunk_size=int(o["chunk_size"] or 65536),
        mime=_to_text(o["mime"]),
        enforce_path=bool(o["enforce_path"]),
        require_auth=bool(o["require_auth"]),
        expected_path=expected_path,
        expected_user=o["user"],
        expected_pass=o["pw"],
        timeout=o["timeout"],
        on_progress=on_progress,
        bytes_sent=0,
        extra_headers=o.get("extra_headers") or {},
        rate_limit_bps=o.get("rate_limit_bps") or None
    )

    class Handler(BaseHTTPRequestHandler):
        # def log_message(self, fmt, *args): pass

        def _fail_401(self):
            self.send_response(401, "Unauthorized")
            self.send_header("WWW-Authenticate", 'Basic realm="file"')
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            try: self.wfile.write(_to_bytes("Unauthorized\n"))
            except Exception: pass

        def _fail_404(self):
            self.send_response(404, "Not Found")
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            try: self.wfile.write(_to_bytes("Not Found\n"))
            except Exception: pass

        def _ok_headers(self, length_known):
            self.send_response(200, "OK")
            self.send_header("Content-Type", state["mime"])
            if length_known and state["total"] is not None:
                self.send_header("Content-Length", str(int(state["total"])))
            else:
                self.send_header("Transfer-Encoding", "chunked")
            if state["sha"]:
                self.send_header("ETag", '"%s"' % state["sha"])
                self.send_header("X-File-SHA256", state["sha"])
            if state["total"] is not None:
                self.send_header("X-File-Length", str(int(state["total"])))
            for k, v in (state["extra_headers"] or {}).items():
                try: self.send_header(_to_text(k), _to_text(v))
                except Exception: pass
            self.end_headers()

        def _path_only(self):
            p = _urlparse(self.path or "/")
            try:
                from urllib.parse import unquote
            except ImportError:
                from urllib import unquote
            return _to_text(unquote(p.path or "/"))

        def _check_basic_auth(self):
            if not state["require_auth"]:
                return True
            ah = self.headers.get("Authorization")
            if not ah or not ah.strip().lower().startswith("basic "):
                return False
            try:
                import base64
                b64 = ah.strip().split(" ", 1)[1]
                raw = base64.b64decode(_to_bytes(b64))
                try: raw_txt = raw.decode("utf-8")
                except Exception: raw_txt = raw.decode("latin-1", "replace")
                if ":" not in raw_txt: return False
                u, p = raw_txt.split(":", 1)
                if state["expected_user"] is not None and u != _to_text(state["expected_user"]): return False
                if state["expected_pass"] is not None and p != _to_text(state["expected_pass"]): return False
                return True
            except Exception:
                return False

        def _serve_body(self, method):
            if state["timeout"] is not None:
                try: self.connection.settimeout(state["timeout"])
                except Exception: pass

            if method == "HEAD":
                self._ok_headers(length_known=(state["total"] is not None))
                return

            # GET body
            if state["total"] is not None:
                self._ok_headers(length_known=True)
                if start_pos is not None:
                    try: state["fileobj"].seek(start_pos, os.SEEK_SET)
                    except Exception: pass

                cs = state["chunk_size"]
                last_cb = time.time()
                rl_ts = time.time()
                rl_bytes = 0

                while True:
                    buf = state["fileobj"].read(cs)
                    if not buf: break
                    b = _to_bytes(buf)
                    try: self.wfile.write(b)
                    except Exception: break
                    state["bytes_sent"] += len(b)

                    if state["on_progress"] and (time.time() - last_cb) >= 0.1:
                        try: state["on_progress"](state["bytes_sent"], state["total"])
                        except Exception: pass
                        last_cb = time.time()

                    if state["rate_limit_bps"]:
                        sleep_s, rl_ts, rl_bytes = _pace_rate(rl_ts, rl_bytes, state["rate_limit_bps"], add_bytes=len(b))
                        if sleep_s > 0.0: time.sleep(sleep_s)
            else:
                # unknown length → chunked
                self._ok_headers(length_known=False)
                cs = state["chunk_size"]
                last_cb = time.time()
                rl_ts = time.time()
                rl_bytes = 0

                while True:
                    buf = state["fileobj"].read(cs)
                    if not buf:
                        try: self.wfile.write(b"0\r\n\r\n")
                        except Exception: pass
                        break
                    b = _to_bytes(buf)
                    try:
                        self.wfile.write(("%x\r\n" % len(b)).encode("ascii"))
                        self.wfile.write(b)
                        self.wfile.write(b"\r\n")
                    except Exception: break
                    state["bytes_sent"] += len(b)

                    if state["on_progress"] and (time.time() - last_cb) >= 0.1:
                        try: state["on_progress"](state["bytes_sent"], None)
                        except Exception: pass
                        last_cb = time.time()

                    if state["rate_limit_bps"]:
                        sleep_s, rl_ts, rl_bytes = _pace_rate(rl_ts, rl_bytes, state["rate_limit_bps"], add_bytes=len(b))
                        if sleep_s > 0.0: time.sleep(sleep_s)

        def _handle(self, method):
            req_path = self._path_only()
            if state["enforce_path"] and (req_path != state["expected_path"]):
                return self._fail_404()
            if not self._check_basic_auth():
                return self._fail_401()
            return self._serve_body(method)

        def do_GET(self):  return self._handle("GET")
        def do_HEAD(self): return self._handle("HEAD")

    # HTTP server with reuse + explicit select-based wait
    class _OneShotHTTPServer(HTTPServer):
        allow_reuse_address = True

    server_address = (o["host"], o["port"])
    httpd = _OneShotHTTPServer(server_address, Handler)

    # TLS if https
    if o["scheme"] == "https":
        import ssl
        if not o["certfile"]:
            httpd.server_close()
            raise ValueError("HTTPS requires ?cert=/path/cert.pem (and optionally &key=...)")
        try:
            httpd.socket = ssl.wrap_socket(
                httpd.socket, certfile=o["certfile"], keyfile=o["keyfile"], server_side=True
            )
        except Exception:
            httpd.server_close()
            raise

    # ---------- WAIT LOOP (select + handle_request) ----------
    wait_seconds = o.get("wait_seconds", None)  # None = wait indefinitely
    started = time.time()

    # set both socket and server timeouts
    per_accept = 1.0 if o["timeout"] is None else float(o["timeout"])
    try: httpd.socket.settimeout(per_accept)
    except Exception: pass
    try: httpd.timeout = per_accept
    except Exception: pass

    try:
        import select
        while True:
            if state["bytes_sent"] > 0:
                break
            if wait_seconds is not None and (time.time() - started) >= wait_seconds:
                break

            # poll the listening socket; only call handle_request if ready
            try:
                rlist, _, _ = select.select([httpd.socket], [], [], per_accept)
            except Exception:
                rlist = []

            if not rlist:
                continue

            try:
                httpd.handle_request()
            except socket.timeout:
                # keep looping
                continue
            except Exception:
                # unexpected error; exit loop
                break
    finally:
        try: httpd.server_close()
        except Exception: pass

    return state["bytes_sent"]



def run_tcp_file_server(fileobj, url, on_progress=None):
    """
    One-shot TCP uploader: wait for a client, authenticate (optional),
    then send control preface (LEN...), followed by the file bytes.
    Ends after serving exactly one client or wait window elapses.

    URL example:
      tcp://user:pass@0.0.0.0:5000/path/my.arc?
          auth=1&enforce_path=1&rate=200000&timeout=5&wait=30&ssl=0
    """
    parts, o = _parse_net_url(url)  # already returns proto/host/port/timeout/ssl/etc.
    if o["proto"] != "tcp":
        raise ValueError("run_tcp_file_server requires tcp:// URL")

    # Pull extras from the query string (enforce_path, want_sha, rate, wait)
    qs = parse_qs(parts.query or "")
    enforce_path = _qflag(qs, "enforce_path", True)
    want_sha      = _qflag(qs, "sha", True)
    rate_limit    = _qnum(qs, "rate", None, float)
    wait_seconds  = _qnum(qs, "wait", None, float)  # None = wait forever

    # Discover length (and precompute sha if requested & length known)
    total_bytes, start_pos = _discover_len_and_reset(fileobj)
    sha_hex = None
    if want_sha and total_bytes is not None:
        try:
            import hashlib
            h = hashlib.sha256()
            # hash current stream content
            cur = None
            try: cur = fileobj.tell()
            except Exception: pass
            if start_pos is not None:
                try: fileobj.seek(start_pos, os.SEEK_SET)
                except Exception: pass
            _HSZ = 1024 * 1024
            while True:
                blk = fileobj.read(_HSZ)
                if not blk: break
                h.update(_to_bytes(blk))
            sha_hex = h.hexdigest()
            # restore
            if start_pos is not None:
                try: fileobj.seek(start_pos, os.SEEK_SET)
                except Exception: pass
            elif cur is not None:
                try: fileobj.seek(cur, os.SEEK_SET)
                except Exception: pass
        except Exception:
            sha_hex = None

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        try: srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except Exception: pass
        srv.bind((o["host"], o["port"]))
        srv.listen(1)

        # Wait loop: keep accepting until a client is served or wait expires
        started = time.time()
        per_accept = float(o["timeout"]) if o["timeout"] is not None else 1.0
        try: srv.settimeout(per_accept)
        except Exception: pass

        bytes_sent = 0

        while True:
            # stop conditions
            if bytes_sent > 0:
                break
            if (wait_seconds is not None) and ((time.time() - started) >= wait_seconds):
                break

            try:
                conn, peer = srv.accept()
            except socket.timeout:
                continue
            except Exception:
                break

            # Optional TLS
            if o["use_ssl"]:
                if not _ssl_available():
                    try: conn.close()
                    except Exception: pass
                    break
                conn = _ssl_wrap_socket(conn, server_side=True,
                                        server_hostname=None,
                                        verify=o["ssl_verify"],
                                        ca_file=o["ssl_ca_file"],
                                        certfile=o["ssl_certfile"],
                                        keyfile=o["ssl_keyfile"])
            # Per-connection timeout
            if o["timeout"] is not None:
                try: conn.settimeout(float(o["timeout"]))
                except Exception: pass

            try:
                # --------- AUTH handshake (AF1 preferred, legacy fallback) ---------
                ok = True
                if (o["user"] is not None) or (o["pw"] is not None) or o.get("force_auth", False):
                    # Expect an auth preface from client
                    try:
                        preface = conn.recv(4096)
                    except socket.timeout:
                        ok = False
                        preface = b""

                    if ok:
                        v_ok, v_user, v_scope, _r, _len, _sha = verify_auth_blob_v1(
                            preface or b"", expected_user=o["user"], secret=o["pw"],
                            max_skew=600, expect_scope=(parts.path or u"")
                        )
                        if v_ok:
                            ok = True
                        else:
                            u, p = _parse_auth_blob_legacy(preface or b"")
                            ok = (u is not None and
                                  (o["user"] is None or u == _to_bytes(o["user"])) and
                                  (o["pw"] is None or p == _to_bytes(o["pw"])))
                            # if enforcing path with legacy, optionally let the client
                            # send a second line with PATH <text> (best-effort)
                            if ok and enforce_path:
                                try:
                                    line = conn.recv(1024)
                                    if line and line.startswith(b"PATH "):
                                        want_path = _to_text(line[5:].strip())
                                        ok = (want_path == (parts.path or u""))
                                except Exception:
                                    pass

                    # Respond OK/NO then proceed/close
                    try: conn.sendall(_OK if ok else _NO)
                    except Exception: pass
                    if not ok:
                        try: conn.close()
                        except Exception: pass
                        continue

                # --------- Control preface: LEN ---------
                if total_bytes is not None:
                    # "LEN <bytes> <sha?>\n"
                    line = "LEN %d%s\n" % (
                        int(total_bytes),
                        ((" " + sha_hex) if sha_hex else "")
                    )
                else:
                    line = "LEN -1\n"
                try: conn.sendall(_to_bytes(line))
                except Exception:
                    try: conn.close()
                    except Exception: pass
                    continue

                # --------- Stream payload ---------
                if start_pos is not None:
                    try: fileobj.seek(start_pos, os.SEEK_SET)
                    except Exception: pass

                last_cb = time.time()
                rl_ts   = time.time()
                rl_bytes= 0
                CS = int(o["chunk_size"] or 65536)

                while True:
                    buf = fileobj.read(CS)
                    if not buf:
                        break
                    b = _to_bytes(buf)
                    try:
                        conn.sendall(b)
                    except Exception:
                        break
                    bytes_sent += len(b)

                    if on_progress and (time.time() - last_cb) >= 0.1:
                        try: on_progress(bytes_sent, total_bytes)
                        except Exception: pass
                        last_cb = time.time()

                    if rate_limit:
                        sleep_s, rl_ts, rl_bytes = _pace_rate(rl_ts, rl_bytes, int(rate_limit), len(b))
                        if sleep_s > 0.0:
                            time.sleep(sleep_s)

                # Unknown-length: send DONE marker so clients can stop cleanly
                if total_bytes is None:
                    try: conn.sendall(b"DONE\n")
                    except Exception: pass

            finally:
                try: conn.shutdown(socket.SHUT_RDWR)
                except Exception: pass
                try: conn.close()
                except Exception: pass

        return bytes_sent

    finally:
        try: srv.close()
        except Exception: pass

def recv_to_fileobj(fileobj, host="", port=0, proto="tcp", timeout=None,
                    max_bytes=None, chunk_size=65536, backlog=1,
                    use_ssl=False, ssl_verify=True, ssl_ca_file=None,
                    ssl_certfile=None, ssl_keyfile=None,
                    require_auth=False, expected_user=None, expected_pass=None,
                    total_timeout=None, expect_scope=None,
                    on_progress=None, rate_limit_bps=None,
                    enforce_path=True, wait_seconds=None):
    """
    Receive bytes into fileobj over TCP/UDP.

    Path enforcement:
      - UDP: expects 'PATH <...>\\n' control frame first (if enforce_path).
      - TCP: reads first line 'PATH <...>\\n' before auth/payload (if enforce_path).

    UDP control frames understood: PATH, LEN, HASH, DONE (+ AF1 auth blob).

    wait_seconds (TCP only): overall accept window to wait for a client
      (mirrors the HTTP server behavior). None = previous behavior (single accept
      with 'timeout' as the accept timeout).
    """
    proto = (proto or "tcp").lower()
    port = int(port)
    total = 0

    start_ts = time.time()
    def _time_left():
        if total_timeout is None:
            return None
        left = total_timeout - (time.time() - start_ts)
        return 0.0 if left <= 0 else left

    def _set_effective_timeout(socklike, base_timeout):
        left = _time_left()
        if left == 0.0:
            return False
        eff = base_timeout
        if left is not None:
            eff = left if eff is None else min(eff, left)
        if eff is not None:
            try:
                socklike.settimeout(eff)
            except Exception:
                pass
        return True

    if proto not in ("tcp", "udp"):
        raise ValueError("proto must be 'tcp' or 'udp'")

    # ---------------- UDP server ----------------
    if proto == "udp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        authed_addr = None
        expected_len = None
        expected_sha = None
        path_checked = (not enforce_path)

        try:
            sock.bind(("", port))
            if timeout is None:
                try: sock.settimeout(10.0)
                except Exception: pass

            recvd_so_far = 0
            last_cb_ts = monotonic()
            rl_ts = last_cb_ts
            rl_bytes = 0

            while True:
                if _time_left() == 0.0:
                    if expected_len is not None and total < expected_len:
                        raise RuntimeError("UDP receive aborted by total_timeout before full payload received")
                    break
                if (max_bytes is not None) and (total >= max_bytes):
                    break

                if not _set_effective_timeout(sock, timeout):
                    if expected_len is not None and total < expected_len:
                        raise RuntimeError("UDP receive timed out before full payload received")
                    if expected_len is None and total > 0:
                        raise RuntimeError("UDP receive timed out with unknown length; partial data")
                    if expected_len is None and total == 0:
                        raise RuntimeError("UDP receive: no packets received before timeout (is the sender running?)")
                    break

                try:
                    data, addr = sock.recvfrom(chunk_size)
                except socket.timeout:
                    if expected_len is not None and total < expected_len:
                        raise RuntimeError("UDP receive idle-timeout before full payload received")
                    if expected_len is None and total > 0:
                        raise RuntimeError("UDP receive idle-timeout with unknown length; partial data")
                    if expected_len is None and total == 0:
                        raise RuntimeError("UDP receive: no packets received before timeout (is the sender running?)")
                    break

                if not data:
                    continue

                # (0) PATH first (strict)
                if not path_checked and data.startswith(b"PATH "):
                    got_path = _unquote_path_from_wire(data[5:].strip())
                    if _to_text(got_path) != _to_text(expect_scope or u""):
                        raise RuntimeError("UDP path mismatch: got %r expected %r"
                                           % (got_path, expect_scope))
                    path_checked = True
                    continue
                if enforce_path and not path_checked:
                    if not data.startswith(b"PATH "):
                        continue  # ignore until PATH arrives

                # (0b) Control frames
                if data.startswith(b"LEN ") and expected_len is None:
                    try:
                        parts = data.strip().split()
                        n = int(parts[1])
                        expected_len = (None if n < 0 else n)
                        if len(parts) >= 3:
                            expected_sha = parts[2].decode("ascii")
                    except Exception:
                        expected_len = None; expected_sha = None
                    continue

                if data.startswith(b"HASH "):
                    try:
                        expected_sha = data.strip().split()[1].decode("ascii")
                    except Exception:
                        expected_sha = None
                    continue

                if data == b"DONE\n":
                    break

                # (1) Auth (if required)
                if authed_addr is None and require_auth:
                    ok = False
                    v_ok, v_user, v_scope, _r, v_len, v_sha = verify_auth_blob_v1(
                        data, expected_user=expected_user, secret=expected_pass,
                        max_skew=600, expect_scope=expect_scope
                    )
                    if v_ok:
                        ok = True
                        if expected_len is None:
                            expected_len = v_len
                        if expected_sha is None:
                            expected_sha = v_sha
                    else:
                        user, pw = _parse_auth_blob_legacy(data)
                        ok = (user is not None and
                              (expected_user is None or user == _to_bytes(expected_user)) and
                              (expected_pass is None or pw == _to_bytes(expected_pass)))
                    try:
                        sock.sendto((_OK if ok else _NO), addr)
                    except Exception:
                        pass
                    if ok:
                        authed_addr = addr
                    continue

                if require_auth and addr != authed_addr:
                    continue

                # (2) Payload
                fileobj.write(data)
                try: fileobj.flush()
                except Exception: pass
                total += len(data)
                recvd_so_far += len(data)

                if rate_limit_bps:
                    sleep_s, rl_ts, rl_bytes = _pace_rate(rl_ts, rl_bytes, rate_limit_bps, len(data))
                    if sleep_s > 0.0:
                        time.sleep(min(sleep_s, 0.25))

                if on_progress and (monotonic() - last_cb_ts) >= 0.1:
                    try: on_progress(recvd_so_far, expected_len)
                    except Exception: pass
                    last_cb_ts = monotonic()

                if expected_len is not None and total >= expected_len:
                    break

            # Post-conditions
            if expected_len is not None and total != expected_len:
                raise RuntimeError("UDP receive incomplete: got %d of %s bytes" % (total, expected_len))

            if expected_sha:
                import hashlib
                try:
                    cur = fileobj.tell(); fileobj.seek(0)
                except Exception:
                    cur = None
                h = hashlib.sha256(); _HSZ = 1024 * 1024
                while True:
                    blk = fileobj.read(_HSZ)
                    if not blk: break
                    h.update(_to_bytes(blk))
                got = h.hexdigest()
                if cur is not None:
                    try: fileobj.seek(cur)
                    except Exception: pass
                if got != expected_sha:
                    raise RuntimeError("UDP checksum mismatch: got %s expected %s" % (got, expected_sha))

        finally:
            try: sock.close()
            except Exception: pass
        return total

    # ---------------- TCP server (one-shot with optional wait window) ----------------
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        try: srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except Exception: pass
        srv.bind((host or "", port))
        srv.listen(int(backlog) if backlog else 1)

        bytes_written = 0
        started = time.time()

        # per-accept wait
        per_accept = float(timeout) if timeout is not None else 1.0
        try: srv.settimeout(per_accept)
        except Exception: pass

        while True:
            if bytes_written > 0:
                break
            if wait_seconds is not None and (time.time() - started) >= wait_seconds:
                break

            try:
                conn, _peer = srv.accept()
            except socket.timeout:
                continue
            except Exception:
                break

            # TLS
            if use_ssl:
                if not _ssl_available():
                    try: conn.close()
                    except Exception: pass
                    break
                if not ssl_certfile:
                    try: conn.close()
                    except Exception: pass
                    raise ValueError("TLS server requires ssl_certfile (and usually ssl_keyfile).")
                conn = _ssl_wrap_socket(conn, server_side=True, server_hostname=None,
                                        verify=ssl_verify, ca_file=ssl_ca_file,
                                        certfile=ssl_certfile, keyfile=ssl_keyfile)

            recvd_so_far = 0
            last_cb_ts = monotonic()
            rl_ts = last_cb_ts
            rl_bytes = 0

            try:
                # (0) PATH line (if enforced)
                if enforce_path:
                    line = _recv_line(conn, maxlen=4096, timeout=timeout)
                    if not line or not line.startswith(b"PATH "):
                        try: conn.close()
                        except Exception: pass
                        continue
                    got_path = _unquote_path_from_wire(line[5:].strip())
                    if _to_text(got_path) != _to_text(expect_scope or u""):
                        try: conn.close()
                        except Exception: pass
                        raise RuntimeError("TCP path mismatch: got %r expected %r"
                                           % (got_path, expect_scope))

                # (1) Auth preface
                if require_auth:
                    if not _set_effective_timeout(conn, timeout):
                        try: conn.close()
                        except Exception: pass
                        continue
                    try:
                        preface = conn.recv(2048)
                    except socket.timeout:
                        try: conn.sendall(_NO)
                        except Exception: pass
                        try: conn.close()
                        except Exception: pass
                        continue

                    ok = False
                    v_ok, v_user, v_scope, _r, v_len, v_sha = verify_auth_blob_v1(
                        preface or b"", expected_user=expected_user, secret=expected_pass,
                        max_skew=600, expect_scope=expect_scope
                    )
                    if v_ok:
                        ok = True
                    else:
                        user, pw = _parse_auth_blob_legacy(preface or b"")
                        ok = (user is not None and
                              (expected_user is None or user == _to_bytes(expected_user)) and
                              (expected_pass is None or pw == _to_bytes(expected_pass)))
                    try: conn.sendall(_OK if ok else _NO)
                    except Exception: pass
                    if not ok:
                        try: conn.close()
                        except Exception: pass
                        continue

                # (2) Payload loop
                while True:
                    if _time_left() == 0.0: break
                    if (max_bytes is not None) and (bytes_written >= max_bytes): break

                    if not _set_effective_timeout(conn, timeout):
                        break
                    try:
                        data = conn.recv(chunk_size)
                    except socket.timeout:
                        break
                    if not data:
                        break

                    fileobj.write(data)
                    try: fileobj.flush()
                    except Exception: pass
                    total += len(data)
                    bytes_written += len(data)
                    recvd_so_far += len(data)

                    if rate_limit_bps:
                        sleep_s, rl_ts, rl_bytes = _pace_rate(rl_ts, rl_bytes, rate_limit_bps, len(data))
                        if sleep_s > 0.0:
                            time.sleep(min(sleep_s, 0.25))

                    if on_progress and (monotonic() - last_cb_ts) >= 0.1:
                        try: on_progress(recvd_so_far, max_bytes)
                        except Exception: pass
                        last_cb_ts = monotonic()

            finally:
                try: conn.shutdown(socket.SHUT_RD)
                except Exception: pass
                try: conn.close()
                except Exception: pass

        return total

    finally:
        try: srv.close()
        except Exception: pass


def run_udp_file_server(fileobj, url, on_progress=None):
    """
    One-shot UDP uploader: wait for a client auth/hello, reply OK, then
    send LEN + payload as datagrams (and DONE if unknown length).
    Ends after serving exactly one client or wait window elapses.

    URL example:
      udp://user:pass@0.0.0.0:5001/path/my.arc?
          auth=1&enforce_path=1&rate=250000&timeout=5&wait=30
    """
    parts, o = _parse_net_url(url)
    if o["proto"] != "udp":
        raise ValueError("run_udp_file_server requires udp:// URL")

    qs = parse_qs(parts.query or "")
    enforce_path = _qflag(qs, "enforce_path", True)
    want_sha      = _qflag(qs, "sha", True)
    rate_limit    = _qnum(qs, "rate", None, float)
    wait_seconds  = _qnum(qs, "wait", None, float)

    total_bytes, start_pos = _discover_len_and_reset(fileobj)
    sha_hex = None
    if want_sha and total_bytes is not None:
        try:
            import hashlib
            h = hashlib.sha256()
            cur = None
            try: cur = fileobj.tell()
            except Exception: pass
            if start_pos is not None:
                try: fileobj.seek(start_pos, os.SEEK_SET)
                except Exception: pass
            _HSZ = 1024 * 1024
            while True:
                blk = fileobj.read(_HSZ)
                if not blk: break
                h.update(_to_bytes(blk))
            sha_hex = h.hexdigest()
            if start_pos is not None:
                try: fileobj.seek(start_pos, os.SEEK_SET)
                except Exception: pass
            elif cur is not None:
                try: fileobj.seek(cur, os.SEEK_SET)
                except Exception: pass
        except Exception:
            sha_hex = None

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((o["host"], o["port"]))
        if o["timeout"] is not None:
            try: sock.settimeout(float(o["timeout"]))
            except Exception: pass

        started = time.time()
        CS = int(o["chunk_size"] or 65536)
        bytes_sent = 0
        client = None

        # ---------- wait for client hello/auth ----------
        while True:
            # overall wait window
            if (wait_seconds is not None) and ((time.time() - started) >= wait_seconds):
                break
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except Exception:
                break

            ok = True
            # Require auth if creds configured or ?auth=1
            force_auth = o.get("force_auth", False) or (o["user"] is not None) or (o["pw"] is not None)
            if force_auth:
                v_ok, v_user, v_scope, _r, _len, _sha = verify_auth_blob_v1(
                    data or b"", expected_user=o["user"], secret=o["pw"],
                    max_skew=600, expect_scope=(parts.path or u"")
                )
                if v_ok:
                    ok = True
                else:
                    u, p = _parse_auth_blob_legacy(data or b"")
                    ok = (u is not None and
                          (o["user"] is None or u == _to_bytes(o["user"])) and
                          (o["pw"] is None or p == _to_bytes(o["pw"])))
                    # optional legacy PATH check (best effort)
                    if ok and enforce_path:
                        try:
                            line, addr2 = sock.recvfrom(1024)
                            if addr2 == addr and line and line.startswith(b"PATH "):
                                want_path = _to_text(line[5:].strip())
                                ok = (want_path == (parts.path or u""))
                        except Exception:
                            pass

            try: sock.sendto((_OK if ok else _NO), addr)
            except Exception:
                ok = False

            if ok:
                client = addr
                break

        if not client:
            return 0

        # ---------- send LEN preface ----------
        if total_bytes is not None:
            line = "LEN %d%s\n" % (int(total_bytes), ((" " + sha_hex) if sha_hex else ""))
        else:
            line = "LEN -1\n"
        try:
            sock.sendto(_to_bytes(line), client)
        except Exception:
            return 0

        # ---------- stream payload ----------
        if start_pos is not None:
            try: fileobj.seek(start_pos, os.SEEK_SET)
            except Exception: pass

        last_cb = time.time()
        rl_ts   = time.time()
        rl_bytes= 0

        while True:
            buf = fileobj.read(CS)
            if not buf:
                break
            b = _to_bytes(buf)
            try:
                sock.sendto(b, client)
            except Exception:
                break
            bytes_sent += len(b)

            if on_progress and (time.time() - last_cb) >= 0.1:
                try: on_progress(bytes_sent, total_bytes)
                except Exception: pass
                last_cb = time.time()

            if rate_limit:
                sleep_s, rl_ts, rl_bytes = _pace_rate(rl_ts, rl_bytes, int(rate_limit), len(b))
                if sleep_s > 0.0:
                    time.sleep(sleep_s)

        # Unknown length: send DONE marker to signal end to the client
        if total_bytes is None:
            try: sock.sendto(b"DONE\n", client)
            except Exception:
                pass

        return bytes_sent

    finally:
        try: sock.close()
        except Exception: pass


# ---------- URL drivers ----------
def send_via_url(fileobj, url, send_from_fileobj_func=send_from_fileobj):
    parts, o = _parse_net_url(url)
    use_auth = (o["user"] is not None and o["pw"] is not None) or o["force_auth"]
    return send_from_fileobj_func(
        fileobj,
        o["host"], o["port"], proto=o["proto"],
        timeout=o["timeout"], chunk_size=o["chunk_size"],
        use_ssl=o["use_ssl"], ssl_verify=o["ssl_verify"],
        ssl_ca_file=o["ssl_ca_file"], ssl_certfile=o["ssl_certfile"], ssl_keyfile=o["ssl_keyfile"],
        server_hostname=o["server_hostname"],
        auth_user=(o["user"] if use_auth else None),
        auth_pass=(o["pw"]   if use_auth else None),
        auth_scope=o["path"],
        want_sha=o["want_sha"],
        enforce_path=o["enforce_path"],
        path_text=o["path"],
    )


def recv_via_url(fileobj, url, recv_to_fileobj_func=recv_to_fileobj):
    parts, o = _parse_net_url(url)
    require_auth = (o["user"] is not None and o["pw"] is not None) or o["force_auth"]
    return recv_to_fileobj_func(
        fileobj,
        o["host"], o["port"], proto=o["proto"],
        timeout=o["timeout"], total_timeout=o["total_timeout"],
        chunk_size=o["chunk_size"],
        use_ssl=o["use_ssl"], ssl_verify=o["ssl_verify"],
        ssl_ca_file=o["ssl_ca_file"], ssl_certfile=o["ssl_certfile"], ssl_keyfile=o["ssl_keyfile"],
        require_auth=require_auth,
        expected_user=o["user"], expected_pass=o["pw"],
        expect_scope=o["path"],
        enforce_path=o["enforce_path"],
    )

# ------------------------------
# HTTP/HTTPS URL drivers (server/client)
# ------------------------------

def send_via_http(fileobj, url, send_server_func=None, on_progress=None, backlog=5):
    """
    SERVER SIDE (uploader): serve 'fileobj' once via HTTP/HTTPS according to URL.
    Equivalent to send_via_url but for http(s)://
    
    Args:
        fileobj: readable file-like object positioned at the start of the data to serve
        url (str): http(s)://[user:pass@]host:port/path?query...
        send_server_func: optional override (defaults to run_http_file_server)
        on_progress: optional callback(bytes_sent, total_or_None)
        backlog (int): listen backlog (for the one accepted request)
    Returns:
        int: total bytes sent to the client (0 if none)
    """
    if send_server_func is None:
        # Provided earlier; tiny HTTP/HTTPS one-shot server with path/auth/sha support
        send_server_func = run_http_file_server
    return send_server_func(fileobj, url, on_progress=on_progress, backlog=backlog)


def recv_via_http(fileobj, url, http_download_func=None, copy_chunk_size=65536):
    """
    CLIENT SIDE (downloader): fetch via HTTP/HTTPS and copy into fileobj.
    Supports ?h=/headers=…/hjson=… for outbound request headers,
    and ?rate=… to throttle local write rate (bytes/sec).
    """
    if http_download_func is None:
        http_download_func = download_file_from_http_file

    # Extract client-side extras: headers + optional write rate
    u = urlparse(url)
    qs = parse_qs(u.query or "")
    client_headers = _parse_headers_from_qs(qs)
    rate_limit_bps = _qnum(qs, "rate", None, float)  # client write pacing

    # Use your downloader (it accepts headers=)
    tmpfp = http_download_func(url, headers=client_headers)
    total = 0
    try:
        try: tmpfp.seek(0)
        except Exception: pass

        last_ts = time.time()
        bytes_since = 0

        while True:
            chunk = tmpfp.read(copy_chunk_size)
            if not chunk:
                break
            b = _to_bytes(chunk)
            fileobj.write(b)
            total += len(b)

            # client-side pacing (write throttling)
            if rate_limit_bps:
                sleep_s, last_ts, bytes_since = _pace_rate(last_ts, bytes_since, int(rate_limit_bps), len(b))
                if sleep_s > 0.0:
                    time.sleep(sleep_s)

        try: fileobj.flush()
        except Exception: pass
    finally:
        try: tmpfp.close()
        except Exception: pass
    return total
