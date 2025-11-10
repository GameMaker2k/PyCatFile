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

    $FileInfo: pycatfile.py - Last Update: 11/6/2025 Ver. 0.25.2 RC 1 - Author: cooldude2k $
'''

from __future__ import absolute_import, division, print_function, unicode_literals, generators, with_statement, nested_scopes
import io
import os
import re
import sys
import time
import stat
import zlib
import mmap
import hmac
import base64
import shutil
import socket
import struct
import hashlib
import inspect
import logging
import zipfile
import binascii
import datetime
import platform
from io import StringIO, BytesIO
from collections import namedtuple
import posixpath  # POSIX-safe joins/normpaths
try:
    from backports import tempfile
except ImportError:
    import tempfile

try:
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from socketserver import TCPServer
    from urllib.parse import urlparse, parse_qs
    import base64
except ImportError:
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
    from SocketServer import TCPServer
    from urlparse import urlparse, parse_qs
    import base64

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

testyaml = False
try:
    import oyaml as yaml
    testyaml = True
except ImportError:
    try:
        import yaml
        testyaml = True
    except ImportError:
        testyaml = False

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
try:
    long
except NameError:  # Py3
    long = int
try:
    PermissionError
except NameError:  # Py2
    PermissionError = OSError

if PY2:
    # In Py2, 'str' is bytes; define a 'bytes' alias for clarity
    bytes_type = str
    text_type = unicode  # noqa: F821 (Py2-only)
else:
    bytes_type = bytes
    text_type = str

# Text streams (as provided by Python)
PY_STDIN_TEXT  = sys.stdin
PY_STDOUT_TEXT = sys.stdout
PY_STDERR_TEXT = sys.stderr

# Binary-friendly streams (use .buffer on Py3, fall back on Py2)
PY_STDIN_BUF  = getattr(sys.stdin,  "buffer", sys.stdin)
PY_STDOUT_BUF = getattr(sys.stdout, "buffer", sys.stdout)
PY_STDERR_BUF = getattr(sys.stderr, "buffer", sys.stderr)

# Text vs bytes tuples you can use with isinstance()
TEXT_TYPES   = (basestring,)                  # "str or unicode" on Py2, "str" on Py3
BINARY_TYPES = (bytes,) if not PY2 else (str,)  # bytes on Py3, str on Py2
# Optional: support os.PathLike on Py3
try:
    from os import PathLike
    PATH_TYPES = (basestring, PathLike)
except Exception:
    PATH_TYPES = (basestring,)

def _ensure_text(s, encoding="utf-8", errors="replace", allow_none=False):
    """
    Normalize any input to text_type (unicode on Py2, str on Py3).

    - bytes/bytearray/memoryview -> decode
    - os.PathLike -> fspath then normalize
    - None -> "" (unless allow_none=True, then return None)
    - everything else -> text_type(s)
    """
    if s is None:
        return None if allow_none else text_type("")

    if isinstance(s, text_type):
        return s

    if isinstance(s, (bytes_type, bytearray, memoryview)):
        return bytes(s).decode(encoding, errors)

    # Handle pathlib.Path & other path-like objects
    try:
        import os
        if hasattr(os, "fspath"):
            fs = os.fspath(s)
            if isinstance(fs, text_type):
                return fs
            if isinstance(fs, (bytes_type, bytearray, memoryview)):
                return bytes(fs).decode(encoding, errors)
    except Exception:
        pass

    return text_type(s)

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

# Define FileNotFoundError for Python 2
try:
    FileNotFoundError
except NameError:
    FileNotFoundError = IOError

try:
    # Works on Py3 and Py2.7
    from io import UnsupportedOperation
except Exception:
    # Mimic CPython: subclass both OSError/IOError and ValueError
    try:
        class UnsupportedOperation(IOError, ValueError):
            pass
    except Exception:
        # Ultra-old fallback if multiple inheritance caused issues on exotic runtimes
        class UnsupportedOperation(IOError):
            pass

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
except (ImportError, OSError):
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
except (ImportError, OSError):
    pass

# PySFTP support
havepysftp = False
try:
    import pysftp
    havepysftp = True
except (ImportError, OSError):
    pass

# Add the mechanize import check
havemechanize = False
try:
    import mechanize
    havemechanize = True
except (ImportError, OSError):
    pass

# Requests support
haverequests = False
try:
    import requests
    haverequests = True
    import urllib3
    logging.getLogger("urllib3").setLevel(logging.WARNING)
except (ImportError, OSError):
    pass

# HTTPX support
havehttpx = False
try:
    import httpx
    havehttpx = True
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
except (ImportError, OSError):
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

def add_format(reg, key, magic, ext, name=None, ver="001",
               new_style=True, use_advanced_list=True, use_alt_inode=False, delim="\x00"):
    if key in reg:
        return
    magic_bytes = magic.encode("utf-8")
    reg[key] = {
        "format_name": name or key,
        "format_magic": magic,
        "format_len": len(magic_bytes),
        "format_hex": magic_bytes.hex(),
        "format_delimiter": delim,
        "format_ver": ver,
        "new_style": new_style,
        "use_advanced_list": use_advanced_list,
        "use_alt_inode": use_alt_inode,
        "format_extension": ext,
    }

__upload_proto_support__ = "^(http|https|ftp|ftps|sftp|scp|tcp|udp)://"
__download_proto_support__ = "^(http|https|ftp|ftps|sftp|scp|tcp|udp)://"
__use_pysftp__ = False
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
__use_inmem__ = True
__use_memfd__ = True
__use_spoolfile__ = False
__use_spooldir__ = tempfile.gettempdir()
BYTES_PER_KiB = 1024
BYTES_PER_MiB = 1024 * BYTES_PER_KiB
# Spool: not tiny, but won’t blow up RAM if many are in use
DEFAULT_SPOOL_MAX = 4 * BYTES_PER_MiB      # 4 MiB per spooled temp file
__spoolfile_size__ = DEFAULT_SPOOL_MAX
# Buffer: bigger than stdlib default (16 KiB), but still modest
DEFAULT_BUFFER_MAX = 256 * BYTES_PER_KiB   # 256 KiB copy buffer
__filebuff_size__ = DEFAULT_BUFFER_MAX
__program_name__ = "Py"+__file_format_default__
__use_env_file__ = True
__use_ini_file__ = True
__use_ini_name__ = "catfile.ini"
__use_json_file__ = False
__use_json_name__ = "catfile.json"
if(__use_ini_file__ and __use_json_file__):
    __use_json_file__ = False
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
elif(__use_ini_file__ and not __use_json_file__):
    __config_file__ = os.path.join(os.path.dirname(os.path.realpath(__file__)), __use_ini_name__)
elif(not __use_ini_file__ and __use_json_file__):
    __config_file__ = os.path.join(os.path.dirname(os.path.realpath(__file__)), __use_json_name__)
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
    __use_inmem__ = config.getboolean('config', 'useinmem')
    __use_memfd__ = config.getboolean('config', 'usememfd')
    __use_spoolfile__ = config.getboolean('config', 'usespoolfile')
    __spoolfile_size__ = config.getint('config', 'spoolfilesize')
    # Loop through all sections
    for section in config.sections():
        if section == "config":
            continue

        required_keys = [
            "len", "hex", "ver", "name",
            "magic", "delimiter", "extension",
            "newstyle", "advancedlist", "altinode"
        ]

        # Py2+Py3 compatible key presence check
        has_all_required = all(config.has_option(section, key) for key in required_keys)
        if not has_all_required:
            continue

        delim = decode_unicode_escape(config.get(section, 'delimiter'))
        if (not is_only_nonprintable(delim)):
            delim = "\x00" * len("\x00")

        __file_format_multi_dict__.update({
            decode_unicode_escape(config.get(section, 'magic')): {
                'format_name':        decode_unicode_escape(config.get(section, 'name')),
                'format_magic':       decode_unicode_escape(config.get(section, 'magic')),
                'format_len':         config.getint(section, 'len'),
                'format_hex':         config.get(section, 'hex'),
                'format_delimiter':   delim,
                'format_ver':         config.get(section, 'ver'),
                'new_style':          config.getboolean(section, 'newstyle'),
                'use_advanced_list':  config.getboolean(section, 'advancedlist'),
                'use_alt_inode':      config.getboolean(section, 'altinode'),
                'format_extension':   decode_unicode_escape(config.get(section, 'extension')),
            }
        })
        if not __file_format_multi_dict__ and not __include_defaults__:
            __include_defaults__ = True
elif __use_json_file__ and os.path.exists(__config_file__):
    # Prefer ujson/simplejson if available (you already have this import block above)
    with open(__config_file__, 'rb') as f:
        raw = f.read()

    # Ensure we get a unicode string for json.loads on both Py2 and Py3
    if sys.version_info[0] < 3:
        text = raw.decode('utf-8')  # Py2 bytes -> unicode
    else:
        text = raw if isinstance(raw, str) else raw.decode('utf-8')

    cfg = json.loads(text)

    # --- helpers: coerce + decode like your INI path ---
    def decode_unicode_escape(value):
        if sys.version_info[0] < 3:  # Python 2
            if isinstance(value, unicode):  # noqa: F821 (Py2 only)
                return value.encode('utf-8').decode('unicode_escape')
            elif isinstance(value, str):
                return value.decode('unicode_escape')
            else:
                return value
        else:  # Python 3
            if isinstance(value, str):
                return bytes(value, 'UTF-8').decode('unicode_escape')
            else:
                return value

    def _to_bool(v):
        # handle true/false, 1/0, and "true"/"false"/"1"/"0"
        if isinstance(v, bool):
            return v
        if isinstance(v, (int, float)):
            return bool(v)
        if isinstance(v, (str,)):
            lv = v.strip().lower()
            if lv in ('true', 'yes', '1'):
                return True
            if lv in ('false', 'no', '0'):
                return False
        return bool(v)

    def _to_int(v, default=0):
        try:
            return int(v)
        except Exception:
            return default

    def _get(section_dict, key, default=None):
        return section_dict.get(key, default)

    # --- read global config (like INI's [config]) ---
    cfg_config = cfg.get('config', {}) or {}
    __file_format_default__ = decode_unicode_escape(_get(cfg_config, 'default', ''))
    __program_name__        = decode_unicode_escape(_get(cfg_config, 'proname', ''))
    __include_defaults__    = _to_bool(_get(cfg_config, 'includedef', True))
    __use_inmem__       = _to_bool(_get(cfg_config, 'useinmem', True))
    __use_memfd__       = _to_bool(_get(cfg_config, 'usememfd', True))
    __use_spoolfile__       = _to_bool(_get(cfg_config, 'usespoolfile', False))
    __spoolfile_size__       = _to_int(_get(cfg_config, 'spoolfilesize', DEFAULT_SPOOL_MAX))

    # --- iterate format sections (everything except "config") ---
    required_keys = [
        "len", "hex", "ver", "name",
        "magic", "delimiter", "extension",
        "newstyle", "advancedlist", "altinode"
    ]

    for section_name, section in cfg.items():
        if section_name == 'config' or not isinstance(section, dict):
            continue

        # check required keys present
        if not all(k in section for k in required_keys):
            continue

        # pull + coerce values
        magic      = decode_unicode_escape(_get(section, 'magic', ''))
        name       = decode_unicode_escape(_get(section, 'name', ''))
        fmt_len    = _to_int(_get(section, 'len', 0))
        fmt_hex    = decode_unicode_escape(_get(section, 'hex', ''))
        fmt_ver    = decode_unicode_escape(_get(section, 'ver', ''))
        delim      = decode_unicode_escape(_get(section, 'delimiter', ''))
        new_style  = _to_bool(_get(section, 'newstyle', False))
        adv_list   = _to_bool(_get(section, 'advancedlist', False))
        alt_inode  = _to_bool(_get(section, 'altinode', False))
        extension  = decode_unicode_escape(_get(section, 'extension', ''))

        # keep your delimiter validation semantics
        if not is_only_nonprintable(delim):
            delim = "\x00" * len("\x00")  # same as your INI branch

        __file_format_multi_dict__.update({
            magic: {
                'format_name':        name,
                'format_magic':       magic,
                'format_len':         fmt_len,
                'format_hex':         fmt_hex,
                'format_delimiter':   delim,
                'format_ver':         fmt_ver,
                'new_style':          new_style,
                'use_advanced_list':  adv_list,
                'use_alt_inode':      alt_inode,
                'format_extension':   extension,
            }
        })

    # mirror your INI logic
    if not __file_format_multi_dict__ and not __include_defaults__:
        __include_defaults__ = True
elif __use_ini_file__ and not os.path.exists(__config_file__):
    __use_ini_file__ = False
    __use_json_file__ = False
    __include_defaults__ = True
elif __use_json_file__ and not os.path.exists(__config_file__):
    __use_json_file__ = False
    __use_ini_file__ = False
    __include_defaults__ = True
if not __use_ini_file__ and not __include_defaults__:
    __include_defaults__ = True
if __include_defaults__:
    # Cat / Neko
    add_format(__file_format_multi_dict__, "CatFile",     "CatFile",     ".cat",     "CatFile")
    add_format(__file_format_multi_dict__, "NekoFile",    "NekoFile",    ".neko",    "NekoFile")
    add_format(__file_format_multi_dict__, "ねこファイル", "ねこファイル", ".ねこ",    "NekoFairu")
    add_format(__file_format_multi_dict__, "ネコファイル", "ネコファイル", ".ネコ",    "NekoFairu")
    add_format(__file_format_multi_dict__, "네코파일",     "네코파일",     ".네코",    "NekoPa-il")
    add_format(__file_format_multi_dict__, "고양이파일",   "고양이파일",   ".고양이",  "GoyangiPa-il")
    add_format(__file_format_multi_dict__, "内酷法伊鲁",   "内酷法伊鲁",   ".内酷",    "NèiKùFǎYīLǔ")
    add_format(__file_format_multi_dict__, "猫文件",       "猫文件",       ".猫",      "MāoWénjiàn")

# Pick a default if current default key is not present
if __file_format_default__ not in __file_format_multi_dict__:
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
__program_alt_name__ = __program_name__
__project_url__ = "https://github.com/GameMaker2k/PyCatFile"
__project_release_url__ = __project_url__+"/releases/latest"
__version_info__ = (0, 25, 2, "RC 1", 1)
__version_date_info__ = (2025, 11, 6, "RC 1", 1)
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

# From: https://stackoverflow.com/a/28568003
# By Phaxmohdem


def versiontuple(v):
    filled = []
    for point in v.split("."):
        filled.append(point.zfill(8))
    return tuple(filled)


def version_check(myvercheck, newvercheck):
    vercheck = 0
    try:
        from packaging import version
        vercheck = 1
    except ImportError:
        try:
            from distutils.version import LooseVersion, StrictVersion
            vercheck = 2
        except ImportError:
            try:
                from pkg_resources import parse_version
                vercheck = 3
            except ImportError:
                return 5
    # print(myvercheck, newvercheck)
    if (vercheck == 1):
        if (version.parse(myvercheck) == version.parse(newvercheck)):
            return 0
        elif (version.parse(myvercheck) < version.parse(newvercheck)):
            return 1
        elif (version.parse(myvercheck) > version.parse(newvercheck)):
            return 2
        else:
            return 3
    elif (vercheck == 2):
        if (StrictVersion(myvercheck) == StrictVersion(newvercheck)):
            return 0
        elif (StrictVersion(myvercheck) < StrictVersion(newvercheck)):
            return 1
        elif (StrictVersion(myvercheck) > StrictVersion(newvercheck)):
            return 2
        else:
            return 3
    elif (vercheck == 3):
        if (parse_version(myvercheck) == parse_version(newvercheck)):
            return 0
        elif (parse_version(myvercheck) < parse_version(newvercheck)):
            return 1
        elif (parse_version(myvercheck) > parse_version(newvercheck)):
            return 2
        else:
            return 3
    else:
        if (versiontuple(myvercheck) == versiontuple(newvercheck)):
            return 0
        elif (versiontuple(myvercheck) < versiontuple(newvercheck)):
            return 1
        elif (versiontuple(myvercheck) > versiontuple(newvercheck)):
            return 2
        else:
            return 3
    return 4


def check_version_number(myversion=__version__, proname=__program_alt_name__, newverurl=__project_release_url__):
    prevercheck = download_from_url(newverurl, geturls_headers, geturls_cj)
    newvercheck = re.findall(proname + " ([0-9\\.]+)<\\/a\\>", prevercheck['Content'].decode("UTF-8"))[0]
    myvercheck = re.findall("([0-9\\.]+)", myversion)[0]
    return version_check(myvercheck, newvercheck)

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
    "files", "hardlinks", "symlinks", "characters", "blocks",
    "directories", "fifos", "sockets", "doors", "ports",
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
    py_implementation = "CPython"
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
'''
try:
    import lzo
    compressionsupport.append("lzo")
    compressionsupport.append("lzop")
except ImportError:
    lzo = None
    pass
'''
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
'''
if('lzop' in compressionsupport):
    compressionlist.append('lzop')
    compressionlistalt.append('lzop')
    outextlist.append('lzop')
    outextlistwd.append('.lzop')
'''
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


# Use a module logger instead of the root logger
_logger = logging.getLogger(__name__)

# Map common level names (case-insensitive) to numeric levels
_LEVEL_BY_NAME = {
    "debug":    logging.DEBUG,
    "info":     logging.INFO,
    "warning":  logging.WARNING,
    "error":    logging.ERROR,
    "critical": logging.CRITICAL,
}

def VerbosePrintOut(dbgtxt, outtype="log", dbgenable=True, dgblevel=20, **kwargs):
    """
    Python 2/3-safe logging switchboard.

    Args:
        dbgtxt: message to emit (any object; coerced to text).
        outtype: 'print', a level name (info/warning/error/critical/debug),
                 an ALL-CAPS logging constant name ('INFO', 'WARNING', ...),
                 an integer level, or 'log' to use dgblevel.
        dbgenable: if False, skip emitting and return False.
        dgblevel: numeric level used when outtype is 'log' or unmapped.
        **kwargs: passed to logging (e.g., exc_info=True, stacklevel=2, extra=...).

    Returns:
        True if something was emitted; False otherwise.
    """
    if not dbgenable:
        return False

    logger = kwargs.pop("logger", None) or _logger
    msg = _to_text(dbgtxt)

    # Normalize outtype
    lvl = None
    if isinstance(outtype, int):
        lvl = outtype
        route = "logging"
    else:
        name = (outtype or "log")
        if isinstance(name, TEXT_TYPES):
            name_l = name.lower()
            if name_l == "print":
                print(msg)
                return True
            if name_l in _LEVEL_BY_NAME:
                lvl = _LEVEL_BY_NAME[name_l]
                route = "logging"
            elif name.isupper() and hasattr(logging, name):
                # Accept 'INFO', 'WARNING', etc.
                lvl = getattr(logging, name)
                route = "logging"
            elif name_l in ("log", "logalt"):
                lvl = int(dgblevel)
                route = "logging"
            elif name_l == "exception":
                # Safer: only include exc_info if the caller asked for it
                lvl = logging.ERROR
                kwargs.setdefault("exc_info", True)
                route = "logging"
            else:
                # Unknown string → fall back to dgblevel
                lvl = int(dgblevel)
                route = "logging"
        else:
            # Unknown type → fallback
            lvl = int(dgblevel)
            route = "logging"

    if route == "logging":
        if not logger.isEnabledFor(lvl):
            return False
        logger.log(lvl, msg, **kwargs)
        return True

    return False


def VerbosePrintOutReturn(dbgtxt, outtype="log", dbgenable=True, dgblevel=20, **kwargs):
    """
    Log/print dbgtxt (per VerbosePrintOut) and return dbgtxt unchanged.
    Useful for tap-style debugging in pipelines.
    """
    VerbosePrintOut(dbgtxt, outtype, dbgenable, dgblevel, **kwargs)
    return dbgtxt


def _split_posix(name):
    """
    Return a list of path parts without collapsing '..'.
    - Normalize backslashes to '/'
    - Strip leading './' (repeated)
    - Remove '' and '.' parts; keep '..' for traversal detection
    """
    if not name:
        return []
    n = name.replace(u"\\", u"/")
    while n.startswith(u"./"):
        n = n[2:]
    return [p for p in n.split(u"/") if p not in (u"", u".")]

def _is_abs_like(name):
    """Detect absolute-like paths across platforms (/, \\, drive letters, UNC)."""
    if not name:
        return False
    n = name.replace(u"\\", u"/")

    # POSIX absolute
    if n.startswith(u"/"):
        return True

    # Windows UNC (\\server\share\...) -> after replace: startswith '//'
    if n.startswith(u"//"):
        return True

    # Windows drive: 'C:/', 'C:\', or bare 'C:' (treat as absolute-like conservatively)
    if len(n) >= 2 and n[1] == u":":
        if len(n) == 2:
            return True
        if n[2:3] in (u"/", u"\\"):
            return True
    return False

def _resolves_outside(parent, target):
    """
    Does a symlink from 'parent' to 'target' escape parent?
    - Absolute-like target => escape.
    - Compare normalized '/<parent>/<target>' against '/<parent>'.
    - 'parent' is POSIX-style ('' means archive root).
    """
    parent = _ensure_text(parent or u"")
    target = _ensure_text(target or u"")

    # Absolute target is unsafe by definition
    if _is_abs_like(target):
        return True

    import posixpath as pp
    root = u"/"
    base = posixpath.normpath(posixpath.join(root, parent))   # '/dir/sub' or '/'
    cand = posixpath.normpath(posixpath.join(base, target))   # resolved target under '/'

    # ensure trailing slash on base for the prefix test
    base_slash = base if base.endswith(u"/") else (base + u"/")
    return not (cand == base or cand.startswith(base_slash))

def _to_bytes(data, encoding="utf-8", errors="strict"):
    """
    Robustly coerce `data` to bytes:
      - None -> b""
      - bytes/bytearray/memoryview -> bytes(...)
      - unicode/str -> .encode(encoding, errors)
      - file-like (has .read) -> read all, return bytes
      - int -> encode its decimal string (avoid bytes(int) => NULs)
      - other -> try __bytes__, else str(...).encode(...)
    """
    if data is None:
        return b""

    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)

    if isinstance(data, unicode):
        return data.encode(encoding, errors)

    # file-like: read its content
    if hasattr(data, "read"):
        chunk = data.read()
        return bytes(chunk) if isinstance(chunk, (bytes, bytearray, memoryview)) else (
            (chunk if isinstance(chunk, unicode) else str(chunk)).encode(encoding, errors)
        )

    # avoid bytes(int) => NUL padding
    if isinstance(data, int):
        return str(data).encode(encoding, errors)

    # prefer __bytes__ when available
    to_bytes = getattr(data, "__bytes__", None)
    if callable(to_bytes):
        try:
            return bytes(data)
        except Exception:
            pass

    # fallback: string form
    return (data if isinstance(data, unicode) else str(data)).encode(encoding, errors)


def _to_text(s, encoding="utf-8", errors="replace", normalize=None, prefer_surrogates=False):
    """
    Coerce `s` to a text/unicode string safely.

    Args:
      s: Any object (bytes/bytearray/memoryview/str/unicode/other).
      encoding: Used when decoding bytes-like objects (default: 'utf-8').
      errors: Decoding error policy (default: 'replace').
              Consider 'surrogateescape' when you need byte-preserving round-trip on Py3.
      normalize: Optional unicode normalization form, e.g. 'NFC', 'NFKC', 'NFD', 'NFKD'.
      prefer_surrogates: If True on Py3 and errors is the default, use 'surrogateescape'
                         to preserve undecodable bytes.

    Returns:
      A text string (unicode on Py2, str on Py3).
    """
    # Fast path: already text
    if isinstance(s, unicode):
        out = s
    else:
        # Bytes-like → decode
        if isinstance(s, (bytes, bytearray, memoryview)):
            b = s if isinstance(s, (bytes, bytearray)) else bytes(s)
            # Prefer surrogateescape on Py3 if requested (keeps raw bytes round-tripable)
            eff_errors = errors
            if prefer_surrogates and errors == "replace":
                try:
                    # Only available on Py3
                    "".encode("utf-8", "surrogateescape")
                    eff_errors = "surrogateescape"
                except LookupError:
                    pass
            try:
                out = b.decode(encoding, eff_errors)
            except Exception:
                # Last-resort: decode with 'latin-1' to avoid exceptions
                out = b.decode("latin-1", "replace")
        else:
            # Not bytes-like: stringify
            try:
                # Py2: many objects implement __unicode__
                if hasattr(s, "__unicode__"):
                    out = s.__unicode__()  # noqa: E1101 (only on Py2 objects)
                else:
                    out = unicode(s)
            except Exception:
                # Fallback to repr() if object’s __str__/__unicode__ is broken
                out = unicode(repr(s))

    # Optional normalization
    if normalize:
        try:
            import unicodedata
            out = unicodedata.normalize(normalize, out)
        except Exception:
            # Keep original if normalization fails
            pass

    return out

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
    return base or 'CatFile'+__file_format_extension__

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
    parts = urlparse(url)
    qs = parse_qs(parts.query or "")

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
        raw = base64.b64decode(_to_bytes(b64))
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

def DetectTarBombFoxFileArray(listarrayfiles,
                              top_file_ratio_threshold=0.6,
                              min_members_for_ratio=4,
                              symlink_policy="escape-only",  # 'escape-only' | 'deny' | 'single-folder-only'
                              to_text=None):
    """
    Detect 'tarbomb-like' archives from dicts.

    Returns dict with:
      - is_tarbomb, reasons, total_members, top_level_entries, top_level_files_count,
        has_absolute_paths, has_parent_traversal,
        symlink_escapes_root (bool), symlink_issues (list[{entry,target,reason}]),
        has_symlinks (bool)
    """
    if to_text is None:
        to_text = _ensure_text

    files = listarrayfiles or {}
    members = files.get('ffilelist') or []

    names = []
    has_abs = False
    has_parent = False

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

        # Symlink detection
        ftype = m.get('ftype')
        if _symlink_type(ftype):
            has_any_symlink = True
            target = to_text(m.get('flinkname', u""))
            # Absolute target or escaping target is unsafe
            if _is_abs_like(target):
                any_symlink_escape = True
                symlink_issues.append({'entry': norm_name, 'target': target, 'reason': 'absolute symlink target'})
            else:
                parent = u'/'.join(parts[:-1])  # '' for root
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
            "has_symlinks": has_any_symlink,
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
    # (escape-only handled by the escape detection above)

    # Tarbomb layout heuristics
    if len(top_keys) == 1:
        reasons.append("single top-level entry '{0}'".format(top_keys[0]))
    else:
        ratio = float(top_level_files_count) / float(total)
        if total >= int(min_members_for_ratio) and ratio > float(top_file_ratio_threshold):
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
        "has_symlinks": has_any_symlink,
    }


def _as_bytes_like(data):
    if isinstance(data, bytes):
        return data
    if isinstance(data, bytearray):
        return bytes(data)
    try:
        mv = memoryview
    except NameError:
        mv = ()
    if mv and isinstance(data, mv):
        return bytes(data)
    return None

def _normalize_initial_data(data, isbytes, encoding, errors=None):
    """
    Return bytes (if isbytes) or text (unicode on Py2, str on Py3).
    Py2-safe signature (no keyword-only args).
    """
    if errors is None:
        errors = "strict"

    if data is None:
        return None

    if isbytes:
        b = _as_bytes_like(data)
        if b is not None:
            return b
        if PY2:
            # Py2: 'unicode' -> encode; 'str' is already bytes
            if isinstance(data, unicode_type):
                return data.encode(encoding, errors)
            if isinstance(data, str):
                return data
        else:
            # Py3: text -> encode
            if isinstance(data, str):
                return data.encode(encoding, errors)
        raise TypeError("data must be bytes-like or text for isbytes=True (got %r)" % (type(data),))
    else:
        # text mode
        if PY2:
            if isinstance(data, unicode_type):
                return data
            b = _as_bytes_like(data)
            if b is not None:
                return b.decode(encoding, errors)
            if isinstance(data, str):
                # Py2 str -> decode
                return data.decode(encoding, errors)
            raise TypeError("data must be unicode or bytes-like for text mode (got %r)" % (type(data),))
        else:
            if isinstance(data, str):
                return data
            b = _as_bytes_like(data)
            if b is not None:
                return b.decode(encoding, errors)
            raise TypeError("data must be str or bytes-like for text mode (got %r)" % (type(data),))


def MkTempFile(data=None,
               inmem=__use_inmem__, usememfd=__use_memfd__,
               isbytes=True,
               prefix=__program_name__,
               delete=True,
               encoding="utf-8",
               newline=None,
               text_errors="strict",
               dir=None,
               suffix="",
               use_spool=__use_spoolfile__,
               autoswitch_spool=False,
               spool_max=__spoolfile_size__,
               spool_dir=__use_spooldir__,
               reset_to_start=True,
               memfd_name=None,
               memfd_allow_sealing=False,
               memfd_flags_extra=0,
               on_create=None):
    """
    Return a file-like handle with consistent behavior on Py2.7 and Py3.x.

    Storage:
      - inmem=True, usememfd=True, isbytes=True and memfd available
            -> memfd-backed anonymous file (binary)
      - inmem=True, otherwise
            -> BytesIO (bytes) or StringIO (text)
      - inmem=False, use_spool=True
            -> SpooledTemporaryFile (binary), optionally TextIOWrapper for text
      - inmem=False, use_spool=False
            -> NamedTemporaryFile (binary), optionally TextIOWrapper for text

    Text vs bytes:
      - isbytes=True  -> file expects bytes; 'data' must be bytes-like
      - isbytes=False -> file expects text; 'data' must be text (unicode/str). Newline translation and
                         encoding apply only for spooled/named files (not BytesIO/StringIO).

    Notes:
      - On Windows, NamedTemporaryFile(delete=True) keeps the file open and cannot be reopened by
        other processes. Use delete=False if you need to pass the path elsewhere.
      - For text: in-memory StringIO ignores 'newline' and 'text_errors' (as usual).
      - When available, and if usememfd=True, memfd is used only for inmem=True and isbytes=True,
        providing an anonymous in-memory file descriptor (Linux-only). Text in-memory still uses
        StringIO to preserve newline semantics.
      - If autoswitch_spool=True and initial data size exceeds spool_max, in-memory storage is
        skipped and a spooled file is used instead (if use_spool=True).
      - If on_create is not None, it is called as on_create(fp, kind) where kind is one of:
        "memfd", "bytesio", "stringio", "spool", "disk".
    """

    # -- sanitize simple params (avoid None surprises) --
    prefix = prefix or ""
    suffix = suffix or ""
    # dir/spool_dir may be None (allowed)

    # -- normalize initial data to the right type early --
    if data is not None:
        if isbytes:
            # Require a bytes-like; convert common cases safely
            if isinstance(data, (bytearray, memoryview)):
                init = bytes(data)
            elif isinstance(data, bytes):
                init = data
            elif isinstance(data, str):
                # Py3 str or Py2 unicode: encode using 'encoding'
                init = data.encode(encoding)
            else:
                raise TypeError("data must be bytes-like for isbytes=True")
        else:
            # Require text (unicode/str); convert common cases safely
            if isinstance(data, (bytes, bytearray, memoryview)):
                init = bytes(data).decode(encoding, errors="strict")
            elif isinstance(data, str):
                init = data
            else:
                raise TypeError("data must be text (str/unicode) for isbytes=False")
    else:
        init = None

    # Size of init for autoswitch; only meaningful for bytes
    init_len = len(init) if (init is not None and isbytes) else None

    # -------- In-memory --------
    if inmem:
        # If autoswitch is enabled and data is larger than spool_max, and
        # spooling is allowed, skip the in-memory branch and fall through
        # to the spool/disk logic below.
        if autoswitch_spool and use_spool and init_len is not None and init_len > spool_max:
            pass  # fall through to spool/disk sections
        else:
            # Use memfd only for bytes, and only where available (Linux, Python 3.8+)
            if usememfd and isbytes and hasattr(os, "memfd_create"):
                name = memfd_name or prefix or "MkTempFile"
                flags = 0
                # Close-on-exec is almost always what you want for temps
                if hasattr(os, "MFD_CLOEXEC"):
                    flags |= os.MFD_CLOEXEC
                # Optional sealing support if requested and available
                if memfd_allow_sealing and hasattr(os, "MFD_ALLOW_SEALING"):
                    flags |= os.MFD_ALLOW_SEALING
                # Extra custom flags (e.g. hugepage flags) if caller wants them
                if memfd_flags_extra:
                    flags |= memfd_flags_extra

                fd = os.memfd_create(name, flags)
                # Binary read/write file-like object backed by RAM
                f = os.fdopen(fd, "w+b")

                if init is not None:
                    f.write(init)
                if reset_to_start:
                    f.seek(0)

                if on_create is not None:
                    on_create(f, "memfd")
                return f

            # Fallback: pure Python in-memory objects
            if isbytes:
                f = io.BytesIO(init if init is not None else b"")
                kind = "bytesio"
            else:
                # newline/text_errors not enforced for StringIO; matches stdlib semantics
                f = io.StringIO(init if init is not None else "")
                kind = "stringio"

            if reset_to_start:
                f.seek(0)

            if on_create is not None:
                on_create(f, kind)
            return f

    # Helper: wrap a binary file into a text file with encoding/newline
    def _wrap_text(handle):
        # For both Py2 & Py3, TextIOWrapper gives consistent newline/encoding behavior
        return io.TextIOWrapper(handle, encoding=encoding,
                                newline=newline, errors=text_errors)

    # -------- Spooled (RAM then disk) --------
    if use_spool:
        # Always create binary spooled file; wrap for text if needed
        bin_mode = "w+b"  # read/write, binary
        b = tempfile.SpooledTemporaryFile(max_size=spool_max, mode=bin_mode, dir=spool_dir)
        f = b if isbytes else _wrap_text(b)

        if init is not None:
            f.write(init)
            if reset_to_start:
                f.seek(0)
        elif reset_to_start:
            f.seek(0)

        if on_create is not None:
            on_create(f, "spool")
        return f

    # -------- On-disk temp (NamedTemporaryFile) --------
    # Always create binary file; wrap for text if needed for uniform Py2/3 behavior
    b = tempfile.NamedTemporaryFile(mode="w+b", prefix=prefix, suffix=suffix,
                                    dir=dir, delete=delete)
    f = b if isbytes else _wrap_text(b)

    if init is not None:
        f.write(init)
        if reset_to_start:
            f.seek(0)
    elif reset_to_start:
        f.seek(0)

    if on_create is not None:
        on_create(f, "disk")
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
                PY_STDERR_TEXT.write("Error accessing file {}: {}\n".format(item, e))
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

if PY2:
    binary_types = (str, bytearray, buffer)  # noqa: F821 (buffer in Py2)
else:
    binary_types = (bytes, bytearray, memoryview)


# ---------- Helpers (same semantics as your snippet) ----------
def _byte_at(b, i):
    """Return int value of byte at index i for both Py2 and Py3."""
    if PY2:
        return ord(b[i:i+1])
    return b[i]

def _is_valid_zlib_header(cmf, flg):
    """
    RFC1950 CMF/FLG validation:
      - CM (lower 4 bits of CMF) must be 8 (DEFLATE)
      - CINFO (upper 4 bits of CMF) <= 7 (window up to 32K)
      - (CMF*256 + FLG) % 31 == 0
    """
    cm = cmf & 0x0F
    cinfo = (cmf >> 4) & 0x0F
    if cm != 8 or cinfo > 7:
        return False
    if ((cmf << 8) + flg) % 31 != 0:
        return False
    return True

# ---------- Main class ----------
class ZlibFile(object):
    """
    Read/Write RFC1950 zlib streams with support for concatenated members.

    Modes:
      'rb','rt','wb','wt','ab','at','xb','xt'

    New options:
      tolerant_read (bool): if True, skip up to 'scan_bytes' of leading junk to find first zlib member.
      scan_bytes (int): max bytes to scan when tolerant_read=True (default 64 KiB).
      spool_threshold (int): max in-memory bytes before spilling to disk for reads (default 8 MiB).

    Notes:
      - Write path streams with buffering; no per-write Z_SYNC_FLUSH (explicit flush uses it).
      - Read path spools decompressed payload to a SpooledTemporaryFile enabling seek/tell/iter.
      - Streams with preset dictionaries (FDICT) are rejected.
      - wbits must be > 0 (zlib wrapper).
    """

    def __init__(self, file_path=None, fileobj=None, mode='rb', level=6, wbits=15,
                 encoding=None, errors=None, newline=None,
                 tolerant_read=False, scan_bytes=(64 << 10), spool_threshold=__spoolfile_size__):

        if file_path is None and fileobj is None:
            raise ValueError("Either file_path or fileobj must be provided")
        if file_path is not None and fileobj is not None:
            raise ValueError("Only one of file_path or fileobj should be provided")

        if 'b' not in mode and 't' not in mode:
            mode += 'b'  # default to binary
        if 'x' in mode and PY2:
            raise ValueError("Exclusive creation mode 'x' is not supported on Python 2")

        self.file_path = file_path
        self.file = None
        self._external_fp = (fileobj is not None)

        self.mode = mode
        self.level = int(level)
        self.wbits = int(wbits)
        self.encoding = encoding
        self.errors = errors
        self.newline = newline
        self._text_mode = ('t' in mode)

        # New config
        self.tolerant_read = bool(tolerant_read)
        self.scan_bytes = int(scan_bytes)
        self.spool_threshold = int(spool_threshold)

        # Internal state
        self._compressor = None
        self._write_buf = bytearray()
        self._spool = None              # SpooledTemporaryFile for read-path bytes
        self._text_reader = None        # TextIOWrapper over _spool in text mode
        self._position = 0              # mirrors underlying tell() for convenience
        self.closed = False

        # Open underlying file with binary I/O
        internal_mode = mode.replace('t', 'b')
        if file_path is not None:
            if 'x' in internal_mode and os.path.exists(file_path):
                raise IOError("File exists: '{}'".format(file_path))
            self.file = open(file_path, internal_mode)
        else:
            self.file = fileobj
            if self.file is None:
                raise ValueError("fileobj is None")
            if 'r' in internal_mode and not hasattr(self.file, 'read'):
                raise ValueError("fileobj must support read() in read mode")
            if any(ch in internal_mode for ch in ('w', 'a', 'x')) and not hasattr(self.file, 'write'):
                raise ValueError("fileobj must support write() in write/append mode")

        self._fp = self.file
        # Initialize per mode
        if any(ch in internal_mode for ch in ('w', 'a', 'x')):
            if self.wbits <= 0:
                raise ValueError("wbits must be > 0 for zlib wrapper")
            if 'a' in internal_mode:
                try:
                    self.file.seek(0, os.SEEK_END)
                except Exception:
                    pass
            self._compressor = zlib.compressobj(self.level, zlib.DEFLATED, self.wbits)

        elif 'r' in internal_mode:
            if self.wbits <= 0:
                raise ValueError("wbits must be > 0 for zlib wrapper")
            self._load_all_members_spooled()
        else:
            raise ValueError("Unsupported mode: {}".format(mode))

    # ---------- utilities ----------

    @property
    def name(self):
        return self.file_path

    def readable(self):
        return 'r' in self.mode

    def writable(self):
        return any(ch in self.mode for ch in ('w', 'a', 'x'))

    def seekable(self):
        # spooled read path is always seekable; write path defers to underlying file
        if self._spool is not None:
            return True
        return bool(getattr(self.file, 'seek', None))

    def _normalize_newlines_for_write(self, s):
        # Map all newlines to configured newline (default '\n')
        nl = self.newline if self.newline is not None else "\n"
        return s.replace("\r\n", "\n").replace("\r", "\n").replace("\n", nl)

    def _reader(self):
        """Return the active read handle (binary spool or text wrapper)."""
        if self._text_mode:
            return self._text_reader
        return self._spool

    # ---------- READ PATH (spooled) ----------

    def _load_all_members_spooled(self):
        """
        Decompress all concatenated zlib members into a SpooledTemporaryFile.
        In text mode, wrap the spool with io.TextIOWrapper for decoding/newlines.
        """
        try:
            self.file.seek(0)
        except Exception:
            pass

        self._spool = tempfile.SpooledTemporaryFile(max_size=self.spool_threshold)
        pending = b""
        d = None
        absolute_offset = 0
        scanned_leading = 0  # for tolerant header scan

        while True:
            data = self.file.read(__filebuff_size__)  # 1 MiB blocks
            if not data:
                if d is not None:
                    self._spool.write(d.flush())
                break

            buf = pending + data
            absolute_offset += len(data)

            while True:
                if d is None:
                    # Need at least 2 bytes for CMF/FLG
                    if len(buf) < 2:
                        pending = buf
                        break
                    cmf = _byte_at(buf, 0)
                    flg = _byte_at(buf, 1)

                    if not _is_valid_zlib_header(cmf, flg):
                        if self.tolerant_read and scanned_leading < self.scan_bytes:
                            # Skip forward by one byte, keep scanning within limit
                            buf = buf[1:]
                            scanned_leading += 1
                            if len(buf) < 2:
                                pending = buf
                                break
                            continue
                        start_off = absolute_offset - len(buf)
                        raise ValueError("Invalid zlib header near byte offset {}".format(start_off))

                    if (flg & 0x20) != 0:
                        start_off = absolute_offset - len(buf)
                        raise ValueError("Preset dictionary (FDICT) not supported (offset {})".format(start_off))

                    d = zlib.decompressobj(self.wbits)

                out = d.decompress(buf)
                if out:
                    self._spool.write(out)

                if d.unused_data:
                    self._spool.write(d.flush())
                    buf = d.unused_data
                    d = None
                    if not buf:
                        break
                    continue

                pending = b""
                break  # need more input

        # Prepare read handles
        try:
            self._spool.seek(0)
        except Exception:
            pass

        if self._text_mode:
            enc = self.encoding or 'UTF-8'
            errs = self.errors or 'strict'
            # newline=None => universal newline translation; exact string if provided
            tw_newline = self.newline
            self._text_reader = io.TextIOWrapper(self._spool, encoding=enc, errors=errs, newline=tw_newline)
            try:
                self._text_reader.seek(0)
            except Exception:
                pass

        self._position = 0

    # Exposed read API delegates to underlying reader
    def read(self, size=-1):
        if self.closed:
            raise ValueError("I/O operation on closed file")
        r = self._reader()
        if r is None:
            raise IOError("File not opened for reading")
        out = r.read() if (size is None or size < 0) else r.read(int(size))
        try:
            self._position = r.tell()
        except Exception:
            pass
        return out

    def readline(self, size=-1):
        if self.closed:
            raise ValueError("I/O operation on closed file")
        r = self._reader()
        if r is None:
            raise IOError("File not opened for reading")
        out = r.readline() if (size is None or size < 0) else r.readline(int(size))
        try:
            self._position = r.tell()
        except Exception:
            pass
        if not self._text_mode and out is None:
            return b""
        if self._text_mode and out is None:
            return text_type("")
        return out

    def __iter__(self):
        return self

    def __next__(self):
        line = self.readline()
        if (self._text_mode and line == "") or (not self._text_mode and line == b""):
            raise StopIteration
        return line

    if PY2:
        next = __next__

    def seek(self, offset, whence=0):
        if self.closed:
            raise ValueError("I/O operation on closed file")
        r = self._reader()
        if r is None:
            raise IOError("File not opened for reading")
        newpos = r.seek(int(offset), int(whence))
        self._position = newpos
        return newpos

    def tell(self):
        if self._reader() is not None:
            try:
                self._position = self._reader().tell()
            except Exception:
                pass
        return self._position

    # ---------- WRITE PATH ----------

    def write(self, data):
        if self.closed:
            raise ValueError("I/O operation on closed file")
        if self._compressor is None:
            raise IOError("File not opened for writing")

        if self._text_mode:
            enc = self.encoding or 'UTF-8'
            errs = self.errors or 'strict'
            if isinstance(data, text_type):
                data = self._normalize_newlines_for_write(data).encode(enc, errs)
            else:
                raise TypeError("write() expects text (unicode/str) in text mode")
        else:
            if not isinstance(data, binary_types):
                raise TypeError("write() expects bytes-like in binary mode")

        # Normalize to bytes for Py2/3 edge cases
        if (not PY2) and isinstance(data, memoryview):
            data = data.tobytes()
        elif PY2 and isinstance(data, bytearray):
            data = bytes(data)

        # Buffer and compress in chunks to limit memory
        self._write_buf += data
        if len(self._write_buf) >= (__filebuff_size__):  # 1 MiB threshold
            chunk = self._compressor.compress(bytes(self._write_buf))
            if chunk:
                self.file.write(chunk)
            del self._write_buf[:]  # clear

        return len(data)

    def flush(self):
        if self.closed:
            return
        if self._compressor is not None:
            if self._write_buf:
                chunk = self._compressor.compress(bytes(self._write_buf))
                if chunk:
                    self.file.write(chunk)
                del self._write_buf[:]
            out = self._compressor.flush(zlib.Z_SYNC_FLUSH)
            if out:
                self.file.write(out)
        if hasattr(self.file, 'flush'):
            self.file.flush()

    def close(self):
        if self.closed:
            return
        try:
            if self._compressor is not None:
                if self._write_buf:
                    self.file.write(self._compressor.compress(bytes(self._write_buf)))
                    del self._write_buf[:]
                final = self._compressor.flush(zlib.Z_FINISH)
                if final:
                    self.file.write(final)
            if hasattr(self.file, 'flush'):
                try:
                    self.file.flush()
                except Exception:
                    pass
        finally:
            # Only close underlying file if we opened it
            if self.file_path and self.file is not None:
                try:
                    self.file.close()
                except Exception:
                    pass
            # Clean up readers/spool
            try:
                if self._text_reader is not None:
                    # Detach to avoid double-close on spool; safe if already closed
                    self._text_reader.detach()
            except Exception:
                pass
            try:
                if self._spool is not None:
                    self._spool.close()
            except Exception:
                pass
            self.closed = True

    # ---------- File-like helpers ----------

    def fileno(self):
        if hasattr(self.file, 'fileno'):
            return self.file.fileno()
        raise OSError("Underlying file object does not support fileno()")

    def isatty(self):
        return bool(getattr(self.file, 'isatty', lambda: False)())

    def truncate(self, size=None):
        # Prevent corruption of compressed streams
        raise OSError("truncate() is not supported for compressed streams")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, tb):
        self.close()

    # ---------- Convenience constructors ----------

    @classmethod
    def open(cls, path, mode='rb', **kw):
        """
        Mirror built-in open() but for ZlibFile.
        Example:
            with ZlibFile.open("data.z", "rt", encoding="utf-8") as f:
                print(f.readline())
        """
        return cls(file_path=path, mode=mode, **kw)

    @classmethod
    def from_fileobj(cls, fileobj, mode='rb', **kw):
        """
        Wrap an existing binary file-like object.
        Caller retains ownership of fileobj.
        """
        return cls(fileobj=fileobj, mode=mode, **kw)

    @classmethod
    def from_bytes(cls, data, mode='rb', **kw):
        """
        Read from an in-memory bytes buffer.
        Example:
            f = ZlibFile.from_bytes(blob, mode='rt', encoding='utf-8', tolerant_read=True)
            text = f.read()
        """
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("from_bytes() expects a bytes-like object")
        bio = MkTempFile(bytes(data) if not isinstance(data, bytes) else data)
        return cls(fileobj=bio, mode=mode, **kw)

    # compatibility aliases for unwrapping utilities
    @property
    def fileobj(self):
        return self.file

    @property
    def myfileobj(self):
        return self.file

# ---------- Top-level helpers (optional) ----------
def decompress_bytes(blob, **kw):
    """
    Decompress concatenated zlib members from a bytes blob.
    Returns bytes (or text if mode='rt' provided via kw).
    Example:
        raw = decompress_bytes(blob, mode='rb', tolerant_read=True)
        txt = decompress_bytes(blob, mode='rt', encoding='utf-8')
    """
    mode = kw.pop('mode', 'rb')
    f = ZlibFile.from_bytes(blob, mode=mode, **kw)
    try:
        return f.read()
    finally:
        f.close()

def compress_bytes(payload, level=6, wbits=15, text=False, **kw):
    """
    Compress a single payload into one zlib member and return the zlib-wrapped bytes.
    Set text=True to treat payload as text with encoding/newline handling.
    Example:
        out = compress_bytes(b"hello")
        out = compress_bytes(u"hello\n", text=True, encoding="utf-8", newline="\n")
    """
    bio = MkTempFile()
    mode = 'wt' if text else 'wb'
    f = ZlibFile(fileobj=bio, mode=mode, level=level, wbits=wbits, **kw)
    try:
        f.write(payload)
        f.flush()
    finally:
        f.close()  # ensures Z_FINISH written
    return bio.getvalue()


# ---------- Single-shot helpers ----------
def _gzip_compress(data, compresslevel=9):
    """Compress into a single gzip member. Returns bytes."""
    co = zlib.compressobj(compresslevel, zlib.DEFLATED, 31)  # 31 => gzip wrapper
    return co.compress(data) + co.flush(zlib.Z_FINISH)

def _gzip_decompress(data):
    """Decompress a single gzip member (stops at member end)."""
    return zlib.decompress(data, 31)

def _gzip_decompress_multimember(data):
    """Decompress concatenated gzip members. Returns bytes."""
    out = []
    buf = data
    last_len = None
    while buf:
        d = zlib.decompressobj(31)
        out.append(d.decompress(buf))
        out.append(d.flush())
        if d.unused_data:
            new_buf = d.unused_data
            # progress guard vs malformed inputs
            if last_len is not None and len(new_buf) >= last_len:
                break
            last_len = len(new_buf)
            buf = new_buf
        else:
            break
    return b"".join(out)


# ---------- Streaming, spooled GzipFile ----------
class GzipFile(object):
    """
    A gzip reader/writer using zlib (wbits=31) with:
      - streaming writes (no giant in-memory buffer)
      - spooled streaming reads with multi-member support (seek/tell/iter)
      - strict text ('t') vs binary modes
      - 'a' appends a new gzip member

    Modes: 'rb', 'rt', 'wb', 'wt', 'ab', 'at', ('xb'/'xt' unsupported on Py2)

    Options:
      tolerant_read (bool): If True, scan forward (up to scan_bytes) to find first gzip header.
      scan_bytes (int): Max leading bytes to scan when tolerant_read=True (default 64 KiB).
      spool_threshold (int): SpooledTemporaryFile RAM threshold before spilling to disk (default 8 MiB).
    """

    GZIP_MAGIC = b'\x1f\x8b'
    GZIP_CM_DEFLATE = 8

    def __init__(self, file_path=None, fileobj=None, mode='rb',
                 level=6, encoding=None, errors=None, newline=None,
                 tolerant_read=False, scan_bytes=(64 << 10), spool_threshold=__spoolfile_size__):

        if file_path is None and fileobj is None:
            raise ValueError("Either file_path or fileobj must be provided")
        if file_path is not None and fileobj is not None:
            raise ValueError("Only one of file_path or fileobj should be provided")

        if 'b' not in mode and 't' not in mode:
            mode += 'b'
        if 'x' in mode and PY2:
            raise ValueError("Exclusive creation mode 'x' not supported on Python 2")

        self.file_path = file_path
        self.file = fileobj
        self.mode = mode
        self.level = int(level)
        self.encoding = encoding
        self.errors = errors
        self.newline = newline
        self._text_mode = ('t' in mode)

        # Config
        self.tolerant_read = bool(tolerant_read)
        self.scan_bytes = int(scan_bytes)
        self.spool_threshold = int(spool_threshold)

        # State
        self._compressor = None         # write-side compressor
        self._write_buf = bytearray()   # staging buffer
        self._spool = None              # SpooledTemporaryFile for decompressed bytes
        self._text_reader = None        # TextIOWrapper over _spool in text mode
        self._position = 0
        self.closed = False

        # Open underlying file in binary
        internal_mode = mode.replace('t', 'b')
        if self.file is None:
            if 'x' in internal_mode and os.path.exists(file_path):
                raise IOError("File exists: '{}'".format(file_path))
            self.file = open(file_path, internal_mode)
        else:
            if 'r' in internal_mode and not hasattr(self.file, 'read'):
                raise ValueError("fileobj must support read() in read mode")
            if any(ch in internal_mode for ch in ('w', 'a', 'x')) and not hasattr(self.file, 'write'):
                raise ValueError("fileobj must support write() in write/append mode")

        self._fp = self.file
        # Init per mode
        if any(ch in internal_mode for ch in ('w', 'a', 'x')):
            # Streaming write: start a new gzip member
            if 'a' in internal_mode:
                try:
                    self.file.seek(0, os.SEEK_END)
                except Exception:
                    pass
            self._compressor = zlib.compressobj(self.level, zlib.DEFLATED, 31)

        elif 'r' in internal_mode:
            self._load_all_members_spooled()
        else:
            raise ValueError("Unsupported mode: {}".format(mode))

    # ---------- helpers ----------

    @property
    def name(self):
        return self.file_path

    def readable(self):
        return 'r' in self.mode

    def writable(self):
        return any(ch in self.mode for ch in ('w', 'a', 'x'))

    def seekable(self):
        return True if self._spool is not None else bool(getattr(self.file, 'seek', None))

    def _normalize_newlines_for_write(self, s):
        nl = self.newline if self.newline is not None else "\n"
        return s.replace("\r\n", "\n").replace("\r", "\n").replace("\n", nl)

    def _reader(self):
        return self._text_reader if self._text_mode else self._spool

    # ---------- READ PATH (spooled, multi-member, optional tolerant scan) ----------

    def _load_all_members_spooled(self):
        # Rewind if possible
        try:
            self.file.seek(0)
        except Exception:
            pass

        self._spool = tempfile.SpooledTemporaryFile(max_size=self.spool_threshold)

        CHUNK = __filebuff_size__
        pending = b""
        d = None
        absolute_offset = 0
        scanned = 0

        while True:
            chunk = self.file.read(CHUNK)
            if not chunk:
                if d is not None:
                    self._spool.write(d.flush())
                break

            buf = pending + chunk
            absolute_offset += len(chunk)

            while True:
                if d is None:
                    # Need at least 2 bytes for quick check
                    if len(buf) < 2:
                        pending = buf
                        break
                    # Tolerant scan for magic
                    if not (buf[0:2] == self.GZIP_MAGIC):
                        if self.tolerant_read and scanned < self.scan_bytes:
                            buf = buf[1:]
                            scanned += 1
                            if len(buf) < 2:
                                pending = buf
                                break
                            continue
                        # Not tolerant: let zlib raise below
                    d = zlib.decompressobj(31)

                # Decompress as much as possible
                try:
                    out = d.decompress(buf)
                except zlib.error as e:
                    start_off = absolute_offset - len(buf)
                    raise ValueError("GZIP decompression error near offset {}: {}"
                                     .format(start_off, e))
                if out:
                    self._spool.write(out)

                if d.unused_data:
                    # Member finished. Flush and continue with remaining bytes (next member).
                    self._spool.write(d.flush())
                    buf = d.unused_data
                    d = None
                    if not buf:
                        break
                    continue

                # Need more input
                pending = b""
                break

        # Prepare read handles
        try:
            self._spool.seek(0)
        except Exception:
            pass

        if self._text_mode:
            enc = self.encoding or 'UTF-8'
            errs = self.errors or 'strict'
            # newline=None => universal newline translation; exact string if provided
            self._text_reader = io.TextIOWrapper(self._spool, encoding=enc, errors=errs, newline=self.newline)
            try:
                self._text_reader.seek(0)
            except Exception:
                pass

        self._position = 0

    # Delegate read API to the active reader (text or binary)
    def read(self, size=-1):
        if self.closed:
            raise ValueError("I/O operation on closed file")
        r = self._reader()
        if r is None:
            raise IOError("File not open for reading")
        out = r.read() if (size is None or size < 0) else r.read(int(size))
        try:
            self._position = r.tell()
        except Exception:
            pass
        return out

    def readline(self, size=-1):
        if self.closed:
            raise ValueError("I/O operation on closed file")
        r = self._reader()
        if r is None:
            raise IOError("File not open for reading")
        out = r.readline() if (size is None or size < 0) else r.readline(int(size))
        try:
            self._position = r.tell()
        except Exception:
            pass
        if not self._text_mode and out is None:
            return b""
        if self._text_mode and out is None:
            return text_type("")
        return out

    def __iter__(self):
        return self

    def __next__(self):
        line = self.readline()
        if (self._text_mode and line == "") or (not self._text_mode and line == b""):
            raise StopIteration
        return line

    if PY2:
        next = __next__

    def seek(self, offset, whence=0):
        if self.closed:
            raise ValueError("I/O operation on closed file")
        r = self._reader()
        if r is None:
            raise IOError("File not open for reading")
        newpos = r.seek(int(offset), int(whence))
        self._position = newpos
        return newpos

    def tell(self):
        if self._reader() is not None:
            try:
                self._position = self._reader().tell()
            except Exception:
                pass
        return self._position

    # ---------- WRITE PATH (streaming) ----------

    def write(self, data):
        if self.closed:
            raise ValueError("I/O operation on closed file")
        if self._compressor is None:
            raise IOError("File not open for writing")

        if self._text_mode:
            enc = self.encoding or 'UTF-8'
            errs = self.errors or 'strict'
            if isinstance(data, text_type):
                data = self._normalize_newlines_for_write(data).encode(enc, errs)
            else:
                raise TypeError("write() expects text (unicode/str) in text mode")
        else:
            if not isinstance(data, binary_types):
                raise TypeError("write() expects bytes-like in binary mode")

        # Normalize Py3 memoryview and Py2 bytearray
        if (not PY2) and isinstance(data, memoryview):
            data = data.tobytes()
        elif PY2 and isinstance(data, bytearray):
            data = bytes(data)

        # Stage and compress in chunks
        self._write_buf += data
        if len(self._write_buf) >= (__filebuff_size__):  # 1 MiB threshold
            out = self._compressor.compress(bytes(self._write_buf))
            if out:
                self.file.write(out)
            del self._write_buf[:]
        return len(data)

    def flush(self):
        if self.closed:
            return
        if self._compressor is not None:
            if self._write_buf:
                out = self._compressor.compress(bytes(self._write_buf))
                if out:
                    self.file.write(out)
                del self._write_buf[:]
            out = self._compressor.flush(zlib.Z_SYNC_FLUSH)
            if out:
                self.file.write(out)
        if hasattr(self.file, 'flush'):
            self.file.flush()

    def close(self):
        if self.closed:
            return
        try:
            if self._compressor is not None:
                if self._write_buf:
                    self.file.write(self._compressor.compress(bytes(self._write_buf)))
                    del self._write_buf[:]
                final = self._compressor.flush(zlib.Z_FINISH)
                if final:
                    self.file.write(final)
            if hasattr(self.file, 'flush'):
                try:
                    self.file.flush()
                except Exception:
                    pass
        finally:
            # Only close underlying file if we opened it
            if self.file_path and self.file is not None:
                try:
                    self.file.close()
                except Exception:
                    pass
            # Clean up readers/spool
            try:
                if self._text_reader is not None:
                    self._text_reader.detach()
            except Exception:
                pass
            try:
                if self._spool is not None:
                    self._spool.close()
            except Exception:
                pass
            self.closed = True

    # ---------- Misc ----------

    def fileno(self):
        if hasattr(self.file, 'fileno'):
            return self.file.fileno()
        raise OSError("Underlying file object does not support fileno()")

    def isatty(self):
        return bool(getattr(self.file, 'isatty', lambda: False)())

    def truncate(self, size=None):
        # Prevent corruption of compressed streams
        raise OSError("truncate() is not supported for compressed streams")

    # ---------- Convenience constructors ----------
    @classmethod
    def open(cls, path, mode='rb', **kw):
        """
        Mirror built-in open() but for GzipFile.
        Example:
            with GzipFile.open("data.gz", "rt", encoding="utf-8") as f:
                print(f.readline())
        """
        return cls(file_path=path, mode=mode, **kw)

    @classmethod
    def from_fileobj(cls, fileobj, mode='rb', **kw):
        """
        Wrap an existing file-like object (caller retains ownership).
        """
        return cls(fileobj=fileobj, mode=mode, **kw)

    @classmethod
    def from_bytes(cls, data, mode='rb', **kw):
        """
        Read from an in-memory bytes buffer.
        Example:
            f = GzipFile.from_bytes(blob, mode='rt', encoding='utf-8', tolerant_read=True)
            text = f.read()
        """
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("from_bytes() expects a bytes-like object")
        bio = MkTempFile(bytes(data) if not isinstance(data, bytes) else data)
        return cls(fileobj=bio, mode=mode, **kw)

    # compatibility aliases for unwrapping utilities
    @property
    def fileobj(self):
        return self.file

    @property
    def myfileobj(self):
        return self.file

# ---------- Top-level helpers ----------
def gzip_decompress_bytes(blob, mode='rb', multi=True, **kw):
    """
    Decompress gzip data from a bytes blob.
    - mode='rb' -> returns bytes, mode='rt' -> returns text (set encoding/errors/newline in kw)
    - multi=True -> handle concatenated members (recommended)
      multi=False -> only first member (classic gzip behavior)
    Extra kwargs (passed to GzipFile): tolerant_read, scan_bytes, spool_threshold, encoding, errors, newline
    """
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        raise TypeError("gzip_decompress_bytes() expects a bytes-like object")

    if not multi and mode == 'rb' and not kw:
        # Fast path for a single member, binary mode, no options
        return _gzip_decompress(bytes(blob))

    # General path via streaming reader (supports text + options + multi-member)
    f = GzipFile.from_bytes(blob, mode=mode, **kw)
    try:
        return f.read()
    finally:
        f.close()

def gzip_compress_bytes(payload, level=6, text=False, **kw):
    """
    Compress payload into a single gzip member and return bytes.
    - text=True: 'payload' must be text; encoding/newline/errors (in kw) are used via GzipFile('wt')
    - text=False: 'payload' must be bytes-like; written via GzipFile('wb')
    You can pass newline/encoding/errors to control text encoding.
    """
    bio = MkTempFile()
    mode = 'wt' if text else 'wb'
    gf = GzipFile(fileobj=bio, mode=mode, level=level, **kw)
    try:
        gf.write(payload)
        gf.flush()  # optional; final trailer is written on close
    finally:
        gf.close()
    return bio.getvalue()

def gzip_decompress_bytes_first_member(blob):
    """
    Explicit helper: return ONLY the first gzip member's payload (bytes).
    Equivalent to gzip_decompress_bytes(..., multi=False, mode='rb').
    """
    return _gzip_decompress(bytes(blob))

def gzip_decompress_bytes_all_members(blob):
    """
    Explicit helper: return ALL members' concatenated payloads (bytes).
    Equivalent to gzip_decompress_bytes(..., multi=True, mode='rb').
    """
    return _gzip_decompress_multimember(bytes(blob))

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

# =========================
#   Byte / text helpers
# =========================
def _mv_tobytes(mv):
    """Compat: memoryview to bytes (Py3: tobytes, Py2: tostring)."""
    return mv.tobytes() if hasattr(mv, "tobytes") else mv.tostring()

# =========================
#   Byte / text helpers
# =========================
def _iter_bytes(msg):
    """Iterate ints 0..255 over msg on Py2/3 efficiently."""
    if isinstance(msg, memoryview):
        b = _mv_tobytes(msg)
    else:
        try:
            b = _mv_tobytes(memoryview(msg))
        except TypeError:
            # iterable of ints fallback
            for x in msg:
                yield int(x) & 0xFF
            return
    for ch in b:
        if not isinstance(ch, int):  # Py2: str of len 1
            ch = ord(ch)
        yield ch & 0xFF


def _delim_bytes(delimiter):
    if delimiter is None:
        delimiter = __file_format_dict__['format_delimiter']
    return delimiter.encode('utf-8') if isinstance(delimiter, basestring) else bytes(delimiter)

def _serialize_header_fields(value, delimiter):
    """
    Accept list/tuple (joined with delimiter + trailing delimiter) or single field.
    Returns bytes.
    """
    d = _delim_bytes(delimiter)
    if isinstance(value, (list, tuple)):
        parts = []
        for v in value:
            if isinstance(v, (bytes, bytearray, memoryview)):
                parts.append(bytes(v))
            elif isinstance(v, basestring) or v is None:
                parts.append((u"" if v is None else unicode(v)).encode('utf-8'))
            else:
                parts.append(str(v).encode('utf-8'))
        return d.join(parts) + d
    # single field
    return _to_bytes(value)

def _hex_pad(n, width_bits):
    width = (width_bits + 3) // 4
    return format(n, '0{}x'.format(width)).lower()

# =========================
#   Reflection + tables
# =========================
def _reflect(v, width):
    r = 0
    for _ in range(width):
        r = (r << 1) | (v & 1)
        v >>= 1
    return r

_crc_table_cache = {}  # (width, poly, refin) -> table[256]

def _build_table(width, poly, refin):
    key = (width, poly, refin)
    tbl = _crc_table_cache.get(key)
    if tbl is not None:
        return tbl

    mask = (1 << width) - 1
    tbl = [0] * 256
    if refin:
        rpoly = _reflect(poly, width)
        for i in range(256):
            crc = i
            for _ in range(8):
                crc = (crc >> 1) ^ rpoly if (crc & 1) else (crc >> 1)
            tbl[i] = crc & mask
    else:
        top = 1 << (width - 1)
        for i in range(256):
            crc = i << (width - 8)
            for _ in range(8):
                crc = ((crc << 1) ^ poly) & mask if (crc & top) else ((crc << 1) & mask)
            tbl[i] = crc & mask
    _crc_table_cache[key] = tbl
    return tbl

# =========================
#  Generic (table) CRC API
# =========================
def crc_generic(msg, width, poly, init, xorout, refin, refout):
    mask = (1 << width) - 1
    table = _build_table(width, poly, refin)

    crc = init & mask
    if refin:
        for b in _iter_bytes(msg):
            crc = table[(crc ^ b) & 0xFF] ^ (crc >> 8)
    else:
        shift = width - 8
        for b in _iter_bytes(msg):
            crc = table[((crc >> shift) ^ b) & 0xFF] ^ ((crc << 8) & mask)

    if refout ^ refin:
        crc = _reflect(crc, width)
    return (crc ^ xorout) & mask

# --- helpers --------------------------------------------------------------

try:
    # Python 2 may not have algorithms_available
    _ALGORITHMS_AVAILABLE = set(hashlib.algorithms_available)
except AttributeError:
    _ALGORITHMS_AVAILABLE = set(getattr(hashlib, "algorithms", []))


def _coerce_bytes(data):
    """Return `data` as a bytes object (Py2 / Py3)."""
    if isinstance(data, memoryview):
        # Py3 has .tobytes(), Py2 falls back to bytes()
        try:
            return data.tobytes()
        except AttributeError:
            return bytes(data)

    if isinstance(data, bytearray):
        return bytes(data)

    if not isinstance(data, bytes):
        # E.g. list of ints, unicode, etc.
        return bytes(bytearray(data))

    return data


def _bytes_to_int(b):
    """Big-endian bytes -> int, Py2/3 safe."""
    if not isinstance(b, (bytes, bytearray)):
        b = _coerce_bytes(b)

    value = 0
    for ch in b:
        if not isinstance(ch, int):  # Py2: ch is a 1-char string
            ch = ord(ch)
        value = (value << 8) | ch
    return value

# =========================
#     Public checksum API
# =========================
def GetHeaderChecksum(inlist=None, checksumtype="md5", encodedata=True, formatspecs=__file_format_dict__, saltkey=None):
    """
    Serialize header fields (list/tuple => joined with delimiter + trailing delimiter;
    or a single field) and compute the requested checksum. Returns lowercase hex.
    """
    algo_key = (checksumtype or "md5").lower()

    delim = formatspecs.get('format_delimiter', u"\0")
    hdr_bytes = _serialize_header_fields(inlist or [], delim)
    if encodedata and not isinstance(hdr_bytes, (bytes, bytearray, memoryview)):
        hdr_bytes = _to_bytes(hdr_bytes)
    hdr_bytes = bytes(hdr_bytes)
    saltkey = _to_bytes(saltkey)
    if CheckSumSupport(algo_key, hashlib_guaranteed):
        if(saltkey is None):
            h = hashlib.new(algo_key, hdr_bytes)
        else:
            h = hmac.new(saltkey, hdr_bytes, digestmod=algo_key)
        return h.hexdigest().lower()

    return "0"

def GetFileChecksum(inbytes, checksumtype="md5", encodedata=True, formatspecs=__file_format_dict__, saltkey=None):
    """
    Accepts bytes/str/file-like.
      - Hashlib algos: streamed in 1 MiB chunks.
      - CRC algos (crc16_ansi/ccitt/x25/kermit, crc64_iso/ecma): streamed via CRCContext for file-like.
      - Falls back to one-shot for non-file-like inputs.
    """
    algo_key = (checksumtype or "md5").lower()
    saltkey = _to_bytes(saltkey)
    # file-like streaming
    if hasattr(inbytes, "read"):
        # hashlib

        if CheckSumSupport(algo_key, hashlib_guaranteed):
            if(saltkey is None):
                h = hashlib.new(algo_key)
            else:
                h = hmac.new(saltkey, digestmod=algo_key)
            while True:
                chunk = inbytes.read(__filebuff_size__)
                if not chunk:
                    break
                if not isinstance(chunk, (bytes, bytearray, memoryview)):
                    chunk = bytes(bytearray(chunk))
                h.update(chunk)
            return h.hexdigest().lower()

        # not known streaming algo: fallback to one-shot bytes
        data = inbytes.read()
        if not isinstance(data, (bytes, bytearray, memoryview)):
            data = bytes(bytearray(data))
    else:
        data = _to_bytes(inbytes) if (encodedata or not isinstance(inbytes, (bytes, bytearray, memoryview))) else inbytes
        data = bytes(data)

    # one-shot

    if CheckSumSupport(algo_key, hashlib_guaranteed):
        if(saltkey is None):
            h = hashlib.new(algo_key, data)
        else:
            h = hmac.new(saltkey, data, digestmod=algo_key)
        return h.hexdigest().lower()

    return "0"

def ValidateHeaderChecksum(inlist=None, checksumtype="md5", inchecksum="0", formatspecs=__file_format_dict__, saltkey=None):
    calc = GetHeaderChecksum(inlist, checksumtype, True, formatspecs, saltkey)
    want = (inchecksum or "0").strip().lower()
    if want.startswith("0x"):
        want = want[2:]
    return CheckChecksums(want, calc)

def ValidateFileChecksum(infile, checksumtype="md5", inchecksum="0", formatspecs=__file_format_dict__, saltkey=None):
    calc = GetFileChecksum(infile, checksumtype, True, formatspecs, saltkey)
    want = (inchecksum or "0").strip().lower()
    if want.startswith("0x"):
        want = want[2:]
    return CheckChecksums(want, calc)

def CheckChecksums(inchecksum, outchecksum):
    # Normalize as text first
    calc = (inchecksum or "0").strip().lower()
    want = (outchecksum or "0").strip().lower()

    if want.startswith("0x"):
        want = want[2:]

    # Now force both to bytes
    calc_b = _to_bytes(calc)   # defaults to utf-8, strict
    want_b = _to_bytes(want)

    return hmac.compare_digest(want_b, calc_b)

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


# ========= pushback-aware delimiter reader =========
class _DelimiterReader(object):
    """
    Chunked reader that consumes up to N occurrences of a byte delimiter.
    - Works with non-seekable streams by stashing over-read bytes on fp._read_until_delim_pushback
    - For seekable streams, rewinds over-read via seek(-n, SEEK_CUR)
    """
    _PB_ATTR = "_read_until_delim_pushback"

    def __init__(self, fp, delimiter, chunk_size=8192, max_read=64 * 1024 * 1024):
        if not hasattr(fp, "read"):
            raise ValueError("fp must be a readable file-like object")

        # normalize delimiter -> bytes
        if delimiter is None:
            delimiter = u"\0"
        if isinstance(delimiter, str):
            delimiter_b = delimiter.encode("utf-8")
        else:
            delimiter_b = bytes(delimiter)
        if not delimiter_b:
            raise ValueError("delimiter must not be empty")

        self.fp = fp
        self.delim = delimiter_b
        self.dlen = len(delimiter_b)
        self.chunk = int(chunk_size)
        self.max_read = int(max_read)

        self._buf = bytearray()
        self._total = 0

        # detect seekability (best-effort)
        self._seekable = bool(getattr(fp, "seekable", lambda: hasattr(fp, "seek"))())
        if not self._seekable:
            self._seekable = hasattr(fp, "seek") and hasattr(fp, "tell")

        # Preload any pushback from previous reads on this fp
        pb = getattr(fp, self._PB_ATTR, None)
        if pb:
            self._buf.extend(pb)
            setattr(fp, self._PB_ATTR, bytearray())  # consume

    def _read_more(self):
        data = self.fp.read(self.chunk)
        if not data:
            return False
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("fp.read() must return bytes-like")
        if isinstance(data, memoryview):
            data = data.tobytes()
        self._buf.extend(data)
        self._total += len(data)
        if self._total > self.max_read:
            raise ValueError("Maximum read limit reached without finding the delimiter")
        return True

    def _pushback(self, over_bytes):
        """Return extra bytes to the stream (seek back) or stash on the fp."""
        if not over_bytes:
            return
        if self._seekable:
            try:
                self.fp.seek(-len(over_bytes), io.SEEK_CUR)
                return
            except Exception:
                pass
        # Non-seekable: stash for next call on this fp
        pb = getattr(self.fp, self._PB_ATTR, None)
        if pb is None:
            setattr(self.fp, self._PB_ATTR, bytearray(over_bytes))
        else:
            pb.extend(over_bytes)

    def read_one_piece(self):
        """
        Read bytes up to (but not including) the next delimiter.
        Returns (piece_bytes, found_delimiter_bool).
        """
        out = bytearray()
        while True:
            idx = self._buf.find(self.delim)
            if idx != -1:
                # Found delimiter in buffer
                out.extend(self._buf[:idx])
                over = self._buf[idx + self.dlen:]
                self._buf[:] = b""
                self._pushback(over)
                return bytes(out), True

            # No delimiter present: emit buffer and read more
            if self._buf:
                out.extend(self._buf)
                self._buf[:] = b""

            if not self._read_more():
                # EOF: return whatever we have (possibly empty), no delimiter
                return bytes(out), False

    def read_n_pieces(self, n, pad_to_n=False):
        """
        Read up to n pieces (n delimiters). Returns list of bytes; len <= n.
        If pad_to_n=True, pads with b"" until length == n (avoids downstream IndexError).
        """
        n = int(n)
        parts = []
        while len(parts) < n:
            piece, found = self.read_one_piece()
            if not found and piece == b"":
                break  # true EOF with nothing more
            parts.append(piece)
            if not found:
                # EOF after a final unterminated piece
                break
        if pad_to_n and len(parts) < n:
            parts.extend([b""] * (n - len(parts)))
        return parts

# ========= helpers =========
def _default_delim(delimiter):
    # Try your global spec if present; else default to NUL
    try:
        if delimiter is None:
            delimiter = __file_format_dict__['format_delimiter']
    except Exception:
        pass
    return delimiter if delimiter is not None else u"\0"

def _decode_text(b, errors):
    return b.decode('utf-8', errors=errors)

def _read_exact(fp, n):
    """Read exactly n bytes or raise IOError on premature EOF."""
    want = int(n)
    out = bytearray()
    while len(out) < want:
        chunk = fp.read(want - len(out))
        if not chunk:
            raise IOError("Unexpected EOF: wanted {} more bytes".format(want - len(out)))
        if isinstance(chunk, memoryview):
            chunk = chunk.tobytes()
        out.extend(chunk)
    return bytes(out)

def _expect_delimiter(fp, delimiter):
    """Read exactly len(delimiter) bytes and require an exact match (no seeking)."""
    delim = _default_delim(delimiter)
    if isinstance(delim, str):
        delim_b = delim.encode('utf-8')
    else:
        delim_b = bytes(delim)
    got = _read_exact(fp, len(delim_b))
    if got != delim_b:
        raise ValueError("Delimiter mismatch: expected {!r}, got {!r}".format(delim_b, got))

# ========= unified public API (bytes/text control) =========
def read_until_delimiter(fp,
                         delimiter=b"\0",
                         max_read=None,
                         chunk_size=None,
                         decode=True,
                         errors=None):
    """
    Read until the first occurrence of 'delimiter'. Strips the delimiter.
    - Returns text (UTF-8) when decode=True; bytes when decode=False.
    - Non-seekable streams are supported via pushback on the file object.
    Py2/3 compatible (no keyword-only args).
    """
    if max_read is None:
        max_read = 64 * 1024 * 1024
    if chunk_size is None:
        chunk_size = 8192
    if errors is None:
        errors = "strict"

    r = _DelimiterReader(fp, delimiter=_default_delim(delimiter),
                         chunk_size=chunk_size, max_read=max_read)
    piece, _found = r.read_one_piece()
    return _decode_text(piece, errors) if decode else piece


def read_until_n_delimiters(fp,
                            delimiter=b"\0",
                            num_delimiters=1,
                            max_read=None,
                            chunk_size=None,
                            decode=True,
                            errors=None,
                            pad_to_n=False):
    """
    Read up to 'num_delimiters' occurrences. Returns list of pieces (len <= N).
    If pad_to_n=True, pads with empty pieces to length N (useful for rigid parsers).
    Py2/3 compatible (no keyword-only args).
    """
    if max_read is None:
        max_read = 64 * 1024 * 1024
    if chunk_size is None:
        chunk_size = 8192
    if errors is None:
        errors = "strict"

    r = _DelimiterReader(fp, delimiter=_default_delim(delimiter),
                         chunk_size=chunk_size, max_read=max_read)
    parts = r.read_n_pieces(num_delimiters, pad_to_n=pad_to_n)
    if decode:
        return [_decode_text(p, errors) for p in parts]
    return parts


# ========= back-compat wrappers (your original names) =========
def ReadTillNullByteOld(fp, delimiter=_default_delim(None)):
    # emulate byte-by-byte via chunk_size=1; decode with 'replace' like your Alt
    return read_until_delimiter(fp, delimiter, max_read=64 * 1024 * 1024, chunk_size=1,
                                decode=True, errors="replace")

def ReadUntilNullByteOld(fp, delimiter=_default_delim(None)):
    return ReadTillNullByteOld(fp, delimiter)

def ReadTillNullByteAlt(fp, delimiter=_default_delim(None), chunk_size=1024, max_read=64 * 1024 * 1024):
    return read_until_delimiter(fp, delimiter, max_read=max_read, chunk_size=chunk_size,
                                decode=True, errors="replace")

def ReadUntilNullByteAlt(fp, delimiter=_default_delim(None), chunk_size=1024, max_read=64 * 1024 * 1024):
    return ReadTillNullByteAlt(fp, delimiter, chunk_size, max_read)

def ReadTillNullByte(fp, delimiter=_default_delim(None), max_read=64 * 1024 * 1024):
    return read_until_delimiter(fp, delimiter, max_read=max_read, chunk_size=8192,
                                decode=True, errors="strict")

def ReadUntilNullByte(fp, delimiter=_default_delim(None), max_read=64 * 1024 * 1024):
    return ReadTillNullByte(fp, delimiter, max_read)

def ReadTillNullByteByNum(fp, delimiter=_default_delim(None), num_delimiters=1,
                          chunk_size=1024, max_read=64 * 1024 * 1024):
    # Return list of text parts; **pad to N** to avoid IndexError in rigid parsers
    return read_until_n_delimiters(fp, delimiter, num_delimiters,
                                   max_read=max_read, chunk_size=chunk_size,
                                   decode=True, errors="replace", pad_to_n=True)

def ReadUntilNullByteByNum(fp, delimiter=_default_delim(None), num_delimiters=1,
                           chunk_size=1024, max_read=64 * 1024 * 1024):
    return ReadTillNullByteByNum(fp, delimiter, num_delimiters, chunk_size, max_read)


def SeekToEndOfFile(fp):
    lasttell = 0
    while(True):
        fp.seek(1, 1)
        if(lasttell == fp.tell()):
            break
        lasttell = fp.tell()
    return True


# ========= your header readers (seek-safe, variable field counts handled) =========
def ReadFileHeaderData(fp, rounds=0, delimiter=_default_delim(None)):
    """Read `rounds` delimited header fields. Returns a list[str]."""
    if not hasattr(fp, "read"):
        return False
    rounds = int(rounds)
    if rounds <= 0:
        return []
    out = []
    for _ in range(rounds):
        out.append(read_until_delimiter(fp, delimiter, decode=True, errors="strict"))
    return out

def ReadFileHeaderDataBySize(fp, delimiter=_default_delim(None)):
    """
    Layout:
      [headersize-hex]<delim>[subheader-bytes...][delim]
    where the subheader bytes themselves contain:
      [headernumfields-hex]<delim><field1><delim>...<fieldN><delim>
    """
    if not hasattr(fp, "read"):
        return False

    # 1) Size of the subheader block (hex)
    preheaderdata = [read_until_delimiter(fp, delimiter, decode=True, errors="strict")]
    headersize = int(preheaderdata[0].strip() or "0", 16)
    if headersize <= 0:
        return []

    # 2) Read exactly headersize bytes into an in-memory temp (no seeking)
    subfp = MkTempFile(inmem=True, isbytes=True)
    subfp.write(_read_exact(fp, headersize))

    # 3) Verify & consume the delimiter after the subheader block (no seeking)
    _expect_delimiter(fp, delimiter)

    # 4) Parse subheader: first the count, then that many fields (all delimited inside the block)
    subfp.seek(0)
    prealtheaderdata = [read_until_delimiter(subfp, delimiter, decode=True, errors="strict")]
    headernumfields = int(prealtheaderdata[0].strip() or "0", 16)

    # Read exactly headernumfields fields from the subheader bytes (pad to avoid IndexError)
    headerdata = read_until_n_delimiters(
        subfp, delimiter, num_delimiters=headernumfields, decode=True, errors="replace", pad_to_n=True
    )

    subfp.close()
    return preheaderdata + prealtheaderdata + headerdata

def ReadFileHeaderDataWoSize(fp, delimiter=_default_delim(None)):
    """
    Layout:
      [headersize-hex]<delim>[headernumfields-hex]<delim><field1><delim>...<fieldN><delim>
    (i.e., size and field count are both inline; no separate size-bounded subheader block)
    """
    if not hasattr(fp, "read"):
        return False

    # Read the first two hex fields in one pass (no seek)
    first_two = read_until_n_delimiters(fp, delimiter, num_delimiters=2, decode=True, errors="strict", pad_to_n=True)
    headersize = int(first_two[0].strip() or "0", 16)
    headernumfields = int(first_two[1].strip() or "0", 16)

    if headersize <= 0 or headernumfields <= 0:
        return []

    # Now read exactly `headernumfields` fields from the main stream (pad to avoid IndexError)
    headerdata = read_until_n_delimiters(
        fp, delimiter, num_delimiters=headernumfields, decode=True, errors="replace", pad_to_n=True
    )

    return first_two + headerdata


def ReadFileHeaderDataWithContent(fp, listonly=False, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__, saltkey=None):
    if(not hasattr(fp, "read")):
        return False
    delimiter = formatspecs['format_delimiter']
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
    elif(testyaml and fjsontype == "yaml"):
        fjsoncontent = {}
        fprejsoncontent = fp.read(fjsonsize).decode("UTF-8")
        if (fjsonsize > 0):
            try:
                # try base64 → utf-8 → YAML
                fjsonrawcontent = base64.b64decode(fprejsoncontent.encode("UTF-8")).decode("UTF-8")
                fjsoncontent = yaml.safe_load(fjsonrawcontent) or {}
            except (binascii.Error, UnicodeDecodeError, yaml.YAMLError):
                try:
                    # fall back to treating the bytes as plain text YAML
                    fjsonrawcontent = fprejsoncontent
                    fjsoncontent = yaml.safe_load(fjsonrawcontent) or {}
                except (UnicodeDecodeError, yaml.YAMLError):
                    # final fallback: empty
                    fprejsoncontent = ""
                    fjsonrawcontent = fprejsoncontent
                    fjsoncontent = {}
        else:
            fprejsoncontent = ""
            fjsonrawcontent = fprejsoncontent
            fjsoncontent = {}
    elif(not testyaml and fjsontype == "yaml"):
        fjsoncontent = {}
        fprejsoncontent = fp.read(fjsonsize).decode("UTF-8")
        fprejsoncontent = ""
        fjsonrawcontent = fprejsoncontent
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
    jsonfcs = GetFileChecksum(fprejsoncontent, fjsonchecksumtype, True, formatspecs, saltkey)
    if(not CheckChecksums(fjsonchecksum, jsonfcs) and not skipchecksum):
        VerbosePrintOut("File JSON Data Checksum Error with file " +
                        fname + " at offset " + str(fheaderstart))
        VerbosePrintOut("'" + fjsonchecksum + "' != " + "'" + jsonfcs + "'")
        return False
    fp.seek(len(delimiter), 1)
    newfcs = GetHeaderChecksum(HeaderOut[:-2], HeaderOut[-4].lower(), True, formatspecs, saltkey)
    HeaderOut.append(fjsoncontent)
    if(fcs != newfcs and not skipchecksum):
        VerbosePrintOut("File Header Checksum Error with file " +
                        fname + " at offset " + str(fheaderstart))
        VerbosePrintOut("'" + fcs + "' != " + "'" + newfcs + "'")
        return False
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
    newfccs = GetFileChecksum(fcontents, HeaderOut[-3].lower(), False, formatspecs, saltkey)
    fcontents.seek(0, 0)
    if(not CheckChecksums(fccs, newfccs) and not skipchecksum and not listonly):
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
            shutil.copyfileobj(cfcontents, fcontents, length=__filebuff_size__)
            cfcontents.close()
            fcontents.seek(0, 0)
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


def ReadFileHeaderDataWithContentToArray(fp, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__, saltkey=None):
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
    fblksize = int(HeaderOut[8], 16)
    fblocks = int(HeaderOut[9], 16)
    fflags = int(HeaderOut[10], 16)
    fatime = int(HeaderOut[11], 16)
    fmtime = int(HeaderOut[12], 16)
    fctime = int(HeaderOut[13], 16)
    fbtime = int(HeaderOut[14], 16)
    fmode = int(HeaderOut[15], 16)
    fchmode = stat.S_IMODE(fmode)
    ftypemod = stat.S_IFMT(fmode)
    fwinattributes = int(HeaderOut[16], 16)
    fcompression = HeaderOut[17]
    fcsize = int(HeaderOut[18], 16)
    fuid = int(HeaderOut[19], 16)
    funame = HeaderOut[20]
    fgid = int(HeaderOut[21], 16)
    fgname = HeaderOut[22]
    fid = int(HeaderOut[23], 16)
    finode = int(HeaderOut[24], 16)
    flinkcount = int(HeaderOut[25], 16)
    fdev = int(HeaderOut[26], 16)
    frdev = int(HeaderOut[27], 16)
    fseeknextfile = HeaderOut[28]
    fjsontype = HeaderOut[29]
    fjsonlen = int(HeaderOut[30], 16)
    fjsonsize = int(HeaderOut[31], 16)
    fjsonchecksumtype = HeaderOut[32]
    fjsonchecksum = HeaderOut[33]
    fextrasize = int(HeaderOut[34], 16)
    fextrafields = int(HeaderOut[35], 16)
    fextrafieldslist = []
    extrastart = 36
    extraend = extrastart + fextrafields
    while(extrastart < extraend):
        fextrafieldslist.append(HeaderOut[extrastart])
        extrastart = extrastart + 1
    fvendorfieldslist = []
    fvendorfields = 0;
    if(len(HeaderOut)>40):
        extrastart = extraend
        extraend = len(HeaderOut) - 4
        while(extrastart < extraend):
            fvendorfieldslist.append(HeaderOut[extrastart])
            extrastart = extrastart + 1
            fvendorfields = fvendorfields + 1
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
    elif(testyaml and fjsontype == "yaml"):
        fjsoncontent = {}
        fprejsoncontent = fp.read(fjsonsize).decode("UTF-8")
        if (fjsonsize > 0):
            try:
                # try base64 → utf-8 → YAML
                fjsonrawcontent = base64.b64decode(fprejsoncontent.encode("UTF-8")).decode("UTF-8")
                fjsoncontent = yaml.safe_load(fjsonrawcontent) or {}
            except (binascii.Error, UnicodeDecodeError, yaml.YAMLError):
                try:
                    # fall back to treating the bytes as plain text YAML
                    fjsonrawcontent = fprejsoncontent
                    fjsoncontent = yaml.safe_load(fjsonrawcontent) or {}
                except (UnicodeDecodeError, yaml.YAMLError):
                    # final fallback: empty
                    fprejsoncontent = ""
                    fjsonrawcontent = fprejsoncontent
                    fjsoncontent = {}
        else:
            fprejsoncontent = ""
            fjsonrawcontent = fprejsoncontent
            fjsoncontent = {}
    elif(not testyaml and fjsontype == "yaml"):
        fjsoncontent = {}
        fprejsoncontent = fp.read(fjsonsize).decode("UTF-8")
        fprejsoncontent = ""
        fjsonrawcontent = fprejsoncontent
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
    jsonfcs = GetFileChecksum(fprejsoncontent, fjsonchecksumtype, True, formatspecs, saltkey)
    if(not CheckChecksums(fjsonchecksum, jsonfcs) and not skipchecksum):
        VerbosePrintOut("File JSON Data Checksum Error with file " +
                        fname + " at offset " + str(fheaderstart))
        VerbosePrintOut("'" + fjsonchecksum + "' != " + "'" + jsonfcs + "'")
        return False
    fcs = HeaderOut[-2].lower()
    fccs = HeaderOut[-1].lower()
    newfcs = GetHeaderChecksum(HeaderOut[:-2], HeaderOut[-4].lower(), True, formatspecs, saltkey)
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
    newfccs = GetFileChecksum(fcontents, HeaderOut[-3].lower(), False, formatspecs, saltkey)
    fcontents.seek(0, 0)
    if(not CheckChecksums(fccs, newfccs) and not skipchecksum and not listonly):
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
            shutil.copyfileobj(cfcontents, fcontents, length=__filebuff_size__)
            cfcontents.close()
            fcontents.seek(0, 0)
            fccs = GetFileChecksum(fcontents, HeaderOut[-3].lower(), False, formatspecs, saltkey)
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
    outlist = {'fheadersize': fheadsize, 'fhstart': fheaderstart, 'fhend': fhend, 'ftype': ftype, 'fencoding': fencoding, 'fcencoding': fcencoding, 'fname': fname, 'fbasedir': fbasedir, 'flinkname': flinkname, 'fsize': fsize, 'fblksize': fblksize, 'fblocks': fblocks, 'fflags': fflags, 'fatime': fatime, 'fmtime': fmtime, 'fctime': fctime, 'fbtime': fbtime, 'fmode': fmode, 'fchmode': fchmode, 'ftypemod': ftypemod, 'fwinattributes': fwinattributes, 'fcompression': fcompression, 'fcsize': fcsize, 'fuid': fuid, 'funame': funame, 'fgid': fgid, 'fgname': fgname, 'finode': finode, 'flinkcount': flinkcount,
               'fdev': fdev, 'frdev': frdev, 'fseeknextfile': fseeknextfile, 'fheaderchecksumtype': HeaderOut[-4], 'fjsonchecksumtype': fjsonchecksumtype, 'fcontentchecksumtype': HeaderOut[-3], 'fnumfields': fnumfields + 2, 'frawheader': HeaderOut, 'fvendorfields': fvendorfields, 'fvendordata': fvendorfieldslist, 'fextrafields': fextrafields, 'fextrafieldsize': fextrasize, 'fextradata': fextrafieldslist, 'fjsontype': fjsontype, 'fjsonlen': fjsonlen, 'fjsonsize': fjsonsize, 'fjsonrawdata': fjsonrawcontent, 'fjsondata': fjsoncontent, 'fjstart': fjstart, 'fjend': fjend, 'fheaderchecksum': fcs, 'fjsonchecksum': fjsonchecksum, 'fcontentchecksum': fccs, 'fhascontents': pyhascontents, 'fcontentstart': fcontentstart, 'fcontentend': fcontentend, 'fcontentasfile': contentasfile, 'fcontents': fcontents}
    return outlist


def ReadFileHeaderDataWithContentToList(fp, listonly=False, contentasfile=False, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__, saltkey=None):
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
    fblksize = int(HeaderOut[8], 16)
    fblocks = int(HeaderOut[9], 16)
    fflags = int(HeaderOut[10], 16)
    fatime = int(HeaderOut[11], 16)
    fmtime = int(HeaderOut[12], 16)
    fctime = int(HeaderOut[13], 16)
    fbtime = int(HeaderOut[14], 16)
    fmode = int(HeaderOut[15], 16)
    fchmode = stat.S_IMODE(fmode)
    ftypemod = stat.S_IFMT(fmode)
    fwinattributes = int(HeaderOut[16], 16)
    fcompression = HeaderOut[17]
    fcsize = int(HeaderOut[18], 16)
    fuid = int(HeaderOut[19], 16)
    funame = HeaderOut[20]
    fgid = int(HeaderOut[21], 16)
    fgname = HeaderOut[22]
    fid = int(HeaderOut[23], 16)
    finode = int(HeaderOut[24], 16)
    flinkcount = int(HeaderOut[25], 16)
    fdev = int(HeaderOut[26], 16)
    frdev = int(HeaderOut[27], 16)
    fseeknextfile = HeaderOut[28]
    fjsontype = HeaderOut[29]
    fjsonlen = int(HeaderOut[30], 16)
    fjsonsize = int(HeaderOut[31], 16)
    fjsonchecksumtype = HeaderOut[32]
    fjsonchecksum = HeaderOut[33]
    fextrasize = int(HeaderOut[34], 16)
    fextrafields = int(HeaderOut[35], 16)
    fextrafieldslist = []
    extrastart = 36
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
    elif(testyaml and fjsontype == "yaml"):
        fjsoncontent = {}
        fprejsoncontent = fp.read(fjsonsize).decode("UTF-8")
        if (fjsonsize > 0):
            try:
                # try base64 → utf-8 → YAML
                fjsonrawcontent = base64.b64decode(fprejsoncontent.encode("UTF-8")).decode("UTF-8")
                fjsoncontent = yaml.safe_load(fjsonrawcontent) or {}
            except (binascii.Error, UnicodeDecodeError, yaml.YAMLError):
                try:
                    # fall back to treating the bytes as plain text YAML
                    fjsonrawcontent = fprejsoncontent
                    fjsoncontent = yaml.safe_load(fjsonrawcontent) or {}
                except (UnicodeDecodeError, yaml.YAMLError):
                    # final fallback: empty
                    fprejsoncontent = ""
                    fjsonrawcontent = fprejsoncontent
                    fjsoncontent = {}
        else:
            fprejsoncontent = ""
            fjsonrawcontent = fprejsoncontent
            fjsoncontent = {}
    elif(not testyaml and fjsontype == "yaml"):
        fjsoncontent = {}
        fprejsoncontent = fp.read(fjsonsize).decode("UTF-8")
        fprejsoncontent = ""
        fjsonrawcontent = fprejsoncontent
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
    jsonfcs = GetFileChecksum(fprejsoncontent, fjsonchecksumtype, True, formatspecs, saltkey)
    if(not CheckChecksums(fjsonchecksum, jsonfcs) and not skipchecksum):
        VerbosePrintOut("File JSON Data Checksum Error with file " +
                        fname + " at offset " + str(fheaderstart))
        VerbosePrintOut("'" + fjsonchecksum + "' != " + "'" + jsonfcs + "'")
        return False
    fcs = HeaderOut[-2].lower()
    fccs = HeaderOut[-1].lower()
    newfcs = GetHeaderChecksum(HeaderOut[:-2], HeaderOut[-4].lower(), True, formatspecs, saltkey)
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
    newfccs = GetFileChecksum(fcontents, HeaderOut[-3].lower(), False, formatspecs, saltkey)
    if(not CheckChecksums(fccs, newfccs) and not skipchecksum and not listonly):
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
            shutil.copyfileobj(cfcontents, fcontents, length=__filebuff_size__)
            cfcontents.close()
            fcontents.seek(0, 0)
            fccs = GetFileChecksum(fcontents, HeaderOut[-3].lower(), False, formatspecs, saltkey)
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
    outlist = [ftype, fencoding, fcencoding, fname, flinkname, fsize, fblksize, fblocks, fflags, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression, fcsize, fuid, funame, fgid, fgname, fid,
               finode, flinkcount, fdev, frdev, fseeknextfile, fjsoncontent, fextrafieldslist, HeaderOut[-4], HeaderOut[-3], fcontents]
    return outlist


def ReadFileDataWithContent(fp, filestart=0, listonly=False, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__, saltkey=None):
    if(not hasattr(fp, "read")):
        return False
    delimiter = formatspecs['format_delimiter']
    curloc = filestart
    try:
        fp.seek(0, 2)
    except (OSError, ValueError):
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
    newfcs = GetHeaderChecksum([formstring] + inheader[:-1], fprechecksumtype, True, formatspecs, saltkey)
    if(not headercheck and not skipchecksum):
        VerbosePrintOut(
            "File Header Checksum Error with file at offset " + str(0))
        VerbosePrintOut("'" + fprechecksum + "' != " +
                        "'" + newfcs + "'")
        return False
    fnumfiles = int(inheader[6], 16)
    outfseeknextfile = inheaderdata[7]
    fjsonsize = int(inheaderdata[10], 16)
    fjsonchecksumtype = inheader[11]
    fjsonchecksum = inheader[12]
    fp.read(fjsonsize)
    # Next seek directive
    if(re.findall(r"^\+([0-9]+)", outfseeknextfile)):
        fseeknextasnum = int(outfseeknextfile.replace("+", ""))
        if(abs(fseeknextasnum) == 0):
            pass
        fp.seek(fseeknextasnum, 1)
    elif(re.findall(r"^\-([0-9]+)", outfseeknextfile)):
        fseeknextasnum = int(outfseeknextfile)
        if(abs(fseeknextasnum) == 0):
            pass
        fp.seek(fseeknextasnum, 1)
    elif(re.findall(r"^([0-9]+)", outfseeknextfile)):
        fseeknextasnum = int(outfseeknextfile)
        if(abs(fseeknextasnum) == 0):
            pass
        fp.seek(fseeknextasnum, 0)
    else:
        return False
    countnum = 0
    flist = []
    while(countnum < fnumfiles):
        HeaderOut = ReadFileHeaderDataWithContent(fp, listonly, uncompress, skipchecksum, formatspecs, saltkey)
        if(len(HeaderOut) == 0):
            break
        flist.append(HeaderOut)
        countnum = countnum + 1
    return flist


def ReadFileDataWithContentToArray(fp, filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__, saltkey=None, seektoend=False):
    if(not hasattr(fp, "read")):
        return False
    delimiter = formatspecs['format_delimiter']
    curloc = filestart
    try:
        fp.seek(0, 2)
    except (OSError, ValueError):
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
    fnumextrafieldsize = int(inheader[13], 16)
    fnumextrafields = int(inheader[14], 16)
    fextrafieldslist = []
    extrastart = 15
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
    fpythontype = inheader[4]
    fprojectname = inheader[4]
    fnumfiles = int(inheader[6], 16)
    fseeknextfile = inheader[7]
    fjsontype = inheader[8]
    fjsonlen = int(inheader[9], 16)
    fjsonsize = int(inheader[10], 16)
    fjsonchecksumtype = inheader[11]
    fjsonchecksum = inheader[12]
    fjsoncontent = {}
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
    elif(testyaml and fjsontype == "yaml"):
        fjsoncontent = {}
        fprejsoncontent = fp.read(fjsonsize).decode("UTF-8")
        if (fjsonsize > 0):
            try:
                # try base64 → utf-8 → YAML
                fjsonrawcontent = base64.b64decode(fprejsoncontent.encode("UTF-8")).decode("UTF-8")
                fjsoncontent = yaml.safe_load(fjsonrawcontent) or {}
            except (binascii.Error, UnicodeDecodeError, yaml.YAMLError):
                try:
                    # fall back to treating the bytes as plain text YAML
                    fjsonrawcontent = fprejsoncontent
                    fjsoncontent = yaml.safe_load(fjsonrawcontent) or {}
                except (UnicodeDecodeError, yaml.YAMLError):
                    # final fallback: empty
                    fprejsoncontent = ""
                    fjsonrawcontent = fprejsoncontent
                    fjsoncontent = {}
        else:
            fprejsoncontent = ""
            fjsonrawcontent = fprejsoncontent
            fjsoncontent = {}
    elif(not testyaml and fjsontype == "yaml"):
        fjsoncontent = {}
        fprejsoncontent = fp.read(fjsonsize).decode("UTF-8")
        fprejsoncontent = ""
        fjsonrawcontent = fprejsoncontent
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
    fjend = fp.tell()
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
    jsonfcs = GetFileChecksum(fprejsoncontent, fjsonchecksumtype, True, formatspecs, saltkey)
    if(not CheckChecksums(fjsonchecksum, jsonfcs) and not skipchecksum):
        VerbosePrintOut("File JSON Data Checksum Error with file " +
                        fname + " at offset " + str(fheaderstart))
        VerbosePrintOut("'" + fjsonchecksum + "' != " + "'" + jsonfcs + "'")
        return False
    fprechecksumtype = inheader[-2]
    fprechecksum = inheader[-1]
    headercheck = ValidateHeaderChecksum([formstring] + inheader[:-1], fprechecksumtype, fprechecksum, formatspecs)
    newfcs = GetHeaderChecksum([formstring] + inheader[:-1], fprechecksumtype, True, formatspecs, saltkey)
    if(not headercheck and not skipchecksum):
        VerbosePrintOut(
            "File Header Checksum Error with file at offset " + str(0))
        VerbosePrintOut("'" + fprechecksum + "' != " +
                        "'" + newfcs + "'")
        return False
    formversions = re.search('(.*?)(\\d+)', formstring).groups()
    fcompresstype = ""
    outlist = {'fnumfiles': fnumfiles, 'ffilestart': filestart, 'fformat': formversions[0], 'fcompression': fcompresstype, 'fencoding': fhencoding, 'fversion': formversions[1], 'fostype': fostype, 'fprojectname': fprojectname, 'fimptype': fpythontype, 'fheadersize': fheadsize, 'fsize': CatSizeEnd, 'fnumfields': fnumfields + 2, 'fformatspecs': formatspecs, 'fseeknextfile': fseeknextfile, 'fchecksumtype': fprechecksumtype, 'fheaderchecksum': fprechecksum, 'fjsonchecksumtype': fjsonchecksumtype, 'fjsontype': fjsontype, 'fjsonlen': fjsonlen, 'fjsonsize': fjsonsize, 'fjsonrawdata': fjsonrawcontent, 'fjsondata': fjsoncontent, 'fjstart': fjstart, 'fjend': fjend, 'fjsonchecksum': fjsonchecksum, 'frawheader': [formstring] + inheader, 'fextrafields': fnumextrafields, 'fextrafieldsize': fnumextrafieldsize, 'fextradata': fextrafieldslist, 'ffilelist': []}
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
            prejsonfcs = GetFileChecksum(prejsoncontent, prefjsonchecksumtype, True, formatspecs, saltkey)
            if(not CheckChecksums(prefjsonchecksum, prejsonfcs) and not skipchecksum):
                VerbosePrintOut("File JSON Data Checksum Error with file " +
                                prefname + " at offset " + str(prefhstart))
                VerbosePrintOut("'" + prefjsonchecksum + "' != " + "'" + prejsonfcs + "'")
                return False
            prenewfcs = GetHeaderChecksum(preheaderdata[:-2], preheaderdata[-4].lower(), True, formatspecs, saltkey)
            prefcs = preheaderdata[-2]
            if(not CheckChecksums(prefcs, prenewfcs) and not skipchecksum):
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
                prenewfccs = GetFileChecksum(prefcontents, preheaderdata[-3].lower(), False, formatspecs, saltkey)
                prefccs = preheaderdata[-1]
                pyhascontents = True
                if(not CheckChecksums(prefccs, prenewfccs) and not skipchecksum):
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
        HeaderOut = ReadFileHeaderDataWithContentToArray(fp, listonly, contentasfile, uncompress, skipchecksum, formatspecs, saltkey)
        if(len(HeaderOut) == 0):
            break
        HeaderOut.update({'fid': realidnum, 'fidalt': realidnum})
        outlist['ffilelist'].append(HeaderOut)
        countnum = countnum + 1
        realidnum = realidnum + 1
    outlist.update({'fp': fp})
    return outlist


def ReadFileDataWithContentToList(fp, filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=False, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__, saltkey=None, seektoend=False):
    if(not hasattr(fp, "read")):
        return False
    delimiter = formatspecs['format_delimiter']
    curloc = filestart
    try:
        fp.seek(0, 2)
    except (OSError, ValueError):
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
    fnumextrafieldsize = int(inheader[13], 16)
    fnumextrafields = int(inheader[14], 16)
    fextrafieldslist = []
    extrastart = 15
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
    fnumfiles = int(inheader[6], 16)
    fseeknextfile = inheaderdata[7]
    fjsontype = int(inheader[8], 16)
    fjsonlen = int(inheader[9], 16)
    fjsonsize = int(inheader[10], 16)
    fjsonchecksumtype = inheader[11]
    fjsonchecksum = inheader[12]
    fjsoncontent = {}
    fjstart = fp.tell()
    fprejsoncontent = fp.read(fjsonsize).decode("UTF-8")
    fjend = fp.tell()
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
    jsonfcs = GetFileChecksum(fprejsoncontent, fjsonchecksumtype, True, formatspecs, saltkey)
    if(not CheckChecksums(fjsonchecksum, jsonfcs) and not skipchecksum):
        VerbosePrintOut("File JSON Data Checksum Error with file " +
                        fname + " at offset " + str(fheaderstart))
        VerbosePrintOut("'" + fjsonchecksum + "' != " + "'" + jsonfcs + "'")
        return False
    fprechecksumtype = inheader[-2]
    fprechecksum = inheader[-1]
    headercheck = ValidateHeaderChecksum([formstring] + inheader[:-1], fprechecksumtype, fprechecksum, formatspecs)
    newfcs = GetHeaderChecksum([formstring] + inheader[:-1], fprechecksumtype, True, formatspecs, saltkey)
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
            prejsonfcs = GetFileChecksum(prefprejsoncontent, prefjsonchecksumtype, True, formatspecs, saltkey)
            if(not CheckChecksums(prefjsonchecksum, prejsonfcs) and not skipchecksum):
                VerbosePrintOut("File JSON Data Checksum Error with file " +
                                prefname + " at offset " + str(prefhstart))
                VerbosePrintOut("'" + prefjsonchecksum + "' != " + "'" + prejsonfcs + "'")
                return False
            prenewfcs = GetHeaderChecksum(preheaderdata[:-2], preheaderdata[-4].lower(), True, formatspecs, saltkey)
            prefcs = preheaderdata[-2]
            if(not CheckChecksums(prefcs, prenewfcs) and not skipchecksum):
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
                prenewfccs = GetFileChecksum(prefcontents, preheaderdata[-3].lower(), False, formatspecs, saltkey)
                prefccs = preheaderdata[-1]
                pyhascontents = True
                if(not CheckChecksums(prefccs, prenewfccs) and not skipchecksum):
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
        HeaderOut = ReadFileHeaderDataWithContentToList(fp, listonly, contentasfile, uncompress, skipchecksum, formatspecs, saltkey)
        if(len(HeaderOut) == 0):
            break
        outlist.append(HeaderOut)
        countnum = countnum + 1
        realidnum = realidnum + 1
    return outlist

def ReadInFileWithContentToArray(infile, fmttype="auto", filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_multi_dict__, saltkey=None, seektoend=False):
    if(hasattr(infile, "read") or hasattr(infile, "write")):
        fp = infile
        try:
            fp.seek(0, 2)
        except (OSError, ValueError):
            SeekToEndOfFile(fp)
        outfsize = fp.tell()
        fp.seek(filestart, 0)
        currentfilepos = fp.tell()
    elif(infile == "-"):
        fp = MkTempFile()
        shutil.copyfileobj(PY_STDIN_BUF, fp, length=__filebuff_size__)
        try:
            fp.seek(0, 2)
        except (OSError, ValueError):
            SeekToEndOfFile(fp)
        outfsize = fp.tell()
        fp.seek(filestart, 0)
        currentfilepos = fp.tell()
    elif(isinstance(infile, bytes) and sys.version_info[0] >= 3):
        fp = MkTempFile()
        fp.write(infile)
        try:
            fp.seek(0, 2)
        except (OSError, ValueError):
            SeekToEndOfFile(fp)
        outfsize = fp.tell()
        fp.seek(filestart, 0)
        currentfilepos = fp.tell()
    elif(re.findall(__download_proto_support__, infile)):
        fp = download_file_from_internet_file(infile)
        try:
            fp.seek(0, 2)
        except (OSError, ValueError):
            SeekToEndOfFile(fp)
        outfsize = fp.tell()
        fp.seek(filestart, 0)
        currentfilepos = fp.tell()
    elif(isinstance(infile, FileLikeAdapter)):
        try:
            fp.seek(0, 2)
        except (OSError, ValueError):
            SeekToEndOfFile(fp)
        outfsize = fp.tell()
        fp.seek(filestart, 0)
        currentfilepos = fp.tell()
    else:
        infile = RemoveWindowsPath(infile)
        fp = open(infile, "rb")
        try:
            fp.seek(0, 2)
        except (OSError, ValueError):
            SeekToEndOfFile(fp)
        outfsize = fp.tell()
        fp.seek(filestart, 0)
        currentfilepos = fp.tell()
    if(not isinstance(infile, FileLikeAdapter)):

        # For uncompressed: optional mmap
        mm = None
        try:
            base = _extract_base_fp(fp)
            if base is not None:
                mm = mmap.mmap(base.fileno(), 0, access=mmap.ACCESS_READ if "r" in mode else mmap.ACCESS_WRITE)
        except Exception:
            mm = None  # fallback to normal file stream
        readfp = FileLikeAdapter(fp, mode="rb", mm=mm)
    else:
        readfp = fp
    ArchiveList = []
    while True:
        if currentfilepos >= outfsize:   # stop when function signals False
            break
        oldfppos = readfp.tell()
        compresscheck = CheckCompressionType(readfp, formatspecs, currentfilepos, False)
        if(IsNestedDict(formatspecs) and compresscheck in formatspecs):
            pass
        else:
            checkcompressfile = CheckCompressionSubType(readfp, formatspecs, currentfilepos, False)
            if(IsNestedDict(formatspecs) and checkcompressfile in formatspecs):
                pass
            else:
                break
        readfp.seek(oldfppos, 0)
        if(compresscheck in formatspecs):
            if currentfilepos >= outfsize:   # stop when function signals False
                break
            oldfppos = readfp.tell()
            compresscheck = CheckCompressionType(readfp, formatspecs, currentfilepos, False)
            if(IsNestedDict(formatspecs) and compresscheck in formatspecs):
                informatspecs = formatspecs[compresscheck]
            else:
                break
            readfp.seek(oldfppos, 0)
            ArchiveList.append(ReadFileDataWithContentToArray(readfp, currentfilepos, seekstart, seekend, listonly, contentasfile, uncompress, skipchecksum, informatspecs, saltkey, seektoend))
            currentfilepos = readfp.tell()
        else:
            infp = UncompressFileAlt(readfp, formatspecs, currentfilepos)
            infp.seek(0, 0)
            currentinfilepos = infp.tell()
            try:
                infp.seek(0, 2)
            except (OSError, ValueError):
                SeekToEndOfFile(infp)
            outinfsize = infp.tell()
            infp.seek(currentinfilepos, 0)
            while True:
                if currentinfilepos >= outinfsize:   # stop when function signals False
                    break
                oldinfppos = infp.tell()
                compresscheck = CheckCompressionType(infp, formatspecs, currentinfilepos, False)
                if(IsNestedDict(formatspecs) and compresscheck in formatspecs):
                    informatspecs = formatspecs[compresscheck]
                else:
                    break
                infp.seek(oldinfppos, 0)
                ArchiveList.append(ReadFileDataWithContentToArray(infp, currentinfilepos, seekstart, seekend, listonly, contentasfile, uncompress, skipchecksum, informatspecs, saltkey, seektoend))
                currentinfilepos = infp.tell()
            currentfilepos = readfp.tell()
    return ArchiveList


def ReadInMultipleFileWithContentToArray(infile, fmttype="auto", filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_multi_dict__, saltkey=None, seektoend=False):
    if(isinstance(infile, (list, tuple, ))):
        pass
    else:
        infile = [infile]
    outretval = []
    for curfname in infile:
        outretval.append(ReadInFileWithContentToArray(curfname, fmttype, filestart, seekstart, seekend, listonly, contentasfile, uncompress, skipchecksum, formatspecs, saltkey, seektoend))
    return outretval

def ReadInMultipleFilesWithContentToArray(infile, fmttype="auto", filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_multi_dict__, saltkey=None, seektoend=False):
    return ReadInMultipleFileWithContentToArray(infile, fmttype, filestart, seekstart, seekend, listonly, contentasfile, uncompress, skipchecksum, formatspecs, saltkey, seektoend)


def ReadInFileWithContentToList(infile, fmttype="auto", filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_multi_dict__, saltkey=None, seektoend=False):
    if(hasattr(infile, "read") or hasattr(infile, "write")):
        fp = infile
        try:
            fp.seek(0, 2)
        except (OSError, ValueError):
            SeekToEndOfFile(fp)
        outfsize = fp.tell()
        fp.seek(filestart, 0)
        currentfilepos = fp.tell()
    elif(infile == "-"):
        fp = MkTempFile()
        shutil.copyfileobj(PY_STDIN_BUF, fp, length=__filebuff_size__)
        try:
            fp.seek(0, 2)
        except (OSError, ValueError):
            SeekToEndOfFile(fp)
        outfsize = fp.tell()
        fp.seek(filestart, 0)
        currentfilepos = fp.tell()
    elif(isinstance(infile, bytes) and sys.version_info[0] >= 3):
        fp = MkTempFile()
        fp.write(infile)
        try:
            fp.seek(0, 2)
        except (OSError, ValueError):
            SeekToEndOfFile(fp)
        outfsize = fp.tell()
        fp.seek(filestart, 0)
        currentfilepos = fp.tell()
    elif(re.findall(__download_proto_support__, infile)):
        fp = download_file_from_internet_file(infile)
        try:
            fp.seek(0, 2)
        except (OSError, ValueError):
            SeekToEndOfFile(fp)
        outfsize = fp.tell()
        fp.seek(filestart, 0)
        currentfilepos = fp.tell()
    elif(isinstance(infile, FileLikeAdapter)):
        try:
            fp.seek(0, 2)
        except (OSError, ValueError):
            SeekToEndOfFile(fp)
        outfsize = fp.tell()
        fp.seek(filestart, 0)
        currentfilepos = fp.tell()
    else:
        infile = RemoveWindowsPath(infile)
        fp = open(infile, "rb")
        try:
            fp.seek(0, 2)
        except (OSError, ValueError):
            SeekToEndOfFile(fp)
        outfsize = fp.tell()
        fp.seek(filestart, 0)
        currentfilepos = fp.tell()
    if(not isinstance(infile, FileLikeAdapter)):

        # For uncompressed: optional mmap
        mm = None
        try:
            base = _extract_base_fp(fp)
            if base is not None:
                mm = mmap.mmap(base.fileno(), 0, access=mmap.ACCESS_READ if "r" in mode else mmap.ACCESS_WRITE)
        except Exception:
            mm = None  # fallback to normal file stream
        readfp = FileLikeAdapter(fp, mode="rb", mm=mm)
    else:
        readfp = fp
    ArchiveList = []
    while True:
        if currentfilepos >= outfsize:   # stop when function signals False
            break
        oldfppos = readfp.tell()
        compresscheck = CheckCompressionType(readfp, formatspecs, currentfilepos, False)
        if(IsNestedDict(formatspecs) and compresscheck in formatspecs):
            pass
        else:
            checkcompressfile = CheckCompressionSubType(readfp, formatspecs, currentfilepos, False)
            if(IsNestedDict(formatspecs) and checkcompressfile in formatspecs):
                pass
            else:
                break
        readfp.seek(oldfppos, 0)
        if(compresscheck in formatspecs):
            if currentfilepos >= outfsize:   # stop when function signals False
                break
            oldfppos = readfp.tell()
            compresscheck = CheckCompressionType(readfp, formatspecs, currentfilepos, False)
            if(IsNestedDict(formatspecs) and compresscheck in formatspecs):
                informatspecs = formatspecs[compresscheck]
            else:
                break
            readfp.seek(oldfppos, 0)
            ArchiveList.append(ReadFileDataWithContentToList(readfp, currentfilepos, seekstart, seekend, listonly, contentasfile, uncompress, skipchecksum, informatspecs, saltkey, seektoend))
            currentfilepos = readfp.tell()
        else:
            infp = UncompressFileAlt(readfp, formatspecs, currentfilepos)
            infp.seek(0, 0)
            currentinfilepos = infp.tell()
            try:
                infp.seek(0, 2)
            except (OSError, ValueError):
                SeekToEndOfFile(infp)
            outinfsize = infp.tell()
            infp.seek(currentinfilepos, 0)
            while True:
                if currentinfilepos >= outinfsize:   # stop when function signals False
                    break
                oldinfppos = infp.tell()
                compresscheck = CheckCompressionType(infp, formatspecs, currentinfilepos, False)
                if(IsNestedDict(formatspecs) and compresscheck in formatspecs):
                    informatspecs = formatspecs[compresscheck]
                else:
                    break
                infp.seek(oldinfppos, 0)
                ArchiveList.append(ReadFileDataWithContentToList(infp, currentinfilepos, seekstart, seekend, listonly, contentasfile, uncompress, skipchecksum, informatspecs, saltkey, seektoend))
                currentinfilepos = infp.tell()
            currentfilepos = readfp.tell()
    return ArchiveList


def ReadInMultipleFileWithContentToList(infile, fmttype="auto", filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_multi_dict__, saltkey=None, seektoend=False):
    if(isinstance(infile, (list, tuple, ))):
        pass
    else:
        infile = [infile]
    outretval = {}
    for curfname in infile:
        outretval.append(ReadInFileWithContentToList(curfname, fmttype, filestart, seekstart, seekend, listonly, contentasfile, uncompress, skipchecksum, formatspecs, saltkey, seektoend))
    return outretval

def ReadInMultipleFilesWithContentToList(infile, fmttype="auto", filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_multi_dict__, saltkey=None, seektoend=False):
    return ReadInMultipleFileWithContentToList(infile, fmttype, filestart, seekstart, seekend, listonly, contentasfile, uncompress, skipchecksum, formatspecs, saltkey, seektoend)


def _field_to_bytes(x):
    """Convert one field to bytes (no delimiter)."""
    if x is None:
        return b""
    if isinstance(x, (bytes, bytearray, memoryview)):
        return bytes(x)
    if isinstance(x, unicode):
        return x.encode('utf-8')
    if isinstance(x, int):
        # Avoid bytes(int) => NULs; use decimal string
        return str(x).encode('utf-8')
    # Prefer __bytes__ if present
    to_bytes = getattr(x, '__bytes__', None)
    if callable(to_bytes):
        try:
            return bytes(x)
        except Exception:
            pass
    return (x if isinstance(x, unicode) else str(x)).encode('utf-8')


# ---------- Fixed implementations ----------

def AppendNullByte(indata, delimiter=__file_format_dict__['format_delimiter']):
    """
    Return <field-bytes> + <delimiter-bytes>.
    - Accepts bytes/bytearray/memoryview/str/unicode/int/None/other.
    - Always returns bytes.
    """
    d = _delim_bytes(delimiter)
    return _field_to_bytes(indata) + d


def AppendNullBytes(indata=None, delimiter=__file_format_dict__['format_delimiter']):
    """
    Join many fields with delimiter and append a trailing delimiter.
    Equivalent to: delimiter.join(map(bytes, indata)) + delimiter
    but robust and fast (O(n)).
    """
    if not indata:
        # Match old behavior: empty list -> b"" (no trailing delimiter)
        return b""
    d = _delim_bytes(delimiter)
    # Convert all fields to bytes once, then join
    parts = [_field_to_bytes(x) for x in indata]
    return d.join(parts) + d


def _hex_lower(n):
    return format(int(n), 'x').lower()

def AppendFileHeader(fp, numfiles, fencoding, extradata=[], jsondata={}, checksumtype=["md5", "md5"], formatspecs=__file_format_dict__, saltkey=None):
    """
    Build and write the archive file header.
    Returns the same file-like 'fp' on success, or False on failure.
    NOTE: This preserves the original field ordering & sizing logic.
    """
    # basic capability
    if not hasattr(fp, "write"):
        return False

    # normalize inputs
    delimiter = formatspecs['format_delimiter']
    d = _delim_bytes(delimiter)

    formver = formatspecs['format_ver']
    # "1.2.3" -> "123"
    fileheaderver = str(int(str(formver).replace(".", "")))
    magic_plus_ver = str(formatspecs['format_magic']) + fileheaderver

    # 1) fileheader = MAGIC+VER<delim>
    fileheader = AppendNullByte(magic_plus_ver, delimiter)

    # 2) normalize extradata -> list[str]
    if extradata is None:
        xlist = []
    elif isinstance(extradata, (list, tuple)):
        # coerce each item to text; we’ll bytes-encode in AppendNullBytes
        xlist = [x if isinstance(x, (bytes, bytearray)) else
                 (x if isinstance(x, str) else json.dumps(x, separators=(',', ':')))
                 for x in extradata]
    elif isinstance(extradata, dict) or IsNestedDictAlt(extradata):
        # compact JSON, ensure UTF-8 bytes → base64 → text
        j = json.dumps(extradata, separators=(',', ':')).encode("utf-8")
        xlist = [base64.b64encode(j).decode("utf-8")]
    else:
        # single non-dict value → make a single-element list
        xlist = [extradata]

    # 3) extras block (count + items), including its own serialized bytes length
    extrafields = _hex_lower(len(xlist))                         # count (hex)
    extrasizestr = AppendNullByte(extrafields, delimiter)        # count+delim
    if xlist:
        extrasizestr += AppendNullBytes(xlist, delimiter)        # items joined + trailing delim
    extrasizelen = _hex_lower(len(extrasizestr))                 # byte length of the extras block

    # 4) core header fields before checksum:
    #    tmpoutlenhex, fencoding, platform.system(), fnumfiles
    fnumfiles_hex = _hex_lower(numfiles)
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
    tmpoutlist = []
    tmpoutlist.append(fjsontype)
    tmpoutlist.append(fjsonlen)
    tmpoutlist.append(fjsonsize)
    if(len(jsondata) > 0):
        tmpoutlist.append(checksumtype[1])
        tmpoutlist.append(GetFileChecksum(fjsoncontent, checksumtype[1], True, formatspecs, saltkey))
    else:
        tmpoutlist.append("none")
        tmpoutlist.append(GetFileChecksum(fjsoncontent, "none", True, formatspecs, saltkey))
    # Preserve your original "tmpoutlen" computation exactly
    tmpoutlist.append(extrasizelen)
    tmpoutlist.append(extrafields)
    tmpoutlen = 8 + len(tmpoutlist) + len(xlist)
    tmpoutlenhex = _hex_lower(tmpoutlen)

    # Serialize the first group
    fnumfilesa = AppendNullBytes([tmpoutlenhex, fencoding, platform.system(), py_implementation, __program_name__, fnumfiles_hex, "+"+str(len(formatspecs['format_delimiter']))], delimiter)
    # Append tmpoutlist
    fnumfilesa += AppendNullBytes(tmpoutlist, delimiter)
    # Append extradata items if any
    if xlist:
        fnumfilesa += AppendNullBytes(xlist, delimiter)
    # Append checksum type
    fnumfilesa += AppendNullByte(checksumtype[0], delimiter)

    # 5) inner checksum over fnumfilesa
    outfileheadercshex = GetFileChecksum(fnumfilesa, checksumtype[0], True, formatspecs, saltkey)
    tmpfileoutstr = fnumfilesa + AppendNullByte(outfileheadercshex, delimiter)

    # 6) size of (tmpfileoutstr) excluding one delimiter, per your original math
    formheaersize = _hex_lower(len(tmpfileoutstr) - len(d))

    # 7) prepend the fileheader + size, recompute outer checksum
    fnumfilesa = (
        fileheader
        + AppendNullByte(formheaersize, delimiter)
        + fnumfilesa
    )

    outfileheadercshex = GetFileChecksum(fnumfilesa, checksumtype[0], True, formatspecs, saltkey)
    fnumfilesa += AppendNullByte(outfileheadercshex, delimiter)

    # 8) final total size field (again per your original logic)
    formheaersize = _hex_lower(len(fnumfilesa) - len(d))
    formheaersizestr = AppendNullByte(formheaersize, delimiter)  # computed but not appended in original
    # Note: you computed 'formheaersizestr' but didn’t append it afterward in the original either.
    # Keeping that behavior for compatibility.
    nullstrecd = formatspecs['format_delimiter'].encode('UTF-8')
    outfileout = fnumfilesa + fjsoncontent + nullstrecd
    # 9) write and try to sync
    try:
        fp.write(outfileout)
    except (OSError, io.UnsupportedOperation):
        return False

    try:
        # flush Python buffers
        if hasattr(fp, "flush"):
            fp.flush()
        # best-effort durability
        if hasattr(fp, "fileno"):
            try:
                os.fsync(fp.fileno())
            except (OSError, io.UnsupportedOperation, AttributeError):
                pass
    except Exception:
        # swallowing to match your tolerant behavior
        pass

    return fp


def MakeEmptyFilePointer(fp, fmttype=__file_format_default__, checksumtype=["md5", "md5"], formatspecs=__file_format_multi_dict__, saltkey=None):
    if(IsNestedDict(formatspecs) and fmttype in formatspecs):
        formatspecs = formatspecs[fmttype]
    elif(IsNestedDict(formatspecs) and fmttype not in formatspecs):
        fmttype = __file_format_default__
        formatspecs = formatspecs[fmttype]
    AppendFileHeader(fp, 0, "UTF-8", [], {}, checksumtype, formatspecs, saltkey)
    return fp


def MakeEmptyCatFilePointer(fp, fmttype=__file_format_default__, checksumtype=["md5", "md5"], formatspecs=__file_format_multi_dict__, saltkey=None):
    return MakeEmptyFilePointer(fp, fmttype, checksumtype, formatspecs, saltkey)


def MakeEmptyFile(outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["md5", "md5"], formatspecs=__file_format_multi_dict__, saltkey=None, returnfp=False):
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
        return MakeEmptyFilePointer(fp, fmttype, checksumtype, formatspecs, saltkey)
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
    AppendFileHeader(fp, 0, "UTF-8", ['hello', 'goodbye'], {}, checksumtype, formatspecs)
    if(outfile == "-" or outfile is None or hasattr(outfile, "read") or hasattr(outfile, "write")):
        fp = CompressOpenFileAlt(
            fp, compression, compressionlevel, compressionuselist, formatspecs)
        try:
            fp.flush()
            if(hasattr(os, "sync")):
                os.fsync(fp.fileno())
        except (io.UnsupportedOperation, AttributeError, OSError):
            pass
    if(outfile == "-"):
        fp.seek(0, 0)
        shutil.copyfileobj(fp, PY_STDOUT_BUF, length=__filebuff_size__)
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


def MakeEmptyCatFile(outfile, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["md5", "md5"], formatspecs=__file_format_dict__, saltkey=None, returnfp=False):
    return MakeEmptyFile(outfile, "auto", compression, compresswholefile, compressionlevel, compressionuselist, checksumtype, formatspecs, saltkey, returnfp)


def AppendFileHeaderWithContent(fp, filevalues=[], extradata=[], jsondata={}, filecontent="", checksumtype=["md5", "md5", "md5"], formatspecs=__file_format_dict__, saltkey=None):
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
        tmpoutlist.append(GetFileChecksum(fjsoncontent, checksumtype[2], True, formatspecs, saltkey))
    else:
        tmpoutlist.append("none")
        tmpoutlist.append(GetFileChecksum(fjsoncontent, "none", True, formatspecs, saltkey))
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
    outfileheadercshex = GetFileChecksum(outfileoutstr, checksumtype[0], True, formatspecs, saltkey)
    if(len(filecontent) == 0):
        outfilecontentcshex = GetFileChecksum(filecontent, "none", False, formatspecs, saltkey)
    else:
        outfilecontentcshex = GetFileChecksum(filecontent, checksumtype[1], False, formatspecs, saltkey)
    tmpfileoutstr = outfileoutstr + \
        AppendNullBytes([outfileheadercshex, outfilecontentcshex],
                        formatspecs['format_delimiter'])
    formheaersize = format(int(len(tmpfileoutstr) - len(formatspecs['format_delimiter'])), 'x').lower()
    outfileoutstr = AppendNullByte(
        formheaersize, formatspecs['format_delimiter']) + outfileoutstr
    outfileheadercshex = GetFileChecksum(outfileoutstr, checksumtype[0], True, formatspecs, saltkey)
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
    except (io.UnsupportedOperation, AttributeError, OSError):
        pass
    return fp

def AppendFilesWithContent(infiles, fp, dirlistfromtxt=False, extradata=[], jsondata={}, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, followlink=False, checksumtype=["md5", "md5", "md5", "md5", "md5"], formatspecs=__file_format_dict__, saltkey=None, verbose=False):
    if(not hasattr(fp, "write")):
        return False
    advancedlist = formatspecs['use_advanced_list']
    altinode = formatspecs['use_alt_inode']
    if(verbose):
        logging.basicConfig(format="%(message)s",
                            stream=PY_STDOUT_TEXT, level=logging.DEBUG)
    infilelist = []
    if(infiles == "-"):
        for line in PY_STDIN_TEXT:
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
    AppendFileHeader(fp, numfiles, "UTF-8", [], {}, [checksumtype[0], checksumtype[1]], formatspecs)
    try:
        fp.flush()
        if(hasattr(os, "sync")):
            os.fsync(fp.fileno())
    except (io.UnsupportedOperation, AttributeError, OSError):
        pass
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
        fblksize = 0
        if(hasattr(fstatinfo, "st_blksize")):
            fblksize = format(int(fstatinfo.st_blksize), 'x').lower()
        fblocks = 0
        if(hasattr(fstatinfo, "st_blocks")):
            fblocks = format(int(fstatinfo.st_blocks), 'x').lower()
        fflags = 0
        if(hasattr(fstatinfo, "st_flags")):
            fflags = format(int(fstatinfo.st_flags), 'x').lower()
        ftype = 0
        if(not followlink and hasattr(os.path, "isjunction") and os.path.isjunction(fname)):
            ftype = 13
        elif(stat.S_ISREG(fpremode)):
            if(hasattr(fstatinfo, "st_blocks") and fstatinfo.st_size > 0 and fstatinfo.st_blocks * 512 < fstatinfo.st_size):
                ftype = 12
            else:
                ftype = 0
        elif(not followlink and stat.S_ISLNK(fpremode)):
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
        if(not followlink and finode != 0):
            unique_id = (fstatinfo.st_dev, finode)
            if(ftype != 1):
                if(unique_id in inodetofile):
                    # Hard link detected
                    ftype = 1
                    flinkname = inodetofile[unique_id]
                else:
                    # First time seeing this inode
                    inodetofile[unique_id] = fname
                if(unique_id not in inodetoforminode):
                    inodetoforminode[unique_id] = curinode
                    curinode = curinode + 1
                if(altinode):
                    # altinode == True → use real inode number
                    fcurinode = format(int(unique_id[1]), 'x').lower()
                else:
                    # altinode == False → use synthetic inode id
                    fcurinode = format(int(inodetoforminode[unique_id]), 'x').lower()
        else:
            # Handle cases where inodes are not supported or symlinks are followed
            fcurinode = format(int(curinode), 'x').lower()
            curinode = curinode + 1
        curfid = curfid + 1
        if(ftype == 2):
            flinkname = os.readlink(fname)
            if(not os.path.exists(fname)):
                return False
        try:
            fdev = fstatinfo.st_rdev
        except AttributeError:
            fdev = 0
        try:
            frdev = fstatinfo.st_rdev
        except AttributeError:
            frdev = 0
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
        frdev = format(int(frdev), 'x').lower()
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
                shutil.copyfileobj(fpc, fcontents, length=__filebuff_size__)
                typechecktest = CheckCompressionType(fcontents, filestart=0, closefp=False)
                fcontents.seek(0, 0)
                if(typechecktest is not False):
                    typechecktest = GetBinaryFileType(fcontents, filestart=0, closefp=True)
                    fcontents.seek(0, 0)
                fcencoding = GetFileEncoding(fcontents, 0, False)[0]
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
                            shutil.copyfileobj(fcontents, cfcontents, length=__filebuff_size__)
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
                    shutil.copyfileobj(fcontents, cfcontents, length=__filebuff_size__)
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
        elif followlink and (ftype == 2 or ftype in data_types):
            if(not os.path.exists(fname)):
                return False
            with open(flinkname, "rb") as fpc:
                shutil.copyfileobj(fpc, fcontents, length=__filebuff_size__)
                typechecktest = CheckCompressionType(fcontents, filestart=0, closefp=False)
                fcontents.seek(0, 0)
                if(typechecktest is not False):
                    typechecktest = GetBinaryFileType(fcontents, filestart=0, closefp=True)
                    fcontents.seek(0, 0)
                fcencoding = GetFileEncoding(fcontents, 0, False)[0]
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
                            shutil.copyfileobj(fcontents, cfcontents, length=__filebuff_size__)
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
                    shutil.copyfileobj(fcontents, cfcontents, length=__filebuff_size__)
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
        tmpoutlist = [ftypehex, fencoding, fcencoding, fname, flinkname, fsize, fblksize, fblocks, fflags, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression,
                      fcsize, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev, frdev, "+"+str(len(formatspecs['format_delimiter']))]
        AppendFileHeaderWithContent(fp, tmpoutlist, extradata, jsondata, fcontents.read(), [checksumtype[2], checksumtype[3], checksumtype[4]], formatspecs, saltkey)
        try:
            fp.flush()
            if(hasattr(os, "sync")):
                os.fsync(fp.fileno())
        except (io.UnsupportedOperation, AttributeError, OSError):
            pass
    return fp

def AppendFilesWithContentFromTarFile(infile, fp, extradata=[], jsondata={}, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["md5", "md5", "md5", "md5", "md5"], formatspecs=__file_format_dict__, saltkey=None, verbose=False):
    if(not hasattr(fp, "write")):
        return False
    if(verbose):
        logging.basicConfig(format="%(message)s",
                            stream=PY_STDOUT_TEXT, level=logging.DEBUG)
    curinode = 0
    curfid = 0
    inodelist = []
    inodetofile = {}
    filetoinode = {}
    inodetoforminode = {}
    if(infile == "-"):
        infile = MkTempFile()
        shutil.copyfileobj(PY_STDIN_BUF, infile, length=__filebuff_size__)
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
    AppendFileHeader(fp, numfiles, "UTF-8", [], {}, [checksumtype[0], checksumtype[1]], formatspecs)
    try:
        fp.flush()
        if(hasattr(os, "sync")):
            os.fsync(fp.fileno())
    except (io.UnsupportedOperation, AttributeError, OSError):
        pass
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
        fblksize = 0
        if(hasattr(fstatinfo, "st_blksize")):
            fblksize = format(int(fstatinfo.st_blksize), 'x').lower()
        fblocks = 0
        if(hasattr(fstatinfo, "st_blocks")):
            fblocks = format(int(fstatinfo.st_blocks), 'x').lower()
        fflags = 0
        if(hasattr(fstatinfo, "st_flags")):
            fflags = format(int(fstatinfo.st_flags), 'x').lower()
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
        fdev = format(int("0"), 'x').lower()
        try:
            frdev = format(int(os.makedev(member.devmajor, member.devminor)), 'x').lower()
        except AttributeError:
            frdev = format(int(MakeDevAlt(member.devmajor, member.devminor)), 'x').lower()
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
            shutil.copyfileobj(fpc, fcontents, length=__filebuff_size__)
            fpc.close()
            typechecktest = CheckCompressionType(fcontents, filestart=0, closefp=False)
            fcontents.seek(0, 0)
            if(typechecktest is not False):
                typechecktest = GetBinaryFileType(fcontents, filestart=0, closefp=True)
                fcontents.seek(0, 0)
            fcencoding = GetFileEncoding(fcontents, 0, False)[0]
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
                        shutil.copyfileobj(fcontents, cfcontents, length=__filebuff_size__)
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
                shutil.copyfileobj(fcontents, cfcontents, length=__filebuff_size__)
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
        tmpoutlist = [ftypehex, fencoding, fcencoding, fname, flinkname, fsize, fblksize, fblocks, fflags, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression,
                      fcsize, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev, frdev, "+"+str(len(formatspecs['format_delimiter']))]
        AppendFileHeaderWithContent(fp, tmpoutlist, extradata, jsondata, fcontents.read(), [checksumtype[2], checksumtype[3], checksumtype[4]], formatspecs, saltkey)
        try:
            fp.flush()
            if(hasattr(os, "sync")):
                os.fsync(fp.fileno())
        except (io.UnsupportedOperation, AttributeError, OSError):
            pass
        fcontents.close()
    return fp

def AppendFilesWithContentFromZipFile(infile, fp, extradata=[], jsondata={}, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["md5", "md5", "md5", "md5", "md5"], formatspecs=__file_format_dict__, saltkey=None, verbose=False):
    if(not hasattr(fp, "write")):
        return False
    if(verbose):
        logging.basicConfig(format="%(message)s",
                            stream=PY_STDOUT_TEXT, level=logging.DEBUG)
    curinode = 0
    curfid = 0
    inodelist = []
    inodetofile = {}
    filetoinode = {}
    inodetoforminode = {}
    if(infile == "-"):
        infile = MkTempFile()
        shutil.copyfileobj(PY_STDIN_BUF, infile, length=__filebuff_size__)
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
    AppendFileHeader(fp, numfiles, "UTF-8", [], {}, [checksumtype[0], checksumtype[1]], formatspecs)
    try:
        fp.flush()
        if(hasattr(os, "sync")):
            os.fsync(fp.fileno())
    except (io.UnsupportedOperation, AttributeError, OSError):
        pass
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
            fpremode = int(stat.S_IFDIR | 0x1ff)
        else:
            fpremode = int(stat.S_IFREG | 0x1b6)
        flinkcount = 0
        fblksize = 0
        if(hasattr(fstatinfo, "st_blksize")):
            fblksize = format(int(fstatinfo.st_blksize), 'x').lower()
        fblocks = 0
        if(hasattr(fstatinfo, "st_blocks")):
            fblocks = format(int(fstatinfo.st_blocks), 'x').lower()
        fflags = 0
        if(hasattr(fstatinfo, "st_flags")):
            fflags = format(int(fstatinfo.st_flags), 'x').lower()
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
        frdev = format(int(0), 'x').lower()
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
            fwinattributes = format(int(zipinfo.external_attr & 0xFFFF), 'x').lower()
            if ((hasattr(member, "is_dir") and member.is_dir()) or member.filename.endswith('/')):
                fmode = format(int(stat.S_IFDIR | 0x1ff), 'x').lower()
                fchmode = stat.S_IMODE(int(stat.S_IFDIR | 0x1ff))
                ftypemod = stat.S_IFMT(int(stat.S_IFDIR | 0x1ff))
            else:
                fmode = format(int(stat.S_IFREG | 0x1b6), 'x').lower()
                fchmode = stat.S_IMODE(int(stat.S_IFREG | 0x1b6))
                ftypemod = stat.S_IFMT(int(stat.S_IFREG | 0x1b6))
        elif(zipinfo.create_system == 3):
            fwinattributes = format(int(zipinfo.external_attr & 0xFFFF), 'x').lower()
            fmode = format(int((zipinfo.external_attr >> 16) & 0xFFFF), 'x').lower()
            prefmode = int((zipinfo.external_attr >> 16) & 0xFFFF)
            if (prefmode == 0):
                if ((hasattr(member, "is_dir") and member.is_dir()) or member.filename.endswith('/')):
                    fmode = format(int(stat.S_IFDIR | 0x1ff), 'x').lower()
                    prefmode = int(stat.S_IFDIR | 0x1ff)
                    fchmode = stat.S_IMODE(prefmode)
                    ftypemod = stat.S_IFMT(prefmode)
                else:
                    fmode = format(int(stat.S_IFREG | 0x1b6), 'x').lower()
                    prefmode = int(stat.S_IFREG | 0x1b6)
                    fchmode = stat.S_IMODE(prefmode)
                    ftypemod = stat.S_IFMT(prefmode)
            fchmode = stat.S_IMODE(prefmode)
            ftypemod = stat.S_IFMT(prefmode)
        else:
            fwinattributes = format(int(zipinfo.external_attr & 0xFFFF), 'x').lower()
            if ((hasattr(member, "is_dir") and member.is_dir()) or member.filename.endswith('/')):
                fmode = format(int(stat.S_IFDIR | 0x1ff), 'x').lower()
                prefmode = int(stat.S_IFDIR | 0x1ff)
                fchmode = stat.S_IMODE(prefmode)
                ftypemod = stat.S_IFMT(prefmode)
            else:
                fmode = format(int(stat.S_IFREG | 0x1b6), 'x').lower()
                prefmode = int(stat.S_IFREG | 0x1b6)
                fchmode = stat.S_IMODE(prefmode)
                ftypemod = stat.S_IFMT(prefmode)
        fcompression = ""
        fcsize = format(int(0), 'x').lower()
        try:
            fuid = format(int(os.getuid()), 'x').lower()
        except (KeyError, AttributeError):
            fuid = format(int(0), 'x').lower()
        try:
            fgid = format(int(os.getgid()), 'x').lower()
        except (KeyError, AttributeError):
            fgid = format(int(0), 'x').lower()
        try:
            import pwd
            try:
                userinfo = pwd.getpwuid(os.getuid())
                funame = userinfo.pw_name
            except (KeyError, AttributeError):
                funame = ""
        except ImportError:
            funame = ""
        fgname = ""
        try:
            import grp
            try:
                groupinfo = grp.getgrgid(os.getgid())
                fgname = groupinfo.gr_name
            except (KeyError, AttributeError):
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
            fcencoding = GetFileEncoding(fcontents, 0, False)[0]
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
                        shutil.copyfileobj(fcontents, cfcontents, length=__filebuff_size__)
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
                shutil.copyfileobj(fcontents, cfcontents, length=__filebuff_size__)
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
        tmpoutlist = [ftypehex, fencoding, fcencoding, fname, flinkname, fsize, fblksize, fblocks, fflags, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression,
                      fcsize, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev, frdev, "+"+str(len(formatspecs['format_delimiter']))]
        AppendFileHeaderWithContent(fp, tmpoutlist, extradata, jsondata, fcontents.read(), [checksumtype[2], checksumtype[3], checksumtype[4]], formatspecs, saltkey)
        try:
            fp.flush()
            if(hasattr(os, "sync")):
                os.fsync(fp.fileno())
        except (io.UnsupportedOperation, AttributeError, OSError):
            pass
        fcontents.close()
    return fp

if(not rarfile_support):
    def AppendFilesWithContentFromRarFile(infile, fp, extradata=[], jsondata={}, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["md5", "md5", "md5", "md5", "md5"], formatspecs=__file_format_dict__, saltkey=None, verbose=False):
        return False
else:       
    def AppendFilesWithContentFromRarFile(infile, fp, extradata=[], jsondata={}, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["md5", "md5", "md5", "md5", "md5"], formatspecs=__file_format_dict__, saltkey=None, verbose=False):
        if(not hasattr(fp, "write")):
            return False
        if(verbose):
            logging.basicConfig(format="%(message)s",
                                stream=PY_STDOUT_TEXT, level=logging.DEBUG)
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
        AppendFileHeader(fp, numfiles, "UTF-8", [], {}, [checksumtype[0], checksumtype[1]], formatspecs)
        try:
            fp.flush()
            if(hasattr(os, "sync")):
                os.fsync(fp.fileno())
        except (io.UnsupportedOperation, AttributeError, OSError):
            pass
        try:
            fp.flush()
            if(hasattr(os, "sync")):
                os.fsync(fp.fileno())
        except (io.UnsupportedOperation, AttributeError, OSError):
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
                fpremode = int(stat.S_IFREG | 0x1b6)
            elif(member.is_symlink()):
                fpremode = int(stat.S_IFLNK | 0x1b6)
            elif(member.is_dir()):
                fpremode = int(stat.S_IFDIR | 0x1ff)
            if(is_windows and member.external_attr != 0):
                fwinattributes = format(int(member.external_attr), 'x').lower()
            else:
                fwinattributes = format(int(0), 'x').lower()
            fcompression = ""
            fcsize = format(int(0), 'x').lower()
            flinkcount = 0
            fblksize = 0
            if(hasattr(fstatinfo, "st_blksize")):
                fblksize = format(int(fstatinfo.st_blksize), 'x').lower()
            fblocks = 0
            if(hasattr(fstatinfo, "st_blocks")):
                fblocks = format(int(fstatinfo.st_blocks), 'x').lower()
            fflags = 0
            if(hasattr(fstatinfo, "st_flags")):
                fflags = format(int(fstatinfo.st_flags), 'x').lower()
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
            frdev = format(int(0), 'x').lower()
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
                fmode = format(int(stat.S_IFREG | 0x1b6), 'x').lower()
                fchmode = format(
                    int(stat.S_IMODE(int(stat.S_IFREG | 0x1b6))), 'x').lower()
                ftypemod = format(
                    int(stat.S_IFMT(int(stat.S_IFREG | 0x1b6))), 'x').lower()
            elif(member.is_symlink()):
                fmode = format(int(stat.S_IFLNK | 0x1b6), 'x').lower()
                fchmode = format(
                    int(stat.S_IMODE(int(stat.S_IFREG | 0x1b6))), 'x').lower()
                ftypemod = format(
                    int(stat.S_IFMT(int(stat.S_IFREG | 0x1b6))), 'x').lower()
            elif(member.is_dir()):
                fmode = format(int(stat.S_IFDIR | 0x1ff), 'x').lower()
                fchmode = format(
                    int(stat.S_IMODE(int(stat.S_IFDIR | 0x1ff))), 'x').lower()
                ftypemod = format(
                    int(stat.S_IFMT(int(stat.S_IFDIR | 0x1ff))), 'x').lower()
            try:
                fuid = format(int(os.getuid()), 'x').lower()
            except (KeyError, AttributeError):
                fuid = format(int(0), 'x').lower()
            try:
                fgid = format(int(os.getgid()), 'x').lower()
            except (KeyError, AttributeError):
                fgid = format(int(0), 'x').lower()
            try:
                import pwd
                try:
                    userinfo = pwd.getpwuid(os.getuid())
                    funame = userinfo.pw_name
                except (KeyError, AttributeError):
                    funame = ""
            except ImportError:
                funame = ""
            fgname = ""
            try:
                import grp
                try:
                    groupinfo = grp.getgrgid(os.getgid())
                    fgname = groupinfo.gr_name
                except (KeyError, AttributeError):
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
                fcencoding = GetFileEncoding(fcontents, 0, False)[0]
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
                            shutil.copyfileobj(fcontents, cfcontents, length=__filebuff_size__)
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
                    shutil.copyfileobj(fcontents, cfcontents, length=__filebuff_size__)
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
            tmpoutlist = [ftypehex, fencoding, fcencoding, fname, flinkname, fsize, fblksize, fblocks, fflags, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression,
                          fcsize, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev, frdev, "+"+str(len(formatspecs['format_delimiter']))]
            AppendFileHeaderWithContent(fp, tmpoutlist, extradata, jsondata, fcontents.read(), [checksumtype[2], checksumtype[3], checksumtype[4]], formatspecs, saltkey)
            try:
                fp.flush()
                if(hasattr(os, "sync")):
                    os.fsync(fp.fileno())
            except (io.UnsupportedOperation, AttributeError, OSError):
                pass
            fcontents.close()
        return fp

if(not py7zr_support):
    def AppendFilesWithContentFromSevenZipFile(infile, fp, extradata=[], jsondata={}, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["md5", "md5", "md5", "md5", "md5"], formatspecs=__file_format_dict__, saltkey=None, verbose=False):
        return False
else:
    def AppendFilesWithContentFromSevenZipFile(infile, fp, extradata=[], jsondata={}, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["md5", "md5", "md5", "md5", "md5"], formatspecs=__file_format_dict__, saltkey=None, verbose=False):
        if(not hasattr(fp, "write")):
            return False
        if(verbose):
            logging.basicConfig(format="%(message)s",
                                stream=PY_STDOUT_TEXT, level=logging.DEBUG)
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
        AppendFileHeader(fp, numfiles, "UTF-8", [], {}, [checksumtype[0], checksumtype[1]], formatspecs)
        try:
            fp.flush()
            if(hasattr(os, "sync")):
                os.fsync(fp.fileno())
        except (io.UnsupportedOperation, AttributeError, OSError):
            pass
        for member in sorted(szpfp.list(), key=lambda x: x.filename):
            fencoding = "UTF-8"
            if(re.findall("^[.|/]", member.filename)):
                fname = member.filename
            else:
                fname = "./"+member.filename
            if(verbose):
                VerbosePrintOut(fname)
            if(not member.is_directory):
                fpremode = int(stat.S_IFREG | 0x1b6)
            elif(member.is_directory):
                fpremode = int(stat.S_IFDIR | 0x1ff)
            fwinattributes = format(int(0), 'x').lower()
            fcompression = ""
            fcsize = format(int(0), 'x').lower()
            flinkcount = 0
            fblksize = 0
            if(hasattr(fstatinfo, "st_blksize")):
                fblksize = format(int(fstatinfo.st_blksize), 'x').lower()
            fblocks = 0
            if(hasattr(fstatinfo, "st_blocks")):
                fblocks = format(int(fstatinfo.st_blocks), 'x').lower()
            fflags = 0
            if(hasattr(fstatinfo, "st_flags")):
                fflags = format(int(fstatinfo.st_flags), 'x').lower()
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
            frdev = format(int(0), 'x').lower()
            if(ftype == 5):
                fsize = format(int("0"), 'x').lower()
            fatime = format(int(member.creationtime.timestamp()), 'x').lower()
            fmtime = format(int(member.creationtime.timestamp()), 'x').lower()
            fctime = format(int(member.creationtime.timestamp()), 'x').lower()
            fbtime = format(int(member.creationtime.timestamp()), 'x').lower()
            if(member.is_directory):
                fmode = format(int(stat.S_IFDIR | 0x1ff), 'x').lower()
                fchmode = format(
                    int(stat.S_IMODE(int(stat.S_IFDIR | 0x1ff))), 'x').lower()
                ftypemod = format(
                    int(stat.S_IFMT(int(stat.S_IFDIR | 0x1ff))), 'x').lower()
            else:
                fmode = format(int(stat.S_IFREG | 0x1b6), 'x').lower()
                fchmode = format(
                    int(stat.S_IMODE(int(stat.S_IFREG | 0x1b6))), 'x').lower()
                ftypemod = format(
                    int(stat.S_IFMT(int(stat.S_IFREG | 0x1b6))), 'x').lower()
            try:
                fuid = format(int(os.getuid()), 'x').lower()
            except (KeyError, AttributeError):
                fuid = format(int(0), 'x').lower()
            try:
                fgid = format(int(os.getgid()), 'x').lower()
            except (KeyError, AttributeError):
                fgid = format(int(0), 'x').lower()
            try:
                import pwd
                try:
                    userinfo = pwd.getpwuid(os.getuid())
                    funame = userinfo.pw_name
                except (KeyError, AttributeError):
                    funame = ""
            except ImportError:
                funame = ""
            fgname = ""
            try:
                import grp
                try:
                    groupinfo = grp.getgrgid(os.getgid())
                    fgname = groupinfo.gr_name
                except (KeyError, AttributeError):
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
                fcencoding = GetFileEncoding(fcontents, 0, False)[0]
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
                            shutil.copyfileobj(fcontents, cfcontents, length=__filebuff_size__)
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
                    shutil.copyfileobj(fcontents, cfcontents, length=__filebuff_size__)
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
            tmpoutlist = [ftypehex, fencoding, fcencoding, fname, flinkname, fsize, fblksize, fblocks, fflags, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression,
                          fcsize, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev, frdev, "+"+str(len(formatspecs['format_delimiter']))]
            AppendFileHeaderWithContent(fp, tmpoutlist, extradata, jsondata, fcontents.read(), [checksumtype[2], checksumtype[3], checksumtype[4]], formatspecs, saltkey)
            try:
                fp.flush()
                if(hasattr(os, "sync")):
                    os.fsync(fp.fileno())
            except (io.UnsupportedOperation, AttributeError, OSError):
                pass
            fcontents.close()
        return fp

def AppendListsWithContent(inlist, fp, dirlistfromtxt=False, extradata=[], jsondata={}, compression="auto", compresswholefile=True, compressionlevel=None, followlink=False, checksumtype=["md5", "md5", "md5", "md5", "md5"], formatspecs=__file_format_dict__, saltkey=None, verbose=False):
    if(not hasattr(fp, "write")):
        return False
    if(verbose):
        logging.basicConfig(format="%(message)s", stream=PY_STDOUT_TEXT, level=logging.DEBUG)
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
    AppendFileHeader(fp, numfiles, "UTF-8", [], [checksumtype[0], checksumtype[1]], formatspecs)
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
        fblksize = format(curfname[6], 'x').lower()
        fblocks = format(curfname[7], 'x').lower()
        fflags = format(curfname[8], 'x').lower()
        fatime = format(curfname[9], 'x').lower()
        fmtime = format(curfname[10], 'x').lower()
        fctime = format(curfname[11], 'x').lower()
        fbtime = format(curfname[12], 'x').lower()
        fmode = format(curfname[13], 'x').lower()
        fwinattributes = format(curfname[14], 'x').lower()
        fcompression = curfname[15]
        fcsize = format(curfname[16], 'x').lower()
        fuid = format(curfname[17], 'x').lower()
        funame = curfname[18]
        fgid = format(curfname[19], 'x').lower()
        fgname = curfname[20]
        fid = format(curfname[21], 'x').lower()
        finode = format(curfname[22], 'x').lower()
        flinkcount = format(curfname[23], 'x').lower()
        fdev = format(curfname[24], 'x').lower()
        frdev = format(curfname[25], 'x').lower()
        fseeknextfile = curfname[26]
        extradata = curfname[27]
        fheaderchecksumtype = curfname[28]
        fcontentchecksumtype = curfname[29]
        fcontents = curfname[30]
        fencoding = GetFileEncoding(fcontents, 0, False)[0]
        tmpoutlist = [ftype, fencoding, fcencoding, fname, flinkname, fsize, fblksize, fblocks, fflags, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression, fcsize,
                      fuid, funame, fgid, fgname, fid, finode, flinkcount, fdev, frdev, fseeknextfile]
        fcontents.seek(0, 0)
        AppendFileHeaderWithContent(fp, tmpoutlist, extradata, jsondata, fcontents.read(), [checksumtype[2], checksumtype[3], checksumtype[4]], formatspecs, saltkey)
    return fp


def AppendInFileWithContent(infile, fp, dirlistfromtxt=False, extradata=[], jsondata={}, followlink=False, checksumtype=["md5", "md5", "md5", "md5"], formatspecs=__file_format_dict__, saltkey=None, verbose=False):
    inlist = ReadInFileWithContentToList(infile, "auto", 0, 0, False, False, True, False, formatspecs, saltkey, False)
    return AppendListsWithContent(inlist, fp, dirlistfromtxt, extradata, jsondata, followlink, checksumtype, formatspecs, saltkey, verbose)


def AppendFilesWithContentToOutFile(infiles, outfile, dirlistfromtxt=False, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, extradata=[], jsondata={}, followlink=False, checksumtype=["md5", "md5", "md5", "md5", "md5"], formatspecs=__file_format_multi_dict__, saltkey=None, verbose=False, returnfp=False):
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
        if(os.path.exists(outfile)):
            try:
                os.unlink(outfile)
            except OSError:
                pass
    if(outfile == "-" or outfile is None):
        verbose = False
        fp = MkTempFile()
    elif(isinstance(outfile, FileLikeAdapter)):
        fp = outfile
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
    AppendFilesWithContent(infiles, fp, dirlistfromtxt, extradata, jsondata, compression, compresswholefile, compressionlevel, compressionuselist, followlink, checksumtype, formatspecs, saltkey, verbose)
    if(outfile == "-" or outfile is None or hasattr(outfile, "read") or hasattr(outfile, "write")):
        fp = CompressOpenFileAlt(
            fp, compression, compressionlevel, compressionuselist, formatspecs)
        try:
            fp.flush()
            if(hasattr(os, "sync")):
                os.fsync(fp.fileno())
        except (io.UnsupportedOperation, AttributeError, OSError):
            pass
    if(outfile == "-"):
        fp.seek(0, 0)
        shutil.copyfileobj(fp, PY_STDOUT_BUF, length=__filebuff_size__)
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
        return fp
    else:
        fp.close()
        return True

def AppendFilesWithContentToStackedOutFile(infiles, outfile, dirlistfromtxt=False, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, extradata=[], jsondata={}, followlink=False, checksumtype=["md5", "md5", "md5", "md5", "md5"], formatspecs=__file_format_multi_dict__, saltkey=None, verbose=False, returnfp=False):
    if not isinstance(infiles, list):
        infiles = [infiles]
    returnout = False
    for infileslist in infiles:
        returnout = AppendFilesWithContentToOutFile(infileslist, outfile, dirlistfromtxt, fmttype, compression, compresswholefile, compressionlevel, compressionuselist, extradata, jsondata, followlink, checksumtype, formatspecs, saltkey, verbose, True)
        if(not returnout):
            break
        else:
            outfile = returnout
    if(not returnfp and returnout):
        returnout.close()
        return True
    return returnout

def AppendListsWithContentToOutFile(inlist, outfile, dirlistfromtxt=False, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, extradata=[], jsondata={}, followlink=False, checksumtype=["md5", "md5", "md5", "md5", "md5"], formatspecs=__file_format_dict__, verbose=False, saltkey=None, returnfp=False):
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
    AppendListsWithContent(inlist, fp, dirlistfromtxt, extradata, jsondata, compression, compresswholefile, compressionlevel, followlink, checksumtype, formatspecs, saltkey, verbose)
    if(outfile == "-" or outfile is None or hasattr(outfile, "read") or hasattr(outfile, "write")):
        fp = CompressOpenFileAlt(
            fp, compression, compressionlevel, compressionuselist, formatspecs)
        try:
            fp.flush()
            if(hasattr(os, "sync")):
                os.fsync(fp.fileno())
        except (io.UnsupportedOperation, AttributeError, OSError):
            pass
    if(outfile == "-"):
        fp.seek(0, 0)
        shutil.copyfileobj(fp, PY_STDOUT_BUF, length=__filebuff_size__)
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

def AppendFilesWithContentFromTarFileToOutFile(infiles, outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, extradata=[], jsondata={}, checksumtype=["md5", "md5", "md5", "md5", "md5"], formatspecs=__file_format_multi_dict__, saltkey=None, verbose=False, returnfp=False):
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
    AppendFilesWithContentFromTarFile(infiles, fp, extradata, jsondata, compression, compresswholefile, compressionlevel, compressionuselist, checksumtype, formatspecs, saltkey, verbose)
    if(outfile == "-" or outfile is None or hasattr(outfile, "read") or hasattr(outfile, "write")):
        fp = CompressOpenFileAlt(
            fp, compression, compressionlevel, compressionuselist, formatspecs)
        try:
            fp.flush()
            if(hasattr(os, "sync")):
                os.fsync(fp.fileno())
        except (io.UnsupportedOperation, AttributeError, OSError):
            pass
    if(outfile == "-"):
        fp.seek(0, 0)
        shutil.copyfileobj(fp, PY_STDOUT_BUF, length=__filebuff_size__)
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

def AppendFilesWithContentFromTarFileToStackedOutFile(infiles, outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, extradata=[], jsondata={}, checksumtype=["md5", "md5", "md5", "md5", "md5"], formatspecs=__file_format_multi_dict__, saltkey=None, verbose=False, returnfp=False):
    if not isinstance(infiles, list):
        infiles = [infiles]
    returnout = False
    for infileslist in infiles:
        returnout = AppendFilesWithContentFromTarFileToOutFile(infileslist, outfile, fmttype, compression, compresswholefile, compressionlevel, compressionuselist, extradata, jsondata, checksumtype, formatspecs, saltkey, verbose, True)
        if(not returnout):
            break
        else:
            outfile = returnout
    if(not returnfp and returnout):
        returnout.close()
        return True
    return returnout

def AppendFilesWithContentFromZipFileToOutFile(infiles, outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, extradata=[], jsondata={}, checksumtype=["md5", "md5", "md5", "md5", "md5"], formatspecs=__file_format_multi_dict__, saltkey=None, verbose=False, returnfp=False):
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
    AppendFilesWithContentFromZipFile(infiles, fp, extradata, jsondata, compression, compresswholefile, compressionlevel, compressionuselist, checksumtype, formatspecs, saltkey, verbose)
    if(outfile == "-" or outfile is None or hasattr(outfile, "read") or hasattr(outfile, "write")):
        fp = CompressOpenFileAlt(
            fp, compression, compressionlevel, compressionuselist, formatspecs)
        try:
            fp.flush()
            if(hasattr(os, "sync")):
                os.fsync(fp.fileno())
        except (io.UnsupportedOperation, AttributeError, OSError):
            pass
    if(outfile == "-"):
        fp.seek(0, 0)
        shutil.copyfileobj(fp, PY_STDOUT_BUF, length=__filebuff_size__)
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

def AppendFilesWithContentFromZipFileToStackedOutFile(infiles, outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, extradata=[], jsondata={}, checksumtype=["md5", "md5", "md5", "md5", "md5"], formatspecs=__file_format_multi_dict__, saltkey=None, verbose=False, returnfp=False):
    if not isinstance(infiles, list):
        infiles = [infiles]
    returnout = False
    for infileslist in infiles:
        returnout = AppendFilesWithContentFromZipFileToOutFile(infileslist, outfile, fmttype, compression, compresswholefile, compressionlevel, compressionuselist, extradata, jsondata, checksumtype, formatspecs, saltkey, verbose, True)
        if(not returnout):
            break
        else:
            outfile = returnout
    if(not returnfp and returnout):
        returnout.close()
        return True
    return returnout

if(not rarfile_support):
    def AppendFilesWithContentFromRarFileToOutFile(infiles, outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, extradata=[], jsondata={}, checksumtype=["md5", "md5", "md5", "md5", "md5"], formatspecs=__file_format_multi_dict__, saltkey=None, verbose=False, returnfp=False):
        return False
else:
    def AppendFilesWithContentFromRarFileToOutFile(infiles, outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, extradata=[], jsondata={}, checksumtype=["md5", "md5", "md5", "md5", "md5"], formatspecs=__file_format_multi_dict__, saltkey=None, verbose=False, returnfp=False):
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
        AppendFilesWithContentFromRarFile(infiles, fp, extradata, jsondata, compression, compresswholefile, compressionlevel, compressionuselist, checksumtype, formatspecs, saltkey, verbose)
        if(outfile == "-" or outfile is None or hasattr(outfile, "read") or hasattr(outfile, "write")):
            fp = CompressOpenFileAlt(
                fp, compression, compressionlevel, compressionuselist, formatspecs)
            try:
                fp.flush()
                if(hasattr(os, "sync")):
                    os.fsync(fp.fileno())
            except (io.UnsupportedOperation, AttributeError, OSError):
                pass
        if(outfile == "-"):
            fp.seek(0, 0)
            shutil.copyfileobj(fp, PY_STDOUT_BUF, length=__filebuff_size__)
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

def AppendFilesWithContentFromRarFileToStackedOutFile(infiles, outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, extradata=[], jsondata={}, checksumtype=["md5", "md5", "md5", "md5", "md5"], formatspecs=__file_format_multi_dict__, saltkey=None, verbose=False, returnfp=False):
    if not isinstance(infiles, list):
        infiles = [infiles]
    returnout = False
    for infileslist in infiles:
        returnout = AppendFilesWithContentFromRarFileToOutFile(infileslist, outfile, fmttype, compression, compresswholefile, compressionlevel, compressionuselist, extradata, jsondata, checksumtype, formatspecs, saltkey, verbose, True)
        if(not returnout):
            break
        else:
            outfile = returnout
    if(not returnfp and returnout):
        returnout.close()
        return True
    return returnout

if(not py7zr_support):
    def AppendFilesWithContentFromSevenZipFileToOutFile(infiles, outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, extradata=[], jsondata={}, checksumtype=["md5", "md5", "md5", "md5", "md5"], formatspecs=__file_format_multi_dict__, saltkey=None, verbose=False, returnfp=False):
        return False
else:
    def AppendFilesWithContentFromSevenZipFileToOutFile(infiles, outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, extradata=[], jsondata={}, checksumtype=["md5", "md5", "md5", "md5", "md5"], formatspecs=__file_format_multi_dict__, saltkey=None, verbose=False, returnfp=False):
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
        AppendFilesWithContentFromSevenZipFile(infiles, fp, extradata, jsondata, compression, compresswholefile, compressionlevel, compressionuselist, checksumtype, formatspecs, saltkey, verbose)
        if(outfile == "-" or outfile is None or hasattr(outfile, "read") or hasattr(outfile, "write")):
            fp = CompressOpenFileAlt(
                fp, compression, compressionlevel, compressionuselist, formatspecs)
            try:
                fp.flush()
                if(hasattr(os, "sync")):
                    os.fsync(fp.fileno())
            except (io.UnsupportedOperation, AttributeError, OSError):
                pass
        if(outfile == "-"):
            fp.seek(0, 0)
            shutil.copyfileobj(fp, PY_STDOUT_BUF, length=__filebuff_size__)
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

def AppendFilesWithContentFromSevenZipFileToStackedOutFile(infiles, outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, extradata=[], jsondata={}, checksumtype=["md5", "md5", "md5", "md5", "md5"], formatspecs=__file_format_multi_dict__, saltkey=None, verbose=False, returnfp=False):
    if not isinstance(infiles, list):
        infiles = [infiles]
    returnout = False
    for infileslist in infiles:
        returnout = AppendFilesWithContentFromSevenZipFileToOutFile(infileslist, outfile, fmttype, compression, compresswholefile, compressionlevel, compressionuselist, extradata, jsondata, checksumtype, formatspecs, saltkey, verbose, True)
        if(not returnout):
            break
        else:
            outfile = returnout
    if(not returnfp and returnout):
        returnout.close()
        return True
    return returnout

def AppendInFileWithContentToOutFile(infile, outfile, dirlistfromtxt=False, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, extradata=[], jsondata={}, followlink=False, checksumtype=["md5", "md5", "md5", "md5", "md5"], formatspecs=__file_format_dict__, saltkey=None, verbose=False, returnfp=False):
    inlist = ReadInFileWithContentToList(infile, "auto", 0, 0, False, False, True, False, formatspecs, saltkey, False)
    return AppendListsWithContentToOutFile(inlist, outfile, dirlistfromtxt, fmttype, compression, compresswholefile, compressionlevel, extradata, jsondata, followlink, checksumtype, formatspecs, saltkey, verbose, returnfp)


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
    except (KeyError, AttributeError):
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
        with gzip.GzipFile(filename=None, fileobj=out, mode="wb", compresslevel=compresslevel) as f:
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
        with gzip.GzipFile(filename=None, fileobj=inp, mode="rb") as f:
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
    """
    Detect file/text encoding from BOM (and a few special signatures).
    Returns (encoding_name, bom_len). If no BOM is found, returns ("UTF-8", 0).

    Compatible with Python 2 and 3.
    - infile: path string OR file-like object (binary mode)
    - filestart: byte offset where detection should begin
    - closefp: if True, close the file only if we opened it here
    """
    # --- Precomputed signatures (bytes) ---
    H = binascii.unhexlify  # convenience

    # 4-byte BOMs
    BOM_UTF32_LE = H("FFFE0000")
    BOM_UTF32_BE = H("0000FEFF")
    BOM_UTF_EBCDIC = H("DD736673")

    # 3-byte BOMs
    BOM_UTF8 = H("EFBBBF")
    BOM_SCSU = H("0EFEFF")  # SCSU BOM (0E FE FF)

    # 2-byte BOMs
    BOM_UTF16_LE = H("FFFE")
    BOM_UTF16_BE = H("FEFF")

    # UTF-7 variants (first 4 bytes: 2B 2F 76 <38|39|2B|2F>)
    UTF7_PREFIX = H("2B2F76")
    UTF7_VARIANTS = (H("38"), H("39"), H("2B"), H("2F"))

    opened_here = False
    fp = None

    # --- Obtain a binary file object ---
    if hasattr(infile, "read") or hasattr(infile, "write"):
        fp = infile
    else:
        try:
            fp = open(infile, "rb")  # Python 2 & 3
            opened_here = True
        except (IOError, OSError):
            return ("UTF-8", 0)  # fallback; file not found or unreadable

    try:
        # Seek to starting point
        try:
            fp.seek(filestart, 0)
        except (IOError, OSError):
            # If seek fails, treat as start
            pass

        # Read up to 4 bytes once
        pre4 = fp.read(4) or b""
        # Create pre2, pre3 without re-reading
        pre3 = pre4[:3]
        pre2 = pre4[:2]

        # --- Check 4-byte BOMs ---
        if pre4.startswith(BOM_UTF32_LE):
            _advance(fp, filestart, 4)
            return ("UTF-32LE", 4)
        if pre4.startswith(BOM_UTF32_BE):
            _advance(fp, filestart, 4)
            return ("UTF-32BE", 4)
        if pre4.startswith(BOM_UTF_EBCDIC):
            _advance(fp, filestart, 4)
            return ("UTF-EBCDIC", 4)

        # --- Check 3-byte BOMs ---
        if pre3 == BOM_UTF8:
            _advance(fp, filestart, 3)
            return ("UTF-8", 3)
        if pre3 == BOM_SCSU:
            _advance(fp, filestart, 3)
            return ("SCSU", 3)

        # --- Check 2-byte BOMs ---
        if pre2 == BOM_UTF16_LE:
            _advance(fp, filestart, 2)
            return ("UTF-16LE", 2)
        if pre2 == BOM_UTF16_BE:
            _advance(fp, filestart, 2)
            return ("UTF-16BE", 2)

        # --- Check UTF-7 (no official BOM, but common signature prefix) ---
        # 2B 2F 76 <38|39|2B|2F>
        if len(pre4) >= 4 and pre4[:3] == UTF7_PREFIX and pre4[3:4] in UTF7_VARIANTS:
            # No BOM length to skip; this is a signature, not a BOM
            _advance(fp, filestart, 0)
            return ("UTF-7", 0)

        # Default/fallback: assume UTF-8 with no BOM
        _advance(fp, filestart, 0)
        return ("UTF-8", 0)

    finally:
        if closefp and opened_here and fp is not None:
            try:
                fp.close()
            except Exception:
                pass


def _advance(fp, base, n):
    """
    Move file position to right after the BOM/signature.
    If fp is not seekable, this silently does nothing.
    """
    try:
        fp.seek(base + n, 0)
    except Exception:
        # Not seekable or error; ignore
        pass


def GetFileEncodingFromString(instring, filestart=0, closefp=True):
    try:
        instringsfile = MkTempFile(instring)
    except TypeError:
        instringsfile = MkTempFile(instring.encode("UTF-8"))
    return GetFileEncoding(instringsfile, filestart, closefp)

def GetBinaryFileType(infile, filestart=0, closefp=True):
    """
    Detect common *non-compression* binary file types by magic bytes / structure.
    Returns (type_string, sig_len) or False if not recognized.
    - infile: path (str), file-like object (opened rb), or raw bytes/bytearray
    - filestart: offset to start inspecting
    - closefp: close only if we opened the file here
    """
    H = binascii.unhexlify
    opened_here = False

    # --- Normalize to bytes buffer 'data' ---
    if isinstance(infile, (bytes, bytearray)):
        data = infile[filestart:filestart+560]
        fp = None
    else:
        fp = infile if (hasattr(infile, "read") or hasattr(infile, "write")) else None
        if fp is None:
            try:
                fp = open(infile, "rb")
                opened_here = True
            except (IOError, OSError):
                return False
        try:
            try:
                fp.seek(filestart, 0)
            except Exception:
                pass
            data = fp.read(560) or b""
        finally:
            if closefp and opened_here and fp is not None:
                try:
                    fp.close()
                except Exception:
                    pass

    pre16 = data[:16]
    pre12 = data[:12]
    pre8  = data[:8]
    pre7  = data[:7]
    pre6  = data[:6]
    pre5  = data[:5]
    pre4  = data[:4]
    pre3  = data[:3]
    pre2  = data[:2]
    pre1  = data[:1]

    # -------------- EXECUTABLES --------------
    # ELF
    if pre4 == H("7F454C46"):
        return ("ELF", 4)

    # Mach-O (32/64; BE/LE)
    if pre4 in (H("FEEDFACE"), H("FEEDFACF"), H("CEFAEDFE"), H("CFFAEDFE")):
        return ("Mach-O", 4)

    # PE/COFF (Windows EXE/DLL): 'MZ' + 'PE\0\0' at lfanew
    if pre2 == H("4D5A"):
        if len(data) >= 0x40:
            peofs = struct.unpack("<I", data[0x3C:0x40])[0]
            if 0 <= peofs <= len(data) - 4 and data[peofs:peofs+4] == b"PE\0\0":
                return ("PE", 2)
        return ("MZ", 2)  # generic MZ (could be DOS stub)

    # -------------- DOCUMENTS / DB --------------
    # PDF
    if pre5 == b"%PDF-":
        return ("PDF", 5)

    # SQLite 3
    if pre16 == b"SQLite format 3\0":
        return ("SQLite3", 16)

    # -------------- MEDIA CONTAINERS --------------
    # RIFF (WAV/AVI/WEBP)
    if pre4 == b"RIFF" and len(data) >= 12:
        fourcc = data[8:12]
        if fourcc == b"WAVE":
            return ("WAV", 4)
        if fourcc == b"AVI ":
            return ("AVI", 4)
        if fourcc == b"WEBP":
            return ("WEBP", 4)
        return ("RIFF", 4)

    # MP3 with ID3
    if pre3 == H("494433"):
        return ("MP3/ID3", 3)

    # OGG
    if pre4 == H("4F676753"):
        return ("OGG", 4)

    # FLAC
    if pre4 == H("664C6143"):
        return ("FLAC", 4)

    # -------------- IMAGES / ICONS --------------
    # JPEG
    if pre3 == H("FFD8FF"):
        return ("JPEG", 3)

    # PNG
    if pre8 == H("89504E470D0A1A0A"):
        return ("PNG", 8)

    # GIF87a
    if pre6 == H("474946383761"):
        return ("GIF87a", 6)

    # GIF89a
    if pre6 == H("474946383961"):
        return ("GIF89a", 6)

    # BMP
    if pre2 == H("424D"):
        return ("BMP", 2)

    # TIFF (LE / BE)
    if pre4 == H("49492A00"):
        return ("TIFF-LE", 4)
    if pre4 == H("4D4D002A"):
        return ("TIFF-BE", 4)

    # ICO
    if pre4 == H("00000100"):
        return ("ICO", 4)

    # ICNS
    if pre4 == H("69636E73"):
        return ("ICNS", 4)

    # PSD
    if pre4 == H("38425053"):
        return ("PSD", 4)

    # DDS
    if pre4 == H("44445320"):
        return ("DDS", 4)

    # SVG (text-based)
    if data.lstrip().startswith(b"<svg"):
        return ("SVG", 0)

    # HEIF/AVIF (ISO BMFF) via ftyp brand
    if len(data) >= 12 and data[4:8] == b"ftyp":
        brand = data[8:12]
        if brand in (b"heic", b"heix", b"hevc", b"hevx", b"mif1", b"msf1"):
            return ("HEIF", 0)
        if brand in (b"avif", b"avis"):
            return ("AVIF", 0)

    # -------------- FONTS --------------
    # TTF (sfnt 00010000)
    if pre4 == H("00010000"):
        return ("TTF", 4)

    # OTF (OTTO)
    if pre4 == H("4F54544F"):
        return ("OTF", 4)

    # TTC (ttcf)
    if pre4 == H("74746366"):
        return ("TTC", 4)

    # WOFF / WOFF2
    if pre4 == H("774F4646"):
        return ("WOFF", 4)
    if pre4 == H("774F4632"):
        return ("WOFF2", 4)

    # CFF / CFF2
    if pre4 == H("01000404"):
        return ("CFF", 4)
    if pre4 == H("01000405"):
        return ("CFF2", 4)

    # EOT
    if pre4 == H("4C500000"):
        return ("EOT", 4)

    # PFB (Type 1 binary)
    if pre2 in (H("8001"), H("8002")):
        return ("PFB", 2)

    # PFA / BDF (text-based)
    if data.lstrip().startswith(b"%!PS-AdobeFont"):
        return ("PFA", 0)
    if data.lstrip().startswith(b"STARTFONT"):
        return ("BDF", 0)

    # PCF
    if pre4 in (H("01666370"), H("70636601")):
        return ("PCF", 4)

    # -------------- FALLBACK --------------
    return False

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


def UncompressFileAlt(fp, formatspecs=__file_format_multi_dict__, filestart=0,
                      use_mmap=False, reuse_adapter=True):
    """
    Detect compression at 'filestart' on fp and return a seekable, bytes-only stream.
    - If fp is a FileLikeAdapter and reuse_adapter=True, reuse it by swapping its _fp.
    - If passthrough (uncompressed), optionally mmap the raw file.
    """
    if not hasattr(fp, "read"):
        return False

    # Always operate on the raw source for probe/wrap
    if hasattr(fp, "_fp"):
        src = getattr(fp, "_fp", fp)
    else:
        src = fp

    # Probe at filestart using RAW handle
    try:
        src.seek(filestart, 0)
    except Exception:
        pass

    kind = CheckCompressionType(src, formatspecs, filestart, False)
    # Optional canonicalization so names match your compressionsupport entries
    if kind == "bz2":
        kind = "bzip2"

    if IsNestedDict(formatspecs) and kind in formatspecs:
        formatspecs = formatspecs[kind]

    # Guard against detector side-effects: ensure we're back at filestart
    try:
        src.seek(filestart, 0)
    except Exception:
        pass

    # Build logical stream (or passthrough)
    if   kind == "gzip"   and "gzip"   in compressionsupport:
        wrapped = gzip.GzipFile(fileobj=src, mode="rb")
    elif kind == "bzip2"  and ("bzip2" in compressionsupport or "bz2" in compressionsupport):
        wrapped = bz2.BZ2File(src)
    elif kind in ("lzma","xz") and (("lzma" in compressionsupport) or ("xz" in compressionsupport)):
        wrapped = lzma.LZMAFile(src)
    elif kind == "zstd"   and ("zstd" in compressionsupport or "zstandard" in compressionsupport):
        if 'zstandard' in sys.modules:
            wrapped = ZstdFile(fileobj=src, mode="rb")
        elif 'pyzstd' in sys.modules:
            wrapped = pyzstd.zstdfile.ZstdFile(fileobj=src, mode="rb")
        else:
            return False
    elif kind == "lz4"    and "lz4"    in compressionsupport:
        wrapped = lz4.frame.LZ4FrameFile(src, mode="rb")
    elif kind == "zlib"   and "zlib"   in compressionsupport:
        wrapped = ZlibFile(fileobj=src, mode="rb")
    else:
        # Passthrough
        wrapped = src
        try:
            wrapped.seek(filestart, 0)
        except Exception:
            pass
        kind = ""  # treat as uncompressed for logic below

    # Positioning: start-of-member for compressed; filestart for passthrough
    try:
        if kind in compressionsupport:
            wrapped.seek(0, 0)
        else:
            wrapped.seek(filestart, 0)
    except Exception:
        pass

    # Reuse existing adapter by swapping its underlying handle
    if isinstance(fp, FileLikeAdapter) and reuse_adapter:
        fp._mm = None
        fp._fp = wrapped
        fp._mode = "rb"
        fp._pos = 0
        return fp

    # New adapter; mmap only for passthrough/raw file
    mm = None
    if use_mmap and wrapped is src and kind == "":
        base = _extract_base_fp(src)
        try:
            if base is not None:
                mm = mmap.mmap(base.fileno(), 0, access=mmap.ACCESS_READ)
        except Exception:
            mm = None

    return FileLikeAdapter(wrapped, mode="rb", mm=mm)

def UncompressFile(infile, formatspecs=__file_format_multi_dict__, mode="rb",
                   filestart=0, use_mmap=False):

    """
    Opens a path, detects compression by header, and returns a FileLikeAdapter.
    If uncompressed and use_mmap=True, returns an mmap-backed reader.
    """
    compresscheck = CheckCompressionType(infile, formatspecs, filestart, False)
    if IsNestedDict(formatspecs) and compresscheck in formatspecs:
        formatspecs = formatspecs[compresscheck]

    # Python 2 text-mode fixups if needed (though you're bytes-only)
    if sys.version_info[0] == 2 and compresscheck:
        if mode == "rt": mode = "r"
        elif mode == "wt": mode = "w"

    try:
        # Compressed branches
        if (compresscheck == "gzip" and "gzip" in compressionsupport):
            fp = GzipFile(infile, mode=mode) if sys.version_info[0] == 2 else gzip.open(infile, mode)
        elif (compresscheck == "bzip2" and "bzip2" in compressionsupport):
            fp = bz2.open(infile, mode)
        elif (compresscheck == "zstd" and "zstandard" in compressionsupport):
            if 'zstandard' in sys.modules:
                fp = ZstdFile(infile, mode=mode)
            elif 'pyzstd' in sys.modules:
                fp = pyzstd.zstdfile.ZstdFile(infile, mode=mode)
            else:
                return False
        elif (compresscheck == "lz4" and "lz4" in compressionsupport):
            fp = lz4.frame.open(infile, mode)
        elif ((compresscheck == "lzma" or compresscheck == "xz") and "xz" in compressionsupport):
            fp = lzma.open(infile, mode)
        elif (compresscheck == "zlib" and "zlib" in compressionsupport):
            fp = ZlibFile(infile, mode=mode)

        # Uncompressed (or unknown): open plain file
        else:
            fp = open(infile, mode)

    except FileNotFoundError:
        return False

    # For uncompressed: optional mmap
    mm = None
    if use_mmap and (compresscheck is None or compresscheck == formatspecs.get('format_magic', None)):
        try:
            base = _extract_base_fp(fp)
            if base is not None:
                mm = mmap.mmap(base.fileno(), 0, access=mmap.ACCESS_READ if "r" in mode else mmap.ACCESS_WRITE)
        except Exception:
            mm = None  # fallback to normal file stream

    # Position to filestart if caller requested it (mainly for fileobj-based headers)
    try:
        fp.seek(0 if compresscheck else filestart, 0)
    except Exception:
        pass

    out = FileLikeAdapter(fp, mode="rb" if "r" in mode else "wb", mm=mm)
    try:
        out.write_through = True
    except Exception:
        pass
    return out


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
    filefp = MkTempFile("", isbytes=False)
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
    filefp = MkTempFile("", isbytes=False)
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


# ========= core utilities =========

def _extract_base_fp(obj):
    """Return deepest file-like with working fileno(), or None."""
    seen = set()
    cur = obj
    while cur and id(cur) not in seen:
        seen.add(id(cur))
        f = getattr(cur, "fileno", None)
        if callable(f):
            try:
                f()  # probe fileno()
                return cur
            except (Exception, UnsupportedOperation):
                pass
        for attr in ("fileobj", "fp", "_fp", "buffer", "raw"):
            nxt = getattr(cur, attr, None)
            if nxt is not None and id(nxt) not in seen:
                cur = nxt
                break
        else:
            cur = None
    return None


class FileLikeAdapter(object):
    """
    Bytes-only, Py2/3-compatible file-like wrapper.
    Can wrap: BytesIO, real files, compressed streams, or (file, mmap) pair.

    Notes:
      - Only bytes I/O is supported (text must be encoded/decoded by caller).
      - flush() can optionally fsync the base fd (fsync_on_flush=True).
    """
    def __init__(self, fp_like, mode="rb", mm=None, name=None, fsync_on_flush=False):
        self._fp = fp_like
        self._mm = mm
        self._pos = 0
        self._mode = mode
        self.name = name if name is not None else getattr(fp_like, "name", None)
        self._closed = False
        self._readable = ("r" in mode) or ("+" in mode)
        self._writable = ("w" in mode) or ("a" in mode) or ("x" in mode) or ("+" in mode)
        self.write_through = False  # accept & ignore (compat knob)
        self._fsync_on_flush = bool(fsync_on_flush)

    # ---- capabilities ----
    def readable(self):
        return bool(self._readable)

    def writable(self):
        return bool(self._writable)

    def seekable(self):
        if self._mm is not None:
            return True
        s = getattr(self._fp, "seekable", None)
        if callable(s):
            try:
                return bool(s())
            except Exception:
                return hasattr(self._fp, "seek")
        return hasattr(self._fp, "seek")

    @property
    def closed(self):
        base_closed = getattr(self._fp, "closed", None)
        return bool(base_closed) or self._closed

    # ---- position ----
    def tell(self):
        if self._mm is not None:
            return self._pos
        return self._fp.tell()

    def seek(self, offset, whence=io.SEEK_SET):
        if self._mm is None:
            return self._fp.seek(offset, whence)
        if whence == io.SEEK_SET:
            new = offset
        elif whence == io.SEEK_CUR:
            new = self._pos + offset
        elif whence == io.SEEK_END:
            new = len(self._mm) + offset
        else:
            raise ValueError("bad whence")
        if not (0 <= new <= len(self._mm)):
            raise ValueError("seek out of range")
        self._pos = new
        return self._pos

    # ---- reads ----
    def read(self, n=-1):
        if not self._readable:
            raise UnsupportedOperation("not readable")
        if self._mm is None:
            return self._fp.read(n)
        if n is None or n < 0:
            n = len(self._mm) - self._pos
        end = min(self._pos + n, len(self._mm))
        if end <= self._pos:
            return b"" if not PY2 else bytes_type()
        out = bytes(self._mm[self._pos:end])
        self._pos = end
        return out

    def readinto(self, b):
        if not self._readable:
            raise UnsupportedOperation("not readable")
        mv = memoryview(b)
        if mv.readonly:
            raise TypeError("readinto() argument must be a writable buffer")
        if self._mm is None:
            ri = getattr(self._fp, "readinto", None)
            if callable(ri):
                return ri(b)
            data = self._fp.read(len(mv))
            if not data:
                return 0
            n = min(len(mv), len(data))
            mv[:n] = data[:n]
            return n
        remaining = len(self._mm) - self._pos
        n = min(len(mv), remaining)
        if n <= 0:
            return 0
        mv[:n] = self._mm[self._pos:self._pos + n]
        self._pos += n
        return n

    def readline(self, limit=-1):
        if not self._readable:
            raise UnsupportedOperation("not readable")
        if self._mm is None:
            return self._fp.readline(limit)
        end_limit = (min(self._pos + limit, len(self._mm))
                     if (limit is not None and limit >= 0) else len(self._mm))
        nl = self._mm.find(b"\n", self._pos, end_limit)
        end = end_limit if nl == -1 else nl + 1
        out = bytes(self._mm[self._pos:end])
        self._pos = end
        return out

    def readlines(self, hint=-1):
        lines, total = [], 0
        while True:
            line = self.readline()
            if not line:
                break
            lines.append(line)
            total += len(line)
            if hint >= 0 and total >= hint:
                break
        return lines

    def __iter__(self):
        return self

    def __next__(self):
        line = self.readline()
        if not line:
            raise StopIteration
        return line

    if PY2:
        next = __next__

    # ---- writes ----
    def write(self, b):
        if not self._writable:
            raise UnsupportedOperation("not writable")

        # Allow bytearray/memoryview; for mmap we can assign memoryview directly.
        if isinstance(b, (bytearray, memoryview)):
            if self._mm is None:
                b = bytes(b)
        if not isinstance(b, bytes_type):
            raise TypeError("write() requires bytes; encode text before writing")

        if self._mm is None:
            return self._fp.write(b)

        mv = memoryview(b)
        end = self._pos + len(mv)
        if end > len(self._mm):
            raise IOError("write past mapped size; pre-size or use truncate() to grow")
        self._mm[self._pos:end] = mv
        self._pos = end
        return len(mv)

    def writelines(self, lines):
        for ln in lines:
            self.write(ln)

    # ---- durability & size ----
    def flush(self):
        if self._mm is not None:
            try:
                self._mm.flush()
            except Exception:
                pass
        try:
            self._fp.flush()
        except Exception:
            pass
        if self._fsync_on_flush:
            base = _extract_base_fp(self._fp)
            if base is not None:
                try:
                    os.fsync(base.fileno())
                except Exception:
                    pass

    def truncate(self, size=None):
        if self._mm is not None:
            base = _extract_base_fp(self._fp)
            if base is None:
                raise UnsupportedOperation("truncate unsupported for mmapped non-file")
            if size is None:
                size = self.tell()
            was_pos = self._pos
            try:
                self._mm.close()
            except Exception:
                pass
            # grow/shrink underlying
            try:
                os.ftruncate(base.fileno(), size)
            except Exception:
                base.truncate(size)
            # remap (size==0 => no mapping)
            if size > 0:
                access = mmap.ACCESS_WRITE if self._writable else mmap.ACCESS_READ
                self._mm = mmap.mmap(base.fileno(), size, access=access)
            else:
                self._mm = None
            self._pos = min(was_pos, size)
            return size

        trunc = getattr(self._fp, "truncate", None)
        if not callable(trunc):
            raise UnsupportedOperation("truncate unsupported by underlying object")
        return trunc(size)

    # ---- fd/tty ----
    def fileno(self):
        f = getattr(self._fp, "fileno", None)
        if callable(f):
            return f()
        raise UnsupportedOperation("no fileno()")

    def isatty(self):
        f = getattr(self._fp, "isatty", None)
        try:
            return bool(f()) if callable(f) else False
        except Exception:
            return False

    # ---- close & ctx mgr ----
    def close(self):
        if self._closed:
            return
        try:
            if self._writable:
                self.flush()
        finally:
            if self._mm is not None:
                try:
                    self._mm.close()
                except Exception:
                    pass
                self._mm = None
            try:
                self._fp.close()
            except Exception:
                pass
            self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    # ---- passthrough & attribute handling ----
    def __setattr__(self, name, value):
        if name == "write_through":
            object.__setattr__(self, name, value)
            return
        object.__setattr__(self, name, value)

    def __getattr__(self, name):
        # lightweight passthrough of underlying harmless attributes
        fp = object.__getattribute__(self, "_fp")
        if fp is not None and hasattr(fp, name):
            return getattr(fp, name)
        raise AttributeError(name)

    def detach(self):
        """Return (fp, mm) without closing them; mark adapter as closed."""
        fp, mm = self._fp, self._mm
        self._fp = None
        self._mm = None
        self._closed = True
        return fp, mm

    # compatibility aliases for unwrapping utilities
    @property
    def fileobj(self):
        return self.file

    @property
    def myfileobj(self):
        return self.file



# ========= mmap helpers & openers =========

def _maybe_make_mmap(fp_like, mode, use_mmap=False, mmap_size=None):
    """
    If use_mmap is True and fp_like ultimately has a real fileno(),
    return (fp_like, mm) where mm is an mmap.mmap for:
      - READ: whole file (if size > 0)
      - WRITE: pre-sized mapping of length mmap_size
    Otherwise return (fp_like, None).
    """
    if not use_mmap:
        return fp_like, None

    base = _extract_base_fp(fp_like)
    if base is None:
        return fp_like, None  # BytesIO / compressed stream etc.

    # READ mapping: map entire file (non-empty only)
    if ("r" in mode) and not any(ch in mode for ch in "wax+"):
        try:
            st = os.fstat(base.fileno())
            if st.st_size == 0:
                return fp_like, None
            mm = mmap.mmap(base.fileno(), 0, access=mmap.ACCESS_READ)
            return fp_like, mm
        except Exception:
            return fp_like, None

    # WRITE mapping: must pre-size
    if any(ch in mode for ch in "wax+"):
        if not mmap_size or mmap_size <= 0:
            # caller must provide a mapping length for writes
            return fp_like, None
        try:
            fd = base.fileno()
            try:
                os.ftruncate(fd, mmap_size)
            except Exception:
                base.truncate(mmap_size)
            mm = mmap.mmap(fd, mmap_size, access=mmap.ACCESS_WRITE)
            return fp_like, mm
        except Exception:
            return fp_like, None

    return fp_like, None


def open_adapter(obj_or_path, mode="rb", use_mmap=False, mmap_size=None, **adapter_kw):
    """
    Universal opener:
      - If given a path (str/bytes/PathLike), open it with built-in open().
      - If given a file-like, use it as-is.
    Returns a FileLikeAdapter, optionally mmap-backed (only when possible).

    adapter_kw are passed to FileLikeAdapter (e.g., fsync_on_flush=True).
    """
    PathLike = getattr(os, "PathLike", ())
    is_path = isinstance(obj_or_path, (str, bytes) + ((PathLike,) if PathLike else ()))

    if is_path:
        fp = open(obj_or_path, mode)
        fp, mm = _maybe_make_mmap(fp, mode, use_mmap=use_mmap, mmap_size=mmap_size)
        return FileLikeAdapter(fp, mode=mode, mm=mm, **adapter_kw)

    # file-like object
    fp_like = obj_or_path
    fp_like, mm = _maybe_make_mmap(fp_like, mode, use_mmap=use_mmap, mmap_size=mmap_size)
    return FileLikeAdapter(fp_like, mode=mode, mm=mm, **adapter_kw)


def ensure_filelike(infile, mode="rb", use_mmap=False, **adapter_kw):
    """
    Accepts either a path/PathLike or an existing file-like object.
    Returns a FileLikeAdapter (optionally mmap-backed), or None if opening fails.
    """
    if hasattr(infile, "read") or hasattr(infile, "write"):
        fp = infile
    else:
        try:
            fp = open(infile, mode)
        except IOError:  # covers FileNotFoundError on Py2
            return None

    return open_adapter(fp, mode=mode, use_mmap=use_mmap, **adapter_kw)


# ========= copy helpers =========

def fast_copy(infp, outfp, bufsize=__filebuff_size__):
    """
    Efficient copy from any readable file-like to any writable file-like.
    Uses readinto() when available to avoid extra allocations.
    """
    buf = bytearray(bufsize)
    mv = memoryview(buf)
    while True:
        rin = getattr(infp, "readinto", None)
        if callable(rin):
            n = infp.readinto(mv)
            if not n:
                break
            outfp.write(mv[:n])
        else:
            data = infp.read(bufsize)
            if not data:
                break
            outfp.write(data)


def copy_file_to_mmap_dest(src_path, outfp, chunk_size=__spoolfile_size__):
    """
    Copy a disk file into an mmap-backed destination (FileLikeAdapter).
    Falls back to buffered copy if the source cannot be mmapped.
    """
    with open(src_path, "rb") as fp:
        try:
            st = os.fstat(fp.fileno())
            if st.st_size == 0:
                return
            mm_src = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)
            try:
                pos, size = 0, len(mm_src)
                while pos < size:
                    end = min(pos + chunk_size, size)
                    outfp.write(mm_src[pos:end])
                    pos = end
            finally:
                mm_src.close()
        except (ValueError, mmap.error, OSError):
            shutil.copyfileobj(fp, outfp, length=chunk_size)


def copy_opaque(src, dst, bufsize=__filebuff_size__, grow_step=64 << 20):
    """
    Copy opaque bytes from 'src' (any readable file-like) to 'dst'
    (your mmap-backed FileLikeAdapter or any writable file-like).

    - Uses readinto() when available (zero extra allocations).
    - If dst is mmapped and size is exceeded, auto-grow via truncate().
    Returns total bytes copied.
    """
    total = 0
    buf = bytearray(bufsize)
    mv = memoryview(buf)

    while True:
        readinto = getattr(src, "readinto", None)
        if callable(readinto):
            n = src.readinto(mv)
            if not n:
                break
            try:
                dst.write(mv[:n])
            except IOError:
                # likely "write past mapped size"; try to grow
                try:
                    new_size = max(dst.tell() + n, dst.tell() + grow_step)
                    dst.truncate(new_size)
                    dst.write(mv[:n])
                except Exception:
                    raise
            total += n
        else:
            chunk = src.read(bufsize)
            if not chunk:
                break
            try:
                dst.write(chunk)
            except IOError:
                try:
                    new_size = max(dst.tell() + len(chunk), dst.tell() + grow_step)
                    dst.truncate(new_size)
                    dst.write(chunk)
                except Exception:
                    raise
            total += len(chunk)

    dst.flush()
    return total


def CompressOpenFileAlt(fp, compression="auto", compressionlevel=None,
                        compressionuselist=compressionlistalt,
                        formatspecs=__file_format_dict__):
    """
    Takes an already-open *bytes* file-like (e.g., BytesIO or file),
    maybe compresses its contents into a temp file-like, and returns a file-like.
    Always returns a FileLikeAdapter positioned at start.
    """
    if not hasattr(fp, "read"):
        return False

    try:
        fp.seek(0, 0)
    except (io.UnsupportedOperation, AttributeError, OSError):
        pass

    if (not compression or compression == formatspecs['format_magic']
        or (compression not in compressionuselist and compression is None)):
        compression = "auto"

    # helper to coerce level
    def _lvl(x):
        return 9 if x is None else int(x)

    # default: pass-through
    bytesfp = fp

    try:
        if compression == "gzip" and "gzip" in compressionsupport:
            bytesfp = MkTempFile()
            bytesfp.write(GzipCompressData(fp.read(), compresslevel=_lvl(compressionlevel)))
        elif compression == "bzip2" and "bzip2" in compressionsupport:
            bytesfp = MkTempFile()
            bytesfp.write(BzipCompressData(fp.read(), compresslevel=_lvl(compressionlevel)))
        elif compression == "lz4" and "lz4" in compressionsupport:
            bytesfp = MkTempFile()
            bytesfp.write(lz4.frame.compress(fp.read(), compression_level=_lvl(compressionlevel)))
        elif (compression in ("lzo", "lzop")) and "lzop" in compressionsupport:
            bytesfp = MkTempFile()
            bytesfp.write(lzo.compress(fp.read(), _lvl(compressionlevel)))
        elif compression == "zstd" and "zstandard" in compressionsupport:
            bytesfp = MkTempFile()
            level = _lvl(compressionlevel)
            compressor = zstandard.ZstdCompressor(level, threads=get_default_threads())
            bytesfp.write(compressor.compress(fp.read()))
        elif compression == "lzma" and "lzma" in compressionsupport:
            bytesfp = MkTempFile()
            level = _lvl(compressionlevel)
            try:
                bytesfp.write(lzma.compress(fp.read(), format=lzma.FORMAT_ALONE,
                                            filters=[{"id": lzma.FILTER_LZMA1, "preset": level}]))
            except (NotImplementedError, lzma.LZMAError):
                bytesfp.write(lzma.compress(fp.read(), format=lzma.FORMAT_ALONE))
        elif compression == "xz" and "xz" in compressionsupport:
            bytesfp = MkTempFile()
            level = _lvl(compressionlevel)
            try:
                bytesfp.write(lzma.compress(fp.read(), format=lzma.FORMAT_XZ,
                                            filters=[{"id": lzma.FILTER_LZMA2, "preset": level}]))
            except (NotImplementedError, lzma.LZMAError):
                bytesfp.write(lzma.compress(fp.read(), format=lzma.FORMAT_XZ))
        elif compression == "zlib" and "zlib" in compressionsupport:
            bytesfp = MkTempFile()
            bytesfp.write(zlib.compress(fp.read(), _lvl(compressionlevel)))
        else:
            # "auto" or unsupported -> pass-through
            bytesfp = fp
    except FileNotFoundError:
        return False

    try:
        bytesfp.seek(0, 0)
    except (io.UnsupportedOperation, AttributeError, OSError):
        pass
    out = FileLikeAdapter(bytesfp, mode="rb")  # read interface for the caller
    try:
        out.write_through = True
    except Exception:
        pass
    return out


def CompressOpenFile(outfile, compressionenable=True, compressionlevel=None,
                     use_mmap=False, mmap_size=None):
    """
    Opens a path for writing (compressed based on extension), returning a FileLikeAdapter.
    If uncompressed and use_mmap=True, pre-sizes the file and expose mmap-backed writer.
    """
    if outfile is None:
        return False

    # If caller already gave us a FileLikeAdapter => honor it and return it.
    if isinstance(outfile, FileLikeAdapter):
        try:
            outfile.write_through = True
        except Exception:
            pass
        return outfile

    fbasename, fextname = os.path.splitext(outfile)
    compressionlevel = 9 if compressionlevel is None else int(compressionlevel)
    mode = "w" if PY2 else "wb"

    try:
        # Uncompressed branch
        if (fextname not in outextlistwd) or (not compressionenable):
            if use_mmap:
                if not mmap_size or mmap_size <= 0:
                    raise ValueError("use_mmap=True requires positive mmap_size")
                fp = open(outfile, "w+b")
                fp.truncate(mmap_size)
                mm = mmap.mmap(fp.fileno(), mmap_size, access=mmap.ACCESS_WRITE)
                outfp = FileLikeAdapter(fp, mode="wb", mm=mm)
            else:
                outfp = FileLikeAdapter(open(outfile, "wb"), mode="wb")

        # Compressed branches (unchanged openers; all wrapped)
        elif (fextname == ".gz" and "gzip" in compressionsupport):
            if PY2:
                outfp = FileLikeAdapter(GzipFile(outfile, mode=mode, level=compressionlevel), mode="wb")
            else:
                outfp = FileLikeAdapter(gzip.open(outfile, mode, compressionlevel), mode="wb")

        elif (fextname == ".bz2" and "bzip2" in compressionsupport):
            outfp = FileLikeAdapter(bz2.open(outfile, mode, compressionlevel), mode="wb")

        elif (fextname == ".zst" and "zstandard" in compressionsupport):
            if 'zstandard' in sys.modules:
                outfp = FileLikeAdapter(ZstdFile(outfile, mode=mode, level=compressionlevel), mode="wb")
            elif 'pyzstd' in sys.modules:
                outfp = FileLikeAdapter(pyzstd.zstdfile.ZstdFile(outfile, mode=mode, level=compressionlevel), mode="wb")
            else:
                return False  # fix: 'Flase' -> False

        elif (fextname == ".xz" and "xz" in compressionsupport):
            try:
                outfp = FileLikeAdapter(
                    lzma.open(outfile, mode, format=lzma.FORMAT_XZ,
                              filters=[{"id": lzma.FILTER_LZMA2, "preset": compressionlevel}]),
                    mode="wb")
            except (NotImplementedError, lzma.LZMAError):
                outfp = FileLikeAdapter(lzma.open(outfile, mode, format=lzma.FORMAT_XZ), mode="wb")

        elif (fextname == ".lz4" and "lz4" in compressionsupport):
            outfp = FileLikeAdapter(lz4.frame.open(outfile, mode, compression_level=compressionlevel), mode="wb")

        elif (fextname == ".lzma" and "lzma" in compressionsupport):
            try:
                outfp = FileLikeAdapter(
                    lzma.open(outfile, mode, format=lzma.FORMAT_ALONE,
                              filters=[{"id": lzma.FILTER_LZMA1, "preset": compressionlevel}]),
                    mode="wb")
            except (NotImplementedError, lzma.LZMAError):
                outfp = FileLikeAdapter(lzma.open(outfile, mode, format=lzma.FORMAT_ALONE), mode="wb")

        elif ((fextname in (".zz", ".zl", ".zlib")) and "zlib" in compressionsupport):
            outfp = FileLikeAdapter(ZlibFile(outfile, mode=mode, level=compressionlevel), mode="wb")

        else:
            # Fallback: treat as uncompressed
            outfp = FileLikeAdapter(open(outfile, "wb"), mode="wb")

    except FileNotFoundError:
        return False

    try:
        outfp.write_through = True
    except Exception:
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
            try:
                hash_list = sorted(list(hashlib.algorithms))
            except AttributeError:
                hash_list = sorted(list(a.lower() for a in hashlib.algorithms_available))
    else:
        try:
            hash_list = sorted(list(hashlib.algorithms_available))
        except AttributeError:
            try:
                hash_list = sorted(list(hashlib.algorithms))
            except AttributeError:
                hash_list = sorted(list(a.lower() for a in hashlib.algorithms_available))
    checklistout = hash_list
    if(checkfor in checklistout):
        return True
    else:
        return False


def PackCatFile(infiles, outfile, dirlistfromtxt=False, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, followlink=False, checksumtype=["md5", "md5", "md5", "md5", "md5"], extradata=[], jsondata={}, formatspecs=__file_format_multi_dict__, saltkey=None, verbose=False, returnfp=False):
        return AppendFilesWithContentToOutFile(infiles, outfile, dirlistfromtxt, fmttype, compression, compresswholefile, compressionlevel, compressionuselist, extradata, jsondata, followlink, checksumtype, formatspecs, saltkey, verbose, returnfp)

def PackStackedCatFile(infiles, outfile, dirlistfromtxt=False, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, followlink=False, checksumtype=["md5", "md5", "md5", "md5", "md5"], extradata=[], jsondata={}, formatspecs=__file_format_multi_dict__, saltkey=None, verbose=False, returnfp=False):
        return AppendFilesWithContentToStackedOutFile(infiles, outfile, dirlistfromtxt, fmttype, compression, compresswholefile, compressionlevel, compressionuselist, extradata, jsondata, followlink, checksumtype, formatspecs, saltkey, verbose, returnfp)

def PackCatFileFromDirList(infiles, outfile, dirlistfromtxt=False, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, followlink=False, checksumtype=["md5", "md5", "md5", "md5", "md5"], extradata=[], formatspecs=__file_format_dict__, saltkey=None, verbose=False, returnfp=False):
    return PackCatFile(infiles, outfile, dirlistfromtxt, fmttype, compression, compresswholefile, compressionlevel, compressionuselist, followlink, checksumtype, extradata, formatspecs, saltkey, verbose, returnfp)


def PackCatFileFromTarFile(infile, outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["md5", "md5", "md5", "md5", "md5"], extradata=[], jsondata={}, formatspecs=__file_format_dict__, saltkey=None, verbose=False, returnfp=False):
    return AppendFilesWithContentFromTarFileToOutFile(infile, outfile, fmttype, compression, compresswholefile, compressionlevel, compressionuselist, extradata, jsondata, checksumtype, formatspecs, saltkey, verbose, returnfp)


def PackCatFileFromZipFile(infile, outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["md5", "md5", "md5", "md5", "md5"], extradata=[], jsondata={}, formatspecs=__file_format_dict__, saltkey=None, verbose=False, returnfp=False):
    return AppendFilesWithContentFromZipFileToOutFile(infile, outfile, fmttype, compression, compresswholefile, compressionlevel, compressionuselist, extradata, jsondata, checksumtype, formatspecs, saltkey, verbose, returnfp)


if(not rarfile_support):
    def PackCatFileFromRarFile(infile, outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["md5", "md5", "md5", "md5", "md5"], extradata=[], jsondata={}, formatspecs=__file_format_dict__, saltkey=None, verbose=False, returnfp=False):
        return False
else:
    def PackCatFileFromRarFile(infile, outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["md5", "md5", "md5", "md5", "md5"], extradata=[], jsondata={}, formatspecs=__file_format_dict__, saltkey=None, verbose=False, returnfp=False):
        return AppendFilesWithContentFromRarFileToOutFile(infile, outfile, fmttype, compression, compresswholefile, compressionlevel, compressionuselist, extradata, jsondata, checksumtype, formatspecs, saltkey, verbose, returnfp)


if(not py7zr_support):
    def PackCatFileFromSevenZipFile(infile, outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["md5", "md5", "md5", "md5", "md5"], extradata=[], formatspecs=__file_format_dict__, saltkey=None, verbose=False, returnfp=False):
        return False
else:
    def PackCatFileFromSevenZipFile(infile, outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["md5", "md5", "md5", "md5", "md5"], extradata=[], jsondata={}, formatspecs=__file_format_dict__, saltkey=None, verbose=False, returnfp=False):
        return AppendFilesWithContentFromSevenZipFileToOutFile(infile, outfile, fmttype, compression, compresswholefile, compressionlevel, compressionuselist, extradata, jsondata, checksumtype, formatspecs, saltkey, verbose, returnfp)


def PackCatFileFromInFile(infile, outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["md5", "md5", "md5", "md5", "md5"], extradata=[], jsondata={}, formatspecs=__file_format_dict__, saltkey=None, verbose=False, returnfp=False):
    checkcompressfile = CheckCompressionSubType(infile, formatspecs, 0, True)
    if(IsNestedDict(formatspecs) and checkcompressfile in formatspecs):
        formatspecs = formatspecs[checkcompressfile]
    if(verbose):
        logging.basicConfig(format="%(message)s", stream=PY_STDOUT_TEXT, level=logging.DEBUG)
    if(checkcompressfile == "tarfile" and TarFileCheck(infile)):
        return PackCatFileFromTarFile(infile, outfile, fmttype, compression, compresswholefile, compressionlevel, compressionuselist, checksumtype, extradata, jsondata, formatspecs, saltkey, verbose, returnfp)
    elif(checkcompressfile == "zipfile" and zipfile.is_zipfile(infile)):
        return PackCatFileFromZipFile(infile, outfile, fmttype, compression, compresswholefile, compressionlevel, compressionuselist, checksumtype, extradata, jsondata, formatspecs, saltkey, verbose, returnfp)
    elif(rarfile_support and checkcompressfile == "rarfile" and (rarfile.is_rarfile(infile) or rarfile.is_rarfile_sfx(infile))):
        return PackCatFileFromRarFile(infile, outfile, fmttype, compression, compresswholefile, compressionlevel, compressionuselist, checksumtype, extradata, jsondata, formatspecs, saltkey, verbose, returnfp)
    elif(py7zr_support and checkcompressfile == "7zipfile" and py7zr.is_7zfile(infile)):
        return PackCatFileFromSevenZipFile(infile, outfile, fmttype, compression, compresswholefile, compressionlevel, compressionuselist, checksumtype, extradata, jsondata, formatspecs, saltkey, verbose, returnfp)
    elif(IsSingleDict(formatspecs) and checkcompressfile == formatspecs['format_magic']):
        return RePackCatFile(infile, outfile, fmttype, compression, compresswholefile, compressionlevel, False, 0, 0, checksumtype, False, extradata, jsondata, formatspecs, saltkey, verbose, returnfp)
    else:
        return False
    return False

# --- Add this helper (Py2/3 compatible) ---
def CatFileArrayValidate(listarrayfiles, verbose=False):
    import logging
    # Top-level checks
    if not isinstance(listarrayfiles, dict):
        if verbose: logging.warning("listarrayfiles must be a dict, got %r", type(listarrayfiles))
        return False
    for key in ("ffilelist", "fnumfiles"):
        if key not in listarrayfiles:
            if verbose: logging.warning("Missing top-level key: %s", key)
            return False
    if not isinstance(listarrayfiles["ffilelist"], list):
        if verbose: logging.warning("ffilelist must be a list, got %r", type(listarrayfiles["ffilelist"]))
        return False

    # Per-entry required keys
    required = [
        "fname", "fencoding", "fheadersize", "fsize", "flinkname",
        "fatime", "fmtime", "fctime", "fbtime",
        "fmode", "fchmode", "fuid", "funame", "fgid", "fgname",
        "finode", "flinkcount", "fwinattributes",
        "fcompression", "fcsize",
        "fdev", "fminor", "fmajor",
        "fseeknextfile", "fextradata", "fextrafields",
        "fcontents", "fcontentasfile", "fjsondata", "ftype",
    ]
    ok = True
    for i, ent in enumerate(listarrayfiles["ffilelist"]):
        if not isinstance(ent, dict):
            if verbose: logging.warning("ffilelist[%d] must be a dict, got %r", i, type(ent))
            ok = False
            continue
        missing = [k for k in required if k not in ent]
        if missing:
            if verbose: logging.warning("ffilelist[%d] missing keys: %s", i, ", ".join(missing))
            ok = False
            continue
        # Light type/convert checks for numeric-ish fields
        intish = [
            "fheadersize", "fsize", "fatime", "fmtime", "fctime", "fbtime",
            "fmode", "fchmode", "fuid", "fgid", "finode",
            "flinkcount", "fwinattributes", "fcsize",
            "fdev", "fminor", "fmajor", "ftype",
        ]
        for k in intish:
            try:
                int(ent[k])
            except Exception:
                if verbose: logging.warning("ffilelist[%d].%s expected int-convertible, got %r", i, k, ent[k])
                ok = False
        # Booleans/flags presence
        if not isinstance(ent["fcontentasfile"], (bool, int)):  # tolerate 0/1
            if verbose: logging.warning("ffilelist[%d].fcontentasfile should be bool-like, got %r", i, ent["fcontentasfile"])
            ok = False
        # Arrays presence
        for arrk in ("fextradata",):
            if not isinstance(ent[arrk], list):
                if verbose: logging.warning("ffilelist[%d].%s should be a list, got %r", i, arrk, type(ent[arrk]))
                ok = False
        if not isinstance(ent.get("fjsondata", {}), dict):
            if verbose: logging.warning("ffilelist[%d].fjsondata should be a dict, got %r", i, type(ent.get("fjsondata")))
            ok = False
    return ok

def CatFileValidate(infile, fmttype="auto", filestart=0, formatspecs=__file_format_multi_dict__, saltkey=None, seektoend=False, verbose=False, returnfp=False):
    if(verbose):
        logging.basicConfig(format="%(message)s", stream=PY_STDOUT_TEXT, level=logging.DEBUG)
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
        elif(IsSingleDict(formatspecs) and checkcompressfile != formatspecs['format_magic']):
            return False
        elif(IsNestedDict(formatspecs) and checkcompressfile not in formatspecs):
            return False
        if(not fp):
            return False
        fp.seek(filestart, 0)
    elif(infile == "-"):
        fp = MkTempFile()
        shutil.copyfileobj(PY_STDIN_BUF, fp, length=__filebuff_size__)
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
    except (OSError, ValueError):
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
    formdelsize = len(formatspecs['format_delimiter'])
    formdel = fp.read(formdelsize).decode("UTF-8")
    if(formstring != formatspecs['format_magic'] + inheaderver):
        return False
    if(formdel != formatspecs['format_delimiter']):
        return False
    if(formatspecs['new_style']):
        inheader = ReadFileHeaderDataBySize(fp, formatspecs['format_delimiter'])
    else:
        inheader = ReadFileHeaderDataWoSize(fp, formatspecs['format_delimiter'])
    fnumextrafieldsize = int(inheader[13], 16)
    fnumextrafields = int(inheader[14], 16)
    extrastart = 15
    extraend = extrastart + fnumextrafields
    formversion = re.findall("([\\d]+)", formstring)
    fheadsize = int(inheader[0], 16)
    fnumfields = int(inheader[1], 16)
    fnumfiles = int(inheader[6], 16)
    fprechecksumtype = inheader[-2]
    fprechecksum = inheader[-1]
    outfseeknextfile = inheader[7]
    fjsonsize = int(inheader[10], 16)
    fjsonchecksumtype = inheader[11]
    fjsonchecksum = inheader[12]
    fprejsoncontent = fp.read(fjsonsize)
    jsonfcs = GetFileChecksum(fprejsoncontent, fjsonchecksumtype, True, formatspecs, saltkey)
    if(fjsonsize > 0):
        if(CheckChecksums(jsonfcs, fjsonchecksum)):
            if(verbose):
                VerbosePrintOut("File JSON Data Checksum Passed at offset " + str(outfjstart))
                VerbosePrintOut("'" + outfjsonchecksum + "' == " + "'" + injsonfcs + "'")
        else:
            valid_archive = False
            invalid_archive = True
            if(verbose):
                VerbosePrintOut("File JSON Data Checksum Error at offset " + str(outfjstart))
                VerbosePrintOut("'" + outfjsonchecksum + "' != " + "'" + injsonfcs + "'")
    if(not CheckChecksums(fjsonchecksum, jsonfcs) and not skipchecksum):
        VerbosePrintOut("File JSON Data Checksum Error with file " +
                        fname + " at offset " + str(fheaderstart))
        VerbosePrintOut("'" + fjsonchecksum + "' != " + "'" + jsonfcs + "'")
        return False
    # Next seek directive
    if(re.findall(r"^\+([0-9]+)", outfseeknextfile)):
        fseeknextasnum = int(outfseeknextfile.replace("+", ""))
        if(abs(fseeknextasnum) == 0):
            pass
        fp.seek(fseeknextasnum, 1)
    elif(re.findall(r"^\-([0-9]+)", outfseeknextfile)):
        fseeknextasnum = int(outfseeknextfile)
        if(abs(fseeknextasnum) == 0):
            pass
        fp.seek(fseeknextasnum, 1)
    elif(re.findall(r"^([0-9]+)", outfseeknextfile)):
        fseeknextasnum = int(outfseeknextfile)
        if(abs(fseeknextasnum) == 0):
            pass
        fp.seek(fseeknextasnum, 0)
    else:
        return False
    il = 0
    headercheck = ValidateHeaderChecksum([formstring] + inheader[:-1], fprechecksumtype, fprechecksum, formatspecs)
    newfcs = GetHeaderChecksum([formstring] + inheader[:-1], fprechecksumtype, True, formatspecs, saltkey)
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
            VerbosePrintOut("'" + fprechecksum + "' == " + "'" + newfcs + "'")
    else:
        # always flip flags, even when not verbose
        valid_archive = False
        invalid_archive = True
        if(verbose):
            VerbosePrintOut("File Header Checksum Failed at offset " + str(0))
            VerbosePrintOut("'" + fprechecksum + "' != " + "'" + newfcs + "'")
    if(verbose):
        VerbosePrintOut("")
    # Iterate either until EOF (seektoend) or fixed count
    while (fp.tell() < CatSizeEnd) if seektoend else (il < fnumfiles):
        outfhstart = fp.tell()
        if(formatspecs['new_style']):
            inheaderdata = ReadFileHeaderDataBySize(fp, formatspecs['format_delimiter'])
        else:
            inheaderdata = ReadFileHeaderDataWoSize(fp, formatspecs['format_delimiter'])

        if(len(inheaderdata) == 0):
            break
        if(re.findall("^[.|/]", inheaderdata[5])):
            outfname = inheaderdata[5]
        else:
            outfname = "./" + inheaderdata[5]
        outfbasedir = os.path.dirname(outfname)
        outfsize = int(inheaderdata[7], 16)
        outfcompression = inheaderdata[17]
        outfcsize = int(inheaderdata[18], 16)
        fid = int(inheaderdata[23], 16)
        finode = int(inheaderdata[24], 16)
        outfseeknextfile = inheaderdata[28]
        outfjsonsize = int(inheaderdata[31], 16)
        outfjsonchecksumtype = inheaderdata[32]
        outfjsonchecksum = inheaderdata[33]
        outfhend = fp.tell() - 1  # (kept for parity; not used)
        outfjstart = fp.tell()
        # Read JSON bytes; compute checksum on bytes for robustness
        outfprejsoncontent_bytes = fp.read(outfjsonsize)
        # Decode for any downstream text needs (not used further here)
        try:
            outfprejsoncontent = outfprejsoncontent_bytes.decode("UTF-8")
        except Exception:
            outfprejsoncontent = None
        outfjend = fp.tell()
        fp.seek(len(formatspecs['format_delimiter']), 1)
        injsonfcs = GetFileChecksum(outfprejsoncontent_bytes, outfjsonchecksumtype, True, formatspecs, saltkey)
        outfextrafields = int(inheaderdata[35], 16)
        extrafieldslist = []
        extrastart = 36
        extraend = extrastart + outfextrafields
        outfcs = inheaderdata[-2].lower()
        outfccs = inheaderdata[-1].lower()
        infcs = GetHeaderChecksum(inheaderdata[:-2], inheaderdata[-4].lower(), True, formatspecs, saltkey)
        if(verbose):
            VerbosePrintOut(outfname)
            VerbosePrintOut("Record Number " + str(il) + "; File ID " + str(fid) + "; iNode Number " + str(finode))

        if(CheckChecksums(outfcs, infcs)):
            if(verbose):
                VerbosePrintOut("File Header Checksum Passed at offset " + str(outfhstart))
                VerbosePrintOut("'" + outfcs + "' == " + "'" + infcs + "'")
        else:
            valid_archive = False
            invalid_archive = True
            if(verbose):
                VerbosePrintOut("File Header Checksum Failed at offset " + str(outfhstart))
                VerbosePrintOut("'" + outfcs + "' != " + "'" + infcs + "'")
        if(outfjsonsize > 0):
            if(CheckChecksums(injsonfcs, outfjsonchecksum)):
                if(verbose):
                    VerbosePrintOut("File JSON Data Checksum Passed at offset " + str(outfjstart))
                    VerbosePrintOut("'" + outfjsonchecksum + "' == " + "'" + injsonfcs + "'")
            else:
                valid_archive = False
                invalid_archive = True
                if(verbose):
                    VerbosePrintOut("File JSON Data Checksum Error at offset " + str(outfjstart))
                    VerbosePrintOut("'" + outfjsonchecksum + "' != " + "'" + injsonfcs + "'")
        outfcontentstart = fp.tell()
        outfcontents = b""   # FIX: bytes for Py2/3 consistency
        pyhascontents = False
        if(outfsize > 0):
            if(outfcompression == "none" or outfcompression == "" or outfcompression == "auto"):
                outfcontents = fp.read(outfsize)
            else:
                outfcontents = fp.read(outfcsize)

            infccs = GetFileChecksum(outfcontents, inheaderdata[-3].lower(), False, formatspecs, saltkey)
            pyhascontents = True

            if(CheckChecksums(outfccs, infccs)):
                if(verbose):
                    VerbosePrintOut("File Content Checksum Passed at offset " + str(outfcontentstart))
                    VerbosePrintOut("'" + outfccs + "' == " + "'" + infccs + "'")
            else:
                valid_archive = False
                invalid_archive = True
                if(verbose):
                    VerbosePrintOut("File Content Checksum Failed at offset " + str(outfcontentstart))
                    VerbosePrintOut("'" + outfccs + "' != " + "'" + infccs + "'")
        if(verbose):
            VerbosePrintOut("")
        # Next seek directive
        if(re.findall(r"^\+([0-9]+)", outfseeknextfile)):
            fseeknextasnum = int(outfseeknextfile.replace("+", ""))
            if(abs(fseeknextasnum) == 0):
                pass
            fp.seek(fseeknextasnum, 1)
        elif(re.findall(r"^\-([0-9]+)", outfseeknextfile)):
            fseeknextasnum = int(outfseeknextfile)
            if(abs(fseeknextasnum) == 0):
                pass
            fp.seek(fseeknextasnum, 1)
        elif(re.findall(r"^([0-9]+)", outfseeknextfile)):
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


def CatFileValidateFile(infile, fmttype="auto", filestart=0, formatspecs=__file_format_multi_dict__, saltkey=None, seektoend=False, verbose=False, returnfp=False):
    return CatFileValidate(infile, fmttype, filestart, formatspecs, saltkey, seektoend, verbose, returnfp)


def CatFileValidateMultiple(infile, fmttype="auto", filestart=0, formatspecs=__file_format_multi_dict__, saltkey=None, seektoend=False, verbose=False, returnfp=False):
    if(isinstance(infile, (list, tuple, ))):
        pass
    else:
        infile = [infile]
    outretval = True
    for curfname in infile:
        curretfile = CatFileValidate(curfname, fmttype, filestart, formatspecs, saltkey, seektoend, verbose, returnfp)
        if(not curretfile):
            outretval = False
    return outretval

def CatFileValidateMultipleFiles(infile, fmttype="auto", filestart=0, formatspecs=__file_format_multi_dict__, saltkey=None, seektoend=False, verbose=False, returnfp=False):
    return CatFileValidateMultiple(infile, fmttype, filestart, formatspecs, saltkey, seektoend, verbose, returnfp)


def StackedCatFileValidate(infile, fmttype="auto", filestart=0, formatspecs=__file_format_multi_dict__, saltkey=None, seektoend=False, verbose=False, returnfp=False):
    outretval = []
    outstartfile = filestart
    outfsize = float('inf')
    while True:
        if outstartfile >= outfsize:   # stop when function signals False
            break
        is_valid_file = CatFileValidate(infile, fmttype, outstartfile, formatspecs, saltkey, seektoend, verbose, True)
        if is_valid_file is False:   # stop when function signals False
            outretval.append(is_valid_file)
            break
        else:
            outretval.append(True)
        infile = is_valid_file
        outstartfile = infile.tell()
        try:
            infile.seek(0, 2)
        except (OSError, ValueError):
            SeekToEndOfFile(infile)
        outfsize = infile.tell()
        infile.seek(outstartfile, 0)
    if(returnfp):
        return infile
    else:
        try:
            infile.close()
        except AttributeError:
            pass
        return outretval
    


def StackedCatFileValidateFile(infile, fmttype="auto", filestart=0, formatspecs=__file_format_multi_dict__, saltkey=None, seektoend=False, verbose=False, returnfp=False):
    return StackedCatFileValidate(infile, fmttype, filestart, formatspecs, saltkey, seektoend, verbose, returnfp)


def StackedCatFileValidateMultiple(infile, fmttype="auto", filestart=0, formatspecs=__file_format_multi_dict__, saltkey=None, seektoend=False, verbose=False, returnfp=False):
    if(isinstance(infile, (list, tuple, ))):
        pass
    else:
        infile = [infile]
    outretval = True
    for curfname in infile:
        curretfile = StackedCatFileValidate(curfname, fmttype, filestart, formatspecs, saltkey, seektoend, verbose, returnfp)
        if(not curretfile):
            outretval = False
    return outretval

def StackedCatFileValidateMultipleFiles(infile, fmttype="auto", filestart=0, formatspecs=__file_format_multi_dict__, saltkey=None, seektoend=False, verbose=False, returnfp=False):
    return StackedCatFileValidateMultiple(infile, fmttype, filestart, formatspecs, saltkey, seektoend, verbose, returnfp)


def CatFileToArray(infile, fmttype="auto", filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_multi_dict__, saltkey=None, seektoend=False, returnfp=False):
    outfp = ReadInFileWithContentToArray(infile, fmttype, filestart, seekstart, seekend, listonly, contentasfile, uncompress, skipchecksum, formatspecs, saltkey, seektoend)
    if not returnfp:
        for item in outfp:
            fp = item.get('fp')
            try:
                if fp and hasattr(fp, "close"):
                    fp.close()
            except Exception:
                # optionally log/collect errors here
                pass
            item['fp'] = None
    return outfp


def MultipleCatFileToArray(infile, fmttype="auto", filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_multi_dict__, saltkey=None, seektoend=False, returnfp=False):
    if(isinstance(infile, (list, tuple, ))):
        pass
    else:
        infile = [infile]
    outretval = []
    for curfname in infile:
        outretval.append(CatFileToArray(curfname, fmttype, filestart, seekstart, seekend, listonly, contentasfile, uncompress, skipchecksum, formatspecs, saltkey, seektoend, returnfp))
    return outretval

def MultipleCatFilesToArray(infile, fmttype="auto", filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_multi_dict__, saltkey=None, seektoend=False, returnfp=False):
    return MultipleCatFileToArray(infile, fmttype, filestart, seekstart, seekend, listonly, contentasfile, uncompress, skipchecksum, formatspecs, saltkey, seektoend, returnfp)


def CatFileStringToArray(instr, filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, skipchecksum=False, formatspecs=__file_format_multi_dict__, saltkey=None, seektoend=False, returnfp=False):
    checkcompressfile = CheckCompressionSubType(infile, formatspecs, filestart, True)
    if(IsNestedDict(formatspecs) and checkcompressfile in formatspecs):
        formatspecs = formatspecs[checkcompressfile]
    fp = MkTempFile(instr)
    listarrayfiles = CatFileToArray(fp, "auto", filestart, seekstart, seekend, listonly, contentasfile, True, skipchecksum, formatspecs, saltkey, seektoend, returnfp)
    return listarrayfiles


def TarFileToArray(infile, seekstart=0, seekend=0, listonly=False, contentasfile=True, skipchecksum=False, formatspecs=__file_format_dict__, seektoend=False, returnfp=False):
    checkcompressfile = CheckCompressionSubType(infile, formatspecs, filestart, True)
    if(IsNestedDict(formatspecs) and checkcompressfile in formatspecs):
        formatspecs = formatspecs[checkcompressfile]
    fp = MkTempFile()
    fp = PackCatFileFromTarFile(infile, fp, "auto", True, None, compressionlistalt, "md5", [], formatspecs, None, False, True)
    listarrayfiles = CatFileToArray(fp, "auto", 0, seekstart, seekend, listonly, contentasfile, True, skipchecksum, formatspecs, None, seektoend, returnfp)
    return listarrayfiles


def ZipFileToArray(infile, seekstart=0, seekend=0, listonly=False, contentasfile=True, skipchecksum=False, formatspecs=__file_format_dict__, seektoend=False, returnfp=False):
    checkcompressfile = CheckCompressionSubType(infile, formatspecs, filestart, True)
    if(IsNestedDict(formatspecs) and checkcompressfile in formatspecs):
        formatspecs = formatspecs[checkcompressfile]
    fp = MkTempFile()
    fp = PackCatFileFromZipFile(infile, fp, "auto", True, None, compressionlistalt, "md5", [], formatspecs, None, False, True)
    listarrayfiles = CatFileToArray(fp, "auto", 0, seekstart, seekend, listonly, contentasfile, True, skipchecksum, formatspecs, None, seektoend, returnfp)
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
        fp = PackCatFileFromRarFile(infile, fp, "auto", True, None, compressionlistalt, "md5", [], formatspecs, None, False, True)
        listarrayfiles = CatFileToArray(fp, "auto", 0, seekstart, seekend, listonly, contentasfile, True, skipchecksum, formatspecs, None, seektoend, returnfp)
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
        fp = PackCatFileFromSevenZipFile(infile, fp, "auto", True, None, compressionlistalt, "md5", [], formatspecs, None, False, True)
        listarrayfiles = CatFileToArray(fp, "auto", 0, seekstart, seekend, listonly, contentasfile, True, skipchecksum, formatspecs, None, seektoend, returnfp)
        return listarrayfiles


def InFileToArray(infile, filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, skipchecksum=False, formatspecs=__file_format_multi_dict__, saltkey=None, seektoend=False, returnfp=False):
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
        return CatFileToArray(infile, "auto", filestart, seekstart, seekend, listonly, contentasfile, True, skipchecksum, formatspecs, saltkey, seektoend, returnfp)
    else:
        return False
    return False


def ListDirToArray(infiles, dirlistfromtxt=False, fmttype=__file_format_default__, compression="auto", compresswholefile=True, compressionlevel=None, followlink=False, filestart=0, seekstart=0, seekend=0, listonly=False, saltkey=None, skipchecksum=False, checksumtype=["md5", "md5", "md5"], extradata=[], formatspecs=__file_format_dict__, verbose=False, seektoend=False, returnfp=False):
    outarray = MkTempFile()
    packform = PackCatFile(infiles, outarray, dirlistfromtxt, fmttype, compression, compresswholefile, compressionlevel, followlink, checksumtype, extradata, formatspecs, saltkey, verbose, True)
    listarrayfiles = CatFileToArray(outarray, "auto", filestart, seekstart, seekend, listonly, True, True, skipchecksum, formatspecs, saltkey, seektoend, returnfp)
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


def RePackCatFile(infile, outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt,  followlink=False, filestart=0, seekstart=0, seekend=0, checksumtype=["md5", "md5", "md5", "md5", "md5"], skipchecksum=False, extradata=[], jsondata={}, formatspecs=None, saltkey=None, seektoend=False, verbose=False, returnfp=False):
    # ---------- Safe defaults ----------
    if compressionuselist is None:
        compressionuselist = compressionlistalt
    if checksumtype is None:
        checksumtype = ["md5", "md5", "md5", "md5", "md5"]
    if extradata is None:
        extradata = []
    if jsondata is None:
        jsondata = {}
    if formatspecs is None:
        formatspecs = __file_format_multi_dict__

    # ---------- Input handling ----------
    if isinstance(infile, dict):
        listarrayfileslist = [infile]
    elif isinstance(infile, list):
        listarrayfileslist = infile
    else:
        if (infile != "-" and not isinstance(infile, bytes_type)  # bytes is str on Py2
            and not hasattr(infile, "read") and not hasattr(infile, "write")):
            infile = RemoveWindowsPath(infile)
        listarrayfileslist = CatFileToArray(
            infile, "auto", filestart, seekstart, seekend,
            False, True, True, skipchecksum, formatspecs, seektoend, False
        )

    # ---------- Format specs selection ----------
    if IsNestedDict(formatspecs) and fmttype in formatspecs:
        formatspecs = formatspecs[fmttype]
    elif IsNestedDict(formatspecs) and fmttype not in formatspecs:
        fmttype = __file_format_default__
        formatspecs = formatspecs.get(fmttype, formatspecs)
        if IsNestedDict(formatspecs) and fmttype in formatspecs:
            formatspecs = formatspecs[fmttype]
        elif IsNestedDict(formatspecs) and fmttype not in formatspecs:
            fmttype = __file_format_default__
            formatspecs = formatspecs.get(fmttype, formatspecs)

    # ---------- Outfile path normalization (fixed: check outfile, not infile) ----------
    if (outfile != "-" and not isinstance(outfile, bytes_type)
        and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
        outfile = RemoveWindowsPath(outfile)

    # ---------- Prepare destination ----------
    if (outfile != "-" and outfile is not None
        and not hasattr(outfile, "read") and not hasattr(outfile, "write")):
        if os.path.exists(outfile):
            try:
                os.unlink(outfile)
            except OSError as e:
                if verbose:
                    logging.warning("Could not unlink existing outfile %r: %s", outfile, e)

    # Decide file object
    if outfile == "-" or outfile is None:
        verbose = False
        fp = MkTempFile()
    elif(isinstance(outfile, FileLikeAdapter)):
        fp = outfile
    elif hasattr(outfile, "read") or hasattr(outfile, "write"):
        fp = outfile
    elif re.findall(__upload_proto_support__, outfile):
        fp = MkTempFile()
    else:
        fbasename = os.path.splitext(outfile)[0]
        fextname = os.path.splitext(outfile)[1]
        if (not compresswholefile and fextname in outextlistwd):
            compresswholefile = True
        try:
            fp = CompressOpenFile(outfile, compresswholefile, compressionlevel)
        except PermissionError:
            return False

    for listarrayfiles in listarrayfileslist:
        # Light guard on required structure
        if not listarrayfiles or 'ffilelist' not in listarrayfiles or 'fnumfiles' not in listarrayfiles:
            if verbose:
                logging.warning("Invalid listarrayfiles structure.")
            return False

        # ---------- Compression normalization (fixed logic) ----------
        try:
            fmt_magic = formatspecs['format_magic']
        except Exception:
            fmt_magic = None
        if (not compression) or (fmt_magic is not None and compression == fmt_magic):
            compression = "auto"
        if (compression is None) or (compressionuselist and compression not in compressionuselist):
            compression = "auto"

        if verbose:
            logging.basicConfig(format="%(message)s", stream=PY_STDOUT_TEXT, level=logging.DEBUG)

        # No files?
        if not listarrayfiles.get('ffilelist'):
            return False

        # ---------- Header prep ----------
        formver = formatspecs.get('format_ver', "1.0")
        fileheaderver = str(int(str(formver).replace(".", "")))  # kept for parity
        lenlist = len(listarrayfiles['ffilelist'])
        fnumfiles = int(listarrayfiles.get('fnumfiles', lenlist))
        if lenlist != fnumfiles:
            fnumfiles = lenlist

        AppendFileHeader(fp, fnumfiles, listarrayfiles.get('fencoding', 'utf-8'), listarrayfiles['fextradata'], listarrayfiles['fjsondata'], [checksumtype[0], checksumtype[1]], formatspecs)

        # loop counters
        lcfi = 0
        lcfx = fnumfiles
        curinode = 0
        curfid = 0
        inodetofile = {}
        filetoinode = {}
        reallcfi = 0

        # ---------- File entries loop ----------
        while lcfi < lcfx:
            cur_entry = listarrayfiles['ffilelist'][reallcfi]

            fencoding = cur_entry.get('fencoding', listarrayfiles.get('fencoding', 'utf-8'))

            # path
            fname_field = cur_entry['fname']
            if re.findall(r"^[.|/]", fname_field):
                fname = fname_field
            else:
                fname = "./" + fname_field

            if verbose:
                VerbosePrintOut(fname)

            # fields (hex-encoded where expected)
            fheadersize = format(int(cur_entry['fheadersize']), 'x').lower()
            fsize       = format(int(cur_entry['fsize']), 'x').lower()
            fblksize       = format(int(cur_entry['fblksize']), 'x').lower()
            fblocks       = format(int(cur_entry['fblocks']), 'x').lower()
            fflags       = format(int(cur_entry['fflags']), 'x').lower()
            flinkname   = cur_entry['flinkname']
            fatime      = format(int(cur_entry['fatime']), 'x').lower()
            fmtime      = format(int(cur_entry['fmtime']), 'x').lower()
            fctime      = format(int(cur_entry['fctime']), 'x').lower()
            fbtime      = format(int(cur_entry['fbtime']), 'x').lower()
            fmode       = format(int(cur_entry['fmode']), 'x').lower()
            fchmode     = format(int(cur_entry['fchmode']), 'x').lower()
            fuid        = format(int(cur_entry['fuid']), 'x').lower()
            funame      = cur_entry['funame']
            fgid        = format(int(cur_entry['fgid']), 'x').lower()
            fgname      = cur_entry['fgname']
            finode_int  = int(cur_entry['finode'])  # use int for logic
            finode      = format(finode_int, 'x').lower()
            flinkcount  = format(int(cur_entry['flinkcount']), 'x').lower()
            fwinattributes = format(int(cur_entry['fwinattributes']), 'x').lower()
            fcompression   = cur_entry['fcompression']
            fcsize         = format(int(cur_entry['fcsize']), 'x').lower()
            fdev           = format(int(cur_entry['fdev']), 'x').lower()
            fdev_minor     = format(int(cur_entry['fminor']), 'x').lower()
            fdev_major     = format(int(cur_entry['fmajor']), 'x').lower()
            fseeknextfile  = cur_entry['fseeknextfile']

            # extra fields sizing
            if (len(cur_entry['fextradata']) > cur_entry['fextrafields']
                and len(cur_entry['fextradata']) > 0):
                cur_entry['fextrafields'] = len(cur_entry['fextradata'])

            # extradata/jsondata defaults per file
            if not followlink and len(extradata) <= 0:
                extradata = cur_entry['fextradata']

            fvendorfields = cur_entry['fvendorfields']
            ffvendorfieldslist = []
            if(fvendorfields>0):
                ffvendorfieldslist = cur_entry['fvendorfieldslist']

            if not followlink and len(jsondata) <= 0:
                jsondata = cur_entry['fjsondata']

            # content handling
            fcontents = cur_entry['fcontents']
            if not cur_entry['fcontentasfile']:
                fcontents = MkTempFile(fcontents)

            # detect/possibly recompress per-file (only if not already compressed and not compresswholefile)
            typechecktest = CheckCompressionType(fcontents, filestart=0, closefp=False)
            fcontents.seek(0, 0)

            # get fcencoding once here
            fcencoding = GetFileEncoding(fcontents, 0, False)[0]

            fcompression = ""
            fcsize = format(int(0), 'x').lower()
            curcompression = "none"

            if typechecktest is False and not compresswholefile:
                fcontents.seek(0, 2)
                ucfsize = fcontents.tell()
                fcontents.seek(0, 0)

                if compression == "auto":
                    ilsize = len(compressionuselist)
                    ilmin = 0
                    ilcsize = []
                    while ilmin < ilsize:
                        cfcontents = MkTempFile()
                        fcontents.seek(0, 0)
                        shutil.copyfileobj(fcontents, cfcontents, length=__filebuff_size__)
                        fcontents.seek(0, 0)
                        cfcontents.seek(0, 0)
                        cfcontents = CompressOpenFileAlt(
                            cfcontents, compressionuselist[ilmin], compressionlevel, compressionuselist, formatspecs
                        )
                        if cfcontents:
                            cfcontents.seek(0, 2)
                            ilcsize.append(cfcontents.tell())
                            cfcontents.close()
                        else:
                            ilcsize.append(float("inf"))
                        ilmin += 1
                    ilcmin = ilcsize.index(min(ilcsize))
                    curcompression = compressionuselist[ilcmin]

                fcontents.seek(0, 0)
                cfcontents = MkTempFile()
                shutil.copyfileobj(fcontents, cfcontents, length=__filebuff_size__)
                cfcontents.seek(0, 0)
                cfcontents = CompressOpenFileAlt(
                    cfcontents, curcompression, compressionlevel, compressionuselist, formatspecs
                )
                cfcontents.seek(0, 2)
                cfsize_val = cfcontents.tell()
                if ucfsize > cfsize_val:
                    fcsize = format(int(cfsize_val), 'x').lower()
                    fcompression = curcompression
                    fcontents.close()
                    fcontents = cfcontents

            # link following (fixed: use listarrayfiles, not prelistarrayfiles)
            if followlink:
                if (cur_entry['ftype'] == 1 or cur_entry['ftype'] == 2):
                    getflinkpath = cur_entry['flinkname']
                    flinkid = listarrayfiles['filetoid'][getflinkpath]
                    flinkinfo = listarrayfiles['ffilelist'][flinkid]
                    fheadersize = format(int(flinkinfo['fheadersize']), 'x').lower()
                    fsize       = format(int(flinkinfo['fsize']), 'x').lower()
                    fblksize       = format(int(flinkinfo['fblksize']), 'x').lower()
                    fblocks       = format(int(flinkinfo['fblocks']), 'x').lower()
                    fflags       = format(int(flinkinfo['fflags']), 'x').lower()
                    flinkname   = flinkinfo['flinkname']
                    fatime      = format(int(flinkinfo['fatime']), 'x').lower()
                    fmtime      = format(int(flinkinfo['fmtime']), 'x').lower()
                    fctime      = format(int(flinkinfo['fctime']), 'x').lower()
                    fbtime      = format(int(flinkinfo['fbtime']), 'x').lower()
                    fmode       = format(int(flinkinfo['fmode']), 'x').lower()
                    fchmode     = format(int(flinkinfo['fchmode']), 'x').lower()
                    fuid        = format(int(flinkinfo['fuid']), 'x').lower()
                    funame      = flinkinfo['funame']
                    fgid        = format(int(flinkinfo['fgid']), 'x').lower()
                    fgname      = flinkinfo['fgname']
                    finode_int  = int(flinkinfo['finode'])
                    finode      = format(int(flinkinfo['finode']), 'x').lower()
                    flinkcount  = format(int(flinkinfo['flinkcount']), 'x').lower()
                    fwinattributes = format(int(flinkinfo['fwinattributes']), 'x').lower()
                    fcompression   = flinkinfo['fcompression']
                    fcsize         = format(int(flinkinfo['fcsize']), 'x').lower()
                    fdev           = format(int(flinkinfo['fdev']), 'x').lower()
                    fdev_minor     = format(int(flinkinfo['fminor']), 'x').lower()
                    fdev_major     = format(int(flinkinfo['fmajor']), 'x').lower()
                    fseeknextfile  = flinkinfo['fseeknextfile']
                    if (len(flinkinfo['fextradata']) > flinkinfo['fextrafields']
                        and len(flinkinfo['fextradata']) > 0):
                        flinkinfo['fextrafields'] = len(flinkinfo['fextradata'])
                    if len(extradata) < 0:
                        extradata = flinkinfo['fextradata']

                    fvendorfields = flinkinfo['fvendorfields']
                    ffvendorfieldslist = []
                    if(fvendorfields>0):
                        ffvendorfieldslist = flinkinfo['fvendorfieldslist']

                    if len(jsondata) < 0:
                        jsondata = flinkinfo['fjsondata']
                    fcontents = flinkinfo['fcontents']
                    if not flinkinfo['fcontentasfile']:
                        fcontents = MkTempFile(fcontents)
                    ftypehex = format(flinkinfo['ftype'], 'x').lower()
            else:
                ftypehex = format(int(cur_entry['ftype']), 'x').lower()

            # file/inode ids (fixed: compare using int)
            fcurfid = format(curfid, 'x').lower()
            if (not followlink and finode_int != 0):
                if cur_entry['ftype'] != 1:
                    fcurinode = format(int(curinode), 'x').lower()
                    inodetofile[curinode] = fname
                    filetoinode[fname] = curinode
                    curinode += 1
                else:
                    fcurinode = format(int(filetoinode[flinkname]), 'x').lower()
            else:
                fcurinode = format(int(curinode), 'x').lower()
                curinode += 1
            curfid += 1

            if fcompression == "none":
                fcompression = ""

            tmpoutlist = [
                ftypehex, fencoding, fcencoding, fname, flinkname, fsize, fblksize, fblocks, fflags, fatime, fmtime,
                fctime, fbtime, fmode, fwinattributes, fcompression, fcsize, fuid, funame,
                fgid, fgname, fcurfid, fcurinode, flinkcount, fdev, fdev_minor, fdev_major, fseeknextfile
            ]

            if(fvendorfields>0 and len(ffvendorfieldslist)>0):
                extradata.extend(fvendorfields)

            AppendFileHeaderWithContent(fp, tmpoutlist, extradata, jsondata, fcontents.read(),[checksumtype[2], checksumtype[3], checksumtype[4]], formatspecs, saltkey)
            try:
                fcontents.close()
            except Exception:
                pass
            lcfi += 1
            reallcfi += 1

    # ---------- Finalization ----------
    if (outfile == "-" or outfile is None
        or hasattr(outfile, "read") or hasattr(outfile, "write")):
        fp = CompressOpenFileAlt(fp, compression, compressionlevel, compressionuselist, formatspecs)
        try:
            fp.flush()
            if hasattr(os, "sync"):
                os.fsync(fp.fileno())
        except (io.UnsupportedOperation, AttributeError, OSError):
            pass

    if outfile == "-":
        fp.seek(0, 0)
        shutil.copyfileobj(fp, PY_STDOUT_BUF, length=__filebuff_size__)
    elif outfile is None:
        fp.seek(0, 0)
        outvar = fp.read()
        try:
            fp.close()
        except Exception:
            pass
        return outvar
    elif ((not hasattr(outfile, "read") and not hasattr(outfile, "write"))
          and re.findall(__upload_proto_support__, outfile)):
        fp = CompressOpenFileAlt(fp, compression, compressionlevel, compressionuselist, formatspecs)
        fp.seek(0, 0)
        upload_file_to_internet_file(fp, outfile)

    if returnfp:
        return fp
    else:
        try:
            fp.close()
        except Exception:
            pass
        return True

def RePackMultipleCatFile(infiles, outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt,  followlink=False, filestart=0, seekstart=0, seekend=0, checksumtype=["md5", "md5", "md5", "md5", "md5"], skipchecksum=False, extradata=[], jsondata={}, formatspecs=None, saltkey=None, seektoend=False, verbose=False, returnfp=False):
    if not isinstance(infiles, list):
        infiles = [infiles]
    returnout = False
    for infileslist in infiles:
        returnout = RePackCatFile(infileslist, outfile, fmttype, compression, compresswholefile, compressionlevel, compressionuselist, followlink, filestart, seekstart, seekend, checksumtype, skipchecksum, extradata, jsondata, formatspecs, saltkey, seektoend, verbose, True)
        if(not returnout):
            break
        else:
            outfile = returnout
    if(not returnfp and returnout):
        returnout.close()
        return True
    return returnout

def RePackCatFileFromString(instr, outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt,  followlink=False, filestart=0, seekstart=0, seekend=0, checksumtype=["md5", "md5", "md5", "md5", "md5"], skipchecksum=False, extradata=[], jsondata={}, formatspecs=None, saltkey=None, seektoend=False, verbose=False, returnfp=False):
    fp = MkTempFile(instr)
    listarrayfiles = RePackCatFile(fp, outfile, fmttype, compression, compresswholefile, compressionlevel, compressionuselist, followlink, filestart, seekstart, seekend, checksumtype, skipchecksum, extradata, jsondata, formatspecs, saltkey, seektoend, verbose, returnfp)
    return listarrayfiles


def PackCatFileFromListDir(infiles, outfile, dirlistfromtxt=False, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, followlink=False, filestart=0, seekstart=0, seekend=0, checksumtype=["md5", "md5", "md5", "md5", "md5"], skipchecksum=False, extradata=[], jsondata={}, formatspecs=__file_format_dict__, saltkey=None, seektoend=False, verbose=False, returnfp=False):
    outarray = MkTempFile()
    packform = PackCatFile(infiles, outarray, dirlistfromtxt, fmttype, compression, compresswholefile, compressionlevel, compressionuselist, followlink, checksumtype, extradata, formatspecs, saltkey, verbose, True)
    listarrayfiles = RePackCatFile(outarray, outfile, fmttype, compression, compresswholefile, compressionlevel, compressionuselist, followlink, filestart, seekstart, seekend, checksumtype, skipchecksum, extradata, jsondata, formatspecs, saltkey, seektoend, verbose, returnfp)
    return listarrayfiles


def UnPackCatFile(infile, outdir=None, followlink=False, filestart=0, seekstart=0, seekend=0, skipchecksum=False, formatspecs=__file_format_multi_dict__, saltkey=None, preservepermissions=True, preservetime=True, seektoend=False, verbose=False, returnfp=False):
    if(outdir is not None):
        outdir = RemoveWindowsPath(outdir)
    if(verbose):
        logging.basicConfig(format="%(message)s", stream=PY_STDOUT_TEXT, level=logging.DEBUG)
    if(isinstance(infile, dict)):
        listarrayfiles = infile
    else:
        if(infile != "-" and not hasattr(infile, "read") and not hasattr(infile, "write") and not (sys.version_info[0] >= 3 and isinstance(infile, bytes))):
            infile = RemoveWindowsPath(infile)
        listarrayfiles = CatFileToArray(infile, "auto", filestart, seekstart, seekend, False, True, True, skipchecksum, formatspecs, saltkey, seektoend, returnfp)
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
                    listarrayfiles['ffilelist'][lcfi]['fcontents'], fpc, length=__filebuff_size__)
                try:
                    fpc.flush()
                    if(hasattr(os, "sync")):
                        os.fsync(fpc.fileno())
                except (io.UnsupportedOperation, AttributeError, OSError):
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
                        shutil.copyfileobj(flinkinfo['fcontents'], fpc, length=__filebuff_size__)
                        try:
                            fpc.flush()
                            if(hasattr(os, "sync")):
                                os.fsync(fpc.fileno())
                        except (io.UnsupportedOperation, AttributeError, OSError):
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
                        shutil.copyfileobj(flinkinfo['fcontents'], fpc, length=__filebuff_size__)
                        try:
                            fpc.flush()
                            if(hasattr(os, "sync")):
                                os.fsync(fpc.fileno())
                        except (io.UnsupportedOperation, AttributeError, OSError):
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


def UnPackCatFileString(instr, outdir=None, followlink=False, filestart=0, seekstart=0, seekend=0, skipchecksum=False, formatspecs=__file_format_multi_dict__, saltkey=None, seektoend=False, verbose=False, returnfp=False):
    fp = MkTempFile(instr)
    listarrayfiles = UnPackCatFile(fp, outdir, followlink, filestart, seekstart, seekend, skipchecksum, formatspecs, saltkey, seektoend, verbose, returnfp)
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

def CatFileListFiles(infile, fmttype="auto", filestart=0, seekstart=0, seekend=0, skipchecksum=False, formatspecs=__file_format_multi_dict__, saltkey=None, seektoend=False, verbose=False, newstyle=False, returnfp=False):
    if(verbose):
        logging.basicConfig(format="%(message)s", stream=PY_STDOUT_TEXT, level=logging.DEBUG)
    if(isinstance(infile, dict)):
        listarrayfileslist = [infile]
    if(isinstance(infile, list)):
        listarrayfileslist = infile
    else:
        if(infile != "-" and not hasattr(infile, "read") and not hasattr(infile, "write") and not (sys.version_info[0] >= 3 and isinstance(infile, bytes))):
            infile = RemoveWindowsPath(infile)
        listarrayfileslist = CatFileToArray(infile, fmttype, filestart, seekstart, seekend, True, False, False, skipchecksum, formatspecs, saltkey, seektoend, returnfp)
    if(not listarrayfileslist):
        return False
    for listarrayfiles in listarrayfileslist:
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


def MultipleCatFileListFiles(infile, fmttype="auto", filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_multi_dict__, saltkey=None, seektoend=False, returnfp=False):
    if(isinstance(infile, (list, tuple, ))):
        pass
    else:
        infile = [infile]
    outretval = {}
    for curfname in infile:
        outretval[curfname] = CatFileListFiles(infile, fmttype, filestart, seekstart, seekend, skipchecksum, formatspecs, saltkey, seektoend, verbose, newstyle, returnfp)
    return outretval


def StackedCatFileListFiles(infile, fmttype="auto", filestart=0, seekstart=0, seekend=0, skipchecksum=False, formatspecs=__file_format_multi_dict__, saltkey=None, seektoend=False, verbose=False, newstyle=False, returnfp=False):
    outretval = []
    outstartfile = filestart
    outfsize = float('inf')
    while True:
        if outstartfile >= outfsize:   # stop when function signals False
            break
        list_file_retu = CatFileListFiles(infile, fmttype, outstartfile, seekstart, seekend, skipchecksum, formatspecs, saltkey, seektoend, verbose, newstyle, True)
        if list_file_retu is False:   # stop when function signals False
            outretval.append(list_file_retu)
        else:
            outretval.append(True)
        infile = list_file_retu
        outstartfile = infile.tell()
        try:
            infile.seek(0, 2)
        except (OSError, ValueError):
            SeekToEndOfFile(infile)
        outfsize = infile.tell()
        infile.seek(outstartfile, 0)
    if(returnfp):
        return infile
    else:
        try:
            infile.close()
        except AttributeError:
            pass
        return outretval


def MultipleStackedCatFileListFiles(infile, fmttype="auto", filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_multi_dict__, saltkey=None, seektoend=False, returnfp=False):
    if(isinstance(infile, (list, tuple, ))):
        pass
    else:
        infile = [infile]
    outretval = {}
    for curfname in infile:
        outretval[curfname] = StackedCatFileListFiles(curfname, fmttype, filestart, seekstart, seekend, listonly, contentasfile, uncompress, skipchecksum, formatspecs, saltkey, seektoend, returnfp)
    return outretval


def CatFileStringListFiles(instr, filestart=0, seekstart=0, seekend=0, skipchecksum=False, formatspecs=__file_format_multi_dict__, saltkey=None, seektoend=False, verbose=False, newstyle=False, returnfp=False):
    fp = MkTempFile(instr)
    listarrayfiles = CatFileListFiles(instr, "auto", filestart, seekstart, seekend, skipchecksum, formatspecs, saltkey, seektoend, verbose, newstyle, returnfp)
    return listarrayfiles


def TarFileListFiles(infile, verbose=False, returnfp=False):
    if(verbose):
        logging.basicConfig(format="%(message)s", stream=PY_STDOUT_TEXT, level=logging.DEBUG)
    if(infile == "-"):
        infile = MkTempFile()
        shutil.copyfileobj(PY_STDIN_BUF, infile, length=__filebuff_size__)
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
        logging.basicConfig(format="%(message)s", stream=PY_STDOUT_TEXT, level=logging.DEBUG)
    if(infile == "-"):
        infile = MkTempFile()
        shutil.copyfileobj(PY_STDIN_BUF, infile, length=__filebuff_size__)
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
                fmode = int(stat.S_IFDIR | 0x1ff)
                fchmode = int(stat.S_IMODE(int(stat.S_IFDIR | 0x1ff)))
                ftypemod = int(stat.S_IFMT(int(stat.S_IFDIR | 0x1ff)))
            else:
                fmode = int(stat.S_IFREG | 0x1b6)
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
                fmode = int(stat.S_IFDIR | 0x1ff)
                fchmode = int(stat.S_IMODE(int(stat.S_IFDIR | 0x1ff)))
                ftypemod = int(stat.S_IFMT(int(stat.S_IFDIR | 0x1ff)))
            else:
                fmode = int(stat.S_IFREG | 0x1b6)
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
            except (KeyError, AttributeError):
                fuid = int(0)
            try:
                fgid = int(os.getgid())
            except (KeyError, AttributeError):
                fgid = int(0)
            try:
                import pwd
                try:
                    userinfo = pwd.getpwuid(os.getuid())
                    funame = userinfo.pw_name
                except (KeyError, AttributeError):
                    funame = ""
            except ImportError:
                funame = ""
            fgname = ""
            try:
                import grp
                try:
                    groupinfo = grp.getgrgid(os.getgid())
                    fgname = groupinfo.gr_name
                except (KeyError, AttributeError):
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
            logging.basicConfig(format="%(message)s", stream=PY_STDOUT_TEXT, level=logging.DEBUG)
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
                fpremode = int(stat.S_IFREG | 0x1b6)
            elif(member.is_symlink()):
                fpremode = int(stat.S_IFLNK | 0x1b6)
            elif(member.is_dir()):
                fpremode = int(stat.S_IFDIR | 0x1ff)
            if(is_windows and member.external_attr != 0):
                fwinattributes = int(member.external_attr)
            else:
                fwinattributes = int(0)
            if(is_unix and member.external_attr != 0):
                fmode = int(member.external_attr)
                fchmode = int(stat.S_IMODE(member.external_attr))
                ftypemod = int(stat.S_IFMT(member.external_attr))
            elif(member.is_file()):
                fmode = int(stat.S_IFREG | 0x1b6)
                fchmode = int(stat.S_IMODE(int(stat.S_IFREG | 0x1b6)))
                ftypemod = int(stat.S_IFMT(int(stat.S_IFREG | 0x1b6)))
            elif(member.is_symlink()):
                fmode = int(stat.S_IFLNK | 0x1b6)
                fchmode = int(stat.S_IMODE(int(stat.S_IFLNK | 0x1b6)))
                ftypemod = int(stat.S_IFMT(int(stat.S_IFLNK | 0x1b6)))
            elif(member.is_dir()):
                fmode = int(stat.S_IFDIR | 0x1ff)
                fchmode = int(stat.S_IMODE(int(stat.S_IFDIR | 0x1ff)))
                ftypemod = int(stat.S_IFMT(int(stat.S_IFDIR | 0x1ff)))
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
                except (KeyError, AttributeError):
                    fuid = int(0)
                try:
                    fgid = int(os.getgid())
                except (KeyError, AttributeError):
                    fgid = int(0)
                try:
                    import pwd
                    try:
                        userinfo = pwd.getpwuid(os.getuid())
                        funame = userinfo.pw_name
                    except (KeyError, AttributeError):
                        funame = ""
                except ImportError:
                    funame = ""
                fgname = ""
                try:
                    import grp
                    try:
                        groupinfo = grp.getgrgid(os.getgid())
                        fgname = groupinfo.gr_name
                    except (KeyError, AttributeError):
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
            logging.basicConfig(format="%(message)s", stream=PY_STDOUT_TEXT, level=logging.DEBUG)
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
                fpremode = int(stat.S_IFREG | 0x1b6)
            elif(member.is_directory):
                fpremode = int(stat.S_IFDIR | 0x1ff)
            fwinattributes = int(0)
            if(member.is_directory):
                fmode = int(stat.S_IFDIR | 0x1ff)
                fchmode = int(stat.S_IMODE(int(stat.S_IFDIR | 0x1ff)))
                ftypemod = int(stat.S_IFMT(int(stat.S_IFDIR | 0x1ff)))
            else:
                fmode = int(stat.S_IFLNK | 0x1b6)
                fchmode = int(stat.S_IMODE(int(stat.S_IFLNK | 0x1b6)))
                ftypemod = int(stat.S_IFMT(int(stat.S_IFLNK | 0x1b6)))
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
                except (KeyError, AttributeError):
                    fuid = int(0)
                try:
                    fgid = int(os.getgid())
                except (KeyError, AttributeError):
                    fgid = int(0)
                try:
                    import pwd
                    try:
                        userinfo = pwd.getpwuid(os.getuid())
                        funame = userinfo.pw_name
                    except (KeyError, AttributeError):
                        funame = ""
                except ImportError:
                    funame = ""
                fgname = ""
                try:
                    import grp
                    try:
                        groupinfo = grp.getgrgid(os.getgid())
                        fgname = groupinfo.gr_name
                    except (KeyError, AttributeError):
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
        logging.basicConfig(format="%(message)s", stream=PY_STDOUT_TEXT, level=logging.DEBUG)
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


def ListDirListFiles(infiles, dirlistfromtxt=False, compression="auto", compresswholefile=True, compressionlevel=None, followlink=False, seekstart=0, seekend=0, skipchecksum=False, checksumtype=["md5", "md5", "md5"], formatspecs=__file_format_dict__, seektoend=False, verbose=False, returnfp=False):
    outarray = MkTempFile()
    packform = PackCatFile(infiles, outarray, dirlistfromtxt, compression, compresswholefile,
                              compressionlevel, followlink, checksumtype, formatspecs, False, True)
    listarrayfiles = CatFileListFiles(
        outarray, seekstart, seekend, skipchecksum, formatspecs, seektoend, verbose, returnfp)
    return listarrayfiles

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
    except (socket.gaierror, socket.timeout):
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
    except (socket.gaierror, socket.timeout):
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
        shutil.copyfileobj(response.raw, httpfile, length=__filebuff_size__)

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
            shutil.copyfileobj(raw_wrapper, httpfile, length=__filebuff_size__)

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
        shutil.copyfileobj(response, httpfile, length=__filebuff_size__)

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
        shutil.copyfileobj(response, httpfile, length=__filebuff_size__)

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
        shutil.copyfileobj(fileobj, buf, length=__filebuff_size__)

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
        except (socket.gaierror, socket.timeout):
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
        except (socket.gaierror, socket.timeout):
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
        except (socket.gaierror, socket.timeout):
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
        except (socket.gaierror, socket.timeout):
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
      tcp://user:pass@0.0.0.0:5000/path/my.cat?
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
      udp://user:pass@0.0.0.0:5001/path/my.cat?
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
            p = urlparse(self.path or "/")
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
      tcp://user:pass@0.0.0.0:5000/path/my.cat?
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
      udp://user:pass@0.0.0.0:5001/path/my.cat?
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
