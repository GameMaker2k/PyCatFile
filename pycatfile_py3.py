#!/usr/bin/env python
# -*- coding: UTF-8 -*-

'''
    This program is free software; you can redistribute it and/or modify
    it under the terms of the Revised BSD License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Revised BSD License for more details.

    Copyright 2018-2026 Cool Dude 2k - http://idb.berlios.de/
    Copyright 2018-2026 Game Maker 2k - http://intdb.sourceforge.net/
    Copyright 2018-2026 Kazuki Przyborowski - https://github.com/KazukiPrzyborowski

    $FileInfo: pycatfile.py - Last Update: 2/3/2026 Ver. 0.28.0 RC 1 - Author: cooldude2k $
'''

import io
import os
import re
import sys
import ssl
import time
import stat
import mmap
import hmac
import base64
import shutil
import socket
import struct
import getpass
import hashlib
import inspect
import logging
import zipfile
import binascii
import datetime
import platform
import mimetypes
import collections
from io import open, StringIO, BytesIO
from typing import Any, Dict, Optional, Tuple, Union, BinaryIO, IO, Iterable, List, Mapping, Callable
import posixpath  # POSIX-safe joins/normpaths
try:
    from backports import tempfile
except ImportError:
    import tempfile

import threading

try:
    from mimetypes import guess_type
except ImportError:
    guess_type = None

try:
    from secrets import randbits
except Exception:
    def randbits(k):
        if k < 0:
            raise ValueError('number of bits must be non-negative')
        num_bytes = (k + 7) // 8
        raw_bytes = os.urandom(num_bytes)
        value = int.from_bytes(raw_bytes, 'big')
        return value >> (num_bytes * 8 - k)

# Optional Bluetooth RFCOMM support: works via stdlib on Linux (AF_BLUETOOTH/BTPROTO_RFCOMM)
# and via PyBluez if installed.
try:
    import bluetooth as _pybluez  # type: ignore
except Exception:
    _pybluez = None

defcert = None
try:
    import certifi
    defcert = certifi.where()
except ImportError:
    pass

import http.cookiejar as cookielib
from http.cookies import SimpleCookie
from http.client import HTTPException
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.error import URLError, HTTPError
from urllib.parse import urlparse, urlunparse, parse_qs, unquote, quote_from_bytes, unquote_to_bytes, urlencode
from urllib.request import Request, build_opener, HTTPBasicAuthHandler, HTTPCookieProcessor, HTTPHandler, HTTPSHandler, HTTPPasswordMgrWithDefaultRealm, install_opener, build_opener, url2pathname
import socketserver as _socketserver

try:
    # Python 3.8+ only
    from multiprocessing import shared_memory
except ImportError:
    shared_memory = None

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

import configparser

# --- Python 3-only compatibility helpers (Python 2 support removed) ---
from io import IOBase

# Legacy names kept for internal compatibility (Py3-only module)
basestring = str
unicode = str
long = int
file = IOBase
PY2 = False

text_type = str
bytes_type = bytes

# Text streams (as provided by Python)
PY_STDIN_TEXT  = sys.stdin
PY_STDOUT_TEXT = sys.stdout
PY_STDERR_TEXT = sys.stderr

# Binary-friendly streams
PY_STDIN_BUF  = sys.stdin.buffer
PY_STDOUT_BUF = sys.stdout.buffer
PY_STDERR_BUF = sys.stderr.buffer

# Type tuples for isinstance()
TEXT_TYPES   = (str,)
BINARY_TYPES = (bytes, bytearray, memoryview)
PATH_TYPES   = (str, os.PathLike)


def running_interactively():
    main = sys.modules.get("__main__")
    no_main_file = not hasattr(main, "__file__")
    interactive_flag = bool(getattr(sys.flags, "interactive", 0))
    return no_main_file or interactive_flag

if running_interactively():
    logging.basicConfig(format="%(message)s", stream=PY_STDOUT_TEXT, level=logging.DEBUG)

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
        if hasattr(os, "fspath"):
            fs = os.fspath(s)
            if isinstance(fs, text_type):
                return fs
            if isinstance(fs, (bytes_type, bytearray, memoryview)):
                return bytes(fs).decode(encoding, errors)
    except Exception:
        pass

    return text_type(s)

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

def to_text(s, encoding="utf-8", errors="ignore"):
    """Backward-compatible text coercion.

    Keeps legacy behavior: None -> "".
    Delegates to _to_text() for robust handling of bytes/path-like objects.
    """
    if s is None:
        return ""
    return _to_text(s, encoding=encoding, errors=errors)

baseint = []
try:
    baseint.append(long)
    baseint.insert(0, int)
except NameError:
    baseint.append(int)
baseint = tuple(baseint)


# Windows-specific setup
if os.name == "nt":
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

from io import UnsupportedOperation

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

haverequests = False
try:
    import requests
    haverequests = True
except Exception:
    pass

haveurllib3 = False
try:
    import urllib3
    haveurllib3 = True
except Exception:
    pass

havehttpx = False
try:
    import httpx
    havehttpx = True
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
except Exception:
    pass

havehttpcore = False
try:
    import httpcore
    havehttpcore = True
except ImportError:
    pass

havemechanize = False
try:
    import mechanize
    havemechanize = True
except Exception:
    pass

havepycurl = False
try:
    import pycurl
    havepycurl = True
except ImportError:
    pass

haveparamiko = False
try:
    import paramiko
    haveparamiko = True
except Exception:
    pass

havepysftp = False
try:
    import pysftp
    havepysftp = True
except Exception:
    pass


ftpssl = True
try:
    from ftplib import FTP, FTP_TLS, all_errors
except Exception:
    ftpssl = False
    from ftplib import FTP, all_errors


def get_importing_script_path():
    """Best-effort path of the importing (caller) script, or None."""
    for frame_info in inspect.stack():
        filename = frame_info.filename
        if filename != __file__:  # Ignore current module's file
            return os.path.abspath(filename)
    return None

def get_default_threads():
    """Return the number of CPU threads available, or 1 if unavailable."""
    n = os.cpu_count()
    return n if n is not None else 1

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

__upload_proto_support__ = "^(http|https|ftp|ftps|sftp|scp|tcp|udp|data|file|bt|rfcomm|bluetooth)://"
__download_proto_support__ = "^(http|https|ftp|ftps|sftp|scp|tcp|udp|data|file|bt|rfcomm|bluetooth)://"
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
def is_only_nonprintable(var) -> bool:
    """True if every character is non-printable (handles bytes via to_text)."""
    if var is None:
        return True
    s = to_text(var)
    return all(not ch.isprintable() for ch in s)

__file_format_multi_dict__ = {}
__file_format_default__ = "CatFile"
__include_defaults__ = True
__use_inmem__ = True
__use_memfd__ = True
__use_spoolfile__ = False
__use_spooldir__ = tempfile.gettempdir()
__use_new_style__ = True
__use_advanced_list__ = True
__use_alt_inode__ = False
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
if('PYARCHIVEFILE_CONFIG_FILE' in os.environ and os.path.exists(os.environ['PYARCHIVEFILE_CONFIG_FILE']) and __use_env_file__):
    scriptconf = os.environ['PYARCHIVEFILE_CONFIG_FILE']
else:
    prescriptpath = get_importing_script_path()
    if(prescriptpath is not None):
        if(__use_ini_file__ and not __use_json_file__):
            scriptconf = os.path.join(os.path.dirname(prescriptpath), __use_ini_name__)
        elif(__use_json_file__ and not __use_ini_file__):
            scriptconf = os.path.join(os.path.dirname(prescriptpath), __use_json_name__)
        else:
            scriptconf = ""
            prescriptpath = None
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
        """Decode INI/JSON escape sequences (Py3)."""
        if value is None:
            return ""
        if isinstance(value, (bytes, bytearray, memoryview)):
            value = bytes(value).decode('utf-8', 'replace')
        if not isinstance(value, str):
            value = str(value)
        return value.encode('utf-8').decode('unicode_escape')

    __file_format_default__ = decode_unicode_escape(config.get('config', 'default'))
    __program_name__ = decode_unicode_escape(config.get('config', 'proname'))
    __include_defaults__ = config.getboolean('config', 'includedef')
    __use_inmem__ = config.getboolean('config', 'useinmem')
    __use_memfd__ = config.getboolean('config', 'usememfd')
    __use_spoolfile__ = config.getboolean('config', 'usespoolfile')
    __spoolfile_size__ = config.getint('config', 'spoolfilesize')
    __use_new_style__ = config.getboolean('config', 'newstyle')
    __use_advanced_list__ = config.getboolean('config', 'advancedlist')
    __use_alt_inode__ = config.getboolean('config', 'altinode')
    # Loop through all sections
    for section in config.sections():
        if section == "config":
            continue

        required_keys = [
            "len", "hex", "ver", "name",
            "magic", "delimiter", "extension"
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
                'format_extension':   decode_unicode_escape(config.get(section, 'extension')),
            }
        })
        if not __file_format_multi_dict__ and not __include_defaults__:
            __include_defaults__ = True
elif __use_json_file__ and os.path.exists(__config_file__):
    # Prefer ujson/simplejson if available (you already have this import block above)
    with open(__config_file__, 'rb') as f:
        raw = f.read()

    # Ensure we get a text string for json.loads (Py3-only)
    text = raw.decode('utf-8', 'replace')
    cfg = json.loads(text)

    # --- helpers: coerce + decode like your INI path ---
    def decode_unicode_escape(value):
        """Decode INI/JSON escape sequences (Py3)."""
        if value is None:
            return ""
        if isinstance(value, (bytes, bytearray, memoryview)):
            value = bytes(value).decode('utf-8', 'replace')
        if not isinstance(value, str):
            value = str(value)
        return value.encode('utf-8').decode('unicode_escape')

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
    __use_new_style__       = _to_bool(_get(cfg_config, 'usespoolfile', True))
    __use_advanced_list__       = _to_bool(_get(cfg_config, 'usespoolfile', True))
    __use_alt_inode__       = _to_bool(_get(cfg_config, 'usespoolfile', False))

    # --- iterate format sections (everything except "config") ---
    required_keys = [
        "len", "hex", "ver", "name",
        "magic", "delimiter", "extension"
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
__file_format_extension__ = __file_format_multi_dict__[__file_format_default__]['format_extension']
__file_format_dict__ = __file_format_multi_dict__[__file_format_default__]
__project__ = __program_name__
__program_alt_name__ = __program_name__
__project_url__ = "https://github.com/GameMaker2k/PyCatFile"
__project_release_url__ = __project_url__+"/releases/latest"
__version_info__ = (0, 28, 0, "RC 1", 1)
__version_date_info__ = (2026, 2, 3, "RC 1", 1)
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

_logger = logging.getLogger(__project__)      # library-style logger
_logger.addHandler(logging.NullHandler())     # don't emit logs unless app configures logging

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
# Works across platforms

# Python interpreter bitness
PyBitness = "64" if struct.calcsize("P") * 8 == 64 else ("64" if sys.maxsize > 2**32 else "32")

# Operating system bitness
try:
    OSBitness = platform.architecture()[0].replace("bit", "")
except Exception:
    m = platform.machine().lower()
    OSBitness = "64" if "64" in m else "32"

geturls_cj = cookielib.CookieJar()
geturls_ua_pywwwget_python = "Mozilla/5.0 (compatible; {proname}/{prover}; +{prourl})".format(
    proname=__project__, prover=__version__, prourl=__project_url__)
if(platform.python_implementation() != ""):
    py_implementation = platform.python_implementation()
if(platform.python_implementation() == ""):
    py_implementation = "Python"
geturls_ua_pywwwget_python_alt = "Mozilla/5.0 ({osver}; {archtype}; +{prourl}) {pyimp}/{pyver} (KHTML, like Gecko) {proname}/{prover}".format(osver=platform.system(
)+" "+platform.release(), archtype=platform.machine(), prourl=__project_url__, pyimp=py_implementation, pyver=platform.python_version(), proname=__project__, prover=__version__)
geturls_ua_googlebot_google = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
geturls_ua_googlebot_google_old = "Googlebot/2.1 (+http://www.google.com/bot.html)"
geturls_headers_pywwwget_python = {'Referer': "http://google.com/", 'User-Agent': geturls_ua_pywwwget_python, 'Accept-Encoding': "none", 'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6", 'Accept-Charset': "ISO-8859-1,ISO-8859-15,utf-8;q=0.7,*;q=0.7", 'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'Connection': "close",
                                    'SEC-CH-UA': "\""+__project__+"\";v=\""+str(__version__)+"\", \"Not;A=Brand\";v=\"8\", \""+py_implementation+"\";v=\""+str(platform.release())+"\"", 'SEC-CH-UA-FULL-VERSION': str(__version__), 'SEC-CH-UA-PLATFORM': ""+py_implementation+"", 'SEC-CH-UA-ARCH': ""+platform.machine()+"", 'SEC-CH-UA-PLATFORM-VERSION': str(__version__), 'SEC-CH-UA-BITNESS': str(PyBitness)}
geturls_headers_pywwwget_python_alt = {'Referer': "http://google.com/", 'User-Agent': geturls_ua_pywwwget_python_alt, 'Accept-Encoding': "none", 'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6", 'Accept-Charset': "ISO-8859-1,ISO-8859-15,utf-8;q=0.7,*;q=0.7", 'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'Connection': "close",
                                        'SEC-CH-UA': "\""+__project__+"\";v=\""+str(__version__)+"\", \"Not;A=Brand\";v=\"8\", \""+py_implementation+"\";v=\""+str(platform.release())+"\"", 'SEC-CH-UA-FULL-VERSION': str(__version__), 'SEC-CH-UA-PLATFORM': ""+py_implementation+"", 'SEC-CH-UA-ARCH': ""+platform.machine()+"", 'SEC-CH-UA-PLATFORM-VERSION': str(__version__), 'SEC-CH-UA-BITNESS': str(PyBitness)}
geturls_headers_googlebot_google = {'Referer': "http://google.com/", 'User-Agent': geturls_ua_googlebot_google, 'Accept-Encoding': "none", 'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6",
                                    'Accept-Charset': "ISO-8859-1,ISO-8859-15,utf-8;q=0.7,*;q=0.7", 'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'Connection': "close"}
geturls_headers_googlebot_google_old = {'Referer': "http://google.com/", 'User-Agent': geturls_ua_googlebot_google_old, 'Accept-Encoding': "none", 'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6",
                                        'Accept-Charset': "ISO-8859-1,ISO-8859-15,utf-8;q=0.7,*;q=0.7", 'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'Connection': "close"}

compressionsupport = []
try:
    try:
        import compression.gzip as gzip
    except ImportError:
        import gzip
    compressionsupport.append("gz")
    compressionsupport.append("gzip")
except ImportError:
    pass
try:
    try:
        import compression.bz2 as bz2
    except ImportError:
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
    try:
        import compression.zstd as zstd
    except ImportError:
        import pyzstd.zstdfile as zstd
    compressionsupport.append("zst")
    compressionsupport.append("zstd")
    compressionsupport.append("zstandard")
except ImportError:
    pass
try:
    try:
        import compression.lzma as lzma
    except ImportError:
        try:
            import lzma
        except ImportError:
            from backports import lzma
    compressionsupport.append("lzma")
    compressionsupport.append("xz")
except ImportError:
    pass
try:
    try:
        import compression.zlib as zlib
    except ImportError:
        import zlib
    compressionsupport.append("zlib")
    compressionsupport.append("zl")
    compressionsupport.append("zz")
    compressionsupport.append("Z")
    compressionsupport.append("z")
except ImportError:
    pass
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
    Python 3-only logging switchboard.

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

def to_ns(timestamp):
    """
    Convert a second-resolution timestamp (int or float)
    into a nanosecond timestamp (int) by zero-padding.
    Works in Python 3.
    """
    try:
        # Convert incoming timestamp to float so it works for int or float
        seconds = float(timestamp)
    except (TypeError, ValueError):
        raise ValueError("Timestamp must be int or float")

    # Multiply by 1e9 to get nanoseconds, then cast to int
    return int(seconds * 1000000000)

def format_ns_utc(ts_ns, fmt='%Y-%m-%d %H:%M:%S'):
    ts_ns = int(ts_ns)
    sec, ns = divmod(ts_ns, 10**9)
    dt = datetime.datetime.utcfromtimestamp(sec).replace(microsecond=ns // 1000)
    base = dt.strftime(fmt)
    ns_str = "%09d" % ns
    return base + "." + ns_str

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
               memfd_name=__program_name__,
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

class SharedMemoryFile(object):
    """
    File-like wrapper around multiprocessing.shared_memory.SharedMemory.

    Binary-only API, intended to behave similarly to a regular file opened in
    'rb', 'wb', or 'r+b' modes (but backed by a fixed-size shared memory block).

    Notes:
      - Requires Python 3.8+ at runtime to actually use SharedMemory.
      - On Python 2, importing is fine but constructing will raise RuntimeError.
      - There is no automatic resizing; buffer size is fixed by SharedMemory.
      - No real fileno(); this does not represent an OS-level file descriptor.
      - For text mode, wrap this with io.TextIOWrapper on Python 3:
            f = SharedMemoryFile(...)
            tf = io.TextIOWrapper(f, encoding="utf-8")
    """

    def __init__(self, shm=None, name=None, create=False, size=0,
                 mode='r+b', offset=0, unlink_on_close=False):
        """
        Parameters:
          shm   : existing SharedMemory object (preferred).
          name  : name of shared memory block (for attach or create).
          create: if True, create new SharedMemory; else attach existing.
          size  : size in bytes (required when create=True).
          mode  : like 'rb', 'wb', 'r+b', 'ab' (binary only; 't' not supported).
          offset: starting offset within the shared memory buffer.
          unlink_on_close: if True, call shm.unlink() when close() is called.

        Usage examples:

            # Create new block and file-like wrapper
            f = SharedMemoryFile(name=None, create=True, size=4096, mode='r+b')

            # Attach to existing shared memory by name
            f = SharedMemoryFile(name="xyz", create=False, mode='r+b')

            # Wrap an existing SharedMemory object
            shm = shared_memory.SharedMemory(create=True, size=1024)
            f = SharedMemoryFile(shm=shm, mode='r+b')
        """
        if shared_memory is None:
            # No SharedMemory available on this interpreter
            raise RuntimeError("multiprocessing.shared_memory.SharedMemory "
                               "is not available on this Python version")

        if 't' in mode:
            raise ValueError("SharedMemoryFile is binary-only; "
                             "wrap it with io.TextIOWrapper for text")

        self.mode = mode
        self._closed = False
        self._unlinked = False
        self._unlink_on_close = bool(unlink_on_close)

        if shm is not None:
            self._shm = shm
        else:
            # name may be None when create=True
            self._shm = shared_memory.SharedMemory(name=name, create=create, size=size)

        self._buf = self._shm.buf
        self._base_offset = int(offset)
        if self._base_offset < 0 or self._base_offset > len(self._buf):
            raise ValueError("offset out of range")

        # We treat the accessible region as [base_offset, len(buf))
        self._size = len(self._buf) - self._base_offset
        self._pos = 0  # logical file position within that region

    # ---------- basic properties ----------

    @property
    def name(self):
        # SharedMemory name (may be None for anonymous)
        return getattr(self._shm, "name", None)

    @property
    def closed(self):
        return self._closed

    def readable(self):
        return ('r' in self.mode) or ('+' in self.mode)

    def writable(self):
        return any(ch in self.mode for ch in ('w', 'a', '+'))

    def seekable(self):
        return True

    # ---------- core helpers ----------

    def _check_closed(self):
        if self._closed:
            raise ValueError("I/O operation on closed SharedMemoryFile")

    def _clamp_pos(self, pos):
        if pos < 0:
            return 0
        if pos > self._size:
            return self._size
        return pos

    def _region_bounds(self):
        """Return (start, end) absolute indices into the SharedMemory buffer."""
        start = self._base_offset + self._pos
        end = self._base_offset + self._size
        return start, end

    # ---------- positioning ----------

    def seek(self, offset, whence=0):
        """
        Seek to a new file position.

        whence: 0 = from start, 1 = from current, 2 = from end.
        """
        self._check_closed()
        offset = int(offset)
        whence = int(whence)

        if whence == 0:   # from start
            new_pos = offset
        elif whence == 1: # from current
            new_pos = self._pos + offset
        elif whence == 2: # from end
            new_pos = self._size + offset
        else:
            raise ValueError("invalid whence (expected 0, 1, or 2)")

        self._pos = self._clamp_pos(new_pos)
        return self._pos

    def tell(self):
        return self._pos

    # ---------- reading ----------

    def read(self, size=-1):
        """
        Read up to 'size' bytes (or to EOF if size<0 or None).
        Returns bytes (py3) or str (py2).
        """
        self._check_closed()
        if not self.readable():
            raise IOError("SharedMemoryFile not opened for reading")

        if size is None or size < 0:
            size = self._size - self._pos
        else:
            size = int(size)
            if size < 0:
                size = 0

        if size == 0:
            return b'' if not PY2 else ''

        start, end_abs = self._region_bounds()
        available = end_abs - (self._base_offset + self._pos)
        if available <= 0:
            return b'' if not PY2 else ''

        size = min(size, available)

        abs_start = self._base_offset + self._pos
        abs_end = abs_start + size

        chunk = self._buf[abs_start:abs_end]
        if PY2:
            data = bytes(chunk)  # bytes() -> str in py2
        else:
            data = bytes(chunk)

        self._pos += len(data)
        return data

    def readline(self, size=-1):
        """
        Read a single line (ending with '\\n' or EOF).
        If size >= 0, at most that many bytes are returned.
        """
        self._check_closed()
        if not self.readable():
            raise IOError("SharedMemoryFile not opened for reading")

        # Determine maximum bytes we can scan
        start, end_abs = self._region_bounds()
        remaining = end_abs - (self._base_offset + self._pos)
        if remaining <= 0:
            return b'' if not PY2 else ''

        if size is not None and size >= 0:
            size = int(size)
            max_len = min(size, remaining)
        else:
            max_len = remaining

        abs_start = self._base_offset + self._pos
        abs_max = abs_start + max_len

        # Work on a local bytes slice for easy .find()
        if PY2:
            buf_bytes = bytes(self._buf[abs_start:abs_max])
        else:
            buf_bytes = bytes(self._buf[abs_start:abs_max])

        idx = buf_bytes.find(b'\n')
        if idx == -1:
            # No newline; read entire chunk
            line_bytes = buf_bytes
        else:
            line_bytes = buf_bytes[:idx + 1]

        self._pos += len(line_bytes)

        if PY2:
            return line_bytes  # already str
        return line_bytes

    def readinto(self, b):
        """
        Read bytes into a pre-allocated writable buffer (bytearray/memoryview).
        Returns number of bytes read.
        """
        self._check_closed()
        if not self.readable():
            raise IOError("SharedMemoryFile not opened for reading")

        # Normalize target buffer
        if isinstance(b, memoryview):
            mv = b
        else:
            mv = memoryview(b)

        size = len(mv)
        if size <= 0:
            return 0

        start, end_abs = self._region_bounds()
        remaining = end_abs - (self._base_offset + self._pos)
        if remaining <= 0:
            return 0

        size = min(size, remaining)

        abs_start = self._base_offset + self._pos
        abs_end = abs_start + size

        mv[:size] = self._buf[abs_start:abs_end]
        self._pos += size
        return size

    # ---------- writing ----------

    def write(self, data):
        """
        Write bytes-like object to the shared memory region.

        Returns number of bytes written. Will raise if not opened writable
        or if writing would overflow the fixed-size region.
        """
        self._check_closed()
        if not self.writable():
            raise IOError("SharedMemoryFile not opened for writing")

        if isinstance(data, memoryview):
            data = bytes(data)
        elif isinstance(data, bytearray):
            data = bytes(data)

        if not isinstance(data, binary_types):
            raise TypeError("write() expects a bytes-like object")

        data_len = len(data)
        if data_len == 0:
            return 0

        # Handle "append" semantics roughly: start from end on first write
        if 'a' in self.mode and self._pos == 0:
            # Move to logical end of region
            self._pos = self._size

        start, end_abs = self._region_bounds()
        remaining = end_abs - (self._base_offset + self._pos)
        if data_len > remaining:
            raise IOError("write would overflow SharedMemory region (need %d, have %d)"
                          % (data_len, remaining))

        abs_start = self._base_offset + self._pos
        abs_end = abs_start + data_len

        self._buf[abs_start:abs_end] = data
        self._pos += data_len
        return data_len

    def flush(self):
        """
        No-op for shared memory; provided for file-like compatibility.
        """
        self._check_closed()
        # nothing to flush

    # ---------- unlink / close / context manager ----------

    def unlink(self):
        """
        Unlink (destroy) the underlying shared memory block.

        After unlink(), new processes cannot attach via name.
        Existing attachments (including this one) can continue to use
        the memory until they close() it.

        This is idempotent: calling it more than once is safe.
        """
        if self._unlinked:
            return

        try:
            self._shm.unlink()
        except AttributeError:
            # Should not happen on normal Python 3.8+,
            # but keep a clear error if it does.
            raise RuntimeError("Underlying SharedMemory object "
                               "does not support unlink()")

        self._unlinked = True

    def close(self):
        if self._closed:
            return
        self._closed = True

        # Optionally unlink on close if requested
        if self._unlink_on_close and not self._unlinked:
            try:
                self.unlink()
            except Exception:
                # best-effort; close anyway
                pass

        try:
            self._shm.close()
        except Exception:
            pass

    def __enter__(self):
        self._check_closed()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    # ---------- iteration ----------

    def __iter__(self):
        return self

    def __next__(self):
        line = self.readline()
        if (not line) or len(line) == 0:
            raise StopIteration
        return line

    if PY2:
        next = __next__

    # ---------- misc helpers ----------

    def fileno(self):
        """
        There is no real OS-level file descriptor; raise OSError for APIs
        that require a fileno().
        """
        raise OSError("SharedMemoryFile does not have a real fileno()")

    def isatty(self):
        return False

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
    saltkeyval = None
    if(hasattr(saltkey, "read")):
        saltkeyval = skfp.read()
        if(not isinstance(saltkeyval, bytes) and sys.version_info[0] >= 3):
            saltkeyval = saltkeyval.encode("UTF-8")
    elif(isinstance(saltkey, bytes) and sys.version_info[0] >= 3):
        saltkeyval = saltkey
    elif(saltkey is not None and os.path.exists(saltkey)):
        with open(saltkey, "rb") as skfp:
            saltkeyval = skfp.read()
    else:
        saltkey = None
    if(saltkeyval is None):
        saltkey = None
    if CheckSumSupport(algo_key, hashlib_guaranteed):
        if(saltkey is None or saltkeyval is None):
            h = hashlib.new(algo_key, hdr_bytes)
        else:
            h = hmac.new(saltkeyval, hdr_bytes, digestmod=algo_key)
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
    saltkeyval = None
    if(hasattr(saltkey, "read")):
        saltkeyval = skfp.read()
        if(not isinstance(saltkeyval, bytes) and sys.version_info[0] >= 3):
            saltkeyval = saltkeyval.encode("UTF-8")
    elif(isinstance(saltkey, bytes) and sys.version_info[0] >= 3):
        saltkeyval = saltkey
    elif(saltkey is not None and os.path.exists(saltkey)):
        with open(saltkey, "rb") as skfp:
            saltkeyval = skfp.read()
    else:
        saltkey = None
    if(saltkeyval is None):
        saltkey = None
    # file-like streaming
    if hasattr(inbytes, "read"):
        # hashlib

        if CheckSumSupport(algo_key, hashlib_guaranteed):
            if(saltkey is None or saltkeyval is None):
                h = hashlib.new(algo_key)
            else:
                h = hmac.new(saltkeyval, digestmod=algo_key)
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
        if(saltkey is None or saltkeyval is None):
            h = hashlib.new(algo_key, data)
        else:
            h = hmac.new(saltkeyval, data, digestmod=algo_key)
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
    if(__use_new_style__):
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
    if(__use_new_style__):
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
    if((len(HeaderOut) - 4)>extraend):
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
    if(__use_new_style__):
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
    if((len(HeaderOut) - 4)>extraend):
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
    outlist = {'fheaders': [ftype, fencoding, fcencoding, fname, flinkname, fsize, fblksize, fblocks, fflags, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression,
               fcsize, fuid, funame, fgid, fgname, fid, finode, flinkcount, fdev, frdev, fseeknextfile], 'fextradata': fextrafieldslist, 'fjsoncontent': fjsoncontent, 'fcontents': fcontents, 'fjsonchecksumtype': fjsonchecksumtype, 'fheaderchecksumtype': HeaderOut[-4].lower(), 'fcontentchecksumtype': HeaderOut[-3].lower()}
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
    headeroffset = fp.tell()
    formstring = fp.read(formatspecs['format_len'] + len(inheaderver)).decode("UTF-8")
    formdelszie = len(formatspecs['format_delimiter'])
    formdel = fp.read(formdelszie).decode("UTF-8")
    if(formstring != formatspecs['format_magic']+inheaderver):
        return False
    if(formdel != formatspecs['format_delimiter']):
        return False
    if(__use_new_style__):
        inheader = ReadFileHeaderDataBySize(
            fp, formatspecs['format_delimiter'])
    else:
        inheader = ReadFileHeaderDataWoSize(
            fp, formatspecs['format_delimiter'])
    fprechecksumtype = inheader[-2]
    fprechecksum = inheader[-1]
    headercheck = ValidateHeaderChecksum([formstring] + inheader[:-1], fprechecksumtype, fprechecksum, formatspecs, saltkey)
    newfcs = GetHeaderChecksum([formstring] + inheader[:-1], fprechecksumtype, True, formatspecs, saltkey)
    if(not headercheck and not skipchecksum):
        VerbosePrintOut(
            "File Header Checksum Error with file at offset " + str(headeroffset))
        VerbosePrintOut("'" + fprechecksum + "' != " +
                        "'" + newfcs + "'")
        return False
    fnumfiles = int(inheader[8], 16)
    outfseeknextfile = inheaderdata[9]
    fjsonsize = int(inheaderdata[12], 16)
    fjsonchecksumtype = inheader[13]
    fjsonchecksum = inheader[14]
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
    headeroffset = fp.tell()
    formstring = fp.read(formatspecs['format_len'] + len(inheaderver)).decode("UTF-8")
    formdelszie = len(formatspecs['format_delimiter'])
    formdel = fp.read(formdelszie).decode("UTF-8")
    if(formstring != formatspecs['format_magic']+inheaderver):
        return False
    if(formdel != formatspecs['format_delimiter']):
        return False
    if(__use_new_style__):
        inheader = ReadFileHeaderDataBySize(
            fp, formatspecs['format_delimiter'])
    else:
        inheader = ReadFileHeaderDataWoSize(
            fp, formatspecs['format_delimiter'])
    fnumextrafieldsize = int(inheader[15], 16)
    fnumextrafields = int(inheader[16], 16)
    fextrafieldslist = []
    extrastart = 17
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
    fvendorfieldslist = []
    fvendorfields = 0;
    if((len(inheader) - 2)>extraend):
        extrastart = extraend
        extraend = len(inheader) - 2
        while(extrastart < extraend):
            fvendorfieldslist.append(HeaderOut[extrastart])
            extrastart = extrastart + 1
            fvendorfields = fvendorfields + 1
    formversion = re.findall("([\\d]+)", formstring)
    fheadsize = int(inheader[0], 16)
    fnumfields = int(inheader[1], 16)
    fheadctime = int(inheader[2], 16)
    fheadmtime = int(inheader[3], 16)
    fhencoding = inheader[4]
    fostype = inheader[5]
    fpythontype = inheader[6]
    fprojectname = inheader[7]
    fnumfiles = int(inheader[8], 16)
    fseeknextfile = inheader[9]
    fjsontype = inheader[10]
    fjsonlen = int(inheader[11], 16)
    fjsonsize = int(inheader[12], 16)
    fjsonchecksumtype = inheader[13]
    fjsonchecksum = inheader[14]
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
    headercheck = ValidateHeaderChecksum([formstring] + inheader[:-1], fprechecksumtype, fprechecksum, formatspecs, saltkey)
    newfcs = GetHeaderChecksum([formstring] + inheader[:-1], fprechecksumtype, True, formatspecs, saltkey)
    if(not headercheck and not skipchecksum):
        VerbosePrintOut(
            "File Header Checksum Error with file at offset " + str(headeroffset))
        VerbosePrintOut("'" + fprechecksum + "' != " +
                        "'" + newfcs + "'")
        return False
    formversions = re.search('(.*?)(\\d+)', formstring).groups()
    fcompresstype = ""
    outlist = {'fnumfiles': fnumfiles, 'ffilestart': filestart, 'fformat': formversions[0], 'fcompression': fcompresstype, 'fencoding': fhencoding, 'fmtime': fheadmtime, 'fctime': fheadctime, 'fversion': formversions[1], 'fostype': fostype, 'fprojectname': fprojectname, 'fimptype': fpythontype, 'fheadersize': fheadsize, 'fsize': CatSizeEnd, 'fnumfields': fnumfields + 2, 'fformatspecs': formatspecs, 'fseeknextfile': fseeknextfile, 'fchecksumtype': fprechecksumtype, 'fheaderchecksum': fprechecksum, 'fjsonchecksumtype': fjsonchecksumtype, 'fjsontype': fjsontype, 'fjsonlen': fjsonlen, 'fjsonsize': fjsonsize, 'fjsonrawdata': fjsonrawcontent, 'fjsondata': fjsoncontent, 'fjstart': fjstart, 'fjend': fjend, 'fjsonchecksum': fjsonchecksum, 'frawheader': [formstring] + inheader, 'fextrafields': fnumextrafields, 'fextrafieldsize': fnumextrafieldsize, 'fextradata': fextrafieldslist, 'fvendorfields': fvendorfields, 'fvendordata': fvendorfieldslist, 'ffilelist': []}
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
    headeroffset = fp.tell()
    formstring = fp.read(formatspecs['format_len'] + len(inheaderver)).decode("UTF-8")
    formdelszie = len(formatspecs['format_delimiter'])
    formdel = fp.read(formdelszie).decode("UTF-8")
    if(formstring != formatspecs['format_magic']+inheaderver):
        return False
    if(formdel != formatspecs['format_delimiter']):
        return False
    if(__use_new_style__):
        inheader = ReadFileHeaderDataBySize(
            fp, formatspecs['format_delimiter'])
    else:
        inheader = ReadFileHeaderDataWoSize(
            fp, formatspecs['format_delimiter'])
    fnumextrafieldsize = int(inheader[15], 16)
    fnumextrafields = int(inheader[16], 16)
    fextrafieldslist = []
    extrastart = 17
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
    fvendorfieldslist = []
    fvendorfields = 0;
    if((len(inheader) - 2)>extraend):
        extrastart = extraend
        extraend = len(inheader) - 2
        while(extrastart < extraend):
            fvendorfieldslist.append(HeaderOut[extrastart])
            extrastart = extrastart + 1
            fvendorfields = fvendorfields + 1
    formversion = re.findall("([\\d]+)", formstring)
    fheadsize = int(inheader[0], 16)
    fnumfields = int(inheader[1], 16)
    fheadctime = int(inheader[2], 16)
    fheadmtime = int(inheader[3], 16)
    fhencoding = inheader[4]
    fostype = inheader[5]
    fpythontype = inheader[6]
    fprojectname = inheader[7]
    fnumfiles = int(inheader[8], 16)
    fseeknextfile = inheader[9]
    fjsontype = inheader[10]
    fjsonlen = int(inheader[11], 16)
    fjsonsize = int(inheader[12], 16)
    fjsonchecksumtype = inheader[13]
    fjsonchecksum = inheader[14]
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
    headercheck = ValidateHeaderChecksum([formstring] + inheader[:-1], fprechecksumtype, fprechecksum, formatspecs, saltkey)
    newfcs = GetHeaderChecksum([formstring] + inheader[:-1], fprechecksumtype, True, formatspecs, saltkey)
    if(not headercheck and not skipchecksum):
        VerbosePrintOut(
            "File Header Checksum Error with file at offset " + str(headeroffset))
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
            if(__use_new_style__):
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

def system_and_major():
    info = platform.uname()

    # Python 3: info is a namedtuple with .system / .release
    # Python 2: info is a plain tuple (system, node, release, version, machine, processor)
    try:
        system = info.system
        release = info.release
    except AttributeError:
        # Fallback for Python 2
        system = info[0]
        release = info[2]

    # Find the first run of digits in the release string
    m = re.search(r'\d+', release)
    if m:
        major = m.group(0)  # e.g. '11' or '6'
        return u"%s%s" % (system, major)  # unicode-safe in Py2
    else:
        return system

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
    tmpoutlen = 10 + len(tmpoutlist) + len(xlist)
    tmpoutlenhex = _hex_lower(tmpoutlen)
    if(hasattr(time, "time_ns")):
        fctime = format(int(time.time_ns()), 'x').lower()
    else:
        fctime = format(int(to_ns(time.time())), 'x').lower()
    # Serialize the first group
    fnumfilesa = AppendNullBytes([tmpoutlenhex, fctime, fctime, fencoding, system_and_major(), py_implementation, __program_name__+str(__version_info__[0]), fnumfiles_hex, "+"+str(len(formatspecs['format_delimiter']))], delimiter)
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
    AppendFileHeader(fp, 0, "UTF-8", ['hello', 'goodbye'], {}, checksumtype, formatspecs, saltkey)
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

def AppendFilesWithContentToList(infiles, dirlistfromtxt=False, extradata=[], jsondata={}, contentasfile=False, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, followlink=False, checksumtype=["md5", "md5", "md5"], formatspecs=__file_format_dict__, saltkey=None, verbose=False):
    advancedlist = __use_advanced_list__
    altinode = __use_alt_inode__
    infilelist = []
    if(not dirlistfromtxt and not isinstance(infiles, (list, tuple, )) and infiles == "-"):
        for line in PY_STDIN_TEXT:
            infilelist.append(line.strip())
        infilelist = list(filter(None, infilelist))
    if(not dirlistfromtxt and isinstance(infiles, (list, tuple, )) and len(infiles)==1 and infiles[0] == "-"):
        for line in PY_STDIN_TEXT:
            infilelist.append(line.strip())
        infilelist = list(filter(None, infilelist))
    elif(dirlistfromtxt):
        if(not isinstance(infiles, (list, tuple, ))):
            infiles = [infiles]
        if(isinstance(infiles, (list, tuple, ))):
            for fileloc in infiles:
                if(fileloc == "-"):
                    for line in PY_STDIN_TEXT:
                        infilelist.append(line.strip())
                else:
                    if(not os.path.exists(fileloc) or not os.path.isfile(fileloc)):
                        return False
                    else:
                        with UncompressFile(fileloc, formatspecs, "r") as finfile:
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
    FullSizeFilesAlt = 0
    tmpoutlist = []
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
        if(hasattr(fstatinfo, "st_atime_ns")):
            fatime = format(int(fstatinfo.st_atime_ns), 'x').lower()
        else:
            fatime = format(int(to_ns(fstatinfo.st_atime)), 'x').lower()
        if(hasattr(fstatinfo, "st_mtime_ns")):
            fmtime = format(int(fstatinfo.st_mtime_ns), 'x').lower()
        else:
            fmtime = format(int(to_ns(fstatinfo.st_mtime)), 'x').lower()
        if(hasattr(fstatinfo, "st_ctime_ns")):
            fctime = format(int(fstatinfo.st_ctime_ns), 'x').lower()
        else:
            fctime = format(int(to_ns(fstatinfo.st_ctime)), 'x').lower()
        if(hasattr(fstatinfo, "st_birthtime")):
            if(hasattr(fstatinfo, "st_birthtime_ns")):
                fbtime = format(int(fstatinfo.st_birthtime_ns), 'x').lower()
            else:
                fbtime = format(int(to_ns(fstatinfo.st_birthtime)), 'x').lower()
        else:
            if(hasattr(fstatinfo, "st_ctime_ns")):
                fbtime = format(int(fstatinfo.st_ctime_ns), 'x').lower()
            else:
                fbtime = format(int(to_ns(fstatinfo.st_ctime)), 'x').lower()
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
                    typechecktest = GetBinaryFileType(fcontents, filestart=0, closefp=False)
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
                    typechecktest = GetBinaryFileType(fcontents, filestart=0, closefp=False)
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
        if(not contentasfile):
            fcontents = fcontents.read()
        ftypehex = format(ftype, 'x').lower()
        tmpoutlist.append({'fheaders': [ftypehex, fencoding, fcencoding, fname, flinkname, fsize, fblksize, fblocks, fflags, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression,
                           fcsize, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev, frdev, "+"+str(len(formatspecs['format_delimiter']))], 'fextradata': extradata, 'fjsoncontent': jsondata, 'fcontents': fcontents, 'fjsonchecksumtype': checksumtype[2], 'fheaderchecksumtype': checksumtype[0], 'fcontentchecksumtype': checksumtype[1]})
    return tmpoutlist

def AppendFilesWithContent(infiles, fp, dirlistfromtxt=False, extradata=[], jsondata={}, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, followlink=False, checksumtype=["md5", "md5", "md5", "md5", "md5"], formatspecs=__file_format_dict__, saltkey=None, verbose=False):
    GetDirList = AppendFilesWithContentToList(infiles, dirlistfromtxt, extradata, jsondata, False, compression, compresswholefile, compressionlevel, compressionuselist, followlink, [checksumtype[2], checksumtype[3], checksumtype[3]], formatspecs, saltkey, verbose)
    if(not hasattr(fp, "write")):
        return False
    numfiles = int(len(GetDirList))
    fnumfiles = format(numfiles, 'x').lower()
    AppendFileHeader(fp, numfiles, "UTF-8", [], {}, [checksumtype[0], checksumtype[1]], formatspecs, saltkey)
    try:
        fp.flush()
        if(hasattr(os, "sync")):
            os.fsync(fp.fileno())
    except (io.UnsupportedOperation, AttributeError, OSError):
        pass
    for curfname in GetDirList:
        tmpoutlist = curfname['fheaders']
        AppendFileHeaderWithContent(fp, tmpoutlist, curfname['fextradata'], curfname['fjsoncontent'], curfname['fcontents'], [curfname['fheaderchecksumtype'], curfname['fcontentchecksumtype'], curfname['fjsonchecksumtype']], formatspecs, saltkey)
        try:
            fp.flush()
            if(hasattr(os, "sync")):
                os.fsync(fp.fileno())
        except (io.UnsupportedOperation, AttributeError, OSError):
            pass
    return fp

def AppendFilesWithContentFromTarFileToList(infile, extradata=[], jsondata={}, contentasfile=False, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["md5", "md5", "md5"], formatspecs=__file_format_dict__, saltkey=None, verbose=False):
    curinode = 0
    curfid = 0
    inodelist = []
    inodetofile = {}
    filetoinode = {}
    inodetoforminode = {}
    if(isinstance(infile, (list, tuple, ))):
        infile = infile[0]
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
                if 'zstd' in compressionsupport:
                    infile = zstd.ZstdFile(infile, mode="rb")
                tarfp = tarfile.open(fileobj=infile, mode="r")
            else:
                tarfp = tarfile.open(fileobj=infile, mode="r")
        else:
            compresscheck = CheckCompressionType(infile, formatspecs, 0, True)
            if(IsNestedDict(formatspecs) and compresscheck in formatspecs):
                formatspecs = formatspecs[compresscheck]
            if(compresscheck=="zstd"):
                if 'zstd' in compressionsupport:
                    infile = zstd.ZstdFile(infile, mode="rb")
                tarfp = tarfile.open(fileobj=infile, mode="r")
            else:
                tarfp = tarfile.open(infile, "r")
    except FileNotFoundError:
        return False
    tmpoutlist = []
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
        fblocks = 0
        fflags = 0
        ftype = 0
        if(member.isreg() or member.isfile()):
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
        fatime = format(int(to_ns(member.mtime)), 'x').lower()
        fmtime = format(int(to_ns(member.mtime)), 'x').lower()
        fctime = format(int(to_ns(member.mtime)), 'x').lower()
        fbtime = format(int(to_ns(member.mtime)), 'x').lower()
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
                typechecktest = GetBinaryFileType(fcontents, filestart=0, closefp=False)
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
        if(not contentasfile):
            fcontents = fcontents.read()
        ftypehex = format(ftype, 'x').lower()
        tmpoutlist.append({'fheaders': [ftypehex, fencoding, fcencoding, fname, flinkname, fsize, fblksize, fblocks, fflags, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression,
                           fcsize, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev, frdev, "+"+str(len(formatspecs['format_delimiter']))], 'fextradata': extradata, 'fjsoncontent': jsondata, 'fcontents': fcontents, 'fjsonchecksumtype': checksumtype[2], 'fheaderchecksumtype': checksumtype[0], 'fcontentchecksumtype': checksumtype[1]})
    return tmpoutlist

def AppendFilesWithContentFromTarFile(infile, fp, extradata=[], jsondata={}, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["md5", "md5", "md5", "md5", "md5"], formatspecs=__file_format_dict__, saltkey=None, verbose=False):
    if(not hasattr(fp, "write")):
        return False
    GetDirList = AppendFilesWithContentFromTarFileToList(infile, extradata, jsondata, False, compression, compresswholefile, compressionlevel, compressionuselist, [checksumtype[2], checksumtype[3], checksumtype[3]], formatspecs, saltkey, verbose)
    numfiles = int(len(GetDirList))
    fnumfiles = format(numfiles, 'x').lower()
    AppendFileHeader(fp, numfiles, "UTF-8", [], {}, [checksumtype[0], checksumtype[1]], formatspecs, saltkey)
    try:
        fp.flush()
        if(hasattr(os, "sync")):
            os.fsync(fp.fileno())
    except (io.UnsupportedOperation, AttributeError, OSError):
        pass
    for curfname in GetDirList:
        tmpoutlist = curfname['fheaders']
        AppendFileHeaderWithContent(fp, tmpoutlist, curfname['fextradata'], curfname['fjsoncontent'], curfname['fcontents'], [curfname['fheaderchecksumtype'], curfname['fcontentchecksumtype'], curfname['fjsonchecksumtype']], formatspecs, saltkey)
        try:
            fp.flush()
            if(hasattr(os, "sync")):
                os.fsync(fp.fileno())
        except (io.UnsupportedOperation, AttributeError, OSError):
            pass
    return fp

def AppendFilesWithContentFromZipFileToList(infile, extradata=[], jsondata={}, contentasfile=False, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["md5", "md5", "md5", "md5", "md5"], formatspecs=__file_format_dict__, saltkey=None, verbose=False):
    curinode = 0
    curfid = 0
    inodelist = []
    inodetofile = {}
    filetoinode = {}
    inodetoforminode = {}
    if(isinstance(infile, (list, tuple, ))):
        infile = infile[0]
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
    tmpoutlist = []
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
        fblocks = 0
        fflags = 0
        ftype = 0
        if ((hasattr(member, "is_dir") and member.is_dir()) or member.filename.endswith('/')):
            ftype = 5
        elif ((hasattr(member, "symlink") and member.symlink())):
            ftype = 2
        else:
            ftype = 0
        flinkname = ""
        if(ftype==2):
            flinkname = zipfp.read(member.filename).decode("UTF-8")
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
            int(to_ns(time.mktime(member.date_time + (0, 0, -1)))), 'x').lower()
        fmtime = format(
            int(to_ns(time.mktime(member.date_time + (0, 0, -1)))), 'x').lower()
        fctime = format(
            int(to_ns(time.mktime(member.date_time + (0, 0, -1)))), 'x').lower()
        fbtime = format(
            int(to_ns(time.mktime(member.date_time + (0, 0, -1)))), 'x').lower()
        if(zipinfo.create_system == 0 or zipinfo.create_system == 10):
            fwinattributes = format(int(zipinfo.external_attr & 0xFFFF), 'x').lower()
            if ((hasattr(member, "is_dir") and member.is_dir()) or member.filename.endswith('/')):
                fmode = format(int(stat.S_IFDIR | 0x1ff), 'x').lower()
                fchmode = stat.S_IMODE(int(stat.S_IFDIR | 0x1ff))
                ftypemod = stat.S_IFMT(int(stat.S_IFDIR | 0x1ff))
            elif ((hasattr(member, "symlink") and member.symlink()) or member.filename.endswith('/')):
                fmode = format(int(stat.S_IFREG | 0x1b6), 'x').lower()
                fchmode = stat.S_IMODE(int(stat.S_IFREG | 0x1b6))
                ftypemod = stat.S_IFMT(int(stat.S_IFREG | 0x1b6))
            else:
                fmode = format(int(stat.S_IFREG | 0x1b6), 'x').lower()
                fchmode = stat.S_IMODE(int(stat.S_IFREG | 0x1b6))
                ftypemod = stat.S_IFMT(int(stat.S_IFREG | 0x1b6))
        elif(zipinfo.create_system == 3):
            fwinattributes = format(int(zipinfo.external_attr & 0xFFFF), 'x').lower()
            fmode = format(int((zipinfo.external_attr >> 16) & 0xFFFF), 'x').lower()
            prefmode = int((zipinfo.external_attr >> 16) & 0xFFFF)
            if(prefmode==0):
                fmode = 0
                prefmode = 0
            else:
                file_type = prefmode & 0xF000
                if(file_type not in (stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK)):
                    fmode = 0
                    prefmode = 0
                if((mode & 0x1FF) == 0):
                    fmode = 0
                    prefmode = 0
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
            if(typechecktest is not False):
                typechecktest = GetBinaryFileType(fcontents, filestart=0, closefp=False)
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
        if(not contentasfile):
            fcontents = fcontents.read()
        ftypehex = format(ftype, 'x').lower()
        tmpoutlist.append({'fheaders': [ftypehex, fencoding, fcencoding, fname, flinkname, fsize, fblksize, fblocks, fflags, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression,
                           fcsize, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev, frdev, "+"+str(len(formatspecs['format_delimiter']))], 'fextradata': extradata, 'fjsoncontent': jsondata, 'fcontents': fcontents, 'fjsonchecksumtype': checksumtype[2], 'fheaderchecksumtype': checksumtype[0], 'fcontentchecksumtype': checksumtype[1]})
    return tmpoutlist

def AppendFilesWithContentFromZipFile(infile, fp, extradata=[], jsondata={}, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["md5", "md5", "md5", "md5", "md5"], formatspecs=__file_format_dict__, saltkey=None, verbose=False):
    if(not hasattr(fp, "write")):
        return False
    GetDirList = AppendFilesWithContentFromZipFileToList(infile, extradata, jsondata, False, compression, compresswholefile, compressionlevel, compressionuselist, [checksumtype[2], checksumtype[3], checksumtype[3]], formatspecs, saltkey, verbose)
    numfiles = int(len(GetDirList))
    fnumfiles = format(numfiles, 'x').lower()
    AppendFileHeader(fp, numfiles, "UTF-8", [], {}, [checksumtype[0], checksumtype[1]], formatspecs, saltkey)
    try:
        fp.flush()
        if(hasattr(os, "sync")):
            os.fsync(fp.fileno())
    except (io.UnsupportedOperation, AttributeError, OSError):
        pass
    for curfname in GetDirList:
        tmpoutlist = curfname['fheaders']
        AppendFileHeaderWithContent(fp, tmpoutlist, curfname['fextradata'], curfname['fjsoncontent'], curfname['fcontents'], [curfname['fheaderchecksumtype'], curfname['fcontentchecksumtype'], curfname['fjsonchecksumtype']], formatspecs, saltkey)
        try:
            fp.flush()
            if(hasattr(os, "sync")):
                os.fsync(fp.fileno())
        except (io.UnsupportedOperation, AttributeError, OSError):
            pass
    return fp

if(not rarfile_support):
    def AppendFilesWithContentFromRarFileToList(infile, extradata=[], jsondata={}, contentasfile=False, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["md5", "md5", "md5"], formatspecs=__file_format_dict__, saltkey=None, verbose=False):
        return False
    def AppendFilesWithContentFromRarFile(infile, fp, extradata=[], jsondata={}, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["md5", "md5", "md5", "md5", "md5"], formatspecs=__file_format_dict__, saltkey=None, verbose=False):
        return False
else:
    def AppendFilesWithContentFromRarFileToList(infile, extradata=[], jsondata={}, contentasfile=False, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["md5", "md5", "md5"], formatspecs=__file_format_dict__, saltkey=None, verbose=False):
        curinode = 0
        curfid = 0
        inodelist = []
        inodetofile = {}
        filetoinode = {}
        inodetoforminode = {}
        if(isinstance(infile, (list, tuple, ))):
            infile = infile[0]
        if(not os.path.exists(infile) or not os.path.isfile(infile)):
            return False
        if(not rarfile.is_rarfile(infile) and not rarfile.is_rarfile_sfx(infile)):
            return False
        rarfp = rarfile.RarFile(infile, "r")
        rartest = rarfp.testrar()
        if(rartest):
            VerbosePrintOut("Bad file found!")
        tmpoutlist = []
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
            fblocks = 0
            fflags = 0
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
                    fatime = format(int(to_ns(member.atime.timestamp())), 'x').lower()
                else:
                    fatime = format(int(to_ns(member.mtime.timestamp())), 'x').lower()
            except AttributeError:
                fatime = format(int(to_ns(member.mtime.timestamp())), 'x').lower()
            fmtime = format(int(to_ns(member.mtime.timestamp())), 'x').lower()
            try:
                if(member.ctime):
                    fctime = format(int(to_ns(member.ctime.timestamp())), 'x').lower()
                else:
                    fctime = format(int(to_ns(member.mtime.timestamp())), 'x').lower()
            except AttributeError:
                fctime = format(int(to_ns(member.mtime.timestamp())), 'x').lower()
            fbtime = format(int(to_ns(member.mtime.timestamp())), 'x').lower()
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
                if(typechecktest is not False):
                    typechecktest = GetBinaryFileType(fcontents, filestart=0, closefp=False)
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
            if(not contentasfile):
                fcontents = fcontents.read()
            ftypehex = format(ftype, 'x').lower()
            tmpoutlist.append({'fheaders': [ftypehex, fencoding, fcencoding, fname, flinkname, fsize, fblksize, fblocks, fflags, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression,
                               fcsize, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev, frdev, "+"+str(len(formatspecs['format_delimiter']))], 'fextradata': extradata, 'fjsoncontent': jsondata, 'fcontents': fcontents, 'fjsonchecksumtype': checksumtype[2], 'fheaderchecksumtype': checksumtype[0], 'fcontentchecksumtype': checksumtype[1]})
        return tmpoutlist
    def AppendFilesWithContentFromRarFile(infile, fp, extradata=[], jsondata={}, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["md5", "md5", "md5", "md5", "md5"], formatspecs=__file_format_dict__, saltkey=None, verbose=False):
        if(not hasattr(fp, "write")):
            return False
        GetDirList = AppendFilesWithContentFromRarFileToList(infile, extradata, jsondata, False, compression, compresswholefile, compressionlevel, compressionuselist, [checksumtype[2], checksumtype[3], checksumtype[3]], formatspecs, saltkey, verbose)
        numfiles = int(len(GetDirList))
        fnumfiles = format(numfiles, 'x').lower()
        AppendFileHeader(fp, numfiles, "UTF-8", [], {}, [checksumtype[0], checksumtype[1]], formatspecs, saltkey)
        try:
            fp.flush()
            if(hasattr(os, "sync")):
                os.fsync(fp.fileno())
        except (io.UnsupportedOperation, AttributeError, OSError):
            pass
        for curfname in GetDirList:
            tmpoutlist = curfname['fheaders']
            AppendFileHeaderWithContent(fp, tmpoutlist, curfname['fextradata'], curfname['fjsoncontent'], curfname['fcontents'], [curfname['fheaderchecksumtype'], curfname['fcontentchecksumtype'], curfname['fjsonchecksumtype']], formatspecs, saltkey)
            try:
                fp.flush()
                if(hasattr(os, "sync")):
                    os.fsync(fp.fileno())
            except (io.UnsupportedOperation, AttributeError, OSError):
                pass
        return fp

if(not py7zr_support):
    def sevenzip_readall(infile, **kwargs):
        return False
else:
    class _MemoryIO(py7zr.Py7zIO):
        """In-memory file object used by py7zr's factory API."""
        def __init__(self):
            self._buf = bytearray()
        def write(self, data):
            # py7zr will call this repeatedly with chunks
            self._buf.extend(data)
        def read(self, size=None):
            if size is None:
                return bytes(self._buf)
            return bytes(self._buf[:size])
        def seek(self, offset, whence=0):
            # we don't really need seeking for your use case
            return 0
        def flush(self):
            pass
        def size(self):
            return len(self._buf)
    class _MemoryFactory(py7zr.WriterFactory):
        """Factory that creates _MemoryIO objects and keeps them by filename."""
        def __init__(self):
            self.files = {}
        def create(self, filename: str) -> py7zr.Py7zIO:
            io_obj = _MemoryIO()
            self.files[filename] = io_obj
            return io_obj
    def sevenzip_readall(infile, **kwargs):
        """
        Replacement for SevenZipFile.readall() using the new py7zr API.

        Returns: dict[filename -> _MemoryIO]
        """
        factory = _MemoryFactory()
        with py7zr.SevenZipFile(infile, mode="r", **kwargs) as archive:
            archive.extractall(factory=factory)
        return factory.files

if(not py7zr_support):
    def AppendFilesWithContentFromSevenZipFileToList(infile, extradata=[], jsondata={}, contentasfile=False, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["md5", "md5", "md5"], formatspecs=__file_format_dict__, saltkey=None, verbose=False):
        return False
    def AppendFilesWithContentFromSevenZipFile(infile, fp, extradata=[], jsondata={}, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["md5", "md5", "md5", "md5", "md5"], formatspecs=__file_format_dict__, saltkey=None, verbose=False):
        return False
else:
    def AppendFilesWithContentFromSevenZipFileToList(infile, extradata=[], jsondata={}, contentasfile=False, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["md5", "md5", "md5"], formatspecs=__file_format_dict__, saltkey=None, verbose=False):
        formver = formatspecs['format_ver']
        fileheaderver = str(int(formver.replace(".", "")))
        curinode = 0
        curfid = 0
        inodelist = []
        inodetofile = {}
        filetoinode = {}
        inodetoforminode = {}
        if(isinstance(infile, (list, tuple, ))):
            infile = infile[0]
        if(not os.path.exists(infile) or not os.path.isfile(infile)):
            return False
        szpfp = py7zr.SevenZipFile(infile, mode="r")
        try:
            file_content = szpfp.readall()
        except AttributeError:
            file_content = sevenzip_readall(infile)
        #sztest = szpfp.testzip()
        sztestalt = szpfp.test()
        if(sztestalt):
            VerbosePrintOut("Bad file found!")
        tmpoutlist = []
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
            try:
                fwinattributes = format(int(member.attributes & 0xFFFF), 'x').lower()
            except AttributeError:
                fwinattributes = format(int(0), 'x').lower()
            fcompression = ""
            fcsize = format(int(0), 'x').lower()
            flinkcount = 0
            fblksize = 0
            fblocks = 0
            fflags = 0
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
            fatime = format(int(to_ns(member.creationtime.timestamp())), 'x').lower()
            fmtime = format(int(to_ns(member.creationtime.timestamp())), 'x').lower()
            fctime = format(int(to_ns(member.creationtime.timestamp())), 'x').lower()
            fbtime = format(int(to_ns(member.creationtime.timestamp())), 'x').lower()
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
                ffullmode = member.posix_mode
                fmode = format(int(ffullmode), 'x').lower()
                fchmode = format(int(stat.S_IMODE(ffullmode)), 'x').lower()
                ftypemod = format(int(stat.S_IFMT(ffullmode)), 'x').lower()
            except AttributeError:
                pass
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
                if(typechecktest is not False):
                    typechecktest = GetBinaryFileType(fcontents, filestart=0, closefp=False)
                    fcontents.seek(0, 0)
                fcencoding = GetFileEncoding(fcontents, 0, False)[0]
                try:
                    file_content[member.filename].close()
                except AttributeError:
                    pass
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
            if(not contentasfile):
                fcontents = fcontents.read()
            ftypehex = format(ftype, 'x').lower()
            tmpoutlist.append({'fheaders': [ftypehex, fencoding, fcencoding, fname, flinkname, fsize, fblksize, fblocks, fflags, fatime, fmtime, fctime, fbtime, fmode, fwinattributes, fcompression,
                               fcsize, fuid, funame, fgid, fgname, fcurfid, fcurinode, flinkcount, fdev, frdev, "+"+str(len(formatspecs['format_delimiter']))], 'fextradata': extradata, 'fjsoncontent': jsondata, 'fcontents': fcontents, 'fjsonchecksumtype': checksumtype[2], 'fheaderchecksumtype': checksumtype[0], 'fcontentchecksumtype': checksumtype[1]})
        return tmpoutlist
    def AppendFilesWithContentFromSevenZipFile(infile, fp, extradata=[], jsondata={}, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["md5", "md5", "md5", "md5", "md5"], formatspecs=__file_format_dict__, saltkey=None, verbose=False):
        if(not hasattr(fp, "write")):
            return False
        GetDirList = AppendFilesWithContentFromSevenZipFileToList(infile, extradata, jsondata, False, compression, compresswholefile, compressionlevel, compressionuselist, [checksumtype[2], checksumtype[3], checksumtype[3]], formatspecs, saltkey, verbose)
        numfiles = int(len(GetDirList))
        fnumfiles = format(numfiles, 'x').lower()
        AppendFileHeader(fp, numfiles, "UTF-8", [], {}, [checksumtype[0], checksumtype[1]], formatspecs, saltkey)
        try:
            fp.flush()
            if(hasattr(os, "sync")):
                os.fsync(fp.fileno())
        except (io.UnsupportedOperation, AttributeError, OSError):
            pass
        for curfname in GetDirList:
            tmpoutlist = curfname['fheaders']
            AppendFileHeaderWithContent(fp, tmpoutlist, curfname['fextradata'], curfname['fjsoncontent'], curfname['fcontents'], [curfname['fheaderchecksumtype'], curfname['fcontentchecksumtype'], curfname['fjsonchecksumtype']], formatspecs, saltkey)
            try:
                fp.flush()
                if(hasattr(os, "sync")):
                    os.fsync(fp.fileno())
            except (io.UnsupportedOperation, AttributeError, OSError):
                pass
        return fp

def AppendListsWithContent(inlist, fp, dirlistfromtxt=False, extradata=[], jsondata={}, compression="auto", compresswholefile=True, compressionlevel=None, followlink=False, checksumtype=["md5", "md5", "md5", "md5", "md5"], formatspecs=__file_format_dict__, saltkey=None, verbose=False):
    if(not hasattr(fp, "write")):
        return False
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
    AppendFileHeader(fp, numfiles, "UTF-8", [], [checksumtype[0], checksumtype[1]], formatspecs, saltkey)
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

def AppendReadInFileWithContentToList(infile, extradata=[], jsondata={}, contentasfile=False, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["md5", "md5", "md5"], formatspecs=__file_format_multi_dict__, saltkey=None, verbose=False):
    return ReadInFileWithContentToList(infile, "auto", 0, 0, 0, False, contentasfile, uncompress, skipchecksum, formatspecs, saltkey, seektoend)

def AppendReadInMultipleFileWithContentToList(infile, extradata=[], jsondata={}, contentasfile=False, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["md5", "md5", "md5"], formatspecs=__file_format_multi_dict__, saltkey=None, verbose=False):
    return ReadInMultipleFileWithContentToList(infile, fmttype, 0, 0, 0, False, contentasfile, uncompress, skipchecksum, formatspecs, saltkey, seektoend)

def AppendReadInMultipleFilesWithContentToList(infile, extradata=[], jsondata={}, contentasfile=False, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["md5", "md5", "md5"], formatspecs=__file_format_multi_dict__, saltkey=None, verbose=False):
    return ReadInMultipleFilesWithContentToList(infile, fmttype, 0, 0, 0, False, contentasfile, uncompress, skipchecksum, formatspecs, saltkey, seektoend)

def AppendReadInFileWithContent(infile, fp, extradata=[], jsondata={}, compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, checksumtype=["md5", "md5", "md5", "md5", "md5"], formatspecs=__file_format_multi_dict__, insaltkey=None, outsaltkey=None, verbose=False):
    if(not hasattr(fp, "write")):
        return False
    GetDirList = AppendReadInFileWithContentToList(infile, extradata, jsondata, False, compression, compresswholefile, compressionlevel, compressionuselist, [checksumtype[2], checksumtype[3], checksumtype[3]], formatspecs, insaltkey, verbose)
    numfiles = int(len(GetDirList))
    fnumfiles = format(numfiles, 'x').lower()
    AppendFileHeader(fp, numfiles, "UTF-8", [], {}, [checksumtype[0], checksumtype[1]], formatspecs, outsaltkey)
    try:
        fp.flush()
        if(hasattr(os, "sync")):
            os.fsync(fp.fileno())
    except (io.UnsupportedOperation, AttributeError, OSError):
        pass
    for curfname in GetDirList:
        tmpoutlist = curfname['fheaders']
        AppendFileHeaderWithContent(fp, tmpoutlist, curfname['fextradata'], curfname['fjsoncontent'], curfname['fcontents'], [curfname['fheaderchecksumtype'], curfname['fcontentchecksumtype'], curfname['fjsonchecksumtype']], formatspecs, outsaltkey)
        try:
            fp.flush()
            if(hasattr(os, "sync")):
                os.fsync(fp.fileno())
        except (io.UnsupportedOperation, AttributeError, OSError):
            pass
    return fp

def AppendReadInFileWithContentToOutFile(infiles, outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, extradata=[], jsondata={}, checksumtype=["md5", "md5", "md5", "md5", "md5"], formatspecs=__file_format_multi_dict__, insaltkey=None, outsaltkey=None, verbose=False, returnfp=False):
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
    AppendReadInFileWithContent(infiles, fp, extradata, jsondata, compression, compresswholefile, compressionlevel, compressionuselist, checksumtype, formatspecs, insaltkey, outsaltkey, verbose)
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

def AppendReadInFileWithContentToStackedOutFile(infiles, outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, extradata=[], jsondata={}, checksumtype=["md5", "md5", "md5", "md5", "md5"], formatspecs=__file_format_multi_dict__, insaltkey=None, outsaltkey=None, verbose=False, returnfp=False):
    if not isinstance(infiles, list):
        infiles = [infiles]
    returnout = False
    for infileslist in infiles:
        returnout = AppendReadInFileWithContentToOutFile(infileslist, outfile, fmttype, compression, compresswholefile, compressionlevel, compressionuselist, extradata, jsondata, checksumtype, formatspecs, insaltkey, outsaltkey, verbose, True)
        if(not returnout):
            break
        else:
            outfile = returnout
    if(not returnfp and returnout):
        returnout.close()
        return True
    return returnout

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
    if(not compresscheck and isinstance(infile, (str, bytes, os.PathLike))):
        fextname = os.path.splitext(infile)[1]
        if(fextname == ".gz"):
            compresscheck = "gzip"
        elif(fextname == ".bz2"):
            compresscheck = "bzip2"
        elif(fextname == ".zst"):
            compresscheck = "zstd"
        elif(fextname == ".lz4"):
            compresscheck = "lz4"
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
                if 'zstd' in compressionsupport:
                    fp = zstd.ZstdFile(infile, mode="rb")
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
        if 'zstd' in compressionsupport:
            wrapped = zstd.ZstdFile(src, mode="rb")
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
            if 'zstd' in compressionsupport:
                fp = zstd.ZstdFile(infile, mode=mode)
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
            if 'zstd' in compressionsupport:
                outfp = FileLikeAdapter(zstd.ZstdFile(outfile, mode=mode, level=compressionlevel), mode="wb")
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
            elif(fextname == ".lz4"):
                compresscheck = "lz4"
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
    headeroffset = fp.tell()
    formstring = fp.read(formatspecs['format_len'] + len(inheaderver)).decode("UTF-8")
    formdelsize = len(formatspecs['format_delimiter'])
    formdel = fp.read(formdelsize).decode("UTF-8")
    if(formstring != formatspecs['format_magic'] + inheaderver):
        return False
    if(formdel != formatspecs['format_delimiter']):
        return False
    if(__use_new_style__):
        inheader = ReadFileHeaderDataBySize(fp, formatspecs['format_delimiter'])
    else:
        inheader = ReadFileHeaderDataWoSize(fp, formatspecs['format_delimiter'])
    fnumextrafieldsize = int(inheader[15], 16)
    fnumextrafields = int(inheader[16], 16)
    extrastart = 17
    extraend = extrastart + fnumextrafields
    formversion = re.findall("([\\d]+)", formstring)
    fheadsize = int(inheader[0], 16)
    fnumfields = int(inheader[1], 16)
    fnumfiles = int(inheader[8], 16)
    fprechecksumtype = inheader[-2]
    fprechecksum = inheader[-1]
    outfseeknextfile = inheader[9]
    fjsonsize = int(inheader[12], 16)
    fjsonchecksumtype = inheader[13]
    fjsonchecksum = inheader[14]
    headerjsonoffset = fp.tell()
    fprejsoncontent = fp.read(fjsonsize)
    jsonfcs = GetFileChecksum(fprejsoncontent, fjsonchecksumtype, True, formatspecs, saltkey)
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
    headercheck = ValidateHeaderChecksum([formstring] + inheader[:-1], fprechecksumtype, fprechecksum, formatspecs, saltkey)
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
            VerbosePrintOut("File Header Checksum Passed at offset " + str(headeroffset))
            VerbosePrintOut("'" + fprechecksum + "' == " + "'" + newfcs + "'")
    else:
        # always flip flags, even when not verbose
        valid_archive = False
        invalid_archive = True
        if(verbose):
            VerbosePrintOut("File Header Checksum Failed at offset " + str(headeroffset))
            VerbosePrintOut("'" + fprechecksum + "' != " + "'" + newfcs + "'")
    if(fjsonsize > 0):
        if(CheckChecksums(jsonfcs, fjsonchecksum)):
            if(verbose):
                VerbosePrintOut("File JSON Data Checksum Passed at offset " + str(headerjsonoffset))
                VerbosePrintOut("'" + outfjsonchecksum + "' == " + "'" + injsonfcs + "'")
        else:
            valid_archive = False
            invalid_archive = True
            if(verbose):
                VerbosePrintOut("File JSON Data Checksum Error at offset " + str(headerjsonoffset))
                VerbosePrintOut("'" + outfjsonchecksum + "' != " + "'" + injsonfcs + "'")
    if(verbose):
        VerbosePrintOut("")
    # Iterate either until EOF (seektoend) or fixed count
    while (fp.tell() < CatSizeEnd) if seektoend else (il < fnumfiles):
        outfhstart = fp.tell()
        if(__use_new_style__):
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
            return False
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


def RePackCatFile(infile, outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt,  followlink=False, filestart=0, seekstart=0, seekend=0, checksumtype=["md5", "md5", "md5", "md5", "md5"], skipchecksum=False, extradata=[], jsondata={}, formatspecs=__file_format_multi_dict__, insaltkey=None, outsaltkey=None, seektoend=False, verbose=False, returnfp=False):
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
            False, True, True, skipchecksum, formatspecs, insaltkey, seektoend, False
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

        AppendFileHeader(fp, fnumfiles, listarrayfiles.get('fencoding', 'utf-8'), listarrayfiles['fextradata'], listarrayfiles['fjsondata'], [checksumtype[0], checksumtype[1]], formatspecs, outsaltkey)

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
            frdev           = format(int(cur_entry['frdev']), 'x').lower()
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

            fcontents.seek(0, 0)
            if(typechecktest is not False):
                typechecktest = GetBinaryFileType(fcontents, filestart=0, closefp=False)
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
                            cfcontents,
                            compressionuselist[ilmin],
                            compressionlevel,
                            compressionuselist,
                            formatspecs
                        )
                        if cfcontents:
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
                    cfcontents,
                    curcompression,
                    compressionlevel,
                    compressionuselist,
                    formatspecs
                )
                cfcontents.seek(0, 2)
                cfsize = cfcontents.tell()
                if ucfsize > cfsize:
                    fcsize = format(int(cfsize), 'x').lower()
                    fcompression = curcompression
                    fcontents.close()
                    fcontents = cfcontents

            if fcompression == "none":
                fcompression = ""
            fcontents.seek(0, 0)

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
                    frdev           = format(int(flinkinfo['frdev']), 'x').lower()
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
                fgid, fgname, fcurfid, fcurinode, flinkcount, fdev, frdev, fseeknextfile
            ]

            if(fvendorfields>0 and len(ffvendorfieldslist)>0):
                extradata.extend(fvendorfields)
            
            AppendFileHeaderWithContent(fp, tmpoutlist, extradata, jsondata, fcontents.read(),[checksumtype[2], checksumtype[3], checksumtype[4]], formatspecs, outsaltkey)
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

def RePackMultipleCatFile(infiles, outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt,  followlink=False, filestart=0, seekstart=0, seekend=0, checksumtype=["md5", "md5", "md5", "md5", "md5"], skipchecksum=False, extradata=[], jsondata={}, formatspecs=__file_format_multi_dict__, insaltkey=None, outsaltkey=None, seektoend=False, verbose=False, returnfp=False):
    if not isinstance(infiles, list):
        infiles = [infiles]
    returnout = False
    for infileslist in infiles:
        returnout = RePackCatFile(infileslist, outfile, fmttype, compression, compresswholefile, compressionlevel, compressionuselist, followlink, filestart, seekstart, seekend, checksumtype, skipchecksum, extradata, jsondata, formatspecs, insaltkey, outsaltkey, seektoend, verbose, True)
        if(not returnout):
            break
        else:
            outfile = returnout
    if(not returnfp and returnout):
        returnout.close()
        return True
    return returnout

def RePackCatFileFromString(instr, outfile, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, followlink=False, filestart=0, seekstart=0, seekend=0, checksumtype=["md5", "md5", "md5", "md5", "md5"], skipchecksum=False, extradata=[], jsondata={}, formatspecs=__file_format_multi_dict__, insaltkey=None, outsaltkey=None, seektoend=False, verbose=False, returnfp=False):
    fp = MkTempFile(instr)
    listarrayfiles = RePackCatFile(fp, outfile, fmttype, compression, compresswholefile, compressionlevel, compressionuselist, followlink, filestart, seekstart, seekend, checksumtype, skipchecksum, extradata, jsondata, formatspecs, insaltkey, outsaltkey, seektoend, verbose, returnfp)
    return listarrayfiles


def PackCatFileFromListDir(infiles, outfile, dirlistfromtxt=False, fmttype="auto", compression="auto", compresswholefile=True, compressionlevel=None, compressionuselist=compressionlistalt, followlink=False, filestart=0, seekstart=0, seekend=0, checksumtype=["md5", "md5", "md5", "md5", "md5"], skipchecksum=False, extradata=[], jsondata={}, formatspecs=__file_format_dict__, saltkey=None, seektoend=False, verbose=False, returnfp=False):
    outarray = MkTempFile()
    packform = PackCatFile(infiles, outarray, dirlistfromtxt, fmttype, compression, compresswholefile, compressionlevel, compressionuselist, followlink, checksumtype, extradata, formatspecs, saltkey, verbose, True)
    listarrayfiles = RePackCatFile(outarray, outfile, fmttype, compression, compresswholefile, compressionlevel, compressionuselist, followlink, filestart, seekstart, seekend, checksumtype, skipchecksum, extradata, jsondata, formatspecs, saltkey, seektoend, verbose, returnfp)
    return listarrayfiles


def UnPackCatFile(infile, outdir=None, followlink=False, filestart=0, seekstart=0, seekend=0, skipchecksum=False, formatspecs=__file_format_multi_dict__, saltkey=None, preservepermissions=True, preservetime=True, seektoend=False, verbose=False, returnfp=False):
    if(outdir is not None):
        outdir = RemoveWindowsPath(outdir)
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
                    ts_ns = listarrayfiles['ffilelist'][lcfi]['fmtime']
                    sec, ns = divmod(int(ts_ns), 10**9)
                    dt = datetime.datetime.utcfromtimestamp(sec).replace(microsecond=ns // 1000)
                    VerbosePrintOut(PrintPermissionString(listarrayfiles['ffilelist'][lcfi]['fmode'], listarrayfiles['ffilelist'][lcfi]['ftype']) + " " + str(fuprint) + "/" + str(fgprint) + " " + str(
                    listarrayfiles['ffilelist'][lcfi]['fsize']).rjust(15) + " " + dt.strftime('%Y-%m-%d %H:%M') + " " + printfname)
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
            return False
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


def TarFileListFiles(infile, formatspecs=__file_format_multi_dict__, verbose=False, returnfp=False):
    if(isinstance(infile, (list, tuple, ))):
        infile = infile[0]
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
                if 'zstd' in compressionsupport:
                    infile = zstd.ZstdFile(infile, mode="rb")
                tarfp = tarfile.open(fileobj=infile, mode="r")
            else:
                tarfp = tarfile.open(fileobj=infile, mode="r")
        else:
            compresscheck = CheckCompressionType(infile, formatspecs, 0, True)
            if(IsNestedDict(formatspecs) and compresscheck in formatspecs):
                formatspecs = formatspecs[compresscheck]
            if(compresscheck=="zstd"):
                if 'zstd' in compressionsupport:
                    infile = zstd.ZstdFile(infile, mode="rb")
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
        if(member.isreg() or member.isfile()):
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


def TarFileListFile(infile, formatspecs=__file_format_multi_dict__, verbose=False, returnfp=False):
    return TarFileListFiles(infile, formatspecs, verbose, returnfp)


def ZipFileListFiles(infile, verbose=False, returnfp=False):
    if(isinstance(infile, (list, tuple, ))):
        infile = infile[0]
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
            fwinattributes = int(zipinfo.external_attr & 0xFFFF)
            if ((hasattr(member, "is_dir") and member.is_dir()) or member.filename.endswith('/')):
                fmode = int(stat.S_IFDIR | 0x1ff)
                fchmode = stat.S_IMODE(int(stat.S_IFDIR | 0x1ff))
                ftypemod = stat.S_IFMT(int(stat.S_IFDIR | 0x1ff))
            elif ((hasattr(member, "symlink") and member.symlink()) or member.filename.endswith('/')):
                fmode = int(stat.S_IFREG | 0x1b6)
                fchmode = stat.S_IMODE(int(stat.S_IFREG | 0x1b6))
                ftypemod = stat.S_IFMT(int(stat.S_IFREG | 0x1b6))
            else:
                fmode = int(stat.S_IFREG | 0x1b6)
                fchmode = stat.S_IMODE(int(stat.S_IFREG | 0x1b6))
                ftypemod = stat.S_IFMT(int(stat.S_IFREG | 0x1b6))
        elif(zipinfo.create_system == 3):
            fwinattributes = int(zipinfo.external_attr & 0xFFFF)
            fmode = int((zipinfo.external_attr >> 16) & 0xFFFF)
            prefmode = int((zipinfo.external_attr >> 16) & 0xFFFF)
            if(prefmode==0):
                fmode = 0
                prefmode = 0
            else:
                file_type = prefmode & 0xF000
                if(file_type not in (stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK)):
                    fmode = 0
                    prefmode = 0
                if((mode & 0x1FF) == 0):
                    fmode = 0
                    prefmode = 0
            if (prefmode == 0):
                if ((hasattr(member, "is_dir") and member.is_dir()) or member.filename.endswith('/')):
                    fmode = int(stat.S_IFDIR | 0x1ff)
                    prefmode = int(stat.S_IFDIR | 0x1ff)
                    fchmode = stat.S_IMODE(prefmode)
                    ftypemod = stat.S_IFMT(prefmode)
                else:
                    fmode = int(stat.S_IFREG | 0x1b6)
                    prefmode = int(stat.S_IFREG | 0x1b6)
                    fchmode = stat.S_IMODE(prefmode)
                    ftypemod = stat.S_IFMT(prefmode)
            fchmode = stat.S_IMODE(prefmode)
            ftypemod = stat.S_IFMT(prefmode)
        else:
            fwinattributes = int(zipinfo.external_attr & 0xFFFF)
            if ((hasattr(member, "is_dir") and member.is_dir()) or member.filename.endswith('/')):
                fmode = int(stat.S_IFDIR | 0x1ff)
                prefmode = int(stat.S_IFDIR | 0x1ff)
                fchmode = stat.S_IMODE(prefmode)
                ftypemod = stat.S_IFMT(prefmode)
            else:
                fmode = int(stat.S_IFREG | 0x1b6)
                prefmode = int(stat.S_IFREG | 0x1b6)
                fchmode = stat.S_IMODE(prefmode)
                ftypemod = stat.S_IFMT(prefmode)
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
            elif ((hasattr(member, "symlink") and member.symlink())):
                ftype = 2
                permissionstr = "l" + permissionstr
            else:
                ftype = 0
                permissionstr = "-" + permissionstr
            printfname = member.filename
            if(ftype==2):
                flinkname = zipfp.read(member.filename).decode("UTF-8")
            if(ftype==2):
                printfname = member.filename + " -> " + flinkname
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


def ZipFileListFile(infile, verbose=False, returnfp=False):
    return ZipFileListFiles(infile, verbose, returnfp)


if(not rarfile_support):
    def RarFileListFiles(infile, verbose=False, returnfp=False):
        return False
else:
    def RarFileListFiles(infile, verbose=False, returnfp=False):
        if(isinstance(infile, (list, tuple, ))):
            infile = infile[0]
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


def RarFileListFile(infile, verbose=False, returnfp=False):
    return RarFileListFiles(infile, verbose, returnfp)


if(not py7zr_support):
    def SevenZipFileListFiles(infile, verbose=False, returnfp=False):
        return False
else:
    def SevenZipFileListFiles(infile, verbose=False, returnfp=False):
        if(isinstance(infile, (list, tuple, ))):
            infile = infile[0]
        if(not os.path.exists(infile) or not os.path.isfile(infile)):
            return False
        lcfi = 0
        returnval = {}
        szpfp = py7zr.SevenZipFile(infile, mode="r")
        try:
            file_content = szpfp.readall()
        except AttributeError:
            file_content = sevenzip_readall(infile)
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
            try:
                ffullmode = member.posix_mode
                fmode = format(int(ffullmode), 'x').lower()
                fchmode = format(int(stat.S_IMODE(ffullmode)), 'x').lower()
                ftypemod = format(int(stat.S_IFMT(ffullmode)), 'x').lower()
            except AttributeError:
                pass
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
                    try:
                        file_content[member.filename].close()
                    except AttributeError:
                        pass
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


def SevenZipFileListFile(infile, verbose=False, returnfp=False):
    return SevenZipFileListFiles(infile, verbose, returnfp)


def InFileListFiles(infile, verbose=False, formatspecs=__file_format_multi_dict__, seektoend=False, newstyle=False, returnfp=False):
    checkcompressfile = CheckCompressionSubType(infile, formatspecs, filestart, True)
    if(IsNestedDict(formatspecs) and checkcompressfile in formatspecs):
        formatspecs = formatspecs[checkcompressfile]
    if(checkcompressfile == "tarfile" and TarFileCheck(infile)):
        return TarFileListFiles(infile, formatspecs, verbose, returnfp)
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


def InFileListFile(infile, verbose=False, formatspecs=__file_format_multi_dict__, seektoend=False, newstyle=False, returnfp=False):
    return InFileListFiles(infile, verbose, formatspecs, seektoend, newstyle, returnfp)


def ListDirListFiles(infiles, dirlistfromtxt=False, compression="auto", compresswholefile=True, compressionlevel=None, followlink=False, seekstart=0, seekend=0, skipchecksum=False, checksumtype=["md5", "md5", "md5"], formatspecs=__file_format_dict__, seektoend=False, verbose=False, returnfp=False):
    outarray = MkTempFile()
    packform = PackCatFile(infiles, outarray, dirlistfromtxt, compression, compresswholefile,
                              compressionlevel, followlink, checksumtype, formatspecs, False, True)
    listarrayfiles = CatFileListFiles(
        outarray, seekstart, seekend, skipchecksum, formatspecs, seektoend, verbose, returnfp)
    return listarrayfiles


def ListDirListFiles(infiles, dirlistfromtxt=False, compression="auto", compresswholefile=True, compressionlevel=None, followlink=False, seekstart=0, seekend=0, skipchecksum=False, checksumtype=["md5", "md5", "md5"], formatspecs=__file_format_dict__, seektoend=False, verbose=False, returnfp=False):
    return ListDirListFiles(infiles, dirlistfromtxt, compression, compresswholefile, compressionlevel, followlink, seekstart, seekend, skipchecksum, checksumtype, formatspecs, seektoend, verbose, returnfp)

_TEXT_MIME_DEFAULT = 'text/plain; charset=utf-8'
_BIN_MIME_DEFAULT = 'application/octet-stream'
def get_readable_size(bytes, precision=1, unit="IEC"):
    unit = unit.upper()
    if(unit != "IEC" and unit != "SI"):
        unit = "IEC"
    if(unit == "IEC"):
        units = [" B", " KiB", " MiB", " GiB", " TiB", " PiB", " EiB", " ZiB"]
        unitswos = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB"]
        unitsize = 1024.0
    if(unit == "SI"):
        units = [" B", " kB", " MB", " GB", " TB", " PB", " EB", " ZB"]
        unitswos = ["B", "kB", "MB", "GB", "TB", "PB", "EB", "ZB"]
        unitsize = 1000.0
    return_val = {}
    orgbytes = bytes
    for unit in units:
        if abs(bytes) < unitsize:
            strformat = "%3."+str(precision)+"f%s"
            pre_return_val = (strformat % (bytes, unit))
            pre_return_val = re.sub(
                r"([0]+) ([A-Za-z]+)", r" \2", pre_return_val)
            pre_return_val = re.sub(r"\. ([A-Za-z]+)", r" \1", pre_return_val)
            alt_return_val = pre_return_val.split()
            return_val = {'Bytes': orgbytes, 'ReadableWithSuffix': pre_return_val,
                          'ReadableWithoutSuffix': alt_return_val[0], 'ReadableSuffix': alt_return_val[1]}
            return return_val
        bytes /= unitsize
    strformat = "%."+str(precision)+"f%s"
    pre_return_val = (strformat % (bytes, "YiB"))
    pre_return_val = re.sub(r"([0]+) ([A-Za-z]+)", r" \2", pre_return_val)
    pre_return_val = re.sub(r"\. ([A-Za-z]+)", r" \1", pre_return_val)
    alt_return_val = pre_return_val.split()
    return_val = {'Bytes': orgbytes, 'ReadableWithSuffix': pre_return_val,
                  'ReadableWithoutSuffix': alt_return_val[0], 'ReadableSuffix': alt_return_val[1]}
    return return_val


def get_readable_size_from_file(infile, precision=1, unit="IEC", usehashes=False, usehashtypes="md5,sha1"):
    unit = unit.upper()
    usehashtypes = usehashtypes.lower()
    getfilesize = os.path.getsize(infile)
    return_val = get_readable_size(getfilesize, precision, unit)
    if(usehashes):
        hashtypelist = usehashtypes.split(",")
        openfile = open(infile, "rb")
        filecontents = openfile.read()
        openfile.close()
        listnumcount = 0
        listnumend = len(hashtypelist)
        while(listnumcount < listnumend):
            hashtypelistlow = hashtypelist[listnumcount].strip()
            hashtypelistup = hashtypelistlow.upper()
            filehash = hashlib.new(hashtypelistup)
            filehash.update(filecontents)
            filegethash = filehash.hexdigest()
            return_val.update({hashtypelistup: filegethash})
            listnumcount += 1
    return return_val


def _is_probably_text(data_bytes):
    if not data_bytes:
        return True
    if b'\x00' in data_bytes:
        return False
    try:
        decoded = data_bytes.decode('utf-8')
    except Exception:
        return False

    control = 0
    for ch in decoded:
        o = ord(ch)
        if (o < 32 and ch not in u'\t\n\r') or o == 127:
            control += 1
    return control <= max(1, len(decoded) // 200)


def data_url_encode(fileobj,
                    mime=None,
                    is_text=None,
                    charset='utf-8',
                    base64_encode=None):
    raw = fileobj.read()
    if isinstance(raw, text_type):
        raw_bytes = raw.encode(charset)
        detected_text = True
    else:
        raw_bytes = raw
        detected_text = _is_probably_text(raw_bytes)

    if is_text is None:
        is_text = detected_text

    if mime is None:
        mime = _TEXT_MIME_DEFAULT if is_text else _BIN_MIME_DEFAULT
    else:
        mlow = mime.lower()
        if mlow.startswith('text/') and 'charset=' not in mlow:
            mime = mime + '; charset=' + charset

    if base64_encode is None:
        base64_encode = not is_text

    if base64_encode:
        b64 = base64.b64encode(raw_bytes)
        if not isinstance(b64, text_type):
            b64 = b64.decode('ascii')
        return u'data:{0};base64,{1}'.format(mime, b64)
    else:
        encoded = quote_from_bytes(raw_bytes, safe="!$&'()*+,;=:@-._~")
        if not isinstance(encoded, text_type):
            encoded = encoded.decode('ascii')
        return u'data:{0},{1}'.format(mime, encoded)


_DATA_URL_RE = re.compile(r'^data:(?P<meta>[^,]*?),(?P<data>.*)$', re.DOTALL)


def data_url_decode(data_url):
    if not isinstance(data_url, text_type):
        try:
            data_url = data_url.decode('utf-8')
        except Exception:
            data_url = data_url.decode('ascii')

    m = _DATA_URL_RE.match(data_url)
    if not m:
        raise ValueError('Not a valid data: URL')

    meta = m.group('meta')
    data_part = m.group('data')

    meta_parts = [p for p in meta.split(';') if p] if meta else []
    is_base64 = False
    mime = None

    if meta_parts:
        if '/' in meta_parts[0]:
            mime = meta_parts[0]
            rest = meta_parts[1:]
        else:
            rest = meta_parts

        for p in rest:
            if p.lower() == 'base64':
                is_base64 = True
            else:
                if mime is None:
                    mime = p
                else:
                    mime = mime + ';' + p

    if is_base64:
        try:
            decoded_bytes = base64.b64decode(data_part.encode('ascii'))
        except Exception:
            cleaned = ''.join(data_part.split())
            decoded_bytes = base64.b64decode(cleaned.encode('ascii'))
    else:
        decoded_bytes = unquote_to_bytes(data_part)

        if isinstance(decoded_bytes, text_type):
            decoded_bytes = decoded_bytes.encode('latin-1')

    if mime is None:
        mime = "text/plain;charset=US-ASCII"
    is_text = str(mime).lower().startswith("text/")
    return MkTempFile(decoded_bytes), mime, is_text

def fix_header_names(header_dict):
    if(sys.version[0] == "2"):
        header_dict = {k.title(): v for k, v in header_dict.items()}
    if(sys.version[0] >= "3"):
        header_dict = {k.title(): v for k, v in header_dict.items()}
    return header_dict

def make_http_headers_from_dict_to_list(headers):
    if isinstance(headers, dict):
        returnval = []
        if(sys.version[0] == "2"):
            for headkey, headvalue in headers.items():
                returnval.append((headkey, headvalue))
        if(sys.version[0] >= "3"):
            for headkey, headvalue in headers.items():
                returnval.append((headkey, headvalue))
    elif isinstance(headers, list):
        returnval = headers
    else:
        returnval = False
    return returnval


def make_http_headers_from_dict_to_pycurl(headers):
    if isinstance(headers, dict):
        returnval = []
        if(sys.version[0] == "2"):
            for headkey, headvalue in headers.items():
                returnval.append(headkey+": "+headvalue)
        if(sys.version[0] >= "3"):
            for headkey, headvalue in headers.items():
                returnval.append(headkey+": "+headvalue)
    elif isinstance(headers, list):
        returnval = headers
    else:
        returnval = False
    return returnval


def make_http_headers_from_pycurl_to_dict(headers):
    header_dict = {}
    headers = headers.strip().split('\r\n')
    for header in headers:
        parts = header.split(': ', 1)
        if(len(parts) == 2):
            key, value = parts
            header_dict[key.title()] = value
    return header_dict


def make_http_headers_from_list_to_dict(headers):
    if isinstance(headers, list):
        returnval = {}
        mli = 0
        mlil = len(headers)
        while(mli < mlil):
            returnval.update({headers[mli][0]: headers[mli][1]})
            mli = mli + 1
    elif isinstance(headers, dict):
        returnval = headers
    else:
        returnval = False
    return returnval

__use_inmem__ = True
__use_memfd__ = True
__use_spoolfile__ = False
__use_spooldir__ = tempfile.gettempdir()

BYTES_PER_KiB = 1024
BYTES_PER_MiB = 1024 * BYTES_PER_KiB

DEFAULT_SPOOL_MAX = 4 * BYTES_PER_MiB
__spoolfile_size__ = DEFAULT_SPOOL_MAX

DEFAULT_BUFFER_MAX = 256 * BYTES_PER_KiB
__filebuff_size__ = DEFAULT_BUFFER_MAX

text_type = str

binary_types = (bytes, bytearray, memoryview)

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
_LOG = logging.getLogger(__name__)

def _emit(msg: str, *, logger: Optional[logging.Logger] = None, level: int = logging.INFO, stream: str = "stderr") -> None:
    """Emit a human-facing message.

    - If `logger` is provided, log there.
    - Otherwise, write to stderr/stdout (default: stderr).
    """
    try:
        if logger is not None:
            logger.log(level, msg)
            return
    except Exception:
        # Fall back to stream output
        pass

    out = sys.stderr if stream != "stdout" else sys.stdout
    try:
        out.write(msg + "\n")
        out.flush()
    except Exception:
        pass

def _logger_from_kwargs(kwargs: Mapping[str, Any]) -> Optional[logging.Logger]:
    try:
        lg = kwargs.get("logger")  # type: ignore[attr-defined]
        return lg if isinstance(lg, logging.Logger) else None
    except Exception:
        return None

def _best_lan_ip():
    """Attempt to find the best LAN IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"
    finally:
        s.close()

def _listen_urls(scheme, bind_host, port, path, query=""):
    if not path:
        path = "/"
    if not path.startswith("/"):
        path = "/" + path
    q = ""
    if query:
        q = "?" + query.lstrip("?")
    urls = []
    if not bind_host or bind_host == "0.0.0.0":
        urls.append("%s://127.0.0.1:%d%s%s" % (scheme, port, path, q))
        ip = _best_lan_ip()
        if ip and ip != "127.0.0.1":
            urls.append("%s://%s:%d%s%s" % (scheme, ip, port, path, q))
    else:
        urls.append("%s://%s:%d%s%s" % (scheme, bind_host, port, path, q))
    return urls

def _parse_kv_headers(qs, prefix="hdr_"):
    out = {}
    for k in qs.keys():
        if k.startswith(prefix):
            hk = k[len(prefix):].replace("_", "-")
            try:
                out[hk] = qs.get(k)[0]
            except Exception:
                try:
                    out[hk] = qs[k][0]
                except Exception:
                    pass
    return out


def _throttle_bps(rate_bps, sent, started):
    """Sleep to enforce approximate bytes/sec rate."""
    try:
        rate_bps = float(rate_bps)
    except Exception:
        return
    if rate_bps <= 0:
        return
    elapsed = time.time() - started
    if elapsed <= 0:
        return
    should = float(sent) / rate_bps
    if should > elapsed:
        time.sleep(should - elapsed)


def _hs_token():
    try:
        import random
        return ('%x' % random.getrandbits(64)).encode('ascii')
    except Exception:
        try:
            return ('%x' % (int(time.time()*1000000) ^ os.getpid())).encode('ascii')
        except Exception:
            return ('%x' % int(time.time()*1000000)).encode('ascii')

def _byte_at(b, i):
    v = b[i]
    return v if isinstance(v, int) else ord(v)

def _to_bytes(x):
    if x is None:
        return b""
    if isinstance(x, bytes):
        return x
    try:
        return x.encode("utf-8")
    except Exception:
        return bytes(x)

def _to_text(x):
    if x is None:
        return u""
    if isinstance(x, bytes):
        try:
            return x.decode("utf-8", "replace")
        except Exception:
            return x.decode("latin-1", "replace")
    return x

def _rand_u64():
    return struct.unpack("!Q", os.urandom(8))[0]

def _set_query_param(url, key, value):
    try:
        up = urlparse(url)
        qs = up.query or ""
        parts = []
        if qs:
            for kv in qs.split("&"):
                if not kv:
                    continue
                if kv.split("=", 1)[0] != key:
                    parts.append(kv)
        parts.append("%s=%s" % (key, value))
        newq = "&".join(parts)
        return urlunparse((up.scheme, up.netloc, up.path, up.params, newq, up.fragment))
    except Exception:
        return url

def _qflag(qs, key, default=False):
    v = qs.get(key, [None])[0]
    if v is None:
        return default
    v = _to_text(v).strip().lower()
    return v in ("1", "true", "yes", "on", "y")

def _qnum(qs, key, default, cast=int):
    v = qs.get(key, [None])[0]
    if v is None or v == "":
        return default
    try:
        return cast(v)
    except Exception:
        try:
            return cast(_to_text(v))
        except Exception:
            return default

def _qstr(qs, key, default=None):
    v = qs.get(key, [None])[0]
    if v is None:
        return default
    return _to_text(v)

def _ensure_dir(d):
    if not d:
        return
    if not os.path.isdir(d):
        try:
            os.makedirs(d)
        except Exception:
            pass

def _guess_filename(url):
    p = urlparse(url)
    bn = os.path.basename(p.path or "")
    return bn or "download.bin"

def _choose_output_path(fname, overwrite=False, save_dir=None):
    if not save_dir:
        save_dir = "."
    _ensure_dir(save_dir)
    base = os.path.join(save_dir, fname)
    if overwrite or not os.path.exists(base):
        return base
    root, ext = os.path.splitext(base)
    for i in range(1, 10000):
        cand = "%s.%d%s" % (root, i, ext)
        if not os.path.exists(cand):
            return cand
    return base

def _copy_fileobj_to_path(fileobj, path, overwrite=False):
    if (not overwrite) and os.path.exists(path):
        raise IOError("Refusing to overwrite: %s" % path)
    _ensure_dir(os.path.dirname(path) or ".")
    with open(path, "wb") as out:
        try:
            fileobj.seek(0, 0)
        except Exception:
            pass
        shutil.copyfileobj(fileobj, out)

OP_RRQ   = 1
OP_WRQ   = 2
OP_DATA  = 3
OP_ACK   = 4
OP_ERROR = 5

BLOCK_SIZE = 512


class TFTPError(Exception):
    pass


def _make_rrq(filename, mode=b"octet"):
    return struct.pack("!H", OP_RRQ) + _to_bytes(filename) + b"\x00" + _to_bytes(mode) + b"\x00"


def _make_wrq(filename, mode=b"octet"):
    return struct.pack("!H", OP_WRQ) + _to_bytes(filename) + b"\x00" + _to_bytes(mode) + b"\x00"


def _make_data(blockno, payload):
    return struct.pack("!HH", OP_DATA, blockno) + payload


def _make_ack(blockno):
    return struct.pack("!HH", OP_ACK, blockno)


def _parse_packet(pkt):
    if len(pkt) < 2:
        raise TFTPError("Short packet")
    op = struct.unpack("!H", pkt[:2])[0]
    return op


def _parse_ack(pkt):
    if len(pkt) < 4:
        raise TFTPError("Short ACK")
    op, blockno = struct.unpack("!HH", pkt[:4])
    if op != OP_ACK:
        raise TFTPError("Expected ACK, got opcode %d" % op)
    return blockno


def _parse_data(pkt):
    if len(pkt) < 4:
        raise TFTPError("Short DATA")
    op, blockno = struct.unpack("!HH", pkt[:4])
    if op != OP_DATA:
        raise TFTPError("Expected DATA, got opcode %d" % op)
    return blockno, pkt[4:]


def _parse_error(pkt):
    if len(pkt) < 4:
        raise TFTPError("Short ERROR")
    op, errcode = struct.unpack("!HH", pkt[:4])
    if op != OP_ERROR:
        raise TFTPError("Not an ERROR packet")
    msg = pkt[4:]
    if b"\x00" in msg:
        msg = msg.split(b"\x00", 1)[0]
    try:
        msg = msg.decode("utf-8", "replace")
    except Exception:
        msg = repr(msg)
    raise TFTPError("TFTP ERROR %d: %s" % (errcode, msg))


def _mk_sock(proxy, timeout):
    """
    proxy: dict or None
      If dict, expected keys:
        host, port, username(optional), password(optional)
    """
    s = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)

    if proxy:
        s.set_proxy(
            proxy_type=socks.SOCKS5,
            addr=proxy["host"],
            port=int(proxy["port"]),
            username=proxy.get("username"),
            password=proxy.get("password"),
            rdns=True,
        )
    return s


def tftp_upload(server_host, remote_filename, fileobj,
                server_port=69, mode="octet",
                proxy=None, timeout=5.0, retries=5):
    sock = _mk_sock(proxy, timeout)

    try:
        wrq = _make_wrq(remote_filename, mode=_to_bytes(mode))
        sock.sendto(wrq, (server_host, int(server_port)))

        for attempt in range(retries):
            try:
                pkt, addr = sock.recvfrom(4 + 128)
                op = _parse_packet(pkt)
                if op == OP_ERROR:
                    _parse_error(pkt)
                if op != OP_ACK:
                    raise TFTPError("Expected ACK(0), got opcode %d" % op)
                ack_block = _parse_ack(pkt)
                if ack_block != 0:
                    raise TFTPError("Expected ACK block 0, got %d" % ack_block)
                server_tid = addr
                break
            except socket.timeout:
                sock.sendto(wrq, (server_host, int(server_port)))
        else:
            raise TFTPError("Timeout waiting for ACK(0)")
        blockno = 1
        while True:
            data = fileobj.read(BLOCK_SIZE)
            if data is None:
                data = b""
            if not isinstance(data, (bytes, bytearray)):
                raise TFTPError("fileobj.read() must return bytes")

            data_pkt = _make_data(blockno, data)

            for attempt in range(retries):
                sock.sendto(data_pkt, server_tid)
                try:
                    pkt, addr = sock.recvfrom(4 + 128)
                    if addr != server_tid:
                        continue
                    op = _parse_packet(pkt)
                    if op == OP_ERROR:
                        _parse_error(pkt)
                    ackb = _parse_ack(pkt)
                    if ackb == blockno:
                        break
                except socket.timeout:
                    continue
            else:
                raise TFTPError("Timeout waiting for ACK(%d)" % blockno)

            if len(data) < BLOCK_SIZE:
                return

            blockno = (blockno + 1) & 0xFFFF
            if blockno == 0:
                raise TFTPError("Block number rollover not supported in this simple implementation.")

    finally:
        try:
            sock.close()
        except Exception:
            pass


def tftp_download(server_host, remote_filename,
                  server_port=69, mode="octet",
                  proxy=None, timeout=5.0, retries=5):
    sock = _mk_sock(proxy, timeout)
    out = MkTempFile()

    rrq = _make_rrq(remote_filename, mode=_to_bytes(mode))

    try:
        sock.sendto(rrq, (server_host, int(server_port)))

        expected = 1
        server_tid = None
        last_ack = 0

        while True:
            for attempt in range(retries):
                try:
                    pkt, addr = sock.recvfrom(4 + BLOCK_SIZE + 128)
                    op = _parse_packet(pkt)

                    if op == OP_ERROR:
                        _parse_error(pkt)

                    if op != OP_DATA:
                        raise TFTPError("Expected DATA, got opcode %d" % op)

                    blockno, payload = _parse_data(pkt)

                    if server_tid is None:
                        server_tid = addr

                    if addr != server_tid:
                        continue

                    if blockno == expected:
                        out.write(payload)
                        ack = _make_ack(blockno)
                        sock.sendto(ack, server_tid)
                        last_ack = blockno

                        if len(payload) < BLOCK_SIZE:
                            out.seek(0)
                            return out

                        expected = (expected + 1) & 0xFFFF
                        if expected == 0:
                            raise TFTPError("Block number rollover not supported in this simple implementation.")
                        break

                    elif blockno == last_ack:

                        sock.sendto(_make_ack(blockno), server_tid)
                        break

                    else:

                        sock.sendto(_make_ack(last_ack), server_tid)
                        break

                except socket.timeout:

                    if server_tid is None:
                        sock.sendto(rrq, (server_host, int(server_port)))
                    else:
                        sock.sendto(_make_ack(last_ack), server_tid)
            else:
                raise TFTPError("Timeout receiving DATA block %d" % expected)

    finally:
        try:
            sock.close()
        except Exception:
            pass

def download_file_from_tftp_file(url, timeout=60, returnstats=False):
    p = urlparse(url)
    if p.scheme != "tftp":
        return False

    host = p.hostname
    port = p.port or 69
    user = p.username
    pw = p.password
    path = p.path or "/"
    file_dir = os.path.dirname(path)
    start_time = time.time()
    socket.setdefaulttimeout(float(timeout))
    try:
        bio = tftp_download(host, p.path, port, timeout=float(timeout))
        fulldatasize = bio.tell()
        bio.seek(0, 0)
        end_time = time.time()
        total_time = end_time - start_time
        if(returnstats):
            returnval = {'Type': "Buffer", 'Buffer': bio, 'Contentsize': fulldatasize, 'ContentsizeAlt': {'IEC': get_readable_size(fulldatasize, 2, "IEC"), 'SI': get_readable_size(fulldatasize, 2, "SI")}, 'Headers': None, 'Version': None, 'Method': None, 'HeadersSent': None, 'URL': url, 'Code': None, 'RequestTime': {'StartTime': start_time, 'EndTime': end_time, 'TotalTime': total_time}, 'FTPLib': 'pyftp'}
        else:
            return bio
    except Exception:
        try:
            ftp.close()
        except Exception:
            pass
        return False

def download_file_from_tftp_bytes(url, timeout=60, returnstats=False):
    fp = download_file_from_tftp_file(url, timeout, returnstats)
    return fp.read() if fp else False

def download_file_from_tftp_to_file(url, outfile, timeout=60):
    outfile = open(outfile, "wb")
    outfile.seek(0, 0)
    httpbytes = download_file_from_tftp_bytes(url, timeout, False)
    outfile.write(httpbytes)
    outfile.close()
    return True

def upload_file_to_tftp_file(fileobj, url, timeout=60):
    p = urlparse(url)
    if p.scheme != "tftp":
        return False

    socket.setdefaulttimeout(float(timeout))
    host = p.hostname
    port = p.port or 21
    user = p.username
    pw = p.password
    path = p.path or "/"
    file_dir = os.path.dirname(path)
    fname = os.path.basename(path) or "upload.bin"

    try:
        try:
            fileobj.seek(0, 0)
        except Exception:
            pass
        tftp_upload(host, p.path, fileobj, port, timeout=float(timeout))
        try:
            fileobj.seek(0, 0)
        except Exception:
            pass

        return fileobj
    except Exception:
        return False

def upload_file_to_tftp_bytes(data, url, timeout=60):
    bio = MkTempFile(_to_bytes(data))
    out = upload_file_to_tftp_file(bio, url, timeout)
    try:
        bio.close()
    except Exception:
        pass
    return out

def upload_file_to_tftp_from_file(infile, url, timeout=60):
    infile = open(infile, "rb")
    upload_file_to_tftp_file(infile, url, timeout)
    infile.close()
    return True

def detect_cwd_ftp(ftp, file_dir):
    if not file_dir:
        return False
    try:
        ftp.cwd(file_dir)
        return True
    except all_errors:
        return False

def _ftp_login(ftp, user, pw):
    if user is None:
        user = "anonymous"
    if pw is None:
        pw = "anonymous" if user == "anonymous" else ""
    ftp.login(user, pw)

def download_file_from_ftp_file(url, resumefile=None, timeout=60, returnstats=False):
    p = urlparse(url)
    if p.scheme not in ("ftp", "ftps"):
        return False
    if p.scheme == "ftps" and not ftpssl:
        return False

    host = p.hostname
    port = p.port or 21
    user = p.username
    pw = p.password
    path = p.path or "/"
    file_dir = os.path.dirname(path)
    start_time = time.time()
    socket.setdefaulttimeout(float(timeout))
    ftp = FTP_TLS() if (p.scheme == "ftps") else FTP()
    try:
        ftp.connect(host, port, timeout=float(timeout))
        _ftp_login(ftp, user, pw)
        if p.scheme == "ftps":
            try:
                ftp.prot_p()
            except Exception:
                pass

        use_cwd = detect_cwd_ftp(ftp, file_dir)
        retr_path = os.path.basename(path) if use_cwd else path
        extendargs = {}
        if(resumefile is not None and hasattr(resumefile, "write")):
            resumefile.seek(0, 2)
            bio = resumefile
            extendargs = {'rest': resumefile.tell()}
        else:
            bio = MkTempFile()
        ftp.retrbinary("RETR " + retr_path, bio.write)
        ftp.quit()
        fulldatasize = bio.tell()
        bio.seek(0, 0)
        end_time = time.time()
        total_time = end_time - start_time
        if(returnstats):
            returnval = {'Type': "Buffer", 'Buffer': bio, 'Contentsize': fulldatasize, 'ContentsizeAlt': {'IEC': get_readable_size(fulldatasize, 2, "IEC"), 'SI': get_readable_size(fulldatasize, 2, "SI")}, 'Headers': None, 'Version': None, 'Method': None, 'HeadersSent': None, 'URL': url, 'Code': None, 'RequestTime': {'StartTime': start_time, 'EndTime': end_time, 'TotalTime': total_time}, 'FTPLib': 'pyftp'}
        else:
            return bio
    except Exception:
        try:
            ftp.close()
        except Exception:
            pass
        return False

def download_file_from_ftp_bytes(url, resumefile=None, timeout=60, returnstats=False):
    fp = download_file_from_ftp_file(url, resumefile, timeout, returnstats)
    return fp.read() if fp else False

def download_file_from_ftp_to_file(url, outfile, timeout=60):
    if(os.path.exists(outfile)):
        outfile = open(outfile, "ab")
        outfile.seek(0, 2)
        httpbytes = download_file_from_ftp_file(url, outfile, timeout, False)
        outfile.close()
    else:
        outfile = open(outfile, "wb")
        httpbytes = download_file_from_ftp_bytes(url, None, timeout, False)
        outfile.write(httpbytes)
        outfile.close()
    return True

def download_file_from_ftps_file(url, resumefile=None, timeout=60, returnstats=False):
    return download_file_from_ftp_file(url, resumefile, timeout, returnstats)

def download_file_from_ftps_bytes(url, resumefile=None, timeout=60, returnstats=False):
    return download_file_from_ftp_bytes(url, resumefile, timeout, returnstats)

def download_file_from_ftps_to_file(url, outfile, timeout=60):
    return download_file_from_ftp_to_file(url, outfile, timeout, returnstats)

def upload_file_to_ftp_file(fileobj, url, timeout=60):
    p = urlparse(url)
    if p.scheme not in ("ftp", "ftps"):
        return False
    if p.scheme == "ftps" and not ftpssl:
        return False
    socket.setdefaulttimeout(float(timeout))
    host = p.hostname
    port = p.port or 21
    user = p.username
    pw = p.password
    path = p.path or "/"
    file_dir = os.path.dirname(path)
    fname = os.path.basename(path) or "upload.bin"

    ftp = FTP_TLS() if (p.scheme == "ftps") else FTP()
    try:
        ftp.connect(host, port, timeout=float(timeout))
        _ftp_login(ftp, user, pw)
        if p.scheme == "ftps":
            try:
                ftp.prot_p()
            except Exception:
                pass

        use_cwd = detect_cwd_ftp(ftp, file_dir)
        stor_path = fname if use_cwd else path

        try:
            fileobj.seek(0, 0)
        except Exception:
            pass
        ftp.storbinary("STOR " + stor_path, fileobj)
        ftp.quit()
        try:
            fileobj.seek(0, 0)
        except Exception:
            pass
        return fileobj
    except Exception:
        try:
            ftp.close()
        except Exception:
            pass
        return False

def upload_file_to_ftp_bytes(data, url, timeout=60):
    bio = MkTempFile(_to_bytes(data))
    out = upload_file_to_ftp_file(bio, url, timeout)
    try:
        bio.close()
    except Exception:
        pass
    return out

def upload_file_to_ftp_from_file(infile, url, timeout=60):
    infile = open(infile, "rb")
    upload_file_to_ftp_file(infile, url, timeout)
    infile.close()
    return True

def upload_file_to_ftps_file(fileobj, url, timeout=60):
    return upload_file_to_ftp_file(fileobj, url, timeout)

def upload_file_to_ftps_from_file(infile, url, timeout=60):
    return upload_file_to_ftp_from_file(infile, url, timeout)

def upload_file_to_ftps_bytes(fileobj, url, timeout=60):
    return upload_file_to_ftp_bytes(fileobj, url, timeout)


def detect_cwd_sftp(sftp, file_dir):
    if not file_dir:
        return False
    try:
        sftp.chdir(file_dir)
        return True
    except all_errors:
        return False

def download_file_from_sftp_file(url, timeout=60, returnstats=False):
    if not haveparamiko:
        return False
    p = urlparse(url)
    if p.scheme not in ("sftp", "scp"):
        return False
    host = p.hostname
    port = p.port or 22
    user = p.username or "anonymous"
    pw = p.password or ("anonymous" if user == "anonymous" else "")
    path = p.path or "/"
    socket.setdefaulttimeout(float(timeout))
    start_time = time.time()
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, port=port, username=user, password=pw, timeout=float(timeout))
        sftp = ssh.open_sftp()
        use_cwd = detect_cwd_sftp(sftp, path)
        retr_path = os.path.basename(path) if use_cwd else path
        bio = MkTempFile()
        sftp.getfo(retr_path, bio)
        sftp.close()
        ssh.close()
        fulldatasize = bio.tell()
        bio.seek(0, 0)
        end_time = time.time()
        total_time = end_time - start_time
        if(returnstats):
            returnval = {'Type': "Buffer", 'Buffer': bio, 'Contentsize': fulldatasize, 'ContentsizeAlt': {'IEC': get_readable_size(fulldatasize, 2, "IEC"), 'SI': get_readable_size(fulldatasize, 2, "SI")}, 'Headers': None, 'Version': None, 'Method': None, 'HeadersSent': None, 'URL': url, 'Code': None, 'RequestTime': {'StartTime': start_time, 'EndTime': end_time, 'TotalTime': total_time}, 'SFTPLib': 'paramiko'}
        else:
            return bio
    except Exception:
        try:
            ssh.close()
        except Exception:
            pass
        return False

def download_file_from_sftp_bytes(url, timeout=60, returnstats=False):
    fp = download_file_from_sftp_file(url, timeout, returnstats)
    return fp.read() if fp else False

def download_file_from_sftp_to_file(url, outfile, timeout=60):
    outfile = open(outfile, "wb")
    httpbytes = download_file_from_sftp_bytes(url, timeout, False)
    outfile.write(httpbytes)
    outfile.close()
    return True

def upload_file_to_sftp_file(fileobj, url, timeout=60):
    if not haveparamiko:
        return False
    p = urlparse(url)
    if p.scheme not in ("sftp", "scp"):
        return False
    host = p.hostname
    port = p.port or 22
    user = p.username or "anonymous"
    pw = p.password or ("anonymous" if user == "anonymous" else "")
    path = p.path or "/"
    fname = os.path.basename(path) or "upload.bin"
    socket.setdefaulttimeout(float(timeout))
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, port=port, username=user, password=pw, timeout=float(timeout))
        sftp = ssh.open_sftp()
        use_cwd = detect_cwd_sftp(sftp, path)
        stor_path = fname if use_cwd else path
        try:
            fileobj.seek(0, 0)
        except Exception:
            pass
        sftp.putfo(fileobj, stor_path)
        sftp.close()
        ssh.close()
        try:
            fileobj.seek(0, 0)
        except Exception:
            pass
        return fileobj
    except Exception:
        try:
            ssh.close()
        except Exception:
            pass
        return False

def upload_file_to_sftp_from_file(infile, url, timeout=60):
    infile = open(infile, "rb")
    upload_file_to_sftp_file(infile, url, timeout)
    infile.close()
    return True

def upload_file_to_sftp_bytes(data, url, timeout=60):
    bio = MkTempFile(_to_bytes(data))
    out = upload_file_to_sftp_file(bio, url, timeout)
    try:
        bio.close()
    except Exception:
        pass
    return out


def download_file_from_pysftp_file(url, timeout=60, returnstats=False):
    if not havepysftp:
        return False
    p = urlparse(url)
    if p.scheme not in ("sftp", "scp"):
        return False
    socket.setdefaulttimeout(float(timeout))
    host = p.hostname
    port = p.port or 22
    user = p.username or "anonymous"
    pw = p.password or ("anonymous" if user == "anonymous" else "")
    path = p.path or "/"
    fname = os.path.basename(path) or "upload.bin"

    conn = None
    start_time = time.time()
    try:
        conn = pysftp.Connection(host=host, port=port, username=user, password=pw)

        sftp = conn.sftp_client
        use_cwd = detect_cwd_sftp(sftp, path)
        retr_path = os.path.basename(path) if use_cwd else path
        bio = BytesIO()
        sftp.getfo(retr_path, bio)

        fulldatasize = bio.tell()
        bio.seek(0, 0)

        end_time = time.time()
        total_time = end_time - start_time
        if(returnstats):
            returnval = {'Type': "Buffer", 'Buffer': bio, 'Contentsize': fulldatasize, 'ContentsizeAlt': {'IEC': get_readable_size(fulldatasize, 2, "IEC"), 'SI': get_readable_size(fulldatasize, 2, "SI")}, 'Headers': None, 'Version': None, 'Method': None, 'HeadersSent': None, 'URL': url, 'Code': None, 'RequestTime': {'StartTime': start_time, 'EndTime': end_time, 'TotalTime': total_time}, 'SFTPLib': 'pysftp'}
        else:
            return bio

    except Exception:
        return False
    finally:
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass

def download_file_from_pysftp_bytes(url, timeout=60, returnstats=False):
    fp = download_file_from_pysftp_file(url, timeout, returnstats)
    return fp.read() if fp else False

def download_file_from_pysftp_to_file(url, outfile, timeout=60):
    outfile = open(outfile, "wb")
    httpbytes = download_file_from_pysftp_bytes(url, timeout, False)
    outfile.write(httpbytes)
    outfile.close()
    return True

def upload_file_to_pysftp_file(fileobj, url, timeout=60):
    if not havepysftp:
        return False
    p = urlparse(url)
    if p.scheme not in ("sftp", "scp"):
        return False
    socket.setdefaulttimeout(float(timeout))
    host = p.hostname
    port = p.port or 22
    user = p.username or "anonymous"
    pw = p.password or ("anonymous" if user == "anonymous" else "")
    path = p.path or "/"
    fname = os.path.basename(path) or "upload.bin"

    conn = None
    try:
        conn = pysftp.Connection(host=host, port=port, username=user, password=pw)

        sftp = conn.sftp_client
        use_cwd = detect_cwd_sftp(sftp, path)
        stor_path = fname if use_cwd else path
        try:
            fileobj.seek(0, 0)
        except Exception:
            pass

        sftp.putfo(fileobj, stor_path)

        try:
            fileobj.seek(0, 0)
        except Exception:
            pass

        return fileobj

    except Exception:
        return False
    finally:
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass

def upload_file_to_pysftp_from_file(infile, url, timeout=60):
    infile = open(infile, "rb")
    upload_file_to_pysftp_file(infile, url, timeout)
    infile.close()
    return True

def upload_file_to_pysftp_bytes(data, url, timeout=60):
    bio = MkTempFile(_to_bytes(data))
    out = upload_file_to_pysftp_file(bio, url, timeout)
    try:
        bio.close()
    except Exception:
        pass
    return out

def decoded_stream(resp):
    enc = None
    try:
        enc = resp.headers.get("Content-Encoding")
    except Exception:
        pass

    if not enc:
        return resp

    enc = enc.lower().strip()

    if enc == "gzip":
        return gzip.GzipFile(fileobj=resp)
    if enc == "deflate":
        data = resp.read()
        try:
            return io.BytesIO(zlib.decompress(data))
        except zlib.error:
            return io.BytesIO(zlib.decompress(data, -zlib.MAX_WBITS))

    return resp


def http_status_to_reason(code):
    reasons = {
        100: 'Continue',
        101: 'Switching Protocols',
        102: 'Processing',
        200: 'OK',
        201: 'Created',
        202: 'Accepted',
        203: 'Non-Authoritative Information',
        204: 'No Content',
        205: 'Reset Content',
        206: 'Partial Content',
        207: 'Multi-Status',
        208: 'Already Reported',
        226: 'IM Used',
        300: 'Multiple Choices',
        301: 'Moved Permanently',
        302: 'Found',
        303: 'See Other',
        304: 'Not Modified',
        305: 'Use Proxy',
        307: 'Temporary Redirect',
        308: 'Permanent Redirect',
        400: 'Bad Request',
        401: 'Unauthorized',
        402: 'Payment Required',
        403: 'Forbidden',
        404: 'Not Found',
        405: 'Method Not Allowed',
        406: 'Not Acceptable',
        407: 'Proxy Authentication Required',
        408: 'Request Timeout',
        409: 'Conflict',
        410: 'Gone',
        411: 'Length Required',
        412: 'Precondition Failed',
        413: 'Payload Too Large',
        414: 'URI Too Long',
        415: 'Unsupported Media Type',
        416: 'Range Not Satisfiable',
        417: 'Expectation Failed',
        421: 'Misdirected Request',
        422: 'Unprocessable Entity',
        423: 'Locked',
        424: 'Failed Dependency',
        426: 'Upgrade Required',
        428: 'Precondition Required',
        429: 'Too Many Requests',
        431: 'Request Header Fields Too Large',
        451: 'Unavailable For Legal Reasons',
        500: 'Internal Server Error',
        501: 'Not Implemented',
        502: 'Bad Gateway',
        503: 'Service Unavailable',
        504: 'Gateway Timeout',
        505: 'HTTP Version Not Supported',
        506: 'Variant Also Negotiates',
        507: 'Insufficient Storage',
        508: 'Loop Detected',
        510: 'Not Extended',
        511: 'Network Authentication Required'
    }
    return reasons.get(code, 'Unknown Status Code')


def ftp_status_to_reason(code):
    reasons = {
        110: 'Restart marker reply',
        120: 'Service ready in nnn minutes',
        125: 'Data connection already open; transfer starting',
        150: 'File status okay; about to open data connection',
        200: 'Command okay',
        202: 'Command not implemented, superfluous at this site',
        211: 'System status, or system help reply',
        212: 'Directory status',
        213: 'File status',
        214: 'Help message',
        215: 'NAME system type',
        220: 'Service ready for new user',
        221: 'Service closing control connection',
        225: 'Data connection open; no transfer in progress',
        226: 'Closing data connection',
        227: 'Entering Passive Mode',
        230: 'User logged in, proceed',
        250: 'Requested file action okay, completed',
        257: '"PATHNAME" created',
        331: 'User name okay, need password',
        332: 'Need account for login',
        350: 'Requested file action pending further information',
        421: 'Service not available, closing control connection',
        425: 'Can\'t open data connection',
        426: 'Connection closed; transfer aborted',
        450: 'Requested file action not taken',
        451: 'Requested action aborted. Local error in processing',
        452: 'Requested action not taken. Insufficient storage space in system',
        500: 'Syntax error, command unrecognized',
        501: 'Syntax error in parameters or arguments',
        502: 'Command not implemented',
        503: 'Bad sequence of commands',
        504: 'Command not implemented for that parameter',
        530: 'Not logged in',
        532: 'Need account for storing files',
        550: 'Requested action not taken. File unavailable',
        551: 'Requested action aborted. Page type unknown',
        552: 'Requested file action aborted. Exceeded storage allocation',
        553: 'Requested action not taken. File name not allowed'
    }
    return reasons.get(code, 'Unknown Status Code')


def sftp_status_to_reason(code):
    reasons = {
        0: 'SSH_FX_OK',
        1: 'SSH_FX_EOF',
        2: 'SSH_FX_NO_SUCH_FILE',
        3: 'SSH_FX_PERMISSION_DENIED',
        4: 'SSH_FX_FAILURE',
        5: 'SSH_FX_BAD_MESSAGE',
        6: 'SSH_FX_NO_CONNECTION',
        7: 'SSH_FX_CONNECTION_LOST',
        8: 'SSH_FX_OP_UNSUPPORTED'
    }
    return reasons.get(code, 'Unknown Status Code')

def read_all(fileobj, encoding='utf-8', errors='replace'):
    data = fileobj.read()
    if data is None:
        return ''
    if isinstance(data, bytes):
        return data.decode(encoding, errors)
    return data

_req_line_http1 = re.compile(r'^(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/(?P<version>\d+\.\d)\s*$')
_req_line_h2    = re.compile(r'^(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/(?P<version>2(?:\.0)?)\s*$')
_status_line_v1 = re.compile(r'^HTTP/(?P<version>\d+\.\d)\s+(?P<code>\d{3})(?:\s+(?P<reason>.*))?$')
_status_line_h2 = re.compile(r'^HTTP/(?P<version>2(?:\.0)?)\s+(?P<code>\d{3})(?:\s+(?P<reason>.*))?$')

def _normalize(text):
    return text.replace('\r\n', '\n').replace('\r', '\n')

def _split_header_block(block_text):
    block_text = _normalize(block_text)
    lines = block_text.split('\n')
    while lines and lines[-1] == '':
        lines.pop()

    out = []
    for line in lines:
        if out and (line.startswith(' ') or line.startswith('\t')):
            out[-1] += ' ' + line.lstrip()
        else:
            out.append(line)
    return out

def _parse_headers(lines):
    headers = {}
    for line in lines:
        if not line or ':' not in line:
            continue
        name, value = line.split(':', 1)
        name = name.strip()
        value = value.strip()
        key = name.lower()

        if key in headers:
            if isinstance(headers[key], list):
                headers[key].append(value)
            else:
                headers[key] = [headers[key], value]
        else:
            headers[key] = value
    return headers

def parse_request_block(block_text):
    if not block_text:
        return None
    lines = _split_header_block(block_text)
    if not lines:
        return None

    m = _req_line_http1.match(lines[0]) or _req_line_h2.match(lines[0])
    if not m:
        return None

    return {
        'method': m.group('method'),
        'path': m.group('path'),
        'version': m.group('version'),
        'headers': _parse_headers(lines[1:]),
    }

def parse_response_block(block_text):
    if not block_text:
        return None
    lines = _split_header_block(block_text)
    if not lines:
        return None

    m = _status_line_v1.match(lines[0]) or _status_line_h2.match(lines[0])
    if not m:
        return None

    code = int(m.group('code'))
    reason = (m.group('reason') or '').strip()
    return {
        'version': m.group('version'),
        'status_code': code,
        'reason': reason,
        'headers': _parse_headers(lines[1:]),
    }


_HTTP1_REQ_BLOCK = re.compile(
    r'(?ms)^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+\S+\s+HTTP/\d\.\d\s*\n'
    r'(?:.*?\n)*?\n'
)

_HTTP2_SYN_REQ_BLOCK = re.compile(
    r'(?ms)^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+\S+\s+HTTP/2(?:\.0)?\s*\n'
    r'(?:.*?\n)*?\n'
)

_HTTP2_BRACKET_LINE = re.compile(
    r'^\[HTTP/2\]\s*\[(?P<stream>\d+)\]\s*\[(?P<kv>.+?)\]\s*$'
)

def _extract_http2_bracket_request(text):
    t = _normalize(text)
    lines = t.split('\n')


    per_stream = {}
    order = []
    for line in lines:
        m = _HTTP2_BRACKET_LINE.match(line)
        if not m:
            continue
        stream = m.group('stream')
        kv = m.group('kv')
        if stream not in per_stream:
            per_stream[stream] = []
            order.append(stream)
        per_stream[stream].append(kv)

    if not order:
        return (None, None)

    for stream in order:
        kvs = per_stream[stream]
        pseudo = {}
        normal = []
        for kv in kvs:
            if ':' not in kv:
                continue
            name, value = kv.split(':', 1)
            name = name.strip()
            value = value.strip()

            if name == '' and value:
                if ':' in value:
                    n2, v2 = value.split(':', 1)
                    pseudo[':' + n2.strip()] = v2.strip()
                continue

            normal.append((name, value))

        if ':method' in pseudo and ':path' in pseudo:
            method = pseudo[':method']
            path = pseudo[':path']
            authority = pseudo.get(':authority')

            block_lines = []
            block_lines.append('%s %s HTTP/2' % (method, path))
            if authority:
                block_lines.append('Host: %s' % authority)

            for (name, value) in normal:
                block_lines.append('%s: %s' % (name, value))
            block_lines.append('')

            return ('\n'.join(block_lines), stream)

    return (None, None)


_HTTP1_RESP_BLOCK = re.compile(
    r'(?ms)^HTTP/\d\.\d\s+\d{3}.*\n(?:.*?\n)*?\n'
)
_HTTP2_RESP_BLOCK = re.compile(
    r'(?ms)^HTTP/2(?:\.0)?\s+\d{3}.*\n(?:.*?\n)*?\n'
)

def extract_request_and_response(debug_text):
    t = _normalize(debug_text)

    m = _HTTP1_REQ_BLOCK.search(t)
    if m:
        req_block = m.group(0)
    else:
        m2 = _HTTP2_SYN_REQ_BLOCK.search(t)
        if m2:
            req_block = m2.group(0)
        else:
            req_block, _stream = _extract_http2_bracket_request(t)

    mr2 = _HTTP2_RESP_BLOCK.search(t)
    mr1 = _HTTP1_RESP_BLOCK.search(t)
    if mr2 and mr1:
        resp_block = mr2.group(0) if mr2.start() < mr1.start() else mr1.group(0)
    elif mr2:
        resp_block = mr2.group(0)
    elif mr1:
        resp_block = mr1.group(0)
    else:
        resp_block = None

    return req_block, resp_block

def parse_pycurl_verbose(fileobj_or_text):
    if hasattr(fileobj_or_text, 'read'):
        text = read_all(fileobj_or_text)
    else:
        if isinstance(fileobj_or_text, bytes):
            text = fileobj_or_text.decode('utf-8', 'replace')
        else:
            text = fileobj_or_text

    req_block, resp_block = extract_request_and_response(text)
    return {
        'raw': {'request': req_block, 'response': resp_block},
        'request': parse_request_block(req_block) if req_block else None,
        'response': parse_response_block(resp_block) if resp_block else None,
    }

def decode_headers_any(headers):
    if hasattr(headers, "items"):
        pairs = headers.items()
    else:
        pairs = headers

    return {
        (k.decode("ascii", "replace") if isinstance(k, (bytes, bytearray)) else str(k)):
        (v.decode("latin-1", "replace") if isinstance(v, (bytes, bytearray)) else str(v))
        for k, v in pairs
    }

def _is_many_specs(value):
    return (
        isinstance(value, (list, tuple)) and value and
        isinstance(value[0], (list, tuple)) and len(value[0]) >= 2
    )


def _normalize_ctype(filename, ctype):
    if ctype == "textplain":
        return "text/plain"
    if ctype:
        return ctype
    if guess_type:
        guessed = guess_type(filename)[0]
        if guessed:
            return guessed
    return "application/octet-stream"


def _ensure_ext(filename, default_ext=".txt"):
    if "." not in filename:
        return filename + default_ext
    return filename


def _read_fileobj(fobj):
    data = fobj.read()
    try:
        fobj.seek(0)
    except Exception:
        pass
    return data


def to_requests_files(payload, default_ext=".txt"):
    out = []
    items = payload.items()

    for filename, spec in items:
        if not isinstance(filename, text_type):
            filename = text_type(filename)

        filename2 = _ensure_ext(filename, default_ext)

        specs = spec if _is_many_specs(spec) else [spec]

        for one in specs:
            if not isinstance(one, (list, tuple)) or len(one) < 2:
                raise ValueError("Bad spec for %r: expected [fieldname, fileobj, (optional) ctype]" % filename)

            fieldname = one[0]
            fobj = one[1]
            ctype = one[2] if len(one) > 2 else None

            ctype = _normalize_ctype(filename2, ctype)
            data = _read_fileobj(fobj)

            out.append((fieldname, (filename2, data, ctype)))

    return out

def to_pycurl_httpost(payload, default_ext=".txt"):

    http_post = []
    for filename, spec in payload.items():
        if not isinstance(filename, text_type):
            filename = text_type(filename)

        filename2 = _ensure_ext(filename, default_ext)
        specs = spec if _is_many_specs(spec) else [spec]

        for one in specs:
            if not isinstance(one, (list, tuple)) or len(one) < 2:
                raise ValueError("Bad spec for %r: expected [fieldname, fileobj, (optional) ctype]" % filename)

            fieldname = one[0]
            fobj = one[1]
            ctype = one[2] if len(one) > 2 else None
            ctype = _normalize_ctype(filename2, ctype)

            data = fobj.read()
            try:
                fobj.seek(0)
            except Exception:
                pass

            if isinstance(data, text_type):
                data = data.encode("utf-8")

            http_post.append((
                fieldname,
                (
                    pycurl.FORM_BUFFER, filename2,
                    pycurl.FORM_BUFFERPTR, data,
                    pycurl.FORM_CONTENTTYPE, ctype,
                )
            ))

    return http_post

class ResponseStream(io.RawIOBase):
    def __init__(self, body_iter):
        self.body = body_iter

    def read(self, n=-1):
        try:
            # Yields the next chunk from the HTTPCore stream
            return next(self.body)
        except StopIteration:
            return b""

def fix_localhost_cookies(jar: cookielib.CookieJar) -> None:

    to_add = []
    to_del = []

    for c in jar:
        if getattr(c, "domain", None) == "localhost.local":
            to_del.append((c.domain, c.path, c.name))

            # Some Python versions store extra attrs in _rest, some in other places.
            rest = getattr(c, "rest", None)
            if rest is None:
                rest = getattr(c, "_rest", {}) or {}
            if not isinstance(rest, dict):
                rest = {}

            new_cookie = cookielib.Cookie(
                version=getattr(c, "version", 0),
                name=c.name,
                value=c.value,
                port=getattr(c, "port", None),
                port_specified=getattr(c, "port_specified", False),

                domain="localhost",
                domain_specified=False,       # host-only
                domain_initial_dot=False,

                path=getattr(c, "path", "/"),
                path_specified=getattr(c, "path_specified", True),

                secure=getattr(c, "secure", False),
                expires=getattr(c, "expires", None),
                discard=getattr(c, "discard", True),

                comment=getattr(c, "comment", None),
                comment_url=getattr(c, "comment_url", None),

                rest=rest,
                rfc2109=getattr(c, "rfc2109", False),
            )
            to_add.append(new_cookie)

    for dom, path, name in to_del:
        jar.clear(domain=dom, path=path, name=name)

    for c in to_add:
        jar.set_cookie(c)

def _cookie_header_from_jar(jar, url):
    u = urlparse(url)
    host = (u.hostname or "").lower()
    path = u.path or "/"
    secure = (u.scheme == "https")

    pairs = []
    now = int(time.time())

    for c in jar:
        # expired?
        if c.expires is not None and c.expires != 0 and c.expires < now:
            continue
        # secure?
        if c.secure and not secure:
            continue
        # domain match
        cd = (c.domain or "").lstrip(".").lower()
        if cd and host != cd and not host.endswith("." + cd):
            continue
        # path match
        cp = c.path or "/"
        if not path.startswith(cp):
            continue

        pairs.append("{}={}".format(c.name, c.value))

    return "; ".join(pairs)

def _update_jar_from_set_cookie(jar, url, set_cookie_values):
    u = urlparse(url)
    host = (u.hostname or "").lower()
    default_path = u.path or "/"
    if "/" in default_path:
        default_path = default_path.rsplit("/", 1)[0] or "/"

    if not set_cookie_values:
        return

    string_types = (str,)

    if isinstance(set_cookie_values, string_types):
        set_cookie_values = [set_cookie_values]

    for hdr in set_cookie_values:
        sc = SimpleCookie()
        sc.load(hdr)

        for name, morsel in sc.items():
            value = morsel.value

            domain = morsel["domain"] or host
            path = morsel["path"] or default_path
            secure = bool(morsel["secure"])
            expires = None  # (best effort placeholder)

            cookie = cookielib.Cookie(
                version=0,
                name=name,
                value=value,
                port=None,
                port_specified=False,
                domain=domain,
                domain_specified=bool(morsel["domain"]),
                domain_initial_dot=domain.startswith("."),
                path=path,
                path_specified=bool(morsel["path"]),
                secure=secure,
                expires=expires,
                discard=False,
                comment=None,
                comment_url=None,
                rest={},  # could add HttpOnly/SameSite if desired
                rfc2109=False,
            )
            jar.set_cookie(cookie)

def download_file_from_http_file(url, headers=None, usehttp=__use_http_lib__, usesslcert=defcert, resumefile=None, keepsession=False, insessionvar=None, httpuseragent=None, httpreferer=None, httpcookie=None, httpmethod="GET", postdata=None, jsonpost=False, sendfiles=None, putfile=None, timeout=60, returnstats=False):
    if headers is None:
        headers = {}
    else:
        if(isinstance(headers, list)):
            headers = make_http_headers_from_list_to_dict(headers)
    if httpcookie is None:
        name = hashlib.sha1(getpass.getuser().encode("utf-8")).hexdigest() + ".txt"
        httpcookie = os.path.join(tempfile.gettempdir(), name)
    cookie_name, cookie_ext = os.path.splitext(httpcookie)
    cookiefile = httpcookie
    if(usehttp!="pycurl" or not havepycurl):
        if(cookie_ext == ".lwp"):
            policy = cookielib.DefaultCookiePolicy(netscape=True, rfc2965=False, hide_cookie2=True)
            httpcookie = cookielib.LWPCookieJar(cookiefile, policy=policy)
        else:
            policy = cookielib.DefaultCookiePolicy(netscape=True, rfc2965=False, hide_cookie2=True)
            httpcookie = cookielib.MozillaCookieJar(cookiefile, policy=policy)
        if os.path.exists(cookiefile):
            httpcookie.load(ignore_discard=True, ignore_expires=True)
        if(usehttp=="httpcore" or usehttp=="urllib3"):
            openeralt = build_opener(HTTPCookieProcessor(httpcookie))
            install_opener(openeralt)
    p = urlparse(url)
    username = unquote(p.username) if p.username else None
    password = unquote(p.password) if p.password else None
    if(httpmethod is None):
        httpmethod = "GET"
    httpmethod = httpmethod.upper()
    # Strip auth from URL
    netloc = p.hostname or ""
    if p.port:
        netloc += ":" + str(p.port)
    rebuilt_url = urlunparse((p.scheme, netloc, p.path, p.params, p.query, p.fragment))
    extendargs = {}

    if(resumefile is not None and hasattr(resumefile, "write")):
        resumefile.seek(0, 2)
        if('Range' in headers):
            headers['Range'] = "bytes=%d-" % resumefile.tell()
        else:
            headers.update({'Range': "bytes=%d-" % resumefile.tell()})
        httpfile = resumefile
    else:
        httpfile = MkTempFile()

    if(httpuseragent is not None):
        if('User-Agent' in headers):
            headers['User-Agent'] = httpuseragent
        else:
            headers.update({'User-Agent': httpuseragent})
    if(httpreferer is not None):
        if('Referer' in headers):
            headers['Referer'] = httpreferer
        else:
            headers.update({'Referer': httpreferer})

    socket.setdefaulttimeout(float(timeout))
    start_time = time.time()

    # Requests
    if usehttp == "requests" and haverequests:
        auth = (username, password) if (username and password) else None
        extendargs.update({'url': rebuilt_url, 'method': httpmethod, 'headers': headers, 'auth': auth, 'stream': True, 'allow_redirects': True, 'timeout': (float(timeout), float(timeout))})
        if(insessionvar is not None):
            session = insessionvar
        else:
            session = requests.Session()
        session.cookies = httpcookie
        try:
            if(httpmethod == "POST"):
                if(putfile is not None and sendfiles is not None):
                    putfile = None
                if(putfile is not None):
                    putfile.seek(0, 0)
                    extendargs.update({'data': putfile})
                if(sendfiles is not None and isinstance(sendfiles, dict)):
                    jsonpost = False
                    sendfiles = to_requests_files(sendfiles)
                    if(sendfiles is not None):
                        for _, (_, fobj, *_) in sendfiles:
                            if hasattr(fobj, "seek"):
                                fobj.seek(0)
                    extendargs.update({'files': sendfiles})
                if(jsonpost and postdata is not None):
                    extendargs.update({'json': postdata})
                elif(not jsonpost and postdata is not None):
                    extendargs.update({'data': postdata})
            elif(httpmethod == "PUT" or httpmethod == "PATCH" or httpmethod == "DELETE"):
                if(putfile is not None and sendfiles is not None):
                    sendfiles = None
                if(putfile is not None):
                    putfile.seek(0, 0)
                    extendargs.update({'data': putfile})
                if(sendfiles is not None and isinstance(sendfiles, dict)):
                    jsonpost = False
                    sendfiles = to_requests_files(sendfiles)
                    if(sendfiles is not None):
                        for _, (_, fobj, *_) in sendfiles:
                            if hasattr(fobj, "seek"):
                                fobj.seek(0)
                    extendargs.update({'files': sendfiles})
                if(jsonpost and postdata is not None):
                    extendargs.update({'json': postdata})
                elif(not jsonpost and postdata is not None and (isinstance(sendfiles, dict) or sendfiles is None)):
                    extendargs.update({'data': postdata})
            if(usesslcert is None):
                pass
            else:
                extendargs.update({'verify': usesslcert})
            r = session.request(**extendargs)
            r.raise_for_status()
        except requests.exceptions.HTTPError as e:
            r = e.response
        except (socket.timeout, socket.gaierror, requests.exceptions.ConnectionError):
            return False
        r.raw.decode_content = True
        if(resumefile is not None and hasattr(resumefile, "write")):
            if r.status_code == 206 and "Content-Range" in r.headers:
                pass
            else:
                httpfile.truncate(0)
                httpfile.seek(0, 0)
        #shutil.copyfileobj(r.raw, httpfile)
        for chunk in r.iter_content(chunk_size=1024 * 1024):
            if chunk:
                httpfile.write(chunk)
        fix_localhost_cookies(httpcookie)
        session.cookies.save(ignore_discard=True, ignore_expires=True)
        httpcodeout = r.status_code
        httpcodereason = r.reason
        vertostr = {
                    10: "HTTP/1.0",
                    11: "HTTP/1.1"
        }
        try:
            httpversionout = vertostr[r.raw.version]
        except AttributeError:
            httpversionout = "HTTP/1.1"
        httpmethodout = httpmethod
        httpurlout = r.url
        httpheaderout = r.headers
        httpheadersentout = r.request.headers
        httpsession = session
        if((not keepsession and not returnstats) or not keepsession or httpmethod == "HEAD"):
            session.close()
            httpsession = None

    # HTTPX
    elif usehttp == "httpx" and havehttpx:
        try:
            import h2
            usehttp2 = True
        except ImportError:
            usehttp2 = False
        try:
            if(insessionvar is not None):
                client = insessionvar
            else:
                if(usesslcert is None):
                    client = httpx.Client(follow_redirects=True, http1=True, http2=usehttp2, trust_env=True, timeout=float(timeout), cookies=httpcookie)
                else:
                    context = ssl.create_default_context()
                    context.load_verify_locations(cafile=usesslcert)
                    client = httpx.Client(follow_redirects=True, http1=True, http2=usehttp2, trust_env=True, timeout=float(timeout), cookies=httpcookie, verify=context)
            auth = (username, password) if (username and password) else None
            extendargs.update({'url': rebuilt_url, 'method': httpmethod, 'headers': headers, 'auth': auth, 'cookies': httpcookie})
            if(httpmethod == "POST"):
                if(putfile is not None and sendfiles is not None):
                    putfile = None
                if(putfile is not None):
                    putfile.seek(0, 0)
                    extendargs.update({'content': putfile})
                if(sendfiles is not None and isinstance(sendfiles, dict)):
                    jsonpost = False
                    sendfiles = to_requests_files(sendfiles)
                    if(sendfiles is not None):
                        for _, (_, fobj, *_) in sendfiles:
                            if hasattr(fobj, "seek"):
                                fobj.seek(0)
                    extendargs.update({'files': sendfiles})
                if(jsonpost and postdata is not None):
                    extendargs.update({'json': postdata})
                elif(not jsonpost and postdata is not None):
                    extendargs.update({'data': postdata})
            elif(httpmethod == "PUT" or httpmethod == "PATCH" or httpmethod == "DELETE"):
                if(putfile is not None and sendfiles is not None):
                    sendfiles = None
                if(putfile is not None):
                    putfile.seek(0, 0)
                    extendargs.update({'content': putfile})
                if(sendfiles is not None and isinstance(sendfiles, dict)):
                    jsonpost = False
                    sendfiles = to_requests_files(sendfiles)
                    if(sendfiles is not None):
                        for _, (_, fobj, *_) in sendfiles:
                            if hasattr(fobj, "seek"):
                                fobj.seek(0)
                    extendargs.update({'files': sendfiles})
                if(jsonpost and postdata is not None):
                    extendargs.update({'json': postdata})
                elif(not jsonpost and postdata is not None):
                    extendargs.update({'data': postdata})
            r = client.request(**extendargs)
            r.raise_for_status()
        except httpx.HTTPStatusError as e:
            r = e.response
        except (socket.timeout, socket.gaierror, httpx.ConnectError):
            return False
        if(resumefile is not None and hasattr(resumefile, "write")):
            if r.status_code == 206 and "Content-Range" in r.headers:
                pass
            else:
                httpfile.truncate(0)
                httpfile.seek(0, 0)
        for chunk in r.iter_bytes(chunk_size=1024 * 1024):
            if chunk:
                httpfile.write(chunk)
        fix_localhost_cookies(httpcookie)
        httpcookie.save(cookiefile, ignore_discard=True, ignore_expires=True)
        httpcodeout = r.status_code
        try:
            httpcodereason = r.reason_phrase
        except:
            httpcodereason = http_status_to_reason(r.status_code)
        httpversionout = r.http_version
        httpmethodout = httpmethod
        httpurlout = str(r.url)
        httpheaderout = {
            k.decode("ascii", errors="replace")
            if isinstance(k, (bytes, bytearray)) else str(k):
            v.decode("ascii", errors="replace")
            if isinstance(v, (bytes, bytearray)) else str(v)
            for k, v in r.headers.items()
        }
        httpheadersentout = r.request.headers
        httpsession = client
        if((not keepsession and not returnstats) or not keepsession or httpmethod == "HEAD"):
            client.close()
            httpsession = None


    # HTTPCore
    elif usehttp == "httpcore" and havehttpcore:
        try:
            import h2
            usehttp2 = True
        except ImportError:
            usehttp2 = False
        if(insessionvar is not None):
            client = insessionvar
        else:
            client = httpcore.ConnectionPool(http1=True, http2=usehttp2)
        timeoutdict = {"connect": float(timeout), "read": float(timeout), "write": float(timeout), "pool": float(timeout)}
        if(usesslcert is None):
            extdict = {'extensions': {"timeout": timeoutdict}}
        else:
            context = ssl.create_default_context()
            context.load_verify_locations(cafile=usesslcert)
            extdict = {'extensions': {"timeout": timeoutdict, 'ssl_context': context}}
        extendargs.update({'url': rebuilt_url, 'method': httpmethod})
        extendargs.update(extdict)
        if(httpmethod == "POST" or httpmethod == "PUT" or httpmethod == "PATCH" or httpmethod == "DELETE"):
            if(jsonpost and postdata is not None and putfile is None):
                if('Content-Type' in headers):
                    headers['Content-Type'] = "application/json"
                else:
                    headers.update({'Content-Type': "application/json"})
                extendargs.update({'content': json.dumps(postdata).encode('UTF-8')})
            elif(not jsonpost and postdata is not None and putfile is None):
                if('Content-Type' in headers):
                    headers['Content-Type'] = "application/x-www-form-urlencoded"
                else:
                    headers.update({'Content-Type': "application/x-www-form-urlencoded"})
                extendargs.update({'content': urlencode(postdata).encode('UTF-8')})
            elif(putfile is not None):
                putfile.seek(0, 2)
                if('Content-Type' in headers):
                    headers['Content-Type'] = "application/octet-stream"
                else:
                    headers.update({'Content-Type': "application/octet-stream"})
                if('Content-Length' in headers):
                    headers['Content-Length'] = str(putfile.tell())
                else:
                    headers.update({'Content-Length': str(putfile.tell())})
                putfile.seek(0, 0)
                extendargs.update({'content': putfile})
        extendargs.update({'headers': headers})
        try:
            with client.stream(**extendargs, ) as r:
                decoded_headers = decode_headers_any(r.headers)
                if(resumefile is not None and hasattr(resumefile, "write")):
                    if r.status == 206 and "Content-Range" in decoded_headers:
                        pass
                    else:
                        httpfile.truncate(0)
                        httpfile.seek(0, 0)
                shutil.copyfileobj(ResponseStream(r.iter_stream()), httpfile, length=1024 * 1024)
        except (socket.timeout, socket.gaierror, httpcore.ConnectError):
            return False
        fix_localhost_cookies(httpcookie)
        httpcookie.save(cookiefile, ignore_discard=True, ignore_expires=True)
        httpcodeout = r.status
        httpcodereason = http_status_to_reason(r.status)
        httpversionout = r.extensions.get("http_version")
        if isinstance(httpversionout, (bytes, bytearray)):
            httpversionout = httpversionout.decode("ascii", errors="replace")
        httpmethodout = httpmethod
        httpurlout = str(rebuilt_url)
        httpheaderout = decoded_headers
        httpheadersentout = headers
        httpsession = client
        if((not keepsession and not returnstats) or not keepsession or httpmethod == "HEAD"):
            client.close()
            httpsession = None

    # Mechanize
    elif usehttp == "mechanize" and havemechanize:
        if(insessionvar is not None):
            br = insessionvar
        else:
            br = mechanize.Browser()
        br.set_cookiejar(httpcookie)
        br.set_handle_robots(False)

        if(usesslcert is None):
            pass
        else:
            br.set_ca_data(cafile=usesslcert)

        if username and password:
            br.add_password(rebuilt_url, username, password)
        if(not jsonpost and postdata is not None and not isinstance(postdata, dict)):
            postdata = urlencode(postdata).encode('UTF-8')
        elif(jsonpost and postdata is not None and not isinstance(postdata, dict)):
            postdata = json.dumps(postdata).encode('UTF-8')
        try:
            if(httpmethod == "GET"):
                if headers:
                    br.addheaders = list(headers.items())
                resp = br.open(rebuilt_url, timeout=timeout)
            elif(httpmethod == "POST"):
                extendargs.update({'timeout': float(timeout)})
                if(jsonpost and postdata is not None):
                    if('Content-Type' in headers):
                        headers['Content-Type'] = "application/json"
                    else:
                        headers.update({'Content-Type': "application/json"})
                    extendargs.update({'data': json.dumps(postdata)})
                else:
                    extendargs.update({'data': urlencode(postdata).encode("ascii")})
                if headers:
                    br.addheaders = list(headers.items())
                resp = br.open(rebuilt_url, **extendargs)
            else:
                if headers:
                    br.addheaders = list(headers.items())
                resp = br.open(rebuilt_url, timeout=timeout)
        except HTTPError as e:
            resp = e
        except (socket.timeout, socket.gaierror, URLError):
            return False
        if(resumefile is not None and hasattr(resumefile, "write")):
            if resp.code == 206 and "Content-Range" in dict(resp.info()):
                pass
            else:
                httpfile.truncate(0)
                httpfile.seek(0, 0)
        shutil.copyfileobj(resp, httpfile, length=1024 * 1024)
        fix_localhost_cookies(httpcookie)
        httpcookie.save(cookiefile, ignore_discard=True, ignore_expires=True)
        httpcodeout = resp.code
        httpcodereason = resp.msg
        vertostr = {
                    10: "HTTP/1.0",
                    11: "HTTP/1.1"
        }
        try:
            httpversionout = vertostr[br.version]
        except AttributeError:
            httpversionout = "HTTP/1.1"
        httpmethodout = httpmethod
        httpurlout = resp.geturl()
        httpheaderout = dict(resp.info())
        reqhead = br.request
        httpheadersentout = reqhead.header_items()
        httpsession = br
        if((not keepsession and not returnstats) or not keepsession or httpmethod == "HEAD"):
            br.close()
            httpsession = None

    # URLLib3
    elif usehttp == "urllib3" and haveurllib3:
        if(insessionvar is not None):
            http = insessionvar
        else:
            if(usesslcert is None):
                http = urllib3.PoolManager(timeout=urllib3.Timeout(total=float(timeout)))
            else:
                http = urllib3.PoolManager(timeout=urllib3.Timeout(total=float(timeout)), cert_reqs='CERT_REQUIRED', ca_certs=usesslcert)
        if username and password:
            auth_headers = urllib3.make_headers(basic_auth="{}:{}".format(username, password))
            headers.update(auth_headers)
        # Request with preload_content=False to get a file-like object
        try:
            extendargs.update({'url': rebuilt_url, 'method': httpmethod, 'headers': headers, 'preload_content': False, 'decode_content': True})
            if(httpmethod == "POST"):
                if(putfile is not None and sendfiles is not None):
                    putfile = None
                if(putfile is not None and not isinstance(putfile, dict)):
                    putfile.seek(0, 0)
                    extendargs.update({'body': putfile})
                if(sendfiles is not None and isinstance(sendfiles, dict)):
                    jsonpost = False
                    sendfiles = to_requests_files(sendfiles)
                    if(sendfiles is not None):
                        for _, (_, fobj, *_) in sendfiles:
                            if hasattr(fobj, "seek"):
                                fobj.seek(0)
                    extendargs.update({'fields': sendfiles})
                if(jsonpost and postdata is not None):
                    extendargs.update({'json': postdata})
                elif(not jsonpost and postdata is not None):
                    if('fields' in extendargs):
                        extendargs['fields'].update({postdata})
                    else:
                        extendargs.update({'fields': postdata})
            elif(httpmethod == "PUT" or httpmethod == "PATCH" or httpmethod == "DELETE"):
                if(putfile is not None and sendfiles is not None):
                    sendfiles = None
                if(putfile is not None and not isinstance(putfile, dict)):
                    putfile.seek(0, 0)
                    extendargs.update({'body': putfile})
                if(sendfiles is not None and isinstance(sendfiles, dict)):
                    jsonpost = False
                    sendfiles = to_requests_files(sendfiles)
                    if(sendfiles is not None):
                        for _, (_, fobj, *_) in sendfiles:
                            if hasattr(fobj, "seek"):
                                fobj.seek(0)
                    extendargs.update({'fields': sendfiles})
                if(jsonpost and postdata is not None):
                    extendargs.update({'json': postdata})
                elif(not jsonpost and postdata is not None):
                    if('fields' in extendargs):
                        extendargs['fields'].update({postdata})
                    else:
                        extendargs.update({'fields': postdata})
            cookie_hdr = _cookie_header_from_jar(httpcookie, rebuilt_url)
            if cookie_hdr:
                headers["Cookie"] = cookie_hdr
            resp = http.request(**extendargs)
            set_cookie_vals = resp.headers.getlist("Set-Cookie")  # returns [] if none
            _update_jar_from_set_cookie(httpcookie, rebuilt_url, set_cookie_vals)
        except (socket.timeout, socket.gaierror, urllib3.exceptions.MaxRetryError):
            return False
        if(resumefile is not None and hasattr(resumefile, "write")):
            if resp.status == 206 and "Content-Range" in dict(resp.info()):
                pass
            else:
                httpfile.truncate(0)
                httpfile.seek(0, 0)
        shutil.copyfileobj(resp, httpfile, length=1024 * 1024)
        fix_localhost_cookies(httpcookie)
        httpcookie.save(cookiefile, ignore_discard=True, ignore_expires=True)
        httpcodeout = resp.status
        httpcodereason = resp.reason
        vertostr = {
                    10: "HTTP/1.0",
                    11: "HTTP/1.1"
        }
        try:
            httpversionout = vertostr[resp.version]
        except AttributeError:
            httpversionout = "HTTP/1.1"
        httpmethodout = httpmethod
        httpurlout = resp.geturl()
        httpheaderout = dict(resp.info())
        httpheadersentout = headers
        resp.release_conn()
        httpsession = http
        if((not keepsession and not returnstats) or not keepsession or httpmethod == "HEAD"):
            http.clear()
            httpsession = None

    elif(usehttp == "pycurl" and havepycurl):
        retrieved_body = MkTempFile()
        retrieved_headers = MkTempFile()
        sentout_headers = MkTempFile()
        if(insessionvar is not None):
            curlreq = insessionvar
        else:
            curlreq = pycurl.Curl()
        if(hasattr(pycurl, "CURL_HTTP_VERSION_3_0")):
            usehttpver = pycurl.CURL_HTTP_VERSION_3_0
        elif(hasattr(pycurl, "CURL_HTTP_VERSION_2_0")):
            usehttpver = pycurl.CURL_HTTP_VERSION_2_0
        else:
            usehttpver = pycurl.CURL_HTTP_VERSION_1_1
        curlreq.setopt(pycurl.URL, rebuilt_url)
        curlreq.setopt(pycurl.HTTP_VERSION, usehttpver)
        curlreq.setopt(pycurl.WRITEDATA, retrieved_body)
        curlreq.setopt(pycurl.WRITEHEADER, retrieved_headers)
        curlreq.setopt(pycurl.VERBOSE, 1)
        if(usesslcert is None):
            pass
        else:
            curlreq.setopt(pycurl.CAINFO, usesslcert)
        curlreq.setopt(pycurl.DEBUGFUNCTION, lambda t, m: sentout_headers.write(m))
        curlreq.setopt(pycurl.FOLLOWLOCATION, True)
        curlreq.setopt(pycurl.TIMEOUT, timeout)
        # Load cookies from this file at the start
        curlreq.setopt(pycurl.COOKIEFILE, cookiefile)
        # Save cookies to this file when c.close() is called
        curlreq.setopt(pycurl.COOKIEJAR, cookiefile)
        if(httpmethod == "GET"):
            curlreq.setopt(pycurl.HTTPGET, True)
        elif(httpmethod == "POST"):
            if(putfile is not None and sendfiles is not None):
                putfile = None
            curlreq.setopt(pycurl.POST, True)
            if(sendfiles is not None):
                jsonpost = False
                sendfiles = to_pycurl_httpost(sendfiles)
                curlreq.setopt(pycurl.HTTPPOST, sendfiles)
            if(jsonpost and postdata is not None):
                if('Content-Type' in headers):
                    headers['Content-Type'] = "application/json"
                else:
                    headers.update({'Content-Type': "application/json"})
                    curlreq.setopt(pycurl.POSTFIELDS, json.dumps(postdata).encode('UTF-8'))
            elif(not jsonpost and postdata is not None):
                curlreq.setopt(pycurl.POSTFIELDS, urlencode(postdata).encode('UTF-8'))
        elif(httpmethod == "PUT" or httpmethod == "PATCH" or httpmethod == "DELETE"):
            if(putfile is not None and sendfiles is not None):
                sendfiles = None
            curlreq.setopt(pycurl.CUSTOMREQUEST, httpmethod)
            if(putfile is not None):
                putfile.seek(0, 2)
                if('Content-Type' in headers):
                    headers['Content-Type'] = "application/octet-stream"
                else:
                    headers.update({'Content-Type': "application/octet-stream"})
                if('Content-Length' in headers):
                    headers['Content-Length'] = str(putfile.tell())
                else:
                    headers.update({'Content-Length': str(putfile.tell())})
                curlreq.setopt(pycurl.UPLOAD, True)
                putfile.seek(0, 0)
                curlreq.setopt(pycurl.READDATA, putfile)
            if(sendfiles is not None):
                jsonpost = False
                sendfiles = to_pycurl_httpost(sendfiles)
                curlreq.setopt(pycurl.HTTPPOST, sendfiles)
            if(jsonpost and postdata is not None):
                if('Content-Type' in headers):
                    headers['Content-Type'] = "application/json"
                else:
                    headers.update({'Content-Type': "application/json"})
                    curlreq.setopt(pycurl.POSTFIELDS, json.dumps(postdata).encode('UTF-8'))
            elif(not jsonpost and postdata is not None):
                curlreq.setopt(pycurl.POSTFIELDS, urlencode(postdata).encode('UTF-8'))
        else:
            curlreq.setopt(pycurl.HTTPGET, True)
        headers = make_http_headers_from_dict_to_pycurl(headers)
        curlreq.setopt(pycurl.HTTPHEADER, headers)
        try:
            curlreq.perform()
        except (socket.timeout, socket.gaierror, pycurl.error):
            curlreq.close()
            return False
        retrieved_headers.seek(0, 0)
        sentout_headers.seek(0, 0)
        httpheadersentpre = parse_pycurl_verbose(sentout_headers)
        sentout_headers.close()
        if(sys.version[0] == "2"):
            pycurlhead = retrieved_headers.read()
        if(sys.version[0] >= "3"):
            pycurlhead = retrieved_headers.read().decode('UTF-8')
        pycurlheadersout = make_http_headers_from_pycurl_to_dict(pycurlhead)
        retrieved_body.seek(0, 0)
        httpfile = retrieved_body
        retrieved_headers.close()
        HTTP_VERSION_MAP = {
            pycurl.CURL_HTTP_VERSION_1_0: "HTTP/1.0",
            pycurl.CURL_HTTP_VERSION_1_1: "HTTP/1.1",
        }
        if hasattr(pycurl, "CURL_HTTP_VERSION_2"):
            HTTP_VERSION_MAP[pycurl.CURL_HTTP_VERSION_2] = "HTTP/2.0"
        if hasattr(pycurl, "CURL_HTTP_VERSION_3"):
            HTTP_VERSION_MAP[pycurl.CURL_HTTP_VERSION_3] = "HTTP/3.0"
        ver_enum = curlreq.getinfo(pycurl.INFO_HTTP_VERSION)
        httpcodeout = curlreq.getinfo(pycurl.HTTP_CODE)
        httpcodereason = http_status_to_reason(curlreq.getinfo(pycurl.HTTP_CODE))
        httpversionout = HTTP_VERSION_MAP.get(ver_enum, "HTTP/1.1")
        httpmethodout = httpmethod
        httpurlout = curlreq.getinfo(pycurl.EFFECTIVE_URL)
        curlreq.close()
        httpheaderout = pycurlheadersout
        try:
            httpheadersentout = httpheadersentpre['request']['headers']
        except TypeError:
            httpheadersentout = headers
        httpsession = curlreq
        if((not keepsession and not returnstats) or not keepsession or httpmethod == "HEAD"):
            curlreq.close()
            httpsession = None

    # urllib fallback
    else:
        extendargs.update({'url': rebuilt_url, 'method': httpmethod})
        if(httpmethod == "POST" or httpmethod == "PUT" or httpmethod == "PATCH" or httpmethod == "DELETE"):
            if(putfile is not None and postdata is None):
                putfile.seek(0, 2)
                if('Content-Type' in headers):
                    headers['Content-Type'] = "application/octet-stream"
                else:
                    headers.update({'Content-Type': "application/octet-stream"})
                if('Content-Length' in headers):
                    headers['Content-Length'] = str(putfile.tell())
                else:
                    headers.update({'Content-Length': str(putfile.tell())})
                putfile.seek(0, 0)
                extendargs.update({'data': putfile})
            if(jsonpost and postdata is not None and putfile is None):
                if('Content-Type' in headers):
                    headers['Content-Type'] = "application/json"
                else:
                    headers.update({'Content-Type': "application/json"})
                extendargs.update({'data': json.dumps(postdata)})
            elif(not jsonpost and postdata is not None and putfile is None):
                extendargs.update({'data': urlencode(postdata).encode("ascii")})
        extendargs.update({'headers': headers})
        req = Request(**extendargs)
        handlers = [HTTPCookieProcessor(httpcookie)]
        if username and password:
            mgr = HTTPPasswordMgrWithDefaultRealm()
            mgr.add_password(None, rebuilt_url, username, password)
            handlers.insert(0, HTTPBasicAuthHandler(mgr))
        if(usesslcert is None):
            pass
        else:
            ssl_context = ssl.create_default_context()
            ssl_context.load_verify_locations(usesslcert)
            handlers.append(HTTPSHandler(context=ssl_context))
        if(insessionvar is not None):
            opener = insessionvar
        else:
            opener = build_opener(*handlers)        
        try:
            resp = opener.open(req, timeout=timeout)
        except HTTPError as e:
            resp = e;
        except (socket.timeout, socket.gaierror, URLError):
            return False
        resp2 = decoded_stream(resp)
        if(resumefile is not None and hasattr(resumefile, "write")):
            if resp.getcode() == 206 and "Content-Range" in dict(resp.info()):
                pass
            else:
                httpfile.truncate(0)
                httpfile.seek(0, 0)
        shutil.copyfileobj(resp2, httpfile, length=1024 * 1024)
        fix_localhost_cookies(httpcookie)
        httpcookie.save(ignore_discard=True, ignore_expires=True)
        httpcodeout = resp.getcode()
        try:
            httpcodereason = resp.reason
        except AttributeError:
            httpcodereason = http_status_to_reason(geturls_text.getcode())
        vertostr = {
                    10: "HTTP/1.0",
                    11: "HTTP/1.1"
        }
        try:
            httpversionout = vertostr[resp.version]
        except AttributeError:
            httpversionout = "HTTP/1.1"
        try:
            httpmethodout = resp.get_method()
        except AttributeError:
            httpmethodout = resp._method
        httpurlout = resp.geturl()
        httpheaderout = dict(resp.info())
        try:
            httpheadersentout =  req.unredirected_hdrs | req.headers
        except AttributeError:
            httpheadersentout = req.header_items()
        httpsession = opener
        if((not keepsession and not returnstats) or not keepsession or httpmethod == "HEAD"):
            httpsession = None


    fulldatasize = httpfile.tell()
    try:
        httpfile.seek(0, 0)
    except Exception:
        pass
    end_time = time.time()
    total_time = end_time - start_time
    if(not httpsession):
        httpsession = None
    if(returnstats):
        if(isinstance(httpheaderout, list)):
            httpheaderout = make_http_headers_from_list_to_dict(httpheaderout)
        httpheaderout = fix_header_names(httpheaderout)
        returnval = {'Type': "Buffer", 'Buffer': httpfile, 'Session': httpsession, 'ContentSize': fulldatasize, 'ContentsizeAlt': {'IEC': get_readable_size(
            fulldatasize, 2, "IEC"), 'SI': get_readable_size(fulldatasize, 2, "SI")}, 'Headers': httpheaderout, 'Version': httpversionout, 'Method': httpmethodout, 'HeadersSent': httpheadersentout, 'URL': httpurlout, 'Code': httpcodeout, 'Reason': httpcodereason, 'HTTPLib': usehttp, 'RequestTime': {'StartTime': start_time, 'EndTime': end_time, 'TotalTime': total_time}}
        return returnval
    else:
        if(httpmethod == "HEAD"):
            return httpheaderout
        else:
            return httpfile

def download_file_from_http_bytes(url, headers=None, usehttp=__use_http_lib__, usesslcert=defcert, resumefile=None, keepsession=False, insessionvar=None, httpuseragent=None, httpreferer=None, httpcookie=None, httpmethod="GET", postdata=None, jsonpost=False, sendfiles=None, putfile=None, timeout=60, returnstats=False):
    fp = download_file_from_http_file(url, headers, usehttp, usesslcert, resumefile, keepsession, insessionvar, httpuseragent, httpreferer, httpcookie, httpmethod, postdata, jsonpost, sendfiles, putfile, timeout, False)
    return fp.read() if fp else False

def download_file_from_http_to_file(url, outfile, headers=None, usehttp=__use_http_lib__, usesslcert=defcert, keepsession=False, insessionvar=None, httpuseragent=None, httpreferer=None, httpcookie=None, postdata=None, jsonpost=False, sendfiles=None, putfile=None, timeout=60):
    if(os.path.exists(outfile)):
        outfile = open(outfile, "ab")
        outfile.seek(0, 2)
        httpbytes = download_file_from_http_file(url, headers, usehttp, usesslcert, outfile, keepsession, insessionvar, httpuseragent, httpreferer, httpcookie, "GET", postdata, jsonpost, sendfiles, putfile, timeout, False)
        outfile.close()
    else:
        outfile = open(outfile, "wb")
        httpbytes = download_file_from_http_bytes(url, headers, usehttp, usesslcert, None, keepsession, insessionvar, httpuseragent, httpreferer, httpcookie, "GET", postdata, jsonpost, sendfiles, putfile, timeout, False)
        outfile.write(httpbytes)
        outfile.close()
    return True

def file_list_to_file_dict(infiles=None, infields=None):
    outdict = {}
    if(infiles is None):
        infiles = []
    if(infields is None):
        infields = []
    for files, fields in zip(infiles, infields):
        filename = os.path.basename(files)
        openfile = open(files, "rb")
        openfile.seek(0, 0)
        outdict.update({filename: [fields, openfile]})
    return outdict

def upload_file_to_http_file(infiles, url, headers=None, usehttp=__use_http_lib__, usesslcert=defcert, keepsession=False, insessionvar=None, httpuseragent=None, httpreferer=None, httpcookie=None, postdata=None, jsonpost=False, putfile=None, timeout=60, returnstats=False):
    return download_file_from_http_file(url, headers, usehttp, usesslcert, None, keepsession, insessionvar, httpuseragent, httpreferer, httpcookie, "POST", postdata, jsonpost, infiles, putfile, timeout, returnstats)

def upload_file_to_http_from_file(infiles, infields, url, headers=None, usehttp=__use_http_lib__, usesslcert=defcert, keepsession=False, insessionvar=None, httpuseragent=None, httpreferer=None, httpcookie=None, postdata=None, jsonpost=False, putfile=None, timeout=60, returnstats=False):
    infilelist = file_list_to_file_dict(infiles, infields)
    return upload_file_to_http_file(infilelist, url, headers, usehttp, usesslcert, keepsession, insessionvar, httpuseragent, httpreferer, httpcookie, postdata, jsonpost, putfile, timeout, returnstats)

def download_file_from_https_file(url, headers=None, usehttp=__use_http_lib__, usesslcert=defcert, resumefile=None, keepsession=False, insessionvar=None, httpuseragent=None, httpreferer=None, httpcookie=None, httpmethod="GET", postdata=None, jsonpost=False, sendfiles=None, putfile=None, timeout=60, returnstats=False):
    return download_file_from_http_file(url, headers, usehttp, usesslcert, resumefile, keepsession, insessionvar, httpuseragent, httpreferer, httpcookie, httpmethod, postdata, jsonpost, sendfiles, putfile, timeout, returnstats)

def download_file_from_https_bytes(url, headers=None, usehttp=__use_http_lib__, usesslcert=defcert, resumefile=None, keepsession=False, insessionvar=None, httpuseragent=None, httpreferer=None, httpcookie=None, httpmethod="GET", postdata=None, jsonpost=False, sendfiles=None, putfile=None, timeout=60, returnstats=False):
    return download_file_from_http_bytes(url, headers, usehttp, usesslcert, resumefile, keepsession, insessionvar, httpuseragent, httpreferer, httpcookie, httpmethod, postdata, jsonpost, sendfiles, putfile, timeout, returnstats)

def download_file_from_https_file(url, outfile, headers=None, usehttp=__use_http_lib__, usesslcert=defcert, keepsession=False, insessionvar=None, httpuseragent=None, httpreferer=None, httpcookie=None, postdata=None, jsonpost=False, sendfiles=None, putfile=None, timeout=60):
    return download_file_from_http_to_file(url, outfile, headers, usehttp, usesslcert, keepsession, insessionvar, httpuseragent, httpreferer, httpcookie, postdata, jsonpost, sendfiles, putfile, timeout)

def upload_file_to_https_file(infiles, url, headers=None, usehttp=__use_http_lib__, usesslcert=defcert, keepsession=False, insessionvar=None, httpuseragent=None, httpreferer=None, httpcookie=None, postdata=None, jsonpost=False, putfile=None, timeout=60, returnstats=False):
    return upload_file_to_http_from_file(infiles, url, headers, usehttp, usesslcert, keepsession, insessionvar, httpuseragent, httpreferer, httpcookie, postdata, jsonpost, putfile, timeout, returnstats)

def upload_file_to_https_from_file(infiles, infields, url, headers=None, usehttp=__use_http_lib__, usesslcert=defcert, keepsession=False, insessionvar=None, httpuseragent=None, httpreferer=None, httpcookie=None, postdata=None, jsonpost=False, putfile=None, timeout=60, returnstats=False):
    return upload_file_to_http_from_file(infiles, infields, url, headers, usehttp, usesslcert, keepsession, insessionvar, httpuseragent, httpreferer, httpcookie, postdata, jsonpost, putfile, timeout, returnstats)

_U_MAGIC = b"PWG2" 
_U_VER = 1
_U_HDR = "!4sBBIQ Q".replace(" ", "")
_U_HDR_LEN = struct.calcsize(_U_HDR)

_UF_DATA   = 0x01
_UF_ACK    = 0x02
_UF_DONE   = 0x04
_UF_RESUME = 0x08
_UF_META   = 0x10
_UF_CRC    = 0x20

# ---- Protocol constants ----
_PT_INITIAL   = 0x01
_PT_HANDSHAKE = 0x02
_PT_0RTT      = 0x03
_PT_1RTT      = 0x04
_PT_RETRY     = 0x05
_PT_CLOSE     = 0x1c

# Frames
_FT_STREAM = 0x10   # STREAM: stream_id(u16) + off(u32) + len(u16) + data
_FT_ACK    = 0x02   # ACK: largest(u32) + ack_upto(u32) + sack_mask(u64)
_FT_META   = 0x20   # META: total_len(u64) + flags(u8) + optional text + token?
_FT_RESUME = 0x21   # RESUME: next_offset(u64)
_FT_DONE   = 0x22   # DONE: "DONE" + sha256(32) optional
_FT_RETRY  = 0x23   # RETRY: token_len(u16) + token(bytes)

_MF_RESUME_REQ = 0x01
_MF_HAS_TOKEN  = 0x02

_MAGIC = b"UQIC"
_HDR_FMT = "!4sBBQIH"
_HDR_SZ = struct.calcsize(_HDR_FMT)
_TAG_SZ = 16


def _u_pack(flags, seq, total, tid):
    return struct.pack(
        _U_HDR,
        _U_MAGIC,
        _U_VER,
        int(flags) & 0xFF,
        int(seq) & 0xFFFFFFFF,
        int(total) & 0xFFFFFFFFFFFFFFFF,
        int(tid) & 0xFFFFFFFFFFFFFFFF,
    )

def _u_unpack(pkt):
    if not pkt or len(pkt) < _U_HDR_LEN:
        return None
    magic, ver, flags, seq, total, tid = struct.unpack(_U_HDR, pkt[:_U_HDR_LEN])
    if magic != _U_MAGIC or ver != _U_VER:
        return None
    return (flags, seq, total, tid, pkt[_U_HDR_LEN:])

def _net_log(verbose, msg, logger=None):
    if verbose:
        _emit(str(msg), logger=logger, level=logging.INFO, stream="stderr")

def _resolve_wait_timeout(scheme, mode, o):
    wt = o.get("wait_timeout", None)
    if wt is not None:
        try:
            return float(wt)
        except Exception:
            return wt
    if o.get("wait_forever"):
        return None
    tt = o.get("total_timeout", 0.0)
    try:
        if tt not in (None, 0, 0.0) and float(tt) > 0.0:
            return float(tt)
    except Exception:
        pass
    if scheme == "udp" and (mode or "seq") == "raw":
        return None
    return o.get("timeout", None)

def _parse_net_url(url):
    p = urlparse(url)
    qs = parse_qs(p.query or "")
    mode = _qstr(qs, "mode", "seq" if p.scheme == "udp" else "raw").lower()
    has_timeout = "timeout" in qs
    if p.scheme == "tcp" and not has_timeout:
        timeout = None
    else:
        timeout = float(_qnum(qs, "timeout", 1.0 if p.scheme == "udp" else 30.0, cast=float))
    accept_timeout = float(_qnum(qs, "accept_timeout", 0.0 if p.scheme == "tcp" else (timeout or 0.0), cast=float))
    total_timeout = float(_qnum(qs, "total_timeout", 0.0, cast=float))
    window = int(_qnum(qs, "window", 32, cast=int))
    retries = int(_qnum(qs, "retries", 20, cast=int))
    chunk = int(_qnum(qs, "chunk", 1200 if p.scheme == "udp" else 65536, cast=int))
    print_url = _qflag(qs, "print_url", False)
    if "wait" in qs:
        wait = _qflag(qs, "wait", False)
    else:
        wait = (p.scheme == "udp" and mode == "raw")
    if "connect_wait" in qs:
        connect_wait = _qflag(qs, "connect_wait", False)
    else:
        connect_wait = (p.scheme == "tcp")
    handshake = _qflag(qs, "handshake", True if p.scheme in ("tcp","udp") else False)
    hello_interval = float(_qnum(qs, "hello_interval", 0.1, cast=float))
    wait_timeout = _qnum(qs, "wait_timeout", None, cast=float)
    wait_forever = _qflag(qs, "wait_forever", False)
    verbose = _qflag(qs, "verbose", False) or _qflag(qs, "debug", False)
    bind = _qstr(qs, "bind", None)
    resume = _qflag(qs, "resume", False)
    resume_to = _qstr(qs, "resume_to", None)
    save = _qflag(qs, "save", False)
    overwrite = _qflag(qs, "overwrite", False)
    save_dir = _qstr(qs, "save_dir", None)
    done = _qflag(qs, "done", False)
    done_token = _qstr(qs, "done_token", None)
    framing = _qstr(qs, "framing", None)
    sha256 = _qflag(qs, "sha256", False) or _qflag(qs, "sha", False)
    raw_meta = _qflag(qs, "raw_meta", True)
    raw_ack = _qflag(qs, "raw_ack", False)
    raw_ack_timeout = _qnum(qs, "raw_ack_timeout", 0.5, cast=float)
    raw_ack_retries = int(_qnum(qs, "raw_ack_retries", 40, cast=int))
    raw_ack_window = int(_qnum(qs, "raw_ack_window", 1, cast=int))
    if raw_ack_window < 1:
        raw_ack_window = 1
    raw_sha = _qflag(qs, "raw_sha", False)
    raw_hash = _qstr(qs, "raw_hash", "sha256")

    return p, {
        "mode": mode,
        "timeout": timeout,
        "accept_timeout": accept_timeout,
        "total_timeout": total_timeout,
        "window": window,
        "retries": retries,
        "chunk": chunk,
        "print_url": print_url,
        "wait": wait,
        "connect_wait": connect_wait,
        "wait_timeout": wait_timeout,
        "wait_forever": wait_forever,
        "verbose": verbose,
        "handshake": handshake,
        "hello_interval": hello_interval,
        "bind": bind,
        "resume": resume,
        "resume_to": resume_to,
        "save": save,
        "overwrite": overwrite,
        "save_dir": save_dir,
        "done": done,
        "done_token": done_token,
        "framing": framing,
        "sha256": sha256,
        "raw_meta": raw_meta,
        "raw_ack": raw_ack,
        "raw_ack_timeout": raw_ack_timeout,
        "raw_ack_retries": raw_ack_retries,
        "raw_ack_window": raw_ack_window,
        "raw_sha": raw_sha,
        "raw_hash": raw_hash,
    }
# --- Bluetooth RFCOMM helpers -------------------------------------------------
# Notes:
# - URLs use the "bt", "rfcomm", or "bluetooth" schemes.
# - Netloc parsing cannot rely on urlparse.hostname because MAC addresses contain ':'.
# - Receiver/listener uses recv_to_fileobj(..., proto="bt") which binds and listens on RFCOMM.
# - Sender uses send_from_fileobj(..., proto="bt") which connects to the receiver.

_BT_SCHEMES = ("bt", "rfcomm", "bluetooth")

def _has_rfcomm() -> bool:
    """Return True if we can create an RFCOMM stream socket (native or PyBluez)."""
    try:
        if hasattr(socket, "AF_BLUETOOTH") and hasattr(socket, "BTPROTO_RFCOMM"):
            return True
    except Exception:
        pass
    try:
        if _pybluez is not None and hasattr(_pybluez, "BluetoothSocket") and hasattr(_pybluez, "RFCOMM"):
            return True
    except Exception:
        pass
    return False

def _bt_socket_stream():
    """Create an RFCOMM stream socket using stdlib (BlueZ) or PyBluez fallback."""
    try:
        if hasattr(socket, "AF_BLUETOOTH") and hasattr(socket, "BTPROTO_RFCOMM"):
            return socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
    except Exception:
        pass
    try:
        if _pybluez is not None:
            return _pybluez.BluetoothSocket(_pybluez.RFCOMM)
    except Exception:
        pass
    return None

def _norm_bt_addr(addr: Optional[str]) -> str:
    """Normalize Bluetooth addresses (AA:BB:.. or AA-BB-..) and accept any/empty markers."""
    if not addr:
        return "00:00:00:00:00:00"  # BDADDR_ANY
    a = str(addr).strip()
    if a.lower() in ("any", "bdaddr_any", "00:00:00:00:00:00"):
        return "00:00:00:00:00:00"
    return a.replace("-", ":")

def _bt_bind_addr(addr: Optional[str]) -> str:
    """Map our BDADDR_ANY marker to what the underlying stack expects."""
    a = _norm_bt_addr(addr)
    # For stdlib BlueZ, BDADDR_ANY is "00:.."; for PyBluez, empty string is typical.
    if a == "00:00:00:00:00:00" and _pybluez is not None and not (
        hasattr(socket, "AF_BLUETOOTH") and hasattr(socket, "BTPROTO_RFCOMM")
    ):
        return ""
    return a

def _split_bt_netloc(netloc: str) -> Tuple[str, Optional[int]]:
    """Parse bt scheme netloc safely without urlparse hostname/port (MAC contains ':').

    Supported:
      - "AA:BB:CC:DD:EE:FF:3"  -> (AA:..:FF, 3)
      - "AA-BB-CC-DD-EE-FF:3"  -> (AA:..:FF, 3)
      - "AA:BB:CC:DD:EE:FF"    -> (AA:..:FF, None)
      - ""                     -> (BDADDR_ANY, None)
    """
    if not netloc:
        return ("00:00:00:00:00:00", None)
    s = str(netloc).strip()
    if "@" in s:
        # strip any accidental userinfo "x@y"
        s = s.split("@", 1)[1]
    s = s.replace("-", ":")
    parts = s.split(":")
    ch: Optional[int] = None
    if len(parts) >= 7 and parts[-1].isdigit():
        try:
            ch = int(parts[-1], 10)
        except Exception:
            ch = None
        addr = ":".join(parts[:-1])
        return (_norm_bt_addr(addr), ch)
    return (_norm_bt_addr(s), None)

def _bt_host_channel_from_url(parts, qs: Mapping[str, List[str]], o: Mapping[str, Any]) -> Tuple[str, int]:
    """Resolve bdaddr+channel from urlparse parts and query/bind options."""
    addr, ch = _split_bt_netloc(getattr(parts, "netloc", "") or "")
    bind = o.get("bind") or _qstr(qs, "bind", None)
    if bind:
        addr = _norm_bt_addr(bind)
    qch = _qnum(qs, "channel", None, cast=int)
    if qch is None:
        qch = _qnum(qs, "rfcomm_channel", None, cast=int)
    if ch is None and qch is not None:
        ch = int(qch)
    if ch is None or int(ch) <= 0:
        ch = 1
    return addr, int(ch)


def _kw_bool(v, default=False):
    """
    Normalize common URL/query-string truthy/falsey values.
    Fixes the classic bug: "0" is truthy in Python.
    """
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    if isinstance(v, (bytes, bytearray)):
        try:
            v = v.decode("utf-8", "ignore")
        except Exception:
            return bool(v)
    if isinstance(v, str):
        s = v.strip().lower()
        if s in ("0", "false", "no", "off", "n", ""):
            return False
        if s in ("1", "true", "yes", "on", "y"):
            return True
    return bool(v)


def recv_to_fileobj(fileobj, host, port, proto="tcp", path_text=None, **kwargs):
    proto = (proto or "tcp").lower()
    port = int(port)
    logger = _logger_from_kwargs(kwargs)

    # Aliases / normalization for URL params
    if "framing" not in kwargs and "frame" in kwargs:
        kwargs["framing"] = kwargs.get("frame")

    if proto == "tcp" or proto in _BT_SCHEMES:
        is_bt = proto in _BT_SCHEMES

        # --- Boolean normalization (BT has different safe defaults) ---
        # For BT: handshake default OFF (RFCOMM + MSG_PEEK is unreliable)
        hs_default = False if is_bt else True
        kwargs["handshake"] = _kw_bool(kwargs.get("handshake", hs_default), hs_default)

        # For BT: send_path default OFF (PATH preface can break framing alignment)
        kwargs["send_path"] = _kw_bool(kwargs.get("send_path", False), False)

        # Other common bool-like flags
        kwargs["resume"] = _kw_bool(kwargs.get("resume", False), False)
        kwargs["done"] = _kw_bool(kwargs.get("done", False), False)
        kwargs["sha256"] = _kw_bool(kwargs.get("sha256", False), False)
        kwargs["sha"] = _kw_bool(kwargs.get("sha", False), False)
        kwargs["want_sha"] = _kw_bool(kwargs.get("want_sha", False), False)

        framing = (kwargs.get("framing") or "").lower()

        # BT safe: if using len framing, never allow PATH to be sent
        if is_bt and framing == "len":
            kwargs["send_path"] = False

        # --- Set up server socket ---
        if is_bt:
            if not _has_rfcomm():
                _emit("Bluetooth RFCOMM is not available (missing AF_BLUETOOTH/BTPROTO_RFCOMM or PyBluez).",
                      logger=logger, level=logging.ERROR, stream="stderr")
                return False
            srv = _bt_socket_stream()
            if srv is None:
                _emit("Failed to create Bluetooth RFCOMM socket.", logger=logger, level=logging.ERROR, stream="stderr")
                return False
            try:
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except Exception:
                pass

            bind_addr = _bt_bind_addr(host or "")
            ch = int(port) if int(port) > 0 else 1
            try:
                srv.bind((bind_addr, ch))
            except Exception:
                try:
                    srv.close()
                except Exception:
                    pass
                return False
            try:
                srv.listen(1)
            except Exception:
                try:
                    srv.close()
                except Exception:
                    pass
                return False

            chosen_port = ch
            try:
                sn = srv.getsockname()
                if isinstance(sn, tuple) and len(sn) >= 2:
                    chosen_port = int(sn[1])
            except Exception:
                pass

            if kwargs.get("print_url"):
                path = path_text or "/"
                if not path.startswith("/"):
                    path = "/" + path
                bind_host = _norm_bt_addr(host or "00:00:00:00:00:00")
                if bind_host == "00:00:00:00:00:00":
                    try:
                        if _pybluez is not None and hasattr(_pybluez, "read_local_bdaddr"):
                            addrs = _pybluez.read_local_bdaddr()
                            if addrs:
                                bind_host = _norm_bt_addr(addrs[0])
                    except Exception:
                        pass
                _emit(f"Listening: bt://{bind_host}:{int(chosen_port)}{path}",
                      logger=logger, level=logging.INFO, stream="stdout")
                try:
                    sys.stdout.flush()
                except Exception:
                    pass

        else:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except Exception:
                pass
            srv.bind((host or "", port))
            srv.listen(1)

            chosen_port = srv.getsockname()[1]
            if kwargs.get("print_url"):
                path = path_text or "/"
                bind_host = host or "0.0.0.0"
                for u in _listen_urls("tcp", bind_host, chosen_port, path, ""):
                    _emit("Listening: %s" % u, logger=logger, level=logging.INFO, stream="stdout")
                try:
                    sys.stdout.flush()
                except Exception:
                    pass

        # --- timeouts for accept/listen ---
        idle_to = kwargs.get("idle_timeout", None)
        acc_to = kwargs.get("accept_timeout", None)
        to = kwargs.get("timeout", None)
        try:
            if idle_to is not None and float(idle_to) > 0:
                srv.settimeout(float(idle_to))
            elif acc_to is not None and float(acc_to) > 0:
                srv.settimeout(float(acc_to))
            elif to is not None and float(to) > 0:
                srv.settimeout(float(to))
            else:
                srv.settimeout(None)
        except Exception:
            pass

        if kwargs.get("verbose"):
            _net_log(True, f"{'BT' if is_bt else 'TCP'}: waiting accept on ch={port}", logger=logger)

        conn = None
        try:
            conn, _addr = srv.accept()
        except socket.timeout:
            try:
                srv.close()
            except Exception:
                pass
            return False
        except KeyboardInterrupt:
            try:
                srv.close()
            except Exception:
                pass
            raise
        except Exception:
            try:
                srv.close()
            except Exception:
                pass
            return False

        if kwargs.get("verbose"):
            _net_log(True, f"{'BT' if is_bt else 'TCP'}: accepted {_addr}", logger=logger)

        ok = False
        try:
            # --- handshake (TCP uses peek; BT default is off, but can be enabled safely only if you patched BT-safe handshake) ---
            if kwargs.get("handshake", True):
                try:
                    conn.settimeout(0.25)
                    if hasattr(socket, "MSG_PEEK"):
                        peekh = conn.recv(6, socket.MSG_PEEK)
                    else:
                        peekh = b""
                except Exception:
                    peekh = b""
                try:
                    if to is not None and float(to) > 0:
                        conn.settimeout(float(to))
                    else:
                        conn.settimeout(None)
                except Exception:
                    pass
                if peekh == b"HELLO ":
                    line = b""
                    while True:
                        b = conn.recv(1)
                        if not b:
                            break
                        line += b
                        if line.endswith(b"\n") or len(line) > 4096:
                            break
                    tok = b""
                    try:
                        parts2 = line.strip().split(None, 1)
                        if len(parts2) == 2:
                            tok = parts2[1]
                    except Exception:
                        tok = b""
                    try:
                        conn.sendall(b"READY " + tok + b"\n")
                    except Exception:
                        pass

            # PATH preface (only if sender sent it)
            try:
                conn.settimeout(0.25)
                if hasattr(socket, "MSG_PEEK"):
                    peek = conn.recv(5, socket.MSG_PEEK)
                else:
                    peek = b""
            except Exception:
                peek = b""
            try:
                if to is not None and float(to) > 0:
                    conn.settimeout(float(to))
                else:
                    conn.settimeout(None)
            except Exception:
                pass

            if peek == b"PATH ":
                line = b""
                while True:
                    b = conn.recv(1)
                    if not b:
                        break
                    line += b
                    if line.endswith(b"\n") or len(line) > 4096:
                        break

            # Resume handshake
            if kwargs.get("resume"):
                try:
                    cur = fileobj.tell()
                except Exception:
                    cur = 0
                msg = ("OFFSET %d\n" % int(cur)).encode("utf-8")
                try:
                    conn.sendall(msg)
                except Exception:
                    pass

            framing = (kwargs.get("framing") or "").lower()
            want_sha = bool(kwargs.get("sha256") or kwargs.get("sha") or kwargs.get("want_sha"))
            h = hashlib.sha256() if want_sha else None

            if framing == "len":
                # --- LEN framing: read PWG4 header ---
                try:
                    header = b""
                    while len(header) < 16:
                        chunk = conn.recv(16 - len(header))
                        if not chunk:
                            break
                        header += _to_bytes(chunk)

                    if kwargs.get("verbose"):
                        _net_log(True, f"{'BT' if is_bt else 'TCP'} len: header={header[:16]!r} len={len(header)}",
                                 logger=logger)

                    if len(header) != 16 or not header.startswith(b"PWG4"):
                        ok = False
                    else:
                        size = struct.unpack("!Q", header[4:12])[0]
                        flags = struct.unpack("!I", header[12:16])[0]
                        sha_in_stream = bool(flags & 1)
                        remaining = int(size)

                        while remaining > 0:
                            chunk = conn.recv(min(65536, remaining))
                            if not chunk:
                                break
                            chunk = _to_bytes(chunk)
                            fileobj.write(chunk)
                            if h is not None:
                                h.update(chunk)
                            remaining -= len(chunk)

                        if remaining != 0:
                            ok = False
                        else:
                            if sha_in_stream:
                                digest = b""
                                while len(digest) < 32:
                                    part = conn.recv(32 - len(digest))
                                    if not part:
                                        break
                                    digest += _to_bytes(part)
                                if len(digest) != 32:
                                    ok = False
                                elif h is not None and h.digest() != digest:
                                    ok = False
                                else:
                                    ok = True
                            else:
                                ok = (not want_sha)
                except Exception:
                    ok = False
            else:
                # Legacy stream mode
                done = bool(kwargs.get("done"))
                tok = kwargs.get("done_token") or "\nDONE\n"
                tokb = _to_bytes(tok)
                tlen = len(tokb)
                tail = b""

                while True:
                    try:
                        chunk = conn.recv(65536)
                    except socket.timeout:
                        continue
                    except Exception:
                        break
                    if not chunk:
                        break
                    chunk = _to_bytes(chunk)

                    if not done:
                        fileobj.write(chunk)
                        continue

                    buf = tail + chunk
                    if tlen and buf.endswith(tokb):
                        if len(buf) > tlen:
                            fileobj.write(buf[:-tlen])
                        tail = b""
                        break

                    if tlen and len(buf) > tlen:
                        fileobj.write(buf[:-tlen])
                        tail = buf[-tlen:]
                    else:
                        tail = buf

                if done and tail:
                    fileobj.write(tail)

                ok = True

        finally:
            try:
                if conn is not None:
                    conn.close()
            except Exception:
                pass
            try:
                srv.close()
            except Exception:
                pass

        if ok:
            try:
                fileobj.seek(0, 0)
            except Exception:
                pass
        return ok

    # UDP modes unchanged
    mode = (kwargs.get("mode") or "seq").lower()
    if mode == "raw":
        return _udp_raw_recv(fileobj, host, port, **kwargs)
    elif mode == "quic":
        return _udp_quic_recv(fileobj, host, port, **kwargs)
    return _udp_seq_recv(fileobj, host, port, **kwargs)


def send_from_fileobj(fileobj, host, port, proto="tcp", path_text=None, **kwargs):
    proto = (proto or "tcp").lower()
    port = int(port)
    logger = _logger_from_kwargs(kwargs)

    # Aliases / normalization for URL params
    if "framing" not in kwargs and "frame" in kwargs:
        kwargs["framing"] = kwargs.get("frame")

    if proto == "tcp" or proto in _BT_SCHEMES:
        is_bt = proto in _BT_SCHEMES

        # --- Boolean normalization (BT has different safe defaults) ---
        hs_default = False if is_bt else True
        kwargs["handshake"] = _kw_bool(kwargs.get("handshake", hs_default), hs_default)

        kwargs["send_path"] = _kw_bool(kwargs.get("send_path", False), False)
        kwargs["resume"] = _kw_bool(kwargs.get("resume", False), False)
        kwargs["done"] = _kw_bool(kwargs.get("done", False), False)
        kwargs["sha256"] = _kw_bool(kwargs.get("sha256", False), False)
        kwargs["sha"] = _kw_bool(kwargs.get("sha", False), False)
        kwargs["want_sha"] = _kw_bool(kwargs.get("want_sha", False), False)

        framing = (kwargs.get("framing") or "").lower()

        # BT quality-of-life: if user didn't choose framing, default to len
        if is_bt and not framing:
            framing = "len"
            kwargs["framing"] = "len"

        # BT + len framing: PATH must be disabled (keeps PWG4 header aligned)
        if is_bt and framing == "len":
            kwargs["send_path"] = False

        if is_bt:
            if not _has_rfcomm():
                _emit("Bluetooth RFCOMM is not available (missing AF_BLUETOOTH/BTPROTO_RFCOMM or PyBluez).",
                      logger=logger, level=logging.ERROR, stream="stderr")
                return False
            sock = _bt_socket_stream()
            if sock is None:
                _emit("Failed to create Bluetooth RFCOMM socket.", logger=logger, level=logging.ERROR, stream="stderr")
                return False
            addr = _norm_bt_addr(host)
            if not addr or addr == "00:00:00:00:00:00":
                _emit("Bluetooth send requires a concrete remote bdaddr (not BDADDR_ANY).",
                      logger=logger, level=logging.ERROR, stream="stderr")
                try:
                    sock.close()
                except Exception:
                    pass
                return False
            connect_target = (addr, int(port))
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            connect_target = (host, int(port))

        try:
            to = kwargs.get("timeout", None)
            if to is not None and float(to) > 0:
                sock.settimeout(float(to))
        except Exception:
            pass

        if "wait" not in kwargs and "connect_wait" not in kwargs:
            kwargs["connect_wait"] = True
        wait = bool(kwargs.get("wait", False) or kwargs.get("connect_wait", False))
        wait_timeout = kwargs.get("wait_timeout", None)
        if wait_timeout is not None:
            try:
                wait_timeout = float(wait_timeout)
            except Exception:
                wait_timeout = None

        start_t = time.time()
        while True:
            try:
                sock.connect(connect_target)
                break
            except Exception:
                if not wait:
                    try:
                        sock.close()
                    except Exception:
                        pass
                    return False
                if wait_timeout is not None and wait_timeout >= 0 and (time.time() - start_t) >= wait_timeout:
                    try:
                        sock.close()
                    except Exception:
                        pass
                    return False
                try:
                    _net_log(kwargs.get("verbose"), f"{'BT' if is_bt else 'TCP'}: waiting for receiver, retrying...",
                             logger=logger)
                    time.sleep(0.1)
                except Exception:
                    pass
                continue

        if kwargs.get("verbose"):
            _net_log(True, f"SEND {'BT' if is_bt else 'TCP'} framing={framing} want_sha={bool(kwargs.get('sha256') or kwargs.get('sha') or kwargs.get('want_sha'))}",
                     logger=logger)

        # Handshake (OFF by default for BT; if enabled, keep as-is)
        if kwargs.get("handshake", True):
            tok = kwargs.get("token")
            if tok is None:
                tok = _hs_token()
            else:
                tok = _to_bytes(tok)
            try:
                sock.sendall(b"HELLO " + tok + b"\n")
            except Exception:
                try:
                    sock.close()
                except Exception:
                    pass
                return False
            wt = kwargs.get("wait_timeout", None)
            try:
                sock.settimeout(float(wt) if wt is not None else None)
            except Exception:
                pass
            buf = b""
            while b"\n" not in buf and len(buf) < 4096:
                try:
                    b = sock.recv(1024)
                except Exception:
                    b = b""
                if not b:
                    try:
                        sock.close()
                    except Exception:
                        pass
                    return False
                buf += b
            line = buf.split(b"\n", 1)[0].strip()
            if not line.startswith(b"READY"):
                try:
                    sock.close()
                except Exception:
                    pass
                return False
            if b" " in line:
                rt = line.split(None, 1)[1].strip()
                if rt and rt != tok:
                    try:
                        sock.close()
                    except Exception:
                        pass
                    return False
            try:
                to = kwargs.get("timeout", None)
                if to is not None and float(to) > 0:
                    sock.settimeout(float(to))
                else:
                    sock.settimeout(None)
            except Exception:
                pass

        # PATH (never for BT+len framing)
        if path_text and (not is_bt or kwargs.get("send_path")):
            try:
                line = ("PATH %s\n" % (path_text or "/")).encode("utf-8")
                sock.sendall(line)
            except Exception:
                pass

        # Resume support (unchanged)
        if kwargs.get("resume"):
            try:
                buf = b""
                while not buf.endswith(b"\n") and len(buf) < 128:
                    b = sock.recv(1)
                    if not b:
                        break
                    buf += b
                if buf.startswith(b"OFFSET "):
                    off = int(buf.split()[1])
                    try:
                        fileobj.seek(off, 0)
                    except Exception:
                        pass
            except Exception:
                pass

        want_sha = bool(kwargs.get("sha256") or kwargs.get("sha") or kwargs.get("want_sha"))
        h = hashlib.sha256() if want_sha else None

        if framing == "len":
            size = None
            try:
                cur = fileobj.tell()
                fileobj.seek(0, os.SEEK_END)
                end = fileobj.tell()
                fileobj.seek(cur, os.SEEK_SET)
                size = int(end - cur)
            except Exception:
                size = None
            if size is None or size < 0:
                try:
                    sock.close()
                except Exception:
                    pass
                return False
            flags = 1 if want_sha else 0
            header = b"PWG4" + struct.pack("!Q", int(size)) + struct.pack("!I", int(flags))
            try:
                sock.sendall(header)
            except Exception:
                try:
                    sock.close()
                except Exception:
                    pass
                return False

        try:
            while True:
                data = fileobj.read(65536)
                if not data:
                    break
                data = _to_bytes(data)
                sock.sendall(data)
                if h is not None:
                    h.update(data)

            if framing == "len" and want_sha:
                sock.sendall(h.digest())
            elif kwargs.get("done"):
                tok = kwargs.get("done_token") or "\nDONE\n"
                sock.sendall(_to_bytes(tok))
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            return False

        try:
            sock.shutdown(socket.SHUT_WR)
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass
        return True

    # UDP send path unchanged
    mode = (kwargs.get("mode") or "seq").lower()
    if mode == "raw":
        # your existing raw sender code here (unchanged)
        return _udp_raw_send(fileobj, host, port, **kwargs) if "_udp_raw_send" in globals() else _udp_seq_send(fileobj, host, port, **kwargs)
    elif mode == "quic":
        return _udp_quic_send(fileobj, host, port, **kwargs)
    return _udp_seq_send(fileobj, host, port, **kwargs)

def _udp_raw_recv(fileobj, host, port, **kwargs):
    logger = _logger_from_kwargs(kwargs)
    addr = (host or "", int(port))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Bind to all interfaces unless user explicitly gave a concrete local bind
        bind_host = host if host not in (None, "", "127.0.0.1") else ""
        sock.bind((bind_host, int(port)))
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        return False

    # Waiting behavior
    wait = bool(kwargs.get("wait", True) or kwargs.get("connect_wait", False))
    wait_timeout = kwargs.get("wait_timeout", None)
    try:
        wait_timeout = float(wait_timeout) if wait_timeout is not None else None
    except Exception:
        wait_timeout = None

    # If raw_ack enabled, we must do READY/ACK
    raw_ack = bool(kwargs.get("raw_ack"))
    handshake = bool(kwargs.get("handshake", True))

    # Optional meta/hash
    want_meta = bool(kwargs.get("raw_meta", True))
    want_hash = bool(kwargs.get("raw_sha", False))
    raw_hash = (kwargs.get("raw_hash", "sha256") or "sha256").lower()

    expected_len = None
    expected_hash_hex = None

    # In-order receive support (prevents duplicates/“extra bigger”)
    expected_seq = 0
    buffered = {}  # seq -> data

    # For verifying HASH if requested/sent
    h = None
    if want_hash:
        try:
            h = hashlib.sha256() if raw_hash != "md5" else hashlib.md5()
        except Exception:
            h = None

    sender_addr = None
    got_any = False
    start_t = time.time()

    # Optional debug
    verbose = kwargs.get("verbose", False)

    def _log(msg):
        _net_log(verbose, msg, logger=logger)

    def _sendto(bts, a):
        try:
            sock.sendto(bts, a)
        except Exception:
            pass

    def _try_flush_buffer():
        nonlocal expected_seq
        while expected_seq in buffered:
            data = buffered.pop(expected_seq)
            try:
                fileobj.write(data)
            except Exception:
                pass
            if h is not None:
                try:
                    h.update(data)
                except Exception:
                    pass
            expected_seq += 1

    try:
        # Use a short timeout so we can enforce wait_timeout cleanly
        try:
            sock.settimeout(0.25 if wait else 0.0)
        except Exception:
            pass

        while True:
            # timeout handling
            if not got_any and wait_timeout is not None and wait_timeout >= 0:
                if (time.time() - start_t) >= wait_timeout:
                    return False

            try:
                pkt, a = sock.recvfrom(65536)
            except socket.timeout:
                continue
            except KeyboardInterrupt:
                raise
            except Exception:
                return False

            if not pkt:
                continue

            got_any = True
            if sender_addr is None:
                sender_addr = a

            # --- CONTROL: HELLO/READY ---
            if handshake and pkt.startswith(b"HELLO "):
                tok = pkt.split(None, 1)[1].strip()
                _log(f"UDP raw: got HELLO from {a}")
                _sendto(b"READY " + tok + b"\n", a)
                continue

            # --- CONTROL: META ---
            if want_meta and pkt.startswith(b"META "):
                try:
                    expected_len = int(pkt.split(None, 1)[1].strip())
                    _log(f"UDP raw: got META len={expected_len}")
                except Exception:
                    pass
                continue

            # --- CONTROL: HASH ---
            if want_hash and pkt.startswith(b"HASH "):
                # "HASH <alg> <hex>\n"
                try:
                    parts = pkt.strip().split()
                    if len(parts) >= 3:
                        alg = parts[1].decode("ascii", "ignore").lower()
                        hx = parts[2].decode("ascii", "ignore").lower()
                        expected_hash_hex = hx
                        _log(f"UDP raw: got HASH alg={alg}")
                        # If alg differs, we still accept but won't verify correctly.
                except Exception:
                    pass
                continue

            # --- CONTROL: DONE ---
            if pkt.startswith(b"DONE"):
                _log("UDP raw: got DONE")
                # Flush anything buffered (best effort)
                _try_flush_buffer()

                # Verify length if META was provided
                if expected_len is not None:
                    try:
                        cur = fileobj.tell()
                        ok_len = (int(cur) == int(expected_len))
                    except Exception:
                        ok_len = True  # can't verify
                else:
                    ok_len = True

                # Verify hash if provided
                ok_hash = True
                if expected_hash_hex and h is not None:
                    try:
                        ok_hash = (h.hexdigest().lower() == expected_hash_hex.lower())
                    except Exception:
                        ok_hash = True

                return bool(ok_len and ok_hash)

            # --- DATA (raw_ack framed) ---
            if raw_ack and pkt.startswith(b"PKT "):
                # Format: b"PKT <seq> <data...>"
                try:
                    sp1 = pkt.find(b" ")
                    sp2 = pkt.find(b" ", sp1 + 1)
                    seq = int(pkt[sp1 + 1:sp2])
                    data = pkt[sp2 + 1:]
                except Exception:
                    continue

                # ACK immediately (even if duplicate/out-of-order)
                _sendto(b"ACK " + str(seq).encode("ascii") + b"\n", a)

                if seq < expected_seq:
                    # duplicate
                    continue

                if seq == expected_seq:
                    try:
                        fileobj.write(data)
                    except Exception:
                        pass
                    if h is not None:
                        try:
                            h.update(data)
                        except Exception:
                            pass
                    expected_seq += 1
                    _try_flush_buffer()
                else:
                    # out of order: buffer
                    if seq not in buffered:
                        buffered[seq] = data
                continue

            # --- DATA (legacy raw, no framing) ---
            # If sender is not using PKT framing, treat all other packets as raw payload.
            # This mode cannot be reliable or ordered, but works on localhost.
            try:
                fileobj.write(_to_bytes(pkt))
                if h is not None:
                    h.update(_to_bytes(pkt))
            except Exception:
                pass

    finally:
        try:
            sock.close()
        except Exception:
            pass

def _udp_seq_send(fileobj, host, port, resume=False, path_text=None, **kwargs):
    addr = (host, int(port))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    base_timeout = float(kwargs.get("timeout", 1.0))
    min_to = float(kwargs.get("min_timeout", 0.05))
    max_to = float(kwargs.get("max_timeout", 3.0))

    timeout = max(min_to, min(max_to, base_timeout))
    sock.settimeout(timeout)

    chunk = int(kwargs.get("chunk", 1200))
    max_window = int(kwargs.get("window", 32))          # cap
    init_window = int(kwargs.get("init_window", max(1, min(4, max_window))))
    retries = int(kwargs.get("retries", 20))
    total_timeout = float(kwargs.get("total_timeout", 0.0))

    enable_fast_retx = bool(kwargs.get("fast_retx", True))

    use_crc = bool(kwargs.get("crc32", False))

    want_sha = bool(kwargs.get("sha256") or kwargs.get("sha") or kwargs.get("want_sha"))
    _h = hashlib.sha256() if want_sha else None

    tid = int(kwargs.get("tid", 0) or 0)
    if tid == 0:
        tid = randbits(64)

    stats = {
        "tid": tid,
        "bytes_sent_payload": 0,
        "pkts_sent": 0,
        "pkts_retx": 0,
        "pkts_acked": 0,
        "pkts_sacked": 0,
        "loss_events": 0,
        "duration_s": 0.0,
        "throughput_Bps": 0.0,
        "srtt": None,
        "rttvar": None,
        "timeout": timeout,
        "cwnd_start": init_window,
        "cwnd_end": init_window,
    }

    total = 0
    try:
        start_pos = fileobj.tell()
        fileobj.seek(0, os.SEEK_END)
        total = int(fileobj.tell())
        fileobj.seek(start_pos, os.SEEK_SET)
    except Exception:
        total = 0

    start_seq = 0
    if resume:
        sock.sendto(_u_pack(_UF_META, 0xFFFFFFFF, total, tid) + b"RESUME", addr)
        t0 = time.time()
        while True:
            if total_timeout and (time.time() - t0) > total_timeout:
                break
            try:
                pkt, _peer = sock.recvfrom(2048)
            except Exception:
                break
            up = _u_unpack(pkt)
            if not up:
                continue
            flags, _seq, _t, r_tid, payload = up
            if r_tid != tid:
                continue
            if (flags & _UF_RESUME) and len(payload) >= 4:
                resume_seq = struct.unpack("!I", payload[:4])[0]
                try:
                    fileobj.seek(int(resume_seq) * chunk, os.SEEK_SET)
                    start_seq = int(resume_seq)
                except Exception:
                    start_seq = 0
                break

    cwnd = max(1, min(max_window, init_window))
    cwnd_float = float(cwnd)

    next_seq = start_seq
    in_flight = {}  # seq -> (wire_payload, ts_sent, tries, data_len)

    srtt = None
    rttvar = None

    def _update_rtt(sample):
        nonlocal srtt, rttvar, timeout
        if sample <= 0:
            return
        if srtt is None:
            srtt = sample
            rttvar = sample / 2.0
        else:
            alpha = 1 / 8
            beta = 1 / 4
            rttvar = (1 - beta) * rttvar + beta * abs(srtt - sample)
            srtt = (1 - alpha) * srtt + alpha * sample
        timeout = srtt + 4.0 * rttvar
        timeout = max(min_to, min(max_to, timeout))
        try:
            sock.settimeout(timeout)
        except Exception:
            pass

    def _loss_event():
        nonlocal cwnd, cwnd_float
        stats["loss_events"] += 1
        cwnd = max(1, cwnd // 2)
        cwnd_float = float(cwnd)

    def _ai_increase(acked_count):
        nonlocal cwnd, cwnd_float
        if acked_count <= 0:
            return
        cwnd_float += float(acked_count) / max(1.0, float(cwnd))
        new_cwnd = int(cwnd_float)
        if new_cwnd > cwnd:
            cwnd = min(max_window, new_cwnd)
            cwnd_float = float(cwnd)

    def _send_pkt(seq, wire_payload, flags):
        sock.sendto(_u_pack(flags, seq, total, tid) + wire_payload, addr)
        stats["pkts_sent"] += 1

    t_start = time.time()
    failed = False

    def _read_chunk():
        data = fileobj.read(chunk)
        if not data:
            return None
        data = _to_bytes(data)
        if _h is not None:
            _h.update(data)
        return data

    eof = False
    while not eof and len(in_flight) < cwnd:
        data = _read_chunk()
        if data is None:
            eof = True
            break
        flags = _UF_DATA | (_UF_CRC if use_crc else 0)
        wire = struct.pack("!I", zlib.crc32(data) & 0xFFFFFFFF) + data if use_crc else data
        _send_pkt(next_seq, wire, flags)
        in_flight[next_seq] = (wire, time.time(), 0, len(data))
        stats["bytes_sent_payload"] += len(data)
        next_seq += 1

    while in_flight or not eof:
        if total_timeout and (time.time() - t_start) > total_timeout:
            failed = True
            break

        try:
            pkt, _peer = sock.recvfrom(2048)
            up = _u_unpack(pkt)
            if up:
                flags, _seq, _t, r_tid, payload = up
                if r_tid == tid and (flags & _UF_ACK) and len(payload) >= 4:
                    ack_upto = None
                    sack_mask = 0
                    if len(payload) >= 12:
                        ack_upto, sack_mask = struct.unpack("!IQ", payload[:12])
                    else:
                        (ack_upto,) = struct.unpack("!I", payload[:4])

                    newly_acked = 0
                    now = time.time()

                    # Cumulative ACK: drop all <= ack_upto
                    for s in [s for s in list(in_flight.keys()) if s <= ack_upto]:
                        wire, ts, _tries, _dlen = in_flight[s]
                        sample = now - ts
                        _update_rtt(sample)
                        del in_flight[s]
                        stats["pkts_acked"] += 1
                        newly_acked += 1

                    if sack_mask:
                        base = (ack_upto + 1) & 0xFFFFFFFF
                        for i in range(64):
                            if (sack_mask >> i) & 1:
                                s = (base + i) & 0xFFFFFFFF
                                if s in in_flight:
                                    wire, ts, _tries, _dlen = in_flight[s]
                                    sample = now - ts
                                    _update_rtt(sample)
                                    del in_flight[s]
                                    stats["pkts_sacked"] += 1
                                    newly_acked += 1

                        if enable_fast_retx:
                            missing = base
                            if missing in in_flight:
                                wire, _ts, tries, _dlen = in_flight[missing]
                                if tries < retries:
                                    _send_pkt(missing, wire, _UF_DATA | (_UF_CRC if use_crc else 0))
                                    in_flight[missing] = (wire, time.time(), tries + 1, _dlen)
                                    stats["pkts_retx"] += 1
                                    _loss_event()

                    _ai_increase(newly_acked)
        except socket.timeout:
            pass
        except Exception:
            pass

        now = time.time()
        for seq in list(in_flight.keys()):
            wire, ts, tries, dlen = in_flight[seq]
            if (now - ts) >= timeout:
                if tries >= retries:
                    failed = True
                    in_flight.clear()
                    break
                _send_pkt(seq, wire, _UF_DATA | (_UF_CRC if use_crc else 0))
                in_flight[seq] = (wire, now, tries + 1, dlen)
                stats["pkts_retx"] += 1
                _loss_event()

        if failed:
            break

        while not eof and len(in_flight) < cwnd:
            data = _read_chunk()
            if data is None:
                eof = True
                break
            flags = _UF_DATA | (_UF_CRC if use_crc else 0)
            wire = struct.pack("!I", zlib.crc32(data) & 0xFFFFFFFF) + data if use_crc else data
            _send_pkt(next_seq, wire, flags)
            in_flight[next_seq] = (wire, time.time(), 0, len(data))
            stats["bytes_sent_payload"] += len(data)
            next_seq += 1

    dur = max(1e-9, time.time() - t_start)
    stats["duration_s"] = dur
    stats["throughput_Bps"] = float(stats["bytes_sent_payload"]) / dur
    stats["timeout"] = timeout
    stats["srtt"] = srtt
    stats["rttvar"] = rttvar
    stats["cwnd_end"] = cwnd

    if failed:
        try:
            sock.close()
        except Exception:
            pass
        if kwargs.get("return_stats"):
            return (False, stats)
        so = kwargs.get("stats_obj")
        if isinstance(so, dict):
            so.update(stats)
        return False

    payload = b"DONE"
    if _h is not None:
        payload += _h.digest()

    for _i in range(3):
        sock.sendto(_u_pack(_UF_DONE, 0xFFFFFFFE, total, tid) + payload, addr)
        time.sleep(0.02)

    try:
        sock.close()
    except Exception:
        pass

    so = kwargs.get("stats_obj")
    if isinstance(so, dict):
        so.update(stats)

    if kwargs.get("return_stats"):
        return (True, stats)
    return True
def _udp_seq_recv(fileobj, host, port, **kwargs):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host or "", int(port)))

    if kwargs.get("print_url"):
        _emit("Listening: udp://%s:%d/" % (host or "0.0.0.0", sock.getsockname()[1]), logger=logger, level=logging.INFO, stream="stdout")
        try:
            sys.stdout.flush()
        except Exception:
            pass

    timeout = float(kwargs.get("timeout", 1.0))
    sock.settimeout(timeout)

    chunk = int(kwargs.get("chunk", 1200))
    window = int(kwargs.get("window", 32))
    total_timeout = float(kwargs.get("total_timeout", 0.0))

    framing = (kwargs.get("framing") or "").lower()
    want_sha = bool(kwargs.get("sha256") or kwargs.get("sha") or kwargs.get("want_sha"))
    _h = hashlib.sha256() if want_sha else None

    use_crc = bool(kwargs.get("crc32", False))

    total_len = None
    bytes_written = 0
    got_digest = None

    resume_off = 0
    try:
        resume_off = int(kwargs.get("resume_offset", 0) or 0)
    except Exception:
        resume_off = 0
    resume_seq = int(max(0, resume_off) // chunk)
    expected = resume_seq

    received = {}
    done = False
    complete = False
    t0 = time.time()

    active_tid = None

    crc_bad = 0

    def _ack(addr):
        ack_upto = int(expected - 1) & 0xFFFFFFFF
        sack_mask = 0
        base = int(expected)
        for s in received.keys():
            d = int(s) - base
            if 0 <= d < 64:
                sack_mask |= (1 << d)
        payload = struct.pack("!IQ", ack_upto, sack_mask)
        sock.sendto(_u_pack(_UF_ACK, 0, 0, active_tid) + payload, addr)

    def _send_resume(addr):
        sock.sendto(
            _u_pack(_UF_RESUME, 0xFFFFFFFE, 0, active_tid)
            + struct.pack("!I", int(resume_seq) & 0xFFFFFFFF),
            addr,
        )

    while True:
        if total_timeout and (time.time() - t0) > total_timeout:
            break
        try:
            pkt, addr = sock.recvfrom(65536)
        except socket.timeout:
            if complete and want_sha:
                continue
            if done and not received:
                break
            continue
        except Exception:
            break

        up = _u_unpack(pkt)
        if not up:
            continue
        flags, seq, total, tid, payload = up

        if active_tid is None:
            active_tid = tid
        if tid != active_tid:
            continue

        if total_len is None and total:
            try:
                total_len = int(total)
            except Exception:
                total_len = None

        if flags & _UF_META:
            try:
                _send_resume(addr)
            except Exception:
                pass
            continue

        if flags & _UF_DONE:
            done = True
            if payload.startswith(b"DONE") and len(payload) >= 4 + 32:
                got_digest = payload[4:4 + 32]
            if complete and ((not want_sha) or (got_digest is not None)):
                break
            if not received and not want_sha:
                break
            continue

        if not (flags & _UF_DATA):
            continue

        if complete:
            try:
                _ack(addr)
            except Exception:
                pass
            continue

        if seq < expected:
            try:
                _ack(addr)
            except Exception:
                pass
            continue
        if seq >= expected + window * 8:
            continue

        if use_crc and (flags & _UF_CRC):
            if len(payload) < 4:
                crc_bad += 1
                try:
                    _ack(addr)
                except Exception:
                    pass
                continue
            want = struct.unpack("!I", payload[:4])[0]
            data = payload[4:]
            got = zlib.crc32(data) & 0xFFFFFFFF
            if got != want:
                crc_bad += 1
                try:
                    _ack(addr)
                except Exception:
                    pass
                continue
            payload = data

        if seq == expected:
            fileobj.write(payload)
            bytes_written += len(payload)
            if _h is not None:
                _h.update(_to_bytes(payload))
            expected += 1
            while expected in received:
                bufp = received.pop(expected)
                fileobj.write(bufp)
                bytes_written += len(bufp)
                if _h is not None:
                    _h.update(_to_bytes(bufp))
                expected += 1
        else:
            if seq not in received:
                received[seq] = payload

        try:
            _ack(addr)
        except Exception:
            pass

        if (framing == "len") and (total_len is not None) and (bytes_written >= total_len):
            complete = True
            if not want_sha:
                break
            if got_digest is not None:
                break

        if done and not received:
            break

    if want_sha:
        if got_digest is None:
            try:
                sock.close()
            except Exception:
                pass
            return False
        if _h is None or _h.digest() != got_digest:
            try:
                sock.close()
            except Exception:
                pass
            return False

    try:
        sock.close()
    except Exception:
        pass
    try:
        fileobj.seek(0, 0)
    except Exception:
        pass

    so = kwargs.get("stats_obj")
    if isinstance(so, dict):
        so["crc_bad"] = crc_bad

    return True

def _make_tag(psk, header_and_body):
    mac = hmac.new(_to_bytes(psk), header_and_body, hashlib.sha256).digest()
    return mac[:_TAG_SZ]

def _pack_pkt(pt, cid, pn, body, psk=None, flags=0):
    body = _to_bytes(body)
    if len(body) > 65535:
        body = body[:65535]
    hdr = struct.pack(_HDR_FMT, _MAGIC, int(pt) & 0xFF, int(flags) & 0xFF,
                      int(cid) & 0xFFFFFFFFFFFFFFFF, int(pn) & 0xFFFFFFFF, len(body))
    wire = hdr + body
    if psk:
        wire += _make_tag(psk, wire)
    return wire

def _unpack_pkt(wire, psk=None):
    wire = _to_bytes(wire)
    if len(wire) < _HDR_SZ:
        return None
    magic, pt, flags, cid, pn, blen = struct.unpack(_HDR_FMT, wire[:_HDR_SZ])
    if magic != _MAGIC:
        return None
    need = _HDR_SZ + int(blen)
    if len(wire) < need:
        return None
    body = wire[_HDR_SZ:need]
    if psk:
        if len(wire) < need + _TAG_SZ:
            return None
        tag = wire[need:need + _TAG_SZ]
        calc = _make_tag(psk, wire[:need])
        if tag != calc:
            return None
    return (pt, flags, cid, pn, body)

def _pack_frame(ft, payload):
    payload = _to_bytes(payload)
    if len(payload) > 65535:
        payload = payload[:65535]
    return struct.pack("!BH", int(ft) & 0xFF, len(payload)) + payload

def _iter_frames(body):
    body = _to_bytes(body)
    i = 0
    n = len(body)
    while i + 3 <= n:
        ft, flen = struct.unpack("!BH", body[i:i+3])
        i += 3
        if i + flen > n:
            return
        yield (ft, body[i:i+flen])
        i += flen

def _retry_token(retry_secret, addr, cid):
    secret = _to_bytes(retry_secret)
    ip = addr[0]
    port = int(addr[1])
    msg = _to_bytes("%s:%d|" % (ip, port)) + struct.pack("!Q", int(cid) & 0xFFFFFFFFFFFFFFFF)
    mac = hmac.new(secret, msg, hashlib.sha256).digest()
    return mac[:16]

def _token_valid(retry_secret, addr, cid, token):
    if not retry_secret:
        return True
    token = _to_bytes(token)
    return token == _retry_token(retry_secret, addr, cid)

def _cc_init(cc, init_cwnd, max_cwnd):
    cc = (cc or "reno").lower()
    if cc == "fixed":
        cwnd = max_cwnd
        cwnd_f = float(cwnd)
    else:
        cwnd = max(1, min(max_cwnd, int(init_cwnd)))
        cwnd_f = float(cwnd)
    return cc, cwnd, cwnd_f

def _cc_on_ack(cc, cwnd, cwnd_f, acked, max_cwnd):
    if acked <= 0:
        return cwnd, cwnd_f
    if cc == "fixed":
        return max_cwnd, float(max_cwnd)
    if cc == "cubic":
        cwnd_f += 0.4 * float(acked) + (float(acked) / max(1.0, float(cwnd)))
        new_cwnd = int(cwnd_f)
        if new_cwnd > cwnd:
            cwnd = min(max_cwnd, new_cwnd)
            cwnd_f = float(cwnd)
        return cwnd, cwnd_f

    cwnd_f += float(acked) / max(1.0, float(cwnd))
    new_cwnd = int(cwnd_f)
    if new_cwnd > cwnd:
        cwnd = min(max_cwnd, new_cwnd)
        cwnd_f = float(cwnd)
    return cwnd, cwnd_f

def _cc_on_loss(cc, cwnd, cwnd_f, max_cwnd):
    if cc == "fixed":
        return max_cwnd, float(max_cwnd)
    if cc == "cubic":
        cwnd = max(1, int(float(cwnd) * 0.7))
        return cwnd, float(cwnd)
    cwnd = max(1, cwnd // 2)
    return cwnd, float(cwnd)

def _udp_quic_send(fileobj, host, port, resume=False, path_text=None, **kwargs):
    addr = (host, int(port))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    base_timeout = float(kwargs.get("timeout", 1.0))
    min_to = float(kwargs.get("min_timeout", 0.05))
    max_to = float(kwargs.get("max_timeout", 3.0))
    timeout = max(min_to, min(max_to, base_timeout))
    try:
        sock.settimeout(timeout)
    except Exception:
        pass

    chunk = int(kwargs.get("chunk", 1200))
    max_window = int(kwargs.get("window", 32))
    init_window = int(kwargs.get("init_window", max(1, min(4, max_window))))
    retries = int(kwargs.get("retries", 20))
    total_timeout = float(kwargs.get("total_timeout", 0.0))
    fast_retx = bool(kwargs.get("fast_retx", True))

    cc = kwargs.get("cc", "reno")

    want_sha = bool(kwargs.get("sha256") or kwargs.get("sha") or kwargs.get("want_sha"))
    _h = hashlib.sha256() if want_sha else None

    psk = kwargs.get("psk", None)
    if psk:
        psk = _to_bytes(psk)

    cid = int(kwargs.get("cid", 0) or 0)
    if cid == 0:
        cid = _rand_u64()

    stream_id = int(kwargs.get("stream_id", 0) or 0) & 0xFFFF

    enable_0rtt = bool(kwargs.get("enable_0rtt", True))
    token = kwargs.get("token", None)
    if token is not None:
        token = _to_bytes(token)

    stats = {
        "cid": cid,
        "bytes_sent_payload": 0,
        "pkts_sent": 0,
        "pkts_retx": 0,
        "pkts_acked": 0,
        "pkts_sacked": 0,
        "loss_events": 0,
        "duration_s": 0.0,
        "throughput_Bps": 0.0,
        "srtt": None,
        "rttvar": None,
        "timeout": timeout,
        "cwnd_start": init_window,
        "cwnd_end": init_window,
        "cc": cc,
        "retry_used": False,
        "server_token": None,
        "start_offset": 0,
    }

    total_len = 0
    try:
        cur = fileobj.tell()
        fileobj.seek(0, os.SEEK_END)
        total_len = int(fileobj.tell())
        fileobj.seek(cur, os.SEEK_SET)
    except Exception:
        total_len = 0

    rtt = {"srtt": None, "rttvar": None, "timeout": timeout}
    def _update_rtt(sample):
        if sample <= 0:
            return
        if rtt["srtt"] is None:
            rtt["srtt"] = sample
            rtt["rttvar"] = sample / 2.0
        else:
            alpha = 1.0 / 8.0
            beta = 1.0 / 4.0
            rtt["rttvar"] = (1 - beta) * rtt["rttvar"] + beta * abs(rtt["srtt"] - sample)
            rtt["srtt"] = (1 - alpha) * rtt["srtt"] + alpha * sample
        to = rtt["srtt"] + 4.0 * rtt["rttvar"]
        to = max(min_to, min(max_to, to))
        rtt["timeout"] = to
        try:
            sock.settimeout(to)
        except Exception:
            pass

    cc, cwnd, cwnd_f = _cc_init(cc, init_window, max_window)

    pn = 1

    start_offset = 0
    meta_flags = 0
    if resume:
        meta_flags |= _MF_RESUME_REQ
    if token is not None:
        meta_flags |= _MF_HAS_TOKEN

    meta_payload = struct.pack("!QB", int(total_len) & 0xFFFFFFFFFFFFFFFF, int(meta_flags) & 0xFF)
    if path_text:
        meta_payload += _to_bytes(path_text)[:512]
    if token is not None:
        meta_payload += struct.pack("!H", len(token) & 0xFFFF) + token

    body = _pack_frame(_FT_META, meta_payload)
    sock.sendto(_pack_pkt(_PT_INITIAL, cid, pn, body, psk=psk), addr)
    stats["pkts_sent"] += 1
    pn = (pn + 1) & 0xFFFFFFFF

    def _send_stream(pkt_pn, off, data, pt=_PT_1RTT):
        off32 = int(off) & 0xFFFFFFFF
        if len(data) > 65535:
            data = data[:65535]
        fp = struct.pack("!HIH", int(stream_id) & 0xFFFF, off32, len(data)) + data
        b = _pack_frame(_FT_STREAM, fp)
        sock.sendto(_pack_pkt(pt, cid, pkt_pn, b, psk=psk), addr)
        stats["pkts_sent"] += 1

    t_hand = time.time()
    server_allows_0rtt = bool(resume and enable_0rtt)
    pending_retry = False

    while True:
        if total_timeout and (time.time() - t_hand) > total_timeout:
            break
        try:
            pkt, _ = sock.recvfrom(4096)
        except socket.timeout:
            break
        except Exception:
            break
        up = _unpack_pkt(pkt, psk=psk)
        if not up:
            continue
        rpt, _fl, rcid, _rpn, rbody = up
        if rcid != cid:
            continue

        if rpt == _PT_RETRY:
            for ft, fp in _iter_frames(rbody):
                if ft == _FT_RETRY and len(fp) >= 2:
                    (tlen,) = struct.unpack("!H", fp[:2])
                    tok = fp[2:2 + int(tlen)]
                    if tok:
                        stats["retry_used"] = True
                        stats["server_token"] = tok
                        token = tok
                        pending_retry = True
            break

        for ft, fp in _iter_frames(rbody):
            if ft == _FT_RESUME and len(fp) >= 8:
                (start_offset,) = struct.unpack("!Q", fp[:8])
                try:
                    fileobj.seek(int(start_offset), os.SEEK_SET)
                except Exception:
                    start_offset = 0
                break
        if start_offset:
            break

    if pending_retry and token is not None:
        pn_retry = pn
        pn = (pn + 1) & 0xFFFFFFFF

        meta_flags = 0
        if resume:
            meta_flags |= _MF_RESUME_REQ
        meta_flags |= _MF_HAS_TOKEN
        meta_payload = struct.pack("!QB", int(total_len) & 0xFFFFFFFFFFFFFFFF, int(meta_flags) & 0xFF)
        if path_text:
            meta_payload += _to_bytes(path_text)[:512]
        meta_payload += struct.pack("!H", len(token) & 0xFFFF) + token

        body = _pack_frame(_FT_META, meta_payload)
        sock.sendto(_pack_pkt(_PT_INITIAL, cid, pn_retry, body, psk=psk), addr)
        stats["pkts_sent"] += 1

        # wait a bit for RESUME (optional)
        t2 = time.time()
        while True:
            if total_timeout and (time.time() - t2) > total_timeout:
                break
            try:
                pkt, _ = sock.recvfrom(4096)
            except socket.timeout:
                break
            except Exception:
                break
            up = _unpack_pkt(pkt, psk=psk)
            if not up:
                continue
            _pt, _fl, rcid, _rpn, rbody = up
            if rcid != cid:
                continue
            for ft, fp in _iter_frames(rbody):
                if ft == _FT_RESUME and len(fp) >= 8:
                    (start_offset,) = struct.unpack("!Q", fp[:8])
                    try:
                        fileobj.seek(int(start_offset), os.SEEK_SET)
                    except Exception:
                        start_offset = 0
                    break
            if start_offset:
                break

    stats["start_offset"] = int(start_offset)

    in_flight = {}

    next_off = int(start_offset)
    eof = False
    failed = False
    t_start = time.time()

    def _read_chunk():
        data = fileobj.read(chunk)
        if not data:
            return None
        data = _to_bytes(data)
        if _h is not None:
            _h.update(data)
        return data

    largest_acked = 0

    while not eof and len(in_flight) < cwnd:
        data = _read_chunk()
        if data is None:
            eof = True
            break
        pt_use = _PT_0RTT if server_allows_0rtt else _PT_1RTT
        _send_stream(pn, next_off, data, pt=pt_use)
        in_flight[pn] = (time.time(), 0, next_off, data, pt_use)
        stats["bytes_sent_payload"] += len(data)
        next_off += len(data)
        pn = (pn + 1) & 0xFFFFFFFF

    while in_flight or not eof:
        if total_timeout and (time.time() - t_start) > total_timeout:
            failed = True
            break

        try:
            pkt, _ = sock.recvfrom(4096)
            up = _unpack_pkt(pkt, psk=psk)
            if up:
                rpt, _fl, rcid, _rpn, rbody = up
                if rcid == cid:
                    if rpt == _PT_RETRY:
                        server_allows_0rtt = False

                    for ft, fp in _iter_frames(rbody):
                        if ft != _FT_ACK:
                            continue
                        if len(fp) < 16:
                            continue
                        largest, ack_upto, sack_mask = struct.unpack("!IIQ", fp[:16])
                        largest_acked = max(largest_acked, int(largest))
                        now = time.time()
                        newly_acked = 0

                        for p in [p for p in list(in_flight.keys()) if p <= int(ack_upto)]:
                            ts, _tries, _off, _data, _pt_use = in_flight.pop(p)
                            _update_rtt(now - ts)
                            stats["pkts_acked"] += 1
                            newly_acked += 1

                        base = (int(ack_upto) + 1) & 0xFFFFFFFF
                        if sack_mask:
                            for i in range(64):
                                if (sack_mask >> i) & 1:
                                    p = (base + i) & 0xFFFFFFFF
                                    if p in in_flight:
                                        ts, _tries, _off, _data, _pt_use = in_flight.pop(p)
                                        _update_rtt(now - ts)
                                        stats["pkts_sacked"] += 1
                                        newly_acked += 1

                            if fast_retx and (base in in_flight):
                                ts, tries, off, data, pt_use = in_flight[base]
                                if tries < retries:
                                    _send_stream(base, off, data, pt=pt_use if pt_use != _PT_0RTT else _PT_1RTT)
                                    in_flight[base] = (time.time(), tries + 1, off, data, _PT_1RTT)
                                    stats["pkts_retx"] += 1
                                    stats["loss_events"] += 1
                                    cwnd, cwnd_f = _cc_on_loss(cc, cwnd, cwnd_f, max_window)

                        cwnd, cwnd_f = _cc_on_ack(cc, cwnd, cwnd_f, newly_acked, max_window)

        except socket.timeout:
            pass
        except Exception:
            pass

        now = time.time()
        to = float(rtt["timeout"]) if rtt["timeout"] else timeout
        for p in list(in_flight.keys()):
            ts, tries, off, data, pt_use = in_flight[p]
            if (now - ts) >= to:
                if tries >= retries:
                    failed = True
                    in_flight.clear()
                    break
                _send_stream(p, off, data, pt=_PT_1RTT)
                in_flight[p] = (now, tries + 1, off, data, _PT_1RTT)
                stats["pkts_retx"] += 1
                stats["loss_events"] += 1
                cwnd, cwnd_f = _cc_on_loss(cc, cwnd, cwnd_f, max_window)

        if failed:
            break

        while not eof and len(in_flight) < cwnd:
            data = _read_chunk()
            if data is None:
                eof = True
                break
            pt_use = _PT_0RTT if server_allows_0rtt else _PT_1RTT
            _send_stream(pn, next_off, data, pt=pt_use)
            in_flight[pn] = (time.time(), 0, next_off, data, pt_use)
            stats["bytes_sent_payload"] += len(data)
            next_off += len(data)
            pn = (pn + 1) & 0xFFFFFFFF

    dur = max(1e-9, time.time() - t_start)
    stats["duration_s"] = dur
    stats["throughput_Bps"] = float(stats["bytes_sent_payload"]) / dur
    stats["srtt"] = rtt["srtt"]
    stats["rttvar"] = rtt["rttvar"]
    stats["timeout"] = rtt["timeout"]
    stats["cwnd_end"] = cwnd

    if failed:
        try:
            sock.close()
        except Exception:
            pass
        so = kwargs.get("stats_obj")
        if isinstance(so, dict):
            so.update(stats)
        if kwargs.get("return_stats"):
            return (False, stats)
        return False

    done_payload = b"DONE"
    if _h is not None:
        done_payload += _h.digest()
    body = _pack_frame(_FT_DONE, done_payload)
    for _i in range(3):
        try:
            sock.sendto(_pack_pkt(_PT_1RTT, cid, pn, body, psk=psk), addr)
            stats["pkts_sent"] += 1
        except Exception:
            pass
        time.sleep(0.02)

    try:
        sock.close()
    except Exception:
        pass

    so = kwargs.get("stats_obj")
    if isinstance(so, dict):
        so.update(stats)
    if kwargs.get("return_stats"):
        return (True, stats)
    return True

def _udp_quic_recv(fileobj, host, port, **kwargs):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host or "", int(port)))

    if kwargs.get("print_url"):
        _emit("Listening: udp://%s:%d/" % (host or "0.0.0.0", sock.getsockname()[1]), logger=logger, level=logging.INFO, stream="stdout")
        try:
            sys.stdout.flush()
        except Exception:
            pass

    timeout = float(kwargs.get("timeout", 1.0))
    try:
        sock.settimeout(timeout)
    except Exception:
        pass

    chunk = int(kwargs.get("chunk", 1200))
    window = int(kwargs.get("window", 32))
    total_timeout = float(kwargs.get("total_timeout", 0.0))

    framing = (kwargs.get("framing") or "").lower()
    want_sha = bool(kwargs.get("sha256") or kwargs.get("sha") or kwargs.get("want_sha"))
    _h = hashlib.sha256() if want_sha else None

    psk = kwargs.get("psk", None)
    if psk:
        psk = _to_bytes(psk)

    stream_map = kwargs.get("stream_map", None)  # {stream_id:int -> fileobj}
    if not isinstance(stream_map, dict):
        stream_map = {}
    if 0 not in stream_map:
        stream_map[0] = fileobj

    stateless_retry = bool(kwargs.get("stateless_retry", False))
    retry_secret = kwargs.get("retry_secret", None)
    if retry_secret is not None:
        retry_secret = _to_bytes(retry_secret)

    total_len = None
    bytes_written = {}
    got_digest = None

    resume_off = 0
    try:
        resume_off = int(kwargs.get("resume_offset", 0) or 0)
    except Exception:
        resume_off = 0

    active_cid = None

    received = {}
    expected_off = {}
    expected_off[0] = int(max(0, resume_off))

    ack_upto = 0
    seen_pn = set([0])
    largest_pn = 0

    done = False
    complete = False
    t0 = time.time()

    allow_0rtt = not stateless_retry  # if no retry, allow

    def _send_ack(addr, cid):
        base = (int(ack_upto) + 1) & 0xFFFFFFFF
        mask = 0
        for p in seen_pn:
            d = int(p) - int(base)
            if 0 <= d < 64:
                mask |= (1 << d)
        payload = struct.pack("!IIQ",
                              int(largest_pn) & 0xFFFFFFFF,
                              int(ack_upto) & 0xFFFFFFFF,
                              int(mask) & 0xFFFFFFFFFFFFFFFF)
        body = _pack_frame(_FT_ACK, payload)
        try:
            sock.sendto(_pack_pkt(_PT_1RTT, cid, 0, body, psk=psk), addr)
        except Exception:
            pass

    def _send_retry(addr, cid, token):
        token = _to_bytes(token)
        fp = struct.pack("!H", len(token) & 0xFFFF) + token
        body = _pack_frame(_FT_RETRY, fp)
        try:
            sock.sendto(_pack_pkt(_PT_RETRY, cid, 1, body, psk=psk), addr)
        except Exception:
            pass

    def _send_resume(addr, cid, stream_id, off):
        body = _pack_frame(_FT_RESUME, struct.pack("!Q", int(off) & 0xFFFFFFFFFFFFFFFF))
        try:
            sock.sendto(_pack_pkt(_PT_HANDSHAKE, cid, 2, body, psk=psk), addr)
        except Exception:
            pass

    while True:
        if total_timeout and (time.time() - t0) > total_timeout:
            break
        try:
            pkt, addr = sock.recvfrom(65536)
        except socket.timeout:
            if complete and want_sha:
                continue
            if done:
                break
            continue
        except Exception:
            break

        up = _unpack_pkt(pkt, psk=psk)
        if not up:
            continue
        pt, _flags, cid, pn, body = up

        if active_cid is None:
            active_cid = cid
        if cid != active_cid:
            continue

        pn_i = int(pn) & 0xFFFFFFFF
        largest_pn = max(largest_pn, pn_i)
        seen_pn.add(pn_i)
        while ((ack_upto + 1) & 0xFFFFFFFF) in seen_pn:
            ack_upto = (ack_upto + 1) & 0xFFFFFFFF

        if pt == _PT_INITIAL:
            for ft, fp in _iter_frames(body):
                if ft != _FT_META or len(fp) < 9:
                    continue
                (tlen, mflags) = struct.unpack("!QB", fp[:9])
                if tlen:
                    try:
                        total_len = int(tlen)
                    except Exception:
                        total_len = None

                token = None
                if int(mflags) & _MF_HAS_TOKEN:
                    if len(fp) >= 9 + 2:
                        buf = fp[9:]
                        found = None
                        scan_max = min(len(buf), 64)
                        for i in range(max(0, len(buf) - scan_max), len(buf) - 1):
                            if i + 2 > len(buf):
                                continue
                            (tl,) = struct.unpack("!H", buf[i:i+2])
                            if tl == (len(buf) - (i + 2)) and tl > 0:
                                found = buf[i+2:]
                                break
                        if found is not None:
                            token = found

                if stateless_retry and retry_secret:
                    if (token is None) or (not _token_valid(retry_secret, addr, cid, token)):
                        tok = _retry_token(retry_secret, addr, cid)
                        allow_0rtt = False
                        _send_retry(addr, cid, tok)

                        _send_ack(addr, cid)
                        continue
                    else:
                        allow_0rtt = True

                if int(mflags) & _MF_RESUME_REQ:
                    off0 = int(expected_off.get(0, 0))
                    _send_resume(addr, cid, 0, off0)

            _send_ack(addr, cid)
            continue

        if pt == _PT_0RTT and not allow_0rtt:
            _send_ack(addr, cid)
            continue

        for ft, fp in _iter_frames(body):
            if ft == _FT_DONE:
                done = True
                if fp.startswith(b"DONE") and len(fp) >= 4 + 32:
                    got_digest = fp[4:4+32]
                continue

            if ft != _FT_STREAM:
                continue
            if len(fp) < 2 + 4 + 2:
                continue

            sid, off32, dlen = struct.unpack("!HIH", fp[:8])
            sid = int(sid) & 0xFFFF
            data = fp[8:8+int(dlen)]

            out = stream_map.get(sid, None)
            if out is None:
                continue

            if sid not in received:
                received[sid] = {}
            if sid not in expected_off:
                expected_off[sid] = 0
            if sid not in bytes_written:
                bytes_written[sid] = 0

            exp = int(expected_off[sid])
            off = int(off32)
            if off + len(data) < exp:
                continue
            if off > exp + window * chunk * 8:
                continue

            if off == exp:
                out.write(data)
                bytes_written[sid] += len(data)
                if _h is not None and sid == 0:
                    _h.update(_to_bytes(data))
                expected_off[sid] = exp + len(data)

                while int(expected_off[sid]) in received[sid]:
                    buf = received[sid].pop(int(expected_off[sid]))
                    out.write(buf)
                    bytes_written[sid] += len(buf)
                    if _h is not None and sid == 0:
                        _h.update(_to_bytes(buf))
                    expected_off[sid] = int(expected_off[sid]) + len(buf)
            else:
                if off not in received[sid]:
                    received[sid][off] = data

        _send_ack(addr, cid)

        bw0 = int(bytes_written.get(0, 0))
        if (framing == "len") and (total_len is not None) and (bw0 >= int(total_len)):
            complete = True
            if not want_sha:
                break
            if got_digest is not None:
                break

        if done:
            if want_sha and got_digest is None:
                continue
            break

    if want_sha:
        if got_digest is None:
            try:
                sock.close()
            except Exception:
                pass
            return False
        if _h is None or _h.digest() != got_digest:
            try:
                sock.close()
            except Exception:
                pass
            return False

    try:
        sock.close()
    except Exception:
        pass

    try:
        stream_map.get(0, fileobj).seek(0, 0)
    except Exception:
        pass

    return True


def send_path(path: str, url: str, fmt: str = "tar", compression: Optional[str] = None, **kwargs: Any) -> bool:
    """
    Convenience helper: package a directory (or single file) and send it using upload_file_to_internet_file.

    - path: file or directory path.
    - url: destination URL (tcp://, udp://, ftp://, etc.)
    - fmt: "tar" or "zip"
    - compression: for tar: "gz" or None; for zip: ignored (zip uses deflate by default)
    Extra kwargs are forwarded to upload_file_to_internet_file via query params or directly.
    Returns whatever upload_file_to_internet_file returns.
    """
    try:
        import tempfile, tarfile, zipfile
    except Exception:
        return False

    p = os.path.abspath(path)

    tmp = None
    try:
        tmp = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024, mode="w+b")
        if fmt.lower() == "zip":
            zf = zipfile.ZipFile(tmp, mode="w", compression=zipfile.ZIP_DEFLATED)
            try:
                if os.path.isdir(p):
                    for root, dirs, files in os.walk(p):
                        for fn in files:
                            full = os.path.join(root, fn)
                            rel = os.path.relpath(full, os.path.dirname(p))
                            zf.write(full, rel)
                else:
                    zf.write(p, os.path.basename(p))
            finally:
                zf.close()
        else:
            mode = "w"
            if compression in ("gz", "gzip"):
                mode = "w:gz"
            tf = tarfile.open(fileobj=tmp, mode=mode)
            try:
                arcname = os.path.basename(p.rstrip(os.sep))
                if os.path.isdir(p):
                    tf.add(p, arcname=arcname)
                else:
                    tf.add(p, arcname=os.path.basename(p))
            finally:
                tf.close()

        tmp.seek(0, 0)
        return upload_file_to_internet_file(tmp, url, **kwargs)
    finally:
        try:
            if tmp is not None:
                tmp.close()
        except Exception:
            pass

def recv_to_path(url: str, out_path: str, auto_extract: bool = False, extract_dir: Optional[str] = None, keep_archive: bool = True, **kwargs: Any) -> Union[str, bool]:
    # listen-mode HTTP/HTTPS can stream straight to disk (avoid BytesIO)
    try:
        up = urlparse(url)
        if (up.scheme or "").lower() in ("http", "https"):
            qs = parse_qs(up.query or "")
            if _qflag(qs, "listen", False) or _qflag(qs, "recv", False):
                url2 = url
                if "out" not in qs:
                    url2 = _set_query_param(url2, "out", out_path)
                if "mkdir" not in qs:
                    url2 = _set_query_param(url2, "mkdir", "1")
                if "overwrite" not in qs:
                    url2 = _set_query_param(url2, "overwrite", "1")
                ok = download_file_from_internet_file(url2, **kwargs)
                return out_path if ok is not False else False
    except Exception:
        pass

    f = download_file_from_internet_file(url, **kwargs)
    if f is False:
        return False
    try:
        parent = os.path.dirname(os.path.abspath(out_path))
        if parent and not os.path.isdir(parent):
            try:
                os.makedirs(parent)
            except Exception:
                pass
        outfp = open(out_path, "wb")
        try:
            shutil.copyfileobj(f, outfp)
        finally:
            try:
                outfp.close()
            except Exception:
                pass
    except Exception:
        return False

    if auto_extract:
        try:
            import tarfile, zipfile
            ext = out_path.lower()
            if extract_dir is None:
                extract_dir = os.path.dirname(os.path.abspath(out_path)) or "."
            if ext.endswith(".zip"):
                zf = zipfile.ZipFile(out_path, "r")
                try:
                    zf.extractall(extract_dir)
                finally:
                    zf.close()
            elif ext.endswith(".tar") or ext.endswith(".tar.gz") or ext.endswith(".tgz") or ext.endswith(".tar.bz2") or ext.endswith(".tbz2") or ext.endswith(".tar.xz") or ext.endswith(".txz"):
                tf = tarfile.open(out_path, "r:*")
                try:
                    tf.extractall(extract_dir)
                finally:
                    tf.close()
            if not keep_archive:
                try:
                    os.unlink(out_path)
                except Exception:
                    pass
        except Exception:
            pass
    return out_path

def download_file_from_internet_file(url: str, **kwargs: Any):
    """Top-level dispatcher: returns a file-like object or False."""
    p = urlparse(url)
    if p.scheme in ("http", "https"):
        try:
            qs = parse_qs(p.query or "")
            if _qflag(qs, "listen", False) or _qflag(qs, "recv", False):
                return _recv_file_over_http(url, logger=kwargs.get("logger"))
        except Exception:
            pass
        return download_file_from_http_file(url, **kwargs)
    if p.scheme in ("ftp", "ftps"):
        return download_file_from_ftp_file(url, **kwargs)
    if p.scheme in ("tftp", ):
        return download_file_from_tftp_file(url, **kwargs)
    if p.scheme in ("sftp", "scp"):
        if __use_pysftp__ and havepysftp:
            return download_file_from_pysftp_file(url, **kwargs)
        return download_file_from_sftp_file(url, **kwargs)

    if p.scheme in ("data", ):
        return data_url_decode(url)[0]

    if p.scheme in ("file" or ""):
        return io.open(unquote(p.path), "rb")

    if p.scheme in ("tcp", "udp") or p.scheme in _BT_SCHEMES:
        parts, o = _parse_net_url(url)
        path_text = parts.path or "/"
        if parts.scheme in _BT_SCHEMES:
            qs = parse_qs(parts.query or "")
            host, port = _bt_host_channel_from_url(parts, qs, o)
            proto = "bt"
        else:
            host = o.get("bind") or parts.hostname or ""
            port = parts.port or 0
            proto = parts.scheme

        outfile = None
        dest_path = None
        resume_off = 0

        if o.get("resume"):
            dest_path = o.get("resume_to")
            if not dest_path and o.get("save"):
                dest_path = _choose_output_path(_guess_filename(url), o.get("overwrite", False), o.get("save_dir"))
            if dest_path:
                try:
                    if os.path.exists(dest_path):
                        outfile = open(dest_path, "r+b")
                        outfile.seek(0, 2)
                        resume_off = int(outfile.tell())
                    else:
                        _ensure_dir(os.path.dirname(dest_path) or ".")
                        outfile = open(dest_path, "w+b")
                        resume_off = 0
                except Exception:
                    outfile = None
                    dest_path = None
                    resume_off = 0

        if outfile is None:
            outfile = MkTempFile()

        ok = recv_to_fileobj(
            outfile, host=host, port=port, proto=proto,
            mode=o.get("mode"), timeout=o.get("timeout"), total_timeout=o.get("total_timeout"),
            window=o.get("window"), retries=o.get("retries"), chunk=o.get("chunk"),
            print_url=o.get("print_url"), resume_offset=resume_off, path_text=path_text, framing=o.get("framing"), handshake=o.get("handshake"), send_path=o.get("send_path"), logger=kwargs.get("logger")
        )
        if not ok:
            return False

        if dest_path:
            try:
                outfile.seek(0, 0)
            except Exception:
                pass
            return outfile

        if o.get("save"):
            out_path = _choose_output_path(_guess_filename(url), o.get("overwrite", False), o.get("save_dir"))
            try:
                _copy_fileobj_to_path(outfile, out_path, overwrite=o.get("overwrite", False))
                _emit("Saved: %s" % out_path, logger=kwargs.get("logger"), level=logging.INFO, stream="stdout")
                sys.stdout.flush()
            except Exception:
                return False

        try:
            outfile.seek(0, 0)
        except Exception:
            pass
        return outfile

    return False

def download_file_from_internet_bytes(url: str, **kwargs: Any) -> Union[bytes, bool]:
    fp = download_file_from_internet_file(url, **kwargs)
    if not fp:
        return False
    try:
        return fp.read()
    finally:
        try:
            fp.close()
        except Exception:
            pass


def _serve_file_over_http(fileobj, url, logger=None):
    p = urlparse(url)
    qs = parse_qs(p.query or "")

    bind = _qstr(qs, "bind", None) or (p.hostname or "0.0.0.0")
    port = p.port if (p.port is not None) else int(_qnum(qs, "port", 0, cast=int))
    path = p.path or "/"
    print_url = _qflag(qs, "print_url", False)
    max_clients = int(_qnum(qs, "max_clients", 1, cast=int))
    idle_timeout = float(_qnum(qs, "idle_timeout", 0.0, cast=float))
    allow_range = _qflag(qs, "range", True)
    gzip_on = _qflag(qs, "gzip", False)
    cors = _qflag(qs, "cors", False)
    content_type = _qstr(qs, "content_type", None)
    download = _qstr(qs, "download", None)
    auth = _qstr(qs, "auth", None)
    extra_headers = _parse_kv_headers(qs, prefix="hdr_")

    file_path = getattr(fileobj, "name", None)
    can_reopen = False
    if file_path and isinstance(file_path, (str,)):
        try:
            can_reopen = os.path.isfile(file_path)
        except Exception:
            can_reopen = False

    use_direct = (not can_reopen) and (max_clients == 1)
    data_bytes = None
    if (not can_reopen) and (not use_direct):
        try:
            pos = fileobj.tell()
        except Exception:
            pos = None
        try:
            try:
                fileobj.seek(0, 0)
            except Exception:
                pass
            data_bytes = fileobj.read()
        finally:
            if pos is not None:
                try:
                    fileobj.seek(pos, 0)
                except Exception:
                    pass
        data_bytes = _to_bytes(data_bytes)

    default_name = os.path.basename(path.strip("/")) or "download.bin"
    if download and download not in ("1", "true", "yes"):
        disp_name = download
    else:
        disp_name = default_name

    if not content_type:
        try:
            content_type = mimetypes.guess_type(default_name)[0] or "application/octet-stream"
        except Exception:
            content_type = "application/octet-stream"

    auth_user = auth_pass = None
    if auth:
        if ":" in auth:
            auth_user, auth_pass = auth.split(":", 1)
        else:
            auth_user, auth_pass = auth, ""

    state = {"served": 0, "stop": False, "logger": logger}

    def _open_reader():
        if use_direct:
            try:
                fileobj.seek(0, 0)
            except Exception:
                pass
            return fileobj
        if can_reopen:
            return open(file_path, "rb")
        return MkTempFile(data_bytes)

    class _Handler(BaseHTTPRequestHandler):
        server_version = "PyWWWGetHTTP/1.0"

        def log_message(self, fmt, *args):
            # quiet by default
            return

        def _unauth(self):
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="pywwwget"')
            self.send_header("Connection", "close")
            self.end_headers()

        def _check_auth(self):
            if not auth_user:
                return True
            h = self.headers.get("Authorization")
            if not h or not h.startswith("Basic "):
                return False
            try:
                raw = base64.b64decode(h.split(" ", 1)[1].strip().encode("utf-8"))
                if not isinstance(raw, bytes):
                    raw = _to_bytes(raw)
                pair = raw.decode("utf-8", "ignore")
            except Exception:
                return False
            if ":" in pair:
                u, pw = pair.split(":", 1)
            else:
                u, pw = pair, ""
            return (u == auth_user and pw == auth_pass)

        def do_HEAD(self):
            self._do_send(body=False)

        def do_GET(self):
            self._do_send(body=True)

        def _do_send(self, body=True):
            req_path = self.path.split("?", 1)[0]
            if req_path != path:
                self.send_response(404)
                self.send_header("Connection", "close")
                self.end_headers()
                return

            if not self._check_auth():
                self._unauth()
                return

            f = _open_reader()
            try:
                try:
                    f.seek(0, 2)
                    total = f.tell()
                    f.seek(0, 0)
                except Exception:
                    total = None
                    try:
                        f.seek(0, 0)
                    except Exception:
                        pass

                start = 0
                end = None
                status = 200
                if allow_range and total is not None:
                    rng = self.headers.get("Range")
                    if rng and rng.startswith("bytes="):
                        try:
                            spec = rng.split("=", 1)[1].strip()
                            a, b = spec.split("-", 1)
                            if a:
                                start = int(a)
                            if b:
                                end = int(b)
                            status = 206
                        except Exception:
                            start = 0
                            end = None
                            status = 200

                if total is not None and start < 0:
                    start = 0
                if total is not None and start > total:
                    start = total

                if total is not None:
                    f.seek(start, 0)
                    remain = total - start
                    if end is not None and end >= start:
                        remain = min(remain, (end - start + 1))
                else:
                    remain = None

                use_gzip = False
                if gzip_on and status == 200:
                    ae = self.headers.get("Accept-Encoding", "") or ""
                    if "gzip" in ae.lower():
                        if content_type.startswith("text/") or content_type in ("application/json", "application/xml"):
                            use_gzip = True

                self.send_response(status)
                self.send_header("Content-Type", content_type)
                if cors:
                    self.send_header("Access-Control-Allow-Origin", "*")

                if download:
                    self.send_header("Content-Disposition", 'attachment; filename="%s"' % disp_name)

                for hk, hv in extra_headers.items():
                    try:
                        self.send_header(hk, hv)
                    except Exception:
                        pass

                if total is not None:
                    if status == 206:
                        last = start + (remain - 1 if remain is not None else 0)
                        self.send_header("Content-Range", "bytes %d-%d/%d" % (start, last, total))
                    self.send_header("Accept-Ranges", "bytes")

                if use_gzip:
                    self.send_header("Content-Encoding", "gzip")

                if not body:
                    self.send_header("Connection", "close")
                    self.end_headers()
                    return

                if use_gzip:
                    self.send_header("Connection", "close")
                    self.end_headers()
                    gz = gzip.GzipFile(fileobj=self.wfile, mode="wb")
                    try:
                        shutil.copyfileobj(f, gz)
                    finally:
                        try:
                            gz.close()
                        except Exception:
                            pass
                else:
                    if remain is not None:
                        self.send_header("Content-Length", str(int(remain)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    if remain is None:
                        shutil.copyfileobj(f, self.wfile)
                    else:
                        left = int(remain)
                        buf = 64 * 1024
                        while left > 0:
                            chunk = f.read(min(buf, left))
                            if not chunk:
                                break
                            self.wfile.write(chunk)
                            left -= len(chunk)

                state["served"] += 1
                if state["served"] >= max_clients:
                    state["stop"] = True
            finally:
                try:
                    if not use_direct: f.close()
                except Exception:
                    pass

    class _ThreadingHTTPServer(_socketserver.ThreadingMixIn, HTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    try:
        httpd = _ThreadingHTTPServer((bind, int(port)), _Handler)
    except Exception:
        return False

    bound_port = httpd.server_address[1]
    if print_url:
        for u in _listen_urls(("https" if tls_on else p.scheme), bind, bound_port, path, p.query):
            try:
                _emit("Listening: %s" % u, logger=logger, level=logging.INFO, stream="stdout")
            except Exception:
                pass
        try:
            sys.stdout.flush()
        except Exception:
            pass

    if idle_timeout and idle_timeout > 0:
        try:
            httpd.timeout = float(idle_timeout)
        except Exception:
            pass

    try:
        sidecar_start = None
        while not state["stop"]:
            httpd.handle_request()

            if idle_timeout and idle_timeout > 0:
                if state["served"] == 0:
                    break

            if expect_sidecar and state.get("upload_done") and (not state.get("sidecar_done")):
                if sidecar_start is None:
                    sidecar_start = time.time()
                if sidecar_timeout is not None and sidecar_timeout >= 0:
                    if (time.time() - sidecar_start) >= float(sidecar_timeout):
                        try:
                            if print_hash:
                                _emit("Sidecar timeout (%.1fs); continuing without enforcement." % float(sidecar_timeout), logger=state.get("logger"), level=logging.WARNING, stream="stdout")
                                sys.stdout.flush()
                                if sidecar_timeout_mode == "delete":
                                    try:
                                        sp = state.get("saved_path")
                                        if sp and os.path.exists(sp):
                                            os.unlink(sp)
                                            try:
                                                _emit("Deleted (sidecar timeout): %s" % sp, logger=state.get("logger"), level=logging.WARNING, stream="stdout")
                                                sys.stdout.flush()
                                            except Exception:
                                                pass
                                    except Exception:
                                        pass
                        except Exception:
                            pass
                        break
    finally:
        try:
            httpd.server_close()
        except Exception:
            pass

    return bound_port


def _recv_file_over_http(url, logger=None):
    p = urlparse(url)
    qs = parse_qs(p.query or "")

    bind = _qstr(qs, "bind", None) or (p.hostname or "0.0.0.0")
    port = p.port if (p.port is not None) else int(_qnum(qs, "port", 0, cast=int))
    want_path = p.path or "/"
    print_url = _qflag(qs, "print_url", False)
    max_clients = int(_qnum(qs, "max_clients", 1, cast=int))
    idle_timeout = float(_qnum(qs, "idle_timeout", 0.0, cast=float))
    cors = _qflag(qs, "cors", False)
    auth = _qstr(qs, "auth", None)
    out_path = _qstr(qs, "out", None)
    use_tmp = _qflag(qs, "tmp", False)
    overwrite = _qflag(qs, "overwrite", False)
    mkdir = _qflag(qs, "mkdir", False)
    max_size = _qnum(qs, "max_size", None, cast=int)
    print_save = _qflag(qs, "print_save", False)
    hash_algo = (_qstr(qs, "hash", None) or "").lower().strip() or None
    expect_hash = (_qstr(qs, "expect_hash", None) or _qstr(qs, "want_hash", None) or "").strip() or None
    print_hash = _qflag(qs, "print_hash", True)
    expect_sidecar = _qflag(qs, "expect_sidecar", False) or (_qstr(qs, "stream_hash", "") or "").lower().strip() == "sidecar"
    sidecar_suffix = _qstr(qs, "sidecar_suffix", ".hash")
    sidecar_timeout = _qnum(qs, "sidecar_timeout", None, cast=float)
    sidecar_timeout_mode = (_qstr(qs, "sidecar_timeout_mode", "keep") or "keep").lower().strip()
    if sidecar_timeout_mode not in ("keep", "delete"):
        sidecar_timeout_mode = "keep"
    if sidecar_timeout is None and expect_sidecar and idle_timeout and float(idle_timeout) > 0:
        sidecar_timeout = float(idle_timeout)
    extra_headers = _parse_kv_headers(qs, prefix="hdr_")
    method_only = (_qstr(qs, "method", "") or "").upper().strip()

    state = {
        "served": 0,
        "logger": logger,
        "stop": False,
        "out": None,
        "upload_digest": None,
        "sidecar_digest": None,
        "saved_path": None,
        "upload_done": False,
        "sidecar_done": False,
    }

    userpass = None
    if auth:
        if ":" in auth:
            userpass = auth.split(":", 1)
        else:
            userpass = [auth, ""]

    class Handler(BaseHTTPRequestHandler):
        server_version = "PyWWWGetHTTPRecv/1.0"
        def _unauth(self):
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="PyWWWGet"')
            self.end_headers()

        def _check_auth(self):
            if not userpass:
                return True
            ah = self.headers.get("Authorization")
            if not ah or not ah.lower().startswith("basic "):
                return False
            try:
                import base64
                raw = base64.b64decode(ah.split(None, 1)[1].strip().encode("ascii"))
                u, pw = raw.decode("utf-8", "ignore").split(":", 1)
                return (u == userpass[0] and pw == userpass[1])
            except Exception:
                return False

        def log_message(self, *args):
            return

        def _common_headers(self):
            if cors:
                self.send_header("Access-Control-Allow-Origin", "*")
            for k, v in extra_headers.items():
                self.send_header(k, v)

        def do_OPTIONS(self):
            self.send_response(204)
            self.send_header("Access-Control-Allow-Methods", "PUT, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type, Content-Length")
            self._common_headers()
            self.end_headers()
def _handle_sidecar(self):
    want_sidecar = (want_path or "/") + (sidecar_suffix or ".hash")
    if self.path.split("?", 1)[0] != want_sidecar:
        self.send_response(404)
        self._common_headers()
        self.end_headers()
        return
    if not self._check_auth():
        self._unauth()
        return

    length = self.headers.get("Content-Length")
    data = b""
    try:
        if length is not None:
            data = self.rfile.read(int(length))
        else:
            data = self.rfile.read(65536)
    except Exception:
        data = b""

    try:
        txt = data.decode("utf-8", "ignore").strip()
    except Exception:
        txt = ""
    dig = ""
    parts = txt.split()
    if len(parts) == 1:
        dig = parts[0]
    elif len(parts) >= 2:
        if parts[0].lower() == (hash_algo or "").lower():
            dig = parts[1]
        else:
            dig = parts[-1]
    state["sidecar_digest"] = dig
    state["sidecar_done"] = True

    ud = state.get("upload_digest")
    if ud and dig and ud.lower() != dig.lower():
        try:
            sp = state.get("saved_path")
            if sp and os.path.exists(sp):
                os.unlink(sp)
        except Exception:
            pass
        self.send_response(422)
        self._common_headers()
        self.end_headers()
        state["stop"] = True
        return

    if state.get("upload_done") and ud and dig and ud.lower() == dig.lower():
        state["stop"] = True

    self.send_response(200)
    self._common_headers()
    self.send_header("Content-Type", "text/plain")
    self.end_headers()
    try:
        self.wfile.write(b"OK\n")
    except Exception:
        pass



def _handle_upload(self):
    if method_only and self.command != method_only:
        self.send_response(405)
        self._common_headers()
        self.end_headers()
        return
    if self.path.split("?", 1)[0] != want_path:
        self.send_response(404)
        self._common_headers()
        self.end_headers()
        return
    if not self._check_auth():
        self._unauth()
        return

    length = self.headers.get("Content-Length")

    out = None
    outfp = None
    outname = None

    try:
        if out_path:
            outname = out_path
            if mkdir:
                try:
                    parent = os.path.dirname(os.path.abspath(outname))
                    if parent and not os.path.isdir(parent):
                        os.makedirs(parent)
                except Exception:
                    pass
            if (not overwrite) and os.path.exists(outname):
                self.send_response(409)
                self._common_headers()
                self.end_headers()
                return
            outfp = open(outname, "wb")
        elif use_tmp:
            import tempfile
            tf = tempfile.NamedTemporaryFile(delete=False)
            outname = tf.name
            outfp = tf
        else:
            out = MkTempFile()

        total = 0
        if length is not None:
            to_read = int(length)
            while to_read > 0:
                chunk = self.rfile.read(min(65536, to_read))
                if not chunk:
                    break
                total += len(chunk)
                if max_size is not None and max_size >= 0 and total > int(max_size):
                    raise ValueError("max_size exceeded")
                if outfp is not None:
                    outfp.write(chunk)
                else:
                    out.write(chunk)
                to_read -= len(chunk)
        else:
            while True:
                chunk = self.rfile.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if max_size is not None and max_size >= 0 and total > int(max_size):
                    raise ValueError("max_size exceeded")
                if outfp is not None:
                    outfp.write(chunk)
                else:
                    out.write(chunk)

        if outfp is not None:
            try:
                outfp.close()
            except Exception:
                pass
            if print_save and outname:
                try:
                    _emit("Saved: %s" % outname, logger=kwargs.get("logger"), level=logging.INFO, stream="stdout")
                    sys.stdout.flush()
                except Exception:
                    pass
            try:
                out = open(outname, "rb")
            except Exception:
                out = False
        else:
            out.seek(0, 0)

    except Exception:
        try:
            if outfp is not None:
                outfp.close()
        except Exception:
            pass
        try:
            if outname and os.path.exists(outname) and (use_tmp or out_path):
                os.unlink(outname)
        except Exception:
            pass
        self.send_response(413)
        self._common_headers()
        self.end_headers()
        return

    state["out"] = out
    state["served"] += 1
    if state["served"] >= max_clients:
        state["stop"] = True

    self.send_response(200)
    self._common_headers()
    self.send_header("Content-Type", "text/plain")
    self.end_headers()
    try:
        self.wfile.write(b"OK\n")
    except Exception:
        pass

        def do_PUT(self):

            self._handle_upload()

        def do_POST(self):
            self._handle_upload()
    from http.server import HTTPServer, BaseHTTPRequestHandler

    try:
        httpd = HTTPServer((bind, int(port)), Handler)
    except Exception:
        return False

    bound_port = httpd.server_address[1]

    if print_url:
        bind_host = bind or "0.0.0.0"
        for u in _listen_urls("http", bind_host, bound_port, want_path, p.query):
            _emit("Listening: %s" % u, logger=logger, level=logging.INFO, stream="stdout")
        try:
            sys.stdout.flush()
        except Exception:
            pass

    if idle_timeout and idle_timeout > 0:
        try:
            httpd.timeout = float(idle_timeout)
        except Exception:
            pass

    try:
        while not state["stop"]:
            httpd.handle_request()
            if idle_timeout and idle_timeout > 0 and state["served"] == 0:
                break
    finally:
        try:
            httpd.server_close()
        except Exception:
            pass

    return state["out"] if state["out"] is not None else False



def upload_file_to_internet_file(fileobj, url: str, **kwargs: Any):
    """Top-level dispatcher: uploads/sends a file object to the destination URL.

    For stream URLs:
      - tcp://host:port/...
      - udp://host:port/...
      - bt://BDADDR:channel/... (RFCOMM)

    The caller typically provides a seekable file object.
    """
    p = urlparse(url)
    if p.scheme in ("http", "https"):
        return _serve_file_over_http(fileobj, url, logger=kwargs.get("logger"))
    if p.scheme in ("ftp", "ftps"):
        return upload_file_to_ftp_file(fileobj, url)
    if p.scheme in ("tftp",):
        return upload_file_to_tftp_file(fileobj, url)
    if p.scheme in ("sftp", "scp"):
        if __use_pysftp__ and havepysftp:
            return upload_file_to_pysftp_file(fileobj, url)
        return upload_file_to_sftp_file(fileobj, url)
    if p.scheme in ("data",):
        return data_url_encode(fileobj)
    if p.scheme in ("file" or ""):
        try:
            fileobj.seek(0, 0)
        except Exception:
            pass
        _ensure_dir(os.path.dirname(unquote(p.path)) or ".")
        with io.open(unquote(p.path), "wb") as fdst:
            shutil.copyfileobj(fileobj, fdst)
        try:
            fileobj.seek(0, 0)
        except Exception:
            pass
        return fileobj

    if p.scheme in ("tcp", "udp") or p.scheme in _BT_SCHEMES:
        parts, o = _parse_net_url(url)
        path_text = parts.path or "/"

        if parts.scheme in _BT_SCHEMES:
            qs = parse_qs(parts.query or "")
            o2 = dict(o)
            # For sending (client), never treat bind= as the remote host.
            o2["bind"] = None
            host, port = _bt_host_channel_from_url(parts, qs, o2)
            proto = "bt"
            # bt:// historically used raw streaming; do not send PATH preface unless requested.
            send_path = _qflag(qs, "send_path", False) or bool(o.get("send_path"))
            if not send_path:
                path_text = None
        else:
            host = parts.hostname
            port = parts.port or 0
            proto = parts.scheme

        try:
            fileobj.seek(0, 0)
        except Exception:
            pass
        ok = send_from_fileobj(
            fileobj, host=host, port=port, proto=proto,
            mode=o.get("mode"),
            timeout=o.get("timeout"), total_timeout=o.get("total_timeout"),
            wait=o.get("wait"), connect_wait=o.get("connect_wait"),
            wait_timeout=(_resolve_wait_timeout(parts.scheme, o.get("mode"), o) if parts.scheme in ("udp", "tcp") else o.get("timeout")),
            window=o.get("window"), retries=o.get("retries"), chunk=o.get("chunk"),
            resume=o.get("resume"), path_text=path_text,
            done=o.get("done"), done_token=o.get("done_token"), framing=o.get("framing"), sha256=o.get("sha256"),
            logger=kwargs.get("logger"),
        )
        return fileobj if ok else False

    return False

def upload_file_to_internet_bytes(data, url):
    bio = MkTempFile(_to_bytes(data))
    out = upload_file_to_internet_file(bio, url)
    try:
        bio.close()
    except Exception:
        pass
    return out
