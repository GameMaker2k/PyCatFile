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

    $FileInfo: pyfile.py - Last Update: 2/8/2026 Ver. 0.28.8 RC 1 - Author: cooldude2k $
'''

import io
import os
import re
import sys
import time
import hmac
import json
import stat
import atexit
import shutil
import base64
import logging
import zipfile
import platform
import datetime
import binascii
import hashlib
import inspect
import tempfile
import configparser
from io import open, StringIO, BytesIO
__enable_pywwwget__ = True
pywwwget = False
try:
    if(__enable_pywwwget__):
        from .pywwwget import upload_file_to_internet_file, download_file_from_internet_file
        pywwwget = True
    else:
        pywwwget = False
        pass
except ImportError:
    pywwwget = False
from io import open

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
    from safetar import is_tarfile
except ImportError:
    from tarfile import is_tarfile

# TAR file module
try:
    import safetar as tarfile
except ImportError:
        import tarfile

try:
    from multiprocessing import shared_memory
except Exception:
    shared_memory = None

def running_interactively():
    main = sys.modules.get("__main__")
    no_main_file = not hasattr(main, "__file__")
    interactive_flag = bool(getattr(sys.flags, "interactive", 0))
    return no_main_file or interactive_flag

if running_interactively():
    logging.basicConfig(format="%(message)s", stream=PY_STDOUT_TEXT, level=logging.DEBUG)

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
try:
    _ALGORITHMS_AVAILABLE = set(hashlib.algorithms_available)
except AttributeError:
    _ALGORITHMS_AVAILABLE = set(getattr(hashlib, "algorithms", []))
# Environment setup
os.environ["PYTHONIOENCODING"] = "UTF-8"

from io import UnsupportedOperation

def ensure_text(s, encoding="utf-8", errors="replace", allow_none=False,
                normalize=None, prefer_surrogates=False):
    """
    Coerce `s` to a Python 3 `str` safely.

    Features (best-of):
      - None handling: None -> "" (or None if allow_none=True)
      - Fast path for str
      - Bytes-like decode (bytes/bytearray/memoryview) with configurable encoding/errors
      - Optional surrogateescape preference for byte-preserving round-trips (Py3)
      - PathLike support via os.fspath(), including bytes paths
      - Defensive fallback to repr() if __str__ is broken
      - Optional unicode normalization (NFC/NFKC/NFD/NFKD)

    Notes:
      - Default encoding is UTF-8.
      - No latin-1 fallback is used; failures fall back to a safer decode attempt
        using the *same* encoding but with 'replace' to avoid exceptions.
    """
    if s is None:
        return None if allow_none else ""

    # Fast path: already text
    if isinstance(s, str):
        out = s
    else:
        # PathLike: normalize early (common boundary)
        try:
            s = os.fspath(s)
        except Exception:
            pass

        # Bytes-like -> decode
        if isinstance(s, (bytes, bytearray, memoryview)):
            b = bytes(s)

            eff_errors = errors
            if prefer_surrogates and errors == "replace":
                # surrogateescape exists on Py3; keep this guarded in case of odd runtimes
                try:
                    "".encode("utf-8", "surrogateescape")
                    eff_errors = "surrogateescape"
                except LookupError:
                    pass

            try:
                out = b.decode(encoding, eff_errors)
            except Exception:
                # No latin-1 fallback: retry with the same encoding, forcing replace
                try:
                    out = b.decode(encoding, "replace")
                except Exception:
                    # Absolute last resort: decode as UTF-8 with replace
                    out = b.decode("utf-8", "replace")
        else:
            # Non-bytes: stringify
            try:
                out = str(s)
            except Exception:
                # Fallback if object's __str__ is broken
                out = repr(s)
                if not isinstance(out, str):
                    try:
                        out = str(out)
                    except Exception:
                        out = "<unprintable object>"

    # Optional normalization
    if normalize:
        try:
            import unicodedata
            out = unicodedata.normalize(normalize, out)
        except Exception:
            pass

    return out

def ensure_bytes(data, encoding="utf-8", errors="strict", allow_none=False,
                 prefer_surrogates=False):
    """
    Robustly coerce `data` to `bytes` (Python 3 only).

    - None -> b"" (or None if allow_none=True)
    - bytes/bytearray/memoryview -> bytes(...)
    - str -> encode(encoding, errors)
      * if prefer_surrogates and errors=="strict", uses errors="surrogateescape" (Py3)
    - os.PathLike -> os.fspath(...) then convert (supports str/bytes paths)
    - file-like (has .read) -> read once, then convert result
    - int -> encode decimal string (avoids bytes(int) => NUL padding)
    - other -> try bytes(obj) (uses buffer protocol / __bytes__ if available),
              else str(obj).encode(...), falling back to repr(obj) if __str__ is broken

    Notes:
      - Default encoding is UTF-8.
      - No latin-1 fallback is used.
    """
    if data is None:
        return None if allow_none else b""

    # Fast path: already bytes-like
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)

    # PathLike early (common boundary)
    try:
        data = os.fspath(data)
    except Exception:
        pass

    # str -> encode
    if isinstance(data, str):
        eff_errors = errors
        if prefer_surrogates and errors == "strict":
            # Keep raw bytes round-trippable for strings containing surrogates
            try:
                "".encode("utf-8", "surrogateescape")
                eff_errors = "surrogateescape"
            except LookupError:
                pass
        return data.encode(encoding, eff_errors)

    # file-like: read its content (single read; caller controls buffering)
    read = getattr(data, "read", None)
    if callable(read):
        try:
            chunk = read()
        except Exception:
            # If read fails, fall back to stringifying the object itself
            chunk = data
        return ensure_bytes(chunk, encoding=encoding, errors=errors,
                           allow_none=allow_none, prefer_surrogates=prefer_surrogates)

    # avoid bytes(int) => NUL padding
    if isinstance(data, int):
        return str(data).encode(encoding, errors)

    # Try bytes(obj) first: supports __bytes__ and buffer protocol
    try:
        b = bytes(data)
        # Guard against the common pitfall: bytes(some_int) returns NULs
        # (we already handled int above, but keep this defensive)
        if isinstance(data, int):
            return str(data).encode(encoding, errors)
        return b
    except Exception:
        pass

    # Fallback: stringify (defensive), then encode
    try:
        s = str(data)
    except Exception:
        s = repr(data)
        if not isinstance(s, str):
            try:
                s = str(s)
            except Exception:
                s = "<unprintable object>"

    eff_errors = errors
    if prefer_surrogates and errors == "strict":
        try:
            "".encode("utf-8", "surrogateescape")
            eff_errors = "surrogateescape"
        except LookupError:
            pass

    return s.encode(encoding, eff_errors)

def _split_posix(name):
    """
    Return a list of path parts without collapsing '..'.
    - Normalize backslashes to '/'
    - Strip leading './' (repeated)
    - Remove '' and '.' parts; keep '..' for traversal detection
    """
    if not name:
        return []

    n = name.replace("\\", "/")

    while n.startswith("./"):
        n = n[2:]

    return [p for p in n.split("/") if p not in ("", ".")]


def _is_abs_like(name):
    """Detect absolute-like paths across platforms (/, \\, drive letters, UNC)."""
    if not name:
        return False

    n = name.replace("\\", "/")

    # POSIX absolute
    if n.startswith("/"):
        return True

    # Windows UNC (\\server\share\...) -> after replace: startswith '//'
    if n.startswith("//"):
        return True

    # Windows drive: 'C:/', 'C:\', or bare 'C:'
    if len(n) >= 2 and n[1] == ":":
        if len(n) == 2:
            return True
        if n[2:3] in ("/", "\\"):
            return True

    return False


def _resolves_outside(parent, target):
    """
    Does a symlink from 'parent' to 'target' escape parent?
    - Absolute-like target => escape.
    - Compare normalized '/<parent>/<target>' against '/<parent>'.
    - 'parent' is POSIX-style ('' means archive root).
    """
    parent = _ensure_text(parent or "")
    target = _ensure_text(target or "")

    # Absolute target is unsafe by definition
    if _is_abs_like(target):
        return True

    root = "/"
    base = posixpath.normpath(posixpath.join(root, parent))  # '/dir/sub' or '/'
    cand = posixpath.normpath(posixpath.join(base, target))  # resolved target under '/'

    # ensure trailing slash on base for the prefix test
    base_slash = base if base.endswith("/") else base + "/"
    return not (cand == base or cand.startswith(base_slash))

def _as_bytes_like(data):
    if isinstance(data, bytes):
        return data
    if isinstance(data, bytearray):
        return bytes(data)
    if isinstance(data, memoryview):
        return bytes(data)
    return None


def _normalize_initial_data(data, isbytes, encoding, errors=None):
    """
    Return bytes (if isbytes) or str (text in Python 3).
    """
    if errors is None:
        errors = "strict"

    if data is None:
        return None

    if isbytes:
        b = _as_bytes_like(data)
        if b is not None:
            return b
        if isinstance(data, str):
            return data.encode(encoding, errors)
        raise TypeError(
            "data must be bytes-like or text for isbytes=True (got %r)" % (type(data),)
        )
    else:
        # text mode
        if isinstance(data, str):
            return data
        b = _as_bytes_like(data)
        if b is not None:
            return b.decode(encoding, errors)
        raise TypeError(
            "data must be str or bytes-like for text mode (got %r)" % (type(data),)
        )

__upload_proto_support__ = "^(http|https|ftp|ftps|sftp|scp|tcp|udp|sctp|data|file|bt|rfcomm|l2cap|bluetooth|unixstream|unixdgram|unixseqpacket)://"
__download_proto_support__ = "^(http|https|ftp|ftps|sftp|scp|tcp|udp|sctp|data|file|bt|rfcomm|l2cap|bluetooth|unixstream|unixdgram|unixseqpacket)://"
if(platform.python_implementation() != ""):
    py_implementation = platform.python_implementation()
if(platform.python_implementation() == ""):
    py_implementation = "Python"

def get_importing_script_path():
    """Best-effort path of the importing (caller) script, or None."""
    for frame_info in inspect.stack():
        filename = frame_info.filename
        if filename != __file__:  # Ignore current module's file
            return os.path.abspath(filename)
    return None

def is_only_nonprintable(var):
    """True if every character is non-printable (handles bytes via to_text)."""
    if var is None:
        return True
    return all(not ch.isprintable() for ch in var)

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

# Process-lifetime extract dir (only used when resources aren't on the filesystem)
_EXTRACT_DIR = None

def _get_extract_dir():
    global _EXTRACT_DIR
    if _EXTRACT_DIR is None:
        _EXTRACT_DIR = tempfile.mkdtemp(prefix="gm2k-cfg-")
        atexit.register(lambda: shutil.rmtree(_EXTRACT_DIR, ignore_errors=True))
    return _EXTRACT_DIR

def _atomic_write(path, data):
    tmp = path + ".tmp"
    f = open(tmp, "wb")
    try:
        f.write(data)
    finally:
        f.close()

    try:
        # Py3
        os.replace(tmp, path)
    except Exception:
        # Py2 / fallback
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass
        os.rename(tmp, path)

def resource_path(package_name, filename):
    """
    Return a REAL filesystem path to a resource inside this package.

    - If package is installed normally on disk: returns the existing path (no copy).
    - If package is imported from zip/egg: extracts to a temp dir once and returns that path.
    - Falls back to pkg_resources if needed.
    """
    files = None
    try:
        try:
            from importlib.resources import files as _files  # Py3.9+ (and sometimes available)
            files = _files
        except Exception:
            from importlib_resources import files as _files  # backport
            files = _files
    except Exception:
        files = None

    if files is not None:
        try:
            ref = files(package_name).joinpath(filename)

            # If backed by filesystem, return that path
            try:
                return os.fspath(ref)  # Py3 only
            except Exception:
                # zipped/non-path traversable -> extract bytes
                out = os.path.join(_get_extract_dir(), filename)
                if not os.path.exists(out):
                    data = ref.read_bytes()
                    _atomic_write(out, data)
                return out
        except Exception:
            pass

    # setuptools fallback
    try:
        import pkg_resources
        return pkg_resources.resource_filename(package_name, filename)
    except Exception:
        pass

    # last resort: __file__ relative (works only when not zipped)
    mod = sys.modules.get(package_name)
    base = os.path.dirname(getattr(mod, "__file__", __file__))
    return os.path.join(base, filename)

def resource_dir(package_name, filenames):
    """
    Ensure a set of resources exist as real files in one directory.
    Returns that directory path.
    """
    paths = [resource_path(package_name, fn) for fn in filenames]
    return os.path.dirname(paths[0])

filecfgpath = resource_dir(__name__, [
    "catfile.ini",
    "catfile.json",
])

__file_format_multi_dict__ = {}
__file_format_default__ = "CatFile"
__include_defaults__ = True
__use_inmem__ = True
__use_memfd__ = False
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
__use_ini_name__ = os.path.join(filecfgpath, "catfile.ini")
__use_json_file__ = False
__use_json_name__ = os.path.join(filecfgpath, "catfile.json")
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
    add_format(__file_format_multi_dict__, "CatFile", "CatFile", ".cat", "CatFile")
    add_format(__file_format_multi_dict__, "NekoFile", "NekoFile", ".neko", "NekoFile")
    add_format(__file_format_multi_dict__, "ねこファイル", "ねこファイル", ".ねこ", "NekoFairu")
    add_format(__file_format_multi_dict__, "ネコファイル", "ネコファイル", ".ネコ", "NekoFairu")
    add_format(__file_format_multi_dict__, "네코파일", "네코파일", ".네코", "NekoPa-il")
    add_format(__file_format_multi_dict__, "고양이파일", "고양이파일", ".고양이", "GoyangiPa-il")
    add_format(__file_format_multi_dict__, "内酷法伊鲁", "内酷法伊鲁", ".内酷", "NèiKùFǎYīLǔ")
    add_format(__file_format_multi_dict__, "猫文件", "猫文件", ".猫", "MāoWénjiàn")

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
__version_info__ = (0, 28, 8, "RC 1", 1)
__version_date_info__ = (2026, 2, 8, "RC 1", 1)
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
    "files", "hardlinks", "symlinks", "characters", "blocks",
    "directories", "fifos", "sockets", "doors", "ports",
    "whiteouts", "sparsefiles", "junctions", "links", "devices"
]

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
    scrfile = curscrpath + "__main__.py"
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
    msg = str(dbgtxt)

    # Normalize outtype
    lvl = None
    if isinstance(outtype, int):
        lvl = outtype
        route = "logging"
    else:
        name = (outtype or "log")
        if isinstance(name, str):
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

hashlib_guaranteed = False

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

def GetHeaderChecksum(inlist=None, checksumtype="md5", encodedata=True, formatspecs=__file_format_dict__, saltkey=None):
    """
    Serialize header fields (list/tuple => joined with delimiter + trailing delimiter;
    or a single field) and compute the requested checksum. Returns lowercase hex.
    """
    algo_key = (checksumtype or "md5").lower()

    delim = formatspecs.get('format_delimiter', u"\0")
    hdr_bytes = AppendNullBytes(inlist or [], delim)
    if encodedata and not isinstance(hdr_bytes, (bytes, bytearray, memoryview)):
        hdr_bytes = hdr_bytes.encode("UTF-8")
    hdr_bytes = bytes(hdr_bytes)
    saltkeyval = None
    if(hasattr(saltkey, "read")):
        saltkeyval = skfp.read()
        if(not isinstance(saltkeyval, bytes)):
            saltkeyval = saltkeyval.encode("UTF-8")
    elif(isinstance(saltkey, bytes)):
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
        if(not isinstance(saltkeyval, bytes)):
            saltkeyval = saltkeyval.encode("UTF-8")
    elif(isinstance(saltkey, bytes)):
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
        data = inbytes if (encodedata or not isinstance(inbytes, (bytes, bytearray, memoryview))) else inbytes
        if isinstance(inbytes, str) and encodedata:
            data = data.encode("UTF-8")

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
    calc_b = calc.encode("UTF-8")   # defaults to utf-8, strict
    want_b = want.encode("UTF-8")

    return hmac.compare_digest(want_b, calc_b)

def AppendNullByte(indata, delimiter=None):
    if(delimiter is None):
        return False
    return (indata + delimiter).encode("UTF-8")


def AppendNullBytes(indata=None, delimiter=None):
    if(delimiter is None):
        return False
    parts = [x for x in indata]
    return (delimiter.join(parts) + delimiter).encode("UTF-8")

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

def _is_printable_byte(b):
    # Accept common printable ASCII range; tweak if your format allows others.
    # This avoids decoding per byte.
    return 32 <= b <= 126  # space..~


def _read_exact(fp, n):
    data = fp.read(n)
    if len(data) != n:
        raise EOFError("Unexpected EOF while reading %d bytes" % n)
    return data


def ReadFileHeaderDataBySize(fp, delimiter="\x00", encoding="utf-8", errors="strict"):
    # Normalize delimiter to bytes for reliable multi-byte/multi-char matching
    if isinstance(delimiter, str):
        delimiter_b = delimiter.encode(encoding)
        delimiter_t = delimiter
    else:
        delimiter_b = bytes(delimiter)
        delimiter_t = delimiter_b.decode(encoding, errors)

    if not delimiter_b:
        raise ValueError("delimiter must not be empty")

    # Read the initial hex field as printable ASCII-ish bytes (same intent as .isprintable()).
    # Hex digits are ASCII, so this is appropriate and avoids per-byte decoding.
    numhex_bytes = bytearray()
    while True:
        b = fp.read(1)
        if not b:
            # EOF before terminator
            break
        c = b[0]
        if 32 <= c <= 126:  # printable ASCII range
            numhex_bytes.append(c)
            continue

        # Hit the terminator (likely the delimiter); rewind so delimiter read aligns
        fp.seek(-1, 1)
        break

    numhex = numhex_bytes.decode(encoding, errors)
    numdec = int(numhex, 16)

    # Consume exactly one delimiter (supports multi-byte delimiters)
    got = fp.read(len(delimiter_b))
    if got != delimiter_b:
        raise ValueError("Delimiter mismatch: expected %r, got %r" % (delimiter_b, got))

    # Read header payload by size
    headerdata = fp.read(numdec).decode(encoding, errors)

    # Split using delimiter as text (matches original behavior)
    headerdatasplit = headerdata.split(delimiter_t)
    headerdatasplit.insert(0, numhex)

    # Consume trailing delimiter (like original fp.seek(len(delimiter), 1))
    got2 = fp.read(len(delimiter_b))
    if got2 != delimiter_b:
        raise ValueError("Trailing delimiter mismatch: expected %r, got %r" % (delimiter_b, got2))

    return headerdatasplit

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

    prefix = prefix or ""
    suffix = suffix or ""
    init = None
    if data is not None:
        if isbytes:
            if isinstance(data, binary_types):
                init = bytes(data) if not isinstance(data, bytes) else data
            elif isinstance(data, text_type):
                init = data.encode(encoding)
            else:
                raise TypeError("data must be bytes-like for isbytes=True")
        else:
            if isinstance(data, binary_types):
                init = bytes(data).decode(encoding, errors="strict")
            elif isinstance(data, text_type):
                init = data
            else:
                raise TypeError("data must be text (str/unicode) for isbytes=False")

    init_len = len(init) if (init is not None and isbytes) else None

    def _created(fp, kind):
        if on_create is not None:
            on_create(fp, kind)

    def _wrap_text(binary_handle):
        return io.TextIOWrapper(binary_handle, encoding=encoding,
                                newline=newline, errors=text_errors)

    if inmem:
        if autoswitch_spool and use_spool and init_len is not None and init_len > spool_max:
            pass
        else:
            memfd_create = getattr(os, "memfd_create", None)
            if usememfd and isbytes and callable(memfd_create):
                name = memfd_name or prefix or "MkTempFile"
                flags = 0
                if hasattr(os, "MFD_CLOEXEC"):
                    flags |= os.MFD_CLOEXEC
                if memfd_allow_sealing and hasattr(os, "MFD_ALLOW_SEALING"):
                    flags |= os.MFD_ALLOW_SEALING
                if memfd_flags_extra:
                    flags |= int(memfd_flags_extra)

                fd = memfd_create(name, flags)
                f = os.fdopen(fd, "w+b")
                if init is not None:
                    f.write(init)
                if reset_to_start:
                    f.seek(0)
                _created(f, "memfd")
                return f
            if isbytes:
                f = BytesIO(init if init is not None else b"")
                if reset_to_start:
                    f.seek(0)
                _created(f, "bytesio")
                return f
            else:
                f = io.StringIO(init if init is not None else u"")
                if reset_to_start:
                    f.seek(0)
                _created(f, "stringio")
                return f
    if use_spool:
        b = tempfile.SpooledTemporaryFile(max_size=spool_max, mode="w+b", dir=spool_dir)
        f = b if isbytes else _wrap_text(b)
        if init is not None:
            f.write(init)
        if reset_to_start:
            f.seek(0)
        _created(f, "spool")
        return f
    b = tempfile.NamedTemporaryFile(mode="w+b", prefix=prefix, suffix=suffix, dir=dir, delete=delete)
    f = b if isbytes else _wrap_text(b)
    if init is not None:
        f.write(init)
    if reset_to_start:
        f.seek(0)
    _created(f, "disk")
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
    elif isinstance(dirpath, str):
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
                if not isinstance(dpath, str):
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
                    if not isinstance(fpath, str):
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
            if not isinstance(path, str):
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
    elif isinstance(dirpath, str):
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
                if not isinstance(dpath, str):
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
                    if not isinstance(fpath, str):
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
            if not isinstance(path, str):
                path = path.decode(fs_encoding)
            # Apply regex filtering for single paths
            if ((not include_pattern or include_pattern.search(path)) and
                (not exclude_pattern or not exclude_pattern.search(path))):
                retlist.append(path)
    return retlist

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

def TarFileCheck(infile):
    tar = None
    pos = None
    try:
        if hasattr(infile, "read"):
            # Only do this if the file object is seekable
            pos = infile.tell()
            tar = tarfile.open(fileobj=infile, mode="r")
        else:
            tar = tarfile.open(infile, mode="r")

        member = tar.next()
        if member is None:
            return False

        if not member.name or "\x00" in member.name:
            return False

        # if not member.name.isprintable():
        #     return False

        return True

    except (tarfile.TarError, tarfile.ReadError, AttributeError, OSError, IOError):
        return False
    finally:
        try:
            if tar is not None:
                tar.close()
        finally:
            try:
                if pos is not None and hasattr(infile, "seek"):
                    infile.seek(pos)
            except Exception:
                pass

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
    if(filetype == "gzip" or filetype == "bzip2" or filetype == "lzma" or filetype == "xz" or filetype == "zstd" or filetype == "lz4" or filetype == "zlib"):
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
    if(compresscheck == "gzip" or compresscheck == "bzip2" or compresscheck == "lzma" or compresscheck == "xz" or compresscheck == "zstd" or compresscheck == "lz4" or compresscheck == "zlib"):
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
    precfp = None
    if(hasattr(infile, "read") or hasattr(infile, "write") and compresscheck in compressionsupport):
        fp = UncompressFileAlt(infile, formatspecs, filestart)
        curloc = fp.tell()
    elif(hasattr(infile, "read") or hasattr(infile, "write") and compresscheck not in compressionsupport):
        fp = infile
    else:
        try:
            if(compresscheck == "gzip" and compresscheck in compressionsupport):
                precfp = open(infile, "rb")
                precfp.seek(filestart, 0)
                fp = gzip.GzipFile(fileobj=precfp, mode="rb")
                curloc = fp.tell()
            elif(compresscheck == "bzip2" and compresscheck in compressionsupport):
                precfp = open(infile, "rb")
                precfp.seek(filestart, 0)
                fp = bz2.BZ2File(precfp, "rb")
                curloc = fp.tell()
            elif(compresscheck == "lz4" and compresscheck in compressionsupport):
                precfp = open(infile, "rb")
                precfp.seek(filestart, 0)
                fp = lz4.frame.open(precfp, "rb")
                curloc = fp.tell()
            elif(compresscheck == "zstd" and compresscheck in compressionsupport):
                precfp = open(infile, "rb")
                precfp.seek(filestart, 0)
                if 'zstd' in compressionsupport:
                    fp = zstd.ZstdFile(precfp, mode="rb")
                    curloc = fp.tell()
                else:
                    return Flase
            elif((compresscheck == "lzma" or compresscheck == "xz") and compresscheck in compressionsupport):
                precfp = open(infile, "rb")
                precfp.seek(filestart, 0)
                fp = lzma.open(precfp, "rb")
                curloc = fp.tell()
            elif(compresscheck == "zlib" and compresscheck in compressionsupport):
                fp = ZlibFile(infile, mode="rb")
                fp.seek(filestart, 0)
                curloc = fp.tell()
            else:
                fp = open(infile, "rb")
        except FileNotFoundError:
            return False
    filetype = False
    fp.seek(curloc, 0)
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
                pass
            if(formdel != formatspecs['format_delimiter']):
                pass
            filetype = formatspecs['format_magic']
    else:
        pass
    fp.seek(curloc, 0)
    prefp = fp.read(10)
    if(prefp == binascii.unhexlify("7061785f676c6f62616c")):
        filetype = "tarfile"
    fp.seek(curloc, 0)
    if(hasattr(precfp, "read") or hasattr(precfp, "write")):
        precfp.close()
    if(closefp):
        fp.close()
    return filetype

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
    return (((cmf << 8) + flg) % 31) == 0


# ---------- SharedMemory-backed file ----------
class SharedMemoryFile(object):
    """
    File-like wrapper around multiprocessing.shared_memory.SharedMemory.

    Binary-only. For text mode: wrap with io.TextIOWrapper.

    NOTE: requires Python 3.8+ to actually use shared_memory.
    """

    def __init__(self, shm=None, name=None, create=False, size=0,
                 mode="r+b", offset=0, unlink_on_close=False):

        if shared_memory is None:
            raise RuntimeError("multiprocessing.shared_memory is not available on this Python version")

        if "t" in mode:
            raise ValueError("SharedMemoryFile is binary-only; wrap with io.TextIOWrapper for text")

        self.mode = mode
        self._closed = False
        self._unlinked = False
        self._unlink_on_close = bool(unlink_on_close)

        if shm is not None:
            self._shm = shm
        else:
            self._shm = shared_memory.SharedMemory(name=name, create=create, size=size)

        self._buf = self._shm.buf
        self._base_offset = int(offset)
        if self._base_offset < 0 or self._base_offset > len(self._buf):
            raise ValueError("offset out of range")

        # Accessible region: [base_offset, end)
        self._size = len(self._buf) - self._base_offset
        self._pos = 0

    @property
    def name(self):
        return self._shm.name

    @property
    def closed(self):
        return self._closed

    def readable(self):
        return ("r" in self.mode) or ("+" in self.mode)

    def writable(self):
        return any(ch in self.mode for ch in ("w", "a", "+"))

    def seekable(self):
        return True

    def _check_closed(self):
        if self._closed:
            raise ValueError("I/O operation on closed SharedMemoryFile")

    def _clamp_pos(self, pos):
        if pos < 0:
            return 0
        if pos > self._size:
            return self._size
        return pos

    def seek(self, offset, whence=0):
        self._check_closed()
        offset = int(offset)
        whence = int(whence)

        if whence == 0:
            new_pos = offset
        elif whence == 1:
            new_pos = self._pos + offset
        elif whence == 2:
            new_pos = self._size + offset
        else:
            raise ValueError("invalid whence (expected 0, 1, or 2)")

        self._pos = self._clamp_pos(new_pos)
        return self._pos

    def tell(self):
        return self._pos

    def read(self, size=-1):
        self._check_closed()
        if not self.readable():
            raise IOError("SharedMemoryFile not opened for reading")

        if size is None or size < 0:
            size = self._size - self._pos
        else:
            size = max(0, int(size))

        if size == 0:
            return b""

        remaining = self._size - self._pos
        if remaining <= 0:
            return b""

        size = min(size, remaining)
        abs_start = self._base_offset + self._pos
        abs_end = abs_start + size

        data = bytes(self._buf[abs_start:abs_end])
        self._pos += len(data)
        return data

    def readline(self, size=-1):
        self._check_closed()
        if not self.readable():
            raise IOError("SharedMemoryFile not opened for reading")

        remaining = self._size - self._pos
        if remaining <= 0:
            return b""

        if size is None or size < 0:
            max_len = remaining
        else:
            max_len = min(int(size), remaining)

        abs_start = self._base_offset + self._pos
        abs_max = abs_start + max_len

        buf_bytes = bytes(self._buf[abs_start:abs_max])
        idx = buf_bytes.find(b"\n")
        line = buf_bytes if idx == -1 else buf_bytes[:idx + 1]

        self._pos += len(line)
        return line

    def readinto(self, b):
        self._check_closed()
        if not self.readable():
            raise IOError("SharedMemoryFile not opened for reading")

        mv = b if isinstance(b, memoryview) else memoryview(b)
        size = len(mv)
        if size <= 0:
            return 0

        remaining = self._size - self._pos
        if remaining <= 0:
            return 0

        size = min(size, remaining)
        abs_start = self._base_offset + self._pos
        abs_end = abs_start + size

        mv[:size] = self._buf[abs_start:abs_end]
        self._pos += size
        return size

    def write(self, data):
        self._check_closed()
        if not self.writable():
            raise IOError("SharedMemoryFile not opened for writing")

        if isinstance(data, memoryview):
            data = data.tobytes()
        elif isinstance(data, bytearray):
            data = bytes(data)
        elif not isinstance(data, (bytes,)):
            raise TypeError("write() expects bytes-like object")

        data_len = len(data)
        if data_len == 0:
            return 0

        # Rough append behavior: if 'a' and at pos 0, jump to end
        if "a" in self.mode and self._pos == 0:
            self._pos = self._size

        remaining = self._size - self._pos
        if data_len > remaining:
            raise IOError("write would overflow SharedMemory region (need %d, have %d)"
                          % (data_len, remaining))

        abs_start = self._base_offset + self._pos
        abs_end = abs_start + data_len
        self._buf[abs_start:abs_end] = data
        self._pos += data_len
        return data_len

    def flush(self):
        self._check_closed()
        # no-op

    def unlink(self):
        if self._unlinked:
            return
        self._shm.unlink()
        self._unlinked = True

    def close(self):
        if self._closed:
            return
        self._closed = True

        if self._unlink_on_close and not self._unlinked:
            try:
                self.unlink()
            except Exception:
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

    def __iter__(self):
        return self

    def __next__(self):
        line = self.readline()
        if not line:
            raise StopIteration
        return line

    def fileno(self):
        raise OSError("SharedMemoryFile does not have a real fileno()")

    def isatty(self):
        return False


# ---------- ZlibFile ----------
class ZlibFile(object):
    """
    Read/Write RFC1950 zlib streams with support for concatenated members.

    Modes: 'rb','rt','wb','wt','ab','at','xb','xt'
    """

    def __init__(self, file_path=None, fileobj=None, mode="rb",
                 level=6, wbits=15,
                 encoding=None, errors=None, newline=None,
                 tolerant_read=False, scan_bytes=(64 << 10),
                 spool_threshold=__spoolfile_size__):

        if (file_path is None) == (fileobj is None):
            raise ValueError("Provide exactly one of file_path or fileobj")

        if "b" not in mode and "t" not in mode:
            mode += "b"

        self.file_path = file_path
        self.file = None
        self.mode = mode
        self.level = int(level)
        self.wbits = int(wbits)
        self.encoding = encoding
        self.errors = errors
        self.newline = newline
        self._text_mode = ("t" in mode)

        self.tolerant_read = bool(tolerant_read)
        self.scan_bytes = int(scan_bytes)
        self.spool_threshold = int(spool_threshold)

        self._compressor = None
        self._write_buf = bytearray()
        self._spool = None
        self._text_reader = None
        self._position = 0
        self.closed = False

        internal_mode = mode.replace("t", "b")

        if file_path is not None:
            if "x" in internal_mode and os.path.exists(file_path):
                raise IOError("File exists: %r" % (file_path,))
            self.file = open(file_path, internal_mode)
        else:
            self.file = fileobj
            if "r" in internal_mode and not hasattr(self.file, "read"):
                raise ValueError("fileobj must support read()")
            if any(ch in internal_mode for ch in ("w", "a", "x")) and not hasattr(self.file, "write"):
                raise ValueError("fileobj must support write()")

        if any(ch in internal_mode for ch in ("w", "a", "x")):
            if self.wbits <= 0:
                raise ValueError("wbits must be > 0 for zlib wrapper")
            if "a" in internal_mode:
                try:
                    self.file.seek(0, os.SEEK_END)
                except Exception:
                    pass
            self._compressor = zlib.compressobj(self.level, zlib.DEFLATED, self.wbits)

        elif "r" in internal_mode:
            if self.wbits <= 0:
                raise ValueError("wbits must be > 0 for zlib wrapper")
            self._load_all_members_spooled()

        else:
            raise ValueError("Unsupported mode: %r" % (mode,))

    @property
    def name(self):
        return self.file_path

    def readable(self):
        return "r" in self.mode

    def writable(self):
        return any(ch in self.mode for ch in ("w", "a", "x"))

    def seekable(self):
        return True if self._spool is not None else bool(getattr(self.file, "seek", None))

    def _normalize_newlines_for_write(self, s):
        nl = self.newline if self.newline is not None else "\n"
        return s.replace("\r\n", "\n").replace("\r", "\n").replace("\n", nl)

    def _reader(self):
        return self._text_reader if self._text_mode else self._spool

    def _load_all_members_spooled(self):
        try:
            self.file.seek(0)
        except Exception:
            pass

        self._spool = tempfile.SpooledTemporaryFile(max_size=self.spool_threshold)

        pending = b""
        d = None
        scanned_leading = 0
        absolute_offset = 0

        while True:
            data = self.file.read(__filebuff_size__)
            if not data:
                if d is not None:
                    self._spool.write(d.flush())
                break

            buf = pending + data
            absolute_offset += len(data)

            while True:
                if d is None:
                    if len(buf) < 2:
                        pending = buf
                        break

                    cmf = buf[0]
                    flg = buf[1]

                    if not _is_valid_zlib_header(cmf, flg):
                        if self.tolerant_read and scanned_leading < self.scan_bytes:
                            buf = buf[1:]
                            scanned_leading += 1
                            if len(buf) < 2:
                                pending = buf
                                break
                            continue
                        start_off = absolute_offset - len(buf)
                        raise ValueError("Invalid zlib header near byte offset %d" % start_off)

                    if (flg & 0x20) != 0:
                        start_off = absolute_offset - len(buf)
                        raise ValueError("Preset dictionary (FDICT) not supported (offset %d)" % start_off)

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
                break

        self._spool.seek(0)

        if self._text_mode:
            enc = self.encoding or "utf-8"
            errs = self.errors or "strict"
            self._text_reader = io.TextIOWrapper(self._spool, encoding=enc, errors=errs, newline=self.newline)
            self._text_reader.seek(0)

        self._position = 0

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
        return out

    def __iter__(self):
        return self

    def __next__(self):
        line = self.readline()
        if (self._text_mode and line == "") or (not self._text_mode and line == b""):
            raise StopIteration
        return line

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
        r = self._reader()
        if r is not None:
            try:
                self._position = r.tell()
            except Exception:
                pass
        return self._position

    def write(self, data):
        if self.closed:
            raise ValueError("I/O operation on closed file")
        if self._compressor is None:
            raise IOError("File not opened for writing")

        if self._text_mode:
            if not isinstance(data, str):
                raise TypeError("write() expects str in text mode")
            enc = self.encoding or "utf-8"
            errs = self.errors or "strict"
            data_b = self._normalize_newlines_for_write(data).encode(enc, errs)
        else:
            if isinstance(data, memoryview):
                data_b = data.tobytes()
            elif isinstance(data, bytearray):
                data_b = bytes(data)
            elif isinstance(data, bytes):
                data_b = data
            else:
                raise TypeError("write() expects bytes-like in binary mode")

        self._write_buf += data_b
        if len(self._write_buf) >= __filebuff_size__:
            chunk = self._compressor.compress(bytes(self._write_buf))
            if chunk:
                self.file.write(chunk)
            del self._write_buf[:]

        return len(data_b) if not self._text_mode else len(data)

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
        if hasattr(self.file, "flush"):
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
            if hasattr(self.file, "flush"):
                try:
                    self.file.flush()
                except Exception:
                    pass
        finally:
            if self.file_path and self.file is not None:
                try:
                    self.file.close()
                except Exception:
                    pass
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

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, tb):
        self.close()

    @classmethod
    def open(cls, path, mode="rb", **kw):
        return cls(file_path=path, mode=mode, **kw)

    @classmethod
    def from_fileobj(cls, fileobj, mode="rb", **kw):
        return cls(fileobj=fileobj, mode=mode, **kw)

    @classmethod
    def from_bytes(cls, data, mode="rb", **kw):
        if isinstance(data, memoryview):
            data = data.tobytes()
        elif isinstance(data, bytearray):
            data = bytes(data)
        elif not isinstance(data, bytes):
            raise TypeError("from_bytes() expects bytes-like")
        bio = MkTempFile(data)
        return cls(fileobj=bio, mode=mode, **kw)

    @property
    def fileobj(self):
        return self.file


# ---------- zlib helpers ----------
def decompress_bytes(blob, **kw):
    mode = kw.pop("mode", "rb")
    f = ZlibFile.from_bytes(blob, mode=mode, **kw)
    try:
        return f.read()
    finally:
        f.close()


def compress_bytes(payload, level=6, wbits=15, text=False, **kw):
    bio = MkTempFile()
    mode = "wt" if text else "wb"
    f = ZlibFile(fileobj=bio, mode=mode, level=level, wbits=wbits, **kw)
    try:
        f.write(payload)
        f.flush()
    finally:
        f.close()
    return bio.getvalue()


# ---------- Single-shot gzip helpers ----------
def _gzip_compress(data, compresslevel=9):
    co = zlib.compressobj(compresslevel, zlib.DEFLATED, 31)
    return co.compress(data) + co.flush(zlib.Z_FINISH)


def _gzip_decompress(data):
    return zlib.decompress(data, 31)


def _gzip_decompress_multimember(data):
    out = []
    buf = data
    last_len = None
    while buf:
        d = zlib.decompressobj(31)
        out.append(d.decompress(buf))
        out.append(d.flush())
        if d.unused_data:
            new_buf = d.unused_data
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
    Gzip reader/writer using zlib (wbits=31) with:
      - streaming writes
      - spooled reads with multi-member support (seek/tell/iter)
      - text ('t') vs binary modes
      - 'a' appends a new gzip member

    Modes: 'rb','rt','wb','wt','ab','at','xb','xt'
    """

    GZIP_MAGIC = b"\x1f\x8b"

    def __init__(self, file_path=None, fileobj=None, mode="rb",
                 level=6, encoding=None, errors=None, newline=None,
                 tolerant_read=False, scan_bytes=(64 << 10),
                 spool_threshold=__spoolfile_size__):

        if (file_path is None) == (fileobj is None):
            raise ValueError("Provide exactly one of file_path or fileobj")

        if "b" not in mode and "t" not in mode:
            mode += "b"

        self.file_path = file_path
        self.file = fileobj
        self.mode = mode
        self.level = int(level)
        self.encoding = encoding
        self.errors = errors
        self.newline = newline
        self._text_mode = ("t" in mode)

        self.tolerant_read = bool(tolerant_read)
        self.scan_bytes = int(scan_bytes)
        self.spool_threshold = int(spool_threshold)

        self._compressor = None
        self._write_buf = bytearray()
        self._spool = None
        self._text_reader = None
        self._position = 0
        self.closed = False

        internal_mode = mode.replace("t", "b")

        if self.file is None:
            if "x" in internal_mode and os.path.exists(file_path):
                raise IOError("File exists: %r" % (file_path,))
            self.file = open(file_path, internal_mode)
        else:
            if "r" in internal_mode and not hasattr(self.file, "read"):
                raise ValueError("fileobj must support read()")
            if any(ch in internal_mode for ch in ("w", "a", "x")) and not hasattr(self.file, "write"):
                raise ValueError("fileobj must support write()")

        if any(ch in internal_mode for ch in ("w", "a", "x")):
            if "a" in internal_mode:
                try:
                    self.file.seek(0, os.SEEK_END)
                except Exception:
                    pass
            self._compressor = zlib.compressobj(self.level, zlib.DEFLATED, 31)

        elif "r" in internal_mode:
            self._load_all_members_spooled()
        else:
            raise ValueError("Unsupported mode: %r" % (mode,))

    @property
    def name(self):
        return self.file_path

    def readable(self):
        return "r" in self.mode

    def writable(self):
        return any(ch in self.mode for ch in ("w", "a", "x"))

    def seekable(self):
        return True if self._spool is not None else bool(getattr(self.file, "seek", None))

    def _normalize_newlines_for_write(self, s):
        nl = self.newline if self.newline is not None else "\n"
        return s.replace("\r\n", "\n").replace("\r", "\n").replace("\n", nl)

    def _reader(self):
        return self._text_reader if self._text_mode else self._spool

    def _load_all_members_spooled(self):
        try:
            self.file.seek(0)
        except Exception:
            pass

        self._spool = tempfile.SpooledTemporaryFile(max_size=self.spool_threshold)

        pending = b""
        d = None
        absolute_offset = 0
        scanned = 0

        while True:
            chunk = self.file.read(__filebuff_size__)
            if not chunk:
                if d is not None:
                    self._spool.write(d.flush())
                break

            buf = pending + chunk
            absolute_offset += len(chunk)

            while True:
                if d is None:
                    if len(buf) < 2:
                        pending = buf
                        break

                    if buf[0:2] != self.GZIP_MAGIC:
                        if self.tolerant_read and scanned < self.scan_bytes:
                            buf = buf[1:]
                            scanned += 1
                            if len(buf) < 2:
                                pending = buf
                                break
                            continue
                        # not tolerant: let zlib raise

                    d = zlib.decompressobj(31)

                try:
                    out = d.decompress(buf)
                except zlib.error as e:
                    start_off = absolute_offset - len(buf)
                    raise ValueError("GZIP decompression error near offset %d: %s"
                                     % (start_off, e))

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
                break

        self._spool.seek(0)

        if self._text_mode:
            enc = self.encoding or "utf-8"
            errs = self.errors or "strict"
            self._text_reader = io.TextIOWrapper(self._spool, encoding=enc, errors=errs, newline=self.newline)
            self._text_reader.seek(0)

        self._position = 0

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
        return out

    def __iter__(self):
        return self

    def __next__(self):
        line = self.readline()
        if (self._text_mode and line == "") or (not self._text_mode and line == b""):
            raise StopIteration
        return line

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
        r = self._reader()
        if r is not None:
            try:
                self._position = r.tell()
            except Exception:
                pass
        return self._position

    def write(self, data):
        if self.closed:
            raise ValueError("I/O operation on closed file")
        if self._compressor is None:
            raise IOError("File not open for writing")

        if self._text_mode:
            if not isinstance(data, str):
                raise TypeError("write() expects str in text mode")
            enc = self.encoding or "utf-8"
            errs = self.errors or "strict"
            data_b = self._normalize_newlines_for_write(data).encode(enc, errs)
        else:
            if isinstance(data, memoryview):
                data_b = data.tobytes()
            elif isinstance(data, bytearray):
                data_b = bytes(data)
            elif isinstance(data, bytes):
                data_b = data
            else:
                raise TypeError("write() expects bytes-like in binary mode")

        self._write_buf += data_b
        if len(self._write_buf) >= __filebuff_size__:
            out = self._compressor.compress(bytes(self._write_buf))
            if out:
                self.file.write(out)
            del self._write_buf[:]
        return len(data_b) if not self._text_mode else len(data)

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
        if hasattr(self.file, "flush"):
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
            if hasattr(self.file, "flush"):
                try:
                    self.file.flush()
                except Exception:
                    pass
        finally:
            if self.file_path and self.file is not None:
                try:
                    self.file.close()
                except Exception:
                    pass
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

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, tb):
        self.close()

    @classmethod
    def open(cls, path, mode="rb", **kw):
        return cls(file_path=path, mode=mode, **kw)

    @classmethod
    def from_fileobj(cls, fileobj, mode="rb", **kw):
        return cls(fileobj=fileobj, mode=mode, **kw)

    @classmethod
    def from_bytes(cls, data, mode="rb", **kw):
        if isinstance(data, memoryview):
            data = data.tobytes()
        elif isinstance(data, bytearray):
            data = bytes(data)
        elif not isinstance(data, bytes):
            raise TypeError("from_bytes() expects bytes-like")
        bio = MkTempFile(data)
        return cls(fileobj=bio, mode=mode, **kw)

    @property
    def fileobj(self):
        return self.file


# ---------- gzip helpers ----------
def gzip_decompress_bytes(blob, mode="rb", multi=True, **kw):
    if isinstance(blob, memoryview):
        blob = blob.tobytes()
    elif isinstance(blob, bytearray):
        blob = bytes(blob)
    elif not isinstance(blob, bytes):
        raise TypeError("gzip_decompress_bytes() expects bytes-like")

    if not multi and mode == "rb" and not kw:
        return _gzip_decompress(blob)

    f = GzipFile.from_bytes(blob, mode=mode, **kw)
    try:
        return f.read()
    finally:
        f.close()


def gzip_compress_bytes(payload, level=6, text=False, **kw):
    bio = MkTempFile()
    mode = "wt" if text else "wb"
    gf = GzipFile(fileobj=bio, mode=mode, level=level, **kw)
    try:
        gf.write(payload)
        gf.flush()
    finally:
        gf.close()
    return bio.getvalue()


def gzip_decompress_bytes_first_member(blob):
    if isinstance(blob, memoryview):
        blob = blob.tobytes()
    elif isinstance(blob, bytearray):
        blob = bytes(blob)
    elif not isinstance(blob, bytes):
        raise TypeError("expects bytes-like")
    return _gzip_decompress(blob)


def gzip_decompress_bytes_all_members(blob):
    if isinstance(blob, memoryview):
        blob = blob.tobytes()
    elif isinstance(blob, bytearray):
        blob = bytes(blob)
    elif not isinstance(blob, bytes):
        raise TypeError("expects bytes-like")
    return _gzip_decompress_multimember(blob)

def UncompressFileAlt(fp, formatspecs=__file_format_multi_dict__, filestart=0):
    if not hasattr(fp, "read"):
        return False

    src = fp

    kind = CheckCompressionType(src, formatspecs, filestart, False)
    # Optional canonicalization so names match your compressionsupport entries
    if kind == "bz2":
        kind = "bzip2"

    if IsNestedDict(formatspecs) and kind in formatspecs:
        formatspecs = formatspecs[kind]

    src.seek(filestart, 0)

    # Build logical stream (or passthrough)
    if   kind == "gzip"   and "gzip"   in compressionsupport:
        wrapped = gzip.GzipFile(fileobj=src, mode="rb")
        wrapped.seek(0, 0)
    elif kind == "bzip2"  and ("bzip2" in compressionsupport or "bz2" in compressionsupport):
        wrapped = bz2.BZ2File(src)
        wrapped.seek(0, 0)
    elif kind in ("lzma","xz") and (("lzma" in compressionsupport) or ("xz" in compressionsupport)):
        wrapped = lzma.LZMAFile(src)
        wrapped.seek(0, 0)
    elif kind == "zstd"   and ("zstd" in compressionsupport or "zstandard" in compressionsupport):
        if 'zstd' in compressionsupport:
            wrapped = zstd.ZstdFile(src, mode="rb")
            wrapped.seek(0, 0)
        else:
            return False
    elif kind == "lz4"    and "lz4"    in compressionsupport:
        wrapped = lz4.frame.LZ4FrameFile(src, mode="rb")
        wrapped.seek(0, 0)
    elif kind == "zlib"   and "zlib"   in compressionsupport:
        wrapped = ZlibFile(fileobj=src, mode="rb")
        wrapped.seek(0, 0)
    else:
        # Passthrough
        wrapped = src
        wrapped.seek(filestart, 0)

    return wrapped

def UncompressFile(infile, formatspecs=__file_format_multi_dict__, mode="rb",
                   filestart=0):

    compresscheck = CheckCompressionType(infile, formatspecs, filestart, False)
    if IsNestedDict(formatspecs) and compresscheck in formatspecs:
        formatspecs = formatspecs[compresscheck]

    try:
        # Compressed branches
        if (compresscheck == "gzip" and "gzip" in compressionsupport):
            fp = gzip.open(infile, mode)
            fp.seek(0, 0)
        elif (compresscheck == "bzip2" and "bzip2" in compressionsupport):
            fp = bz2.open(infile, mode)
            fp.seek(0, 0)
        elif (compresscheck == "zstd" and "zstandard" in compressionsupport):
            if 'zstd' in compressionsupport:
                fp = zstd.ZstdFile(infile, mode=mode)
                fp.seek(0, 0)
            else:
                return False
        elif (compresscheck == "lz4" and "lz4" in compressionsupport):
            fp = lz4.frame.open(infile, mode)
            fp.seek(0, 0)
        elif ((compresscheck == "lzma" or compresscheck == "xz") and "xz" in compressionsupport):
            fp = lzma.open(infile, mode)
            fp.seek(0, 0)
        elif (compresscheck == "zlib" and "zlib" in compressionsupport):
            fp = ZlibFile(infile, mode=mode)
            fp.seek(0, 0)

        # Uncompressed (or unknown): open plain file
        else:
            fp = open(infile, mode)
            fp.seek(filestart, 0)

    except FileNotFoundError:
        return False

    return fp

def CompressOpenFileAlt(fp, compression="auto", compressionlevel=None,
                        compressionuselist=compressionlistalt,
                        formatspecs=__file_format_dict__):
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
            compressor = zstd.ZstdCompressor(level=level)
            bytesfp.write(compressor.compress(fp.read()))
            bytesfp.write(compressor.flush())
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

    return bytesfp

def CompressOpenFile(outfile, compressionenable=True, compressionlevel=None):
    if outfile is None:
        return False

    fbasename, fextname = os.path.splitext(outfile)
    compressionlevel = 9 if compressionlevel is None else int(compressionlevel)
    mode = "wb"

    try:
        # Uncompressed branch
        if (fextname not in outextlistwd) or (not compressionenable):
            outfp = open(outfile, "wb")

        # Compressed branches (unchanged openers; all wrapped)
        elif (fextname == ".gz" and "gzip" in compressionsupport):
            outfp = gzip.open(outfile, mode, compressionlevel)

        elif (fextname == ".bz2" and "bzip2" in compressionsupport):
            outfp = bz2.open(outfile, mode, compressionlevel)

        elif (fextname == ".zst" and "zstandard" in compressionsupport):
            if 'zstd' in compressionsupport:
                outfp = zstd.ZstdFile(outfile, mode=mode, level=compressionlevel)
            else:
                return False  # fix: 'Flase' -> False

        elif (fextname == ".xz" and "xz" in compressionsupport):
            try:
                outfp = lzma.open(outfile, mode, format=lzma.FORMAT_XZ,
                              filters=[{"id": lzma.FILTER_LZMA2, "preset": compressionlevel}])
            except (NotImplementedError, lzma.LZMAError):
                outfp = lzma.open(outfile, mode, format=lzma.FORMAT_XZ)

        elif (fextname == ".lz4" and "lz4" in compressionsupport):
            outfp = lz4.frame.open(outfile, mode, compression_level=compressionlevel)

        elif (fextname == ".lzma" and "lzma" in compressionsupport):
            try:
                outfp = lzma.open(outfile, mode, format=lzma.FORMAT_ALONE,
                              filters=[{"id": lzma.FILTER_LZMA1, "preset": compressionlevel}])
            except (NotImplementedError, lzma.LZMAError):
                outfp = lzma.open(outfile, mode, format=lzma.FORMAT_ALONE)

        elif ((fextname in (".zz", ".zl", ".zlib")) and "zlib" in compressionsupport):
            outfp = ZlibFile(outfile, mode=mode, level=compressionlevel)

        else:
            # Fallback: treat as uncompressed
            outfp = open(outfile, "wb")

    except FileNotFoundError:
        return False

    return outfp

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
class _DelimiterReader:
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
            delimiter = "\0"
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
        seekable = getattr(fp, "seekable", None)
        if callable(seekable):
            self._seekable = bool(seekable())
        else:
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
                break  # EOF after a final unterminated piece
        if pad_to_n and len(parts) < n:
            parts.extend([b""] * (n - len(parts)))
        return parts


# ========= helpers =========
def _default_delim(delimiter):
    # Try your global spec if present; else default to NUL
    try:
        if delimiter is None:
            delimiter = __file_format_dict__["format_delimiter"]
    except Exception:
        pass
    return delimiter if delimiter is not None else "\0"


def _decode_text(b, errors):
    return b.decode("utf-8", errors=errors)


def _read_exact(fp, n):
    """Read exactly n bytes or raise EOFError on premature EOF."""
    want = int(n)
    out = bytearray()
    while len(out) < want:
        chunk = fp.read(want - len(out))
        if not chunk:
            raise EOFError("Unexpected EOF: wanted {} more bytes".format(want - len(out)))
        if isinstance(chunk, memoryview):
            chunk = chunk.tobytes()
        out.extend(chunk)
    return bytes(out)


def _expect_delimiter(fp, delimiter):
    """Read exactly len(delimiter) bytes and require an exact match (no seeking)."""
    delim = _default_delim(delimiter)
    if isinstance(delim, str):
        delim_b = delim.encode("utf-8")
    else:
        delim_b = bytes(delim)
    got = _read_exact(fp, len(delim_b))
    if got != delim_b:
        raise ValueError("Delimiter mismatch: expected {!r}, got {!r}".format(delim_b, got))


# ========= unified public API (bytes/text control) =========
def read_until_delimiter(
    fp,
    delimiter=b"\0",
    max_read=None,
    chunk_size=None,
    decode=True,
    errors=None,
):
    """
    Read until the first occurrence of 'delimiter'. Strips the delimiter.
    - Returns text (UTF-8) when decode=True; bytes when decode=False.
    - Non-seekable streams are supported via pushback on the file object.
    """
    if max_read is None:
        max_read = 64 * 1024 * 1024
    if chunk_size is None:
        chunk_size = 8192
    if errors is None:
        errors = "strict"

    r = _DelimiterReader(
        fp,
        delimiter=_default_delim(delimiter),
        chunk_size=chunk_size,
        max_read=max_read,
    )
    piece, _found = r.read_one_piece()
    return _decode_text(piece, errors) if decode else piece


def read_until_n_delimiters(
    fp,
    delimiter=b"\0",
    num_delimiters=1,
    max_read=None,
    chunk_size=None,
    decode=True,
    errors=None,
    pad_to_n=False,
):
    """
    Read up to 'num_delimiters' occurrences. Returns list of pieces (len <= N).
    If pad_to_n=True, pads with empty pieces to length N (useful for rigid parsers).
    """
    if max_read is None:
        max_read = 64 * 1024 * 1024
    if chunk_size is None:
        chunk_size = 8192
    if errors is None:
        errors = "strict"

    r = _DelimiterReader(
        fp,
        delimiter=_default_delim(delimiter),
        chunk_size=chunk_size,
        max_read=max_read,
    )
    parts = r.read_n_pieces(num_delimiters, pad_to_n=pad_to_n)
    if decode:
        return [_decode_text(p, errors) for p in parts]
    return parts


# ========= back-compat wrappers (your original names) =========
def ReadTillNullByteOld(fp, delimiter=_default_delim(None)):
    # emulate byte-by-byte via chunk_size=1; decode with 'replace' like your Alt
    return read_until_delimiter(
        fp,
        delimiter,
        max_read=64 * 1024 * 1024,
        chunk_size=1,
        decode=True,
        errors="replace",
    )


def ReadUntilNullByteOld(fp, delimiter=_default_delim(None)):
    return ReadTillNullByteOld(fp, delimiter)


def ReadTillNullByteAlt(fp, delimiter=_default_delim(None), chunk_size=1024, max_read=64 * 1024 * 1024):
    return read_until_delimiter(
        fp,
        delimiter,
        max_read=max_read,
        chunk_size=chunk_size,
        decode=True,
        errors="replace",
    )


def ReadUntilNullByteAlt(fp, delimiter=_default_delim(None), chunk_size=1024, max_read=64 * 1024 * 1024):
    return ReadTillNullByteAlt(fp, delimiter, chunk_size, max_read)


def ReadTillNullByte(fp, delimiter=_default_delim(None), max_read=64 * 1024 * 1024):
    return read_until_delimiter(
        fp,
        delimiter,
        max_read=max_read,
        chunk_size=8192,
        decode=True,
        errors="strict",
    )


def ReadUntilNullByte(fp, delimiter=_default_delim(None), max_read=64 * 1024 * 1024):
    return ReadTillNullByte(fp, delimiter, max_read)


def ReadTillNullByteByNum(
    fp,
    delimiter=_default_delim(None),
    num_delimiters=1,
    chunk_size=1024,
    max_read=64 * 1024 * 1024,
):
    # Return list of text parts; **pad to N** to avoid IndexError in rigid parsers
    return read_until_n_delimiters(
        fp,
        delimiter,
        num_delimiters,
        max_read=max_read,
        chunk_size=chunk_size,
        decode=True,
        errors="replace",
        pad_to_n=True,
    )


def ReadUntilNullByteByNum(
    fp,
    delimiter=_default_delim(None),
    num_delimiters=1,
    chunk_size=1024,
    max_read=64 * 1024 * 1024,
):
    return ReadTillNullByteByNum(fp, delimiter, num_delimiters, chunk_size, max_read)


def SeekToEndOfFile(fp):
    lasttell = 0
    while(True):
        fp.seek(1, 1)
        if(lasttell == fp.tell()):
            break
        lasttell = fp.tell()
    return True

def ReadFileHeaderData(fp, skipchecksum=False, formatspecs=None, saltkey=None):
    if(formatspecs is None):
        formatspecs = __file_format_multi_dict__
    filespec = None
    delimiter = None
    for key, value in formatspecs.items():
        oldseek = fp.tell()
        filetype = fp.read(value['format_len'])
        formatver = str(int(value['format_ver']))
        filever = fp.read(len(formatver)).decode("UTF-8")
        if(filetype.hex()==value['format_hex'] and formatver==filever):
            filespec = formatspecs[key]
            delimiter = filespec['format_delimiter']
            filetypefull = filetype.decode("UTF-8")+filever
            break
        fp.seek(oldseek, 1)
    if(filespec is None or delimiter is None):
        return False
    fp.seek(len(delimiter), 1)
    outlist = ReadFileHeaderDataBySize(fp, delimiter)
    outlist.insert(0, filetypefull)
    if(not ValidateHeaderChecksum(outlist[:-1], outlist[-2], outlist[-1], filespec, saltkey) and not skipchecksum):
        return False
    fp.seek(len(delimiter), 1)
    return outlist

def ReadFileHeaderDataWithContent(fp, listonly=False, contentasfile=False, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__, saltkey=None):
    if(not hasattr(fp, "read")):
        return False
    delimiter = formatspecs['format_delimiter']
    fheaderstart = fp.tell()
    HeaderOut = ReadFileHeaderDataBySize(fp, delimiter)
    if(len(HeaderOut) == 0):
        return False
    if(re.findall("^[.|/]", HeaderOut[5])):
        fname = HeaderOut[5]
    else:
        fname = "./"+HeaderOut[5]
    fcs = HeaderOut[-2].lower()
    fccs = HeaderOut[-1].lower()
    fsize = int(HeaderOut[7], 16)
    fcompression = HeaderOut[17]
    fcsize = int(HeaderOut[18], 16)
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
    HeaderOut.append(fcontents)
    return HeaderOut


def ReadFileHeaderDataWithContentToArray(fp, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__, saltkey=None):
    if(not hasattr(fp, "read")):
        return False
    delimiter = formatspecs['format_delimiter']
    fheaderstart = fp.tell()
    HeaderOut = ReadFileHeaderDataBySize(fp, delimiter)
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
    HeaderOut = ReadFileHeaderDataBySize(fp, delimiter)
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


def ReadFileDataWithContent(fp, filestart=0, listonly=False, contentasfile=False, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__, saltkey=None):
    if(not hasattr(fp, "read")):
        return False
    delimiter = formatspecs['format_delimiter']
    curloc = filestart
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
    outfseeknextfile = inheader[9]
    fjsonsize = int(inheader[12], 16)
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
        HeaderOut = ReadFileHeaderDataWithContent(fp, listonly, contentasfile, uncompress, skipchecksum, formatspecs, saltkey)
        if(len(HeaderOut) == 0):
            break
        flist.append(HeaderOut)
        countnum = countnum + 1
    CatSize = fp.tell()
    CatSizeEnd = CatSize
    return flist


def ReadFileDataWithContentToArray(fp, filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=True, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__, saltkey=None, seektoend=False):
    if(not hasattr(fp, "read")):
        return False
    delimiter = formatspecs['format_delimiter']
    curloc = filestart
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
            fvendorfieldslist.append(inheader[extrastart])
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
    outlist = {'fnumfiles': fnumfiles, 'ffilestart': filestart, 'fformat': formversions[0], 'fcompression': fcompresstype, 'fencoding': fhencoding, 'fmtime': fheadmtime, 'fctime': fheadctime, 'fversion': formversions[1], 'fostype': fostype, 'fprojectname': fprojectname, 'fimptype': fpythontype, 'fheadersize': fheadsize, 'fnumfields': fnumfields + 2, 'fformatspecs': formatspecs, 'fseeknextfile': fseeknextfile, 'fchecksumtype': fprechecksumtype, 'fheaderchecksum': fprechecksum, 'fjsonchecksumtype': fjsonchecksumtype, 'fjsontype': fjsontype, 'fjsonlen': fjsonlen, 'fjsonsize': fjsonsize, 'fjsonrawdata': fjsonrawcontent, 'fjsondata': fjsoncontent, 'fjstart': fjstart, 'fjend': fjend, 'fjsonchecksum': fjsonchecksum, 'frawheader': [formstring] + inheader, 'fextrafields': fnumextrafields, 'fextrafieldsize': fnumextrafieldsize, 'fextradata': fextrafieldslist, 'fvendorfields': fvendorfields, 'fvendordata': fvendorfieldslist, 'ffilelist': []}
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
    while (countnum < seekend):
        HeaderOut = ReadFileHeaderDataWithContentToArray(fp, listonly, contentasfile, uncompress, skipchecksum, formatspecs, saltkey)
        if(len(HeaderOut) == 0):
            break
        HeaderOut.update({'fid': realidnum, 'fidalt': realidnum})
        outlist['ffilelist'].append(HeaderOut)
        countnum = countnum + 1
        realidnum = realidnum + 1
    CatSize = fp.tell()
    CatSizeEnd = CatSize
    outlist.update({'fp': fp, 'fsize': CatSizeEnd})
    return outlist


def ReadFileDataWithContentToList(fp, filestart=0, seekstart=0, seekend=0, listonly=False, contentasfile=False, uncompress=True, skipchecksum=False, formatspecs=__file_format_dict__, saltkey=None, seektoend=False):
    if(not hasattr(fp, "read")):
        return False
    delimiter = formatspecs['format_delimiter']
    curloc = filestart
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
            fvendorfieldslist.append(inheader[extrastart])
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
    while (countnum < seekend):
        HeaderOut = ReadFileHeaderDataWithContentToList(fp, listonly, contentasfile, uncompress, skipchecksum, formatspecs, saltkey)
        if(len(HeaderOut) == 0):
            break
        outlist.append(HeaderOut)
        countnum = countnum + 1
        realidnum = realidnum + 1
    CatSize = fp.tell()
    CatSizeEnd = CatSize
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
    elif(isinstance(infile, bytes)):
        fp = MkTempFile()
        fp.write(infile)
        try:
            fp.seek(0, 2)
        except (OSError, ValueError):
            SeekToEndOfFile(fp)
        outfsize = fp.tell()
        fp.seek(filestart, 0)
        currentfilepos = fp.tell()
    elif(re.findall(__download_proto_support__, infile) and pywwwget):
        fp = download_file_from_internet_file(infile)
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
            if(not infp):
                break
            infp.seek(0, 0)
            currentinfilepos = infp.tell()
            while True:
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
    elif(isinstance(infile, bytes)):
        fp = MkTempFile()
        fp.write(infile)
        try:
            fp.seek(0, 2)
        except (OSError, ValueError):
            SeekToEndOfFile(fp)
        outfsize = fp.tell()
        fp.seek(filestart, 0)
        currentfilepos = fp.tell()
    elif(re.findall(__download_proto_support__, infile) and pywwwget):
        fp = download_file_from_internet_file(infile)
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
            if(not infp):
                break
            infp.seek(0, 0)
            currentinfilepos = infp.tell()
            while True:
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
    d = delimiter.encode("UTF-8")

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
    extrafields = format(int(len(xlist)), 'x').lower()           # count (hex)
    extrasizestr = AppendNullByte(extrafields, delimiter)        # count+delim
    if xlist:
        extrasizestr += AppendNullBytes(xlist, delimiter)        # items joined + trailing delim
    extrasizelen = format(int(len(extrasizestr)), 'x').lower()   # byte length of the extras block

    # 4) core header fields before checksum:
    #    tmpoutlenhex, fencoding, platform.system(), fnumfiles
    fnumfiles_hex = format(int(numfiles), 'x').lower()
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
    tmpoutlenhex = format(int(tmpoutlen), 'x').lower()
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
    formheaersize = format(int(len(tmpfileoutstr) - len(d)), 'x').lower()

    # 7) prepend the fileheader + size, recompute outer checksum
    fnumfilesa = (
        fileheader
        + AppendNullByte(formheaersize, delimiter)
        + fnumfilesa
    )

    outfileheadercshex = GetFileChecksum(fnumfilesa, checksumtype[0], True, formatspecs, saltkey)
    fnumfilesa += AppendNullByte(outfileheadercshex, delimiter)

    # 8) final total size field (again per your original logic)
    formheaersize = format(int(len(fnumfilesa) - len(d)), 'x').lower()
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
    elif(re.findall(__upload_proto_support__, outfile) and pywwwget):
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
    elif(re.findall(__upload_proto_support__, outfile) and pywwwget):
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
        elif(isinstance(infiles, (str, ))):
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
        fblksize = format(int(0), 'x').lower()
        if(hasattr(fstatinfo, "st_blksize")):
            fblksize = format(int(fstatinfo.st_blksize), 'x').lower()
        fblocks = format(int(0), 'x').lower()
        if(hasattr(fstatinfo, "st_blocks")):
            fblocks = format(int(fstatinfo.st_blocks), 'x').lower()
        fflags = format(int(0), 'x').lower()
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
            fdev = format(int(0), 'x').lower()
        try:
            frdev = fstatinfo.st_rdev
        except AttributeError:
            frdev = format(int(0), 'x').lower()
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
    elif(re.findall(__download_proto_support__, infile) and pywwwget):
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
        fblksize = format(int(0), 'x').lower()
        fblocks = format(int(0), 'x').lower()
        fflags = format(int(0), 'x').lower()
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
        pax_headers = getattr(member, "pax_headers", None)
        if(not pax_headers):
            pax_headers = None
        if(pax_headers is not None):
            jsondata.update({'pax_headers': pax_headers})
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
    elif(re.findall(__download_proto_support__, infile) and pywwwget):
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
        fblksize = format(int(0), 'x').lower()
        fblocks = format(int(0), 'x').lower()
        fflags = format(int(0), 'x').lower()
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
        flinkcount = format(int(flinkcount), 'x').lower()
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
            mode = int(zipinfo.external_attr >> 16)
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
            fblksize = format(int(0), 'x').lower()
            fblocks = format(int(0), 'x').lower()
            fflags = format(int(0), 'x').lower()
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
            flinkcount = format(int(flinkcount), 'x').lower()
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
            fblksize = format(int(0), 'x').lower()
            fblocks = format(int(0), 'x').lower()
            fflags = format(int(0), 'x').lower()
            ftype = 0
            if(member.is_directory):
                ftype = 5
            else:
                ftype = 0
            flinkname = ""
            fcurfid = format(int(curfid), 'x').lower()
            fcurinode = format(int(curfid), 'x').lower()
            curfid = curfid + 1
            flinkcount = format(int(flinkcount), 'x').lower()
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
    elif(hasattr(outfile, "read") or hasattr(outfile, "write")):
        fp = outfile
    elif(re.findall(__upload_proto_support__, outfile) and pywwwget):
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
    elif((not hasattr(outfile, "read") and not hasattr(outfile, "write")) and re.findall(__upload_proto_support__, outfile) and pywwwget):
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
    elif(re.findall(__upload_proto_support__, outfile) and pywwwget):
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
    elif((not hasattr(outfile, "read") and not hasattr(outfile, "write")) and re.findall(__upload_proto_support__, outfile) and pywwwget):
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
    elif(re.findall(__upload_proto_support__, outfile) and pywwwget):
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
    elif((not hasattr(outfile, "read") and not hasattr(outfile, "write")) and re.findall(__upload_proto_support__, outfile) and pywwwget):
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
    elif(re.findall(__upload_proto_support__, outfile) and pywwwget):
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
    elif((not hasattr(outfile, "read") and not hasattr(outfile, "write")) and re.findall(__upload_proto_support__, outfile) and pywwwget):
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
    elif(re.findall(__upload_proto_support__, outfile) and pywwwget):
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
    elif((not hasattr(outfile, "read") and not hasattr(outfile, "write")) and re.findall(__upload_proto_support__, outfile) and pywwwget):
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
        elif(re.findall(__upload_proto_support__, outfile) and pywwwget):
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
        elif((not hasattr(outfile, "read") and not hasattr(outfile, "write")) and re.findall(__upload_proto_support__, outfile) and pywwwget):
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
        elif(re.findall(__upload_proto_support__, outfile) and pywwwget):
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
        elif((not hasattr(outfile, "read") and not hasattr(outfile, "write")) and re.findall(__upload_proto_support__, outfile) and pywwwget):
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
    elif(isinstance(infile, bytes)):
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
    elif(re.findall(__download_proto_support__, infile) and pywwwget):
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
        elif(isinstance(infile, bytes)):
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
    while (il < fnumfiles):
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
        if (infile != "-" and not isinstance(infile, (bytes, bytearray, memoryview))  # bytes is str on Py2
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
    if (outfile != "-" and not isinstance(outfile, (bytes, bytearray, memoryview))
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
          and re.findall(__upload_proto_support__, outfile) and pywwwget):
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
        listarrayfilespre = infile
    else:
        if(infile != "-" and not hasattr(infile, "read") and not hasattr(infile, "write") and not isinstance(infile, bytes)):
            infile = RemoveWindowsPath(infile)
        listarrayfilespre = CatFileToArray(infile, "auto", filestart, seekstart, seekend, False, True, True, skipchecksum, formatspecs, saltkey, seektoend, returnfp)
    if(not listarrayfilespre):
        return False
    if(not isinstance(listarrayfilespre, list)):
        listarrayfilespre = [listarrayfilespre]
    fplist = []
    if os.path.exists(outdir) and os.path.isdir(outdir):
        pass
    elif os.path.exists(outdir) and os.path.isdir(outdir):
        return False
    elif not os.path.exists(outdir):
        os.makedirs(outdir)
    for listarrayfiles in listarrayfilespre:
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
            if(returnfp):
                fplist.append(listarrayfiles['ffilelist'][lcfi]['fp'])
            lcfi = lcfi + 1
    if(returnfp):
        return fplist
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
        if(infile != "-" and not hasattr(infile, "read") and not hasattr(infile, "write") and not isinstance(infile, bytes)):
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
    elif(re.findall(__download_proto_support__, infile) and pywwwget):
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
    elif(re.findall(__download_proto_support__, infile) and pywwwget):
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
            mode = int(zipinfo.external_attr >> 16)
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


def InFileListFiles(infile, fmttype="auto", filestart=0, seekstart=0, seekend=0, skipchecksum=False, formatspecs=__file_format_multi_dict__, saltkey=None, seektoend=False, verbose=False, newstyle=False, returnfp=False):
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
        return ArchiveFileListFiles(infile, fmttype, filestart, seekstart, seekend, skipchecksum, formatspecs, saltkey, seektoend, verbose, newstyle, returnfp)
    else:
        return False
    return False


def InFileListFile(infile, verbose=False, formatspecs=__file_format_multi_dict__, seektoend=False, newstyle=False, returnfp=False):
    return InFileListFiles(infile, verbose, formatspecs, seektoend, newstyle, returnfp)
