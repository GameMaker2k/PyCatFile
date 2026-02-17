#!/usr/bin/env python3

import os
import io
import re
import sys
import logging
from typing import Any, Dict, Optional, Tuple, Union, BinaryIO, IO, Iterable, List, Mapping, Callable
import json
import getpass
import random
import platform
import socket
import ipaddress

try:
    import socks  # type: ignore
except Exception:
    socks = None

# Optional Bluetooth support: works via stdlib on Linux (AF_BLUETOOTH/BTPROTO_RFCOMM and BTPROTO_L2CAP)
# and via PyBluez if installed.
try:
    import bluetooth as _pybluez  # type: ignore
except Exception:
    _pybluez = None
import shutil
import time
import struct
import hmac
import hashlib
import tempfile
import zlib
import gzip
import ssl
import mimetypes

try:
    mimetypes.init()
except Exception:
    pass
import base64
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

import http.cookiejar as cookielib

from http.cookies import SimpleCookie

defcert = None
try:
    import certifi
    defcert = certifi.where()
except ImportError:
    pass

from io import BytesIO

from urllib.parse import quote_from_bytes, unquote_to_bytes, urlencode
from urllib.request import install_opener, build_opener


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


from urllib.parse import urlparse, urlunparse, parse_qs, unquote
from urllib.request import (
    Request,
    build_opener,
    HTTPBasicAuthHandler,
    HTTPCookieProcessor,
    HTTPSHandler,
    HTTPPasswordMgrWithDefaultRealm,
)
from urllib.error import URLError, HTTPError
from http.client import HTTPException

from http.server import BaseHTTPRequestHandler, HTTPServer
import socketserver as _socketserver



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

__program_name__ = "PyNeoWWW-Get"
__program_alt_name__ = "PyWWWGet"
__program_small_name__ = "wwwget"
__project__ = __program_name__
__project_url__ = "https://github.com/GameMaker2k/PyNeoWWW-Get"
__version_info__ = (2, 2, 0, "RC 1", 1)
__version_date_info__ = (2026, 1, 23, "RC 1", 1)
__version_date__ = str(__version_date_info__[0])+"."+str(__version_date_info__[
    1]).zfill(2)+"."+str(__version_date_info__[2]).zfill(2)
__revision__ = __version_info__[3]
__revision_id__ = "$Id$"
if(__version_info__[4] is not None):
    __version_date_plusrc__ = __version_date__ + \
        "-"+str(__version_date_info__[4])
if(__version_info__[4] is None):
    __version_date_plusrc__ = __version_date__
if(__version_info__[3] is not None):
    __version__ = str(__version_info__[0])+"."+str(__version_info__[1])+"."+str(
        __version_info__[2])+" "+str(__version_info__[3])
if(__version_info__[3] is None):
    __version__ = str(
        __version_info__[0])+"."+str(__version_info__[1])+"."+str(__version_info__[2])

PyBitness = platform.architecture()
if(PyBitness == "32bit" or PyBitness == "32"):
    PyBitness = "32"
elif(PyBitness == "64bit" or PyBitness == "64"):
    PyBitness = "64"
else:
    PyBitness = "32"

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

def _strip_ipv6_brackets(host):
    host = "" if host is None else str(host)
    host = host.strip()
    if host.startswith("[") and host.endswith("]") and len(host) >= 2:
        return host[1:-1]
    return host

def _is_ipv6_literal(host):
    host = _strip_ipv6_brackets(host)
    # allow RFC6874 zone indices (e.g. "fe80::1%en0")
    base = host.split("%", 1)[0]
    try:
        return isinstance(ipaddress.ip_address(base), ipaddress.IPv6Address)
    except Exception:
        return False

def _url_host(host):
    host = _strip_ipv6_brackets(host)
    if _is_ipv6_literal(host):
        # RFC6874: zone id must be percent-encoded inside brackets
        if "%" in host:
            host = host.replace("%", "%25")
        return "[" + host + "]"
    return host

def _set_ipv6_dualstack(sock):
    # Best-effort dual-stack (IPv4-mapped) support on AF_INET6 sockets.
    try:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    except Exception:
        pass

def _gai_list(host, port, socktype, flags=0):
    host = _strip_ipv6_brackets(host) if host else None
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socktype, 0, flags)
    except Exception:
        infos = []
    # Prefer IPv6 first (helps dual-stack bind & AAAA-first environments)
    af6 = getattr(socket, "AF_INET6", None)
    infos.sort(key=lambda it: 0 if it[0] == af6 else 1)
    return infos

def _tcp_listen_socket(host, port, backlog=1, reuse=True):
    flags = getattr(socket, "AI_PASSIVE", 0)
    h = host
    if h in ("", None, "0.0.0.0", "::"):
        h = None

    infos = _gai_list(h, int(port), socket.SOCK_STREAM, flags=flags)
    if not infos:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if reuse:
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                except Exception:
                    pass
            s.bind((host or "", int(port)))
            s.listen(int(backlog))
            return s
        except Exception:
            return None

    for fam, st, pr, _cn, sa in infos:
        s = None
        try:
            s = socket.socket(fam, st, pr)
            if reuse:
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                except Exception:
                    pass
            if fam == getattr(socket, "AF_INET6", None):
                _set_ipv6_dualstack(s)
            s.bind(sa)
            s.listen(int(backlog))
            return s
        except Exception:
            try:
                if s:
                    s.close()
            except Exception:
                pass
            continue
    return None

def _tcp_connect_socket(host, port, timeout=None, wait=False, wait_timeout=None, verbose=False, logger=None):
    # socket.create_connection uses AF_UNSPEC internally (IPv4+IPv6)
    start_t = time.time()
    while True:
        try:
            to = float(timeout) if timeout is not None else None
        except Exception:
            to = None
        try:
            s = socket.create_connection((_strip_ipv6_brackets(host), int(port)), timeout=to)
            return s
        except Exception:
            if not wait:
                return None
            if wait_timeout is not None:
                try:
                    wt = float(wait_timeout)
                    if wt >= 0 and (time.time() - start_t) >= wt:
                        return None
                except Exception:
                    pass
            _net_log(verbose, "TCP: waiting for receiver, retrying...", logger=logger)
            try:
                time.sleep(0.1)
            except Exception:
                pass


def _ipproto_sctp() -> int:
    """Best-effort IPPROTO_SCTP constant (stdlib may omit it on some builds)."""
    try:
        return int(getattr(socket, "IPPROTO_SCTP"))
    except Exception:
        # IANA assigned SCTP protocol number
        return 132


def _is_seqpacket_socket(sock) -> bool:
    try:
        return getattr(sock, "type", None) == socket.SOCK_SEQPACKET
    except Exception:
        return False


def _recv_line(sock, max_len: int = 4096) -> bytes:
    """Read a single \n-terminated control line safely.

    For stream sockets, we use MSG_PEEK to find the newline and then consume exactly
    that many bytes, so we don't accidentally eat file payload data.

    For SOCK_SEQPACKET sockets (e.g., SCTP SEQPACKET, BT L2CAP), control messages
    must be sent in a single record; we recv() once.

    Returns raw bytes (may not include trailing \n if sender didn't include one).
    """
    try:
        max_len = int(max_len)
    except Exception:
        max_len = 4096
    if max_len <= 0:
        max_len = 4096

    if _is_seqpacket_socket(sock):
        try:
            b = sock.recv(max_len)
            return b if isinstance(b, (bytes, bytearray)) else bytes(b)
        except Exception:
            return b""

    # stream socket: peek then recv exact up-to-newline
    try:
        if hasattr(socket, "MSG_PEEK"):
            buf = sock.recv(max_len, socket.MSG_PEEK)
        else:
            buf = b""
    except Exception:
        buf = b""

    if not buf:
        try:
            b = sock.recv(max_len)
            return b if isinstance(b, (bytes, bytearray)) else bytes(b)
        except Exception:
            return b""

    nl = buf.find(b"\n")
    to_read = (nl + 1) if nl >= 0 else len(buf)

    out = bytearray()
    while len(out) < to_read:
        try:
            chunk = sock.recv(to_read - len(out))
        except Exception:
            break
        if not chunk:
            break
        out.extend(chunk if isinstance(chunk, (bytes, bytearray)) else bytes(chunk))
    return bytes(out)


def _sctp_listen_socket(host, port, backlog: int = 1, reuse: bool = True):
    """Create an SCTP SOCK_SEQPACKET listening socket (IPv4/IPv6 via getaddrinfo)."""
    proto = _ipproto_sctp()
    flags = getattr(socket, "AI_PASSIVE", 0)
    h = host
    if h in ("", None, "0.0.0.0", "::"):
        h = None

    infos = _gai_list(h, int(port), socket.SOCK_SEQPACKET, flags=flags)
    if not infos:
        # fallback (IPv4)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_SEQPACKET, proto)
            if reuse:
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                except Exception:
                    pass
            s.bind((_strip_ipv6_brackets(host or ""), int(port)))
            s.listen(int(backlog))
            return s
        except Exception:
            return None

    for fam, _st, _pr, _cn, sa in infos:
        s = None
        try:
            s = socket.socket(fam, socket.SOCK_SEQPACKET, proto)
            if reuse:
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                except Exception:
                    pass
            if fam == getattr(socket, "AF_INET6", None):
                _set_ipv6_dualstack(s)
            s.bind(sa)
            s.listen(int(backlog))
            return s
        except Exception:
            try:
                if s:
                    s.close()
            except Exception:
                pass
            continue
    return None


def _sctp_connect_socket(host, port, timeout=None, wait: bool = False, wait_timeout=None, verbose: bool = False, logger=None):
    """Connect to an SCTP SOCK_SEQPACKET endpoint (IPv4/IPv6)."""
    proto = _ipproto_sctp()
    start_t = time.time()

    while True:
        try:
            to = float(timeout) if timeout is not None else None
        except Exception:
            to = None

        infos = _gai_list(host, int(port), socket.SOCK_SEQPACKET, flags=0)
        if not infos:
            infos = [(socket.AF_INET, socket.SOCK_SEQPACKET, proto, "", (_strip_ipv6_brackets(host), int(port)))]

        last_err = None
        for fam, _st, _pr, _cn, sa in infos:
            s = None
            try:
                s = socket.socket(fam, socket.SOCK_SEQPACKET, proto)
                if fam == getattr(socket, "AF_INET6", None):
                    _set_ipv6_dualstack(s)
                if to is not None:
                    s.settimeout(to)
                s.connect(sa)
                return s
            except Exception as e:
                last_err = e
                try:
                    if s:
                        s.close()
                except Exception:
                    pass
                continue

        if not wait:
            return None

        if wait_timeout is not None:
            try:
                wt = float(wait_timeout)
                if wt >= 0 and (time.time() - start_t) >= wt:
                    return None
            except Exception:
                pass

        _net_log(verbose, "SCTP: waiting for receiver, retrying...", logger=logger)
        try:
            time.sleep(0.1)
        except Exception:
            pass


def _udp_bind_socket(host, port, reuse=True):
    flags = getattr(socket, "AI_PASSIVE", 0)
    h = host
    if h in ("", None, "0.0.0.0", "::"):
        h = None

    infos = _gai_list(h, int(port), socket.SOCK_DGRAM, flags=flags)
    if not infos:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if reuse:
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                except Exception:
                    pass
            s.bind((host or "", int(port)))
            return s
        except Exception:
            return None

    for fam, st, pr, _cn, sa in infos:
        s = None
        try:
            s = socket.socket(fam, st, pr)
            if reuse:
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                except Exception:
                    pass
            if fam == getattr(socket, "AF_INET6", None):
                _set_ipv6_dualstack(s)
            s.bind(sa)
            return s
        except Exception:
            try:
                if s:
                    s.close()
            except Exception:
                pass
            continue
    return None

def _udp_socket_and_addr(host, port):
    infos = _gai_list(host, int(port), socket.SOCK_DGRAM, flags=0)
    for fam, st, pr, _cn, sa in infos:
        s = None
        try:
            s = socket.socket(fam, st, pr)
            if fam == getattr(socket, "AF_INET6", None):
                _set_ipv6_dualstack(s)
            return s, sa
        except Exception:
            try:
                if s:
                    s.close()
            except Exception:
                pass
            continue
    # fallback (IPv4)
    return socket.socket(socket.AF_INET, socket.SOCK_DGRAM), (_strip_ipv6_brackets(host), int(port))

def _best_lan_ip():
    """Attempt to find the best LAN IPv4 address."""
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
        try:
            s.close()
        except Exception:
            pass

def _best_lan_ip6():
    """Attempt to find the best LAN IPv6 address (best-effort)."""
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    except Exception:
        return "::1"
    try:
        # public IPv6 anycast resolver (route selection only; no packets sent)
        s.connect(("2001:4860:4860::8888", 80, 0, 0))
        return s.getsockname()[0]
    except Exception:
        # fallback: try hostname AAAA
        try:
            hn = socket.gethostname()
            infos = socket.getaddrinfo(hn, None, socket.AF_INET6)
            for it in infos:
                ip = it[4][0]
                if ip:
                    return ip
        except Exception:
            pass
        return "::1"
    finally:
        try:
            s.close()
        except Exception:
            pass

def _listen_urls(scheme, bind_host, port, path, query=""):
    if not path:
        path = "/"
    if not path.startswith("/"):
        path = "/" + path
    q = ""
    if query:
        q = "?" + query.lstrip("?")

    urls = []

    def _add(h):
        h = _strip_ipv6_brackets(h)
        if not h:
            return
        urls.append("%s://%s:%d%s%s" % (scheme, _url_host(h), int(port), path, q))

    bh = _strip_ipv6_brackets(bind_host or "")

    # If binding to "all", show loopback + LAN (v4 + v6).
    if not bh or bh in ("0.0.0.0", "::"):
        _add("127.0.0.1")
        _add("::1")

        ip4 = _best_lan_ip()
        if ip4 and ip4 not in ("127.0.0.1", "0.0.0.0"):
            _add(ip4)

        ip6 = _best_lan_ip6()
        if ip6 and ip6 not in ("::1", "::"):
            _add(ip6)
    else:
        _add(bh)

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



def _seqpacket_send_chunked(sock, payload, max_chunk=1024, logger=None):
    """Send bytes over SOCK_SEQPACKET sockets by splitting into <=MTU-sized chunks.

    Linux/BlueZ L2CAP uses SOCK_SEQPACKET with a per-packet MTU limit. If you try to
    send a larger message, you'll typically get EMSGSIZE ("Message too long").
    This helper splits payload into chunks and automatically backs off chunk size
    if EMSGSIZE is encountered.

    Returns the (possibly reduced) chunk size that succeeded, so callers can reuse it.
    """
    import errno as _errno

    if payload is None:
        return int(max_chunk or 1024)

    try:
        chunk = int(max_chunk or 1024)
    except Exception:
        chunk = 1024
    if chunk <= 0:
        chunk = 1024

    off = 0
    n = len(payload)
    while off < n:
        part = payload[off:off + chunk]
        try:
            sent = sock.send(part)
            if sent is None:
                sent = len(part)
            if sent <= 0:
                raise OSError("send returned 0 bytes")
            off += sent
        except OSError as e:
            if getattr(e, "errno", None) == getattr(_errno, "EMSGSIZE", 90) and chunk > 64:
                chunk = max(64, chunk // 2)
                continue
            raise
    return chunk
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


def _mk_sock(proxy, timeout, family=socket.AF_INET):
    """
    proxy: dict or None
      If dict, expected keys:
        host, port, username(optional), password(optional)
    family: socket.AF_INET or socket.AF_INET6 (best-effort)
    """
    af6 = getattr(socket, "AF_INET6", None)
    fam = family if (family in (socket.AF_INET, af6)) else socket.AF_INET

    if socks is None:
        if proxy:
            raise RuntimeError("SOCKS proxy requested but the 'socks' (PySocks) module is not installed.")
        s = socket.socket(fam, socket.SOCK_DGRAM)
    else:
        s = socks.socksocket(fam, socket.SOCK_DGRAM)

    try:
        if fam == af6:
            _set_ipv6_dualstack(s)
    except Exception:
        pass

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
    fam = socket.AF_INET
    try:
        infos = _gai_list(server_host, int(server_port), socket.SOCK_DGRAM, flags=0)
        if infos:
            fam = infos[0][0]
    except Exception:
        pass
    sock = _mk_sock(proxy, timeout, family=fam)

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
    fam = socket.AF_INET
    try:
        infos = _gai_list(server_host, int(server_port), socket.SOCK_DGRAM, flags=0)
        if infos:
            fam = infos[0][0]
    except Exception:
        pass
    sock = _mk_sock(proxy, timeout, family=fam)
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

_UNIX_STREAM_SCHEMES = {"unix", "unixstream"}
_UNIX_SEQPACKET_SCHEMES = {"unixstreamsctp", "unixseqpacket", "unix_seqpacket", "unixsp"}
_UNIX_DGRAM_SCHEMES  = {"unixdgram", "unixgram", "unix_datagram"}
_UNIX_SCHEMES = _UNIX_STREAM_SCHEMES | _UNIX_SEQPACKET_SCHEMES | _UNIX_DGRAM_SCHEMES

def _unix_sock_is_seqpacket(proto: str, kwargs: dict) -> bool:
    """Return True if an AF_UNIX socket should be treated as SOCK_SEQPACKET.

    This is True for explicit unix seqpacket schemes (unixstreamsctp, unixseqpacket, ...)
    and also for unix/unixstream when the URL specifies socktype=seqpacket.
    """
    try:
        if proto in _UNIX_SEQPACKET_SCHEMES:
            return True
        if proto in _UNIX_STREAM_SCHEMES:
            st = (kwargs or {}).get("socktype") or ""
            st = str(st).strip().lower()
            return st in ("seqpacket", "seq", "seqpkt", "sp", "sctp", "unixseqpacket", "unix_seqpacket", "unixstreamsctp")
    except Exception:
        pass
    return False




def _safe_unlink(path: str):
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except Exception:
        pass


def _tmp_unix_client_path(prefix="pwg4-client-", dir="/tmp") -> str:
    # For UNIX datagrams, client MUST bind to a unique path to receive READY/ACK
    fd, p = tempfile.mkstemp(prefix=prefix, suffix=".sock", dir=dir)
    os.close(fd)
    _safe_unlink(p)  # remove the file so bind() can create a socket there
    return p


def _unix_path_from_parts(parts, o, fallback_port=0) -> str:
    # allow overrides via query: ?unix_path=/tmp/x.sock or ?path=/tmp/x.sock
    p = o.get("unix_path") or o.get("path")
    if p:
        return str(p)
    # normal: unix:///tmp/x.sock
    if getattr(parts, "path", None):
        return unquote(parts.path)
    return f"/tmp/pwg4-{int(fallback_port)}.sock"

def _parse_net_url(url):
    p = urlparse(url)
    qs = parse_qs(p.query or "")

    is_udpish = (p.scheme == "udp") or (p.scheme in _UNIX_DGRAM_SCHEMES)
    is_tcpish = (p.scheme in ("tcp", "sctp")) or (p.scheme in _UNIX_STREAM_SCHEMES) or (p.scheme in _UNIX_SEQPACKET_SCHEMES)
    is_btish = (p.scheme in ("bt", "rfcomm", "bluetooth", "l2cap", "btl2cap", "bluetoothl2cap", "bluetooth_l2cap"))

    # mode default
    if p.scheme in _UNIX_DGRAM_SCHEMES:
        mode_default = "raw"
    else:
        mode_default = "seq" if p.scheme == "udp" else "raw"

    mode = _qstr(qs, "mode", mode_default).lower()

    has_timeout = "timeout" in qs
    if is_tcpish and not has_timeout:
        timeout = None
    else:
        timeout = float(_qnum(qs, "timeout", 1.0 if is_udpish else 30.0, cast=float))

    accept_timeout = float(_qnum(
        qs, "accept_timeout",
        0.0 if is_tcpish else (timeout or 0.0),
        cast=float
    ))

    total_timeout = float(_qnum(qs, "total_timeout", 0.0, cast=float))
    window = int(_qnum(qs, "window", 32, cast=int))
    retries = int(_qnum(qs, "retries", 20, cast=int))

    chunk_default = 1200 if is_udpish else (1024 if is_btish else 65536)
    chunk = int(_qnum(qs, "chunk", chunk_default, cast=int))

    print_url = _qflag(qs, "print_url", False)

    if "wait" in qs:
        wait = _qflag(qs, "wait", False)
    else:
        wait = (is_udpish and mode == "raw")

    if "connect_wait" in qs:
        connect_wait = _qflag(qs, "connect_wait", False)
    else:
        connect_wait = is_tcpish

    handshake_default = True if (p.scheme in ("tcp", "udp", "sctp") or p.scheme in _UNIX_SCHEMES) else False
    handshake = _qflag(qs, "handshake", handshake_default)

    hello_interval = float(_qnum(qs, "hello_interval", 0.1, cast=float))
    wait_timeout = _qnum(qs, "wait_timeout", None, cast=float)
    wait_forever = _qflag(qs, "wait_forever", False)
    verbose = _qflag(qs, "verbose", False) or _qflag(qs, "debug", False)

    # bind:
    # - tcp/udp: local bind interface
    # - unixdgram: OPTIONAL client bind path (so sender can receive READY/ACK); if not set we make a temp path
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

    unix_path = _qstr(qs, "unix_path", None) or _qstr(qs, "path", None)
    socktype = _qstr(qs, "socktype", None) or _qstr(qs, "stype", None)
    if socktype is not None:
        try:
            socktype = str(socktype).strip().lower()
        except Exception:
            pass

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
        "unix_path": unix_path,
        "socktype": socktype,
    }

# --- Bluetooth helpers ---------------------------------------------------------
# Notes:
# - RFCOMM URLs use the "bt", "rfcomm", or "bluetooth" schemes.
# - L2CAP URLs use the "l2cap" (or "btl2cap") schemes.
# - Netloc parsing cannot rely on urlparse.hostname because MAC addresses contain ':'.
# - Receiver/listener uses recv_to_fileobj(..., proto="bt" or proto="l2cap") to bind/listen.
# - Sender uses send_from_fileobj(..., proto="bt" or proto="l2cap") to connect.

_BT_RFCOMM_SCHEMES = ("bt", "rfcomm", "bluetooth")
_BT_L2CAP_SCHEMES  = ("l2cap", "btl2cap", "bluetoothl2cap", "bluetooth_l2cap")
_BT_URL_SCHEMES    = _BT_RFCOMM_SCHEMES + _BT_L2CAP_SCHEMES

# "proto" values used internally by recv_to_fileobj/send_from_fileobj
_BT_PROTOS = set(_BT_RFCOMM_SCHEMES) | {"l2cap"}

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

def _has_l2cap() -> bool:
    """Return True if we can create an L2CAP socket (native or PyBluez)."""
    try:
        if hasattr(socket, "AF_BLUETOOTH") and hasattr(socket, "BTPROTO_L2CAP") and hasattr(socket, "SOCK_SEQPACKET"):
            return True
    except Exception:
        pass
    try:
        if _pybluez is not None and hasattr(_pybluez, "BluetoothSocket") and hasattr(_pybluez, "L2CAP"):
            return True
    except Exception:
        pass
    return False

def _bt_socket_l2cap_seqpacket():
    """Create an L2CAP SOCK_SEQPACKET socket using stdlib (BlueZ) or PyBluez fallback."""
    try:
        if hasattr(socket, "AF_BLUETOOTH") and hasattr(socket, "BTPROTO_L2CAP") and hasattr(socket, "SOCK_SEQPACKET"):
            return socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
    except Exception:
        pass
    try:
        if _pybluez is not None and hasattr(_pybluez, "L2CAP"):
            return _pybluez.BluetoothSocket(_pybluez.L2CAP)
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
    if len(parts) >= 7:
        last = parts[-1]
        # Accept decimal or 0x-prefixed hex for channel/psm.
        if re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", last or ""):
            try:
                ch = int(last, 0)
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

def _bt_host_psm_from_url(parts, qs: Mapping[str, List[str]], o: Mapping[str, Any]) -> Tuple[str, int]:
    """Resolve bdaddr+psm from urlparse parts and query/bind options (for L2CAP)."""
    addr, psm = _split_bt_netloc(getattr(parts, "netloc", "") or "")
    bind = o.get("bind") or _qstr(qs, "bind", None)
    if bind:
        addr = _norm_bt_addr(bind)

    def _int0(v):
        return int(str(v), 0)

    qpsm = _qnum(qs, "psm", None, cast=_int0)
    if qpsm is None:
        qpsm = _qnum(qs, "l2cap_psm", None, cast=_int0)
    if psm is None and qpsm is not None:
        psm = int(qpsm)
    if psm is None:
        # Custom / dynamic PSM start; users should override with ?psm=... when needed.
        psm = 0x1001
    return addr, int(psm)


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

    if proto in ("tcp", "sctp") or proto in _BT_PROTOS or proto in _UNIX_STREAM_SCHEMES or proto in _UNIX_SEQPACKET_SCHEMES:
        is_bt = proto in _BT_PROTOS
        netlab = ("UNIX-SEQ" if _unix_sock_is_seqpacket(proto, kwargs) else ("UNIX" if proto in _UNIX_STREAM_SCHEMES else ("BT" if is_bt else ("SCTP" if proto == "sctp" else "TCP"))))
        is_seqpacket = bool((proto == "sctp") or _unix_sock_is_seqpacket(proto, kwargs) or (is_bt and (proto == "l2cap")))


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
            is_l2cap = (proto == "l2cap")
            if is_l2cap:
                if not _has_l2cap():
                    _emit("Bluetooth L2CAP is not available (missing AF_BLUETOOTH/BTPROTO_L2CAP or PyBluez).",
                          logger=logger, level=logging.ERROR, stream="stderr")
                    return False
                srv = _bt_socket_l2cap_seqpacket()
                if srv is None:
                    _emit("Failed to create Bluetooth L2CAP socket.", logger=logger, level=logging.ERROR, stream="stderr")
                    return False
            else:
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
            bt_port = int(port)
            if (not is_l2cap) and bt_port <= 0:
                bt_port = 1
            # For L2CAP, bt_port is the PSM. A value of 0 can be used to request auto-assignment on bind.
            try:
                srv.bind((bind_addr, int(bt_port)))
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

            chosen_port = bt_port
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
                scheme_out = "l2cap" if is_l2cap else "bt"
                _emit(f"Listening: {scheme_out}://{bind_host}:{int(chosen_port)}{path}",
                      logger=logger, level=logging.INFO, stream="stdout")
                try:
                    sys.stdout.flush()
                except Exception:
                    pass

        else:
            if proto in _UNIX_STREAM_SCHEMES or proto in _UNIX_SEQPACKET_SCHEMES:
                unix_path = kwargs.get("unix_path") or host
                if _unix_sock_is_seqpacket(proto, kwargs):
                    srv = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                    try:
                        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    except Exception:
                        pass
                else:
                    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                _safe_unlink(unix_path)
                srv.bind(unix_path)
                srv.listen(1)

                chosen_port = 0
                if kwargs.get("print_url"):
                    scheme_out = "unixstream" if (proto in _UNIX_STREAM_SCHEMES) else proto
                    extra = ""
                    if _unix_sock_is_seqpacket(proto, kwargs) and proto in _UNIX_STREAM_SCHEMES:
                        extra = "?socktype=seqpacket"
                    _emit(f"Listening: {scheme_out}://{unix_path}{extra}",
                          logger=logger, level=logging.INFO, stream="stdout")
                    try:
                        sys.stdout.flush()
                    except Exception:
                        pass
            else:
                if proto == "sctp":
                    srv = _sctp_listen_socket(host, int(port), backlog=1, reuse=True)
                else:
                    srv = _tcp_listen_socket(host, int(port), backlog=1, reuse=True)
                if srv is None:
                    return False

                chosen_port = srv.getsockname()[1]
                if kwargs.get("print_url"):
                    path = path_text or "/"
                    bind_host = host or ("::" if srv.family == getattr(socket, "AF_INET6", None) else "0.0.0.0")
                    scheme_out = "sctp" if proto == "sctp" else "tcp"
                    for u in _listen_urls(scheme_out, bind_host, chosen_port, path, ""):
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
            _net_log(True, f"{netlab}: waiting accept on ch={port}", logger=logger)

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
            _net_log(True, f"{netlab}: accepted {_addr}", logger=logger)

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
                    line = _recv_line(conn, 4096)
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
                line = _recv_line(conn, 4096)

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
                        _net_log(True, f"{netlab} len: header={header[:16]!r} len={len(header)}",
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
            if proto in _UNIX_STREAM_SCHEMES:
                unix_path = kwargs.get("unix_path") or host
                _safe_unlink(unix_path)

        if ok:
            try:
                fileobj.seek(0, 0)
            except Exception:
                pass
        return ok

    # UDP modes unchanged
    mode = (kwargs.get("mode") or "seq").lower()
    if proto in _UNIX_DGRAM_SCHEMES:
        unix_path = kwargs.get("unix_path") or host
        mode = (kwargs.get("mode") or "raw").lower()
        if mode == "seq":
            return _unix_dgram_seq_recv(fileobj, unix_path, **kwargs)
        if mode == "quic":
            return _unix_dgram_quic_recv(fileobj, unix_path, **kwargs)
        return _unix_dgram_raw_recv(fileobj, unix_path, **kwargs)
    elif mode == "raw":
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

    if proto in ("tcp", "sctp") or proto in _BT_PROTOS or proto in _UNIX_STREAM_SCHEMES or proto in _UNIX_SEQPACKET_SCHEMES:
        is_bt = proto in _BT_PROTOS
        netlab = ("UNIX-SEQ" if _unix_sock_is_seqpacket(proto, kwargs) else ("UNIX" if proto in _UNIX_STREAM_SCHEMES else ("BT" if is_bt else ("SCTP" if proto == "sctp" else "TCP"))))
        is_seqpacket = bool((proto == "sctp") or _unix_sock_is_seqpacket(proto, kwargs) or (is_bt and (proto == "l2cap")))


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
        # BT + len framing: PATH must be disabled (keeps PWG4 header aligned)
        if is_bt and framing == "len":
            kwargs["send_path"] = False

        if is_bt:
            is_l2cap = (proto == "l2cap")
            if is_l2cap:
                if not _has_l2cap():
                    _emit("Bluetooth L2CAP is not available (missing AF_BLUETOOTH/BTPROTO_L2CAP or PyBluez).",
                          logger=logger, level=logging.ERROR, stream="stderr")
                    return False
                sock = _bt_socket_l2cap_seqpacket()
                if sock is None:
                    _emit("Failed to create Bluetooth L2CAP socket.", logger=logger, level=logging.ERROR, stream="stderr")
                    return False
                if int(port) <= 0:
                    _emit("Bluetooth L2CAP send requires a concrete remote PSM (use :psm in URL or ?psm=...).",
                          logger=logger, level=logging.ERROR, stream="stderr")
                    try:
                        sock.close()
                    except Exception:
                        pass
                    return False
            else:
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
            if proto in _UNIX_STREAM_SCHEMES or proto in _UNIX_SEQPACKET_SCHEMES:
                unix_path = kwargs.get("unix_path") or host
                if _unix_sock_is_seqpacket(proto, kwargs):
                    sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                else:
                    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                connect_target = unix_path
            else:
                # TCP: defer socket creation to _tcp_connect_socket (IPv4/IPv6 via getaddrinfo)
                sock = None
                connect_target = (host, int(port))

        # timeout handling
        to = kwargs.get("timeout", None)
        try:
            to = float(to) if to is not None else None
        except Exception:
            to = None
        if to is not None and to <= 0:
            to = None

        if sock is not None and to is not None:
            try:
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

        if sock is None:
            if proto == "sctp":
                sock = _sctp_connect_socket(host, int(port), timeout=to, wait=wait, wait_timeout=wait_timeout,
                                            verbose=kwargs.get("verbose"), logger=logger)
            else:
                sock = _tcp_connect_socket(host, int(port), timeout=to, wait=wait, wait_timeout=wait_timeout,
                                           verbose=kwargs.get("verbose"), logger=logger)
            if sock is None:
                return False
        else:
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
                        _net_log(kwargs.get("verbose"), f"{netlab}: waiting for receiver, retrying...",
                                 logger=logger)
                        time.sleep(0.1)
                    except Exception:
                        pass
                    continue



        if kwargs.get("verbose"):
            _net_log(True, f"SEND {netlab} framing={framing} want_sha={bool(kwargs.get('sha256') or kwargs.get('sha') or kwargs.get('want_sha'))}",
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
                buf = _recv_line(sock, 128)
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
            # For SOCK_SEQPACKET transports (BT L2CAP, SCTP), keep record sizes bounded.
            seq_chunk = kwargs.get("chunk", None)

            if is_bt and (proto == "l2cap"):
                # L2CAP MTU is usually small; default to 1024 and auto-backoff on EMSGSIZE.
                try:
                    seq_chunk = int(seq_chunk) if seq_chunk is not None else 1024
                except Exception:
                    seq_chunk = 1024
                if seq_chunk <= 0:
                    seq_chunk = 1024
            elif proto == "sctp":
                # SCTP can fragment, but keeping message sizes reasonable improves interoperability.
                try:
                    seq_chunk = int(seq_chunk) if seq_chunk is not None else 65536
                except Exception:
                    seq_chunk = 65536
                if seq_chunk <= 0:
                    seq_chunk = 65536

            while True:
                data = fileobj.read(65536)
                if not data:
                    break
                data = _to_bytes(data)
                if is_seqpacket:
                    seq_chunk = _seqpacket_send_chunked(sock, data, seq_chunk or 65536, logger=logger)
                else:
                    sock.sendall(data)
                if h is not None:
                    h.update(data)

            if framing == "len" and want_sha:
                digest = h.digest() if h is not None else b""
                if is_seqpacket:
                    _seqpacket_send_chunked(sock, digest, seq_chunk or 65536, logger=logger)
                else:
                    sock.sendall(digest)
            elif kwargs.get("done"):
                tok = kwargs.get("done_token") or "\nDONE\n"
                btok = _to_bytes(tok)
                if is_seqpacket:
                    _seqpacket_send_chunked(sock, btok, seq_chunk or 65536, logger=logger)
                else:
                    sock.sendall(btok)
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
    if proto in _UNIX_DGRAM_SCHEMES:
        unix_path = kwargs.get("unix_path") or host
        mode = (kwargs.get("mode") or "raw").lower()
        if mode == "seq":
            return _unix_dgram_seq_send(fileobj, unix_path, **kwargs)
        if mode == "quic":
            return _unix_dgram_quic_send(fileobj, unix_path, **kwargs)
        return _unix_dgram_raw_send(fileobj, unix_path, **kwargs)
    elif mode == "raw":
        # your existing raw sender code here (unchanged)
        return _udp_raw_send(fileobj, host, port, **kwargs) if "_udp_raw_send" in globals() else _udp_seq_send(fileobj, host, port, **kwargs)
    elif mode == "quic":
        return _udp_quic_send(fileobj, host, port, **kwargs)
    return _udp_seq_send(fileobj, host, port, **kwargs)

def _unix_dgram_raw_send(fileobj, unix_server_path, **kwargs):
    logger = _logger_from_kwargs(kwargs)

    handshake = _kw_bool(kwargs.get("handshake", True), True)
    raw_ack = _kw_bool(kwargs.get("raw_ack", False), False)
    raw_meta = _kw_bool(kwargs.get("raw_meta", True), True)
    raw_sha = _kw_bool(kwargs.get("raw_sha", False), False)
    wait = _kw_bool(kwargs.get("wait", True), True) or _kw_bool(kwargs.get("connect_wait", False), False)
    verbose = _kw_bool(kwargs.get("verbose", False), False)

    def _log(msg):
        _net_log(verbose, msg, logger=logger)

    try:
        chunk = int(kwargs.get("chunk", 1200))
    except Exception:
        chunk = 1200
    if chunk < 256:
        chunk = 256

    try:
        wt = kwargs.get("wait_timeout", None)
        wt = float(wt) if wt is not None else None
    except Exception:
        wt = None

    try:
        hello_iv = float(kwargs.get("hello_interval", 0.1) or 0.1)
    except Exception:
        hello_iv = 0.1
    if hello_iv <= 0:
        hello_iv = 0.1

    # ---- compute total remaining length (for META and/or HASH) ----
    total_len = None
    pos = None
    if raw_meta or raw_sha:
        try:
            pos = fileobj.tell()
            fileobj.seek(0, os.SEEK_END)
            end = fileobj.tell()
            fileobj.seek(pos, os.SEEK_SET)
            total_len = int(end - pos)
            if total_len < 0:
                total_len = None
        except Exception:
            total_len = None
            try:
                if pos is not None:
                    fileobj.seek(pos, os.SEEK_SET)
            except Exception:
                pass

    # ---- precompute expected hash (optional) ----
    expected_hex = None
    raw_hash = (kwargs.get("raw_hash", "sha256") or "sha256").lower()
    if raw_sha and total_len is not None:
        try:
            h = hashlib.sha256() if raw_hash != "md5" else hashlib.md5()
            cur = fileobj.tell()
            while True:
                b = fileobj.read(65536)
                if not b:
                    break
                h.update(_to_bytes(b))
            expected_hex = h.hexdigest()
            fileobj.seek(cur, os.SEEK_SET)
        except Exception:
            expected_hex = None
            try:
                if pos is not None:
                    fileobj.seek(pos, os.SEEK_SET)
            except Exception:
                pass

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

    # IMPORTANT: client must bind its own path to receive READY/ACK
    client_path = kwargs.get("bind") or kwargs.get("unix_client_path") or _tmp_unix_client_path()
    _safe_unlink(client_path)
    sock.bind(client_path)

    try:
        tok = kwargs.get("token")
        tok = _hs_token() if tok is None else _to_bytes(tok)

        if wait:
            start_t = time.time()
            while True:
                if wt is not None and wt >= 0 and (time.time() - start_t) >= wt:
                    _log("UNIX dgram raw: wait_timeout reached; no receiver READY")
                    return False

                if handshake:
                    try:
                        sock.sendto(b"HELLO " + tok + b"\n", unix_server_path)
                    except Exception:
                        pass

                if raw_meta and total_len is not None:
                    try:
                        sock.sendto(b"META " + str(total_len).encode("ascii") + b"\n", unix_server_path)
                    except Exception:
                        pass

                if raw_sha and expected_hex:
                    try:
                        sock.sendto(
                            b"HASH " + raw_hash.encode("ascii") + b" " + expected_hex.encode("ascii") + b"\n",
                            unix_server_path
                        )
                    except Exception:
                        pass

                try:
                    sock.settimeout(hello_iv)
                except Exception:
                    pass

                try:
                    pkt, _a = sock.recvfrom(1024)
                    if pkt.startswith(b"READY"):
                        if b" " in pkt:
                            rt = pkt.split(None, 1)[1].strip()
                            if rt and rt != tok:
                                continue
                        _log("UNIX dgram raw: received READY from receiver")
                        break
                except socket.timeout:
                    continue
                except Exception:
                    continue
        else:
            # if not waiting, still send META/HASH once up front
            if handshake:
                try:
                    sock.sendto(b"HELLO " + tok + b"\n", unix_server_path)
                except Exception:
                    pass
            if raw_meta and total_len is not None:
                try:
                    sock.sendto(b"META " + str(total_len).encode("ascii") + b"\n", unix_server_path)
                except Exception:
                    pass
            if raw_sha and expected_hex:
                try:
                    sock.sendto(
                        b"HASH " + raw_hash.encode("ascii") + b" " + expected_hex.encode("ascii") + b"\n",
                        unix_server_path
                    )
                except Exception:
                    pass

        # ---- send data ----
        if raw_ack:
            try:
                ack_to = float(kwargs.get("raw_ack_timeout", 0.5) or 0.5)
            except Exception:
                ack_to = 0.5
            try:
                retries_max = int(kwargs.get("raw_ack_retries", 40) or 40)
            except Exception:
                retries_max = 40
            try:
                win = int(kwargs.get("raw_ack_window", 1) or 1)
            except Exception:
                win = 1
            if win < 1:
                win = 1

            try:
                sock.settimeout(ack_to)
            except Exception:
                pass

            def _make_pkt(seq, data):
                return b"PKT " + str(seq).encode("ascii") + b" " + _to_bytes(data)

            base_seq = 0
            next_seq = 0
            pkts = {}
            eof = False
            timeout_tries = 0

            while True:
                # fill window
                while (not eof) and next_seq < base_seq + win:
                    data = fileobj.read(chunk)
                    if not data:
                        eof = True
                        break
                    pkt = _make_pkt(next_seq, data)
                    pkts[next_seq] = pkt
                    try:
                        sock.sendto(pkt, unix_server_path)
                    except Exception:
                        pass
                    next_seq += 1

                if eof and base_seq == next_seq:
                    break

                try:
                    apkt, _a = sock.recvfrom(1024)
                    if apkt.startswith(b"ACK "):
                        try:
                            aseq = int(apkt.split()[1])
                        except Exception:
                            aseq = -1
                        new_base = aseq + 1
                        if new_base > base_seq:
                            for s in list(pkts.keys()):
                                if s < new_base:
                                    pkts.pop(s, None)
                            base_seq = new_base
                            timeout_tries = 0
                except socket.timeout:
                    timeout_tries += 1
                    if retries_max >= 0 and timeout_tries >= retries_max:
                        _log("UNIX dgram raw: too many ACK timeouts, giving up")
                        return False
                    # retransmit all in-flight
                    for s in range(base_seq, next_seq):
                        pkt = pkts.get(s)
                        if pkt is None:
                            continue
                        try:
                            sock.sendto(pkt, unix_server_path)
                        except Exception:
                            pass
                except Exception:
                    timeout_tries += 1

        else:
            # legacy raw: just send datagrams
            while True:
                data = fileobj.read(chunk)
                if not data:
                    break
                try:
                    sock.sendto(_to_bytes(data), unix_server_path)
                except Exception:
                    pass

        # ---- finish ----
        try:
            sock.sendto(b"DONE", unix_server_path)
        except Exception:
            pass

        return True

    finally:
        try:
            sock.close()
        except Exception:
            pass
        _safe_unlink(client_path)

def _unix_dgram_raw_recv(fileobj, unix_server_path, **kwargs):
    logger = _logger_from_kwargs(kwargs)

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        _safe_unlink(unix_server_path)
        sock.bind(unix_server_path)
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        return False

    wait = _kw_bool(kwargs.get("wait", True), True) or _kw_bool(kwargs.get("connect_wait", False), False)
    wait_timeout = kwargs.get("wait_timeout", None)
    try:
        wait_timeout = float(wait_timeout) if wait_timeout is not None else None
    except Exception:
        wait_timeout = None

    raw_ack = _kw_bool(kwargs.get("raw_ack", False), False)
    handshake = _kw_bool(kwargs.get("handshake", True), True)

    want_meta = _kw_bool(kwargs.get("raw_meta", True), True)
    want_hash = _kw_bool(kwargs.get("raw_sha", False), False)
    raw_hash = (kwargs.get("raw_hash", "sha256") or "sha256").lower()

    expected_len = None
    expected_hash_hex = None

    expected_seq = 0
    buffered = {}

    h = None
    if want_hash:
        try:
            h = hashlib.sha256() if raw_hash != "md5" else hashlib.md5()
        except Exception:
            h = None

    got_any = False
    start_t = time.time()
    verbose = _kw_bool(kwargs.get("verbose", False), False)

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
        try:
            sock.settimeout(0.25 if wait else 0.0)
        except Exception:
            pass

        while True:
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

            # HELLO/READY
            if handshake and pkt.startswith(b"HELLO "):
                tok = pkt.split(None, 1)[1].strip()
                _log(f"UNIX dgram raw: got HELLO from {a}")
                _sendto(b"READY " + tok + b"\n", a)
                continue

            # META
            if want_meta and pkt.startswith(b"META "):
                try:
                    expected_len = int(pkt.split(None, 1)[1].strip())
                    _log(f"UNIX dgram raw: got META len={expected_len}")
                except Exception:
                    pass
                continue

            # HASH
            if want_hash and pkt.startswith(b"HASH "):
                try:
                    parts = pkt.strip().split()
                    if len(parts) >= 3:
                        expected_hash_hex = parts[2].decode("ascii", "ignore").lower()
                        _log("UNIX dgram raw: got HASH")
                except Exception:
                    pass
                continue

            # DONE
            if pkt.startswith(b"DONE"):
                _log("UNIX dgram raw: got DONE")
                _try_flush_buffer()

                if expected_len is not None:
                    try:
                        cur = fileobj.tell()
                        ok_len = (int(cur) == int(expected_len))
                    except Exception:
                        ok_len = True
                else:
                    ok_len = True

                ok_hash = True
                if expected_hash_hex and h is not None:
                    try:
                        ok_hash = (h.hexdigest().lower() == expected_hash_hex.lower())
                    except Exception:
                        ok_hash = True

                return bool(ok_len and ok_hash)

            # ACK-framed packets
            if raw_ack and pkt.startswith(b"PKT "):
                try:
                    sp1 = pkt.find(b" ")
                    sp2 = pkt.find(b" ", sp1 + 1)
                    seq = int(pkt[sp1 + 1:sp2])
                    data = pkt[sp2 + 1:]
                except Exception:
                    continue

                _sendto(b"ACK " + str(seq).encode("ascii") + b"\n", a)

                if seq < expected_seq:
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
                    if seq not in buffered:
                        buffered[seq] = data
                continue

            # legacy payload
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
        _safe_unlink(unix_server_path)



def _unix_dgram_wait_for_receiver(sock, unix_server_path, wait_timeout=None, interval=0.1, logger=None, verbose=False):
    """For AF_UNIX datagrams, sendto() typically fails with ENOENT until the server path exists.
    This helper retries a harmless ping until sendto succeeds (or wait_timeout elapses)."""
    try:
        iv = float(interval) if interval is not None else 0.1
    except Exception:
        iv = 0.1
    if iv <= 0:
        iv = 0.1
    try:
        wt = float(wait_timeout) if wait_timeout is not None else None
    except Exception:
        wt = None

    start_t = time.time()
    while True:
        try:
            sock.sendto(b"PING", unix_server_path)
            return True
        except FileNotFoundError:
            pass
        except OSError as e:
            # ENOENT (2) => receiver socket path not present yet
            if getattr(e, "errno", None) != 2:
                pass
        except Exception:
            pass

        if wt is not None and wt >= 0 and (time.time() - start_t) >= wt:
            _net_log(bool(verbose), f"UNIX dgram: wait_timeout reached; receiver not available: {unix_server_path}", logger=logger)
            return False
        try:
            time.sleep(iv)
        except Exception:
            time.sleep(0.05)


def _unix_dgram_seq_send(fileobj, unix_server_path, resume=False, path_text=None, **kwargs):
    logger = _logger_from_kwargs(kwargs)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

    client_path = kwargs.get("bind") or kwargs.get("unix_client_path") or _tmp_unix_client_path()
    _safe_unlink(client_path)
    try:
        sock.bind(client_path)
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        _safe_unlink(client_path)
        return False

    addr = unix_server_path

    # Optional wait-for-receiver (AF_UNIX datagrams error if server socket doesn't exist)
    wait = _kw_bool(kwargs.get("wait", False), False) or _kw_bool(kwargs.get("connect_wait", False), False)
    hello_iv = kwargs.get("hello_interval", 0.1)
    wait_timeout = kwargs.get("wait_timeout", None)
    verbose = _kw_bool(kwargs.get("verbose", False), False)
    if wait:
        if not _unix_dgram_wait_for_receiver(sock, addr, wait_timeout=wait_timeout, interval=hello_iv, logger=logger, verbose=verbose):
            try:
                sock.close()
            except Exception:
                pass
            _safe_unlink(client_path)
            return False

    try:
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
    finally:
        try:
            sock.close()
        except Exception:
            pass
        _safe_unlink(client_path)


def _unix_dgram_seq_recv(fileobj, unix_server_path, **kwargs):
    logger = _logger_from_kwargs(kwargs)
    scheme = (kwargs.get("_scheme") or "unixdgram")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        _safe_unlink(unix_server_path)
        sock.bind(unix_server_path)
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        _safe_unlink(unix_server_path)
        return False

    if kwargs.get("print_url"):
        try:
            _emit("Listening: %s://%s" % (scheme, unix_server_path), logger=logger, level=logging.INFO, stream="stdout")
            sys.stdout.flush()
        except Exception:
            pass

    try:
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

    finally:
        try:
            sock.close()
        except Exception:
            pass
        _safe_unlink(unix_server_path)


def _unix_dgram_quic_send(fileobj, unix_server_path, resume=False, path_text=None, **kwargs):
    logger = _logger_from_kwargs(kwargs)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

    client_path = kwargs.get("bind") or kwargs.get("unix_client_path") or _tmp_unix_client_path()
    _safe_unlink(client_path)
    try:
        sock.bind(client_path)
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        _safe_unlink(client_path)
        return False

    addr = unix_server_path

    wait = _kw_bool(kwargs.get("wait", False), False) or _kw_bool(kwargs.get("connect_wait", False), False)
    hello_iv = kwargs.get("hello_interval", 0.1)
    wait_timeout = kwargs.get("wait_timeout", None)
    verbose = _kw_bool(kwargs.get("verbose", False), False)
    if wait:
        if not _unix_dgram_wait_for_receiver(sock, addr, wait_timeout=wait_timeout, interval=hello_iv, logger=logger, verbose=verbose):
            try:
                sock.close()
            except Exception:
                pass
            _safe_unlink(client_path)
            return False

    try:
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

    finally:
        try:
            sock.close()
        except Exception:
            pass
        _safe_unlink(client_path)


def _unix_dgram_quic_recv(fileobj, unix_server_path, **kwargs):
    logger = _logger_from_kwargs(kwargs)
    scheme = (kwargs.get("_scheme") or "unixdgram")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        _safe_unlink(unix_server_path)
        sock.bind(unix_server_path)
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        _safe_unlink(unix_server_path)
        return False

    if kwargs.get("print_url"):
        try:
            _emit("Listening: %s://%s" % (scheme, unix_server_path), logger=logger, level=logging.INFO, stream="stdout")
            sys.stdout.flush()
        except Exception:
            pass

    try:
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
                        if (token is None) or (not _token_valid(retry_secret, (addr, 0), cid, token)):
                            tok = _retry_token(retry_secret, (addr, 0), cid)
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


    finally:
        try:
            sock.close()
        except Exception:
            pass
        _safe_unlink(unix_server_path)


def _udp_raw_recv(fileobj, host, port, **kwargs):
    logger = _logger_from_kwargs(kwargs)
    addr = (host or "", int(port))
    # Bind to all interfaces unless user explicitly gave a concrete local bind
    bind_host = host if host not in (None, "", "127.0.0.1", "::1") else ""
    sock = _udp_bind_socket(bind_host, int(port))
    if sock is None:
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
    sock, addr = _udp_socket_and_addr(host, port)

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
    logger = _logger_from_kwargs(kwargs)
    sock = _udp_bind_socket(host or "", int(port))
    if sock is None:
        return False

    if kwargs.get("print_url"):
        bh = host or ("::" if sock.family == getattr(socket, "AF_INET6", None) else "0.0.0.0")
        _emit("Listening: udp://%s:%d/" % (_url_host(bh), sock.getsockname()[1]), logger=logger, level=logging.INFO, stream="stdout")
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
    sock, addr = _udp_socket_and_addr(host, port)

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
    logger = _logger_from_kwargs(kwargs)
    sock = _udp_bind_socket(host or "", int(port))
    if sock is None:
        return False

    if kwargs.get("print_url"):
        bh = host or ("::" if sock.family == getattr(socket, "AF_INET6", None) else "0.0.0.0")
        _emit("Listening: udp://%s:%d/" % (_url_host(bh), sock.getsockname()[1]), logger=logger, level=logging.INFO, stream="stdout")
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

    if p.scheme in ("tcp", "udp", "sctp") or p.scheme in _BT_URL_SCHEMES or p.scheme in _UNIX_SCHEMES:
        parts, o = _parse_net_url(url)
        path_text = parts.path or "/"
        if parts.scheme in _BT_RFCOMM_SCHEMES:
            qs = parse_qs(parts.query or "")
            host, port = _bt_host_channel_from_url(parts, qs, o)
            proto = "bt"

        elif parts.scheme in _BT_L2CAP_SCHEMES:
            qs = parse_qs(parts.query or "")
            host, port = _bt_host_psm_from_url(parts, qs, o)
            proto = "l2cap"

        elif parts.scheme in _UNIX_SCHEMES:
            host = _unix_path_from_parts(parts, o, fallback_port=0)  # store path in host
            port = 0
            proto = parts.scheme

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
            print_url=o.get("print_url"), resume_offset=resume_off, path_text=path_text,
            framing=o.get("framing"), handshake=o.get("handshake"), send_path=o.get("send_path"),
            unix_path=o.get("unix_path"),
            bind=o.get("bind"),
            logger=kwargs.get("logger"),
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
      - l2cap://BDADDR:psm/... (L2CAP)

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

    if p.scheme in ("tcp", "udp", "sctp") or p.scheme in _BT_URL_SCHEMES or p.scheme in _UNIX_SCHEMES:
        parts, o = _parse_net_url(url)
        path_text = parts.path or "/"

        if parts.scheme in _BT_RFCOMM_SCHEMES:
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

        elif parts.scheme in _BT_L2CAP_SCHEMES:
            qs = parse_qs(parts.query or "")
            o2 = dict(o)
            # For sending (client), never treat bind= as the remote host.
            o2["bind"] = None
            host, port = _bt_host_psm_from_url(parts, qs, o2)
            proto = "l2cap"
            send_path = _qflag(qs, "send_path", False) or bool(o.get("send_path"))
            if not send_path:
                path_text = None
        elif parts.scheme in _UNIX_SCHEMES:
            host = _unix_path_from_parts(parts, o, fallback_port=0)  # store path in host
            port = 0
            proto = parts.scheme
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
            wait_timeout=(_resolve_wait_timeout(parts.scheme, o.get("mode"), o) if parts.scheme in ("udp", "tcp", "sctp") else o.get("timeout")),
            window=o.get("window"), retries=o.get("retries"), chunk=o.get("chunk"),
            resume=o.get("resume"), path_text=path_text,
            done=o.get("done"), done_token=o.get("done_token"), framing=o.get("framing"), sha256=o.get("sha256"),
            unix_path=o.get("unix_path"),
            bind=o.get("bind"),
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
