#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""catfile.py (Python 3 only)

This script is part of the catfile/pycatfile project.

This refactor removes Python 2 compatibility code paths while preserving the
original CLI behavior and wiring into `pycatfile`.
"""

import argparse
import binascii
import logging
import os
import sys
from io import BytesIO, StringIO  # noqa: F401  (kept for parity with original)

import pycatfile_py3 as pycatfile

# Text streams (as provided by Python)
PY_STDIN_TEXT = sys.stdin
PY_STDOUT_TEXT = sys.stdout
PY_STDERR_TEXT = sys.stderr

# Binary-friendly streams (.buffer exists on Python 3 text streams)
PY_STDIN_BUF = sys.stdin.buffer
PY_STDOUT_BUF = sys.stdout.buffer
PY_STDERR_BUF = sys.stderr.buffer

# Keep original behavior: log to stdout with simple message format.
logging.basicConfig(format="%(message)s", stream=PY_STDOUT_TEXT, level=logging.DEBUG)

# Unix SIGPIPE handling (matches original intent: exit cleanly on broken pipe)
if os.name != "nt":
    import signal

    if hasattr(signal, "SIGPIPE"):

        def _sigpipe_handler(signum, frame):
            pycatfile.VerbosePrintOut("Received SIGPIPE, exiting gracefully.", "info")
            raise SystemExit(0)

        signal.signal(signal.SIGPIPE, _sigpipe_handler)

# Feature flags (re-exported from module; kept for CLI parity)
rarfile_support = pycatfile.rarfile_support
py7zr_support = pycatfile.py7zr_support

# Re-export metadata/constants from `pycatfile` (kept for --version, defaults, etc.)
__project__ = pycatfile.__project__
__program_name__ = pycatfile.__program_name__
__file_format_name__ = pycatfile.__file_format_name__
__file_format_magic__ = pycatfile.__file_format_magic__
__file_format_len__ = pycatfile.__file_format_len__
__file_format_hex__ = pycatfile.__file_format_hex__
__file_format_delimiter__ = pycatfile.__file_format_delimiter__
__file_format_dict__ = pycatfile.__file_format_dict__
__file_format_default__ = pycatfile.__file_format_default__
__file_format_multi_dict__ = pycatfile.__file_format_multi_dict__
__use_new_style__ = pycatfile.__use_new_style__
__use_advanced_list__ = pycatfile.__use_advanced_list__
__use_alt_inode__ = pycatfile.__use_alt_inode__
__project_url__ = pycatfile.__project_url__
__version_info__ = pycatfile.__version_info__
__version_date_info__ = pycatfile.__version_date_info__
__version_date__ = pycatfile.__version_date__
__version_date_plusrc__ = pycatfile.__version_date_plusrc__
__version__ = pycatfile.__version__


def _build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Manipulate archive files.",
        conflict_handler="resolve",
        add_help=True,
    )

    # Version information
    p.add_argument("-V", "--version", action="version", version=f"{__program_name__} {__version__}")

    # Input and output specifications
    p.add_argument(
        "-i",
        "--input",
        nargs="+",
        help="Specify the file(s) to concatenate or the archive file to extract.",
        required=True,
    )
    p.add_argument("-o", "--output", default=None, help="Specify the name for the extracted or output archive files.")

    # Operations
    p.add_argument("-c", "--create", action="store_true", help="Perform only the concatenation operation.")
    p.add_argument("-e", "--extract", action="store_true", help="Perform only the extraction operation.")
    p.add_argument("-t", "--convert", action="store_true", help="Convert a tar/zip/rar/7zip file to a archive file.")
    p.add_argument("-r", "--repack", action="store_true", help="Re-concatenate files, fixing checksum errors if any.")
    p.add_argument("-S", "--filestart", type=int, default=0, help="Start reading file at.")

    # File manipulation options
    p.add_argument("-F", "--format", default="auto", help="Specify the format to use.")
    p.add_argument(
        "-D",
        "--delimiter",
        default=__file_format_dict__["format_delimiter"],
        help="Specify the delimiter to use.",
    )
    p.add_argument("-m", "--formatver", default=__file_format_dict__["format_ver"], help="Specify the format version.")
    p.add_argument("-l", "--list", action="store_true", help="List files included in the archive file.")

    # Compression options
    p.add_argument("-P", "--compression", default="auto", help="Specify the compression method to use for concatenation.")
    p.add_argument("-L", "--level", default=None, help="Specify the compression level for concatenation.")
    p.add_argument("-W", "--wholefile", action="store_true", help="Whole file compression method to use for concatenation.")

    # Checksum and validation
    p.add_argument("-v", "--validate", action="store_true", help="Validate archive file checksums.")
    p.add_argument("-C", "--checksum", default="md5", help="Specify the type of checksum to use. The default is md5.")
    p.add_argument("-s", "--skipchecksum", action="store_true", help="Skip the checksum check of files.")
    p.add_argument("-k", "--insecretkey", default=None, help="Secretkey to use for checksum input.")
    p.add_argument("-K", "--outsecretkey", default=None, help="Secretkey to use for checksum output.")

    # Permissions and metadata
    p.add_argument("-p", "--preserve", action="store_false", help="Do not preserve permissions and timestamps of files.")

    # Miscellaneous
    p.add_argument("-d", "--verbose", action="store_true", help="Enable verbose mode to display various debugging information.")
    p.add_argument("-T", "--text", action="store_true", help="Read file locations from a text file.")

    return p


def _resolve_format(getargs):
    """Compute the format dict exactly as the original script did."""
    global __file_format_default__  # keep parity with original module-level behavior

    fname = getargs.format
    if fname == "auto":
        fnamedict = __file_format_multi_dict__
        __file_format_default__ = getargs.format
    else:
        fnamemagic = fname
        fnamelen = len(fname)
        fnamehex = binascii.hexlify(fname.encode("utf-8")).decode("utf-8")
        __file_format_default__ = fnamemagic
        fnamesty = __use_new_style__
        fnamelst = __use_advanced_list__
        fnameino = __use_alt_inode__
        fnamedict = {
            "format_name": fname,
            "format_magic": fnamemagic,
            "format_len": fnamelen,
            "format_hex": fnamehex,
            "format_delimiter": getargs.delimiter,
            "format_ver": getargs.formatver,
            "new_style": fnamesty,
            "use_advanced_list": fnamelst,
            "use_alt_inode": fnameino,
        }
    return fnamedict


def main(argv=None) -> int:
    argparser = _build_argparser()
    getargs = argparser.parse_args(argv)

    fnamedict = _resolve_format(getargs)

    # Determine the primary action based on user input (same order/behavior as original)
    actions = ("create", "extract", "list", "repack", "validate")
    active_action = next((a for a in actions if getattr(getargs, a)), None)

    input_file = getargs.input[0]

    if not active_action:
        # Preserve original behavior: do nothing if no action flag is set.
        return 0

    # Execute the appropriate functions based on determined actions and arguments
    if active_action == "create":
        if getargs.convert:
            checkcompressfile = pycatfile.CheckCompressionSubType(input_file, fnamedict, 0, True)
            if (
                (pycatfile.IsNestedDict(fnamedict) and checkcompressfile in fnamedict)
                or (pycatfile.IsSingleDict(fnamedict) and checkcompressfile == fnamedict["format_magic"])
            ):
                tmpout = pycatfile.RePackCatFile(
                    input_file,
                    getargs.output,
                    "auto",
                    getargs.compression,
                    getargs.wholefile,
                    getargs.level,
                    pycatfile.compressionlistalt,
                    False,
                    0,
                    0,
                    0,
                    [getargs.checksum] * 5,
                    getargs.skipchecksum,
                    [],
                    {},
                    fnamedict,
                    getargs.insecretkey,
                    getargs.outsecretkey,
                    False,
                    getargs.verbose,
                    False,
                )
            else:
                tmpout = pycatfile.PackCatFileFromInFile(
                    input_file,
                    getargs.output,
                    __file_format_default__,
                    getargs.compression,
                    getargs.wholefile,
                    getargs.level,
                    pycatfile.compressionlistalt,
                    [getargs.checksum] * 5,
                    [],
                    {},
                    fnamedict,
                    getargs.outsecretkey,
                    getargs.verbose,
                    False,
                )
            if not tmpout:
                return 1
        else:
            pycatfile.PackCatFile(
                getargs.input,
                getargs.output,
                getargs.text,
                __file_format_default__,
                getargs.compression,
                getargs.wholefile,
                getargs.level,
                pycatfile.compressionlistalt,
                False,
                [getargs.checksum] * 5,
                [],
                {},
                fnamedict,
                getargs.outsecretkey,
                getargs.verbose,
                False,
            )

    elif active_action == "repack":
        if getargs.convert:
            checkcompressfile = pycatfile.CheckCompressionSubType(input_file, fnamedict, 0, True)
            if (
                (pycatfile.IsNestedDict(fnamedict) and checkcompressfile in fnamedict)
                or (pycatfile.IsSingleDict(fnamedict) and checkcompressfile == fnamedict["format_magic"])
            ):
                # NOTE: original script forgot to store the return value (tmpout) here.
                tmpout = pycatfile.RePackCatFile(
                    input_file,
                    getargs.output,
                    "auto",
                    getargs.compression,
                    getargs.wholefile,
                    getargs.level,
                    pycatfile.compressionlistalt,
                    False,
                    0,
                    0,
                    0,
                    [getargs.checksum] * 5,
                    getargs.skipchecksum,
                    [],
                    {},
                    fnamedict,
                    getargs.insecretkey,
                    getargs.outsecretkey,
                    False,
                    getargs.verbose,
                    False,
                )
            else:
                tmpout = pycatfile.PackCatFileFromInFile(
                    input_file,
                    getargs.output,
                    __file_format_default__,
                    getargs.compression,
                    getargs.wholefile,
                    getargs.level,
                    pycatfile.compressionlistalt,
                    [getargs.checksum] * 5,
                    [],
                    {},
                    fnamedict,
                    getargs.outsecretkey,
                    getargs.verbose,
                    False,
                )
            if not tmpout:
                return 1
        else:
            pycatfile.RePackCatFile(
                input_file,
                getargs.output,
                "auto",
                getargs.compression,
                getargs.wholefile,
                getargs.level,
                pycatfile.compressionlistalt,
                False,
                getargs.filestart,
                0,
                0,
                [getargs.checksum] * 5,
                getargs.skipchecksum,
                [],
                {},
                fnamedict,
                getargs.insecretkey,
                getargs.outsecretkey,
                False,
                getargs.verbose,
                False,
            )

    elif active_action == "extract":
        if getargs.convert:
            checkcompressfile = pycatfile.CheckCompressionSubType(input_file, fnamedict, 0, True)
            tempout = BytesIO()
            if (
                (pycatfile.IsNestedDict(fnamedict) and checkcompressfile in fnamedict)
                or (pycatfile.IsSingleDict(fnamedict) and checkcompressfile == fnamedict["format_magic"])
            ):
                tmpout = pycatfile.RePackCatFile(
                    input_file,
                    tempout,
                    "auto",
                    getargs.compression,
                    getargs.wholefile,
                    getargs.level,
                    pycatfile.compressionlistalt,
                    False,
                    0,
                    0,
                    0,
                    [getargs.checksum] * 5,
                    getargs.skipchecksum,
                    [],
                    {},
                    fnamedict,
                    getargs.insecretkey,
                    getargs.outsecretkey,
                    False,
                    False,
                )
            else:
                tmpout = pycatfile.PackCatFileFromInFile(
                    input_file,
                    tempout,
                    __file_format_default__,
                    getargs.compression,
                    getargs.wholefile,
                    getargs.level,
                    pycatfile.compressionlistalt,
                    [getargs.checksum] * 5,
                    [],
                    {},
                    fnamedict,
                    getargs.outsecretkey,
                    False,
                    False,
                )
            if not tmpout:
                return 1
            input_file = tempout

        pycatfile.UnPackCatFile(
            input_file,
            getargs.output,
            False,
            getargs.filestart,
            0,
            0,
            getargs.skipchecksum,
            fnamedict,
            getargs.verbose,
            getargs.preserve,
            getargs.preserve,
            False,
            False,
        )

    elif active_action == "list":
        if getargs.convert:
            checkcompressfile = pycatfile.CheckCompressionSubType(input_file, fnamedict, 0, True)
            if (
                (pycatfile.IsNestedDict(fnamedict) and checkcompressfile in fnamedict)
                or (pycatfile.IsSingleDict(fnamedict) and checkcompressfile == fnamedict["format_magic"])
            ):
                tmpout = pycatfile.CatFileListFiles(
                    input_file,
                    "auto",
                    getargs.filestart,
                    0,
                    0,
                    getargs.skipchecksum,
                    fnamedict,
                    getargs.insecretkey,
                    False,
                    getargs.verbose,
                    False,
                    False,
                )
            else:
                tmpout = pycatfile.InFileListFiles(
                    input_file,
                    getargs.verbose,
                    fnamedict,
                    getargs.insecretkey,
                    False,
                    False,
                    False,
                )
            if not tmpout:
                return 1
        else:
            pycatfile.CatFileListFiles(
                input_file,
                "auto",
                getargs.filestart,
                0,
                0,
                getargs.skipchecksum,
                fnamedict,
                getargs.insecretkey,
                False,
                getargs.verbose,
                False,
                False,
            )

    elif active_action == "validate":
        if getargs.convert:
            checkcompressfile = pycatfile.CheckCompressionSubType(input_file, fnamedict, 0, True)
            tempout = BytesIO()
            if (
                (pycatfile.IsNestedDict(fnamedict) and checkcompressfile in fnamedict)
                or (pycatfile.IsSingleDict(fnamedict) and checkcompressfile == fnamedict["format_magic"])
            ):
                tmpout = pycatfile.RePackCatFile(
                    input_file,
                    tempout,
                    "auto",
                    getargs.compression,
                    getargs.wholefile,
                    getargs.level,
                    pycatfile.compressionlistalt,
                    False,
                    0,
                    0,
                    0,
                    [getargs.checksum] * 5,
                    getargs.skipchecksum,
                    [],
                    {},
                    fnamedict,
                    getargs.insecretkey,
                    getargs.outsecretkey,
                    False,
                    False,
                    False,
                )
            else:
                tmpout = pycatfile.PackCatFileFromInFile(
                    input_file,
                    tempout,
                    __file_format_default__,
                    getargs.compression,
                    getargs.wholefile,
                    getargs.level,
                    pycatfile.compressionlistalt,
                    [getargs.checksum] * 5,
                    [],
                    {},
                    fnamedict,
                    getargs.outsecretkey,
                    False,
                    False,
                )

            input_file = tempout
            if not tmpout:
                return 1

        fvalid = pycatfile.StackedCatFileValidate(
            input_file,
            "auto",
            getargs.filestart,
            fnamedict,
            getargs.insecretkey,
            False,
            getargs.verbose,
            False,
        )
        if fvalid:
            pycatfile.VerbosePrintOut("File is valid: \n" + str(input_file))
        else:
            pycatfile.VerbosePrintOut("File is invalid: \n" + str(input_file))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
