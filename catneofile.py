#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function, unicode_literals

import sys, os, io, argparse

try:
    import pycatfile as P  # core must provide *_neo functions
except Exception as e:
    sys.stderr.write("Failed to import core module 'pycatfile': %s\n" % (e,))
    sys.exit(2)


def _expand_combined_short_opts(argv):
    out = [argv[0]]
    i = 1
    while i < len(argv):
        a = argv[i]
        if a.startswith("--") or not (a.startswith("-") and len(a) > 2):
            out.append(a); i += 1; continue
        for ch in a[1:]:
            out.append("-" + ch)
        i += 1
    return out


def main():
    argv = _expand_combined_short_opts(sys.argv)

    p = argparse.ArgumentParser(
        description="PyNeoFile CLI (uses pycatfile core)")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("-l", "--list", action="store_true", help="List archive")
    g.add_argument("-e", "--extract", action="store_true", help="Extract archive")
    g.add_argument("-c", "--create", action="store_true", help="Create archive from path")
    g.add_argument("-r", "--repack", action="store_true", help="Repack (recompress) an archive")
    g.add_argument("-E", "--empty", action="store_true", help="Create an empty archive")

    p.add_argument("-i", "--input", help="Input file/path", nargs="*")
    p.add_argument("-o", "--output", help="Output file/dir (or '-' for stdout)")
    p.add_argument("-d", "--verbose", action="store_true", help="Verbose/detailed listing")
    p.add_argument("-P", "--compression", default="auto", help="Compression algo (auto, none, zlib, gzip, bz2, lzma)")
    p.add_argument("-L", "--level", type=int, default=None, help="Compression level/preset")
    p.add_argument("--checksum", default="crc32", help="Checksum type for header/content/json (default: crc32)")

    args = p.parse_args(argv[1:])

    src = None
    if args.input:
        if isinstance(args.input, list) and len(args.input) == 1:
            src = args.input[0]
        elif isinstance(args.input, list) and len(args.input) > 1:
            src = args.input[0]
        else:
            src = args.input

    if args.empty:
        dst = args.output or "-"
        blob_or_true = P.make_empty_file_neo(dst, fmttype="auto", checksumtype=args.checksum, encoding="UTF-8", returnfp=False)
        if dst in (None, "-"):
            data = blob_or_true if isinstance(blob_or_true, (bytes, bytearray)) else b""
            if hasattr(sys.stdout, "buffer"):
                sys.stdout.buffer.write(data)
            else:
                sys.stdout.write(data.decode("latin1"))
        return 0

    if args.list:
        if not src:
            p.error("list requires -i <archive>")
        P.archivefilelistfiles_neo(src, advanced=args.verbose, include_dirs=True)
        return 0

    if args.extract:
        if not src:
            p.error("extract requires -i <archive>")
        outdir = args.output or "."
        ok = P.unpack_neo(src, outdir, skipchecksum=False, uncompress=True)
        return 0 if ok else 1

    if args.create:
        if not src:
            p.error("create requires -i <path>")
        if args.verbose:
            walkroot = src
            if os.path.isdir(walkroot):
                print(walkroot)
                for root, dirs, files in os.walk(walkroot):
                    relroot = root if root.startswith("./") else "./" + root.replace("\\", "/")
                    if root != walkroot:
                        print(relroot)
                    for name in sorted(files):
                        path = os.path.join(root, name).replace("\\", "/")
                        if not path.startswith("./"):
                            path = "./" + path
                        print(path)
            else:
                path = src if src.startswith("./") else "./" + src
                print(path)

        outpath = args.output or "-"
        ok = P.pack_neo(src, outpath, checksumtypes=(args.checksum,args.checksum,args.checksum,args.checksum),
                        encoding="UTF-8", compression=args.compression, compression_level=args.level)
        if outpath in (None, "-") and isinstance(ok, (bytes, bytearray)):
            if hasattr(sys.stdout, "buffer"):
                sys.stdout.buffer.write(ok)
            else:
                sys.stdout.write(ok.decode("latin1"))
            return 0
        return 0 if ok else 1

    if args.repack:
        if not src:
            p.error("repack requires -i <archive>")
        outpath = args.output or "-"
        ok = P.repack_neo(src, outpath, checksumtypes=(args.checksum,args.checksum,args.checksum,args.checksum),
                          compression=args.compression, compression_level=args.level)
        if outpath in (None, "-") and isinstance(ok, (bytes, bytearray)):
            if hasattr(sys.stdout, "buffer"):
                sys.stdout.buffer.write(ok)
            else:
                sys.stdout.write(ok.decode("latin1"))
            return 0
        return 0 if ok else 1

    return 0


if __name__ == "__main__":
    sys.exit(main())