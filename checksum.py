#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
    This program is free software; you can redistribute it and/or modify
    it under the terms of the Revised BSD License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Revised BSD License for more details.

    Copyright 2018-2022 Cool Dude 2k - http://idb.berlios.de/
    Copyright 2018-2022 Game Maker 2k - http://intdb.sourceforge.net/
    Copyright 2018-2022 Kazuki Przyborowski - https://github.com/KazukiPrzyborowski

    $FileInfo: checksum.py - Last Update: 10/17/2022 Ver. 0.0.1 RC 1 - Author: cooldude2k $
'''

from __future__ import absolute_import, division, print_function, unicode_literals;
import os, binascii, argparse, shutil, hashlib, zlib;
from io import open as open;

chksum_list = sorted(['adler32', 'crc16', 'crc32']);
chksum_list_hash = sorted(list(hashlib.algorithms_guaranteed));

def crc16(msg):
 # CRC-16-IBM / CRC-16-ANSI polynomial and initial value
 poly = 0x8005;  # Polynomial for CRC-16-IBM / CRC-16-ANSI
 crc = 0xFFFF;  # Initial value
 for b in msg:
  crc ^= b << 8;  # XOR byte into CRC top byte
  for _ in range(8):  # Process each bit
   if crc & 0x8000:  # If the top bit is set
    crc = (crc << 1) ^ poly;  # Shift left and XOR with the polynomial
   else:
    crc = crc << 1;  # Just shift left
   crc &= 0xFFFF;  # Ensure CRC remains 16-bit
 return crc;

def crc64_ecma(msg):
 # CRC-64-ECMA polynomial and initial value
 poly = 0x42F0E1EBA9EA3693;
 crc = 0x0000000000000000;  # Initial value for CRC-64-ECMA
 for b in msg:
  crc ^= b << 56;  # XOR byte into the most significant byte of the CRC
  for _ in range(8):  # Process each bit
   if crc & (1 << 63):  # Check if the leftmost (most significant) bit is set
    crc = (crc << 1) ^ poly;  # Shift left and XOR with poly if the MSB is 1
   else:
    crc <<= 1;  # Just shift left if the MSB is 0
   crc &= 0xFFFFFFFFFFFFFFFF;  # Ensure CRC remains 64-bit
 return crc;

def crc64_iso(msg):
 # CRC-64-ISO polynomial and initial value
 poly = 0x000000000000001B;
 crc = 0xFFFFFFFFFFFFFFFF;  # Common initial value for CRC-64-ISO
 for b in msg:
  crc ^= b << 56;  # XOR byte into the most significant byte of the CRC
  for _ in range(8):  # Process each bit
   if crc & (1 << 63):  # Check if the leftmost (most significant) bit is set
    crc = (crc << 1) ^ poly;  # Shift left and XOR with poly if the MSB is 1
   else:
    crc <<= 1;  # Just shift left if the MSB is 0
   crc &= 0xFFFFFFFFFFFFFFFF;  # Ensure CRC remains 64-bit
 return crc;

def crc16_file(infile):
 if(not os.path.exists(infile) or not os.path.isfile(infile)):
  return False;
 filefp = open(infile, "rb");
 checksum = format(crc16(filefp.read()) & 0xffff, '04x').lower();
 filefp.close();
 return checksum;

def adler32_file(infile):
 if(not os.path.exists(infile) or not os.path.isfile(infile)):
  return False;
 filefp = open(infile, "rb");
 checksum = format(zlib.adler32(filefp.read()) & 0xffffffff, '08x').lower();
 filefp.close();
 return checksum;

def crc32_file(infile):
 if(not os.path.exists(infile) or not os.path.isfile(infile)):
  return False;
 filefp = open(infile, "rb");
 checksum = format(zlib.crc32(filefp.read()) & 0xffffffff, '08x').lower();
 filefp.close();
 return checksum;

def crc64_ecma_file(infile):
 if(not os.path.exists(infile) or not os.path.isfile(infile)):
  return False;
 filefp = open(infile, "rb");
 checksum = format(crc64_ecma(filefp.read()) & 0xffffffffffffffff, '016x').lower();
 filefp.close();
 return checksum;

def crc64_iso_file(infile):
 if(not os.path.exists(infile) or not os.path.isfile(infile)):
  return False;
 filefp = open(infile, "rb");
 checksum = format(crc64_iso(filefp.read()) & 0xffffffffffffffff, '016x').lower();
 filefp.close();
 return checksum;

def hash_file(infile, checksumtype):
 if(checksumtype not in chksum_list_hash):
  return False;
 if(not os.path.exists(infile) or not os.path.isfile(infile)):
  return False;
 filefp = open(infile, "rb");
 checksumoutstr = hashlib.new(checksumtype);
 checksumoutstr.update(filefp.read());
 checksum = checksumoutstr.hexdigest().lower();
 filefp.close();
 return checksum;

if __name__ == "__main__":
 argparser = argparse.ArgumentParser(description="Get File Checksum", conflict_handler="resolve", add_help=True);
 argparser.add_argument("-V", "--version", action="version", version="PyChecksum 0.0.1");
 argparser.add_argument("-i", "-f", "--input", help="Files to checksum", required=True);
 argparser.add_argument("-c", "-checksum", "--checksum", default="auto", help="Checksum to use", required=True);
 argparser.add_argument("-q", "--quiet", action="store_true", help="Print only checksum");
 getargs = argparser.parse_args();
 if(getargs.checksum not in chksum_list + chksum_list_hash):
  exit();
 if(getargs.checksum in chksum_list):
  if(getargs.checksum=="crc16"):
   outchck = crc16_file(getargs.input);
   if(not outchck):
    exit();
   if(not getargs.quiet):
    print(str(outchck)+" *"+getargs.input);
   else:
    print(str(outchck));
  if(getargs.checksum=="crc32"):
   outchck = crc32_file(getargs.input);
   if(not outchck):
    exit();
   if(not getargs.quiet):
    print(str(outchck)+" *"+getargs.input);
   else:
    print(str(outchck));
  if(getargs.checksum=="adler32"):
   outchck = adler32_file(getargs.input);
   if(not outchck):
    exit();
   if(not getargs.quiet):
    print(str(outchck)+" *"+getargs.input);
   else:
    print(str(outchck));
  if(getargs.checksum=="crc64_ecma"):
   outchck = crc64_ecma_file(getargs.input);
   if(not outchck):
    exit();
   if(not getargs.quiet):
    print(str(outchck)+" *"+getargs.input);
   else:
    print(str(outchck));
  if(getargs.checksum=="crc64_iso"):
   outchck = crc64_iso_file(getargs.input);
   if(not outchck):
    exit();
   if(not getargs.quiet):
    print(str(outchck)+" *"+getargs.input);
   else:
    print(str(outchck));
 if(getargs.checksum in chksum_list_hash):
  outchck = hash_file(getargs.input, getargs.checksum);
  if(not outchck):
   exit();
  if(not getargs.quiet):
   print(str(outchck)+" *"+getargs.input);
  else:
   print(str(outchck));
