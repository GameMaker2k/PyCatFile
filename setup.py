#!/usr/bin/env python

'''
    This program is free software; you can redistribute it and/or modify
    it under the terms of the Revised BSD License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Revised BSD License for more details.

    Copyright 2016-2024 Cool Dude 2k - http://idb.berlios.de/
    Copyright 2016-2024 Game Maker 2k - http://intdb.sourceforge.net/
    Copyright 2016-2024 Kazuki Przyborowski - https://github.com/KazukiPrzyborowski

    $FileInfo: setup.py - Last Update: 8/26/2025 Ver. 0.21.4 RC 1 - Author: cooldude2k $
'''

import os
import re
import sys
from setuptools import setup

# Open and read the version info file in a Python 2/3 compatible way
verinfofilename = os.path.realpath("."+os.path.sep+os.path.sep+"pycatfile.py")

# Use `with` to ensure the file is properly closed after reading
# In Python 2, open defaults to text mode; in Python 3, it’s better to specify encoding
open_kwargs = {'encoding': 'utf-8'} if sys.version_info[0] >= 3 else {}
with open(verinfofilename, "r", **open_kwargs) as verinfofile:
    verinfodata = verinfofile.read()

# Define the regex pattern for extracting version info
# We ensure the pattern works correctly in both Python 2 and 3 by escaping the strings properly
version_pattern = "__version_info__ = \(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*['\"]([\w\s]+)['\"]\s*,\s*(\d+)\s*\)"
setuppy_verinfo = re.findall(version_pattern, verinfodata)[0]

# If version info is found, process it; handle the case where no match is found
if setuppy_verinfo:
    setuppy_verinfo_exp = setuppy_verinfo
else:
    print("Version info not found.")
    setuppy_verinfo_exp = None  # Handle missing version info gracefully

# Define the regex pattern for extracting version date info
date_pattern = "__version_date_info__ = \(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*['\"]([\w\s]+)['\"]\s*,\s*(\d+)\s*\)"
setuppy_dateinfo = re.findall(date_pattern, verinfodata)[0]

# If date info is found, process it; handle the case where no match is found
if setuppy_dateinfo:
    setuppy_dateinfo_exp = setuppy_dateinfo
else:
    print("Date info not found.")
    setuppy_dateinfo_exp = None  # Handle missing date info gracefully

pymodule = {}
pymodule['version'] = str(setuppy_verinfo_exp[0])+"." + \
    str(setuppy_verinfo_exp[1])+"."+str(setuppy_verinfo_exp[2])
pymodule['versionrc'] = int(setuppy_verinfo_exp[4])
pymodule['versionlist'] = (int(setuppy_verinfo_exp[0]), int(setuppy_verinfo_exp[1]), int(
    setuppy_verinfo_exp[2]), str(setuppy_verinfo_exp[3]), int(setuppy_verinfo_exp[4]))
pymodule['verdate'] = str(setuppy_dateinfo_exp[0])+"." + \
    str(setuppy_dateinfo_exp[1])+"."+str(setuppy_dateinfo_exp[2])
pymodule['verdaterc'] = int(setuppy_dateinfo_exp[4])
pymodule['verdatelist'] = (int(setuppy_dateinfo_exp[0]), int(setuppy_dateinfo_exp[1]), int(
    setuppy_dateinfo_exp[2]), str(setuppy_dateinfo_exp[3]), int(setuppy_dateinfo_exp[4]))
pymodule['name'] = 'PyCatFile'
pymodule['author'] = 'Kazuhana Neko-chan'
pymodule['authoremail'] = 'kazuki.suzuki.cat@gmail.com'
pymodule['maintainer'] = 'Kazuhika Kitsune-chan'
pymodule['maintaineremail'] = 'kazuki.suzuki.fox@gmail.com'
pymodule['description'] = 'A tar like file format name catfile after unix cat command (concatenate files) .'
pymodule['license'] = 'Revised BSD License'
pymodule['keywords'] = 'cat catfile cat-archive catfile-archive pycatfile python python-catfile neko nekofile neko-archive nekofile-archive pynekofile python python-nekofile compression tarball gzip tar bzip2 tar-archive lzma xz gz lzma2 xz2 tarlike tarlite hairball'
pymodule['url'] = 'https://github.com/GameMaker2k/PyCatFile'
pymodule['downloadurl'] = 'https://github.com/GameMaker2k/PyCatFile/archive/master.tar.gz'
pymodule[
    'longdescription'] = 'A tar like file format name catfile after unix cat command (concatenate files) .'
pymodule['platforms'] = 'OS Independent'
pymodule['zipsafe'] = True
pymodule['pymodules'] = ['pycatfile']
pymodule['scripts'] = ['catfile.py']
pymodule['classifiers'] = [
    'Development Status :: 5 - Production/Stable',
    'Intended Audience :: Developers',
    'Intended Audience :: Other Audience',
    'License :: OSI Approved',
    'License :: OSI Approved :: BSD License',
    'Natural Language :: English',
    'Operating System :: MacOS',
    'Operating System :: MacOS :: MacOS X',
    'Operating System :: Microsoft',
    'Operating System :: Microsoft :: Windows',
    'Operating System :: OS/2',
    'Operating System :: OS Independent',
    'Operating System :: POSIX',
    'Operating System :: Unix',
    'Programming Language :: Python',
    'Topic :: Utilities',
    'Topic :: Software Development',
    'Topic :: Software Development :: Libraries',
    'Topic :: Software Development :: Libraries :: Python Modules'
]
if(len(sys.argv) > 1 and (sys.argv[1] == "versioninfo" or sys.argv[1] == "getversioninfo")):
    import json
    pymodule_data = json.dumps(pymodule)
    print(pymodule_data)
    sys.exit()
if(len(sys.argv) > 1 and (sys.argv[1] == "sourceinfo" or sys.argv[1] == "getsourceinfo")):
    srcinfofilename = os.path.realpath("."+os.path.sep+
              pymodule['name'].replace('-', '_')+".egg-info"+os.path.sep+"SOURCES.txt")
    srcinfofile = open(srcinfofilename, "r")
    srcinfodata = srcinfofile.read()
    srcinfofile.close()
    srcinfolist = srcinfodata.split('\n')
    srcfilelist = ""
    srcpdir = os.path.basename(os.path.dirname(os.path.realpath(__file__)))
    for ifile in srcinfolist:
        srcfilelist = "."+os.path.sep+srcpdir+os.path.sep+ifile+" "+srcfilelist
    print(srcfilelist)
    sys.exit()
if(len(sys.argv) > 1 and sys.argv[1] == "cleansourceinfo"):
    os.system("rm -rfv \""+os.path.realpath("."+os.path.sep+"dist\""))
    os.system("rm -rfv \""+os.path.realpath("."+os.path.sep +
              pymodule['name'].replace('-', '_')+".egg-info\""))
    sys.exit()

if(len(sys.argv) > 1 and (sys.argv[1] == "buildcfg" or sys.argv[1] == "makecfg")):
    outcfgvar = """[project]
    name = "{}"
    version = "{}"
    readme = "README.md"
    license = {{ text = "BSD-3-Clause" }}
    keywords = []
    description = "{}"
    authors = [
        {{ name = "{}", email = "{}" }},
    ]
    """.format(pymodule['name'], pymodule['version'], pymodule['description'], pymodule['author'], pymodule['authoremail'])
    mytoml = open("./pyproject.toml", "w")
    mytoml.write(outcfgvar)
    mytoml.flush()
    if(hasattr(os, "sync")):
        os.fsync(mytoml.fileno())
    mytoml.close()
    sys.exit()

setup(
    name=pymodule['name'],
    version=pymodule['version'],
    author=pymodule['author'],
    author_email=pymodule['authoremail'],
    maintainer=pymodule['maintainer'],
    maintainer_email=pymodule['maintaineremail'],
    description=pymodule['description'],
    license=pymodule['license'],
    keywords=pymodule['keywords'],
    url=pymodule['url'],
    download_url=pymodule['downloadurl'],
    long_description=pymodule['longdescription'],
    platforms=pymodule['platforms'],
    zip_safe=pymodule['zipsafe'],
    py_modules=pymodule['pymodules'],
    scripts=pymodule['scripts'],
    classifiers=pymodule['classifiers']
)
