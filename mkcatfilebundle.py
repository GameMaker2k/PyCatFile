#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
    This program is free software; you can redistribute it and/or modify
    it under the terms of the Revised BSD License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Revised BSD License for more details.

    Copyright 2015-2021 Game Maker 2k - https://github.com/GameMaker2k
    Copyright 2015-2021 Kazuki Przyborowski - https://github.com/KazukiPrzyborowski

    $FileInfo: mkbundle.py - Last Update: 3/17/2021 Ver. 0.6.0 RC 1 - Author: cooldude2k $
'''

import os, sys, shutil, subprocess, tempfile, subprocess, platform;

tempdir = tempfile.gettempdir();
if(os.sep=="\\"):
 tempdir = tempdir.replace(os.sep, "/");
elif(os.path.sep=="\\"):
 tempdir = tempdir.replace(os.path.sep, "/");

pyimplementation = platform.python_implementation();
pylist = ['CPython', 'IronPython', 'PyPy', 'CPython2', 'CPython3', 'Python2', 'Python3', 'Python', 'PyPy2', 'PyPy3', 'IronPython2', 'IronPython3'];

if(len(sys.argv) > 1):
 if(sys.argv[1] in pylist):
  if(sys.argv[1]=="CPython"):
   pystring = "python3";
  elif(sys.argv[1]=="IronPython"):
   pystring = "ipy2";
  elif(sys.argv[1]=="PyPy"):
   pystring = "pypy3";
  elif(sys.argv[1]=="CPython2"):
   pystring = "python2";
  elif(sys.argv[1]=="CPython3"):
   pystring = "python3";
  elif(sys.argv[1]=="Python2"):
   pystring = "python2";
  elif(sys.argv[1]=="Python3"):
   pystring = "python3";
  elif(sys.argv[1]=="PyPy2"):
   pystring = "pypy";
  elif(sys.argv[1]=="PyPy3"):
   pystring = "pypy3";
  elif(sys.argv[1]=="IronPython2"):
   pystring = "ipy2";
  elif(sys.argv[1]=="IronPython3"):
   pystring = "ipy3";
  else:
   sys.exit();
 else:
  sys.exit();
 
if(len(sys.argv) < 1):
 if(pyimplementation=="CPython"):
  pystring = "python"+str(sys.version_info[0]);
 elif(pyimplementation=="IronPython"):
  pystring = "ipy"+str(sys.version_info[0]);
 elif(pyimplementation=="PyPy"):
  if(sys.version_info[0]==2):
   pystring = "pypy";
  elif(sys.version_info[0]==3):
   pystring = "pypy"+str(sys.version_info[0]);
  else:
   sys.exit(1);
 else:
  sys.exit(1);

if(len(sys.argv) > 2):
 if(os.path.exists("./"+sys.argv[2]) and os.path.isfile("./"+sys.argv[2])):
  infile = sys.argv[2];
  outfilebin = os.path.splitext(infile)[0];
  outfilezip = outfilebin+".zip";
 elif(os.path.exists("./"+sys.argv[2]) and os.path.isdir("./"+sys.argv[2])):
  infile = "catfile.py";
  outfilebin = os.path.splitext(infile)[0];
  outfilezip = outfilebin+".zip";
 else:
  infile = "catfile.py";
  outfilebin = os.path.splitext(infile)[0];
  outfilezip = outfilebin+".zip";
else:
 infile = "catfile.py";
 outfilebin = os.path.splitext(infile)[0];
 outfilezip = outfilebin+".zip";
if(os.path.exists(tempdir+"/pybundle") and os.path.isfile(tempdir+"/pybundle")):
 os.unlink(tempdir+"/pybundle");
if(os.path.exists(tempdir+"/pybundle") and os.path.isdir(tempdir+"/pybundle")):
 shutil.rmtree(tempdir+"/pybundle");
os.mkdir(tempdir+"/pybundle");
if(os.path.exists(tempdir+"/pybundle/__main__.py") and os.path.isfile(tempdir+"/pybundle/__main__.py")):
 os.unlink(tempdir+"/pybundle/__main__.py");
if(os.path.exists(tempdir+"/pybundle/__main__.py") and os.path.isdir(tempdir+"/pybundle/__main__.py")):
 shutil.rmtree(tempdir+"/pybundle/__main__.py");
shutil.copy2("./"+infile, tempdir+"/pybundle/__main__.py");
if(os.path.exists(tempdir+"/pybundle/pycatfile.py") and os.path.isfile(tempdir+"/pybundle/pycatfile.py")):
 os.unlink(tempdir+"/pybundle/pycatfile.py");
if(os.path.exists(tempdir+"/pybundle/pycatfile.py") and os.path.isdir(tempdir+"/pybundle/pycatfile.py")):
 shutil.rmtree(tempdir+"/pybundle/pycatfile.py");
shutil.copy2("./pycatfile.py", tempdir+"/pybundle/pycatfile.py");
if(os.path.exists(tempdir+"/"+outfilezip) and os.path.isfile(tempdir+"/"+outfilezip)):
 os.unlink(tempdir+"/"+outfilezip);
if(os.path.exists(tempdir+"/"+outfilezip) and os.path.isdir(tempdir+"/"+outfilezip)):
 shutil.rmtree(tempdir+"/"+outfilezip);
shutil.make_archive(tempdir+"/"+outfilebin, "zip", tempdir+"/pybundle");
if(os.path.exists(tempdir+"/pybundle/"+outfilezip) and os.path.isfile(tempdir+"/pybundle/"+outfilezip)):
 os.unlink(tempdir+"/pybundle/"+outfilezip);
if(os.path.exists(tempdir+"/pybundle/"+outfilezip) and os.path.isdir(tempdir+"/pybundle/"+outfilezip)):
 shutil.rmtree(tempdir+"/pybundle/"+outfilezip);
shutil.move(tempdir+"/"+outfilezip, tempdir+"/pybundle/"+outfilezip);
if(os.path.exists(tempdir+"/pybundle/"+outfilebin) and os.path.isfile(tempdir+"/pybundle/"+outfilebin)):
 os.unlink(tempdir+"/pybundle/"+outfilebin);
if(os.path.exists(tempdir+"/pybundle/"+outfilebin) and os.path.isdir(tempdir+"/pybundle/"+outfilebin)):
 shutil.rmtree(tempdir+"/pybundle/"+outfilebin);
mkbstring = "#!/usr/bin/env "+pystring+"\n\n";
mkbfp = open(tempdir+"/pybundle/"+outfilebin, "wb+");
mkbfp.write(mkbstring.encode());
zipfp = open(tempdir+"/pybundle/"+outfilezip, "rb");
mkbfp.write(zipfp.read());
mkbfp.close();
zipfp.close();
shutil.rmtree("./bundle/"+pystring);
os.mkdir("./bundle/"+pystring);
shutil.move(tempdir+"/pybundle/"+outfilebin, "./bundle/"+pystring+"/"+outfilebin);
os.chmod("./bundle/"+pystring+"/"+outfilebin, 0o755);
shutil.rmtree(tempdir+"/pybundle");
oldpath = os.getcwd();
os.chdir("./bundle/"+pystring);
curscrpath = os.path.dirname("./"+outfilebin);
if(curscrpath==""):
 curscrpath = ".";
if(os.sep=="\\"):
 curscrpath = curscrpath.replace(os.sep, "/");
elif(os.path.sep=="\\"):
 curscrpath = curscrpath.replace(os.path.sep, "/");
curscrpath = curscrpath+os.path.sep;
scrfile = curscrpath+outfilebin;
'''
if(os.path.exists(scrfile) and os.path.isfile(scrfile) and infile=="catfile.py"):
 scrcmd = subprocess.Popen([sys.executable, scrfile, "mksymlinks"]);
 scrcmd.wait();
'''
os.chdir(oldpath);
