#!/usr/bin/env python

import sys
import shutil
import random
import pefile
import zipfile

NUM_SAMPLES = 100
ZIP_PW = 'infected'

zip = zipfile.ZipFile(sys.argv[1])
namelist = zip.namelist()

s = set()
se = set()
while len(s) < NUM_SAMPLES:
    nm = random.choice(namelist)
    if nm in s: continue
    zf = zip.open(nm, 'r', ZIP_PW)
    try: pe = pefile.PE(data=zf.read(0x1000), fast_load=True)
    except pefile.PEFormatError: continue
    if pe.FILE_HEADER.IMAGE_FILE_DLL: continue
    if pe.OPTIONAL_HEADER.Subsystem == pefile.SUBSYSTEM_TYPE['IMAGE_SUBSYSTEM_NATIVE']:
        ext = '.sys'
    else:
        ext = '.exe'
    s.add(nm)
    se.add( (nm, ext) )
    zf.close()

for nm, ext in se:
    partial_name = '/home/brendan/malrec/queue/pending/.' + nm + '.partial'
    final_name = '/home/brendan/malrec/queue/pending/' + nm + ext
    zf = zip.open(nm, 'r', ZIP_PW)
    of = open(partial_name, 'wb')
    with zf, of:
        shutil.copyfileobj(zf, of)
    shutil.move(partial_name, final_name)
    print "Unpacked", nm, "into 'pending' queue"
