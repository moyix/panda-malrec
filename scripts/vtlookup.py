#!/usr/bin/env python

import os
import json
import sys
import virustotal
import ConfigParser
import sqlite3

conf = ConfigParser.ConfigParser()
conf.read(sys.argv[1])

vt = virustotal.VirusTotal('798e91925a52e4f2c16a5a4e83337a0ff392c8f44d4d1bde9824e2dc4a378af3')

database = conf.get('Main', 'db')

conn = sqlite3.connect(database)
cur = conn.cursor()

basedir = conf.get('Main', 'basedir')
logdir = os.path.join(basedir, 'logs')

cur.execute('SELECT uuid,md5 FROM samples')
for uuid, md5 in cur.fetchall()[-100:]:
    print uuid, md5
    rep = vt.get(md5)
    fname = os.path.join(logdir, 'vt', uuid + '.json')
    f = open(fname, 'w')
    if rep:
        rep.join()
        json.dump(rep._report, f)
    f.close()

conn.close()
