#!/usr/bin/env python

import pefile
import ConfigParser
import logging
import os
import shutil
import socket
import string
import subprocess
import sys
import telnetlib
import threading
import time
import uuid
import pefile
import sqlite3
import hashlib

keymap = {
    '-': 'minus',
    '=': 'equal',
    '[': 'bracket_left',
    ']': 'bracket_right',
    ';': 'semicolon',
    '\'': 'apostrophe',
    '\\': 'backslash',
    ',': 'comma',
    '.': 'dot',
    '/': 'slash',
    '*': 'asterisk',
    ' ': 'spc',
    '_': 'shift-minus',
    '+': 'shift-equal',
    '{': 'shift-bracket_left',
    '}': 'shift-bracket_right',
    ':': 'shift-semicolon',
    '"': 'shift-apostrophe',
    '|': 'shift-backslash',
    '<': 'shift-comma',
    '>': 'shift-dot',
    '?': 'shift-slash',
    '\n': 'ret',
}

def md5_for_file(fname, block_size=2**20):
    f = open(fname, 'rb')
    md5 = hashlib.md5()
    while True:
        data = f.read(block_size)
        if not data:
            break
        md5.update(data)
    digest = md5.hexdigest()
    f.close()
    return digest

def mon_cmd(s, mon):
    mon.write(s)
    logging.info(mon.read_until("(qemu)"))

def guest_type(s, mon):
    for c in s:
        if c in string.ascii_uppercase:
            key = 'shift-' + c.lower()
        else:
            key = keymap.get(c, c)
        mon_cmd('sendkey {0}\n'.format(key), mon)
        time.sleep(.1)

conf = ConfigParser.ConfigParser()
conf.read(sys.argv[1])

sample_name = sys.argv[2]
instance = int(sys.argv[3])
run_id = str(uuid.uuid4())

# Setup from config
monitor_port = 1234 + instance
basedir = conf.get('Main', 'basedir')
exec_time = int(conf.get('VM', 'exec_time'))
panda_exe = os.path.join(conf.get('Main', 'panda'), 'x86_64-softmmu', 'qemu-system-x86_64')
queuedir = os.path.join(basedir, 'queue')
logdir = os.path.join(basedir, 'logs')
rr_logdir = os.path.join(logdir, 'rr')
rr_logname = os.path.join(rr_logdir, run_id)
pcap_name = os.path.join(logdir, 'pcap', run_id + '.pcap')
logfile = os.path.join(logdir, 'text', time.strftime('%Y%m%d.%H.%M.%S.{0}.log').format(instance))
database = conf.get('Main', 'db')

# Init the logger
logging.basicConfig(filename=logfile, level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')

# Startup msgs
logging.info("Config file: {0}".format(sys.argv[1]))
logging.info("UUID: {0}".format(run_id))
logging.info("Sample: {0}".format(sample_name))

# Claim ownership of this file
logging.info("Moving sample into 'running' queue.")
sample_file = os.path.join(queuedir, 'running', sample_name)
shutil.move(
    os.path.join(queuedir, 'pending', sample_name),
    sample_file
)

# Calc sample md5
sample_md5 = md5_for_file(sample_file)
logging.info("MD5: {0}".format(sample_md5))

# Make the CD image
iso_file = os.path.join(basedir, 'iso', run_id + '.iso')
logging.info("Creating CD image {0}".format(iso_file))
genisoimage = ['/usr/bin/genisoimage', '-iso-level', '4', '-l', '-R', '-J', '-o', iso_file, sample_file]
logging.info(str(genisoimage))
isoproc = subprocess.Popen(genisoimage, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
(stdout, stderr) = isoproc.communicate()
logging.info(stdout)
logging.info(stderr)

# Check architecture of PE file
pe = pefile.PE(sample_file, fast_load=True)
if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
    logging.info("Sample detected as 64-bit")
    is_64bit = True
elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
    logging.info("Sample detected as 32-bit")
    is_64bit = False
else:
    logging.error("Unknown sample type: %#x" % pe.FILE_HEADER.Machine)
    sys.exit(1)

# Copy the qcow
if is_64bit:
    master_qcow = os.path.join(basedir, 'qcow', 'win7_64.base.qcow2')
else:
    master_qcow = os.path.join(basedir, 'qcow', 'win7.base.qcow2')
new_qcow = os.path.join(basedir, 'qcow', 'win7.{0}.qcow2').format(instance)
shutil.copyfile(master_qcow, new_qcow)

# Our args
panda_args = [panda_exe,
              '-m', conf.get('VM', 'mem'),
              '-monitor', 'telnet:localhost:{0},server,nowait'.format(monitor_port),
              '-drive', 'file={0},cache=unsafe'.format(new_qcow),
              '-record-from', 'bootsys:{0}'.format(rr_logname),
              '-net', 'nic,model=e1000',
              '-net', 'dump,file={0}'.format(pcap_name),
              '-net', 'user',
              '-vnc', '127.0.0.1:{0}'.format(instance),
              ]

# Start the QEMU process
panda_stdout = open(os.path.join(logdir, 'text', run_id + '.stdout'), 'w')
panda_stderr = open(os.path.join(logdir, 'text', run_id + '.stderr'), 'w')
panda = subprocess.Popen(panda_args, stdin=subprocess.PIPE, stdout=panda_stdout, stderr=panda_stderr)

# Connect to the monitor
# Give it time to come up...
tries = 10
mon = None
for i in range(tries):
    try:
        logging.info('Connecting to monitor, try {0}/{1}'.format(i, tries))
        mon = telnetlib.Telnet('localhost', monitor_port)
        break
    except socket.error:
        time.sleep(1)

if not mon:
    logging.error("Couldn't connect to monitor on port {0}".format(monitor_port))
    sys.exit(1)
else:
    logging.info("Successfully connected to monitor on port {0}".format(monitor_port))

# Wait for prompt
mon.read_until("(qemu)")

# Mount the CD
logging.info('Mounting CD image')
mon_cmd('change ide1-cd0 {0}\n'.format(iso_file), mon)

# Get rid of the CD dialog
logging.info('Getting rid of CD autoplay dialog')
time.sleep(1)
mon_cmd('sendkey esc\n', mon)

# Refresh network
logging.info("Renewing DHCP lease")
guest_type(r"ipconfig /renew" + '\n', mon)
time.sleep(1)

# Copy the file to the desktop
logging.info("Copying file to desktop.")
guest_type(r"copy D:\{0} C:\Users\qemu\Desktop".format(sample_name) + '\n', mon)

# Run the sample
logging.info("Starting sample.")
# Handle 3 cases: driver, exe, dll
if sample_name.endswith('.exe'):
    logging.info("Starting .exe as a normal executable.")
    guest_type(r"start C:\Users\qemu\Desktop\{0}".format(sample_name) + '\n', mon)
elif sample_name.endswith('.sys'):
    logging.info("Starting .sys as a kernel service.")
    guest_type(r"sc create sample binPath= C:\Users\qemu\Desktop\{0} type= kernel".format(sample_name) + '\n', mon)
    guest_type(r"sc start sample" + '\n', mon)
else:
    logging.error("Unknown sample type: extension {0}".format(os.path.splitext(sample_name)[1]))
    sys.exit(1)

# Wait
logging.info("Sleeping for {0} seconds...".format(exec_time))
time.sleep(exec_time)

# End the record
logging.info("Ending record.")
mon_cmd("end_record\n", mon)
logging.info("Quitting PANDA.")
mon.write("q\n")

# Move sample to the finished queue
logging.info("Moving sample into 'finished' queue.")
shutil.move(
    sample_file,
    os.path.join(queuedir, 'finished', sample_name)
)

# Cleanup
os.unlink(iso_file)
os.unlink(new_qcow)
panda_stdout.close()
panda_stderr.close()

# Write to DB
conn = sqlite3.connect(database)
c = conn.cursor()
while True:
    try:
        c.execute('INSERT INTO samples VALUES(?,?,?)', (run_id, sample_name, sample_md5))
        break
    except sqlite3.OperationalError:
        pass
c.close()
conn.commit()
conn.close()

# All done, write the stamp
stampfile = os.path.join(logdir, 'stamps', run_id)
open(stampfile, 'w').close()
