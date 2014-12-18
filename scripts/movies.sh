#!/bin/bash

BASEDIR=/home/brendan/malrec
sqlite3 ${BASEDIR}/db/panda.db 'SELECT uuid FROM samples' | tail -n 100 | parallel -u -j 8 sh ${BASEDIR}/scripts/mkmovie.sh {/}
