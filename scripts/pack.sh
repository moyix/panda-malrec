#!/bin/sh

echo "${1}"
~/git/panda/scripts/rrpack.py "${1}"
rm "${1}"-rr-snp "${1}"-rr-nondet.log
