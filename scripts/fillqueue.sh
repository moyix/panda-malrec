#!/bin/sh

# SSH keychain setup
. ~/.keychain/panda-sh

DATE=`date -d '1 day ago' "+%Y%m%d"`
MALWARE_ARCHIVE=samples-${DATE}.zip
LOCAL_ARCHIVE=~/malrec/incoming/$MALWARE_ARCHIVE

sftp XXX_YOUR_SERVER_HERE_XXX:daily/${MALWARE_ARCHIVE} ${LOCAL_ARCHIVE}

if [ ! -f $LOCAL_ARCHIVE ]; then
    echo unable to retrieve $MALWARE_ARCHIVE;
    exit 1
else
    ~/malrec/scripts/unpack_samples.py ${LOCAL_ARCHIVE}
    rm -f ${LOCAL_ARCHIVE}
fi
