#!/bin/sh

OUTF=/home/brendan/malrec/logs/index.html
echo "<table>" > ${OUTF}
echo "<tr><th>UUID</th><th>Filename</th><th>MD5</th><th>PCAP</th><th>RR Log</th><th>Added</th></tr>" >> ${OUTF}
sqlite3 /home/brendan/malrec/db/panda.db  'SELECT * FROM samples' | sed 's/|/ /g' | tac | while read uuid fn md5 ; do
    echo "<tr><td>$uuid</td><td>$fn</td><td>$md5</td><td><a href=\"pcap/${uuid}.pcap\">pcap</a></td><td><a href=\"rr/${uuid}.rr\">rrlog</a></td><td>$(stat -c %y /home/brendan/malrec/logs/rr/${uuid}.rr)</td></tr>" >> ${OUTF}
done
echo "</table>" >> ${OUTF}
